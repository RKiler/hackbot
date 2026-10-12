"""Resolve an observed, owned object request at dispatch time.

Plans retain opaque references, not captured URLs or application object IDs.
This module has no transport and cannot send a request.
"""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import quote, unquote, urlsplit, urlunsplit
import uuid

from .evidence import FactStatus
from .executor import RequestTemplate
from .logging import SecretRedactor
from .response_compare import ResponseComparator
from .store import EvidenceFactStore
from .target_package import TargetPackage
from .target_scope import ScopeResult
from .test_objects import ObjectRegistry, ObjectState
from .traffic import AuthState, ExchangeState, TrafficStore
from .typed_mutations import BatchBinding, NestedBinding


_KEYS = frozenset({"binding", "method", "source_exchange_id", "test_object_id",
                   "variant", "fingerprint", "authentication"})
_GRAPHQL_KEYS = _KEYS | {"variable_name"}
_NESTED_KEYS = _KEYS | {"parent_object_id", "foreign_parent_object_id"}
_BATCH_KEYS = _KEYS | {"owner_peer_object_id", "actor_object_id"}
_VARIANTS = frozenset({"OWNER", "FOREIGN", "INVALID_OBJECT", "ANONYMOUS",
                       "POST_READBACK"})


def single_rename_operation(query: str, id_variable: str, name_variable: str) -> str | None:
    """Accept one plain rename field; reject aliases, fragments and second operations."""
    if name_variable not in {"name", "newName"}:
        return None
    identifier = r"[A-Za-z_][A-Za-z_0-9]*"
    pattern = (
        rf"\s*mutation\s+(?P<operation>{identifier})\s*"
        rf"\(\s*\${re.escape(id_variable)}\s*:\s*ID!\s*,\s*"
        rf"\${re.escape(name_variable)}\s*:\s*String!\s*\)\s*"
        rf"\{{\s*rename{identifier}\s*\(\s*id\s*:\s*\${re.escape(id_variable)}\s*,\s*"
        rf"{re.escape(name_variable)}\s*:\s*\${re.escape(name_variable)}\s*\)\s*"
        rf"\{{\s*(?P<selection>(?:{identifier}\s*)+)\}}\s*\}}\s*"
    )
    match = re.fullmatch(pattern, query, flags=re.ASCII)
    if match is None:
        return None
    fields = match.group("selection").split()
    if len(fields) != len(set(fields)) or not {"id", "name"}.issubset(fields) or not set(fields) <= {
            "id", "name", "owner", "tenant"}:
        return None
    return match.group("operation")


def reference_fingerprint(shape: dict[str, str]) -> str:
    keys = (_BATCH_KEYS if shape.get("binding") == "AUTHORIZATION_BATCH_PATH_V1" else
            _NESTED_KEYS if shape.get("binding") == "AUTHORIZATION_NESTED_PARENT_V1" else
            _GRAPHQL_KEYS if shape.get("binding") in {
        "AUTHORIZATION_GRAPHQL_QUERY_V1", "AUTHORIZATION_GRAPHQL_MUTATION_V1"} else _KEYS)
    payload = {key: shape[key] for key in sorted(keys - {"fingerprint"})}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def resolve_exposure_read(shape: dict[str, str], *, package: TargetPackage,
                          run_id: str, objects: ObjectRegistry, traffic: TrafficStore,
                          evidence: EvidenceFactStore) -> tuple[RequestTemplate, str]:
    """Rebuild only an exact observed owned GET; never replay captured credentials."""
    if (set(shape) != _KEYS or shape.get("binding") != "EXPOSURE_OBJECT_PATH_V1"
            or shape.get("authentication") != "EXECUTOR_SUPPLIED"
            or shape.get("method") != "GET"
            or shape.get("variant") not in {"OWNER", "ANONYMOUS", "INVALID_OBJECT"}
            or shape.get("fingerprint") != reference_fingerprint(shape)):
        raise ValueError("invalid exposure request reference")
    item = objects.get(shape["test_object_id"], package.target.id)
    if (item is None or item.package_id != package.id or item.state is not ObjectState.IN_USE
            or not item.disposable or item.verified_at is None or not item.external_id_hash
            or not item.external_id_evidence_id or objects.active_reservation(item.id) != run_id):
        raise ValueError("owned exposure object reservation is missing")
    for predicate, value in (("created_by", item.creator_identity_id),
                             ("resource_tenant", item.tenant_id), ("disposable", "true")):
        facts = evidence.find_facts(item.id, predicate, limit=8).items
        if not any(fact.target_ref == package.target.id and fact.status is FactStatus.ACTIVE
                   and fact.source != "MANUAL" and fact.confidence >= 0.9
                   and fact.evidence_ids and fact.object == value for fact in facts):
            raise ValueError("owned exposure object facts are missing")
    external = evidence.read_content(item.external_id_evidence_id,
                                     allow_sensitive=True, max_bytes=256).decode("ascii")
    if (not external or "/" in external or "\\" in external or
            hashlib.sha256((item.id + ":" + external).encode()).hexdigest() != item.external_id_hash):
        raise ValueError("owned exposure object ID integrity failed")
    exchange = traffic.get_exchange(shape["source_exchange_id"])
    if (exchange is None or exchange.target_id != package.target.id or exchange.package_id != package.id
            or exchange.state is not ExchangeState.COMPLETE or exchange.response is None
            or exchange.attribution.auth_state is not AuthState.VERIFIED
            or exchange.attribution.verified_identity_id != item.creator_identity_id
            or exchange.scope_result is not ScopeResult.IN_SCOPE
            or exchange.request.record.method != "GET" or
            exchange.response.record.status_code != 200 or
            not exchange.response.body_hash or not exchange.response.record.size_bytes or
            exchange.response.record.content_type in {"text/html", "application/xhtml+xml"}):
        raise ValueError("verified owned exposure baseline is missing")
    request_ref = exchange.request.observation_evidence_id
    record = evidence.get_evidence(request_ref) if request_ref else None
    if record is None or record.target_ref != package.target.id:
        raise ValueError("owned exposure request provenance is missing")
    try:
        observed = json.loads(evidence.read_content(record.evidence_id,
                                                    allow_sensitive=True, max_bytes=8192))
        url = observed["url"]
        parsed = urlsplit(url)
    except (KeyError, TypeError, ValueError, UnicodeError, PermissionError):
        raise ValueError("owned exposure URL is unavailable") from None
    if (not isinstance(url, str) or parsed.scheme not in {"http", "https"}
            or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            or package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE):
        raise ValueError("owned exposure URL is unsafe")
    segments = parsed.path.split("/")
    positions = [index for index, segment in enumerate(segments) if unquote(segment) == external]
    if len(positions) != 1:
        raise ValueError("owned exposure path lacks one exact object ID")
    if shape["variant"] == "INVALID_OBJECT":
        segments[positions[0]] = quote(str(uuid.uuid5(uuid.NAMESPACE_URL, run_id + ":" + item.id)), safe="")
        url = urlunsplit((parsed.scheme, parsed.netloc, "/".join(segments), "", ""))
        if package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
            raise ValueError("invalid-object control left scope")
    return RequestTemplate("GET", url), item.external_id_hash


def resolve_authorization_request(shape: dict[str, str], *, package: TargetPackage,
                                  run_id: str, objects: ObjectRegistry,
                                  traffic: TrafficStore, evidence: EvidenceFactStore) -> tuple[RequestTemplate, str]:
    """Return a single exact-path request and its salted owned-object hash."""
    graphql = shape.get("binding") in {"AUTHORIZATION_GRAPHQL_QUERY_V1",
                                       "AUTHORIZATION_GRAPHQL_MUTATION_V1"}
    nested = shape.get("binding") == "AUTHORIZATION_NESTED_PARENT_V1"
    batch = shape.get("binding") == "AUTHORIZATION_BATCH_PATH_V1"
    mutation = shape.get("binding") == "AUTHORIZATION_GRAPHQL_MUTATION_V1"
    if (set(shape) != (_BATCH_KEYS if batch else _NESTED_KEYS if nested else
                       _GRAPHQL_KEYS if graphql else _KEYS) or
            shape.get("binding") not in {"AUTHORIZATION_OBJECT_PATH_V1",
                                          "AUTHORIZATION_GRAPHQL_QUERY_V1",
                                          "AUTHORIZATION_GRAPHQL_MUTATION_V1",
                                          "AUTHORIZATION_NESTED_PARENT_V1",
                                          "AUTHORIZATION_BATCH_PATH_V1"}
            or shape.get("authentication") != "EXECUTOR_SUPPLIED"
            or shape.get("variant") not in _VARIANTS
            or (graphql and (shape.get("method") != "POST" or
                             shape.get("variant") in {"ANONYMOUS", "POST_READBACK"} or
                             not isinstance(shape.get("variable_name"), str) or
                             not shape["variable_name"].isidentifier()))
            or (mutation and shape.get("variant") not in {"FOREIGN", "INVALID_OBJECT"})
            or (not graphql and shape.get("method") not in {"GET", "HEAD"})
            or (nested and (shape.get("method") != "GET" or shape.get("variant") != "FOREIGN"))
            or (batch and (shape.get("method") != "GET" or
                           shape.get("variant") not in {"OWNER", "FOREIGN"}))
            or (shape.get("variant") == "POST_READBACK" and graphql)
            or shape.get("fingerprint") != reference_fingerprint(shape)):
        raise ValueError("invalid authorization request reference")
    item = objects.get(shape["test_object_id"], package.target.id)
    if (item is None or item.package_id != package.id or item.state is not ObjectState.IN_USE
            or not item.disposable or item.verified_at is None or not item.external_id_hash
            or not item.external_id_evidence_id or objects.active_reservation(item.id) != run_id):
        raise ValueError("owned object reservation is missing")
    for predicate, value in (("created_by", item.creator_identity_id),
                             ("resource_tenant", item.tenant_id), ("disposable", "true")):
        facts = evidence.find_facts(item.id, predicate, limit=8).items
        if not any(fact.target_ref == package.target.id and fact.status is FactStatus.ACTIVE
                   and fact.source != "MANUAL" and fact.confidence >= 0.9
                   and fact.evidence_ids and fact.object == value for fact in facts):
            raise ValueError("owned object facts are missing")
    external = evidence.read_content(item.external_id_evidence_id,
                                     allow_sensitive=True, max_bytes=256).decode("ascii")
    if (not external or "/" in external or "\\" in external or
            hashlib.sha256((item.id + ":" + external).encode()).hexdigest() != item.external_id_hash):
        raise ValueError("owned object ID integrity failed")
    exchange = traffic.get_exchange(shape["source_exchange_id"])
    if (exchange is None or exchange.target_id != package.target.id or exchange.package_id != package.id
            or exchange.state is not ExchangeState.COMPLETE or exchange.response is None
            or exchange.attribution.auth_state is not AuthState.VERIFIED
            or exchange.attribution.verified_identity_id != item.creator_identity_id
            or exchange.scope_result is not ScopeResult.IN_SCOPE
            or exchange.request.record.method != shape["method"]):
        raise ValueError("owner request is not verified")
    features = ResponseComparator(evidence).features(exchange)
    if (features.status_code is None or not 200 <= features.status_code < 300
            or features.graphql_errors_present
            or (graphql and not features.graphql_data_present)
            or hashlib.sha256(external.encode()).hexdigest() not in features.object_id_hashes):
        raise ValueError("owner request lacks semantic object proof")
    request_evidence = evidence.get_evidence(exchange.request.observation_evidence_id)
    if request_evidence is None or request_evidence.target_ref != package.target.id:
        raise ValueError("owner request evidence is unavailable")
    try:
        observed = json.loads(evidence.read_content(request_evidence.evidence_id,
                                                    allow_sensitive=True, max_bytes=8192))
        url = observed["url"]
        parsed = urlsplit(url)
    except (KeyError, TypeError, ValueError, UnicodeError, PermissionError):
        raise ValueError("owner request URL is unavailable") from None
    if (not isinstance(url, str) or parsed.scheme not in {"http", "https"}
            or not parsed.hostname or parsed.username or parsed.password or parsed.query
            or parsed.fragment or package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE):
        raise ValueError("owner request URL is unsafe")
    if graphql:
        body_ref = exchange.request.body_evidence_id
        body_item = evidence.get_evidence(body_ref) if body_ref else None
        if (body_item is None or body_item.target_ref != package.target.id or
                body_item.redaction_status.value != "ORIGINAL" or body_item.content_size > 8192):
            raise ValueError("captured GraphQL body is unavailable")
        try:
            raw = evidence.read_content(body_ref, allow_sensitive=True, max_bytes=8192)
            if exchange.request.body_hash != hashlib.sha256(raw).hexdigest():
                raise ValueError
            def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
                result: dict[str, object] = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate GraphQL JSON key")
                    result[key] = value
                return result
            payload = json.loads(raw, object_pairs_hook=unique_pairs)
            variables = payload["variables"]
            query = payload["query"]
            if (not isinstance(payload, dict) or set(payload) - {"query", "variables", "operationName"}
                    or not isinstance(query, str) or not query.lstrip().startswith(
                        "mutation " if mutation else "query ")
                    or len(query) > 4096 or SecretRedactor.from_environment().text(query) != query
                    or re.search(r"\b(?:query|subscription)\b" if mutation else
                                 r"\b(?:mutation|subscription)\b", query, re.I)
                    or not isinstance(variables, dict) or
                    (set(variables) not in ({shape["variable_name"], "name"},
                                            {shape["variable_name"], "newName"}) if mutation else
                     set(variables) != {shape["variable_name"]}) or
                    variables.get(shape["variable_name"]) != external):
                raise ValueError
            if mutation:
                changes = {key: value for key, value in variables.items()
                           if key != shape["variable_name"]}
                if (len(changes) != 1 or not all(
                        isinstance(value, str) and 4 <= len(value) <= 80 and
                        value.replace("-", "").isalnum() and
                        SecretRedactor.from_environment().text(value) == value
                        for value in changes.values())):
                    raise ValueError
                name_variable = next(iter(changes))
                operation_name = single_rename_operation(
                    query, shape["variable_name"], name_variable)
                if operation_name is None or payload.get("operationName") != operation_name:
                    raise ValueError
        except (KeyError, TypeError, ValueError, UnicodeError, PermissionError):
            raise ValueError("captured GraphQL query is not a single-ID template") from None
        if shape["variant"] == "INVALID_OBJECT":
            variables[shape["variable_name"]] = str(uuid.uuid5(
                uuid.NAMESPACE_URL, run_id + ":" + item.id))
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return RequestTemplate("POST", url, (("Content-Type", "application/json"),), body), item.external_id_hash
    segments = parsed.path.split("/")
    if batch:
        peer = objects.get(shape["owner_peer_object_id"], package.target.id)
        actor_object = objects.get(shape["actor_object_id"], package.target.id)
        if (peer is None or actor_object is None or
                item.id in {peer.id, actor_object.id} or peer.id == actor_object.id or
                peer.tenant_id != item.tenant_id or
                peer.creator_identity_id != item.creator_identity_id or
                actor_object.tenant_id == item.tenant_id or
                peer.object_type != item.object_type or
                actor_object.object_type != item.object_type):
            raise ValueError("batch ownership relation is invalid")
        BatchBinding(exchange.request.record.operation_id or "batchRead",
                     (item.id, peer.id, actor_object.id), actor_object.creator_identity_id,
                     (actor_object.id,), 4)
        for entry in (peer, actor_object):
            if (entry.package_id != package.id or entry.state is not ObjectState.IN_USE or
                    not entry.disposable or not entry.verified_at or
                    objects.active_reservation(entry.id) != run_id or
                    not entry.external_id_evidence_id or not entry.external_id_hash):
                raise ValueError("batch object reservation is missing")
            for predicate, value in (("created_by", entry.creator_identity_id),
                                     ("resource_tenant", entry.tenant_id), ("disposable", "true")):
                facts = evidence.find_facts(entry.id, predicate, limit=8).items
                if not any(fact.target_ref == package.target.id and fact.status is FactStatus.ACTIVE
                           and fact.source != "MANUAL" and fact.confidence >= 0.9 and
                           fact.evidence_ids and fact.object == value for fact in facts):
                    raise ValueError("batch ownership facts are missing")
        def batch_external(entry) -> str:
            value = evidence.read_content(entry.external_id_evidence_id,
                                          allow_sensitive=True, max_bytes=256).decode("ascii")
            if hashlib.sha256((entry.id + ":" + value).encode()).hexdigest() != entry.external_id_hash:
                raise ValueError("batch ID integrity failed")
            return value
        peer_external = batch_external(peer)
        actor_external = batch_external(actor_object)
        if (len(segments) < 2 or segments[-2] != "batch" or
                segments[-1].split(",") != [external, peer_external] or
                hashlib.sha256(peer_external.encode()).hexdigest() not in
                features.object_id_hashes):
            raise ValueError("observed batch is not exactly two owned objects")
        if shape["variant"] == "FOREIGN":
            segments[-1] = quote(actor_external, safe="") + "," + quote(external, safe="")
        resolved = urlunsplit((parsed.scheme, parsed.netloc, "/".join(segments), "", ""))
        if package.scope.evaluate_url(resolved).result is not ScopeResult.IN_SCOPE:
            raise ValueError("batch request is outside scope")
        return RequestTemplate("GET", resolved), item.external_id_hash
    positions = [index for index, segment in enumerate(segments) if unquote(segment) == external]
    if len(positions) != 1:
        raise ValueError("object ID path binding is ambiguous")
    if nested:
        parent = objects.get(shape["parent_object_id"], package.target.id)
        foreign_parent = objects.get(shape["foreign_parent_object_id"], package.target.id)
        if (parent is None or foreign_parent is None or item.parent_id != parent.id or
                parent.id == foreign_parent.id or parent.tenant_id != item.tenant_id or
                foreign_parent.tenant_id == item.tenant_id or
                parent.object_type != foreign_parent.object_type or
                any(entry.package_id != package.id or entry.state is not ObjectState.IN_USE or
                    not entry.disposable or not entry.verified_at or
                    objects.active_reservation(entry.id) != run_id or
                    not entry.external_id_evidence_id or not entry.external_id_hash
                    for entry in (parent, foreign_parent))):
            raise ValueError("nested object reservations or relation missing")
        for entry in (parent, foreign_parent):
            for predicate, value in (("created_by", entry.creator_identity_id),
                                     ("resource_tenant", entry.tenant_id), ("disposable", "true")):
                facts = evidence.find_facts(entry.id, predicate, limit=8).items
                if not any(fact.target_ref == package.target.id and fact.status is FactStatus.ACTIVE
                           and fact.source != "MANUAL" and fact.confidence >= 0.9 and
                           fact.evidence_ids and fact.object == value for fact in facts):
                    raise ValueError("nested ownership facts missing")
        def parent_external(entry) -> str:
            value = evidence.read_content(entry.external_id_evidence_id,
                                          allow_sensitive=True, max_bytes=256).decode("ascii")
            if hashlib.sha256((entry.id + ":" + value).encode()).hexdigest() != entry.external_id_hash:
                raise ValueError("nested parent ID integrity failed")
            return value
        original_parent = parent_external(parent)
        replacement_parent = parent_external(foreign_parent)
        parent_positions = [index for index, segment in enumerate(segments)
                            if unquote(segment) == original_parent]
        if len(parent_positions) != 1 or parent_positions[0] == positions[0]:
            raise ValueError("observed nested URL is ambiguous")
        response_ref = exchange.response.body_evidence_id if exchange.response else None
        if not response_ref:
            raise ValueError("nested relation read-back missing")
        response_item = evidence.get_evidence(response_ref)
        if (response_item is None or response_item.target_ref != package.target.id or
                response_item.redaction_status.value != "ORIGINAL" or
                response_item.content_size > 8192):
            raise ValueError("nested relation evidence is unavailable")
        content = evidence.read_content(response_ref, allow_sensitive=True, max_bytes=8192)
        if hashlib.sha256(content).hexdigest() != exchange.response.body_hash:
            raise ValueError("nested relation evidence changed")
        response = json.loads(content)
        if (not isinstance(response, dict) or response.get("id") != external or
                response.get("parentId", response.get("parent_id")) != original_parent):
            raise ValueError("nested relation response changed")
        NestedBinding(parent.id, item.id, parent.tenant_id, item.tenant_id,
                      exchange.request.record.operation_id or "nestedRead",
                      (response_ref,))
        segments[parent_positions[0]] = quote(replacement_parent, safe="")
    if shape["variant"] == "INVALID_OBJECT":
        replacement = str(uuid.uuid5(uuid.NAMESPACE_URL, run_id + ":" + item.id))
        segments[positions[0]] = quote(replacement, safe="")
    resolved = urlunsplit((parsed.scheme, parsed.netloc, "/".join(segments), "", ""))
    if package.scope.evaluate_url(resolved).result is not ScopeResult.IN_SCOPE:
        raise ValueError("resolved request is outside scope")
    return RequestTemplate(shape["method"], resolved), item.external_id_hash
