"""Dispatch-time binding for observed API reads; never creates a transport."""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit
import uuid

from .api_graphql import (encode_observed_global_id, graphql_batch_values,
                          observed_global_id_type, parse_operations,
                          single_node_id_binding, single_node_id_variable,
                          single_nodes_ids_variable)
from .api_registry import APIOperationRegistry, APIOperationType
from .authorization_binding import (reference_fingerprint as legacy_fingerprint,
                                    resolve_authorization_request)
from .evidence import FactStatus, RedactionStatus
from .executor import RequestTemplate
from .response_compare import ResponseComparator
from .store import EvidenceFactStore
from .target_package import TargetPackage
from .target_scope import ScopeResult
from .test_objects import ObjectRegistry, ObjectState, TestObject
from .traffic import AuthState, ExchangeState, TrafficStore


_KEYS = frozenset({"binding", "operation_id", "version_hash", "source_exchange_id",
                   "test_object_id", "variant", "variable_name", "field_path",
                   "method", "authentication", "fingerprint"})
_VARIANTS = frozenset({"OWNER", "FOREIGN", "INVALID_OBJECT"})
_BATCH_KEYS = _KEYS | {"source_companion_id", "companion_object_id",
                       "root_key", "id_type", "envelope"}


def api_reference_fingerprint(shape: dict[str, str]) -> str:
    payload = {key: shape[key] for key in sorted(_KEYS - {"fingerprint"})}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def api_batch_reference_fingerprint(shape: dict[str, str]) -> str:
    payload = {key: shape[key] for key in sorted(_BATCH_KEYS - {"fingerprint"})}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def resolve_api_read(shape: dict[str, str], *, package: TargetPackage, run_id: str,
                     operations: APIOperationRegistry, objects: ObjectRegistry,
                     traffic: TrafficStore, evidence: EvidenceFactStore) -> tuple[RequestTemplate, str]:
    if (set(shape) != _KEYS or shape.get("binding") != "API_OBSERVED_READ_V1" or
            shape.get("variant") not in _VARIANTS or
            shape.get("authentication") != "EXECUTOR_SUPPLIED" or
            shape.get("fingerprint") != api_reference_fingerprint(shape)):
        raise ValueError("Invalid API read binding")
    operation = operations.get_operation(package.target.id, shape["operation_id"])
    if (operation is None or operation.package_id != package.id or operation.state != "CURRENT" or
            operation.version_hash != shape["version_hash"] or
            shape["source_exchange_id"] not in operation.exchange_ids or
            operation.type not in {APIOperationType.REST, APIOperationType.GRAPHQL_QUERY} or
            operation.method != shape["method"]):
        raise ValueError("Observed API operation is unavailable or stale")
    item = objects.get(shape["test_object_id"], package.target.id)
    if (item is None or item.package_id != package.id or item.state is not ObjectState.IN_USE or
            not item.disposable or not item.verified_at or not item.external_id_hash or
            not item.external_id_evidence_id or objects.active_reservation(item.id) != run_id):
        raise ValueError("Verified owned API object reservation is missing")
    for predicate, value in (("created_by", item.creator_identity_id),
                             ("resource_tenant", item.tenant_id), ("disposable", "true")):
        facts = evidence.find_facts(item.id, predicate, limit=8).items
        if not any(fact.target_ref == package.target.id and fact.status is FactStatus.ACTIVE and
                   fact.source != "MANUAL" and fact.confidence >= 0.9 and fact.evidence_ids and
                   fact.object == value for fact in facts):
            raise ValueError("Verified API object facts are missing")
    external = evidence.read_content(item.external_id_evidence_id,
                                     allow_sensitive=True, max_bytes=256).decode("ascii")
    if hashlib.sha256((item.id + ":" + external).encode()).hexdigest() != item.external_id_hash:
        raise ValueError("API object identifier integrity failed")
    exchange = traffic.get_exchange(shape["source_exchange_id"])
    if (exchange is None or exchange.target_id != package.target.id or
            exchange.package_id != package.id or exchange.state is not ExchangeState.COMPLETE or
            exchange.scope_result is not ScopeResult.IN_SCOPE or exchange.response is None or
            exchange.attribution.auth_state is not AuthState.VERIFIED or
            exchange.attribution.verified_identity_id != item.creator_identity_id or
            exchange.request.record.method != operation.method):
        raise ValueError("Verified owner API control is unavailable")
    token = "{p:" + hashlib.sha256(external.encode()).hexdigest()[:12] + "}"
    observed_endpoint = (exchange.request.origin +
                         exchange.request.display_path.replace(token, "{object_id}"))
    if observed_endpoint != operation.endpoint:
        raise ValueError("Verified owner API route no longer matches the operation")
    features = ResponseComparator(evidence).features(exchange)
    if (features.status_code is None or not 200 <= features.status_code < 300 or
            hashlib.sha256(external.encode()).hexdigest() not in features.object_id_hashes or
            (operation.type is APIOperationType.GRAPHQL_QUERY and
             (not features.graphql_data_present or features.graphql_errors_present))):
        raise ValueError("Owner API control lacks semantic object proof")
    field_path = shape["field_path"]
    if field_path:
        if (operation.type is not APIOperationType.GRAPHQL_QUERY or
                field_path not in {field.path for field in operation.fields} or
                features.graphql_value(field_path) is None):
            raise ValueError("Protected field is absent from owner control")
    if operation.type is APIOperationType.REST:
        if (shape["variable_name"] or field_path or operation.method not in {"GET", "HEAD"}):
            raise ValueError("REST API read binding is invalid")
        legacy = {"binding": "AUTHORIZATION_OBJECT_PATH_V1", "method": operation.method,
                  "source_exchange_id": exchange.id, "test_object_id": item.id,
                  "variant": shape["variant"], "authentication": "EXECUTOR_SUPPLIED"}
        legacy["fingerprint"] = legacy_fingerprint(legacy)
        return resolve_authorization_request(legacy, package=package, run_id=run_id,
                                             objects=objects, traffic=traffic, evidence=evidence)
    if (operation.method != "POST" or not shape["variable_name"].isidentifier()):
        raise ValueError("GraphQL read requires an observed POST and declared ID variable")
    request_ref = evidence.get_evidence(exchange.request.observation_evidence_id)
    body_ref = evidence.get_evidence(exchange.request.body_evidence_id) if exchange.request.body_evidence_id else None
    if (request_ref is None or request_ref.target_ref != package.target.id or
            body_ref is None or body_ref.target_ref != package.target.id or
            body_ref.redaction_status is not RedactionStatus.ORIGINAL or
            body_ref.content_size > 16384):
        raise ValueError("Protected observed GraphQL request is unavailable")
    try:
        request = json.loads(evidence.read_content(request_ref.evidence_id,
                                                   allow_sensitive=True, max_bytes=16384))
        url = request["url"]
        parsed_url = urlsplit(url)
        if (not isinstance(url, str) or parsed_url.query or parsed_url.fragment or
                parsed_url.username or parsed_url.password or
                package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE):
            raise ValueError
        raw = evidence.read_content(body_ref.evidence_id, allow_sensitive=True, max_bytes=16384)
        if hashlib.sha256(raw).hexdigest() != exchange.request.body_hash:
            raise ValueError
        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        payload = json.loads(raw, object_pairs_hook=unique_pairs)
        if (not isinstance(payload, dict) or set(payload) - {"query", "variables", "operationName"}
                or not isinstance(payload.get("query"), str) or
                hashlib.sha256(payload["query"].encode()).hexdigest() != operation.version_hash or
                not isinstance(payload.get("variables"), dict) or
                len(payload["variables"]) > 10 or
                payload.get("operationName") != operation.name):
            raise ValueError
        observed_id = payload["variables"].get(shape["variable_name"])
        if operation.global_id_type and operation.global_id_type != "PLAIN":
            if (operation.global_id_type == "CONFLICT" or
                    single_node_id_variable(payload["query"]) != shape["variable_name"] or
                    observed_global_id_type(observed_id, external) != operation.global_id_type):
                raise ValueError
        elif observed_id != external:
            raise ValueError
        parsed = parse_operations(payload["query"])
        if (len(parsed) != 1 or parsed[0].kind != "QUERY" or parsed[0].name != operation.name or
                len(parsed[0].root_fields) != 1 or
                shape["variable_name"] not in parsed[0].variables or
                not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", operation.name)):
            raise ValueError
    except (KeyError, TypeError, ValueError, UnicodeError, PermissionError):
        raise ValueError("Observed GraphQL request cannot be bound safely") from None
    if shape["variant"] == "INVALID_OBJECT":
        invalid = str(uuid.uuid5(uuid.NAMESPACE_URL, run_id + ":" + item.id))
        payload["variables"][shape["variable_name"]] = (
            encode_observed_global_id(operation.global_id_type, invalid)
            if operation.global_id_type and operation.global_id_type != "PLAIN" else invalid)
    return (RequestTemplate("POST", url, (("Content-Type", "application/json"),),
                            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()),
            item.external_id_hash)


def resolve_api_batch(shape: dict[str, str], *, package: TargetPackage, run_id: str,
                      operations: APIOperationRegistry, objects: ObjectRegistry,
                      traffic: TrafficStore, evidence: EvidenceFactStore) -> tuple[RequestTemplate, str]:
    """Rebind one captured two-ID nodes query to four reserved disposable objects."""
    if (set(shape) != _BATCH_KEYS or shape.get("binding") != "API_OBSERVED_BATCH_V1" or
            shape.get("variant") not in _VARIANTS or
            shape.get("envelope") not in {"NODES_LIST", "OPERATION_ARRAY"} or
            shape.get("authentication") != "EXECUTOR_SUPPLIED" or
            shape.get("fingerprint") != api_batch_reference_fingerprint(shape)):
        raise ValueError("Invalid observed API batch binding")
    operation = operations.get_operation(package.target.id, shape["operation_id"])
    if (operation is None or operation.package_id != package.id or
            operation.state != "CURRENT" or operation.type is not APIOperationType.GRAPHQL_QUERY or
            operation.method != "POST" or operation.version_hash != shape["version_hash"] or
            shape["source_exchange_id"] not in operation.exchange_ids or
            shape["method"] != "POST"):
        raise ValueError("Observed API batch operation is unavailable or stale")

    resolved: dict[str, tuple[TestObject, str]] = {}
    for field in ("test_object_id", "source_companion_id", "companion_object_id"):
        item = objects.get(shape[field], package.target.id)
        if (item is None or item.package_id != package.id or
                item.state is not ObjectState.IN_USE or not item.disposable or
                not item.verified_at or not item.external_id_evidence_id or
                not item.external_id_hash or objects.active_reservation(item.id) != run_id):
            raise ValueError("Verified API batch object reservation is missing")
        for predicate, value in (("created_by", item.creator_identity_id),
                                 ("resource_tenant", item.tenant_id), ("disposable", "true")):
            if not any(fact.target_ref == package.target.id and
                       fact.status is FactStatus.ACTIVE and fact.source != "MANUAL" and
                       fact.confidence >= 0.9 and fact.evidence_ids and fact.object == value
                       for fact in evidence.find_facts(item.id, predicate, limit=8).items):
                raise ValueError("Verified API batch object facts are missing")
        try:
            external = evidence.read_content(item.external_id_evidence_id,
                         allow_sensitive=True, max_bytes=256).decode("ascii")
            if hashlib.sha256((item.id + ":" + external).encode()).hexdigest() != item.external_id_hash:
                raise ValueError
        except (ValueError, UnicodeError, PermissionError):
            raise ValueError("API batch object identifier integrity failed") from None
        resolved[field] = item, external
    primary, first_id = resolved["test_object_id"]
    source_companion, second_id = resolved["source_companion_id"]
    companion, companion_id = resolved["companion_object_id"]
    if (primary.id == source_companion.id or
            primary.creator_identity_id != source_companion.creator_identity_id or
            primary.tenant_id != source_companion.tenant_id or
            (shape["variant"] == "FOREIGN" and (
                companion.id in {primary.id, source_companion.id} or
                companion.tenant_id == primary.tenant_id or
                companion.creator_identity_id == primary.creator_identity_id)) or
            (shape["variant"] != "FOREIGN" and companion.id != source_companion.id)):
        raise ValueError("API batch ownership binding is invalid")
    exchange = traffic.get_exchange(shape["source_exchange_id"])
    if (exchange is None or exchange.target_id != package.target.id or
            exchange.package_id != package.id or exchange.state is not ExchangeState.COMPLETE or
            exchange.scope_result is not ScopeResult.IN_SCOPE or exchange.response is None or
            exchange.attribution.auth_state is not AuthState.VERIFIED or
            exchange.attribution.verified_identity_id != primary.creator_identity_id or
            exchange.request.record.method != "POST" or
            exchange.request.origin + exchange.request.display_path != operation.endpoint or
            exchange.response.record.status_code != 200):
        raise ValueError("Verified API batch owner control is unavailable")
    request_ref = evidence.get_evidence(exchange.request.observation_evidence_id)
    body_ref = evidence.get_evidence(exchange.request.body_evidence_id) if exchange.request.body_evidence_id else None
    response_ref = evidence.get_evidence(exchange.response.body_evidence_id) if exchange.response.body_evidence_id else None
    if (request_ref is None or request_ref.target_ref != package.target.id or
            body_ref is None or body_ref.target_ref != package.target.id or
            response_ref is None or response_ref.target_ref != package.target.id or
            body_ref.redaction_status is not RedactionStatus.ORIGINAL or
            response_ref.redaction_status is not RedactionStatus.ORIGINAL or
            body_ref.content_size > 16384 or response_ref.content_size > 262144 or
            response_ref.content_hash != exchange.response.body_hash):
        raise ValueError("Protected API batch evidence is unavailable")
    try:
        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            value: dict[str, object] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError
                value[key] = item
            return value
        request = json.loads(evidence.read_content(request_ref.evidence_id,
                             allow_sensitive=True, max_bytes=16384), object_pairs_hook=unique_pairs)
        url = request["url"]
        parsed_url = urlsplit(url)
        if (not isinstance(url, str) or parsed_url.query or parsed_url.fragment or
                parsed_url.username or parsed_url.password or
                package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE):
            raise ValueError
        raw = evidence.read_content(body_ref.evidence_id, allow_sensitive=True, max_bytes=16384)
        if hashlib.sha256(raw).hexdigest() != exchange.request.body_hash:
            raise ValueError
        payload = json.loads(raw, object_pairs_hook=unique_pairs)
        parts = [payload] if shape["envelope"] == "NODES_LIST" else payload
        if (not isinstance(parts, list) or len(parts) != (
                1 if shape["envelope"] == "NODES_LIST" else 2) or
                any(not isinstance(part, dict) or set(part) !=
                    {"query", "variables", "operationName"} or
                    not isinstance(part["query"], str) or
                    hashlib.sha256(part["query"].encode()).hexdigest() != operation.version_hash or
                    part["operationName"] != operation.name or
                    not isinstance(part["variables"], dict) or
                    set(part["variables"]) != {shape["variable_name"]}
                    for part in parts) or
                any(part["query"] != parts[0]["query"] for part in parts)):
            raise ValueError
        binding = (single_nodes_ids_variable(parts[0]["query"]) if
                   shape["envelope"] == "NODES_LIST" else
                   single_node_id_binding(parts[0]["query"]))
        if binding != (shape["variable_name"], shape["root_key"]):
            raise ValueError
        observed = (parts[0]["variables"][shape["variable_name"]] if
                    shape["envelope"] == "NODES_LIST" else
                    [part["variables"][shape["variable_name"]] for part in parts])
        if not isinstance(observed, list) or len(observed) != 2:
            raise ValueError
        if shape["id_type"] == "PLAIN":
            if observed != [first_id, second_id]:
                raise ValueError
        elif (observed_global_id_type(observed[0], first_id) != shape["id_type"] or
              observed_global_id_type(observed[1], second_id) != shape["id_type"]):
            raise ValueError
        response_raw = evidence.read_content(response_ref.evidence_id,
                                             allow_sensitive=True, max_bytes=262144)
        if hashlib.sha256(response_raw).hexdigest() != exchange.response.body_hash:
            raise ValueError
        response = json.loads(response_raw, object_pairs_hook=unique_pairs)
        if len(graphql_batch_values(response, shape["root_key"], frozenset(
                hashlib.sha256(value.encode()).hexdigest() for value in observed),
                envelope=shape["envelope"])) != 2:
            raise ValueError
    except (KeyError, IndexError, TypeError, ValueError, UnicodeError, PermissionError):
        raise ValueError("Observed GraphQL batch cannot be bound safely") from None
    def encoded(value: str) -> str:
        return (value if shape["id_type"] == "PLAIN" else
                encode_observed_global_id(shape["id_type"], value))
    replacement = observed
    if shape["variant"] == "INVALID_OBJECT":
        replacement = [
            encoded(str(uuid.uuid5(uuid.NAMESPACE_URL, run_id + ":" + item.id)))
            for item in (primary, source_companion)]
    elif shape["variant"] == "FOREIGN":
        replacement = [encoded(companion_id), encoded(first_id)]
    if shape["envelope"] == "NODES_LIST":
        parts[0]["variables"][shape["variable_name"]] = replacement
    else:
        for part, value in zip(parts, replacement):
            part["variables"][shape["variable_name"]] = value
    return (RequestTemplate("POST", url, (("Content-Type", "application/json"),),
                            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()),
            primary.external_id_hash)
