"""Existing-data-first API/GraphQL inventory and bounded authorization hypotheses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import binascii
import hashlib
import json
import re
import uuid
from urllib.parse import urlsplit, urlunsplit

from .api_graphql import (GraphQLField, extract_js_api_page, graphql_batch_values,
                          observed_field_selection_pair, observed_global_id_type,
                          nested_child_values, parse_operations,
                          single_node_id_binding, single_nodes_ids_variable)
from .api_registry import (APICandidate, APIInventoryProgress, APIOperation,
                           APIOperationRegistry, APIOperationType)
from .authorization import (AuthorizationActor, AuthorizationObject, AuthorizationOperation,
                            AuthorizationSpecialist, AuthorizationSurface)
from .authorization_store import (AuthorizationMode, Boundary, HuntStatus,
                                  candidate_dedupe_key)
from .behaviour import BehaviourStore
from .domxss_store import DOMXSSStore
from .hypotheses import Hypothesis, HypothesisSource, HypothesisStatus
from .object_recipes import ObjectRecipe
from .plan_runs import RunStatus
from .skill_plans import APIReadPlanBinding, TypedMutationPlanBinding
from .evidence import FactStatus, RedactionStatus
from .recon import Page, ReconRepository
from .response_compare import ResponseComparator
from .store import EvidenceFactStore
from .target_package import PackageStatus, TargetPackage
from .target_recon import ReconDomainResolver, resolve_recon_target
from .target_policy import PolicyDecision
from .target_scope import ScopeResult
from .test_objects import ObjectState, TestObject
from .traffic import AuthState, ExchangeState, TrafficExchange, TrafficStore
from .typed_mutations import MutationType
from .validation_store import ValidationStatus


_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_RISK_FIELD = re.compile(r"(?:role|owner|tenant|is_admin|permissions|status|isAdmin|"
                         r"can_?(?:share|edit|admin)|privilege|access_level)", re.I)
_FUNCTION = re.compile(r"(?:export|integration|admin|settings|member|invite|run|test)", re.I)
_JS_API_HINT = re.compile(rb"\b(?:query|mutation|subscription|fragment)\s+[A-Za-z_]"
                          rb"|\b(?:gql|graphql)\s*`|/api/")


def _hash(*values: str) -> str:
    return hashlib.sha256("\x00".join(values).encode()).hexdigest()


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate API JSON key")
        output[key] = value
    return output


@dataclass(frozen=True, slots=True)
class APIAnalysisLimits:
    traffic: int = 100
    js_assets: int = 30
    recon_surfaces: int = 12
    candidates: int = 24

    def __post_init__(self) -> None:
        for value, bound in ((self.traffic, 150), (self.js_assets, 50),
                             (self.recon_surfaces, 20), (self.candidates, 40)):
            if type(value) is not int or not 1 <= value <= bound:
                raise ValueError("API analysis limit is invalid")


@dataclass(frozen=True, slots=True)
class _BatchControls:
    owner: AuthorizationActor
    actor: AuthorizationActor
    owner_objects: tuple[AuthorizationObject, AuthorizationObject]
    actor_objects: tuple[AuthorizationObject, AuthorizationObject]
    owner_exchange: TrafficExchange
    actor_exchange: TrafficExchange
    variable_name: str
    root_key: str
    id_type: str
    envelope: str


@dataclass(frozen=True, slots=True)
class _DeleteControls:
    owner: AuthorizationActor
    actor: AuthorizationActor
    target: AuthorizationObject
    control: AuthorizationObject
    source: TrafficExchange
    recipe: ObjectRecipe


class APISpecialist:
    def __init__(self, *, registry: APIOperationRegistry, traffic: TrafficStore,
                 evidence: EvidenceFactStore, js: DOMXSSStore,
                 behaviour: BehaviourStore | None = None,
                 recon: ReconRepository | None = None,
                 authorization: AuthorizationSpecialist | None = None) -> None:
        self.registry = registry
        self.traffic = traffic
        self.evidence = evidence
        self.js = js
        self.behaviour = behaviour
        self.recon = recon
        self.authorization = authorization
        self.comparator = ResponseComparator(evidence)

    def _trusted_field_expectation(self, package: TargetPackage, object_id: str | None,
                                   field_path: str | None) -> bool:
        auth = self.authorization
        if auth is None or not object_id or not field_path:
            return False
        item = auth.objects.get(object_id, package.target.id)
        if item is None or not item.verified_at or not item.disposable:
            return False
        try:
            subject = hashlib.sha256(auth._external_id(item).encode()).hexdigest()
        except (ValueError, UnicodeError, PermissionError):
            return False
        field_name = field_path.rsplit("/", 1)[-1]
        def trusted(predicate: str, expected: str) -> bool:
            return any(fact.target_ref == package.target.id and
                       fact.status is FactStatus.ACTIVE and fact.source != "MANUAL" and
                       fact.confidence >= 0.9 and fact.evidence_ids and
                       fact.object == expected for fact in
                       self.evidence.find_facts(subject, predicate, limit=8).items)
        return trusted("data_classification", "SENSITIVE") and (
            trusted("field_visibility", field_name) or
            any(fact.target_ref == package.target.id and
                fact.status is FactStatus.ACTIVE and fact.source != "MANUAL" and
                fact.confidence >= 0.9 and fact.evidence_ids and
                fact.object.startswith(field_name + ":") for fact in
                self.evidence.find_facts(subject, "field_visibility", limit=8).items))

    def _trusted_private_boundary(self, package: TargetPackage,
                                  item: AuthorizationObject | None) -> bool:
        auth = self.authorization
        if auth is None or item is None:
            return False
        record = auth.objects.get(item.id, package.target.id)
        if record is None or not record.verified_at or not record.disposable:
            return False
        try:
            subject = hashlib.sha256(auth._external_id(record).encode()).hexdigest()
        except (ValueError, UnicodeError, PermissionError):
            return False
        for predicate, expected in (
                ("resource_visibility", {"PRIVATE"}),
                ("resource_tenant", {item.tenant_id}),
                ("access_policy", {"OWNER_ONLY", "TENANT_ONLY"})):
            if not any(fact.target_ref == package.target.id and
                       fact.status is FactStatus.ACTIVE and fact.source != "MANUAL" and
                       fact.confidence >= 0.9 and fact.object in expected and
                       fact.evidence_ids and all(
                           (evidence := self.evidence.get_evidence(ref)) is not None and
                           evidence.target_ref == package.target.id
                           for ref in fact.evidence_ids)
                       for fact in self.evidence.find_facts(subject, predicate, limit=8).items):
                return False
        return True

    def _nested_child(self, package: TargetPackage, operation: APIOperation,
                      owner_exchange_id: str | None, parent_id: str | None,
                      objects: dict[str, AuthorizationObject]) -> tuple[str | None, str | None]:
        auth = self.authorization
        if (auth is None or operation.type is not APIOperationType.GRAPHQL_QUERY or
                not owner_exchange_id or not parent_id):
            return None, None
        exchange = self.traffic.get_exchange(owner_exchange_id)
        response = exchange.response if exchange else None
        ref = self.evidence.get_evidence(response.body_evidence_id) if response and response.body_evidence_id else None
        if (ref is None or ref.target_ref != package.target.id or
                ref.redaction_status is not RedactionStatus.ORIGINAL or
                ref.content_size > 262144 or ref.content_hash != response.body_hash):
            return None, None
        paths = tuple(dict.fromkeys(field.parent for field in operation.fields
                                    if field.name == "id" and field.parent.count("/") == 2))
        if not paths:
            return None, None
        parent = auth.objects.get(parent_id, package.target.id)
        if parent is None:
            return None, None
        try:
            parent_hash = hashlib.sha256(auth._external_id(parent).encode()).hexdigest()
            body = json.loads(self.evidence.read_content(ref.evidence_id,
                              allow_sensitive=True, max_bytes=262144),
                              object_pairs_hook=_unique_pairs)
        except (ValueError, TypeError, UnicodeError, PermissionError):
            return None, None
        def trusted(subject: str, predicate: str, expected: str) -> bool:
            return any(fact.target_ref == package.target.id and
                       fact.status is FactStatus.ACTIVE and fact.source != "MANUAL" and
                       (predicate != "belongs_to" or fact.source in {
                           "OBJECT_FACTORY", "NORMAL_BEHAVIOUR_LEARNER", "FIXTURE"}) and
                       fact.confidence >= 0.9 and fact.evidence_ids and
                       fact.object == expected for fact in
                       self.evidence.find_facts(subject, predicate, limit=8).items)
        for child in sorted(objects.values(), key=lambda item: item.id):
            if (child.parent_id != parent_id or child.tenant_id != parent.tenant_id or
                    child.owner_identity_id != parent.creator_identity_id):
                continue
            record = auth.objects.get(child.id, package.target.id)
            if record is None or not record.disposable or not record.verified_at or (
                    not trusted(child.id, "belongs_to", parent_id)):
                continue
            try:
                child_hash = hashlib.sha256(auth._external_id(record).encode()).hexdigest()
            except (ValueError, UnicodeError, PermissionError):
                continue
            if (not trusted(child_hash, "resource_visibility", "PRIVATE") or
                    not (trusted(child_hash, "access_policy", "TENANT_ONLY") or
                         trusted(child_hash, "access_policy", "OWNER_ONLY")) or
                    not trusted(child_hash, "resource_tenant", child.tenant_id)):
                continue
            for path in paths[:6]:
                if nested_child_values(body, path, parent_hash, child_hash):
                    return child.id, path
        return None, None

    def _response_body(self, exchange: TrafficExchange) -> object | None:
        response = exchange.response
        ref = self.evidence.get_evidence(response.body_evidence_id) if response and response.body_evidence_id else None
        if (ref is None or ref.target_ref != exchange.target_id or
                ref.redaction_status is not RedactionStatus.ORIGINAL or
                ref.content_size > 262144 or ref.content_hash != response.body_hash):
            return None
        try:
            return json.loads(self.evidence.read_content(ref.evidence_id,
                              allow_sensitive=True, max_bytes=262144),
                              object_pairs_hook=_unique_pairs)
        except (ValueError, TypeError, UnicodeError, PermissionError):
            return None

    def _delete_controls(self, package: TargetPackage, operation: APIOperation,
                         surface: AuthorizationSurface | None) -> _DeleteControls | None:
        auth = self.authorization
        if (auth is None or auth.factory is None or surface is None or
                operation.type is not APIOperationType.REST or
                operation.method != "DELETE" or operation.state != "CURRENT" or
                operation.package_id != package.id):
            return None
        actors = {item.identity_id: item for item in surface.actors if item.session_id}
        current = {item.id: item for item in surface.objects if
                   (record := auth.objects.get(item.id, package.target.id)) is not None and
                   record.state is ObjectState.READY}
        if len(current) < 2:
            return None
        recent_sources: tuple[TestObject, ...] | None = None
        for ref in operation.exchange_ids[:16]:
            exchange = self.traffic.get_exchange(ref)
            if (exchange is None or exchange.target_id != package.target.id or
                    exchange.package_id != package.id or
                    exchange.state is not ExchangeState.COMPLETE or
                    exchange.scope_result is not ScopeResult.IN_SCOPE or
                    exchange.request.record.method != "DELETE" or
                    exchange.response is None or
                    exchange.response.record.status_code not in {200, 202, 204} or
                    exchange.attribution.auth_state is not AuthState.VERIFIED):
                continue
            source_url = self._request_url(exchange)
            if not source_url or package.scope.evaluate_url(source_url).result is not ScopeResult.IN_SCOPE:
                continue
            linked_source = auth.objects.find_cleaned_by_delete_exchange(
                package.target.id, ref)
            if linked_source is not None:
                sources = (linked_source,)
            else:
                if recent_sources is None:
                    recent_sources = auth.objects.list_for_target(
                        package.target.id, limit=50,
                        state=ObjectState.CLEANED).items
                sources = recent_sources
            for source in sources:
                if (source.package_id != package.id or not source.disposable or
                        not source.verified_at or not source.external_id_hash or
                        source.creator_identity_id != exchange.attribution.verified_identity_id or
                        source.creator_identity_id not in actors):
                    continue
                recipe = auth.factory.recipes.get(package.id, source.recipe_id)
                if (recipe is None or recipe.sha256 != source.recipe_hash or
                        recipe.cleanup is None or recipe.cleanup.method != "DELETE" or
                        not any(mutation.mutation_type is MutationType.DELETE_DISPOSABLE and
                                mutation.write == recipe.cleanup and
                                mutation.readback == recipe.verify for mutation in recipe.mutations)):
                    continue
                try:
                    expected_url = recipe.cleanup.template(
                        test_name=source.test_name,
                        object_id=auth._external_id(source)).url
                except (ValueError, UnicodeError, PermissionError):
                    continue
                if source_url != expected_url:
                    continue
                owner = actors[source.creator_identity_id]
                owned = [item for item in current.values() if
                         item.owner_identity_id == owner.identity_id and
                         item.tenant_id == source.tenant_id and
                         item.object_type == source.object_type and
                         (record := auth.objects.get(item.id, package.target.id)) is not None and
                         record.recipe_id == source.recipe_id and
                         record.recipe_hash == source.recipe_hash and
                         record.parent_id == source.parent_id]
                if len(owned) < 2:
                    continue
                if source.tenant_id not in owner.observed_tenants:
                    continue
                target = next((item for item in owned if
                               self._trusted_private_boundary(package, item)), None)
                control = next((item for item in owned if target is not None and
                                item.id != target.id and
                                self._trusted_private_boundary(package, item)), None)
                actor = next((item for item in actors.values() if
                              item.identity_id != owner.identity_id and
                              item.observed_tenants and
                              target is not None and
                              target.tenant_id not in item.tenants and
                              target.tenant_id not in item.observed_tenants), None)
                if target is not None and control is not None and actor is not None:
                    return _DeleteControls(owner, actor, target, control, exchange, recipe)
        return None

    def _batch_controls(self, package: TargetPackage, operation: APIOperation,
                        surface: AuthorizationSurface | None) -> _BatchControls | None:
        auth = self.authorization
        if (auth is None or surface is None or operation.type is not APIOperationType.GRAPHQL_QUERY
                or operation.method != "POST" or operation.state != "CURRENT" or
                operation.package_id != package.id):
            return None
        actors = {item.identity_id: item for item in surface.actors if item.session_id}
        by_external: dict[str, AuthorizationObject | None] = {}
        for item in surface.objects[:30]:
            record = auth.objects.get(item.id, package.target.id)
            if record is None or not record.disposable or not record.verified_at:
                continue
            try:
                external = auth._external_id(record)
                by_external[external] = (item if external not in by_external else None)
            except (ValueError, UnicodeError, PermissionError):
                continue
        controls: list[tuple[AuthorizationActor, tuple[AuthorizationObject, AuthorizationObject],
                             TrafficExchange, str, str, str, str]] = []
        for exchange_id in operation.exchange_ids[:16]:
            exchange = self.traffic.get_exchange(exchange_id)
            if (exchange is None or exchange.package_id != package.id or
                    exchange.target_id != package.target.id or
                    exchange.state is not ExchangeState.COMPLETE or
                    exchange.scope_result is not ScopeResult.IN_SCOPE or
                    exchange.response is None or
                    exchange.attribution.auth_state is not AuthState.VERIFIED or
                    exchange.request.record.method != "POST" or
                    exchange.request.origin + exchange.request.display_path != operation.endpoint):
                continue
            actor = actors.get(exchange.attribution.verified_identity_id or "")
            payload = self._request_body(exchange)
            if actor is None:
                continue
            envelope = "NODES_LIST" if isinstance(payload, dict) else "OPERATION_ARRAY"
            parts = (payload,) if isinstance(payload, dict) else payload
            if (not isinstance(parts, (tuple, list)) or
                    len(parts) != (1 if envelope == "NODES_LIST" else 2) or
                    any(not isinstance(part, dict) or
                        set(part) != {"query", "variables", "operationName"} or
                        not isinstance(part["query"], str) or
                        hashlib.sha256(part["query"].encode()).hexdigest() != operation.version_hash or
                        part["operationName"] != operation.name or
                        not isinstance(part["variables"], dict) or
                        len(part["variables"]) != 1 for part in parts)):
                continue
            binding = (single_nodes_ids_variable(parts[0]["query"]) if
                       envelope == "NODES_LIST" else
                       single_node_id_binding(parts[0]["query"]))
            if (binding is None or binding[0] not in operation.variables or
                    any(part["query"] != parts[0]["query"] for part in parts)):
                continue
            variable, root = binding
            values = (parts[0]["variables"].get(variable) if envelope == "NODES_LIST"
                      else [part["variables"].get(variable) for part in parts])
            if (not isinstance(values, list) or len(values) != 2 or
                    any(not isinstance(value, str) or len(value) > 256 for value in values) or
                    values[0] == values[1]):
                continue
            matched: list[AuthorizationObject] = []
            id_types: list[str] = []
            for value in values:
                matches = [(item, "PLAIN" if value == external else
                            observed_global_id_type(value, external))
                           for external, item in by_external.items() if item is not None]
                matches = [(item, typename) for item, typename in matches if typename]
                if len(matches) != 1:
                    break
                matched.append(matches[0][0])
                id_types.append(matches[0][1])
            if (len(matched) != 2 or matched[0].id == matched[1].id or
                    id_types[0] != id_types[1] or
                    any(item.owner_identity_id != actor.identity_id or
                        item.tenant_id not in actor.observed_tenants for item in matched) or
                    matched[0].tenant_id != matched[1].tenant_id):
                continue
            response = self._response_body(exchange)
            if (exchange.response.record.status_code != 200 or
                    len(graphql_batch_values(response, root,
                                             frozenset(_hash(value) for value in values),
                                             envelope=envelope)) != 2):
                continue
            controls.append((actor, (matched[0], matched[1]), exchange,
                             variable, root, id_types[0], envelope))
        controls.sort(key=lambda control: self._trusted_private_boundary(
            package, control[1][0]), reverse=True)
        for owner, owned, owner_exchange, variable, root, id_type, envelope in controls:
            for actor, actor_owned, actor_exchange, other_var, other_root, other_type, other_envelope in controls:
                if (owner.identity_id != actor.identity_id and
                        owned[0].tenant_id != actor_owned[0].tenant_id and
                        owned[0].tenant_id not in actor.observed_tenants and
                        variable == other_var and root == other_root and
                        id_type == other_type and envelope == other_envelope):
                    return _BatchControls(owner, actor, owned, actor_owned,
                                          owner_exchange, actor_exchange,
                                          variable, root, id_type, envelope)
        return None

    def _safe_endpoint(self, package: TargetPackage, url: str) -> str | None:
        try:
            parsed = urlsplit(url)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname or
                    parsed.username or parsed.password or
                    package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE):
                return None
            endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
            return endpoint if package.scope.evaluate_url(endpoint).result is ScopeResult.IN_SCOPE else None
        except ValueError:
            return None

    def record_manual_hint(self, package: TargetPackage, *, endpoint: str,
                           evidence_id: str, name: str = "ManualAPI",
                           method: str = "UNKNOWN") -> APIOperation:
        """Keep researcher context as a non-executable, evidence-linked inventory hint."""
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("API hint requires a tracked package")
        evidence = self.evidence.get_evidence(evidence_id)
        if evidence is None or evidence.target_ref != package.target.id:
            raise ValueError("API hint evidence must belong to the target")
        parsed = urlsplit(endpoint)
        scoped = self._safe_endpoint(package, endpoint)
        if (scoped is None or scoped != endpoint or parsed.query or parsed.fragment or
                method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "UNKNOWN"}):
            raise ValueError("API hint endpoint or method is invalid")
        return self.registry.upsert_operation(
            target_id=package.target.id, package_id=package.id, name=name,
            kind=APIOperationType.UNKNOWN, endpoint=scoped, method=method,
            version_hash=_hash("MANUAL", evidence_id, scoped, method, name),
            feature=self._feature(parsed.path, name), evidence_ids=(evidence_id,),
            source_refs=("MANUAL:" + evidence_id,),
            observed_at=evidence.observed_at.isoformat())

    def _request_url(self, exchange: TrafficExchange) -> str | None:
        try:
            raw = self.evidence.read_content(exchange.request.observation_evidence_id,
                                             allow_sensitive=True, max_bytes=16384)
            value = json.loads(raw, object_pairs_hook=_unique_pairs)
            return value.get("url") if isinstance(value, dict) and isinstance(value.get("url"), str) else None
        except (ValueError, TypeError, UnicodeError, PermissionError, KeyError):
            return None

    def _request_body(self, exchange: TrafficExchange) -> object | None:
        ref = exchange.request.body_evidence_id
        record = self.evidence.get_evidence(ref) if ref else None
        if (record is None or record.target_ref != exchange.target_id or
                record.redaction_status is not RedactionStatus.ORIGINAL or
                record.content_size > 16384):
            return None
        try:
            raw = self.evidence.read_content(ref, allow_sensitive=True, max_bytes=16384)
            if hashlib.sha256(raw).hexdigest() != exchange.request.body_hash:
                return None
            return json.loads(raw, object_pairs_hook=_unique_pairs)
        except (ValueError, TypeError, UnicodeError, PermissionError):
            return None

    def _field_actor_control(self, package: TargetPackage, operation: APIOperation,
                             owner_source: AuthorizationOperation,
                             boundary: AuthorizationActor,
                             objects: dict[str, AuthorizationObject],
                             surface: AuthorizationSurface,
                             field_path: str
                             ) -> tuple[AuthorizationOperation, APIOperation] | None:
        if operation.type is not APIOperationType.GRAPHQL_QUERY or not field_path:
            return None
        owner_exchange = self.traffic.get_exchange(owner_source.exchange_id)
        owner_body = self._request_body(owner_exchange) if owner_exchange else None
        if not isinstance(owner_body, dict) or not isinstance(owner_body.get("query"), str):
            return None
        for source in surface.operations:
            item = objects.get(source.object_id)
            if (not source.semantic_owner_success or source.method != "POST" or
                    source.graphql_kind != "QUERY" or source.owner_identity_id != boundary.identity_id or
                    source.variable_name != owner_source.variable_name or
                    item is None or item.tenant_id not in boundary.observed_tenants or
                    source.origin + source.display_path != operation.endpoint):
                continue
            exchange = self.traffic.get_exchange(source.exchange_id)
            body = self._request_body(exchange) if exchange else None
            document = body.get("query") if isinstance(body, dict) else None
            if (not isinstance(document, str) or
                    body.get("operationName") != operation.name or
                    not observed_field_selection_pair(owner_body["query"], document,
                                                       field_path)):
                continue
            actor_operation = self.registry.find_current_operation(
                package.target.id, endpoint=operation.endpoint, method="POST",
                name=operation.name, kind=APIOperationType.GRAPHQL_QUERY,
                version_hash=hashlib.sha256(document.encode()).hexdigest())
            if (actor_operation is not None and
                    source.exchange_id in actor_operation.exchange_ids):
                return source, actor_operation
        return None

    def _observed_fields(self, exchange: TrafficExchange, fields: tuple[GraphQLField, ...],
                         identity: str | None, roles: tuple[str, ...]) -> tuple[GraphQLField, ...]:
        response = exchange.response
        ref = self.evidence.get_evidence(response.body_evidence_id) if response and response.body_evidence_id else None
        if (ref is None or ref.target_ref != exchange.target_id or
                ref.redaction_status is not RedactionStatus.ORIGINAL or ref.content_size > 262144):
            return fields
        try:
            raw = self.evidence.read_content(ref.evidence_id, allow_sensitive=True,
                                             max_bytes=262144)
            if hashlib.sha256(raw).hexdigest() != response.body_hash:
                return fields
            body = json.loads(raw, object_pairs_hook=_unique_pairs)
            data = body.get("data") if isinstance(body, dict) else None
            if not isinstance(data, dict):
                return fields
            observed: list[GraphQLField] = []
            for field in fields:
                parent: object = data
                for name in field.parent.strip("/").split("/") if field.parent != "/" else ():
                    parent = parent.get(name) if isinstance(parent, dict) else None
                value = parent.get(field.alias or field.name) if isinstance(parent, dict) else None
                if value is None:
                    observed.append(field)
                    continue
                parent_type = parent.get("__typename") if isinstance(parent, dict) else None
                nested = value.get("__typename") if isinstance(value, dict) else None
                if isinstance(value, list):
                    nested = next((item.get("__typename") for item in value[:16]
                                   if isinstance(item, dict) and item.get("__typename")), None)
                observed.append(GraphQLField(
                    field.path, field.name, field.alias, field.parent, field.sensitivity,
                    parent_type if isinstance(parent_type, str) and _NAME.fullmatch(parent_type)
                    else "UNKNOWN",
                    nested if isinstance(nested, str) and _NAME.fullmatch(nested)
                    else "UNKNOWN",
                    (identity,) if identity else (), roles if identity else (), (ref.evidence_id,)))
            return tuple(observed)
        except (ValueError, TypeError, UnicodeError, PermissionError):
            return fields

    @staticmethod
    def _feature(path: str, name: str) -> str:
        for token in re.split(r"[^A-Za-z0-9_]+", path + "/" + name):
            if token.lower() in {"admin", "settings", "members", "billing", "exports",
                                 "integrations", "projects", "users", "files", "reports"}:
                return token.lower()
        return "other"

    def _ingest_traffic(self, package: TargetPackage, limit: int,
                        cursor: str | None = None,
                        authorization_surface: AuthorizationSurface | None = None,
                        ) -> tuple[int, tuple[str, ...], str | None]:
        target = package.target.id
        if authorization_surface is None and self.authorization:
            authorization_surface = self.authorization.profile(package)
        known_auth_exchanges = ({item.exchange_id for item in authorization_surface.operations}
                                if authorization_surface else set())
        owner_by_exchange = ({item.exchange_id: item for item in authorization_surface.operations
                              if item.semantic_owner_success and item.object_id}
                             if authorization_surface else {})
        known_object_tokens: set[str] = set()
        if self.authorization and authorization_surface:
            for item in authorization_surface.objects[:100]:
                record = self.authorization.objects.get(item.id, target)
                if record is None or not record.disposable or not record.verified_at:
                    continue
                try:
                    external = self.authorization._external_id(record)
                except (ValueError, UnicodeError, PermissionError):
                    continue
                known_object_tokens.add("{p:" + hashlib.sha256(external.encode()).hexdigest()[:12] + "}")
        hot = (self.traffic.list_exchanges_for_target(
            target, limit=min(10, limit // 5)).items if cursor and limit >= 5 else ())
        pending = list(hot)
        next_cursor = cursor
        while len(pending) < limit:
            page = self.traffic.list_exchanges_for_target(
                target, limit=min(limit - len(pending), 50), cursor=next_cursor)
            pending.extend(page.items)
            next_cursor = page.next_cursor
            if not page.items or next_cursor is None:
                break
        pending = list({item.id: item for item in pending}.values())
        pending.sort(key=lambda item: (item.observed_at, item.request.record.created_at))
        page = Page(tuple(pending), None)
        scanned = 0
        seen: set[str] = set()
        gaps: set[str] = set()
        while True:
            for exchange in page.items:
                scanned += 1
                if (exchange.package_id != package.id or exchange.state is not ExchangeState.COMPLETE
                        or exchange.scope_result is not ScopeResult.IN_SCOPE):
                    continue
                url = self._request_url(exchange)
                endpoint = self._safe_endpoint(package, url) if url else None
                if not endpoint:
                    continue
                # Collapse only verified fixture IDs; unknown hashed path segments stay distinct.
                path_shape = exchange.request.display_path
                for token in known_object_tokens:
                    path_shape = path_shape.replace(token, "{object_id}")
                endpoint = exchange.request.origin + path_shape
                method = exchange.request.record.method
                body = self._request_body(exchange)
                path = urlsplit(endpoint).path
                raw_path = urlsplit(url).path.lower()
                is_graphql = "graphql" in raw_path or (
                    isinstance(body, dict) and isinstance(body.get("query"), str))
                is_rpc = "rpc" in raw_path or "trpc" in raw_path
                if not (is_graphql or is_rpc or "/api/" in raw_path or
                        raw_path.startswith("/api") or exchange.request.record.operation_id or
                        exchange.id in known_auth_exchanges):
                    continue
                identity = (exchange.attribution.verified_identity_id if
                            exchange.attribution.auth_state is AuthState.VERIFIED else None)
                roles = exchange.attribution.declared_role_ids[:8] if identity else ()
                tenants = exchange.attribution.declared_tenant_ids[:8] if identity else ()
                refs = tuple(dict.fromkeys(exchange.evidence_ids))[:16]
                source = ("TRAFFIC:" + exchange.id,)
                payloads = body if isinstance(body, list) and len(body) <= 2 else (body,)
                for payload in payloads:
                    document = payload.get("query") if isinstance(payload, dict) else None
                    extension = payload.get("extensions") if isinstance(payload, dict) else None
                    persisted = (extension.get("persistedQuery") if isinstance(extension, dict)
                                 else None)
                    persisted_hash = (persisted.get("sha256Hash") if isinstance(persisted, dict)
                                      else None)
                    if not isinstance(persisted_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", persisted_hash):
                        persisted_hash = None
                    parsed = ()
                    if isinstance(document, str):
                        try:
                            parsed = parse_operations(document)
                        except ValueError:
                            gaps.add("SCHEMA_CONTEXT_MISSING")
                    if parsed:
                        for operation in parsed:
                            if isinstance(payload.get("operationName"), str) and (
                                    payload["operationName"] != operation.name):
                                continue
                            kind = APIOperationType("GRAPHQL_" + operation.kind)
                            version = hashlib.sha256(document.encode()).hexdigest()
                            key = _hash(endpoint, method, operation.name, version)
                            if key not in seen and len(seen) >= limit:
                                continue
                            seen.add(key)
                            global_id_type = None
                            owner_operation = owner_by_exchange.get(exchange.id)
                            if (operation.kind == "QUERY" and
                                    operation.root_fields == ("node",) and
                                    owner_operation and owner_operation.variable_name and
                                    isinstance(payload.get("variables"), dict) and
                                    self.authorization):
                                record = self.authorization.objects.get(
                                    owner_operation.object_id, target)
                                if record is not None and record.disposable and record.verified_at:
                                    try:
                                        known_id = self.authorization._external_id(record)
                                        global_id_type = observed_global_id_type(
                                            payload["variables"].get(owner_operation.variable_name),
                                            known_id)
                                    except (ValueError, UnicodeError, PermissionError):
                                        pass
                            self.registry.upsert_operation(
                                target_id=target, package_id=package.id, name=operation.name,
                                kind=kind, endpoint=endpoint, method=method, version_hash=version,
                                document_evidence_id=exchange.request.body_evidence_id,
                                persisted_hash=persisted_hash, variables=operation.variables,
                                input_types=operation.input_types,
                                fields=self._observed_fields(exchange, operation.fields,
                                                             identity, roles),
                                global_id_type=(global_id_type or "PLAIN") if owner_operation and
                                owner_operation.variable_name and operation.kind == "QUERY" and
                                operation.root_fields == ("node",) else None,
                                feature=self._feature(path, operation.name),
                                identity_ids=(identity,) if identity else (), role_ids=roles,
                                tenant_ids=tenants, exchange_ids=(exchange.id,), evidence_ids=refs,
                                source_refs=source, observed_at=exchange.observed_at.isoformat())
                    elif is_graphql and isinstance(payload, dict):
                        name = payload.get("operationName")
                        if not isinstance(name, str) or not _NAME.fullmatch(name):
                            gaps.add("OPERATION_DOCUMENT_MISSING")
                            continue
                        version = persisted_hash or _hash(endpoint, name, method)
                        key = _hash(endpoint, method, name, version)
                        if key not in seen and len(seen) >= limit:
                            continue
                        seen.add(key)
                        self.registry.upsert_operation(
                            target_id=target, package_id=package.id, name=name,
                            kind=APIOperationType.UNKNOWN, endpoint=endpoint, method=method,
                            version_hash=version, persisted_hash=persisted_hash,
                            variables=tuple(sorted(key for key in payload.get("variables", {})
                                if isinstance(key, str) and _NAME.fullmatch(key)))[:40]
                                if isinstance(payload.get("variables"), dict) else (),
                            feature=self._feature(path, name), identity_ids=(identity,) if identity else (),
                            role_ids=roles, tenant_ids=tenants, exchange_ids=(exchange.id,),
                            evidence_ids=refs, source_refs=source,
                            observed_at=exchange.observed_at.isoformat())
                    else:
                        name = exchange.request.record.operation_id or re.sub(
                            r"[^A-Za-z0-9_]", "_", method + "_" + path.strip("/"))[:120]
                        if not _NAME.fullmatch(name):
                            name = "ObservedAPI"
                        body_shape = (json.dumps({key: type(value).__name__ for key, value in
                                                  payload.items() if isinstance(key, str)},
                                                 sort_keys=True) if isinstance(payload, dict)
                                      else type(payload).__name__)
                        version = _hash(endpoint, method, name,
                                        ",".join(exchange.request.query_names),
                                        exchange.request.content_type or "", body_shape)
                        key = _hash(endpoint, method, name, version)
                        if key not in seen and len(seen) >= limit:
                            continue
                        seen.add(key)
                        fields = ()
                        variables = exchange.request.query_names[:40]
                        if isinstance(payload, dict):
                            variables = tuple(dict.fromkeys((*variables, *(key for key in payload
                                if isinstance(key, str) and _NAME.fullmatch(key)))))[:40]
                        kind = (APIOperationType.BULK_API if isinstance(body, list) or
                                "/bulk" in raw_path or "/batch" in raw_path else
                                APIOperationType.RPC if is_rpc else APIOperationType.REST)
                        self.registry.upsert_operation(
                            target_id=target, package_id=package.id, name=name, kind=kind,
                            endpoint=endpoint, method=method, version_hash=version,
                            variables=variables, fields=fields, feature=self._feature(path, name),
                            identity_ids=(identity,) if identity else (), role_ids=roles,
                            tenant_ids=tenants, exchange_ids=(exchange.id,), evidence_ids=refs,
                            source_refs=source, observed_at=exchange.observed_at.isoformat())
            if not page.next_cursor or scanned >= limit:
                break
            page = self.traffic.list_exchanges_for_target(target,
                limit=min(limit - scanned, 50), cursor=page.next_cursor)
        return len(seen), tuple(sorted(gaps)), next_cursor

    @staticmethod
    def _js_resume(cursor: str | None, target: str) -> tuple[str | None, str | None, int]:
        if cursor is None:
            return None, None, 0
        try:
            raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4),
                                   altchars=b"-_", validate=True)
            parts = json.loads(raw)
        except (ValueError, UnicodeError, binascii.Error):
            return cursor, None, 0
        if not isinstance(parts, list) or not parts or parts[0] != "API_JS_V1":
            return cursor, None, 0
        if (len(parts) != 5 or parts[1] != target or
                not isinstance(parts[2], str) or
                not re.fullmatch(r"DOMART-[0-9a-f]{32}", parts[2]) or
                parts[3] is not None and (not isinstance(parts[3], str) or
                                          len(parts[3]) > 512) or
                type(parts[4]) is not int or not 1 <= parts[4] <= 1024):
            raise ValueError("Invalid API JavaScript resume cursor")
        return parts[3], parts[2], parts[4]

    @staticmethod
    def _js_resume_token(target: str, asset_id: str,
                         before: str | None, offset: int) -> str:
        raw = json.dumps(["API_JS_V1", target, asset_id, before, offset],
                         separators=(",", ":")).encode()
        token = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        if len(token) > 512:
            raise ValueError("API JavaScript resume cursor exceeds bound")
        return token

    def _ingest_js(self, package: TargetPackage, limit: int,
                   cursor: str | None = None
                   ) -> tuple[int, tuple[str, ...], str | None]:
        target = package.target.id
        base_cursor, resume_asset, resume_offset = self._js_resume(cursor, target)
        count = 0
        gaps: set[str] = set()
        hot = (self.js.page_current_assets(target, limit=min(5, limit // 5))[0]
               if base_cursor and limit >= 5 else ())
        pending = []
        next_cursor = base_cursor
        while len(pending) < limit - len(hot):
            items, next_cursor = self.js.page_current_assets(
                target, limit=min(limit - len(hot) - len(pending), 50), cursor=next_cursor)
            pending.extend(items)
            if not items or next_cursor is None:
                break
        backlog_ids = {item.artifact_id for item in pending}
        pending = list({item.artifact_id: item for item in (*pending, *hot)}.values())
        processed_cursor = base_cursor
        for asset in pending:
            if count >= limit * 4:
                return count, tuple(sorted(gaps | {"JS_EXTRACTION_LIMIT"})), processed_cursor
            backlog = asset.artifact_id in backlog_ids
            before_asset = processed_cursor
            offset = resume_offset if backlog and asset.artifact_id == resume_asset else 0
            if asset.source != "FIXTURE":
                scoped = False
                if asset.retrieval_exchange_id:
                    capture = self.traffic.get_exchange(asset.retrieval_exchange_id)
                    url = self._request_url(capture) if capture else None
                    scoped = bool(capture and capture.target_id == target and
                                  capture.package_id == package.id and
                                  capture.scope_result is ScopeResult.IN_SCOPE and url and
                                  hashlib.sha256(url.encode()).hexdigest() == asset.asset_url_sha256 and
                                  self._safe_endpoint(package, url))
                elif asset.recon_asset_id and self.recon is not None:
                    try:
                        recon_target = resolve_recon_target(package, self.recon)
                        record = self.recon.get_js_asset(recon_target.domain_id, asset.recon_asset_id) \
                            if recon_target else None
                        scoped = bool(record and record.http_status == 200 and
                                      record.latest_sha256 == asset.artifact_sha256 and
                                      hashlib.sha256(record.asset_url.encode()).hexdigest() ==
                                      asset.asset_url_sha256 and
                                      self._safe_endpoint(package, record.asset_url))
                    except (ValueError, RuntimeError, OSError):
                        scoped = False
                if not scoped:
                    gaps.add("JS_SCOPE_UNVERIFIED")
                    if backlog:
                        processed_cursor = self.js.cursor_after_current_asset(asset)
                    continue
            try:
                body = self.evidence.read_content(asset.evidence_id, allow_sensitive=True,
                                                  max_bytes=1_048_576)
                if hashlib.sha256(body).hexdigest() != asset.artifact_sha256:
                    gaps.add("JS_BODY_HASH_MISMATCH")
                    if backlog:
                        processed_cursor = self.js.cursor_after_current_asset(asset)
                    continue
                if not _JS_API_HINT.search(body):
                    if backlog:
                        processed_cursor = self.js.cursor_after_current_asset(asset)
                    continue
            except (ValueError, PermissionError, KeyError):
                gaps.add("JS_BODY_UNAVAILABLE")
                if backlog:
                    processed_cursor = self.js.cursor_after_current_asset(asset)
                continue
            while True:
                try:
                    page = extract_js_api_page(body, offset=offset)
                except RuntimeError:
                    gaps.add("JS_EXTRACTION_UNAVAILABLE")
                    return count, tuple(sorted(gaps)), before_asset
                except ValueError:
                    gaps.add("JS_PARSE_FAILED")
                    break
                if page.truncated:
                    gaps.add("JS_EXTRACTION_TRUNCATED")
                for index, entry in enumerate(page.entries):
                    if entry.kind == "GRAPHQL":
                        try:
                            operations = parse_operations(entry.value)
                        except ValueError:
                            operations = ()
                        for operation in operations:
                            gaps.add("OPERATION_ENDPOINT_UNKNOWN")
                            self.registry.upsert_operation(
                                target_id=target, package_id=package.id, name=operation.name,
                                kind=APIOperationType("GRAPHQL_" + operation.kind), endpoint="",
                                method="POST", version_hash=hashlib.sha256(entry.value.encode()).hexdigest(),
                                document_evidence_id=asset.evidence_id, variables=operation.variables,
                                input_types=operation.input_types, fields=operation.fields,
                                feature=self._feature("", operation.name),
                                evidence_ids=(asset.evidence_id,), source_refs=("JS:" + asset.artifact_id,),
                                source_asset_hash=asset.artifact_sha256,
                                observed_at=asset.retrieved_at.isoformat())
                            count += 1
                    else:
                        assert entry.method is not None
                        name = "JS_" + entry.method + "_" + re.sub(
                            r"[^A-Za-z0-9_]", "_", entry.value.strip("/"))[:100]
                        self.registry.upsert_operation(
                            target_id=target, package_id=package.id, name=name,
                            kind=APIOperationType.REST, endpoint=entry.value,
                            method=entry.method,
                            version_hash=_hash("JS_ROUTE", entry.method, entry.value),
                            feature=self._feature(entry.value, name),
                            evidence_ids=(asset.evidence_id,),
                            source_refs=("JS:" + asset.artifact_id,),
                            source_asset_hash=asset.artifact_sha256,
                            observed_at=asset.retrieved_at.isoformat())
                        count += 1
                    remaining = index + 1 < len(page.entries) or page.next_offset is not None
                    if count >= limit * 4 and remaining:
                        position = entry.ordinal + 1
                        resume = (self._js_resume_token(target, asset.artifact_id,
                                                        before_asset, position)
                                  if backlog else processed_cursor)
                        return count, tuple(sorted(gaps | {"JS_EXTRACTION_LIMIT"})), resume
                if page.next_offset is None:
                    break
                offset = page.next_offset
            if backlog:
                processed_cursor = self.js.cursor_after_current_asset(asset)
        return count, tuple(sorted(gaps)), next_cursor

    def _ingest_recon(self, package: TargetPackage, limit: int) -> tuple[int, tuple[str, ...]]:
        if self.recon is None:
            return 0, ("RECON_UNAVAILABLE",)
        try:
            target = resolve_recon_target(package, self.recon)
        except (ValueError, RuntimeError, OSError):
            return 0, ("RECON_UNAVAILABLE",)
        if target is None:
            return 0, ("RECON_TARGET_MISSING",)
        count = 0
        try:
            hosts = ReconDomainResolver(self.recon).select_hosts(package).hosts
        except (ValueError, RuntimeError, OSError):
            hosts = ()
        host_ids: tuple[int | None, ...] = tuple(host.host_id for host in hosts) + (None,)
        seen: set[int] = set()
        for host_id in host_ids:
            for surface_type in ("GRAPHQL", "OPENAPI", "REST", "RPC"):
                try:
                    page = self.recon.list_api_surfaces(target.domain_id, surface_type,
                                                        host_id=host_id, limit=min(limit, 20))
                except (ValueError, RuntimeError, OSError):
                    continue
                for surface in page.items:
                    if surface.surface_id in seen:
                        continue
                    endpoint = self._safe_endpoint(package, surface.location)
                    if not endpoint:
                        continue
                    seen.add(surface.surface_id)
                    name = "Surface_" + surface_type
                    self.registry.upsert_operation(
                        target_id=package.target.id, package_id=package.id, name=name,
                        kind=APIOperationType.UNKNOWN, endpoint=endpoint, method="UNKNOWN",
                        version_hash=_hash(str(surface.surface_id), surface_type),
                        source_refs=("RECON_API_SURFACE:" + str(surface.surface_id),),
                        feature=self._feature(endpoint, name),
                        observed_at=surface.provenance.observed_at.isoformat()
                        if surface.provenance.observed_at else None)
                    count += 1
                    if count >= limit:
                        return count, ()
        return count, ()

    def profile(self, package: TargetPackage, *, limits: APIAnalysisLimits = APIAnalysisLimits(),
                _authorization_surface: AuthorizationSurface | None = None) -> dict[str, object]:
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("API specialist requires a tracked package")
        if _authorization_surface is not None and (
                not isinstance(_authorization_surface, AuthorizationSurface) or
                _authorization_surface.target_id != package.target.id or
                _authorization_surface.package_id != package.id):
            raise ValueError("Authorization snapshot does not match target package")
        progress = self.registry.progress(package.target.id, package.id)
        traffic_count, traffic_gaps, traffic_cursor = self._ingest_traffic(
            package, limits.traffic, progress.traffic_cursor,
            authorization_surface=_authorization_surface)
        js_count, js_gaps, js_cursor = self._ingest_js(
            package, limits.js_assets, progress.js_cursor)
        self.registry.expire_missing_js_operations(package.target.id)
        recon_count, recon_gaps = self._ingest_recon(package, limits.recon_surfaces)
        self.registry.save_progress(package.target.id, package.id, APIInventoryProgress(
            traffic_cursor, js_cursor, progress.operation_cursor))
        types = self.registry.operation_type_counts(package.target.id)
        return {"target_id": package.target.id,
                "counts": {"traffic_operations": traffic_count, "js_operations": js_count,
                           "recon_surfaces": recon_count, **self.registry.counts(package.target.id)},
                "gaps": sorted(set((*traffic_gaps, *js_gaps, *recon_gaps))),
                "inventory_more": {"traffic": traffic_cursor is not None,
                                   "js": js_cursor is not None},
                "surface_types": sorted(types),
                "queries": types.get("GRAPHQL_QUERY", 0),
                "mutations": types.get("GRAPHQL_MUTATION", 0)}

    def generate(self, package: TargetPackage, *, limits: APIAnalysisLimits = APIAnalysisLimits(),
                 mode: str = "PLAN_ONLY",
                 operation_id: str | None = None) -> tuple[APICandidate, ...]:
        if mode not in {"PLAN_ONLY", "BOUNDED_AUTONOMOUS"}:
            raise ValueError("Invalid API specialist mode")
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("API specialist requires a tracked package")
        authorization = self.authorization.profile(package) if self.authorization else None
        summary = self.profile(package, limits=limits,
                               _authorization_surface=authorization)
        target = package.target.id
        learned = self.behaviour.profile(target) if self.behaviour else None
        owner_by_exchange = ({item.exchange_id: item for item in authorization.operations
                             if item.semantic_owner_success} if authorization else {})
        object_by_id = ({item.id: item for item in authorization.objects} if authorization else {})
        actors = ({item.identity_id: item for item in authorization.actors} if authorization else {})
        if operation_id is not None:
            selected = self.registry.get_operation(target, operation_id)
            if selected is None or selected.package_id != package.id or selected.state != "CURRENT":
                raise ValueError("API operation is unavailable or stale")
            operations = (selected,)
        else:
            progress = self.registry.progress(target, package.id)
            backlog, page_cursor = self.registry.page_operations(
                target, limit=100, cursor=progress.operation_cursor)
            if not backlog and progress.operation_cursor is not None:
                backlog, page_cursor = self.registry.page_operations(target, limit=100)
            hot = (self.registry.list_operations(target, limit=1)
                   if progress.operation_cursor is not None and limits.candidates >= 12 else ())
            operations = tuple({item.id: item for item in (*hot, *backlog)}.values())
            backlog_ids = {item.id for item in backlog}
        candidates: list[APICandidate] = []
        last_backlog_processed: APIOperation | None = None
        for operation in operations:
            if len(candidates) >= limits.candidates:
                break
            if operation_id is None and operation.id in backlog_ids:
                last_backlog_processed = operation
            graphql_batch = (operation.type is APIOperationType.GRAPHQL_QUERY and
                any(field.parent == "/" and field.name == "nodes" for field in operation.fields))
            if operation.type is APIOperationType.GRAPHQL_QUERY and not graphql_batch:
                for ref in operation.exchange_ids[:16]:
                    exchange = self.traffic.get_exchange(ref)
                    body = self._request_body(exchange) if exchange else None
                    if isinstance(body, list) and len(body) == 2:
                        graphql_batch = True
                        break
            batch = self._batch_controls(package, operation, authorization) if graphql_batch else None
            delete = self._delete_controls(package, operation, authorization)
            owner_sources = [owner_by_exchange[ref] for ref in operation.exchange_ids
                             if ref in owner_by_exchange]
            owner_op = next((source for source in owner_sources if
                             self._trusted_private_boundary(
                                 package, object_by_id.get(source.object_id))),
                            owner_sources[0] if owner_sources else None)
            owned = object_by_id.get(owner_op.object_id) if owner_op else None
            owner = actors.get(owner_op.owner_identity_id) if owner_op else None
            foreign = next((actor for actor in actors.values()
                            if owned and actor.identity_id != owned.owner_identity_id
                            and actor.session_id and actor.observed_tenants
                            and owned.tenant_id not in actor.observed_tenants), None)
            actor_control = next((owner_by_exchange[ref] for ref in operation.exchange_ids
                                  if ref in owner_by_exchange and foreign is not None and
                                  owner_by_exchange[ref].owner_identity_id == foreign.identity_id and
                                  owner_by_exchange[ref].object_id in object_by_id and
                                  object_by_id[owner_by_exchange[ref].object_id].tenant_id in
                                  foreign.observed_tenants), None)
            if batch is not None:
                owned, owner, foreign = batch.owner_objects[0], batch.owner, batch.actor
                actor_control = batch.actor_exchange
            elif delete is not None:
                owned, owner, foreign = delete.target, delete.owner, delete.actor
            required_role = (self.authorization._role_restriction(target, owned)
                             if self.authorization and owned else None)
            lower_role = next((actor for actor in actors.values()
                               if owned and owner and required_role in owner.observed_roles and
                               actor.identity_id != owned.owner_identity_id
                               and actor.session_id and owned.tenant_id in actor.observed_tenants
                               and required_role not in actor.observed_roles), None)
            nested_child_id, nested_path = self._nested_child(
                package, operation, owner_op.exchange_id if owner_op else None,
                owned.id if owned else None, object_by_id)
            classes = []
            if (operation.type is APIOperationType.GRAPHQL_QUERY or
                    operation.type is APIOperationType.REST and operation.method in {"GET", "HEAD"}) and not graphql_batch:
                classes.append(("OBJECT_AUTH", None, 80 if operation.global_id_type and
                                operation.global_id_type not in {"CONFLICT", "PLAIN"} else 75))
            if (operation.type is APIOperationType.REST and
                    owner_op is not None and owned is not None and
                    self.authorization is not None and authorization is not None and
                    self.authorization._observed_parent_child(authorization, owned, owner_op)):
                classes.append(("NESTED_AUTH", None, 82))
            if operation.type is APIOperationType.GRAPHQL_QUERY and not graphql_batch:
                if any(item.sensitivity == "SENSITIVE_NAME" for item in operation.fields):
                    field = next(item.path for item in operation.fields
                                 if item.sensitivity == "SENSITIVE_NAME")
                    classes.append(("FIELD_AUTH", field, 85))
                if any(item.path.count("/") >= 3 for item in operation.fields):
                    classes.append(("NESTED_AUTH", nested_path, 83 if nested_child_id else 78))
            if graphql_batch:
                classes.append(("BATCH_AUTH", None, 84))
            if (operation.type in {APIOperationType.GRAPHQL_MUTATION, APIOperationType.REST} and
                    operation.method not in {"GET", "HEAD", "UNKNOWN"}):
                classes.append(("MUTATION_AUTH", None, 86))
                if any(_RISK_FIELD.search(name) for name in operation.variables):
                    classes.append(("MASS_ASSIGNMENT_CANDIDATE", None, 75))
            if operation.type is APIOperationType.BULK_API:
                classes.append(("BATCH_AUTH", None, 80))
            if _FUNCTION.search(operation.name + operation.endpoint):
                classes.append(("BFLA", None, 75))
            if operation.type is APIOperationType.UNKNOWN and not classes:
                classes.append(("OBJECT_AUTH", None, 40))
            for category, field_path, base in classes:
                if len(candidates) >= limits.candidates:
                    break
                boundary_actor = lower_role if category == "BFLA" else foreign
                field_control = (self._field_actor_control(
                    package, operation, owner_op, boundary_actor, object_by_id,
                    authorization, field_path) if category == "FIELD_AUTH" and
                    actor_control is None and owner_op is not None and
                    boundary_actor is not None and authorization is not None and
                    field_path is not None else None)
                learned_keys = ({item["key"] for item in learned.operations
                                 if any(ref in operation.exchange_ids for ref in item["exchange_ids"])}
                                if learned else set())
                role_gap = bool(learned and boundary_actor and any(
                    row.get("state") == "NOT_OBSERVED" and
                    row.get("role_id") in boundary_actor.observed_roles and
                    row.get("operation_key") in learned_keys
                    for row in learned.role_operation_matrix))
                observed_denial = bool(learned and boundary_actor and any(
                    row.get("operation_key") in learned_keys and
                    row.get("role_id") in boundary_actor.observed_roles and
                    isinstance(row.get("explicit_denials"), int) and
                    row["explicit_denials"] > 0 for row in learned.role_operation_matrix))
                configured_denial = bool(learned and boundary_actor and any(
                    row.get("status") == "CONFIGURED_EXPECTATION" and
                    row.get("expected_access") == "DENY" and
                    row.get("role_id") in boundary_actor.observed_roles and
                    row.get("feature") == operation.feature for row in learned.expected_access))
                gaps = []
                if not operation.endpoint or operation.method == "UNKNOWN":
                    gaps.append("OPERATION_DOCUMENT_MISSING" if operation.method == "UNKNOWN"
                                else "SCHEMA_CONTEXT_MISSING")
                if owned is None:
                    gaps.append("OBJECT_OWNERSHIP_UNKNOWN")
                if boundary_actor is None:
                    gaps.append("LOWER_ROLE_MISSING" if category == "BFLA" else
                                "SECOND_TENANT_MISSING")
                if owner_op is None and batch is None and not (delete and category == "MUTATION_AUTH"):
                    gaps.append("CONTROL_MISSING")
                if actor_control is None and field_control is None and category in {"OBJECT_AUTH", "FIELD_AUTH",
                                                          "NESTED_AUTH", "BATCH_AUTH"}:
                    gaps.append("ACTOR_OWNED_CONTROL_MISSING")
                if category == "FIELD_AUTH" and not self._trusted_field_expectation(
                        package, owned.id if owned else None, field_path):
                    gaps.append("FIELD_EXPECTATION_UNKNOWN")
                if (operation.type is APIOperationType.GRAPHQL_QUERY and not graphql_batch and
                        len({field.path for field in operation.fields if field.parent == "/"}) != 1):
                    gaps.append("EXACT_SINGLE_ROOT_REQUIRED")
                if category == "MUTATION_AUTH" and delete is None:
                    gaps.append("READBACK_MISSING")
                if (category == "BATCH_AUTH" and operation.type is APIOperationType.GRAPHQL_QUERY
                        and batch is None or
                        category == "NESTED_AUTH" and not nested_child_id and
                        operation.type is APIOperationType.GRAPHQL_QUERY):
                    gaps.append("EXACT_MULTI_OBJECT_BINDING_MISSING")
                if category == "BFLA" and not required_role:
                    gaps.append("REQUIRED_ROLE_EXPECTATION_MISSING")
                if (operation.type not in {APIOperationType.REST,
                                           APIOperationType.GRAPHQL_QUERY} or
                        operation.type is APIOperationType.REST and
                        operation.method not in {"GET", "HEAD"}) and not (
                        delete is not None and category == "MUTATION_AUTH"):
                    gaps.append("READ_BINDING_UNAVAILABLE")
                if operation.type is APIOperationType.UNKNOWN:
                    gaps.append("OPERATION_DOCUMENT_MISSING")
                if category == "MASS_ASSIGNMENT_CANDIDATE":
                    gaps.append("SAFE_DISPOSABLE_PROOF_REQUIRED")
                if operation.type is APIOperationType.GRAPHQL_SUBSCRIPTION:
                    gaps.append("NEEDS_RESEARCH")
                score = min(100, max(0, base + (8 if owned else -25) +
                                      (8 if boundary_actor else -15) + (4 if role_gap else 0) +
                                      (6 if observed_denial else 0) +
                                      (4 if configured_denial else 0) +
                                      (4 if operation.source_asset_hash else 0) -
                                      (12 if category in {"MUTATION_AUTH", "MASS_ASSIGNMENT_CANDIDATE"}
                                       else 0)))
                reasons = ["OBSERVED_OPERATION" if operation.exchange_ids else
                           "CURRENT_JS_OPERATION" if operation.source_asset_hash else "RECON_HINT_ONLY"]
                if owner_op or batch:
                    reasons.append("VERIFIED_OWNER_CONTROL")
                if batch:
                    reasons.append("OBSERVED_TWO_ID_OWNER_AND_ACTOR_CONTROLS")
                if delete is not None and category == "MUTATION_AUTH":
                    reasons.append("OBSERVED_REVIEWED_DISPOSABLE_DELETE")
                if operation.global_id_type and operation.global_id_type not in {"CONFLICT", "PLAIN"}:
                    reasons.append("OBSERVED_GLOBAL_ID_STRUCTURE_NOT_PROOF")
                elif operation.global_id_type == "CONFLICT":
                    gaps.append("GLOBAL_ID_STRUCTURE_CONFLICT")
                if role_gap:
                    reasons.append("NOT_OBSERVED_ROLE_GAP_NOT_DENIAL")
                if observed_denial:
                    reasons.append("OBSERVED_ROLE_DENIAL_NOT_PROOF")
                if configured_denial:
                    reasons.append("CONFIGURED_ROLE_DENIAL_EXPECTATION")
                if field_path:
                    reasons.append("VERIFIED_NESTED_CHILD_NOT_PROOF" if category == "NESTED_AUTH"
                                   else "SENSITIVE_FIELD_NAME_NOT_PROOF")
                if field_control is not None:
                    reasons.append("OBSERVED_FIELD_SELECTION_DIFFERENTIAL")
                status = "REVIEW" if category == "MASS_ASSIGNMENT_CANDIDATE" else (
                    "READY" if not gaps else "PLAN_ONLY")
                candidate = self.registry.upsert_candidate(APICandidate(
                    id="APIC-" + _hash(target, operation.id, category,
                                        boundary_actor.identity_id if boundary_actor else "",
                                        owned.id if owned else "",
                                        field_path or "")[:32],
                    target_id=target, operation_id=operation.id, category=category,
                    boundary_identity_id=boundary_actor.identity_id if boundary_actor else None,
                    owner_identity_id=owner.identity_id if owner else None,
                    test_object_id=owned.id if owned else None,
                    owner_exchange_id=(delete.source.id if delete is not None and
                                       category == "MUTATION_AUTH" else
                                       batch.owner_exchange.id if batch else
                                       owner_op.exchange_id if owner_op else None),
                    field_path=field_path, score=score, reasons=tuple(reasons),
                    gaps=tuple(dict.fromkeys(gaps)), status=status,
                    behaviour_run_id=learned.run_id if learned else None,
                    child_object_id=nested_child_id if category == "NESTED_AUTH" else None))
                candidates.append(candidate)
        if operation_id is None:
            next_operation_cursor = (
                self.registry.cursor_after_operation(last_backlog_processed)
                if last_backlog_processed is not None and last_backlog_processed != backlog[-1]
                else page_cursor if last_backlog_processed is not None else
                progress.operation_cursor)
            self.registry.save_progress(target, package.id, APIInventoryProgress(
                progress.traffic_cursor, progress.js_cursor, next_operation_cursor))
        auto_gaps: set[str] = set()
        if mode == "BOUNDED_AUTONOMOUS":
            if (package.rules.automated_testing_allowed is not True or
                    package.autonomy.bounded_active is not PolicyDecision.ALLOW or
                    package.autonomy.cross_identity_testing is not PolicyDecision.ALLOW):
                auto_gaps.add("AUTONOMOUS_POLICY_NOT_ALLOW")
            elif (self.authorization is None or self.authorization.orchestrator is None or
                  self.authorization.validator is None):
                auto_gaps.add("AUTONOMOUS_RUNTIME_UNAVAILABLE")
            else:
                for candidate in candidates:
                    operation = self.registry.get_operation(target, candidate.operation_id)
                    if (candidate.status != "READY" or candidate.gaps or operation is None or
                            candidate.category not in {"OBJECT_AUTH", "FIELD_AUTH"} or
                            not (operation.type is APIOperationType.REST and
                                     operation.method in {"GET", "HEAD"} or
                                     operation.type is APIOperationType.GRAPHQL_QUERY and
                                     operation.method in {"GET", "POST"})):
                        continue
                    prepared = self.prepare_candidate(package, candidate.id)
                    if prepared.status == "VALIDATED":
                        break  # The exact current boundary was already confirmed by Phase 19.
                    plan = (self.authorization.planner.store.get(prepared.plan_id, target)
                            if prepared.plan_id and self.authorization.planner else None)
                    if prepared.status != "PLANNED" or not plan or plan["request_budget"] > 5:
                        auto_gaps.add("AUTONOMOUS_PLAN_NOT_READY")
                        continue
                    detail = self.start_candidate(package, prepared.id)
                    for _ in range(12):
                        if detail["run"]["status"] not in {RunStatus.CREATED.value,
                                                            RunStatus.READY.value}:
                            break
                        detail = self.advance_candidate(package, prepared.id)
                    if detail["run"]["status"] != RunStatus.COMPLETED.value:
                        auto_gaps.add("AUTONOMOUS_RUN_REQUIRES_REVIEW")
                    break  # One observed, owner-bound read plan per call.
        self.registry.record_run(target, package.id, mode,
                                 {**summary["counts"], "candidates_generated": len(candidates)},
                                 tuple(sorted(set(summary["gaps"]) | auto_gaps)))
        return tuple(self.registry.get_candidate(target, item.id) for item in candidates)

    def _reuse_confirmed_object_boundary(self, package: TargetPackage,
                                         candidate: APICandidate,
                                         operation: APIOperation,
                                         source: AuthorizationOperation,
                                         owner: AuthorizationActor,
                                         boundary: AuthorizationActor,
                                         owned: AuthorizationObject) -> APICandidate | None:
        auth = self.authorization
        if (auth is None or auth.validator is None or
                candidate.category != "OBJECT_AUTH" or
                operation.type not in {APIOperationType.REST,
                                       APIOperationType.GRAPHQL_QUERY} or
                not operation.last_seen or not owner.session_id or
                not boundary.session_id or not self._trusted_private_boundary(package, owned)):
            return None
        if (source.exchange_id != candidate.owner_exchange_id or
                source.object_id != owned.id or
                source.owner_identity_id != owner.identity_id or
                not source.semantic_owner_success or source.method != operation.method or
                source.exchange_id not in operation.exchange_ids):
            return None
        if operation.type is APIOperationType.GRAPHQL_QUERY:
            if source.graphql_kind != "QUERY":
                return None
            auth_boundary = Boundary.GRAPHQL_OBJECT
        elif source.protocol == "REST" and operation.method in {"GET", "HEAD"}:
            auth_boundary = Boundary.CROSS_TENANT
        else:
            return None
        key = candidate_dedupe_key(package.target.id, auth_boundary.value, owned.id,
                                   source.key, boundary.identity_id)
        prior = auth.ledger.find_candidate_by_dedupe(package.target.id, key)
        if (prior is None or prior.status != "VALIDATED" or
                prior.owner_exchange_id != source.exchange_id or
                prior.test_object_id != owned.id or
                prior.owner_identity_id != owner.identity_id or
                prior.boundary_identity_id != boundary.identity_id or
                not prior.plan_id or not prior.run_id or not prior.validation_id):
            return None
        record = auth.objects.get(owned.id, package.target.id)
        run = auth.validator.runs.get(prior.run_id, package.target.id)
        result = auth.validator.results.get(prior.validation_id, package.target.id)
        if (record is None or record.state not in {ObjectState.READY,
                                                  ObjectState.CLEANUP_PENDING} or
                auth.objects.active_reservation(record.id) is not None or
                not record.disposable or not record.verified_at or
                run is None or run.status is not RunStatus.COMPLETED or
                run.package_id != package.id or run.plan_id != prior.plan_id or
                result is None or result.status is not ValidationStatus.CONFIRMED or
                result.run_id != run.id or result.plan_id != prior.plan_id or
                result.hypothesis_id != prior.hypothesis_id):
            return None
        try:
            if datetime.fromisoformat(result.created_at) < datetime.fromisoformat(operation.last_seen):
                return None
        except (TypeError, ValueError):
            return None
        return self.registry.link_candidate(
            package.target.id, candidate.id, status="VALIDATED",
            hypothesis_id=prior.hypothesis_id, plan_id=prior.plan_id,
            run_id=prior.run_id, validation_id=prior.validation_id,
            authorization_candidate_id=prior.id)

    def prepare_candidate(self, package: TargetPackage, candidate_id: str) -> APICandidate:
        """Create an immutable API read plan; no target request is sent here."""
        auth = self.authorization
        if auth is None or auth.context is None or auth.planner is None:
            raise ValueError("API planning dependencies are unavailable")
        self.registry.expire_missing_js_operations(package.target.id)
        candidate = self.registry.get_candidate(package.target.id, candidate_id)
        if candidate is None:
            raise LookupError("API candidate not found")
        operation = self.registry.get_operation(package.target.id, candidate.operation_id)
        if (operation is None or operation.package_id != package.id or
                operation.state != "CURRENT" or candidate.status == "STALE"):
            raise ValueError("API candidate operation is stale")
        if candidate.plan_id:
            return candidate
        if (candidate.category == "MUTATION_AUTH" and
                operation.type is APIOperationType.REST and operation.method == "DELETE"):
            return self._prepare_disposable_delete(package, candidate, operation)
        surface = auth.profile(package) if candidate.category == "OBJECT_AUTH" else None
        if surface is not None:
            actors = {item.identity_id: item for item in surface.actors}
            owner = actors.get(candidate.owner_identity_id or "")
            boundary = actors.get(candidate.boundary_identity_id or "")
            record = auth.objects.get(candidate.test_object_id or "", package.target.id)
            if (owner is not None and boundary is not None and record is not None and
                    record.creator_identity_id == owner.identity_id and
                    record.tenant_id in owner.observed_tenants and
                    record.tenant_id not in boundary.observed_tenants and
                    record.external_id_hash and candidate.owner_exchange_id):
                owned = AuthorizationObject(
                    record.id, record.object_type, record.creator_identity_id,
                    record.owner_principal_id, record.tenant_id, record.parent_id,
                    record.external_id_hash, record.verification_evidence_ids[:8], ())
                source = auth.observed_operation(package, owned, candidate.owner_exchange_id)
                if source is not None:
                    reused = self._reuse_confirmed_object_boundary(
                        package, candidate, operation, source, owner, boundary, owned)
                    if reused is not None:
                        return reused
        if (candidate.category == "BATCH_AUTH" and
                operation.type is APIOperationType.GRAPHQL_QUERY):
            return self._prepare_graphql_batch(package, candidate, operation)
        if candidate.category in {"BATCH_AUTH", "MUTATION_AUTH", "BFLA"} or (
                candidate.category == "NESTED_AUTH" and
                operation.type is APIOperationType.REST):
            return self._prepare_authorization_delegate(package, candidate, operation)
        if (candidate.status != "READY" or candidate.gaps or
                candidate.category not in {"OBJECT_AUTH", "FIELD_AUTH", "NESTED_AUTH"} or
                operation.type not in {APIOperationType.REST, APIOperationType.GRAPHQL_QUERY} or
                operation.type is APIOperationType.REST and operation.method not in {"GET", "HEAD"} or
                candidate.category == "NESTED_AUTH" and (
                    operation.type is not APIOperationType.GRAPHQL_QUERY or
                    not candidate.child_object_id or not candidate.field_path)):
            return self.registry.link_candidate(package.target.id, candidate_id, status="REVIEW")
        surface = surface or auth.profile(package)
        actors = {item.identity_id: item for item in surface.actors}
        objects = {item.id: item for item in surface.objects}
        owner = actors.get(candidate.owner_identity_id or "")
        boundary = actors.get(candidate.boundary_identity_id or "")
        owned = objects.get(candidate.test_object_id or "")
        owner_source = next((item for item in surface.operations if
                             item.exchange_id == candidate.owner_exchange_id and
                             item.exchange_id in operation.exchange_ids and
                             item.object_id == candidate.test_object_id and
                             item.semantic_owner_success and item.method == operation.method), None)
        if owner_source is None and owned is not None and candidate.owner_exchange_id in operation.exchange_ids:
            owner_source = auth.observed_operation(package, owned, candidate.owner_exchange_id)
            if owner_source is not None and (not owner_source.semantic_owner_success or
                                             owner_source.method != operation.method):
                owner_source = None
        actor_source = next((item for item in surface.operations if
                             boundary is not None and item.exchange_id in operation.exchange_ids and
                             item.owner_identity_id == boundary.identity_id and
                             item.semantic_owner_success and item.method == operation.method and
                             item.object_id in objects and
                             objects[item.object_id].tenant_id in boundary.observed_tenants), None)
        if actor_source is None and boundary is not None:
            actor_objects = tuple(item for item in objects.values()
                                  if item.owner_identity_id == boundary.identity_id and
                                  item.tenant_id in boundary.observed_tenants)
            for ref in operation.exchange_ids[:16]:
                exchange = self.traffic.get_exchange(ref)
                if exchange is None or exchange.attribution.verified_identity_id != boundary.identity_id:
                    continue
                actor_source = next((matched for item in actor_objects
                                     if (matched := auth.observed_operation(
                                         package, item, ref)) is not None and
                                     matched.semantic_owner_success and
                                     matched.method == operation.method), None)
                if actor_source is not None:
                    break
        field_control = (self._field_actor_control(
            package, operation, owner_source, boundary, objects, surface,
            candidate.field_path) if candidate.category == "FIELD_AUTH" and
            actor_source is None and owner_source is not None and
            boundary is not None and candidate.field_path else None)
        actor_operation = operation
        if field_control is not None:
            actor_source, actor_operation = field_control
        actor_object = objects.get(actor_source.object_id) if actor_source else None
        if (owner is None or boundary is None or owned is None or actor_object is None or
                not owner.session_id or not boundary.session_id or
                owner.identity_id == boundary.identity_id or
                owned.tenant_id == actor_object.tenant_id or
                owned.tenant_id in boundary.observed_tenants or
                not owner_source or not actor_source or
                operation.type is APIOperationType.GRAPHQL_QUERY and (
                    not owner_source.variable_name or
                    owner_source.variable_name != actor_source.variable_name)):
            return self.registry.link_candidate(package.target.id, candidate_id, status="REVIEW")
        field_path = candidate.field_path if candidate.category == "FIELD_AUTH" else ""
        if candidate.category == "FIELD_AUTH" and (
                operation.type is not APIOperationType.GRAPHQL_QUERY or
                field_path not in {field.path for field in operation.fields} or
                self.comparator.features(self.traffic.get_exchange(owner_source.exchange_id))
                .graphql_value(field_path) is None):
            return self.registry.link_candidate(package.target.id, candidate_id, status="REVIEW")
        child_object = objects.get(candidate.child_object_id or "")
        if candidate.category == "NESTED_AUTH" and (
                child_object is None or child_object.parent_id != owned.id or
                child_object.owner_identity_id != owner.identity_id or
                child_object.tenant_id != owned.tenant_id or
                self._nested_child(package, operation, owner_source.exchange_id,
                                   owned.id, objects) !=
                (child_object.id, candidate.field_path)):
            return self.registry.link_candidate(package.target.id, candidate_id, status="REVIEW")
        now = datetime.now(timezone.utc)
        hypothesis = auth.hypotheses.upsert(Hypothesis(
            "HYP-" + uuid.uuid4().hex, package.target.id,
            _hash("api-read", candidate.id, operation.version_hash), candidate.category,
            "Test whether a foreign verified identity receives a protected owned API object or field.",
            HypothesisStatus.READY_FOR_EXPERIMENT, candidate.score, 0.75,
            "Protected API data disclosure", "MEDIUM",
            owner_source.operation_id if operation.type is APIOperationType.GRAPHQL_QUERY
            and owner_source.operation_id else owner_source.display_path, "TENANT",
            "A current observed owner operation and two verified disposable controls are available.",
            ("owner control", "actor-owned control", "invalid object control"), (),
            "Compare the exact observed API read under a foreign identity.",
            "Foreign identity receives the protected object or field.",
            "Foreign identity is denied or receives no protected data.",
            ("api-observed-read",), HypothesisSource.DETERMINISTIC, "API_SPECIALIST",
            tuple(dict.fromkeys((*operation.evidence_ids, *owned.evidence_ids,
                                     *actor_object.evidence_ids)))[:16],
            tuple(dict.fromkeys((*owned.facts, *actor_object.facts)))[:8], now, now))
        context = auth.context.build(hypothesis, auth.hypotheses.latest_profile(package.target.id),
                                     package)
        def bind(item, source, actor, role: str, variant: str,
                 selected_operation: APIOperation = operation) -> APIReadPlanBinding:
            return APIReadPlanBinding(
                selected_operation.id, selected_operation.version_hash, source.exchange_id, item.id,
                item.object_type, item.external_id_hash, selected_operation.method,
                actor.identity_id, actor.session_id, role, variant,
                source.variable_name or "",
                "" if selected_operation.id != operation.id else field_path)
        bindings = (bind(owned, owner_source, owner, "CONTROL", "OWNER"),
                    bind(actor_object, actor_source, boundary, "CONTROL", "OWNER",
                         actor_operation),
                    bind(owned, owner_source, owner, "OTHER", "INVALID_OBJECT"),
                    bind(owned, owner_source, boundary, "BOUNDARY", "FOREIGN"),
                    bind(owned, owner_source, boundary, "BOUNDARY", "FOREIGN"))
        try:
            plan = auth.planner.bind_api_read(
                package, hypothesis, context, candidate.id, candidate.category, bindings,
                nested_child_id=child_object.id if candidate.category == "NESTED_AUTH" else None,
                nested_path=candidate.field_path if candidate.category == "NESTED_AUTH" else None)
            for item in (owned, actor_object, *((child_object,) if candidate.category == "NESTED_AUTH" else ())):
                record = auth.objects.get(item.id, package.target.id)
                if record is None:
                    raise ValueError("API object reservation prerequisite is missing")
                auth.objects.add_requirement(
                    plan_id=str(plan["id"]), target_id=package.target.id,
                    object_type=record.object_type, recipe_id=record.recipe_id,
                    identity_id=record.creator_identity_id, tenant_id=record.tenant_id,
                    parent_id=record.parent_id, test_object_id=record.id)
        except ValueError:
            return self.registry.link_candidate(package.target.id, candidate.id,
                                                status="REVIEW", hypothesis_id=hypothesis.id)
        return self.registry.link_candidate(package.target.id, candidate.id, status="PLANNED",
                                            hypothesis_id=hypothesis.id, plan_id=str(plan["id"]))

    def _prepare_disposable_delete(self, package: TargetPackage,
                                   candidate: APICandidate,
                                   operation: APIOperation) -> APICandidate:
        auth = self.authorization
        assert auth is not None and auth.context is not None and auth.planner is not None
        controls = self._delete_controls(package, operation, auth.profile(package))
        if (candidate.status != "READY" or candidate.gaps or controls is None or
                candidate.owner_exchange_id != controls.source.id or
                candidate.test_object_id != controls.target.id or
                candidate.owner_identity_id != controls.owner.identity_id or
                candidate.boundary_identity_id != controls.actor.identity_id or
                package.autonomy.delete_disposable_objects is not PolicyDecision.ALLOW):
            return self.registry.link_candidate(package.target.id, candidate.id,
                                                status="REVIEW")
        target = auth.objects.get(controls.target.id, package.target.id)
        control = auth.objects.get(controls.control.id, package.target.id)
        mutation = next((item for item in controls.recipe.mutations if
                         item.mutation_type is MutationType.DELETE_DISPOSABLE), None)
        if (target is None or control is None or mutation is None or
                target.state is not ObjectState.READY or
                control.state is not ObjectState.READY or
                not target.external_id_hash or not control.external_id_hash or
                auth.objects.active_reservation(target.id) is not None or
                auth.objects.active_reservation(control.id) is not None):
            return self.registry.link_candidate(package.target.id, candidate.id,
                                                status="REVIEW")
        now = datetime.now(timezone.utc)
        hypothesis = auth.hypotheses.upsert(Hypothesis(
            "HYP-" + uuid.uuid4().hex, package.target.id,
            _hash("api-disposable-delete", candidate.id, operation.version_hash),
            "CROSS_TENANT",
            "Test whether a foreign verified identity can delete an owned disposable API object.",
            HypothesisStatus.READY_FOR_EXPERIMENT, candidate.score, 0.75,
            "Unauthorized deletion of a disposable tenant-private object", "MEDIUM",
            controls.source.request.display_path, "TENANT",
            "An observed owner cleanup DELETE matches a reviewed recipe and two current owned fixtures.",
            ("owner delete control", "target-present preflight", "foreign delete", "final owner read-back"),
            (), "Use the reviewed two-object typed DELETE contract.",
            "Foreign deletion changes the target from present to absent.",
            "Foreign deletion is denied; owner cleanup removes the target.",
            ("typed-authorization-mutation",), HypothesisSource.DETERMINISTIC,
            "API_SPECIALIST",
            tuple(dict.fromkeys((*operation.evidence_ids, *controls.source.evidence_ids,
                                  *controls.target.evidence_ids,
                                  *controls.control.evidence_ids)))[:16],
            tuple(dict.fromkeys((*controls.target.facts,
                                  *controls.control.facts)))[:8], now, now))
        context = auth.context.build(
            hypothesis, auth.hypotheses.latest_profile(package.target.id), package)
        try:
            plan = auth.planner.bind_typed_mutation(
                package, hypothesis, context, TypedMutationPlanBinding(
                    target.id, target.object_type, target.external_id_hash,
                    target.recipe_id, target.recipe_hash, "DELETE_DISPOSABLE", "DELETE",
                    mutation.readback.operation, mutation.write.operation,
                    controls.owner.identity_id, controls.owner.session_id,
                    controls.actor.identity_id, controls.actor.session_id,
                    Boundary.CROSS_TENANT.value,
                    delete_control_object_id=control.id,
                    delete_control_ref_hash=control.external_id_hash))
            for item in (target, control):
                auth.objects.add_requirement(
                    plan_id=str(plan["id"]), target_id=package.target.id,
                    object_type=item.object_type, recipe_id=item.recipe_id,
                    identity_id=item.creator_identity_id, tenant_id=item.tenant_id,
                    parent_id=item.parent_id, test_object_id=item.id)
        except (LookupError, ValueError):
            return self.registry.link_candidate(package.target.id, candidate.id,
                                                status="REVIEW", hypothesis_id=hypothesis.id)
        return self.registry.link_candidate(
            package.target.id, candidate.id, status="PLANNED",
            hypothesis_id=hypothesis.id, plan_id=str(plan["id"]))

    def _prepare_graphql_batch(self, package: TargetPackage,
                               candidate: APICandidate,
                               operation: APIOperation) -> APICandidate:
        auth = self.authorization
        assert auth is not None and auth.planner is not None and auth.context is not None
        controls = self._batch_controls(package, operation, auth.profile(package))
        if (controls is None or candidate.status != "READY" or candidate.gaps or
                candidate.owner_exchange_id != controls.owner_exchange.id or
                candidate.test_object_id != controls.owner_objects[0].id or
                candidate.owner_identity_id != controls.owner.identity_id or
                candidate.boundary_identity_id != controls.actor.identity_id):
            return self.registry.link_candidate(package.target.id, candidate.id,
                                                status="REVIEW")
        now = datetime.now(timezone.utc)
        evidence_ids = tuple(dict.fromkeys((
            *operation.evidence_ids,
            *(ref for item in (*controls.owner_objects, *controls.actor_objects)
              for ref in item.evidence_ids))))[:16]
        fact_ids = tuple(dict.fromkeys(
            ref for item in (*controls.owner_objects, *controls.actor_objects)
            for ref in item.facts))[:8]
        hypothesis = auth.hypotheses.upsert(Hypothesis(
            "HYP-" + uuid.uuid4().hex, package.target.id,
            _hash("api-batch", candidate.id, operation.version_hash), "BATCH_AUTH",
            "Test whether a mixed two-object GraphQL read discloses a foreign private object.",
            HypothesisStatus.READY_FOR_EXPERIMENT, candidate.score, 0.75,
            "Cross-tenant protected API data disclosure", "MEDIUM",
            controls.owner_exchange.request.record.operation_id or
            controls.owner_exchange.request.display_path,
            "TENANT", "Current observed two-ID owner and actor controls are available.",
            ("owner batch", "actor-owned batch", "invalid batch"), (),
            "Compare one exact observed nodes query with two known disposable IDs.",
            "Foreign identity receives private data for the owner's object.",
            "Foreign object is filtered or denied without protected data.",
            ("api-observed-read",), HypothesisSource.DETERMINISTIC, "API_SPECIALIST",
            evidence_ids, fact_ids, now, now))
        context = auth.context.build(hypothesis,
                                     auth.hypotheses.latest_profile(package.target.id), package)
        def bind(primary: AuthorizationObject, source: TrafficExchange,
                 actor: AuthorizationActor, role: str, variant: str,
                 source_companion: AuthorizationObject,
                 companion: AuthorizationObject) -> APIReadPlanBinding:
            return APIReadPlanBinding(
                operation.id, operation.version_hash, source.id, primary.id,
                primary.object_type, primary.external_id_hash, "POST",
                actor.identity_id, actor.session_id or "", role, variant,
                controls.variable_name, "", source_companion.id, companion.id)
        first, second = controls.owner_objects
        actor_first, actor_second = controls.actor_objects
        bindings = (
            bind(first, controls.owner_exchange, controls.owner, "CONTROL", "OWNER",
                 second, second),
            bind(actor_first, controls.actor_exchange, controls.actor, "CONTROL", "OWNER",
                 actor_second, actor_second),
            bind(first, controls.owner_exchange, controls.owner, "OTHER", "INVALID_OBJECT",
                 second, second),
            bind(first, controls.owner_exchange, controls.actor, "BOUNDARY", "FOREIGN",
                 second, actor_first),
            bind(first, controls.owner_exchange, controls.actor, "BOUNDARY", "FOREIGN",
                 second, actor_first),
        )
        try:
            plan = auth.planner.bind_api_read(
                package, hypothesis, context, candidate.id, "BATCH_AUTH", bindings,
                batch_root_key=controls.root_key, batch_id_type=controls.id_type,
                batch_envelope=controls.envelope)
            for item in (first, second, actor_first, actor_second):
                record = auth.objects.get(item.id, package.target.id)
                if record is None:
                    raise ValueError("API batch object prerequisite is missing")
                auth.objects.add_requirement(
                    plan_id=str(plan["id"]), target_id=package.target.id,
                    object_type=record.object_type, recipe_id=record.recipe_id,
                    identity_id=record.creator_identity_id, tenant_id=record.tenant_id,
                    parent_id=record.parent_id, test_object_id=record.id)
        except ValueError:
            return self.registry.link_candidate(package.target.id, candidate.id,
                                                status="REVIEW", hypothesis_id=hypothesis.id)
        return self.registry.link_candidate(package.target.id, candidate.id,
                                            status="PLANNED", hypothesis_id=hypothesis.id,
                                            plan_id=str(plan["id"]))

    def _prepare_authorization_delegate(self, package: TargetPackage,
                                        candidate: APICandidate,
                                        operation: APIOperation) -> APICandidate:
        """Reuse Phase 19/20 plans only when their observed owner boundary matches exactly."""
        auth = self.authorization
        assert auth is not None
        supported = (
            candidate.category == "NESTED_AUTH" and operation.type is APIOperationType.REST
            and operation.method in {"GET", "HEAD"} or
            candidate.category == "BATCH_AUTH" and operation.type is APIOperationType.BULK_API
            and operation.method == "GET" or
            candidate.category == "MUTATION_AUTH" and (
                operation.type is APIOperationType.GRAPHQL_MUTATION and operation.method == "POST" or
                operation.type is APIOperationType.REST and operation.method in {"PATCH", "PUT", "POST"}) or
            candidate.category == "BFLA" and operation.type is APIOperationType.REST
            and operation.method in {"GET", "HEAD"})
        if not supported or not candidate.owner_exchange_id or not candidate.test_object_id or (
                not candidate.boundary_identity_id):
            return self.registry.link_candidate(package.target.id, candidate.id, status="REVIEW")
        expected = ({"NESTED_AUTH": {Boundary.PARENT_CHILD},
                     "BATCH_AUTH": {Boundary.CROSS_TENANT},
                     "MUTATION_AUTH": {Boundary.CROSS_TENANT, Boundary.HORIZONTAL,
                                       Boundary.VERTICAL, Boundary.HIDDEN_FUNCTION,
                                       Boundary.GRAPHQL_MUTATION},
                     "BFLA": {Boundary.VERTICAL, Boundary.HIDDEN_FUNCTION}}
                    [candidate.category])
        hunt = auth.ledger.create_hunt(package.target.id, package.id,
                                       mode=AuthorizationMode.PLAN_ONLY,
                                       candidate_limit=50, request_budget=7)
        generated = auth.generate(hunt, package)
        matching = next((item for item in generated
                         if item.owner_exchange_id == candidate.owner_exchange_id and
                         item.test_object_id == candidate.test_object_id and
                         item.owner_identity_id == candidate.owner_identity_id and
                         item.boundary_identity_id == candidate.boundary_identity_id and
                         item.boundary in expected), None)
        if matching is None:
            return self.registry.link_candidate(package.target.id, candidate.id, status="REVIEW")
        if matching.status in {"VALIDATED", "REJECTED"} and matching.validation_id:
            return self.registry.link_candidate(
                package.target.id, candidate.id, status=matching.status,
                hypothesis_id=matching.hypothesis_id, plan_id=matching.plan_id,
                run_id=matching.run_id, validation_id=matching.validation_id,
                authorization_candidate_id=matching.id)
        previous_hunt = auth.ledger.get_hunt(matching.hunt_id, package.target.id)
        if previous_hunt is None or previous_hunt.status not in {HuntStatus.READY, HuntStatus.RUNNING}:
            return self.registry.link_candidate(package.target.id, candidate.id, status="REVIEW",
                                                authorization_candidate_id=matching.id)
        if matching.status == "CANDIDATE":
            try:
                matching = auth.prepare(matching.id, package)
            except (LookupError, ValueError):
                return self.registry.link_candidate(package.target.id, candidate.id, status="REVIEW",
                                                    authorization_candidate_id=matching.id)
        if matching.status not in {"PLANNED", "RUNNING"} or not matching.plan_id:
            return self.registry.link_candidate(package.target.id, candidate.id, status="REVIEW",
                                                authorization_candidate_id=matching.id)
        return self.registry.link_candidate(
            package.target.id, candidate.id, status=matching.status,
            hypothesis_id=matching.hypothesis_id, plan_id=matching.plan_id,
            run_id=matching.run_id, authorization_candidate_id=matching.id)

    def start_candidate(self, package: TargetPackage, candidate_id: str) -> dict[str, object]:
        self.profile(package)
        candidate = self.registry.get_candidate(package.target.id, candidate_id)
        operation = (self.registry.get_operation(package.target.id, candidate.operation_id)
                     if candidate else None)
        if operation is None or operation.package_id != package.id or operation.state != "CURRENT":
            raise ValueError("API candidate operation is stale")
        auth = self.authorization
        if auth is None or auth.orchestrator is None:
            raise ValueError("API orchestrator is unavailable")
        if (candidate is None or candidate.status != "PLANNED" or
                not candidate.plan_id or candidate.run_id):
            raise ValueError("API candidate has no ready plan")
        if candidate.authorization_candidate_id:
            detail = auth.start_candidate(candidate.authorization_candidate_id, package)
            self._sync_authorization_candidate(package, candidate)
            return detail
        detail = auth.orchestrator.start(candidate.plan_id, package.id)
        self.registry.link_candidate(package.target.id, candidate.id, status="RUNNING",
                                     run_id=str(detail["run"]["id"]))
        return detail

    def validate_candidate(self, package: TargetPackage, candidate_id: str) -> dict[str, object]:
        auth = self.authorization
        if auth is None or auth.validator is None:
            raise ValueError("API validator is unavailable")
        candidate = self.registry.get_candidate(package.target.id, candidate_id)
        if candidate is None or not candidate.run_id:
            raise ValueError("API candidate has no run")
        if candidate.authorization_candidate_id:
            detail = auth.validate_candidate(candidate.authorization_candidate_id, package)
            self._sync_authorization_candidate(package, candidate)
            return detail
        run = auth.validator.runs.get(candidate.run_id, package.target.id)
        if run is None or run.package_id != package.id or run.status is not RunStatus.COMPLETED:
            raise ValueError("API run is not complete")
        result, finding = auth.validator.validate_run(run.id, package.target.id)
        status = ("VALIDATED" if result.status is ValidationStatus.CONFIRMED else
                  "REJECTED" if result.status is ValidationStatus.REJECTED else "REVIEW")
        self.registry.link_candidate(package.target.id, candidate_id, status=status,
                                     validation_id=result.id)
        return {"result": result.to_dict(), "finding": finding.to_dict() if finding else None}

    def _sync_authorization_candidate(self, package: TargetPackage,
                                      candidate: APICandidate) -> APICandidate:
        auth = self.authorization
        assert auth is not None and candidate.authorization_candidate_id
        linked = auth.ledger.get_candidate(candidate.authorization_candidate_id,
                                            package.target.id)
        if linked is None or linked.owner_exchange_id != candidate.owner_exchange_id or (
                linked.test_object_id != candidate.test_object_id or
                linked.boundary_identity_id != candidate.boundary_identity_id):
            raise ValueError("API authorization delegation no longer matches its boundary")
        status = ("REVIEW" if linked.status == "NEEDS_MANUAL_REVIEW" else linked.status)
        if status not in {"PLANNED", "RUNNING", "VALIDATED", "REJECTED", "BLOCKED"}:
            raise ValueError("API authorization delegation has an unexpected state")
        return self.registry.link_candidate(
            package.target.id, candidate.id, status=status,
            hypothesis_id=linked.hypothesis_id, plan_id=linked.plan_id,
            run_id=linked.run_id, validation_id=linked.validation_id,
            authorization_candidate_id=linked.id)

    def advance_candidate(self, package: TargetPackage, candidate_id: str) -> dict[str, object]:
        auth = self.authorization
        if auth is None or auth.orchestrator is None:
            raise ValueError("API orchestrator is unavailable")
        candidate = self.registry.get_candidate(package.target.id, candidate_id)
        if candidate is None or candidate.status != "RUNNING" or not candidate.run_id:
            raise ValueError("API candidate has no running plan")
        if candidate.authorization_candidate_id:
            detail = auth.advance_candidate(candidate.authorization_candidate_id, package)
            self._sync_authorization_candidate(package, candidate)
            return detail
        detail = auth.orchestrator.advance(candidate.run_id, package.id)
        status = detail["run"]["status"]
        if status == RunStatus.COMPLETED.value:
            return {**detail, "validation": self.validate_candidate(package, candidate_id)}
        if status in {RunStatus.BLOCKED.value, RunStatus.FAILED.value,
                      RunStatus.BUDGET_EXHAUSTED.value, RunStatus.CANCELLED.value}:
            self.registry.link_candidate(package.target.id, candidate_id, status="BLOCKED")
        return detail
