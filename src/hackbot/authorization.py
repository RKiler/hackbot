"""Evidence-bounded authorization profiling; active work remains in the plan runner."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
from urllib.parse import unquote, urlsplit
import uuid

from .authorization_store import (AuthorizationCandidate, AuthorizationHunt, AuthorizationMode,
                                  AuthorizationStore, Boundary, HuntStatus, MatrixResult,
                                  candidate_dedupe_key)
from .authorization_binding import single_rename_operation
from .api_graphql import (observed_global_id_type, single_nested_rename_operation,
                          single_node_id_variable)
from .browser import BrowserSessionManager, BrowserStatus, VerificationStatus
from .domain import ObservationState
from .evidence import FactStatus
from .hypotheses import (Hypothesis, HypothesisSource, HypothesisStatus, HypothesisStore)
from .identity import IdentityStatus, MembershipStatus
from .identity_registry import IdentityRegistry
from .orchestrator import PlanOrchestrator
from .object_factory import ObjectFactory, ObjectFactoryResult
from .object_recipes import unique_json_pairs
from .plan_runs import RunStatus
from .profile import TargetProfile
from .recon import ReconRepository
from .response_compare import ResponseComparator
from .skill_plans import (AuthorizationPlanBinding, TypedMutationPlanBinding, PrerequisiteState,
                          SkillContextBuilder, SkillPlanner, SkillRouter)
from .store import EvidenceFactStore
from .target_package import PackageStatus, TargetPackage
from .target_scope import ScopeResult
from .target_policy import PolicyDecision
from .test_objects import CleanupStrategy, ObjectRegistry, ObjectState, TestObject
from .traffic import AuthState, ExchangeState, TrafficExchange, TrafficStore
from .validation_store import ValidationStatus
from .validator import DeterministicValidatorEngine


def _hash(*parts: str) -> str:
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class AuthorizationActor:
    identity_id: str
    alias: str
    principal_id: str | None
    session_id: str | None
    tenants: tuple[str, ...]
    roles: tuple[str, ...]
    observed_tenants: tuple[str, ...]
    observed_roles: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"identity_id": self.identity_id, "alias": self.alias,
                "principal_id": self.principal_id, "verified_session_id": self.session_id,
                "tenants": list(self.tenants), "roles": list(self.roles),
                "observed_tenants": list(self.observed_tenants),
                "observed_roles": list(self.observed_roles)}


@dataclass(frozen=True, slots=True)
class AuthorizationObject:
    id: str
    object_type: str
    owner_identity_id: str
    owner_principal_id: str | None
    tenant_id: str
    parent_id: str | None
    external_id_hash: str
    evidence_ids: tuple[str, ...]
    facts: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "object_type": self.object_type,
                "owner_identity_id": self.owner_identity_id,
                "owner_principal_id": self.owner_principal_id, "tenant_id": self.tenant_id,
                "parent_id": self.parent_id, "external_id_fingerprint": self.external_id_hash[:16],
                "evidence_ids": list(self.evidence_ids), "fact_ids": list(self.facts)}


@dataclass(frozen=True, slots=True)
class AuthorizationOperation:
    key: str
    exchange_id: str
    owner_identity_id: str
    object_id: str
    method: str
    origin: str
    display_path: str
    operation_id: str | None
    protocol: str
    semantic_owner_success: bool
    evidence_ids: tuple[str, ...]
    variable_name: str | None = None
    graphql_kind: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {"key": self.key, "exchange_id": self.exchange_id,
                "owner_identity_id": self.owner_identity_id, "object_id": self.object_id,
                "method": self.method, "origin": self.origin, "display_path": self.display_path,
                "operation_id": self.operation_id, "protocol": self.protocol,
                "semantic_owner_success": self.semantic_owner_success,
                "evidence_ids": list(self.evidence_ids), "variable_name": self.variable_name,
                "graphql_kind": self.graphql_kind}


@dataclass(frozen=True, slots=True)
class AuthorizationSurface:
    target_id: str
    package_id: str
    actors: tuple[AuthorizationActor, ...]
    objects: tuple[AuthorizationObject, ...]
    operations: tuple[AuthorizationOperation, ...]
    profile_signal_count: int
    recon_hint_count: int
    gaps: tuple[str, ...]
    truncated: bool

    def to_dict(self) -> dict[str, object]:
        actors = {actor.identity_id: actor for actor in self.actors}
        role_operations: dict[str, set[str]] = {}
        role_features: dict[str, set[str]] = {}
        for operation in self.operations:
            actor = actors.get(operation.owner_identity_id)
            if actor is None:
                continue
            feature = next((part for part in operation.display_path.split("/")
                            if part and part not in {"api", "v1", "v2"}), "unknown")
            for role in actor.observed_roles:
                role_operations.setdefault(role, set()).add(operation.key)
                role_features.setdefault(role, set()).add(feature)
        return {"target_id": self.target_id, "package_id": self.package_id,
                "identities": [actor.to_dict() for actor in self.actors],
                "objects": [item.to_dict() for item in self.objects],
                "operations": [item.to_dict() for item in self.operations],
                "profile_signal_count": self.profile_signal_count,
                "recon_hint_count": self.recon_hint_count, "gaps": list(self.gaps),
                "observed_role_operations": {key: sorted(values) for key, values in
                                             sorted(role_operations.items())},
                "observed_role_features": {key: sorted(values) for key, values in
                                           sorted(role_features.items())},
                "truncated": self.truncated}


class AuthorizationSpecialist:
    """Local reasoning only; never owns a transport or a credential provider."""

    def __init__(self, *, identities: IdentityRegistry, browser: BrowserSessionManager,
                 objects: ObjectRegistry, traffic: TrafficStore, evidence: EvidenceFactStore,
                 hypotheses: HypothesisStore, ledger: AuthorizationStore,
                 recon: ReconRepository | None = None,
                 context: SkillContextBuilder | None = None,
                 router: SkillRouter | None = None,
                 planner: SkillPlanner | None = None,
                 orchestrator: PlanOrchestrator | None = None,
                 validator: DeterministicValidatorEngine | None = None,
                 factory: ObjectFactory | None = None,
                 behaviour: "BehaviourStore | None" = None) -> None:
        self.identities, self.browser, self.objects = identities, browser, objects
        self.traffic, self.evidence, self.hypotheses = traffic, evidence, hypotheses
        self.ledger, self.recon = ledger, recon
        self.context, self.router, self.planner = context, router, planner
        self.orchestrator, self.validator = orchestrator, validator
        self.factory = factory
        self.behaviour = behaviour
        self.comparator = ResponseComparator(evidence)

    def _actors(self, target_id: str) -> tuple[AuthorizationActor, ...]:
        result = []
        for identity in self.identities.list_identities(target_id, limit=12).items[:12]:
            if identity.status is not IdentityStatus.ACTIVE:
                continue
            session_id = None
            session = self.browser.get_session_for_identity(target_id, identity.id)
            if session is not None:
                try:
                    context = self.browser.session_context(session.id)
                    if (context.target_id == target_id and context.identity_id == identity.id and
                            context.browser_status is BrowserStatus.VALID and
                            context.verification_status is VerificationStatus.MATCH and
                            context.authentication_status == "VALID" and context.browser_available):
                        session_id = session.id
                except (LookupError, ValueError):
                    pass
            memberships = self.identities.list_memberships(identity.id, limit=12).items
            current = [membership for membership in memberships
                       if membership.status is MembershipStatus.ACTIVE]
            observed = []
            for membership in current:
                if membership.observation_state is not ObservationState.OBSERVED or not membership.fact_id:
                    continue
                fact = self.evidence.get_fact(membership.fact_id)
                if (fact and fact.target_ref == target_id and fact.status is FactStatus.ACTIVE and
                        fact.source != "MANUAL" and fact.confidence >= 0.9 and fact.evidence_ids and
                        fact.subject in {identity.id, identity.principal_id} and
                        fact.predicate == "member_of" and fact.object == membership.tenant_id):
                    observed.append(membership)
            principal = identity.principal_id if identity.principal_state is ObservationState.OBSERVED else None
            result.append(AuthorizationActor(
                identity.id, identity.alias, principal, session_id,
                tuple(sorted({item.tenant_id for item in current})),
                tuple(sorted({role for item in current for role in item.role_ids})),
                tuple(sorted({item.tenant_id for item in observed})),
                tuple(sorted({role for item in observed for role in item.role_ids}))))
        return tuple(result)

    def _owned_objects(self, target_id: str) -> tuple[AuthorizationObject, ...]:
        result = []
        for item in self.objects.list_for_target(target_id, limit=30).items[:30]:
            if (item.state not in {ObjectState.READY, ObjectState.IN_USE} or not item.disposable or
                    not item.verified_at or not item.external_id_hash or not item.external_id_evidence_id):
                continue
            fact_ids = []
            valid = True
            for predicate, value in (("created_by", item.creator_identity_id),
                                     ("resource_tenant", item.tenant_id), ("disposable", "true")):
                facts = self.evidence.find_facts(item.id, predicate, limit=8).items
                found = next((fact for fact in facts if fact.target_ref == target_id and
                              fact.status is FactStatus.ACTIVE and fact.source != "MANUAL" and
                              fact.confidence >= 0.9 and fact.evidence_ids and fact.object == value), None)
                if found is None:
                    valid = False
                    break
                fact_ids.append(found.fact_id)
            if not valid:
                continue
            result.append(AuthorizationObject(
                item.id, item.object_type, item.creator_identity_id, item.owner_principal_id,
                item.tenant_id, item.parent_id, item.external_id_hash,
                item.verification_evidence_ids[:8], tuple(fact_ids)))
        return tuple(result)

    def _external_id(self, item: TestObject) -> str:
        if item.external_id_evidence_id is None or item.external_id_hash is None:
            raise ValueError("object identifier missing")
        value = self.evidence.read_content(item.external_id_evidence_id,
                                           allow_sensitive=True, max_bytes=256).decode("ascii")
        if hashlib.sha256((item.id + ":" + value).encode()).hexdigest() != item.external_id_hash:
            raise ValueError("object identifier integrity mismatch")
        return value

    @staticmethod
    def _request_url(exchange: TrafficExchange, evidence: EvidenceFactStore) -> str | None:
        item = evidence.get_evidence(exchange.request.observation_evidence_id)
        if item is None or item.target_ref != exchange.target_id:
            return None
        try:
            observation = json.loads(evidence.read_content(item.evidence_id,
                                                            allow_sensitive=True, max_bytes=8192))
            return observation["url"] if isinstance(observation["url"], str) else None
        except (ValueError, KeyError, UnicodeDecodeError, PermissionError):
            return None

    def _graphql_variable(self, exchange: TrafficExchange,
                          external_id: str) -> tuple[str, str] | None:
        if (exchange.request.record.method != "POST" or
                not exchange.request.record.operation_id or
                not exchange.request.body_evidence_id):
            return None
        item = self.evidence.get_evidence(exchange.request.body_evidence_id)
        if (item is None or item.target_ref != exchange.target_id or
                item.redaction_status.value != "ORIGINAL" or item.content_size > 8192):
            return None
        try:
            raw = self.evidence.read_content(item.evidence_id, allow_sensitive=True,
                                             max_bytes=8192)
            if hashlib.sha256(raw).hexdigest() != exchange.request.body_hash:
                return None
            def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
                values: dict[str, object] = {}
                for key, value in pairs:
                    if key in values:
                        raise ValueError("ambiguous GraphQL JSON")
                    values[key] = value
                return values
            data = json.loads(raw, object_pairs_hook=unique_pairs)
            query = data["query"]
            variables = data["variables"]
            if (not isinstance(query, str) or not isinstance(variables, dict) or
                    not isinstance(data, dict) or set(data) - {"query", "variables", "operationName"} or
                    len(query) > 4096 or len(variables) not in {1, 2, 3}):
                return None
            kind = "QUERY" if query.lstrip().startswith("query ") else (
                "MUTATION" if query.lstrip().startswith("mutation ") else None)
            if kind is None or ("mutation" in query.lower() and kind == "QUERY"):
                return None
            node_variable = single_node_id_variable(query) if kind == "QUERY" else None
            matching = [key for key, value in variables.items() if value == external_id or (
                key == node_variable and observed_global_id_type(value, external_id))]
            variable = matching[0] if len(matching) == 1 else None
            if not isinstance(variable, str) or not variable.isidentifier():
                return None
            if len(variables) == 2:
                changes = {key: value for key, value in variables.items() if key != variable}
                if (kind != "MUTATION" or set(changes) not in ({"name"}, {"newName"}) or
                        not all(isinstance(value, str) and
                                4 <= len(value) <= 80 and
                                value.replace("-", "").isalnum() for value in changes.values())):
                    return None
            if len(variables) == 3 and (kind != "MUTATION" or variable != "id" or
                    set(variables) != {"parentId", "id", "name"} or
                    not isinstance(variables["parentId"], str) or
                    not isinstance(variables["name"], str) or
                    not variables["name"].startswith("hackbot-test-") or
                    single_nested_rename_operation(query) != data.get("operationName")):
                return None
            return variable, kind
        except (KeyError, TypeError, ValueError, UnicodeError, PermissionError):
            return None

    def _operation_for_exchange(self, package: TargetPackage, item: AuthorizationObject,
                                exchange: TrafficExchange | None) -> AuthorizationOperation | None:
        if (exchange is None or exchange.target_id != package.target.id or
                exchange.package_id != package.id or exchange.state is not ExchangeState.COMPLETE or
                exchange.scope_result is not ScopeResult.IN_SCOPE or
                exchange.attribution.auth_state is not AuthState.VERIFIED or
                exchange.attribution.verified_identity_id != item.owner_identity_id or
                exchange.response is None):
            return None
        url = self._request_url(exchange, self.evidence)
        if url is None or package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
            return None
        parsed = urlsplit(url)
        method = exchange.request.record.method
        path_parts = tuple(unquote(segment) for segment in parsed.path.split("/"))
        batch_ids = (path_parts[-1].split(",") if method == "GET" and
                     len(path_parts) >= 3 and path_parts[-2] == "batch" else [])
        stored = self.objects.get(item.id, package.target.id)
        if stored is None or not stored.disposable or not stored.verified_at:
            return None
        try:
            external_id = self._external_id(stored)
        except (ValueError, UnicodeError, KeyError, PermissionError):
            return None
        graphql = self._graphql_variable(exchange, external_id)
        if external_id not in path_parts and graphql is None and (
                not batch_ids or external_id != batch_ids[0]):
            return None
        features = self.comparator.features(exchange)
        semantic = bool(features.status_code is not None and
                        200 <= features.status_code < 300 and
                        not features.graphql_errors_present and
                        (graphql is None or features.graphql_data_present) and
                        hashlib.sha256(external_id.encode()).hexdigest() in features.object_id_hashes)
        tenant = self.identities.get_tenant(package.target.id, item.tenant_id)
        tenant_segments = ({tenant.label, tenant.external_id} - {None, ""}) if tenant else set()
        normalized_path = "/".join(
            "{batch}" if segment == path_parts[-1] and external_id in batch_ids else
            "{object}" if segment == external_id else
            "{tenant}" if segment in tenant_segments else segment for segment in path_parts)
        key = _hash(method, exchange.request.origin, normalized_path,
                    exchange.request.record.operation_id or "")
        return AuthorizationOperation(
            key, exchange.id, item.owner_identity_id, item.id, method,
            exchange.request.origin, exchange.request.display_path,
            exchange.request.record.operation_id,
            "GRAPHQL" if graphql else "BATCH" if external_id in batch_ids else "REST",
            semantic, exchange.evidence_ids[:8],
            graphql[0] if graphql else None, graphql[1] if graphql else None)

    def observed_operation(self, package: TargetPackage, item: AuthorizationObject,
                           exchange_id: str) -> AuthorizationOperation | None:
        """Resolve one exact owned capture without widening the normal profile page."""
        return self._operation_for_exchange(package, item,
                                            self.traffic.get_exchange(exchange_id))

    def _operations(self, package: TargetPackage,
                    objects: tuple[AuthorizationObject, ...]) -> tuple[AuthorizationOperation, ...]:
        result = []
        for exchange in self.traffic.find_recent(package.target.id, limit=50).items:
            for item in objects:
                operation = self._operation_for_exchange(package, item, exchange)
                if operation is not None:
                    result.append(operation)
                    if len(result) >= 40:
                        return tuple(result)
        return tuple(result)

    def profile(self, package: TargetPackage) -> AuthorizationSurface:
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("authorization specialist requires a tracked target package")
        actors = self._actors(package.target.id)
        objects = self._owned_objects(package.target.id)
        operations = self._operations(package, objects)
        target_profile: TargetProfile | None = self.hypotheses.latest_profile(package.target.id)
        signal_count = len(target_profile.signals[:100]) if target_profile else 0
        recon_count = 0
        if (self.recon is not None and target_profile is not None and
                target_profile.recon_domain_id is not None):
            try:
                for kind in ("GRAPHQL", "OPENAPI"):
                    recon_count += len(self.recon.list_api_surfaces(
                        target_profile.recon_domain_id, kind, limit=4).items)
            except (OSError, ValueError, RuntimeError):
                pass
        gaps = []
        if not any(actor.session_id for actor in actors):
            gaps.append("NO_VERIFIED_SESSION")
        if not objects:
            gaps.append("NO_VERIFIED_DISPOSABLE_OBJECT")
        if not operations:
            gaps.append("NO_MATCHED_OWNER_REQUEST")
        if target_profile is None:
            gaps.append("TARGET_PROFILE_MISSING")
        return AuthorizationSurface(package.target.id, package.id, actors, objects,
                                    operations, signal_count, recon_count, tuple(gaps),
                                    len(actors) >= 12 or len(objects) >= 30 or len(operations) >= 40)

    def _candidate(self, hunt: AuthorizationHunt, surface: AuthorizationSurface,
                   obj: AuthorizationObject, operation: AuthorizationOperation,
                   boundary: Boundary, actor: AuthorizationActor | None,
                   reasons: tuple[str, ...], score: int) -> AuthorizationCandidate:
        attacker = actor.identity_id if actor else None
        key = candidate_dedupe_key(surface.target_id, boundary.value, obj.id,
                                   operation.key, attacker)
        candidate = AuthorizationCandidate(
            "AUTHC-" + uuid.uuid4().hex, surface.target_id, hunt.id, key, boundary,
            obj.owner_identity_id, attacker, obj.id, operation.exchange_id,
            operation.key, min(100, score), reasons, "CANDIDATE")
        return self.ledger.upsert_candidate(candidate)

    def _role_restriction(self, target_id: str, item: AuthorizationObject) -> str | None:
        stored = self.objects.get(item.id, target_id)
        if stored is None:
            return None
        try:
            external = self._external_id(stored)
        except (ValueError, UnicodeError, PermissionError):
            return None
        subject = hashlib.sha256(external.encode()).hexdigest()
        for fact in self.evidence.find_facts(subject, "required_role", limit=8).items:
            if (fact.target_ref == target_id and fact.status is FactStatus.ACTIVE and
                    fact.source != "MANUAL" and fact.confidence >= 0.9 and fact.evidence_ids):
                return fact.object
        return None

    def _protected_artifact_facts(self, target_id: str,
                                  item: AuthorizationObject) -> tuple[str, ...]:
        stored = self.objects.get(item.id, target_id)
        if stored is None:
            return ()
        try:
            subject = hashlib.sha256(self._external_id(stored).encode()).hexdigest()
        except (ValueError, UnicodeError, PermissionError):
            return ()
        found = []
        for predicate, allowed in (("resource_visibility", {"PRIVATE"}),
                                   ("data_classification", {"PROTECTED_FILE", "SENSITIVE"})):
            match = next((fact for fact in self.evidence.find_facts(subject, predicate, limit=8).items
                          if fact.target_ref == target_id and fact.status is FactStatus.ACTIVE
                          and fact.source != "MANUAL" and fact.confidence >= 0.9
                          and fact.evidence_ids and fact.object in allowed), None)
            if match is None:
                return ()
            found.append(match.fact_id)
        return tuple(found)

    def _observed_parent_child(self, surface: AuthorizationSurface,
                               child: AuthorizationObject,
                               operation: AuthorizationOperation) -> AuthorizationObject | None:
        """Require a nested owner request and matching response parent before surfacing a lead."""
        parent = next((item for item in surface.objects if item.id == child.parent_id), None)
        if (parent is None or parent.tenant_id != child.tenant_id or
                operation.method not in {"GET", "HEAD"} or not operation.semantic_owner_success):
            return None
        source = self.traffic.get_exchange(operation.exchange_id)
        if source is None or source.response is None or not source.response.body_evidence_id:
            return None
        try:
            parent_item = self.objects.get(parent.id, surface.target_id)
            child_item = self.objects.get(child.id, surface.target_id)
            if parent_item is None or child_item is None:
                return None
            parent_external = self._external_id(parent_item)
            child_external = self._external_id(child_item)
            url = self._request_url(source, self.evidence)
            if url is None:
                return None
            path_parts = [unquote(part) for part in urlsplit(url).path.split("/") if part]
            if path_parts.count(parent_external) != 1 or path_parts.count(child_external) != 1:
                return None
            body = json.loads(self.evidence.read_content(
                source.response.body_evidence_id, allow_sensitive=True, max_bytes=8192),
                object_pairs_hook=unique_json_pairs)
            if (not isinstance(body, dict) or body.get("id") != child_external or
                    body.get("parentId", body.get("parent_id")) != parent_external):
                return None
            return parent
        except (ValueError, TypeError, UnicodeError, PermissionError):
            return None

    def _hidden_operation(self, target_id: str, operation: AuthorizationOperation) -> bool:
        profile = self.hypotheses.latest_profile(target_id)
        if profile is None:
            return False
        route = tuple(part for part in operation.display_path.split("/")
                      if part and not part.startswith("{"))
        for signal in profile.signals[:100]:
            if signal.code != "SURFACE_INTERNAL" or signal.method not in {None, operation.method}:
                continue
            if signal.source_id == operation.exchange_id:
                return True
            signal_path = signal.display.split("/", 1)[-1]
            candidate_route = tuple(part for part in signal_path.split("/")
                                    if part and not part.startswith("{"))
            if len(route) >= 2 and route == candidate_route:
                return True
        return False

    def generate(self, hunt: AuthorizationHunt, package: TargetPackage) -> tuple[AuthorizationCandidate, ...]:
        if hunt.target_id != package.target.id or hunt.package_id != package.id:
            raise ValueError("authorization hunt package mismatch")
        if hunt.status is not HuntStatus.CREATED:
            raise ValueError("authorization hunt already started")
        self.ledger.transition(hunt.id, hunt.target_id, HuntStatus.CREATED, HuntStatus.PROFILING)
        surface = self.profile(package)
        learned = self.behaviour.profile(package.target.id) if self.behaviour else None
        learned_by_exchange = ({exchange_id: item for item in learned.operations
                                for exchange_id in item["exchange_ids"]} if learned else {})
        self.ledger.transition(hunt.id, hunt.target_id, HuntStatus.PROFILING, HuntStatus.GENERATING)
        actors = {actor.identity_id: actor for actor in surface.actors}
        ranked: list[tuple[int, AuthorizationObject, AuthorizationOperation, Boundary,
                           AuthorizationActor | None, tuple[str, ...]]] = []
        for operation in surface.operations:
            obj = next((item for item in surface.objects if item.id == operation.object_id), None)
            owner = actors.get(operation.owner_identity_id)
            if obj is None or owner is None:
                continue
            required_role = self._role_restriction(surface.target_id, obj)
            if operation.semantic_owner_success:
                try:
                    self.ledger.record_observation(
                        target_id=surface.target_id, operation_key=operation.key,
                        exchange_id=operation.exchange_id, result=MatrixResult.OBSERVED_ALLOWED,
                        test_object_id=obj.id, tenant_id=obj.tenant_id)
                except ValueError:
                    pass
            else:
                self.ledger.record_observation(
                    target_id=surface.target_id, operation_key=operation.key,
                    exchange_id=operation.exchange_id, result=MatrixResult.UNKNOWN,
                    test_object_id=obj.id, tenant_id=obj.tenant_id)
            for actor in surface.actors:
                if actor.identity_id == owner.identity_id:
                    continue
                if (obj.tenant_id in owner.observed_tenants and actor.observed_tenants and
                        obj.tenant_id not in actor.observed_tenants):
                    protocol_boundary = (Boundary.GRAPHQL_OBJECT if operation.graphql_kind == "QUERY" else
                                         Boundary.GRAPHQL_MUTATION if operation.graphql_kind == "MUTATION" else
                                         Boundary.CROSS_TENANT)
                    boundary, reasons, score = (
                        protocol_boundary,
                        ("DISTINCT_OBSERVED_TENANTS", "VERIFIED_OBJECT_OWNERSHIP",
                         "OWNER_TRAFFIC_OBSERVED") +
                        (("BATCH_READ_EXACT_OBSERVED",) if operation.protocol == "BATCH" else ()),
                        88)
                elif (obj.tenant_id in owner.observed_tenants and
                      obj.tenant_id in actor.observed_tenants and required_role and
                      required_role in owner.observed_roles and
                      required_role not in actor.observed_roles):
                    hidden = self._hidden_operation(surface.target_id, operation)
                    boundary, reasons, score = (
                        Boundary.HIDDEN_FUNCTION if hidden else Boundary.VERTICAL,
                        ("OBSERVED_ROLE_RESTRICTION", "DISTINCT_VERIFIED_ROLES",
                         "OWNER_TRAFFIC_OBSERVED") +
                        (("MATCHED_INTERNAL_SURFACE",) if hidden else ()),
                        90 if hidden else 85)
                elif (obj.tenant_id in owner.observed_tenants and
                      obj.tenant_id in actor.observed_tenants and owner.principal_id and
                      actor.principal_id and owner.principal_id != actor.principal_id):
                    boundary, reasons, score = (Boundary.HORIZONTAL,
                                                ("SAME_TENANT_DISTINCT_PRINCIPALS",
                                                 "VERIFIED_OBJECT_OWNERSHIP", "OWNER_TRAFFIC_OBSERVED"), 77)
                else:
                    continue
                if operation.semantic_owner_success:
                    score += 5
                if actor.session_id and owner.session_id:
                    score += 5
                else:
                    score -= 15
                if any(other.key == operation.key and other.owner_identity_id == actor.identity_id
                       and other.semantic_owner_success for other in surface.operations):
                    score += 8
                if boundary is Boundary.GRAPHQL_MUTATION:
                    score -= 15  # Recipe-bound writes remain costlier than read comparisons.
                if operation.protocol == "BATCH" and not operation.semantic_owner_success:
                    continue
                learned_operation = learned_by_exchange.get(operation.exchange_id)
                if learned_operation and learned:
                    role_gap = any(row["operation_key"] == learned_operation["key"] and
                                   row["role_id"] in actor.observed_roles and
                                   row["state"] == "NOT_OBSERVED"
                                   for row in learned.role_operation_matrix)
                    if role_gap:
                        score += 3
                        reasons += ("LEARNED_ROLE_OPERATION_GAP_NOT_DENIAL",)
                ranked.append((score, obj, operation, boundary, actor, reasons))
            if (operation.method in {"GET", "HEAD"} and
                    operation.protocol == "REST" and operation.graphql_kind is None and
                    operation.semantic_owner_success and
                    self._protected_artifact_facts(surface.target_id, obj)):
                ranked.append((70, obj, operation, Boundary.ANONYMOUS, None,
                               ("OWNER_TRAFFIC_OBSERVED", "VERIFIED_OBJECT_OWNERSHIP",
                                "ANONYMOUS_COMPARISON_PENDING")))
            parent = self._observed_parent_child(surface, obj, operation)
            if parent is not None:
                for actor in surface.actors:
                    if (actor.identity_id == owner.identity_id or
                            obj.tenant_id in actor.observed_tenants or
                            not any(other.object_type == parent.object_type and
                                    other.owner_identity_id == actor.identity_id and
                                    other.tenant_id in actor.observed_tenants
                                    for other in surface.objects)):
                        continue
                    ranked.append((75, obj, operation, Boundary.PARENT_CHILD, actor,
                                   ("NESTED_OWNER_REQUEST", "READBACK_PARENT_MATCH",
                                    "FOREIGN_VERIFIED_PARENT", "MANUAL_BINDING_REQUIRED")))
        result = []
        seen = set()
        for score, obj, operation, boundary, actor, reasons in sorted(
                ranked, key=lambda item: (-item[0], item[2].key, item[3].value)):
            dedupe = candidate_dedupe_key(surface.target_id, boundary.value, obj.id,
                                          operation.key, actor.identity_id if actor else None)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            candidate = self._candidate(hunt, surface, obj, operation, boundary,
                                        actor, reasons, score)
            result.append(candidate)
            if len(result) >= hunt.candidate_limit:
                break
        self.ledger.transition(hunt.id, hunt.target_id, HuntStatus.GENERATING,
                               HuntStatus.READY if result else HuntStatus.BLOCKED,
                               None if result else "NO_ELIGIBLE_BOUNDARY")
        return tuple(result)

    def _hypothesis(self, candidate: AuthorizationCandidate,
                    operation: AuthorizationOperation,
                    owned: AuthorizationObject) -> Hypothesis:
        skill_name = {Boundary.CROSS_TENANT: "cross-tenant-object-authorization",
                      Boundary.HORIZONTAL: "horizontal-object-authorization",
                      Boundary.VERTICAL: "vertical-role-authorization",
                      Boundary.HIDDEN_FUNCTION: "hidden-function-authorization",
                      Boundary.ANONYMOUS: "unauthenticated-sensitive-download",
                      Boundary.GRAPHQL_OBJECT: "graphql-object-authorization",
                      Boundary.GRAPHQL_MUTATION: "graphql-mutation-authorization",
                      Boundary.PARENT_CHILD: "nested-resource-authorization"}[candidate.boundary]
        if operation.protocol == "BATCH":
            skill_name = "batch-object-authorization"
        now = datetime.now(timezone.utc)
        statement = ("Check whether a verified foreign principal receives the same "
                     "protected owned object through the observed operation.")
        if candidate.boundary is Boundary.PARENT_CHILD:
            statement = ("Check whether a foreign parent can be paired with this verified "
                         "owned child to disclose protected child data.")
        return self.hypotheses.upsert(Hypothesis(
            "HYP-" + uuid.uuid4().hex, candidate.target_id,
            _hash("authorization", candidate.dedupe_key), candidate.boundary.value,
            statement, HypothesisStatus.READY_FOR_EXPERIMENT, candidate.score,
            0.7, "Protected object disclosure", "MEDIUM",
            operation.operation_id if candidate.boundary in {Boundary.GRAPHQL_OBJECT,
                                                             Boundary.GRAPHQL_MUTATION} and
            operation.operation_id else operation.display_path,
            "TENANT" if candidate.boundary in {Boundary.CROSS_TENANT,
                                                Boundary.GRAPHQL_OBJECT,
                                                Boundary.GRAPHQL_MUTATION} else
            "ROLE" if candidate.boundary in {Boundary.VERTICAL, Boundary.HIDDEN_FUNCTION} else
            "AUTHENTICATED" if candidate.boundary is Boundary.ANONYMOUS else "OBJECT",
            "Verified owner object and operation support a controlled comparison.",
            ("owner control", "foreign owned control", "invalid object control"), (),
            "Compare two verified owners and a foreign-object request.",
            "Foreign actor receives matching protected object data.",
            "Foreign actor is denied or receives no protected object data.",
            (skill_name,), HypothesisSource.DETERMINISTIC, "AUTHORIZATION_SPECIALIST",
            tuple(dict.fromkeys((*operation.evidence_ids, *owned.evidence_ids)))[:16],
            (*owned.facts, *self._protected_artifact_facts(candidate.target_id, owned))[:8], now, now))

    def prepare(self, candidate_id: str, package: TargetPackage, *,
                allow_setup: bool = True) -> AuthorizationCandidate:
        """Create a bounded Phase 15 plan; this method never dispatches traffic."""
        if self.context is None or self.router is None or self.planner is None:
            raise ValueError("authorization planning is unavailable")
        candidate = self.ledger.get_candidate(candidate_id, package.target.id)
        if candidate is None:
            raise LookupError("authorization candidate not found")
        if candidate.plan_id:
            return candidate
        if candidate.boundary is Boundary.PARENT_CHILD:
            return self._prepare_nested(candidate, package)
        source_exchange = self.traffic.get_exchange(candidate.owner_exchange_id)
        if (source_exchange is not None and source_exchange.request.record.method == "GET" and
                (url := self._request_url(source_exchange, self.evidence)) and
                "/batch/" in urlsplit(url).path and
                "BATCH_READ_EXACT_OBSERVED" in candidate.reasons):
            return self._prepare_batch(candidate, package)
        if candidate.boundary not in {Boundary.CROSS_TENANT, Boundary.HORIZONTAL,
                                      Boundary.VERTICAL, Boundary.HIDDEN_FUNCTION,
                                      Boundary.ANONYMOUS, Boundary.GRAPHQL_OBJECT,
                                      Boundary.GRAPHQL_MUTATION}:
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_MANUAL_REVIEW")
        hunt = self.ledger.get_hunt(candidate.hunt_id, candidate.target_id)
        if hunt is None or hunt.package_id != package.id or hunt.status is not HuntStatus.READY:
            raise ValueError("authorization hunt is not ready")
        surface = self.profile(package)
        by_id = {item.identity_id: item for item in surface.actors}
        owner = by_id.get(candidate.owner_identity_id)
        foreign = by_id.get(candidate.boundary_identity_id or "")
        if (owner is None or not owner.session_id or
                (candidate.boundary is not Boundary.ANONYMOUS and
                 (foreign is None or not foreign.session_id))):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_SESSION")
        owned = next((item for item in surface.objects if item.id == candidate.test_object_id), None)
        operation = next((item for item in surface.operations if
                          item.exchange_id == candidate.owner_exchange_id and
                          item.object_id == candidate.test_object_id and
                          item.semantic_owner_success and
                          (item.method in {"GET", "HEAD"} or
                           (candidate.boundary is Boundary.GRAPHQL_OBJECT and
                            item.method == "POST" and item.graphql_kind == "QUERY") or
                           (item.method == "POST" and item.graphql_kind == "MUTATION") or
                           (item.method == "POST" and item.protocol == "REST") or
                           (item.method in {"PATCH", "PUT"} and item.protocol == "REST"))), None)
        if owned is None or operation is None:
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_TEMPLATE")
        if operation.method in {"PATCH", "PUT"} or (
                operation.method == "POST" and operation.protocol == "REST") or (
                operation.graphql_kind == "MUTATION" and operation.method == "POST"
                and self.factory is not None):
            return self._prepare_typed_mutation(candidate, hunt, package, owned,
                                                operation, owner, foreign)
        mutation = candidate.boundary is Boundary.GRAPHQL_MUTATION
        if mutation:
            source = self.traffic.get_exchange(operation.exchange_id)
            body_ref = source.request.body_evidence_id if source else None
            body_item = self.evidence.get_evidence(body_ref) if body_ref else None
            try:
                if body_item is None or body_item.content_size > 8192:
                    raise ValueError
                payload = json.loads(self.evidence.read_content(
                    body_ref, allow_sensitive=True, max_bytes=8192))
                if not isinstance(payload.get("variables"), dict) or len(payload["variables"]) != 2:
                    raise ValueError
                changes = set(payload["variables"]) - {operation.variable_name}
                name_variable = next(iter(changes)) if len(changes) == 1 else ""
                operation_name = single_rename_operation(
                    payload.get("query", ""), operation.variable_name or "", name_variable)
                if operation_name is None or payload.get("operationName") != operation_name:
                    raise ValueError
            except (AttributeError, TypeError, ValueError, PermissionError):
                return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                                  status="NEEDS_MANUAL_REVIEW")
        owner_read = next((item for item in surface.operations if mutation and
                           item.object_id == owned.id and item.owner_identity_id == owner.identity_id and
                           item.method == "GET" and item.protocol == "REST" and
                           item.semantic_owner_success), None)
        if mutation and owner_read is None:
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_TEMPLATE")
        comparison = owner_read if mutation else operation
        foreign_control = next((item for item in surface.operations if foreign and
                                item.key == comparison.key and item.owner_identity_id == foreign.identity_id
                                and item.semantic_owner_success and item.method == comparison.method), None)
        foreign_object = next((item for item in surface.objects if foreign_control and
                               item.id == foreign_control.object_id and
                               item.tenant_id in foreign.observed_tenants), None)
        if (foreign_control is None and candidate.boundary in {
                Boundary.CROSS_TENANT, Boundary.HORIZONTAL, Boundary.GRAPHQL_OBJECT,
                Boundary.GRAPHQL_MUTATION} and
                hunt.mode is AuthorizationMode.BOUNDED_AUTONOMOUS and allow_setup):
            self._resolve_control_with_factory(package, owned, foreign, hunt.id)
            surface = self.profile(package)
            foreign_control = next((item for item in surface.operations if
                                    item.key == comparison.key and
                                    item.owner_identity_id == foreign.identity_id and
                                    item.semantic_owner_success and item.method == comparison.method), None)
            foreign_object = next((item for item in surface.objects if foreign_control and
                                   item.id == foreign_control.object_id and
                                   item.tenant_id in foreign.observed_tenants), None)
        if candidate.boundary in {Boundary.CROSS_TENANT, Boundary.HORIZONTAL,
                                  Boundary.GRAPHQL_OBJECT, Boundary.GRAPHQL_MUTATION} and (
                foreign_control is None or foreign_object is None):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_OBJECT")
        hypothesis = self._hypothesis(candidate, operation, owned)
        skill_name = {Boundary.CROSS_TENANT: "cross-tenant-object-authorization",
                      Boundary.HORIZONTAL: "horizontal-object-authorization",
                      Boundary.VERTICAL: "vertical-role-authorization",
                      Boundary.HIDDEN_FUNCTION: "hidden-function-authorization",
                      Boundary.ANONYMOUS: "unauthenticated-sensitive-download",
                      Boundary.GRAPHQL_OBJECT: "graphql-object-authorization",
                      Boundary.GRAPHQL_MUTATION: "graphql-mutation-authorization"}[candidate.boundary]
        if candidate.boundary in {Boundary.GRAPHQL_OBJECT, Boundary.GRAPHQL_MUTATION}:
            assert operation.operation_id is not None
            stored = self.objects.get(owned.id, candidate.target_id)
            if stored is None:
                return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                                  status="BLOCKED", hypothesis_id=hypothesis.id)
            subject = hashlib.sha256(self._external_id(stored).encode()).hexdigest()
            existing = next((fact for fact in self.evidence.find_facts(
                subject, "graphql_operation", limit=8).items if fact.target_ref == candidate.target_id and
                fact.status is FactStatus.ACTIVE and fact.object == operation.operation_id), None)
            if existing is None:
                existing = self.evidence.create_fact(
                    subject, "graphql_operation", operation.operation_id, confidence=1,
                    evidence_ids=operation.evidence_ids[:2], source="AUTHORIZATION_SPECIALIST",
                    target_ref=candidate.target_id)
            owned = replace(owned, facts=(*owned.facts, existing.fact_id))
        context = self.context.build(hypothesis, self.hypotheses.latest_profile(candidate.target_id),
                                     package)
        routes = self.router.route(hypothesis, context)
        selected = next((row for row in routes if row["skill"]["name"] == skill_name), None)
        if selected is None or selected["prerequisites"]["state"] != PrerequisiteState.READY.value:
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_MANUAL_REVIEW", hypothesis_id=hypothesis.id)
        def bind(item: AuthorizationObject, source: AuthorizationOperation,
                 actor: AuthorizationActor | None, role: str, variant: str) -> AuthorizationPlanBinding:
            return AuthorizationPlanBinding(source.exchange_id, item.id, item.object_type,
                                            item.external_id_hash, source.method,
                                            actor.identity_id if actor else None,
                                            actor.session_id if actor else None,
                                            role, variant, source.operation_id,
                                            "AUTHORIZATION_GRAPHQL_QUERY_V1" if
                                            source.graphql_kind == "QUERY" else
                                            "AUTHORIZATION_GRAPHQL_MUTATION_V1" if
                                            source.graphql_kind == "MUTATION" else
                                            "AUTHORIZATION_OBJECT_PATH_V1",
                                            source.variable_name)
        controls = (bind(owned, comparison, owner, "CONTROL", "OWNER"),)
        if foreign_control is not None and foreign_object is not None:
            controls += (bind(foreign_object, foreign_control, foreign, "CONTROL", "OWNER"),)
        if mutation:
            bindings = (*controls, bind(owned, operation, owner, "OTHER", "INVALID_OBJECT"),
                        bind(owned, operation, foreign, "BOUNDARY", "FOREIGN"),
                        bind(owned, owner_read, owner, "OTHER", "POST_READBACK"))
        else:
            boundary_variant = "ANONYMOUS" if candidate.boundary is Boundary.ANONYMOUS else "FOREIGN"
            bindings = (*controls, bind(owned, operation, owner, "OTHER", "INVALID_OBJECT"),
                        bind(owned, operation, foreign, "BOUNDARY", boundary_variant),
                        bind(owned, operation, foreign, "BOUNDARY", boundary_variant))
        if len(bindings) > hunt.request_budget:
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_MANUAL_REVIEW", hypothesis_id=hypothesis.id)
        plan = self.planner.bind_authorization(package, hypothesis, context, skill_name,
                                               bindings, request_cap=hunt.request_budget)
        for item in (owned, foreign_object) if foreign_object is not None else (owned,):
            stored = self.objects.get(item.id, candidate.target_id)
            if stored is None:
                return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                                  status="BLOCKED", hypothesis_id=hypothesis.id,
                                                  plan_id=str(plan["id"]))
            self.objects.add_requirement(
                plan_id=str(plan["id"]), target_id=candidate.target_id,
                object_type=stored.object_type, recipe_id=stored.recipe_id,
                identity_id=stored.creator_identity_id, tenant_id=stored.tenant_id,
                parent_id=stored.parent_id, test_object_id=stored.id)
        return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                          status="PLANNED", hypothesis_id=hypothesis.id,
                                          plan_id=str(plan["id"]))

    def _prepare_batch(self, candidate: AuthorizationCandidate,
                       package: TargetPackage) -> AuthorizationCandidate:
        hunt = self.ledger.get_hunt(candidate.hunt_id, candidate.target_id)
        if (hunt is None or hunt.package_id != package.id or
                hunt.status is not HuntStatus.READY or hunt.request_budget < 4):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_MANUAL_REVIEW")
        surface = self.profile(package)
        actors = {actor.identity_id: actor for actor in surface.actors}
        owner = actors.get(candidate.owner_identity_id)
        actor = actors.get(candidate.boundary_identity_id or "")
        item = next((row for row in surface.objects if row.id == candidate.test_object_id), None)
        source = next((row for row in surface.operations if
                       row.exchange_id == candidate.owner_exchange_id and
                       row.object_id == candidate.test_object_id and
                       row.protocol == "BATCH" and row.method == "GET" and
                       row.semantic_owner_success), None)
        if (owner is None or actor is None or item is None or source is None or
                not owner.session_id or not actor.session_id):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_TEMPLATE")
        exchange = self.traffic.get_exchange(source.exchange_id)
        url = self._request_url(exchange, self.evidence) if exchange else None
        first = self.objects.get(item.id, candidate.target_id)
        if url is None or first is None:
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_TEMPLATE")
        ids = urlsplit(url).path.rsplit("/", 1)[-1].split(",")
        if len(ids) != 2 or ids[0] != self._external_id(first):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_TEMPLATE")
        peer = next((row for row in surface.objects if row.id != item.id and
                     row.owner_identity_id == owner.identity_id and
                     row.tenant_id == item.tenant_id and
                     self._external_id(self.objects.get(row.id, candidate.target_id)) == ids[1]), None)
        actor_object = next((row for row in surface.objects if
                             row.owner_identity_id == actor.identity_id and
                             row.tenant_id in actor.observed_tenants and
                             row.tenant_id != item.tenant_id and
                             row.object_type == item.object_type and
                             any(op.object_id == row.id and op.method == "GET" and
                                 op.protocol == "REST" and op.semantic_owner_success
                                 for op in surface.operations)), None)
        actor_control = next((op for op in surface.operations if actor_object and
                              op.object_id == actor_object.id and op.method == "GET" and
                              op.protocol == "REST" and op.semantic_owner_success), None)
        if peer is None or actor_object is None or actor_control is None:
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_OBJECT")
        hypothesis = self._hypothesis(candidate, source, item)
        context = self.context.build(hypothesis,
                                     self.hypotheses.latest_profile(candidate.target_id), package)
        selection = next((row for row in self.router.route(hypothesis, context)
                          if row["skill"]["name"] == "batch-object-authorization"), None)
        if selection is None or selection["prerequisites"]["state"] != PrerequisiteState.READY.value:
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_MANUAL_REVIEW",
                                              hypothesis_id=hypothesis.id)
        def batch_binding(identity: AuthorizationActor, role: str, variant: str):
            return AuthorizationPlanBinding(
                source.exchange_id, item.id, item.object_type, item.external_id_hash,
                "GET", identity.identity_id, identity.session_id, role, variant,
                source.operation_id, "AUTHORIZATION_BATCH_PATH_V1", None,
                None, None, peer.id, actor_object.id)
        own = AuthorizationPlanBinding(
            actor_control.exchange_id, actor_object.id, actor_object.object_type,
            actor_object.external_id_hash, "GET", actor.identity_id, actor.session_id,
            "CONTROL", "OWNER", actor_control.operation_id)
        bindings = (batch_binding(owner, "CONTROL", "OWNER"), own,
                    batch_binding(actor, "BOUNDARY", "FOREIGN"),
                    batch_binding(actor, "BOUNDARY", "FOREIGN"))
        try:
            plan = self.planner.bind_authorization(
                package, hypothesis, context, "batch-object-authorization",
                bindings, request_cap=hunt.request_budget)
        except (LookupError, ValueError):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_MANUAL_REVIEW",
                                              hypothesis_id=hypothesis.id)
        for selected in (item, peer, actor_object):
            stored = self.objects.get(selected.id, candidate.target_id)
            if stored is None:
                return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                                  status="BLOCKED", hypothesis_id=hypothesis.id)
            self.objects.add_requirement(
                plan_id=str(plan["id"]), target_id=candidate.target_id,
                object_type=stored.object_type, recipe_id=stored.recipe_id,
                identity_id=stored.creator_identity_id, tenant_id=stored.tenant_id,
                parent_id=stored.parent_id, test_object_id=stored.id)
        return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                          status="PLANNED", hypothesis_id=hypothesis.id,
                                          plan_id=str(plan["id"]))

    def _prepare_nested(self, candidate: AuthorizationCandidate,
                        package: TargetPackage) -> AuthorizationCandidate:
        hunt = self.ledger.get_hunt(candidate.hunt_id, candidate.target_id)
        if (hunt is None or hunt.package_id != package.id or
                hunt.status is not HuntStatus.READY or hunt.request_budget < 4):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_MANUAL_REVIEW")
        surface = self.profile(package)
        actors = {actor.identity_id: actor for actor in surface.actors}
        owner = actors.get(candidate.owner_identity_id)
        foreign = actors.get(candidate.boundary_identity_id or "")
        child = next((item for item in surface.objects if item.id == candidate.test_object_id), None)
        operation = next((item for item in surface.operations if
                          item.exchange_id == candidate.owner_exchange_id and
                          item.object_id == candidate.test_object_id and
                          item.method == "GET" and item.protocol == "REST" and
                          item.semantic_owner_success), None)
        parent = self._observed_parent_child(surface, child, operation) if child and operation else None
        foreign_parent = next((item for item in surface.objects if parent and foreign and
                               item.object_type == parent.object_type and
                               item.owner_identity_id == foreign.identity_id and
                               item.tenant_id in foreign.observed_tenants and
                               item.tenant_id != child.tenant_id), None)
        if (owner is None or foreign is None or not owner.session_id or
                not foreign.session_id or child is None or operation is None or
                parent is None or foreign_parent is None):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_OBJECT")
        hypothesis = self._hypothesis(candidate, operation, child)
        context = self.context.build(hypothesis,
                                     self.hypotheses.latest_profile(candidate.target_id), package)
        selection = next((item for item in self.router.route(hypothesis, context)
                          if item["skill"]["name"] == "nested-resource-authorization"), None)
        if selection is None or selection["prerequisites"]["state"] != PrerequisiteState.READY.value:
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_MANUAL_REVIEW",
                                              hypothesis_id=hypothesis.id)
        def bind(actor: AuthorizationActor, role: str, variant: str) -> AuthorizationPlanBinding:
            nested = role == "BOUNDARY"
            return AuthorizationPlanBinding(
                operation.exchange_id, child.id, child.object_type, child.external_id_hash,
                "GET", actor.identity_id, actor.session_id, role, variant,
                operation.operation_id,
                "AUTHORIZATION_NESTED_PARENT_V1" if nested else
                "AUTHORIZATION_OBJECT_PATH_V1", None,
                parent.id if nested else None,
                foreign_parent.id if nested else None)
        bindings = (bind(owner, "CONTROL", "OWNER"),
                    bind(owner, "OTHER", "INVALID_OBJECT"),
                    bind(foreign, "BOUNDARY", "FOREIGN"),
                    bind(foreign, "BOUNDARY", "FOREIGN"))
        try:
            plan = self.planner.bind_authorization(
                package, hypothesis, context, "nested-resource-authorization",
                bindings, request_cap=hunt.request_budget)
        except (LookupError, ValueError):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_MANUAL_REVIEW",
                                              hypothesis_id=hypothesis.id)
        for item in (child, parent, foreign_parent):
            stored = self.objects.get(item.id, candidate.target_id)
            if stored is None:
                return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                                  status="BLOCKED", hypothesis_id=hypothesis.id)
            self.objects.add_requirement(
                plan_id=str(plan["id"]), target_id=candidate.target_id,
                object_type=stored.object_type, recipe_id=stored.recipe_id,
                identity_id=stored.creator_identity_id, tenant_id=stored.tenant_id,
                parent_id=stored.parent_id, test_object_id=stored.id)
        return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                          status="PLANNED", hypothesis_id=hypothesis.id,
                                          plan_id=str(plan["id"]))

    def _prepare_typed_mutation(self, candidate: AuthorizationCandidate,
                                hunt: AuthorizationHunt, package: TargetPackage,
                                owned: AuthorizationObject,
                                operation: AuthorizationOperation,
                                owner: AuthorizationActor,
                                foreign: AuthorizationActor | None) -> AuthorizationCandidate:
        if (self.factory is None or foreign is None or not foreign.session_id or
                candidate.boundary not in {Boundary.CROSS_TENANT, Boundary.HORIZONTAL,
                                            Boundary.VERTICAL, Boundary.HIDDEN_FUNCTION,
                                            Boundary.GRAPHQL_MUTATION} or
                hunt.request_budget < 7):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_MANUAL_REVIEW")
        item = self.objects.get(owned.id, candidate.target_id)
        recipe = self.factory.recipes.get(package.id, item.recipe_id) if item else None
        if (item is None or recipe is None or recipe.sha256 != item.recipe_hash or
                not item.disposable or item.state is not ObjectState.READY or
                item.verified_at is None):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_OBJECT")
        mutation = next((entry for entry in recipe.mutations if
                         entry.mutation_type.value == "RENAME" and
                         entry.write.method == operation.method), None)
        if mutation is None:
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_TEMPLATE")
        nested = (isinstance(mutation.write.body, dict) and
                  isinstance(mutation.write.body.get("variables"), dict) and
                  "parentId" in mutation.write.body["variables"])
        parent = foreign_parent = None
        if nested:
            parent = self.objects.get(item.parent_id, candidate.target_id) if item.parent_id else None
            if (parent is None or parent.state is not ObjectState.READY or
                    not parent.disposable or not parent.verified_at or
                    parent.creator_identity_id != owner.identity_id or
                    parent.tenant_id != item.tenant_id or
                    recipe.parent_type != parent.object_type or
                    len(foreign.observed_tenants) != 1 or
                    foreign.observed_tenants[0] == item.tenant_id):
                return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                                  status="NEEDS_OBJECT")
            foreign_parent = self.objects.find_reusable(
                candidate.target_id, parent.object_type,
                foreign.observed_tenants[0], foreign.identity_id)
            if foreign_parent is None:
                return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                                  status="NEEDS_OBJECT")
        source = self.traffic.get_exchange(operation.exchange_id)
        if source is None or source.request.body_evidence_id is None:
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_TEMPLATE")
        try:
            external = self._external_id(item)
            parent_external = self._external_id(parent) if parent else None
            expected_url = mutation.write.template(test_name=item.test_name,
                                                   object_id=external,
                                                   parent_id=parent_external).url
            observed_url = self._request_url(source, self.evidence)
            raw = self.evidence.read_content(
                source.request.body_evidence_id, allow_sensitive=True, max_bytes=8192)
            if hashlib.sha256(raw).hexdigest() != source.request.body_hash:
                raise ValueError
            body = json.loads(raw, object_pairs_hook=unique_json_pairs)
            if observed_url != expected_url or not isinstance(body, dict):
                raise ValueError
            if mutation.write.method == "POST" and operation.protocol == "GRAPHQL":
                expected = mutation.write.template(test_name="hackbot-test-control",
                                                   object_id=external,
                                                   parent_id=parent_external)
                expected_body = json.loads(expected.body or b"{}")
                variables = body.get("variables")
                if (set(body) != set(expected_body) or
                        body.get("query") != expected_body["query"] or
                        body.get("operationName") != expected_body["operationName"] or
                        not isinstance(variables, dict) or
                        set(variables) != ({"parentId", "id", "name"} if nested else
                                           {"id", "name"}) or
                        variables.get("id") != external or
                        (nested and variables.get("parentId") != parent_external) or
                        not isinstance(variables.get("name"), str) or
                        not variables["name"].startswith("hackbot-test-")):
                    raise ValueError
                if nested:
                    response = source.response
                    if response is None or not response.body_evidence_id:
                        raise ValueError
                    raw_response = self.evidence.read_content(
                        response.body_evidence_id, allow_sensitive=True, max_bytes=8192)
                    if hashlib.sha256(raw_response).hexdigest() != response.body_hash:
                        raise ValueError
                    result = json.loads(raw_response, object_pairs_hook=unique_json_pairs)
                    data = result.get("data") if isinstance(result, dict) else None
                    node = next(iter(data.values())) if isinstance(data, dict) and len(data) == 1 else None
                    if (not isinstance(node, dict) or node.get("id") != external or
                            node.get("parentId") != parent_external):
                        raise ValueError
            elif (set(body) != {mutation.field} or
                  not isinstance(body[mutation.field], str) or
                  not body[mutation.field].startswith("hackbot-test-")):
                raise ValueError
        except (ValueError, TypeError, UnicodeError, PermissionError):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_TEMPLATE")
        hypothesis = self._hypothesis(candidate, operation, owned)
        context = self.context.build(hypothesis,
                                     self.hypotheses.latest_profile(candidate.target_id),
                                     package)
        try:
            plan = self.planner.bind_typed_mutation(
                package, hypothesis, context,
                TypedMutationPlanBinding(
                    item.id, item.object_type, item.external_id_hash or "",
                    item.recipe_id, item.recipe_hash, mutation.mutation_type.value,
                    mutation.write.method, mutation.readback.operation,
                    mutation.write.operation, owner.identity_id, owner.session_id or "",
                    foreign.identity_id, foreign.session_id, candidate.boundary.value,
                    parent.id if parent else None,
                    foreign_parent.id if foreign_parent else None))
        except (LookupError, ValueError):
            return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                              status="NEEDS_MANUAL_REVIEW",
                                              hypothesis_id=hypothesis.id)
        self.objects.add_requirement(
            plan_id=str(plan["id"]), target_id=candidate.target_id,
            object_type=item.object_type, recipe_id=item.recipe_id,
            identity_id=item.creator_identity_id, tenant_id=item.tenant_id,
            parent_id=item.parent_id, test_object_id=item.id)
        for required in (parent, foreign_parent):
            if required is not None:
                self.objects.add_requirement(
                    plan_id=str(plan["id"]), target_id=candidate.target_id,
                    object_type=required.object_type, recipe_id=required.recipe_id,
                    identity_id=required.creator_identity_id, tenant_id=required.tenant_id,
                    parent_id=required.parent_id, test_object_id=required.id)
        return self.ledger.link_candidate(candidate.id, candidate.target_id,
                                          status="PLANNED", hypothesis_id=hypothesis.id,
                                          plan_id=str(plan["id"]))

    def _resolve_control_with_factory(self, package: TargetPackage,
                                      owned: AuthorizationObject,
                                      foreign: AuthorizationActor,
                                      hunt_id: str) -> ObjectFactoryResult | None:
        if (self.factory is None or foreign.session_id is None or
                len(foreign.observed_tenants) != 1 or
                package.rules.automated_testing_allowed is not True or
                package.autonomy.create_disposable_objects is not PolicyDecision.ALLOW or
                package.autonomy.state_changing is not PolicyDecision.ALLOW):
            return None
        tenant_id = foreign.observed_tenants[0]
        tenant = self.identities.get_tenant(package.target.id, tenant_id)
        if tenant is None:
            return None
        for metadata in self.factory.recipes.list_for_package(package.id)[:12]:
            if metadata["object_type"] != owned.object_type:
                continue
            recipe = self.factory.recipes.get(package.id, metadata["id"])
            if (recipe is None or recipe.target_id != package.target.id or
                    recipe.expected_owner != foreign.alias or recipe.expected_tenant != tenant.label or
                    recipe.parent_type is not None):
                continue
            result = self.factory.resolve(package_id=package.id, recipe_id=recipe.id,
                                          identity_id=foreign.identity_id, tenant_id=tenant_id,
                                          session_id=foreign.session_id,
                                          purpose="Owned authorization comparison control")
            if result.created_new and result.item is not None:
                self.ledger.link_created_object(hunt_id, package.target.id, result.item.id)
            return result
        return None

    def comparison_control_ready(self, candidate_id: str, package: TargetPackage) -> bool:
        candidate = self.ledger.get_candidate(candidate_id, package.target.id)
        if candidate is None or candidate.boundary not in {Boundary.CROSS_TENANT,
                                                            Boundary.HORIZONTAL}:
            return False
        surface = self.profile(package)
        owner = next((item for item in surface.operations
                      if item.exchange_id == candidate.owner_exchange_id
                      and item.object_id == candidate.test_object_id
                      and item.protocol == "REST" and item.method in {"GET", "HEAD"}
                      and item.semantic_owner_success), None)
        if owner is None:
            return False
        actor = next((item for item in surface.actors
                      if item.identity_id == candidate.boundary_identity_id), None)
        if actor is None:
            return False
        foreign = next((item for item in surface.operations
                        if item.key == owner.key and item.method == owner.method
                        and item.owner_identity_id == candidate.boundary_identity_id
                        and item.object_id != candidate.test_object_id
                        and item.semantic_owner_success), None)
        return bool(foreign and any(item.id == foreign.object_id and
                                   item.owner_identity_id == candidate.boundary_identity_id and
                                   item.tenant_id in actor.observed_tenants
                                   for item in surface.objects))

    def ensure_comparison_control(self, candidate_id: str,
                                  package: TargetPackage) -> ObjectFactoryResult | None:
        candidate = self.ledger.get_candidate(candidate_id, package.target.id)
        if candidate is None or candidate.boundary not in {Boundary.CROSS_TENANT,
                                                            Boundary.HORIZONTAL}:
            return None
        hunt = self.ledger.get_hunt(candidate.hunt_id, package.target.id)
        if (hunt is None or hunt.package_id != package.id or
                hunt.mode is not AuthorizationMode.BOUNDED_AUTONOMOUS or
                hunt.status is not HuntStatus.READY):
            return None
        surface = self.profile(package)
        owned = next((item for item in surface.objects
                      if item.id == candidate.test_object_id), None)
        foreign = next((item for item in surface.actors
                        if item.identity_id == candidate.boundary_identity_id), None)
        if (owned is None or foreign is None or not foreign.session_id or
                not any(item.exchange_id == candidate.owner_exchange_id
                        and item.object_id == owned.id and item.protocol == "REST"
                        and item.method in {"GET", "HEAD"} and item.semantic_owner_success
                        for item in surface.operations)):
            return None
        return self._resolve_control_with_factory(package, owned, foreign, hunt.id)

    def cleanup_created_objects(self, hunt_id: str, target_id: str) -> dict[str, int]:
        """Attempt cleanup only for objects this hunt created, never reused fixtures."""
        if self.factory is None:
            return {"cleaned": 0, "pending": 0}
        actors = {actor.identity_id: actor for actor in self._actors(target_id)}
        cleaned = pending = 0
        for object_id, outcome in self.ledger.created_objects(hunt_id, target_id):
            if outcome == "CLEANED":
                cleaned += 1
                continue
            item = self.objects.get(object_id, target_id)
            if item is None:
                pending += 1
                continue
            if item.state is ObjectState.CLEANED:
                self.ledger.record_cleanup(hunt_id, target_id, object_id, "CLEANED")
                cleaned += 1
                continue
            actor = actors.get(item.creator_identity_id)
            if (item.cleanup_strategy is not CleanupStrategy.AUTO_CLEANUP or
                    item.state not in {ObjectState.READY, ObjectState.CLEANUP_PENDING} or
                    self.objects.active_reservation(item.id) or actor is None or
                    actor.session_id is None):
                self.ledger.record_cleanup(hunt_id, target_id, object_id,
                                           "MANUAL_CLEANUP_REQUIRED")
                pending += 1
                continue
            try:
                result = self.factory.cleanup(item.id, target_id, session_id=actor.session_id)
                outcome = result.outcome
            except (LookupError, ValueError, RuntimeError, OSError):
                outcome = "CLEANUP_REVIEW_REQUIRED"
            self.ledger.record_cleanup(hunt_id, target_id, object_id, outcome)
            if outcome == "CLEANED":
                cleaned += 1
            else:
                pending += 1
        return {"cleaned": cleaned, "pending": pending}

    def start_candidate(self, candidate_id: str, package: TargetPackage) -> dict[str, object]:
        if self.orchestrator is None:
            raise ValueError("authorization orchestrator is unavailable")
        candidate = self.ledger.get_candidate(candidate_id, package.target.id)
        if candidate is None or candidate.plan_id is None or candidate.status != "PLANNED" or candidate.run_id:
            raise ValueError("authorization candidate is not ready to run")
        hunt = self.ledger.get_hunt(candidate.hunt_id, candidate.target_id)
        if hunt is None or hunt.package_id != package.id or hunt.status not in {
                HuntStatus.READY, HuntStatus.RUNNING}:
            raise ValueError("authorization hunt is not runnable")
        detail = self.orchestrator.start(candidate.plan_id, package.id)
        self.ledger.link_candidate(candidate.id, candidate.target_id, status="RUNNING",
                                   run_id=str(detail["run"]["id"]))
        if hunt.status is HuntStatus.READY:
            self.ledger.transition(hunt.id, hunt.target_id, HuntStatus.READY, HuntStatus.RUNNING)
        return detail

    def _sync_matrix(self, candidate: AuthorizationCandidate) -> None:
        if self.orchestrator is None or not candidate.run_id or not candidate.plan_id:
            return
        run = self.orchestrator.runs.get(candidate.run_id, candidate.target_id)
        if run is None:
            return
        plan = self.orchestrator.runs.snapshot(candidate.plan_id, candidate.target_id).data
        for step in self.orchestrator.runs.steps(run.id):
            if step.action_slot is None:
                continue
            result = self.orchestrator.runs.result(step.id)
            if result is None or not result.exchange_ids:
                continue
            shape = plan["request_templates"][step.action_slot]
            object_id = shape.get("test_object_id") if shape.get("variant") != "INVALID_OBJECT" else None
            owned = self.objects.get(object_id, candidate.target_id) if object_id else None
            for exchange_id in result.exchange_ids[:1]:
                exchange = self.traffic.get_exchange(exchange_id)
                if exchange is None or exchange.response is None:
                    continue
                features = self.comparator.features(exchange)
                if features.graphql_errors_present and not features.graphql_data_present:
                    observed = MatrixResult.OBSERVED_DENIED
                elif features.status_code == 403:
                    observed = MatrixResult.OBSERVED_DENIED
                elif features.status_code == 401:
                    observed = MatrixResult.AUTH_REQUIRED
                elif features.status_code == 404:
                    observed = MatrixResult.NOT_FOUND
                elif (owned is not None and features.status_code is not None and
                      200 <= features.status_code < 300 and not features.graphql_errors_present):
                    try:
                        value = self._external_id(owned)
                        matched = hashlib.sha256(value.encode()).hexdigest() in features.object_id_hashes
                    except (ValueError, UnicodeError, PermissionError):
                        matched = False
                    observed = MatrixResult.OBSERVED_ALLOWED if matched else MatrixResult.AMBIGUOUS
                else:
                    observed = MatrixResult.AMBIGUOUS
                self.ledger.record_observation(
                    target_id=candidate.target_id, candidate_id=candidate.id,
                    operation_key=candidate.operation_key, exchange_id=exchange.id,
                    result=observed, test_object_id=owned.id if owned else None,
                    tenant_id=owned.tenant_id if owned else None)

    def advance_candidate(self, candidate_id: str, package: TargetPackage) -> dict[str, object]:
        if self.orchestrator is None:
            raise ValueError("authorization orchestrator is unavailable")
        candidate = self.ledger.get_candidate(candidate_id, package.target.id)
        if candidate is None or candidate.run_id is None or candidate.status != "RUNNING":
            raise ValueError("authorization candidate has no active run")
        previous = self.orchestrator.runs.get(candidate.run_id, candidate.target_id)
        if previous is not None and previous.status is RunStatus.COMPLETED:
            return {"run": previous.to_dict(),
                    "validation": self.validate_candidate(candidate_id, package)}
        detail = self.orchestrator.advance(candidate.run_id, package.id)
        self._sync_matrix(candidate)
        if detail["run"]["status"] == RunStatus.COMPLETED.value:
            return {**detail, "validation": self.validate_candidate(candidate_id, package)}
        if detail["run"]["status"] in {RunStatus.BLOCKED.value, RunStatus.FAILED.value,
                                        RunStatus.BUDGET_EXHAUSTED.value, RunStatus.CANCELLED.value}:
            self.ledger.link_candidate(candidate.id, candidate.target_id, status="BLOCKED")
        return detail

    def validate_candidate(self, candidate_id: str, package: TargetPackage) -> dict[str, object]:
        if self.validator is None:
            raise ValueError("authorization validator is unavailable")
        candidate = self.ledger.get_candidate(candidate_id, package.target.id)
        if candidate is None or candidate.run_id is None:
            raise ValueError("authorization candidate has no run")
        run = self.validator.runs.get(candidate.run_id, candidate.target_id)
        if run is None or run.status is not RunStatus.COMPLETED:
            raise ValueError("authorization run is not completed")
        self._sync_matrix(candidate)
        result, finding = self.validator.validate_run(run.id, candidate.target_id)
        status = ("VALIDATED" if result.status is ValidationStatus.CONFIRMED else
                  "REJECTED" if result.status is ValidationStatus.REJECTED else
                  "NEEDS_MANUAL_REVIEW")
        self.ledger.link_candidate(candidate.id, candidate.target_id, status=status,
                                   validation_id=result.id)
        self._complete_if_terminal(candidate.hunt_id, candidate.target_id)
        return {"result": result.to_dict(), "finding": finding.to_dict() if finding else None}

    def _complete_if_terminal(self, hunt_id: str, target_id: str) -> None:
        hunt = self.ledger.get_hunt(hunt_id, target_id)
        if hunt is None or hunt.status not in {HuntStatus.READY, HuntStatus.RUNNING}:
            return
        items = self.ledger.list_candidates(target_id, hunt_id=hunt_id, limit=50)
        if items and all(item.status in {"VALIDATED", "REJECTED", "BLOCKED"} for item in items):
            self.ledger.transition(hunt_id, target_id, hunt.status, HuntStatus.COMPLETED,
                                   "ALL_CANDIDATES_TERMINAL")
            self.cleanup_created_objects(hunt_id, target_id)

    def start_hunt(self, package: TargetPackage, *, mode: AuthorizationMode = AuthorizationMode.PLAN_ONLY,
                   candidate_limit: int = 12, request_budget: int = 20) -> dict[str, object]:
        hunt = self.ledger.create_hunt(package.target.id, package.id, mode=mode,
                                       candidate_limit=candidate_limit, request_budget=request_budget)
        candidates = self.generate(hunt, package)
        prepared = []
        if mode is not AuthorizationMode.MANUAL and candidates:
            for candidate in candidates:
                if candidate.hunt_id == hunt.id and candidate.status == "CANDIDATE":
                    prepared.append(self.prepare(candidate.id, package))
        if mode is AuthorizationMode.BOUNDED_AUTONOMOUS and prepared:
            if (package.rules.automated_testing_allowed is not True or
                    package.autonomy.bounded_active is not PolicyDecision.ALLOW or
                    package.autonomy.cross_identity_testing is not PolicyDecision.ALLOW):
                return {"hunt": self.ledger.get_hunt(hunt.id, hunt.target_id).to_dict(),
                        "candidates": [item.to_dict() for item in prepared],
                        "autonomous_state": "POLICY_NOT_ALLOW"}
            used = 0
            for candidate in prepared:
                plan = self.planner.store.get(candidate.plan_id, package.target.id) if candidate.plan_id else None
                needed = int(plan["request_budget"]) if plan else 0
                if candidate.status != "PLANNED" or not needed or used + needed > request_budget:
                    continue
                detail = self.start_candidate(candidate.id, package)
                for _ in range(12):
                    state = detail["run"]["status"]
                    if state not in {RunStatus.CREATED.value, RunStatus.READY.value}:
                        break
                    detail = self.advance_candidate(candidate.id, package)
                used += int(detail["run"]["requests_consumed"])
                if detail["run"]["status"] != RunStatus.COMPLETED.value:
                    current = self.ledger.get_hunt(hunt.id, hunt.target_id)
                    if current and current.status is HuntStatus.RUNNING:
                        self.ledger.transition(hunt.id, hunt.target_id, HuntStatus.RUNNING,
                                               HuntStatus.PAUSED, "RUN_REQUIRES_REVIEW")
                    break
                if detail.get("validation", {}).get("result", {}).get("status") == "CONFIRMED":
                    current = self.ledger.get_hunt(hunt.id, hunt.target_id)
                    if current and current.status is HuntStatus.RUNNING:
                        self.ledger.transition(hunt.id, hunt.target_id, HuntStatus.RUNNING,
                                               HuntStatus.COMPLETED, "CONFIRMED_STOP_PROOF")
                        self.cleanup_created_objects(hunt.id, hunt.target_id)
                    break
        if candidates and not any(item.hunt_id == hunt.id for item in candidates):
            current = self.ledger.get_hunt(hunt.id, hunt.target_id)
            if current and current.status is HuntStatus.READY:
                self.ledger.transition(hunt.id, hunt.target_id, HuntStatus.READY,
                                       HuntStatus.COMPLETED, "NO_NEW_CANDIDATES")
        self._complete_if_terminal(hunt.id, hunt.target_id)
        return {"hunt": self.ledger.get_hunt(hunt.id, hunt.target_id).to_dict(),
                "candidates": [self.ledger.get_candidate(item.id, hunt.target_id).to_dict()
                               for item in candidates]}
