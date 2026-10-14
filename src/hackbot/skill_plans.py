"""Bounded skill routing and immutable policy-simulated investigation plans."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from itertools import combinations
import hashlib
import json
import re
from typing import Any, Callable
from urllib.parse import urlsplit
import uuid

from .authorization_binding import reference_fingerprint
from .api_binding import api_batch_reference_fingerprint, api_reference_fingerprint
from .domxss_static import DOMCandidateStatus
from .domxss_store import DOMXSSStore
from .exposure_store import ExposureStore
from .exposure_models import ExposureCategory, ExposureStatus
from .postmessage_static import MessageCandidateStatus
from .postmessage_store import PostMessageStore
from .mutation_binding import DELETE_STAGES, MutationStage, STAGES, mutation_fingerprint
from .executor import RequestTemplate
from .hypotheses import Hypothesis
from .identity_registry import IdentityRegistry
from .logging import SecretRedactor
from .policy import PolicyEngine
from .policy_models import ActionCategory, ActorMode, ProposedAction
from .profile import TargetProfile
from .recon import ReconRepository
from .skills import SkillMetadata, SkillRegistry
from .store import EvidenceFactStore
from .target_package import PackageStatus, TargetPackage
from .target_scope import ScopeResult
from .traffic import TrafficStore
from .test_objects import ObjectRegistry, ObjectState


class PrerequisiteState(StrEnum):
    READY = "READY"
    MISSING_CONTEXT = "MISSING_CONTEXT"
    MISSING_IDENTITY = "MISSING_IDENTITY"
    MISSING_OBJECT = "MISSING_OBJECT"
    MISSING_TRAFFIC = "MISSING_TRAFFIC"
    MISSING_RESEARCH = "MISSING_RESEARCH"
    UNSUPPORTED = "UNSUPPORTED"


class StepType(StrEnum):
    OBSERVE = "OBSERVE"
    ESTABLISH_CONTROL = "ESTABLISH_CONTROL"
    CREATE_TEST_OBJECT = "CREATE_TEST_OBJECT"
    EXECUTE_REQUEST = "EXECUTE_REQUEST"
    COMPARE_RESPONSE = "COMPARE_RESPONSE"
    VERIFY_BROWSER = "VERIFY_BROWSER"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(frozen=True, slots=True)
class PrerequisiteResult:
    state: PrerequisiteState
    missing: tuple[str, ...]
    satisfied: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"state": self.state.value, "missing": list(self.missing), "satisfied": list(self.satisfied)}


@dataclass(frozen=True, slots=True)
class SkillContext:
    target_id: str
    hypothesis_id: str
    category: str
    boundary: str
    surface_key: str
    technologies: tuple[str, ...]
    features: tuple[str, ...]
    signals: tuple[str, ...]
    evidence: tuple[dict[str, object], ...]
    facts: tuple[dict[str, object], ...]
    traffic: tuple[dict[str, object], ...]
    identities: tuple[dict[str, object], ...]
    flags: frozenset[str]
    missing_hypothesis: tuple[str, ...]
    recon_refs: tuple[dict[str, object], ...] = ()
    message_protocol: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return {"target_id": self.target_id, "hypothesis_id": self.hypothesis_id,
                "category": self.category, "boundary": self.boundary,
                "surface_key": self.surface_key, "technologies": list(self.technologies),
                "features": list(self.features), "signals": list(self.signals),
                "evidence": list(self.evidence), "facts": list(self.facts),
                "traffic": list(self.traffic), "identities": list(self.identities),
                "flags": sorted(self.flags), "missing_hypothesis": list(self.missing_hypothesis),
                "recon_refs": list(self.recon_refs),
                "message_protocol": self.message_protocol}


def _safe(value: str, maximum: int = 160) -> str:
    text = SecretRedactor.from_environment().text(str(value))
    return text[:maximum]


def _protocol_labels(values: tuple[str, ...], limit: int) -> list[str]:
    return [_safe(value, 48) for value in values[:limit]
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:/-]{0,47}", value)]


class SkillContextBuilder:
    """Metadata only. No Evidence bodies, request bodies, credentials, or recon dumps."""

    def __init__(self, store: EvidenceFactStore, registry: IdentityRegistry,
                 traffic: TrafficStore, browser: Any | None = None,
                 recon: ReconRepository | None = None,
                 objects: ObjectRegistry | None = None,
                 dom: DOMXSSStore | None = None,
                 messages: PostMessageStore | None = None,
                 exposure: ExposureStore | None = None) -> None:
        self.store = store
        self.registry = registry
        self.traffic = traffic
        self.browser = browser
        self.recon = recon
        self.objects = objects
        self.dom = dom
        self.messages = messages
        self.exposure = exposure

    def build(self, hypothesis: Hypothesis, profile: TargetProfile | None,
              package: TargetPackage | None = None,
              skill: SkillMetadata | None = None) -> SkillContext:
        if profile is not None and profile.target_id != hypothesis.target_id:
            raise ValueError("profile target mismatch")
        signals = tuple(_safe(item.code) for item in (profile.signals if profile else ())
                        if item.surface_key == hypothesis.surface_key)[:8]
        evidence = []
        for ref in hypothesis.evidence_ids[:4]:
            item = self.store.get_evidence(ref)
            if item and item.target_ref == hypothesis.target_id:
                evidence.append({"id": item.evidence_id, "type": item.evidence_type,
                                 "sensitivity": item.sensitivity.value})
        facts = []
        verified_object_identifier = False
        for ref in hypothesis.fact_ids[:8]:
            item = self.store.get_fact(ref)
            if item and item.target_ref == hypothesis.target_id:
                facts.append({"id": item.fact_id, "predicate": _safe(item.predicate),
                              "status": item.status.value, "sensitivity": item.sensitivity.value})
                if (self.objects is not None and item.predicate == "created_by" and
                        item.status.value == "ACTIVE" and item.source == "OBJECT_FACTORY" and
                        item.confidence >= 0.9 and item.evidence_ids):
                    owned = self.objects.get(item.subject, hypothesis.target_id)
                    verified_object_identifier = bool(
                        owned and owned.state in {ObjectState.READY, ObjectState.IN_USE}
                        and owned.disposable and owned.verified_at and owned.external_id_hash
                        and owned.external_id_evidence_id and owned.creator_identity_id == item.object)
        traffic = []
        traffic_page = (self.traffic.find_by_operation(hypothesis.target_id,
                                                      hypothesis.surface_key, limit=12)
                        if hypothesis.surface_key.startswith(("GQL-", "OPERATION-")) else
                        self.traffic.find_recent(hypothesis.target_id, limit=12))
        for exchange in traffic_page.items:
            req = exchange.request
            if hypothesis.surface_key not in (req.display_path, req.origin + req.display_path,
                                              req.record.endpoint_id, req.record.operation_id):
                continue
            if len(req.origin) > 250 or len(req.display_path) > 250:
                continue
            traffic.append({"id": exchange.id, "method": req.record.method,
                            "origin": _safe(req.origin, 250), "display_path": _safe(req.display_path, 250),
                            "operation_id": req.record.operation_id,
                            "auth_state": exchange.attribution.auth_state.value,
                            "identity_id": exchange.attribution.verified_identity_id,
                            "status_code": exchange.response.record.status_code if exchange.response else None,
                            "body_hash": exchange.response.body_hash if exchange.response else None})
            if len(traffic) >= 4:
                break
        identities = []
        role_ids: set[str] = set()
        principals: set[str] = set()
        for identity in self.registry.list_identities(hypothesis.target_id, limit=8).items[:4]:
            if identity.status.value != "ACTIVE":
                continue
            memberships = self.registry.list_memberships(identity.id, limit=8).items
            tenants = sorted({m.tenant_id for m in memberships if m.status.value == "ACTIVE"})[:4]
            roles = sorted({role for m in memberships for role in m.role_ids})[:6]
            role_ids.update(roles)
            if identity.principal_id:
                principals.add(identity.principal_id)
            session_id = None
            if self.browser is not None:
                session = self.browser.get_session_for_identity(hypothesis.target_id, identity.id)
                if session is not None:
                    try:
                        context = self.browser.session_context(session.id)
                        if (context.authentication_status == "VALID" and context.browser_available
                                and context.browser_status.value == "VALID"
                                and context.verification_status.value == "MATCH"):
                            session_id = session.id
                    except (LookupError, ValueError):
                        pass
            identities.append({"id": identity.id, "principal_id": identity.principal_id,
                               "tenants": tenants, "roles": roles, "verified_session_id": session_id})
        flags: set[str] = set()
        if package is not None and package.target.id != hypothesis.target_id:
            raise ValueError("package target mismatch")
        if package is not None and package.status is PackageStatus.TRACKED:
            flags.add("in_scope_target")
        if any(set(a["tenants"]).isdisjoint(b["tenants"]) and a["tenants"] and b["tenants"]
               for a, b in combinations(identities, 2)):
            flags.add("multiple_tenants")
        if len(role_ids) >= 2 and any(set(a["roles"]) != set(b["roles"])
                                      for a, b in combinations(identities, 2)):
            flags.add("multiple_roles")
        if len(principals) >= 2:
            flags.add("multiple_principals")
        if sum(bool(i["verified_session_id"]) for i in identities) >= 1:
            flags.add("verified_sessions")
        if traffic:
            flags.add("baseline_traffic")
        if any(t["auth_state"] == "VERIFIED" for t in traffic):
            flags.add("authenticated_endpoint")
        if any(t["auth_state"] == "ANONYMOUS" for t in traffic):
            flags.add("anonymous_access")
        if "OBJECT_ID" in signals:
            flags.add("known_object_identifier")
        if verified_object_identifier:
            flags.add("known_object_identifier")
            flags.add("known_ownership")
        if any(f["predicate"] in {"owns", "owned_by", "object_owner", "tenant_owner"}
               and f["status"] == "ACTIVE" for f in facts):
            flags.add("known_ownership")
        if "API_GRAPHQL" in signals or any(t["operation_id"] for t in traffic):
            flags.add("graphql_operation")
        if "API_GRAPHQL_MUTATION" in signals or hypothesis.category == "GRAPHQL_MUTATION":
            flags.add("graphql_mutation")
        if hypothesis.category != "DOM_XSS" and any(s.startswith("JS_") for s in signals):
            flags.add("current_js")  # Still requires current-bundle validation later.
        if "JS_POSTMESSAGE" in signals:
            flags.add("message_listener")
        if hypothesis.category != "DOM_XSS" and "JS_DOM_SINK" in signals:
            flags.add("dangerous_dom_sink")
        if hypothesis.category != "DOM_XSS" and "JS_DECODER" in signals:
            flags.add("transformation_trace")
        if hypothesis.category != "DOM_XSS" and "JS_SOURCE" in signals:
            flags.add("attacker_controlled_source")
        message_protocol = None
        if (self.dom is not None and hypothesis.category == "DOM_XSS"
                and re.fullmatch(r"js:DOM-[0-9a-f]{32}", hypothesis.surface_key)):
            candidate_id = hypothesis.surface_key[3:]
            candidate = self.dom.get_candidate(hypothesis.target_id, candidate_id)
            artifact = self.dom.candidate_asset(hypothesis.target_id, candidate_id)
            if (candidate is not None and artifact is not None and artifact.state == "CURRENT"
                    and artifact.recon_sha256 == artifact.artifact_sha256
                    and candidate.asset_sha256 == artifact.artifact_sha256
                    and candidate.status in {DOMCandidateStatus.STATICALLY_SUPPORTED,
                                             DOMCandidateStatus.RUNTIME_READY,
                                             DOMCandidateStatus.RUNTIME_TESTED,
                                             DOMCandidateStatus.VALIDATION_READY}):
                flags.add("current_js")
                if candidate.attacker_controlled:
                    flags.add("attacker_controlled_source")
                if candidate.transforms and candidate.check_before_transform:
                    flags.add("transformation_trace")
                if candidate.sink_kind in {"HTML_EXECUTION", "URL_RESOURCE", "NAVIGATION_URL"}:
                    flags.add("dangerous_dom_sink")
        if (self.messages is not None and hypothesis.category == "POSTMESSAGE"
                and re.fullmatch(r"js:MSG-[0-9a-f]{32}", hypothesis.surface_key)):
            candidate = self.messages.get_candidate(hypothesis.target_id,
                                                    hypothesis.surface_key[3:])
            artifact = self.messages.current_asset(hypothesis.target_id,
                                                   hypothesis.surface_key[3:])
            if (candidate is not None and artifact is not None
                    and candidate.status not in {MessageCandidateStatus.STALE,
                                                 MessageCandidateStatus.REJECTED}):
                flags.update({"current_js", "message_listener"})
                message_protocol = {
                    "candidate_id": candidate.candidate_id,
                    "asset_sha256": artifact.artifact_sha256,
                    "receiver": _safe(candidate.receiver, 80),
                    "handler_location": {"line": candidate.receiver_location.line,
                                         "column": candidate.receiver_location.column},
                    "sender_slice": _protocol_labels(candidate.sender_contexts, 4),
                    "handler_slice": {
                        "receives": _protocol_labels(candidate.message_types, 4),
                        "replies": _protocol_labels(candidate.reply_types, 4),
                        "origin_checks": [check.kind for check in candidate.origin_checks[:4]],
                        "source_checks": [check.kind for check in candidate.source_checks[:4]],
                    },
                    "protocol_sequence": _protocol_labels(candidate.protocol_sequence, 8),
                    "accepts_port": candidate.port_accepted,
                    "binds_port": candidate.port_bound,
                    "rpc_methods": _protocol_labels(candidate.rpc_methods, 4),
                }
        if "FEATURE_DOWNLOAD" in signals or "FEATURE_PII_OBJECT" in signals:
            flags.add("sensitive_artifact")  # Candidate only, never secret bytes.
        if self.exposure is not None and hypothesis.surface_key.startswith("exposure:"):
            candidate = self.exposure.get(hypothesis.target_id, hypothesis.surface_key[9:])
            if candidate is not None and candidate.status not in {
                    ExposureStatus.STALE, ExposureStatus.REJECTED_PUBLIC,
                    ExposureStatus.REJECTED_PLACEHOLDER}:
                flags.add("sensitive_artifact")
                signals = tuple(dict.fromkeys((*signals, candidate.category.value)))[:8]
                if candidate.source.value == "TRAFFIC":
                    for link in self.exposure.source_links(hypothesis.target_id,
                                                          candidate.candidate_id)[:8]:
                        exchange = self.traffic.get_exchange(str(link["source_ref"]))
                        if (exchange is not None and exchange.target_id == hypothesis.target_id
                                and exchange.response is not None
                                and exchange.response.record.status_code == 200
                                and exchange.attribution.auth_state.value == "VERIFIED"):
                            flags.update({"baseline_traffic", "authenticated_endpoint"})
                            break
        if any(f["predicate"] == "data_classification" and f["status"] == "ACTIVE"
               for f in facts):
            flags.add("sensitive_artifact")
        if "SURFACE_INTERNAL" in signals and "multiple_roles" in flags:
            flags.add("role_hidden_operation")
        recon_refs = []
        if (skill is not None and self.recon is not None and profile is not None
                and profile.recon_domain_id is not None and skill.category == "api"
                and "GRAPHQL_AUTHORIZATION" in skill.triggers):
            for surface in self.recon.list_api_surfaces(profile.recon_domain_id, "GRAPHQL", limit=2).items:
                recon_refs.append({"source": "recon_api_surface", "id": surface.surface_id,
                                   "surface_type": surface.surface_type,
                                   "status_code": surface.status_code})
        return SkillContext(hypothesis.target_id, hypothesis.id, hypothesis.category, hypothesis.boundary,
                            _safe(hypothesis.surface_key, 250),
                            tuple(_safe(x) for x in (profile.technologies if profile else ())[:8]),
                            tuple(_safe(x) for x in (profile.features if profile else ())[:8]),
                            signals, tuple(evidence), tuple(facts), tuple(traffic), tuple(identities),
                            frozenset(flags), tuple(_safe(x) for x in hypothesis.missing[:8]),
                            tuple(recon_refs), message_protocol)


class PrerequisiteChecker:
    def check(self, skill: SkillMetadata, context: SkillContext) -> PrerequisiteResult:
        return self.check_requirements(skill.prerequisites, skill.category, context)

    def check_requirements(self, required: tuple[str, ...], category: str,
                           context: SkillContext) -> PrerequisiteResult:
        flags = set(context.flags)
        if (category in {"authorization", "api"}
                and sum(bool(identity["verified_session_id"]) for identity in context.identities) < 2):
            flags.discard("verified_sessions")
        missing = tuple(item for item in required if item not in flags)
        satisfied = tuple(item for item in required if item in flags)
        if not missing:
            state = PrerequisiteState.READY
        elif "in_scope_target" in missing:
            state = PrerequisiteState.UNSUPPORTED
        elif set(missing) & {"multiple_tenants", "multiple_roles", "multiple_principals", "verified_sessions"}:
            state = PrerequisiteState.MISSING_IDENTITY
        elif set(missing) & {"known_object_identifier", "known_ownership", "sensitive_artifact"}:
            state = PrerequisiteState.MISSING_OBJECT
        elif set(missing) & {"authenticated_endpoint", "baseline_traffic", "anonymous_access"}:
            state = PrerequisiteState.MISSING_TRAFFIC
        elif set(missing) & {"current_js", "message_listener", "dangerous_dom_sink",
                               "attacker_controlled_source", "transformation_trace", "graphql_operation",
                               "graphql_mutation", "role_hidden_operation"}:
            state = PrerequisiteState.MISSING_RESEARCH
        else:
            state = PrerequisiteState.MISSING_CONTEXT
        return PrerequisiteResult(state, missing, satisfied)


class SkillRouter:
    def __init__(self, registry: SkillRegistry, checker: PrerequisiteChecker | None = None,
                 outcome_provider: Callable[[str], dict[str, int]] | None = None) -> None:
        self.registry = registry
        self.checker = checker or PrerequisiteChecker()
        self.outcome_provider = outcome_provider

    def route(self, hypothesis: Hypothesis, context: SkillContext, *, limit: int = 3) -> tuple[dict[str, object], ...]:
        if type(limit) is not int or not 1 <= limit <= 5:
            raise ValueError("invalid skill candidate limit")
        ranked = []
        for meta in self.registry.discover():
            exact = hypothesis.category in meta.triggers
            tag = meta.name in hypothesis.skill_tags
            contextual = bool(set(meta.triggers) & set(context.signals))
            if not (exact or tag or contextual):
                continue
            prereq = self.checker.check(meta, context)
            score = (50 if exact else 0) + (25 if tag else 0) + (15 if contextual else 0)
            score += 2 * len(prereq.satisfied) - 3 * len(prereq.missing)
            score += 4 * len(set(x.lower() for x in context.technologies) & set(x.lower() for x in meta.technologies))
            score += 3 * len(set(x.lower() for x in context.features) & set(x.lower() for x in meta.features))
            score += 5 if hypothesis.boundary in meta.boundaries else 0
            score -= {"LOW": 0, "MEDIUM": 2, "HIGH": 5}[meta.risk]
            score -= meta.request_budget // 4 + meta.token_budget // 2048
            if "graphql_mutation" in meta.prerequisites and "graphql_mutation" not in context.flags:
                score -= 20
            outcomes = self.outcome_provider(meta.name) if self.outcome_provider else None
            ranked.append({"skill": meta.to_dict(), "score": score, "prerequisites": prereq.to_dict(),
                           "usage_count": 0, "metrics_available": outcomes is not None,
                           "validation_outcomes": outcomes})
        ranked.sort(key=lambda item: (-item["score"], item["skill"]["name"]))
        return tuple(ranked[:limit])


@dataclass(frozen=True, slots=True)
class InvestigationPlan:
    id: str
    hypothesis_id: str
    skill_id: str
    skill_version: str
    skill_hash: str
    skill_category: str
    vulnerability_classes: tuple[str, ...]
    required_prerequisites: tuple[str, ...]
    required_validators: tuple[str, ...]
    target_id: str
    manual_selection: bool
    prerequisites: PrerequisiteResult
    controls: tuple[str, ...]
    steps: tuple[tuple[StepType, str], ...]
    proposed_actions: tuple[dict[str, object], ...]
    request_templates: tuple[dict[str, str], ...]
    positive_signals: tuple[str, ...]
    negative_signals: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    confirmation_requirements: tuple[str, ...]
    rejection_conditions: tuple[str, ...]
    risk: str
    request_budget: int
    token_budget: int
    status: str
    created_at: str
    comparison_pairs: tuple[dict[str, int], ...] = ()
    dom_binding: dict[str, str] | None = None
    message_binding: dict[str, str] | None = None
    exposure_binding: dict[str, str] | None = None
    api_binding: dict[str, str] | None = None

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "hypothesis_id": self.hypothesis_id, "skill_id": self.skill_id,
                "skill_version": self.skill_version, "skill_hash": self.skill_hash,
                "skill_category": self.skill_category,
                "vulnerability_classes": list(self.vulnerability_classes),
                "required_prerequisites": list(self.required_prerequisites),
                "required_validators": list(self.required_validators),
                "target_id": self.target_id, "manual_selection": self.manual_selection,
                "prerequisites": self.prerequisites.to_dict(), "controls": list(self.controls),
                "steps": [{"type": kind.value, "description": description} for kind, description in self.steps],
                "proposed_actions": list(self.proposed_actions), "request_templates": list(self.request_templates),
                "positive_signals": list(self.positive_signals), "negative_signals": list(self.negative_signals),
                "evidence_requirements": list(self.evidence_requirements),
                "confirmation_requirements": list(self.confirmation_requirements),
                "rejection_conditions": list(self.rejection_conditions), "risk": self.risk,
                "request_budget": self.request_budget, "token_budget": self.token_budget,
                "expected_request_count": len(self.proposed_actions), "status": self.status,
                "created_at": self.created_at, "comparison_pairs": list(self.comparison_pairs),
                "dom_binding": self.dom_binding,
                "message_binding": self.message_binding,
                "exposure_binding": self.exposure_binding,
                "api_binding": self.api_binding,
                "execution_started": False, "finding_status": "UNVALIDATED"}


@dataclass(frozen=True, slots=True)
class AuthorizationPlanBinding:
    source_exchange_id: str
    test_object_id: str
    object_type: str
    object_ref_hash: str
    method: str
    identity_id: str | None
    session_id: str | None
    role: str
    variant: str
    operation: str | None = None
    binding: str = "AUTHORIZATION_OBJECT_PATH_V1"
    variable_name: str | None = None
    parent_object_id: str | None = None
    foreign_parent_object_id: str | None = None
    owner_peer_object_id: str | None = None
    actor_object_id: str | None = None


@dataclass(frozen=True, slots=True)
class APIReadPlanBinding:
    operation_id: str
    version_hash: str
    source_exchange_id: str
    test_object_id: str
    object_type: str
    object_ref_hash: str
    method: str
    identity_id: str
    session_id: str
    role: str
    variant: str
    variable_name: str = ""
    field_path: str = ""
    source_companion_id: str = ""
    companion_object_id: str = ""


@dataclass(frozen=True, slots=True)
class TypedMutationPlanBinding:
    test_object_id: str
    object_type: str
    object_ref_hash: str
    recipe_id: str
    recipe_hash: str
    mutation_type: str
    write_method: str
    read_operation: str
    write_operation: str
    owner_identity_id: str
    owner_session_id: str
    boundary_identity_id: str
    boundary_session_id: str
    boundary: str
    parent_object_id: str | None = None
    foreign_parent_object_id: str | None = None
    delete_control_object_id: str | None = None
    delete_control_ref_hash: str | None = None


@dataclass(frozen=True, slots=True)
class DOMPlanBinding:
    candidate_id: str
    route_url: str
    asset_url: str
    browser_session_id: str
    identity_id: str | None
    input_kind: str
    input_name: str | None = None


@dataclass(frozen=True, slots=True)
class MessagePlanBinding:
    candidate_id: str
    route_url: str
    asset_url: str
    browser_session_id: str
    identity_id: str | None
    activation_type: str
    port_type: str | None
    allowed_method: str | None
    window_mode: str = "IFRAME"
    dom_field: str | None = None
    owned_object_id: str | None = None


class SkillPlanStore:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    def get(self, plan_id: str, target_id: str) -> dict[str, object] | None:
        if not re.fullmatch(r"PLAN-[0-9a-f]{32}", plan_id):
            raise ValueError("invalid plan ID")
        with self.store._connection() as db:
            row = db.execute("SELECT plan_json FROM skill_plans WHERE plan_id=? AND target_id=?",
                             (plan_id, target_id)).fetchone()
            return self._with_selections(db, json.loads(row[0])) if row else None

    @staticmethod
    def _with_selections(db: Any, payload: dict[str, object]) -> dict[str, object]:
        rows = db.execute("SELECT manual_selection,selected_at FROM skill_plan_selections "
                          "WHERE plan_id=? ORDER BY selected_at", (payload["id"],)).fetchall()
        return {**payload, "selection_history": [{"manual": bool(row[0]), "at": row[1]}
                                                  for row in rows]}

    def usage_counts(self) -> dict[str, int]:
        with self.store._connection() as db:
            rows = db.execute("SELECT skill_id,count(*) FROM skill_plans GROUP BY skill_id").fetchall()
        return {row[0]: row[1] for row in rows}

    def outcome_counts(self, skill_id: str) -> dict[str, int]:
        if not isinstance(skill_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", skill_id):
            raise ValueError("Invalid skill ID")
        with self.store._connection() as db:
            rows = db.execute("""SELECT status,count(*) FROM validations
                WHERE skill_id=? GROUP BY status""", (skill_id,)).fetchall()
        return {row[0]: row[1] for row in rows}

    def save(self, plan: InvestigationPlan, *, regenerate: bool = False) -> dict[str, object]:
        payload = plan.to_dict()
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len(serialized) > 32_768 or not _safe_plan_values(payload):
            raise ValueError("unsafe or oversized plan")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT generation,plan_json FROM skill_plans WHERE hypothesis_id=? AND skill_id=? "
                              "AND skill_version=? AND skill_hash=? ORDER BY generation DESC LIMIT 1",
                              (plan.hypothesis_id, plan.skill_id, plan.skill_version, plan.skill_hash)).fetchall()
            if rows and not regenerate:
                existing = json.loads(rows[0]["plan_json"])
                db.execute("INSERT OR IGNORE INTO skill_plan_selections VALUES (?,?,?)",
                           (existing["id"], int(plan.manual_selection), plan.created_at))
                return self._with_selections(db, existing)
            generation = rows[0]["generation"] + 1 if rows else 0
            db.execute("INSERT INTO skill_plans VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (plan.id, plan.target_id, plan.hypothesis_id, plan.skill_id, plan.skill_version,
                        plan.skill_hash, generation, int(plan.manual_selection), plan.status,
                        plan.created_at, serialized))
            db.execute("INSERT INTO skill_plan_selections VALUES (?,?,?)",
                       (plan.id, int(plan.manual_selection), plan.created_at))
            return self._with_selections(db, payload)


def _safe_plan_values(value: object) -> bool:
    redactor = SecretRedactor.from_environment()
    if isinstance(value, dict):
        return all(_safe_plan_values(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return all(_safe_plan_values(item) for item in value)
    return not isinstance(value, str) or redactor.text(value) == value


class SkillPlanner:
    def __init__(self, registry: SkillRegistry, checker: PrerequisiteChecker,
                 policy: PolicyEngine, store: SkillPlanStore,
                 dom: DOMXSSStore | None = None,
                 messages: PostMessageStore | None = None,
                 objects: ObjectRegistry | None = None,
                 exposure: ExposureStore | None = None) -> None:
        self.registry, self.checker, self.policy, self.store = registry, checker, policy, store
        self.dom = dom
        self.messages = messages
        self.objects = objects
        self.exposure = exposure

    def bind_protected_response(self, package: TargetPackage, hypothesis: Hypothesis,
                                context: SkillContext, candidate_id: str) -> dict[str, object]:
        if (self.exposure is None or hypothesis.target_id != package.target.id or
                hypothesis.surface_key != "exposure:" + candidate_id or
                context.target_id != package.target.id):
            raise ValueError("Protected response binding target mismatch")
        candidate = self.exposure.get(package.target.id, candidate_id)
        link = next((item for item in self.exposure.source_links(package.target.id, candidate_id)
                     if item["current"] and candidate is not None and
                     item["source_ref"] == candidate.endpoint_or_asset and
                     item["artifact_sha256"] == candidate.artifact_sha256), None)
        if (candidate is None or candidate.source.value != "TRAFFIC" or
                candidate.credential is None or candidate.artifact_sha256 is None or
                candidate.status in {ExposureStatus.STALE, ExposureStatus.REJECTED_PUBLIC,
                                     ExposureStatus.REJECTED_PLACEHOLDER} or link is None):
            raise ValueError("Controlled protected response required")
        skill = self.registry.select("protected-response-exposure")
        prerequisite = self.checker.check(skill.metadata, context)
        if prerequisite.state is not PrerequisiteState.READY:
            raise ValueError("Protected response prerequisites unavailable")
        frozen = {"candidate_id": candidate_id, "source_ref": candidate.endpoint_or_asset,
                  "evidence_id": str(link["evidence_id"]),
                  "artifact_sha256": candidate.artifact_sha256}
        shape = {**frozen, "binding": "EXPOSURE_HTTP_V1", "method": "GET",
                 "authentication": "EXECUTOR_SUPPLIED"}
        shape["fingerprint"] = hashlib.sha256(json.dumps(
            shape, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        actions = ({"category": "SAFE_READ", "actor": "ANONYMOUS", "identity_id": None,
                    "session_id": None, "method": "GET", "role": "BOUNDARY",
                    "vulnerability_class": "exposure",
                    "request_template_fingerprint": shape["fingerprint"],
                    "policy": {"result": "RECHECK_AT_DISPATCH"}, "simulation_only": True},)
        plan = InvestigationPlan(
            "PLAN-" + uuid.uuid4().hex, hypothesis.id, skill.metadata.name,
            skill.metadata.version, skill.content_hash, skill.metadata.category,
            skill.metadata.vulnerability_classes, skill.metadata.prerequisites,
            skill.metadata.required_validators, package.target.id, True, prerequisite,
            skill.controls, tuple((StepType(kind), description)
                                  for kind, description in skill.workflow), actions,
            (shape,), skill.positive_signals, skill.negative_signals,
            skill.evidence_requirements, skill.confirmation_requirements,
            skill.rejection_conditions, skill.metadata.risk, 1, skill.metadata.token_budget,
            "READY_FOR_MANUAL_REVIEW", datetime.now(timezone.utc).isoformat(),
            exposure_binding=frozen)
        result = self.store.save(plan, regenerate=True)
        self.exposure.bind_plan(package.target.id, candidate_id, hypothesis.id, result["id"])
        return result

    def bind_vhost(self, package: TargetPackage, hypothesis: Hypothesis,
                   context: SkillContext, candidate_id: str, *,
                   source_ref: str, host_sha256: str) -> dict[str, object]:
        """Freeze three same-destination controls without persisting the internal hostname."""
        if (self.exposure is None or package.rules.internal_vhost_testing_allowed is not True
                or hypothesis.target_id != package.target.id
                or hypothesis.surface_key != "exposure:" + candidate_id
                or context.target_id != package.target.id
                or not re.fullmatch(r"[0-9a-f]{64}", host_sha256)):
            raise ValueError("Virtual-host testing is not explicitly authorized")
        candidate = self.exposure.get(package.target.id, candidate_id)
        source = next((item for item in self.exposure.source_links(package.target.id, candidate_id)
                       if item["current"] and item["source_ref"] == source_ref and
                       candidate is not None and item["artifact_sha256"] == candidate.artifact_sha256), None)
        if (candidate is None or candidate.category is not ExposureCategory.INTERNAL_VHOST_CANDIDATE
                or candidate.artifact_sha256 is None or source is None
                or "_redacted_" in candidate.location or
                package.scope.evaluate_url(candidate.location).result is not ScopeResult.IN_SCOPE):
            raise ValueError("Current exact in-scope VHOST source is required")
        skill = self.registry.select("internal-vhost-access")
        prerequisite = self.checker.check(skill.metadata, context)
        if prerequisite.state is not PrerequisiteState.READY:
            raise ValueError("Virtual-host prerequisites are unavailable")
        frozen = {"candidate_id": candidate_id, "source_ref": source_ref,
                  "evidence_id": str(source["evidence_id"]),
                  "artifact_sha256": candidate.artifact_sha256,
                  "host_sha256": host_sha256, "url": candidate.location}
        actions: list[dict[str, object]] = []
        templates: list[dict[str, str]] = []
        for role, variant in (("CONTROL", "NORMAL"), ("OTHER", "INVALID"),
                              ("BOUNDARY", "CANDIDATE")):
            shape = {**frozen, "binding": "EXPOSURE_VHOST_V1", "variant": variant,
                     "method": "GET", "authentication": "EXECUTOR_SUPPLIED"}
            shape["fingerprint"] = hashlib.sha256(json.dumps(
                shape, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            templates.append(shape)
            actions.append({"category": "SAFE_READ", "actor": "ANONYMOUS",
                            "identity_id": None, "session_id": None, "method": "GET",
                            "role": role, "control_kind": "INVALID_HOST" if variant == "INVALID" else None,
                            "vulnerability_class": "internal_surface",
                            "request_template_fingerprint": shape["fingerprint"],
                            "policy": {"result": "RECHECK_AT_DISPATCH"}, "simulation_only": True})
        steps = [(StepType.OBSERVE, "Check current source and exact destination.")]
        steps.extend((StepType.EXECUTE_REQUEST, "Execute one policy-gated Host control.")
                     for _ in templates)
        steps.append((StepType.COMPARE_RESPONSE, "Compare protected candidate-only effect."))
        plan = InvestigationPlan(
            "PLAN-" + uuid.uuid4().hex, hypothesis.id, skill.metadata.name,
            skill.metadata.version, skill.content_hash, skill.metadata.category,
            skill.metadata.vulnerability_classes, skill.metadata.prerequisites,
            skill.metadata.required_validators, package.target.id, True, prerequisite,
            skill.controls, tuple(steps), tuple(actions), tuple(templates),
            skill.positive_signals, skill.negative_signals,
            skill.evidence_requirements, skill.confirmation_requirements,
            skill.rejection_conditions, skill.metadata.risk, 3, skill.metadata.token_budget,
            "READY_FOR_MANUAL_REVIEW", datetime.now(timezone.utc).isoformat(),
            ({"control_slot": 0, "boundary_slot": 2},), exposure_binding=frozen)
        result = self.store.save(plan, regenerate=True)
        self.exposure.bind_plan(package.target.id, candidate_id, hypothesis.id, result["id"])
        return result

    def bind_exposure_artifact(self, package: TargetPackage, hypothesis: Hypothesis,
                               context: SkillContext, candidate_id: str) -> dict[str, object]:
        """Freeze an existing protected artifact; this plan cannot issue HTTP traffic."""
        if (self.exposure is None or hypothesis.target_id != package.target.id or
                context.target_id != package.target.id or
                hypothesis.surface_key != "exposure:" + candidate_id):
            raise ValueError("Exposure artifact binding is invalid")
        candidate = self.exposure.get(package.target.id, candidate_id)
        links = self.exposure.source_links(package.target.id, candidate_id)
        source_link = next((link for link in links if link["current"] and
                            candidate is not None and link["source"] == candidate.source.value and
                            link["artifact_sha256"] == candidate.artifact_sha256), None)
        if (candidate is None or candidate.source.value not in {"JS_ASSET", "SOURCE_MAP"}
                or candidate.credential is None or candidate.artifact_sha256 is None
                or candidate.status in {ExposureStatus.STALE, ExposureStatus.REJECTED_PUBLIC,
                                        ExposureStatus.REJECTED_PLACEHOLDER}
                or source_link is None):
            raise ValueError("Current credential artifact candidate required")
        skill = self.registry.select("credential-disclosure")
        prereq = self.checker.check(skill.metadata, context)
        if prereq.state is not PrerequisiteState.READY:
            raise ValueError("Exposure artifact prerequisites are not current")
        frozen = {"candidate_id": candidate_id, "source": candidate.source.value,
                  "source_ref": str(source_link["source_ref"]),
                  "evidence_id": str(source_link["evidence_id"]),
                  "artifact_sha256": candidate.artifact_sha256,
                  "credential_fingerprint": candidate.credential.fingerprint_sha256}
        plan = InvestigationPlan(
            "PLAN-" + uuid.uuid4().hex, hypothesis.id, skill.metadata.name,
            skill.metadata.version, skill.content_hash, skill.metadata.category,
            skill.metadata.vulnerability_classes, skill.metadata.prerequisites,
            skill.metadata.required_validators, package.target.id, True, prereq,
            skill.controls,
            tuple((StepType(kind), description) for kind, description in skill.workflow),
            (), (), skill.positive_signals, skill.negative_signals,
            skill.evidence_requirements, skill.confirmation_requirements,
            skill.rejection_conditions, skill.metadata.risk, 0,
            skill.metadata.token_budget, "READY_FOR_MANUAL_REVIEW",
            datetime.now(timezone.utc).isoformat(), exposure_binding=frozen,
        )
        result = self.store.save(plan, regenerate=True)
        self.exposure.bind_plan(package.target.id, candidate_id, hypothesis.id, result["id"])
        return result

    def bind_message(self, package: TargetPackage, hypothesis: Hypothesis,
                     context: SkillContext, binding: MessagePlanBinding) -> dict[str, object]:
        if (self.messages is None or hypothesis.target_id != package.target.id
                or context.target_id != package.target.id or hypothesis.category != "POSTMESSAGE"
                or hypothesis.surface_key != "js:" + binding.candidate_id):
            raise ValueError("Messaging plan binding is invalid")
        candidate = self.messages.get_candidate(package.target.id, binding.candidate_id)
        asset = self.messages.current_asset(package.target.id, binding.candidate_id)
        safe_methods = {"ping", "getVersion", "getStatus", "readSynthetic", "readCanary"}
        if (candidate is None or asset is None or candidate.route != binding.route_url
                or candidate.transport_kind != "WINDOW"
                or binding.activation_type not in candidate.message_types
                or binding.port_type not in (None, *candidate.message_types)
                or binding.allowed_method not in (None, *candidate.rpc_methods)
                or binding.allowed_method not in (None, *safe_methods)
                or binding.allowed_method is not None and not any(
                    method.name == binding.allowed_method and method.capability == "READ"
                    for method in candidate.rpc_details)
                or hashlib.sha256(binding.asset_url.encode()).hexdigest() != asset.asset_url_sha256
                or candidate.status not in {MessageCandidateStatus.STATIC_CANDIDATE,
                                             MessageCandidateStatus.RUNTIME_READY}):
            raise ValueError("Messaging candidate is stale or proof method is not allowlisted")
        if binding.dom_field is not None:
            if (binding.dom_field != self.messages.dom_xss_field(package.target.id,
                                                                  binding.candidate_id) or
                    binding.allowed_method is not None or binding.port_type is not None):
                raise ValueError("Messaging DOM field is not backed by a Phase 21 flow")
        owned = None
        if binding.owned_object_id is not None:
            if (self.objects is None or binding.identity_id is None
                    or binding.allowed_method != "readCanary" or binding.dom_field is not None):
                raise ValueError("Owned messaging canary requires a verified read-only RPC")
            owned = self.objects.get(binding.owned_object_id, package.target.id)
            if (owned is None or owned.package_id != package.id
                    or owned.creator_identity_id != binding.identity_id
                    or owned.state is not ObjectState.READY or not owned.disposable
                    or not owned.verified_at or not owned.verification_evidence_ids
                    or not owned.external_id_hash or not owned.external_id_evidence_id):
                raise ValueError("Owned messaging canary is not verified and available")
        if (binding.window_mode not in {"IFRAME", "POPUP"}
                or binding.window_mode == "POPUP" and "OPENER" not in candidate.sender_contexts):
            raise ValueError("Messaging window mode is unsupported by the current protocol")
        skill = self.registry.select("postmessage-trust-analysis")
        prereq = self.checker.check(skill.metadata, context)
        if prereq.state is not PrerequisiteState.READY:
            raise ValueError("Messaging prerequisites are not current")
        route, js_url = urlsplit(binding.route_url), urlsplit(binding.asset_url)
        if (route.scheme not in {"http", "https"} or not route.hostname
                or route.username or route.password or route.query or route.fragment
                or js_url.username or js_url.password or js_url.query or js_url.fragment
                or package.scope.evaluate_url(binding.route_url).result is not ScopeResult.IN_SCOPE
                or package.scope.evaluate_url(binding.asset_url).result is not ScopeResult.IN_SCOPE):
            raise ValueError("Messaging browser route or bundle is out of scope")
        action = ProposedAction(
            target_id=package.target.id, package_id=package.id,
            category=ActionCategory.BROWSER_NAVIGATION,
            actor=ActorMode.AUTHENTICATED if binding.identity_id else ActorMode.ANONYMOUS,
            source="postmessage_plan", purpose="Simulate bounded messaging browser navigation",
            url=binding.route_url, method="GET", identity_id=binding.identity_id,
            session_id=binding.browser_session_id if binding.identity_id else None,
            hypothesis_id=hypothesis.id, vulnerability_class="postmessage",
        )
        if self.policy.evaluate(package, action, record=False).result.value != "ALLOW":
            raise ValueError("Messaging navigation is not policy-allowed")
        frozen = {"candidate_id": binding.candidate_id, "route_url": binding.route_url,
                  "asset_url": binding.asset_url,
                  "browser_session_id": binding.browser_session_id,
                  "identity_id": binding.identity_id or "",
                  "activation_type": binding.activation_type,
                  "port_type": binding.port_type or "",
                  "allowed_method": binding.allowed_method or "",
                  "window_mode": binding.window_mode,
                  "dom_field": binding.dom_field or "",
                  "owned_object_id": owned.id if owned else "",
                  "owned_canary_sha256": hashlib.sha256(owned.test_name.encode()).hexdigest()
                  if owned else "",
                  "owned_verified_at": owned.verified_at if owned else ""}
        plan = InvestigationPlan(
            "PLAN-" + uuid.uuid4().hex, hypothesis.id, skill.metadata.name,
            skill.metadata.version, skill.content_hash, skill.metadata.category,
            skill.metadata.vulnerability_classes, skill.metadata.prerequisites,
            skill.metadata.required_validators, package.target.id, True, prereq,
            skill.controls,
            tuple((StepType(kind), description) for kind, description in skill.workflow),
            (), (), skill.positive_signals, skill.negative_signals,
            skill.evidence_requirements, skill.confirmation_requirements,
            skill.rejection_conditions, skill.metadata.risk, skill.metadata.request_budget,
            skill.metadata.token_budget, "READY_FOR_MANUAL_REVIEW",
            datetime.now(timezone.utc).isoformat(), message_binding=frozen,
        )
        result = self.store.save(plan, regenerate=True)
        if owned is not None:
            assert self.objects is not None
            self.objects.add_requirement(
                plan_id=result["id"], target_id=package.target.id,
                object_type=owned.object_type, recipe_id=owned.recipe_id,
                identity_id=owned.creator_identity_id, tenant_id=owned.tenant_id,
                parent_id=owned.parent_id, test_object_id=owned.id)
        self.messages.bind_plan(package.target.id, binding.candidate_id,
                                hypothesis.id, result["id"])
        return result

    def bind_dom(self, package: TargetPackage, hypothesis: Hypothesis,
                 context: SkillContext, binding: DOMPlanBinding) -> dict[str, object]:
        if (self.dom is None or hypothesis.target_id != package.target.id
                or context.target_id != package.target.id or hypothesis.category != "DOM_XSS"
                or hypothesis.surface_key != "js:" + binding.candidate_id
                or binding.input_kind not in {"QUERY", "FRAGMENT"}
                or (binding.input_kind == "QUERY" and
                    (not binding.input_name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,39}",
                                                             binding.input_name)))
                or (binding.input_kind == "FRAGMENT" and binding.input_name is not None)):
            raise ValueError("DOM plan binding is invalid")
        candidate = self.dom.get_candidate(package.target.id, binding.candidate_id)
        artifact = self.dom.candidate_asset(package.target.id, binding.candidate_id)
        if (candidate is None or artifact is None or artifact.state != "CURRENT"
                or artifact.recon_sha256 != artifact.artifact_sha256
                or candidate.asset_sha256 != artifact.artifact_sha256
                or candidate.route != binding.route_url
                or hashlib.sha256(binding.asset_url.encode()).hexdigest() != artifact.asset_url_sha256
                or (binding.input_kind == "QUERY" and candidate.source != "location.search")
                or (binding.input_kind == "FRAGMENT" and candidate.source != "location.hash")
                or candidate.status not in {DOMCandidateStatus.STATICALLY_SUPPORTED,
                                            DOMCandidateStatus.RUNTIME_READY}):
            raise ValueError("DOM candidate is stale or route is unbound")
        skill = self.registry.select("check-before-transform-dom-xss")
        prereq = self.checker.check(skill.metadata, context)
        if prereq.state is not PrerequisiteState.READY:
            raise ValueError("DOM prerequisites are not current")
        route = urlsplit(binding.route_url)
        asset_url = urlsplit(binding.asset_url)
        if (route.scheme not in {"http", "https"} or not route.hostname
                or route.username or route.password or route.query or route.fragment
                or asset_url.username or asset_url.password or asset_url.query or asset_url.fragment
                or package.scope.evaluate_url(binding.route_url).result is not ScopeResult.IN_SCOPE
                or package.scope.evaluate_url(binding.asset_url).result is not ScopeResult.IN_SCOPE):
            raise ValueError("DOM browser route or bundle is out of scope")
        action = ProposedAction(
            target_id=package.target.id, package_id=package.id,
            category=ActionCategory.BROWSER_NAVIGATION,
            actor=ActorMode.AUTHENTICATED if binding.identity_id else ActorMode.ANONYMOUS,
            source="domxss_plan", purpose="Simulate bounded DOM browser navigation",
            url=binding.route_url, method="GET", identity_id=binding.identity_id,
            session_id=binding.browser_session_id if binding.identity_id else None,
            hypothesis_id=hypothesis.id, vulnerability_class="dom_xss",
        )
        decision = self.policy.evaluate(package, action, record=False)
        if decision.result.value != "ALLOW":
            raise ValueError("DOM browser navigation is not policy-allowed")
        frozen = {"candidate_id": binding.candidate_id, "route_url": binding.route_url,
                  "asset_url": binding.asset_url,
                  "browser_session_id": binding.browser_session_id,
                  "identity_id": binding.identity_id or "",
                  "input_kind": binding.input_kind,
                  "input_name": binding.input_name or ""}
        plan = InvestigationPlan(
            "PLAN-" + uuid.uuid4().hex, hypothesis.id, skill.metadata.name,
            skill.metadata.version, skill.content_hash, skill.metadata.category,
            skill.metadata.vulnerability_classes, skill.metadata.prerequisites,
            skill.metadata.required_validators, package.target.id, True, prereq,
            skill.controls,
            tuple((StepType(kind), description) for kind, description in skill.workflow),
            (), (), skill.positive_signals, skill.negative_signals,
            skill.evidence_requirements, skill.confirmation_requirements,
            skill.rejection_conditions, skill.metadata.risk, skill.metadata.request_budget,
            skill.metadata.token_budget, "READY_FOR_MANUAL_REVIEW",
            datetime.now(timezone.utc).isoformat(), dom_binding=frozen,
        )
        result = self.store.save(plan, regenerate=True)
        self.dom.bind_plan(package.target.id, binding.candidate_id, hypothesis.id, result["id"])
        return result

    @staticmethod
    def _template(context: SkillContext) -> RequestTemplate | None:
        for item in context.traffic:
            path = item["display_path"]
            origin = item["origin"]
            if (item["method"] not in {"GET", "HEAD"} or not path.startswith("/") or
                    any(char in path for char in "?#[") or "[REDACTED]" in path or
                    "[AUTH_CONTEXT]" in path or re.search(r"[A-Za-z0-9_-]{24,}", path) or
                    SecretRedactor.from_environment().text(path) != path):
                continue
            parsed = urlsplit(origin)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
                    or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
                continue
            return RequestTemplate(item["method"], origin.rstrip("/") + path)
        return None

    def generate(self, package: TargetPackage, hypothesis: Hypothesis, context: SkillContext,
                 skill_id: str, *, manual_selection: bool = False,
                 regenerate: bool = False) -> dict[str, object]:
        if hypothesis.target_id != package.target.id or context.target_id != package.target.id:
            raise ValueError("plan target mismatch")
        skill = self.registry.select(skill_id)
        prereq = self.checker.check(skill.metadata, context)
        actions: list[dict[str, object]] = []
        templates: list[dict[str, str]] = []
        # Ownership metadata does not bind a concrete foreign actor to a concrete object.
        # Authorization and GraphQL plans remain planning-only until that binding exists.
        template = (self._template(context) if prereq.state is PrerequisiteState.READY
                    and skill.metadata.category not in {"authorization", "api"} else None)
        if template is not None:
            for intent in skill.action_intents[:skill.metadata.request_budget]:
                authenticated = intent == "AUTHORIZATION_TEST"
                actor = ActorMode.AUTHENTICATED if authenticated else ActorMode.ANONYMOUS
                owned = next((i for i in context.identities if i["verified_session_id"]), None)
                if authenticated and owned is None:
                    break
                action = ProposedAction(
                    target_id=package.target.id, package_id=package.id,
                    category=ActionCategory(intent), actor=actor, source="skill_plan",
                    purpose="Skill investigation plan policy simulation", url=template.url,
                    method=template.method, hypothesis_id=hypothesis.id,
                    identity_id=owned["id"] if authenticated else None,
                    session_id=owned["verified_session_id"] if authenticated else None,
                    vulnerability_class=skill.metadata.vulnerability_classes[0].lower()
                    if skill.metadata.vulnerability_classes else None,
                    cross_identity=authenticated and skill.metadata.category == "authorization")
                decision = self.policy.evaluate(package, action, record=False)
                actions.append({"action_id": action.id, "category": intent, "actor": actor.value,
                                "identity_id": action.identity_id, "session_id": action.session_id,
                                "method": template.method,
                                "vulnerability_class": action.vulnerability_class,
                                "request_template_fingerprint": template.fingerprint(),
                                "policy": decision.to_dict(), "simulation_only": True})
                templates.append({"method": template.method, "url": template.url,
                                  "fingerprint": template.fingerprint(), "authentication": "EXECUTOR_SUPPLIED"})
        if len(actions) > skill.metadata.request_budget:
            raise ValueError("request budget exceeded")
        if prereq.state is not PrerequisiteState.READY:
            status = "BLOCKED_PREREQUISITES"
        elif skill.action_intents and not actions:
            status = ("NEEDS_ACTOR_OBJECT_BINDING" if skill.metadata.category in {"authorization", "api"}
                      else "NEEDS_REQUEST_TEMPLATE")
        elif any(a["policy"]["result"] == "DENY" for a in actions):
            status = "POLICY_DENIED"
        elif any(a["policy"]["result"] == "REQUIRE_APPROVAL" for a in actions):
            status = "REQUIRE_APPROVAL"
        else:
            status = "READY_FOR_MANUAL_REVIEW"
        plan = InvestigationPlan(
            "PLAN-" + uuid.uuid4().hex, hypothesis.id, skill_id, skill.metadata.version,
            skill.content_hash, skill.metadata.category, skill.metadata.vulnerability_classes,
            skill.metadata.prerequisites, skill.metadata.required_validators,
            package.target.id, manual_selection, prereq, skill.controls,
            tuple((StepType(kind), description) for kind, description in skill.workflow),
            tuple(actions), tuple(templates), skill.positive_signals, skill.negative_signals,
            skill.evidence_requirements, skill.confirmation_requirements,
            skill.rejection_conditions, skill.metadata.risk, skill.metadata.request_budget,
            skill.metadata.token_budget, status, datetime.now(timezone.utc).isoformat())
        return self.store.save(plan, regenerate=regenerate)

    def bind_api_read(self, package: TargetPackage, hypothesis: Hypothesis,
                      context: SkillContext, candidate_id: str, category: str,
                      bindings: tuple[APIReadPlanBinding, ...], *,
                      nested_child_id: str | None = None,
                      nested_path: str | None = None,
                      batch_root_key: str | None = None,
                      batch_id_type: str | None = None,
                      batch_envelope: str | None = None) -> dict[str, object]:
        """Freeze a five-request, observed-operation comparison without request bytes."""
        if hypothesis.target_id != package.target.id or context.target_id != package.target.id:
            raise ValueError("API plan target mismatch")
        skill = self.registry.select("api-observed-read")
        prerequisite = self.checker.check(skill.metadata, context)
        if prerequisite.state is not PrerequisiteState.READY:
            raise ValueError("API read prerequisites are not ready")
        if (category not in {"OBJECT_AUTH", "FIELD_AUTH", "NESTED_AUTH", "BATCH_AUTH", "BFLA"}
                or len(bindings) != 5 or skill.metadata.request_budget < 5
                or tuple(item.role for item in bindings) !=
                ("CONTROL", "CONTROL", "OTHER", "BOUNDARY", "BOUNDARY")
                or tuple(item.variant for item in bindings) !=
                ("OWNER", "OWNER", "INVALID_OBJECT", "FOREIGN", "FOREIGN")
                or len({item.operation_id for index, item in enumerate(bindings) if index != 1}) != 1
                or len({item.version_hash for index, item in enumerate(bindings) if index != 1}) != 1
                or len({item.method for item in bindings}) != 1
                or len({item.field_path for index, item in enumerate(bindings) if index != 1}) != 1
                or (bindings[1].operation_id != bindings[0].operation_id and
                    (category != "FIELD_AUTH" or bindings[1].field_path or
                     bindings[1].version_hash == bindings[0].version_hash))
                or (bindings[1].operation_id == bindings[0].operation_id and
                    (bindings[1].version_hash != bindings[0].version_hash or
                     bindings[1].field_path != bindings[0].field_path))
                or bindings[0].test_object_id != bindings[2].test_object_id
                or bindings[0].test_object_id != bindings[3].test_object_id
                or bindings[0].test_object_id != bindings[4].test_object_id
                or bindings[1].test_object_id == bindings[0].test_object_id
                or bindings[0].identity_id != bindings[2].identity_id
                or bindings[1].identity_id != bindings[3].identity_id
                or bindings[1].identity_id != bindings[4].identity_id
                or category == "FIELD_AUTH" and not bindings[0].field_path
                or category != "FIELD_AUTH" and bindings[0].field_path
                or category == "NESTED_AUTH" and (
                    not nested_child_id or not nested_path or
                    not re.fullmatch(r"/[A-Za-z_][A-Za-z0-9_]*/[A-Za-z_][A-Za-z0-9_]*",
                                     nested_path))
                or category != "NESTED_AUTH" and (nested_child_id or nested_path)):
            raise ValueError("API read controls are incomplete")
        if category == "BATCH_AUTH":
            if (not batch_root_key or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", batch_root_key)
                    or not batch_id_type or not re.fullmatch(
                        r"(?:PLAIN|[A-Za-z_][A-Za-z0-9_]{0,63})", batch_id_type)
                    or batch_envelope not in {"NODES_LIST", "OPERATION_ARRAY"}
                    or any(item.method != "POST" or not item.variable_name or
                           not item.source_companion_id or not item.companion_object_id
                           for item in bindings)
                    or bindings[0].source_companion_id != bindings[0].companion_object_id
                    or bindings[1].source_companion_id != bindings[1].companion_object_id
                    or bindings[2].source_companion_id != bindings[0].source_companion_id
                    or bindings[3].source_companion_id != bindings[0].source_companion_id
                    or bindings[4].source_companion_id != bindings[0].source_companion_id
                    or bindings[2].companion_object_id != bindings[0].companion_object_id
                    or bindings[3].companion_object_id != bindings[1].test_object_id
                    or bindings[4].companion_object_id != bindings[1].test_object_id
                    or bindings[0].source_exchange_id != bindings[2].source_exchange_id
                    or bindings[0].source_exchange_id != bindings[3].source_exchange_id
                    or bindings[0].source_exchange_id != bindings[4].source_exchange_id):
                raise ValueError("API batch controls are incomplete")
        elif (batch_root_key or batch_id_type or batch_envelope or
              any(item.source_companion_id or item.companion_object_id for item in bindings)):
            raise ValueError("Unexpected API batch binding")
        frozen = {"candidate_id": candidate_id, "category": category,
                  "operation_id": bindings[0].operation_id,
                  "version_hash": bindings[0].version_hash,
                  "field_path": bindings[0].field_path}
        if bindings[1].operation_id != bindings[0].operation_id:
            frozen["actor_control_operation_id"] = bindings[1].operation_id
            frozen["actor_control_version_hash"] = bindings[1].version_hash
        if category == "NESTED_AUTH":
            frozen["nested_child_id"] = nested_child_id
            frozen["nested_path"] = nested_path
        if category == "BATCH_AUTH":
            frozen.update({"batch_root_key": batch_root_key,
                           "batch_id_type": batch_id_type,
                           "batch_envelope": batch_envelope})
        actions: list[dict[str, object]] = []
        templates: list[dict[str, str]] = []
        for item in bindings:
            if (not item.identity_id or not item.session_id or
                    not re.fullmatch(r"[0-9a-f]{64}", item.object_ref_hash) or
                    not re.fullmatch(r"[0-9a-f]{64}", item.version_hash) or
                    item.method not in {"GET", "HEAD", "POST"} or
                    item.method == "POST" and not item.variable_name.isidentifier() or
                    item.method != "POST" and item.variable_name):
                raise ValueError("API read binding is unsafe")
            shape = {"binding": "API_OBSERVED_READ_V1", "operation_id": item.operation_id,
                     "version_hash": item.version_hash,
                     "source_exchange_id": item.source_exchange_id,
                     "test_object_id": item.test_object_id, "variant": item.variant,
                     "variable_name": item.variable_name, "field_path": item.field_path,
                     "method": item.method, "authentication": "EXECUTOR_SUPPLIED"}
            if category == "BATCH_AUTH":
                shape.update({"binding": "API_OBSERVED_BATCH_V1",
                              "source_companion_id": item.source_companion_id,
                              "companion_object_id": item.companion_object_id,
                              "root_key": batch_root_key, "id_type": batch_id_type,
                              "envelope": batch_envelope})
            shape["fingerprint"] = (api_batch_reference_fingerprint(shape)
                                    if category == "BATCH_AUTH" else
                                    api_reference_fingerprint(shape))
            templates.append(shape)
            actions.append({"category": "AUTHORIZATION_TEST" if item.role == "BOUNDARY" or
                            item.method == "POST" else "SAFE_READ", "actor": "AUTHENTICATED",
                            "identity_id": item.identity_id, "session_id": item.session_id,
                            "method": item.method, "operation": item.operation_id,
                            "object_type": item.object_type,
                            "object_ref_hash": item.object_ref_hash,
                            "disposable_intent": True,
                            "cross_identity": item.variant == "FOREIGN",
                            "role": item.role,
                            "control_kind": "INVALID_OBJECT" if item.variant == "INVALID_OBJECT" else None,
                            "vulnerability_class": skill.metadata.vulnerability_classes[0].lower(),
                            "request_template_fingerprint": shape["fingerprint"],
                            "policy": {"result": "RECHECK_AT_DISPATCH"}, "simulation_only": True})
        steps = ((StepType.OBSERVE, "Review the observed API operation and owned controls."),
                 *((StepType.EXECUTE_REQUEST, "Execute one bound API read.") for _ in bindings),
                 (StepType.COMPARE_RESPONSE, "Compare semantic object and field data."))
        plan = InvestigationPlan(
            "PLAN-" + uuid.uuid4().hex, hypothesis.id, skill.metadata.name,
            skill.metadata.version, skill.content_hash, skill.metadata.category,
            skill.metadata.vulnerability_classes, skill.metadata.prerequisites,
            skill.metadata.required_validators, package.target.id, True, prerequisite,
            skill.controls, steps, tuple(actions), tuple(templates), skill.positive_signals,
            skill.negative_signals, skill.evidence_requirements, skill.confirmation_requirements,
            skill.rejection_conditions, skill.metadata.risk, 5, skill.metadata.token_budget,
            "READY_FOR_MANUAL_REVIEW", datetime.now(timezone.utc).isoformat(),
            ({"control_slot": 0, "boundary_slot": 3},), api_binding=frozen)
        return self.store.save(plan, regenerate=True)

    def bind_authorization(self, package: TargetPackage, hypothesis: Hypothesis,
                           context: SkillContext, skill_id: str,
                           bindings: tuple[AuthorizationPlanBinding, ...],
                           *, request_cap: int) -> dict[str, object]:
        """Freeze exact owner/object references; policy is re-evaluated at dispatch."""
        if hypothesis.target_id != package.target.id or context.target_id != package.target.id:
            raise ValueError("authorization plan target mismatch")
        skill = self.registry.select(skill_id)
        if skill.metadata.category not in {"authorization", "api"} and not (
                skill_id in {"unauthenticated-sensitive-download", "sensitive-data-exposure",
                             "overexposed-api-response"} and
                skill.metadata.category == "exposure"):
            raise ValueError("not an authorization skill")
        prerequisite = self.checker.check(skill.metadata, context)
        if prerequisite.state is not PrerequisiteState.READY:
            raise ValueError("authorization prerequisites are not ready")
        if (type(request_cap) is not int or not 1 <= request_cap <= 20 or
                not 1 <= len(bindings) <= min(request_cap, skill.metadata.request_budget)
                or not any(item.role == "BOUNDARY" for item in bindings)
                or bindings[0].role != "CONTROL"):
            raise ValueError("authorization plan exceeds skill or hunt budget")
        exposure_binding = (skill_id in {"unauthenticated-sensitive-download", "sensitive-data-exposure"}
                            and any(item.binding == "EXPOSURE_OBJECT_PATH_V1" for item in bindings))
        if exposure_binding and (
                len(bindings) != 4 or
                tuple(item.binding for item in bindings) != ("EXPOSURE_OBJECT_PATH_V1",) * 4 or
                tuple(item.variant for item in bindings) !=
                ("OWNER", "ANONYMOUS", "ANONYMOUS", "INVALID_OBJECT") or
                tuple(item.role for item in bindings) !=
                ("CONTROL", "BOUNDARY", "BOUNDARY", "OTHER") or
                len({item.test_object_id for item in bindings}) != 1 or
                len({item.source_exchange_id for item in bindings}) != 1 or
                len({item.object_ref_hash for item in bindings}) != 1):
            raise ValueError("exposure read requires owner, two anonymous, and invalid controls")
        if skill_id == "graphql-mutation-authorization" and (
                len(bindings) != 5 or
                tuple(item.variant for item in bindings) !=
                ("OWNER", "OWNER", "INVALID_OBJECT", "FOREIGN", "POST_READBACK") or
                tuple(item.binding for item in bindings) !=
                ("AUTHORIZATION_OBJECT_PATH_V1", "AUTHORIZATION_OBJECT_PATH_V1",
                 "AUTHORIZATION_GRAPHQL_MUTATION_V1", "AUTHORIZATION_GRAPHQL_MUTATION_V1",
                 "AUTHORIZATION_OBJECT_PATH_V1") or
                bindings[0].test_object_id != bindings[2].test_object_id or
                bindings[0].test_object_id != bindings[3].test_object_id or
                bindings[0].test_object_id != bindings[4].test_object_id or
                bindings[0].identity_id != bindings[4].identity_id):
            raise ValueError("mutation plan requires owned before/after read-back")
        actions: list[dict[str, object]] = []
        templates: list[dict[str, str]] = []
        for item in bindings:
            graphql_query = item.binding == "AUTHORIZATION_GRAPHQL_QUERY_V1"
            graphql_mutation = item.binding == "AUTHORIZATION_GRAPHQL_MUTATION_V1"
            nested = item.binding == "AUTHORIZATION_NESTED_PARENT_V1"
            batch = item.binding == "AUTHORIZATION_BATCH_PATH_V1"
            graphql = graphql_query or graphql_mutation
            if (item.binding not in {"AUTHORIZATION_OBJECT_PATH_V1", "EXPOSURE_OBJECT_PATH_V1",
                                     "AUTHORIZATION_GRAPHQL_QUERY_V1",
                                     "AUTHORIZATION_GRAPHQL_MUTATION_V1",
                                     "AUTHORIZATION_NESTED_PARENT_V1",
                                     "AUTHORIZATION_BATCH_PATH_V1"}
                    or (nested and (skill_id != "nested-resource-authorization" or
                                    item.method != "GET" or item.variant != "FOREIGN" or
                                    not item.parent_object_id or not item.foreign_parent_object_id))
                    or (not nested and (item.parent_object_id or item.foreign_parent_object_id))
                    or (batch and (skill_id != "batch-object-authorization" or
                                   item.method != "GET" or item.variant not in {"OWNER", "FOREIGN"} or
                                   not item.owner_peer_object_id or not item.actor_object_id))
                    or (not batch and (item.owner_peer_object_id or item.actor_object_id))
                    or (graphql and (item.method != "POST" or
                                      skill_id != ("graphql-mutation-authorization" if graphql_mutation
                                                   else "graphql-object-authorization")
                                            or not item.variable_name or not item.variable_name.isidentifier()))
                    or (not graphql and (item.method not in {"GET", "HEAD"} or item.variable_name))
                    or (item.binding == "EXPOSURE_OBJECT_PATH_V1" and
                        (not exposure_binding or item.method != "GET" or item.variant not in {
                            "OWNER", "ANONYMOUS", "INVALID_OBJECT"}))
                    or (exposure_binding and item.binding != "EXPOSURE_OBJECT_PATH_V1")
                    or item.role not in {"CONTROL", "BOUNDARY", "OTHER"}
                    or item.variant not in {"OWNER", "FOREIGN", "INVALID_OBJECT", "ANONYMOUS",
                                            "POST_READBACK"}
                    or (item.variant == "OWNER") != (item.role == "CONTROL")
                    or (item.variant in {"FOREIGN", "ANONYMOUS"}) != (item.role == "BOUNDARY")
                    or (item.variant in {"INVALID_OBJECT", "POST_READBACK"}) != (item.role == "OTHER")
                    or (item.variant == "POST_READBACK" and item.binding != "AUTHORIZATION_OBJECT_PATH_V1")
                    or (graphql_mutation and item.variant not in {"FOREIGN", "INVALID_OBJECT"})
                    or (item.variant == "ANONYMOUS" and (item.identity_id or item.session_id))
                    or (item.variant != "ANONYMOUS" and
                        (not item.identity_id or not item.session_id))
                    or not re.fullmatch(r"[0-9a-f]{64}", item.object_ref_hash)):
                raise ValueError("invalid authorization plan binding")
            shape = {"binding": item.binding, "method": item.method,
                     "source_exchange_id": item.source_exchange_id,
                     "test_object_id": item.test_object_id, "variant": item.variant,
                     "authentication": "EXECUTOR_SUPPLIED"}
            if graphql:
                shape["variable_name"] = item.variable_name
            if nested:
                shape["parent_object_id"] = item.parent_object_id
                shape["foreign_parent_object_id"] = item.foreign_parent_object_id
            if batch:
                shape["owner_peer_object_id"] = item.owner_peer_object_id
                shape["actor_object_id"] = item.actor_object_id
            shape["fingerprint"] = reference_fingerprint(shape)
            templates.append(shape)
            actions.append({"category": ("AUTHORIZATION_TEST" if item.role == "BOUNDARY" or
                                         graphql else "SAFE_READ"),
                            "actor": "ANONYMOUS" if item.variant == "ANONYMOUS" else "AUTHENTICATED",
                            "identity_id": item.identity_id,
                            "session_id": item.session_id, "method": item.method,
                            "operation": item.operation, "object_type": item.object_type,
                            "object_ref_hash": item.object_ref_hash,
                            "disposable_intent": True,
                            "cross_identity": item.variant == "FOREIGN",
                            "role": item.role,
                            "control_kind": ("INVALID_OBJECT" if item.variant == "INVALID_OBJECT" else
                                             "POST_READBACK" if item.variant == "POST_READBACK" else None),
                            "vulnerability_class": skill.metadata.vulnerability_classes[0].lower(),
                            "request_template_fingerprint": shape["fingerprint"],
                            "policy": {"result": "RECHECK_AT_DISPATCH"}, "simulation_only": True})
        steps = [(StepType.OBSERVE, "Review observed operation and ownership evidence.")]
        steps.extend((StepType.EXECUTE_REQUEST, "Execute one bound authorization comparison.")
                     for _ in bindings)
        steps.append((StepType.COMPARE_RESPONSE, "Compare owner and boundary metadata."))
        boundary_slot = next(index for index, item in enumerate(bindings) if item.role == "BOUNDARY")
        plan = InvestigationPlan(
            "PLAN-" + uuid.uuid4().hex, hypothesis.id, skill_id, skill.metadata.version,
            skill.content_hash, skill.metadata.category, skill.metadata.vulnerability_classes,
            skill.metadata.prerequisites, skill.metadata.required_validators,
            package.target.id, True, prerequisite, skill.controls, tuple(steps),
            tuple(actions), tuple(templates), skill.positive_signals, skill.negative_signals,
            skill.evidence_requirements, skill.confirmation_requirements,
            skill.rejection_conditions, skill.metadata.risk, len(bindings),
            skill.metadata.token_budget, "READY_FOR_MANUAL_REVIEW",
            datetime.now(timezone.utc).isoformat(),
            ({"control_slot": 0, "boundary_slot": boundary_slot},))
        return self.store.save(plan, regenerate=True)

    def bind_typed_mutation(self, package: TargetPackage, hypothesis: Hypothesis,
                            context: SkillContext,
                            binding: TypedMutationPlanBinding) -> dict[str, object]:
        """Freeze only opaque references; current recipe and ownership are rechecked per step."""
        if hypothesis.target_id != package.target.id or context.target_id != package.target.id:
            raise ValueError("typed mutation plan target mismatch")
        skill = self.registry.select("typed-authorization-mutation")
        prerequisite = self.checker.check(skill.metadata, context)
        if prerequisite.state is not PrerequisiteState.READY:
            raise ValueError("typed mutation prerequisites are not ready")
        deleting = binding.mutation_type == "DELETE_DISPOSABLE"
        stages = DELETE_STAGES if deleting else STAGES
        if (binding.mutation_type not in {"RENAME", "DELETE_DISPOSABLE"} or
                binding.write_method not in ({"DELETE"} if deleting else {"PATCH", "PUT", "POST"})
                or binding.boundary not in {"CROSS_TENANT", "HORIZONTAL", "VERTICAL",
                                             "HIDDEN_FUNCTION", "GRAPHQL_MUTATION"}
                or binding.owner_identity_id == binding.boundary_identity_id
                or not re.fullmatch(r"[0-9a-f]{64}", binding.object_ref_hash)
                or not re.fullmatch(r"[0-9a-f]{64}", binding.recipe_hash)
                or len(stages) > skill.metadata.request_budget):
            raise ValueError("typed mutation plan binding is unsafe")
        nested = bool(binding.parent_object_id or binding.foreign_parent_object_id)
        if (deleting and (nested or not binding.delete_control_object_id or
                          binding.delete_control_object_id == binding.test_object_id or
                          not isinstance(binding.delete_control_ref_hash, str) or
                          not re.fullmatch(r"[0-9a-f]{64}", binding.delete_control_ref_hash)) or
                not deleting and (binding.delete_control_object_id or
                                  binding.delete_control_ref_hash)):
            raise ValueError("delete mutation needs a distinct verified control object")
        if (nested and (binding.write_method != "POST" or
                        not binding.parent_object_id or not binding.foreign_parent_object_id or
                        len({binding.test_object_id, binding.parent_object_id,
                             binding.foreign_parent_object_id}) != 3)):
            raise ValueError("nested mutation needs two distinct verified parents")
        actions: list[dict[str, object]] = []
        templates: list[dict[str, str]] = []
        for stage in stages:
            boundary = stage is MutationStage.BOUNDARY_MUTATE
            mutating = stage in {MutationStage.OWNER_MUTATE,
                                 MutationStage.BOUNDARY_MUTATE, MutationStage.RESTORE}
            shape = {"binding": "AUTHORIZATION_RECIPE_MUTATION_V1",
                     "recipe_id": binding.recipe_id, "recipe_hash": binding.recipe_hash,
                     "test_object_id": binding.test_object_id,
                     "mutation_type": binding.mutation_type, "stage": stage.value,
                     "method": binding.write_method if mutating else "GET",
                     "authentication": "EXECUTOR_SUPPLIED"}
            if nested:
                shape["parent_object_id"] = binding.parent_object_id
                shape["foreign_parent_object_id"] = binding.foreign_parent_object_id
            if deleting:
                shape["delete_control_object_id"] = binding.delete_control_object_id
            shape["fingerprint"] = mutation_fingerprint(shape)
            templates.append(shape)
            control_object = deleting and stage in {
                MutationStage.BEFORE_READ, MutationStage.OWNER_MUTATE,
                MutationStage.OWNER_READBACK}
            actions.append({"category": ("OBJECT_DELETE" if deleting else "OBJECT_UPDATE")
                            if mutating else "SAFE_READ",
                            "actor": "AUTHENTICATED",
                            "identity_id": (binding.boundary_identity_id if boundary else
                                            binding.owner_identity_id),
                            "session_id": (binding.boundary_session_id if boundary else
                                           binding.owner_session_id),
                            "method": shape["method"],
                            "operation": binding.write_operation if mutating else binding.read_operation,
                            "object_type": binding.object_type,
                            "object_ref_hash": (binding.delete_control_ref_hash if control_object
                                                else binding.object_ref_hash),
                            "disposable_intent": True, "cross_identity": boundary,
                            "role": ("BOUNDARY" if boundary else "CONTROL" if stage in {
                                MutationStage.BEFORE_READ, MutationStage.OWNER_MUTATE,
                                MutationStage.OWNER_READBACK,
                                MutationStage.TARGET_BEFORE_READ} else "OTHER"),
                            "control_kind": stage.value, "vulnerability_class": "bola",
                            "request_template_fingerprint": shape["fingerprint"],
                            "policy": {"result": "RECHECK_AT_DISPATCH"}, "simulation_only": True})
        steps = [(StepType.OBSERVE, "Verify owned disposable object and permission boundary.")]
        steps.extend((StepType.EXECUTE_REQUEST, "Execute one recipe-bound mutation or read-back.")
                     for _ in stages)
        steps.append((StepType.COMPARE_RESPONSE, "Compare independently verified object state."))
        plan = InvestigationPlan(
            "PLAN-" + uuid.uuid4().hex, hypothesis.id, skill.metadata.name,
            skill.metadata.version, skill.content_hash, skill.metadata.category,
            skill.metadata.vulnerability_classes, skill.metadata.prerequisites,
            skill.metadata.required_validators, package.target.id, True, prerequisite,
            skill.controls, tuple(steps), tuple(actions), tuple(templates),
            skill.positive_signals, skill.negative_signals, skill.evidence_requirements,
            skill.confirmation_requirements, skill.rejection_conditions,
            skill.metadata.risk, len(stages), skill.metadata.token_budget,
            "READY_FOR_MANUAL_REVIEW", datetime.now(timezone.utc).isoformat(),
            ({"control_slot": 2, "boundary_slot": 4},))
        return self.store.save(plan, regenerate=True)
