"""Bounded skill routing and immutable policy-simulated investigation plans."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from itertools import combinations
import json
import re
from typing import Any
from urllib.parse import urlsplit
import uuid

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
from .traffic import TrafficStore


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

    def to_dict(self) -> dict[str, object]:
        return {"target_id": self.target_id, "hypothesis_id": self.hypothesis_id,
                "category": self.category, "boundary": self.boundary,
                "surface_key": self.surface_key, "technologies": list(self.technologies),
                "features": list(self.features), "signals": list(self.signals),
                "evidence": list(self.evidence), "facts": list(self.facts),
                "traffic": list(self.traffic), "identities": list(self.identities),
                "flags": sorted(self.flags), "missing_hypothesis": list(self.missing_hypothesis),
                "recon_refs": list(self.recon_refs)}


def _safe(value: str, maximum: int = 160) -> str:
    text = SecretRedactor.from_environment().text(str(value))
    return text[:maximum]


class SkillContextBuilder:
    """Metadata only. No Evidence bodies, request bodies, credentials, or recon dumps."""

    def __init__(self, store: EvidenceFactStore, registry: IdentityRegistry,
                 traffic: TrafficStore, browser: Any | None = None,
                 recon: ReconRepository | None = None) -> None:
        self.store = store
        self.registry = registry
        self.traffic = traffic
        self.browser = browser
        self.recon = recon

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
        for ref in hypothesis.fact_ids[:4]:
            item = self.store.get_fact(ref)
            if item and item.target_ref == hypothesis.target_id:
                facts.append({"id": item.fact_id, "predicate": _safe(item.predicate),
                              "status": item.status.value, "sensitivity": item.sensitivity.value})
        traffic = []
        for exchange in self.traffic.find_recent(hypothesis.target_id, limit=12).items:
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
        if any(f["predicate"] in {"owns", "owned_by", "object_owner", "tenant_owner"}
               and f["status"] == "ACTIVE" for f in facts):
            flags.add("known_ownership")
        if "API_GRAPHQL" in signals or any(t["operation_id"] for t in traffic):
            flags.add("graphql_operation")
        if "API_GRAPHQL_MUTATION" in signals or hypothesis.category == "GRAPHQL_MUTATION":
            flags.add("graphql_mutation")
        if any(s.startswith("JS_") for s in signals):
            flags.add("current_js")  # Still requires current-bundle validation later.
        if "JS_POSTMESSAGE" in signals:
            flags.add("message_listener")
        if "JS_DOM_SINK" in signals:
            flags.add("dangerous_dom_sink")
        if "JS_DECODER" in signals:
            flags.add("transformation_trace")
        if "JS_SOURCE" in signals:
            flags.add("attacker_controlled_source")
        if "FEATURE_DOWNLOAD" in signals or "FEATURE_PII_OBJECT" in signals:
            flags.add("sensitive_artifact")  # Candidate only, never secret bytes.
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
                            tuple(recon_refs))


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
    def __init__(self, registry: SkillRegistry, checker: PrerequisiteChecker | None = None) -> None:
        self.registry = registry
        self.checker = checker or PrerequisiteChecker()

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
            ranked.append({"skill": meta.to_dict(), "score": score, "prerequisites": prereq.to_dict(),
                           "usage_count": 0, "metrics_available": False})
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

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "hypothesis_id": self.hypothesis_id, "skill_id": self.skill_id,
                "skill_version": self.skill_version, "skill_hash": self.skill_hash,
                "skill_category": self.skill_category,
                "vulnerability_classes": list(self.vulnerability_classes),
                "required_prerequisites": list(self.required_prerequisites),
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
                "created_at": self.created_at, "execution_started": False, "finding_status": "UNVALIDATED"}


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
                 policy: PolicyEngine, store: SkillPlanStore) -> None:
        self.registry, self.checker, self.policy, self.store = registry, checker, policy, store

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
            skill.metadata.prerequisites,
            package.target.id, manual_selection, prereq, skill.controls,
            tuple((StepType(kind), description) for kind, description in skill.workflow),
            tuple(actions), tuple(templates), skill.positive_signals, skill.negative_signals,
            skill.evidence_requirements, skill.confirmation_requirements,
            skill.rejection_conditions, skill.metadata.risk, skill.metadata.request_budget,
            skill.metadata.token_budget, status, datetime.now(timezone.utc).isoformat())
        return self.store.save(plan, regenerate=regenerate)
