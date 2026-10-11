"""Deterministic, read-only judgment of completed investigation runs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import uuid
from typing import Protocol

from .domain import ObservationState
from .evidence import Fact, FactStatus
from .hypotheses import HypothesisStore
from .identity import MembershipStatus
from .identity_registry import IdentityRegistry
from .plan_runs import PlanRun, PlanRunStore, RunStatus, RuntimeStep, RuntimeStepStatus
from .response_compare import ResponseComparator, ResponseFeatures
from .store import EvidenceFactStore
from .traffic import AuthState, ExchangeState, TrafficExchange, TrafficStore
from .validation_store import (CheckOutcome, FindingSpec, ValidationCheck,
                               ValidationResult, ValidationStatus, ValidationStore)


_AUTH_SKILLS = {
    "cross-tenant-object-authorization": "CROSS_TENANT",
    "horizontal-object-authorization": "HORIZONTAL",
    "vertical-role-authorization": "VERTICAL",
    "hidden-function-authorization": "HIDDEN_FUNCTION",
}
_GRAPHQL_SKILLS = {"graphql-object-authorization", "graphql-mutation-authorization"}
_EXPOSURE_SKILLS = {"unauthenticated-sensitive-download", "sensitive-data-exposure"}
_CLIENT_SKILLS = {"check-before-transform-dom-xss", "postmessage-trust-analysis"}
_KINDS = {**{skill: "AUTHORIZATION" for skill in _AUTH_SKILLS},
          **{skill: "GRAPHQL" for skill in _GRAPHQL_SKILLS},
          **{skill: "EXPOSURE" for skill in _EXPOSURE_SKILLS},
          **{skill: "CLIENT_SIDE" for skill in _CLIENT_SKILLS},
          "internal-surface-candidate": "INTERNAL_SURFACE"}
_EXPECTED_VALIDATORS = {
    "cross-tenant-object-authorization": {"ownership_matrix", "response_diff", "protected_content"},
    "horizontal-object-authorization": {"ownership_matrix", "response_diff"},
    "vertical-role-authorization": {"role_matrix", "state_readback"},
    "hidden-function-authorization": {"role_matrix", "protected_effect"},
    "graphql-object-authorization": {"graphql_data_diff", "ownership_matrix"},
    "graphql-mutation-authorization": {"state_readback", "role_matrix"},
    "unauthenticated-sensitive-download": {"content_hash_match", "authorization_control"},
    "sensitive-data-exposure": {"sensitivity_review", "public_by_design_check"},
    "check-before-transform-dom-xss": {"browser_execution", "source_sink_trace"},
    "postmessage-trust-analysis": {"origin_control", "capability_proof"},
    "internal-surface-candidate": {"scope_review", "current_reachability"},
}
_DENIED = {401, 403, 404}
_VALIDATOR_VERSION = "1.0.0"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class Observation:
    step: RuntimeStep
    exchange: TrafficExchange
    features: ResponseFeatures
    actor: str
    identity_id: str | None
    object_ref_hash: str | None
    object_type: str | None
    operation: str | None
    audit_valid: bool
    audit_reason: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValidationContext:
    run: PlanRun
    plan: dict[str, object]
    observations: tuple[Observation, ...]
    evidence_snapshot_hash: str
    criteria: tuple[str, ...]
    rejections: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValidatorDecision:
    status: ValidationStatus
    checks: tuple[ValidationCheck, ...]
    controls: tuple[str, ...]
    reasons: tuple[str, ...]
    limitations: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]
    contradicting_evidence_ids: tuple[str, ...]
    reproduction_count: int
    demonstrated_impact: str | None
    potential_impact: str | None
    finding: FindingSpec | None = None


class Validator(Protocol):
    id: str
    version: str

    def evaluate(self, context: ValidationContext, engine: DeterministicValidatorEngine) -> ValidatorDecision: ...


def _check(code: str, outcome: bool | None, evidence: tuple[str, ...] = ()) -> ValidationCheck:
    return ValidationCheck(code, CheckOutcome.UNKNOWN if outcome is None else
                           CheckOutcome.PASS if outcome else CheckOutcome.FAIL, evidence)


def _decision(status: ValidationStatus, reason: str, *, checks: tuple[ValidationCheck, ...] = (),
              controls: tuple[str, ...] = (), supporting: tuple[str, ...] = (),
              contradicting: tuple[str, ...] = (), reproductions: int = 0,
              impact: str | None = None, finding: FindingSpec | None = None,
              limitations: tuple[str, ...] = ()) -> ValidatorDecision:
    return ValidatorDecision(status, checks, controls, (reason,), limitations,
                             supporting, contradicting, reproductions, impact, None, finding)


class ValidatorRegistry:
    def __init__(self) -> None:
        self._items: dict[str, Validator] = {}
        for name, boundary in _AUTH_SKILLS.items():
            self._items[name] = AuthorizationValidator(boundary)
        for name in _GRAPHQL_SKILLS:
            self._items[name] = GraphQLValidator(name == "graphql-mutation-authorization")
        for name in _EXPOSURE_SKILLS:
            self._items[name] = ExposureValidator(name == "sensitive-data-exposure")
        for name in _CLIENT_SKILLS:
            self._items[name] = ClientSideValidator(name)
        self._items["internal-surface-candidate"] = InternalSurfaceValidator()

    def select(self, skill_id: str) -> Validator | None:
        return self._items.get(skill_id)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._items))


class DeterministicValidatorEngine:
    def __init__(self, *, runs: PlanRunStore, traffic: TrafficStore,
                 evidence: EvidenceFactStore, identities: IdentityRegistry,
                 hypotheses: HypothesisStore, results: ValidationStore,
                 registry: ValidatorRegistry | None = None) -> None:
        self.runs, self.traffic, self.evidence = runs, traffic, evidence
        self.identities, self.hypotheses, self.results = identities, hypotheses, results
        self.registry = registry or ValidatorRegistry()
        self.comparator = ResponseComparator(evidence)

    def _trusted_fact(self, subject: str, predicate: str, target_id: str) -> tuple[Fact, ...]:
        page = self.evidence.find_facts(subject, predicate, limit=20)
        if page.next_cursor is not None:
            return ()
        found = page.items
        trusted = []
        for fact in found:
            if (fact.target_ref != target_id or fact.status is not FactStatus.ACTIVE or
                    fact.confidence < 0.9 or fact.source == "MANUAL" or not fact.evidence_ids):
                continue
            if all((item := self.evidence.get_evidence(ref)) is not None and
                   item.target_ref == target_id for ref in fact.evidence_ids):
                trusted.append(fact)
        return tuple(trusted)

    def fact(self, subject: str | None, predicate: str, target_id: str) -> tuple[Fact, ...]:
        return self._trusted_fact(subject, predicate, target_id) if subject else ()

    def fact_value(self, subject: str | None, predicate: str, target_id: str) -> tuple[str | None, tuple[str, ...]]:
        facts = self.fact(subject, predicate, target_id)
        values = {fact.object for fact in facts}
        if len(values) != 1:
            return None, tuple(fact.evidence_ids[0] for fact in facts)[:16]
        return next(iter(values)), tuple(fact.evidence_ids[0] for fact in facts)[:16]

    def membership(self, identity_id: str | None, target_id: str) -> tuple[str, tuple[str, ...], tuple[str, ...]] | None:
        if not identity_id:
            return None
        identity = self.identities.get_identity(target_id, identity_id)
        if identity is None:
            return None
        page = self.identities.list_memberships(identity_id, limit=20)
        active = []
        for membership in page.items:
            if (membership.target_id != target_id or membership.status is not MembershipStatus.ACTIVE or
                    membership.observation_state is not ObservationState.OBSERVED or
                    not membership.fact_id):
                continue
            facts = self.fact(identity_id, "member_of", target_id)
            if any(fact.fact_id == membership.fact_id and fact.object == membership.tenant_id
                   for fact in facts):
                active.append(membership)
        if len(active) != 1 or page.next_cursor is not None:
            return None
        item = active[0]
        return item.tenant_id, item.role_ids, item.evidence_ids

    def principal(self, identity_id: str | None, target_id: str) -> tuple[str, tuple[str, ...]] | None:
        if not identity_id:
            return None
        identity = self.identities.get_identity(target_id, identity_id)
        if (identity is None or identity.principal_state is not ObservationState.OBSERVED or
                not identity.principal_id or not identity.principal_fact_id):
            return None
        facts = self.fact(identity_id, "resolves_to", target_id)
        for fact in facts:
            if fact.fact_id == identity.principal_fact_id and fact.object == identity.principal_id:
                return identity.principal_id, fact.evidence_ids
        return None

    def _audit(self, step: RuntimeStep, exchange: TrafficExchange, run: PlanRun) -> tuple[bool, str, dict[str, object]]:
        if (step.status is not RuntimeStepStatus.COMPLETED or not step.decision_id or
                not step.permit_id or not step.action_id or exchange.target_id != run.target_id or
                exchange.package_id != run.package_id or
                exchange.state is not ExchangeState.COMPLETE or exchange.response is None or
                exchange.scope_result.value != "IN_SCOPE" or
                exchange.correlation_hash != _digest(step.execution_id or "")):
            return False, "UNTRUSTED_TRAFFIC", {}
        with self.evidence._connection() as db:
            row = db.execute(
                "SELECT a.actor,a.identity_id,a.session_id,a.object_ref_hash,a.object_type,a.operation,"
                "a.target_id,a.package_id,a.action_id,d.decision_id,p.permit_id,"
                "d.result,d.scope_result,p.consumed_at,p.approval_id,"
                "ev.event_id AS sent_event FROM executor_events ev "
                "JOIN executor_permits p ON p.permit_id=ev.permit_id "
                "JOIN policy_actions a ON a.action_id=p.action_id "
                "JOIN policy_decisions d ON d.decision_id=p.decision_id "
                "WHERE ev.exchange_id=? AND ev.event_type='REQUEST_SENT' AND ev.target_id=? "
                "AND p.permit_id=? AND a.action_id=? "
                "ORDER BY ev.event_id DESC LIMIT 1",
                (exchange.id, run.target_id, step.permit_id, step.action_id)).fetchone()
            preflight = db.execute("SELECT action_id,result,scope_result FROM policy_decisions "
                                   "WHERE decision_id=?", (step.decision_id,)).fetchone()
            first = db.execute("SELECT action_id FROM executor_permits WHERE permit_id=?",
                               (step.permit_id,)).fetchone()
            approval = (db.execute("SELECT status FROM policy_approvals WHERE approval_id=?",
                                   (row["approval_id"],)).fetchone() if row and row["approval_id"] else None)
        if (row is None or first is None or preflight is None or
                first["action_id"] != step.action_id or
                preflight["action_id"] != step.action_id or
                preflight["result"] != "ALLOW" or preflight["scope_result"] != "IN_SCOPE" or
                row["target_id"] != run.target_id or row["package_id"] != run.package_id or
                row["result"] != "ALLOW" or row["scope_result"] != "IN_SCOPE" or
                not row["consumed_at"] or approval is not None and approval["status"] != "CONSUMED"):
            return False, "POLICY_OR_PERMIT_UNVERIFIED", {}
        if row["actor"] == "ANONYMOUS":
            if (exchange.attribution.auth_state is not AuthState.ANONYMOUS or
                    exchange.attribution.verified_identity_id is not None or row["identity_id"]):
                return False, "ANONYMOUS_CONTEXT_INVALID", {}
        elif (row["actor"] != "AUTHENTICATED" or
              exchange.attribution.auth_state is not AuthState.VERIFIED or
              exchange.attribution.verified_identity_id != row["identity_id"] or
              exchange.attribution.browser_session_id != row["session_id"]):
            return False, "SESSION_INVALID", {}
        return True, "POLICY_AUTHORIZED", dict(row)

    def _context(self, run: PlanRun) -> ValidationContext:
        snapshot = self.runs.snapshot(run.plan_id, run.target_id)
        if snapshot.content_hash != run.snapshot_hash:
            raise ValueError("plan snapshot changed after execution")
        if self.hypotheses.get(run.hypothesis_id, run.target_id) is None:
            raise ValueError("hypothesis missing from validation chain")
        observations: list[Observation] = []
        snap_parts = [run.id, run.snapshot_hash, run.status.value]
        for step in self.runs.steps(run.id):
            if step.type != "EXECUTE_REQUEST":
                continue
            result = self.runs.result(step.id)
            snap_parts.append(step.id + ":" + (result.id if result else "MISSING"))
            if result is None or not result.exchange_ids:
                continue
            exchanges = tuple(self.traffic.get_exchange(ref) for ref in result.exchange_ids)
            if any(item is None for item in exchanges):
                continue
            for exchange in exchanges:
                assert exchange is not None
                snap_parts.append(exchange.id + ":" +
                                  (exchange.response.body_hash if exchange.response else "NO_RESPONSE"))
            exchange = exchanges[-1]
            assert exchange is not None
            audited = [self._audit(step, item, run) for item in exchanges if item is not None]
            valid = all(item[0] for item in audited)
            data = audited[-1][2] if valid else {}
            reason = "POLICY_AUTHORIZED" if valid else next(item[1] for item in audited if not item[0])
            refs = tuple(dict.fromkeys((*result.evidence_ids, *exchange.evidence_ids)))[:24]
            observations.append(Observation(
                step, exchange, self.comparator.features(exchange),
                str(data.get("actor", "")), data.get("identity_id"),
                data.get("object_ref_hash"), data.get("object_type"),
                data.get("operation"), valid, reason, refs))
        validators = snapshot.data.get("required_validators", [])
        if not isinstance(validators, list) or any(not isinstance(item, str) for item in validators):
            validators = []
        criteria = tuple(str(item) for item in snapshot.data.get("confirmation_requirements", [])[:16])
        rejections = tuple(str(item) for item in snapshot.data.get("rejection_conditions", [])[:16])
        snap_parts.extend(sorted(validators))
        return ValidationContext(run, snapshot.data, tuple(observations),
                                 _digest("|".join(snap_parts)), criteria, rejections)

    @staticmethod
    def _controls(context: ValidationContext) -> tuple[Observation | None, tuple[Observation, ...],
                                                       tuple[Observation, ...]]:
        control = next((item for item in context.observations if item.step.role == "CONTROL"), None)
        boundary = tuple(item for item in context.observations if item.step.role == "BOUNDARY")
        negative = tuple(item for item in context.observations if item.step.role == "OTHER" and
                         item.step.action_slot is not None and
                         context.plan["proposed_actions"][item.step.action_slot].get("control_kind")
                         == "INVALID_OBJECT")
        return control, boundary, negative

    @staticmethod
    def _base_checks(control: Observation | None, boundary: tuple[Observation, ...],
                     negative: tuple[Observation, ...]) -> tuple[ValidationCheck, ...]:
        return (_check("OWNER_CONTROL", bool(control and control.audit_valid and
                                        control.features.status_code is not None and
                                        200 <= control.features.status_code < 300),
                       control.evidence_ids[:2] if control else ()),
                _check("BOUNDARY_OBSERVED", bool(boundary) and all(item.audit_valid for item in boundary),
                       tuple(ref for item in boundary for ref in item.evidence_ids[:1])[:8]),
                _check("NEGATIVE_CONTROL", bool(negative) and all(
                    item.audit_valid and item.features.status_code in _DENIED for item in negative),
                       tuple(ref for item in negative for ref in item.evidence_ids[:1])[:4]))

    @staticmethod
    def _finding(context: ValidationContext, control: Observation, boundary: Observation,
                 category: str, impact: str, root_key: str | None = None) -> FindingSpec:
        shape = re.sub(r"\{p:[0-9a-f]{12}\}", "{id}", boundary.exchange.request.display_path)
        operation = root_key or boundary.operation or (boundary.features.request_method + ":" +
                                                       boundary.exchange.request.origin + shape)
        raw = json.dumps((context.run.target_id, category, operation, boundary.object_type or "UNKNOWN"),
                         separators=(",", ":"))
        surface = boundary.features.request_structural_fingerprint
        return FindingSpec(category, _digest(raw), surface, boundary.object_type,
                           category.replace("_", " ").title(),
                           "Protected boundary effect reproduced with owned controls.", impact)

    def validate_run(self, run_id: str, target_id: str) -> tuple[ValidationResult, object | None]:
        run = self.runs.get(run_id, target_id)
        if run is None:
            raise LookupError("run not found")
        if run.status is not RunStatus.COMPLETED:
            raise ValueError("only completed runs are evidence-ready for deterministic validation")
        context = self._context(run)
        validator = self.registry.select(run.skill_id)
        expected = _EXPECTED_VALIDATORS.get(run.skill_id)
        declared = context.plan.get("required_validators")
        if validator is None or expected is None or not isinstance(declared, list) or not expected <= set(declared):
            decision = _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "VALIDATOR_BINDING_MISSING",
                                 limitations=("The plan lacks a frozen validator contract.",))
            validator_id = "unbound_validator"
        else:
            decision = validator.evaluate(context, self)
            validator_id = validator.id
        if decision.status is ValidationStatus.CONFIRMED and (
                decision.finding is None or not decision.supporting_evidence_ids or
                any(check.outcome is not CheckOutcome.PASS for check in decision.checks)):
            raise RuntimeError("confirmed validation failed its evidence gate")
        decision_snapshot = _digest(json.dumps({
            "base": context.evidence_snapshot_hash,
            "status": decision.status.value,
            "checks": [check.to_dict() for check in decision.checks],
            "supporting": decision.supporting_evidence_ids,
            "contradicting": decision.contradicting_evidence_ids,
            "reasons": decision.reasons,
        }, sort_keys=True, separators=(",", ":")))
        refs = tuple(dict.fromkeys(decision.supporting_evidence_ids))[:64]
        contradicting = tuple(dict.fromkeys(decision.contradicting_evidence_ids))[:64]
        result = ValidationResult(
            "VALIDATION-" + uuid.uuid4().hex, run.target_id, run.id, run.plan_id,
            run.hypothesis_id, run.skill_id, run.skill_version, run.skill_hash,
            validator_id, _VALIDATOR_VERSION, "DETERMINISTIC", decision.status,
            "HIGH" if decision.status is ValidationStatus.CONFIRMED else
            "MEDIUM" if decision.status is ValidationStatus.REJECTED else "LOW",
            run.snapshot_hash, decision_snapshot, refs, contradicting,
            decision.controls, context.criteria, context.rejections, decision.checks,
            decision.demonstrated_impact, decision.potential_impact,
            decision.reproduction_count, decision.limitations, decision.reasons,
            {"CONFIRMED": "Controlled protected boundary impact reproduced.",
             "REJECTED": "Controlled observation disproves the proposed boundary failure.",
             "INVALID_TEST": "Required owner or negative control failed.",
             "NEEDS_MANUAL_REVIEW": "Evidence requires independent researcher review.",
             "INSUFFICIENT_EVIDENCE": "Required protected evidence is missing."}[decision.status.value],
            _now())
        return self.results.record(result, decision.finding)

    def record_manual(self, run_id: str, target_id: str, status: ValidationStatus,
                      evidence_ids: tuple[str, ...], reason_code: str) -> ValidationResult:
        if status not in {ValidationStatus.REJECTED, ValidationStatus.NEEDS_MANUAL_REVIEW,
                          ValidationStatus.INSUFFICIENT_EVIDENCE, ValidationStatus.INVALID_TEST}:
            raise ValueError("manual assertions cannot create confirmed findings")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason_code) or not evidence_ids or len(evidence_ids) > 16:
            raise ValueError("manual validation requires bounded evidence and a reason code")
        run = self.runs.get(run_id, target_id)
        if run is None or run.status is not RunStatus.COMPLETED:
            raise ValueError("manual validation requires a completed target run")
        for ref in evidence_ids:
            item = self.evidence.get_evidence(ref)
            if item is None or item.target_ref != target_id:
                raise ValueError("manual evidence is not target-owned")
        result = ValidationResult(
            "VALIDATION-" + uuid.uuid4().hex, run.target_id, run.id, run.plan_id,
            run.hypothesis_id, run.skill_id, run.skill_version, run.skill_hash,
            "researcher_review", "1.0.0", "MANUAL", status, "LOW", run.snapshot_hash,
            _digest("|".join((run.id, *sorted(evidence_ids), reason_code, _now()))),
            evidence_ids, (), (), (), (), (), None, None, 0,
            ("Researcher assertion; no deterministic confirmation.",), (reason_code,),
            "Researcher review recorded without a confirmed finding.", _now())
        stored, _ = self.results.record(result)
        return stored


class AuthorizationValidator:
    version = _VALIDATOR_VERSION

    def __init__(self, boundary: str) -> None:
        self.boundary = boundary
        self.id = "authorization_" + boundary.lower()

    def evaluate(self, context: ValidationContext, engine: DeterministicValidatorEngine) -> ValidatorDecision:
        control, boundaries, negative = engine._controls(context)
        checks = list(engine._base_checks(control, boundaries, negative))
        if control is None or checks[0].outcome is CheckOutcome.FAIL:
            return _decision(ValidationStatus.INVALID_TEST, "CONTROL_FAILED", checks=tuple(checks))
        if not boundaries:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "BOUNDARY_MISSING", checks=tuple(checks))
        if not negative:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "NEGATIVE_CONTROL_MISSING", checks=tuple(checks))
        if checks[2].outcome is CheckOutcome.FAIL:
            return _decision(ValidationStatus.INVALID_TEST, "NEGATIVE_CONTROL_FAILED", checks=tuple(checks))
        if not all(item.audit_valid for item in boundaries):
            return _decision(ValidationStatus.INVALID_TEST, "SESSION_INVALID", checks=tuple(checks))
        if any(item.features.status_code in _DENIED for item in boundaries) and all(
                item.features.status_code in _DENIED for item in boundaries):
            return _decision(ValidationStatus.REJECTED, "BOUNDARY_DENIED", checks=tuple(checks),
                             controls=("OWNER_CONTROL", "INVALID_OBJECT"),
                             contradicting=tuple(ref for item in boundaries for ref in item.evidence_ids[:2])[:16])
        object_hash = control.object_ref_hash
        if (not object_hash or any(item.object_ref_hash != object_hash for item in boundaries) or
                not re.fullmatch(r"[0-9a-f]{64}", object_hash)):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "OBJECT_BINDING_UNKNOWN", checks=tuple(checks))
        target = context.run.target_id
        visibility, vis_refs = engine.fact_value(object_hash, "resource_visibility", target)
        if visibility == "PUBLIC":
            return _decision(ValidationStatus.REJECTED, "INTENTIONALLY_PUBLIC", checks=tuple(checks),
                             contradicting=vis_refs)
        policy, policy_refs = engine.fact_value(object_hash, "access_policy", target)
        tenant, tenant_refs = engine.fact_value(object_hash, "resource_tenant", target)
        owner, owner_refs = engine.fact_value(object_hash, "resource_owner", target)
        if visibility != "PRIVATE" or policy is None:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "PROTECTION_UNPROVEN", checks=tuple(checks))
        owner_member = engine.membership(control.identity_id, target)
        foreign_member = engine.membership(boundaries[0].identity_id, target)
        if owner_member is None or foreign_member is None:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "TENANT_OR_ROLE_UNKNOWN", checks=tuple(checks))
        owner_tenant, owner_roles, owner_membership_refs = owner_member
        foreign_tenant, foreign_roles, foreign_membership_refs = foreign_member
        relationship_refs = (*vis_refs, *policy_refs, *tenant_refs, *owner_refs,
                             *owner_membership_refs, *foreign_membership_refs)
        if self.boundary == "CROSS_TENANT":
            relation = bool(tenant and tenant == owner_tenant and foreign_tenant != tenant and
                            policy in {"TENANT_ONLY", "OWNER_ONLY"})
            category = "CROSS_TENANT_BOLA"
        elif self.boundary == "HORIZONTAL":
            first = engine.principal(control.identity_id, target)
            second = engine.principal(boundaries[0].identity_id, target)
            relation = bool(first and second and first[0] != second[0] and
                            owner_tenant == foreign_tenant == tenant and owner == first[0] and
                            policy == "OWNER_ONLY")
            relationship_refs += tuple(first[1] if first else ()) + tuple(second[1] if second else ())
            category = "HORIZONTAL_IDOR"
        else:
            restriction, restriction_refs = engine.fact_value(object_hash, "required_role", target)
            relation = bool(tenant and owner_tenant == foreign_tenant == tenant and
                            restriction and restriction in owner_roles and
                            restriction not in foreign_roles and policy == "ROLE_RESTRICTED")
            relationship_refs += restriction_refs
            category = "VERTICAL_ROLE_BYPASS" if self.boundary == "VERTICAL" else "HIDDEN_FUNCTION_BYPASS"
        checks.append(_check("BOUNDARY_RELATIONSHIP", relation, tuple(relationship_refs)[:8]))
        if not relation:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "BOUNDARY_NOT_PROVEN", checks=tuple(checks))
        matches = []
        tenant_marker, marker_refs = engine.fact_value(object_hash, "resource_tenant_marker", target)
        if tenant_marker is not None:
            relationship_refs += marker_refs
        for item in boundaries:
            pair = engine.comparator.compare(control.features, item.features)
            object_match = (object_hash in item.features.object_id_hashes
                            if item.features.object_id_hashes else False)
            tenant_match = (not item.features.tenant_id_hashes or
                            bool(tenant_marker and tenant_marker in item.features.tenant_id_hashes))
            exact_protected = (pair.same_request_path and pair.body_hash_equal and
                               bool(control.features.body_size and control.features.body_size > 0) and
                               control.features.content_type != "text/html" and object_match and tenant_match)
            if (control.features.request_method not in {"GET", "HEAD"} or
                    item.features.request_method not in {"GET", "HEAD"}):
                continue
            if (item.features.status_code is not None and 200 <= item.features.status_code < 300 and
                    exact_protected and item.identity_id == boundaries[0].identity_id):
                matches.append(item)
        checks.append(_check("PROTECTED_CONTENT", len(matches) >= 2,
                             tuple(ref for item in matches for ref in item.evidence_ids[:2])[:8]))
        if not matches:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "NO_PROTECTED_CONTENT", checks=tuple(checks))
        if len(matches) < 2:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW, "REPRODUCTION_REQUIRED",
                             checks=tuple(checks), reproductions=len(matches))
        evidence = tuple(dict.fromkeys((*control.evidence_ids[:3],
                                         *(ref for item in matches for ref in item.evidence_ids[:3]),
                                         *(ref for item in negative for ref in item.evidence_ids[:2]),
                                         *relationship_refs)))[:64]
        root_key, root_refs = engine.fact_value(object_hash, "root_cause_key", target)
        if root_key:
            evidence = tuple(dict.fromkeys((*evidence, *root_refs)))[:64]
        checks[-1] = _check("PROTECTED_CONTENT", True, evidence[:8])
        finding = engine._finding(context, control, matches[0], category,
                                  "PROTECTED_OBJECT_READ", root_key)
        return _decision(ValidationStatus.CONFIRMED, "UNAUTHORIZED_PROTECTED_READ",
                         checks=tuple(checks), controls=("OWNER_CONTROL", "INVALID_OBJECT"),
                         supporting=evidence, reproductions=len(matches),
                         impact="PROTECTED_OBJECT_READ", finding=finding)


class GraphQLValidator:
    version = _VALIDATOR_VERSION
    id = "graphql_authorization"

    def __init__(self, mutation: bool) -> None:
        self.mutation = mutation

    def evaluate(self, context: ValidationContext, engine: DeterministicValidatorEngine) -> ValidatorDecision:
        control, boundaries, negative = engine._controls(context)
        checks = list(engine._base_checks(control, boundaries, negative))
        if control is None or checks[0].outcome is CheckOutcome.FAIL:
            return _decision(ValidationStatus.INVALID_TEST, "CONTROL_FAILED", checks=tuple(checks))
        if not boundaries or not negative:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "GRAPHQL_CONTROLS_MISSING", checks=tuple(checks))
        if not all(item.audit_valid for item in (*boundaries, *negative)):
            return _decision(ValidationStatus.INVALID_TEST, "SESSION_INVALID", checks=tuple(checks))
        if control.features.graphql_errors_present or not control.features.graphql_data_present:
            return _decision(ValidationStatus.INVALID_TEST, "GRAPHQL_CONTROL_FAILED", checks=tuple(checks))
        semantic_negative = all(item.features.graphql_errors_present or
                                not item.features.graphql_data_present for item in negative)
        checks[2] = _check("NEGATIVE_CONTROL", semantic_negative,
                           tuple(ref for item in negative for ref in item.evidence_ids[:1])[:4])
        if not semantic_negative:
            return _decision(ValidationStatus.INVALID_TEST, "NEGATIVE_CONTROL_FAILED", checks=tuple(checks))
        if all(item.features.graphql_errors_present or not item.features.graphql_data_present
               for item in boundaries):
            return _decision(ValidationStatus.REJECTED, "GRAPHQL_BOUNDARY_DENIED", checks=tuple(checks),
                             contradicting=tuple(ref for item in boundaries for ref in item.evidence_ids[:2])[:16])
        object_hash = control.object_ref_hash
        if not object_hash or any(item.object_ref_hash != object_hash for item in boundaries):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "OBJECT_BINDING_UNKNOWN", checks=tuple(checks))
        visibility, vis_refs = engine.fact_value(object_hash, "resource_visibility", context.run.target_id)
        if visibility == "PUBLIC":
            return _decision(ValidationStatus.REJECTED, "INTENTIONALLY_PUBLIC", checks=tuple(checks),
                             contradicting=vis_refs)
        operation, op_refs = engine.fact_value(object_hash, "graphql_operation", context.run.target_id)
        tenant, tenant_refs = engine.fact_value(object_hash, "resource_tenant", context.run.target_id)
        policy, policy_refs = engine.fact_value(object_hash, "access_policy", context.run.target_id)
        first = engine.membership(control.identity_id, context.run.target_id)
        second = engine.membership(boundaries[0].identity_id, context.run.target_id)
        if (visibility != "PRIVATE" or not operation or operation != control.operation or
                not tenant or not first or not second or first[0] != tenant or second[0] == tenant or
                policy not in {"TENANT_ONLY", "OWNER_ONLY"}):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "GRAPHQL_BOUNDARY_UNPROVEN",
                             checks=tuple(checks))
        tenant_marker, marker_refs = engine.fact_value(object_hash, "resource_tenant_marker",
                                                       context.run.target_id)
        matches = tuple(item for item in boundaries if
                        item.features.graphql_data_present and not item.features.graphql_errors_present and
                        item.features.graphql_data_hash == control.features.graphql_data_hash and
                        object_hash in item.features.object_id_hashes and
                        (not item.features.tenant_id_hashes or
                         bool(tenant_marker and tenant_marker in item.features.tenant_id_hashes)) and
                        item.operation == operation and item.features.request_method == control.features.request_method)
        checks.append(_check("GRAPHQL_DATA_PROOF", len(matches) >= 2,
                             tuple(ref for item in matches for ref in item.evidence_ids[:2])[:8]))
        if self.mutation:
            checks.append(_check("SIDE_EFFECT_READBACK", None))
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW, "NO_ATTESTED_SIDE_EFFECT_READBACK",
                             checks=tuple(checks), reproductions=len(matches),
                             limitations=("A Fact alone cannot prove a durable mutation effect.",))
        if not matches:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "GRAPHQL_DATA_UNPROVEN",
                             checks=tuple(checks))
        if len(matches) < 2:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW, "REPRODUCTION_REQUIRED",
                             checks=tuple(checks), reproductions=len(matches))
        evidence = tuple(dict.fromkeys((*control.evidence_ids[:3],
                                         *(ref for item in matches for ref in item.evidence_ids[:3]),
                                         *(ref for item in negative for ref in item.evidence_ids[:2]),
                                         *vis_refs, *op_refs, *tenant_refs, *policy_refs, *marker_refs,
                                         *first[2], *second[2])))[:64]
        finding = engine._finding(context, control, matches[0], "GRAPHQL_AUTHORIZATION",
                                  "GRAPHQL_PROTECTED_OBJECT_READ" if not self.mutation else
                                  "GRAPHQL_UNAUTHORIZED_STATE_CHANGE", operation)
        return _decision(ValidationStatus.CONFIRMED, "GRAPHQL_PROTECTED_BOUNDARY",
                         checks=tuple(checks), controls=("OWNER_CONTROL", "INVALID_OBJECT"),
                         supporting=evidence, reproductions=len(matches),
                         impact="GRAPHQL_PROTECTED_OBJECT_READ" if not self.mutation else
                         "GRAPHQL_UNAUTHORIZED_STATE_CHANGE", finding=finding)


class ExposureValidator:
    version = _VALIDATOR_VERSION
    id = "anonymous_exposure"

    def __init__(self, sensitive: bool) -> None:
        self.sensitive = sensitive

    def evaluate(self, context: ValidationContext, engine: DeterministicValidatorEngine) -> ValidatorDecision:
        control, boundaries, negative = engine._controls(context)
        checks = list(engine._base_checks(control, boundaries, negative))
        if control is None or checks[0].outcome is CheckOutcome.FAIL or control.actor != "AUTHENTICATED":
            return _decision(ValidationStatus.INVALID_TEST, "CONTROL_FAILED", checks=tuple(checks))
        if not negative:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "NEGATIVE_CONTROL_MISSING", checks=tuple(checks))
        if checks[2].outcome is CheckOutcome.FAIL:
            return _decision(ValidationStatus.INVALID_TEST, "NEGATIVE_CONTROL_FAILED", checks=tuple(checks))
        if not boundaries:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "ANONYMOUS_TEST_MISSING", checks=tuple(checks))
        if any(not item.audit_valid or item.actor != "ANONYMOUS" for item in boundaries):
            return _decision(ValidationStatus.INVALID_TEST, "ANONYMOUS_CONTEXT_INVALID", checks=tuple(checks))
        if all(item.features.status_code in _DENIED for item in boundaries):
            return _decision(ValidationStatus.REJECTED, "ANONYMOUS_BOUNDARY_DENIED", checks=tuple(checks),
                             contradicting=tuple(ref for item in boundaries for ref in item.evidence_ids[:2])[:16])
        object_hash = control.object_ref_hash
        if not object_hash or any(item.object_ref_hash != object_hash for item in boundaries):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "OBJECT_BINDING_UNKNOWN", checks=tuple(checks))
        visibility, vis_refs = engine.fact_value(object_hash, "resource_visibility", context.run.target_id)
        if visibility == "PUBLIC":
            return _decision(ValidationStatus.REJECTED, "INTENTIONALLY_PUBLIC", checks=tuple(checks),
                             contradicting=vis_refs)
        classification, class_refs = engine.fact_value(object_hash, "data_classification", context.run.target_id)
        if self.sensitive:
            sample, sample_refs = engine.fact_value(object_hash, "sample_data", context.run.target_id)
            if sample == "TRUE":
                return _decision(ValidationStatus.REJECTED, "TEST_DATA_ONLY", checks=tuple(checks),
                                 contradicting=sample_refs)
            if classification not in {"SENSITIVE", "CREDENTIAL"}:
                return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "SENSITIVITY_UNPROVEN",
                                 checks=tuple(checks))
            if classification == "CREDENTIAL":
                cleartext, clear_refs = engine.fact_value(object_hash, "cleartext_exposure", context.run.target_id)
                relevance, rel_refs = engine.fact_value(object_hash, "target_relevance", context.run.target_id)
                if cleartext != "VERIFIED" or relevance != "FIRST_PARTY":
                    return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW, "CREDENTIAL_CONTEXT_UNPROVEN",
                                     checks=tuple(checks))
                class_refs += clear_refs + rel_refs
        elif classification not in {"PROTECTED_FILE", "SENSITIVE"}:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "PROTECTED_CONTENT_UNPROVEN",
                             checks=tuple(checks))
        if visibility != "PRIVATE":
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "PRIVACY_EXPECTATION_UNKNOWN",
                             checks=tuple(checks))
        matches = tuple(item for item in boundaries if
                        item.features.status_code is not None and 200 <= item.features.status_code < 300 and
                        engine.comparator.compare(control.features, item.features).same_request_path and
                        engine.comparator.compare(control.features, item.features).body_hash_equal and
                        bool(control.features.body_size and control.features.body_size > 0) and
                        control.features.content_type != "text/html")
        checks.append(_check("PROTECTED_CONTENT_EQUAL", len(matches) >= 2,
                             tuple(ref for item in matches for ref in item.evidence_ids[:2])[:8]))
        if not matches:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "CONTENT_EQUIVALENCE_UNPROVEN",
                             checks=tuple(checks))
        if len(matches) < 2:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW, "REPRODUCTION_REQUIRED",
                             checks=tuple(checks), reproductions=len(matches))
        evidence = tuple(dict.fromkeys((*control.evidence_ids[:3],
                                         *(ref for item in matches for ref in item.evidence_ids[:3]),
                                         *(ref for item in negative for ref in item.evidence_ids[:2]),
                                         *vis_refs, *class_refs)))[:64]
        category = "SENSITIVE_DATA_EXPOSURE" if self.sensitive else "UNAUTHENTICATED_DOWNLOAD"
        finding = engine._finding(context, control, matches[0], category,
                                  "ANONYMOUS_PROTECTED_CONTENT_READ")
        return _decision(ValidationStatus.CONFIRMED, "ANONYMOUS_PROTECTED_CONTENT",
                         checks=tuple(checks), controls=("OWNER_CONTROL", "INVALID_OBJECT"),
                         supporting=evidence, reproductions=len(matches),
                         impact="ANONYMOUS_PROTECTED_CONTENT_READ", finding=finding)


class ClientSideValidator:
    version = _VALIDATOR_VERSION

    def __init__(self, skill_id: str) -> None:
        self.id = "client_side_" + skill_id.replace("-", "_")
        self.skill_id = skill_id

    def evaluate(self, context: ValidationContext, engine: DeterministicValidatorEngine) -> ValidatorDecision:
        required = ("ATTACKER_SOURCE", "SOURCE_SINK_TRACE", "EXECUTION_MARKER",
                    "BENIGN_CONTROL", "NEGATIVE_CONTROL", "FRESH_BROWSER_CONTEXT",
                    "CSP_SANDBOX_BEHAVIOR") if self.skill_id == "check-before-transform-dom-xss" else (
                    "UNTRUSTED_ORIGIN", "MESSAGE_PROTOCOL", "ORIGIN_SOURCE_DECISION",
                    "UNAUTHORIZED_CAPABILITY", "NEGATIVE_CONTROL", "FRESH_BROWSER_CONTEXT")
        return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "BROWSER_PROOF_NOT_CAPTURED",
                         checks=tuple(_check(code, None) for code in required),
                         limitations=("Phase 16 has no attested browser execution/capability proof record.",))


class InternalSurfaceValidator:
    id = "internal_surface"
    version = _VALIDATOR_VERSION

    def evaluate(self, context: ValidationContext, engine: DeterministicValidatorEngine) -> ValidatorDecision:
        return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW, "EXTERNAL_REACHABILITY_UNPROVEN",
                         checks=(_check("CURRENT_EXTERNAL_REACHABILITY", None),
                                 _check("SENSITIVE_FUNCTION", None)),
                         limitations=("No new VHOST or Host-header probe is permitted in validation.",))
