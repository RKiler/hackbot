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
from .mutation_results import MutationResultStore, MutationStatus, value_hash
from .typed_mutations import MutationPhase
from .plan_runs import PlanRun, PlanRunStore, RunStatus, RuntimeStep, RuntimeStepStatus
from .response_compare import ResponseComparator, ResponseFeatures
from .store import EvidenceFactStore
from .traffic import AuthState, ExchangeState, TrafficExchange, TrafficStore
from .validation_store import (CheckOutcome, FindingSpec, ValidationCheck,
                               ValidationResult, ValidationStatus, ValidationStore)


_AUTH_SKILLS = {
    "cross-tenant-object-authorization": "CROSS_TENANT",
    "nested-resource-authorization": "PARENT_CHILD",
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
_KINDS["batch-object-authorization"] = "AUTHORIZATION"
_EXPECTED_VALIDATORS = {
    "cross-tenant-object-authorization": {"ownership_matrix", "response_diff", "protected_content"},
    "nested-resource-authorization": {"ownership_matrix", "response_diff", "protected_content"},
    "batch-object-authorization": {"ownership_matrix", "response_diff", "protected_content"},
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
    "typed-authorization-mutation": {"ownership_matrix", "state_readback", "restore_readback"},
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
        self._items["typed-authorization-mutation"] = TypedMutationValidator()
        self._items["batch-object-authorization"] = BatchReadValidator()

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

    def _semantic_object_hash(self, run: PlanRun, salted_hash: str | None,
                              object_type: str | None) -> str | None:
        """Bridge ObjectFactory's salted registry key to response/Facts object hashes."""
        if not salted_hash or not object_type:
            return salted_hash
        with self.evidence._connection() as db:
            row = db.execute(
                "SELECT test_object_id,external_id_evidence_id,verified_at,disposable "
                "FROM test_objects WHERE target_id=? AND package_id=? AND "
                "external_id_hash=? AND object_type=? LIMIT 1",
                (run.target_id, run.package_id, salted_hash, object_type)).fetchone()
        if row is None:
            return salted_hash
        if not row["verified_at"] or not row["disposable"] or not row["external_id_evidence_id"]:
            return None
        try:
            value = self.evidence.read_content(row["external_id_evidence_id"],
                                               allow_sensitive=True, max_bytes=256).decode("ascii")
        except (ValueError, UnicodeError, PermissionError):
            return None
        if _digest(row["test_object_id"] + ":" + value) != salted_hash:
            return None
        return _digest(value)

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
                self._semantic_object_hash(run, data.get("object_ref_hash"),
                                           data.get("object_type")), data.get("object_type"),
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
        elif self.boundary == "PARENT_CHILD":
            shapes = context.plan.get("request_templates", [])
            relation = False
            if (len(shapes) == 4 and all(isinstance(shape, dict) for shape in shapes) and
                    shapes[2].get("binding") == shapes[3].get("binding") ==
                    "AUTHORIZATION_NESTED_PARENT_V1" and
                    shapes[2].get("parent_object_id") == shapes[3].get("parent_object_id") and
                    shapes[2].get("foreign_parent_object_id") ==
                    shapes[3].get("foreign_parent_object_id")):
                with engine.evidence._connection() as db:
                    child = db.execute("SELECT parent_test_object_id,tenant_id,verified_at,disposable "
                                       "FROM test_objects WHERE test_object_id=? AND target_id=?",
                                       (shapes[0].get("test_object_id"), target)).fetchone()
                    parent = db.execute("SELECT tenant_id,verified_at,disposable FROM test_objects "
                                        "WHERE test_object_id=? AND target_id=?",
                                        (shapes[2].get("parent_object_id"), target)).fetchone()
                    foreign_parent = db.execute("SELECT tenant_id,creator_identity_id,verified_at,"
                                                "disposable FROM test_objects WHERE test_object_id=? "
                                                "AND target_id=?",
                                                (shapes[2].get("foreign_parent_object_id"), target)).fetchone()
                relation = bool(child and parent and foreign_parent and
                                child["parent_test_object_id"] == shapes[2]["parent_object_id"] and
                                child["tenant_id"] == parent["tenant_id"] == tenant == owner_tenant and
                                foreign_parent["tenant_id"] == foreign_tenant != tenant and
                                foreign_parent["creator_identity_id"] == boundaries[0].identity_id and
                                all(row["verified_at"] and row["disposable"] for row in
                                    (child, parent, foreign_parent)) and
                                policy in {"TENANT_ONLY", "OWNER_ONLY"})
            category = "NESTED_PARENT_CHILD_BOLA"
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
            exact_protected = ((pair.same_request_path or self.boundary == "PARENT_CHILD") and
                               pair.body_hash_equal and
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


class BatchReadValidator:
    id = "batch_object_authorization"
    version = _VALIDATOR_VERSION

    @staticmethod
    def _json(observation: Observation, engine: DeterministicValidatorEngine) -> object | None:
        response = observation.exchange.response
        ref = response.body_evidence_id if response else None
        record = engine.evidence.get_evidence(ref) if ref else None
        if (record is None or record.target_ref != observation.exchange.target_id or
                record.redaction_status.value != "ORIGINAL" or record.content_size > 8192):
            return None
        try:
            raw = engine.evidence.read_content(ref, allow_sensitive=True, max_bytes=8192)
            if hashlib.sha256(raw).hexdigest() != response.body_hash:
                return None
            def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
                result: dict[str, object] = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("ambiguous batch JSON")
                    result[key] = value
                return result
            return json.loads(raw, object_pairs_hook=unique_pairs)
        except (ValueError, TypeError, UnicodeError, PermissionError):
            return None

    @staticmethod
    def _items(data: object) -> dict[str, dict[str, object]] | None:
        if not isinstance(data, dict) or set(data) != {"items"} or not isinstance(data["items"], list):
            return None
        if len(data["items"]) > 3:
            return None
        result = {}
        for value in data["items"]:
            if not isinstance(value, dict) or not isinstance(value.get("id"), str):
                return None
            if value["id"] in result:
                return None
            result[value["id"]] = value
        return result

    def evaluate(self, context: ValidationContext, engine: DeterministicValidatorEngine) -> ValidatorDecision:
        plan, target = context.plan, context.run.target_id
        shapes = plan.get("request_templates", [])
        observed = {item.step.action_slot: item for item in context.observations}
        if (len(shapes) != 4 or set(observed) != {0, 1, 2, 3} or
                any(not item.audit_valid or item.features.request_method != "GET"
                    for item in observed.values()) or
                tuple(shape.get("binding") for shape in shapes) != (
                    "AUTHORIZATION_BATCH_PATH_V1", "AUTHORIZATION_OBJECT_PATH_V1",
                    "AUTHORIZATION_BATCH_PATH_V1", "AUTHORIZATION_BATCH_PATH_V1") or
                any(shapes[index].get("owner_peer_object_id") != shapes[0].get("owner_peer_object_id") or
                    shapes[index].get("actor_object_id") != shapes[0].get("actor_object_id")
                    for index in (2, 3))):
            return _decision(ValidationStatus.INVALID_TEST, "BATCH_PLAN_OR_AUDIT_INVALID")
        owner, actor, first, second = (observed[index] for index in range(4))
        if (owner.identity_id is None or actor.identity_id is None or
                owner.identity_id == actor.identity_id or
                first.identity_id != actor.identity_id or second.identity_id != actor.identity_id or
                owner.features.status_code != 200 or actor.features.status_code != 200):
            return _decision(ValidationStatus.INVALID_TEST, "BATCH_ACTORS_INVALID")
        with engine.evidence._connection() as db:
            rows = {name: db.execute("SELECT test_object_id,tenant_id,creator_identity_id,"
                                     "verified_at,disposable,external_id_evidence_id "
                                     "FROM test_objects WHERE test_object_id=? AND target_id=?",
                                     (object_id, target)).fetchone()
                    for name, object_id in (("foreign", shapes[0].get("test_object_id")),
                                            ("peer", shapes[0].get("owner_peer_object_id")),
                                            ("actor", shapes[0].get("actor_object_id")))}
        foreign, peer, owned = rows["foreign"], rows["peer"], rows["actor"]
        if (any(row is None or not row["verified_at"] or not row["disposable"] for row in rows.values()) or
                foreign["creator_identity_id"] != peer["creator_identity_id"] or
                foreign["creator_identity_id"] == actor.identity_id or
                owned["creator_identity_id"] != actor.identity_id or
                foreign["tenant_id"] != peer["tenant_id"] or
                foreign["tenant_id"] == owned["tenant_id"]):
            return _decision(ValidationStatus.INVALID_TEST, "BATCH_OWNERSHIP_INVALID")
        try:
            ids = {name: engine.evidence.read_content(row["external_id_evidence_id"],
                                                       allow_sensitive=True, max_bytes=256).decode("ascii")
                   for name, row in rows.items()}
        except (ValueError, UnicodeError, PermissionError):
            return _decision(ValidationStatus.INVALID_TEST, "BATCH_IDS_UNAVAILABLE")
        owner_items = self._items(self._json(owner, engine))
        actor_json = self._json(actor, engine)
        if (owner_items is None or set(owner_items) != {ids["foreign"], ids["peer"]} or
                not isinstance(actor_json, dict) or actor_json.get("id") != ids["actor"]):
            return _decision(ValidationStatus.INVALID_TEST, "BATCH_OWNER_CONTROLS_INVALID")
        object_hash = hashlib.sha256(ids["foreign"].encode()).hexdigest()
        visibility, visibility_refs = engine.fact_value(object_hash, "resource_visibility", target)
        policy, policy_refs = engine.fact_value(object_hash, "access_policy", target)
        tenant, tenant_refs = engine.fact_value(object_hash, "resource_tenant", target)
        owner_member = engine.membership(owner.identity_id, target)
        actor_member = engine.membership(actor.identity_id, target)
        relation = bool(visibility == "PRIVATE" and policy in {"TENANT_ONLY", "OWNER_ONLY"} and
                        tenant == foreign["tenant_id"] and owner_member and actor_member and
                        owner_member[0] == tenant and actor_member[0] == owned["tenant_id"] != tenant)
        checks = [_check("BATCH_OWNERSHIP", relation,
                         (*visibility_refs, *policy_refs, *tenant_refs)[:8])]
        if not relation:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "BATCH_PROTECTION_UNPROVEN", checks=tuple(checks))
        matches = []
        for candidate in (first, second):
            if candidate.features.status_code in _DENIED:
                continue
            values = self._items(self._json(candidate, engine))
            if values is None:
                return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                                 "BATCH_PER_OBJECT_READBACK_MISSING", checks=tuple(checks))
            if (candidate.features.status_code == 200 and
                    values.get(ids["foreign"]) == owner_items[ids["foreign"]]):
                matches.append(candidate)
        checks.append(_check("FOREIGN_OBJECT_RETURNED", len(matches) >= 2,
                             tuple(ref for row in matches for ref in row.evidence_ids[:2])[:8]))
        if not matches:
            return _decision(ValidationStatus.REJECTED, "BATCH_FOREIGN_OBJECT_FILTERED",
                             checks=tuple(checks))
        if len(matches) < 2:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW, "BATCH_REPRODUCTION_REQUIRED",
                             checks=tuple(checks), reproductions=len(matches))
        evidence = tuple(dict.fromkeys((
            *owner.evidence_ids, *actor.evidence_ids,
            *(ref for row in matches for ref in row.evidence_ids),
            *visibility_refs, *policy_refs, *tenant_refs)))[:64]
        finding = engine._finding(context, owner, matches[0],
                                  "BATCH_CROSS_TENANT_BOLA", "PROTECTED_OBJECT_READ")
        return _decision(ValidationStatus.CONFIRMED, "BATCH_FOREIGN_OBJECT_DISCLOSED",
                         checks=tuple(checks), controls=("OWNER_BATCH", "ACTOR_OBJECT"),
                         supporting=evidence, reproductions=len(matches),
                         impact="PROTECTED_OBJECT_READ", finding=finding)


class TypedMutationValidator:
    id = "typed_authorization_mutation"
    version = _VALIDATOR_VERSION

    def evaluate(self, context: ValidationContext, engine: DeterministicValidatorEngine) -> ValidatorDecision:
        run, target = context.run, context.run.target_id
        if len(context.plan.get("request_templates", [])) != 7:
            return _decision(ValidationStatus.INVALID_TEST, "MUTATION_PLAN_SHAPE_INVALID")
        stages = ("BEFORE_READ", "OWNER_MUTATE", "OWNER_READBACK", "BOUNDARY_MUTATE",
                  "BOUNDARY_READBACK", "RESTORE", "RESTORE_READBACK")
        templates = context.plan["request_templates"]
        if tuple(item.get("stage") for item in templates) != stages or any(
                item.get("binding") != "AUTHORIZATION_RECIPE_MUTATION_V1" for item in templates):
            return _decision(ValidationStatus.INVALID_TEST, "MUTATION_PLAN_SHAPE_INVALID")
        observations = {item.step.action_slot: item for item in context.observations}
        if set(observations) != set(range(7)) or not all(item.audit_valid for item in observations.values()):
            return _decision(ValidationStatus.INVALID_TEST, "MUTATION_AUDIT_INVALID")
        first, owner_write, owner_after, foreign_write, foreign_after, restore, restored = (
            observations[index] for index in range(7))
        if (any(item.identity_id != first.identity_id for item in
                (owner_write, owner_after, foreign_after, restore, restored)) or
                foreign_write.identity_id in {None, first.identity_id} or
                any(item.object_ref_hash != first.object_ref_hash for item in observations.values()) or
                owner_write.features.graphql_errors_present or
                first.features.status_code != 200 or owner_after.features.status_code != 200 or
                foreign_after.features.status_code != 200 or restored.features.status_code != 200):
            return _decision(ValidationStatus.INVALID_TEST, "MUTATION_ACTORS_OR_READBACK_INVALID")
        item_id = templates[0]["test_object_id"]
        with engine.evidence._connection() as db:
            row = db.execute("SELECT test_name,disposable,verified_at,creator_identity_id,"
                             "tenant_id,external_id_hash,object_type FROM test_objects "
                             "WHERE test_object_id=? AND target_id=?", (item_id, target)).fetchone()
        if (row is None or not row["disposable"] or not row["verified_at"] or
                row["creator_identity_id"] != first.identity_id):
            return _decision(ValidationStatus.INVALID_TEST, "DISPOSABLE_OWNERSHIP_INVALID")
        ledger = MutationResultStore(engine.evidence)
        control = ledger.for_phase(run.id, item_id, MutationPhase.OWNER_CONTROL)
        boundary = ledger.for_phase(run.id, item_id, MutationPhase.BOUNDARY)
        reversal = ledger.for_phase(run.id, item_id, MutationPhase.RESTORE)
        if not control or not boundary or not reversal:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "MUTATION_LEDGER_INCOMPLETE")
        linked = bool(
            control.mutation_action_id == owner_write.step.action_id and
            control.mutation_exchange_id == owner_write.exchange.id and
            control.readback_action_id == owner_after.step.action_id and
            control.readback_exchange_id == owner_after.exchange.id and
            boundary.mutation_action_id == foreign_write.step.action_id and
            boundary.mutation_exchange_id == foreign_write.exchange.id and
            boundary.readback_action_id == foreign_after.step.action_id and
            boundary.readback_exchange_id == foreign_after.exchange.id and
            reversal.mutation_action_id == restore.step.action_id and
            reversal.mutation_exchange_id == restore.exchange.id and
            reversal.readback_action_id == restored.step.action_id and
            reversal.readback_exchange_id == restored.exchange.id and
            all(entry.recipe_hash == templates[0]["recipe_hash"] for entry in
                (control, boundary, reversal)))
        checks = [_check("AUDIT_CHAIN", linked,
                         tuple(ref for item in observations.values() for ref in item.evidence_ids[:1])[:8]),
                  _check("OWNER_CONTROL_READBACK", control.verified_effect,
                         control.evidence_ids[:4]),
                  _check("BOUNDARY_READBACK", boundary.readback_exchange_id is not None,
                         boundary.evidence_ids[:4]),
                  _check("RESTORE_READBACK", reversal.verified_effect,
                         reversal.evidence_ids[:4])]
        if not linked or not control.verified_effect:
            return _decision(ValidationStatus.INVALID_TEST, "MUTATION_CONTROL_INVALID",
                             checks=tuple(checks))
        if boundary.status is MutationStatus.INSUFFICIENT_EVIDENCE:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW, "BOUNDARY_READBACK_INCONCLUSIVE",
                             checks=tuple(checks))
        if not reversal.verified_effect:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW, "RESTORE_UNVERIFIED",
                             checks=tuple(checks))
        object_hash = first.object_ref_hash
        visibility, vis_refs = engine.fact_value(object_hash, "resource_visibility", target)
        policy, policy_refs = engine.fact_value(object_hash, "access_policy", target)
        tenant, tenant_refs = engine.fact_value(object_hash, "resource_tenant", target)
        owner_member = engine.membership(first.identity_id, target)
        foreign_member = engine.membership(foreign_write.identity_id, target)
        hypothesis = engine.hypotheses.get(run.hypothesis_id, target)
        relation = False
        extra_refs: tuple[str, ...] = ()
        if visibility == "PRIVATE" and policy and tenant and owner_member and foreign_member and hypothesis:
            if hypothesis.category in {"CROSS_TENANT", "GRAPHQL_MUTATION"}:
                relation = bool(owner_member[0] == tenant and foreign_member[0] != tenant and
                                policy in {"TENANT_ONLY", "OWNER_ONLY"})
            elif hypothesis.category == "HORIZONTAL":
                owner_principal = engine.principal(first.identity_id, target)
                foreign_principal = engine.principal(foreign_write.identity_id, target)
                resource_owner, owner_refs = engine.fact_value(object_hash, "resource_owner", target)
                relation = bool(policy == "OWNER_ONLY" and owner_member[0] == foreign_member[0] == tenant and
                                owner_principal and foreign_principal and
                                owner_principal[0] != foreign_principal[0] and
                                resource_owner == owner_principal[0])
                extra_refs = owner_refs
            elif hypothesis.category in {"VERTICAL", "HIDDEN_FUNCTION"}:
                restriction, restriction_refs = engine.fact_value(object_hash, "required_role", target)
                relation = bool(policy == "ROLE_RESTRICTED" and
                                owner_member[0] == foreign_member[0] == tenant and
                                restriction and restriction in owner_member[1] and
                                restriction not in foreign_member[1])
                extra_refs = restriction_refs
        checks.append(_check("PERMISSION_EXPECTATION", relation,
                             (*vis_refs, *policy_refs, *tenant_refs, *extra_refs)[:8]))
        if not relation:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "MUTATION_BOUNDARY_UNPROVEN",
                             checks=tuple(checks))
        state_chain = bool(control.before_value_hash == value_hash(row["test_name"]) and
                           boundary.before_value_hash == control.after_value_hash and
                           reversal.before_value_hash == (
                               boundary.after_value_hash if boundary.verified_effect else
                               control.after_value_hash) and
                           reversal.after_value_hash == control.before_value_hash and
                           first.features.request_method == "GET" and
                           owner_after.features.request_method == "GET" and
                           foreign_after.features.request_method == "GET" and
                           restored.features.request_method == "GET")
        checks.append(_check("STATE_CHAIN", state_chain,
                             (*control.evidence_ids[:2], *boundary.evidence_ids[:2],
                              *reversal.evidence_ids[:2])))
        if not state_chain:
            return _decision(ValidationStatus.INVALID_TEST, "MUTATION_STATE_CHAIN_INVALID",
                             checks=tuple(checks))
        if boundary.status is MutationStatus.DENIED:
            return _decision(ValidationStatus.REJECTED, "BOUNDARY_MUTATION_DENIED",
                             checks=tuple(checks), controls=("OWNER_CONTROL", "OWNER_READBACK",
                                                              "FOREIGN_READBACK", "RESTORE_READBACK"),
                             contradicting=boundary.evidence_ids[:8])
        checks.append(_check("UNAUTHORIZED_DURABLE_EFFECT", boundary.verified_effect,
                             boundary.evidence_ids[:4]))
        if not boundary.verified_effect:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW, "BOUNDARY_EFFECT_UNPROVEN",
                             checks=tuple(checks))
        supporting = tuple(dict.fromkeys((
            *(ref for entry in (control, boundary, reversal) for ref in entry.evidence_ids),
            *vis_refs, *policy_refs, *tenant_refs, *extra_refs,
            *owner_member[2], *foreign_member[2])))[:64]
        finding = engine._finding(context, first, foreign_write,
                                  "AUTHORIZATION_MUTATION", "UNAUTHORIZED_STATE_CHANGE")
        return _decision(ValidationStatus.CONFIRMED, "UNAUTHORIZED_MUTATION_READBACK",
                         checks=tuple(checks), controls=("OWNER_CONTROL", "OWNER_READBACK",
                                                          "FOREIGN_READBACK", "RESTORE_READBACK"),
                         supporting=supporting, reproductions=1,
                         impact="UNAUTHORIZED_STATE_CHANGE", finding=finding)


class GraphQLValidator:
    version = _VALIDATOR_VERSION
    id = "graphql_authorization"

    def __init__(self, mutation: bool) -> None:
        self.mutation = mutation

    @staticmethod
    def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("ambiguous duplicate JSON key")
            value[key] = item
        return value

    @staticmethod
    def _object_state(item: Observation, engine: DeterministicValidatorEngine,
                      object_hash: str) -> tuple[str, str] | None:
        response = item.exchange.response
        evidence_id = response.body_evidence_id if response else None
        record = engine.evidence.get_evidence(evidence_id) if evidence_id else None
        if (record is None or record.target_ref != item.exchange.target_id or
                record.redaction_status.value != "ORIGINAL" or record.content_size > 262144):
            return None
        try:
            raw = engine.evidence.read_content(evidence_id, allow_sensitive=True,
                                               max_bytes=262144)
            if hashlib.sha256(raw).hexdigest() != response.body_hash:
                return None
            data = json.loads(raw, object_pairs_hook=GraphQLValidator._unique_pairs)
            if (not isinstance(data, dict) or not isinstance(data.get("id"), str) or
                    not isinstance(data.get("name"), str) or
                    _digest(data["id"]) != object_hash):
                return None
            return data["id"], data["name"]
        except (TypeError, ValueError, UnicodeError, PermissionError):
            return None

    def _evaluate_mutation(self, context: ValidationContext,
                           engine: DeterministicValidatorEngine) -> ValidatorDecision:
        control, boundaries, negative = engine._controls(context)
        checks = list(engine._base_checks(control, boundaries, negative))
        readbacks = tuple(item for item in context.observations if item.step.role == "OTHER" and
                          item.step.action_slot is not None and
                          context.plan["proposed_actions"][item.step.action_slot].get("control_kind")
                          == "POST_READBACK")
        if (control is None or checks[0].outcome is CheckOutcome.FAIL or len(boundaries) != 1 or
                len(negative) != 1 or len(readbacks) != 1):
            return _decision(ValidationStatus.INVALID_TEST, "MUTATION_CONTROLS_MISSING",
                             checks=tuple(checks))
        boundary, invalid, after = boundaries[0], negative[0], readbacks[0]
        if not all(item.audit_valid for item in (control, boundary, invalid, after)):
            return _decision(ValidationStatus.INVALID_TEST, "MUTATION_AUDIT_INVALID",
                             checks=tuple(checks))
        if not (control.step.ordinal < invalid.step.ordinal < boundary.step.ordinal <
                after.step.ordinal):
            return _decision(ValidationStatus.INVALID_TEST, "MUTATION_SEQUENCE_INVALID",
                             checks=tuple(checks))
        semantic_negative = bool(invalid.features.graphql_errors_present and
                                 not invalid.features.graphql_data_present)
        checks[2] = _check("NEGATIVE_CONTROL", semantic_negative, invalid.evidence_ids[:2])
        if not semantic_negative:
            return _decision(ValidationStatus.INVALID_TEST, "NEGATIVE_CONTROL_FAILED",
                             checks=tuple(checks))
        if boundary.features.graphql_errors_present or not boundary.features.graphql_data_present:
            return _decision(ValidationStatus.REJECTED, "GRAPHQL_BOUNDARY_DENIED",
                             checks=tuple(checks), contradicting=boundary.evidence_ids[:3])
        object_hash = control.object_ref_hash
        if (not object_hash or any(item.object_ref_hash != object_hash
                                   for item in (boundary, invalid, after)) or
                control.features.request_method != "GET" or
                after.features.request_method != "GET" or
                boundary.features.request_method != "POST" or
                control.identity_id != after.identity_id or
                control.identity_id == boundary.identity_id or
                any(item.features.status_code is None or
                    not 200 <= item.features.status_code < 300
                    for item in (control, boundary, after)) or
                not engine.comparator.compare(control.features, after.features).same_request_path):
            return _decision(ValidationStatus.INVALID_TEST, "MUTATION_BINDING_INVALID",
                             checks=tuple(checks))
        target = context.run.target_id
        visibility, vis_refs = engine.fact_value(object_hash, "resource_visibility", target)
        tenant, tenant_refs = engine.fact_value(object_hash, "resource_tenant", target)
        policy, policy_refs = engine.fact_value(object_hash, "access_policy", target)
        operation, op_refs = engine.fact_value(object_hash, "graphql_operation", target)
        first = engine.membership(control.identity_id, target)
        second = engine.membership(boundary.identity_id, target)
        relation = bool(visibility == "PRIVATE" and tenant and first and second and
                        first[0] == tenant and second[0] != tenant and
                        policy in {"TENANT_ONLY", "OWNER_ONLY"} and
                        operation and operation == boundary.operation)
        checks.append(_check("MUTATION_BOUNDARY", relation,
                             (*vis_refs, *tenant_refs, *policy_refs, *op_refs)[:8]))
        if not relation:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "MUTATION_BOUNDARY_UNPROVEN",
                             checks=tuple(checks))
        before_state = self._object_state(control, engine, object_hash)
        after_state = self._object_state(after, engine, object_hash)
        request_ref = boundary.exchange.request.body_evidence_id
        request_record = engine.evidence.get_evidence(request_ref) if request_ref else None
        desired = None
        if (request_record is not None and request_record.target_ref == target and
                request_record.redaction_status.value == "ORIGINAL" and
                request_record.content_size <= 8192):
            try:
                raw = engine.evidence.read_content(request_ref, allow_sensitive=True, max_bytes=8192)
                if hashlib.sha256(raw).hexdigest() == boundary.exchange.request.body_hash:
                    variables = json.loads(
                        raw, object_pairs_hook=self._unique_pairs)["variables"]
                    changes = {key: value for key, value in variables.items()
                               if key in {"name", "newName"}}
                    if len(changes) == 1:
                        desired = next(iter(changes.values()))
            except (KeyError, TypeError, ValueError, UnicodeError, PermissionError):
                pass
        changed = bool(before_state and after_state and isinstance(desired, str) and
                       before_state[1] != desired and after_state[1] == desired and
                       before_state[0] == after_state[0] and
                       object_hash in boundary.features.object_id_hashes)
        checks.append(_check("SIDE_EFFECT_READBACK", changed,
                             (*control.evidence_ids[:2], *boundary.evidence_ids[:2],
                              *after.evidence_ids[:2])))
        if not changed:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "NO_ATTESTED_SIDE_EFFECT_READBACK", checks=tuple(checks))
        evidence = tuple(dict.fromkeys((*control.evidence_ids[:3],
                                         *boundary.evidence_ids[:3], *after.evidence_ids[:3],
                                         *invalid.evidence_ids[:2], *vis_refs, *tenant_refs,
                                         *policy_refs, *op_refs, *first[2], *second[2])))[:64]
        finding = engine._finding(context, control, boundary, "GRAPHQL_AUTHORIZATION",
                                  "GRAPHQL_UNAUTHORIZED_STATE_CHANGE", operation)
        return _decision(ValidationStatus.CONFIRMED, "GRAPHQL_MUTATION_DURABLE_EFFECT",
                         checks=tuple(checks), controls=("OWNER_BEFORE", "INVALID_OBJECT",
                                                        "OWNER_AFTER"), supporting=evidence,
                         reproductions=1, impact="GRAPHQL_UNAUTHORIZED_STATE_CHANGE",
                         finding=finding)

    def evaluate(self, context: ValidationContext, engine: DeterministicValidatorEngine) -> ValidatorDecision:
        if self.mutation:
            return self._evaluate_mutation(context, engine)
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
                                  "GRAPHQL_PROTECTED_OBJECT_READ", operation)
        return _decision(ValidationStatus.CONFIRMED, "GRAPHQL_PROTECTED_BOUNDARY",
                         checks=tuple(checks), controls=("OWNER_CONTROL", "INVALID_OBJECT"),
                         supporting=evidence, reproductions=len(matches),
                         impact="GRAPHQL_PROTECTED_OBJECT_READ", finding=finding)


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
