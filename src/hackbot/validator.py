"""Deterministic, read-only judgment of completed investigation runs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import uuid
from typing import Protocol
from urllib.parse import parse_qsl, unquote, urlsplit

from .domain import ObservationState
from .evidence import EvidenceType, Fact, FactStatus, RedactionStatus, Retention
from .domxss_static import DOMCandidateStatus
from .api_registry import APICandidate, APIOperation, APIOperationRegistry, APIOperationType
from .api_graphql import (encode_observed_global_id, graphql_batch_values,
                          observed_field_selection_pair,
                          nested_child_values)
from .domxss_store import DOMXSSStore
from .exposure import ExposureSpecialist
from .exposure_models import ExposureSource, ExposureStatus
from .exposure_static import MAX_JS_SCAN_BYTES, MAX_MAP_SCAN_BYTES
from .postmessage_static import MessageCandidateStatus
from .postmessage_browser import (PostMessageBrowserExperimentExecutor,
                                  lookalike_origin, verified_owned_canary)
from .postmessage_store import PostMessageStore
from .hypotheses import HypothesisStore
from .identity import MembershipStatus
from .identity_registry import IdentityRegistry
from .mutation_results import MutationResultStore, MutationStatus, value_hash
from .typed_mutations import MutationPhase
from .plan_runs import PlanRun, PlanRunStore, RunStatus, RuntimeStep, RuntimeStepStatus
from .response_compare import ResponseComparator, ResponseFeatures
from .store import EvidenceFactStore
from .target_loader import TargetPackageRepository
from .target_scope import ScopeResult
from .traffic import AuthState, ExchangeState, TrafficExchange, TrafficStore
from .test_objects import ObjectRegistry, ObjectState
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
_EXPOSURE_SKILLS.add("credential-disclosure")
_EXPOSURE_SKILLS.add("internal-vhost-access")
_EXPOSURE_SKILLS.add("protected-response-exposure")
_EXPOSURE_SKILLS.add("overexposed-api-response")
_CLIENT_SKILLS = {"check-before-transform-dom-xss", "postmessage-trust-analysis"}
_KINDS = {**{skill: "AUTHORIZATION" for skill in _AUTH_SKILLS},
          **{skill: "GRAPHQL" for skill in _GRAPHQL_SKILLS},
          **{skill: "EXPOSURE" for skill in _EXPOSURE_SKILLS},
          **{skill: "CLIENT_SIDE" for skill in _CLIENT_SKILLS},
          "internal-surface-candidate": "INTERNAL_SURFACE"}
_KINDS["batch-object-authorization"] = "AUTHORIZATION"
_KINDS["api-observed-read"] = "API"
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
    "credential-disclosure": {"current_artifact", "credential_semantics", "public_by_design_check"},
    "internal-vhost-access": {"scope_review", "current_reachability", "protected_effect"},
    "protected-response-exposure": {"current_response", "credential_semantics",
                                    "public_by_design_check"},
    "overexposed-api-response": {"field_policy", "owner_control", "role_boundary"},
    "check-before-transform-dom-xss": {"browser_execution", "source_sink_trace"},
    "postmessage-trust-analysis": {"origin_control", "capability_proof"},
    "internal-surface-candidate": {"scope_review", "current_reachability"},
    "typed-authorization-mutation": {"ownership_matrix", "state_readback", "restore_readback"},
    "api-observed-read": {"api_semantic_data", "ownership_matrix", "negative_control"},
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
            self._items[name] = (ExposureArtifactValidator() if name == "credential-disclosure"
                                 else ExposureVHostValidator() if name == "internal-vhost-access"
                                 else ExposureHttpValidator() if name == "protected-response-exposure"
                                 else ExposureFieldValidator() if name == "overexposed-api-response"
                                 else ExposureValidator(name == "sensitive-data-exposure"))
        for name in _CLIENT_SKILLS:
            self._items[name] = (DOMXSSValidator() if name == "check-before-transform-dom-xss"
                                 else PostMessageValidator())
        self._items["internal-surface-candidate"] = InternalSurfaceValidator()
        self._items["typed-authorization-mutation"] = TypedMutationValidator()
        self._items["batch-object-authorization"] = BatchReadValidator()
        self._items["api-observed-read"] = APIReadValidator()

    def select(self, skill_id: str) -> Validator | None:
        return self._items.get(skill_id)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._items))


class DeterministicValidatorEngine:
    def __init__(self, *, runs: PlanRunStore, traffic: TrafficStore,
                 evidence: EvidenceFactStore, identities: IdentityRegistry,
                 hypotheses: HypothesisStore, results: ValidationStore,
                 registry: ValidatorRegistry | None = None,
                 dom: DOMXSSStore | None = None,
                 messages: PostMessageStore | None = None,
                 targets: TargetPackageRepository | None = None,
                 exposure: ExposureSpecialist | None = None,
                 api_operations: APIOperationRegistry | None = None) -> None:
        self.runs, self.traffic, self.evidence = runs, traffic, evidence
        self.identities, self.hypotheses, self.results = identities, hypotheses, results
        self.registry = registry or ValidatorRegistry()
        self.comparator = ResponseComparator(evidence)
        self.dom = dom
        self.messages = messages
        self.targets = targets
        self.exposure = exposure
        self.api_operations = api_operations

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
            if step.type == "VERIFY_BROWSER":
                result = self.runs.result(step.id)
                snap_parts.append(step.id + ":" + (result.id if result else "MISSING"))
                if result:
                    for ref in result.evidence_ids:
                        item = self.evidence.get_evidence(ref)
                        snap_parts.append(ref + ":" + (item.content_hash if item else "MISSING"))
                continue
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
        recorded, finding = self.results.record(result, decision.finding)
        if self.api_operations is not None and run.skill_id == "api-observed-read":
            frozen = context.plan.get("api_binding")
            candidate = (self.api_operations.get_candidate(
                run.target_id, frozen["candidate_id"]) if
                isinstance(frozen, dict) and isinstance(frozen.get("candidate_id"), str)
                else None)
            if candidate is not None and candidate.plan_id == run.plan_id:
                self.api_operations.link_candidate(
                    run.target_id, candidate.id,
                    status="VALIDATED" if recorded.status is ValidationStatus.CONFIRMED else
                    "REJECTED" if recorded.status is ValidationStatus.REJECTED else "REVIEW",
                    run_id=run.id, validation_id=recorded.id)
        if self.dom is not None and run.skill_id == "check-before-transform-dom-xss":
            binding = context.plan.get("dom_binding")
            if isinstance(binding, dict) and isinstance(binding.get("candidate_id"), str):
                self.dom.bind_validation(run.target_id, binding["candidate_id"],
                                         run.id, recorded.id)
                if recorded.status is ValidationStatus.CONFIRMED and finding is not None:
                    for ref in recorded.supporting_evidence_ids:
                        self.evidence.set_retention(
                            ref, Retention(retain=True, pinned=True, finding_related=True),
                            actor="dom_xss_validator", reason="confirmed_dom_xss_finding")
        if self.messages is not None and run.skill_id == "postmessage-trust-analysis":
            binding = context.plan.get("message_binding")
            if isinstance(binding, dict) and isinstance(binding.get("candidate_id"), str):
                self.messages.bind_validation(run.target_id, binding["candidate_id"],
                                              run.id, recorded.id)
                if recorded.status is ValidationStatus.CONFIRMED and finding is not None:
                    for ref in recorded.supporting_evidence_ids:
                        self.evidence.set_retention(
                            ref, Retention(retain=True, pinned=True, finding_related=True),
                            actor="postmessage_validator", reason="confirmed_message_finding")
        if self.exposure is not None and run.skill_id in _EXPOSURE_SKILLS:
            candidate_id = self.exposure.store.candidate_for_plan(run.target_id, run.plan_id)
            if candidate_id is not None:
                self.exposure.store.bind_validation(run.target_id, candidate_id,
                                                    run.id, recorded.id)
                if recorded.status is ValidationStatus.CONFIRMED and finding is not None:
                    for ref in recorded.supporting_evidence_ids:
                        self.evidence.set_retention(
                            ref, Retention(retain=True, pinned=True, finding_related=True),
                            actor="exposure_validator", reason="confirmed_credential_exposure")
        return recorded, finding

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
        if (context.plan.get("request_templates") and
                context.plan["request_templates"][0].get("mutation_type") == "DELETE_DISPOSABLE"):
            return self._evaluate_delete(context, engine)
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
            row = db.execute("SELECT test_object_id,test_name,disposable,verified_at,creator_identity_id,"
                             "tenant_id,external_id_hash,external_id_evidence_id,object_type,"
                             "parent_test_object_id FROM test_objects "
                             "WHERE test_object_id=? AND target_id=?", (item_id, target)).fetchone()
        if (row is None or not row["disposable"] or not row["verified_at"] or
                row["creator_identity_id"] != first.identity_id):
            return _decision(ValidationStatus.INVALID_TEST, "DISPOSABLE_OWNERSHIP_INVALID")
        nested_refs: tuple[str, ...] = ()
        if "parent_object_id" in templates[0]:
            parent_id = templates[0].get("parent_object_id")
            foreign_parent_id = templates[0].get("foreign_parent_object_id")
            if (not isinstance(parent_id, str) or not isinstance(foreign_parent_id, str) or
                    len({item_id, parent_id, foreign_parent_id}) != 3 or
                    any(item.get("parent_object_id") != parent_id or
                        item.get("foreign_parent_object_id") != foreign_parent_id
                        for item in templates) or row["parent_test_object_id"] != parent_id):
                return _decision(ValidationStatus.INVALID_TEST, "NESTED_MUTATION_SHAPE_INVALID")
            with engine.evidence._connection() as db:
                parents = [db.execute(
                    "SELECT test_object_id,target_id,tenant_id,creator_identity_id,"
                    "object_type,disposable,verified_at,external_id_hash,"
                    "external_id_evidence_id FROM test_objects WHERE test_object_id=?",
                    (parent_ref,)).fetchone() for parent_ref in (parent_id, foreign_parent_id)]
            if (any(parent is None for parent in parents) or
                    any(parent["target_id"] != target or
                        not parent["disposable"] or not parent["verified_at"] or
                        parent["object_type"] != parents[0]["object_type"]
                        for parent in parents) or
                    parents[0]["tenant_id"] != row["tenant_id"] or
                    parents[0]["creator_identity_id"] != first.identity_id or
                    parents[1]["tenant_id"] == row["tenant_id"] or
                    parents[1]["creator_identity_id"] != foreign_write.identity_id):
                return _decision(ValidationStatus.INVALID_TEST, "NESTED_MUTATION_PARENTS_INVALID")
            refs: list[str] = []
            for parent in parents:
                for predicate, value in (("created_by", parent["creator_identity_id"]),
                                         ("resource_tenant", parent["tenant_id"]),
                                         ("disposable", "true")):
                    facts = engine.evidence.find_facts(parent["test_object_id"],
                                                       predicate, limit=8).items
                    trusted = next((fact for fact in facts if fact.target_ref == target and
                                    fact.status is FactStatus.ACTIVE and fact.source != "MANUAL" and
                                    fact.confidence >= 0.9 and fact.object == value and
                                    fact.evidence_ids), None)
                    if trusted is None:
                        return _decision(ValidationStatus.INVALID_TEST,
                                         "NESTED_MUTATION_PARENT_FACTS_INVALID")
                    refs.extend(trusted.evidence_ids[:2])
            try:
                object_rows = (row, *parents)
                external_ids = []
                for object_row in object_rows:
                    external = engine.evidence.read_content(
                        object_row["external_id_evidence_id"], allow_sensitive=True,
                        max_bytes=256).decode("ascii")
                    if hashlib.sha256((object_row["test_object_id"] + ":" + external).encode()).hexdigest() != object_row["external_id_hash"]:
                        raise ValueError
                    external_ids.append(external)
                for observation, expected_parent in ((owner_write, external_ids[1]),
                                                     (foreign_write, external_ids[2]),
                                                     (restore, external_ids[1])):
                    request = observation.exchange.request
                    raw = engine.evidence.read_content(request.body_evidence_id,
                                                       allow_sensitive=True, max_bytes=8192)
                    if hashlib.sha256(raw).hexdigest() != request.body_hash:
                        raise ValueError
                    payload = json.loads(raw, object_pairs_hook=GraphQLValidator._unique_pairs)
                    variables = payload.get("variables") if isinstance(payload, dict) else None
                    if (not isinstance(variables, dict) or
                            set(variables) != {"parentId", "id", "name"} or
                            variables["id"] != external_ids[0] or
                            variables["parentId"] != expected_parent):
                        raise ValueError
                    if request.body_evidence_id:
                        refs.append(request.body_evidence_id)
            except (AttributeError, KeyError, TypeError, ValueError, UnicodeError,
                    PermissionError):
                return _decision(ValidationStatus.INVALID_TEST,
                                 "NESTED_MUTATION_TRAFFIC_INVALID")
            nested_refs = tuple(dict.fromkeys(refs))[:16]
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
        if nested_refs:
            checks.append(_check("NESTED_PARENT_CHILD_BINDING", True, nested_refs[:8]))
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
            *vis_refs, *policy_refs, *tenant_refs, *extra_refs, *nested_refs,
            *owner_member[2], *foreign_member[2])))[:64]
        finding = engine._finding(context, first, foreign_write,
                                  "AUTHORIZATION_MUTATION", "UNAUTHORIZED_STATE_CHANGE")
        return _decision(ValidationStatus.CONFIRMED, "UNAUTHORIZED_MUTATION_READBACK",
                         checks=tuple(checks), controls=("OWNER_CONTROL", "OWNER_READBACK",
                                                          "FOREIGN_READBACK", "RESTORE_READBACK"),
                         supporting=supporting, reproductions=1,
                         impact="UNAUTHORIZED_STATE_CHANGE", finding=finding)

    def _evaluate_delete(self, context: ValidationContext,
                         engine: DeterministicValidatorEngine) -> ValidatorDecision:
        run, target = context.run, context.run.target_id
        stages = ("BEFORE_READ", "OWNER_MUTATE", "OWNER_READBACK",
                  "TARGET_BEFORE_READ", "BOUNDARY_MUTATE", "BOUNDARY_READBACK",
                  "RESTORE", "RESTORE_READBACK")
        templates = context.plan.get("request_templates", [])
        if (len(templates) != 8 or
                tuple(item.get("stage") for item in templates) != stages or
                any(item.get("binding") != "AUTHORIZATION_RECIPE_MUTATION_V1" or
                    item.get("mutation_type") != "DELETE_DISPOSABLE" or
                    item.get("recipe_hash") != templates[0].get("recipe_hash") or
                    item.get("test_object_id") != templates[0].get("test_object_id") or
                    item.get("delete_control_object_id") != templates[0].get("delete_control_object_id") or
                    "parent_object_id" in item for item in templates)):
            return _decision(ValidationStatus.INVALID_TEST, "DELETE_PLAN_SHAPE_INVALID")
        control_id = templates[0].get("delete_control_object_id")
        target_id = templates[0].get("test_object_id")
        if not isinstance(control_id, str) or not isinstance(target_id, str) or control_id == target_id:
            return _decision(ValidationStatus.INVALID_TEST, "DELETE_OBJECT_PAIR_INVALID")
        observations = {item.step.action_slot: item for item in context.observations}
        restore_step = next((item for item in engine.runs.steps(run.id)
                             if item.action_slot == 6), None)
        skipped_cleanup = bool(restore_step is not None and
                               restore_step.status is RuntimeStepStatus.COMPLETED and
                               restore_step.safe_reason == "DELETE_ALREADY_ABSENT" and
                               engine.runs.result(restore_step.id) is not None and
                               not engine.runs.result(restore_step.id).exchange_ids)
        expected_slots = set(range(8)) - ({6} if skipped_cleanup else set())
        if (set(observations) != expected_slots or
                not all(item.audit_valid for item in observations.values())):
            return _decision(ValidationStatus.INVALID_TEST, "DELETE_AUDIT_INVALID")
        first, owner_write, owner_after, target_before, foreign_write, foreign_after, final = (
            observations[index] for index in (0, 1, 2, 3, 4, 5, 7))
        cleanup = observations.get(6)
        if (any(item.identity_id != first.identity_id for item in
                (owner_write, owner_after, target_before, foreign_after, final,
                 *((cleanup,) if cleanup else ()))) or
                foreign_write.identity_id in {None, first.identity_id} or
                any(item.features.request_method != "GET" for item in
                    (first, owner_after, target_before, foreign_after, final)) or
                any(item.features.request_method != "DELETE" for item in
                    (owner_write, foreign_write, *((cleanup,) if cleanup else ()))) or
                first.features.status_code != 200 or
                owner_write.features.status_code not in {200, 202, 204} or
                owner_after.features.status_code not in {404, 410} or
                target_before.features.status_code != 200 or
                foreign_after.features.status_code not in {200, 404, 410} or
                final.features.status_code not in {404, 410} or
                first.object_ref_hash is None or target_before.object_ref_hash is None or
                any(item.object_ref_hash != first.object_ref_hash for item in
                    (owner_write, owner_after)) or
                any(item.object_ref_hash != target_before.object_ref_hash for item in
                    (foreign_write, foreign_after, final,
                     *((cleanup,) if cleanup else ()))) or
                first.object_ref_hash == target_before.object_ref_hash):
            return _decision(ValidationStatus.INVALID_TEST, "DELETE_ACTORS_OR_READBACK_INVALID")
        with engine.evidence._connection() as db:
            rows = [db.execute(
                "SELECT test_object_id,package_id,disposable,verified_at,creator_identity_id,"
                "tenant_id,object_type,parent_test_object_id,recipe_id,recipe_hash,"
                "external_id_hash,external_id_evidence_id FROM test_objects "
                "WHERE test_object_id=? AND target_id=?", (object_id, target)).fetchone()
                for object_id in (control_id, target_id)]
        control_row, target_row = rows
        if (any(row is None or not row["disposable"] or not row["verified_at"] or
                not row["external_id_evidence_id"] or row["creator_identity_id"] != first.identity_id or
                row["package_id"] != run.package_id or row["recipe_hash"] != templates[0]["recipe_hash"]
                for row in rows) or
                any(control_row[key] != target_row[key] for key in
                    ("tenant_id", "object_type", "parent_test_object_id", "recipe_id"))):
            return _decision(ValidationStatus.INVALID_TEST, "DELETE_DISPOSABLE_OWNERSHIP_INVALID")
        try:
            external_ids = [engine.evidence.read_content(
                row["external_id_evidence_id"], allow_sensitive=True,
                max_bytes=256).decode("ascii") for row in rows]
            if any(_digest(row["test_object_id"] + ":" + value) != row["external_id_hash"]
                   for row, value in zip(rows, external_ids)):
                raise ValueError
            for observation, external in ((first, external_ids[0]),
                                          (target_before, external_ids[1])):
                if _digest(external) not in observation.features.object_id_hashes:
                    raise ValueError
            urls = {}
            for slot, observation in observations.items():
                record = engine.evidence.get_evidence(
                    observation.exchange.request.observation_evidence_id)
                if record is None or record.target_ref != target:
                    raise ValueError
                payload = json.loads(engine.evidence.read_content(
                    record.evidence_id, allow_sensitive=True, max_bytes=8192))
                urls[slot] = payload["url"]
            if (len({urls[slot] for slot in (0, 1, 2)}) != 1 or
                    len({urls[slot] for slot in expected_slots - {0, 1, 2}}) != 1 or
                    urls[0] == urls[3] or
                    urlsplit(urls[0]).path.split("/")[-1] != external_ids[0] or
                    urlsplit(urls[3]).path.split("/")[-1] != external_ids[1]):
                raise ValueError
        except (KeyError, TypeError, ValueError, UnicodeError, PermissionError):
            return _decision(ValidationStatus.INVALID_TEST, "DELETE_OBJECT_TRAFFIC_INVALID")
        ledger = MutationResultStore(engine.evidence)
        owner = ledger.for_phase(run.id, control_id, MutationPhase.OWNER_CONTROL)
        boundary = ledger.for_phase(run.id, target_id, MutationPhase.BOUNDARY)
        reversal = ledger.for_phase(run.id, target_id, MutationPhase.RESTORE)
        if owner is None or boundary is None or (reversal is None and not skipped_cleanup):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "DELETE_LEDGER_INCOMPLETE")
        linked_entries = [(owner, owner_write, owner_after),
                          (boundary, foreign_write, foreign_after)]
        if cleanup is not None and reversal is not None:
            linked_entries.append((reversal, cleanup, final))
        linked = all((entry.mutation_action_id == write.step.action_id and
                      entry.mutation_exchange_id == write.exchange.id and
                      entry.readback_action_id == read.step.action_id and
                      entry.readback_exchange_id == read.exchange.id and
                      entry.mutation_type.value == "DELETE_DISPOSABLE" and
                      entry.recipe_hash == templates[0]["recipe_hash"])
                     for entry, write, read in linked_entries)
        if skipped_cleanup and reversal is not None:
            linked = False
        expected_present, expected_absent = value_hash("present"), value_hash("absent")
        state_chain = (owner.before_value_hash == expected_present and
                       owner.after_value_hash == expected_absent and owner.verified_effect and
                       boundary.before_value_hash == expected_present and
                       boundary.after_value_hash in {expected_present, expected_absent} and
                       ((skipped_cleanup and boundary.verified_effect and
                         boundary.after_value_hash == expected_absent) or
                        (reversal is not None and
                         reversal.before_value_hash == boundary.after_value_hash and
                         reversal.after_value_hash == expected_absent and
                         ((boundary.status is MutationStatus.VERIFIED and
                           reversal.status is MutationStatus.DENIED) or
                          (boundary.status is MutationStatus.DENIED and
                           reversal.status is MutationStatus.VERIFIED)))))
        checks = (_check("DELETE_AUDIT_CHAIN", linked,
                         tuple(ref for item in observations.values() for ref in item.evidence_ids[:1])[:8]),
                  _check("OWNER_DELETE_CONTROL", owner.verified_effect, owner.evidence_ids[:4]),
                  _check("TARGET_PRESENT_BEFORE_BOUNDARY", True, target_before.evidence_ids[:4]),
                  _check("BOUNDARY_DELETE_READBACK", boundary.readback_exchange_id is not None,
                         boundary.evidence_ids[:4]),
                  _check("TARGET_ABSENT_AFTER_CLEANUP", state_chain,
                         reversal.evidence_ids[:4] if reversal else final.evidence_ids[:4]))
        if not linked or not state_chain:
            return _decision(ValidationStatus.INVALID_TEST, "DELETE_STATE_CHAIN_INVALID",
                             checks=checks)
        for row in rows:
            for predicate, value in (("created_by", row["creator_identity_id"]),
                                     ("resource_tenant", row["tenant_id"]),
                                     ("disposable", "true")):
                facts = engine.evidence.find_facts(row["test_object_id"], predicate, limit=8).items
                if not any(fact.target_ref == target and fact.status is FactStatus.ACTIVE and
                           fact.source != "MANUAL" and fact.confidence >= 0.9 and
                           fact.evidence_ids and fact.object == value for fact in facts):
                    return _decision(ValidationStatus.INVALID_TEST, "DELETE_OBJECT_FACTS_INVALID",
                                     checks=checks)
        visibility, vis_refs = engine.fact_value(target_before.object_ref_hash,
                                                 "resource_visibility", target)
        policy, policy_refs = engine.fact_value(target_before.object_ref_hash,
                                                "access_policy", target)
        tenant, tenant_refs = engine.fact_value(target_before.object_ref_hash,
                                                "resource_tenant", target)
        owner_member = engine.membership(first.identity_id, target)
        foreign_member = engine.membership(foreign_write.identity_id, target)
        hypothesis = engine.hypotheses.get(run.hypothesis_id, target)
        relation = False
        if (visibility == "PRIVATE" and policy and tenant and owner_member and
                foreign_member and hypothesis):
            if hypothesis.category == "CROSS_TENANT":
                relation = (owner_member[0] == tenant and foreign_member[0] != tenant and
                            policy in {"TENANT_ONLY", "OWNER_ONLY"})
            elif hypothesis.category == "HORIZONTAL":
                owner_principal = engine.principal(first.identity_id, target)
                foreign_principal = engine.principal(foreign_write.identity_id, target)
                resource_owner, _ = engine.fact_value(target_before.object_ref_hash,
                                                      "resource_owner", target)
                relation = bool(policy == "OWNER_ONLY" and
                                owner_member[0] == foreign_member[0] == tenant and
                                owner_principal and foreign_principal and
                                owner_principal[0] != foreign_principal[0] and
                                resource_owner == owner_principal[0])
            elif hypothesis.category in {"VERTICAL", "HIDDEN_FUNCTION"}:
                role, _ = engine.fact_value(target_before.object_ref_hash,
                                            "required_role", target)
                relation = bool(policy == "ROLE_RESTRICTED" and
                                owner_member[0] == foreign_member[0] == tenant and
                                role and role in owner_member[1] and
                                role not in foreign_member[1])
        if not relation:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "DELETE_BOUNDARY_UNPROVEN", checks=checks)
        if boundary.status is MutationStatus.DENIED:
            return _decision(ValidationStatus.REJECTED, "BOUNDARY_DELETE_DENIED",
                             checks=checks,
                             controls=("OWNER_DELETE", "TARGET_PREFLIGHT", "TARGET_FINAL_ABSENCE"),
                             contradicting=boundary.evidence_ids[:8])
        supporting = tuple(dict.fromkeys((
            *(ref for entry in (owner, boundary, *((reversal,) if reversal else ()))
              for ref in entry.evidence_ids),
            *vis_refs, *policy_refs, *tenant_refs, *owner_member[2], *foreign_member[2])))[:64]
        finding = engine._finding(context, target_before, foreign_write,
                                  "AUTHORIZATION_DELETE", "UNAUTHORIZED_OBJECT_DELETION")
        return _decision(ValidationStatus.CONFIRMED, "UNAUTHORIZED_DELETE_READBACK",
                         checks=checks,
                         controls=("OWNER_DELETE", "TARGET_PREFLIGHT", "TARGET_FINAL_ABSENCE"),
                         supporting=supporting, reproductions=1,
                         impact="UNAUTHORIZED_OBJECT_DELETION", finding=finding)


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


class APIReadValidator:
    """Confirm only owned, protected API data read through an audited plan."""

    id = "api_observed_read"

    @staticmethod
    def _executed_query(item: Observation,
                        engine: DeterministicValidatorEngine) -> str | None:
        request = item.exchange.request
        record = engine.evidence.get_evidence(request.body_evidence_id) if request.body_evidence_id else None
        if (record is None or record.target_ref != item.exchange.target_id or
                record.redaction_status is not RedactionStatus.ORIGINAL or
                record.content_size > 16384):
            return None
        try:
            raw = engine.evidence.read_content(record.evidence_id, allow_sensitive=True,
                                               max_bytes=16384)
            if hashlib.sha256(raw).hexdigest() != request.body_hash:
                return None
            payload = json.loads(raw, object_pairs_hook=GraphQLValidator._unique_pairs)
            return payload.get("query") if isinstance(payload, dict) and isinstance(
                payload.get("query"), str) else None
        except (ValueError, TypeError, UnicodeError, PermissionError):
            return None
    version = _VALIDATOR_VERSION

    @staticmethod
    def _batch_payload(item: Observation, engine: DeterministicValidatorEngine) -> object | None:
        response = item.exchange.response
        ref = engine.evidence.get_evidence(response.body_evidence_id) if response and response.body_evidence_id else None
        if (ref is None or ref.target_ref != item.exchange.target_id or
                ref.redaction_status.value != "ORIGINAL" or ref.content_size > 262144 or
                ref.content_hash != response.body_hash):
            return None
        try:
            return json.loads(engine.evidence.read_content(
                ref.evidence_id, allow_sensitive=True, max_bytes=262144),
                object_pairs_hook=GraphQLValidator._unique_pairs)
        except (ValueError, TypeError, UnicodeError, PermissionError):
            return None

    def _evaluate_batch(self, context: ValidationContext,
                        engine: DeterministicValidatorEngine,
                        candidate: APICandidate, operation: APIOperation,
                        observations: tuple[Observation, ...],
                        frozen: dict[str, object]) -> ValidatorDecision:
        owner, actor_control, invalid, first, second = observations
        target = context.run.target_id
        templates = context.plan["request_templates"]
        root = frozen.get("batch_root_key")
        id_type = frozen.get("batch_id_type")
        envelope = frozen.get("batch_envelope")
        object_ids = (templates[0]["test_object_id"],
                      templates[0]["source_companion_id"],
                      templates[1]["test_object_id"],
                      templates[1]["source_companion_id"])
        if (operation.type is not APIOperationType.GRAPHQL_QUERY or
                operation.method != "POST" or not isinstance(root, str) or
                not isinstance(id_type, str) or envelope not in {
                    "NODES_LIST", "OPERATION_ARRAY"} or len(set(object_ids)) != 4 or
                candidate.test_object_id != object_ids[0] or
                tuple(shape.get("source_companion_id") for shape in templates) !=
                (object_ids[1], object_ids[3], object_ids[1], object_ids[1], object_ids[1]) or
                tuple(shape.get("companion_object_id") for shape in templates) !=
                (object_ids[1], object_ids[3], object_ids[1], object_ids[2], object_ids[2]) or
                tuple(shape.get("test_object_id") for shape in templates) !=
                (object_ids[0], object_ids[2], object_ids[0], object_ids[0], object_ids[0]) or
                any(shape.get("root_key") != root or shape.get("id_type") != id_type or
                    shape.get("envelope") != envelope or
                    shape.get("variable_name") != templates[0].get("variable_name")
                    for shape in templates)):
            return _decision(ValidationStatus.INVALID_TEST, "API_BATCH_BINDING_INVALID")
        registry = ObjectRegistry(engine.evidence)
        records = [registry.get(object_id, target) for object_id in object_ids]
        if any(item is None or not item.disposable or not item.verified_at or
               item.cleaned_at or item.state not in {ObjectState.READY, ObjectState.IN_USE,
                                                     ObjectState.CLEANUP_PENDING} or
               not item.external_id_evidence_id or not item.external_id_hash
               for item in records):
            return _decision(ValidationStatus.INVALID_TEST, "API_BATCH_OBJECTS_UNAVAILABLE")
        display_hashes: list[str] = []
        external_hashes: list[str] = []
        for item in records:
            try:
                external = engine.evidence.read_content(item.external_id_evidence_id,
                    allow_sensitive=True, max_bytes=256).decode("ascii")
                if _digest(item.id + ":" + external) != item.external_id_hash:
                    raise ValueError
                display = external if id_type == "PLAIN" else encode_observed_global_id(
                    id_type, external)
            except (ValueError, UnicodeError, PermissionError):
                return _decision(ValidationStatus.INVALID_TEST, "API_BATCH_OBJECT_ID_INVALID")
            display_hashes.append(_digest(display))
            external_hashes.append(_digest(external))
        if (records[0].creator_identity_id != owner.identity_id or
                records[1].creator_identity_id != owner.identity_id or
                records[2].creator_identity_id != first.identity_id or
                records[3].creator_identity_id != first.identity_id or
                records[0].tenant_id != records[1].tenant_id or
                records[2].tenant_id != records[3].tenant_id or
                records[0].tenant_id == records[2].tenant_id):
            return _decision(ValidationStatus.INVALID_TEST, "API_BATCH_OWNERSHIP_INVALID")
        owner_member = engine.membership(owner.identity_id, target)
        actor_member = engine.membership(first.identity_id, target)
        fact_refs: list[str] = []
        for item in records:
            creator, refs = engine.fact_value(item.id, "created_by", target)
            tenant, tenant_refs = engine.fact_value(item.id, "resource_tenant", target)
            disposable, disposable_refs = engine.fact_value(item.id, "disposable", target)
            if (creator != item.creator_identity_id or tenant != item.tenant_id or
                    disposable != "true"):
                return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                                 "API_BATCH_OWNERSHIP_UNPROVEN")
            fact_refs.extend((*refs, *tenant_refs, *disposable_refs))
        tenant, tenant_refs = engine.fact_value(external_hashes[0], "resource_tenant", target)
        visibility, visibility_refs = engine.fact_value(external_hashes[0],
                                                       "resource_visibility", target)
        policy, policy_refs = engine.fact_value(external_hashes[0], "access_policy", target)
        if visibility == "PUBLIC":
            return _decision(ValidationStatus.REJECTED, "API_BATCH_OBJECT_PUBLIC",
                             contradicting=visibility_refs)
        boundary = bool(owner_member and actor_member and
                        owner_member[0] == records[0].tenant_id and
                        actor_member[0] == records[2].tenant_id and
                        tenant == records[0].tenant_id and visibility == "PRIVATE" and
                        policy in {"OWNER_ONLY", "TENANT_ONLY"})
        checks = [_check("BATCH_PRIVATE_TENANT_BOUNDARY", boundary,
                         tuple((*tenant_refs, *visibility_refs, *policy_refs))[:6])]
        if not boundary:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "API_BATCH_PRIVACY_UNPROVEN", checks=tuple(checks))
        owner_values = graphql_batch_values(self._batch_payload(owner, engine), root,
                                           frozenset(display_hashes[:2]), envelope=envelope)
        actor_values = graphql_batch_values(self._batch_payload(actor_control, engine), root,
                                           frozenset(display_hashes[2:]), envelope=envelope)
        owner_ok = owner.features.status_code == 200 and len(owner_values) == 2
        actor_ok = actor_control.features.status_code == 200 and len(actor_values) == 2
        negative = self._batch_payload(invalid, engine)
        if envelope == "NODES_LIST":
            negative_data = negative.get("data") if isinstance(negative, dict) else None
            negative_nodes = negative_data.get(root) if isinstance(negative_data, dict) else None
            negative_empty = bool(isinstance(negative, dict) and
                (root in negative_data if isinstance(negative_data, dict) else
                 isinstance(negative.get("errors"), list) and bool(negative["errors"])) and
                (negative_nodes is None or negative_nodes == [] or
                 isinstance(negative_nodes, list) and len(negative_nodes) <= 2 and
                 all(value is None for value in negative_nodes)))
        else:
            negative_empty = bool(isinstance(negative, list) and len(negative) == 2 and
                all(isinstance(part, dict) and
                    (isinstance(part.get("data"), dict) and
                     part["data"].get(root) is None or
                     isinstance(part.get("errors"), list) and bool(part["errors"])) and
                    not (isinstance(part.get("data"), dict) and
                         isinstance(part["data"].get(root), dict)) for part in negative))
        negative_ok = bool(invalid.features.status_code in {200, 400, 404} and
                           negative_empty)
        checks.extend((_check("OWNER_TWO_ITEM_CONTROL", owner_ok, owner.evidence_ids[:2]),
                       _check("ACTOR_TWO_ITEM_CONTROL", actor_ok,
                              actor_control.evidence_ids[:2]),
                       _check("INVALID_TWO_ITEM_CONTROL", negative_ok,
                              invalid.evidence_ids[:2])))
        if not owner_ok or not actor_ok or not negative_ok:
            return _decision(ValidationStatus.INVALID_TEST,
                             "API_BATCH_CONTROLS_FAILED", checks=tuple(checks))
        matched: list[Observation] = []
        for item in (first, second):
            values = graphql_batch_values(self._batch_payload(item, engine), root,
                                          frozenset((display_hashes[0], display_hashes[2])),
                                          envelope=envelope)
            if (item.features.status_code == 200 and len(values) == 2 and
                    any(values[display_hashes[0]].get(key) == value
                        for key, value in owner_values[display_hashes[0]].items()) and
                    any(values[display_hashes[2]].get(key) == value
                        for key, value in actor_values[display_hashes[2]].items())):
                matched.append(item)
        checks.append(_check("MIXED_BATCH_PER_OBJECT_DATA", len(matched) == 2,
                             tuple(ref for item in matched for ref in item.evidence_ids[:2])[:4]))
        if not matched:
            return _decision(ValidationStatus.REJECTED, "API_BATCH_FOREIGN_ITEM_FILTERED",
                             checks=tuple(checks), contradicting=first.evidence_ids[:2] +
                             second.evidence_ids[:2])
        if len(matched) == 1:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "API_BATCH_REPRODUCTION_REQUIRED", checks=tuple(checks),
                             reproductions=1)
        root_key, root_refs = engine.fact_value(external_hashes[0], "root_cause_key", target)
        finding = engine._finding(context, owner, first, "API_AUTHORIZATION",
                                  "CROSS_TENANT_PROTECTED_BATCH_READ",
                                  root_key or operation.operation_key)
        refs = tuple(dict.fromkeys((
            *owner.evidence_ids[:3], *actor_control.evidence_ids[:3], *invalid.evidence_ids[:2],
            *first.evidence_ids[:3], *second.evidence_ids[:3],
            *(ref for item in records for ref in item.verification_evidence_ids),
            *fact_refs, *tenant_refs, *visibility_refs, *policy_refs, *root_refs)))[:64]
        return _decision(ValidationStatus.CONFIRMED, "API_PROTECTED_MIXED_BATCH",
                         checks=tuple(checks), controls=("OWNER_BATCH", "ACTOR_BATCH",
                                                        "INVALID_BATCH"),
                         supporting=refs, reproductions=2,
                         impact="CROSS_TENANT_PROTECTED_BATCH_READ", finding=finding)

    @staticmethod
    def _nested_values(item: Observation, engine: DeterministicValidatorEngine,
                       path: str, parent_hash: str, child_hash: str) -> dict[str, str]:
        response = item.exchange.response
        ref = engine.evidence.get_evidence(response.body_evidence_id) if response and response.body_evidence_id else None
        if (ref is None or ref.target_ref != item.exchange.target_id or
                ref.redaction_status.value != "ORIGINAL" or ref.content_size > 262144 or
                ref.content_hash != response.body_hash):
            return {}
        try:
            body = json.loads(engine.evidence.read_content(
                ref.evidence_id, allow_sensitive=True, max_bytes=262144),
                object_pairs_hook=GraphQLValidator._unique_pairs)
        except (ValueError, TypeError, UnicodeError, PermissionError):
            return {}
        return nested_child_values(body, path, parent_hash, child_hash)

    def _evaluate_nested(self, context: ValidationContext,
                         engine: DeterministicValidatorEngine,
                         candidate: APICandidate, operation: APIOperation,
                         observations: tuple[Observation, ...],
                         frozen: dict[str, object]) -> ValidatorDecision:
        owner, actor_control, invalid, first, second = observations
        target = context.run.target_id
        templates = context.plan["request_templates"]
        parent_id = templates[0]["test_object_id"]
        child_id = frozen.get("nested_child_id")
        path = frozen.get("nested_path")
        registry = ObjectRegistry(engine.evidence)
        parent = registry.get(parent_id, target)
        child = registry.get(child_id, target) if isinstance(child_id, str) else None
        if (operation.type is not APIOperationType.GRAPHQL_QUERY or
                candidate.test_object_id != parent_id or
                candidate.child_object_id != child_id or
                candidate.field_path != path or
                not isinstance(path, str) or
                path + "/id" not in {field.path for field in operation.fields}):
            return _decision(ValidationStatus.INVALID_TEST, "API_NESTED_BINDING_INVALID")
        if (parent is None or child is None or child.parent_id != parent.id or
                child.creator_identity_id != owner.identity_id or
                child.tenant_id != parent.tenant_id):
            return _decision(ValidationStatus.INVALID_TEST, "API_NESTED_OBJECT_RELATION_INVALID")
        if (not child.disposable or not child.verified_at or
                child.state not in {ObjectState.READY, ObjectState.IN_USE,
                                    ObjectState.CLEANUP_PENDING} or child.cleaned_at or
                not child.external_id_evidence_id or not child.external_id_hash):
            return _decision(ValidationStatus.INVALID_TEST, "API_NESTED_CHILD_UNAVAILABLE")
        try:
            external = engine.evidence.read_content(child.external_id_evidence_id,
                        allow_sensitive=True, max_bytes=256).decode("ascii")
            if _digest(child.id + ":" + external) != child.external_id_hash:
                raise ValueError
        except (ValueError, UnicodeError, PermissionError):
            return _decision(ValidationStatus.INVALID_TEST, "API_NESTED_CHILD_ID_INVALID")
        child_hash = _digest(external)
        relation, relation_refs = engine.fact_value(child.id, "belongs_to", target)
        creator, creator_refs = engine.fact_value(child.id, "created_by", target)
        relation_source = any(fact.object == parent.id and fact.source in {
            "OBJECT_FACTORY", "NORMAL_BEHAVIOUR_LEARNER", "FIXTURE"}
                              for fact in engine.fact(child.id, "belongs_to", target))
        creator_source = any(fact.object == owner.identity_id and fact.source in {
            "OBJECT_FACTORY", "FIXTURE"}
                             for fact in engine.fact(child.id, "created_by", target))
        tenant, tenant_refs = engine.fact_value(child_hash, "resource_tenant", target)
        visibility, visibility_refs = engine.fact_value(child_hash, "resource_visibility", target)
        policy, policy_refs = engine.fact_value(child_hash, "access_policy", target)
        owner_member = engine.membership(owner.identity_id, target)
        foreign_member = engine.membership(first.identity_id, target)
        relationship = bool(relation == parent.id and relation_source and
                            creator == owner.identity_id and creator_source and
                            owner_member and foreign_member and tenant == child.tenant_id and
                            owner_member[0] == tenant and foreign_member[0] != tenant and
                            visibility == "PRIVATE" and policy in {"OWNER_ONLY", "TENANT_ONLY"})
        checks = [_check("NESTED_CHILD_RELATION_AND_PRIVACY", relationship,
                         (*relation_refs, *creator_refs, *tenant_refs,
                          *visibility_refs, *policy_refs)[:10])]
        if not relationship:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "API_NESTED_CHILD_PRIVACY_UNPROVEN", checks=tuple(checks))
        parent_hash = owner.object_ref_hash
        owner_ok = (owner.features.status_code == 200 and
                    self._graphql_owned_data(owner, engine, parent_hash))
        actor_ok = (actor_control.features.status_code == 200 and
                    self._graphql_owned_data(actor_control, engine,
                                             actor_control.object_ref_hash))
        negative_ok = (not invalid.features.graphql_data_present and
                       not self._graphql_owned_data(invalid, engine, parent_hash))
        checks.extend((_check("OWNER_PARENT_CONTROL", owner_ok, owner.evidence_ids[:2]),
                       _check("ACTOR_PARENT_CONTROL", actor_ok, actor_control.evidence_ids[:2]),
                       _check("INVALID_PARENT_CONTROL", negative_ok, invalid.evidence_ids[:2])))
        if not owner_ok or not actor_ok or not negative_ok:
            return _decision(ValidationStatus.INVALID_TEST,
                             "API_NESTED_CONTROLS_FAILED", checks=tuple(checks))
        owner_values = self._nested_values(owner, engine, path, parent_hash, child_hash)
        if not owner_values:
            return _decision(ValidationStatus.INVALID_TEST,
                             "API_NESTED_OWNER_CHILD_DATA_MISSING", checks=tuple(checks))
        matches = tuple(item for item in (first, second) if
                        item.features.status_code == 200 and
                        any(self._nested_values(item, engine, path, parent_hash,
                                                child_hash).get(key) == value
                            for key, value in owner_values.items()))
        checks.append(_check("PROTECTED_NESTED_CHILD_DATA", len(matches) == 2,
                             tuple(ref for item in matches for ref in item.evidence_ids[:2])[:4]))
        if not matches:
            return _decision(ValidationStatus.REJECTED, "API_NESTED_CHILD_FILTERED",
                             checks=tuple(checks), contradicting=first.evidence_ids[:2] +
                             second.evidence_ids[:2])
        if len(matches) == 1:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "API_NESTED_REPRODUCTION_REQUIRED", checks=tuple(checks),
                             reproductions=1)
        root_key, root_refs = engine.fact_value(child_hash, "root_cause_key", target)
        finding = engine._finding(context, owner, first, "API_AUTHORIZATION",
                                  "CROSS_TENANT_PROTECTED_NESTED_CHILD_READ",
                                  root_key or operation.operation_key)
        refs = tuple(dict.fromkeys((*owner.evidence_ids[:3], *actor_control.evidence_ids[:3],
                                    *invalid.evidence_ids[:2], *first.evidence_ids[:3],
                                    *second.evidence_ids[:3], *child.verification_evidence_ids,
                                    *relation_refs, *creator_refs, *tenant_refs,
                                    *visibility_refs, *policy_refs, *root_refs)))[:64]
        return _decision(ValidationStatus.CONFIRMED, "API_PROTECTED_NESTED_CHILD",
                         checks=tuple(checks), controls=("OWNER_PARENT", "ACTOR_PARENT",
                                                        "INVALID_PARENT"),
                         supporting=refs, reproductions=2,
                         impact="CROSS_TENANT_PROTECTED_NESTED_CHILD_READ", finding=finding)

    @staticmethod
    def _graphql_owned_values(item: Observation, engine: DeterministicValidatorEngine,
                              object_hash: str) -> dict[str, str]:
        response = item.exchange.response
        ref = engine.evidence.get_evidence(response.body_evidence_id) if response and response.body_evidence_id else None
        if (ref is None or ref.target_ref != item.exchange.target_id or
                ref.redaction_status.value != "ORIGINAL" or ref.content_size > 262144 or
                ref.content_hash != response.body_hash):
            return {}
        try:
            body = json.loads(engine.evidence.read_content(
                ref.evidence_id, allow_sensitive=True, max_bytes=262144),
                object_pairs_hook=GraphQLValidator._unique_pairs)
            data = body.get("data") if isinstance(body, dict) else None
            pending: list[tuple[object, int]] = [(data, 0)]
            visits = 0
            while pending:
                value, depth = pending.pop()
                visits += 1
                if visits > 512 or depth > 10:
                    return {}
                if isinstance(value, dict):
                    if isinstance(value.get("id"), str) and _digest(value["id"]) == object_hash:
                        return {key: _digest(json.dumps(field, sort_keys=True,
                                                        ensure_ascii=True)) for key, field in
                                list(value.items())[:24] if key not in {
                                    "id", "__typename", "type", "tenant", "tenantId",
                                    "owner", "ownerId"}
                                and field is not None and isinstance(field, (str, int, float, bool))}
                    pending.extend((child, depth + 1) for child in value.values())
                elif isinstance(value, list):
                    pending.extend((child, depth + 1) for child in value[:16])
        except (KeyError, TypeError, ValueError, UnicodeError, PermissionError):
            return {}
        return {}

    @staticmethod
    def _graphql_owned_data(item: Observation, engine: DeterministicValidatorEngine,
                            object_hash: str, field_path: str | None = None) -> bool:
        response = item.exchange.response
        ref = engine.evidence.get_evidence(response.body_evidence_id) if response and response.body_evidence_id else None
        if (ref is None or ref.target_ref != item.exchange.target_id or
                ref.redaction_status.value != "ORIGINAL" or ref.content_size > 262144 or
                ref.content_hash != response.body_hash):
            return False
        try:
            body = json.loads(engine.evidence.read_content(ref.evidence_id, allow_sensitive=True,
                                                           max_bytes=262144),
                              object_pairs_hook=GraphQLValidator._unique_pairs)
            data = body.get("data") if isinstance(body, dict) else None
            if field_path:
                parts = field_path.strip("/").split("/")
                if (not isinstance(data, dict) or len(parts) not in {2, 3} or
                        any(not part or part in {".", ".."} for part in parts)):
                    return False
                root = data.get(parts[0])
                if (not isinstance(root, dict) or not isinstance(root.get("id"), str) or
                        _digest(root["id"]) != object_hash):
                    return False
                parent = root
                for part in parts[1:-1]:
                    parent = parent.get(part) if isinstance(parent, dict) else None
                    if (not isinstance(parent, dict) or
                            "id" in parent and
                            (not isinstance(parent["id"], str) or
                             _digest(parent["id"]) != object_hash)):
                        return False
                value = parent.get(parts[-1]) if isinstance(parent, dict) else None
                return value is not None and isinstance(value, (str, int, float, bool))
            pending: list[tuple[object, int]] = [(data, 0)]
            visits = 0
            while pending:
                value, depth = pending.pop()
                visits += 1
                if visits > 512 or depth > 10:
                    return False
                if isinstance(value, dict):
                    if isinstance(value.get("id"), str) and _digest(value["id"]) == object_hash:
                        return True
                    pending.extend((nested, depth + 1) for nested in value.values())
                elif isinstance(value, list):
                    pending.extend((nested, depth + 1) for nested in value[:16])
        except (KeyError, TypeError, ValueError, UnicodeError, PermissionError):
            return False
        return False

    def evaluate(self, context: ValidationContext,
                 engine: DeterministicValidatorEngine) -> ValidatorDecision:
        frozen = context.plan.get("api_binding")
        if (engine.api_operations is None or not isinstance(frozen, dict) or
                context.plan.get("skill_id") != "api-observed-read"):
            return _decision(ValidationStatus.INVALID_TEST, "API_BINDING_MISSING")
        candidate = engine.api_operations.get_candidate(context.run.target_id,
                                                        frozen.get("candidate_id", ""))
        operation = engine.api_operations.get_operation(context.run.target_id,
                                                        frozen.get("operation_id", ""))
        if (candidate is None or operation is None or candidate.operation_id != operation.id or
                candidate.plan_id != context.run.plan_id or
                candidate.category != frozen.get("category") or
                operation.version_hash != frozen.get("version_hash") or
                operation.state != "CURRENT" or operation.package_id != context.run.package_id or
                candidate.category not in {"OBJECT_AUTH", "FIELD_AUTH", "NESTED_AUTH",
                                           "BATCH_AUTH"}):
            return _decision(ValidationStatus.INVALID_TEST, "API_OPERATION_STALE_OR_UNBOUND")
        observations = sorted(context.observations,
                              key=lambda item: item.step.action_slot if item.step.action_slot is not None else 99)
        if (len(observations) != 5 or
                tuple(item.step.action_slot for item in observations) != (0, 1, 2, 3, 4) or
                tuple(item.step.role for item in observations) !=
                ("CONTROL", "CONTROL", "OTHER", "BOUNDARY", "BOUNDARY") or
                not all(item.audit_valid for item in observations)):
            return _decision(ValidationStatus.INVALID_TEST, "API_AUDIT_OR_CONTROLS_MISSING")
        owner, actor_control, invalid, first, second = observations
        templates = context.plan.get("request_templates")
        alternate = ("actor_control_operation_id" in frozen or
                     "actor_control_version_hash" in frozen)
        actor_operation = (engine.api_operations.get_operation(
            context.run.target_id, frozen.get("actor_control_operation_id", ""))
            if alternate else operation)
        if (actor_operation is None or actor_operation.state != "CURRENT" or
                actor_operation.package_id != context.run.package_id or
                (alternate and (candidate.category != "FIELD_AUTH" or
                                actor_operation.id == operation.id or
                                actor_operation.type is not APIOperationType.GRAPHQL_QUERY or
                                actor_operation.endpoint != operation.endpoint or
                                actor_operation.method != operation.method or
                                actor_operation.name != operation.name or
                                actor_operation.version_hash != frozen.get(
                                    "actor_control_version_hash")))):
            return _decision(ValidationStatus.INVALID_TEST, "API_FIELD_CONTROL_OPERATION_INVALID")
        if (not isinstance(templates, list) or len(templates) != 5 or
                any(not isinstance(shape, dict) or shape.get("binding") != (
                        "API_OBSERVED_BATCH_V1" if candidate.category == "BATCH_AUTH" else
                        "API_OBSERVED_READ_V1") or
                    shape.get("operation_id") != (actor_operation.id if index == 1 else operation.id) or
                    shape.get("version_hash") != (actor_operation.version_hash if index == 1
                                                  else operation.version_hash) or
                    shape.get("field_path") != ("" if alternate and index == 1 else
                                                frozen.get("field_path"))
                    for index, shape in enumerate(templates)) or
                (alternate and templates[1].get("source_exchange_id") not in
                 actor_operation.exchange_ids) or
                tuple(shape.get("variant") for shape in templates) !=
                ("OWNER", "OWNER", "INVALID_OBJECT", "FOREIGN", "FOREIGN") or
                owner.identity_id != invalid.identity_id or
                actor_control.identity_id != first.identity_id or
                first.identity_id != second.identity_id or
                owner.identity_id == first.identity_id or
                owner.object_ref_hash is None or
                owner.object_ref_hash != first.object_ref_hash or
                owner.object_ref_hash != second.object_ref_hash or
                actor_control.object_ref_hash is None or
                actor_control.object_ref_hash == owner.object_ref_hash or
                any(item.operation != (actor_operation.id if index == 1 else operation.id)
                    for index, item in enumerate(observations)) or
                any(item.features.request_method != operation.method for item in observations)):
            return _decision(ValidationStatus.INVALID_TEST, "API_CONTROL_BINDING_INVALID")
        if alternate:
            owner_document = self._executed_query(owner, engine)
            actor_document = self._executed_query(actor_control, engine)
            if (owner_document is None or actor_document is None or
                    hashlib.sha256(owner_document.encode()).hexdigest() != operation.version_hash or
                    hashlib.sha256(actor_document.encode()).hexdigest() != actor_operation.version_hash or
                    not observed_field_selection_pair(owner_document, actor_document,
                                                       frozen.get("field_path", ""))):
                return _decision(ValidationStatus.INVALID_TEST,
                                 "API_FIELD_SELECTION_DIFFERENTIAL_INVALID")
        if candidate.category == "NESTED_AUTH":
            return self._evaluate_nested(context, engine, candidate, operation,
                                         tuple(observations), frozen)
        if candidate.category == "BATCH_AUTH":
            return self._evaluate_batch(context, engine, candidate, operation,
                                        tuple(observations), frozen)
        target = context.run.target_id
        obj_hash = owner.object_ref_hash
        owner_member = engine.membership(owner.identity_id, target)
        foreign_member = engine.membership(first.identity_id, target)
        tenant, tenant_refs = engine.fact_value(obj_hash, "resource_tenant", target)
        visibility, visibility_refs = engine.fact_value(obj_hash, "resource_visibility", target)
        policy, policy_refs = engine.fact_value(obj_hash, "access_policy", target)
        if visibility == "PUBLIC":
            return _decision(ValidationStatus.REJECTED, "API_OBJECT_PUBLIC",
                             contradicting=visibility_refs)
        relationship = bool(owner_member and foreign_member and tenant and
                            owner_member[0] == tenant and foreign_member[0] != tenant and
                            visibility == "PRIVATE" and policy in {"OWNER_ONLY", "TENANT_ONLY"})
        checks = [
            _check("OWNER_CONTROL", owner.features.status_code is not None and
                   200 <= owner.features.status_code < 300, owner.evidence_ids[:2]),
            _check("ACTOR_OWNED_CONTROL", actor_control.features.status_code is not None and
                   200 <= actor_control.features.status_code < 300,
                   actor_control.evidence_ids[:2]),
            _check("TENANT_PRIVACY_BOUNDARY", relationship,
                   (*tenant_refs, *visibility_refs, *policy_refs)[:6]),
        ]
        if not relationship:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "API_OWNERSHIP_OR_PRIVACY_UNPROVEN", checks=tuple(checks))
        graphql = operation.type is APIOperationType.GRAPHQL_QUERY
        def has_object(item: Observation, expected: str) -> bool:
            if item.features.status_code is None or not 200 <= item.features.status_code < 300:
                return False
            if graphql:
                return self._graphql_owned_data(item, engine, expected)
            return expected in item.features.object_id_hashes and bool(item.features.normalized_json_hash)
        owner_ok = has_object(owner, obj_hash)
        actor_ok = has_object(actor_control, actor_control.object_ref_hash)
        checks[0] = _check("OWNER_CONTROL", owner_ok, owner.evidence_ids[:2])
        checks[1] = _check("ACTOR_OWNED_CONTROL", actor_ok, actor_control.evidence_ids[:2])
        if not owner_ok or not actor_ok:
            return _decision(ValidationStatus.INVALID_TEST, "API_SEMANTIC_CONTROL_FAILED",
                             checks=tuple(checks))
        negative_ok = not has_object(invalid, obj_hash) and (
            invalid.features.status_code in _DENIED if not graphql else
            not invalid.features.graphql_data_present)
        checks.append(_check("INVALID_OBJECT_CONTROL", negative_ok, invalid.evidence_ids[:2]))
        if not negative_ok:
            return _decision(ValidationStatus.INVALID_TEST, "API_NEGATIVE_CONTROL_FAILED",
                             checks=tuple(checks))
        field_path = frozen.get("field_path", "")
        if candidate.category == "FIELD_AUTH":
            classification, class_refs = engine.fact_value(obj_hash, "data_classification", target)
            field_name = field_path.rsplit("/", 1)[-1]
            field_visibility, field_refs = engine.fact_value(obj_hash, "field_visibility", target)
            field_protected = bool(field_path and classification == "SENSITIVE" and
                                   (field_visibility == field_name or
                                    isinstance(field_visibility, str) and
                                    field_visibility.startswith(field_name + ":")))
            checks.append(_check("PROTECTED_FIELD_POLICY", field_protected,
                                 (*class_refs, *field_refs)[:4]))
            if not field_protected:
                return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                                 "API_FIELD_EXPECTATION_UNKNOWN", checks=tuple(checks))
            owner_value = owner.features.graphql_value(field_path)
            if not self._graphql_owned_data(owner, engine, obj_hash, field_path):
                return _decision(ValidationStatus.INVALID_TEST,
                                 "API_FIELD_OWNER_BINDING_INVALID", checks=tuple(checks))
            def disclosed(item: Observation) -> bool:
                return bool(owner_value and
                            self._graphql_owned_data(item, engine, obj_hash, field_path) and
                            item.features.graphql_value(field_path) == owner_value)
        else:
            owner_values = self._graphql_owned_values(owner, engine, obj_hash) if graphql else {}
            if graphql and not owner_values:
                return _decision(ValidationStatus.INVALID_TEST,
                                 "API_OBJECT_OWNER_DATA_MISSING", checks=tuple(checks))
            def disclosed(item: Observation) -> bool:
                if not has_object(item, obj_hash):
                    return False
                if graphql:
                    values = self._graphql_owned_values(item, engine, obj_hash)
                    return any(values.get(key) == value for key, value in owner_values.items())
                return bool(item.features.normalized_json_hash and
                            item.features.normalized_json_hash == owner.features.normalized_json_hash)
        matches = tuple(item for item in (first, second) if disclosed(item))
        checks.append(_check("PROTECTED_DATA", len(matches) == 2,
                             tuple(ref for item in matches for ref in item.evidence_ids[:2])[:4]))
        if len(matches) == 0:
            return _decision(ValidationStatus.REJECTED, "API_BOUNDARY_DENIED",
                             checks=tuple(checks), contradicting=first.evidence_ids[:2] +
                             second.evidence_ids[:2])
        if len(matches) == 1:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW, "API_REPRODUCTION_REQUIRED",
                             checks=tuple(checks), reproductions=1)
        refs = tuple(dict.fromkeys((*owner.evidence_ids[:3], *actor_control.evidence_ids[:3],
                                    *invalid.evidence_ids[:2], *first.evidence_ids[:3],
                                    *second.evidence_ids[:3], *tenant_refs,
                                    *visibility_refs, *policy_refs,
                                    *(owner_member[2] if owner_member else ()),
                                    *(foreign_member[2] if foreign_member else ()))))[:64]
        root_key, root_refs = engine.fact_value(obj_hash, "root_cause_key", target)
        if not root_key:
            root_key = operation.operation_key
        refs = tuple(dict.fromkeys((*refs, *root_refs)))[:64]
        impact = ("CROSS_TENANT_PROTECTED_FIELD_READ" if candidate.category == "FIELD_AUTH" else
                  "CROSS_TENANT_PROTECTED_OBJECT_READ")
        finding = engine._finding(context, owner, first, "API_AUTHORIZATION", impact,
                                  root_key)
        return _decision(ValidationStatus.CONFIRMED, "API_PROTECTED_BOUNDARY",
                         checks=tuple(checks), controls=("OWNER", "ACTOR_OWNED", "INVALID_OBJECT"),
                         supporting=refs, reproductions=2, impact=impact, finding=finding)


class ExposureFieldValidator:
    """A trusted field policy, not a JSON key name, defines the privacy boundary."""

    id = "restricted_api_field_exposure"
    version = "1.0.0"

    def evaluate(self, context: ValidationContext,
                 engine: DeterministicValidatorEngine) -> ValidatorDecision:
        if (engine.exposure is None or context.plan.get("skill_id") !=
                "overexposed-api-response"):
            return _decision(ValidationStatus.INVALID_TEST, "FIELD_EXPOSURE_BINDING_MISSING")
        candidate_id = engine.exposure.store.candidate_for_plan(
            context.run.target_id, context.run.plan_id)
        candidate = engine.exposure.store.get(context.run.target_id, candidate_id) if candidate_id else None
        if candidate is None or candidate.category.value != "OVEREXPOSED_API_RESPONSE":
            return _decision(ValidationStatus.INVALID_TEST, "FIELD_EXPOSURE_CANDIDATE_MISSING")
        owner, boundaries, negatives = engine._controls(context)
        checks = engine._base_checks(owner, boundaries, negatives)
        if (owner is None or len(boundaries) != 1 or len(negatives) != 1 or
                any(item.outcome is CheckOutcome.FAIL for item in checks) or
                not all(item.audit_valid for item in (owner, *boundaries, *negatives))):
            return _decision(ValidationStatus.INVALID_TEST, "FIELD_EXPOSURE_CONTROLS_INVALID",
                             checks=checks)
        member = boundaries[0]
        target, object_hash = context.run.target_id, owner.object_ref_hash
        if (not object_hash or member.object_ref_hash != object_hash or
                owner.identity_id == member.identity_id or
                owner.features.status_code != 200):
            return _decision(ValidationStatus.INVALID_TEST, "FIELD_OBJECT_OR_ROLE_UNPROVEN",
                             checks=checks)
        if member.features.status_code in _DENIED:
            return _decision(ValidationStatus.REJECTED, "FIELD_BOUNDARY_DENIED",
                             checks=checks, contradicting=member.evidence_ids[:4])
        visibility, vis_refs = engine.fact_value(object_hash, "resource_visibility", target)
        if visibility == "PUBLIC":
            return _decision(ValidationStatus.REJECTED, "FIELD_RESOURCE_PUBLIC",
                             checks=checks, contradicting=vis_refs)
        classification, class_refs = engine.fact_value(object_hash, "data_classification", target)
        restricted, field_refs = engine.fact_value(object_hash, "field_visibility", target)
        if visibility != "PRIVATE" or classification != "SENSITIVE":
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "TRUSTED_FIELD_PRIVACY_POLICY_MISSING", checks=checks)
        owner_membership = engine.membership(owner.identity_id, target)
        member_membership = engine.membership(member.identity_id, target)
        if owner_membership is None or member_membership is None:
            return _decision(ValidationStatus.INVALID_TEST, "FIELD_ROLE_BOUNDARY_UNPROVEN",
                             checks=checks)
        cross_tenant = owner_membership[0] != member_membership[0]
        if not cross_tenant:
            if (not isinstance(restricted, str) or
                    not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}:ROLE-[0-9a-f]{32}",
                                     restricted)):
                return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                                 "TRUSTED_FIELD_PRIVACY_POLICY_MISSING", checks=checks)
            field_name, required_role = restricted.split(":", 1)
            if (required_role not in owner_membership[1] or
                    required_role in member_membership[1]):
                return _decision(ValidationStatus.INVALID_TEST, "FIELD_ROLE_BOUNDARY_UNPROVEN",
                                 checks=checks)
        if (member.features.status_code != 200 or
                object_hash not in owner.features.object_id_hashes or
                object_hash not in member.features.object_id_hashes):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "FIELD_SAME_OBJECT_UNPROVEN", checks=checks)
        def body(item: Observation) -> dict[str, object] | None:
            ref = item.exchange.response.body_evidence_id if item.exchange.response else None
            record = engine.evidence.get_evidence(ref) if ref else None
            if (record is None or record.target_ref != target or
                    record.redaction_status.value != "ORIGINAL" or
                    record.content_size > 8192 or
                    record.content_hash != item.features.body_hash):
                return None
            try:
                value = json.loads(engine.evidence.read_content(ref, allow_sensitive=True,
                                                                max_bytes=8192))
                return value if isinstance(value, dict) else None
            except (KeyError, TypeError, ValueError, PermissionError):
                return None
        owner_body, member_body = body(owner), body(member)
        if owner_body is None or member_body is None:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "FIELD_RESPONSE_CONTENT_UNAVAILABLE", checks=checks)
        if cross_tenant:
            pii_fields = ("email", "phone", "address", "date_of_birth", "dob",
                          "account_number", "government_id")
            field_name = next((field for field in pii_fields
                               if field in owner_body and field in member_body and
                               isinstance(owner_body[field], str) and
                               len(owner_body[field]) >= 5 and
                               owner_body[field] == member_body[field]), None)
            if field_name is None:
                return _decision(ValidationStatus.REJECTED, "FOREIGN_PRIVATE_PII_NOT_DISCLOSED",
                                 checks=checks, contradicting=member.evidence_ids[:4])
        elif field_name not in owner_body:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "FIELD_RESPONSE_CONTENT_UNAVAILABLE", checks=checks)
        if field_name not in member_body:
            return _decision(ValidationStatus.REJECTED, "RESTRICTED_FIELD_REMOVED",
                             checks=checks, contradicting=member.evidence_ids[:4])
        owner_value = owner_body[field_name]
        member_value = member_body[field_name]
        if not isinstance(owner_value, (str, int)) or not owner_value or owner_value != member_value:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "RESTRICTED_FIELD_VALUE_NOT_PROVEN", checks=checks)
        refs = tuple(dict.fromkeys((*owner.evidence_ids[:4], *member.evidence_ids[:4],
                                    *negatives[0].evidence_ids[:2], *vis_refs,
                                    *class_refs, *field_refs, *owner_membership[2],
                                    *member_membership[2])))[:48]
        checks = (*checks, _check("TRUSTED_PRIVATE_DATA_POLICY", True,
                                 class_refs if cross_tenant else field_refs),
                  _check("MEMBER_RECEIVED_OWNER_FIELD", True, member.evidence_ids[:4]))
        title = ("Foreign tenant received private profile data" if cross_tenant else
                 "Lower-role API response includes a restricted field")
        impact = "CROSS_TENANT_PRIVATE_PII_DISCLOSURE" if cross_tenant else "RESTRICTED_API_FIELD_DISCLOSED"
        finding = FindingSpec(
            "FIELD_LEVEL_AUTHORIZATION", _digest(target + ":" + candidate_id + ":" + field_name),
            _digest(candidate.location), None,
            title,
            "A verified unauthorized account received protected data for one controlled object. The invalid-object control was denied.",
            impact, None, "MEDIUM")
        return _decision(ValidationStatus.CONFIRMED, "RESTRICTED_FIELD_DISCLOSED",
                         checks=checks, controls=("OWNER", "FOREIGN_TENANT" if cross_tenant else "LOWER_ROLE", "INVALID_OBJECT"),
                         supporting=refs, reproductions=1,
                         impact=impact, finding=finding)


class ExposureHttpValidator:
    """One fresh, exact Phase 14 re-read of a protected anonymous response."""

    id = "controlled_response_exposure"
    version = "1.0.0"

    def evaluate(self, context: ValidationContext,
                 engine: DeterministicValidatorEngine) -> ValidatorDecision:
        frozen = context.plan.get("exposure_binding")
        if (engine.exposure is None or engine.targets is None or
                not isinstance(frozen, dict) or
                context.plan.get("skill_id") != "protected-response-exposure"):
            return _decision(ValidationStatus.INVALID_TEST, "EXPOSURE_HTTP_BINDING_MISSING")
        package = engine.targets.get_target_package(context.run.package_id)
        if package is None or package.target.id != context.run.target_id:
            return _decision(ValidationStatus.INVALID_TEST, "EXPOSURE_HTTP_PACKAGE_MISSING")
        try:
            template = engine.exposure.resolve_captured_response(package, frozen)
        except (KeyError, TypeError, ValueError, PermissionError):
            return _decision(ValidationStatus.INVALID_TEST, "EXPOSURE_HTTP_SOURCE_UNTRUSTED")
        candidate = engine.exposure.store.get(context.run.target_id, frozen["candidate_id"])
        original = engine.evidence.get_evidence(frozen["evidence_id"])
        if (candidate is None or candidate.credential is None or original is None or
                original.target_ref != context.run.target_id or
                original.evidence_type != EvidenceType.HTTP_RESPONSE.value or
                original.content_hash != frozen["artifact_sha256"] or
                original.redaction_status.value != "ORIGINAL"):
            return _decision(ValidationStatus.INVALID_TEST, "EXPOSURE_HTTP_ARTIFACT_INVALID")
        if len(context.observations) != 1:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "EXPOSURE_HTTP_REPRODUCTION_MISSING")
        observed = context.observations[0]
        if (not observed.audit_valid or observed.actor != "ANONYMOUS" or
                observed.step.action_slot != 0 or
                observed.exchange.request.record.method != "GET"):
            return _decision(ValidationStatus.INVALID_TEST, "EXPOSURE_HTTP_POLICY_UNPROVEN")
        try:
            request = json.loads(engine.evidence.read_content(
                observed.exchange.request.observation_evidence_id,
                allow_sensitive=True, max_bytes=8192))
            if request["url"] != template.url:
                return _decision(ValidationStatus.INVALID_TEST,
                                 "EXPOSURE_HTTP_URL_MISMATCH")
        except (KeyError, TypeError, ValueError, PermissionError):
            return _decision(ValidationStatus.INVALID_TEST,
                             "EXPOSURE_HTTP_REQUEST_UNAVAILABLE")
        refs = tuple(dict.fromkeys((original.evidence_id, *observed.evidence_ids)))[:32]
        if observed.features.status_code in _DENIED:
            return _decision(ValidationStatus.REJECTED, "EXPOSURE_HTTP_CURRENTLY_DENIED",
                             contradicting=refs)
        if (observed.features.status_code != 200 or
                observed.features.body_hash != original.content_hash):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "EXPOSURE_HTTP_CURRENT_HASH_CHANGED", contradicting=refs)
        current_record = next((record for ref in observed.evidence_ids
                               if (record := engine.evidence.get_evidence(ref)) is not None and
                               record.target_ref == context.run.target_id and
                               record.evidence_type == EvidenceType.HTTP_RESPONSE.value and
                               record.source == "controlled_asset_fetch" and
                               record.content_hash == original.content_hash and
                               record.redaction_status.value == "ORIGINAL" and
                               record.content_size <= 65_536), None)
        if current_record is None:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "EXPOSURE_HTTP_CURRENT_BYTES_UNAVAILABLE", supporting=refs)
        try:
            body = engine.evidence.read_content(current_record.evidence_id,
                                                allow_sensitive=True, max_bytes=65_536)
        except (KeyError, ValueError, PermissionError):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "EXPOSURE_HTTP_BYTES_UNAVAILABLE", supporting=refs)
        signal = next((item for item in engine.exposure.analyzer.analyze_js(body).signals
                       if item.fingerprint_sha256 == candidate.credential.fingerprint_sha256), None)
        if signal is None:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "EXPOSURE_HTTP_CREDENTIAL_NOT_REPRODUCED", supporting=refs)
        if signal.status in {ExposureStatus.REJECTED_PUBLIC,
                             ExposureStatus.REJECTED_PLACEHOLDER}:
            return _decision(ValidationStatus.REJECTED,
                             "EXPOSURE_HTTP_PUBLIC_OR_SAMPLE", contradicting=refs)
        credential_ok = signal.status is ExposureStatus.FORMAT_VALID and (
            signal.credential_type in {"CLIENT_SECRET", "PASSWORD", "PRIVATE_KEY",
                                       "CONNECTION_STRING", "KNOWN_FORMAT_TOKEN"} or
            signal.credential_type in {"API_KEY", "TOKEN"} and
            "APPLICATION_REQUEST_USAGE" in signal.reason_codes)
        if not credential_ok:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "EXPOSURE_HTTP_CREDENTIAL_SEMANTICS_UNPROVEN", supporting=refs)
        checks = (_check("EXACT_SCOPED_SOURCE", True, refs[:1]),
                  _check("ANONYMOUS_POLICY_REPRODUCTION", True, refs[-4:]),
                  _check("CURRENT_NON_PUBLIC_CREDENTIAL", True,
                         (original.evidence_id, current_record.evidence_id)))
        finding = FindingSpec(
            "CREDENTIAL_DISCLOSURE", _digest(context.run.target_id + ":" +
                                             candidate.credential.fingerprint_sha256),
            _digest(template.url), None,
            "Anonymous response discloses non-public application credential",
            "One exact scoped response was re-read anonymously and still contained non-public credential material. No credential was used.",
            "NON_PUBLIC_CREDENTIAL_DISCLOSED", None, "MEDIUM")
        return _decision(ValidationStatus.CONFIRMED,
                         "EXPOSURE_HTTP_CREDENTIAL_REPRODUCED", checks=checks,
                         controls=("EXACT_ORIGINAL", "FRESH_ANONYMOUS", "PUBLIC_VALUE_FILTER"),
                         supporting=refs, reproductions=1,
                         impact="NON_PUBLIC_CREDENTIAL_DISCLOSED", finding=finding)


class ExposureVHostValidator:
    """Candidate-only protected content behind an explicitly approved Host route."""

    id = "bounded_internal_vhost_exposure"
    version = "1.0.0"

    def evaluate(self, context: ValidationContext,
                 engine: DeterministicValidatorEngine) -> ValidatorDecision:
        frozen = context.plan.get("exposure_binding")
        if (engine.exposure is None or engine.targets is None or
                not isinstance(frozen, dict) or
                context.plan.get("skill_id") != "internal-vhost-access"):
            return _decision(ValidationStatus.INVALID_TEST, "VHOST_BINDING_MISSING")
        package = engine.targets.get_target_package(context.run.package_id)
        if (package is None or package.target.id != context.run.target_id or
                package.rules.internal_vhost_testing_allowed is not True or
                package.scope.evaluate_url(str(frozen.get("url", ""))).result
                is not ScopeResult.IN_SCOPE):
            return _decision(ValidationStatus.INVALID_TEST, "VHOST_POLICY_OR_SCOPE_MISSING")
        candidate_id = frozen.get("candidate_id")
        if not isinstance(candidate_id, str):
            return _decision(ValidationStatus.INVALID_TEST, "VHOST_CANDIDATE_MISSING")
        candidate = engine.exposure.current_candidate(package, candidate_id)
        if candidate is None or candidate.artifact_sha256 != frozen.get("artifact_sha256"):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "VHOST_SOURCE_STALE")
        try:
            host = engine.exposure.vhost_reference(package, candidate_id,
                                                    str(frozen["source_ref"]))
        except (KeyError, ValueError, PermissionError):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "VHOST_SOURCE_UNPROVEN")
        if hashlib.sha256(host.encode()).hexdigest() != frozen.get("host_sha256"):
            return _decision(ValidationStatus.INVALID_TEST, "VHOST_HOST_BINDING_CHANGED")
        observations = {item.step.action_slot: item for item in context.observations}
        if set(observations) != {0, 1, 2}:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "VHOST_THREE_CONTROLS_MISSING")
        normal, invalid, routed = (observations[index] for index in (0, 1, 2))
        expected_hosts = (None,
                          "invalid-" + hashlib.sha256(context.run.id.encode()).hexdigest()[:16]
                          + ".invalid", host)
        for index, item in enumerate((normal, invalid, routed)):
            if (not item.audit_valid or item.actor != "ANONYMOUS" or
                    item.exchange.request.record.method != "GET" or
                    item.exchange.response is None or
                    item.exchange.response.record.status_code is None):
                return _decision(ValidationStatus.INVALID_TEST, "VHOST_CONTROL_UNTRUSTED")
            ref = item.exchange.request.observation_evidence_id
            try:
                observed = json.loads(engine.evidence.read_content(
                    ref, allow_sensitive=True, max_bytes=8192))
                headers = {str(name).lower(): value for name, value in observed["headers"]}
                if (observed["url"] != frozen["url"] or
                        headers.get("host") != expected_hosts[index]):
                    return _decision(ValidationStatus.INVALID_TEST, "VHOST_HOST_OR_DESTINATION_MISMATCH")
            except (KeyError, TypeError, ValueError, PermissionError):
                return _decision(ValidationStatus.INVALID_TEST, "VHOST_REQUEST_EVIDENCE_MISSING")
        refs = tuple(dict.fromkeys((str(frozen["evidence_id"]),
                                    *(ref for item in (normal, invalid, routed)
                                      for ref in item.evidence_ids[:4]))))[:32]
        if routed.features.status_code in _DENIED:
            return _decision(ValidationStatus.REJECTED, "INTERNAL_VHOST_DENIED",
                             contradicting=refs)
        if (routed.features.status_code != 200 or not routed.features.body_hash or
                routed.features.body_hash in {normal.features.body_hash,
                                              invalid.features.body_hash}):
            return _decision(ValidationStatus.REJECTED, "VHOST_NOT_DISTINCT_OR_NOT_REACHABLE",
                             contradicting=refs)
        def captured_body(item: Observation) -> bytes | None:
            for ref in item.evidence_ids:
                record = engine.evidence.get_evidence(ref)
                if (record is None or record.target_ref != context.run.target_id or
                        record.evidence_type != EvidenceType.HTTP_RESPONSE.value or
                        record.source != "controlled_asset_fetch" or
                        record.redaction_status.value != "ORIGINAL" or
                        record.content_hash != item.features.body_hash or
                        record.content_size > 65_536):
                    continue
                try:
                    return engine.evidence.read_content(ref, allow_sensitive=True,
                                                        max_bytes=65_536)
                except (KeyError, ValueError, PermissionError):
                    return None
            return None
        body = captured_body(routed)
        if body is None:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "VHOST_PROTECTED_BYTES_UNAVAILABLE", supporting=refs)
        analysis = engine.exposure.analyzer.analyze_js(body)
        credential = next((signal for signal in analysis.signals
                           if signal.status is ExposureStatus.FORMAT_VALID and
                           signal.credential_type in {"CLIENT_SECRET", "PASSWORD",
                                                      "PRIVATE_KEY", "CONNECTION_STRING",
                                                      "KNOWN_FORMAT_TOKEN"}), None)
        if credential is None:
            return _decision(ValidationStatus.REJECTED, "VHOST_NO_PROTECTED_EFFECT",
                             contradicting=refs)
        for item in (normal, invalid):
            comparison = captured_body(item)
            if comparison is not None and any(
                    signal.fingerprint_sha256 == credential.fingerprint_sha256
                    for signal in engine.exposure.analyzer.analyze_js(comparison).signals):
                return _decision(ValidationStatus.REJECTED, "VHOST_SECRET_ON_CONTROL_ROUTE",
                                 contradicting=refs)
        checks = (_check("EXPLICIT_SCOPE_AND_POLICY", True, refs[:1]),
                  _check("THREE_AUDITED_HOST_CONTROLS", True, refs[:4]),
                  _check("CANDIDATE_ONLY_PROTECTED_CONTENT", True, refs[-4:]))
        finding = FindingSpec(
            "INTERNAL_SURFACE_EXPOSURE", _digest(context.run.target_id + ":" + candidate_id),
            _digest(str(frozen["url"])), None,
            "Internal virtual host exposes non-public configuration",
            "A sourced internal Host routed an unauthenticated scoped request to configuration containing non-public credential material; normal and invalid Host controls did not.",
            "INTERNAL_VHOST_CREDENTIAL_DISCLOSURE", None, "MEDIUM")
        return _decision(ValidationStatus.CONFIRMED, "INTERNAL_VHOST_PROTECTED_CONTENT",
                         checks=checks, controls=("NORMAL_HOST", "INVALID_HOST", "SOURCED_HOST"),
                         supporting=refs, reproductions=1,
                         impact="INTERNAL_VHOST_CREDENTIAL_DISCLOSURE", finding=finding)


class ExposureArtifactValidator:
    """Validate an exact protected JS/map artifact without using the discovered value."""

    id = "credential_artifact_exposure"
    version = "1.0.0"

    def evaluate(self, context: ValidationContext,
                 engine: DeterministicValidatorEngine) -> ValidatorDecision:
        frozen = context.plan.get("exposure_binding")
        if (engine.exposure is None or engine.targets is None or not isinstance(frozen, dict)
                or context.plan.get("skill_id") != "credential-disclosure"):
            return _decision(ValidationStatus.INVALID_TEST, "EXPOSURE_BINDING_MISSING")
        package = engine.targets.get_target_package(context.run.package_id)
        if package is None or package.target.id != context.run.target_id:
            return _decision(ValidationStatus.INVALID_TEST, "TARGET_PACKAGE_MISSING")
        candidate_id = frozen.get("candidate_id")
        if not isinstance(candidate_id, str):
            return _decision(ValidationStatus.INVALID_TEST, "EXPOSURE_BINDING_INVALID")
        candidate = engine.exposure.current_candidate(package, candidate_id)
        if candidate is None:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "CURRENT_ARTIFACT_UNPROVEN")
        link = next((item for item in engine.exposure.store.source_links(
            context.run.target_id, candidate_id) if item["current"] and
            all(item.get(key) == frozen.get(key) for key in
                ("source_ref", "evidence_id", "artifact_sha256")) and
            item["source"] == frozen.get("source")), None)
        if (link is None or candidate.credential is None or
                candidate.credential.fingerprint_sha256 != frozen.get("credential_fingerprint") or
                candidate.artifact_sha256 != frozen.get("artifact_sha256") or
                candidate.source not in {ExposureSource.JS_ASSET, ExposureSource.SOURCE_MAP}):
            return _decision(ValidationStatus.INVALID_TEST, "ARTIFACT_BINDING_MISMATCH")
        source_ref = str(link["source_ref"])
        if candidate.source is ExposureSource.JS_ASSET:
            asset = engine.exposure.dom.get_asset(context.run.target_id, source_ref)
            retrieval_id = asset.retrieval_exchange_id if asset else None
        else:
            source_map = engine.exposure.dom.get_source_map_by_id(context.run.target_id, source_ref)
            asset = (engine.exposure.dom.get_asset(context.run.target_id, source_map.js_artifact_id)
                     if source_map else None)
            retrieval_id = source_map.retrieval_exchange_id if source_map else None
        if asset is None:
            return _decision(ValidationStatus.INVALID_TEST, "ARTIFACT_SOURCE_MISSING")
        source_evidence = engine.evidence.get_evidence(str(link["evidence_id"]))
        if (source_evidence is None or source_evidence.target_ref != context.run.target_id
                or source_evidence.sensitivity.value != "SENSITIVE"
                or source_evidence.content_hash != frozen["artifact_sha256"]
                or source_evidence.redaction_status.value != "ORIGINAL"):
            return _decision(ValidationStatus.INVALID_TEST, "PROTECTED_SOURCE_INVALID")
        retrieval_refs: tuple[str, ...] = ()
        if asset.source == "CONTROLLED_HTTP":
            exchange = engine.traffic.get_exchange(retrieval_id) if retrieval_id else None
            if (exchange is None or exchange.state is not ExchangeState.COMPLETE
                    or exchange.target_id != context.run.target_id or
                    exchange.package_id != package.id or exchange.scope_result is not ScopeResult.IN_SCOPE
                    or exchange.attribution.auth_state is not AuthState.ANONYMOUS
                    or exchange.response is None or exchange.response.record.status_code != 200
                    or exchange.response.body_hash != frozen["artifact_sha256"]):
                return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                                 "ANONYMOUS_CONTROLLED_RETRIEVAL_UNPROVEN")
            retrieval_refs = tuple(dict.fromkeys((*exchange.request.record.evidence_ids[:2],
                                                   *exchange.response.record.evidence_ids[:2])))
        elif asset.source != "FIXTURE" or not package.primary_domain.endswith(".test"):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "CONTROLLED_RETRIEVAL_REQUIRED")
        try:
            body = engine.evidence.read_content(
                source_evidence.evidence_id, allow_sensitive=True,
                max_bytes=MAX_JS_SCAN_BYTES if candidate.source is ExposureSource.JS_ASSET
                else MAX_MAP_SCAN_BYTES)
        except (KeyError, ValueError, PermissionError):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "ARTIFACT_BYTES_UNAVAILABLE")
        if hashlib.sha256(body).hexdigest() != frozen["artifact_sha256"]:
            return _decision(ValidationStatus.INVALID_TEST, "ARTIFACT_HASH_MISMATCH")
        analysis = (engine.exposure.analyzer.analyze_js(body)
                    if candidate.source is ExposureSource.JS_ASSET else
                    engine.exposure.analyzer.analyze_source_map(body))
        signal = next((item for item in analysis.signals if
                       item.fingerprint_sha256 == frozen["credential_fingerprint"]), None)
        refs = tuple(dict.fromkeys((source_evidence.evidence_id, *retrieval_refs)))[:16]
        checks = (_check("CURRENT_ARTIFACT", True, refs),
                  _check("ANONYMOUS_PUBLIC_RETRIEVAL", True, refs),
                  _check("CREDENTIAL_PRESENT", signal is not None, refs))
        if signal is None or analysis.truncated or analysis.parse_error:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "CREDENTIAL_SIGNAL_UNPROVEN", checks=checks)
        if signal.status in {ExposureStatus.REJECTED_PUBLIC, ExposureStatus.REJECTED_PLACEHOLDER}:
            return _decision(ValidationStatus.REJECTED,
                             "PUBLIC_OR_PLACEHOLDER_VALUE", checks=checks,
                             contradicting=refs)
        used = "APPLICATION_REQUEST_USAGE" in signal.reason_codes
        sensitive_type = signal.credential_type in {
            "CLIENT_SECRET", "PASSWORD", "TOKEN", "API_KEY", "CONNECTION_STRING",
            "KNOWN_FORMAT_TOKEN", "PRIVATE_KEY", "SECRET"}
        checks += (_check("NON_PUBLIC_CREDENTIAL", sensitive_type, refs),
                   _check("APPLICATION_REQUEST_USAGE", used, refs),
                   _check("TARGET_RELEVANCE", signal.service_class in {
                       "APPLICATION", "DATABASE", "CLOUD", "GITHUB"} and used, refs))
        if not sensitive_type or signal.status is ExposureStatus.NEEDS_RESEARCH:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "CREDENTIAL_SEMANTICS_UNPROVEN", checks=checks)
        if not used:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "APPLICATION_USE_UNPROVEN", checks=checks)
        root = _digest(context.run.target_id + ":" + signal.fingerprint_sha256)
        finding = FindingSpec(
            "CREDENTIAL_DISCLOSURE", root, _digest(candidate.location), None,
            "Non-public application credential in current first-party asset",
            "An anonymous visitor can retrieve a current first-party asset containing a non-public credential used in application request construction.",
            "NON_PUBLIC_APPLICATION_CREDENTIAL_DISCLOSED", None, "MEDIUM")
        return _decision(ValidationStatus.CONFIRMED,
                         "CURRENT_APPLICATION_CREDENTIAL_EXPOSED", checks=checks,
                         controls=("CURRENT_HASH", "ANONYMOUS_RETRIEVAL", "PUBLIC_IDENTIFIER_FILTER"),
                         supporting=refs, reproductions=1,
                         impact="NON_PUBLIC_APPLICATION_CREDENTIAL_DISCLOSED", finding=finding)


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


class PostMessageValidator:
    id = "postmessage_cross_origin_capability"
    version = "1.0.0"

    @staticmethod
    def _trace_valid(trial: dict[str, object], expected_method: object) -> bool:
        return (trial.get("rpc_method") == expected_method
                and PostMessageBrowserExperimentExecutor.trace_is_valid(
                    trial.get("event_trace"),
                    source_attested=trial.get("source_attested"),
                    message_count=trial.get("message_count"),
                    port_count=trial.get("port_count"),
                    rpc_calls=trial.get("rpc_calls"),
                    effect_kind=trial.get("effect_kind")))

    @staticmethod
    def _owned_denial_exchange(engine: DeterministicValidatorEngine, run: PlanRun,
                               owned, first_trial_at: datetime) -> tuple[bool, tuple[str, ...]]:
        if not owned.external_id_evidence_id:
            return False, ()
        try:
            external = engine.evidence.read_content(
                owned.external_id_evidence_id, allow_sensitive=True, max_bytes=256).decode("ascii")
            verified_at = datetime.fromisoformat(owned.verified_at)
        except (ValueError, UnicodeError, PermissionError, TypeError):
            return False, ()
        package = engine.targets.get_target_package(run.package_id) if engine.targets else None
        if package is None:
            return False, ()
        with engine.evidence._connection() as db:
            rows = db.execute("""SELECT r.observation_evidence_id AS request_ref,
                p.observation_evidence_id AS response_ref, e.observed_at
                FROM traffic_exchanges e
                JOIN traffic_requests r ON r.request_id=e.request_id
                JOIN traffic_responses p ON p.request_id=e.request_id
                WHERE e.target_id=? AND e.package_id=? AND e.auth_state='ANONYMOUS'
                  AND e.source='HACKBOT' AND e.capture_provider='HACKBOT'
                  AND e.scope_result='IN_SCOPE' AND e.state='COMPLETE'
                  AND r.method='GET' AND p.status_code IN (401,403)
                ORDER BY e.observed_at DESC LIMIT 50""",
                (run.target_id, run.package_id)).fetchall()
        for row in rows:
            refs = (row["request_ref"], row["response_ref"])
            try:
                observed = datetime.fromisoformat(row["observed_at"])
                if not verified_at <= observed <= first_trial_at:
                    continue
                request = json.loads(engine.evidence.read_content(
                    refs[0], allow_sensitive=True, max_bytes=4096))
                url = request.get("url") if isinstance(request, dict) else None
                parsed = urlsplit(url) if isinstance(url, str) else None
                if (parsed is None or package.scope.evaluate_url(url).result
                        is not ScopeResult.IN_SCOPE):
                    continue
                values = (*[unquote(part) for part in parsed.path.split("/")],
                          *[value for key, value in parse_qsl(parsed.query,
                                                               keep_blank_values=True)
                            if key.lower().replace("-", "_") in {"id", "uuid", "object_id"}
                            or key.lower().replace("-", "_").endswith("_id")])
                if external in values:
                    return True, refs
            except (ValueError, UnicodeError, PermissionError, TypeError):
                continue
        return False, ()

    def evaluate(self, context: ValidationContext,
                 engine: DeterministicValidatorEngine) -> ValidatorDecision:
        run, frozen = context.run, context.plan.get("message_binding")
        if engine.messages is None or engine.targets is None or not isinstance(frozen, dict):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "MESSAGE_VALIDATOR_DEPENDENCY_MISSING")
        package = engine.targets.get_target_package(run.package_id)
        candidate_id = frozen.get("candidate_id")
        if (package is None or package.target.id != run.target_id
                or not isinstance(candidate_id, str)
                or not re.fullmatch(r"MSG-[0-9a-f]{32}", candidate_id)):
            return _decision(ValidationStatus.INVALID_TEST, "MESSAGE_TARGET_OR_BINDING_INVALID")
        candidate = engine.messages.get_candidate(run.target_id, candidate_id)
        asset = engine.messages.current_asset(run.target_id, candidate_id)
        route, asset_url = frozen.get("route_url"), frozen.get("asset_url")
        window_mode = frozen.get("window_mode")
        current = (candidate is not None and asset is not None
                   and candidate.transport_kind == "WINDOW"
                   and asset.recon_sha256 == asset.artifact_sha256
                   and asset.artifact_sha256 in candidate.asset_hashes
                   and isinstance(route, str) and isinstance(asset_url, str)
                   and candidate.route == route and asset.asset_url_sha256 == _digest(asset_url)
                   and package.scope.evaluate_url(route).result is ScopeResult.IN_SCOPE
                   and package.scope.evaluate_url(asset_url).result is ScopeResult.IN_SCOPE)
        current = (current and window_mode in {"IFRAME", "POPUP"}
                   and (window_mode != "POPUP" or "OPENER" in candidate.sender_contexts))
        checks = [_check("CURRENT_MESSAGING_BUNDLE", current,
                         (asset.evidence_id,) if asset else ())]
        if not current:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "MESSAGE_CURRENT_ASSET_UNVERIFIED", checks=tuple(checks))
        assert candidate is not None and asset is not None
        links = engine.messages.links(run.target_id, candidate_id)
        if (links is None or links["hypothesis_id"] != run.hypothesis_id
                or links["plan_id"] != run.plan_id or links["run_id"] != run.id):
            return _decision(ValidationStatus.INVALID_TEST, "MESSAGE_AUDIT_BINDING_INVALID",
                             checks=tuple(checks))
        step = next((item for item in engine.runs.steps(run.id)
                     if item.type == "VERIFY_BROWSER"), None)
        result = engine.runs.result(step.id) if step else None
        if (step is None or step.status is not RuntimeStepStatus.COMPLETED
                or result is None or not 4 <= len(result.evidence_ids) <= 8):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "MESSAGE_BROWSER_CONTROLS_MISSING", checks=tuple(checks))
        with engine.evidence._connection() as db:
            dispatches = db.execute("""SELECT variant FROM plan_message_dispatches
                WHERE run_id=? ORDER BY accounted_at,rowid""", (run.id,)).fetchall()
        trials: list[dict[str, object]] = []
        trial_times: list[datetime] = []
        for ref in result.evidence_ids:
            evidence = engine.evidence.get_evidence(ref)
            if (evidence is None or evidence.target_ref != run.target_id
                    or evidence.evidence_type != EvidenceType.MESSAGE_PROOF.value
                    or evidence.source != "postmessage_browser"
                    or evidence.provenance.record_id != candidate_id):
                return _decision(ValidationStatus.INVALID_TEST,
                                 "MESSAGE_EVIDENCE_PROVENANCE_INVALID", checks=tuple(checks))
            try:
                trial = json.loads(engine.evidence.read_content(
                    ref, allow_sensitive=True, max_bytes=8192))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError, PermissionError):
                return _decision(ValidationStatus.INVALID_TEST,
                                 "MESSAGE_EVIDENCE_UNREADABLE", checks=tuple(checks))
            if (not isinstance(trial, dict) or trial.get("candidate_id") != candidate_id
                    or trial.get("run_id") != run.id
                    or trial.get("browser_session_id") != frozen.get("browser_session_id")
                    or trial.get("route_sha256") != _digest(route)
                    or trial.get("asset_sha256") != _digest(asset_url)
                    or trial.get("owned_object_id") !=
                    (frozen.get("owned_object_id") or None)
                    or trial.get("owned_canary_sha256") !=
                    (frozen.get("owned_canary_sha256") or None)
                    or trial.get("victim_bundle_sha256") != asset.artifact_sha256
                    or not re.fullmatch(r"MSGCTX-[0-9a-f]{32}", str(trial.get("context_id")))
                    or type(trial.get("capability_observed")) is not bool
                    or type(trial.get("source_attested")) is not bool
                    or not self._trace_valid(trial, frozen.get("allowed_method") or None)
                    or any(type(trial.get(name)) is not int or trial[name] < 0 or
                           trial[name] > maximum for name, maximum in
                           (("message_count", 3), ("port_count", 1), ("rpc_calls", 1),
                            ("request_count", 24), ("denial_count", 24),
                            ("rate_reserved_count", 24), ("rate_released_count", 24)))):
                return _decision(ValidationStatus.INVALID_TEST,
                                 "MESSAGE_EVIDENCE_BINDING_INVALID", checks=tuple(checks))
            trials.append(trial)
            trial_times.append(evidence.created_at)
        variants = [item["variant"] for item in trials]
        order = (variants[:3] == ["NO_MESSAGE", "WRONG_TYPE", "TRUSTED"]
                 and variants == [row["variant"] for row in dispatches]
                 and variants[-1] in {"UNRELATED", "ATTACKER_PORT", "FRESH_REPRODUCTION",
                                      "FRESH_WRONG_SOURCE", "LOOKALIKE_ORIGIN",
                                      "FRESH_LOOKALIKE_ORIGIN"}
                 and len(variants) == len(set(variants)))
        checks.append(_check("MESSAGE_CONTROL_SEQUENCE", order, result.evidence_ids))
        if not order:
            return _decision(ValidationStatus.INVALID_TEST, "MESSAGE_CONTROL_SEQUENCE_INVALID",
                             checks=tuple(checks))
        policy_ok = True
        with engine.evidence._connection() as db:
            for trial in trials:
                ids = trial.get("policy_decision_ids")
                if (not isinstance(ids, list) or not 2 <= len(ids) <= 24
                        or trial.get("rate_limiter") != "PHASE14_SHARED"
                        or trial["request_count"] != len(ids)
                        or trial["rate_reserved_count"] != trial["request_count"]
                        or trial["rate_released_count"] != trial["rate_reserved_count"]
                        or trial["denial_count"] or trial.get("error_code")):
                    policy_ok = False
                    break
                navigations = 0
                for decision_id in ids:
                    row = db.execute("""SELECT d.result,d.scope_result,d.target_id,
                        a.package_id,a.category,a.actor,a.method,a.source,a.vulnerability_class
                        FROM policy_decisions d JOIN policy_actions a ON a.action_id=d.action_id
                        WHERE d.decision_id=?""", (decision_id,)).fetchone()
                    if (row is None or row["result"] != "ALLOW" or row["scope_result"] != "IN_SCOPE"
                            or row["target_id"] != run.target_id
                            or row["package_id"] != run.package_id
                            or row["category"] not in {"BROWSER_NAVIGATION", "SAFE_READ"}
                            or row["actor"] != ("AUTHENTICATED" if frozen.get("identity_id")
                                                 else "ANONYMOUS")
                            or row["method"] not in {"GET", "HEAD"}
                            or row["source"] != "postmessage_browser"
                            or row["vulnerability_class"] != "postmessage"):
                        policy_ok = False
                        break
                    navigations += row["category"] == "BROWSER_NAVIGATION"
                if not policy_ok or navigations < 1:
                    policy_ok = False
                    break
        checks.append(_check("POLICY_SCOPE_EACH_TRIAL", policy_ok, result.evidence_ids))
        if not policy_ok:
            return _decision(ValidationStatus.INVALID_TEST, "MESSAGE_POLICY_AUDIT_INVALID",
                             checks=tuple(checks))
        controls = all(not item["capability_observed"] for item in trials[:2])
        if candidate.port_accepted:
            controls = controls and trials[1]["port_count"] == 1
            if frozen.get("allowed_method"):
                controls = controls and trials[1]["rpc_calls"] == 1
        if "NO_PORT" in variants:
            controls = controls and not trials[variants.index("NO_PORT")]["capability_observed"]
        checks.append(_check("NO_MESSAGE_WRONG_TYPE_PORT_CONTROLS", controls,
                             result.evidence_ids[:4]))
        if not controls:
            return _decision(ValidationStatus.INVALID_TEST, "MESSAGE_NEGATIVE_CONTROL_FAILED",
                             checks=tuple(checks), contradicting=result.evidence_ids[:4])
        proof_index = next((index for index, item in enumerate(trials)
                            if item["variant"] in {"UNRELATED", "ATTACKER_PORT",
                                                    "LOOKALIKE_ORIGIN"}
                            and item["capability_observed"]), None)
        if proof_index is None:
            proof_index = next((index for index, item in enumerate(trials)
                                if item["variant"] == "WRONG_SOURCE"
                                and item["capability_observed"]), None)
        if proof_index is None:
            return _decision(ValidationStatus.REJECTED, "MESSAGE_UNTRUSTED_SENDER_DENIED",
                             checks=tuple(checks), contradicting=result.evidence_ids)
        proof = trials[proof_index]
        attested = all(trials[index].get("source_attested") is True
                       for index in (2, proof_index, len(trials) - 1)
                       if index < len(trials))
        checks.append(_check("FIXTURE_SENDER_WINDOW_ATTESTED", attested,
                             (result.evidence_ids[proof_index],)))
        if not attested:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "MESSAGE_SENDER_REFERENCE_UNVERIFIED", checks=tuple(checks))
        source_only = proof["variant"] == "WRONG_SOURCE"
        lookalike = proof["variant"] == "LOOKALIKE_ORIGIN"
        expected_origin = f"{urlsplit(route).scheme}://{urlsplit(route).netloc}"
        expected_probe_origin = None
        if lookalike:
            try:
                expected_probe_origin = lookalike_origin(route, candidate.origin_validation)
            except ValueError:
                pass
        expected_relationship = ("FIXTURE_OPENER_OF_VICTIM" if window_mode == "POPUP"
                                 else "FIXTURE_PARENT_OF_VICTIM")
        untrusted_context = (
            proof.get("attacker_origin") == expected_origin
            and proof.get("source_relationship") == "SIBLING_FRAME"
            and "PARENT" in candidate.sender_contexts
        ) if source_only else (
            expected_probe_origin is not None
            and proof.get("attacker_origin") == expected_probe_origin
            and candidate.origin_validation in {"SUBSTRING", "STARTSWITH", "ENDSWITH",
                                                "REGEX_REVIEW", "WEAK_COMPARISON"}
            and package.scope.evaluate_url(proof["attacker_origin"] + "/").result
            is not ScopeResult.IN_SCOPE
            and proof.get("source_relationship") == expected_relationship
        ) if lookalike else (
            proof.get("attacker_origin") == "http://attacker.fixture.invalid"
            and package.scope.evaluate_url(proof["attacker_origin"] + "/").result
            is not ScopeResult.IN_SCOPE
            and proof.get("source_relationship") == expected_relationship
        )
        checks.append(_check("UNTRUSTED_ORIGIN_OR_WINDOW", untrusted_context,
                             (result.evidence_ids[proof_index],)))
        if not untrusted_context:
            return _decision(ValidationStatus.INVALID_TEST, "MESSAGE_ATTACKER_CONTEXT_INVALID",
                             checks=tuple(checks))
        if source_only and asset.source != "FIXTURE":
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "MESSAGE_SAME_ORIGIN_SENDER_CONTROL_UNPROVEN",
                             checks=tuple(checks), supporting=result.evidence_ids)
        dom_handoff = (DOMXSSValidator.message_handoff(engine, package, candidate,
                                                       asset, frozen, proof)
                       if proof.get("effect_kind") == "DOM_EXECUTION" else None)
        def port_proof(trial: dict[str, object]) -> bool:
            if not candidate.port_accepted or trial.get("effect_kind") == "DOM_EXECUTION":
                return True
            events = [entry[0] for entry in trial["event_trace"]]
            if (trial.get("port_count") != 1 or trial.get("rpc_calls") != 1
                    or "PORT_TRANSFERRED" not in events):
                return False
            if frozen.get("port_type") and (
                    "READY_RECEIVED" not in events or
                    events.index("READY_RECEIVED") > events.index("PORT_TRANSFERRED")):
                return False
            return True

        owned = None
        if proof.get("effect_kind") == "OWNED_DATA":
            object_id = frozen.get("owned_object_id")
            identity_id = frozen.get("identity_id")
            if (isinstance(object_id, str) and isinstance(identity_id, str)
                    and identity_id and frozen.get("allowed_method") == "readCanary"):
                owned = verified_owned_canary(
                    ObjectRegistry(engine.evidence), engine.evidence,
                    target_id=run.target_id, package_id=run.package_id,
                    plan_id=run.plan_id, run_id=run.id, identity_id=identity_id,
                    object_id=object_id,
                    canary_sha256=str(frozen.get("owned_canary_sha256") or ""),
                    verified_at=str(frozen.get("owned_verified_at") or ""),
                    active=False)
            if owned is not None:
                with engine.evidence._connection() as db:
                    reservation = db.execute("SELECT created_at,expires_at,released_at "
                        "FROM test_object_reservations WHERE test_object_id=? AND "
                        "holder_run_id=? ORDER BY created_at DESC LIMIT 1",
                        (owned.id, run.id)).fetchone()
                try:
                    reserved_at = datetime.fromisoformat(reservation["created_at"])
                    expires_at = datetime.fromisoformat(reservation["expires_at"])
                    released_at = (datetime.fromisoformat(reservation["released_at"])
                                   if reservation["released_at"] else None)
                    during_reservation = all(
                        reserved_at <= moment <= expires_at and
                        (released_at is None or moment <= released_at)
                        for moment in trial_times)
                except (TypeError, ValueError):
                    during_reservation = False
                if not during_reservation:
                    owned = None
        protected = (dom_handoff is not None if proof.get("effect_kind") == "DOM_EXECUTION"
                     else proof.get("effect_kind") == "SYNTHETIC_DATA"
                     and proof.get("effect_fingerprint") ==
                     _digest("HACKBOT_SYNTHETIC_PRIVATE")
                     and port_proof(proof)
                     or proof.get("effect_kind") == "OWNED_DATA"
                     and owned is not None
                     and proof.get("effect_fingerprint") ==
                     frozen.get("owned_canary_sha256")
                     and port_proof(proof))
        checks.append(_check("PROTECTED_MESSAGING_CAPABILITY", protected,
                             (result.evidence_ids[proof_index],)))
        if not protected:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "MESSAGE_CAPABILITY_IMPACT_UNCLASSIFIED", checks=tuple(checks))
        if proof.get("effect_kind") == "SYNTHETIC_DATA":
            fixture_only = asset.source == "FIXTURE"
            checks.append(_check("SYNTHETIC_MARKER_FIXTURE_PROVENANCE", fixture_only,
                                 (asset.evidence_id, result.evidence_ids[proof_index])))
            if not fixture_only:
                return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                                 "MESSAGE_SYNTHETIC_FIXTURE_ONLY", checks=tuple(checks),
                                 supporting=result.evidence_ids)
        privacy_refs: tuple[str, ...] = ()
        if owned is not None and asset.source != "FIXTURE":
            visibility, visibility_refs = engine.fact_value(
                owned.id, "resource_visibility", run.target_id)
            observed_denial, exchange_refs = self._owned_denial_exchange(
                engine, run, owned, min(trial_times))
            privacy_refs = tuple(dict.fromkeys((*visibility_refs, *exchange_refs)))
            private = visibility == "PRIVATE" and observed_denial
            checks.append(_check("OWNED_CANARY_PRIVATE_AND_PUBLIC_READ_DENIED",
                                 private, privacy_refs))
            if not private:
                return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                                 "MESSAGE_OWNED_DATA_PRIVACY_UNPROVEN",
                                 checks=tuple(checks), supporting=result.evidence_ids)
        reproduction = trials[-1] if variants[-1] == (
            "FRESH_WRONG_SOURCE" if source_only else
            "FRESH_LOOKALIKE_ORIGIN" if lookalike else "FRESH_REPRODUCTION") else None
        trusted = trials[2]
        fresh = (reproduction is not None and trusted.get("capability_observed") is True
                 and trusted.get("effect_kind") == proof.get("effect_kind")
                 and port_proof(trusted)
                 and (trusted.get("effect_fingerprint") != proof.get("effect_fingerprint")
                      and DOMXSSValidator.message_handoff(engine, package, candidate,
                                                           asset, frozen, trusted) == dom_handoff
                      if dom_handoff else trusted.get("effect_fingerprint") ==
                      proof.get("effect_fingerprint"))
                 and reproduction.get("capability_observed") is True
                 and reproduction.get("effect_kind") == proof.get("effect_kind")
                 and port_proof(reproduction)
                 and (reproduction.get("effect_fingerprint") != proof.get("effect_fingerprint")
                      and DOMXSSValidator.message_handoff(engine, package, candidate,
                                                           asset, frozen, reproduction) == dom_handoff
                      if dom_handoff else reproduction.get("effect_fingerprint") ==
                      proof.get("effect_fingerprint"))
                 and reproduction.get("attacker_origin") == proof.get("attacker_origin")
                 and reproduction.get("source_relationship") == proof.get("source_relationship")
                 and reproduction.get("context_id") != proof.get("context_id")
                 and len({item["context_id"] for item in trials}) == len(trials))
        checks.append(_check("FRESH_MESSAGING_CONTEXT", fresh,
                             (result.evidence_ids[proof_index], result.evidence_ids[-1])))
        if not fresh or candidate.status is not MessageCandidateStatus.VALIDATION_READY:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "MESSAGE_FRESH_REPRODUCTION_MISSING", checks=tuple(checks))
        map_ref = ()
        if candidate.source_map_sha256:
            with engine.evidence._connection() as db:
                mapped = db.execute("""SELECT evidence_id FROM dom_source_maps WHERE target_id=?
                    AND js_artifact_id=? AND map_sha256=? LIMIT 1""",
                    (run.target_id, asset.artifact_id, candidate.source_map_sha256)).fetchone()
            if mapped is None:
                return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                                 "MESSAGE_SOURCE_MAP_PROVENANCE_MISSING", checks=tuple(checks))
            map_ref = (mapped["evidence_id"],)
        root_key = _digest("|".join((run.target_id, candidate.handler_fingerprint,
                                      "MESSAGE_DOM_XSS" if dom_handoff else
                                      "CROSS_ORIGIN_MESSAGE_CAPABILITY")))
        surface = _digest("|".join((run.target_id, route,
                                     ",".join(candidate.message_types))))
        owned_disclosure = owned is not None and proof.get("effect_kind") == "OWNED_DATA"
        finding = (FindingSpec(
            "DOM_XSS", root_key, surface, "BROWSER_MESSAGE",
            "Cross-origin message executes script in the target document",
            "A controlled unauthorized browser context reached a Phase 21 HTML sink.",
            "BROWSER_SCRIPT_EXECUTION_IN_TARGET_ORIGIN", preliminary_severity="MEDIUM")
            if dom_handoff else FindingSpec(
                "POSTMESSAGE", root_key, surface, "BROWSER_MESSAGE_PORT" if candidate.port_accepted
                else "BROWSER_MESSAGE", "Untrusted window receives a protected messaging capability",
                "A controlled unauthorized browser context received " +
                ("a verified owned test-object canary." if owned_disclosure else
                 "synthetic protected fixture data."),
                "CROSS_ORIGIN_OWNED_TEST_DATA_DISCLOSURE" if owned_disclosure else
                "CROSS_ORIGIN_SYNTHETIC_DATA_DISCLOSURE", preliminary_severity="MEDIUM"))
        supporting = tuple(dict.fromkeys((*candidate.evidence_ids, asset.evidence_id,
                                          *(dom_handoff.evidence_ids if dom_handoff else ()),
                                          *(owned.verification_evidence_ids if owned else ()),
                                          *privacy_refs,
                                          *map_ref, *result.evidence_ids)))[:64]
        impact = ("BROWSER_SCRIPT_EXECUTION_IN_TARGET_ORIGIN" if dom_handoff else
                  "CROSS_ORIGIN_OWNED_TEST_DATA_DISCLOSURE" if owned_disclosure else
                  "CROSS_ORIGIN_SYNTHETIC_DATA_DISCLOSURE")
        return _decision(ValidationStatus.CONFIRMED,
                         "DOM_MESSAGE_BROWSER_EXECUTION_REPRODUCED" if dom_handoff else
                         "MESSAGE_CAPABILITY_REPRODUCED",
                         checks=tuple(checks), controls=("NO_MESSAGE", "WRONG_TYPE", "TRUSTED",
                                                         "NO_PORT" if candidate.port_accepted else "NO_PORT_NA",
                                                         "WRONG_SOURCE" if source_only else
                                                         "LOOKALIKE_ORIGIN" if lookalike
                                                         else "UNRELATED_ORIGIN", "FRESH_CONTEXT"),
                         supporting=supporting, reproductions=2,
                         impact=impact, finding=finding)


class DOMXSSValidator:
    id = "dom_xss_browser_execution"
    version = "1.0.0"

    @staticmethod
    def message_handoff(engine: DeterministicValidatorEngine, package, message_candidate,
                        message_asset, frozen: dict[str, object], trial: dict[str, object]):
        """Validate message-source execution against a current Phase 21 sink trace."""
        field = frozen.get("dom_field")
        if (engine.dom is None or not isinstance(field, str)
                or field != engine.messages.dom_xss_field(package.target.id,
                                                            message_candidate.candidate_id)
                or trial.get("effect_kind") != "DOM_EXECUTION"
                or trial.get("capability_observed") is not True
                or not re.fullmatch(r"[0-9a-f]{64}", str(trial.get("effect_fingerprint")))
                or trial.get("marker_context") not in {"MAIN", "IFRAME"}
                or not isinstance(trial.get("document_origin"), str)
                or trial["document_origin"] !=
                f"{urlsplit(str(frozen.get('route_url'))).scheme}://"
                f"{urlsplit(str(frozen.get('route_url'))).netloc}"
                or package.scope.evaluate_url(trial["document_origin"] + "/").result
                is not ScopeResult.IN_SCOPE):
            return None
        for candidate_id in engine.messages.dom_xss_handoffs(package.target.id,
                                                               message_candidate.candidate_id):
            flow = engine.dom.get_candidate(package.target.id, candidate_id)
            flow_asset = engine.dom.candidate_asset(package.target.id, candidate_id)
            if (flow is not None and flow_asset is not None
                    and flow_asset.artifact_id == message_asset.artifact_id
                    and flow.asset_sha256 == message_asset.artifact_sha256
                    and flow.source in {f"event.data.{field}", f"e.data.{field}",
                                        f"messageEvent.data.{field}"}
                    and flow.sink_kind == "HTML_EXECUTION"
                    and not flow.sanitizers and not flow.post_checks
                    and not flow.unresolved_helper):
                return flow
        return None

    def evaluate(self, context: ValidationContext,
                 engine: DeterministicValidatorEngine) -> ValidatorDecision:
        run, frozen = context.run, context.plan.get("dom_binding")
        if engine.dom is None or engine.targets is None or not isinstance(frozen, dict):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE,
                             "DOM_VALIDATOR_DEPENDENCY_MISSING")
        package = engine.targets.get_target_package(run.package_id)
        if package is None or package.target.id != run.target_id:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "DOM_TARGET_PACKAGE_MISSING")
        candidate_id = frozen.get("candidate_id")
        if not isinstance(candidate_id, str) or not re.fullmatch(r"DOM-[0-9a-f]{32}", candidate_id):
            return _decision(ValidationStatus.INVALID_TEST, "DOM_PLAN_BINDING_INVALID")
        candidate = engine.dom.get_candidate(run.target_id, candidate_id)
        asset = engine.dom.candidate_asset(run.target_id, candidate_id)
        if candidate is None or asset is None:
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "DOM_STATIC_TRACE_MISSING")
        route, asset_url = frozen.get("route_url"), frozen.get("asset_url")
        current = (asset.state == "CURRENT" and asset.recon_sha256 == asset.artifact_sha256
                   and candidate.asset_sha256 == asset.artifact_sha256
                   and isinstance(route, str) and isinstance(asset_url, str)
                   and candidate.route == route
                   and not urlsplit(asset_url).query and not urlsplit(asset_url).fragment
                   and asset.asset_url_sha256 == _digest(asset_url)
                   and package.scope.evaluate_url(route).result is ScopeResult.IN_SCOPE
                   and package.scope.evaluate_url(asset_url).result is ScopeResult.IN_SCOPE)
        trace = (candidate.attacker_controlled and candidate.check_before_transform
                 and bool(candidate.validation) and bool(candidate.transforms)
                 and candidate.sink_kind in {"HTML_EXECUTION", "URL_RESOURCE", "NAVIGATION_URL"}
                 and not candidate.post_checks and not candidate.sanitizers
                 and not candidate.unresolved_helper)
        checks = [_check("CURRENT_JS_ASSET", current, (asset.evidence_id,)),
                  _check("SOURCE_SINK_TRACE", trace, candidate.evidence_ids[:4])]
        if not current or not trace:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "DOM_CURRENT_TRACE_UNVERIFIED", checks=tuple(checks))
        with engine.evidence._connection() as db:
            link = db.execute("""
                SELECT hypothesis_id,plan_id,run_id FROM dom_flow_candidates
                WHERE target_id=? AND candidate_id=?
            """, (run.target_id, candidate_id)).fetchone()
            dispatches = db.execute("""
                SELECT variant FROM plan_dom_dispatches WHERE run_id=?
                ORDER BY accounted_at,rowid
            """, (run.id,)).fetchall()
        if (link is None or link["hypothesis_id"] != run.hypothesis_id
                or link["plan_id"] != run.plan_id or link["run_id"] != run.id):
            return _decision(ValidationStatus.INVALID_TEST, "DOM_AUDIT_BINDING_INVALID",
                             checks=tuple(checks))
        step = next((item for item in engine.runs.steps(run.id)
                     if item.type == "VERIFY_BROWSER"), None)
        result = engine.runs.result(step.id) if step else None
        if (step is None or step.status is not RuntimeStepStatus.COMPLETED
                or result is None or not 1 <= len(result.evidence_ids) <= 6):
            return _decision(ValidationStatus.INSUFFICIENT_EVIDENCE, "DOM_BROWSER_TRIALS_MISSING",
                             checks=tuple(checks))
        trials: list[dict[str, object]] = []
        for ref in result.evidence_ids:
            evidence = engine.evidence.get_evidence(ref)
            if (evidence is None or evidence.target_ref != run.target_id
                    or evidence.evidence_type != EvidenceType.DOM_PROOF.value
                    or evidence.source != "domxss_browser"
                    or evidence.provenance.record_id != candidate_id):
                return _decision(ValidationStatus.INVALID_TEST, "DOM_EVIDENCE_PROVENANCE_INVALID",
                                 checks=tuple(checks))
            try:
                trial = json.loads(engine.evidence.read_content(ref, max_bytes=8192))
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError, PermissionError):
                return _decision(ValidationStatus.INVALID_TEST, "DOM_EVIDENCE_UNREADABLE",
                                 checks=tuple(checks))
            if (not isinstance(trial, dict) or trial.get("candidate_id") != candidate_id
                    or trial.get("run_id") != run.id
                    or trial.get("browser_session_id") != frozen.get("browser_session_id")
                    or trial.get("route_url_sha256") != _digest(route)
                    or trial.get("asset_url_sha256") != asset.asset_url_sha256
                    or trial.get("bundle_sha256") != candidate.asset_sha256
                    or trial.get("input_kind") != frozen.get("input_kind")
                    or (trial.get("input_name") or "") != frozen.get("input_name")
                    or type(trial.get("marker_observed")) is not bool
                    or not re.fullmatch(r"DOMCTX-[0-9a-f]{32}", str(trial.get("context_id")))
                    or not re.fullmatch(r"[0-9a-f]{64}", str(trial.get("probe_url_sha256")))
                    or not re.fullmatch(r"[0-9a-f]{64}", str(trial.get("marker_sha256")))
                    or type(trial.get("csp_present")) is not bool
                    or type(trial.get("trusted_types_enforced")) is not bool
                    or not isinstance(trial.get("sandbox_flags"), list)
                    or type(trial.get("request_count")) is not int
                    or not 1 <= trial["request_count"] <= 24):
                return _decision(ValidationStatus.INVALID_TEST, "DOM_EVIDENCE_BINDING_INVALID",
                                 checks=tuple(checks))
            trials.append(trial)
        variants = [item["variant"] for item in trials]
        expected_prefix = ["INERT", "BENIGN", "DIRECT_DANGEROUS", "ENCODED_ONCE"]
        ordered = (variants[:4] == expected_prefix
                   and variants == [item["variant"] for item in dispatches]
                   and (len(variants) == 4 or
                        variants[4:] in (["FRESH_REPRODUCTION"],
                                         ["ENCODED_TWICE"],
                                         ["ENCODED_TWICE", "FRESH_REPRODUCTION"]))
                   and all(item.get("payload_variant") == item.get("variant")
                           for item in trials if item.get("variant") != "FRESH_REPRODUCTION")
                   and all(item.get("payload_variant") in {"ENCODED_ONCE", "ENCODED_TWICE"}
                           for item in trials if item.get("variant") == "FRESH_REPRODUCTION"))
        checks.append(_check("BROWSER_TRIAL_ORDER", ordered, result.evidence_ids))
        if not ordered:
            return _decision(ValidationStatus.INVALID_TEST, "DOM_CONTROL_SEQUENCE_INVALID",
                             checks=tuple(checks))
        policy_ok = True
        with engine.evidence._connection() as db:
            for trial in trials:
                ids = trial.get("policy_decision_ids")
                if (not isinstance(ids, list) or len(ids) < 2
                        or len(ids) > 25 or trial["request_count"] > len(ids) - 1):
                    policy_ok = False
                    break
                navigations = 0
                for decision_id in ids:
                    row = db.execute("""
                        SELECT d.result,d.scope_result,d.target_id,a.package_id,
                               a.category,a.actor,a.method,a.source,a.vulnerability_class
                        FROM policy_decisions d JOIN policy_actions a ON a.action_id=d.action_id
                        WHERE d.decision_id=?
                    """, (decision_id,)).fetchone()
                    if (row is None or row["result"] != "ALLOW" or row["scope_result"] != "IN_SCOPE"
                            or row["target_id"] != run.target_id
                            or row["package_id"] != run.package_id
                            or row["category"] not in {"BROWSER_NAVIGATION", "SAFE_READ"}
                            or row["source"] != "domxss_browser"
                            or row["method"] not in {"GET", "HEAD"}
                            or row["actor"] != ("AUTHENTICATED" if frozen.get("identity_id")
                                                 else "ANONYMOUS")
                            or row["vulnerability_class"] != "dom_xss"):
                        policy_ok = False
                        break
                    navigations += row["category"] == "BROWSER_NAVIGATION"
                if not policy_ok or navigations < 1:
                    policy_ok = False
                    break
        checks.append(_check("POLICY_SCOPE_FOR_EVERY_TRIAL", policy_ok, result.evidence_ids))
        if not policy_ok:
            return _decision(ValidationStatus.INVALID_TEST, "DOM_POLICY_AUDIT_INVALID",
                             checks=tuple(checks))
        controls_clear = all(not item["marker_observed"] for item in trials[:3])
        checks.append(_check("INERT_BENIGN_DIRECT_CONTROLS", controls_clear,
                             result.evidence_ids[:3]))
        if not controls_clear:
            return _decision(ValidationStatus.INVALID_TEST, "DOM_NEGATIVE_CONTROL_FAILED",
                             checks=tuple(checks), contradicting=result.evidence_ids[:3])
        successful = [(index, item) for index, item in enumerate(trials)
                      if item["variant"] in {"ENCODED_ONCE", "ENCODED_TWICE"}
                      and item["marker_observed"] is True]
        if not successful:
            blocked = any(item.get("browser_blocked") or item.get("denial_count")
                          or item.get("error_code") for item in trials)
            status = (ValidationStatus.NEEDS_MANUAL_REVIEW if blocked
                      else ValidationStatus.REJECTED)
            return _decision(status, "DOM_BROWSER_BLOCKED" if blocked else "DOM_NO_EXECUTION",
                             checks=tuple(checks), contradicting=result.evidence_ids)
        proof_index, proof = successful[0]
        reproduction = trials[-1] if trials[-1]["variant"] == "FRESH_REPRODUCTION" else None
        fresh = (reproduction is not None and reproduction["marker_observed"] is True
                 and reproduction["payload_variant"] == proof["variant"]
                 and reproduction["marker_sha256"] != proof["marker_sha256"]
                 and reproduction["context_id"] != proof["context_id"]
                 and len({item["context_id"] for item in trials}) == len(trials))
        checks.append(_check("FRESH_BROWSER_CONTEXT", fresh,
                             (result.evidence_ids[proof_index], result.evidence_ids[-1])))
        if not fresh:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "DOM_FRESH_REPRODUCTION_MISSING", checks=tuple(checks))
        origins = (proof.get("document_origin"), reproduction.get("document_origin"))
        origin_ok = all(isinstance(origin, str) and
                        package.scope.evaluate_url(origin + "/").result is ScopeResult.IN_SCOPE
                        for origin in origins)
        execution_ok = all(item.get("marker_context") in {"MAIN", "IFRAME"}
                           and not item.get("browser_blocked") and not item.get("navigation_only")
                           for item in (proof, reproduction))
        checks.extend((_check("TARGET_ORIGIN_EXECUTION", origin_ok,
                              (result.evidence_ids[proof_index], result.evidence_ids[-1])),
                       _check("EXECUTION_NOT_NAVIGATION", execution_ok,
                              (result.evidence_ids[proof_index], result.evidence_ids[-1])),
                       _check("CSP_TT_SANDBOX_RECORDED", True,
                              (result.evidence_ids[proof_index], result.evidence_ids[-1]))))
        if not origin_ok or not execution_ok:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "DOM_EXECUTION_CONTEXT_UNCLEAR", checks=tuple(checks))
        if candidate.status is not DOMCandidateStatus.VALIDATION_READY:
            return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                             "DOM_CANDIDATE_NOT_VALIDATION_READY", checks=tuple(checks))
        map_ref = ()
        if candidate.source_map_sha256:
            with engine.evidence._connection() as db:
                source_map = db.execute("""
                    SELECT evidence_id FROM dom_source_maps WHERE target_id=?
                      AND js_artifact_id=? AND map_sha256=? LIMIT 1
                """, (run.target_id, asset.artifact_id,
                      candidate.source_map_sha256)).fetchone()
            if source_map is None:
                return _decision(ValidationStatus.NEEDS_MANUAL_REVIEW,
                                 "DOM_SOURCE_MAP_PROVENANCE_MISSING", checks=tuple(checks))
            map_ref = (source_map["evidence_id"],)
        root_key = _digest("|".join((run.target_id, asset.asset_url_sha256,
                                      candidate.mapped_source or str(candidate.sink_location),
                                      candidate.source, candidate.sink)))
        surface = _digest("|".join((run.target_id, route, candidate.sink)))
        finding = FindingSpec(
            "DOM_XSS", root_key, surface, "BROWSER_DOCUMENT",
            "Check-before-transform DOM XSS executes in target browser context",
            "Browser execution reproduced using a harmless DOM attribute marker.",
            "BROWSER_SCRIPT_EXECUTION_IN_TARGET_ORIGIN",
            preliminary_severity="MEDIUM",
        )
        supporting = tuple(dict.fromkeys((*candidate.evidence_ids, asset.evidence_id,
                                          *map_ref, *result.evidence_ids)))[:64]
        return _decision(ValidationStatus.CONFIRMED, "DOM_BROWSER_EXECUTION_REPRODUCED",
                         checks=tuple(checks), controls=("INERT", "BENIGN", "DIRECT_NEGATIVE",
                                                        "TRANSFORMED_PROOF", "FRESH_CONTEXT"),
                         supporting=supporting, reproductions=2,
                         impact="BROWSER_SCRIPT_EXECUTION_IN_TARGET_ORIGIN", finding=finding)


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
