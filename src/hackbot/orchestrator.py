"""One explicit, policy-gated plan step per call. No vulnerability validation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import uuid
from urllib.parse import urlsplit
from typing import Any

from .auth import AuthMechanism, AuthStatus
from .evidence import EvidenceProvenance, EvidenceType, Sensitivity
from .executor import ExecutionError, ExecutionResult, RequestTemplate, TrafficExecutor
from .hypotheses import HypothesisStore
from .logging import SecretRedactor
from .plan_runs import (PlanRun, PlanRunStore, PlanSnapshot, RunStatus, RuntimeStep,
                        RuntimeStepStatus, RuntimeStepType, StepResult)
from .policy import PolicyEngine
from .policy_models import ActionCategory, ActorMode, ApprovalStatus, ProposedAction
from .policy_store import PolicyStore
from .rate_limit import ExperimentBudget
from .skill_plans import PrerequisiteChecker, PrerequisiteState, SkillContextBuilder
from .skills import SkillRegistry
from .store import EvidenceFactStore
from .target_loader import TargetPackageRepository
from .target_policy import PolicyDecision
from .traffic import TrafficStore
from .test_objects import ObjectRegistry


_MAP = {
    "OBSERVE": RuntimeStepType.PASSIVE_OBSERVATION.value,
    "ESTABLISH_CONTROL": RuntimeStepType.ESTABLISH_CONTROL.value,
    "EXECUTE_REQUEST": RuntimeStepType.EXECUTE_REQUEST.value,
    "COMPARE_RESPONSE": RuntimeStepType.COMPARE_METADATA.value,
    "VERIFY_BROWSER": RuntimeStepType.MANUAL_REVIEW.value,
    "MANUAL_REVIEW": RuntimeStepType.MANUAL_REVIEW.value,
}
_ACTIVE = frozenset({ActionCategory.SAFE_READ, ActionCategory.AUTHORIZATION_TEST,
                     ActionCategory.OBJECT_CREATE, ActionCategory.OBJECT_UPDATE,
                     ActionCategory.OBJECT_DELETE, ActionCategory.HTTP_REQUEST})
_TERMINAL = frozenset({RunStatus.COMPLETED, RunStatus.BLOCKED, RunStatus.REJECTED,
                       RunStatus.FAILED, RunStatus.BUDGET_EXHAUSTED, RunStatus.CANCELLED})


class PlanRunError(ValueError):
    """Safe, operator-facing error; never include a URL or secret."""


@dataclass(frozen=True, slots=True)
class _BoundAction:
    action: ProposedAction
    template: RequestTemplate
    role: str


class PlanOrchestrator:
    def __init__(self, *, runs: PlanRunStore, targets: TargetPackageRepository,
                 hypotheses: HypothesisStore, context: SkillContextBuilder,
                 checker: PrerequisiteChecker, registry: SkillRegistry,
                 policy: PolicyEngine, approvals: PolicyStore,
                 executor: TrafficExecutor, traffic: TrafficStore,
                 evidence: EvidenceFactStore, objects: ObjectRegistry | None = None) -> None:
        self.runs, self.targets, self.hypotheses = runs, targets, hypotheses
        self.context, self.checker, self.registry = context, checker, registry
        self.policy, self.approvals, self.executor = policy, approvals, executor
        self.traffic, self.evidence = traffic, evidence
        self.objects = objects

    @staticmethod
    def _requirements(snapshot: PlanSnapshot, registry: SkillRegistry) -> tuple[tuple[str, ...], str]:
        plan = snapshot.data
        required = plan.get("required_prerequisites")
        category = plan.get("skill_category")
        if isinstance(required, list) and isinstance(category, str):
            if (len(required) > 16 or any(not isinstance(value, str) for value in required)
                    or category not in {"authorization", "api", "client-side", "exposure"}):
                raise PlanRunError("invalid prerequisite snapshot")
            return tuple(required), category
        # Phase 15 legacy snapshots did not carry the skill category. Only use
        # installed metadata when its exact content hash still matches.
        try:
            current = registry.select(str(plan["skill_id"]))
        except (LookupError, ValueError):
            raise PlanRunError("legacy skill snapshot cannot be verified") from None
        if current.content_hash != plan["skill_hash"]:
            raise PlanRunError("legacy skill snapshot changed")
        old = plan.get("prerequisites", {})
        if not isinstance(old, dict):
            raise PlanRunError("invalid prerequisite snapshot")
        return tuple(dict.fromkeys((*old.get("satisfied", []), *old.get("missing", [])))), current.metadata.category

    @staticmethod
    def _compile(snapshot: PlanSnapshot) -> tuple[dict[str, object], ...]:
        plan = snapshot.data
        workflow, actions, templates = plan.get("steps"), plan.get("proposed_actions"), plan.get("request_templates")
        budget = plan.get("request_budget")
        if (not isinstance(workflow, list) or not 1 <= len(workflow) <= 20 or
                not isinstance(actions, list) or not isinstance(templates, list) or
                len(actions) != len(templates) or type(budget) is not int or
                not 0 <= budget <= 20 or len(actions) > budget or
                type(plan.get("token_budget")) is not int or not 0 <= plan["token_budget"] <= 8192):
            raise PlanRunError("invalid or unbounded plan snapshot")
        classes = plan.get("vulnerability_classes")
        if actions and (not isinstance(classes, list) or not classes or
                        any(not isinstance(value, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", value)
                            for value in classes)):
            raise PlanRunError("active plan lacks an immutable vulnerability class")
        result: list[dict[str, object]] = [
            {"id": "STEP-" + uuid.uuid4().hex, "type": RuntimeStepType.CHECK_PREREQUISITES.value}]
        action_slot = 0
        last_control: str | None = None
        for index, item in enumerate(workflow):
            if not isinstance(item, dict) or not isinstance(item.get("type"), str):
                raise PlanRunError("invalid plan step")
            kind = _MAP.get(item["type"], "UNSUPPORTED")
            step: dict[str, object] = {"id": "STEP-" + uuid.uuid4().hex,
                                       "type": kind, "source_step_index": index}
            if kind == RuntimeStepType.EXECUTE_REQUEST.value:
                if action_slot < len(actions):
                    descriptor = actions[action_slot]
                    if not isinstance(descriptor, dict):
                        raise PlanRunError("invalid action binding")
                    role = descriptor.get("role", "OTHER")
                    if role not in {"CONTROL", "BOUNDARY", "OTHER"}:
                        raise PlanRunError("invalid action role")
                    step.update({"action_slot": action_slot, "role": role,
                                 "action_id": "ACTION-" + uuid.uuid4().hex})
                    if role == "CONTROL":
                        last_control = str(step["id"])
                    elif role == "BOUNDARY":
                        step["control_step_id"] = last_control
                    action_slot += 1
            result.append(step)
        if action_slot != len(actions):
            raise PlanRunError("plan actions lack explicit execution steps")
        return tuple(result)

    def _current(self, run: PlanRun, snapshot: PlanSnapshot) -> tuple[Any, Any, Any]:
        package = self.targets.get_target_package(run.package_id)
        if package is None or package.target.id != run.target_id:
            raise PlanRunError("target package unavailable")
        hypothesis = self.hypotheses.get(run.hypothesis_id, run.target_id)
        if hypothesis is None:
            raise PlanRunError("hypothesis unavailable")
        profile = self.hypotheses.latest_profile(run.target_id)
        context = self.context.build(hypothesis, profile, package)
        required, category = self._requirements(snapshot, self.registry)
        prereq = self.checker.check_requirements(required, category, context)
        return package, context, prereq

    def start(self, plan_id: str, package_id: str, *, rerun: bool = False) -> dict[str, object]:
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise LookupError("target package not found")
        snapshot = self.runs.snapshot(plan_id, package.target.id)
        plan = snapshot.data
        if plan.get("status") not in {"READY_FOR_MANUAL_REVIEW", "REQUIRE_APPROVAL"}:
            raise PlanRunError("plan is not ready to start")
        steps = self._compile(snapshot)
        required, category = self._requirements(snapshot, self.registry)
        hypothesis = self.hypotheses.get(str(plan["hypothesis_id"]), package.target.id)
        if hypothesis is None:
            raise PlanRunError("hypothesis unavailable")
        current = self.context.build(hypothesis, self.hypotheses.latest_profile(package.target.id), package)
        prereq = self.checker.check_requirements(required, category, current)
        if prereq.state is not PrerequisiteState.READY:
            raise PlanRunError("current prerequisites are not ready")
        run = self.runs.create(snapshot, package_id, steps, rerun=rerun)
        if self.objects and self.objects.requirements(plan_id, package.target.id):
            if not self.objects.reserve_requirements(run.id, run.target_id):
                run = self.runs.transition(run.id, run.target_id, RunStatus.CHECKING_PREREQUISITES,
                                           "DISPOSABLE_OBJECT_REQUIRED",
                                           expected=frozenset({RunStatus.CREATED}))
        return self.runs.details(run)

    def _load(self, run_id: str, package_id: str) -> tuple[PlanRun, PlanSnapshot]:
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise LookupError("target package not found")
        run = self.runs.get(run_id, package.target.id)
        if run is None or run.package_id != package_id:
            raise LookupError("plan run not found")
        snapshot = self.runs.snapshot(run.plan_id, run.target_id)
        if snapshot.content_hash != run.snapshot_hash:
            if run.status not in _TERMINAL and run.status is not RunStatus.RUNNING:
                blocked = self.runs.transition(run.id, run.target_id, RunStatus.BLOCKED,
                                               "SNAPSHOT_CHANGED",
                                               expected=frozenset({run.status}))
                if self.objects:
                    self.objects.release_run(blocked.id, blocked.target_id)
            raise PlanRunError("plan snapshot changed")
        return run, snapshot

    def detail(self, run_id: str, package_id: str) -> dict[str, object]:
        run, _ = self._load(run_id, package_id)
        return self.runs.details(run)

    @staticmethod
    def _bound(snapshot: PlanSnapshot, step: RuntimeStep, run: PlanRun) -> _BoundAction:
        if step.action_slot is None or step.action_id is None:
            raise PlanRunError("request step lacks an explicit action binding")
        try:
            descriptor = snapshot.data["proposed_actions"][step.action_slot]
            shape = snapshot.data["request_templates"][step.action_slot]
            if not isinstance(descriptor, dict) or not isinstance(shape, dict):
                raise ValueError
            if (set(shape) - {"method", "url", "fingerprint", "authentication"} or
                    shape.get("authentication") != "EXECUTOR_SUPPLIED"):
                raise ValueError
            template = RequestTemplate(shape["method"], shape["url"])
            if (template.fingerprint() != shape.get("fingerprint") or
                    template.fingerprint() != descriptor.get("request_template_fingerprint") or
                    template.method != descriptor.get("method") or
                    descriptor.get("simulation_only") is not True):
                raise ValueError
            url = urlsplit(template.url)
            if (url.scheme not in {"http", "https"} or not url.hostname or url.query or url.fragment
                    or url.username or url.password or "[REDACTED]" in template.url
                    or SecretRedactor.from_environment().text(template.url) != template.url):
                raise ValueError
            category = ActionCategory(descriptor["category"])
            actor = ActorMode(descriptor["actor"])
            if category not in _ACTIVE or actor not in {ActorMode.ANONYMOUS, ActorMode.AUTHENTICATED}:
                raise ValueError
            identity_id = descriptor.get("identity_id")
            session_id = descriptor.get("session_id")
            if (actor is ActorMode.AUTHENTICATED and (not identity_id or not session_id)
                    or actor is ActorMode.ANONYMOUS and (identity_id or session_id)):
                raise ValueError
            vulnerability_class = descriptor.get("vulnerability_class")
            declared_classes = snapshot.data.get("vulnerability_classes")
            if (not isinstance(vulnerability_class, str) or
                    vulnerability_class not in {str(value).lower() for value in declared_classes}):
                raise ValueError
            action = ProposedAction(
                target_id=run.target_id, package_id=run.package_id, category=category, actor=actor,
                source="plan_orchestrator", purpose="Bound investigation plan step",
                url=template.url, method=template.method, hypothesis_id=run.hypothesis_id,
                identity_id=identity_id, session_id=session_id,
                operation=descriptor.get("operation"),
                object_type=descriptor.get("object_type"),
                object_ref_hash=descriptor.get("object_ref_hash"),
                disposable_intent=descriptor.get("disposable_intent", False),
                cross_identity=descriptor.get("cross_identity", False), id=step.action_id,
                vulnerability_class=vulnerability_class,
            )
            return _BoundAction(action, template, step.role)
        except (TypeError, KeyError, IndexError, ValueError):
            raise PlanRunError("request binding is incomplete or unsafe") from None

    def _result(self, step: RuntimeStep, summary: str, *, execution: ExecutionResult | None = None,
                evidence_ids: tuple[str, ...] = (), exchange_ids: tuple[str, ...] = (),
                error: str | None = None) -> StepResult:
        status = execution.status_code if execution else None
        body_hash = artifact_hash = None
        if exchange_ids:
            exchange = self.traffic.get_exchange(exchange_ids[-1])
            if exchange and exchange.response:
                body_hash = exchange.response.body_hash
                artifact_hash = exchange.response.record.artifact_hash
        duration = (int((execution.finished_at - execution.started_at).total_seconds() * 1000)
                    if execution else None)
        return StepResult("RESULT-" + uuid.uuid4().hex, step.id,
                          execution.execution_id if execution else None, exchange_ids, evidence_ids,
                          status, body_hash, artifact_hash, duration, error, summary,
                          datetime.now(timezone.utc).isoformat())

    def _finish(self, run: PlanRun, step: RuntimeStep, *, status: RuntimeStepStatus,
                reason: str, result: StepResult | None = None, consumed: int = 0,
                waiting: RunStatus | None = None, prereq_state: str | None = None,
                approval_id: str | None = None) -> dict[str, object]:
        following = step.ordinal + 1 < len(self.runs.steps(run.id))
        run_status = waiting or (RunStatus.READY if following else RunStatus.COMPLETED)
        updated = self.runs.finish(run.id, step.id, step_status=status,
                                   run_status=run_status, reason=reason, result=result,
                                   consumed=consumed, approval_id=approval_id,
                                   prerequisite_state=prereq_state,
                                   advance=status is RuntimeStepStatus.COMPLETED)
        if self.objects and updated.status in _TERMINAL:
            self.objects.release_run(updated.id, updated.target_id)
        return self.runs.details(updated)

    def _record_execution_evidence(self, run: PlanRun, step: RuntimeStep,
                                   execution: ExecutionResult) -> tuple[str, ...]:
        payload = {"execution_id": execution.execution_id, "action_id": execution.action_id,
                   "decision_id": execution.decision_id, "permit_id": execution.permit_id,
                   "approval_id": execution.approval_id, "exchange_ids": execution.exchange_ids,
                   "status_code": execution.status_code,
                   "error_class": execution.error.value if execution.error else None}
        record = self.evidence.create_evidence(
            EvidenceType.EXPERIMENT_RESULT,
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
            source="plan_orchestrator", target_ref=run.target_id,
            provenance=EvidenceProvenance("BUGHUNTER", "plan_step", step.id),
            sensitivity=Sensitivity.INTERNAL)
        return tuple(dict.fromkeys((*execution.evidence_ids, record.evidence_id)))[:16]

    def advance(self, run_id: str, package_id: str) -> dict[str, object]:
        run, snapshot = self._load(run_id, package_id)
        if self.objects and run.status is RunStatus.CHECKING_PREREQUISITES:
            if not self.objects.reserve_requirements(run.id, run.target_id):
                return self.runs.details(run)
            ready = self.runs.transition(run.id, run.target_id, RunStatus.READY,
                                         "OBJECT_PREREQUISITES_READY",
                                         expected=frozenset({RunStatus.CHECKING_PREREQUISITES}))
            return self.runs.details(ready)
        if run.status not in {RunStatus.CREATED, RunStatus.READY}:
            raise PlanRunError("run is not ready for a step")
        if self.objects and self.objects.requirements(run.plan_id, run.target_id):
            if not self.objects.reserved_for_run(run.id, run.target_id):
                waiting = self.runs.transition(run.id, run.target_id,
                                               RunStatus.CHECKING_PREREQUISITES,
                                               "OBJECT_RESERVATION_MISSING",
                                               expected=frozenset({run.status}))
                return self.runs.details(waiting)
        step = self.runs.current_step(run)
        if step is None:
            raise PlanRunError("no pending step")
        if not self.runs.claim(run, step):
            raise PlanRunError("another plan step is active")
        try:
            package, context, prereq = self._current(run, snapshot)
            if prereq.state is not PrerequisiteState.READY:
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="PREREQUISITES_STALE", waiting=RunStatus.BLOCKED,
                                    prereq_state=prereq.state.value)
            if step.type == RuntimeStepType.CHECK_PREREQUISITES.value:
                return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                    reason="PREREQUISITES_CURRENT", prereq_state=prereq.state.value,
                                    result=self._result(step, "Current prerequisites are present."))
            if step.type == RuntimeStepType.PASSIVE_OBSERVATION.value:
                refs = tuple(item["id"] for item in context.evidence)
                if not refs and not context.facts and not context.traffic:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="HUMAN_OBSERVATION_REQUIRED", waiting=RunStatus.WAITING_HUMAN)
                return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                    reason="METADATA_OBSERVED", result=self._result(
                                        step, "Existing evidence or traffic metadata inspected.", evidence_ids=refs))
            if step.type == RuntimeStepType.COMPARE_METADATA.value:
                pairs = snapshot.data.get("comparison_pairs", [])
                if not isinstance(pairs, list) or not pairs:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="COMPARISON_BINDING_REQUIRED", waiting=RunStatus.WAITING_HUMAN)
                pair = pairs[0]
                if (not isinstance(pair, dict) or type(pair.get("control_slot")) is not int or
                        type(pair.get("boundary_slot")) is not int):
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="COMPARISON_BINDING_INVALID", waiting=RunStatus.BLOCKED)
                indexed = {item.action_slot: item for item in self.runs.steps(run.id)
                           if item.action_slot is not None}
                control = indexed.get(pair["control_slot"])
                boundary = indexed.get(pair["boundary_slot"])
                first = self.runs.result(control.id) if control else None
                second = self.runs.result(boundary.id) if boundary else None
                if not first or not second:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="COMPARISON_INPUTS_MISSING", waiting=RunStatus.WAITING_HUMAN)
                same = first.response_hash == second.response_hash if first.response_hash and second.response_hash else None
                summary = ("Metadata comparison recorded: status_equal=" +
                           str(first.status_code == second.status_code) + ", hash_equal=" + str(same))
                result = self._result(step, summary,
                                      evidence_ids=tuple(dict.fromkeys((*first.evidence_ids,
                                                                        *second.evidence_ids)))[:16],
                                      exchange_ids=(*first.exchange_ids, *second.exchange_ids)[:16])
                return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                    reason="METADATA_COMPARED", result=result)
            if step.type != RuntimeStepType.EXECUTE_REQUEST.value:
                reason = ("HUMAN_REVIEW_REQUIRED" if step.type in {
                    RuntimeStepType.ESTABLISH_CONTROL.value, RuntimeStepType.MANUAL_REVIEW.value}
                          else "BLOCKED_UNSUPPORTED")
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason=reason, waiting=(RunStatus.WAITING_HUMAN
                                                            if reason == "HUMAN_REVIEW_REQUIRED"
                                                            else RunStatus.BLOCKED))
            if run.requests_consumed >= run.request_budget:
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="REQUEST_BUDGET_EXHAUSTED", waiting=RunStatus.BUDGET_EXHAUSTED)
            try:
                bound = self._bound(snapshot, step, run)
            except PlanRunError:
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="ACTION_BINDING_INVALID", waiting=RunStatus.BLOCKED)
            action, template = bound.action, bound.template
            if action.actor is ActorMode.AUTHENTICATED:
                matched = any(identity["id"] == action.identity_id and
                              identity["verified_session_id"] == action.session_id
                              for identity in context.identities)
                auth = self.executor.auth.get(run.target_id, action.identity_id)
                if (not matched or auth is None or auth.status is not AuthStatus.VALID or
                        auth.browser_session_ref != action.session_id or
                        auth.mechanism is AuthMechanism.MANUAL_LOGIN or not auth.secret_ref):
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="BOUND_IDENTITY_UNVERIFIED", waiting=RunStatus.BLOCKED)
            decision = self.policy.evaluate(package, action, record=True)
            self.runs.policy(run.id, step.id, decision.id, decision.approval_id, decision.reason_code)
            if decision.result is PolicyDecision.DENY:
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="POLICY_DENIED", waiting=RunStatus.BLOCKED)
            if decision.result is PolicyDecision.REQUIRE_APPROVAL:
                return self._finish(run, step, status=RuntimeStepStatus.WAITING_APPROVAL,
                                    reason="APPROVAL_REQUIRED", waiting=RunStatus.WAITING_APPROVAL,
                                    approval_id=decision.approval_id)
            try:
                permit = self.executor.authorize(action, template)
            except ValueError:
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="PERMIT_NOT_ISSUED", waiting=RunStatus.BLOCKED)
            execution_id = "EXEC-" + uuid.uuid4().hex
            self.runs.permit(run.id, step.id, permit.id, execution_id)
            remaining = run.request_budget - run.requests_consumed
            execution = self.executor.execute(
                action, permit, template, experiment_id=run.id,
                budget=ExperimentBudget(max_requests=run.request_budget),
                max_dispatches=remaining, execution_id=execution_id,
                continue_dispatch=lambda: self.runs.should_dispatch(run.id),
                on_dispatch=lambda exchange_id: self.runs.account_dispatch(
                    run.id, step.id, exchange_id))
            evidence_ids = self._record_execution_evidence(run, step, execution)
            result = self._result(step, "HTTP observation recorded." if execution.error is None else
                                  "Execution ended with a classified error.",
                                  execution=execution, evidence_ids=evidence_ids,
                                  exchange_ids=execution.exchange_ids,
                                  error=execution.error.value if execution.error else None)
            consumed = len(execution.exchange_ids)
            if execution.error is not None:
                mutating = template.method not in {"GET", "HEAD", "OPTIONS"}
                if execution.error in {ExecutionError.PROXY_UNAVAILABLE, ExecutionError.DIRECT_DISABLED}:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="CAPTURE_UNAVAILABLE" if execution.error is
                                        ExecutionError.PROXY_UNAVAILABLE else "DIRECT_EXECUTION_DISABLED",
                                        result=result, consumed=consumed, waiting=RunStatus.BLOCKED)
                if execution.error is ExecutionError.OPERATOR_STOPPED:
                    return self._finish(run, step, status=RuntimeStepStatus.FAILED,
                                        reason="OPERATOR_STOPPED", result=result, consumed=consumed,
                                        waiting=RunStatus.WAITING_HUMAN)
                if execution.error is ExecutionError.BUDGET_EXHAUSTED:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="REQUEST_BUDGET_EXHAUSTED", result=result, consumed=consumed,
                                        waiting=RunStatus.BUDGET_EXHAUSTED)
                return self._finish(run, step, status=RuntimeStepStatus.FAILED,
                                    reason="AMBIGUOUS_MUTATION" if mutating and consumed else
                                    "EXECUTION_FAILED", result=result, consumed=consumed,
                                    waiting=RunStatus.WAITING_HUMAN if mutating and consumed else RunStatus.FAILED)
            if step.role == "CONTROL" and (execution.status_code is None or
                                            not 200 <= execution.status_code < 300):
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="CONTROL_NOT_SUCCESSFUL", result=result, consumed=consumed,
                                    waiting=RunStatus.BLOCKED)
            return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                reason="EXECUTION_RECORDED", result=result, consumed=consumed)
        except Exception:
            # Never let an in-process error make the next call silently replay a step.
            current = self.runs.current_step(run)
            if current and current.status is RuntimeStepStatus.EXECUTING:
                self.runs.reconcile()
                updated = self.runs.get(run.id, run.target_id)
                assert updated is not None
                return self.runs.details(updated)
            raise

    def resume(self, run_id: str, package_id: str) -> dict[str, object]:
        run, snapshot = self._load(run_id, package_id)
        if run.status not in {RunStatus.PAUSED, RunStatus.WAITING_APPROVAL}:
            raise PlanRunError("run is not resumable")
        try:
            package, context, prereq = self._current(run, snapshot)
        except PlanRunError:
            updated = self.runs.transition(run.id, run.target_id, RunStatus.BLOCKED,
                                           "PREREQUISITES_STALE", expected=frozenset({run.status}))
            if self.objects:
                self.objects.release_run(updated.id, updated.target_id)
            return self.runs.details(updated)
        if prereq.state is not PrerequisiteState.READY:
            updated = self.runs.transition(run.id, run.target_id, RunStatus.BLOCKED,
                                           "PREREQUISITES_STALE", expected=frozenset({run.status}))
            if self.objects:
                self.objects.release_run(updated.id, updated.target_id)
            return self.runs.details(updated)
        step = self.runs.current_step(run)
        if step is None:
            raise PlanRunError("run has no pending step")
        if run.approval_id:
            approval = self.approvals.get(run.approval_id, run.target_id)
            if approval is None or approval.status in {ApprovalStatus.EXPIRED, ApprovalStatus.REJECTED}:
                status = RunStatus.REJECTED if approval and approval.status is ApprovalStatus.REJECTED else RunStatus.BLOCKED
                updated = self.runs.transition(run.id, run.target_id, status,
                                               "APPROVAL_REJECTED" if status is RunStatus.REJECTED else
                                               "APPROVAL_EXPIRED", expected=frozenset({run.status}))
                if self.objects:
                    self.objects.release_run(updated.id, updated.target_id)
                return self.runs.details(updated)
            if approval.status is not ApprovalStatus.APPROVED_ONCE:
                if run.status is RunStatus.PAUSED:
                    updated = self.runs.transition(run.id, run.target_id, RunStatus.WAITING_APPROVAL,
                                                   "APPROVAL_PENDING", expected=frozenset({run.status}))
                    return self.runs.details(updated)
                return self.runs.details(run)
        if step.type == RuntimeStepType.EXECUTE_REQUEST.value:
            try:
                bound = self._bound(snapshot, step, run)
                decision = self.policy.evaluate(package, bound.action, record=False)
            except (PlanRunError, ValueError):
                decision = None
            if decision is None or decision.result is PolicyDecision.DENY:
                updated = self.runs.transition(run.id, run.target_id, RunStatus.BLOCKED,
                                               "POLICY_CHANGED", expected=frozenset({run.status}))
                if self.objects:
                    self.objects.release_run(updated.id, updated.target_id)
                return self.runs.details(updated)
            if decision.result is PolicyDecision.REQUIRE_APPROVAL:
                if run.status is RunStatus.PAUSED:
                    updated = self.runs.transition(run.id, run.target_id, RunStatus.WAITING_APPROVAL,
                                                   "APPROVAL_REQUIRED", expected=frozenset({run.status}))
                    return self.runs.details(updated)
                return self.runs.details(run)
        updated = self.runs.transition(run.id, run.target_id, RunStatus.READY,
                                       "OPERATOR_RESUMED", expected=frozenset({run.status}))
        return self.runs.details(updated)

    def pause(self, run_id: str, package_id: str) -> dict[str, object]:
        run, _ = self._load(run_id, package_id)
        return self.runs.details(self.runs.request_stop(run.id, run.target_id, cancel=False))

    def cancel(self, run_id: str, package_id: str) -> dict[str, object]:
        run, _ = self._load(run_id, package_id)
        stopped = self.runs.request_stop(run.id, run.target_id, cancel=True)
        if self.objects and stopped.status in _TERMINAL:
            self.objects.release_run(stopped.id, stopped.target_id)
        return self.runs.details(stopped)

    def complete_human_step(self, run_id: str, package_id: str, step_id: str,
                            *, evidence_ids: tuple[str, ...] = (),
                            exchange_id: str | None = None) -> dict[str, object]:
        run, _ = self._load(run_id, package_id)
        step = self.runs.current_step(run)
        if (run.status is not RunStatus.WAITING_HUMAN or step is None or step.id != step_id
                or step.safe_reason not in {"HUMAN_OBSERVATION_REQUIRED", "HUMAN_REVIEW_REQUIRED",
                                            "COMPARISON_BINDING_REQUIRED", "COMPARISON_INPUTS_MISSING",
                                            "RECOVERY_REVIEW_REQUIRED", "AMBIGUOUS_MUTATION"}):
            raise PlanRunError("step is not awaiting human evidence")
        if not evidence_ids and exchange_id is None or len(evidence_ids) > 16:
            raise PlanRunError("human completion requires an evidence reference")
        for ref in evidence_ids:
            item = self.evidence.get_evidence(ref)
            if item is None or item.target_ref != run.target_id:
                raise PlanRunError("evidence does not belong to target")
        exchanges: tuple[str, ...] = ()
        if exchange_id is not None:
            item = self.traffic.get_exchange(exchange_id)
            if item is None or item.target_id != run.target_id:
                raise PlanRunError("traffic does not belong to target")
            exchanges = (exchange_id,)
            evidence_ids = tuple(dict.fromkeys((*evidence_ids, *item.evidence_ids)))[:16]
        result = self._result(step, "Operator linked existing target-owned evidence.",
                              evidence_ids=evidence_ids, exchange_ids=exchanges)
        updated = self.runs.manual_complete(run, step, result)
        return self.runs.details(updated)
