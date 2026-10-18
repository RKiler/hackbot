"""One explicit planner run over existing policy-gated specialist workflows."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from typing import Any

from .api_specialist import APIAnalysisLimits, APISpecialist
from .authorization import AuthorizationSpecialist
from .authorization_store import AuthorizationMode, Boundary, HuntStatus
from .browser import BrowserSessionManager, BrowserStatus
from .domxss import DOMXSSSpecialist
from .domain import ObservationState
from .exposure import ExposureSpecialist
from .hypotheses import HypothesisStore
from .identity import MembershipStatus
from .object_factory import ObjectFactory, ObjectFactoryResult
from .orchestrator import PlanOrchestrator
from .planner import BROWSER_TRIAL_CAPS, CrossSpecialistPlanner
from .planner_models import (
    CandidateOverride, CandidateStatus, PlannerCandidate, PlannerMode, PlannerRun,
    PlannerStatus, PlannerTask, PlannerTaskStatus, PlannerTaskType, Specialist,
)
from .planner_store import MAX_RUN_TASKS, PlannerStore
from .policy import policy_version
from .policy_models import ApprovalStatus
from .postmessage import PostMessageSpecialist
from .research import KnowledgeGap, ResearchBudget, ResearchCoordinator
from .skill_plans import SkillContextBuilder, SkillPlanner, SkillRouter
from .target_package import TargetPackage
from .target_policy import PolicyDecision
from .test_objects import ObjectRegistry, ObjectState, TestObject
from .validation_store import ValidationStatus
from .validator import DeterministicValidatorEngine


_CHILD_STOPS = frozenset({"BLOCKED", "REJECTED", "FAILED", "BUDGET_EXHAUSTED", "CANCELLED"})
_WAITING = frozenset({"WAITING_APPROVAL", "WAITING_HUMAN", "PAUSED"})
_TASK_DONE = frozenset({PlannerTaskStatus.COMPLETED, PlannerTaskStatus.FAILED,
                        PlannerTaskStatus.BLOCKED, PlannerTaskStatus.SKIPPED,
                        PlannerTaskStatus.CANCELLED})


def _routed_specialist(skill: dict[str, object]) -> Specialist | None:
    category = skill.get("category")
    if category == "authorization":
        return Specialist.AUTHORIZATION
    if category == "api":
        return Specialist.API_GRAPHQL
    if category == "exposure":
        return Specialist.EXPOSURE
    if category == "client-side":
        classes = set(skill.get("vulnerability_classes") or ())
        if "POSTMESSAGE" in classes or "MESSAGEPORT" in classes:
            return Specialist.POSTMESSAGE
        if "DOM_XSS" in classes:
            return Specialist.DOM_XSS
    return None


class PlannerRunner:
    """No raw HTTP, browser-driver, or permit-store dependency belongs here."""

    def __init__(self, *, planner: CrossSpecialistPlanner, store: PlannerStore,
                 hypotheses: HypothesisStore, contexts: SkillContextBuilder,
                 router: SkillRouter, skill_planner: SkillPlanner,
                 authorization: AuthorizationSpecialist, api: APISpecialist,
                 dom: DOMXSSSpecialist | None, messages: PostMessageSpecialist | None,
                 exposure: ExposureSpecialist, research: ResearchCoordinator,
                 objects: ObjectRegistry, object_factory: ObjectFactory,
                 browser: BrowserSessionManager, orchestrator: PlanOrchestrator,
                 validator: DeterministicValidatorEngine) -> None:
        self.planner, self.store = planner, store
        self.hypotheses, self.contexts, self.router = hypotheses, contexts, router
        self.skill_planner = skill_planner
        self.authorization, self.api = authorization, api
        self.dom, self.messages, self.exposure = dom, messages, exposure
        self.research, self.objects, self.object_factory = research, objects, object_factory
        self.browser, self.orchestrator, self.validator = browser, orchestrator, validator

    @staticmethod
    def _current(package: TargetPackage, run: PlannerRun) -> None:
        if (package.id != run.package_id or package.target.id != run.target_id or
                package.version != run.package_version or
                package.status.value != "TRACKED" or policy_version(package) != run.policy_hash):
            raise ValueError("Target package or policy changed")

    @staticmethod
    def _expired(run: PlannerRun) -> bool:
        return (datetime.now(timezone.utc) -
                datetime.fromisoformat(run.created_at)).total_seconds() >= run.limits.seconds

    def _source(self, candidate: PlannerCandidate) -> Any:
        target, source = candidate.target_id, candidate.source_id
        if candidate.source_kind == "AUTHORIZATION":
            return self.authorization.ledger.get_candidate(source, target)
        if candidate.source_kind == "API_GRAPHQL":
            return self.api.registry.get_candidate(target, source)
        if candidate.source_kind == "DOM_XSS":
            return self.dom.store.get_candidate(target, source) if self.dom else None
        if candidate.source_kind == "POSTMESSAGE":
            return self.messages.store.get_candidate(target, source) if self.messages else None
        if candidate.source_kind == "EXPOSURE":
            return self.exposure.store.get(target, source)
        return self.hypotheses.get(source, target)

    def _fresh(self, package: TargetPackage, candidate: PlannerCandidate) -> bool:
        source = self._source(candidate)
        if source is None:
            return False
        target = candidate.target_id
        if candidate.source_kind == "API_GRAPHQL":
            operation = self.api.registry.get_operation(target, source.operation_id)
            return bool(operation and operation.package_id == package.id and
                        operation.state == "CURRENT" and source.status != "STALE")
        if candidate.source_kind == "DOM_XSS":
            asset = self.dom.store.candidate_asset(target, candidate.source_id) if self.dom else None
            return bool(source.status.value != "STALE" and asset and asset.state == "CURRENT" and
                        asset.artifact_sha256 == source.asset_sha256 and
                        asset.recon_sha256 == source.asset_sha256)
        if candidate.source_kind == "POSTMESSAGE":
            asset = self.messages.store.current_asset(target, candidate.source_id) if self.messages else None
            return bool(source.status.value != "STALE" and asset and asset.state == "CURRENT")
        if candidate.source_kind == "EXPOSURE":
            return bool(source.status.value not in {"STALE", "REJECTED_PUBLIC", "REJECTED_PLACEHOLDER"}
                        and package.scope.evaluate_url(source.location).result.value == "IN_SCOPE"
                        and self.exposure.current_candidate(package, candidate.source_id))
        if candidate.source_kind == "AUTHORIZATION":
            exchange = self.authorization.traffic.get_exchange(source.owner_exchange_id)
            return bool(exchange and exchange.target_id == target and
                        exchange.package_id == package.id and
                        source.status not in {"BLOCKED", "REJECTED"})
        return source.status.value not in {"REJECTED", "BLOCKED"}

    def _sessions(self, target_id: str) -> dict[str, str]:
        page = self.browser.list_sessions_for_target(target_id, limit=50)
        return {item.identity_id: item.id for item in page.items
                if item.identity_id and item.status is BrowserStatus.VALID}

    def _identity_ready(self, candidate: PlannerCandidate) -> bool:
        sessions = self._sessions(candidate.target_id)
        source = self._source(candidate)
        if source is None:
            return False
        if "MISSING_SECOND_TENANT" in candidate.gaps:
            memberships = []
            for identity_id in tuple(sessions)[:12]:
                page = self.planner.context.identities.list_memberships(identity_id, limit=8)
                memberships.append({item.tenant_id for item in page.items
                                    if item.status is MembershipStatus.ACTIVE and
                                    item.observation_state is ObservationState.OBSERVED})
            if not any(left and right and left != right for index, left in
                       enumerate(memberships) for right in memberships[index + 1:]):
                return False
        if candidate.source_kind in {"AUTHORIZATION", "API_GRAPHQL"}:
            owner = getattr(source, "owner_identity_id", None)
            boundary = getattr(source, "boundary_identity_id", None)
            return bool(owner in sessions and (boundary is None or boundary in sessions))
        return bool(sessions)

    def _missing_identity_ref(self, candidate: PlannerCandidate) -> str | None:
        source = self._source(candidate)
        if source is None:
            return None
        sessions = self._sessions(candidate.target_id)
        for identity_id in (getattr(source, "owner_identity_id", None),
                            getattr(source, "boundary_identity_id", None)):
            if isinstance(identity_id, str) and identity_id not in sessions:
                try:
                    identity = self.planner.context.identities.get_identity(
                        candidate.target_id, identity_id)
                except ValueError:
                    identity = None
                if identity is not None:
                    return identity.id
        return None

    def _object(self, candidate: PlannerCandidate):
        source = self._source(candidate)
        object_id = getattr(source, "test_object_id", None) if source else None
        return self.objects.get(object_id, candidate.target_id) if object_id else None

    def _setup_approval_item(self, task: PlannerTask, run: PlannerRun):
        if not task.result_ref or not task.result_ref.startswith("TESTOBJ-"):
            return None, None
        item = self.objects.get(task.result_ref, run.target_id)
        if item is None or item.package_id != run.package_id:
            return None, None
        if item.state is ObjectState.READY and item.verified_at:
            return item, "READY"
        if not item.pending_approval_id or not item.pending_action_id:
            return item, None
        audit = self.object_factory.policy.audit
        approval = audit.get(item.pending_approval_id, run.target_id) if audit else None
        if approval is None or approval.action_id != item.pending_action_id:
            return item, None
        return item, approval.status.value

    def _continue_setup(self, item: TestObject, target_id: str,
                        session_id: str) -> ObjectFactoryResult:
        if item.state is ObjectState.PLANNED:
            return self.object_factory.create(item.id, target_id, session_id=session_id)
        if item.state in {ObjectState.CREATED, ObjectState.VERIFYING}:
            return self.object_factory.verify(item.id, target_id, session_id=session_id)
        raise ValueError("Disposable setup is not resumable from this state")

    def _login_ready_for_task(self, task: PlannerTask,
                              candidate: PlannerCandidate) -> bool:
        if (task.task_type is PlannerTaskType.CREATE_DISPOSABLE_OBJECT and task.result_ref
                and task.result_ref.startswith("TESTOBJ-")):
            item = self.objects.get(task.result_ref, candidate.target_id)
            return bool(item and item.creator_identity_id in self._sessions(candidate.target_id))
        return self._identity_ready(candidate)

    def _child_prerequisite_gap(self, candidate: PlannerCandidate) -> tuple[str, str | None] | None:
        if candidate.source_kind not in {"AUTHORIZATION", "API_GRAPHQL"}:
            return None
        if not self._identity_ready(candidate):
            return "LOGIN_REQUIRED", self._missing_identity_ref(candidate)
        source = self._source(candidate)
        if source and getattr(source, "test_object_id", None):
            item = self._object(candidate)
            held_by_child = bool(item and candidate.plan_run_id and
                                 item.state is ObjectState.IN_USE and
                                 self.objects.active_reservation(item.id) == candidate.plan_run_id)
            if item is None or not item.verified_at or not (
                    item.state is ObjectState.READY or held_by_child):
                return "OBJECT_REQUIRED", None
        return None

    def _complete(self, run: PlannerRun, task: PlannerTask, reason: str,
                  ref: str | None = None) -> None:
        self.store.finish_task(run.target_id, run.id, task.id,
                               PlannerTaskStatus.COMPLETED, reason, result_ref=ref)

    def _wait(self, run: PlannerRun, task: PlannerTask, reason: str,
              ref: str | None = None) -> None:
        self.store.finish_task(run.target_id, run.id, task.id,
                               PlannerTaskStatus.WAITING, reason, result_ref=ref)

    def _block(self, run: PlannerRun, task: PlannerTask,
               candidate: PlannerCandidate, reason: str) -> None:
        self.store.finish_task(run.target_id, run.id, task.id,
                               PlannerTaskStatus.BLOCKED, reason)
        self.store.update_candidate(run.target_id, run.id, candidate.id,
                                    status=CandidateStatus.BLOCKED, reason=reason)
        self.store.skip_candidate_tasks(run.target_id, run.id, candidate.id, reason)
        if candidate.state_hash or run.context_hash:
            self.store.remember_branch(run.target_id, candidate.root_cause_key,
                                       candidate.state_hash or run.context_hash, "BLOCKED", run.id, reason)

    def _research_gap(self, candidate: PlannerCandidate) -> KnowledgeGap:
        target = candidate.target_id
        prefix = {"HYPOTHESIS": "hypothesis", "API_GRAPHQL": "api",
                  "EXPOSURE": "exposure"}.get(candidate.source_kind)
        ref = f"{prefix}:{candidate.source_id}" if prefix else ""
        if ref:
            try:
                return self.research.store.find_gap(target, ref)
            except LookupError:
                pass
        return self.research.store.find_gap(target, "planner:" + candidate.id)

    def _research_brief_reason(self, target_id: str, brief_id: str) -> str:
        brief = self.research.store.brief(target_id, brief_id)
        if brief is None or brief.get("freshness") == "RETIRED":
            return "RESEARCH_BRIEF_MISSING"
        proposal = brief.get("ephemeral_skill_proposal")
        if proposal is None:
            return "RESEARCH_BRIEF_READY"
        if (not isinstance(proposal, dict) or proposal.get("brief_id") != brief_id or
                proposal.get("status") != "ADVISORY" or
                not isinstance(proposal.get("name"), str)):
            return "EPHEMERAL_SKILL_REVIEW_REQUIRED"
        try:
            self.router.registry.select(proposal["name"])
        except (LookupError, ValueError, UnicodeError, OSError):
            return "EPHEMERAL_SKILL_REVIEW_REQUIRED"
        return "RESEARCH_SKILL_CATALOG_MATCH"

    def _promote_successor(self, package: TargetPackage, run: PlannerRun,
                           task: PlannerTask, stale: PlannerCandidate,
                           signal: Any) -> bool:
        context = self.planner.context.build(package, run.limits)
        successor = self.planner._rank(run, context, (signal,))[0]
        budgeted = self.store.get(run.target_id, run.id)
        assert budgeted is not None
        siblings = [item for item in self.store.candidates(
            run.target_id, run.id, limit=200) if item.id != stale.id]
        selected = [item for item in siblings if item.status in {
            CandidateStatus.SELECTED, CandidateStatus.NEEDS_REFRESH,
            CandidateStatus.PLANNED, CandidateStatus.RUNNING,
            CandidateStatus.WAITING, CandidateStatus.VALIDATED}]
        if (successor.status is not CandidateStatus.SELECTED or
                any(item.root_cause_key == successor.root_cause_key for item in siblings) or
                sum(item.estimated_requests for item in selected)
                + successor.estimated_requests > run.limits.requests - run.limits.cleanup_reserve or
                sum(item.estimated_browser for item in selected)
                + successor.estimated_browser > run.limits.browser_actions or
                sum(item.estimated_tokens for item in selected)
                + successor.estimated_tokens > run.limits.tokens or
                budgeted.usage.requests + successor.estimated_requests
                > run.limits.requests - run.limits.cleanup_reserve or
                budgeted.usage.browser_actions + successor.estimated_browser
                > run.limits.browser_actions or
                budgeted.usage.tokens + successor.estimated_tokens > run.limits.tokens):
            return False
        successor = self.store.supersede_stale(run, stale, task, successor)
        self._complete(run, task, "SOURCE_SUPERSEDED")
        self.planner.build_tasks(run, successor)
        return True

    def _prerequisite(self, package: TargetPackage, run: PlannerRun, task: PlannerTask,
                      candidate: PlannerCandidate) -> None:
        kind = task.task_type
        if kind is PlannerTaskType.RESOLVE_IDENTITY:
            if self._identity_ready(candidate):
                self._complete(run, task, "IDENTITY_VERIFIED")
            else:
                self._wait(run, task, "LOGIN_REQUIRED",
                           self._missing_identity_ref(candidate))
            return
        if kind is PlannerTaskType.RESOLVE_OBJECT:
            source = self._source(candidate) if candidate.source_kind == "AUTHORIZATION" else None
            if candidate.source_kind == "AUTHORIZATION" and source is None:
                self._wait(run, task, "SOURCE_MISSING")
                return
            if (candidate.source_kind == "AUTHORIZATION" and
                    "MISSING_OBJECT" in candidate.gaps and
                    source is not None and source.boundary in {
                        Boundary.CROSS_TENANT, Boundary.HORIZONTAL}):
                if self.authorization.comparison_control_ready(candidate.source_id, package):
                    self._complete(run, task, "COMPARISON_CONTROL_READY")
                else:
                    self._wait(run, task, "COMPARISON_OBJECT_REQUIRED")
                return
            item = self._object(candidate)
            if item and item.state is ObjectState.READY and item.disposable and item.verified_at:
                self._complete(run, task, "OWNED_OBJECT_READY", item.id)
            else:
                self._wait(run, task, "OBJECT_REQUIRED")
            return
        if kind is PlannerTaskType.CREATE_DISPOSABLE_OBJECT:
            if run.mode is not PlannerMode.BOUNDED_AUTONOMOUS:
                self._wait(run, task, "AUTONOMOUS_MODE_REQUIRED")
                return
            if not self._fresh(package, candidate):
                self._wait(run, task, "STALE_SOURCE")
                return
            source = self._source(candidate) if candidate.source_kind == "AUTHORIZATION" else None
            if (candidate.source_kind == "AUTHORIZATION" and
                    "MISSING_OBJECT" in candidate.gaps and
                    source is not None and source.boundary in {
                        Boundary.CROSS_TENANT, Boundary.HORIZONTAL}):
                if self.authorization.comparison_control_ready(candidate.source_id, package):
                    self._complete(run, task, "COMPARISON_CONTROL_READY")
                    return
                hunt = self.authorization.ledger.get_hunt(source.hunt_id, run.target_id)
                if (hunt is None or hunt.status is not HuntStatus.READY or
                        hunt.mode is not AuthorizationMode.BOUNDED_AUTONOMOUS):
                    self._wait(run, task, "SPECIALIST_AUTONOMY_REQUIRED")
                    return
                if (package.rules.automated_testing_allowed is not True or
                        package.autonomy.create_disposable_objects is not PolicyDecision.ALLOW or
                        package.autonomy.state_changing is not PolicyDecision.ALLOW):
                    self._block(run, task, candidate, "POLICY_BLOCKED")
                    return
                if source.boundary_identity_id not in self._sessions(run.target_id):
                    self._wait(run, task, "LOGIN_REQUIRED")
                    return
                if not self.store.reserve_task_budget(run.target_id, run.id, task.id,
                                                      requests=4):
                    self._block(run, task, candidate, "BUDGET_TOO_LOW")
                    return
                from .campaign_store import CampaignStore
                if not CampaignStore(self.store.store).claim_planner_task(
                        run.target_id, run.id, task.id, "SETUP"):
                    self._block(run, task, candidate, "CAMPAIGN_SETUP_LIMIT")
                    return
                prior_item, approval_state = self._setup_approval_item(task, run)
                if prior_item is not None:
                    if prior_item.state not in {ObjectState.PLANNED, ObjectState.CREATED,
                                                ObjectState.VERIFYING} or approval_state != \
                            ApprovalStatus.APPROVED_ONCE.value:
                        self._wait(run, task, "COMPARISON_OBJECT_REVIEW", prior_item.id)
                        return
                    session = self._sessions(run.target_id).get(prior_item.creator_identity_id)
                    if not session:
                        self._wait(run, task, "LOGIN_REQUIRED",
                                   prior_item.id)
                        return
                    result = self._continue_setup(prior_item, run.target_id, session)
                else:
                    result = self.authorization.ensure_comparison_control(candidate.source_id,
                                                                           package)
                if (result and result.outcome == "READY" and result.item and
                        self.authorization.comparison_control_ready(candidate.source_id,
                                                                    package)):
                    self._complete(run, task, "COMPARISON_OBJECT_CREATED", result.item.id)
                elif result and result.outcome == "APPROVAL_REQUIRED":
                    self._wait(run, task, "APPROVAL_PENDING",
                               result.item.id if result.item else None)
                else:
                    self._wait(run, task, "COMPARISON_OBJECT_REVIEW",
                               result.item.id if result and result.item else None)
                return
            item = self._object(candidate)
            if item and item.state is ObjectState.READY and item.disposable and item.verified_at:
                self._complete(run, task, "OWNED_OBJECT_READY", item.id)
                return
            if not item or item.package_id != package.id or item.state not in {
                    ObjectState.PLANNED, ObjectState.CREATED, ObjectState.VERIFYING}:
                self._wait(run, task, "EXACT_OBJECT_RECIPE_REQUIRED", task.result_ref)
                return
            if task.result_ref == item.id and item.pending_approval_id:
                _, approval_state = self._setup_approval_item(task, run)
                if approval_state != ApprovalStatus.APPROVED_ONCE.value:
                    self._wait(run, task, "APPROVAL_PENDING", item.id)
                    return
            session = self._sessions(run.target_id).get(item.creator_identity_id)
            if not session:
                self._wait(run, task, "LOGIN_REQUIRED", task.result_ref)
                return
            if not self.store.reserve_task_budget(run.target_id, run.id, task.id, requests=4):
                self._block(run, task, candidate, "BUDGET_TOO_LOW")
                return
            from .campaign_store import CampaignStore
            if not CampaignStore(self.store.store).claim_planner_task(
                    run.target_id, run.id, task.id, "SETUP"):
                self._block(run, task, candidate, "CAMPAIGN_SETUP_LIMIT")
                return
            result = self._continue_setup(item, run.target_id, session)
            if result.outcome == "READY" and result.item and result.item.state is ObjectState.READY:
                self._complete(run, task, "OBJECT_CREATED", result.item.id)
            elif result.outcome == "APPROVAL_REQUIRED":
                self._wait(run, task, "APPROVAL_PENDING", result.item.id if result.item else None)
            else:
                self._wait(run, task, "OBJECT_MANUAL_REVIEW", result.item.id if result.item else None)
            return
        if kind in {PlannerTaskType.REFRESH_TRAFFIC, PlannerTaskType.REFRESH_ASSET}:
            if self._fresh(package, candidate):
                self._complete(run, task, "SOURCE_CURRENT")
                return
            if (kind is PlannerTaskType.REFRESH_TRAFFIC and
                    candidate.source_kind == "API_GRAPHQL"):
                source = self._source(candidate)
                operation = (self.api.registry.get_operation(run.target_id, source.operation_id)
                             if source else None)
                if operation and operation.package_id == package.id:
                    limits = APIAnalysisLimits(traffic=20, js_assets=10,
                                               recon_surfaces=4, candidates=8)
                    self.api.profile(package, limits=limits)
                    operation = self.api.registry.get_operation(run.target_id, operation.id)
                    if operation is None:
                        self._wait(run, task, "REFRESH_NO_MATCH")
                        return
                    if operation.state == "CURRENT" and source.status == "STALE":
                        self.api.generate(package, limits=limits, mode="PLAN_ONLY",
                                          operation_id=operation.id)
                    if self._fresh(package, candidate):
                        self._complete(run, task, "SOURCE_REFRESHED")
                        return
                    for current in self.api.registry.current_js_successors(
                            run.target_id, operation.id, limit=3):
                        refreshed = self.api.generate(
                            package, limits=limits, mode="PLAN_ONLY",
                            operation_id=current.id)
                        match = next((item for item in refreshed
                            if item.id != source.id and item.category == source.category
                            and item.owner_identity_id == source.owner_identity_id
                            and item.boundary_identity_id == source.boundary_identity_id
                            and item.test_object_id == source.test_object_id
                            and item.field_path == source.field_path), None)
                        signal = self.planner.api_signal(package, match) if match else None
                        if signal is not None and self._promote_successor(
                                package, run, task, candidate, signal):
                            return
                self._wait(run, task, "REFRESH_NO_MATCH")
                return
            if (kind is PlannerTaskType.REFRESH_ASSET and
                    candidate.source_kind == "DOM_XSS" and self.dom):
                source = self._source(candidate)
                old = self.dom.store.candidate_asset(run.target_id, candidate.source_id)
                if source and old and old.recon_asset_id and source.recon_asset_id == old.recon_asset_id:
                    if run.mode is not PlannerMode.BOUNDED_AUTONOMOUS:
                        self._wait(run, task, "AUTONOMOUS_MODE_REQUIRED")
                        return
                    if not self.store.reserve_task_budget(run.target_id, run.id, task.id,
                                                          requests=3):
                        self._block(run, task, candidate, "BUDGET_TOO_LOW")
                        return
                    recon_target = self.dom.recon.resolve_target(package.target.root_domain)
                    observed = (self.dom.recon.get_js_asset(recon_target.domain_id,
                                 old.recon_asset_id) if recon_target else None)
                    if (observed is None or observed.asset_id != old.recon_asset_id or
                            hashlib.sha256(observed.asset_url.encode()).hexdigest()
                            != old.asset_url_sha256):
                        self._wait(run, task, "OBSERVED_ASSET_CHANGED")
                        return
                    acquired = self.dom.acquire(package.id, observed)
                    if acquired.status.value not in {"RETRIEVED", "REUSED"} or not acquired.artifact:
                        self._wait(run, task, acquired.reason_code or acquired.status.value)
                        return
                    _, analysis = self.dom.analyze(run.target_id, acquired.artifact.artifact_id)
                    if self._fresh(package, candidate):
                        self._complete(run, task, "SOURCE_REFRESHED")
                        return
                    matches = [item for item in analysis.candidates
                               if item.candidate_id != source.candidate_id
                               and item.recon_asset_id == source.recon_asset_id
                               and item.source == source.source
                               and item.sink_kind == source.sink_kind
                               and item.attacker_controlled and item.check_before_transform]
                    matches.sort(key=lambda item: (-item.score, item.candidate_id))
                    next_id = matches[0].candidate_id if matches else None
                    signal = next((item for item in self.planner._signals(
                        package, run.limits.portfolio) if item.source_kind == "DOM_XSS"
                        and item.source_id == next_id), None) if next_id else None
                    if signal is not None and self._promote_successor(
                            package, run, task, candidate, signal):
                        return
                    self._wait(run, task, "REFRESH_NO_MATCH")
                    return
            if (kind is PlannerTaskType.REFRESH_ASSET and
                    candidate.source_kind == "POSTMESSAGE" and self.messages and self.dom):
                source = self._source(candidate)
                assets = (source.artifact_ids if source else ())
                old = self.dom.store.get_asset(run.target_id, assets[-1]) if assets else None
                if old and old.recon_asset_id:
                    if run.mode is not PlannerMode.BOUNDED_AUTONOMOUS:
                        self._wait(run, task, "AUTONOMOUS_MODE_REQUIRED")
                        return
                    if not self.store.reserve_task_budget(run.target_id, run.id, task.id,
                                                          requests=3):
                        self._block(run, task, candidate, "BUDGET_TOO_LOW")
                        return
                    status, _, _, reason = self.messages.refresh_observed_asset(
                        package.id, old.recon_asset_id, include_source_map=False)
                    if status in {"RETRIEVED", "REUSED"} and self._fresh(package, candidate):
                        self._complete(run, task, "SOURCE_REFRESHED")
                        return
                    self._wait(run, task, reason or "STALE_SOURCE_REPLACED")
                    return
            self.store.update_candidate(run.target_id, run.id, candidate.id,
                                        status=CandidateStatus.NEEDS_REFRESH,
                                        reason="SOURCE_STALE")
            self._wait(run, task, "STALE_SOURCE")
            return
        if kind is PlannerTaskType.REQUEST_RESEARCH:
            from .campaign_store import CampaignStore
            if not CampaignStore(self.store.store).claim_planner_task(
                    run.target_id, run.id, task.id, "RESEARCH"):
                self._block(run, task, candidate, "CAMPAIGN_RESEARCH_LIMIT")
                return
            gap = self._research_gap(candidate)
            submission = self.research.submit(gap, budget=ResearchBudget(max_tokens=500),
                                              external=False, private_target=True)
            request_id = str(submission["request_id"])
            self.store.bump_metrics(run.target_id, run.id, research_requests=1)
            if submission["status"] == "CACHE_HIT":
                brief_id = str(submission["brief_id"])
                reason = self._research_brief_reason(run.target_id, brief_id)
                if reason == "RESEARCH_BRIEF_MISSING":
                    self._wait(run, task, reason, request_id)
                else:
                    self._complete(run, task, reason, brief_id)
                return
            if not self.store.reserve_task_budget(run.target_id, run.id, task.id, tokens=500):
                self.research.store.cancel(run.target_id, request_id)
                self._block(run, task, candidate, "TOKEN_BUDGET_LOW")
                return
            outcome = self.research.run(gap, request_id)
            if outcome.get("brief_id") and outcome.get("status") in {"COMPLETED", "PARTIAL"}:
                brief_id = str(outcome["brief_id"])
                reason = self._research_brief_reason(run.target_id, brief_id)
                if reason == "RESEARCH_BRIEF_MISSING":
                    self._wait(run, task, reason, request_id)
                else:
                    self._complete(run, task, reason, brief_id)
            else:
                self._wait(run, task, "RESEARCH_PENDING", request_id)
            return
        self._wait(run, task, "HUMAN_REVIEW_REQUIRED")
        if candidate.state_hash:
            self.store.remember_branch(run.target_id, candidate.root_cause_key,
                                       candidate.state_hash, "MANUAL_REVIEW", run.id,
                                       "HUMAN_REVIEW_REQUIRED")

    def _prepare(self, package: TargetPackage, run: PlannerRun, task: PlannerTask,
                 candidate: PlannerCandidate) -> None:
        if not self._fresh(package, candidate):
            self.store.update_candidate(run.target_id, run.id, candidate.id,
                                        status=CandidateStatus.NEEDS_REFRESH,
                                        reason="SOURCE_STALE")
            self._wait(run, task, "STALE_SOURCE")
            return
        gap = self._child_prerequisite_gap(candidate)
        if gap:
            self._wait(run, task, *gap)
            return
        if candidate.plan_id:
            self._complete(run, task, "PLAN_ALREADY_LINKED", candidate.plan_id)
            return
        source = candidate.source_id
        profile = self.hypotheses.latest_profile(run.target_id)
        if candidate.source_kind == "AUTHORIZATION":
            prepared = self.authorization.prepare(source, package, allow_setup=False)
            plan_id, hypothesis_id = prepared.plan_id, prepared.hypothesis_id
        elif candidate.source_kind == "API_GRAPHQL":
            prepared = self.api.prepare_candidate(package, source)
            plan_id, hypothesis_id = prepared.plan_id, prepared.hypothesis_id
        elif candidate.source_kind == "DOM_XSS" and self.dom:
            prepared = self.dom.prepare_candidate(package.id, source, hypotheses=self.hypotheses,
                contexts=self.contexts, router=self.router, planner=self.skill_planner, profile=profile)
            plan_id, hypothesis_id = str(prepared.plan["id"]), prepared.hypothesis.id
        elif candidate.source_kind == "POSTMESSAGE" and self.messages:
            prepared = self.messages.prepare_candidate(package.id, source, hypotheses=self.hypotheses,
                contexts=self.contexts, router=self.router, planner=self.skill_planner)
            plan_id, hypothesis_id = str(prepared.plan["id"]), prepared.hypothesis.id
        elif candidate.source_kind == "EXPOSURE":
            prepared = self.exposure.prepare_candidate(package, source, hypotheses=self.hypotheses,
                contexts=self.contexts, router=self.router, planner=self.skill_planner, profile=profile)
            plan_id, hypothesis_id = prepared.plan_id, prepared.hypothesis_id
        elif candidate.source_kind == "HYPOTHESIS":
            hypothesis = self.hypotheses.get(source, run.target_id)
            if hypothesis is None:
                self._block(run, task, candidate, "HYPOTHESIS_MISSING")
                return
            context = self.contexts.build(hypothesis, profile, package=package)
            routes = self.router.route(hypothesis, context, limit=5)
            names = tuple(str(item["skill"]["name"]) for item in routes)
            linked = next((item for item in self.research.store.list(
                run.target_id, limit=50).get("items", [])
                if item.get("gap_ref") == "hypothesis:" + hypothesis.id
                and item.get("freshness") == "FRESH"), None)
            hinted = next((name for name in linked.get("recommended_skills", [])
                           if name in names), None) if linked else None
            skill_id = candidate.override_skill_id or hinted or (names[0] if names else None)
            if skill_id not in names:
                brief_id = linked.get("brief_id") if linked else None
                reason = (self._research_brief_reason(run.target_id, brief_id)
                          if isinstance(brief_id, str) else "VALID_SKILL_REQUIRED")
                self._wait(run, task, reason if reason in {
                    "EPHEMERAL_SKILL_REVIEW_REQUIRED", "RESEARCH_BRIEF_MISSING"}
                    else "VALID_SKILL_REQUIRED", brief_id)
                return
            plan = self.skill_planner.generate(package, hypothesis, context, skill_id)
            plan_id, hypothesis_id = str(plan["id"]), hypothesis.id
        else:
            self._block(run, task, candidate, "SPECIALIST_UNAVAILABLE")
            return
        if not plan_id or not hypothesis_id:
            self._wait(run, task, "PLAN_PREREQUISITE_MISSING")
            return
        self.store.update_candidate(run.target_id, run.id, candidate.id,
            status=CandidateStatus.PLANNED, hypothesis_id=hypothesis_id, plan_id=plan_id,
            reason="PLAN_CREATED")
        self.store.bump_metrics(run.target_id, run.id, plans_created=1)
        self._complete(run, task, "PLAN_CREATED", plan_id)

    def _start_child(self, package: TargetPackage, candidate: PlannerCandidate) -> dict[str, object]:
        if candidate.source_kind == "AUTHORIZATION":
            return self.authorization.start_candidate(candidate.source_id, package)
        if candidate.source_kind == "API_GRAPHQL":
            return self.api.start_candidate(package, candidate.source_id)
        assert candidate.plan_id is not None
        return self.orchestrator.start(candidate.plan_id, package.id)

    def _advance_child(self, package: TargetPackage, candidate: PlannerCandidate) -> dict[str, object]:
        if candidate.source_kind == "AUTHORIZATION":
            return self.authorization.advance_candidate(candidate.source_id, package)
        if candidate.source_kind == "API_GRAPHQL":
            return self.api.advance_candidate(package, candidate.source_id)
        assert candidate.plan_run_id is not None
        return self.orchestrator.advance(candidate.plan_run_id, package.id)

    def _run_plan(self, package: TargetPackage, run: PlannerRun, task: PlannerTask,
                  candidate: PlannerCandidate) -> None:
        if run.mode is not PlannerMode.BOUNDED_AUTONOMOUS or not candidate.plan_id:
            self._block(run, task, candidate, "PLAN_NOT_EXECUTABLE")
            return
        if not self._fresh(package, candidate):
            self.store.update_candidate(run.target_id, run.id, candidate.id,
                                        status=CandidateStatus.NEEDS_REFRESH,
                                        reason="SOURCE_STALE")
            self._wait(run, task, "STALE_SOURCE")
            return
        gap = self._child_prerequisite_gap(candidate)
        if gap:
            self._wait(run, task, *gap)
            return
        plan = self.skill_planner.store.get(candidate.plan_id, run.target_id)
        if plan is None or plan["hypothesis_id"] != candidate.hypothesis_id or plan["status"] not in {
                "READY_FOR_MANUAL_REVIEW", "REQUIRE_APPROVAL"}:
            self._wait(run, task, "PLAN_PREREQUISITE_MISSING")
            return
        request_budget = int(plan["request_budget"])
        browser_budget = candidate.estimated_browser
        if not candidate.plan_run_id:
            prior = self.orchestrator.runs.list_for_plan(candidate.plan_id, run.target_id, limit=1)["items"]
            if prior:
                self._wait(run, task, "EXISTING_CHILD_RUN_REVIEW", str(prior[0]["id"]))
                return
            if not self.store.reserve_task_budget(run.target_id, run.id, task.id,
                requests=request_budget, browser_actions=browser_budget,
                tokens=candidate.estimated_tokens):
                self._block(run, task, candidate, "BUDGET_TOO_LOW")
                return
            detail = self._start_child(package, candidate)
            child_id = str(detail["run"]["id"])
            self.store.update_candidate(run.target_id, run.id, candidate.id,
                status=CandidateStatus.RUNNING, plan_run_id=child_id, reason="PLAN_STARTED")
            self.store.bump_metrics(run.target_id, run.id, plans_executed=1)
            return
        child = self.orchestrator.runs.get(candidate.plan_run_id, run.target_id)
        if child is None or child.package_id != package.id or child.plan_id != candidate.plan_id:
            self._wait(run, task, "CHILD_RUN_MISSING")
            return
        if child.status.value == "COMPLETED":
            self._complete(run, task, "PLAN_COMPLETED", child.id)
            return
        if child.status.value in _CHILD_STOPS:
            self._block(run, task, candidate, "CHILD_" + child.status.value)
            return
        if child.status.value in _WAITING:
            self._wait(run, task, "APPROVAL_PENDING" if child.status.value == "WAITING_APPROVAL"
                       else "CHILD_HUMAN_REVIEW", child.id)
            return
        detail = self._advance_child(package, candidate)
        status = str(detail["run"]["status"])
        if status == "COMPLETED":
            self._complete(run, task, "PLAN_COMPLETED", child.id)
        elif status in _CHILD_STOPS:
            self._block(run, task, candidate, "CHILD_" + status)
        elif status in _WAITING:
            self._wait(run, task, "APPROVAL_PENDING" if status == "WAITING_APPROVAL"
                       else "CHILD_HUMAN_REVIEW", child.id)

    def _validate(self, run: PlannerRun, task: PlannerTask,
                  candidate: PlannerCandidate) -> None:
        if not candidate.plan_run_id:
            self._block(run, task, candidate, "CHILD_RUN_MISSING")
            return
        child = self.orchestrator.runs.get(candidate.plan_run_id, run.target_id)
        if child is None or child.status.value != "COMPLETED":
            self._wait(run, task, "CHILD_NOT_COMPLETE")
            return
        result, finding = self.validator.validate_run(child.id, run.target_id)
        self.store.bump_metrics(run.target_id, run.id, validations=1)
        if result.status is ValidationStatus.CONFIRMED and finding is not None:
            status, outcome = CandidateStatus.VALIDATED, "CONFIRMED"
            self.store.bump_metrics(run.target_id, run.id, findings=1)
        elif result.status is ValidationStatus.DUPLICATE_CANDIDATE:
            status, outcome = CandidateStatus.DUPLICATE, "DUPLICATE"
        elif result.status is ValidationStatus.REJECTED:
            status, outcome = CandidateStatus.REJECTED, "REJECTED"
        else:
            status, outcome = CandidateStatus.WAITING, "MANUAL_REVIEW"
            self.store.bump_metrics(run.target_id, run.id, manual_reviews=1)
        self.store.update_candidate(run.target_id, run.id, candidate.id, status=status,
            validation_id=result.id,
            finding_id=finding.id if outcome == "CONFIRMED" and finding else None,
            reason="VALIDATION_" + result.status.value)
        self._complete(run, task, "VALIDATION_" + result.status.value, result.id)
        if candidate.state_hash or run.context_hash:
            self.store.remember_branch(run.target_id, candidate.root_cause_key,
                                       candidate.state_hash or run.context_hash, outcome, run.id,
                                       "VALIDATION_" + result.status.value)
        if outcome in {"CONFIRMED", "REJECTED", "DUPLICATE"}:
            for sibling in self.store.candidates(run.target_id, run.id, limit=200):
                if sibling.id != candidate.id and sibling.root_cause_key == candidate.root_cause_key:
                    self.store.update_candidate(run.target_id, run.id, sibling.id,
                        status=CandidateStatus.DUPLICATE if outcome in {"CONFIRMED", "DUPLICATE"}
                        else CandidateStatus.SKIPPED, reason="ROOT_CAUSE_" + outcome)
                    self.store.skip_candidate_tasks(run.target_id, run.id, sibling.id,
                                                    "ROOT_CAUSE_" + outcome)

    def _settle(self, run: PlannerRun) -> PlannerRun:
        tasks = self.store.tasks(run.target_id, run.id, limit=MAX_RUN_TASKS)
        if any(item.status is PlannerTaskStatus.RUNNING for item in tasks):
            return self.store.get(run.target_id, run.id) or run
        if not tasks or all(item.status in _TASK_DONE for item in tasks):
            return self.store.transition(run.target_id, run.id, PlannerStatus.COMPLETED,
                                         "ALL_BRANCHES_SETTLED")
        waiting = [item for item in tasks if item.status is PlannerTaskStatus.WAITING]
        completed = {item.id for item in tasks if item.status is PlannerTaskStatus.COMPLETED}
        ready = [item for item in tasks if item.status in {
            PlannerTaskStatus.READY, PlannerTaskStatus.PENDING} and
            set(item.dependencies).issubset(completed)]
        if ready:
            return self.store.get(run.target_id, run.id) or run
        if waiting:
            reasons = {item.reason_code for item in waiting}
            state = (PlannerStatus.WAITING_APPROVAL if "APPROVAL_PENDING" in reasons
                     else PlannerStatus.WAITING_LOGIN if "LOGIN_REQUIRED" in reasons
                     else PlannerStatus.WAITING_RESEARCH if "RESEARCH_PENDING" in reasons
                     else PlannerStatus.WAITING_HUMAN)
            return self.store.transition(run.target_id, run.id, state,
                                         "PREREQUISITE_WAIT")
        return self.store.transition(run.target_id, run.id, PlannerStatus.BLOCKED,
                                     "DEPENDENCY_BLOCKED")

    def _exhausted(self, package: TargetPackage, run: PlannerRun) -> PlannerRun:
        ambiguous = False
        for task in self.store.tasks(run.target_id, run.id, limit=MAX_RUN_TASKS):
            if task.task_type is not PlannerTaskType.RUN_PLAN or task.status not in {
                    PlannerTaskStatus.RUNNING, PlannerTaskStatus.WAITING}:
                continue
            candidate = self.store.candidate(run.target_id, run.id, task.candidate_id)
            if candidate is None or not candidate.plan_run_id:
                ambiguous = True
                continue
            try:
                self.orchestrator.cancel(candidate.plan_run_id, package.id)
            except (LookupError, ValueError):
                ambiguous = True
                continue
            self.store.finish_task(run.target_id, run.id, task.id,
                                   PlannerTaskStatus.CANCELLED, "TIME_BUDGET_EXHAUSTED",
                                   result_ref=candidate.plan_run_id)
        if ambiguous:
            return self.store.transition(run.target_id, run.id, PlannerStatus.PAUSED,
                                         "CHILD_STOP_UNCONFIRMED")
        self.store.cancel_remaining_tasks(run.target_id, run.id)
        return self.store.transition(run.target_id, run.id, PlannerStatus.BUDGET_EXHAUSTED,
                                     "TIME_BUDGET_EXHAUSTED")

    def advance(self, package: TargetPackage, run_id: str) -> dict[str, object]:
        run = self.store.get(package.target.id, run_id)
        if run is None:
            raise LookupError("Planner run not found")
        from .campaign_store import CampaignStore
        if not CampaignStore(self.store.store).planner_may_advance(run.target_id, run.id):
            return {"run": run.to_dict(), "task": None, "reason": "CAMPAIGN_NOT_RUNNING"}
        try:
            self._current(package, run)
        except ValueError:
            if run.status not in {PlannerStatus.CANCELLED, PlannerStatus.COMPLETED,
                                  PlannerStatus.BLOCKED, PlannerStatus.FAILED,
                                  PlannerStatus.BUDGET_EXHAUSTED}:
                run = self.store.transition(run.target_id, run.id, PlannerStatus.PAUSED,
                                            "PACKAGE_POLICY_CHANGED")
                return {"run": run.to_dict(), "task": None, "reason": "PACKAGE_POLICY_CHANGED"}
            raise
        if run.status not in {PlannerStatus.READY, PlannerStatus.RUNNING}:
            return {"run": run.to_dict(), "task": None, "reason": "NOT_RUNNABLE"}
        if self._expired(run):
            run = self._exhausted(package, run)
            return {"run": run.to_dict(), "task": None,
                    "reason": run.stop_reason or "CHILD_STOP_UNCONFIRMED"}
        tasks = self.store.tasks(run.target_id, run.id, limit=MAX_RUN_TASKS)
        task = next((item for item in tasks if item.status is PlannerTaskStatus.RUNNING), None)
        if task is None:
            for item in tasks:
                task = self.store.claim_task(run.target_id, run.id, item.id)
                if task is not None:
                    break
        if task is None:
            run = self._settle(run)
            return {"run": run.to_dict(), "task": None, "reason": "NO_READY_TASK"}
        candidate = self.store.candidate(run.target_id, run.id, task.candidate_id)
        if candidate is None:
            raise ValueError("Planner task lacks candidate")
        try:
            if task.task_type in {PlannerTaskType.CREATE_DISPOSABLE_OBJECT,
                                  PlannerTaskType.RESOLVE_IDENTITY, PlannerTaskType.RESOLVE_OBJECT,
                                  PlannerTaskType.REFRESH_TRAFFIC, PlannerTaskType.REFRESH_ASSET,
                                  PlannerTaskType.REQUEST_RESEARCH, PlannerTaskType.MANUAL_REVIEW}:
                self._prerequisite(package, run, task, candidate)
            elif task.task_type is PlannerTaskType.CREATE_PLAN:
                self._prepare(package, run, task, candidate)
            elif task.task_type is PlannerTaskType.RUN_PLAN:
                self._run_plan(package, run, task, candidate)
            elif task.task_type is PlannerTaskType.VALIDATE_RUN:
                self._validate(run, task, candidate)
        except (LookupError, ValueError):
            if self.store.task(run.target_id, run.id, task.id).status is PlannerTaskStatus.RUNNING:
                self._wait(run, task, "SPECIALIST_PREREQUISITE")
        except Exception:
            if self.store.task(run.target_id, run.id, task.id).status is PlannerTaskStatus.RUNNING:
                self._wait(run, task, "AMBIGUOUS_SPECIALIST_ERROR")
        current = self.store.task(run.target_id, run.id, task.id)
        latest = self.store.get(run.target_id, run.id)
        assert current is not None and latest is not None
        if current.status is not PlannerTaskStatus.RUNNING:
            latest = self._settle(latest)
        return {"run": latest.to_dict(), "task": current.to_dict(), "reason":
                current.reason_code or "TASK_IN_PROGRESS"}

    def run_to_pause(self, package: TargetPackage, run_id: str, *, max_steps: int = 50) -> PlannerRun:
        if type(max_steps) is not int or not 1 <= max_steps <= 100:
            raise ValueError("Invalid planner step cap")
        for _ in range(max_steps):
            result = self.advance(package, run_id)
            run = self.store.get(package.target.id, run_id)
            assert run is not None
            if (run.status not in {PlannerStatus.READY, PlannerStatus.RUNNING}
                    or result["task"] is None):
                return run
        result = self.store.get(package.target.id, run_id)
        assert result is not None
        return result

    def pause(self, package: TargetPackage, run_id: str) -> PlannerRun:
        run = self.store.get(package.target.id, run_id)
        if run is None:
            raise LookupError("Planner run not found")
        if package.id != run.package_id:
            raise ValueError("Planner package mismatch")
        if run.status in {PlannerStatus.PAUSED, PlannerStatus.COMPLETED, PlannerStatus.CANCELLED}:
            return run
        for task in self.store.tasks(run.target_id, run.id, limit=MAX_RUN_TASKS):
            if task.task_type is PlannerTaskType.RUN_PLAN and task.status is PlannerTaskStatus.RUNNING:
                candidate = self.store.candidate(run.target_id, run.id, task.candidate_id)
                if candidate and candidate.plan_run_id:
                    self.orchestrator.pause(candidate.plan_run_id, package.id)
        return self.store.transition(run.target_id, run.id, PlannerStatus.PAUSED,
                                     "OPERATOR_PAUSED")

    def resume(self, package: TargetPackage, run_id: str) -> PlannerRun:
        run = self.store.get(package.target.id, run_id)
        if run is None:
            raise LookupError("Planner run not found")
        self._current(package, run)
        if run.status not in {PlannerStatus.PAUSED, PlannerStatus.WAITING_LOGIN,
                              PlannerStatus.WAITING_RESEARCH, PlannerStatus.WAITING_APPROVAL,
                              PlannerStatus.WAITING_HUMAN}:
            raise ValueError("Planner run is not waiting")
        if self._expired(run):
            return self._exhausted(package, run)
        for task in self.store.tasks(run.target_id, run.id, limit=MAX_RUN_TASKS):
            if task.status is PlannerTaskStatus.RUNNING and task.task_type is PlannerTaskType.RUN_PLAN:
                candidate = self.store.candidate(run.target_id, run.id, task.candidate_id)
                if candidate and candidate.plan_run_id:
                    child = self.orchestrator.runs.get(candidate.plan_run_id, run.target_id)
                    if child and child.status.value == "PAUSED":
                        self.orchestrator.resume(child.id, package.id)
                continue
            if task.status is not PlannerTaskStatus.WAITING:
                continue
            candidate = self.store.candidate(run.target_id, run.id, task.candidate_id)
            if candidate is None:
                continue
            if task.reason_code == "LOGIN_REQUIRED" and self._login_ready_for_task(task, candidate):
                self.store.wake_waiting_task(run.target_id, run.id, task.id, "LOGIN_COMPLETED")
            elif (task.reason_code in {"STALE_SOURCE", "AUTONOMOUS_MODE_REQUIRED",
                                        "STALE_SOURCE_REPLACED", "REFRESH_NO_MATCH"}
                  and task.task_type in {PlannerTaskType.REFRESH_ASSET,
                                         PlannerTaskType.REFRESH_TRAFFIC}
                  and self._fresh(package, candidate)):
                self.store.finish_task(run.target_id, run.id, task.id,
                    PlannerTaskStatus.COMPLETED, "SOURCE_REFRESHED")
            elif (task.reason_code == "REFRESH_NO_MATCH" and
                  task.task_type is PlannerTaskType.REFRESH_TRAFFIC and
                  candidate.source_kind == "API_GRAPHQL" and task.attempt < 2):
                source = self._source(candidate)
                operation = (self.api.registry.get_operation(run.target_id, source.operation_id)
                             if source else None)
                if (operation and operation.package_id == package.id and
                        (operation.state == "CURRENT" and source.status == "STALE" or
                         self.api.registry.current_js_replacement_available(
                             run.target_id, operation.id))):
                    self.store.wake_waiting_task(run.target_id, run.id, task.id,
                                                 "SOURCE_CHANGED")
            elif task.reason_code == "AMBIGUOUS_RESTART":
                if task.task_type in {PlannerTaskType.REFRESH_ASSET,
                                      PlannerTaskType.REFRESH_TRAFFIC}:
                    replaced = any(item["relation"] == "SUPERSEDED_BY" for item in
                                   self.store.relationships(run.target_id, run.id, candidate.id))
                    if replaced:
                        self.store.finish_task(run.target_id, run.id, task.id,
                            PlannerTaskStatus.COMPLETED, "SOURCE_SUPERSEDED")
                    elif self._fresh(package, candidate):
                        self.store.finish_task(run.target_id, run.id, task.id,
                            PlannerTaskStatus.COMPLETED, "SOURCE_REFRESHED")
                elif task.task_type is PlannerTaskType.CREATE_PLAN and candidate.plan_id:
                    self.store.finish_task(run.target_id, run.id, task.id,
                        PlannerTaskStatus.COMPLETED, "PLAN_RECOVERED", result_ref=candidate.plan_id)
                elif task.task_type is PlannerTaskType.RUN_PLAN and candidate.plan_run_id:
                    child = self.orchestrator.runs.get(candidate.plan_run_id, run.target_id)
                    if child and child.status.value == "COMPLETED":
                        self.store.finish_task(run.target_id, run.id, task.id,
                            PlannerTaskStatus.COMPLETED, "CHILD_RECOVERED", result_ref=child.id)
            elif (task.reason_code == "APPROVAL_PENDING" and
                  task.task_type is PlannerTaskType.RUN_PLAN and candidate.plan_run_id):
                child = self.orchestrator.runs.get(candidate.plan_run_id, run.target_id)
                if child and child.status.value in {"READY", "RUNNING", "COMPLETED"}:
                    self.store.wake_waiting_task(run.target_id, run.id, task.id,
                                                 "APPROVAL_RESOLVED")
                elif child and child.status.value in {"PAUSED", "WAITING_APPROVAL"}:
                    detail = self.orchestrator.resume(child.id, package.id)
                    if detail["run"]["status"] in {"READY", "RUNNING", "COMPLETED"}:
                        self.store.wake_waiting_task(run.target_id, run.id, task.id,
                                                     "APPROVAL_RESOLVED")
                    elif detail["run"]["status"] in _CHILD_STOPS:
                        self._block(run, task, candidate,
                                    "CHILD_" + str(detail["run"]["status"]))
            elif (task.reason_code == "APPROVAL_PENDING" and
                  task.task_type is PlannerTaskType.CREATE_DISPOSABLE_OBJECT):
                item, approval_state = self._setup_approval_item(task, run)
                if item and approval_state in {"READY", ApprovalStatus.APPROVED_ONCE.value}:
                    self.store.wake_waiting_task(run.target_id, run.id, task.id,
                                                 "SETUP_APPROVAL_RESOLVED")
                elif approval_state in {ApprovalStatus.REJECTED.value,
                                        ApprovalStatus.EXPIRED.value}:
                    self._block(run, task, candidate, "SETUP_APPROVAL_" + approval_state)
            elif (task.reason_code == "CHILD_HUMAN_REVIEW" and
                  task.task_type is PlannerTaskType.RUN_PLAN and candidate.plan_run_id):
                child = self.orchestrator.runs.get(candidate.plan_run_id, run.target_id)
                if child and child.status.value in {"READY", "RUNNING", "COMPLETED"}:
                    self.store.wake_waiting_task(run.target_id, run.id, task.id,
                                                 "CHILD_RESUMED")
                elif child and child.status.value == "PAUSED":
                    detail = self.orchestrator.resume(child.id, package.id)
                    if detail["run"]["status"] in {"READY", "RUNNING", "COMPLETED"}:
                        self.store.wake_waiting_task(run.target_id, run.id, task.id,
                                                     "CHILD_RESUMED")
            elif task.reason_code in {"RESEARCH_PENDING", "RESEARCH_BRIEF_MISSING"} and task.result_ref:
                research = self.research.store.request(run.target_id, task.result_ref)
                if research and research["brief_id"]:
                    brief_id = str(research["brief_id"])
                    reason = self._research_brief_reason(run.target_id, brief_id)
                    if reason != "RESEARCH_BRIEF_MISSING":
                        self.store.finish_task(run.target_id, run.id, task.id,
                            PlannerTaskStatus.COMPLETED, reason, result_ref=brief_id)
            elif (task.reason_code in {"VALID_SKILL_REQUIRED",
                                       "EPHEMERAL_SKILL_REVIEW_REQUIRED"} and
                  task.task_type is PlannerTaskType.CREATE_PLAN and
                  candidate.source_kind == "HYPOTHESIS"):
                hypothesis = self.hypotheses.get(candidate.source_id, run.target_id)
                if hypothesis:
                    try:
                        context = self.contexts.build(
                            hypothesis, self.hypotheses.latest_profile(run.target_id),
                            package=package)
                        routed = self.router.route(hypothesis, context, limit=5)
                    except (LookupError, ValueError):
                        routed = ()
                    valid = False
                    for route in routed:
                        try:
                            self.router.registry.select(str(route["skill"]["name"]))
                        except (KeyError, LookupError, ValueError, UnicodeError, OSError):
                            continue
                        valid = True
                        break
                    if valid:
                        self.store.wake_waiting_task(run.target_id, run.id, task.id,
                                                     "VALID_SKILL_AVAILABLE")
            elif (task.reason_code in {"COMPARISON_OBJECT_REQUIRED",
                                        "COMPARISON_OBJECT_REVIEW"} and
                  candidate.source_kind == "AUTHORIZATION" and
                  self.authorization.comparison_control_ready(candidate.source_id, package)):
                self.store.finish_task(run.target_id, run.id, task.id,
                    PlannerTaskStatus.COMPLETED, "COMPARISON_CONTROL_READY",
                    result_ref=task.result_ref)
            elif task.reason_code in {"OBJECT_MANUAL_REVIEW",
                                       "EXACT_OBJECT_RECIPE_REQUIRED"}:
                item = self._object(candidate)
                if item and item.state is ObjectState.READY and item.verified_at:
                    self.store.finish_task(run.target_id, run.id, task.id,
                        PlannerTaskStatus.COMPLETED, "OWNED_OBJECT_READY",
                        result_ref=item.id)
                elif (task.reason_code == "EXACT_OBJECT_RECIPE_REQUIRED" and item and
                      item.state is ObjectState.PLANNED and
                      task.task_type is PlannerTaskType.CREATE_DISPOSABLE_OBJECT):
                    self.store.wake_waiting_task(run.target_id, run.id, task.id,
                                                 "OBJECT_RECIPE_AVAILABLE")
            elif task.reason_code == "OBJECT_REQUIRED":
                item = self._object(candidate)
                if item and item.state is ObjectState.READY and item.verified_at:
                    if task.task_type is PlannerTaskType.RESOLVE_OBJECT:
                        self.store.finish_task(run.target_id, run.id, task.id,
                            PlannerTaskStatus.COMPLETED, "OWNED_OBJECT_READY", result_ref=item.id)
                    else:
                        self.store.wake_waiting_task(run.target_id, run.id, task.id,
                                                     "OWNED_OBJECT_READY")
        tasks = self.store.tasks(run.target_id, run.id, limit=MAX_RUN_TASKS)
        completed = {task.id for task in tasks if task.status is PlannerTaskStatus.COMPLETED}
        runnable = any(task.status in {PlannerTaskStatus.READY, PlannerTaskStatus.RUNNING}
                       or (task.status is PlannerTaskStatus.PENDING and
                           set(task.dependencies).issubset(completed)) for task in tasks)
        if not runnable and any(task.status is PlannerTaskStatus.WAITING for task in tasks):
            return self.store.get(run.target_id, run.id) or run
        return self.store.transition(run.target_id, run.id, PlannerStatus.READY,
                                     "OPERATOR_RESUMED")

    def cancel(self, package: TargetPackage, run_id: str) -> PlannerRun:
        run = self.store.get(package.target.id, run_id)
        if run is None:
            raise LookupError("Planner run not found")
        if package.id != run.package_id:
            raise ValueError("Planner package mismatch")
        if run.status is PlannerStatus.CANCELLED:
            return run
        ambiguous = False
        for task in self.store.tasks(run.target_id, run.id, limit=MAX_RUN_TASKS):
            if task.task_type is PlannerTaskType.RUN_PLAN and task.status in {
                    PlannerTaskStatus.RUNNING, PlannerTaskStatus.WAITING}:
                candidate = self.store.candidate(run.target_id, run.id, task.candidate_id)
                if not candidate or not candidate.plan_run_id:
                    ambiguous = True
                    continue
                try:
                    self.orchestrator.cancel(candidate.plan_run_id, package.id)
                except (LookupError, ValueError):
                    ambiguous = True
                    continue
                self.store.finish_task(run.target_id, run.id, task.id,
                                       PlannerTaskStatus.CANCELLED, "PLANNER_CANCELLED",
                                       result_ref=candidate.plan_run_id)
        if ambiguous:
            return self.store.transition(run.target_id, run.id, PlannerStatus.PAUSED,
                                         "CHILD_STOP_UNCONFIRMED")
        self.store.cancel_remaining_tasks(run.target_id, run.id)
        return self.store.transition(run.target_id, run.id, PlannerStatus.CANCELLED,
                                     "OPERATOR_CANCELLED")

    def override(self, package: TargetPackage, run_id: str, candidate_id: str,
                 choice: CandidateOverride, *, specialist: Specialist | None = None,
                 skill_id: str | None = None) -> PlannerCandidate:
        run = self.store.get(package.target.id, run_id)
        if run is None:
            raise LookupError("Planner run not found")
        self._current(package, run)
        if run.mode is PlannerMode.ANALYZE_ONLY or run.status not in {
                PlannerStatus.READY, PlannerStatus.PAUSED}:
            raise ValueError("Planner override requires an idle executable run")
        candidate = self.store.candidate(run.target_id, run.id, candidate_id)
        if candidate is None:
            raise LookupError("Planner candidate not found")
        if candidate.plan_id or candidate.status in {
                CandidateStatus.DUPLICATE, CandidateStatus.BLOCKED, CandidateStatus.REJECTED,
                CandidateStatus.VALIDATED, CandidateStatus.RUNNING, CandidateStatus.PLANNED}:
            raise ValueError("Candidate cannot be rerouted after planning")
        cost_requests = cost_browser = None
        changing_specialist = specialist is not None and specialist is not candidate.specialist
        if changing_specialist:
            if choice is not CandidateOverride.PIN or candidate.source_kind != "HYPOTHESIS":
                raise ValueError("Specialist override requires an unplanned hypothesis")
            hypothesis = self.hypotheses.get(candidate.source_id, run.target_id)
            if hypothesis is None:
                raise ValueError("Current hypothesis is required for specialist override")
            context = self.contexts.build(
                hypothesis, self.hypotheses.latest_profile(run.target_id), package=package)
            routed = self.router.route(hypothesis, context, limit=5)
            matching = [item["skill"] for item in routed
                        if _routed_specialist(item["skill"]) is specialist]
            chosen = next((item for item in matching if item["name"] == skill_id), None) \
                if skill_id else next(iter(matching), None)
            if chosen is None:
                raise ValueError("Alternate specialist is not eligible under Phase 15")
            skill_id = str(chosen["name"])
            cost_requests = int(chosen["request_budget"])
            cost_browser = BROWSER_TRIAL_CAPS.get(specialist, 0)
            candidate = replace(candidate, specialist=specialist,
                                estimated_requests=cost_requests,
                                estimated_browser=cost_browser)
        elif skill_id:
            hypothesis = (self.hypotheses.get(candidate.hypothesis_id, run.target_id)
                          if candidate.hypothesis_id else None)
            if hypothesis is None:
                raise ValueError("Skill override needs a current routed hypothesis")
            context = self.contexts.build(
                hypothesis, self.hypotheses.latest_profile(run.target_id), package=package)
            routed = self.router.route(hypothesis, context, limit=5)
            if not any(item["skill"]["name"] == skill_id for item in routed):
                raise ValueError("Skill is not eligible under Phase 15 routing")
            if candidate.source_kind != "HYPOTHESIS" and skill_id not in candidate.skill_ids:
                raise ValueError("Specialist source has a fixed validated skill binding")
        if choice is CandidateOverride.EXCLUDE:
            updated = self.store.override(run.target_id, run.id, candidate_id, choice,
                                          specialist=specialist, skill_id=skill_id,
                                          status=CandidateStatus.SKIPPED)
            self.store.skip_candidate_tasks(run.target_id, run.id, candidate_id,
                                            "OPERATOR_EXCLUDED")
            self.store.recount_selected(run.target_id, run.id)
            return updated
        if choice is CandidateOverride.DEPRIORITIZE:
            return self.store.override(run.target_id, run.id, candidate_id, choice,
                                       specialist=specialist, skill_id=skill_id, priority=0)
        if choice is not CandidateOverride.PIN:
            raise ValueError("Unsupported planner override")
        selected = [item for item in self.store.candidates(run.target_id, run.id, limit=200)
                    if item.id != candidate.id and item.status in {
                        CandidateStatus.SELECTED, CandidateStatus.NEEDS_REFRESH}]
        def fits(items: list[PlannerCandidate]) -> bool:
            return (len(items) + 1 <= run.limits.candidates and
                    sum(item.specialist is candidate.specialist for item in items) + 1
                    <= run.limits.per_specialist and
                    sum(item.estimated_requests for item in items) + candidate.estimated_requests
                    <= run.limits.requests - run.limits.cleanup_reserve and
                    sum(item.estimated_browser for item in items) + candidate.estimated_browser
                    <= run.limits.browser_actions and
                    sum(item.estimated_tokens for item in items) + candidate.estimated_tokens
                    <= run.limits.tokens - run.usage.tokens)
        if candidate.status in {CandidateStatus.SELECTED, CandidateStatus.NEEDS_REFRESH}:
            if not fits(selected):
                raise ValueError("Specialist override exceeds planner budget or cap")
            return self.store.override(run.target_id, run.id, candidate_id, choice,
                                       specialist=specialist, skill_id=skill_id, priority=100,
                                       estimated_requests=cost_requests,
                                       estimated_browser=cost_browser)
        if candidate.status is not CandidateStatus.DEFERRED:
            raise ValueError("Only deferred candidates can be added to the run")
        evictions: list[PlannerCandidate] = []
        if not fits(selected):
            evictable = sorted((item for item in selected
                if all(task.status in {PlannerTaskStatus.PENDING, PlannerTaskStatus.READY}
                        for task in self.store.tasks(run.target_id, run.id, limit=MAX_RUN_TASKS)
                        if task.candidate_id == item.id)), key=lambda item: (item.priority, item.id))
            for item in evictable:
                selected.remove(item)
                evictions.append(item)
                if fits(selected):
                    break
        if not fits(selected):
            raise ValueError("Pin exceeds candidate, specialist, or budget cap")
        for item in evictions:
            self.store.override(run.target_id, run.id, item.id,
                                CandidateOverride.DEPRIORITIZE,
                                status=CandidateStatus.DEFERRED, priority=0)
            self.store.skip_candidate_tasks(run.target_id, run.id, item.id,
                                            "PINNED_CANDIDATE_PRECEDENCE")
        updated = self.store.override(run.target_id, run.id, candidate_id, choice,
                                      specialist=specialist, skill_id=skill_id,
                                      status=CandidateStatus.SELECTED, priority=100,
                                      estimated_requests=cost_requests,
                                      estimated_browser=cost_browser)
        self.planner.build_tasks(run, updated)
        self.store.recount_selected(run.target_id, run.id)
        return updated
