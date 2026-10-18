"""Explicit, bounded coordination of existing policy-gated BugHunter components."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
from typing import TYPE_CHECKING

from .behaviour import LearningLimits, LearningStatus
from .bootstrap_store import BootstrapIdentityPolicy, BootstrapLimits, BootstrapStatus
from .campaign_models import (
    Campaign, CampaignLimits, CampaignStatus, CampaignWorkKind,
    CampaignWorkStatus, TERMINAL_CAMPAIGN_STATUSES,
)
from .campaign_store import CampaignStore
from .planner_models import (
    CandidateStatus, PlannerLimits, PlannerMode, PlannerStatus, PlannerTaskType,
    TERMINAL_STATUSES,
)
from .policy import policy_version
from .profile import AttackSurfaceProfiler
from .research import GapType, ResearchBudget, ResearchStatus
from .resources import ResourceError, WorkKind
from .target_package import TargetPackage
from .test_objects import ObjectState

if TYPE_CHECKING:
    from .service import BugHunterRuntime


_WAIT_MAP = {
    PlannerStatus.WAITING_LOGIN: CampaignStatus.WAITING_LOGIN,
    PlannerStatus.WAITING_APPROVAL: CampaignStatus.WAITING_APPROVAL,
    PlannerStatus.WAITING_RESEARCH: CampaignStatus.WAITING_RESEARCH,
    PlannerStatus.WAITING_HUMAN: CampaignStatus.WAITING_HUMAN,
    PlannerStatus.PAUSED: CampaignStatus.WAITING_HUMAN,
}


class CampaignCoordinator:
    """Decides when to call existing components; never issues a request or finding."""

    def __init__(self, runtime: BugHunterRuntime) -> None:
        self.runtime = runtime
        self.store = CampaignStore(runtime.store)

    def start(self, package: TargetPackage, *, mode: PlannerMode,
              limits: CampaignLimits, requested_by: str = "operator") -> Campaign:
        self.runtime.resources.admit(WorkKind.CAMPAIGN, active=self.active_count())
        self.runtime.registry.register_target(package)
        return self.store.create(package, mode, limits, policy_version(package), requested_by)

    def active_count(self) -> int:
        with self.runtime.store._connection() as db:
            return db.execute("SELECT count(*) FROM campaigns WHERE status IN "
                              "('CREATED','ASSESSING_READINESS','RUNNING')").fetchone()[0]

    @staticmethod
    def _remaining(campaign: Campaign) -> dict[str, int]:
        limits, used = campaign.limits, campaign.usage
        elapsed = (int((datetime.now(timezone.utc) -
                        datetime.fromisoformat(campaign.started_at)).total_seconds())
                   if campaign.started_at else 0)
        return {
            "requests": max(0, limits.requests - limits.cleanup_reserve -
                            used.requests - used.cleanup_requests),
            "browser_actions": max(0, limits.browser_actions - used.browser_actions),
            "research_requests": max(0, limits.research_requests - used.research_requests),
            "tokens": max(0, limits.tokens - used.tokens),
            "setup_objects": max(0, limits.setup_objects - used.setup_objects),
            "seconds": max(0, limits.seconds - elapsed),
        }

    def detail(self, package: TargetPackage, campaign_id: str) -> dict[str, object]:
        campaign = self.store.get(package.target.id, campaign_id)
        if campaign is None or campaign.package_id != package.id:
            raise LookupError("Campaign not found")
        cycles = self.store.cycles(package.target.id, campaign_id)
        works = self.store.works(package.target.id, campaign_id)
        linked = []
        candidates = []
        tasks = []
        active_tasks = []
        for work in works:
            summary = work.to_dict()
            if work.kind is CampaignWorkKind.PLANNER and work.child_id:
                run = self.runtime.planner_store.get(package.target.id, work.child_id)
                summary["planner"] = run.to_dict() if run else None
                if run:
                    run_candidates = self.runtime.planner_store.candidates(
                        package.target.id, run.id, limit=200)
                    run_tasks = self.runtime.planner_store.tasks(
                        package.target.id, run.id, limit=320)
                    candidates.extend(run_candidates)
                    tasks.extend(run_tasks)
                    specialist_by_candidate = {item.id: item.specialist.value
                                               for item in run_candidates}
                    for task in run_tasks:
                        if task.status.value in {"PENDING", "READY", "RUNNING", "WAITING"}:
                            active_tasks.append({
                                "planner_run_id": run.id,
                                "task_type": task.task_type.value,
                                "status": task.status.value,
                                "reason_code": task.reason_code,
                                "specialist": specialist_by_candidate.get(task.candidate_id),
                            })
            linked.append(summary)
        context, remaining = self._readiness(package, campaign)
        behaviour = self.runtime.behaviour_store.profile(package.target.id)
        resource = self.runtime.resources.snapshot()
        findings = self.finding_links(package.target.id, campaign_id)
        with self.runtime.store._connection() as db:
            notification_events = db.execute(
                "SELECT count(DISTINCT n.event_id) FROM notification_events AS n "
                "WHERE n.target_id=? AND ("
                "(n.source_kind='PLANNER' AND n.source_id IN ("
                "SELECT child_id FROM campaign_work WHERE campaign_id=? AND kind='PLANNER')) "
                "OR n.finding_id IN (SELECT p.finding_id FROM planner_candidates AS p "
                "JOIN campaign_work AS w ON w.child_id=p.run_id "
                "WHERE w.campaign_id=? AND w.kind='PLANNER' AND p.finding_id IS NOT NULL))",
                (campaign.target_id, campaign_id, campaign_id)).fetchone()[0]
        planner_runs = [work["planner"] for work in linked if work.get("planner")]
        objects = self.store.objects(package.target.id, campaign_id)
        pending_objects = sum(item["cleanup_status"] != "CLEANED" for item in objects)
        metrics = {
            "planner_runs": len(planner_runs),
            "candidates_considered": sum(run["candidate_count"] for run in planner_runs),
            "candidates_selected": sum(run["selected_count"] for run in planner_runs),
            "plans_created": sum(run["plans_created"] for run in planner_runs),
            "plans_executed": sum(run["plans_executed"] for run in planner_runs),
            "validations": sum(run["validations"] for run in planner_runs),
            "manual_reviews": sum(run["manual_reviews"] for run in planner_runs),
            "findings": len(findings), "cleanup_pending": pending_objects,
            "rejected_validations": sum(candidate.status is CandidateStatus.REJECTED
                                        and candidate.validation_id is not None
                                        for candidate in candidates),
            "research_work": sum(work.kind is CampaignWorkKind.RESEARCH and
                                 work.status is CampaignWorkStatus.COMPLETED
                                 for work in works),
            "objects_created": len(objects),
            "objects_cleaned": len(objects) - pending_objects,
            "report_drafts": sum(item["report_id"] is not None for item in findings),
            "notification_events": notification_events,
            "requests_per_finding": (round((campaign.usage.requests +
                                             campaign.usage.cleanup_requests) / len(findings), 2)
                                     if findings else None),
        }
        exercised = {candidate.specialist.value for candidate in candidates
                     if candidate.status in {CandidateStatus.PLANNED,
                                             CandidateStatus.RUNNING,
                                             CandidateStatus.WAITING,
                                             CandidateStatus.VALIDATED,
                                             CandidateStatus.REJECTED}}
        processed = {CandidateStatus.VALIDATED, CandidateStatus.REJECTED,
                     CandidateStatus.DUPLICATE, CandidateStatus.SKIPPED}
        waiting_tasks = sum(task.status.value == "WAITING" for task in tasks)
        progress = {
            "completed_tasks": sum(task.status.value == "COMPLETED" for task in tasks),
            "active_tasks": len(active_tasks),
            "high_priority_candidates_processed": sum(
                candidate.priority >= 80 and candidate.status in processed
                for candidate in candidates),
            "remaining_blockers": max(waiting_tasks, int(campaign.status in {
                CampaignStatus.WAITING_LOGIN, CampaignStatus.WAITING_APPROVAL,
                CampaignStatus.WAITING_RESEARCH, CampaignStatus.WAITING_HUMAN})),
            "knowledge_changes": max(0, len({cycle["source_digest"] for cycle in cycles
                                              if cycle["source_digest"]}) - 1),
        }
        coverage_summary = {
            "identities": len(context.identity_ids),
            "verified_identities": len(context.verified_identity_ids),
            "roles": len(behaviour.roles) if behaviour else 0,
            "tenants": max(len(context.tenant_ids), len(behaviour.tenants) if behaviour else 0),
            "features": (len(behaviour.features) if behaviour else
                         len(package.context.known_features)),
            "specialists_exercised": sorted(exercised),
            "candidate_classes": dict(sorted(Counter(candidate.category for candidate in
                                                      candidates).items())),
            "validated_outcomes": dict(sorted(Counter(candidate.status.value for candidate in
                                                        candidates if candidate.status in {
                    CandidateStatus.VALIDATED, CandidateStatus.REJECTED,
                    CandidateStatus.DUPLICATE}).items())),
        }
        return {
            "campaign": campaign.to_dict(), "remaining": remaining,
            "readiness": context.public_dict(),
            "resource": {"state": resource.state, "warnings": list(resource.warnings)},
            "capture": self.runtime.burp.status(campaign.target_id),
            "metrics": metrics, "progress": progress,
            "coverage_summary": coverage_summary,
            "cycles": cycles, "work": linked,
            "active_tasks": active_tasks[:24],
            "active_tasks_truncated": len(active_tasks) > 24,
            "objects": objects,
            "suppressions": self.store.suppressions(package.target.id, campaign_id),
            "timeline": self.store.events(package.target.id, campaign_id),
            "findings": findings,
        }

    def finding_links(self, target_id: str, campaign_id: str) -> tuple[dict[str, str], ...]:
        with self.runtime.store._connection() as db:
            rows = db.execute(
                "SELECT DISTINCT p.finding_id,p.validation_id,p.plan_run_id,"
                "p.run_id AS planner_run_id,r.report_id "
                "FROM planner_candidates AS p JOIN campaign_work AS w "
                "ON w.child_id=p.run_id AND w.kind='PLANNER' "
                "LEFT JOIN report_drafts AS r ON r.report_id=("
                "SELECT rd.report_id FROM report_drafts AS rd WHERE rd.finding_id=p.finding_id "
                "ORDER BY rd.version DESC LIMIT 1) "
                "WHERE w.campaign_id=? AND p.target_id=? AND p.finding_id IS NOT NULL "
                "ORDER BY p.finding_id LIMIT 100", (campaign_id, target_id)).fetchall()
        return tuple(dict(row) for row in rows)

    def _resource(self, kind: WorkKind) -> str | None:
        active_sets = {
            WorkKind.PLANNER: self.runtime._planner_threads,
            WorkKind.BOOTSTRAP: self.runtime._bootstrap_threads,
            WorkKind.LEARNING: self.runtime._behaviour_threads,
            WorkKind.RESEARCH: self.runtime._research_threads,
        }
        active = sum(thread.is_alive() for thread in active_sets.get(kind, {}).values())
        try:
            self.runtime.resources.admit(kind, active=active)
        except ResourceError as exc:
            return exc.reason_code
        return None

    def _pause_for_resource(self, campaign: Campaign, reason: str) -> Campaign:
        return self.store.transition(campaign.target_id, campaign.id,
                                     CampaignStatus.PAUSED, reason)

    def _expired(self, campaign: Campaign) -> bool:
        return self._remaining(campaign)["seconds"] == 0

    def _has_active_session(self, target_id: str) -> bool:
        page = self.runtime.identities.list_identities(target_id, limit=50)
        return any(self.runtime.browser.get_active_session(target_id, item.id)
                   is not None for item in page.items)

    def _track_planner_objects(self, campaign: Campaign, work_id: str,
                               planner_run_id: str) -> None:
        for task in self.runtime.planner_store.tasks(campaign.target_id, planner_run_id,
                                                     limit=320):
            if task.task_type is PlannerTaskType.CREATE_DISPOSABLE_OBJECT and task.result_ref:
                self.store.track_created_object(campaign.target_id, campaign.id,
                                                work_id, task.result_ref)

    def _record_outcomes(self, campaign: Campaign, planner_run_id: str) -> None:
        for candidate in self.runtime.planner_store.candidates(
                campaign.target_id, planner_run_id, limit=200):
            if candidate.status is CandidateStatus.VALIDATED and candidate.finding_id:
                kind = "CONFIRMED"
            elif candidate.status is CandidateStatus.REJECTED:
                kind = "REJECTED"
            else:
                continue
            if candidate.state_hash:
                self.store.suppress(campaign.target_id, campaign.id,
                                    candidate.root_cause_key, candidate.state_hash, kind)

    def _cleanup(self, package: TargetPackage, campaign: Campaign,
                 desired: CampaignStatus, reason: str) -> Campaign:
        self.store.reconcile_objects(campaign.target_id, campaign.id)
        objects = self.store.objects(campaign.target_id, campaign.id)
        for row in objects:
            object_id = row["object_id"]
            state = self.store.refresh_object_cleanup(campaign.target_id,
                                                      campaign.id, object_id)
            if state == "CLEANED":
                continue
            if state == "ORPHANED":
                return self.store.transition(campaign.target_id, campaign.id,
                                             CampaignStatus.CLEANUP_REQUIRED,
                                             "OBJECT_ORPHANED")
            item = self.runtime.objects.get(object_id, campaign.target_id)
            if item is None or item.state not in {ObjectState.READY, ObjectState.CLEANUP_PENDING}:
                return self.store.transition(campaign.target_id, campaign.id,
                                             CampaignStatus.CLEANUP_REQUIRED,
                                             "OBJECT_NOT_CLEANABLE")
            session = self.runtime.browser.get_active_session(campaign.target_id,
                                                              item.creator_identity_id)
            if session is None:
                return self.store.transition(campaign.target_id, campaign.id,
                                             CampaignStatus.CLEANUP_REQUIRED,
                                             "CLEANUP_LOGIN_REQUIRED")
            try:
                work = self.store.reserve_work(campaign.target_id, campaign.id,
                                               CampaignWorkKind.CLEANUP, requests=3)
                self.store.link_child(campaign.target_id, campaign.id, work.id, object_id)
                result = self.runtime.object_factory.cleanup(
                    object_id, campaign.target_id, session_id=session.id)
            except (ValueError, LookupError, ResourceError):
                return self.store.transition(campaign.target_id, campaign.id,
                                             CampaignStatus.CLEANUP_REQUIRED,
                                             "CLEANUP_BLOCKED")
            self.store.refresh_object_cleanup(campaign.target_id, campaign.id, object_id)
            if result.outcome != "CLEANED":
                return self.store.transition(campaign.target_id, campaign.id,
                                             CampaignStatus.CLEANUP_REQUIRED,
                                             "CLEANUP_REVIEW_REQUIRED")
            self.store.finish_work(campaign.target_id, campaign.id, work.id,
                                   reason="ABSENCE_VERIFIED")
        return self.store.transition(campaign.target_id, campaign.id, desired, reason)

    def _readiness(self, package: TargetPackage, campaign: Campaign) -> tuple[object, dict[str, int]]:
        remaining = self._remaining(campaign)
        probe = PlannerLimits(requests=min(remaining["requests"], 20),
                              browser_actions=min(remaining["browser_actions"], 12),
                              tokens=min(remaining["tokens"], 2000),
                              seconds=max(1, min(remaining["seconds"], 300)),
                              cleanup_reserve=0)
        return self.runtime.planner_context.build(package, probe), remaining

    def _bootstrap(self, package: TargetPackage, campaign: Campaign,
                   remaining: dict[str, int]) -> bool:
        if (campaign.mode is not PlannerMode.BOUNDED_AUTONOMOUS or
                remaining["requests"] < 2 or remaining["seconds"] < 20):
            return False
        reason = self._resource(WorkKind.BOOTSTRAP)
        if reason:
            self._pause_for_resource(campaign, reason)
            return True
        allowance = min(remaining["requests"], 8)
        work = self.store.reserve_work(campaign.target_id, campaign.id,
                                       CampaignWorkKind.BOOTSTRAP, requests=allowance)
        limits = BootstrapLimits(max_requests=allowance, max_pages=3,
                                 max_navigation_depth=1, max_js_assets=3,
                                 max_bootstrap_duration=min(remaining["seconds"], 120))
        run = self.runtime.bootstrap.create(
            package.id, limits=limits,
            identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY,
            campaign_work_id=work.id)
        result = self.runtime.bootstrap.run(run.bootstrap_id, package.id)
        if result.status in {BootstrapStatus.COMPLETED, BootstrapStatus.PARTIAL,
                             BootstrapStatus.BLOCKED, BootstrapStatus.FAILED,
                             BootstrapStatus.BUDGET_EXHAUSTED, BootstrapStatus.CANCELLED}:
            self.store.finish_work(campaign.target_id, campaign.id, work.id,
                                   reason="BOOTSTRAP_SETTLED")
        elif result.status is BootstrapStatus.WAITING_LOGIN:
            self.store.transition(campaign.target_id, campaign.id,
                                  CampaignStatus.WAITING_LOGIN,
                                  "BOOTSTRAP_LOGIN_REQUIRED")
        return True

    def _learn(self, package: TargetPackage, campaign: Campaign,
               remaining: dict[str, int]) -> bool:
        if remaining["seconds"] < 10:
            return False
        reason = self._resource(WorkKind.LEARNING)
        if reason:
            self._pause_for_resource(campaign, reason)
            return True
        work = self.store.reserve_work(campaign.target_id, campaign.id,
                                       CampaignWorkKind.BEHAVIOUR)
        run = self.runtime.behaviour.create(
            package, limits=LearningLimits(max_duration_seconds=min(remaining["seconds"], 60)),
            campaign_work_id=work.id)
        source = AttackSurfaceProfiler(
            self.runtime.registry, self.runtime.store, self.runtime.traffic,
            self.runtime.recon, bootstrap=self.runtime.bootstrap_store).profile(package)
        result = self.runtime.behaviour.run(package, run.run_id, target_profile=source)
        if result.status is LearningStatus.WAITING_LOGIN:
            self.store.transition(campaign.target_id, campaign.id,
                                  CampaignStatus.WAITING_LOGIN,
                                  "BEHAVIOUR_LOGIN_REQUIRED")
        elif result.status in {LearningStatus.COMPLETED, LearningStatus.PARTIAL,
                               LearningStatus.BLOCKED, LearningStatus.FAILED,
                               LearningStatus.CANCELLED}:
            self.store.finish_work(campaign.target_id, campaign.id, work.id,
                                   reason="BEHAVIOUR_SETTLED")
        return True

    def _research(self, campaign: Campaign, remaining: dict[str, int]) -> bool:
        if remaining["research_requests"] == 0 or remaining["tokens"] < 100:
            return False
        gaps = self.runtime.research_store.gaps(campaign.target_id, limit=12)
        gap = next((item for item in gaps if item.gap_type in {
            GapType.UNKNOWN_PROTOCOL, GapType.NEW_API_STYLE,
            GapType.UNKNOWN_FRAMEWORK, GapType.NEW_FRAMEWORK}), None)
        if gap is None:
            return False
        reason = self._resource(WorkKind.RESEARCH)
        if reason:
            return False
        budget = ResearchBudget(max_tokens=min(500, remaining["tokens"]),
                                max_duration_seconds=min(20, remaining["seconds"]))
        cache_key = self.runtime.research.cache_key(gap, private_target=True)
        if (self.runtime.research_store.active_for_cache(cache_key, campaign.target_id)
                or any(work.kind is CampaignWorkKind.RESEARCH for work in
                       self.store.works(campaign.target_id, campaign.id))):
            return False
        work = self.store.reserve_work(campaign.target_id, campaign.id,
                                       CampaignWorkKind.RESEARCH,
                                       research_requests=1, tokens=budget.max_tokens)
        submission = self.runtime.research.submit(
            gap, budget=budget, external=False, private_target=True,
            campaign_work_id=work.id)
        outcome = (submission if submission["status"] == "CACHE_HIT" else
                   self.runtime.research.run(gap, str(submission["request_id"])))
        if outcome["status"] in {"CACHE_HIT", "COMPLETED", "PARTIAL", "FAILED", "BLOCKED"}:
            self.store.finish_work(campaign.target_id, campaign.id, work.id,
                                   reason="RESEARCH_SETTLED")
        return True

    def _planner(self, package: TargetPackage, campaign: Campaign,
                 remaining: dict[str, int]) -> Campaign:
        if (campaign.mode is PlannerMode.BOUNDED_AUTONOMOUS and
                remaining["requests"] == 0):
            return self._cleanup(package, campaign, CampaignStatus.BUDGET_EXHAUSTED,
                                 "REQUEST_BUDGET_REACHED")
        reason = self._resource(WorkKind.PLANNER)
        if reason:
            return self._pause_for_resource(campaign, reason)
        active = campaign.mode is PlannerMode.BOUNDED_AUTONOMOUS
        request_cap = min(remaining["requests"], 20)
        browser_cap = min(remaining["browser_actions"], 12)
        token_cap = min(remaining["tokens"], 2000)
        research_cap = min(remaining["research_requests"], 1) if active else 0
        setup_cap = min(remaining["setup_objects"], 1) if active else 0
        work = self.store.reserve_work(
            campaign.target_id, campaign.id, CampaignWorkKind.PLANNER,
            requests=request_cap if active else 0,
            browser_actions=browser_cap if active else 0,
            research_requests=research_cap, tokens=token_cap,
            setup_objects=setup_cap)
        limits = PlannerLimits(
            requests=request_cap, browser_actions=browser_cap, tokens=token_cap,
            seconds=max(1, min(remaining["seconds"], 300)), candidates=8,
            per_specialist=3, cleanup_reserve=0)
        with self.runtime._planner_lock:
            run = self.runtime.planner.start(package, mode=campaign.mode,
                                             limits=limits, campaign_work_id=work.id,
                                             suppressed_roots=frozenset(
                                                 (item["root_key"], item["state_hash"])
                                                 for item in self.store.suppressions(
                                                     campaign.target_id, campaign.id)))
        return self.store.get(campaign.target_id, campaign.id) or campaign

    def _settle_prerequisite(self, campaign: Campaign, work) -> Campaign:
        if work.kind is CampaignWorkKind.BOOTSTRAP:
            child = self.runtime.bootstrap_store.get(work.child_id, campaign.target_id)
            status = child.status if child else None
            terminal = {BootstrapStatus.PARTIAL, BootstrapStatus.COMPLETED,
                        BootstrapStatus.BLOCKED, BootstrapStatus.FAILED,
                        BootstrapStatus.BUDGET_EXHAUSTED, BootstrapStatus.CANCELLED}
        elif work.kind is CampaignWorkKind.BEHAVIOUR:
            child = self.runtime.behaviour_store.get_run(campaign.target_id, work.child_id)
            status = child.status if child else None
            terminal = {LearningStatus.COMPLETED, LearningStatus.PARTIAL,
                        LearningStatus.BLOCKED, LearningStatus.FAILED,
                        LearningStatus.CANCELLED}
        elif work.kind is CampaignWorkKind.RESEARCH:
            child = self.runtime.research_store.typed_request(campaign.target_id,
                                                               work.child_id)
            status = child.status if child else None
            terminal = {ResearchStatus.CACHE_HIT, ResearchStatus.COMPLETED,
                        ResearchStatus.PARTIAL, ResearchStatus.BLOCKED,
                        ResearchStatus.FAILED, ResearchStatus.CANCELLED,
                        ResearchStatus.STALE}
        else:
            return self.store.transition(campaign.target_id, campaign.id,
                                         CampaignStatus.WAITING_HUMAN,
                                         "CLEANUP_RECONCILIATION_REQUIRED")
        if status is not None and status.value == "WAITING_LOGIN" and self._has_active_session(
                campaign.target_id):
            self.store.finish_work(campaign.target_id, campaign.id, work.id,
                                   reason="LOGIN_RESTORED")
            return self.store.get(campaign.target_id, campaign.id) or campaign
        if status in terminal:
            self.store.finish_work(campaign.target_id, campaign.id, work.id,
                                   reason="PREREQUISITE_SETTLED")
            return self.store.get(campaign.target_id, campaign.id) or campaign
        wait_status = (CampaignStatus.WAITING_LOGIN if status and
                       status.value == "WAITING_LOGIN" else CampaignStatus.WAITING_HUMAN)
        return self.store.transition(campaign.target_id, campaign.id, wait_status,
                                     "CHILD_RECONCILIATION_REQUIRED")

    def advance(self, package: TargetPackage, campaign_id: str) -> Campaign:
        campaign = self.store.get(package.target.id, campaign_id)
        if campaign is None or campaign.package_id != package.id:
            raise LookupError("Campaign not found")
        if campaign.status in TERMINAL_CAMPAIGN_STATUSES or campaign.status in {
                CampaignStatus.PAUSED, CampaignStatus.WAITING_LOGIN,
                CampaignStatus.WAITING_APPROVAL, CampaignStatus.WAITING_RESEARCH,
                CampaignStatus.WAITING_HUMAN}:
            return campaign
        if package.status.value != "TRACKED":
            return self.store.transition(campaign.target_id, campaign.id,
                                         CampaignStatus.BLOCKED, "TARGET_UNAVAILABLE")
        current_hash = policy_version(package)
        if (campaign.package_version != package.version or
                campaign.policy_hash != current_hash):
            return self._pause_for_resource(campaign, "PACKAGE_POLICY_CHANGED")
        if campaign.status is CampaignStatus.CREATED:
            return self.store.transition(campaign.target_id, campaign.id,
                                         CampaignStatus.ASSESSING_READINESS,
                                         "READINESS_STARTED")
        if self._expired(campaign):
            return self._cleanup(package, campaign, CampaignStatus.TIME_EXHAUSTED,
                                 "TIME_LIMIT_REACHED")
        cycles = self.store.cycles(campaign.target_id, campaign.id)
        active = next((work for work in reversed(self.store.works(
            campaign.target_id, campaign.id)) if work.status in {
                CampaignWorkStatus.LINKED, CampaignWorkStatus.INTENT,
                CampaignWorkStatus.AMBIGUOUS}), None)
        if active is not None:
            if active.status is not CampaignWorkStatus.LINKED or active.child_id is None:
                return self.store.transition(campaign.target_id, campaign.id,
                                             CampaignStatus.WAITING_HUMAN,
                                             "AMBIGUOUS_CHILD_START")
            if active.kind is CampaignWorkKind.PLANNER:
                reason = self._resource(WorkKind.PLANNER)
                if reason:
                    return self._pause_for_resource(campaign, reason)
                with self.runtime._planner_lock:
                    child = self.runtime.planner_store.get(campaign.target_id, active.child_id)
                    if child is None:
                        return self.store.transition(campaign.target_id, campaign.id,
                                                     CampaignStatus.WAITING_HUMAN,
                                                     "CHILD_MISSING")
                    if child.status in {PlannerStatus.READY, PlannerStatus.RUNNING}:
                        result = self.runtime.planner_runner.advance(package, child.id)
                        self.runtime.record_planner_notification(campaign.target_id,
                                                                 child.id, result)
                        child = self.runtime.planner_store.get(campaign.target_id, child.id)
                    assert child is not None
                self._track_planner_objects(campaign, active.id, child.id)
                self._record_outcomes(campaign, child.id)
                if child.status in _WAIT_MAP:
                    return self.store.transition(campaign.target_id, campaign.id,
                                                 _WAIT_MAP[child.status],
                                                 "PLANNER_" + child.status.value)
                if child.status not in TERMINAL_STATUSES:
                    return self.store.get(campaign.target_id, campaign.id) or campaign
                self.store.finish_work(campaign.target_id, campaign.id, active.id,
                                       reason="PLANNER_SETTLED")
                if campaign.mode is PlannerMode.ANALYZE_ONLY or child.selected_count == 0:
                    return self._cleanup(package, campaign, CampaignStatus.COMPLETED,
                                         "NO_READY_WORK")
                if campaign.current_cycle >= campaign.limits.max_cycles:
                    return self._cleanup(package, campaign, CampaignStatus.COMPLETED,
                                         "CYCLE_CAP_REACHED")
                context, _ = self._readiness(package, campaign)
                if context.snapshot_hash == child.context_hash:
                    return self._cleanup(package, campaign, CampaignStatus.COMPLETED,
                                         "KNOWLEDGE_STABLE")
                return self.store.transition(campaign.target_id, campaign.id,
                                             CampaignStatus.ASSESSING_READINESS,
                                             "KNOWLEDGE_CHANGED")
            return self._settle_prerequisite(campaign, active)
        if campaign.status is CampaignStatus.ASSESSING_READINESS:
            reason = self._resource(WorkKind.CAMPAIGN)
            if reason:
                return self._pause_for_resource(campaign, reason)
            if campaign.current_cycle >= campaign.limits.max_cycles:
                return self._cleanup(package, campaign, CampaignStatus.COMPLETED,
                                     "CYCLE_CAP_REACHED")
            context, _ = self._readiness(package, campaign)
            campaign = self.store.begin_cycle(package, campaign.id, current_hash,
                                              source_digest=context.snapshot_hash,
                                              readiness_digest=context.snapshot_hash,
                                              behaviour_run_id=context.behaviour_run_id)
            return self.store.transition(campaign.target_id, campaign.id,
                                         CampaignStatus.RUNNING, "CYCLE_READY",
                                         package=package, policy_hash=current_hash)
        context, remaining = self._readiness(package, campaign)
        if (campaign.current_cycle == 1 and context.profile_id is None and
                not context.recent_exchange_ids and context.recon_status != "RECON_BACKED" and
                self.runtime.bootstrap_store.list_runs(campaign.target_id, limit=1) == ()):
            if self._bootstrap(package, campaign, remaining):
                return self.store.get(campaign.target_id, campaign.id) or campaign
        if (campaign.mode is PlannerMode.BOUNDED_AUTONOMOUS and
                context.recent_exchange_ids and context.behaviour_run_id is None and
                self.runtime.behaviour_store.list_runs(campaign.target_id, limit=1) == ()):
            if self._learn(package, campaign, remaining):
                return self.store.get(campaign.target_id, campaign.id) or campaign
        if campaign.mode is PlannerMode.BOUNDED_AUTONOMOUS and self._research(campaign, remaining):
            return self.store.get(campaign.target_id, campaign.id) or campaign
        return self._planner(package, campaign, remaining)

    def pause(self, package: TargetPackage, campaign_id: str) -> Campaign:
        campaign = self.store.get(package.target.id, campaign_id)
        if campaign is None:
            raise LookupError("Campaign not found")
        for work in self.store.works(campaign.target_id, campaign.id):
            if work.kind is CampaignWorkKind.PLANNER and work.status is CampaignWorkStatus.LINKED:
                with self.runtime._planner_lock:
                    self.runtime.planner_runner.pause(package, work.child_id)
        return self.store.transition(campaign.target_id, campaign.id,
                                     CampaignStatus.PAUSED, "OPERATOR_PAUSED")

    def resume(self, package: TargetPackage, campaign_id: str) -> Campaign:
        campaign = self.store.get(package.target.id, campaign_id)
        if campaign is None or campaign.status not in {
                CampaignStatus.PAUSED, CampaignStatus.WAITING_LOGIN,
                CampaignStatus.WAITING_APPROVAL, CampaignStatus.WAITING_RESEARCH,
                CampaignStatus.WAITING_HUMAN}:
            raise ValueError("Campaign is not waiting")
        if (campaign.status is CampaignStatus.WAITING_LOGIN and
                not self._has_active_session(campaign.target_id)):
            return campaign
        self.runtime.resources.admit(WorkKind.CAMPAIGN, active=self.active_count())
        if package.status.value != "TRACKED":
            raise ValueError("Target Package is not tracked")
        if (campaign.package_version != package.version or
                campaign.policy_hash != policy_version(package)):
            return self.store.transition(campaign.target_id, campaign.id,
                                         CampaignStatus.ASSESSING_READINESS,
                                         "PACKAGE_REASSESSMENT_REQUIRED",
                                         package=package, policy_hash=policy_version(package))
        if campaign.current_cycle == 0:
            return self.store.transition(campaign.target_id, campaign.id,
                                         CampaignStatus.ASSESSING_READINESS,
                                         "OPERATOR_RESUMED",
                                         package=package, policy_hash=policy_version(package))
        for work in self.store.works(campaign.target_id, campaign.id):
            if work.kind is CampaignWorkKind.PLANNER and work.status is CampaignWorkStatus.LINKED:
                with self.runtime._planner_lock:
                    child = self.runtime.planner_store.get(campaign.target_id, work.child_id)
                    if child and child.status in _WAIT_MAP:
                        self.runtime.planner_runner.resume(package, child.id)
        return self.store.transition(campaign.target_id, campaign.id,
                                     CampaignStatus.RUNNING, "OPERATOR_RESUMED",
                                     package=package, policy_hash=policy_version(package))

    def cancel(self, package: TargetPackage, campaign_id: str) -> Campaign:
        campaign = self.store.get(package.target.id, campaign_id)
        if campaign is None:
            raise LookupError("Campaign not found")
        uncertain_child = False
        for work in self.store.works(campaign.target_id, campaign.id):
            if work.kind is CampaignWorkKind.PLANNER and work.status is CampaignWorkStatus.LINKED:
                with self.runtime._planner_lock:
                    child = self.runtime.planner_store.get(campaign.target_id, work.child_id)
                    if child and child.status not in TERMINAL_STATUSES:
                        stopped = self.runtime.planner_runner.cancel(package, child.id)
                        uncertain_child = uncertain_child or stopped.status not in TERMINAL_STATUSES
        if uncertain_child:
            return self.store.transition(campaign.target_id, campaign.id,
                                         CampaignStatus.WAITING_HUMAN,
                                         "CHILD_STOP_UNCONFIRMED")
        self.store.reconcile_objects(campaign.target_id, campaign.id)
        if self.store.objects(campaign.target_id, campaign.id):
            return self._cleanup(package, campaign, CampaignStatus.CANCELLED,
                                 "OPERATOR_CANCELLED")
        return self.store.transition(campaign.target_id, campaign.id,
                                     CampaignStatus.CANCELLED, "OPERATOR_CANCELLED")
