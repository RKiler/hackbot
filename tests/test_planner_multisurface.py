"""Phase 28 routing acceptance against one synthetic, store-backed target."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
import sqlite3
from threading import Event, Lock
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hackbot.api_registry import APIOperationRegistry
from hackbot.api_specialist import APISpecialist
from hackbot.authorization_store import AuthorizationMode, Boundary
from hackbot.behaviour import BehaviourStore
from hackbot.bootstrap_store import BootstrapStore
from hackbot.campaign import CampaignCoordinator
from hackbot.campaign_models import CampaignLimits, CampaignStatus, CampaignWorkKind
from hackbot.campaign_store import CampaignStore
from hackbot.domain import TrafficSource
from hackbot.domxss_static import DOMStaticAnalyzer
from hackbot.domxss_store import DOMXSSStore
from hackbot.exposure import ExposureSpecialist
from hackbot.exposure_models import ExposureCategory, ExposureStatus
from hackbot.exposure_store import ExposureStore
from hackbot.orchestrator import PlanOrchestrator
from hackbot.notification_store import NotificationStore
from hackbot.planner import CrossSpecialistPlanner, _Signal
from hackbot.planner_context import PlannerContextBuilder
from hackbot.planner_models import (CandidateStatus, PlannerLimits, PlannerMode,
                                    PlannerStatus, PlannerTaskStatus, PlannerTaskType,
                                    Specialist)
from hackbot.planner_runner import PlannerRunner
from hackbot.planner_store import PlannerStore
from hackbot.plan_runs import PlanRunStore
from hackbot.policy import policy_version
from hackbot.policy_store import PolicyStore
from hackbot.postmessage_static import PostMessageStaticAnalyzer
from hackbot.postmessage_store import PostMessageStore
from hackbot.research import ResearchStore
from hackbot.reports import ReportProvenance, ReportReadiness, ReportStore
from hackbot.store import ArtifactStore
from hackbot.service import BugHunterRuntime
from hackbot.traffic import CapturePacket, CapturedRequest, CapturedResponse
from hackbot.target_policy import PolicyDecision
from hackbot.validator import DeterministicValidatorEngine
from hackbot.validation_store import ValidationStore
from tests.test_postmessage_static import TWO_STAGE


DOM_FLOW = b"""
function render() {
  const input = location.hash;
  if (!input.startsWith('javascript:')) {
    iframe.src = decodeURIComponent(input);
  }
}
"""


class PlannerMultisurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.test_authorization import AuthorizationSpecialistTests

        self.auth = AuthorizationSpecialistTests(
            methodName="test_cross_tenant_candidate_uses_verified_object_and_owner_traffic")
        self.auth.setUp()
        self.addCleanup(self.auth.doCleanups)
        self.fx = self.auth.fx
        self.package = self.fx.package
        self.target = self.package.target.id
        self.dom = DOMXSSStore(self.fx.store)
        self.messages = PostMessageStore(self.fx.store, self.dom)
        self.exposure_store = ExposureStore(self.fx.store)
        self.exposure = ExposureSpecialist(
            dom=self.dom, store=self.exposure_store, traffic=self.fx.traffic)
        self.api_registry = APIOperationRegistry(self.fx.store)
        self.behaviour = BehaviourStore(self.fx.store)
        self.api = APISpecialist(
            registry=self.api_registry, traffic=self.fx.traffic,
            evidence=self.fx.store, js=self.dom, behaviour=self.behaviour,
            authorization=self.auth.specialist)
        self.research = ResearchStore(self.fx.store)
        self.validations = ValidationStore(self.fx.store)
        self.planner_store = PlannerStore(self.fx.store)
        context = PlannerContextBuilder(
            hypotheses=self.auth.hypotheses, behaviour=self.behaviour,
            bootstrap=BootstrapStore(self.fx.store), identities=self.fx.registry,
            browser=self.fx.browser, objects=self.fx.objects,
            traffic=self.fx.traffic, research=self.research,
            validations=self.validations)
        self.planner = CrossSpecialistPlanner(
            store=self.planner_store, context=context,
            hypotheses=self.auth.hypotheses, authorization=self.auth.ledger,
            api=self.api_registry, dom=self.dom, messages=self.messages,
            exposure=self.exposure_store, traffic=self.fx.traffic,
            validations=self.validations, skill_context=self.auth.specialist.context,
            skill_router=self.auth.specialist.router)

    def _runner(self) -> PlannerRunner:
        child_runs = PlanRunStore(self.fx.store)
        orchestrator = PlanOrchestrator(
            runs=child_runs, targets=self.fx.targets, hypotheses=self.auth.hypotheses,
            context=self.auth.specialist.context,
            checker=self.auth.specialist.planner.checker,
            registry=self.auth.specialist.planner.registry, policy=self.fx.policy,
            approvals=PolicyStore(self.fx.store), executor=self.fx.executor,
            traffic=self.fx.traffic, evidence=self.fx.store, objects=self.fx.objects)
        validator = DeterministicValidatorEngine(
            runs=child_runs, traffic=self.fx.traffic, evidence=self.fx.store,
            identities=self.fx.registry, hypotheses=self.auth.hypotheses,
            results=self.validations)
        self.auth.specialist.orchestrator = orchestrator
        self.auth.specialist.validator = validator
        return PlannerRunner(
            planner=self.planner, store=self.planner_store,
            hypotheses=self.auth.hypotheses, contexts=self.auth.specialist.context,
            router=self.auth.specialist.router,
            skill_planner=self.auth.specialist.planner,
            authorization=self.auth.specialist, api=self.api, dom=None, messages=None,
            exposure=self.exposure, research=SimpleNamespace(), objects=self.fx.objects,
            object_factory=self.fx.factory, browser=self.fx.browser,
            orchestrator=orchestrator, validator=validator)

    def test_autonomous_portfolio_defers_api_leads_without_proof_prerequisites(self) -> None:
        limits = PlannerLimits(requests=30, browser_actions=0, candidates=2,
                               per_specialist=2, cleanup_reserve=2)
        run = self.planner_store.create(
            self.package, PlannerMode.BOUNDED_AUTONOMOUS, limits,
            policy_version(self.package))
        context = self.planner.context.build(self.package, limits)

        def signal(source_id: str, surface: str) -> _Signal:
            return _Signal("API_GRAPHQL", source_id, Specialist.API_GRAPHQL,
                           "OBJECT_AUTH", surface, "CROSS_TENANT", 90, 70, 1,
                           "CURRENT", "LOW", 5, 0, 0, (), (source_id,))

        owned = "TESTOBJ-" + "d" * 32
        context = replace(context, ready_object_ids=(owned,))
        sources = (replace(signal("ready", "/api/documents/{id}/preview"),
                           object_id=owned),
                   replace(signal("same-object", "/api/documents/{id}"),
                           object_id=owned, score=80),
                   signal("plan-only", "/api/documents/{id}/history"))
        with patch.object(self.api_registry, "get_candidate", side_effect=lambda _, key:
                          SimpleNamespace(status="PLAN_ONLY" if key == "plan-only" else "READY")):
            ranked = self.planner._rank(run, context, sources)
        statuses = {item.source_id: item for item in ranked}
        self.assertEqual(statuses["ready"].status, CandidateStatus.SELECTED)
        self.assertEqual(statuses["same-object"].status, CandidateStatus.DEFERRED)
        self.assertIn("OWNED_OBJECT_RESERVED_FOR_BRANCH",
                      statuses["same-object"].reason_codes)
        self.assertEqual(statuses["plan-only"].status, CandidateStatus.DEFERRED)
        self.assertIn("API_PROOF_PREREQUISITES_MISSING",
                      statuses["plan-only"].reason_codes)
        with patch.object(self.api_registry, "get_candidate",
                          return_value=SimpleNamespace(status="READY")):
            resumed = self.planner._rank(
                run, context, sources,
                suppressed_sources=frozenset({("API_GRAPHQL", "ready")}))
        resumed_statuses = {item.source_id: item for item in resumed}
        self.assertEqual(resumed_statuses["ready"].status, CandidateStatus.SKIPPED)
        self.assertIn("CAMPAIGN_SOURCE_ALREADY_ATTEMPTED",
                      resumed_statuses["ready"].reason_codes)
        not_ready = replace(context, ready_object_ids=())
        with patch.object(self.api_registry, "get_candidate",
                          return_value=SimpleNamespace(status="READY")):
            deferred = self.planner._rank(run, not_ready, sources)
        self.assertEqual(next(item for item in deferred if item.source_id == "ready").status,
                         CandidateStatus.DEFERRED)

    def _exchange(self, url: str, body: bytes, status: int, session_id: str | None,
                  *, content_type: str = "application/octet-stream") -> None:
        packet = CapturePacket(
            CapturedRequest("GET", url),
            CapturedResponse(status, (("Content-Type", content_type),), body),
            browser_session_id=session_id)
        return self.fx.traffic.store_exchange(
            self.package, packet, source=TrafficSource.FIXTURE,
            capture_provider="LOCAL_FIXTURE",
            browser_manager=self.fx.browser if session_id else None,
            anonymous=session_id is None)

    def _asset(self, name: str, body: bytes, recon_asset_id: int):
        return self.dom.record_artifact(
            target_id=self.target, asset_url=self.fx.base + "/assets/" + name,
            body=body, recon_asset_id=recon_asset_id,
            recon_sha256=hashlib.sha256(body).hexdigest(), source="FIXTURE")

    def test_real_specialist_stores_route_five_surfaces_and_reject_noise(self) -> None:
        owner, session, tenant, item = self.auth.fixture_object()
        self.auth.actor("tenant_b_admin", "tenant-b")
        self.auth.protect(item, tenant, policy="OWNER_ONLY")
        external_id = self.auth.specialist._external_id(item)
        self.fx.store.create_fact(
            hashlib.sha256(external_id.encode()).hexdigest(),
            "data_classification", "PROTECTED_FILE", confidence=1,
            evidence_ids=(item.verification_evidence_ids[0],),
            source="FIXTURE", target_ref=self.target)
        private_body = json.dumps({"id": external_id, "owner": "tenant_a_admin",
                                   "tenant": "tenant-a", "name": "fixture export"}).encode()
        shared = self.fx.base + f"/fixture/tenant-a/projects/{external_id}/download"
        standalone = self.fx.base + "/fixture/download/private-report.bin"
        secure = self.fx.base + f"/fixture/tenant-a/projects/{external_id}/secure"
        shared_owner = self._exchange(
            shared, private_body, 200, session.id, content_type="application/json")
        shared_anonymous = self._exchange(
            shared, private_body, 200, None, content_type="application/json")
        self._exchange(standalone, b"fixture-only private report", 200, session.id)
        self._exchange(standalone, b"fixture-only private report", 200, None)
        self._exchange(secure, private_body, 200, session.id)
        self._exchange(secure, b'{"error":"forbidden"}', 403, None,
                       content_type="application/json")
        self.auth.graphql_owner_exchange(owner, session, item)

        dom_asset = self._asset("dom.js", DOM_FLOW, 51)
        _, dom_analysis = self.dom.analyze_asset(
            self.target, dom_asset.artifact_id, DOMStaticAnalyzer())
        self.assertTrue(dom_analysis.candidates)
        message_asset = self._asset("bridge.js", TWO_STAGE, 52)
        _, message_analysis = self.messages.analyze_asset(
            self.target, message_asset.artifact_id, PostMessageStaticAnalyzer())
        self.assertTrue(any(item.port_bound for item in message_analysis.candidates))
        noise_asset = self._asset(
            "noise.js", b'const NEXT_PUBLIC_API_KEY="pk_live_PublicClientIdentifier987"; '
            b'const password="changeme";', 53)
        self.exposure.analyze_js(self.package, noise_asset.artifact_id,
                                 fixture_url=self.fx.base + "/assets/noise.js")

        exposure_result = self.exposure.discover_traffic(self.package)
        self.assertGreaterEqual(exposure_result.signals, 2)
        exposure_rows = self.exposure_store.list(self.target, limit=20).items
        self.assertTrue(any(item.category is ExposureCategory.UNAUTHENTICATED_DOWNLOAD
                            for item in exposure_rows))
        self.assertFalse(any("secure" in item.location for item in exposure_rows))
        self.assertTrue(any(item.status is ExposureStatus.REJECTED_PUBLIC
                            for item in exposure_rows))
        self.assertTrue(any(item.status is ExposureStatus.REJECTED_PLACEHOLDER
                            for item in exposure_rows))
        shared_exposure = next(item for item in exposure_rows
                               if item.endpoint_or_asset == shared_anonymous.id)

        surface = self.auth.specialist.profile(self.package)
        self.assertTrue(any(op.semantic_owner_success for op in surface.operations))
        hunt = self.auth.ledger.create_hunt(self.target, self.package.id,
                                            candidate_limit=20)
        auth_candidates = self.auth.specialist.generate(hunt, self.package)
        self.assertTrue(auth_candidates)
        shared_auth = next(candidate for candidate in auth_candidates
                           if candidate.boundary is Boundary.ANONYMOUS
                           and candidate.owner_exchange_id == shared_owner.id)
        self.api.profile(self.package)
        api_candidates = self.api.generate(self.package, mode="PLAN_ONLY")
        self.assertTrue(api_candidates)

        before = len(self.fx.server.received)
        run = self.planner.start(
            self.package, mode=PlannerMode.ANALYZE_ONLY,
            limits=PlannerLimits(requests=80, browser_actions=30,
                                 candidates=10, per_specialist=3, cleanup_reserve=5))
        self.assertEqual(len(self.fx.server.received), before)
        candidates = self.planner_store.candidates(self.target, run.id, limit=100)
        selected = [item for item in candidates if item.status is CandidateStatus.SELECTED]
        self.assertEqual({item.specialist for item in selected}, set(Specialist))
        auth_branch = next(item for item in candidates
                           if item.source_kind == "AUTHORIZATION"
                           and item.source_id == shared_auth.id)
        exposure_branch = next(item for item in candidates
                               if item.source_kind == "EXPOSURE"
                               and item.source_id == shared_exposure.candidate_id)
        self.assertEqual(auth_branch.root_cause_key, exposure_branch.root_cause_key)
        self.assertEqual(
            {auth_branch.status, exposure_branch.status} & {CandidateStatus.DUPLICATE},
            {CandidateStatus.DUPLICATE})
        self.assertFalse(any(item.source_id in {noise.candidate_id for noise in exposure_rows
                                                 if noise.status in {
                                                     ExposureStatus.REJECTED_PUBLIC,
                                                     ExposureStatus.REJECTED_PLACEHOLDER}}
                             for item in candidates))
        self.assertEqual(self.validations.list_findings(self.target, limit=20)["items"], [])

    def test_confirmed_child_finding_retains_full_planner_audit_chain(self) -> None:
        self.fx.package = replace(self.fx.package, autonomy=replace(
            self.fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        self.fx.targets.package = self.fx.package
        self.package = self.fx.package
        owner_a, _, tenant_a, object_a = self.auth.fixture_object()
        owner_b, session_b, _ = self.auth.actor("tenant_b_admin", "tenant-b")
        self.fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        object_b = self.fx.factory.resolve(
            package_id=self.package.id, recipe_id="project_b", identity_id=owner_b.id,
            tenant_id=self.auth.tenants["tenant-b"].id, session_id=session_b.id,
            purpose="Planner audit fixture").item
        self.assertIsNotNone(object_b)
        self.auth.protect(object_a, tenant_a, policy="TENANT_ONLY")
        self.auth.specialist.profile(self.package)
        hunt = self.auth.ledger.create_hunt(self.target, self.package.id, candidate_limit=6)
        source = next(item for item in self.auth.specialist.generate(hunt, self.package)
                      if item.boundary is Boundary.CROSS_TENANT
                      and item.test_object_id == object_a.id)

        limits = PlannerLimits(requests=20, browser_actions=0, candidates=2,
                               per_specialist=2, cleanup_reserve=2, seconds=1800)
        campaign_store = CampaignStore(self.fx.store)
        campaign = campaign_store.create(
            self.package, PlannerMode.BOUNDED_AUTONOMOUS,
            CampaignLimits(max_cycles=1, seconds=1800, requests=30,
                           browser_actions=0, research_requests=0),
            policy_version(self.package), "fixture")
        campaign = campaign_store.transition(
            self.target, campaign.id, CampaignStatus.RUNNING, "FIXTURE_READY",
            package=self.package, policy_hash=policy_version(self.package))
        campaign_store.begin_cycle(self.package, campaign.id, policy_version(self.package))
        campaign_work = campaign_store.reserve_work(
            self.target, campaign.id, CampaignWorkKind.PLANNER, requests=20)
        run = self.planner_store.create(
            self.package, PlannerMode.BOUNDED_AUTONOMOUS, limits,
            policy_version(self.package), campaign_work_id=campaign_work.id)
        self.planner_store.transition(self.target, run.id, PlannerStatus.LOADING_CONTEXT,
                                      "CONTEXT_STARTED")
        self.planner_store.transition(self.target, run.id, PlannerStatus.RANKING,
                                      "CONTEXT_READY")
        context = self.planner.context.build(self.package, limits)
        signal = next(item for item in self.planner._signals(self.package, limits.portfolio)
                      if item.source_kind == "AUTHORIZATION" and item.source_id == source.id)
        ranked = self.planner._rank(run, context, (signal,))
        self.assertEqual(ranked[0].status, CandidateStatus.SELECTED)
        sibling_hypothesis = self.auth.hypotheses.add_manual(
            self.target, "CROSS_TENANT", "Same-root review variant",
            "Check the same controlled project boundary")
        sibling = replace(ranked[0], id="PLCAND-" + "f" * 32,
                          source_kind="HYPOTHESIS", source_id=sibling_hypothesis.id,
                          hypothesis_id=sibling_hypothesis.id,
                          gaps=("MISSING_BROWSER_ROUTE",),
                          reason_codes=("SAME_ROOT_CAUSE_VARIANT",))
        run = self.planner_store.save_portfolio(run, (ranked[0], sibling), context.readiness,
                                                context.snapshot_hash, context)
        self.planner.build_tasks(run, ranked[0])
        self.planner.build_tasks(run, sibling)

        runner = self._runner()
        child_runs = runner.orchestrator.runs
        self.fx.server.fixture_secure = False
        start_errors: list[str] = []
        start_child = runner._start_child

        def traced_start(*args):
            try:
                return start_child(*args)
            except Exception as exc:
                start_errors.append(f"{type(exc).__name__}: {exc}")
                raise

        with patch.object(runner, "_start_child", side_effect=traced_start):
            campaign_runtime = SimpleNamespace(
                store=self.fx.store, planner_store=self.planner_store,
                planner_runner=runner, _planner_lock=Lock(),
                _planner_threads={}, _bootstrap_threads={},
                _behaviour_threads={}, _research_threads={},
                resources=SimpleNamespace(admit=lambda *_args, **_kwargs: None),
                record_planner_notification=lambda *_args: None)
            coordinator = CampaignCoordinator(campaign_runtime)
            for _ in range(50):
                campaign_state = coordinator.advance(self.package, campaign.id)
                if campaign_state.status is not CampaignStatus.RUNNING:
                    break
            final = self.planner_store.get(self.target, run.id)
        self.assertEqual(campaign_state.status, CampaignStatus.COMPLETED)
        self.assertEqual(final.status, PlannerStatus.COMPLETED,
                         (final.status, final.stop_reason, start_errors,
                          [(task.task_type.value, task.status.value, task.reason_code)
                           for task in self.planner_store.tasks(self.target, run.id)]))
        candidate = self.planner_store.candidate(self.target, run.id, ranked[0].id)
        self.assertIsNotNone(candidate.finding_id)
        suppressed = self.planner_store.candidate(self.target, run.id, sibling.id)
        self.assertEqual(suppressed.status, CandidateStatus.DUPLICATE)
        self.assertTrue(all(task.status is PlannerTaskStatus.SKIPPED for task in
                            self.planner_store.tasks(self.target, run.id)
                            if task.candidate_id == sibling.id))
        finding = self.validations.get_finding(candidate.finding_id, self.target)
        validation = self.validations.get(candidate.validation_id, self.target)
        child = child_runs.get(candidate.plan_run_id, self.target)
        plan = self.auth.specialist.planner.store.get(candidate.plan_id, self.target)
        self.assertEqual(finding.validation_id, validation.id)
        self.assertEqual(validation.run_id, child.id)
        self.assertEqual(validation.plan_id, plan["id"])
        self.assertEqual(plan["hypothesis_id"], candidate.hypothesis_id)
        links = coordinator.finding_links(self.target, campaign.id)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["finding_id"], finding.id)
        self.assertEqual(links[0]["validation_id"], validation.id)
        self.assertEqual(links[0]["plan_run_id"], child.id)
        self.assertEqual(links[0]["planner_run_id"], run.id)
        self.assertEqual(campaign_store.finding_counts((campaign.id,)), {campaign.id: 1})
        self.assertTrue(any(item["kind"] == "CONFIRMED" for item in
                            campaign_store.suppressions(self.target, campaign.id)))
        draft_store = ReportStore(self.fx.store, ArtifactStore(
            self.fx.root / "artifacts" / "campaign-reports"))
        draft = draft_store.save(
            target_id=self.target, finding_id=finding.id,
            validation_id=validation.id, snapshot_hash=hashlib.sha256(
                finding.id.encode()).hexdigest(),
            markdown="# Synthetic finding\n\nControlled fixture only.\n",
            readiness=ReportReadiness.READY,
            provenance=ReportProvenance.DETERMINISTIC)
        self.assertEqual(coordinator.finding_links(self.target, campaign.id)[0]["report_id"],
                         draft.id)
        outbox = NotificationStore(self.fx.store)
        notification_runtime = SimpleNamespace(
            planner_store=self.planner_store, validations=self.validations,
            notification_store=outbox, _notification_wakeup=Event(),
            logger=SimpleNamespace(error=lambda *_args: None))
        for _ in range(2):
            BugHunterRuntime.record_planner_notification(
                notification_runtime, self.target, run.id,
                {"run": final.to_dict(), "task": None})
        with self.fx.store._connection() as db:
            count = db.execute(
                "SELECT count(*) FROM notification_events WHERE target_id=? "
                "AND event_type='PLANNER_COMPLETED_WITH_FINDINGS' AND source_id=?",
                (self.target, run.id)).fetchone()[0]
        self.assertEqual(count, 1)
        self.assertTrue(finding.evidence_ids)
        self.assertTrue(any(task.task_type is PlannerTaskType.VALIDATE_RUN
                            and task.result_ref == validation.id for task in
                            self.planner_store.tasks(self.target, run.id)))
        with sqlite3.connect(self.fx.store.db_path) as db:
            audited = db.execute(
                "SELECT count(*) FROM plan_run_steps s JOIN policy_decisions d "
                "ON d.decision_id=s.decision_id JOIN executor_permits p "
                "ON p.permit_id=s.permit_id WHERE s.run_id=? AND d.result='ALLOW'",
                (child.id,)).fetchone()[0]
        self.assertGreater(audited, 0)
        context_events = [event for event in self.planner_store.events(self.target, run.id)
                          if event["event_type"] == "CONTEXT_REFERENCED"]
        self.assertTrue(any(event["reason_code"] == "TRAFFIC" and
                            set(event["safe_refs"]) & set(context.recent_exchange_ids)
                            for event in context_events))
        self.assertTrue(any(event["reason_code"] == "FACT" and
                            set(event["safe_refs"]) & set(context.recent_fact_ids)
                            for event in context_events))

    def test_missing_foreign_control_is_created_before_authorization_plan(self) -> None:
        self.fx.package = replace(self.fx.package, autonomy=replace(
            self.fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        self.fx.targets.package = self.fx.package
        self.package = self.fx.package
        _, _, tenant_a, object_a = self.auth.fixture_object()
        self.auth.actor("tenant_b_admin", "tenant-b")
        self.fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        self.auth.protect(object_a, tenant_a, policy="TENANT_ONLY")
        self.auth.specialist.factory = self.fx.factory
        self.auth.specialist.profile(self.package)
        hunt = self.auth.ledger.create_hunt(
            self.target, self.package.id, candidate_limit=6,
            mode=AuthorizationMode.BOUNDED_AUTONOMOUS)
        source = next(item for item in self.auth.specialist.generate(hunt, self.package)
                      if item.boundary is Boundary.CROSS_TENANT
                      and item.test_object_id == object_a.id)
        self.assertFalse(self.auth.specialist.comparison_control_ready(source.id,
                                                                        self.package))
        run = self.planner.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=PlannerLimits(requests=20, browser_actions=0, candidates=1,
                                 per_specialist=1, cleanup_reserve=2, seconds=1800))
        candidate = next(item for item in self.planner_store.candidates(
            self.target, run.id, limit=20) if item.source_id == source.id)
        self.assertEqual(candidate.status, CandidateStatus.SELECTED)
        self.assertIn("MISSING_OBJECT", candidate.gaps)
        runner = self._runner()
        self.assertEqual(runner.advance(self.package, run.id)["reason"],
                         "COMPARISON_OBJECT_CREATED")
        self.assertTrue(self.auth.specialist.comparison_control_ready(source.id,
                                                                       self.package))
        self.assertEqual(runner.advance(self.package, run.id)["reason"],
                         "COMPARISON_CONTROL_READY")
        self.assertEqual(runner.advance(self.package, run.id)["reason"],
                         "PLAN_CREATED")
        tasks = self.planner_store.tasks(self.target, run.id)
        self.assertEqual([item.status for item in tasks[:3]],
                         [PlannerTaskStatus.COMPLETED] * 3)
        self.assertEqual(len(self.auth.ledger.created_objects(hunt.id, self.target)), 1)
