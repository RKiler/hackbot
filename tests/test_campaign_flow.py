from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hackbot.campaign_models import CampaignLimits, CampaignStatus, CampaignWorkKind
from hackbot.bootstrap_store import BootstrapStatus
from hackbot.behaviour import LearningStatus
from hackbot.config import TargetSettings, load_config
from hackbot.hypotheses import Hypothesis, HypothesisSource, HypothesisStatus
from hackbot.planner_models import (CandidateStatus, PlannerCandidate, PlannerLimits,
                                   PlannerMode, PlannerStatus, PlannerTaskType, Specialist)
from hackbot.recon_postgres import ReconQueryError
from hackbot.research import ResearchStatus
from hackbot.resources import ResourceError
from hackbot.service import BugHunterRuntime, create_app
from hackbot.test_objects import ObjectState


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class CampaignFlowTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        shutil.copytree(EXAMPLE, root / "targets/example")
        base = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                    "XDG_STATE_HOME": str(root)})
        self.runtime = BugHunterRuntime(replace(base, targets=TargetSettings(root / "targets")),
                                        driver=SimpleNamespace(name="FAKE"),
                                        vnc_ready=lambda: False)
        self.package = self.runtime.package("example")
        self.admission = patch.object(self.runtime.resources, "admit", return_value=None)
        self.admission.start()
        self.addCleanup(self.admission.stop)

    def test_analyze_only_completes_without_target_execution(self):
        with patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target request")):
            campaign = self.runtime.campaign.start(
                self.package, mode=PlannerMode.ANALYZE_ONLY,
                limits=CampaignLimits(), requested_by="tester")
            for _ in range(8):
                campaign = self.runtime.campaign.advance(self.package, campaign.id)
                if campaign.status in {CampaignStatus.COMPLETED, CampaignStatus.BLOCKED}:
                    break
        self.assertEqual(campaign.status, CampaignStatus.COMPLETED)
        self.assertEqual(campaign.current_cycle, 1)
        self.assertEqual(len(self.runtime.campaign.store.works(campaign.target_id,
                                                               campaign.id)), 1)
        self.assertEqual(campaign.usage.requests, 0)

    def test_pause_resume_cancel_and_target_lock(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.PLAN_ONLY,
            limits=CampaignLimits(), requested_by="tester")
        with self.assertRaises(ValueError):
            self.runtime.campaign.start(self.package, mode=PlannerMode.ANALYZE_ONLY,
                                        limits=CampaignLimits(), requested_by="tester")
        paused = self.runtime.campaign.pause(self.package, campaign.id)
        self.assertEqual(paused.status, CampaignStatus.PAUSED)
        resumed = self.runtime.campaign.resume(self.package, campaign.id)
        self.assertEqual(resumed.status, CampaignStatus.ASSESSING_READINESS)
        cancelled = self.runtime.campaign.cancel(self.package, campaign.id)
        self.assertEqual(cancelled.status, CampaignStatus.CANCELLED)
        self.assertEqual(self.runtime.campaign.advance(self.package, campaign.id).status,
                         CampaignStatus.CANCELLED)

    def test_prestart_pause_does_not_spend_execution_time_budget(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.PLAN_ONLY,
            limits=CampaignLimits(seconds=30), requested_by="tester")
        self.runtime.campaign.pause(self.package, campaign.id)
        old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with self.runtime.store._connection() as db:
            db.execute("UPDATE campaigns SET created_at=? WHERE campaign_id=?",
                       (old, campaign.id))
        resumed = self.runtime.campaign.resume(self.package, campaign.id)
        self.assertEqual(resumed.status, CampaignStatus.ASSESSING_READINESS)
        self.assertEqual(self.runtime.campaign._remaining(resumed)["seconds"], 30)
        first_cycle = self.runtime.campaign.advance(self.package, campaign.id)
        self.assertEqual(first_cycle.status, CampaignStatus.RUNNING)
        self.assertIsNotNone(first_cycle.started_at)

    def test_paused_campaign_blocks_old_planner_route_and_restart_replays_nothing(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.PLAN_ONLY,
            limits=CampaignLimits(), requested_by="tester")
        for _ in range(3):
            campaign = self.runtime.campaign.advance(self.package, campaign.id)
        works = self.runtime.campaign.store.works(campaign.target_id, campaign.id)
        self.assertEqual(len(works), 1)
        planner_id = works[0].child_id
        self.assertIsNotNone(planner_id)
        self.assertEqual(self.runtime.campaign.store.reconcile_interrupted(), 1)
        self.assertEqual(self.runtime.campaign.store.reconcile_interrupted(), 0)
        blocked = self.runtime.planner_runner.advance(self.package, planner_id)
        self.assertEqual(blocked["reason"], "CAMPAIGN_NOT_RUNNING")
        self.assertEqual(len(self.runtime.campaign.store.works(campaign.target_id,
                                                               campaign.id)), 1)

    def test_restart_resume_settles_existing_analysis_child_once(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.ANALYZE_ONLY,
            limits=CampaignLimits(), requested_by="tester")
        for _ in range(3):
            campaign = self.runtime.campaign.advance(self.package, campaign.id)
        work = self.runtime.campaign.store.works(campaign.target_id, campaign.id)[0]
        self.assertEqual(self.runtime.campaign.store.reconcile_interrupted(), 1)
        resumed = self.runtime.campaign.resume(self.package, campaign.id)
        self.assertEqual(resumed.status, CampaignStatus.RUNNING)
        completed = self.runtime.campaign.advance(self.package, campaign.id)
        self.assertEqual(completed.status, CampaignStatus.COMPLETED)
        works = self.runtime.campaign.store.works(campaign.target_id, campaign.id)
        self.assertEqual(len(works), 1)
        self.assertEqual(works[0].id, work.id)
        self.assertEqual(works[0].status.value, "COMPLETED")

    def test_expired_campaign_stops_before_planner(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.ANALYZE_ONLY,
            limits=CampaignLimits(seconds=30), requested_by="tester")
        for _ in range(2):
            self.runtime.campaign.advance(self.package, campaign.id)
        expired_at = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        with self.runtime.store._connection() as db:
            db.execute("UPDATE campaigns SET started_at=? WHERE campaign_id=?",
                       (expired_at, campaign.id))
        result = self.runtime.campaign.advance(self.package, campaign.id)
        self.assertEqual(result.status, CampaignStatus.TIME_EXHAUSTED)
        self.assertEqual(self.runtime.campaign.store.works(campaign.target_id,
                                                           campaign.id), ())

    def test_zero_request_budget_blocks_autonomous_target_work(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(requests=0, cleanup_reserve=0, setup_objects=0),
            requested_by="tester")
        with patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target request")):
            for _ in range(3):
                result = self.runtime.campaign.advance(self.package, campaign.id)
        self.assertEqual(result.status, CampaignStatus.BUDGET_EXHAUSTED)
        self.assertEqual(result.usage.requests, 0)

    def test_private_api_rejects_bad_limits_and_exposes_ledger(self):
        client = create_app(runtime=self.runtime).test_client()
        response = client.post("/v1/campaigns", json={"target": "example",
                                                      "mode": "ANALYZE_ONLY",
                                                      "preset": "CUSTOM", "limits": {}})
        self.assertEqual(response.status_code, 400)
        with patch.object(self.runtime, "launch_campaign"):
            response = client.post("/v1/campaigns", json={"target": "example",
                                                          "mode": "ANALYZE_ONLY",
                                                          "preset": "SMALL"})
        self.assertEqual(response.status_code, 201)
        campaign_id = response.json["id"]
        listed = client.get("/v1/campaigns?target=example").json["items"][0]
        self.assertEqual(listed["id"], campaign_id)
        self.assertEqual(listed["finding_count"], 0)
        detail = client.get(f"/v1/campaigns/{campaign_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json["coverage_summary"]["identities"], 0)
        self.assertEqual(detail.json["progress"]["completed_tasks"], 0)
        self.assertEqual(client.post(f"/v1/campaigns/{campaign_id}/pause", json={}).json["status"],
                         "PAUSED")

    def test_resource_pressure_pauses_before_new_work(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(), requested_by="tester")
        self.runtime.campaign.advance(self.package, campaign.id)
        with patch.object(self.runtime.resources, "admit",
                          side_effect=ResourceError("CRITICAL_DISK")):
            paused = self.runtime.campaign.advance(self.package, campaign.id)
            self.assertEqual(paused.status, CampaignStatus.PAUSED)
            self.assertEqual(paused.readiness_code, "CRITICAL_DISK")
            with self.assertRaises(ResourceError):
                self.runtime.campaign.resume(self.package, campaign.id)
        self.assertEqual(self.runtime.campaign.store.works(campaign.target_id,
                                                           campaign.id), ())

    def test_cold_start_bootstrap_is_linked_before_planner(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(), requested_by="tester")
        self.runtime.campaign.advance(self.package, campaign.id)
        self.runtime.campaign.advance(self.package, campaign.id)

        def finish_bootstrap(run_id, package_id):
            self.assertEqual(package_id, self.package.id)
            return self.runtime.bootstrap_store.transition(
                run_id, campaign.target_id, BootstrapStatus.COMPLETED)

        with patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target request")):
            with patch.object(self.runtime.bootstrap, "run", side_effect=finish_bootstrap):
                self.runtime.campaign.advance(self.package, campaign.id)
        works = self.runtime.campaign.store.works(campaign.target_id, campaign.id)
        self.assertEqual(len(works), 1)
        self.assertEqual(works[0].kind.value, "BOOTSTRAP")
        self.assertEqual(works[0].status.value, "COMPLETED")
        self.assertTrue(works[0].child_id.startswith("BOOT-"))
        current = self.runtime.campaign.store.get(campaign.target_id, campaign.id)
        self.assertGreater(current.usage.requests, 0)
        self.assertLessEqual(current.usage.requests, campaign.limits.requests)

    def test_recon_outage_keeps_local_analysis_available(self):
        def unavailable(_domain):
            raise ReconQueryError("fixture recon unavailable")

        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.ANALYZE_ONLY,
            limits=CampaignLimits(), requested_by="tester")
        with patch.object(self.runtime.planner_context, "recon",
                          SimpleNamespace(resolve_target=unavailable)), \
                patch.object(self.runtime.executor, "execute",
                             side_effect=AssertionError("target request")):
            for _ in range(8):
                campaign = self.runtime.campaign.advance(self.package, campaign.id)
                if campaign.status in {CampaignStatus.COMPLETED, CampaignStatus.BLOCKED}:
                    break
        self.assertEqual(campaign.status, CampaignStatus.COMPLETED)
        works = self.runtime.campaign.store.works(campaign.target_id, campaign.id)
        self.assertEqual([work.kind for work in works], [CampaignWorkKind.PLANNER])
        self.assertEqual(campaign.usage.requests, 0)

    def test_package_version_change_pauses_before_child_work(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.PLAN_ONLY,
            limits=CampaignLimits(), requested_by="tester")
        changed = replace(self.package, rules=replace(
            self.package.rules, automated_testing_allowed=False))
        result = self.runtime.campaign.advance(changed, campaign.id)
        self.assertEqual(result.status, CampaignStatus.PAUSED)
        self.assertEqual(result.readiness_code, "PACKAGE_POLICY_CHANGED")
        self.assertEqual(result.current_cycle, 0)

    def test_behaviour_gap_uses_linked_local_learning_run(self):
        original = self.runtime.planner_context.build(self.package, PlannerLimits())
        context = replace(original, recent_exchange_ids=("EXCHANGE-fixture",))
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(), requested_by="tester")

        def finish_learning(package, run_id, **_kwargs):
            ledger = self.runtime.behaviour_store
            ledger.transition(package.target.id, run_id, LearningStatus.READY)
            ledger.transition(package.target.id, run_id, LearningStatus.RUNNING)
            return ledger.transition(package.target.id, run_id, LearningStatus.COMPLETED)

        with patch.object(self.runtime.planner_context, "build", return_value=context):
            with patch.object(self.runtime.behaviour, "run", side_effect=finish_learning):
                with patch.object(self.runtime.executor, "execute",
                                  side_effect=AssertionError("target request")):
                    for _ in range(3):
                        self.runtime.campaign.advance(self.package, campaign.id)
        works = self.runtime.campaign.store.works(campaign.target_id, campaign.id)
        self.assertEqual(len(works), 1)
        self.assertEqual(works[0].kind.value, "BEHAVIOUR")
        self.assertEqual(works[0].status.value, "COMPLETED")
        self.assertTrue(works[0].child_id.startswith("LEARN-"))

    def test_learning_login_wait_resumes_without_replaying_child(self):
        context = replace(self.runtime.planner_context.build(self.package, PlannerLimits()),
                          recent_exchange_ids=("EXCHANGE-fixture",))
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(), requested_by="tester")

        def wait_for_login(package, run_id, **_kwargs):
            ledger = self.runtime.behaviour_store
            ledger.transition(package.target.id, run_id, LearningStatus.READY)
            ledger.transition(package.target.id, run_id, LearningStatus.RUNNING)
            return ledger.transition(package.target.id, run_id,
                                     LearningStatus.WAITING_LOGIN)

        with patch.object(self.runtime.planner_context, "build", return_value=context), \
                patch.object(self.runtime.behaviour, "run", side_effect=wait_for_login), \
                patch.object(self.runtime.executor, "execute",
                             side_effect=AssertionError("target request")):
            for _ in range(3):
                campaign = self.runtime.campaign.advance(self.package, campaign.id)
            self.assertEqual(campaign.status, CampaignStatus.WAITING_LOGIN)
            work = self.runtime.campaign.store.works(campaign.target_id, campaign.id)[0]
            with patch.object(self.runtime.campaign, "_has_active_session",
                              return_value=False):
                self.assertEqual(self.runtime.campaign.resume(
                    self.package, campaign.id).status, CampaignStatus.WAITING_LOGIN)
            with patch.object(self.runtime.campaign, "_has_active_session",
                              return_value=True):
                self.assertEqual(self.runtime.campaign.resume(
                    self.package, campaign.id).status, CampaignStatus.RUNNING)
                self.runtime.campaign.advance(self.package, campaign.id)
            settled = self.runtime.campaign.store.work(campaign.target_id, campaign.id,
                                                       work.id)
            self.assertEqual(settled.status.value, "COMPLETED")
            self.assertEqual(settled.child_id, work.child_id)

    def test_research_gap_is_bounded_linked_and_not_repeated(self):
        now = datetime.now(timezone.utc)
        hypothesis = Hypothesis(
            "HYP-" + "a" * 32, self.package.target.id, "unknown-protocol-fixture",
            "UNKNOWN_PROTOCOL", "Unknown protocol boundary needs documentation",
            HypothesisStatus.NEEDS_RESEARCH, 90, 0.5, "UNSPECIFIED", "LOW",
            "fixture-surface", "protocol", "fixture gap", (), (),
            "Review protocol details", "documented handling", "no relevant source",
            (), HypothesisSource.MANUAL, "fixture", (), (), now, now)
        self.runtime.hypotheses.upsert(hypothesis)
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(), requested_by="tester")
        self.runtime.campaign.advance(self.package, campaign.id)
        campaign = self.runtime.campaign.advance(self.package, campaign.id)

        def finish_research(gap, request_id):
            self.assertEqual(gap.hypothesis_id, hypothesis.id)
            self.runtime.research_store.transition(request_id, ResearchStatus.COMPLETED)
            return {"request_id": request_id, "status": "COMPLETED", "brief_id": None}

        with patch.object(self.runtime.research, "run", side_effect=finish_research):
            self.assertTrue(self.runtime.campaign._research(
                campaign, self.runtime.campaign._remaining(campaign)))
        works = self.runtime.campaign.store.works(campaign.target_id, campaign.id)
        self.assertEqual(len(works), 1)
        self.assertEqual(works[0].kind.value, "RESEARCH")
        self.assertEqual(works[0].status.value, "COMPLETED")
        request = self.runtime.research_store.request(campaign.target_id, works[0].child_id)
        self.assertEqual(request["external_allowed"], 0)
        self.assertFalse(self.runtime.campaign._research(
            campaign, self.runtime.campaign._remaining(campaign)))

    def test_analyze_only_ranks_current_hypothesis_without_execution(self):
        now = datetime.now(timezone.utc)
        hypothesis = Hypothesis(
            "HYP-" + "b" * 32, self.package.target.id, "owned-object-fixture",
            "BOLA", "Owned object authorization boundary",
            HypothesisStatus.NEW, 90, 0.9, "DATA_EXPOSURE", "LOW",
            "fixture-object", "CROSS_TENANT", "owned fixture CANARY_PRIVATE_VALUE_31", (), (),
            "Compare owned actors", "isolation", "no differential", (),
            HypothesisSource.MANUAL, "fixture", (), (), now, now)
        self.runtime.hypotheses.upsert(hypothesis)
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.ANALYZE_ONLY,
            limits=CampaignLimits(), requested_by="tester")
        with patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target request")):
            for _ in range(5):
                campaign = self.runtime.campaign.advance(self.package, campaign.id)
        self.assertEqual(campaign.status, CampaignStatus.COMPLETED)
        work = self.runtime.campaign.store.works(campaign.target_id, campaign.id)[0]
        candidates = self.runtime.planner_store.candidates(campaign.target_id,
                                                           work.child_id, limit=20)
        self.assertTrue(any(item.source_id == hypothesis.id for item in candidates))
        self.assertEqual(campaign.usage.requests, 0)
        detail = self.runtime.campaign.detail(self.package, campaign.id)
        self.assertNotIn("CANARY_PRIVATE_VALUE_31", json.dumps(detail))
        self.assertGreaterEqual(sum(detail["coverage_summary"]["candidate_classes"].values()), 1)
        self.assertEqual(detail["metrics"]["notification_events"], 0)
        self.assertEqual(detail["metrics"]["objects_created"], 0)
        self.assertEqual(detail["active_tasks"], [])

    def test_plan_only_builds_local_plan_without_target_execution(self):
        now = datetime.now(timezone.utc)
        hypothesis = Hypothesis(
            "HYP-" + "c" * 32, self.package.target.id, "plan-only-fixture",
            "DOM_XSS", "Current browser input boundary", HypothesisStatus.NEW,
            95, 0.95, "CLIENT_CODE_EXECUTION", "LOW", "fixture-page",
            "CLIENT_SERVER_TRUST", "local fixture only", (), (),
            "Trace browser input", "no execution", "unreachable source", (),
            HypothesisSource.MANUAL, "fixture", (), (), now, now)
        self.runtime.hypotheses.upsert(hypothesis)
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.PLAN_ONLY,
            limits=CampaignLimits(), requested_by="tester")
        with patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target request")):
            for _ in range(25):
                campaign = self.runtime.campaign.advance(self.package, campaign.id)
                if campaign.status not in {CampaignStatus.RUNNING,
                                           CampaignStatus.ASSESSING_READINESS}:
                    break
        detail = self.runtime.campaign.detail(self.package, campaign.id)
        self.assertEqual(campaign.usage.requests, 0)
        self.assertEqual(detail["metrics"]["plans_executed"], 0)
        self.assertGreaterEqual(detail["metrics"]["plans_created"], 1,
                                msg=str((campaign.status, detail["work"])))

    def test_rejected_root_is_skipped_until_target_state_changes(self):
        self.runtime.registry.register_target(self.package)
        now = datetime.now(timezone.utc)
        hypothesis = Hypothesis(
            "HYP-" + "d" * 32, self.package.target.id, "rejected-dom-fixture",
            "DOM_XSS", "Current browser input boundary", HypothesisStatus.NEW,
            95, 0.95, "CLIENT_CODE_EXECUTION", "LOW", "fixture-page",
            "CLIENT_SERVER_TRUST", "local fixture only", (), (),
            "Trace browser input", "no execution", "unreachable source", (),
            HypothesisSource.MANUAL, "fixture", (), (), now, now)
        self.runtime.hypotheses.upsert(hypothesis)
        baseline = self.runtime.planner.start(
            self.package, mode=PlannerMode.ANALYZE_ONLY,
            limits=PlannerLimits(requests=16, browser_actions=8,
                                 tokens=2000, cleanup_reserve=0))
        first = next(item for item in self.runtime.planner_store.candidates(
            self.package.target.id, baseline.id) if item.source_id == hypothesis.id)
        self.assertIsNotNone(first.state_hash)
        for kind in ("REJECTED", "CONFIRMED"):
            campaign = self.runtime.campaign.start(
                self.package, mode=PlannerMode.PLAN_ONLY,
                limits=CampaignLimits(), requested_by="tester")
            self.runtime.campaign.store.suppress(campaign.target_id, campaign.id,
                                                 first.root_cause_key,
                                                 first.state_hash, kind)
            for _ in range(5):
                campaign = self.runtime.campaign.advance(self.package, campaign.id)
            self.assertEqual(campaign.status, CampaignStatus.COMPLETED)
            work = self.runtime.campaign.store.works(campaign.target_id,
                                                     campaign.id)[0]
            candidate = next(item for item in self.runtime.planner_store.candidates(
                campaign.target_id, work.child_id) if item.source_id == hypothesis.id)
            self.assertEqual(candidate.status, CandidateStatus.SKIPPED)
            self.assertIn("CAMPAIGN_SUPPRESSED", candidate.reason_codes)

    def test_cleanup_missing_session_is_visible_and_never_executes(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(), requested_by="tester")
        self.runtime.campaign.advance(self.package, campaign.id)
        campaign = self.runtime.campaign.advance(self.package, campaign.id)
        object_id = "TESTOBJ-" + "d" * 32
        row = {"object_id": object_id, "cleanup_status": "PENDING"}
        item = SimpleNamespace(state=ObjectState.READY,
                               creator_identity_id="IDENTITY-" + "a" * 32)
        with patch.object(self.runtime.campaign.store, "reconcile_objects", return_value=0), \
                patch.object(self.runtime.campaign.store, "objects", return_value=(row,)), \
                patch.object(self.runtime.campaign.store, "refresh_object_cleanup",
                             return_value="PENDING"), \
                patch.object(self.runtime.objects, "get", return_value=item), \
                patch.object(self.runtime.browser, "get_active_session",
                             return_value=None), \
                patch.object(self.runtime.object_factory, "cleanup",
                             side_effect=AssertionError("cleanup without session")):
            result = self.runtime.campaign._cleanup(
                self.package, campaign, CampaignStatus.COMPLETED, "NO_READY_WORK")
        self.assertEqual(result.status, CampaignStatus.CLEANUP_REQUIRED)
        self.assertEqual(result.stop_reason, "CLEANUP_LOGIN_REQUIRED")

    def test_cancel_reconciles_child_created_object_before_completion(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(), requested_by="tester")
        object_id = "TESTOBJ-" + "c" * 32
        row = {"object_id": object_id, "cleanup_status": "PENDING"}
        item = SimpleNamespace(state=ObjectState.READY,
                               creator_identity_id="IDENTITY-" + "a" * 32)
        with patch.object(self.runtime.campaign.store, "reconcile_objects",
                          return_value=1) as reconcile, \
                patch.object(self.runtime.campaign.store, "objects",
                             return_value=(row,)), \
                patch.object(self.runtime.campaign.store, "refresh_object_cleanup",
                             return_value="PENDING"), \
                patch.object(self.runtime.objects, "get", return_value=item), \
                patch.object(self.runtime.browser, "get_active_session",
                             return_value=None), \
                patch.object(self.runtime.object_factory, "cleanup",
                             side_effect=AssertionError("cleanup without session")):
            result = self.runtime.campaign.cancel(self.package, campaign.id)
        self.assertEqual(reconcile.call_count, 2)
        self.assertEqual(result.status, CampaignStatus.CLEANUP_REQUIRED)
        self.assertEqual(result.stop_reason, "CLEANUP_LOGIN_REQUIRED")

    def test_cleanup_success_requires_verified_absence(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(), requested_by="tester")
        self.runtime.campaign.advance(self.package, campaign.id)
        campaign = self.runtime.campaign.advance(self.package, campaign.id)
        object_id = "TESTOBJ-" + "e" * 32
        row = {"object_id": object_id, "cleanup_status": "PENDING"}
        item = SimpleNamespace(state=ObjectState.READY,
                               creator_identity_id="IDENTITY-" + "a" * 32)
        with patch.object(self.runtime.campaign.store, "reconcile_objects", return_value=0), \
                patch.object(self.runtime.campaign.store, "objects", return_value=(row,)), \
                patch.object(self.runtime.campaign.store, "refresh_object_cleanup",
                             side_effect=("PENDING", "CLEANED")), \
                patch.object(self.runtime.objects, "get", return_value=item), \
                patch.object(self.runtime.browser, "get_active_session",
                             return_value=SimpleNamespace(id="SESSION-fixture")), \
                patch.object(self.runtime.campaign.store, "link_child"), \
                patch.object(self.runtime.campaign.store, "finish_work"), \
                patch.object(self.runtime.object_factory, "cleanup",
                             return_value=SimpleNamespace(outcome="CLEANED")) as cleanup:
            result = self.runtime.campaign._cleanup(
                self.package, campaign, CampaignStatus.COMPLETED, "NO_READY_WORK")
        self.assertEqual(result.status, CampaignStatus.COMPLETED)
        self.assertEqual(result.usage.cleanup_requests, 3)
        cleanup.assert_called_once_with(object_id, campaign.target_id,
                                        session_id="SESSION-fixture")

    def test_campaign_honors_ready_branch_before_human_wait(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(max_cycles=1), requested_by="tester")
        self.runtime.campaign.advance(self.package, campaign.id)
        self.runtime.campaign.advance(self.package, campaign.id)
        work = self.runtime.campaign.store.reserve_work(
            campaign.target_id, campaign.id, CampaignWorkKind.PLANNER,
            requests=5, tokens=200)
        run = self.runtime.planner_store.create(
            self.package, PlannerMode.BOUNDED_AUTONOMOUS,
            PlannerLimits(requests=5, tokens=200, cleanup_reserve=0),
            self.runtime.campaign.store.get(campaign.target_id, campaign.id).policy_hash,
            campaign_work_id=work.id)
        self.runtime.planner_store.transition(run.target_id, run.id,
                                              PlannerStatus.LOADING_CONTEXT,
                                              "CONTEXT_STARTED")
        digest = hashlib.sha256(b"campaign-wait-fixture").hexdigest()
        first = PlannerCandidate(
            "PLCAND-" + "1" * 32, run.id, run.target_id,
            "HYPOTHESIS", "HYP-" + "1" * 32, None, Specialist.AUTHORIZATION,
            "CROSS_TENANT", digest, digest, 90, 80, 100, 5, 0, 0,
            "LOW", 80, "CURRENT", status=CandidateStatus.SELECTED)
        second = replace(first, id="PLCAND-" + "2" * 32,
                         source_id="HYP-" + "2" * 32,
                         root_cause_key=hashlib.sha256(b"independent").hexdigest())
        self.runtime.planner_store.transition(run.target_id, run.id,
                                              PlannerStatus.RANKING, "CONTEXT_READY")
        run = self.runtime.planner_store.save_portfolio(run, (first, second), {}, digest)
        waiting = self.runtime.planner_store.add_task(run, first,
                                                      PlannerTaskType.MANUAL_REVIEW,
                                                      priority=100)
        independent = self.runtime.planner_store.add_task(run, second,
                                                          PlannerTaskType.MANUAL_REVIEW,
                                                          priority=80)
        self.runtime.campaign.advance(self.package, campaign.id)
        tasks = self.runtime.planner_store.tasks(run.target_id, run.id)
        self.assertEqual(next(item for item in tasks if item.id == waiting.id).status.value,
                         "WAITING")
        self.assertEqual(self.runtime.campaign.store.get(campaign.target_id,
                                                         campaign.id).status,
                         CampaignStatus.RUNNING)
        self.runtime.campaign.advance(self.package, campaign.id)
        tasks = self.runtime.planner_store.tasks(run.target_id, run.id)
        self.assertEqual(next(item for item in tasks if item.id == independent.id).status.value,
                         "WAITING")
        self.assertEqual(self.runtime.campaign.store.get(campaign.target_id,
                                                         campaign.id).status,
                         CampaignStatus.WAITING_HUMAN)

    def test_campaign_runs_independent_task_before_approval_wait(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(max_cycles=1), requested_by="tester")
        self.runtime.campaign.advance(self.package, campaign.id)
        self.runtime.campaign.advance(self.package, campaign.id)
        work = self.runtime.campaign.store.reserve_work(
            campaign.target_id, campaign.id, CampaignWorkKind.PLANNER,
            requests=5, tokens=200)
        run = self.runtime.planner_store.create(
            self.package, PlannerMode.BOUNDED_AUTONOMOUS,
            PlannerLimits(requests=5, tokens=200, cleanup_reserve=0),
            campaign.policy_hash, campaign_work_id=work.id)
        self.runtime.planner_store.transition(run.target_id, run.id,
                                              PlannerStatus.LOADING_CONTEXT,
                                              "CONTEXT_STARTED")
        digest = hashlib.sha256(b"campaign-approval-fixture").hexdigest()
        first = PlannerCandidate(
            "PLCAND-" + "3" * 32, run.id, run.target_id,
            "HYPOTHESIS", "HYP-" + "3" * 32, None, Specialist.AUTHORIZATION,
            "CROSS_TENANT", digest, digest, 90, 80, 100, 5, 0, 0,
            "LOW", 80, "CURRENT", status=CandidateStatus.SELECTED)
        second = replace(first, id="PLCAND-" + "4" * 32,
                         source_id="HYP-" + "4" * 32,
                         root_cause_key=hashlib.sha256(b"independent").hexdigest())
        self.runtime.planner_store.transition(run.target_id, run.id,
                                              PlannerStatus.RANKING, "CONTEXT_READY")
        run = self.runtime.planner_store.save_portfolio(run, (first, second), {}, digest)
        waiting = self.runtime.planner_store.add_task(run, first, PlannerTaskType.RUN_PLAN)
        independent = self.runtime.planner_store.add_task(
            run, second, PlannerTaskType.MANUAL_REVIEW)
        plan_id, child_id = "PLAN-" + "5" * 32, "RUN-" + "6" * 32
        linked = replace(first, plan_id=plan_id, plan_run_id=child_id)
        original_candidate = self.runtime.planner_runner.store.candidate
        child = SimpleNamespace(id=child_id, package_id=self.package.id, plan_id=plan_id,
                                status=SimpleNamespace(value="WAITING_APPROVAL"))
        with patch.object(self.runtime.planner_runner, "_fresh", return_value=True), \
                patch.object(self.runtime.planner_runner.store, "candidate",
                             side_effect=lambda target, run_id, item_id:
                             linked if item_id == first.id else
                             original_candidate(target, run_id, item_id)), \
                patch.object(self.runtime.skill_planner.store, "get",
                             return_value={"status": "REQUIRE_APPROVAL",
                                           "hypothesis_id": None, "request_budget": 5}), \
                patch.object(self.runtime.orchestrator.runs, "get", return_value=child):
            first_step = self.runtime.campaign.advance(self.package, campaign.id)
            first_task = self.runtime.planner_store.task(run.target_id, run.id, waiting.id)
            second_step = self.runtime.campaign.advance(self.package, campaign.id)
        second_task = self.runtime.planner_store.task(run.target_id, run.id,
                                                      independent.id)
        self.assertEqual(first_step.status, CampaignStatus.RUNNING)
        self.assertEqual(first_task.reason_code, "APPROVAL_PENDING")
        self.assertEqual(second_task.reason_code, "HUMAN_REVIEW_REQUIRED")
        self.assertEqual(second_step.status, CampaignStatus.WAITING_APPROVAL)

    def test_campaign_runs_independent_task_before_login_wait(self):
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
            limits=CampaignLimits(max_cycles=1), requested_by="tester")
        self.runtime.campaign.advance(self.package, campaign.id)
        self.runtime.campaign.advance(self.package, campaign.id)
        work = self.runtime.campaign.store.reserve_work(
            campaign.target_id, campaign.id, CampaignWorkKind.PLANNER, requests=5)
        run = self.runtime.planner_store.create(
            self.package, PlannerMode.BOUNDED_AUTONOMOUS,
            PlannerLimits(requests=5, cleanup_reserve=0),
            campaign.policy_hash, campaign_work_id=work.id)
        self.runtime.planner_store.transition(run.target_id, run.id,
                                              PlannerStatus.LOADING_CONTEXT,
                                              "CONTEXT_STARTED")
        digest = hashlib.sha256(b"campaign-login-fixture").hexdigest()
        first = PlannerCandidate(
            "PLCAND-" + "7" * 32, run.id, run.target_id,
            "HYPOTHESIS", "HYP-" + "7" * 32, None, Specialist.AUTHORIZATION,
            "CROSS_TENANT", digest, digest, 90, 80, 100, 5, 0, 0,
            "LOW", 80, "CURRENT", status=CandidateStatus.SELECTED)
        second = replace(first, id="PLCAND-" + "8" * 32,
                         source_id="HYP-" + "8" * 32,
                         root_cause_key=hashlib.sha256(b"anonymous").hexdigest())
        self.runtime.planner_store.transition(run.target_id, run.id,
                                              PlannerStatus.RANKING, "CONTEXT_READY")
        run = self.runtime.planner_store.save_portfolio(run, (first, second), {}, digest)
        login = self.runtime.planner_store.add_task(
            run, first, PlannerTaskType.RESOLVE_IDENTITY, priority=100)
        independent = self.runtime.planner_store.add_task(
            run, second, PlannerTaskType.MANUAL_REVIEW, priority=80)
        original = self.runtime.planner_runner._prerequisite

        def wait_for_login(package, planner_run, task, candidate):
            if task.id == login.id:
                self.runtime.planner_runner._wait(planner_run, task, "LOGIN_REQUIRED")
            else:
                original(package, planner_run, task, candidate)

        with patch.object(self.runtime.planner_runner, "_prerequisite",
                          side_effect=wait_for_login):
            first_step = self.runtime.campaign.advance(self.package, campaign.id)
            second_step = self.runtime.campaign.advance(self.package, campaign.id)
        first_task = self.runtime.planner_store.task(run.target_id, run.id, login.id)
        second_task = self.runtime.planner_store.task(run.target_id, run.id,
                                                      independent.id)
        self.assertEqual(first_step.status, CampaignStatus.RUNNING)
        self.assertEqual(first_task.reason_code, "LOGIN_REQUIRED")
        self.assertEqual(second_task.reason_code, "HUMAN_REVIEW_REQUIRED")
        self.assertEqual(second_step.status, CampaignStatus.WAITING_LOGIN)


if __name__ == "__main__":
    unittest.main()
