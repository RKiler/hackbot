from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hackbot.auth import AuthMechanism
from hackbot.application_mapper import MappingResult
from hackbot.browser import IdentityObservation, IdentityVerificationRule
from hackbot.campaign_models import (CampaignLimits, CampaignPreset,
                                     CampaignStatus, CampaignWorkStatus)
from hackbot.config import (BrowserSettings, BurpSettings, ResourceSettings,
                            TargetSettings, load_config)
from hackbot.domain import TrafficSource
from hackbot.hunt_store import HuntMode, HuntState
from hackbot.planner_models import PlannerMode
from hackbot.policy_models import ActionCategory, ActorMode, ProposedAction
from hackbot.resources import ResourceError
from hackbot.service import BugHunterRuntime, create_app
from hackbot.target_policy import PolicyDecision, RiskLevel
from hackbot.traffic import CapturePacket, CapturedRequest, CapturedResponse


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class FakeDriver:
    name = "FAKE"

    def __init__(self) -> None:
        self.running: set[str] = set()
        self.observations: dict[str, IdentityObservation] = {}

    def start(self, session_id, profile, *, display, proxy) -> None:
        self.running.add(session_id)

    def stop(self, session_id) -> None:
        self.running.discard(session_id)

    def is_running(self, session_id) -> bool:
        return session_id in self.running

    def observe_identity(self, session_id, rule) -> IdentityObservation:
        return self.observations.get(session_id, IdentityObservation())

    def apply_imported_session(self, session_id, material, allowed_url) -> None:
        raise AssertionError("No imported session in this fixture")


class HuntSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        shutil.copytree(EXAMPLE, root / "targets/example")
        base = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                    "XDG_STATE_HOME": str(root)})
        config = replace(
            base, targets=TargetSettings(root / "targets"),
            browser=BrowserSettings(profile_root=root / "profiles", display=":901",
                                    vnc_url="http://127.0.0.1:6901/vnc.html"),
            burp=BurpSettings(True, root / "burp"),
            resources=ResourceSettings(min_available_memory_bytes=0),
        )
        self.config = config
        self.driver = FakeDriver()
        self.runtime = BugHunterRuntime(config, driver=self.driver,
                                        vnc_ready=lambda: True)
        self.package = self.runtime.package("example")

    def test_confirmed_planner_validation_generates_report_draft_once(self) -> None:
        finding_id = "FINDING-" + "a" * 32
        event = {"run": {"id": "PLRUN-" + "b" * 32, "status": "RUNNING"},
                 "task": {"task_type": "VALIDATE_RUN", "status": "COMPLETED",
                          "candidate_id": "PLCAND-" + "c" * 32}}
        with patch.object(self.runtime.planner_store, "candidate",
                          return_value=SimpleNamespace(finding_id=finding_id)), \
             patch.object(self.runtime.report_store, "latest", return_value=None) as latest, \
             patch.object(self.runtime.report_generator, "generate") as generate:
            self.runtime.record_planner_notification(
                self.package.target.id, event["run"]["id"], event)
            latest.assert_called_once_with(finding_id, self.package.target.id)
            generate.assert_called_once_with(finding_id, self.package.target.id)
            self.assertTrue(self.runtime._notification_wakeup.is_set())

        with patch.object(self.runtime.planner_store, "candidate",
                          return_value=SimpleNamespace(finding_id=None)), \
             patch.object(self.runtime.report_generator, "generate") as generate:
            self.runtime.record_planner_notification(
                self.package.target.id, event["run"]["id"], event)
            generate.assert_not_called()

    def test_restart_reprepares_interrupted_mapping_without_target_traffic(self) -> None:
        self.runtime.registry.register_target(self.package)
        run = self.runtime.hunts.create(self.package)
        run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.READY,
                                            "PREPARATION_COMPLETE")
        run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.MAPPING,
                                            "MAPPING_STARTED")
        with patch("hackbot.executor.TrafficExecutor.execute",
                   side_effect=AssertionError("target traffic sent")):
            restarted = BugHunterRuntime(self.config, driver=FakeDriver(),
                                         vnc_ready=lambda: True)
        recovered = restarted.hunts.get(run.target_id, run.id)
        self.assertEqual(recovered.state, HuntState.PREPARING)
        self.assertEqual(recovered.reason_code, "PROCESS_RESTART_REPREPARE")
        self.assertEqual(restarted.hunt_supervisor.reconcile_interrupted(), 0)
        with patch.object(restarted, "launch_hunt_preparation") as launch:
            self.assertEqual(restarted.resume_reconciled_hunts(), 1)
        launch.assert_called_once_with(self.package.id, run.id)

    def test_wsgi_startup_dispatches_only_reconciled_hunts(self) -> None:
        self.runtime.registry.register_target(self.package)
        run = self.runtime.hunts.create(self.package)
        run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.READY,
                                            "PREPARATION_COMPLETE")
        restarted = BugHunterRuntime(self.config, driver=FakeDriver(),
                                     vnc_ready=lambda: True)
        with patch("hackbot.service.BugHunterRuntime", return_value=restarted), \
             patch.object(restarted.delta_scheduler, "start"), \
             patch.object(restarted, "resume_reconciled_hunts") as resume, \
             patch.object(restarted.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            create_app(config=self.config)
        resume.assert_called_once_with()
        self.assertEqual(restarted.hunts.get(run.target_id, run.id).state,
                         HuntState.PREPARING)

    def test_restart_capacity_pressure_surfaces_one_paused_state(self) -> None:
        self.runtime.registry.register_target(self.package)
        run = self.runtime.hunts.create(self.package)
        self.runtime.hunts.transition(run.target_id, run.id, HuntState.READY,
                                      "PREPARATION_COMPLETE")
        restarted = BugHunterRuntime(self.config, driver=FakeDriver(),
                                     vnc_ready=lambda: True)
        with patch.object(restarted, "launch_hunt_preparation",
                          side_effect=ResourceError("CONCURRENCY_LIMIT")), \
             patch.object(restarted.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            self.assertEqual(restarted.resume_reconciled_hunts(), 0)
        paused = restarted.hunts.get(run.target_id, run.id)
        self.assertEqual(paused.state, HuntState.PAUSED_RESOURCE_PRESSURE)
        self.assertEqual(paused.reason_code, "HUNT_CAPACITY_UNAVAILABLE")
        with patch.object(restarted, "launch_hunt_preparation") as launch:
            self.assertEqual(restarted.retry_resource_paused_hunts(), 1)
        launch.assert_called_once_with(self.package.id, run.id)

    def test_resource_retry_does_not_replay_paused_campaign(self) -> None:
        self.runtime.registry.register_target(self.package)
        run = self.runtime.hunts.create(self.package)
        self.runtime.hunts.transition(run.target_id, run.id,
                                      HuntState.PAUSED_RESOURCE_PRESSURE,
                                      "CAMPAIGN_CAPACITY_UNAVAILABLE")
        with patch.object(self.runtime, "launch_hunt_preparation") as launch:
            self.assertEqual(self.runtime.retry_resource_paused_hunts(), 0)
        launch.assert_not_called()

    def test_restart_preserves_waiting_approval(self) -> None:
        self.runtime.registry.register_target(self.package)
        run = self.runtime.hunts.create(self.package)
        run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.READY,
                                            "PREPARATION_COMPLETE")
        run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.HUNTING,
                                            "HUNT_STARTED")
        run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.WAITING_APPROVAL,
                                            "ACTION_APPROVAL_REQUIRED")
        restarted = BugHunterRuntime(self.config, driver=FakeDriver(),
                                     vnc_ready=lambda: True)
        self.assertEqual(restarted.hunts.get(run.target_id, run.id).state,
                         HuntState.WAITING_APPROVAL)

    def test_restart_does_not_repeat_ambiguous_campaign_start(self) -> None:
        self.runtime.registry.register_target(self.package)
        run = self.runtime.hunts.create(self.package)
        run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.READY,
                                            "PREPARATION_COMPLETE")
        run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.HUNTING,
                                            "CAMPAIGN_STARTING")
        restarted = BugHunterRuntime(self.config, driver=FakeDriver(),
                                     vnc_ready=lambda: True)
        recovered = restarted.hunts.get(run.target_id, run.id)
        self.assertEqual(recovered.state, HuntState.WAITING_HUMAN)
        self.assertEqual(recovered.reason_code, "CAMPAIGN_START_UNCONFIRMED")

    def test_restart_settles_linked_completed_campaign(self) -> None:
        self.runtime.registry.register_target(self.package)
        run = self.runtime.hunts.create(self.package)
        run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.READY,
                                            "PREPARATION_COMPLETE")
        run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.HUNTING,
                                            "CAMPAIGN_STARTING")
        campaign = self.runtime.campaign.start(
            self.package, mode=PlannerMode.PLAN_ONLY,
            limits=CampaignLimits(), requested_by="operator")
        self.runtime.hunts.link_campaign(run.target_id, run.id, campaign.id)
        with self.runtime.store._connection() as db:
            db.execute("UPDATE campaigns SET status='COMPLETED' WHERE campaign_id=?",
                       (campaign.id,))
        restarted = BugHunterRuntime(self.config, driver=FakeDriver(),
                                     vnc_ready=lambda: True)
        recovered = restarted.hunts.get(run.target_id, run.id)
        self.assertEqual(recovered.state, HuntState.COMPLETE)
        self.assertEqual(recovered.reason_code, "CAMPAIGN_COMPLETED")

    def test_plan_only_preparation_never_starts_browser_or_target_traffic(self) -> None:
        with patch.object(self.runtime, "ensure_burp_bridge",
                          side_effect=AssertionError("Burp started")), \
             patch.object(self.driver, "start",
                          side_effect=AssertionError("browser started")), \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            run = self.runtime.hunt_supervisor.start(self.package,
                                                     mode=HuntMode.PLAN_ONLY)
        self.assertEqual(run.state, HuntState.READY)
        self.assertEqual(run.reason_code, "PASSIVE_PREPARATION_READY")

    def test_plan_only_handoff_links_one_campaign_without_target_traffic(self) -> None:
        run = self.runtime.hunt_supervisor.start(self.package, mode=HuntMode.PLAN_ONLY)
        with patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            handed = self.runtime.hunt_supervisor.handoff_ready(self.package, run.id)
            again = self.runtime.hunt_supervisor.handoff_ready(self.package, run.id)
        self.assertEqual(handed.state, HuntState.HUNTING)
        self.assertEqual(again.campaign_id, handed.campaign_id)
        campaign = self.runtime.campaign.store.get(handed.target_id, handed.campaign_id)
        self.assertEqual(campaign.mode, PlannerMode.PLAN_ONLY)
        self.assertEqual(campaign.limits, CampaignLimits.preset(CampaignPreset.STANDARD))
        self.assertEqual(self.runtime.hunts.for_campaign(handed.target_id,
                                                         campaign.id).id, run.id)

    def test_supervised_handoff_uses_active_campaign_with_hunt_approval_context(self) -> None:
        anonymous = replace(self.package, accounts=())
        with patch.object(self.runtime, "ensure_burp_bridge"), \
             patch.object(self.runtime.burp, "ready", return_value=True), \
             patch.object(self.runtime.resources, "admit"):
            run = self.runtime.hunt_supervisor.start(anonymous)
        self.assertEqual(run.reason_code, "ANONYMOUS_CAPTURE_READY")
        handed = self.runtime.hunt_supervisor.handoff_ready(anonymous, run.id)
        campaign = self.runtime.campaign.store.get(handed.target_id, handed.campaign_id)
        self.assertEqual(handed.state, HuntState.HUNTING)
        self.assertEqual(campaign.mode, PlannerMode.BOUNDED_AUTONOMOUS)
        self.assertEqual(campaign.limits, CampaignLimits.preset(CampaignPreset.HUNT))
        self.runtime.campaign.store.transition(handed.target_id, campaign.id,
                                               CampaignStatus.WAITING_APPROVAL,
                                               "SYNTHETIC_APPROVAL")
        synced = self.runtime.hunt_supervisor.sync_campaign(anonymous, campaign.id)
        self.assertEqual(synced.state, HuntState.WAITING_APPROVAL)
        self.assertEqual(self.runtime.hunt_supervisor.needs_you(anonymous, run.id)[0][
            "kind"], "APPROVAL_REQUIRED")

    def _resource_paused_campaign_hunt(self, reason: str = "LOW_MEMORY"):
        run = self.runtime.hunt_supervisor.start(self.package, mode=HuntMode.PLAN_ONLY)
        run = self.runtime.hunt_supervisor.handoff_ready(self.package, run.id)
        self.runtime.campaign.advance(self.package, run.campaign_id)
        self.runtime.campaign.store.transition(run.target_id, run.campaign_id,
                                               CampaignStatus.PAUSED, reason)
        paused = self.runtime.hunt_supervisor.sync_campaign(self.package,
                                                            run.campaign_id)
        self.assertEqual(paused.state, HuntState.PAUSED_RESOURCE_PRESSURE)
        self.assertEqual(paused.reason_code, "CAMPAIGN_RESOURCE_PRESSURE")
        return paused

    def test_resource_paused_campaign_auto_resumes_without_replaying_child(self) -> None:
        run = self._resource_paused_campaign_hunt()
        with patch.object(self.runtime.resources, "admit"), \
             patch.object(self.runtime, "launch_campaign") as launch:
            self.assertEqual(self.runtime.retry_resource_paused_hunts(), 1)
        launch.assert_called_once_with(self.package.id, run.campaign_id)
        resumed = self.runtime.hunts.get(run.target_id, run.id)
        self.assertEqual(resumed.state, HuntState.HUNTING)
        self.assertEqual(resumed.reason_code, "CAMPAIGN_RESOURCE_RECOVERED")
        campaign = self.runtime.campaign.store.get(run.target_id, run.campaign_id)
        self.assertEqual(campaign.status, CampaignStatus.ASSESSING_READINESS)

    def test_resource_retry_does_not_resume_ambiguous_child(self) -> None:
        run = self._resource_paused_campaign_hunt()
        work = SimpleNamespace(status=CampaignWorkStatus.LINKED)
        with patch.object(self.runtime.campaign.store, "works", return_value=(work,)), \
             patch.object(self.runtime, "launch_campaign") as launch:
            self.assertEqual(self.runtime.retry_resource_paused_hunts(), 0)
        launch.assert_not_called()
        blocked = self.runtime.hunts.get(run.target_id, run.id)
        self.assertEqual(blocked.state, HuntState.WAITING_HUMAN)
        self.assertEqual(blocked.reason_code, "CAMPAIGN_RECONCILIATION_REQUIRED")

    def test_resource_retry_waits_for_capacity_without_changing_hunt_state(self) -> None:
        run = self._resource_paused_campaign_hunt()
        with patch.object(self.runtime.resources, "admit",
                          side_effect=ResourceError("LOW_MEMORY")), \
             patch.object(self.runtime, "launch_campaign") as launch:
            self.assertEqual(self.runtime.retry_resource_paused_hunts(), 0)
        launch.assert_not_called()
        self.assertEqual(self.runtime.hunts.get(run.target_id, run.id).state,
                         HuntState.PAUSED_RESOURCE_PRESSURE)

    def test_target_429_cooldown_waits_then_resumes_automatically(self) -> None:
        run = self._resource_paused_campaign_hunt("TARGET_THROTTLED")
        with patch.object(self.runtime, "launch_campaign") as launch:
            self.assertEqual(self.runtime.retry_resource_paused_hunts(), 0)
            launch.assert_not_called()
        old = (datetime.now(timezone.utc) - timedelta(minutes=3)).isoformat()
        with self.runtime.store._connection() as db:
            db.execute("UPDATE campaigns SET updated_at=? WHERE campaign_id=?",
                       (old, run.campaign_id))
        with patch.object(self.runtime.resources, "admit"), \
             patch.object(self.runtime, "launch_campaign") as launch:
            self.assertEqual(self.runtime.retry_resource_paused_hunts(), 1)
        launch.assert_called_once_with(self.package.id, run.campaign_id)
        self.assertEqual(self.runtime.hunts.get(run.target_id, run.id).state,
                         HuntState.HUNTING)

    def test_restart_preserves_resource_pause_for_safe_retry(self) -> None:
        run = self._resource_paused_campaign_hunt()
        self.runtime.hunts.transition(run.target_id, run.id, HuntState.HUNTING,
                                      "SYNTHETIC_PRE_RESTART")
        with patch("hackbot.executor.TrafficExecutor.execute",
                   side_effect=AssertionError("target traffic sent")):
            restarted = BugHunterRuntime(self.config, driver=FakeDriver(),
                                         vnc_ready=lambda: True)
        recovered = restarted.hunts.get(run.target_id, run.id)
        self.assertEqual(recovered.state, HuntState.PAUSED_RESOURCE_PRESSURE)
        self.assertEqual(recovered.reason_code, "CAMPAIGN_RESOURCE_PRESSURE")

    def test_campaign_worker_applies_supervised_gate_and_settles_hunt(self) -> None:
        package = replace(self.package, accounts=(), autonomy=replace(
            self.package.autonomy, bounded_active=PolicyDecision.ALLOW))
        with patch.object(self.runtime, "ensure_burp_bridge"), \
             patch.object(self.runtime.burp, "ready", return_value=True), \
             patch.object(self.runtime.resources, "admit"):
            run = self.runtime.hunt_supervisor.start(package)
        run = self.runtime.hunt_supervisor.handoff_ready(package, run.id)
        decisions = []

        def advance(_package, campaign_id):
            action = ProposedAction(
                target_id=package.target.id, package_id=package.id,
                category=ActionCategory.SAFE_READ, actor=ActorMode.ANONYMOUS,
                source="unit_test", purpose="Synthetic supervised gate check",
                url="https://api.example.test/api/profile", method="GET",
                requested_risk=RiskLevel.BOUNDED_ACTIVE)
            decisions.append(self.runtime.policy.evaluate(package, action).result)
            return self.runtime.campaign.store.transition(
                run.target_id, campaign_id, CampaignStatus.COMPLETED,
                "SYNTHETIC_NO_WORK")

        with patch.object(self.runtime, "package", return_value=package), \
             patch.object(self.runtime.campaign, "advance", side_effect=advance), \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            self.runtime._campaign_work(package.id, run.campaign_id)
        self.assertEqual(decisions, [PolicyDecision.REQUIRE_APPROVAL])
        self.assertEqual(self.runtime.hunts.get(run.target_id, run.id).state,
                         HuntState.COMPLETE)

    def test_anonymous_capture_is_provisioned_and_reused_without_target_traffic(self) -> None:
        package = replace(self.package, accounts=())
        with patch.object(self.runtime, "ensure_burp_bridge"), \
             patch.object(self.runtime.burp, "ready", return_value=True), \
             patch.object(self.runtime.resources, "admit"), \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            run = self.runtime.hunt_supervisor.start(package)
            binding = self.runtime.burp.anonymous_capture_binding(run.target_id)
            self.assertIsNotNone(binding)
            self.assertEqual(run.state, HuntState.READY)
            self.assertIsNone(self.runtime.browser.get(binding.browser_session_id).identity_id)
            self.runtime.hunts.transition(run.target_id, run.id, HuntState.PREPARING,
                                          "SYNTHETIC_RECHECK")
            again = self.runtime.hunt_supervisor.advance(package, run.id)
        self.assertEqual(again.reason_code, "ANONYMOUS_CAPTURE_READY")
        self.assertEqual(len([item for item in self.runtime.browser.list_sessions_for_target(
            run.target_id).items if item.identity_id is None]), 1)

    def test_stale_anonymous_session_uses_supported_teardown_before_replacement(self) -> None:
        package = replace(self.package, accounts=())
        self.runtime.registry.register_target(package)
        stale = self.runtime.browser.create(package.target.id)
        with patch.object(self.runtime, "ensure_burp_bridge"), \
             patch.object(self.runtime.burp, "ready", return_value=True), \
             patch.object(self.runtime.resources, "admit"), \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            run = self.runtime.hunt_supervisor.start(package)
        self.assertEqual(run.state, HuntState.READY)
        self.assertIsNone(self.runtime.browser.get(stale.id))
        self.assertIsNotNone(self.runtime.browser.get_for_retention(stale.id))

    def test_anonymous_capture_readiness_failure_releases_new_session(self) -> None:
        package = replace(self.package, accounts=())
        with patch.object(self.runtime, "ensure_burp_bridge"), \
             patch.object(self.runtime.burp, "ready", return_value=False), \
             patch.object(self.runtime.resources, "admit"), \
             patch.object(self.runtime.hunt_supervisor, "_capture_ready",
                          return_value=False), \
             patch.object(self.runtime.burp, "start_browser",
                          side_effect=AssertionError("browser started without capture")):
            run = self.runtime.hunt_supervisor.start(package)
        self.assertEqual(run.state, HuntState.WAITING_HUMAN)
        self.assertEqual(run.reason_code, "ANONYMOUS_CAPTURE_UNAVAILABLE")
        self.assertEqual(self.runtime.browser.list_sessions_for_target(
            run.target_id).items, ())
        with self.runtime.store._connection() as db:
            active = db.execute("SELECT count(*) FROM burp_listener_bindings WHERE "
                                "target_id=? AND state='ACTIVE'", (run.target_id,)).fetchone()[0]
        self.assertEqual(active, 0)

    def test_capture_readiness_wait_is_bounded(self) -> None:
        with patch.object(self.runtime.burp, "ready", side_effect=[False, True]), \
             patch("hackbot.hunt_supervisor.time.sleep") as sleep:
            self.assertTrue(self.runtime.hunt_supervisor._capture_ready(
                "BSESSION-" + "1" * 32, timeout_seconds=1))
            sleep.assert_called_once()
        with patch.object(self.runtime.burp, "ready", return_value=False), \
             patch("hackbot.hunt_supervisor.time.sleep") as sleep:
            self.assertFalse(self.runtime.hunt_supervisor._capture_ready(
                "BSESSION-" + "1" * 32, timeout_seconds=0))
            sleep.assert_not_called()

    def test_campaign_start_ambiguity_never_replays_creation(self) -> None:
        run = self.runtime.hunt_supervisor.start(self.package, mode=HuntMode.PLAN_ONLY)
        original = self.runtime.campaign.start
        created = []

        def fail_after_create(*args, **kwargs):
            created.append(original(*args, **kwargs))
            raise ValueError("synthetic post-create failure")

        with patch.object(self.runtime.campaign, "start", side_effect=fail_after_create):
            uncertain = self.runtime.hunt_supervisor.handoff_ready(self.package, run.id)
            again = self.runtime.hunt_supervisor.handoff_ready(self.package, run.id)
        self.assertEqual(uncertain.state, HuntState.WAITING_HUMAN)
        self.assertEqual(uncertain.reason_code, "CAMPAIGN_START_UNCONFIRMED")
        self.assertEqual(again, uncertain)
        self.assertEqual(len(created), 1)

    def _capture_fakes(self):
        bindings = {}
        proxy = self.runtime.burp.proxy_config(38080)

        def provision(package, identity_id):
            session = self.runtime.browser.create(package.target.id, identity_id,
                                                  proxy=proxy)
            binding = SimpleNamespace(state="ACTIVE")
            bindings[session.id] = binding
            return session, binding

        def start_browser(session_id, *, package):
            return self.runtime.browser.start(session_id, proxy=proxy, package=package,
                                              proxy_health_check=lambda _: True)

        return (patch.object(self.runtime, "ensure_burp_bridge"),
                patch.object(self.runtime.resources, "admit"),
                patch.object(self.runtime.burp, "provision_session", side_effect=provision),
                patch.object(self.runtime.burp, "start_browser", side_effect=start_browser),
                patch.object(self.runtime.burp, "binding_for_session",
                             side_effect=lambda sid: bindings.get(sid)),
                patch.object(self.runtime.burp, "ready", return_value=True))

    def test_start_prepares_burp_sessions_then_waits_for_owned_login(self) -> None:
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5], \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            run = self.runtime.hunt_supervisor.start(self.package)
            self.assertEqual(run.state, HuntState.LOGIN_REQUIRED)
            actions = self.runtime.hunt_supervisor.needs_you(self.package, run.id)
            self.assertEqual({item["alias"] for item in actions},
                             {item.alias for item in self.package.accounts})
            self.assertTrue(all(item["session_id"] in self.driver.running
                                for item in actions))

            identities = {item.alias: self.runtime.registry.get_identity(
                run.target_id, item.alias) for item in self.package.accounts}
            def rule(package, identity_id):
                alias = next(alias for alias, item in identities.items()
                             if item.id == identity_id)
                return IdentityVerificationRule(package.target.id, identity_id,
                                                user_id_selector="#owned-account",
                                                expected_user_id=alias)
            with patch.object(self.runtime, "verification_rule", side_effect=rule):
                for item in actions:
                    self.driver.observations[item["session_id"]] = IdentityObservation(
                        user_id=item["alias"])
                    self.runtime.browser.login_complete(item["session_id"])
                run = self.runtime.hunt_supervisor.advance(self.package, run.id)
            self.assertEqual(run.state, HuntState.READY)
            self.assertEqual(self.runtime.hunt_supervisor.needs_you(self.package, run.id), ())
            self.assertEqual(len(self.runtime.hunts.events(run.target_id, run.id)), 3)

    def test_verified_accounts_map_once_and_persist_session_checkpoints(self) -> None:
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5], \
             patch.object(self.runtime.resources, "snapshot",
                          return_value=SimpleNamespace(state="OK")):
            run = self.runtime.hunt_supervisor.start(self.package)
            actions = self.runtime.hunt_supervisor.needs_you(self.package, run.id)
            identities = {account.alias: self.runtime.registry.get_identity(
                run.target_id, account.alias) for account in self.package.accounts}

            def rule(package, identity_id):
                alias = next(alias for alias, item in identities.items()
                             if item.id == identity_id)
                return IdentityVerificationRule(package.target.id, identity_id,
                                                user_id_selector="#owned-account",
                                                expected_user_id=alias)

            with patch.object(self.runtime, "verification_rule", side_effect=rule):
                for item in actions:
                    self.driver.observations[item["session_id"]] = IdentityObservation(
                        user_id=item["alias"])
                    self.runtime.browser.login_complete(item["session_id"])
                run = self.runtime.hunt_supervisor.advance(self.package, run.id)
            self.assertEqual(run.state, HuntState.READY)

            calls = []

            def mapped(_package, session_id, **_kwargs):
                calls.append(session_id)
                return MappingResult(session_id, 2, 1, 3, 1, 1, (), ())

            with patch.object(self.runtime.application_mapper, "map_session",
                              side_effect=mapped), \
                 patch.object(self.runtime.executor, "execute",
                              side_effect=AssertionError("API triage sent target traffic")), \
                 patch.object(self.runtime.api, "generate",
                              wraps=self.runtime.api.generate) as generate:
                run = self.runtime.hunt_supervisor.map_ready(self.package, run.id)
                again = self.runtime.hunt_supervisor.map_ready(self.package, run.id)
            self.assertEqual(generate.call_count, 1)
            self.assertEqual(generate.call_args.kwargs["mode"], "PLAN_ONLY")
            self.assertEqual(run.state, HuntState.READY)
            self.assertEqual(run.reason_code, "MAPPING_COMPLETE")
            self.assertEqual(again, run)
            self.assertEqual(len(calls), len(self.package.accounts))
            checkpoints = self.runtime.hunts.mapping_sessions(run.target_id, run.id)
            self.assertEqual({item["browser_session_id"] for item in checkpoints}, set(calls))
            self.assertTrue(all(item["pages_observed"] == 1 for item in checkpoints))

    def test_mapping_mismatched_session_fails_closed(self) -> None:
        package = replace(self.package, accounts=self.package.accounts[:1])
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5], \
             patch.object(self.runtime.resources, "snapshot",
                          return_value=SimpleNamespace(state="OK")):
            run = self.runtime.hunt_supervisor.start(package)
            first = self.runtime.hunt_supervisor.needs_you(package, run.id)[0]
            identity = self.runtime.registry.get_identity(run.target_id, first["alias"])
            self.driver.observations[first["session_id"]] = IdentityObservation(
                user_id=first["alias"])
            self.runtime.browser.login_complete(first["session_id"])
            rule = IdentityVerificationRule(package.target.id, identity.id,
                                            user_id_selector="#owned-account",
                                            expected_user_id=first["alias"])
            with patch.object(self.runtime, "verification_rule", return_value=rule):
                run = self.runtime.hunt_supervisor.advance(package, run.id)
            self.assertEqual(run.state, HuntState.READY)
            wrong = MappingResult("BSESSION-" + "0" * 32, 1, 1, 1, 0, 0, (), ())
            with patch.object(self.runtime.application_mapper, "map_session",
                              return_value=wrong):
                run = self.runtime.hunt_supervisor.map_ready(package, run.id)
            self.assertEqual(run.state, HuntState.WAITING_HUMAN)
            self.assertEqual(run.reason_code, "MAPPING_SESSION_MISMATCH")
            self.assertEqual(self.runtime.hunts.mapping_sessions(run.target_id, run.id), ())

    def test_mapping_capture_loss_requires_review(self) -> None:
        package = replace(self.package, accounts=self.package.accounts[:1])
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5], \
             patch.object(self.runtime.resources, "snapshot",
                          return_value=SimpleNamespace(state="OK")):
            run = self.runtime.hunt_supervisor.start(package)
            session_id = self.runtime.hunt_supervisor.needs_you(package, run.id)[0]["session_id"]
            session = self.runtime.browser.get(session_id)
            run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.READY,
                                                "SESSION_VERIFIED")
            result = MappingResult(session_id, 1, 0, 0, 0, 0, (),
                                   ("CAPTURE_OR_IDENTITY_LOST",))
            with patch.object(self.runtime.browser, "get_active_session", return_value=session), \
                 patch.object(self.runtime.application_mapper, "map_session",
                              return_value=result):
                run = self.runtime.hunt_supervisor.map_ready(package, run.id)
            self.assertEqual(run.state, HuntState.WAITING_HUMAN)
            self.assertEqual(run.reason_code, "MAPPING_CAPTURE_REVIEW_REQUIRED")
            self.assertEqual(self.runtime.hunts.mapping_sessions(run.target_id, run.id)[0][
                "blocked_count"], 1)

    def test_js_capture_cap_is_a_partial_mapping_checkpoint(self) -> None:
        from hackbot.captured_js import CapturedJSResult

        package = replace(self.package, accounts=self.package.accounts[:1])
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5], \
             patch.object(self.runtime.resources, "snapshot",
                          return_value=SimpleNamespace(state="OK")):
            run = self.runtime.hunt_supervisor.start(package)
            session_id = self.runtime.hunt_supervisor.needs_you(package, run.id)[0]["session_id"]
            session = self.runtime.browser.get(session_id)
            run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.READY,
                                                "SESSION_VERIFIED")
            mapped = MappingResult(session_id, 1, 1, 1, 2, 0, (), ())
            with patch.object(self.runtime.browser, "get_active_session", return_value=session), \
                 patch.object(self.runtime.application_mapper, "map_session",
                              return_value=mapped), \
                 patch.object(self.runtime.captured_js, "collect",
                              return_value=CapturedJSResult(2, (), 0, True)):
                run = self.runtime.hunt_supervisor.map_ready(package, run.id)
            self.assertEqual(run.state, HuntState.READY)
            self.assertEqual(run.reason_code, "MAPPING_PARTIAL")
            self.assertEqual(self.runtime.hunts.mapping_sessions(run.target_id, run.id)[0][
                "blocked_count"], 1)

    def test_mapping_indexes_captured_js_api_and_graphql_without_recon(self) -> None:
        package = replace(self.package, accounts=self.package.accounts[:1])
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5], \
             patch.object(self.runtime.resources, "snapshot",
                          return_value=SimpleNamespace(state="OK")):
            run = self.runtime.hunt_supervisor.start(package)
            action = self.runtime.hunt_supervisor.needs_you(package, run.id)[0]
            identity = self.runtime.registry.get_identity(run.target_id, action["alias"])
            self.driver.observations[action["session_id"]] = IdentityObservation(
                user_id=action["alias"])
            self.runtime.browser.login_complete(action["session_id"])
            rule = IdentityVerificationRule(package.target.id, identity.id,
                                            user_id_selector="#owned-account",
                                            expected_user_id=action["alias"])
            with patch.object(self.runtime, "verification_rule", return_value=rule):
                run = self.runtime.hunt_supervisor.advance(package, run.id)
            self.assertEqual(run.state, HuntState.READY)
            self.assertIsNone(self.runtime.recon)
            now = datetime.now(timezone.utc)
            self.runtime.traffic.store_exchange(
                package, CapturePacket(
                    CapturedRequest("GET", "https://app.example.test/assets/app.js",
                                    observed_at=now, http_version="HTTP/1.1"),
                    CapturedResponse(200, (("Content-Type", "application/javascript"),),
                                     b"fetch('/api/documents',{method:'GET'});"
                                     b"const q=gql`query GetDocument($id:ID!){node(id:$id){id name}}`;",
                                     observed_at=now, http_version="HTTP/1.1"),
                    browser_session_id=action["session_id"]),
                source=TrafficSource.BURP, capture_provider="MONTOYA_V1",
                browser_manager=self.runtime.browser)
            mapped = MappingResult(action["session_id"], 1, 1, 1, 1, 0, (), ())
            with patch.object(self.runtime.application_mapper, "map_session",
                              return_value=mapped):
                run = self.runtime.hunt_supervisor.map_ready(package, run.id)
            self.assertEqual(run.reason_code, "MAPPING_COMPLETE")
            assets = self.runtime.domxss_store.list_current_assets(run.target_id)
            self.assertEqual(len(assets), 1)
            self.assertEqual(assets[0].source, "CAPTURED_BURP")
            self.assertGreaterEqual(self.runtime.api_operations.counts(run.target_id)[
                "operations_current"], 2)
            self.assertGreaterEqual(self.runtime.api_operations.operation_type_counts(
                run.target_id).get("GRAPHQL_QUERY", 0), 1)
            status = create_app(runtime=self.runtime).test_client().get(
                "/v1/targets/example/hunt")
            self.assertEqual(status.status_code, 200)
            inventory = status.get_json()["inventory"]
            self.assertEqual(inventory["js_assets_current"], 1)
            self.assertGreaterEqual(inventory["api_operations_current"], 2)
            self.assertGreaterEqual(inventory["graphql_operations_current"], 1)

    def test_mapping_resume_skips_completed_session(self) -> None:
        package = replace(self.package, accounts=self.package.accounts[:1])
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5]:
            run = self.runtime.hunt_supervisor.start(package)
            session_id = self.runtime.hunt_supervisor.needs_you(package, run.id)[0]["session_id"]
            session = self.runtime.browser.get(session_id)
            run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.READY,
                                                "SESSION_VERIFIED")
            run = self.runtime.hunts.transition(run.target_id, run.id, HuntState.MAPPING,
                                                "AUTHENTICATED_MAPPING_STARTED")
            self.runtime.hunts.record_mapping(run.target_id, run.id,
                                              MappingResult(session_id, 2, 1, 3, 1, 1, (), ()))
            with patch.object(self.runtime.browser, "get_active_session", return_value=session), \
                 patch.object(self.runtime.application_mapper, "map_session",
                              side_effect=AssertionError("completed session remapped")):
                run = self.runtime.hunt_supervisor.map_ready(package, run.id)
            self.assertEqual(run.state, HuntState.READY)
            self.assertEqual(run.reason_code, "MAPPING_COMPLETE")

    def test_needs_you_distinguishes_login_and_identity_confirmation(self) -> None:
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5]:
            run = self.runtime.hunt_supervisor.start(self.package)
            first = self.runtime.hunt_supervisor.needs_you(self.package, run.id)[0]
            self.runtime.browser.login_complete(first["session_id"])
            run = self.runtime.hunt_supervisor.advance(self.package, run.id)
            self.assertEqual(run.state, HuntState.WAITING_HUMAN)
            self.assertEqual(run.reason_code, "IDENTITY_CONFIRMATION_REQUIRED")
            items = self.runtime.hunt_supervisor.needs_you(self.package, run.id)
            self.assertEqual(sum(item["kind"] == "CONFIRM_IDENTITY" for item in items), 1)
            self.assertEqual(sum(item["kind"] == "LOGIN_REQUIRED" for item in items),
                             len(self.package.accounts) - 1)

    def test_resource_pressure_pauses_without_direct_browser_fallback(self) -> None:
        with patch.object(self.runtime.resources, "admit",
                          side_effect=ResourceError("CONCURRENCY_LIMIT")), \
             patch.object(self.runtime.burp, "provision_session",
                          side_effect=AssertionError("bypassed admission")):
            run = self.runtime.hunt_supervisor.start(self.package)
        self.assertEqual(run.state, HuntState.PAUSED_RESOURCE_PRESSURE)
        self.assertEqual(run.reason_code, "BROWSER_CAPACITY_UNAVAILABLE")

    def test_stale_direct_session_is_retired_before_captured_login(self) -> None:
        package = replace(self.package, accounts=self.package.accounts[:1])
        self.runtime.registry.register_target(package)
        self.runtime.registry.import_package_accounts(package)
        identity = self.runtime.registry.get_identity(package.target.id,
                                                      package.accounts[0].alias)
        self.runtime.auth.prepare(package.target.id, identity.id,
                                  mechanism=AuthMechanism.MANUAL_LOGIN)
        stale = self.runtime.browser.create(package.target.id, identity.id)
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5]:
            run = self.runtime.hunt_supervisor.start(package)
        self.assertEqual(run.state, HuntState.LOGIN_REQUIRED)
        self.assertIsNone(self.runtime.browser.get(stale.id))
        self.assertIsNotNone(self.runtime.browser.get_for_retention(stale.id))

    def _verified_single_account(self, package):
        run = self.runtime.hunt_supervisor.start(package)
        action = self.runtime.hunt_supervisor.needs_you(package, run.id)[0]
        identity = self.runtime.registry.get_identity(run.target_id, action["alias"])
        self.driver.observations[action["session_id"]] = IdentityObservation(
            user_id=action["alias"])
        self.runtime.browser.login_complete(action["session_id"])
        rule = IdentityVerificationRule(package.target.id, identity.id,
                                        user_id_selector="#owned-account",
                                        expected_user_id=action["alias"])
        with patch.object(self.runtime, "verification_rule", return_value=rule):
            run = self.runtime.hunt_supervisor.advance(package, run.id)
        self.assertEqual(run.state, HuntState.READY)
        return run, action["session_id"]

    def test_crashed_browser_recreates_capture_and_requests_login(self) -> None:
        package = replace(self.package, accounts=self.package.accounts[:1])
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5], \
             patch.object(self.runtime.burp, "release") as release, \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            run, old_session = self._verified_single_account(package)
            self.driver.running.discard(old_session)
            self.runtime.hunts.transition(run.target_id, run.id, HuntState.PREPARING,
                                          "SYNTHETIC_BROWSER_CRASH")
            recovered = self.runtime.hunt_supervisor.advance(package, run.id)
            release.assert_called_with(old_session)
        self.assertEqual(recovered.state, HuntState.LOGIN_REQUIRED)
        self.assertIsNone(self.runtime.browser.get(old_session))
        self.assertIsNotNone(self.runtime.browser.get_for_retention(old_session))
        self.assertNotEqual(self.runtime.hunt_supervisor.needs_you(package, run.id)[0][
            "session_id"], old_session)

    def test_expired_owned_session_recreates_capture_and_requests_login(self) -> None:
        package = replace(self.package, accounts=self.package.accounts[:1])
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5], \
             patch.object(self.runtime.burp, "release") as release, \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            run, old_session = self._verified_single_account(package)
            self.runtime.browser.expire(old_session)
            self.runtime.hunts.transition(run.target_id, run.id, HuntState.PREPARING,
                                          "SYNTHETIC_SESSION_EXPIRED")
            recovered = self.runtime.hunt_supervisor.advance(package, run.id)
            release.assert_called_with(old_session)
        self.assertEqual(recovered.state, HuntState.LOGIN_REQUIRED)
        self.assertIsNone(self.runtime.browser.get(old_session))
        self.assertNotEqual(self.runtime.hunt_supervisor.needs_you(package, run.id)[0][
            "session_id"], old_session)

    def test_lost_burp_listener_recreates_capture_without_direct_fallback(self) -> None:
        package = replace(self.package, accounts=self.package.accounts[:1])
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5] as ready, \
             patch.object(self.runtime.burp, "release") as release, \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            run, old_session = self._verified_single_account(package)
            ready.side_effect = lambda session_id: session_id != old_session
            self.runtime.hunts.transition(run.target_id, run.id, HuntState.PREPARING,
                                          "SYNTHETIC_BURP_RESTART")
            recovered = self.runtime.hunt_supervisor.advance(package, run.id)
            release.assert_called_with(old_session)
        self.assertEqual(recovered.state, HuntState.LOGIN_REQUIRED)
        self.assertIsNone(self.runtime.browser.get(old_session))
        self.assertNotEqual(self.runtime.hunt_supervisor.needs_you(package, run.id)[0][
            "session_id"], old_session)

    def test_pending_login_with_lost_capture_is_reprovisioned(self) -> None:
        package = replace(self.package, accounts=self.package.accounts[:1])
        fakes = self._capture_fakes()
        with fakes[0], fakes[1], fakes[2], fakes[3], fakes[4], fakes[5] as ready, \
             patch.object(self.runtime.burp, "release") as release, \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            run = self.runtime.hunt_supervisor.start(package)
            old_session = self.runtime.hunt_supervisor.needs_you(package, run.id)[0][
                "session_id"]
            ready.side_effect = lambda session_id: session_id != old_session
            recovered = self.runtime.hunt_supervisor.advance(package, run.id)
            release.assert_called_with(old_session)
        self.assertEqual(recovered.state, HuntState.LOGIN_REQUIRED)
        self.assertIsNone(self.runtime.browser.get(old_session))
        self.assertNotEqual(self.runtime.hunt_supervisor.needs_you(package, run.id)[0][
            "session_id"], old_session)

    def test_automation_rule_blocks_active_hunt_before_side_effects(self) -> None:
        denied = replace(self.package, rules=replace(
            self.package.rules, automated_testing_allowed=False))
        with self.assertRaisesRegex(ValueError, "explicitly allow"):
            self.runtime.hunt_supervisor.start(denied)
        self.assertIsNone(self.runtime.hunts.current(self.package.target.id))


if __name__ == "__main__":
    unittest.main()
