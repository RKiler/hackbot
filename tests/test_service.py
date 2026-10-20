from __future__ import annotations

from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import sqlite3
import socket
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import Mock, patch

from hackbot.browser import IdentityObservation
from hackbot.auth import AuthMechanism
from hackbot.api_registry import APICandidate, APIOperationType
from hackbot.campaign_models import CampaignLimits
from hackbot.config import (BrowserSettings, BurpSettings, SecretBindingConfig,
                            SecretSettings, TargetSettings, ResourceSettings, load_config)
from hackbot.burp_storage import BurpStorageStatus
from hackbot.domxss import DOMAcquisitionStatus
from hackbot.domain import TrafficSource
from hackbot.postmessage_static import PostMessageStaticAnalyzer
from hackbot.resources import ResourceError
from hackbot.research import GapType, KnowledgeGap, ResearchBudget, ResearchStatus
from hackbot.service import BugHunterRuntime, create_app
from hackbot.target_operator import TargetSetupError
from hackbot.store import EvidenceFactStore, StoreSchemaError
from hackbot.planner_models import PlannerLimits, PlannerMode, PlannerStatus
from hackbot.process_health import OwnedProcessStatus
from hackbot.notification_store import DeliveryStatus, NotificationPriority, NotificationType
from hackbot.policy import policy_version
from hackbot.traffic import CapturePacket, CapturedRequest, CapturedResponse
from tests.schema_utils import drop_phase28_schema


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class FakeDriver:
    name = "FAKE"

    def __init__(self):
        self.running = set()
        self.observation = IdentityObservation()

    def start(self, session_id, profile, *, display, proxy):
        self.running.add(session_id)

    def stop(self, session_id):
        self.running.discard(session_id)

    def is_running(self, session_id):
        return session_id in self.running

    def observe_identity(self, session_id, rule):
        return self.observation

    def apply_imported_session(self, session_id, material, allowed_url):
        raise AssertionError("not part of Phase 11 fixture")


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        temporary = TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        root = Path(temporary.name)
        config = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                      "XDG_STATE_HOME": str(root)})
        store = EvidenceFactStore.from_config(config)
        store.initialize()
        cls._empty_schema = store.db_path

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        targets = root / "targets"
        shutil.copytree(EXAMPLE, targets / "example")
        base = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                    "XDG_STATE_HOME": str(root)})
        self.config = replace(base, targets=TargetSettings(targets), browser=BrowserSettings(
            profile_root=root / "profiles", display=":901",
            vnc_url="http://127.0.0.1:6901/vnc.html"),
            resources=ResourceSettings(min_available_memory_bytes=0))
        state = self.config.paths.state
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(self._empty_schema, state / "bughunter.sqlite3")
        self.driver = FakeDriver()
        self.runtime = BugHunterRuntime(self.config, driver=self.driver, vnc_ready=lambda: True)
        self.app = create_app(runtime=self.runtime)
        self.client = self.app.test_client()
        self.target = self.runtime.package("example").target.id

    def get(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def test_operator_target_create_accounts_and_import_are_local_only(self):
        payload = {
            "name": "Local Pilot Fixture", "id": "local-pilot-fixture",
            "primary_domain": "app.local.test", "confirmed": True,
            "scope": {"include": ["app.local.test", "api.local.test"],
                      "exclude": ["billing.local.test"], "schemes": ["https"], "ports": [443]},
            "source": {"kind": "RESEARCHER", "reference": "synthetic fixture",
                       "operator": "test-operator"},
            "rules": {"automated_testing_allowed": True,
                      "account_creation_allowed": False,
                      "forbidden_actions": ["credential_stuffing"]},
            "autonomy": {"passive": "ALLOW", "safe_read": "ALLOW",
                         "bounded_active": "DENY", "state_changing": "DENY",
                         "destructive": "DENY"},
            "rate": {"requests_per_second": 1, "requests_per_minute": 30,
                     "max_concurrency": 1, "burst": 1}}
        self.assertIn("RESEARCHER", self.get("/v1/targets/setup-options")["source_kinds"])
        self.assertEqual(self.client.get("/v1/targets/local-pilot-fixture").status_code, 404)
        with patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target traffic")):
            created = self.client.post("/v1/targets", json=payload)
        self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
        self.assertEqual(created.get_json()["network_requests_sent"], 0)
        self.assertEqual(self.get("/v1/targets/local-pilot-fixture")["primary_domain"], "app.local.test")
        self.assertEqual(self.client.post("/v1/targets", json=payload).status_code, 409)
        accounts_path = self.config.targets.root / "local-pilot-fixture" / "accounts.yaml"
        self.assertFalse(accounts_path.exists())
        saved = self.client.post("/v1/targets/local-pilot-fixture/accounts", json={"accounts": [
            {"alias": "admin", "tenant": "company1", "role": "admin"},
            {"alias": "member", "tenant": "company1", "role": "member"}]})
        self.assertEqual(saved.status_code, 200, saved.get_data(as_text=True))
        self.assertEqual(saved.get_json()["configured"], 2)
        self.assertTrue(accounts_path.is_file())
        self.assertEqual(self.get("/v1/targets/local-pilot-fixture/accounts")["items"][0][
            "registration"], "NOT_REGISTERED")
        imported = self.client.post("/v1/targets/local-pilot-fixture/import-identities", json={})
        self.assertEqual(imported.status_code, 201, imported.get_data(as_text=True))
        self.assertEqual(imported.get_json()["imported"], 2)
        self.assertEqual(self.get("/v1/targets/local-pilot-fixture/accounts")["items"][0][
            "registration"], "REGISTERED")
        self.assertEqual(self.client.post("/v1/targets/local-pilot-fixture/accounts", json={
            "accounts": [{"alias": "admin", "tenant": "company2", "role": "admin"}]}).status_code, 409)
        self.assertEqual(self.client.get("/v1/targets/local-pilot-fixture/accounts").status_code, 200)

    def test_runtime_rejects_old_existing_schema_without_migration(self):
        database = self.runtime.store.db_path
        with sqlite3.connect(database) as connection:
            drop_phase28_schema(connection)
            connection.execute("PRAGMA user_version=34")
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        with self.assertRaisesRegex(StoreSchemaError, "reviewed schema migration"):
            BugHunterRuntime(self.config, driver=FakeDriver(), vnc_ready=lambda: True)
        self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)
        with sqlite3.connect(database) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 34)

    def test_runtime_wires_dom_retention_periods(self):
        configured = replace(self.config, retention=replace(
            self.config.retention, js_artifact_hours=24, source_map_hours=48))
        runtime = BugHunterRuntime(configured, driver=FakeDriver(), vnc_ready=lambda: True)
        self.assertEqual(runtime.domxss_store.js_retention_hours, 24)
        self.assertEqual(runtime.domxss_store.source_map_retention_hours, 48)
        self.assertEqual(runtime.executor.retention.js_artifact_hours, 24)
        self.assertEqual(runtime.executor.retention.source_map_hours, 48)

    def test_safe_overview_targets_scope_burp_and_pagination(self):
        self.assertEqual(self.get("/v1/health")["checks"]["traffic_store"], "ok")
        self.assertEqual(self.get("/v1/overview")["targets"], 1)
        page = self.get("/v1/targets?limit=1")
        self.assertEqual(page["items"][0]["authority"], "TARGET_PACKAGE")
        self.assertEqual(self.get("/v1/targets/example/scope")["authority"], "AUTHORIZED_TARGET_SCOPE")
        self.assertEqual(self.get("/v1/burp/status")["availability"], "BURP_NOT_INSTALLED")
        self.assertEqual(self.client.get("/v1/targets?limit=999").status_code, 400)
        self.assertEqual(self.client.get("/v1/targets/not-here").status_code, 404)
        self.assertEqual(self.client.get("/v1/evidence/EV-invalid?target=example").status_code, 400)

    def test_operations_snapshot_is_local_and_reports_missing_backup(self):
        data = self.get("/v1/operations")
        self.assertIn("burp_storage", data)
        self.assertEqual(data["burp_storage"]["state"], "DISABLED")
        self.assertEqual(data["components"]["burp_storage"], "DISABLED")
        self.assertEqual(data["storage"]["schema_actual"], data["storage"]["schema_expected"])
        self.assertEqual(data["backup"]["state"], "MISSING")
        self.assertIn("BACKUP_MISSING", data["warnings"])
        self.assertEqual(data["counts"]["evidence"], 0)
        self.assertEqual(data["storage"]["artifact_count"], 0)
        self.assertIn("browser_reauth_required", data["counts"])
        self.assertIn("processes", data)
        self.assertEqual(data["recon"], "DISCONNECTED")
        self.assertEqual(data["components"]["state_database"], "OK")
        self.assertEqual(data["components"]["artifact_store"], "OK")
        self.assertEqual(data["components"]["recon"], "DISABLED")
        self.assertEqual(data["components"]["research_external"], "DISABLED")
        self.assertEqual(data["retention"]["traffic"]["anonymous_hours"], 720)
        self.assertEqual(data["retention"]["traffic"]["payload_cleanup"], "CLI_REVIEWED")
        self.assertEqual(data["retention"]["traffic"]["physical_gc"], "SEPARATE_REVIEW")
        self.assertIsNotNone(self.runtime.traffic.retention_policy)

    def test_operations_warns_for_owned_display_orphan_and_blocks_profile_cleanup(self):
        orphan = OwnedProcessStatus(
            "OK", {"bughunter-agent.service": 1, "bughunter-burp.service": 0,
                   "bughunter-vnc.service": 1}, (), (), (101,), (201,), (101,))
        with patch("hackbot.service.inspect_owned_processes", return_value=orphan):
            self.assertFalse(self.runtime._profile_process_safe())
            data = self.get("/v1/operations")
        self.assertIn("SUSPECTED_DISPLAY_ORPHAN", data["warnings"])
        self.assertEqual(data["processes"]["vnc_display_pids"], [201])

        expected = OwnedProcessStatus(
            "OK", {"bughunter-agent.service": 1, "bughunter-burp.service": 0,
                   "bughunter-vnc.service": 1}, (), (), (), (201,), ())
        with patch("hackbot.service.inspect_owned_processes", return_value=expected):
            self.assertTrue(self.runtime._profile_process_safe())
            healthy = self.get("/v1/operations")
            self.runtime._vnc_ready = lambda: False
            disconnected = self.get("/v1/operations")
        self.assertNotIn("SUSPECTED_DISPLAY_ORPHAN", healthy["warnings"])
        self.assertIn("SUSPECTED_DISPLAY_ORPHAN", disconnected["warnings"])

    def test_operations_degrades_incomplete_burp_storage_inventory(self):
        self.runtime.config = replace(
            self.runtime.config,
            burp=replace(self.runtime.config.burp, enabled=True),
        )
        incomplete = BurpStorageStatus("PARTIAL", 3, 1, 1, 1, 17, 17, 0, 0)
        with patch("hackbot.service.inspect_burp_storage", return_value=incomplete):
            data = self.get("/v1/operations")
        self.assertEqual(data["components"]["burp_storage"], "DEGRADED")
        self.assertIn("BURP_STORAGE_INVENTORY_INCOMPLETE", data["warnings"])
        self.assertEqual(data["burp_storage"]["data_estimated_bytes"], 17)
        self.assertNotIn(str(self.runtime.config.burp.runtime_root), json.dumps(data["burp_storage"]))

    def test_operations_exposes_configured_cpu_load_warning(self):
        self.runtime.resources.settings = replace(
            self.runtime.resources.settings,
            high_load_per_cpu=4.0,
            critical_load_per_cpu=8.0,
        )
        self.runtime.resources._load_per_cpu = lambda: 5.0
        data = self.get("/v1/operations")
        self.assertEqual(data["resources"]["load_per_cpu"], 5.0)
        self.assertIn("HIGH_LOAD", data["warnings"])
        self.assertEqual(data["state"], "DEGRADED")

    def test_optional_status_failures_degrade_operations_without_exposing_errors(self):
        self.runtime.config = replace(
            self.runtime.config,
            burp=replace(self.runtime.config.burp, enabled=True))
        with (patch.object(self.runtime.burp, "status",
                           side_effect=RuntimeError("Authorization: Bearer DO_NOT_LOG")),
              patch.object(self.runtime.notifications, "status",
                           side_effect=RuntimeError("password=DO_NOT_LOG"))):
            data = self.get("/v1/operations")
        self.assertEqual(data["components"]["burp"], "FAILED")
        self.assertEqual(data["components"]["notifier"], "DEGRADED")
        self.assertIn("BURP_DOWN", data["warnings"])
        self.assertIn("NOTIFIER_FAILURE", data["warnings"])
        self.assertNotIn("DO_NOT_LOG", json.dumps(data))

    def test_inflight_notification_is_visible_as_degraded(self):
        event = self.runtime.notification_store.enqueue(
            target_id=self.target, event_type=NotificationType.TEST,
            source_kind="TEST", source_id="TEST-" + uuid.uuid4().hex,
            priority=NotificationPriority.LOW,
        )
        self.runtime.notification_store.prepare_deliveries(event.id, ("fixture",))
        claimed = self.runtime.notification_store.claim("fixture")
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed[0].status, DeliveryStatus.SENDING)

        operations = self.get("/v1/operations")
        self.assertEqual(operations["notifications"]["delivery"]["sending"], 1)
        self.assertEqual(operations["components"]["notifier"], "DEGRADED")
        self.assertIn("NOTIFIER_FAILURE", operations["warnings"])
        self.assertEqual(self.get("/v1/health")["checks"]["notifier"], "degraded")

    def test_research_provider_configuration_is_not_reported_as_verified(self):
        self.runtime.config = replace(
            self.runtime.config,
            research=replace(self.runtime.config.research, enabled=True))
        self.runtime.research.web_provider = object()
        data = self.get("/v1/operations")
        self.assertEqual(data["components"]["research_local"], "UNVERIFIED")
        self.assertEqual(data["components"]["research_external"], "UNVERIFIED")

    def test_recent_research_provider_failure_warns_without_network_probe(self):
        self.runtime.config = replace(
            self.runtime.config,
            research=replace(self.runtime.config.research, enabled=True))
        self.runtime.research.web_provider = object()
        self.runtime.registry.register_target(self.runtime.package("example"))
        gap = KnowledgeGap("hypothesis:HYP-" + "a" * 32, self.target,
                           GapType.UNKNOWN_PROTOCOL, "fixture research gap", None,
                           "authorization", "api", None, 50)
        request_id = self.runtime.research_store.create_request(
            gap, ResearchBudget(), external=True, private_target=False,
            cache_key="fixture:" + "a" * 64)
        self.runtime.research_store.record_usage(
            request_id, searches=1, sources=0, source_bytes=0,
            input_tokens=0, output_tokens=0)
        self.runtime.research_store.transition(
            request_id, ResearchStatus.FAILED,
            error_code="EXTERNAL_PROVIDER_UNAVAILABLE")
        data = self.get("/v1/operations")
        self.assertEqual(data["components"]["research"], "DEGRADED")
        self.assertEqual(data["components"]["research_external"], "DEGRADED")
        self.assertIn("RESEARCH_PROVIDER_UNAVAILABLE", data["warnings"])
        with self.runtime.store._connection() as db:
            db.execute("UPDATE research_requests SET updated_at=? WHERE request_id=?",
                       ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
                        request_id))
        stale = self.get("/v1/operations")
        self.assertEqual(stale["components"]["research_external"], "DEGRADED")
        self.assertIn("RESEARCH_PROVIDER_UNAVAILABLE", stale["warnings"])
        recovered_id = self.runtime.research_store.create_request(
            gap, ResearchBudget(), external=True, private_target=False,
            cache_key="fixture:" + "b" * 64)
        self.runtime.research_store.record_usage(
            recovered_id, searches=1, sources=1, source_bytes=100,
            input_tokens=20, output_tokens=10)
        self.runtime.research_store.transition(recovered_id, ResearchStatus.COMPLETED)
        recovered = self.get("/v1/operations")
        self.assertEqual(recovered["components"]["research_external"], "OK")
        self.assertNotIn("RESEARCH_PROVIDER_UNAVAILABLE", recovered["warnings"])

    def test_legacy_provider_failure_does_not_blame_an_unidentified_provider(self):
        self.runtime.config = replace(
            self.runtime.config,
            research=replace(self.runtime.config.research, enabled=True))
        self.runtime.research.web_provider = object()
        self.runtime.registry.register_target(self.runtime.package("example"))
        gap = KnowledgeGap("hypothesis:HYP-" + "c" * 32, self.target,
                           GapType.UNKNOWN_PROTOCOL, "fixture research gap", None,
                           "authorization", "api", None, 50)
        request_id = self.runtime.research_store.create_request(
            gap, ResearchBudget(), external=True, private_target=False,
            cache_key="fixture:" + "e" * 64)
        self.runtime.research_store.record_usage(
            request_id, searches=1, sources=0, source_bytes=0,
            input_tokens=0, output_tokens=0)
        self.runtime.research_store.transition(
            request_id, ResearchStatus.PARTIAL, error_code="PROVIDER_UNAVAILABLE")
        state = self.get("/v1/operations")
        self.assertEqual(state["components"]["research"], "DEGRADED")
        self.assertEqual(state["components"]["research_local"], "UNVERIFIED")
        self.assertEqual(state["components"]["research_external"], "UNVERIFIED")
        self.assertIn("RESEARCH_PROVIDER_UNAVAILABLE", state["warnings"])
        self.assertNotIn("RESEARCH_LOCAL_PROVIDER_UNAVAILABLE", state["warnings"])

    def test_interrupted_research_is_degraded_until_a_later_completed_request(self):
        self.runtime.registry.register_target(self.runtime.package("example"))
        gap = KnowledgeGap("hypothesis:HYP-" + "b" * 32, self.target,
                           GapType.UNKNOWN_PROTOCOL, "fixture research gap", None,
                           "authorization", "api", None, 50)
        failed_id = self.runtime.research_store.create_request(
            gap, ResearchBudget(), external=False, private_target=False,
            cache_key="fixture:" + "c" * 64)
        self.runtime.research_store.transition(
            failed_id, ResearchStatus.PARTIAL, error_code="INTERRUPTED")
        degraded = self.get("/v1/operations")
        self.assertEqual(degraded["components"]["research"], "DEGRADED")
        self.assertEqual(degraded["components"]["research_local"], "UNVERIFIED")
        self.assertIn("RESEARCH_EXECUTION_FAILURE", degraded["warnings"])

        recovered_id = self.runtime.research_store.create_request(
            gap, ResearchBudget(), external=False, private_target=False,
            cache_key="fixture:" + "d" * 64)
        self.runtime.research_store.transition(recovered_id, ResearchStatus.COMPLETED)
        recovered = self.get("/v1/operations")
        self.assertEqual(recovered["components"]["research"], "OK")
        self.assertNotIn("RESEARCH_EXECUTION_FAILURE", recovered["warnings"])

    def test_operations_stays_readable_when_storage_budget_is_unavailable(self):
        with patch.object(self.runtime.resources, "snapshot",
                          side_effect=ResourceError("REQUIRED_MOUNT_UNAVAILABLE")):
            data = self.get("/v1/operations")
            self.assertEqual(data["state"], "BLOCKED")
            self.assertIn("REQUIRED_MOUNT_UNAVAILABLE", data["warnings"])
            self.assertEqual(data["resources"]["disk_free_bytes"], 0)

    def test_startup_rejects_missing_required_mount_before_sqlite_creation(self):
        mount = Path(self.temp.name) / "unmounted"
        root = mount / "bughunter"
        root.mkdir(parents=True)
        config = replace(self.config, paths=replace(self.config.paths, root=root),
                         resources=ResourceSettings(required_mount=str(mount)))
        with patch("hackbot.resources.os.path.ismount", return_value=False):
            with self.assertRaisesRegex(ResourceError, "REQUIRED_MOUNT_UNAVAILABLE"):
                BugHunterRuntime(config, driver=self.driver, vnc_ready=lambda: True)
        self.assertFalse((root / "state" / "bughunter.sqlite3").exists())

    def test_startup_rejects_off_mount_artifacts_before_sqlite_creation(self):
        mount = Path(self.temp.name) / "mounted"
        root = mount / "bughunter"
        root.mkdir(parents=True)
        outside = Path(self.temp.name) / "outside-artifacts"
        config = replace(self.config, paths=replace(self.config.paths, root=root),
                         store=replace(self.config.store, artifact_root=outside),
                         resources=ResourceSettings(required_mount=str(mount)))
        with patch("hackbot.resources.os.path.ismount", return_value=True):
            with self.assertRaisesRegex(ResourceError, "ARTIFACT_STORAGE_OUTSIDE_REQUIRED_MOUNT"):
                BugHunterRuntime(config, driver=self.driver, vnc_ready=lambda: True)
        self.assertFalse((root / "state" / "bughunter.sqlite3").exists())

    def test_startup_accepts_required_mount_with_state_and_artifacts_on_it(self):
        mount = Path(self.temp.name) / "mounted"
        root = mount / "bughunter"
        root.mkdir(parents=True)
        artifact_root = root / "artifacts" / "evidence"
        config = replace(self.config, paths=replace(self.config.paths, root=root),
                         store=replace(self.config.store, artifact_root=artifact_root),
                         resources=ResourceSettings(required_mount=str(mount)))
        with patch("hackbot.resources.os.path.ismount", return_value=True):
            runtime = BugHunterRuntime(config, driver=self.driver, vnc_ready=lambda: True)
        self.assertTrue(runtime.store.db_path.is_file())
        self.assertTrue(artifact_root.is_dir())

    def test_startup_rejects_artifact_symlink_escaping_required_mount(self):
        mount = Path(self.temp.name) / "mounted"
        root = mount / "bughunter"
        root.mkdir(parents=True)
        outside = Path(self.temp.name) / "outside-artifacts"
        outside.mkdir()
        (root / "linked").symlink_to(outside, target_is_directory=True)
        config = replace(self.config, paths=replace(self.config.paths, root=root),
                         store=replace(self.config.store, artifact_root=root / "linked" / "evidence"),
                         resources=ResourceSettings(required_mount=str(mount)))
        with patch("hackbot.resources.os.path.ismount", return_value=True):
            with self.assertRaisesRegex(ResourceError, "ARTIFACT_STORAGE_OUTSIDE_REQUIRED_MOUNT"):
                BugHunterRuntime(config, driver=self.driver, vnc_ready=lambda: True)
        self.assertFalse((root / "state" / "bughunter.sqlite3").exists())

    def test_recon_probe_is_cached_and_failure_degrades_without_crashing(self):
        repo = Mock()
        repo.probe.return_value = True
        self.runtime.recon = repo
        self.assertEqual(self.get("/v1/operations")["recon"], "OK")
        self.assertEqual(self.get("/v1/health")["checks"]["recon"], "OK")
        repo.probe.assert_called_once_with()

        repo.probe.side_effect = RuntimeError("password=DO_NOT_LOG")
        self.runtime._recon_probe_until = 0.0
        operations = self.get("/v1/operations")
        self.assertEqual(operations["recon"], "DISCONNECTED")
        self.assertIn("RECON_DISCONNECTED", operations["warnings"])
        health = self.get("/v1/health")
        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["checks"]["recon"], "DISCONNECTED")
        self.assertNotIn("DO_NOT_LOG", json.dumps(operations) + json.dumps(health))

    def test_readiness_distinguishes_essential_and_optional_failures(self):
        self.assertEqual(self.get("/v1/ready")["state"], "READY")
        repo = Mock()
        repo.probe.return_value = False
        self.runtime.recon = repo
        degraded = self.get("/v1/ready")
        self.assertEqual(degraded["state"], "DEGRADED")
        self.assertEqual(degraded["checks"]["recon"], "FAILED")

        original_root = self.runtime.store.artifacts.root
        self.runtime.store.artifacts.root = original_root / "missing"
        try:
            response = self.client.get("/v1/ready")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.get_json()["state"], "NOT_READY")
        finally:
            self.runtime.store.artifacts.root = original_root

    def test_liveness_stays_responsive_when_local_store_fails(self):
        with patch.object(self.runtime.store, "_connection", side_effect=OSError("secret")):
            response = self.client.get("/v1/health")
            self.assertEqual(response.status_code, 200)
            result = response.get_json()
            self.assertEqual(result["status"], "degraded")
            self.assertEqual(result["checks"]["bughunter_store"], "failed")
            self.assertNotIn("secret", response.get_data(as_text=True))

    def test_operations_maintenance_is_explicit_and_local_only(self):
        self.assertEqual(self.get("/v1/operations/maintenance")["status"], "IDLE")
        missing_confirmation = self.client.post("/v1/operations/maintenance",
                                                json={"action": "RETENTION_RUN"})
        self.assertEqual(missing_confirmation.status_code, 400)
        self.assertEqual(missing_confirmation.get_json()["reason_code"], "CONFIRMATION_REQUIRED")
        unsafe_id = self.client.post("/v1/operations/maintenance",
                                     json={"action": "BACKUP_VERIFY", "backup_id": "../state"})
        self.assertEqual(unsafe_id.status_code, 400)
        started = self.client.post("/v1/operations/maintenance",
                                   json={"action": "RETENTION_PLAN"})
        self.assertEqual(started.status_code, 202)
        self.runtime.maintenance.wait_for_test()
        finished = self.get("/v1/operations/maintenance")
        self.assertEqual(finished["status"], "COMPLETED")
        self.assertEqual(finished["result"]["candidate_count"], 0)
        denied = self.client.post("/v1/operations/maintenance",
                                  json={"action": "RETENTION_RUN", "confirmed": True,
                                        "review_id": finished["id"]})
        self.assertEqual(denied.status_code, 400)
        self.assertEqual(denied.get_json()["reason_code"], "REVIEW_REQUIRED")

    def test_operations_profile_retention_uses_terminal_anonymous_fixture_only(self):
        self.runtime.registry.register_target(self.runtime.package("example"))
        session = self.runtime.browser.create(self.target)
        self.runtime.browser.start(session.id)
        self.runtime.browser.stop(session.id)
        path = self.runtime.browser.profiles.path(session)
        (path / "cache.bin").write_bytes(b"ephemeral")
        old = (datetime.now(timezone.utc) - timedelta(hours=49)).isoformat()
        with self.runtime.store._connection() as db:
            db.execute("UPDATE browser_sessions SET created_at=?,updated_at=? WHERE session_id=?",
                       (old, old, session.id))
        self.runtime.maintenance.profiles.process_safe = lambda: True
        started = self.client.post("/v1/operations/maintenance", json={"action": "PROFILE_PLAN"})
        self.assertEqual(started.status_code, 202)
        self.runtime.maintenance.wait_for_test()
        planned = self.get("/v1/operations/maintenance")
        self.assertEqual(planned["result"]["candidate_count"], 1)
        self.assertEqual(self.client.post("/v1/operations/maintenance",
                                          json={"action": "PROFILE_RUN"}).status_code, 400)
        self.assertTrue(path.exists())
        started = self.client.post("/v1/operations/maintenance",
                                   json={"action": "PROFILE_RUN", "confirmed": True,
                                         "review_id": planned["id"]})
        self.assertEqual(started.status_code, 202)
        self.runtime.maintenance.wait_for_test()
        self.assertEqual(self.get("/v1/operations/maintenance")["result"]["removed"], 1)
        self.assertFalse(path.exists())

    def test_operations_disabled_profile_retention_is_identity_bound(self):
        from hackbot.auth import AuthMechanism
        from hackbot.identity import IdentityStatus

        self.runtime.registry.register_target(self.runtime.package("example"))
        identity = self.runtime.registry.register_identity(
            self.target, "disabled_profile_fixture", status=IdentityStatus.ACTIVE)
        self.runtime.auth.prepare(self.target, identity.id,
                                  mechanism=AuthMechanism.MANUAL_LOGIN)
        session = self.runtime.browser.create(self.target, identity.id)
        self.runtime.browser.start(session.id)
        self.runtime.browser.stop(session.id)
        path = self.runtime.browser.profiles.path(session)
        (path / "cache.bin").write_bytes(b"sensitive session fixture")
        self.runtime.registry.disable_identity(identity.id)
        old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        with self.runtime.store._connection() as db:
            db.execute("UPDATE registry_identities SET created_at=?,updated_at=? WHERE identity_id=?",
                       (old, old, identity.id))
            db.execute("UPDATE browser_sessions SET created_at=?,updated_at=? WHERE session_id=?",
                       (old, old, session.id))
        self.runtime.maintenance.profiles.process_safe = lambda: True
        action = {"action": "DISABLED_PROFILE_PLAN", "target_id": self.target,
                  "identity_id": identity.id}
        self.assertEqual(self.client.post("/v1/operations/maintenance", json=action).status_code, 202)
        self.runtime.maintenance.wait_for_test()
        reviewed = self.get("/v1/operations/maintenance")
        self.assertEqual(reviewed["result"]["candidate_count"], 1)
        action = {"action": "DISABLED_PROFILE_RUN", "target_id": self.target,
                  "identity_id": identity.id, "review_id": reviewed["id"], "confirmed": True}
        self.assertEqual(self.client.post("/v1/operations/maintenance", json=action).status_code, 202)
        self.runtime.maintenance.wait_for_test()
        self.assertEqual(self.get("/v1/operations/maintenance")["result"]["removed"], 1)
        self.assertFalse(path.exists())

    def test_operations_named_profile_retention_requires_exact_review(self):
        from hackbot.auth import AuthMechanism
        from hackbot.identity import IdentityStatus

        self.runtime.registry.register_target(self.runtime.package("example"))
        identity = self.runtime.registry.register_identity(
            self.target, "named_profile_fixture", status=IdentityStatus.ACTIVE)
        self.runtime.auth.prepare(self.target, identity.id,
                                  mechanism=AuthMechanism.MANUAL_LOGIN)
        session = self.runtime.browser.create(self.target, identity.id)
        self.runtime.browser.start(session.id)
        self.runtime.browser.stop(session.id)
        path = self.runtime.browser.profiles.path(session)
        (path / "cache.bin").write_bytes(b"owned session fixture")
        old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
        with self.runtime.store._connection() as db:
            db.execute("UPDATE browser_sessions SET created_at=?,updated_at=? WHERE session_id=?",
                       (old, old, session.id))
        self.runtime.maintenance.profiles.process_safe = lambda: True
        action = {"action": "NAMED_PROFILE_PLAN", "target_id": self.target,
                  "identity_id": identity.id, "session_id": session.id}
        self.assertEqual(self.client.post("/v1/operations/maintenance", json=action).status_code, 202)
        self.runtime.maintenance.wait_for_test()
        reviewed = self.get("/v1/operations/maintenance")
        self.assertEqual(reviewed["result"]["candidate_count"], 1)
        bad = {**action, "action": "NAMED_PROFILE_RUN", "review_id": reviewed["id"],
               "confirmed": True, "session_id": "BSESSION-" + "0" * 32}
        self.assertEqual(self.client.post("/v1/operations/maintenance", json=bad).status_code, 400)
        self.assertTrue(path.exists())
        action.update({"action": "NAMED_PROFILE_RUN", "review_id": reviewed["id"],
                       "confirmed": True})
        self.assertEqual(self.client.post("/v1/operations/maintenance", json=action).status_code, 202)
        self.runtime.maintenance.wait_for_test()
        self.assertEqual(self.get("/v1/operations/maintenance")["result"]["removed"], 1)
        self.assertFalse(path.exists())

    def test_phase29_private_report_and_notification_routes(self):
        self.assertEqual(self.get("/v1/reports?target=example")["items"], [])
        self.assertEqual(self.get("/v1/notifications?target=example")["items"], [])
        status = self.get("/v1/notifications/status?target=example")
        self.assertFalse(status["discord_configured"])
        self.assertFalse(status["smtp_configured"])
        self.assertEqual(self.client.post("/v1/findings/FINDING-" + "a" * 32 + "/report",
                                          json={"target": "example"}).status_code, 404)
        self.assertEqual(self.client.get("/v1/reports/REPORT-" + "a" * 32 +
                                         "/download?target=example").status_code, 404)
        test = self.client.post("/v1/notifications/test", json={"target": "example"})
        self.assertEqual(test.status_code, 200)
        self.assertEqual(test.get_json()["label"], "TEST")
        events = self.get("/v1/notifications?target=example")["items"]
        self.assertEqual([item["event_type"] for item in events], ["TEST"])

    def test_phase29_planner_login_alert_is_deduped(self):
        package = self.runtime.package("example")
        self.runtime.registry.register_target(package)
        run = self.runtime.planner_store.create(
            package, PlannerMode.PLAN_ONLY, PlannerLimits(), policy_version(package))
        waiting = self.runtime.planner_store.transition(
            self.target, run.id, PlannerStatus.WAITING_LOGIN, "LOGIN_REQUIRED")
        observation = {"run": waiting.to_dict(), "task": {"reason_code": "LOGIN_REQUIRED"}}
        self.runtime.record_planner_notification(self.target, run.id, observation)
        self.runtime.record_planner_notification(self.target, run.id, observation)
        events = self.runtime.notification_store.list_events(self.target)["items"]
        self.assertEqual([item["event_type"] for item in events], ["AUTH_REQUIRES_LOGIN"])
        self.assertEqual(self.runtime.notification_store.stats(self.target)["deduped"], 1)

    def test_phase29_failed_notifier_degrades_health_without_service_failure(self):
        event = self.runtime.notification_store.enqueue(
            target_id=self.target, event_type=NotificationType.TEST,
            source_kind="TEST", source_id="TEST-" + uuid.uuid4().hex,
            priority=NotificationPriority.LOW)
        self.runtime.notification_store.prepare_deliveries(event.id, ("fixture",))
        claimed = self.runtime.notification_store.claim("fixture")
        self.assertIsNotNone(claimed)
        self.runtime.notification_store.finish(claimed[0].id, DeliveryStatus.FAILED,
                                               error_code="FIXTURE_FAILURE")
        health = self.get("/v1/health")
        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["checks"]["notifier"], "degraded")
        self.assertEqual(health["checks"]["bughunter_store"], "ok")

    def test_behaviour_read_api_and_expectation_validation(self):
        base = "/v1/targets/example/behaviour"
        self.assertIsNone(self.get(base)["profile"])
        self.assertEqual(self.get(base + "/coverage")["coverage"]["state"], "NONE")
        for suffix in ("/features", "/workflows", "/gaps"):
            self.assertEqual(self.get(base + suffix)["items"], [])
        self.assertEqual(self.get(base + "/matrix")["role_feature"], [])
        self.assertEqual(self.client.post(base + "/expectations", json={
            "feature": "projects", "expected_access": "ALLOW", "provenance": "RESEARCHER"}).status_code, 201)
        self.assertEqual(len(self.runtime.behaviour_store.expectations(self.target)), 1)
        self.assertEqual(self.client.post(base + "/expectations", json={
            "feature": "projects", "expected_access": "SUPERADMIN"}).status_code, 400)
        self.assertEqual(self.client.post(base, json={"limits": {"max_traffic_records": 501}}).status_code, 400)

    def test_behaviour_start_and_cancel_run(self):
        base = "/v1/targets/example/behaviour"
        started, release = Event(), Event()
        actual_run = self.runtime.behaviour.run

        def delayed_run(*args, **kwargs):
            started.set()
            release.wait(5)
            return actual_run(*args, **kwargs)

        try:
            with patch.object(self.runtime.hypotheses, "latest_profile", return_value=None), \
                    patch("hackbot.service.AttackSurfaceProfiler.profile", return_value=None), \
                    patch.object(self.runtime.behaviour, "run", side_effect=delayed_run):
                response = self.client.post(base, json={"limits": {"max_traffic_records": 5}})
                self.assertEqual(response.status_code, 202, response.get_data(as_text=True))
                run_id = response.get_json()["run_id"]
                self.assertTrue(started.wait(3))
                self.assertEqual(self.client.post(f"{base}/runs/{run_id}/cancel", json={}).status_code, 200)
                release.set()
                thread = self.runtime._behaviour_threads.get(run_id)
                if thread:
                    thread.join(5)
                self.assertEqual(self.get(f"{base}/runs/{run_id}")["status"], "CANCELLED")
        finally:
            release.set()

    def test_anonymous_session_registers_tracked_package_without_accounts(self):
        self.assertIsNone(self.runtime.registry.target_id_for_package("example"))
        invalid = self.client.post("/v1/browser/sessions", json={
            "target": "example", "anonymous": True, "capture_provider": "UNKNOWN"})
        self.assertEqual(invalid.status_code, 400)
        self.assertIsNone(self.runtime.registry.target_id_for_package("example"))
        created = self.client.post("/v1/browser/sessions", json={
            "target": "example", "anonymous": True, "capture_provider": "DIRECT"})
        self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
        self.assertEqual(self.runtime.registry.target_id_for_package("example"), self.target)
        self.assertEqual(self.client.post(
            f"/v1/browser/sessions/{created.get_json()['id']}/stop?target=example",
            json={}).status_code, 200)

    def test_delete_session_retains_history_and_releases_capacity(self):
        self.config = replace(self.config, resources=replace(
            self.config.resources, max_browser_sessions=1))
        self.runtime = BugHunterRuntime(self.config, driver=self.driver, vnc_ready=lambda: True)
        self.app = create_app(runtime=self.runtime)
        self.client = self.app.test_client()
        created = self.client.post("/v1/browser/sessions", json={
            "target": "example", "anonymous": True, "capture_provider": "DIRECT"})
        self.assertEqual(created.status_code, 201)
        full = self.client.post("/v1/browser/sessions", json={
            "target": "example", "anonymous": True, "capture_provider": "DIRECT"})
        self.assertEqual(full.status_code, 503)
        self.assertEqual(full.get_json()["reason_code"], "CONCURRENCY_LIMIT")
        session_id = created.get_json()["id"]
        profile = self.runtime.browser.profiles.path(self.runtime.browser.get(session_id))
        self.assertTrue(profile.exists())
        self.assertEqual(self.client.delete(f"/v1/browser/sessions/{session_id}?target=wrong").status_code, 404)
        self.assertEqual(self.client.post(
            f"/v1/browser/sessions/{session_id}/start?target=example", json={}).status_code, 200)
        self.assertTrue(self.driver.is_running(session_id))
        now = datetime.now(timezone.utc)
        exchange = self.runtime.traffic.store_exchange(
            self.runtime.package("example"), CapturePacket(
                CapturedRequest("GET", "https://app.example.test/synthetic", (), None, now),
                CapturedResponse(200, (("Content-Type", "text/plain"),), b"fixture", now),
                browser_session_id=session_id),
            source=TrafficSource.BROWSER, capture_provider="LOCAL_FIXTURE",
            browser_manager=self.runtime.browser)
        deleted = self.client.delete(f"/v1/browser/sessions/{session_id}?target=example")
        self.assertEqual(deleted.status_code, 200, deleted.get_data(as_text=True))
        self.assertFalse(self.driver.is_running(session_id))
        self.assertTrue(profile.exists())
        self.assertIsNone(self.runtime.browser.get(session_id))
        self.assertEqual(self.get(f"/v1/traffic/{exchange.id}?target=example")["attribution"]["browser_session_id"],
                         session_id)
        self.assertNotIn(session_id, [item["id"] for item in self.get(
            "/v1/browser/sessions?target=example")["items"]])
        self.assertEqual(self.runtime.target_cleanup_dependencies(self.target)["browser_sessions"], 0)
        self.assertEqual(self.client.post("/v1/browser/sessions", json={
            "target": "example", "anonymous": True, "capture_provider": "DIRECT"}).status_code, 201)
        self.assertEqual(self.client.delete(f"/v1/browser/sessions/{session_id}?target=example").status_code, 404)
        with self.runtime.store._connection() as connection:
            self.assertEqual(connection.execute(
                "SELECT status FROM browser_sessions WHERE session_id=?", (session_id,)).fetchone()[0], "STOPPED")
            self.assertIsNotNone(connection.execute(
                "SELECT 1 FROM browser_session_events WHERE session_id=? AND event_type='browser_deleted'",
                (session_id,)).fetchone())

    def test_delete_reauth_required_stale_session(self):
        created = self.client.post("/v1/browser/sessions", json={
            "target": "example", "anonymous": True, "capture_provider": "DIRECT"})
        session_id = created.get_json()["id"]
        self.assertEqual(self.client.post(f"/v1/browser/sessions/{session_id}/start?target=example",
                                          json={}).status_code, 200)
        self.driver.running.remove(session_id)
        reconciled = self.client.post(f"/v1/browser/sessions/{session_id}/reconcile?target=example",
                                      json={})
        self.assertEqual(reconciled.get_json()["status"], "REAUTH_REQUIRED")
        self.assertEqual(self.client.delete(f"/v1/browser/sessions/{session_id}?target=example").status_code, 200)
        with self.runtime.store._connection() as db:
            self.assertEqual(db.execute("SELECT status FROM browser_sessions WHERE session_id=?",
                                        (session_id,)).fetchone()[0], "STOPPED")

    def test_target_runtime_cleanup_then_typed_delete_keeps_history(self):
        created = self.client.post("/v1/browser/sessions", json={
            "target": "example", "anonymous": True, "capture_provider": "DIRECT"})
        self.assertEqual(created.status_code, 201)
        session_id = created.get_json()["id"]
        preview = self.get("/v1/targets/example/delete-preview")
        self.assertEqual(preview["dependencies"]["browser_sessions"], 1)
        self.assertFalse(preview["can_delete"])
        self.assertEqual(self.client.delete("/v1/targets/example",
                                            json={"confirm_package_id": "wrong"}).status_code, 400)
        self.assertEqual(self.client.delete("/v1/targets/example",
                                            json={"confirm_package_id": "example"}).status_code, 409)
        with patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target traffic")):
            cleaned = self.client.post("/v1/targets/example/clean-runtime", json={})
            self.assertEqual(cleaned.status_code, 200, cleaned.get_data(as_text=True))
            self.assertEqual(cleaned.get_json()["removed_sessions"], [session_id])
            self.assertEqual(self.get("/v1/targets/example/delete-preview")["can_delete"], True)
            deleted = self.client.delete("/v1/targets/example",
                                         json={"confirm_package_id": "example"})
        self.assertEqual(deleted.status_code, 200, deleted.get_data(as_text=True))
        self.assertFalse((self.config.targets.root / "example").exists())
        self.assertEqual(self.client.get("/v1/targets/example").status_code, 404)
        self.assertEqual(self.runtime.registry.target_id_for_package("example"), self.target)
        self.assertEqual(self.get("/v1/target-tombstones")["items"][0]["label"], "example (deleted)")
        self.assertEqual(self.client.post("/v1/targets", json={"id": "example"}).status_code, 409)
        with self.runtime.store._connection() as db:
            self.assertIsNotNone(db.execute("SELECT 1 FROM browser_sessions WHERE session_id=?",
                                            (session_id,)).fetchone())
            self.assertIsNotNone(db.execute("SELECT 1 FROM service_events WHERE event_type='target_deleted' "
                                            "AND target_id=?", (self.target,)).fetchone())

    def test_target_delete_rejects_paths_and_symlinks(self):
        with self.assertRaises(TargetSetupError):
            self.runtime.target_operator.delete("../example")
        with self.assertRaises(TargetSetupError):
            self.runtime.target_operator.delete("/tmp/example")
        external = Path(self.temp.name) / "external"
        external.mkdir()
        (self.config.targets.root / "linked").symlink_to(external, target_is_directory=True)
        with self.assertRaises(TargetSetupError):
            self.runtime.target_operator.delete("linked")
        (self.config.targets.root / "example" / "linked-file").symlink_to(external)
        with self.assertRaises(TargetSetupError):
            self.runtime.target_operator.delete("example")
        self.assertTrue((self.config.targets.root / "example" / "target.yaml").is_file())

    def test_active_campaign_blocks_session_cleanup_and_target_delete(self):
        package = self.runtime.package("example")
        self.runtime.registry.register_target(package)
        created = self.client.post("/v1/browser/sessions", json={
            "target": "example", "anonymous": True, "capture_provider": "DIRECT"})
        session_id = created.get_json()["id"]
        campaign = self.runtime.campaign.store.create(
            package, PlannerMode.PLAN_ONLY, CampaignLimits(), policy_version(package), "operator")
        self.assertEqual(self.get("/v1/targets/example/delete-preview")["dependencies"][
            "active_campaigns"], 1)
        self.assertEqual(self.client.delete(f"/v1/browser/sessions/{session_id}?target=example").status_code, 409)
        self.assertEqual(self.client.post("/v1/targets/example/clean-runtime", json={}).status_code, 409)
        self.assertEqual(self.client.delete("/v1/targets/example",
                                            json={"confirm_package_id": "example"}).status_code, 409)
        self.assertTrue((self.config.targets.root / "example" / "target.yaml").is_file())

    def test_account_remove_blocks_session_and_preserves_identity(self):
        self.runtime.registry.register_target(self.runtime.package("example"))
        self.client.post("/v1/targets/example/import-identities", json={})
        accounts = self.get("/v1/targets/example/accounts")["items"]
        alias = accounts[0]["alias"]
        identity = self.runtime.registry.get_identity(self.target, alias)
        self.runtime.auth.prepare(self.target, identity.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        created = self.client.post("/v1/browser/sessions", json={
            "target": "example", "identity_id": identity.id, "capture_provider": "DIRECT"})
        self.assertEqual(created.status_code, 201)
        route = f"/v1/targets/example/accounts/{alias}"
        self.assertEqual(self.client.delete(route).status_code, 409)
        self.assertEqual(self.client.delete(
            f"/v1/browser/sessions/{created.get_json()['id']}?target=example").status_code, 200)
        removed = self.client.delete(route)
        self.assertEqual(removed.status_code, 200, removed.get_data(as_text=True))
        self.assertNotIn(alias, [item["alias"] for item in self.get(
            "/v1/targets/example/accounts")["items"]])
        self.assertEqual(self.runtime.registry.get_identity(self.target, alias).status.value, "DISABLED")

    def test_burp_session_requires_bridge_and_listener_before_browser_start(self):
        root = Path(self.temp.name)
        jar = root / "burpsuite_desktop_v2026.9.2.jar"
        jar.write_bytes(b"fixture")
        with socket.socket() as bridge_socket, socket.socket() as listener_socket:
            bridge_socket.bind(("127.0.0.1", 0))
            listener_socket.bind(("127.0.0.1", 0))
            bridge_port = bridge_socket.getsockname()[1]
            listener_port = listener_socket.getsockname()[1]
        settings = BurpSettings(True, root / "burp-projects", installation_jar=jar,
                                listener_start=listener_port, listener_end=listener_port,
                                bridge_port=bridge_port, bridge_secret_ref="ref:burp_bridge")
        secrets = SecretSettings(bindings=(SecretBindingConfig(
            "ref:burp_bridge", "env:HACKBOT_SECRET_BURP_BRIDGE", "API_TOKEN"),))
        config = replace(self.config, burp=settings, secrets=secrets)
        token = "fixture-bridge-token-with-at-least-32-characters"
        with patch.dict(os.environ, {"HACKBOT_SECRET_BURP_BRIDGE": token}):
            runtime = BugHunterRuntime(config, driver=FakeDriver(), vnc_ready=lambda: True)
            self.addCleanup(runtime.close_burp_bridge)
            self.assertIsNone(runtime.registry.target_id_for_package("example"))
            client = create_app(runtime=runtime).test_client()
            response = client.post("/v1/browser/sessions", json={
                "target": "example", "anonymous": True, "capture_provider": "BURP"})
            self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
            self.assertEqual(runtime.registry.target_id_for_package("example"),
                             runtime.package("example").target.id)
            session = response.get_json()
            self.assertEqual(session["capture_provider"], "BURP")
            self.assertEqual(session["capture_listener"], f"127.0.0.1:{listener_port}")
            with closing(http.client.HTTPConnection("127.0.0.1", bridge_port, timeout=2)) as connection:
                connection.request("GET", "/v1/health")
                self.assertEqual(connection.getresponse().status, 401)
            with closing(http.client.HTTPConnection("127.0.0.1", bridge_port, timeout=2)) as connection:
                connection.request("GET", "/v1/health", headers={"X-Hackbot-Bridge-Token": token})
                self.assertEqual(connection.getresponse().status, 200)
            start_path = f"/v1/browser/sessions/{session['id']}/start?target=example"
            self.assertEqual(client.post(start_path, json={}).status_code, 400)
            self.assertFalse(runtime.driver.is_running(session["id"]))
            runtime.burp.heartbeat(runtime.package("example").target.id, "1.0")
            with patch.object(runtime.burp, "listener_reachable", return_value=True):
                started = client.post(start_path, json={})
            self.assertEqual(started.status_code, 200, started.get_data(as_text=True))
            self.assertTrue(runtime.driver.is_running(session["id"]))
            self.assertEqual(started.get_json()["capture_provider"], "BURP")
            stopped = client.post(f"/v1/browser/sessions/{session['id']}/stop?target=example", json={})
            self.assertEqual(stopped.status_code, 200, stopped.get_data(as_text=True))
            self.assertEqual(stopped.get_json()["status"], "STOPPED")
            self.assertEqual(runtime.burp.binding_for_session(session["id"]).state, "RELEASED")
            self.assertFalse(runtime.burp.bridge_connected(runtime.package("example").target.id))
            another = client.post("/v1/browser/sessions", json={
                "target": "example", "anonymous": True, "capture_provider": "BURP"})
            self.assertEqual(another.status_code, 201, another.get_data(as_text=True))
            self.assertEqual(another.get_json()["capture_listener"], f"127.0.0.1:{listener_port}")
            self.assertEqual(client.get("/v1/targets/example/delete-preview").get_json()[
                "dependencies"]["active_capture_bindings"], 1)
            self.assertEqual(client.delete(
                f"/v1/browser/sessions/{another.get_json()['id']}?target=example", json={}
            ).status_code, 200)
            self.assertEqual(runtime.burp.binding_for_session(another.get_json()["id"]).state,
                             "RELEASED")
            self.assertEqual(client.get("/v1/targets/example/delete-preview").get_json()[
                "dependencies"]["active_capture_bindings"], 0)
            self.assertIsNone(runtime.browser.get(another.get_json()["id"]))
            self.assertEqual(client.delete(
                f"/v1/browser/sessions/{session['id']}?target=example", json={}
            ).status_code, 200)
            orphan = client.post("/v1/browser/sessions", json={
                "target": "example", "anonymous": True, "capture_provider": "BURP"})
            self.assertEqual(orphan.status_code, 201)
            orphan_id = orphan.get_json()["id"]
            runtime.browser.retire(orphan_id)
            preview = client.get("/v1/targets/example/delete-preview").get_json()
            self.assertEqual(preview["dependencies"]["browser_sessions"], 0)
            self.assertEqual(preview["dependencies"]["active_capture_bindings"], 1)
            self.assertFalse(preview["can_delete"])
            self.assertEqual(client.delete("/v1/targets/example",
                                           json={"confirm_package_id": "example"}).status_code, 409)
            cleanup = client.post("/v1/targets/example/clean-runtime", json={})
            self.assertEqual(cleanup.status_code, 200, cleanup.get_data(as_text=True))
            self.assertEqual(cleanup.get_json()["released_bindings"], [orphan_id])
            self.assertEqual(runtime.burp.binding_for_session(orphan_id).state, "RELEASED")
            restarted = BugHunterRuntime(config, driver=FakeDriver(), vnc_ready=lambda: True)
            self.addCleanup(restarted.close_burp_bridge)
            self.assertEqual(restarted.burp.binding_for_session(session["id"]).state, "RELEASED")
            self.assertFalse(restarted.burp.bridge_connected(restarted.package("example").target.id))

    def test_exposure_api_is_target_scoped_and_redacted(self):
        fixture_secret = "FixtureOnlySecret-a9Yh2Rk8bN4qP6vJ"
        self.runtime.registry.register_target(self.runtime.package("example"))
        body = f'const client_secret = "{fixture_secret}";'.encode()
        asset = self.runtime.domxss_store.record_artifact(
            target_id=self.target, asset_url="https://app.example.test/static/exposure.js",
            body=body, recon_asset_id=3,
            recon_sha256=hashlib.sha256(body).hexdigest(), source="FIXTURE")
        self.runtime.exposure.analyze_js(self.runtime.package("example"), asset.artifact_id,
                                         fixture_url="https://app.example.test/static/exposure.js")
        listed = self.get("/v1/exposure/example/candidates")
        self.assertEqual(len(listed["items"]), 1)
        candidate_id = listed["items"][0]["candidate_id"]
        artifacts = self.get("/v1/exposure/example/artifacts")
        self.assertEqual(artifacts["items"][0]["artifact_id"], asset.artifact_id)
        self.assertFalse(artifacts["items"][0]["has_source_map"])
        self.assertNotIn("asset_url", json.dumps(artifacts))
        self.assertEqual(self.get("/v1/exposure/example/captures")["items"], [])
        self.assertEqual(self.get("/v1/exposure/example/field-exchanges")["items"], [])
        self.assertEqual(self.client.post("/v1/exposure/example/analyze-response", json={
            "url": "http://127.0.0.1/internal"}).status_code, 400)
        self.assertEqual(self.client.post("/v1/exposure/example/analyze-field", json={
            "url": "http://127.0.0.1/internal"}).status_code, 400)
        detail = self.get(f"/v1/exposure/example/candidates/{candidate_id}")
        self.assertEqual(detail["candidate"]["category"], "JS_SECRET")
        self.assertEqual(self.get("/v1/exposure/example/metrics")["candidates"], 1)
        self.assertNotIn(fixture_secret, json.dumps(detail))
        prepared_response = self.client.post(
            f"/v1/exposure/example/candidates/{candidate_id}/prepare", json={})
        self.assertEqual(prepared_response.status_code, 200,
                         prepared_response.get_data(as_text=True))
        prepared = prepared_response.get_json()
        self.assertEqual(prepared["network_requests_sent"], 0)
        self.assertTrue(prepared["plan_id"].startswith("PLAN-"))
        self.assertEqual(self.client.get(f"/v1/exposure/unknown/candidates/{candidate_id}").status_code, 404)
        self.assertEqual(self.client.get("/v1/exposure/example/candidates?limit=1000").status_code, 400)
        self.assertEqual(self.client.post("/v1/exposure/example/analyze", json={
            "kind": "js", "artifact_id": asset.artifact_id,
            "url": "http://127.0.0.1/internal"}).status_code, 400)
        self.assertEqual(self.client.post("/v1/exposure/example/discover", json={
            "source": "traffic"}).get_json()["network_requests_sent"], 0)
        self.assertEqual(self.client.post(
            f"/v1/exposure/example/candidates/{candidate_id}/bind-field",
            json={"host": "internal.example.test"}).status_code, 400)

    def test_synthetic_current_js_credential_has_phase16_phase17_audit_chain(self):
        from hackbot.validation_store import ValidationStatus

        secret = "FixtureOnlySecret-a9Yh2Rk8bN4qP6vJ"
        self.runtime.registry.register_target(self.runtime.package("example"))
        body = (f'const client_secret = "{secret}"; '
                'fetch("/fixture-api", {headers: {Authorization: "Bearer " + client_secret}});').encode()
        before = self.runtime.traffic.stats(self.target)["sample_count"]
        asset = self.runtime.domxss_store.record_artifact(
            target_id=self.target, asset_url="https://app.example.test/static/credential.js",
            body=body, recon_asset_id=4, recon_sha256=hashlib.sha256(body).hexdigest(),
            source="FIXTURE")
        analysis = self.runtime.exposure.analyze_js(
            self.runtime.package("example"), asset.artifact_id,
            fixture_url="https://app.example.test/static/credential.js")
        candidate_id = analysis.candidate_ids[0]
        planned = self.runtime.exposure.prepare_candidate(
            self.runtime.package("example"), candidate_id,
            hypotheses=self.runtime.hypotheses, contexts=self.runtime.skill_context,
            router=self.runtime.skill_router, planner=self.runtime.skill_planner)
        self.assertEqual(planned.plan_status, "READY_FOR_MANUAL_REVIEW")
        run = self.runtime.orchestrator.start(planned.plan_id, "example")
        for _ in range(8):
            if run["run"]["status"] == "COMPLETED":
                break
            run = self.runtime.orchestrator.advance(run["run"]["id"], "example")
        self.assertEqual(run["run"]["status"], "COMPLETED")
        validation, finding = self.runtime.validator.validate_run(run["run"]["id"], self.target)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertEqual(self.runtime.exposure_store.links(self.target, candidate_id)["validation_id"],
                         validation.id)
        self.assertEqual(self.runtime.traffic.stats(self.target)["sample_count"], before)
        self.assertNotIn(secret, json.dumps(finding.to_dict()))
        self.assertNotIn(secret, json.dumps(validation.to_dict()))
        revised = b"/* revised build */ " + body
        next_asset = self.runtime.domxss_store.record_artifact(
            target_id=self.target, asset_url="https://app.example.test/static/credential-v2.js",
            body=revised, recon_asset_id=6,
            recon_sha256=hashlib.sha256(revised).hexdigest(), source="FIXTURE")
        repeated = self.runtime.exposure.analyze_js(
            self.runtime.package("example"), next_asset.artifact_id,
            fixture_url="https://app.example.test/static/credential-v2.js")
        self.assertEqual(repeated.candidate_ids, (candidate_id,))
        self.assertEqual(self.runtime.exposure_store.validation_state(self.target, candidate_id),
                         "UNVALIDATED")
        self.assertIsNone(self.runtime.exposure_store.links(self.target, candidate_id)["plan_id"])
        self.assertEqual(self.runtime.exposure_store.get(self.target, candidate_id).artifact_sha256,
                         next_asset.artifact_sha256)

    def test_source_map_credential_validates_and_public_config_is_rejected(self):
        from hackbot.validation_store import ValidationStatus

        secret = "FixtureOnlySecret-b8Wn3Pq7mR5sT2vL"
        self.runtime.registry.register_target(self.runtime.package("example"))
        js = b"console.log('fixture app')"
        asset = self.runtime.domxss_store.record_artifact(
            target_id=self.target, asset_url="https://app.example.test/static/mapped.js",
            body=js, recon_asset_id=5, recon_sha256=hashlib.sha256(js).hexdigest(),
            source="FIXTURE")
        source = (f'const client_secret = "{secret}"; '
                  'fetch("/fixture-api", {headers: {Authorization: "Bearer " + client_secret}}); '
                  'const NEXT_PUBLIC_API_KEY = "pk_live_PublicClientIdentifier987";')
        self.runtime.domxss_store.record_source_map(
            target_id=self.target, js_artifact_id=asset.artifact_id,
            map_url="https://app.example.test/static/mapped.js.map",
            body=json.dumps({"version": 3, "sources": ["app.ts"],
                             "sourcesContent": [source]}).encode(), source="FIXTURE")
        analyzed = self.runtime.exposure.analyze_source_map(
            self.runtime.package("example"), asset.artifact_id,
            fixture_url="https://app.example.test/static/mapped.js")
        self.assertEqual(analyzed.signals, 2)
        candidates = [self.runtime.exposure_store.get(self.target, ref)
                      for ref in analyzed.candidate_ids]
        public = next(item for item in candidates if item.status.value == "REJECTED_PUBLIC")
        protected = next(item for item in candidates if item.status.value == "FORMAT_VALID")
        with self.assertRaises(ValueError):
            self.runtime.exposure.prepare_candidate(
                self.runtime.package("example"), public.candidate_id,
                hypotheses=self.runtime.hypotheses, contexts=self.runtime.skill_context,
                router=self.runtime.skill_router, planner=self.runtime.skill_planner)
        planned = self.runtime.exposure.prepare_candidate(
            self.runtime.package("example"), protected.candidate_id,
            hypotheses=self.runtime.hypotheses, contexts=self.runtime.skill_context,
            router=self.runtime.skill_router, planner=self.runtime.skill_planner)
        run = self.runtime.orchestrator.start(planned.plan_id, "example")
        for _ in range(8):
            if run["run"]["status"] == "COMPLETED":
                break
            run = self.runtime.orchestrator.advance(run["run"]["id"], "example")
        result, finding = self.runtime.validator.validate_run(run["run"]["id"], self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertNotIn(secret, json.dumps(self.get(
            f"/v1/exposure/example/candidates/{protected.candidate_id}")))

    def test_placeholder_and_stale_artifact_cannot_confirm(self):
        self.runtime.registry.register_target(self.runtime.package("example"))
        body = (b'const password="changeme"; const client_secret="'
                b'FixtureOnlySecret-c6Dn4Yk9qP3sW2tM"; '
                b'fetch("/fixture-api", {headers: {Authorization: client_secret}});')
        asset = self.runtime.domxss_store.record_artifact(
            target_id=self.target, asset_url="https://app.example.test/static/stale.js",
            body=body, recon_asset_id=6, recon_sha256=hashlib.sha256(body).hexdigest(),
            source="FIXTURE")
        analyzed = self.runtime.exposure.analyze_js(
            self.runtime.package("example"), asset.artifact_id,
            fixture_url="https://app.example.test/static/stale.js")
        candidates = [self.runtime.exposure_store.get(self.target, ref)
                      for ref in analyzed.candidate_ids]
        placeholder = next(item for item in candidates if item.status.value == "REJECTED_PLACEHOLDER")
        protected = next(item for item in candidates if item.status.value == "FORMAT_VALID")
        with self.assertRaises(ValueError):
            self.runtime.exposure.prepare_candidate(
                self.runtime.package("example"), placeholder.candidate_id,
                hypotheses=self.runtime.hypotheses, contexts=self.runtime.skill_context,
                router=self.runtime.skill_router, planner=self.runtime.skill_planner)
        planned = self.runtime.exposure.prepare_candidate(
            self.runtime.package("example"), protected.candidate_id,
            hypotheses=self.runtime.hypotheses, contexts=self.runtime.skill_context,
            router=self.runtime.skill_router, planner=self.runtime.skill_planner)
        self.runtime.exposure_store.mark_artifact_stale(self.target, asset.artifact_id)
        from hackbot.orchestrator import PlanRunError
        with self.assertRaises(PlanRunError):
            self.runtime.orchestrator.start(planned.plan_id, "example")
        self.assertEqual(self.runtime.exposure_store.validation_state(
            self.target, protected.candidate_id), "UNVALIDATED")

    def test_object_api_is_target_scoped_and_has_no_raw_request_surface(self):
        self.assertEqual(self.get("/v1/objects?target=example")["items"], [])
        self.assertEqual(self.get("/v1/objects/recipes?target=example")["items"], [])
        self.assertEqual(self.client.get("/v1/objects?target=not-here").status_code, 404)
        self.assertEqual(self.client.get("/v1/objects/TESTOBJ-" + "a" * 32 +
                                         "?target=example").status_code, 404)
        self.assertEqual(self.client.post("/v1/objects/TESTOBJ-" + "a" * 32 +
                                          "/cleanup", json={"target": "example",
                                                            "session_id": "BSESSION-" + "a" * 32}).status_code, 404)
        before = self.get("/v1/traffic/stats?target=example")
        response = self.client.post("/v1/objects", json={"target": "example", "recipe_id": "unknown",
                                                     "identity_id": "IDENTITY-" + "a" * 32,
                                                     "tenant_id": "TENANT-" + "a" * 32,
                                                     "session_id": "BSESSION-" + "a" * 32,
                                                     "purpose": "Fixture"})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()["outcome"], "MISSING_CREATION_RECIPE")
        self.assertEqual(self.get("/v1/traffic/stats?target=example"), before)
        self.assertEqual(self.get("/v1/health")["checks"]["object_factory"], "ready")
        self.assertEqual(self.client.post("/v1/objects/TESTOBJ-" + "a" * 32 +
                                          "/mutate", json={"field": "name", "value": "unsafe"}).status_code,
                         404)

    def test_domxss_api_is_target_scoped_bounded_and_has_no_payload_surface(self):
        self.runtime.registry.register_target(self.runtime.package("example"))
        view = self.client.get("/domxss")
        self.assertEqual(view.status_code, 200)
        self.assertIn("frame-ancestors 'none'", view.headers["Content-Security-Policy"])
        self.assertIn(b'content=""', view.data)
        view.close()
        asset = self.client.get("/domxss/assets/domxss.js")
        self.assertEqual(asset.status_code, 200)
        asset.close()
        self.assertEqual(self.client.get("/domxss/assets/unknown.js").status_code, 404)
        with patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target traffic")):
            self.assertEqual(self.get("/v1/domxss/example/candidates")["items"], [])
            self.assertEqual(self.get("/v1/domxss/example/metrics")["browser_actions"], 0)
            self.assertEqual(self.client.get("/v1/domxss/example/inventory").status_code, 503)
            self.assertEqual(self.client.get("/v1/domxss/not-here/candidates").status_code, 404)
            self.assertEqual(self.client.get("/v1/domxss/example/candidates?limit=999").status_code, 400)
            self.assertEqual(self.client.get("/v1/domxss/example/candidates/DOM-" + "a" * 32).status_code,
                             404)
            self.assertEqual(self.client.post("/v1/domxss/example/analyze",
                                              json={"recon_asset_id": 1}).status_code, 503)
            self.assertEqual(self.client.post("/v1/domxss/example/analyze",
                                              json={"javascript": "alert(1)"}).status_code, 400)
            self.assertEqual(self.client.post("/v1/domxss/example/candidates/DOM-" + "a" * 32 +
                                              "/prepare", json={}).status_code, 503)

    def test_postmessage_api_is_target_scoped_bounded_and_has_no_send_surface(self):
        self.runtime.registry.register_target(self.runtime.package("example"))
        candidate = "MSG-" + "a" * 32
        with patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target traffic")):
            self.assertEqual(self.get("/v1/postmessage/example/candidates")["items"], [])
            metrics = self.get("/v1/postmessage/example/metrics")
            self.assertEqual(metrics["runtime_tests"], 0)
            self.assertEqual(metrics["messages_sent"], 0)
            self.assertEqual(self.client.get("/v1/postmessage/example/inventory").status_code, 503)
            self.assertEqual(self.client.get("/v1/postmessage/not-here/candidates").status_code, 404)
            self.assertEqual(self.client.get("/v1/postmessage/example/candidates?limit=999").status_code, 400)
            self.assertEqual(self.client.get("/v1/postmessage/example/candidates/" + candidate).status_code, 404)
            self.assertEqual(self.client.post("/v1/postmessage/example/analyze",
                                              json={"recon_asset_id": 1}).status_code, 503)
            self.assertEqual(self.client.post("/v1/postmessage/example/analyze",
                                              json={"message": {"type": "ACTIVATE"}}).status_code, 400)
            self.assertEqual(self.client.post("/v1/postmessage/example/candidates/" + candidate +
                                              "/prepare", json={}).status_code, 503)
            self.assertEqual(self.client.post("/v1/postmessage/example/send",
                                              json={"message": "ACTIVATE"}).status_code, 404)

    def test_postmessage_candidate_survives_service_reinitialization(self):
        self.runtime.registry.register_target(self.runtime.package("example"))
        body = b"""window.addEventListener('message', event => {
          if (event.data.type !== 'ACTIVATE') return;
          const port = event.ports[0];
          if (port) port.onmessage = packet => {
            if (packet.data.method === 'readSynthetic')
              port.postMessage({type:'RESULT', value:syntheticCanary});
          };
        });"""
        asset = self.runtime.domxss_store.record_artifact(
            target_id=self.target, asset_url="https://api.example.test/bridge.js",
            body=body, recon_asset_id=1, recon_sha256=hashlib.sha256(body).hexdigest(),
            source="FIXTURE")
        _, analysis = self.runtime.postmessage_store.analyze_asset(
            self.target, asset.artifact_id, PostMessageStaticAnalyzer())
        candidate_id = analysis.candidates[0].candidate_id

        restarted = BugHunterRuntime(self.config, driver=FakeDriver(), vnc_ready=lambda: True)
        client = create_app(runtime=restarted).test_client()
        listed = client.get("/v1/postmessage/example/candidates")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.get_json()["items"][0]["id"], candidate_id)
        detail = client.get(f"/v1/postmessage/example/candidates/{candidate_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("ACTIVATE", detail.get_json()["message_types"])
        self.assertEqual(client.get(f"/v1/postmessage/example/candidates/{candidate_id}/runtime")
                         .get_json()["links"]["run_id"], None)

    def test_domxss_analyze_maps_only_high_priority_candidates(self):
        self.runtime.registry.register_target(self.runtime.package("example"))
        high = SimpleNamespace(candidate_id="DOM-" + "a" * 32, score=80)
        low = SimpleNamespace(candidate_id="DOM-" + "b" * 32, score=40)
        fake = Mock()
        fake.inventory.return_value = (SimpleNamespace(asset=SimpleNamespace(asset_id=91)),)
        fake.acquire.return_value = SimpleNamespace(
            status=DOMAcquisitionStatus.REUSED, artifact=SimpleNamespace(artifact_id="DOMART-fixture"),
            exchange_ids=())
        fake.analyze.return_value = ("DOMAN-fixture", SimpleNamespace(
            status="ANALYZED", asset_sha256="a" * 64, candidates=(high, low), parse_errors=0))
        fake.acquire_source_map.return_value = SimpleNamespace(
            status=DOMAcquisitionStatus.RETRIEVED, source_map=object())
        with (patch.object(self.runtime, "domxss", fake),
              patch.object(self.runtime.domxss_store, "map_candidate") as mapping,
              patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target traffic"))):
            response = self.client.post("/v1/domxss/example/analyze", json={"recon_asset_id": 91})
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        self.assertEqual(response.get_json()["source_map_status"], "RETRIEVED")
        self.assertEqual(response.get_json()["mapped_candidate_ids"], [high.candidate_id])
        mapping.assert_called_once()
        self.assertEqual(mapping.call_args.args[1], high.candidate_id)

        fake.analyze.return_value = ("DOMAN-fixture", SimpleNamespace(
            status="ANALYZED", asset_sha256="a" * 64, candidates=(low,), parse_errors=0))
        fake.acquire_source_map.reset_mock()
        with (patch.object(self.runtime, "domxss", fake),
              patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target traffic"))):
            response = self.client.post("/v1/domxss/example/analyze", json={"recon_asset_id": 91})
        self.assertEqual(response.get_json()["source_map_status"], "NOT_REQUESTED")
        fake.acquire_source_map.assert_not_called()

    def test_authorization_api_is_target_scoped_bounded_and_local_only(self):
        self.runtime.registry.register_target(self.runtime.package("example"))
        with patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target traffic")):
            profile = self.get("/v1/authorization/example/profile")
            self.assertEqual(profile["target_id"], self.target)
            self.assertEqual(self.get("/v1/authorization/example/hunts")["items"], [])
            self.assertEqual(self.get("/v1/authorization/example/candidates")["items"], [])
            self.assertEqual(self.get("/v1/authorization/example/matrix")["items"], [])
            self.assertEqual(self.get("/v1/authorization/example/metrics")["requests_used"], 0)
            created = self.client.post("/v1/authorization/example/hunts", json={
                "mode": "PLAN_ONLY", "candidate_limit": 2, "request_budget": 5})
            self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
            hunt_id = created.get_json()["hunt"]["id"]
            self.assertEqual(created.get_json()["hunt"]["status"], "BLOCKED")
            self.assertEqual(self.get("/v1/authorization/example/metrics?hunt_id=" +
                                      hunt_id)["candidates"], 0)
            metrics = self.get("/v1/authorization/example/metrics")
            self.assertEqual(metrics["mutation_candidates"], 0)
            self.assertEqual(metrics["mutation_plans"], 0)
            self.assertEqual(metrics["nested_candidates"], 0)
            self.assertEqual(metrics["batch_candidates"], 0)
            self.assertEqual(metrics["typed_mutations"]["executed"], 0)
            self.assertEqual(self.client.get("/v1/authorization/example/metrics?hunt_id=missing").status_code,
                             404)
            self.assertEqual(self.client.get("/v1/authorization/not-here/profile").status_code, 404)
            self.assertEqual(self.client.post("/v1/authorization/example/hunts", json={
                "mode": "PLAN_ONLY", "candidate_limit": 500}).status_code, 400)

    def test_api_specialist_routes_are_target_scoped_and_local_only(self):
        self.runtime.registry.register_target(self.runtime.package("example"))
        base = "/v1/api/example"
        with patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target traffic")):
            coverage = self.get(base + "/coverage")
            self.assertEqual(coverage["counts"]["operations_current"], 0)
            self.assertEqual(coverage["metrics"]["plans"], 0)
            self.assertEqual(coverage["metrics"]["requests"], 0)
            self.assertEqual(coverage["inventory_more"], {
                "traffic": False, "js": False, "operations": False})
            self.assertEqual(self.get(base + "/operations")["items"], [])
            self.assertEqual(self.get(base + "/candidates")["items"], [])
            analyzed = self.client.post(base + "/analyze", json={"mode": "PLAN_ONLY",
                "limits": {"traffic": 5, "js_assets": 2, "recon_surfaces": 2, "candidates": 2}})
            self.assertEqual(analyzed.status_code, 201, analyzed.get_data(as_text=True))
            self.assertEqual(analyzed.get_json()["items"], [])
            self.assertEqual(self.client.post(base + "/analyze", json={
                "limits": {"traffic": 151}}).status_code, 400)
            self.assertEqual(self.client.post(base + "/analyze", json={
                "mode": "BOUNDED_AUTONOMOUS"}).status_code, 201)
            self.assertEqual(self.client.post(base + "/analyze", json={
                "query": "{ users { id } }"}).status_code, 400)
            self.assertEqual(self.client.post(base + "/query", json={
                "query": "{ users { id } }"}).status_code, 404)
            self.assertEqual(self.client.get("/v1/api/not-here/coverage").status_code, 404)
            self.assertEqual(self.client.get(base + "/operations/APIO-invalid").status_code, 404)
            self.assertEqual(self.client.get(base + "/candidates/APIC-invalid").status_code, 404)
            for number in range(3):
                self.runtime.api_operations.upsert_operation(
                    target_id=self.runtime.package("example").target.id,
                    package_id="example", name=f"PageTest{number}",
                    kind=APIOperationType.REST,
                    endpoint=f"https://app.example.com/api/items/{number}",
                    method="GET", version_hash=hashlib.sha256(str(number).encode()).hexdigest(),
                    observed_at=f"2026-01-01T00:00:0{number}+00:00")
            first = self.get(base + "/operations?limit=2")
            self.assertEqual(len(first["items"]), 2)
            self.assertIsNotNone(first["next_cursor"])
            second = self.get(base + "/operations?limit=2&cursor=" + first["next_cursor"])
            self.assertEqual(len(second["items"]), 1)
            self.assertIsNone(second["next_cursor"])
            self.assertFalse({item["id"] for item in first["items"]} &
                             {item["id"] for item in second["items"]})
            selected = first["items"][0]
            self.runtime.api_operations.upsert_candidate(APICandidate(
                id="APIC-service-fixture", target_id=self.runtime.package("example").target.id,
                operation_id=selected["id"], category="OBJECT_AUTH",
                boundary_identity_id=None, owner_identity_id=None,
                test_object_id=None, owner_exchange_id=None, field_path=None,
                score=50, reasons=("FIXTURE",), gaps=("OBJECT_OWNERSHIP_UNKNOWN",),
                status="PLAN_ONLY"))
            detail = self.get(base + "/operations/" + selected["id"])
            self.assertEqual([item["id"] for item in detail["candidates"]],
                             ["APIC-service-fixture"])
            self.assertEqual([item["id"] for item in self.get(
                base + "/candidates?operation_id=" + selected["id"])["items"]],
                ["APIC-service-fixture"])
            self.assertEqual(self.client.get(base + "/candidates?operation_id=APIO-invalid")
                             .status_code, 404)
            focused = self.client.post(base + "/analyze", json={
                "mode": "PLAN_ONLY", "operation_id": selected["id"]})
            self.assertEqual(focused.status_code, 201)
            self.assertEqual({item["operation_id"] for item in focused.get_json()["items"]},
                             {selected["id"]})

    def test_skill_routes_are_target_scoped_and_never_execute(self):
        catalog = self.get("/v1/skills")["items"]
        self.assertEqual(len(catalog), 19)
        self.assertTrue(all(item["status"] == "PLAN_ONLY" for item in catalog))
        detail = self.get("/v1/skills/check-before-transform-dom-xss")
        self.assertEqual(detail["execution"], "PLAN_ONLY")
        self.assertTrue(detail["workflow"])
        self.assertEqual(self.get("/v1/skills/postmessage-trust-analysis")
                         ["validation_outcomes"], {})
        self.assertEqual(self.client.get("/v1/skills/not-a-skill").status_code, 404)
        manual = self.client.post("/v1/hypotheses/manual", json={
            "target": "example", "category": "DOM_XSS", "statement": "Controlled source may reach a sink",
            "future_experiment": "Trace a current bundle and test harmless browser controls",
        })
        self.assertEqual(manual.status_code, 201, manual.get_data(as_text=True))
        hypothesis_id = manual.get_json()["id"]
        route = self.client.post(f"/v1/hypotheses/{hypothesis_id}/skills/route", json={"target": "example"})
        self.assertEqual(route.status_code, 200, route.get_data(as_text=True))
        self.assertEqual(route.get_json()["candidates"][0]["skill"]["name"],
                         "check-before-transform-dom-xss")
        self.assertIn("recommended_skills", self.get(f"/v1/hypotheses/{hypothesis_id}?target=example"))
        from unittest.mock import patch
        with patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target traffic")):
            created = self.client.post(f"/v1/hypotheses/{hypothesis_id}/plan", json={
                "target": "example", "skill_id": "check-before-transform-dom-xss", "selection": "RECOMMENDED"})
        self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
        plan = created.get_json()
        self.assertEqual(plan["status"], "BLOCKED_PREREQUISITES")
        self.assertFalse(plan["execution_started"])
        self.assertEqual(plan["proposed_actions"], [])
        self.assertEqual(self.get(f"/v1/plans/{plan['id']}?target=example")["id"], plan["id"])
        again = self.client.post(f"/v1/hypotheses/{hypothesis_id}/plan", json={
            "target": "example", "skill_id": "check-before-transform-dom-xss", "selection": "RECOMMENDED"})
        self.assertEqual(again.get_json()["id"], plan["id"])
        self.assertEqual(self.client.get(f"/v1/plans/{plan['id']}?target=unknown").status_code, 404)
        self.assertEqual(self.client.post(f"/v1/hypotheses/{hypothesis_id}/plan", json={
            "target": "example", "skill_id": "not-a-skill", "selection": "MANUAL"}).status_code, 404)

    def test_plan_run_api_is_target_scoped_and_advances_one_manual_step(self):
        hypothesis = self.runtime.hypotheses.add_manual(
            self.target, "EXPOSURE", "Fixture observation needs review",
            "Link an existing target-owned evidence record")
        plan_id = "PLAN-" + uuid.uuid4().hex
        payload = {
            "id": plan_id, "target_id": self.target, "hypothesis_id": hypothesis.id,
            "skill_id": "fixture-review", "skill_version": "1.0.0", "skill_hash": "a" * 64,
            "skill_category": "exposure", "vulnerability_classes": [],
            "required_prerequisites": ["in_scope_target"],
            "status": "READY_FOR_MANUAL_REVIEW", "steps": [{"type": "MANUAL_REVIEW"}],
            "proposed_actions": [], "request_templates": [], "request_budget": 0,
            "token_budget": 0,
        }
        with self.runtime.store._connection() as db:
            db.execute("INSERT INTO skill_plans VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (plan_id, self.target, hypothesis.id, payload["skill_id"],
                        payload["skill_version"], payload["skill_hash"], 0, 0,
                        payload["status"], datetime.now(timezone.utc).isoformat(),
                        json.dumps(payload, sort_keys=True, separators=(",", ":"))))
        with patch.object(self.runtime.executor, "execute", side_effect=AssertionError("target request")):
            created = self.client.post(f"/v1/plans/{plan_id}/runs", json={"target": "example"})
            self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
            run_id = created.get_json()["run"]["id"]
            self.assertEqual(self.get(f"/v1/plans/{plan_id}/runs?target=example")["items"][0]["id"], run_id)
            self.assertEqual(self.get("/v1/runs?target=example")["items"][0]["id"], run_id)
            first = self.client.post(f"/v1/runs/{run_id}/advance", json={"target": "example"})
            self.assertEqual(first.get_json()["run"]["status"], "READY")
            second = self.client.post(f"/v1/runs/{run_id}/advance", json={"target": "example"})
            self.assertEqual(second.get_json()["run"]["status"], "WAITING_HUMAN")
            self.assertEqual(self.client.post(f"/v1/runs/{run_id}/archive",
                                              json={"target": "example"}).status_code, 409)
            self.assertEqual(self.client.post(f"/v1/hypotheses/{hypothesis.id}/archive",
                                              json={"target": "example"}).status_code, 409)
            self.assertEqual(second.get_json()["run"]["requests_consumed"], 0)
            self.assertEqual(self.client.post(f"/v1/runs/{run_id}/pause",
                                              json={"target": "example"}).status_code, 400)
            self.assertEqual(self.client.get(f"/v1/runs/{run_id}?target=unknown").status_code, 404)
            self.assertEqual(self.client.get(f"/v1/plans/{plan_id}/runs?target=unknown").status_code, 404)
            cancelled = self.client.post(f"/v1/runs/{run_id}/cancel", json={"target": "example"})
            self.assertEqual(cancelled.get_json()["run"]["status"], "CANCELLED")
            self.assertEqual(self.client.post(f"/v1/runs/{run_id}/archive",
                                              json={"target": "example"}).status_code, 200)
            self.assertEqual(self.get("/v1/runs?target=example")["items"], [])
            self.assertEqual(self.get("/v1/runs?target=example&archived=1")["items"][0]["id"], run_id)
            self.assertEqual(self.client.post(f"/v1/hypotheses/{hypothesis.id}/archive",
                                              json={"target": "example"}).status_code, 200)
            self.assertEqual(self.get("/v1/hypotheses?target=example")["items"], [])
            self.assertEqual(self.get("/v1/hypotheses?target=example&archived=1")["items"][0]["id"],
                             hypothesis.id)

    def test_manual_login_never_self_verifies_and_is_target_scoped(self):
        imported = self.client.post("/v1/targets/example/import-identities", json={})
        self.assertEqual(imported.status_code, 201, imported.get_data(as_text=True))
        identities = self.get("/v1/targets/example/identities")["items"]
        self.assertEqual(len(identities), 3)
        identity = next(item["identity"] for item in identities if item["identity"]["alias"] == "org1_member")
        self.assertNotIn("ref:fixture_admin", json.dumps(identities))
        self.assertEqual(self.client.post(f"/v1/identities/{identity['id']}/prepare-auth",
                                          json={"target": "example", "mechanism": "MANUAL_LOGIN"}).status_code, 200)
        created = self.client.post("/v1/browser/sessions", json={"target": "example", "identity_id": identity["id"]})
        self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
        session_id = created.get_json()["id"]
        self.assertEqual(created.get_json()["status"], "CREATED")
        self.assertIsNone(created.get_json()["vnc_url"])
        self.assertEqual(self.client.post(f"/v1/browser/sessions/{session_id}/login-complete?target=example",
                                          json={}).status_code, 400)
        started = self.client.post(f"/v1/browser/sessions/{session_id}/start?target=example", json={})
        self.assertEqual(started.get_json()["status"], "WAITING_LOGIN")
        self.assertTrue(started.get_json()["vnc_available"])
        self.assertEqual(started.get_json()["vnc_url"], "http://127.0.0.1:6901/vnc.html")
        completed = self.client.post(f"/v1/browser/sessions/{session_id}/login-complete?target=example", json={})
        self.assertEqual(completed.get_json()["status"], "NEEDS_MANUAL_REVIEW")
        self.assertNotEqual(completed.get_json()["status"], "VALID")
        self.assertEqual(self.get("/v1/browser/sessions?target=example")["items"][0]["id"], session_id)
        self.assertEqual(self.client.get(f"/v1/browser/sessions/{session_id}?target=other").status_code, 404)
        self.assertEqual(self.client.post(f"/v1/browser/sessions/{session_id}/stop?target=example",
                                          json={}).get_json()["status"], "STOPPED")
        activity = self.get("/v1/activity?limit=2")
        self.assertEqual(len(activity["items"]), 2)
        self.assertIsNotNone(activity["next_cursor"])
        self.assertNotIn("ref:fixture_admin", json.dumps(activity))

    def test_server_side_verification_and_restart_reconciliation(self):
        self.client.post("/v1/targets/example/import-identities", json={})
        identity = self.get("/v1/targets/example/identities")["items"][0]["identity"]
        self.client.post(f"/v1/identities/{identity['id']}/prepare-auth",
                         json={"target": "example", "mechanism": "MANUAL_LOGIN"})
        created = self.client.post("/v1/browser/sessions", json={"target": "example", "identity_id": identity["id"]})
        session_id = created.get_json()["id"]
        self.client.post(f"/v1/browser/sessions/{session_id}/start?target=example", json={})
        rule = {identity["alias"]: {"expected_user_id": "owned-fixture-user",
                                   "user_id_selector": "[data-user]"}}
        (self.config.targets.root / "example/verification.json").write_text(json.dumps(rule))
        self.driver.observation = IdentityObservation(user_id="wrong-fixture-user")
        completed = self.client.post(f"/v1/browser/sessions/{session_id}/login-complete?target=example", json={})
        self.assertEqual(completed.get_json()["status"], "REAUTH_REQUIRED")
        self.driver.running.clear()
        restarted = BugHunterRuntime(self.config, driver=FakeDriver(), vnc_ready=lambda: False)
        self.assertEqual(restarted.browser.get(session_id).status.value, "REAUTH_REQUIRED")

    def test_traffic_is_empty_and_filters_reject_invalid_input(self):
        self.assertEqual(self.get("/v1/traffic?target=example")["items"], [])
        self.assertEqual(self.get("/v1/traffic/stats?target=example")["sample_count"], 0)
        self.assertEqual(self.client.get("/v1/traffic?target=example&status=999").status_code, 400)
        self.assertEqual(self.client.get("/v1/traffic?target=example&method=GET%0A").status_code, 400)

    def test_synthetic_traffic_filter_pagination_detail_and_secret_safety(self):
        package = self.runtime.package("example")
        self.runtime.registry.register_target(package)
        now = datetime.now(timezone.utc)
        for method, status in (("GET", 200), ("POST", 201)):
            packet = CapturePacket(
                CapturedRequest(method, "https://app.example.test/api/items?token=hidden-secret",
                                (("Authorization", "Bearer hidden-secret"),
                                 ("Cookie", "sid=hidden-secret")), None, now),
                CapturedResponse(status, (("Content-Type", "application/json"),),
                                 b'{"ok":true}', now),
            )
            self.runtime.traffic.store_exchange(package, packet, source=TrafficSource.FIXTURE,
                                                capture_provider="LOCAL_FIXTURE", anonymous=True)
        first = self.get("/v1/traffic?target=example&limit=1")
        self.assertEqual(len(first["items"]), 1)
        self.assertIsNotNone(first["next_cursor"])
        second = self.get("/v1/traffic?target=example&limit=1&cursor=" + first["next_cursor"])
        self.assertEqual(len(second["items"]), 1)
        self.assertNotEqual(first["items"][0]["id"], second["items"][0]["id"])
        filtered = self.get("/v1/traffic?target=example&method=POST&status=201&source=FIXTURE")
        self.assertEqual(len(filtered["items"]), 1)
        self.assertEqual(filtered["items"][0]["request"]["method"], "POST")
        self.assertEqual(self.client.get("/v1/traffic?target=example&method=GET&cursor="
                                         + first["next_cursor"]).status_code, 400)
        detail = self.get("/v1/traffic/" + filtered["items"][0]["id"] + "?target=example")
        self.assertEqual(detail["response"]["status_code"], 201)
        for output in (first, second, filtered, detail):
            self.assertNotIn("hidden-secret", json.dumps(output))
            self.assertNotIn("Authorization", json.dumps(output))
            self.assertNotIn("Cookie", json.dumps(output))
        self.assertEqual(self.get("/v1/traffic/stats?target=example")["sample_count"], 2)


if __name__ == "__main__":
    unittest.main()
