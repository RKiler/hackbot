"""Local dashboard-to-campaign Hunt journey with real browser and capture."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import hashlib
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from flask import Flask, abort, request
from werkzeug.serving import make_server

from hackbot.config import (BrowserSettings, BurpSettings, ResourceSettings,
                            TargetSettings, load_config)
from hackbot.browser import BrowserError
from hackbot.domain import ObservationState
from hackbot.secrets import SecretValue
from hackbot.service import BugHunterRuntime, create_app
from hackbot.store import EvidenceFactStore

from tests.synthetic_capture import SyntheticCapturePool
from tests.synthetic_saas import ACCOUNTS, LOGIN_PASSWORD, SyntheticSaaS


_GATEWAY = Path(__file__).resolve().parents[2] / "enhanced_recon_framework" / "hackbot_gateway.py"
_CHROMIUM = Path("/root/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome")


def _install_gateway():
    spec = importlib.util.spec_from_file_location("local_hunt_gateway", _GATEWAY)
    if spec is None or spec.loader is None:
        raise RuntimeError("Dashboard gateway cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.install_hackbot_routes


@unittest.skipUnless(_GATEWAY.is_file() and _CHROMIUM.is_file(),
                     "Local gateway or Chromium is unavailable")
class LocalHuntOperatorE2ETests(unittest.TestCase):
    def test_three_account_login_capture_mapping_and_campaign_handoff(self) -> None:
        self._run_operator_journey(vulnerable=True)

    def test_secure_counterpart_creates_no_confirmed_finding(self) -> None:
        self._run_operator_journey(vulnerable=False)

    def _run_operator_journey(self, *, vulnerable: bool) -> None:
        with ExitStack() as stack:
            root = Path(stack.enter_context(TemporaryDirectory()))
            fixture = stack.enter_context(SyntheticSaaS(vulnerable=vulnerable))
            captures = stack.enter_context(SyntheticCapturePool(
                fixture.base_url, count=len(ACCOUNTS)))
            base = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                        "XDG_STATE_HOME": str(root)})
            bridge_port = next(port for port in (38777, 38778, 38779, 38780)
                               if not captures.first_port <= port <= captures.last_port)
            config = replace(
                base,
                targets=TargetSettings(root / "targets"),
                browser=BrowserSettings(profile_root=root / "profiles",
                                        chromium_executable=_CHROMIUM),
                burp=BurpSettings(True, root / "burp",
                                  listener_start=captures.first_port,
                                  listener_end=captures.last_port,
                                  bridge_port=bridge_port),
                resources=ResourceSettings(min_free_disk_bytes=0,
                                           min_free_system_disk_bytes=0,
                                           min_available_memory_bytes=0,
                                           warning_disk_percent=95,
                                           high_disk_percent=97,
                                           critical_disk_percent=99),
            )
            EvidenceFactStore.from_config(config).initialize()
            runtime = BugHunterRuntime(config, vnc_ready=lambda: True)
            specialist_errors: list[str] = []
            original_start = runtime.api.start_candidate

            def start_with_diagnostic(*args, **kwargs):
                try:
                    return original_start(*args, **kwargs)
                except (LookupError, ValueError) as exc:
                    specialist_errors.append(str(exc))
                    raise

            runtime.api.start_candidate = start_with_diagnostic
            socket_path = root / "control.sock"
            service = make_server("unix://" + str(socket_path), 0,
                                  create_app(runtime=runtime), threaded=True)
            service_thread = Thread(target=service.serve_forever, daemon=True)
            service_thread.start()
            dashboard = Flask(__name__)

            def csrf() -> None:
                if request.headers.get("X-CSRF-Token") != "fixture-csrf":
                    abort(403)

            _install_gateway()(dashboard, authorized=lambda: True,
                               csrf_token=lambda: "fixture-csrf", require_csrf=csrf,
                               auth_enabled=lambda: True, socket_path=str(socket_path),
                               hunt_ui_enabled=True)
            client = dashboard.test_client()

            def post(path: str, body: dict[str, object]):
                return client.post("/api/hackbot/" + path, json=body,
                                   headers={"X-CSRF-Token": "fixture-csrf"})

            def hunt_status() -> dict[str, object]:
                response = client.get("/api/hackbot/targets/synthetic-local/hunt")
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                return response.get_json()

            try:
                target = {
                    "name": "Synthetic Local SaaS", "id": "synthetic-local",
                    "primary_domain": "127.0.0.1", "confirmed": True,
                    "scope": {"include": ["127.0.0.1"], "exclude": [],
                              "schemes": ["http", "https"],
                              "ports": [urlsplit(fixture.base_url).port]},
                    "source": {"kind": "RESEARCHER", "reference": "local fixture",
                               "operator": "test-operator"},
                    "rules": {"automated_testing_allowed": True,
                              "account_creation_allowed": False,
                              "forbidden_actions": []},
                    "autonomy": {"passive": "ALLOW", "safe_read": "ALLOW",
                                 "bounded_active": "ALLOW", "state_changing": "ALLOW",
                                 "destructive": "DENY",
                                 "create_disposable_objects": "ALLOW",
                                 "delete_disposable_objects": "ALLOW",
                                 "cross_identity_testing": "ALLOW"},
                    "rate": {"requests_per_second": 1, "requests_per_minute": 30,
                             "max_concurrency": 1, "burst": 1},
                }
                created = post("targets", target)
                self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
                package = runtime.package("synthetic-local")
                saved = post("targets/synthetic-local/accounts", {"accounts": [
                    {"alias": alias, "tenant": tenant, "role": role}
                    for alias, (tenant, role) in ACCOUNTS.items()]})
                self.assertEqual(saved.status_code, 200, saved.get_data(as_text=True))
                self.assertEqual(saved.get_json()["configured"], len(ACCOUNTS))
                self.assertTrue(all(item["registration"] == "REGISTERED"
                                    for item in saved.get_json()["items"]))
                captures.attach(runtime.package("synthetic-local"), runtime)

                with patch.object(runtime, "ensure_burp_bridge"), \
                     patch.object(runtime.burp, "bridge_connected", return_value=True):
                    started = post("targets/synthetic-local/hunt", {"mode": "RESEARCHER_AUTONOMOUS"})
                    self.assertEqual(started.status_code, 202, started.get_data(as_text=True))
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        status = hunt_status()
                        if status["hunt"]["state"] != "PREPARING":
                            break
                        time.sleep(0.2)
                    self.assertEqual(status["hunt"]["state"], "LOGIN_REQUIRED", status)
                    self.assertEqual({item["alias"] for item in status["needs_you"]},
                                     set(ACCOUNTS))
                    sessions = {item["alias"]: item["session_id"]
                                for item in status["needs_you"]}
                    self.assertEqual(len({runtime.burp.binding_for_session(session_id).proxy_port
                                          for session_id in sessions.values()}), len(ACCOUNTS))
                    dashboard = Flask(__name__ + "_restarted")
                    _install_gateway()(dashboard, authorized=lambda: True,
                                       csrf_token=lambda: "fixture-csrf", require_csrf=csrf,
                                       auth_enabled=lambda: True, socket_path=str(socket_path),
                                       hunt_ui_enabled=True)
                    client = dashboard.test_client()
                    resumed = hunt_status()
                    self.assertEqual(resumed["hunt"]["id"], status["hunt"]["id"])
                    self.assertEqual({item["alias"] for item in resumed["needs_you"]},
                                     set(ACCOUNTS))

                    def operator_login(alias: str, session_id: str) -> str:
                        driver = runtime.driver._driver
                        page = driver._contexts[session_id].pages[0]
                        page.goto(fixture.base_url + "/login", wait_until="domcontentloaded",
                                  timeout=15000)
                        page.select_option('select[name="alias"]', alias)
                        page.fill('input[name="password"]', LOGIN_PASSWORD)
                        page.get_by_role("button", name="Sign in").click()
                        page.wait_for_selector("[data-user]", timeout=15000)
                        return page.locator("[data-user]").inner_text()

                    for alias, session_id in sessions.items():
                        self.assertTrue(runtime.burp.ready(session_id))
                        self.assertEqual(runtime.driver._worker.submit(
                            operator_login, alias, session_id).result(30), alias)
                        completed = post(
                            f"browser/sessions/{session_id}/login-complete?target=synthetic-local",
                            {"confirm_alias": alias})
                        self.assertEqual(completed.status_code, 200,
                                         completed.get_data(as_text=True))
                        self.assertEqual(completed.get_json()["verification_method"],
                                         "OPERATOR_CONFIRMED")
                        material = runtime.driver.cookie_header_for(
                            session_id, fixture.base_url + "/api/me")
                        self.assertIsInstance(material, SecretValue)
                        with self.assertRaises(BrowserError):
                            runtime.driver.cookie_header_for(
                                session_id, fixture.base_url.replace("127.0.0.1", "localhost")
                                + "/api/me")

                    deadline = time.monotonic() + 180
                    while time.monotonic() < deadline:
                        status = hunt_status()
                        if len(status["mapping"]) == len(ACCOUNTS) or status["hunt"]["state"] in {
                                "WAITING_HUMAN", "PAUSED_RESOURCE_PRESSURE", "FAILED"}:
                            break
                        time.sleep(0.4)
                    self.assertEqual(len(status["mapping"]), len(ACCOUNTS), status)
                    self.assertTrue(all(row["pages_observed"] > 0
                                        for row in status["mapping"]), status)
                    self.assertGreater(status["inventory"]["js_assets_current"], 0, status)
                    for alias, session_id in sessions.items():
                        exchanges = runtime.traffic.list_exchanges_for_session(
                            package.target.id, session_id, limit=100).items
                        identity = runtime.registry.get_identity(package.target.id, alias)
                        self.assertTrue(any(item.attribution.verified_identity_id == identity.id
                                            for item in exchanges), alias)
                        self.assertTrue(any(item.source.value == "BURP" for item in exchanges))
                        self.assertTrue(any(row.path == "/app" and row.actor == alias
                                            for row in fixture.requests), alias)
                    self.assertTrue(any(row.path == "/session/login" and row.status == 303
                                        for row in fixture.requests))
                    deadline = time.monotonic() + 240
                    while time.monotonic() < deadline:
                        status = hunt_status()
                        if (status["inventory"]["api_operations_current"] >= 2
                                and status["inventory"]["graphql_operations_current"] >= 1):
                            break
                        if status["hunt"]["state"] in {"WAITING_HUMAN", "FAILED"}:
                            break
                        time.sleep(1.0)
                    self.assertGreaterEqual(status["inventory"]["api_operations_current"], 2,
                                            status)
                    self.assertGreaterEqual(status["inventory"]["graphql_operations_current"],
                                            1, status)
                    deadline = time.monotonic() + 120
                    js_routes = set()
                    while time.monotonic() < deadline:
                        js_routes = {(operation.method, operation.endpoint)
                                     for operation in runtime.api.registry.list_operations(
                                         package.target.id, limit=100)
                                     if any(ref.startswith("JS:")
                                            for ref in operation.source_refs)}
                        if (("GET", "/api/documents/{id}/preview") in js_routes and
                                ("DELETE", "/api/documents/{id}") in js_routes):
                            break
                        status = hunt_status()
                        if status["hunt"]["state"] in {"WAITING_HUMAN", "FAILED"}:
                            break
                        time.sleep(1)
                    self.assertIn(("GET", "/api/documents/{id}/preview"), js_routes)
                    self.assertIn(("DELETE", "/api/documents/{id}"), js_routes)
                    deadline = time.monotonic() + 180
                    while time.monotonic() < deadline:
                        status = hunt_status()
                        if status["hunt"]["campaign_id"] is not None or status["hunt"]["state"] in {
                                "WAITING_HUMAN", "FAILED", "PAUSED_RESOURCE_PRESSURE"}:
                            break
                        time.sleep(0.4)
                    self.assertIsNotNone(status["hunt"]["campaign_id"],
                                         (status, [(item.id, item.state.value)
                                                   for item in runtime.objects.list_for_target(
                                                       package.target.id, limit=20).items]))
                    self.assertGreater(status["inventory"]["api_candidates"], 0,
                                       status)
                    self.assertGreater(status["inventory"]["api_candidates_ready"], 0,
                                       (status, [(item.category, item.status, item.gaps)
                                                 for item in runtime.api.registry.list_candidates(
                                                     package.target.id, limit=30)]))
                    api_candidates = runtime.api.registry.list_candidates(
                        package.target.id, limit=100)
                    ready_routes = []
                    for item in api_candidates:
                        operation = runtime.api.registry.get_operation(
                            package.target.id, item.operation_id)
                        ready_routes.append((item.status, operation.endpoint,
                                             len(operation.exchange_ids)))
                    preview_shape = "/{p:" + hashlib.sha256(b"preview").hexdigest()[:12] + "}"
                    self.assertTrue(any(state == "READY" and route.endswith(preview_shape)
                                        and captures > 0
                                        for state, route, captures in ready_routes), ready_routes)
                    fixtures = runtime.hunts.fixtures(package.target.id,
                                                     status["hunt"]["id"])
                    self.assertEqual(len(fixtures), 2, (fixtures, status))
                    self.assertEqual(fixture.disposable_count, 2)
                    self.assertTrue(all(runtime.objects.get(
                        row["test_object_id"], package.target.id).verified_at
                        for row in fixtures))
                    self.assertTrue(any(
                        row.path.startswith("/api/documents/doc-test-") and
                        row.path.endswith("/preview") for row in fixture.requests))
                    deadline = time.monotonic() + 240
                    while time.monotonic() < deadline:
                        status = hunt_status()
                        if status["hunt"]["state"] in {"COMPLETE", "WAITING_HUMAN",
                                                       "WAITING_APPROVAL", "LOGIN_REQUIRED",
                                                       "PAUSED_RESOURCE_PRESSURE", "FAILED"}:
                            break
                        time.sleep(1)
                    campaign = runtime.campaign.store.get(
                        package.target.id, status["hunt"]["campaign_id"])
                    planner_runs = runtime.planner_store.list(package.target.id, limit=5)
                    subject = hashlib.sha256(runtime.object_factory._external_id(
                        runtime.objects.get(fixtures[0]["test_object_id"],
                                            package.target.id)).encode()).hexdigest()
                    diagnostic = {
                        "hunt": (status["hunt"]["state"], status["hunt"]["reason_code"]),
                        "campaign": ((campaign.status.value, campaign.stop_reason)
                                     if campaign else None),
                        "planners": [(item.status.value, item.stop_reason,
                                      [(task.task_type.value, task.status.value,
                                        task.reason_code) for task in
                                       runtime.planner_store.tasks(package.target.id,
                                                                   item.id, limit=20)
                                       if task.status.value not in {"COMPLETED", "SKIPPED"}][:8])
                                     for item in planner_runs[:2]],
                        "plan_runs": [(item["status"], item["stop_reason"])
                                      for item in runtime.run_store.list(
                                          package.target.id, limit=8)["items"]],
                        "candidates": [(item.source_kind, item.status.value,
                                        bool(item.finding_id),
                                        (runtime.api.registry.get_operation(
                                            package.target.id,
                                            runtime.api.registry.get_candidate(
                                                package.target.id, item.source_id).operation_id).endpoint
                                         if item.source_kind == "API_GRAPHQL" else ""))
                                       for planner in planner_runs[:2]
                                       for item in runtime.planner_store.candidates(
                                           package.target.id, planner.id, limit=10)
                                       if item.status.value != "DEFERRED"][:5],
                        "api_ready": status["inventory"]["api_candidates_ready"],
                        "api_routes": [(item.status, runtime.api.registry.get_operation(
                            package.target.id, item.operation_id).endpoint,
                            item.gaps, bool(item.run_id)) for item in
                            runtime.api.registry.list_candidates(package.target.id, limit=30)],
                        "api_control_detail": [
                            (candidate.status, candidate.category,
                             candidate.owner_identity_id, candidate.boundary_identity_id,
                             candidate.test_object_id, candidate.owner_exchange_id,
                             operation.exchange_ids,
                             [(item.id, item.state.value) for item in
                              runtime.objects.list_for_target(package.target.id,
                                                              limit=10).items],
                             [(item.exchange_id, item.owner_identity_id, item.object_id,
                               item.semantic_owner_success) for item in
                              runtime.authorization.profile(package).operations
                              if item.exchange_id in operation.exchange_ids],
                             [(ref, exchange.attribution.verified_identity_id,
                               exchange.response.record.status_code if exchange.response else None)
                              for ref in operation.exchange_ids
                              if (exchange := runtime.traffic.get_exchange(ref)) is not None])
                            for candidate in runtime.api.registry.list_candidates(
                                package.target.id, limit=30)
                            if candidate.status in {"READY", "REVIEW"} and
                            candidate.category == "OBJECT_AUTH" and
                            (operation := runtime.api.registry.get_operation(
                                package.target.id, candidate.operation_id)) is not None],
                        "planner_candidates": [(planner.id, [
                            (item.source_kind, item.status.value, item.priority,
                             item.reason_codes, item.gaps,
                             (runtime.api.registry.get_operation(
                                 package.target.id, runtime.api.registry.get_candidate(
                                     package.target.id, item.source_id).operation_id).endpoint
                              if item.source_kind == "API_GRAPHQL" else ""))
                            for item in runtime.planner_store.candidates(
                                package.target.id, planner.id, limit=30)])
                            for planner in planner_runs[:2]],
                        "validations": [(item["status"], item["reason_codes"])
                                        for item in runtime.validations.list(
                                            package.target.id, limit=3)["items"]],
                        "specialist_errors": specialist_errors,
                        "policy": {key: [fact.object for fact in runtime.store.find_facts(
                            subject, key, limit=4).items] for key in
                            ("resource_tenant", "resource_visibility", "access_policy")},
                    }
                    self.assertEqual(status["hunt"]["state"], "COMPLETE", diagnostic)
                    findings = runtime.campaign.finding_links(
                        package.target.id, status["hunt"]["campaign_id"])
                    if vulnerable:
                        self.assertTrue(findings, diagnostic)
                        self.assertTrue(all(item["report_id"] for item in findings), findings)
                        self.assertEqual({item["id"] for item in status["findings"]},
                                         {item["finding_id"] for item in findings})
                    else:
                        self.assertFalse(findings, diagnostic)
                        self.assertEqual(status["findings"], [])
                        self.assertFalse(runtime.validations.list_findings(
                            package.target.id, limit=10)["items"])
                    self.assertEqual(fixture.disposable_count, 0)
                    self.assertTrue(any(
                        row.path.startswith("/api/documents/doc-test-") and
                        row.path.endswith("/preview") and row.status == 200
                        for row in fixture.requests))
                    self.assertTrue(any(
                        row.path.startswith("/api/documents/doc-test-") and
                        not row.path.endswith("/preview") and row.status == 404
                        for row in fixture.requests))
                    recipes = runtime.object_factory.recipes.list_for_package(package.id)
                    self.assertGreaterEqual(len(recipes), 2, (recipes, status["mapping"]))
                    self.assertTrue(all(item["object_type"] == "document" for item in recipes))
                    for alias in ACCOUNTS:
                        identity = runtime.registry.get_identity(package.target.id, alias)
                        self.assertEqual(identity.principal_state, ObservationState.OBSERVED,
                                         alias)
                        self.assertTrue(any(
                            item.observation_state is ObservationState.OBSERVED
                            for item in runtime.registry.list_memberships(
                                identity.id, limit=12).items), alias)
            finally:
                for thread in tuple(runtime._hunt_threads.values()):
                    thread.join(timeout=30)
                for thread in tuple(runtime._campaign_threads.values()):
                    thread.join(timeout=30)
                for session in runtime.browser.list_sessions_for_target(
                        package.target.id, limit=20).items if 'package' in locals() else ():
                    if runtime.driver.is_running(session.id):
                        runtime.browser.stop(session.id)
                    runtime.burp.release(session.id)
                runtime.driver.close()
                service.shutdown()
                service.server_close()
                service_thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
