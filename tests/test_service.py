from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

from hackbot.browser import IdentityObservation
from hackbot.config import BrowserSettings, TargetSettings, load_config
from hackbot.domain import TrafficSource
from hackbot.service import BugHunterRuntime, create_app
from hackbot.traffic import CapturePacket, CapturedRequest, CapturedResponse


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
            vnc_url="http://127.0.0.1:6901/vnc.html"))
        self.driver = FakeDriver()
        self.runtime = BugHunterRuntime(self.config, driver=self.driver, vnc_ready=lambda: True)
        self.app = create_app(runtime=self.runtime)
        self.client = self.app.test_client()
        self.target = self.runtime.package("example").target.id

    def get(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

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

    def test_skill_routes_are_target_scoped_and_never_execute(self):
        catalog = self.get("/v1/skills")["items"]
        self.assertEqual(len(catalog), 11)
        self.assertTrue(all(item["status"] == "PLAN_ONLY" for item in catalog))
        detail = self.get("/v1/skills/check-before-transform-dom-xss")
        self.assertEqual(detail["execution"], "PLAN_ONLY")
        self.assertTrue(detail["workflow"])
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
