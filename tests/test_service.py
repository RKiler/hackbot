from __future__ import annotations

from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import Mock, patch

from hackbot.browser import IdentityObservation
from hackbot.config import (BrowserSettings, BurpSettings, SecretBindingConfig,
                            SecretSettings, TargetSettings, load_config)
from hackbot.domxss import DOMAcquisitionStatus
from hackbot.domain import TrafficSource
from hackbot.postmessage_static import PostMessageStaticAnalyzer
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
            runtime.registry.register_target(runtime.package("example"))
            client = create_app(runtime=runtime).test_client()
            response = client.post("/v1/browser/sessions", json={
                "target": "example", "anonymous": True, "capture_provider": "BURP"})
            self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
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
            runtime.browser.stop(session["id"])
            runtime.close_burp_bridge()
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

    def test_skill_routes_are_target_scoped_and_never_execute(self):
        catalog = self.get("/v1/skills")["items"]
        self.assertEqual(len(catalog), 18)
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
            self.assertEqual(second.get_json()["run"]["requests_consumed"], 0)
            self.assertEqual(self.client.post(f"/v1/runs/{run_id}/pause",
                                              json={"target": "example"}).status_code, 400)
            self.assertEqual(self.client.get(f"/v1/runs/{run_id}?target=unknown").status_code, 404)
            self.assertEqual(self.client.get(f"/v1/plans/{plan_id}/runs?target=unknown").status_code, 404)
            cancelled = self.client.post(f"/v1/runs/{run_id}/cancel", json={"target": "example"})
            self.assertEqual(cancelled.get_json()["run"]["status"], "CANCELLED")

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
