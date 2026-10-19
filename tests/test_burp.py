"""Phase 10 fixtures never contact a bounty target or production recon."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
from io import StringIO
import json
import fcntl
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
import types
import unittest
from unittest.mock import patch

from deploy.burp import run_community
from hackbot.artifacts import ArtifactStore
from hackbot.auth import AuthContextManager, AuthMechanism
from hackbot.browser import (BrowserError, BrowserSessionManager, IdentityObservation,
                             IdentityVerificationRule)
from hackbot.browser_trust import ProfileTrustError, install_profile_ca
from hackbot.browser_playwright import PlaywrightBrowserDriver
from hackbot.burp import BurpError, BurpExecutionProxyAdapter, BurpProxyProvider
from hackbot.burp_bridge import (BurpBridgeServer, BurpCaptureProvider,
                                 BurpObservation, _BridgeHandler)
from hackbot.burp_temp import (BurpTempCollector, BurpTempError, BurpTempPolicy)
from hackbot.cli import main
from hackbot.config import (BrowserSettings, BurpSettings, ConfigError, SecretBindingConfig,
                            SecretSettings, StoreSettings)
from hackbot.domain import TrafficSource, new_entity_id
from hackbot.identity import IdentityStatus
from hackbot.identity_registry import IdentityRegistry
from hackbot.policy_models import ActionCategory, ActorMode, ProposedAction
from hackbot.secrets import RoutedSecretProvider, SecretValue
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package
from hackbot.traffic import AuthState, ExchangeState, TrafficRetentionPolicy, TrafficStore
from hackbot.traffic_retention import TrafficPayloadRetirementManager


EXAMPLE = Path(__file__).parent / "examples/targets/example"
TOKEN = "fixture-bridge-token-with-at-least-32-characters"


class BridgeReplyTests(unittest.TestCase):
    def test_disconnected_client_does_not_trigger_second_reply(self):
        class ClosedClient:
            def __init__(self):
                self.wfile = self
                self.writes = 0

            def send_response(self, _status):
                pass

            def send_header(self, _name, _value):
                pass

            def end_headers(self):
                pass

            def write(self, _body):
                self.writes += 1
                raise BrokenPipeError

        client = ClosedClient()
        _BridgeHandler._reply(client, 200, {"status": "ok"})
        self.assertEqual(client.writes, 1)


class BurpLauncherTests(unittest.TestCase):
    def test_late_wizard_within_bounded_wait_starts_temporary_project(self):
        java = types.SimpleNamespace(poll=lambda: None)
        with patch.object(run_community.time, "monotonic",
                          side_effect=(0, 0, 50, 100)), patch.object(
                              run_community.time, "sleep"
                          ), patch.object(run_community, "windows",
                                          side_effect=([], [], [], [], ["123"])) as windows, patch.object(
                              run_community, "start_temporary_project"
                          ) as start:
            run_community.wait_for_wizard(
                java, 38080, seconds=run_community.WIZARD_WAIT_SECONDS)
        self.assertEqual(windows.call_count, 5)
        start.assert_called_once_with("123")

    def test_unexpected_window_fails_without_title_or_navigation(self):
        java = types.SimpleNamespace(poll=lambda: None)
        with patch.object(run_community.time, "monotonic",
                          side_effect=(0, 181)), patch.object(
                              run_community, "windows", return_value=["123"]
                          ), patch.object(run_community, "start_temporary_project") as start:
            with self.assertRaisesRegex(RuntimeError, "window changed or was not ready"):
                run_community.wait_for_wizard(java, 38080, seconds=180)
        start.assert_not_called()

    def test_runtime_lock_allows_shared_launch_and_blocks_cleanup(self):
        with TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "burp-runtime"
            (runtime / "tmp").mkdir(parents=True)
            first = run_community.acquire_runtime_lock(runtime)
            second = run_community.acquire_runtime_lock(runtime)
            try:
                lock = os.open(runtime / "tmp" / ".community-maintenance.lock", os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(lock)
            finally:
                os.close(second)
                os.close(first)

    def test_busy_runtime_lock_has_sanitized_startup_reason(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "burp-runtime"
            (runtime / "tmp").mkdir(parents=True)
            jar = root / "burp.jar"
            project = root / "project.json"
            user = root / "user.json"
            for path in (jar, project, user):
                path.write_bytes(b"fixture")
            argv = ["run_community.py", "--jar", str(jar),
                    "--runtime-root", str(runtime), "--project-config", str(project),
                    "--user-config", str(user), "--listener-port", "38080"]
            with patch.object(sys, "argv", argv), patch.dict(
                os.environ, {"DISPLAY": ":902", "HACKBOT_SECRET_BURP_BRIDGE": "x" * 32}
            ), patch.object(run_community, "acquire_runtime_lock",
                            side_effect=RuntimeError("untrusted internal detail")):
                with self.assertRaisesRegex(SystemExit,
                                            "Burp runtime maintenance lock is unavailable") as failure:
                    run_community.main()
            self.assertNotIn("untrusted internal detail", str(failure.exception))


class BurpTempCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root / "burp-runtime"
        (self.runtime / "tmp").mkdir(parents=True)
        (self.runtime / "data").mkdir()
        self.review = self.root / "state" / "burp-temp-review.json"
        self.audit = self.root / "logs" / "burp-temp-audit.jsonl"
        self.collector = BurpTempCollector(self.runtime, self.review, self.audit,
                                           require_stopped=lambda _root: None)

    def project(self, name: str, *, hours_old: int = 48) -> Path:
        path = self.runtime / "tmp" / name
        path.mkdir()
        body = path / "cache.bin"
        body.write_bytes(b"fixture-temporary-burp-data")
        old = time.time() - hours_old * 3600
        os.utime(body, (old, old))
        os.utime(path, (old, old))
        return path

    def test_reviewed_cleanup_removes_only_stale_launcher_projects(self):
        old = self.project("community-abcdefgh")
        recent = self.project("community-ijklmnop", hours_old=1)
        unrelated = self.project("burp123456.tmp")
        plan = self.collector.plan()
        self.assertEqual(plan.candidates, (old.name,))
        self.assertGreater(plan.estimated_bytes, 0)
        self.assertEqual(self.review.stat().st_mode & 0o777, 0o600)
        result = self.collector.run(plan.review_id, confirmed=True)
        self.assertEqual(result["removed"], 1)
        self.assertFalse(old.exists())
        self.assertTrue(recent.exists())
        self.assertTrue(unrelated.exists())
        self.assertEqual([json.loads(line)["stage"] for line in self.audit.read_text().splitlines()],
                         ["STARTED", "COMPLETED"])
        with self.assertRaises(BurpTempError):
            self.collector.run(plan.review_id, confirmed=True)

    def test_active_service_and_changed_tree_block_cleanup(self):
        path = self.project("community-abcdefgh")
        plan = self.collector.plan()
        blocked = BurpTempCollector(self.runtime, self.review, self.audit,
                                    require_stopped=lambda _root: (_ for _ in ()).throw(
                                        BurpTempError("Burp service must be stopped")))
        with self.assertRaisesRegex(BurpTempError, "must be stopped"):
            blocked.run(plan.review_id, confirmed=True)
        self.assertTrue(path.exists())
        (path / "cache.bin").write_bytes(b"changed")
        with self.assertRaisesRegex(BurpTempError, "changed after review"):
            self.collector.run(plan.review_id, confirmed=True)
        self.assertTrue(path.exists())

    def test_shared_launcher_lock_allows_plan_but_blocks_run(self):
        self.project("community-abcdefgh")
        lock = self.runtime / "tmp" / ".community-maintenance.lock"
        fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            plan = self.collector.plan()
            self.assertEqual(len(plan.candidates), 1)
            with self.assertRaisesRegex(BurpTempError, "runtime is active"):
                self.collector.run(plan.review_id, confirmed=True)
        finally:
            os.close(fd)

    def test_symlink_and_entry_limit_fail_closed(self):
        path = self.project("community-abcdefgh")
        (path / "outside").symlink_to(self.root)
        with self.assertRaisesRegex(BurpTempError, "Unsafe Burp temp entry"):
            self.collector.plan()
        (path / "outside").unlink()
        (path / "second.bin").write_bytes(b"second")
        limited = BurpTempCollector(self.runtime, self.review, self.audit,
                                    BurpTempPolicy(max_tree_entries=2),
                                    require_stopped=lambda _root: None)
        with self.assertRaisesRegex(BurpTempError, "exceeds review limit"):
            limited.plan()

    def test_cli_plan_uses_configured_runtime_without_database(self):
        self.project("community-abcdefgh")
        config = self.root / "config.toml"
        config.write_text(f'[paths]\nroot = "{self.root}"\n'
                          f'[burp]\nruntime_root = "{self.runtime}"\n', encoding="utf-8")
        out, err = StringIO(), StringIO()
        result = main(["--config", str(config), "burp", "temp-plan"],
                      stdout=out, stderr=err)
        self.assertEqual(result, 0, err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["candidate_count"], 1)
        self.assertFalse((self.root / "state" / "bughunter.sqlite3").exists())


class FixtureBrowser:
    name = "FIXTURE"

    def __init__(self) -> None:
        self.running: set[str] = set()
        self.observations: dict[str, IdentityObservation] = {}
        self.last_proxy = None

    def start(self, session_id, profile, *, display, proxy):
        self.last_proxy = proxy
        self.running.add(session_id)

    def stop(self, session_id):
        self.running.discard(session_id)

    def is_running(self, session_id):
        return session_id in self.running

    def apply_imported_session(self, session_id, material, allowed_url):
        raise AssertionError("No imported session is used in the fixture")

    def observe_identity(self, session_id, rule):
        return self.observations.get(session_id, IdentityObservation())


def observation(capture_id: str, listener: str, *, response: bool = False,
                url: str = "https://app.example.test/api/projects/owned",
                body: bytes | None = None, authenticated: bool = True) -> bytes:
    item = {
        "schema": 1, "capture_id": capture_id,
        "event": "RESPONSE" if response else "REQUEST",
        "listener": listener, "at": datetime.now(timezone.utc).isoformat(),
        "bridge_version": "1.0",
        "request": {
            "method": "GET", "url": url, "http_version": "HTTP/1.1",
            "headers": ([["Authorization", "Bearer bearer-fixture-secret"],
                         ["Cookie", "sid=cookie-fixture-secret"]] if authenticated else [])
                       + [["Accept", "application/json"]],
            "body_b64": None,
        },
    }
    if response:
        item["response"] = {
            "status_code": 200, "http_version": "HTTP/1.1",
            "headers": [["Content-Type", "application/json"],
                        ["Set-Cookie", "sid=response-fixture-secret"]],
            "body_b64": base64.b64encode(body if body is not None else b'{"ok":true}').decode(),
        }
    return json.dumps(item, separators=(",", ":")).encode()


class BurpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "state/bughunter.sqlite3"
        blobs = self.root / "blobs"
        evidence = EvidenceFactStore(self.db, ArtifactStore(blobs), StoreSettings(blobs))
        self.registry = IdentityRegistry(evidence)
        self.registry.initialize()
        self.package = load_target_package(EXAMPLE)
        self.registry.register_target(self.package)
        self.target = self.package.target.id
        self.traffic = TrafficStore(evidence, self.registry)
        self.driver = FixtureBrowser()
        self.auth = AuthContextManager(self.registry, RoutedSecretProvider(SecretSettings(), {}))
        self.browser = BrowserSessionManager(
            self.registry, self.auth, self.driver,
            BrowserSettings(profile_root=self.root / "profiles"),
        )
        self.settings = BurpSettings(True, self.root / "projects", listener_start=38080,
                                     listener_end=38090, bridge_secret_ref="ref:burp_bridge")
        self.proxy = BurpProxyProvider(self.settings, self.traffic, self.browser)
        self.capture = BurpCaptureProvider(self.package, self.proxy, self.traffic)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def session(self, alias: str | None, port: int, *, actual_user: str | None = None,
                verify: bool = True):
        identity = None
        if alias is not None:
            identity = self.registry.register_identity(self.target, alias, status=IdentityStatus.ACTIVE)
            self.auth.prepare(self.target, identity.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        session, binding = self.proxy.provision_session(self.package, identity.id if identity else None,
                                                        port=port)
        self.driver.running.add(session.id)
        if identity is not None and verify:
            self.browser.start(session.id, proxy=self.proxy.proxy_config(port),
                               proxy_health_check=lambda _: True)
            self.browser.login_complete(session.id)
            self.driver.observations[session.id] = IdentityObservation(user_id=actual_user or alias,
                                                                        tenant_id="tenant-a")
            self.browser.verify(session.id, IdentityVerificationRule(
                self.target, identity.id, "[data-user]", None, "[data-tenant]",
                alias, None, "tenant-a"))
        elif identity is None:
            self.browser.start(session.id, proxy=self.proxy.proxy_config(port),
                               proxy_health_check=lambda _: True)
        else:
            self.browser.start(session.id, proxy=self.proxy.proxy_config(port),
                               proxy_health_check=lambda _: True)
        return identity, session, binding

    def test_global_status_aggregates_active_listener_and_recent_bridge(self) -> None:
        _, _, binding = self.session(None, 38080)
        self.capture.ingest_bytes(observation("global-status", binding.listener_key,
                                              authenticated=False))
        with patch.object(self.proxy, "listener_reachable", return_value=True), \
             patch("hackbot.burp.socket.create_connection"):
            status = self.proxy.status()
        self.assertEqual(status["configured_listeners"], 1)
        self.assertEqual(status["reachable_listeners"], 1)
        self.assertTrue(status["bridge_connected"])
        self.assertIsNotNone(status["last_heartbeat_at"])

    def test_cold_start_routes_only_through_anonymous_target_listener(self) -> None:
        identity, verified_session, authenticated = self.session("org1_admin", 38080)
        self.assertIsNotNone(identity)
        adapter = BurpExecutionProxyAdapter(self.proxy)
        action = ProposedAction(self.target, self.package.id, ActionCategory.SAFE_READ,
                                ActorMode.ANONYMOUS, "cold_start_bootstrap",
                                "Bounded first-party discovery read",
                                url="https://example.test/", method="GET")
        with patch.object(self.proxy, "listener_reachable", return_value=True), \
             patch.object(self.proxy, "bridge_connected", return_value=True):
            self.assertIsNone(adapter.route(action))
            _, anonymous, binding = self.session(None, 38081)
            route = adapter.route(action)
            self.assertIsNotNone(route)
            self.assertEqual(route.url, "http://127.0.0.1:38081")
            self.assertNotEqual(binding.listener_key, authenticated.listener_key)
            captured = self.capture.ingest_bytes(observation(
                "cold-start-anonymous", binding.listener_key, response=True,
                authenticated=False))
            exchange = self.traffic.get_exchange(captured.exchange_id)
            self.assertEqual(exchange.attribution.auth_state, AuthState.ANONYMOUS)
            self.assertIsNone(exchange.attribution.verified_identity_id)
            self.assertEqual(exchange.attribution.browser_session_id, anonymous.id)
            authenticated_action = replace(action, actor=ActorMode.AUTHENTICATED,
                                           identity_id=identity.id,
                                           session_id=verified_session.id)
            authenticated_route = adapter.route(authenticated_action)
            self.assertIsNotNone(authenticated_route)
            self.assertEqual(authenticated_route.url, "http://127.0.0.1:38080")
            authenticated_capture = self.capture.ingest_bytes(observation(
                "cold-start-authenticated-control", authenticated.listener_key,
                response=True, authenticated=True))
            authenticated_exchange = self.traffic.get_exchange(authenticated_capture.exchange_id)
            self.assertEqual(authenticated_exchange.attribution.auth_state, AuthState.VERIFIED)
            self.assertEqual(authenticated_exchange.attribution.verified_identity_id, identity.id)
            self.assertIsNone(adapter.route(replace(action, source="unrelated_action")))
            self.assertIsNone(adapter.route(replace(action, target_id=new_entity_id("TARGET"))))
            self.assertIsNone(adapter.route(replace(action, method="POST")))
        with patch.object(self.proxy, "bridge_connected", return_value=False):
            self.assertIsNone(adapter.route(action))

    def test_request_response_incomplete_retry_and_protected_artifacts(self) -> None:
        identity, session, binding = self.session("org1_admin", 38080)
        first = self.capture.ingest_bytes(observation("fixture-1", binding.listener_key))
        self.assertEqual(first.state, ExchangeState.REQUEST_ONLY.value)
        self.assertFalse(first.duplicate)
        self.assertTrue(self.capture.ingest_bytes(observation("fixture-1", binding.listener_key)).duplicate)
        completed = self.capture.ingest_bytes(observation("fixture-1", binding.listener_key,
                                                           response=True))
        self.assertEqual(completed.state, ExchangeState.COMPLETE.value)
        self.assertFalse(completed.duplicate)
        self.assertTrue(self.capture.ingest_bytes(observation("fixture-1", binding.listener_key,
                                                              response=True)).duplicate)
        exchange = self.traffic.get_exchange(completed.exchange_id)
        self.assertEqual(self.proxy.status(self.target)["last_capture_at"],
                         exchange.observed_at.isoformat())
        self.assertEqual(exchange.source, TrafficSource.BURP)
        self.assertEqual(exchange.capture_provider, "MONTOYA_V1")
        self.assertEqual(exchange.attribution.auth_state, AuthState.VERIFIED)
        self.assertEqual(exchange.attribution.verified_identity_id, identity.id)
        self.assertEqual(exchange.attribution.browser_session_id, session.id)
        self.assertEqual(exchange.response.record.status_code, 200)
        self.assertEqual(self.traffic.list_exchanges_for_target(self.target).items[0].id, exchange.id)
        self.assertEqual(len(self.traffic.list_exchanges_for_target(self.target).items), 1)
        request_evidence = self.traffic.evidence.read_content(
            exchange.request.observation_evidence_id, allow_sensitive=True)
        response_evidence = self.traffic.evidence.read_content(
            exchange.response.observation_evidence_id, allow_sensitive=True)
        for secret in (b"bearer-fixture-secret", b"cookie-fixture-secret", b"response-fixture-secret"):
            self.assertNotIn(secret, request_evidence + response_evidence)
        self.assertIn(b"[AUTH_CONTEXT]", request_evidence + response_evidence)
        self.assertEqual(self.traffic.evidence.read_content(
            exchange.response.body_evidence_id, allow_sensitive=True), b'{"ok":true}')
        with sqlite3.connect(self.db) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM burp_capture_index").fetchone()[0], 1)
        self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 48)

    def test_retired_burp_capture_rejects_late_retry_without_rehydrating_payload(self) -> None:
        self.traffic.retention_policy = TrafficRetentionPolicy(1, 1, 1)
        _, _, binding = self.session(None, 38080)
        completed = self.capture.ingest_bytes(
            observation("retired-capture", binding.listener_key, response=True,
                        authenticated=False))
        exchange = self.traffic.get_exchange(completed.exchange_id)
        body_id = exchange.response.body_evidence_id
        future = time.time() + 48 * 3600
        manager = TrafficPayloadRetirementManager(self.traffic.evidence)
        self.assertEqual(manager.plan(now=future).exchange_ids, (exchange.id,))
        self.assertEqual(manager.run(confirmed=True, now=future)["retired_exchanges"], 1)
        for response in (False, True):
            with self.assertRaisesRegex(BurpError, "Retired bridge capture"):
                self.capture.ingest_bytes(
                    observation("retired-capture", binding.listener_key,
                                response=response, authenticated=False))
        with self.traffic.evidence._connection() as db:
            self.assertEqual(db.execute(
                "SELECT count(*) FROM burp_capture_index WHERE exchange_id=?",
                (exchange.id,),
            ).fetchone()[0], 1)
            self.assertEqual(db.execute(
                "SELECT count(*) FROM traffic_exchanges WHERE target_id=?",
                (self.target,),
            ).fetchone()[0], 1)
        with self.assertRaisesRegex(FileNotFoundError, "retired"):
            self.traffic.evidence.read_content(body_id, allow_sensitive=True)

    def test_bridge_persistence_error_is_redacted(self) -> None:
        parsed = BurpObservation.parse(
            observation("persistence-error", "127.0.0.1:38080", authenticated=False),
            self.settings.max_event_bytes,
        )
        with patch.object(self.capture, "_ingest",
                          side_effect=sqlite3.OperationalError("sensitive-local-db-path")):
            with self.assertRaisesRegex(BurpError, "Bridge persistence unavailable") as failure:
                self.capture.ingest(parsed)
        self.assertNotIn("sensitive-local-db-path", str(failure.exception))

    def test_four_sessions_wrong_identity_and_no_cross_attribution(self) -> None:
        cases = [
            ("org1_admin", 38080, AuthState.VERIFIED),
            ("org1_member", 38081, AuthState.VERIFIED),
            ("org2_admin", 38082, AuthState.VERIFIED),
            (None, 38083, AuthState.ANONYMOUS),
            ("wrong_identity", 38084, AuthState.UNVERIFIED_IDENTITY),
            ("pending_identity", 38085, AuthState.UNVERIFIED_IDENTITY),
        ]
        sessions = []
        for alias, port, expected_state in cases:
            identity, session, binding = self.session(
                alias, port, actual_user="someone-else" if alias == "wrong_identity" else None,
                verify=alias != "pending_identity")
            sessions.append((alias, port, expected_state, identity, session, binding))
        with ThreadPoolExecutor(max_workers=6) as executor:
            results = list(executor.map(
                lambda item: self.capture.ingest_bytes(observation(
                    f"capture-{item[1]}", item[5].listener_key,
                    response=True, authenticated=item[0] is not None)), sessions))
        observed = []
        for (_, _, expected_state, identity, session, _), result in zip(sessions, results):
            exchange = self.traffic.get_exchange(result.exchange_id)
            self.assertEqual(exchange.attribution.auth_state, expected_state)
            self.assertEqual(exchange.attribution.browser_session_id, session.id)
            self.assertEqual(exchange.attribution.verified_identity_id,
                             identity.id if expected_state is AuthState.VERIFIED else None)
            observed.append(exchange.id)
        self.assertEqual(len(set(observed)), len(cases))
        self.assertEqual(len(self.traffic.list_exchanges_for_target(self.target, limit=10).items), len(cases))

    def test_listener_uniqueness_unknown_stale_and_conflicting_capture(self) -> None:
        _, session, binding = self.session("owner", 38080)
        with self.assertRaises(BurpError):
            self.proxy.provision_session(self.package, port=38081, listener_key="127.0.0.1:38082")
        with self.assertRaises(BurpError):
            self.proxy.provision_session(self.package, port=38080)
        with self.assertRaises(BurpError):
            self.capture.ingest_bytes(observation("unknown", "127.0.0.1:38090"))
        self.capture.ingest_bytes(observation("same-id", binding.listener_key))
        with self.assertRaises(BurpError):
            self.capture.ingest_bytes(observation("same-id", binding.listener_key,
                                                  url="https://app.example.test/other"))
        self.driver.running.remove(session.id)
        with self.assertRaises(BurpError):
            self.capture.ingest_bytes(observation("stale", binding.listener_key))

    def test_projects_and_listeners_are_isolated_by_target(self) -> None:
        _, _, first = self.session(None, 38080)
        second_package = replace(
            self.package, id="second-fixture",
            target=replace(self.package.target, id=new_entity_id("TARGET"), name="Second Fixture"),
            scope=replace(self.package.scope, package_id="second-fixture"),
        )
        self.registry.register_target(second_package)
        second_proxy = BurpProxyProvider(self.settings, self.traffic, self.browser)
        second_session, second = second_proxy.provision_session(second_package, port=38081)
        self.browser.start(second_session.id, proxy=second_proxy.proxy_config(38081),
                           proxy_health_check=lambda _: True)
        second_capture = BurpCaptureProvider(second_package, second_proxy, self.traffic)
        self.assertNotEqual(self.proxy.register_project(self.package),
                            second_proxy.register_project(second_package))
        with self.assertRaises(BurpError):
            self.capture.ingest_bytes(observation("cross-first", second.listener_key))
        with self.assertRaises(BurpError):
            second_capture.ingest_bytes(observation("cross-second", first.listener_key))
        self.assertEqual(len(self.traffic.list_exchanges_for_target(self.target).items), 0)
        self.assertEqual(len(self.traffic.list_exchanges_for_target(second_package.target.id).items), 0)

    def test_scope_drop_and_metadata_only(self) -> None:
        _, _, binding = self.session(None, 38080)
        dropped = self.capture.ingest_bytes(observation("outside", binding.listener_key,
                                                         url="https://third-party.invalid/private?token=secret"))
        self.assertEqual(dropped.state, "DROPPED_BY_POLICY")
        self.assertIsNone(dropped.exchange_id)
        self.assertEqual(len(self.traffic.list_exchanges_for_target(self.target).items), 0)
        self.proxy.settings = BurpSettings(True, self.root / "projects", listener_start=38080,
                                           listener_end=38090, bridge_secret_ref="ref:burp_bridge",
                                           third_party_capture="METADATA_ONLY")
        result = self.capture.ingest_bytes(observation(
            "outside-metadata", binding.listener_key, response=True,
            url="https://third-party.invalid/private/person?token=secret"))
        exchange = self.traffic.get_exchange(result.exchange_id)
        self.assertEqual(exchange.scope_result.value, "UNKNOWN")
        self.assertEqual(exchange.attribution.auth_state, AuthState.UNVERIFIED_IDENTITY)
        retained = self.traffic.evidence.read_content(exchange.request.observation_evidence_id,
                                                       allow_sensitive=True)
        self.assertNotIn(b"private", retained)
        self.assertNotIn(b"secret", retained)
        self.assertIsNone(exchange.response.body_evidence_id)
        excluded = self.capture.ingest_bytes(observation(
            "excluded-path", binding.listener_key,
            url="https://api.example.test/internal/private?token=secret", authenticated=False))
        excluded_exchange = self.traffic.get_exchange(excluded.exchange_id)
        self.assertEqual(excluded.scope, "OUT_OF_SCOPE")
        self.assertEqual(excluded_exchange.scope_result.value, "OUT_OF_SCOPE")
        excluded_evidence = self.traffic.evidence.read_content(
            excluded_exchange.request.observation_evidence_id, allow_sensitive=True)
        self.assertNotIn(b"internal", excluded_evidence)
        self.assertNotIn(b"private", excluded_evidence)
        self.assertNotIn(b"secret", excluded_evidence)

    def test_schema_limits_and_duplicate_keys(self) -> None:
        valid = observation("fixture", "127.0.0.1:38080")
        self.assertEqual(BurpObservation.parse(observation(
            "019dec18-d5e9-7e93-a999-95f4fecd3891:42", "127.0.0.1:38080"),
            self.settings.max_event_bytes).event, "REQUEST")
        for payload in (b"", b"[]", b"not json", b'{"schema":1,"schema":1}',
                        valid + b"x", b"x" * (self.settings.max_event_bytes + 1)):
            with self.subTest(payload=payload[:20]):
                with self.assertRaises(BurpError):
                    BurpObservation.parse(payload, self.settings.max_event_bytes)
        bad = json.loads(valid)
        bad["request"]["headers"] = [["Cookie", "x"], ["Invalid\nHeader", "y"]]
        with self.assertRaises(BurpError):
            BurpObservation.parse(json.dumps(bad).encode(), self.settings.max_event_bytes)

    def test_project_metadata_and_fail_closed_browser_start(self) -> None:
        session, binding = self.proxy.provision_session(self.package, port=38080)
        self.assertEqual(binding.browser_session_id, session.id)
        self.assertEqual(self.proxy.register_project(self.package),
                         self.root / "projects" / self.target / "project.burp")
        with sqlite3.connect(self.db) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM burp_projects").fetchone()[0], 1)
        with self.assertRaises(BrowserError):
            self.browser.start(session.id, proxy=self.proxy.proxy_config(38080))
        with self.assertRaises(BrowserError):
            self.proxy.start_browser(session.id)
        self.assertFalse(self.driver.is_running(session.id))
        self.assertEqual(self.proxy.availability().value, "BURP_NOT_INSTALLED")

    def test_config_rejects_unsafe_bridge_and_listener_settings(self) -> None:
        with self.assertRaises(ConfigError):
            BurpSettings(True, self.root / "projects", listener_start=38090, listener_end=38080)
        with self.assertRaises(ConfigError):
            BurpSettings(True, self.root / "projects", bridge_port=38080)
        with self.assertRaises(ConfigError):
            BurpSettings(True, self.root / "projects", third_party_capture="FULL")
        with self.assertRaises(ConfigError):
            BurpSettings(True, Path("relative/projects"))

    def test_bridge_requires_live_socket_and_cold_start_releases_wrong_identity(self) -> None:
        _, session, _ = self.session("fixture_a", 38080, actual_user="wrong-user")
        self.assertEqual(self.browser.get(session.id).status.value, "REAUTH_REQUIRED")
        with socket.socket() as endpoint:
            endpoint.bind(("127.0.0.1", 0))
            self.proxy.settings = replace(self.settings, bridge_port=endpoint.getsockname()[1])
            self.proxy.heartbeat(self.target, "1.0")
            self.assertFalse(self.proxy.bridge_connected(self.target))
            endpoint.listen(1)
            self.assertTrue(self.proxy.bridge_connected(self.target))
            self.driver.running.clear()
            self.proxy.reconcile_cold_start()
            self.assertFalse(self.proxy.bridge_connected(self.target))
        self.assertEqual(self.proxy.binding_for_session(session.id).state, "RELEASED")
        self.assertEqual(self.proxy.status(self.target)["configured_listeners"], 0)

    def test_status_separates_proxy_listeners_from_session_assignments(self) -> None:
        with patch.object(self.proxy, "listener_reachable", side_effect=lambda port: port in {38080, 38083}):
            status = self.proxy.status(self.target)
        self.assertEqual(status["proxy_listener_capacity"], 11)
        self.assertEqual(status["proxy_listeners_reachable"], 2)
        self.assertEqual(status["configured_listeners"], 0)
        self.assertEqual(status["reachable_listeners"], 0)

    def test_bridge_http_auth_size_and_heartbeat(self) -> None:
        _, _, binding = self.session(None, 38080)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        settings = BurpSettings(True, self.root / "projects", listener_start=38080,
                                listener_end=38090, bridge_port=port,
                                bridge_secret_ref="ref:burp_bridge", max_event_bytes=4096)
        self.proxy.settings = settings
        secrets = RoutedSecretProvider(SecretSettings(bindings=(SecretBindingConfig(
            "ref:burp_bridge", "env:HACKBOT_SECRET_BURP_BRIDGE", "API_TOKEN"),)),
            {"HACKBOT_SECRET_BURP_BRIDGE": TOKEN})
        server = BurpBridgeServer.from_secret_provider(settings, self.capture, secrets)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            def send(path: str, payload: bytes, token: str = TOKEN):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
                conn.request("POST", path, payload, {"X-Hackbot-Bridge-Token": token,
                                                   "Content-Type": "application/json"})
                response = conn.getresponse()
                body = response.read()
                status = response.status
                conn.close()
                return status, body

            self.assertEqual(send("/v1/capture", b"{}", "invalid")[0], 401)
            self.assertEqual(send("/v1/capture", b"x" * 4097)[0], 413)
            self.assertEqual(send("/v1/capture", b"not-json")[0], 400)
            self.assertEqual(send("/v1/heartbeat", b'{"version":"1.0","dropped_events":2}')[0], 200)
            self.assertTrue(self.proxy.bridge_connected(self.target))
            self.assertEqual(self.proxy.status(self.target)["dropped_events"], 2)
            self.assertEqual(send("/v1/heartbeat", b'{"version":"1.0"}')[0], 200)
            self.assertEqual(self.proxy.status(self.target)["dropped_events"], 2)
            self.assertEqual(send("/v1/heartbeat", b'{"version":"1.0","dropped_events":-1}')[0], 400)
            with socket.create_connection(("127.0.0.1", port), timeout=30) as malformed:
                malformed.sendall(("POST /v1/capture HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                                   f"X-Hackbot-Bridge-Token: {TOKEN}\r\n"
                                   "Content-Type: application/json\r\n"
                                   "Content-Length: 999999999999999999999999999999999999999999\r\n"
                                   "Connection: close\r\n\r\n").encode("ascii"))
                self.assertIn(b"413", malformed.recv(1024))
            code, data = send("/v1/capture", observation("http-1", binding.listener_key))
            self.assertEqual(code, 201)
            self.assertEqual(self.proxy.status(self.target)["dropped_events"], 2)
            self.assertEqual(json.loads(data)["state"], ExchangeState.REQUEST_ONLY.value)
            self.assertEqual(send("/v1/capture", observation("http-1", binding.listener_key))[0], 200)
            self.assertNotIn(TOKEN.encode(), data)
            for _ in range(settings.max_inflight):
                self.assertTrue(server._slots.acquire(timeout=2))
            try:
                inbound, outbound = socket.socketpair()
                try:
                    server.process_request(inbound, ("127.0.0.1", 0))
                    self.assertIn(b"503 Service Unavailable", outbound.recv(1024))
                finally:
                    outbound.close()
            finally:
                for _ in range(settings.max_inflight):
                    server._slots.release()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=30)

    def test_bridge_rejects_invalid_token_and_mismatched_settings(self) -> None:
        with self.assertRaises(BurpError):
            BurpBridgeServer(self.settings, self.capture, SecretValue("short"))
        with self.assertRaises(BurpError):
            BurpBridgeServer(self.settings, self.capture, SecretValue("x" * 31 + "\n"))
        changed = BurpSettings(True, self.root / "projects", bridge_secret_ref="ref:burp_bridge",
                               bridge_port=38778)
        with self.assertRaises(BurpError):
            BurpBridgeServer(changed, self.capture, SecretValue(TOKEN))

    def test_playwright_driver_uses_required_proxy_without_direct_fallback(self) -> None:
        captured = {}

        class Context:
            def close(self):
                pass

        class Chromium:
            def launch_persistent_context(self, profile, **options):
                captured.update(options)
                return Context()

        class Playwright:
            chromium = Chromium()

            def stop(self):
                pass

        class Manager:
            def start(self):
                return Playwright()

        root = types.ModuleType("playwright")
        sync = types.ModuleType("playwright.sync_api")
        sync.sync_playwright = lambda: Manager()
        profile = self.root / "browser-fixture"
        profile.mkdir()
        driver = PlaywrightBrowserDriver()
        with patch.dict(sys.modules, {"playwright": root, "playwright.sync_api": sync}):
            driver.start("fixture", profile, display=None, proxy=self.proxy.proxy_config(38080))
            driver.stop("fixture")
        self.assertEqual(captured["proxy"], {"server": "http://127.0.0.1:38080"})
        self.assertIn("--proxy-bypass-list=<-loopback>", captured["args"])
        self.assertFalse(captured["ignore_https_errors"])

    def test_java_encoder_fixture_matches_python_schema_when_built(self) -> None:
        extension = Path(__file__).resolve().parents[1] / "integrations/burp-extension"
        classes = extension / "build/classes"
        tests = extension / "build/test-classes"
        if shutil.which("java") is None or not classes.is_dir() or not tests.is_dir():
            self.skipTest("Build the optional Montoya extension before running this contract test")
        result = subprocess.run(
            ["java", "-ea", "-cp", f"{classes}:{tests}", "org.bughunter.burp.ExtensionFixture"],
            cwd=extension, capture_output=True, text=True, timeout=10, check=True,
        )
        event = BurpObservation.parse(result.stdout.strip().encode(), self.settings.max_event_bytes)
        self.assertEqual(event.event, "RESPONSE")
        self.assertEqual(event.response.status_code, 200)
        self.assertEqual(event.capture_id,
                         "019dec18-d5e9-7e93-a999-95f4fecd3891:127.0.0.1:38080:42")

    def test_cli_local_status_check_and_listeners(self) -> None:
        _, session, binding = self.session(None, 38080)
        config = self.root / "config.toml"
        config.write_text(
            f'[paths]\nroot = "{self.root}"\n'
            f'[targets]\nroot = "{EXAMPLE.parent}"\n'
            '[burp]\nenabled = true\n', encoding="ascii")

        def run(args):
            out, err = StringIO(), StringIO()
            code = main(["--config", str(config), "burp", *args],
                        environ={"HOME": str(self.root)}, stdout=out, stderr=err)
            return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()

        code, checked, error = run(["check"])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(checked["availability"], "BURP_NOT_INSTALLED")
        code, status, error = run(["status", "example"])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(status["target_id"], self.target)
        self.assertEqual(status["captured_exchanges"], 0)
        code, listeners, error = run(["listeners", "example"])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(listeners["items"][0]["browser_session_id"], session.id)
        self.assertEqual(listeners["items"][0]["listener_key"], binding.listener_key)
        code, bridge, error = run(["bridge", "status", "example"])
        self.assertEqual((code, error), (0, ""))
        self.assertFalse(bridge["connected"])
        self.assertEqual(bridge["dropped_events"], 0)

    def test_profile_ca_does_not_use_system_store(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("OpenSSL fixture generator unavailable")
        profile = self.root / "profiles" / "owned-session"
        profile.mkdir(parents=True)
        cert = self.root / "ca.pem"
        key = self.root / "unused-key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1",
                        "-subj", "/CN=Fixture Burp CA"], capture_output=True, check=True, timeout=10)
        with patch("hackbot.browser_trust.shutil.which", return_value=None):
            with self.assertRaises(ProfileTrustError):
                install_profile_ca(profile, cert)
        self.assertFalse((profile.parent / ".pki").exists())

        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 1 if "-L" in command else 0)

        with patch("hackbot.browser_trust.shutil.which", return_value="/usr/bin/certutil"), \
                patch("hackbot.browser_trust.subprocess.run", side_effect=fake_run):
            install_profile_ca(profile, cert)
        self.assertEqual(len(calls), 3)
        expected_db = "sql:" + str(profile.parent / ".pki/nssdb")
        self.assertTrue(all(expected_db in command for command, _ in calls))
        self.assertTrue(all("/etc/" not in " ".join(command) for command, _ in calls))

    def test_loopback_fixture_proxy_browser_app_bridge_store(self) -> None:
        app_hits = []
        loopback_timeout = 30

        class AppHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                app_hits.append(self.path)
                body = b"local-fixture-response"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        app = ThreadingHTTPServer(("127.0.0.1", 0), AppHandler)
        app_thread = threading.Thread(target=app.serve_forever, daemon=True)
        app_thread.start()
        bridge_port = 0
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            bridge_port = sock.getsockname()[1]

        class ProxyHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                local = http.client.HTTPConnection(
                    "127.0.0.1", app.server_address[1], timeout=loopback_timeout)
                local.request("GET", "/local-fixture")
                response = local.getresponse()
                body = response.read()
                local.close()
                event = observation("loopback-capture-1", f"127.0.0.1:{self.server.server_port}",
                                    response=True, url=self.path, body=body, authenticated=False)
                channel = http.client.HTTPConnection(
                    "127.0.0.1", bridge_port, timeout=loopback_timeout)
                channel.request("POST", "/v1/capture", event,
                                {"X-Hackbot-Bridge-Token": TOKEN, "Content-Type": "application/json"})
                receipt = channel.getresponse()
                receipt.read()
                status = receipt.status
                channel.close()
                if status != 201:
                    self.send_error(502)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        proxy_server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        proxy_port = proxy_server.server_address[1]
        self.proxy.settings = BurpSettings(True, self.root / "projects", listener_start=proxy_port,
                                           listener_end=proxy_port, bridge_port=bridge_port,
                                           bridge_secret_ref="ref:burp_bridge")
        _, session, _ = self.session(None, proxy_port)
        bridge = BurpBridgeServer(self.proxy.settings, self.capture, SecretValue(TOKEN))
        proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
        bridge_thread = threading.Thread(target=bridge.serve_forever, daemon=True)
        proxy_thread.start()
        bridge_thread.start()
        try:
            client = http.client.HTTPConnection(
                "127.0.0.1", proxy_port, timeout=loopback_timeout + 15)
            client.request("GET", "https://app.example.test/local-fixture")
            reply = client.getresponse()
            self.assertEqual(reply.status, 200)
            self.assertEqual(reply.read(), b"local-fixture-response")
            client.close()
            exchange = self.traffic.list_exchanges_for_session(self.target, session.id).items[0]
            self.assertEqual(exchange.state, ExchangeState.COMPLETE)
            self.assertEqual(exchange.attribution.auth_state, AuthState.ANONYMOUS)
            self.assertEqual(exchange.source, TrafficSource.BURP)
            self.assertEqual(app_hits, ["/local-fixture"])
            proxy_server.shutdown()
            proxy_server.server_close()
            proxy_thread.join(timeout=3)
            with self.assertRaises((ConnectionRefusedError, OSError)):
                direct = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=1)
                direct.request("GET", "https://app.example.test/local-fixture")
            self.assertEqual(app_hits, ["/local-fixture"])
        finally:
            if proxy_thread.is_alive():
                proxy_server.shutdown()
            proxy_server.server_close()
            bridge.shutdown()
            bridge.server_close()
            app.shutdown()
            app.server_close()
            for thread in (proxy_thread, bridge_thread, app_thread):
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
