from __future__ import annotations

from dataclasses import replace
from datetime import timedelta, datetime, timezone
import gzip
import hashlib
import http.client
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.auth import AuthContextManager, AuthMechanism, AuthStatus
from hackbot.browser import BrowserSessionManager, IdentityObservation, IdentityVerificationRule
from hackbot.config import (BrowserSettings, ExecutorSettings, SecretBindingConfig,
                            SecretSettings, StoreSettings)
from hackbot.domxss import DOMAcquisitionStatus, DOMXSSSpecialist
from hackbot.domxss_store import DOMXSSStore
from hackbot.executor import (ExecutionError, ProxyRoute, RequestTemplate, TrafficExecutor)
from hackbot.identity import IdentityStatus
from hackbot.identity_registry import IdentityRegistry
from hackbot.permit_store import PermitError, PolicyPermitStore
from hackbot.policy import PolicyEngine
from hackbot.policy_models import ActionCategory, ActorMode, ProposedAction
from hackbot.policy_store import PolicyStore
from hackbot.rate_limit import ExperimentBudget, RateLimiter
from hackbot.recon import Page, Provenance, ReconJsAsset, ReconTarget
from hackbot.secrets import RoutedSecretProvider
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package
from hackbot.target_policy import RatePolicy
from hackbot.target_policy import PolicyDecision
from hackbot.target_scope import HostRule
from hackbot.traffic import AuthState, ExchangeState, TrafficStore


EXAMPLE = Path(__file__).parent / "examples/targets/example"
SECRET = "fixture-cookie=very-private-test-value"


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _answer(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def do_GET(self):
        self.server.received.append(("GET", self.path, self.headers.get("Cookie")))
        if self.path == "/assets/app.js":
            return self._answer(200, b'const api_key="fixture-secret";location.search;iframe.src;\n'
                                b'//# sourceMappingURL=app.js.map',
                                (("Content-Type", "application/javascript"),))
        if self.path == "/assets/app.js.map":
            return self._answer(200, b'{"version":3,"sources":["app.js"],"mappings":"AAAA"}',
                                (("Content-Type", "application/json"),))
        if self.path == "/assets/fallback.js":
            return self._answer(200, b"<html>fallback</html>", (("Content-Type", "text/html"),))
        if self.path.startswith("/fixture/"):
            parts = self.path.split("/")
            if (len(parts) == 6 and parts[3] == "projects" and parts[4] == "batch"):
                identifiers = parts[5].split(",")
                if len(identifiers) != 2 or identifiers[0] == identifiers[1]:
                    return self._answer(400, b"{}", (("Content-Type", "application/json"),))
                items = []
                for identifier in identifiers:
                    item = self.server.fixture_objects.get(identifier)
                    if item is None or item["type"] != "project":
                        continue
                    if (getattr(self.server, "fixture_batch_vulnerable", False) or
                            self.headers.get("Cookie") == "fixture_actor=" + item["owner"]):
                        items.append(item)
                return self._answer(200, json.dumps({"items": items}).encode(),
                                    (("Content-Type", "application/json"),))
            if (len(parts) == 7 and parts[3] == "projects" and
                    parts[5] == "dashboards"):
                parent = self.server.fixture_objects.get(parts[4])
                child = self.server.fixture_objects.get(parts[6])
                if (parent is None or child is None or parent["type"] != "project" or
                        child["type"] != "dashboard" or
                        child.get("parentId") is None):
                    return self._answer(404, b"{}", (("Content-Type", "application/json"),))
                cookie = self.headers.get("Cookie")
                child_owner = cookie == "fixture_actor=" + child["owner"]
                parent_owner = cookie == "fixture_actor=" + parent["owner"]
                if (not child_owner and not (getattr(self.server, "fixture_nested_vulnerable", False)
                                             and parent_owner)):
                    return self._answer(403, b'{"error":"forbidden"}',
                                        (("Content-Type", "application/json"),))
                body = {key: child[key] for key in ("id", "parentId", "owner", "tenant")}
                return self._answer(200, json.dumps(body).encode(),
                                    (("Content-Type", "application/json"),))
            if len(parts) == 5 and parts[3] in {"projects", "dashboards", "documents"}:
                item = self.server.fixture_objects.get(parts[4])
                if item is None or item["tenant"] != parts[2] or item["type"] != parts[3][:-1]:
                    return self._answer(404, b"{}", (("Content-Type", "application/json"),))
                if getattr(self.server, "fixture_drop_get_response", False):
                    self.server.fixture_drop_get_response = False
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                if getattr(self.server, "fixture_fail_next_get", False):
                    self.server.fixture_fail_next_get = False
                    return self._answer(503, b'{"error":"read unavailable"}',
                                        (("Content-Type", "application/json"),))
                if getattr(self.server, "fixture_secure", False) and (
                    self.headers.get("Cookie") != "fixture_actor=" + item["owner"]
                ):
                    return self._answer(403, b'{"error":"forbidden"}',
                                        (("Content-Type", "application/json"),))
                return self._answer(200, json.dumps(item).encode(), (("Content-Type", "application/json"),))
        if self.path in {"/validated/object-a", "/validated/object-a-alt"}:
            return self._answer(200, b'{"id":"object-a","tenantId":"tenant-a","payload":"owned-fixture"}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/object-b":
            return self._answer(200, b'{"id":"object-b","tenantId":"tenant-b","payload":"other-fixture"}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/object-c":
            return self._answer(200, b'{"id":"object-c","tenantId":"tenant-a","payload":"role-fixture"}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/private-file":
            return self._answer(200, b"disposable-fixture-file", (("Content-Type", "application/octet-stream"),))
        if self.path == "/validated/example-key":
            return self._answer(200, b'{"api_key":"example"}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/missing":
            return self._answer(404, b"missing", (("Content-Type", "text/plain"),))
        if self.path == "/validated/denied":
            return self._answer(403, b"denied", (("Content-Type", "text/plain"),))
        if self.path == "/validated/graphql":
            return self._answer(200, b'{"data":{"node":{"id":"object-a","tenantId":"tenant-a"}}}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/graphql-invalid":
            return self._answer(200, b'{"data":{"node":null},"errors":[{"message":"not found"}]}',
                                (("Content-Type", "application/json"),))
        if self.path == "/tenant-a/object-a":
            allowed = self.headers.get("Cookie") == "fixture_actor=tenant_a_admin"
            return self._answer(200 if allowed else 403, b"owned-object-a" if allowed else b"denied")
        if self.path == "/tenant-b/object-b":
            allowed = self.headers.get("Cookie") == "fixture_actor=tenant_b_admin"
            return self._answer(200 if allowed else 403, b"owned-object-b" if allowed else b"denied")
        if self.path == "/redirect-out":
            return self._answer(302, headers=(("Location", "http://localhost:9/foreign"),))
        if self.path == "/redirect-in":
            return self._answer(302, headers=(("Location", "/ok"),))
        if self.path == "/large":
            return self._answer(200, b"A" * 10000)
        if self.path == "/gzip":
            body = gzip.compress(b"B" * 10000)
            return self._answer(200, body, (("Content-Encoding", "gzip"),))
        if self.path == "/sleep":
            time.sleep(0.4)
        if self.path == "/cookie":
            return self._answer(200 if self.headers.get("Cookie") == SECRET else 401, b"fixture")
        return self._answer(200, b"fixture", (("Content-Type", "text/plain"),))

    def do_POST(self):
        self.server.received.append(("POST", self.path, self.headers.get("Cookie")))
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        if self.path == "/fixture/graphql":
            try:
                payload = json.loads(body)
                value = payload["variables"]["id"]
            except (KeyError, TypeError, ValueError):
                return self._answer(400, b'{}', (("Content-Type", "application/json"),))
            item = self.server.fixture_objects.get(value)
            if item is None:
                result = {"data": {"node": None}, "errors": [{"message": "not found"}]}
            elif (getattr(self.server, "fixture_secure", False) and
                  self.headers.get("Cookie") != "fixture_actor=" + item["owner"]):
                result = {"data": {"node": None}, "errors": [{"message": "forbidden"}]}
            else:
                if str(payload.get("query", "")).lstrip().startswith("mutation "):
                    name = payload["variables"].get("name", payload["variables"].get("newName"))
                    if not isinstance(name, str):
                        return self._answer(400, b'{}', (("Content-Type", "application/json"),))
                    if not getattr(self.server, "fixture_noop_mutation", False) and not (
                            getattr(self.server, "fixture_graphql_boundary_noop", False) and
                            self.headers.get("Cookie") == "fixture_actor=tenant_b_admin"):
                        item["name"] = name
                result = {"data": {"node": item}}
            return self._answer(200, json.dumps(result).encode(),
                                (("Content-Type", "application/json"),))
        if self.path.startswith("/fixture/"):
            parts = self.path.split("/")
            if len(parts) == 4 and parts[3] in {"projects", "dashboards", "documents", "projects-ambiguous"}:
                try:
                    data = json.loads(body)
                except ValueError:
                    return self._answer(400)
                if not isinstance(data, dict) or not isinstance(data.get("name"), str):
                    return self._answer(400)
                cookie = self.headers.get("Cookie") or ""
                identity = ("tenant_a_admin" if parts[2] == "tenant-a" else "tenant_b_admin") \
                    if cookie == SECRET else cookie.removeprefix("fixture_actor=")
                if identity not in {"tenant_a_admin", "tenant_a_member", "tenant_b_admin"}:
                    return self._answer(401)
                value = f"fixture{len(self.server.fixture_objects) + 1}"
                item = {"id": value, "name": data["name"], "owner": identity,
                        "tenant": parts[2], "type": "project" if parts[3] == "projects-ambiguous"
                        else parts[3][:-1]}
                self.server.fixture_objects[value] = item
                if self.path.endswith("projects-ambiguous"):
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                return self._answer(201, json.dumps(item).encode(), (("Content-Type", "application/json"),))
        if self.path == "/validated/graphql":
            return self._answer(200, b'{"data":{"node":{"id":"object-a","tenantId":"tenant-a"}}}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/graphql-invalid":
            return self._answer(200, b'{"data":{"node":null},"errors":[{"message":"not found"}]}',
                                (("Content-Type", "application/json"),))
        if self.path == "/create":
            self.server.created.append(body)
        self._answer(201, b"created")

    def do_PATCH(self):
        self.server.received.append(("PATCH", self.path, self.headers.get("Cookie")))
        parts = self.path.split("/")
        if len(parts) == 5 and parts[3] in {"projects", "dashboards"}:
            item = self.server.fixture_objects.get(parts[4])
            if item is not None and item["tenant"] == parts[2]:
                if (getattr(self.server, "fixture_csrf_required", False) and
                        self.headers.get("X-CSRF-Token") != "fixture-csrf-secret-token"):
                    return self._answer(403, b'{"error":"csrf"}',
                                        (("Content-Type", "application/json"),))
                if (getattr(self.server, "fixture_secure", False) and
                        self.headers.get("Cookie") != "fixture_actor=" + item["owner"]):
                    return self._answer(403, b'{"error":"forbidden"}',
                                        (("Content-Type", "application/json"),))
                data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                if (getattr(self.server, "fixture_fail_restore", False) and
                        data.get("name") == getattr(self.server, "fixture_restore_value", None)):
                    return self._answer(403, b'{"error":"restore blocked"}',
                                        (("Content-Type", "application/json"),))
                if not getattr(self.server, "fixture_noop_mutation", False):
                    item["name"] = data.get("name", item["name"])
                if getattr(self.server, "fixture_fail_mutation_readback", False):
                    self.server.fixture_fail_mutation_readback = False
                    self.server.fixture_fail_next_get = True
                if getattr(self.server, "fixture_drop_patch_response", False):
                    self.server.fixture_drop_patch_response = False
                    if getattr(self.server, "fixture_drop_recovery_get", False):
                        self.server.fixture_drop_get_response = True
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                return self._answer(200, json.dumps(item).encode(), (("Content-Type", "application/json"),))
        self._answer(404)

    def do_DELETE(self):
        self.server.received.append(("DELETE", self.path, self.headers.get("Cookie")))
        parts = self.path.split("/")
        if len(parts) == 5 and parts[3] in {"projects", "dashboards"}:
            item = self.server.fixture_objects.get(parts[4])
            if item is not None and item["tenant"] == parts[2]:
                del self.server.fixture_objects[parts[4]]
                if self.server.drop_delete_response:
                    self.server.drop_delete_response = False
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                return self._answer(204)
        self._answer(404)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.received.append(self.path)
        target = self.server.target
        connection = http.client.HTTPConnection("127.0.0.1", target.server_port, timeout=1)
        try:
            connection.request("GET", "/ok")
            response = connection.getresponse()
            body = response.read()
        finally:
            connection.close()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeDriver:
    name = "FIXTURE"

    def __init__(self):
        self.running = set()
        self.observations = {}

    def start(self, session_id, profile, *, display, proxy):
        self.running.add(session_id)

    def stop(self, session_id):
        self.running.discard(session_id)

    def is_running(self, session_id):
        return session_id in self.running

    def is_available(self):
        return True

    def observe_identity(self, session_id, rule):
        return self.observations.get(session_id, IdentityObservation())


class FakeTargets:
    def __init__(self, package):
        self.package = package

    def get_target_package(self, package_id):
        return self.package if self.package.id == package_id else None


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        self.server.received = []
        self.server.created = []
        self.server.fixture_objects = {}
        self.server.fixture_secure = False
        self.server.fixture_noop_mutation = False
        self.server.fixture_graphql_boundary_noop = False
        self.server.fixture_csrf_required = False
        self.server.fixture_drop_patch_response = False
        self.server.fixture_drop_get_response = False
        self.server.fixture_drop_recovery_get = False
        self.server.fixture_nested_vulnerable = False
        self.server.fixture_batch_vulnerable = False
        self.server.fixture_fail_restore = False
        self.server.fixture_fail_mutation_readback = False
        self.server.fixture_fail_next_get = False
        self.server.fixture_restore_value = None
        self.server.drop_delete_response = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        base_package = load_target_package(EXAMPLE)
        self.package = replace(
            base_package,
            scope=replace(base_package.scope, include_hosts=(HostRule("127.0.0.1"),),
                          exclude_hosts=(), exclude_paths=(), default_schemes=("http",),
                          default_ports=(self.server.server_port,)),
            rate=RatePolicy(requests_per_second=100, requests_per_minute=100,
                            max_concurrency=2, burst=100),
        )
        self.targets = FakeTargets(self.package)
        blobs = self.root / "blobs"
        self.store = EvidenceFactStore(self.root / "state/bughunter.sqlite3",
                                       ArtifactStore(blobs), StoreSettings(blobs))
        self.store.initialize()
        self.registry = IdentityRegistry(self.store)
        self.registry.register_target(self.package)
        self.secret_env = {"HACKBOT_SECRET_COOKIE": SECRET}
        self.provider = RoutedSecretProvider(
            SecretSettings(bindings=(SecretBindingConfig(
                "ref:fixture_cookie", "env:HACKBOT_SECRET_COOKIE", "COOKIE"),)),
            self.secret_env,
        )
        self.auth = AuthContextManager(self.registry, self.provider)
        self.driver = FakeDriver()
        self.browser = BrowserSessionManager(
            self.registry, self.auth, self.driver,
            BrowserSettings(profile_root=self.root / "profiles"),
        )
        self.rate = RateLimiter()
        self.policy = PolicyEngine(registry=self.registry, browser=self.browser,
                                   audit=PolicyStore(self.store), rate=self.rate)
        self.permits = PolicyPermitStore(self.store)
        self.traffic = TrafficStore(self.store, self.registry)
        self.executor = TrafficExecutor(
            targets=self.targets, policy=self.policy, permits=self.permits,
            rate=self.rate, traffic=self.traffic, auth=self.auth, secrets=self.provider,
            settings=ExecutorSettings(allow_direct=True, max_response_bytes=1024,
                                      connect_timeout_seconds=0.2, read_timeout_seconds=0.2,
                                      overall_timeout_seconds=2),
            browser=self.browser,
        )

    def action(self, path="/ok", *, method="GET", actor=ActorMode.ANONYMOUS,
               identity_id=None, session_id=None, category=ActionCategory.SAFE_READ):
        return ProposedAction(
            target_id=self.package.target.id, package_id=self.package.id,
            category=category, actor=actor, source="unit_test", purpose="Local fixture check",
            url=self.base + path, method=method, identity_id=identity_id, session_id=session_id,
        )

    def run_action(self, action, *, template=None, permit=None, **kwargs):
        template = template or RequestTemplate(action.method, action.url)
        permit = permit or self.executor.authorize(action, template)
        return self.executor.execute(action, permit, template, **kwargs)

    def owned_session(self, alias, *, secret_ref="ref:fixture_cookie"):
        identity = self.registry.register_identity(
            self.package.target.id, alias, status=IdentityStatus.ACTIVE,
            secret_ref=secret_ref,
        )
        self.auth.prepare(self.package.target.id, identity.id)
        session = self.browser.create(self.package.target.id, identity.id)
        self.browser.start(session.id)
        self.browser.login_complete(session.id)
        self.driver.observations[session.id] = IdentityObservation(user_id=alias, tenant_id=alias)
        rule = IdentityVerificationRule(self.package.target.id, identity.id,
                                        "[data-user]", None, "[data-tenant]", alias, None, alias)
        self.browser.verify(session.id, rule)
        return identity, session

    def test_no_permit_wrong_binding_expiry_and_reuse_send_zero_extra(self):
        action = self.action()
        template = RequestTemplate("GET", action.url)
        denied = self.executor.execute(action, None, template)
        self.assertEqual(denied.error, ExecutionError.PERMIT_DENIED)
        self.assertEqual(self.server.received, [])
        with self.store._connection() as db:
            rows = db.execute("SELECT event_type FROM executor_events WHERE action_id=? ORDER BY event_id",
                              (action.id,)).fetchall()
        self.assertEqual([row[0] for row in rows], ["EXECUTION_REQUESTED", "EXECUTION_FAILED"])
        permit = self.executor.authorize(action, template)
        wrong = replace(permit, target_id="TARGET-" + "9" * 32)
        self.assertEqual(self.executor.execute(action, wrong, template).error, ExecutionError.PERMIT_DENIED)
        wrong_identity = replace(permit, identity_id="IDENTITY-" + "8" * 32)
        self.assertEqual(self.executor.execute(action, wrong_identity, template).error, ExecutionError.PERMIT_DENIED)
        expired = replace(permit, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        self.assertEqual(self.executor.execute(action, expired, template).error, ExecutionError.PERMIT_DENIED)
        changed = replace(template, headers=(("Accept", "application/json"),))
        self.assertEqual(self.executor.execute(action, permit, changed).error, ExecutionError.PERMIT_DENIED)
        self.assertEqual(self.server.received, [])
        good = self.executor.execute(action, permit, template)
        self.assertEqual((good.error, good.status_code), (None, 200))
        self.assertEqual(self.executor.execute(action, permit, template).error, ExecutionError.PERMIT_DENIED)
        self.assertEqual(len(self.server.received), 1)
        self.assertEqual(self.traffic.get_exchange(good.exchange_ids[0]).state, ExchangeState.COMPLETE)

    def test_protected_asset_capture_is_typed_and_local_only(self):
        action = self.action("/assets/app.js")
        result = self.run_action(action, artifact_capture_kind="JS")
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.artifact_evidence_id)
        self.assertIn(b"fixture-secret", self.store.read_content(
            result.artifact_evidence_id, allow_sensitive=True))
        self.assertEqual(len(result.exchange_ids), 1)

        map_action = self.action("/assets/app.js.map")
        source_map = self.run_action(map_action, artifact_capture_kind="SOURCE_MAP")
        self.assertIsNotNone(source_map.artifact_evidence_id)
        fallback = self.run_action(self.action("/assets/fallback.js"), artifact_capture_kind="JS")
        self.assertIsNone(fallback.artifact_evidence_id)
        invalid = self.run_action(self.action("/assets/app.js"), artifact_capture_kind="SOURCE_MAP")
        self.assertIsNone(invalid.artifact_evidence_id)

    def test_dom_specialist_acquires_once_through_policy_executor(self):
        body = (b'const api_key="fixture-secret";location.search;iframe.src;\n'
                b'//# sourceMappingURL=app.js.map')
        digest = hashlib.sha256(body).hexdigest()
        asset = ReconJsAsset(91, 7, self.base + "/assets/app.js", digest, len(body), 200,
                             Provenance("js_assets", 91, None, "fixture"))

        class LocalRecon:
            def resolve_target(self, _name):
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, None, "fixture"))

            def list_js_assets(self, _domain_id, _host_id, *, limit, cursor=None):
                return Page((asset,), None)

            def get_js_asset(self, _domain_id, asset_id):
                return asset if asset_id == asset.asset_id else None

        specialist = DOMXSSSpecialist(recon=LocalRecon(), targets=self.targets,
                                      executor=self.executor, store=DOMXSSStore(self.store))
        first = specialist.acquire(self.package.id, asset)
        self.assertEqual(first.status, DOMAcquisitionStatus.RETRIEVED)
        self.assertEqual(first.artifact.artifact_sha256, digest)
        self.assertEqual(len(first.exchange_ids), 1)
        self.assertEqual(len(self.server.received), 1)
        second = specialist.acquire(self.package.id, asset)
        self.assertEqual(second.status, DOMAcquisitionStatus.REUSED)
        self.assertEqual(len(self.server.received), 1)
        source_map = specialist.acquire_source_map(self.package.id, asset, first.artifact)
        self.assertEqual(source_map.status, DOMAcquisitionStatus.RETRIEVED)
        self.assertEqual(len(self.server.received), 2)
        reused_map = specialist.acquire_source_map(self.package.id, asset, first.artifact)
        self.assertEqual(reused_map.status, DOMAcquisitionStatus.REUSED)
        self.assertEqual(len(self.server.received), 2)

    def test_scope_policy_change_and_redirects(self):
        out = self.action("/redirect-out")
        result = self.run_action(out)
        self.assertEqual(result.error, ExecutionError.REDIRECT_DENIED)
        self.assertEqual(len(self.server.received), 1)
        self.assertEqual(len(result.redirects), 1)
        self.assertFalse(result.redirects[0].followed)
        inside = self.run_action(self.action("/redirect-in"))
        self.assertIsNone(inside.error)
        self.assertEqual([row[1] for row in self.server.received[-2:]], ["/redirect-in", "/ok"])
        action = self.action()
        template = RequestTemplate("GET", action.url)
        permit = self.executor.authorize(action, template)
        self.targets.package = replace(self.package, scope=replace(
            self.package.scope, include_hosts=(HostRule("localhost"),)))
        before = len(self.server.received)
        denied = self.executor.execute(action, permit, template)
        self.assertIn(denied.error, {ExecutionError.SCOPE_DENIED, ExecutionError.POLICY_DENIED})
        self.assertEqual(len(self.server.received), before)

    def test_anonymous_and_verified_cookie_isolation(self):
        identity, session = self.owned_session("tenant_a_admin")
        auth_action = self.action("/cookie", actor=ActorMode.AUTHENTICATED,
                                  identity_id=identity.id, session_id=session.id)
        authenticated = self.run_action(auth_action)
        self.assertEqual((authenticated.error, authenticated.status_code), (None, 200))
        self.assertEqual(self.traffic.get_exchange(authenticated.exchange_ids[0]).attribution.auth_state,
                         AuthState.VERIFIED)
        self.assertNotIn(SECRET.encode(), self.store.db_path.read_bytes())
        anonymous = self.run_action(self.action("/cookie"))
        self.assertEqual((anonymous.error, anonymous.status_code), (None, 401))
        self.assertIsNone(self.server.received[-1][2])
        self.assertNotIn(SECRET, repr(authenticated))
        self.assertNotIn(SECRET, repr(self.traffic.get_exchange(authenticated.exchange_ids[0])))

    def test_unverified_expired_missing_and_manual_auth_send_nothing(self):
        identity, session = self.owned_session("tenant_a_member")
        action = self.action("/cookie", actor=ActorMode.AUTHENTICATED,
                             identity_id=identity.id, session_id=session.id)
        template = RequestTemplate("GET", action.url)
        permit = self.executor.authorize(action, template)
        self.auth.set_status(self.package.target.id, identity.id, AuthStatus.EXPIRED)
        self.assertIn(self.executor.execute(action, permit, template).error,
                      {ExecutionError.POLICY_DENIED, ExecutionError.AUTH_UNAVAILABLE})
        self.assertEqual(self.server.received, [])
        self.driver.running.clear()
        with self.assertRaises(PermitError):
            self.executor.authorize(replace(action, id=action.id.replace("a", "b", 1)), template)

    def test_missing_secret_and_manual_login_do_not_send(self):
        identity, session = self.owned_session("tenant_b_admin")
        action = self.action("/cookie", actor=ActorMode.AUTHENTICATED,
                             identity_id=identity.id, session_id=session.id)
        template = RequestTemplate("GET", action.url)
        permit = self.executor.authorize(action, template)
        self.secret_env.clear()
        self.assertEqual(self.executor.execute(action, permit, template).error,
                         ExecutionError.AUTH_UNAVAILABLE)
        self.assertEqual(self.server.received, [])
        self.assertEqual(self.executor.execute(action, permit, template).error,
                         ExecutionError.PERMIT_DENIED)

        manual = self.registry.register_identity(
            self.package.target.id, "manual_user", status=IdentityStatus.ACTIVE)
        self.auth.prepare(self.package.target.id, manual.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        browser_session = self.browser.create(self.package.target.id, manual.id)
        self.browser.start(browser_session.id)
        self.browser.login_complete(browser_session.id)
        self.driver.observations[browser_session.id] = IdentityObservation(user_id="manual_user")
        self.browser.verify(browser_session.id, IdentityVerificationRule(
            self.package.target.id, manual.id, "[data-user]", None, None,
            "manual_user", None, None))
        manual_action = self.action(actor=ActorMode.AUTHENTICATED,
                                    identity_id=manual.id, session_id=browser_session.id)
        self.assertEqual(self.run_action(manual_action).error, ExecutionError.AUTH_UNAVAILABLE)
        self.assertEqual(self.server.received, [])

    def test_body_cap_gzip_and_timeout(self):
        for path in ("/large", "/gzip"):
            result = self.run_action(self.action(path))
            self.assertIsNone(result.error)
            self.assertTrue(result.truncated)
            self.assertEqual(result.body_bytes_captured, 1024)
        timeout = self.run_action(self.action("/sleep"))
        self.assertEqual(timeout.error, ExecutionError.TIMEOUT)
        self.assertEqual(self.traffic.get_exchange(timeout.exchange_ids[0]).state, ExchangeState.TIMEOUT)

    def test_budget_rate_proxy_and_direct_mode(self):
        first = self.run_action(self.action(), experiment_id="test_budget",
                                budget=ExperimentBudget(max_requests=1))
        self.assertIsNone(first.error)
        second = self.run_action(self.action(), experiment_id="test_budget",
                                 budget=ExperimentBudget(max_requests=1))
        self.assertIn(second.error, {ExecutionError.POLICY_DENIED, ExecutionError.RATE_LIMITED})
        before = len(self.server.received)
        self.executor.settings = ExecutorSettings(allow_direct=False, capture_required=True)
        blocked = self.run_action(self.action())
        self.assertEqual(blocked.error, ExecutionError.PROXY_UNAVAILABLE)
        self.assertEqual(len(self.server.received), before)

    def test_proxy_route_and_approval_backed_post(self):
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        proxy.received = []
        proxy.target = self.server
        worker = threading.Thread(target=proxy.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(proxy.server_close)
        self.addCleanup(proxy.shutdown)

        class LocalProxy:
            def route(self, action):
                return ProxyRoute(f"http://127.0.0.1:{proxy.server_port}")

        self.executor.proxy = LocalProxy()
        self.executor.settings = ExecutorSettings(capture_required=True, max_response_bytes=1024)
        result = self.run_action(self.action())
        self.assertIsNone(result.error)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(proxy.received), 1)
        self.assertEqual(self.server.received[-1][1], "/ok")

        self.executor.proxy = None
        self.executor.settings = ExecutorSettings(allow_direct=True, max_response_bytes=1024)
        self.targets.package = replace(
            self.package, autonomy=replace(self.package.autonomy,
                                           state_changing=PolicyDecision.REQUIRE_APPROVAL,
                                           create_disposable_objects=PolicyDecision.REQUIRE_APPROVAL),
        )
        action = self.action("/create", method="POST", category=ActionCategory.OBJECT_CREATE)
        action = replace(action, disposable_intent=True, object_type="fixture")
        template = RequestTemplate("POST", action.url, (("Content-Type", "application/json"),), b'{"name":"fixture"}')
        decision = self.policy.evaluate(self.targets.package, action, record=True)
        self.assertEqual(decision.result, PolicyDecision.REQUIRE_APPROVAL)
        PolicyStore(self.store).decide(decision.approval_id, action.target_id, approve=True)
        permit = self.executor.authorize(action, template)
        executed = self.executor.execute(action, permit, template)
        self.assertEqual((executed.error, executed.status_code, executed.approval_id),
                         (None, 201, decision.approval_id))
        self.assertEqual(PolicyStore(self.store).get(decision.approval_id, action.target_id).status.value,
                         "CONSUMED")
        self.assertEqual(self.server.received[-1][:2], ("POST", "/create"))
        self.assertEqual(self.server.created, [b'{"name":"fixture"}'])

    def test_shared_rate_concurrency_blocks_second_request(self):
        self.targets.package = replace(self.package, rate=replace(self.package.rate, max_concurrency=1))
        first_action = self.action("/sleep")
        first_template = RequestTemplate("GET", first_action.url)
        first_permit = self.executor.authorize(first_action, first_template)
        outcome = []
        worker = threading.Thread(target=lambda: outcome.append(
            self.executor.execute(first_action, first_permit, first_template)), daemon=True)
        worker.start()
        for _ in range(100):
            if self.server.received:
                break
            time.sleep(0.005)
        self.assertEqual(len(self.server.received), 1)
        second_action = self.action()
        second_template = RequestTemplate("GET", second_action.url)
        # The shared Phase 13 limiter denies issuance or execution while first is in flight.
        try:
            second_permit = self.executor.authorize(second_action, second_template)
        except PermitError:
            second_permit = None
        if second_permit is not None:
            self.assertIn(self.executor.execute(second_action, second_permit, second_template).error,
                          {ExecutionError.POLICY_DENIED, ExecutionError.RATE_LIMITED})
        self.assertEqual(len(self.server.received), 1)
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())

    def test_template_header_validation(self):
        for header in (("Host", "other.test"), ("Authorization", "Bearer hidden"),
                       ("X-API-Key", "hidden"), ("X-HackBot-Correlation", "bad"),
                       ("Accept", "ok\r\nInjected: yes")):
            with self.assertRaises(ValueError):
                RequestTemplate("GET", self.base + "/ok", (header,))


if __name__ == "__main__":
    unittest.main()
