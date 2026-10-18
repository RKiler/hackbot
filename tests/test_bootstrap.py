"""Phase 24 uses local HTTP fixtures only; no production recon or bounty target."""

from __future__ import annotations

from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
from types import SimpleNamespace
from tempfile import TemporaryDirectory
from threading import Thread
import time
import unittest
from unittest.mock import patch

from hackbot.bootstrap import BrowserDiscoveryProvider, _HTMLSignals, _safe_url
from hackbot.bootstrap_store import (BootstrapIdentityPolicy, BootstrapLimits, BootstrapMode,
                                    BootstrapStatus)
from hackbot.config import TargetSettings, load_config
from hackbot.domain import TrafficSource
from hackbot.recon import Page, Provenance, ReconEndpoint, ReconHost, ReconTarget
from hackbot.recon_postgres import ReconQueryError
from hackbot.resources import ResourceBudgetManager
from hackbot.service import BugHunterRuntime, create_app
from hackbot.target_policy import RatePolicy
from hackbot.target_scope import HostRule
from hackbot.traffic import CapturedRequest, CapturedResponse


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.visits.append(self.path)
        if self.path == "/" and self.server.login_required:
            body = b"login required"
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
        elif self.path == "/":
            if self.server.login_form:
                body = b'<html><form method="post"><input type="password"></form></html>'
            else:
                extra = ('<script src="/chunk-a.js"></script><script src="/chunk-b.js"></script>'
                         '<script src="/build-manifest.js"></script>'
                         if self.server.js_heavy else '')
                body = (f'<html><script src="/app.js"></script>'
                        f'{extra}'
                        f'<script src="http://127.0.0.2:{self.server.server_port}/third.js"></script>'
                        '<a href="/dashboard">Dashboard</a><a href="/logout">Logout</a>'
                        '<a href="/sign-out">Sign out</a>'
                        '<a href="/oauth/authorize?client_id=public&amp;state=opaque">Sign in</a>'
                        '<a href="/out">External</a><a href="/go">Go</a>'
                        '<form action="/delete" method="post"></form>'
                        '</html>').encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        elif self.path == "/dashboard":
            body = (b'<html><script id="__NEXT_DATA__" type="application/json">{}</script>'
                    b'<a href="/api/projects?tenant_id=123">Projects</a></html>')
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        elif self.path == "/out":
            body = b""
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.2:{self.server.server_port}/private")
        elif self.path == "/go":
            body = b""
            self.send_response(302)
            self.send_header("Location", "/logout")
        elif self.path == "/app.js":
            body = self.server.js_body
            self.send_response(200)
            self.send_header("Content-Type", self.server.js_type)
        elif self.path in {"/chunk-a.js", "/chunk-b.js"}:
            body = b'fetch("/api/projects"); new WebSocket("wss://example.invalid/ws"); /* grpc-web */'
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
        elif self.path == "/build-manifest.js":
            body = b'window.__BUILD_MANIFEST={sortedPages:["/dashboard","/settings","/projects/{id}"]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
        elif self.path == "/app.js.map":
            body = b'{"version":3,"sources":["app.js"],"names":[],"mappings":""}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        else:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class EmptyRecon:
    def resolve_target(self, _identity):
        return ReconTarget(7, "example.test", True, True,
                           Provenance("domains", 7, None, "fixture"))

    def list_hosts(self, _domain_id, *, limit, cursor=None):
        return Page((), None)

    def list_scan_snapshots(self, _domain_id, *, limit, cursor=None):
        return Page((), None)

    def list_api_surfaces(self, _domain_id, _type, *, limit, cursor=None):
        return Page((), None)


class BoundedRecon(EmptyRecon):
    def __init__(self, host_url):
        self.host_url = host_url
        self.provenance = Provenance("fixture", 1, None, "fixture")

    def list_hosts(self, _domain_id, *, limit, cursor=None):
        return Page((ReconHost(host_id=9, domain_id=7, hostname="127.0.0.1",
                               url=self.host_url, status_code=200,
                               provenance=self.provenance),), None)

    def list_endpoints(self, _domain_id, _host_id, *, limit, cursor=None):
        return Page((ReconEndpoint(endpoint_id=11, host_id=9, path="/api/projects",
                                   method="GET", status_code=200, source="fixture",
                                   provenance=self.provenance),), None)

    def list_js_assets(self, *_args, **_kwargs):
        return Page((), None)

    def list_parameters(self, *_args, **_kwargs):
        return Page((), None)

    def list_endpoint_js_references(self, *_args, **_kwargs):
        return Page((), None)

    def get_js_analysis(self, *_args, **_kwargs):
        return None


class UnavailableRecon:
    def resolve_target(self, _identity):
        raise ReconQueryError("fixture read-only recon unavailable")


class FixedTargets:
    def __init__(self, package):
        self.package = package

    def get_target_package(self, package_id):
        return self.package if package_id == self.package.id else None


class Phase24Tests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        targets = root / "targets"
        shutil.copytree(EXAMPLE, targets / "example")
        config = replace(load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                              "XDG_STATE_HOME": str(root)}), targets=TargetSettings(targets))
        self.runtime = BugHunterRuntime(config, vnc_ready=lambda: False)
        healthy_disk = SimpleNamespace(total=100 * 1024**3, used=10 * 1024**3,
                                       free=90 * 1024**3)
        self.runtime.resources = ResourceBudgetManager(
            config.paths.root, self.runtime.resources.settings,
            disk_usage=lambda _path: healthy_disk,
            memory_available=lambda: 8 * 1024**3,
            load_per_cpu=lambda: 0.0,
            system_disk_path=Path("/"),
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        self.server.visits = []
        self.server.login_required = False
        self.server.login_form = False
        self.server.js_heavy = False
        self.server.js_body = (b'fetch("/graphql"); const channel = new MessageChannel(); ApolloClient;'
                               b'\n//# sourceMappingURL=app.js.map')
        self.server.js_type = "application/javascript"
        thread = Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        package = self.runtime.package("example")
        port = self.server.server_port
        scope = replace(package.scope, include_hosts=(HostRule("127.0.0.1", ("http",), (port,)),),
                        exclude_hosts=(), include_paths=(), exclude_paths=(),
                        default_schemes=("http",), default_ports=(port,))
        self.package = replace(package, scope=scope, rate=RatePolicy(100, 6000, 1, 100))
        self.targets = FixedTargets(self.package)
        self.runtime.targets = self.targets
        self.runtime.executor.targets = self.targets
        self.runtime.bootstrap.targets = self.targets
        self.runtime.executor.settings = replace(self.runtime.executor.settings,
                                                 allow_direct=True, capture_required=False,
                                                 max_response_bytes=1_048_576)
        self.runtime.registry.register_target(self.package)

    def test_no_recon_bootstraps_and_reuses_js(self):
        run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        self.assertEqual(result.mode, BootstrapMode.COLD_START)
        self.assertEqual(result.status, BootstrapStatus.COMPLETED)
        self.assertGreaterEqual(result.counts["pages_visited"], 2)
        self.assertEqual(result.counts["js_assets_acquired"], 1)
        self.assertEqual(result.counts["source_maps_acquired"], 1)
        self.assertGreaterEqual(result.counts["traffic_exchanges_recorded"], 3)
        self.assertEqual(result.counts["requests_used"], len(self.server.visits))
        self.assertNotIn("/logout", self.server.visits)
        self.assertNotIn("/sign-out", self.server.visits)
        self.assertNotIn("/delete", self.server.visits)
        self.assertNotIn("/third.js", self.server.visits)
        profile = self.runtime.hypotheses.latest_profile(self.package.target.id)
        self.assertIsNotNone(profile)
        self.assertIn("GRAPHQL", profile.api_styles)
        self.assertIn("NEXTJS", profile.technologies)
        self.assertIn("APOLLO", profile.technologies)
        self.assertIsNotNone(self.runtime.domxss_store.cached_cold_start_asset(
            self.package.target.id, f"http://127.0.0.1:{self.server.server_port}/app.js"))
        second = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        self.runtime.bootstrap.run(second.bootstrap_id, "example")
        self.assertEqual(self.server.visits.count("/app.js"), 1)
        self.assertLess(result.counts["requests_used"], run.limits.max_requests)

    def test_recon_transition_keeps_target_identity_and_evidence(self):
        first = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        original = self.runtime.bootstrap.run(first.bootstrap_id, "example")
        first_fact = self.runtime.store.list_facts_for_target(original.target_id, limit=1).items[0]
        first_evidence_id = original.evidence_ids[0]
        self.runtime.bootstrap.recon = BoundedRecon(f"http://127.0.0.1:{self.server.server_port}/")
        self.runtime.bootstrap.recon_provider.recon = self.runtime.bootstrap.recon
        app = create_app(runtime=self.runtime)
        pre_run = app.test_client().get("/v1/targets/example/bootstrap")
        self.assertEqual(pre_run.json["recon_availability"], "RECON_BACKED")
        second = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        merged = self.runtime.bootstrap.run(second.bootstrap_id, "example")
        self.assertEqual(merged.mode, BootstrapMode.RECON_BACKED)
        self.assertEqual(merged.target_id, original.target_id)
        self.assertIsNotNone(self.runtime.store.get_fact(first_fact.fact_id))
        self.assertIsNotNone(self.runtime.store.get_evidence(first_evidence_id))
        self.assertIsNotNone(self.runtime.bootstrap_store.get(first.bootstrap_id, original.target_id))
        signals = self.runtime.bootstrap_store.list_observations(original.target_id, run_id=second.bootstrap_id)
        self.assertTrue(any(item.source == "RECON" and item.code == "API_REST" for item in signals))
        self.assertTrue(any(item.source == "COLD_START_TRAFFIC" for item in signals))
        self.assertEqual(self.runtime.bootstrap_store.discovery_state(original.target_id)["state"],
                         "RECON_BACKED")

    def test_recon_backed_state_is_visible_before_first_bootstrap(self):
        self.runtime.bootstrap.recon = BoundedRecon(f"http://127.0.0.1:{self.server.server_port}/")
        self.runtime.bootstrap.recon_provider.recon = self.runtime.bootstrap.recon
        app = create_app(runtime=self.runtime)
        response = app.test_client().get("/v1/targets/example/bootstrap")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["recon_availability"], "RECON_BACKED")
        self.assertEqual(response.json["discovery_state"], "RECON_BACKED")

    def test_recon_and_verified_browser_observations_merge(self):
        self.runtime.bootstrap.recon = BoundedRecon(f"http://127.0.0.1:{self.server.server_port}/")
        self.runtime.bootstrap.recon_provider.recon = self.runtime.bootstrap.recon
        identity_id = "IDENTITY-" + "a" * 32
        session = SimpleNamespace(id="BSESSION-fixture", identity_id=identity_id)
        context = SimpleNamespace(target_id=self.package.target.id, identity_id=identity_id,
                                  browser_available=True, authentication_status="VALID")

        class ObservedDriver:
            def observe_current_page(self, _session_id):
                return {"url": f"http://127.0.0.1:{self_server_port}/dashboard",
                        "scripts": ("/app.js",), "links": (), "forms": ()}

        self_server_port = self.server.server_port
        self.runtime.bootstrap.browser_provider = BrowserDiscoveryProvider(self.runtime.browser, ObservedDriver())
        with patch.object(self.runtime.browser, "get_active_session", return_value=session), \
             patch.object(self.runtime.browser, "session_context", return_value=context):
            run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.PRIMARY_IDENTITY,
                                                identity_id=identity_id)
            result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        self.assertEqual(result.mode, BootstrapMode.RECON_BACKED)
        self.assertEqual(result.counts["authenticated_pages"], 1)
        observations = self.runtime.bootstrap_store.list_observations(self.package.target.id,
                                                                      run_id=run.bootstrap_id)
        self.assertTrue(any(item.source == "RECON" for item in observations))
        self.assertTrue(any(item.source == "COLD_START_BROWSER" for item in observations))
        profile = self.runtime.hypotheses.latest_profile(self.package.target.id)
        self.assertTrue(any(signal.source.value == "RECON" for signal in profile.signals))
        self.assertTrue(any(signal.source.value == "COLD_START_BROWSER" for signal in profile.signals))

    def test_js_heavy_rest_graphql_and_websocket_signals(self):
        self.server.js_heavy = True
        run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        profile = self.runtime.hypotheses.latest_profile(self.package.target.id)
        self.assertEqual(result.counts["js_assets_acquired"], 4)
        self.assertTrue(profile.javascript_heavy)
        self.assertIn("REST", profile.api_styles)
        self.assertIn("GRAPHQL", profile.api_styles)
        self.assertIn("WEBSOCKET", profile.api_styles)
        self.assertIn("GRPC_WEB", profile.api_styles)
        observations = self.runtime.bootstrap_store.list_observations(self.package.target.id,
                                                                      run_id=run.bootstrap_id)
        self.assertTrue(any(item.code == "ROUTE_HINT" for item in observations))

    def test_first_party_websocket_hint_is_not_connected(self):
        self.server.js_body = (f'new WebSocket("ws://127.0.0.1:{self.server.server_port}/events")').encode()
        run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        self.runtime.bootstrap.run(run.bootstrap_id, "example")
        observations = self.runtime.bootstrap_store.list_observations(self.package.target.id,
                                                                      run_id=run.bootstrap_id)
        self.assertTrue(any(item.source == "COLD_START_JS" and item.code == "API_WEBSOCKET"
                            and item.display.startswith("127.0.0.1/")
                            for item in observations))
        self.assertNotIn("/events", self.server.visits)

    def test_captured_websocket_upgrade_is_observed(self):
        url = f"http://127.0.0.1:{self.server.server_port}/ws"
        exchange = self.runtime.traffic.store_request(
            self.package, CapturedRequest("GET", url, (("Upgrade", "websocket"),)),
            source=TrafficSource.FIXTURE, capture_provider="LOCAL_FIXTURE", anonymous=True)
        self.runtime.traffic.store_response(
            exchange.id, CapturedResponse(101, (("Upgrade", "websocket"),)))
        run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        self.runtime.bootstrap.run(run.bootstrap_id, "example")
        observations = self.runtime.bootstrap_store.list_observations(self.package.target.id,
                                                                      run_id=run.bootstrap_id)
        self.assertTrue(any(item.source == "COLD_START_TRAFFIC" and item.code == "API_WEBSOCKET"
                            and item.display.startswith("127.0.0.1/") for item in observations))
        self.assertNotIn("/ws", self.server.visits)

    def test_query_bearing_oauth_and_api_links_are_observed_but_not_fetched(self):
        run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        observations = self.runtime.bootstrap_store.list_observations(self.package.target.id,
                                                                      run_id=run.bootstrap_id)
        self.assertEqual(result.status, BootstrapStatus.COMPLETED)
        self.assertTrue(any(item.code == "API_OAUTH" for item in observations))
        self.assertTrue(any(item.code == "API_REST" for item in observations))
        self.assertTrue(any(item.display.startswith("parameter client_id") for item in observations))
        self.assertTrue(any(item.display.startswith("parameter tenant_id") for item in observations))
        self.assertFalse(any(path.startswith("/oauth/authorize") or path.startswith("/api/projects")
                             for path in self.server.visits))
        self.assertFalse(any("opaque" in item.display for item in observations))

    def test_unavailable_recon_does_not_block_cold_start(self):
        recon = UnavailableRecon()
        self.runtime.bootstrap.recon = recon
        self.runtime.bootstrap.recon_provider.recon = recon
        app = create_app(runtime=self.runtime)
        self.assertEqual(app.test_client().get("/v1/targets/example/bootstrap").json["recon_availability"],
                         "RECON_UNAVAILABLE")
        run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        self.assertEqual(result.mode, BootstrapMode.COLD_START)
        self.assertEqual(result.status, BootstrapStatus.COMPLETED)
        self.assertIn("RECON_UNAVAILABLE", result.limitations)

    def test_explicit_refresh_detects_js_hash_change_without_losing_old_artifact(self):
        url = f"http://127.0.0.1:{self.server.server_port}/app.js"
        first = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        self.runtime.bootstrap.run(first.bootstrap_id, "example")
        old = self.runtime.domxss_store.cached_cold_start_asset(self.package.target.id, url)
        self.assertIsNotNone(old)
        self.server.js_body = b'fetch("/api/new-feature"); const view = React.createElement("div");'
        second = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(second.bootstrap_id, "example", refresh=True)
        new = self.runtime.domxss_store.cached_cold_start_asset(self.package.target.id, url)
        self.assertEqual(result.status, BootstrapStatus.COMPLETED)
        self.assertEqual(result.counts["js_assets_changed"], 1)
        self.assertNotEqual(old.artifact_sha256, new.artifact_sha256)
        self.assertEqual(self.runtime.domxss_store.get_asset(self.package.target.id, old.artifact_id).state,
                         "STALE")
        self.assertIn("/app.js", self.server.visits)
        self.assertEqual(self.server.visits.count("/app.js"), 2)

    def test_scope_redirect_and_third_party_are_not_followed(self):
        self.assertIsNone(_safe_url(f"http://127.0.0.1:{self.server.server_port}/",
                                     f"http://127.0.0.2:{self.server.server_port}/", self.package))
        run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        self.runtime.bootstrap.run(run.bootstrap_id, "example")
        self.assertIn("/out", self.server.visits)
        self.assertIn("/go", self.server.visits)
        self.assertNotIn("/logout", self.server.visits)
        self.assertNotIn("/private", self.server.visits)
        self.assertNotIn("/third.js", self.server.visits)

    def test_budget_and_no_account_partial(self):
        run = self.runtime.bootstrap.create("example", limits=BootstrapLimits(max_requests=1),
                                            identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        self.assertEqual(result.status, BootstrapStatus.BUDGET_EXHAUSTED)
        self.assertEqual(result.counts["requests_used"], 1)
        later = self.runtime.bootstrap.create("example")
        result = self.runtime.bootstrap.run(later.bootstrap_id, "example")
        self.assertEqual(result.status, BootstrapStatus.PARTIAL)
        self.assertIn("AUTHENTICATED_COVERAGE_UNAVAILABLE", result.limitations)

    def test_disabled_transport_is_blocked_without_network_use(self):
        self.runtime.executor.settings = replace(self.runtime.executor.settings,
                                                 allow_direct=False, capture_required=False)
        run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        self.assertEqual(result.status, BootstrapStatus.BLOCKED)
        self.assertIn("DIRECT_DISABLED", result.limitations)
        self.assertEqual(result.counts["requests_used"], 0)
        self.assertEqual(self.server.visits, [])

    def test_small_asset_cap_is_a_limit_not_a_failed_run(self):
        run = self.runtime.bootstrap.create("example", limits=BootstrapLimits(max_asset_bytes=64),
                                            identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        self.assertNotEqual(result.status, BootstrapStatus.FAILED)
        self.assertIn("HTML_BODY_UNAVAILABLE", result.limitations)
        self.assertLessEqual(result.counts["requests_used"], run.limits.max_requests)
        self.server.js_body = b"const padding = '" + b"x" * 1000 + b"';"
        second = self.runtime.bootstrap.create("example", limits=BootstrapLimits(max_asset_bytes=512),
                                               identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(second.bootstrap_id, "example")
        self.assertNotEqual(result.status, BootstrapStatus.FAILED)
        self.assertIn("JS_ASSET_EXCEEDS_LIMIT", result.limitations)

    def test_html_fallback_at_js_path_is_not_counted_as_javascript(self):
        self.server.js_type = "text/plain"
        self.server.js_body = b"<!doctype html><html><body>Login required</body></html>"
        run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        self.assertEqual(result.counts["js_assets_discovered"], 1)
        self.assertEqual(result.counts["js_assets_acquired"], 0)
        self.assertIn("JS_NON_SCRIPT_RESPONSE", result.limitations)
        self.assertIsNone(self.runtime.domxss_store.cached_cold_start_asset(
            self.package.target.id, f"http://127.0.0.1:{self.server.server_port}/app.js"))

    def test_verified_browser_enriches_login_required_target_without_clicking(self):
        self.server.login_required = True
        identity_id = "IDENTITY-" + "a" * 32
        session = SimpleNamespace(id="BSESSION-fixture", identity_id=identity_id)
        context = SimpleNamespace(target_id=self.package.target.id, identity_id=identity_id,
                                  browser_available=True, authentication_status="VALID")
        current_url = f"http://127.0.0.1:{self.server.server_port}/dashboard"

        class ObservedDriver:
            def observe_current_page(self, _session_id):
                return {"url": current_url, "title_present": True,
                        "scripts": ("/app.js", "https://outside.invalid/private.js"),
                        "links": ("/sign-out", "/settings"),
                        "forms": ("/delete",)}

        driver = ObservedDriver()
        self.runtime.bootstrap.browser_provider = BrowserDiscoveryProvider(self.runtime.browser, driver)
        with patch.object(self.runtime.browser, "get_active_session", return_value=session), \
             patch.object(self.runtime.browser, "session_context", return_value=context):
            run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.PRIMARY_IDENTITY,
                                                identity_id=identity_id)
            result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
            self.runtime.executor.settings = replace(self.runtime.executor.settings, allow_direct=False)
            limited = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.PRIMARY_IDENTITY,
                                                    identity_id=identity_id)
            limited_result = self.runtime.bootstrap.run(limited.bootstrap_id, "example")
        self.assertEqual(result.status, BootstrapStatus.COMPLETED)
        self.assertEqual(limited_result.status, BootstrapStatus.PARTIAL)
        self.assertIn("DIRECT_DISABLED", limited_result.limitations)
        self.assertEqual(result.counts["authenticated_pages"], 1)
        self.assertEqual(result.counts["anonymous_pages"], 0)
        self.assertEqual(result.counts["js_assets_acquired"], 1)
        self.assertNotIn("/sign-out", self.server.visits)
        self.assertNotIn("/delete", self.server.visits)
        observations = self.runtime.bootstrap_store.list_observations(self.package.target.id,
                                                                      run_id=run.bootstrap_id)
        self.assertTrue(any(item.source == "COLD_START_BROWSER" for item in observations))
        self.assertFalse(any("outside.invalid" in item.display for item in observations))

    def test_unverified_browser_not_used_and_active_run_deduplicated(self):
        identity_id = "IDENTITY-" + "a" * 32
        with self.assertRaises(ValueError):
            self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.PRIMARY_IDENTITY,
                                          identity_id=identity_id)
        first = self.runtime.bootstrap.create("example")
        with self.assertRaisesRegex(ValueError, "already active"):
            self.runtime.bootstrap.create("example")
        self.runtime.bootstrap.run(first.bootstrap_id, "example")
        later = self.runtime.bootstrap.create("example")
        self.assertNotEqual(first.bootstrap_id, later.bootstrap_id)

    def test_interrupted_run_reconciles_without_request_replay(self):
        first = self.runtime.bootstrap.create("example")
        self.assertEqual(self.runtime.bootstrap_store.reconcile(), 1)
        recovered = self.runtime.bootstrap_store.get(first.bootstrap_id, first.target_id)
        self.assertEqual(recovered.status, BootstrapStatus.PARTIAL)
        self.assertEqual(recovered.stop_reason, "SERVICE_RESTART")
        self.assertEqual(recovered.counts["requests_used"], 0)
        self.assertEqual(self.server.visits, [])
        self.runtime.bootstrap.create("example")

    def test_login_required_anonymous_is_partial_and_url_guard_blocks_secrets(self):
        self.server.login_required = True
        run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        self.assertEqual(result.status, BootstrapStatus.PARTIAL)
        self.assertNotIn("/dashboard", self.server.visits)
        root = f"http://127.0.0.1:{self.server.server_port}/"
        for value in ("/logout", "/sign-out", "/delete-account", "/buy/purchase",
                      "/invite/accept", "/approval/confirm", "/jobs/run", "/settings/reset",
                      "/dashboard?token=private", "/?view=logout",
                      "https://outside.invalid/app.js"):
            self.assertIsNone(_safe_url(root, value, self.package), value)

    def test_versioned_asset_query_and_withheld_login_form(self):
        root = f"http://127.0.0.1:{self.server.server_port}/"
        self.assertEqual(_safe_url(root, "/app.js?v=1.2.3", self.package), root + "app.js?v=1.2.3")
        self.assertEqual(_safe_url(root, "/app.js?version=2026.10", self.package),
                         root + "app.js?version=2026.10")
        self.assertIsNone(_safe_url(root, "/app.js?token=private", self.package))
        parsed = _HTMLSignals()
        parsed.feed('<html><form method="post"><input type="password"></form></html>')
        self.assertTrue(parsed.has_password_input)
        self.server.login_form = True
        run = self.runtime.bootstrap.create("example", identity_policy=BootstrapIdentityPolicy.ANONYMOUS_ONLY)
        result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        self.assertEqual(result.status, BootstrapStatus.PARTIAL)
        self.assertIn("HTML_BODY_UNAVAILABLE", result.limitations)
        observations = self.runtime.bootstrap_store.list_observations(self.package.target.id,
                                                                      run_id=run.bootstrap_id)
        self.assertFalse(any(item.code == "BOUNDARY_AUTHENTICATED" for item in observations))

    def test_cancel_and_private_api(self):
        app = create_app(runtime=self.runtime)
        client = app.test_client()
        self.assertEqual(client.post("/v1/targets/unknown/bootstrap", json={}).status_code, 404)
        self.assertEqual(self.server.visits, [])
        response = client.get("/v1/targets/example/bootstrap")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["recon_availability"], "NOT_CONFIGURED")
        run = self.runtime.bootstrap.create("example")
        self.assertTrue(self.runtime.bootstrap_store.request_cancel(run.bootstrap_id, run.target_id))
        result = self.runtime.bootstrap.run(run.bootstrap_id, "example")
        self.assertEqual(result.status, BootstrapStatus.CANCELLED)
        detail = client.get(f"/v1/targets/example/bootstrap/{run.bootstrap_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json["run"]["status"], "CANCELLED")
        self.assertEqual(client.post("/v1/targets/example/bootstrap", json={"limits": {
            "max_requests": 1000}}).status_code, 400)
        started = client.post("/v1/targets/example/bootstrap",
                              json={"identity_policy": "anonymous_only", "limits": {"max_requests": 2}})
        self.assertEqual(started.status_code, 201)
        run_id = started.json["bootstrap_id"]
        thread = self.runtime._bootstrap_threads.get(run_id)
        if thread is not None:
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive())
        current = client.get(f"/v1/targets/example/bootstrap/{run_id}")
        self.assertEqual(current.status_code, 200)
        self.assertIn(current.json["run"]["status"], {"COMPLETED", "BUDGET_EXHAUSTED"})
        self.assertLessEqual(current.json["run"]["requests_used"], 2)

    def test_browser_observation_error_does_not_strand_bootstrap(self):
        client = create_app(runtime=self.runtime).test_client()
        with patch.object(self.runtime.bootstrap, "capture_browser_signals", side_effect=RuntimeError):
            started = client.post("/v1/targets/example/bootstrap", json={})
        self.assertEqual(started.status_code, 201)
        run_id = started.json["bootstrap_id"]
        thread = self.runtime._bootstrap_threads.get(run_id)
        if thread is not None:
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive())
        result = self.runtime.bootstrap_store.get(run_id, self.package.target.id)
        self.assertEqual(result.status, BootstrapStatus.PARTIAL)
        self.assertIn("AUTHENTICATED_COVERAGE_UNAVAILABLE", result.limitations)
        self.runtime.bootstrap.create("example")

    def test_worker_start_error_releases_active_run(self):
        client = create_app(runtime=self.runtime).test_client()
        with patch("hackbot.service.Thread.start", side_effect=RuntimeError):
            response = client.post("/v1/targets/example/bootstrap", json={})
        self.assertEqual(response.status_code, 500)
        run = self.runtime.bootstrap_store.list_runs(self.package.target.id)[0]
        self.assertEqual(run.status, BootstrapStatus.FAILED)
        self.assertEqual(run.stop_reason, "WORKER_START_FAILED")
        self.runtime.bootstrap.create("example")


if __name__ == "__main__":
    unittest.main()
