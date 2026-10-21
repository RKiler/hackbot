"""Optional local Chromium smoke: no external URLs are opened."""

from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from urllib.parse import urlsplit

from hackbot.browser import BrowserProxyConfig, IdentityVerificationRule
from hackbot.browser_playwright import PlaywrightBrowserDriver
from hackbot.target_scope import HostRule, ProgramScope, ScopeProvenance, ScopeSourceKind
from datetime import datetime, timezone

try:
    import playwright.sync_api  # noqa: F401
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
else:
    PLAYWRIGHT_AVAILABLE = True


CHROMIUM_BINARY = os.environ.get("HACKBOT_TEST_CHROMIUM")


@unittest.skipUnless(PLAYWRIGHT_AVAILABLE and CHROMIUM_BINARY and Path(CHROMIUM_BINARY).is_file(),
                     "Playwright or an explicit local Chromium test binary is unavailable")
class LocalPlaywrightTests(unittest.TestCase):
    def test_captured_browser_blocks_unrelated_origin_before_capture(self):
        received = []

        class ProxyFixture(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.path)
                self.send_response(200)
                self.end_headers()

            def do_CONNECT(self):
                received.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, _format, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyFixture)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with TemporaryDirectory() as directory:
                driver = PlaywrightBrowserDriver(Path(CHROMIUM_BINARY))
                proxy = BrowserProxyConfig(
                    enabled=True, proxy_url=f"http://127.0.0.1:{server.server_port}",
                    reference="local_proxy", capture_required=True,
                    guard_scope=ProgramScope(
                        package_id="fixture", include_hosts=(HostRule("mapped.fixture.test"),),
                        provenance=ScopeProvenance(ScopeSourceKind.RESEARCHER, "fixture",
                                                   datetime.now(timezone.utc))))
                driver.start("local", Path(directory) / "profile", display=None, proxy=proxy)
                try:
                    page = driver._contexts["local"].pages[0]
                    with self.assertRaises(Exception):
                        page.goto("http://outside.fixture.invalid/", timeout=2500)
                    self.assertEqual(received, [])
                    self.assertGreaterEqual(driver._proxy_guards["local"].counts[1], 1)
                finally:
                    driver.stop("local")
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_bounded_navigation_checks_redirects_and_blocks_writes(self):
        received = []

        class ProxyFixture(BaseHTTPRequestHandler):
            def do_CONNECT(self):
                received.append(("CONNECT", self.path))
                if self.path != "mapped.fixture.test:80":
                    self.send_response(502)
                    self.end_headers()
                    return
                self.send_response(200, "Connection Established")
                self.end_headers()
                self.close_connection = False
                self.handle_one_request()

            def do_GET(self):
                path = urlsplit(self.path).path
                received.append(("GET", path))
                if path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/page")
                elif path == "/outside":
                    self.send_response(302)
                    self.send_header("Location", "http://outside.fixture.invalid/leak")
                elif path == "/page":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                else:
                    self.send_response(404)
                self.end_headers()
                if path == "/page":
                    self.wfile.write(
                        b'<html><script src="/app.js"></script><a href="/next">Next</a>'
                        b'<form method="POST" action="/write"><input name="name">'
                        b'<input name="password" type="password"><button aria-label="Save">'
                        b'Save</button></form><script>fetch("/write",{method:"POST"})</script></html>')

            def do_POST(self):
                received.append(("POST", urlsplit(self.path).path))
                self.send_response(200)
                self.end_headers()

            def log_message(self, _format, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyFixture)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        origin = "http://mapped.fixture.test"
        gate_calls = []
        try:
            with TemporaryDirectory() as directory:
                driver = PlaywrightBrowserDriver(Path(CHROMIUM_BINARY))
                proxy = BrowserProxyConfig(enabled=True,
                                           proxy_url=f"http://127.0.0.1:{server.server_port}",
                                           reference="local_proxy", capture_required=True,
                                           guard_scope=ProgramScope(
                                               package_id="fixture",
                                               include_hosts=(HostRule("mapped.fixture.test"),),
                                               provenance=ScopeProvenance(
                                                   ScopeSourceKind.RESEARCHER, "fixture",
                                                   datetime.now(timezone.utc)),
                                               default_ports=(80, 443)))
                driver.start("local", Path(directory) / "profile", display=None, proxy=proxy)
                try:
                    def gate(url, method, navigation):
                        gate_calls.append((url, method, navigation))
                        return url.startswith(origin) and method in {"GET", "HEAD"}

                    direct = driver.navigate_readonly(
                        "local", origin + "/page", gate,
                        lambda url: url.startswith(origin), timeout_ms=8000)
                    self.assertEqual(direct.error_code, None,
                                     (direct, received, gate_calls))
                    result = driver.navigate_readonly(
                        "local", origin + "/redirect", gate,
                        lambda url: url.startswith(origin), timeout_ms=8000)
                    self.assertEqual(result.error_code, None,
                                     (result, received, gate_calls))
                    self.assertEqual(result.redirect_count, 1,
                                     (result, received, gate_calls))
                    self.assertEqual(result.url, origin + "/page")
                    self.assertEqual(result.forms, (("/write", "POST"),))
                    self.assertEqual(result.form_fields, ((("name", "text"),),))
                    self.assertIn("/next", result.links)
                    self.assertNotIn(("POST", "/write"), received)
                    self.assertTrue(all(method in {"GET", "HEAD"}
                                        for _, method, _ in gate_calls))
                    blocked = driver.navigate_readonly(
                        "local", origin + "/outside", gate,
                        lambda url: url.startswith(origin), timeout_ms=8000)
                    self.assertEqual(blocked.error_code, "REDIRECT_DENIED")
                    self.assertNotIn(("GET", "/leak"), received)
                finally:
                    driver.stop("local")
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_fulfilled_redirect_does_not_reenter_browser_route(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/final")
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                self.end_headers()
                if self.path == "/final":
                    self.wfile.write(b"<html><title>Local fixture</title></html>")

            def log_message(self, _format, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        visited = []
        try:
            with TemporaryDirectory() as directory:
                driver = PlaywrightBrowserDriver(Path(CHROMIUM_BINARY))
                driver.start("local", Path(directory) / "profile", display=None,
                             proxy=BrowserProxyConfig())
                try:
                    context = driver._contexts["local"]

                    def routed(route):
                        visited.append(route.request.url)
                        route.fulfill(response=route.fetch(max_redirects=0))

                    context.route("**/*", routed)
                    response = context.pages[0].goto(
                        f"http://127.0.0.1:{server.server_port}/redirect",
                        wait_until="domcontentloaded")
                    self.assertEqual(response.status, 200)
                    self.assertEqual([url.rsplit("/", 1)[-1] for url in visited],
                                     ["redirect"])
                finally:
                    driver.stop("local")
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_profile_cookie_isolation_and_local_dom_identity(self):
        with TemporaryDirectory() as directory:
            driver = PlaywrightBrowserDriver(Path(CHROMIUM_BINARY))
            profile_a = Path(directory) / "a"
            profile_b = Path(directory) / "b"
            driver.start("a", profile_a, display=None, proxy=BrowserProxyConfig())
            try:
                driver.start("b", profile_b, display=None, proxy=BrowserProxyConfig())
                context_a = driver._contexts["a"]
                context_b = driver._contexts["b"]
                context_a.add_cookies([{"url": "https://fixture.example.test/", "name": "sid", "value": "fake-a"}])
                context_b.add_cookies([{"url": "https://fixture.example.test/", "name": "sid", "value": "fake-b"}])
                self.assertEqual(context_a.cookies()[0]["value"], "fake-a")
                self.assertEqual(context_b.cookies()[0]["value"], "fake-b")
                context_a.pages[0].set_content('<span id="u">user-a</span><span id="t">tenant-a</span>')
                rule = IdentityVerificationRule(
                    target_id="TARGET-" + "1" * 32, identity_id="IDENTITY-" + "2" * 32,
                    user_id_selector="#u", expected_user_id="user-a",
                    tenant_selector="#t", expected_tenant_id="tenant-a",
                )
                observed = driver.observe_identity("a", rule)
                self.assertEqual((observed.user_id, observed.tenant_id), ("user-a", "tenant-a"))
                self.assertEqual(driver.observe_identity("b", rule).user_id, None)
            finally:
                driver.stop("a")
                driver.stop("b")


if __name__ == "__main__":
    unittest.main()
