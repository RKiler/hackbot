"""Loopback-only browser semantics for the typed DOM experiment driver."""

from __future__ import annotations

import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlsplit
import unittest

from hackbot.browser import BrowserProxyConfig
from hackbot.browser_playwright import PlaywrightBrowserDriver
from hackbot.domxss_browser import DOMBrowserExperimentExecutor, DOMInputKind, DOMVariant


JS_BODY = b"""
const next = new URLSearchParams(location.search).get('next');
if (next && !next.startsWith('javascript:')) {
  document.getElementById('target').src = decodeURIComponent(next);
}
"""
HTML_BODY = b"""
const next = new URLSearchParams(location.search).get('next');
if (next && !next.startsWith('<img')) {
  document.getElementById('target').innerHTML = decodeURIComponent(next);
}
"""


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path in {"/bundle.js", "/bundle-tt.js"}:
            body = HTML_BODY if path == "/bundle-tt.js" else JS_BODY
            kind = "application/javascript"
        elif path in {"/preview", "/preview-csp", "/preview-sandbox", "/preview-tt"}:
            if path == "/preview-tt":
                body = b'<html><body><div id="target"></div><script src="/bundle-tt.js"></script></body></html>'
            else:
                sandbox = b' sandbox=""' if path == "/preview-sandbox" else b""
                body = (b'<html><body><iframe id="target"' + sandbox +
                        b'></iframe><script src="/bundle.js"></script></body></html>')
            kind = "text/html"
        elif path == "/reflection":
            query = parse_qs(urlsplit(self.path).query).get("next", [""])[0]
            body = ("<html><body>" + html.escape(query) + "</body></html>").encode()
            kind = "text/html"
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/destination")
            self.end_headers()
            return
        else:
            body, kind = b"not found", "text/plain"
        self.send_response(200 if path in {"/bundle.js", "/bundle-tt.js", "/preview",
                                             "/preview-csp", "/preview-sandbox", "/preview-tt",
                                             "/reflection"} else 404)
        self.send_header("Content-Type", kind)
        if path == "/preview-csp":
            self.send_header("Content-Security-Policy", "script-src 'self'; object-src 'none'")
        if path == "/preview-tt":
            self.send_header("Content-Security-Policy",
                             "require-trusted-types-for 'script'; script-src 'self'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class PlaywrightDOMFixtureTests(unittest.TestCase):
    def test_check_before_decode_executes_only_encoded_variant(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright browser extra unavailable")
        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        root = f"http://127.0.0.1:{server.server_port}"
        with sync_playwright() as playwright:
            executable = os.environ.get("HACKBOT_TEST_CHROMIUM")
            driver = PlaywrightBrowserDriver(Path(executable) if executable else None)
            driver._playwright = playwright
            driver._contexts["fixture"] = object()
            driver._proxy_settings["fixture"] = BrowserProxyConfig()
            results = {}

            def gate(url, method, _navigation):
                parsed = urlsplit(url)
                return method == "GET" and parsed.scheme == "http" and parsed.netloc == urlsplit(root).netloc

            for variant in (DOMVariant.INERT, DOMVariant.BENIGN,
                            DOMVariant.DIRECT_DANGEROUS, DOMVariant.ENCODED_ONCE):
                marker = "fixture" + variant.value.lower()
                payload = DOMBrowserExperimentExecutor._payload(
                    variant, marker, "URL_RESOURCE", root + "/preview")
                url = DOMBrowserExperimentExecutor._url(
                    root + "/preview", DOMInputKind.QUERY, "next", payload)
                results[variant] = driver.execute_dom_variant(
                    "fixture", url, marker, root + "/bundle.js", gate,
                    authenticated=False, request_cap=24, timeout_ms=12_000)
            self.assertEqual([results[key].marker_observed for key in results],
                             [False, False, False, True])
            self.assertEqual(results[DOMVariant.ENCODED_ONCE].marker_context, "IFRAME")
            self.assertEqual(results[DOMVariant.ENCODED_ONCE].document_origin, root)
            self.assertEqual(results[DOMVariant.ENCODED_ONCE].bundle_sha256,
                             hashlib.sha256(JS_BODY).hexdigest())

            encoded = DOMBrowserExperimentExecutor._payload(
                DOMVariant.ENCODED_ONCE, "cspfixture", "URL_RESOURCE", root + "/preview-csp")
            for path in ("/preview-csp", "/preview-sandbox"):
                url = DOMBrowserExperimentExecutor._url(
                    root + path, DOMInputKind.QUERY, "next", encoded)
                observed = driver.execute_dom_variant(
                    "fixture", url, "cspfixture", root + "/bundle.js", gate,
                    authenticated=False, request_cap=24, timeout_ms=12_000)
                self.assertFalse(observed.marker_observed)
                if path == "/preview-csp":
                    self.assertTrue(observed.csp_present)
                else:
                    self.assertIn("", observed.sandbox_flags)

            html_payload = DOMBrowserExperimentExecutor._payload(
                DOMVariant.ENCODED_ONCE, "ttfixture", "HTML_EXECUTION", root + "/preview-tt")
            url = DOMBrowserExperimentExecutor._url(
                root + "/preview-tt", DOMInputKind.QUERY, "next", html_payload)
            trusted = driver.execute_dom_variant(
                "fixture", url, "ttfixture", root + "/bundle-tt.js", gate,
                authenticated=False, request_cap=24, timeout_ms=12_000)
            self.assertTrue(trusted.trusted_types_enforced)
            self.assertFalse(trusted.marker_observed)

            for path in ("/reflection", "/redirect"):
                url = DOMBrowserExperimentExecutor._url(
                    root + path, DOMInputKind.QUERY, "next", encoded)
                observation = driver.execute_dom_variant(
                    "fixture", url, "cspfixture", root + "/bundle.js", gate,
                    authenticated=False, request_cap=24, timeout_ms=12_000)
                self.assertFalse(observation.marker_observed)


if __name__ == "__main__":
    unittest.main()
