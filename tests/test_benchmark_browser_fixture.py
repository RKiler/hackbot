from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen
import unittest

from hackbot.benchmark_browser_fixture import BenchmarkBrowserFixture
from hackbot.benchmark_browser import _QUERY_GET
from hackbot.browser import BrowserProxyConfig
from hackbot.browser_playwright import PlaywrightBrowserDriver
from hackbot.domxss_browser import DOMBrowserExperimentExecutor, DOMInputKind, DOMVariant
from hackbot.postmessage_browser import MessageExperimentBinding, MessageVariant


CHROMIUM = Path("/root/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome")


class BrowserFixtureTests(unittest.TestCase):
    def test_query_selector_is_derived_from_asset_source(self) -> None:
        self.assertEqual(_QUERY_GET.findall(
            b"new URLSearchParams(location.search).get('return_url')"),
            [b"return_url"])
        self.assertEqual(_QUERY_GET.findall(b"const next = 'fixed';"), [])

    def test_dom_pair_is_bounded_and_changes_only_server_behavior(self) -> None:
        bodies = []
        for secure in (False, True):
            with BenchmarkBrowserFixture(family="DOM", secure=secure,
                                         max_requests=3) as fixture:
                with urlopen(fixture.base_url + "/preview", timeout=3) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIn(b"/bundle.js", response.read())
                with urlopen(fixture.base_url + "/bundle.js", timeout=3) as response:
                    bodies.append(response.read())
                with urlopen(fixture.base_url + "/preview?next=marker", timeout=3) as response:
                    self.assertEqual(response.status, 200)
                with self.assertRaises(HTTPError) as limited:
                    urlopen(fixture.base_url + "/preview", timeout=3)
                self.assertEqual(limited.exception.code, 429)
                self.assertEqual(len(fixture.requests), 4)
        self.assertEqual(bodies[0], bodies[1])
        self.assertIn(b"decodeURIComponent(input)", bodies[0])
        self.assertIn(b"decodeURIComponent(input)", bodies[1])

    def test_message_pair_has_same_entry_route_and_guarded_origin(self) -> None:
        bodies = []
        for secure in (False, True):
            with BenchmarkBrowserFixture(family="MESSAGE", secure=secure) as fixture:
                with urlopen(fixture.base_url + "/victim", timeout=3) as response:
                    self.assertIn(b"/bundle.js", response.read())
                with urlopen(fixture.base_url + "/bundle.js", timeout=3) as response:
                    bodies.append(response.read())
                self.assertEqual(len(fixture.requests), 2)
        self.assertNotEqual(bodies[0], bodies[1])
        self.assertNotIn(b"event.origin", bodies[0])
        self.assertIn(b"event.origin !== window.location.origin", bodies[1])

    def test_real_browser_dom_pair(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright unavailable")
        if not CHROMIUM.is_file():
            self.skipTest("Local Chromium unavailable")
        with sync_playwright() as playwright:
            driver = PlaywrightBrowserDriver(CHROMIUM)
            driver._playwright = playwright
            driver._contexts["fixture"] = object()
            driver._proxy_settings["fixture"] = BrowserProxyConfig()
            for secure in (False, True):
                with BenchmarkBrowserFixture(family="DOM", secure=secure) as fixture:
                    with urlopen(fixture.base_url + "/bundle.js", timeout=3) as response:
                        digest = hashlib.sha256(response.read()).hexdigest()

                    def gate(url, method, _navigation):
                        return method == "GET" and url.startswith(fixture.base_url + "/")

                    observed = []
                    for variant in (DOMVariant.INERT, DOMVariant.BENIGN,
                                    DOMVariant.DIRECT_DANGEROUS, DOMVariant.ENCODED_ONCE):
                        marker = "fixture" + variant.value.lower()
                        payload = DOMBrowserExperimentExecutor._payload(
                            variant, marker, "URL_RESOURCE", fixture.base_url + "/preview")
                        url = DOMBrowserExperimentExecutor._url(
                            fixture.base_url + "/preview", DOMInputKind.QUERY, "next", payload)
                        result = driver.execute_dom_variant(
                            "fixture", url, marker, fixture.base_url + "/bundle.js", gate,
                            authenticated=False, request_cap=24, timeout_ms=12_000)
                        self.assertEqual(result.bundle_sha256, digest)
                        observed.append(result.marker_observed)
                    self.assertEqual(observed, [False, False, False, not secure])

    def test_real_browser_message_pair(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright unavailable")
        if not CHROMIUM.is_file():
            self.skipTest("Local Chromium unavailable")
        with sync_playwright() as playwright:
            driver = PlaywrightBrowserDriver(CHROMIUM)
            driver._playwright = playwright
            driver._contexts["fixture"] = object()
            driver._proxy_settings["fixture"] = BrowserProxyConfig()
            for secure in (False, True):
                with BenchmarkBrowserFixture(family="MESSAGE", secure=secure) as fixture:
                    binding = MessageExperimentBinding(
                        candidate_id="MSG-" + "a" * 32, run_id="RUN-" + "b" * 32,
                        browser_session_id="fixture", route_url=fixture.base_url + "/victim",
                        asset_url=fixture.base_url + "/bundle.js",
                        activation_type="ACTIVATE", port_type=None,
                        allowed_method="readSynthetic", identity_id=None)

                    def gate(url, method, _navigation):
                        return "LOCAL" if method == "GET" and url.startswith(
                            fixture.base_url + "/") else None

                    result = driver.execute_message_trial(
                        "fixture", binding, MessageVariant.ATTACKER_PORT, gate,
                        authenticated=False, request_cap=8, timeout_ms=8000)
                    self.assertEqual(result.error_code, None)
                    self.assertEqual(result.capability_observed, not secure)


if __name__ == "__main__":
    unittest.main()
