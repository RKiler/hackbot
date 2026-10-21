"""Browser-cookie handoff stays inside the verified capture and scope boundary."""

from __future__ import annotations

from pathlib import Path
import unittest

from hackbot.browser import BrowserError, BrowserProxyConfig
from hackbot.browser_playwright import PlaywrightBrowserDriver
from hackbot.secrets import SecretValue
from hackbot.target_loader import load_target_package


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class _Context:
    def __init__(self, cookies: list[dict[str, object]]) -> None:
        self._cookies = cookies
        self.requests: list[list[str]] = []

    def cookies(self, *, urls: list[str]) -> list[dict[str, object]]:
        self.requests.append(urls)
        return self._cookies


class BrowserCookieBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = PlaywrightBrowserDriver()
        self.scope = load_target_package(EXAMPLE).scope
        self.context = _Context([
            {"name": "owned", "value": "local-fixture", "domain": ".example.test",
             "path": "/app", "secure": True, "expires": -1},
            {"name": "wrong_host", "value": "reject", "domain": "other.example.test",
             "path": "/app", "secure": True, "expires": -1},
            {"name": "wrong_path", "value": "reject", "domain": ".example.test",
             "path": "/admin", "secure": True, "expires": -1},
            {"name": "expired", "value": "reject", "domain": ".example.test",
             "path": "/app", "secure": True, "expires": 1},
        ])
        self.driver._contexts["fixture-session"] = self.context
        self.driver._proxy_settings["fixture-session"] = BrowserProxyConfig(
            enabled=True, proxy_url="http://127.0.0.1:38080",
            capture_required=True, guard_scope=self.scope)

    def test_only_matching_cookie_is_returned_as_opaque_secret(self) -> None:
        material = self.driver.cookie_header_for(
            "fixture-session", "https://app.example.test/app/item")
        self.assertIsInstance(material, SecretValue)
        self.assertEqual(material.reveal(execution_boundary=True), "owned=local-fixture")
        self.assertEqual(self.context.requests, [["https://app.example.test/app/item"]])

    def test_scope_and_cookie_errors_fail_closed(self) -> None:
        for url in ("https://billing.example.test/app/item",
                    "https://app.example.test/other", "http://app.example.test/app/item",
                    "https://app.example.test:8443/app/item"):
            with self.subTest(url=url), self.assertRaises(BrowserError):
                self.driver.cookie_header_for("fixture-session", url)
        self.assertEqual(len(self.context.requests), 1)
        self.context._cookies = [{"name": "owned", "value": "bad\r\nvalue",
                                  "domain": ".example.test", "path": "/app",
                                  "secure": True, "expires": -1}]
        with self.assertRaises(BrowserError):
            self.driver.cookie_header_for("fixture-session",
                                          "https://app.example.test/app/item")
        self.driver._proxy_settings["fixture-session"] = BrowserProxyConfig()
        with self.assertRaises(BrowserError):
            self.driver.cookie_header_for("fixture-session",
                                          "https://app.example.test/app/item")


if __name__ == "__main__":
    unittest.main()
