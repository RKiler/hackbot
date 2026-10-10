"""Optional local Chromium smoke: no external URLs are opened."""

from pathlib import Path
import os
from tempfile import TemporaryDirectory
import unittest

from hackbot.browser import BrowserProxyConfig, IdentityVerificationRule
from hackbot.browser_playwright import PlaywrightBrowserDriver

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
