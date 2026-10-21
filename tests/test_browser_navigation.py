"""Synthetic policy/capture checks for authenticated browser mapping."""

from dataclasses import replace
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from hackbot.auth import AuthMechanism
from hackbot.browser import (BrowserProxyConfig, IdentityObservation,
                             IdentityVerificationRule)
from hackbot.browser_navigation import (BrowserActionExecutor,
                                        BrowserNavigationError,
                                        BrowserRequestGate)
from hackbot.browser_playwright import BrowserNavigationObservation
from hackbot.config import (BrowserSettings, BurpSettings, ResourceSettings,
                            TargetSettings, load_config)
from hackbot.rate_limit import ExperimentBudget
from hackbot.service import BugHunterRuntime


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class FakeNavigationDriver:
    name = "FAKE"

    def __init__(self) -> None:
        self.running: set[str] = set()
        self.ticket_seen = False

    def start(self, session_id, _profile, *, display, proxy) -> None:
        self.running.add(session_id)

    def stop(self, session_id) -> None:
        self.running.discard(session_id)

    def is_running(self, session_id) -> bool:
        return session_id in self.running

    def observe_identity(self, _session_id, rule) -> IdentityObservation:
        return IdentityObservation(user_id=rule.expected_user_id)

    def apply_imported_session(self, _session_id, _material, _allowed_url) -> None:
        raise AssertionError("No imported session in this fixture")

    def navigate_readonly(self, session_id, url, gate, redirect_allowed, *,
                          request_cap, timeout_ms, response_cap):
        ticket = gate(url, "GET", True)
        if ticket is None:
            return BrowserNavigationObservation(url, None, (), (), (), (), 1, 1, 0,
                                                "POLICY_DENIED")
        self.ticket_seen = True
        gate.release(ticket, True)
        return BrowserNavigationObservation(url, 200, (), (), (), (), 1, 0, 0, None)


class BrowserNavigationTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        shutil.copytree(EXAMPLE, root / "targets/example")
        base = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                    "XDG_STATE_HOME": str(root)})
        config = replace(
            base, targets=TargetSettings(root / "targets"),
            browser=BrowserSettings(profile_root=root / "profiles", display=":901",
                                    vnc_url="http://127.0.0.1:6901/vnc.html"),
            burp=BurpSettings(True, root / "burp"),
            resources=ResourceSettings(min_available_memory_bytes=0))
        self.driver = FakeNavigationDriver()
        self.runtime = BugHunterRuntime(config, driver=self.driver,
                                        vnc_ready=lambda: True)
        self.package = self.runtime.package("example")
        self.runtime.registry.register_target(self.package)
        self.runtime.registry.import_package_accounts(self.package)
        self.identity = self.runtime.registry.get_identity(self.package.target.id,
                                                          "org1_admin")
        self.runtime.auth.prepare(self.package.target.id, self.identity.id,
                                  mechanism=AuthMechanism.MANUAL_LOGIN)
        proxy = BrowserProxyConfig(enabled=True, proxy_url="http://127.0.0.1:38080",
                                   reference="test_proxy", capture_required=True)
        self.session = self.runtime.browser.create(self.package.target.id, self.identity.id,
                                                   proxy=proxy)
        self.runtime.browser.start(self.session.id, proxy=proxy,
                                   proxy_health_check=lambda _: True)
        self.runtime.browser.login_complete(self.session.id)
        self.runtime.browser.verify(
            self.session.id, IdentityVerificationRule(
                self.package.target.id, self.identity.id,
                user_id_selector="#fixture", expected_user_id="org1_admin"))

    def _gate(self) -> BrowserRequestGate:
        return BrowserRequestGate(
            self.package, self.session.id, self.identity.id,
            self.runtime.policy, self.runtime.permits, self.runtime.rate,
            self.runtime.burp, "synthetic-browser-map",
            ExperimentBudget(max_requests=4, max_mutations=0,
                             max_creations=0, max_retries=0))

    def test_scope_and_method_are_denied_before_permit(self):
        with patch.object(self.runtime.burp, "ready", return_value=True):
            gate = self._gate()
            self.assertIsNone(gate("https://foreign.invalid/", "GET", True))
            self.assertIsNone(gate("https://example.test/write", "POST", True))
            self.assertEqual(gate.authorized_count, 0)
            ticket = gate("https://example.test/projects", "GET", True)
            self.assertIsNotNone(ticket)
            gate.release(ticket, True)
            self.assertEqual(gate.authorized_count, 1)
            self.assertFalse(self.runtime.rate.release(ticket.reservation_id))
            self.assertIsNone(gate("https://billing.example.test/", "GET", True))

    def test_gate_paces_second_read_within_target_rate(self):
        with patch.object(self.runtime.burp, "ready", return_value=True):
            gate = self._gate()
            first = gate("https://example.test/projects", "GET", True)
            self.assertIsNotNone(first)
            gate.release(first, True)
            second = gate("https://example.test/settings", "GET", True)
            self.assertIsNotNone(second)
            gate.release(second, True)
            self.assertEqual(gate.authorized_count, 2)

    def test_navigation_requires_burp_capture_evidence(self):
        executor = BrowserActionExecutor(
            browser=self.runtime.browser, driver=self.driver,
            burp=self.runtime.burp, policy=self.runtime.policy,
            permits=self.runtime.permits, rate=self.runtime.rate,
            traffic=self.runtime.traffic)
        with patch.object(self.runtime.burp, "ready", return_value=True):
            with self.assertRaisesRegex(BrowserNavigationError, "not recorded"):
                executor.navigate(self.package, self.session.id,
                                  "https://example.test/projects",
                                  experiment_id="synthetic-browser-map")
        self.assertTrue(self.driver.ticket_seen)

    def test_redirect_query_is_not_authorized_by_host_scope_alone(self):
        executor = BrowserActionExecutor(
            browser=self.runtime.browser, driver=self.driver,
            burp=self.runtime.burp, policy=self.runtime.policy,
            permits=self.runtime.permits, rate=self.runtime.rate,
            traffic=self.runtime.traffic)

        def inspect(_session, url, _gate, redirect_allowed, **_kwargs):
            self.assertTrue(redirect_allowed("https://example.test/settings"))
            self.assertFalse(redirect_allowed(
                "https://example.test/callback?code=synthetic-secret"))
            self.assertFalse(redirect_allowed("https://billing.example.test/"))
            return BrowserNavigationObservation(url, None, (), (), (), (), 0, 0, 1,
                                                "REDIRECT_DENIED")

        with patch.object(self.runtime.burp, "ready", return_value=True), \
             patch.object(self.driver, "navigate_readonly", side_effect=inspect):
            result = executor.navigate(self.package, self.session.id,
                                       "https://example.test/settings",
                                       experiment_id="synthetic-redirect")
        self.assertEqual(result.error_code, "REDIRECT_DENIED")


if __name__ == "__main__":
    unittest.main()
