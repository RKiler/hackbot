"""Synthetic, no-network authenticated application map selection."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import unittest

from hackbot.application_mapper import ApplicationMapper, MappingLimits
from hackbot.browser_navigation import BrowserNavigationBudgetReached
from hackbot.browser_playwright import BrowserNavigationObservation
from hackbot.target_loader import load_target_package


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class ApplicationMapperTests(unittest.TestCase):
    def test_current_authenticated_scheme_skips_alternate_scheme_root(self):
        original = load_target_package(EXAMPLE)
        package = replace(original, scope=replace(
            original.scope, default_schemes=("http", "https"),
            default_ports=(80, 443)))
        browser = Mock()
        browser.session_context.return_value = SimpleNamespace(
            target_id=package.target.id, identity_id="IDENTITY-" + "2" * 32)
        driver = Mock()
        driver.observe_current_page.return_value = {"url": "http://example.test/app"}
        visited = []

        def navigate(_package, _session, url, **_kwargs):
            visited.append(url)
            links = ("/projects",) if url.endswith("/app") else ()
            return BrowserNavigationObservation(url, 200, (), links, (), (),
                                                1, 0, 0, None)

        navigation = Mock()
        navigation.navigate.side_effect = navigate
        evidence = Mock()
        evidence.create_evidence.return_value = SimpleNamespace(
            evidence_id="EV-" + "3" * 32)
        mapper = ApplicationMapper(browser=browser, driver=driver,
                                   navigation=navigation, evidence=evidence)
        result = mapper.map_session(package, "BSESSION-" + "3" * 32,
                                    experiment_id="mixed-scheme",
                                    limits=MappingLimits(max_pages=2))
        self.assertEqual(result.pages_observed, 2)
        self.assertEqual(visited,
                         ["http://example.test/app", "http://example.test/projects"])

    def test_observed_links_are_bounded_scoped_and_redacted_in_evidence(self):
        package = load_target_package(EXAMPLE)
        browser = Mock()
        browser.session_context.return_value = SimpleNamespace(
            target_id=package.target.id, identity_id="IDENTITY-" + "2" * 32)
        driver = Mock()
        driver.observe_current_page.return_value = {
            "url": "https://example.test/projects"}
        requested = []

        def navigate(_package, _session, url, **_kwargs):
            requested.append(url)
            links = (("/projects/123", "https://billing.example.test/",
                      "/delete", "/settings", "/settings")
                     if url.endswith("/projects") else ())
            return BrowserNavigationObservation(
                url, 200, ("/static/app.js",), links,
                (("/projects/create", "POST"),), (("submit", "Save"),),
                2, 0, 0, None,
                form_fields=((('name', 'text'), ('password', 'password'),
                              ('csrf_token', 'hidden')),))

        navigation = Mock()
        navigation.navigate.side_effect = navigate
        content = []
        evidence = Mock()

        def record(_kind, body, **_kwargs):
            content.append(body.decode())
            return SimpleNamespace(evidence_id="EV-" + f"{len(content):032x}")

        evidence.create_evidence.side_effect = record
        mapper = ApplicationMapper(browser=browser, driver=driver,
                                   navigation=navigation, evidence=evidence)
        result = mapper.map_session(package, "BSESSION-" + "3" * 32,
                                    experiment_id="synthetic-map",
                                    limits=MappingLimits(max_pages=4))
        self.assertEqual(result.pages_observed, 4)
        self.assertIn("https://example.test/settings", requested)
        self.assertIn("https://example.test/projects/123", requested)
        self.assertNotIn("https://billing.example.test/", requested)
        self.assertNotIn("https://example.test/delete", requested)
        self.assertEqual(result.forms_observed, 4)
        self.assertTrue(all("/projects/123" not in item for item in content))
        self.assertTrue(all("billing.example.test" not in item for item in content))
        self.assertTrue(any('"action":"https://example.test/projects/create"' in item
                            and '"name":"name"' in item for item in content))
        self.assertTrue(all("password" not in item and "csrf_token" not in item
                            for item in content))

    def test_form_schema_rejects_query_and_unscoped_actions(self):
        from hackbot.application_mapper import _form_schema

        package = load_target_package(EXAMPLE)
        self.assertIsNone(_form_schema(
            "https://example.test/projects", ("/api/create?token=secret", "POST"),
            (("name", "text"),), package))
        self.assertIsNone(_form_schema(
            "https://example.test/projects", ("https://other.invalid/create", "POST"),
            (("name", "text"),), package))

    def test_spent_request_budget_is_partial_coverage_not_capture_loss(self):
        package = load_target_package(EXAMPLE)
        browser = Mock()
        browser.session_context.return_value = SimpleNamespace(
            target_id=package.target.id, identity_id="IDENTITY-" + "2" * 32)
        driver = Mock()
        driver.observe_current_page.return_value = {"url": "https://example.test/projects"}
        navigation = Mock()
        navigation.navigate.side_effect = BrowserNavigationBudgetReached(
            "Browser mapping request budget reached")
        mapper = ApplicationMapper(browser=browser, driver=driver,
                                   navigation=navigation, evidence=Mock())
        result = mapper.map_session(package, "BSESSION-" + "3" * 32,
                                    experiment_id="spent-budget")
        self.assertEqual(result.blocked, ("MAPPING_REQUEST_BUDGET",))
        self.assertEqual(result.pages_observed, 0)


if __name__ == "__main__":
    unittest.main()
