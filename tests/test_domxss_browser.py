import unittest

from hackbot.domxss_browser import (DOMBrowserExperimentExecutor, DOMInputKind,
                                    DOMVariant)


class DOMBrowserPayloadTests(unittest.TestCase):
    def test_query_value_is_encoded_without_changing_route(self) -> None:
        url = DOMBrowserExperimentExecutor._url(
            "https://app.example.invalid/preview", DOMInputKind.QUERY,
            "next", "javascript:proof()")
        self.assertEqual(url,
                         "https://app.example.invalid/preview?next=javascript%3Aproof%28%29")

    def test_fragment_does_not_become_a_network_query(self) -> None:
        url = DOMBrowserExperimentExecutor._url(
            "https://app.example.invalid/preview", DOMInputKind.FRAGMENT,
            None, "HACKBOT_DOM_PROBE_abc")
        self.assertEqual(url,
                         "https://app.example.invalid/preview#HACKBOT_DOM_PROBE_abc")

    def test_payload_strategy_is_fixed_and_transform_driven(self) -> None:
        marker = "a" * 32
        route = "https://app.example.invalid/preview"
        direct = DOMBrowserExperimentExecutor._payload(
            DOMVariant.DIRECT_DANGEROUS, marker, "URL_RESOURCE", route)
        single = DOMBrowserExperimentExecutor._payload(
            DOMVariant.ENCODED_ONCE, marker, "URL_RESOURCE", route)
        double = DOMBrowserExperimentExecutor._payload(
            DOMVariant.ENCODED_TWICE, marker, "URL_RESOURCE", route)
        self.assertTrue(direct.startswith("javascript:"))
        self.assertIn("javascript%3A", single)
        self.assertIn("javascript%253A", double)
        self.assertNotIn("cookie", direct)
        self.assertNotIn("localStorage", direct)
        self.assertNotIn("fetch(", direct)


if __name__ == "__main__":
    unittest.main()
