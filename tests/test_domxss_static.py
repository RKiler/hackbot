import shutil
from subprocess import TimeoutExpired
import unittest
from unittest.mock import patch

from hackbot.domxss_static import (
    DOMCandidateStatus, DOMStaticAnalyzer, MAX_ASSET_BYTES,
)


@unittest.skipUnless(shutil.which("node"), "Node/Babel parser unavailable")
class DOMStaticAnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = DOMStaticAnalyzer()

    def analyze(self, source: str):
        return self.analyzer.analyze(target_id="TARGET-local", recon_asset_id=7,
                                     body=source.encode())

    def test_check_before_transform_connected_flow(self) -> None:
        result = self.analyze("""
          function render() {
            const p = new URLSearchParams(location.search).get('u');
            if (!p.startsWith('javascript:')) {
              const decoded = decodeURIComponent(p);
              iframe.src = decoded;
            }
          }
        """)
        self.assertEqual(result.status, "ANALYZED")
        self.assertEqual(len(result.candidates), 1)
        item = result.candidates[0]
        self.assertEqual(item.status, DOMCandidateStatus.STATICALLY_SUPPORTED)
        self.assertEqual(item.source, "location.search")
        self.assertEqual(item.sink, "iframe.src")
        self.assertEqual([step.operation for step in item.transforms], ["decodeURIComponent"])
        self.assertTrue(item.check_before_transform)

    def test_double_decode_requires_two_observed_transforms(self) -> None:
        result = self.analyze("""
          function render() {
            const input = location.hash;
            if (!input.includes('javascript:')) {
              const twice = decodeURIComponent(decodeURIComponent(input));
              iframe.src = twice;
            }
          }
        """)
        self.assertEqual(result.status, "ANALYZED", result.reason)
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(len(result.candidates[0].transforms), 2)

    def test_unrelated_source_and_sink_are_not_connected(self) -> None:
        result = self.analyze("""
          function render() {
            const input = location.search;
            if (input.startsWith('https:')) console.log(input);
            iframe.src = '/static/help';
          }
        """)
        self.assertEqual(result.candidates, ())

    def test_final_encoder_is_rejected_as_static_candidate(self) -> None:
        result = self.analyze("""
          function render() {
            const input = location.hash;
            if (input.startsWith('safe:')) {
              const decoded = decodeURIComponent(input);
              iframe.src = encodeURIComponent(decoded);
            }
          }
        """)
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(result.candidates[0].status, DOMCandidateStatus.REJECTED)
        self.assertEqual(result.candidates[0].sanitizers[0].operation, "encodeURIComponent")

    def test_post_transform_guard_needs_review(self) -> None:
        result = self.analyze("""
          function render() {
            const input = location.hash;
            if (!input.startsWith('javascript:')) {
              const decoded = decodeURIComponent(input);
              if (decoded.startsWith('javascript:')) return;
              iframe.src = decoded;
            }
          }
        """)
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(result.candidates[0].status, DOMCandidateStatus.NEEDS_MANUAL_REVIEW)
        self.assertEqual(result.candidates[0].post_checks[0].operation, "startsWith")

    def test_unknown_helper_needs_review(self) -> None:
        result = self.analyze("""
          function render() {
            const input = location.hash;
            if (!input.startsWith('javascript:')) {
              iframe.src = unknownSecurityHelper(decodeURIComponent(input));
            }
          }
        """)
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(result.candidates[0].status, DOMCandidateStatus.NEEDS_MANUAL_REVIEW)
        self.assertTrue(result.candidates[0].unresolved_helper)

    def test_postmessage_source_is_not_assumed_attacker_controlled(self) -> None:
        result = self.analyze("""
          function onMessage(event) {
            const value = event.data;
            if (value.startsWith('https:')) {
              iframe.src = decodeURIComponent(value);
            }
          }
        """)
        self.assertEqual(result.status, "ANALYZED", result.reason)
        self.assertEqual(len(result.candidates), 1)
        self.assertFalse(result.candidates[0].attacker_controlled)
        self.assertEqual(result.candidates[0].status, DOMCandidateStatus.TRACING)

    def test_oversized_asset_is_not_parsed(self) -> None:
        result = self.analyzer.analyze(target_id="TARGET-local",
                                       body=b"location.search;iframe.src=" + b"a" * MAX_ASSET_BYTES)
        self.assertEqual(result.status, DOMCandidateStatus.ANALYSIS_LIMIT_REACHED.value)
        self.assertEqual(result.candidates, ())

    def test_malformed_js_is_not_promoted(self) -> None:
        result = self.analyze("function broken( { location.search; iframe.src = ;")
        self.assertEqual(result.status, DOMCandidateStatus.PARSE_FAILED.value)
        self.assertEqual(result.candidates, ())

    def test_parser_timeout_is_visible_and_never_promotes_a_candidate(self) -> None:
        with patch("hackbot.domxss_static.subprocess.run",
                   side_effect=TimeoutExpired(cmd="node", timeout=20)):
            result = self.analyze("function f(){iframe.src=location.hash}")
        self.assertEqual(result.status, DOMCandidateStatus.PARSE_FAILED.value)
        self.assertEqual(result.reason, "PARSER_TIMEOUT")
        self.assertEqual(result.candidates, ())


if __name__ == "__main__":
    unittest.main()
