from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest

from hackbot.benchmark_acceptance import assess_low_resource_fixture_coverage
from hackbot.benchmark_catalog import BenchmarkCatalog
from hackbot.benchmark_models import BenchmarkCategory, BenchmarkFixtureKind


BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"


class LowResourceCoverageTests(unittest.TestCase):
    def test_current_candidate_suite_pairs_all_specialists(self) -> None:
        catalog = BenchmarkCatalog(BENCHMARKS / "visible", BENCHMARKS / "truth")
        result = assess_low_resource_fixture_coverage(catalog, "local-low-resource-candidate")
        coverage = {item.specialist: item.to_dict() for item in result.specialist_pairs}
        self.assertTrue(result.complete)
        self.assertTrue(coverage["AUTHORIZATION"]["covered"])
        self.assertTrue(coverage["API_GRAPHQL"]["covered"])
        self.assertTrue(coverage["EXPOSURE"]["covered"])
        self.assertTrue(coverage["DOM_XSS"]["covered"])
        self.assertTrue(coverage["POSTMESSAGE"]["covered"])
        self.assertEqual(result.noisy_secure_cases, ("local_surface_c",))
        self.assertEqual(result.mixed_cases, ("local_mixed_a",))

    def test_unpaired_specialist_does_not_pass(self) -> None:
        class Catalog:
            def suite(self, _name):
                return ("dom-positive", "other-secure", "noisy", "mixed")

            def visible(self, case_id):
                kind = (BenchmarkFixtureKind.LOCAL_OWNED_DOWNLOAD if case_id in {"other-secure", "noisy"}
                        else BenchmarkFixtureKind.LOCAL_MIXED_WORKSPACE if case_id == "mixed"
                        else BenchmarkFixtureKind.LOCAL_GRAPHQL_OBJECT)
                return SimpleNamespace(case_id=case_id, fixture_kind=kind, version=1,
                                       visible_hash="a" * 64)

            def audit_visible_inputs(self, _case_id):
                return ()

            def ground_truth(self, case_id):
                return SimpleNamespace(
                    case_id=case_id, version=1,
                    roots=(SimpleNamespace(category=BenchmarkCategory.CROSS_TENANT_BOLA),
                           SimpleNamespace(category=BenchmarkCategory.CROSS_TENANT_BOLA))
                          if case_id == "mixed" else
                          (SimpleNamespace(category=BenchmarkCategory.DOM_XSS),)
                          if case_id == "dom-positive" else (),
                    expected_specialist="DOM_XSS" if case_id == "dom-positive" else None,
                    category=BenchmarkCategory.NOISY_FALSE_POSITIVE_CASE
                    if case_id == "noisy" else BenchmarkCategory.OTHER)

        result = assess_low_resource_fixture_coverage(Catalog(), "fixture")
        dom = next(item for item in result.specialist_pairs
                   if item.specialist == "DOM_XSS")
        self.assertEqual(dom.vulnerable_cases, ("dom-positive",))
        self.assertEqual(dom.secure_cases, ())
        self.assertEqual(dom.paired_fixture_kinds, ())
        self.assertFalse(result.mixed_cases)
        self.assertFalse(result.complete)

    def test_answer_leak_aborts_coverage(self) -> None:
        catalog = BenchmarkCatalog(BENCHMARKS / "visible", BENCHMARKS / "truth")
        original = catalog.audit_visible_inputs
        catalog.audit_visible_inputs = lambda case_id: ("LEAK",) if case_id == "local_tenant_a" else original(case_id)
        with self.assertRaisesRegex(ValueError, "leaked"):
            assess_low_resource_fixture_coverage(catalog, "local-low-resource-candidate")

    def test_same_kind_with_different_visible_inputs_is_not_a_pair(self) -> None:
        class Catalog:
            def suite(self, _name):
                return ("positive", "guarded")

            def visible(self, case_id):
                return SimpleNamespace(case_id=case_id, version=1,
                    fixture_kind=BenchmarkFixtureKind.LOCAL_GRAPHQL_OBJECT,
                    visible_hash=("a" if case_id == "positive" else "b") * 64)

            def audit_visible_inputs(self, _case_id):
                return ()

            def ground_truth(self, case_id):
                return SimpleNamespace(case_id=case_id, version=1,
                    roots=(SimpleNamespace(category=BenchmarkCategory.GRAPHQL_OBJECT_AUTH),)
                          if case_id == "positive" else (),
                    expected_specialist="API_GRAPHQL" if case_id == "positive" else None,
                    category=BenchmarkCategory.GRAPHQL_OBJECT_AUTH if case_id == "positive"
                    else BenchmarkCategory.SECURE_NEGATIVE_CASE)

        result = assess_low_resource_fixture_coverage(Catalog(), "fixture")
        graphql = next(item for item in result.specialist_pairs
                       if item.specialist == "API_GRAPHQL")
        self.assertEqual(graphql.vulnerable_cases, ("positive",))
        self.assertEqual(graphql.secure_cases, ())
        self.assertFalse(graphql.paired_fixture_kinds)


if __name__ == "__main__":
    unittest.main()
