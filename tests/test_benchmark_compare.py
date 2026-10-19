from __future__ import annotations

import unittest

from hackbot.benchmark_compare import RegressionThresholds, compare_reports


def report(run_id: str):
    return {
        "run_id": run_id, "suite": "smoke", "benchmark_version": "33.1",
        "status": "COMPLETED", "total_case_runs": 1, "evaluated_cases": 1,
        "cases": [{"case_id": "case_a", "trial": 1, "visible_hash": "a" * 64}],
        "metrics": {"precision": 1.0, "recall": 0.5,
                    "false_confirmed_findings": 0,
                    "secure_cases_with_false_confirmations": 0,
                    "safety_violations": 0, "orphaned_objects": 0,
                    "requests_per_detection": 10.0,
                    "top_k_recall": {"1": 0.5}},
    }


class BenchmarkCompareTests(unittest.TestCase):
    def test_new_false_confirmation_is_critical(self):
        before, after = report("a"), report("b")
        after["metrics"]["false_confirmed_findings"] = 1
        result = compare_reports(before, after)
        self.assertEqual(result["outcome"], "FAIL")
        self.assertEqual(result["checks"]["new_false_confirmed"], "FAIL")

    def test_changed_fixture_is_not_comparable(self):
        before, after = report("a"), report("b")
        after["cases"][0]["visible_hash"] = "b" * 64
        self.assertEqual(compare_reports(before, after)["reason_code"],
                         "INCOMPARABLE_FIXTURE_SET")

    def test_configured_quality_threshold_warns(self):
        before, after = report("a"), report("b")
        after["metrics"].update({"precision": 0.9, "recall": 0.4,
                                 "requests_per_detection": 14.0})
        result = compare_reports(before, after, RegressionThresholds(
            max_precision_drop=0.05, max_recall_drop=0.05,
            max_requests_per_detection_increase_ratio=0.2))
        self.assertEqual(result["outcome"], "WARN")
        self.assertEqual(result["checks"]["request_cost"], "WARN")

    def test_incomplete_run_is_not_measured(self):
        before, after = report("a"), report("b")
        after["status"] = "AMBIGUOUS"
        self.assertEqual(compare_reports(before, after)["reason_code"],
                         "INCOMPLETE_RUN")

    def test_nan_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            RegressionThresholds(max_precision_drop=float("nan"))


if __name__ == "__main__":
    unittest.main()
