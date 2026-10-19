from __future__ import annotations

from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from hackbot.cli import main


BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"


class BenchmarkCLITests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.env = {"HOME": str(self.root), "XDG_CONFIG_HOME": str(self.root),
                    "XDG_STATE_HOME": str(self.root),
                    "HACKBOT_HOME": str(self.root / "runtime")}

    def call(self, *args):
        out, err = StringIO(), StringIO()
        code = main(args, environ=self.env, stdout=out, stderr=err)
        return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()

    def test_list_run_show_compare_and_readiness(self):
        root = ("benchmark", "--fixtures-root", str(BENCHMARKS))
        code, listed, _ = self.call(*root, "list")
        self.assertEqual(code, 0)
        self.assertIn("smoke", {item["name"] for item in listed["suites"]})
        with patch("socket.socket.connect", side_effect=AssertionError("network attempted")):
            code, created, _ = self.call(*root, "run", "smoke")
        self.assertEqual(code, 0)
        self.assertEqual(created["status"], "COMPLETED")
        run_id = created["run_id"]
        code, resumed, _ = self.call(*root, "resume", run_id)
        self.assertEqual(code, 0)
        self.assertEqual(resumed["status"], "COMPLETED")
        code, shown, _ = self.call("benchmark", "show", run_id)
        self.assertEqual(code, 0)
        self.assertEqual(shown["metrics"]["expected_vulnerabilities"], 1)
        self.assertEqual(shown["metrics"]["detected_vulnerabilities"], 0)
        code, compared, _ = self.call("benchmark", "compare", run_id, run_id)
        self.assertEqual(code, 0)
        self.assertEqual(compared["baseline"], compared["current"])
        code, readiness, _ = self.call("readiness")
        self.assertEqual(code, 0)
        self.assertEqual(readiness["readiness"]["conclusion"], "NOT_READY")
        self.assertFalse((self.root / "runtime/state/bughunter.sqlite3").exists())

    def test_unknown_run_is_redacted_error(self):
        code, result, err = self.call("benchmark", "show", "BENCH-missing")
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertIn("benchmark unavailable", err)

    def test_low_resource_coverage_is_read_only_and_complete(self):
        root = ("benchmark", "--fixtures-root", str(BENCHMARKS))
        with patch("socket.socket.connect", side_effect=AssertionError("network attempted")):
            code, result, _ = self.call(*root, "coverage", "local-low-resource-candidate")
        self.assertEqual(code, 0)
        self.assertTrue(result["fixture_coverage_complete"])
        self.assertEqual(result["scope"], "FIXTURE_INVENTORY_ONLY")
        self.assertFalse((self.root / "runtime/state/benchmark.sqlite3").exists())

    def test_local_mode_requires_explicit_selection(self):
        root = ("benchmark", "--fixtures-root", str(BENCHMARKS))
        code, result, err = self.call(*root, "run", "local-smoke")
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertIn("benchmark unavailable", err)

    def test_bounded_trials_are_operator_selected_and_resumable(self):
        root = ("benchmark", "--fixtures-root", str(BENCHMARKS))
        with patch("socket.socket.connect", side_effect=AssertionError("network attempted")):
            code, created, _ = self.call(*root, "run", "smoke", "--trials", "2",
                                         "--seed", "33")
        self.assertEqual(code, 0)
        self.assertEqual(created["status"], "COMPLETED")
        code, shown, _ = self.call("benchmark", "show", created["run_id"])
        self.assertEqual(code, 0)
        self.assertEqual(shown["total_case_runs"], 4)
        self.assertEqual(shown["metrics"]["trial_stability"]["download_exposed"]["trials"], 2)
        code, resumed, _ = self.call(*root, "resume", created["run_id"])
        self.assertEqual(code, 0)
        self.assertEqual(resumed["status"], "COMPLETED")
        code, result, err = self.call(*root, "run", "smoke", "--trials", "6")
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertIn("benchmark unavailable", err)

    def test_offline_traffic_ablation_is_operator_selected(self):
        root = ("benchmark", "--fixtures-root", str(BENCHMARKS))
        with patch("socket.socket.connect", side_effect=AssertionError("network attempted")):
            code, created, _ = self.call(*root, "run", "smoke", "--ablation",
                                         "NO_TRAFFIC")
        self.assertEqual(code, 0)
        code, shown, _ = self.call("benchmark", "show", created["run_id"])
        self.assertEqual(code, 0)
        self.assertEqual(shown["ablations"], ["NO_TRAFFIC"])
        self.assertEqual(shown["metrics"]["candidate_count"], 0)
        code, resumed, _ = self.call(*root, "resume", created["run_id"])
        self.assertEqual(code, 0)
        self.assertEqual(resumed["status"], "COMPLETED")

    def test_fake_provider_model_ablations_are_operator_invoked_and_resumable(self):
        root = ("benchmark", "--fixtures-root", str(BENCHMARKS))
        code, created, _ = self.call(*root, "run", "local-advice", "--mode", "local",
                                     "--fake-providers", "--ablation", "NO_CHALLENGER")
        self.assertEqual(code, 0)
        code, shown, _ = self.call("benchmark", "show", created["run_id"])
        self.assertEqual(code, 0)
        self.assertEqual(shown["ablations"], ["NO_CHALLENGER"])
        self.assertEqual(shown["model_comparison"]["lane_statuses"]["CHALLENGER"],
                         {"NOT_CONFIGURED": 2})
        self.assertIn("FAKE_PROVIDER_DIAGNOSTIC_NOT_MODEL_QUALITY",
                      shown["limitations"])
        code, resumed, _ = self.call(*root, "resume", created["run_id"])
        self.assertEqual(code, 0)
        self.assertEqual(resumed["status"], "COMPLETED")

        code, model_free, _ = self.call(*root, "run", "local-advice", "--mode", "local",
                                        "--fake-providers", "--ablation", "NO_MODEL")
        self.assertEqual(code, 0)
        code, shown, _ = self.call("benchmark", "show", model_free["run_id"])
        self.assertEqual(code, 0)
        self.assertEqual(shown["model_mode"], "DETERMINISTIC_ONLY")
        self.assertEqual(shown["metrics"]["tokens"], 0)

    def test_failed_run_writes_report_and_exits_nonzero(self):
        root = ("benchmark", "--fixtures-root", str(BENCHMARKS))
        with patch("hackbot.benchmark_runner.BenchmarkOfflineRunner.run",
                   return_value="BENCH-" + "1" * 32), patch(
                   "hackbot.benchmark_report.build_benchmark_report",
                   return_value={"status": "FAILED", "readiness": {
                       "conclusion": "NOT_READY"}}), patch(
                   "hackbot.benchmark_report.write_benchmark_report",
                   return_value=(self.root / "report.json", self.root / "report.md")):
            code, result, _ = self.call(*root, "run", "smoke")
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
