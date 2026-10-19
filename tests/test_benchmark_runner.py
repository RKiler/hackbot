from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from hackbot.benchmark_catalog import BenchmarkCatalog
from hackbot.benchmark_models import BenchmarkRunConfig
from hackbot.benchmark_runner import BenchmarkOfflineRunner
from hackbot.benchmark_report import build_benchmark_report, write_benchmark_report
from hackbot.benchmark_store import BenchmarkStore
from hackbot.resources import ResourceError


EXAMPLE = Path(__file__).parent / "examples/targets/example/target.yaml"
BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"


class BenchmarkOfflineRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.visible = self.root / "visible"
        self.truth = self.root / "truth"
        case_root = self.visible / "secure_a"
        (case_root / "package").mkdir(parents=True)
        self.truth.mkdir()
        shutil.copyfile(EXAMPLE, case_root / "package/target.yaml")
        package_file = case_root / "package/target.yaml"
        package_file.write_text(
            package_file.read_text(encoding="utf-8").replace(
                '    - "*.example.test"\n', ""), encoding="utf-8")
        (case_root / "traffic.json").write_text(json.dumps([
            {"method": "GET", "url": "https://example.test/api/projects/123",
             "status": 403},
        ]), encoding="utf-8")
        digest = hashlib.sha256()
        for name in ("package/target.yaml", "traffic.json"):
            digest.update(name.encode("ascii") + b"\0")
            digest.update((case_root / name).read_bytes())
            digest.update(b"\0")
        manifest = {
            "case_id": "secure_a", "version": 1, "fixture_id": "example",
            "target_package": "package/target.yaml", "scope_hosts": ["example.test"],
            "identity_aliases": [], "input_files": ["traffic.json"],
            "context_file": None, "budget": {
                "requests": 0, "browser_actions": 0, "research_calls": 0,
                "tokens": 0, "seconds": 60}, "visible_hash": digest.hexdigest(),
        }
        (case_root / "case.json").write_text(json.dumps(manifest), encoding="utf-8")
        (self.visible / "suites.json").write_text('{"smoke":["secure_a"]}',
                                                  encoding="utf-8")
        truth = {
            "case_id": "secure_a", "version": 1,
            "category": "SECURE_NEGATIVE_CASE", "difficulty": "BASIC",
            "split": "DEVELOPMENT", "roots": [], "expected_specialist": None,
            "expected_skill_ids": [], "forbidden_interpretations": [],
            "known_controls": ["anonymous_403"], "tags": [],
        }
        (self.truth / "secure_a.json").write_text(json.dumps(truth), encoding="utf-8")

    def test_real_campaign_analysis_is_offline_and_isolated(self):
        catalog = BenchmarkCatalog(self.visible, self.truth)
        store = BenchmarkStore(self.root / "benchmark-state/benchmark.sqlite3")
        runner = BenchmarkOfflineRunner(catalog, store, self.root / "work")
        with patch("socket.socket.connect", side_effect=AssertionError("network attempted")):
            run_id = runner.run(BenchmarkRunConfig("smoke"),
                                bughunter_version="test", bughunter_schema=48)
        run = store.get(run_id)
        self.assertEqual(run["status"], "COMPLETED")
        case = store.cases(run_id)[0]
        self.assertEqual(case["status"], "COMPLETED")
        self.assertIsNotNone(case["campaign_id"])
        self.assertEqual(case["evaluation"]["detected_vulnerabilities"], 0)
        self.assertEqual(case["evaluation"]["false_confirmed_findings"], 0)
        self.assertEqual(case["evaluation"]["usage"]["requests"], 0)
        self.assertEqual({path.name for path in (self.root / "work").iterdir()},
                         {".benchmark-run.lock"})
        report = build_benchmark_report(store, run_id)
        self.assertEqual(report["label"], "SYNTHETIC / EVALUATION")
        self.assertEqual(report["metrics"]["secure_cases_with_false_confirmations"], 0)
        self.assertEqual(report["readiness"]["conclusion"], "NOT_READY")
        self.assertEqual(report["cost_estimate"]["total_usd"], None)
        json_path, md_path = write_benchmark_report(report, self.root / "reports")
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["run_id"], run_id)
        self.assertIn("OFFLINE_ANALYSIS_HAS_NO_VALIDATION_PROOF",
                      md_path.read_text(encoding="utf-8"))
        self.assertEqual(json_path.stat().st_mode & 0o777, 0o600)

    def test_refuses_non_synthetic_scope_before_campaign(self):
        manifest_path = self.visible / "secure_a/case.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["scope_hosts"] = ["real.example.com"]
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        store = BenchmarkStore(self.root / "state/benchmark.sqlite3")
        runner = BenchmarkOfflineRunner(BenchmarkCatalog(self.visible, self.truth), store,
                                        self.root / "work")
        run_id = runner.run(BenchmarkRunConfig("smoke"),
                            bughunter_version="test", bughunter_schema=48)
        case = store.cases(run_id)[0]
        self.assertEqual(case["status"], "FAILED")
        self.assertEqual(case["error_code"], "ValueError")
        self.assertEqual(case["trace"], None)

    def test_resource_failure_records_only_reason_code(self):
        store = BenchmarkStore(self.root / "resource-state/benchmark.sqlite3")
        runner = BenchmarkOfflineRunner(BenchmarkCatalog(self.visible, self.truth), store,
                                        self.root / "resource-work")
        with patch.object(runner, "_run_case", side_effect=ResourceError("LOW_MEMORY")):
            run_id = runner.run(BenchmarkRunConfig("smoke"),
                                bughunter_version="test", bughunter_schema=48)
        case = store.cases(run_id)[0]
        self.assertEqual(case["status"], "FAILED")
        self.assertEqual(case["error_code"], "LOW_MEMORY")
        self.assertIsNone(case["trace"])

    def test_versioned_download_pair_runs_without_confirmation_credit(self):
        catalog = BenchmarkCatalog(BENCHMARKS / "visible", BENCHMARKS / "truth")
        self.assertEqual(catalog.suite("smoke"),
                         ("download_exposed", "download_guarded"))
        store = BenchmarkStore(self.root / "pair-state/benchmark.sqlite3")
        runner = BenchmarkOfflineRunner(catalog, store, self.root / "pair-work")
        with patch("socket.socket.connect", side_effect=AssertionError("network attempted")):
            run_id = runner.run(BenchmarkRunConfig("smoke"),
                                bughunter_version="test", bughunter_schema=48)
        rows = store.cases(run_id)
        self.assertEqual([row["status"] for row in rows], ["COMPLETED", "COMPLETED"])
        report = build_benchmark_report(store, run_id)
        self.assertEqual(report["metrics"]["expected_vulnerabilities"], 1)
        self.assertEqual(report["metrics"]["detected_vulnerabilities"], 0)
        self.assertEqual(report["readiness"]["conclusion"], "NOT_READY")

    def test_no_traffic_ablation_is_explicit_and_resumable(self):
        catalog = BenchmarkCatalog(BENCHMARKS / "visible", BENCHMARKS / "truth")
        store = BenchmarkStore(self.root / "ablation-state/benchmark.sqlite3")
        runner = BenchmarkOfflineRunner(catalog, store, self.root / "ablation-work")
        config = BenchmarkRunConfig("smoke", ablations=("NO_TRAFFIC",))
        with patch("hackbot.benchmark_runner._fixture_traffic",
                   side_effect=AssertionError("fixture traffic was consumed")):
            run_id = runner.run(config, bughunter_version="test", bughunter_schema=48)
            runner.resume(run_id)
        self.assertEqual(store.get(run_id)["status"], "COMPLETED")
        self.assertTrue(all(row["status"] == "COMPLETED" for row in store.cases(run_id)))
        report = build_benchmark_report(store, run_id)
        self.assertEqual(report["ablations"], ["NO_TRAFFIC"])
        self.assertEqual(report["metrics"]["candidate_count"], 0)
        with self.assertRaisesRegex(ValueError, "supports only NO_TRAFFIC"):
            runner.run(BenchmarkRunConfig("smoke", ablations=("NO_MODEL",)),
                       bughunter_version="test", bughunter_schema=48)

    def test_resume_does_not_replay_interrupted_case(self):
        catalog = BenchmarkCatalog(BENCHMARKS / "visible", BENCHMARKS / "truth")
        store = BenchmarkStore(self.root / "resume-state/benchmark.sqlite3")
        store.initialize()
        cases = tuple((case_id, catalog.visible(case_id).visible_hash)
                      for case_id in catalog.suite("smoke"))
        run_id = store.create(BenchmarkRunConfig("smoke"), cases,
                              benchmark_version="33.1", bughunter_version="test",
                              bughunter_schema=48,
                              environment={"mode": "SYNTHETIC_OFFLINE"})
        claimed = store.claim(run_id)
        self.assertEqual(claimed["case_id"], "download_exposed")
        runner = BenchmarkOfflineRunner(catalog, store, self.root / "resume-work")
        with patch("socket.socket.connect", side_effect=AssertionError("network attempted")):
            runner.resume(run_id)
        rows = {row["case_id"]: row for row in store.cases(run_id)}
        self.assertEqual(rows["download_exposed"]["status"], "AMBIGUOUS")
        self.assertEqual(rows["download_exposed"]["trace"], None)
        self.assertEqual(rows["download_guarded"]["status"], "COMPLETED")
        self.assertEqual(store.get(run_id)["status"], "AMBIGUOUS")


if __name__ == "__main__":
    unittest.main()
