from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from hackbot.benchmark_catalog import BenchmarkCatalog
from hackbot.benchmark_eval import CaseTrace, CaseUsage, evaluate_case
from hackbot.benchmark_models import BENCHMARK_VERSION, BenchmarkRunConfig, BenchmarkStatus
from hackbot.benchmark_store import BenchmarkStore
from hackbot.config import load_config
from hackbot.service import create_app


BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"


class BenchmarkAPITests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        env = {"HOME": str(root), "XDG_CONFIG_HOME": str(root),
               "XDG_STATE_HOME": str(root), "HACKBOT_HOME": str(root / "runtime")}
        self.config = load_config(environ=env)
        fake = SimpleNamespace(config=self.config,
                               logger=SimpleNamespace(error=lambda *args: None))
        self.client = create_app(self.config, runtime=fake).test_client()
        self.store = BenchmarkStore(self.config.paths.state / "benchmark.sqlite3")

    def _completed_run(self) -> str:
        catalog = BenchmarkCatalog(BENCHMARKS / "visible", BENCHMARKS / "truth")
        case_id = "local_download_b"
        self.store.initialize()
        run_id = self.store.create(
            BenchmarkRunConfig("local-smoke"),
            ((case_id, catalog.visible(case_id).visible_hash),),
            benchmark_version=BENCHMARK_VERSION, bughunter_version="test",
            bughunter_schema=48,
            environment={"mode": "SYNTHETIC_OFFLINE", "network": "DISABLED"})
        self.store.claim(run_id)
        trace = CaseTrace(case_id, None, (), (), CaseUsage(),
                          "2026-10-18T00:00:00+00:00",
                          "2026-10-18T00:00:01+00:00")
        evaluation = evaluate_case(catalog.evaluator_case(case_id), trace)
        self.store.finish_case(run_id, case_id, 1,
                               status=BenchmarkStatus.COMPLETED,
                               campaign_id=None, trace=asdict(trace),
                               evaluation=evaluation.to_dict())
        self.store.finalize(run_id)
        return run_id

    def test_empty_state_is_read_only_and_suites_do_not_expose_answer_keys(self):
        response = self.client.get("/v1/evaluation/suites")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["label"], "SYNTHETIC / EVALUATION")
        self.assertIn("local-smoke", {item["name"] for item in response.json["items"]})
        self.assertNotIn("roots", response.get_data(as_text=True))
        self.assertEqual(self.client.get("/v1/evaluation/runs").json["items"], [])
        self.assertIsNone(self.client.get("/v1/evaluation/readiness").json["run_id"])
        self.assertFalse(self.store.path.exists())
        self.assertEqual(self.client.post("/v1/evaluation/runs", json={}).status_code, 405)

    def test_paged_read_only_results_and_comparison(self):
        run_id = self._completed_run()
        listed = self.client.get("/v1/evaluation/runs?limit=5")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json["items"][0]["run_id"], run_id)
        detail = self.client.get(f"/v1/evaluation/runs/{run_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json["status"], "COMPLETED")
        self.assertNotIn("cases", detail.json)
        self.assertEqual(detail.json["model_mode"], "DETERMINISTIC_ONLY")
        self.assertEqual(detail.json["specialist_breakdown"][2]["status"], "NOT_MEASURED")
        self.assertEqual(detail.json["failure_analysis"]["missed_cases"], 0)
        cases = self.client.get(f"/v1/evaluation/runs/{run_id}/cases?limit=1&offset=0")
        self.assertEqual(cases.status_code, 200)
        self.assertEqual(cases.json["items"][0]["case_id"], "local_download_b")
        self.assertNotIn("trace", cases.json["items"][0])
        self.assertEqual(self.client.get(
            f"/v1/evaluation/compare?baseline_id={run_id}&current_id={run_id}"
        ).status_code, 200)
        self.assertEqual(self.client.get(
            f"/v1/evaluation/readiness?run_id={run_id}"
        ).json["run_id"], run_id)
        self.assertEqual(self.client.get("/v1/evaluation/runs/BENCH-invalid").status_code, 400)
        self.assertEqual(self.client.get(f"/v1/evaluation/runs/{run_id}/cases?limit=200"
                                         ).status_code, 400)
        self.assertEqual(self.client.get("/v1/evaluation/runs/BENCH-" + "0" * 32
                                         ).status_code, 404)


if __name__ == "__main__":
    unittest.main()
