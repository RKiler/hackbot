from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.benchmark_models import BenchmarkRunConfig, BenchmarkStatus
from hackbot.benchmark_store import BenchmarkStore


class BenchmarkStoreTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.store = BenchmarkStore(self.root / "evaluation/benchmark.sqlite3")
        self.store.initialize()

    def create(self, trials=1):
        return self.store.create(BenchmarkRunConfig("smoke", trials=trials),
                                 (("case_a", "a" * 64), ("case_b", "b" * 64)),
                                 benchmark_version="33.1", bughunter_version="0.1.0",
                                 bughunter_schema=48, environment={"platform": "fixture"})

    def test_isolated_checkpoint_and_no_duplicate_claim(self):
        run_id = self.create()
        first = self.store.claim(run_id)
        self.assertEqual((first["case_id"], first["trial"]), ("case_a", 1))
        second = self.store.claim(run_id)
        self.assertEqual(second["case_id"], "case_b")
        self.assertIsNone(self.store.claim(run_id))
        self.store.finish_case(run_id, "case_a", 1, status=BenchmarkStatus.COMPLETED,
                               campaign_id="CMP-1", trace={"requests": 2},
                               evaluation={"detected": 1})
        with self.assertRaises(ValueError):
            self.store.finish_case(run_id, "case_a", 1, status=BenchmarkStatus.COMPLETED,
                                   campaign_id=None, trace=None, evaluation=None)
        self.assertEqual(self.store.cases(run_id)[0]["evaluation"], {"detected": 1})
        self.assertEqual(self.store.get(run_id)["suite"], "smoke")

    def test_interrupted_case_is_ambiguous_and_not_replayed(self):
        run_id = self.create(trials=2)
        self.assertEqual(self.store.claim(run_id)["case_id"], "case_a")
        self.assertEqual(self.store.reconcile_interrupted(), 1)
        self.assertEqual(self.store.reconcile_interrupted(), 0)
        self.assertEqual(self.store.get(run_id)["status"], "AMBIGUOUS")
        next_case = self.store.claim(run_id)
        self.assertEqual((next_case["case_id"], next_case["trial"]), ("case_a", 2))
        self.assertEqual(self.store.cases(run_id)[0]["status"], "AMBIGUOUS")

    def test_permissions_and_schema_guard(self):
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.store.path.parent.stat().st_mode & 0o777, 0o700)
        self.store.initialize()
        with self.assertRaises(ValueError):
            BenchmarkStore(self.root / "other/benchmark.sqlite3",
                           required_mount=self.root).initialize()


if __name__ == "__main__":
    unittest.main()
