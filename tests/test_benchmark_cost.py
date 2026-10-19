from __future__ import annotations

from dataclasses import replace
import unittest

from hackbot.benchmark_cost import estimate_cost
from hackbot.benchmark_eval import ModelCallUsage, evaluate_case
from hackbot.benchmark_models import (BenchmarkRunConfig, ModelLane, ModelRole,
                                      ModelSelection)
from tests.test_benchmark_eval import benchmark_case, candidate, finding, trace


class BenchmarkCostTests(unittest.TestCase):
    def test_independent_primary_and_challenger_pricing(self):
        primary = ModelSelection(ModelRole.PLANNER_ADVISOR, "fake", "a",
                                 lane=ModelLane.PRIMARY,
                                 input_usd_per_million=1,
                                 output_usd_per_million=2)
        challenger = ModelSelection(ModelRole.PLANNER_ADVISOR, "fake", "b",
                                    lane=ModelLane.CHALLENGER,
                                    input_usd_per_million=3,
                                    output_usd_per_million=4)
        config = BenchmarkRunConfig("smoke", models=(primary, challenger),
                                    vps_usd_per_hour=3.6)
        calls = (ModelCallUsage(ModelRole.PLANNER_ADVISOR, ModelLane.PRIMARY,
                                "fake", "a", 1000, 500, 10),
                 ModelCallUsage(ModelRole.PLANNER_ADVISOR, ModelLane.CHALLENGER,
                                "fake", "b", 1000, 500, 20))
        observed = replace(trace(candidates=(candidate(),), findings=(finding(),)),
                           model_calls=calls)
        evaluated = evaluate_case(benchmark_case(), observed)
        round_trip = type(evaluated).from_dict(evaluated.to_dict())
        self.assertEqual(round_trip.model_calls, calls)
        cost = estimate_cost((round_trip,), config)
        self.assertEqual(cost.model_usd, 0.007)
        self.assertEqual(cost.vps_usd, 0.01)
        self.assertEqual(cost.cost_per_detection_usd, 0.017)
        self.assertEqual(cost.unpriced_model_calls, 0)

    def test_unpriced_model_does_not_look_free(self):
        call = ModelCallUsage(ModelRole.PLANNER_ADVISOR, ModelLane.PRIMARY,
                              "other", "unknown", 100, 50, 1)
        evaluated = evaluate_case(benchmark_case(),
                                  replace(trace(), model_calls=(call,)))
        cost = estimate_cost((evaluated,), BenchmarkRunConfig("smoke"))
        self.assertIsNone(cost.total_usd)
        self.assertIsNone(cost.model_usd)
        self.assertEqual(cost.unpriced_model_calls, 1)

    def test_duplicate_role_and_lane_rejected(self):
        a = ModelSelection(ModelRole.PLANNER_ADVISOR, "fake", "a")
        b = ModelSelection(ModelRole.PLANNER_ADVISOR, "fake", "b")
        with self.assertRaises(ValueError):
            BenchmarkRunConfig("smoke", models=(a, b))

    def test_non_finite_model_and_vps_prices_are_rejected(self):
        with self.assertRaises(ValueError):
            ModelSelection(ModelRole.PLANNER_ADVISOR, "fake", "a",
                           input_usd_per_million=float("inf"))
        with self.assertRaises(ValueError):
            BenchmarkRunConfig("smoke", vps_usd_per_hour=float("nan"))


if __name__ == "__main__":
    unittest.main()
