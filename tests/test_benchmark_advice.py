from __future__ import annotations

import unittest

from hackbot.benchmark_advice import (
    AdvicePacket, BenchmarkComparisonAdvisor, BenchmarkPlannerAdvisor,
    ModelAdviceResult, compare_advisors,
)
from hackbot.benchmark_models import CandidateProvenance, ModelRole


def packet():
    return AdvicePacket(ModelRole.PLANNER_ADVISOR, tuple({
        "candidate_id": f"PLCAND-{index:032x}", "score": 90 - index,
        "specialist": "AUTHORIZATION", "category": "CROSS_TENANT",
        "gaps": [], "evidence_strength": 75,
    } for index in range(4)))


class FakeProvider:
    def __init__(self, name, order, *, mutate=False):
        self.name = name
        self.order = order
        self.mutate = mutate
        self.seen = []
        self.roles = []

    def advise(self, value):
        self.seen.append(tuple(item["candidate_id"] for item in value.candidates))
        self.roles.append(value.role)
        if self.mutate:
            value.candidates[0]["candidate_id"] = "outside"
        return ModelAdviceResult(self.order, input_tokens=10, output_tokens=3,
                                 latency_ms=5)


class BenchmarkAdviceTests(unittest.TestCase):
    def test_independent_advisors_receive_same_packet(self):
        value = packet()
        baseline = tuple(item["candidate_id"] for item in value.candidates)
        first = FakeProvider("primary", baseline[::-1], mutate=True)
        second = FakeProvider("challenger", baseline)
        result = compare_advisors(value, primary=first, challenger=second)
        self.assertEqual(first.seen, second.seen)
        self.assertEqual(second.seen[0], baseline)
        self.assertEqual(value.candidates[0]["candidate_id"], baseline[0])
        self.assertEqual(result.disagreement_count, 4)
        self.assertEqual(result.provenance[baseline[1]], CandidateProvenance.BOTH)

    def test_malicious_or_malformed_advice_is_rejected(self):
        value = packet()
        bad = FakeProvider("bad", ("out-of-scope",))
        result = compare_advisors(value, primary=bad, challenger=None)
        self.assertEqual(result.primary.status, "REJECTED")
        self.assertEqual(result.challenger.status, "NOT_CONFIGURED")
        self.assertEqual(set(result.provenance.values()),
                         {CandidateProvenance.DETERMINISTIC})
        adapter = BenchmarkPlannerAdvisor(bad)
        self.assertEqual(adapter.choose(value.candidates).ordered_candidate_ids,
                         result.baseline_order)

    def test_comparison_advisor_uses_only_primary_for_planner_order(self):
        value = packet()
        baseline = tuple(item["candidate_id"] for item in value.candidates)
        primary = FakeProvider("primary", baseline[::-1], mutate=True)
        challenger = FakeProvider("challenger", baseline)
        critic = FakeProvider("critic", baseline)
        advisor = BenchmarkComparisonAdvisor(primary=primary,
                                             challenger=challenger, critic=critic)
        self.assertEqual(advisor.choose(value.candidates).ordered_candidate_ids,
                         baseline[::-1])
        self.assertEqual(primary.seen, challenger.seen)
        self.assertEqual(challenger.seen, critic.seen)
        self.assertEqual(critic.roles, [ModelRole.FALSE_POSITIVE_CRITIC])
        self.assertEqual(value.candidates[0]["candidate_id"], baseline[0])
        self.assertEqual(len(advisor.comparisons), 1)

        invalid = BenchmarkComparisonAdvisor(
            primary=FakeProvider("bad", ("foreign",)), challenger=challenger)
        self.assertEqual(invalid.choose(value.candidates).ordered_candidate_ids,
                         baseline)
        self.assertEqual(invalid.comparisons[0].primary.status, "REJECTED")

    def test_oversized_or_secret_bearing_packet_rejected(self):
        value = packet()
        broken = tuple({**item, "cookie": "fixture"} for item in value.candidates)
        with self.assertRaises(ValueError):
            AdvicePacket(ModelRole.PLANNER_ADVISOR, broken)
        unsafe = tuple({**item, "gaps": ["Cookie: secret=value"]}
                       for item in value.candidates)
        with self.assertRaisesRegex(ValueError, "non-code data"):
            AdvicePacket(ModelRole.PLANNER_ADVISOR, unsafe)


if __name__ == "__main__":
    unittest.main()
