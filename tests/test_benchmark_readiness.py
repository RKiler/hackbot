from __future__ import annotations

import unittest

from hackbot.benchmark_eval import evaluate_case
from hackbot.benchmark_models import GateOutcome, ReadinessConclusion
from hackbot.benchmark_readiness import ReadinessCategory, assess_readiness
from tests.test_benchmark_eval import benchmark_case, candidate, finding, trace


class BenchmarkReadinessTests(unittest.TestCase):
    def test_missing_evidence_is_not_ready(self):
        assessment = assess_readiness((), matrix_passed=None,
                                      backup_rehearsal_passed=None,
                                      checkpoint_recovery_passed=None)
        self.assertEqual(assessment.conclusion, ReadinessConclusion.NOT_READY)
        self.assertTrue(all(gate.outcome is GateOutcome.NOT_MEASURED
                            for gate in assessment.gates))

    def test_secure_false_confirmation_fails_even_without_positive_suite(self):
        secure = evaluate_case(benchmark_case(secure=True), trace(findings=(finding(),)))
        assessment = assess_readiness((secure,), matrix_passed=True,
                                      backup_rehearsal_passed=True,
                                      checkpoint_recovery_passed=True)
        precision = next(gate for gate in assessment.gates
                         if gate.category is ReadinessCategory.VALIDATION_PRECISION)
        self.assertEqual(precision.outcome, GateOutcome.FAIL)
        self.assertEqual(assessment.conclusion, ReadinessConclusion.NOT_READY)

    def test_positive_and_secure_cases_with_all_critical_gates(self):
        positive = evaluate_case(benchmark_case(), trace(candidates=(candidate(),),
                                                         findings=(finding(),)))
        secure = evaluate_case(benchmark_case(secure=True), trace())
        assessment = assess_readiness((positive, secure), matrix_passed=True,
                                      backup_rehearsal_passed=True,
                                      checkpoint_recovery_passed=True,
                                      active_safety_coverage=True)
        self.assertEqual(assessment.conclusion, ReadinessConclusion.READY_WITH_LIMITATIONS)
        self.assertEqual(assessment.to_dict()["synthetic_only"], True)

    def test_failed_matrix_blocks_even_when_detection_succeeds(self):
        positive = evaluate_case(benchmark_case(), trace(candidates=(candidate(),),
                                                         findings=(finding(),)))
        secure = evaluate_case(benchmark_case(secure=True), trace())
        assessment = assess_readiness((positive, secure), matrix_passed=False,
                                      backup_rehearsal_passed=True,
                                      checkpoint_recovery_passed=True,
                                      active_safety_coverage=True)
        self.assertEqual(assessment.conclusion, ReadinessConclusion.NOT_READY)

    def test_offline_cases_do_not_prove_active_safety(self):
        positive = evaluate_case(benchmark_case(), trace(candidates=(candidate(),),
                                                         findings=(finding(),)))
        secure = evaluate_case(benchmark_case(secure=True), trace())
        assessment = assess_readiness((positive, secure), matrix_passed=True,
                                      backup_rehearsal_passed=True,
                                      checkpoint_recovery_passed=True,
                                      full_suite=True)
        safety = next(gate for gate in assessment.gates
                      if gate.category is ReadinessCategory.SAFETY)
        self.assertEqual(safety.outcome, GateOutcome.NOT_MEASURED)
        self.assertEqual(assessment.conclusion, ReadinessConclusion.NOT_READY)


if __name__ == "__main__":
    unittest.main()
