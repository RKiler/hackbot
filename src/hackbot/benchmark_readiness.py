"""Typed, conservative production-readiness assessment for synthetic benchmarks."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .benchmark_eval import CaseEvaluation, aggregate_metrics
from .benchmark_models import GateOutcome, ReadinessConclusion


class ReadinessCategory(StrEnum):
    SAFETY = "SAFETY"
    VALIDATION_PRECISION = "VALIDATION_PRECISION"
    AUDIT_CHAIN = "AUDIT_CHAIN"
    DISCOVERY_RECALL = "DISCOVERY_RECALL"
    PLANNER_QUALITY = "PLANNER_QUALITY"
    OPERATIONAL_STABILITY = "OPERATIONAL_STABILITY"
    RESOURCE_EFFICIENCY = "RESOURCE_EFFICIENCY"
    REPORT_QUALITY = "REPORT_QUALITY"
    PRODUCTION_TEST_MATRIX = "PRODUCTION_TEST_MATRIX"
    BACKUP_RECOVERY = "BACKUP_RECOVERY"


@dataclass(frozen=True, slots=True)
class ReadinessGate:
    category: ReadinessCategory
    outcome: GateOutcome
    reason_code: str
    measured_cases: int

    def to_dict(self) -> dict[str, object]:
        return {"category": self.category.value, "outcome": self.outcome.value,
                "reason_code": self.reason_code, "measured_cases": self.measured_cases}


@dataclass(frozen=True, slots=True)
class ProductionReadinessAssessment:
    conclusion: ReadinessConclusion
    gates: tuple[ReadinessGate, ...]
    benchmark_cases: int
    synthetic_only: bool = True

    def to_dict(self) -> dict[str, object]:
        return {"conclusion": self.conclusion.value,
                "gates": [item.to_dict() for item in self.gates],
                "benchmark_cases": self.benchmark_cases,
                "synthetic_only": self.synthetic_only}


def assess_readiness(cases: tuple[CaseEvaluation, ...], *,
                     matrix_passed: bool | None,
                     backup_rehearsal_passed: bool | None,
                     checkpoint_recovery_passed: bool | None,
                     active_safety_coverage: bool = False,
                     fixture_coverage_complete: bool = False,
                     full_suite: bool = False) -> ProductionReadinessAssessment:
    metrics = aggregate_metrics(cases)
    gates: list[ReadinessGate] = []

    def gate(category: ReadinessCategory, outcome: GateOutcome,
             reason: str, count: int = 0) -> None:
        gates.append(ReadinessGate(category, outcome, reason, count))

    def external(category: ReadinessCategory, value: bool | None, reason: str) -> None:
        gate(category, GateOutcome.NOT_MEASURED if value is None else
             GateOutcome.PASS if value else GateOutcome.FAIL,
             "NOT_MEASURED" if value is None else reason if value else reason + "_FAILED")

    safety = metrics["safety_violations"] + metrics["orphaned_objects"]
    gate(ReadinessCategory.SAFETY,
         GateOutcome.FAIL if safety else
         GateOutcome.NOT_MEASURED if not cases or not active_safety_coverage else
         GateOutcome.PASS,
         "SAFETY_VIOLATION_OR_ORPHAN" if safety else
         "NO_ACTIVE_SAFETY_COVERAGE" if not active_safety_coverage else
         "NO_OBSERVED_SAFETY_VIOLATIONS", len(cases))

    secure = [item for item in cases if item.expected_vulnerabilities == 0]
    false = metrics["false_confirmed_findings"] + metrics["duplicate_confirmed_findings"]
    gate(ReadinessCategory.VALIDATION_PRECISION,
         GateOutcome.FAIL if false else
         GateOutcome.NOT_MEASURED if not secure or not metrics["expected_vulnerabilities"] else
         GateOutcome.PASS,
         "FALSE_OR_DUPLICATE_CONFIRMED" if false else
         "MISSING_POSITIVE_OR_SECURE_CASE" if not secure or not metrics["expected_vulnerabilities"]
         else "NO_FALSE_CONFIRMATIONS",
         len(cases))

    confirmed_cases = [item for item in cases if item.detected_vulnerabilities or
                       item.false_confirmed_findings]
    bad_audit = any(not item.audit_quality_pass or not item.finding_quality_pass
                    for item in confirmed_cases)
    gate(ReadinessCategory.AUDIT_CHAIN,
         GateOutcome.NOT_MEASURED if not confirmed_cases else
         GateOutcome.FAIL if bad_audit else GateOutcome.PASS,
         "NO_CONFIRMED_FINDING" if not confirmed_cases else
         "BROKEN_FINDING_AUDIT" if bad_audit else "AUDIT_CHAIN_VERIFIED",
         len(confirmed_cases))

    expected = metrics["expected_vulnerabilities"]
    detected = metrics["detected_vulnerabilities"]
    gate(ReadinessCategory.DISCOVERY_RECALL,
         GateOutcome.NOT_MEASURED if not expected else
         GateOutcome.WARN if detected == 0 else GateOutcome.PASS,
         "NO_POSITIVE_CASE" if not expected else "ZERO_BLIND_DETECTIONS" if detected == 0
         else "BLIND_DETECTION_OBSERVED", sum(item.expected_vulnerabilities > 0 for item in cases))

    ranked = [item for item in cases if item.expected_vulnerabilities]
    top = sum(item.top_k["10"] for item in ranked)
    gate(ReadinessCategory.PLANNER_QUALITY,
         GateOutcome.NOT_MEASURED if not ranked else
         GateOutcome.WARN if top == 0 else GateOutcome.PASS,
         "NO_POSITIVE_CASE" if not ranked else "NO_TOP_10_ROOT" if top == 0
         else "ROOT_RANKED_IN_TOP_10", len(ranked))

    external(ReadinessCategory.PRODUCTION_TEST_MATRIX, matrix_passed, "MATRIX_PASS")
    external(ReadinessCategory.BACKUP_RECOVERY, backup_rehearsal_passed, "BACKUP_PASS")
    external(ReadinessCategory.OPERATIONAL_STABILITY, checkpoint_recovery_passed,
             "CHECKPOINT_RECOVERY_PASS")

    reports = [item for item in cases if item.report_quality_pass is not None]
    gate(ReadinessCategory.REPORT_QUALITY,
         GateOutcome.NOT_MEASURED if not reports else
         GateOutcome.FAIL if any(not item.report_quality_pass for item in reports) else
         GateOutcome.PASS,
         "NO_REPORTS" if not reports else "REPORT_QUALITY_FAILED" if
         any(not item.report_quality_pass for item in reports) else "REPORT_QUALITY_VERIFIED",
         len(reports))

    gate(ReadinessCategory.RESOURCE_EFFICIENCY,
         GateOutcome.NOT_MEASURED if not cases else
         GateOutcome.WARN if not detected else GateOutcome.PASS,
         "NO_CASES" if not cases else "NO_USEFUL_RESULT" if not detected
         else "COSTS_RECORDED", len(cases))

    critical = {ReadinessCategory.SAFETY, ReadinessCategory.VALIDATION_PRECISION,
                ReadinessCategory.AUDIT_CHAIN, ReadinessCategory.PRODUCTION_TEST_MATRIX,
                ReadinessCategory.BACKUP_RECOVERY, ReadinessCategory.OPERATIONAL_STABILITY}
    critical_ok = all(item.outcome is GateOutcome.PASS for item in gates
                      if item.category in critical)
    if not critical_ok or not detected:
        conclusion = ReadinessConclusion.NOT_READY
    elif full_suite and fixture_coverage_complete and all(
            item.outcome is GateOutcome.PASS for item in gates):
        conclusion = ReadinessConclusion.READY_FOR_SUPERVISED_PILOT
    else:
        conclusion = ReadinessConclusion.READY_WITH_LIMITATIONS
    return ProductionReadinessAssessment(conclusion, tuple(gates), len(cases))
