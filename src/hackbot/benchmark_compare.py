"""Fail-closed benchmark regression checks on equivalent fixture versions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import math


class RegressionOutcome(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NOT_MEASURED = "NOT_MEASURED"


@dataclass(frozen=True, slots=True)
class RegressionThresholds:
    max_precision_drop: float | None = None
    max_recall_drop: float | None = None
    max_requests_per_detection_increase_ratio: float | None = None

    def __post_init__(self) -> None:
        for name in ("max_precision_drop", "max_recall_drop",
                     "max_requests_per_detection_increase_ratio"):
            value = getattr(self, name)
            if value is not None and (type(value) not in (float, int) or
                                      not math.isfinite(value) or value < 0):
                raise ValueError("Invalid benchmark regression threshold")


def compare_reports(before: dict[str, object], after: dict[str, object],
                    thresholds: RegressionThresholds = RegressionThresholds()) -> dict[str, object]:
    if (before["suite"] != after["suite"] or
            before["benchmark_version"] != after["benchmark_version"] or
            before["total_case_runs"] != after["total_case_runs"] or
            {(item["case_id"], item["trial"], item["visible_hash"])
             for item in before["cases"]} !=
            {(item["case_id"], item["trial"], item["visible_hash"])
             for item in after["cases"]}):
        return {"outcome": RegressionOutcome.NOT_MEASURED.value,
                "reason_code": "INCOMPARABLE_FIXTURE_SET",
                "baseline_id": before["run_id"], "current_id": after["run_id"]}
    if (before["status"] != "COMPLETED" or after["status"] != "COMPLETED" or
            before["evaluated_cases"] != before["total_case_runs"] or
            after["evaluated_cases"] != after["total_case_runs"]):
        return {"outcome": RegressionOutcome.NOT_MEASURED.value,
                "reason_code": "INCOMPLETE_RUN",
                "baseline_id": before["run_id"], "current_id": after["run_id"]}
    old, new = before["metrics"], after["metrics"]
    checks: dict[str, str] = {}
    checks["new_false_confirmed"] = (
        RegressionOutcome.FAIL.value if
        new["false_confirmed_findings"] > old["false_confirmed_findings"] or
        new["secure_cases_with_false_confirmations"] >
        old["secure_cases_with_false_confirmations"] else RegressionOutcome.PASS.value)
    checks["new_safety_violation"] = (
        RegressionOutcome.FAIL.value if
        new["safety_violations"] > old["safety_violations"] or
        new["orphaned_objects"] > old["orphaned_objects"] else
        RegressionOutcome.PASS.value)
    for name, maximum in (("precision", thresholds.max_precision_drop),
                          ("recall", thresholds.max_recall_drop)):
        prior, current = old[name], new[name]
        checks[name] = (RegressionOutcome.NOT_MEASURED.value
                        if maximum is None or prior is None or current is None
                        else RegressionOutcome.WARN.value if prior - current > maximum
                        else RegressionOutcome.PASS.value)
    prior = old["requests_per_detection"]
    current = new["requests_per_detection"]
    maximum = thresholds.max_requests_per_detection_increase_ratio
    checks["request_cost"] = (
        RegressionOutcome.NOT_MEASURED.value if maximum is None or
        prior is None or current is None or prior == 0 else
        RegressionOutcome.WARN.value if current / prior - 1 > maximum else
        RegressionOutcome.PASS.value)
    outcome = (RegressionOutcome.FAIL if RegressionOutcome.FAIL.value in checks.values() else
               RegressionOutcome.WARN if RegressionOutcome.WARN.value in checks.values() else
               RegressionOutcome.PASS)
    return {"outcome": outcome.value, "reason_code": "COMPARABLE",
            "baseline_id": before["run_id"], "current_id": after["run_id"],
            "checks": checks,
            "baseline": {key: old[key] for key in
                         ("precision", "recall", "false_confirmed_findings",
                          "safety_violations", "requests_per_detection", "top_k_recall")},
            "current": {key: new[key] for key in
                        ("precision", "recall", "false_confirmed_findings",
                         "safety_violations", "requests_per_detection", "top_k_recall")}}
