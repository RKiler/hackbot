"""Versioned, synthetic-only benchmark summaries and baseline artifacts."""

from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from .benchmark_cost import estimate_cost
from .benchmark_eval import (CaseEvaluation, aggregate_metrics, failure_stage_breakdown,
                             model_comparison_breakdown, model_usage_breakdown,
                             specialist_breakdown)
from .benchmark_models import BenchmarkRunConfig
from .benchmark_readiness import assess_readiness
from .benchmark_store import BenchmarkStore


def build_benchmark_report(store: BenchmarkStore, run_id: str, *,
                           matrix_passed: bool | None = None,
                           backup_rehearsal_passed: bool | None = None,
                           checkpoint_recovery_passed: bool | None = None) -> dict[str, object]:
    run = store.get(run_id)
    if run is None:
        raise LookupError("Benchmark run unavailable")
    rows = []
    for offset in range(0, 1280, 100):
        page = store.cases(run_id, limit=100, offset=offset)
        rows.extend(page)
        if len(page) < 100:
            break
    counts = Counter(row["status"] for row in rows)
    completed = tuple(CaseEvaluation.from_dict(row["evaluation"])
                      for row in rows if row["status"] == "COMPLETED" and
                      row["evaluation"] is not None)
    config = BenchmarkRunConfig.from_dict(run["config"])
    readiness = assess_readiness(
        completed, matrix_passed=matrix_passed,
        backup_rehearsal_passed=backup_rehearsal_passed,
        checkpoint_recovery_passed=checkpoint_recovery_passed,
        active_safety_coverage=False, fixture_coverage_complete=False,
        full_suite=False)
    limitations = (["OFFLINE_ANALYSIS_HAS_NO_VALIDATION_PROOF"]
                   if run["environment"].get("mode") == "SYNTHETIC_OFFLINE" else
                   ["LOCAL_TRAFFIC_BACKED_ROUTE_SEEDED"]
                   if run["environment"].get("mode") == "SYNTHETIC_LOCAL" else [])
    if any(item.campaign_outcome == "WAITING_HUMAN" for item in completed):
        limitations.append("MANUAL_WAIT_NOT_AUTOMATIC_REJECTION")
    if config.models and "NO_MODEL" not in config.ablations and not any(
            item.model_calls for item in completed):
        limitations.append("MODEL_ADVISOR_NOT_INVOKED")
    if config.models and all(item.provider == "fixture" for item in config.models):
        limitations.append("FAKE_PROVIDER_DIAGNOSTIC_NOT_MODEL_QUALITY")
    return {
        "label": "SYNTHETIC / EVALUATION",
        "run_id": run_id, "suite": run["suite"], "status": run["status"],
        "benchmark_version": run["benchmark_version"],
        "bughunter_version": run["bughunter_version"],
        "bughunter_schema": run["bughunter_schema"],
        "environment": run["environment"],
        "started_at": run["started_at"], "finished_at": run["finished_at"],
        "case_status_counts": dict(counts),
        "evaluated_cases": len(completed), "total_case_runs": len(rows),
        "metrics": aggregate_metrics(completed),
        "specialist_breakdown": specialist_breakdown(completed),
        "model_mode": "DETERMINISTIC_ONLY" if not config.models or
                      "NO_MODEL" in config.ablations else "CONFIGURED_MODEL_LANES",
        "ablations": list(config.ablations),
        "model_usage": model_usage_breakdown(completed),
        "model_comparison": model_comparison_breakdown(completed),
        "failure_analysis": failure_stage_breakdown(completed),
        "cost_estimate": estimate_cost(completed, config).to_dict(),
        "readiness": readiness.to_dict(),
        "cases": [{"case_id": row["case_id"], "trial": row["trial"],
                   "visible_hash": row["visible_hash"],
                   "status": row["status"], "error_code": row["error_code"],
                   "evaluation": row["evaluation"]} for row in rows],
        "limitations": limitations,
    }


def _atomic_private(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                            prefix=".benchmark-", delete=False) as handle:
        name = handle.name
        try:
            os.chmod(name, 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            Path(name).unlink(missing_ok=True)
            raise
    try:
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def write_benchmark_report(report: dict[str, object], output_root: Path) -> tuple[Path, Path]:
    run_id = report["run_id"]
    if not isinstance(run_id, str) or not run_id.startswith("BENCH-") or len(run_id) != 38:
        raise ValueError("Invalid benchmark report identifier")
    root = output_root.resolve(strict=False) / run_id
    json_path = root / "report.json"
    md_path = root / "report.md"
    metrics = report["metrics"]
    readiness = report["readiness"]
    lines = ["# Synthetic BugHunter Evaluation", "", f"Run: `{run_id}`",
             f"Suite: `{report['suite']}`", f"Status: `{report['status']}`",
             f"Ablations: `{report['ablations']}`",
             f"Build: `{report['bughunter_version']}` / benchmark `{report['benchmark_version']}`",
             "", "## Measured results", "",
             f"Evaluated cases: {report['evaluated_cases']} / {report['total_case_runs']}",
             f"Confirmed detections: {metrics['detected_vulnerabilities']}",
             f"False confirmed findings: {metrics['false_confirmed_findings']}",
             f"Precision: {metrics['precision']}", f"Recall: {metrics['recall']}",
             f"Top-K recall: {metrics['top_k_recall']}",
             f"Requests: {metrics['requests']}",
             f"Cost estimate: {report['cost_estimate']['total_usd']}"]
    if metrics["trial_stability"]:
        lines.extend(["", "## Repeated-trial stability", ""])
        for case_id, row in metrics["trial_stability"].items():
            lines.append(
                f"- `{case_id}`: {row['trials']} trials; confirmed rate "
                f"{row['confirmed_rate']}; top-3 rate {row['top_3_rate']}; "
                f"root rank spans {row['root_rank_spans']}; "
                f"top-three order consistent {row['top_three_category_order_consistent']}")
    lines.extend(["", "## Readiness", "", f"{readiness['conclusion']}", "",
                  "## Limitations", ""])
    lines.extend("- " + item for item in report["limitations"])
    if report["evaluated_cases"] != report["total_case_runs"]:
        lines.append("- Some cases were not evaluated; metrics exclude them.")
    _atomic_private(json_path, json.dumps(report, sort_keys=True, indent=2) + "\n")
    _atomic_private(md_path, "\n".join(lines) + "\n")
    return json_path, md_path
