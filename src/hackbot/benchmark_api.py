"""Read-only private evaluation API; benchmark execution remains CLI-owned."""

from __future__ import annotations

from pathlib import Path
import re
import sqlite3

from flask import Flask, jsonify, request

from .benchmark_catalog import BenchmarkCatalog
from .benchmark_compare import compare_reports
from .benchmark_report import build_benchmark_report
from .benchmark_store import BenchmarkStore
from .config import AppConfig


_RUN_ID = re.compile(r"BENCH-[0-9a-f]{32}\Z")
_LABEL = "SYNTHETIC / EVALUATION"


class BenchmarkUnavailable(RuntimeError):
    pass


def _number(name: str, *, default: int, minimum: int, maximum: int) -> int:
    raw = request.args.get(name, str(default))
    if not raw.isdecimal():
        raise ValueError("Invalid benchmark pagination")
    value = int(raw)
    if not minimum <= value <= maximum:
        raise ValueError("Invalid benchmark pagination")
    return value


def _run_id(value: str | None) -> str:
    if value is None or not _RUN_ID.fullmatch(value):
        raise ValueError("Invalid benchmark run ID")
    return value


def install_evaluation_routes(app: Flask, config: AppConfig) -> None:
    """No startup DB creation, target requests, or benchmark worker launch."""
    state_path = config.paths.state / "benchmark.sqlite3"
    visible_root = Path(__file__).resolve().parents[2] / "benchmarks" / "visible"

    def state() -> BenchmarkStore | None:
        if not state_path.exists():
            return None
        if state_path.is_symlink() or not state_path.is_file():
            raise BenchmarkUnavailable("Benchmark state unavailable")
        return BenchmarkStore(state_path)

    def report(run_id: str) -> dict[str, object]:
        store = state()
        if store is None:
            raise LookupError("Benchmark run unavailable")
        try:
            return build_benchmark_report(store, run_id)
        except LookupError:
            raise
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise BenchmarkUnavailable("Benchmark report unavailable") from exc

    @app.errorhandler(BenchmarkUnavailable)
    def benchmark_unavailable(_exc):
        return jsonify(error="benchmark_unavailable"), 503

    @app.get("/v1/evaluation/suites")
    def evaluation_suites():
        try:
            catalog = BenchmarkCatalog(visible_root)
            items = [{"name": name, "case_count": len(catalog.suite(name))}
                     for name in catalog.suites()]
        except (OSError, ValueError) as exc:
            raise BenchmarkUnavailable("Benchmark catalog unavailable") from exc
        return jsonify(label=_LABEL, items=items)

    @app.get("/v1/evaluation/runs")
    def evaluation_runs():
        limit = _number("limit", default=20, minimum=1, maximum=50)
        store = state()
        try:
            items = store.list(limit=limit) if store is not None else ()
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise BenchmarkUnavailable("Benchmark runs unavailable") from exc
        return jsonify(label=_LABEL, items=items)

    @app.get("/v1/evaluation/runs/<run_id>")
    def evaluation_run(run_id: str):
        value = report(_run_id(run_id))
        value.pop("cases", None)
        return jsonify(value)

    @app.get("/v1/evaluation/runs/<run_id>/cases")
    def evaluation_cases(run_id: str):
        run_id = _run_id(run_id)
        limit = _number("limit", default=20, minimum=1, maximum=50)
        offset = _number("offset", default=0, minimum=0, maximum=4096)
        store = state()
        if store is None:
            raise LookupError("Benchmark run unavailable")
        try:
            if store.get(run_id) is None:
                raise LookupError("Benchmark run unavailable")
            page = store.cases(run_id, limit=limit, offset=offset)
        except LookupError:
            raise
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise BenchmarkUnavailable("Benchmark cases unavailable") from exc
        items = [{"case_id": item["case_id"], "trial": item["trial"],
                  "status": item["status"], "error_code": item["error_code"],
                  "evaluation": item["evaluation"]} for item in page]
        return jsonify(label=_LABEL, run_id=run_id, items=items,
                       next_offset=offset + len(items) if len(items) == limit else None)

    @app.get("/v1/evaluation/compare")
    def evaluation_compare():
        before = report(_run_id(request.args.get("baseline_id")))
        after = report(_run_id(request.args.get("current_id")))
        result = compare_reports(before, after)
        result["label"] = _LABEL
        return jsonify(result)

    @app.get("/v1/evaluation/readiness")
    def evaluation_readiness():
        requested = request.args.get("run_id")
        if requested is not None:
            run_id = _run_id(requested)
        else:
            store = state()
            if store is None:
                return jsonify(label=_LABEL, run_id=None, readiness=None)
            try:
                latest = store.list(limit=1)
            except (OSError, ValueError, sqlite3.Error) as exc:
                raise BenchmarkUnavailable("Benchmark state unavailable") from exc
            if not latest:
                return jsonify(label=_LABEL, run_id=None, readiness=None)
            run_id = latest[0]["run_id"]
        value = report(run_id)
        return jsonify(label=_LABEL, run_id=run_id,
                       readiness=value["readiness"],
                       case_status_counts=value["case_status_counts"])
