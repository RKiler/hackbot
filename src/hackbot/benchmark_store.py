"""Isolated benchmark ledger; never writes the production Finding database."""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import uuid

from .benchmark_models import BenchmarkRunConfig, BenchmarkStatus


_SCHEMA = """
CREATE TABLE benchmark_runs (
    run_id TEXT PRIMARY KEY,
    suite TEXT NOT NULL,
    config_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN
        ('PENDING','RUNNING','COMPLETED','INCOMPLETE','FAILED','AMBIGUOUS')),
    benchmark_version TEXT NOT NULL,
    bughunter_version TEXT NOT NULL,
    bughunter_schema INTEGER NOT NULL,
    environment_json TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE benchmark_case_runs (
    run_id TEXT NOT NULL REFERENCES benchmark_runs(run_id),
    case_id TEXT NOT NULL,
    trial INTEGER NOT NULL CHECK(trial BETWEEN 1 AND 5),
    visible_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN
        ('PENDING','RUNNING','COMPLETED','INCOMPLETE','FAILED','AMBIGUOUS')),
    campaign_id TEXT,
    trace_json TEXT,
    evaluation_json TEXT,
    error_code TEXT,
    started_at TEXT,
    finished_at TEXT,
    PRIMARY KEY(run_id,case_id,trial)
);
CREATE INDEX benchmark_cases_by_run ON benchmark_case_runs(run_id,status,case_id,trial);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class BenchmarkStore:
    """Only small, redacted metadata and evaluation results belong here."""

    def __init__(self, path: Path, *, required_mount: Path | None = None) -> None:
        self.path = path.expanduser().resolve(strict=False)
        self.required_mount = required_mount.resolve(strict=False) if required_mount else None

    def initialize(self) -> None:
        if self.required_mount is not None:
            if (not os.path.ismount(self.required_mount) or
                    not self.path.is_relative_to(self.required_mount)):
                raise ValueError("Benchmark storage mount unavailable")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink() or not self.path.parent.is_dir():
            raise ValueError("Unsafe benchmark state path")
        os.chmod(self.path.parent, 0o700)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("PRAGMA foreign_keys=ON")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError("Unsupported benchmark state schema")
            if version == 0:
                if db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]:
                    raise ValueError("Unversioned benchmark store is not empty")
                db.executescript(_SCHEMA)
                db.execute("PRAGMA user_version=1")
                db.commit()
            os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("Benchmark store unavailable")
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        if db.execute("PRAGMA user_version").fetchone()[0] != 1:
            db.close()
            raise ValueError("Benchmark store schema mismatch")
        return db

    def create(self, config: BenchmarkRunConfig, cases: tuple[tuple[str, str], ...],
               *, benchmark_version: str, bughunter_version: str,
               bughunter_schema: int, environment: dict[str, object]) -> str:
        if not cases or len(cases) > 256 or len({case for case, _ in cases}) != len(cases):
            raise ValueError("Invalid benchmark case selection")
        if any(len(digest) != 64 for _, digest in cases):
            raise ValueError("Invalid benchmark fixture digest")
        run_id = "BENCH-" + uuid.uuid4().hex
        with closing(self._connect()) as db:
            with db:
                db.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                           (run_id, config.suite, _json(asdict(config)),
                            BenchmarkStatus.PENDING.value, benchmark_version,
                            bughunter_version, bughunter_schema,
                            _json(environment), None, None, _now()))
                db.executemany("INSERT INTO benchmark_case_runs "
                               "(run_id,case_id,trial,visible_hash,status) VALUES (?,?,?,?,?)",
                               ((run_id, case_id, trial, digest, BenchmarkStatus.PENDING.value)
                                for case_id, digest in cases
                                for trial in range(1, config.trials + 1)))
        return run_id

    def claim(self, run_id: str) -> dict[str, object] | None:
        with closing(self._connect()) as db:
            with db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT * FROM benchmark_case_runs WHERE run_id=? "
                                 "AND status='PENDING' ORDER BY case_id,trial LIMIT 1",
                                 (run_id,)).fetchone()
                if row is None:
                    return None
                db.execute("UPDATE benchmark_case_runs SET status='RUNNING',started_at=? "
                           "WHERE run_id=? AND case_id=? AND trial=? AND status='PENDING'",
                           (_now(), run_id, row["case_id"], row["trial"]))
                db.execute("UPDATE benchmark_runs SET status='RUNNING'," 
                           "started_at=COALESCE(started_at,?) WHERE run_id=?",
                           (_now(), run_id))
                claimed = dict(row)
                claimed["status"] = BenchmarkStatus.RUNNING.value
                return claimed

    def finish_case(self, run_id: str, case_id: str, trial: int, *,
                    status: BenchmarkStatus, campaign_id: str | None,
                    trace: dict[str, object] | None, evaluation: dict[str, object] | None,
                    error_code: str | None = None) -> None:
        if status not in {BenchmarkStatus.COMPLETED, BenchmarkStatus.INCOMPLETE,
                          BenchmarkStatus.FAILED, BenchmarkStatus.AMBIGUOUS}:
            raise ValueError("Invalid benchmark completion status")
        with closing(self._connect()) as db:
            with db:
                changed = db.execute(
                    "UPDATE benchmark_case_runs SET status=?,campaign_id=?,trace_json=?,"
                    "evaluation_json=?,error_code=?,finished_at=? WHERE run_id=? AND case_id=? "
                    "AND trial=? AND status='RUNNING'",
                    (status.value, campaign_id, _json(trace) if trace is not None else None,
                     _json(evaluation) if evaluation is not None else None, error_code, _now(),
                     run_id, case_id, trial)).rowcount
                if changed != 1:
                    raise ValueError("Benchmark case is not claimed")

    def reconcile_interrupted(self, run_id: str | None = None) -> int:
        """Never replay a possibly state-changing fixture case after a crash."""
        with closing(self._connect()) as db:
            with db:
                count = db.execute("UPDATE benchmark_case_runs SET status='AMBIGUOUS',"
                                   "error_code='INTERRUPTED_REVIEW_REQUIRED',finished_at=? "
                                   "WHERE status='RUNNING' AND (? IS NULL OR run_id=?)",
                                   (_now(), run_id, run_id)).rowcount
                db.execute("UPDATE benchmark_runs SET status='AMBIGUOUS' "
                           "WHERE status='RUNNING' AND (? IS NULL OR run_id=?) AND "
                           "EXISTS (SELECT 1 FROM "
                           "benchmark_case_runs c WHERE c.run_id=benchmark_runs.run_id "
                           "AND c.status='AMBIGUOUS')", (run_id, run_id))
                return count

    def finalize(self, run_id: str) -> BenchmarkStatus:
        """Close only runs with no pending or running case; preserve partial results."""
        with closing(self._connect()) as db:
            with db:
                rows = db.execute("SELECT status,COUNT(*) AS n FROM benchmark_case_runs "
                                  "WHERE run_id=? GROUP BY status", (run_id,)).fetchall()
                if not rows:
                    raise LookupError("Benchmark run unavailable")
                counts = {row["status"]: row["n"] for row in rows}
                if counts.get("PENDING", 0) or counts.get("RUNNING", 0):
                    raise ValueError("Benchmark run has unfinished cases")
                status = (BenchmarkStatus.AMBIGUOUS if counts.get("AMBIGUOUS", 0) else
                          BenchmarkStatus.INCOMPLETE if counts.get("INCOMPLETE", 0) else
                          BenchmarkStatus.FAILED if counts.get("FAILED", 0) else
                          BenchmarkStatus.COMPLETED)
                db.execute("UPDATE benchmark_runs SET status=?,finished_at=? WHERE run_id=?",
                           (status.value, _now(), run_id))
                return status

    def get(self, run_id: str) -> dict[str, object] | None:
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM benchmark_runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["config"] = json.loads(result.pop("config_json"))
            result["environment"] = json.loads(result.pop("environment_json"))
            return result

    def cases(self, run_id: str, *, limit: int = 100,
              offset: int = 0) -> tuple[dict[str, object], ...]:
        if not 1 <= limit <= 256 or type(offset) is not int or not 0 <= offset <= 4096:
            raise ValueError("Invalid benchmark page limit")
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM benchmark_case_runs WHERE run_id=? "
                              "ORDER BY case_id,trial LIMIT ? OFFSET ?",
                              (run_id, limit, offset)).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                for field in ("trace_json", "evaluation_json"):
                    item[field[:-5]] = json.loads(item.pop(field)) if item[field] else None
                result.append(item)
            return tuple(result)

    def list(self, *, limit: int = 20) -> tuple[dict[str, object], ...]:
        if not 1 <= limit <= 100:
            raise ValueError("Invalid benchmark page limit")
        with closing(self._connect()) as db:
            rows = db.execute("SELECT run_id,suite,status,benchmark_version,created_at,"
                              "started_at,finished_at FROM benchmark_runs "
                              "ORDER BY created_at DESC,run_id DESC LIMIT ?", (limit,)).fetchall()
            return tuple(dict(row) for row in rows)
