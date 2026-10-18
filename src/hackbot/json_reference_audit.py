"""Bounded, independent audit of the trigger-maintained JSON reference indexes.

Run this on an isolated SQLite backup/restore copy. A full scan of the live
rollback-journal database would hold a read transaction against its writers.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
import re
import sqlite3
import time

from .evidence_json_index_schema import verify_evidence_json_index
from .json_reference_schema import json_reference_columns, quote_identifier
from .traffic_guard_schema import verify_traffic_json_index


_EVIDENCE_ID = re.compile(r"EV-[0-9a-f]{32}\Z")
_TRAFFIC_ID = re.compile(r"(?:EXCHANGE|REQUEST|RESPONSE)-[0-9a-f]{32}\Z")


class ReferenceIndexAuditError(RuntimeError):
    """The audit could not establish a complete, consistent snapshot."""


@dataclass(frozen=True)
class ReferenceIndexAudit:
    scanned_values: int
    json_columns: int
    evidence_ids: int
    traffic_ids: int
    evidence_mismatches: int
    traffic_mismatches: int

    @property
    def matches(self) -> bool:
        return self.evidence_mismatches == self.traffic_mismatches == 0


def _record_values(body: str, evidence: Counter[str], traffic: Counter[str],
                   max_distinct_ids: int) -> None:
    # Keep duplicate object values: SQLite json_tree counts them independently.
    parsed = json.loads(body, object_pairs_hook=lambda pairs: [v for _, v in pairs])
    pending = [parsed]
    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            if _EVIDENCE_ID.fullmatch(value):
                evidence[value] += 1
            elif _TRAFFIC_ID.fullmatch(value):
                traffic[value] += 1
            if len(evidence) + len(traffic) > max_distinct_ids:
                raise ReferenceIndexAuditError("JSON reference audit exceeded ID limit")


def _mismatches(db: sqlite3.Connection, table: str, expected: Counter[str],
                max_distinct_ids: int) -> int:
    observed = {}
    for ref_id, count in db.execute(
        f"SELECT ref_id,ref_count FROM {quote_identifier(table)} "
        "ORDER BY ref_id LIMIT ?", (max_distinct_ids + 1,),
    ):
        if len(observed) >= max_distinct_ids:
            raise ReferenceIndexAuditError("JSON reference audit exceeded index limit")
        observed[ref_id] = count
    return sum(observed.get(key) != expected.get(key) for key in observed.keys() | expected.keys())


def audit_json_reference_indexes(
    db: sqlite3.Connection, *, max_values: int = 250_000,
    max_distinct_ids: int = 100_000, max_json_bytes: int = 4_000_000,
    max_seconds: float = 60.0, page_size: int = 500,
) -> ReferenceIndexAudit:
    """Compare independently decoded source values against schema-43/44 indexes.

    Limits fail closed. This is an operator audit of an isolated copy, not an
    implicit retention-write check and not a sample-based success signal.
    """
    if db.in_transaction:
        raise ValueError("JSON reference audit requires its own read transaction")
    if (type(max_values) is not int or not 1 <= max_values <= 10_000_000 or
            type(max_distinct_ids) is not int or not 1 <= max_distinct_ids <= 1_000_000 or
            type(max_json_bytes) is not int or not 1 <= max_json_bytes <= 100_000_000 or
            type(page_size) is not int or not 1 <= page_size <= 10_000 or
            not isinstance(max_seconds, (int, float)) or
            not 0 < max_seconds <= 3600):
        raise ValueError("Invalid JSON reference audit limits")
    deadline = time.monotonic() + max_seconds
    evidence: Counter[str] = Counter()
    traffic: Counter[str] = Counter()
    scanned = 0
    try:
        db.execute("BEGIN")
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        verify_evidence_json_index(db)
        verify_traffic_json_index(db)
        columns = json_reference_columns(db)
        for table, column in columns:
            cursor: int | None = None
            while True:
                if time.monotonic() >= deadline:
                    raise ReferenceIndexAuditError("JSON reference audit exceeded deadline")
                clause = "" if cursor is None else "WHERE rowid>? "
                params = (page_size,) if cursor is None else (cursor, page_size)
                rows = db.execute(
                    f"SELECT rowid,{quote_identifier(column)} FROM "
                    f"{quote_identifier(table)} {clause}ORDER BY rowid LIMIT ?", params,
                ).fetchall()
                if not rows:
                    break
                for cursor, body in rows:
                    scanned += 1
                    if scanned > max_values:
                        raise ReferenceIndexAuditError("JSON reference audit exceeded row limit")
                    if body is None:
                        continue
                    if (not isinstance(body, str) or len(body) > max_json_bytes or
                            len(body.encode("utf-8")) > max_json_bytes):
                        raise ReferenceIndexAuditError("JSON reference audit encountered oversized data")
                    _record_values(body, evidence, traffic, max_distinct_ids)
                    if time.monotonic() >= deadline:
                        raise ReferenceIndexAuditError("JSON reference audit exceeded deadline")
                if len(rows) < page_size:
                    break
        return ReferenceIndexAudit(
            scanned, len(columns), len(evidence), len(traffic),
            _mismatches(db, "evidence_json_reference_counts", evidence, max_distinct_ids),
            _mismatches(db, "traffic_json_reference_counts", traffic, max_distinct_ids),
        )
    except (sqlite3.Error, ValueError, UnicodeError, RecursionError) as exc:
        raise ReferenceIndexAuditError("JSON reference audit is incomplete") from exc
    finally:
        db.set_progress_handler(None, 0)
        if db.in_transaction:
            db.rollback()
