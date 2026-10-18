"""Reviewed retirement of expired, unlinked ResearchBrief cache payloads."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
import uuid

from .store import EvidenceFactStore


_ID = re.compile(r"RBRF-[0-9a-f]{32}\Z")
_GUARDS = frozenset({
    "research_ref_candidate_insert_guard", "research_ref_candidate_update_guard",
    "research_ref_candidate_insert", "research_ref_candidate_update",
    "research_ref_candidate_delete", "research_ref_hypothesis_insert",
    "research_ref_event_insert_guard", "research_ref_event_insert",
    "planner_events_no_update", "planner_events_no_delete",
    "research_ref_hypothesis_update", "research_ref_proposal_insert",
    "research_ref_proposal_update", "research_ref_task_insert",
    "research_ref_task_update", "research_ref_request_insert",
    "research_ref_request_update", "research_retirement_guard",
    "research_retirement_no_update", "research_retirement_no_delete",
    "research_payload_no_rewrite",
})


def verify_research_retirement_schema(db: sqlite3.Connection) -> None:
    if db.execute("PRAGMA user_version").fetchone()[0] < 45:
        return
    names = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND name IN ("
        + ",".join("?" for _ in _GUARDS) + ")", tuple(_GUARDS))}
    if names != _GUARDS:
        raise ValueError("ResearchBrief retirement guards are incomplete")
    columns = {row[1] for row in db.execute("PRAGMA table_info(planner_candidate_research_refs)")}
    if columns != {"candidate_id", "brief_id"}:
        raise ValueError("ResearchBrief reference index is incomplete")
    columns = {row[1] for row in db.execute("PRAGMA table_info(planner_event_research_refs)")}
    if columns != {"event_id", "brief_id"}:
        raise ValueError("ResearchBrief event index is incomplete")


@dataclass(frozen=True, slots=True)
class ResearchBriefRetentionPolicy:
    grace_days: int = 30
    max_scan_entries: int = 250
    max_retire: int = 25
    reference_scan_seconds: int = 5

    def __post_init__(self) -> None:
        if (type(self.grace_days) is not int or not 1 <= self.grace_days <= 3650 or
                type(self.max_scan_entries) is not int or not 1 <= self.max_scan_entries <= 10_000 or
                type(self.max_retire) is not int or not 1 <= self.max_retire <= self.max_scan_entries or
                type(self.reference_scan_seconds) is not int or
                not 1 <= self.reference_scan_seconds <= 60):
            raise ValueError("Invalid ResearchBrief retention policy")


@dataclass(frozen=True, slots=True)
class ResearchBriefRetentionPlan:
    brief_ids: tuple[str, ...]
    scanned: int
    logical_bytes: int
    truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {"class": "EXPIRED_RESEARCH_BRIEF_CACHE", "dry_run": True,
                "brief_ids": self.brief_ids, "scanned": self.scanned,
                "candidate_count": len(self.brief_ids), "logical_bytes": self.logical_bytes,
                "truncated": self.truncated,
                "physical_reclaim": "SQLite free pages; file shrink requires separate offline maintenance"}


class ResearchBriefRetentionManager:
    """Preserve brief identity/provenance; retire only old unlinked cache content."""

    def __init__(self, store: EvidenceFactStore,
                 policy: ResearchBriefRetentionPolicy = ResearchBriefRetentionPolicy(),
                 audit_path: Path | None = None, review_path: Path | None = None) -> None:
        self.store = store
        self.policy = policy
        self.audit_path = audit_path
        self.review_path = review_path or store.db_path.parent / "research-retirement-review.json"

    @staticmethod
    def _timestamp(raw: str) -> datetime:
        value = datetime.fromisoformat(raw)
        if value.tzinfo is None:
            raise ValueError("Naive ResearchBrief timestamp")
        return value.astimezone(timezone.utc)

    def _json_reference(self, db: sqlite3.Connection, brief_id: str,
                        deadline: float, *, indexed_table: str,
                        source_table: str, json_column: str) -> bool:
        indexed = db.execute(
            f"SELECT 1 FROM {indexed_table} WHERE brief_id=? LIMIT 1",
            (brief_id,),
        ).fetchone()
        if indexed:
            return True
        if db.execute(f"SELECT 1 FROM {source_table} LIMIT 1").fetchone() is None:
            return False
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        try:
            return db.execute(
                f"SELECT 1 FROM {source_table} WHERE instr({json_column},?)>0 LIMIT 1",
                (brief_id,),
            ).fetchone() is not None
        except sqlite3.OperationalError as exc:
            if time.monotonic() >= deadline:
                raise ValueError("ResearchBrief reference scan incomplete") from None
            raise exc
        finally:
            db.set_progress_handler(None, 0)

    def _eligible(self, db: sqlite3.Connection, brief_id: str, now: datetime,
                  deadline: float) -> tuple[int, str] | None:
        row = db.execute(
            "SELECT b.payload_json,b.expires_at,b.retrieved_at FROM research_briefs b "
            "LEFT JOIN research_brief_payload_retirements r ON r.brief_id=b.brief_id "
            "WHERE b.brief_id=? AND r.brief_id IS NULL", (brief_id,),
        ).fetchone()
        if row is None or row["payload_json"] == "{}":
            return None
        grace = timedelta(days=self.policy.grace_days)
        if now < self._timestamp(row["expires_at"]) + grace or now < self._timestamp(row["retrieved_at"]) + grace:
            return None
        for query in (
            "SELECT 1 FROM research_hypothesis_links WHERE brief_id=? LIMIT 1",
            "SELECT 1 FROM research_skill_proposals WHERE brief_id=? LIMIT 1",
            "SELECT 1 FROM planner_tasks WHERE result_ref=? LIMIT 1",
            "SELECT 1 FROM research_requests WHERE brief_id=? "
            "AND status IN ('PENDING','RESEARCHING') LIMIT 1",
        ):
            if db.execute(query, (brief_id,)).fetchone():
                return None
        if self._json_reference(db, brief_id, deadline,
                                indexed_table="planner_candidate_research_refs",
                                source_table="planner_candidates",
                                json_column="source_refs_json"):
            return None
        if self._json_reference(db, brief_id, deadline,
                                indexed_table="planner_event_research_refs",
                                source_table="planner_events",
                                json_column="safe_refs_json"):
            return None
        payload = row["payload_json"].encode("utf-8")
        return len(payload), hashlib.sha256(payload).hexdigest()

    def _read_review(self) -> dict[str, object]:
        path = self.review_path
        if not path.exists() and not path.is_symlink():
            return {"next_after": None, "review": None}
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65_536:
            raise ValueError("Unsafe ResearchBrief retirement review")
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise ValueError("Invalid ResearchBrief retirement review") from None
        if not isinstance(state, dict):
            raise ValueError("Invalid ResearchBrief retirement review")
        cursor = state.get("next_after")
        review = state.get("review")
        if cursor is not None and (not isinstance(cursor, str) or not _ID.fullmatch(cursor)):
            raise ValueError("Invalid ResearchBrief retirement review")
        if review is not None and (
            not isinstance(review, dict) or type(review.get("at")) not in (int, float) or
            not isinstance(review.get("payloads"), list) or
            len(review["payloads"]) > self.policy.max_retire or
            any(not isinstance(item, dict) or
                not isinstance(item.get("id"), str) or not _ID.fullmatch(item["id"]) or
                type(item.get("bytes")) is not int or item["bytes"] <= 2 or
                not isinstance(item.get("sha256"), str) or
                not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                for item in review["payloads"]) or
            len({item["id"] for item in review["payloads"]}) != len(review["payloads"])
        ):
            raise ValueError("Invalid ResearchBrief retirement review")
        return {"next_after": cursor, "review": review}

    def _write_review(self, state: dict[str, object]) -> None:
        path = self.review_path
        parent = path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or path.is_symlink():
            raise ValueError("Unsafe ResearchBrief retirement review path")
        fd, temporary = tempfile.mkstemp(prefix=".research-review-", dir=parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def plan(self, *, now: float | None = None) -> ResearchBriefRetentionPlan:
        current = time.time() if now is None else now
        instant = datetime.fromtimestamp(current, timezone.utc)
        state = self._read_review()
        with self.store._connection() as db:
            verify_research_retirement_schema(db)
            rows = db.execute(
                "SELECT brief_id FROM research_briefs WHERE brief_id>? "
                "ORDER BY brief_id LIMIT ?",
                (state["next_after"] or "", self.policy.max_scan_entries + 1),
            ).fetchall()
            page = rows[:self.policy.max_scan_entries]
            candidates: list[tuple[str, int, str]] = []
            logical_bytes = 0
            scanned = 0
            deadline = time.monotonic() + self.policy.reference_scan_seconds
            for row in page:
                scanned += 1
                brief_id = row[0]
                eligible = self._eligible(db, brief_id, instant, deadline)
                if eligible is not None:
                    candidates.append((brief_id, *eligible))
                    logical_bytes += eligible[0] - 2
                    if len(candidates) >= self.policy.max_retire:
                        break
            truncated = len(rows) > scanned
            cursor = page[scanned - 1][0] if scanned and truncated else None
        self._write_review({"next_after": cursor,
                            "review": {"at": current, "payloads": [
                                {"id": brief_id, "bytes": size, "sha256": digest}
                                for brief_id, size, digest in candidates]}})
        return ResearchBriefRetentionPlan(tuple(item[0] for item in candidates),
                                          scanned, logical_bytes, truncated)

    def run(self, *, confirmed: bool, now: float | None = None) -> dict[str, object]:
        if confirmed is not True:
            raise ValueError("ResearchBrief retirement requires explicit confirmation")
        current = time.time() if now is None else now
        instant = datetime.fromtimestamp(current, timezone.utc)
        state = self._read_review()
        review = state["review"]
        if not isinstance(review, dict) or not 0 <= current - review["at"] <= 900:
            raise ValueError("ResearchBrief retirement requires a recent dry-run review")
        operation_id = "RR-" + uuid.uuid4().hex
        retired = logical_bytes = 0
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            verify_research_retirement_schema(db)
            deadline = time.monotonic() + self.policy.reference_scan_seconds
            ready: list[tuple[str, int, str]] = []
            for item in review["payloads"]:
                brief_id = item["id"]
                eligible = self._eligible(db, brief_id, instant, deadline)
                if eligible == (item["bytes"], item["sha256"]):
                    ready.append((brief_id, *eligible))
            self._audit(operation_id, "STARTED", len(ready))
            for brief_id, size, digest in ready:
                db.execute("UPDATE research_briefs SET payload_json='{}' WHERE brief_id=?",
                           (brief_id,))
                db.execute("INSERT INTO research_brief_payload_retirements "
                           "(brief_id,retired_at,payload_sha256,payload_bytes,reason) "
                           "VALUES (?,?,?,?,?)",
                           (brief_id, instant.isoformat(), digest, size,
                            "reviewed-expired-cache"))
                retired += 1
                logical_bytes += size - 2
        self._write_review({"next_after": state["next_after"], "review": None})
        self._audit(operation_id, "COMPLETED", retired)
        return {"retired": retired, "logical_bytes": logical_bytes,
                "physical_reclaim": "SQLite free pages; file shrink requires separate offline maintenance"}

    def _audit(self, operation_id: str, stage: str, count: int) -> None:
        if self.audit_path is None:
            return
        path = self.audit_path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.is_symlink() or path.is_symlink():
            raise ValueError("Unsafe ResearchBrief retirement audit path")
        event = {"at": datetime.now(timezone.utc).isoformat(),
                 "action": "RESEARCH_BRIEF_RETIREMENT", "operation_id": operation_id,
                 "stage": stage, "count": count}
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
