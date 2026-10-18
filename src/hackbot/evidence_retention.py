"""Reviewed retirement of expired, unreferenced Evidence payloads."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
import uuid

from .artifact_refs import EVIDENCE_ARTIFACT_REFERENCES, verify_artifact_reference_schema
from .evidence_refs import (EvidenceReferenceError, evidence_reference_inventory,
                            has_evidence_reference)
from .store import EvidenceFactStore


_ID = re.compile(r"EV-[0-9a-f]{32}\Z")


@dataclass(frozen=True, slots=True)
class EvidencePayloadPolicy:
    grace_hours: int = 24
    max_scan_entries: int = 250
    max_retire: int = 25

    def __post_init__(self) -> None:
        if (type(self.grace_hours) is not int or not 1 <= self.grace_hours <= 8760 or
                type(self.max_scan_entries) is not int or
                not 1 <= self.max_scan_entries <= 10_000 or
                type(self.max_retire) is not int or not 1 <= self.max_retire <= 1000):
            raise ValueError("Invalid Evidence payload retention policy")


@dataclass(frozen=True, slots=True)
class EvidenceRetirementPlan:
    evidence_ids: tuple[str, ...]
    scanned: int
    candidate_bytes: int
    estimated_reclaimable_bytes: int
    blocked_unknown: int
    truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {"class": "EXPIRED_EVIDENCE_PAYLOAD", "dry_run": True,
                "evidence_ids": self.evidence_ids, "scanned": self.scanned,
                "candidate_count": len(self.evidence_ids),
                "candidate_bytes": self.candidate_bytes,
                "estimated_reclaimable_bytes": self.estimated_reclaimable_bytes,
                "blocked_unknown": self.blocked_unknown,
                "truncated": self.truncated}


class EvidencePayloadRetirementManager:
    """Mark only standalone expired payloads; physical deletion is a separate GC review."""

    def __init__(self, store: EvidenceFactStore,
                 policy: EvidencePayloadPolicy = EvidencePayloadPolicy(),
                 audit_path: Path | None = None, review_path: Path | None = None) -> None:
        self.store = store
        self.policy = policy
        self.audit_path = audit_path
        self.review_path = review_path or store.db_path.parent / "evidence-retirement-review.json"

    @staticmethod
    def _timestamp(raw: str) -> datetime:
        value = datetime.fromisoformat(raw)
        if value.tzinfo is None:
            raise ValueError("Naive Evidence timestamp")
        return value.astimezone(timezone.utc)

    def _eligible(self, db: sqlite3.Connection, evidence_id: str,
                  now: datetime) -> tuple[str, int, str] | None:
        row = db.execute("""
            SELECT e.artifact_hash,e.content_size,e.content_kind,e.created_at,e.sensitivity,
                   p.retain,p.expires_at,p.pinned,p.finding_related
            FROM evidence e
            JOIN evidence_policy_events p ON p.event_id=(
                SELECT max(event_id) FROM evidence_policy_events
                WHERE evidence_id=e.evidence_id)
            LEFT JOIN evidence_payload_retirements r ON r.evidence_id=e.evidence_id
            WHERE e.evidence_id=? AND r.evidence_id IS NULL
        """, (evidence_id,)).fetchone()
        if row is None or row["content_kind"] != "ARTIFACT" or row["artifact_hash"] is None:
            return None
        if row["sensitivity"] == "SECRET" or row["pinned"] or row["finding_related"]:
            return None
        age = (now - self._timestamp(row["created_at"])).total_seconds()
        if age < self.policy.grace_hours * 3600:
            return None
        expires = self._timestamp(row["expires_at"]) if row["expires_at"] else None
        if row["retain"] and (expires is None or expires > now):
            return None
        if db.execute(
            "SELECT 1 FROM finding_evidence WHERE evidence_id=? UNION ALL "
            "SELECT 1 FROM finding_validation_evidence_holds WHERE evidence_id=? LIMIT 1",
            (evidence_id, evidence_id),
        ).fetchone():
            return None
        classification = "EPHEMERAL" if not row["retain"] else "REGENERABLE"
        return row["artifact_hash"], row["content_size"], classification

    def _read_review(self) -> dict[str, object]:
        path = self.review_path
        if not path.exists() and not path.is_symlink():
            return {"next_after": None, "review": None}
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65_536:
            raise ValueError("Unsafe Evidence retirement review")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise ValueError("Invalid Evidence retirement review") from None
        if not isinstance(data, dict):
            raise ValueError("Invalid Evidence retirement review")
        cursor = data.get("next_after")
        review = data.get("review")
        if cursor is not None and (not isinstance(cursor, str) or not _ID.fullmatch(cursor)):
            raise ValueError("Invalid Evidence retirement review")
        if review is not None and (
            not isinstance(review, dict) or type(review.get("at")) not in (int, float) or
            not isinstance(review.get("ids"), list) or
            len(review["ids"]) > self.policy.max_retire or
            any(not isinstance(item, str) or not _ID.fullmatch(item) for item in review["ids"]) or
            len(set(review["ids"])) != len(review["ids"])
        ):
            raise ValueError("Invalid Evidence retirement review")
        return {"next_after": cursor, "review": review}

    def _write_review(self, data: dict[str, object]) -> None:
        path = self.review_path
        parent = path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or path.is_symlink():
            raise ValueError("Unsafe Evidence retirement review path")
        fd, temporary = tempfile.mkstemp(prefix=".evidence-review-", dir=parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, sort_keys=True)
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

    @staticmethod
    def _potential_reclaim(db: sqlite3.Connection, digest: str,
                           retiring_ids: set[str]) -> bool:
        for row in db.execute(
            "SELECT e.evidence_id,r.evidence_id IS NOT NULL AS retired "
            "FROM evidence e LEFT JOIN evidence_payload_retirements r "
            "ON r.evidence_id=e.evidence_id WHERE e.artifact_hash=?",
            (digest,),
        ):
            if row[1] and has_evidence_reference(db, row[0]):
                return False
            if not row[1] and row[0] not in retiring_ids:
                return False
        for table, column in EVIDENCE_ARTIFACT_REFERENCES:
            if table != "evidence" and db.execute(
                f"SELECT 1 FROM {table} WHERE {column}=? LIMIT 1", (digest,)
            ).fetchone():
                return False
        return True

    def plan(self, *, now: float | None = None) -> EvidenceRetirementPlan:
        current = time.time() if now is None else now
        instant = datetime.fromtimestamp(current, timezone.utc)
        with self.store.artifacts.hold():
            state = self._read_review()
            start = state["next_after"]
            with self.store._connection() as db:
                verify_artifact_reference_schema(db)
                evidence_reference_inventory(db)
                rows = db.execute(
                    "SELECT evidence_id FROM evidence WHERE evidence_id>? "
                    "ORDER BY evidence_id LIMIT ?",
                    (start or "", self.policy.max_scan_entries + 1),
                ).fetchall()
                page = rows[:self.policy.max_scan_entries]
                candidates: dict[str, tuple[str, int, str]] = {}
                blocked = 0
                for row in page:
                    evidence_id = row[0]
                    eligible = self._eligible(db, evidence_id, instant)
                    if eligible is None:
                        continue
                    try:
                        linked = has_evidence_reference(db, evidence_id)
                    except EvidenceReferenceError:
                        blocked += 1
                        continue
                    if not linked:
                        candidates[evidence_id] = eligible
                        if len(candidates) >= self.policy.max_retire:
                            break
                scanned = len(page) if len(candidates) < self.policy.max_retire else next(
                    index + 1 for index, row in enumerate(page) if row[0] == next(reversed(candidates)))
                last = page[scanned - 1][0] if scanned else None
                truncated = len(rows) > scanned
                retiring = set(candidates)
                bytes_total = sum(value[1] for value in candidates.values())
                reclaimable = 0
                seen: set[str] = set()
                for digest, _, _ in candidates.values():
                    if digest not in seen and self._potential_reclaim(db, digest, retiring):
                        path = self.store.artifacts.path_for(digest)
                        try:
                            details = path.lstat()
                        except FileNotFoundError:
                            details = None
                        if details is not None:
                            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                                raise ValueError("Unsafe Evidence artifact entry")
                            reclaimable += details.st_size
                    seen.add(digest)
            self._write_review({"next_after": last if truncated else None,
                                "review": {"at": current, "ids": list(candidates)}})
        return EvidenceRetirementPlan(tuple(candidates), scanned, bytes_total,
                                      reclaimable, blocked, truncated)

    def run(self, *, confirmed: bool, now: float | None = None) -> dict[str, object]:
        if confirmed is not True:
            raise ValueError("Evidence payload retirement requires explicit confirmation")
        current = time.time() if now is None else now
        instant = datetime.fromtimestamp(current, timezone.utc)
        with self.store.artifacts.hold():
            state = self._read_review()
            review = state["review"]
            if (not isinstance(review, dict) or
                    not 0 <= current - review["at"] <= 900):
                raise ValueError("Evidence payload retirement requires a recent dry-run review")
            reviewed_ids = tuple(review["ids"])
            operation_id = "ER-" + uuid.uuid4().hex
            with self.store._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                verify_artifact_reference_schema(db)
                evidence_reference_inventory(db)
                ready: list[tuple[str, str]] = []
                for evidence_id in reviewed_ids:
                    eligible = self._eligible(db, evidence_id, instant)
                    if eligible is not None and not has_evidence_reference(db, evidence_id):
                        ready.append((evidence_id, eligible[2]))
                self._audit(operation_id, "STARTED", len(ready))
                for evidence_id, classification in ready:
                    db.execute(
                        "INSERT INTO evidence_payload_retirements "
                        "(evidence_id,retired_at,retention_class,actor,reason) "
                        "VALUES (?,?,?,?,?)",
                        (evidence_id, instant.isoformat(), classification,
                         "operator", "reviewed-expired-payload"),
                    )
            self._write_review({"next_after": state["next_after"], "review": None})
            self._audit(operation_id, "COMPLETED", len(ready))
        return {"retired": len(ready), "reviewed": len(reviewed_ids),
                "physical_deletion": "requires separate artifact GC review"}

    def _audit(self, operation_id: str, stage: str, count: int) -> None:
        if self.audit_path is None:
            return
        path = self.audit_path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.is_symlink() or path.is_symlink():
            raise ValueError("Unsafe Evidence retention audit path")
        event = {"at": datetime.now(timezone.utc).isoformat(),
                 "action": "EVIDENCE_PAYLOAD_RETIREMENT", "operation_id": operation_id,
                 "stage": stage, "count": count}
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
