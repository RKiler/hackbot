"""Bounded eligibility review for expired DOM-owned asset payloads."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
import uuid

from .dom_refs import DOMReferenceError, has_external_dom_reference
from .dom_guard_schema import verify_dom_retirement_guards
from .evidence_refs import EvidenceReferenceError, has_evidence_reference
from .store import EvidenceFactStore


_OWNERS = {
    "JS": ("dom_js_artifacts", "artifact_id", "artifact_sha256", "JS_ASSET", "DOMART-"),
    "SOURCE_MAP": ("dom_source_maps", "map_id", "map_sha256", "SOURCE_MAP", "DOMMAP-"),
}


@dataclass(frozen=True, slots=True)
class DOMPayloadPolicy:
    grace_hours: int = 24
    max_scan_entries: int = 100
    max_candidates: int = 25
    max_seconds: float = 10.0

    def __post_init__(self) -> None:
        if (type(self.grace_hours) is not int or not 1 <= self.grace_hours <= 8760 or
                type(self.max_scan_entries) is not int or
                not 1 <= self.max_scan_entries <= 1000 or
                type(self.max_candidates) is not int or
                not 1 <= self.max_candidates <= self.max_scan_entries or
                type(self.max_seconds) not in (int, float) or
                not 0 < self.max_seconds <= 30):
            raise ValueError("Invalid DOM payload review policy")


@dataclass(frozen=True, slots=True)
class DOMPayloadCandidate:
    owner_id: str
    evidence_id: str
    artifact_sha256: str
    logical_bytes: int


@dataclass(frozen=True, slots=True)
class DOMPayloadPlan:
    kind: str
    candidates: tuple[DOMPayloadCandidate, ...]
    scanned: int
    blocked_unknown: int
    next_after: str | None
    truncated: bool
    deadline_exceeded: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "class": "EXPIRED_DOM_PAYLOAD", "kind": self.kind, "dry_run": True,
            "owner_ids": [item.owner_id for item in self.candidates],
            "candidate_count": len(self.candidates),
            "candidate_bytes": sum(item.logical_bytes for item in self.candidates),
            "scanned": self.scanned, "blocked_unknown": self.blocked_unknown,
            "next_after": self.next_after, "truncated": self.truncated,
            "deadline_exceeded": self.deadline_exceeded,
            "physical_reclaim": "not estimated; requires a separate reviewed artifact-GC run",
        }


class DOMPayloadPlanner:
    """Advisory only: a future write action must recheck every hold in one transaction."""

    def __init__(self, store: EvidenceFactStore,
                 policy: DOMPayloadPolicy = DOMPayloadPolicy()) -> None:
        self.store = store
        self.policy = policy

    @staticmethod
    def _utc(raw: str) -> datetime:
        value = datetime.fromisoformat(raw)
        if value.tzinfo is None:
            raise ValueError("Naive DOM retention timestamp")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _target_busy(db: sqlite3.Connection, target_id: str) -> bool:
        for sql in (
            "SELECT 1 FROM plan_runs WHERE target_id=? AND status NOT IN "
            "('COMPLETED','REJECTED','FAILED','BUDGET_EXHAUSTED','CANCELLED') LIMIT 1",
            "SELECT 1 FROM planner_runs WHERE target_id=? AND status NOT IN "
            "('COMPLETED','BLOCKED','FAILED','CANCELLED','BUDGET_EXHAUSTED') LIMIT 1",
            "SELECT 1 FROM test_objects WHERE target_id=? AND lifecycle IN "
            "('CREATING','VERIFYING','IN_USE','CLEANUP_PENDING','CLEANING','ORPHANED','UNKNOWN') "
            "LIMIT 1",
        ):
            if db.execute(sql, (target_id,)).fetchone():
                return True
        return False

    def _eligible(self, db: sqlite3.Connection, kind: str, owner_id: str,
                  now: datetime, deadline: float) -> DOMPayloadCandidate | None:
        table, key, digest_column, evidence_type, _ = _OWNERS[kind]
        row = db.execute(f"""
            SELECT o.target_id,o.evidence_id,o.{digest_column} AS digest,o.retrieved_at,
                   e.artifact_hash,e.content_hash,e.content_size,e.content_kind,
                   e.evidence_type,e.target_ref,e.created_at,e.metadata_json,e.sensitivity,
                   p.retain,p.expires_at,p.pinned,p.finding_related
            FROM {table} o JOIN evidence e ON e.evidence_id=o.evidence_id
            JOIN evidence_policy_events p ON p.event_id=(
                SELECT max(event_id) FROM evidence_policy_events
                WHERE evidence_id=e.evidence_id)
            LEFT JOIN evidence_payload_retirements r ON r.evidence_id=e.evidence_id
            WHERE o.{key}=? AND r.evidence_id IS NULL
        """, (owner_id,)).fetchone()
        if row is None or row["content_kind"] != "ARTIFACT" or row["evidence_type"] != evidence_type:
            return None
        if (row["artifact_hash"] != row["digest"] or row["content_hash"] != row["digest"] or
                row["target_ref"] != row["target_id"] or row["sensitivity"] == "SECRET" or
                row["pinned"] or row["finding_related"] or not row["expires_at"]):
            return None
        metadata = json.loads(row["metadata_json"])
        if not isinstance(metadata, dict) or metadata.get("retention_class") != "REGENERABLE":
            return None
        grace = timedelta(hours=self.policy.grace_hours)
        if (now < self._utc(row["expires_at"]) or
                now < self._utc(row["created_at"]) + grace or
                now < self._utc(row["retrieved_at"]) + grace):
            return None
        if self._target_busy(db, row["target_id"]):
            return None
        if kind == "SOURCE_MAP" and db.execute(
            "SELECT 1 FROM dom_flow_candidates c JOIN dom_source_maps m "
            "ON m.js_artifact_id=c.artifact_id WHERE m.map_id=? "
            "AND c.status NOT IN ('REJECTED','STALE') LIMIT 1", (owner_id,),
        ).fetchone():
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DOMReferenceError("DOM payload review is incomplete")
        if has_evidence_reference(
            db, row["evidence_id"], max_seconds=min(2.0, remaining),
            allowed_dom_artifact_id=owner_id if kind == "JS" else None,
            allowed_dom_map_id=owner_id if kind == "SOURCE_MAP" else None,
        ):
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DOMReferenceError("DOM payload review is incomplete")
        if has_external_dom_reference(db, owner_id, max_seconds=min(2.0, remaining)):
            return None
        return DOMPayloadCandidate(owner_id, row["evidence_id"], row["digest"],
                                   row["content_size"])

    def plan(self, kind: str, *, after: str | None = None,
             now: float | None = None) -> DOMPayloadPlan:
        if kind not in _OWNERS:
            raise ValueError("Unknown DOM payload kind")
        table, key, _, _, prefix = _OWNERS[kind]
        if after is not None and (not isinstance(after, str) or
                                  not re.fullmatch(prefix + r"[0-9a-f]{32}", after)):
            raise ValueError("Invalid DOM payload cursor")
        instant = datetime.fromtimestamp(time.time() if now is None else now, timezone.utc)
        deadline = time.monotonic() + self.policy.max_seconds
        candidates: list[DOMPayloadCandidate] = []
        blocked = 0
        scanned = 0
        with self.store._connection() as db:
            verify_dom_retirement_guards(db)
            rows = db.execute(
                f"SELECT {key} FROM {table} WHERE {key}>? ORDER BY {key} LIMIT ?",
                (after or "", self.policy.max_scan_entries + 1),
            ).fetchall()
            page = rows[:self.policy.max_scan_entries]
            for row in page:
                if time.monotonic() >= deadline:
                    break
                scanned += 1
                try:
                    candidate = self._eligible(db, kind, row[0], instant, deadline)
                except (DOMReferenceError, EvidenceReferenceError, sqlite3.Error,
                        ValueError, TypeError):
                    blocked += 1
                    if time.monotonic() >= deadline:
                        break
                    continue
                if candidate is not None:
                    candidates.append(candidate)
                    if len(candidates) >= self.policy.max_candidates:
                        break
        truncated = len(rows) > scanned
        next_after = page[scanned - 1][0] if scanned and truncated else after if truncated else None
        return DOMPayloadPlan(kind, tuple(candidates), scanned, blocked, next_after,
                              truncated, time.monotonic() >= deadline)


class DOMPayloadRetirementManager:
    """Review and retire only eligible DOM Evidence; leave physical GC disabled."""

    def __init__(self, store: EvidenceFactStore,
                 policy: DOMPayloadPolicy = DOMPayloadPolicy(),
                 *, review_path: Path | None = None,
                 audit_path: Path | None = None) -> None:
        self.store = store
        self.planner = DOMPayloadPlanner(store, policy)
        self.policy = policy
        self.review_path = review_path or store.db_path.parent / "dom-retirement-review.json"
        self.audit_path = audit_path

    def _read_review(self) -> dict[str, object] | None:
        path = self.review_path
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return None
        try:
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                info = os.fstat(handle.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        info.st_size > 65_536 or stat.S_IMODE(info.st_mode) & 0o077):
                    raise ValueError("Unsafe DOM retirement review")
                raw = handle.read(65_537)
            if len(raw) > 65_536:
                raise ValueError("Unsafe DOM retirement review")
        finally:
            if fd >= 0:
                os.close(fd)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise ValueError("Invalid DOM retirement review") from None
        if not isinstance(data, dict) or set(data) != {"review"}:
            raise ValueError("Invalid DOM retirement review")
        review = data["review"]
        if review is None:
            return None
        if (not isinstance(review, dict) or set(review) != {"kind", "at", "items"} or
                not isinstance(review.get("kind"), str) or review["kind"] not in _OWNERS or
                type(review.get("at")) not in (int, float) or
                not math.isfinite(review["at"]) or
                not isinstance(review.get("items"), list) or
                len(review["items"]) > self.policy.max_candidates):
            raise ValueError("Invalid DOM retirement review")
        prefix = _OWNERS[review["kind"]][4]
        ids: set[str] = set()
        for item in review["items"]:
            if (not isinstance(item, dict) or set(item) != {
                "owner_id", "evidence_id", "artifact_sha256", "logical_bytes"
            } or not isinstance(item["owner_id"], str) or
                    not re.fullmatch(prefix + r"[0-9a-f]{32}", item["owner_id"]) or
                    not isinstance(item["evidence_id"], str) or
                    not re.fullmatch(r"EV-[0-9a-f]{32}", item["evidence_id"]) or
                    not isinstance(item["artifact_sha256"], str) or
                    not re.fullmatch(r"[0-9a-f]{64}", item["artifact_sha256"]) or
                    type(item["logical_bytes"]) is not int or item["logical_bytes"] < 0 or
                    item["owner_id"] in ids):
                raise ValueError("Invalid DOM retirement review")
            ids.add(item["owner_id"])
        return review

    def _write_review(self, review: dict[str, object] | None) -> None:
        path = self.review_path
        parent = path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or path.is_symlink():
            raise ValueError("Unsafe DOM retirement review path")
        fd, temporary = tempfile.mkstemp(prefix=".dom-retirement-", dir=parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"review": review}, handle, sort_keys=True)
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

    def _audit(self, operation_id: str, stage: str, count: int) -> None:
        if self.audit_path is None:
            return
        path = self.audit_path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.is_symlink() or path.is_symlink():
            raise ValueError("Unsafe DOM retirement audit path")
        event = {"at": datetime.now(timezone.utc).isoformat(),
                 "action": "DOM_EVIDENCE_RETIREMENT", "operation_id": operation_id,
                 "stage": stage, "count": count}
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def plan(self, kind: str, *, after: str | None = None,
             now: float | None = None) -> DOMPayloadPlan:
        with self.store.artifacts.hold():
            self._write_review(None)
            result = self.planner.plan(kind, after=after, now=now)
            if result.blocked_unknown or result.deadline_exceeded:
                return result
            current = time.time() if now is None else now
            self._write_review({"kind": kind, "at": current,
                                "items": [
                                    {"owner_id": item.owner_id,
                                     "evidence_id": item.evidence_id,
                                     "artifact_sha256": item.artifact_sha256,
                                     "logical_bytes": item.logical_bytes}
                                    for item in result.candidates
                                ]})
            return result

    def run(self, kind: str, *, confirmed: bool,
            now: float | None = None) -> dict[str, object]:
        if confirmed is not True or kind not in _OWNERS:
            raise ValueError("DOM retirement requires explicit confirmation and kind")
        current = time.time() if now is None else now
        instant = datetime.fromtimestamp(current, timezone.utc)
        with self.store.artifacts.hold():
            review = self._read_review()
            if (review is None or review["kind"] != kind or
                    not 0 <= current - review["at"] <= 900):
                raise ValueError("DOM retirement requires a recent matching review")
            operation_id = "DR-" + uuid.uuid4().hex
            retired = 0
            with self.store._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                verify_dom_retirement_guards(db)
                deadline = time.monotonic() + self.policy.max_seconds
                ready: list[DOMPayloadCandidate] = []
                for item in review["items"]:
                    if time.monotonic() >= deadline:
                        raise ValueError("DOM retirement reference recheck is incomplete")
                    candidate = self.planner._eligible(
                        db, kind, item["owner_id"], instant, deadline)
                    if candidate is not None and candidate == DOMPayloadCandidate(**item):
                        ready.append(candidate)
                self._audit(operation_id, "STARTED", len(ready))
                for candidate in ready:
                    db.execute(
                        "INSERT INTO evidence_payload_retirements "
                        "(evidence_id,retired_at,retention_class,actor,reason) "
                        "VALUES (?,?,?,?,?)",
                        (candidate.evidence_id, instant.isoformat(), "REGENERABLE",
                         "operator", "reviewed-dom-payload"),
                    )
                    retired += 1
            self._write_review(None)
            self._audit(operation_id, "COMPLETED", retired)
        return {"retired": retired, "reviewed": len(review["items"]),
                "physical_deletion": "not performed; requires a separate reviewed artifact-GC run"}
