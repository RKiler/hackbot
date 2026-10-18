"""Reviewed logical retirement of expired TrafficStore payloads."""

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

from .artifact_refs import verify_artifact_reference_schema
from .evidence_refs import (EvidenceReferenceError, evidence_reference_inventory,
                            has_evidence_reference)
from .store import EvidenceFactStore
from .traffic_guard_schema import verify_traffic_retirement_guards
from .traffic_refs import TrafficReferenceError, has_external_traffic_reference


_EXCHANGE_ID = re.compile(r"EXCHANGE-[0-9a-f]{32}\Z")


@dataclass(frozen=True, slots=True)
class TrafficPayloadPolicy:
    grace_hours: int = 24
    max_scan_entries: int = 250
    max_retire: int = 25
    reference_check_seconds: float = 1.0

    def __post_init__(self) -> None:
        if (type(self.grace_hours) is not int or not 1 <= self.grace_hours <= 8760 or
                type(self.max_scan_entries) is not int or
                not 1 <= self.max_scan_entries <= 10_000 or
                type(self.max_retire) is not int or not 1 <= self.max_retire <= 1000 or
                type(self.reference_check_seconds) not in (int, float) or
                not 0 < self.reference_check_seconds <= 30):
            raise ValueError("Invalid traffic payload retirement policy")


@dataclass(frozen=True, slots=True)
class TrafficRetirementPlan:
    exchange_ids: tuple[str, ...]
    evidence_count: int
    candidate_bytes: int
    max_reclaimable_bytes: int
    scanned: int
    blocked_unknown: int
    truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {"class": "EXPIRED_TRAFFIC_PAYLOAD", "dry_run": True,
                "exchange_ids": self.exchange_ids,
                "candidate_count": len(self.exchange_ids),
                "evidence_count": self.evidence_count,
                "candidate_bytes": self.candidate_bytes,
                "max_reclaimable_bytes": self.max_reclaimable_bytes,
                "scanned": self.scanned, "blocked_unknown": self.blocked_unknown,
                "truncated": self.truncated,
                "physical_deletion": "requires separate artifact GC review"}


class TrafficPayloadRetirementManager:
    """Retire payload access, not immutable TrafficStore metadata or physical blobs."""

    def __init__(self, store: EvidenceFactStore,
                 policy: TrafficPayloadPolicy = TrafficPayloadPolicy(),
                 audit_path: Path | None = None, review_path: Path | None = None) -> None:
        self.store = store
        self.policy = policy
        self.audit_path = audit_path
        self.review_path = review_path or store.db_path.parent / "traffic-retirement-review.json"

    @staticmethod
    def _timestamp(raw: str) -> datetime:
        value = datetime.fromisoformat(raw)
        if value.tzinfo is None:
            raise ValueError("Naive traffic timestamp")
        return value.astimezone(timezone.utc)

    def _eligible(self, db: sqlite3.Connection, exchange_id: str,
                  now: datetime) -> tuple[tuple[str, ...], dict[str, int], str, str | None] | None:
        if db.execute("SELECT 1 FROM traffic_payload_retirements WHERE exchange_id=?",
                      (exchange_id,)).fetchone():
            return None
        exchange = db.execute(
            "SELECT exchange_id,request_id,target_id,source,state,retain,expires_at,"
            "pinned,finding_related,created_at FROM traffic_exchanges WHERE exchange_id=?",
            (exchange_id,),
        ).fetchone()
        if exchange is None or exchange["state"] not in {
            "COMPLETE", "FAILED", "ABORTED", "TIMEOUT"
        } or exchange["pinned"] or exchange["finding_related"]:
            return None
        if (now - self._timestamp(exchange["created_at"])).total_seconds() < self.policy.grace_hours * 3600:
            return None
        expires = self._timestamp(exchange["expires_at"]) if exchange["expires_at"] else None
        if exchange["retain"] and (expires is None or expires > now):
            return None
        request = db.execute(
            "SELECT target_id,body_evidence_id,observation_evidence_id,artifact_hash "
            "FROM traffic_requests WHERE request_id=?", (exchange["request_id"],),
        ).fetchone()
        response = db.execute(
            "SELECT response_id,target_id,body_evidence_id,observation_evidence_id,artifact_hash "
            "FROM traffic_responses WHERE request_id=?", (exchange["request_id"],),
        ).fetchone()
        if (request is None or request["target_id"] != exchange["target_id"] or
                (exchange["state"] == "COMPLETE") != (response is not None) or
                (response is not None and response["target_id"] != exchange["target_id"])):
            return None
        evidence_ids = tuple(value for value in (
            request["observation_evidence_id"], request["body_evidence_id"],
            response["observation_evidence_id"] if response else None,
            response["body_evidence_id"] if response else None,
        ) if value is not None)
        if len(evidence_ids) != len(set(evidence_ids)):
            return None
        if has_external_traffic_reference(
            db, exchange_id=exchange_id, request_id=exchange["request_id"],
            response_id=response["response_id"] if response else None,
            max_seconds=self.policy.reference_check_seconds,
        ):
            return None
        digests: dict[str, int] = {}
        for evidence_id in evidence_ids:
            row = db.execute(
                "SELECT e.target_ref,e.source,e.sensitivity,e.content_kind,e.artifact_hash,"
                "e.content_size,p.retain,p.expires_at,p.pinned,p.finding_related "
                "FROM evidence e JOIN evidence_policy_events p ON p.event_id=("
                "SELECT max(event_id) FROM evidence_policy_events WHERE evidence_id=e.evidence_id) "
                "LEFT JOIN evidence_payload_retirements r ON r.evidence_id=e.evidence_id "
                "WHERE e.evidence_id=? AND r.evidence_id IS NULL",
                (evidence_id,),
            ).fetchone()
            if (row is None or row["target_ref"] != exchange["target_id"] or
                    row["source"] != "TRAFFIC_" + exchange["source"] or
                    row["sensitivity"] != "SECRET" or row["content_kind"] != "ARTIFACT" or
                    row["artifact_hash"] is None or row["pinned"] or row["finding_related"]):
                return None
            policy_expiry = self._timestamp(row["expires_at"]) if row["expires_at"] else None
            if row["retain"] and (policy_expiry is None or policy_expiry > now):
                return None
            if has_evidence_reference(
                db, evidence_id, allowed_traffic_request_id=exchange["request_id"],
                max_seconds=self.policy.reference_check_seconds,
            ):
                return None
            digests[row["artifact_hash"]] = row["content_size"]
        for owner in (request, response):
            if owner is not None and owner["body_evidence_id"] is not None:
                body = db.execute(
                    "SELECT artifact_hash FROM evidence WHERE evidence_id=?",
                    (owner["body_evidence_id"],),
                ).fetchone()
                if body is None or owner["artifact_hash"] != body[0]:
                    raise TrafficReferenceError("Traffic artifact link is inconsistent")
            elif owner is not None and owner["artifact_hash"] is not None:
                raise TrafficReferenceError("Traffic artifact link is inconsistent")
        return evidence_ids, digests, exchange["request_id"], (
            response["response_id"] if response else None)

    def _read_review(self) -> dict[str, object]:
        path = self.review_path
        if not path.exists() and not path.is_symlink():
            return {"next_after": None, "review": None}
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size > 65_536:
            raise ValueError("Unsafe traffic retirement review")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise ValueError("Invalid traffic retirement review") from None
        if not isinstance(data, dict):
            raise ValueError("Invalid traffic retirement review")
        cursor, review = data.get("next_after"), data.get("review")
        if cursor is not None and (not isinstance(cursor, str) or not _EXCHANGE_ID.fullmatch(cursor)):
            raise ValueError("Invalid traffic retirement review")
        if review is not None and (
            not isinstance(review, dict) or type(review.get("at")) not in (int, float) or
            not isinstance(review.get("ids"), list) or
            len(review["ids"]) > self.policy.max_retire or
            any(not isinstance(item, str) or not _EXCHANGE_ID.fullmatch(item) for item in review["ids"]) or
            len(set(review["ids"])) != len(review["ids"])
        ):
            raise ValueError("Invalid traffic retirement review")
        return {"next_after": cursor, "review": review}

    def _write_review(self, state: dict[str, object]) -> None:
        path = self.review_path
        parent = path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or path.is_symlink():
            raise ValueError("Unsafe traffic retirement review path")
        fd, temporary = tempfile.mkstemp(prefix=".traffic-review-", dir=parent)
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

    def plan(self, *, now: float | None = None) -> TrafficRetirementPlan:
        current = time.time() if now is None else now
        instant = datetime.fromtimestamp(current, timezone.utc)
        with self.store.artifacts.hold():
            state = self._read_review()
            start = state["next_after"]
            with self.store._connection() as db:
                verify_artifact_reference_schema(db)
                evidence_reference_inventory(db)
                verify_traffic_retirement_guards(db)
                rows = db.execute(
                    "SELECT exchange_id FROM traffic_exchanges WHERE exchange_id>? "
                    "ORDER BY exchange_id LIMIT ?",
                    (start or "", self.policy.max_scan_entries + 1),
                ).fetchall()
                page = rows[:self.policy.max_scan_entries]
                candidates: dict[str, tuple[tuple[str, ...], dict[str, int], str, str | None]] = {}
                blocked = 0
                scanned = 0
                for row in page:
                    scanned += 1
                    try:
                        eligible = self._eligible(db, row[0], instant)
                    except (EvidenceReferenceError, TrafficReferenceError):
                        blocked += 1
                        continue
                    if eligible is not None:
                        candidates[row[0]] = eligible
                        if len(candidates) >= self.policy.max_retire:
                            break
                last = page[scanned - 1][0] if scanned else None
                truncated = len(rows) > scanned
                evidence_count = sum(len(item[0]) for item in candidates.values())
                candidate_bytes = sum(sum(item[1].values()) for item in candidates.values())
                all_digests = {digest: size for _, digests, _, _ in candidates.values()
                               for digest, size in digests.items()}
                max_reclaimable = sum(all_digests.values())
            self._write_review({"next_after": last if truncated else None,
                                "review": {"at": current, "ids": list(candidates)}})
        return TrafficRetirementPlan(tuple(candidates), evidence_count, candidate_bytes,
                                     max_reclaimable, scanned, blocked, truncated)

    def run(self, *, confirmed: bool, now: float | None = None) -> dict[str, object]:
        if confirmed is not True:
            raise ValueError("Traffic retirement requires explicit confirmation")
        current = time.time() if now is None else now
        instant = datetime.fromtimestamp(current, timezone.utc)
        with self.store.artifacts.hold():
            state = self._read_review()
            review = state["review"]
            if not isinstance(review, dict) or not 0 <= current - review["at"] <= 900:
                raise ValueError("Traffic retirement requires a recent dry-run review")
            reviewed = tuple(review["ids"])
            operation_id = "TR-" + uuid.uuid4().hex
            with self.store._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                verify_artifact_reference_schema(db)
                evidence_reference_inventory(db)
                verify_traffic_retirement_guards(db)
                ready: list[tuple[str, tuple[str, ...], str, str | None]] = []
                for exchange_id in reviewed:
                    eligible = self._eligible(db, exchange_id, instant)
                    if eligible is not None:
                        ready.append((exchange_id, eligible[0], eligible[2], eligible[3]))
                self._audit(operation_id, "STARTED", len(ready))
                for exchange_id, evidence_ids, request_id, response_id in ready:
                    for evidence_id in evidence_ids:
                        db.execute(
                            "INSERT INTO evidence_payload_retirements "
                            "(evidence_id,retired_at,retention_class,actor,reason) "
                            "VALUES (?,?,?,?,?)",
                            (evidence_id, instant.isoformat(), "REGENERABLE",
                             "operator", "reviewed-expired-traffic-payload"),
                        )
                    db.execute(
                        "INSERT INTO traffic_payload_retirements "
                        "(exchange_id,request_id,response_id,retired_at,actor,reason) "
                        "VALUES (?,?,?,?,?,?)",
                        (exchange_id, request_id, response_id, instant.isoformat(),
                         "operator", "reviewed-expired-traffic-payload"),
                    )
            self._write_review({"next_after": state["next_after"], "review": None})
            self._audit(operation_id, "COMPLETED", len(ready))
        return {"retired_exchanges": len(ready),
                "retired_evidence": sum(len(ids) for _, ids, _, _ in ready),
                "reviewed": len(reviewed),
                "physical_deletion": "requires separate artifact GC review"}

    def _audit(self, operation_id: str, stage: str, count: int) -> None:
        if self.audit_path is None:
            return
        path = self.audit_path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.is_symlink() or path.is_symlink():
            raise ValueError("Unsafe traffic retention audit path")
        event = {"at": datetime.now(timezone.utc).isoformat(),
                 "action": "TRAFFIC_PAYLOAD_RETIREMENT", "operation_id": operation_id,
                 "stage": stage, "count": count}
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
