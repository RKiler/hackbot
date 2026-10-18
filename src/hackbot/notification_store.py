"""Target-bound notification outbox and provider delivery journal."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import re
import sqlite3
import uuid

from .store import EvidenceFactStore


_ID = re.compile(r"[A-Z][A-Z_]*-[0-9a-f]{32}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class NotificationType(StrEnum):
    CONFIRMED_FINDING = "CONFIRMED_FINDING"
    FINDING_READY_FOR_REPORT = "FINDING_READY_FOR_REPORT"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
    CLEANUP_FAILURE = "CLEANUP_FAILURE"
    AUTH_REQUIRES_LOGIN = "AUTH_REQUIRES_LOGIN"
    PLANNER_COMPLETED_WITH_FINDINGS = "PLANNER_COMPLETED_WITH_FINDINGS"
    FINDING_TRIAGE_CHANGED = "FINDING_TRIAGE_CHANGED"
    TEST = "TEST"


class NotificationPriority(StrEnum):
    URGENT = "URGENT"
    HIGH = "HIGH"
    NORMAL = "NORMAL"
    LOW = "LOW"


class DeliveryStatus(StrEnum):
    PENDING = "PENDING"
    SENDING = "SENDING"
    RETRY = "RETRY"
    SENT = "SENT"
    FAILED = "FAILED"
    NEEDS_REVIEW = "NEEDS_REVIEW"


@dataclass(frozen=True, slots=True)
class NotificationEvent:
    id: str
    target_id: str
    event_type: NotificationType
    source_kind: str
    source_id: str
    finding_id: str | None
    validation_id: str | None
    priority: NotificationPriority
    workflow_version: int
    dedupe_key: str
    created_at: str

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "target_id": self.target_id,
                "event_type": self.event_type.value, "source_kind": self.source_kind,
                "source_id": self.source_id, "finding_id": self.finding_id,
                "validation_id": self.validation_id, "priority": self.priority.value,
                "workflow_version": self.workflow_version, "created_at": self.created_at}


@dataclass(frozen=True, slots=True)
class NotificationDelivery:
    id: str
    event_id: str
    provider: str
    status: DeliveryStatus
    attempt_count: int
    created_at: str
    claimed_at: str | None
    sent_at: str | None
    next_attempt_at: str | None
    last_error_code: str | None

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "event_id": self.event_id,
                "provider": self.provider, "status": self.status.value,
                "attempt_count": self.attempt_count, "created_at": self.created_at,
                "sent_at": self.sent_at, "next_attempt_at": self.next_attempt_at,
                "last_error_code": self.last_error_code}


class NotificationStore:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    @staticmethod
    def _event(row: sqlite3.Row) -> NotificationEvent:
        return NotificationEvent(
            row["event_id"], row["target_id"], NotificationType(row["event_type"]),
            row["source_kind"], row["source_id"], row["finding_id"], row["validation_id"],
            NotificationPriority(row["priority"]), row["workflow_version"],
            row["dedupe_key"], row["created_at"])

    @staticmethod
    def _delivery(row: sqlite3.Row) -> NotificationDelivery:
        return NotificationDelivery(
            row["delivery_id"], row["event_id"], row["provider"],
            DeliveryStatus(row["status"]), row["attempt_count"], row["created_at"],
            row["claimed_at"], row["sent_at"], row["next_attempt_at"],
            row["last_error_code"])

    def enqueue(self, *, target_id: str, event_type: NotificationType,
                source_kind: str, source_id: str, priority: NotificationPriority,
                finding_id: str | None = None, validation_id: str | None = None,
                workflow_version: int = 0) -> NotificationEvent:
        if (not isinstance(event_type, NotificationType) or
                not isinstance(priority, NotificationPriority) or
                source_kind not in {"FINDING", "VALIDATION", "PLANNER", "OBJECT", "TEST"} or
                not isinstance(source_id, str) or not _ID.fullmatch(source_id) or
                type(workflow_version) is not int or not 0 <= workflow_version <= 1_000_000):
            raise ValueError("invalid notification source")
        expected_source = {
            NotificationType.CONFIRMED_FINDING: "FINDING",
            NotificationType.FINDING_READY_FOR_REPORT: "FINDING",
            NotificationType.FINDING_TRIAGE_CHANGED: "FINDING",
            NotificationType.MANUAL_REVIEW_REQUIRED: "VALIDATION",
            NotificationType.CLEANUP_FAILURE: "OBJECT",
            NotificationType.AUTH_REQUIRES_LOGIN: "PLANNER",
            NotificationType.PLANNER_COMPLETED_WITH_FINDINGS: "PLANNER",
            NotificationType.TEST: "TEST",
        }[event_type]
        if source_kind != expected_source:
            raise ValueError("notification event and source do not match")
        if event_type is NotificationType.CONFIRMED_FINDING and (
                source_kind != "FINDING" or finding_id != source_id):
            raise ValueError("confirmed notification requires a finding")
        if event_type is NotificationType.MANUAL_REVIEW_REQUIRED and (
                source_kind != "VALIDATION" or validation_id != source_id):
            raise ValueError("manual-review notification requires a validation")
        dedupe = hashlib.sha256(
            f"{event_type.value}:{source_id}:{workflow_version}".encode("ascii")
        ).hexdigest()
        now = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if finding_id:
                row = db.execute(
                    "SELECT validation_id FROM findings WHERE finding_id=? AND target_id=?",
                    (finding_id, target_id)).fetchone()
                if row is None or (validation_id and row[0] != validation_id):
                    raise ValueError("notification finding is not target-bound")
                validation_id = row[0]
            elif validation_id:
                row = db.execute(
                    "SELECT status FROM validations WHERE validation_id=? AND target_id=?",
                    (validation_id, target_id)).fetchone()
                if row is None or (event_type is NotificationType.MANUAL_REVIEW_REQUIRED and
                                   row[0] != "NEEDS_MANUAL_REVIEW"):
                    raise ValueError("notification validation is not eligible")
            elif source_kind != "TEST":
                table = {"PLANNER": ("planner_runs", "run_id"),
                         "OBJECT": ("test_objects", "object_id")}.get(source_kind)
                if table is None or db.execute(
                    f"SELECT 1 FROM {table[0]} WHERE {table[1]}=? AND target_id=?",
                    (source_id, target_id)).fetchone() is None:
                    raise ValueError("notification source is not target-bound")
            if event_type is NotificationType.CONFIRMED_FINDING and db.execute(
                    "SELECT 1 FROM validations WHERE validation_id=? AND target_id=? "
                    "AND status='CONFIRMED' AND source='DETERMINISTIC'",
                    (validation_id, target_id)).fetchone() is None:
                raise ValueError("notification is not backed by a confirmed validation")
            inserted = db.execute(
                "INSERT OR IGNORE INTO notification_events(event_id,target_id,event_type,"
                "source_kind,source_id,finding_id,validation_id,priority,workflow_version,"
                "dedupe_key,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("NOTIF-" + uuid.uuid4().hex, target_id, event_type.value, source_kind,
                 source_id, finding_id, validation_id, priority.value, workflow_version,
                 dedupe, now))
            if inserted.rowcount == 0:
                db.execute("UPDATE notification_events SET suppressed_count=suppressed_count+1 "
                           "WHERE dedupe_key=?", (dedupe,))
            row = db.execute("SELECT * FROM notification_events WHERE dedupe_key=?",
                             (dedupe,)).fetchone()
        return self._event(row)

    def event(self, event_id: str, target_id: str) -> NotificationEvent | None:
        if not isinstance(event_id, str) or not re.fullmatch(r"NOTIF-[0-9a-f]{32}", event_id):
            raise ValueError("invalid notification ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM notification_events WHERE event_id=? AND target_id=?",
                             (event_id, target_id)).fetchone()
        return self._event(row) if row else None

    def list_events(self, target_id: str, *, limit: int = 20,
                    cursor: str | None = None) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= 50 or (
                cursor is not None and not cursor.isdecimal()):
            raise ValueError("invalid notification page")
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT rowid AS cursor_id,* FROM notification_events WHERE target_id=? "
                "AND (? IS NULL OR rowid<?) ORDER BY rowid DESC LIMIT ?",
                (target_id, int(cursor) if cursor else None,
                 int(cursor) if cursor else None, limit + 1)).fetchall()
            items = []
            for row in rows[:limit]:
                deliveries = db.execute(
                    "SELECT * FROM notification_deliveries WHERE event_id=? ORDER BY provider",
                    (row["event_id"],)).fetchall()
                items.append({**self._event(row).to_dict(),
                              "deliveries": [self._delivery(item).to_dict()
                                             for item in deliveries]})
        return {"items": items, "next_cursor": str(rows[limit - 1]["cursor_id"])
                if len(rows) > limit else None}

    def for_finding(self, finding_id: str, target_id: str, *, limit: int = 20) -> list[dict[str, object]]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("invalid notification limit")
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT * FROM notification_events WHERE finding_id=? AND target_id=? "
                "ORDER BY rowid DESC LIMIT ?", (finding_id, target_id, limit)).fetchall()
            result = []
            for row in rows:
                deliveries = db.execute(
                    "SELECT * FROM notification_deliveries WHERE event_id=? ORDER BY provider",
                    (row["event_id"],)).fetchall()
                result.append({**self._event(row).to_dict(),
                               "deliveries": [self._delivery(item).to_dict()
                                              for item in deliveries]})
        return result

    def prepare_deliveries(self, event_id: str, providers: tuple[str, ...]) -> None:
        if len(providers) > 4 or any(not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name)
                                     for name in providers):
            raise ValueError("invalid notifier provider")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM notification_events WHERE event_id=?",
                          (event_id,)).fetchone() is None:
                raise LookupError("notification event not found")
            for name in providers:
                db.execute(
                    "INSERT OR IGNORE INTO notification_deliveries(delivery_id,event_id,provider,"
                    "status,created_at) VALUES (?,?,?,?,?)",
                    ("NDEL-" + uuid.uuid4().hex, event_id, name,
                     DeliveryStatus.PENDING.value, _now()))

    def unprepared_events(self, provider: str, event_types: tuple[NotificationType, ...],
                          *, limit: int = 50) -> tuple[NotificationEvent, ...]:
        if (not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", provider) or
                type(limit) is not int or not 1 <= limit <= 100 or
                not event_types or any(not isinstance(item, NotificationType) for item in event_types)):
            raise ValueError("invalid outbox page")
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT e.* FROM notification_events e LEFT JOIN notification_deliveries d "
                "ON d.event_id=e.event_id AND d.provider=? WHERE d.delivery_id IS NULL "
                "AND e.event_type IN (" + ",".join("?" for _ in event_types) + ") "
                "ORDER BY CASE e.priority WHEN 'URGENT' THEN 0 WHEN 'HIGH' THEN 1 "
                "WHEN 'NORMAL' THEN 2 ELSE 3 END,e.created_at,e.event_id LIMIT ?",
                (provider, *(item.value for item in event_types), limit)).fetchall()
        return tuple(self._event(row) for row in rows)

    def claim(self, provider: str, *, hourly_cap: int = 30,
              target_daily_cap: int = 10) -> tuple[NotificationDelivery, NotificationEvent] | None:
        now = datetime.now(timezone.utc)
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            hour_since = (now - timedelta(hours=1)).isoformat()
            day_since = (now - timedelta(days=1)).isoformat()
            attempted_hour = db.execute(
                "SELECT (SELECT count(*) FROM notification_attempts a "
                "JOIN notification_deliveries d ON d.delivery_id=a.delivery_id "
                "WHERE d.provider=? AND a.occurred_at>=?) + "
                "(SELECT count(*) FROM notification_deliveries "
                "WHERE provider=? AND status='SENDING' AND claimed_at>=?)",
                (provider, hour_since, provider, hour_since)
            ).fetchone()[0]
            if attempted_hour >= hourly_cap:
                return None
            row = db.execute(
                "SELECT d.*,e.target_id FROM notification_deliveries d "
                "JOIN notification_events e ON e.event_id=d.event_id WHERE d.provider=? "
                "AND d.status IN ('PENDING','RETRY') "
                "AND (d.next_attempt_at IS NULL OR d.next_attempt_at<=?) "
                "AND ((SELECT count(*) FROM notification_attempts a "
                "JOIN notification_deliveries d2 ON d2.delivery_id=a.delivery_id "
                "JOIN notification_events e2 ON e2.event_id=d2.event_id "
                "WHERE d2.provider=? AND e2.target_id=e.target_id AND a.occurred_at>=?) + "
                "(SELECT count(*) FROM notification_deliveries d3 "
                "JOIN notification_events e3 ON e3.event_id=d3.event_id "
                "WHERE d3.provider=? AND e3.target_id=e.target_id "
                "AND d3.status='SENDING' AND d3.claimed_at>=?))<? "
                "ORDER BY CASE e.priority WHEN 'URGENT' THEN 0 WHEN 'HIGH' THEN 1 "
                "WHEN 'NORMAL' THEN 2 ELSE 3 END,e.created_at,d.delivery_id LIMIT 1",
                (provider, now.isoformat(), provider, day_since,
                 provider, day_since, target_daily_cap)
            ).fetchone()
            if row is None:
                return None
            db.execute(
                "UPDATE notification_deliveries SET status='SENDING',attempt_count=attempt_count+1,"
                "claimed_at=?,next_attempt_at=NULL WHERE delivery_id=?",
                (now.isoformat(), row["delivery_id"]))
            delivery_row = db.execute("SELECT * FROM notification_deliveries WHERE delivery_id=?",
                                      (row["delivery_id"],)).fetchone()
            event_row = db.execute("SELECT * FROM notification_events WHERE event_id=?",
                                   (row["event_id"],)).fetchone()
        return self._delivery(delivery_row), self._event(event_row)

    def finish(self, delivery_id: str, status: DeliveryStatus, *,
               error_code: str | None = None, retry_seconds: int = 0) -> NotificationDelivery:
        if status not in {DeliveryStatus.SENT, DeliveryStatus.RETRY,
                          DeliveryStatus.FAILED, DeliveryStatus.NEEDS_REVIEW}:
            raise ValueError("invalid delivery result")
        if error_code is not None and not _CODE.fullmatch(error_code):
            raise ValueError("invalid safe delivery error code")
        if type(retry_seconds) is not int or not 0 <= retry_seconds <= 3600:
            raise ValueError("invalid retry interval")
        now = datetime.now(timezone.utc)
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM notification_deliveries WHERE delivery_id=?",
                             (delivery_id,)).fetchone()
            if row is None or row["status"] != "SENDING":
                raise ValueError("delivery is not claimed")
            if status is DeliveryStatus.RETRY and row["attempt_count"] >= 3:
                status, error_code = DeliveryStatus.FAILED, "RETRY_LIMIT_REACHED"
            next_at = ((now + timedelta(seconds=max(1, retry_seconds))).isoformat()
                       if status is DeliveryStatus.RETRY else None)
            db.execute(
                "UPDATE notification_deliveries SET status=?,sent_at=?,next_attempt_at=?,"
                "last_error_code=? WHERE delivery_id=?",
                (status.value, now.isoformat() if status is DeliveryStatus.SENT else None,
                 next_at, error_code, delivery_id))
            db.execute(
                "INSERT INTO notification_attempts(delivery_id,attempt_number,status,error_code,"
                "occurred_at) VALUES (?,?,?,?,?)",
                (delivery_id, row["attempt_count"], status.value, error_code,
                 now.isoformat()))
            updated = db.execute("SELECT * FROM notification_deliveries WHERE delivery_id=?",
                                 (delivery_id,)).fetchone()
        return self._delivery(updated)

    def reconcile_inflight(self, *, batch_size: int = 256) -> int:
        if type(batch_size) is not int or not 1 <= batch_size <= 1000:
            raise ValueError("invalid notification recovery batch")
        reconciled = 0
        last_delivery_id = ""
        while True:
            with self.store._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                rows = db.execute(
                    "SELECT delivery_id,attempt_count FROM notification_deliveries "
                    "WHERE status='SENDING' AND delivery_id>? "
                    "ORDER BY delivery_id LIMIT ?",
                    (last_delivery_id, batch_size),
                ).fetchall()
                for row in rows:
                    db.execute(
                        "UPDATE notification_deliveries SET status='NEEDS_REVIEW',"
                        "last_error_code='IN_FLIGHT_AFTER_RESTART' WHERE delivery_id=?",
                        (row["delivery_id"],),
                    )
                    db.execute(
                        "INSERT OR IGNORE INTO notification_attempts(delivery_id,attempt_number,"
                        "status,error_code,occurred_at) VALUES (?,?,?,?,?)",
                        (row["delivery_id"], row["attempt_count"], "NEEDS_REVIEW",
                         "IN_FLIGHT_AFTER_RESTART", _now()),
                    )
                reconciled += len(rows)
                if rows:
                    last_delivery_id = rows[-1]["delivery_id"]
            if len(rows) < batch_size:
                return reconciled

    def stats(self, target_id: str | None = None) -> dict[str, int]:
        with self.store._connection() as db:
            clause = " WHERE e.target_id=?" if target_id else ""
            args = (target_id,) if target_id else ()
            rows = db.execute(
                "SELECT d.status,count(*) AS n FROM notification_deliveries d "
                "JOIN notification_events e ON e.event_id=d.event_id" + clause +
                " GROUP BY d.status", args).fetchall()
            event_count = db.execute(
                "SELECT count(*) FROM notification_events" +
                (" WHERE target_id=?" if target_id else ""), args).fetchone()[0]
            duplicate_findings = db.execute(
                "SELECT count(*) FROM finding_duplicates d JOIN findings f "
                "ON f.finding_id=d.finding_id" +
                (" WHERE f.target_id=?" if target_id else ""), args).fetchone()[0]
            suppressed = db.execute(
                "SELECT coalesce(sum(suppressed_count),0) FROM notification_events" +
                (" WHERE target_id=?" if target_id else ""), args).fetchone()[0]
        counts = {row["status"]: row["n"] for row in rows}
        return {"events": event_count, "sent": counts.get("SENT", 0),
                "deduped": duplicate_findings + suppressed,
                "failed": counts.get("FAILED", 0), "pending": counts.get("PENDING", 0) +
                counts.get("RETRY", 0), "sending": counts.get("SENDING", 0),
                "needs_review": counts.get("NEEDS_REVIEW", 0)}
