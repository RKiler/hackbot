"""BugHunter-owned, crash-safe delta settings and candidate ledger."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import re
import sqlite3
import uuid

from .delta_models import (ContinuousSettings, DeltaCadence, DeltaSignal,
                           DeltaSource, DeltaStatus, WatchStatus)
from .planner_models import Specialist
from .store import EvidenceFactStore
from .target_package import PackageStatus, TargetPackage


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"DELTA-[0-9a-f]{32}\Z")
_WATCH_ID = re.compile(r"DWATCH-[0-9a-f]{32}\Z")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def _settings(db: sqlite3.Connection, row: sqlite3.Row) -> ContinuousSettings:
    specialists = tuple(Specialist(item[0]) for item in db.execute(
        "SELECT specialist FROM continuous_target_specialists WHERE target_id=? "
        "ORDER BY specialist", (row["target_id"],)))
    cadence = next(item for item in DeltaCadence
                   if item.seconds == row["cadence_seconds"])
    return ContinuousSettings(
        bool(row["enabled"]), cadence, row["minimum_relevance"],
        row["cooldown_seconds"], row["daily_campaign_cap"], row["request_cap"],
        specialists)


class DeltaStore:
    """All writes are local SQLite writes; recon PostgreSQL is never mutated."""

    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    def ensure(self, package: TargetPackage) -> dict[str, object]:
        if not isinstance(package, TargetPackage):
            raise ValueError("Target Package required")
        settings = ContinuousSettings()
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM registry_targets WHERE target_id=?",
                          (package.target.id,)).fetchone() is None:
                raise ValueError("Target must be registered")
            inserted = db.execute(
                "INSERT OR IGNORE INTO continuous_targets(target_id,package_id,enabled,"
                "cadence_seconds,minimum_relevance,cooldown_seconds,daily_campaign_cap,"
                "request_cap,status,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (package.target.id, package.id, 0, settings.cadence.seconds,
                 settings.minimum_relevance, settings.cooldown_seconds,
                 settings.daily_campaign_cap, settings.request_cap,
                 WatchStatus.DISABLED.value, at))
            if inserted.rowcount:
                db.executemany(
                    "INSERT OR IGNORE INTO continuous_target_specialists VALUES (?,?)",
                    ((package.target.id, item.value) for item in settings.allowed_specialists))
        result = self.get(package.target.id)
        assert result is not None
        return result

    def configure(self, package: TargetPackage,
                  settings: ContinuousSettings) -> dict[str, object]:
        if not isinstance(settings, ContinuousSettings):
            raise ValueError("Invalid continuous settings")
        if settings.enabled and package.status is not PackageStatus.TRACKED:
            raise ValueError("Only tracked targets may enable continuous hunting")
        self.ensure(package)
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM continuous_targets WHERE target_id=? "
                             "AND package_id=?", (package.target.id, package.id)).fetchone()
            if row is None:
                raise ValueError("Target Package changed")
            if row["status"] == WatchStatus.RUNNING.value:
                raise ValueError("Cannot change settings during a watch")
            status = WatchStatus.PENDING if settings.enabled else WatchStatus.DISABLED
            db.execute(
                "UPDATE continuous_targets SET enabled=?,cadence_seconds=?,"
                "minimum_relevance=?,cooldown_seconds=?,daily_campaign_cap=?,"
                "request_cap=?,status=?,next_check_at=?,error_code=NULL,updated_at=? "
                "WHERE target_id=?", (int(settings.enabled), settings.cadence.seconds,
                settings.minimum_relevance, settings.cooldown_seconds,
                settings.daily_campaign_cap, settings.request_cap, status.value,
                at if settings.enabled else None, at, package.target.id))
            db.execute("DELETE FROM continuous_target_specialists WHERE target_id=?",
                       (package.target.id,))
            db.executemany("INSERT INTO continuous_target_specialists VALUES (?,?)",
                           ((package.target.id, item.value)
                            for item in settings.allowed_specialists))
            db.execute("INSERT INTO continuous_target_events(target_id,event_type,"
                       "reason_code,changed_at) VALUES (?,?,?,?)",
                       (package.target.id, "SETTINGS_CHANGED",
                        "ENABLED" if settings.enabled else "DISABLED", at))
        result = self.get(package.target.id)
        assert result is not None
        return result

    def get(self, target_id: str) -> dict[str, object] | None:
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM continuous_targets WHERE target_id=?",
                             (target_id,)).fetchone()
            if row is None:
                return None
            settings = _settings(db, row)
            result = dict(row)
        result["enabled"] = bool(result["enabled"])
        result["settings"] = settings.to_dict()
        result.pop("cadence_seconds")
        result.pop("minimum_relevance")
        result.pop("cooldown_seconds")
        result.pop("daily_campaign_cap")
        result.pop("request_cap")
        return result

    def settings(self, target_id: str) -> ContinuousSettings | None:
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM continuous_targets WHERE target_id=?",
                             (target_id,)).fetchone()
            return _settings(db, row) if row else None

    def due_targets(self, *, limit: int = 8) -> tuple[str, ...]:
        if type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError("Invalid due-target limit")
        with self.store._connection() as db:
            rows = db.execute("SELECT target_id FROM continuous_targets WHERE enabled=1 "
                              "AND next_check_at<=? AND status IN ('PENDING','IDLE','DEGRADED') "
                              "ORDER BY next_check_at,target_id LIMIT ?",
                              (_now(), limit)).fetchall()
        return tuple(row[0] for row in rows)

    def pause(self, package: TargetPackage) -> dict[str, object]:
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT enabled,status FROM continuous_targets WHERE target_id=? "
                             "AND package_id=?", (package.target.id, package.id)).fetchone()
            if row is None or not row["enabled"]:
                raise ValueError("Continuous target is not enabled")
            if row["status"] == WatchStatus.RUNNING.value:
                raise ValueError("Cannot pause an active watch")
            db.execute("UPDATE continuous_targets SET status='PAUSED',next_check_at=NULL,"
                       "updated_at=? WHERE target_id=?", (at, package.target.id))
            db.execute("INSERT INTO continuous_target_events(target_id,event_type,"
                       "reason_code,changed_at) VALUES (?,?,?,?)",
                       (package.target.id, "PAUSED", "OPERATOR", at))
        result = self.get(package.target.id)
        assert result is not None
        return result

    def resume(self, package: TargetPackage) -> dict[str, object]:
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("UPDATE continuous_targets SET status='PENDING',"
                       "next_check_at=?,updated_at=? WHERE target_id=? AND package_id=? "
                       "AND enabled=1 AND status='PAUSED'",
                       (at, at, package.target.id, package.id))
            if changed.rowcount != 1:
                raise ValueError("Continuous target is not paused")
            db.execute("INSERT INTO continuous_target_events(target_id,event_type,"
                       "reason_code,changed_at) VALUES (?,?,?,?)",
                       (package.target.id, "RESUMED", "OPERATOR", at))
        result = self.get(package.target.id)
        assert result is not None
        return result

    def defer_target(self, target_id: str, reason_code: str) -> None:
        if not _CODE.fullmatch(reason_code):
            raise ValueError("Invalid continuous target reason")
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT cadence_seconds,enabled,status FROM continuous_targets "
                             "WHERE target_id=?", (target_id,)).fetchone()
            if row is None:
                raise LookupError("Continuous target not found")
            if row["status"] == WatchStatus.RUNNING.value:
                raise ValueError("Cannot defer an active watch")
            next_check = ((datetime.fromisoformat(at) + timedelta(
                seconds=row["cadence_seconds"])).isoformat() if row["enabled"] else None)
            db.execute("UPDATE continuous_targets SET status='DEGRADED',error_code=?,"
                       "next_check_at=?,updated_at=? WHERE target_id=?",
                       (reason_code, next_check, at, target_id))

    def begin_watch(self, package: TargetPackage,
                    *, trigger: str = "MANUAL") -> str:
        if trigger not in {"SCHEDULED", "MANUAL", "FIXTURE"}:
            raise ValueError("Invalid watch trigger")
        self.ensure(package)
        watch_id, at = "DWATCH-" + uuid.uuid4().hex, _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT enabled,status,package_id FROM continuous_targets "
                             "WHERE target_id=?", (package.target.id,)).fetchone()
            if row is None or row["package_id"] != package.id:
                raise ValueError("Target Package changed")
            if trigger == "SCHEDULED" and not row["enabled"]:
                raise ValueError("Continuous hunting is disabled")
            if row["status"] == WatchStatus.PAUSED.value:
                raise ValueError("Continuous hunting is paused")
            if row["status"] == WatchStatus.RUNNING.value:
                raise ValueError("Watch already running")
            db.execute("INSERT INTO delta_watch_runs(watch_id,target_id,trigger_kind,"
                       "status,source_kind,started_at) VALUES (?,?,?,?,?,?)",
                       (watch_id, package.target.id, trigger,
                        WatchStatus.RUNNING.value, "NONE", at))
            db.execute("UPDATE continuous_targets SET status=?,updated_at=? WHERE target_id=?",
                       (WatchStatus.RUNNING.value, at, package.target.id))
        return watch_id

    @staticmethod
    def _validate_signal(signal: DeltaSignal) -> None:
        if (not _REF.fullmatch(signal.source_ref) or
                not _REF.fullmatch(signal.entity_type) or
                (signal.entity_id is not None and not _REF.fullmatch(signal.entity_id)) or
                not _DIGEST.fullmatch(signal.location_hash) or
                not _DIGEST.fullmatch(signal.new_fingerprint) or
                (signal.old_fingerprint is not None and
                 not _DIGEST.fullmatch(signal.old_fingerprint)) or
                (signal.semantic_hash is not None and
                 not _DIGEST.fullmatch(signal.semantic_hash)) or
                not 1 <= len(signal.display_location) <= 512 or
                any(char in signal.display_location for char in "?#\r\n") or
                len(signal.specialist_hints) > 5 or len(signal.signal_tags) > 16 or
                any(not _CODE.fullmatch(tag) for tag in signal.signal_tags)):
            raise ValueError("Invalid or unsafe delta signal")

    def finish_watch(self, package: TargetPackage, watch_id: str, *,
                     source: DeltaSource | None, signals: tuple[DeltaSignal, ...] = (),
                     observations: tuple[tuple[str, str, str, str | None,
                                               str | None, str], ...] = (),
                     snapshot_id: int | None = None,
                     event_highwater: tuple[str, int] | None = None,
                     backfill: tuple[str, str, str, str, int] | None = None,
                     bootstrap_highwater: tuple[str, str] | None = None,
                     js_highwater: str | None = None,
                     backlog_min_count: int = 0,
                     backlog_oldest_at: str | None = None,
                     events_scanned: int | None = None,
                     baseline: bool = False,
                     degraded_reason: str | None = None) -> dict[str, object]:
        scanned = len(observations) if events_scanned is None else events_scanned
        if (not _WATCH_ID.fullmatch(watch_id) or len(signals) > 200 or
                len(observations) > 200 or type(backlog_min_count) is not int or
                not 0 <= backlog_min_count <= 1000000 or
                type(scanned) is not int or not 0 <= scanned <= 200 or
                (backlog_oldest_at is not None and
                 (not isinstance(backlog_oldest_at, str) or
                  len(backlog_oldest_at) > 64)) or
                (snapshot_id is not None and
                 (type(snapshot_id) is not int or snapshot_id <= 0)) or
                (degraded_reason is not None and not _CODE.fullmatch(degraded_reason)) or
                (backfill is not None and (len(backfill) != 5 or
                 any(not isinstance(item, str) or not 1 <= len(item) <= 1024
                     for item in backfill[:4]) or
                 type(backfill[4]) is not int or backfill[4] <= 0)) or
                (bootstrap_highwater is not None and
                 (len(bootstrap_highwater) != 2 or
                  not isinstance(bootstrap_highwater[0], str) or
                  not isinstance(bootstrap_highwater[1], str) or
                  not _REF.fullmatch(bootstrap_highwater[1])))):
            raise ValueError("Invalid bounded watch result")
        if backlog_oldest_at is not None:
            try:
                datetime.fromisoformat(backlog_oldest_at)
            except ValueError as exc:
                raise ValueError("Invalid backlog timestamp") from exc
        for signal in signals:
            self._validate_signal(signal)
        at = _now()
        created = ignored = 0
        status = WatchStatus.DEGRADED if degraded_reason else WatchStatus.IDLE
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute("SELECT target_id,status FROM delta_watch_runs WHERE watch_id=?",
                             (watch_id,)).fetchone()
            target = db.execute("SELECT * FROM continuous_targets WHERE target_id=?",
                                (package.target.id,)).fetchone()
            if (run is None or run["target_id"] != package.target.id or
                    run["status"] != WatchStatus.RUNNING.value or target is None or
                    target["package_id"] != package.id):
                raise ValueError("Watch is not active for this Target Package")
            for source_kind, entity_key, fingerprint, semantic_hash, artifact_id, seen_at in observations:
                if (source_kind not in {item.value for item in DeltaSource} or
                        not _REF.fullmatch(entity_key) or not _DIGEST.fullmatch(fingerprint) or
                        (semantic_hash is not None and not _DIGEST.fullmatch(semantic_hash))):
                    raise ValueError("Invalid delta observation")
                db.execute(
                    "INSERT INTO delta_observations(target_id,source_kind,entity_key,"
                    "fingerprint,semantic_hash,artifact_id,observed_at,updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(target_id,source_kind,entity_key) "
                    "DO UPDATE SET fingerprint=excluded.fingerprint,"
                    "semantic_hash=excluded.semantic_hash,artifact_id=excluded.artifact_id,"
                    "observed_at=excluded.observed_at,updated_at=excluded.updated_at",
                    (package.target.id, source_kind, entity_key, fingerprint,
                     semantic_hash, artifact_id, seen_at, at))
            for signal in signals:
                entity_key = f"{signal.entity_type}:{signal.entity_id or signal.location_hash}"
                root_key = _hash(package.target.id, signal.source.value, entity_key,
                                 signal.delta_type.value, signal.location_hash)
                dedupe_key = _hash(root_key, signal.new_fingerprint,
                                   signal.semantic_hash or "")
                delta_id = "DELTA-" + dedupe_key[:32]
                initial_status = (DeltaStatus.IGNORED if signal.relevance == 0 else
                                  DeltaStatus.DEFERRED if signal.reason_code ==
                                  "SEMANTIC_UNKNOWN" else DeltaStatus.CLASSIFIED)
                cursor = db.execute(
                    "INSERT OR IGNORE INTO delta_candidates(delta_id,target_id,delta_type,"
                    "source_kind,source_ref,entity_type,entity_id,location_hash,"
                    "display_location,old_fingerprint,new_fingerprint,observed_at,relevance,"
                    "semantic_hash,status,dedupe_key,reason_code,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (delta_id, package.target.id, signal.delta_type.value,
                     signal.source.value, signal.source_ref, signal.entity_type,
                     signal.entity_id, signal.location_hash, signal.display_location,
                     signal.old_fingerprint, signal.new_fingerprint,
                     signal.observed_at, signal.relevance,
                     signal.semantic_hash,
                     initial_status.value,
                     dedupe_key, signal.reason_code, at, at))
                if not cursor.rowcount:
                    continue
                created += 1
                if initial_status is DeltaStatus.IGNORED:
                    ignored += 1
                db.executemany("INSERT INTO delta_candidate_hints VALUES (?,?)",
                               ((delta_id, item.value) for item in signal.specialist_hints))
                db.executemany("INSERT INTO delta_candidate_tags VALUES (?,?)",
                               ((delta_id, tag) for tag in signal.signal_tags))
                db.execute("INSERT INTO delta_candidate_events(delta_id,old_status,"
                           "new_status,reason_code,changed_at) VALUES (?,?,?,?,?)",
                           (delta_id, None, initial_status.value,
                            signal.reason_code, at))
                db.execute("UPDATE delta_candidates SET status=?,updated_at=? "
                           "WHERE target_id=? AND entity_type=? AND entity_id IS ? "
                           "AND delta_type=? AND delta_id!=? AND campaign_id IS NULL "
                           "AND status IN ('NEW','CLASSIFIED','DEFERRED','CAMPAIGN_READY')",
                           (DeltaStatus.SUPERSEDED.value, at, package.target.id,
                            signal.entity_type, signal.entity_id,
                            signal.delta_type.value, delta_id))
            cadence = target["cadence_seconds"]
            next_check = ((datetime.fromisoformat(at) + timedelta(
                seconds=60 if backlog_min_count else cadence)).isoformat()
                          if target["enabled"] else None)
            highwater_at = (event_highwater[0] if event_highwater and backfill is None
                            else target["last_event_at"])
            highwater_id = (event_highwater[1] if event_highwater and backfill is None
                            else target["last_event_id"])
            db.execute(
                "UPDATE continuous_targets SET status=?,next_check_at=?,last_checked_at=?,"
                "last_success_at=?,last_snapshot_id=COALESCE(?,last_snapshot_id),"
                "last_event_at=?,last_event_id=?,"
                "backfill_cursor=?,backfill_window_start=?,backfill_window_end=?,"
                "backfill_highwater_at=?,backfill_highwater_id=?,"
                "last_bootstrap_at=COALESCE(?,last_bootstrap_at),"
                "last_bootstrap_id=COALESCE(?,last_bootstrap_id),"
                "last_js_at=COALESCE(?,last_js_at),"
                "last_delta_at=CASE WHEN ?>0 THEN ? ELSE last_delta_at END,"
                "backlog_min_count=?,backlog_oldest_at=?,error_code=?,updated_at=? "
                "WHERE target_id=?",
                (status.value, next_check, at, at if not degraded_reason else
                 target["last_success_at"], snapshot_id, highwater_at, highwater_id,
                 backfill[0] if backfill else None,
                 backfill[1] if backfill else None,
                 backfill[2] if backfill else None,
                 backfill[3] if backfill else None,
                 backfill[4] if backfill else None,
                 bootstrap_highwater[0] if bootstrap_highwater else None,
                 bootstrap_highwater[1] if bootstrap_highwater else None,
                 js_highwater, created, at,
                 backlog_min_count, backlog_oldest_at, degraded_reason, at,
                 package.target.id))
            db.execute("UPDATE delta_watch_runs SET status=?,baseline=?,source_kind=?,"
                       "snapshot_id=?,events_scanned=?,candidates_created=?,"
                       "ignored_count=?,backlog_min_count=?,error_code=?,finished_at=? "
                       "WHERE watch_id=?",
                       (status.value, int(baseline), source.value if source else "NONE",
                        snapshot_id, scanned, created, ignored,
                        backlog_min_count, degraded_reason, at, watch_id))
        return {"watch_id": watch_id, "status": status.value,
                "baseline": baseline, "source": source.value if source else "NONE",
                "events_scanned": scanned, "candidates_created": created,
                "ignored_count": ignored, "backlog_min_count": backlog_min_count,
                "error_code": degraded_reason}

    def fail_watch(self, package: TargetPackage, watch_id: str,
                   reason_code: str) -> None:
        if not _WATCH_ID.fullmatch(watch_id) or not _CODE.fullmatch(reason_code):
            raise ValueError("Invalid watch failure")
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT cadence_seconds,enabled FROM continuous_targets "
                             "WHERE target_id=? AND package_id=?",
                             (package.target.id, package.id)).fetchone()
            if row is None:
                raise LookupError("Continuous target not found")
            next_check = ((datetime.fromisoformat(at) + timedelta(
                seconds=row["cadence_seconds"])).isoformat() if row["enabled"] else None)
            updated = db.execute("UPDATE delta_watch_runs SET status='FAILED',error_code=?,"
                       "finished_at=? WHERE watch_id=? AND target_id=? AND status='RUNNING'",
                       (reason_code, at, watch_id, package.target.id))
            if updated.rowcount != 1:
                raise ValueError("Watch is not active for this Target Package")
            db.execute("UPDATE continuous_targets SET status='DEGRADED',error_code=?,"
                       "next_check_at=?,updated_at=? WHERE target_id=?",
                       (reason_code, next_check, at, package.target.id))

    def observation(self, target_id: str, source: DeltaSource,
                    entity_key: str) -> dict[str, object] | None:
        if not _REF.fullmatch(entity_key):
            raise ValueError("Invalid observation key")
        with self.store._connection() as db:
            row = db.execute("SELECT fingerprint,semantic_hash,artifact_id,observed_at "
                             "FROM delta_observations WHERE target_id=? AND source_kind=? "
                             "AND entity_key=?",
                             (target_id, source.value, entity_key)).fetchone()
        return dict(row) if row else None

    def get_candidate(self, target_id: str, delta_id: str) -> dict[str, object] | None:
        if not _ID.fullmatch(delta_id):
            raise ValueError("Invalid delta ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM delta_candidates WHERE target_id=? AND delta_id=?",
                             (target_id, delta_id)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["specialist_hints"] = [item[0] for item in db.execute(
                "SELECT specialist FROM delta_candidate_hints WHERE delta_id=? "
                "ORDER BY specialist", (delta_id,))]
            result["signal_tags"] = [item[0] for item in db.execute(
                "SELECT tag FROM delta_candidate_tags WHERE delta_id=? ORDER BY tag",
                (delta_id,))]
            result["campaign_status"] = None
            result["finding_count"] = 0
            if result["campaign_id"]:
                campaign = db.execute("SELECT status FROM campaigns WHERE campaign_id=? "
                                      "AND target_id=?", (result["campaign_id"],
                                      target_id)).fetchone()
                result["campaign_status"] = campaign["status"] if campaign else None
                result["finding_count"] = db.execute(
                    "SELECT count(DISTINCT p.finding_id) FROM campaign_work AS w "
                    "JOIN planner_candidates AS p ON p.run_id=w.child_id "
                    "WHERE w.campaign_id=? AND w.kind='PLANNER' "
                    "AND p.finding_id IS NOT NULL",
                    (result["campaign_id"],)).fetchone()[0]
        return result

    def list_candidates(self, *, target_id: str | None = None,
                        status: DeltaStatus | None = None,
                        limit: int = 30) -> tuple[dict[str, object], ...]:
        return self.page_candidates(target_id=target_id, status=status,
                                    limit=limit)["items"]

    def page_candidates(self, *, target_id: str | None = None,
                        status: DeltaStatus | None = None,
                        limit: int = 30,
                        before: str | None = None) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid delta page size")
        clauses, args = [], []
        if target_id is not None:
            clauses.append("target_id=?"); args.append(target_id)
        if status is not None:
            clauses.append("status=?"); args.append(status.value)
        with self.store._connection() as db:
            if before is not None:
                if not _ID.fullmatch(before):
                    raise ValueError("Invalid delta cursor")
                anchor = db.execute(
                    "SELECT target_id,status,observed_at,delta_id FROM delta_candidates "
                    "WHERE delta_id=?", (before,)).fetchone()
                if (anchor is None or
                        (target_id is not None and anchor["target_id"] != target_id) or
                        (status is not None and anchor["status"] != status.value)):
                    raise ValueError("Delta cursor is outside the selected filter")
                clauses.append("(observed_at,delta_id)<(?,?)")
                args.extend((anchor["observed_at"], anchor["delta_id"]))
            predicate = " WHERE " + " AND ".join(clauses) if clauses else ""
            rows = db.execute("SELECT target_id,delta_id FROM delta_candidates" + predicate +
                              " ORDER BY observed_at DESC,delta_id DESC LIMIT ?",
                              (*args, limit + 1)).fetchall()
        has_more = len(rows) > limit
        page = rows[:limit]
        items = tuple(item for row in page if (item := self.get_candidate(
            row["target_id"], row["delta_id"])) is not None)
        return {"items": items,
                "next_cursor": page[-1]["delta_id"] if has_more and page else None}

    def ready_candidates(self, target_id: str, *, minimum_relevance: int,
                         limit: int = 20) -> tuple[dict[str, object], ...]:
        if (type(minimum_relevance) is not int or not 0 <= minimum_relevance <= 100 or
                type(limit) is not int or not 1 <= limit <= 50):
            raise ValueError("Invalid delta candidate selection")
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT d.delta_id FROM delta_candidates AS d WHERE d.target_id=? "
                "AND d.status='CLASSIFIED' AND d.relevance>=? AND EXISTS "
                "(SELECT 1 FROM delta_candidate_hints AS h WHERE h.delta_id=d.delta_id) "
                "ORDER BY d.relevance DESC,d.observed_at DESC,d.delta_id DESC LIMIT ?",
                (target_id, minimum_relevance, limit)).fetchall()
        return tuple(item for row in rows if (item := self.get_candidate(
            target_id, row["delta_id"])) is not None)

    def unmaterialized_candidates(self, target_id: str, *,
                                  limit: int = 20) -> tuple[str, ...]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Invalid evidence batch size")
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT delta_id FROM delta_candidates WHERE target_id=? "
                "AND evidence_id IS NULL ORDER BY relevance DESC,observed_at DESC "
                "LIMIT ?", (target_id, limit)).fetchall()
        return tuple(row["delta_id"] for row in rows)

    def stats(self) -> dict[str, object]:
        today = datetime.now(timezone.utc).date().isoformat() + "T00:00:00+00:00"
        with self.store._connection() as db:
            targets = db.execute(
                "SELECT count(*) AS total,sum(enabled) AS enabled,"
                "sum(CASE WHEN status='DEGRADED' THEN 1 ELSE 0 END) AS degraded,"
                "sum(backlog_min_count) AS backlog_min_count,"
                "min(last_success_at) AS oldest_last_success_at,"
                "min(backlog_oldest_at) AS backlog_oldest_at "
                "FROM continuous_targets").fetchone()
            deltas = db.execute(
                "SELECT count(*) AS total,"
                "sum(CASE WHEN created_at>=? THEN 1 ELSE 0 END) AS today,"
                "sum(CASE WHEN status='IGNORED' THEN 1 ELSE 0 END) AS ignored,"
                "avg(max(0,(julianday(created_at)-julianday(observed_at))*86400)) "
                "AS detection_seconds "
                "FROM delta_candidates", (today,)).fetchone()
            meaningful = db.execute(
                "SELECT count(*) FROM delta_candidates AS d JOIN continuous_targets AS t "
                "ON t.target_id=d.target_id WHERE d.relevance>=t.minimum_relevance "
                "AND d.status NOT IN ('IGNORED','DEFERRED','SUPERSEDED','BLOCKED') "
                "AND EXISTS (SELECT 1 FROM delta_candidate_hints AS h "
                "WHERE h.delta_id=d.delta_id)").fetchone()[0]
            watches = db.execute(
                "SELECT count(*) AS total,coalesce(sum(events_scanned),0) AS events_scanned "
                "FROM delta_watch_runs").fetchone()
            campaigns = db.execute(
                "SELECT count(*) AS total,coalesce(sum(c.requests_used+c.cleanup_used),0) "
                "AS requests_used,sum(f.automatic) AS automatic FROM delta_campaign_focus AS f "
                "JOIN campaigns AS c ON c.campaign_id=f.campaign_id").fetchone()
            findings = db.execute(
                "SELECT count(DISTINCT p.finding_id) FROM delta_campaign_focus AS f "
                "JOIN campaign_work AS w ON w.campaign_id=f.campaign_id "
                "AND w.kind='PLANNER' JOIN planner_candidates AS p ON p.run_id=w.child_id "
                "WHERE p.finding_id IS NOT NULL").fetchone()[0]
            rejected = db.execute(
                "SELECT count(*) FROM delta_campaign_focus AS f "
                "JOIN campaign_work AS w ON w.campaign_id=f.campaign_id "
                "AND w.kind='PLANNER' JOIN planner_candidates AS p ON p.run_id=w.child_id "
                "WHERE p.status='REJECTED'").fetchone()[0]
            validation = db.execute(
                "SELECT avg(max(0,(julianday(confirmed_at)-julianday(observed_at))*86400)) "
                "FROM (SELECT f.finding_id,min(f.created_at) AS confirmed_at,"
                "min(d.observed_at) AS observed_at FROM delta_campaign_focus_deltas AS fd "
                "JOIN delta_candidates AS d ON d.delta_id=fd.delta_id "
                "JOIN campaign_work AS w ON w.campaign_id=fd.campaign_id "
                "AND w.kind='PLANNER' JOIN planner_candidates AS p ON p.run_id=w.child_id "
                "JOIN findings AS f ON f.finding_id=p.finding_id "
                "GROUP BY f.finding_id)").fetchone()[0]
        backlog_age = None
        if targets["backlog_oldest_at"]:
            oldest = datetime.fromisoformat(targets["backlog_oldest_at"])
            if oldest.tzinfo is None:
                oldest = oldest.replace(tzinfo=timezone.utc)
            backlog_age = max(0, int((datetime.now(timezone.utc) - oldest).total_seconds()))
        campaign_count = int(campaigns["total"] or 0)
        finding_count = int(findings or 0)
        return {
            "targets": int(targets["total"] or 0),
            "enabled_targets": int(targets["enabled"] or 0),
            "degraded_targets": int(targets["degraded"] or 0),
            "backlog_min_count": int(targets["backlog_min_count"] or 0),
            "backlog_age_seconds": backlog_age,
            "oldest_last_success_at": targets["oldest_last_success_at"],
            "deltas": int(deltas["total"] or 0),
            "deltas_today": int(deltas["today"] or 0),
            "ignored_deltas": int(deltas["ignored"] or 0),
            "classified_deltas": int(deltas["total"] or 0),
            "meaningful_deltas": int(meaningful or 0),
            "mean_time_to_detection_seconds": (round(deltas["detection_seconds"], 1)
                                               if deltas["detection_seconds"] is not None else None),
            "watch_cycles": int(watches["total"] or 0),
            "events_scanned": int(watches["events_scanned"] or 0),
            "focused_campaigns": campaign_count,
            "automatic_focused_campaigns": int(campaigns["automatic"] or 0),
            "focused_requests_reserved": int(campaigns["requests_used"] or 0),
            "findings_from_deltas": finding_count,
            "planner_rejections": int(rejected or 0),
            "mean_time_to_validation_seconds": (round(validation, 1)
                                                if validation is not None else None),
            "findings_per_delta_campaign": (round(finding_count / campaign_count, 3)
                                            if campaign_count else None),
            "campaigns_per_meaningful_delta": (round(campaign_count / meaningful, 3)
                                               if meaningful else None),
            "requests_per_delta_finding": (round(int(campaigns["requests_used"] or 0) /
                                                finding_count, 3) if finding_count else None),
        }

    def link_evidence(self, target_id: str, delta_id: str, evidence_id: str) -> None:
        if not _ID.fullmatch(delta_id):
            raise ValueError("Invalid delta ID")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM evidence WHERE evidence_id=? AND target_ref=?",
                          (evidence_id, target_id)).fetchone() is None:
                raise ValueError("Delta evidence target mismatch")
            row = db.execute("SELECT evidence_id FROM delta_candidates WHERE delta_id=? "
                             "AND target_id=?", (delta_id, target_id)).fetchone()
            if row is None:
                raise LookupError("Delta candidate not found")
            if row[0] is not None and row[0] != evidence_id:
                raise ValueError("Delta evidence is immutable")
            db.execute("UPDATE delta_candidates SET evidence_id=? WHERE delta_id=?",
                       (evidence_id, delta_id))

    def link_hypothesis(self, target_id: str, delta_id: str,
                        hypothesis_id: str) -> None:
        if not _ID.fullmatch(delta_id):
            raise ValueError("Invalid delta ID")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM hypotheses WHERE hypothesis_id=? AND target_id=?",
                          (hypothesis_id, target_id)).fetchone() is None:
                raise ValueError("Delta hypothesis target mismatch")
            row = db.execute("SELECT 1 FROM delta_candidates WHERE target_id=? AND delta_id=?",
                             (target_id, delta_id)).fetchone()
            if row is None:
                raise LookupError("Delta candidate not found")
            db.execute("INSERT OR IGNORE INTO delta_candidate_hypotheses VALUES (?,?)",
                       (delta_id, hypothesis_id))
            db.execute("UPDATE delta_candidates SET hypothesis_id=COALESCE(hypothesis_id,?),"
                       "updated_at=? WHERE target_id=? AND delta_id=?",
                       (hypothesis_id, _now(), target_id, delta_id))

    def hypothesis_ids(self, target_id: str, delta_id: str) -> tuple[str, ...]:
        if not _ID.fullmatch(delta_id):
            raise ValueError("Invalid delta ID")
        with self.store._connection() as db:
            rows = db.execute("SELECT h.hypothesis_id FROM delta_candidate_hypotheses AS h "
                              "JOIN delta_candidates AS d ON d.delta_id=h.delta_id "
                              "WHERE d.target_id=? AND d.delta_id=? ORDER BY h.hypothesis_id",
                              (target_id, delta_id)).fetchall()
        return tuple(row[0] for row in rows)

    def transition_candidate(self, target_id: str, delta_id: str,
                             status: DeltaStatus, reason_code: str) -> dict[str, object]:
        if not _ID.fullmatch(delta_id) or not isinstance(status, DeltaStatus) or\
                not _CODE.fullmatch(reason_code):
            raise ValueError("Invalid delta transition")
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM delta_candidates WHERE target_id=? "
                             "AND delta_id=?", (target_id, delta_id)).fetchone()
            if row is None:
                raise LookupError("Delta candidate not found")
            if row["status"] != status.value:
                db.execute("UPDATE delta_candidates SET status=?,reason_code=?,updated_at=? "
                           "WHERE target_id=? AND delta_id=?",
                           (status.value, reason_code, at, target_id, delta_id))
                db.execute("INSERT INTO delta_candidate_events(delta_id,old_status,"
                           "new_status,reason_code,changed_at) VALUES (?,?,?,?,?)",
                           (delta_id, row["status"], status.value, reason_code, at))
        result = self.get_candidate(target_id, delta_id)
        assert result is not None
        return result

    def reconcile_interrupted(self) -> int:
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT watch_id,target_id FROM delta_watch_runs "
                              "WHERE status='RUNNING'").fetchall()
            for row in rows:
                db.execute("UPDATE delta_watch_runs SET status='DEGRADED',"
                           "error_code='INTERRUPTED_RESTART',finished_at=? WHERE watch_id=?",
                           (at, row["watch_id"]))
                db.execute("UPDATE continuous_targets SET status='DEGRADED',"
                           "error_code='INTERRUPTED_RESTART',next_check_at=?,updated_at=? "
                           "WHERE target_id=?", (at, at, row["target_id"]))
        return len(rows)
