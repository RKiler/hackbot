"""Conservative, reviewed retention of terminal Chromium profiles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import stat
from typing import Callable
import uuid

from .browser import BrowserSessionManager
from .domain import validate_entity_id


class ProfileRetentionError(RuntimeError):
    """The profile cleanup boundary cannot be proven safe."""


@dataclass(frozen=True, slots=True)
class ProfileRetentionPolicy:
    anonymous_grace_hours: int = 48
    max_scan_profiles: int = 1000
    max_delete_profiles: int = 20
    max_tree_entries: int = 100_000
    disabled_identity_grace_hours: int = 168
    active_identity_grace_hours: int = 720

    def __post_init__(self) -> None:
        values = (self.anonymous_grace_hours, self.max_scan_profiles,
                  self.max_delete_profiles, self.max_tree_entries,
                  self.disabled_identity_grace_hours,
                  self.active_identity_grace_hours)
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("Invalid browser profile retention policy")
        if self.max_delete_profiles > self.max_scan_profiles:
            raise ValueError("Browser profile delete cap exceeds scan cap")


@dataclass(frozen=True, slots=True)
class ProfileRetentionPlan:
    session_ids: tuple[str, ...]
    estimated_bytes: int
    scanned: int
    truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {"class": "TERMINAL_ANONYMOUS_BROWSER_PROFILE", "dry_run": True,
                "candidate_count": len(self.session_ids),
                "session_ids": list(self.session_ids),
                "estimated_bytes": self.estimated_bytes, "scanned": self.scanned,
                "truncated": self.truncated}


@dataclass(frozen=True, slots=True)
class DisabledProfileRetentionPlan:
    target_id: str
    identity_id: str
    session_ids: tuple[str, ...]
    estimated_bytes: int
    scanned: int
    truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {"class": "TERMINAL_DISABLED_IDENTITY_BROWSER_PROFILE", "dry_run": True,
                "target_id": self.target_id, "identity_id": self.identity_id,
                "candidate_count": len(self.session_ids),
                "session_ids": list(self.session_ids),
                "estimated_bytes": self.estimated_bytes, "scanned": self.scanned,
                "truncated": self.truncated}


@dataclass(frozen=True, slots=True)
class NamedProfileRetentionPlan:
    target_id: str
    identity_id: str
    session_ids: tuple[str, ...]
    estimated_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {"class": "TERMINAL_ACTIVE_IDENTITY_BROWSER_PROFILE", "dry_run": True,
                "target_id": self.target_id, "identity_id": self.identity_id,
                "session_ids": list(self.session_ids),
                "candidate_count": len(self.session_ids),
                "estimated_bytes": self.estimated_bytes}


class BrowserProfileCollector:
    """Anonymous cleanup is separate from explicit disabled-identity cleanup."""

    def __init__(self, manager: BrowserSessionManager, policy: ProfileRetentionPolicy,
                 process_safe: Callable[[], bool], audit_path: Path) -> None:
        self.manager = manager
        self.policy = policy
        self.process_safe = process_safe
        self.audit_path = audit_path

    @staticmethod
    def _target_busy(db: object, target_id: str) -> bool:
        checks = (
            ("SELECT 1 FROM plan_runs WHERE target_id=? AND status NOT IN "
             "('COMPLETED','REJECTED','FAILED','BUDGET_EXHAUSTED','CANCELLED') LIMIT 1"),
            ("SELECT 1 FROM planner_runs WHERE target_id=? AND status NOT IN "
             "('COMPLETED','BLOCKED','FAILED','CANCELLED','BUDGET_EXHAUSTED') LIMIT 1"),
            ("SELECT 1 FROM test_objects WHERE target_id=? AND cleanup_required=1 "
             "AND lifecycle NOT IN ('CLEANED') LIMIT 1"),
        )
        return any(db.execute(sql, (target_id,)).fetchone() is not None for sql in checks)

    def _profile_bytes(self, path: Path) -> int:
        if not path.exists():
            return 0
        if path.is_symlink() or not path.is_dir():
            raise ProfileRetentionError("Unsafe browser profile path")
        total = seen = 0
        for current, dirs, files in os.walk(path, followlinks=False):
            for name in dirs + files:
                seen += 1
                if seen > self.policy.max_tree_entries:
                    raise ProfileRetentionError("Browser profile tree exceeds cleanup bound")
                details = (Path(current) / name).lstat()
                if stat.S_ISREG(details.st_mode):
                    total += details.st_size
                elif not (stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode)):
                    raise ProfileRetentionError("Unsafe browser profile entry")
        return total

    def _select(self, db: object, now: datetime) -> ProfileRetentionPlan:
        if not self.process_safe() or not shutil.rmtree.avoids_symlink_attacks:
            raise ProfileRetentionError("Browser process ownership is not proven")
        cutoff = (now - timedelta(hours=self.policy.anonymous_grace_hours)).isoformat()
        rows = db.execute(
            "SELECT session_id,target_id FROM browser_sessions WHERE identity_id IS NULL "
            "AND status IN ('STOPPED','FAILED','EXPIRED') AND updated_at<=? "
            "ORDER BY updated_at,session_id LIMIT ?",
            (cutoff, self.policy.max_scan_profiles + 1),
        ).fetchall()
        selected: list[str] = []
        size = 0
        for row in rows[:self.policy.max_scan_profiles]:
            if self._target_busy(db, row["target_id"]):
                continue
            session = self.manager.get(row["session_id"])
            if (session is None or not session.anonymous or
                    session.updated_at > now - timedelta(hours=self.policy.anonymous_grace_hours) or
                    self.manager.driver.is_running(session.id)):
                continue
            path = self.manager.profiles.path(session)
            if not path.exists():
                continue
            size += self._profile_bytes(path)
            selected.append(session.id)
            if len(selected) >= self.policy.max_delete_profiles:
                break
        return ProfileRetentionPlan(tuple(selected), size,
                                    min(len(rows), self.policy.max_scan_profiles),
                                    len(rows) > self.policy.max_scan_profiles or
                                    len(selected) >= self.policy.max_delete_profiles)

    def plan(self, *, now: datetime | None = None) -> ProfileRetentionPlan:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("Retention time must be timezone-aware")
        with self.manager.registry.store._connection() as db:
            return self._select(db, current)

    def _select_disabled(self, db: object, now: datetime, *, target_id: str,
                         identity_id: str) -> DisabledProfileRetentionPlan:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(identity_id, "IDENTITY")
        if not self.process_safe() or not shutil.rmtree.avoids_symlink_attacks:
            raise ProfileRetentionError("Browser process ownership is not proven")
        cutoff_time = now - timedelta(hours=self.policy.disabled_identity_grace_hours)
        cutoff = cutoff_time.isoformat()
        identity = db.execute(
            "SELECT status,updated_at FROM registry_identities WHERE target_id=? AND identity_id=?",
            (target_id, identity_id),
        ).fetchone()
        try:
            disabled_at = datetime.fromisoformat(identity["updated_at"]) if identity else None
        except (TypeError, ValueError):
            disabled_at = None
        if (identity is None or identity["status"] != "DISABLED" or
                disabled_at is None or disabled_at.tzinfo is None or
                disabled_at > cutoff_time):
            raise ProfileRetentionError("Identity is not eligible for profile cleanup")
        if self._target_busy(db, target_id):
            return DisabledProfileRetentionPlan(target_id, identity_id, (), 0, 0, False)
        rows = db.execute(
            "SELECT session_id FROM browser_sessions WHERE target_id=? AND identity_id=? "
            "AND status IN ('STOPPED','FAILED','EXPIRED') AND updated_at<=? "
            "AND (last_used_at IS NULL OR last_used_at<=?) "
            "AND (last_verified_at IS NULL OR last_verified_at<=?) "
            "ORDER BY updated_at,session_id LIMIT ?",
            (target_id, identity_id, cutoff, cutoff, cutoff,
             self.policy.max_scan_profiles + 1),
        ).fetchall()
        selected: list[str] = []
        size = 0
        for row in rows[:self.policy.max_scan_profiles]:
            session = self.manager.get(row["session_id"])
            if (session is None or session.target_id != target_id or
                    session.identity_id != identity_id or
                    session.status.value not in {"STOPPED", "FAILED", "EXPIRED"} or
                    session.updated_at > cutoff_time or
                    (session.last_used_at is not None and session.last_used_at > cutoff_time) or
                    (session.last_verified_at is not None and session.last_verified_at > cutoff_time) or
                    self.manager.driver.is_running(session.id)):
                continue
            path = self.manager.profiles.path(session)
            if not path.exists():
                continue
            size += self._profile_bytes(path)
            selected.append(session.id)
            if len(selected) >= self.policy.max_delete_profiles:
                break
        return DisabledProfileRetentionPlan(
            target_id, identity_id, tuple(selected), size,
            min(len(rows), self.policy.max_scan_profiles),
            len(rows) > self.policy.max_scan_profiles or
            len(selected) >= self.policy.max_delete_profiles)

    def plan_disabled(self, target_id: str, identity_id: str, *,
                      now: datetime | None = None) -> DisabledProfileRetentionPlan:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("Retention time must be timezone-aware")
        with self.manager.registry.store._connection() as db:
            return self._select_disabled(db, current, target_id=target_id,
                                         identity_id=identity_id)

    def _select_named(self, db: object, now: datetime, *, target_id: str,
                      identity_id: str, session_id: str) -> NamedProfileRetentionPlan:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(identity_id, "IDENTITY")
        validate_entity_id(session_id, "BSESSION")
        if not self.process_safe() or not shutil.rmtree.avoids_symlink_attacks:
            raise ProfileRetentionError("Browser process ownership is not proven")
        identity = db.execute(
            "SELECT status FROM registry_identities WHERE target_id=? AND identity_id=?",
            (target_id, identity_id),
        ).fetchone()
        if identity is None or identity["status"] != "ACTIVE":
            raise ProfileRetentionError("Active identity is required for named profile review")
        empty = NamedProfileRetentionPlan(target_id, identity_id, (), 0)
        if self._target_busy(db, target_id):
            return empty
        session = self.manager.get(session_id)
        cutoff = now - timedelta(hours=self.policy.active_identity_grace_hours)
        if (session is None or session.target_id != target_id or
                session.identity_id != identity_id or
                session.status.value not in {"STOPPED", "FAILED", "EXPIRED", "REAUTH_REQUIRED"} or
                session.updated_at > cutoff or
                (session.last_used_at is not None and session.last_used_at > cutoff) or
                (session.last_verified_at is not None and session.last_verified_at > cutoff) or
                self.manager.driver.is_running(session_id)):
            return empty
        if db.execute(
            "SELECT 1 FROM auth_contexts WHERE target_id=? AND identity_id=? "
            "AND browser_session_ref=? AND status='VALID' LIMIT 1",
            (target_id, identity_id, session_id),
        ).fetchone():
            return empty
        path = self.manager.profiles.path(session)
        if not path.exists():
            return empty
        return NamedProfileRetentionPlan(target_id, identity_id, (session_id,),
                                         self._profile_bytes(path))

    def plan_named(self, target_id: str, identity_id: str, session_id: str, *,
                   now: datetime | None = None) -> NamedProfileRetentionPlan:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("Retention time must be timezone-aware")
        with self.manager.registry.store._connection() as db:
            return self._select_named(db, current, target_id=target_id,
                                      identity_id=identity_id, session_id=session_id)

    def run_named(self, target_id: str, identity_id: str, session_id: str, *,
                  confirmed: bool, approved_plan: NamedProfileRetentionPlan,
                  now: datetime | None = None) -> dict[str, object]:
        with self.manager.profile_lifecycle_lock:
            return self._run_named_locked(target_id, identity_id, session_id,
                                          confirmed=confirmed, approved_plan=approved_plan,
                                          now=now)

    def _run_named_locked(self, target_id: str, identity_id: str, session_id: str, *,
                          confirmed: bool, approved_plan: NamedProfileRetentionPlan,
                          now: datetime | None) -> dict[str, object]:
        if confirmed is not True or not isinstance(approved_plan, NamedProfileRetentionPlan):
            raise ProfileRetentionError("Named profile cleanup requires reviewed confirmation")
        if (approved_plan.target_id != target_id or approved_plan.identity_id != identity_id or
                approved_plan.session_ids != (session_id,)):
            raise ProfileRetentionError("Named profile review does not match session")
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("Retention time must be timezone-aware")
        with self.manager.registry.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            fresh = self._select_named(db, current, target_id=target_id,
                                       identity_id=identity_id, session_id=session_id)
            if fresh.session_ids != (session_id,):
                raise ProfileRetentionError("Named profile is no longer eligible")
            operation_id = "PROFILE-" + uuid.uuid4().hex
            self._audit(operation_id, "STARTED", 0, 0,
                        retention_class="TERMINAL_ACTIVE_IDENTITY_BROWSER_PROFILE",
                        target_id=target_id, identity_id=identity_id)
            session = self.manager.get(session_id)
            if session is None or self.manager.driver.is_running(session_id):
                raise ProfileRetentionError("Browser session changed during cleanup")
            reclaimed = self._profile_bytes(self.manager.profiles.path(session))
            self.manager.profiles.delete(session)
            self._audit(operation_id, "COMPLETED", 1, reclaimed,
                        retention_class="TERMINAL_ACTIVE_IDENTITY_BROWSER_PROFILE",
                        target_id=target_id, identity_id=identity_id)
            return {"removed": 1, "reclaimed_bytes": reclaimed, "truncated": False}

    def run(self, *, confirmed: bool, now: datetime | None = None,
            approved_plan: ProfileRetentionPlan | None = None) -> dict[str, object]:
        with self.manager.profile_lifecycle_lock:
            return self._run_locked(confirmed=confirmed, now=now,
                                    approved_plan=approved_plan)

    def _run_locked(self, *, confirmed: bool, now: datetime | None,
                    approved_plan: ProfileRetentionPlan | None) -> dict[str, object]:
        if confirmed is not True:
            raise ProfileRetentionError("Browser profile cleanup requires confirmation")
        if approved_plan is not None and not isinstance(approved_plan, ProfileRetentionPlan):
            raise ProfileRetentionError("Invalid approved browser profile plan")
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("Retention time must be timezone-aware")
        with self.manager.registry.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            plan = self._select(db, current)
            if approved_plan is not None:
                allowed = set(approved_plan.session_ids)
                plan = ProfileRetentionPlan(
                    tuple(value for value in plan.session_ids if value in allowed),
                    0, plan.scanned, plan.truncated)
            operation_id = "PROFILE-" + uuid.uuid4().hex
            self._audit(operation_id, "STARTED", 0, 0)
            removed = 0
            reclaimed = 0
            for session_id in plan.session_ids:
                session = self.manager.get(session_id)
                if session is None or not session.anonymous or self.manager.driver.is_running(session_id):
                    raise ProfileRetentionError("Browser session changed during cleanup")
                reclaimed += self._profile_bytes(self.manager.profiles.path(session))
                self.manager.profiles.delete(session)
                removed += 1
            self._audit(operation_id, "COMPLETED", removed, reclaimed)
            return {"removed": removed, "reclaimed_bytes": reclaimed,
                    "truncated": plan.truncated}

    def run_disabled(self, target_id: str, identity_id: str, *, confirmed: bool,
                     approved_plan: DisabledProfileRetentionPlan,
                     now: datetime | None = None) -> dict[str, object]:
        with self.manager.profile_lifecycle_lock:
            return self._run_disabled_locked(target_id, identity_id, confirmed=confirmed,
                                             approved_plan=approved_plan, now=now)

    def _run_disabled_locked(self, target_id: str, identity_id: str, *, confirmed: bool,
                             approved_plan: DisabledProfileRetentionPlan,
                             now: datetime | None) -> dict[str, object]:
        if confirmed is not True or not isinstance(approved_plan, DisabledProfileRetentionPlan):
            raise ProfileRetentionError("Disabled profile cleanup requires reviewed confirmation")
        if (approved_plan.target_id != target_id or approved_plan.identity_id != identity_id):
            raise ProfileRetentionError("Disabled profile review does not match identity")
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("Retention time must be timezone-aware")
        with self.manager.registry.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            fresh = self._select_disabled(db, current, target_id=target_id,
                                          identity_id=identity_id)
            allowed = set(approved_plan.session_ids)
            selected = tuple(value for value in fresh.session_ids if value in allowed)
            operation_id = "PROFILE-" + uuid.uuid4().hex
            self._audit(operation_id, "STARTED", 0, 0,
                        retention_class="TERMINAL_DISABLED_IDENTITY_BROWSER_PROFILE",
                        target_id=target_id, identity_id=identity_id)
            removed = 0
            reclaimed = 0
            for session_id in selected:
                session = self.manager.get(session_id)
                if (session is None or session.target_id != target_id or
                        session.identity_id != identity_id or
                        session.status.value not in {"STOPPED", "FAILED", "EXPIRED"} or
                        self.manager.driver.is_running(session_id)):
                    raise ProfileRetentionError("Browser session changed during cleanup")
                reclaimed += self._profile_bytes(self.manager.profiles.path(session))
                self.manager.profiles.delete(session)
                removed += 1
            self._audit(operation_id, "COMPLETED", removed, reclaimed,
                        retention_class="TERMINAL_DISABLED_IDENTITY_BROWSER_PROFILE",
                        target_id=target_id, identity_id=identity_id)
            return {"removed": removed, "reclaimed_bytes": reclaimed,
                    "truncated": fresh.truncated}

    def _audit(self, operation_id: str, stage: str, removed: int, reclaimed: int,
               *, retention_class: str = "TERMINAL_ANONYMOUS_BROWSER_PROFILE",
               target_id: str | None = None, identity_id: str | None = None) -> None:
        parent = self.audit_path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if parent.is_symlink() or self.audit_path.is_symlink():
            raise ProfileRetentionError("Unsafe profile retention audit path")
        event = {"at": datetime.now(timezone.utc).isoformat(),
                 "action": "BROWSER_PROFILE_RETENTION", "operation_id": operation_id,
                 "retention_class": retention_class, "target_id": target_id,
                 "identity_id": identity_id, "stage": stage, "removed": removed,
                 "reclaimed_bytes": reclaimed}
        try:
            fd = os.open(self.audit_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "ab") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write((json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            raise ProfileRetentionError("Cannot audit browser profile retention") from None
