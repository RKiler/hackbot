"""One bounded, local-only maintenance action with conservative restart state."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
from threading import Lock, Thread
import uuid

from .backup import BackupManager
from .profile_retention import (BrowserProfileCollector, DisabledProfileRetentionPlan,
                                NamedProfileRetentionPlan, ProfileRetentionPlan)
from .retention import ArtifactGarbageCollector, CollectionPlan


_ACTIONS = frozenset({"BACKUP_CREATE", "BACKUP_VERIFY", "RETENTION_PLAN", "RETENTION_RUN",
                      "PROFILE_PLAN", "PROFILE_RUN", "DISABLED_PROFILE_PLAN",
                      "DISABLED_PROFILE_RUN", "NAMED_PROFILE_PLAN", "NAMED_PROFILE_RUN"})
_RUN_ACTIONS = frozenset({"RETENTION_RUN", "PROFILE_RUN", "DISABLED_PROFILE_RUN",
                          "NAMED_PROFILE_RUN"})
_DISABLED_PROFILE_ACTIONS = frozenset({"DISABLED_PROFILE_PLAN", "DISABLED_PROFILE_RUN"})
_NAMED_PROFILE_ACTIONS = frozenset({"NAMED_PROFILE_PLAN", "NAMED_PROFILE_RUN"})
_BACKUP_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z")


class MaintenanceError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class MaintenanceCoordinator:
    """Persist action state; never resume an interrupted action automatically."""

    def __init__(self, state_path: Path, backup: BackupManager,
                 retention: ArtifactGarbageCollector,
                 profiles: BrowserProfileCollector | None = None) -> None:
        self.state_path = state_path
        self.backup = backup
        self.retention = retention
        self.profiles = profiles
        self._lock = Lock()
        self._thread: Thread | None = None
        self._reviewed_retention: tuple[str, CollectionPlan] | None = None
        self._reviewed_profiles: tuple[str, ProfileRetentionPlan] | None = None
        self._reviewed_disabled_profiles: tuple[str, DisabledProfileRetentionPlan] | None = None
        self._reviewed_named_profile: tuple[str, NamedProfileRetentionPlan] | None = None
        try:
            self._current = self._read()
        except MaintenanceError:
            self._current = {"status": "FAILED", "reason_code": "CORRUPT_MAINTENANCE_STATE"}
        if self._current.get("status") in {"QUEUED", "RUNNING"}:
            self._current = {**self._current, "status": "INTERRUPTED",
                             "reason_code": "PROCESS_RESTART", "finished_at": _now()}
            self._write(self._current)

    def _read(self) -> dict[str, object]:
        path = self.state_path
        if not path.exists():
            return {"status": "IDLE"}
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16_384:
            raise MaintenanceError("UNSAFE_MAINTENANCE_STATE")
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise MaintenanceError("CORRUPT_MAINTENANCE_STATE") from None
        if (not isinstance(state, dict) or state.get("status") not in
                {"QUEUED", "RUNNING", "COMPLETED", "FAILED", "INTERRUPTED"}
                or state.get("action") not in _ACTIONS or
                not isinstance(state.get("id"), str) or
                not re.fullmatch(r"MAINT-[0-9a-f]{32}", state["id"])):
            raise MaintenanceError("CORRUPT_MAINTENANCE_STATE")
        return state

    def _write(self, state: dict[str, object]) -> None:
        path = self.state_path
        parent = path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or path.is_symlink():
            raise MaintenanceError("UNSAFE_MAINTENANCE_STATE")
        fd, temporary = tempfile.mkstemp(prefix=".maintenance-", dir=parent)
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

    def status(self) -> dict[str, object]:
        with self._lock:
            return dict(self._current)

    def start(self, action: str, *, backup_id: str | None = None,
              review_id: str | None = None,
              confirmed: bool = False, target_id: str | None = None,
              identity_id: str | None = None,
              session_id: str | None = None) -> dict[str, object]:
        if action not in _ACTIONS:
            raise MaintenanceError("INVALID_MAINTENANCE_ACTION")
        if action == "BACKUP_VERIFY" and (
                not isinstance(backup_id, str) or not _BACKUP_ID.fullmatch(backup_id)):
            raise MaintenanceError("INVALID_BACKUP_ID")
        if action != "BACKUP_VERIFY" and backup_id is not None:
            raise MaintenanceError("INVALID_BACKUP_ID")
        if action in _RUN_ACTIONS and confirmed is not True:
            raise MaintenanceError("CONFIRMATION_REQUIRED")
        if action not in _RUN_ACTIONS and review_id is not None:
            raise MaintenanceError("INVALID_REVIEW_ID")
        if action in _RUN_ACTIONS and (
                not isinstance(review_id, str) or
                not re.fullmatch(r"MAINT-[0-9a-f]{32}", review_id)):
            raise MaintenanceError("INVALID_REVIEW_ID")
        if action in _DISABLED_PROFILE_ACTIONS | _NAMED_PROFILE_ACTIONS:
            if (not isinstance(target_id, str) or
                    not re.fullmatch(r"TARGET-[0-9a-f]{32}", target_id) or
                    not isinstance(identity_id, str) or
                    not re.fullmatch(r"IDENTITY-[0-9a-f]{32}", identity_id)):
                raise MaintenanceError("INVALID_PROFILE_IDENTITY")
        elif target_id is not None or identity_id is not None:
            raise MaintenanceError("INVALID_PROFILE_IDENTITY")
        if action in _NAMED_PROFILE_ACTIONS:
            if (not isinstance(session_id, str) or
                    not re.fullmatch(r"BSESSION-[0-9a-f]{32}", session_id)):
                raise MaintenanceError("INVALID_PROFILE_SESSION")
        elif session_id is not None:
            raise MaintenanceError("INVALID_PROFILE_SESSION")
        if (action in _DISABLED_PROFILE_ACTIONS | _NAMED_PROFILE_ACTIONS or
                action.startswith("PROFILE_")) and self.profiles is None:
            raise MaintenanceError("PROFILE_RETENTION_UNAVAILABLE")
        with self._lock:
            if self._current.get("reason_code") == "CORRUPT_MAINTENANCE_STATE":
                raise MaintenanceError("CORRUPT_MAINTENANCE_STATE")
            if self._current.get("status") in {"QUEUED", "RUNNING"}:
                raise MaintenanceError("MAINTENANCE_BUSY")
            approved_plan = None
            if action in _RUN_ACTIONS:
                if action == "RETENTION_RUN":
                    review = self._reviewed_retention
                    expected_action = "RETENTION_PLAN"
                elif action == "PROFILE_RUN":
                    review = self._reviewed_profiles
                    expected_action = "PROFILE_PLAN"
                elif action == "DISABLED_PROFILE_RUN":
                    review = self._reviewed_disabled_profiles
                    expected_action = "DISABLED_PROFILE_PLAN"
                else:
                    review = self._reviewed_named_profile
                    expected_action = "NAMED_PROFILE_PLAN"
                try:
                    finished = datetime.fromisoformat(self._current["finished_at"])
                    fresh = (finished.tzinfo is not None and
                             0 <= (datetime.now(timezone.utc) - finished).total_seconds() <= 900)
                except (KeyError, TypeError, ValueError):
                    fresh = False
                has_candidates = False
                if review is not None:
                    plan = review[1]
                    has_candidates = (bool(plan.digests or plan.temporary_files)
                                      if action == "RETENTION_RUN" else bool(plan.session_ids))
                    if action == "DISABLED_PROFILE_RUN":
                        has_candidates = (has_candidates and plan.target_id == target_id
                                          and plan.identity_id == identity_id)
                    elif action == "NAMED_PROFILE_RUN":
                        has_candidates = (has_candidates and plan.target_id == target_id
                                          and plan.identity_id == identity_id and
                                          plan.session_ids == (session_id,))
                if (review is None or not has_candidates or
                        self._current.get("status") != "COMPLETED" or
                        self._current.get("action") != expected_action or
                        self._current.get("id") != review_id or review[0] != review_id or
                        not fresh):
                    raise MaintenanceError("REVIEW_REQUIRED")
                approved_plan = review[1]
            state: dict[str, object] = {
                "id": "MAINT-" + uuid.uuid4().hex, "action": action,
                "status": "QUEUED", "created_at": _now(), "backup_id": backup_id,
                "target_id": target_id, "identity_id": identity_id,
                "session_id": session_id,
            }
            self._write(state)
            self._current = state
            if action == "RETENTION_RUN":
                self._reviewed_retention = None
            elif action == "PROFILE_RUN":
                self._reviewed_profiles = None
            elif action == "DISABLED_PROFILE_RUN":
                self._reviewed_disabled_profiles = None
            elif action == "NAMED_PROFILE_RUN":
                self._reviewed_named_profile = None
            worker = Thread(target=self._work, args=(state["id"], action, backup_id,
                                                     approved_plan, target_id, identity_id,
                                                     session_id),
                            daemon=True, name="bughunter-maintenance")
            self._thread = worker
            try:
                worker.start()
            except RuntimeError:
                failed = {**state, "status": "FAILED", "reason_code": "WORKER_UNAVAILABLE",
                          "finished_at": _now()}
                self._write(failed)
                self._current = failed
                raise MaintenanceError("WORKER_UNAVAILABLE") from None
            return dict(state)

    def _transition(self, task_id: str, status: str, **details: object) -> None:
        with self._lock:
            if self._current.get("id") != task_id:
                return
            state = {**self._current, "status": status, **details}
            if status == "RUNNING":
                state["started_at"] = _now()
            if status in {"COMPLETED", "FAILED"}:
                state["finished_at"] = _now()
            try:
                self._write(state)
            except Exception:
                self._current = {**self._current, "status": "INTERRUPTED",
                                 "reason_code": "PERSISTENCE_UNAVAILABLE", "finished_at": _now()}
                raise MaintenanceError("PERSISTENCE_UNAVAILABLE") from None
            self._current = state

    def _work(self, task_id: str, action: str, backup_id: str | None,
              approved_plan: CollectionPlan | ProfileRetentionPlan |
              DisabledProfileRetentionPlan | NamedProfileRetentionPlan | None,
              target_id: str | None, identity_id: str | None,
              session_id: str | None) -> None:
        try:
            self._transition(task_id, "RUNNING")
            if action == "BACKUP_CREATE":
                result = self.backup.create().to_dict()
            elif action == "BACKUP_VERIFY":
                assert backup_id is not None
                result = self.backup.verify(backup_id, record=True).to_dict()
            elif action == "RETENTION_PLAN":
                plan = self.retention.plan()
                with self._lock:
                    self._reviewed_retention = (task_id, plan)
                preview = ([f"sha256:{digest[:16]}..." for digest in plan.digests] +
                           [f"temporary:{name}" for name in plan.temporary_files])
                result = {"candidate_count": len(plan.digests) + len(plan.temporary_files),
                          "temporary_count": len(plan.temporary_files),
                          "estimated_bytes": plan.estimated_bytes,
                          "candidate_preview": preview[:20],
                          "preview_truncated": len(preview) > 20,
                          "truncated": plan.truncated}
            elif action == "RETENTION_RUN":
                result = self.retention.run(confirmed=True, approved_plan=approved_plan)
            elif action == "PROFILE_PLAN":
                assert self.profiles is not None
                plan = self.profiles.plan()
                with self._lock:
                    self._reviewed_profiles = (task_id, plan)
                result = {"candidate_count": len(plan.session_ids),
                          "estimated_bytes": plan.estimated_bytes,
                          "candidate_preview": [f"session:{value[:18]}..."
                                                for value in plan.session_ids[:20]],
                          "preview_truncated": len(plan.session_ids) > 20,
                          "truncated": plan.truncated}
            elif action == "PROFILE_RUN":
                assert self.profiles is not None
                result = self.profiles.run(confirmed=True, approved_plan=approved_plan)
            elif action == "DISABLED_PROFILE_PLAN":
                assert self.profiles is not None and target_id is not None and identity_id is not None
                plan = self.profiles.plan_disabled(target_id, identity_id)
                with self._lock:
                    self._reviewed_disabled_profiles = (task_id, plan)
                result = {"candidate_count": len(plan.session_ids),
                          "estimated_bytes": plan.estimated_bytes,
                          "candidate_preview": [f"session:{value[:18]}..."
                                                for value in plan.session_ids[:20]],
                          "preview_truncated": len(plan.session_ids) > 20,
                          "truncated": plan.truncated,
                          "target_id": target_id, "identity_id": identity_id}
            elif action == "DISABLED_PROFILE_RUN":
                assert self.profiles is not None and target_id is not None and identity_id is not None
                result = self.profiles.run_disabled(target_id, identity_id,
                                                    confirmed=True, approved_plan=approved_plan)
            elif action == "NAMED_PROFILE_PLAN":
                assert (self.profiles is not None and target_id is not None and
                        identity_id is not None and session_id is not None)
                plan = self.profiles.plan_named(target_id, identity_id, session_id)
                with self._lock:
                    self._reviewed_named_profile = (task_id, plan)
                result = {"candidate_count": len(plan.session_ids),
                          "estimated_bytes": plan.estimated_bytes,
                          "candidate_preview": [f"session:{value[:18]}..."
                                                for value in plan.session_ids],
                          "target_id": target_id, "identity_id": identity_id,
                          "session_id": session_id}
            else:
                assert (self.profiles is not None and target_id is not None and
                        identity_id is not None and session_id is not None)
                result = self.profiles.run_named(target_id, identity_id, session_id,
                                                 confirmed=True, approved_plan=approved_plan)
            self._transition(task_id, "COMPLETED", result=result)
        except Exception:
            reason = "BACKUP_FAILED" if action.startswith("BACKUP") else "RETENTION_FAILED"
            if self.status().get("reason_code") == "PERSISTENCE_UNAVAILABLE":
                return
            try:
                self._transition(task_id, "FAILED", reason_code=reason)
            except MaintenanceError:
                pass

    def wait_for_test(self, timeout: float = 10) -> None:
        worker = self._thread
        if worker is not None:
            worker.join(timeout=timeout)
