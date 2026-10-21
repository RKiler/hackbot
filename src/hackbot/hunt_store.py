"""Durable target-scoped hunt state; execution remains in existing components."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import re
import sqlite3

from .domain import new_entity_id, validate_entity_id
from .application_mapper import MappingResult
from .policy import policy_version
from .store import EvidenceFactStore
from .target_package import TargetPackage
from .test_objects import TestObject


class HuntMode(StrEnum):
    SUPERVISED = "SUPERVISED"
    RESEARCHER_AUTONOMOUS = "RESEARCHER_AUTONOMOUS"
    PLAN_ONLY = "PLAN_ONLY"
    ADVANCED = "ADVANCED"


class HuntState(StrEnum):
    PREPARING = "PREPARING"
    LOGIN_REQUIRED = "LOGIN_REQUIRED"
    READY = "READY"
    MAPPING = "MAPPING"
    HUNTING = "HUNTING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    WAITING_HUMAN = "WAITING_HUMAN"
    PAUSED_RESOURCE_PRESSURE = "PAUSED_RESOURCE_PRESSURE"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


_TRANSITIONS = {
    HuntState.PREPARING: {HuntState.LOGIN_REQUIRED, HuntState.READY,
                          HuntState.WAITING_HUMAN, HuntState.PAUSED_RESOURCE_PRESSURE,
                          HuntState.FAILED},
    HuntState.LOGIN_REQUIRED: {HuntState.PREPARING, HuntState.READY,
                               HuntState.WAITING_HUMAN,
                               HuntState.PAUSED_RESOURCE_PRESSURE,
                               HuntState.FAILED},
    HuntState.READY: {HuntState.PREPARING, HuntState.MAPPING, HuntState.HUNTING,
                      HuntState.LOGIN_REQUIRED, HuntState.WAITING_HUMAN,
                      HuntState.PAUSED_RESOURCE_PRESSURE, HuntState.FAILED},
    HuntState.MAPPING: {HuntState.PREPARING, HuntState.READY, HuntState.HUNTING, HuntState.LOGIN_REQUIRED,
                        HuntState.WAITING_HUMAN, HuntState.PAUSED_RESOURCE_PRESSURE,
                        HuntState.FAILED},
    HuntState.HUNTING: {HuntState.PREPARING, HuntState.LOGIN_REQUIRED, HuntState.WAITING_APPROVAL,
                        HuntState.WAITING_HUMAN, HuntState.PAUSED_RESOURCE_PRESSURE,
                        HuntState.COMPLETE, HuntState.FAILED},
    HuntState.WAITING_APPROVAL: {HuntState.HUNTING, HuntState.WAITING_HUMAN,
                                 HuntState.FAILED},
    HuntState.WAITING_HUMAN: {HuntState.PREPARING, HuntState.MAPPING,
                              HuntState.HUNTING, HuntState.FAILED},
    HuntState.PAUSED_RESOURCE_PRESSURE: {HuntState.PREPARING, HuntState.MAPPING,
                                         HuntState.HUNTING, HuntState.WAITING_HUMAN,
                                         HuntState.FAILED},
    HuntState.COMPLETE: set(),
    HuntState.FAILED: set(),
}
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_ACTOR = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class HuntRun:
    id: str
    target_id: str
    package_id: str
    package_version: int
    policy_hash: str
    mode: HuntMode
    state: HuntState
    reason_code: str | None
    campaign_id: str | None
    requested_by: str
    created_at: str
    updated_at: str
    finished_at: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id, "target_id": self.target_id,
            "package_id": self.package_id, "package_version": self.package_version,
            "policy_hash": self.policy_hash, "mode": self.mode.value,
            "state": self.state.value, "reason_code": self.reason_code,
            "campaign_id": self.campaign_id, "requested_by": self.requested_by,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "finished_at": self.finished_at,
        }


class HuntStore:
    """Transition ledger with one nonterminal hunt per registered target."""

    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    @staticmethod
    def _row(row: sqlite3.Row) -> HuntRun:
        return HuntRun(
            row["hunt_id"], row["target_id"], row["package_id"],
            row["package_version"], row["policy_hash"], HuntMode(row["mode"]),
            HuntState(row["state"]), row["reason_code"], row["campaign_id"],
            row["requested_by"], row["created_at"], row["updated_at"],
            row["finished_at"],
        )

    def create(self, package: TargetPackage, mode: HuntMode = HuntMode.SUPERVISED,
               *, requested_by: str = "operator") -> HuntRun:
        if (package.status.value != "TRACKED" or not isinstance(mode, HuntMode)
                or not isinstance(requested_by, str)
                or not _ACTOR.fullmatch(requested_by)):
            raise ValueError("Hunt requires a tracked target and valid operator")
        hunt_id, at = new_entity_id("HUNT"), _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            target = db.execute("SELECT package_id,deleted_at FROM registry_targets "
                                "WHERE target_id=?", (package.target.id,)).fetchone()
            if target is None or target["package_id"] != package.id or target["deleted_at"]:
                raise ValueError("Current registered TargetPackage is required")
            try:
                db.execute("INSERT INTO hunt_runs(hunt_id,target_id,package_id,"
                           "package_version,policy_hash,mode,state,requested_by,created_at,"
                           "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                           (hunt_id, package.target.id, package.id, package.version,
                            policy_version(package), mode.value, HuntState.PREPARING.value,
                            requested_by, at, at))
            except sqlite3.IntegrityError:
                raise ValueError("An active hunt already owns this target") from None
            db.execute("INSERT INTO hunt_events(hunt_id,from_state,to_state,reason_code,"
                       "occurred_at) VALUES (?,?,?,?,?)",
                       (hunt_id, None, HuntState.PREPARING.value, "OPERATOR_STARTED", at))
        result = self.get(package.target.id, hunt_id)
        assert result is not None
        return result

    def get(self, target_id: str, hunt_id: str) -> HuntRun | None:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(hunt_id, "HUNT")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM hunt_runs WHERE target_id=? AND hunt_id=?",
                             (target_id, hunt_id)).fetchone()
        return self._row(row) if row else None

    def current(self, target_id: str) -> HuntRun | None:
        validate_entity_id(target_id, "TARGET")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM hunt_runs WHERE target_id=? "
                             "ORDER BY created_at DESC,hunt_id DESC LIMIT 1",
                             (target_id,)).fetchone()
        return self._row(row) if row else None

    def for_campaign(self, target_id: str, campaign_id: str) -> HuntRun | None:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(campaign_id, "CMP")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM hunt_runs WHERE target_id=? AND campaign_id=?",
                             (target_id, campaign_id)).fetchone()
        return self._row(row) if row else None

    def active(self, *, after_hunt_id: str | None = None,
               limit: int = 100) -> tuple[HuntRun, ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid hunt page size")
        cursor = validate_entity_id(after_hunt_id, "HUNT") if after_hunt_id else ""
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT * FROM hunt_runs WHERE state NOT IN ('COMPLETE','FAILED') "
                "AND hunt_id>? ORDER BY hunt_id LIMIT ?", (cursor, limit)).fetchall()
        return tuple(self._row(row) for row in rows)

    def transition(self, target_id: str, hunt_id: str, state: HuntState,
                   reason_code: str) -> HuntRun:
        if not isinstance(state, HuntState) or not isinstance(reason_code, str) or not _CODE.fullmatch(reason_code):
            raise ValueError("Invalid hunt transition")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM hunt_runs WHERE target_id=? AND hunt_id=?",
                             (validate_entity_id(target_id, "TARGET"),
                              validate_entity_id(hunt_id, "HUNT"))).fetchone()
            if row is None:
                raise LookupError("Hunt not found")
            old = HuntState(row["state"])
            if state not in _TRANSITIONS[old]:
                raise ValueError("Invalid hunt state transition")
            at = _now()
            db.execute("UPDATE hunt_runs SET state=?,reason_code=?,updated_at=?,"
                       "finished_at=? WHERE hunt_id=?",
                       (state.value, reason_code, at,
                        at if state in {HuntState.COMPLETE, HuntState.FAILED} else None,
                        hunt_id))
            db.execute("INSERT INTO hunt_events(hunt_id,from_state,to_state,reason_code,"
                       "occurred_at) VALUES (?,?,?,?,?)",
                       (hunt_id, old.value, state.value, reason_code, at))
        result = self.get(target_id, hunt_id)
        assert result is not None
        return result

    def link_campaign(self, target_id: str, hunt_id: str, campaign_id: str) -> HuntRun:
        validate_entity_id(campaign_id, "CMP")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            hunt = db.execute("SELECT campaign_id,state,package_id,package_version,policy_hash "
                              "FROM hunt_runs WHERE target_id=? "
                              "AND hunt_id=?", (validate_entity_id(target_id, "TARGET"),
                                              validate_entity_id(hunt_id, "HUNT"))).fetchone()
            if hunt is None:
                raise LookupError("Hunt not found")
            if hunt["campaign_id"] is not None or hunt["state"] != HuntState.HUNTING.value:
                raise ValueError("Hunt cannot link a campaign")
            campaign = db.execute("SELECT target_id,package_id,package_version,policy_hash,status "
                                  "FROM campaigns WHERE campaign_id=?",
                                  (campaign_id,)).fetchone()
            if (campaign is None or campaign["target_id"] != target_id
                    or any(campaign[field] != hunt[field] for field in (
                        "package_id", "package_version", "policy_hash"))
                    or campaign["status"] in {"COMPLETED", "BLOCKED", "FAILED", "CANCELLED",
                                             "BUDGET_EXHAUSTED", "TIME_EXHAUSTED",
                                             "CLEANUP_REQUIRED"}):
                raise ValueError("Campaign does not match the current hunt")
            db.execute("UPDATE hunt_runs SET campaign_id=?,updated_at=? WHERE hunt_id=?",
                       (campaign_id, _now(), hunt_id))
            db.execute("INSERT INTO hunt_events(hunt_id,from_state,to_state,reason_code,"
                       "occurred_at) VALUES (?,?,?,?,?)",
                       (hunt_id, HuntState.HUNTING.value, HuntState.HUNTING.value,
                        "CAMPAIGN_LINKED", _now()))
        result = self.get(target_id, hunt_id)
        assert result is not None
        return result

    def events(self, target_id: str, hunt_id: str, *, limit: int = 100) -> tuple[dict[str, object], ...]:
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("Invalid hunt event limit")
        if self.get(target_id, hunt_id) is None:
            raise LookupError("Hunt not found")
        with self.store._connection() as db:
            rows = db.execute("SELECT event_id,from_state,to_state,reason_code,occurred_at "
                              "FROM hunt_events WHERE hunt_id=? ORDER BY event_id DESC LIMIT ?",
                              (hunt_id, limit)).fetchall()
        return tuple(dict(row) for row in rows)

    def mapping_sessions(self, target_id: str, hunt_id: str) -> tuple[dict[str, object], ...]:
        if self.get(target_id, hunt_id) is None:
            raise LookupError("Hunt not found")
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT browser_session_id,pages_attempted,pages_observed,links_discovered,"
                "js_references,forms_observed,evidence_count,blocked_count,completed_at "
                "FROM hunt_mapping_sessions WHERE target_id=? AND hunt_id=? "
                "ORDER BY completed_at,browser_session_id",
                (target_id, hunt_id)).fetchall()
        return tuple(dict(row) for row in rows)

    def fixtures(self, target_id: str, hunt_id: str) -> tuple[dict[str, str], ...]:
        if self.get(target_id, hunt_id) is None:
            raise LookupError("Hunt not found")
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT identity_id,tenant_id,object_type,test_object_id,created_at "
                "FROM hunt_fixtures WHERE target_id=? AND hunt_id=? "
                "ORDER BY created_at,test_object_id LIMIT 8",
                (target_id, hunt_id)).fetchall()
        return tuple(dict(row) for row in rows)

    def track_fixture(self, target_id: str, hunt_id: str, item: TestObject) -> bool:
        """Link a local creation intent before ObjectFactory can dispatch it."""
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(hunt_id, "HUNT")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            hunt = db.execute(
                "SELECT package_id,state FROM hunt_runs WHERE target_id=? AND hunt_id=?",
                (target_id, hunt_id)).fetchone()
            object_row = db.execute(
                "SELECT target_id,package_id,creator_identity_id,tenant_id,object_type,"
                "lifecycle,disposable,cleanup_strategy,parent_test_object_id "
                "FROM test_objects WHERE test_object_id=?",
                (item.id,)).fetchone()
            if (hunt is None or hunt["state"] != HuntState.READY.value or
                    object_row is None or object_row["target_id"] != target_id or
                    object_row["package_id"] != hunt["package_id"] or
                    object_row["creator_identity_id"] != item.creator_identity_id or
                    object_row["tenant_id"] != item.tenant_id or
                    object_row["object_type"] != item.object_type or
                    object_row["lifecycle"] != "PLANNED" or
                    object_row["disposable"] != 1 or
                    object_row["cleanup_strategy"] != "AUTO_CLEANUP" or
                    object_row["parent_test_object_id"] is not None):
                raise ValueError("Hunt fixture must be a current, disposable local intent")
            existing = db.execute(
                "SELECT test_object_id FROM hunt_fixtures WHERE hunt_id=? "
                "AND tenant_id=? AND object_type=?",
                (hunt_id, item.tenant_id, item.object_type)).fetchone()
            if existing is not None:
                return existing["test_object_id"] == item.id
            db.execute(
                "INSERT INTO hunt_fixtures(hunt_id,target_id,identity_id,tenant_id,"
                "object_type,test_object_id,created_at) VALUES (?,?,?,?,?,?,?)",
                (hunt_id, target_id, item.creator_identity_id, item.tenant_id,
                 item.object_type, item.id, _now()))
            db.execute(
                "INSERT INTO hunt_events(hunt_id,from_state,to_state,reason_code,occurred_at) "
                "VALUES (?,?,?,?,?)",
                (hunt_id, HuntState.READY.value, HuntState.READY.value,
                 "DISPOSABLE_FIXTURE_PLANNED", _now()))
        return True

    def record_mapping(self, target_id: str, hunt_id: str, result: MappingResult) -> None:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(hunt_id, "HUNT")
        validate_entity_id(result.session_id, "BSESSION")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            hunt = db.execute("SELECT state FROM hunt_runs WHERE target_id=? AND hunt_id=?",
                              (target_id, hunt_id)).fetchone()
            session = db.execute("SELECT target_id,identity_id FROM browser_sessions "
                                 "WHERE session_id=?", (result.session_id,)).fetchone()
            if hunt is None or hunt["state"] != HuntState.MAPPING.value:
                raise ValueError("Hunt is not mapping")
            if session is None or session["target_id"] != target_id or session["identity_id"] is None:
                raise ValueError("Mapped session does not belong to this target identity")
            db.execute("INSERT OR IGNORE INTO hunt_mapping_sessions(hunt_id,target_id,"
                       "browser_session_id,pages_attempted,pages_observed,links_discovered,"
                       "js_references,forms_observed,evidence_count,blocked_count,completed_at) "
                       "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (hunt_id, target_id, result.session_id, result.pages_attempted,
                        result.pages_observed, result.links_discovered,
                        result.js_references, result.forms_observed,
                        len(result.evidence_ids), len(result.blocked), _now()))
