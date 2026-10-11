"""BugHunter-owned, secret-free plan-run state and audit persistence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import re
import sqlite3
import uuid

from .store import EvidenceFactStore


_RUN_ID = re.compile(r"RUN-[0-9a-f]{32}\Z")
_STEP_ID = re.compile(r"STEP-[0-9a-f]{32}\Z")
_PLAN_ID = re.compile(r"PLAN-[0-9a-f]{32}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_TERMINAL = frozenset({"COMPLETED", "BLOCKED", "REJECTED", "FAILED", "BUDGET_EXHAUSTED", "CANCELLED"})


class RunStatus(StrEnum):
    CREATED = "CREATED"
    CHECKING_PREREQUISITES = "CHECKING_PREREQUISITES"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    WAITING_HUMAN = "WAITING_HUMAN"
    BLOCKED = "BLOCKED"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    CANCELLED = "CANCELLED"


class RuntimeStepType(StrEnum):
    CHECK_PREREQUISITES = "CHECK_PREREQUISITES"
    PASSIVE_OBSERVATION = "PASSIVE_OBSERVATION"
    ESTABLISH_CONTROL = "ESTABLISH_CONTROL"
    EXECUTE_REQUEST = "EXECUTE_REQUEST"
    COMPARE_METADATA = "COMPARE_METADATA"
    WAIT_APPROVAL = "WAIT_APPROVAL"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class RuntimeStepStatus(StrEnum):
    PENDING = "PENDING"
    READY = "READY"
    WAITING_POLICY = "WAITING_POLICY"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class PlanSnapshot:
    data: dict[str, object]
    content_hash: str


@dataclass(frozen=True, slots=True)
class PlanRun:
    id: str
    plan_id: str
    target_id: str
    package_id: str
    hypothesis_id: str
    skill_id: str
    skill_version: str
    skill_hash: str
    snapshot_hash: str
    status: RunStatus
    request_budget: int
    requests_consumed: int
    token_budget: int
    current_step: int
    approval_id: str | None
    stop_reason: str | None
    pause_requested: bool
    cancel_requested: bool
    created_at: str
    started_at: str | None
    updated_at: str
    finished_at: str | None

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "plan_id": self.plan_id, "target_id": self.target_id,
                "package_id": self.package_id, "hypothesis_id": self.hypothesis_id,
                "skill_id": self.skill_id, "skill_version": self.skill_version,
                "skill_hash": self.skill_hash, "snapshot_hash": self.snapshot_hash,
                "status": self.status.value, "request_budget": self.request_budget,
                "requests_consumed": self.requests_consumed, "token_budget": self.token_budget,
                "current_step": self.current_step, "approval_id": self.approval_id,
                "stop_reason": self.stop_reason, "pause_requested": self.pause_requested,
                "cancel_requested": self.cancel_requested, "created_at": self.created_at,
                "started_at": self.started_at, "updated_at": self.updated_at,
                "finished_at": self.finished_at, "finding_status": "UNVALIDATED"}


@dataclass(frozen=True, slots=True)
class RuntimeStep:
    id: str
    run_id: str
    ordinal: int
    type: str
    source_step_index: int | None
    action_slot: int | None
    role: str
    control_step_id: str | None
    status: RuntimeStepStatus
    prerequisite_state: str | None
    action_id: str | None
    decision_id: str | None
    approval_id: str | None
    permit_id: str | None
    execution_id: str | None
    result_id: str | None
    safe_reason: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "ordinal": self.ordinal, "type": self.type,
                "source_step_index": self.source_step_index, "action_slot": self.action_slot,
                "role": self.role, "control_step_id": self.control_step_id,
                "status": self.status.value, "prerequisite_state": self.prerequisite_state,
                "action_id": self.action_id, "decision_id": self.decision_id,
                "approval_id": self.approval_id, "permit_id": self.permit_id,
                "execution_id": self.execution_id, "result_id": self.result_id,
                "safe_reason": self.safe_reason, "created_at": self.created_at,
                "started_at": self.started_at, "finished_at": self.finished_at}


@dataclass(frozen=True, slots=True)
class StepResult:
    id: str
    step_id: str
    execution_id: str | None
    exchange_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    status_code: int | None
    response_hash: str | None
    artifact_hash: str | None
    duration_ms: int | None
    error_class: str | None
    safe_summary: str
    created_at: str

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "step_id": self.step_id, "execution_id": self.execution_id,
                "traffic_exchange_ids": list(self.exchange_ids), "evidence_ids": list(self.evidence_ids),
                "status_code": self.status_code, "response_hash": self.response_hash,
                "artifact_hash": self.artifact_hash, "duration_ms": self.duration_ms,
                "error_class": self.error_class, "safe_summary": self.safe_summary,
                "created_at": self.created_at}


class PlanRunStore:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    @staticmethod
    def _event(db: sqlite3.Connection, run_id: str, step_id: str | None,
               event: str, reason: str) -> None:
        if not _CODE.fullmatch(event) or not _CODE.fullmatch(reason):
            raise ValueError("invalid plan audit code")
        db.execute("INSERT INTO plan_run_events(run_id,step_id,event_type,reason_code,occurred_at) "
                   "VALUES (?,?,?,?,?)", (run_id, step_id, event, reason, _now()))

    @staticmethod
    def _run(row: sqlite3.Row) -> PlanRun:
        return PlanRun(row["run_id"], row["plan_id"], row["target_id"], row["package_id"],
                       row["hypothesis_id"], row["skill_id"], row["skill_version"],
                       row["skill_hash"], row["snapshot_hash"], RunStatus(row["status"]),
                       row["request_budget"], row["requests_consumed"], row["token_budget"],
                       row["current_step"], row["approval_id"], row["stop_reason"],
                       bool(row["pause_requested"]), bool(row["cancel_requested"]),
                       row["created_at"], row["started_at"], row["updated_at"], row["finished_at"])

    @staticmethod
    def _step(row: sqlite3.Row) -> RuntimeStep:
        return RuntimeStep(row["step_id"], row["run_id"], row["ordinal"], row["step_type"],
                           row["source_step_index"], row["action_slot"], row["role"],
                           row["control_step_id"], RuntimeStepStatus(row["status"]),
                           row["prerequisite_state"], row["action_id"], row["decision_id"],
                           row["approval_id"], row["permit_id"], row["execution_id"],
                           row["result_id"], row["safe_reason"], row["created_at"],
                           row["started_at"], row["finished_at"])

    @staticmethod
    def _result(row: sqlite3.Row) -> StepResult:
        return StepResult(row["result_id"], row["step_id"], row["execution_id"],
                          tuple(json.loads(row["exchange_ids_json"])),
                          tuple(json.loads(row["evidence_ids_json"])), row["status_code"],
                          row["response_hash"], row["artifact_hash"], row["duration_ms"],
                          row["error_class"], row["safe_summary"], row["created_at"])

    def snapshot(self, plan_id: str, target_id: str) -> PlanSnapshot:
        if not isinstance(plan_id, str) or not _PLAN_ID.fullmatch(plan_id):
            raise ValueError("invalid plan ID")
        with self.store._connection() as db:
            row = db.execute("SELECT plan_json,target_id,skill_hash,skill_id,skill_version,hypothesis_id "
                             "FROM skill_plans WHERE plan_id=? AND target_id=?",
                             (plan_id, target_id)).fetchone()
        if row is None:
            raise LookupError("plan not found")
        raw = row["plan_json"]
        data = json.loads(raw)
        if (not isinstance(data, dict) or data.get("id") != plan_id or
                data.get("target_id") != target_id or
                any(data.get(name) != row[name] for name in
                    ("skill_hash", "skill_id", "skill_version", "hypothesis_id")) or
                not re.fullmatch(r"[0-9a-f]{64}", row["skill_hash"])):
            raise ValueError("plan snapshot integrity failure")
        return PlanSnapshot(data, hashlib.sha256(raw.encode()).hexdigest())

    def create(self, snapshot: PlanSnapshot, package_id: str,
               steps: tuple[dict[str, object], ...], *, rerun: bool = False) -> PlanRun:
        if not steps or len(steps) > 21:
            raise ValueError("invalid bounded run steps")
        plan = snapshot.data
        plan_id, target_id = str(plan["id"]), str(plan["target_id"])
        now = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM plan_runs WHERE plan_id=? "
                                  "ORDER BY created_at DESC,run_id DESC LIMIT 1", (plan_id,)).fetchone()
            if existing is not None:
                if existing["package_id"] != package_id or existing["target_id"] != target_id:
                    raise ValueError("plan run package mismatch")
                if existing["status"] not in _TERMINAL or not rerun:
                    return self._run(existing)
            run_id = "RUN-" + uuid.uuid4().hex
            db.execute("INSERT INTO plan_runs(run_id,plan_id,target_id,package_id,hypothesis_id,"
                       "skill_id,skill_version,skill_hash,snapshot_hash,status,request_budget,"
                       "token_budget,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (run_id, plan_id, target_id, package_id, plan["hypothesis_id"],
                        plan["skill_id"], plan["skill_version"], plan["skill_hash"],
                        snapshot.content_hash, RunStatus.CREATED.value,
                        plan["request_budget"], plan["token_budget"], now, now))
            for ordinal, item in enumerate(steps):
                db.execute("INSERT INTO plan_run_steps(step_id,run_id,ordinal,step_type,"
                           "source_step_index,action_slot,role,control_step_id,status,action_id,"
                           "created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                           (item["id"], run_id, ordinal, item["type"], item.get("source_step_index"),
                            item.get("action_slot"), item.get("role", "OTHER"), item.get("control_step_id"),
                            RuntimeStepStatus.PENDING.value, item.get("action_id"), now))
            self._event(db, run_id, None, "RUN_CREATED", "PLAN_SELECTED")
            db.execute("UPDATE plan_run_steps SET status='READY' WHERE run_id=? AND ordinal=0",
                       (run_id,))
            self._event(db, run_id, steps[0]["id"], "STEP_READY", "ORDERED_NEXT")
            row = db.execute("SELECT * FROM plan_runs WHERE run_id=?", (run_id,)).fetchone()
        return self._run(row)

    def get(self, run_id: str, target_id: str) -> PlanRun | None:
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise ValueError("invalid run ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM plan_runs WHERE run_id=? AND target_id=?",
                             (run_id, target_id)).fetchone()
        return self._run(row) if row else None

    def steps(self, run_id: str) -> tuple[RuntimeStep, ...]:
        with self.store._connection() as db:
            rows = db.execute("SELECT * FROM plan_run_steps WHERE run_id=? ORDER BY ordinal LIMIT 32",
                              (run_id,)).fetchall()
        return tuple(self._step(row) for row in rows)

    def current_step(self, run: PlanRun) -> RuntimeStep | None:
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM plan_run_steps WHERE run_id=? AND ordinal=?",
                             (run.id, run.current_step)).fetchone()
        return self._step(row) if row else None

    def result(self, step_id: str) -> StepResult | None:
        if not isinstance(step_id, str) or not _STEP_ID.fullmatch(step_id):
            raise ValueError("invalid step ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM plan_step_results WHERE step_id=?", (step_id,)).fetchone()
        return self._result(row) if row else None

    def details(self, run: PlanRun) -> dict[str, object]:
        with self.store._connection() as db:
            step_rows = db.execute("SELECT * FROM plan_run_steps WHERE run_id=? ORDER BY ordinal LIMIT 32",
                                   (run.id,)).fetchall()
            result_rows = db.execute("SELECT * FROM plan_step_results WHERE step_id IN "
                                     "(SELECT step_id FROM plan_run_steps WHERE run_id=?)",
                                     (run.id,)).fetchall()
            manual_rows = db.execute("SELECT * FROM plan_step_manual_links WHERE step_id IN "
                                     "(SELECT step_id FROM plan_run_steps WHERE run_id=?)",
                                     (run.id,)).fetchall()
            events = db.execute("SELECT event_id,step_id,event_type,reason_code,occurred_at "
                                "FROM plan_run_events WHERE run_id=? ORDER BY event_id DESC LIMIT 100",
                                (run.id,)).fetchall()
        results = {row["step_id"]: self._result(row).to_dict() for row in result_rows}
        manual = {row["step_id"]: {"evidence_ids": json.loads(row["evidence_ids_json"]),
                                   "traffic_exchange_ids": json.loads(row["exchange_ids_json"]),
                                   "linked_at": row["linked_at"]} for row in manual_rows}
        return {"run": run.to_dict(),
                "steps": [{**self._step(row).to_dict(), "result": results.get(row["step_id"]),
                           "manual_review": manual.get(row["step_id"])}
                          for row in step_rows],
                "timeline": [dict(row) for row in reversed(events)]}

    def list(self, target_id: str, *, limit: int = 20, cursor: str | None = None) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("invalid run page size")
        if cursor is not None and (not cursor.isdecimal() or int(cursor) < 1):
            raise ValueError("invalid run cursor")
        marker = int(cursor) if cursor else None
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT rowid AS cursor_id,* FROM plan_runs WHERE target_id=? AND (? IS NULL OR rowid<?) "
                "ORDER BY rowid DESC LIMIT ?", (target_id, marker, marker, limit + 1)).fetchall()
        return {"items": [self._run(row).to_dict() for row in rows[:limit]],
                "next_cursor": str(rows[limit - 1]["cursor_id"]) if len(rows) > limit else None}

    def list_for_plan(self, plan_id: str, target_id: str, *, limit: int = 20,
                      cursor: str | None = None) -> dict[str, object]:
        if not isinstance(plan_id, str) or not _PLAN_ID.fullmatch(plan_id):
            raise ValueError("invalid plan ID")
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("invalid run page size")
        if cursor is not None and (not cursor.isdecimal() or int(cursor) < 1):
            raise ValueError("invalid run cursor")
        marker = int(cursor) if cursor else None
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT rowid AS cursor_id,* FROM plan_runs WHERE target_id=? AND plan_id=? "
                "AND (? IS NULL OR rowid<?) ORDER BY rowid DESC LIMIT ?",
                (target_id, plan_id, marker, marker, limit + 1)).fetchall()
        return {"items": [self._run(row).to_dict() for row in rows[:limit]],
                "next_cursor": str(rows[limit - 1]["cursor_id"]) if len(rows) > limit else None}

    def stats(self, target_id: str | None = None) -> dict[str, int]:
        with self.store._connection() as db:
            where = " WHERE target_id=?" if target_id else ""
            args = (target_id,) if target_id else ()
            rows = db.execute("SELECT status,count(*) AS count FROM plan_runs" + where +
                              " GROUP BY status", args).fetchall()
            consumed = db.execute("SELECT COALESCE(sum(requests_consumed),0) FROM plan_runs" + where,
                                  args).fetchone()[0]
            timing = db.execute(
                "SELECT COALESCE(sum(s.duration_ms),0) AS duration_ms,"
                "count(CASE WHEN s.error_class IS NOT NULL THEN 1 END) AS failures "
                "FROM plan_step_results s JOIN plan_run_steps p ON p.step_id=s.step_id "
                "JOIN plan_runs r ON r.run_id=p.run_id" +
                (" WHERE r.target_id=?" if target_id else ""), args).fetchone()
        counts = {row["status"]: row["count"] for row in rows}
        return {"runs": sum(counts.values()), "completed": counts.get("COMPLETED", 0),
                "blocked": counts.get("BLOCKED", 0),
                "approval_waits": counts.get("WAITING_APPROVAL", 0),
                "execution_failures": timing["failures"],
                "execution_duration_ms": timing["duration_ms"],
                "requests_consumed": consumed, "active": sum(counts.get(name, 0) for name in
                                                       ("CREATED", "READY", "RUNNING"))}

    def approval_run(self, approval_id: str, target_id: str) -> dict[str, str] | None:
        with self.store._connection() as db:
            row = db.execute("SELECT s.run_id,s.step_id FROM plan_run_steps s JOIN plan_runs r "
                             "ON r.run_id=s.run_id WHERE s.approval_id=? AND r.target_id=? "
                             "ORDER BY r.created_at DESC LIMIT 1", (approval_id, target_id)).fetchone()
        return dict(row) if row else None

    def approval_decision(self, approval_id: str, target_id: str, *, granted: bool) -> None:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT s.run_id,s.step_id FROM plan_run_steps s JOIN plan_runs r "
                             "ON r.run_id=s.run_id WHERE s.approval_id=? AND r.target_id=? "
                             "ORDER BY r.created_at DESC LIMIT 1", (approval_id, target_id)).fetchone()
            if row is not None:
                self._event(db, row["run_id"], row["step_id"],
                            "APPROVAL_GRANTED" if granted else "APPROVAL_REJECTED",
                            "OPERATOR_DECISION")

    def claim(self, run: PlanRun, step: RuntimeStep) -> bool:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT status,current_step FROM plan_runs WHERE run_id=?",
                                 (run.id,)).fetchone()
            if (current is None or current["status"] not in {"CREATED", "READY"} or
                    current["current_step"] != step.ordinal or
                    db.execute("SELECT 1 FROM plan_runs WHERE status='RUNNING' AND run_id<>? LIMIT 1",
                               (run.id,)).fetchone() is not None):
                return False
            changed = db.execute("UPDATE plan_run_steps SET status='EXECUTING',started_at=COALESCE(started_at,?) "
                                 "WHERE step_id=? AND status IN ('PENDING','READY','WAITING_APPROVAL')",
                                 (_now(), step.id)).rowcount
            if changed != 1:
                return False
            now = _now()
            db.execute("UPDATE plan_runs SET status='RUNNING',started_at=COALESCE(started_at,?),"
                       "updated_at=? WHERE run_id=?", (now, now, run.id))
            self._event(db, run.id, step.id, "STEP_STARTED", "ONE_STEP_CLAIMED")
            return True

    def should_dispatch(self, run_id: str) -> bool:
        with self.store._connection() as db:
            row = db.execute("SELECT status,pause_requested,cancel_requested FROM plan_runs "
                             "WHERE run_id=?", (run_id,)).fetchone()
        return bool(row and row["status"] == "RUNNING" and
                    not row["pause_requested"] and not row["cancel_requested"])

    def account_dispatch(self, run_id: str, step_id: str, exchange_id: str) -> bool:
        if not isinstance(exchange_id, str) or not re.fullmatch(r"EXCHANGE-[0-9a-f]{32}", exchange_id):
            raise ValueError("invalid traffic exchange reference")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status,current_step,requests_consumed,request_budget,"
                             "pause_requested,cancel_requested FROM plan_runs WHERE run_id=?",
                             (run_id,)).fetchone()
            step = db.execute("SELECT ordinal,status FROM plan_run_steps WHERE step_id=? AND run_id=?",
                              (step_id, run_id)).fetchone()
            if (row is None or step is None or row["status"] != "RUNNING" or
                    step["status"] != "EXECUTING" or step["ordinal"] != row["current_step"] or
                    row["requests_consumed"] >= row["request_budget"]):
                return False
            db.execute("UPDATE plan_runs SET requests_consumed=requests_consumed+1,updated_at=? "
                       "WHERE run_id=?", (_now(), run_id))
            self._event(db, run_id, step_id, "DISPATCH_ACCOUNTED", "BUDGET_RESERVED")
            return not row["pause_requested"] and not row["cancel_requested"]

    def policy(self, run_id: str, step_id: str, decision_id: str,
               approval_id: str | None, reason: str) -> None:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE plan_run_steps SET decision_id=?,approval_id=? WHERE step_id=? AND run_id=? "
                       "AND status='EXECUTING'", (decision_id, approval_id, step_id, run_id))
            self._event(db, run_id, step_id, "POLICY_EVALUATED", reason)

    def permit(self, run_id: str, step_id: str, permit_id: str, execution_id: str) -> None:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("UPDATE plan_run_steps SET permit_id=?,execution_id=? "
                                 "WHERE step_id=? AND run_id=? AND status='EXECUTING'",
                                 (permit_id, execution_id, step_id, run_id)).rowcount
            if changed != 1:
                raise RuntimeError("step is no longer claimed")
            self._event(db, run_id, step_id, "PERMIT_ISSUED", "ONE_USE")
            self._event(db, run_id, step_id, "EXECUTION_STARTED", "DISPATCH_INTENT")

    def finish(self, run_id: str, step_id: str, *, step_status: RuntimeStepStatus,
               run_status: RunStatus, reason: str, consumed: int = 0,
               result: StepResult | None = None, approval_id: str | None = None,
               prerequisite_state: str | None = None, advance: bool = False) -> PlanRun:
        if not _CODE.fullmatch(reason) or consumed < 0:
            raise ValueError("invalid safe step result")
        now = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM plan_runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None or row["status"] != "RUNNING":
                raise RuntimeError("run is not executing")
            step = db.execute("SELECT * FROM plan_run_steps WHERE step_id=? AND run_id=?",
                              (step_id, run_id)).fetchone()
            if step is None or step["status"] != "EXECUTING" or step["ordinal"] != row["current_step"]:
                raise RuntimeError("step is not executing")
            accounted = db.execute("SELECT count(*) FROM plan_run_events WHERE run_id=? AND step_id=? "
                                   "AND event_type='DISPATCH_ACCOUNTED'", (run_id, step_id)).fetchone()[0]
            total = row["requests_consumed"]
            if consumed != accounted:
                raise RuntimeError("dispatch accounting requires reconciliation")
            if total > row["request_budget"]:
                raise RuntimeError("request budget exceeded")
            final_status = (RunStatus.CANCELLED if row["cancel_requested"] else
                            RunStatus.PAUSED if row["pause_requested"] and run_status in
                            {RunStatus.READY, RunStatus.WAITING_APPROVAL} else run_status)
            next_step = row["current_step"] + int(advance)
            end = now if final_status.value in _TERMINAL else None
            db.execute("UPDATE plan_run_steps SET status=?,prerequisite_state=COALESCE(?,prerequisite_state),"
                       "approval_id=COALESCE(?,approval_id),execution_id=COALESCE(?,execution_id),"
                       "result_id=COALESCE(?,result_id),safe_reason=?,finished_at=? WHERE step_id=?",
                       (step_status.value, prerequisite_state, approval_id,
                        result.execution_id if result else None, result.id if result else None,
                        reason, now if step_status in {RuntimeStepStatus.COMPLETED, RuntimeStepStatus.FAILED,
                                                        RuntimeStepStatus.BLOCKED} else None, step_id))
            if result is not None:
                db.execute("INSERT INTO plan_step_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                           (result.id, result.step_id, result.execution_id,
                            json.dumps(result.exchange_ids), json.dumps(result.evidence_ids),
                            result.status_code, result.response_hash, result.artifact_hash,
                            result.duration_ms, result.error_class, result.safe_summary, result.created_at))
                if result.execution_id is not None:
                    self._event(db, run_id, step_id, "EXECUTION_FINISHED", reason)
            if advance and final_status in {RunStatus.READY, RunStatus.PAUSED}:
                next_row = db.execute("SELECT step_id FROM plan_run_steps WHERE run_id=? AND ordinal=?",
                                      (run_id, next_step)).fetchone()
                if next_row is not None:
                    db.execute("UPDATE plan_run_steps SET status='READY' WHERE step_id=? "
                               "AND status='PENDING'", (next_row["step_id"],))
                    self._event(db, run_id, next_row["step_id"], "STEP_READY", "ORDERED_NEXT")
            db.execute("UPDATE plan_runs SET status=?,current_step=?,requests_consumed=?,approval_id=?,"
                       "stop_reason=?,updated_at=?,finished_at=?,pause_requested=0,cancel_requested=0 "
                       "WHERE run_id=?", (final_status.value, next_step, total, approval_id,
                                         reason if final_status.value in _TERMINAL else None,
                                         now, end, run_id))
            self._event(db, run_id, step_id, "STEP_FINISHED", reason)
            if final_status is RunStatus.WAITING_APPROVAL:
                self._event(db, run_id, step_id, "APPROVAL_REQUESTED", reason)
            self._event(db, run_id, step_id, "RUN_" + final_status.value, reason)
            updated = db.execute("SELECT * FROM plan_runs WHERE run_id=?", (run_id,)).fetchone()
        return self._run(updated)

    def transition(self, run_id: str, target_id: str, status: RunStatus, reason: str,
                   *, expected: frozenset[RunStatus]) -> PlanRun:
        if not _CODE.fullmatch(reason):
            raise ValueError("invalid run reason")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM plan_runs WHERE run_id=? AND target_id=?",
                             (run_id, target_id)).fetchone()
            if row is None:
                raise LookupError("run not found")
            if RunStatus(row["status"]) not in expected:
                raise ValueError("invalid run state transition")
            now = _now()
            db.execute("UPDATE plan_runs SET status=?,updated_at=?,finished_at=?,stop_reason=? "
                       "WHERE run_id=?", (status.value, now, now if status.value in _TERMINAL else None,
                                         reason if status.value in _TERMINAL else None, run_id))
            self._event(db, run_id, None, "RUN_" + status.value, reason)
            updated = db.execute("SELECT * FROM plan_runs WHERE run_id=?", (run_id,)).fetchone()
        return self._run(updated)

    def request_stop(self, run_id: str, target_id: str, *, cancel: bool) -> PlanRun:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM plan_runs WHERE run_id=? AND target_id=?",
                             (run_id, target_id)).fetchone()
            if row is None:
                raise LookupError("run not found")
            if row["status"] in _TERMINAL:
                return self._run(row)
            if not cancel and row["status"] == "WAITING_HUMAN":
                raise ValueError("manual-review step cannot be paused")
            if not cancel and row["status"] == "PAUSED":
                return self._run(row)
            now = _now()
            if row["status"] == "RUNNING":
                db.execute("UPDATE plan_runs SET " + ("cancel_requested=1" if cancel else "pause_requested=1") +
                           ",updated_at=? WHERE run_id=?", (now, run_id))
                reason = "AFTER_ACTIVE_STEP"
            else:
                state = RunStatus.CANCELLED if cancel else RunStatus.PAUSED
                db.execute("UPDATE plan_runs SET status=?,updated_at=?,finished_at=?,stop_reason=? "
                           "WHERE run_id=?", (state.value, now, now if cancel else None,
                                             "OPERATOR_CANCELLED" if cancel else None, run_id))
                reason = "OPERATOR_CANCELLED" if cancel else "OPERATOR_PAUSED"
            self._event(db, run_id, None, "RUN_CANCEL_REQUESTED" if cancel else "RUN_PAUSE_REQUESTED", reason)
            updated = db.execute("SELECT * FROM plan_runs WHERE run_id=?", (run_id,)).fetchone()
        return self._run(updated)

    def manual_complete(self, run: PlanRun, step: RuntimeStep, result: StepResult) -> PlanRun:
        now = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT status,current_step FROM plan_runs WHERE run_id=?", (run.id,)).fetchone()
            if (current is None or current["status"] != "WAITING_HUMAN" or
                    current["current_step"] != step.ordinal):
                raise ValueError("run is not waiting for this step")
            existing = db.execute("SELECT result_id,evidence_ids_json,exchange_ids_json "
                                  "FROM plan_step_results WHERE step_id=?",
                                  (step.id,)).fetchone()
            if existing is not None:
                old_evidence = set(json.loads(existing["evidence_ids_json"]))
                old_exchanges = set(json.loads(existing["exchange_ids_json"]))
                if (set(result.evidence_ids) <= old_evidence and
                        set(result.exchange_ids) <= old_exchanges):
                    raise ValueError("manual review must add independent evidence")
            result_id = existing["result_id"] if existing else result.id
            changed = db.execute("UPDATE plan_run_steps SET status='COMPLETED',result_id=?,"
                                 "safe_reason='OPERATOR_EVIDENCE',finished_at=? WHERE step_id=? "
                                 "AND status IN ('BLOCKED','FAILED')",
                                 (result_id, now, step.id)).rowcount
            if changed != 1:
                raise ValueError("step is not awaiting human evidence")
            if existing is None:
                db.execute("INSERT INTO plan_step_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                           (result.id, step.id, None, json.dumps(result.exchange_ids),
                            json.dumps(result.evidence_ids), result.status_code, result.response_hash,
                            result.artifact_hash, result.duration_ms, result.error_class,
                            result.safe_summary, result.created_at))
            db.execute("INSERT INTO plan_step_manual_links VALUES (?,?,?,?)",
                       (step.id, json.dumps(result.evidence_ids), json.dumps(result.exchange_ids), now))
            following = db.execute("SELECT 1 FROM plan_run_steps WHERE run_id=? AND ordinal>? LIMIT 1",
                                   (run.id, step.ordinal)).fetchone()
            status = RunStatus.READY if following else RunStatus.COMPLETED
            if following:
                next_row = db.execute("SELECT step_id FROM plan_run_steps WHERE run_id=? AND ordinal=?",
                                      (run.id, step.ordinal + 1)).fetchone()
                assert next_row is not None
                db.execute("UPDATE plan_run_steps SET status='READY' WHERE step_id=? AND status='PENDING'",
                           (next_row["step_id"],))
                self._event(db, run.id, next_row["step_id"], "STEP_READY", "ORDERED_NEXT")
            db.execute("UPDATE plan_runs SET status=?,current_step=?,updated_at=?,finished_at=? "
                       "WHERE run_id=?", (status.value, step.ordinal + 1, now,
                                         now if status is RunStatus.COMPLETED else None, run.id))
            self._event(db, run.id, step.id, "HUMAN_STEP_COMPLETED", "OPERATOR_EVIDENCE")
            if status is RunStatus.COMPLETED:
                self._event(db, run.id, step.id, "RUN_COMPLETED", "OPERATOR_EVIDENCE")
            updated = db.execute("SELECT * FROM plan_runs WHERE run_id=?", (run.id,)).fetchone()
        return self._run(updated)

    def reconcile(self) -> int:
        """No automatic replay after a stale dispatch, even if no exchange was retained."""
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT run_id,current_step,request_budget,requests_consumed FROM plan_runs "
                              "WHERE status='RUNNING' LIMIT 100").fetchall()
            for row in rows:
                step = db.execute("SELECT * FROM plan_run_steps WHERE run_id=? AND ordinal=?",
                                  (row["run_id"], row["current_step"])).fetchone()
                if step is None:
                    db.execute("UPDATE plan_runs SET status='BLOCKED',stop_reason='MISSING_ACTIVE_STEP',"
                               "finished_at=?,updated_at=? WHERE run_id=?", (_now(), _now(), row["run_id"]))
                    continue
                exchange_rows = []
                if step["execution_id"]:
                    ref_hash = hashlib.sha256(step["execution_id"].encode()).hexdigest()
                    exchange_rows = db.execute(
                        "SELECT e.exchange_id,e.state,q.observation_evidence_id AS request_evidence,"
                        "q.body_evidence_id AS request_body_evidence,p.observation_evidence_id AS response_evidence,"
                        "p.body_evidence_id AS response_body_evidence,p.status_code,p.body_hash,"
                        "p.artifact_hash,p.elapsed_ms FROM traffic_exchanges e "
                        "JOIN traffic_requests q ON q.request_id=e.request_id "
                        "LEFT JOIN traffic_responses p ON p.request_id=q.request_id "
                        "WHERE e.target_id=(SELECT target_id FROM plan_runs WHERE run_id=?) "
                        "AND e.correlation_hash=? ORDER BY e.created_at,e.exchange_id LIMIT 20",
                        (row["run_id"], ref_hash)).fetchall()
                accounted = db.execute("SELECT count(*) FROM plan_run_events WHERE run_id=? AND step_id=? "
                                       "AND event_type='DISPATCH_ACCOUNTED'",
                                       (row["run_id"], step["step_id"])).fetchone()[0]
                # The exchange may have committed before its budget event on a crash.
                conservative = max(len(exchange_rows), int(bool(step["permit_id"])))
                total = min(row["request_budget"], row["requests_consumed"] +
                            max(0, conservative - accounted))
                if step["result_id"] is None:
                    last = exchange_rows[-1] if exchange_rows else None
                    evidence_ids = tuple(dict.fromkeys(value for item in exchange_rows for value in
                                          (item["request_evidence"], item["request_body_evidence"],
                                           item["response_evidence"], item["response_body_evidence"])
                                          if value))[:16]
                    recovered = StepResult(
                        "RESULT-" + uuid.uuid4().hex, step["step_id"], step["execution_id"],
                        tuple(item["exchange_id"] for item in exchange_rows), evidence_ids,
                        last["status_code"] if last else None,
                        last["body_hash"] if last else None,
                        last["artifact_hash"] if last else None,
                        last["elapsed_ms"] if last else None,
                        "RECOVERY_REVIEW_REQUIRED", "Dispatch outcome requires operator review.", _now())
                    db.execute("INSERT INTO plan_step_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                               (recovered.id, recovered.step_id, recovered.execution_id,
                                json.dumps(recovered.exchange_ids), json.dumps(recovered.evidence_ids),
                                recovered.status_code, recovered.response_hash, recovered.artifact_hash,
                                recovered.duration_ms, recovered.error_class,
                                recovered.safe_summary, recovered.created_at))
                    db.execute("UPDATE plan_run_steps SET result_id=? WHERE step_id=?",
                               (recovered.id, step["step_id"]))
                db.execute("UPDATE plan_run_steps SET status='BLOCKED',safe_reason='RECOVERY_REVIEW_REQUIRED',"
                           "finished_at=? WHERE step_id=? AND status='EXECUTING'", (_now(), step["step_id"]))
                db.execute("UPDATE plan_runs SET status='WAITING_HUMAN',requests_consumed=?,"
                           "stop_reason='RECOVERY_REVIEW_REQUIRED',updated_at=? WHERE run_id=?",
                           (total, _now(), row["run_id"]))
                self._event(db, row["run_id"], step["step_id"], "RUN_RECOVERED", "NO_AUTOMATIC_REPLAY")
            return len(rows)
