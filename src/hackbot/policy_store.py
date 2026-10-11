"""Append-only BugHunter policy history and narrowly scoped approvals."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import re
import sqlite3
import uuid

from .policy_models import (
    ActionCategory, ActionDecision, ApprovalRequest, ApprovalStatus, ProposedAction,
)
from .store import EvidenceFactStore
from .target_policy import PolicyDecision, RiskLevel


_APPROVAL_ID = re.compile(r"APPROVAL-[0-9a-f]{32}\Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _row_to_approval(row: sqlite3.Row, *, now: datetime | None = None) -> ApprovalRequest:
    status = ApprovalStatus(row["status"])
    expiry = datetime.fromisoformat(row["expires_at"])
    if status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED_ONCE} and expiry <= (now or _now()):
        status = ApprovalStatus.EXPIRED
    return ApprovalRequest(
        id=row["approval_id"], decision_id=row["decision_id"], action_id=row["action_id"],
        target_id=row["target_id"], hypothesis_id=row["hypothesis_id"],
        identity_id=row["identity_id"], category=ActionCategory(row["category"]),
        risk=RiskLevel(row["risk"]), operation=row["operation"],
        object_type=row["object_type"], object_ref_hash=row["object_ref_hash"],
        action_fingerprint=row["action_fingerprint"], policy_version=row["policy_version"],
        reason_code=row["reason_code"], status=status,
        created_at=datetime.fromisoformat(row["created_at"]), expires_at=expiry,
        decided_at=datetime.fromisoformat(row["decided_at"]) if row["decided_at"] else None,
    )


class PolicyStore:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    @staticmethod
    def _event(db: sqlite3.Connection, target_id: str, action_id: str,
               decision_id: str | None, approval_id: str | None, event: str,
               reason: str, at: datetime) -> None:
        db.execute(
            "INSERT INTO policy_events(target_id,action_id,decision_id,approval_id,"
            "event_type,reason_code,occurred_at) VALUES (?,?,?,?,?,?,?)",
            (target_id, action_id, decision_id, approval_id, event, reason, at.isoformat()),
        )

    def record(self, action: ProposedAction, decision: ActionDecision) -> ActionDecision:
        if action.id != decision.action_id or action.target_id != decision.target_id:
            raise ValueError("Policy decision/action mismatch")
        fingerprint = action.fingerprint()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT fingerprint FROM policy_actions WHERE action_id=?", (action.id,),
            ).fetchone()
            if existing is not None and existing["fingerprint"] != fingerprint:
                raise ValueError("Action ID reused with different content")
            if existing is None:
                db.execute(
                    "INSERT INTO policy_actions(action_id,target_id,package_id,fingerprint,"
                    "category,actor,source,method,hypothesis_id,identity_id,session_id,"
                    "operation,vulnerability_class,object_type,object_ref_hash,created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (action.id, action.target_id, action.package_id, fingerprint,
                     action.category.value, action.actor.value, action.source, action.method,
                     action.hypothesis_id, action.identity_id, action.session_id,
                     action.operation, action.vulnerability_class, action.object_type, action.object_ref_hash,
                     action.created_at.isoformat()),
                )
                self._event(db, action.target_id, action.id, None, None,
                            "ACTION_PROPOSED", "ACTION_PROPOSED", decision.created_at)

            approval_id = decision.approval_id
            create_approval = False
            if decision.result is PolicyDecision.REQUIRE_APPROVAL:
                pending = db.execute(
                    "SELECT approval_id FROM policy_approvals WHERE action_id=? AND "
                    "action_fingerprint=? AND policy_version=? AND status='PENDING' "
                    "AND expires_at>? ORDER BY sequence DESC LIMIT 1",
                    (action.id, fingerprint, decision.policy_version, decision.created_at.isoformat()),
                ).fetchone()
                approval_id = pending["approval_id"] if pending else "APPROVAL-" + uuid.uuid4().hex
                create_approval = pending is None
            decision = replace(decision, approval_id=approval_id)
            db.execute(
                "INSERT INTO policy_decisions(decision_id,action_id,target_id,result,"
                "reason_code,scope_result,matched_scope_rule,matched_policy_rule,risk,"
                "side_effect,policy_version,approval_id,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (decision.id, action.id, action.target_id, decision.result.value,
                 decision.reason_code, decision.scope_result.value if decision.scope_result else None,
                 decision.matched_scope_rule, decision.matched_policy_rule,
                 decision.risk.value, decision.side_effect.value, decision.policy_version,
                 approval_id, decision.created_at.isoformat()),
            )
            self._event(db, action.target_id, action.id, decision.id, approval_id,
                        "SCOPE_EVALUATED", decision.scope_result.value if decision.scope_result else "LOCAL_PASSIVE",
                        decision.created_at)
            self._event(db, action.target_id, action.id, decision.id, approval_id,
                        "POLICY_DECIDED", decision.reason_code, decision.created_at)
            if create_approval:
                db.execute(
                    "INSERT INTO policy_approvals(approval_id,decision_id,action_id,target_id,"
                    "hypothesis_id,identity_id,category,risk,operation,object_type,"
                    "object_ref_hash,action_fingerprint,policy_version,reason_code,status,"
                    "created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (approval_id, decision.id, action.id, action.target_id,
                     action.hypothesis_id, action.identity_id, action.category.value,
                     decision.risk.value, action.operation, action.object_type,
                     action.object_ref_hash, fingerprint, decision.policy_version,
                     decision.reason_code, ApprovalStatus.PENDING.value,
                     decision.created_at.isoformat(),
                     (decision.created_at + timedelta(minutes=30)).isoformat()),
                )
                self._event(db, action.target_id, action.id, decision.id, approval_id,
                            "APPROVAL_REQUESTED", decision.reason_code, decision.created_at)
        return decision

    def get(self, approval_id: str, target_id: str, *, now: datetime | None = None) -> ApprovalRequest | None:
        if not _APPROVAL_ID.fullmatch(approval_id):
            raise ValueError("Invalid approval ID")
        with self.store._connection() as db:
            row = db.execute(
                "SELECT * FROM policy_approvals WHERE approval_id=? AND target_id=?",
                (approval_id, target_id),
            ).fetchone()
        return _row_to_approval(row, now=now) if row else None

    def list(self, target_id: str, *, limit: int = 20, cursor: str | None = None,
             now: datetime | None = None) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Invalid approval page size")
        if cursor is not None and (not cursor.isdecimal() or int(cursor) <= 0):
            raise ValueError("Invalid approval cursor")
        where = "target_id=?" + (" AND sequence<?" if cursor else "")
        args: list[object] = [target_id]
        if cursor:
            args.append(int(cursor))
        args.append(limit + 1)
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT * FROM policy_approvals WHERE " + where + " ORDER BY sequence DESC LIMIT ?",
                args,
            ).fetchall()
        items = [_row_to_approval(row, now=now).to_dict() for row in rows[:limit]]
        return {"items": items, "next_cursor": str(rows[limit-1]["sequence"]) if len(rows) > limit else None}

    def approved_for(self, action: ProposedAction, policy_version: str,
                     now: datetime) -> ApprovalRequest | None:
        with self.store._connection() as db:
            row = db.execute(
                "SELECT * FROM policy_approvals WHERE target_id=? AND action_id=? "
                "AND action_fingerprint=? AND policy_version=? AND status='APPROVED_ONCE' "
                "AND expires_at>? ORDER BY sequence DESC LIMIT 1",
                (action.target_id, action.id, action.fingerprint(), policy_version, now.isoformat()),
            ).fetchone()
        return _row_to_approval(row, now=now) if row else None

    def decide(self, approval_id: str, target_id: str, *,
               approve: bool, now: datetime | None = None) -> ApprovalRequest:
        if not _APPROVAL_ID.fullmatch(approval_id):
            raise ValueError("Invalid approval ID")
        current = now or _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM policy_approvals WHERE approval_id=? AND target_id=?",
                (approval_id, target_id),
            ).fetchone()
            if row is None:
                raise LookupError("Approval not found")
            existing = ApprovalStatus(row["status"])
            if existing in {ApprovalStatus.APPROVED_ONCE, ApprovalStatus.REJECTED,
                            ApprovalStatus.EXPIRED, ApprovalStatus.CONSUMED}:
                if (approve and existing is ApprovalStatus.APPROVED_ONCE) or (
                    not approve and existing is ApprovalStatus.REJECTED
                ):
                    return _row_to_approval(row, now=current)
                raise ValueError("Approval is already decided")
            expired = datetime.fromisoformat(row["expires_at"]) <= current
            status = (ApprovalStatus.EXPIRED if expired else
                      ApprovalStatus.APPROVED_ONCE if approve else ApprovalStatus.REJECTED)
            db.execute(
                "UPDATE policy_approvals SET status=?,decided_at=? WHERE approval_id=? AND status='PENDING'",
                (status.value, current.isoformat(), approval_id),
            )
            self._event(db, target_id, row["action_id"], row["decision_id"], approval_id,
                        {"EXPIRED": "APPROVAL_EXPIRED", "APPROVED_ONCE": "APPROVAL_APPROVED_ONCE",
                         "REJECTED": "APPROVAL_REJECTED"}[status.value],
                        status.value, current)
            updated = db.execute("SELECT * FROM policy_approvals WHERE approval_id=?",
                                 (approval_id,)).fetchone()
        return _row_to_approval(updated, now=current)

    def claim_once(self, action: ProposedAction, policy_version: str, approval_id: str,
                   *, now: datetime | None = None) -> bool:
        """Future permit issuer may atomically consume only an exact approval."""
        current = now or _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM policy_approvals WHERE approval_id=? AND target_id=? "
                "AND action_id=? AND action_fingerprint=? AND policy_version=? "
                "AND status='APPROVED_ONCE' AND expires_at>?",
                (approval_id, action.target_id, action.id, action.fingerprint(),
                 policy_version, current.isoformat()),
            ).fetchone()
            if row is None:
                return False
            db.execute("UPDATE policy_approvals SET status='CONSUMED' WHERE approval_id=?",
                       (approval_id,))
            self._event(db, action.target_id, action.id, row["decision_id"], approval_id,
                        "APPROVAL_CONSUMED", "APPROVED_ONCE", current)
            return True

    def history(self, target_id: str, action_id: str, *, limit: int = 30) -> list[dict[str, object]]:
        if not re.fullmatch(r"ACTION-[0-9a-f]{32}", action_id) or type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Invalid policy history request")
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT event_id,event_type,reason_code,occurred_at,decision_id,approval_id "
                "FROM policy_events WHERE target_id=? AND action_id=? ORDER BY event_id DESC LIMIT ?",
                (target_id, action_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]
