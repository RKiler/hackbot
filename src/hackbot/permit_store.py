"""Persisted, one-use policy permits and secret-free execution audit."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
import sqlite3
import uuid

from .policy_models import ActionDecision, PolicyPermit, ProposedAction
from .store import EvidenceFactStore
from .target_policy import PolicyDecision


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


class PermitError(ValueError):
    """Execution was not authorized; no request should be sent."""


class PolicyPermitStore:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    def issue(self, action: ProposedAction, decision: ActionDecision,
              request_fingerprint: str, *, now: datetime | None = None,
              ttl_seconds: int = 30) -> PolicyPermit:
        current = now or datetime.now(timezone.utc)
        if (not isinstance(action, ProposedAction) or not isinstance(decision, ActionDecision)
                or not isinstance(request_fingerprint, str) or not _HASH.fullmatch(request_fingerprint)
                or type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 120
                or current.tzinfo is None or decision.result is not PolicyDecision.ALLOW
                or decision.action_id != action.id or decision.target_id != action.target_id):
            raise PermitError("Invalid policy authorization")
        permit = PolicyPermit(
            id="PERMIT-" + uuid.uuid4().hex, decision_id=decision.id,
            action_id=action.id, action_fingerprint=action.fingerprint(),
            request_fingerprint=request_fingerprint, target_id=action.target_id,
            package_id=action.package_id, category=action.category,
            identity_id=action.identity_id, policy_version=decision.policy_version,
            scope_rule=decision.matched_scope_rule, approval_id=decision.approval_id,
            expires_at=current + timedelta(seconds=ttl_seconds),
        )
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT a.fingerprint,a.package_id,a.category,a.identity_id,d.result,d.policy_version,"
                "d.approval_id,d.matched_scope_rule FROM policy_actions a JOIN policy_decisions d "
                "ON d.action_id=a.action_id WHERE a.action_id=? AND d.decision_id=? AND d.target_id=?",
                (action.id, decision.id, action.target_id),
            ).fetchone()
            if (row is None or row["fingerprint"] != permit.action_fingerprint
                    or row["package_id"] != permit.package_id or row["category"] != permit.category.value
                    or row["identity_id"] != permit.identity_id or row["result"] != "ALLOW"
                    or row["policy_version"] != permit.policy_version
                    or row["approval_id"] != permit.approval_id
                    or row["matched_scope_rule"] != permit.scope_rule):
                raise PermitError("Policy authorization is not persisted")
            db.execute(
                "INSERT INTO executor_permits(permit_id,decision_id,action_id,target_id,package_id,"
                "category,identity_id,action_fingerprint,request_fingerprint,policy_version,scope_rule,"
                "approval_id,issued_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (permit.id, permit.decision_id, permit.action_id, permit.target_id, permit.package_id,
                 permit.category.value, permit.identity_id, permit.action_fingerprint,
                 permit.request_fingerprint, permit.policy_version, permit.scope_rule,
                 permit.approval_id, current.isoformat(), permit.expires_at.isoformat()),
            )
            self._event(db, permit, "PERMIT_ISSUED", "POLICY_ALLOW", current)
        return permit

    @staticmethod
    def _event(db: sqlite3.Connection, permit: PolicyPermit, event: str,
               reason: str, at: datetime, exchange_id: str | None = None) -> None:
        if not _CODE.fullmatch(event) or not _CODE.fullmatch(reason):
            raise PermitError("Invalid executor audit code")
        db.execute(
            "INSERT INTO executor_events(permit_id,action_id,target_id,event_type,reason_code,"
            "exchange_id,occurred_at) VALUES (?,?,?,?,?,?,?)",
            (permit.id, permit.action_id, permit.target_id, event, reason,
             exchange_id, at.isoformat()),
        )

    def record(self, permit: PolicyPermit, event: str, reason: str,
               exchange_id: str | None = None) -> None:
        with self.store._connection() as db:
            self._event(db, permit, event, reason, datetime.now(timezone.utc), exchange_id)

    def record_attempt(self, action: ProposedAction, event: str, reason: str) -> None:
        if not isinstance(action, ProposedAction) or not _CODE.fullmatch(event) or not _CODE.fullmatch(reason):
            raise PermitError("Invalid executor audit attempt")
        with self.store._connection() as db:
            db.execute(
                "INSERT INTO executor_events(permit_id,action_id,target_id,event_type,reason_code,"
                "exchange_id,occurred_at) VALUES (NULL,?,?,?,?,NULL,?)",
                (action.id, action.target_id, event, reason, datetime.now(timezone.utc).isoformat()),
            )

    def consume(self, permit: PolicyPermit, action: ProposedAction, request_fingerprint: str,
                policy_version: str, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        if (not isinstance(permit, PolicyPermit) or not isinstance(action, ProposedAction)
                or permit.action_id != action.id or permit.target_id != action.target_id
                or permit.package_id != action.package_id or permit.category != action.category
                or permit.identity_id != action.identity_id
                or permit.action_fingerprint != action.fingerprint()
                or permit.request_fingerprint != request_fingerprint
                or permit.policy_version != policy_version
                or permit.expires_at <= current or not permit.one_time):
            return False
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM executor_permits WHERE permit_id=? AND consumed_at IS NULL",
                (permit.id,),
            ).fetchone()
            if row is None or any((
                row["decision_id"] != permit.decision_id,
                row["action_id"] != permit.action_id,
                row["target_id"] != permit.target_id,
                row["package_id"] != permit.package_id,
                row["category"] != permit.category.value,
                row["identity_id"] != permit.identity_id,
                row["action_fingerprint"] != permit.action_fingerprint,
                row["request_fingerprint"] != permit.request_fingerprint,
                row["policy_version"] != permit.policy_version,
                row["scope_rule"] != permit.scope_rule,
                row["approval_id"] != permit.approval_id,
                row["expires_at"] != permit.expires_at.isoformat(),
                datetime.fromisoformat(row["expires_at"]) <= current,
            )):
                return False
            decision = db.execute(
                "SELECT result,policy_version FROM policy_decisions WHERE decision_id=? AND action_id=?",
                (permit.decision_id, permit.action_id),
            ).fetchone()
            if decision is None or decision["result"] != "ALLOW" or decision["policy_version"] != policy_version:
                return False
            if permit.approval_id:
                changed = db.execute(
                    "UPDATE policy_approvals SET status='CONSUMED' WHERE approval_id=? AND target_id=? "
                    "AND action_id=? AND action_fingerprint=? AND policy_version=? "
                    "AND status='APPROVED_ONCE' AND expires_at>?",
                    (permit.approval_id, permit.target_id, permit.action_id,
                     permit.action_fingerprint, policy_version, current.isoformat()),
                ).rowcount
                if changed != 1:
                    return False
                db.execute(
                    "INSERT INTO policy_events(target_id,action_id,decision_id,approval_id,"
                    "event_type,reason_code,occurred_at) VALUES (?,?,?,?,?,?,?)",
                    (permit.target_id, permit.action_id, permit.decision_id, permit.approval_id,
                     "APPROVAL_CONSUMED", "APPROVED_ONCE", current.isoformat()),
                )
            db.execute("UPDATE executor_permits SET consumed_at=? WHERE permit_id=? AND consumed_at IS NULL",
                       (current.isoformat(), permit.id))
            self._event(db, permit, "PERMIT_CONSUMED", "POLICY_ALLOW", current)
        return True
