"""Manual, auditable lifecycle transitions for deterministic findings."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from decimal import Decimal, InvalidOperation
import re
import uuid

from .notification_store import NotificationType
from .safe_output import safe_text
from .store import EvidenceFactStore
from .validation_store import FindingStatus, ValidationStore


_TRANSITIONS = {
    FindingStatus.CONFIRMED: {FindingStatus.READY_FOR_REPORT, FindingStatus.DUPLICATE,
                              FindingStatus.INFORMATIVE},
    FindingStatus.READY_FOR_REPORT: {FindingStatus.SUBMITTED, FindingStatus.DUPLICATE,
                                     FindingStatus.INFORMATIVE},
    FindingStatus.SUBMITTED: {FindingStatus.TRIAGED, FindingStatus.DUPLICATE,
                              FindingStatus.INFORMATIVE, FindingStatus.RESOLVED},
    FindingStatus.TRIAGED: {FindingStatus.RESOLVED, FindingStatus.REWARDED,
                            FindingStatus.DUPLICATE, FindingStatus.INFORMATIVE},
    FindingStatus.RESOLVED: {FindingStatus.REWARDED},
    FindingStatus.DUPLICATE: set(),
    FindingStatus.INFORMATIVE: set(),
    FindingStatus.REWARDED: set(),
}
_PLATFORM = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,39}\Z")
_EXTERNAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}\Z")
_CURRENCY = re.compile(r"[A-Z]{3}\Z")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FindingWorkflow:
    def __init__(self, store: EvidenceFactStore, validations: ValidationStore) -> None:
        self.store = store
        self.validations = validations

    def detail(self, finding_id: str, target_id: str) -> dict[str, object]:
        finding = self.validations.get_finding(finding_id, target_id)
        if finding is None:
            raise LookupError("finding not found")
        with self.store._connection() as db:
            history = db.execute(
                "SELECT event_id,status,reason_code,details_json,actor_alias,workflow_version,"
                "occurred_at FROM finding_status_events WHERE finding_id=? "
                "ORDER BY event_id DESC LIMIT 100", (finding_id,)).fetchall()
            meta = db.execute("SELECT * FROM finding_submission_metadata WHERE finding_id=?",
                              (finding_id,)).fetchone()
            source = db.execute(
                "SELECT skill_id,skill_version,plan_id,run_id FROM validations "
                "WHERE validation_id=? AND target_id=?",
                (finding.validation_id, target_id)).fetchone()
            planner = db.execute(
                "SELECT p.candidate_id,p.run_id,p.specialist,t.result_ref AS research_brief_id "
                "FROM planner_candidates p LEFT JOIN planner_tasks t ON "
                "t.candidate_id=p.candidate_id AND t.task_type='REQUEST_RESEARCH' "
                "AND t.status='COMPLETED' AND t.result_ref LIKE 'RBRF-%' "
                "WHERE p.finding_id=? AND p.target_id=? ORDER BY p.updated_at DESC LIMIT 10",
                (finding_id, target_id)).fetchall()
            attempt = db.execute(
                "SELECT readiness,report_id FROM report_attempts WHERE finding_id=? "
                "ORDER BY attempt_id DESC LIMIT 1", (finding_id,)).fetchone()
            latest_draft = db.execute(
                "SELECT report_id,readiness FROM report_drafts WHERE finding_id=? "
                "ORDER BY version DESC LIMIT 1", (finding_id,)).fetchone()
        version = history[0]["workflow_version"] if history else 0
        allowed = set(_TRANSITIONS[finding.status])
        if FindingStatus.READY_FOR_REPORT in allowed and (
                attempt is None or latest_draft is None or
                attempt["readiness"] != "READY" or latest_draft["readiness"] != "READY" or
                attempt["report_id"] != latest_draft["report_id"]):
            allowed.remove(FindingStatus.READY_FOR_REPORT)
        return {"finding": finding.to_dict(), "workflow_version": version,
                "allowed_transitions": [item.value for item in sorted(
                    allowed, key=lambda item: item.value)],
                "history": [{"status": row["status"], "reason_code": row["reason_code"],
                             "details": json.loads(row["details_json"]),
                             "actor_alias": row["actor_alias"],
                             "version": row["workflow_version"],
                             "occurred_at": row["occurred_at"]} for row in history],
                "submission": dict(meta) if meta else None,
                "lineage": {"skill_id": source["skill_id"] if source else None,
                            "skill_version": source["skill_version"] if source else None,
                            "plan_id": source["plan_id"] if source else None,
                            "plan_run_id": source["run_id"] if source else None,
                            "planner_links": [dict(item) for item in planner]}}

    def transition(self, finding_id: str, target_id: str, status: FindingStatus, *,
                   expected_version: int, actor_alias: str | None = None,
                   note: str | None = None, platform: str | None = None,
                   program: str | None = None, external_report_id: str | None = None,
                   external_duplicate_ref: str | None = None,
                   reward_amount: str | None = None, reward_currency: str | None = None,
                   triage_status: str | None = None) -> dict[str, object]:
        if (not isinstance(status, FindingStatus) or type(expected_version) is not int or
                not 0 <= expected_version < 1_000_000):
            raise ValueError("invalid workflow transition")
        if actor_alias is not None and (not _EXTERNAL_ID.fullmatch(actor_alias) or len(actor_alias) > 64):
            raise ValueError("invalid operator alias")
        if platform is not None and not _PLATFORM.fullmatch(platform):
            raise ValueError("invalid submission platform")
        if external_report_id is not None and not _EXTERNAL_ID.fullmatch(external_report_id):
            raise ValueError("invalid external report ID")
        if external_duplicate_ref is not None and not _EXTERNAL_ID.fullmatch(external_duplicate_ref):
            raise ValueError("invalid duplicate reference")
        if program is not None and (not isinstance(program, str) or not 1 <= len(program) <= 100):
            raise ValueError("invalid program")
        if reward_currency is not None and not _CURRENCY.fullmatch(reward_currency):
            raise ValueError("invalid reward currency")
        if reward_amount is not None:
            try:
                amount = Decimal(reward_amount)
            except (InvalidOperation, TypeError):
                raise ValueError("invalid reward amount") from None
            if not amount.is_finite() or not 0 <= amount <= 10_000_000 or amount.as_tuple().exponent < -2:
                raise ValueError("invalid reward amount")
        if status is FindingStatus.REWARDED and (reward_amount is None or reward_currency is None):
            raise ValueError("reward requires amount and currency")
        if status is FindingStatus.SUBMITTED and (platform is None or external_report_id is None):
            raise ValueError("submission requires platform and report ID")
        if note is not None and (not isinstance(note, str) or len(note) > 1000):
            raise ValueError("invalid workflow note")
        now = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM findings WHERE finding_id=? AND target_id=?",
                             (finding_id, target_id)).fetchone()
            if row is None:
                raise LookupError("finding not found")
            current = FindingStatus(row["status"])
            version_row = db.execute(
                "SELECT workflow_version FROM finding_status_events WHERE finding_id=? "
                "ORDER BY event_id DESC LIMIT 1", (finding_id,)).fetchone()
            version = version_row[0] if version_row else 0
            if version != expected_version:
                raise ValueError("stale workflow version")
            if status not in _TRANSITIONS[current]:
                raise ValueError("invalid finding status transition")
            if status is FindingStatus.READY_FOR_REPORT:
                attempt = db.execute(
                    "SELECT a.readiness,a.report_id FROM report_attempts a "
                    "WHERE a.finding_id=? ORDER BY a.attempt_id DESC LIMIT 1",
                    (finding_id,)).fetchone()
                latest_draft = db.execute(
                    "SELECT report_id,readiness FROM report_drafts WHERE finding_id=? "
                    "ORDER BY version DESC LIMIT 1", (finding_id,)).fetchone()
                if (attempt is None or latest_draft is None or
                        attempt["readiness"] != "READY" or
                        latest_draft["readiness"] != "READY" or
                        attempt["report_id"] != latest_draft["report_id"]):
                    raise ValueError("latest report draft must be ready")
            details = {"note": safe_text(note, limit=800) if note else None,
                       "platform": platform,
                       "program": safe_text(program, limit=100) if program else None,
                       "external_report_id": external_report_id,
                       "external_duplicate_ref": external_duplicate_ref,
                       "triage_status": safe_text(triage_status, limit=80) if triage_status else None,
                       "reward_amount": reward_amount, "reward_currency": reward_currency}
            db.execute("UPDATE findings SET status=? WHERE finding_id=?", (status.value, finding_id))
            db.execute(
                "INSERT INTO finding_status_events(finding_id,status,reason_code,occurred_at,"
                "details_json,actor_alias,workflow_version) VALUES (?,?,?,?,?,?,?)",
                (finding_id, status.value, "OPERATOR_TRANSITION", now,
                 json.dumps(details, sort_keys=True), actor_alias, version + 1))
            if any(value is not None for value in (platform, program, external_report_id,
                    external_duplicate_ref, reward_amount, reward_currency, triage_status)) or status is FindingStatus.SUBMITTED:
                db.execute(
                    "INSERT INTO finding_submission_metadata(finding_id,platform,program,external_report_id,"
                    "submitted_at,triage_status,reward_amount,reward_currency,external_duplicate_ref,updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET "
                    "platform=COALESCE(excluded.platform,platform),"
                    "program=COALESCE(excluded.program,program),"
                    "external_report_id=COALESCE(excluded.external_report_id,external_report_id),"
                    "submitted_at=COALESCE(excluded.submitted_at,submitted_at),"
                    "triage_status=COALESCE(excluded.triage_status,triage_status),"
                    "reward_amount=COALESCE(excluded.reward_amount,reward_amount),"
                    "reward_currency=COALESCE(excluded.reward_currency,reward_currency),"
                    "external_duplicate_ref=COALESCE(excluded.external_duplicate_ref,external_duplicate_ref),"
                    "updated_at=excluded.updated_at",
                    (finding_id, platform, safe_text(program, limit=100) if program else None,
                     external_report_id, now if status is FindingStatus.SUBMITTED else None,
                     safe_text(triage_status, limit=80) if triage_status else None,
                     reward_amount, reward_currency, external_duplicate_ref, now))
            event_type = (NotificationType.FINDING_READY_FOR_REPORT if status is FindingStatus.READY_FOR_REPORT
                          else NotificationType.FINDING_TRIAGE_CHANGED)
            dedupe_key = hashlib.sha256(
                f"{event_type.value}:{finding_id}:{version + 1}".encode("ascii")
            ).hexdigest()
            db.execute(
                "INSERT INTO notification_events(event_id,target_id,event_type,source_kind,source_id,"
                "finding_id,validation_id,priority,workflow_version,dedupe_key,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("NOTIF-" + uuid.uuid4().hex, target_id, event_type.value, "FINDING",
                 finding_id, finding_id, row["validation_id"], "NORMAL", version + 1,
                 dedupe_key, now))
        return self.detail(finding_id, target_id)

    def metrics(self, target_id: str | None = None) -> dict[str, int]:
        with self.store._connection() as db:
            where = " WHERE target_id=?" if target_id else ""
            rows = db.execute("SELECT status,count(*) n FROM findings" + where + " GROUP BY status",
                              (target_id,) if target_id else ()).fetchall()
            accepted = db.execute(
                "SELECT count(*) FROM finding_submission_metadata m JOIN findings f "
                "ON f.finding_id=m.finding_id WHERE UPPER(m.triage_status)='ACCEPTED'" +
                (" AND f.target_id=?" if target_id else ""),
                (target_id,) if target_id else ()).fetchone()[0]
        result = {status.value.lower(): next(
            (row["n"] for row in rows if row["status"] == status.value), 0)
                  for status in FindingStatus}
        result["accepted"] = accepted
        return result
