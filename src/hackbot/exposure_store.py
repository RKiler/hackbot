"""Target-scoped exposure lead ledger; no response body or secret value columns."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import base64
import json
import re

from .evidence import Sensitivity
from .exposure_models import (CredentialMetadata, ExposureCandidate, ExposureCategory,
                              ExposureSource, ExposureStatus)
from .store import EvidenceFactStore


@dataclass(frozen=True, slots=True)
class ExposureCandidatePage:
    items: tuple[ExposureCandidate, ...]
    next_cursor: str | None


def _from_row(row: object) -> ExposureCandidate:
    data = json.loads(row["candidate_json"])
    credential = data.get("credential")
    if credential is not None:
        credential = CredentialMetadata(
            credential["type"], credential["fingerprint_sha256"], credential["value_length"],
            credential["service_class"], credential["potential_privilege"],
            ExposureStatus(credential["validation_status"]),
        )
    return ExposureCandidate(
        candidate_id=data["candidate_id"], target_id=data["target_id"],
        category=ExposureCategory(data["category"]), location=data["location"],
        endpoint_or_asset=data["endpoint_or_asset"], identity_context=data["identity_context"],
        source=ExposureSource(data["source"]), evidence_ids=tuple(data["evidence_ids"]),
        sensitivity=Sensitivity(data["sensitivity"]), confidence=data["confidence"],
        priority=data["priority"], verification_requirements=tuple(data["verification_requirements"]),
        status=ExposureStatus(row["status"]), created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        reason_codes=tuple(data["reason_codes"]), artifact_sha256=data["artifact_sha256"],
        credential=credential, pii_categories=tuple(data["pii_categories"]),
    )


class ExposureStore:
    def __init__(self, evidence: EvidenceFactStore) -> None:
        self.evidence = evidence

    @staticmethod
    def _json(candidate: ExposureCandidate) -> str:
        data = candidate.public_dict()
        data.pop("finding_status")
        return json.dumps(data, separators=(",", ":"), sort_keys=True)

    def get(self, target_id: str, candidate_id: str) -> ExposureCandidate | None:
        with self.evidence._connection() as db:
            row = db.execute("""SELECT * FROM exposure_candidates
                WHERE target_id=? AND candidate_id=? LIMIT 1""", (target_id, candidate_id)).fetchone()
        return _from_row(row) if row else None

    def existing_recon_pointer(self, target_id: str, candidate_id: str,
                               source_ref: str, content_hash: str) -> str | None:
        """Reuse unchanged recon metadata instead of inserting a new Evidence row."""
        with self.evidence._connection() as db:
            row = db.execute("""SELECT e.evidence_id FROM exposure_candidates c
                JOIN exposure_candidate_sources s ON s.candidate_id=c.candidate_id
                JOIN evidence e ON e.evidence_id=s.evidence_id
                WHERE c.target_id=? AND c.candidate_id=? AND s.source_kind='RECON'
                  AND s.source_ref=? AND s.current=1 AND e.target_ref=?
                  AND e.evidence_type='RECON_RECORD' AND e.content_hash=?
                ORDER BY s.observed_at DESC LIMIT 1""",
                (target_id, candidate_id, source_ref, target_id, content_hash)).fetchone()
        return str(row["evidence_id"]) if row else None

    def save(self, candidate: ExposureCandidate, *, source_ref: str,
             evidence_id: str) -> ExposureCandidate:
        """Deduplicate one signal while keeping independently attributed source links."""
        if not re.fullmatch(r"[A-Z][A-Za-z0-9_-]{0,127}", source_ref):
            raise ValueError("Source reference must be an opaque ID")
        if evidence_id not in candidate.evidence_ids:
            raise ValueError("Exposure source evidence must belong to candidate")
        evidence = self.evidence.get_evidence(evidence_id)
        if evidence is None or evidence.target_ref != candidate.target_id:
            raise ValueError("Target-bound source evidence is required")
        existing = self.get(candidate.target_id, candidate.candidate_id)
        hash_changed = bool(existing is not None and existing.artifact_sha256 and
                            candidate.artifact_sha256 and
                            existing.artifact_sha256 != candidate.artifact_sha256)
        if existing is not None:
            merged_evidence = tuple(dict.fromkeys((*existing.evidence_ids, *candidate.evidence_ids)))[:24]
            merged_reasons = tuple(dict.fromkeys((*existing.reason_codes, *candidate.reason_codes)))[:16]
            keep_status = existing.status if not hash_changed and existing.status in {
                ExposureStatus.SAFE_VALIDATED, ExposureStatus.NEEDS_MANUAL_REVIEW} else candidate.status
            candidate = replace(existing, evidence_ids=merged_evidence, reason_codes=merged_reasons,
                                confidence=max(existing.confidence, candidate.confidence),
                                priority=max(existing.priority, candidate.priority),
                                status=keep_status, updated_at=datetime.now(timezone.utc),
                                artifact_sha256=candidate.artifact_sha256 or existing.artifact_sha256,
                                endpoint_or_asset=candidate.endpoint_or_asset,
                                location=candidate.location,
                                credential=candidate.credential or existing.credential)
        now = candidate.updated_at.isoformat()
        with self.evidence._connection() as db:
            if existing is None:
                db.execute("""INSERT INTO exposure_candidates
                    (candidate_id,target_id,category,priority,status,candidate_json,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (candidate.candidate_id, candidate.target_id, candidate.category.value,
                     candidate.priority, candidate.status.value, self._json(candidate),
                     candidate.created_at.isoformat(), now))
                db.execute("""INSERT INTO exposure_candidate_events
                    (candidate_id,old_status,new_status,reason_code,changed_at)
                    VALUES (?,?,?,?,?)""", (candidate.candidate_id, None,
                                              candidate.status.value, "DISCOVERED", now))
            else:
                db.execute("""UPDATE exposure_candidates SET priority=?,status=?,candidate_json=?,updated_at=?
                    WHERE candidate_id=? AND target_id=?""",
                    (candidate.priority, candidate.status.value, self._json(candidate), now,
                     candidate.candidate_id, candidate.target_id))
                if hash_changed:
                    db.execute("""UPDATE exposure_candidates SET hypothesis_id=NULL,plan_id=NULL,
                        run_id=NULL,validation_id=NULL WHERE candidate_id=? AND target_id=?""",
                        (candidate.candidate_id, candidate.target_id))
                if existing.status != candidate.status:
                    db.execute("""INSERT INTO exposure_candidate_events
                        (candidate_id,old_status,new_status,reason_code,changed_at)
                        VALUES (?,?,?,?,?)""", (candidate.candidate_id, existing.status.value,
                                                  candidate.status.value, "RECLASSIFIED", now))
            db.execute("""INSERT INTO exposure_candidate_sources
                (candidate_id,source_kind,source_ref,artifact_sha256,evidence_id,current,observed_at)
                VALUES (?,?,?,?,?,1,?)
                ON CONFLICT(candidate_id,source_kind,source_ref,evidence_id)
                DO UPDATE SET current=1,observed_at=excluded.observed_at""",
                (candidate.candidate_id, candidate.source.value, source_ref,
                 candidate.artifact_sha256, evidence_id, now))
        return candidate

    def mark_artifact_stale(self, target_id: str, source_ref: str) -> int:
        """Invalidate only candidates with no other current source."""
        changed = 0
        now = datetime.now(timezone.utc).isoformat()
        with self.evidence._connection() as db:
            rows = db.execute("""SELECT DISTINCT c.candidate_id,c.status FROM exposure_candidates c
                JOIN exposure_candidate_sources s ON s.candidate_id=c.candidate_id
                WHERE c.target_id=? AND s.source_ref=? AND s.current=1""",
                (target_id, source_ref)).fetchall()
            db.execute("""UPDATE exposure_candidate_sources SET current=0
                WHERE source_ref=? AND candidate_id IN
                (SELECT candidate_id FROM exposure_candidates WHERE target_id=?)""",
                (source_ref, target_id))
            for row in rows:
                active = db.execute("""SELECT 1 FROM exposure_candidate_sources
                    WHERE candidate_id=? AND current=1 LIMIT 1""", (row["candidate_id"],)).fetchone()
                if active is not None or row["status"] == ExposureStatus.STALE.value:
                    continue
                db.execute("""UPDATE exposure_candidates SET status=?,updated_at=?
                    WHERE candidate_id=? AND target_id=?""",
                    (ExposureStatus.STALE.value, now, row["candidate_id"], target_id))
                db.execute("""INSERT INTO exposure_candidate_events
                    (candidate_id,old_status,new_status,reason_code,changed_at)
                    VALUES (?,?,?,?,?)""", (row["candidate_id"], row["status"],
                                              ExposureStatus.STALE.value, "ARTIFACT_STALE", now))
                changed += 1
        return changed

    def list(self, target_id: str, *, category: ExposureCategory | None = None,
             status: ExposureStatus | None = None, limit: int = 20,
             cursor: str | None = None) -> ExposureCandidatePage:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Exposure page size must be 1..100")
        marker: tuple[int, str] | None = None
        if cursor is not None:
            try:
                decoded = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
                version, target, saved_category, saved_status, priority, candidate_id = json.loads(decoded)
                if (version != 1 or target != target_id or saved_category != (category.value if category else None)
                        or saved_status != (status.value if status else None)
                        or type(priority) is not int or not 0 <= priority <= 100
                        or not re.fullmatch(r"EXP-[0-9a-f]{32}", candidate_id)):
                    raise ValueError
                marker = priority, candidate_id
            except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
                raise ValueError("Invalid exposure cursor") from None
        sql = "SELECT * FROM exposure_candidates WHERE target_id=?"
        values: list[object] = [target_id]
        if category is not None:
            sql += " AND category=?"
            values.append(category.value)
        if status is not None:
            sql += " AND status=?"
            values.append(status.value)
        if marker is not None:
            sql += " AND (priority<? OR (priority=? AND candidate_id>?))"
            values.extend((marker[0], marker[0], marker[1]))
        sql += " ORDER BY priority DESC,candidate_id ASC LIMIT ?"
        values.append(limit + 1)
        with self.evidence._connection() as db:
            rows = db.execute(sql, values).fetchall()
        items = tuple(_from_row(row) for row in rows[:limit])
        next_cursor = None
        if len(rows) > limit and items:
            last = items[-1]
            payload = [1, target_id, category.value if category else None,
                       status.value if status else None, last.priority, last.candidate_id]
            next_cursor = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
        return ExposureCandidatePage(items, next_cursor)

    def source_links(self, target_id: str, candidate_id: str) -> tuple[dict[str, object], ...]:
        if self.get(target_id, candidate_id) is None:
            return ()
        with self.evidence._connection() as db:
            rows = db.execute("""SELECT source_kind,source_ref,artifact_sha256,evidence_id,current,observed_at
                FROM exposure_candidate_sources WHERE candidate_id=?
                ORDER BY observed_at DESC LIMIT 24""", (candidate_id,)).fetchall()
        return tuple({"source": row["source_kind"], "source_ref": row["source_ref"],
                      "artifact_sha256": row["artifact_sha256"],
                      "evidence_id": row["evidence_id"], "current": bool(row["current"]),
                      "observed_at": row["observed_at"]} for row in rows)

    def links(self, target_id: str, candidate_id: str) -> dict[str, str | None]:
        with self.evidence._connection() as db:
            row = db.execute("""SELECT hypothesis_id,plan_id,run_id,validation_id
                FROM exposure_candidates WHERE target_id=? AND candidate_id=? LIMIT 1""",
                (target_id, candidate_id)).fetchone()
        if row is None:
            raise LookupError("Exposure candidate not found")
        return dict(row)

    def candidate_for_plan(self, target_id: str, plan_id: str) -> str | None:
        with self.evidence._connection() as db:
            row = db.execute("""SELECT candidate_id FROM exposure_candidates
                WHERE target_id=? AND plan_id=? LIMIT 1""", (target_id, plan_id)).fetchone()
        return str(row["candidate_id"]) if row else None

    def validation_state(self, target_id: str, candidate_id: str) -> str:
        with self.evidence._connection() as db:
            row = db.execute("""SELECT v.status FROM exposure_candidates c
                JOIN validations v ON v.validation_id=c.validation_id AND v.target_id=c.target_id
                WHERE c.target_id=? AND c.candidate_id=? LIMIT 1""",
                (target_id, candidate_id)).fetchone()
        return str(row["status"]) if row else "UNVALIDATED"

    def bind_plan(self, target_id: str, candidate_id: str,
                  hypothesis_id: str, plan_id: str) -> None:
        candidate = self.get(target_id, candidate_id)
        if candidate is None or candidate.status in {
                ExposureStatus.STALE, ExposureStatus.REJECTED_PUBLIC,
                ExposureStatus.REJECTED_PLACEHOLDER}:
            raise ValueError("Current actionable exposure candidate required")
        with self.evidence._connection() as db:
            hypothesis = db.execute("SELECT 1 FROM hypotheses WHERE hypothesis_id=? AND target_id=?",
                                    (hypothesis_id, target_id)).fetchone()
            plan = db.execute("SELECT 1 FROM skill_plans WHERE plan_id=? AND target_id=? AND hypothesis_id=?",
                              (plan_id, target_id, hypothesis_id)).fetchone()
            if hypothesis is None or plan is None:
                raise ValueError("Exposure plan must be linked to target hypothesis")
            db.execute("""UPDATE exposure_candidates SET hypothesis_id=?,plan_id=?
                WHERE target_id=? AND candidate_id=?""",
                (hypothesis_id, plan_id, target_id, candidate_id))

    def bind_validation(self, target_id: str, candidate_id: str,
                        run_id: str, validation_id: str) -> None:
        with self.evidence._connection() as db:
            row = db.execute("""SELECT plan_id,validation_id FROM exposure_candidates
                WHERE target_id=? AND candidate_id=? LIMIT 1""", (target_id, candidate_id)).fetchone()
            if row is None or not row["plan_id"]:
                raise ValueError("Exposure candidate has no bound plan")
            run = db.execute("""SELECT 1 FROM plan_runs WHERE run_id=? AND plan_id=? AND target_id=?""",
                             (run_id, row["plan_id"], target_id)).fetchone()
            validation = db.execute("""SELECT status FROM validations
                WHERE validation_id=? AND run_id=? AND target_id=?""",
                (validation_id, run_id, target_id)).fetchone()
            if run is None or validation is None:
                raise ValueError("Exposure validation must match the candidate plan run")
            db.execute("""UPDATE exposure_candidates SET run_id=?,validation_id=?
                WHERE target_id=? AND candidate_id=?""", (run_id, validation_id, target_id, candidate_id))
            if validation["status"] == "CONFIRMED" and row["validation_id"] != validation_id:
                db.execute("""INSERT INTO exposure_candidate_events
                    (candidate_id,old_status,new_status,reason_code,changed_at)
                    VALUES (?,?,?,?,?)""", (candidate_id, None, "CONFIRMED",
                                              "STOP_ON_PROOF", datetime.now(timezone.utc).isoformat()))

    def metrics(self, target_id: str) -> dict[str, object]:
        with self.evidence._connection() as db:
            rows = db.execute("""SELECT category,status,COUNT(*) count FROM exposure_candidates
                WHERE target_id=? GROUP BY category,status""", (target_id,)).fetchall()
            validation_rows = db.execute("""SELECT v.status,COUNT(*) count FROM exposure_candidates c
                JOIN validations v ON v.validation_id=c.validation_id AND v.target_id=c.target_id
                WHERE c.target_id=? GROUP BY v.status""", (target_id,)).fetchall()
            requests = db.execute("""SELECT COALESCE(SUM(r.requests_consumed),0) total
                FROM exposure_candidates c JOIN plan_runs r ON r.run_id=c.run_id
                WHERE c.target_id=?""", (target_id,)).fetchone()
            sensitive = db.execute("""SELECT COUNT(DISTINCT e.evidence_id) total
                FROM exposure_candidates c JOIN exposure_candidate_sources s
                ON s.candidate_id=c.candidate_id JOIN evidence e ON e.evidence_id=s.evidence_id
                WHERE c.target_id=? AND e.sensitivity IN ('SENSITIVE','SECRET')""",
                (target_id,)).fetchone()
            proof = db.execute("""SELECT COUNT(*) total FROM exposure_candidate_events x
                JOIN exposure_candidates c ON c.candidate_id=x.candidate_id
                WHERE c.target_id=? AND x.reason_code='STOP_ON_PROOF'""",
                (target_id,)).fetchone()
            rejection_rows = db.execute("""SELECT status,COUNT(*) count FROM exposure_candidates
                WHERE target_id=? AND status IN ('REJECTED_PUBLIC','REJECTED_PLACEHOLDER','STALE')
                GROUP BY status""", (target_id,)).fetchall()
        by_category: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for row in rows:
            by_category[row["category"]] = by_category.get(row["category"], 0) + row["count"]
            by_status[row["status"]] = by_status.get(row["status"], 0) + row["count"]
        return {"candidates": sum(by_category.values()), "categories": by_category,
                "statuses": by_status,
                "validations": {row["status"]: row["count"] for row in validation_rows},
                "requests": int(requests["total"]) if requests else 0,
                "sensitive_artifacts": int(sensitive["total"]) if sensitive else 0,
                "stop_on_proof_events": int(proof["total"]) if proof else 0,
                "false_positive_reasons": {row["status"]: row["count"]
                                           for row in rejection_rows}}
