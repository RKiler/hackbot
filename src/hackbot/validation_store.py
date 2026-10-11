"""Append-only validation decisions and confirmed, root-cause-deduplicated findings."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
import json
import re
import sqlite3
import uuid

from .store import EvidenceFactStore


_ID = re.compile(r"[A-Z][A-Z_]*-[0-9a-f]{32}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class ValidationStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    INVALID_TEST = "INVALID_TEST"
    DUPLICATE_CANDIDATE = "DUPLICATE_CANDIDATE"


class CheckOutcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class FindingStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    READY_FOR_REPORT = "READY_FOR_REPORT"
    SUBMITTED = "SUBMITTED"
    TRIAGED = "TRIAGED"
    DUPLICATE = "DUPLICATE"
    INFORMATIVE = "INFORMATIVE"
    RESOLVED = "RESOLVED"
    REWARDED = "REWARDED"


@dataclass(frozen=True, slots=True)
class ValidationCheck:
    code: str
    outcome: CheckOutcome
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {"code": self.code, "outcome": self.outcome.value,
                "evidence_ids": list(self.evidence_ids)}


@dataclass(frozen=True, slots=True)
class ValidationResult:
    id: str
    target_id: str
    run_id: str
    plan_id: str
    hypothesis_id: str
    skill_id: str
    skill_version: str
    skill_hash: str
    validator_id: str
    validator_version: str
    source: str
    status: ValidationStatus
    confidence_band: str
    plan_snapshot_hash: str
    evidence_snapshot_hash: str
    supporting_evidence_ids: tuple[str, ...]
    contradicting_evidence_ids: tuple[str, ...]
    controls_evaluated: tuple[str, ...]
    confirmation_criteria: tuple[str, ...]
    rejection_criteria: tuple[str, ...]
    checks: tuple[ValidationCheck, ...]
    demonstrated_impact: str | None
    potential_impact: str | None
    reproduction_count: int
    limitations: tuple[str, ...]
    reason_codes: tuple[str, ...]
    safe_summary: str
    created_at: str
    supersedes_id: str | None = None
    duplicate_of_finding_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "target_id": self.target_id, "run_id": self.run_id,
                "plan_id": self.plan_id, "hypothesis_id": self.hypothesis_id,
                "skill_id": self.skill_id, "skill_version": self.skill_version,
                "skill_hash": self.skill_hash, "validator_id": self.validator_id,
                "validator_version": self.validator_version, "source": self.source,
                "status": self.status.value, "confidence_band": self.confidence_band,
                "plan_snapshot_hash": self.plan_snapshot_hash,
                "evidence_snapshot_hash": self.evidence_snapshot_hash,
                "supporting_evidence_ids": list(self.supporting_evidence_ids),
                "contradicting_evidence_ids": list(self.contradicting_evidence_ids),
                "controls_evaluated": list(self.controls_evaluated),
                "confirmation_criteria": list(self.confirmation_criteria),
                "rejection_criteria": list(self.rejection_criteria),
                "checks": [check.to_dict() for check in self.checks],
                "impact": {"demonstrated": self.demonstrated_impact,
                           "potential": self.potential_impact},
                "reproduction_count": self.reproduction_count,
                "limitations": list(self.limitations), "reason_codes": list(self.reason_codes),
                "safe_summary": self.safe_summary, "created_at": self.created_at,
                "supersedes_id": self.supersedes_id,
                "duplicate_of_finding_id": self.duplicate_of_finding_id}


@dataclass(frozen=True, slots=True)
class FindingSpec:
    category: str
    root_cause_fingerprint: str
    surface_fingerprint: str
    object_type: str | None
    title: str
    safe_summary: str
    demonstrated_impact: str
    potential_impact: str | None = None
    preliminary_severity: str | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    target_id: str
    validation_id: str
    hypothesis_id: str
    category: str
    status: FindingStatus
    root_cause_fingerprint: str
    surface_fingerprint: str
    object_type: str | None
    title: str
    safe_summary: str
    demonstrated_impact: str
    potential_impact: str | None
    preliminary_severity: str | None
    created_at: str
    evidence_ids: tuple[str, ...] = ()
    locations: tuple[str, ...] = ()
    duplicate_validation_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "target_id": self.target_id,
                "validation_id": self.validation_id, "hypothesis_id": self.hypothesis_id,
                "category": self.category, "status": self.status.value,
                "root_cause_fingerprint": self.root_cause_fingerprint,
                "surface_fingerprint": self.surface_fingerprint,
                "object_type": self.object_type, "title": self.title,
                "safe_summary": self.safe_summary,
                "impact": {"demonstrated": self.demonstrated_impact,
                           "potential": self.potential_impact},
                "preliminary_severity": self.preliminary_severity,
                "created_at": self.created_at, "evidence_ids": list(self.evidence_ids),
                "evidence_count": len(self.evidence_ids), "locations": list(self.locations),
                "duplicate_validation_ids": list(self.duplicate_validation_ids),
                "report_readiness": "RESEARCHER_REVIEW_REQUIRED"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(values: tuple[str, ...]) -> str:
    return json.dumps(values, separators=(",", ":"))


class ValidationStore:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    @staticmethod
    def _row(row: sqlite3.Row, checks: tuple[ValidationCheck, ...]) -> ValidationResult:
        impact = json.loads(row["impact_json"])
        return ValidationResult(
            row["validation_id"], row["target_id"], row["run_id"], row["plan_id"],
            row["hypothesis_id"], row["skill_id"], row["skill_version"], row["skill_hash"],
            row["validator_id"], row["validator_version"], row["source"],
            ValidationStatus(row["status"]), row["confidence_band"],
            row["plan_snapshot_hash"], row["evidence_snapshot_hash"],
            tuple(json.loads(row["supporting_evidence_json"])),
            tuple(json.loads(row["contradicting_evidence_json"])),
            tuple(json.loads(row["controls_json"])),
            tuple(json.loads(row["confirmation_criteria_json"])),
            tuple(json.loads(row["rejection_criteria_json"])), checks,
            impact.get("demonstrated"), impact.get("potential"), row["reproduction_count"],
            tuple(json.loads(row["limitations_json"])),
            tuple(json.loads(row["reason_codes_json"])), row["safe_summary"],
            row["created_at"], row["supersedes_id"], row["duplicate_of_finding_id"])

    @staticmethod
    def _finding(db: sqlite3.Connection, row: sqlite3.Row) -> Finding:
        finding_id = row["finding_id"]
        evidence = tuple(item[0] for item in db.execute(
            "SELECT evidence_id FROM finding_evidence WHERE finding_id=? ORDER BY evidence_id LIMIT 64",
            (finding_id,)))
        locations = tuple(item[0] for item in db.execute(
            "SELECT surface_fingerprint FROM finding_locations WHERE finding_id=? "
            "ORDER BY created_at,surface_fingerprint LIMIT 64", (finding_id,)))
        duplicates = tuple(item[0] for item in db.execute(
            "SELECT validation_id FROM finding_duplicates WHERE finding_id=? "
            "ORDER BY created_at,validation_id LIMIT 64", (finding_id,)))
        return Finding(finding_id, row["target_id"], row["validation_id"], row["hypothesis_id"],
                       row["category"], FindingStatus(row["status"]), row["root_cause_fingerprint"],
                       row["surface_fingerprint"], row["object_type"], row["title"],
                       row["safe_summary"], row["demonstrated_impact"], row["potential_impact"],
                       row["preliminary_severity"], row["created_at"], evidence, locations, duplicates)

    def _checks(self, db: sqlite3.Connection, validation_id: str) -> tuple[ValidationCheck, ...]:
        rows = db.execute("SELECT criterion_code,outcome,evidence_ids_json FROM validation_checks "
                          "WHERE validation_id=? ORDER BY criterion_code LIMIT 64", (validation_id,))
        return tuple(ValidationCheck(row["criterion_code"], CheckOutcome(row["outcome"]),
                                     tuple(json.loads(row["evidence_ids_json"]))) for row in rows)

    def record(self, result: ValidationResult, finding: FindingSpec | None = None) -> tuple[ValidationResult, Finding | None]:
        if result.status is ValidationStatus.CONFIRMED and (result.source != "DETERMINISTIC" or finding is None or
                                                             not result.checks or any(
                                                                 check.outcome is not CheckOutcome.PASS
                                                                 for check in result.checks)):
            raise ValueError("confirmed validation requires passing deterministic checks and finding evidence")
        if finding is not None and (result.status is not ValidationStatus.CONFIRMED or
                                    result.source != "DETERMINISTIC" or
                                    not result.supporting_evidence_ids or
                                    not _HASH.fullmatch(finding.root_cause_fingerprint) or
                                    not _HASH.fullmatch(finding.surface_fingerprint)):
            raise ValueError("finding requires a deterministic confirmed result")
        if (not _ID.fullmatch(result.id) or result.id.split("-", 1)[0] != "VALIDATION" or
                not _HASH.fullmatch(result.evidence_snapshot_hash) or
                not _HASH.fullmatch(result.plan_snapshot_hash) or
                len(result.checks) > 64 or len(set(check.code for check in result.checks)) != len(result.checks) or
                any(not _CODE.fullmatch(check.code) for check in result.checks)):
            raise ValueError("invalid validation metadata")
        refs = set((*result.supporting_evidence_ids, *result.contradicting_evidence_ids,
                    *(ref for check in result.checks for ref in check.evidence_ids)))
        if len(refs) > 64 or any(not ref.startswith("EV-") for ref in refs):
            raise ValueError("invalid evidence references")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute("SELECT target_id,plan_id,hypothesis_id,skill_id,skill_version,skill_hash,"
                             "snapshot_hash FROM plan_runs WHERE run_id=?", (result.run_id,)).fetchone()
            if (run is None or any(run[key] != getattr(result, {"snapshot_hash": "plan_snapshot_hash"}.get(key, key))
                                   for key in ("target_id", "plan_id", "hypothesis_id", "skill_id",
                                               "skill_version", "skill_hash", "snapshot_hash"))):
                raise ValueError("validation does not match its run")
            if refs:
                marks = ",".join("?" for _ in refs)
                count = db.execute(f"SELECT count(*) FROM evidence WHERE target_ref=? AND evidence_id IN ({marks})",
                                   (result.target_id, *sorted(refs))).fetchone()[0]
                if count != len(refs):
                    raise ValueError("validation evidence belongs to another target or is missing")
            previous = db.execute("SELECT * FROM validations WHERE run_id=? AND validator_id=? "
                                  "AND validator_version=? AND evidence_snapshot_hash=? AND source=? "
                                  "ORDER BY created_at DESC LIMIT 1",
                                  (result.run_id, result.validator_id, result.validator_version,
                                   result.evidence_snapshot_hash, result.source)).fetchone()
            if previous is not None:
                restored = self._row(previous, self._checks(db, previous["validation_id"]))
                row = db.execute("SELECT * FROM findings WHERE validation_id=?", (restored.id,)).fetchone()
                return restored, self._finding(db, row) if row else None
            latest = db.execute("SELECT validation_id FROM validations WHERE run_id=? "
                                "ORDER BY created_at DESC,validation_id DESC LIMIT 1",
                                (result.run_id,)).fetchone()
            result = replace(result, supersedes_id=latest[0] if latest else None)
            duplicate = None
            if finding is not None:
                duplicate = db.execute("SELECT * FROM findings WHERE root_cause_fingerprint=?",
                                       (finding.root_cause_fingerprint,)).fetchone()
                if duplicate is not None:
                    result = replace(result, status=ValidationStatus.DUPLICATE_CANDIDATE,
                                     duplicate_of_finding_id=duplicate["finding_id"],
                                     reason_codes=(*result.reason_codes, "DUPLICATE_ROOT_CAUSE"),
                                     safe_summary="Equivalent confirmed root cause already recorded.")
            db.execute("INSERT INTO validations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (result.id, result.target_id, result.run_id, result.plan_id,
                        result.hypothesis_id, result.skill_id, result.skill_version, result.skill_hash,
                        result.validator_id, result.validator_version, result.source, result.status.value,
                        result.confidence_band, result.plan_snapshot_hash, result.evidence_snapshot_hash,
                        _json(result.supporting_evidence_ids), _json(result.contradicting_evidence_ids),
                        _json(result.controls_evaluated), _json(result.confirmation_criteria),
                        _json(result.rejection_criteria),
                        json.dumps({"demonstrated": result.demonstrated_impact,
                                    "potential": result.potential_impact}, separators=(",", ":")),
                        result.reproduction_count, _json(result.limitations), _json(result.reason_codes),
                        result.safe_summary, result.supersedes_id,
                        result.duplicate_of_finding_id, result.created_at))
            for check in result.checks:
                db.execute("INSERT INTO validation_checks VALUES (?,?,?,?)",
                           (result.id, check.code, check.outcome.value, _json(check.evidence_ids)))
            if duplicate is not None:
                db.execute("INSERT INTO finding_duplicates VALUES (?,?,?)",
                           (result.id, duplicate["finding_id"], result.created_at))
                db.execute("INSERT OR IGNORE INTO finding_locations VALUES (?,?,?,?)",
                           (duplicate["finding_id"], finding.surface_fingerprint, result.id, result.created_at))
                for ref in result.supporting_evidence_ids:
                    db.execute("INSERT OR IGNORE INTO finding_evidence VALUES (?,?)",
                               (duplicate["finding_id"], ref))
                return result, self._finding(db, duplicate)
            if finding is None:
                return result, None
            finding_id = "FINDING-" + uuid.uuid4().hex
            db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (finding_id, result.target_id, result.id, result.hypothesis_id,
                        finding.category, FindingStatus.CONFIRMED.value,
                        finding.root_cause_fingerprint, finding.surface_fingerprint,
                        finding.object_type, finding.title, finding.safe_summary,
                        finding.demonstrated_impact, finding.potential_impact,
                        finding.preliminary_severity, result.created_at))
            for ref in result.supporting_evidence_ids:
                db.execute("INSERT OR IGNORE INTO finding_evidence VALUES (?,?)", (finding_id, ref))
            db.execute("INSERT INTO finding_locations VALUES (?,?,?,?)",
                       (finding_id, finding.surface_fingerprint, result.id, result.created_at))
            db.execute("INSERT INTO finding_status_events(finding_id,status,reason_code,occurred_at) "
                       "VALUES (?,?,?,?)", (finding_id, "CONFIRMED", "VALIDATOR_CONFIRMED", result.created_at))
            row = db.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
            return result, self._finding(db, row)

    def get(self, validation_id: str, target_id: str) -> ValidationResult | None:
        if not isinstance(validation_id, str) or not re.fullmatch(r"VALIDATION-[0-9a-f]{32}", validation_id):
            raise ValueError("invalid validation ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM validations WHERE validation_id=? AND target_id=?",
                             (validation_id, target_id)).fetchone()
            return self._row(row, self._checks(db, validation_id)) if row else None

    def latest_for_run(self, run_id: str, target_id: str) -> ValidationResult | None:
        if not isinstance(run_id, str) or not re.fullmatch(r"RUN-[0-9a-f]{32}", run_id):
            raise ValueError("invalid run ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM validations WHERE run_id=? AND target_id=? "
                             "ORDER BY rowid DESC LIMIT 1", (run_id, target_id)).fetchone()
            return self._row(row, self._checks(db, row["validation_id"])) if row else None

    def finding_for_validation(self, validation_id: str, target_id: str) -> Finding | None:
        if not isinstance(validation_id, str) or not re.fullmatch(r"VALIDATION-[0-9a-f]{32}", validation_id):
            raise ValueError("invalid validation ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM findings WHERE validation_id=? AND target_id=?",
                             (validation_id, target_id)).fetchone()
            return self._finding(db, row) if row else None

    def get_finding(self, finding_id: str, target_id: str) -> Finding | None:
        if not isinstance(finding_id, str) or not re.fullmatch(r"FINDING-[0-9a-f]{32}", finding_id):
            raise ValueError("invalid finding ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM findings WHERE finding_id=? AND target_id=?",
                             (finding_id, target_id)).fetchone()
            return self._finding(db, row) if row else None

    def list(self, target_id: str, *, limit: int = 20, cursor: str | None = None,
             status: ValidationStatus | None = None) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= 50 or cursor is not None and not cursor.isdecimal():
            raise ValueError("invalid validation page")
        sql = "SELECT rowid AS cursor_id,* FROM validations WHERE target_id=?"
        args: list[object] = [target_id]
        if status is not None:
            sql += " AND status=?"
            args.append(status.value)
        if cursor:
            sql += " AND rowid<?"
            args.append(int(cursor))
        sql += " ORDER BY rowid DESC LIMIT ?"
        args.append(limit + 1)
        with self.store._connection() as db:
            rows = db.execute(sql, args).fetchall()
            items = [self._row(row, self._checks(db, row["validation_id"])).to_dict()
                     for row in rows[:limit]]
        return {"items": items, "next_cursor": str(rows[limit - 1]["cursor_id"])
                if len(rows) > limit else None}

    def list_findings(self, target_id: str, *, limit: int = 20, cursor: str | None = None,
                      status: FindingStatus | None = None) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= 50 or cursor is not None and not cursor.isdecimal():
            raise ValueError("invalid finding page")
        sql = "SELECT rowid AS cursor_id,* FROM findings WHERE target_id=?"
        args: list[object] = [target_id]
        if status is not None:
            sql += " AND status=?"
            args.append(status.value)
        if cursor:
            sql += " AND rowid<?"
            args.append(int(cursor))
        sql += " ORDER BY rowid DESC LIMIT ?"
        args.append(limit + 1)
        with self.store._connection() as db:
            rows = db.execute(sql, args).fetchall()
            items = [self._finding(db, row).to_dict() for row in rows[:limit]]
        return {"items": items, "next_cursor": str(rows[limit - 1]["cursor_id"])
                if len(rows) > limit else None}

    def stats(self, target_id: str | None = None) -> dict[str, object]:
        with self.store._connection() as db:
            clause = " WHERE target_id=?" if target_id else ""
            args = (target_id,) if target_id else ()
            rows = db.execute("SELECT status,count(*) AS n FROM validations" + clause +
                              " GROUP BY status", args).fetchall()
            finding_count = db.execute("SELECT count(*) FROM findings" + clause, args).fetchone()[0]
            reasons = db.execute("SELECT reason_codes_json FROM validations" + clause +
                                 " ORDER BY created_at DESC LIMIT 1000", args).fetchall()
        counts = {row["status"]: row["n"] for row in rows}
        reason_counts: dict[str, int] = {}
        for row in reasons:
            for reason in json.loads(row["reason_codes_json"]):
                reason_counts[reason] = reason_counts.get(reason, 0) + 1
        return {"validator_runs": sum(counts.values()), "confirmed": counts.get("CONFIRMED", 0),
                "rejected": counts.get("REJECTED", 0),
                "manual_review": counts.get("NEEDS_MANUAL_REVIEW", 0),
                "insufficient_evidence": counts.get("INSUFFICIENT_EVIDENCE", 0),
                "invalid_tests": counts.get("INVALID_TEST", 0),
                "duplicates": counts.get("DUPLICATE_CANDIDATE", 0),
                "findings": finding_count, "recent_reason_counts": reason_counts}
