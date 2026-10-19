"""Transactional, target-scoped local state for explicit planner runs."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import sqlite3
import uuid
from typing import TYPE_CHECKING

from .planner_models import (
    PLANNER_VERSION, CandidateAssessment, CandidateOverride, CandidateStatus, PlannerCandidate,
    PlannerLimits, PlannerMode, PlannerRun, PlannerStatus, PlannerTask,
    PlannerTaskStatus, PlannerTaskType, PlannerUsage, Specialist, TERMINAL_STATUSES,
)
from .store import EvidenceFactStore
from .target_package import TargetPackage

if TYPE_CHECKING:
    from .planner_context import PlannerContext


_ID = re.compile(r"(?:PLRUN|PLCAND|PLTASK)-[0-9a-f]{32}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_REF = re.compile(r"(?:PLAN|RUN|VALIDATION|FINDING|RREQ|RBRF|TESTOBJ|IDENTITY|HYP|EV|"
                  r"PROF|LEARN|EXCHANGE|FA)-[0-9a-f]{32}\Z")
MAX_RUN_TASKS = 320
MAX_APPROVED_CHILD_RESUMES = 32


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: object, maximum: int = 4096) -> str:
    result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(result.encode()) > maximum:
        raise ValueError("Planner metadata exceeds bound")
    return result


class PlannerStore:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    @staticmethod
    def _run(row: sqlite3.Row) -> PlannerRun:
        return PlannerRun(
            row["run_id"], row["target_id"], row["package_id"], row["package_version"],
            row["policy_hash"], PlannerMode(row["mode"]), PlannerStatus(row["status"]),
            PlannerLimits(**json.loads(row["limits_json"])),
            PlannerUsage(**json.loads(row["usage_json"])), json.loads(row["readiness_json"]),
            row["context_hash"], row["candidate_count"], row["selected_count"],
            row["plans_created"], row["plans_executed"], row["validations"],
            row["findings"], row["manual_reviews"], row["research_requests"],
            row["stop_reason"], row["planner_version"], row["started_at"],
            row["created_at"], row["updated_at"], row["finished_at"],
        )

    @staticmethod
    def _candidate(row: sqlite3.Row) -> PlannerCandidate:
        return PlannerCandidate(
            row["candidate_id"], row["run_id"], row["target_id"], row["source_kind"],
            row["source_id"], row["hypothesis_id"], Specialist(row["specialist"]),
            row["category"], row["root_cause_key"], row["surface_hash"], row["score"],
            row["expected_value"], row["priority"], row["estimated_requests"],
            row["estimated_browser"], row["estimated_tokens"], row["risk"],
            row["evidence_strength"], row["freshness"], tuple(json.loads(row["gaps_json"])),
            tuple(json.loads(row["reason_codes_json"])), tuple(json.loads(row["source_refs_json"])),
            tuple(json.loads(row["skill_ids_json"])), tuple(json.loads(row["handoffs_json"])),
            CandidateStatus(row["status"]), row["related_candidate_id"], row["plan_id"],
            row["plan_run_id"], row["validation_id"], row["finding_id"],
            CandidateOverride(row["override"]), row["override_specialist"],
            row["override_skill_id"], row["created_at"], row["updated_at"],
            row["state_hash"], CandidateAssessment.from_dict(
                json.loads(row["assessment_json"])),
        )

    @staticmethod
    def _task(db: sqlite3.Connection, row: sqlite3.Row) -> PlannerTask:
        deps = db.execute("SELECT depends_on FROM planner_task_dependencies WHERE task_id=? "
                          "ORDER BY depends_on", (row["task_id"],)).fetchall()
        return PlannerTask(
            row["task_id"], row["run_id"], row["candidate_id"],
            PlannerTaskType(row["task_type"]), PlannerTaskStatus(row["status"]),
            row["priority"], json.loads(row["budget_json"]), tuple(item[0] for item in deps),
            row["attempt"], row["result_ref"], row["reason_code"], row["created_at"],
            row["updated_at"], row["started_at"], row["finished_at"],
        )

    @staticmethod
    def _event(db: sqlite3.Connection, run_id: str, event: str, reason: str,
               *, candidate_id: str | None = None, task_id: str | None = None,
               refs: tuple[str, ...] = ()) -> None:
        if not _CODE.fullmatch(event) or not _CODE.fullmatch(reason):
            raise ValueError("Invalid planner event")
        if len(refs) > 8 or any(not _REF.fullmatch(ref) for ref in refs):
            raise ValueError("Invalid planner event references")
        db.execute("INSERT INTO planner_events(run_id,candidate_id,task_id,event_type,reason_code,"
                   "safe_refs_json,occurred_at) VALUES (?,?,?,?,?,?,?)",
                   (run_id, candidate_id, task_id, event, reason, _json(refs), _now()))

    def create(self, package: TargetPackage, mode: PlannerMode,
               limits: PlannerLimits, policy_hash: str,
               *, campaign_work_id: str | None = None) -> PlannerRun:
        if package.status.value != "TRACKED" or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}:[0-9a-f]{64}", policy_hash):
            raise ValueError("Target Package is not ready for planning")
        run_id, at = "PLRUN-" + uuid.uuid4().hex, _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            target = db.execute("SELECT target_id FROM registry_targets WHERE target_id=?",
                                (package.target.id,)).fetchone()
            if target is None:
                raise ValueError("Target is not registered")
            db.execute("INSERT INTO planner_runs(run_id,target_id,package_id,package_version,"
                       "policy_hash,mode,status,limits_json,usage_json,readiness_json,"
                       "planner_version,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (run_id, package.target.id, package.id, package.version, policy_hash,
                        mode.value, PlannerStatus.CREATED.value, _json(limits.to_dict()),
                        _json(PlannerUsage().to_dict()), "{}", PLANNER_VERSION, at, at))
            if campaign_work_id is not None:
                from .campaign_models import CampaignWorkKind
                from .campaign_store import link_created_child
                link_created_child(db, campaign_work_id, kind=CampaignWorkKind.PLANNER,
                                   target_id=package.target.id, child_id=run_id)
            self._event(db, run_id, "PLANNER_STARTED", "EXPLICIT_OPERATOR_RUN")
        result = self.get(package.target.id, run_id)
        assert result is not None
        return result

    def get(self, target_id: str, run_id: str) -> PlannerRun | None:
        if not _ID.fullmatch(run_id) or not run_id.startswith("PLRUN-"):
            raise ValueError("Invalid planner run ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM planner_runs WHERE target_id=? AND run_id=?",
                             (target_id, run_id)).fetchone()
        return self._run(row) if row else None

    def list(self, target_id: str, *, limit: int = 20) -> tuple[PlannerRun, ...]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Invalid planner page size")
        with self.store._connection() as db:
            rows = db.execute("SELECT * FROM planner_runs WHERE target_id=? "
                              "ORDER BY created_at DESC,run_id DESC LIMIT ?",
                              (target_id, limit)).fetchall()
        return tuple(self._run(row) for row in rows)

    def transition(self, target_id: str, run_id: str, status: PlannerStatus,
                   reason: str, *, expected: tuple[PlannerStatus, ...] | None = None) -> PlannerRun:
        if not _CODE.fullmatch(reason):
            raise ValueError("Invalid planner reason")
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM planner_runs WHERE target_id=? AND run_id=?",
                             (target_id, run_id)).fetchone()
            if row is None:
                raise LookupError("Planner run not found")
            before = PlannerStatus(row["status"])
            if before in TERMINAL_STATUSES or (expected is not None and before not in expected):
                raise ValueError("Planner state transition is not permitted")
            db.execute("UPDATE planner_runs SET status=?,stop_reason=?,updated_at=?,"
                       "started_at=COALESCE(started_at,?),finished_at=? WHERE run_id=?",
                       (status.value, reason if status in TERMINAL_STATUSES else None, at,
                        at if status is PlannerStatus.RUNNING else None,
                        at if status in TERMINAL_STATUSES else None, run_id))
            self._event(db, run_id, "STATUS_CHANGED", reason)
        result = self.get(target_id, run_id)
        assert result is not None
        return result

    def save_portfolio(self, run: PlannerRun, candidates: tuple[PlannerCandidate, ...],
                       readiness: dict[str, object], context_hash: str,
                       context: PlannerContext | None = None) -> PlannerRun:
        if not re.fullmatch(r"[0-9a-f]{64}", context_hash) or len(candidates) > run.limits.portfolio:
            raise ValueError("Invalid planner portfolio")
        if context is not None and (context.target_id != run.target_id or
                                    context.package_id != run.package_id or
                                    context.snapshot_hash != context_hash):
            raise ValueError("Planner context does not match its run")
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT status FROM planner_runs WHERE run_id=? AND target_id=?",
                                 (run.id, run.target_id)).fetchone()
            if current is None or current[0] not in {"LOADING_CONTEXT", "RANKING"}:
                raise ValueError("Planner portfolio cannot be replaced")
            if db.execute("SELECT 1 FROM planner_candidates WHERE run_id=? LIMIT 1", (run.id,)).fetchone():
                raise ValueError("Planner portfolio is immutable")
            if context is not None:
                for kind, refs in context.audit_refs():
                    if len(refs) > 20 or any(not _REF.fullmatch(ref) for ref in refs):
                        raise ValueError("Invalid planner context references")
                    for ref in refs:
                        if kind == "RESEARCH":
                            exists = db.execute(
                                "SELECT 1 FROM research_briefs b JOIN research_requests r "
                                "ON r.brief_id=b.brief_id WHERE b.brief_id=? AND r.target_id=? "
                                "AND NOT EXISTS (SELECT 1 FROM research_brief_payload_retirements "
                                "WHERE brief_id=b.brief_id)",
                                (ref, run.target_id)).fetchone()
                        else:
                            table, id_column, target_column = {
                                "TARGET_PROFILE": ("target_profiles", "profile_id", "target_id"),
                                "BEHAVIOUR": ("behaviour_runs", "run_id", "target_id"),
                                "TRAFFIC": ("traffic_exchanges", "exchange_id", "target_id"),
                                "FACT": ("facts", "fact_id", "target_ref"),
                            }[kind]
                            exists = db.execute(
                                f"SELECT 1 FROM {table} WHERE {id_column}=? AND {target_column}=?",
                                (ref, run.target_id)).fetchone()
                        if exists is None:
                            raise ValueError("Planner context reference is missing or cross-target")
                    for offset in range(0, len(refs), 8):
                        self._event(db, run.id, "CONTEXT_REFERENCED", kind,
                                    refs=refs[offset:offset + 8])
            for item in candidates:
                if item.run_id != run.id or item.target_id != run.target_id or item.created_at or item.updated_at:
                    raise ValueError("Candidate target/run mismatch")
                if (not _ID.fullmatch(item.id) or not item.id.startswith("PLCAND-")
                        or not re.fullmatch(r"[0-9a-f]{64}", item.root_cause_key)
                        or not re.fullmatch(r"[0-9a-f]{64}", item.surface_hash)
                        or len(item.gaps) > 16 or len(item.source_refs) > 12
                        or (item.state_hash and not re.fullmatch(r"[0-9a-f]{64}", item.state_hash))):
                    raise ValueError("Invalid candidate metadata")
                db.execute("INSERT INTO planner_candidates(candidate_id,run_id,target_id,source_kind,"
                    "source_id,hypothesis_id,specialist,category,root_cause_key,surface_hash,score,"
                    "expected_value,priority,estimated_requests,estimated_browser,estimated_tokens,"
                    "risk,evidence_strength,freshness,gaps_json,reason_codes_json,source_refs_json,"
                    "skill_ids_json,handoffs_json,status,related_candidate_id,created_at,"
                    "updated_at,state_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (item.id, run.id, run.target_id, item.source_kind, item.source_id,
                     item.hypothesis_id, item.specialist.value, item.category,
                     item.root_cause_key, item.surface_hash, item.score, item.expected_value,
                     item.priority, item.estimated_requests, item.estimated_browser,
                     item.estimated_tokens, item.risk, item.evidence_strength,
                     item.freshness, _json(item.gaps), _json(item.reason_codes),
                     _json(item.source_refs), _json(item.skill_ids), _json(item.handoffs),
                     item.status.value, item.related_candidate_id, at, at, item.state_hash))
                db.execute("INSERT INTO planner_candidate_assessments(candidate_id,assessment_json) "
                           "VALUES (?,?)", (item.id, _json(item.assessment.to_dict(), 2048)))
                self._event(db, run.id, "CANDIDATE_SELECTED" if item.status is CandidateStatus.SELECTED
                            else "CANDIDATE_DEFERRED", item.reason_codes[0] if item.reason_codes else "RANKED",
                            candidate_id=item.id)
            by_source = {item.source_id: item.id for item in candidates}
            for item in candidates:
                if item.related_candidate_id:
                    if item.related_candidate_id not in {part.id for part in candidates}:
                        raise ValueError("Cross-run candidate relationship")
                    db.execute("INSERT INTO planner_candidate_relationships VALUES (?,?,?,?)",
                               (item.id, item.related_candidate_id, "DUPLICATE_OF", at))
                for handoff in item.handoffs:
                    related = by_source.get(handoff)
                    if related and related != item.id:
                        db.execute("INSERT OR IGNORE INTO planner_candidate_relationships "
                                   "VALUES (?,?,?,?)", (item.id, related, "ENRICHES", at))
            db.execute("UPDATE planner_runs SET status='READY',readiness_json=?,context_hash=?,"
                       "candidate_count=?,selected_count=?,updated_at=? WHERE run_id=?",
                       (_json(readiness), context_hash, len(candidates),
                        sum(item.status in {CandidateStatus.SELECTED, CandidateStatus.NEEDS_REFRESH}
                            for item in candidates), at, run.id))
        result = self.get(run.target_id, run.id)
        assert result is not None
        return result

    def candidates(self, target_id: str, run_id: str, *, limit: int = 100) -> tuple[PlannerCandidate, ...]:
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("Invalid candidate page size")
        with self.store._connection() as db:
            rows = db.execute("SELECT c.*,COALESCE(a.assessment_json,'{}') AS assessment_json "
                              "FROM planner_candidates c LEFT JOIN planner_candidate_assessments a "
                              "ON a.candidate_id=c.candidate_id WHERE c.target_id=? AND c.run_id=? "
                              "ORDER BY c.priority DESC,c.candidate_id LIMIT ?",
                              (target_id, run_id, limit)).fetchall()
        return tuple(self._candidate(row) for row in rows)

    def relationships(self, target_id: str, run_id: str,
                      candidate_id: str) -> tuple[dict[str, str], ...]:
        with self.store._connection() as db:
            rows = db.execute("SELECT l.related_id,l.relation,l.created_at FROM "
                              "planner_candidate_relationships l JOIN planner_candidates c "
                              "ON c.candidate_id=l.candidate_id WHERE c.target_id=? "
                              "AND c.run_id=? AND c.candidate_id=? ORDER BY l.relation,l.related_id "
                              "LIMIT 24", (target_id, run_id, candidate_id)).fetchall()
        return tuple(dict(row) for row in rows)

    def add_relation(self, target_id: str, run_id: str, candidate_id: str,
                     related_id: str, relation: str) -> None:
        allowed = {"DUPLICATE_OF", "VARIANT_OF", "DEPENDS_ON", "BLOCKED_BY",
                   "ENRICHES", "SHARES_ROOT_CAUSE", "SUPERSEDED_BY"}
        if relation not in allowed or candidate_id == related_id:
            raise ValueError("Invalid planner relation")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT candidate_id FROM planner_candidates WHERE target_id=? "
                              "AND run_id=? AND candidate_id IN (?,?)",
                              (target_id, run_id, candidate_id, related_id)).fetchall()
            if len(rows) != 2:
                raise ValueError("Cross-run planner relation")
            db.execute("INSERT OR IGNORE INTO planner_candidate_relationships VALUES (?,?,?,?)",
                       (candidate_id, related_id, relation, _now()))
            self._event(db, run_id, "CANDIDATE_RELATED", relation,
                        candidate_id=candidate_id)

    def supersede_stale(self, run: PlannerRun, stale: PlannerCandidate,
                        refresh_task: PlannerTask, successor: PlannerCandidate) -> PlannerCandidate:
        """Atomically replace one unstarted stale branch with its refreshed source."""
        if (stale.run_id != run.id or successor.run_id != run.id or
                stale.target_id != run.target_id or successor.target_id != run.target_id or
                stale.specialist is not successor.specialist or
                stale.source_kind != successor.source_kind or
                stale.source_id == successor.source_id or
                successor.status is not CandidateStatus.SELECTED or
                successor.plan_id or successor.plan_run_id or successor.hypothesis_id or
                not _ID.fullmatch(successor.id) or not successor.id.startswith("PLCAND-") or
                not re.fullmatch(r"[0-9a-f]{64}", successor.root_cause_key) or
                not re.fullmatch(r"[0-9a-f]{64}", successor.surface_hash) or
                (successor.state_hash and not re.fullmatch(r"[0-9a-f]{64}", successor.state_hash)) or
                len(successor.gaps) > 16 or len(successor.source_refs) > 12):
            raise ValueError("Invalid refreshed planner candidate")
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT * FROM planner_runs WHERE run_id=? AND target_id=?",
                                 (run.id, run.target_id)).fetchone()
            old = db.execute("SELECT * FROM planner_candidates WHERE run_id=? AND target_id=? "
                             "AND candidate_id=?", (run.id, run.target_id, stale.id)).fetchone()
            task = db.execute("SELECT * FROM planner_tasks WHERE run_id=? AND candidate_id=? "
                              "AND task_id=?", (run.id, stale.id, refresh_task.id)).fetchone()
            if (current is None or current["status"] not in {"READY", "RUNNING"} or
                    old is None or old["status"] != "NEEDS_REFRESH" or
                    old["plan_id"] or old["plan_run_id"] or
                    task is None or task["task_type"] not in {"REFRESH_ASSET", "REFRESH_TRAFFIC"} or
                    task["status"] != "RUNNING"):
                raise ValueError("Stale branch is not eligible for replacement")
            existing = db.execute("SELECT 1 FROM planner_candidates WHERE run_id=? "
                                  "AND source_kind=? AND source_id=?", (run.id,
                                  successor.source_kind, successor.source_id)).fetchone()
            limits = PlannerLimits(**json.loads(current["limits_json"]))
            if (existing or current["candidate_count"] >= min(200, limits.portfolio + limits.candidates)
                    or db.execute("SELECT 1 FROM planner_candidate_relationships WHERE "
                                  "candidate_id=? AND relation='SUPERSEDED_BY' LIMIT 1",
                                  (stale.id,)).fetchone()):
                raise ValueError("Refreshed branch already exists or portfolio is full")
            db.execute("INSERT INTO planner_candidates(candidate_id,run_id,target_id,source_kind,"
                "source_id,hypothesis_id,specialist,category,root_cause_key,surface_hash,score,"
                "expected_value,priority,estimated_requests,estimated_browser,estimated_tokens,"
                "risk,evidence_strength,freshness,gaps_json,reason_codes_json,source_refs_json,"
                "skill_ids_json,handoffs_json,status,created_at,updated_at,state_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (successor.id, run.id, run.target_id, successor.source_kind,
                 successor.source_id, None, successor.specialist.value, successor.category,
                 successor.root_cause_key, successor.surface_hash, successor.score,
                 successor.expected_value, successor.priority, successor.estimated_requests,
                 successor.estimated_browser, successor.estimated_tokens, successor.risk,
                 successor.evidence_strength, successor.freshness, _json(successor.gaps),
                 _json(successor.reason_codes), _json(successor.source_refs),
                 _json(successor.skill_ids), _json(successor.handoffs),
                 successor.status.value, at, at, successor.state_hash))
            db.execute("INSERT INTO planner_candidate_assessments(candidate_id,assessment_json) "
                       "VALUES (?,?)", (successor.id,
                                       _json(successor.assessment.to_dict(), 2048)))
            db.execute("UPDATE planner_candidates SET status='SKIPPED',updated_at=? "
                       "WHERE candidate_id=?", (at, stale.id))
            db.execute("UPDATE planner_tasks SET status='SKIPPED',reason_code='SOURCE_SUPERSEDED',"
                       "updated_at=?,finished_at=? WHERE candidate_id=? AND task_id!=? "
                       "AND status IN ('PENDING','READY','WAITING')",
                       (at, at, stale.id, refresh_task.id))
            db.execute("INSERT INTO planner_candidate_relationships VALUES (?,?,?,?)",
                       (stale.id, successor.id, "SUPERSEDED_BY", at))
            db.execute("UPDATE planner_runs SET candidate_count=candidate_count+1,updated_at=? "
                       "WHERE run_id=?", (at, run.id))
            self._event(db, run.id, "CANDIDATE_SUPERSEDED", "SOURCE_REFRESHED",
                        candidate_id=successor.id, task_id=refresh_task.id)
        result = self.candidate(run.target_id, run.id, successor.id)
        assert result is not None
        return result

    def candidate(self, target_id: str, run_id: str, candidate_id: str) -> PlannerCandidate | None:
        with self.store._connection() as db:
            row = db.execute("SELECT c.*,COALESCE(a.assessment_json,'{}') AS assessment_json "
                             "FROM planner_candidates c LEFT JOIN planner_candidate_assessments a "
                             "ON a.candidate_id=c.candidate_id WHERE c.target_id=? AND c.run_id=? "
                             "AND c.candidate_id=?", (target_id, run_id, candidate_id)).fetchone()
        return self._candidate(row) if row else None

    def update_candidate(self, target_id: str, run_id: str, candidate_id: str, *,
                         status: CandidateStatus | None = None,
                         hypothesis_id: str | None = None, plan_id: str | None = None,
                         plan_run_id: str | None = None, validation_id: str | None = None,
                         finding_id: str | None = None, reason: str = "STATE_UPDATED") -> PlannerCandidate:
        if not _CODE.fullmatch(reason):
            raise ValueError("Invalid candidate reason")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM planner_candidates WHERE target_id=? AND run_id=? "
                             "AND candidate_id=?", (target_id, run_id, candidate_id)).fetchone()
            if row is None:
                raise LookupError("Planner candidate not found")
            fields = {"status": status.value if status else row["status"],
                      "hypothesis_id": hypothesis_id or row["hypothesis_id"],
                      "plan_id": plan_id or row["plan_id"],
                      "plan_run_id": plan_run_id or row["plan_run_id"],
                      "validation_id": validation_id or row["validation_id"],
                      "finding_id": finding_id or row["finding_id"]}
            for table, key, value in (("hypotheses", "hypothesis_id", fields["hypothesis_id"]),
                                      ("skill_plans", "plan_id", fields["plan_id"]),
                                      ("plan_runs", "run_id", fields["plan_run_id"]),
                                      ("validations", "validation_id", fields["validation_id"]),
                                      ("findings", "finding_id", fields["finding_id"])):
                if value and db.execute(f"SELECT 1 FROM {table} WHERE {key}=? AND target_id=?",
                                        (value, target_id)).fetchone() is None:
                    raise ValueError("Cross-target planner link")
            if fields["plan_id"] and fields["hypothesis_id"]:
                linked = db.execute("SELECT hypothesis_id FROM skill_plans WHERE plan_id=?",
                                    (fields["plan_id"],)).fetchone()
                if linked is None or linked[0] != fields["hypothesis_id"]:
                    raise ValueError("Planner plan/hypothesis mismatch")
            if fields["plan_id"] and fields["plan_run_id"]:
                linked = db.execute("SELECT plan_id FROM plan_runs WHERE run_id=?",
                                    (fields["plan_run_id"],)).fetchone()
                if linked is None or linked[0] != fields["plan_id"]:
                    raise ValueError("Planner plan/run mismatch")
            if fields["plan_run_id"] and fields["validation_id"]:
                linked = db.execute("SELECT run_id FROM validations WHERE validation_id=?",
                                    (fields["validation_id"],)).fetchone()
                if linked is None or linked[0] != fields["plan_run_id"]:
                    raise ValueError("Planner validation/run mismatch")
            if fields["validation_id"] and fields["finding_id"]:
                linked = db.execute("SELECT validation_id FROM findings WHERE finding_id=?",
                                    (fields["finding_id"],)).fetchone()
                if linked is None or linked[0] != fields["validation_id"]:
                    raise ValueError("Planner finding/validation mismatch")
            db.execute("UPDATE planner_candidates SET status=:status,hypothesis_id=:hypothesis_id,"
                       "plan_id=:plan_id,"
                       "plan_run_id=:plan_run_id,validation_id=:validation_id,"
                       "finding_id=:finding_id,updated_at=:updated_at WHERE candidate_id=:candidate_id",
                       {**fields, "updated_at": _now(), "candidate_id": candidate_id})
            self._event(db, run_id, "CANDIDATE_UPDATED", reason, candidate_id=candidate_id)
        result = self.candidate(target_id, run_id, candidate_id)
        assert result is not None
        return result

    def override(self, target_id: str, run_id: str, candidate_id: str, override: CandidateOverride,
                 *, specialist: Specialist | None = None, skill_id: str | None = None,
                 status: CandidateStatus | None = None, priority: int | None = None,
                 estimated_requests: int | None = None,
                 estimated_browser: int | None = None) -> PlannerCandidate:
        if priority is not None and (type(priority) is not int or not 0 <= priority <= 100):
            raise ValueError("Invalid manual priority")
        if any(value is not None and (type(value) is not int or not 0 <= value <= 100)
               for value in (estimated_requests, estimated_browser)):
            raise ValueError("Invalid manual budget estimate")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT c.*,r.status AS run_status FROM planner_candidates c "
                             "JOIN planner_runs r ON r.run_id=c.run_id WHERE c.target_id=? "
                             "AND c.run_id=? AND c.candidate_id=?", (target_id, run_id, candidate_id)).fetchone()
            if row is None:
                raise LookupError("Planner candidate not found")
            if row["run_status"] not in {"READY", "PAUSED"} or row["status"] in {
                    "PLANNED", "RUNNING", "VALIDATED", "REJECTED", "DUPLICATE"}:
                raise ValueError("Candidate cannot be overridden now")
            if skill_id and (len(skill_id) > 80 or not re.fullmatch(r"[a-z][a-z0-9-]{2,79}", skill_id)):
                raise ValueError("Invalid skill override")
            db.execute("UPDATE planner_candidates SET override=?,override_specialist=?,"
                       "override_skill_id=?,specialist=?,estimated_requests=?,estimated_browser=?,"
                       "status=?,priority=?,updated_at=? WHERE candidate_id=?",
                       (override.value, specialist.value if specialist else row["override_specialist"],
                        skill_id if skill_id is not None else row["override_skill_id"],
                        specialist.value if specialist else row["specialist"],
                        row["estimated_requests"] if estimated_requests is None else estimated_requests,
                        row["estimated_browser"] if estimated_browser is None else estimated_browser,
                        (status.value if status else CandidateStatus.SKIPPED.value
                         if override is CandidateOverride.EXCLUDE else row["status"]),
                        row["priority"] if priority is None else priority, _now(), candidate_id))
            if priority is not None:
                db.execute("UPDATE planner_tasks SET priority=?,updated_at=? WHERE candidate_id=? "
                           "AND status IN ('PENDING','READY','WAITING')",
                           (priority, _now(), candidate_id))
            self._event(db, run_id, "MANUAL_OVERRIDE", override.value, candidate_id=candidate_id)
        result = self.candidate(target_id, run_id, candidate_id)
        assert result is not None
        return result

    def add_task(self, run: PlannerRun, candidate: PlannerCandidate, task_type: PlannerTaskType,
                 *, dependencies: tuple[str, ...] = (), priority: int | None = None,
                 budget: dict[str, int] | None = None) -> PlannerTask:
        if candidate.run_id != run.id or candidate.target_id != run.target_id or len(dependencies) > 6:
            raise ValueError("Task/run mismatch")
        task_id, at = "PLTASK-" + uuid.uuid4().hex, _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT task_id FROM planner_tasks WHERE candidate_id=? AND task_type=?",
                                  (candidate.id, task_type.value)).fetchone()
            if existing:
                task_id = existing[0]
            else:
                for dep in dependencies:
                    row = db.execute("SELECT run_id FROM planner_tasks WHERE task_id=?", (dep,)).fetchone()
                    if row is None or row[0] != run.id:
                        raise ValueError("Invalid task dependency")
                db.execute("INSERT INTO planner_tasks(task_id,run_id,candidate_id,task_type,status,"
                           "priority,budget_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                           (task_id, run.id, candidate.id, task_type.value,
                            PlannerTaskStatus.PENDING.value if dependencies else PlannerTaskStatus.READY.value,
                            candidate.priority if priority is None else priority,
                            _json(budget or {}), at, at))
                for dep in dependencies:
                    db.execute("INSERT INTO planner_task_dependencies(task_id,depends_on) VALUES (?,?)",
                               (task_id, dep))
                self._event(db, run.id, "TASK_CREATED", task_type.value,
                            candidate_id=candidate.id, task_id=task_id)
        result = self.task(run.target_id, run.id, task_id)
        assert result is not None
        return result

    def task(self, target_id: str, run_id: str, task_id: str) -> PlannerTask | None:
        with self.store._connection() as db:
            row = db.execute("SELECT t.* FROM planner_tasks t JOIN planner_runs r ON r.run_id=t.run_id "
                             "WHERE r.target_id=? AND t.run_id=? AND t.task_id=?",
                             (target_id, run_id, task_id)).fetchone()
            return self._task(db, row) if row else None

    def tasks(self, target_id: str, run_id: str, *, limit: int = 100) -> tuple[PlannerTask, ...]:
        if type(limit) is not int or not 1 <= limit <= MAX_RUN_TASKS:
            raise ValueError("Invalid task page size")
        with self.store._connection() as db:
            rows = db.execute("SELECT t.* FROM planner_tasks t JOIN planner_runs r ON r.run_id=t.run_id "
                              "WHERE r.target_id=? AND t.run_id=? "
                              "ORDER BY t.priority DESC,t.created_at,t.task_id LIMIT ?",
                              (target_id, run_id, limit)).fetchall()
            return tuple(self._task(db, row) for row in rows)

    def claim_task(self, target_id: str, run_id: str, task_id: str) -> PlannerTask | None:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute("SELECT status FROM planner_runs WHERE run_id=? AND target_id=?",
                             (run_id, target_id)).fetchone()
            task = db.execute("SELECT * FROM planner_tasks WHERE task_id=? AND run_id=?",
                              (task_id, run_id)).fetchone()
            if run is None or task is None or run[0] not in {"READY", "RUNNING"} or task["status"] not in {
                    "READY", "PENDING"}:
                return None
            approved_child_resume = (
                task["task_type"] == PlannerTaskType.RUN_PLAN.value and
                task["reason_code"] == "APPROVAL_RESOLVED" and
                self._approved_child_ready(db, target_id, run_id, task["candidate_id"]))
            if task["attempt"] >= 2 and not approved_child_resume:
                return None
            if db.execute("SELECT 1 FROM planner_task_dependencies d JOIN planner_tasks p "
                          "ON p.task_id=d.depends_on WHERE d.task_id=? AND p.status!='COMPLETED' LIMIT 1",
                          (task_id,)).fetchone():
                return None
            if db.execute("SELECT 1 FROM planner_tasks WHERE run_id=? AND status='RUNNING' LIMIT 1",
                          (run_id,)).fetchone():
                return None
            at = _now()
            db.execute("UPDATE planner_tasks SET status='RUNNING',attempt=attempt+?,"
                       "started_at=COALESCE(started_at,?),updated_at=? WHERE task_id=?",
                       (0 if approved_child_resume and task["attempt"] >= 2 else 1,
                        at, at, task_id))
            db.execute("UPDATE planner_runs SET status='RUNNING',started_at=COALESCE(started_at,?),"
                       "updated_at=? WHERE run_id=?", (at, at, run_id))
            self._event(db, run_id, "TASK_STARTED", task["task_type"],
                        candidate_id=task["candidate_id"], task_id=task_id)
        return self.task(target_id, run_id, task_id)

    @staticmethod
    def _approved_child_ready(db: sqlite3.Connection, target_id: str,
                              run_id: str, candidate_id: str) -> bool:
        row = db.execute(
            "SELECT p.status FROM planner_candidates c JOIN plan_runs p "
            "ON p.run_id=c.plan_run_id AND p.target_id=c.target_id "
            "AND p.plan_id=c.plan_id WHERE c.target_id=? AND c.run_id=? "
            "AND c.candidate_id=? LIMIT 1",
            (target_id, run_id, candidate_id)).fetchone()
        return row is not None and row["status"] in {"READY", "RUNNING", "COMPLETED"}

    def wake_waiting_task(self, target_id: str, run_id: str, task_id: str,
                          reason: str) -> PlannerTask:
        if not _CODE.fullmatch(reason):
            raise ValueError("Invalid planner reason")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT t.* FROM planner_tasks t JOIN planner_runs r ON r.run_id=t.run_id "
                             "WHERE r.target_id=? AND t.run_id=? AND t.task_id=?",
                             (target_id, run_id, task_id)).fetchone()
            if row is None or row["status"] != "WAITING":
                raise ValueError("Waiting task cannot be retried")
            approved_child_resume = (
                row["task_type"] == PlannerTaskType.RUN_PLAN.value and
                row["reason_code"] == "APPROVAL_PENDING" and
                reason == "APPROVAL_RESOLVED" and
                self._approved_child_ready(db, target_id, run_id, row["candidate_id"]))
            if approved_child_resume:
                resumed = db.execute(
                    "SELECT COUNT(*) FROM planner_events WHERE run_id=? AND task_id=? "
                    "AND event_type='TASK_REQUEUED' AND reason_code='APPROVAL_RESOLVED'",
                    (run_id, task_id)).fetchone()[0]
                approved_child_resume = resumed < MAX_APPROVED_CHILD_RESUMES
            if row["attempt"] >= 2 and not approved_child_resume:
                raise ValueError("Waiting task cannot be retried")
            db.execute("UPDATE planner_tasks SET status='READY',reason_code=?,updated_at=? "
                       "WHERE task_id=?", (reason, _now(), task_id))
            self._event(db, run_id, "TASK_REQUEUED", reason,
                        candidate_id=row["candidate_id"], task_id=task_id)
        result = self.task(target_id, run_id, task_id)
        assert result is not None
        return result

    def skip_candidate_tasks(self, target_id: str, run_id: str, candidate_id: str,
                             reason: str) -> None:
        if not _CODE.fullmatch(reason):
            raise ValueError("Invalid planner reason")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM planner_candidates WHERE target_id=? AND run_id=? "
                          "AND candidate_id=?", (target_id, run_id, candidate_id)).fetchone() is None:
                raise LookupError("Planner candidate not found")
            if db.execute("SELECT 1 FROM planner_tasks WHERE candidate_id=? AND status='RUNNING'",
                          (candidate_id,)).fetchone():
                raise ValueError("Cannot skip active candidate")
            db.execute("UPDATE planner_tasks SET status='SKIPPED',reason_code=?,updated_at=?,"
                       "finished_at=? WHERE candidate_id=? AND status IN ('PENDING','READY','WAITING')",
                       (reason, _now(), _now(), candidate_id))
            self._event(db, run_id, "BRANCH_SKIPPED", reason, candidate_id=candidate_id)

    def cancel_remaining_tasks(self, target_id: str, run_id: str) -> None:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM planner_runs WHERE target_id=? AND run_id=?",
                          (target_id, run_id)).fetchone() is None:
                raise LookupError("Planner run not found")
            at = _now()
            db.execute("UPDATE planner_tasks SET status='CANCELLED',reason_code='PLANNER_CANCELLED',"
                       "updated_at=?,finished_at=? WHERE run_id=? AND status IN "
                       "('PENDING','READY','WAITING')", (at, at, run_id))
            self._event(db, run_id, "TASKS_CANCELLED", "PLANNER_CANCELLED")

    def bump_metrics(self, target_id: str, run_id: str, **increments: int) -> PlannerRun:
        allowed = {"plans_created", "plans_executed", "validations", "findings",
                   "manual_reviews", "research_requests"}
        if not increments or any(key not in allowed or type(value) is not int or value < 0 or value > 1
                                 for key, value in increments.items()):
            raise ValueError("Invalid planner metric")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM planner_runs WHERE target_id=? AND run_id=?",
                          (target_id, run_id)).fetchone() is None:
                raise LookupError("Planner run not found")
            updates = ",".join(f"{key}={key}+?" for key in increments)
            db.execute(f"UPDATE planner_runs SET {updates},updated_at=? WHERE run_id=?",
                       (*increments.values(), _now(), run_id))
            self._event(db, run_id, "METRIC_UPDATED", "OUTCOME_RECORDED")
        result = self.get(target_id, run_id)
        assert result is not None
        return result

    def recount_selected(self, target_id: str, run_id: str) -> PlannerRun:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM planner_runs WHERE target_id=? AND run_id=?",
                          (target_id, run_id)).fetchone() is None:
                raise LookupError("Planner run not found")
            count = db.execute("SELECT count(*) FROM planner_candidates WHERE target_id=? "
                               "AND run_id=? AND status IN ('SELECTED','NEEDS_REFRESH',"
                               "'PLANNED','RUNNING','WAITING','VALIDATED')",
                               (target_id, run_id)).fetchone()[0]
            db.execute("UPDATE planner_runs SET selected_count=?,updated_at=? WHERE run_id=?",
                       (count, _now(), run_id))
        result = self.get(target_id, run_id)
        assert result is not None
        return result

    def finish_task(self, target_id: str, run_id: str, task_id: str,
                    status: PlannerTaskStatus, reason: str, *, result_ref: str | None = None) -> PlannerTask:
        if status in {PlannerTaskStatus.PENDING, PlannerTaskStatus.READY, PlannerTaskStatus.RUNNING}:
            raise ValueError("Task finish status is not final or waiting")
        if not _CODE.fullmatch(reason) or (result_ref and not _REF.fullmatch(result_ref)):
            raise ValueError("Invalid task result")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            task = db.execute("SELECT t.* FROM planner_tasks t JOIN planner_runs r ON r.run_id=t.run_id "
                              "WHERE r.target_id=? AND t.run_id=? AND t.task_id=?",
                              (target_id, run_id, task_id)).fetchone()
            if task is None or task["status"] not in {"RUNNING", "WAITING"}:
                raise ValueError("Task is not claimable for completion")
            at = _now()
            db.execute("UPDATE planner_tasks SET status=?,result_ref=?,reason_code=?,updated_at=?,"
                       "finished_at=? WHERE task_id=?",
                       (status.value, result_ref, reason, at,
                        at if status is not PlannerTaskStatus.WAITING else None, task_id))
            self._event(db, run_id, "TASK_FINISHED", reason,
                        candidate_id=task["candidate_id"], task_id=task_id,
                        refs=(result_ref,) if result_ref else ())
        result = self.task(target_id, run_id, task_id)
        assert result is not None
        return result

    def reserve_budget(self, target_id: str, run_id: str, *, requests: int = 0,
                       browser_actions: int = 0, tokens: int = 0) -> bool:
        if any(type(value) is not int or value < 0 for value in (requests, browser_actions, tokens)):
            raise ValueError("Invalid budget reservation")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM planner_runs WHERE target_id=? AND run_id=?",
                             (target_id, run_id)).fetchone()
            if row is None or row["status"] not in {"RANKING", "READY", "RUNNING"}:
                return False
            limits = PlannerLimits(**json.loads(row["limits_json"]))
            usage = PlannerUsage(**json.loads(row["usage_json"]))
            if (usage.requests + requests > limits.requests - limits.cleanup_reserve
                    or usage.browser_actions + browser_actions > limits.browser_actions
                    or usage.tokens + tokens > limits.tokens):
                self._event(db, run_id, "BUDGET_EXHAUSTED", "BUDGET_TOO_LOW")
                return False
            new = PlannerUsage(usage.requests + requests,
                               usage.browser_actions + browser_actions, usage.tokens + tokens)
            db.execute("UPDATE planner_runs SET usage_json=?,updated_at=? WHERE run_id=?",
                       (_json(new.to_dict()), _now(), run_id))
            self._event(db, run_id, "BUDGET_RESERVED", "PER_CANDIDATE_CAP")
            return True

    def reserve_task_budget(self, target_id: str, run_id: str, task_id: str, *,
                            requests: int = 0, browser_actions: int = 0,
                            tokens: int = 0) -> bool:
        values = (requests, browser_actions, tokens)
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("Invalid task budget")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT r.*,t.task_type,t.status AS task_status FROM planner_runs r "
                             "JOIN planner_tasks t ON t.run_id=r.run_id WHERE r.target_id=? "
                             "AND r.run_id=? AND t.task_id=?", (target_id, run_id, task_id)).fetchone()
            if row is None or row["task_type"] not in {"RUN_PLAN", "CREATE_DISPOSABLE_OBJECT",
                                                       "REQUEST_RESEARCH", "REFRESH_ASSET"}:
                raise ValueError("Task cannot reserve budget")
            prior = db.execute("SELECT requests,browser_actions,tokens FROM "
                               "planner_budget_reservations WHERE task_id=?", (task_id,)).fetchone()
            if prior is not None:
                if tuple(prior) != values:
                    raise ValueError("Task budget cannot change after reservation")
                return True
            if row["status"] not in {"READY", "RUNNING"} or row["task_status"] != "RUNNING":
                return False
            limits = PlannerLimits(**json.loads(row["limits_json"]))
            usage = PlannerUsage(**json.loads(row["usage_json"]))
            if (usage.requests + requests > limits.requests - limits.cleanup_reserve
                    or usage.browser_actions + browser_actions > limits.browser_actions
                    or usage.tokens + tokens > limits.tokens):
                self._event(db, run_id, "BUDGET_EXHAUSTED", "BUDGET_TOO_LOW",
                            task_id=task_id)
                return False
            next_usage = PlannerUsage(usage.requests + requests,
                                      usage.browser_actions + browser_actions,
                                      usage.tokens + tokens)
            db.execute("INSERT INTO planner_budget_reservations VALUES (?,?,?,?,?,?)",
                       (task_id, run_id, *values, _now()))
            db.execute("UPDATE planner_runs SET usage_json=?,updated_at=? WHERE run_id=?",
                       (_json(next_usage.to_dict()), _now(), run_id))
            self._event(db, run_id, "BUDGET_RESERVED", "PER_TASK_CAP", task_id=task_id)
            return True

    def remember_branch(self, target_id: str, root_cause_key: str, state_hash: str,
                        outcome: str, run_id: str, reason: str) -> None:
        if (not re.fullmatch(r"[0-9a-f]{64}", root_cause_key)
                or not re.fullmatch(r"[0-9a-f]{64}", state_hash)
                or outcome not in {"CONFIRMED", "DUPLICATE", "REJECTED", "FAILED",
                                   "MANUAL_REVIEW", "BLOCKED"}
                or not _CODE.fullmatch(reason)):
            raise ValueError("Invalid branch memory")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM planner_runs WHERE target_id=? AND run_id=?",
                          (target_id, run_id)).fetchone() is None:
                raise ValueError("Cross-target branch memory")
            db.execute("INSERT INTO planner_branch_memory(target_id,root_cause_key,"
                       "state_hash,outcome,source_run_id,reason_code,recorded_at) "
                       "VALUES (?,?,?,?,?,?,?) ON CONFLICT(target_id,root_cause_key,"
                       "state_hash,outcome) DO NOTHING", (target_id, root_cause_key, state_hash,
                       outcome, run_id, reason, _now()))
            self._event(db, run_id, "BRANCH_REMEMBERED", reason)

    def branch_memory(self, target_id: str, root_cause_key: str,
                      state_hash: str) -> tuple[dict[str, str], ...]:
        with self.store._connection() as db:
            rows = db.execute("SELECT outcome,source_run_id,reason_code,recorded_at FROM "
                              "planner_branch_memory WHERE target_id=? AND root_cause_key=? "
                              "AND state_hash=? ORDER BY recorded_at DESC LIMIT 8",
                              (target_id, root_cause_key, state_hash)).fetchall()
        return tuple(dict(row) for row in rows)

    def events(self, target_id: str, run_id: str, *, limit: int = 100) -> tuple[dict[str, object], ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid event page size")
        with self.store._connection() as db:
            rows = db.execute("SELECT e.* FROM planner_events e JOIN planner_runs r ON r.run_id=e.run_id "
                              "WHERE r.target_id=? AND e.run_id=? ORDER BY e.event_id DESC LIMIT ?",
                              (target_id, run_id, limit)).fetchall()
        return tuple({**dict(row), "safe_refs": json.loads(row["safe_refs_json"])} for row in rows)

    def metrics(self, target_id: str, run_id: str) -> dict[str, object]:
        run = self.get(target_id, run_id)
        if run is None:
            raise LookupError("Planner run not found")
        with self.store._connection() as db:
            rows = db.execute("SELECT specialist,status,count(*) AS count FROM planner_candidates "
                              "WHERE target_id=? AND run_id=? GROUP BY specialist,status",
                              (target_id, run_id)).fetchall()
            task_rows = db.execute("SELECT task_type,status,count(*) AS count FROM planner_tasks "
                                   "WHERE run_id=? GROUP BY task_type,status", (run_id,)).fetchall()
            child_ids = "SELECT DISTINCT plan_run_id FROM planner_candidates WHERE target_id=? " \
                        "AND run_id=? AND plan_run_id IS NOT NULL"
            child_requests = db.execute(
                f"SELECT COALESCE(SUM(requests_consumed),0) FROM plan_runs WHERE run_id IN ({child_ids})",
                (target_id, run_id)).fetchone()[0]
            browser_proofs = db.execute(
                f"SELECT count(*) FROM plan_run_steps WHERE step_type='VERIFY_BROWSER' "
                f"AND status='COMPLETED' AND run_id IN ({child_ids})",
                (target_id, run_id)).fetchone()[0]
            browser_dispatches = db.execute(
                "SELECT COUNT(*) AS trials, COALESCE(SUM(variant LIKE 'FRESH_%'),0) AS fresh "
                "FROM (SELECT variant FROM plan_dom_dispatches WHERE run_id IN ("
                f"{child_ids}) UNION ALL SELECT variant FROM plan_message_dispatches "
                f"WHERE run_id IN ({child_ids}))",
                (target_id, run_id, target_id, run_id)).fetchone()
            research_rows = db.execute(
                "SELECT usage_json FROM research_requests WHERE request_id IN ("
                "SELECT result_ref FROM planner_tasks WHERE run_id=? AND "
                "task_type='REQUEST_RESEARCH' AND result_ref LIKE 'RREQ-%' "
                "UNION SELECT b.created_from_request FROM planner_tasks t "
                "JOIN research_briefs b ON b.brief_id=t.result_ref WHERE t.run_id=? "
                "AND t.task_type='REQUEST_RESEARCH')", (run_id, run_id)).fetchall()
        research_tokens = sum(
            int(usage.get("input_tokens_estimated", 0)) +
            int(usage.get("output_tokens_estimated", 0))
            for row in research_rows for usage in (json.loads(row[0]),))
        specialists: dict[str, dict[str, int]] = {}
        for row in rows:
            specialists.setdefault(row["specialist"], {})[row["status"]] = row["count"]
        tasks: dict[str, dict[str, int]] = {}
        for row in task_rows:
            tasks.setdefault(row["task_type"], {})[row["status"]] = row["count"]
        end = datetime.fromisoformat(run.finished_at) if run.finished_at else datetime.now(timezone.utc)
        duration = max(0, int((end - datetime.fromisoformat(run.created_at)).total_seconds()))
        return {"considered": run.candidate_count, "selected": run.selected_count,
                "deferred": sum(counts.get("DEFERRED", 0) for counts in specialists.values()),
                "blocked": sum(counts.get("BLOCKED", 0) for counts in specialists.values()),
                "validations": run.validations, "confirmed_root_causes": run.findings,
                "rejected": sum(counts.get("REJECTED", 0) for counts in specialists.values()),
                "manual_reviews": run.manual_reviews, "research_requests": run.research_requests,
                "requests_reserved": run.usage.requests,
                "browser_actions_reserved": run.usage.browser_actions,
                "tokens_reserved": run.usage.tokens,
                "child_request_slots_consumed": child_requests,
                "browser_proof_steps_completed": browser_proofs,
                "browser_navigation_attempts_accounted": browser_dispatches["trials"],
                "browser_reload_attempts_accounted": 0,
                "runtime_proof_actions_accounted": browser_dispatches["trials"],
                "fresh_context_reproductions_accounted": browser_dispatches["fresh"],
                "research_tokens_estimated": research_tokens,
                "requests_per_confirmed": round(child_requests / run.findings, 2)
                    if run.findings else None,
                "duration_seconds": duration, "specialists": specialists, "tasks": tasks}

    def reconcile_interrupted(self) -> int:
        """Do not replay a child action whose completion could be ambiguous."""
        changed = 0
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT run_id,target_id,mode,status FROM planner_runs WHERE status IN "
                              "('CREATED','LOADING_CONTEXT','RANKING','RESOLVING_GAPS',"
                              "'READY','RUNNING')").fetchall()
            for row in rows:
                run_id, at = row["run_id"], _now()
                tasks = db.execute("SELECT task_id,candidate_id FROM planner_tasks WHERE run_id=? "
                                   "AND status='RUNNING'", (run_id,)).fetchall()
                if row["status"] in {"CREATED", "LOADING_CONTEXT", "RANKING"} and not tasks:
                    db.execute("UPDATE planner_runs SET status='FAILED',"
                               "stop_reason='INITIALIZATION_INTERRUPTED',updated_at=?,"
                               "finished_at=? WHERE run_id=?", (at, at, run_id))
                    self._event(db, run_id, "PLANNER_RECOVERED",
                                "INITIALIZATION_INTERRUPTED")
                    changed += 1
                    continue
                if (row["status"] == "READY" and not db.execute(
                        "SELECT 1 FROM planner_tasks WHERE run_id=? AND status IN "
                        "('PENDING','READY','RUNNING','WAITING') LIMIT 1",
                        (run_id,)).fetchone() and not db.execute(
                        "SELECT 1 FROM planner_candidates WHERE run_id=? AND "
                        "status IN ('SELECTED','NEEDS_REFRESH') LIMIT 1",
                        (run_id,)).fetchone()):
                    db.execute("UPDATE planner_runs SET status='COMPLETED',"
                               "stop_reason='ALL_BRANCHES_SETTLED',updated_at=?,"
                               "finished_at=? WHERE run_id=?", (at, at, run_id))
                    self._event(db, run_id, "PLANNER_RECOVERED", "EMPTY_RUN_COMPLETED")
                    changed += 1
                    continue
                if row["status"] == "READY" and not tasks:
                    continue
                for task in tasks:
                    db.execute("UPDATE planner_tasks SET status='WAITING',reason_code='AMBIGUOUS_RESTART',"
                               "updated_at=? WHERE task_id=?", (at, task["task_id"]))
                    self._event(db, run_id, "TASK_RECOVERED", "AMBIGUOUS_RESTART",
                                candidate_id=task["candidate_id"], task_id=task["task_id"])
                final_task = ("VALIDATE_RUN" if row["mode"] == "BOUNDED_AUTONOMOUS"
                              else "CREATE_PLAN")
                status = ("READY" if db.execute(
                    "SELECT 1 FROM planner_tasks WHERE run_id=? AND status IN ('READY','PENDING') "
                    "LIMIT 1", (run_id,)).fetchone() or (not tasks and db.execute(
                    "SELECT 1 FROM planner_candidates c WHERE c.run_id=? AND "
                    "c.status IN ('SELECTED','NEEDS_REFRESH') AND NOT EXISTS "
                    "(SELECT 1 FROM planner_tasks t WHERE t.candidate_id=c.candidate_id "
                    "AND t.task_type=?) LIMIT 1",
                    (run_id, final_task)).fetchone()) else
                    "WAITING_HUMAN" if tasks else "PAUSED")
                db.execute("UPDATE planner_runs SET status=?,updated_at=? WHERE run_id=?",
                           (status, at, run_id))
                self._event(db, run_id, "PLANNER_RECOVERED",
                            "SAFE_PENDING_RESUME" if status == "READY" else
                            "AMBIGUOUS_RESTART" if tasks else "SAFE_PAUSE")
                changed += 1
        return changed

    def restartable(self, *, after_run_id: str = "", limit: int = 50) -> tuple[PlannerRun, ...]:
        """Return only explicit runs with safe pending work, in bounded keyset pages."""
        if type(limit) is not int or not 1 <= limit <= 100 or (
                after_run_id and (not _ID.fullmatch(after_run_id) or
                                  not after_run_id.startswith("PLRUN-"))):
            raise ValueError("Invalid planner recovery cursor")
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT r.* FROM planner_runs r WHERE r.status='READY' AND r.run_id>? "
                "AND (EXISTS (SELECT 1 FROM planner_tasks t WHERE t.run_id=r.run_id "
                "AND t.status IN ('READY','PENDING','WAITING')) OR EXISTS "
                "(SELECT 1 FROM planner_candidates c WHERE c.run_id=r.run_id "
                "AND c.status IN ('SELECTED','NEEDS_REFRESH'))) "
                "ORDER BY r.run_id LIMIT ?", (after_run_id, limit)).fetchall()
        return tuple(self._run(row) for row in rows)
