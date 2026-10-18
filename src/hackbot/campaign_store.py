"""Transactional campaign ledger; child components retain execution authority."""

from __future__ import annotations

from datetime import datetime, timezone
import re
import sqlite3
import uuid

from .campaign_models import (
    CAMPAIGN_VERSION, Campaign, CampaignLimits, CampaignStatus, CampaignUsage,
    CampaignWork, CampaignWorkKind, CampaignWorkStatus, TERMINAL_CAMPAIGN_STATUSES,
)
from .planner_models import PlannerMode
from .store import EvidenceFactStore
from .target_package import TargetPackage


_CAMPAIGN_ID = re.compile(r"CMP-[0-9a-f]{32}\Z")
_WORK_ID = re.compile(r"CMPWORK-[0-9a-f]{32}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ACTOR = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
_CLEANUP_STATUSES = frozenset({
    "RUNNING", "PAUSED", "WAITING_LOGIN", "WAITING_APPROVAL",
    "WAITING_RESEARCH", "WAITING_HUMAN", "CANCELLED", "CLEANUP_REQUIRED",
    "BUDGET_EXHAUSTED", "TIME_EXHAUSTED",
})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def link_created_child(db: sqlite3.Connection, work_id: str | None, *,
                       kind: CampaignWorkKind, target_id: str, child_id: str) -> None:
    """Call inside the same transaction that creates a child run."""
    if work_id is None:
        return
    if not _WORK_ID.fullmatch(work_id):
        raise ValueError("Invalid campaign work ID")
    row = db.execute("SELECT w.campaign_id,w.cycle_number,c.status "
                     "FROM campaign_work AS w JOIN campaigns AS c "
                     "ON c.campaign_id=w.campaign_id WHERE w.work_id=? AND w.kind=? "
                     "AND w.status='INTENT' AND c.target_id=?",
                     (work_id, kind.value, target_id)).fetchone()
    if row is None or row["status"] != "RUNNING":
        raise ValueError("Campaign child intent is not current")
    db.execute("UPDATE campaign_work SET status='LINKED',child_id=?,updated_at=? "
               "WHERE work_id=?", (child_id, _now(), work_id))
    if kind is CampaignWorkKind.PLANNER:
        db.execute("UPDATE campaign_cycles SET planner_run_id=?,status='RUNNING',"
                   "updated_at=? WHERE campaign_id=? AND cycle_number=?",
                   (child_id, _now(), row["campaign_id"], row["cycle_number"]))
    CampaignStore._event(db, row["campaign_id"], "CHILD_LINKED", kind.value,
                         cycle=row["cycle_number"], work_id=work_id)


class CampaignStore:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    @staticmethod
    def _campaign(row: sqlite3.Row) -> Campaign:
        return Campaign(
            row["campaign_id"], row["target_id"], row["package_id"],
            row["package_version"], row["policy_hash"], PlannerMode(row["mode"]),
            CampaignStatus(row["status"]), row["requested_by"],
            CampaignLimits(row["max_cycles"], row["seconds_limit"], row["requests_limit"],
                           row["browser_limit"], row["research_limit"], row["tokens_limit"],
                           row["setup_limit"], row["cleanup_reserve"]),
            CampaignUsage(row["requests_used"], row["browser_used"],
                          row["research_used"], row["tokens_used"], row["setup_used"],
                          row["cleanup_used"]),
            row["current_cycle"], row["stop_reason"], row["readiness_code"],
            row["coverage_digest"], row["campaign_version"], row["created_at"],
            row["started_at"], row["updated_at"], row["finished_at"],
        )

    @staticmethod
    def _work(row: sqlite3.Row) -> CampaignWork:
        return CampaignWork(
            row["work_id"], row["campaign_id"], row["cycle_number"],
            CampaignWorkKind(row["kind"]), CampaignWorkStatus(row["status"]),
            row["child_id"], row["requests_allocated"], row["browser_allocated"],
            row["research_allocated"], row["tokens_allocated"], row["setup_allocated"],
            row["created_at"], row["updated_at"],
        )

    @staticmethod
    def _event(db: sqlite3.Connection, campaign_id: str, event: str, reason: str,
               *, cycle: int | None = None, work_id: str | None = None) -> None:
        if not _CODE.fullmatch(event) or not _CODE.fullmatch(reason):
            raise ValueError("Invalid campaign event")
        db.execute("INSERT INTO campaign_events(campaign_id,cycle_number,work_id,"
                   "event_type,reason_code,occurred_at) VALUES (?,?,?,?,?,?)",
                   (campaign_id, cycle, work_id, event, reason, _now()))

    def create(self, package: TargetPackage, mode: PlannerMode, limits: CampaignLimits,
               policy_hash: str, requested_by: str) -> Campaign:
        if (package.status.value != "TRACKED" or not _ACTOR.fullmatch(requested_by)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}:[0-9a-f]{64}", policy_hash)
                or not isinstance(mode, PlannerMode) or not isinstance(limits, CampaignLimits)):
            raise ValueError("Campaign requires a tracked Target Package and valid settings")
        campaign_id, at = "CMP-" + uuid.uuid4().hex, _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM registry_targets WHERE target_id=?",
                          (package.target.id,)).fetchone() is None:
                raise ValueError("Target is not registered")
            if db.execute("SELECT 1 FROM campaigns WHERE target_id=? AND status NOT IN "
                          "('COMPLETED','BLOCKED','FAILED','CANCELLED',"
                          "'BUDGET_EXHAUSTED','TIME_EXHAUSTED','CLEANUP_REQUIRED')",
                          (package.target.id,)).fetchone():
                raise ValueError("An active campaign already owns this target")
            db.execute(
                "INSERT INTO campaigns(campaign_id,target_id,package_id,package_version,"
                "policy_hash,mode,status,requested_by,max_cycles,seconds_limit,requests_limit,"
                "browser_limit,research_limit,tokens_limit,setup_limit,cleanup_reserve,"
                "campaign_version,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (campaign_id, package.target.id, package.id, package.version, policy_hash,
                 mode.value, CampaignStatus.CREATED.value, requested_by, limits.max_cycles,
                 limits.seconds, limits.requests, limits.browser_actions,
                 limits.research_requests, limits.tokens, limits.setup_objects,
                 limits.cleanup_reserve, CAMPAIGN_VERSION, at, at))
            self._event(db, campaign_id, "CREATED", "EXPLICIT_START")
        result = self.get(package.target.id, campaign_id)
        assert result is not None
        return result

    def get(self, target_id: str, campaign_id: str) -> Campaign | None:
        if not _CAMPAIGN_ID.fullmatch(campaign_id):
            raise ValueError("Invalid campaign ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM campaigns WHERE target_id=? AND campaign_id=?",
                             (target_id, campaign_id)).fetchone()
        return self._campaign(row) if row else None

    def find(self, campaign_id: str) -> Campaign | None:
        if not _CAMPAIGN_ID.fullmatch(campaign_id):
            raise ValueError("Invalid campaign ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM campaigns WHERE campaign_id=?",
                             (campaign_id,)).fetchone()
        return self._campaign(row) if row else None

    def list(self, *, target_id: str | None = None, limit: int = 30,
             before: str | None = None) -> tuple[Campaign, ...]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Invalid campaign page size")
        if before is not None and not _CAMPAIGN_ID.fullmatch(before):
            raise ValueError("Invalid campaign cursor")
        with self.store._connection() as db:
            anchor = db.execute("SELECT created_at,campaign_id FROM campaigns WHERE campaign_id=?",
                                (before,)).fetchone() if before else None
            if before and anchor is None:
                raise ValueError("Unknown campaign cursor")
            where = []
            args: list[object] = []
            if target_id is not None:
                where.append("target_id=?")
                args.append(target_id)
            if anchor is not None:
                where.append("(created_at,campaign_id)<(?,?)")
                args.extend(anchor)
            predicate = " WHERE " + " AND ".join(where) if where else ""
            rows = db.execute("SELECT * FROM campaigns" + predicate +
                              " ORDER BY created_at DESC,campaign_id DESC LIMIT ?",
                              (*args, limit)).fetchall()
        return tuple(self._campaign(row) for row in rows)

    def stats(self, target_id: str | None = None) -> dict[str, int]:
        predicate = " WHERE target_id=?" if target_id is not None else ""
        params = (target_id,) if target_id is not None else ()
        with self.store._connection() as db:
            row = db.execute(
                "SELECT count(*) AS started,"
                "sum(CASE WHEN status='COMPLETED' THEN 1 ELSE 0 END) AS completed,"
                "sum(CASE WHEN status='CANCELLED' THEN 1 ELSE 0 END) AS cancelled,"
                "sum(CASE WHEN status='CLEANUP_REQUIRED' THEN 1 ELSE 0 END) "
                "AS cleanup_required,"
                "sum(current_cycle) AS cycles, sum(requests_used+cleanup_used) AS requests,"
                "sum(browser_used) AS browser_actions,"
                "sum(research_used) AS research_requests,"
                "sum(tokens_used) AS tokens, sum(setup_used) AS setup_objects "
                "FROM campaigns" + predicate, params).fetchone()
        return {key: int(row[key] or 0) for key in row.keys()}

    def finding_counts(self, campaign_ids: tuple[str, ...]) -> dict[str, int]:
        if not campaign_ids:
            return {}
        if len(campaign_ids) > 50 or any(not _CAMPAIGN_ID.fullmatch(item)
                                         for item in campaign_ids):
            raise ValueError("Invalid campaign list")
        placeholders = ",".join("?" for _ in campaign_ids)
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT w.campaign_id,count(DISTINCT p.finding_id) AS findings "
                "FROM campaign_work AS w JOIN planner_candidates AS p "
                "ON p.run_id=w.child_id AND w.kind='PLANNER' "
                f"WHERE w.campaign_id IN ({placeholders}) AND p.finding_id IS NOT NULL "
                "GROUP BY w.campaign_id", campaign_ids).fetchall()
        return {row["campaign_id"]: int(row["findings"]) for row in rows}

    def transition(self, target_id: str, campaign_id: str, status: CampaignStatus,
                   reason: str, *, expected: tuple[CampaignStatus, ...] | None = None,
                   package: TargetPackage | None = None,
                   policy_hash: str | None = None,
                   readiness_code: str | None = None,
                   coverage_digest: str | None = None) -> Campaign:
        if (not isinstance(status, CampaignStatus) or not _CODE.fullmatch(reason)
                or (readiness_code is not None and not _CODE.fullmatch(readiness_code))
                or (coverage_digest is not None and not _DIGEST.fullmatch(coverage_digest))):
            raise ValueError("Invalid campaign transition")
        if package is not None and (package.target.id != target_id or
                                    policy_hash is None or
                                    not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}:[0-9a-f]{64}", policy_hash)):
            raise ValueError("Invalid current target policy")
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM campaigns WHERE campaign_id=? AND target_id=?",
                             (campaign_id, target_id)).fetchone()
            if row is None:
                raise LookupError("Campaign not found")
            before = CampaignStatus(row["status"])
            if before in TERMINAL_CAMPAIGN_STATUSES or (expected is not None and before not in expected):
                raise ValueError("Campaign transition is not permitted")
            if status is CampaignStatus.RUNNING and (package is None or
                    package.id != row["package_id"] or package.status.value != "TRACKED"):
                raise ValueError("Current Target Package is required before running")
            db.execute("UPDATE campaigns SET status=?,stop_reason=?,readiness_code=?,"
                       "coverage_digest=COALESCE(?,coverage_digest),"
                       "package_version=COALESCE(?,package_version),"
                       "policy_hash=COALESCE(?,policy_hash),"
                       "started_at=COALESCE(started_at,?),updated_at=?,finished_at=? "
                       "WHERE campaign_id=?",
                       (status.value, reason if status in TERMINAL_CAMPAIGN_STATUSES else None,
                        readiness_code or (reason if status in {
                            CampaignStatus.PAUSED, CampaignStatus.WAITING_LOGIN,
                            CampaignStatus.WAITING_APPROVAL, CampaignStatus.WAITING_RESEARCH,
                            CampaignStatus.WAITING_HUMAN} else None), coverage_digest,
                        package.version if package else None, policy_hash,
                        at if status is CampaignStatus.RUNNING else None,
                        at, at if status in TERMINAL_CAMPAIGN_STATUSES else None,
                        campaign_id))
            if row["current_cycle"]:
                cycle_state = (
                    "AMBIGUOUS" if status is CampaignStatus.CLEANUP_REQUIRED else
                    "COMPLETED" if status in TERMINAL_CAMPAIGN_STATUSES or
                    status is CampaignStatus.ASSESSING_READINESS else
                    "WAITING" if status in {CampaignStatus.PAUSED,
                                            CampaignStatus.WAITING_LOGIN,
                                            CampaignStatus.WAITING_APPROVAL,
                                            CampaignStatus.WAITING_RESEARCH,
                                            CampaignStatus.WAITING_HUMAN} else "RUNNING")
                db.execute("UPDATE campaign_cycles SET status=?,updated_at=? WHERE "
                           "campaign_id=? AND cycle_number=?",
                           (cycle_state, at, campaign_id, row["current_cycle"]))
            self._event(db, campaign_id, "STATUS_CHANGED", reason,
                        cycle=row["current_cycle"])
        result = self.get(target_id, campaign_id)
        assert result is not None
        return result

    def begin_cycle(self, package: TargetPackage, campaign_id: str,
                    policy_hash: str, *, source_digest: str | None = None,
                    readiness_digest: str | None = None,
                    behaviour_run_id: str | None = None) -> Campaign:
        if (source_digest is not None and not _DIGEST.fullmatch(source_digest)) or (
                readiness_digest is not None and not _DIGEST.fullmatch(readiness_digest)):
            raise ValueError("Invalid campaign provenance digest")
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM campaigns WHERE campaign_id=? AND target_id=?",
                             (campaign_id, package.target.id)).fetchone()
            if row is None or row["status"] not in {"RUNNING", "ASSESSING_READINESS"}:
                raise ValueError("Campaign is not ready for a cycle")
            if (package.id != row["package_id"] or package.status.value != "TRACKED" or
                    not policy_hash or package.version != row["package_version"] or
                    policy_hash != row["policy_hash"]):
                raise ValueError("Campaign package or policy changed; reassess first")
            number = row["current_cycle"] + 1
            if number > row["max_cycles"]:
                raise ValueError("Campaign cycle cap reached")
            if behaviour_run_id is not None and db.execute(
                    "SELECT 1 FROM behaviour_runs WHERE run_id=? AND target_id=?",
                    (behaviour_run_id, package.target.id)).fetchone() is None:
                raise ValueError("Behaviour run is not target-bound")
            db.execute("INSERT INTO campaign_cycles(campaign_id,cycle_number,status,"
                       "package_version,policy_hash,behaviour_run_id,source_digest,"
                       "readiness_digest,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (campaign_id, number, "ASSESSING", package.version, policy_hash,
                        behaviour_run_id, source_digest, readiness_digest, at, at))
            db.execute("UPDATE campaigns SET current_cycle=?,updated_at=? WHERE campaign_id=?",
                       (number, at, campaign_id))
            self._event(db, campaign_id, "CYCLE_STARTED", "BOUNDED_CYCLE", cycle=number)
        result = self.get(package.target.id, campaign_id)
        assert result is not None
        return result

    def reserve_work(self, target_id: str, campaign_id: str, kind: CampaignWorkKind,
                     *, requests: int = 0, browser_actions: int = 0,
                     research_requests: int = 0, tokens: int = 0,
                     setup_objects: int = 0) -> CampaignWork:
        amounts = (requests, browser_actions, research_requests, tokens, setup_objects)
        if (not isinstance(kind, CampaignWorkKind) or
                any(type(value) is not int or value < 0 for value in amounts)):
            raise ValueError("Invalid campaign work allocation")
        if kind not in {CampaignWorkKind.CLEANUP, CampaignWorkKind.PLANNER,
                        CampaignWorkKind.BEHAVIOUR} and all(value == 0 for value in amounts):
            raise ValueError("Campaign work needs a bounded allocation")
        work_id, at = "CMPWORK-" + uuid.uuid4().hex, _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM campaigns WHERE campaign_id=? AND target_id=?",
                             (campaign_id, target_id)).fetchone()
            permitted_status = (_CLEANUP_STATUSES if kind is CampaignWorkKind.CLEANUP
                                else {"RUNNING"})
            if row is None or row["status"] not in permitted_status or row["current_cycle"] == 0:
                raise ValueError("Campaign cannot start work")
            if kind is not CampaignWorkKind.CLEANUP and (
                    row["started_at"] is None or (datetime.fromisoformat(at) -
                    datetime.fromisoformat(row["started_at"])).total_seconds() >= row["seconds_limit"]):
                raise ValueError("Campaign time budget exhausted")
            request_ceiling = row["requests_limit"] - (0 if kind is CampaignWorkKind.CLEANUP
                                                       else row["cleanup_reserve"])
            if (row["requests_used"] + row["cleanup_used"] + requests > request_ceiling
                    or row["browser_used"] + browser_actions > row["browser_limit"]
                    or row["research_used"] + research_requests > row["research_limit"]
                    or row["tokens_used"] + tokens > row["tokens_limit"]
                    or row["setup_used"] + setup_objects > row["setup_limit"]):
                raise ValueError("Campaign budget exhausted")
            if kind is CampaignWorkKind.CLEANUP:
                db.execute("UPDATE campaigns SET cleanup_used=cleanup_used+?,updated_at=? "
                           "WHERE campaign_id=?", (requests, at, campaign_id))
            else:
                db.execute("UPDATE campaigns SET requests_used=requests_used+?,"
                           "browser_used=browser_used+?,research_used=research_used+?,"
                           "tokens_used=tokens_used+?,setup_used=setup_used+?,updated_at=? "
                           "WHERE campaign_id=?",
                           (requests, browser_actions, research_requests, tokens,
                            setup_objects, at, campaign_id))
            db.execute("INSERT INTO campaign_work(work_id,campaign_id,cycle_number,kind,"
                       "status,requests_allocated,browser_allocated,research_allocated,"
                       "tokens_allocated,setup_allocated,created_at,updated_at) "
                       "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       (work_id, campaign_id, row["current_cycle"], kind.value,
                        CampaignWorkStatus.INTENT.value, *amounts, at, at))
            self._event(db, campaign_id, "WORK_RESERVED", kind.value,
                        cycle=row["current_cycle"], work_id=work_id)
        work = self.work(target_id, campaign_id, work_id)
        assert work is not None
        return work

    def work(self, target_id: str, campaign_id: str, work_id: str) -> CampaignWork | None:
        if not _WORK_ID.fullmatch(work_id):
            raise ValueError("Invalid campaign work ID")
        with self.store._connection() as db:
            row = db.execute("SELECT w.* FROM campaign_work AS w JOIN campaigns AS c "
                             "ON c.campaign_id=w.campaign_id WHERE c.target_id=? "
                             "AND w.campaign_id=? AND w.work_id=?",
                             (target_id, campaign_id, work_id)).fetchone()
        return self._work(row) if row else None

    def works(self, target_id: str, campaign_id: str) -> tuple[CampaignWork, ...]:
        with self.store._connection() as db:
            rows = db.execute("SELECT w.* FROM campaign_work AS w JOIN campaigns AS c "
                              "ON c.campaign_id=w.campaign_id WHERE c.target_id=? "
                              "AND w.campaign_id=? ORDER BY w.created_at,w.work_id LIMIT 80",
                              (target_id, campaign_id)).fetchall()
        return tuple(self._work(row) for row in rows)

    def link_child(self, target_id: str, campaign_id: str, work_id: str,
                   child_id: str) -> CampaignWork:
        prefixes = {CampaignWorkKind.BOOTSTRAP: ("bootstrap_runs", "run_id", "BOOT-"),
                    CampaignWorkKind.BEHAVIOUR: ("behaviour_runs", "run_id", "LEARN-"),
                    CampaignWorkKind.RESEARCH: ("research_requests", "request_id", "RREQ-"),
                    CampaignWorkKind.PLANNER: ("planner_runs", "run_id", "PLRUN-"),
                    CampaignWorkKind.CLEANUP: ("test_objects", "test_object_id", "TESTOBJ-")}
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            work = db.execute("SELECT w.*,c.target_id,c.status AS campaign_status "
                              "FROM campaign_work AS w JOIN campaigns AS c "
                              "ON c.campaign_id=w.campaign_id WHERE w.work_id=? "
                              "AND w.campaign_id=? AND c.target_id=?",
                              (work_id, campaign_id, target_id)).fetchone()
            allowed = (_CLEANUP_STATUSES
                       if work is not None and work["kind"] == "CLEANUP" else {"RUNNING"})
            if work is None or work["status"] != "INTENT" or work["campaign_status"] not in allowed:
                raise ValueError("Campaign work is not attachable")
            table, column, prefix = prefixes[CampaignWorkKind(work["kind"])]
            if (not isinstance(child_id, str) or not child_id.startswith(prefix) or
                    db.execute(f"SELECT 1 FROM {table} WHERE {column}=? AND target_id=?",
                               (child_id, target_id)).fetchone() is None):
                raise ValueError("Child is missing or outside campaign target")
            db.execute("UPDATE campaign_work SET status='LINKED',child_id=?,updated_at=? "
                       "WHERE work_id=?", (child_id, at, work_id))
            if work["kind"] == "PLANNER":
                db.execute("UPDATE campaign_cycles SET planner_run_id=?,status='RUNNING',"
                           "updated_at=? WHERE campaign_id=? AND cycle_number=?",
                           (child_id, at, campaign_id, work["cycle_number"]))
            self._event(db, campaign_id, "CHILD_LINKED", work["kind"],
                        cycle=work["cycle_number"], work_id=work_id)
        result = self.work(target_id, campaign_id, work_id)
        assert result is not None
        return result

    def finish_work(self, target_id: str, campaign_id: str, work_id: str,
                    *, reason: str) -> CampaignWork:
        if not _CODE.fullmatch(reason):
            raise ValueError("Invalid campaign work outcome")
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT w.* FROM campaign_work AS w JOIN campaigns AS c "
                             "ON c.campaign_id=w.campaign_id WHERE w.work_id=? "
                             "AND w.campaign_id=? AND c.target_id=?",
                             (work_id, campaign_id, target_id)).fetchone()
            if row is None or row["status"] != "LINKED":
                raise ValueError("Campaign work has no linked child")
            db.execute("UPDATE campaign_work SET status='COMPLETED',updated_at=? WHERE work_id=?",
                       (at, work_id))
            self._event(db, campaign_id, "WORK_COMPLETED", reason,
                        cycle=row["cycle_number"], work_id=work_id)
        result = self.work(target_id, campaign_id, work_id)
        assert result is not None
        return result

    def claim_planner_task(self, target_id: str, run_id: str,
                           task_id: str, kind: str) -> bool:
        """Non-campaign planners are unchanged; campaigns get a hard task quota."""
        if kind not in {"SETUP", "RESEARCH"}:
            raise ValueError("Invalid campaign task claim")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT w.work_id,w.setup_allocated,w.research_allocated,c.status "
                "FROM campaign_work AS w JOIN campaigns AS c ON c.campaign_id=w.campaign_id "
                "JOIN planner_tasks AS t ON t.run_id=w.child_id "
                "WHERE w.kind='PLANNER' AND w.child_id=? AND c.target_id=? AND "
                "t.task_id=?", (run_id, target_id, task_id)).fetchone()
            if row is None:
                return True
            if row["status"] != "RUNNING":
                return False
            if db.execute("SELECT 1 FROM campaign_task_claims WHERE work_id=? "
                          "AND planner_task_id=? AND kind=?",
                          (row["work_id"], task_id, kind)).fetchone():
                return True
            cap = row["setup_allocated"] if kind == "SETUP" else row["research_allocated"]
            count = db.execute("SELECT count(*) FROM campaign_task_claims "
                               "WHERE work_id=? AND kind=?",
                               (row["work_id"], kind)).fetchone()[0]
            if count >= cap:
                return False
            db.execute("INSERT INTO campaign_task_claims VALUES (?,?,?,?)",
                       (row["work_id"], task_id, kind, _now()))
            return True

    def planner_may_advance(self, target_id: str, run_id: str) -> bool:
        with self.store._connection() as db:
            row = db.execute(
                "SELECT c.status,w.status AS work_status FROM campaign_work AS w "
                "JOIN campaigns AS c ON c.campaign_id=w.campaign_id "
                "WHERE w.kind='PLANNER' AND w.child_id=? AND c.target_id=?",
                (run_id, target_id)).fetchone()
        return row is None or (row["status"] == "RUNNING" and
                               row["work_status"] == "LINKED")

    def suppress(self, target_id: str, campaign_id: str, root_key: str,
                 state_hash: str, kind: str) -> bool:
        if (not _DIGEST.fullmatch(root_key) or not _DIGEST.fullmatch(state_hash) or
                kind not in {"CONFIRMED", "REJECTED", "MANUAL_EXCLUDE", "DEPRIORITIZED",
                             "STALE", "BRANCH_BUDGET"}):
            raise ValueError("Invalid campaign suppression")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM campaigns WHERE campaign_id=? AND target_id=?",
                          (campaign_id, target_id)).fetchone() is None:
                raise LookupError("Campaign not found")
            cursor = db.execute("INSERT OR IGNORE INTO campaign_suppressions "
                                "(campaign_id,root_key,state_hash,kind,created_at) "
                                "VALUES (?,?,?,?,?)",
                                (campaign_id, root_key, state_hash, kind, _now()))
            if cursor.rowcount:
                self._event(db, campaign_id, "BRANCH_SUPPRESSED", kind)
            return bool(cursor.rowcount)

    def suppressions(self, target_id: str, campaign_id: str) -> tuple[dict[str, str], ...]:
        with self.store._connection() as db:
            rows = db.execute("SELECT s.root_key,s.state_hash,s.kind,s.created_at "
                              "FROM campaign_suppressions AS s JOIN campaigns AS c "
                              "ON c.campaign_id=s.campaign_id WHERE c.target_id=? "
                              "AND s.campaign_id=? ORDER BY s.created_at DESC LIMIT 100",
                              (target_id, campaign_id)).fetchall()
        return tuple(dict(row) for row in rows)

    def events(self, target_id: str, campaign_id: str,
               *, limit: int = 100) -> tuple[dict[str, object], ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid campaign event page size")
        with self.store._connection() as db:
            rows = db.execute("SELECT e.event_id,e.cycle_number,e.work_id,e.event_type,"
                              "e.reason_code,e.occurred_at FROM campaign_events AS e "
                              "JOIN campaigns AS c ON c.campaign_id=e.campaign_id "
                              "WHERE c.target_id=? AND e.campaign_id=? "
                              "ORDER BY e.event_id DESC LIMIT ?",
                              (target_id, campaign_id, limit)).fetchall()
        return tuple(dict(row) for row in rows)

    def cycles(self, target_id: str, campaign_id: str) -> tuple[dict[str, object], ...]:
        with self.store._connection() as db:
            rows = db.execute("SELECT cy.cycle_number,cy.status,cy.package_version,"
                              "cy.policy_hash,cy.behaviour_run_id,cy.planner_run_id,"
                              "cy.source_digest,cy.readiness_digest,cy.created_at,cy.updated_at "
                              "FROM campaign_cycles AS cy JOIN campaigns AS c "
                              "ON c.campaign_id=cy.campaign_id WHERE c.target_id=? "
                              "AND cy.campaign_id=? ORDER BY cy.cycle_number",
                              (target_id, campaign_id)).fetchall()
        return tuple(dict(row) for row in rows)

    def objects(self, target_id: str, campaign_id: str) -> tuple[dict[str, str], ...]:
        with self.store._connection() as db:
            rows = db.execute("SELECT o.object_id,o.cleanup_status,o.created_at,"
                              "o.updated_at FROM campaign_objects AS o JOIN campaigns AS c "
                              "ON c.campaign_id=o.campaign_id WHERE c.target_id=? "
                              "AND o.campaign_id=? ORDER BY o.created_at LIMIT 20",
                              (target_id, campaign_id)).fetchall()
        return tuple(dict(row) for row in rows)

    def track_created_object(self, target_id: str, campaign_id: str,
                             work_id: str, object_id: str) -> bool:
        """Only register a newly created, child-owned object for cleanup."""
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT o.test_object_id,o.lifecycle,c.created_at "
                "FROM test_objects AS o JOIN campaigns AS c ON c.target_id=o.target_id "
                "JOIN campaign_work AS w ON w.campaign_id=c.campaign_id "
                "WHERE c.campaign_id=? AND c.target_id=? AND w.work_id=? "
                "AND w.kind='PLANNER' AND w.status IN ('LINKED','COMPLETED') "
                "AND o.test_object_id=? AND o.created_at>=c.created_at "
                "AND EXISTS (SELECT 1 FROM planner_tasks AS t WHERE t.run_id=w.child_id "
                "AND t.task_type='CREATE_DISPOSABLE_OBJECT' AND t.result_ref=o.test_object_id)",
                (campaign_id, target_id, work_id, object_id)).fetchone()
            if row is None:
                return False
            at = _now()
            result = db.execute("INSERT OR IGNORE INTO campaign_objects "
                                "(campaign_id,object_id,work_id,cleanup_status,created_at,updated_at) "
                                "VALUES (?,?,?,?,?,?)",
                                (campaign_id, object_id, work_id,
                                 "CLEANED" if row["lifecycle"] == "CLEANED" else "PENDING",
                                 at, at))
            if result.rowcount:
                self._event(db, campaign_id, "OBJECT_TRACKED", "DISPOSABLE_CREATED",
                            work_id=work_id)
            return bool(result.rowcount)

    @staticmethod
    def _sync_objects(db: sqlite3.Connection, campaign_id: str,
                      target_id: str) -> int:
        at = _now()
        result = db.execute(
            "INSERT OR IGNORE INTO campaign_objects "
            "(campaign_id,object_id,work_id,cleanup_status,created_at,updated_at) "
            "SELECT c.campaign_id,o.test_object_id,w.work_id,"
            "CASE WHEN o.lifecycle='CLEANED' THEN 'CLEANED' ELSE 'PENDING' END,?,? "
            "FROM campaigns AS c JOIN campaign_work AS w "
            "ON w.campaign_id=c.campaign_id JOIN planner_tasks AS t "
            "ON t.run_id=w.child_id JOIN test_objects AS o "
            "ON o.test_object_id=t.result_ref AND o.target_id=c.target_id "
            "WHERE c.campaign_id=? AND c.target_id=? AND w.kind='PLANNER' "
            "AND w.status IN ('LINKED','COMPLETED') "
            "AND t.task_type='CREATE_DISPOSABLE_OBJECT' AND o.created_at>=c.created_at",
            (at, at, campaign_id, target_id))
        return result.rowcount

    def reconcile_objects(self, target_id: str, campaign_id: str) -> int:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM campaigns WHERE campaign_id=? AND target_id=?",
                          (campaign_id, target_id)).fetchone() is None:
                raise LookupError("Campaign not found")
            added = self._sync_objects(db, campaign_id, target_id)
            if added:
                self._event(db, campaign_id, "OBJECTS_RECONCILED", "DISPOSABLE_CREATED")
            return added

    def refresh_object_cleanup(self, target_id: str, campaign_id: str,
                               object_id: str) -> str:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT o.lifecycle FROM test_objects AS o "
                             "JOIN campaign_objects AS co ON co.object_id=o.test_object_id "
                             "JOIN campaigns AS c ON c.campaign_id=co.campaign_id "
                             "WHERE c.campaign_id=? AND c.target_id=? AND o.test_object_id=?",
                             (campaign_id, target_id, object_id)).fetchone()
            if row is None:
                raise LookupError("Campaign object not found")
            status = ("CLEANED" if row["lifecycle"] == "CLEANED" else
                      "ORPHANED" if row["lifecycle"] in {"ORPHANED", "UNKNOWN"} else
                      "PENDING")
            db.execute("UPDATE campaign_objects SET cleanup_status=?,updated_at=? "
                       "WHERE campaign_id=? AND object_id=?",
                       (status, _now(), campaign_id, object_id))
            if status != "PENDING":
                self._event(db, campaign_id, "CLEANUP_STATE", status)
            return status

    def reconcile_interrupted(self) -> int:
        """Never replay an intent after restart; even a no-child intent is uncertain."""
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT campaign_id,target_id,current_cycle FROM campaigns WHERE status IN "
                              "('CREATED','ASSESSING_READINESS','RUNNING','WAITING_LOGIN',"
                              "'WAITING_APPROVAL','WAITING_RESEARCH','WAITING_HUMAN')").fetchall()
            for row in rows:
                campaign_id = row["campaign_id"]
                if self._sync_objects(db, campaign_id, row["target_id"]):
                    self._event(db, campaign_id, "OBJECTS_RECONCILED", "RESTART_RECOVERY")
                intents = db.execute("SELECT work_id,cycle_number FROM campaign_work "
                                     "WHERE campaign_id=? AND status='INTENT'",
                                     (campaign_id,)).fetchall()
                for item in intents:
                    db.execute("UPDATE campaign_work SET status='AMBIGUOUS',updated_at=? "
                               "WHERE work_id=?", (at, item["work_id"]))
                    self._event(db, campaign_id, "WORK_AMBIGUOUS", "INTERRUPTED_START",
                                cycle=item["cycle_number"], work_id=item["work_id"])
                db.execute("UPDATE campaigns SET status='PAUSED',readiness_code='RESTART_REVIEW',"
                           "updated_at=? WHERE campaign_id=?", (at, campaign_id))
                if row["current_cycle"]:
                    db.execute("UPDATE campaign_cycles SET status='WAITING',updated_at=? "
                               "WHERE campaign_id=? AND cycle_number=?",
                               (at, campaign_id, row["current_cycle"]))
                self._event(db, campaign_id, "STATUS_CHANGED", "RESTART_REVIEW",
                            cycle=row["current_cycle"])
            return len(rows)
