"""Durable, target-scoped disposable-object ledger. No network access."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import json
import re
import sqlite3
import uuid

from .policy_models import ActionCategory, ProposedAction
from .recon import Page
from .store import EvidenceFactStore


_ID = re.compile(r"TESTOBJ-[0-9a-f]{32}\Z")
_RECIPE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PENDING = ("PLANNED", "CREATING", "CREATED", "VERIFYING", "READY", "IN_USE",
            "CLEANUP_PENDING", "CLEANING", "ORPHANED", "UNKNOWN")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ObjectState(StrEnum):
    PLANNED = "PLANNED"
    CREATING = "CREATING"
    CREATED = "CREATED"
    VERIFYING = "VERIFYING"
    READY = "READY"
    IN_USE = "IN_USE"
    CLEANUP_PENDING = "CLEANUP_PENDING"
    CLEANING = "CLEANING"
    CLEANED = "CLEANED"
    ORPHANED = "ORPHANED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class CleanupStrategy(StrEnum):
    AUTO_CLEANUP = "AUTO_CLEANUP"
    MANUAL_CLEANUP = "MANUAL_CLEANUP"
    NO_CLEANUP_REQUIRED = "NO_CLEANUP_REQUIRED"
    CLEANUP_UNAVAILABLE = "CLEANUP_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class TestObject:
    id: str
    target_id: str
    package_id: str
    object_ref_id: str
    object_type: str
    external_id_hash: str | None
    external_id_evidence_id: str | None
    creator_identity_id: str
    owner_principal_id: str | None
    tenant_id: str
    parent_id: str | None
    plan_id: str | None
    run_id: str | None
    hypothesis_id: str | None
    creation_action_id: str
    creation_exchange_id: str | None
    recipe_id: str
    recipe_hash: str
    test_name: str
    state: ObjectState
    disposable: bool
    cleanup_required: bool
    cleanup_strategy: CleanupStrategy
    pending_action_id: str | None
    pending_approval_id: str | None
    setup_requests_reserved: int
    cleanup_requests_reserved: int
    creation_evidence_ids: tuple[str, ...]
    verification_evidence_ids: tuple[str, ...]
    cleanup_evidence_ids: tuple[str, ...]
    created_at: str
    verified_at: str | None
    cleaned_at: str | None
    last_checked_at: str | None
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "target_id": self.target_id, "package_id": self.package_id,
                "object_ref_id": self.object_ref_id, "object_type": self.object_type,
                "external_id_fingerprint": self.external_id_hash[:16] if self.external_id_hash else None,
                "creator_identity_id": self.creator_identity_id,
                "owner_principal_id": self.owner_principal_id, "tenant_id": self.tenant_id,
                "parent_id": self.parent_id, "plan_id": self.plan_id, "run_id": self.run_id,
                "hypothesis_id": self.hypothesis_id, "creation_action_id": self.creation_action_id,
                "creation_exchange_id": self.creation_exchange_id,
                "recipe_id": self.recipe_id, "state": self.state.value,
                "disposable": self.disposable, "cleanup_required": self.cleanup_required,
                "cleanup_strategy": self.cleanup_strategy.value,
                "pending_approval_id": self.pending_approval_id,
                "setup_requests_reserved": self.setup_requests_reserved,
                "cleanup_requests_reserved": self.cleanup_requests_reserved,
                "evidence_ids": list(dict.fromkeys((*self.creation_evidence_ids,
                                                      *self.verification_evidence_ids,
                                                      *self.cleanup_evidence_ids)))[:32],
                "created_at": self.created_at, "verified_at": self.verified_at,
                "cleaned_at": self.cleaned_at, "last_checked_at": self.last_checked_at,
                "updated_at": self.updated_at}


class ObjectRegistry:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    @staticmethod
    def _object(row: sqlite3.Row) -> TestObject:
        return TestObject(
            row["test_object_id"], row["target_id"], row["package_id"], row["object_ref_id"],
            row["object_type"], row["external_id_hash"], row["external_id_evidence_id"],
            row["creator_identity_id"], row["owner_principal_id"], row["tenant_id"],
            row["parent_test_object_id"], row["creation_plan_id"], row["creation_run_id"],
            row["creation_hypothesis_id"], row["creation_action_id"], row["creation_exchange_id"],
            row["recipe_id"], row["recipe_hash"], row["test_name"], ObjectState(row["lifecycle"]),
            bool(row["disposable"]), bool(row["cleanup_required"]),
            CleanupStrategy(row["cleanup_strategy"]), row["pending_action_id"],
            row["pending_approval_id"], row["setup_requests_reserved"],
            row["cleanup_requests_reserved"], tuple(json.loads(row["creation_evidence_json"])),
            tuple(json.loads(row["verification_evidence_json"])),
            tuple(json.loads(row["cleanup_evidence_json"])), row["created_at"],
            row["verified_at"], row["cleaned_at"], row["last_checked_at"], row["updated_at"])

    @staticmethod
    def _event(db: sqlite3.Connection, object_id: str, kind: str, reason: str,
               *, source: str = "OBJECT_FACTORY", action_id: str | None = None,
               exchange_id: str | None = None, evidence_ids: tuple[str, ...] = ()) -> None:
        if not _CODE.fullmatch(kind) or not _CODE.fullmatch(reason) or source not in {
            "OBJECT_FACTORY", "MANUAL", "RECONCILIATION", "PLAN_ORCHESTRATOR"}:
            raise ValueError("invalid object event")
        db.execute("INSERT INTO test_object_events(test_object_id,event_type,reason_code,source,"
                   "action_id,exchange_id,evidence_ids_json,occurred_at) VALUES (?,?,?,?,?,?,?,?)",
                   (object_id, kind, reason, source, action_id, exchange_id,
                    json.dumps(evidence_ids), _now()))

    def plan(self, *, target_id: str, package_id: str, object_type: str,
             creator_identity_id: str, tenant_id: str, recipe_id: str, recipe_hash: str,
             test_name: str, cleanup_strategy: CleanupStrategy,
             parent_id: str | None = None, plan_id: str | None = None,
             run_id: str | None = None, hypothesis_id: str | None = None,
             max_objects_per_plan: int = 3, max_objects_per_target_hour: int = 20) -> TestObject:
        if (not _RECIPE.fullmatch(recipe_id) or not _RECIPE.fullmatch(object_type) or
                not _HASH.fullmatch(recipe_hash) or not re.fullmatch(r"[a-z][a-z0-9-]{3,64}", test_name) or
                not isinstance(cleanup_strategy, CleanupStrategy)):
            raise ValueError("invalid disposable object plan")
        at = _now()
        object_id, action_id, reference_id = (prefix + uuid.uuid4().hex for prefix in
                                              ("TESTOBJ-", "ACTION-", "OBJECT-"))
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            actor = db.execute("SELECT target_id,status FROM registry_identities WHERE identity_id=?",
                               (creator_identity_id,)).fetchone()
            tenant = db.execute("SELECT target_id FROM registry_tenants WHERE tenant_id=?",
                                (tenant_id,)).fetchone()
            if (actor is None or actor["target_id"] != target_id or actor["status"] != "ACTIVE"
                    or tenant is None or tenant["target_id"] != target_id):
                raise ValueError("creator or tenant is not target-owned")
            if run_id:
                run = db.execute("SELECT target_id,plan_id,hypothesis_id FROM plan_runs WHERE run_id=?",
                                 (run_id,)).fetchone()
                if (run is None or run["target_id"] != target_id or
                        (plan_id and plan_id != run["plan_id"]) or
                        (hypothesis_id and hypothesis_id != run["hypothesis_id"])):
                    raise ValueError("object run binding is invalid")
                plan_id = run["plan_id"]
            if plan_id:
                plan = db.execute("SELECT target_id FROM skill_plans WHERE plan_id=?",
                                  (plan_id,)).fetchone()
                if plan is None or plan["target_id"] != target_id:
                    raise ValueError("object plan binding is invalid")
            if parent_id:
                parent = db.execute("SELECT target_id,tenant_id,lifecycle,disposable FROM test_objects "
                                    "WHERE test_object_id=?", (parent_id,)).fetchone()
                if (parent is None or parent["target_id"] != target_id or parent["tenant_id"] != tenant_id
                        or parent["lifecycle"] not in {"READY", "IN_USE"} or not parent["disposable"]):
                    raise ValueError("BLOCKED_MISSING_PARENT")
            if plan_id and db.execute("SELECT count(*) FROM test_objects WHERE creation_plan_id=?",
                                      (plan_id,)).fetchone()[0] >= max_objects_per_plan:
                raise ValueError("PLAN_OBJECT_LIMIT")
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            if db.execute("SELECT count(*) FROM test_objects WHERE target_id=? AND created_at>=?",
                          (target_id, cutoff)).fetchone()[0] >= max_objects_per_target_hour:
                raise ValueError("TARGET_HOURLY_OBJECT_LIMIT")
            db.execute("INSERT INTO test_objects(test_object_id,target_id,package_id,object_ref_id,"
                       "object_type,creator_identity_id,tenant_id,parent_test_object_id,creation_plan_id,"
                       "creation_run_id,creation_hypothesis_id,creation_action_id,recipe_id,recipe_hash,"
                       "test_name,lifecycle,disposable,cleanup_required,cleanup_strategy,created_at,updated_at) "
                       "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (object_id, target_id, package_id, reference_id, object_type,
                        creator_identity_id, tenant_id, parent_id, plan_id, run_id, hypothesis_id,
                        action_id, recipe_id, recipe_hash, test_name, "PLANNED", 1,
                        int(cleanup_strategy is not CleanupStrategy.NO_CLEANUP_REQUIRED),
                        cleanup_strategy.value, at, at))
            self._event(db, object_id, "OBJECT_CREATION_REQUESTED", "KNOWN_RECIPE")
            row = db.execute("SELECT * FROM test_objects WHERE test_object_id=?", (object_id,)).fetchone()
        return self._object(row)

    def get(self, object_id: str, target_id: str) -> TestObject | None:
        if not isinstance(object_id, str) or not _ID.fullmatch(object_id):
            raise ValueError("invalid test object ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM test_objects WHERE test_object_id=? AND target_id=?",
                             (object_id, target_id)).fetchone()
        return self._object(row) if row else None

    def find_cleaned_by_delete_exchange(self, target_id: str,
                                        exchange_id: str) -> TestObject | None:
        """Resolve one verified cleaned object from its exact deletion exchange."""
        if (not isinstance(target_id, str) or not target_id or
                not isinstance(exchange_id, str) or not exchange_id or
                len(exchange_id) > 128):
            raise ValueError("invalid delete source lookup")
        with self.store._connection() as db:
            rows = db.execute(
                "WITH source_ids AS ("
                " SELECT test_object_id FROM authorization_mutation_results"
                " WHERE target_id=? AND mutation_exchange_id=?"
                " AND mutation_type='DELETE_DISPOSABLE' AND status='VERIFIED'"
                " UNION"
                " SELECT p.test_object_id FROM test_object_operations p"
                " JOIN test_objects linked ON linked.test_object_id=p.test_object_id"
                " WHERE linked.target_id=? AND p.exchange_id=?"
                " AND p.operation_kind='CLEANUP' AND p.status='SUCCEEDED'"
                ") SELECT o.* FROM source_ids s"
                " JOIN test_objects o ON o.test_object_id=s.test_object_id"
                " WHERE o.target_id=? AND o.lifecycle='CLEANED'"
                " AND o.disposable=1 AND o.verified_at IS NOT NULL"
                " LIMIT 2",
                (target_id, exchange_id, target_id, exchange_id, target_id)).fetchall()
        return self._object(rows[0]) if len(rows) == 1 else None

    def list_for_target(self, target_id: str, *, limit: int = 20, cursor: str | None = None,
                        state: ObjectState | None = None, object_type: str | None = None,
                        tenant_id: str | None = None, identity_id: str | None = None,
                        cleanup_only: bool = False) -> Page[TestObject]:
        if type(limit) is not int or not 1 <= limit <= 50 or cursor is not None and not cursor.isdecimal():
            raise ValueError("invalid object page")
        sql = "SELECT rowid AS cursor_id,* FROM test_objects WHERE target_id=?"
        args: list[object] = [target_id]
        for field, value in (("lifecycle", state.value if state else None),
                             ("object_type", object_type), ("tenant_id", tenant_id),
                             ("creator_identity_id", identity_id)):
            if value is not None:
                sql += " AND " + field + "=?"
                args.append(value)
        if cleanup_only:
            sql += " AND cleanup_required=1 AND lifecycle IN "
            sql += "('CREATING','CREATED','VERIFYING','READY','IN_USE','CLEANUP_PENDING','CLEANING','ORPHANED','UNKNOWN')"
        if cursor:
            sql += " AND rowid<?"
            args.append(int(cursor))
        sql += " ORDER BY rowid DESC LIMIT ?"
        args.append(limit + 1)
        with self.store._connection() as db:
            rows = db.execute(sql, args).fetchall()
        return Page(tuple(self._object(row) for row in rows[:limit]),
                    str(rows[limit - 1]["cursor_id"]) if len(rows) > limit else None)

    def list_for_identity(self, target_id: str, identity_id: str, **kwargs: object) -> Page[TestObject]:
        return self.list_for_target(target_id, identity_id=identity_id, **kwargs)

    def list_for_tenant(self, target_id: str, tenant_id: str, **kwargs: object) -> Page[TestObject]:
        return self.list_for_target(target_id, tenant_id=tenant_id, **kwargs)

    def list_cleanup_pending(self, target_id: str, *, limit: int = 20,
                             cursor: str | None = None) -> Page[TestObject]:
        return self.list_for_target(target_id, limit=limit, cursor=cursor, cleanup_only=True)

    def find_reusable(self, target_id: str, object_type: str, tenant_id: str,
                      identity_id: str, *, parent_id: str | None = None,
                      recipe_id: str | None = None) -> TestObject | None:
        with self.store._connection() as db:
            row = db.execute("SELECT o.* FROM test_objects o WHERE o.target_id=? AND o.object_type=? "
                             "AND o.tenant_id=? AND o.creator_identity_id=? AND o.parent_test_object_id IS ? "
                             "AND (? IS NULL OR o.recipe_id=?) "
                             "AND o.lifecycle='READY' AND o.disposable=1 AND o.verified_at IS NOT NULL "
                             "AND NOT EXISTS (SELECT 1 FROM test_object_reservations r WHERE "
                             "r.test_object_id=o.test_object_id AND r.status='ACTIVE') "
                             "ORDER BY o.created_at DESC LIMIT 1",
                             (target_id, object_type, tenant_id, identity_id, parent_id,
                              recipe_id, recipe_id)).fetchone()
        return self._object(row) if row else None

    def add_requirement(self, *, plan_id: str, target_id: str, object_type: str,
                        recipe_id: str, identity_id: str, tenant_id: str,
                        parent_id: str | None = None,
                        test_object_id: str | None = None) -> str:
        if not _RECIPE.fullmatch(object_type) or not _RECIPE.fullmatch(recipe_id):
            raise ValueError("invalid object prerequisite")
        requirement_id = "OBJREQ-" + uuid.uuid4().hex
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            plan = db.execute("SELECT target_id FROM skill_plans WHERE plan_id=?",
                              (plan_id,)).fetchone()
            actor = db.execute("SELECT target_id,status FROM registry_identities WHERE identity_id=?",
                               (identity_id,)).fetchone()
            tenant = db.execute("SELECT target_id FROM registry_tenants WHERE tenant_id=?",
                                (tenant_id,)).fetchone()
            if (plan is None or plan["target_id"] != target_id or actor is None or
                    actor["target_id"] != target_id or actor["status"] != "ACTIVE" or
                    tenant is None or tenant["target_id"] != target_id):
                raise ValueError("object prerequisite context is invalid")
            if db.execute("SELECT 1 FROM plan_runs WHERE plan_id=? LIMIT 1", (plan_id,)).fetchone():
                raise ValueError("object prerequisites cannot change after a run starts")
            if parent_id:
                parent = db.execute("SELECT tenant_id,target_id,verified_at,disposable FROM test_objects "
                                    "WHERE test_object_id=?", (parent_id,)).fetchone()
                if (parent is None or parent["tenant_id"] != tenant_id or
                        parent["target_id"] != target_id or not parent["verified_at"] or
                        not parent["disposable"]):
                    raise ValueError("BLOCKED_MISSING_PARENT")
            if test_object_id:
                exact = db.execute("SELECT target_id,object_type,recipe_id,creator_identity_id,"
                                   "tenant_id,parent_test_object_id,disposable,verified_at,lifecycle "
                                   "FROM test_objects WHERE test_object_id=?", (test_object_id,)).fetchone()
                if (exact is None or exact["target_id"] != target_id or
                        exact["object_type"] != object_type or exact["recipe_id"] != recipe_id or
                        exact["creator_identity_id"] != identity_id or exact["tenant_id"] != tenant_id or
                        exact["parent_test_object_id"] != parent_id or not exact["disposable"] or
                        not exact["verified_at"] or exact["lifecycle"] != "READY"):
                    raise ValueError("exact object prerequisite is unavailable")
            plan_row = db.execute("SELECT skill_id,plan_json FROM skill_plans WHERE plan_id=?",
                                  (plan_id,)).fetchone()
            batch_plan = False
            if plan_row is not None and plan_row["skill_id"] == "api-observed-read":
                try:
                    snapshot = json.loads(plan_row["plan_json"])
                    batch_plan = (snapshot.get("api_binding", {}).get("category") == "BATCH_AUTH" and
                                  len(snapshot.get("request_templates", ())) == 5 and
                                  all(shape.get("binding") == "API_OBSERVED_BATCH_V1" for shape in
                                      snapshot["request_templates"]))
                except (TypeError, ValueError, AttributeError):
                    batch_plan = False
            if db.execute("SELECT count(*) FROM plan_object_requirements WHERE plan_id=?",
                          (plan_id,)).fetchone()[0] >= (4 if batch_plan else 3):
                raise ValueError("PLAN_REQUIREMENT_LIMIT")
            db.execute("INSERT INTO plan_object_requirements "
                       "(requirement_id,plan_id,target_id,object_type,recipe_id,creator_identity_id,"
                       "tenant_id,parent_test_object_id,created_at,test_object_id) "
                       "VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (requirement_id, plan_id, target_id, object_type, recipe_id,
                        identity_id, tenant_id, parent_id, _now(), test_object_id))
        return requirement_id

    def requirements(self, plan_id: str, target_id: str) -> tuple[dict[str, str | None], ...]:
        with self.store._connection() as db:
            rows = db.execute("SELECT requirement_id,object_type,recipe_id,creator_identity_id,tenant_id,"
                              "parent_test_object_id,test_object_id FROM plan_object_requirements WHERE plan_id=? "
                              "AND target_id=? ORDER BY requirement_id LIMIT 4",
                              (plan_id, target_id)).fetchall()
        return tuple(dict(row) for row in rows)

    def reserved_for_run(self, run_id: str, target_id: str) -> bool:
        with self.store._connection() as db:
            run = db.execute("SELECT plan_id FROM plan_runs WHERE run_id=? AND target_id=?",
                             (run_id, target_id)).fetchone()
            if run is None:
                return False
            required = db.execute("SELECT count(*) FROM plan_object_requirements WHERE plan_id=?",
                                  (run["plan_id"],)).fetchone()[0]
            if not required:
                return True
            held = db.execute("SELECT count(*) FROM test_object_reservations r "
                              "JOIN test_objects o ON o.test_object_id=r.test_object_id "
                              "JOIN plan_object_requirements q ON q.plan_id=? AND q.target_id=o.target_id "
                              "AND q.object_type=o.object_type AND q.recipe_id=o.recipe_id "
                              "AND q.creator_identity_id=o.creator_identity_id "
                              "AND q.tenant_id=o.tenant_id AND q.parent_test_object_id IS o.parent_test_object_id "
                              "AND (q.test_object_id IS NULL OR q.test_object_id=o.test_object_id) "
                              "WHERE r.holder_run_id=? AND r.status='ACTIVE' AND r.expires_at>? "
                              "AND o.lifecycle='IN_USE'", (run["plan_id"], run_id, _now())).fetchone()[0]
        return held >= required

    def reserve_requirements(self, run_id: str, target_id: str,
                             *, lease_seconds: int = 3600) -> bool:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute("SELECT plan_id,status FROM plan_runs WHERE run_id=? AND target_id=?",
                             (run_id, target_id)).fetchone()
            if run is None or run["status"] not in {"CREATED", "CHECKING_PREREQUISITES", "READY"}:
                raise ValueError("plan run cannot reserve objects")
            requirements = db.execute("SELECT * FROM plan_object_requirements WHERE plan_id=? "
                                      "AND target_id=? ORDER BY requirement_id LIMIT 4",
                                      (run["plan_id"], target_id)).fetchall()
            if not requirements:
                return True
            existing = db.execute("SELECT count(*) FROM test_object_reservations r "
                                  "JOIN test_objects o ON o.test_object_id=r.test_object_id "
                                  "JOIN plan_object_requirements q ON q.plan_id=? AND q.target_id=o.target_id "
                                  "AND q.object_type=o.object_type AND q.recipe_id=o.recipe_id "
                                  "AND q.creator_identity_id=o.creator_identity_id "
                                  "AND q.tenant_id=o.tenant_id "
                                  "AND q.parent_test_object_id IS o.parent_test_object_id "
                                  "AND (q.test_object_id IS NULL OR q.test_object_id=o.test_object_id) "
                                  "WHERE r.holder_run_id=? AND r.status='ACTIVE' AND r.expires_at>? "
                                  "AND o.lifecycle='IN_USE'",
                                  (run["plan_id"], run_id, _now())).fetchone()[0]
            if existing:
                return existing == len(requirements)
            selected: list[str] = []
            for requirement in requirements:
                item = db.execute("SELECT o.test_object_id FROM test_objects o WHERE o.target_id=? "
                                  "AND o.object_type=? AND o.recipe_id=? AND o.creator_identity_id=? AND o.tenant_id=? "
                                  "AND o.parent_test_object_id IS ? AND o.lifecycle='READY' "
                                  "AND (? IS NULL OR o.test_object_id=?) "
                                  "AND o.disposable=1 AND o.verified_at IS NOT NULL "
                                  "AND NOT EXISTS (SELECT 1 FROM test_object_reservations r WHERE "
                                  "r.test_object_id=o.test_object_id AND r.status='ACTIVE') "
                                  "ORDER BY o.created_at DESC LIMIT 1",
                                  (target_id, requirement["object_type"], requirement["recipe_id"],
                                   requirement["creator_identity_id"], requirement["tenant_id"],
                                   requirement["parent_test_object_id"], requirement["test_object_id"],
                                   requirement["test_object_id"])).fetchone()
                if item is None or item[0] in selected:
                    return False
                selected.append(item[0])
            now = datetime.now(timezone.utc)
            for object_id in selected:
                db.execute("INSERT INTO test_object_reservations VALUES (?,?,?,?,?,?,NULL)",
                           ("OBJRES-" + uuid.uuid4().hex, object_id, run_id, "ACTIVE",
                            now.isoformat(), (now + timedelta(seconds=lease_seconds)).isoformat()))
                db.execute("UPDATE test_objects SET lifecycle='IN_USE',updated_at=? WHERE test_object_id=?",
                           (now.isoformat(), object_id))
                self._event(db, object_id, "OBJECT_RESERVED", "PLAN_PREREQUISITE",
                            source="PLAN_ORCHESTRATOR")
        return True

    def release_run(self, run_id: str, target_id: str) -> int:
        count = 0
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT r.reservation_id,r.test_object_id FROM test_object_reservations r "
                              "JOIN test_objects o ON o.test_object_id=r.test_object_id "
                              "WHERE r.holder_run_id=? AND r.status='ACTIVE' AND o.target_id=?",
                              (run_id, target_id)).fetchall()
            for row in rows:
                db.execute("UPDATE test_object_reservations SET status='RELEASED',released_at=? "
                           "WHERE reservation_id=?", (_now(), row["reservation_id"]))
                db.execute("UPDATE test_objects SET lifecycle='CLEANUP_PENDING',updated_at=? "
                           "WHERE test_object_id=? AND lifecycle='IN_USE'", (_now(), row["test_object_id"]))
                self._event(db, row["test_object_id"], "OBJECT_RELEASED", "RUN_FINISHED",
                            source="PLAN_ORCHESTRATOR")
                count += 1
        return count

    def transition(self, object_id: str, target_id: str, expected: frozenset[ObjectState],
                   state: ObjectState, reason: str, *, action_id: str | None = None,
                   approval_id: str | None = None, exchange_id: str | None = None,
                   evidence_ids: tuple[str, ...] = (), external_id_hash: str | None = None,
                   external_id_evidence_id: str | None = None,
                   owner_principal_id: str | None = None,
                   source: str = "OBJECT_FACTORY") -> TestObject:
        if not _ID.fullmatch(object_id) or not isinstance(state, ObjectState) or not _CODE.fullmatch(reason):
            raise ValueError("invalid object transition")
        if (len(evidence_ids) > 16 or external_id_hash is not None and not _HASH.fullmatch(external_id_hash)
                or (external_id_hash is None) != (external_id_evidence_id is None)):
            raise ValueError("invalid object transition evidence")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM test_objects WHERE test_object_id=? AND target_id=?",
                             (object_id, target_id)).fetchone()
            if row is None or ObjectState(row["lifecycle"]) not in expected:
                raise ValueError("object lifecycle changed")
            refs = {"CREATED": "creation_evidence_json", "VERIFYING": "verification_evidence_json",
                    "READY": "verification_evidence_json", "CLEANED": "cleanup_evidence_json",
                    "ORPHANED": "cleanup_evidence_json"}.get(state.value)
            if evidence_ids:
                marks = ",".join("?" for _ in evidence_ids)
                count = db.execute(f"SELECT count(*) FROM evidence WHERE target_ref=? AND evidence_id IN ({marks})",
                                   (target_id, *evidence_ids)).fetchone()[0]
                if count != len(set(evidence_ids)):
                    raise ValueError("object evidence is not target-owned")
            if external_id_evidence_id is not None:
                linked = db.execute("SELECT evidence_type,target_ref,sensitivity FROM evidence WHERE evidence_id=?",
                                    (external_id_evidence_id,)).fetchone()
                if (linked is None or linked["target_ref"] != target_id or
                        linked["sensitivity"] != "SECRET" or
                        linked["evidence_type"] != "TEST_OBJECT_EXTERNAL_ID"):
                    raise ValueError("external object ID evidence is invalid")
            updates = {"lifecycle": state.value, "updated_at": _now(),
                       "pending_action_id": action_id,
                       "pending_approval_id": approval_id}
            if state is ObjectState.READY:
                updates["verified_at"] = _now()
            if state is ObjectState.CLEANED:
                updates["cleaned_at"] = _now()
            if state in {ObjectState.READY, ObjectState.CLEANED, ObjectState.ORPHANED,
                         ObjectState.UNKNOWN, ObjectState.FAILED}:
                updates["last_checked_at"] = _now()
            if external_id_hash is not None:
                updates["external_id_hash"] = external_id_hash
                updates["external_id_evidence_id"] = external_id_evidence_id
            if owner_principal_id is not None:
                updates["owner_principal_id"] = owner_principal_id
            if state is ObjectState.CREATED and exchange_id:
                updates["creation_exchange_id"] = exchange_id
            if refs and evidence_ids:
                updates[refs] = json.dumps(tuple(dict.fromkeys((
                    *json.loads(row[refs]), *evidence_ids)))[:16])
            clause = ",".join(key + "=?" for key in updates)
            db.execute("UPDATE test_objects SET " + clause + " WHERE test_object_id=?",
                       (*updates.values(), object_id))
            self._event(db, object_id, "OBJECT_" + state.value, reason, source=source,
                        action_id=action_id, exchange_id=exchange_id, evidence_ids=evidence_ids)
            new = db.execute("SELECT * FROM test_objects WHERE test_object_id=?", (object_id,)).fetchone()
        return self._object(new)

    def reserve_budget(self, object_id: str, target_id: str, *, cleanup: bool, maximum: int) -> int:
        if type(maximum) is not int or not 1 <= maximum <= 20:
            raise ValueError("invalid object request allowance")
        column = "cleanup_requests_reserved" if cleanup else "setup_requests_reserved"
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT " + column + " FROM test_objects WHERE test_object_id=? AND target_id=?",
                             (object_id, target_id)).fetchone()
            if row is None or row[0] >= maximum:
                raise ValueError("CLEANUP_BUDGET_EXHAUSTED" if cleanup else "SETUP_BUDGET_EXHAUSTED")
            db.execute("UPDATE test_objects SET " + column + "=" + column + "+1,updated_at=? "
                       "WHERE test_object_id=?", (_now(), object_id))
            self._event(db, object_id, "REQUEST_BUDGET_RESERVED", "CLEANUP" if cleanup else "SETUP")
            return row[0] + 1

    def begin_operation(self, object_id: str, target_id: str, action_id: str,
                        kind: str, decision_id: str, permit_id: str) -> bool:
        if kind not in {"CREATE", "VERIFY", "UPDATE", "CLEANUP", "VERIFY_CLEANUP"}:
            raise ValueError("invalid object operation")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT 1 FROM test_objects WHERE test_object_id=? AND target_id=?",
                             (object_id, target_id)).fetchone()
            if row is None:
                raise LookupError("object not found")
            if db.execute("SELECT 1 FROM test_object_operations WHERE action_id=?",
                          (action_id,)).fetchone():
                return False
            at = _now()
            db.execute("INSERT INTO test_object_operations VALUES (?,?,?,NULL,NULL,?,?,?,'AUTHORIZED',?,?)",
                       (action_id, object_id, kind, decision_id, permit_id, "PENDING", at, at))
            self._event(db, object_id, "OBJECT_POLICY_ALLOWED", kind, action_id=action_id)
        return True

    def operation_dispatched(self, action_id: str, exchange_id: str) -> bool:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT test_object_id FROM test_object_operations WHERE action_id=? "
                             "AND status='PENDING'", (action_id,)).fetchone()
            if row is None:
                return False
            db.execute("UPDATE test_object_operations SET status='DISPATCHING',exchange_id=?,updated_at=? "
                       "WHERE action_id=?", (exchange_id, _now(), action_id))
            self._event(db, row["test_object_id"], "OBJECT_REQUEST_DISPATCHED", "BOUND_REQUEST",
                        action_id=action_id, exchange_id=exchange_id)
        return True

    def finish_operation(self, action_id: str, *, status: str, reason: str,
                         execution_id: str | None = None) -> None:
        if status not in {"SUCCEEDED", "DENIED", "FAILED", "AMBIGUOUS"} or not _CODE.fullmatch(reason):
            raise ValueError("invalid object operation result")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT test_object_id,status FROM test_object_operations WHERE action_id=?",
                             (action_id,)).fetchone()
            if row is None or row["status"] not in {"PENDING", "DISPATCHING"}:
                raise ValueError("object operation is not pending")
            db.execute("UPDATE test_object_operations SET status=?,reason_code=?,execution_id=?,updated_at=? "
                       "WHERE action_id=?", (status, reason, execution_id, _now(), action_id))
            self._event(db, row["test_object_id"], "OBJECT_OPERATION_" + status, reason,
                        action_id=action_id)

    def reserve(self, object_id: str, target_id: str, run_id: str, *, lease_seconds: int = 900) -> str:
        if type(lease_seconds) is not int or not 30 <= lease_seconds <= 3600:
            raise ValueError("invalid object lease")
        reservation_id = "OBJRES-" + uuid.uuid4().hex
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT lifecycle,verified_at,disposable FROM test_objects "
                             "WHERE test_object_id=? AND target_id=?", (object_id, target_id)).fetchone()
            run = db.execute("SELECT status,target_id FROM plan_runs WHERE run_id=?", (run_id,)).fetchone()
            if (row is None or row["lifecycle"] != "READY" or not row["verified_at"] or
                    not row["disposable"] or run is None or run["target_id"] != target_id or
                    run["status"] in {"COMPLETED", "FAILED", "CANCELLED", "BLOCKED", "REJECTED"}):
                raise ValueError("object is not reservable")
            now = datetime.now(timezone.utc)
            try:
                db.execute("INSERT INTO test_object_reservations VALUES (?,?,?,?,?,?,NULL)",
                           (reservation_id, object_id, run_id, "ACTIVE", now.isoformat(),
                            (now + timedelta(seconds=lease_seconds)).isoformat()))
            except sqlite3.IntegrityError:
                raise ValueError("object is already reserved") from None
            db.execute("UPDATE test_objects SET lifecycle='IN_USE',updated_at=? WHERE test_object_id=?",
                       (now.isoformat(), object_id))
            self._event(db, object_id, "OBJECT_RESERVED", "PLAN_RUN", source="PLAN_ORCHESTRATOR")
        return reservation_id

    def release(self, object_id: str, target_id: str, run_id: str) -> TestObject:
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT lifecycle FROM test_objects WHERE test_object_id=? AND target_id=?",
                             (object_id, target_id)).fetchone()
            changed = db.execute("UPDATE test_object_reservations SET status='RELEASED',released_at=? "
                                 "WHERE test_object_id=? AND holder_run_id=? AND status='ACTIVE'",
                                 (_now(), object_id, run_id)).rowcount
            if row is None or changed != 1 or row["lifecycle"] != "IN_USE":
                raise ValueError("reservation is not active")
            db.execute("UPDATE test_objects SET lifecycle='CLEANUP_PENDING',updated_at=? "
                       "WHERE test_object_id=?", (_now(), object_id))
            self._event(db, object_id, "OBJECT_RELEASED", "CLEANUP_PENDING",
                        source="PLAN_ORCHESTRATOR")
            new = db.execute("SELECT * FROM test_objects WHERE test_object_id=?", (object_id,)).fetchone()
        return self._object(new)

    def active_reservation(self, object_id: str) -> str | None:
        with self.store._connection() as db:
            row = db.execute("SELECT holder_run_id FROM test_object_reservations WHERE "
                             "test_object_id=? AND status='ACTIVE' LIMIT 1", (object_id,)).fetchone()
        return row[0] if row else None

    def owned_for_action(self, action: ProposedAction) -> bool:
        if (action.object_ref_hash is None or not action.disposable_intent or
                action.category not in {ActionCategory.OBJECT_UPDATE,
                                        ActionCategory.OBJECT_DELETE,
                                        ActionCategory.AUTHORIZATION_TEST}):
            return False
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM test_objects WHERE target_id=? AND package_id=? "
                             "AND external_id_hash=? AND object_type=? AND disposable=1 AND "
                             "verified_at IS NOT NULL AND lifecycle IN "
                             "('READY','IN_USE','CLEANUP_PENDING','CLEANING') LIMIT 1",
                             (action.target_id, action.package_id, action.object_ref_hash,
                              action.object_type)).fetchone()
            if row is None:
                return False
            holder = db.execute("SELECT holder_run_id FROM test_object_reservations WHERE "
                                "test_object_id=? AND status='ACTIVE' LIMIT 1",
                                (row["test_object_id"],)).fetchone()
            if action.source == "object_factory":
                return action.identity_id == row["creator_identity_id"] and holder is None
            if action.source == "plan_orchestrator":
                linked = db.execute("SELECT run_id FROM plan_run_steps WHERE action_id=? LIMIT 1",
                                    (action.id,)).fetchone()
                return bool(linked and holder and linked[0] == holder[0])
            return False

    def reconcile(self) -> int:
        changed = 0
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT test_object_id,lifecycle FROM test_objects WHERE lifecycle IN "
                              "('CREATING','VERIFYING','CLEANING') LIMIT 1000").fetchall()
            for row in rows:
                state = "ORPHANED" if row["lifecycle"] == "CLEANING" else "UNKNOWN"
                db.execute("UPDATE test_objects SET lifecycle=?,updated_at=?,last_checked_at=? "
                           "WHERE test_object_id=?", (state, _now(), _now(), row["test_object_id"]))
                self._event(db, row["test_object_id"], "OBJECT_ORPHANED" if state == "ORPHANED"
                            else "OBJECT_UNKNOWN", "STARTUP_RECONCILIATION", source="RECONCILIATION")
                changed += 1
            leases = db.execute("SELECT r.reservation_id,r.test_object_id FROM test_object_reservations r "
                                "JOIN test_objects o ON o.test_object_id=r.test_object_id "
                                "WHERE r.status='ACTIVE' AND (r.expires_at<=? OR o.lifecycle!='IN_USE') "
                                "LIMIT 1000", (_now(),)).fetchall()
            for row in leases:
                db.execute("UPDATE test_object_reservations SET status='EXPIRED',released_at=? "
                           "WHERE reservation_id=?", (_now(), row["reservation_id"]))
                db.execute("UPDATE test_objects SET lifecycle='UNKNOWN',updated_at=? "
                           "WHERE test_object_id=? AND lifecycle='IN_USE'",
                           (_now(), row["test_object_id"]))
                self._event(db, row["test_object_id"], "OBJECT_UNKNOWN", "LEASE_EXPIRED",
                            source="RECONCILIATION")
                changed += 1
            unreserved = db.execute("SELECT o.test_object_id FROM test_objects o WHERE o.lifecycle='IN_USE' "
                                    "AND NOT EXISTS (SELECT 1 FROM test_object_reservations r WHERE "
                                    "r.test_object_id=o.test_object_id AND r.status='ACTIVE') "
                                    "LIMIT 1000").fetchall()
            for row in unreserved:
                db.execute("UPDATE test_objects SET lifecycle='UNKNOWN',updated_at=? WHERE test_object_id=?",
                           (_now(), row["test_object_id"]))
                self._event(db, row["test_object_id"], "OBJECT_UNKNOWN", "UNRESERVED_IN_USE",
                            source="RECONCILIATION")
                changed += 1
        return changed

    def mark_manual_cleaned(self, object_id: str, target_id: str, *, reason: str,
                            evidence_ids: tuple[str, ...] = ()) -> TestObject:
        if not _CODE.fullmatch(reason):
            raise ValueError("manual cleanup reason must be a code")
        item = self.get(object_id, target_id)
        if item is None or not item.disposable or item.state not in {
            ObjectState.READY, ObjectState.CLEANUP_PENDING, ObjectState.ORPHANED,
            ObjectState.UNKNOWN, ObjectState.FAILED}:
            raise ValueError("object is not eligible for manual cleanup")
        if self.active_reservation(item.id):
            raise ValueError("object is reserved")
        return self.transition(item.id, target_id, frozenset({item.state}), ObjectState.CLEANED,
                               reason, evidence_ids=evidence_ids, source="MANUAL")

    def set_verified_name(self, object_id: str, target_id: str, name: str,
                          evidence_ids: tuple[str, ...]) -> TestObject:
        if not re.fullmatch(r"[a-z][a-z0-9-]{3,64}", name) or not evidence_ids:
            raise ValueError("invalid verified test name")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT lifecycle FROM test_objects WHERE test_object_id=? AND target_id=?",
                             (object_id, target_id)).fetchone()
            if row is None or row["lifecycle"] != "READY":
                raise ValueError("object name update is not verified")
            marks = ",".join("?" for _ in evidence_ids)
            count = db.execute(f"SELECT count(*) FROM evidence WHERE target_ref=? AND evidence_id IN ({marks})",
                               (target_id, *evidence_ids)).fetchone()[0]
            if count != len(set(evidence_ids)):
                raise ValueError("object name evidence is not target-owned")
            db.execute("UPDATE test_objects SET test_name=?,updated_at=? WHERE test_object_id=?",
                       (name, _now(), object_id))
            self._event(db, object_id, "OBJECT_RENAMED", "READBACK_VERIFIED",
                        evidence_ids=evidence_ids)
            new = db.execute("SELECT * FROM test_objects WHERE test_object_id=?", (object_id,)).fetchone()
        return self._object(new)

    def events(self, object_id: str, target_id: str, *, limit: int = 50) -> tuple[dict[str, object], ...]:
        if type(limit) is not int or not 1 <= limit <= 100 or self.get(object_id, target_id) is None:
            raise LookupError("object not found")
        with self.store._connection() as db:
            rows = db.execute("SELECT event_type,reason_code,source,action_id,exchange_id,"
                              "evidence_ids_json,occurred_at FROM test_object_events WHERE test_object_id=? "
                              "ORDER BY event_id DESC LIMIT ?", (object_id, limit)).fetchall()
        return tuple({**dict(row), "evidence_ids": json.loads(row["evidence_ids_json"])}
                     for row in rows)

    def stats(self, target_id: str | None = None) -> dict[str, object]:
        where = " WHERE target_id=?" if target_id else ""
        args = (target_id,) if target_id else ()
        with self.store._connection() as db:
            rows = db.execute("SELECT lifecycle,count(*) AS n,sum(cleanup_required) AS needs_cleanup "
                              "FROM test_objects" + where +
                              " GROUP BY lifecycle", args).fetchall()
            lifetime = db.execute("SELECT avg((julianday(cleaned_at)-julianday(created_at))*86400) "
                                  "FROM test_objects" + where +
                                  (" AND cleaned_at IS NOT NULL" if where else
                                   " WHERE cleaned_at IS NOT NULL"), args).fetchone()[0]
        counts = {row["lifecycle"]: row["n"] for row in rows}
        pending = sum(row["needs_cleanup"] for row in rows if row["lifecycle"] in {
            "CREATING", "CREATED", "VERIFYING", "READY", "IN_USE", "CLEANUP_PENDING",
            "CLEANING", "ORPHANED", "UNKNOWN"})
        return {"objects": sum(counts.values()), "created": sum(counts.get(key, 0) for key in
                ("CREATED", "VERIFYING", "READY", "IN_USE", "CLEANUP_PENDING", "CLEANING", "CLEANED", "ORPHANED")),
                "ready": counts.get("READY", 0), "cleaned": counts.get("CLEANED", 0),
                "orphaned": counts.get("ORPHANED", 0), "unknown": counts.get("UNKNOWN", 0),
                "creation_failures": counts.get("FAILED", 0),
                "cleanup_failures": counts.get("ORPHANED", 0),
                "cleanup_pending": pending,
                "average_lifetime_seconds": round(lifetime, 1) if lifetime is not None else None}
