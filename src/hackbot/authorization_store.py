"""Bounded, target-scoped metadata for authorization research."""

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
from .response_compare import ResponseComparator
from .traffic import TrafficStore


_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuthorizationMode(StrEnum):
    MANUAL = "MANUAL"
    PLAN_ONLY = "PLAN_ONLY"
    BOUNDED_AUTONOMOUS = "BOUNDED_AUTONOMOUS"


class HuntStatus(StrEnum):
    CREATED = "CREATED"
    PROFILING = "PROFILING"
    GENERATING = "GENERATING"
    READY = "READY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class MatrixResult(StrEnum):
    OBSERVED_ALLOWED = "OBSERVED_ALLOWED"
    OBSERVED_DENIED = "OBSERVED_DENIED"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNKNOWN = "UNKNOWN"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    NOT_FOUND = "NOT_FOUND"
    ERROR = "ERROR"
    AMBIGUOUS = "AMBIGUOUS"


class Boundary(StrEnum):
    CROSS_TENANT = "CROSS_TENANT"
    HORIZONTAL = "HORIZONTAL"
    VERTICAL = "VERTICAL"
    HIDDEN_FUNCTION = "HIDDEN_FUNCTION"
    ANONYMOUS = "ANONYMOUS"
    GRAPHQL_OBJECT = "GRAPHQL_OBJECT"
    GRAPHQL_MUTATION = "GRAPHQL_MUTATION"
    SAME_USER = "SAME_USER"
    PARENT_CHILD = "PARENT_CHILD"


@dataclass(frozen=True, slots=True)
class AuthorizationHunt:
    id: str
    target_id: str
    package_id: str
    mode: AuthorizationMode
    status: HuntStatus
    candidate_limit: int
    request_budget: int
    reason_code: str | None
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "target_id": self.target_id, "package_id": self.package_id,
                "mode": self.mode.value, "status": self.status.value,
                "candidate_limit": self.candidate_limit, "request_budget": self.request_budget,
                "reason_code": self.reason_code, "created_at": self.created_at,
                "updated_at": self.updated_at}


@dataclass(frozen=True, slots=True)
class AuthorizationCandidate:
    id: str
    target_id: str
    hunt_id: str
    dedupe_key: str
    boundary: Boundary
    owner_identity_id: str
    boundary_identity_id: str | None
    test_object_id: str
    owner_exchange_id: str
    operation_key: str
    score: int
    reasons: tuple[str, ...]
    status: str
    hypothesis_id: str | None = None
    plan_id: str | None = None
    run_id: str | None = None
    validation_id: str | None = None
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "target_id": self.target_id, "hunt_id": self.hunt_id,
                "boundary": self.boundary.value, "owner_identity_id": self.owner_identity_id,
                "boundary_identity_id": self.boundary_identity_id,
                "test_object_id": self.test_object_id, "owner_exchange_id": self.owner_exchange_id,
                "operation_key": self.operation_key, "score": self.score,
                "reasons": list(self.reasons), "status": self.status,
                "hypothesis_id": self.hypothesis_id, "plan_id": self.plan_id,
                "run_id": self.run_id, "validation_id": self.validation_id,
                "created_at": self.created_at, "updated_at": self.updated_at}


class AuthorizationStore:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    @staticmethod
    def _hunt(row: sqlite3.Row) -> AuthorizationHunt:
        return AuthorizationHunt(row["hunt_id"], row["target_id"], row["package_id"],
                                 AuthorizationMode(row["mode"]), HuntStatus(row["status"]),
                                 row["candidate_limit"], row["request_budget"], row["reason_code"],
                                 row["created_at"], row["updated_at"])

    @staticmethod
    def _candidate(row: sqlite3.Row) -> AuthorizationCandidate:
        return AuthorizationCandidate(row["candidate_id"], row["target_id"], row["hunt_id"],
                                      row["dedupe_key"], Boundary(row["boundary"]),
                                      row["owner_identity_id"], row["boundary_identity_id"],
                                      row["test_object_id"], row["owner_exchange_id"],
                                      row["operation_key"], row["score"],
                                      tuple(json.loads(row["reasons_json"])), row["status"],
                                      row["hypothesis_id"], row["plan_id"], row["run_id"],
                                      row["validation_id"], row["created_at"], row["updated_at"])

    def create_hunt(self, target_id: str, package_id: str, *, mode: AuthorizationMode = AuthorizationMode.PLAN_ONLY,
                    candidate_limit: int = 12, request_budget: int = 20) -> AuthorizationHunt:
        if (not isinstance(mode, AuthorizationMode) or type(candidate_limit) is not int
                or not 1 <= candidate_limit <= 50 or type(request_budget) is not int
                or not 0 <= request_budget <= 50):
            raise ValueError("invalid authorization hunt bounds")
        at = _now()
        hunt_id = "AUTHH-" + uuid.uuid4().hex
        with self.store._connection() as db:
            target = db.execute("SELECT package_id FROM registry_targets WHERE target_id=?",
                                (target_id,)).fetchone()
            if target is None or target[0] != package_id:
                raise ValueError("authorization hunt target mismatch")
            db.execute("INSERT INTO authorization_hunts VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (hunt_id, target_id, package_id, mode.value, HuntStatus.CREATED.value,
                        candidate_limit, request_budget, None, at, at))
        return self.get_hunt(hunt_id, target_id)

    def get_hunt(self, hunt_id: str, target_id: str) -> AuthorizationHunt | None:
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM authorization_hunts WHERE hunt_id=? AND target_id=?",
                             (hunt_id, target_id)).fetchone()
        return self._hunt(row) if row else None

    def list_hunts(self, target_id: str, *, limit: int = 20) -> tuple[AuthorizationHunt, ...]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("invalid authorization hunt page size")
        with self.store._connection() as db:
            rows = db.execute("SELECT * FROM authorization_hunts WHERE target_id=? "
                              "ORDER BY created_at DESC,hunt_id DESC LIMIT ?", (target_id, limit)).fetchall()
        return tuple(self._hunt(row) for row in rows)

    def transition(self, hunt_id: str, target_id: str, expected: HuntStatus,
                   status: HuntStatus, reason_code: str | None = None) -> AuthorizationHunt:
        if reason_code is not None and not _CODE.fullmatch(reason_code):
            raise ValueError("invalid authorization hunt reason")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("UPDATE authorization_hunts SET status=?,reason_code=?,updated_at=? "
                                 "WHERE hunt_id=? AND target_id=? AND status=?",
                                 (status.value, reason_code, _now(), hunt_id, target_id,
                                  expected.value)).rowcount
            if changed != 1:
                raise ValueError("authorization hunt state changed")
        result = self.get_hunt(hunt_id, target_id)
        assert result is not None
        return result

    def upsert_candidate(self, candidate: AuthorizationCandidate) -> AuthorizationCandidate:
        if (not _HASH.fullmatch(candidate.dedupe_key) or not _HASH.fullmatch(candidate.operation_key)
                or not 0 <= candidate.score <= 100 or not 1 <= len(candidate.reasons) <= 12
                or any(not _CODE.fullmatch(reason) for reason in candidate.reasons)
                or candidate.status not in {"CANDIDATE", "NEEDS_OBJECT", "NEEDS_TEMPLATE",
                                             "NEEDS_SESSION", "NEEDS_MANUAL_REVIEW", "READY"}):
            raise ValueError("invalid authorization candidate")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            related = db.execute("SELECT h.target_id AS hunt_target,o.target_id AS object_target,"
                                 "o.creator_identity_id,o.disposable,"
                                 "o.verified_at,x.target_id AS exchange_target,x.verified_identity_id "
                                 "FROM authorization_hunts h JOIN test_objects o ON o.test_object_id=? "
                                 "JOIN traffic_exchanges x ON x.exchange_id=? WHERE h.hunt_id=?",
                                 (candidate.test_object_id, candidate.owner_exchange_id,
                                  candidate.hunt_id)).fetchone()
            if (related is None or any(related[key] != candidate.target_id for key in
                                       ("hunt_target", "object_target", "exchange_target")) or
                    related["creator_identity_id"] != candidate.owner_identity_id or
                    related["verified_identity_id"] != candidate.owner_identity_id or
                    not related["verified_at"] or not related["disposable"]):
                raise ValueError("candidate lacks a verified owned object and owner exchange")
            if candidate.boundary_identity_id:
                actor = db.execute("SELECT target_id FROM registry_identities WHERE identity_id=?",
                                   (candidate.boundary_identity_id,)).fetchone()
                if actor is None or actor[0] != candidate.target_id:
                    raise ValueError("candidate boundary identity is outside target")
            at = _now()
            db.execute("INSERT OR IGNORE INTO authorization_candidates VALUES "
                       "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (candidate.id, candidate.target_id, candidate.hunt_id, candidate.dedupe_key,
                        candidate.boundary.value, candidate.owner_identity_id,
                        candidate.boundary_identity_id, candidate.test_object_id,
                        candidate.owner_exchange_id, candidate.operation_key, candidate.score,
                        json.dumps(candidate.reasons), candidate.status, None, None, None, None,
                        at, at))
            row = db.execute("SELECT * FROM authorization_candidates WHERE target_id=? AND dedupe_key=?",
                             (candidate.target_id, candidate.dedupe_key)).fetchone()
            if row is not None:
                db.execute("INSERT OR IGNORE INTO authorization_hunt_candidates VALUES (?,?,?)",
                           (candidate.hunt_id, row["candidate_id"], at))
        assert row is not None
        return self._candidate(row)

    def get_candidate(self, candidate_id: str, target_id: str) -> AuthorizationCandidate | None:
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM authorization_candidates WHERE candidate_id=? AND target_id=?",
                             (candidate_id, target_id)).fetchone()
        return self._candidate(row) if row else None

    def list_candidates(self, target_id: str, *, limit: int = 20,
                        hunt_id: str | None = None) -> tuple[AuthorizationCandidate, ...]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("invalid authorization candidate page size")
        clause = (" AND candidate_id IN (SELECT candidate_id FROM authorization_hunt_candidates "
                  "WHERE hunt_id=?)") if hunt_id else ""
        params = (target_id, hunt_id, limit) if hunt_id else (target_id, limit)
        with self.store._connection() as db:
            rows = db.execute("SELECT * FROM authorization_candidates WHERE target_id=?" + clause +
                              " ORDER BY score DESC,candidate_id LIMIT ?", params).fetchall()
        return tuple(self._candidate(row) for row in rows)

    def link_candidate(self, candidate_id: str, target_id: str, *, status: str,
                       hypothesis_id: str | None = None, plan_id: str | None = None,
                       run_id: str | None = None, validation_id: str | None = None) -> AuthorizationCandidate:
        if status not in {"NEEDS_OBJECT", "NEEDS_TEMPLATE", "NEEDS_SESSION", "NEEDS_MANUAL_REVIEW",
                          "READY", "PLANNED", "RUNNING", "VALIDATED", "REJECTED", "BLOCKED"}:
            raise ValueError("invalid authorization candidate status")
        for table, key, value in (("hypotheses", "hypothesis_id", hypothesis_id),
                                  ("skill_plans", "plan_id", plan_id),
                                  ("plan_runs", "run_id", run_id),
                                  ("validations", "validation_id", validation_id)):
            if value is None:
                continue
            with self.store._connection() as db:
                row = db.execute(f"SELECT target_id FROM {table} WHERE {key}=?", (value,)).fetchone()
            if row is None or row[0] != target_id:
                raise ValueError("authorization candidate link target mismatch")
        with self.store._connection() as db:
            changed = db.execute("UPDATE authorization_candidates SET status=?,"
                                 "hypothesis_id=COALESCE(?,hypothesis_id),plan_id=COALESCE(?,plan_id),"
                                 "run_id=COALESCE(?,run_id),validation_id=COALESCE(?,validation_id),updated_at=? "
                                 "WHERE candidate_id=? AND target_id=?",
                                 (status, hypothesis_id, plan_id, run_id, validation_id, _now(),
                                  candidate_id, target_id)).rowcount
            if changed != 1:
                raise LookupError("authorization candidate not found")
        result = self.get_candidate(candidate_id, target_id)
        assert result is not None
        return result

    def link_created_object(self, hunt_id: str, target_id: str, object_id: str) -> None:
        """Only the specialist's newly created prerequisites belong to a hunt."""
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT o.target_id,o.package_id,h.package_id AS hunt_package "
                "FROM test_objects o JOIN authorization_hunts h ON h.hunt_id=? "
                "AND h.target_id=? WHERE o.test_object_id=?",
                (hunt_id, target_id, object_id)).fetchone()
            if (row is None or row["target_id"] != target_id or
                    row["package_id"] != row["hunt_package"]):
                raise ValueError("created authorization object is outside hunt")
            at = _now()
            db.execute("INSERT OR IGNORE INTO authorization_hunt_objects VALUES (?,?,?,?,?,?)",
                       (hunt_id, object_id, target_id, None, at, at))

    def created_objects(self, hunt_id: str, target_id: str) -> tuple[tuple[str, str | None], ...]:
        if self.get_hunt(hunt_id, target_id) is None:
            raise LookupError("authorization hunt not found")
        with self.store._connection() as db:
            rows = db.execute("SELECT test_object_id,cleanup_outcome FROM authorization_hunt_objects "
                              "WHERE hunt_id=? AND target_id=? ORDER BY linked_at LIMIT 50",
                              (hunt_id, target_id)).fetchall()
        return tuple((row[0], row[1]) for row in rows)

    def record_cleanup(self, hunt_id: str, target_id: str, object_id: str,
                       outcome: str) -> None:
        if not _CODE.fullmatch(outcome):
            raise ValueError("invalid authorization cleanup result")
        with self.store._connection() as db:
            changed = db.execute("UPDATE authorization_hunt_objects SET cleanup_outcome=?,updated_at=? "
                                 "WHERE hunt_id=? AND target_id=? AND test_object_id=?",
                                 (outcome, _now(), hunt_id, target_id, object_id)).rowcount
            if changed != 1:
                raise LookupError("authorization-created object not found")

    def record_observation(self, *, target_id: str, operation_key: str,
                           exchange_id: str, result: MatrixResult,
                           candidate_id: str | None = None, test_object_id: str | None = None,
                           tenant_id: str | None = None, role_id: str | None = None) -> str:
        if not _HASH.fullmatch(operation_key) or not isinstance(result, MatrixResult):
            raise ValueError("invalid authorization observation")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT target_id,verified_identity_id,principal_id,auth_state,observed_at "
                             "FROM traffic_exchanges WHERE exchange_id=?", (exchange_id,)).fetchone()
            if row is None or row["target_id"] != target_id:
                raise ValueError("authorization observation exchange target mismatch")
            if row["auth_state"] not in {"VERIFIED", "ANONYMOUS"}:
                raise ValueError("unverified traffic cannot become an authorization observation")
            for table, field, value in (("authorization_candidates", "candidate_id", candidate_id),
                                        ("test_objects", "test_object_id", test_object_id),
                                        ("registry_tenants", "tenant_id", tenant_id),
                                        ("registry_roles", "role_id", role_id)):
                if value is None:
                    continue
                linked = db.execute(f"SELECT target_id FROM {table} WHERE {field}=?", (value,)).fetchone()
                if linked is None or linked[0] != target_id:
                    raise ValueError("authorization observation relation target mismatch")
            if result is MatrixResult.OBSERVED_ALLOWED:
                if test_object_id is None:
                    raise ValueError("allowed authorization requires a verified object")
                object_row = db.execute(
                    "SELECT external_id_hash,external_id_evidence_id,verified_at,disposable "
                    "FROM test_objects WHERE test_object_id=? AND target_id=?",
                    (test_object_id, target_id)).fetchone()
                if (object_row is None or not object_row["verified_at"] or
                        not object_row["disposable"] or not object_row["external_id_evidence_id"]):
                    raise ValueError("allowed authorization lacks object ownership proof")
                value = self.store.read_content(object_row["external_id_evidence_id"],
                                                allow_sensitive=True, max_bytes=256).decode("ascii")
                if hashlib.sha256((test_object_id + ":" + value).encode()).hexdigest() != object_row["external_id_hash"]:
                    raise ValueError("allowed authorization object ID integrity failed")
                exchange = TrafficStore(self.store).get_exchange(exchange_id)
                if exchange is None:
                    raise ValueError("allowed authorization exchange is missing")
                features = ResponseComparator(self.store).features(exchange)
                if (features.status_code is None or not 200 <= features.status_code < 300 or
                        features.graphql_errors_present or
                        hashlib.sha256(value.encode()).hexdigest() not in features.object_id_hashes):
                    raise ValueError("allowed authorization lacks semantic object response")
            if result is MatrixResult.OBSERVED_DENIED:
                exchange = TrafficStore(self.store).get_exchange(exchange_id)
                if exchange is None or exchange.response is None:
                    raise ValueError("denied authorization lacks a response")
                features = ResponseComparator(self.store).features(exchange)
                if (features.status_code != 403 and not
                        (features.graphql_errors_present and not features.graphql_data_present)):
                    raise ValueError("denied authorization requires semantic rejection")
            evidence = db.execute("SELECT r.observation_evidence_id AS request_evidence,"
                                  "s.observation_evidence_id AS response_evidence "
                                  "FROM traffic_exchanges x JOIN traffic_requests r ON r.request_id=x.request_id "
                                  "LEFT JOIN traffic_responses s ON s.request_id=r.request_id "
                                  "WHERE x.exchange_id=?", (exchange_id,)).fetchone()
            evidence_ids = [item for item in (evidence[0], evidence[1]) if item]
            observation_id = "AUTHO-" + uuid.uuid4().hex
            db.execute("INSERT OR IGNORE INTO authorization_observations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (observation_id, target_id, candidate_id, row["verified_identity_id"],
                        row["principal_id"], tenant_id, role_id, test_object_id, operation_key,
                        result.value, exchange_id, json.dumps(evidence_ids), row["observed_at"]))
            saved = db.execute("SELECT observation_id FROM authorization_observations WHERE target_id=? "
                               "AND exchange_id=? AND operation_key=?",
                               (target_id, exchange_id, operation_key)).fetchone()
        return saved[0]

    def matrix(self, target_id: str, *, limit: int = 50) -> tuple[dict[str, object], ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid authorization matrix limit")
        with self.store._connection() as db:
            rows = db.execute("SELECT observation_id,candidate_id,identity_id,principal_id,tenant_id,role_id,"
                              "test_object_id,operation_key,result,exchange_id,evidence_ids_json,observed_at "
                              "FROM authorization_observations WHERE target_id=? "
                              "ORDER BY observed_at DESC,observation_id DESC LIMIT ?",
                              (target_id, limit)).fetchall()
        return tuple({"id": row[0], "candidate_id": row[1], "identity_id": row[2],
                      "principal_id": row[3], "tenant_id": row[4], "role_id": row[5],
                      "test_object_id": row[6], "operation_key": row[7], "result": row[8],
                      "exchange_id": row[9], "evidence_ids": json.loads(row[10]),
                      "observed_at": row[11]} for row in rows)

    def stats(self, target_id: str, *, hunt_id: str | None = None) -> dict[str, int]:
        """Small, target-scoped counters; never load individual evidence bodies."""
        if hunt_id is not None and self.get_hunt(hunt_id, target_id) is None:
            raise LookupError("authorization hunt not found")
        clause = (" AND c.candidate_id IN (SELECT candidate_id FROM authorization_hunt_candidates "
                  "WHERE hunt_id=?)") if hunt_id else ""
        args = (target_id, hunt_id) if hunt_id else (target_id,)
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT c.status,count(*) FROM authorization_candidates c WHERE c.target_id=?" +
                clause + " GROUP BY c.status", args).fetchall()
            linked = db.execute(
                "SELECT count(DISTINCT c.plan_id) AS plans,count(DISTINCT c.run_id) AS runs "
                "FROM authorization_candidates c "
                "WHERE c.target_id=?" + clause, args).fetchone()
            validation_rows = db.execute(
                "SELECT v.status,count(*) FROM authorization_candidates c "
                "JOIN validations v ON v.validation_id=c.validation_id "
                "WHERE c.target_id=?" + clause + " GROUP BY v.status", args).fetchall()
            object_clause = " AND h.hunt_id=?" if hunt_id else ""
            object_args = (target_id, hunt_id) if hunt_id else (target_id,)
            object_rows = db.execute(
                "SELECT count(*) AS created,coalesce(sum(CASE WHEN o.lifecycle IN "
                "('ORPHANED','UNKNOWN','FAILED') OR h.cleanup_outcome IN "
                "('CLEANUP_FAILED','CLEANUP_REVIEW_REQUIRED') THEN 1 ELSE 0 END),0) "
                "AS cleanup_failures,"
                "coalesce(sum(CASE WHEN o.lifecycle!='CLEANED' THEN 1 ELSE 0 END),0) "
                "AS cleanup_pending FROM authorization_hunt_objects h "
                "JOIN test_objects o ON o.test_object_id=h.test_object_id "
                "WHERE h.target_id=?" + object_clause, object_args).fetchone()
            # A run belongs to one plan, but different runs may consume the same count.
            request_rows = db.execute(
                "SELECT coalesce(sum(r.requests_consumed),0) FROM plan_runs r "
                "WHERE r.run_id IN (SELECT DISTINCT c.run_id FROM authorization_candidates c "
                "WHERE c.target_id=?" + clause + ")", args).fetchone()
        statuses = dict(rows)
        validations = dict(validation_rows)
        return {"candidates": sum(statuses.values()), "plans": linked["plans"],
                "executed_plans": linked["runs"], "confirmed": validations.get("CONFIRMED", 0),
                "rejected": validations.get("REJECTED", 0),
                "manual_reviews": statuses.get("NEEDS_MANUAL_REVIEW", 0),
                "requests_used": request_rows[0], "objects_created": object_rows["created"],
                "cleanup_failures": object_rows["cleanup_failures"],
                "cleanup_pending": object_rows["cleanup_pending"]}

    def reconcile_runs(self) -> int:
        """Expose interrupted runs for review; never replay a request on restart."""
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT c.candidate_id,c.hunt_id,c.target_id FROM authorization_candidates c "
                "JOIN plan_runs r ON r.run_id=c.run_id WHERE c.status='RUNNING' "
                "AND r.status IN ('WAITING_HUMAN','BLOCKED','FAILED','BUDGET_EXHAUSTED',"
                "'CANCELLED','PAUSED','REJECTED') LIMIT 100").fetchall()
            for row in rows:
                db.execute("UPDATE authorization_candidates SET status='NEEDS_MANUAL_REVIEW',"
                           "updated_at=? WHERE candidate_id=? AND target_id=? AND status='RUNNING'",
                           (_now(), row["candidate_id"], row["target_id"]))
                db.execute("UPDATE authorization_hunts SET status='PAUSED',"
                           "reason_code='RUN_REQUIRES_REVIEW',updated_at=? "
                           "WHERE hunt_id=? AND target_id=? AND status='RUNNING'",
                           (_now(), row["hunt_id"], row["target_id"]))
        return len(rows)
