"""Secret-free, target-scoped mutation/read-back audit records."""

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
from .typed_mutations import MutationPhase, MutationType, TypedMutation


_ID = re.compile(r"MUT-[0-9a-f]{32}\Z")
_ACTION = re.compile(r"ACTION-[0-9a-f]{32}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def value_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class MutationStatus(StrEnum):
    PLANNED = "PLANNED"
    DISPATCHED = "DISPATCHED"
    VERIFIED = "VERIFIED"
    DENIED = "DENIED"
    AMBIGUOUS = "AMBIGUOUS"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True, slots=True)
class MutationResult:
    id: str
    target_id: str
    run_id: str
    test_object_id: str
    mutation_type: MutationType
    phase: MutationPhase
    actor_identity_id: str
    field: str
    recipe_hash: str
    expected_value_hash: str
    before_value_hash: str | None
    after_value_hash: str | None
    mutation_action_id: str
    mutation_exchange_id: str | None
    readback_action_id: str | None
    readback_exchange_id: str | None
    status: MutationStatus
    evidence_ids: tuple[str, ...]
    created_at: str
    updated_at: str

    @property
    def verified_effect(self) -> bool:
        return (self.status is MutationStatus.VERIFIED and
                self.after_value_hash == self.expected_value_hash and
                self.before_value_hash != self.after_value_hash)

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "target_id": self.target_id, "run_id": self.run_id,
                "test_object_id": self.test_object_id, "mutation_type": self.mutation_type.value,
                "phase": self.phase.value, "actor_identity_id": self.actor_identity_id,
                "field": self.field, "status": self.status.value,
                "verified_effect": self.verified_effect,
                "mutation_action_id": self.mutation_action_id,
                "mutation_exchange_id": self.mutation_exchange_id,
                "readback_action_id": self.readback_action_id,
                "readback_exchange_id": self.readback_exchange_id,
                "before_fingerprint": self.before_value_hash[:12] if self.before_value_hash else None,
                "after_fingerprint": self.after_value_hash[:12] if self.after_value_hash else None,
                "expected_fingerprint": self.expected_value_hash[:12],
                "evidence_ids": list(self.evidence_ids), "updated_at": self.updated_at}


class MutationResultStore:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    @staticmethod
    def _row(row: sqlite3.Row) -> MutationResult:
        return MutationResult(
            row["mutation_id"], row["target_id"], row["run_id"], row["test_object_id"],
            MutationType(row["mutation_type"]), MutationPhase(row["phase"]),
            row["actor_identity_id"], row["field"], row["recipe_hash"],
            row["expected_value_hash"], row["before_value_hash"], row["after_value_hash"],
            row["mutation_action_id"], row["mutation_exchange_id"],
            row["readback_action_id"], row["readback_exchange_id"],
            MutationStatus(row["status"]), tuple(json.loads(row["evidence_ids_json"])),
            row["created_at"], row["updated_at"])

    def get(self, mutation_id: str, target_id: str) -> MutationResult | None:
        if not isinstance(mutation_id, str) or not _ID.fullmatch(mutation_id):
            raise ValueError("invalid mutation ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM authorization_mutation_results "
                             "WHERE mutation_id=? AND target_id=?", (mutation_id, target_id)).fetchone()
        return self._row(row) if row else None

    def for_phase(self, run_id: str, test_object_id: str,
                  phase: MutationPhase) -> MutationResult | None:
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM authorization_mutation_results WHERE "
                             "run_id=? AND test_object_id=? AND phase=?",
                             (run_id, test_object_id, phase.value)).fetchone()
        return self._row(row) if row else None

    def list_for_run(self, run_id: str, target_id: str) -> tuple[MutationResult, ...]:
        with self.store._connection() as db:
            rows = db.execute("SELECT * FROM authorization_mutation_results WHERE "
                              "run_id=? AND target_id=? ORDER BY created_at LIMIT 12",
                              (run_id, target_id)).fetchall()
        return tuple(self._row(row) for row in rows)

    def list_for_object(self, object_id: str, target_id: str,
                        *, limit: int = 12) -> tuple[MutationResult, ...]:
        if not 1 <= limit <= 50:
            raise ValueError("invalid mutation history limit")
        with self.store._connection() as db:
            rows = db.execute("SELECT * FROM authorization_mutation_results WHERE "
                              "test_object_id=? AND target_id=? ORDER BY created_at DESC LIMIT ?",
                              (object_id, target_id, limit)).fetchall()
        return tuple(self._row(row) for row in rows)

    def stats(self, target_id: str) -> dict[str, int]:
        with self.store._connection() as db:
            rows = db.execute("SELECT phase,status,count(*) AS n FROM "
                              "authorization_mutation_results WHERE target_id=? "
                              "GROUP BY phase,status", (target_id,)).fetchall()
        counts = {"executed": 0, "verified_boundary": 0, "denied_boundary": 0,
                  "readback_failures": 0, "restore_failures": 0}
        for row in rows:
            if row["status"] != "PLANNED":
                counts["executed"] += row["n"]
            if row["phase"] == "BOUNDARY" and row["status"] == "VERIFIED":
                counts["verified_boundary"] += row["n"]
            if row["phase"] == "BOUNDARY" and row["status"] == "DENIED":
                counts["denied_boundary"] += row["n"]
            if row["status"] in {"AMBIGUOUS", "INSUFFICIENT_EVIDENCE"}:
                counts["readback_failures"] += row["n"]
            if row["phase"] == "RESTORE" and row["status"] in {
                    "DENIED", "AMBIGUOUS", "INSUFFICIENT_EVIDENCE"}:
                counts["restore_failures"] += row["n"]
        return counts

    def reconcile(self) -> int:
        """Mark interrupted writes/read-backs for review after run recovery."""
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT m.mutation_id,m.status,m.mutation_action_id,r.run_id "
                "FROM authorization_mutation_results m JOIN plan_runs r ON r.run_id=m.run_id "
                "WHERE r.status='WAITING_HUMAN' AND r.stop_reason='RECOVERY_REVIEW_REQUIRED' "
                "AND m.status IN ('PLANNED','DISPATCHED') LIMIT 100").fetchall()
            for row in rows:
                if row["status"] == MutationStatus.PLANNED.value:
                    step = db.execute(
                        "SELECT s.result_id FROM plan_run_steps s WHERE s.run_id=? "
                        "AND s.action_id=?", (row["run_id"], row["mutation_action_id"])).fetchone()
                    result = (db.execute("SELECT exchange_ids_json FROM plan_step_results "
                                         "WHERE result_id=?", (step["result_id"],)).fetchone()
                              if step is not None and step["result_id"] else None)
                    exchanges = json.loads(result[0]) if result else []
                    db.execute(
                        "UPDATE authorization_mutation_results SET status='AMBIGUOUS',"
                        "mutation_exchange_id=?,updated_at=? WHERE mutation_id=? AND status='PLANNED'",
                        (exchanges[-1] if exchanges else None, _now(), row["mutation_id"]))
                else:
                    db.execute(
                        "UPDATE authorization_mutation_results SET status='INSUFFICIENT_EVIDENCE',"
                        "updated_at=? WHERE mutation_id=? AND status='DISPATCHED'",
                        (_now(), row["mutation_id"]))
        return len(rows)

    def start(self, mutation: TypedMutation, *, run_id: str, phase: MutationPhase,
              action_id: str, before_value: str) -> MutationResult:
        if not isinstance(mutation, TypedMutation) or not isinstance(phase, MutationPhase):
            raise ValueError("invalid typed mutation")
        if not _ACTION.fullmatch(action_id) or not isinstance(before_value, str):
            raise ValueError("invalid mutation action or before state")
        mid, stamp = "MUT-" + uuid.uuid4().hex, _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute("SELECT target_id,package_id,status FROM plan_runs WHERE run_id=?",
                             (run_id,)).fetchone()
            obj = db.execute("SELECT target_id,package_id,object_type,creator_identity_id,"
                             "tenant_id,recipe_hash,lifecycle,disposable,verified_at FROM test_objects "
                             "WHERE test_object_id=?", (mutation.test_object_id,)).fetchone()
            lease = db.execute("SELECT holder_run_id FROM test_object_reservations WHERE "
                               "test_object_id=? AND status='ACTIVE' AND expires_at>?",
                               (mutation.test_object_id, stamp)).fetchone()
            if (run is None or obj is None or lease is None or lease[0] != run_id or
                    run["target_id"] != mutation.target_id or
                    obj["target_id"] != mutation.target_id or
                    obj["package_id"] != run["package_id"] or
                    obj["object_type"] != mutation.object_type or
                    obj["creator_identity_id"] != mutation.creator_identity_id or
                    obj["tenant_id"] != mutation.tenant_id or
                    obj["recipe_hash"] != mutation.recipe_hash or
                    obj["lifecycle"] != "IN_USE" or not obj["disposable"] or
                    obj["verified_at"] is None):
                raise ValueError("mutation requires a reserved verified disposable object")
            db.execute("INSERT INTO authorization_mutation_results "
                       "(mutation_id,target_id,run_id,test_object_id,mutation_type,phase,"
                       "actor_identity_id,field,recipe_hash,expected_value_hash,before_value_hash,"
                       "mutation_action_id,status,evidence_ids_json,created_at,updated_at) "
                       "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (mid, mutation.target_id, run_id, mutation.test_object_id,
                        mutation.mutation_type.value, phase.value, mutation.actor_identity_id,
                        mutation.field, mutation.recipe_hash, value_hash(mutation.expected_readback),
                        value_hash(before_value), action_id, MutationStatus.PLANNED.value,
                        json.dumps(mutation.evidence_ids), stamp, stamp))
            row = db.execute("SELECT * FROM authorization_mutation_results WHERE mutation_id=?",
                             (mid,)).fetchone()
        return self._row(row)

    def dispatched(self, mutation_id: str, target_id: str, exchange_id: str | None,
                   *, ambiguous: bool = False) -> MutationResult:
        current = self.get(mutation_id, target_id)
        if current is None or current.status is not MutationStatus.PLANNED:
            raise ValueError("mutation dispatch is not pending")
        status = MutationStatus.AMBIGUOUS if ambiguous else MutationStatus.DISPATCHED
        with self.store._connection() as db:
            if exchange_id is not None:
                exchange = db.execute("SELECT target_id FROM traffic_exchanges WHERE exchange_id=?",
                                      (exchange_id,)).fetchone()
                if exchange is None or exchange[0] != target_id:
                    raise ValueError("mutation exchange target mismatch")
            changed = db.execute("UPDATE authorization_mutation_results SET mutation_exchange_id=?,"
                                 "status=?,updated_at=? WHERE mutation_id=? AND status='PLANNED'",
                                 (exchange_id, status.value, _now(), mutation_id)).rowcount
            if changed != 1:
                raise ValueError("mutation dispatch state changed")
        result = self.get(mutation_id, target_id)
        assert result is not None
        return result

    def readback(self, mutation_id: str, target_id: str, *, action_id: str,
                 exchange_id: str, observed_value: str | None,
                 evidence_ids: tuple[str, ...] = ()) -> MutationResult:
        current = self.get(mutation_id, target_id)
        if (current is None or current.status not in {MutationStatus.DISPATCHED,
                                                      MutationStatus.AMBIGUOUS} or
                not _ACTION.fullmatch(action_id) or len(evidence_ids) > 16):
            raise ValueError("mutation read-back is not pending")
        with self.store._connection() as db:
            exchange = db.execute("SELECT target_id FROM traffic_exchanges WHERE exchange_id=?",
                                  (exchange_id,)).fetchone()
            if exchange is None or exchange[0] != target_id:
                raise ValueError("read-back exchange target mismatch")
            for ref in evidence_ids:
                evidence = db.execute("SELECT target_ref FROM evidence WHERE evidence_id=?",
                                      (ref,)).fetchone()
                if evidence is None or evidence[0] != target_id:
                    raise ValueError("read-back evidence target mismatch")
            after_hash = value_hash(observed_value) if observed_value is not None else None
            if after_hash is None:
                status = MutationStatus.INSUFFICIENT_EVIDENCE
            elif after_hash == current.expected_value_hash and after_hash != current.before_value_hash:
                status = MutationStatus.VERIFIED
            elif after_hash == current.before_value_hash:
                status = MutationStatus.DENIED
            else:
                status = MutationStatus.INSUFFICIENT_EVIDENCE
            changed = db.execute("UPDATE authorization_mutation_results SET readback_action_id=?,"
                                 "readback_exchange_id=?,after_value_hash=?,status=?,evidence_ids_json=?,"
                                 "updated_at=? WHERE mutation_id=? AND status IN ('DISPATCHED','AMBIGUOUS')",
                                 (action_id, exchange_id, after_hash, status.value,
                                  json.dumps(tuple(dict.fromkeys((*current.evidence_ids, *evidence_ids)))),
                                  _now(), mutation_id)).rowcount
            if changed != 1:
                raise ValueError("mutation read-back state changed")
        result = self.get(mutation_id, target_id)
        assert result is not None
        return result
