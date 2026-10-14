"""BugHunter-owned, bounded API operation and hypothesis metadata."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
import base64
import binascii
import hashlib
import json
import re
import sqlite3
import uuid

from .api_graphql import GraphQLField
from .store import EvidenceFactStore


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_LABEL = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}\Z")
_CATEGORIES = frozenset({"OBJECT_AUTH", "FIELD_AUTH", "NESTED_AUTH", "MUTATION_AUTH",
                         "BFLA", "BATCH_AUTH", "MASS_ASSIGNMENT_CANDIDATE"})


@dataclass(frozen=True, slots=True)
class APIInventoryProgress:
    traffic_cursor: str | None = None
    js_cursor: str | None = None
    operation_cursor: str | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(*values: str) -> str:
    return hashlib.sha256("\x00".join(values).encode()).hexdigest()


def _cursor(parts: list[object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(parts, separators=(",", ":")).encode()).decode().rstrip("=")


def _cursor_parts(value: str | None, kind: str, target_id: str,
                  state: str | None, size: int) -> list[object] | None:
    if value is None:
        return None
    if len(value) > 512 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Invalid API page cursor")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        parts = json.loads(raw)
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise ValueError("Invalid API page cursor") from exc
    if (not isinstance(parts, list) or len(parts) != size or
            parts[:3] != [kind, target_id, state] or
            any(not isinstance(part, str) or len(part) > 128 for part in parts[3:])):
        raise ValueError("Invalid API page cursor")
    return parts


class APIOperationType(StrEnum):
    REST = "REST"
    GRAPHQL_QUERY = "GRAPHQL_QUERY"
    GRAPHQL_MUTATION = "GRAPHQL_MUTATION"
    GRAPHQL_SUBSCRIPTION = "GRAPHQL_SUBSCRIPTION"
    RPC = "RPC"
    BULK_API = "BULK_API"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class APIOperation:
    id: str
    target_id: str
    package_id: str
    operation_key: str
    version_hash: str
    name: str
    type: APIOperationType
    endpoint: str
    method: str
    document_evidence_id: str | None = None
    persisted_hash: str | None = None
    variables: tuple[str, ...] = ()
    input_types: tuple[str, ...] = ()
    fields: tuple[GraphQLField, ...] = ()
    feature: str = "other"
    identity_ids: tuple[str, ...] = ()
    role_ids: tuple[str, ...] = ()
    tenant_ids: tuple[str, ...] = ()
    exchange_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    source_refs: tuple[str, ...] = ()
    source_asset_hash: str | None = None
    state: str = "CURRENT"
    first_seen: str = ""
    last_seen: str = ""
    global_id_type: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "type": self.type.value,
                "returned_object_types": sorted({field.nested_type for field in self.fields
                                                 if field.nested_type != "UNKNOWN"})}


@dataclass(frozen=True, slots=True)
class APICandidate:
    id: str
    target_id: str
    operation_id: str
    category: str
    boundary_identity_id: str | None
    owner_identity_id: str | None
    test_object_id: str | None
    owner_exchange_id: str | None
    field_path: str | None
    score: int
    reasons: tuple[str, ...]
    gaps: tuple[str, ...]
    status: str = "CANDIDATE"
    hypothesis_id: str | None = None
    plan_id: str | None = None
    run_id: str | None = None
    validation_id: str | None = None
    authorization_candidate_id: str | None = None
    behaviour_run_id: str | None = None
    created_at: str = ""
    updated_at: str = ""
    child_object_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class APIOperationRegistry:
    def __init__(self, store: EvidenceFactStore) -> None:
        self.store = store

    def progress(self, target_id: str, package_id: str) -> APIInventoryProgress:
        with self.store._connection() as db:
            row = db.execute("SELECT package_id,traffic_cursor,js_cursor,operation_cursor "
                             "FROM api_inventory_progress WHERE target_id=?",
                             (target_id,)).fetchone()
        if row is None or row["package_id"] != package_id:
            return APIInventoryProgress()
        return APIInventoryProgress(row["traffic_cursor"], row["js_cursor"],
                                    row["operation_cursor"])

    def save_progress(self, target_id: str, package_id: str,
                      progress: APIInventoryProgress) -> None:
        if not isinstance(progress, APIInventoryProgress) or any(
                cursor is not None and (not isinstance(cursor, str) or
                                        len(cursor) > 512 or
                                        not re.fullmatch(r"[A-Za-z0-9_-]+", cursor))
                for cursor in (progress.traffic_cursor, progress.js_cursor,
                               progress.operation_cursor)):
            raise ValueError("Invalid API inventory progress")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            target = db.execute("SELECT package_id FROM registry_targets WHERE target_id=?",
                                (target_id,)).fetchone()
            if target is None or target[0] != package_id:
                raise ValueError("API inventory target mismatch")
            db.execute("""INSERT INTO api_inventory_progress VALUES (?,?,?,?,?,?)
                ON CONFLICT(target_id) DO UPDATE SET
                  package_id=excluded.package_id,
                  traffic_cursor=excluded.traffic_cursor,
                  js_cursor=excluded.js_cursor,
                  operation_cursor=excluded.operation_cursor,
                  updated_at=excluded.updated_at""",
                (target_id, package_id, progress.traffic_cursor, progress.js_cursor,
                 progress.operation_cursor, _now()))

    def expire_missing_js_operations(self, target_id: str) -> int:
        """Retire JS-only hints whose exact saved body is no longer current."""
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("""
                UPDATE api_operations SET state='STALE'
                WHERE target_id=? AND state='CURRENT' AND source_asset_hash IS NOT NULL
                  AND exchange_ids_json='[]'
                  AND NOT EXISTS (
                    SELECT 1 FROM dom_js_artifacts AS asset
                    WHERE asset.target_id=api_operations.target_id
                      AND asset.artifact_sha256=api_operations.source_asset_hash
                      AND asset.state='CURRENT'
                  )
            """, (target_id,)).rowcount
            if changed:
                db.execute("""
                    UPDATE api_candidates SET status='STALE',updated_at=?
                    WHERE target_id=? AND status IN
                      ('CANDIDATE','PLAN_ONLY','READY','PLANNED','REVIEW','BLOCKED')
                      AND operation_id IN (
                        SELECT operation_id FROM api_operations
                        WHERE target_id=? AND state='STALE'
                          AND source_asset_hash IS NOT NULL AND exchange_ids_json='[]'
                      )
                """, (_now(), target_id, target_id))
        return changed

    @staticmethod
    def _operation(row: sqlite3.Row) -> APIOperation:
        fields = tuple(GraphQLField(**{**item,
            "observed_identity_ids": tuple(item.get("observed_identity_ids", ())),
            "observed_role_ids": tuple(item.get("observed_role_ids", ())),
            "evidence_ids": tuple(item.get("evidence_ids", ()))})
            for item in json.loads(row["fields_json"]))
        return APIOperation(row["operation_id"], row["target_id"], row["package_id"],
            row["operation_key"], row["version_hash"], row["name"],
            APIOperationType(row["operation_type"]), row["endpoint"], row["method"],
            row["document_evidence_id"], row["persisted_hash"],
            tuple(json.loads(row["variables_json"])), tuple(json.loads(row["input_types_json"])),
            fields, row["feature"],
            tuple(json.loads(row["identity_ids_json"])), tuple(json.loads(row["role_ids_json"])),
            tuple(json.loads(row["tenant_ids_json"])), tuple(json.loads(row["exchange_ids_json"])),
            tuple(json.loads(row["evidence_ids_json"])), tuple(json.loads(row["source_refs_json"])),
            row["source_asset_hash"], row["state"], row["first_seen"], row["last_seen"],
            row["global_id_type"])

    @staticmethod
    def _candidate(row: sqlite3.Row) -> APICandidate:
        return APICandidate(row["candidate_id"], row["target_id"], row["operation_id"],
            row["category"], row["boundary_identity_id"], row["owner_identity_id"],
            row["test_object_id"], row["owner_exchange_id"], row["field_path"], row["score"],
            tuple(json.loads(row["reasons_json"])), tuple(json.loads(row["gaps_json"])),
            row["status"], row["hypothesis_id"], row["plan_id"], row["run_id"],
            row["validation_id"], row["authorization_candidate_id"],
            row["behaviour_run_id"],
            row["created_at"], row["updated_at"], row["child_object_id"])

    def upsert_operation(self, *, target_id: str, package_id: str, name: str,
                         kind: APIOperationType, endpoint: str, method: str,
                         version_hash: str, document_evidence_id: str | None = None,
                         persisted_hash: str | None = None, variables: tuple[str, ...] = (),
                         input_types: tuple[str, ...] = (), fields: tuple[GraphQLField, ...] = (),
                         feature: str = "other", identity_ids: tuple[str, ...] = (),
                         role_ids: tuple[str, ...] = (), tenant_ids: tuple[str, ...] = (),
                         exchange_ids: tuple[str, ...] = (), evidence_ids: tuple[str, ...] = (),
                         source_refs: tuple[str, ...] = (), source_asset_hash: str | None = None,
                         global_id_type: str | None = None,
                         observed_at: str | None = None) -> APIOperation:
        if (not isinstance(kind, APIOperationType) or not _HASH.fullmatch(version_hash)
                or source_asset_hash is not None and not _HASH.fullmatch(source_asset_hash)
                or persisted_hash is not None and not _HASH.fullmatch(persisted_hash)
                or not _LABEL.fullmatch(name) or not _LABEL.fullmatch(feature)
                or method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "UNKNOWN"}
                or len(endpoint) > 1024 or "?" in endpoint or "#" in endpoint
                or len(fields) > 80 or len(variables) > 40
                or global_id_type is not None and not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]{0,63}", global_id_type)
                or any(len(values) > limit for values, limit in
                       ((identity_ids, 16), (role_ids, 16), (tenant_ids, 16),
                        (exchange_ids, 16), (evidence_ids, 32), (source_refs, 16)))):
            raise ValueError("Invalid bounded API operation")
        at = observed_at or _now()
        key = _hash(target_id, endpoint, method, name, kind.value)
        operation_id = "APIO-" + _hash(key, version_hash)[:32]
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            target = db.execute("SELECT package_id FROM registry_targets WHERE target_id=?",
                                (target_id,)).fetchone()
            if target is None or target[0] != package_id:
                raise ValueError("API operation target mismatch")
            existing = db.execute("SELECT * FROM api_operations WHERE operation_id=? AND target_id=?",
                                  (operation_id, target_id)).fetchone()
            if existing is not None:
                prior_exchanges = tuple(json.loads(existing["exchange_ids_json"]))
                def merge(column: str, incoming: tuple[str, ...], maximum: int) -> tuple[str, ...]:
                    return tuple(dict.fromkeys((*json.loads(existing[column]), *incoming)))[:maximum]
                identity_ids = merge("identity_ids_json", identity_ids, 16)
                role_ids = merge("role_ids_json", role_ids, 16)
                tenant_ids = merge("tenant_ids_json", tenant_ids, 16)
                exchange_ids = (tuple(dict.fromkeys((*exchange_ids, *prior_exchanges)))[:16]
                                if at > existing["last_seen"] else
                                tuple(dict.fromkeys((*prior_exchanges, *exchange_ids)))[:16])
                evidence_ids = merge("evidence_ids_json", evidence_ids, 32)
                source_refs = merge("source_refs_json", source_refs, 16)
                previous = {field.path: field for field in
                            (GraphQLField(**item) for item in json.loads(existing["fields_json"]))}
                for field in fields:
                    old = previous.get(field.path)
                    if old is None:
                        previous[field.path] = field
                        continue
                    def union(a: tuple[str, ...], b: tuple[str, ...], cap: int) -> tuple[str, ...]:
                        return tuple(dict.fromkeys((*a, *b)))[:cap]
                    previous[field.path] = GraphQLField(
                        field.path, field.name, field.alias, field.parent, field.sensitivity,
                        field.parent_type if field.parent_type != "UNKNOWN" else old.parent_type,
                        field.nested_type if field.nested_type != "UNKNOWN" else old.nested_type,
                        union(tuple(old.observed_identity_ids), tuple(field.observed_identity_ids), 16),
                        union(tuple(old.observed_role_ids), tuple(field.observed_role_ids), 16),
                        union(tuple(old.evidence_ids), tuple(field.evidence_ids), 16))
                fields = tuple(previous.values())[:80]
            incoming_state = "CURRENT"
            if existing is not None and existing["state"] == "STALE":
                newly_observed = (at > existing["last_seen"] and
                                  any(ref not in prior_exchanges for ref in exchange_ids))
                current_asset = (db.execute("SELECT 1 FROM dom_js_artifacts WHERE target_id=? "
                                            "AND artifact_sha256=? AND state='CURRENT' LIMIT 1",
                                            (target_id, source_asset_hash)).fetchone()
                                 if source_asset_hash else None)
                incoming_state = "CURRENT" if current_asset or newly_observed else "STALE"
            db.execute("""INSERT INTO api_operations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(target_id,operation_key,version_hash) DO UPDATE SET
                  state=excluded.state,
                  last_seen=CASE WHEN excluded.last_seen>api_operations.last_seen
                    THEN excluded.last_seen ELSE api_operations.last_seen END,
                  identity_ids_json=excluded.identity_ids_json,role_ids_json=excluded.role_ids_json,
                  tenant_ids_json=excluded.tenant_ids_json,exchange_ids_json=excluded.exchange_ids_json,
                  evidence_ids_json=excluded.evidence_ids_json,source_refs_json=excluded.source_refs_json,
                  fields_json=excluded.fields_json,
                  global_id_type=CASE
                    WHEN api_operations.global_id_type='CONFLICT' THEN 'CONFLICT'
                    WHEN excluded.global_id_type IS NULL THEN api_operations.global_id_type
                    WHEN api_operations.global_id_type IS NULL THEN excluded.global_id_type
                    WHEN api_operations.global_id_type=excluded.global_id_type THEN api_operations.global_id_type
                    ELSE 'CONFLICT' END,
                  source_asset_hash=COALESCE(excluded.source_asset_hash,api_operations.source_asset_hash),
                  document_evidence_id=COALESCE(excluded.document_evidence_id,api_operations.document_evidence_id)""",
                       (operation_id, target_id, package_id, key, version_hash, name, kind.value,
                        endpoint, method, document_evidence_id, persisted_hash,
                        json.dumps(variables), json.dumps(input_types),
                        json.dumps([item.to_dict() for item in fields]), feature,
                        json.dumps(identity_ids), json.dumps(role_ids), json.dumps(tenant_ids),
                        json.dumps(exchange_ids), json.dumps(evidence_ids), json.dumps(source_refs),
                        source_asset_hash, incoming_state, at, at, global_id_type))
        result = self.get_operation(target_id, operation_id)
        assert result is not None
        return result

    def get_operation(self, target_id: str, operation_id: str) -> APIOperation | None:
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM api_operations WHERE target_id=? AND operation_id=?",
                             (target_id, operation_id)).fetchone()
        return self._operation(row) if row else None

    def current_js_successors(self, target_id: str, operation_id: str,
                              *, limit: int = 3) -> tuple[APIOperation, ...]:
        """Find exact same-surface replacements, never parallel observed documents."""
        if type(limit) is not int or not 1 <= limit <= 5:
            raise ValueError("Invalid API successor limit")
        old = self.get_operation(target_id, operation_id)
        if (old is None or old.state != "STALE" or old.exchange_ids or
                not old.source_asset_hash):
            return ()
        refs = [ref[3:] for ref in old.source_refs if ref.startswith("JS:DOMART-")]
        if len(refs) != 1:
            return ()
        with self.store._connection() as db:
            prior = db.execute("SELECT recon_asset_id,asset_url_sha256,artifact_sha256 "
                               "FROM dom_js_artifacts WHERE target_id=? AND artifact_id=?",
                               (target_id, refs[0])).fetchone()
            if (prior is None or prior["artifact_sha256"] != old.source_asset_hash or
                    prior["recon_asset_id"] is None):
                return ()
            rows = db.execute("SELECT op.*,asset.artifact_id AS successor_asset_id FROM "
                "api_operations op JOIN dom_js_artifacts asset ON "
                "asset.target_id=op.target_id AND asset.artifact_sha256=op.source_asset_hash "
                "WHERE op.target_id=? AND op.package_id=? AND op.operation_key=? "
                "AND op.operation_id!=? AND op.state='CURRENT' AND op.exchange_ids_json='[]' "
                "AND asset.state='CURRENT' AND asset.recon_sha256=asset.artifact_sha256 "
                "AND asset.recon_asset_id=? AND asset.asset_url_sha256=? "
                "ORDER BY op.last_seen DESC,op.operation_id DESC LIMIT ?",
                (target_id, old.package_id, old.operation_key, operation_id,
                 prior["recon_asset_id"], prior["asset_url_sha256"], limit)).fetchall()
        return tuple(self._operation(row) for row in rows
                     if "JS:" + row["successor_asset_id"] in
                     json.loads(row["source_refs_json"]))

    def current_js_replacement_available(self, target_id: str, operation_id: str) -> bool:
        """Whether an exact recon JS replacement can justify one retry."""
        old = self.get_operation(target_id, operation_id)
        if old is None or old.exchange_ids or not old.source_asset_hash:
            return False
        refs = [ref[3:] for ref in old.source_refs if ref.startswith("JS:DOMART-")]
        if len(refs) != 1:
            return False
        with self.store._connection() as db:
            prior = db.execute("SELECT recon_asset_id,asset_url_sha256,artifact_sha256 "
                               "FROM dom_js_artifacts WHERE target_id=? AND artifact_id=?",
                               (target_id, refs[0])).fetchone()
            if (prior is None or prior["recon_asset_id"] is None or
                    prior["artifact_sha256"] != old.source_asset_hash):
                return False
            replacement = db.execute("SELECT 1 FROM dom_js_artifacts WHERE target_id=? "
                "AND recon_asset_id=? AND asset_url_sha256=? AND artifact_sha256!=? "
                "AND state='CURRENT' AND recon_sha256=artifact_sha256 LIMIT 1",
                (target_id, prior["recon_asset_id"], prior["asset_url_sha256"],
                 prior["artifact_sha256"])).fetchone()
        return replacement is not None

    def find_current_operation(self, target_id: str, *, endpoint: str, method: str,
                               name: str, kind: APIOperationType,
                               version_hash: str) -> APIOperation | None:
        if not _HASH.fullmatch(version_hash) or not isinstance(kind, APIOperationType):
            raise ValueError("Invalid observed API operation selector")
        key = _hash(target_id, endpoint, method, name, kind.value)
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM api_operations WHERE target_id=? "
                             "AND operation_key=? AND version_hash=? AND state='CURRENT'",
                             (target_id, key, version_hash)).fetchone()
        return self._operation(row) if row else None

    def list_operations(self, target_id: str, *, limit: int = 50,
                        state: str | None = "CURRENT") -> tuple[APIOperation, ...]:
        if type(limit) is not int or not 1 <= limit <= 100 or state not in {None, "CURRENT", "STALE"}:
            raise ValueError("Invalid API inventory page")
        with self.store._connection() as db:
            rows = db.execute("SELECT * FROM api_operations WHERE target_id=? " +
                              ("AND state=? " if state else "") +
                              "ORDER BY last_seen DESC,operation_id DESC LIMIT ?",
                              (target_id, state, limit) if state else (target_id, limit)).fetchall()
        return tuple(self._operation(row) for row in rows)

    def page_operations(self, target_id: str, *, limit: int = 20,
                        state: str = "CURRENT", cursor: str | None = None
                        ) -> tuple[tuple[APIOperation, ...], str | None]:
        if type(limit) is not int or not 1 <= limit <= 100 or state not in {"CURRENT", "STALE"}:
            raise ValueError("Invalid API inventory page")
        marker = _cursor_parts(cursor, "operations", target_id, state, 5)
        condition = (" AND (last_seen<? OR (last_seen=? AND operation_id<?))"
                     if marker else "")
        params = ((target_id, state, marker[3], marker[3], marker[4], limit + 1)
                  if marker else (target_id, state, limit + 1))
        with self.store._connection() as db:
            rows = db.execute("SELECT * FROM api_operations WHERE target_id=? AND state=?" +
                              condition + " ORDER BY last_seen DESC,operation_id DESC LIMIT ?",
                              params).fetchall()
        items = tuple(self._operation(row) for row in rows[:limit])
        next_cursor = (_cursor(["operations", target_id, state, items[-1].last_seen,
                                items[-1].id]) if len(rows) > limit and items else None)
        return items, next_cursor

    @staticmethod
    def cursor_after_operation(operation: APIOperation) -> str:
        if operation.state != "CURRENT":
            raise ValueError("Only current operations can advance inventory")
        return _cursor(["operations", operation.target_id, "CURRENT",
                        operation.last_seen, operation.id])

    def upsert_candidate(self, candidate: APICandidate) -> APICandidate:
        if (candidate.category not in _CATEGORIES or not 0 <= candidate.score <= 100
                or candidate.status not in {"CANDIDATE", "PLAN_ONLY", "READY", "REVIEW"}
                or len(candidate.reasons) > 12 or len(candidate.gaps) > 12
                or candidate.field_path and len(candidate.field_path) > 256
                or candidate.child_object_id and (candidate.category != "NESTED_AUTH" or
                                                  not candidate.field_path)):
            raise ValueError("Invalid API candidate")
        at = _now()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            operation = db.execute("SELECT state FROM api_operations WHERE target_id=? AND operation_id=?",
                                   (candidate.target_id, candidate.operation_id)).fetchone()
            if operation is None or operation[0] != "CURRENT":
                raise ValueError("API candidate operation is stale")
            if candidate.child_object_id:
                child = db.execute("SELECT target_id,parent_test_object_id,disposable,verified_at "
                                   "FROM test_objects "
                                   "WHERE test_object_id=?", (candidate.child_object_id,)).fetchone()
                if (child is None or child["target_id"] != candidate.target_id or
                        child["parent_test_object_id"] != candidate.test_object_id or
                        not child["disposable"] or not child["verified_at"]):
                    raise ValueError("API nested child is not a verified disposable relation")
            if candidate.behaviour_run_id:
                learned = db.execute("SELECT target_id,status FROM behaviour_runs WHERE run_id=?",
                                     (candidate.behaviour_run_id,)).fetchone()
                if (learned is None or learned["target_id"] != candidate.target_id or
                        learned["status"] not in {"COMPLETED", "PARTIAL"}):
                    raise ValueError("API behaviour provenance is invalid")
            db.execute("""INSERT OR IGNORE INTO api_candidates
                (candidate_id,target_id,operation_id,category,boundary_identity_id,owner_identity_id,
                 test_object_id,owner_exchange_id,field_path,score,reasons_json,gaps_json,status,
                 behaviour_run_id,created_at,updated_at,child_object_id)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (candidate.id, candidate.target_id, candidate.operation_id, candidate.category,
                        candidate.boundary_identity_id, candidate.owner_identity_id,
                        candidate.test_object_id, candidate.owner_exchange_id, candidate.field_path,
                        candidate.score, json.dumps(candidate.reasons), json.dumps(candidate.gaps),
                        candidate.status, candidate.behaviour_run_id, at, at,
                        candidate.child_object_id))
            db.execute("""UPDATE api_candidates SET score=?,reasons_json=?,gaps_json=?,status=?,
                behaviour_run_id=COALESCE(behaviour_run_id,?),child_object_id=?,updated_at=?
                WHERE candidate_id=? AND target_id=? AND status IN
                  ('CANDIDATE','PLAN_ONLY','READY','REVIEW','STALE')
                  AND plan_id IS NULL AND run_id IS NULL AND validation_id IS NULL""",
                       (candidate.score, json.dumps(candidate.reasons), json.dumps(candidate.gaps),
                        candidate.status, candidate.behaviour_run_id, candidate.child_object_id, at,
                        candidate.id, candidate.target_id))
            db.execute("""UPDATE api_candidates SET status='STALE',updated_at=?
                WHERE candidate_id=? AND target_id=? AND plan_id IS NOT NULL
                  AND status IN ('PLANNED','RUNNING','BLOCKED','REVIEW')
                  AND child_object_id IS NOT ?""",
                       (at, candidate.id, candidate.target_id, candidate.child_object_id))
            row = db.execute("SELECT * FROM api_candidates WHERE candidate_id=? AND target_id=?",
                             (candidate.id, candidate.target_id)).fetchone()
        assert row is not None
        return self._candidate(row)

    def get_candidate(self, target_id: str, candidate_id: str) -> APICandidate | None:
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM api_candidates WHERE target_id=? AND candidate_id=?",
                             (target_id, candidate_id)).fetchone()
        return self._candidate(row) if row else None

    def list_candidates(self, target_id: str, *, limit: int = 50) -> tuple[APICandidate, ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid API candidate page")
        with self.store._connection() as db:
            rows = db.execute("SELECT * FROM api_candidates WHERE target_id=? "
                              "ORDER BY score DESC,created_at DESC,candidate_id LIMIT ?",
                              (target_id, limit)).fetchall()
        return tuple(self._candidate(row) for row in rows)

    def page_candidates(self, target_id: str, *, limit: int = 20,
                        cursor: str | None = None, operation_id: str | None = None
                        ) -> tuple[tuple[APICandidate, ...], str | None]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid API candidate page")
        marker = _cursor_parts(cursor, "candidates", target_id, operation_id, 6)
        if marker and (not marker[3].isdigit() or not 0 <= int(marker[3]) <= 100):
            raise ValueError("Invalid API page cursor")
        condition = (" AND (score<? OR (score=? AND created_at<?) OR "
                     "(score=? AND created_at=? AND candidate_id>?))" if marker else "")
        params = ((target_id, *((operation_id,) if operation_id else ()),
                   int(marker[3]), int(marker[3]), marker[4],
                   int(marker[3]), marker[4], marker[5], limit + 1)
                  if marker else (target_id, *((operation_id,) if operation_id else ()), limit + 1))
        with self.store._connection() as db:
            rows = db.execute("SELECT * FROM api_candidates WHERE target_id=?" +
                              (" AND operation_id=?" if operation_id else "") + condition +
                              " ORDER BY score DESC,created_at DESC,candidate_id LIMIT ?",
                              params).fetchall()
        items = tuple(self._candidate(row) for row in rows[:limit])
        next_cursor = (_cursor(["candidates", target_id, operation_id, str(items[-1].score),
                                items[-1].created_at, items[-1].id])
                       if len(rows) > limit and items else None)
        return items, next_cursor

    def link_candidate(self, target_id: str, candidate_id: str, *,
                       status: str, hypothesis_id: str | None = None,
                       plan_id: str | None = None, run_id: str | None = None,
                       validation_id: str | None = None,
                       authorization_candidate_id: str | None = None) -> APICandidate:
        if status not in {"PLAN_ONLY", "READY", "PLANNED", "RUNNING", "VALIDATED", "REJECTED",
                          "REVIEW", "STALE", "BLOCKED"}:
            raise ValueError("Invalid API candidate state")
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM api_candidates WHERE target_id=? AND candidate_id=?",
                             (target_id, candidate_id)).fetchone()
            if row is None:
                raise LookupError("API candidate not found")
            if row["status"] == "STALE" and status != "STALE":
                raise ValueError("Stale API candidate cannot be revived")
            operation = db.execute("SELECT state FROM api_operations WHERE target_id=? AND operation_id=?",
                                   (target_id, row["operation_id"])).fetchone()
            if operation is None or operation[0] != "CURRENT" and status != "STALE":
                raise ValueError("API operation is stale")
            for column, value in (("hypothesis_id", hypothesis_id), ("plan_id", plan_id),
                                  ("run_id", run_id), ("validation_id", validation_id),
                                  ("authorization_candidate_id", authorization_candidate_id)):
                if row[column] and value and row[column] != value:
                    raise ValueError("API audit link cannot be replaced")
            db.execute("UPDATE api_candidates SET status=?,hypothesis_id=COALESCE(?,hypothesis_id),"
                       "plan_id=COALESCE(?,plan_id),run_id=COALESCE(?,run_id),"
                       "validation_id=COALESCE(?,validation_id),"
                       "authorization_candidate_id=COALESCE(?,authorization_candidate_id),updated_at=? "
                       "WHERE target_id=? AND candidate_id=?",
                       (status, hypothesis_id, plan_id, run_id, validation_id,
                        authorization_candidate_id,
                        _now(), target_id, candidate_id))
        result = self.get_candidate(target_id, candidate_id)
        assert result is not None
        return result

    def counts(self, target_id: str) -> dict[str, int]:
        with self.store._connection() as db:
            operations = db.execute("SELECT state,count(*) AS n FROM api_operations WHERE target_id=? "
                                    "GROUP BY state", (target_id,)).fetchall()
            observed = db.execute("SELECT count(*) FROM api_operations WHERE target_id=? "
                                  "AND state='CURRENT' AND exchange_ids_json<>'[]'",
                                  (target_id,)).fetchone()[0]
            candidates = db.execute("SELECT status,count(*) AS n FROM api_candidates WHERE target_id=? "
                                    "GROUP BY status", (target_id,)).fetchall()
            progress = db.execute("SELECT count(DISTINCT CASE WHEN run_id IS NOT NULL THEN operation_id END),"
                                  "count(DISTINCT CASE WHEN status='BLOCKED' THEN operation_id END),"
                                  "count(DISTINCT CASE WHEN validation_id IS NOT NULL THEN operation_id END) "
                                  "FROM api_candidates WHERE target_id=?", (target_id,)).fetchone()
        return {"operations_current": next((row["n"] for row in operations if row["state"] == "CURRENT"), 0),
                "operations_stale": next((row["n"] for row in operations if row["state"] == "STALE"), 0),
                "operations_discovered": sum(row["n"] for row in operations),
                "operations_observed": observed,
                "operations_tested": progress[0],
                "operations_blocked": progress[1],
                "operations_validated": progress[2],
                "candidates": sum(row["n"] for row in candidates),
                "candidates_ready": next((row["n"] for row in candidates if row["status"] == "READY"), 0),
                "candidates_stale": next((row["n"] for row in candidates if row["status"] == "STALE"), 0)}

    def metrics(self, target_id: str) -> dict[str, object]:
        with self.store._connection() as db:
            row = db.execute("""SELECT COUNT(DISTINCT plan_id) AS plans,
                COUNT(DISTINCT run_id) AS executions,
                SUM(CASE WHEN status='VALIDATED' THEN 1 ELSE 0 END) AS confirmed,
                SUM(CASE WHEN status='REJECTED' THEN 1 ELSE 0 END) AS rejected,
                SUM(CASE WHEN status='REVIEW' THEN 1 ELSE 0 END) AS manual_review,
                COUNT(DISTINCT CASE WHEN category='MUTATION_AUTH' THEN run_id END) AS mutations
                FROM api_candidates WHERE target_id=?""", (target_id,)).fetchone()
            requests = db.execute("""SELECT COALESCE(SUM(requests_consumed),0) AS n
                FROM plan_runs WHERE target_id=? AND run_id IN
                (SELECT run_id FROM api_candidates WHERE target_id=? AND run_id IS NOT NULL)""",
                (target_id, target_id)).fetchone()["n"]
            outcomes = db.execute("""SELECT category,status,COUNT(*) AS n FROM api_candidates
                WHERE target_id=? AND category IN ('FIELD_AUTH','NESTED_AUTH','BATCH_AUTH')
                GROUP BY category,status""", (target_id,)).fetchall()
        by_category: dict[str, dict[str, int]] = {
            category: {"confirmed": 0, "rejected": 0, "manual_review": 0}
            for category in ("FIELD_AUTH", "NESTED_AUTH", "BATCH_AUTH")}
        for item in outcomes:
            key = {"VALIDATED": "confirmed", "REJECTED": "rejected",
                   "REVIEW": "manual_review"}.get(item["status"])
            if key:
                by_category[item["category"]][key] = item["n"]
        return {"plans": row["plans"], "executions": row["executions"],
                "confirmed": row["confirmed"] or 0, "rejected": row["rejected"] or 0,
                "manual_review": row["manual_review"] or 0, "requests": requests,
                "mutations": row["mutations"], "category_outcomes": by_category}

    def operation_type_counts(self, target_id: str) -> dict[str, int]:
        with self.store._connection() as db:
            rows = db.execute("SELECT operation_type,count(*) AS n FROM api_operations "
                              "WHERE target_id=? AND state='CURRENT' GROUP BY operation_type",
                              (target_id,)).fetchall()
        return {row["operation_type"]: row["n"] for row in rows}

    def record_run(self, target_id: str, package_id: str, mode: str,
                   counts: dict[str, int], gaps: tuple[str, ...]) -> str:
        if mode not in {"PLAN_ONLY", "BOUNDED_AUTONOMOUS"}:
            raise ValueError("Invalid API run mode")
        run_id = "APIR-" + uuid.uuid4().hex
        at = _now()
        with self.store._connection() as db:
            db.execute("INSERT INTO api_specialist_runs VALUES (?,?,?,?,?,?,?,?,?)",
                       (run_id, target_id, package_id, mode, "COMPLETED", json.dumps(counts),
                        json.dumps(gaps), at, at))
        return run_id
