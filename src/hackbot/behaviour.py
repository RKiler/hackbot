"""Bounded, evidence-linked normal-behaviour learning. Never executes traffic."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import json
import re
import sqlite3
import time
import uuid
from typing import Any
from urllib.parse import urlsplit

from .browser import BrowserSessionManager, BrowserStatus, VerificationStatus
from .domain import validate_entity_id
from .identity import IdentityStatus
from .identity_registry import IdentityRegistry
from .logging import SecretRedactor
from .profile import TargetProfile, _FEATURES, _tokens
from .recon import ReconRepository
from .store import EvidenceFactStore
from .target_package import PackageStatus, TargetPackage
from .target_scope import ScopeResult
from .test_objects import ObjectRegistry, ObjectState
from .traffic import AuthState, ExchangeState, TrafficExchange, TrafficStore


_ADDITIONAL_FEATURES = {"settings": "settings", "setting": "settings",
                        "users": "users", "user": "users", "keys": "API keys",
                        "panel": "admin functions"}


class LearningStatus(StrEnum):
    CREATED = "CREATED"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING_LOGIN = "WAITING_LOGIN"
    PARTIAL = "PARTIAL"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class ObservationResult(StrEnum):
    OBSERVED_ALLOWED = "OBSERVED_ALLOWED"
    OBSERVED_DENIED = "OBSERVED_DENIED"
    UNKNOWN = "UNKNOWN"


class ExpectedAccessStatus(StrEnum):
    CONFIGURED_EXPECTATION = "CONFIGURED_EXPECTATION"
    OBSERVED_PATTERN = "OBSERVED_PATTERN"
    UNKNOWN = "UNKNOWN"


class MatrixState(StrEnum):
    OBSERVED = "OBSERVED"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class LearningLimits:
    max_identities: int = 4
    max_pages_per_identity: int = 3
    max_workflow_observations: int = 60
    max_duration_seconds: int = 90
    max_traffic_records: int = 160
    max_objects: int = 50
    freshness_days: int = 14

    def __post_init__(self) -> None:
        caps = (12, 12, 200, 600, 500, 100, 90)
        if any(type(value) is not int or not 1 <= value <= cap
               for value, cap in zip(asdict(self).values(), caps)):
            raise ValueError("Invalid bounded learning limits")


@dataclass(frozen=True, slots=True)
class BehaviourLearningRun:
    run_id: str
    target_id: str
    package_id: str
    status: LearningStatus
    limits: LearningLimits
    selected_identities: tuple[str, ...] = ()
    selected_sessions: tuple[str, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    coverage_before: dict[str, object] = field(default_factory=dict)
    coverage_after: dict[str, object] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    stop_reason: str | None = None
    cancel_requested: bool = False
    created_at: str = ""
    started_at: str | None = None
    finished_at: str | None = None

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["status"] = self.status.value
        return result


@dataclass(frozen=True, slots=True)
class BehaviourProfile:
    target_id: str
    package_id: str
    run_id: str
    generated_at: str
    features: tuple[dict[str, object], ...]
    workflows: tuple[dict[str, object], ...]
    operations: tuple[dict[str, object], ...]
    identities: tuple[dict[str, object], ...]
    tenants: tuple[str, ...]
    roles: tuple[str, ...]
    object_types: tuple[str, ...]
    known_objects: tuple[dict[str, object], ...]
    ownership: tuple[dict[str, object], ...]
    role_feature_matrix: tuple[dict[str, object], ...]
    role_operation_matrix: tuple[dict[str, object], ...]
    anonymous: tuple[dict[str, object], ...]
    expected_access: tuple[dict[str, object], ...]
    coverage: dict[str, object]
    gaps: tuple[dict[str, str], ...]
    provenance: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BehaviourProfile:
        return cls(**{key: tuple(value[key]) if key in {
            "features", "workflows", "operations", "identities", "tenants", "roles",
            "object_types", "known_objects", "ownership", "role_feature_matrix",
            "role_operation_matrix", "anonymous", "expected_access", "gaps"
        } else value[key] for key in cls.__dataclass_fields__})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _key(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()


def _safe_label(value: str) -> str:
    if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_ -]{0,63}", value)
            or SecretRedactor().text(value) != value):
        raise ValueError("Unsafe behaviour label")
    return value.strip().lower()


class BehaviourStore:
    def __init__(self, evidence: EvidenceFactStore) -> None:
        self.evidence = evidence

    def create_run(self, package: TargetPackage, limits: LearningLimits,
                   *, campaign_work_id: str | None = None) -> BehaviourLearningRun:
        run_id = "LEARN-" + uuid.uuid4().hex
        with self.evidence._connection() as db:
            try:
                db.execute("""INSERT INTO behaviour_runs
                    (run_id,target_id,package_id,status,limits_json,created_at)
                    VALUES (?,?,?,?,?,?)""", (run_id, package.target.id, package.id,
                    LearningStatus.CREATED.value, json.dumps(asdict(limits)), _now()))
                if campaign_work_id is not None:
                    from .campaign_models import CampaignWorkKind
                    from .campaign_store import link_created_child
                    link_created_child(db, campaign_work_id,
                                       kind=CampaignWorkKind.BEHAVIOUR,
                                       target_id=package.target.id, child_id=run_id)
            except sqlite3.IntegrityError as exc:
                raise ValueError("A learning run is already active for this target") from exc
        result = self.get_run(package.target.id, run_id)
        assert result is not None
        return result

    @staticmethod
    def _run(row: sqlite3.Row) -> BehaviourLearningRun:
        return BehaviourLearningRun(
            row["run_id"], row["target_id"], row["package_id"], LearningStatus(row["status"]),
            LearningLimits(**json.loads(row["limits_json"])),
            tuple(json.loads(row["selected_identities_json"])),
            tuple(json.loads(row["selected_sessions_json"])), json.loads(row["counts_json"]),
            json.loads(row["coverage_before_json"]), json.loads(row["coverage_after_json"]),
            tuple(json.loads(row["limitations_json"])), row["stop_reason"],
            bool(row["cancel_requested"]), row["created_at"], row["started_at"], row["finished_at"])

    def get_run(self, target_id: str, run_id: str) -> BehaviourLearningRun | None:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(run_id, "LEARN")
        with self.evidence._connection() as db:
            row = db.execute("SELECT * FROM behaviour_runs WHERE target_id=? AND run_id=?",
                             (target_id, run_id)).fetchone()
        return self._run(row) if row else None

    def list_runs(self, target_id: str, limit: int = 10) -> tuple[BehaviourLearningRun, ...]:
        validate_entity_id(target_id, "TARGET")
        if type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError("Invalid learning page size")
        with self.evidence._connection() as db:
            rows = db.execute("SELECT * FROM behaviour_runs WHERE target_id=? "
                              "ORDER BY created_at DESC,run_id DESC LIMIT ?", (target_id, limit)).fetchall()
        return tuple(self._run(row) for row in rows)

    def transition(self, target_id: str, run_id: str, status: LearningStatus, *,
                   identities: tuple[str, ...] = (), sessions: tuple[str, ...] = (),
                   counts: dict[str, int] | None = None,
                   before: dict[str, object] | None = None,
                   after: dict[str, object] | None = None,
                   limitations: tuple[str, ...] = (), reason: str | None = None) -> BehaviourLearningRun:
        current = self.get_run(target_id, run_id)
        if current is None:
            raise LookupError("Learning run not found")
        allowed = {
            LearningStatus.CREATED: {LearningStatus.READY, LearningStatus.BLOCKED,
                                     LearningStatus.CANCELLED, LearningStatus.FAILED},
            LearningStatus.READY: {LearningStatus.RUNNING, LearningStatus.CANCELLED,
                                   LearningStatus.FAILED},
            LearningStatus.RUNNING: {LearningStatus.COMPLETED, LearningStatus.PARTIAL,
                                     LearningStatus.WAITING_LOGIN, LearningStatus.BLOCKED,
                                     LearningStatus.CANCELLED, LearningStatus.FAILED},
        }
        if status not in allowed.get(current.status, set()):
            raise ValueError("Invalid learning state transition")
        finished = status not in {LearningStatus.READY, LearningStatus.RUNNING}
        with self.evidence._connection() as db:
            db.execute("""UPDATE behaviour_runs SET status=?,selected_identities_json=?,
                selected_sessions_json=?,counts_json=?,coverage_before_json=?,coverage_after_json=?,
                limitations_json=?,stop_reason=?,started_at=?,finished_at=? WHERE run_id=? AND target_id=?""",
                (status.value, json.dumps(identities or current.selected_identities),
                 json.dumps(sessions or current.selected_sessions), json.dumps(counts or current.counts),
                 json.dumps(before or current.coverage_before), json.dumps(after or current.coverage_after),
                 json.dumps(limitations or current.limitations), reason,
                 current.started_at or (_now() if status is LearningStatus.RUNNING else None),
                 _now() if finished else None, run_id, target_id))
        result = self.get_run(target_id, run_id)
        assert result is not None
        return result

    def request_cancel(self, target_id: str, run_id: str) -> bool:
        with self.evidence._connection() as db:
            row = db.execute("""UPDATE behaviour_runs SET cancel_requested=1
                WHERE target_id=? AND run_id=? AND status IN ('CREATED','READY','RUNNING')""",
                (target_id, run_id))
            return row.rowcount == 1

    def reconcile(self) -> int:
        with self.evidence._connection() as db:
            row = db.execute("""UPDATE behaviour_runs SET status='PARTIAL',
                stop_reason='PROCESS_INTERRUPTED',finished_at=? WHERE status IN ('CREATED','READY','RUNNING')""",
                (_now(),))
            return row.rowcount

    def add_observation(self, run_id: str, exchange: TrafficExchange, *, feature: str,
                        action: str, protocol: str, result: ObservationResult,
                        metadata: dict[str, object]) -> bool:
        if exchange.response is None:
            return False
        key = _key(protocol, exchange.request.structural_fingerprint,
                   str(exchange.request.record.operation_id or metadata.get("operation_name") or
                       metadata.get("rpc_method") or ""))
        with self.evidence._connection() as db:
            row = db.execute("""INSERT OR IGNORE INTO behaviour_observations
                (observation_id,target_id,run_id,exchange_id,identity_id,session_id,auth_state,
                 role_ids_json,tenant_ids_json,feature,action,protocol,operation_key,
                 operation_metadata_json,result,evidence_id,observed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                "BOBS-" + uuid.uuid4().hex, exchange.target_id, run_id, exchange.id,
                exchange.attribution.verified_identity_id, exchange.attribution.browser_session_id,
                exchange.attribution.auth_state.value,
                json.dumps(exchange.attribution.declared_role_ids),
                json.dumps(exchange.attribution.declared_tenant_ids), feature, action, protocol, key,
                json.dumps(metadata, sort_keys=True), result.value,
                exchange.response.observation_evidence_id, exchange.observed_at.isoformat()))
            return row.rowcount == 1

    def observations(self, target_id: str, *, limit: int = 500) -> tuple[dict[str, object], ...]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("Invalid observation limit")
        with self.evidence._connection() as db:
            rows = db.execute("""SELECT * FROM behaviour_observations WHERE target_id=?
                ORDER BY observed_at DESC,observation_id DESC LIMIT ?""", (target_id, limit)).fetchall()
        return tuple({"id": row["observation_id"], "exchange_id": row["exchange_id"],
                      "identity_id": row["identity_id"], "session_id": row["session_id"],
                      "auth_state": row["auth_state"], "role_ids": json.loads(row["role_ids_json"]),
                      "tenant_ids": json.loads(row["tenant_ids_json"]), "feature": row["feature"],
                      "action": row["action"], "protocol": row["protocol"],
                      "operation_key": row["operation_key"],
                      "metadata": json.loads(row["operation_metadata_json"]), "result": row["result"],
                      "evidence_id": row["evidence_id"], "observed_at": row["observed_at"]}
                     for row in rows)

    def upsert_workflow(self, target_id: str, row: dict[str, object]) -> None:
        with self.evidence._connection() as db:
            db.execute("""INSERT INTO behaviour_workflows
                (workflow_id,target_id,workflow_key,feature,action,identity_id,tenant_ids_json,
                 operation_keys_json,object_ids_json,exchange_ids_json,evidence_ids_json,result,last_observed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(target_id,workflow_key) DO UPDATE SET
                operation_keys_json=excluded.operation_keys_json,
                object_ids_json=excluded.object_ids_json,
                exchange_ids_json=excluded.exchange_ids_json,
                evidence_ids_json=excluded.evidence_ids_json,
                result=excluded.result,last_observed_at=excluded.last_observed_at""", (
                row["id"], target_id, row["key"], row["feature"], row["action"], row["identity_id"],
                json.dumps(row["tenant_ids"]), json.dumps(row["operation_keys"]),
                json.dumps(row["object_ids"]),
                json.dumps(row["exchange_ids"]), json.dumps(row["evidence_ids"]),
                row["result"], row["last_observed_at"]))

    def expectations(self, target_id: str) -> tuple[dict[str, object], ...]:
        with self.evidence._connection() as db:
            rows = db.execute("SELECT * FROM behaviour_expectations WHERE target_id=? "
                              "ORDER BY feature,role_id,action LIMIT 100", (target_id,)).fetchall()
        return tuple(dict(row) for row in rows)

    def set_expectation(self, target_id: str, *, role_id: str | None, feature: str,
                        action: str | None, expected_access: str, provenance: str) -> None:
        validate_entity_id(target_id, "TARGET")
        if role_id is not None:
            validate_entity_id(role_id, "ROLE")
        feature = _safe_label(feature)
        action = _safe_label(action) if action else None
        if expected_access not in {"ALLOW", "DENY", "UNKNOWN"}:
            raise ValueError("Invalid expected access")
        if provenance not in {"RESEARCHER", "PROGRAM_POLICY", "PRODUCT_DOCUMENTATION"}:
            raise ValueError("Invalid expectation provenance")
        with self.evidence._connection() as db:
            db.execute("""INSERT INTO behaviour_expectations
                (expectation_id,target_id,role_id,feature,action,expected_access,status,provenance,created_at)
                VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(target_id,role_id,feature,action)
                DO UPDATE SET expected_access=excluded.expected_access,
                provenance=excluded.provenance,created_at=excluded.created_at""", (
                "BEXP-" + uuid.uuid4().hex, target_id, role_id or "", feature, action or "",
                expected_access, ExpectedAccessStatus.CONFIGURED_EXPECTATION.value, provenance, _now()))

    def save_profile(self, profile: BehaviourProfile) -> None:
        with self.evidence._connection() as db:
            db.execute("""INSERT INTO behaviour_profiles(target_id,package_id,run_id,profile_json,updated_at)
                VALUES (?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET
                package_id=excluded.package_id,run_id=excluded.run_id,
                profile_json=excluded.profile_json,updated_at=excluded.updated_at""",
                (profile.target_id, profile.package_id, profile.run_id,
                 json.dumps(profile.to_dict(), sort_keys=True), _now()))

    def profile(self, target_id: str) -> BehaviourProfile | None:
        with self.evidence._connection() as db:
            row = db.execute("SELECT profile_json FROM behaviour_profiles WHERE target_id=?",
                             (target_id,)).fetchone()
        return BehaviourProfile.from_dict(json.loads(row["profile_json"])) if row else None


def _operation(exchange: TrafficExchange, evidence: EvidenceFactStore) -> tuple[str, str, str, dict[str, object]]:
    request = exchange.request
    path = request.display_path.lower()
    tokens = _tokens(path.replace("{", " ").replace("}", " "))
    try:
        captured = json.loads(evidence.read_content(request.observation_evidence_id,
                                                      allow_sensitive=True, max_bytes=16384))
        captured_url = captured.get("url") if isinstance(captured, dict) else None
        if isinstance(captured_url, str):
            tokens = _tokens(urlsplit(captured_url).path)
    except (ValueError, TypeError, KeyError, PermissionError, UnicodeError):
        pass
    feature = next((_FEATURES.get(item, _ADDITIONAL_FEATURES.get(item)) for item in tokens
                    if item in _FEATURES or item in _ADDITIONAL_FEATURES), "other")
    method = request.record.method.upper()
    protocol = ("GRAPHQL" if "graphql" in path or request.record.operation_id and
                request.record.operation_id.startswith("GQL-") else
                "RPC" if "rpc" in path or "trpc" in path else
                "BROWSER" if exchange.response and exchange.response.record.content_type == "text/html" else "REST")
    action = {"GET": "VIEW", "HEAD": "VIEW", "POST": "CREATE", "PUT": "UPDATE",
              "PATCH": "UPDATE", "DELETE": "DELETE"}.get(method, "UNKNOWN")
    if any(word in tokens for word in ("export", "download")):
        action = "EXPORT"
    elif "invite" in tokens or "invitations" in tokens:
        action = "INVITE" if method not in {"GET", "HEAD"} else "VIEW"
    elif "share" in tokens:
        action = "SHARE" if method not in {"GET", "HEAD"} else "VIEW"
    elif "approve" in tokens:
        action = "APPROVE" if method not in {"GET", "HEAD"} else "VIEW"
    elif "test" in tokens:
        action = "TEST" if method not in {"GET", "HEAD"} else "VIEW"
    graphql_metadata: dict[str, object] = {}
    if protocol == "GRAPHQL" and request.body_evidence_id:
        try:
            body = evidence.read_content(request.body_evidence_id, allow_sensitive=True, max_bytes=16384)
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                name = parsed.get("operationName")
                if isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
                    if SecretRedactor().text(name) == name:
                        graphql_metadata["operation_name"] = name
                        tokens = _tokens(name)
                        feature = next((_FEATURES.get(item, _ADDITIONAL_FEATURES.get(item)) for item in tokens
                                        if item in _FEATURES or item in _ADDITIONAL_FEATURES), feature)
                        action = ("VIEW" if name.lower().startswith(("get", "list", "query")) else
                                  "UPDATE" if name.lower().startswith(("set", "update", "change")) else
                                  "CREATE" if name.lower().startswith("create") else action)
                query = parsed.get("query")
                if isinstance(query, str):
                    query_type = re.match(r"\s*(query|mutation|subscription)\b", query)
                    if query_type:
                        graphql_metadata["operation_type"] = query_type.group(1).upper()
                    if query_type and query_type.group(1) == "query":
                        action = "VIEW"
                    elif query_type and query_type.group(1) == "mutation" and action == "VIEW":
                        action = "UNKNOWN"
                variables = parsed.get("variables")
                if isinstance(variables, dict):
                    graphql_metadata["variable_names"] = sorted(
                        key for key in variables if isinstance(key, str) and
                        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key))[:40]
        except (ValueError, TypeError, KeyError, PermissionError, UnicodeError):
            pass
    if protocol == "RPC" and request.body_evidence_id:
        try:
            body = evidence.read_content(request.body_evidence_id, allow_sensitive=True, max_bytes=8192)
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                rpc_method = parsed.get("method")
                if isinstance(rpc_method, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,63}", rpc_method):
                    if SecretRedactor().text(rpc_method) == rpc_method:
                        graphql_metadata["rpc_method"] = rpc_method
        except (ValueError, TypeError, KeyError, PermissionError, UnicodeError):
            pass
    metadata: dict[str, object] = {"method": method, "path_shape": request.display_path,
            "origin": request.origin, "operation_id": request.record.operation_id,
            "query_names": list(request.query_names[:30]),
            "correlation_hash": exchange.correlation_hash,
            "body_evidence_id": request.body_evidence_id,
            "response_evidence_id": exchange.response.observation_evidence_id if exchange.response else None,
            **graphql_metadata}
    if (exchange.response and exchange.response.body_evidence_id and
            exchange.response.record.content_type in {"application/json", "application/graphql-response+json"}):
        try:
            raw = evidence.read_content(exchange.response.body_evidence_id,
                                        allow_sensitive=True, max_bytes=16384)
            tree = json.loads(raw)
            pending = [tree]
            hints: list[dict[str, object]] = []
            examined = 0
            while pending and examined < 32 and len(hints) < 3:
                node = pending.pop()
                examined += 1
                if isinstance(node, list):
                    pending.extend(node[:8])
                    continue
                if not isinstance(node, dict):
                    continue
                value = next((node.get(key) for key in ("id", "uuid", "slug")
                              if isinstance(node.get(key), (str, int)) and not isinstance(node.get(key), bool)), None)
                if value is not None and len(str(value)) <= 256:
                    kind = node.get("__typename") or node.get("type") or feature
                    kind = kind if isinstance(kind, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", kind) else feature
                    hints.append({"id_hash": _key(str(value)), "type": kind,
                        "owner_hash": _key(str(node.get("ownerId", node.get("owner_id"))))
                            if node.get("ownerId", node.get("owner_id")) is not None else None,
                        "tenant_hash": _key(str(node.get("tenantId", node.get("tenant_id"))))
                            if node.get("tenantId", node.get("tenant_id")) is not None else None,
                        "parent_hash": _key(str(node.get("parentId", node.get("parent_id"))))
                            if node.get("parentId", node.get("parent_id")) is not None else None,
                        "evidence_id": exchange.response.body_evidence_id})
                pending.extend(value for value in list(node.values())[:12] if isinstance(value, (dict, list)))
            if hints:
                metadata["object_hints"] = hints
        except (ValueError, TypeError, KeyError, PermissionError, UnicodeError):
            pass
    return feature, action, protocol, metadata


def _result(exchange: TrafficExchange, evidence: EvidenceFactStore, protocol: str) -> ObservationResult:
    response = exchange.response
    if response is None or exchange.state is not ExchangeState.COMPLETE:
        return ObservationResult.UNKNOWN
    status = response.record.status_code
    if status in {401, 403}:
        return ObservationResult.OBSERVED_DENIED
    if status is None or not 200 <= status < 300 or not response.body_evidence_id:
        return ObservationResult.UNKNOWN
    if response.body_evidence_id and response.record.content_type in {
        "application/json", "application/graphql-response+json"}:
        try:
            body = evidence.read_content(response.body_evidence_id, allow_sensitive=True, max_bytes=32768)
            value = json.loads(body)
            if isinstance(value, dict):
                errors = value.get("errors")
                if isinstance(errors, list) and errors:
                    for error in errors[:5]:
                        if not isinstance(error, dict):
                            continue
                        extensions = error.get("extensions")
                        code = extensions.get("code") if isinstance(extensions, dict) else None
                        if code in {"FORBIDDEN", "UNAUTHORIZED", "PERMISSION_DENIED", "ACCESS_DENIED"}:
                            return ObservationResult.OBSERVED_DENIED
                    return ObservationResult.UNKNOWN
                if value.get("success") is False or value.get("error"):
                    return ObservationResult.UNKNOWN
                if protocol == "GRAPHQL" and value.get("data") is None:
                    return ObservationResult.UNKNOWN
                if (value.get("data") is not None or value.get("result") is not None or
                        value.get("success") is True or value.get("ok") is True or
                        isinstance(value.get("id"), (str, int))):
                    return ObservationResult.OBSERVED_ALLOWED
            elif isinstance(value, list) and value:
                return ObservationResult.OBSERVED_ALLOWED
        except (ValueError, TypeError, KeyError, PermissionError, UnicodeError):
            return ObservationResult.UNKNOWN
    return ObservationResult.UNKNOWN


class NormalBehaviourLearner:
    """Turns only in-scope, already-captured traffic and verified fixtures into context."""

    def __init__(self, ledger: BehaviourStore, traffic: TrafficStore,
                 identities: IdentityRegistry, browser: BrowserSessionManager,
                 objects: ObjectRegistry, evidence: EvidenceFactStore,
                 recon: ReconRepository | None = None) -> None:
        self.ledger = ledger
        self.traffic = traffic
        self.identities = identities
        self.browser = browser
        self.objects = objects
        self.evidence = evidence
        self.recon = recon

    def _representatives(self, target_id: str, limit: int) -> tuple[tuple[str, str], ...]:
        candidates: list[tuple[str, str, frozenset[str]]] = []
        cursor = None
        for _ in range(3):
            page = self.identities.list_identities(target_id, limit=20, cursor=cursor)
            for identity in page.items:
                if identity.status is not IdentityStatus.ACTIVE:
                    continue
                session = self.browser.get_active_session(target_id, identity.id)
                if session is None:
                    continue
                context = self.browser.session_context(session.id)
                if (context.authentication_status != "VALID" or
                    context.verification_status is not VerificationStatus.MATCH or
                    not context.declared_memberships_complete):
                    continue
                dimensions = frozenset((*context.declared_tenant_ids, *context.declared_role_ids))
                candidates.append((identity.id, session.id, dimensions))
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        selected: list[tuple[str, str]] = []
        covered: set[str] = set()
        while candidates and len(selected) < limit:
            candidates.sort(key=lambda item: (-len(item[2] - covered), item[0]))
            identity_id, session_id, dimensions = candidates.pop(0)
            selected.append((identity_id, session_id))
            covered.update(dimensions)
        return tuple(selected)

    def create(self, package: TargetPackage, limits: LearningLimits = LearningLimits(),
               *, campaign_work_id: str | None = None) -> BehaviourLearningRun:
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("Target is not active")
        self.identities.register_target(package)
        return self.ledger.create_run(package, limits,
                                      campaign_work_id=campaign_work_id)

    def run(self, package: TargetPackage, run_id: str, *,
            target_profile: TargetProfile | None = None) -> BehaviourLearningRun:
        current = self.ledger.get_run(package.target.id, run_id)
        if current is None or current.package_id != package.id:
            raise LookupError("Learning run not found")
        if current.status is not LearningStatus.CREATED:
            raise ValueError("Learning run is not startable")
        if current.cancel_requested:
            return self.ledger.transition(package.target.id, run_id, LearningStatus.CANCELLED,
                                          reason="OPERATOR_CANCELLED")
        self.ledger.transition(package.target.id, run_id, LearningStatus.READY)
        self.ledger.transition(package.target.id, run_id, LearningStatus.RUNNING)
        started = time.monotonic()
        limits = current.limits
        before_profile = self.ledger.profile(package.target.id)
        before = before_profile.coverage if before_profile else {"state": "NONE"}
        representatives = self._representatives(package.target.id, limits.max_identities)
        selected_ids = {item[0] for item in representatives}
        selected_sessions = {item[1] for item in representatives}
        counts = {"traffic_examined": 0, "observations_added": 0, "workflows_learned": 0,
                  "objects_learned": 0, "facts_created": 0, "browser_actions": 0}
        limitations: set[str] = set()
        if target_profile is None:
            limitations.add("NO_TARGET_PROFILE")
        profile_changes = tuple(item.observed_at for item in target_profile.signals
                                if item.observed_at and item.recent and item.code in {
                                    "JS_ASSET", "JS_REFERENCE", "ENDPOINT", "API_GRAPHQL", "API_REST"}) if target_profile else ()
        change_at = max(profile_changes) if profile_changes else None
        cursor = None
        seen_pages: dict[str, set[str]] = {}
        while counts["traffic_examined"] < limits.max_traffic_records:
            if time.monotonic() - started > limits.max_duration_seconds:
                limitations.add("DURATION_BUDGET")
                break
            if self.ledger.get_run(package.target.id, run_id).cancel_requested:
                return self.ledger.transition(package.target.id, run_id, LearningStatus.CANCELLED,
                    identities=tuple(selected_ids), sessions=tuple(selected_sessions),
                    counts=counts, before=before, limitations=tuple(sorted(limitations)),
                    reason="OPERATOR_CANCELLED")
            page = self.traffic.list_filtered(package.target.id, limit=min(50,
                limits.max_traffic_records - counts["traffic_examined"]), cursor=cursor,
                scope=ScopeResult.IN_SCOPE.value)
            if not page.items:
                break
            for exchange in page.items:
                counts["traffic_examined"] += 1
                if exchange.package_id != package.id or exchange.response is None:
                    continue
                attribution = exchange.attribution
                if attribution.auth_state is AuthState.UNVERIFIED_IDENTITY:
                    limitations.add("UNVERIFIED_TRAFFIC_EXCLUDED")
                    continue
                if attribution.auth_state is AuthState.VERIFIED:
                    identity_id = attribution.verified_identity_id
                    if identity_id is None or self.identities.get_identity(package.target.id, identity_id) is None:
                        continue
                    # Historical verified capture remains evidence, but it is not a current login.
                    if selected_ids and identity_id not in selected_ids:
                        continue
                    if attribution.browser_session_id:
                        session = self.browser.get(attribution.browser_session_id)
                        if session is None or session.identity_id != identity_id or session.target_id != package.target.id:
                            limitations.add("WRONG_IDENTITY_TRAFFIC_EXCLUDED")
                            continue
                feature, action, protocol, metadata = _operation(exchange, self.evidence)
                actor = attribution.verified_identity_id or "ANONYMOUS"
                if protocol == "BROWSER":
                    pages = seen_pages.setdefault(actor, set())
                    if exchange.request.display_path not in pages and len(pages) >= limits.max_pages_per_identity:
                        limitations.add("PAGE_BUDGET")
                        continue
                    pages.add(exchange.request.display_path)
                result = _result(exchange, self.evidence, protocol)
                if self.ledger.add_observation(run_id, exchange, feature=feature, action=action,
                                               protocol=protocol, result=result, metadata=metadata):
                    counts["observations_added"] += 1
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        if cursor is not None and counts["traffic_examined"] >= limits.max_traffic_records:
            limitations.add("TRAFFIC_BUDGET")
        objects = self._objects(package.target.id, limits.max_objects, counts)
        observations = self.ledger.observations(package.target.id)
        profile = self._profile(package, run_id, target_profile, observations, objects,
                                representatives, counts, limitations, change_at, limits)
        self.ledger.save_profile(profile)
        counts["workflows_learned"] = len(profile.workflows)
        status = (LearningStatus.WAITING_LOGIN if not representatives and
                  self.identities.list_identities(package.target.id, limit=1).items else
                  LearningStatus.PARTIAL if "TRAFFIC_BUDGET" in limitations or
                  "DURATION_BUDGET" in limitations else LearningStatus.COMPLETED)
        reason = ("REAUTH_REQUIRED" if status is LearningStatus.WAITING_LOGIN else
                  "STABLE_EXISTING_DATA" if counts["observations_added"] == 0 else
                  "BOUNDED_PASS_COMPLETE")
        return self.ledger.transition(package.target.id, run_id, status,
            identities=tuple(item[0] for item in representatives),
            sessions=tuple(item[1] for item in representatives), counts=counts,
            before=before, after=profile.coverage, limitations=tuple(sorted(limitations)), reason=reason)

    def _objects(self, target_id: str, limit: int, counts: dict[str, int]) -> tuple[dict[str, object], ...]:
        objects: list[dict[str, object]] = []
        cursor = None
        while len(objects) < limit:
            page = self.objects.list_for_target(target_id, limit=min(50, limit - len(objects)), cursor=cursor)
            for item in page.items:
                if item.state not in {ObjectState.READY, ObjectState.IN_USE} or not item.disposable:
                    continue
                evidence_ids = tuple(dict.fromkeys((*item.creation_evidence_ids,
                                                    *item.verification_evidence_ids)))
                if not item.verification_evidence_ids:
                    continue
                facts = self.evidence.list_facts_for_subject(item.id, limit=20).items
                active = {(fact.predicate, fact.object) for fact in facts if fact.status.value == "ACTIVE"}
                verified = {(fact.predicate, fact.object) for fact in facts
                            if fact.status.value == "ACTIVE" and fact.source == "OBJECT_FACTORY"
                            and fact.confidence >= 0.9 and fact.evidence_ids}
                if (("created_by", item.creator_identity_id) not in verified or
                    ("resource_tenant", item.tenant_id) not in verified):
                    continue
                for predicate, value in (("created_by", item.creator_identity_id),
                                         ("resource_tenant", item.tenant_id),
                                         ("owned_by", item.owner_principal_id),
                                         ("belongs_to", item.parent_id)):
                    if value and (predicate, value) not in active and evidence_ids:
                        self.evidence.create_fact(item.id, predicate, value, confidence=0.95,
                            evidence_ids=evidence_ids[:16], source="NORMAL_BEHAVIOUR_LEARNER",
                            target_ref=target_id)
                        counts["facts_created"] += 1
                objects.append({"id": item.id, "object_ref_id": item.object_ref_id,
                                "type": item.object_type, "owner_identity_id": item.creator_identity_id,
                                "owner_principal_id": item.owner_principal_id,
                                "tenant_id": item.tenant_id, "parent_id": item.parent_id,
                                "creation_exchange_id": item.creation_exchange_id,
                                "evidence_ids": list(evidence_ids[:16]), "confidence": 0.95})
                counts["objects_learned"] += 1
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        return tuple(objects)

    def _profile(self, package: TargetPackage, run_id: str, target_profile: TargetProfile | None,
                 observations: tuple[dict[str, object], ...], objects: tuple[dict[str, object], ...],
                 representatives: tuple[tuple[str, str], ...], counts: dict[str, int],
                 limitations: set[str], change_at: datetime | None,
                 limits: LearningLimits) -> BehaviourProfile:
        now = datetime.now(timezone.utc)
        feature_sources: dict[str, set[str]] = {}
        if target_profile:
            for feature in target_profile.features[:50]:
                feature_sources.setdefault(feature, set()).add("TARGET_PROFILE")
            for signal in target_profile.signals[:120]:
                if signal.feature:
                    feature_sources.setdefault(signal.feature, set()).add(signal.source.value)
        for feature in package.context.known_features[:50]:
            for token in _tokens(feature):
                if token in _FEATURES:
                    feature_sources.setdefault(_FEATURES[token], set()).add("TARGET_CONTEXT")
        for item in observations:
            feature_sources.setdefault(str(item["feature"]), set()).add("TRAFFIC")
        for item in objects:
            feature_sources.setdefault(str(item["type"]), set()).add("OBJECT_FACTORY")
        features = tuple({"name": key, "sources": sorted(value)}
                         for key, value in sorted(feature_sources.items())[:80])
        roles = sorted({role for item in observations for role in item["role_ids"]})[:12]
        tenants = sorted({tenant for item in observations for tenant in item["tenant_ids"]}
                         | {str(item["tenant_id"]) for item in objects})[:30]
        operations: dict[str, dict[str, object]] = {}
        grouped: dict[str, list[dict[str, object]]] = {}
        identity_map: dict[str, dict[str, object]] = {}
        anonymous: dict[str, dict[str, object]] = {}
        stale_count = 0
        fresh_exchange_ids: set[str] = set()
        for item in observations:
            observed_at = datetime.fromisoformat(str(item["observed_at"]))
            stale = observed_at < now - timedelta(days=limits.freshness_days) or (
                change_at is not None and observed_at < change_at)
            stale_count += int(stale)
            if not stale:
                fresh_exchange_ids.add(str(item["exchange_id"]))
            key = str(item["operation_key"])
            operation = operations.setdefault(key, {"key": key, "feature": item["feature"],
                "action": item["action"], "protocol": item["protocol"],
                "metadata": item["metadata"], "exchange_ids": [], "results": [],
                "last_observed_at": item["observed_at"], "stale": stale})
            if len(operation["exchange_ids"]) < 8:
                operation["exchange_ids"].append(item["exchange_id"])
            if item["result"] not in operation["results"]:
                operation["results"].append(item["result"])
            operation["stale"] = bool(operation["stale"]) and stale
            actor = str(item["identity_id"] or "ANONYMOUS")
            correlation = item["metadata"].get("correlation_hash") or key
            workflow_key = _key(actor, str(item["feature"]), str(correlation),
                                ",".join(sorted(item["tenant_ids"])))
            grouped.setdefault(workflow_key, []).append(item)
            summary = identity_map.setdefault(actor, {"identity_id": item["identity_id"],
                "auth_state": item["auth_state"], "features": set(), "operations": set(),
                "tenant_ids": set(), "role_ids": set(), "session_ids": set(), "exchange_ids": []})
            summary["features"].add(item["feature"])
            summary["operations"].add(key)
            summary["tenant_ids"].update(item["tenant_ids"])
            summary["role_ids"].update(item["role_ids"])
            if item["session_id"]:
                summary["session_ids"].add(item["session_id"])
            if len(summary["exchange_ids"]) < 20:
                summary["exchange_ids"].append(item["exchange_id"])
            if actor == "ANONYMOUS":
                anonymous[key] = {"operation_key": key, "feature": item["feature"],
                                  "result": item["result"], "exchange_id": item["exchange_id"]}
        workflows = []
        for key, group in list(grouped.items())[:limits.max_workflow_observations]:
            first = group[0]
            exchange_ids = [item["exchange_id"] for item in group[:8]]
            object_ids = [str(item["id"]) for item in objects
                          if item["creation_exchange_id"] in exchange_ids]
            for item in group[:8]:
                for hint in item["metadata"].get("object_hints", [])[:3]:
                    object_key = _key(str(hint["type"]), str(hint["id_hash"]))
                    object_ids.append("RESPONOBJ-" + object_key[:32])
                for segment in re.findall(r"\{p:([0-9a-f]{12})\}",
                                          str(item["metadata"].get("path_shape", "")))[:3]:
                    object_key = _key(str(item["feature"]), segment)
                    object_ids.append("PATHOBJ-" + object_key[:32])
            workflow = {"id": "BWORK-" + key[:32], "key": key, "feature": first["feature"],
                "action": first["action"], "identity_id": first["identity_id"],
                "tenant_ids": first["tenant_ids"],
                "operation_keys": list(dict.fromkeys(item["operation_key"] for item in group[:8])),
                "object_ids": list(dict.fromkeys(object_ids))[:20],
                "exchange_ids": exchange_ids,
                "evidence_ids": [item["evidence_id"] for item in group[:8]],
                "result": first["result"], "last_observed_at": first["observed_at"]}
            self.ledger.upsert_workflow(package.target.id, workflow)
            workflows.append(workflow)
        role_features = []
        role_operations = []
        verified = [item for item in observations if item["auth_state"] == "VERIFIED" and
                    item["exchange_id"] in fresh_exchange_ids]
        for role in roles:
            role_rows = [item for item in verified if role in item["role_ids"]]
            for feature in [item["name"] for item in features][:25]:
                matches = [item for item in role_rows if item["feature"] == feature]
                state = (MatrixState.OBSERVED if matches else MatrixState.NOT_OBSERVED
                         if role_rows else MatrixState.UNKNOWN)
                role_features.append({"role_id": role, "feature": feature, "state": state.value,
                    "explicit_denials": sum(item["result"] == "OBSERVED_DENIED" for item in matches),
                    "evidence_exchange_ids": [item["exchange_id"] for item in matches[:4]]})
            for operation in list(operations.values())[:25]:
                matches = [item for item in role_rows if item["operation_key"] == operation["key"]]
                state = (MatrixState.OBSERVED if matches else MatrixState.NOT_OBSERVED
                         if role_rows else MatrixState.UNKNOWN)
                role_operations.append({"role_id": role, "operation_key": operation["key"],
                    "feature": operation["feature"], "action": operation["action"],
                    "state": state.value,
                    "explicit_denials": sum(item["result"] == "OBSERVED_DENIED" for item in matches),
                    "evidence_exchange_ids": [item["exchange_id"] for item in matches[:4]]})
        identities = tuple({key: sorted(value) if isinstance(value, set) else value
                            for key, value in summary.items()}
                           for summary in identity_map.values())
        controls = tuple({"identity_id": item["owner_identity_id"], "tenant_id": item["tenant_id"],
                          "object_id": item["id"], "evidence_ids": item["evidence_ids"],
                          "creation_exchange_id": item["creation_exchange_id"]}
                         for item in objects)
        inferred: dict[str, dict[str, object]] = {}
        for item in observations:
            for hint in item["metadata"].get("object_hints", [])[:3]:
                object_key = _key(str(hint["type"]), str(hint["id_hash"]))
                inferred.setdefault(object_key, {"id": "RESPONOBJ-" + object_key[:32],
                    "object_ref_id": hint["id_hash"], "type": hint["type"],
                    "owner_identity_id": None, "owner_principal_id": None,
                    "tenant_id": None, "parent_id": None, "creation_exchange_id": None,
                    "evidence_ids": [hint["evidence_id"]], "confidence": 0.5,
                    "owner_claim_hash": hint["owner_hash"], "tenant_claim_hash": hint["tenant_hash"],
                    "parent_claim_hash": hint["parent_hash"], "source": "RESPONSE_METADATA_ONLY"})
                if len(inferred) >= 50:
                    break
            if len(inferred) >= 50:
                break
            if item["feature"] == "other":
                continue
            for segment in re.findall(r"\{p:([0-9a-f]{12})\}", str(item["metadata"].get("path_shape", "")))[:3]:
                object_key = _key(str(item["feature"]), segment)
                inferred.setdefault(object_key, {"id": "PATHOBJ-" + object_key[:32],
                    "object_ref_id": object_key, "type": item["feature"],
                    "owner_identity_id": None, "owner_principal_id": None,
                    "tenant_id": None, "parent_id": None, "creation_exchange_id": None,
                    "evidence_ids": [item["evidence_id"]], "confidence": 0.3,
                    "source": "TRAFFIC_PATH_ONLY"})
                if len(inferred) >= 50:
                    break
            if len(inferred) >= 50:
                break
        state = ("NONE" if not observations and not objects else "STALE" if observations and
                 stale_count == len(observations) else "GOOD" if len(roles) >= 2 and
                 len(tenants) >= 2 and len(operations) >= 3 else "PARTIAL")
        coverage = {"state": state, "features": len(features), "roles_observed": len(roles),
                    "tenants_observed": len(tenants), "identities_observed": len(identity_map),
                    "operations_observed": len(operations), "workflows_observed": len(workflows),
                    "objects_observed": len(objects) + len(inferred),
                    "verified_owned_objects": len(objects), "traffic_observations": len(observations),
                    "stale_observations": stale_count, "controls": len(controls),
                    "sampled": "TRAFFIC_BUDGET" in limitations}
        gaps: list[dict[str, str]] = []
        if not representatives:
            gaps.append({"code": "NO_VERIFIED_SESSION", "next_step": "Use the VNC login flow and verify an owned session."})
        if len(roles) < 2:
            gaps.append({"code": "SECOND_ROLE_MISSING", "next_step": "Capture normal traffic from a second verified role."})
        if len(tenants) < 2:
            gaps.append({"code": "SECOND_TENANT_MISSING", "next_step": "Add or verify an owned identity in another test tenant."})
        if not objects:
            gaps.append({"code": "OBJECT_OWNERSHIP_UNKNOWN", "next_step": "Verify an owned disposable object through ObjectFactory."})
        if stale_count:
            gaps.append({"code": "STALE_OBSERVATIONS", "next_step": "Refresh changed workflows with verified current traffic."})
        if not observations:
            gaps.append({"code": "NO_TRAFFIC", "next_step": "Use the existing Burp capture path for a normal owned-account workflow."})
        configured = self.ledger.expectations(package.target.id)
        expectations: list[dict[str, object]] = list(configured)
        configured_keys = {(item["role_id"] or "", item["feature"], item["action"] or "")
                           for item in configured}
        for item in role_features[:80]:
            key = (item["role_id"], item["feature"], "")
            if key not in configured_keys:
                expectations.append({"role_id": item["role_id"], "feature": item["feature"],
                    "action": None, "expected_access": "UNKNOWN",
                    "status": (ExpectedAccessStatus.OBSERVED_PATTERN.value if
                               item["state"] == MatrixState.OBSERVED.value else
                               ExpectedAccessStatus.UNKNOWN.value),
                    "provenance": "VERIFIED_TRAFFIC" if item["state"] == MatrixState.OBSERVED.value
                                  else "NO_OBSERVATION"})
        return BehaviourProfile(package.target.id, package.id, run_id, _now(),
            features, tuple(workflows), tuple(list(operations.values())[:80]), identities,
            tuple(tenants), tuple(roles),
            tuple(sorted({str(item["type"]) for item in (*objects, *inferred.values())})),
            tuple((*objects, *inferred.values())), controls, tuple(role_features), tuple(role_operations),
            tuple(anonymous.values()), tuple(expectations), coverage, tuple(gaps),
            {"sources": ["TARGET_PACKAGE", "TARGET_PROFILE", "TRAFFIC_STORE", "IDENTITY_REGISTRY",
                          "OBJECT_FACTORY", "FACT_STORE"],
             "selected_session_ids": [item[1] for item in representatives],
             "traffic_examined": counts["traffic_examined"], "limitations": sorted(limitations)})
