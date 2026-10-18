"""BugHunter-owned SQLite Evidence and Fact Store. No recon connection."""

from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import hashlib
from importlib.resources import files
import json
import math
import os
from pathlib import Path
import re
import sqlite3
from threading import local
from typing import Iterator, Mapping
from urllib.parse import quote
import uuid
from weakref import WeakSet

from .artifacts import ArtifactIntegrityError, ArtifactStore
from .config import AppConfig, StoreSettings
from .evidence import (
    ContentKind, Evidence, EvidenceProvenance, EvidenceType, Fact, FactStatusEvent,
    FactStatus, RedactionStatus, Retention, Sensitivity,
)
from .logging import is_sensitive_key
from .recon import Page


class StoreNotInitialized(RuntimeError):
    pass


class StoreSchemaError(RuntimeError):
    pass


class _StoreConnection(sqlite3.Connection):
    """Track cursors so an idle cached connection cannot retain read locks."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._cursors: WeakSet[sqlite3.Cursor] = WeakSet()

    def cursor(self, factory: type[sqlite3.Cursor] | None = None) -> sqlite3.Cursor:
        cursor = super().cursor(factory) if factory is not None else super().cursor()
        self._cursors.add(cursor)
        return cursor

    def execute(self, sql: str, parameters: object = ()) -> sqlite3.Cursor:
        return self.cursor().execute(sql, parameters)

    def executemany(self, sql: str, seq_of_parameters: object) -> sqlite3.Cursor:
        return self.cursor().executemany(sql, seq_of_parameters)

    def executescript(self, sql_script: str) -> sqlite3.Cursor:
        return self.cursor().executescript(sql_script)

    def close_cursors(self) -> None:
        cursors = tuple(self._cursors)
        self._cursors.clear()
        for cursor in cursors:
            cursor.close()


_ID_PATTERN = re.compile(r"(?:EV|FA)-[0-9a-f]{32}\Z")
_TYPE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_PREDICATE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_MAX_METADATA_BYTES = 8192
_MAX_FACT_EVIDENCE = 16
_SCHEMA_VERSION = 47


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{label} must have a timezone")
    return value.astimezone(timezone.utc)


def _text(value: str, label: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"Invalid {label}")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"Invalid {label}")
    return value


def _optional_text(value: str | None, label: str, maximum: int = 1024) -> str | None:
    return None if value is None else _text(value, label, maximum)


def _id(value: str, prefix: str) -> str:
    if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value) or not value.startswith(prefix + "-"):
        raise ValueError("Invalid record identifier")
    return value


def _json(value: object, *, maximum: int = _MAX_METADATA_BYTES) -> str:
    try:
        result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("Invalid structured metadata") from None
    if len(result.encode("utf-8")) > maximum:
        raise ValueError("Structured metadata is too large")
    return result


def _has_sensitive_key(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(is_sensitive_key(str(key)) or _has_sensitive_key(item) for key, item in value.items())
    if isinstance(value, (tuple, list)):
        return any(_has_sensitive_key(item) for item in value)
    return False


def _cursor_encode(kind: str, scope: tuple[str, ...], created_at: str, record_id: str) -> str:
    blob = _json({"v": 1, "kind": kind, "scope": scope, "at": created_at, "id": record_id}, maximum=2048)
    return base64.urlsafe_b64encode(blob.encode()).decode().rstrip("=")


def _cursor_decode(token: str | None, kind: str, scope: tuple[str, ...], prefix: str) -> tuple[str, str] | None:
    if token is None:
        return None
    if not isinstance(token, str) or not 1 <= len(token) <= 2048:
        raise ValueError("Invalid store cursor")
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        data = json.loads(raw)
        if data["v"] != 1 or data["kind"] != kind or tuple(data["scope"]) != scope:
            raise ValueError
        _id(data["id"], prefix)
        datetime.fromisoformat(data["at"])
        return data["at"], data["id"]
    except (ValueError, TypeError, KeyError, UnicodeDecodeError, binascii.Error):
        raise ValueError("Invalid store cursor") from None


class EvidenceFactStore:
    """Explicitly initialized local state; all public list calls are bounded."""

    def __init__(self, db_path: Path, artifacts: ArtifactStore, settings: StoreSettings) -> None:
        self.db_path = db_path.expanduser().resolve(strict=False)
        self.artifacts = artifacts
        self.settings = settings
        self._connection_state = local()

    def close_idle_connection(self) -> None:
        """Release this thread's cached SQLite connection before maintenance."""
        state = self._connection_state
        if getattr(state, "active", False):
            raise StoreSchemaError("Cannot close an active store connection")
        connection = getattr(state, "connection", None)
        state.connection = None
        state.identity = None
        if connection is not None:
            connection.close()

    @classmethod
    def from_config(cls, config: AppConfig) -> EvidenceFactStore:
        if config.store is None:
            raise ValueError("Store settings are unavailable")
        return cls(
            config.paths.state / "bughunter.sqlite3",
            ArtifactStore(config.store.artifact_root,
                          max_blob_bytes=config.resources.max_artifact_bytes
                          if config.resources else 134_217_728),
            config.store,
        )

    def service_schema_status(self) -> dict[str, object]:
        """Inspect startup compatibility without creating or migrating state."""
        path = self.db_path
        result: dict[str, object] = {"expected_schema": _SCHEMA_VERSION,
                                     "actual_schema": None}
        if path.is_symlink() or (path.exists() and not path.is_file()):
            return {**result, "state": "UNSAFE_PATH"}
        if not path.exists():
            return {**result, "state": "FRESH"}
        try:
            uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=2) as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
        except (OSError, sqlite3.Error):
            return {**result, "state": "UNREADABLE"}
        result["actual_schema"] = version
        return {**result, "state": "READY" if version == _SCHEMA_VERSION
                else "MIGRATION_REQUIRED"}

    def initialize(self, *, allow_existing_migration: bool = False) -> None:
        self.close_idle_connection()
        self.db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.db_path.is_symlink() or not self.db_path.parent.is_dir():
            raise StoreSchemaError("Unsafe local database path")
        fresh = False
        if not allow_existing_migration:
            try:
                fd = os.open(self.db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError:
                pass
            except OSError:
                raise StoreSchemaError("Cannot prepare local database path") from None
            else:
                os.close(fd)
                fresh = True
        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > _SCHEMA_VERSION or version < 0:
                raise StoreSchemaError("Unsupported local store schema version")
            if not allow_existing_migration and not fresh and version != _SCHEMA_VERSION:
                raise StoreSchemaError("Existing store requires reviewed schema migration")
            os.chmod(self.db_path, 0o600)
            for target_version, filename in (
                (1, "001_evidence_facts.sql"),
                (2, "002_identity_registry.sql"),
                (3, "003_auth_contexts.sql"),
                (4, "004_browser_sessions.sql"),
                (5, "005_traffic_store.sql"),
                (6, "006_burp_capture.sql"),
                (7, "007_service_events.sql"),
                (8, "008_target_profiles_hypotheses.sql"),
                (9, "009_policy_engine.sql"),
                (10, "010_traffic_executor.sql"),
                (11, "011_skill_plans.sql"),
                (12, "012_plan_runs.sql"),
                (13, "013_validations_findings.sql"),
                (14, "014_disposable_objects.sql"),
                (15, "015_authorization_specialist.sql"),
                (16, "016_authorization_mutations.sql"),
                (17, "017_dom_xss_specialist.sql"),
                (18, "018_postmessage_specialist.sql"),
                (19, "019_message_dispatch_variants.sql"),
                (20, "020_message_runtime_metrics.sql"),
                (21, "021_message_analysis_links.sql"),
                (22, "022_exposure_specialist.sql"),
                (23, "023_cold_start_bootstrap.sql"),
                (24, "024_normal_behaviour_learning.sql"),
                (25, "025_api_specialist.sql"),
                (26, "026_api_authorization_delegate.sql"),
                (27, "027_api_behaviour_provenance.sql"),
                (28, "028_api_global_id.sql"),
                (29, "029_api_nested_child.sql"),
                (30, "030_api_js_currentness_index.sql"),
                (31, "031_api_inventory_progress.sql"),
                (32, "032_disposable_delete_mutation.sql"),
                (33, "033_delete_source_exchange_index.sql"),
                (34, "034_research_coordinator.sql"),
                (35, "035_cross_specialist_planner.sql"),
                (36, "036_planner_candidate_assessment.sql"),
                (37, "037_notifications_reports.sql"),
                (38, "038_finding_evidence_hold.sql"),
                (39, "039_artifact_reference_indexes.sql"),
                (40, "040_finding_validation_evidence_hold.sql"),
                (41, "041_evidence_payload_retirement.sql"),
                (42, "042_traffic_payload_retirement.sql"),
                (43, "043_traffic_json_reference_index.sql"),
                (44, "044_evidence_json_reference_index.sql"),
                (45, "045_research_brief_retirement.sql"),
                (46, "046_dom_retirement_guards.sql"),
                (47, "047_campaign_coordination.sql"),
            ):
                if version >= target_version:
                    continue
                migration = files("hackbot").joinpath("migrations", filename).read_text()
                if target_version == 42:
                    from .traffic_guard_schema import traffic_guard_sql
                    migration += "\n" + traffic_guard_sql(connection)
                if target_version == 43:
                    from .traffic_guard_schema import traffic_json_index_sql
                    try:
                        migration += "\n" + traffic_json_index_sql(connection)
                    except ValueError:
                        raise StoreSchemaError("Local traffic JSON index cannot be built") from None
                if target_version == 44:
                    from .evidence_json_index_schema import evidence_json_index_sql
                    try:
                        migration += "\n" + evidence_json_index_sql(connection)
                    except ValueError:
                        raise StoreSchemaError("Local Evidence JSON index cannot be built") from None
                if target_version == 46:
                    from .dom_guard_schema import dom_guard_sql
                    migration += "\n" + dom_guard_sql(connection)
                if target_version == 47:
                    from .dom_guard_schema import dom_guard_extension_sql
                    migration += "\n" + dom_guard_extension_sql(
                        migration, table_prefix="campaign_")
                try:
                    connection.executescript(
                        "BEGIN IMMEDIATE;\n" + migration
                        + f"\nPRAGMA user_version={target_version};\nCOMMIT;"
                    )
                except sqlite3.Error:
                    connection.rollback()
                    raise StoreSchemaError("Local store migration failed") from None
                version = target_version
            expected = {"evidence", "evidence_policy_events", "facts", "fact_evidence", "fact_status_events"}
            expected.update({"registry_targets", "registry_principals", "registry_tenants", "registry_roles",
                             "registry_identities", "registry_principal_links", "registry_memberships",
                             "registry_membership_roles", "auth_contexts", "auth_context_events",
                             "browser_sessions", "browser_session_events"})
            expected.update({"traffic_requests", "traffic_responses", "traffic_exchanges"})
            expected.update({"burp_projects", "burp_listener_bindings", "burp_capture_index", "burp_bridge_health"})
            expected.add("service_events")
            expected.update({"target_profiles", "profile_source_evidence", "hypotheses",
                             "hypothesis_evidence", "hypothesis_facts", "hypothesis_events",
                             "hypothesis_relationships"})
            expected.update({"policy_actions", "policy_decisions", "policy_approvals",
                             "policy_events"})
            expected.update({"executor_permits", "executor_events"})
            expected.update({"skill_plans", "skill_plan_selections"})
            expected.update({"plan_runs", "plan_run_steps", "plan_step_results",
                             "plan_step_manual_links", "plan_run_events"})
            expected.update({"validations", "validation_checks", "findings",
                             "finding_evidence", "finding_locations", "finding_duplicates",
                             "finding_status_events"})
            expected.update({"test_objects", "test_object_events", "test_object_reservations",
                             "test_object_operations", "plan_object_requirements"})
            expected.update({"authorization_hunts", "authorization_candidates",
                             "authorization_hunt_candidates", "authorization_observations",
                             "authorization_hunt_objects"})
            expected.add("authorization_mutation_results")
            expected.update({"dom_js_artifacts", "dom_source_maps", "dom_analysis_runs", "dom_flow_candidates",
                             "dom_candidate_events", "plan_dom_dispatches"})
            expected.update({"message_analysis_runs", "message_protocol_candidates",
                             "message_candidate_assets", "message_type_index",
                             "message_candidate_events", "plan_message_dispatches"})
            expected.update({"exposure_candidates", "exposure_candidate_sources",
                             "exposure_candidate_events"})
            expected.update({"bootstrap_runs", "bootstrap_observations", "bootstrap_discovery_states"})
            expected.update({"behaviour_runs", "behaviour_observations", "behaviour_workflows",
                             "behaviour_expectations", "behaviour_profiles"})
            expected.update({"research_requests", "research_briefs", "research_sources",
                             "research_brief_sources", "research_skill_proposals",
                             "research_hypothesis_links"})
            expected.update({"planner_runs", "planner_candidates", "planner_candidate_assessments",
                             "planner_candidate_relationships",
                             "planner_tasks",
                             "planner_budget_reservations", "planner_task_dependencies",
                             "planner_events", "planner_branch_memory"})
            expected.update({"finding_submission_metadata", "notification_events",
                             "notification_deliveries", "notification_attempts",
                             "report_drafts", "report_attempts"})
            expected.add("finding_validation_evidence_holds")
            expected.add("evidence_payload_retirements")
            expected.add("traffic_payload_retirements")
            expected.update({"traffic_json_reference_counts", "traffic_json_reference_sources"})
            expected.update({"evidence_json_reference_counts", "evidence_json_reference_sources"})
            expected.update({"research_brief_payload_retirements",
                             "planner_candidate_research_refs",
                             "planner_event_research_refs"})
            expected.add("dom_retirement_guard_sources")
            expected.update({"campaigns", "campaign_cycles", "campaign_work",
                             "campaign_task_claims", "campaign_events",
                             "campaign_suppressions", "campaign_objects"})
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN (" + ",".join("?" for _ in expected) + ")",
                tuple(expected),
            )}
            if tables != expected:
                raise StoreSchemaError("Local store schema is incomplete")
            from .traffic_guard_schema import (verify_traffic_retirement_guards,
                                               verify_traffic_json_index)
            from .evidence_json_index_schema import verify_evidence_json_index
            try:
                verify_traffic_retirement_guards(connection)
                verify_traffic_json_index(connection)
            except ValueError:
                raise StoreSchemaError("Local traffic retirement guards are incomplete") from None
            try:
                verify_evidence_json_index(connection)
            except ValueError:
                raise StoreSchemaError("Local Evidence JSON reference guards are incomplete") from None
            from .research_retention import verify_research_retirement_schema
            try:
                verify_research_retirement_schema(connection)
            except ValueError:
                raise StoreSchemaError("Local research retention guards are incomplete") from None
            from .dom_guard_schema import verify_dom_retirement_guards
            try:
                verify_dom_retirement_guards(connection)
            except ValueError:
                raise StoreSchemaError("Local DOM retirement guards are incomplete") from None
        finally:
            connection.close()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if not self.db_path.is_file() or self.db_path.is_symlink():
            raise StoreNotInitialized("Initialize the local BugHunter store first")
        state = self._connection_state
        nested = bool(getattr(state, "active", False))
        metadata = self.db_path.stat()
        identity = (os.getpid(), metadata.st_dev, metadata.st_ino)
        if not nested and getattr(state, "identity", None) != identity:
            self.close_idle_connection()
        uri = "file:" + quote(str(self.db_path), safe="/") + "?mode=rw"
        connection = (getattr(state, "connection", None) if not nested else None)
        if connection is None:
            connection = sqlite3.connect(uri, uri=True, timeout=5, factory=_StoreConnection)
            if not nested:
                state.connection = connection
                state.identity = identity
        if not nested:
            state.active = True
        reusable = False
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            if connection.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_VERSION:
                raise StoreSchemaError("Unsupported local store schema version")
            yield connection
            connection.close_cursors()
            connection.commit()
            reusable = True
        except BaseException:
            try:
                connection.close_cursors()
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            if nested:
                connection.close()
            else:
                state.active = False
                if not reusable:
                    self.close_idle_connection()

    def _limit(self, limit: int) -> int:
        if type(limit) is not int or limit <= 0:
            raise ValueError("Page size must be a positive integer")
        return min(limit, self.settings.max_page_size)

    def create_evidence(
        self,
        evidence_type: str | EvidenceType,
        content: bytes,
        *,
        source: str,
        provenance: EvidenceProvenance,
        target_ref: str | None = None,
        observed_at: datetime | None = None,
        metadata: Mapping[str, object] | None = None,
        sensitivity: Sensitivity = Sensitivity.INTERNAL,
        redaction_status: RedactionStatus = RedactionStatus.ORIGINAL,
        retention: Retention = Retention(),
        replaces_evidence_id: str | None = None,
    ) -> Evidence:
        name = evidence_type.value if isinstance(evidence_type, EvidenceType) else evidence_type
        if not isinstance(name, str) or not _TYPE_PATTERN.fullmatch(name):
            raise ValueError("Invalid evidence type")
        if not isinstance(content, bytes):
            raise TypeError("Evidence content must be bytes")
        if not isinstance(provenance, EvidenceProvenance):
            raise ValueError("Evidence provenance is required")
        if not isinstance(sensitivity, Sensitivity) or not isinstance(redaction_status, RedactionStatus):
            raise ValueError("Invalid evidence classification")
        _text(source, "evidence source", 128)
        _optional_text(target_ref, "target reference", 512)
        _text(provenance.system, "provenance system", 128)
        if replaces_evidence_id is not None:
            _id(replaces_evidence_id, "EV")
        meta = dict(metadata or {})
        if any(not isinstance(key, str) for key in meta):
            raise ValueError("Metadata keys must be strings")
        metadata_json = _json(meta)
        if sensitivity is not Sensitivity.SECRET and _has_sensitive_key(meta):
            raise ValueError("Sensitive metadata keys require SECRET classification")
        if not isinstance(retention, Retention) or (retention.pinned and not retention.retain):
            raise ValueError("Pinned evidence must be retained")
        if retention.expires_at is not None:
            _utc(retention.expires_at, "retention expiry")

        observed = _utc(observed_at, "observation time") if observed_at else _now()
        created = _now()
        digest = hashlib.sha256(content).hexdigest()
        evidence_id = "EV-" + uuid.uuid4().hex
        artifact = sensitivity in {Sensitivity.SENSITIVE, Sensitivity.SECRET} or len(content) > self.settings.max_inline_bytes
        provenance_json = _json(provenance.to_reference())
        if replaces_evidence_id is not None and self.get_evidence(replaces_evidence_id) is None:
            raise ValueError("Replacement evidence does not exist")
        with self.artifacts.hold(shared=True) if artifact else nullcontext():
            if artifact:
                self.artifacts.put_bytes(content)
            with self._connection() as connection:
                connection.execute("""
                    INSERT INTO evidence (
                        evidence_id,evidence_type,target_ref,observed_at,created_at,source,
                        content_hash,content_kind,content_size,inline_content,artifact_hash,
                        metadata_json,sensitivity,redaction_status,provenance_json,replaces_evidence_id
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    evidence_id, name, target_ref, observed.isoformat(), created.isoformat(), source,
                    digest, ContentKind.ARTIFACT.value if artifact else ContentKind.INLINE.value,
                    len(content), None if artifact else content, digest if artifact else None,
                    metadata_json, sensitivity.value, redaction_status.value, provenance_json,
                    replaces_evidence_id,
                ))
                connection.execute("""
                    INSERT INTO evidence_policy_events
                    (evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason)
                    VALUES (?,?,?,?,?,?,?,?)
                """, (
                    evidence_id, int(retention.retain),
                    retention.expires_at.isoformat() if retention.expires_at else None,
                    int(retention.pinned), int(retention.finding_related), created.isoformat(),
                    source, "initial",
                ))
        result = self.get_evidence(evidence_id)
        assert result is not None
        return result

    @staticmethod
    def _evidence_row(row: sqlite3.Row) -> Evidence:
        provenance = json.loads(row["provenance_json"])
        observed = provenance.get("observed_at")
        policy = Retention(
            retain=bool(row["retain"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            pinned=bool(row["pinned"]),
            finding_related=bool(row["finding_related"]),
            changed_at=datetime.fromisoformat(row["changed_at"]),
        )
        return Evidence(
            evidence_id=row["evidence_id"], evidence_type=row["evidence_type"],
            target_ref=row["target_ref"], observed_at=datetime.fromisoformat(row["observed_at"]),
            created_at=datetime.fromisoformat(row["created_at"]), source=row["source"],
            content_hash=row["content_hash"], content_kind=ContentKind(row["content_kind"]),
            content_size=row["content_size"], artifact_hash=row["artifact_hash"],
            sensitivity=Sensitivity(row["sensitivity"]),
            redaction_status=RedactionStatus(row["redaction_status"]),
            provenance=EvidenceProvenance(
                system=provenance["system"], entity=provenance["entity"],
                record_id=provenance["record_id"],
                observed_at=datetime.fromisoformat(observed) if observed else None,
                qualification=provenance["qualification"],
            ),
            metadata=json.loads(row["metadata_json"]), retention=policy,
            replaces_evidence_id=row["replaces_evidence_id"],
        )

    _EVIDENCE_SELECT = """
        SELECT e.evidence_id,e.evidence_type,e.target_ref,e.observed_at,e.created_at,
               e.source,e.content_hash,e.content_kind,e.content_size,e.artifact_hash,
               e.metadata_json,e.sensitivity,e.redaction_status,e.provenance_json,
               e.replaces_evidence_id,p.retain,p.expires_at,p.pinned,p.finding_related,
               p.changed_at
        FROM evidence e JOIN evidence_policy_events p ON p.event_id=(
            SELECT event_id FROM evidence_policy_events
            WHERE evidence_id=e.evidence_id ORDER BY event_id DESC LIMIT 1
        )
    """

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        _id(evidence_id, "EV")
        with self._connection() as connection:
            row = connection.execute(
                self._EVIDENCE_SELECT + " WHERE e.evidence_id=? LIMIT 1", (evidence_id,)
            ).fetchone()
        return self._evidence_row(row) if row else None

    def list_evidence(
        self, *, target_ref: str | None = None, limit: int = 20, cursor: str | None = None
    ) -> Page[Evidence]:
        page_limit = self._limit(limit)
        _optional_text(target_ref, "target reference", 512)
        scope = (target_ref or "",)
        position = _cursor_decode(cursor, "evidence", scope, "EV")
        clauses = []
        params: list[object] = []
        if target_ref is not None:
            clauses.append("e.target_ref=?")
            params.append(target_ref)
        if position is not None:
            clauses.append("(e.created_at,e.evidence_id)<(?,?)")
            params.extend(position)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = self._EVIDENCE_SELECT + where + " ORDER BY e.created_at DESC,e.evidence_id DESC LIMIT ?"
        params.append(page_limit + 1)
        with self._connection() as connection:
            rows = connection.execute(sql, params).fetchall()
        kept = rows[:page_limit]
        next_cursor = (
            _cursor_encode("evidence", scope, kept[-1]["created_at"], kept[-1]["evidence_id"])
            if len(rows) > page_limit else None
        )
        return Page(tuple(self._evidence_row(row) for row in kept), next_cursor)

    def list_evidence_for_target(
        self, target_ref: str, *, limit: int = 20, cursor: str | None = None
    ) -> Page[Evidence]:
        _text(target_ref, "target reference", 512)
        return self.list_evidence(target_ref=target_ref, limit=limit, cursor=cursor)

    def read_content(
        self, evidence_id: str, *, allow_sensitive: bool = False, max_bytes: int = 1024 * 1024
    ) -> bytes:
        record = self.get_evidence(evidence_id)
        if record is None:
            raise KeyError("Evidence not found")
        if record.sensitivity in {Sensitivity.SENSITIVE, Sensitivity.SECRET} and not allow_sensitive:
            raise PermissionError("Sensitive evidence content requires explicit access")
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("Invalid content read limit")
        if record.content_size > max_bytes:
            raise ValueError("Evidence content exceeds explicit read limit")
        with self.artifacts.hold(shared=True) if record.content_kind is ContentKind.ARTIFACT else nullcontext():
            with self._connection() as connection:
                retired = connection.execute(
                    "SELECT 1 FROM evidence_payload_retirements WHERE evidence_id=? LIMIT 1",
                    (evidence_id,),
                ).fetchone()
            if retired is not None:
                raise FileNotFoundError("Evidence payload was retired by retention policy")
            if record.content_kind is ContentKind.ARTIFACT:
                assert record.artifact_hash is not None
                content = self.artifacts.get_bytes(record.artifact_hash, max_bytes=max_bytes)
            else:
                with self._connection() as connection:
                    row = connection.execute(
                        "SELECT inline_content FROM evidence WHERE evidence_id=? LIMIT 1", (evidence_id,)
                    ).fetchone()
                if row is None:
                    raise KeyError("Evidence not found")
                content = row["inline_content"]
        if len(content) != record.content_size or hashlib.sha256(content).hexdigest() != record.content_hash:
            raise ArtifactIntegrityError("Evidence content hash mismatch")
        return content

    def set_retention(
        self, evidence_id: str, retention: Retention, *, actor: str, reason: str
    ) -> Evidence:
        _id(evidence_id, "EV")
        _text(actor, "retention actor", 128)
        _text(reason, "retention reason", 512)
        if not isinstance(retention, Retention) or (retention.pinned and not retention.retain):
            raise ValueError("Invalid retention state")
        if retention.expires_at is not None:
            _utc(retention.expires_at, "retention expiry")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM evidence WHERE evidence_id=? LIMIT 1", (evidence_id,)).fetchone() is None:
                raise KeyError("Evidence not found")
            if connection.execute(
                "SELECT 1 FROM evidence_payload_retirements WHERE evidence_id=? LIMIT 1",
                (evidence_id,),
            ).fetchone() is not None and retention.retain:
                raise ValueError("Retired Evidence payload cannot be retained")
            linked = connection.execute(
                "SELECT 1 FROM finding_evidence WHERE evidence_id=? "
                "UNION ALL SELECT 1 FROM finding_validation_evidence_holds "
                "WHERE evidence_id=? LIMIT 1", (evidence_id, evidence_id),
            ).fetchone() is not None
            if linked and (not retention.retain or not retention.pinned or
                           not retention.finding_related or retention.expires_at is not None):
                raise ValueError("Finding evidence must remain pinned")
            connection.execute("""
                INSERT INTO evidence_policy_events
                (evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                evidence_id, int(retention.retain),
                retention.expires_at.isoformat() if retention.expires_at else None,
                int(retention.pinned), int(retention.finding_related), _now().isoformat(),
                actor, reason,
            ))
        result = self.get_evidence(evidence_id)
        assert result is not None
        return result

    _FACT_SELECT = """
        SELECT f.fact_id,f.subject,f.predicate,f.object_ref,f.confidence,f.source,
               f.observed_at,f.created_at,f.target_ref,f.sensitivity,
               se.status,se.changed_at AS status_changed_at
        FROM facts f JOIN fact_status_events se ON se.event_id=(
            SELECT event_id FROM fact_status_events
            WHERE fact_id=f.fact_id ORDER BY event_id DESC LIMIT 1
        )
    """

    def create_fact(
        self,
        subject: str,
        predicate: str,
        object_ref: str,
        *,
        confidence: float,
        evidence_ids: tuple[str, ...] = (),
        source: str,
        observed_at: datetime | None = None,
        target_ref: str | None = None,
        sensitivity: Sensitivity = Sensitivity.INTERNAL,
    ) -> Fact:
        _text(subject, "fact subject")
        _text(object_ref, "fact object")
        if not isinstance(predicate, str) or not _PREDICATE_PATTERN.fullmatch(predicate):
            raise ValueError("Invalid fact predicate")
        _text(source, "fact source", 128)
        _optional_text(target_ref, "target reference", 512)
        if not isinstance(sensitivity, Sensitivity):
            raise ValueError("Invalid fact sensitivity")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("Fact confidence must be between 0 and 1")
        if not isinstance(evidence_ids, tuple) or len(evidence_ids) > _MAX_FACT_EVIDENCE:
            raise ValueError("At most 16 evidence links are allowed")
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("Duplicate evidence link")
        for evidence_id in evidence_ids:
            _id(evidence_id, "EV")
        if source != "MANUAL" and not evidence_ids:
            raise ValueError("Non-manual facts require supporting evidence")
        observed = _utc(observed_at, "fact observation time") if observed_at else _now()
        created = _now()
        fact_id = "FA-" + uuid.uuid4().hex

        with self._connection() as connection:
            if evidence_ids:
                placeholders = ",".join("?" for _ in evidence_ids)
                rows = connection.execute(
                    f"SELECT evidence_id,sensitivity FROM evidence WHERE evidence_id IN ({placeholders}) LIMIT ?",
                    (*evidence_ids, _MAX_FACT_EVIDENCE),
                ).fetchall()
                if len(rows) != len(evidence_ids):
                    raise ValueError("Supporting evidence does not exist")
                rank = {level: index for index, level in enumerate(Sensitivity)}
                for row in rows:
                    linked = Sensitivity(row["sensitivity"])
                    if rank[linked] > rank[sensitivity]:
                        sensitivity = linked
            connection.execute("""
                INSERT INTO facts
                (fact_id,subject,predicate,object_ref,confidence,source,observed_at,created_at,target_ref,sensitivity)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                fact_id, subject, predicate, object_ref, float(confidence), source,
                observed.isoformat(), created.isoformat(), target_ref, sensitivity.value,
            ))
            for evidence_id in evidence_ids:
                connection.execute(
                    "INSERT INTO fact_evidence(fact_id,evidence_id) VALUES (?,?)",
                    (fact_id, evidence_id),
                )
            connection.execute("""
                INSERT INTO fact_status_events
                (fact_id,status,changed_at,producer,reason,supporting_evidence_id,related_fact_id)
                VALUES (?,?,?,?,?,?,?)
            """, (
                fact_id, FactStatus.ACTIVE.value, created.isoformat(), source,
                "initial", evidence_ids[0] if evidence_ids else None, None,
            ))
        result = self.get_fact(fact_id)
        assert result is not None
        return result

    @staticmethod
    def _facts_from_rows(connection: sqlite3.Connection, rows: list[sqlite3.Row]) -> tuple[Fact, ...]:
        if not rows:
            return ()
        ids = [row["fact_id"] for row in rows]
        placeholders = ",".join("?" for _ in ids)
        links: dict[str, list[str]] = {fact_id: [] for fact_id in ids}
        for link in connection.execute(
            f"SELECT fact_id,evidence_id FROM fact_evidence WHERE fact_id IN ({placeholders}) "
            "ORDER BY fact_id,evidence_id LIMIT ?",
            (*ids, len(ids) * _MAX_FACT_EVIDENCE),
        ):
            links[link["fact_id"]].append(link["evidence_id"])
        return tuple(Fact(
            fact_id=row["fact_id"], subject=row["subject"], predicate=row["predicate"],
            object=row["object_ref"], confidence=row["confidence"],
            evidence_ids=tuple(links[row["fact_id"]]), source=row["source"],
            observed_at=datetime.fromisoformat(row["observed_at"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            target_ref=row["target_ref"], status=FactStatus(row["status"]),
            sensitivity=Sensitivity(row["sensitivity"]),
            status_changed_at=datetime.fromisoformat(row["status_changed_at"]),
        ) for row in rows)

    def get_fact(self, fact_id: str) -> Fact | None:
        _id(fact_id, "FA")
        with self._connection() as connection:
            rows = connection.execute(
                self._FACT_SELECT + " WHERE f.fact_id=? LIMIT 1", (fact_id,)
            ).fetchall()
            facts = self._facts_from_rows(connection, rows)
        return facts[0] if facts else None

    def _list_facts(
        self, field: str, value: str, *, predicate: str | None,
        limit: int, cursor: str | None,
    ) -> Page[Fact]:
        _text(value, "fact lookup value")
        if predicate is not None and not _PREDICATE_PATTERN.fullmatch(predicate):
            raise ValueError("Invalid fact predicate")
        page_limit = self._limit(limit)
        scope = (field, value, predicate or "")
        position = _cursor_decode(cursor, "facts", scope, "FA")
        # `field` is selected from internal identifiers, never caller SQL.
        column = {"subject": "f.subject", "object": "f.object_ref",
                  "target": "f.target_ref"}[field]
        clauses = [column + "=?"]
        params: list[object] = [value]
        if predicate is not None:
            clauses.append("f.predicate=?")
            params.append(predicate)
        if position is not None:
            clauses.append("(f.created_at,f.fact_id)<(?,?)")
            params.extend(position)
        sql = (
            self._FACT_SELECT + " WHERE " + " AND ".join(clauses)
            + " ORDER BY f.created_at DESC,f.fact_id DESC LIMIT ?"
        )
        params.append(page_limit + 1)
        with self._connection() as connection:
            rows = connection.execute(sql, params).fetchall()
            kept = rows[:page_limit]
            facts = self._facts_from_rows(connection, kept)
        next_cursor = (
            _cursor_encode("facts", scope, kept[-1]["created_at"], kept[-1]["fact_id"])
            if len(rows) > page_limit else None
        )
        return Page(facts, next_cursor)

    def list_facts_for_subject(
        self, subject: str, *, predicate: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> Page[Fact]:
        return self._list_facts("subject", subject, predicate=predicate, limit=limit, cursor=cursor)

    def list_facts_for_target(
        self, target_ref: str, *, predicate: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> Page[Fact]:
        return self._list_facts("target", target_ref, predicate=predicate,
                                limit=limit, cursor=cursor)

    def find_facts(
        self, subject: str, predicate: str, *, limit: int = 20, cursor: str | None = None
    ) -> Page[Fact]:
        return self.list_facts_for_subject(subject, predicate=predicate, limit=limit, cursor=cursor)

    def find_relationships(
        self, object_ref: str, *, predicate: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> Page[Fact]:
        return self._list_facts("object", object_ref, predicate=predicate, limit=limit, cursor=cursor)

    def change_fact_status(
        self,
        fact_id: str,
        status: FactStatus,
        *,
        producer: str,
        reason: str,
        supporting_evidence_id: str | None = None,
        related_fact_id: str | None = None,
    ) -> Fact:
        _id(fact_id, "FA")
        if not isinstance(status, FactStatus):
            raise ValueError("Invalid fact status")
        _text(producer, "status producer", 128)
        _text(reason, "status reason", 512)
        if producer != "MANUAL" and supporting_evidence_id is None:
            raise ValueError("Non-manual status changes require evidence")
        if supporting_evidence_id is not None:
            _id(supporting_evidence_id, "EV")
        if related_fact_id is not None:
            _id(related_fact_id, "FA")
            if related_fact_id == fact_id:
                raise ValueError("A fact cannot relate to itself")
        if status is FactStatus.SUPERSEDED and related_fact_id is None:
            raise ValueError("Superseded facts need a replacement fact")
        with self._connection() as connection:
            if connection.execute("SELECT 1 FROM facts WHERE fact_id=? LIMIT 1", (fact_id,)).fetchone() is None:
                raise KeyError("Fact not found")
            if related_fact_id is not None and connection.execute(
                "SELECT 1 FROM facts WHERE fact_id=? LIMIT 1", (related_fact_id,)
            ).fetchone() is None:
                raise ValueError("Related fact does not exist")
            if supporting_evidence_id is not None and connection.execute(
                "SELECT 1 FROM evidence WHERE evidence_id=? LIMIT 1", (supporting_evidence_id,)
            ).fetchone() is None:
                raise ValueError("Supporting evidence does not exist")
            connection.execute("""
                INSERT INTO fact_status_events
                (fact_id,status,changed_at,producer,reason,supporting_evidence_id,related_fact_id)
                VALUES (?,?,?,?,?,?,?)
            """, (
                fact_id, status.value, _now().isoformat(), producer, reason,
                supporting_evidence_id, related_fact_id,
            ))
        result = self.get_fact(fact_id)
        assert result is not None
        return result

    def list_fact_status_history(
        self, fact_id: str, *, limit: int = 20, before_event_id: int | None = None
    ) -> tuple[FactStatusEvent, ...]:
        _id(fact_id, "FA")
        page_limit = self._limit(limit)
        if before_event_id is not None and (type(before_event_id) is not int or before_event_id <= 0):
            raise ValueError("Invalid status history cursor")
        params: tuple[object, ...] = (
            (fact_id, before_event_id, page_limit) if before_event_id else (fact_id, page_limit)
        )
        condition = "AND event_id<?" if before_event_id else ""
        with self._connection() as connection:
            rows = connection.execute(f"""
                SELECT event_id,fact_id,status,changed_at,producer,reason,
                       supporting_evidence_id,related_fact_id
                FROM fact_status_events WHERE fact_id=? {condition}
                ORDER BY event_id DESC LIMIT ?
            """, params).fetchall()
        return tuple(FactStatusEvent(
            event_id=row["event_id"], fact_id=row["fact_id"],
            status=FactStatus(row["status"]), changed_at=datetime.fromisoformat(row["changed_at"]),
            producer=row["producer"], reason=row["reason"],
            supporting_evidence_id=row["supporting_evidence_id"],
            related_fact_id=row["related_fact_id"],
        ) for row in rows)
