"""Immutable report drafts assembled from validated, target-bound observations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import re
import sqlite3
import uuid
from graphql import GraphQLError, parse, print_ast
from graphql.language.ast import (BooleanValueNode, EnumValueNode,
                                  FloatValueNode, IntValueNode, NullValueNode,
                                  StringValueNode)
from graphql.language.visitor import Visitor, visit

from .api_registry import APIOperationRegistry
from .artifacts import ArtifactStore
from .domxss_store import DOMXSSStore
from .exposure_store import ExposureStore
from .plan_runs import PlanRunStore, RunStatus, RuntimeStepStatus
from .postmessage_store import PostMessageStore
from .safe_output import safe_text
from .store import EvidenceFactStore
from .target_loader import TargetPackageRepository
from .target_scope import ScopeResult
from .test_objects import ObjectRegistry
from .traffic import TrafficStore
from .validation_store import Finding, FindingStatus, ValidationResult, ValidationStatus, ValidationStore


_REPORT_ID = re.compile(r"REPORT-[0-9a-f]{32}\Z")
_FINDING_ID = re.compile(r"FINDING-[0-9a-f]{32}\Z")
_PLACEHOLDER = re.compile(r"<([A-Za-z][A-Za-z0-9_]{0,48})>")
_ALLOWED_PLACEHOLDERS = {"SESSION_A", "SESSION_B", "CSRF_TOKEN"}
_OPAQUE_ID = re.compile(r"[A-Z][A-Z_]*-[0-9a-f]{32}\Z")
_GENERATOR_VERSION = "phase29-deterministic-v2"
_SUMMARY_EFFECTS = {
    "PROTECTED_OBJECT_READ": "read protected test-object data",
    "CROSS_TENANT_PROTECTED_OBJECT_READ": "read protected test-object data across tenants",
    "CROSS_TENANT_PROTECTED_BATCH_READ": "read protected test-object data in a batch result",
    "CROSS_TENANT_PROTECTED_NESTED_CHILD_READ": "read a protected child object",
    "CROSS_TENANT_PROTECTED_FIELD_READ": "read a protected API field",
    "GRAPHQL_PROTECTED_OBJECT_READ": "read protected test-object data through GraphQL",
    "UNAUTHORIZED_STATE_CHANGE": "change a controlled object's state",
    "UNAUTHORIZED_OBJECT_DELETION": "delete a controlled object",
    "GRAPHQL_UNAUTHORIZED_STATE_CHANGE": "change a controlled object through GraphQL",
    "CROSS_TENANT_PRIVATE_PII_DISCLOSURE": "read private profile data for a controlled object",
    "RESTRICTED_API_FIELD_DISCLOSED": "read a restricted API field",
    "ANONYMOUS_PROTECTED_CONTENT_READ": "read protected content",
    "NON_PUBLIC_CREDENTIAL_DISCLOSED": "retrieve non-public credential material",
    "NON_PUBLIC_APPLICATION_CREDENTIAL_DISCLOSED": "retrieve a non-public application credential",
    "INTERNAL_VHOST_CREDENTIAL_DISCLOSURE": "retrieve non-public credential material from an internal Host route",
    "BROWSER_SCRIPT_EXECUTION_IN_TARGET_ORIGIN": "execute script in the target browser origin",
    "CROSS_ORIGIN_OWNED_TEST_DATA_DISCLOSURE": "receive protected owned test-object data across origins",
    "CROSS_ORIGIN_SYNTHETIC_DATA_DISCLOSURE": "receive synthetic protected fixture data across origins",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ReportReadiness(StrEnum):
    READY = "READY"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"


class ReportProvenance(StrEnum):
    DETERMINISTIC = "DETERMINISTIC"
    MODEL_ASSISTED = "MODEL_ASSISTED"
    MANUALLY_EDITED = "MANUALLY_EDITED"


@dataclass(frozen=True, slots=True)
class ReportDraft:
    id: str
    target_id: str
    finding_id: str
    version: int
    validation_id: str
    source_snapshot_hash: str
    content_sha256: str
    content_bytes: int
    generator_version: str
    provenance: ReportProvenance
    readiness: ReportReadiness
    severity_status: str
    quality_codes: tuple[str, ...]
    previous_report_id: str | None
    created_at: str

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "target_id": self.target_id, "finding_id": self.finding_id,
                "version": self.version, "validation_id": self.validation_id,
                "source_snapshot_hash": self.source_snapshot_hash,
                "content_sha256": self.content_sha256, "content_bytes": self.content_bytes,
                "generator_version": self.generator_version, "provenance": self.provenance.value,
                "readiness": self.readiness.value, "severity_status": self.severity_status,
                "quality_codes": list(self.quality_codes),
                "previous_report_id": self.previous_report_id, "created_at": self.created_at}


@dataclass(frozen=True, slots=True)
class ReportOutcome:
    readiness: ReportReadiness
    quality_codes: tuple[str, ...]
    draft: ReportDraft | None

    def to_dict(self) -> dict[str, object]:
        return {"readiness": self.readiness.value, "quality_codes": list(self.quality_codes),
                "draft": self.draft.to_dict() if self.draft else None}


class ReportStore:
    def __init__(self, store: EvidenceFactStore, root: ArtifactStore) -> None:
        self.store = store
        self.artifacts = root

    @staticmethod
    def _row(row: sqlite3.Row) -> ReportDraft:
        return ReportDraft(
            row["report_id"], row["target_id"], row["finding_id"], row["version"],
            row["validation_id"], row["source_snapshot_hash"], row["content_sha256"],
            row["content_bytes"], row["generator_version"],
            ReportProvenance(row["provenance"]), ReportReadiness(row["readiness"]),
            row["severity_status"], tuple(json.loads(row["quality_codes_json"])),
            row["previous_report_id"], row["created_at"])

    def get(self, report_id: str, target_id: str) -> ReportDraft | None:
        if not isinstance(report_id, str) or not _REPORT_ID.fullmatch(report_id):
            raise ValueError("invalid report ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM report_drafts WHERE report_id=? AND target_id=?",
                             (report_id, target_id)).fetchone()
        return self._row(row) if row else None

    def latest(self, finding_id: str, target_id: str) -> ReportDraft | None:
        if not isinstance(finding_id, str) or not _FINDING_ID.fullmatch(finding_id):
            raise ValueError("invalid finding ID")
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM report_drafts WHERE finding_id=? AND target_id=? "
                             "ORDER BY version DESC LIMIT 1", (finding_id, target_id)).fetchone()
        return self._row(row) if row else None

    def latest_attempt(self, finding_id: str, target_id: str) -> dict[str, object] | None:
        if not isinstance(finding_id, str) or not _FINDING_ID.fullmatch(finding_id):
            raise ValueError("invalid finding ID")
        with self.store._connection() as db:
            row = db.execute(
                "SELECT a.readiness,a.quality_codes_json,a.report_id,a.created_at "
                "FROM report_attempts a JOIN findings f ON f.finding_id=a.finding_id "
                "WHERE a.finding_id=? AND f.target_id=? ORDER BY a.attempt_id DESC LIMIT 1",
                (finding_id, target_id)).fetchone()
        return ({"readiness": row["readiness"],
                 "quality_codes": json.loads(row["quality_codes_json"]),
                 "report_id": row["report_id"], "created_at": row["created_at"]}
                if row else None)

    def list(self, target_id: str, *, limit: int = 20, cursor: str | None = None) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= 50 or (
                cursor is not None and not cursor.isdecimal()):
            raise ValueError("invalid report page")
        with self.store._connection() as db:
            rows = db.execute("SELECT rowid AS cursor_id,* FROM report_drafts WHERE target_id=? "
                              "AND (? IS NULL OR rowid<?) ORDER BY rowid DESC LIMIT ?",
                              (target_id, int(cursor) if cursor else None,
                               int(cursor) if cursor else None, limit + 1)).fetchall()
        return {"items": [self._row(row).to_dict() for row in rows[:limit]],
                "next_cursor": str(rows[limit - 1]["cursor_id"]) if len(rows) > limit else None}

    def markdown(self, report_id: str, target_id: str) -> str:
        draft = self.get(report_id, target_id)
        if draft is None:
            raise LookupError("report not found")
        content = self.artifacts.get_bytes(draft.content_sha256, max_bytes=65_536)
        if len(content) != draft.content_bytes:
            raise ValueError("report artifact size mismatch")
        return content.decode("utf-8")

    def record_attempt(self, finding_id: str, snapshot_hash: str,
                       readiness: ReportReadiness, codes: tuple[str, ...],
                       report_id: str | None = None) -> None:
        codes_json = json.dumps(codes, separators=(",", ":"))
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            latest = db.execute(
                "SELECT source_snapshot_hash,readiness,quality_codes_json,report_id "
                "FROM report_attempts WHERE finding_id=? ORDER BY attempt_id DESC LIMIT 1",
                (finding_id,)).fetchone()
            if (latest is not None and latest["source_snapshot_hash"] == snapshot_hash and
                    latest["readiness"] == readiness.value and
                    latest["quality_codes_json"] == codes_json and
                    latest["report_id"] == report_id):
                return
            db.execute("INSERT INTO report_attempts(finding_id,source_snapshot_hash,"
                       "readiness,quality_codes_json,report_id,created_at) VALUES (?,?,?,?,?,?)",
                       (finding_id, snapshot_hash, readiness.value, codes_json,
                        report_id, _now()))

    def save(self, *, target_id: str, finding_id: str, validation_id: str,
             snapshot_hash: str, markdown: str, readiness: ReportReadiness,
             provenance: ReportProvenance, quality_codes: tuple[str, ...] = (),
             severity_status: str = "UNASSESSED",
             expected_latest_report_id: str | None = None) -> ReportDraft:
        if (readiness not in {ReportReadiness.READY, ReportReadiness.NEEDS_MANUAL_REVIEW} or
                len(markdown.encode("utf-8")) > 65_536 or not markdown or
                severity_status not in {"UNASSESSED", "SUGGESTED", "RESEARCHER_CONFIRMED"}):
            raise ValueError("invalid report draft")
        artifact = self.artifacts.put_bytes(markdown.encode("utf-8"))
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            finding = db.execute("SELECT validation_id FROM findings WHERE finding_id=? AND target_id=?",
                                 (finding_id, target_id)).fetchone()
            if finding is None or finding[0] != validation_id:
                raise ValueError("report finding is not target-bound")
            latest = db.execute("SELECT * FROM report_drafts WHERE finding_id=? "
                                "ORDER BY version DESC LIMIT 1", (finding_id,)).fetchone()
            if expected_latest_report_id is not None and (
                    latest is None or latest["report_id"] != expected_latest_report_id):
                raise ValueError("stale report edit")
            if (latest and latest["source_snapshot_hash"] == snapshot_hash and
                    latest["content_sha256"] == artifact.sha256 and
                    latest["provenance"] == provenance.value):
                return self._row(latest)
            version = latest["version"] + 1 if latest else 1
            report_id = "REPORT-" + uuid.uuid4().hex
            created_at = _now()
            db.execute("INSERT INTO report_drafts(report_id,target_id,finding_id,version,"
                       "validation_id,source_snapshot_hash,content_sha256,content_bytes,"
                       "generator_version,provenance,readiness,severity_status,quality_codes_json,"
                       "previous_report_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (report_id, target_id, finding_id, version, validation_id,
                        snapshot_hash, artifact.sha256, artifact.size_bytes,
                        _GENERATOR_VERSION, provenance.value, readiness.value,
                        severity_status, json.dumps(quality_codes),
                        latest["report_id"] if latest else None, created_at))
            db.execute("INSERT INTO report_attempts(finding_id,source_snapshot_hash,"
                       "readiness,quality_codes_json,report_id,created_at) VALUES (?,?,?,?,?,?)",
                       (finding_id, snapshot_hash, readiness.value,
                        json.dumps(quality_codes, separators=(",", ":")), report_id, created_at))
            row = db.execute("SELECT * FROM report_drafts WHERE report_id=?", (report_id,)).fetchone()
        return self._row(row)

    def edit(self, report_id: str, target_id: str, content: str, *,
             expected_version: int, researcher_reviewed: bool = False) -> ReportDraft:
        current = self.get(report_id, target_id)
        if current is None:
            raise LookupError("report not found")
        latest = self.latest(current.finding_id, target_id)
        if (latest is None or latest.id != current.id or expected_version != current.version or
                not isinstance(content, str) or not 1 <= len(content) <= 65_536 or
                type(researcher_reviewed) is not bool):
            raise ValueError("stale or invalid report edit")
        lines = content.splitlines()
        if len(lines) > 500 or any(len(line) > 4096 for line in lines):
            raise ValueError("report edit exceeds line limits")
        cleaned = "\n".join(safe_text(line, limit=4096) if line else ""
                            for line in lines).strip() + "\n"
        if any(item not in _ALLOWED_PLACEHOLDERS for item in _PLACEHOLDER.findall(cleaned)):
            raise ValueError("unresolved report placeholder")
        if researcher_reviewed:
            required = ("# ", "## Summary", "## Steps to Reproduce", "## Observed Result",
                        "## Expected Result", "## Security Impact", "**Demonstrated:**",
                        "## Supporting Evidence / Notes", current.finding_id,
                        current.validation_id)
            if any(item not in cleaned for item in required):
                raise ValueError("reviewed report is missing required evidence sections")
        if not researcher_reviewed:
            readiness = ReportReadiness.NEEDS_MANUAL_REVIEW
            codes = ("RESEARCHER_REVIEW_REQUIRED",)
        else:
            readiness = ReportReadiness.READY
            codes = ("RESEARCHER_EDIT_REVIEWED",)
        fingerprint = hashlib.sha256((current.source_snapshot_hash + ":edit:" +
                                      hashlib.sha256(cleaned.encode()).hexdigest()).encode()).hexdigest()
        draft = self.save(target_id=target_id, finding_id=current.finding_id,
                          validation_id=current.validation_id, snapshot_hash=fingerprint,
                          markdown=cleaned, readiness=readiness,
                          provenance=ReportProvenance.MANUALLY_EDITED,
                          quality_codes=codes, severity_status=current.severity_status,
                          expected_latest_report_id=current.id)
        return draft

    def stats(self, target_id: str | None = None) -> dict[str, int]:
        with self.store._connection() as db:
            where = " WHERE target_id=?" if target_id else ""
            args = (target_id,) if target_id else ()
            count = db.execute("SELECT count(*) FROM report_drafts" + where, args).fetchone()[0]
            versions = db.execute("SELECT count(*) FROM report_drafts WHERE version>1" +
                                  (" AND target_id=?" if target_id else ""), args).fetchone()[0]
        return {"reports_generated": count, "draft_versions": versions}


class ReportGenerator:
    def __init__(self, *, store: EvidenceFactStore, drafts: ReportStore,
                 validations: ValidationStore, runs: PlanRunStore,
                 traffic: TrafficStore, targets: TargetPackageRepository,
                 objects: ObjectRegistry | None = None,
                 dom: DOMXSSStore | None = None,
                 messages: PostMessageStore | None = None,
                 exposure: ExposureStore | None = None,
                 api: APIOperationRegistry | None = None) -> None:
        self.store = store
        self.drafts = drafts
        self.validations = validations
        self.runs = runs
        self.traffic = traffic
        self.targets = targets
        self.objects = objects
        self.dom = dom
        self.messages = messages
        self.exposure = exposure
        self.api = api

    @staticmethod
    def _summary(finding: Finding, validation: ValidationResult,
                 plan: dict[str, object]) -> str | None:
        effect = _SUMMARY_EFFECTS.get(validation.demonstrated_impact or "")
        if effect is None:
            return None
        if finding.category == "DOM_XSS":
            actor = ("an unrelated-origin sender" if isinstance(plan.get("message_binding"), dict)
                     else "a party controlling the tested browser input")
            boundary = "browser input-to-execution"
        elif finding.category == "POSTMESSAGE":
            actor, boundary = "an unrelated-origin sender", "cross-origin messaging trust"
        elif finding.category in {"CREDENTIAL_DISCLOSURE", "INTERNAL_SURFACE_EXPOSURE",
                                  "SENSITIVE_DATA_EXPOSURE", "UNAUTHENTICATED_DOWNLOAD"}:
            actor, boundary = "an unauthenticated requester", "public-to-protected-content"
        else:
            actions = plan.get("proposed_actions")
            boundary_action = next((item for item in actions
                if isinstance(item, dict) and item.get("role") == "BOUNDARY"), None) \
                if isinstance(actions, list) else None
            if boundary_action is None:
                return None
            if boundary_action.get("actor") == "ANONYMOUS":
                actor = "an unauthenticated requester"
            elif (boundary_action.get("actor") == "AUTHENTICATED" and
                  isinstance(boundary_action.get("identity_id"), str) and
                  _OPAQUE_ID.fullmatch(boundary_action["identity_id"])):
                if (finding.category == "CROSS_TENANT_BOLA" or
                        validation.demonstrated_impact.startswith("CROSS_TENANT_")):
                    actor = "a controlled account in another tenant"
                elif finding.category in {"VERTICAL_ROLE_BYPASS", "HIDDEN_FUNCTION_BYPASS"}:
                    actor = "a controlled lower-privilege account"
                else:
                    actor = "the tested authenticated account"
            else:
                return None
            boundary = {
                "CROSS_TENANT_BOLA": "tenant isolation",
                "HORIZONTAL_IDOR": "object ownership",
                "NESTED_PARENT_CHILD_BOLA": "parent-child authorization",
                "VERTICAL_ROLE_BYPASS": "role authorization",
                "HIDDEN_FUNCTION_BYPASS": "function authorization",
                "GRAPHQL_AUTHORIZATION": "GraphQL object or function authorization",
                "API_AUTHORIZATION": "API object or field authorization",
                "FIELD_LEVEL_AUTHORIZATION": "API field authorization",
            }.get(finding.category, "the validated authorization")
        return (f"The {boundary} boundary allowed {actor} to {effect} "
                "on the affected surface.")

    def _browser_proofs(self, target_id: str, run_id: str, candidate_id: str,
                        evidence_ids: tuple[str, ...], evidence_type: str,
                        source: str) -> list[dict[str, object]]:
        proofs: list[dict[str, object]] = []
        for evidence_id in evidence_ids[:64]:
            evidence = self.store.get_evidence(evidence_id)
            if (evidence is None or evidence.target_ref != target_id or
                    evidence.evidence_type != evidence_type or evidence.source != source or
                    evidence.redaction_status.value != "REDACTED" or
                    evidence.content_size > 8192):
                continue
            try:
                item = json.loads(self.store.read_content(evidence_id, max_bytes=8192))
            except (ValueError, UnicodeError, PermissionError, json.JSONDecodeError):
                continue
            if (isinstance(item, dict) and item.get("run_id") == run_id and
                    item.get("candidate_id") == candidate_id):
                proofs.append(item)
            if len(proofs) >= 8:
                break
        return proofs

    def _specialist(self, target_id: str, plan: dict[str, object],
                    validation: ValidationResult) -> tuple[list[str], list[str]]:
        sections: list[str] = []
        gaps: list[str] = []
        dom_binding = plan.get("dom_binding")
        if isinstance(dom_binding, dict):
            candidate_id = dom_binding.get("candidate_id")
            candidate = (self.dom.get_candidate(target_id, candidate_id)
                         if self.dom and isinstance(candidate_id, str) else None)
            if candidate is None:
                gaps.append("DOM_TRACE_UNAVAILABLE")
            else:
                asset = self.dom.candidate_asset(target_id, candidate_id)
                current = (asset is not None and asset.state == "CURRENT" and
                           asset.artifact_sha256 == candidate.asset_sha256)
                if not current:
                    gaps.append("DOM_ASSET_NOT_CURRENT")
                elif candidate.source_map_sha256:
                    source_map = self.dom.get_source_map(target_id, asset.artifact_id)
                    if source_map is None or source_map.map_sha256 != candidate.source_map_sha256:
                        gaps.append("DOM_SOURCE_MAP_CHANGED")
                sections.extend((
                    "### DOM source-to-sink trace",
                    "- Attacker-controlled source: " + safe_text(candidate.source, markdown=True),
                    "- Validation: " + ", ".join(safe_text(item.operation, markdown=True)
                                                  for item in candidate.validation),
                    "- Transformations: " + ", ".join(safe_text(item.operation, markdown=True)
                                                      for item in candidate.transforms),
                    "- Sink: " + safe_text(candidate.sink, markdown=True),
                    ("- Current JS SHA-256: `" if current else
                     "- Validated historical JS SHA-256: `") + candidate.asset_sha256 + "`",
                    "- Source-map SHA-256: `" + (candidate.source_map_sha256 or "not available") + "`",
                ))
        message_binding = plan.get("message_binding")
        if isinstance(message_binding, dict):
            candidate_id = message_binding.get("candidate_id")
            candidate = (self.messages.get_candidate(target_id, candidate_id)
                         if self.messages and isinstance(candidate_id, str) else None)
            if candidate is None:
                gaps.append("MESSAGING_PROTOCOL_UNAVAILABLE")
            else:
                current_assets = [self.messages.dom.get_asset(target_id, artifact_id)
                                  for artifact_id in candidate.artifact_ids]
                current = (len(current_assets) == len(candidate.asset_hashes) and
                           bool(current_assets) and all(
                               asset is not None and asset.state == "CURRENT" and
                               asset.artifact_sha256 == expected_hash
                               for asset, expected_hash in zip(current_assets,
                                                               candidate.asset_hashes)))
                if not current:
                    gaps.append("MESSAGING_ASSET_NOT_CURRENT")
                sections.extend((
                    "### Cross-origin messaging protocol",
                    "- Receiver: " + safe_text(candidate.receiver, markdown=True),
                    "- Sender contexts: " + ", ".join(safe_text(item, markdown=True)
                                                      for item in candidate.sender_contexts),
                    "- Origin check: " + safe_text(candidate.origin_validation, markdown=True),
                    "- Source check: " + safe_text(candidate.source_validation, markdown=True),
                    "- Protocol: " + ", ".join(safe_text(item, markdown=True)
                                                   for item in candidate.protocol_sequence),
                    "- MessagePort accepted/created/bound: " + "/".join(
                        "yes" if value else "no" for value in
                        (candidate.port_accepted, candidate.port_created, candidate.port_bound)),
                    "- RPC methods observed: " + ", ".join(safe_text(item, markdown=True)
                                                              for item in candidate.rpc_methods),
                    ("- Current asset hashes: " if current else
                     "- Validated historical asset hashes: ") + ", ".join("`" + item + "`"
                                                              for item in candidate.asset_hashes[:4]),
                ))
        exposure_binding = plan.get("exposure_binding")
        if isinstance(exposure_binding, dict):
            candidate_id = exposure_binding.get("candidate_id")
            candidate = (self.exposure.get(target_id, candidate_id)
                         if self.exposure and isinstance(candidate_id, str) else None)
            if candidate is None:
                gaps.append("EXPOSURE_SOURCE_UNAVAILABLE")
            else:
                sections.extend((
                    "### Protected resource",
                    "- Source record: `" + safe_text(candidate.endpoint_or_asset, limit=500,
                                                       markdown=True) + "`",
                    "- Classification: " + candidate.category.value,
                    "- Sensitive categories: " + ", ".join(safe_text(item, markdown=True)
                                                        for item in (candidate.pii_categories or
                                                                     ("not recorded",))),
                    "- Authorized/unauthorized comparison: see executed controls and evidence IDs below.",
                    "- Sensitive response bytes are intentionally omitted.",
                ))
        api_binding = plan.get("api_binding")
        if isinstance(api_binding, dict):
            operation_id = api_binding.get("operation_id")
            operation = (self.api.get_operation(target_id, operation_id)
                         if self.api and isinstance(operation_id, str) else None)
            if operation is None:
                gaps.append("API_OPERATION_UNAVAILABLE")
            else:
                passed = {check.code for check in validation.checks
                          if check.outcome.value == "PASS"}
                semantic = None
                if operation.type.value.startswith("GRAPHQL"):
                    if {"PROTECTED_DATA", "INVALID_OBJECT_CONTROL"} <= passed:
                        semantic = ("Protected owner data matched the foreign actor's GraphQL "
                                    "data branch in the recorded reproductions; the invalid-object "
                                    "control did not return that data.")
                    elif "GRAPHQL_DATA_PROOF" in passed:
                        semantic = ("The foreign actor's GraphQL data branch matched the owner "
                                    "control in repeated observations; the invalid-object control "
                                    "returned no object data.")
                    elif "SIDE_EFFECT_READBACK" in passed:
                        semantic = ("The unauthorized GraphQL mutation produced an effect that "
                                    "the owner subsequently read back; the invalid-object control "
                                    "did not produce that effect.")
                    else:
                        gaps.append("GRAPHQL_SEMANTIC_SUMMARY_UNAVAILABLE")
                sections.extend((
                    "### API operation",
                    "- Operation: " + safe_text(operation.name, markdown=True),
                    "- Type: " + operation.type.value,
                    "- Variables: " + ", ".join("`" + safe_text(item) + "`"
                                                   for item in operation.variables),
                    "- Selected fields: " + ", ".join("`" + safe_text(item.path) + "`"
                                                         for item in operation.fields[:12]),
                    "- Observed document evidence: `" +
                    (operation.document_evidence_id or "not retained") + "`",
                    "- Semantic result: " + (semantic or "consult validated checks and evidence IDs."),
                ))
                document = self._graphql_document(operation.document_evidence_id, target_id,
                                                  operation.version_hash)
                if document:
                    sections.extend(("- Sanitized observed query/mutation:", "```graphql", document, "```"))
                elif operation.type.value.startswith("GRAPHQL"):
                    gaps.append("GRAPHQL_DOCUMENT_WITHHELD")
        return sections, gaps

    def _graphql_document(self, evidence_id: str | None, target_id: str,
                          expected_hash: str) -> str | None:
        if not evidence_id:
            return None
        evidence = self.store.get_evidence(evidence_id)
        if evidence is None or evidence.target_ref != target_id:
            return None
        try:
            raw = self.store.read_content(
                evidence_id, allow_sensitive=True, max_bytes=16_384).decode("utf-8")
            payload = json.loads(raw)
            query = payload.get("query") if isinstance(payload, dict) else raw
            if not isinstance(query, str) or len(query) > 4096:
                return None
            if hashlib.sha256(query.encode("utf-8")).hexdigest() != expected_hash:
                return None
            class LiteralGate(Visitor):
                def enter(self, node, *args):
                    if isinstance(node, (BooleanValueNode, EnumValueNode, FloatValueNode,
                                         IntValueNode, NullValueNode, StringValueNode)):
                        raise ValueError("literal-bearing GraphQL document")

            document = parse(query)
            visit(document, LiteralGate())
            rendered = print_ast(document)
            return rendered if len(rendered) <= 4096 else None
        except (KeyError, ValueError, UnicodeError, PermissionError, GraphQLError):
            return None

    def generate(self, finding_id: str, target_id: str) -> ReportOutcome:
        finding = self.validations.get_finding(finding_id, target_id)
        if finding is None:
            raise LookupError("finding not found")
        validation = self.validations.get(finding.validation_id, target_id)
        run = self.runs.get(validation.run_id, target_id) if validation else None
        package = self.targets.get_target_package(run.package_id) if run else None
        exposure_candidate_id = (self.exposure.candidate_for_plan(target_id, run.plan_id)
                                 if self.exposure and run else None)
        codes: list[str] = []
        if (validation is None or validation.status is not ValidationStatus.CONFIRMED or
                validation.source != "DETERMINISTIC"):
            codes.append("NOT_DETERMINISTICALLY_CONFIRMED")
        if finding.status is FindingStatus.DUPLICATE:
            codes.append("ROOT_CAUSE_DUPLICATE")
        if not finding.demonstrated_impact or not validation or not validation.demonstrated_impact:
            codes.append("MISSING_DEMONSTRATED_IMPACT")
        if run is None or run.status is not RunStatus.COMPLETED:
            codes.append("COMPLETED_RUN_REQUIRED")
        if package is None or package.target.id != target_id:
            codes.append("AUTHORITATIVE_SCOPE_UNAVAILABLE")
        evidence_ids = tuple(dict.fromkeys((*finding.evidence_ids,
            *(validation.supporting_evidence_ids if validation else ()))))
        if not evidence_ids or any((item := self.store.get_evidence(evidence_id)) is None or
                                   item.target_ref != target_id for evidence_id in evidence_ids):
            codes.append("EVIDENCE_UNAVAILABLE")
        source_steps: list[tuple[str, str, tuple[str, ...]]] = []
        scoped_surfaces: list[str] = []
        object_links: list[str] = []
        if run:
            for step in self.runs.steps(run.id):
                if step.status is not RuntimeStepStatus.COMPLETED:
                    continue
                result = self.runs.result(step.id) if step.result_id else None
                if result is None:
                    continue
                sources = []
                for exchange_id in result.exchange_ids[:4]:
                    exchange = self.traffic.get_exchange(exchange_id)
                    if exchange is None or exchange.target_id != target_id:
                        codes.append("TRAFFIC_REFERENCE_MISSING")
                        continue
                    scoped_url = exchange.request.origin + exchange.request.display_path
                    if package and (exchange.scope_result is not ScopeResult.IN_SCOPE or
                                    package.scope.evaluate_url(scoped_url).result is not ScopeResult.IN_SCOPE):
                        codes.append("AFFECTED_ASSET_OUT_OF_SCOPE")
                        continue
                    surface = exchange.request.origin + exchange.request.display_path
                    scoped_surfaces.append(surface)
                    status = exchange.response.record.status_code if exchange.response else None
                    sources.append(exchange.request.record.method + " " + surface +
                                   (f" (HTTP {status})" if status is not None else ""))
                if not sources and not result.evidence_ids:
                    continue
                description = safe_text(step.type + " / " + step.role, markdown=True)
                if sources:
                    description += " against " + "; ".join(safe_text(item, markdown=True, limit=500)
                                                          for item in sources)
                elif result.evidence_ids:
                    description += " with recorded browser/experiment evidence"
                source_steps.append((description, step.id, result.evidence_ids))
        if not source_steps:
            codes.append("EXECUTED_REPRODUCTION_STEPS_MISSING")
        if package and not scoped_surfaces and run:
            plan = self.runs.snapshot(run.plan_id, target_id).data
            for key in ("dom_binding", "message_binding", "exposure_binding"):
                binding = plan.get(key)
                if not isinstance(binding, dict):
                    continue
                route = binding.get("route_url") or binding.get("url")
                if isinstance(route, str) and package.scope.evaluate_url(route).result is ScopeResult.IN_SCOPE:
                    scoped_surfaces.append(route)
                    break
            if not scoped_surfaces:
                codes.append("AFFECTED_SURFACE_UNAVAILABLE")
        snapshot = {"finding": finding.id, "validation": validation.id if validation else None,
                    "evidence_hash": validation.evidence_snapshot_hash if validation else None,
                    "finding_evidence": evidence_ids, "run": run.id if run else None,
                    "run_snapshot": run.snapshot_hash if run else None,
                    "exposure_candidate": exposure_candidate_id,
                    "steps": [(label, step_id, refs) for label, step_id, refs in source_steps],
                    "generator": _GENERATOR_VERSION}
        snapshot_hash = hashlib.sha256(json.dumps(snapshot, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        critical = tuple(dict.fromkeys(codes))
        if critical:
            self.drafts.record_attempt(finding.id, snapshot_hash, ReportReadiness.NEEDS_EVIDENCE,
                                       critical)
            return ReportOutcome(ReportReadiness.NEEDS_EVIDENCE, critical, None)
        assert run and validation and package
        plan = dict(self.runs.snapshot(run.plan_id, target_id).data)
        if exposure_candidate_id and not plan.get("exposure_binding"):
            plan["exposure_binding"] = {"candidate_id": exposure_candidate_id}
        specialist, gaps = self._specialist(target_id, plan, validation)
        summary = self._summary(finding, validation, plan)
        if summary is None:
            gaps.append("SUMMARY_BOUNDARY_OR_ACTOR_UNAVAILABLE")
            summary = finding.safe_summary
        dom_binding = plan.get("dom_binding")
        if isinstance(dom_binding, dict) and isinstance(dom_binding.get("candidate_id"), str):
            proofs = self._browser_proofs(target_id, run.id, dom_binding["candidate_id"],
                evidence_ids, "DOM_PROOF", "domxss_browser")
            executed = [item for item in proofs if item.get("marker_observed") is True]
            if executed:
                specialist.extend((
                    "- Runtime execution variants: " + ", ".join(
                        "`" + safe_text(item.get("variant"), limit=48) + "`" for item in executed),
                    "- Browser proof context: " + safe_text(
                        executed[-1].get("marker_context"), limit=120, markdown=True),
                    "- Browser controls: CSP present=" + str(executed[-1].get("csp_present")) +
                    "; Trusted Types enforced=" + str(executed[-1].get("trusted_types_enforced")) +
                    "; sandbox flags=" + ", ".join(safe_text(flag, limit=60, markdown=True)
                        for flag in executed[-1].get("sandbox_flags", [])[:8]),
                ))
            else:
                gaps.append("DOM_BROWSER_PROOF_METADATA_UNAVAILABLE")
        message_binding = plan.get("message_binding")
        if isinstance(message_binding, dict) and isinstance(message_binding.get("candidate_id"), str):
            proofs = self._browser_proofs(target_id, run.id, message_binding["candidate_id"],
                evidence_ids, "MESSAGE_PROOF", "postmessage_browser")
            capable = [item for item in proofs if item.get("capability_observed") is True]
            if capable:
                specialist.extend((
                    "- Runtime capability variants: " + ", ".join(
                        "`" + safe_text(item.get("variant"), limit=48) + "`" for item in capable),
                    "- Observed capability: " + safe_text(
                        capable[-1].get("effect_kind"), limit=100, markdown=True) +
                    "; MessagePort count=" + str(capable[-1].get("port_count")) +
                    "; RPC calls=" + str(capable[-1].get("rpc_calls")),
                    "- Sender/source relationship: " + safe_text(
                        capable[-1].get("source_relationship"), limit=100, markdown=True),
                    "- Browser controls: frame-ancestors=" + safe_text(
                        capable[-1].get("frame_ancestors"), limit=100, markdown=True) +
                    "; X-Frame-Options=" + safe_text(
                        capable[-1].get("x_frame_options"), limit=100, markdown=True) +
                    "; sandbox flags=" + ", ".join(safe_text(flag, limit=60, markdown=True)
                        for flag in capable[-1].get("sandbox_flags", [])[:8]),
                ))
            else:
                gaps.append("MESSAGE_BROWSER_PROOF_METADATA_UNAVAILABLE")
        seen_objects: set[str] = set()
        for item in (plan.get("request_templates") or ()):  # Opaque owned-object provenance only.
            if not isinstance(item, dict) or not isinstance(item.get("test_object_id"), str) or not self.objects:
                continue
            obj = self.objects.get(item["test_object_id"], target_id)
            if obj is not None and obj.id not in seen_objects:
                seen_objects.add(obj.id)
                object_links.append(f"- Owned fixture `{obj.id}`: creator `{obj.creator_identity_id}`, "
                                    f"tenant `{safe_text(obj.tenant_id or 'none')}`, type "
                                    f"`{safe_text(obj.object_type)}`.")
        actor_lines: list[str] = []
        if ("AUTH" in finding.category.upper() or
                "authorization" in validation.skill_id.lower()):
            seen_actors: set[tuple[str, str]] = set()
            actions = plan.get("proposed_actions")
            for action in (actions[:16] if isinstance(actions, list) else ()):
                if not isinstance(action, dict):
                    continue
                identity_id, role = action.get("identity_id"), action.get("role")
                if (not isinstance(identity_id, str) or not _OPAQUE_ID.fullmatch(identity_id)
                        or not isinstance(role, str) or
                        not re.fullmatch(r"[A-Z][A-Z0-9_]{1,40}", role)):
                    continue
                key = (identity_id, role)
                if key not in seen_actors:
                    seen_actors.add(key)
                    actor_lines.append(f"- Executed `{role}` request as identity `{identity_id}`.")
        readiness = (ReportReadiness.NEEDS_MANUAL_REVIEW if gaps else ReportReadiness.READY)
        safe_title = safe_text(finding.title, limit=180, markdown=True)
        surface = safe_text(scoped_surfaces[0], limit=500, markdown=True)
        lines = [f"# {safe_title}", "", "## Summary",
                 safe_text(summary, limit=600, markdown=True), "",
                 f"Affected surface: `{surface}`. Category: `{safe_text(finding.category)}`.", "",
                 "## Steps to Reproduce", "Use only authorized, tester-owned identities and fixtures. "
                 "Substitute <SESSION_A>, <SESSION_B>, and <CSRF_TOKEN> where the captured "
                 "authenticated request requires them; live values are not included."]
        for index, (description, step_id, refs) in enumerate(source_steps, 1):
            lines.append(f"{index}. {description}. Step `{step_id}`; evidence: " +
                         ", ".join("`" + ref + "`" for ref in refs[:8]) + ".")
        lines.extend(("", "## Observed Result",
                      safe_text(finding.demonstrated_impact, limit=500, markdown=True),
                      "Validation reason codes: " + ", ".join("`" + code + "`"
                                                             for code in validation.reason_codes),
                      "", "## Expected Result",
                      "The tested authorization or execution boundary should prevent the "
                      "observed unauthorized effect.", "", "## Security Impact",
                      "**Demonstrated:** " + safe_text(validation.demonstrated_impact,
                                                       limit=500, markdown=True)))
        if validation.potential_impact or finding.potential_impact:
            lines.append("**Potential, not demonstrated:** " + safe_text(
                validation.potential_impact or finding.potential_impact, limit=500, markdown=True))
        lines.extend(("", "## Supporting Evidence / Notes",
                      f"- Finding: `{finding.id}`; validation: `{validation.id}`; run: `{run.id}`.",
                      "- Controls evaluated: " + ", ".join("`" + safe_text(item) + "`"
                                                                 for item in validation.controls_evaluated),
                      "- Evidence IDs: " + ", ".join("`" + ref + "`" for ref in evidence_ids[:48]),
                      "- Skill: `" + safe_text(validation.skill_id) + "` version `" +
                      safe_text(validation.skill_version) + "`.",
                      "- Severity: " + ("preliminary suggestion `" +
                      safe_text(finding.preliminary_severity) + "`; researcher review required."
                      if finding.preliminary_severity else "unassessed; researcher review required.")))
        lines.extend(object_links)
        if actor_lines:
            lines.extend(("", "### Authorization actors and boundary", *actor_lines,
                          "- Validated controls: " + ", ".join(
                              "`" + safe_text(item) + "`"
                              for item in validation.controls_evaluated) + "."))
        lines.extend(specialist)
        lines.extend(("", "## Limitations"))
        lines.extend("- " + safe_text(item, limit=500, markdown=True)
                     for item in (validation.limitations or ("None recorded by the validator.",)))
        if gaps:
            lines.append("- Manual review required: " + ", ".join(gaps) + ".")
        content = "\n".join(lines).strip() + "\n"
        if any(item not in _ALLOWED_PLACEHOLDERS for item in _PLACEHOLDER.findall(content)):
            self.drafts.record_attempt(finding.id, snapshot_hash, ReportReadiness.NEEDS_MANUAL_REVIEW,
                                       ("UNRESOLVED_PLACEHOLDER",))
            return ReportOutcome(ReportReadiness.NEEDS_MANUAL_REVIEW,
                                 ("UNRESOLVED_PLACEHOLDER",), None)
        draft = self.drafts.save(target_id=target_id, finding_id=finding.id,
                                 validation_id=validation.id, snapshot_hash=snapshot_hash,
                                 markdown=content, readiness=readiness,
                                 provenance=ReportProvenance.DETERMINISTIC,
                                 quality_codes=tuple(gaps),
                                 severity_status="SUGGESTED" if finding.preliminary_severity
                                 else "UNASSESSED")
        return ReportOutcome(readiness, tuple(gaps), draft)
