"""Reference inventory for safe future retirement of Evidence payloads."""

from __future__ import annotations

import re
import sqlite3
import time

from .evidence_json_index_schema import verify_evidence_json_index


class EvidenceReferenceError(RuntimeError):
    """Evidence reachability could not be established safely."""


_EVIDENCE_ID = re.compile(r"EV-[0-9a-f]{32}\Z")
_REQUEST_ID = re.compile(r"REQUEST-[0-9a-f]{32}\Z")
_DOM_ASSET_ID = re.compile(r"DOMART-[0-9a-f]{32}\Z")
_DOM_MAP_ID = re.compile(r"DOMMAP-[0-9a-f]{32}\Z")
_JSON_REFERENCES: frozenset[tuple[str, str]] = frozenset({
    ("registry_principals", "evidence_ids_json"),
    ("registry_tenants", "evidence_ids_json"),
    ("registry_roles", "evidence_ids_json"),
    ("registry_identities", "evidence_ids_json"),
    ("registry_principal_links", "evidence_ids_json"),
    ("registry_memberships", "evidence_ids_json"),
    ("plan_step_results", "evidence_ids_json"),
    ("plan_step_manual_links", "evidence_ids_json"),
    ("test_object_events", "evidence_ids_json"),
    ("test_objects", "creation_evidence_json"),
    ("test_objects", "verification_evidence_json"),
    ("test_objects", "cleanup_evidence_json"),
    ("authorization_mutation_results", "evidence_ids_json"),
    ("behaviour_workflows", "evidence_ids_json"),
    ("api_operations", "evidence_ids_json"),
    ("authorization_observations", "evidence_ids_json"),
    ("validation_checks", "evidence_ids_json"),
    ("validations", "supporting_evidence_json"),
    ("validations", "contradicting_evidence_json"),
})
_IGNORED_DIRECT = frozenset({
    ("evidence_policy_events", "evidence_id"),
    ("evidence_payload_retirements", "evidence_id"),
})
_DECLARED_DIRECT = frozenset({("exposure_candidate_sources", "evidence_id")})
_SELF_IDENTIFIERS = frozenset({("evidence", "evidence_id")})
_APPROVED_DIRECT = frozenset({
    ("api_operations", "document_evidence_id"),
    ("auth_contexts", "evidence_id"),
    ("behaviour_observations", "evidence_id"),
    ("bootstrap_observations", "evidence_id"),
    ("dom_js_artifacts", "evidence_id"),
    ("dom_source_maps", "evidence_id"),
    ("evidence", "replaces_evidence_id"),
    ("exposure_candidate_sources", "evidence_id"),
    ("fact_evidence", "evidence_id"),
    ("fact_status_events", "supporting_evidence_id"),
    ("finding_evidence", "evidence_id"),
    ("finding_validation_evidence_holds", "evidence_id"),
    ("hypothesis_evidence", "evidence_id"),
    ("message_runtime_trials", "evidence_id"),
    ("profile_source_evidence", "evidence_id"),
    ("test_objects", "external_id_evidence_id"),
    ("traffic_requests", "body_evidence_id"),
    ("traffic_requests", "observation_evidence_id"),
    ("traffic_responses", "body_evidence_id"),
    ("traffic_responses", "observation_evidence_id"),
})
_DIRECT_GUARD_PREFIXES = frozenset({
    "evidence", "fact_evidence", "fact_status", "auth_context",
    "traffic_request", "traffic_response", "profile_source", "hypothesis",
    "test_object", "dom_js", "dom_map", "message_trial", "exposure_source",
    "bootstrap", "behaviour", "api_operation",
})


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def evidence_reference_inventory(
    db: sqlite3.Connection,
) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    """Discover declared references and reject unreviewed JSON Evidence fields."""
    tables = tuple(row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"))
    found_json: set[tuple[str, str]] = set()
    found_ids: set[tuple[str, str]] = set()
    all_json: set[tuple[str, str]] = set()
    direct: set[tuple[str, str]] = set()
    for table in tables:
        for column in db.execute(f"PRAGMA table_xinfo({_quote(table)})"):
            name = column[1]
            if name.endswith("_json"):
                all_json.add((table, name))
            if "evidence" in name and name.endswith("_json"):
                found_json.add((table, name))
            if "evidence" in name and name.endswith("_id"):
                found_ids.add((table, name))
        for reference in db.execute(f"PRAGMA foreign_key_list({_quote(table)})"):
            if reference[2] == "evidence":
                direct.add((table, reference[3]))
    if (found_json - _JSON_REFERENCES or
            found_ids - direct - _DECLARED_DIRECT - _SELF_IDENTIFIERS):
        raise EvidenceReferenceError("Evidence reference schema requires review")
    declared = _DECLARED_DIRECT & found_ids
    if db.execute("PRAGMA user_version").fetchone()[0] >= 41:
        if (direct | declared) - _IGNORED_DIRECT != _APPROVED_DIRECT:
            raise EvidenceReferenceError("Evidence direct reference schema requires review")
        expected_direct_guards = {
            f"retired_link_{prefix}_{action}"
            for prefix in _DIRECT_GUARD_PREFIXES
            for action in ("insert", "update")
        } | {
            "finding_evidence_no_retired_payload",
            "finding_validation_hold_no_retired_payload",
        }
        actual_direct_guards = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' "
            "AND (name LIKE 'retired_link_%' OR name IN "
            "('finding_evidence_no_retired_payload',"
            "'finding_validation_hold_no_retired_payload'))"
        )}
        if not expected_direct_guards <= actual_direct_guards:
            raise EvidenceReferenceError("Evidence direct link guards are incomplete")
        expected_guards = {
            f"retired_json_{table}_{action}"
            for table, _ in _JSON_REFERENCES
            for action in ("insert", "update")
        }
        actual_guards = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' "
            "AND name LIKE 'retired_json_%'"
        )}
        if not expected_guards <= actual_guards:
            raise EvidenceReferenceError("Evidence JSON link guards are incomplete")
    return tuple(sorted((direct | declared) - _IGNORED_DIRECT)), tuple(sorted(all_json))


def has_evidence_reference(
    db: sqlite3.Connection, evidence_id: str, *, max_seconds: float = 1.0,
    allowed_traffic_request_id: str | None = None,
    allowed_dom_artifact_id: str | None = None,
    allowed_dom_map_id: str | None = None,
) -> bool:
    """Fail closed when an Evidence ID is used outside its retention history.

    Generic JSON fields are included because some specialist payloads contain
    Evidence IDs without naming the column after Evidence. A caller may exclude
    only a verified owner's direct link for traffic, a DOM asset, or a source
    map; all other direct and JSON references still protect the Evidence.
    """
    if not isinstance(evidence_id, str) or not _EVIDENCE_ID.fullmatch(evidence_id):
        raise ValueError("Invalid Evidence ID")
    if (allowed_traffic_request_id is not None and
            (not isinstance(allowed_traffic_request_id, str) or
             not _REQUEST_ID.fullmatch(allowed_traffic_request_id))):
        raise ValueError("Invalid traffic request ID")
    for owner_id, pattern, label in (
        (allowed_dom_artifact_id, _DOM_ASSET_ID, "DOM artifact"),
        (allowed_dom_map_id, _DOM_MAP_ID, "DOM source map"),
    ):
        if owner_id is not None and (not isinstance(owner_id, str) or
                                     not pattern.fullmatch(owner_id)):
            raise ValueError(f"Invalid {label} ID")
    if not isinstance(max_seconds, (int, float)) or not 0 < max_seconds <= 30:
        raise ValueError("Invalid reference-check deadline")
    direct, json_columns = evidence_reference_inventory(db)
    deadline = time.monotonic() + max_seconds
    db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    try:
        for owner_id, table, key in (
            (allowed_dom_artifact_id, "dom_js_artifacts", "artifact_id"),
            (allowed_dom_map_id, "dom_source_maps", "map_id"),
        ):
            if owner_id is not None and db.execute(
                f"SELECT 1 FROM {table} WHERE {key}=? AND evidence_id=? LIMIT 1",
                (owner_id, evidence_id),
            ).fetchone() is None:
                raise ValueError("DOM owner does not own the Evidence")
        indexed_json = db.execute("PRAGMA user_version").fetchone()[0] >= 44
        if indexed_json:
            verify_evidence_json_index(db)
        for table, column in direct:
            if allowed_traffic_request_id is not None and table in {
                "traffic_requests", "traffic_responses"
            }:
                found = db.execute(
                    f"SELECT 1 FROM {_quote(table)} WHERE {_quote(column)}=? "
                    "AND request_id<>? LIMIT 1",
                    (evidence_id, allowed_traffic_request_id),
                ).fetchone()
            elif table == "dom_js_artifacts" and allowed_dom_artifact_id is not None:
                found = db.execute(
                    "SELECT 1 FROM dom_js_artifacts WHERE evidence_id=? "
                    "AND artifact_id<>? LIMIT 1",
                    (evidence_id, allowed_dom_artifact_id),
                ).fetchone()
            elif table == "dom_source_maps" and allowed_dom_map_id is not None:
                found = db.execute(
                    "SELECT 1 FROM dom_source_maps WHERE evidence_id=? "
                    "AND map_id<>? LIMIT 1",
                    (evidence_id, allowed_dom_map_id),
                ).fetchone()
            else:
                found = db.execute(
                    f"SELECT 1 FROM {_quote(table)} WHERE {_quote(column)}=? LIMIT 1",
                    (evidence_id,),
                ).fetchone()
            if found:
                return True
        if indexed_json:
            return db.execute(
                "SELECT 1 FROM evidence_json_reference_counts "
                "WHERE ref_id=? LIMIT 1", (evidence_id,),
            ).fetchone() is not None
        for table, column in json_columns:
            if db.execute(
                f"SELECT 1 FROM {_quote(table)} WHERE {_quote(column)} IS NOT NULL "
                f"AND json_valid({_quote(column)})=0 LIMIT 1"
            ).fetchone():
                raise EvidenceReferenceError("Evidence reference check is incomplete")
            if db.execute(
                f"SELECT 1 FROM {_quote(table)} AS owner, "
                f"json_tree(owner.{_quote(column)}) AS item "
                f"WHERE (instr(owner.{_quote(column)}, ?) > 0 OR "
                f"instr(owner.{_quote(column)}, ?) > 0) "
                "AND item.type='text' AND item.value=? LIMIT 1",
                (evidence_id, "\\u", evidence_id),
            ).fetchone():
                return True
        return False
    except (sqlite3.Error, ValueError):
        raise EvidenceReferenceError("Evidence reference check is incomplete") from None
    finally:
        db.set_progress_handler(None, 0)
