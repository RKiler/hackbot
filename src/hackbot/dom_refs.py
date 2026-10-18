"""Conservative cross-table reference checks for DOM asset and source-map IDs."""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass


_ASSET_ID = re.compile(r"DOMART-[0-9a-f]{32}\Z")
_MAP_ID = re.compile(r"DOMMAP-[0-9a-f]{32}\Z")


class DOMReferenceError(RuntimeError):
    """DOM reference reachability could not be established safely."""


@dataclass(frozen=True, slots=True)
class RetiredDOMOwner:
    kind: str
    owner_id: str
    evidence_id: str
    artifact_sha256: str


def retired_dom_owner(db: sqlite3.Connection, evidence_id: str) -> RetiredDOMOwner | None:
    """Identify one exact currently retired DOM owner, or hold on inconsistency."""
    if not isinstance(evidence_id, str) or not re.fullmatch(r"EV-[0-9a-f]{32}", evidence_id):
        raise ValueError("Invalid DOM Evidence ID")
    rows = db.execute(
        "SELECT 'JS' AS kind,a.artifact_id AS owner_id,a.artifact_sha256 AS digest,"
        "a.target_id,e.artifact_hash,e.content_hash,e.content_kind,e.target_ref "
        "FROM dom_js_artifacts a JOIN evidence e ON e.evidence_id=a.evidence_id "
        "JOIN evidence_payload_retirements r ON r.evidence_id=e.evidence_id "
        "WHERE a.evidence_id=? UNION ALL "
        "SELECT 'SOURCE_MAP',m.map_id,m.map_sha256,m.target_id,"
        "e.artifact_hash,e.content_hash,e.content_kind,e.target_ref "
        "FROM dom_source_maps m JOIN evidence e ON e.evidence_id=m.evidence_id "
        "JOIN evidence_payload_retirements r ON r.evidence_id=e.evidence_id "
        "WHERE m.evidence_id=? LIMIT 2",
        (evidence_id, evidence_id),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise DOMReferenceError("DOM Evidence has multiple owners")
    kind, owner_id, digest, target_id, artifact_hash, content_hash, content_kind, target_ref = rows[0]
    pattern = _ASSET_ID if kind == "JS" else _MAP_ID
    if (not isinstance(owner_id, str) or not pattern.fullmatch(owner_id) or
            not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or
            digest != artifact_hash or digest != content_hash or
            content_kind != "ARTIFACT" or target_id != target_ref):
        raise DOMReferenceError("DOM Evidence ownership is inconsistent")
    return RetiredDOMOwner(kind, owner_id, evidence_id, digest)


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def has_external_dom_reference(
    db: sqlite3.Connection, reference_id: str, *, max_seconds: float = 2.0,
) -> bool:
    """Check all local text and JSON fields except the owner's own primary key.

    This intentionally treats an ordinary metadata mention as a hold. It is
    suitable for a retention precondition, not for deciding that a link is an
    exploitable finding. A timed-out or malformed scan is never a clean result.
    """
    if not isinstance(reference_id, str) or not (
        _ASSET_ID.fullmatch(reference_id) or _MAP_ID.fullmatch(reference_id)
    ):
        raise ValueError("Invalid DOM reference ID")
    if type(max_seconds) not in (int, float) or not 0 < max_seconds <= 30:
        raise ValueError("Invalid DOM reference deadline")
    owner_table, owner_column = (("dom_js_artifacts", "artifact_id")
                                 if reference_id.startswith("DOMART-") else
                                 ("dom_source_maps", "map_id"))
    deadline = time.monotonic() + max_seconds
    db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    try:
        if db.execute(
            f"SELECT 1 FROM {_quote(owner_table)} WHERE {_quote(owner_column)}=? LIMIT 1",
            (reference_id,),
        ).fetchone() is None:
            raise DOMReferenceError("DOM reference owner is unavailable")
        tables = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
        has_retirements = db.execute("PRAGMA user_version").fetchone()[0] >= 41
        for (table,) in tables:
            if time.monotonic() >= deadline:
                raise DOMReferenceError("DOM reference scan is incomplete")
            for column in db.execute(f"PRAGMA table_xinfo({_quote(table)})"):
                if time.monotonic() >= deadline:
                    raise DOMReferenceError("DOM reference scan is incomplete")
                name = column[1]
                if table == owner_table and name == owner_column:
                    continue
                quoted_table, quoted_name = _quote(table), _quote(name)
                active = (" AND NOT EXISTS (SELECT 1 FROM evidence_payload_retirements "
                          "AS retired WHERE retired.evidence_id=owner.evidence_id)"
                          if table == "evidence" and name in {
                              "provenance_json", "metadata_json"
                          } and has_retirements
                          else "")
                if db.execute(
                    f"SELECT 1 FROM {quoted_table} AS owner "
                    f"WHERE typeof(owner.{quoted_name})='text' "
                    f"AND instr(owner.{quoted_name},?)>0{active} LIMIT 1",
                    (reference_id,),
                ).fetchone():
                    return True
                if name.endswith("_json"):
                    if db.execute(
                        f"SELECT 1 FROM {quoted_table} AS owner "
                        f"WHERE owner.{quoted_name} IS NOT NULL "
                        f"AND json_valid(owner.{quoted_name})=0{active} LIMIT 1"
                    ).fetchone():
                        raise DOMReferenceError("DOM JSON reference scan is incomplete")
                    if db.execute(
                        f"SELECT 1 FROM {quoted_table} AS owner, "
                        f"json_tree(owner.{quoted_name}) AS item "
                        "WHERE ((item.type='text' AND instr(item.value,?)>0) "
                        "OR (typeof(item.key)='text' AND instr(item.key,?)>0))"
                        f"{active} LIMIT 1",
                        (reference_id, reference_id),
                    ).fetchone():
                        return True
        return False
    except sqlite3.Error:
        raise DOMReferenceError("DOM reference scan is incomplete") from None
    finally:
        db.set_progress_handler(None, 0)
