"""Conservative reference checks for retiring captured traffic payloads."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from dataclasses import dataclass

from .traffic_guard_schema import verify_traffic_json_index


class TrafficReferenceError(RuntimeError):
    """Traffic reachability could not be established safely."""


_IDS = {
    "exchange": re.compile(r"EXCHANGE-[0-9a-f]{32}\Z"),
    "request": re.compile(r"REQUEST-[0-9a-f]{32}\Z"),
    "response": re.compile(r"RESPONSE-[0-9a-f]{32}\Z"),
}
_BURP_CAPTURE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_BURP_LISTENER = re.compile(r"[A-Za-z0-9.:[\]_-]{1,128}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_OWN_LINKS = frozenset({
    ("traffic_exchanges", "exchange_id"),
    ("traffic_exchanges", "request_id"),
    ("traffic_requests", "request_id"),
    ("traffic_responses", "request_id"),
    ("traffic_responses", "response_id"),
    ("traffic_payload_retirements", "exchange_id"),
    ("traffic_payload_retirements", "request_id"),
    ("traffic_payload_retirements", "response_id"),
})


@dataclass(frozen=True, slots=True)
class RetiredTrafficOwner:
    exchange_id: str
    request_id: str
    response_id: str | None


def retired_traffic_owner(db: sqlite3.Connection, evidence_id: str) -> RetiredTrafficOwner | None:
    """Return a sole terminal traffic owner only after every peer payload retired."""
    if not isinstance(evidence_id, str) or not re.fullmatch(r"EV-[0-9a-f]{32}", evidence_id):
        raise ValueError("Invalid Evidence ID")
    rows = db.execute(
        "SELECT request_id FROM traffic_requests WHERE body_evidence_id=? "
        "OR observation_evidence_id=? UNION ALL "
        "SELECT request_id FROM traffic_responses WHERE body_evidence_id=? "
        "OR observation_evidence_id=? LIMIT 2",
        (evidence_id,) * 4,
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise TrafficReferenceError("Traffic Evidence has multiple owners")
    request_id = rows[0][0]
    exchange = db.execute(
        "SELECT exchange_id,state FROM traffic_exchanges WHERE request_id=?",
        (request_id,),
    ).fetchone()
    request = db.execute(
        "SELECT body_evidence_id,observation_evidence_id FROM traffic_requests "
        "WHERE request_id=?", (request_id,),
    ).fetchone()
    response = db.execute(
        "SELECT response_id,body_evidence_id,observation_evidence_id "
        "FROM traffic_responses WHERE request_id=?", (request_id,),
    ).fetchone()
    if (exchange is None or request is None or
            exchange[1] not in {"COMPLETE", "FAILED", "ABORTED", "TIMEOUT"} or
            (exchange[1] == "COMPLETE") != (response is not None)):
        raise TrafficReferenceError("Traffic Evidence owner is incomplete")
    peer_ids = tuple(value for value in (
        request[0], request[1], response[1] if response else None,
        response[2] if response else None,
    ) if value is not None)
    if len(peer_ids) != len(set(peer_ids)) or evidence_id not in peer_ids:
        raise TrafficReferenceError("Traffic Evidence ownership is inconsistent")
    marks = ",".join("?" for _ in peer_ids)
    retired = db.execute(
        f"SELECT count(*) FROM evidence_payload_retirements "
        f"WHERE evidence_id IN ({marks})", peer_ids,
    ).fetchone()[0]
    if retired != len(peer_ids):
        return None
    if db.execute("PRAGMA user_version").fetchone()[0] < 42:
        return None
    response_id = response[0] if response else None
    if db.execute(
        "SELECT 1 FROM traffic_payload_retirements WHERE exchange_id=? "
        "AND request_id=? AND response_id IS ? LIMIT 1",
        (exchange[0], request_id, response_id),
    ).fetchone() is None:
        return None
    return RetiredTrafficOwner(exchange[0], request_id, response_id)


def _quote(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _burp_index_is_correlation_only(
    db: sqlite3.Connection, exchange_id: str, request_id: str,
    response_id: str | None,
) -> bool:
    """A matching capture index preserves deduplication, not payload reachability."""
    rows = db.execute(
        "SELECT e.target_id,e.request_id,e.source,e.capture_provider,"
        "e.provider_reference_hash,e.state,q.target_id,q.source,"
        "r.response_id,i.target_id AS index_target_id,"
        "i.capture_id,i.request_digest,i.response_digest,i.listener_key "
        "FROM burp_capture_index i JOIN traffic_exchanges e "
        "ON e.exchange_id=i.exchange_id "
        "JOIN traffic_requests q ON q.request_id=e.request_id "
        "LEFT JOIN traffic_responses r ON r.request_id=e.request_id "
        "WHERE i.exchange_id=? LIMIT 2",
        (exchange_id,),
    ).fetchall()
    if len(rows) != 1:
        return False
    (target_id, owner_request_id, source, provider, reference_hash, state,
     request_target_id, request_source, actual_response_id, index_target_id,
     capture_id, request_digest, response_digest, listener_key) = rows[0]
    has_response = response_id is not None
    return (
        target_id == index_target_id and
        owner_request_id == request_id and
        request_target_id == target_id and request_source == "BURP" and
        actual_response_id == response_id and
        source == "BURP" and
        provider == "MONTOYA_V1" and
        state in {"COMPLETE", "FAILED", "ABORTED", "TIMEOUT"} and
        (state == "COMPLETE") == has_response and
        isinstance(capture_id, str) and _BURP_CAPTURE_ID.fullmatch(capture_id) is not None and
        reference_hash == hashlib.sha256(capture_id.encode()).hexdigest() and
        isinstance(request_digest, str) and _DIGEST.fullmatch(request_digest) is not None and
        (response_digest is None if not has_response else
         isinstance(response_digest, str) and _DIGEST.fullmatch(response_digest) is not None) and
        isinstance(listener_key, str) and _BURP_LISTENER.fullmatch(listener_key) is not None
    )


def has_external_traffic_reference(
    db: sqlite3.Connection, *, exchange_id: str, request_id: str,
    response_id: str | None = None, max_seconds: float = 1.0,
) -> bool:
    """Check direct and JSON links, excluding only the exchange's own rows.

    A verified Burp capture index is retained as idempotency metadata, not a
    payload hold. Inconsistent indexes and all specialist links remain holds.
    """
    values = {"exchange": exchange_id, "request": request_id,
              "response": response_id}
    if any(value is not None and
           (not isinstance(value, str) or not _IDS[kind].fullmatch(value))
           for kind, value in values.items()):
        raise ValueError("Invalid traffic reference ID")
    if not isinstance(max_seconds, (int, float)) or not 0 < max_seconds <= 30:
        raise ValueError("Invalid traffic reference-check deadline")
    deadline = time.monotonic() + max_seconds
    db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    try:
        indexed_json = db.execute("PRAGMA user_version").fetchone()[0] >= 43
        checked = tuple(value for value in values.values() if value is not None)
        if indexed_json:
            verify_traffic_json_index(db)
            marks = ",".join("?" for _ in checked)
            if db.execute(
                "SELECT 1 FROM traffic_json_reference_counts "
                f"WHERE ref_id IN ({marks}) LIMIT 1", checked,
            ).fetchone():
                return True
        for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' "
                              "AND name NOT LIKE 'sqlite_%'"):
            table = row[0]
            foreign = {
                entry[3]: entry[2]
                for entry in db.execute(f"PRAGMA foreign_key_list({_quote(table)})")
            }
            for column in db.execute(f"PRAGMA table_xinfo({_quote(table)})"):
                name = column[1]
                if name.endswith("_json"):
                    if indexed_json:
                        continue
                    marks = ",".join("?" for _ in checked)
                    # Invalid JSON must still fail closed. For valid rows, only an
                    # exact ID or a Unicode escape can encode one of these ASCII IDs.
                    if db.execute(
                        f"SELECT 1 FROM {_quote(table)} WHERE {_quote(name)} IS NOT NULL "
                        f"AND json_valid({_quote(name)})=0 LIMIT 1"
                    ).fetchone():
                        raise TrafficReferenceError("Traffic reference check is incomplete")
                    prefilter = " OR ".join(
                        f"instr(owner.{_quote(name)}, ?) > 0"
                        for _ in (*checked, "\\u")
                    )
                    if db.execute(
                        f"SELECT 1 FROM {_quote(table)} AS owner, "
                        f"json_tree(owner.{_quote(name)}) AS item "
                        f"WHERE ({prefilter}) AND item.type='text' "
                        f"AND item.value IN ({marks}) LIMIT 1",
                        (*checked, "\\u", *checked),
                    ).fetchone():
                        return True
                    continue
                kind = next((kind for kind in values if kind in name and name.endswith("_id")), None)
                if foreign.get(name) == "traffic_exchanges":
                    kind = "exchange"
                elif foreign.get(name) == "traffic_requests":
                    kind = "request"
                elif foreign.get(name) == "traffic_responses":
                    kind = "response"
                if kind is None or values[kind] is None or (table, name) in _OWN_LINKS:
                    continue
                if (table, name) == ("burp_capture_index", "exchange_id") and \
                        _burp_index_is_correlation_only(db, exchange_id, request_id, response_id):
                    continue
                if db.execute(
                    f"SELECT 1 FROM {_quote(table)} WHERE {_quote(name)}=? LIMIT 1",
                    (values[kind],),
                ).fetchone():
                    return True
        return False
    except (sqlite3.Error, ValueError):
        raise TrafficReferenceError("Traffic reference check is incomplete") from None
    finally:
        db.set_progress_handler(None, 0)
