"""Schema-derived SQLite guards for retired traffic references."""

from __future__ import annotations

import sqlite3

from .json_reference_schema import json_array_expression, json_reference_columns


_OWN = frozenset({
    ("traffic_exchanges", "exchange_id"),
    ("traffic_exchanges", "request_id"),
    ("traffic_requests", "request_id"),
    ("traffic_responses", "request_id"),
    ("traffic_responses", "response_id"),
})
_TARGETS = {
    "traffic_exchanges": "exchange_id",
    "traffic_requests": "request_id",
    "traffic_responses": "response_id",
}


def _q(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _fields(db: sqlite3.Connection) -> dict[str, tuple[tuple[str, str], ...]]:
    fields: dict[str, tuple[tuple[str, str], ...]] = {}
    tables = [row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )]
    for table in tables:
        if table == "traffic_payload_retirements":
            continue
        foreign = {
            entry[3]: entry[2]
            for entry in db.execute(f"PRAGMA foreign_key_list({_q(table)})")
        }
        selected = []
        for column in db.execute(f"PRAGMA table_xinfo({_q(table)})"):
            name = column[1]
            if name.endswith("_json"):
                selected.append((name, "json"))
                continue
            if (table, name) in _OWN:
                continue
            kind = next((kind for kind in ("exchange", "request", "response")
                         if kind in name and name.endswith("_id")), None)
            if foreign.get(name) in _TARGETS:
                kind = foreign[name].removeprefix("traffic_").removesuffix("s")
            if kind is not None:
                selected.append((name, kind))
        if selected:
            fields[table] = tuple(selected)
    return fields


def traffic_guard_sql(db: sqlite3.Connection) -> str:
    """Generate guards for the migration's exact pre-existing schema."""
    statements = []
    for table, columns in _fields(db).items():
        checks = []
        for name, kind in columns:
            value = f"NEW.{_q(name)}"
            if kind == "json":
                checks.append(
                    "EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid("
                    + value + ") THEN " + value + " ELSE 'null' END) AS item "
                    "JOIN traffic_payload_retirements AS retired ON "
                    "item.type='text' AND item.value IN "
                    "(retired.exchange_id,retired.request_id,retired.response_id))"
                )
            else:
                checks.append(
                    "EXISTS (SELECT 1 FROM traffic_payload_retirements AS retired "
                    f"WHERE retired.{kind}_id={value})"
                )
        condition = " OR ".join(checks)
        for action in ("insert", "update"):
            statements.append(
                f"CREATE TRIGGER {_q(f'retired_traffic_link_{table}_{action}')} "
                f"BEFORE {action.upper()} ON {_q(table)} "
                "WHEN EXISTS (SELECT 1 FROM traffic_payload_retirements LIMIT 1) "
                f"AND ({condition}) "
                "BEGIN SELECT RAISE(ABORT, 'retired TrafficStore payload cannot be linked'); END;"
            )
    return "\n".join(statements)


def _traffic_id_predicate(alias: str = "item") -> str:
    value = f"{alias}.value"
    shapes = (("EXCHANGE-", 41), ("REQUEST-", 40), ("RESPONSE-", 41))
    return (f"{alias}.type='text' AND (" + " OR ".join(
        f"(length({value})={length} AND substr({value},1,{len(prefix)})="
        f"{_literal(prefix)} AND substr({value},{len(prefix) + 1}) "
        "NOT GLOB '*[^0-9a-f]*')"
        for prefix, length in shapes
    ) + ")")


def _add_json_refs(value: str) -> str:
    return (
        "INSERT INTO traffic_json_reference_counts(ref_id,ref_count) "
        f"SELECT item.value,count(*) FROM json_tree({value}) AS item "
        f"WHERE {_traffic_id_predicate()} GROUP BY item.value "
        "ON CONFLICT(ref_id) DO UPDATE SET ref_count=ref_count+excluded.ref_count;"
    )


def _remove_json_refs(value: str) -> str:
    grouped = (f"SELECT item.value AS ref_id,count(*) AS n "
               f"FROM json_tree({value}) AS item WHERE {_traffic_id_predicate()} "
               "GROUP BY item.value")
    return (
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM (" + grouped + ") AS old_refs "
        "LEFT JOIN traffic_json_reference_counts AS counts "
        "ON counts.ref_id=old_refs.ref_id WHERE counts.ref_count IS NULL "
        "OR counts.ref_count<old_refs.n) THEN "
        "RAISE(ABORT,'traffic JSON reference index is inconsistent') END;"
        "UPDATE traffic_json_reference_counts "
        "SET ref_count=traffic_json_reference_counts.ref_count-old_refs.n "
        f"FROM ({grouped}) AS old_refs WHERE "
        "traffic_json_reference_counts.ref_id=old_refs.ref_id;"
        "DELETE FROM traffic_json_reference_counts WHERE ref_count=0;"
    )


def traffic_json_index_sql(db: sqlite3.Connection) -> str:
    """Backfill and maintain exact JSON traffic-ID references in schema 43."""
    columns = json_reference_columns(db)
    for table, name in columns:
        if db.execute(
            f"SELECT 1 FROM {_q(table)} WHERE {_q(name)} IS NOT NULL "
            f"AND json_valid({_q(name)})=0 LIMIT 1"
        ).fetchone():
            raise ValueError("Existing JSON reference column is invalid")
    statements = [
        "CREATE TABLE traffic_json_reference_counts (ref_id TEXT PRIMARY KEY, "
        "ref_count INTEGER NOT NULL CHECK(ref_count>=0));",
        "CREATE TABLE traffic_json_reference_sources (source_table TEXT NOT NULL, "
        "source_column TEXT NOT NULL, PRIMARY KEY(source_table,source_column));",
    ]
    by_table: dict[str, list[str]] = {}
    for table, name in columns:
        by_table.setdefault(table, []).append(name)
        statements.append(
            "INSERT INTO traffic_json_reference_sources VALUES "
            f"({_literal(table)},{_literal(name)});"
        )
        statements.append(
            "INSERT INTO traffic_json_reference_counts(ref_id,ref_count) "
            f"SELECT item.value,count(*) FROM {_q(table)} AS owner, "
            f"json_tree(owner.{_q(name)}) AS item "
            f"WHERE {_traffic_id_predicate()} GROUP BY item.value "
            "ON CONFLICT(ref_id) DO UPDATE SET ref_count=ref_count+excluded.ref_count;"
        )
    for table, names in by_table.items():
        quoted = _q(table)
        checks = "".join(
            f"SELECT CASE WHEN NEW.{_q(name)} IS NOT NULL AND "
            f"json_valid(NEW.{_q(name)})=0 THEN "
            "RAISE(ABORT,'invalid JSON reference column') END;"
            for name in names
        )
        new_document = json_array_expression(tuple(f"json(NEW.{_q(name)})" for name in names))
        old_document = json_array_expression(tuple(f"json(OLD.{_q(name)})" for name in names))
        added = _add_json_refs(new_document)
        removed = _remove_json_refs(old_document)
        for action, body, columns_clause in (
            ("insert", checks + added, ""),
            ("update", checks + removed + added,
             " OF " + ",".join(_q(name) for name in names)),
            ("delete", removed, ""),
        ):
            statements.append(
                f"CREATE TRIGGER {_q(f'traffic_json_ref_{table}_{action}')} "
                f"AFTER {action.upper()}{columns_clause} ON {quoted} "
                f"BEGIN {body} END;"
            )
    return "\n".join(statements)


def verify_traffic_json_index(db: sqlite3.Connection) -> None:
    if db.execute("PRAGMA user_version").fetchone()[0] < 43:
        raise ValueError("Traffic JSON reference index requires schema 43")
    tables = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    if not {"traffic_json_reference_counts", "traffic_json_reference_sources"} <= tables:
        raise ValueError("Traffic JSON reference index is missing")
    expected = set(json_reference_columns(db))
    actual = {tuple(row) for row in db.execute(
        "SELECT source_table,source_column FROM traffic_json_reference_sources"
    )}
    triggers = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' "
        "AND name LIKE 'traffic_json_ref_%'"
    )}
    expected_triggers = {f"traffic_json_ref_{table}_{action}"
                         for table, _ in expected
                         for action in ("insert", "update", "delete")}
    if actual != expected or not expected_triggers <= triggers:
        raise ValueError("Traffic JSON reference index is incomplete")


def verify_traffic_retirement_guards(db: sqlite3.Connection) -> None:
    if db.execute("PRAGMA user_version").fetchone()[0] < 42:
        raise ValueError("Traffic retirement requires schema 42 guards")
    expected = {
        f"retired_traffic_link_{table}_{action}"
        for table in _fields(db)
        for action in ("insert", "update")
    } | {
        "traffic_payload_retirement_guard",
        "traffic_payload_retirement_no_update",
        "traffic_payload_retirement_no_delete",
    }
    found = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' "
        "AND (name LIKE 'retired_traffic_link_%' "
        "OR name LIKE 'traffic_payload_retirement_%')"
    )}
    if not expected <= found:
        raise ValueError("Traffic retirement link guards are incomplete")
