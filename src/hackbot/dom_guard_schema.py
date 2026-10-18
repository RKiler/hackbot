"""Schema-derived guards against linking retired DOM asset generations."""

from __future__ import annotations

import sqlite3

from .json_reference_schema import json_array_expression


_SOURCE_TABLE = "dom_retirement_guard_sources"
_OWN_COLUMNS = frozenset({
    ("dom_js_artifacts", "artifact_id"),
    ("dom_source_maps", "map_id"),
})


def _q(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _sources(db: sqlite3.Connection) -> dict[str, tuple[str, ...]]:
    sources: dict[str, tuple[str, ...]] = {}
    for (table,) in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ):
        if table == _SOURCE_TABLE:
            continue
        names = tuple(
            row[1] for row in db.execute(f"PRAGMA table_xinfo({_q(table)})")
            if (table, row[1]) not in _OWN_COLUMNS
        )
        if names:
            sources[table] = names
    return sources


def _owner_match() -> str:
    clauses = []
    for table, owner_id in (
        ("dom_js_artifacts", "artifact_id"),
        ("dom_source_maps", "map_id"),
    ):
        clauses.append(
            f"EXISTS (SELECT 1 FROM {_q(table)} AS owner "
            "JOIN evidence_payload_retirements AS retired "
            "ON retired.evidence_id=owner.evidence_id "
            f"WHERE (item.type='text' AND instr(item.value,owner.{_q(owner_id)})>0) "
            f"OR (typeof(item.key)='text' AND instr(item.key,owner.{_q(owner_id)})>0))"
        )
    return " OR ".join(clauses)


def _column_value(name: str) -> str:
    value = f"NEW.{_q(name)}"
    if name.endswith("_json"):
        return f"json(CASE WHEN json_valid({value}) THEN {value} ELSE 'null' END)"
    return f"CASE WHEN typeof({value})='text' THEN {value} ELSE NULL END"


def _trigger(table: str, columns: tuple[str, ...], action: str) -> str:
    name = f"retired_dom_link_{table}_{action}"
    invalid_json = " OR ".join(
        f"(NEW.{_q(column)} IS NOT NULL AND json_valid(NEW.{_q(column)})=0)"
        for column in columns if column.endswith("_json")
    )
    values = tuple(_column_value(column) for column in columns)
    document = json_array_expression(values)
    suspect = (
        "(item.type='text' AND (instr(item.value,'DOMART-')>0 OR "
        "instr(item.value,'DOMMAP-')>0)) OR "
        "(typeof(item.key)='text' AND (instr(item.key,'DOMART-')>0 OR "
        "instr(item.key,'DOMMAP-')>0))"
    )
    owner_check = (
        f"EXISTS (SELECT 1 FROM json_tree({document}) AS item "
        f"WHERE ({suspect}) AND ({_owner_match()}))"
    )
    checks = f"({invalid_json}) OR {owner_check}" if invalid_json else owner_check
    return (
        f"CREATE TRIGGER {_q(name)} BEFORE {action.upper()} ON {_q(table)} "
        "WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements LIMIT 1) "
        f"AND ({checks}) BEGIN SELECT RAISE(ABORT, "
        "'retired DOM payload cannot be linked'); END;"
    )


def dom_guard_sql(db: sqlite3.Connection) -> str:
    """Generate source inventory and guards for the exact pre-migration schema."""
    sources = _sources(db)
    statements = [
        f"CREATE TABLE {_q(_SOURCE_TABLE)} ("
        "source_table TEXT NOT NULL, source_column TEXT NOT NULL, "
        "PRIMARY KEY(source_table,source_column));"
    ]
    for table, columns in sources.items():
        for column in columns:
            statements.append(
                f"INSERT INTO {_q(_SOURCE_TABLE)} VALUES "
                f"({_literal(table)},{_literal(column)});"
            )
        statements.extend(_trigger(table, columns, action)
                          for action in ("insert", "update"))
    return "\n".join(statements)


def verify_dom_retirement_guards(db: sqlite3.Connection) -> None:
    if db.execute("PRAGMA user_version").fetchone()[0] < 46:
        raise ValueError("DOM retirement requires schema 46 guards")
    tables = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    if _SOURCE_TABLE not in tables:
        raise ValueError("DOM retirement guard inventory is missing")
    sources = _sources(db)
    expected = {(table, column) for table, columns in sources.items()
                for column in columns}
    recorded = {tuple(row) for row in db.execute(
        f"SELECT source_table,source_column FROM {_q(_SOURCE_TABLE)}")}
    if recorded != expected:
        raise ValueError("DOM retirement guard inventory is incomplete")
    actual_triggers = {row[0]: row[1] for row in db.execute(
        "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
        "AND name LIKE 'retired_dom_link_%'")}
    required_triggers = {
        f"retired_dom_link_{table}_{action}": _trigger(table, columns, action)
        for table, columns in sources.items() for action in ("insert", "update")
    }
    if (set(actual_triggers) != set(required_triggers) or
            any(actual_triggers[name].strip().rstrip(";") != sql.rstrip(";")
                for name, sql in required_triggers.items())):
        raise ValueError("DOM retirement link guards are incomplete")
