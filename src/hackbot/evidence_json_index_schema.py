"""Schema-44 exact JSON Evidence-ID reference index."""

from __future__ import annotations

import sqlite3

from .json_reference_schema import (json_array_expression, json_reference_columns,
                                    quote_identifier, quote_literal)


_COUNTS = "evidence_json_reference_counts"
_SOURCES = "evidence_json_reference_sources"
_TRIGGER_PREFIX = "evidence_json_ref_"


def _predicate(alias: str = "item") -> str:
    value = f"{alias}.value"
    return (f"{alias}.type='text' AND length({value})=35 "
            f"AND substr({value},1,3)='EV-' "
            f"AND substr({value},4) NOT GLOB '*[^0-9a-f]*'")


def _add(value: str) -> str:
    return (
        f"INSERT INTO {_COUNTS}(ref_id,ref_count) "
        f"SELECT item.value,count(*) FROM json_tree({value}) AS item "
        f"WHERE {_predicate()} GROUP BY item.value "
        "ON CONFLICT(ref_id) DO UPDATE SET ref_count=ref_count+excluded.ref_count;"
    )


def _remove(value: str) -> str:
    grouped = ("SELECT item.value AS ref_id,count(*) AS n "
               f"FROM json_tree({value}) AS item WHERE {_predicate()} GROUP BY item.value")
    return (
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM (" + grouped + ") AS old_refs "
        f"LEFT JOIN {_COUNTS} AS counts ON counts.ref_id=old_refs.ref_id "
        "WHERE counts.ref_count IS NULL OR counts.ref_count<old_refs.n) THEN "
        "RAISE(ABORT,'Evidence JSON reference index is inconsistent') END;"
        f"UPDATE {_COUNTS} SET ref_count={_COUNTS}.ref_count-old_refs.n "
        f"FROM ({grouped}) AS old_refs WHERE {_COUNTS}.ref_id=old_refs.ref_id;"
        f"DELETE FROM {_COUNTS} WHERE ref_count=0;"
    )


def evidence_json_index_sql(db: sqlite3.Connection) -> str:
    """Backfill exact Evidence-ID counts and maintain them on later JSON writes."""
    columns = json_reference_columns(db)
    for table, name in columns:
        if db.execute(
            f"SELECT 1 FROM {quote_identifier(table)} "
            f"WHERE {quote_identifier(name)} IS NOT NULL "
            f"AND json_valid({quote_identifier(name)})=0 LIMIT 1"
        ).fetchone():
            raise ValueError("Existing JSON reference column is invalid")
    statements = [
        f"CREATE TABLE {_COUNTS} (ref_id TEXT PRIMARY KEY, "
        "ref_count INTEGER NOT NULL CHECK(ref_count>=0));",
        f"CREATE TABLE {_SOURCES} (source_table TEXT NOT NULL, "
        "source_column TEXT NOT NULL, PRIMARY KEY(source_table,source_column));",
    ]
    by_table: dict[str, list[str]] = {}
    for table, name in columns:
        by_table.setdefault(table, []).append(name)
        statements.append(
            f"INSERT INTO {_SOURCES} VALUES "
            f"({quote_literal(table)},{quote_literal(name)});"
        )
        statements.append(
            f"INSERT INTO {_COUNTS}(ref_id,ref_count) "
            f"SELECT item.value,count(*) FROM {quote_identifier(table)} AS owner, "
            f"json_tree(owner.{quote_identifier(name)}) AS item "
            f"WHERE {_predicate()} GROUP BY item.value "
            "ON CONFLICT(ref_id) DO UPDATE SET ref_count=ref_count+excluded.ref_count;"
        )
    for table, names in by_table.items():
        checks = "".join(
            f"SELECT CASE WHEN NEW.{quote_identifier(name)} IS NOT NULL "
            f"AND json_valid(NEW.{quote_identifier(name)})=0 THEN "
            "RAISE(ABORT,'invalid JSON reference column') END;"
            for name in names
        )
        new_document = json_array_expression(tuple(
            f"json(NEW.{quote_identifier(name)})" for name in names))
        old_document = json_array_expression(tuple(
            f"json(OLD.{quote_identifier(name)})" for name in names))
        added = _add(new_document)
        removed = _remove(old_document)
        for action, body, columns_clause in (
            ("insert", checks + added, ""),
            ("update", checks + removed + added,
             " OF " + ",".join(quote_identifier(name) for name in names)),
            ("delete", removed, ""),
        ):
            statements.append(
                f"CREATE TRIGGER {quote_identifier(f'{_TRIGGER_PREFIX}{table}_{action}')} "
                f"AFTER {action.upper()}{columns_clause} "
                f"ON {quote_identifier(table)} BEGIN {body} END;"
            )
    return "\n".join(statements)


def verify_evidence_json_index(db: sqlite3.Connection) -> None:
    if db.execute("PRAGMA user_version").fetchone()[0] < 44:
        raise ValueError("Evidence JSON reference index requires schema 44")
    tables = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    if not {_COUNTS, _SOURCES} <= tables:
        raise ValueError("Evidence JSON reference index is missing")
    expected = set(json_reference_columns(db))
    actual = {tuple(row) for row in db.execute(
        f"SELECT source_table,source_column FROM {_SOURCES}"
    )}
    triggers = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' "
        f"AND name LIKE '{_TRIGGER_PREFIX}%'"
    )}
    expected_triggers = {f"{_TRIGGER_PREFIX}{table}_{action}"
                         for table, _ in expected
                         for action in ("insert", "update", "delete")}
    if actual != expected or not expected_triggers <= triggers:
        raise ValueError("Evidence JSON reference index is incomplete")
