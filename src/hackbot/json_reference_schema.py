"""Inventory JSON columns that can contain persisted local reference IDs."""

from __future__ import annotations

import sqlite3


def quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def json_array_expression(values: tuple[str, ...]) -> str:
    """Build a JSON array without exceeding SQLite's function argument limit."""
    if not values:
        raise ValueError("JSON reference document needs a source column")
    parts = [f"json_array({','.join(values[index:index + 50])})"
             for index in range(0, len(values), 50)]
    while len(parts) > 1:
        parts = [f"json_array({','.join(parts[index:index + 50])})"
                 for index in range(0, len(parts), 50)]
    return parts[0]


def json_reference_columns(db: sqlite3.Connection) -> tuple[tuple[str, str], ...]:
    columns = []
    for (table,) in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ):
        for column in db.execute(f"PRAGMA table_xinfo({quote_identifier(table)})"):
            if column[1].endswith("_json"):
                columns.append((table, column[1]))
    return tuple(columns)
