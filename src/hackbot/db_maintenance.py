"""Read-only SQLite integrity inspection for operator maintenance."""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from urllib.parse import quote


class DatabaseCheckError(RuntimeError):
    pass


_CORE_TABLES = frozenset({"evidence", "traffic_exchanges", "findings", "report_drafts",
                          "planner_runs"})


@dataclass(frozen=True, slots=True)
class DatabaseCheck:
    state: str
    schema_actual: int
    schema_expected: int
    integrity_ok: bool
    foreign_keys_ok: bool
    journal_mode: str
    database_bytes: int
    wal_bytes: int
    free_pages: int
    missing_core_tables: int

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "schema_actual": self.schema_actual,
            "schema_expected": self.schema_expected,
            "integrity_ok": self.integrity_ok,
            "foreign_keys_ok": self.foreign_keys_ok,
            "journal_mode": self.journal_mode,
            "database_bytes": self.database_bytes,
            "wal_bytes": self.wal_bytes,
            "free_pages": self.free_pages,
            "missing_core_tables": self.missing_core_tables,
        }


def check_database(path: Path, *, expected_schema: int,
                   required_tables: frozenset[str] = _CORE_TABLES) -> DatabaseCheck:
    """Inspect a consistent read snapshot; never initialize or optimize the DB."""
    if path.is_symlink() or not path.is_file():
        raise DatabaseCheckError("DATABASE_UNAVAILABLE")
    wal = path.with_name(path.name + "-wal")
    if wal.is_symlink():
        raise DatabaseCheckError("UNSAFE_WAL_PATH")
    try:
        uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
            connection.execute("PRAGMA query_only=ON")
            schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
            journal = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).upper()
            integrity_ok = connection.execute("PRAGMA integrity_check(1)").fetchone()[0] == "ok"
            foreign_keys_ok = connection.execute("PRAGMA foreign_key_check").fetchone() is None
            free_pages = int(connection.execute("PRAGMA freelist_count").fetchone()[0])
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            missing_tables = len(required_tables - tables)
        state = ("OK" if integrity_ok and foreign_keys_ok and schema == expected_schema
                 and not missing_tables else
                 "FAILED" if not integrity_ok or not foreign_keys_ok else
                 "SCHEMA_MISMATCH" if schema != expected_schema else "SCHEMA_INCOMPLETE")
        return DatabaseCheck(state, schema, expected_schema, integrity_ok, foreign_keys_ok,
                             journal, path.stat().st_size,
                             wal.stat().st_size if wal.is_file() else 0, free_pages,
                             missing_tables)
    except (OSError, sqlite3.Error, TypeError, ValueError):
        raise DatabaseCheckError("DATABASE_CHECK_FAILED") from None
