import hashlib
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from hackbot.db_maintenance import DatabaseCheckError, check_database


class DatabaseMaintenanceTests(unittest.TestCase):
    def _database(self, directory: str, *, bad_reference: bool = False) -> Path:
        path = Path(directory) / "state.sqlite3"
        with sqlite3.connect(path) as db:
            db.executescript("""
                PRAGMA user_version=7;
                CREATE TABLE parent (id INTEGER PRIMARY KEY);
                CREATE TABLE child (id INTEGER PRIMARY KEY,
                                    parent_id INTEGER REFERENCES parent(id));
            """)
            if bad_reference:
                db.execute("INSERT INTO child (parent_id) VALUES (123)")
        return path

    def test_read_only_integrity_and_journal_status(self) -> None:
        with TemporaryDirectory() as directory:
            path = self._database(directory)
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            result = check_database(path, expected_schema=7,
                                    required_tables=frozenset({"parent", "child"}))
            self.assertEqual(result.state, "OK")
            self.assertTrue(result.integrity_ok)
            self.assertTrue(result.foreign_keys_ok)
            self.assertEqual(result.journal_mode, "DELETE")
            self.assertEqual(result.missing_core_tables, 0)
            self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_foreign_key_violation_and_schema_mismatch(self) -> None:
        with TemporaryDirectory() as directory:
            path = self._database(directory, bad_reference=True)
            result = check_database(path, expected_schema=7,
                                    required_tables=frozenset({"parent", "child"}))
            self.assertEqual(result.state, "FAILED")
            self.assertFalse(result.foreign_keys_ok)
            with sqlite3.connect(path) as db:
                db.execute("DELETE FROM child")
            result = check_database(path, expected_schema=8,
                                    required_tables=frozenset({"parent", "child"}))
            self.assertEqual(result.state, "SCHEMA_MISMATCH")

    def test_incomplete_and_unsafe_database(self) -> None:
        with TemporaryDirectory() as directory:
            path = self._database(directory)
            result = check_database(path, expected_schema=7)
            self.assertEqual(result.state, "SCHEMA_INCOMPLETE")
            self.assertEqual(result.missing_core_tables, 5)
            missing = Path(directory) / "missing.sqlite3"
            with self.assertRaises(DatabaseCheckError):
                check_database(missing, expected_schema=7)
            link = Path(directory) / "linked.sqlite3"
            link.symlink_to(path)
            with self.assertRaises(DatabaseCheckError):
                check_database(link, expected_schema=7)

    def test_corrupt_database_does_not_echo_contents(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "corrupt.sqlite3"
            path.write_bytes(b"not sqlite: secret-token-value")
            with self.assertRaisesRegex(DatabaseCheckError, "DATABASE_CHECK_FAILED") as raised:
                check_database(path, expected_schema=7)
            self.assertNotIn("secret-token-value", str(raised.exception))
