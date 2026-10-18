"""The finding hold is enforced by SQLite, including on schema upgrade."""

from importlib.resources import files
import sqlite3
import unittest


class FindingEvidenceHoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE finding_evidence(finding_id TEXT, evidence_id TEXT);
            CREATE TABLE evidence_policy_events(
                event_id INTEGER PRIMARY KEY, evidence_id TEXT, retain INTEGER,
                expires_at TEXT, pinned INTEGER, finding_related INTEGER,
                changed_at TEXT, actor TEXT, reason TEXT
            );
            INSERT INTO finding_evidence VALUES ('FINDING-old','EV-old');
            INSERT INTO evidence_policy_events
                (evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason)
            VALUES ('EV-old',0,'2020-01-01T00:00:00+00:00',0,0,
                    '2020-01-01T00:00:00+00:00','FIXTURE','old_policy');
        """)
        migration = files("hackbot").joinpath(
            "migrations", "038_finding_evidence_hold.sql").read_text()
        self.db.executescript(migration)

    def latest(self, evidence_id: str) -> tuple[int, str | None, int, int]:
        row = self.db.execute(
            "SELECT retain,expires_at,pinned,finding_related "
            "FROM evidence_policy_events WHERE evidence_id=? ORDER BY event_id DESC LIMIT 1",
            (evidence_id,)).fetchone()
        assert row is not None
        return row

    def test_upgrade_pins_preexisting_finding_evidence(self) -> None:
        self.assertEqual(self.latest("EV-old"), (1, None, 1, 1))

    def test_new_finding_link_pins_evidence_and_direct_unpin_fails(self) -> None:
        self.db.execute("INSERT INTO finding_evidence VALUES ('FINDING-new','EV-new')")
        self.assertEqual(self.latest("EV-new"), (1, None, 1, 1))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("""
                INSERT INTO evidence_policy_events
                    (evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason)
                VALUES ('EV-new',0,NULL,0,0,'2020-01-01','FIXTURE','release')
            """)
        self.assertEqual(self.latest("EV-new"), (1, None, 1, 1))


class FindingValidationEvidenceHoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY);
            CREATE TABLE finding_evidence(finding_id TEXT, evidence_id TEXT);
            CREATE TABLE evidence_policy_events(
                event_id INTEGER PRIMARY KEY, evidence_id TEXT REFERENCES evidence(evidence_id),
                retain INTEGER, expires_at TEXT, pinned INTEGER, finding_related INTEGER,
                changed_at TEXT, actor TEXT, reason TEXT
            );
            CREATE TABLE validations(
                validation_id TEXT PRIMARY KEY, supporting_evidence_json TEXT,
                contradicting_evidence_json TEXT
            );
            CREATE TABLE validation_checks(validation_id TEXT, evidence_ids_json TEXT);
            CREATE TABLE findings(finding_id TEXT, validation_id TEXT);
            CREATE TABLE finding_locations(finding_id TEXT, validation_id TEXT);
            CREATE TABLE finding_duplicates(finding_id TEXT, validation_id TEXT);
            INSERT INTO evidence VALUES ('EV-old-support'), ('EV-old-contradict'),
                ('EV-old-check'), ('EV-new'), ('EV-location'), ('EV-duplicate'),
                ('EV-late');
            INSERT INTO validations VALUES
                ('V-old','["EV-old-support"]','["EV-old-contradict"]');
            INSERT INTO validation_checks VALUES ('V-old','["EV-old-check"]');
            INSERT INTO findings VALUES ('F-old','V-old');
            INSERT INTO evidence_policy_events
                (evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason)
            VALUES ('EV-old-check',1,NULL,1,0,'2020-01-01','FIXTURE','old_policy');
        """)
        for name in ("038_finding_evidence_hold.sql",
                     "040_finding_validation_evidence_hold.sql"):
            self.db.executescript(files("hackbot").joinpath("migrations", name).read_text())

    def latest(self, evidence_id: str) -> tuple[int, str | None, int, int]:
        row = self.db.execute(
            "SELECT retain,expires_at,pinned,finding_related FROM evidence_policy_events "
            "WHERE evidence_id=? ORDER BY event_id DESC LIMIT 1", (evidence_id,),
        ).fetchone()
        assert row is not None
        return row

    def test_upgrade_pins_supporting_contradictory_and_check_only_evidence(self) -> None:
        for evidence_id in ("EV-old-support", "EV-old-contradict", "EV-old-check"):
            self.assertEqual(self.latest(evidence_id), (1, None, 1, 1))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO evidence_policy_events "
                            "(evidence_id,retain,pinned,finding_related,changed_at,actor,reason) "
                            "VALUES ('EV-old-check',0,0,0,'2026-01-01','FIXTURE','release')")

    def test_new_primary_location_and_duplicate_links_pin_validation_evidence(self) -> None:
        self.db.execute("INSERT INTO validations VALUES ('V-new','[\"EV-new\"]','[]')")
        self.db.execute("INSERT INTO findings VALUES ('F-new','V-new')")
        self.db.execute("INSERT INTO validations VALUES ('V-location','[]','[\"EV-location\"]')")
        self.db.execute("INSERT INTO finding_locations VALUES ('F-old','V-location')")
        self.db.execute("INSERT INTO validations VALUES ('V-duplicate','[\"EV-duplicate\"]','[]')")
        self.db.execute("INSERT INTO finding_duplicates VALUES ('F-old','V-duplicate')")
        for evidence_id in ("EV-new", "EV-location", "EV-duplicate"):
            self.assertEqual(self.latest(evidence_id), (1, None, 1, 1))

    def test_late_check_is_pinned_and_hold_cannot_be_deleted(self) -> None:
        self.db.execute("INSERT INTO validation_checks VALUES ('V-old','[\"EV-late\"]')")
        self.assertEqual(self.latest("EV-late"), (1, None, 1, 1))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM finding_validation_evidence_holds "
                            "WHERE evidence_id='EV-late'")

    def test_malformed_validation_reference_cannot_create_finding(self) -> None:
        self.db.execute("INSERT INTO evidence VALUES ('123')")
        for index, refs in enumerate(('[null]', '{}', '"EV-old-support"', '[123]')):
            with self.subTest(refs=refs):
                validation_id = f"V-bad-{index}"
                finding_id = f"F-bad-{index}"
                self.db.execute(
                    "INSERT INTO validations VALUES (?,?,'[]')", (validation_id, refs),
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    self.db.execute(
                        "INSERT INTO findings VALUES (?,?)", (finding_id, validation_id),
                    )
                self.assertIsNone(self.db.execute(
                    "SELECT 1 FROM findings WHERE finding_id=?", (finding_id,),
                ).fetchone())


class FindingValidationMigrationFailureTests(unittest.TestCase):
    def test_bad_historical_reference_rolls_back_schema_upgrade(self) -> None:
        for historical_ref in ('[null]', '["EV-missing"]', 'not-json',
                               '{}', '"EV-preserved"', '[123]'):
            with self.subTest(historical_ref=historical_ref):
                db = sqlite3.connect(":memory:")
                self.addCleanup(db.close)
                db.execute("PRAGMA foreign_keys=ON")
                db.executescript("""
                    CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY);
                    CREATE TABLE evidence_policy_events(
                        event_id INTEGER PRIMARY KEY,
                        evidence_id TEXT REFERENCES evidence(evidence_id),
                        retain INTEGER, expires_at TEXT, pinned INTEGER,
                        finding_related INTEGER, changed_at TEXT, actor TEXT,
                        reason TEXT
                    );
                    CREATE TABLE validations(
                        validation_id TEXT PRIMARY KEY,
                        supporting_evidence_json TEXT,
                        contradicting_evidence_json TEXT
                    );
                    CREATE TABLE validation_checks(validation_id TEXT, evidence_ids_json TEXT);
                    CREATE TABLE findings(finding_id TEXT, validation_id TEXT);
                    CREATE TABLE finding_locations(finding_id TEXT, validation_id TEXT);
                    CREATE TABLE finding_duplicates(finding_id TEXT, validation_id TEXT);
                    INSERT INTO evidence VALUES ('EV-preserved');
                    INSERT INTO evidence VALUES ('123');
                    PRAGMA user_version=39;
                """)
                db.execute(
                    "INSERT INTO validations VALUES ('V-old',?, '[]')",
                    (historical_ref,),
                )
                db.execute("INSERT INTO findings VALUES ('F-old','V-old')")
                db.commit()

                migration = files("hackbot").joinpath(
                    "migrations", "040_finding_validation_evidence_hold.sql",
                ).read_text()
                with self.assertRaises(sqlite3.Error):
                    db.executescript(
                        "BEGIN IMMEDIATE;\n" + migration
                        + "\nPRAGMA user_version=40;\nCOMMIT;"
                    )
                db.rollback()

                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 39)
                self.assertIsNone(db.execute(
                    "SELECT name FROM sqlite_master WHERE name='finding_validation_evidence_holds'",
                ).fetchone())
                self.assertEqual(db.execute(
                    "SELECT evidence_id FROM evidence",
                ).fetchall(), [("EV-preserved",), ("123",)])
                self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_unlinked_malformed_validation_does_not_block_upgrade(self) -> None:
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript("""
            CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY);
            CREATE TABLE evidence_policy_events(
                event_id INTEGER PRIMARY KEY,
                evidence_id TEXT REFERENCES evidence(evidence_id),
                retain INTEGER, expires_at TEXT, pinned INTEGER,
                finding_related INTEGER, changed_at TEXT, actor TEXT, reason TEXT
            );
            CREATE TABLE validations(
                validation_id TEXT PRIMARY KEY,
                supporting_evidence_json TEXT,
                contradicting_evidence_json TEXT
            );
            CREATE TABLE validation_checks(validation_id TEXT, evidence_ids_json TEXT);
            CREATE TABLE findings(finding_id TEXT, validation_id TEXT);
            CREATE TABLE finding_locations(finding_id TEXT, validation_id TEXT);
            CREATE TABLE finding_duplicates(finding_id TEXT, validation_id TEXT);
            INSERT INTO evidence VALUES ('EV-good');
            INSERT INTO validations VALUES ('V-good','["EV-good"]','[]');
            INSERT INTO findings VALUES ('F-good','V-good');
            INSERT INTO validations VALUES ('V-unlinked','not-json','{}');
            PRAGMA user_version=39;
        """)
        migration = files("hackbot").joinpath(
            "migrations", "040_finding_validation_evidence_hold.sql",
        ).read_text()
        db.executescript(
            "BEGIN IMMEDIATE;\n" + migration + "\nPRAGMA user_version=40;\nCOMMIT;"
        )
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 40)
        self.assertEqual(db.execute(
            "SELECT evidence_id FROM finding_validation_evidence_holds",
        ).fetchall(), [("EV-good",)])


if __name__ == "__main__":
    unittest.main()
