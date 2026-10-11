from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
from io import StringIO
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from hackbot.artifacts import ArtifactIntegrityError, ArtifactStore
from hackbot.config import StoreSettings, load_config
from hackbot.evidence import (
    ContentKind, EvidenceProvenance, EvidenceType, FactStatus, Retention, Sensitivity,
)
from hackbot.logging import create_logger
from hackbot.recon import Provenance
from hackbot.store import EvidenceFactStore, StoreNotInitialized, StoreSchemaError


NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_path = root / "state" / "bughunter.sqlite3"
        self.blobs = root / "blobs"
        settings = StoreSettings(self.blobs, max_inline_bytes=8, max_page_size=2)
        self.store = EvidenceFactStore(self.db_path, ArtifactStore(self.blobs), settings)
        self.provenance = EvidenceProvenance("FIXTURE", "test_case", "42", NOW, "observed")

    def tearDown(self):
        self.temp.cleanup()

    def _evidence(self, content=b"sample", **kwargs):
        return self.store.create_evidence(
            EvidenceType.RECON_RECORD, content, source="FIXTURE",
            provenance=self.provenance, target_ref="example.com", **kwargs,
        )

    def _fact(self, evidence_id, **kwargs):
        return self.store.create_fact(
            "endpoint:X", "accepts_parameter", "workspaceId",
            confidence=0.8, evidence_ids=(evidence_id,), source="RULE",
            target_ref="example.com", **kwargs,
        )

    def test_initialization_is_explicit_and_reopen_is_idempotent(self):
        self.assertFalse(self.db_path.exists())
        with self.assertRaises(StoreNotInitialized):
            self.store.list_evidence()
        self.assertFalse(self.db_path.exists())
        self.store.initialize()
        with sqlite3.connect(self.db_path) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            schema = connection.execute(
                "SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type,name"
            ).fetchall()
            self.assertEqual(version, 10)
        self.assertEqual(os.stat(self.db_path).st_mode & 0o777, 0o600)
        self.store.initialize()
        reopened = EvidenceFactStore(self.db_path, ArtifactStore(self.blobs), self.store.settings)
        reopened.initialize()
        with sqlite3.connect(self.db_path) as connection:
            self.assertEqual(schema, connection.execute(
                "SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type,name"
            ).fetchall())
        self.assertEqual(reopened.list_evidence().items, ())

    def test_future_schema_is_rejected_without_mutation(self):
        self.store.initialize()
        with sqlite3.connect(self.db_path) as connection:
            connection.execute("PRAGMA user_version=999")
        with self.assertRaises(StoreSchemaError):
            self.store.initialize()

    def test_evidence_id_hash_provenance_and_reference(self):
        self.store.initialize()
        record = self._evidence(content=b"sample")
        self.assertRegex(record.evidence_id, r"^EV-[0-9a-f]{32}$")
        self.assertEqual(record.content_hash, hashlib.sha256(b"sample").hexdigest())
        self.assertEqual(record.content_kind, ContentKind.INLINE)
        self.assertEqual(record.provenance.record_id, "42")
        self.assertEqual(self.store.read_content(record.evidence_id), b"sample")
        self.assertNotIn("sample", repr(record))
        self.assertNotIn("sample", str(record.to_reference()))
        self.assertEqual(self.store.get_evidence(record.evidence_id), record)

    def test_recon_provenance_compatibility_without_ingestion(self):
        observed = datetime(2026, 10, 8, 12, 0)
        recon = Provenance("endpoints", 123, observed, "latest_recon_row")
        mapped = EvidenceProvenance.from_recon(recon)
        self.assertEqual((mapped.system, mapped.entity, mapped.record_id),
                         ("RECON", "endpoints", "123"))
        self.assertEqual(mapped.observed_at, observed)
        self.assertEqual(mapped.qualification, "latest_recon_row")

    def test_artifact_deduplication_and_content_hash(self):
        self.store.initialize()
        first = self._evidence(content=b"this is larger than eight bytes")
        second = self._evidence(content=b"this is larger than eight bytes")
        self.assertNotEqual(first.evidence_id, second.evidence_id)
        self.assertEqual(first.content_hash, second.content_hash)
        self.assertEqual(first.content_kind, ContentKind.ARTIFACT)
        self.assertEqual(first.artifact_hash, second.artifact_hash)
        self.assertEqual(len(list(self.blobs.rglob(first.content_hash))), 1)
        self.assertEqual(self.store.read_content(second.evidence_id), b"this is larger than eight bytes")
        with sqlite3.connect(self.db_path) as connection:
            rows = connection.execute(
                "SELECT inline_content FROM evidence ORDER BY evidence_id LIMIT 2"
            ).fetchall()
        self.assertEqual(rows, [(None,), (None,)])

    def test_artifact_path_and_link_safety(self):
        artifacts = ArtifactStore(self.blobs)
        for invalid in ("../etc/passwd", "f" * 63, "F" * 64, "f" * 64 + "/x"):
            with self.assertRaises(ValueError):
                artifacts.path_for(invalid)
        digest = hashlib.sha256(b"sensitive").hexdigest()
        path = artifacts.path_for(digest)
        path.parent.mkdir(parents=True)
        outside = Path(self.temp.name) / "outside"
        outside.write_bytes(b"sensitive")
        path.symlink_to(outside)
        with self.assertRaises(ArtifactIntegrityError):
            artifacts.put_bytes(b"sensitive")
        with self.assertRaises(ArtifactIntegrityError):
            artifacts.get_bytes(digest)
        self.assertEqual(outside.read_bytes(), b"sensitive")

    def test_corrupt_artifact_is_not_returned(self):
        self.store.initialize()
        record = self._evidence(content=b"this body belongs in the artifact store")
        self.blobs.joinpath("sha256", record.content_hash[:2], record.content_hash).write_bytes(b"tampered")
        with self.assertRaises(ArtifactIntegrityError):
            self.store.read_content(record.evidence_id)

    def test_local_store_needs_no_recon_connection(self):
        root = Path(self.temp.name) / "isolated"
        config = load_config(environ={
            "HOME": self.temp.name,
            "HACKBOT_HOME": str(root),
            "HACKBOT_RECON_DSN": "invalid://not-a-database",
        })
        local = EvidenceFactStore.from_config(config)
        local.initialize()
        self.assertEqual(local.list_evidence().items, ())
        self.assertTrue((root / "state" / "bughunter.sqlite3").is_file())

    def test_evidence_is_immutable_in_model_and_sqlite(self):
        self.store.initialize()
        record = self._evidence(metadata={"nested": {"tags": ["one"]}})
        with self.assertRaises(FrozenInstanceError):
            record.content_hash = "changed"
        with self.assertRaises(TypeError):
            record.metadata["nested"]["tags"] = ("two",)
        with sqlite3.connect(self.db_path) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE evidence SET source='OTHER' WHERE evidence_id=?", (record.evidence_id,))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM evidence WHERE evidence_id=?", (record.evidence_id,))
        self.assertIsNotNone(self.store.get_evidence(record.evidence_id))

    def test_correction_creates_new_record_and_retention_is_event_based(self):
        self.store.initialize()
        old = self._evidence()
        new = self._evidence(content=b"fixed", replaces_evidence_id=old.evidence_id)
        self.assertEqual(new.replaces_evidence_id, old.evidence_id)
        updated = self.store.set_retention(
            old.evidence_id,
            Retention(retain=True, pinned=True, finding_related=True,
                      expires_at=NOW + timedelta(days=30)),
            actor="MANUAL", reason="report evidence",
        )
        self.assertTrue(updated.retention.pinned)
        self.assertTrue(updated.retention.finding_related)
        self.assertEqual(self.store.get_evidence(old.evidence_id).content_hash, old.content_hash)
        with sqlite3.connect(self.db_path) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM evidence_policy_events WHERE evidence_id=?", (old.evidence_id,)
            ).fetchone()[0]
        self.assertEqual(count, 2)
        with self.assertRaises(ValueError):
            self.store.set_retention(old.evidence_id, Retention(retain=False, pinned=True),
                                     actor="MANUAL", reason="invalid")

    def test_secret_content_and_metadata_never_enter_log_reference(self):
        self.store.initialize()
        secret = self._evidence(
            content=b"password=PRIVATE_VALUE", metadata={"Authorization": "Bearer PRIVATE_VALUE"},
            sensitivity=Sensitivity.SECRET,
        )
        self.assertEqual(secret.content_kind, ContentKind.ARTIFACT)
        with self.assertRaises(PermissionError):
            self.store.read_content(secret.evidence_id)
        self.assertEqual(
            self.store.read_content(secret.evidence_id, allow_sensitive=True),
            b"password=PRIVATE_VALUE",
        )
        stream = StringIO()
        logger = create_logger(stream=stream, environ={})
        logger.info("evidence saved", extra={"context": secret.to_reference()})
        self.assertNotIn("PRIVATE_VALUE", stream.getvalue())
        self.assertNotIn("PRIVATE_VALUE", repr(secret))
        self.assertNotIn("PRIVATE_VALUE", str(secret.to_reference()))
        with self.assertRaises(ValueError):
            self._evidence(metadata={"api_key": "PRIVATE_VALUE"})

    def test_sensitive_reference_omits_target_source_and_provenance(self):
        self.store.initialize()
        record = self.store.create_evidence(
            EvidenceType.MANUAL_NOTE, b"PRIVATE_VALUE", source="PRIVATE_VALUE",
            provenance=EvidenceProvenance("FIXTURE", "PRIVATE_VALUE", "PRIVATE_VALUE"),
            target_ref="PRIVATE_VALUE", sensitivity=Sensitivity.SECRET,
        )
        stream = StringIO()
        create_logger(stream=stream, environ={}).info(
            "record", extra={"context": record.to_reference()}
        )
        self.assertNotIn("PRIVATE_VALUE", repr(record))
        self.assertNotIn("PRIVATE_VALUE", str(record.to_reference()))
        self.assertNotIn("PRIVATE_VALUE", stream.getvalue())
        self.assertEqual(self.store.get_evidence(record.evidence_id).provenance.record_id,
                         "PRIVATE_VALUE")

    def test_evidence_lookup_and_pages_are_bounded_and_scoped(self):
        self.store.initialize()
        records = [self._evidence(content=f"note-{i}".encode()) for i in range(5)]
        first = self.store.list_evidence_for_target("example.com", limit=100)
        self.assertEqual(len(first.items), 2)
        self.assertIsNotNone(first.next_cursor)
        second = self.store.list_evidence_for_target("example.com", limit=2, cursor=first.next_cursor)
        self.assertEqual(len(second.items), 2)
        self.assertFalse({item.evidence_id for item in first.items} &
                         {item.evidence_id for item in second.items})
        with self.assertRaises(ValueError):
            self.store.list_evidence_for_target("other.com", cursor=first.next_cursor)
        with self.assertRaises(ValueError):
            self.store.list_evidence(limit=0)
        self.assertEqual(len(records), 5)

    def test_fact_id_confidence_evidence_and_lookup(self):
        self.store.initialize()
        evidence = self._evidence()
        fact = self._fact(evidence.evidence_id)
        self.assertRegex(fact.fact_id, r"^FA-[0-9a-f]{32}$")
        self.assertEqual(fact.evidence_ids, (evidence.evidence_id,))
        self.assertEqual(fact.confidence, 0.8)
        self.assertEqual(fact.status, FactStatus.ACTIVE)
        self.assertEqual(self.store.get_fact(fact.fact_id), fact)
        self.assertEqual(self.store.find_facts("endpoint:X", "accepts_parameter").items, (fact,))
        self.assertEqual(self.store.find_relationships("workspaceId").items, (fact,))
        with self.assertRaises(FrozenInstanceError):
            fact.confidence = 1.0

    def test_nonmanual_fact_requires_existing_evidence(self):
        self.store.initialize()
        with self.assertRaises(ValueError):
            self.store.create_fact("user:1", "has_role", "admin", confidence=0.9, source="MODEL")
        with self.assertRaises(ValueError):
            self.store.create_fact("user:1", "has_role", "admin", confidence=0.9,
                                   source="MODEL", evidence_ids=("EV-" + "a" * 32,))
        manual = self.store.create_fact("user:1", "has_role", "member",
                                        confidence=0.5, source="MANUAL")
        self.assertEqual(manual.evidence_ids, ())

    def test_confidence_validation(self):
        self.store.initialize()
        evidence = self._evidence()
        for value in (-0.1, 1.1, float("nan"), float("inf"), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.store.create_fact("user:1", "has_role", "admin", confidence=value,
                                       source="RULE", evidence_ids=(evidence.evidence_id,))

    def test_fact_sensitivity_inherits_supporting_evidence(self):
        self.store.initialize()
        evidence = self._evidence(content=b"token=PRIVATE_VALUE", sensitivity=Sensitivity.SECRET)
        fact = self.store.create_fact("user:1", "has_token", "PRIVATE_VALUE", confidence=1,
                                      evidence_ids=(evidence.evidence_id,), source="RULE")
        self.assertEqual(fact.sensitivity, Sensitivity.SECRET)
        self.assertNotIn("PRIVATE_VALUE", repr(fact))
        self.assertNotIn("PRIVATE_VALUE", str(fact.to_reference()))

    def test_contradiction_status_history_preserves_both_facts(self):
        self.store.initialize()
        first_evidence = self._evidence(content=b"role member")
        later_evidence = self._evidence(content=b"role admin")
        old = self.store.create_fact("user:123", "has_role", "member", confidence=1,
                                     evidence_ids=(first_evidence.evidence_id,), source="RULE",
                                     observed_at=NOW)
        new = self.store.create_fact("user:123", "has_role", "admin", confidence=1,
                                     evidence_ids=(later_evidence.evidence_id,), source="RULE",
                                     observed_at=NOW + timedelta(days=1))
        disputed = self.store.change_fact_status(
            old.fact_id, FactStatus.DISPUTED, producer="RULE", reason="later observation",
            supporting_evidence_id=later_evidence.evidence_id, related_fact_id=new.fact_id,
        )
        self.assertEqual(disputed.status, FactStatus.DISPUTED)
        self.assertEqual(self.store.get_fact(new.fact_id).status, FactStatus.ACTIVE)
        superseded = self.store.change_fact_status(
            old.fact_id, FactStatus.SUPERSEDED, producer="RULE", reason="replacement",
            supporting_evidence_id=later_evidence.evidence_id, related_fact_id=new.fact_id,
        )
        self.assertEqual(superseded.status, FactStatus.SUPERSEDED)
        history = self.store.list_fact_status_history(old.fact_id)
        older = self.store.list_fact_status_history(old.fact_id, before_event_id=history[-1].event_id)
        self.assertEqual([entry.status for entry in (*history, *older)],
                         [FactStatus.SUPERSEDED, FactStatus.DISPUTED, FactStatus.ACTIVE])
        self.assertEqual(history[0].related_fact_id, new.fact_id)
        self.assertEqual(old.object, "member")
        self.assertEqual(self.store.get_fact(old.fact_id).object, "member")

    def test_fact_queries_page_by_subject_predicate_and_object(self):
        self.store.initialize()
        evidence = self._evidence()
        for index in range(5):
            self.store.create_fact("endpoint:X", "references", f"asset:{index}",
                                   confidence=0.7, evidence_ids=(evidence.evidence_id,), source="RULE")
        first = self.store.list_facts_for_subject("endpoint:X", limit=100)
        self.assertEqual(len(first.items), 2)
        second = self.store.list_facts_for_subject("endpoint:X", limit=2, cursor=first.next_cursor)
        self.assertEqual(len(second.items), 2)
        self.assertFalse({fact.fact_id for fact in first.items} &
                         {fact.fact_id for fact in second.items})
        self.assertEqual(len(self.store.find_facts("endpoint:X", "references").items), 2)
        self.assertEqual(len(self.store.find_relationships("asset:3", predicate="references").items), 1)
        with self.assertRaises(ValueError):
            self.store.find_relationships("asset:3", cursor=first.next_cursor)

    def test_fact_base_and_links_are_immutable_in_sqlite(self):
        self.store.initialize()
        evidence = self._evidence()
        fact = self._fact(evidence.evidence_id)
        with sqlite3.connect(self.db_path) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE facts SET confidence=1 WHERE fact_id=?", (fact.fact_id,))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM fact_evidence WHERE fact_id=?", (fact.fact_id,))
        self.assertEqual(self.store.get_fact(fact.fact_id).confidence, 0.8)


if __name__ == "__main__":
    unittest.main()
