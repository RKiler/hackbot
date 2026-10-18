from datetime import datetime, timezone
from dataclasses import replace
import base64
import fcntl
import hashlib
from io import StringIO
from importlib.resources import files
import json
import os
from pathlib import Path
import shutil
import sqlite3
from types import SimpleNamespace
from tempfile import TemporaryDirectory
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

from hackbot.artifacts import ArtifactStore
from hackbot.backup import BackupError, BackupManager
from hackbot.backup_crypto import BackupCryptoError
from hackbot.cli import main
from hackbot.config import AppConfig, BackupSettings, LocalPaths, ResourceSettings, StoreSettings
from hackbot.db_maintenance import DatabaseCheckError
from hackbot.dom_retention import DOMPayloadRetirementManager
from hackbot.domxss_store import DOMXSSStore
from hackbot.evidence import EvidenceProvenance, EvidenceType, Retention, Sensitivity
from hackbot.evidence_retention import EvidencePayloadRetirementManager
from hackbot.identity_registry import IdentityRegistry
from hackbot.store import EvidenceFactStore
from hackbot.secrets import SecretValue
from hackbot.planner_models import PlannerLimits, PlannerMode
from hackbot.planner_store import PlannerStore
from hackbot.validation_store import (CheckOutcome, FindingSpec, ValidationCheck,
                                      ValidationStatus)
from hackbot.target_loader import load_target_package
from tests.schema_utils import (drop_evidence_json_index_schema,
                                drop_dom_retirement_guards,
                                drop_research_retirement_schema,
                                drop_traffic_json_index_schema)
from tests import test_phase29 as phase29_fixture


class FixtureKeyProvider:
    def __init__(self, raw: bytes = b"a" * 32):
        self.value = SecretValue(base64.b64encode(raw).decode("ascii"))

    def get(self, _ref):
        return self.value


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.database = root / "state" / "bughunter.sqlite3"
        self.artifacts = ArtifactStore(root / "artifacts" / "evidence")
        self.reports = ArtifactStore(root / "artifacts" / "reports")
        self.store = EvidenceFactStore(self.database, self.artifacts,
                                       StoreSettings(self.artifacts.root, max_inline_bytes=0))
        self.store.initialize()
        self.backup_root = root / "backups"
        self.provenance = EvidenceProvenance(
            "FIXTURE", "test", "backup", datetime.now(timezone.utc), "observed")

    def evidence(self, value: bytes, *, pinned: bool = False):
        return self.store.create_evidence(
            EvidenceType.RECON_RECORD, value, source="FIXTURE",
            provenance=self.provenance, target_ref="target-fixture",
            retention=Retention(retain=True, pinned=pinned, finding_related=pinned),
        )

    def manager(self, mode="FINDING_LINKED"):
        return BackupManager(self.store, BackupSettings(self.backup_root, mode), self.reports)

    def test_backup_holds_artifact_roots_through_snapshot_and_copy(self):
        manager = self.manager()

        def inspect_locks(_backup_id):
            for artifacts in (self.artifacts, self.reports):
                lock_path = artifacts.root / ".artifact.lock"
                fd = os.open(lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(fd)
            return "locked"

        with patch.object(manager, "_create_locked", side_effect=inspect_locks):
            self.assertEqual(manager.create(), "locked")

    def test_backup_create_rejects_missing_required_mount_before_writing(self):
        manager = BackupManager(self.store, BackupSettings(self.backup_root),
                                self.reports, required_mount=self.database.parent.parent)
        with patch("hackbot.backup.os.path.ismount", return_value=False):
            with self.assertRaisesRegex(BackupError, "Required state mount"):
                manager.create()
        self.assertFalse(self.backup_root.exists())

    def test_backup_create_accepts_mounted_state_path(self):
        manager = BackupManager(self.store, BackupSettings(self.backup_root),
                                self.reports, required_mount=self.database.parent.parent)
        with patch("hackbot.backup.os.path.ismount", return_value=True), patch.object(
                manager, "_create_locked", return_value="mounted"):
            self.assertEqual(manager.create(), "mounted")

    def test_configured_required_mount_reaches_standalone_backup_manager(self):
        root = self.database.parent.parent
        config = AppConfig(
            paths=LocalPaths(root / "config.toml", root),
            store=StoreSettings(self.artifacts.root, max_inline_bytes=0),
            backup=BackupSettings(self.backup_root),
            resources=ResourceSettings(required_mount=str(root)))
        self.assertEqual(BackupManager.from_config(config).required_mount, root)

    def test_schema_42_backup_remains_verifiable_without_json_index(self):
        self.evidence(b"schema42-report-proof", pinned=True)
        with sqlite3.connect(self.database) as db:
            drop_traffic_json_index_schema(db)
            db.execute("PRAGMA user_version=42")
        legacy = EvidenceFactStore(self.database, self.artifacts,
                                   StoreSettings(self.artifacts.root, max_inline_bytes=0))
        manager = BackupManager(legacy, BackupSettings(self.backup_root, "ALL"), self.reports)
        created = manager.create()
        self.assertEqual(created.schema_version, 42)
        self.assertTrue(manager.verify(created.backup_id).verified)

    def test_schema_43_backup_remains_verifiable_without_evidence_json_index(self):
        self.evidence(b"schema43-report-proof", pinned=True)
        with sqlite3.connect(self.database) as db:
            drop_evidence_json_index_schema(db)
            db.execute("PRAGMA user_version=43")
        legacy = EvidenceFactStore(self.database, self.artifacts,
                                   StoreSettings(self.artifacts.root, max_inline_bytes=0))
        manager = BackupManager(legacy, BackupSettings(self.backup_root, "ALL"), self.reports)
        created = manager.create()
        self.assertEqual(created.schema_version, 43)
        self.assertTrue(manager.verify(created.backup_id).verified)

    def test_backup_rejects_incomplete_evidence_json_index(self):
        self.evidence(b"schema44-reference-proof", pinned=True)
        with sqlite3.connect(self.database) as db:
            db.execute("DROP TRIGGER evidence_json_ref_registry_roles_insert")
        with self.assertRaisesRegex(BackupError, "reference schema requires review"):
            self.manager("ALL").create()

    def test_schema_44_backup_remains_verifiable_without_research_retirement(self):
        self.evidence(b"schema44-report-proof", pinned=True)
        with sqlite3.connect(self.database) as db:
            drop_research_retirement_schema(db)
            db.execute("PRAGMA user_version=44")
        legacy = EvidenceFactStore(self.database, self.artifacts,
                                   StoreSettings(self.artifacts.root, max_inline_bytes=0))
        manager = BackupManager(legacy, BackupSettings(self.backup_root, "ALL"), self.reports)
        created = manager.create()
        self.assertEqual(created.schema_version, 44)
        self.assertTrue(manager.verify(created.backup_id).verified)

    def test_all_backup_skips_only_released_dom_map_digest(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        parent = dom.record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/backup.js",
            body=b"console.log('backup')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        source_map = dom.record_source_map(
            target_id=package.target.id, js_artifact_id=parent.artifact_id,
            map_url="https://app.example.test/backup.js.map", body=b'{"version":3}',
            source="FIXTURE")
        manager = self.manager("ALL")
        with self.store._connection() as db:
            before, _, _ = manager._artifact_hashes(db, "ALL")
        self.assertIn(parent.artifact_sha256, before)
        self.assertIn(source_map.map_sha256, before)
        future = time.time() + 91 * 86400
        retirement = DOMPayloadRetirementManager(self.store)
        self.assertEqual(len(retirement.plan("SOURCE_MAP", now=future).candidates), 1)
        self.assertEqual(retirement.run("SOURCE_MAP", confirmed=True, now=future)["retired"], 1)
        with self.store._connection() as db:
            after, _, _ = manager._artifact_hashes(db, "ALL")
        self.assertIn(parent.artifact_sha256, after)
        self.assertNotIn(source_map.map_sha256, after)
        created = manager.create()
        self.assertTrue(manager.verify(created.backup_id).verified)

    def test_schema_45_backup_keeps_dom_digest_without_late_link_guards(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        parent = dom.record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/legacy.js",
            body=b"console.log('legacy')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        source_map = dom.record_source_map(
            target_id=package.target.id, js_artifact_id=parent.artifact_id,
            map_url="https://app.example.test/legacy.js.map", body=b'{"version":3}',
            source="FIXTURE")
        future = time.time() + 91 * 86400
        retirement = DOMPayloadRetirementManager(self.store)
        retirement.plan("SOURCE_MAP", now=future)
        self.assertEqual(retirement.run("SOURCE_MAP", confirmed=True, now=future)["retired"], 1)
        with sqlite3.connect(self.database) as db:
            drop_dom_retirement_guards(db)
            db.execute("PRAGMA user_version=45")
        legacy = BackupManager(
            EvidenceFactStore(self.database, self.artifacts,
                              StoreSettings(self.artifacts.root, max_inline_bytes=0)),
            BackupSettings(self.backup_root, "ALL"), self.reports)
        with sqlite3.connect(self.database) as db:
            selected, _, _ = legacy._artifact_hashes(db, "ALL")
        self.assertIn(source_map.map_sha256, selected)
        created = legacy.create()
        self.assertEqual(created.schema_version, 45)
        self.assertTrue(legacy.verify(created.backup_id).verified)

    def test_schema_45_backup_rejects_missing_research_guard(self):
        self.evidence(b"schema45-reference-proof", pinned=True)
        with sqlite3.connect(self.database) as db:
            db.execute("DROP TRIGGER research_ref_event_insert_guard")
        with self.assertRaisesRegex(BackupError, "reference schema requires review"):
            self.manager("ALL").create()

    def test_staged_backup_audit_detects_derived_count_drift(self):
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT INTO evidence_json_reference_counts VALUES (?,1)",
                       ("EV-" + "a" * 32,))
        manager = self.manager("ALL")
        backup_id = manager.create().backup_id
        result = manager.audit_json_indexes(backup_id)
        self.assertFalse(result["matches"])
        self.assertEqual(result["evidence_mismatches"], 1)
        self.assertFalse(result["active_state_replaced"])
        self.assertEqual(list((self.backup_root / "restore-staging").iterdir()), [])
        config = Path(self.temp.name) / "config.toml"
        config.write_text(
            f'[paths]\nroot = "{Path(self.temp.name)}"\n'
            f'[store]\nartifact_root = "{self.artifacts.root}"\n'
            f'[backup]\nroot = "{self.backup_root}"\n', encoding="utf-8")
        out, err = StringIO(), StringIO()
        self.assertEqual(main(["--config", str(config), "backup", "audit-json-indexes",
                               backup_id], stdout=out, stderr=err), 2, err.getvalue())
        self.assertFalse(json.loads(out.getvalue())["matches"])
        self.assertEqual(list((self.backup_root / "restore-staging").iterdir()), [])

    def test_low_space_rejects_backup_before_snapshot(self):
        manager = self.manager()
        original = hashlib.sha256(self.database.read_bytes()).hexdigest()
        with patch("hackbot.backup.shutil.disk_usage",
                   return_value=SimpleNamespace(free=manager.min_free_bytes)):
            with self.assertRaisesRegex(BackupError, "Insufficient free space"):
                manager.create()
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), original)
        self.assertEqual(list(self.backup_root.glob(".pending-*")), [])
        events = [json.loads(line) for line in
                  (self.backup_root / "maintenance-audit.jsonl").read_text().splitlines()]
        self.assertEqual([event["action"] for event in events],
                         ["BACKUP_STARTED", "BACKUP_FAILED"])
        self.assertEqual(events[0]["backup_id"], events[1]["backup_id"])
        self.assertEqual(events[1]["error_type"], "BackupError")
        self.assertNotIn("Insufficient free space", json.dumps(events))

    def test_low_space_after_snapshot_rejects_artifact_copy(self):
        self.evidence(b"finding-proof", pinned=True)
        manager = self.manager()
        original = hashlib.sha256(self.database.read_bytes()).hexdigest()
        with patch("hackbot.backup.shutil.disk_usage", side_effect=(
                SimpleNamespace(free=10**12),
                SimpleNamespace(free=manager.min_free_bytes))):
            with self.assertRaisesRegex(BackupError, "Insufficient free space"):
                manager.create()
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), original)
        self.assertEqual(list(self.backup_root.glob(".pending-*")), [])
        self.assertEqual(list(self.backup_root.glob("*/manifest.json")), [])

    def test_artifact_selection_limit_rejects_before_copying_blobs(self):
        self.evidence(b"first-backup-artifact")
        self.evidence(b"second-backup-artifact")
        manager = self.manager("ALL")
        with patch("hackbot.backup._MAX_BACKUP_ARTIFACTS", 1), patch.object(
                manager, "_copy_digest", wraps=manager._copy_digest) as copy:
            with self.assertRaisesRegex(BackupError, "artifact selection exceeds limit"):
                manager.create()
        copy.assert_not_called()
        self.assertEqual(list(self.backup_root.glob(".pending-*")), [])
        self.assertEqual(list(self.backup_root.glob("*/manifest.json")), [])

    def test_manifest_larger_than_old_limit_remains_verifiable(self):
        manager = self.manager()
        created = manager.create()
        manifest = self.backup_root / created.backup_id / "manifest.json"
        with manifest.open("a", encoding="utf-8") as handle:
            handle.write(" " * (1024 * 1024 + 1))
        self.assertGreater(manifest.stat().st_size, 1024 * 1024)
        self.assertTrue(manager.verify(created.backup_id, record=True).verified)

    def test_oversized_manifest_never_publishes_a_generation(self):
        manager = self.manager()
        with patch("hackbot.backup._MAX_MANIFEST_BYTES", 256):
            with self.assertRaisesRegex(BackupError, "manifest exceeds size limit"):
                manager.create()
        self.assertEqual(list(self.backup_root.glob(".pending-*")), [])
        self.assertEqual(list(self.backup_root.glob("*/manifest.json")), [])

    def test_failed_backup_audit_does_not_mask_low_space_error(self):
        manager = self.manager()
        with patch("hackbot.backup.shutil.disk_usage",
                   return_value=SimpleNamespace(free=0)), patch.object(
                       manager, "_audit", side_effect=(None, BackupError("audit unavailable"))):
            with self.assertRaisesRegex(BackupError, "Insufficient free space"):
                manager.create()

    def test_symlinked_artifact_bucket_is_not_backed_up(self):
        item = self.evidence(b"bucket-proof", pinned=True)
        bucket = self.artifacts.path_for(item.content_hash).parent
        outside = Path(self.temp.name) / "outside-bucket"
        bucket.rename(outside)
        bucket.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(BackupError, "Unsafe backup artifact directory"):
            self.manager().create()
        self.assertEqual((outside / item.content_hash).read_bytes(), b"bucket-proof")
        self.assertEqual(list(self.backup_root.glob(".pending-*")), [])

    def test_encrypted_backup_reserves_transient_copy_space(self):
        item = self.evidence(b"encrypted-proof", pinned=True)
        settings = BackupSettings(self.backup_root, "FINDING_LINKED",
                                  encryption_secret_ref="backup_key")
        manager = BackupManager(self.store, settings, self.reports, FixtureKeyProvider())
        with patch("hackbot.backup.shutil.disk_usage", side_effect=(
                SimpleNamespace(free=10**12),
                SimpleNamespace(free=manager.min_free_bytes + item.content_size))):
            with self.assertRaisesRegex(BackupError, "Insufficient free space"):
                manager.create()
        self.assertEqual(list(self.backup_root.glob(".pending-*")), [])

    def test_encrypted_creation_rejects_low_verify_space_before_publication(self):
        self.evidence(b"encrypted-verification-proof", pinned=True)
        settings = BackupSettings(self.backup_root, "FINDING_LINKED",
                                  encryption_secret_ref="backup_key")
        manager = BackupManager(self.store, settings, self.reports, FixtureKeyProvider())
        with patch("hackbot.backup.shutil.disk_usage", side_effect=(
                SimpleNamespace(free=10**12), SimpleNamespace(free=10**12),
                SimpleNamespace(free=manager.min_free_bytes))):
            with self.assertRaisesRegex(BackupError, "Insufficient free space"):
                manager.create()
        self.assertEqual(list(self.backup_root.glob(".pending-*")), [])
        self.assertEqual(list(self.backup_root.glob("*/manifest.json")), [])

    def test_encrypted_verify_rejects_low_space_before_decryption(self):
        self.evidence(b"encrypted-verify-proof", pinned=True)
        settings = BackupSettings(self.backup_root, "FINDING_LINKED",
                                  encryption_secret_ref="backup_key")
        manager = BackupManager(self.store, settings, self.reports, FixtureKeyProvider())
        created = manager.create()
        with patch("hackbot.backup.shutil.disk_usage",
                   return_value=SimpleNamespace(free=manager.min_free_bytes)), patch.object(
                       manager.crypto, "decrypt") as decrypt:
            with self.assertRaisesRegex(BackupError, "Insufficient free space"):
                manager.verify(created.backup_id)
            decrypt.assert_not_called()
        self.assertEqual(list(self.backup_root.glob(".verify-*")), [])

    def test_restore_rejects_low_space_before_creating_stage(self):
        created = self.manager().create()
        manager = self.manager()
        with patch("hackbot.backup.shutil.disk_usage",
                   return_value=SimpleNamespace(free=manager.min_free_bytes)):
            with self.assertRaisesRegex(BackupError, "Insufficient free space"):
                manager.stage_restore(created.backup_id)
        self.assertFalse((self.backup_root / "restore-staging").exists())

    def test_snapshot_includes_pinned_artifact_but_not_regenerable_cache_by_default(self):
        critical = self.evidence(b"finding-proof", pinned=True)
        cache = self.evidence(b"re-fetchable-cache")
        backup = self.manager().create()
        directory = self.backup_root / backup.backup_id
        self.assertTrue(backup.verified)
        self.assertEqual(backup.artifact_mode, "FINDING_LINKED")
        self.assertTrue((directory / "artifacts/evidence/sha256" /
                         critical.content_hash[:2] / critical.content_hash).is_file())
        self.assertFalse((directory / "artifacts/evidence/sha256" /
                          cache.content_hash[:2] / cache.content_hash).exists())
        manifest = json.loads((directory / "manifest.json").read_text())
        self.assertFalse(manifest["browser_profiles_included"])
        self.assertFalse(manifest["burp_runtime_included"])
        self.assertEqual(manifest["counts"]["evidence"], 2)

    def test_all_mode_copies_shared_digest_once_and_stages_without_live_replace(self):
        first = self.evidence(b"shared-body")
        self.evidence(b"shared-body")
        manager = self.manager("ALL")
        backup = manager.create()
        self.assertEqual(backup.file_count, 2)
        before = hashlib.sha256(self.database.read_bytes()).hexdigest()
        staged = manager.stage_restore(backup.backup_id)
        self.assertTrue((staged / "state.sqlite3").is_file())
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), before)
        with sqlite3.connect(staged / "state.sqlite3") as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM evidence").fetchone()[0], 2)
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.assertEqual((staged / "artifacts/evidence/sha256" /
                          first.content_hash[:2] / first.content_hash).read_bytes(), b"shared-body")

    def test_all_mode_keeps_shared_blob_until_final_evidence_payload_retirement(self):
        first = self.evidence(b"retention-backup-shared")
        second = self.evidence(b"retention-backup-shared")
        self.store.set_retention(first.evidence_id, Retention(retain=False),
                                 actor="fixture", reason="expired-cache")
        now = time.time() + 172800
        retirement = EvidencePayloadRetirementManager(self.store)
        self.assertEqual(retirement.plan(now=now).evidence_ids, (first.evidence_id,))
        self.assertEqual(retirement.run(confirmed=True, now=now)["retired"], 1)
        manager = self.manager("ALL")
        shared_backup = manager.create()
        self.assertEqual(shared_backup.file_count, 2)
        self.assertTrue(manager.verify(shared_backup.backup_id).verified)
        self.store.set_retention(second.evidence_id, Retention(retain=False),
                                 actor="fixture", reason="expired-cache")
        self.assertEqual(retirement.plan(now=now).evidence_ids, (second.evidence_id,))
        self.assertEqual(retirement.run(confirmed=True, now=now)["retired"], 1)
        retired_backup = manager.create()
        self.assertEqual(retired_backup.file_count, 1)
        self.assertTrue(manager.verify(retired_backup.backup_id).verified)
        staged = manager.stage_restore(retired_backup.backup_id)
        self.assertFalse((staged / "artifacts/evidence/sha256" /
                          first.content_hash[:2] / first.content_hash).exists())
        with sqlite3.connect(staged / "state.sqlite3") as db:
            self.assertEqual(db.execute(
                "SELECT count(*) FROM evidence_payload_retirements").fetchone()[0], 2)

    def test_all_mode_limit_counts_only_reachable_artifacts(self):
        retired = [self.evidence(f"retired-{i}".encode()) for i in range(2)]
        live = self.evidence(b"live-backup-artifact")
        for item in retired:
            self.store.set_retention(item.evidence_id, Retention(retain=False),
                                     actor="fixture", reason="expired-cache")
        now = time.time() + 172800
        retirement = EvidencePayloadRetirementManager(self.store)
        self.assertEqual(set(retirement.plan(now=now).evidence_ids),
                         {item.evidence_id for item in retired})
        self.assertEqual(retirement.run(confirmed=True, now=now)["retired"], 2)
        with self.store._connection() as snapshot:
            with patch("hackbot.backup._MAX_BACKUP_ARTIFACTS", 1):
                selected, _, _ = self.manager("ALL")._artifact_hashes(snapshot, "ALL")
        self.assertEqual(selected, [live.content_hash])

    def test_version_two_all_manifest_preserves_pre_retirement_selection(self):
        self.evidence(b"historical-v2-all")
        manager = self.manager("ALL")
        created = manager.create()
        manifest_path = self.backup_root / created.backup_id / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest["artifact_selection_version"], 4)
        manifest["artifact_selection_version"] = 2
        manifest_path.write_text(json.dumps(manifest, sort_keys=True))
        self.assertTrue(manager.verify(created.backup_id).verified)

    def test_all_mode_selects_direct_traffic_and_javascript_artifact_references(self):
        traffic_digest = hashlib.sha256(b"traffic-body").hexdigest()
        js_digest = hashlib.sha256(b"javascript-body").hexdigest()
        with sqlite3.connect(":memory:") as snapshot:
            snapshot.executescript("""
                CREATE TABLE evidence (artifact_hash TEXT);
                CREATE TABLE traffic_requests (artifact_hash TEXT);
                CREATE TABLE dom_js_artifacts (artifact_sha256 TEXT);
            """)
            snapshot.execute("INSERT INTO traffic_requests VALUES (?)", (traffic_digest,))
            snapshot.execute("INSERT INTO dom_js_artifacts VALUES (?)", (js_digest,))
            selected, reports, counts = self.manager("ALL")._artifact_hashes(snapshot, "ALL")
        self.assertEqual(selected, sorted((traffic_digest, js_digest)))
        self.assertEqual(reports, [])
        self.assertEqual(counts["evidence"], 0)

    def test_new_digest_owner_blocks_backup_until_reference_inventory_is_reviewed(self):
        with self.store._connection() as db:
            db.execute("CREATE TABLE future_digest_owner "
                       "(id INTEGER PRIMARY KEY, artifact_hash TEXT)")
        with self.assertRaisesRegex(BackupError, "reference schema requires review"):
            self.manager("ALL").create()
        self.assertEqual([path for path in self.backup_root.iterdir()
                          if path.name.startswith(".pending-")], [])

    def test_corrupt_backup_rejected_and_active_state_unmodified(self):
        self.evidence(b"protected", pinned=True)
        manager = self.manager()
        backup = manager.create()
        state_hash = hashlib.sha256(self.database.read_bytes()).hexdigest()
        database_copy = self.backup_root / backup.backup_id / "state.sqlite3"
        with database_copy.open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaises(BackupError):
            manager.verify(backup.backup_id)
        with self.assertRaises(BackupError):
            manager.stage_restore(backup.backup_id)
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), state_hash)

    def test_backup_rejects_broken_sqlite_foreign_keys(self):
        with sqlite3.connect(self.database) as db:
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute("INSERT INTO fact_evidence(fact_id,evidence_id) VALUES (?,?)",
                       ("FA-missing", "EV-missing"))
        with self.assertRaisesRegex(BackupError, "broken references"):
            self.manager("ALL").create()

    def test_identifier_rejects_path_traversal(self):
        with self.assertRaises(BackupError):
            self.manager().verify("../../state")

    def test_unencrypted_secret_artifact_fails_closed(self):
        self.store.create_evidence(
            EvidenceType.RECON_RECORD, b"protected fixture secret", source="FIXTURE",
            provenance=self.provenance, sensitivity=Sensitivity.SECRET,
            retention=Retention(retain=True, pinned=True, finding_related=True),
        )
        with self.assertRaisesRegex(BackupError, "requires encrypted backup"):
            self.manager("ALL").create()
        self.assertEqual(self.manager("ALL").list(), [])

    def test_unencrypted_validation_only_secret_artifact_fails_closed(self):
        self.store.create_evidence(
            EvidenceType.RECON_RECORD, b"validation-only-secret", source="FIXTURE",
            provenance=self.provenance, sensitivity=Sensitivity.SECRET)
        with self.store._connection() as db:
            with self.assertRaisesRegex(BackupError, "requires encrypted backup"):
                BackupManager._reject_unencrypted_secrets(db)

    def test_unencrypted_finding_linked_backup_rejects_unselected_secret_metadata(self):
        self.store.create_evidence(
            EvidenceType.RECON_RECORD, b"unselected-secret-body", source="FIXTURE",
            provenance=self.provenance, sensitivity=Sensitivity.SECRET,
            metadata={"api_key": "fixture-only-secret-value"},
        )
        with self.assertRaisesRegex(BackupError, "requires encrypted backup"):
            self.manager("FINDING_LINKED").create()
        self.assertEqual(self.manager("FINDING_LINKED").list(), [])

    def test_plaintext_generation_with_secret_metadata_fails_verification(self):
        manager = self.manager("FINDING_LINKED")
        created = manager.create()
        directory = self.backup_root / created.backup_id
        self.store.create_evidence(
            EvidenceType.RECON_RECORD, b"unselected-secret-body", source="FIXTURE",
            provenance=self.provenance, sensitivity=Sensitivity.SECRET,
            metadata={"api_key": "fixture-only-secret-value"},
        )
        snapshot_path = directory / "state.sqlite3"
        with sqlite3.connect(self.database) as source:
            with sqlite3.connect(snapshot_path) as destination:
                source.backup(destination)
        manifest_path = directory / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["counts"]["evidence"] += 1
        manifest["files"][0]["sha256"] = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
        manifest["files"][0]["bytes"] = snapshot_path.stat().st_size
        manifest_path.write_text(json.dumps(manifest, sort_keys=True))
        with self.assertRaisesRegex(BackupError, "requires encrypted backup"):
            manager.verify(created.backup_id)

    def test_legacy_selection_manifest_remains_verifiable(self):
        self.evidence(b"legacy-selection-proof", pinned=True)
        manager = self.manager()
        created = manager.create()
        path = self.backup_root / created.backup_id / "manifest.json"
        manifest = json.loads(path.read_text())
        self.assertEqual(manifest.pop("artifact_selection_version"), 4)
        path.write_text(json.dumps(manifest, sort_keys=True))
        self.assertTrue(manager.verify(created.backup_id).verified)
        manifest["artifact_selection_version"] = True
        path.write_text(json.dumps(manifest, sort_keys=True))
        with self.assertRaisesRegex(BackupError, "manifest is incompatible"):
            manager.verify(created.backup_id)

    def test_latest_metadata_reports_last_verification_without_live_recheck(self):
        manager = self.manager()
        self.assertEqual(manager.latest_metadata()["state"], "MISSING")
        self.evidence(b"pinned-evidence", pinned=True)
        created = manager.create()
        current = manager.latest_metadata()
        self.assertEqual(current["backup_id"], created.backup_id)
        self.assertEqual(current["state"], "RECORDED")
        self.assertEqual(current["verification"], "LAST_VERIFIED")
        self.assertIsNotNone(current["verified_at"])
        marker = self.backup_root / created.backup_id / "verification.json"
        marker.write_text('{"verified_at":"2000-01-01T00:00:00+00:00", "manifest_sha256":"bad"}')
        self.assertEqual(manager.latest_metadata()["verification"], "NOT_CHECKED")

    def test_encrypted_backup_restores_protected_evidence_and_rejects_wrong_key(self):
        sensitive = self.store.create_evidence(
            EvidenceType.RECON_RECORD, b"fixture-sensitive-proof", source="FIXTURE",
            provenance=self.provenance, sensitivity=Sensitivity.SECRET,
            retention=Retention(retain=True, pinned=True, finding_related=True),
        )
        settings = BackupSettings(self.backup_root, "ALL",
                                  encryption_secret_ref="backup_key")
        manager = BackupManager(self.store, settings, self.reports, FixtureKeyProvider())
        created = manager.create()
        self.assertTrue(created.verified)
        directory = self.backup_root / created.backup_id
        manifest = json.loads((directory / "manifest.json").read_text())
        self.assertEqual(manifest["encryption"], "OPENPGP_GPG_AES256")
        self.assertFalse((directory / "state.sqlite3").exists())
        encrypted = directory / "artifacts/evidence/sha256" / sensitive.content_hash[:2] / (
            sensitive.content_hash + ".gpg")
        self.assertTrue(encrypted.is_file())
        self.assertNotIn(b"fixture-sensitive-proof", encrypted.read_bytes())
        staged = manager.stage_restore(created.backup_id)
        restored = staged / "artifacts/evidence/sha256" / sensitive.content_hash[:2] / sensitive.content_hash
        self.assertEqual(restored.read_bytes(), b"fixture-sensitive-proof")
        with self.assertRaises(BackupError):
            BackupManager(self.store, settings, self.reports,
                          FixtureKeyProvider(b"b" * 32)).verify(created.backup_id)

    def test_encrypted_backup_rejects_ciphertext_tampering(self):
        self.store.create_evidence(EvidenceType.RECON_RECORD, b"fixture-secret", source="FIXTURE",
                                   provenance=self.provenance, sensitivity=Sensitivity.SECRET)
        settings = BackupSettings(self.backup_root, "ALL", encryption_secret_ref="backup_key")
        manager = BackupManager(self.store, settings, self.reports, FixtureKeyProvider())
        created = manager.create()
        path = self.backup_root / created.backup_id / "state.sqlite3.gpg"
        with path.open("ab") as handle:
            handle.write(b"altered")
        with self.assertRaises(BackupError):
            manager.verify(created.backup_id)

    def test_decryption_caps_plaintext_before_manifest_hash_check(self):
        self.evidence(b"bounded-plaintext-proof", pinned=True)
        settings = BackupSettings(self.backup_root, "FINDING_LINKED",
                                  encryption_secret_ref="backup_key")
        manager = BackupManager(self.store, settings, self.reports, FixtureKeyProvider())
        created = manager.create()
        directory = self.backup_root / created.backup_id
        ciphertext = directory / "state.sqlite3.gpg"
        limited = Path(self.temp.name) / "limited-state.sqlite3"
        with self.assertRaises(BackupCryptoError):
            manager.crypto.decrypt(ciphertext, limited, Path(self.temp.name) / "limited-gpg",
                                   max_output_bytes=1)
        self.assertFalse(limited.exists())
        manifest_path = directory / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        next(entry for entry in manifest["files"] if entry["path"] == "state.sqlite3.gpg")[
            "plaintext_bytes"] = 1
        manifest_path.write_text(json.dumps(manifest, sort_keys=True))
        with self.assertRaises(BackupError):
            manager.verify(created.backup_id)
        self.assertEqual(list(self.backup_root.glob(".verify-*")), [])

    def test_schema34_backup_stages_and_migrates_on_isolated_copy(self):
        legacy_db = Path(self.temp.name) / "legacy" / "state.sqlite3"
        legacy_db.parent.mkdir(mode=0o700)
        migrations = sorted(files("hackbot").joinpath("migrations").iterdir(),
                            key=lambda item: item.name)
        with sqlite3.connect(legacy_db) as db:
            for version, migration in enumerate(migrations[:34], start=1):
                db.executescript("BEGIN IMMEDIATE;\n" + migration.read_text() +
                                 f"\nPRAGMA user_version={version};\nCOMMIT;")
            value = b"schema34-evidence"
            digest = hashlib.sha256(value).hexdigest()
            evidence_id = "EV-" + uuid.uuid4().hex
            now = datetime.now(timezone.utc).isoformat()
            self.artifacts.put_bytes(value)
            db.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (evidence_id, "RECON_RECORD", "legacy-target", now, now, "FIXTURE",
                        digest, "ARTIFACT", len(value), None, digest, "{}", "SECRET",
                        "ORIGINAL", json.dumps(self.provenance.to_reference()), None))
            db.execute("INSERT INTO evidence_policy_events "
                       "(evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason) "
                       "VALUES (?,?,?,?,?,?,?,?)",
                       (evidence_id, 1, None, 1, 1, now, "FIXTURE", "initial"))
        legacy = EvidenceFactStore(legacy_db, self.artifacts,
                                   StoreSettings(self.artifacts.root, max_inline_bytes=0))
        manager = BackupManager(
            legacy, BackupSettings(self.backup_root, "ALL", encryption_secret_ref="backup_key"),
            self.reports, FixtureKeyProvider())
        created = manager.create()
        self.assertEqual(created.schema_version, 34)
        staged = manager.stage_restore(created.backup_id)
        restored = EvidenceFactStore(
            staged / "state.sqlite3", ArtifactStore(staged / "artifacts/evidence"),
            StoreSettings(staged / "artifacts/evidence", max_inline_bytes=0))
        restored.initialize(allow_existing_migration=True)
        self.assertEqual(restored.read_content(evidence_id, allow_sensitive=True), b"schema34-evidence")
        with sqlite3.connect(staged / "state.sqlite3") as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 47)
        shutil.rmtree(staged)
        original_hash = hashlib.sha256(legacy_db.read_bytes()).hexdigest()
        rehearsal = manager.rehearse_upgrade(created.backup_id)
        self.assertEqual(rehearsal["from_schema"], 34)
        self.assertEqual(rehearsal["to_schema"], 47)
        self.assertEqual(rehearsal["preserved_counts"]["evidence"], 1)
        self.assertTrue(rehearsal["json_reference_audit"]["matches"])
        self.assertGreater(rehearsal["json_reference_audit"]["scanned_values"], 0)
        self.assertFalse(rehearsal["active_state_replaced"])
        self.assertEqual(hashlib.sha256(legacy_db.read_bytes()).hexdigest(), original_hash)
        self.assertEqual(list((self.backup_root / "restore-staging").iterdir()), [])

    def test_recent_schema_copies_upgrade_without_losing_evidence(self):
        migrations = sorted(files("hackbot").joinpath("migrations").iterdir(),
                            key=lambda item: item.name)
        for version in range(35, 40):
            with self.subTest(schema=version):
                database = Path(self.temp.name) / f"schema-{version}.sqlite3"
                value = f"schema-{version}-evidence".encode()
                digest = hashlib.sha256(value).hexdigest()
                evidence_id = "EV-" + uuid.uuid4().hex
                now = datetime.now(timezone.utc).isoformat()
                self.artifacts.put_bytes(value)
                with sqlite3.connect(database) as db:
                    for target, migration in enumerate(migrations[:version], start=1):
                        db.executescript("BEGIN IMMEDIATE;\n" + migration.read_text() +
                                         f"\nPRAGMA user_version={target};\nCOMMIT;")
                    db.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                               (evidence_id, "RECON_RECORD", "legacy-target", now, now, "FIXTURE",
                                digest, "ARTIFACT", len(value), None, digest, "{}", "SECRET",
                                "ORIGINAL", json.dumps(self.provenance.to_reference()), None))
                    db.execute("INSERT INTO evidence_policy_events "
                               "(evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason) "
                               "VALUES (?,?,?,?,?,?,?,?)",
                               (evidence_id, 1, None, 1, 1, now, "FIXTURE", "initial"))
                upgraded = EvidenceFactStore(database, self.artifacts,
                                             StoreSettings(self.artifacts.root, max_inline_bytes=0))
                upgraded.initialize(allow_existing_migration=True)
                self.assertEqual(upgraded.read_content(evidence_id, allow_sensitive=True), value)
                with sqlite3.connect(database) as db:
                    self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 47)
                    self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                    self.assertIsNone(db.execute("PRAGMA foreign_key_check").fetchone())

    def test_rehearsal_failure_removes_decrypted_staging(self):
        self.evidence(b"rehearsal-failure-fixture", pinned=True)
        manager = self.manager("ALL")
        created = manager.create()
        with patch("hackbot.backup.check_database",
                   side_effect=DatabaseCheckError("fixture failure")):
            with self.assertRaises(DatabaseCheckError):
                manager.rehearse_upgrade(created.backup_id)
        self.assertEqual(list((self.backup_root / "restore-staging").iterdir()), [])
        self.assertTrue(manager.verify(created.backup_id).verified)

    def test_rehearsal_rejects_reference_index_mismatch_and_cleans_stage(self):
        self.evidence(b"rehearsal-reference-fixture", pinned=True)
        manager = self.manager("ALL")
        created = manager.create()
        from hackbot.json_reference_audit import ReferenceIndexAudit
        mismatch = ReferenceIndexAudit(1, 1, 1, 0, 1, 0)
        with patch("hackbot.backup.audit_json_reference_indexes", return_value=mismatch):
            with self.assertRaisesRegex(BackupError, "do not match"):
                manager.rehearse_upgrade(created.backup_id)
        self.assertEqual(list((self.backup_root / "restore-staging").iterdir()), [])
        self.assertTrue(manager.verify(created.backup_id).verified)

    def test_full_fixture_restores_target_finding_evidence_report_and_planner(self):
        fixture = phase29_fixture.Phase29Tests(
            methodName="test_cross_tenant_report_is_evidence_backed_and_idempotent")
        fixture.setUp()
        try:
            validation, finding = fixture.confirmed()
            report = fixture.generator.generate(finding.id, fixture.target_id).draft
            self.assertIsNotNone(report)
            planner = PlannerStore(fixture.store).create(
                fixture.fixture.fx.package, PlannerMode.ANALYZE_ONLY,
                PlannerLimits(), "fixture:" + "a" * 64)
            linked_evidence = fixture.store.create_evidence(
                EvidenceType.RECON_RECORD, b"fixture-confirmed-evidence", source="FIXTURE",
                provenance=self.provenance, target_ref=fixture.target_id,
                sensitivity=Sensitivity.SECRET,
                retention=Retention(retain=True, pinned=True, finding_related=True))
            control = fixture.store.create_evidence(
                EvidenceType.RECON_RECORD, b"fixture-check-only-control", source="FIXTURE",
                provenance=self.provenance, target_ref=fixture.target_id,
                sensitivity=Sensitivity.SECRET)
            contradictory = fixture.store.create_evidence(
                EvidenceType.RECON_RECORD, b"fixture-contradictory-control", source="FIXTURE",
                provenance=self.provenance, target_ref=fixture.target_id,
                sensitivity=Sensitivity.SECRET)
            extra_validation = replace(
                validation, id="VALIDATION-" + uuid.uuid4().hex,
                evidence_snapshot_hash=hashlib.sha256(
                    b"fixture-validation-with-additional-controls").hexdigest(),
                contradicting_evidence_ids=(contradictory.evidence_id,),
                checks=(*validation.checks,
                        ValidationCheck("BACKUP_CONTROL", CheckOutcome.PASS,
                                        (control.evidence_id,))))
            duplicate, same_finding = fixture.fixture.results.record(
                extra_validation,
                FindingSpec(finding.category, finding.root_cause_fingerprint,
                            finding.surface_fingerprint, finding.object_type,
                            finding.title, finding.safe_summary,
                            finding.demonstrated_impact, finding.potential_impact,
                            finding.preliminary_severity))
            self.assertEqual(duplicate.status, ValidationStatus.DUPLICATE_CANDIDATE)
            self.assertEqual(same_finding.id, finding.id)
            manager = BackupManager(
                fixture.store,
                BackupSettings(self.backup_root, "FINDING_LINKED",
                               encryption_secret_ref="backup_key"),
                fixture.drafts.artifacts, FixtureKeyProvider())
            created = manager.create()
            manifest = json.loads((self.backup_root / created.backup_id / "manifest.json").read_text())
            self.assertEqual(manifest["artifact_selection_version"], 4)
            self.assertTrue(manager.verify(created.backup_id).verified)
            rehearsal = manager.rehearse_upgrade(created.backup_id)
            self.assertTrue(rehearsal["json_reference_audit"]["matches"])
            self.assertGreater(rehearsal["json_reference_audit"]["evidence_ids"], 0)
            fixture.doCleanups()
            self.assertFalse(fixture.store.db_path.exists())
            staged = manager.stage_restore(created.backup_id)
            with sqlite3.connect(staged / "state.sqlite3") as db:
                db.execute("PRAGMA foreign_keys=ON")
                self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertIsNone(db.execute("PRAGMA foreign_key_check").fetchone())
                self.assertEqual(db.execute("SELECT count(*) FROM registry_targets WHERE target_id=?",
                                            (fixture.target_id,)).fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT validation_id FROM findings WHERE finding_id=?",
                                            (finding.id,)).fetchone()[0], validation.id)
                self.assertEqual(db.execute("SELECT content_sha256 FROM report_drafts WHERE report_id=?",
                                            (report.id,)).fetchone()[0], report.content_sha256)
                self.assertEqual(db.execute("SELECT status FROM planner_runs WHERE run_id=?",
                                            (planner.id,)).fetchone()[0], "CREATED")
                self.assertEqual(db.execute("SELECT count(*) FROM finding_duplicates "
                                            "WHERE finding_id=? AND validation_id=?",
                                            (finding.id, duplicate.id)).fetchone()[0], 1)
                digest = db.execute("SELECT artifact_hash FROM evidence WHERE evidence_id=?",
                                    (linked_evidence.evidence_id,)).fetchone()[0]
            self.assertIsNotNone(digest)
            evidence_path = staged / "artifacts/evidence/sha256" / digest[:2] / digest
            self.assertTrue(evidence_path.is_file())
            self.assertEqual(hashlib.sha256(evidence_path.read_bytes()).hexdigest(), digest)
            for item in (control, contradictory):
                path = staged / "artifacts/evidence/sha256" / item.content_hash[:2] / item.content_hash
                self.assertTrue(path.is_file())
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item.content_hash)
            report_path = (staged / "artifacts/reports/sha256" /
                           report.content_sha256[:2] / report.content_sha256)
            self.assertEqual(hashlib.sha256(report_path.read_bytes()).hexdigest(),
                             report.content_sha256)
        finally:
            fixture.doCleanups()

    def test_cli_create_verify_and_stage_are_local_only(self):
        self.evidence(b"critical", pinned=True)
        config = Path(self.temp.name) / "config.toml"
        config.write_text(
            f'[paths]\nroot = "{Path(self.temp.name)}"\n'
            f'[store]\nartifact_root = "{self.artifacts.root}"\n'
            f'[backup]\nroot = "{self.backup_root}"\n', encoding="utf-8")
        out, err = StringIO(), StringIO()
        self.assertEqual(main(["--config", str(config), "backup", "create"],
                              stdout=out, stderr=err), 0, err.getvalue())
        backup_id = json.loads(out.getvalue())["backup_id"]
        out = StringIO()
        self.assertEqual(main(["--config", str(config), "backup", "verify", backup_id],
                              stdout=out, stderr=err), 0)
        self.assertTrue(json.loads(out.getvalue())["verified"])
        out = StringIO()
        self.assertEqual(main(["--config", str(config), "backup", "stage", backup_id],
                              stdout=out, stderr=err), 0)
        stage = json.loads(out.getvalue())
        self.assertFalse(stage["active_state_replaced"])
        shutil.rmtree(stage["staged_at"])
        out = StringIO()
        self.assertEqual(main(["--config", str(config), "backup", "rehearse", backup_id],
                              stdout=out, stderr=err), 0, err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["integrity"], "OK")
        out = StringIO()
        self.assertEqual(main(["--config", str(config), "backup", "audit-json-indexes",
                               backup_id], stdout=out, stderr=err), 0, err.getvalue())
        self.assertTrue(json.loads(out.getvalue())["matches"])
        self.assertEqual(list((self.backup_root / "restore-staging").iterdir()), [])

    def test_prune_requires_confirmation_and_keeps_verified_newest(self):
        self.evidence(b"critical-prune", pinned=True)
        manager = BackupManager(self.store, BackupSettings(self.backup_root, "ALL", 2), self.reports)
        original = manager.create()
        second = manager.create()
        newest = manager.create()
        plan = manager.prune_plan()
        self.assertEqual(plan["eligible"], [original.backup_id])
        self.assertEqual(plan["retained"], [newest.backup_id, second.backup_id])
        self.assertGreater(plan["estimated_bytes"], 0)
        with self.assertRaises(BackupError):
            manager.prune(confirmed=False)
        self.assertTrue((self.backup_root / original.backup_id).is_dir())
        result = manager.prune(confirmed=True)
        self.assertEqual(result["removed"], [original.backup_id])
        self.assertTrue(manager.verify(second.backup_id).verified)
        self.assertTrue(manager.verify(newest.backup_id).verified)

    def test_prune_refuses_when_retained_generation_is_corrupt(self):
        self.evidence(b"critical-corrupt", pinned=True)
        manager = BackupManager(self.store, BackupSettings(self.backup_root, "ALL", 1), self.reports)
        older = manager.create()
        newer = manager.create()
        with (self.backup_root / newer.backup_id / "state.sqlite3").open("ab") as handle:
            handle.write(b"damage")
        with self.assertRaises(BackupError):
            manager.prune(confirmed=True)
        self.assertTrue((self.backup_root / older.backup_id).is_dir())

    def test_prune_refuses_to_discard_corrupt_older_generation(self):
        self.evidence(b"critical-corrupt-old", pinned=True)
        manager = BackupManager(self.store, BackupSettings(self.backup_root, "ALL", 1), self.reports)
        older = manager.create()
        newer = manager.create()
        with (self.backup_root / older.backup_id / "state.sqlite3").open("ab") as handle:
            handle.write(b"damage")
        with self.assertRaises(BackupError):
            manager.prune_plan()
        with self.assertRaises(BackupError):
            manager.prune(confirmed=True)
        self.assertTrue((self.backup_root / older.backup_id).is_dir())
        self.assertTrue((self.backup_root / newer.backup_id).is_dir())

    def test_malformed_newest_generation_blocks_pruning_without_hiding_valid_backups(self):
        self.evidence(b"critical-malformed", pinned=True)
        manager = BackupManager(self.store, BackupSettings(self.backup_root, "ALL", 1), self.reports)
        older = manager.create()
        newer = manager.create()
        malformed = self.backup_root / "20990101T000000Z-ffffffff"
        malformed.mkdir(mode=0o700)
        (malformed / "manifest.json").write_text("not-json")
        self.assertEqual(manager.latest_metadata()["state"], "INVALID_METADATA")
        with self.assertRaises(BackupError):
            manager.prune_plan()
        with self.assertRaises(BackupError):
            manager.prune(confirmed=True)
        self.assertTrue((self.backup_root / older.backup_id).is_dir())
        self.assertTrue((self.backup_root / newer.backup_id).is_dir())

    def test_prune_rejects_symlink_inside_old_generation(self):
        self.evidence(b"critical-link", pinned=True)
        manager = BackupManager(self.store, BackupSettings(self.backup_root, "ALL", 1), self.reports)
        older = manager.create()
        manager.create()
        (self.backup_root / older.backup_id / "unsafe").symlink_to(self.database)
        with self.assertRaises(BackupError):
            manager.prune_plan()

    def test_stale_incomplete_backup_requires_review_and_confirmation(self):
        manager = self.manager()
        self.backup_root.mkdir()
        stale = Path(tempfile.mkdtemp(prefix=".pending-", dir=self.backup_root))
        recent = Path(tempfile.mkdtemp(prefix=".pending-", dir=self.backup_root))
        (stale / "state.sqlite3").write_bytes(b"private fixture")
        (recent / "state.sqlite3").write_bytes(b"recent fixture")
        old = datetime.now(timezone.utc).timestamp() - 25 * 3600
        os.utime(stale, (old, old))
        plan = manager.incomplete_plan()
        self.assertEqual(plan["candidates"], [stale.name])
        self.assertEqual(plan["estimated_bytes"], len(b"private fixture"))
        with self.assertRaises(BackupError):
            manager.cleanup_incomplete(confirmed=False)
        self.assertTrue(stale.exists())
        result = manager.cleanup_incomplete(confirmed=True)
        self.assertEqual(result["removed"], [stale.name])
        self.assertFalse(stale.exists())
        self.assertTrue(recent.exists())

    def test_cli_incomplete_cleanup_requires_explicit_confirmation(self):
        self.backup_root.mkdir()
        stale = Path(tempfile.mkdtemp(prefix=".pending-", dir=self.backup_root))
        (stale / "state.sqlite3").write_bytes(b"private fixture")
        old = datetime.now(timezone.utc).timestamp() - 25 * 3600
        os.utime(stale, (old, old))
        config = Path(self.temp.name) / "config.toml"
        config.write_text(
            f'[paths]\nroot = "{Path(self.temp.name)}"\n'
            f'[backup]\nroot = "{self.backup_root}"\n', encoding="utf-8")
        out, err = StringIO(), StringIO()
        self.assertEqual(main(["--config", str(config), "backup", "incomplete-plan"],
                              stdout=out, stderr=err), 0)
        self.assertEqual(json.loads(out.getvalue())["candidates"], [stale.name])
        self.assertEqual(main(["--config", str(config), "backup", "incomplete-cleanup"],
                              stdout=StringIO(), stderr=StringIO()), 2)
        self.assertTrue(stale.exists())
        self.assertEqual(main(["--config", str(config), "backup", "incomplete-cleanup",
                               "--confirmed"], stdout=StringIO(), stderr=StringIO()), 0)
        self.assertFalse(stale.exists())

    def test_incomplete_backup_symlink_fails_closed(self):
        manager = self.manager()
        self.backup_root.mkdir()
        stale = Path(tempfile.mkdtemp(prefix=".pending-", dir=self.backup_root))
        (stale / "unsafe").symlink_to(self.database)
        old = datetime.now(timezone.utc).timestamp() - 25 * 3600
        os.utime(stale, (old, old))
        with self.assertRaises(BackupError):
            manager.incomplete_plan()
        self.assertTrue(stale.exists())
        self.assertTrue(self.database.exists())

    def test_stale_restore_stage_requires_exact_review_and_preserves_recent_stage(self):
        manager = self.manager()
        staging_root = self.backup_root / "restore-staging"
        staging_root.mkdir(parents=True)
        stale = Path(tempfile.mkdtemp(prefix="restore-", dir=staging_root))
        recent = Path(tempfile.mkdtemp(prefix="restore-", dir=staging_root))
        (stale / "state.sqlite3").write_bytes(b"decrypted fixture")
        (recent / "state.sqlite3").write_bytes(b"active fixture")
        old = datetime.now(timezone.utc).timestamp() - 25 * 3600
        os.utime(stale, (old, old))
        plan = manager.stale_restore_plan()
        self.assertEqual(plan["candidates"],
                         [{"name": stale.name, "bytes": len(b"decrypted fixture")}])
        with self.assertRaises(BackupError):
            manager.cleanup_stale_restore(stale.name, confirmed=False)
        with self.assertRaises(BackupError):
            manager.cleanup_stale_restore(recent.name, confirmed=True)
        with self.assertRaises(BackupError):
            manager.cleanup_stale_restore("../" + stale.name, confirmed=True)
        self.assertTrue(stale.exists())
        result = manager.cleanup_stale_restore(stale.name, confirmed=True)
        self.assertEqual(result["removed"], stale.name)
        self.assertFalse(stale.exists())
        self.assertTrue(recent.exists())

    def test_restore_staging_symlink_fails_closed(self):
        manager = self.manager()
        staging_root = self.backup_root / "restore-staging"
        staging_root.mkdir(parents=True)
        stale = Path(tempfile.mkdtemp(prefix="restore-", dir=staging_root))
        (stale / "unsafe").symlink_to(self.database)
        old = datetime.now(timezone.utc).timestamp() - 25 * 3600
        os.utime(stale, (old, old))
        with self.assertRaises(BackupError):
            manager.stale_restore_plan()
        self.assertTrue(stale.exists())
        self.assertTrue(self.database.exists())

    def test_cli_restore_staging_cleanup_requires_exact_confirmation(self):
        staging_root = self.backup_root / "restore-staging"
        staging_root.mkdir(parents=True)
        stale = Path(tempfile.mkdtemp(prefix="restore-", dir=staging_root))
        (stale / "state.sqlite3").write_bytes(b"decrypted fixture")
        old = datetime.now(timezone.utc).timestamp() - 25 * 3600
        os.utime(stale, (old, old))
        config = Path(self.temp.name) / "config.toml"
        config.write_text(
            f'[paths]\nroot = "{Path(self.temp.name)}"\n'
            f'[backup]\nroot = "{self.backup_root}"\n', encoding="utf-8")
        out = StringIO()
        self.assertEqual(main(["--config", str(config), "backup", "restore-staging-plan"],
                              stdout=out, stderr=StringIO()), 0)
        self.assertEqual(json.loads(out.getvalue())["candidates"][0]["name"], stale.name)
        self.assertEqual(main(["--config", str(config), "backup", "restore-staging-cleanup",
                               stale.name], stdout=StringIO(), stderr=StringIO()), 2)
        self.assertTrue(stale.exists())
        self.assertEqual(main(["--config", str(config), "backup", "restore-staging-cleanup",
                               stale.name, "--confirmed"], stdout=StringIO(), stderr=StringIO()), 0)
        self.assertFalse(stale.exists())
