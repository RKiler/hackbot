from datetime import datetime, timezone
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from hackbot.artifacts import ArtifactStore
from hackbot.cli import main
from hackbot.config import StoreSettings
from hackbot.domxss_store import DOMXSSStore
from hackbot.dom_refs import DOMReferenceError, has_external_dom_reference
from hackbot.dom_guard_schema import verify_dom_retirement_guards
from hackbot.dom_retention import (DOMPayloadPlanner, DOMPayloadPolicy,
                                   DOMPayloadRetirementManager)
from hackbot.evidence import EvidenceProvenance, EvidenceType, Retention
from hackbot.evidence_refs import (EvidenceReferenceError,
                                   evidence_reference_inventory,
                                   has_evidence_reference)
from hackbot.evidence_retention import (EvidencePayloadPolicy,
                                        EvidencePayloadRetirementManager)
from hackbot.evidence_json_index_schema import evidence_json_index_sql
from hackbot.json_reference_audit import (ReferenceIndexAuditError,
                                          audit_json_reference_indexes)
from hackbot.identity_registry import IdentityRegistry
from hackbot.retention import ArtifactGarbageCollector, OrphanPolicy
from hackbot.store import EvidenceFactStore, StoreSchemaError
from hackbot.target_loader import load_target_package
from hackbot.traffic_guard_schema import traffic_json_index_sql

from tests.schema_utils import (drop_dom_retirement_guards,
                                drop_evidence_json_index_schema)


class ArtifactCollectionTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.artifacts = ArtifactStore(self.root / "artifacts" / "evidence")
        self.store = EvidenceFactStore(
            self.root / "state" / "bughunter.sqlite3", self.artifacts,
            StoreSettings(self.artifacts.root, max_inline_bytes=0))
        self.store.initialize()
        self.provenance = EvidenceProvenance(
            "FIXTURE", "test", "retention", datetime.now(timezone.utc), "observed")
        self.now = time.time()

    def _old(self, digest):
        path = self.artifacts.path_for(digest)
        os.utime(path, (self.now - 172800, self.now - 172800))
        return path

    def _evidence(self, body, pinned=False):
        return self.store.create_evidence(
            EvidenceType.RECON_RECORD, body, source="FIXTURE", provenance=self.provenance,
            retention=Retention(retain=True, pinned=pinned, finding_related=pinned))

    def test_dom_owner_exclusion_requires_exact_evidence_link(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        asset = dom.record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/retention.js",
            body=b"console.log('retention')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        source_map = dom.record_source_map(
            target_id=package.target.id, js_artifact_id=asset.artifact_id,
            map_url="https://app.example.test/retention.js.map", body=b"{}",
            source="FIXTURE")
        with self.store._connection() as db:
            self.assertTrue(has_evidence_reference(db, asset.evidence_id))
            self.assertFalse(has_evidence_reference(
                db, asset.evidence_id, allowed_dom_artifact_id=asset.artifact_id))
            self.assertTrue(has_evidence_reference(db, source_map.evidence_id))
            self.assertFalse(has_evidence_reference(
                db, source_map.evidence_id, allowed_dom_map_id=source_map.map_id))
            with self.assertRaisesRegex(EvidenceReferenceError, "incomplete"):
                has_evidence_reference(
                    db, asset.evidence_id, allowed_dom_artifact_id="DOMART-" + "0" * 32)
            with self.assertRaisesRegex(EvidenceReferenceError, "incomplete"):
                has_evidence_reference(
                    db, source_map.evidence_id, allowed_dom_map_id="DOMMAP-" + "0" * 32)

            db.execute(
                "INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                ("PRINCIPAL-" + "1" * 32, package.target.id, "fixture", None,
                 "OBSERVED", json.dumps([asset.evidence_id]), None, None,
                 asset.retrieved_at.isoformat()),
            )
            self.assertTrue(has_evidence_reference(
                db, asset.evidence_id, allowed_dom_artifact_id=asset.artifact_id))
            db.execute("DELETE FROM registry_principals WHERE principal_id=?",
                       ("PRINCIPAL-" + "1" * 32,))

            db.execute(
                "INSERT INTO dom_js_artifacts "
                "(artifact_id,target_id,recon_asset_id,asset_url_sha256,recon_sha256,"
                "artifact_sha256,evidence_id,retrieval_exchange_id,state,source,retrieved_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("DOMART-" + "1" * 32, package.target.id, None, "1" * 64, None,
                 asset.artifact_sha256, asset.evidence_id, None, "STALE", "FIXTURE",
                 asset.retrieved_at.isoformat()),
            )
            self.assertTrue(has_evidence_reference(
                db, asset.evidence_id, allowed_dom_artifact_id=asset.artifact_id))

    def test_dom_reference_scan_catches_direct_and_escaped_json_links(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        asset = dom.record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/scan.js",
            body=b"console.log('scan')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        with self.store._connection() as db:
            self.assertFalse(has_external_dom_reference(db, asset.artifact_id))
            ticks = iter(range(1, 1_000_000))
            with patch("hackbot.dom_refs.time.monotonic",
                       side_effect=lambda: float(next(ticks))):
                with self.assertRaisesRegex(DOMReferenceError, "incomplete"):
                    has_external_dom_reference(db, asset.artifact_id, max_seconds=0.1)
            with self.assertRaisesRegex(DOMReferenceError, "owner is unavailable"):
                has_external_dom_reference(db, "DOMMAP-" + "0" * 32)
        historical = self.store.create_evidence(
            EvidenceType.RECON_RECORD, b"historical-reference", source="FIXTURE",
            provenance=EvidenceProvenance(
                "FIXTURE", "old-dom-map", asset.artifact_id,
                datetime.now(timezone.utc), "observed"),
            retention=Retention(retain=False),
        )
        with self.store._connection() as db:
            self.assertTrue(has_external_dom_reference(db, asset.artifact_id))
            db.execute(
                "INSERT INTO evidence_payload_retirements "
                "(evidence_id,retired_at,retention_class,actor,reason) "
                "VALUES (?,?,?,?,?)",
                (historical.evidence_id, datetime.now(timezone.utc).isoformat(),
                 "REGENERABLE", "fixture", "historical-reference"),
            )
            self.assertFalse(has_external_dom_reference(db, asset.artifact_id))
        map_record = dom.record_source_map(
            target_id=package.target.id, js_artifact_id=asset.artifact_id,
            map_url="https://app.example.test/scan.js.map", body=b"{}", source="FIXTURE")
        with self.store._connection() as db:
            self.assertTrue(has_external_dom_reference(db, asset.artifact_id))
            self.assertFalse(has_external_dom_reference(db, map_record.map_id))
            db.execute("CREATE TABLE fixture_dom_refs (payload_json TEXT NOT NULL)")
            encoded = json.dumps({"source": map_record.map_id}).replace(
                "DOMMAP-", "\\u0044OMMAP-", 1)
            db.execute("INSERT INTO fixture_dom_refs VALUES (?)", (encoded,))
            self.assertTrue(has_external_dom_reference(db, map_record.map_id))
            encoded_key = json.dumps({map_record.map_id: 1}).replace(
                "DOMMAP-", "\\u0044OMMAP-", 1)
            db.execute("UPDATE fixture_dom_refs SET payload_json=?", (encoded_key,))
            self.assertTrue(has_external_dom_reference(db, map_record.map_id))
            db.execute("UPDATE fixture_dom_refs SET payload_json='not-json'")
            with self.assertRaisesRegex(DOMReferenceError, "incomplete"):
                has_external_dom_reference(db, map_record.map_id)

    def test_dom_payload_plan_requires_expiry_and_unlinked_owner(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        parent = dom.record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/parent.js",
            body=b"console.log('parent')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        source_map = dom.record_source_map(
            target_id=package.target.id, js_artifact_id=parent.artifact_id,
            map_url="https://app.example.test/parent.js.map", body=b"{}",
            source="FIXTURE")
        standalone = dom.record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/standalone.js",
            body=b"console.log('standalone')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        planner = DOMPayloadPlanner(self.store, DOMPayloadPolicy(max_scan_entries=10,
                                                                 max_candidates=10))
        future = self.now + 91 * 86400
        self.assertEqual(planner.plan("JS", now=self.now).candidates, ())
        js_plan = planner.plan("JS", now=future)
        self.assertEqual([item.owner_id for item in js_plan.candidates], [standalone.artifact_id])
        self.assertEqual(js_plan.to_dict()["candidate_bytes"], len(b"console.log('standalone')"))
        self.assertEqual([item.owner_id for item in planner.plan("SOURCE_MAP", now=future).candidates],
                         [source_map.map_id])
        self.assertTrue(self.artifacts.path_for(standalone.artifact_sha256).is_file())

        self.store.set_retention(standalone.evidence_id, Retention(retain=True, pinned=True),
                                 actor="fixture", reason="preserve")
        self.assertEqual(planner.plan("JS", now=future).candidates, ())
        with self.store._connection() as db:
            db.execute(
                "INSERT INTO planner_runs "
                "(run_id,target_id,package_id,package_version,policy_hash,mode,status,"
                "limits_json,usage_json,planner_version,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                ("PLRUN-" + "1" * 32, package.target.id, package.id, 1, "fixture",
                 "ANALYZE_ONLY", "RUNNING", "{}", "{}", "fixture",
                 datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
            )
        self.assertEqual(planner.plan("SOURCE_MAP", now=future).candidates, ())
        with self.store._connection() as db:
            db.execute("DELETE FROM planner_runs WHERE run_id=?", ("PLRUN-" + "1" * 32,))
        self.assertEqual([item.owner_id for item in planner.plan("SOURCE_MAP", now=future).candidates],
                         [source_map.map_id])
        with self.store._connection() as db:
            db.execute(
                "INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                ("PRINCIPAL-" + "2" * 32, package.target.id, "fixture", None,
                 "OBSERVED", json.dumps([source_map.evidence_id]), None, None,
                 datetime.now(timezone.utc).isoformat()),
            )
        self.assertEqual(planner.plan("SOURCE_MAP", now=future).candidates, ())

    def test_dom_payload_plan_pages_and_fails_closed_on_unknown_links(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        assets = [dom.record_artifact(
            target_id=package.target.id, asset_url=f"https://app.example.test/{index}.js",
            body=f"console.log({index})".encode(), recon_asset_id=None,
            recon_sha256=None, source="FIXTURE") for index in range(2)]
        future = self.now + 91 * 86400
        planner = DOMPayloadPlanner(self.store, DOMPayloadPolicy(max_scan_entries=1,
                                                                 max_candidates=1))
        first = planner.plan("JS", now=future)
        second = planner.plan("JS", after=first.next_after, now=future)
        self.assertTrue(first.truncated)
        self.assertFalse(second.truncated)
        self.assertEqual({item.owner_id for item in first.candidates + second.candidates},
                         {item.artifact_id for item in assets})
        with self.assertRaisesRegex(ValueError, "cursor"):
            planner.plan("JS", after="not-an-asset", now=future)
        with self.store._connection() as db:
            db.execute("CREATE TABLE fixture_dom_links (payload_json TEXT NOT NULL)")
            db.execute("INSERT INTO fixture_dom_links VALUES ('not-json')")
        with self.assertRaisesRegex(ValueError, "guard inventory is incomplete"):
            DOMPayloadPlanner(self.store, DOMPayloadPolicy(max_scan_entries=10,
                                                            max_candidates=10)).plan(
                                                                "JS", now=future)

    def test_cli_dom_retention_is_read_only(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        asset = DOMXSSStore(self.store).record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/cli.js",
            body=b"console.log('cli')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        config = self.root / "config.toml"
        config.write_text(
            f'[paths]\nroot = "{self.root}"\n'
            f'[store]\nartifact_root = "{self.artifacts.root}"\n'
            '[retention]\norphan_grace_hours = 24\n', encoding="utf-8")
        with patch("hackbot.dom_retention.time.time", return_value=self.now + 91 * 86400):
            out, err = StringIO(), StringIO()
            self.assertEqual(main(["--config", str(config), "retention", "dom-plan",
                                   "--kind", "JS"], stdout=out, stderr=err), 0, err.getvalue())
        result = json.loads(out.getvalue())
        self.assertEqual(result["owner_ids"], [asset.artifact_id])
        self.assertTrue(result["dry_run"])
        self.assertTrue(self.artifacts.path_for(asset.artifact_sha256).is_file())

    def test_dom_review_retires_only_expired_unlinked_evidence(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        asset = dom.record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/retire.js",
            body=b"console.log('retire')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        future = self.now + 91 * 86400
        manager = DOMPayloadRetirementManager(
            self.store, DOMPayloadPolicy(max_scan_entries=10, max_candidates=10),
            audit_path=self.root / "logs" / "dom-retirement-audit.jsonl")
        self.assertEqual([item.owner_id for item in manager.plan("JS", now=future).candidates],
                         [asset.artifact_id])
        with self.assertRaisesRegex(ValueError, "explicit confirmation"):
            manager.run("JS", confirmed=False, now=future)
        result = manager.run("JS", confirmed=True, now=future)
        self.assertEqual(result["retired"], 1)
        self.assertIsNone(dom.get_asset(package.target.id, asset.artifact_id))
        with self.assertRaises(FileNotFoundError):
            self.store.read_content(asset.evidence_id, allow_sensitive=True)
        self.assertTrue(self.artifacts.path_for(asset.artifact_sha256).is_file())
        with self.assertRaisesRegex(ValueError, "recent matching review"):
            manager.run("JS", confirmed=True, now=future)
        audit = [json.loads(line) for line in manager.audit_path.read_text().splitlines()]
        self.assertEqual([item["stage"] for item in audit], ["STARTED", "COMPLETED"])

    def test_dom_review_rechecks_new_reference_and_pin(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        asset = dom.record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/linked.js",
            body=b"console.log('linked')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        future = self.now + 91 * 86400
        manager = DOMPayloadRetirementManager(
            self.store, DOMPayloadPolicy(max_scan_entries=10, max_candidates=10))
        self.assertEqual(len(manager.plan("JS", now=future).candidates), 1)
        with self.store._connection() as db:
            db.execute(
                "INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                ("PRINCIPAL-" + "4" * 32, package.target.id, "fixture", None,
                 "OBSERVED", json.dumps([asset.evidence_id]), None, None,
                 datetime.now(timezone.utc).isoformat()),
            )
        self.assertEqual(manager.run("JS", confirmed=True, now=future)["retired"], 0)
        self.assertIsNotNone(dom.get_asset(package.target.id, asset.artifact_id))
        with self.store._connection() as db:
            db.execute("DELETE FROM registry_principals WHERE principal_id=?",
                       ("PRINCIPAL-" + "4" * 32,))
        self.assertEqual(len(manager.plan("JS", now=future).candidates), 1)
        with self.store._connection() as db:
            db.execute(
                "INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                ("PRINCIPAL-" + "5" * 32, package.target.id, "fixture", None,
                 "OBSERVED", json.dumps([asset.artifact_id]), None, None,
                 datetime.now(timezone.utc).isoformat()),
            )
        self.assertEqual(manager.run("JS", confirmed=True, now=future)["retired"], 0)
        with self.store._connection() as db:
            db.execute("DELETE FROM registry_principals WHERE principal_id=?",
                       ("PRINCIPAL-" + "5" * 32,))
        self.assertEqual(len(manager.plan("JS", now=future).candidates), 1)
        self.store.set_retention(asset.evidence_id, Retention(retain=True, pinned=True),
                                 actor="fixture", reason="preserve")
        self.assertEqual(manager.run("JS", confirmed=True, now=future)["retired"], 0)
        self.assertIsNotNone(dom.get_asset(package.target.id, asset.artifact_id))

    def test_dom_source_map_retirement_preserves_parent_and_rehydrates(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        asset = dom.record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/map-parent.js",
            body=b"console.log('parent')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        source_map = dom.record_source_map(
            target_id=package.target.id, js_artifact_id=asset.artifact_id,
            map_url="https://app.example.test/map-parent.js.map", body=b"{}",
            source="FIXTURE")
        future = self.now + 91 * 86400
        manager = DOMPayloadRetirementManager(self.store)
        self.assertEqual([item.owner_id for item in manager.plan(
            "SOURCE_MAP", now=future).candidates], [source_map.map_id])
        self.assertEqual(manager.run("SOURCE_MAP", confirmed=True, now=future)["retired"], 1)
        self.assertIsNone(dom.get_source_map_by_id(package.target.id, source_map.map_id))
        self.assertIsNotNone(dom.get_asset(package.target.id, asset.artifact_id))
        self.assertTrue(self.artifacts.path_for(source_map.map_sha256).is_file())
        refreshed = dom.record_source_map(
            target_id=package.target.id, js_artifact_id=asset.artifact_id,
            map_url="https://app.example.test/map-parent.js.map", body=b"{}",
            source="FIXTURE")
        self.assertEqual(refreshed.map_id, source_map.map_id)
        self.assertNotEqual(refreshed.evidence_id, source_map.evidence_id)
        self.assertIsNotNone(dom.get_source_map_by_id(package.target.id, source_map.map_id))

    def test_retired_dom_owner_rejects_late_direct_and_escaped_json_links(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        url = "https://app.example.test/guarded.js"
        body = b"console.log('guarded')"
        asset = dom.record_artifact(
            target_id=package.target.id, asset_url=url, body=body,
            recon_asset_id=None, recon_sha256=None, source="FIXTURE")
        future = self.now + 91 * 86400
        manager = DOMPayloadRetirementManager(self.store)
        self.assertEqual(len(manager.plan("JS", now=future).candidates), 1)
        self.assertEqual(manager.run("JS", confirmed=True, now=future)["retired"], 1)
        with self.store._connection() as db:
            verify_dom_retirement_guards(db)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "retired DOM payload"):
                db.execute(
                    "INSERT INTO dom_analysis_runs "
                    "(analysis_id,target_id,artifact_id,analyzer_version,status,"
                    "parse_errors,candidate_count,analyzed_at) VALUES (?,?,?,?,?,?,?,?)",
                    ("DOMAN-" + "1" * 32, package.target.id, asset.artifact_id,
                     "fixture", "DONE", 0, 0, datetime.now(timezone.utc).isoformat()),
                )
            encoded = json.dumps([asset.artifact_id]).replace(
                "DOMART-", "\\u0044OMART-", 1)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "retired DOM payload"):
                db.execute(
                    "INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                    ("PRINCIPAL-" + "6" * 32, package.target.id, "fixture", None,
                     "OBSERVED", encoded, None, None,
                     datetime.now(timezone.utc).isoformat()),
                )
            encoded_key = json.dumps({asset.artifact_id: 1}).replace(
                "DOMART-", "\\u0044OMART-", 1)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "retired DOM payload"):
                db.execute(
                    "INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                    ("PRINCIPAL-" + "7" * 32, package.target.id, "fixture", None,
                     "OBSERVED", encoded_key, None, None,
                     datetime.now(timezone.utc).isoformat()),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "retired DOM payload"):
                db.execute(
                    "INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                    ("PRINCIPAL-" + "8" * 32, package.target.id, asset.artifact_id,
                     None, "OBSERVED", "[]", None, None,
                     datetime.now(timezone.utc).isoformat()),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "retired DOM payload"):
                db.execute(
                    "INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                    ("PRINCIPAL-" + "9" * 32, package.target.id, "fixture", None,
                     "OBSERVED", "{invalid-json", None, None,
                     datetime.now(timezone.utc).isoformat()),
                )
            db.execute(
                "INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                ("PRINCIPAL-" + "a" * 32, package.target.id, "ordinary text", None,
                 "OBSERVED", "[]", None, None,
                 datetime.now(timezone.utc).isoformat()),
            )
        refreshed = dom.record_artifact(
            target_id=package.target.id, asset_url=url, body=body,
            recon_asset_id=None, recon_sha256=None, source="FIXTURE")
        self.assertEqual(refreshed.artifact_id, asset.artifact_id)
        self.assertNotEqual(refreshed.evidence_id, asset.evidence_id)
        with self.store._connection() as db:
            db.execute(
                "INSERT INTO dom_analysis_runs "
                "(analysis_id,target_id,artifact_id,analyzer_version,status,"
                "parse_errors,candidate_count,analyzed_at) VALUES (?,?,?,?,?,?,?,?)",
                ("DOMAN-" + "1" * 32, package.target.id, asset.artifact_id,
                 "fixture", "DONE", 0, 0, datetime.now(timezone.utc).isoformat()),
            )

    def test_dom_guard_inventory_detects_drift_and_migrates_from_45(self):
        with self.store._connection() as db:
            verify_dom_retirement_guards(db)
            db.execute("CREATE TABLE fixture_unreviewed_dom_links (asset_id TEXT)")
            with self.assertRaisesRegex(ValueError, "inventory is incomplete"):
                verify_dom_retirement_guards(db)
            db.execute("DROP TABLE fixture_unreviewed_dom_links")
            drop_dom_retirement_guards(db)
            db.execute("PRAGMA user_version=45")
        self.store.initialize(allow_existing_migration=True)
        with self.store._connection() as db:
            verify_dom_retirement_guards(db)
            db.execute("DROP TRIGGER retired_dom_link_dom_analysis_runs_insert")
            with self.assertRaisesRegex(ValueError, "link guards are incomplete"):
                verify_dom_retirement_guards(db)

    def test_reviewed_gc_reclaims_retired_map_and_preserves_active_parent(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        asset = dom.record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/gc.js",
            body=b"console.log('gc')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        source_map = dom.record_source_map(
            target_id=package.target.id, js_artifact_id=asset.artifact_id,
            map_url="https://app.example.test/gc.js.map", body=b'{"version":3}',
            source="FIXTURE")
        future = self.now + 91 * 86400
        retirement = DOMPayloadRetirementManager(self.store)
        self.assertEqual(len(retirement.plan("SOURCE_MAP", now=future).candidates), 1)
        self.assertEqual(retirement.run("SOURCE_MAP", confirmed=True, now=future)["retired"], 1)
        collector = ArtifactGarbageCollector(self.store, OrphanPolicy(max_scan_entries=10))
        preview = collector.plan(now=future)
        self.assertEqual(preview.digests, (source_map.map_sha256,))
        self.assertNotIn(asset.artifact_sha256, preview.digests)
        self.assertEqual(collector.run(confirmed=True, now=future)["removed"], 1)
        self.assertFalse(self.artifacts.path_for(source_map.map_sha256).exists())
        self.assertTrue(self.artifacts.path_for(asset.artifact_sha256).is_file())
        refreshed = dom.record_source_map(
            target_id=package.target.id, js_artifact_id=asset.artifact_id,
            map_url="https://app.example.test/gc.js.map", body=b'{"version":3}',
            source="FIXTURE")
        self.assertEqual(refreshed.map_id, source_map.map_id)
        self.assertNotEqual(refreshed.evidence_id, source_map.evidence_id)
        self.assertTrue(self.artifacts.path_for(source_map.map_sha256).is_file())

    def test_gc_holds_digest_shared_with_active_map(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        parents = [dom.record_artifact(
            target_id=package.target.id,
            asset_url=f"https://app.example.test/shared-{index}.js",
            body=f"console.log({index})".encode(), recon_asset_id=None,
            recon_sha256=None, source="FIXTURE") for index in range(2)]
        maps = [dom.record_source_map(
            target_id=package.target.id, js_artifact_id=parent.artifact_id,
            map_url=f"https://app.example.test/shared-{index}.js.map",
            body=b'{"version":3,"same":true}', source="FIXTURE")
            for index, parent in enumerate(parents)]
        self.assertEqual(maps[0].map_sha256, maps[1].map_sha256)
        future = self.now + 91 * 86400
        self.store.set_retention(maps[1].evidence_id, Retention(retain=True, pinned=True),
                                 actor="fixture", reason="hold-shared-map")
        retirement = DOMPayloadRetirementManager(self.store)
        self.assertEqual([item.owner_id for item in retirement.plan(
            "SOURCE_MAP", now=future).candidates], [maps[0].map_id])
        self.assertEqual(retirement.run("SOURCE_MAP", confirmed=True, now=future)["retired"], 1)
        collector = ArtifactGarbageCollector(self.store, OrphanPolicy(max_scan_entries=10))
        self.assertNotIn(maps[0].map_sha256, collector.plan(now=future).digests)
        self.assertTrue(self.artifacts.path_for(maps[0].map_sha256).is_file())
        self.store.set_retention(
            maps[1].evidence_id,
            Retention(retain=True, expires_at=datetime.fromtimestamp(
                future - 86400, timezone.utc)), actor="fixture", reason="release-shared-map")
        self.assertEqual([item.owner_id for item in retirement.plan(
            "SOURCE_MAP", now=future).candidates], [maps[1].map_id])
        self.assertEqual(retirement.run("SOURCE_MAP", confirmed=True, now=future)["retired"], 1)
        self.assertIn(maps[0].map_sha256, collector.plan(now=future).digests)

    def test_reviewed_gc_reclaims_unlinked_retired_js_and_allows_refetch(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        dom = DOMXSSStore(self.store)
        url = "https://app.example.test/expired-standalone.js"
        body = b"console.log('expired')"
        asset = dom.record_artifact(
            target_id=package.target.id, asset_url=url, body=body,
            recon_asset_id=None, recon_sha256=None, source="FIXTURE")
        future = self.now + 91 * 86400
        retirement = DOMPayloadRetirementManager(self.store)
        self.assertEqual(len(retirement.plan("JS", now=future).candidates), 1)
        self.assertEqual(retirement.run("JS", confirmed=True, now=future)["retired"], 1)
        collector = ArtifactGarbageCollector(self.store, OrphanPolicy(max_scan_entries=10))
        self.assertEqual(collector.plan(now=future).digests, (asset.artifact_sha256,))
        self.assertEqual(collector.run(confirmed=True, now=future)["removed"], 1)
        self.assertFalse(self.artifacts.path_for(asset.artifact_sha256).exists())
        refreshed = dom.record_artifact(
            target_id=package.target.id, asset_url=url, body=body,
            recon_asset_id=None, recon_sha256=None, source="FIXTURE")
        self.assertEqual(refreshed.artifact_id, asset.artifact_id)
        self.assertNotEqual(refreshed.evidence_id, asset.evidence_id)
        self.assertTrue(self.artifacts.path_for(asset.artifact_sha256).is_file())

    def test_dom_review_is_kind_bound_short_lived_and_private(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        asset = DOMXSSStore(self.store).record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/review.js",
            body=b"console.log('review')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        future = self.now + 91 * 86400
        manager = DOMPayloadRetirementManager(self.store)
        manager.plan("JS", now=future)
        self.assertEqual(manager.review_path.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ValueError, "recent matching review"):
            manager.run("SOURCE_MAP", confirmed=True, now=future)
        with self.assertRaisesRegex(ValueError, "recent matching review"):
            manager.run("JS", confirmed=True, now=future + 901)
        self.assertIsNotNone(DOMXSSStore(self.store).get_asset(package.target.id,
                                                               asset.artifact_id))

    def test_cli_dom_run_requires_review_and_confirmation(self):
        package = load_target_package(Path(__file__).parent / "examples/targets/example")
        IdentityRegistry(self.store).register_target(package)
        asset = DOMXSSStore(self.store).record_artifact(
            target_id=package.target.id, asset_url="https://app.example.test/cli-retire.js",
            body=b"console.log('cli-retire')", recon_asset_id=None,
            recon_sha256=None, source="FIXTURE")
        config = self.root / "config.toml"
        config.write_text(
            f'[paths]\nroot = "{self.root}"\n'
            f'[store]\nartifact_root = "{self.artifacts.root}"\n'
            '[retention]\norphan_grace_hours = 24\n', encoding="utf-8")
        future = self.now + 91 * 86400
        with patch("hackbot.dom_retention.time.time", return_value=future):
            out, err = StringIO(), StringIO()
            self.assertEqual(main(["--config", str(config), "retention", "dom-run",
                                   "--kind", "JS", "--confirmed"], stdout=out, stderr=err), 2)
            self.assertEqual(main(["--config", str(config), "retention", "dom-plan",
                                   "--kind", "JS"], stdout=StringIO(), stderr=StringIO()), 0)
            self.assertEqual(main(["--config", str(config), "retention", "dom-run",
                                   "--kind", "JS"], stdout=StringIO(), stderr=StringIO()), 2)
            out, err = StringIO(), StringIO()
            self.assertEqual(main(["--config", str(config), "retention", "dom-run",
                                   "--kind", "JS", "--confirmed"], stdout=out, stderr=err),
                             0, err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["retired"], 1)
        self.assertTrue(self.artifacts.path_for(asset.artifact_sha256).is_file())

    def test_retired_evidence_reference_lookup_streams_rows(self):
        class RetiredRows:
            def __iter__(self):
                yield ("EV-" + "a" * 32,)
                yield ("EV-" + "b" * 32,)

            def fetchall(self):
                raise AssertionError("retired Evidence rows must not be materialized")

        class NoLiveRows:
            def fetchone(self):
                return None

            def fetchall(self):
                return []

        class Database:
            def execute(self, statement, _params=()):
                return RetiredRows() if "JOIN evidence_payload_retirements" in statement else NoLiveRows()

        with patch("hackbot.retention.EVIDENCE_ARTIFACT_REFERENCES",
                   (("evidence", "artifact_hash"),)), patch(
                       "hackbot.retention.has_evidence_reference", return_value=False
                   ) as lookup:
            self.assertFalse(ArtifactGarbageCollector._referenced(Database(), "a" * 64))
        self.assertEqual(lookup.call_count, 2)

    def test_dry_run_and_cleanup_preserve_pinned_and_shared_artifacts(self):
        orphan = self.artifacts.put_bytes(b"abandoned-cache")
        orphan_path = self._old(orphan.sha256)
        pinned = self._evidence(b"confirmed-finding-proof", pinned=True)
        pinned_path = self._old(pinned.content_hash)
        shared = self._evidence(b"shared-proof")
        self._evidence(b"shared-proof")
        shared_path = self._old(shared.content_hash)
        manager = ArtifactGarbageCollector(self.store, OrphanPolicy(),
                                           self.root / "logs" / "retention-audit.jsonl")
        plan = manager.plan(now=self.now)
        self.assertEqual(plan.digests, (orphan.sha256,))
        self.assertEqual(plan.estimated_bytes, len(b"abandoned-cache"))
        self.assertTrue(orphan_path.exists())
        with self.assertRaisesRegex(ValueError, "explicit confirmation"):
            manager.run(confirmed=False, now=self.now)
        result = manager.run(confirmed=True, now=self.now)
        self.assertEqual(result["removed"], 1)
        self.assertFalse(orphan_path.exists())
        self.assertTrue(pinned_path.is_file())
        self.assertTrue(shared_path.is_file())
        self.assertEqual(self.store.read_content(pinned.evidence_id), b"confirmed-finding-proof")
        self.assertEqual(self.store.read_content(shared.evidence_id), b"shared-proof")
        audit = [json.loads(line) for line in
                 (self.root / "logs" / "retention-audit.jsonl").read_text().splitlines()]
        self.assertEqual([entry["stage"] for entry in audit], ["STARTED", "COMPLETED"])
        self.assertEqual(audit[0]["operation_id"], audit[1]["operation_id"])
        self.assertEqual(audit[-1]["removed"], 1)

    def test_cleanup_scans_before_write_transaction_and_rechecks_guards(self):
        orphan = self.artifacts.put_bytes(b"scan-before-write-lock")
        self._old(orphan.sha256)
        manager = ArtifactGarbageCollector(self.store)
        manager.plan(now=self.now)
        original = manager._verify_reference_guards
        phases = []

        def record_guards(db):
            phases.append(db.in_transaction)
            return original(db)

        with patch.object(ArtifactGarbageCollector, "_verify_reference_guards",
                          staticmethod(record_guards)):
            result = manager.run(confirmed=True, now=self.now)
        self.assertEqual(phases, [False, True])
        self.assertEqual(result["removed"], 1)

    def test_cleanup_preserves_reference_added_after_preflight_scan(self):
        orphan = self.artifacts.put_bytes(b"late-reference")
        path = self._old(orphan.sha256)
        manager = ArtifactGarbageCollector(self.store)
        manager.plan(now=self.now)
        original = manager._candidates

        def add_late_reference(db, cutoff, after=None):
            self.assertFalse(db.in_transaction)
            selected = original(db, cutoff, after)
            self.assertIn(orphan.sha256, selected[0])
            stamp = datetime.now(timezone.utc).isoformat()
            with sqlite3.connect(self.store.db_path) as other:
                other.execute(
                    "INSERT INTO evidence (evidence_id,evidence_type,target_ref,observed_at,"
                    "created_at,source,content_hash,content_kind,content_size,inline_content,"
                    "artifact_hash,metadata_json,sensitivity,redaction_status,provenance_json,"
                    "replaces_evidence_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    ("EV-" + "e" * 32, "RECON_RECORD", None, stamp, stamp, "FIXTURE",
                     orphan.sha256, "ARTIFACT", len(b"late-reference"), None,
                     orphan.sha256, "{}", "INTERNAL", "ORIGINAL", "{}", None),
                )
            return selected

        with patch.object(manager, "_candidates", side_effect=add_late_reference):
            result = manager.run(confirmed=True, now=self.now)
        self.assertEqual(result["removed"], 0)
        self.assertTrue(path.is_file())

    def test_recent_orphan_is_not_removed(self):
        fresh = self.artifacts.put_bytes(b"recent")
        manager = ArtifactGarbageCollector(self.store)
        self.assertEqual(manager.plan(now=self.now).digests, ())
        self.assertTrue(self.artifacts.path_for(fresh.sha256).exists())

    def test_confirmed_cleanup_does_not_expand_beyond_reviewed_plan(self):
        first = self.artifacts.put_bytes(b"reviewed-orphan")
        first_path = self._old(first.sha256)
        manager = ArtifactGarbageCollector(self.store)
        reviewed = manager.plan(now=self.now)
        later = self.artifacts.put_bytes(b"newly-eligible-orphan")
        later_path = self._old(later.sha256)
        result = manager.run(confirmed=True, now=self.now, approved_plan=reviewed)
        self.assertEqual(result["removed"], 1)
        self.assertFalse(first_path.exists())
        self.assertTrue(later_path.exists())

    def test_bounded_scan_advances_past_referenced_prefix_across_instances(self):
        bodies = [f"scan-window-{index}".encode() for index in range(5)]
        ordered = sorted((self.artifacts.put_bytes(body).sha256, body) for body in bodies)
        for _, body in ordered[:2]:
            self._evidence(body)
        orphan_path = self._old(ordered[2][0])
        policy = OrphanPolicy(max_scan_entries=2)
        first = ArtifactGarbageCollector(self.store, policy).plan(now=self.now)
        self.assertEqual(first.digests, ())
        self.assertTrue(first.truncated)
        self.assertEqual(first.scanned, 2)
        second_manager = ArtifactGarbageCollector(self.store, policy)
        second = second_manager.plan(now=self.now)
        self.assertEqual(second.digests, (ordered[2][0],))
        self.assertTrue(second.truncated)
        result = second_manager.run(confirmed=True, now=self.now, approved_plan=second)
        self.assertEqual(result["removed"], 1)
        self.assertFalse(orphan_path.exists())

    def test_scan_cursor_pages_within_one_large_hash_bucket(self):
        by_bucket = {}
        for index in range(5000):
            body = f"same-bucket-{index}".encode()
            digest = hashlib.sha256(body).hexdigest()
            group = by_bucket.setdefault(digest[:2], [])
            group.append((digest, body))
            if len(group) == 4:
                break
        else:
            self.fail("Could not form a deterministic hash-bucket fixture")
        ordered = sorted(group)
        for _, body in ordered:
            self.artifacts.put_bytes(body)
        for _, body in ordered[:2]:
            self._evidence(body)
        orphan_path = self._old(ordered[2][0])
        policy = OrphanPolicy(max_scan_entries=2)
        self.assertEqual(ArtifactGarbageCollector(self.store, policy).plan(now=self.now).digests, ())
        reviewed = ArtifactGarbageCollector(self.store, policy).plan(now=self.now)
        self.assertEqual(reviewed.digests, (ordered[2][0],))
        self.assertEqual(ArtifactGarbageCollector(self.store, policy).run(
            confirmed=True, now=self.now, approved_plan=reviewed)["removed"], 1)
        self.assertFalse(orphan_path.exists())

    def test_artifact_scan_deadline_fails_closed_and_invalidates_old_review(self):
        orphan = self.artifacts.put_bytes(b"deadline-orphan")
        orphan_path = self._old(orphan.sha256)
        policy = OrphanPolicy(max_scan_seconds=30)
        manager = ArtifactGarbageCollector(self.store, policy)
        reviewed = manager.plan(now=self.now)
        self.assertEqual(reviewed.digests, (orphan.sha256,))

        ticks = iter([0.0] * 4 + [31.0] * 100)
        with patch("hackbot.retention.time.monotonic", side_effect=ticks):
            with self.assertRaisesRegex(ValueError, "deadline exceeded"):
                manager.plan(now=self.now)
        self.assertTrue(orphan_path.exists())
        with self.assertRaisesRegex(ValueError, "recent dry-run review"):
            manager.run(confirmed=True, now=self.now)
        with self.assertRaisesRegex(ValueError, "recent dry-run review"):
            manager.run(confirmed=True, now=self.now, approved_plan=reviewed)

    def test_artifact_cleanup_deadline_never_unlinks_reviewed_file(self):
        orphan = self.artifacts.put_bytes(b"deadline-reviewed")
        orphan_path = self._old(orphan.sha256)
        policy = OrphanPolicy(max_scan_seconds=30)
        manager = ArtifactGarbageCollector(self.store, policy)
        manager.plan(now=self.now)

        ticks = iter([0.0] * 4 + [31.0] * 100)
        with patch("hackbot.retention.time.monotonic", side_effect=ticks):
            with self.assertRaisesRegex(ValueError, "deadline exceeded"):
                manager.run(confirmed=True, now=self.now)
        self.assertTrue(orphan_path.exists())
        self.assertEqual(manager.run(confirmed=True, now=self.now)["removed"], 1)

    def test_artifact_scan_deadline_policy_rejects_invalid_limits(self):
        for value in (0, 301, True, "30"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                OrphanPolicy(max_scan_seconds=value)

    def test_approved_artifact_plan_must_match_current_review(self):
        first = self.artifacts.put_bytes(b"first-review")
        second = self.artifacts.put_bytes(b"second-review")
        first_path = self._old(first.sha256)
        second_path = self._old(second.sha256)
        manager = ArtifactGarbageCollector(self.store, OrphanPolicy(max_delete_files=1))
        initial = manager.plan(now=self.now)
        current = manager.plan(now=self.now)
        self.assertNotEqual(initial.digests, current.digests)
        with self.assertRaisesRegex(ValueError, "does not match"):
            manager.run(confirmed=True, now=self.now, approved_plan=initial)
        self.assertTrue(first_path.exists())
        self.assertTrue(second_path.exists())

    def test_run_uses_last_reviewed_window_and_only_reviewed_candidates(self):
        policy = OrphanPolicy(max_scan_entries=2)
        first = self.artifacts.put_bytes(b"reviewed-window")
        first_path = self._old(first.sha256)
        manager = ArtifactGarbageCollector(self.store, policy)
        reviewed = manager.plan(now=self.now)
        self.assertEqual(reviewed.digests, (first.sha256,))
        second = self.artifacts.put_bytes(b"not-in-reviewed-window")
        second_path = self._old(second.sha256)
        result = ArtifactGarbageCollector(self.store, policy).run(
            confirmed=True, now=self.now)
        self.assertEqual(result["removed"], 1)
        self.assertFalse(first_path.exists())
        self.assertTrue(second_path.exists())
        with self.assertRaisesRegex(ValueError, "recent dry-run review"):
            manager.run(confirmed=True, now=self.now)

    def test_run_requires_recent_review(self):
        orphan = self.artifacts.put_bytes(b"review-required")
        path = self._old(orphan.sha256)
        manager = ArtifactGarbageCollector(self.store)
        with self.assertRaisesRegex(ValueError, "recent dry-run review"):
            manager.run(confirmed=True, now=self.now)
        manager.plan(now=self.now - 901)
        with self.assertRaisesRegex(ValueError, "recent dry-run review"):
            manager.run(confirmed=True, now=self.now)
        self.assertTrue(path.exists())

    def test_unsafe_scan_cursor_blocks_cleanup(self):
        orphan = self.artifacts.put_bytes(b"cursor-must-fail-closed")
        path = self._old(orphan.sha256)
        cursor = self.store.db_path.parent / "artifact-scan-cursor.json"
        cursor.symlink_to(self.root / "outside-cursor")
        manager = ArtifactGarbageCollector(self.store)
        with self.assertRaisesRegex(ValueError, "scan cursor"):
            manager.plan(now=self.now)
        with self.assertRaisesRegex(ValueError, "scan cursor"):
            manager.run(confirmed=True, now=self.now)
        self.assertTrue(path.exists())

    def test_aged_temporary_file_is_reviewed_and_removed_but_recent_one_survives(self):
        artifact = self.artifacts.put_bytes(b"referenced-proof")
        self._evidence(b"referenced-proof", pinned=True)
        bucket = self.artifacts.path_for(artifact.sha256).parent
        old = bucket / ".tmp-Abcdef12"
        old.write_bytes(b"abandoned-sensitive-fixture")
        os.utime(old, (self.now - 172800, self.now - 172800))
        recent = bucket / ".tmp-Qwerty34"
        recent.write_bytes(b"in-progress")
        manager = ArtifactGarbageCollector(self.store, OrphanPolicy())
        plan = manager.plan(now=self.now)
        self.assertEqual(plan.digests, ())
        self.assertEqual(plan.temporary_files, (f"{bucket.name}/{old.name}",))
        self.assertEqual(plan.to_dict()["candidate_count"], 1)
        self.assertTrue(old.exists())
        result = manager.run(confirmed=True, now=self.now)
        self.assertEqual(result["removed"], 1)
        self.assertFalse(old.exists())
        self.assertTrue(recent.exists())
        self.assertTrue(self.artifacts.path_for(artifact.sha256).exists())

    def test_failed_pre_delete_audit_preserves_orphan(self):
        orphan = self.artifacts.put_bytes(b"must-survive-audit-error")
        path = self._old(orphan.sha256)
        log = self.root / "logs" / "audit.jsonl"
        log.parent.mkdir()
        log.symlink_to(self.root / "outside")
        manager = ArtifactGarbageCollector(self.store, OrphanPolicy(), log)
        manager.plan(now=self.now)
        with self.assertRaisesRegex(ValueError, "Unsafe maintenance audit path"):
            manager.run(confirmed=True, now=self.now)
        self.assertTrue(path.exists())

    def test_unknown_artifact_digest_column_blocks_cleanup(self):
        orphan = self.artifacts.put_bytes(b"retained-until-schema-reviewed")
        path = self._old(orphan.sha256)
        manager = ArtifactGarbageCollector(self.store)
        reviewed = manager.plan(now=self.now)
        with self.store._connection() as db:
            db.execute("CREATE TABLE new_artifact_owner (id INTEGER PRIMARY KEY, "
                       "cached_artifact_hash TEXT NOT NULL)")
            db.execute("INSERT INTO new_artifact_owner (cached_artifact_hash) VALUES (?)",
                       (orphan.sha256,))
        with self.assertRaisesRegex(ValueError, "reference schema"):
            manager.plan(now=self.now)
        with self.assertRaisesRegex(ValueError, "recent dry-run review"):
            manager.run(confirmed=True, now=self.now,
                        approved_plan=reviewed)
        self.assertTrue(path.exists())

    def test_evidence_reference_inventory_covers_direct_and_json_links(self):
        evidence = self._evidence(b"reference-graph-fixture")
        with self.store._connection() as db:
            direct, json_columns = evidence_reference_inventory(db)
            self.assertIn(("finding_evidence", "evidence_id"), direct)
            self.assertIn(("exposure_candidate_sources", "evidence_id"), direct)
            self.assertIn(("registry_principals", "evidence_ids_json"), json_columns)
            self.assertFalse(has_evidence_reference(db, evidence.evidence_id))
            db.execute("CREATE TABLE fixture_evidence_owner "
                       "(evidence_id TEXT REFERENCES evidence(evidence_id))")
            db.execute("INSERT INTO fixture_evidence_owner VALUES (?)", (evidence.evidence_id,))
            with self.assertRaisesRegex(EvidenceReferenceError, "direct reference schema requires review"):
                has_evidence_reference(db, evidence.evidence_id)
            db.execute("DROP TABLE fixture_evidence_owner")
            db.execute("INSERT INTO registry_targets(target_id,package_id,registered_at) VALUES (?,?,?)",
                       ("TARGET-fixture", "fixture-package", datetime.now(timezone.utc).isoformat()))
            db.execute("INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                       ("PRINCIPAL-fixture", "TARGET-fixture", "fixture", None, "OBSERVED",
                        json.dumps({"nested": [evidence.evidence_id]}), None, None,
                        datetime.now(timezone.utc).isoformat()))
            self.assertTrue(has_evidence_reference(db, evidence.evidence_id))
            db.execute("DELETE FROM registry_principals")
            db.execute("CREATE TABLE generic_payload (payload_json TEXT NOT NULL)")
            db.execute("INSERT INTO generic_payload VALUES (?)",
                       (json.dumps({"reference": evidence.evidence_id}),))
            with self.assertRaisesRegex(EvidenceReferenceError, "incomplete"):
                has_evidence_reference(db, evidence.evidence_id)
            db.execute("DROP TABLE generic_payload")
            escaped = json.dumps({"reference": evidence.evidence_id}).replace(
                "EV-", "\\u0045V-", 1)
            db.execute("INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                       ("PRINCIPAL-fixture", "TARGET-fixture", "fixture", None, "OBSERVED",
                        escaped, None, None, datetime.now(timezone.utc).isoformat()))
            self.assertTrue(has_evidence_reference(db, evidence.evidence_id))
            db.execute("UPDATE registry_principals SET evidence_ids_json='[]'")
            self.assertFalse(has_evidence_reference(db, evidence.evidence_id))

    def test_evidence_reference_check_fails_closed_on_unknown_or_invalid_json(self):
        evidence = self._evidence(b"reference-schema-fixture")
        with self.store._connection() as db:
            db.execute("CREATE TABLE future_refs (new_evidence_ids_json TEXT)")
            with self.assertRaisesRegex(EvidenceReferenceError, "schema requires review"):
                evidence_reference_inventory(db)
            db.execute("DROP TABLE future_refs")
            db.execute("CREATE TABLE unreviewed_direct (new_evidence_id TEXT)")
            with self.assertRaisesRegex(EvidenceReferenceError, "schema requires review"):
                evidence_reference_inventory(db)
            db.execute("DROP TABLE unreviewed_direct")
            db.execute("INSERT INTO registry_targets(target_id,package_id,registered_at) VALUES (?,?,?)",
                       ("TARGET-fixture", "fixture-package", datetime.now(timezone.utc).isoformat()))
            with self.assertRaisesRegex(sqlite3.IntegrityError, "invalid JSON reference column"):
                db.execute("INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                           ("PRINCIPAL-fixture", "TARGET-fixture", "fixture", None, "OBSERVED",
                            "{", None, None, datetime.now(timezone.utc).isoformat()))
            # Reconstruct schema 43 and simulate legacy corruption for its scan path.
            drop_evidence_json_index_schema(db)
            db.execute("DROP TRIGGER traffic_json_ref_registry_principals_insert")
            db.execute("PRAGMA user_version=43")
            db.execute("INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                       ("PRINCIPAL-fixture", "TARGET-fixture", "fixture", None, "OBSERVED",
                        "{", None, None, datetime.now(timezone.utc).isoformat()))
            with self.assertRaisesRegex(EvidenceReferenceError, "incomplete"):
                has_evidence_reference(db, evidence.evidence_id)

    def test_schema_43_upgrade_backfills_evidence_json_reference(self):
        evidence = self._evidence(b"schema43-evidence-reference")
        with sqlite3.connect(self.store.db_path) as db:
            drop_evidence_json_index_schema(db)
            db.execute("INSERT INTO registry_targets(target_id,package_id,registered_at) VALUES (?,?,?)",
                       ("TARGET-fixture", "fixture-package", datetime.now(timezone.utc).isoformat()))
            db.execute("INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                       ("PRINCIPAL-fixture", "TARGET-fixture", "fixture", None, "OBSERVED",
                        json.dumps([evidence.evidence_id]), None, None,
                        datetime.now(timezone.utc).isoformat()))
            db.execute("PRAGMA user_version=43")
        self.store.initialize(allow_existing_migration=True)
        with self.store._connection() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 51)
            self.assertEqual(db.execute(
                "SELECT ref_count FROM evidence_json_reference_counts WHERE ref_id=?",
                (evidence.evidence_id,),
            ).fetchone()[0], 1)
            self.assertTrue(has_evidence_reference(db, evidence.evidence_id))

    def test_schema_43_upgrade_refuses_invalid_json_without_advancing(self):
        with sqlite3.connect(self.store.db_path) as db:
            drop_evidence_json_index_schema(db)
            db.execute("DROP TRIGGER traffic_json_ref_registry_principals_insert")
            db.execute("INSERT INTO registry_targets(target_id,package_id,registered_at) VALUES (?,?,?)",
                       ("TARGET-fixture", "fixture-package", datetime.now(timezone.utc).isoformat()))
            db.execute("INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                       ("PRINCIPAL-fixture", "TARGET-fixture", "fixture", None, "OBSERVED",
                        "{", None, None, datetime.now(timezone.utc).isoformat()))
            db.execute("PRAGMA user_version=43")
        with self.assertRaisesRegex(StoreSchemaError, "Evidence JSON index cannot be built"):
            self.store.initialize(allow_existing_migration=True)
        with sqlite3.connect(self.store.db_path) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 43)

    def test_evidence_json_index_drift_blocks_reference_check(self):
        evidence = self._evidence(b"evidence-index-drift")
        with self.store._connection() as db:
            db.execute("DROP TRIGGER evidence_json_ref_registry_principals_update")
            with self.assertRaisesRegex(EvidenceReferenceError, "incomplete"):
                has_evidence_reference(db, evidence.evidence_id)

    def test_evidence_json_index_counts_repeated_ids_and_delete(self):
        evidence = self._evidence(b"evidence-index-counts")
        with self.store._connection() as db:
            db.execute("INSERT INTO registry_targets(target_id,package_id,registered_at) VALUES (?,?,?)",
                       ("TARGET-fixture", "fixture-package", datetime.now(timezone.utc).isoformat()))
            db.execute("INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                       ("PRINCIPAL-fixture", "TARGET-fixture", "fixture", None, "OBSERVED",
                        json.dumps([evidence.evidence_id, {"ref": evidence.evidence_id}]),
                        None, None, datetime.now(timezone.utc).isoformat()))
            self.assertEqual(db.execute(
                "SELECT ref_count FROM evidence_json_reference_counts WHERE ref_id=?",
                (evidence.evidence_id,),
            ).fetchone()[0], 2)
            db.execute("UPDATE registry_principals SET evidence_ids_json=?",
                       (json.dumps([evidence.evidence_id]),))
            self.assertEqual(db.execute(
                "SELECT ref_count FROM evidence_json_reference_counts WHERE ref_id=?",
                (evidence.evidence_id,),
            ).fetchone()[0], 1)
            db.execute("DELETE FROM registry_principals")
            self.assertFalse(has_evidence_reference(db, evidence.evidence_id))

    def test_missing_json_link_guard_blocks_retirement_reference_inventory(self):
        with self.store._connection() as db:
            db.execute("DROP TRIGGER retired_json_validations_insert")
            with self.assertRaisesRegex(EvidenceReferenceError, "guards are incomplete"):
                evidence_reference_inventory(db)

    def test_missing_direct_link_guard_blocks_retirement_reference_inventory(self):
        with self.store._connection() as db:
            db.execute("DROP TRIGGER retired_link_fact_evidence_insert")
            with self.assertRaisesRegex(EvidenceReferenceError, "direct link guards are incomplete"):
                evidence_reference_inventory(db)

    def test_new_direct_evidence_reference_requires_review(self):
        with self.store._connection() as db:
            db.execute("CREATE TABLE future_link (evidence_id TEXT REFERENCES evidence(evidence_id))")
            with self.assertRaisesRegex(EvidenceReferenceError, "direct reference schema requires review"):
                evidence_reference_inventory(db)

    def test_generated_digest_owner_is_not_hidden_from_schema_check(self):
        self.artifacts.put_bytes(b"generated-owner-fixture")
        with self.store._connection() as db:
            db.execute("CREATE TABLE generated_owner (raw_hash TEXT, "
                       "artifact_hash TEXT GENERATED ALWAYS AS (raw_hash) STORED)")
        with self.assertRaisesRegex(ValueError, "reference schema"):
            ArtifactGarbageCollector(self.store).plan(now=self.now)

    def test_expired_standalone_payload_retirement_preserves_shared_blob_until_final_owner(self):
        first = self._evidence(b"shared-retirable-payload")
        second = self._evidence(b"shared-retirable-payload")
        protected = self._evidence(b"pinned-durable-proof", pinned=True)
        digest_path = self._old(first.content_hash)
        self._old(protected.content_hash)
        self.store.set_retention(first.evidence_id, Retention(retain=False),
                                 actor="fixture", reason="ephemeral")
        instant = self.now + 172800
        manager = EvidencePayloadRetirementManager(self.store)
        plan = manager.plan(now=instant)
        self.assertEqual(plan.evidence_ids, (first.evidence_id,))
        self.assertEqual(plan.estimated_reclaimable_bytes, 0)
        with self.assertRaisesRegex(ValueError, "explicit confirmation"):
            manager.run(confirmed=False, now=instant)
        self.assertEqual(manager.run(confirmed=True, now=instant)["retired"], 1)
        self.assertEqual(ArtifactGarbageCollector(self.store).plan(now=instant).digests, ())
        self.assertEqual(self.store.read_content(second.evidence_id), b"shared-retirable-payload")
        with self.assertRaisesRegex(FileNotFoundError, "retired"):
            self.store.read_content(first.evidence_id)
        with self.assertRaisesRegex(ValueError, "Retired Evidence"):
            self.store.set_retention(first.evidence_id, Retention(retain=True),
                                     actor="fixture", reason="re-pin")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "retired Evidence"):
            with self.store._connection() as db:
                db.execute("INSERT INTO finding_evidence (finding_id,evidence_id) VALUES (?,?)",
                           ("F-unknown", first.evidence_id))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "retired Evidence"):
            with self.store._connection() as db:
                db.execute("INSERT INTO fact_evidence (fact_id,evidence_id) VALUES (?,?)",
                           ("FA-" + "0" * 32, first.evidence_id))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "retired Evidence"):
            with self.store._connection() as db:
                db.execute(
                    "INSERT INTO exposure_candidate_sources "
                    "(candidate_id,source_kind,source_ref,evidence_id,observed_at) "
                    "VALUES (?,?,?,?,?)",
                    ("EX-unknown", "FIXTURE", "fixture", first.evidence_id,
                     datetime.now(timezone.utc).isoformat()),
                )
        self.store.set_retention(second.evidence_id, Retention(retain=False),
                                 actor="fixture", reason="ephemeral")
        plan = manager.plan(now=instant)
        self.assertEqual(plan.evidence_ids, (second.evidence_id,))
        self.assertEqual(plan.estimated_reclaimable_bytes, len(b"shared-retirable-payload"))
        self.assertEqual(manager.run(confirmed=True, now=instant)["retired"], 1)
        collector = ArtifactGarbageCollector(self.store)
        self.assertEqual(collector.plan(now=instant).digests, (first.content_hash,))
        self.assertEqual(collector.run(confirmed=True, now=instant)["removed"], 1)
        self.assertFalse(digest_path.exists())
        self.assertEqual(self.store.read_content(protected.evidence_id), b"pinned-durable-proof")

    def test_evidence_retirement_rechecks_link_and_requires_recent_review(self):
        candidate = self._evidence(b"would-be-retired")
        self.store.set_retention(candidate.evidence_id, Retention(retain=False),
                                 actor="fixture", reason="ephemeral")
        instant = self.now + 172800
        manager = EvidencePayloadRetirementManager(self.store)
        with self.assertRaisesRegex(ValueError, "recent dry-run"):
            manager.run(confirmed=True, now=instant)
        self.assertEqual(manager.plan(now=instant).evidence_ids, (candidate.evidence_id,))
        with self.store._connection() as db:
            db.execute("CREATE TABLE fixture_evidence_link "
                       "(evidence_id TEXT REFERENCES evidence(evidence_id))")
            db.execute("INSERT INTO fixture_evidence_link VALUES (?)", (candidate.evidence_id,))
        with self.assertRaisesRegex(EvidenceReferenceError, "direct reference schema requires review"):
            manager.run(confirmed=True, now=instant)
        self.assertEqual(self.store.read_content(candidate.evidence_id), b"would-be-retired")
        with self.store._connection() as db:
            db.execute("DROP TABLE fixture_evidence_link")
        manager.plan(now=instant - 901)
        with self.assertRaisesRegex(ValueError, "recent dry-run"):
            manager.run(confirmed=True, now=instant)

    def test_late_reference_blocks_physical_gc_of_retired_evidence(self):
        candidate = self._evidence(b"retired-but-relinked")
        path = self._old(candidate.content_hash)
        self.store.set_retention(candidate.evidence_id, Retention(retain=False),
                                 actor="fixture", reason="ephemeral")
        instant = self.now + 172800
        retirement = EvidencePayloadRetirementManager(self.store)
        retirement.plan(now=instant)
        self.assertEqual(retirement.run(confirmed=True, now=instant)["retired"], 1)
        with self.store._connection() as db:
            db.execute("CREATE TABLE fixture_late_link "
                       "(evidence_id TEXT REFERENCES evidence(evidence_id))")
            db.execute("INSERT INTO fixture_late_link VALUES (?)", (candidate.evidence_id,))
        collector = ArtifactGarbageCollector(self.store)
        with self.assertRaisesRegex(EvidenceReferenceError, "direct reference schema requires review"):
            collector.plan(now=instant)
        self.assertTrue(path.exists())

    def test_retired_evidence_cannot_enter_named_json_reference_fields(self):
        candidate = self._evidence(b"json-retirement-link")
        self.store.set_retention(candidate.evidence_id, Retention(retain=False),
                                 actor="fixture", reason="ephemeral")
        instant = self.now + 172800
        manager = EvidencePayloadRetirementManager(self.store)
        manager.plan(now=instant)
        self.assertEqual(manager.run(confirmed=True, now=instant)["retired"], 1)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "retired Evidence"):
            with self.store._connection() as db:
                db.execute(
                    "INSERT INTO validations "
                    "(supporting_evidence_json,contradicting_evidence_json) VALUES (?,?)",
                    (json.dumps([candidate.evidence_id]), "[]"),
                )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "retired Evidence"):
            with self.store._connection() as db:
                db.execute(
                    "INSERT INTO test_objects (creation_evidence_json) VALUES (?)",
                    (json.dumps({"nested": [candidate.evidence_id]}),),
                )
        with self.store._connection() as db:
            db.execute("INSERT INTO registry_targets(target_id,package_id,registered_at) VALUES (?,?,?)",
                       ("TARGET-fixture", "fixture-package",
                        datetime.now(timezone.utc).isoformat()))
            db.execute("INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                       ("PRINCIPAL-fixture", "TARGET-fixture", "fixture", None, "OBSERVED",
                        "[]", None, None, datetime.now(timezone.utc).isoformat()))
            with self.assertRaisesRegex(sqlite3.IntegrityError, "retired Evidence"):
                db.execute("UPDATE registry_principals SET evidence_ids_json=? "
                           "WHERE principal_id=?",
                           (json.dumps([candidate.evidence_id]), "PRINCIPAL-fixture"))

    def test_evidence_retirement_scan_advances_past_protected_prefix(self):
        rows = [self._evidence(f"retirement-{index}".encode()) for index in range(3)]
        ordered = sorted(rows, key=lambda item: item.evidence_id)
        self.store.set_retention(ordered[1].evidence_id, Retention(retain=False),
                                 actor="fixture", reason="ephemeral")
        manager = EvidencePayloadRetirementManager(
            self.store, EvidencePayloadPolicy(max_scan_entries=1))
        instant = self.now + 172800
        self.assertEqual(manager.plan(now=instant).evidence_ids, ())
        self.assertEqual(manager.plan(now=instant).evidence_ids,
                         (ordered[1].evidence_id,))

    def test_evidence_retirement_does_not_expand_to_later_eligible_record(self):
        reviewed = self._evidence(b"reviewed-expiration")
        later = self._evidence(b"later-expiration")
        self.store.set_retention(reviewed.evidence_id, Retention(retain=False),
                                 actor="fixture", reason="ephemeral")
        instant = self.now + 172800
        manager = EvidencePayloadRetirementManager(self.store)
        self.assertEqual(manager.plan(now=instant).evidence_ids, (reviewed.evidence_id,))
        self.store.set_retention(later.evidence_id, Retention(retain=False),
                                 actor="fixture", reason="ephemeral")
        self.assertEqual(manager.run(confirmed=True, now=instant)["retired"], 1)
        with self.assertRaisesRegex(FileNotFoundError, "retired"):
            self.store.read_content(reviewed.evidence_id)
        self.assertEqual(self.store.read_content(later.evidence_id), b"later-expiration")

    def test_failed_retirement_audit_preserves_payload(self):
        candidate = self._evidence(b"audit-protected-retirement")
        self.store.set_retention(candidate.evidence_id, Retention(retain=False),
                                 actor="fixture", reason="ephemeral")
        audit = self.root / "logs" / "evidence-retirement.jsonl"
        audit.parent.mkdir()
        audit.symlink_to(self.root / "outside-audit")
        manager = EvidencePayloadRetirementManager(self.store, audit_path=audit)
        instant = self.now + 172800
        manager.plan(now=instant)
        with self.assertRaisesRegex(ValueError, "Unsafe Evidence retention audit"):
            manager.run(confirmed=True, now=instant)
        self.assertEqual(self.store.read_content(candidate.evidence_id),
                         b"audit-protected-retirement")

    def test_cli_requires_confirmation_and_returns_dry_run(self):
        orphan = self.artifacts.put_bytes(b"cli-orphan")
        self._old(orphan.sha256)
        config = self.root / "config.toml"
        config.write_text(
            f'[paths]\nroot = "{self.root}"\n'
            f'[store]\nartifact_root = "{self.artifacts.root}"\n'
            '[retention]\norphan_grace_hours = 24\n', encoding="utf-8")
        out, err = StringIO(), StringIO()
        self.assertEqual(main(["--config", str(config), "retention", "plan"],
                              stdout=out, stderr=err), 0, err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["candidate_count"], 1)
        self.assertTrue(self.artifacts.path_for(orphan.sha256).is_file())
        self.assertEqual(main(["--config", str(config), "retention", "run"],
                              stdout=StringIO(), stderr=StringIO()), 2)
        out = StringIO()
        self.assertEqual(main(["--config", str(config), "retention", "run", "--confirmed"],
                              stdout=out, stderr=err), 0, err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["removed"], 1)

    def test_cli_evidence_retirement_is_reviewed_and_separate_from_gc(self):
        candidate = self._evidence(b"cli-expired-payload")
        self.store.set_retention(candidate.evidence_id, Retention(retain=False),
                                 actor="fixture", reason="ephemeral")
        config = self.root / "config.toml"
        config.write_text(
            f'[paths]\nroot = "{self.root}"\n'
            f'[store]\nartifact_root = "{self.artifacts.root}"\n'
            '[retention]\norphan_grace_hours = 24\n', encoding="utf-8")
        with patch("hackbot.evidence_retention.time.time", return_value=self.now + 172800):
            out, err = StringIO(), StringIO()
            self.assertEqual(main(["--config", str(config), "retention", "evidence-plan"],
                                  stdout=out, stderr=err), 0, err.getvalue())
            self.assertEqual(json.loads(out.getvalue())["evidence_ids"],
                             [candidate.evidence_id])
            self.assertEqual(main(["--config", str(config), "retention", "evidence-run"],
                                  stdout=StringIO(), stderr=StringIO()), 2)
            out = StringIO()
            self.assertEqual(main(["--config", str(config), "retention", "evidence-run",
                                   "--confirmed"], stdout=out, stderr=err), 0, err.getvalue())
            self.assertEqual(json.loads(out.getvalue())["retired"], 1)
        self.assertTrue(self.artifacts.path_for(candidate.content_hash).exists())


class CompactJsonReferenceTriggerTests(unittest.TestCase):
    def test_multi_column_counts_and_tampered_removal_fail_closed(self):
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE TABLE fixture (id INTEGER PRIMARY KEY, first_json TEXT, "
                       "second_json TEXT)")
            db.executescript(evidence_json_index_sql(db))
            db.executescript(traffic_json_index_sql(db))
            ev_a, ev_b = "EV-" + "a" * 32, "EV-" + "b" * 32
            request, response = "REQUEST-" + "c" * 32, "RESPONSE-" + "d" * 32
            with self.assertRaisesRegex(sqlite3.IntegrityError, "invalid JSON"):
                db.execute("INSERT INTO fixture VALUES (1,?,?)", ("{invalid", "[]"))
            db.execute("INSERT INTO fixture VALUES (1,?,?)",
                       (json.dumps([ev_a, request]),
                        json.dumps([ev_a, ev_b, response])))
            self.assertEqual(dict(db.execute(
                "SELECT ref_id,ref_count FROM evidence_json_reference_counts")),
                {ev_a: 2, ev_b: 1})
            self.assertEqual(dict(db.execute(
                "SELECT ref_id,ref_count FROM traffic_json_reference_counts")),
                {request: 1, response: 1})
            db.execute("UPDATE fixture SET second_json=? WHERE id=1",
                       (json.dumps([ev_b, request]),))
            self.assertEqual(dict(db.execute(
                "SELECT ref_id,ref_count FROM evidence_json_reference_counts")),
                {ev_a: 1, ev_b: 1})
            self.assertEqual(dict(db.execute(
                "SELECT ref_id,ref_count FROM traffic_json_reference_counts")),
                {request: 2})
            db.execute("UPDATE evidence_json_reference_counts SET ref_count=0 WHERE ref_id=?",
                       (ev_a,))
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM fixture WHERE id=1")
            self.assertIsNotNone(db.execute("SELECT id FROM fixture WHERE id=1").fetchone())
            db.execute("UPDATE evidence_json_reference_counts SET ref_count=1 WHERE ref_id=?",
                       (ev_a,))
            db.execute("UPDATE traffic_json_reference_counts SET ref_count=0 WHERE ref_id=?",
                       (request,))
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM fixture WHERE id=1")
            self.assertIsNotNone(db.execute("SELECT id FROM fixture WHERE id=1").fetchone())
            db.execute("UPDATE traffic_json_reference_counts SET ref_count=2 WHERE ref_id=?",
                       (request,))
            db.execute("DELETE FROM fixture WHERE id=1")
            self.assertEqual(db.execute(
                "SELECT count(*) FROM evidence_json_reference_counts").fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT count(*) FROM traffic_json_reference_counts").fetchone()[0], 0)


class JsonReferenceAuditTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        artifacts = ArtifactStore(root / "artifacts")
        self.store = EvidenceFactStore(root / "state.sqlite3", artifacts,
                                       StoreSettings(artifacts.root))
        self.store.initialize()
        with self.store._connection() as db:
            db.execute("INSERT INTO registry_targets(target_id,package_id,registered_at) VALUES (?,?,?)",
                       ("TARGET-audit", "fixture-package",
                        datetime.now(timezone.utc).isoformat()))

    @staticmethod
    def _source(db: sqlite3.Connection, label: str, body: str) -> None:
        db.execute("INSERT INTO registry_principals VALUES (?,?,?,?,?,?,?,?,?)",
                   ("PRINCIPAL-" + label, "TARGET-audit", label, None, "OBSERVED",
                    body, None, None, datetime.now(timezone.utc).isoformat()))

    def test_audit_counts_duplicate_and_escaped_source_values(self):
        evidence_id = "EV-" + "a" * 32
        traffic_id = "REQUEST-" + "b" * 32
        escaped = "EV-\\u0061" + "a" * 31
        with self.store._connection() as db:
            self._source(db, "a", '["' + evidence_id + '","' + escaped + '","' +
                         traffic_id + '"]')
            db.commit()
            result = audit_json_reference_indexes(db)
        self.assertTrue(result.matches)
        self.assertEqual(result.evidence_ids, 1)
        self.assertEqual(result.traffic_ids, 1)

    def test_audit_detects_missing_and_extra_derived_counts(self):
        evidence_id = "EV-" + "a" * 32
        traffic_id = "REQUEST-" + "b" * 32
        with self.store._connection() as db:
            self._source(db, "a", json.dumps([evidence_id, traffic_id]))
            db.execute("UPDATE evidence_json_reference_counts SET ref_count=0 "
                       "WHERE ref_id=?", (evidence_id,))
            db.execute("INSERT INTO traffic_json_reference_counts VALUES (?,1)",
                       ("RESPONSE-" + "c" * 32,))
            db.commit()
            result = audit_json_reference_indexes(db)
        self.assertFalse(result.matches)
        self.assertEqual((result.evidence_mismatches, result.traffic_mismatches), (1, 1))

    def test_audit_limits_fail_closed(self):
        with self.store._connection() as db:
            self._source(db, "a", "[]")
            self._source(db, "b", "[]")
            db.commit()
            with self.assertRaisesRegex(ReferenceIndexAuditError, "row limit"):
                audit_json_reference_indexes(db, max_values=1)
            with self.assertRaisesRegex(ReferenceIndexAuditError, "oversized"):
                audit_json_reference_indexes(db, max_json_bytes=1)

    def test_audit_rejects_missing_trigger(self):
        with self.store._connection() as db:
            db.execute("DROP TRIGGER evidence_json_ref_registry_principals_insert")
            db.commit()
            with self.assertRaisesRegex(ReferenceIndexAuditError, "incomplete"):
                audit_json_reference_indexes(db)

    def test_audit_uses_utf8_bytes_for_json_size_limit(self):
        with self.store._connection() as db:
            self._source(db, "a", '["\u00e9"]')
            db.commit()
            with self.assertRaisesRegex(ReferenceIndexAuditError, "oversized"):
                audit_json_reference_indexes(db, max_json_bytes=5)

    def test_audit_treats_parser_depth_failure_as_incomplete(self):
        with self.store._connection() as db:
            self._source(db, "a", "[]")
            db.commit()
            with patch("hackbot.json_reference_audit.json.loads", side_effect=RecursionError):
                with self.assertRaisesRegex(ReferenceIndexAuditError, "incomplete"):
                    audit_json_reference_indexes(db)

