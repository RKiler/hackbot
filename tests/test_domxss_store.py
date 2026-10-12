from pathlib import Path
import shutil
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.config import StoreSettings
from hackbot.domxss_static import DOMCandidateStatus, DOMStaticAnalyzer
from hackbot.domxss_store import DOMXSSStore
from hackbot.evidence import Sensitivity
from hackbot.identity_registry import IdentityRegistry
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package


EXAMPLE = Path(__file__).parent / "examples/targets/example"
JS = b"""
function render() {
  const p = new URLSearchParams(location.search).get('u');
  if (!p.startsWith('javascript:')) {
    const decoded = decodeURIComponent(p);
    iframe.src = decoded;
  }
}
"""


@unittest.skipUnless(shutil.which("node"), "Node/Babel parser unavailable")
class DOMXSSStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.db = root / "state/bughunter.sqlite3"
        artifacts = root / "artifacts"
        self.evidence = EvidenceFactStore(self.db, ArtifactStore(artifacts), StoreSettings(artifacts))
        self.evidence.initialize()
        self.package = load_target_package(EXAMPLE)
        IdentityRegistry(self.evidence).register_target(self.package)
        self.target = self.package.target.id
        self.ledger = DOMXSSStore(self.evidence)
        self.url = "https://app.example.test/static/app.js?v=1"

    def record(self, body=JS, recon_hash=None):
        return self.ledger.record_artifact(
            target_id=self.target, asset_url=self.url, body=body,
            recon_asset_id=42, recon_sha256=recon_hash, source="FIXTURE",
        )

    def test_artifact_cache_analysis_and_restart(self) -> None:
        import hashlib
        digest = hashlib.sha256(JS).hexdigest()
        asset = self.record(recon_hash=digest)
        self.assertEqual(asset.state, "CURRENT")
        self.assertEqual(self.ledger.current_asset(self.target, self.url, digest), asset)
        self.assertEqual(self.record(recon_hash=digest), asset)
        evidence = self.evidence.get_evidence(asset.evidence_id)
        self.assertEqual(evidence.sensitivity, Sensitivity.SENSITIVE)
        with self.assertRaises(PermissionError):
            self.evidence.read_content(asset.evidence_id)
        self.assertEqual(self.evidence.read_content(asset.evidence_id, allow_sensitive=True), JS)

        analysis_id, analysis = self.ledger.analyze_asset(self.target, asset.artifact_id,
                                                          DOMStaticAnalyzer())
        self.assertEqual(analysis.status, "ANALYZED")
        self.assertEqual(len(analysis.candidates), 1)
        item = analysis.candidates[0]
        self.assertEqual(item.status, DOMCandidateStatus.STATICALLY_SUPPORTED)
        self.assertEqual(item.evidence_ids, (asset.evidence_id,))
        self.assertEqual(self.ledger.analyze_asset(self.target, asset.artifact_id,
                                                  DOMStaticAnalyzer())[0], analysis_id)
        reopened = DOMXSSStore(EvidenceFactStore(self.db, ArtifactStore(self.evidence.artifacts.root),
                                                  self.evidence.settings))
        self.assertEqual(reopened.get_candidate(self.target, item.candidate_id), item)
        self.assertEqual(reopened.list_candidates(self.target).items, (item,))
        with sqlite3.connect(self.db) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM dom_analysis_runs").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM dom_js_artifacts").fetchone()[0], 1)
            self.assertNotIn(self.url, str(connection.execute("SELECT * FROM dom_js_artifacts").fetchone()))

    def test_new_hash_stales_prior_candidate(self) -> None:
        import hashlib
        first = self.record(recon_hash=hashlib.sha256(JS).hexdigest())
        _, analysis = self.ledger.analyze_asset(self.target, first.artifact_id, DOMStaticAnalyzer())
        changed = JS.replace(b"iframe.src", b"window.location.href")
        second = self.record(changed, hashlib.sha256(changed).hexdigest())
        self.assertNotEqual(first.artifact_id, second.artifact_id)
        self.assertEqual(self.ledger.get_asset(self.target, first.artifact_id).state, "STALE")
        self.assertEqual(self.ledger.get_candidate(self.target, analysis.candidates[0].candidate_id).status,
                         DOMCandidateStatus.STALE)
        self.assertIsNone(self.ledger.current_asset(self.target, self.url,
                                                     hashlib.sha256(JS).hexdigest()))

    def test_unverified_hash_and_controlled_provenance_gate(self) -> None:
        asset = self.record()
        self.assertEqual(asset.state, "UNVERIFIED_CURRENT")
        self.assertIsNone(self.ledger.current_asset(self.target, self.url, None))
        with self.assertRaises(ValueError):
            self.ledger.record_artifact(target_id=self.target, asset_url=self.url, body=JS,
                                        recon_asset_id=42, recon_sha256=None,
                                        source="CONTROLLED_HTTP")
        with self.assertRaises(ValueError):
            self.ledger.record_artifact(target_id=self.target, asset_url=self.url, body=JS,
                                        recon_asset_id=42, recon_sha256=None,
                                        source="CONTROLLED_HTTP", retrieval_exchange_id="EXCHANGE-missing")

    def test_source_map_is_bound_to_current_bundle(self) -> None:
        import hashlib
        import json
        one_line = (b"function run(){const p=location.search;if(p.startsWith('https:')){"
                    b"iframe.src=decodeURIComponent(p)}}//# sourceMappingURL=app.js.map")
        asset = self.record(one_line, hashlib.sha256(one_line).hexdigest())
        _, analysis = self.ledger.analyze_asset(self.target, asset.artifact_id, DOMStaticAnalyzer())
        map_body = json.dumps({"version": 3, "sources": ["src/main.js"],
                               "names": [], "mappings": "AAAA"}).encode()
        source_map = self.ledger.record_source_map(
            target_id=self.target, js_artifact_id=asset.artifact_id,
            map_url="https://app.example.test/static/app.js.map", body=map_body,
            source="FIXTURE",
        )
        mapped = self.ledger.map_candidate(self.target, analysis.candidates[0].candidate_id, source_map)
        self.assertEqual(mapped.source_map_sha256, hashlib.sha256(map_body).hexdigest())
        self.assertIn("src/main.js", mapped.mapped_source)
        self.assertIn(source_map.evidence_id, mapped.evidence_ids)


if __name__ == "__main__":
    unittest.main()
