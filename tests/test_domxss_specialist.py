import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.config import StoreSettings
from hackbot.domxss import DOMAcquisitionStatus, DOMXSSSpecialist
from hackbot.domxss_store import DOMXSSStore
from hackbot.hypotheses import HypothesisStatus, HypothesisStore
from hackbot.identity_registry import IdentityRegistry
from hackbot.policy import PolicyEngine
from hackbot.recon import Page, Provenance, ReconAssetEvent, ReconJsAsset
from hackbot.skill_plans import (PrerequisiteChecker, SkillContextBuilder,
                                SkillPlanStore, SkillPlanner, SkillRouter)
from hackbot.skills import SkillRegistry
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import TargetPackageRepository, load_target_package
from hackbot.traffic import TrafficStore
from tests.test_phase12 import FixtureRecon


EXAMPLE_ROOT = Path(__file__).parent / "examples/targets"


class NoTrafficExecutor:
    def authorize(self, *_args, **_kwargs):
        raise AssertionError("No active request expected")

    def execute(self, *_args, **_kwargs):
        raise AssertionError("No active request expected")


class DOMXSSSpecialistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        artifacts = root / "artifacts"
        self.evidence = EvidenceFactStore(root / "state/bughunter.sqlite3",
                                          ArtifactStore(artifacts), StoreSettings(artifacts))
        self.evidence.initialize()
        self.package = load_target_package(EXAMPLE_ROOT / "example")
        IdentityRegistry(self.evidence).register_target(self.package)
        self.recon = FixtureRecon()
        self.store = DOMXSSStore(self.evidence)
        self.specialist = DOMXSSSpecialist(
            recon=self.recon, targets=TargetPackageRepository(EXAMPLE_ROOT),
            executor=NoTrafficExecutor(), store=self.store,
        )

    def test_inventory_is_bounded_and_scope_filtered(self) -> None:
        leads = self.specialist.inventory("example")
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0].asset.asset_id, 51)
        self.assertIn("JS_SINK_SIGNAL", leads[0].reasons)
        self.assertTrue(all(call[0] != "list_endpoints" for call in self.recon.calls))
        self.assertTrue(all(call[1] <= 8 for call in self.recon.calls
                            if call[0] in {"list_hosts"}))

    def test_recent_delta_asset_outside_initial_host_page_is_ranked(self) -> None:
        changed = ReconJsAsset(99, 99, "https://api.example.test/static/new.js", "b" * 64,
                               200, 200, Provenance("js_assets", 99, None, "fixture"))
        self.recon.list_asset_events = lambda *_args, **_kwargs: Page((
            ReconAssetEvent(100, 7, "new", "js_asset", 99, changed.asset_url, "high",
                            Provenance("asset_events", 100, None, "fixture")),), None)
        original_get = self.recon.get_js_asset
        self.recon.get_js_asset = lambda _domain_id, asset_id: (
            changed if asset_id == 99 else original_get(_domain_id, asset_id))
        leads = self.specialist.inventory("example")
        self.assertEqual(leads[0].asset.asset_id, 99)
        self.assertIn("RECENT_DELTA", leads[0].reasons)
        self.assertEqual(self.specialist._observed_asset("example", changed), True)

    def test_matching_hash_reuses_protected_artifact_without_network(self) -> None:
        lead = self.specialist.inventory("example")[0]
        body = b"const input=location.search;iframe.src=decodeURIComponent(input);"
        digest = hashlib.sha256(body).hexdigest()
        asset = ReconJsAsset(lead.asset.asset_id, lead.asset.host_id, lead.asset.asset_url,
                             digest, len(body), 200, lead.asset.provenance)
        self.recon.get_js_asset = lambda _domain_id, asset_id: (
            asset if asset_id == asset.asset_id else None)
        cached = self.store.record_artifact(
            target_id=self.package.target.id, asset_url=asset.asset_url, body=body,
            recon_asset_id=asset.asset_id, recon_sha256=digest, source="FIXTURE",
        )
        result = self.specialist.acquire("example", asset)
        self.assertEqual(result.status, DOMAcquisitionStatus.REUSED)
        self.assertEqual(result.artifact, cached)
        self.assertEqual(result.exchange_ids, ())

    def test_third_party_js_is_never_sent(self) -> None:
        asset = ReconJsAsset(99, 1, "https://third-party.invalid/library.js", None, 50,
                             200, Provenance("js_assets", 99, None, "fixture"))
        result = self.specialist.acquire("example", asset)
        self.assertEqual(result.status, DOMAcquisitionStatus.BLOCKED)
        self.assertEqual(result.exchange_ids, ())

    def test_third_party_source_map_is_never_sent(self) -> None:
        lead = self.specialist.inventory("example")[0]
        body = b"const x=location.search;iframe.src=x;\n//# sourceMappingURL=https://third-party.invalid/app.map"
        asset = self.store.record_artifact(
            target_id=self.package.target.id, asset_url=lead.asset.asset_url,
            body=body, recon_asset_id=lead.asset.asset_id,
            recon_sha256=hashlib.sha256(body).hexdigest(), source="FIXTURE",
        )
        result = self.specialist.acquire_source_map("example", lead.asset, asset)
        self.assertEqual(result.status, DOMAcquisitionStatus.BLOCKED)
        self.assertEqual(result.reason_code, "MAP_OUT_OF_SCOPE")

    def test_current_trace_routes_to_phase15_plan_without_network(self) -> None:
        lead = self.specialist.inventory("example")[0]
        body = b"""
        function render() {
          const input = location.hash;
          if (!input.startsWith('javascript:')) {
            iframe.src = decodeURIComponent(input);
          }
        }
        """
        asset = self.store.record_artifact(
            target_id=self.package.target.id, asset_url=lead.asset.asset_url,
            body=body, recon_asset_id=lead.asset.asset_id,
            recon_sha256=hashlib.sha256(body).hexdigest(), source="FIXTURE",
        )
        _, analysis = self.specialist.analyze(self.package.target.id, asset.artifact_id)
        candidate = analysis.candidates[0]
        catalog = Path(__file__).resolve().parents[1] / "src/hackbot/skill_catalog"
        skills = SkillRegistry(catalog)
        skills.discover()
        hypotheses = HypothesisStore(self.evidence)
        contexts = SkillContextBuilder(self.evidence, IdentityRegistry(self.evidence),
                                       TrafficStore(self.evidence), dom=self.store)
        router = SkillRouter(skills)
        planner = SkillPlanner(skills, PrerequisiteChecker(), PolicyEngine(),
                               SkillPlanStore(self.evidence))
        result = self.specialist.prepare_candidate(
            "example", candidate.candidate_id, hypotheses=hypotheses,
            contexts=contexts, router=router, planner=planner,
        )
        self.assertEqual(result.hypothesis.status, HypothesisStatus.NEEDS_RESEARCH)
        self.assertEqual(result.selected_skill, "check-before-transform-dom-xss")
        self.assertEqual(result.prerequisite_state, "READY")
        self.assertEqual(result.plan["proposed_actions"], [])
        with self.evidence._connection() as connection:
            binding = connection.execute("""
                SELECT hypothesis_id,plan_id FROM dom_flow_candidates WHERE candidate_id=?
            """, (candidate.candidate_id,)).fetchone()
        self.assertEqual((binding["hypothesis_id"], binding["plan_id"]),
                         (result.hypothesis.id, result.plan["id"]))
        again = self.specialist.prepare_candidate(
            "example", candidate.candidate_id, hypotheses=hypotheses,
            contexts=contexts, router=router, planner=planner,
        )
        self.assertEqual(again.hypothesis.id, result.hypothesis.id)
        self.assertEqual(again.plan["id"], result.plan["id"])


if __name__ == "__main__":
    unittest.main()
