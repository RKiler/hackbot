from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as NS
from urllib.parse import parse_qs, urlsplit
import unittest
import uuid

from hackbot.artifacts import ArtifactStore
from hackbot.browser import BrowserStatus
from hackbot.config import StoreSettings
from hackbot.domxss import DOMXSSSpecialist
from hackbot.domxss_browser import (DOMBrowserExperimentExecutor,
                                    DOMBrowserObservation)
from hackbot.domxss_store import DOMXSSStore
from hackbot.evidence import EvidenceProvenance, EvidenceType, Sensitivity
from hackbot.hypotheses import HypothesisStore
from hackbot.identity_registry import IdentityRegistry
from hackbot.orchestrator import PlanOrchestrator
from hackbot.plan_runs import PlanRunStore
from hackbot.policy import PolicyEngine
from hackbot.policy_store import PolicyStore
from hackbot.skill_plans import (DOMPlanBinding, PrerequisiteChecker,
                                SkillContextBuilder, SkillPlanStore, SkillPlanner,
                                SkillRouter)
from hackbot.skills import SkillRegistry
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import TargetPackageRepository, load_target_package
from hackbot.traffic import TrafficStore
from hackbot.validation_store import ValidationStatus, ValidationStore
from hackbot.validator import DeterministicValidatorEngine
from tests.test_phase12 import FixtureRecon


EXAMPLES = Path(__file__).parent / "examples/targets"
CATALOG = Path(__file__).resolve().parents[1] / "src/hackbot/skill_catalog"


class NoTrafficExecutor:
    def authorize(self, *_args, **_kwargs):
        raise AssertionError("HTTP executor must not run in browser fixture")


class FakeBrowserDriver:
    def __init__(self, asset_url: str, digest: str, *, mismatch: bool = False,
                 proof: bool = True, double_only: bool = False) -> None:
        self.asset_url = asset_url
        self.digest = digest
        self.mismatch = mismatch
        self.proof = proof
        self.double_only = double_only
        self.calls = []

    def is_running(self, _session_id: str) -> bool:
        return True

    def execute_dom_variant(self, session_id, url, marker, expected_asset_url,
                            gate, *, authenticated, request_cap, timeout_ms):
        assert not authenticated
        assert expected_asset_url == self.asset_url
        assert gate(url, "GET", True)
        assert gate(expected_asset_url, "GET", False)
        value = parse_qs(urlsplit(url).query).get("next", [""])[0]
        execution = (("%253A" if self.double_only else "%3A") in value
                     and "javascript" in value and self.proof)
        context_id = "DOMCTX-" + uuid.uuid4().hex
        self.calls.append((url, context_id))
        return DOMBrowserObservation(
            context_id=context_id, marker_observed=execution,
            marker_context="IFRAME" if execution else None,
            document_origin="https://api.example.test" if execution else None,
            response_status=200,
            bundle_sha256="0" * 64 if self.mismatch else self.digest,
            csp_present=True, trusted_types_enforced=False,
            sandbox_flags=(), browser_blocked=False, navigation_only=False,
            request_count=2, denial_count=0,
        )


class FakeBrowserManager:
    def __init__(self, target_id: str, driver: FakeBrowserDriver) -> None:
        self.driver = driver
        self.session = NS(id="BSESSION-" + "1" * 32, target_id=target_id, identity_id=None)

    def get(self, session_id: str):
        return self.session if session_id == self.session.id else None

    def session_context(self, _session_id: str):
        return NS(browser_status=BrowserStatus.RUNNING)


class DOMRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        artifacts = root / "artifacts"
        self.evidence = EvidenceFactStore(root / "state/db.sqlite3", ArtifactStore(artifacts),
                                          StoreSettings(artifacts))
        self.evidence.initialize()
        self.package = load_target_package(EXAMPLES / "example")
        self.target_id = self.package.target.id
        self.registry = IdentityRegistry(self.evidence)
        self.registry.register_target(self.package)
        self.targets = TargetPackageRepository(EXAMPLES)
        self.dom = DOMXSSStore(self.evidence)
        self.hypotheses = HypothesisStore(self.evidence)
        self.traffic = TrafficStore(self.evidence)
        self.contexts = SkillContextBuilder(self.evidence, self.registry,
                                            self.traffic, dom=self.dom)
        self.skills = SkillRegistry(CATALOG)
        self.skills.discover()
        self.checker = PrerequisiteChecker()
        self.router = SkillRouter(self.skills, self.checker)
        self.plans = SkillPlanStore(self.evidence)
        self.policy = PolicyEngine(audit=PolicyStore(self.evidence))
        self.planner = SkillPlanner(self.skills, self.checker, self.policy,
                                    self.plans, self.dom)
        self.runs = PlanRunStore(self.evidence)
        self.recon = FixtureRecon()
        self.specialist = DOMXSSSpecialist(recon=self.recon, targets=self.targets,
                                          executor=NoTrafficExecutor(), store=self.dom)
        self.asset_url = self.specialist.inventory("example")[0].asset.asset_url
        self.route = "https://api.example.test/preview"

    def _build(self, *, mismatch: bool = False, proof: bool = True,
               double_decode: bool = False):
        body = (b"""
        function render() {
          const input = new URLSearchParams(location.search).get('next');
          if (!input.startsWith('javascript:')) {
            iframe.src = """ + (b"decodeURIComponent(decodeURIComponent(input))"
                                if double_decode else b"decodeURIComponent(input)") + b""";
          }
        }
        """)
        digest = hashlib.sha256(body).hexdigest()
        asset = self.dom.record_artifact(
            target_id=self.target_id, asset_url=self.asset_url, body=body,
            recon_asset_id=51, recon_sha256=digest, source="FIXTURE")
        _, analysis = self.specialist.analyze(self.target_id, asset.artifact_id)
        candidate = analysis.candidates[0]
        route_evidence = self.evidence.create_evidence(
            EvidenceType.MANUAL_NOTE, b"fictional route fixture", source="test_fixture",
            target_ref=self.target_id,
            provenance=EvidenceProvenance("FIXTURE", "PAGE_ROUTE", "preview"),
            sensitivity=Sensitivity.INTERNAL)
        self.dom.bind_route(self.target_id, candidate.candidate_id,
                            self.route, route_evidence.evidence_id)
        prepared = self.specialist.prepare_candidate(
            "example", candidate.candidate_id, hypotheses=self.hypotheses,
            contexts=self.contexts, router=self.router, planner=self.planner)
        context = self.contexts.build(prepared.hypothesis, None, self.package)
        driver = FakeBrowserDriver(self.asset_url, digest, mismatch=mismatch, proof=proof,
                                   double_only=double_decode)
        browser = FakeBrowserManager(self.target_id, driver)
        bound = self.planner.bind_dom(
            self.package, prepared.hypothesis, context,
            DOMPlanBinding(candidate.candidate_id, self.route, self.asset_url,
                           browser.session.id, None, "QUERY", "next"))
        dom_executor = DOMBrowserExperimentExecutor(
            targets=self.targets, store=self.dom, browser=browser,
            driver=driver, policy=self.policy, runs=self.runs,
            evidence=self.evidence)
        orchestrator = PlanOrchestrator(
            runs=self.runs, targets=self.targets, hypotheses=self.hypotheses,
            context=self.contexts, checker=self.checker, registry=self.skills,
            policy=self.policy, approvals=PolicyStore(self.evidence),
            executor=NoTrafficExecutor(), traffic=self.traffic,
            evidence=self.evidence, dom=dom_executor)
        started = orchestrator.start(bound["id"], "example")
        return orchestrator, started["run"]["id"], driver, candidate

    def _validate(self, run_id: str):
        validator = DeterministicValidatorEngine(
            runs=self.runs, traffic=self.traffic, evidence=self.evidence,
            identities=self.registry, hypotheses=self.hypotheses,
            results=ValidationStore(self.evidence), dom=self.dom, targets=self.targets)
        return validator.validate_run(run_id, self.target_id)

    def test_plan_run_controls_proof_fresh_reproduction_and_no_http_executor(self) -> None:
        orchestrator, run_id, driver, candidate = self._build()
        for _ in range(5):
            detail = orchestrator.advance(run_id, "example")
        self.assertEqual(detail["run"]["status"], "COMPLETED")
        self.assertEqual(len(driver.calls), 5)
        self.assertEqual(len({context for _, context in driver.calls}), 5)
        self.assertEqual(self.dom.get_candidate(self.target_id, candidate.candidate_id).status.value,
                         "VALIDATION_READY")
        verify = next(step for step in detail["steps"] if step["type"] == "VERIFY_BROWSER")
        self.assertEqual(len(verify["result"]["evidence_ids"]), 5)
        self.assertEqual(detail["run"]["requests_consumed"], 5)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertEqual(validation.reproduction_count, 2)
        self.assertEqual(len(validation.supporting_evidence_ids) >= 6, True)

    def test_changed_bundle_stops_before_executable_variants(self) -> None:
        orchestrator, run_id, driver, candidate = self._build(mismatch=True)
        for _ in range(4):
            detail = orchestrator.advance(run_id, "example")
        self.assertEqual(len(driver.calls), 1)
        self.assertNotEqual(self.dom.get_candidate(self.target_id, candidate.candidate_id).status.value,
                            "VALIDATION_READY")
        with self.assertRaises(ValueError):
            self._validate(run_id)

    def test_no_execution_cannot_be_promoted(self) -> None:
        orchestrator, run_id, driver, candidate = self._build(proof=False)
        for _ in range(5):
            orchestrator.advance(run_id, "example")
        self.assertEqual(len(driver.calls), 4)
        self.assertEqual(self.dom.get_candidate(self.target_id, candidate.candidate_id).status.value,
                         "RUNTIME_TESTED")
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.REJECTED)
        self.assertIsNone(finding)

    def test_two_decodes_allow_one_bounded_double_variant_and_matching_fresh_proof(self) -> None:
        orchestrator, run_id, driver, _ = self._build(double_decode=True)
        for _ in range(5):
            detail = orchestrator.advance(run_id, "example")
        self.assertEqual(detail["run"]["status"], "COMPLETED")
        self.assertEqual(len(driver.calls), 6)
        verify = next(step for step in detail["steps"] if step["type"] == "VERIFY_BROWSER")
        self.assertEqual(len(verify["result"]["evidence_ids"]), 6)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)


if __name__ == "__main__":
    unittest.main()
