"""Phase 23 read-boundary controls use only the local loopback fixture."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
import unittest

from hackbot.domxss_store import DOMXSSStore
from hackbot.domain import TrafficSource
from hackbot.exposure import ExposureSpecialist
from hackbot.exposure_store import ExposureStore
from hackbot.hypotheses import HypothesisStore
from hackbot.orchestrator import PlanOrchestrator
from hackbot.plan_runs import PlanRunStore
from hackbot.policy_store import PolicyStore
from hackbot.skill_plans import (PrerequisiteChecker, SkillContextBuilder,
                                 SkillPlanStore, SkillPlanner, SkillRouter)
from hackbot.skills import SkillRegistry
from hackbot.target_policy import PolicyDecision
from hackbot.traffic import CapturedRequest, CapturedResponse
from hackbot.validation_store import ValidationStatus, ValidationStore
from hackbot.validator import DeterministicValidatorEngine
from tests import test_authorization as authorization_fixture


CATALOG = Path(__file__).resolve().parents[1] / "src/hackbot/skill_catalog"


class ExposureRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.owner_fixture = authorization_fixture.AuthorizationSpecialistTests(
            methodName="test_no_object_or_owner_request_produces_no_candidate_and_no_traffic")
        self.owner_fixture.setUp()
        self.addCleanup(self.owner_fixture.doCleanups)
        self.fx = self.owner_fixture.fx
        self.package = self.fx.package
        self.target = self.package.target.id
        self.hypotheses = HypothesisStore(self.fx.store)
        self.ledger = ExposureStore(self.fx.store)
        self.specialist = ExposureSpecialist(
            dom=DOMXSSStore(self.fx.store), store=self.ledger, traffic=self.fx.traffic)
        skills = SkillRegistry(CATALOG)
        checker = PrerequisiteChecker()
        self.contexts = SkillContextBuilder(
            self.fx.store, self.fx.registry, self.fx.traffic, self.fx.browser,
            objects=self.fx.objects, exposure=self.ledger)
        self.router = SkillRouter(skills, checker)
        self.planner = SkillPlanner(
            skills, checker, self.fx.policy, SkillPlanStore(self.fx.store),
            objects=self.fx.objects, exposure=self.ledger)
        self.runs = PlanRunStore(self.fx.store)
        self.orchestrator = PlanOrchestrator(
            runs=self.runs, targets=self.fx.targets, hypotheses=self.hypotheses,
            context=self.contexts, checker=checker, registry=skills,
            policy=self.fx.policy, approvals=PolicyStore(self.fx.store),
            executor=self.fx.executor, traffic=self.fx.traffic,
            evidence=self.fx.store, objects=self.fx.objects,
            exposure=self.specialist)
        self.validator = DeterministicValidatorEngine(
            runs=self.runs, traffic=self.fx.traffic, evidence=self.fx.store,
            identities=self.fx.registry, hypotheses=self.hypotheses,
            results=ValidationStore(self.fx.store), targets=self.fx.targets,
            exposure=self.specialist)

    def _candidate(self, *, private: bool = True, pii: bool = False):
        owner, session, tenant, item = self.owner_fixture.fixture_object(object_type="document")
        external = self.owner_fixture.specialist._external_id(item)
        if private:
            self.owner_fixture.protect(item, tenant, policy="OWNER_ONLY")
        subject = hashlib.sha256(external.encode()).hexdigest()
        if not private:
            self.fx.store.create_fact(
                subject, "resource_visibility", "PUBLIC", confidence=1.0,
                evidence_ids=(item.verification_evidence_ids[0],), source="FIXTURE",
                target_ref=self.target)
        if pii:
            self.fx.server.fixture_objects[external]["email"] = "owned-profile@example.test"
        self.fx.store.create_fact(
            subject, "data_classification", "SENSITIVE" if pii else "PROTECTED_FILE", confidence=1.0,
            evidence_ids=(item.verification_evidence_ids[0],), source="FIXTURE",
            target_ref=self.target)
        url = self.fx.base + "/fixture/tenant-a/documents/" + external
        body = json.dumps(self.fx.server.fixture_objects[external], sort_keys=True).encode()

        def capture(browser_session_id):
            exchange = self.fx.traffic.store_request(
                self.package, CapturedRequest("GET", url), source=TrafficSource.FIXTURE,
                capture_provider="FIXTURE", browser_manager=self.fx.browser
                if browser_session_id else None,
                browser_session_id=browser_session_id,
                anonymous=browser_session_id is None,
                auth_material_observed=browser_session_id is not None)
            return self.fx.traffic.store_response(
                exchange.id, CapturedResponse(200, (("Content-Type", "application/json"),), body))

        capture(session.id)
        capture(None)
        discovered = self.specialist.discover_traffic(self.package)
        self.assertGreaterEqual(discovered.signals, 1)
        self.assertEqual(len(discovered.candidate_ids), 1)
        return owner, session, item, discovered.candidate_ids[0]

    def _run(self, *, secure: bool, private: bool = True, pii: bool = False):
        owner, session, item, candidate_id = self._candidate(private=private, pii=pii)
        prepared = self.specialist.prepare_candidate(
            self.package, candidate_id, hypotheses=self.hypotheses,
            contexts=self.contexts, router=self.router, planner=self.planner)
        self.assertTrue(prepared.plan_id.startswith("PLAN-"))
        bound = self.specialist.bind_owned_read(
            self.package, candidate_id, test_object_id=item.id,
            owner_session_id=session.id, objects=self.fx.objects,
            hypotheses=self.hypotheses, contexts=self.contexts, planner=self.planner)
        self.assertEqual(bound.plan_status, "READY_FOR_MANUAL_REVIEW")
        self.fx.server.fixture_secure = secure
        before = len(self.fx.server.received)
        state = self.orchestrator.start(bound.plan_id, self.package.id)
        for _ in range(12):
            if state["run"]["status"] == "COMPLETED":
                break
            state = self.orchestrator.advance(state["run"]["id"], self.package.id)
        self.assertEqual(state["run"]["status"], "COMPLETED")
        self.assertEqual(state["run"]["requests_consumed"], 4)
        self.assertEqual(len(self.fx.server.received) - before, 4)
        self.assertEqual(self.ledger.links(self.target, candidate_id)["plan_id"], bound.plan_id)
        return state["run"]["id"], candidate_id

    def test_private_owned_download_anonymous_equivalent_confirms(self):
        run_id, _ = self._run(secure=False)
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertEqual(result.reproduction_count, 2)
        metrics = self.ledger.metrics(self.target)
        self.assertEqual(metrics["stop_on_proof_events"], 1)
        self.assertGreater(metrics["sensitive_artifacts"], 0)

    def test_secure_owned_download_rejects_anonymous_boundary(self):
        run_id, _ = self._run(secure=True)
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertIsNone(finding)

    def test_private_profile_pii_confirms_without_exposing_value(self):
        run_id, candidate_id = self._run(secure=False, pii=True)
        self.assertEqual(self.ledger.get(self.target, candidate_id).category.value, "PII_EXPOSURE")
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertEqual(self.ledger.validation_state(self.target, candidate_id), "CONFIRMED")
        self.assertNotIn("owned-profile@example.test", json.dumps(
            self.ledger.get(self.target, candidate_id).public_dict()))

    def test_public_email_is_not_a_finding(self):
        run_id, candidate_id = self._run(secure=False, private=False, pii=True)
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertIsNone(finding)
        self.assertEqual(self.ledger.validation_state(self.target, candidate_id), "REJECTED")

    def _vhost_run(self, mode: str, *, allowed: bool = True):
        self.fx.package = replace(self.fx.package, rules=replace(
            self.fx.package.rules, internal_vhost_testing_allowed=allowed))
        self.fx.targets.package = self.fx.package
        self.package = self.fx.package
        self.fx.server.fixture_vhost_mode = mode
        url = self.fx.base + "/assets/app-vhost.js"
        body = (b'const virtualHost = "http://admin.svc.internal"; '
                b'const route = "/assets/app-vhost.js";')
        asset = self.specialist.dom.record_artifact(
            target_id=self.target, asset_url=url, body=body, recon_asset_id=1,
            recon_sha256=hashlib.sha256(body).hexdigest(), source="FIXTURE")
        analysis = self.specialist.analyze_js(self.package, asset.artifact_id, fixture_url=url)
        self.assertEqual(analysis.signals, 1)
        candidate_id = analysis.candidate_ids[0]
        candidate = self.ledger.get(self.target, candidate_id)
        self.assertEqual(candidate.category.value, "INTERNAL_VHOST_CANDIDATE")
        if not allowed:
            return candidate_id, None
        prepared = self.specialist.prepare_candidate(
            self.package, candidate_id, hypotheses=self.hypotheses,
            contexts=self.contexts, router=self.router, planner=self.planner)
        self.assertEqual(prepared.plan_status, "READY_FOR_MANUAL_REVIEW")
        before = len(self.fx.server.received)
        state = self.orchestrator.start(prepared.plan_id, self.package.id)
        for _ in range(12):
            if state["run"]["status"] == "COMPLETED":
                break
            state = self.orchestrator.advance(state["run"]["id"], self.package.id)
        self.assertEqual(state["run"]["status"], "COMPLETED")
        self.assertEqual(len(self.fx.server.received) - before, 3)
        return candidate_id, state["run"]["id"]

    def test_vhost_protected_config_confirms(self):
        candidate_id, run_id = self._vhost_run("vulnerable")
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertEqual(self.ledger.validation_state(self.target, candidate_id), "CONFIRMED")
        self.assertNotIn("FixtureOnlyInternal-z8Qp4Rm7Tn2Yv6Wk", json.dumps(finding.to_dict()))

    def test_vhost_denied_and_title_only_are_not_findings(self):
        for mode in ("secure", "title_only"):
            with self.subTest(mode=mode):
                candidate_id, run_id = self._vhost_run(mode)
                result, finding = self.validator.validate_run(run_id, self.target)
                self.assertEqual(result.status, ValidationStatus.REJECTED)
                self.assertIsNone(finding)

    def test_vhost_without_explicit_policy_stays_passive(self):
        candidate_id, run_id = self._vhost_run("vulnerable", allowed=False)
        self.assertIsNone(run_id)
        self.assertEqual(self.ledger.validation_state(self.target, candidate_id), "UNVALIDATED")

    def _captured_response_run(self, path: str, *, fresh_mode: str = "normal"):
        self.fx.server.fixture_exposure_mode = "normal"
        source_action = self.fx.action(path)
        source = self.fx.run_action(source_action, artifact_capture_kind="EXPOSURE")
        self.assertIsNone(source.error)
        self.assertIsNotNone(source.artifact_evidence_id)
        analysis = self.specialist.analyze_captured_response(
            self.package, exchange_id=source.exchange_ids[-1],
            artifact_evidence_id=source.artifact_evidence_id)
        candidate_id = analysis.candidate_ids[0]
        candidate = self.ledger.get(self.target, candidate_id)
        if candidate.status.value in {"REJECTED_PUBLIC", "REJECTED_PLACEHOLDER"}:
            return candidate_id, None
        prepared = self.specialist.prepare_candidate(
            self.package, candidate_id, hypotheses=self.hypotheses,
            contexts=self.contexts, router=self.router, planner=self.planner)
        self.assertEqual(prepared.plan_status, "READY_FOR_MANUAL_REVIEW")
        self.fx.server.fixture_exposure_mode = fresh_mode
        before = len(self.fx.server.received)
        state = self.orchestrator.start(prepared.plan_id, self.package.id)
        for _ in range(8):
            if state["run"]["status"] == "COMPLETED":
                break
            state = self.orchestrator.advance(state["run"]["id"], self.package.id)
        self.assertEqual(state["run"]["status"], "COMPLETED")
        self.assertEqual(len(self.fx.server.received) - before, 1)
        return candidate_id, state["run"]["id"]

    def test_config_debug_and_backup_disclosure_confirm_synthetic_secret(self):
        for path, category in (("/fixture/config.json", "CONFIG_DISCLOSURE"),
                               ("/fixture/debug.txt", "DEBUG_ENDPOINT"),
                               ("/fixture/backup.json", "BACKUP_ARTIFACT")):
            with self.subTest(path=path):
                candidate_id, run_id = self._captured_response_run(path)
                self.assertEqual(self.ledger.get(self.target, candidate_id).category.value, category)
                result, finding = self.validator.validate_run(run_id, self.target)
                self.assertEqual(result.status, ValidationStatus.CONFIRMED)
                self.assertIsNotNone(finding)
                self.assertEqual(self.ledger.validation_state(self.target, candidate_id), "CONFIRMED")

    def test_dummy_config_rejected_before_active_recheck(self):
        candidate_id, run_id = self._captured_response_run("/fixture/dummy.json")
        self.assertIsNone(run_id)
        self.assertEqual(self.ledger.get(self.target, candidate_id).status.value,
                         "REJECTED_PLACEHOLDER")

    def test_changed_or_denied_config_does_not_confirm(self):
        for mode, expected in (("changed", ValidationStatus.INSUFFICIENT_EVIDENCE),
                               ("deny", ValidationStatus.REJECTED)):
            with self.subTest(mode=mode):
                candidate_id, run_id = self._captured_response_run(
                    "/fixture/config.json", fresh_mode=mode)
                result, finding = self.validator.validate_run(run_id, self.target)
                self.assertEqual(result.status, expected)
                self.assertIsNone(finding)

    def _field_run(self, *, public: bool = False, secure: bool = False,
                   cross_tenant: bool = False):
        self.fx.package = replace(self.fx.package, autonomy=replace(
            self.fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        self.fx.targets.package = self.fx.package
        self.package = self.fx.package
        owner, owner_session, tenant, item = self.owner_fixture.fixture_object(role="admin")
        member, member_session, _ = self.owner_fixture.actor(
            "tenant_b_admin" if cross_tenant else "tenant_a_member",
            "tenant-b" if cross_tenant else "tenant-a",
            role="admin" if cross_tenant else "member")
        external = self.owner_fixture.specialist._external_id(item)
        subject = hashlib.sha256(external.encode()).hexdigest()
        if public:
            self.fx.store.create_fact(
                subject, "resource_visibility", "PUBLIC", confidence=1.0,
                evidence_ids=(item.verification_evidence_ids[0],), source="FIXTURE",
                target_ref=self.target)
        else:
            self.owner_fixture.protect(item, tenant, policy="TENANT_ONLY")
        facts = [("data_classification", "SENSITIVE")]
        if not cross_tenant:
            facts.append(("field_visibility", "admin_note:" +
                          self.owner_fixture.roles["admin"].id))
        for predicate, value in facts:
            self.fx.store.create_fact(
                subject, predicate, value, confidence=1.0,
                evidence_ids=(item.verification_evidence_ids[0],), source="FIXTURE",
                target_ref=self.target)
        self.fx.server.fixture_objects[external]["admin_note"] = "synthetic-private-note"
        if cross_tenant:
            self.fx.server.fixture_objects[external]["email"] = "owned-private@example.test"
        url = self.fx.base + "/fixture/tenant-a/projects/" + external
        body = json.dumps(self.fx.server.fixture_objects[external]).encode()

        def capture(session_id):
            exchange = self.fx.traffic.store_request(
                self.package, CapturedRequest("GET", url), source=TrafficSource.FIXTURE,
                capture_provider="FIXTURE", browser_manager=self.fx.browser,
                browser_session_id=session_id, auth_material_observed=True)
            return self.fx.traffic.store_response(exchange.id, CapturedResponse(
                200, (("Content-Type", "application/json"),), body))

        owner_exchange = capture(owner_session.id)
        member_exchange = capture(member_session.id)
        selections = self.specialist.list_field_exchanges(self.package)
        self.assertTrue({owner_exchange.id, member_exchange.id}.issubset(
            {item["exchange_id"] for item in selections}))
        self.assertNotIn("synthetic-private-note", json.dumps(selections))
        self.assertNotIn("owned-private@example.test", json.dumps(selections))
        analysis = self.specialist.analyze_field_boundary(
            self.package, owner_exchange_id=owner_exchange.id,
            member_exchange_id=member_exchange.id)
        candidate_id = analysis.candidate_ids[0]
        prepared = self.specialist.prepare_candidate(
            self.package, candidate_id, hypotheses=self.hypotheses,
            contexts=self.contexts, router=self.router, planner=self.planner)
        self.assertTrue(prepared.plan_id.startswith("PLAN-"))
        bound = self.specialist.bind_field_read(
            self.package, candidate_id, test_object_id=item.id,
            owner_session_id=owner_session.id, member_session_id=member_session.id,
            objects=self.fx.objects, hypotheses=self.hypotheses,
            contexts=self.contexts, planner=self.planner)
        self.fx.server.fixture_secure = secure
        before = len(self.fx.server.received)
        state = self.orchestrator.start(bound.plan_id, self.package.id)
        for _ in range(12):
            if state["run"]["status"] == "COMPLETED":
                break
            self.assertIn(state["run"]["status"],
                          {"CREATED", "READY", "CHECKING_PREREQUISITES"}, state)
            state = self.orchestrator.advance(state["run"]["id"], self.package.id)
        self.assertEqual(state["run"]["status"], "COMPLETED")
        self.assertEqual(len(self.fx.server.received) - before, 3)
        return candidate_id, state["run"]["id"]

    def test_member_admin_only_field_exposure_confirms(self):
        candidate_id, run_id = self._field_run()
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertEqual(self.ledger.validation_state(self.target, candidate_id), "CONFIRMED")
        self.assertNotIn("synthetic-private-note", json.dumps(finding.to_dict()))

    def test_cross_tenant_private_profile_pii_confirms(self):
        candidate_id, run_id = self._field_run(cross_tenant=True)
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertNotIn("owned-private@example.test", json.dumps(finding.to_dict()))

    def test_public_field_does_not_confirm(self):
        candidate_id, run_id = self._field_run(public=True)
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertIsNone(finding)

    def test_denied_member_field_does_not_confirm(self):
        candidate_id, run_id = self._field_run(secure=True)
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertIsNone(finding)


if __name__ == "__main__":
    unittest.main()
