"""Phase 25 fixtures use only local stores and a fake already-open browser."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.auth import AuthContextManager, AuthMechanism
from hackbot.behaviour import (BehaviourStore, LearningLimits, LearningStatus,
                               NormalBehaviourLearner)
from hackbot.browser import BrowserSessionManager, IdentityObservation, IdentityVerificationRule
from hackbot.config import BrowserSettings, SecretSettings, StoreSettings
from hackbot.domain import Role, Tenant, TrafficSource
from hackbot.evidence import EvidenceProvenance, EvidenceType, Sensitivity
from hackbot.identity import IdentityStatus, MembershipStatus
from hackbot.identity_registry import IdentityRegistry
from hackbot.secrets import RoutedSecretProvider
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package
from hackbot.traffic import CapturePacket, CapturedRequest, CapturedResponse, TrafficStore
from hackbot.test_objects import CleanupStrategy, ObjectRegistry, ObjectState

from tests.test_traffic import FakeBrowser


EXAMPLE = Path(__file__).parent / "examples/targets/example"
NOW = datetime.now(timezone.utc)


class BehaviourTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        blobs = root / "blobs"
        self.evidence = EvidenceFactStore(root / "state/bughunter.sqlite3", ArtifactStore(blobs),
                                          StoreSettings(blobs, max_page_size=50))
        self.identities = IdentityRegistry(self.evidence)
        self.identities.initialize()
        self.package = load_target_package(EXAMPLE)
        self.identities.register_target(self.package)
        self.target = self.package.target.id
        self.traffic = TrafficStore(self.evidence, self.identities)
        self.driver = FakeBrowser()
        auth = AuthContextManager(self.identities, RoutedSecretProvider(SecretSettings(), {}))
        self.browser = BrowserSessionManager(self.identities, auth, self.driver,
                                             BrowserSettings(profile_root=root / "browser-profiles"))
        self.objects = ObjectRegistry(self.evidence)
        self.ledger = BehaviourStore(self.evidence)
        self.learner = NormalBehaviourLearner(self.ledger, self.traffic, self.identities,
                                              self.browser, self.objects, self.evidence)
        self.tenant_a = self.identities.register_tenant(Tenant(target_id=self.target, label="tenant_a", kind="company"))
        self.tenant_b = self.identities.register_tenant(Tenant(target_id=self.target, label="tenant_b", kind="company"))
        self.admin = self.identities.register_role(Role(target_id=self.target, name="admin"))
        self.member = self.identities.register_role(Role(target_id=self.target, name="member"))

    def session(self, alias, tenant, role, *, match=True):
        identity = self.identities.register_identity(self.target, alias, status=IdentityStatus.ACTIVE)
        self.identities.add_membership(identity.id, tenant.id, role_ids=(role.id,), status=MembershipStatus.ACTIVE)
        self.browser.auth.prepare(self.target, identity.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        session = self.browser.create(self.target, identity.id)
        self.browser.start(session.id)
        self.browser.login_complete(session.id)
        self.driver.observations[session.id] = IdentityObservation(user_id=alias if match else "wrong-user",
                                                                   tenant_id=tenant.label)
        self.browser.verify(session.id, IdentityVerificationRule(self.target, identity.id,
            "[data-user]", None, "[data-tenant]", alias, None, tenant.label))
        return identity, session

    def capture(self, url, *, session=None, status=200, body=b'{"data":{"ok":true}}',
                method="GET", request_body=None, observed_at=NOW, source=None):
        packet = CapturePacket(
            CapturedRequest(method, url, (("Accept", "application/json"),), request_body, observed_at),
            CapturedResponse(status, (("Content-Type", "application/json"),), body,
                             observed_at + timedelta(milliseconds=5)),
            browser_session_id=session.id if session else None)
        return self.traffic.store_exchange(self.package, packet,
            source=source or (TrafficSource.BROWSER if session else TrafficSource.FIXTURE),
            capture_provider="LOCAL_FIXTURE", browser_manager=self.browser if session else None,
            anonymous=session is None)

    def learn(self, limits=LearningLimits()):
        run = self.learner.create(self.package, limits)
        completed = self.learner.run(self.package, run.run_id)
        return completed, self.ledger.profile(self.target)

    def test_role_feature_absence_is_not_denial_and_explicit_denial_is_recorded(self):
        admin, admin_session = self.session("admin_a", self.tenant_a, self.admin)
        member, member_session = self.session("member_a", self.tenant_a, self.member)
        self.capture("https://app.example.test/api/v1/settings", session=admin_session)
        self.capture("https://app.example.test/api/v1/projects", session=member_session)
        _, profile = self.learn()
        matrix = {(item["role_id"], item["feature"]): item
                  for item in profile.role_feature_matrix}
        self.assertEqual(matrix[self.admin.id, "settings"]["state"], "OBSERVED")
        self.assertEqual(matrix[self.member.id, "settings"]["state"], "NOT_OBSERVED")
        self.assertEqual(matrix[self.member.id, "settings"]["explicit_denials"], 0)
        self.capture("https://app.example.test/api/v1/settings", session=member_session, status=403)
        _, profile = self.learn()
        matrix = {(item["role_id"], item["feature"]): item
                  for item in profile.role_feature_matrix}
        self.assertEqual(matrix[self.member.id, "settings"]["explicit_denials"], 1)
        self.assertEqual(profile.coverage["identities_observed"], 2)

    def test_two_tenant_controls_and_anonymous_are_separate(self):
        _, admin_a = self.session("admin_a", self.tenant_a, self.admin)
        _, admin_b = self.session("admin_b", self.tenant_b, self.admin)
        self.capture("https://app.example.test/api/v1/projects", session=admin_a)
        self.capture("https://app.example.test/api/v1/projects", session=admin_b)
        self.capture("https://app.example.test/login")
        run, profile = self.learn()
        self.assertEqual(run.status, LearningStatus.COMPLETED)
        self.assertEqual(set(profile.tenants), {self.tenant_a.id, self.tenant_b.id})
        self.assertTrue(profile.anonymous)
        self.assertEqual(profile.provenance["traffic_examined"], 3)
        self.assertEqual(run.counts["browser_actions"], 0)

    def test_graphql_http_200_denial_and_no_secret_body_persistence(self):
        _, session = self.session("member_a", self.tenant_a, self.member)
        exchange = self.capture("https://app.example.test/graphql", session=session,
            method="POST", request_body=b'{"operationName":"GetProject","query":"query GetProject { project { id } }"}',
            body=b'{"data":null,"errors":[{"extensions":{"code":"FORBIDDEN"}}]}')
        _, profile = self.learn()
        operation = profile.operations[0]
        self.assertEqual(operation["protocol"], "GRAPHQL")
        self.assertIn("OBSERVED_DENIED", operation["results"])
        self.assertEqual(operation["metadata"]["body_evidence_id"], exchange.request.body_evidence_id)
        self.assertNotIn("query GetProject", str(profile.to_dict()))

    def test_http_200_without_positive_result_is_not_allowed(self):
        _, session = self.session("member_a", self.tenant_a, self.member)
        ambiguous = self.capture("https://app.example.test/api/v1/projects", session=session,
                                 body=b'{"message":"Please log in"}')
        successful = self.capture("https://app.example.test/api/v1/settings", session=session,
                                  body=b'{"data":{"enabled":true}}')
        self.learn()
        results = {item["exchange_id"]: item["result"] for item in self.ledger.observations(self.target)}
        self.assertEqual(results[ambiguous.id], "UNKNOWN")
        self.assertEqual(results[successful.id], "OBSERVED_ALLOWED")

    def test_burp_attribution_and_out_of_scope_exclusion(self):
        identity, session = self.session("admin_a", self.tenant_a, self.admin)
        self.capture("https://app.example.test/api/v1/projects", session=session,
                     source=TrafficSource.BURP)
        self.capture("https://outside.invalid/api/v1/projects")
        _, profile = self.learn()
        self.assertEqual(profile.coverage["traffic_observations"], 1)
        self.assertEqual(profile.identities[0]["identity_id"], identity.id)
        self.assertEqual(profile.provenance["traffic_examined"], 1)

    def test_response_object_hints_are_hashed_and_not_ownership_facts(self):
        _, session = self.session("admin_a", self.tenant_a, self.admin)
        self.capture("https://app.example.test/api/v1/projects/123", session=session,
                     body=b'{"id":123,"ownerId":"private-owner","tenantId":"private-tenant"}')
        _, profile = self.learn()
        inferred = [item for item in profile.known_objects if item["source"] == "RESPONSE_METADATA_ONLY"]
        self.assertEqual(len(inferred), 1)
        self.assertIsNone(inferred[0]["owner_identity_id"])
        self.assertTrue(inferred[0]["owner_claim_hash"])
        self.assertNotIn("private-owner", str(profile.to_dict()))
        self.assertFalse(profile.ownership)
        self.assertIn(inferred[0]["id"], profile.workflows[0]["object_ids"])

    def test_reauth_and_wrong_identity_excluded(self):
        identity, session = self.session("member_a", self.tenant_a, self.member, match=False)
        self.capture("https://app.example.test/api/v1/projects", session=session)
        run, profile = self.learn()
        self.assertEqual(run.status, LearningStatus.WAITING_LOGIN)
        self.assertEqual(profile.coverage["traffic_observations"], 0)
        self.assertIn("UNVERIFIED_TRAFFIC_EXCLUDED", run.limitations)
        self.assertEqual(run.counts["browser_actions"], 0)

    def test_budgets_existing_data_and_stability(self):
        _, session = self.session("admin_a", self.tenant_a, self.admin)
        for index in range(5):
            self.capture(f"https://app.example.test/api/v1/projects/{index}", session=session)
        first, profile = self.learn(LearningLimits(max_traffic_records=2))
        self.assertEqual(first.counts["traffic_examined"], 2)
        self.assertIn("TRAFFIC_BUDGET", first.limitations)
        self.assertEqual(first.status, LearningStatus.PARTIAL)
        second, updated = self.learn(LearningLimits(max_traffic_records=2))
        self.assertEqual(second.counts["observations_added"], 0)
        self.assertEqual(second.stop_reason, "STABLE_EXISTING_DATA")
        self.assertEqual(second.counts["browser_actions"], 0)

    def test_workflows_deduplicate_repeated_requests_and_keep_references(self):
        _, session = self.session("admin_a", self.tenant_a, self.admin)
        first = self.capture("https://app.example.test/api/v1/projects/123", session=session,
                             body=b'{"data":{"id":123}}')
        _, initial = self.learn()
        second = self.capture("https://app.example.test/api/v1/projects/123", session=session,
                              body=b'{"data":{"id":123}}')
        _, updated = self.learn()
        self.assertEqual(len(initial.workflows), 1)
        self.assertEqual(len(updated.workflows), 1)
        self.assertEqual(set(updated.workflows[0]["exchange_ids"]), {first.id, second.id})
        with sqlite3.connect(self.evidence.db_path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM behaviour_workflows").fetchone()[0], 1)
            self.assertIn("RESPONOBJ-", db.execute(
                "SELECT object_ids_json FROM behaviour_workflows").fetchone()[0])

    def test_stale_traffic_and_expected_access_provenance(self):
        _, session = self.session("admin_a", self.tenant_a, self.admin)
        self.capture("https://app.example.test/api/v1/projects", session=session,
                     observed_at=NOW - timedelta(days=45))
        self.ledger.set_expectation(self.target, role_id=self.admin.id, feature="projects",
                                    action="manage", expected_access="ALLOW", provenance="RESEARCHER")
        _, profile = self.learn()
        self.assertEqual(profile.coverage["state"], "STALE")
        self.assertEqual(profile.expected_access[0]["status"], "CONFIGURED_EXPECTATION")
        self.assertTrue(any(gap["code"] == "STALE_OBSERVATIONS" for gap in profile.gaps))

    def test_verified_disposable_ownership_and_parent_facts(self):
        identity, _ = self.session("admin_a", self.tenant_a, self.admin)
        proof = self.evidence.create_evidence(EvidenceType.BROWSER_EVENT,
            b"fictional owner and tenant read-back", source="LOCAL_FIXTURE",
            provenance=EvidenceProvenance("FIXTURE", "object", "readback", NOW),
            target_ref=self.target, sensitivity=Sensitivity.INTERNAL)

        def ready_object(kind, parent=None):
            item = self.objects.plan(target_id=self.target, package_id=self.package.id,
                object_type=kind, creator_identity_id=identity.id, tenant_id=self.tenant_a.id,
                recipe_id=kind, recipe_hash="a" * 64, test_name="codex-fixture-object",
                cleanup_strategy=CleanupStrategy.AUTO_CLEANUP, parent_id=parent)
            item = self.objects.transition(item.id, self.target, frozenset({ObjectState.PLANNED}),
                ObjectState.CREATING, "FIXTURE")
            item = self.objects.transition(item.id, self.target, frozenset({ObjectState.CREATING}),
                ObjectState.CREATED, "FIXTURE", evidence_ids=(proof.evidence_id,))
            item = self.objects.transition(item.id, self.target, frozenset({ObjectState.CREATED}),
                ObjectState.VERIFYING, "FIXTURE")
            item = self.objects.transition(item.id, self.target, frozenset({ObjectState.VERIFYING}),
                ObjectState.READY, "OWNERSHIP_VERIFIED", evidence_ids=(proof.evidence_id,),
                owner_principal_id=identity.id)
            for predicate, value in (("created_by", identity.id), ("resource_tenant", self.tenant_a.id)):
                self.evidence.create_fact(item.id, predicate, value, confidence=1.0,
                    evidence_ids=(proof.evidence_id,), source="OBJECT_FACTORY", target_ref=self.target)
            return item

        parent = ready_object("project")
        child = ready_object("dashboard", parent.id)
        _, profile = self.learn()
        self.assertEqual(profile.coverage["objects_observed"], 2)
        facts = self.evidence.list_facts_for_subject(child.id, limit=20).items
        self.assertTrue(any(fact.predicate == "belongs_to" and fact.object == parent.id
                            for fact in facts))
        self.assertTrue(any(fact.predicate == "owned_by" and fact.object == identity.id
                            for fact in facts))
        repeat, _ = self.learn()
        self.assertEqual(repeat.counts["facts_created"], 0)

    def test_cancel_and_invalid_limits(self):
        with self.assertRaises(ValueError):
            LearningLimits(max_traffic_records=501)
        run = self.learner.create(self.package)
        self.assertTrue(self.ledger.request_cancel(self.target, run.run_id))
        result = self.learner.run(self.package, run.run_id)
        self.assertEqual(result.status, LearningStatus.CANCELLED)
        self.assertFalse(self.ledger.request_cancel(self.target, run.run_id))

    def test_interrupted_created_run_is_reconciled(self):
        run = self.learner.create(self.package)
        self.assertEqual(self.ledger.reconcile(), 1)
        self.assertEqual(self.ledger.get_run(self.target, run.run_id).status, LearningStatus.PARTIAL)
        self.assertEqual(self.ledger.reconcile(), 0)
        self.assertEqual(self.learner.create(self.package).status, LearningStatus.CREATED)


if __name__ == "__main__":
    unittest.main()
