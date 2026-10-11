"""Phase 17 deterministic validation against policy-gated loopback runs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from hackbot.auth import AuthContextManager
from hackbot.browser import IdentityObservation, IdentityVerificationRule
from hackbot.config import SecretBindingConfig, SecretSettings
from hackbot.domain import ObservationState, Principal, Role, Tenant
from hackbot.evidence import EvidenceProvenance, Sensitivity
from hackbot.hypotheses import HypothesisStore
from hackbot.identity import IdentityStatus, MembershipStatus
from hackbot.response_compare import ResponseComparator
from hackbot.recon import Page
from hackbot.secrets import RoutedSecretProvider
from hackbot.validation_store import ValidationStatus, ValidationStore
from hackbot.validator import DeterministicValidatorEngine
from hackbot.service import create_app
from tests import test_orchestrator as orchestrator_fixture


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self.work = orchestrator_fixture.OrchestratorTests(
            methodName="test_scope_and_policy_changed_send_zero_requests")
        self.work.setUp()
        self.addCleanup(self.work.doCleanups)
        self.fx = self.work.fixture
        self.target = self.fx.package.target.id
        hypothesis = HypothesisStore(self.fx.store).add_manual(
            self.target, "AUTHORIZATION", "Controlled fixture authorization boundary",
            "Compare controlled owner and foreign actor")
        self.work.hypotheses.id = hypothesis.id
        self.work.context.hypothesis_id = hypothesis.id
        self.results = ValidationStore(self.fx.store)
        self.validator = DeterministicValidatorEngine(
            runs=self.work.runs, traffic=self.fx.traffic, evidence=self.fx.store,
            identities=self.fx.registry, hypotheses=HypothesisStore(self.fx.store),
            results=self.results)
        aliases = ("tenant_a_owner", "tenant_a_member", "tenant_b_admin")
        bindings = tuple(SecretBindingConfig(
            f"ref:{alias}", f"env:HACKBOT_SECRET_{alias.upper()}", "COOKIE") for alias in aliases)
        provider = RoutedSecretProvider(SecretSettings(bindings=bindings), {
            f"HACKBOT_SECRET_{alias.upper()}": f"fixture_actor={alias}" for alias in aliases})
        self.fx.auth = AuthContextManager(self.fx.registry, provider)
        self.fx.browser.auth = self.fx.auth
        self.fx.executor.auth = self.fx.auth
        self.fx.executor.secrets = provider
        self.tenants = {
            label: self.fx.registry.register_tenant(Tenant(
                target_id=self.target, label=label, kind="ORG", external_id=label))
            for label in ("tenant-a", "tenant-b")}
        self.roles = {
            label: self.fx.registry.register_role(Role(target_id=self.target, name=label))
            for label in ("admin", "member")}
        self.actors = {}
        for alias in aliases:
            identity = self.fx.registry.register_identity(
                self.target, alias, status=IdentityStatus.ACTIVE, secret_ref=f"ref:{alias}")
            self.fx.auth.prepare(self.target, identity.id)
            session = self.fx.browser.create(self.target, identity.id)
            self.fx.browser.start(session.id)
            self.fx.browser.login_complete(session.id)
            tenant_label = "tenant-b" if alias.startswith("tenant_b") else "tenant-a"
            self.fx.driver.observations[session.id] = IdentityObservation(
                user_id=alias, tenant_id=tenant_label)
            rule = IdentityVerificationRule(self.target, identity.id, "[data-user]", None,
                                            "[data-tenant]", alias, None, tenant_label)
            self.fx.browser.verify(session.id, rule)
            tenant = self.tenants[tenant_label]
            role = self.roles["member" if alias.endswith("member") else "admin"]
            evidence = self._evidence(f"membership:{alias}:{tenant_label}")
            fact = self.fx.store.create_fact(identity.id, "member_of", tenant.id, confidence=1,
                                             evidence_ids=(evidence,), source="FIXTURE",
                                             target_ref=self.target)
            self.fx.registry.add_membership(
                identity.id, tenant.id, status=MembershipStatus.ACTIVE, role_ids=(role.id,),
                observation_state=ObservationState.OBSERVED, evidence_ids=(evidence,), fact_id=fact.fact_id)
            self.actors[alias] = (identity, session)
        self.work.context.flags.update({"verified_sessions", "multiple_tenants", "known_ownership"})
        self.work.context.identities = tuple(
            {"id": identity.id, "verified_session_id": session.id}
            for identity, session in self.actors.values())

    def _evidence(self, content: str) -> str:
        return self.fx.store.create_evidence(
            "TEST_ASSERTION", content.encode(), source="FIXTURE",
            provenance=EvidenceProvenance(system="FIXTURE"), target_ref=self.target,
            sensitivity=Sensitivity.INTERNAL).evidence_id

    def fact(self, object_hash: str, predicate: str, value: str) -> None:
        reference = self._evidence(f"{predicate}:{value}")
        self.fx.store.create_fact(object_hash, predicate, value, confidence=1,
                                  evidence_ids=(reference,), source="FIXTURE", target_ref=self.target)

    def protected(self, *, policy="TENANT_ONLY", visibility="PRIVATE", object_name="object-a") -> str:
        object_hash = digest(object_name)
        self.fact(object_hash, "resource_visibility", visibility)
        self.fact(object_hash, "access_policy", policy)
        self.fact(object_hash, "resource_tenant", self.tenants["tenant-a"].id)
        self.fact(object_hash, "resource_tenant_marker", digest("tenant-a"))
        return object_hash

    def action(self, path: str, alias: str | None, role: str, object_hash: str,
               *, vulnerability="CROSS_TENANT", control_kind=None, operation=None):
        identity, session = self.actors[alias] if alias else (None, None)
        return self.work.action(
            path, actor="AUTHENTICATED" if alias else "ANONYMOUS",
            identity=identity.id if identity else None, session=session.id if session else None,
            role=role, vulnerability=vulnerability, object_ref_hash=object_hash,
            object_type="fixture_record", control_kind=control_kind, operation=operation)

    def run_fixture(self, skill: str, actions: list[tuple[dict, dict]]) -> str:
        plan = self.work.plan(actions, skill_name=skill,
                              workflow=[{"type": "EXECUTE_REQUEST"} for _ in actions] +
                                       [{"type": "COMPARE_RESPONSE"}],
                              comparisons=[{"control_slot": 0, "boundary_slot": 1}],
                              budget=len(actions), category="authorization")
        run_id = self.work.start(plan)
        for _ in range(len(actions) + 4):
            result = self.work.advance(run_id)
            if result["run"]["status"] == "COMPLETED":
                return run_id
            if result["run"]["status"] in {"BLOCKED", "REJECTED", "FAILED", "BUDGET_EXHAUSTED"}:
                self.fail(f"fixture run failed: {result['run']['status']}")
        self.fail("fixture run did not complete")

    def auth_run(self, *, skill="cross-tenant-object-authorization", boundary_alias="tenant_b_admin",
                 boundary_path="/validated/object-a", control_path="/validated/object-a",
                 visibility="PRIVATE", object_name="object-a") -> str:
        object_hash = self.protected(visibility=visibility, object_name=object_name,
                                     policy="OWNER_ONLY" if skill == "horizontal-object-authorization" else
                                     "ROLE_RESTRICTED" if skill in {"vertical-role-authorization",
                                                                    "hidden-function-authorization"} else "TENANT_ONLY")
        if skill == "horizontal-object-authorization":
            self._principals()
            self.fact(object_hash, "resource_owner", self.principals["tenant_a_owner"].id)
        if skill in {"vertical-role-authorization", "hidden-function-authorization"}:
            self.fact(object_hash, "required_role", self.roles["admin"].id)
        actions = [self.action(control_path, "tenant_a_owner", "CONTROL", object_hash),
                   self.action(boundary_path, boundary_alias, "BOUNDARY", object_hash),
                   self.action(boundary_path, boundary_alias, "BOUNDARY", object_hash),
                   self.action("/validated/missing", boundary_alias, "OTHER", digest("missing"),
                               control_kind="INVALID_OBJECT")]
        return self.run_fixture(skill, actions)

    def _principals(self):
        self.principals = {}
        for alias in ("tenant_a_owner", "tenant_a_member"):
            identity, _ = self.actors[alias]
            principal = self.fx.registry.register_principal(
                Principal(target_id=self.target, label=alias))
            reference = self._evidence(f"principal:{alias}")
            fact = self.fx.store.create_fact(identity.id, "resolves_to", principal.id,
                                             confidence=1, evidence_ids=(reference,),
                                             source="FIXTURE", target_ref=self.target)
            self.fx.registry.link_principal(identity.id, principal.id,
                                            observation_state=ObservationState.OBSERVED,
                                            evidence_ids=(reference,), fact_id=fact.fact_id)
            self.principals[alias] = principal

    def test_cross_tenant_confirmation_audit_and_duplicate(self):
        run_id = self.auth_run()
        sent_before = len(self.fx.server.received)
        with patch("requests.sessions.Session.send", side_effect=AssertionError("validator sent traffic")):
            result, finding = self.validator.validate_run(run_id, self.target)
            again, same = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.reproduction_count, 2)
        self.assertEqual(again.id, result.id)
        self.assertEqual(same.id, finding.id)
        self.assertEqual(len(self.fx.server.received), sent_before)
        self.assertTrue(finding.evidence_ids)
        with self.fx.store._connection() as db:
            chain = db.execute(
                "SELECT f.finding_id,v.validation_id,r.run_id,p.plan_id,h.hypothesis_id,"
                "p.skill_id,a.action_id,d.decision_id,pm.permit_id,e.exchange_id "
                "FROM findings f JOIN validations v ON v.validation_id=f.validation_id "
                "JOIN plan_runs r ON r.run_id=v.run_id JOIN skill_plans p ON p.plan_id=r.plan_id "
                "JOIN hypotheses h ON h.hypothesis_id=v.hypothesis_id "
                "JOIN plan_run_steps s ON s.run_id=r.run_id AND s.role='BOUNDARY' "
                "JOIN policy_actions a ON a.action_id=s.action_id "
                "JOIN policy_decisions d ON d.decision_id=s.decision_id "
                "JOIN executor_permits pm ON pm.permit_id=s.permit_id "
                "JOIN executor_events ev ON ev.permit_id=pm.permit_id "
                "JOIN traffic_exchanges e ON e.exchange_id=ev.exchange_id "
                "WHERE f.finding_id=? AND ev.event_type='REQUEST_SENT' LIMIT 1",
                (finding.id,)).fetchone()
        self.assertIsNotNone(chain)
        self.assertEqual(chain["run_id"], run_id)
        second_run = self.auth_run()
        duplicate, original = self.validator.validate_run(second_run, self.target)
        self.assertEqual(duplicate.status, ValidationStatus.DUPLICATE_CANDIDATE)
        self.assertEqual(original.id, finding.id)
        self.assertEqual(self.results.stats(self.target)["findings"], 1)

    def test_denied_public_and_control_failure_never_confirm(self):
        denied = self.auth_run(boundary_path="/validated/denied")
        rejected, finding = self.validator.validate_run(denied, self.target)
        self.assertEqual(rejected.status, ValidationStatus.REJECTED)
        self.assertIsNone(finding)
        public = self.auth_run(visibility="PUBLIC", object_name="object-b",
                               control_path="/validated/object-b", boundary_path="/validated/object-b")
        public_result, _ = self.validator.validate_run(public, self.target)
        self.assertEqual(public_result.status, ValidationStatus.REJECTED)
        self.assertIn("INTENTIONALLY_PUBLIC", public_result.reason_codes)
        context = self.validator._context(self.work.runs.get(denied, self.target))
        failed_owner = replace(context.observations[0], features=replace(
            context.observations[0].features, status_code=403))
        invalid_context = replace(context, observations=(failed_owner, *context.observations[1:]))
        decision = self.validator.registry.select("cross-tenant-object-authorization").evaluate(
            invalid_context, self.validator)
        self.assertEqual(decision.status, ValidationStatus.INVALID_TEST)

    def test_horizontal_and_vertical(self):
        for skill, alias in (("horizontal-object-authorization", "tenant_a_member"),
                             ("vertical-role-authorization", "tenant_a_member"),
                             ("hidden-function-authorization", "tenant_a_member")):
            with self.subTest(skill=skill):
                role_skill = skill != "horizontal-object-authorization"
                run_id = self.auth_run(
                    skill=skill, boundary_alias=alias,
                    object_name="object-c" if role_skill else "object-a",
                    control_path="/validated/object-c" if role_skill else "/validated/object-a",
                    boundary_path="/validated/object-c" if role_skill else "/validated/object-a")
                result, finding = self.validator.validate_run(run_id, self.target)
                self.assertEqual(result.status, ValidationStatus.CONFIRMED)
                self.assertIsNotNone(finding)

    def test_anonymous_download_and_sensitive_metadata(self):
        object_hash = self.protected(object_name="private-file")
        self.fact(object_hash, "data_classification", "PROTECTED_FILE")
        run_id = self.run_fixture("unauthenticated-sensitive-download", [
            self.action("/validated/private-file", "tenant_a_owner", "CONTROL", object_hash),
            self.action("/validated/private-file", None, "BOUNDARY", object_hash),
            self.action("/validated/private-file", None, "BOUNDARY", object_hash),
            self.action("/validated/missing", None, "OTHER", digest("missing"),
                        control_kind="INVALID_OBJECT")])
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertNotIn("disposable-fixture-file", json.dumps(finding.to_dict()))
        self.assertNotIn("disposable-fixture-file", json.dumps(result.to_dict()))

    def test_graphql_data_not_http_200_alone(self):
        object_hash = self.protected()
        self.fact(object_hash, "graphql_operation", "protected_node")
        actions = [self.action("/validated/graphql", "tenant_a_owner", "CONTROL", object_hash,
                               operation="protected_node"),
                   self.action("/validated/graphql", "tenant_b_admin", "BOUNDARY", object_hash,
                               operation="protected_node"),
                   self.action("/validated/graphql", "tenant_b_admin", "BOUNDARY", object_hash,
                               operation="protected_node"),
                   self.action("/validated/graphql-invalid", "tenant_b_admin", "OTHER",
                               digest("missing"), control_kind="INVALID_OBJECT",
                               operation="protected_node")]
        run_id = self.run_fixture("graphql-object-authorization", actions)
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)

        context = self.validator._context(self.work.runs.get(run_id, self.target))
        denied = replace(context.observations[1], features=replace(
            context.observations[1].features, graphql_data_present=False,
            graphql_errors_present=True))
        denied_again = replace(context.observations[2], features=denied.features)
        invalid_negative = replace(context.observations[3], features=replace(
            context.observations[3].features, graphql_data_present=True,
            graphql_errors_present=False))
        invalid_context = replace(context, observations=(
            context.observations[0], denied, denied_again, invalid_negative))
        decision = self.validator.registry.select("graphql-object-authorization").evaluate(
            invalid_context, self.validator)
        self.assertEqual(decision.status, ValidationStatus.INVALID_TEST)
        self.assertIn("NEGATIVE_CONTROL_FAILED", decision.reasons)

    def test_validation_rows_are_append_only(self):
        run_id = self.auth_run()
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertIsNotNone(finding)
        with self.fx.store._connection() as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE validations SET status='REJECTED' WHERE validation_id=?",
                           (result.id,))
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM validation_checks WHERE validation_id=?", (result.id,))

    def test_same_root_cause_across_distinct_routes_is_one_finding(self):
        self.fact(self.protected(), "root_cause_key", "shared-fixture-helper")
        first_run = self.auth_run()
        first, finding = self.validator.validate_run(first_run, self.target)
        self.assertEqual(first.status, ValidationStatus.CONFIRMED)
        second_run = self.auth_run(boundary_path="/validated/object-a-alt",
                                   control_path="/validated/object-a-alt")
        duplicate, original = self.validator.validate_run(second_run, self.target)
        self.assertEqual(duplicate.status, ValidationStatus.DUPLICATE_CANDIDATE)
        self.assertEqual(original.id, finding.id)
        self.assertEqual(len(original.locations), 2)
        self.assertEqual(self.results.stats(self.target)["findings"], 1)

    def test_sample_credential_and_client_side_without_browser_proof(self):
        object_hash = self.protected(object_name="example-key")
        self.fact(object_hash, "data_classification", "CREDENTIAL")
        self.fact(object_hash, "sample_data", "TRUE")
        run_id = self.run_fixture("sensitive-data-exposure", [
            self.action("/validated/example-key", "tenant_a_owner", "CONTROL", object_hash),
            self.action("/validated/example-key", None, "BOUNDARY", object_hash),
            self.action("/validated/example-key", None, "BOUNDARY", object_hash),
            self.action("/validated/missing", None, "OTHER", digest("missing"),
                        control_kind="INVALID_OBJECT")])
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertIn("TEST_DATA_ONLY", result.reason_codes)
        self.assertIsNone(finding)
        from hackbot.validator import ClientSideValidator
        context = self.validator._context(self.work.runs.get(run_id, self.target))
        for skill in ("check-before-transform-dom-xss", "postmessage-trust-analysis"):
            decision = ClientSideValidator(skill).evaluate(context, self.validator)
            self.assertEqual(decision.status, ValidationStatus.INSUFFICIENT_EVIDENCE)
            self.assertFalse(decision.supporting_evidence_ids)

    def test_private_api_target_scoping_and_manual_review(self):
        run_id = self.auth_run()
        events = []
        def scoped_package(package_id):
            if package_id != self.fx.package.id:
                raise LookupError("target not found")
            return self.fx.package
        service = SimpleNamespace(package=scoped_package, run_store=self.work.runs,
                                  validator=self.validator, validations=self.results,
                                  audit=lambda event, **kwargs: events.append(event),
                                  logger=SimpleNamespace(error=lambda *args, **kwargs: None))
        client = create_app(runtime=service).test_client()
        self.assertEqual(client.get("/v1/findings?target=unknown").status_code, 404)
        self.assertEqual(client.post(f"/v1/runs/{run_id}/validate", json={"target": "unknown"}).status_code, 404)
        before = len(self.fx.server.received)
        with patch("requests.sessions.Session.send", side_effect=AssertionError("validator sent traffic")):
            response = client.post(f"/v1/runs/{run_id}/validate", json={"target": "example"})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(len(self.fx.server.received), before)
        payload = response.get_json()
        self.assertEqual(payload["validation"]["status"], "CONFIRMED")
        self.assertFalse(payload["request_sent"])
        finding_id = payload["finding"]["id"]
        validation_id = payload["validation"]["id"]
        self.assertEqual(client.get("/v1/findings?target=example").get_json()["items"][0]["id"], finding_id)
        self.assertEqual(client.get(f"/v1/findings/{finding_id}?target=example").get_json()["finding"]["id"],
                         finding_id)
        self.assertEqual(client.get(f"/v1/validations/{validation_id}?target=example")
                         .get_json()["validation"]["id"], validation_id)
        self.assertEqual(client.get(f"/v1/findings/{finding_id}?target=unknown").status_code, 404)
        self.assertIn("finding_created", events)
        evidence_id = payload["validation"]["supporting_evidence_ids"][0]
        manual = self.validator.record_manual(run_id, self.target,
                                              ValidationStatus.NEEDS_MANUAL_REVIEW,
                                              (evidence_id,), "RESEARCHER_REVIEW")
        self.assertEqual(manual.source, "MANUAL")
        self.assertEqual(self.results.stats(self.target)["findings"], 1)

    def test_response_comparator_exact_volatile_paths_preserve_identity(self):
        from hackbot.response_compare import _walk
        volatile = frozenset({"/requestId", "/timestamp"})
        def normalized(value):
            return _walk(value, "", volatile, [0], set(), set())
        self.assertEqual(normalized({"requestId": "a", "timestamp": "now", "id": "x"}),
                         normalized({"requestId": "b", "timestamp": "later", "id": "x"}))
        self.assertNotEqual(normalized({"requestId": "a", "tenantId": "a", "id": "x"}),
                            normalized({"requestId": "b", "tenantId": "b", "id": "x"}))
        with self.assertRaises(ValueError):
            ResponseComparator(self.fx.store, volatile_json_paths=frozenset({"/id"}))
        with self.assertRaises(ValueError):
            ResponseComparator(self.fx.store, volatile_json_paths=frozenset({"/data/node/tenantId"}))

    def test_paginated_fact_relationship_is_not_trusted_as_complete(self):
        with patch.object(self.fx.store, "find_facts", return_value=Page((), "more")):
            value, evidence = self.validator.fact_value("resource-hash", "resource_visibility",
                                                        self.target)
        self.assertIsNone(value)
        self.assertEqual(evidence, ())

