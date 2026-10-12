"""Phase 19 specialist fixtures use only the local loopback test server."""

from __future__ import annotations

import ast
import unittest
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from hackbot.authorization import AuthorizationSpecialist
from hackbot.authorization_binding import resolve_authorization_request, single_rename_operation
from hackbot.authorization_store import AuthorizationMode, AuthorizationStore, Boundary, HuntStatus, MatrixResult
from hackbot.config import SecretBindingConfig, SecretSettings
from hackbot.domain import ObservationState, Principal, Role, Tenant, TrafficSource
from hackbot.evidence import EvidenceProvenance
from hackbot.hypotheses import HypothesisStore
from hackbot.identity import MembershipStatus
from hackbot.orchestrator import PlanOrchestrator
from hackbot.policy_models import ActorMode
from hackbot.profile import SignalSource, SurfaceSignal, TargetProfile
from hackbot.plan_runs import PlanRunStore
from hackbot.policy_store import PolicyStore
from hackbot.secrets import RoutedSecretProvider
from hackbot.skill_plans import (PrerequisiteChecker, PrerequisiteState, SkillContextBuilder,
                                 SkillPlanStore, SkillPlanner, SkillRouter)
from hackbot.skills import SkillRegistry
from hackbot.target_policy import PolicyDecision
from hackbot.traffic import CapturedRequest, CapturedResponse
from hackbot.validator import DeterministicValidatorEngine
from hackbot.validation_store import ValidationStatus, ValidationStore
from tests import test_object_factory as _object_factory_fixture


class RenameDocumentSafetyTests(unittest.TestCase):
    def test_only_one_plain_rename_operation_is_eligible(self):
        query = ("mutation RenameProject($id:ID!,$name:String!)"
                 "{renameProject(id:$id,name:$name){id name owner tenant}}")
        self.assertEqual(single_rename_operation(query, "id", "name"), "RenameProject")
        for unsafe in (
                query + " mutation Extra{deleteProject(id:1){id}}",
                query.replace("renameProject(", "alias:renameProject("),
                query.replace("id name owner tenant", "id name secrets"),
                query.replace("renameProject", "updateProject"),
                query.replace("{id name owner tenant}", "{id name {nested}}")):
            with self.subTest(unsafe=unsafe):
                self.assertIsNone(single_rename_operation(unsafe, "id", "name"))


class AuthorizationSpecialistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = _object_factory_fixture.ObjectFactoryTests(
            methodName="test_create_verify_facts_cleanup_and_no_repeat")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        aliases = ("tenant_a_admin", "tenant_a_member", "tenant_b_admin")
        bindings = tuple(SecretBindingConfig(
            "ref:fixture_cookie_" + alias,
            "env:HACKBOT_SECRET_" + alias.upper(), "COOKIE") for alias in aliases)
        self.fx.provider = RoutedSecretProvider(
            SecretSettings(bindings=bindings),
            {"HACKBOT_SECRET_" + alias.upper(): "fixture_actor=" + alias for alias in aliases})
        self.fx.auth.secrets = self.fx.provider
        self.fx.executor.secrets = self.fx.provider
        self.target = self.fx.package.target.id
        self.tenants = {}
        self.roles = {}
        self.ledger = AuthorizationStore(self.fx.store)
        self.hypotheses = HypothesisStore(self.fx.store)
        skills = SkillRegistry(Path(__file__).resolve().parents[1] / "src/hackbot/skill_catalog")
        checker = PrerequisiteChecker()
        context = SkillContextBuilder(self.fx.store, self.fx.registry, self.fx.traffic,
                                      self.fx.browser, objects=self.fx.objects)
        self.specialist = AuthorizationSpecialist(
            identities=self.fx.registry, browser=self.fx.browser, objects=self.fx.objects,
            traffic=self.fx.traffic, evidence=self.fx.store,
            hypotheses=self.hypotheses, ledger=self.ledger, context=context,
            router=SkillRouter(skills, checker),
            planner=SkillPlanner(skills, checker, self.fx.policy, SkillPlanStore(self.fx.store)))

    def actor(self, alias: str, tenant_label: str, role: str | None = None):
        identity, session = self.fx.owned_session(
            alias, secret_ref="ref:fixture_cookie_" + alias)
        principal = self.fx.registry.register_principal(Principal(target_id=self.target, label=alias))
        principal_evidence = self.fx.store.create_evidence(
            "TEST_ASSERTION", f"principal:{alias}".encode(), source="FIXTURE",
            provenance=EvidenceProvenance(system="FIXTURE"), target_ref=self.target)
        principal_fact = self.fx.store.create_fact(
            identity.id, "resolves_to", principal.id, confidence=1,
            evidence_ids=(principal_evidence.evidence_id,), source="FIXTURE", target_ref=self.target)
        self.fx.registry.link_principal(identity.id, principal.id,
                                        observation_state=ObservationState.OBSERVED,
                                        evidence_ids=(principal_evidence.evidence_id,),
                                        fact_id=principal_fact.fact_id)
        tenant = self.tenants.get(tenant_label)
        if tenant is None:
            tenant = self.fx.registry.register_tenant(
                Tenant(target_id=self.target, label=tenant_label, kind="organization"))
            self.tenants[tenant_label] = tenant
        role_id = None
        if role is not None:
            observed_role = self.roles.get(role)
            if observed_role is None:
                observed_role = self.fx.registry.register_role(Role(target_id=self.target, name=role))
                self.roles[role] = observed_role
            role_id = observed_role.id
        evidence = self.fx.store.create_evidence(
            "TEST_ASSERTION", f"membership:{alias}:{tenant_label}".encode(), source="FIXTURE",
            provenance=EvidenceProvenance(system="FIXTURE"), target_ref=self.target)
        fact = self.fx.store.create_fact(
            identity.id, "member_of", tenant.id, confidence=1,
            evidence_ids=(evidence.evidence_id,), source="FIXTURE", target_ref=self.target)
        self.fx.registry.add_membership(
            identity.id, tenant.id, status=MembershipStatus.ACTIVE,
            role_ids=(role_id,) if role_id else (),
            observation_state=ObservationState.OBSERVED,
            evidence_ids=(evidence.evidence_id,), fact_id=fact.fact_id)
        return identity, session, tenant

    def protect(self, item, tenant, *, policy: str, role_id: str | None = None,
                owner_principal: str | None = None):
        external = self.specialist._external_id(item)
        subject = hashlib.sha256(external.encode()).hexdigest()
        facts = [("resource_visibility", "PRIVATE"), ("access_policy", policy),
                 ("resource_tenant", tenant.id)]
        if role_id:
            facts.append(("required_role", role_id))
        if owner_principal:
            facts.append(("resource_owner", owner_principal))
        for predicate, value in facts:
            self.fx.store.create_fact(subject, predicate, value, confidence=1,
                                      evidence_ids=(item.verification_evidence_ids[0],),
                                      source="FIXTURE", target_ref=self.target)

    def graphql_owner_exchange(self, owner, session, item, *, mutation: bool = False,
                               rename: str | None = None):
        external = self.specialist._external_id(item)
        operation = ("mutation RenameProject($id:ID!,$name:String!){renameProject(id:$id,name:$name){id name owner tenant}}"
                     if rename is not None else
                     "mutation RenameProject($id:ID!){node(id:$id){id name owner tenant}}"
                     if mutation else
                     "query GetProject($id:ID!){node(id:$id){id name owner tenant}}")
        variables = {"id": external}
        if rename is not None:
            variables["name"] = rename
        body = json.dumps({"query": operation,
                           "variables": variables,
                           "operationName": "RenameProject" if mutation else "GetProject"}).encode()
        request = CapturedRequest("POST", self.fx.base + "/fixture/graphql",
                                  headers=(("Content-Type", "application/json"),), body=body,
                                  operation_id="GQL-" + ("2" if mutation else "1") * 32)
        exchange = self.fx.traffic.store_request(
            self.fx.package, request, source=TrafficSource.FIXTURE,
            capture_provider="FIXTURE", browser_manager=self.fx.browser,
            browser_session_id=session.id, auth_material_observed=True)
        value = self.fx.server.fixture_objects[external]
        if rename is not None:
            value["name"] = rename
        return self.fx.traffic.store_response(
            exchange.id, CapturedResponse(200, (("Content-Type", "application/json"),),
                                          json.dumps({"data": {"node": value}}).encode()))

    def fixture_object(self, *, role: str | None = None,
                       object_type: str = "project"):
        owner, session, tenant = self.actor("tenant_a_admin", "tenant-a", role=role)
        self.fx.recipe(recipe_id="project_a", tenant="tenant-a", owner="tenant_a_admin",
                       object_type=object_type)
        result = self.fx.factory.resolve(
            package_id=self.fx.package.id, recipe_id="project_a", identity_id=owner.id,
            tenant_id=tenant.id, session_id=session.id, purpose="Authorization fixture")
        self.assertEqual(result.outcome, "READY")
        return owner, session, tenant, result.item

    def test_no_object_or_owner_request_produces_no_candidate_and_no_traffic(self):
        self.actor("tenant_a_admin", "tenant-a")
        self.actor("tenant_b_admin", "tenant-b")
        before = len(self.fx.server.received)
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id)
        self.assertEqual(self.specialist.generate(hunt, self.fx.package), ())
        self.assertEqual(self.ledger.get_hunt(hunt.id, self.target).status, HuntStatus.BLOCKED)
        self.assertEqual(len(self.fx.server.received), before)

    def test_real_object_write_record_does_not_become_autonomous_candidate(self):
        owner, session, _ = self.actor("tenant_a_admin", "tenant-a")
        self.actor("tenant_b_admin", "tenant-b")
        request = CapturedRequest("PATCH", self.fx.base + "/fixture/tenant-a/projects/real-object",
                                  body=b'{"name":"test"}')
        exchange = self.fx.traffic.store_request(
            self.fx.package, request, source=TrafficSource.FIXTURE,
            capture_provider="FIXTURE", browser_manager=self.fx.browser,
            browser_session_id=session.id, auth_material_observed=True)
        self.fx.traffic.store_response(
            exchange.id, CapturedResponse(200, (("Content-Type", "application/json"),),
                                          b'{"id":"real-object","owner":"tenant_a_admin"}'))
        before = len(self.fx.server.received)
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id,
                                       mode=AuthorizationMode.BOUNDED_AUTONOMOUS)
        self.assertEqual(self.specialist.generate(hunt, self.fx.package), ())
        self.assertEqual(len(self.fx.server.received), before)
        self.assertEqual(self.ledger.get_hunt(hunt.id, self.target).status, HuntStatus.BLOCKED)

    def test_cross_tenant_candidate_uses_verified_object_and_owner_traffic(self):
        owner, _, tenant, item = self.fixture_object()
        foreign, _, foreign_tenant = self.actor("tenant_b_admin", "tenant-b")
        before = len(self.fx.server.received)
        surface = self.specialist.profile(self.fx.package)
        self.assertEqual(len(surface.objects), 1)
        self.assertEqual(surface.objects[0].id, item.id)
        self.assertTrue(surface.operations)
        self.assertTrue(surface.operations[0].semantic_owner_success)
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id,
                                       mode=AuthorizationMode.PLAN_ONLY, candidate_limit=3)
        candidates = self.specialist.generate(hunt, self.fx.package)
        cross = next(candidate for candidate in candidates if candidate.boundary is Boundary.CROSS_TENANT)
        self.assertEqual(cross.owner_identity_id, owner.id)
        self.assertEqual(cross.boundary_identity_id, foreign.id)
        self.assertEqual(cross.test_object_id, item.id)
        self.assertIn("VERIFIED_OBJECT_OWNERSHIP", cross.reasons)
        self.assertEqual(len(self.fx.server.received), before)
        self.assertEqual(len(self.ledger.matrix(self.target)), 1)
        self.assertEqual(self.ledger.matrix(self.target)[0]["result"], "OBSERVED_ALLOWED")
        self.assertEqual(tenant.id, item.tenant_id)
        self.assertNotEqual(foreign_tenant.id, item.tenant_id)

    def test_nested_parent_child_relation_creates_bounded_plan(self):
        owner, owner_session, tenant, parent = self.fixture_object()
        self.fx.recipe(recipe_id="dashboard_a", tenant="tenant-a", owner="tenant_a_admin",
                       object_type="dashboard", parent_type="project")
        child_result = self.fx.factory.resolve(
            package_id=self.fx.package.id, recipe_id="dashboard_a", identity_id=owner.id,
            tenant_id=tenant.id, session_id=owner_session.id, parent_id=parent.id,
            purpose="Nested authorization fixture")
        self.assertEqual(child_result.outcome, "READY")
        child = child_result.item
        foreign, foreign_session, foreign_tenant = self.actor("tenant_b_admin", "tenant-b")
        self.fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        foreign_parent = self.fx.factory.resolve(
            package_id=self.fx.package.id, recipe_id="project_b", identity_id=foreign.id,
            tenant_id=foreign_tenant.id, session_id=foreign_session.id,
            purpose="Nested foreign control")
        self.assertEqual(foreign_parent.outcome, "READY")
        parent_external = self.specialist._external_id(parent)
        child_external = self.specialist._external_id(child)
        self.fx.server.fixture_objects[child_external]["parentId"] = parent_external
        request = CapturedRequest(
            "GET", self.fx.base + "/fixture/tenant-a/projects/" + parent_external +
            "/dashboards/" + child_external)
        exchange = self.fx.traffic.store_request(
            self.fx.package, request, source=TrafficSource.FIXTURE,
            capture_provider="FIXTURE", browser_manager=self.fx.browser,
            browser_session_id=owner_session.id, auth_material_observed=True)
        self.fx.traffic.store_response(
            exchange.id, CapturedResponse(200, (("Content-Type", "application/json"),),
                                          json.dumps({"id": child_external,
                                                      "parentId": parent_external,
                                                      "owner": "tenant_a_admin",
                                                      "tenant": "tenant-a"}).encode()))
        before = len(self.fx.server.received)
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id,
                                       mode=AuthorizationMode.BOUNDED_AUTONOMOUS,
                                       candidate_limit=20)
        candidates = self.specialist.generate(hunt, self.fx.package)
        nested = next(item for item in candidates if item.boundary is Boundary.PARENT_CHILD)
        self.assertEqual(nested.status, "CANDIDATE")
        prepared = self.specialist.prepare(nested.id, self.fx.package)
        self.assertEqual(prepared.status, "PLANNED")
        self.assertIsNotNone(prepared.plan_id)
        self.assertEqual(len(self.fx.server.received), before)

    def test_unverified_second_identity_is_only_a_lead_and_sends_no_request(self):
        _, _, _, _ = self.fixture_object()
        foreign, foreign_session, _ = self.actor("tenant_b_admin", "tenant-b")
        self.fx.browser.stop(foreign_session.id)
        before = len(self.fx.server.received)
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id, candidate_limit=2)
        candidates = self.specialist.generate(hunt, self.fx.package)
        cross = next(candidate for candidate in candidates if candidate.boundary is Boundary.CROSS_TENANT)
        self.assertIsNone(next(actor for actor in self.specialist.profile(self.fx.package).actors
                               if actor.identity_id == foreign.id).session_id)
        self.assertEqual(len(self.fx.server.received), before)
        self.assertEqual(cross.status, "CANDIDATE")

    def test_same_boundary_is_deduplicated_across_hunts(self):
        self.fixture_object()
        self.actor("tenant_b_admin", "tenant-b")
        first = self.ledger.create_hunt(self.target, self.fx.package.id, candidate_limit=2)
        first_rows = self.specialist.generate(first, self.fx.package)
        second = self.ledger.create_hunt(self.target, self.fx.package.id, candidate_limit=2)
        second_rows = self.specialist.generate(second, self.fx.package)
        self.assertEqual({item.id for item in first_rows}, {item.id for item in second_rows})
        self.assertLessEqual(len(self.ledger.list_candidates(self.target)), 2)
        self.assertEqual({item.id for item in second_rows},
                         {item.id for item in self.ledger.list_candidates(self.target, hunt_id=second.id)})

    def test_cross_tenant_plan_uses_exact_owned_objects_and_no_raw_ids(self):
        _, _, _, object_a = self.fixture_object()
        owner_b, session_b, tenant_b = self.actor("tenant_b_admin", "tenant-b")
        self.fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        result_b = self.fx.factory.resolve(
            package_id=self.fx.package.id, recipe_id="project_b", identity_id=owner_b.id,
            tenant_id=tenant_b.id, session_id=session_b.id, purpose="Authorization fixture")
        self.assertEqual(result_b.outcome, "READY")
        before = len(self.fx.server.received)
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id, candidate_limit=3)
        candidate = next(item for item in self.specialist.generate(hunt, self.fx.package)
                         if item.boundary is Boundary.CROSS_TENANT and
                         item.test_object_id == object_a.id)
        prepared = self.specialist.prepare(candidate.id, self.fx.package)
        self.assertEqual(prepared.status, "PLANNED")
        self.assertEqual(len(self.fx.server.received), before)
        plan = SkillPlanStore(self.fx.store).get(prepared.plan_id, self.target)
        self.assertEqual(plan["skill_id"], "cross-tenant-object-authorization")
        self.assertEqual(len(plan["proposed_actions"]), 5)
        self.assertEqual({item["variant"] for item in plan["request_templates"]},
                         {"OWNER", "FOREIGN", "INVALID_OBJECT"})
        self.assertTrue(all("url" not in item for item in plan["request_templates"]))
        self.assertEqual({item["test_object_id"] for item in plan["request_templates"]},
                         {object_a.id, result_b.item.id})
        requirements = self.fx.objects.requirements(prepared.plan_id, self.target)
        self.assertEqual({item["test_object_id"] for item in requirements},
                         {object_a.id, result_b.item.id})
        metrics = self.ledger.stats(self.target, hunt_id=hunt.id)
        self.assertEqual(metrics["candidates"], len(
            self.ledger.list_candidates(self.target, hunt_id=hunt.id)))
        self.assertEqual(metrics["plans"], 1)
        self.assertEqual(metrics["executed_plans"], 0)
        self.assertEqual(metrics["requests_used"], 0)
        with self.assertRaises(LookupError):
            self.ledger.stats(self.target, hunt_id="AUTHH-missing")

    def _run_boundary_case(self, boundary: Boundary, *, secure: bool):
        self.fx.package = replace(self.fx.package, autonomy=replace(
            self.fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        self.fx.targets.package = self.fx.package
        owner_a, session_a, tenant_a, object_a = self.fixture_object(
            role="admin" if boundary in {Boundary.VERTICAL, Boundary.HIDDEN_FUNCTION} else None,
            object_type="document" if boundary is Boundary.ANONYMOUS else "project")
        if boundary in {Boundary.CROSS_TENANT, Boundary.GRAPHQL_OBJECT}:
            owner_b, session_b, tenant_b = self.actor("tenant_b_admin", "tenant-b")
            self.fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
            object_b = self.fx.factory.resolve(
                package_id=self.fx.package.id, recipe_id="project_b", identity_id=owner_b.id,
                tenant_id=tenant_b.id, session_id=session_b.id, purpose="Authorization fixture").item
            if boundary is Boundary.GRAPHQL_OBJECT:
                self.graphql_owner_exchange(owner_a, session_a, object_a)
                self.graphql_owner_exchange(owner_b, session_b, object_b)
            policy = "TENANT_ONLY"
        elif boundary is Boundary.HORIZONTAL:
            owner_b, session_b, tenant_b = self.actor("tenant_a_member", "tenant-a")
            self.fx.recipe(recipe_id="project_member", tenant="tenant-a", owner="tenant_a_member")
            object_b = self.fx.factory.resolve(
                package_id=self.fx.package.id, recipe_id="project_member", identity_id=owner_b.id,
                tenant_id=tenant_b.id, session_id=session_b.id, purpose="Authorization fixture").item
            policy = "OWNER_ONLY"
        elif boundary is Boundary.ANONYMOUS:
            object_b = None
            policy = "OWNER_ONLY"
        else:
            self.actor("tenant_a_member", "tenant-a", role="member")
            object_b = None
            policy = "ROLE_RESTRICTED"
        self.protect(object_a, tenant_a, policy=policy,
                     role_id=self.roles["admin"].id if boundary in {
                         Boundary.VERTICAL, Boundary.HIDDEN_FUNCTION} else None,
                     owner_principal=self.fx.registry.get_identity(self.target, owner_a.id).principal_id
                     if boundary is Boundary.HORIZONTAL else None)
        if boundary is Boundary.ANONYMOUS:
            subject = hashlib.sha256(self.specialist._external_id(object_a).encode()).hexdigest()
            self.fx.store.create_fact(subject, "data_classification", "PROTECTED_FILE",
                                      confidence=1,
                                      evidence_ids=(object_a.verification_evidence_ids[0],),
                                      source="FIXTURE", target_ref=self.target)
        if boundary is Boundary.HIDDEN_FUNCTION:
            observed = self.specialist.profile(self.fx.package).operations[0]
            self.hypotheses.save_profile(TargetProfile(
                self.target, self.fx.package.id, "localhost", "TRACKED",
                datetime.now(timezone.utc), None, "NOT_CONFIGURED", (), (), (), (), (), (),
                0, False, False, 0,
                (SurfaceSignal("SURFACE_INTERNAL", SignalSource.JS_ANALYSIS,
                               observed.display_path, observed.origin + observed.display_path,
                               "fixture_js", observed.exchange_id, method=observed.method),),
                {}, ()))
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id, candidate_limit=6)
        candidate = next(item for item in self.specialist.generate(hunt, self.fx.package)
                         if item.boundary is boundary and
                         item.test_object_id == object_a.id)
        prepared = self.specialist.prepare(candidate.id, self.fx.package)
        self.assertEqual(prepared.status, "PLANNED")
        runs = PlanRunStore(self.fx.store)
        orchestrator = PlanOrchestrator(
            runs=runs, targets=self.fx.targets, hypotheses=self.hypotheses,
            context=self.specialist.context, checker=self.specialist.planner.checker,
            registry=self.specialist.planner.registry, policy=self.fx.policy,
            approvals=PolicyStore(self.fx.store), executor=self.fx.executor,
            traffic=self.fx.traffic, evidence=self.fx.store, objects=self.fx.objects)
        self.fx.server.fixture_secure = secure
        detail = orchestrator.start(prepared.plan_id, self.fx.package.id)
        self.assertEqual(detail["run"]["status"], "CREATED")
        for _ in range(24):
            if detail["run"]["status"] == "COMPLETED":
                break
            if detail["run"]["status"] == "WAITING_APPROVAL" and boundary is Boundary.GRAPHQL_OBJECT:
                approval_id = detail["run"]["approval_id"]
                current = runs.get(detail["run"]["id"], self.target)
                _, _, prerequisites = orchestrator._current(
                    current, runs.snapshot(prepared.plan_id, self.target))
                self.assertEqual(prerequisites.state, PrerequisiteState.READY,
                                 prerequisites.to_dict())
                self.fx.policy.audit.decide(approval_id, self.target, approve=True)
                runs.approval_decision(approval_id, self.target, granted=True)
                detail = orchestrator.resume(detail["run"]["id"], self.fx.package.id)
                continue
            if detail["run"]["status"] not in {"CREATED", "READY"}:
                break
            detail = orchestrator.advance(detail["run"]["id"], self.fx.package.id)
        self.assertEqual(detail["run"]["status"], "COMPLETED",
                         (detail["run"]["status"], detail["run"]["stop_reason"]))
        self.assertEqual(detail["run"]["requests_consumed"], 4 if object_b is None else 5)
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.fx.traffic, evidence=self.fx.store,
            identities=self.fx.registry, hypotheses=self.hypotheses,
            results=ValidationStore(self.fx.store))
        validation, finding = validator.validate_run(detail["run"]["id"], self.target)
        self.assertEqual(self.fx.objects.active_reservation(object_a.id), None)
        if object_b is not None:
            self.assertEqual(self.fx.objects.active_reservation(object_b.id), None)
        return validation, finding

    def test_owned_cross_tenant_fixture_runs_through_orchestrator_and_validator(self):
        validation, finding = self._run_boundary_case(Boundary.CROSS_TENANT, secure=False)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED,
                         validation.reason_codes)
        self.assertIsNotNone(finding)

    def test_secure_cross_tenant_fixture_is_rejected(self):
        validation, finding = self._run_boundary_case(Boundary.CROSS_TENANT, secure=True)
        self.assertEqual(validation.status, ValidationStatus.REJECTED,
                         validation.reason_codes)
        self.assertIsNone(finding)

    def test_same_tenant_horizontal_private_object_read_confirms(self):
        validation, finding = self._run_boundary_case(Boundary.HORIZONTAL, secure=False)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED, validation.reason_codes)
        self.assertEqual(finding.category, "HORIZONTAL_IDOR")

    def test_same_tenant_vertical_role_restriction_confirms(self):
        validation, finding = self._run_boundary_case(Boundary.VERTICAL, secure=False)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED, validation.reason_codes)
        self.assertEqual(finding.category, "VERTICAL_ROLE_BYPASS")

    def test_secure_vertical_role_boundary_rejects(self):
        validation, finding = self._run_boundary_case(Boundary.VERTICAL, secure=True)
        self.assertEqual(validation.status, ValidationStatus.REJECTED, validation.reason_codes)
        self.assertIsNone(finding)

    def test_hidden_backend_function_requires_role_and_runtime_proof(self):
        validation, finding = self._run_boundary_case(Boundary.HIDDEN_FUNCTION, secure=False)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED, validation.reason_codes)
        self.assertEqual(finding.category, "HIDDEN_FUNCTION_BYPASS")

    def test_graphql_http_200_error_is_denied_not_allowed(self):
        owner, session, _, item = self.fixture_object()
        action = self.fx.action("/validated/graphql-invalid", actor=ActorMode.AUTHENTICATED,
                                identity_id=owner.id, session_id=session.id)
        exchange_id = self.fx.run_action(action).exchange_ids[0]
        key = "a" * 64
        self.ledger.record_observation(target_id=self.target, operation_key=key,
                                       exchange_id=exchange_id, result=MatrixResult.OBSERVED_DENIED,
                                       test_object_id=item.id)
        self.assertEqual(self.ledger.matrix(self.target)[0]["result"], "OBSERVED_DENIED")
        with self.assertRaisesRegex(ValueError, "semantic object response"):
            self.ledger.record_observation(target_id=self.target, operation_key="b" * 64,
                                           exchange_id=exchange_id,
                                           result=MatrixResult.OBSERVED_ALLOWED,
                                           test_object_id=item.id)

    def test_anonymous_private_document_access_confirms(self):
        validation, finding = self._run_boundary_case(Boundary.ANONYMOUS, secure=False)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED, validation.reason_codes)
        self.assertEqual(finding.category, "UNAUTHENTICATED_DOWNLOAD")

    def test_secure_anonymous_document_access_rejects(self):
        validation, finding = self._run_boundary_case(Boundary.ANONYMOUS, secure=True)
        self.assertEqual(validation.status, ValidationStatus.REJECTED, validation.reason_codes)
        self.assertIsNone(finding)

    def test_graphql_cross_tenant_query_confirms_from_owned_variable(self):
        validation, finding = self._run_boundary_case(Boundary.GRAPHQL_OBJECT, secure=False)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED, validation.reason_codes)
        self.assertEqual(finding.category, "GRAPHQL_AUTHORIZATION")

    def test_graphql_http_200_authorization_error_rejects(self):
        validation, finding = self._run_boundary_case(Boundary.GRAPHQL_OBJECT, secure=True)
        self.assertEqual(validation.status, ValidationStatus.REJECTED, validation.reason_codes)
        self.assertIsNone(finding)

    def test_unverified_foreign_identity_blocks_before_boundary_request(self):
        _, _, _, object_a = self.fixture_object()
        foreign, foreign_session, tenant_b = self.actor("tenant_b_admin", "tenant-b")
        self.fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        self.fx.factory.resolve(package_id=self.fx.package.id, recipe_id="project_b",
                                identity_id=foreign.id, tenant_id=tenant_b.id,
                                session_id=foreign_session.id, purpose="Authorization fixture")
        self.fx.browser.stop(foreign_session.id)
        before = len(self.fx.server.received)
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id, candidate_limit=3)
        candidate = next(item for item in self.specialist.generate(hunt, self.fx.package)
                         if item.boundary is Boundary.CROSS_TENANT and
                         item.test_object_id == object_a.id)
        self.assertEqual(self.specialist.prepare(candidate.id, self.fx.package).status,
                         "NEEDS_SESSION")
        self.assertEqual(len(self.fx.server.received), before)

    def test_candidate_and_request_budgets_fail_closed(self):
        self.fixture_object()
        foreign, session, tenant = self.actor("tenant_b_admin", "tenant-b")
        self.fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        self.fx.factory.resolve(package_id=self.fx.package.id, recipe_id="project_b",
                                identity_id=foreign.id, tenant_id=tenant.id,
                                session_id=session.id, purpose="Authorization fixture")
        before = len(self.fx.server.received)
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id,
                                       candidate_limit=1, request_budget=4)
        candidates = self.specialist.generate(hunt, self.fx.package)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(self.specialist.prepare(candidates[0].id, self.fx.package).status,
                         "NEEDS_MANUAL_REVIEW")
        self.assertEqual(len(self.fx.server.received), before)

    def test_graphql_mutation_is_manual_until_durable_readback_exists(self):
        owner, session, _, _ = self.fixture_object()
        foreign, _, _ = self.actor("tenant_b_admin", "tenant-b")
        item = self.fx.objects.list_for_target(self.target, limit=2).items[0]
        self.graphql_owner_exchange(owner, session, item, mutation=True)
        before = len(self.fx.server.received)
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id, candidate_limit=2)
        candidate = next(item for item in self.specialist.generate(hunt, self.fx.package)
                         if item.boundary is Boundary.GRAPHQL_MUTATION and
                         item.boundary_identity_id == foreign.id)
        self.assertEqual(self.specialist.prepare(candidate.id, self.fx.package).status,
                         "NEEDS_MANUAL_REVIEW")
        self.assertEqual(len(self.fx.server.received), before)

    def _run_graphql_mutation_case(self, *, secure: bool, noop: bool = False):
        self.fx.package = replace(self.fx.package, autonomy=replace(
            self.fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        self.fx.targets.package = self.fx.package
        owner_a, session_a, tenant_a, object_a = self.fixture_object()
        owner_b, session_b, tenant_b = self.actor("tenant_b_admin", "tenant-b")
        self.fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        object_b = self.fx.factory.resolve(
            package_id=self.fx.package.id, recipe_id="project_b", identity_id=owner_b.id,
            tenant_id=tenant_b.id, session_id=session_b.id,
            purpose="Authorization fixture").item
        self.protect(object_a, tenant_a, policy="TENANT_ONLY")
        desired = "hackbot-test-mutated"
        self.graphql_owner_exchange(owner_a, session_a, object_a, mutation=True,
                                    rename=desired)
        reset = self.fx.factory.update_name(object_a.id, self.target, session_id=session_a.id)
        self.assertEqual(reset.outcome, "READY")
        original = reset.item.test_name
        self.assertNotEqual(original, desired)
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id, candidate_limit=8)
        candidate = next(item for item in self.specialist.generate(hunt, self.fx.package)
                         if item.boundary is Boundary.GRAPHQL_MUTATION and
                         item.test_object_id == object_a.id)
        prepared = self.specialist.prepare(candidate.id, self.fx.package)
        self.assertEqual(prepared.status, "PLANNED")
        plan = SkillPlanStore(self.fx.store).get(prepared.plan_id, self.target)
        self.assertEqual([item["variant"] for item in plan["request_templates"]],
                         ["OWNER", "OWNER", "INVALID_OBJECT", "FOREIGN", "POST_READBACK"])
        runs = PlanRunStore(self.fx.store)
        orchestrator = PlanOrchestrator(
            runs=runs, targets=self.fx.targets, hypotheses=self.hypotheses,
            context=self.specialist.context, checker=self.specialist.planner.checker,
            registry=self.specialist.planner.registry, policy=self.fx.policy,
            approvals=PolicyStore(self.fx.store), executor=self.fx.executor,
            traffic=self.fx.traffic, evidence=self.fx.store, objects=self.fx.objects)
        self.specialist.orchestrator = orchestrator
        self.specialist.validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.fx.traffic, evidence=self.fx.store,
            identities=self.fx.registry, hypotheses=self.hypotheses,
            results=ValidationStore(self.fx.store))
        self.fx.server.fixture_secure = secure
        self.fx.server.fixture_noop_mutation = noop
        detail = self.specialist.start_candidate(candidate.id, self.fx.package)
        for shape in plan["request_templates"]:
            resolve_authorization_request(
                shape, package=self.fx.package, run_id=detail["run"]["id"],
                objects=self.fx.objects, traffic=self.fx.traffic, evidence=self.fx.store)
        snapshot = runs.snapshot(prepared.plan_id, self.target)
        current_run = runs.get(detail["run"]["id"], self.target)
        for step in runs.steps(current_run.id):
            if step.action_slot is not None:
                try:
                    orchestrator._bound(snapshot, step, current_run)
                except Exception as exc:
                    self.fail(f"local binding slot {step.action_slot}: {type(exc).__name__}")
        for _ in range(24):
            status = detail["run"]["status"]
            if status == "COMPLETED":
                break
            if status == "WAITING_APPROVAL":
                approval_id = detail["run"]["approval_id"]
                self.fx.policy.audit.decide(approval_id, self.target, approve=True)
                runs.approval_decision(approval_id, self.target, granted=True)
                detail = orchestrator.resume(detail["run"]["id"], self.fx.package.id)
                continue
            self.assertIn(status, {"CREATED", "READY"}, detail["run"])
            detail = self.specialist.advance_candidate(candidate.id, self.fx.package)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        validation = detail.get("validation") or self.specialist.validate_candidate(
            candidate.id, self.fx.package)
        result = validation["result"]
        external = self.specialist._external_id(object_a)
        self.assertEqual(self.fx.server.fixture_objects[external]["name"],
                         original if secure or noop else desired)
        self.assertEqual(self.fx.objects.active_reservation(object_a.id), None)
        self.assertEqual(self.fx.objects.active_reservation(object_b.id), None)
        self.assertEqual(self.fx.factory.cleanup(object_a.id, self.target,
                                                 session_id=session_a.id).outcome, "CLEANED")
        self.assertEqual(self.fx.factory.cleanup(object_b.id, self.target,
                                                 session_id=session_b.id).outcome, "CLEANED")
        return result

    def test_graphql_mutation_requires_durable_readback_and_confirms(self):
        result = self._run_graphql_mutation_case(secure=False)
        self.assertEqual(result["status"], ValidationStatus.CONFIRMED.value,
                         result["reason_codes"])
        self.assertEqual(result["impact"]["demonstrated"],
                         "GRAPHQL_UNAUTHORIZED_STATE_CHANGE")

    def test_graphql_mutation_http_200_error_does_not_confirm(self):
        result = self._run_graphql_mutation_case(secure=True)
        self.assertEqual(result["status"], ValidationStatus.REJECTED.value,
                         result["reason_codes"])

    def test_graphql_mutation_success_shaped_noop_needs_review(self):
        result = self._run_graphql_mutation_case(secure=False, noop=True)
        self.assertEqual(result["status"], ValidationStatus.NEEDS_MANUAL_REVIEW.value,
                         result["reason_codes"])

    def test_repeated_hunt_does_not_replan_existing_candidate(self):
        self.fixture_object()
        self.actor("tenant_b_admin", "tenant-b")
        first = self.specialist.start_hunt(self.fx.package, candidate_limit=2)
        second = self.specialist.start_hunt(self.fx.package, candidate_limit=2)
        self.assertEqual({item["id"] for item in first["candidates"]},
                         {item["id"] for item in second["candidates"]})
        self.assertEqual(second["hunt"]["status"], HuntStatus.COMPLETED.value)
        self.assertEqual(second["hunt"]["reason_code"], "NO_NEW_CANDIDATES")

    def test_autonomous_hunt_stops_after_first_confirmed_boundary(self):
        self.fx.package = replace(self.fx.package, autonomy=replace(
            self.fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        self.fx.targets.package = self.fx.package
        owner_a, _, tenant_a, object_a = self.fixture_object()
        owner_b, session_b, tenant_b = self.actor("tenant_b_admin", "tenant-b")
        self.fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        object_b = self.fx.factory.resolve(
            package_id=self.fx.package.id, recipe_id="project_b", identity_id=owner_b.id,
            tenant_id=tenant_b.id, session_id=session_b.id,
            purpose="Authorization fixture").item
        self.protect(object_a, tenant_a, policy="TENANT_ONLY")
        self.protect(object_b, tenant_b, policy="TENANT_ONLY")
        runs = PlanRunStore(self.fx.store)
        self.specialist.orchestrator = PlanOrchestrator(
            runs=runs, targets=self.fx.targets, hypotheses=self.hypotheses,
            context=self.specialist.context, checker=self.specialist.planner.checker,
            registry=self.specialist.planner.registry, policy=self.fx.policy,
            approvals=PolicyStore(self.fx.store), executor=self.fx.executor,
            traffic=self.fx.traffic, evidence=self.fx.store, objects=self.fx.objects)
        self.specialist.validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.fx.traffic, evidence=self.fx.store,
            identities=self.fx.registry, hypotheses=self.hypotheses,
            results=ValidationStore(self.fx.store))
        result = self.specialist.start_hunt(
            self.fx.package, mode=AuthorizationMode.BOUNDED_AUTONOMOUS,
            candidate_limit=2, request_budget=20)
        self.assertEqual(result["hunt"]["status"], HuntStatus.COMPLETED.value)
        self.assertEqual(result["hunt"]["reason_code"], "CONFIRMED_STOP_PROOF")
        metrics = self.ledger.stats(self.target, hunt_id=result["hunt"]["id"])
        self.assertEqual(metrics["confirmed"], 1)
        self.assertEqual(metrics["executed_plans"], 1)
        self.assertEqual(metrics["requests_used"], 5)
        self.assertEqual(self.fx.objects.active_reservation(object_a.id), None)
        self.assertEqual(self.fx.objects.active_reservation(object_b.id), None)
        with self.fx.store._connection() as db:
            chain = db.execute(
                "SELECT count(*) FROM authorization_candidates c "
                "JOIN validations v ON v.validation_id=c.validation_id "
                "JOIN plan_runs r ON r.run_id=v.run_id "
                "JOIN skill_plans p ON p.plan_id=r.plan_id "
                "JOIN hypotheses h ON h.hypothesis_id=p.hypothesis_id "
                "JOIN findings f ON f.validation_id=v.validation_id "
                "WHERE c.target_id=? AND c.hunt_id=? AND v.status='CONFIRMED'",
                (self.target, result["hunt"]["id"])).fetchone()[0]
            observed = db.execute(
                "SELECT count(*) FROM authorization_observations o "
                "JOIN authorization_candidates c ON c.candidate_id=o.candidate_id "
                "JOIN traffic_exchanges x ON x.exchange_id=o.exchange_id "
                "WHERE c.target_id=? AND c.hunt_id=?",
                (self.target, result["hunt"]["id"])).fetchone()[0]
            permits = db.execute(
                "SELECT count(*) FROM authorization_candidates c "
                "JOIN plan_run_steps s ON s.run_id=c.run_id "
                "JOIN executor_permits p ON p.permit_id=s.permit_id "
                "WHERE c.target_id=? AND c.hunt_id=?",
                (self.target, result["hunt"]["id"])).fetchone()[0]
        self.assertEqual(chain, 1)
        self.assertGreaterEqual(observed, 5)
        self.assertGreaterEqual(permits, 5)

    def test_specialist_has_no_direct_network_or_executor_dispatch(self):
        source = (Path(__file__).resolve().parents[1] /
                  "src/hackbot/authorization.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {node.module for node in ast.walk(tree)
                   if isinstance(node, ast.ImportFrom)}
        imports.update(alias.name for node in ast.walk(tree)
                       if isinstance(node, ast.Import) for alias in node.names)
        self.assertFalse({"socket", "requests", "httpx", "urllib.request", "subprocess"} & imports)
        calls = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)}
        self.assertFalse({"urlopen", "request", "execute", "send"} & calls)

    def test_interrupted_run_reconciles_to_manual_review_without_replay(self):
        self.fixture_object()
        foreign, session, tenant = self.actor("tenant_b_admin", "tenant-b")
        self.fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        self.fx.factory.resolve(package_id=self.fx.package.id, recipe_id="project_b",
                                identity_id=foreign.id, tenant_id=tenant.id,
                                session_id=session.id, purpose="Authorization fixture")
        hunt = self.ledger.create_hunt(self.target, self.fx.package.id, candidate_limit=1)
        candidate = self.specialist.generate(hunt, self.fx.package)[0]
        prepared = self.specialist.prepare(candidate.id, self.fx.package)
        self.assertEqual(prepared.status, "PLANNED")
        runs = PlanRunStore(self.fx.store)
        self.specialist.orchestrator = PlanOrchestrator(
            runs=runs, targets=self.fx.targets, hypotheses=self.hypotheses,
            context=self.specialist.context, checker=self.specialist.planner.checker,
            registry=self.specialist.planner.registry, policy=self.fx.policy,
            approvals=PolicyStore(self.fx.store), executor=self.fx.executor,
            traffic=self.fx.traffic, evidence=self.fx.store, objects=self.fx.objects)
        detail = self.specialist.start_candidate(candidate.id, self.fx.package)
        before = len(self.fx.server.received)
        with self.fx.store._connection() as db:
            db.execute("UPDATE plan_runs SET status='WAITING_HUMAN' WHERE run_id=?",
                       (detail["run"]["id"],))
        self.assertEqual(self.ledger.reconcile_runs(), 1)
        self.assertEqual(self.ledger.reconcile_runs(), 0)
        self.assertEqual(len(self.fx.server.received), before)
        self.assertEqual(self.ledger.get_candidate(candidate.id, self.target).status,
                         "NEEDS_MANUAL_REVIEW")
        self.assertEqual(self.ledger.get_hunt(hunt.id, self.target).status, HuntStatus.PAUSED)

    def test_autonomous_factory_control_is_attributed_and_cleaned(self):
        self.fx.package = replace(self.fx.package, autonomy=replace(
            self.fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        self.fx.targets.package = self.fx.package
        owner_a, session_a, tenant_a, object_a = self.fixture_object()
        self.actor("tenant_b_admin", "tenant-b")
        self.fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        self.protect(object_a, tenant_a, policy="TENANT_ONLY")
        runs = PlanRunStore(self.fx.store)
        self.specialist.factory = self.fx.factory
        self.specialist.orchestrator = PlanOrchestrator(
            runs=runs, targets=self.fx.targets, hypotheses=self.hypotheses,
            context=self.specialist.context, checker=self.specialist.planner.checker,
            registry=self.specialist.planner.registry, policy=self.fx.policy,
            approvals=PolicyStore(self.fx.store), executor=self.fx.executor,
            traffic=self.fx.traffic, evidence=self.fx.store, objects=self.fx.objects)
        self.specialist.validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.fx.traffic, evidence=self.fx.store,
            identities=self.fx.registry, hypotheses=self.hypotheses,
            results=ValidationStore(self.fx.store))
        result = self.specialist.start_hunt(
            self.fx.package, mode=AuthorizationMode.BOUNDED_AUTONOMOUS,
            candidate_limit=1, request_budget=20)
        hunt_id = result["hunt"]["id"]
        self.assertEqual(result["hunt"]["status"], HuntStatus.COMPLETED.value)
        self.assertEqual(self.ledger.stats(self.target, hunt_id=hunt_id)["confirmed"], 1)
        self.assertEqual(self.ledger.stats(self.target, hunt_id=hunt_id)["objects_created"], 1)
        self.assertEqual(self.ledger.stats(self.target, hunt_id=hunt_id)["cleanup_pending"], 0)
        created = self.ledger.created_objects(hunt_id, self.target)
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0][1], "CLEANED")
        self.assertEqual(len(self.fx.server.fixture_objects), 1)
        self.assertEqual(self.fx.factory.cleanup(object_a.id, self.target,
                                                 session_id=session_a.id).outcome, "CLEANED")


if __name__ == "__main__":
    unittest.main()
