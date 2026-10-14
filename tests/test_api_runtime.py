"""Phase 26 observed API planning uses only local owned-object fixtures."""

from __future__ import annotations

import unittest
from unittest.mock import patch
from dataclasses import replace
import hashlib
import http.client
import json
from types import SimpleNamespace
from urllib.parse import urlsplit

from hackbot.api_registry import APIOperationRegistry
from hackbot.api_graphql import encode_observed_global_id
from hackbot.api_specialist import APIAnalysisLimits, APISpecialist
from hackbot.authorization import AuthorizationObject
from hackbot.authorization_store import Boundary
from hackbot.behaviour import BehaviourStore, NormalBehaviourLearner
from hackbot.domxss_store import DOMXSSStore
from hackbot.domain import TrafficSource
from hackbot.traffic import CapturedRequest, CapturedResponse
from hackbot.orchestrator import PlanOrchestrator, PlanRunError
from hackbot.plan_runs import PlanRunStore
from hackbot.policy_store import PolicyStore
from hackbot.target_policy import PolicyDecision
from hackbot.test_objects import ObjectState
from hackbot.validation_store import ValidationStatus, ValidationStore
from hackbot.validator import APIReadValidator, DeterministicValidatorEngine
from tests import test_authorization as _authorization_fixture
from tests import test_authorization_mutations as _mutation_fixture


class APIReadPlanningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case = _authorization_fixture.AuthorizationSpecialistTests(
            "test_cross_tenant_candidate_uses_verified_object_and_owner_traffic")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        owner, owner_session, tenant, owned = self.case.fixture_object()
        foreign, foreign_session, foreign_tenant = self.case.actor(
            "tenant_b_admin", "tenant-b")
        self.case.fx.recipe(recipe_id="project_b", tenant="tenant-b",
                            owner="tenant_b_admin")
        control = self.case.fx.factory.resolve(
            package_id=self.case.fx.package.id, recipe_id="project_b",
            identity_id=foreign.id, tenant_id=foreign_tenant.id,
            session_id=foreign_session.id, purpose="API actor-owned control")
        self.assertEqual(control.outcome, "READY")
        self.case.protect(owned, tenant, policy="TENANT_ONLY")
        self.case.graphql_owner_exchange(owner, owner_session, owned)
        self.case.graphql_owner_exchange(foreign, foreign_session, control.item)
        self.owner, self.owner_session, self.owned = owner, owner_session, owned
        self.foreign, self.foreign_session, self.foreign_object = (
            foreign, foreign_session, control.item)
        self.registry = APIOperationRegistry(self.case.fx.store)
        self.api = APISpecialist(
            registry=self.registry, traffic=self.case.fx.traffic,
            evidence=self.case.fx.store, js=DOMXSSStore(self.case.fx.store),
            authorization=self.case.specialist)

    def test_two_observed_owners_are_aggregated_and_plan_has_fixed_controls(self):
        before = len(self.case.fx.server.received)
        candidates = self.api.generate(self.case.fx.package, limits=APIAnalysisLimits(
            traffic=20, js_assets=5, recon_surfaces=3, candidates=10))
        query = next(item for item in self.registry.list_operations(self.case.target)
                     if item.name == "GetProject")
        self.assertEqual(len(query.identity_ids), 2)
        self.assertEqual(len(query.exchange_ids), 2)
        id_field = next(field for field in query.fields if field.name == "id")
        self.assertEqual(set(id_field.observed_identity_ids),
                         {self.owner.id, self.foreign.id})
        candidate = next(item for item in candidates
                         if item.operation_id == query.id and item.category == "OBJECT_AUTH")
        self.assertEqual(candidate.status, "READY")
        self.assertEqual(candidate.test_object_id, self.owned.id)
        self.assertEqual(candidate.boundary_identity_id, self.foreign.id)
        prepared = self.api.prepare_candidate(self.case.fx.package, candidate.id)
        self.assertEqual(prepared.status, "PLANNED")
        plan = self.case.specialist.planner.store.get(prepared.plan_id, self.case.target)
        self.assertEqual(plan["api_binding"]["operation_id"], query.id)
        self.assertEqual([item["variant"] for item in plan["request_templates"]],
                         ["OWNER", "OWNER", "INVALID_OBJECT", "FOREIGN", "FOREIGN"])
        self.assertEqual(len(self.case.fx.server.received), before)

    def test_prior_confirmed_phase19_object_boundary_needs_no_new_api_requests(self):
        fx = self.case.fx
        fx.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        fx.targets.package = fx.package
        api_candidate = next(item for item in self.api.generate(fx.package)
                             if item.category == "OBJECT_AUTH" and
                             item.test_object_id == self.owned.id and
                             item.boundary_identity_id == self.foreign.id and
                             item.status == "READY")
        runs = PlanRunStore(fx.store)
        self.case.specialist.orchestrator = PlanOrchestrator(
            runs=runs, targets=fx.targets, hypotheses=self.case.hypotheses,
            context=self.case.specialist.context,
            checker=self.case.specialist.planner.checker,
            registry=self.case.specialist.planner.registry,
            policy=fx.policy, approvals=PolicyStore(fx.store), executor=fx.executor,
            traffic=fx.traffic, evidence=fx.store, objects=fx.objects)
        self.case.specialist.validator = DeterministicValidatorEngine(
            runs=runs, traffic=fx.traffic, evidence=fx.store,
            identities=fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(fx.store))
        hunt = self.case.ledger.create_hunt(self.case.target, fx.package.id,
                                            candidate_limit=20)
        prior = next(item for item in self.case.specialist.generate(hunt, fx.package)
                     if item.boundary is Boundary.GRAPHQL_OBJECT and
                     item.test_object_id == self.owned.id and
                     item.boundary_identity_id == self.foreign.id and
                     item.owner_exchange_id == api_candidate.owner_exchange_id)
        prior = self.case.specialist.prepare(prior.id, fx.package)
        detail = self.case.specialist.start_candidate(prior.id, fx.package)
        for _ in range(24):
            if detail["run"]["status"] == "COMPLETED":
                break
            if detail["run"]["status"] == "WAITING_APPROVAL":
                approval_id = detail["run"]["approval_id"]
                fx.policy.audit.decide(approval_id, self.case.target, approve=True)
                runs.approval_decision(approval_id, self.case.target, granted=True)
                detail = self.case.specialist.orchestrator.resume(
                    detail["run"]["id"], fx.package.id)
            else:
                self.assertIn(detail["run"]["status"], {"CREATED", "READY"})
                detail = self.case.specialist.advance_candidate(prior.id, fx.package)
        self.assertEqual(detail["run"]["status"], "COMPLETED")
        verified = self.case.specialist.validate_candidate(prior.id, fx.package)
        self.assertEqual(verified["result"]["status"], "CONFIRMED")
        prior = self.case.ledger.get_candidate(prior.id, self.case.target)
        record = fx.objects.get(self.owned.id, self.case.target)
        self.assertEqual(record.state.value, "CLEANUP_PENDING")
        owned = AuthorizationObject(
            record.id, record.object_type, record.creator_identity_id,
            record.owner_principal_id, record.tenant_id, record.parent_id,
            record.external_id_hash, record.verification_evidence_ids[:8], ())
        source = self.case.specialist.observed_operation(
            fx.package, owned, api_candidate.owner_exchange_id)
        operation = self.registry.get_operation(self.case.target, api_candidate.operation_id)
        actors = {item.identity_id: item for item in self.case.specialist.profile(fx.package).actors}
        self.assertIsNotNone(source)
        self.assertIsNone(self.api._reuse_confirmed_object_boundary(
            fx.package, api_candidate,
            replace(operation, last_seen="9999-12-31T00:00:00+00:00"), source,
            actors[self.owner.id], actors[self.foreign.id], owned))
        self.assertIsNone(self.api._reuse_confirmed_object_boundary(
            fx.package, replace(api_candidate, owner_exchange_id="TX-missing"),
            operation, source, actors[self.owner.id], actors[self.foreign.id], owned))
        before = len(fx.server.received)
        reused = self.api.prepare_candidate(fx.package, api_candidate.id)
        self.assertEqual(reused.status, "VALIDATED")
        self.assertEqual(reused.authorization_candidate_id, prior.id)
        self.assertEqual(reused.validation_id, prior.validation_id)
        self.assertEqual(self.api.validate_candidate(fx.package, reused.id)["result"]["id"],
                         prior.validation_id)
        self.assertEqual(len(fx.server.received), before)

    def test_stale_operation_blocks_before_any_test_request(self):
        candidate = next(item for item in self.api.generate(self.case.fx.package)
                         if item.category == "OBJECT_AUTH" and item.status == "READY")
        prepared = self.api.prepare_candidate(self.case.fx.package, candidate.id)
        operation = self.registry.get_operation(self.case.target, candidate.operation_id)
        with self.case.fx.store._connection() as db:
            db.execute("UPDATE api_operations SET state='STALE' WHERE operation_id=?",
                       (operation.id,))
            db.execute("UPDATE api_candidates SET status='STALE' WHERE candidate_id=?",
                       (prepared.id,))
        before = len(self.case.fx.server.received)
        with self.assertRaisesRegex(ValueError, "stale"):
            self.api.start_candidate(self.case.fx.package, prepared.id)
        self.assertEqual(len(self.case.fx.server.received), before)
        self.assertEqual(self.registry.get_candidate(self.case.target, prepared.id).status,
                         "STALE")

    def test_unverified_boundary_identity_sends_zero_autonomous_requests(self):
        fx = self.case.fx
        fx.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        fx.targets.package = fx.package
        fx.browser.stop(self.foreign_session.id)
        before = len(fx.server.received)
        candidates = self.api.generate(fx.package, mode="BOUNDED_AUTONOMOUS")
        self.assertTrue(candidates)
        self.assertTrue(all(item.status != "PLANNED" and item.status != "RUNNING"
                            for item in candidates))
        self.assertTrue(any("SECOND_TENANT_MISSING" in item.gaps for item in candidates))
        self.assertEqual(len(fx.server.received), before)

    def _field_observations(self, *, unrelated_field: bool = False,
                            actor_subset: bool = False,
                            nested_profile: bool = False,
                            foreign_profile_id: bool = False):
        document = ("query GetProject($id:ID!){node(id:$id){id name owner tenant "
                    "profile{timezone email}}}" if nested_profile else
                    "query GetProject($id:ID!){node(id:$id){id name owner tenant email}}")
        owner_exchange = None
        for actor, session, item in ((self.owner, self.owner_session, self.owned),
                                     (self.foreign, self.foreign_session, self.foreign_object)):
            external = self.case.specialist._external_id(item)
            if nested_profile:
                self.case.fx.server.fixture_objects[external]["profile"] = {
                    "timezone": "UTC", "email": "synthetic-private@example.test"}
                if foreign_profile_id and item.id == self.owned.id:
                    self.case.fx.server.fixture_objects[external]["profile"]["id"] = (
                        self.case.specialist._external_id(self.foreign_object))
            else:
                self.case.fx.server.fixture_objects[external]["email"] = (
                    "synthetic-private@example.test")
            selected = (("query GetProject($id:ID!){node(id:$id){id name owner tenant "
                         "profile{timezone}}}" if nested_profile else
                         "query GetProject($id:ID!){node(id:$id){id name owner tenant}}")
                        if actor_subset and item.id == self.foreign_object.id else document)
            body = json.dumps({"query": selected, "variables": {"id": external},
                               "operationName": "GetProject"}).encode()
            exchange = self.case.fx.traffic.store_request(
                self.case.fx.package,
                CapturedRequest("POST", self.case.fx.base + "/fixture/graphql",
                                headers=(("Content-Type", "application/json"),), body=body,
                                operation_id="GQL-" + "1" * 32),
                source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
                browser_manager=self.case.fx.browser,
                browser_session_id=session.id, auth_material_observed=True)
            node = dict(self.case.fx.server.fixture_objects[external])
            if selected != document:
                if nested_profile:
                    node["profile"] = {"timezone": "UTC"}
                else:
                    node.pop("email")
            payload = {"data": {"node": node}}
            if unrelated_field:
                payload["data"]["other"] = {"email": "synthetic-private@example.test"}
            self.case.fx.traffic.store_response(
                exchange.id, CapturedResponse(200, (("Content-Type", "application/json"),),
                                              json.dumps(payload).encode()))
            if item.id == self.owned.id:
                owner_exchange = exchange
        subject = hashlib.sha256(self.case.specialist._external_id(self.owned).encode()).hexdigest()
        for predicate, value in (("data_classification", "SENSITIVE"),
                                 ("field_visibility", "email")):
            self.case.fx.store.create_fact(
                subject, predicate, value, confidence=1,
                evidence_ids=(self.owned.verification_evidence_ids[0],),
                source="FIXTURE", target_ref=self.case.target)
        return self.case.fx.traffic.get_exchange(owner_exchange.id)

    def _global_id_observations(self) -> None:
        document = "query GlobalProject($id:ID!){node(id:$id){id name owner tenant}}"
        for actor, session, item in ((self.owner, self.owner_session, self.owned),
                                     (self.foreign, self.foreign_session, self.foreign_object)):
            external = self.case.specialist._external_id(item)
            body = json.dumps({"query": document,
                               "variables": {"id": encode_observed_global_id("Project", external)},
                               "operationName": "GlobalProject"}).encode()
            exchange = self.case.fx.traffic.store_request(
                self.case.fx.package,
                CapturedRequest("POST", self.case.fx.base + "/fixture/graphql",
                                headers=(("Content-Type", "application/json"),), body=body,
                                operation_id="GQL-" + "3" * 32),
                source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
                browser_manager=self.case.fx.browser, browser_session_id=session.id,
                auth_material_observed=True)
            self.case.fx.traffic.store_response(
                exchange.id, CapturedResponse(
                    200, (("Content-Type", "application/json"),),
                    json.dumps({"data": {"node": self.case.fx.server.fixture_objects[external]}}).encode()))

    def _nested_observations(self, *, trusted_relation: bool = True) -> str:
        fx = self.case.fx
        tenant = fx.registry.get_tenant(self.case.target, self.owned.tenant_id)
        assert tenant is not None
        fx.recipe(recipe_id="dashboard_a", tenant="tenant-a", owner="tenant_a_admin",
                  object_type="dashboard", parent_type="project")
        resolved = fx.factory.resolve(
            package_id=fx.package.id, recipe_id="dashboard_a",
            identity_id=self.owner.id, tenant_id=tenant.id,
            session_id=self.owner_session.id, parent_id=self.owned.id,
            purpose="API nested dashboard fixture")
        self.assertEqual(resolved.outcome, "READY")
        child = resolved.item
        self.case.protect(child, tenant, policy="TENANT_ONLY")
        if trusted_relation:
            fx.store.create_fact(
                child.id, "belongs_to", self.owned.id, confidence=1,
                evidence_ids=(child.verification_evidence_ids[0],), source="FIXTURE",
                target_ref=self.case.target)
        owner_external = self.case.specialist._external_id(self.owned)
        child_external = self.case.specialist._external_id(child)
        actor_external = self.case.specialist._external_id(self.foreign_object)
        fx.server.fixture_nested_children = {owner_external: (child_external,),
                                             actor_external: ()}
        document = ("query GetProjectWithDashboards($id:ID!){node(id:$id){id name owner tenant "
                    "dashboards{id name owner tenant}}}")
        for actor, session, item in ((self.owner, self.owner_session, self.owned),
                                     (self.foreign, self.foreign_session, self.foreign_object)):
            external = self.case.specialist._external_id(item)
            body = json.dumps({"query": document, "variables": {"id": external},
                               "operationName": "GetProjectWithDashboards"}).encode()
            exchange = fx.traffic.store_request(
                fx.package, CapturedRequest("POST", fx.base + "/fixture/graphql",
                                            headers=(("Content-Type", "application/json"),),
                                            body=body, operation_id="GQL-" + "4" * 32),
                source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
                browser_manager=fx.browser, browser_session_id=session.id,
                auth_material_observed=True)
            node = {**fx.server.fixture_objects[external],
                    "dashboards": [fx.server.fixture_objects[key] for key in
                                   fx.server.fixture_nested_children[external]]}
            fx.traffic.store_response(
                exchange.id, CapturedResponse(200, (("Content-Type", "application/json"),),
                                              json.dumps({"data": {"node": node}}).encode()))
        return child.id

    def _batch_observations(self, *, envelope: str = "NODES_LIST") -> tuple[str, str]:
        fx = self.case.fx
        fx.recipe(recipe_id="project_a_batch", tenant="tenant-a", owner="tenant_a_admin")
        fx.recipe(recipe_id="project_b_batch", tenant="tenant-b", owner="tenant_b_admin")
        owner_second = fx.factory.resolve(
            package_id=fx.package.id, recipe_id="project_a_batch",
            identity_id=self.owner.id, tenant_id=self.owned.tenant_id,
            session_id=self.owner_session.id, purpose="API owner batch control")
        actor_second = fx.factory.resolve(
            package_id=fx.package.id, recipe_id="project_b_batch",
            identity_id=self.foreign.id, tenant_id=self.foreign_object.tenant_id,
            session_id=self.foreign_session.id, purpose="API actor batch control")
        self.assertEqual(owner_second.outcome, "READY")
        self.assertEqual(actor_second.outcome, "READY")
        self.case.protect(owner_second.item, self.case.tenants["tenant-a"],
                          policy="TENANT_ONLY")
        self.case.protect(actor_second.item, self.case.tenants["tenant-b"],
                          policy="TENANT_ONLY")
        document = ("query ReadMany($ids:[ID!]!){chosen:nodes(ids:$ids){id name owner tenant}}"
                    if envelope == "NODES_LIST" else
                    "query ReadArray($id:ID!){chosen:node(id:$id){id name owner tenant}}")
        operation_name = "ReadMany" if envelope == "NODES_LIST" else "ReadArray"
        for actor, session, pair in (
                (self.owner, self.owner_session, (self.owned, owner_second.item)),
                (self.foreign, self.foreign_session,
                 (self.foreign_object, actor_second.item))):
            ids = [self.case.specialist._external_id(item) for item in pair]
            payload = ({"query": document, "variables": {"ids": ids},
                        "operationName": operation_name} if envelope == "NODES_LIST" else
                       [{"query": document, "variables": {"id": value},
                         "operationName": operation_name} for value in ids])
            body = json.dumps(payload).encode()
            exchange = fx.traffic.store_request(
                fx.package, CapturedRequest("POST", fx.base + "/fixture/graphql",
                                            headers=(("Content-Type", "application/json"),),
                                            body=body, operation_id="GQL-" + "5" * 32),
                source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
                browser_manager=fx.browser, browser_session_id=session.id,
                auth_material_observed=True)
            result = ({"data": {"chosen": [fx.server.fixture_objects[key] for key in ids]}}
                      if envelope == "NODES_LIST" else
                      [{"data": {"chosen": fx.server.fixture_objects[key]}} for key in ids])
            fx.traffic.store_response(
                exchange.id, CapturedResponse(200, (("Content-Type", "application/json"),),
                                              json.dumps(result).encode()))
        return owner_second.item.id, actor_second.item.id

    def test_observed_two_id_batch_is_current_candidate(self):
        self._batch_observations()
        before = len(self.case.fx.server.received)
        candidates = self.api.generate(self.case.fx.package)
        batch = next(item for item in candidates if item.category == "BATCH_AUTH" and
                     self.registry.get_operation(self.case.target,
                                                 item.operation_id).name == "ReadMany")
        self.assertEqual(batch.status, "READY", batch.gaps)
        self.assertEqual(batch.test_object_id, self.owned.id)
        self.assertEqual(batch.boundary_identity_id, self.foreign.id)
        prepared = self.api.prepare_candidate(self.case.fx.package, batch.id)
        self.assertEqual(prepared.status, "PLANNED")
        plan = self.case.specialist.planner.store.get(prepared.plan_id, self.case.target)
        self.assertEqual({item["binding"] for item in plan["request_templates"]},
                         {"API_OBSERVED_BATCH_V1"})
        self.assertEqual(len(self.case.fx.objects.requirements(prepared.plan_id,
                                                                 self.case.target)), 4)
        self.assertEqual(len(self.case.fx.server.received), before)

    def test_batch_without_verified_actor_session_sends_no_test_requests(self):
        self._batch_observations()
        self.case.fx.browser.stop(self.foreign_session.id)
        before = len(self.case.fx.server.received)
        candidates = self.api.generate(self.case.fx.package)
        batch = next(item for item in candidates if item.category == "BATCH_AUTH" and
                     self.registry.get_operation(self.case.target,
                                                 item.operation_id).name == "ReadMany")
        self.assertNotEqual(batch.status, "READY")
        self.assertEqual(self.api.prepare_candidate(self.case.fx.package, batch.id).status,
                         "REVIEW")
        self.assertEqual(len(self.case.fx.server.received), before)

    def test_field_proof_must_belong_to_matching_object_branch(self):
        exchange = self._field_observations(unrelated_field=True)
        object_hash = hashlib.sha256(self.case.specialist._external_id(self.owned).encode()).hexdigest()
        engine = SimpleNamespace(evidence=self.case.fx.store)
        observation = SimpleNamespace(exchange=exchange)
        self.assertTrue(APIReadValidator._graphql_owned_data(
            observation, engine, object_hash, "/node/email"))
        self.assertFalse(APIReadValidator._graphql_owned_data(
            observation, engine, object_hash, "/other/email"))

    def test_nested_field_proof_rejects_independent_foreign_object(self):
        exchange = self._field_observations(nested_profile=True,
                                            foreign_profile_id=True)
        object_hash = hashlib.sha256(
            self.case.specialist._external_id(self.owned).encode()).hexdigest()
        engine = SimpleNamespace(evidence=self.case.fx.store)
        observation = SimpleNamespace(exchange=exchange)
        self.assertTrue(APIReadValidator._graphql_owned_data(
            observation, engine, object_hash))
        self.assertFalse(APIReadValidator._graphql_owned_data(
            observation, engine, object_hash, "/node/profile/email"))

    def _run_local_query(self, *, secure: bool, category: str = "OBJECT_AUTH",
                         field_secure: bool = False, partial_error: bool = False,
                         autonomous: bool = False, global_id: bool = False,
                         actor_subset: bool = False,
                         nested_profile: bool = False,
                         nested: bool = False, batch: bool = False,
                         array_batch: bool = False) -> dict[str, object]:
        fx = self.case.fx
        fx.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        fx.targets.package = fx.package
        if category == "FIELD_AUTH":
            self._field_observations(actor_subset=actor_subset,
                                     nested_profile=nested_profile)
            fx.server.fixture_nested_profile = nested_profile
        if global_id:
            self._global_id_observations()
            fx.server.fixture_global_lookup = True
        child_id = self._nested_observations() if nested else None
        if batch:
            self._batch_observations(envelope="OPERATION_ARRAY" if array_batch else
                                     "NODES_LIST")
        runs = PlanRunStore(fx.store)
        self.case.specialist.orchestrator = PlanOrchestrator(
            runs=runs, targets=fx.targets, hypotheses=self.case.hypotheses,
            context=self.case.specialist.context,
            checker=self.case.specialist.planner.checker,
            registry=self.case.specialist.planner.registry,
            policy=fx.policy, approvals=PolicyStore(fx.store), executor=fx.executor,
            traffic=fx.traffic, evidence=fx.store, objects=fx.objects,
            api_operations=self.registry)
        self.case.specialist.validator = DeterministicValidatorEngine(
            runs=runs, traffic=fx.traffic, evidence=fx.store,
            identities=fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(fx.store), api_operations=self.registry)
        fx.server.fixture_secure = secure and not nested and not batch
        fx.server.fixture_field_secure = field_secure
        fx.server.fixture_partial_error = partial_error
        fx.server.fixture_nested_secure = secure and nested
        fx.server.fixture_batch_secure = secure and batch
        before = len(fx.server.received)
        candidates = self.api.generate(
            fx.package, mode="BOUNDED_AUTONOMOUS" if autonomous else "PLAN_ONLY")
        if autonomous:
            self.assertTrue(any(item.category == category and item.status in
                                {"VALIDATED", "REJECTED", "RUNNING"} for item in candidates),
                            [(item.category, item.status, item.gaps) for item in candidates])
        candidate = next(item for item in candidates
                         if item.category == category and
                         (not nested or item.child_object_id == child_id) and
                         (not batch or self.registry.get_operation(
                             self.case.target, item.operation_id).name == (
                                 "ReadArray" if array_batch else "ReadMany")) and
                         (not global_id or self.registry.get_operation(
                             self.case.target, item.operation_id).global_id_type == "Project") and
                         item.status in
                         ({"VALIDATED", "REJECTED", "RUNNING"} if autonomous else {"READY"}))
        if autonomous:
            self.assertLessEqual(len(fx.server.received) - before, 5)
            if candidate.status == "RUNNING":
                return {"candidate": candidate.to_dict(),
                        "run_status": runs.get(candidate.run_id, self.case.target).status.value}
            return self.api.validate_candidate(fx.package, candidate.id)
        prepared = self.api.prepare_candidate(fx.package, candidate.id)
        self.assertEqual(prepared.status, "PLANNED")
        detail = self.api.start_candidate(fx.package, candidate.id)
        for _ in range(26):
            status = detail["run"]["status"]
            if status == "COMPLETED":
                break
            if status == "WAITING_APPROVAL":
                approval_id = detail["run"]["approval_id"]
                fx.policy.audit.decide(approval_id, self.case.target, approve=True)
                runs.approval_decision(approval_id, self.case.target, granted=True)
                detail = self.case.specialist.orchestrator.resume(
                    detail["run"]["id"], fx.package.id)
                continue
            self.assertIn(status, {"CREATED", "READY"}, detail["run"])
            detail = self.api.advance_candidate(fx.package, candidate.id)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        return detail.get("validation") or self.api.validate_candidate(fx.package, candidate.id)

    def test_graphql_foreign_object_read_is_confirmed(self):
        result = self._run_local_query(secure=False)
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value,
                         result["result"]["reason_codes"])
        self.assertIsNotNone(result["finding"])

    def test_confirmed_api_audit_chain_and_existing_evidence_reuse(self):
        fx = self.case.fx
        behaviour = BehaviourStore(fx.store)
        learner = NormalBehaviourLearner(
            behaviour, fx.traffic, fx.registry, fx.browser, fx.objects, fx.store)
        learning_run = learner.create(fx.package)
        completed = learner.run(fx.package, learning_run.run_id)
        self.assertIn(completed.status.value, {"COMPLETED", "PARTIAL"})
        self.api.behaviour = behaviour
        detail = self._run_local_query(secure=False)
        self.assertEqual(detail["result"]["status"], ValidationStatus.CONFIRMED.value)
        candidate = next(row for row in self.registry.list_candidates(self.case.target)
                         if row.status == "VALIDATED" and row.category == "OBJECT_AUTH" and
                         row.test_object_id == self.owned.id)
        self.assertEqual(candidate.behaviour_run_id, completed.run_id)
        operation = self.registry.get_operation(self.case.target, candidate.operation_id)
        self.assertIn(candidate.owner_exchange_id, operation.exchange_ids)
        self.assertTrue(operation.evidence_ids)
        self.assertTrue(fx.objects.get(candidate.test_object_id, self.case.target).verified_at)
        plan = self.case.specialist.planner.store.get(candidate.plan_id, self.case.target)
        run = PlanRunStore(fx.store).get(candidate.run_id, self.case.target)
        result = ValidationStore(fx.store).get(candidate.validation_id, self.case.target)
        finding = ValidationStore(fx.store).get_finding(
            detail["finding"]["id"], self.case.target)
        hypothesis = self.case.hypotheses.get(candidate.hypothesis_id, self.case.target)
        self.assertEqual(finding.validation_id, result.id)
        self.assertEqual(result.run_id, run.id)
        self.assertEqual(run.plan_id, plan["id"])
        self.assertEqual(plan["hypothesis_id"], hypothesis.id)
        self.assertEqual(plan["api_binding"]["operation_id"], operation.id)
        self.assertEqual(result.skill_id, plan["skill_id"])
        self.assertGreaterEqual(self.case.specialist.planner.store.outcome_counts(
            "api-observed-read").get("CONFIRMED", 0), 1)
        self.assertTrue(result.supporting_evidence_ids)
        steps = [step for step in PlanRunStore(fx.store).steps(run.id)
                 if step.action_slot is not None]
        self.assertEqual(len(steps), 5)
        self.assertEqual(run.requests_consumed, 5)
        metrics = self.registry.metrics(self.case.target)
        self.assertGreaterEqual(metrics["plans"], 1)
        self.assertGreaterEqual(metrics["executions"], 1)
        self.assertEqual(metrics["requests"], 5)
        self.assertGreaterEqual(metrics["confirmed"], 1)
        for step in steps:
            self.assertTrue(step.action_id and step.decision_id and step.permit_id and
                            step.result_id, step.to_dict())
            with fx.store._connection() as db:
                decision = db.execute(
                    "SELECT action_id,target_id FROM policy_decisions WHERE decision_id=?",
                    (step.decision_id,)).fetchone()
                permit = db.execute(
                    "SELECT action_id,target_id,consumed_at FROM executor_permits "
                    "WHERE permit_id=?", (step.permit_id,)).fetchone()
            self.assertEqual(decision["action_id"], step.action_id)
            self.assertEqual(permit["action_id"], step.action_id)
            self.assertEqual(decision["target_id"], self.case.target)
            self.assertEqual(permit["target_id"], self.case.target)
            self.assertIsNotNone(permit["consumed_at"])
            step_result = PlanRunStore(fx.store).result(step.id)
            self.assertTrue(step_result.exchange_ids)
            for exchange_id in step_result.exchange_ids:
                exchange = fx.traffic.get_exchange(exchange_id)
                self.assertEqual(exchange.target_id, self.case.target)
                self.assertTrue(exchange.evidence_ids)
        before = len(fx.server.received)
        reopened = APISpecialist(
            registry=APIOperationRegistry(fx.store), traffic=fx.traffic,
            evidence=fx.store, js=DOMXSSStore(fx.store), behaviour=behaviour,
            authorization=self.case.specialist)
        self.assertEqual(reopened.prepare_candidate(fx.package, candidate.id).plan_id,
                         candidate.plan_id)
        self.assertEqual(reopened.validate_candidate(fx.package, candidate.id)
                         ["result"]["id"], result.id)
        self.assertEqual(len(fx.server.received), before)

    def test_graphql_http_200_denial_is_rejected(self):
        result = self._run_local_query(secure=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.REJECTED.value,
                         result["result"]["reason_codes"])
        self.assertIsNone(result["finding"])

    def test_known_global_id_foreign_node_lookup_is_confirmed(self):
        result = self._run_local_query(secure=False, global_id=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value,
                         result["result"]["reason_codes"])

    def test_known_global_id_node_lookup_denial_is_rejected(self):
        result = self._run_local_query(secure=True, global_id=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.REJECTED.value,
                         result["result"]["reason_codes"])

    def test_protected_nested_child_disclosed_under_accessible_parent(self):
        result = self._run_local_query(secure=False, category="NESTED_AUTH", nested=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value,
                         result["result"]["reason_codes"])
        self.assertEqual(self.registry.metrics(self.case.target)["category_outcomes"]
                         ["NESTED_AUTH"]["confirmed"], 1)

    def test_secure_nested_child_filtered_under_accessible_parent(self):
        result = self._run_local_query(secure=True, category="NESTED_AUTH", nested=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.REJECTED.value,
                         result["result"]["reason_codes"])

    def test_mixed_observed_graphql_batch_discloses_foreign_item(self):
        result = self._run_local_query(secure=False, category="BATCH_AUTH", batch=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value,
                         result["result"]["reason_codes"])
        self.assertIsNotNone(result["finding"])
        self.assertEqual(self.registry.metrics(self.case.target)["category_outcomes"]
                         ["BATCH_AUTH"]["confirmed"], 1)

    def test_mixed_observed_graphql_batch_filters_foreign_item(self):
        result = self._run_local_query(secure=True, category="BATCH_AUTH", batch=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.REJECTED.value,
                         result["result"]["reason_codes"])
        self.assertIsNone(result["finding"])

    def test_observed_two_operation_graphql_array_discloses_foreign_item(self):
        result = self._run_local_query(secure=False, category="BATCH_AUTH",
                                       batch=True, array_batch=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value,
                         result["result"]["reason_codes"])

    def test_observed_two_operation_graphql_array_filters_foreign_item(self):
        result = self._run_local_query(secure=True, category="BATCH_AUTH",
                                       batch=True, array_batch=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.REJECTED.value,
                         result["result"]["reason_codes"])

    def test_nested_shape_without_verified_relationship_stays_plan_only(self):
        self._nested_observations(trusted_relation=False)
        before = len(self.case.fx.server.received)
        candidates = self.api.generate(self.case.fx.package)
        nested = next(item for item in candidates if item.category == "NESTED_AUTH" and
                      self.registry.get_operation(self.case.target, item.operation_id).name ==
                      "GetProjectWithDashboards")
        self.assertIsNone(nested.child_object_id)
        self.assertIn("EXACT_MULTI_OBJECT_BINDING_MISSING", nested.gaps)
        self.assertEqual(self.api.prepare_candidate(self.case.fx.package, nested.id).status,
                         "REVIEW")
        self.assertEqual(len(self.case.fx.server.received), before)

    def test_protected_graphql_field_is_confirmed(self):
        result = self._run_local_query(secure=False, category="FIELD_AUTH")
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value,
                         result["result"]["reason_codes"])
        self.assertEqual(self.registry.metrics(self.case.target)["category_outcomes"]
                         ["FIELD_AUTH"]["confirmed"], 1)

    def test_observed_actor_field_subset_uses_owner_selection_for_boundary(self):
        result = self._run_local_query(secure=False, category="FIELD_AUTH",
                                       actor_subset=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value,
                         result["result"]["reason_codes"])
        candidate = next(item for item in self.registry.list_candidates(self.case.target)
                         if item.category == "FIELD_AUTH" and item.status == "VALIDATED")
        plan = self.case.specialist.planner.store.get(candidate.plan_id, self.case.target)
        shapes = plan["request_templates"]
        self.assertNotEqual(shapes[0]["operation_id"], shapes[1]["operation_id"])
        self.assertEqual(shapes[1]["field_path"], "")
        self.assertTrue(all(shapes[index]["operation_id"] == shapes[0]["operation_id"]
                            for index in (2, 3, 4)))

    def test_observed_actor_field_subset_still_rejects_secure_boundary(self):
        result = self._run_local_query(secure=False, category="FIELD_AUTH",
                                       field_secure=True, actor_subset=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.REJECTED.value,
                         result["result"]["reason_codes"])

    def test_observed_nested_profile_subset_confirms_protected_scalar(self):
        result = self._run_local_query(secure=False, category="FIELD_AUTH",
                                       actor_subset=True, nested_profile=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value,
                         result["result"]["reason_codes"])

    def test_observed_nested_profile_subset_rejects_denied_field(self):
        result = self._run_local_query(secure=False, category="FIELD_AUTH",
                                       actor_subset=True, nested_profile=True,
                                       field_secure=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.REJECTED.value,
                         result["result"]["reason_codes"])

    def test_null_protected_field_with_permission_error_is_rejected(self):
        result = self._run_local_query(secure=False, category="FIELD_AUTH",
                                       field_secure=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.REJECTED.value,
                         result["result"]["reason_codes"])

    def test_partial_graphql_data_with_error_still_confirms_field(self):
        result = self._run_local_query(secure=False, category="FIELD_AUTH",
                                       partial_error=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value,
                         result["result"]["reason_codes"])

    def test_partial_graphql_data_with_unrelated_error_still_confirms_object(self):
        result = self._run_local_query(secure=False, partial_error=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value,
                         result["result"]["reason_codes"])

    def test_autonomous_graphql_read_waits_for_approval(self):
        result = self._run_local_query(secure=False, autonomous=True)
        self.assertEqual(result["candidate"]["status"], "RUNNING")
        self.assertEqual(result["run_status"], "WAITING_APPROVAL")


class APIAuthorizationDelegationTests(unittest.TestCase):
    def test_synthetic_mass_assignment_signal_stays_review_only(self):
        case = _authorization_fixture.AuthorizationSpecialistTests(
            "test_cross_tenant_candidate_uses_verified_object_and_owner_traffic")
        case.setUp()
        self.addCleanup(case.doCleanups)
        owner, session, tenant, item = case.fixture_object()
        case.protect(item, tenant, policy="TENANT_ONLY")
        fx = case.fx
        external = case.specialist._external_id(item)
        fx.server.fixture_objects[external]["can_share_test"] = False
        fx.server.fixture_mass_assignment_enabled = True
        endpoint = fx.base + "/fixture/tenant-a/projects/" + external
        parsed = urlsplit(endpoint)
        body = b'{"can_share_test":true}'
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
        try:
            connection.request("PATCH", parsed.path, body=body, headers={
                "Content-Type": "application/json",
                "Cookie": "fixture_actor=tenant_a_admin"})
            response = connection.getresponse()
            changed = response.read()
        finally:
            connection.close()
        self.assertEqual(response.status, 200)
        self.assertTrue(json.loads(changed)["can_share_test"])
        captured = fx.traffic.store_request(
            fx.package, CapturedRequest("PATCH", endpoint,
                headers=(("Content-Type", "application/json"),), body=body,
                operation_id="OPERATION-" + "6" * 32),
            source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
            browser_manager=fx.browser, browser_session_id=session.id,
            auth_material_observed=True)
        fx.traffic.store_response(captured.id, CapturedResponse(
            200, (("Content-Type", "application/json"),), changed))
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
        try:
            connection.request("GET", parsed.path,
                               headers={"Cookie": "fixture_actor=tenant_a_admin"})
            readback = connection.getresponse()
            readback_body = readback.read()
        finally:
            connection.close()
        self.assertEqual(readback.status, 200)
        self.assertTrue(json.loads(readback_body)["can_share_test"])
        registry = APIOperationRegistry(fx.store)
        specialist = APISpecialist(
            registry=registry, traffic=fx.traffic, evidence=fx.store,
            js=DOMXSSStore(fx.store), authorization=case.specialist)
        before = len(fx.server.received)
        candidates = specialist.generate(fx.package)
        lead = next(row for row in candidates if
                    row.category == "MASS_ASSIGNMENT_CANDIDATE" and
                    row.owner_exchange_id == captured.id)
        self.assertEqual(lead.status, "REVIEW")
        self.assertIn("SAFE_DISPOSABLE_PROOF_REQUIRED", lead.gaps)
        self.assertEqual(specialist.prepare_candidate(fx.package, lead.id).status,
                         "REVIEW")
        self.assertEqual(len(fx.server.received), before)
        self.assertIsNone(registry.get_candidate(case.target, lead.id).validation_id)

    def _exercise_rest_batch(self, *, vulnerable: bool) -> None:
        fixture = _mutation_fixture.AuthorizationBatchFixtureTests(
            "test_mixed_batch_discloses_foreign_object")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        authorization_candidate, orchestrator, runs = fixture._prepare(
            vulnerable=vulnerable)
        case, fx = fixture.case, fixture.case.fx
        case.specialist.orchestrator = orchestrator
        case.specialist.validator = DeterministicValidatorEngine(
            runs=runs, traffic=fx.traffic, evidence=fx.store,
            identities=fx.registry, hypotheses=case.hypotheses,
            results=ValidationStore(fx.store))
        registry = APIOperationRegistry(fx.store)
        specialist = APISpecialist(
            registry=registry, traffic=fx.traffic, evidence=fx.store,
            js=DOMXSSStore(fx.store), authorization=case.specialist)
        before = len(fx.server.received)
        candidates = specialist.generate(fx.package)
        candidate = next(row for row in candidates if row.category == "BATCH_AUTH" and
                         row.owner_exchange_id == authorization_candidate.owner_exchange_id and
                         row.test_object_id == authorization_candidate.test_object_id)
        prepared = specialist.prepare_candidate(fx.package, candidate.id)
        self.assertEqual(prepared.status, "PLANNED")
        self.assertEqual(prepared.plan_id, authorization_candidate.plan_id)
        self.assertEqual(len(fx.server.received), before)
        detail = specialist.start_candidate(fx.package, candidate.id)
        for _ in range(16):
            if detail["run"]["status"] == "COMPLETED":
                break
            self.assertIn(detail["run"]["status"], {"CREATED", "READY"})
            detail = specialist.advance_candidate(fx.package, candidate.id)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 4)
        expected = ValidationStatus.CONFIRMED if vulnerable else ValidationStatus.REJECTED
        self.assertEqual(detail["validation"]["result"]["status"], expected.value,
                         detail["validation"]["result"]["reason_codes"])
        linked = registry.get_candidate(case.target, candidate.id)
        self.assertEqual(linked.status, "VALIDATED" if vulnerable else "REJECTED")

    def test_mixed_rest_batch_discloses_foreign_object(self):
        self._exercise_rest_batch(vulnerable=True)

    def test_mixed_rest_batch_filters_foreign_object(self):
        self._exercise_rest_batch(vulnerable=False)

    def test_autonomous_rest_read_completes_one_five_request_plan(self):
        case = _authorization_fixture.AuthorizationSpecialistTests(
            "test_cross_tenant_candidate_uses_verified_object_and_owner_traffic")
        case.setUp()
        self.addCleanup(case.doCleanups)
        fx = case.fx
        fx.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        fx.targets.package = fx.package
        owner, owner_session, tenant, owned = case.fixture_object()
        actor, actor_session, actor_tenant = case.actor(
            "tenant_b_admin", "tenant-b")
        fx.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        actor_object = fx.factory.resolve(
            package_id=fx.package.id, recipe_id="project_b",
            identity_id=actor.id, tenant_id=actor_tenant.id,
            session_id=actor_session.id, purpose="API actor control").item
        case.protect(owned, tenant, policy="TENANT_ONLY")
        for identity, session, item in ((owner, owner_session, owned),
                                        (actor, actor_session, actor_object)):
            external = case.specialist._external_id(item)
            request = fx.traffic.store_request(
                fx.package, CapturedRequest("GET", fx.base + "/api/projects/" + external),
                source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
                browser_manager=fx.browser, browser_session_id=session.id,
                auth_material_observed=True)
            fx.traffic.store_response(
                request.id, CapturedResponse(
                    200, (("Content-Type", "application/json"),),
                    json.dumps(fx.server.fixture_objects[external]).encode()))
        registry = APIOperationRegistry(fx.store)
        runs = PlanRunStore(fx.store)
        case.specialist.orchestrator = PlanOrchestrator(
            runs=runs, targets=fx.targets, hypotheses=case.hypotheses,
            context=case.specialist.context, checker=case.specialist.planner.checker,
            registry=case.specialist.planner.registry, policy=fx.policy,
            approvals=PolicyStore(fx.store), executor=fx.executor,
            traffic=fx.traffic, evidence=fx.store, objects=fx.objects,
            api_operations=registry)
        case.specialist.validator = DeterministicValidatorEngine(
            runs=runs, traffic=fx.traffic, evidence=fx.store,
            identities=fx.registry, hypotheses=case.hypotheses,
            results=ValidationStore(fx.store), api_operations=registry)
        specialist = APISpecialist(
            registry=registry, traffic=fx.traffic, evidence=fx.store,
            js=DOMXSSStore(fx.store), authorization=case.specialist)
        before = len(fx.server.received)
        candidates = specialist.generate(fx.package, mode="BOUNDED_AUTONOMOUS")
        self.assertEqual(len(fx.server.received) - before, 5,
                         {"candidates": [(row.category, row.status, row.gaps,
                                          row.owner_exchange_id) for row in candidates],
                          "operations": [(row.endpoint, row.version_hash,
                                          row.exchange_ids) for row in
                                         registry.list_operations(case.target)],
                          "run": next((runs.get(row.run_id, case.target).to_dict()
                                       for row in candidates if row.run_id), None)})
        candidate = next(row for row in candidates if row.category == "OBJECT_AUTH" and
                         row.test_object_id == owned.id and row.status == "VALIDATED")
        self.assertEqual(specialist.validate_candidate(fx.package, candidate.id)
                         ["result"]["status"], ValidationStatus.CONFIRMED.value)
        metrics = registry.metrics(case.target)
        self.assertEqual(metrics["executions"], 1)
        self.assertEqual(metrics["requests"], 5)
        self.assertEqual(metrics["confirmed"], 1)

    def _run_rest_bfla(self, *, secure: bool) -> tuple[dict[str, object], APISpecialist]:
        case = _authorization_fixture.AuthorizationSpecialistTests(
            "test_same_tenant_vertical_role_restriction_confirms")
        case.setUp()
        self.addCleanup(case.doCleanups)
        owner, owner_session, tenant, item = case.fixture_object(role="admin")
        member, _, _ = case.actor("tenant_a_member", "tenant-a", role="member")
        case.protect(item, tenant, policy="ROLE_RESTRICTED",
                     role_id=case.roles["admin"].id)
        external = case.specialist._external_id(item)
        exchange = case.fx.traffic.store_request(
            case.fx.package,
            CapturedRequest("GET", case.fx.base + "/api/admin/projects/" + external),
            source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
            browser_manager=case.fx.browser,
            browser_session_id=owner_session.id, auth_material_observed=True)
        case.fx.traffic.store_response(
            exchange.id, CapturedResponse(
                200, (("Content-Type", "application/json"),),
                json.dumps({"id": external, "owner": "tenant_a_admin",
                            "tenant": "tenant-a"}).encode()))
        registry = APIOperationRegistry(case.fx.store)
        specialist = APISpecialist(
            registry=registry, traffic=case.fx.traffic, evidence=case.fx.store,
            js=DOMXSSStore(case.fx.store), authorization=case.specialist)
        before = len(case.fx.server.received)
        candidates = specialist.generate(case.fx.package)
        candidate = next(row for row in candidates if row.category == "BFLA" and
                         row.test_object_id == item.id and
                         row.owner_exchange_id == exchange.id)
        self.assertEqual(candidate.boundary_identity_id, member.id)
        prepared = specialist.prepare_candidate(case.fx.package, candidate.id)
        self.assertEqual(prepared.status, "PLANNED")
        self.assertIsNotNone(prepared.authorization_candidate_id)
        self.assertEqual(len(case.fx.server.received), before)
        runs = PlanRunStore(case.fx.store)
        case.specialist.orchestrator = PlanOrchestrator(
            runs=runs, targets=case.fx.targets, hypotheses=case.hypotheses,
            context=case.specialist.context,
            checker=case.specialist.planner.checker,
            registry=case.specialist.planner.registry,
            policy=case.fx.policy, approvals=PolicyStore(case.fx.store),
            executor=case.fx.executor, traffic=case.fx.traffic,
            evidence=case.fx.store, objects=case.fx.objects)
        case.specialist.validator = DeterministicValidatorEngine(
            runs=runs, traffic=case.fx.traffic, evidence=case.fx.store,
            identities=case.fx.registry, hypotheses=case.hypotheses,
            results=ValidationStore(case.fx.store))
        case.fx.server.fixture_secure = secure
        detail = specialist.start_candidate(case.fx.package, prepared.id)
        for _ in range(24):
            if detail["run"]["status"] == "COMPLETED":
                break
            if detail["run"]["status"] == "WAITING_APPROVAL":
                approval_id = detail["run"]["approval_id"]
                case.fx.policy.audit.decide(approval_id, case.target, approve=True)
                runs.approval_decision(approval_id, case.target, granted=True)
                detail = case.specialist.orchestrator.resume(
                    detail["run"]["id"], case.fx.package.id)
                continue
            self.assertIn(detail["run"]["status"], {"CREATED", "READY"}, detail)
            detail = specialist.advance_candidate(case.fx.package, prepared.id)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail)
        self.assertEqual(detail["run"]["requests_consumed"], 4)
        self.assertTrue(any(path.startswith("/api/admin/projects/") and
                            cookie == "fixture_actor=tenant_a_member"
                            for method, path, cookie in case.fx.server.received[before:]
                            if method == "GET"))
        return specialist.validate_candidate(case.fx.package, prepared.id), specialist

    def test_rest_bfla_member_invokes_admin_api_and_confirms(self):
        result, _ = self._run_rest_bfla(secure=False)
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value)
        self.assertIsNotNone(result["finding"])

    def test_rest_bfla_member_denied_by_admin_api_is_rejected(self):
        result, _ = self._run_rest_bfla(secure=True)
        self.assertEqual(result["result"]["status"], ValidationStatus.REJECTED.value)
        self.assertIsNone(result["finding"])

    def test_nested_rest_candidate_uses_verified_parent_child_plan(self):
        case = _authorization_fixture.AuthorizationSpecialistTests(
            "test_nested_parent_child_relation_creates_bounded_plan")
        case.setUp()
        self.addCleanup(case.doCleanups)
        owner, owner_session, tenant, parent = case.fixture_object()
        case.fx.recipe(recipe_id="dashboard_a", tenant="tenant-a",
                       owner="tenant_a_admin", object_type="dashboard",
                       parent_type="project")
        child = case.fx.factory.resolve(
            package_id=case.fx.package.id, recipe_id="dashboard_a",
            identity_id=owner.id, tenant_id=tenant.id,
            session_id=owner_session.id, parent_id=parent.id,
            purpose="API nested fixture").item
        foreign, foreign_session, foreign_tenant = case.actor(
            "tenant_b_admin", "tenant-b")
        case.fx.recipe(recipe_id="project_b", tenant="tenant-b",
                       owner="tenant_b_admin")
        case.fx.factory.resolve(
            package_id=case.fx.package.id, recipe_id="project_b",
            identity_id=foreign.id, tenant_id=foreign_tenant.id,
            session_id=foreign_session.id, purpose="API foreign parent")
        parent_external = case.specialist._external_id(parent)
        child_external = case.specialist._external_id(child)
        case.fx.server.fixture_objects[child_external]["parentId"] = parent_external
        exchange = case.fx.traffic.store_request(
            case.fx.package,
            CapturedRequest("GET", case.fx.base + "/fixture/tenant-a/projects/" +
                            parent_external + "/dashboards/" + child_external),
            source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
            browser_manager=case.fx.browser,
            browser_session_id=owner_session.id, auth_material_observed=True)
        case.fx.traffic.store_response(
            exchange.id, CapturedResponse(
                200, (("Content-Type", "application/json"),),
                json.dumps({"id": child_external, "parentId": parent_external,
                            "owner": "tenant_a_admin", "tenant": "tenant-a"}).encode()))
        registry = APIOperationRegistry(case.fx.store)
        specialist = APISpecialist(
            registry=registry, traffic=case.fx.traffic, evidence=case.fx.store,
            js=DOMXSSStore(case.fx.store), authorization=case.specialist)
        before = len(case.fx.server.received)
        candidates = specialist.generate(case.fx.package)
        nested = next(row for row in candidates if row.category == "NESTED_AUTH" and
                      row.test_object_id == child.id and
                      row.owner_exchange_id == exchange.id)
        prepared = specialist.prepare_candidate(case.fx.package, nested.id)
        self.assertEqual(prepared.status, "PLANNED")
        self.assertIsNotNone(prepared.authorization_candidate_id)
        self.assertEqual(len(case.fx.server.received), before)

    def _exercise_typed_mutation(self, *, denied: bool,
                                 nested: bool = False, action: bool = False) -> None:
        fixture = _mutation_fixture.AuthorizationMutationFixtureTests(
            "test_graphql_foreign_rename_requires_readback_and_restores")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        item, authorization_candidate, orchestrator, runs, mutations, _ = fixture._fixture(
            graphql=not action, action=action,
            graphql_boundary_noop=denied and not nested and not action,
            nested_graphql=nested, secure=denied and (nested or action))
        fx = fixture.case.fx
        fixture.case.specialist.orchestrator = orchestrator
        fixture.case.specialist.validator = DeterministicValidatorEngine(
            runs=runs, traffic=fx.traffic, evidence=fx.store,
            identities=fx.registry, hypotheses=fixture.case.hypotheses,
            results=ValidationStore(fx.store))
        registry = APIOperationRegistry(fx.store)
        specialist = APISpecialist(
            registry=registry, traffic=fx.traffic, evidence=fx.store,
            js=DOMXSSStore(fx.store), authorization=fixture.case.specialist)
        before = len(fx.server.received)
        candidates = specialist.generate(fx.package)
        candidate = next(row for row in candidates if row.category == "MUTATION_AUTH" and
                         row.test_object_id == item.id and row.owner_exchange_id ==
                         authorization_candidate.owner_exchange_id)
        prepared = specialist.prepare_candidate(fx.package, candidate.id)
        self.assertEqual(prepared.status, "PLANNED")
        self.assertEqual(prepared.plan_id, authorization_candidate.plan_id)
        self.assertEqual(prepared.authorization_candidate_id, authorization_candidate.id)
        self.assertEqual(len(fx.objects.requirements(prepared.plan_id, fixture.case.target)),
                         3 if nested else 1)
        self.assertEqual(len(fx.server.received), before)
        detail = specialist.start_candidate(fx.package, candidate.id)
        for _ in range(24):
            if detail["run"]["status"] == "COMPLETED":
                break
            self.assertIn(detail["run"]["status"], {"CREATED", "READY"})
            detail = specialist.advance_candidate(fx.package, candidate.id)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 7)
        validation = detail["validation"]
        expected = ValidationStatus.REJECTED if denied else ValidationStatus.CONFIRMED
        self.assertEqual(validation["result"]["status"], expected.value,
                         validation["result"]["reason_codes"])
        linked = registry.get_candidate(fixture.case.target, candidate.id)
        self.assertEqual(linked.validation_id, validation["result"]["id"])
        self.assertEqual(linked.status, "REJECTED" if denied else "VALIDATED")
        self.assertEqual(fx.server.fixture_objects[
            fixture.case.specialist._external_id(item)]["name"], item.test_name)
        self.assertEqual(len(mutations.list_for_run(detail["run"]["id"], fixture.case.target)), 3)

    def test_graphql_mutation_reuses_phase20_readback_and_restore(self):
        self._exercise_typed_mutation(denied=False)

    def test_graphql_http_200_denied_mutation_stays_rejected(self):
        self._exercise_typed_mutation(denied=True)

    def test_nested_graphql_mutation_reuses_typed_plan(self):
        self._exercise_typed_mutation(denied=False, nested=True)

    def test_nested_graphql_mutation_denial_reuses_typed_plan(self):
        self._exercise_typed_mutation(denied=True, nested=True)

    def test_rest_post_action_reuses_phase20_readback_and_restore(self):
        self._exercise_typed_mutation(denied=False, action=True)

    def test_rest_post_action_denial_remains_rejected(self):
        self._exercise_typed_mutation(denied=True, action=True)


class APIDisposableDeleteTests(unittest.TestCase):
    def _exercise(self, *, secure: bool, invalid_foreign: bool = False) -> None:
        fixture = _mutation_fixture.AuthorizationMutationFixtureTests(
            "test_disposable_delete_vulnerable_boundary_confirms")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        previous, source, _, runs, mutations = fixture._run_delete(secure=secure)
        self.assertEqual(previous["run"]["status"], "COMPLETED")
        case, fx = fixture.case, fixture.case.fx
        self.assertEqual(fx.objects.get(source.id, case.target).state, ObjectState.CLEANED)
        owner_session = fx.browser.get_active_session(case.target, source.creator_identity_id)
        self.assertIsNotNone(owner_session)
        recipe = fx.catalog.get(fx.package.id, source.recipe_id)
        self.assertIsNotNone(recipe)
        current = []
        for label in ("target", "control"):
            draft = fx.objects.plan(
                target_id=case.target, package_id=fx.package.id,
                object_type=recipe.object_type,
                creator_identity_id=source.creator_identity_id,
                tenant_id=source.tenant_id, recipe_id=recipe.id,
                recipe_hash=recipe.sha256,
                test_name="hackbot-test-api-delete-" + label,
                cleanup_strategy=recipe.cleanup_strategy)
            item = fx.factory.create(draft.id, case.target,
                                     session_id=owner_session.id).item
            self.assertEqual(item.state, ObjectState.READY)
            case.protect(item, case.tenants["tenant-a"], policy="TENANT_ONLY")
            current.append(item)
        case.specialist.orchestrator = PlanOrchestrator(
            runs=runs, targets=fx.targets, hypotheses=case.hypotheses,
            context=case.specialist.context, checker=case.specialist.planner.checker,
            registry=case.specialist.planner.registry, policy=fx.policy,
            approvals=PolicyStore(fx.store), executor=fx.executor,
            traffic=fx.traffic, evidence=fx.store, objects=fx.objects,
            recipes=fx.catalog, mutations=mutations)
        case.specialist.validator = DeterministicValidatorEngine(
            runs=runs, traffic=fx.traffic, evidence=fx.store,
            identities=fx.registry, hypotheses=case.hypotheses,
            results=ValidationStore(fx.store))
        registry = APIOperationRegistry(fx.store)
        api = APISpecialist(registry=registry, traffic=fx.traffic,
                            evidence=fx.store, js=DOMXSSStore(fx.store),
                            authorization=case.specialist)
        before = len(fx.server.received)
        api.profile(fx.package)
        surface = case.specialist.profile(fx.package)
        operation = next(item for item in registry.list_operations(case.target, limit=100)
                         if item.method == "DELETE" and
                         api._delete_controls(fx.package, item, surface) is not None)
        source_write = next(item for item in mutations.list_for_run(
            previous["run"]["id"], case.target) if
            item.test_object_id == source.id and item.mutation_exchange_id)
        self.assertEqual(fx.objects.find_cleaned_by_delete_exchange(
            case.target, source_write.mutation_exchange_id).id, source.id)
        self.assertIsNone(fx.objects.find_cleaned_by_delete_exchange(
            case.target, "TX-" + "0" * 32))
        with patch.object(fx.objects, "list_for_target",
                          side_effect=AssertionError("recent source scan used")):
            self.assertIsNotNone(api._delete_controls(fx.package, operation, surface))
        candidate = next(item for item in api.generate(fx.package,
                             operation_id=operation.id)
                         if item.category == "MUTATION_AUTH")
        self.assertEqual(candidate.status, "READY", candidate.gaps)
        self.assertIn(candidate.test_object_id, {item.id for item in current})
        self.assertNotEqual(candidate.test_object_id, source.id)
        prepared = api.prepare_candidate(fx.package, candidate.id)
        self.assertEqual(prepared.status, "PLANNED", prepared.to_dict())
        plan = case.specialist.planner.store.get(prepared.plan_id, case.target)
        self.assertEqual(len(plan["request_templates"]), 8)
        self.assertEqual(len(fx.objects.requirements(prepared.plan_id, case.target)), 2)
        self.assertEqual(len(fx.server.received), before)
        if invalid_foreign:
            foreign_session = fx.browser.get_active_session(
                case.target, candidate.boundary_identity_id)
            self.assertIsNotNone(foreign_session)
            fx.browser.stop(foreign_session.id)
            with self.assertRaisesRegex(PlanRunError, "current prerequisites"):
                api.start_candidate(fx.package, candidate.id)
            self.assertEqual(len(fx.server.received), before)
            return
        detail = api.start_candidate(fx.package, candidate.id)
        for _ in range(24):
            if detail["run"]["status"] == "COMPLETED":
                break
            self.assertIn(detail["run"]["status"], {"CREATED", "READY"})
            detail = api.advance_candidate(fx.package, candidate.id)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 8 if secure else 7)
        self.assertEqual(detail["validation"]["result"]["status"],
                         (ValidationStatus.REJECTED if secure else
                          ValidationStatus.CONFIRMED).value)
        self.assertTrue(all(fx.objects.get(item.id, case.target).state is ObjectState.CLEANED
                            for item in current))

    def test_observed_disposable_delete_confirms_foreign_deletion(self):
        self._exercise(secure=False)

    def test_observed_disposable_delete_rejects_denied_boundary(self):
        self._exercise(secure=True)

    def test_observed_disposable_delete_invalid_actor_sends_no_requests(self):
        self._exercise(secure=False, invalid_foreign=True)


if __name__ == "__main__":
    unittest.main()
