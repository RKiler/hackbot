"""Phase 20 mutation checks use only the local loopback fixture."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
import logging
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hackbot.authorization_store import Boundary
from hackbot.domain import TrafficSource
from hackbot.mutation_results import MutationResultStore, MutationStatus
from hackbot.orchestrator import PlanOrchestrator, PlanRunError
from hackbot.plan_runs import PlanRunStore
from hackbot.policy_store import PolicyStore
from hackbot.profile import SignalSource, SurfaceSignal, TargetProfile
from hackbot.service import create_app
from hackbot.target_policy import PolicyDecision
from hackbot.typed_mutations import MutationPhase
from hackbot.validation_store import ValidationStatus, ValidationStore
from hackbot.validator import DeterministicValidatorEngine
from hackbot.traffic import CapturedRequest, CapturedResponse
from tests.test_authorization import AuthorizationSpecialistTests as _AuthorizationFixture


class AuthorizationMutationFixtureTests(unittest.TestCase):
    def setUp(self):
        self.case = _AuthorizationFixture(
            methodName="test_cross_tenant_candidate_uses_verified_object_and_owner_traffic")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.case.specialist.factory = self.case.fx.factory
        fx = self.case.fx
        fx.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            state_changing=PolicyDecision.ALLOW,
            modify_disposable_objects=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        fx.targets.package = fx.package

    def _fixture(self, *, secure: bool = False, noop: bool = False,
                 csrf: bool = False, token: str | None = None,
                 graphql: bool = False, graphql_boundary_noop: bool = False,
                 boundary: Boundary = Boundary.CROSS_TENANT):
        case, fx = self.case, self.case.fx
        role_boundary = boundary in {Boundary.VERTICAL, Boundary.HIDDEN_FUNCTION}
        owner, owner_session, tenant = case.actor(
            "tenant_a_admin", "tenant-a", role="admin" if role_boundary else None)
        foreign, _, _ = case.actor(
            "tenant_a_member" if role_boundary else "tenant_b_admin",
            "tenant-a" if role_boundary else "tenant-b",
            role="member" if role_boundary else None)
        data = fx.recipe(recipe_id="project_a", tenant="tenant-a", owner="tenant_a_admin")
        data["mutations"] = [{
            "type": "RENAME", "field": "name", "write": data["update"],
            "readback": data["verify"], "readback_pointer": "/name",
            "restore": data["update"], "side_effect": "SAFE_UPDATE",
            "identity_requirement": "VERIFIED_DISPOSABLE_OWNER_AND_BOUNDARY"}]
        if graphql:
            mutation_operation = {
                "method": "POST", "url": fx.base + "/fixture/graphql",
                "operation": "renameProject",
                "body": {
                    "query": "mutation RenameProject($id:ID!,$name:String!)"
                             "{renameProject(id:$id,name:$name){id name owner tenant}}",
                    "variables": {"id": "$object_id", "name": "$test_name"},
                    "operationName": "RenameProject"}}
            data["mutations"][0]["write"] = mutation_operation
            data["mutations"][0]["restore"] = mutation_operation
        if csrf:
            data["mutations"][0]["csrf_header"] = "X-CSRF-Token"
        path = fx.object_settings.recipe_root / fx.package.id / "project_a.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        item = fx.factory.resolve(package_id=fx.package.id, recipe_id="project_a",
                                  identity_id=owner.id, tenant_id=tenant.id,
                                  session_id=owner_session.id,
                                  purpose="Typed mutation fixture").item
        self.assertEqual(item.state.value, "READY")
        case.protect(item, tenant,
                     policy="ROLE_RESTRICTED" if role_boundary else "TENANT_ONLY",
                     role_id=case.roles["admin"].id if role_boundary else None)
        updated = fx.factory.update_name(item.id, item.target_id,
                                         session_id=owner_session.id)
        self.assertEqual(updated.outcome, "READY")
        item = updated.item
        if graphql:
            case.graphql_owner_exchange(owner, owner_session, item, mutation=True,
                                        rename="hackbot-test-observed")
            fx.server.fixture_objects[case.specialist._external_id(item)]["name"] = item.test_name
        if boundary is Boundary.HIDDEN_FUNCTION:
            observed = next(op for op in case.specialist.profile(fx.package).operations
                            if op.object_id == item.id and op.method == "PATCH")
            case.hypotheses.save_profile(TargetProfile(
                case.target, fx.package.id, "localhost", "TRACKED",
                datetime.now(timezone.utc), None, "NOT_CONFIGURED", (), (), (), (), (), (),
                0, False, False, 0,
                (SurfaceSignal("SURFACE_INTERNAL", SignalSource.JS_ANALYSIS,
                               observed.display_path, observed.origin + observed.display_path,
                               "fixture_js", observed.exchange_id, method=observed.method),),
                {}, ()))
        hunt = case.ledger.create_hunt(case.target, fx.package.id, candidate_limit=20)
        candidate = next(row for row in case.specialist.generate(hunt, fx.package)
                         if row.boundary is (Boundary.GRAPHQL_MUTATION if graphql else
                                             boundary) and
                         row.test_object_id == item.id and
                         fx.traffic.get_exchange(row.owner_exchange_id).request.record.method ==
                         ("POST" if graphql else "PATCH"))
        prepared = case.specialist.prepare(candidate.id, fx.package)
        self.assertEqual(prepared.status, "PLANNED")
        runs = PlanRunStore(fx.store)
        mutations = MutationResultStore(fx.store)
        orchestrator = PlanOrchestrator(
            runs=runs, targets=fx.targets, hypotheses=case.hypotheses,
            context=case.specialist.context, checker=case.specialist.planner.checker,
            registry=case.specialist.planner.registry, policy=fx.policy,
            approvals=PolicyStore(fx.store), executor=fx.executor,
            traffic=fx.traffic, evidence=fx.store, objects=fx.objects,
            recipes=fx.catalog, mutations=mutations)
        fx.server.fixture_secure = secure
        fx.server.fixture_noop_mutation = noop
        fx.server.fixture_graphql_boundary_noop = graphql_boundary_noop
        fx.server.fixture_csrf_required = csrf
        if token is not None:
            class FixtureTokenResolver:
                def resolve(self, action, header_name):
                    return token
            fx.executor.token_resolver = FixtureTokenResolver()
        return item, prepared, orchestrator, runs, mutations, foreign

    def _run(self, *, secure=False, noop=False, csrf=False, token=None,
             drop_patch=False, drop_recovery=False, graphql=False,
             graphql_boundary_noop=False, boundary=Boundary.CROSS_TENANT,
             fail_restore=False, fail_readback=False):
        item, candidate, orchestrator, runs, mutations, foreign = self._fixture(
            secure=secure, noop=noop, csrf=csrf, token=token,
            graphql=graphql, graphql_boundary_noop=graphql_boundary_noop,
            boundary=boundary)
        fx = self.case.fx
        fx.server.fixture_drop_patch_response = drop_patch
        fx.server.fixture_drop_recovery_get = drop_recovery
        fx.server.fixture_fail_restore = fail_restore
        fx.server.fixture_fail_mutation_readback = fail_readback
        fx.server.fixture_restore_value = item.test_name if fail_restore else None
        detail = orchestrator.start(candidate.plan_id, fx.package.id)
        for _ in range(24):
            status = detail["run"]["status"]
            if status == "COMPLETED" or status not in {"CREATED", "READY"}:
                break
            detail = orchestrator.advance(detail["run"]["id"], fx.package.id)
        return detail, item, runs, mutations

    def test_vulnerable_cross_tenant_restores_after_independent_readback(self):
        detail, item, runs, mutations = self._run()
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 7)
        entries = mutations.list_for_run(detail["run"]["id"], self.case.target)
        self.assertEqual([entry.phase for entry in entries],
                         list(MutationPhase))
        self.assertTrue(all(entry.verified_effect for entry in entries))
        self.assertEqual(self.case.fx.server.fixture_objects[
            self.case.specialist._external_id(item)]["name"], item.test_name)
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED, result.reason_codes)
        self.assertIsNotNone(finding)

    def test_secure_cross_tenant_is_rejected(self):
        detail, item, runs, mutations = self._run(secure=True)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        boundary = mutations.for_phase(detail["run"]["id"], item.id,
                                       MutationPhase.BOUNDARY)
        self.assertEqual(boundary.status, MutationStatus.DENIED)
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.REJECTED, result.reason_codes)
        self.assertIsNone(finding)


    def test_noop_owner_control_stops_before_foreign_request(self):
        detail, item, runs, mutations = self._run(noop=True)
        self.assertEqual(detail["run"]["status"], "BLOCKED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 3)
        self.assertIsNone(mutations.for_phase(detail["run"]["id"], item.id,
                                               MutationPhase.BOUNDARY))

    def test_trusted_csrf_resolver_and_token_secrecy(self):
        detail, item, runs, mutations = self._run(
            csrf=True, token="fixture-csrf-secret-token")
        self.assertEqual(detail["run"]["status"], "COMPLETED")
        self.assertEqual(detail["run"]["requests_consumed"], 7)
        self.assertNotIn("fixture-csrf-secret-token", json.dumps(detail))
        snapshot = runs.snapshot(detail["run"]["plan_id"], self.case.target)
        self.assertNotIn("fixture-csrf-secret-token", json.dumps(snapshot.data))
        for exchange in self.case.fx.traffic.find_recent(self.case.target, limit=50).items:
            self.assertNotIn("fixture-csrf-secret-token", str(exchange))
        with self.case.fx.store._connection() as db:
            rows = db.execute("SELECT evidence_id,metadata_json,inline_content FROM evidence "
                              "WHERE target_ref=?", (self.case.target,)).fetchall()
        for row in rows:
            self.assertNotIn("fixture-csrf-secret-token", row["metadata_json"])
            if row["inline_content"] is not None:
                self.assertNotIn(b"fixture-csrf-secret-token", row["inline_content"])

    def test_missing_csrf_resolver_blocks_before_mutation(self):
        detail, item, runs, mutations = self._run(csrf=True)
        self.assertEqual(detail["run"]["status"], "BLOCKED")
        self.assertEqual(detail["run"]["requests_consumed"], 1)
        self.assertIsNone(mutations.for_phase(detail["run"]["id"], item.id,
                                               MutationPhase.OWNER_CONTROL))

    def test_non_disposable_object_stops_before_any_plan_request(self):
        item, candidate, orchestrator, runs, mutations, foreign = self._fixture()
        with self.case.fx.store._connection() as db:
            db.execute("UPDATE test_objects SET disposable=0 WHERE test_object_id=?", (item.id,))
        before = len(self.case.fx.server.received)
        with self.assertRaises(PlanRunError):
            orchestrator.start(candidate.plan_id, self.case.fx.package.id)
        self.assertEqual(len(self.case.fx.server.received), before)

    def test_stale_csrf_token_blocks_owner_control(self):
        detail, item, runs, mutations = self._run(csrf=True, token="stale-fixture-token")
        self.assertEqual(detail["run"]["status"], "BLOCKED")
        self.assertEqual(detail["run"]["requests_consumed"], 2)
        self.assertIsNone(mutations.for_phase(detail["run"]["id"], item.id,
                                               MutationPhase.BOUNDARY))

    def test_lost_write_response_uses_one_owner_read_and_never_retries_write(self):
        detail, item, runs, mutations = self._run(drop_patch=True)
        self.assertEqual(detail["run"]["status"], "WAITING_HUMAN")
        self.assertEqual(detail["run"]["requests_consumed"], 3)
        control = mutations.for_phase(detail["run"]["id"], item.id,
                                      MutationPhase.OWNER_CONTROL)
        self.assertTrue(control.verified_effect)
        external = self.case.specialist._external_id(item)
        self.assertEqual(sum(method == "PATCH" and external in path for method, path, _
                             in self.case.fx.server.received[-3:]), 1)

    def test_lost_write_and_readback_require_manual_review(self):
        detail, item, runs, mutations = self._run(drop_patch=True, drop_recovery=True)
        self.assertEqual(detail["run"]["status"], "WAITING_HUMAN")
        self.assertEqual(detail["run"]["requests_consumed"], 3)
        control = mutations.for_phase(detail["run"]["id"], item.id,
                                      MutationPhase.OWNER_CONTROL)
        self.assertEqual(control.status, MutationStatus.AMBIGUOUS)

    def test_crash_after_write_dispatch_marks_mutation_ambiguous_without_replay(self):
        item, candidate, orchestrator, runs, mutations, _ = self._fixture()
        fx = self.case.fx
        detail = orchestrator.start(candidate.plan_id, fx.package.id)
        for _ in range(4):
            if detail["run"]["requests_consumed"] == 1:
                break
            detail = orchestrator.advance(detail["run"]["id"], fx.package.id)
        self.assertEqual(detail["run"]["requests_consumed"], 1)
        original = fx.executor.execute

        def sent_then_lost(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("simulated process loss after mutation dispatch")

        before = len(fx.server.received)
        with patch.object(fx.executor, "execute", side_effect=sent_then_lost):
            recovered = orchestrator.advance(detail["run"]["id"], fx.package.id)
        self.assertEqual(recovered["run"]["status"], "WAITING_HUMAN")
        self.assertEqual(len(fx.server.received), before + 1)
        control = mutations.for_phase(recovered["run"]["id"], item.id,
                                      MutationPhase.OWNER_CONTROL)
        self.assertEqual(control.status, MutationStatus.AMBIGUOUS)
        self.assertEqual(mutations.reconcile(), 0)
        with self.assertRaises(PlanRunError):
            orchestrator.advance(recovered["run"]["id"], fx.package.id)
        self.assertEqual(len(fx.server.received), before + 1)

    def test_graphql_foreign_rename_requires_readback_and_restores(self):
        detail, item, runs, mutations = self._run(graphql=True)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 7)
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED, result.reason_codes)
        self.assertIsNotNone(finding)

    def test_graphql_200_noop_is_not_a_finding(self):
        detail, item, runs, mutations = self._run(graphql=True, graphql_boundary_noop=True)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        boundary = mutations.for_phase(detail["run"]["id"], item.id,
                                       MutationPhase.BOUNDARY)
        self.assertEqual(boundary.status, MutationStatus.DENIED)
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.REJECTED, result.reason_codes)
        self.assertIsNone(finding)

    def test_lower_role_mutation_is_verified_and_restored(self):
        detail, item, runs, mutations = self._run(boundary=Boundary.VERTICAL)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED, result.reason_codes)
        self.assertIsNotNone(finding)

    def test_hidden_privileged_mutation_is_verified_and_restored(self):
        detail, item, runs, mutations = self._run(boundary=Boundary.HIDDEN_FUNCTION)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED, result.reason_codes)
        self.assertIsNotNone(finding)

    def test_restore_failure_remains_visible_and_unconfirmed(self):
        detail, item, runs, mutations = self._run(fail_restore=True)
        self.assertEqual(detail["run"]["status"], "WAITING_HUMAN", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 7)
        restoration = mutations.for_phase(detail["run"]["id"], item.id,
                                          MutationPhase.RESTORE)
        self.assertIsNotNone(restoration)
        self.assertFalse(restoration.verified_effect)
        self.assertGreaterEqual(mutations.stats(self.case.target)["restore_failures"], 1)

    def test_owner_readback_outage_stops_before_boundary(self):
        detail, item, runs, mutations = self._run(fail_readback=True)
        self.assertEqual(detail["run"]["status"], "BLOCKED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 3)
        owner = mutations.for_phase(detail["run"]["id"], item.id,
                                    MutationPhase.OWNER_CONTROL)
        self.assertEqual(owner.status, MutationStatus.INSUFFICIENT_EVIDENCE)
        self.assertIsNone(mutations.for_phase(detail["run"]["id"], item.id,
                                               MutationPhase.BOUNDARY))

    def test_private_api_exposes_only_redacted_mutation_metadata(self):
        detail, item, runs, mutations = self._run()
        fx = self.case.fx
        runtime = SimpleNamespace(
            package=lambda name: fx.package if name == fx.package.id else None,
            orchestrator=SimpleNamespace(detail=lambda run_id, package_id:
                                         runs.details(runs.get(run_id, fx.package.target.id))),
            validations=ValidationStore(fx.store), run_store=runs,
            mutation_results=mutations, objects=fx.objects, object_factory=fx.factory,
            logger=logging.getLogger("fixture-api"))
        client = create_app(runtime=runtime).test_client()
        run_id = detail["run"]["id"]
        run_response = client.get(f"/v1/runs/{run_id}?target={fx.package.id}")
        self.assertEqual(run_response.status_code, 200, run_response.get_data(as_text=True))
        body = run_response.get_json()
        self.assertEqual(body["mutation_approval"]["field"], "name")
        self.assertTrue(body["mutation_approval"]["disposable"])
        self.assertEqual(body["mutation_cleanup_status"], "RESTORED")
        self.assertEqual(len(body["mutation_results"]), 3)
        self.assertNotIn("hackbot-test-", json.dumps(body["mutation_approval"]))
        object_response = client.get(f"/v1/objects/{item.id}?target={fx.package.id}")
        self.assertEqual(object_response.status_code, 200,
                         object_response.get_data(as_text=True))
        self.assertEqual(object_response.get_json()["mutation_state"], "RESTORED")
        self.assertIsNotNone(object_response.get_json()["latest_readback"])
        self.assertEqual(client.post(f"/v1/objects/{item.id}/mutate",
                                     json={"field": "name"}).status_code, 404)


class AuthorizationNestedFixtureTests(unittest.TestCase):
    def setUp(self):
        self.case = _AuthorizationFixture(
            methodName="test_cross_tenant_candidate_uses_verified_object_and_owner_traffic")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        fx = self.case.fx
        fx.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        fx.targets.package = fx.package

    def _run(self, *, vulnerable: bool):
        case, fx = self.case, self.case.fx
        owner, owner_session, tenant = case.actor("tenant_a_admin", "tenant-a")
        foreign, foreign_session, foreign_tenant = case.actor("tenant_b_admin", "tenant-b")
        fx.recipe(recipe_id="parent_a", tenant="tenant-a", owner="tenant_a_admin")
        parent = fx.factory.resolve(package_id=fx.package.id, recipe_id="parent_a",
                                    identity_id=owner.id, tenant_id=tenant.id,
                                    session_id=owner_session.id,
                                    purpose="Nested owner parent").item
        fx.recipe(recipe_id="child_a", tenant="tenant-a", owner="tenant_a_admin",
                  object_type="dashboard", parent_type="project")
        child = fx.factory.resolve(package_id=fx.package.id, recipe_id="child_a",
                                   identity_id=owner.id, tenant_id=tenant.id,
                                   session_id=owner_session.id, parent_id=parent.id,
                                   purpose="Nested owner child").item
        fx.recipe(recipe_id="parent_b", tenant="tenant-b", owner="tenant_b_admin")
        foreign_parent = fx.factory.resolve(package_id=fx.package.id, recipe_id="parent_b",
                                            identity_id=foreign.id, tenant_id=foreign_tenant.id,
                                            session_id=foreign_session.id,
                                            purpose="Nested foreign parent").item
        parent_id = case.specialist._external_id(parent)
        child_id = case.specialist._external_id(child)
        fx.server.fixture_objects[child_id]["parentId"] = parent_id
        case.protect(child, tenant, policy="TENANT_ONLY")
        body = {"id": child_id, "parentId": parent_id,
                "owner": "tenant_a_admin", "tenant": "tenant-a"}
        request = CapturedRequest(
            "GET", fx.base + "/fixture/tenant-a/projects/" + parent_id +
            "/dashboards/" + child_id)
        exchange = fx.traffic.store_request(
            fx.package, request, source=TrafficSource.FIXTURE,
            capture_provider="FIXTURE", browser_manager=fx.browser,
            browser_session_id=owner_session.id, auth_material_observed=True)
        fx.traffic.store_response(
            exchange.id, CapturedResponse(200, (("Content-Type", "application/json"),),
                                          json.dumps(body).encode()))
        hunt = case.ledger.create_hunt(case.target, fx.package.id, candidate_limit=20)
        candidate = next(row for row in case.specialist.generate(hunt, fx.package)
                         if row.boundary is Boundary.PARENT_CHILD and
                         row.test_object_id == child.id)
        prepared = case.specialist.prepare(candidate.id, fx.package)
        self.assertEqual(prepared.status, "PLANNED")
        runs = PlanRunStore(fx.store)
        orchestrator = PlanOrchestrator(
            runs=runs, targets=fx.targets, hypotheses=case.hypotheses,
            context=case.specialist.context, checker=case.specialist.planner.checker,
            registry=case.specialist.planner.registry, policy=fx.policy,
            approvals=PolicyStore(fx.store), executor=fx.executor,
            traffic=fx.traffic, evidence=fx.store, objects=fx.objects)
        fx.server.fixture_nested_vulnerable = vulnerable
        detail = orchestrator.start(prepared.plan_id, fx.package.id)
        for _ in range(16):
            if detail["run"]["status"] not in {"CREATED", "READY"}:
                break
            detail = orchestrator.advance(detail["run"]["id"], fx.package.id)
        return detail, runs

    def test_foreign_parent_exposes_protected_child(self):
        detail, runs = self._run(vulnerable=True)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 4)
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED, result.reason_codes)
        self.assertIsNotNone(finding)

    def test_redundant_parent_but_child_authorization_is_secure(self):
        detail, runs = self._run(vulnerable=False)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.REJECTED, result.reason_codes)
        self.assertIsNone(finding)


class AuthorizationBatchFixtureTests(unittest.TestCase):
    def setUp(self):
        self.case = _AuthorizationFixture(
            methodName="test_cross_tenant_candidate_uses_verified_object_and_owner_traffic")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        fx = self.case.fx
        fx.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        fx.targets.package = fx.package

    def _run(self, *, vulnerable: bool):
        case, fx = self.case, self.case.fx
        owner, owner_session, tenant_b = case.actor("tenant_b_admin", "tenant-b")
        actor, actor_session, tenant_a = case.actor("tenant_a_admin", "tenant-a")
        fx.recipe(recipe_id="batch_b1", tenant="tenant-b", owner="tenant_b_admin")
        first = fx.factory.resolve(package_id=fx.package.id, recipe_id="batch_b1",
                                   identity_id=owner.id, tenant_id=tenant_b.id,
                                   session_id=owner_session.id, purpose="Batch owner first").item
        fx.recipe(recipe_id="batch_b2", tenant="tenant-b", owner="tenant_b_admin")
        second = fx.factory.resolve(package_id=fx.package.id, recipe_id="batch_b2",
                                    identity_id=owner.id, tenant_id=tenant_b.id,
                                    session_id=owner_session.id, purpose="Batch owner second").item
        fx.recipe(recipe_id="batch_a1", tenant="tenant-a", owner="tenant_a_admin")
        owned = fx.factory.resolve(package_id=fx.package.id, recipe_id="batch_a1",
                                   identity_id=actor.id, tenant_id=tenant_a.id,
                                   session_id=actor_session.id, purpose="Batch actor control").item
        case.protect(first, tenant_b, policy="TENANT_ONLY")
        first_id = case.specialist._external_id(first)
        second_id = case.specialist._external_id(second)
        request = CapturedRequest(
            "GET", fx.base + "/fixture/tenant-b/projects/batch/" +
            first_id + "," + second_id)
        exchange = fx.traffic.store_request(
            fx.package, request, source=TrafficSource.FIXTURE,
            capture_provider="FIXTURE", browser_manager=fx.browser,
            browser_session_id=owner_session.id, auth_material_observed=True)
        fx.traffic.store_response(
            exchange.id, CapturedResponse(200, (("Content-Type", "application/json"),),
                                          json.dumps({"items": [
                                              fx.server.fixture_objects[first_id],
                                              fx.server.fixture_objects[second_id]]}).encode()))
        hunt = case.ledger.create_hunt(case.target, fx.package.id, candidate_limit=20)
        candidate = next(row for row in case.specialist.generate(hunt, fx.package)
                         if "BATCH_READ_EXACT_OBSERVED" in row.reasons and
                         row.test_object_id == first.id)
        prepared = case.specialist.prepare(candidate.id, fx.package)
        self.assertEqual(prepared.status, "PLANNED")
        runs = PlanRunStore(fx.store)
        orchestrator = PlanOrchestrator(
            runs=runs, targets=fx.targets, hypotheses=case.hypotheses,
            context=case.specialist.context, checker=case.specialist.planner.checker,
            registry=case.specialist.planner.registry, policy=fx.policy,
            approvals=PolicyStore(fx.store), executor=fx.executor,
            traffic=fx.traffic, evidence=fx.store, objects=fx.objects)
        fx.server.fixture_batch_vulnerable = vulnerable
        detail = orchestrator.start(prepared.plan_id, fx.package.id)
        for _ in range(16):
            if detail["run"]["status"] not in {"CREATED", "READY"}:
                break
            detail = orchestrator.advance(detail["run"]["id"], fx.package.id)
        return detail, runs

    def test_mixed_batch_discloses_foreign_object(self):
        detail, runs = self._run(vulnerable=True)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 4)
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED, result.reason_codes)
        self.assertIsNotNone(finding)

    def test_mixed_batch_filters_foreign_object(self):
        detail, runs = self._run(vulnerable=False)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.REJECTED, result.reason_codes)
        self.assertIsNone(finding)


if __name__ == "__main__":
    unittest.main()
