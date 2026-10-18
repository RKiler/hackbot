"""Phase 20 mutation checks use only the local loopback fixture."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from importlib.resources import files
import json
import logging
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hackbot.authorization_store import Boundary
from hackbot.domain import TrafficSource
from hackbot.mutation_results import MutationResultStore, MutationStatus
from hackbot.object_recipes import ObjectRecipe
from hackbot.orchestrator import PlanOrchestrator, PlanRunError
from hackbot.plan_runs import PlanRunStore
from hackbot.policy_store import PolicyStore
from hackbot.policy_models import SideEffect
from hackbot.profile import SignalSource, SurfaceSignal, TargetProfile
from hackbot.service import create_app
from hackbot.skill_plans import TypedMutationPlanBinding
from hackbot.target_policy import PolicyDecision
from hackbot.typed_mutations import MutationPhase, MutationType, TypedMutation
from hackbot.validation_store import ValidationStatus, ValidationStore
from hackbot.validator import DeterministicValidatorEngine
from hackbot.traffic import CapturedRequest, CapturedResponse
from hackbot.test_objects import ObjectState
from tests import test_authorization
from tests.schema_utils import drop_phase28_schema


class AuthorizationMutationFixtureTests(unittest.TestCase):
    def setUp(self):
        self.case = test_authorization.AuthorizationSpecialistTests(
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
                 action: bool = False,
                 nested_graphql: bool = False,
                 boundary: Boundary = Boundary.CROSS_TENANT):
        case, fx = self.case, self.case.fx
        if action and graphql:
            raise ValueError("REST action and GraphQL mutation are distinct fixtures")
        role_boundary = boundary in {Boundary.VERTICAL, Boundary.HIDDEN_FUNCTION}
        owner, owner_session, tenant = case.actor(
            "tenant_a_admin", "tenant-a", role="admin" if role_boundary else None)
        foreign, foreign_session, foreign_tenant = case.actor(
            "tenant_a_member" if role_boundary else "tenant_b_admin",
            "tenant-a" if role_boundary else "tenant-b",
            role="member" if role_boundary else None)
        parent = None
        if nested_graphql:
            if not graphql or role_boundary:
                raise ValueError("nested GraphQL fixture needs a cross-tenant mutation")
            fx.recipe(recipe_id="parent_a", tenant="tenant-a", owner="tenant_a_admin")
            parent = fx.factory.resolve(
                package_id=fx.package.id, recipe_id="parent_a",
                identity_id=owner.id, tenant_id=tenant.id,
                session_id=owner_session.id, purpose="Nested mutation owner parent").item
            fx.recipe(recipe_id="parent_b", tenant="tenant-b", owner="tenant_b_admin")
            fx.factory.resolve(
                package_id=fx.package.id, recipe_id="parent_b",
                identity_id=foreign.id, tenant_id=foreign_tenant.id,
                session_id=foreign_session.id, purpose="Nested mutation foreign parent")
        recipe_id = "dashboard_a" if nested_graphql else "project_a"
        data = fx.recipe(recipe_id=recipe_id, tenant="tenant-a", owner="tenant_a_admin",
                         object_type="dashboard" if nested_graphql else "project",
                         parent_type="project" if nested_graphql else None)
        data["mutations"] = [{
            "type": "RENAME", "field": "name", "write": data["update"],
            "readback": data["verify"], "readback_pointer": "/name",
            "restore": data["update"], "side_effect": "SAFE_UPDATE",
            "identity_requirement": "VERIFIED_DISPOSABLE_OWNER_AND_BOUNDARY"}]
        if graphql:
            mutation_operation = {
                "method": "POST", "url": fx.base + "/fixture/graphql",
                "operation": "renameDashboard" if nested_graphql else "renameProject",
                "body": {
                    "query": ("mutation RenameDashboard($parentId:ID!,$id:ID!,$name:String!)"
                              "{renameDashboard(parentId:$parentId,id:$id,name:$name)"
                              "{id name parentId}}" if nested_graphql else
                              "mutation RenameProject($id:ID!,$name:String!)"
                              "{renameProject(id:$id,name:$name){id name owner tenant}}"),
                    "variables": ({"parentId": "$parent_id", "id": "$object_id",
                                   "name": "$test_name"} if nested_graphql else
                                  {"id": "$object_id", "name": "$test_name"}),
                    "operationName": "RenameDashboard" if nested_graphql else "RenameProject"}}
            data["mutations"][0]["write"] = mutation_operation
            data["mutations"][0]["restore"] = mutation_operation
        if action:
            action_operation = {
                "method": "POST", "url": data["verify"]["url"] + "/rename",
                "operation": "renameProject", "body": {"name": "$test_name"}}
            data["mutations"][0]["write"] = action_operation
            data["mutations"][0]["restore"] = action_operation
        if csrf:
            data["mutations"][0]["csrf_header"] = "X-CSRF-Token"
        path = fx.object_settings.recipe_root / fx.package.id / (recipe_id + ".json")
        path.write_text(json.dumps(data), encoding="utf-8")
        item = fx.factory.resolve(package_id=fx.package.id, recipe_id=recipe_id,
                                  identity_id=owner.id, tenant_id=tenant.id,
                                  session_id=owner_session.id,
                                  parent_id=parent.id if parent else None,
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
            if nested_graphql:
                child_external = case.specialist._external_id(item)
                parent_external = case.specialist._external_id(parent)
                fx.server.fixture_objects[child_external]["parentId"] = parent_external
                request = fx.traffic.store_request(
                    fx.package, CapturedRequest(
                        "POST", fx.base + "/fixture/graphql",
                        headers=(("Content-Type", "application/json"),),
                        body=json.dumps({"query": mutation_operation["body"]["query"],
                                         "variables": {"parentId": parent_external,
                                                       "id": child_external,
                                                       "name": "hackbot-test-observed"},
                                         "operationName": "RenameDashboard"}).encode(),
                        operation_id="GQL-" + "7" * 32),
                    source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
                    browser_manager=fx.browser, browser_session_id=owner_session.id,
                    auth_material_observed=True)
                fx.traffic.store_response(
                    request.id, CapturedResponse(
                        200, (("Content-Type", "application/json"),),
                        json.dumps({"data": {"renameDashboard": {
                            "id": child_external, "name": "hackbot-test-observed",
                            "parentId": parent_external}}}).encode()))
            else:
                case.graphql_owner_exchange(owner, owner_session, item, mutation=True,
                                            rename="hackbot-test-observed")
                fx.server.fixture_objects[case.specialist._external_id(item)]["name"] = item.test_name
        if action:
            external = case.specialist._external_id(item)
            observed_name = "hackbot-test-observed"
            request = fx.traffic.store_request(
                fx.package, CapturedRequest(
                    "POST", fx.base + "/fixture/tenant-a/projects/" + external + "/rename",
                    headers=(("Content-Type", "application/json"),),
                    body=json.dumps({"name": observed_name}).encode()),
                source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
                browser_manager=fx.browser, browser_session_id=owner_session.id,
                auth_material_observed=True)
            fx.traffic.store_response(request.id, CapturedResponse(
                200, (("Content-Type", "application/json"),),
                json.dumps({**fx.server.fixture_objects[external], "name": observed_name}).encode()))
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
                         ("POST" if graphql or action else "PATCH"))
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
        fx.server.fixture_nested_mutation_secure = secure and nested_graphql
        fx.server.fixture_csrf_required = csrf
        if token is not None:
            class FixtureTokenResolver:
                def resolve(self, action, header_name):
                    return token
            fx.executor.token_resolver = FixtureTokenResolver()
        return item, prepared, orchestrator, runs, mutations, foreign

    def _run(self, *, secure=False, noop=False, csrf=False, token=None,
             drop_patch=False, drop_recovery=False, graphql=False, action=False,
             graphql_boundary_noop=False, nested_graphql=False,
             boundary=Boundary.CROSS_TENANT,
             fail_restore=False, fail_readback=False):
        item, candidate, orchestrator, runs, mutations, foreign = self._fixture(
            secure=secure, noop=noop, csrf=csrf, token=token,
            graphql=graphql, action=action,
            graphql_boundary_noop=graphql_boundary_noop,
            nested_graphql=nested_graphql,
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

    def test_disposable_delete_schema_upgrade_preserves_real_rename_history(self):
        detail, _, _, mutations = self._run()
        self.assertEqual(detail["run"]["status"], "COMPLETED")
        original = mutations.list_for_run(detail["run"]["id"], self.case.target)
        self.assertEqual(len(original), 3)
        legacy = files("hackbot").joinpath(
            "migrations", "016_authorization_mutations.sql").read_text()
        with sqlite3.connect(self.case.fx.store.db_path) as connection:
            drop_phase28_schema(connection)
            columns = [row[1] for row in connection.execute(
                "PRAGMA table_info(authorization_mutation_results)")]
            rows = connection.execute("SELECT * FROM authorization_mutation_results").fetchall()
            connection.execute("DROP TABLE authorization_mutation_results")
            connection.executescript(legacy)
            connection.executemany(
                "INSERT INTO authorization_mutation_results (" + ",".join(columns) +
                ") VALUES (" + ",".join("?" for _ in columns) + ")", rows)
            connection.execute("PRAGMA user_version=31")
        self.case.fx.store.initialize(allow_existing_migration=True)
        restored = mutations.list_for_run(detail["run"]["id"], self.case.target)
        self.assertEqual([(entry.id, entry.status, entry.phase) for entry in restored],
                         [(entry.id, entry.status, entry.phase) for entry in original])

    def test_rest_post_action_uses_typed_readback_and_restore(self):
        detail, item, runs, mutations = self._run(action=True)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 7)
        self.assertTrue(all(entry.verified_effect for entry in
                            mutations.list_for_run(detail["run"]["id"], self.case.target)))
        self.assertEqual(self.case.fx.server.fixture_objects[
            self.case.specialist._external_id(item)]["name"], item.test_name)
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED, result.reason_codes)
        self.assertIsNotNone(finding)

    def test_secure_rest_post_action_is_rejected_after_readback(self):
        detail, item, runs, mutations = self._run(action=True, secure=True)
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

    def test_rest_post_action_recipe_rejects_unrelated_endpoint(self):
        fx = self.case.fx
        data = fx.recipe(recipe_id="action_guard", tenant="tenant-a",
                         owner="tenant_a_admin")
        action = {"method": "POST", "url": data["verify"]["url"] + "/send",
                  "operation": "renameProject", "body": {"name": "$test_name"}}
        data["mutations"] = [{
            "type": "RENAME", "field": "name", "write": action,
            "readback": data["verify"], "readback_pointer": "/name",
            "restore": action, "side_effect": "SAFE_UPDATE",
            "identity_requirement": "VERIFIED_DISPOSABLE_OWNER_AND_BOUNDARY"}]
        with self.assertRaisesRegex(ValueError, "safe read-back and reversal"):
            ObjectRecipe.from_json(data)

    def test_delete_recipe_requires_exact_verified_cleanup(self):
        fx = self.case.fx
        data = fx.recipe(recipe_id="delete_contract", tenant="tenant-a",
                         owner="tenant_a_admin")
        data["mutations"] = [{
            "type": "DELETE_DISPOSABLE", "field": "existence",
            "write": data["cleanup"], "readback": data["verify"],
            "readback_pointer": data["verify_id_pointer"],
            "restore": data["cleanup"], "side_effect": "SAFE_DELETE",
            "identity_requirement": "VERIFIED_DISPOSABLE_OWNER_AND_BOUNDARY"}]
        recipe = ObjectRecipe.from_json(data)
        self.assertEqual(recipe.mutations[0].mutation_type.value, "DELETE_DISPOSABLE")
        for change in ("wrong_cleanup", "wrong_pointer", "missing_cleanup"):
            with self.subTest(change=change):
                variant = json.loads(json.dumps(data))
                if change == "wrong_cleanup":
                    variant["mutations"][0]["write"]["url"] += "/other"
                    variant["mutations"][0]["restore"]["url"] += "/other"
                elif change == "wrong_pointer":
                    variant["mutations"][0]["readback_pointer"] = "/name"
                else:
                    variant.pop("cleanup")
                    variant["cleanup_strategy"] = "MANUAL_CLEANUP"
                with self.assertRaises(ValueError):
                    ObjectRecipe.from_json(variant)

    def test_delete_typed_value_cannot_claim_other_effects_or_fields(self):
        mutation = TypedMutation(
            "TARGET-" + "a" * 32, "deleteFixture", "TESTOBJ-" + "b" * 32,
            "project", "IDENTITY-" + "c" * 32,
            "IDENTITY-" + "d" * 32, "TENANT-" + "e" * 32,
            MutationType.DELETE_DISPOSABLE, "existence", "absent", "absent",
            "DELETE_AND_VERIFY", SideEffect.SAFE_DELETE, "f" * 64)
        self.assertEqual(mutation.expected_readback, "absent")
        for change in ({"field": "name"}, {"cleanup_strategy": "RESTORE"},
                       {"side_effect": SideEffect.SAFE_UPDATE},
                       {"value_label": "present", "expected_readback": "present"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(mutation, **change)

    def _run_delete(self, *, secure: bool = False, target_missing: bool = False,
                    invalid_foreign: bool = False):
        case, fx = self.case, self.case.fx
        fx.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, delete_disposable_objects=PolicyDecision.ALLOW))
        fx.targets.package = fx.package
        owner, owner_session, tenant = case.actor("tenant_a_admin", "tenant-a")
        foreign, foreign_session, _ = case.actor("tenant_b_admin", "tenant-b")
        data = fx.recipe(recipe_id="delete_a", tenant="tenant-a", owner="tenant_a_admin")
        data["mutations"] = [{
            "type": "DELETE_DISPOSABLE", "field": "existence",
            "write": data["cleanup"], "readback": data["verify"],
            "readback_pointer": data["verify_id_pointer"],
            "restore": data["cleanup"], "side_effect": "SAFE_DELETE",
            "identity_requirement": "VERIFIED_DISPOSABLE_OWNER_AND_BOUNDARY"}]
        path = fx.object_settings.recipe_root / fx.package.id / "delete_a.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        recipe = fx.catalog.get(fx.package.id, "delete_a")
        self.assertIsNotNone(recipe)
        control = fx.factory.resolve(
            package_id=fx.package.id, recipe_id=recipe.id,
            identity_id=owner.id, tenant_id=tenant.id,
            session_id=owner_session.id, purpose="Delete control fixture").item
        self.assertEqual(control.state, ObjectState.READY)
        target_plan = fx.objects.plan(
            target_id=case.target, package_id=fx.package.id,
            object_type=recipe.object_type, creator_identity_id=owner.id,
            tenant_id=tenant.id, recipe_id=recipe.id, recipe_hash=recipe.sha256,
            test_name="hackbot-test-delete-target", cleanup_strategy=recipe.cleanup_strategy)
        target = fx.factory.create(target_plan.id, case.target,
                                   session_id=owner_session.id).item
        self.assertEqual(target.state, ObjectState.READY)
        case.protect(target, tenant, policy="TENANT_ONLY")
        hunt = case.ledger.create_hunt(case.target, fx.package.id, candidate_limit=20)
        candidate = next(row for row in case.specialist.generate(hunt, fx.package)
                         if row.boundary is Boundary.CROSS_TENANT and
                         row.test_object_id == target.id and
                         fx.traffic.get_exchange(row.owner_exchange_id).request.record.method == "GET")
        surface = case.specialist.profile(fx.package)
        owned = next(item for item in surface.objects if item.id == target.id)
        operation = next(item for item in surface.operations
                         if item.exchange_id == candidate.owner_exchange_id)
        hypothesis = case.specialist._hypothesis(candidate, operation, owned)
        context = case.specialist.context.build(
            hypothesis, case.hypotheses.latest_profile(case.target), fx.package)
        plan = case.specialist.planner.bind_typed_mutation(
            fx.package, hypothesis, context, TypedMutationPlanBinding(
                target.id, target.object_type, target.external_id_hash,
                target.recipe_id, target.recipe_hash, "DELETE_DISPOSABLE", "DELETE",
                recipe.verify.operation, recipe.cleanup.operation,
                owner.id, owner_session.id, foreign.id, foreign_session.id,
                Boundary.CROSS_TENANT.value,
                delete_control_object_id=control.id,
                delete_control_ref_hash=control.external_id_hash))
        for item in (control, target):
            fx.objects.add_requirement(
                plan_id=str(plan["id"]), target_id=case.target,
                object_type=item.object_type, recipe_id=item.recipe_id,
                identity_id=item.creator_identity_id, tenant_id=item.tenant_id,
                parent_id=item.parent_id, test_object_id=item.id)
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
        if target_missing:
            del fx.server.fixture_objects[case.specialist._external_id(target)]
        if invalid_foreign:
            fx.browser.stop(foreign_session.id)
        self._delete_plan_start_requests = len(fx.server.received)
        if invalid_foreign:
            with self.assertRaisesRegex(PlanRunError, "current prerequisites"):
                orchestrator.start(str(plan["id"]), fx.package.id)
            return None, control, target, runs, mutations
        detail = orchestrator.start(str(plan["id"]), fx.package.id)
        for _ in range(24):
            if detail["run"]["status"] not in {"CREATED", "READY"}:
                break
            detail = orchestrator.advance(detail["run"]["id"], fx.package.id)
        return detail, control, target, runs, mutations

    def _assert_delete_result(self, secure: bool, expected: ValidationStatus):
        detail, control, target, runs, mutations = self._run_delete(secure=secure)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 8 if secure else 7)
        target_external = self.case.specialist._external_id(target)
        target_deletes = [entry for entry in
                          self.case.fx.server.received[self._delete_plan_start_requests:]
                          if entry[0] == "DELETE" and
                          entry[1].rstrip("/").endswith("/" + target_external)]
        self.assertEqual(len(target_deletes), 2 if secure else 1)
        self.assertNotIn(self.case.specialist._external_id(control),
                         self.case.fx.server.fixture_objects)
        self.assertNotIn(self.case.specialist._external_id(target),
                         self.case.fx.server.fixture_objects)
        self.assertEqual(self.case.fx.objects.get(control.id, self.case.target).state,
                         ObjectState.CLEANED)
        self.assertEqual(self.case.fx.objects.get(target.id, self.case.target).state,
                         ObjectState.CLEANED)
        self.assertTrue(mutations.for_phase(
            detail["run"]["id"], control.id, MutationPhase.OWNER_CONTROL).verified_effect)
        boundary = mutations.for_phase(detail["run"]["id"], target.id,
                                       MutationPhase.BOUNDARY)
        self.assertEqual(boundary.verified_effect, not secure)
        restore = mutations.for_phase(detail["run"]["id"], target.id,
                                      MutationPhase.RESTORE)
        self.assertEqual(restore is not None, secure)
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, expected, result.reason_codes)
        self.assertEqual(finding is not None, not secure)

    def test_disposable_delete_vulnerable_boundary_confirms(self):
        self._assert_delete_result(False, ValidationStatus.CONFIRMED)

    def test_disposable_delete_secure_boundary_rejects(self):
        self._assert_delete_result(True, ValidationStatus.REJECTED)

    def test_disposable_delete_absent_target_stops_before_boundary(self):
        detail, control, target, _, mutations = self._run_delete(target_missing=True)
        self.assertEqual(detail["run"]["status"], "BLOCKED", detail["run"])
        self.assertEqual(detail["run"]["stop_reason"], "TARGET_BASELINE_UNVERIFIED")
        self.assertEqual(detail["run"]["requests_consumed"], 4)
        self.assertIsNone(mutations.for_phase(detail["run"]["id"], target.id,
                                               MutationPhase.BOUNDARY))
        self.assertEqual(self.case.fx.objects.get(control.id, self.case.target).state,
                         ObjectState.CLEANED)

    def test_disposable_delete_invalid_foreign_session_sends_no_plan_requests(self):
        detail, _, _, _, _ = self._run_delete(invalid_foreign=True)
        self.assertIsNone(detail)
        self.assertEqual(len(self.case.fx.server.received), self._delete_plan_start_requests)

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

    def test_nested_graphql_mutation_reuses_readback_and_restore(self):
        detail, item, runs, mutations = self._run(graphql=True, nested_graphql=True)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        self.assertEqual(detail["run"]["requests_consumed"], 7)
        self.assertEqual(self.case.fx.server.fixture_objects[
            self.case.specialist._external_id(item)]["name"], item.test_name)
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED, result.reason_codes)
        self.assertIsNotNone(finding)
        self.assertEqual(len(mutations.list_for_run(detail["run"]["id"], self.case.target)), 3)

    def test_nested_graphql_mutation_foreign_child_is_denied(self):
        detail, _, runs, _, = self._run(graphql=True, nested_graphql=True, secure=True)
        self.assertEqual(detail["run"]["status"], "COMPLETED", detail["run"])
        validator = DeterministicValidatorEngine(
            runs=runs, traffic=self.case.fx.traffic, evidence=self.case.fx.store,
            identities=self.case.fx.registry, hypotheses=self.case.hypotheses,
            results=ValidationStore(self.case.fx.store))
        result, finding = validator.validate_run(detail["run"]["id"], self.case.target)
        self.assertEqual(result.status, ValidationStatus.REJECTED, result.reason_codes)
        self.assertIsNone(finding)
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
        self.case = test_authorization.AuthorizationSpecialistTests(
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
        self.case = test_authorization.AuthorizationSpecialistTests(
            methodName="test_cross_tenant_candidate_uses_verified_object_and_owner_traffic")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        fx = self.case.fx
        fx.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, bounded_active=PolicyDecision.ALLOW,
            cross_identity_testing=PolicyDecision.ALLOW))
        fx.targets.package = fx.package

    def _prepare(self, *, vulnerable: bool):
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
        return prepared, orchestrator, runs

    def _run(self, *, vulnerable: bool):
        prepared, orchestrator, runs = self._prepare(vulnerable=vulnerable)
        fx = self.case.fx
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
