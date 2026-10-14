from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from hackbot.config import ObjectSettings
from hackbot.domain import Tenant
from hackbot.identity import MembershipStatus
from hackbot.object_factory import ObjectFactory
from hackbot.object_recipes import ObjectRecipe, RecipeCatalog
from hackbot.policy_models import ActionCategory, ActorMode, ProposedAction, SideEffect
from hackbot.planner_models import (CandidateStatus, PlannerCandidate, PlannerLimits,
                                    PlannerMode, PlannerStatus, PlannerTaskType, Specialist)
from hackbot.planner_runner import PlannerRunner
from hackbot.planner_store import PlannerStore
from hackbot.policy import policy_version
from hackbot.target_policy import PolicyDecision
from hackbot.test_objects import CleanupStrategy, ObjectRegistry, ObjectState

from .test_executor import ExecutorTests


class ObjectFactoryTests(ExecutorTests):
    def setUp(self):
        super().setUp()
        if self._testMethodName in ObjectFactoryTests.__dict__:
            self.executor.settings = replace(self.executor.settings, connect_timeout_seconds=1,
                                             read_timeout_seconds=1, overall_timeout_seconds=5)
        self.package = replace(self.package, autonomy=replace(
            self.package.autonomy, state_changing=PolicyDecision.ALLOW,
            create_disposable_objects=PolicyDecision.ALLOW,
            modify_disposable_objects=PolicyDecision.ALLOW,
            delete_disposable_objects=PolicyDecision.ALLOW,
            safe_read=PolicyDecision.ALLOW))
        self.targets.package = self.package
        self.objects = ObjectRegistry(self.store)
        self.policy.owned_object = self.objects.owned_for_action
        self.object_settings = ObjectSettings(self.root / "recipes")
        self.catalog = RecipeCatalog(self.object_settings)
        self.factory = ObjectFactory(objects=self.objects, recipes=self.catalog,
                                     policy=self.policy, executor=self.executor,
                                     targets=self.targets, traffic=self.traffic,
                                     settings=self.object_settings)

    def account(self, alias, tenant_label):
        identity, session = self.owned_session(alias)
        tenant = self.registry.register_tenant(Tenant(target_id=self.package.target.id,
                                                      label=tenant_label, kind="organization"))
        self.registry.add_membership(identity.id, tenant.id, status=MembershipStatus.ACTIVE,
                                     is_primary=True)
        return identity, session, tenant

    def recipe(self, *, recipe_id="project", tenant="tenant-a", owner="tenant_a_admin",
               object_type="project", parent_type=None, create_operation="createProject",
               cleanup_operation="deleteProject", cleanup=True, ambiguous_create=False):
        path = self.object_settings.recipe_root / self.package.id / (recipe_id + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        plural = object_type + "s"
        payload = {
            "id": recipe_id, "target_id": self.package.target.id, "package_id": self.package.id,
            "object_type": object_type, "protocol": "REST", "source": "manual_fixture",
            "expected_owner": owner, "expected_tenant": tenant,
            "create": {"method": "POST", "url": f"{self.base}/fixture/{tenant}/" +
                       ("projects-ambiguous" if ambiguous_create else plural),
                       "operation": create_operation, "body": {"name": "$test_name"}},
            "verify": {"method": "GET", "url": f"{self.base}/fixture/{tenant}/{plural}/{{object_id}}",
                       "operation": "readFixture"},
            "update": {"method": "PATCH", "url": f"{self.base}/fixture/{tenant}/{plural}/{{object_id}}",
                       "operation": "renameFixture", "body": {"name": "$test_name"}},
            "id_pointer": "/id", "verify_id_pointer": "/id", "verify_name_pointer": "/name",
            "verify_owner_pointer": "/owner", "verify_tenant_pointer": "/tenant",
            "cleanup_strategy": "AUTO_CLEANUP" if cleanup else "MANUAL_CLEANUP",
        }
        if cleanup:
            payload["cleanup"] = {"method": "DELETE",
                                  "url": f"{self.base}/fixture/{tenant}/{plural}/{{object_id}}",
                                  "operation": cleanup_operation}
        if parent_type:
            payload["parent_type"] = parent_type
        path.write_text(json.dumps(payload), encoding="utf-8")
        return payload

    def run_fixture(self, *, with_run=True):
        plan_id = "PLAN-" + uuid.uuid4().hex
        hyp = "HYP-" + uuid.uuid4().hex
        stamp = datetime.now(timezone.utc).isoformat()
        with self.store._connection() as db:
            db.execute("INSERT INTO skill_plans VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (plan_id, self.package.target.id, hyp, "fixture", "1", "a" * 64,
                        0, 1, "READY_FOR_MANUAL_REVIEW", stamp, "{}"))
        return plan_id, self.create_fixture_run(plan_id, hyp) if with_run else None

    def create_fixture_run(self, plan_id, hyp=None):
        run_id = "RUN-" + uuid.uuid4().hex
        stamp = datetime.now(timezone.utc).isoformat()
        if hyp is None:
            with self.store._connection() as db:
                hyp = db.execute("SELECT hypothesis_id FROM skill_plans WHERE plan_id=?",
                                 (plan_id,)).fetchone()[0]
        with self.store._connection() as db:
            db.execute("INSERT INTO plan_runs(run_id,plan_id,target_id,package_id,hypothesis_id,"
                       "skill_id,skill_version,skill_hash,snapshot_hash,status,request_budget,"
                       "token_budget,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (run_id, plan_id, self.package.target.id, self.package.id, hyp,
                        "fixture", "1", "a" * 64, "b" * 64, "CREATED", 5, 0, stamp, stamp))
        return run_id

    def test_create_verify_facts_cleanup_and_no_repeat(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        self.recipe()
        result = self.factory.resolve(package_id=self.package.id, recipe_id="project",
                                      identity_id=identity.id, tenant_id=tenant.id,
                                      session_id=session.id, purpose="Local fixture")
        self.assertEqual(result.outcome, "READY")
        item = result.item
        self.assertEqual(item.state, ObjectState.READY)
        self.assertEqual(len(self.server.fixture_objects), 1)
        self.assertEqual(self.objects.stats(item.target_id)["cleanup_pending"], 1)
        changed = self.factory.update_name(item.id, item.target_id, session_id=session.id)
        self.assertEqual(changed.outcome, "READY")
        self.assertNotEqual(changed.item.test_name, item.test_name)
        self.assertNotIn("fixture1", json.dumps(item.to_dict()))
        for predicate in ("created_by", "resource_tenant", "disposable"):
            with self.store._connection() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM facts WHERE subject=? AND predicate=?",
                                            (item.id, predicate)).fetchone()[0], 1)
        again = self.factory.resolve(package_id=self.package.id, recipe_id="project",
                                     identity_id=identity.id, tenant_id=tenant.id,
                                     session_id=session.id, purpose="Local fixture")
        self.assertEqual(again.item.id, item.id)
        self.assertEqual(len(self.server.fixture_objects), 1)
        cleaned = self.factory.cleanup(item.id, item.target_id, session_id=session.id)
        self.assertEqual(cleaned.outcome, "CLEANED")
        self.assertEqual(self.server.fixture_objects, {})
        self.assertEqual(self.objects.stats(item.target_id)["cleanup_pending"], 0)
        self.assertEqual(self.factory.cleanup(item.id, item.target_id,
                                               session_id=session.id).outcome, "NOT_CLEANABLE")

    def test_planner_object_prerequisite_uses_real_factory_and_readback(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        self.recipe()
        recipe = self.catalog.get(self.package.id, "project")
        planned = self.objects.plan(
            target_id=self.package.target.id, package_id=self.package.id,
            object_type="project", creator_identity_id=identity.id,
            tenant_id=tenant.id, recipe_id=recipe.id, recipe_hash=recipe.sha256,
            test_name="hackbot-test-planner", cleanup_strategy=CleanupStrategy.AUTO_CLEANUP)
        planner_store = PlannerStore(self.store)
        run = planner_store.create(self.package, PlannerMode.BOUNDED_AUTONOMOUS,
            PlannerLimits(requests=10, cleanup_reserve=2), policy_version(self.package))
        planner_store.transition(run.target_id, run.id, PlannerStatus.LOADING_CONTEXT,
                                 "CONTEXT_STARTED")
        candidate = PlannerCandidate(
            "PLCAND-" + "a" * 32, run.id, run.target_id, "AUTHORIZATION",
            "AUTHC-" + "a" * 32, None, Specialist.AUTHORIZATION, "CROSS_TENANT",
            "b" * 64, "c" * 64, 85, 75, 85, 4, 0, 0,
            "LOW", 75, "CURRENT", status=CandidateStatus.SELECTED)
        run = planner_store.save_portfolio(run, (candidate,), {}, "d" * 64)
        create = planner_store.add_task(run, candidate,
            PlannerTaskType.CREATE_DISPOSABLE_OBJECT, budget={"requests": 4})
        resolve = planner_store.add_task(run, candidate, PlannerTaskType.RESOLVE_OBJECT,
                                          dependencies=(create.id,))
        runner = PlannerRunner(
            planner=SimpleNamespace(), store=planner_store,
            hypotheses=SimpleNamespace(), contexts=SimpleNamespace(),
            router=SimpleNamespace(), skill_planner=SimpleNamespace(),
            authorization=SimpleNamespace(), api=SimpleNamespace(), dom=None,
            messages=None, exposure=SimpleNamespace(), research=SimpleNamespace(),
            objects=self.objects, object_factory=self.factory, browser=self.browser,
            orchestrator=SimpleNamespace(), validator=SimpleNamespace())
        try:
            with patch.object(runner, "_source", return_value=SimpleNamespace(
                    test_object_id=planned.id)), patch.object(runner, "_fresh", return_value=True):
                first = runner.advance(self.package, run.id)
                second = runner.advance(self.package, run.id)
            self.assertEqual(first["task"]["reason_code"], "OBJECT_CREATED")
            self.assertEqual(second["task"]["reason_code"], "OWNED_OBJECT_READY")
            current = self.objects.get(planned.id, run.target_id)
            self.assertEqual(current.state, ObjectState.READY)
            self.assertIsNotNone(current.verified_at)
            self.assertEqual(len(self.server.fixture_objects), 1)
            self.assertEqual(planner_store.get(run.target_id, run.id).usage.requests, 4)
        finally:
            current = self.objects.get(planned.id, run.target_id)
            if current and current.state in {ObjectState.READY, ObjectState.IN_USE}:
                self.factory.cleanup(planned.id, run.target_id, session_id=session.id)
        self.assertEqual(self.server.fixture_objects, {})

    def test_parent_requires_verified_owned_object(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        self.recipe(recipe_id="dashboard", object_type="dashboard", parent_type="project")
        blocked = self.factory.resolve(package_id=self.package.id, recipe_id="dashboard",
                                       identity_id=identity.id, tenant_id=tenant.id,
                                       session_id=session.id, purpose="Local fixture")
        self.assertEqual(blocked.outcome, "BLOCKED_MISSING_PARENT")

    def test_recipe_rejects_account_and_tenant_provisioning(self):
        for object_type in ("user", "account", "tenant", "organization", "workspace"):
            with self.subTest(object_type=object_type):
                recipe = self.recipe(recipe_id="provision_" + object_type,
                                     object_type=object_type)
                with self.assertRaisesRegex(ValueError, "provisioning"):
                    ObjectRecipe.from_json(recipe)

    def test_recipe_side_effect_hint_cannot_lower_risk(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        for hint in ("EXTERNAL_SIDE_EFFECT", "UNKNOWN"):
            with self.subTest(hint=hint):
                recipe_id = "hint_" + hint.lower()
                recipe = self.recipe(recipe_id=recipe_id)
                recipe["create"]["side_effect"] = hint
                path = self.object_settings.recipe_root / self.package.id / (recipe_id + ".json")
                path.write_text(json.dumps(recipe), encoding="utf-8")
                result = self.factory.resolve(package_id=self.package.id, recipe_id=recipe_id,
                                              identity_id=identity.id, tenant_id=tenant.id,
                                              session_id=session.id, purpose="Risk hint fixture")
                self.assertEqual(result.outcome, "UNSAFE_SIDE_EFFECT")
        self.assertEqual(self.server.received, [])

    def test_classifier_camel_case_and_unknown(self):
        for operation, expected in (("inviteUser", SideEffect.EXTERNAL_SIDE_EFFECT),
                                    ("sendEmail", SideEffect.EXTERNAL_SIDE_EFFECT),
                                    ("changeRole", SideEffect.PERMISSION_CHANGE),
                                    ("upgradePlan", SideEffect.FINANCIAL),
                                    ("deleteTenant", SideEffect.DESTRUCTIVE)):
            action = ProposedAction(target_id=self.package.target.id, package_id=self.package.id,
                                    category=ActionCategory.OBJECT_CREATE, actor=ActorMode.ANONYMOUS,
                                    source="unit_test", purpose="Fixture classification",
                                    url=self.base + "/fixture", method="POST", operation=operation,
                                    object_type="project", disposable_intent=True)
            self.assertEqual(self.policy.classifier.classify(action).side_effect, expected)
        unknown = self.action("/fixture", method="POST", category=ActionCategory.HTTP_REQUEST)
        self.assertEqual(self.policy.classifier.classify(unknown).side_effect, SideEffect.UNKNOWN)
        unfamiliar = ProposedAction(target_id=self.package.target.id, package_id=self.package.id,
                                    category=ActionCategory.OBJECT_CREATE, actor=ActorMode.ANONYMOUS,
                                    source="unit_test", purpose="Unknown operation guard",
                                    url=self.base + "/fixture", method="POST", operation="doSomething",
                                    object_type="project", disposable_intent=True)
        self.assertEqual(self.policy.classifier.classify(unfamiliar).side_effect, SideEffect.UNKNOWN)
        for path, operation, expected in (("/fixture/roles", "createRole", SideEffect.PERMISSION_CHANGE),
                                          ("/fixture/billing", "createSubscription", SideEffect.FINANCIAL)):
            with self.subTest(path=path):
                action = replace(unfamiliar, url=self.base + path, operation=operation)
                self.assertEqual(self.policy.classifier.classify(action).side_effect, expected)

    def test_unsafe_recipe_cannot_send(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        for operation in ("inviteUser", "changeRole", "upgradePlan", "deleteTenant", "doSomething"):
            with self.subTest(operation=operation):
                recipe_id = "unsafe_" + operation.lower()
                self.recipe(recipe_id=recipe_id, create_operation=operation)
                result = self.factory.resolve(package_id=self.package.id, recipe_id=recipe_id,
                                              identity_id=identity.id, tenant_id=tenant.id,
                                              session_id=session.id, purpose="Local fixture")
                self.assertEqual(result.outcome, "UNSAFE_SIDE_EFFECT")
        self.assertEqual(self.server.received, [])

    def test_tenant_a_and_b_facts_do_not_cross(self):
        first, first_session, first_tenant = self.account("tenant_a_admin", "tenant-a")
        second, second_session, second_tenant = self.account("tenant_b_admin", "tenant-b")
        self.recipe(recipe_id="project_a", tenant="tenant-a", owner="tenant_a_admin")
        self.recipe(recipe_id="project_b", tenant="tenant-b", owner="tenant_b_admin")
        objects = []
        for recipe_id, identity, session, tenant in (
                ("project_a", first, first_session, first_tenant),
                ("project_b", second, second_session, second_tenant)):
            result = self.factory.resolve(package_id=self.package.id, recipe_id=recipe_id,
                                          identity_id=identity.id, tenant_id=tenant.id,
                                          session_id=session.id, purpose="Cross-tenant fixture")
            self.assertEqual(result.outcome, "READY")
            objects.append(result.item)
        self.assertNotEqual(objects[0].id, objects[1].id)
        self.assertNotEqual(objects[0].tenant_id, objects[1].tenant_id)
        with self.store._connection() as db:
            for item, identity, tenant in zip(objects, (first, second),
                                              (first_tenant, second_tenant)):
                facts = {(row["predicate"], row["object_ref"]) for row in db.execute(
                    "SELECT predicate,object_ref FROM facts WHERE subject=?", (item.id,))}
                self.assertIn(("created_by", identity.id), facts)
                self.assertIn(("resource_tenant", tenant.id), facts)
                self.assertIn(("disposable", "true"), facts)

    def test_identity_mismatch_and_real_object_guard(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        self.recipe()
        self.assertEqual(self.factory.resolve(package_id=self.package.id, recipe_id="project",
                                              identity_id=identity.id, tenant_id=tenant.id,
                                              session_id="BSESSION-" + "1" * 32,
                                              purpose="Local fixture").outcome, "IDENTITY_UNVERIFIED")
        action = ProposedAction(target_id=self.package.target.id, package_id=self.package.id,
                                category=ActionCategory.OBJECT_DELETE, actor=ActorMode.AUTHENTICATED,
                                source="object_factory", purpose="Disposable fixture cleanup",
                                url=self.base + "/fixture/tenant-a/projects/real123", method="DELETE",
                                identity_id=identity.id, session_id=session.id, object_type="project",
                                object_ref_hash="a" * 64, disposable_intent=True)
        self.assertFalse(self.objects.owned_for_action(action))
        self.assertEqual(self.policy.evaluate(self.package, action).result, PolicyDecision.DENY)

    def test_create_ambiguity_is_not_retried(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        self.recipe(ambiguous_create=True)
        result = self.factory.resolve(package_id=self.package.id, recipe_id="project",
                                      identity_id=identity.id, tenant_id=tenant.id,
                                      session_id=session.id, purpose="Ambiguity fixture")
        self.assertEqual(result.outcome, "NEEDS_MANUAL_REVIEW")
        self.assertEqual(result.item.state, ObjectState.UNKNOWN)
        self.assertEqual(len(self.server.fixture_objects), 1)
        self.assertEqual(self.factory.create(result.item.id, result.item.target_id,
                                             session_id=session.id).outcome, "NOT_CREATABLE")
        self.assertEqual(len(self.server.fixture_objects), 1)
        self.assertEqual(self.objects.reconcile(), 0)

    def test_cleanup_ambiguity_is_not_retried(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        self.recipe()
        ready = self.factory.resolve(package_id=self.package.id, recipe_id="project",
                                     identity_id=identity.id, tenant_id=tenant.id,
                                     session_id=session.id, purpose="Cleanup fixture")
        self.server.drop_delete_response = True
        result = self.factory.cleanup(ready.item.id, ready.item.target_id, session_id=session.id)
        self.assertEqual(result.outcome, "NEEDS_MANUAL_REVIEW")
        self.assertEqual(result.item.state, ObjectState.ORPHANED)
        self.assertEqual(self.server.fixture_objects, {})
        self.assertEqual(self.factory.cleanup(ready.item.id, ready.item.target_id,
                                               session_id=session.id).outcome, "NOT_CLEANABLE")

    def test_changed_recipe_surfaces_manual_cleanup(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        recipe = self.recipe()
        ready = self.factory.resolve(package_id=self.package.id, recipe_id=recipe["id"],
                                     identity_id=identity.id, tenant_id=tenant.id,
                                     session_id=session.id, purpose="Pinned recipe fixture")
        self.assertEqual(ready.outcome, "READY")
        recipe["create"]["operation"] = "createFixture"
        path = self.object_settings.recipe_root / self.package.id / "project.json"
        path.write_text(json.dumps(recipe), encoding="utf-8")
        before = len(self.server.received)
        result = self.factory.cleanup(ready.item.id, ready.item.target_id, session_id=session.id)
        self.assertEqual(result.outcome, "MANUAL_CLEANUP_REQUIRED")
        self.assertEqual(result.item.state, ObjectState.ORPHANED)
        self.assertEqual(len(self.server.received), before)

    def test_reservation_and_expiry_reconciliation(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        self.recipe()
        ready = self.factory.resolve(package_id=self.package.id, recipe_id="project",
                                     identity_id=identity.id, tenant_id=tenant.id,
                                     session_id=session.id, purpose="Reservation fixture")
        _, run_a = self.run_fixture()
        _, run_b = self.run_fixture()
        self.objects.reserve(ready.item.id, ready.item.target_id, run_a)
        with self.assertRaises(ValueError):
            self.objects.reserve(ready.item.id, ready.item.target_id, run_b)
        with self.store._connection() as db:
            db.execute("UPDATE test_object_reservations SET expires_at=? WHERE holder_run_id=?",
                       ("2000-01-01T00:00:00+00:00", run_a))
        self.assertEqual(self.objects.reconcile(), 1)
        self.assertEqual(self.objects.get(ready.item.id, ready.item.target_id).state,
                         ObjectState.UNKNOWN)
        self.assertIsNone(self.objects.find_reusable(ready.item.target_id, "project", tenant.id,
                                                     identity.id))

    def test_cleanup_allowance_survives_setup_exhaustion(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        self.recipe()
        self.factory.settings = replace(self.object_settings, setup_request_budget=2,
                                        cleanup_request_budget=2)
        ready = self.factory.resolve(package_id=self.package.id, recipe_id="project",
                                     identity_id=identity.id, tenant_id=tenant.id,
                                     session_id=session.id, purpose="Budget fixture")
        self.assertEqual(ready.outcome, "READY")
        self.assertEqual(ready.item.setup_requests_reserved, 2)
        self.assertEqual(self.factory.cleanup(ready.item.id, ready.item.target_id,
                                               session_id=session.id).outcome, "CLEANED")

    def test_plan_reservation_requires_matching_recipe(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        first = self.recipe(recipe_id="project_one")
        second = self.recipe(recipe_id="project_two")
        one = self.factory.resolve(package_id=self.package.id, recipe_id=first["id"],
                                   identity_id=identity.id, tenant_id=tenant.id,
                                   session_id=session.id, purpose="Recipe one fixture")
        self.assertEqual(one.outcome, "READY")
        plan_id, _ = self.run_fixture(with_run=False)
        self.objects.add_requirement(plan_id=plan_id, target_id=one.item.target_id,
                                     object_type="project", recipe_id=second["id"],
                                     identity_id=identity.id, tenant_id=tenant.id)
        run_id = self.create_fixture_run(plan_id)
        self.assertFalse(self.objects.reserve_requirements(run_id, one.item.target_id))
        two = self.factory.resolve(package_id=self.package.id, recipe_id=second["id"],
                                   identity_id=identity.id, tenant_id=tenant.id,
                                   session_id=session.id, purpose="Recipe two fixture")
        self.assertEqual(two.outcome, "READY")
        self.assertNotEqual(one.item.id, two.item.id)
        self.assertTrue(self.objects.reserve_requirements(run_id, two.item.target_id))
        self.assertEqual(self.objects.get(two.item.id, two.item.target_id).state, ObjectState.IN_USE)
        self.assertEqual(self.objects.get(one.item.id, one.item.target_id).state, ObjectState.READY)
        self.assertTrue(self.objects.reserved_for_run(run_id, two.item.target_id))

    def test_reconcile_inflight_creation_and_cleanup_never_replays(self):
        identity, session, tenant = self.account("tenant_a_admin", "tenant-a")
        recipe = self.recipe()
        descriptor = self.catalog.get(self.package.id, recipe["id"])
        item = self.objects.plan(target_id=self.package.target.id, package_id=self.package.id,
                                 object_type="project", creator_identity_id=identity.id,
                                 tenant_id=tenant.id, recipe_id=recipe["id"],
                                 recipe_hash=descriptor.sha256, test_name="hackbot-test-crash",
                                 cleanup_strategy=CleanupStrategy.AUTO_CLEANUP)
        self.objects.transition(item.id, item.target_id, frozenset({ObjectState.PLANNED}),
                                ObjectState.CREATING, "TEST_INFLIGHT")
        ready = self.factory.resolve(package_id=self.package.id, recipe_id=recipe["id"],
                                     identity_id=identity.id, tenant_id=tenant.id,
                                     session_id=session.id, purpose="Cleanup crash fixture")
        self.assertEqual(ready.outcome, "READY")
        self.objects.transition(ready.item.id, ready.item.target_id,
                                frozenset({ObjectState.READY}), ObjectState.CLEANING,
                                "TEST_INFLIGHT")
        before = len(self.server.received)
        self.assertEqual(self.objects.reconcile(), 2)
        self.assertEqual(len(self.server.received), before)
        self.assertEqual(self.objects.get(item.id, item.target_id).state, ObjectState.UNKNOWN)
        self.assertEqual(self.objects.get(ready.item.id, ready.item.target_id).state,
                         ObjectState.ORPHANED)


if __name__ == "__main__":
    import unittest
    unittest.main()
