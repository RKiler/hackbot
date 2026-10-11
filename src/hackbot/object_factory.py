"""Policy-gated disposable object creation and cleanup; no direct HTTP client."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
from typing import Any
import uuid

from .config import ObjectSettings
from .evidence import EvidenceProvenance, Sensitivity
from .executor import RequestTemplate, TrafficExecutor
from .object_recipes import ObjectRecipe, RecipeCatalog, RecipeOperation, external_id, json_pointer
from .policy import PolicyEngine
from .policy_models import ActionCategory, ActorMode, ProposedAction, SideEffect
from .target_loader import TargetPackageRepository
from .target_policy import PolicyDecision
from .test_objects import CleanupStrategy, ObjectRegistry, ObjectState, TestObject
from .traffic import ExchangeState, TrafficStore


@dataclass(frozen=True, slots=True)
class ObjectFactoryResult:
    outcome: str
    item: TestObject | None
    reason: str
    approval_id: str | None = None
    created_new: bool = False

    def to_dict(self) -> dict[str, object]:
        return {"outcome": self.outcome, "object": self.item.to_dict() if self.item else None,
                "reason": self.reason, "approval_id": self.approval_id}


class ObjectFactory:
    def __init__(self, *, objects: ObjectRegistry, recipes: RecipeCatalog,
                 policy: PolicyEngine, executor: TrafficExecutor,
                 targets: TargetPackageRepository, traffic: TrafficStore,
                 settings: ObjectSettings) -> None:
        self.objects = objects
        self.recipes = recipes
        self.policy = policy
        self.executor = executor
        self.targets = targets
        self.traffic = traffic
        self.settings = settings

    def _recipe(self, item: TestObject) -> ObjectRecipe:
        recipe = self.recipes.get(item.package_id, item.recipe_id)
        if recipe is None or recipe.sha256 != item.recipe_hash or recipe.target_id != item.target_id:
            raise ValueError("MISSING_OR_CHANGED_CREATION_RECIPE")
        return recipe

    def _identity_binding(self, recipe: ObjectRecipe, identity_id: str,
                          tenant_id: str, session_id: str) -> bool:
        try:
            context = self.policy.browser.session_context(session_id) if self.policy.browser else None
        except (ValueError, LookupError):
            return False
        if (context is None or context.target_id != recipe.target_id or
                context.identity_id != identity_id or context.authentication_status != "VALID" or
                tenant_id not in context.declared_tenant_ids):
            return False
        with self.objects.store._connection() as db:
            actor = db.execute("SELECT alias,status FROM registry_identities WHERE identity_id=? AND target_id=?",
                               (identity_id, recipe.target_id)).fetchone()
            tenant = db.execute("SELECT label FROM registry_tenants WHERE tenant_id=? AND target_id=?",
                                (tenant_id, recipe.target_id)).fetchone()
            membership = db.execute("SELECT 1 FROM registry_memberships WHERE identity_id=? AND tenant_id=? "
                                    "AND target_id=? AND status='ACTIVE' LIMIT 1",
                                    (identity_id, tenant_id, recipe.target_id)).fetchone()
        return bool(actor and actor["status"] == "ACTIVE" and actor["alias"] == recipe.expected_owner
                    and tenant and tenant["label"] == recipe.expected_tenant and membership)

    def _external_id(self, item: TestObject) -> str:
        if item.external_id_evidence_id is None or item.external_id_hash is None:
            raise ValueError("object has no verified external identifier")
        value = self.objects.store.read_content(item.external_id_evidence_id,
                                                allow_sensitive=True, max_bytes=256).decode("ascii")
        if hashlib.sha256((item.id + ":" + value).encode()).hexdigest() != item.external_id_hash:
            raise ValueError("external object identifier evidence mismatch")
        return external_id(value)

    def _parent_external_id(self, item: TestObject) -> str | None:
        if item.parent_id is None:
            return None
        parent = self.objects.get(item.parent_id, item.target_id)
        if parent is None or parent.state not in {ObjectState.READY, ObjectState.IN_USE}:
            raise ValueError("BLOCKED_MISSING_PARENT")
        return self._external_id(parent)

    def _response(self, result: object) -> tuple[object | None, tuple[str, ...]]:
        exchange_ids = getattr(result, "exchange_ids", ())
        if len(exchange_ids) != 1:
            return None, ()
        exchange = self.traffic.get_exchange(exchange_ids[0])
        if (exchange is None or exchange.state is not ExchangeState.COMPLETE or
                exchange.response is None or exchange.response.body_evidence_id is None):
            return None, exchange.evidence_ids if exchange else ()
        body = self.objects.store.read_content(exchange.response.body_evidence_id,
                                               allow_sensitive=True, max_bytes=65536)
        try:
            return json.loads(body), exchange.evidence_ids
        except (ValueError, UnicodeError):
            return None, exchange.evidence_ids

    def _send(self, item: TestObject, operation: RecipeOperation, *, kind: str,
              category: ActionCategory, session_id: str, object_id: str | None = None,
              action_id: str | None = None, cleanup: bool = False,
              test_name: str | None = None) -> tuple[str, object | None]:
        recipe = self._recipe(item)
        template = operation.template(test_name=test_name or item.test_name,
                                      parent_id=self._parent_external_id(item), object_id=object_id)
        action = ProposedAction(
            target_id=item.target_id, package_id=item.package_id, category=category,
            actor=ActorMode.AUTHENTICATED, source="object_factory", purpose="Disposable test object " + kind.lower(),
            url=template.url, method=template.method, identity_id=item.creator_identity_id,
            session_id=session_id, hypothesis_id=item.hypothesis_id, operation=operation.operation,
            object_type=item.object_type,
            object_ref_hash=item.external_id_hash if category in {
                ActionCategory.OBJECT_UPDATE, ActionCategory.OBJECT_DELETE} else None,
            disposable_intent=True, side_effect_hint=operation.side_effect,
            id=action_id or "ACTION-" + uuid.uuid4().hex)
        classification = self.policy.classifier.classify(action)
        expected = {"CREATE": SideEffect.SAFE_CREATE, "VERIFY": SideEffect.SAFE_READ,
                    "UPDATE": SideEffect.SAFE_UPDATE, "CLEANUP": SideEffect.SAFE_DELETE,
                    "VERIFY_CLEANUP": SideEffect.SAFE_READ}[kind]
        if classification.side_effect is not expected:
            return "UNSAFE_SIDE_EFFECT", None
        package = self.targets.get_target_package(item.package_id)
        if package is None or package.target.id != item.target_id:
            return "TARGET_UNAVAILABLE", None
        decision = self.policy.evaluate(package, action, record=True)
        if decision.result is PolicyDecision.REQUIRE_APPROVAL:
            self.objects.transition(item.id, item.target_id, frozenset({item.state}), item.state,
                                    "POLICY_APPROVAL_REQUIRED", action_id=action.id,
                                    approval_id=decision.approval_id)
            return "APPROVAL_REQUIRED", decision.approval_id
        if decision.result is not PolicyDecision.ALLOW:
            self.objects.transition(item.id, item.target_id, frozenset({item.state}), item.state,
                                    "POLICY_DENIED", action_id=action.id)
            return "POLICY_DENIED", decision.reason_code
        try:
            permit = self.executor.authorize(action, template)
        except (ValueError, RuntimeError):
            return "POLICY_DENIED", None
        if not self.objects.begin_operation(item.id, item.target_id, action.id, kind,
                                            decision.id, permit.id):
            return "ALREADY_ATTEMPTED", None
        maximum = self.settings.cleanup_request_budget if cleanup else self.settings.setup_request_budget
        try:
            self.objects.reserve_budget(item.id, item.target_id, cleanup=cleanup, maximum=maximum)
        except ValueError:
            self.objects.finish_operation(action.id, status="DENIED", reason="BUDGET_EXHAUSTED")
            return "BUDGET_EXHAUSTED", None
        next_state = {"CREATE": ObjectState.CREATING, "VERIFY": ObjectState.VERIFYING,
            "UPDATE": ObjectState.IN_USE, "CLEANUP": ObjectState.CLEANING,
                      "VERIFY_CLEANUP": ObjectState.CLEANING}[kind]
        self.objects.transition(item.id, item.target_id, frozenset({item.state}), next_state,
                                "EXECUTION_AUTHORIZED")
        result = self.executor.execute(action, permit, template, max_dispatches=1,
                                       on_dispatch=lambda exchange: self.objects.operation_dispatched(
                                           action.id, exchange))
        ambiguous = bool(result.exchange_ids) and (result.error is not None or result.status_code is None)
        self.objects.finish_operation(action.id,
                                      status="AMBIGUOUS" if ambiguous else "FAILED" if result.error else "SUCCEEDED",
                                      reason="AMBIGUOUS_RESPONSE" if ambiguous else
                                             result.error.value if result.error else "HTTP_RESPONSE",
                                      execution_id=result.execution_id)
        if ambiguous:
            state = ObjectState.ORPHANED if cleanup else ObjectState.UNKNOWN
            self.objects.transition(item.id, item.target_id, frozenset({next_state}), state,
                                    "AMBIGUOUS_RESPONSE", action_id=action.id,
                                    evidence_ids=result.evidence_ids[:16])
            return "NEEDS_MANUAL_REVIEW", result
        if result.error is not None:
            state = ObjectState.ORPHANED if cleanup else ObjectState.FAILED
            self.objects.transition(item.id, item.target_id, frozenset({next_state}), state,
                                    "EXECUTION_FAILED", action_id=action.id,
                                    evidence_ids=result.evidence_ids[:16])
            return "EXECUTION_FAILED", result
        return "RESPONSE", result

    def resolve(self, *, package_id: str, recipe_id: str, identity_id: str, tenant_id: str,
                session_id: str, purpose: str, parent_id: str | None = None,
                plan_id: str | None = None, run_id: str | None = None,
                hypothesis_id: str | None = None) -> ObjectFactoryResult:
        recipe = self.recipes.get(package_id, recipe_id)
        if recipe is None:
            return ObjectFactoryResult("MISSING_CREATION_RECIPE", None, "No known operation")
        if not self._identity_binding(recipe, identity_id, tenant_id, session_id):
            return ObjectFactoryResult("IDENTITY_UNVERIFIED", None, "Verified creator and tenant required")
        if (recipe.parent_type is None) != (parent_id is None):
            return ObjectFactoryResult("BLOCKED_MISSING_PARENT", None, "Parent prerequisite not ready")
        if parent_id:
            parent = self.objects.get(parent_id, recipe.target_id)
            if parent is None or parent.object_type != recipe.parent_type or parent.tenant_id != tenant_id:
                return ObjectFactoryResult("BLOCKED_MISSING_PARENT", None, "Parent prerequisite not ready")
            depth = 1
            while parent.parent_id:
                depth += 1
                parent = self.objects.get(parent.parent_id, recipe.target_id)
                if parent is None or depth >= self.settings.max_creation_depth:
                    return ObjectFactoryResult("BLOCKED_MISSING_PARENT", None, "Creation depth exceeded")
        reusable = self.objects.find_reusable(recipe.target_id, recipe.object_type, tenant_id,
                                              identity_id, parent_id=parent_id, recipe_id=recipe.id)
        if reusable:
            return ObjectFactoryResult("READY", reusable, "Existing verified disposable object")
        if not isinstance(purpose, str) or not purpose or len(purpose) > 120:
            raise ValueError("invalid object purpose")
        name = self.settings.name_prefix + uuid.uuid4().hex[:12]
        item = self.objects.plan(
            target_id=recipe.target_id, package_id=recipe.package_id, object_type=recipe.object_type,
            creator_identity_id=identity_id, tenant_id=tenant_id, recipe_id=recipe.id,
            recipe_hash=recipe.sha256, test_name=name, cleanup_strategy=recipe.cleanup_strategy,
            parent_id=parent_id, plan_id=plan_id, run_id=run_id, hypothesis_id=hypothesis_id,
            max_objects_per_plan=self.settings.max_objects_per_plan,
            max_objects_per_target_hour=self.settings.max_objects_per_target_hour)
        return replace(self.create(item.id, recipe.target_id, session_id=session_id),
                       created_new=True)

    def create(self, object_id: str, target_id: str, *, session_id: str) -> ObjectFactoryResult:
        item = self.objects.get(object_id, target_id)
        if item is None:
            raise LookupError("object not found")
        if item.state is not ObjectState.PLANNED:
            return ObjectFactoryResult("NOT_CREATABLE", item, "Creation already attempted")
        recipe = self._recipe(item)
        if not self._identity_binding(recipe, item.creator_identity_id, item.tenant_id, session_id):
            return ObjectFactoryResult("IDENTITY_UNVERIFIED", item, "Verified creator and tenant required")
        state, response = self._send(item, recipe.create, kind="CREATE",
                                     category=ActionCategory.OBJECT_CREATE, session_id=session_id,
                                     action_id=item.pending_action_id or item.creation_action_id)
        item = self.objects.get(object_id, target_id)
        assert item is not None
        if state != "RESPONSE":
            return ObjectFactoryResult(state, item, "Creation not verified",
                                       response if state == "APPROVAL_REQUIRED" else None)
        result = response
        if result.status_code not in {200, 201} or result.truncated:
            self.objects.transition(item.id, target_id, frozenset({ObjectState.CREATING}), ObjectState.UNKNOWN,
                                    "UNEXPECTED_CREATE_RESPONSE", evidence_ids=result.evidence_ids[:16])
            return ObjectFactoryResult("NEEDS_MANUAL_REVIEW", self.objects.get(object_id, target_id),
                                       "Creation response did not establish an object")
        body, evidence = self._response(result)
        try:
            external = external_id(json_pointer(body, recipe.id_pointer))
        except (ValueError, KeyError, TypeError, IndexError):
            self.objects.transition(item.id, target_id, frozenset({ObjectState.CREATING}), ObjectState.UNKNOWN,
                                    "MISSING_OBJECT_ID", evidence_ids=evidence[:16])
            return ObjectFactoryResult("NEEDS_MANUAL_REVIEW", self.objects.get(object_id, target_id),
                                       "No trustworthy object identifier")
        secret = self.objects.store.create_evidence(
            "TEST_OBJECT_EXTERNAL_ID", external.encode(), source="OBJECT_FACTORY",
            provenance=EvidenceProvenance(system="OBJECT_FACTORY", entity="CREATE",
                                          record_id=result.exchange_ids[0]), target_ref=target_id,
            sensitivity=Sensitivity.SECRET)
        item = self.objects.transition(item.id, target_id, frozenset({ObjectState.CREATING}),
                                       ObjectState.CREATED, "CREATE_RESPONSE_ID", exchange_id=result.exchange_ids[0],
                                       evidence_ids=tuple(dict.fromkeys((*evidence, secret.evidence_id)))[:16],
                                       external_id_hash=hashlib.sha256((item.id + ":" + external).encode()).hexdigest(),
                                       external_id_evidence_id=secret.evidence_id)
        return self.verify(item.id, target_id, session_id=session_id)

    def verify(self, object_id: str, target_id: str, *, session_id: str) -> ObjectFactoryResult:
        item = self.objects.get(object_id, target_id)
        if item is None or item.state not in {ObjectState.CREATED, ObjectState.VERIFYING}:
            raise ValueError("object is not awaiting verification")
        recipe = self._recipe(item)
        if not self._identity_binding(recipe, item.creator_identity_id, item.tenant_id, session_id):
            return ObjectFactoryResult("IDENTITY_UNVERIFIED", item, "Verified creator and tenant required")
        state, response = self._send(item, recipe.verify, kind="VERIFY",
                                     category=ActionCategory.SAFE_READ, session_id=session_id,
                                     object_id=self._external_id(item), action_id=item.pending_action_id)
        item = self.objects.get(object_id, target_id)
        assert item is not None
        if state != "RESPONSE":
            return ObjectFactoryResult(state, item, "Ownership not verified",
                                       response if state == "APPROVAL_REQUIRED" else None)
        result = response
        body, evidence = self._response(result)
        try:
            matched = (result.status_code == 200 and not result.truncated and
                       json_pointer(body, recipe.verify_id_pointer) == self._external_id(item) and
                       json_pointer(body, recipe.verify_name_pointer) == item.test_name and
                       json_pointer(body, recipe.verify_owner_pointer) == recipe.expected_owner and
                       json_pointer(body, recipe.verify_tenant_pointer) == recipe.expected_tenant)
        except (ValueError, KeyError, TypeError, IndexError):
            matched = False
        if not matched:
            item = self.objects.transition(item.id, target_id, frozenset({ObjectState.VERIFYING}),
                                           ObjectState.UNKNOWN, "OWNERSHIP_NOT_VERIFIED",
                                           evidence_ids=evidence[:16])
            return ObjectFactoryResult("NEEDS_MANUAL_REVIEW", item, "Owner read-back mismatch")
        item = self.objects.transition(item.id, target_id, frozenset({ObjectState.VERIFYING}),
                                       ObjectState.READY, "OWNERSHIP_VERIFIED", evidence_ids=evidence[:16],
                                       owner_principal_id=item.creator_identity_id)
        links = evidence[:16]
        for predicate, value in (("created_by", item.creator_identity_id),
                                 ("resource_tenant", item.tenant_id), ("disposable", "true")):
            self.objects.store.create_fact(item.id, predicate, value, confidence=1.0,
                                           evidence_ids=links, source="OBJECT_FACTORY",
                                           target_ref=target_id)
        return ObjectFactoryResult("READY", item, "Creation and ownership verified")

    def update_name(self, object_id: str, target_id: str, *, session_id: str) -> ObjectFactoryResult:
        item = self.objects.get(object_id, target_id)
        if item is None:
            raise LookupError("object not found")
        if not item.disposable or item.state is not ObjectState.READY or self.objects.active_reservation(item.id):
            return ObjectFactoryResult("NOT_UPDATABLE", item, "Verified, unreserved disposable object required")
        recipe = self._recipe(item)
        if recipe.update is None:
            return ObjectFactoryResult("UNSUPPORTED_UPDATE", item, "No known update operation")
        if not self._identity_binding(recipe, item.creator_identity_id, item.tenant_id, session_id):
            return ObjectFactoryResult("IDENTITY_UNVERIFIED", item, "Verified creator and tenant required")
        new_name = self.settings.name_prefix + uuid.uuid4().hex[:12]
        state, response = self._send(item, recipe.update, kind="UPDATE",
                                     category=ActionCategory.OBJECT_UPDATE, session_id=session_id,
                                     object_id=self._external_id(item), test_name=new_name)
        item = self.objects.get(object_id, target_id)
        assert item is not None
        if state != "RESPONSE":
            return ObjectFactoryResult(state, item, "Update not verified",
                                       response if state == "APPROVAL_REQUIRED" else None)
        result = response
        if result.status_code not in {200, 204}:
            item = self.objects.transition(item.id, target_id, frozenset({ObjectState.IN_USE}),
                                           ObjectState.UNKNOWN, "UPDATE_RESPONSE_UNEXPECTED",
                                           evidence_ids=result.evidence_ids[:16])
            return ObjectFactoryResult("NEEDS_MANUAL_REVIEW", item, "Update effect is uncertain")
        state, readback = self._send(item, recipe.verify, kind="VERIFY",
                                     category=ActionCategory.SAFE_READ, session_id=session_id,
                                     object_id=self._external_id(item))
        item = self.objects.get(object_id, target_id)
        assert item is not None
        if state != "RESPONSE":
            return ObjectFactoryResult(state, item, "Update read-back unavailable",
                                       readback if state == "APPROVAL_REQUIRED" else None)
        body, evidence = self._response(readback)
        try:
            matched = (readback.status_code == 200 and not readback.truncated and
                       json_pointer(body, recipe.verify_id_pointer) == self._external_id(item) and
                       json_pointer(body, recipe.verify_name_pointer) == new_name and
                       json_pointer(body, recipe.verify_owner_pointer) == recipe.expected_owner and
                       json_pointer(body, recipe.verify_tenant_pointer) == recipe.expected_tenant)
        except (ValueError, KeyError, TypeError, IndexError):
            matched = False
        if not matched:
            item = self.objects.transition(item.id, target_id, frozenset({ObjectState.VERIFYING}),
                                           ObjectState.UNKNOWN, "UPDATE_READBACK_MISMATCH",
                                           evidence_ids=evidence[:16])
            return ObjectFactoryResult("NEEDS_MANUAL_REVIEW", item, "Update was not verified")
        item = self.objects.transition(item.id, target_id, frozenset({ObjectState.VERIFYING}),
                                       ObjectState.READY, "UPDATE_VERIFIED", evidence_ids=evidence[:16])
        item = self.objects.set_verified_name(item.id, target_id, new_name, evidence[:16])
        return ObjectFactoryResult("READY", item, "Safe update verified")

    def cleanup(self, object_id: str, target_id: str, *, session_id: str) -> ObjectFactoryResult:
        item = self.objects.get(object_id, target_id)
        if item is None:
            raise LookupError("object not found")
        if not item.disposable or item.verified_at is None or self.objects.active_reservation(item.id):
            return ObjectFactoryResult("NOT_CLEANABLE", item, "Verified, unreserved disposable object required")
        if item.state not in {ObjectState.READY, ObjectState.CLEANUP_PENDING}:
            return ObjectFactoryResult("NOT_CLEANABLE", item, "Cleanup already attempted or complete")
        try:
            recipe = self._recipe(item)
        except ValueError:
            item = self.objects.transition(item.id, target_id, frozenset({item.state}),
                                           ObjectState.ORPHANED, "CLEANUP_RECIPE_UNAVAILABLE")
            return ObjectFactoryResult("MANUAL_CLEANUP_REQUIRED", item,
                                       "Pinned cleanup recipe is unavailable or changed")
        if recipe.cleanup_strategy is not CleanupStrategy.AUTO_CLEANUP or recipe.cleanup is None:
            return ObjectFactoryResult("MANUAL_CLEANUP_REQUIRED", item, "No safe automatic cleanup recipe")
        if not self._identity_binding(recipe, item.creator_identity_id, item.tenant_id, session_id):
            return ObjectFactoryResult("IDENTITY_UNVERIFIED", item, "Verified creator and tenant required")
        state, response = self._send(item, recipe.cleanup, kind="CLEANUP",
                                     category=ActionCategory.OBJECT_DELETE, session_id=session_id,
                                     object_id=self._external_id(item), cleanup=True,
                                     action_id=item.pending_action_id)
        item = self.objects.get(object_id, target_id)
        assert item is not None
        if state != "RESPONSE":
            return ObjectFactoryResult(state, item, "Cleanup not verified",
                                       response if state == "APPROVAL_REQUIRED" else None)
        result = response
        if result.status_code not in {200, 202, 204}:
            item = self.objects.transition(item.id, target_id, frozenset({ObjectState.CLEANING}),
                                           ObjectState.ORPHANED, "CLEANUP_RESPONSE_UNEXPECTED",
                                           evidence_ids=result.evidence_ids[:16])
            return ObjectFactoryResult("CLEANUP_FAILED", item, "Deletion not established")
        return self.verify_cleanup(item.id, target_id, session_id=session_id)

    def verify_cleanup(self, object_id: str, target_id: str, *, session_id: str) -> ObjectFactoryResult:
        item = self.objects.get(object_id, target_id)
        if item is None or item.state is not ObjectState.CLEANING:
            raise ValueError("object is not awaiting cleanup verification")
        recipe = self._recipe(item)
        state, response = self._send(item, recipe.verify, kind="VERIFY_CLEANUP",
                                     category=ActionCategory.SAFE_READ, session_id=session_id,
                                     object_id=self._external_id(item), cleanup=True,
                                     action_id=item.pending_action_id)
        item = self.objects.get(object_id, target_id)
        assert item is not None
        if state != "RESPONSE":
            return ObjectFactoryResult(state, item, "Cleanup read-back unavailable",
                                       response if state == "APPROVAL_REQUIRED" else None)
        result = response
        if result.status_code not in {404, 410}:
            item = self.objects.transition(item.id, target_id, frozenset({ObjectState.CLEANING}),
                                           ObjectState.ORPHANED, "OBJECT_STILL_PRESENT",
                                           evidence_ids=result.evidence_ids[:16])
            return ObjectFactoryResult("CLEANUP_FAILED", item, "Object remains after cleanup")
        item = self.objects.transition(item.id, target_id, frozenset({ObjectState.CLEANING}),
                                       ObjectState.CLEANED, "ABSENCE_VERIFIED",
                                       evidence_ids=result.evidence_ids[:16])
        return ObjectFactoryResult("CLEANED", item, "Cleanup read-back confirmed absence")
