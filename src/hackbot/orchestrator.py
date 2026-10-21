"""One explicit, policy-gated plan step per call. No vulnerability validation."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import re
import time
import uuid
from urllib.parse import urlsplit
from typing import Any

from .authorization_binding import resolve_authorization_request, resolve_exposure_read
from .api_binding import resolve_api_batch, resolve_api_read
from .api_registry import APIOperationRegistry
from .mutation_binding import (MutationStage, ResolvedMutationStage,
                               mutation_fingerprint, resolve_mutation_stage)
from .mutation_results import MutationResultStore, MutationStatus, value_hash
from .object_recipes import RecipeCatalog, json_pointer, unique_json_pairs
from .auth import AuthMechanism, AuthStatus
from .domxss_browser import (DOMBrowserExperimentExecutor, DOMExperimentBinding,
                             DOMInputKind)
from .exposure import ExposureSpecialist
from .postmessage_browser import (PostMessageBrowserExperimentExecutor,
                                  MessageExperimentBinding)
from .browser import BrowserError, BrowserStatus, VerificationStatus
from .evidence import EvidenceProvenance, EvidenceType, Sensitivity
from .executor import ExecutionError, ExecutionResult, RequestTemplate, TrafficExecutor
from .hypotheses import HypothesisStore
from .logging import SecretRedactor
from .plan_runs import (PlanRun, PlanRunStore, PlanSnapshot, RunStatus, RuntimeStep,
                        RuntimeStepStatus, RuntimeStepType, StepResult)
from .policy import PolicyEngine
from .policy_models import ActionCategory, ActorMode, ApprovalStatus, ProposedAction, new_action_id
from .policy_store import PolicyStore
from .rate_limit import ExperimentBudget
from .skill_plans import PrerequisiteChecker, PrerequisiteState, SkillContextBuilder
from .skills import SkillRegistry
from .store import EvidenceFactStore
from .target_loader import TargetPackageRepository
from .target_policy import PolicyDecision
from .traffic import TrafficStore
from .test_objects import ObjectRegistry, ObjectState
from .typed_mutations import MutationPhase, MutationType, TypedMutation


_MAP = {
    "OBSERVE": RuntimeStepType.PASSIVE_OBSERVATION.value,
    "ESTABLISH_CONTROL": RuntimeStepType.ESTABLISH_CONTROL.value,
    "EXECUTE_REQUEST": RuntimeStepType.EXECUTE_REQUEST.value,
    "COMPARE_RESPONSE": RuntimeStepType.COMPARE_METADATA.value,
    "VERIFY_BROWSER": RuntimeStepType.VERIFY_BROWSER.value,
    "MANUAL_REVIEW": RuntimeStepType.MANUAL_REVIEW.value,
}
_ACTIVE = frozenset({ActionCategory.SAFE_READ, ActionCategory.AUTHORIZATION_TEST,
                     ActionCategory.OBJECT_CREATE, ActionCategory.OBJECT_UPDATE,
                     ActionCategory.OBJECT_DELETE, ActionCategory.HTTP_REQUEST})
_TERMINAL = frozenset({RunStatus.COMPLETED, RunStatus.BLOCKED, RunStatus.REJECTED,
                       RunStatus.FAILED, RunStatus.BUDGET_EXHAUSTED, RunStatus.CANCELLED})


class PlanRunError(ValueError):
    """Safe, operator-facing error; never include a URL or secret."""


@dataclass(frozen=True, slots=True)
class _BoundAction:
    action: ProposedAction
    template: RequestTemplate
    role: str
    mutation: ResolvedMutationStage | None = None


class PlanOrchestrator:
    def __init__(self, *, runs: PlanRunStore, targets: TargetPackageRepository,
                 hypotheses: HypothesisStore, context: SkillContextBuilder,
                 checker: PrerequisiteChecker, registry: SkillRegistry,
                 policy: PolicyEngine, approvals: PolicyStore,
                 executor: TrafficExecutor, traffic: TrafficStore,
                 evidence: EvidenceFactStore, objects: ObjectRegistry | None = None,
                 recipes: RecipeCatalog | None = None,
                 mutations: MutationResultStore | None = None,
                 dom: DOMBrowserExperimentExecutor | None = None,
                 messages: PostMessageBrowserExperimentExecutor | None = None,
                 exposure: ExposureSpecialist | None = None,
                 api_operations: APIOperationRegistry | None = None) -> None:
        self.runs, self.targets, self.hypotheses = runs, targets, hypotheses
        self.context, self.checker, self.registry = context, checker, registry
        self.policy, self.approvals, self.executor = policy, approvals, executor
        self.traffic, self.evidence = traffic, evidence
        self.objects = objects
        self.recipes = recipes
        self.mutations = mutations
        self.dom = dom
        self.messages = messages
        self.exposure = exposure
        self.api_operations = api_operations

    def _exposure_binding_valid(self, package, frozen: object) -> bool:
        if self.exposure is None or not isinstance(frozen, dict):
            return False
        candidate_id = frozen.get("candidate_id")
        if not isinstance(candidate_id, str):
            return False
        candidate = self.exposure.current_candidate(package, candidate_id)
        return bool(candidate is not None and candidate.source.value == frozen.get("source")
                    and candidate.artifact_sha256 == frozen.get("artifact_sha256")
                    and candidate.credential is not None
                    and candidate.credential.fingerprint_sha256 == frozen.get("credential_fingerprint")
                    and any(link["current"] and link["source"] == frozen.get("source") and
                            link["source_ref"] == frozen.get("source_ref") and
                            link["evidence_id"] == frozen.get("evidence_id") and
                            link["artifact_sha256"] == frozen.get("artifact_sha256")
                            for link in self.exposure.store.source_links(package.target.id,
                                                                           candidate_id)))

    @staticmethod
    def _requirements(snapshot: PlanSnapshot, registry: SkillRegistry) -> tuple[tuple[str, ...], str]:
        plan = snapshot.data
        required = plan.get("required_prerequisites")
        category = plan.get("skill_category")
        if isinstance(required, list) and isinstance(category, str):
            if (len(required) > 16 or any(not isinstance(value, str) for value in required)
                    or category not in {"authorization", "api", "client-side", "exposure"}):
                raise PlanRunError("invalid prerequisite snapshot")
            return tuple(required), category
        # Phase 15 legacy snapshots did not carry the skill category. Only use
        # installed metadata when its exact content hash still matches.
        try:
            current = registry.select(str(plan["skill_id"]))
        except (LookupError, ValueError):
            raise PlanRunError("legacy skill snapshot cannot be verified") from None
        if current.content_hash != plan["skill_hash"]:
            raise PlanRunError("legacy skill snapshot changed")
        old = plan.get("prerequisites", {})
        if not isinstance(old, dict):
            raise PlanRunError("invalid prerequisite snapshot")
        return tuple(dict.fromkeys((*old.get("satisfied", []), *old.get("missing", [])))), current.metadata.category

    @staticmethod
    def _compile(snapshot: PlanSnapshot) -> tuple[dict[str, object], ...]:
        plan = snapshot.data
        workflow, actions, templates = plan.get("steps"), plan.get("proposed_actions"), plan.get("request_templates")
        budget = plan.get("request_budget")
        if (not isinstance(workflow, list) or not 1 <= len(workflow) <= 20 or
                not isinstance(actions, list) or not isinstance(templates, list) or
                len(actions) != len(templates) or type(budget) is not int or
                not 0 <= budget <= 20 or len(actions) > budget or
                type(plan.get("token_budget")) is not int or not 0 <= plan["token_budget"] <= 8192):
            raise PlanRunError("invalid or unbounded plan snapshot")
        classes = plan.get("vulnerability_classes")
        if actions and (not isinstance(classes, list) or not classes or
                        any(not isinstance(value, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", value)
                            for value in classes)):
            raise PlanRunError("active plan lacks an immutable vulnerability class")
        result: list[dict[str, object]] = [
            {"id": "STEP-" + uuid.uuid4().hex, "type": RuntimeStepType.CHECK_PREREQUISITES.value}]
        action_slot = 0
        last_control: str | None = None
        for index, item in enumerate(workflow):
            if not isinstance(item, dict) or not isinstance(item.get("type"), str):
                raise PlanRunError("invalid plan step")
            kind = _MAP.get(item["type"], "UNSUPPORTED")
            step: dict[str, object] = {"id": "STEP-" + uuid.uuid4().hex,
                                       "type": kind, "source_step_index": index}
            if kind == RuntimeStepType.EXECUTE_REQUEST.value:
                if action_slot < len(actions):
                    descriptor = actions[action_slot]
                    if not isinstance(descriptor, dict):
                        raise PlanRunError("invalid action binding")
                    role = descriptor.get("role", "OTHER")
                    if role not in {"CONTROL", "BOUNDARY", "OTHER"}:
                        raise PlanRunError("invalid action role")
                    step.update({"action_slot": action_slot, "role": role,
                                 "action_id": "ACTION-" + uuid.uuid4().hex})
                    if role == "CONTROL":
                        last_control = str(step["id"])
                    elif role == "BOUNDARY":
                        step["control_step_id"] = last_control
                    action_slot += 1
            result.append(step)
        if action_slot != len(actions):
            raise PlanRunError("plan actions lack explicit execution steps")
        return tuple(result)

    def _current(self, run: PlanRun, snapshot: PlanSnapshot) -> tuple[Any, Any, Any]:
        package = self.targets.get_target_package(run.package_id)
        if package is None or package.target.id != run.target_id:
            raise PlanRunError("target package unavailable")
        hypothesis = self.hypotheses.get(run.hypothesis_id, run.target_id)
        if hypothesis is None:
            raise PlanRunError("hypothesis unavailable")
        profile = self.hypotheses.latest_profile(run.target_id)
        context = self._context_for_plan(hypothesis, profile, package, snapshot.data)
        required, category = self._requirements(snapshot, self.registry)
        prereq = self.checker.check_requirements(required, category, context)
        return package, context, prereq

    @staticmethod
    def _api_context_refs(plan: dict[str, Any]) -> tuple[str, ...]:
        if not isinstance(plan.get("api_binding"), dict):
            return ()
        templates = plan.get("request_templates")
        if not isinstance(templates, list):
            return ()
        return tuple(dict.fromkeys(
            shape["source_exchange_id"] for shape in templates[:4]
            if isinstance(shape, dict) and
            shape.get("binding") in {"API_OBSERVED_READ_V1", "API_OBSERVED_BATCH_V1"} and
            isinstance(shape.get("source_exchange_id"), str)))[:4]

    def _context_for_plan(self, hypothesis: Any, profile: Any,
                          package: TargetPackage, plan: dict[str, Any]) -> Any:
        refs = self._api_context_refs(plan)
        if refs:
            return self.context.build(hypothesis, profile, package,
                                      traffic_exchange_ids=refs)
        return self.context.build(hypothesis, profile, package)

    def start(self, plan_id: str, package_id: str, *, rerun: bool = False) -> dict[str, object]:
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise LookupError("target package not found")
        snapshot = self.runs.snapshot(plan_id, package.target.id)
        plan = snapshot.data
        if plan.get("status") not in {"READY_FOR_MANUAL_REVIEW", "REQUIRE_APPROVAL"}:
            raise PlanRunError("plan is not ready to start")
        steps = self._compile(snapshot)
        required, category = self._requirements(snapshot, self.registry)
        hypothesis = self.hypotheses.get(str(plan["hypothesis_id"]), package.target.id)
        if hypothesis is None:
            raise PlanRunError("hypothesis unavailable")
        current = self._context_for_plan(
            hypothesis, self.hypotheses.latest_profile(package.target.id), package,
            plan)
        prereq = self.checker.check_requirements(required, category, current)
        if prereq.state is not PrerequisiteState.READY:
            raise PlanRunError("current prerequisites are not ready")
        run = self.runs.create(snapshot, package_id, steps, rerun=rerun)
        if self.objects and self.objects.requirements(plan_id, package.target.id):
            if not self.objects.reserve_requirements(run.id, run.target_id):
                run = self.runs.transition(run.id, run.target_id, RunStatus.CHECKING_PREREQUISITES,
                                           "DISPOSABLE_OBJECT_REQUIRED",
                                           expected=frozenset({RunStatus.CREATED}))
        return self.runs.details(run)

    def _load(self, run_id: str, package_id: str) -> tuple[PlanRun, PlanSnapshot]:
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise LookupError("target package not found")
        run = self.runs.get(run_id, package.target.id)
        if run is None or run.package_id != package_id:
            raise LookupError("plan run not found")
        snapshot = self.runs.snapshot(run.plan_id, run.target_id)
        if snapshot.content_hash != run.snapshot_hash:
            if run.status not in _TERMINAL and run.status is not RunStatus.RUNNING:
                blocked = self.runs.transition(run.id, run.target_id, RunStatus.BLOCKED,
                                               "SNAPSHOT_CHANGED",
                                               expected=frozenset({run.status}))
                if self.objects:
                    self.objects.release_run(blocked.id, blocked.target_id)
            raise PlanRunError("plan snapshot changed")
        return run, snapshot

    def detail(self, run_id: str, package_id: str) -> dict[str, object]:
        run, _ = self._load(run_id, package_id)
        return self.runs.details(run)

    def _bound(self, snapshot: PlanSnapshot, step: RuntimeStep, run: PlanRun) -> _BoundAction:
        if step.action_slot is None or step.action_id is None:
            raise PlanRunError("request step lacks an explicit action binding")
        try:
            descriptor = snapshot.data["proposed_actions"][step.action_slot]
            shape = snapshot.data["request_templates"][step.action_slot]
            if not isinstance(descriptor, dict) or not isinstance(shape, dict):
                raise ValueError
            resolved_mutation: ResolvedMutationStage | None = None
            if shape.get("binding") == "EXPOSURE_HTTP_V1":
                package = self.targets.get_target_package(run.package_id)
                frozen = snapshot.data.get("exposure_binding")
                if (self.exposure is None or package is None or
                        package.target.id != run.target_id or not isinstance(frozen, dict) or
                        set(shape) != set(frozen) | {"binding", "method", "authentication", "fingerprint"} or
                        any(shape.get(key) != value for key, value in frozen.items()) or
                        shape.get("method") != "GET" or
                        shape.get("authentication") != "EXECUTOR_SUPPLIED" or
                        hashlib.sha256(json.dumps({key: value for key, value in shape.items()
                                                   if key != "fingerprint"}, sort_keys=True,
                                                  separators=(",", ":")).encode()).hexdigest()
                        != shape.get("fingerprint") or
                        descriptor.get("request_template_fingerprint") != shape["fingerprint"] or
                        descriptor.get("simulation_only") is not True or
                        descriptor.get("role") != "BOUNDARY" or step.role != "BOUNDARY"):
                    raise ValueError
                template = self.exposure.resolve_captured_response(package, frozen)
            elif shape.get("binding") == "EXPOSURE_VHOST_V1":
                package = self.targets.get_target_package(run.package_id)
                frozen = snapshot.data.get("exposure_binding")
                if (self.exposure is None or package is None or not isinstance(frozen, dict)
                        or package.target.id != run.target_id or
                        set(shape) != set(frozen) | {"binding", "variant", "method",
                                                         "authentication", "fingerprint"} or
                        any(shape.get(key) != value for key, value in frozen.items()) or
                        shape.get("method") != "GET" or
                        shape.get("authentication") != "EXECUTOR_SUPPLIED" or
                        shape.get("variant") not in {"NORMAL", "INVALID", "CANDIDATE"} or
                        hashlib.sha256(json.dumps({key: value for key, value in shape.items()
                                                   if key != "fingerprint"}, sort_keys=True,
                                                  separators=(",", ":")).encode()).hexdigest()
                        != shape.get("fingerprint") or
                        descriptor.get("request_template_fingerprint") != shape["fingerprint"] or
                        descriptor.get("simulation_only") is not True or
                        descriptor.get("role") != step.role or
                        step.role != {"NORMAL": "CONTROL", "INVALID": "OTHER",
                                      "CANDIDATE": "BOUNDARY"}[shape["variant"]] or
                        descriptor.get("control_kind") != (
                            "INVALID_HOST" if shape["variant"] == "INVALID" else None)):
                    raise ValueError
                template = self.exposure.resolve_vhost(package, frozen, shape["variant"], run.id)
            elif shape.get("binding") == "AUTHORIZATION_RECIPE_MUTATION_V1":
                if (self.objects is None or self.recipes is None or self.mutations is None or
                        descriptor.get("simulation_only") is not True):
                    raise ValueError
                package = self.targets.get_target_package(run.package_id)
                if package is None or package.target.id != run.target_id:
                    raise ValueError
                resolved_mutation = resolve_mutation_stage(
                    shape, package=package, run_id=run.id, objects=self.objects,
                    recipes=self.recipes, evidence=self.evidence)
                template = resolved_mutation.template
                item, stage = resolved_mutation.item, resolved_mutation.stage
                owner = item.creator_identity_id
                expected_role = ("BOUNDARY" if stage is MutationStage.BOUNDARY_MUTATE else
                                 "CONTROL" if stage in {MutationStage.BEFORE_READ,
                                                        MutationStage.OWNER_MUTATE,
                                                        MutationStage.OWNER_READBACK,
                                                        MutationStage.TARGET_BEFORE_READ} else "OTHER")
                expected_identity = owner if stage is not MutationStage.BOUNDARY_MUTATE else None
                expected_operation = (resolved_mutation.recipe.write.operation if stage in {
                    MutationStage.OWNER_MUTATE, MutationStage.BOUNDARY_MUTATE} else
                    resolved_mutation.recipe.restore.operation if stage is MutationStage.RESTORE else
                    resolved_mutation.recipe.readback.operation)
                if (descriptor.get("request_template_fingerprint") != shape["fingerprint"] or
                        descriptor.get("object_ref_hash") != item.external_id_hash or
                        descriptor.get("object_type") != item.object_type or
                        descriptor.get("method") != template.method or
                        descriptor.get("operation") != expected_operation or
                        descriptor.get("identity_id") == owner and
                        stage is MutationStage.BOUNDARY_MUTATE or
                        expected_identity is not None and
                        descriptor.get("identity_id") != expected_identity or
                        descriptor.get("cross_identity") is not (stage is MutationStage.BOUNDARY_MUTATE) or
                        descriptor.get("control_kind") != stage.value or
                        step.role != expected_role or
                        descriptor.get("role") != expected_role or
                        descriptor.get("category") != (
                            "OBJECT_DELETE" if template.method == "DELETE" else
                            "OBJECT_UPDATE" if template.method in {"PATCH", "PUT", "POST"} else
                            "SAFE_READ")):
                    raise ValueError
            elif shape.get("binding") in {"API_OBSERVED_READ_V1", "API_OBSERVED_BATCH_V1"}:
                if (self.objects is None or self.api_operations is None or
                        descriptor.get("simulation_only") is not True):
                    raise ValueError
                package = self.targets.get_target_package(run.package_id)
                frozen = snapshot.data.get("api_binding")
                alternate_field_control = (isinstance(frozen, dict) and
                    frozen.get("category") == "FIELD_AUTH" and step.action_slot == 1 and
                    "actor_control_operation_id" in frozen and
                    "actor_control_version_hash" in frozen)
                if (package is None or package.target.id != run.target_id or
                        not isinstance(frozen, dict) or
                        shape.get("operation_id") != frozen.get(
                            "actor_control_operation_id" if alternate_field_control else
                            "operation_id") or
                        shape.get("version_hash") != frozen.get(
                            "actor_control_version_hash" if alternate_field_control else
                            "version_hash") or
                        shape.get("field_path") != (
                            "" if alternate_field_control else frozen.get("field_path")) or
                        descriptor.get("request_template_fingerprint") != shape.get("fingerprint") or
                        descriptor.get("operation") != shape.get("operation_id") or
                        descriptor.get("role") != step.role):
                    raise ValueError
                if frozen.get("category") == "NESTED_AUTH":
                    child_id = frozen.get("nested_child_id")
                    child = self.objects.get(child_id, run.target_id) if isinstance(child_id, str) else None
                    candidate = self.api_operations.get_candidate(
                        run.target_id, frozen.get("candidate_id", ""))
                    if (child is None or candidate is None or
                            candidate.child_object_id != child_id or
                            candidate.field_path != frozen.get("nested_path") or
                            child.parent_id != candidate.test_object_id or
                            not child.disposable or not child.verified_at or
                            self.objects.active_reservation(child.id) != run.id):
                        raise ValueError("Nested API child is no longer reserved")
                if shape["binding"] == "API_OBSERVED_BATCH_V1":
                    candidate = self.api_operations.get_candidate(
                        run.target_id, frozen.get("candidate_id", ""))
                    companion = self.objects.get(shape.get("companion_object_id", ""),
                                                 run.target_id)
                    source_companion = self.objects.get(
                        shape.get("source_companion_id", ""), run.target_id)
                    if (frozen.get("category") != "BATCH_AUTH" or candidate is None or
                            candidate.plan_id != run.plan_id or
                            candidate.test_object_id != snapshot.data["request_templates"][0]["test_object_id"] or
                            shape.get("root_key") != frozen.get("batch_root_key") or
                            shape.get("id_type") != frozen.get("batch_id_type") or
                            shape.get("envelope") != frozen.get("batch_envelope") or
                            companion is None or source_companion is None or
                            self.objects.active_reservation(companion.id) != run.id or
                            self.objects.active_reservation(source_companion.id) != run.id or
                            (shape.get("variant") == "FOREIGN" and
                             descriptor.get("identity_id") != companion.creator_identity_id)):
                        raise ValueError("Observed API batch controls are no longer bound")
                    template, owned_hash = resolve_api_batch(
                        shape, package=package, run_id=run.id,
                        operations=self.api_operations, objects=self.objects,
                        traffic=self.traffic, evidence=self.evidence)
                else:
                    template, owned_hash = resolve_api_read(
                        shape, package=package, run_id=run.id,
                        operations=self.api_operations, objects=self.objects,
                        traffic=self.traffic, evidence=self.evidence)
                item = self.objects.get(shape["test_object_id"], run.target_id)
                variant = shape["variant"]
                if (item is None or descriptor.get("object_ref_hash") != owned_hash or
                        descriptor.get("object_type") != item.object_type or
                        descriptor.get("method") != template.method or
                        (variant == "FOREIGN") != (step.role == "BOUNDARY") or
                        (variant == "OWNER") != (step.role == "CONTROL") or
                        (variant == "INVALID_OBJECT") != (step.role == "OTHER") or
                        bool(descriptor.get("cross_identity")) != (variant == "FOREIGN") or
                        descriptor.get("control_kind") != (
                            "INVALID_OBJECT" if variant == "INVALID_OBJECT" else None) or
                        (variant == "FOREIGN" and
                         descriptor.get("identity_id") == item.creator_identity_id) or
                        (variant != "FOREIGN" and
                         descriptor.get("identity_id") != item.creator_identity_id)):
                    raise ValueError
            elif shape.get("binding") in {"AUTHORIZATION_OBJECT_PATH_V1",
                                        "EXPOSURE_OBJECT_PATH_V1",
                                        "AUTHORIZATION_GRAPHQL_QUERY_V1",
                                        "AUTHORIZATION_GRAPHQL_MUTATION_V1",
                                        "AUTHORIZATION_NESTED_PARENT_V1",
                                        "AUTHORIZATION_BATCH_PATH_V1"}:
                if self.objects is None or descriptor.get("simulation_only") is not True:
                    raise ValueError
                package = self.targets.get_target_package(run.package_id)
                if package is None or package.target.id != run.target_id:
                    raise ValueError
                resolver = (resolve_exposure_read if shape["binding"] == "EXPOSURE_OBJECT_PATH_V1"
                            else resolve_authorization_request)
                template, owned_hash = resolver(
                    shape, package=package, run_id=run.id, objects=self.objects,
                    traffic=self.traffic, evidence=self.evidence)
                item = self.objects.get(shape["test_object_id"], run.target_id)
                if item is None:
                    raise ValueError
                if shape["binding"] == "AUTHORIZATION_NESTED_PARENT_V1":
                    foreign_parent = self.objects.get(shape["foreign_parent_object_id"], run.target_id)
                    if (foreign_parent is None or
                            foreign_parent.creator_identity_id != descriptor.get("identity_id") or
                            foreign_parent.tenant_id == item.tenant_id):
                        raise ValueError
                if shape["binding"] == "AUTHORIZATION_BATCH_PATH_V1":
                    actor_object = self.objects.get(shape["actor_object_id"], run.target_id)
                    expected_actor = (item.creator_identity_id if shape["variant"] == "OWNER" else
                                      actor_object.creator_identity_id if actor_object else None)
                    if actor_object is None or descriptor.get("identity_id") != expected_actor:
                        raise ValueError
                variant = shape["variant"]
                if (descriptor.get("request_template_fingerprint") != shape["fingerprint"]
                        or descriptor.get("object_ref_hash") != owned_hash
                        or descriptor.get("object_type") != item.object_type
                        or descriptor.get("method") != template.method
                        or (variant in {"FOREIGN", "ANONYMOUS"}) != (step.role == "BOUNDARY")
                        or (variant == "INVALID_OBJECT") !=
                        (descriptor.get("control_kind") == "INVALID_OBJECT")
                        or (variant == "POST_READBACK") !=
                        (descriptor.get("control_kind") == "POST_READBACK")
                        or (variant == "OWNER") != (step.role == "CONTROL")
                        or (variant in {"INVALID_OBJECT", "POST_READBACK"}) !=
                        (step.role == "OTHER")
                        or bool(descriptor.get("cross_identity")) != (variant == "FOREIGN")
                        or (variant == "ANONYMOUS" and
                            (descriptor.get("identity_id") or descriptor.get("session_id")))
                        or (variant == "FOREIGN" and
                            descriptor.get("identity_id") == item.creator_identity_id)
                        or (variant in {"OWNER", "INVALID_OBJECT", "POST_READBACK"} and
                            descriptor.get("identity_id") != item.creator_identity_id)):
                    raise ValueError
            else:
                if (set(shape) - {"method", "url", "fingerprint", "authentication"} or
                        shape.get("authentication") != "EXECUTOR_SUPPLIED"):
                    raise ValueError
                template = RequestTemplate(shape["method"], shape["url"])
                if (template.fingerprint() != shape.get("fingerprint") or
                        template.fingerprint() != descriptor.get("request_template_fingerprint") or
                        template.method != descriptor.get("method") or
                        descriptor.get("simulation_only") is not True):
                    raise ValueError
            url = urlsplit(template.url)
            if (url.scheme not in {"http", "https"} or not url.hostname or url.query or url.fragment
                    or url.username or url.password or "[REDACTED]" in template.url
                    or SecretRedactor.from_environment().text(template.url) != template.url):
                raise ValueError
            category = ActionCategory(descriptor["category"])
            actor = ActorMode(descriptor["actor"])
            if category not in _ACTIVE or actor not in {ActorMode.ANONYMOUS, ActorMode.AUTHENTICATED}:
                raise ValueError
            if shape.get("binding") in {"API_OBSERVED_READ_V1", "API_OBSERVED_BATCH_V1"} and (
                    category is not (ActionCategory.AUTHORIZATION_TEST if
                                     shape["variant"] == "FOREIGN" or template.method == "POST"
                                     else ActionCategory.SAFE_READ) or
                    actor is not ActorMode.AUTHENTICATED):
                raise ValueError
            if shape.get("binding") in {"AUTHORIZATION_OBJECT_PATH_V1",
                                        "EXPOSURE_OBJECT_PATH_V1",
                                        "AUTHORIZATION_GRAPHQL_QUERY_V1",
                                        "AUTHORIZATION_GRAPHQL_MUTATION_V1",
                                        "AUTHORIZATION_NESTED_PARENT_V1",
                                        "AUTHORIZATION_BATCH_PATH_V1"}:
                expected_category = (ActionCategory.AUTHORIZATION_TEST if
                                     shape["variant"] in {"FOREIGN", "ANONYMOUS"} or
                                     shape["binding"] in {"AUTHORIZATION_GRAPHQL_QUERY_V1",
                                                           "AUTHORIZATION_GRAPHQL_MUTATION_V1"}
                                     else ActionCategory.SAFE_READ)
                if (category is not expected_category or
                        actor is not (ActorMode.ANONYMOUS if shape["variant"] == "ANONYMOUS"
                                      else ActorMode.AUTHENTICATED)):
                    raise ValueError
            if shape.get("binding") == "EXPOSURE_VHOST_V1" and (
                    category is not ActionCategory.SAFE_READ or actor is not ActorMode.ANONYMOUS
                    or descriptor.get("identity_id") or descriptor.get("session_id")):
                raise ValueError
            if shape.get("binding") == "EXPOSURE_HTTP_V1" and (
                    category is not ActionCategory.SAFE_READ or actor is not ActorMode.ANONYMOUS
                    or descriptor.get("identity_id") or descriptor.get("session_id")):
                raise ValueError
            identity_id = descriptor.get("identity_id")
            session_id = descriptor.get("session_id")
            if (actor is ActorMode.AUTHENTICATED and (not identity_id or not session_id)
                    or actor is ActorMode.ANONYMOUS and (identity_id or session_id)):
                raise ValueError
            vulnerability_class = descriptor.get("vulnerability_class")
            declared_classes = snapshot.data.get("vulnerability_classes")
            if (not isinstance(vulnerability_class, str) or
                    vulnerability_class not in {str(value).lower() for value in declared_classes}):
                raise ValueError
            action = ProposedAction(
                target_id=run.target_id, package_id=run.package_id, category=category, actor=actor,
                source="plan_orchestrator", purpose="Bound investigation plan step",
                url=template.url, method=template.method, hypothesis_id=run.hypothesis_id,
                identity_id=identity_id, session_id=session_id,
                operation=descriptor.get("operation"),
                object_type=descriptor.get("object_type"),
                object_ref_hash=descriptor.get("object_ref_hash"),
                disposable_intent=descriptor.get("disposable_intent", False),
                cross_identity=descriptor.get("cross_identity", False), id=step.action_id,
                side_effect_hint=resolved_mutation.recipe.side_effect if
                resolved_mutation is not None and template.method in {"PATCH", "PUT", "POST", "DELETE"} else None,
                vulnerability_class=vulnerability_class,
            )
            return _BoundAction(action, template, step.role, resolved_mutation)
        except (TypeError, KeyError, IndexError, ValueError):
            raise PlanRunError("request binding is incomplete or unsafe") from None

    def _result(self, step: RuntimeStep, summary: str, *, execution: ExecutionResult | None = None,
                evidence_ids: tuple[str, ...] = (), exchange_ids: tuple[str, ...] = (),
                error: str | None = None) -> StepResult:
        status = execution.status_code if execution else None
        body_hash = artifact_hash = None
        if exchange_ids:
            exchange = self.traffic.get_exchange(exchange_ids[-1])
            if exchange and exchange.response:
                body_hash = exchange.response.body_hash
                artifact_hash = exchange.response.record.artifact_hash
        duration = (int((execution.finished_at - execution.started_at).total_seconds() * 1000)
                    if execution else None)
        return StepResult("RESULT-" + uuid.uuid4().hex, step.id,
                          execution.execution_id if execution else None, exchange_ids, evidence_ids,
                          status, body_hash, artifact_hash, duration, error, summary,
                          datetime.now(timezone.utc).isoformat())

    def _finish(self, run: PlanRun, step: RuntimeStep, *, status: RuntimeStepStatus,
                reason: str, result: StepResult | None = None, consumed: int = 0,
                waiting: RunStatus | None = None, prereq_state: str | None = None,
                approval_id: str | None = None) -> dict[str, object]:
        following = step.ordinal + 1 < len(self.runs.steps(run.id))
        run_status = waiting or (RunStatus.READY if following else RunStatus.COMPLETED)
        updated = self.runs.finish(run.id, step.id, step_status=status,
                                   run_status=run_status, reason=reason, result=result,
                                   consumed=consumed, approval_id=approval_id,
                                   prerequisite_state=prereq_state,
                                   advance=status is RuntimeStepStatus.COMPLETED)
        if self.objects and updated.status in _TERMINAL:
            try:
                self._reconcile_delete_cleanup(updated)
            finally:
                self.objects.release_run(updated.id, updated.target_id)
        return self.runs.details(updated)

    def _reconcile_delete_cleanup(self, run: PlanRun) -> None:
        if self.objects is None or self.recipes is None or self.mutations is None:
            return
        snapshot = self.runs.snapshot(run.plan_id, run.target_id)
        shapes = snapshot.data.get("request_templates", [])
        if (len(shapes) != 8 or shapes[0].get("mutation_type") != "DELETE_DISPOSABLE" or
                tuple(shape.get("stage") for shape in shapes) !=
                ("BEFORE_READ", "OWNER_MUTATE", "OWNER_READBACK",
                 "TARGET_BEFORE_READ", "BOUNDARY_MUTATE", "BOUNDARY_READBACK",
                 "RESTORE", "RESTORE_READBACK")):
            return
        package = self.targets.get_target_package(run.package_id)
        if package is None:
            return
        indexed = {step.action_slot: step for step in self.runs.steps(run.id)
                   if step.action_slot is not None}
        try:
            bound = {slot: resolve_mutation_stage(
                shapes[slot], package=package, run_id=run.id, objects=self.objects,
                recipes=self.recipes, evidence=self.evidence)
                     for slot in (0, 2, 3, 5, 7)}
            control = bound[2].item
            target = bound[7].item
            results = {slot: self.runs.result(indexed[slot].id)
                       for slot in (0, 2, 3, 5, 7)}
            owner_write = self.mutations.for_phase(run.id, control.id,
                                                   MutationPhase.OWNER_CONTROL)
            boundary_write = self.mutations.for_phase(run.id, target.id,
                                                      MutationPhase.BOUNDARY)
            cleanup_write = self.mutations.for_phase(run.id, target.id,
                                                     MutationPhase.RESTORE)
            def observed(slot: int) -> str | None:
                result = results[slot]
                if result is None or len(result.exchange_ids) != 1:
                    return None
                return self._mutation_readback(bound[slot], result.exchange_ids[0])

            control_clean = (owner_write is not None and owner_write.verified_effect and
                             observed(0) == "present" and observed(2) == "absent")
            target_clean = (control_clean and boundary_write is not None and
                            boundary_write.status in {MutationStatus.VERIFIED,
                                                      MutationStatus.DENIED} and
                            ((cleanup_write is not None and
                              cleanup_write.status in {MutationStatus.VERIFIED,
                                                       MutationStatus.DENIED} and
                              cleanup_write.after_value_hash == value_hash("absent")) or
                             (cleanup_write is None and boundary_write.verified_effect and
                              indexed[6].safe_reason == "DELETE_ALREADY_ABSENT")) and
                            observed(3) == "present" and
                            observed(5) in {"present", "absent"} and
                            observed(7) == "absent")
            for item, slot, clean in ((control, 2, control_clean),
                                      (target, 7, target_clean)):
                if not clean:
                    continue
                result = results[slot]
                assert result is not None
                self.objects.transition(
                    item.id, run.target_id, frozenset({ObjectState.IN_USE}),
                    ObjectState.CLEANED, "PLAN_DELETE_ABSENCE_VERIFIED",
                    action_id=indexed[slot].action_id,
                    exchange_id=result.exchange_ids[0],
                    evidence_ids=result.evidence_ids[:16],
                    source="PLAN_ORCHESTRATOR")
        except (KeyError, TypeError, ValueError, LookupError):
            return

    def _record_execution_evidence(self, run: PlanRun, step: RuntimeStep,
                                   execution: ExecutionResult) -> tuple[str, ...]:
        payload = {"execution_id": execution.execution_id, "action_id": execution.action_id,
                   "decision_id": execution.decision_id, "permit_id": execution.permit_id,
                   "approval_id": execution.approval_id, "exchange_ids": execution.exchange_ids,
                   "status_code": execution.status_code,
                   "error_class": execution.error.value if execution.error else None}
        record = self.evidence.create_evidence(
            EvidenceType.EXPERIMENT_RESULT,
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
            source="plan_orchestrator", target_ref=run.target_id,
            provenance=EvidenceProvenance("BUGHUNTER", "plan_step", step.id),
            sensitivity=Sensitivity.INTERNAL)
        return tuple(dict.fromkeys((*execution.evidence_ids, record.evidence_id)))[:16]

    def _mutation_readback(self, bound: ResolvedMutationStage,
                           exchange_id: str | None) -> str | None:
        if not exchange_id or self.recipes is None:
            return None
        exchange = self.traffic.get_exchange(exchange_id)
        recipe = self.recipes.get(bound.item.package_id, bound.item.recipe_id)
        deleting = bound.recipe.mutation_type is MutationType.DELETE_DISPOSABLE
        if (exchange is None or recipe is None or recipe.sha256 != bound.item.recipe_hash or
                exchange.target_id != bound.item.target_id or exchange.response is None or
                exchange.request.record.method != "GET" or
                not bound.item.external_id_evidence_id):
            return None
        if deleting and exchange.response.record.status_code in {404, 410}:
            return "absent"
        if (exchange.response.record.status_code != 200 or
                not exchange.response.body_evidence_id):
            return None
        response_ref = exchange.response.body_evidence_id
        record = self.evidence.get_evidence(response_ref)
        if (record is None or record.target_ref != bound.item.target_id or
                record.redaction_status.value != "ORIGINAL" or record.content_size > 8192):
            return None
        try:
            content = self.evidence.read_content(response_ref, allow_sensitive=True, max_bytes=8192)
            if hashlib.sha256(content).hexdigest() != exchange.response.body_hash:
                return None
            data = json.loads(content, object_pairs_hook=unique_json_pairs)
            external = self.evidence.read_content(bound.item.external_id_evidence_id,
                                                  allow_sensitive=True, max_bytes=256).decode("ascii")
            if (json_pointer(data, recipe.verify_id_pointer) != external or
                    json_pointer(data, recipe.verify_owner_pointer) != recipe.expected_owner or
                    json_pointer(data, recipe.verify_tenant_pointer) != recipe.expected_tenant):
                return None
            if deleting:
                return "present"
            value = json_pointer(data, bound.recipe.readback_pointer)
            return value if isinstance(value, str) and len(value) <= 80 else None
        except (KeyError, IndexError, TypeError, ValueError, UnicodeError, PermissionError):
            return None

    def _recover_ambiguous_mutation(self, run: PlanRun, snapshot: PlanSnapshot,
                                    step: RuntimeStep, action: ProposedAction,
                                    mutation: ResolvedMutationStage,
                                    mutation_id: str) -> ExecutionResult | None:
        """One owner GET may clarify a lost response; the write is never replayed."""
        if (self.objects is None or self.recipes is None or self.mutations is None or
                run.request_budget - run.requests_consumed < 2):
            return None
        try:
            owner = snapshot.data["proposed_actions"][0]
            if (not isinstance(owner, dict) or
                    owner.get("identity_id") != mutation.item.creator_identity_id or
                    not isinstance(owner.get("session_id"), str)):
                return None
            shape = dict(snapshot.data["request_templates"][step.action_slot])
            shape["stage"] = (
                MutationStage.BOUNDARY_READBACK.value
                if mutation.recipe.mutation_type is MutationType.DELETE_DISPOSABLE and
                mutation.stage is MutationStage.BOUNDARY_MUTATE else
                MutationStage.RESTORE_READBACK.value
                if mutation.recipe.mutation_type is MutationType.DELETE_DISPOSABLE and
                mutation.stage is MutationStage.RESTORE else
                MutationStage.OWNER_READBACK.value)
            shape["method"] = "GET"
            shape["fingerprint"] = mutation_fingerprint(shape)
            package = self.targets.get_target_package(run.package_id)
            if package is None:
                return None
            resolved = resolve_mutation_stage(
                shape, package=package, run_id=run.id, objects=self.objects,
                recipes=self.recipes, evidence=self.evidence)
            recovery = replace(
                action, id=new_action_id(), actor=ActorMode.AUTHENTICATED,
                identity_id=owner["identity_id"], session_id=owner["session_id"],
                category=ActionCategory.SAFE_READ, method="GET",
                url=resolved.template.url, operation=resolved.recipe.readback.operation,
                cross_identity=False, side_effect_hint=None)
            decision = self.policy.evaluate(package, recovery, record=True)
            if decision.result is not PolicyDecision.ALLOW:
                return None
            permit = self.executor.authorize(recovery, resolved.template)
            observed = self.executor.execute(
                recovery, permit, resolved.template, experiment_id=run.id,
                budget=ExperimentBudget(max_requests=run.request_budget), max_dispatches=1,
                continue_dispatch=lambda: self.runs.should_dispatch(run.id),
                on_dispatch=lambda exchange_id: self.runs.account_dispatch(
                    run.id, step.id, exchange_id))
            allowed_status = ({200, 404, 410} if mutation.recipe.mutation_type is
                              MutationType.DELETE_DISPOSABLE else {200})
            if (observed.error is None and observed.status_code in allowed_status and
                    len(observed.exchange_ids) == 1):
                value = self._mutation_readback(resolved, observed.exchange_ids[0])
                self.mutations.readback(
                    mutation_id, run.target_id, action_id=recovery.id,
                    exchange_id=observed.exchange_ids[0], observed_value=value,
                    evidence_ids=self._record_execution_evidence(run, step, observed)[:8])
            return observed
        except (KeyError, IndexError, TypeError, ValueError, LookupError):
            return None

    def advance(self, run_id: str, package_id: str) -> dict[str, object]:
        run, snapshot = self._load(run_id, package_id)
        if self.objects and run.status is RunStatus.CHECKING_PREREQUISITES:
            if not self.objects.reserve_requirements(run.id, run.target_id):
                return self.runs.details(run)
            ready = self.runs.transition(run.id, run.target_id, RunStatus.READY,
                                         "OBJECT_PREREQUISITES_READY",
                                         expected=frozenset({RunStatus.CHECKING_PREREQUISITES}))
            return self.runs.details(ready)
        if run.status not in {RunStatus.CREATED, RunStatus.READY}:
            raise PlanRunError("run is not ready for a step")
        if self.objects and self.objects.requirements(run.plan_id, run.target_id):
            if not self.objects.reserved_for_run(run.id, run.target_id):
                waiting = self.runs.transition(run.id, run.target_id,
                                               RunStatus.CHECKING_PREREQUISITES,
                                               "OBJECT_RESERVATION_MISSING",
                                               expected=frozenset({run.status}))
                return self.runs.details(waiting)
        step = self.runs.current_step(run)
        if step is None:
            raise PlanRunError("no pending step")
        if not self.runs.claim(run, step):
            raise PlanRunError("another plan step is active")
        try:
            package, context, prereq = self._current(run, snapshot)
            if prereq.state is not PrerequisiteState.READY:
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="PREREQUISITES_STALE", waiting=RunStatus.BLOCKED,
                                    prereq_state=prereq.state.value)
            if step.type == RuntimeStepType.CHECK_PREREQUISITES.value:
                return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                    reason="PREREQUISITES_CURRENT", prereq_state=prereq.state.value,
                                    result=self._result(step, "Current prerequisites are present."))
            if step.type == RuntimeStepType.PASSIVE_OBSERVATION.value:
                refs = tuple(item["id"] for item in context.evidence)
                if not refs and not context.facts and not context.traffic:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="HUMAN_OBSERVATION_REQUIRED", waiting=RunStatus.WAITING_HUMAN)
                return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                    reason="METADATA_OBSERVED", result=self._result(
                                        step, "Existing evidence or traffic metadata inspected.", evidence_ids=refs))
            if (step.type == RuntimeStepType.ESTABLISH_CONTROL.value
                    and snapshot.data.get("skill_id") == "check-before-transform-dom-xss"
                    and isinstance(snapshot.data.get("dom_binding"), dict)):
                return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                    reason="DOM_CONTROLS_FROZEN", result=self._result(
                                        step, "Inert, benign, direct-dangerous, and transform-derived controls frozen."))
            if (step.type == RuntimeStepType.ESTABLISH_CONTROL.value
                    and snapshot.data.get("skill_id") == "postmessage-trust-analysis"
                    and isinstance(snapshot.data.get("message_binding"), dict)):
                return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                    reason="MESSAGE_CONTROLS_FROZEN", result=self._result(
                                        step, "No-message, wrong-type, trusted, foreign-origin, source, and port controls frozen."))
            if (step.type == RuntimeStepType.ESTABLISH_CONTROL.value
                    and snapshot.data.get("skill_id") == "credential-disclosure"):
                if not self._exposure_binding_valid(package, snapshot.data.get("exposure_binding")):
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="EXPOSURE_ARTIFACT_STALE", waiting=RunStatus.BLOCKED)
                return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                    reason="EXPOSURE_ARTIFACT_FROZEN", result=self._result(
                                        step, "Current protected artifact and credential fingerprint bound."))
            if step.type == RuntimeStepType.VERIFY_BROWSER.value:
                if snapshot.data.get("skill_id") == "postmessage-trust-analysis":
                    frozen = snapshot.data.get("message_binding")
                    if self.messages is None or not isinstance(frozen, dict):
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="MESSAGE_EXECUTOR_UNAVAILABLE", waiting=RunStatus.BLOCKED)
                    try:
                        binding = MessageExperimentBinding(
                            candidate_id=frozen["candidate_id"], run_id=run.id,
                            browser_session_id=frozen["browser_session_id"],
                            route_url=frozen["route_url"], asset_url=frozen["asset_url"],
                            activation_type=frozen["activation_type"],
                            port_type=frozen["port_type"] or None,
                            allowed_method=frozen["allowed_method"] or None,
                            identity_id=frozen["identity_id"] or None,
                            window_mode=frozen["window_mode"],
                            dom_field=frozen.get("dom_field") or None,
                            owned_object_id=frozen.get("owned_object_id") or None,
                            owned_canary_sha256=frozen.get("owned_canary_sha256") or None,
                            owned_verified_at=frozen.get("owned_verified_at") or None,
                        )
                        proof = self.messages.run(run.package_id, binding)
                    except (BrowserError, KeyError, TypeError, ValueError):
                        consumed = self.runs.message_dispatch_count(run.id, step.id)
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="MESSAGE_RUNTIME_PREREQUISITE_FAILED",
                                            waiting=RunStatus.BLOCKED, consumed=consumed)
                    refs = tuple(item.evidence_id for item in proof.trials)
                    if proof.status == "BLOCKED":
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="MESSAGE_BROWSER_POLICY_BLOCKED",
                                            waiting=RunStatus.BLOCKED,
                                            result=self._result(step, "Messaging browser proof blocked.",
                                                                evidence_ids=refs),
                                            consumed=len(proof.trials))
                    return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                        reason="MESSAGE_BROWSER_" + proof.status,
                                        result=self._result(step, "Bounded messaging browser result: " + proof.status,
                                                            evidence_ids=refs), consumed=len(proof.trials))
                frozen = snapshot.data.get("dom_binding")
                if (self.dom is None or snapshot.data.get("skill_id") != "check-before-transform-dom-xss"
                        or not isinstance(frozen, dict)):
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="DOM_EXECUTOR_UNAVAILABLE", waiting=RunStatus.BLOCKED)
                try:
                    binding = DOMExperimentBinding(
                        candidate_id=frozen["candidate_id"], run_id=run.id,
                        browser_session_id=frozen["browser_session_id"],
                        route_url=frozen["route_url"], asset_url=frozen["asset_url"],
                        input_kind=DOMInputKind(frozen["input_kind"]),
                        input_name=frozen["input_name"] or None,
                    )
                    proof = self.dom.run(run.package_id, binding)
                except (KeyError, TypeError, ValueError):
                    consumed = self.runs.dom_dispatch_count(run.id, step.id)
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="DOM_RUNTIME_PREREQUISITE_FAILED", waiting=RunStatus.BLOCKED,
                                        consumed=consumed)
                refs = tuple(item.evidence_id for item in proof.trials)
                if proof.status == "BLOCKED":
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="DOM_BROWSER_POLICY_BLOCKED", waiting=RunStatus.BLOCKED,
                                        result=self._result(step, "Browser request gate blocked the proof.",
                                                            evidence_ids=refs), consumed=len(proof.trials))
                return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                    reason="DOM_BROWSER_" + proof.status,
                                    result=self._result(step, "Bounded DOM browser result: " + proof.status,
                                                        evidence_ids=refs), consumed=len(proof.trials))
            if step.type == RuntimeStepType.COMPARE_METADATA.value:
                if snapshot.data.get("skill_id") == "protected-response-exposure":
                    proof_step = next((item for item in self.runs.steps(run.id)
                                       if item.action_slot == 0), None)
                    proof = self.runs.result(proof_step.id) if proof_step else None
                    if proof is None or not proof.exchange_ids:
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="EXPOSURE_CURRENT_RESPONSE_MISSING",
                                            waiting=RunStatus.BLOCKED)
                    return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                        reason="EXPOSURE_RESPONSE_COMPARED",
                                        result=self._result(step, "Current response metadata recorded.",
                                                            evidence_ids=proof.evidence_ids[:8]))
                if snapshot.data.get("skill_id") == "credential-disclosure":
                    frozen = snapshot.data.get("exposure_binding")
                    if not self._exposure_binding_valid(package, frozen):
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="EXPOSURE_ARTIFACT_STALE", waiting=RunStatus.BLOCKED)
                    candidate = self.exposure.current_candidate(package, frozen["candidate_id"])
                    assert candidate is not None
                    return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                        reason="EXPOSURE_CONTROLS_COMPARED", result=self._result(
                                            step, "Currentness, public-identifier, and placeholder controls recorded.",
                                            evidence_ids=candidate.evidence_ids[:8]))
                if snapshot.data.get("skill_id") == "postmessage-trust-analysis":
                    proof_step = next((item for item in self.runs.steps(run.id)
                                       if item.type == RuntimeStepType.VERIFY_BROWSER.value), None)
                    proof_result = self.runs.result(proof_step.id) if proof_step else None
                    if proof_result is None:
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="MESSAGE_PROOF_RESULT_MISSING", waiting=RunStatus.BLOCKED)
                    return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                        reason="MESSAGE_CONTROLS_COMPARED",
                                        result=self._result(step, "Messaging controls and proof metadata recorded.",
                                                            evidence_ids=proof_result.evidence_ids))
                if snapshot.data.get("skill_id") == "check-before-transform-dom-xss":
                    proof_step = next((item for item in self.runs.steps(run.id)
                                       if item.type == RuntimeStepType.VERIFY_BROWSER.value), None)
                    proof_result = self.runs.result(proof_step.id) if proof_step else None
                    if proof_result is None:
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="DOM_PROOF_RESULT_MISSING", waiting=RunStatus.BLOCKED)
                    return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                        reason="DOM_CONTROLS_COMPARED",
                                        result=self._result(step, "Browser controls and proof metadata recorded.",
                                                            evidence_ids=proof_result.evidence_ids))
                pairs = snapshot.data.get("comparison_pairs", [])
                if not isinstance(pairs, list) or not pairs:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="COMPARISON_BINDING_REQUIRED", waiting=RunStatus.WAITING_HUMAN)
                pair = pairs[0]
                if (not isinstance(pair, dict) or type(pair.get("control_slot")) is not int or
                        type(pair.get("boundary_slot")) is not int):
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="COMPARISON_BINDING_INVALID", waiting=RunStatus.BLOCKED)
                indexed = {item.action_slot: item for item in self.runs.steps(run.id)
                           if item.action_slot is not None}
                control = indexed.get(pair["control_slot"])
                boundary = indexed.get(pair["boundary_slot"])
                first = self.runs.result(control.id) if control else None
                second = self.runs.result(boundary.id) if boundary else None
                if not first or not second:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="COMPARISON_INPUTS_MISSING", waiting=RunStatus.WAITING_HUMAN)
                same = first.response_hash == second.response_hash if first.response_hash and second.response_hash else None
                summary = ("Metadata comparison recorded: status_equal=" +
                           str(first.status_code == second.status_code) + ", hash_equal=" + str(same))
                result = self._result(step, summary,
                                      evidence_ids=tuple(dict.fromkeys((*first.evidence_ids,
                                                                        *second.evidence_ids)))[:16],
                                      exchange_ids=(*first.exchange_ids, *second.exchange_ids)[:16])
                return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                    reason="METADATA_COMPARED", result=result)
            if step.type != RuntimeStepType.EXECUTE_REQUEST.value:
                reason = ("HUMAN_REVIEW_REQUIRED" if step.type in {
                    RuntimeStepType.ESTABLISH_CONTROL.value, RuntimeStepType.MANUAL_REVIEW.value}
                          else "BLOCKED_UNSUPPORTED")
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason=reason, waiting=(RunStatus.WAITING_HUMAN
                                                            if reason == "HUMAN_REVIEW_REQUIRED"
                                                            else RunStatus.BLOCKED))
            if run.requests_consumed >= run.request_budget:
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="REQUEST_BUDGET_EXHAUSTED", waiting=RunStatus.BUDGET_EXHAUSTED)
            try:
                bound = self._bound(snapshot, step, run)
            except PlanRunError:
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="ACTION_BINDING_INVALID", waiting=RunStatus.BLOCKED)
            action, template = bound.action, bound.template
            mutation = bound.mutation
            if (mutation is not None and self.mutations is not None and
                    mutation.recipe.mutation_type is MutationType.DELETE_DISPOSABLE and
                    mutation.stage is MutationStage.RESTORE):
                boundary_record = self.mutations.for_phase(
                    run.id, mutation.item.id, MutationPhase.BOUNDARY)
                boundary_step = next((item for item in self.runs.steps(run.id)
                                      if item.action_slot == 5), None)
                boundary_result = self.runs.result(boundary_step.id) if boundary_step else None
                if (boundary_record is not None and boundary_record.verified_effect and
                        boundary_result is not None and len(boundary_result.exchange_ids) == 1 and
                        self._mutation_readback(
                            mutation, boundary_result.exchange_ids[0]) == "absent"):
                    return self._finish(
                        run, step, status=RuntimeStepStatus.COMPLETED,
                        reason="DELETE_ALREADY_ABSENT",
                        result=self._result(step, "No cleanup write; owner read-back proved absence.",
                                            evidence_ids=boundary_result.evidence_ids[:8]))
            token_header = (mutation.recipe.csrf_header if mutation is not None and
                            template.method in {"PATCH", "PUT", "POST", "DELETE"} else None)
            if token_header is not None and self.executor.token_resolver is None:
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="BLOCKED_TOKEN_REQUIRED", waiting=RunStatus.BLOCKED)
            if mutation is not None and self.mutations is not None:
                stage = mutation.stage
                if stage is MutationStage.OWNER_MUTATE:
                    baseline = next((item for item in self.runs.steps(run.id)
                                     if item.action_slot == 0), None)
                    result = self.runs.result(baseline.id) if baseline else None
                    observed = self._mutation_readback(
                        mutation, result.exchange_ids[-1] if result and result.exchange_ids else None)
                    baseline = ("present" if mutation.recipe.mutation_type is MutationType.DELETE_DISPOSABLE
                                else mutation.item.test_name)
                    if observed != baseline:
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="OWNER_BASELINE_UNVERIFIED", waiting=RunStatus.BLOCKED)
                if stage is MutationStage.BOUNDARY_MUTATE:
                    control_item = mutation.delete_control_item or mutation.item
                    control = self.mutations.for_phase(run.id, control_item.id,
                                                       MutationPhase.OWNER_CONTROL)
                    if control is None or not control.verified_effect:
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="OWNER_MUTATION_CONTROL_UNVERIFIED",
                                            waiting=RunStatus.BLOCKED)
                    if mutation.recipe.mutation_type is MutationType.DELETE_DISPOSABLE:
                        target_step = next((item for item in self.runs.steps(run.id)
                                            if item.action_slot == 3), None)
                        target_result = self.runs.result(target_step.id) if target_step else None
                        if (target_result is None or not target_result.exchange_ids or
                                self._mutation_readback(
                                    mutation, target_result.exchange_ids[-1]) != "present"):
                            return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                                reason="TARGET_BASELINE_UNVERIFIED",
                                                waiting=RunStatus.BLOCKED)
                if stage is MutationStage.RESTORE:
                    control_item = mutation.delete_control_item or mutation.item
                    control = self.mutations.for_phase(run.id, control_item.id,
                                                       MutationPhase.OWNER_CONTROL)
                    boundary = self.mutations.for_phase(run.id, mutation.item.id,
                                                        MutationPhase.BOUNDARY)
                    if control is None or not control.verified_effect or boundary is None:
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="RESTORE_STATE_UNKNOWN", waiting=RunStatus.BLOCKED)
            if action.actor is ActorMode.AUTHENTICATED:
                matched = any(identity["id"] == action.identity_id and
                              identity["verified_session_id"] == action.session_id
                              for identity in context.identities)
                auth = self.executor.auth.get(run.target_id, action.identity_id)
                ready = bool(matched and auth is not None and
                             auth.status is AuthStatus.VALID and
                             auth.browser_session_ref == action.session_id and
                             (auth.expires_at is None or
                              auth.expires_at > datetime.now(timezone.utc)))
                if ready and auth is not None and auth.mechanism is AuthMechanism.MANUAL_LOGIN:
                    browser = self.executor.browser
                    try:
                        session = (browser.session_context(action.session_id)
                                   if browser is not None and action.session_id else None)
                    except (BrowserError, ValueError):
                        session = None
                    ready = bool(session is not None and
                                 session.target_id == run.target_id and
                                 session.identity_id == action.identity_id and
                                 session.auth_context_id == auth.id and
                                 session.browser_status is BrowserStatus.VALID and
                                 session.verification_status is VerificationStatus.MATCH and
                                 session.authentication_status == "VALID" and
                                 session.browser_available and
                                 session.proxy_capture_required)
                elif ready:
                    ready = bool(auth and auth.secret_ref)
                if not ready:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="BOUND_IDENTITY_UNVERIFIED", waiting=RunStatus.BLOCKED)
            if self.policy.rate is not None:
                deadline = time.monotonic() + 61.0
                while True:
                    delay = self.policy.rate.retry_after_seconds(
                        action.target_id, package.rate)
                    if delay is None or delay <= 0:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(max(0.01, delay + 0.01), remaining))
            decision = self.policy.evaluate(package, action, record=True)
            self.runs.policy(run.id, step.id, decision.id, decision.approval_id, decision.reason_code)
            if decision.result is PolicyDecision.DENY:
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="POLICY_DENIED", waiting=RunStatus.BLOCKED)
            if decision.result is PolicyDecision.REQUIRE_APPROVAL:
                return self._finish(run, step, status=RuntimeStepStatus.WAITING_APPROVAL,
                                    reason="APPROVAL_REQUIRED", waiting=RunStatus.WAITING_APPROVAL,
                                    approval_id=decision.approval_id)
            try:
                permit = self.executor.authorize(action, template)
            except ValueError:
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="PERMIT_NOT_ISSUED", waiting=RunStatus.BLOCKED)
            execution_id = "EXEC-" + uuid.uuid4().hex
            self.runs.permit(run.id, step.id, permit.id, execution_id)
            mutation_record = None
            if mutation is not None and self.mutations is not None and mutation.stage in {
                    MutationStage.OWNER_MUTATE, MutationStage.BOUNDARY_MUTATE,
                    MutationStage.RESTORE}:
                phase = (MutationPhase.OWNER_CONTROL if mutation.stage is MutationStage.OWNER_MUTATE
                         else MutationPhase.BOUNDARY if mutation.stage is MutationStage.BOUNDARY_MUTATE
                         else MutationPhase.RESTORE)
                before_value = mutation.before_value
                if phase is MutationPhase.RESTORE:
                    boundary_record = self.mutations.for_phase(run.id, mutation.item.id,
                                                               MutationPhase.BOUNDARY)
                    if boundary_record and boundary_record.verified_effect:
                        before_value = ("absent" if mutation.recipe.mutation_type is
                                        MutationType.DELETE_DISPOSABLE else
                                        TypedMutation.test_value(run.id, mutation.item.id,
                                                                 MutationPhase.BOUNDARY))
                mutation_record = self.mutations.start(
                    mutation.typed_mutation(action.identity_id or "", action.operation or ""),
                    run_id=run.id, phase=phase, action_id=step.action_id,
                    before_value=before_value)
            remaining = run.request_budget - run.requests_consumed
            execution = self.executor.execute(
                action, permit, template, experiment_id=run.id,
                budget=ExperimentBudget(max_requests=run.request_budget),
                max_dispatches=remaining, execution_id=execution_id,
                continue_dispatch=lambda: self.runs.should_dispatch(run.id),
                on_dispatch=lambda exchange_id: self.runs.account_dispatch(
                    run.id, step.id, exchange_id), token_header=token_header,
                artifact_capture_kind=("EXPOSURE" if
                                       snapshot.data.get("skill_id") in {
                                           "internal-vhost-access", "protected-response-exposure"}
                                       else None))
            evidence_ids = self._record_execution_evidence(run, step, execution)
            result = self._result(step, "HTTP observation recorded." if execution.error is None else
                                  "Execution ended with a classified error.",
                                  execution=execution, evidence_ids=evidence_ids,
                                  exchange_ids=execution.exchange_ids,
                                  error=execution.error.value if execution.error else None)
            consumed = len(execution.exchange_ids)
            if mutation_record is not None and self.mutations is not None and consumed:
                self.mutations.dispatched(mutation_record.id, run.target_id,
                                          execution.exchange_ids[-1] if execution.exchange_ids else None,
                                          ambiguous=bool(execution.error and consumed))
            if execution.error is not None:
                mutating = template.method not in {"GET", "HEAD", "OPTIONS"}
                if mutating and consumed and mutation is not None and mutation_record is not None:
                    recovery = self._recover_ambiguous_mutation(
                        run, snapshot, step, action, mutation, mutation_record.id)
                    extra = len(recovery.exchange_ids) if recovery is not None else 0
                    combined = self._result(
                        step, "Mutation response lost; owner read-back attempted without replay.",
                        execution=execution, evidence_ids=evidence_ids,
                        exchange_ids=(*execution.exchange_ids,
                                      *(recovery.exchange_ids if recovery else ())),
                        error=execution.error.value)
                    return self._finish(run, step, status=RuntimeStepStatus.FAILED,
                                        reason="AMBIGUOUS_MUTATION_READBACK" if extra else
                                        "AMBIGUOUS_MUTATION", result=combined,
                                        consumed=consumed + extra, waiting=RunStatus.WAITING_HUMAN)
                if execution.error in {ExecutionError.PROXY_UNAVAILABLE, ExecutionError.DIRECT_DISABLED}:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="CAPTURE_UNAVAILABLE" if execution.error is
                                        ExecutionError.PROXY_UNAVAILABLE else "DIRECT_EXECUTION_DISABLED",
                                        result=result, consumed=consumed, waiting=RunStatus.BLOCKED)
                if execution.error is ExecutionError.OPERATOR_STOPPED:
                    return self._finish(run, step, status=RuntimeStepStatus.FAILED,
                                        reason="OPERATOR_STOPPED", result=result, consumed=consumed,
                                        waiting=RunStatus.WAITING_HUMAN)
                if execution.error is ExecutionError.BUDGET_EXHAUSTED:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="REQUEST_BUDGET_EXHAUSTED", result=result, consumed=consumed,
                                        waiting=RunStatus.BUDGET_EXHAUSTED)
                if execution.error is ExecutionError.TOKEN_REQUIRED:
                    return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                        reason="BLOCKED_TOKEN_REQUIRED", result=result,
                                        consumed=consumed, waiting=RunStatus.BLOCKED)
                return self._finish(run, step, status=RuntimeStepStatus.FAILED,
                                    reason="AMBIGUOUS_MUTATION" if mutating and consumed else
                                    "EXECUTION_FAILED", result=result, consumed=consumed,
                                    waiting=RunStatus.WAITING_HUMAN if mutating and consumed else RunStatus.FAILED)
            if mutation is not None and self.mutations is not None and mutation.stage in {
                    MutationStage.BEFORE_READ, MutationStage.TARGET_BEFORE_READ,
                    MutationStage.OWNER_READBACK,
                    MutationStage.BOUNDARY_READBACK, MutationStage.RESTORE_READBACK}:
                observed = self._mutation_readback(
                    mutation, execution.exchange_ids[-1] if execution.exchange_ids else None)
                if mutation.stage in {MutationStage.BEFORE_READ,
                                      MutationStage.TARGET_BEFORE_READ}:
                    baseline = ("present" if mutation.recipe.mutation_type is MutationType.DELETE_DISPOSABLE
                                else mutation.item.test_name)
                    if observed != baseline:
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason=("TARGET_BASELINE_UNVERIFIED" if mutation.stage is
                                                    MutationStage.TARGET_BEFORE_READ else
                                                    "OWNER_BASELINE_UNVERIFIED"), result=result,
                                            consumed=consumed, waiting=RunStatus.BLOCKED)
                else:
                    phase = (MutationPhase.OWNER_CONTROL if mutation.stage is MutationStage.OWNER_READBACK
                             else MutationPhase.BOUNDARY if mutation.stage is MutationStage.BOUNDARY_READBACK
                             else MutationPhase.RESTORE)
                    record = self.mutations.for_phase(run.id, mutation.item.id, phase)
                    if (record is None and mutation.stage is MutationStage.RESTORE_READBACK and
                            mutation.recipe.mutation_type is MutationType.DELETE_DISPOSABLE):
                        skipped = next((item for item in self.runs.steps(run.id)
                                        if item.action_slot == 6), None)
                        boundary_record = self.mutations.for_phase(
                            run.id, mutation.item.id, MutationPhase.BOUNDARY)
                        if (skipped is not None and skipped.status is RuntimeStepStatus.COMPLETED and
                                skipped.safe_reason == "DELETE_ALREADY_ABSENT" and
                                boundary_record is not None and boundary_record.verified_effect and
                                observed == "absent"):
                            return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                                reason="DELETE_FINAL_ABSENCE_VERIFIED",
                                                result=result, consumed=consumed)
                    if record is None or not execution.exchange_ids:
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="MUTATION_READBACK_MISSING", result=result,
                                            consumed=consumed, waiting=RunStatus.BLOCKED)
                    verified = self.mutations.readback(
                        record.id, run.target_id, action_id=step.action_id,
                        exchange_id=execution.exchange_ids[-1], observed_value=observed,
                        evidence_ids=result.evidence_ids[:8])
                    if mutation.stage is MutationStage.OWNER_READBACK and not verified.verified_effect:
                        return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                            reason="OWNER_MUTATION_CONTROL_UNVERIFIED", result=result,
                                            consumed=consumed, waiting=RunStatus.BLOCKED)
                    delete_absent = (mutation.recipe.mutation_type is MutationType.DELETE_DISPOSABLE and
                                     verified.after_value_hash == value_hash("absent") and
                                     verified.status in {MutationStatus.VERIFIED, MutationStatus.DENIED})
                    if (mutation.stage is MutationStage.RESTORE_READBACK and
                            not (verified.verified_effect or delete_absent)):
                        return self._finish(run, step, status=RuntimeStepStatus.FAILED,
                                            reason="RESTORE_UNVERIFIED", result=result,
                                            consumed=consumed, waiting=RunStatus.WAITING_HUMAN)
            delete_absence = (mutation is not None and
                              mutation.recipe.mutation_type is MutationType.DELETE_DISPOSABLE and
                              mutation.stage is MutationStage.OWNER_READBACK and
                              execution.status_code in {404, 410})
            if step.role == "CONTROL" and not delete_absence and (
                    execution.status_code is None or not 200 <= execution.status_code < 300):
                return self._finish(run, step, status=RuntimeStepStatus.BLOCKED,
                                    reason="CONTROL_NOT_SUCCESSFUL", result=result, consumed=consumed,
                                    waiting=RunStatus.BLOCKED)
            return self._finish(run, step, status=RuntimeStepStatus.COMPLETED,
                                reason="EXECUTION_RECORDED", result=result, consumed=consumed)
        except Exception:
            # Never let an in-process error make the next call silently replay a step.
            current = self.runs.current_step(run)
            if current and current.status is RuntimeStepStatus.EXECUTING:
                self.runs.reconcile()
                if self.mutations is not None:
                    self.mutations.reconcile()
                updated = self.runs.get(run.id, run.target_id)
                assert updated is not None
                return self.runs.details(updated)
            raise

    def resume(self, run_id: str, package_id: str) -> dict[str, object]:
        run, snapshot = self._load(run_id, package_id)
        if run.status not in {RunStatus.PAUSED, RunStatus.WAITING_APPROVAL}:
            raise PlanRunError("run is not resumable")
        try:
            package, context, prereq = self._current(run, snapshot)
        except PlanRunError:
            updated = self.runs.transition(run.id, run.target_id, RunStatus.BLOCKED,
                                           "PREREQUISITES_STALE", expected=frozenset({run.status}))
            if self.objects:
                self.objects.release_run(updated.id, updated.target_id)
            return self.runs.details(updated)
        if prereq.state is not PrerequisiteState.READY:
            updated = self.runs.transition(run.id, run.target_id, RunStatus.BLOCKED,
                                           "PREREQUISITES_STALE", expected=frozenset({run.status}))
            if self.objects:
                self.objects.release_run(updated.id, updated.target_id)
            return self.runs.details(updated)
        step = self.runs.current_step(run)
        if step is None:
            raise PlanRunError("run has no pending step")
        if run.approval_id:
            approval = self.approvals.get(run.approval_id, run.target_id)
            if approval is None or approval.status in {ApprovalStatus.EXPIRED, ApprovalStatus.REJECTED}:
                status = RunStatus.REJECTED if approval and approval.status is ApprovalStatus.REJECTED else RunStatus.BLOCKED
                updated = self.runs.transition(run.id, run.target_id, status,
                                               "APPROVAL_REJECTED" if status is RunStatus.REJECTED else
                                               "APPROVAL_EXPIRED", expected=frozenset({run.status}))
                if self.objects:
                    self.objects.release_run(updated.id, updated.target_id)
                return self.runs.details(updated)
            if approval.status is not ApprovalStatus.APPROVED_ONCE:
                if run.status is RunStatus.PAUSED:
                    updated = self.runs.transition(run.id, run.target_id, RunStatus.WAITING_APPROVAL,
                                                   "APPROVAL_PENDING", expected=frozenset({run.status}))
                    return self.runs.details(updated)
                return self.runs.details(run)
        if step.type == RuntimeStepType.EXECUTE_REQUEST.value:
            try:
                bound = self._bound(snapshot, step, run)
                decision = self.policy.evaluate(package, bound.action, record=False)
            except (PlanRunError, ValueError):
                decision = None
            if decision is None or decision.result is PolicyDecision.DENY:
                updated = self.runs.transition(run.id, run.target_id, RunStatus.BLOCKED,
                                               "POLICY_CHANGED", expected=frozenset({run.status}))
                if self.objects:
                    self.objects.release_run(updated.id, updated.target_id)
                return self.runs.details(updated)
            if decision.result is PolicyDecision.REQUIRE_APPROVAL:
                if run.status is RunStatus.PAUSED:
                    updated = self.runs.transition(run.id, run.target_id, RunStatus.WAITING_APPROVAL,
                                                   "APPROVAL_REQUIRED", expected=frozenset({run.status}))
                    return self.runs.details(updated)
                return self.runs.details(run)
        updated = self.runs.transition(run.id, run.target_id, RunStatus.READY,
                                       "OPERATOR_RESUMED", expected=frozenset({run.status}))
        return self.runs.details(updated)

    def pause(self, run_id: str, package_id: str) -> dict[str, object]:
        run, _ = self._load(run_id, package_id)
        return self.runs.details(self.runs.request_stop(run.id, run.target_id, cancel=False))

    def cancel(self, run_id: str, package_id: str) -> dict[str, object]:
        run, _ = self._load(run_id, package_id)
        stopped = self.runs.request_stop(run.id, run.target_id, cancel=True)
        if self.objects and stopped.status in _TERMINAL:
            self.objects.release_run(stopped.id, stopped.target_id)
        return self.runs.details(stopped)

    def complete_human_step(self, run_id: str, package_id: str, step_id: str,
                            *, evidence_ids: tuple[str, ...] = (),
                            exchange_id: str | None = None) -> dict[str, object]:
        run, _ = self._load(run_id, package_id)
        step = self.runs.current_step(run)
        if (run.status is not RunStatus.WAITING_HUMAN or step is None or step.id != step_id
                or step.safe_reason not in {"HUMAN_OBSERVATION_REQUIRED", "HUMAN_REVIEW_REQUIRED",
                                            "COMPARISON_BINDING_REQUIRED", "COMPARISON_INPUTS_MISSING",
                                            "RECOVERY_REVIEW_REQUIRED", "AMBIGUOUS_MUTATION"}):
            raise PlanRunError("step is not awaiting human evidence")
        if not evidence_ids and exchange_id is None or len(evidence_ids) > 16:
            raise PlanRunError("human completion requires an evidence reference")
        for ref in evidence_ids:
            item = self.evidence.get_evidence(ref)
            if item is None or item.target_ref != run.target_id:
                raise PlanRunError("evidence does not belong to target")
        exchanges: tuple[str, ...] = ()
        if exchange_id is not None:
            item = self.traffic.get_exchange(exchange_id)
            if item is None or item.target_id != run.target_id:
                raise PlanRunError("traffic does not belong to target")
            exchanges = (exchange_id,)
            evidence_ids = tuple(dict.fromkeys((*evidence_ids, *item.evidence_ids)))[:16]
        result = self._result(step, "Operator linked existing target-owned evidence.",
                              evidence_ids=evidence_ids, exchange_ids=exchanges)
        updated = self.runs.manual_complete(run, step, result)
        return self.runs.details(updated)
