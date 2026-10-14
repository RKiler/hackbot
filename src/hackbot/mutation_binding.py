"""Resolve opaque mutation plan stages from a pinned, reviewed object recipe."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from enum import StrEnum

from .evidence import FactStatus
from .executor import RequestTemplate
from .object_recipes import MutationRecipe, RecipeCatalog, external_id
from .store import EvidenceFactStore
from .target_package import TargetPackage
from .target_scope import ScopeResult
from .test_objects import ObjectRegistry, ObjectState, TestObject
from .typed_mutations import MutationPhase, MutationType, TypedMutation


class MutationStage(StrEnum):
    BEFORE_READ = "BEFORE_READ"
    OWNER_MUTATE = "OWNER_MUTATE"
    OWNER_READBACK = "OWNER_READBACK"
    TARGET_BEFORE_READ = "TARGET_BEFORE_READ"
    BOUNDARY_MUTATE = "BOUNDARY_MUTATE"
    BOUNDARY_READBACK = "BOUNDARY_READBACK"
    RESTORE = "RESTORE"
    RESTORE_READBACK = "RESTORE_READBACK"


STAGES = tuple(stage for stage in MutationStage
               if stage is not MutationStage.TARGET_BEFORE_READ)
DELETE_STAGES = tuple(MutationStage)
_KEYS = frozenset({"binding", "recipe_id", "recipe_hash", "test_object_id",
                   "mutation_type", "stage", "method", "authentication", "fingerprint"})
_NESTED_KEYS = _KEYS | {"parent_object_id", "foreign_parent_object_id"}
_DELETE_KEYS = _KEYS | {"delete_control_object_id"}


def mutation_fingerprint(shape: dict[str, str]) -> str:
    keys = (_DELETE_KEYS if "delete_control_object_id" in shape else
            _NESTED_KEYS if "parent_object_id" in shape else _KEYS)
    return hashlib.sha256(json.dumps({key: shape[key] for key in sorted(keys - {"fingerprint"})},
                                     sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ResolvedMutationStage:
    template: RequestTemplate
    item: TestObject
    recipe: MutationRecipe
    stage: MutationStage
    expected_value: str
    before_value: str
    delete_control_item: TestObject | None = None
    delete_target_item: TestObject | None = None

    def typed_mutation(self, actor_identity_id: str, operation_id: str) -> TypedMutation:
        deleting = self.recipe.mutation_type is MutationType.DELETE_DISPOSABLE
        return TypedMutation(self.item.target_id, operation_id, self.item.id,
                             self.item.object_type, self.item.creator_identity_id,
                             actor_identity_id, self.item.tenant_id,
                             self.recipe.mutation_type, self.recipe.field,
                             self.expected_value, self.expected_value,
                             "DELETE_AND_VERIFY" if deleting else "RESTORE",
                             self.recipe.side_effect, self.item.recipe_hash,
                             self.item.verification_evidence_ids[:4])


def resolve_mutation_stage(shape: dict[str, str], *, package: TargetPackage,
                           run_id: str, objects: ObjectRegistry,
                           recipes: RecipeCatalog,
                           evidence: EvidenceFactStore) -> ResolvedMutationStage:
    nested = set(shape) == _NESTED_KEYS
    deleting = set(shape) == _DELETE_KEYS
    if (frozenset(shape) not in {_KEYS, _NESTED_KEYS, _DELETE_KEYS} or
            shape.get("binding") != "AUTHORIZATION_RECIPE_MUTATION_V1"
            or shape.get("authentication") != "EXECUTOR_SUPPLIED"
            or shape.get("fingerprint") != mutation_fingerprint(shape)):
        raise ValueError("invalid typed mutation reference")
    try:
        stage = MutationStage(shape["stage"])
    except (KeyError, ValueError):
        raise ValueError("invalid typed mutation stage") from None
    item = objects.get(shape["test_object_id"], package.target.id)
    if (item is None or item.package_id != package.id or item.state is not ObjectState.IN_USE
            or not item.disposable or item.verified_at is None or
            not item.external_id_hash or not item.external_id_evidence_id or
            objects.active_reservation(item.id) != run_id or
            item.recipe_id != shape["recipe_id"] or item.recipe_hash != shape["recipe_hash"]):
        raise ValueError("verified disposable reservation is missing")
    for predicate, value in (("created_by", item.creator_identity_id),
                             ("resource_tenant", item.tenant_id), ("disposable", "true")):
        facts = evidence.find_facts(item.id, predicate, limit=8).items
        if not any(fact.target_ref == package.target.id and fact.status is FactStatus.ACTIVE
                   and fact.source != "MANUAL" and fact.confidence >= 0.9
                   and fact.evidence_ids and fact.object == value for fact in facts):
            raise ValueError("verified ownership facts are missing")
    raw_id = evidence.read_content(item.external_id_evidence_id,
                                   allow_sensitive=True, max_bytes=256).decode("ascii")
    external = external_id(raw_id)
    if hashlib.sha256((item.id + ":" + external).encode()).hexdigest() != item.external_id_hash:
        raise ValueError("object reference integrity failed")
    recipe = recipes.get(package.id, item.recipe_id)
    if (recipe is None or recipe.sha256 != item.recipe_hash or
            recipe.target_id != package.target.id or recipe.object_type != item.object_type):
        raise ValueError("pinned mutation recipe changed")
    mutation = next((entry for entry in recipe.mutations
                     if entry.mutation_type.value == shape["mutation_type"]), None)
    if mutation is None:
        raise ValueError("mutation is not declared by recipe")
    if deleting != (mutation.mutation_type is MutationType.DELETE_DISPOSABLE):
        raise ValueError("delete mutation binding is incomplete")
    if stage is MutationStage.TARGET_BEFORE_READ and not deleting:
        raise ValueError("target preflight belongs only to delete mutation")
    delete_target = item if deleting else None
    delete_control = None
    if deleting:
        control = objects.get(shape["delete_control_object_id"], package.target.id)
        if (control is None or control.id == item.id or
                control.package_id != item.package_id or
                control.object_type != item.object_type or
                control.recipe_id != item.recipe_id or
                control.recipe_hash != item.recipe_hash or
                control.creator_identity_id != item.creator_identity_id or
                control.tenant_id != item.tenant_id or
                control.parent_id != item.parent_id or
                control.state is not ObjectState.IN_USE or not control.disposable or
                control.verified_at is None or not control.external_id_hash or
                not control.external_id_evidence_id or
                objects.active_reservation(control.id) != run_id):
            raise ValueError("verified delete control reservation is missing")
        for predicate, value in (("created_by", control.creator_identity_id),
                                 ("resource_tenant", control.tenant_id),
                                 ("disposable", "true")):
            facts = evidence.find_facts(control.id, predicate, limit=8).items
            if not any(fact.target_ref == package.target.id and
                       fact.status is FactStatus.ACTIVE and fact.source != "MANUAL" and
                       fact.confidence >= 0.9 and fact.evidence_ids and
                       fact.object == value for fact in facts):
                raise ValueError("verified delete control facts are missing")
        raw_control = evidence.read_content(control.external_id_evidence_id,
                                            allow_sensitive=True, max_bytes=256).decode("ascii")
        control_external = external_id(raw_control)
        if hashlib.sha256((control.id + ":" + control_external).encode()).hexdigest() != control.external_id_hash:
            raise ValueError("delete control reference integrity failed")
        delete_control = control
        if stage in {MutationStage.BEFORE_READ, MutationStage.OWNER_MUTATE,
                     MutationStage.OWNER_READBACK}:
            item, external = control, control_external
    parent_external = None
    if nested:
        variables = (mutation.write.body.get("variables")
                     if isinstance(mutation.write.body, dict) else None)
        if (recipe.parent_type is None or not isinstance(variables, dict) or
                variables.get("parentId") != "$parent_id" or
                item.parent_id != shape["parent_object_id"]):
            raise ValueError("nested mutation recipe or relationship changed")
        parents = []
        for parent_id in (shape["parent_object_id"], shape["foreign_parent_object_id"]):
            parent = objects.get(parent_id, package.target.id)
            if (parent is None or parent.package_id != package.id or
                    parent.object_type != recipe.parent_type or
                    parent.state is not ObjectState.IN_USE or not parent.disposable or
                    parent.verified_at is None or not parent.external_id_hash or
                    not parent.external_id_evidence_id or
                    objects.active_reservation(parent.id) != run_id):
                raise ValueError("verified nested parent reservation is missing")
            for predicate, value in (("created_by", parent.creator_identity_id),
                                     ("resource_tenant", parent.tenant_id),
                                     ("disposable", "true")):
                facts = evidence.find_facts(parent.id, predicate, limit=8).items
                if not any(fact.target_ref == package.target.id and
                           fact.status is FactStatus.ACTIVE and fact.source != "MANUAL" and
                           fact.confidence >= 0.9 and fact.evidence_ids and
                           fact.object == value for fact in facts):
                    raise ValueError("verified nested parent facts are missing")
            raw_parent = evidence.read_content(parent.external_id_evidence_id,
                                               allow_sensitive=True, max_bytes=256).decode("ascii")
            parent_value = external_id(raw_parent)
            if hashlib.sha256((parent.id + ":" + parent_value).encode()).hexdigest() != parent.external_id_hash:
                raise ValueError("nested parent reference integrity failed")
            parents.append((parent, parent_value))
        if (parents[0][0].tenant_id != item.tenant_id or
                parents[0][0].creator_identity_id != item.creator_identity_id or
                parents[1][0].tenant_id == item.tenant_id or
                parents[1][0].creator_identity_id == item.creator_identity_id):
            raise ValueError("nested parent boundary is invalid")
        parent_external = (parents[1][1] if stage is MutationStage.BOUNDARY_MUTATE
                           else parents[0][1])
    elif (isinstance(mutation.write.body, dict) and
          isinstance(mutation.write.body.get("variables"), dict) and
          "parentId" in mutation.write.body["variables"]):
        raise ValueError("nested mutation lacks parent binding")
    if stage in {MutationStage.BEFORE_READ, MutationStage.TARGET_BEFORE_READ,
                 MutationStage.OWNER_READBACK,
                 MutationStage.BOUNDARY_READBACK, MutationStage.RESTORE_READBACK}:
        operation = mutation.readback
    elif stage is MutationStage.RESTORE:
        operation = mutation.restore
    else:
        operation = mutation.write
    expected_method = "GET" if "READ" in stage.value else mutation.write.method
    if shape["method"] != expected_method or operation.method != expected_method:
        raise ValueError("mutation stage method changed")
    if deleting:
        expected = "present" if stage in {MutationStage.BEFORE_READ,
                                           MutationStage.TARGET_BEFORE_READ} else "absent"
        before = "present"
        template = operation.template(test_name=item.test_name, object_id=external)
        if package.scope.evaluate_url(template.url).result is not ScopeResult.IN_SCOPE:
            raise ValueError("mutation request is outside scope")
        return ResolvedMutationStage(template, item, mutation, stage, expected, before,
                                     delete_control, delete_target)
    control = TypedMutation.test_value(run_id, item.id, MutationPhase.OWNER_CONTROL)
    boundary = TypedMutation.test_value(run_id, item.id, MutationPhase.BOUNDARY)
    expected = (item.test_name if stage in {MutationStage.BEFORE_READ,
                                            MutationStage.RESTORE,
                                            MutationStage.RESTORE_READBACK} else
                control if stage in {MutationStage.OWNER_MUTATE, MutationStage.OWNER_READBACK} else
                boundary)
    before = (item.test_name if stage in {MutationStage.BEFORE_READ,
                                          MutationStage.OWNER_MUTATE} else
              control if stage in {MutationStage.OWNER_READBACK,
                                    MutationStage.BOUNDARY_MUTATE,
                                    MutationStage.BOUNDARY_READBACK,
                                    MutationStage.RESTORE} else
              boundary)
    template = operation.template(test_name=expected, object_id=external,
                                  parent_id=parent_external)
    if package.scope.evaluate_url(template.url).result is not ScopeResult.IN_SCOPE:
        raise ValueError("mutation request is outside scope")
    return ResolvedMutationStage(template, item, mutation, stage, expected, before)
