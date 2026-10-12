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
from .typed_mutations import MutationPhase, TypedMutation


class MutationStage(StrEnum):
    BEFORE_READ = "BEFORE_READ"
    OWNER_MUTATE = "OWNER_MUTATE"
    OWNER_READBACK = "OWNER_READBACK"
    BOUNDARY_MUTATE = "BOUNDARY_MUTATE"
    BOUNDARY_READBACK = "BOUNDARY_READBACK"
    RESTORE = "RESTORE"
    RESTORE_READBACK = "RESTORE_READBACK"


STAGES = tuple(MutationStage)
_KEYS = frozenset({"binding", "recipe_id", "recipe_hash", "test_object_id",
                   "mutation_type", "stage", "method", "authentication", "fingerprint"})


def mutation_fingerprint(shape: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps({key: shape[key] for key in sorted(_KEYS - {"fingerprint"})},
                                     sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ResolvedMutationStage:
    template: RequestTemplate
    item: TestObject
    recipe: MutationRecipe
    stage: MutationStage
    expected_value: str
    before_value: str

    def typed_mutation(self, actor_identity_id: str, operation_id: str) -> TypedMutation:
        return TypedMutation(self.item.target_id, operation_id, self.item.id,
                             self.item.object_type, self.item.creator_identity_id,
                             actor_identity_id, self.item.tenant_id,
                             self.recipe.mutation_type, self.recipe.field,
                             self.expected_value, self.expected_value, "RESTORE",
                             self.recipe.side_effect, self.item.recipe_hash,
                             self.item.verification_evidence_ids[:4])


def resolve_mutation_stage(shape: dict[str, str], *, package: TargetPackage,
                           run_id: str, objects: ObjectRegistry,
                           recipes: RecipeCatalog,
                           evidence: EvidenceFactStore) -> ResolvedMutationStage:
    if (set(shape) != _KEYS or shape.get("binding") != "AUTHORIZATION_RECIPE_MUTATION_V1"
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
    if stage in {MutationStage.BEFORE_READ, MutationStage.OWNER_READBACK,
                 MutationStage.BOUNDARY_READBACK, MutationStage.RESTORE_READBACK}:
        operation = mutation.readback
    elif stage is MutationStage.RESTORE:
        operation = mutation.restore
    else:
        operation = mutation.write
    expected_method = "GET" if "READ" in stage.value else mutation.write.method
    if shape["method"] != expected_method or operation.method != expected_method:
        raise ValueError("mutation stage method changed")
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
    template = operation.template(test_name=expected, object_id=external)
    if package.scope.evaluate_url(template.url).result is not ScopeResult.IN_SCOPE:
        raise ValueError("mutation request is outside scope")
    return ResolvedMutationStage(template, item, mutation, stage, expected, before)
