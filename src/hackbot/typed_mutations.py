"""Data-only authorization mutation contracts; this module never sends traffic."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import re

from .logging import SecretRedactor, is_sensitive_key
from .policy_models import SideEffect


_FIELD = re.compile(r"[a-z][a-z0-9_]{0,63}(?:\.[a-z][a-z0-9_]{0,63}){0,3}\Z")
_SAFE_TEXT = re.compile(r"[a-z][a-z0-9-]{3,79}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_OBJECT_ID = re.compile(r"TESTOBJ-[0-9a-f]{32}\Z")
_TARGET_ID = re.compile(r"TARGET-[0-9a-f]{32}\Z")
_IDENTITY_ID = re.compile(r"IDENTITY-[0-9a-f]{32}\Z")
_TENANT_ID = re.compile(r"TENANT-[0-9a-f]{32}\Z")
_OPERATION = re.compile(r"[A-Za-z][A-Za-z0-9_:-]{0,127}\Z")
_FORBIDDEN = frozenset({
    "owner", "owner_id", "tenant", "tenant_id", "role", "roles", "permission",
    "permissions", "billing", "billing_plan", "payment", "account", "email",
    "password", "secret", "token", "api_key", "session", "credential",
})


class MutationType(StrEnum):
    RENAME = "RENAME"
    UPDATE_TEST_FIELD = "UPDATE_TEST_FIELD"
    TOGGLE_TEST_SETTING = "TOGGLE_TEST_SETTING"
    CREATE_CHILD = "CREATE_CHILD"
    DELETE_DISPOSABLE = "DELETE_DISPOSABLE"
    ARCHIVE_DISPOSABLE = "ARCHIVE_DISPOSABLE"


class MutationPhase(StrEnum):
    OWNER_CONTROL = "OWNER_CONTROL"
    BOUNDARY = "BOUNDARY"
    RESTORE = "RESTORE"


@dataclass(frozen=True, slots=True)
class TypedMutation:
    target_id: str
    operation_id: str
    test_object_id: str
    object_type: str
    creator_identity_id: str
    actor_identity_id: str
    tenant_id: str
    mutation_type: MutationType
    field: str
    value_label: str
    expected_readback: str
    cleanup_strategy: str
    side_effect: SideEffect
    recipe_hash: str
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (self.mutation_type is not MutationType.RENAME or
                self.side_effect is not SideEffect.SAFE_UPDATE or
                self.field != "name" or self.cleanup_strategy != "RESTORE"):
            raise ValueError("unsafe mutation classification")
        if (not _TARGET_ID.fullmatch(self.target_id) or
                not _OBJECT_ID.fullmatch(self.test_object_id) or
                not _IDENTITY_ID.fullmatch(self.creator_identity_id) or
                not _IDENTITY_ID.fullmatch(self.actor_identity_id) or
                not _TENANT_ID.fullmatch(self.tenant_id) or
                not _OPERATION.fullmatch(self.operation_id) or
                not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", self.object_type)):
            raise ValueError("mutation identity or operation is invalid")
        if not _FIELD.fullmatch(self.field) or any(
            is_sensitive_key(part) or part in _FORBIDDEN for part in self.field.split(".")
        ):
            raise ValueError("mutation field is not safe")
        if (not _SAFE_TEXT.fullmatch(self.value_label) or
                self.expected_readback != self.value_label or
                SecretRedactor.from_environment().text(self.value_label) != self.value_label):
            raise ValueError("mutation value must be a safe test label")
        if not _HASH.fullmatch(self.recipe_hash):
            raise ValueError("mutation recipe is not pinned")
        if len(self.evidence_ids) > 16:
            raise ValueError("too many mutation evidence references")

    @staticmethod
    def test_value(run_id: str, object_id: str, phase: MutationPhase) -> str:
        if not isinstance(phase, MutationPhase):
            raise ValueError("invalid mutation phase")
        digest = hashlib.sha256(f"{run_id}:{object_id}:{phase.value}".encode()).hexdigest()[:12]
        return "hackbot-test-" + digest


@dataclass(frozen=True, slots=True)
class NestedBinding:
    parent_test_object_id: str
    child_test_object_id: str
    parent_tenant_id: str
    child_tenant_id: str
    operation_id: str
    relation_evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.relation_evidence_ids or len(self.relation_evidence_ids) > 16:
            raise ValueError("nested binding needs relation evidence")
        if (self.parent_test_object_id == self.child_test_object_id or
                not all(_OBJECT_ID.fullmatch(item) for item in (
                    self.parent_test_object_id, self.child_test_object_id)) or
                not all(_TENANT_ID.fullmatch(item) for item in (
                    self.parent_tenant_id, self.child_tenant_id)) or
                not _OPERATION.fullmatch(self.operation_id)):
            raise ValueError("nested parent and child must differ")


@dataclass(frozen=True, slots=True)
class BatchBinding:
    operation_id: str
    test_object_ids: tuple[str, ...]
    actor_identity_id: str
    expected_allowed: tuple[str, ...]
    request_budget: int
    maximum: int = 3

    def __post_init__(self) -> None:
        if not _OPERATION.fullmatch(self.operation_id) or not _IDENTITY_ID.fullmatch(
                self.actor_identity_id):
            raise ValueError("invalid batch operation or actor")
        if type(self.maximum) is not int or not 2 <= self.maximum <= 5:
            raise ValueError("invalid batch cap")
        if (not 2 <= len(self.test_object_ids) <= self.maximum or
                len(set(self.test_object_ids)) != len(self.test_object_ids) or
                any(not _OBJECT_ID.fullmatch(item) for item in self.test_object_ids) or
                not set(self.expected_allowed) <= set(self.test_object_ids)):
            raise ValueError("batch object selection is invalid")
        if type(self.request_budget) is not int or not 1 <= self.request_budget <= 20:
            raise ValueError("batch request budget is invalid")
