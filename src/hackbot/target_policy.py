"""Target-package policy data and pure decisions; no action execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import math
import re


class PolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class RiskLevel(StrEnum):
    PASSIVE = "PASSIVE"
    SAFE_READ = "SAFE_READ"
    BOUNDED_ACTIVE = "BOUNDED_ACTIVE"
    STATE_CHANGING = "STATE_CHANGING"
    DESTRUCTIVE = "DESTRUCTIVE"


class AutonomyAction(StrEnum):
    CREATE_DISPOSABLE_OBJECT = "CREATE_DISPOSABLE_OBJECT"
    MODIFY_DISPOSABLE_OBJECT = "MODIFY_DISPOSABLE_OBJECT"
    DELETE_DISPOSABLE_OBJECT = "DELETE_DISPOSABLE_OBJECT"
    CROSS_IDENTITY_TEST = "CROSS_IDENTITY_TEST"
    ACCOUNT_CREATION = "ACCOUNT_CREATION"
    EXTERNAL_SIDE_EFFECT = "EXTERNAL_SIDE_EFFECT"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    FINANCIAL = "FINANCIAL"


_RISK_FIELD = {
    RiskLevel.PASSIVE: "passive",
    RiskLevel.SAFE_READ: "safe_read",
    RiskLevel.BOUNDED_ACTIVE: "bounded_active",
    RiskLevel.STATE_CHANGING: "state_changing",
    RiskLevel.DESTRUCTIVE: "destructive",
}
_ACTION_FIELD = {
    AutonomyAction.CREATE_DISPOSABLE_OBJECT: "create_disposable_objects",
    AutonomyAction.MODIFY_DISPOSABLE_OBJECT: "modify_disposable_objects",
    AutonomyAction.DELETE_DISPOSABLE_OBJECT: "delete_disposable_objects",
    AutonomyAction.CROSS_IDENTITY_TEST: "cross_identity_testing",
    AutonomyAction.ACCOUNT_CREATION: "account_creation",
    AutonomyAction.EXTERNAL_SIDE_EFFECT: "external_side_effects",
    AutonomyAction.PERMISSION_CHANGE: "permission_changes",
    AutonomyAction.FINANCIAL: "financial",
}
AUTONOMY_RISK_FIELDS = tuple(_RISK_FIELD.values())
AUTONOMY_ACTION_FIELDS = tuple(_ACTION_FIELD.values())
_OWNED_OBJECT_ACTIONS = frozenset({
    AutonomyAction.MODIFY_DISPOSABLE_OBJECT,
    AutonomyAction.DELETE_DISPOSABLE_OBJECT,
    AutonomyAction.CROSS_IDENTITY_TEST,
})
_RISK_ORDER = {
    RiskLevel.PASSIVE: 0,
    RiskLevel.SAFE_READ: 1,
    RiskLevel.BOUNDED_ACTIVE: 2,
    RiskLevel.STATE_CHANGING: 3,
    RiskLevel.DESTRUCTIVE: 4,
}
_ACTION_MINIMUM_RISK = {
    AutonomyAction.CROSS_IDENTITY_TEST: RiskLevel.SAFE_READ,
    AutonomyAction.CREATE_DISPOSABLE_OBJECT: RiskLevel.STATE_CHANGING,
    AutonomyAction.MODIFY_DISPOSABLE_OBJECT: RiskLevel.STATE_CHANGING,
    AutonomyAction.DELETE_DISPOSABLE_OBJECT: RiskLevel.STATE_CHANGING,
    AutonomyAction.ACCOUNT_CREATION: RiskLevel.STATE_CHANGING,
    AutonomyAction.EXTERNAL_SIDE_EFFECT: RiskLevel.STATE_CHANGING,
    AutonomyAction.PERMISSION_CHANGE: RiskLevel.STATE_CHANGING,
    AutonomyAction.FINANCIAL: RiskLevel.STATE_CHANGING,
}
_PRIORITY = {PolicyDecision.ALLOW: 0, PolicyDecision.REQUIRE_APPROVAL: 1, PolicyDecision.DENY: 2}
_LABEL = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    decision: PolicyDecision
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"decision": self.decision.value, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class AutonomyPolicy:
    passive: PolicyDecision = PolicyDecision.ALLOW
    safe_read: PolicyDecision = PolicyDecision.DENY
    bounded_active: PolicyDecision = PolicyDecision.DENY
    state_changing: PolicyDecision = PolicyDecision.DENY
    destructive: PolicyDecision = PolicyDecision.DENY
    create_disposable_objects: PolicyDecision = PolicyDecision.DENY
    modify_disposable_objects: PolicyDecision = PolicyDecision.DENY
    delete_disposable_objects: PolicyDecision = PolicyDecision.DENY
    cross_identity_testing: PolicyDecision = PolicyDecision.DENY
    account_creation: PolicyDecision = PolicyDecision.DENY
    external_side_effects: PolicyDecision = PolicyDecision.REQUIRE_APPROVAL
    permission_changes: PolicyDecision = PolicyDecision.REQUIRE_APPROVAL
    financial: PolicyDecision = PolicyDecision.DENY
    owned_test_objects_only: bool = True

    def __post_init__(self) -> None:
        for name in (*_RISK_FIELD.values(), *_ACTION_FIELD.values()):
            if not isinstance(getattr(self, name), PolicyDecision):
                raise ValueError("Invalid autonomy decision")
        if type(self.owned_test_objects_only) is not bool:
            raise ValueError("Invalid owned-object policy")
        if not self.owned_test_objects_only and self.cross_identity_testing is PolicyDecision.ALLOW:
            raise ValueError("Autonomous cross-identity tests require owned objects")

    def evaluate(
        self, risk: RiskLevel, action: AutonomyAction | None = None,
        *, owned_test_object: bool = False,
    ) -> PolicyEvaluation:
        if not isinstance(risk, RiskLevel) or (action is not None and not isinstance(action, AutonomyAction)):
            raise ValueError("Invalid policy input")
        if type(owned_test_object) is not bool:
            raise ValueError("Invalid owned-object marker")
        if action is not None and _RISK_ORDER[risk] < _RISK_ORDER[_ACTION_MINIMUM_RISK[action]]:
            return PolicyEvaluation(PolicyDecision.DENY, "risk_underclassified_for_action")
        if action in _OWNED_OBJECT_ACTIONS and not owned_test_object:
            return PolicyEvaluation(PolicyDecision.DENY, "owned_test_object_required")
        base = getattr(self, _RISK_FIELD[risk])
        if action is None:
            return PolicyEvaluation(base, "risk_level")
        specific = getattr(self, _ACTION_FIELD[action])
        decision = max((base, specific), key=_PRIORITY.__getitem__)
        return PolicyEvaluation(decision, "risk_and_action")

    def to_dict(self) -> dict[str, object]:
        return {**{name: getattr(self, name).value for name in (*_RISK_FIELD.values(), *_ACTION_FIELD.values())},
                "owned_test_objects_only": self.owned_test_objects_only}


@dataclass(frozen=True, slots=True)
class RatePolicy:
    requests_per_second: float = 1.0
    requests_per_minute: int | None = None
    max_concurrency: int = 1
    burst: int = 1

    def __post_init__(self) -> None:
        value = self.requests_per_second
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 100:
            raise ValueError("Invalid requests-per-second limit")
        if self.requests_per_minute is not None and (type(self.requests_per_minute) is not int or not 1 <= self.requests_per_minute <= 6000):
            raise ValueError("Invalid requests-per-minute limit")
        if type(self.max_concurrency) is not int or not 1 <= self.max_concurrency <= 100:
            raise ValueError("Invalid concurrency limit")
        if type(self.burst) is not int or not 1 <= self.burst <= 1000:
            raise ValueError("Invalid burst limit")

    def to_dict(self) -> dict[str, object]:
        return {
            "requests_per_second": self.requests_per_second,
            "requests_per_minute": self.requests_per_minute,
            "max_concurrency": self.max_concurrency,
            "burst": self.burst,
        }


@dataclass(frozen=True, slots=True)
class ProgramRules:
    automated_testing_allowed: bool | None = None
    account_creation_allowed: bool | None = None
    internal_vhost_testing_allowed: bool = False
    excluded_vulnerability_classes: tuple[str, ...] = ()
    forbidden_actions: tuple[str, ...] = ()
    third_party_restrictions: str | None = field(default=None, repr=False)
    data_handling_restrictions: str | None = field(default=None, repr=False)
    special_testing_notes: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        for value in (self.automated_testing_allowed, self.account_creation_allowed,
                      self.internal_vhost_testing_allowed):
            if value is not None and type(value) is not bool:
                raise ValueError("Invalid program rule boolean")
        for labels in (self.excluded_vulnerability_classes, self.forbidden_actions):
            if not isinstance(labels, tuple) or len(labels) > 50 or any(
                not isinstance(label, str) or not _LABEL.fullmatch(label) for label in labels
            ):
                raise ValueError("Invalid program rule labels")
            if len(set(labels)) != len(labels):
                raise ValueError("Duplicate program rule label")
        for value in (self.third_party_restrictions, self.data_handling_restrictions):
            if value is not None and (not isinstance(value, str) or len(value) > 2048
                                      or any(ord(char) < 32 for char in value)):
                raise ValueError("Invalid program rule text")
        if not isinstance(self.special_testing_notes, tuple) or len(self.special_testing_notes) > 20:
            raise ValueError("Invalid special testing notes")
        for note in self.special_testing_notes:
            if not isinstance(note, str) or not note or len(note) > 512 or any(ord(char) < 32 for char in note):
                raise ValueError("Invalid special testing note")

    def evaluate(self, risk: RiskLevel, action: AutonomyAction | None = None) -> PolicyEvaluation:
        if not isinstance(risk, RiskLevel) or (action is not None and not isinstance(action, AutonomyAction)):
            raise ValueError("Invalid program rule input")
        if action is not None and action.value.lower() in self.forbidden_actions:
            return PolicyEvaluation(PolicyDecision.DENY, "program_forbidden_action")
        if risk is not RiskLevel.PASSIVE:
            if self.automated_testing_allowed is False:
                return PolicyEvaluation(PolicyDecision.DENY, "program_disallows_automation")
            if self.automated_testing_allowed is None:
                return PolicyEvaluation(PolicyDecision.REQUIRE_APPROVAL, "automation_rule_unknown")
        if action is AutonomyAction.ACCOUNT_CREATION:
            if self.account_creation_allowed is False:
                return PolicyEvaluation(PolicyDecision.DENY, "program_disallows_account_creation")
            if self.account_creation_allowed is None:
                return PolicyEvaluation(PolicyDecision.REQUIRE_APPROVAL, "account_creation_rule_unknown")
        return PolicyEvaluation(PolicyDecision.ALLOW, "program_rules_allow")

    def to_dict(self) -> dict[str, object]:
        return {
            "automated_testing_allowed": self.automated_testing_allowed,
            "account_creation_allowed": self.account_creation_allowed,
            "internal_vhost_testing_allowed": self.internal_vhost_testing_allowed,
            "excluded_vulnerability_classes": list(self.excluded_vulnerability_classes),
            "forbidden_actions": list(self.forbidden_actions),
            "third_party_restrictions": "[WITHHELD]" if self.third_party_restrictions else None,
            "data_handling_restrictions": "[WITHHELD]" if self.data_handling_restrictions else None,
            "special_testing_notes_count": len(self.special_testing_notes),
        }
