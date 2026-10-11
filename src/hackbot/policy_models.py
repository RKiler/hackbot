"""Secret-free action and policy records. No network execution lives here."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import re
import uuid

from .domain import validate_entity_id
from .logging import SecretRedactor
from .target_policy import PolicyDecision, RiskLevel
from .target_scope import ScopeResult


class ActionCategory(StrEnum):
    PASSIVE_ANALYSIS = "PASSIVE_ANALYSIS"
    SAFE_READ = "SAFE_READ"
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_REPLAY = "HTTP_REPLAY"
    BROWSER_NAVIGATION = "BROWSER_NAVIGATION"
    OBJECT_CREATE = "OBJECT_CREATE"
    OBJECT_UPDATE = "OBJECT_UPDATE"
    OBJECT_DELETE = "OBJECT_DELETE"
    AUTHORIZATION_TEST = "AUTHORIZATION_TEST"
    FILE_UPLOAD = "FILE_UPLOAD"
    MESSAGE_SEND = "MESSAGE_SEND"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    EXTERNAL_SIDE_EFFECT = "EXTERNAL_SIDE_EFFECT"
    FINANCIAL = "FINANCIAL"
    DESTRUCTIVE = "DESTRUCTIVE"
    UNKNOWN = "UNKNOWN"


class SideEffect(StrEnum):
    PASSIVE = "PASSIVE"
    SAFE_READ = "SAFE_READ"
    SAFE_CREATE = "SAFE_CREATE"
    SAFE_UPDATE = "SAFE_UPDATE"
    SAFE_DELETE = "SAFE_DELETE"
    EXTERNAL_SIDE_EFFECT = "EXTERNAL_SIDE_EFFECT"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    FINANCIAL = "FINANCIAL"
    DESTRUCTIVE = "DESTRUCTIVE"
    UNKNOWN = "UNKNOWN"


class ActorMode(StrEnum):
    LOCAL = "LOCAL"
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED_ONCE = "APPROVED_ONCE"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


_LABEL = re.compile(r"[a-z][a-z0-9_:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ACTION_ID = re.compile(r"ACTION-[0-9a-f]{32}\Z")
_METHOD = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})


def new_action_id() -> str:
    return "ACTION-" + uuid.uuid4().hex


@dataclass(frozen=True, slots=True)
class ProposedAction:
    target_id: str
    package_id: str
    category: ActionCategory
    actor: ActorMode
    source: str
    purpose: str = field(repr=False)
    url: str | None = field(default=None, repr=False)
    method: str | None = None
    hypothesis_id: str | None = None
    identity_id: str | None = None
    session_id: str | None = None
    operation: str | None = None
    vulnerability_class: str | None = None
    object_type: str | None = None
    object_ref_hash: str | None = None
    disposable_intent: bool = False
    cross_identity: bool = False
    side_effect_hint: SideEffect | None = None
    requested_risk: RiskLevel | None = None
    evidence_ids: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=new_action_id)

    def __post_init__(self) -> None:
        validate_entity_id(self.target_id, "TARGET")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", self.package_id):
            raise ValueError("Invalid package ID")
        if not _ACTION_ID.fullmatch(self.id):
            raise ValueError("Invalid action ID")
        if not isinstance(self.category, ActionCategory) or not isinstance(self.actor, ActorMode):
            raise ValueError("Invalid action category or actor")
        if not isinstance(self.source, str) or not _LABEL.fullmatch(self.source):
            raise ValueError("Invalid action source")
        if (not isinstance(self.purpose, str) or not 1 <= len(self.purpose) <= 240
                or any(ord(char) < 32 or ord(char) == 127 for char in self.purpose)
                or SecretRedactor().text(self.purpose) != self.purpose):
            raise ValueError("Invalid action purpose")
        if self.url is not None and (not isinstance(self.url, str) or not 1 <= len(self.url) <= 4096):
            raise ValueError("Invalid action URL")
        if self.method is not None and self.method not in _METHOD:
            raise ValueError("Unsupported HTTP method")
        if self.hypothesis_id is not None and not re.fullmatch(r"HYP-[0-9a-f]{32}", self.hypothesis_id):
            raise ValueError("Invalid hypothesis ID")
        for value, prefix in ((self.identity_id, "IDENTITY"), (self.session_id, "BSESSION")):
            if value is not None:
                validate_entity_id(value, prefix)
        if self.actor is ActorMode.AUTHENTICATED and self.identity_id is None:
            raise ValueError("Authenticated action needs an identity")
        if self.actor is not ActorMode.AUTHENTICATED and (self.identity_id or self.session_id):
            raise ValueError("Non-authenticated action cannot carry a session or identity")
        if self.category is ActionCategory.PASSIVE_ANALYSIS and self.actor is not ActorMode.LOCAL:
            raise ValueError("Passive analysis is local")
        for value in (self.operation, self.vulnerability_class, self.object_type):
            if value is not None and (not isinstance(value, str) or not _LABEL.fullmatch(value)):
                raise ValueError("Invalid operation metadata")
        if self.object_ref_hash is not None and not _HASH.fullmatch(self.object_ref_hash):
            raise ValueError("Object reference must be a SHA-256 fingerprint")
        if type(self.disposable_intent) is not bool or type(self.cross_identity) is not bool:
            raise ValueError("Invalid action flags")
        if self.side_effect_hint is not None and not isinstance(self.side_effect_hint, SideEffect):
            raise ValueError("Invalid side-effect hint")
        if self.requested_risk is not None and not isinstance(self.requested_risk, RiskLevel):
            raise ValueError("Invalid requested risk")
        if (not isinstance(self.evidence_ids, tuple) or len(self.evidence_ids) > 16
                or len(set(self.evidence_ids)) != len(self.evidence_ids)):
            raise ValueError("Invalid evidence references")
        for value in self.evidence_ids:
            validate_entity_id(value, "EV")
        if not isinstance(self.created_at, datetime) or self.created_at.tzinfo is None:
            raise ValueError("Action timestamp must have a timezone")

    def fingerprint(self) -> str:
        # The digest binds every security-relevant input without retaining URL queries.
        data = {key: (value.value if isinstance(value, StrEnum) else value)
                for key, value in {
                    "id": self.id, "target": self.target_id, "package": self.package_id,
                    "source": self.source, "purpose": self.purpose,
                    "category": self.category, "actor": self.actor, "url": self.url,
                    "method": self.method, "hypothesis": self.hypothesis_id,
                    "identity": self.identity_id, "session": self.session_id,
                    "operation": self.operation, "vulnerability_class": self.vulnerability_class,
                    "object_type": self.object_type,
                    "object_ref_hash": self.object_ref_hash,
                    "disposable_intent": self.disposable_intent,
                    "cross_identity": self.cross_identity,
                    "side_effect_hint": self.side_effect_hint,
                    "requested_risk": self.requested_risk,
                    "evidence_ids": self.evidence_ids,
                }.items()}
        return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ActionDecision:
    id: str
    action_id: str
    target_id: str
    result: PolicyDecision
    reason_code: str
    reason: str
    scope_result: ScopeResult | None
    matched_scope_rule: str | None
    matched_policy_rule: str | None
    risk: RiskLevel
    side_effect: SideEffect
    policy_version: str
    created_at: datetime
    approval_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id, "action_id": self.action_id, "target_id": self.target_id,
            "result": self.result.value, "reason_code": self.reason_code,
            "reason": self.reason, "scope_result": self.scope_result.value if self.scope_result else None,
            "matched_scope_rule": self.matched_scope_rule,
            "matched_policy_rule": self.matched_policy_rule,
            "risk": self.risk.value, "side_effect": self.side_effect.value,
            "policy_version": self.policy_version, "created_at": self.created_at.isoformat(),
            "approval_id": self.approval_id,
        }


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    id: str
    decision_id: str
    action_id: str
    target_id: str
    hypothesis_id: str | None
    identity_id: str | None
    category: ActionCategory
    risk: RiskLevel
    operation: str | None
    object_type: str | None
    object_ref_hash: str | None
    action_fingerprint: str
    policy_version: str
    reason_code: str
    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id, "decision_id": self.decision_id, "action_id": self.action_id,
            "target_id": self.target_id, "hypothesis_id": self.hypothesis_id,
            "identity_id": self.identity_id, "category": self.category.value,
            "risk": self.risk.value, "operation": self.operation,
            "object_type": self.object_type, "object_ref_hash": self.object_ref_hash,
            "reason_code": self.reason_code, "status": self.status.value,
            "created_at": self.created_at.isoformat(), "expires_at": self.expires_at.isoformat(),
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
        }


@dataclass(frozen=True, slots=True)
class PolicyPermit:
    """Future executor contract; Phase 13 neither issues nor consumes permits."""

    decision_id: str
    action_fingerprint: str
    target_id: str
    identity_id: str | None
    scope_rule: str | None
    expires_at: datetime
    one_time: bool
