"""Secret-free, target-scoped identity and membership records."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import re

from .domain import ObservationState, SourceRef, new_entity_id, validate_entity_id
from .logging import SecretRedactor


_ALIAS = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_SECRET_REF = re.compile(r"(?:ref:)?[a-z][a-z0-9_-]{0,63}(?:/[a-z][a-z0-9_-]{0,63})?\Z")


class AccountSource(StrEnum):
    RESEARCHER_PROVIDED = "RESEARCHER_PROVIDED"
    PROGRAM_PROVIDED = "PROGRAM_PROVIDED"
    PROGRAM_APPROVED_CREATED = "PROGRAM_APPROVED_CREATED"
    IMPORTED_SESSION = "IMPORTED_SESSION"
    UNKNOWN = "UNKNOWN"


class IdentityStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    PENDING = "PENDING"
    REAUTH_REQUIRED = "REAUTH_REQUIRED"
    UNKNOWN = "UNKNOWN"


class MembershipStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    PENDING = "PENDING"
    UNKNOWN = "UNKNOWN"


def validate_alias(value: str) -> str:
    if not isinstance(value, str) or not _ALIAS.fullmatch(value):
        raise ValueError("Invalid identity alias")
    return value


def validate_secret_ref(value: str | None) -> str | None:
    if value is not None and (not isinstance(value, str) or not _SECRET_REF.fullmatch(value)):
        raise ValueError("Secret reference must be an opaque identifier")
    return value


def _evidence(values: tuple[str, ...], state: ObservationState) -> None:
    if not isinstance(values, tuple) or len(values) > 16 or len(set(values)) != len(values):
        raise ValueError("Invalid identity evidence references")
    for value in values:
        validate_entity_id(value, "EV")
    if state is not ObservationState.CONFIGURED and not values:
        raise ValueError("Observed or inferred identity metadata requires evidence")


def _timestamp(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("Identity timestamp must be timezone-aware")


def _source(value: SourceRef | None) -> None:
    if value is not None and not isinstance(value, SourceRef):
        raise ValueError("Invalid identity provenance")


def _metadata(purpose: str | None, tags: tuple[str, ...]) -> None:
    if purpose is not None and (not isinstance(purpose, str) or not 1 <= len(purpose) <= 256
                                or any(ord(char) < 32 or ord(char) == 127 for char in purpose)
                                or SecretRedactor().text(purpose) != purpose):
        raise ValueError("Invalid identity purpose")
    if not isinstance(tags, tuple) or len(tags) > 16 or len(set(tags)) != len(tags):
        raise ValueError("Invalid identity tags")
    for tag in tags:
        if not isinstance(tag, str) or not _ALIAS.fullmatch(tag):
            raise ValueError("Invalid identity tag")


@dataclass(frozen=True, slots=True, kw_only=True)
class Identity:
    target_id: str
    alias: str
    status: IdentityStatus = IdentityStatus.UNKNOWN
    account_source: AccountSource = AccountSource.UNKNOWN
    principal_id: str | None = None
    principal_state: ObservationState | None = None
    principal_fact_id: str | None = None
    secret_ref: str | None = field(default=None, repr=False)
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    purpose: str | None = field(default=None, repr=False)
    tags: tuple[str, ...] = field(default=(), repr=False)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("IDENTITY"))

    def __post_init__(self) -> None:
        validate_entity_id(self.id, "IDENTITY")
        validate_entity_id(self.target_id, "TARGET")
        validate_alias(self.alias)
        validate_secret_ref(self.secret_ref)
        if not isinstance(self.status, IdentityStatus) or not isinstance(self.account_source, AccountSource):
            raise ValueError("Invalid identity source or status")
        if not isinstance(self.observation_state, ObservationState):
            raise ValueError("Invalid identity observation state")
        if self.principal_id is None:
            if self.principal_state is not None or self.principal_fact_id is not None:
                raise ValueError("Principal metadata without principal")
        else:
            validate_entity_id(self.principal_id, "PRINCIPAL")
            if not isinstance(self.principal_state, ObservationState):
                raise ValueError("Principal relationship needs an observation state")
            if self.principal_state is ObservationState.CONFIGURED:
                if self.principal_fact_id is not None:
                    raise ValueError("Configured principal relationship must not claim an observed fact")
            else:
                validate_entity_id(self.principal_fact_id, "FA")
        _evidence(self.evidence_ids, self.observation_state)
        _source(self.source_ref)
        _metadata(self.purpose, self.tags)
        _timestamp(self.created_at)
        _timestamp(self.updated_at)
        if self.updated_at < self.created_at:
            raise ValueError("Identity update precedes creation")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "alias": self.alias,
            "status": self.status.value,
            "account_source": self.account_source.value,
            "principal_id": self.principal_id,
            "principal_state": self.principal_state.value if self.principal_state else None,
            "observation_state": self.observation_state.value,
            "evidence_ids": list(self.evidence_ids),
            "source": self.source_ref.to_reference() if self.source_ref else None,
            "has_secret_reference": self.secret_ref is not None,
            "purpose_present": self.purpose is not None,
            "tag_count": len(self.tags),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class TenantMembership:
    target_id: str
    identity_id: str
    tenant_id: str
    role_ids: tuple[str, ...] = ()
    status: MembershipStatus = MembershipStatus.UNKNOWN
    is_primary: bool = False
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    fact_id: str | None = None
    source_ref: SourceRef | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("MEMBERSHIP"))

    def __post_init__(self) -> None:
        for value, prefix in ((self.id, "MEMBERSHIP"), (self.target_id, "TARGET"),
                              (self.identity_id, "IDENTITY"), (self.tenant_id, "TENANT")):
            validate_entity_id(value, prefix)
        if not isinstance(self.role_ids, tuple) or len(self.role_ids) > 16 or len(set(self.role_ids)) != len(self.role_ids):
            raise ValueError("Invalid membership roles")
        for role_id in self.role_ids:
            validate_entity_id(role_id, "ROLE")
        if not isinstance(self.status, MembershipStatus) or type(self.is_primary) is not bool:
            raise ValueError("Invalid membership status or primary flag")
        if self.is_primary and self.status is not MembershipStatus.ACTIVE:
            raise ValueError("Primary membership must be active")
        if not isinstance(self.observation_state, ObservationState):
            raise ValueError("Invalid membership observation state")
        _evidence(self.evidence_ids, self.observation_state)
        if self.observation_state is ObservationState.CONFIGURED:
            if self.fact_id is not None:
                raise ValueError("Configured membership must not claim an observed fact")
        else:
            validate_entity_id(self.fact_id, "FA")
        _source(self.source_ref)
        _timestamp(self.created_at)
        _timestamp(self.updated_at)
        if self.updated_at < self.created_at:
            raise ValueError("Membership update precedes creation")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "identity_id": self.identity_id,
            "tenant_id": self.tenant_id,
            "role_ids": list(self.role_ids),
            "status": self.status.value,
            "is_primary": self.is_primary,
            "observation_state": self.observation_state.value,
            "evidence_ids": list(self.evidence_ids),
            "fact_id": self.fact_id,
            "source": self.source_ref.to_reference() if self.source_ref else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class PrincipalLink:
    target_id: str
    identity_id: str
    principal_id: str
    observation_state: ObservationState
    evidence_ids: tuple[str, ...] = ()
    fact_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("PRINCIPAL_LINK"))

    def __post_init__(self) -> None:
        for value, prefix in ((self.id, "PRINCIPAL_LINK"), (self.target_id, "TARGET"),
                              (self.identity_id, "IDENTITY"), (self.principal_id, "PRINCIPAL")):
            validate_entity_id(value, prefix)
        if not isinstance(self.observation_state, ObservationState):
            raise ValueError("Invalid principal link state")
        _evidence(self.evidence_ids, self.observation_state)
        if self.observation_state is ObservationState.CONFIGURED:
            if self.fact_id is not None:
                raise ValueError("Configured principal link must not claim an observed fact")
        else:
            validate_entity_id(self.fact_id, "FA")
        _timestamp(self.created_at)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "identity_id": self.identity_id,
            "principal_id": self.principal_id,
            "observation_state": self.observation_state.value,
            "evidence_ids": list(self.evidence_ids),
            "fact_id": self.fact_id,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class IdentityPair:
    left_identity_id: str
    right_identity_id: str
    tenant_id: str | None = None

    def __post_init__(self) -> None:
        validate_entity_id(self.left_identity_id, "IDENTITY")
        validate_entity_id(self.right_identity_id, "IDENTITY")
        if self.tenant_id is not None:
            validate_entity_id(self.tenant_id, "TENANT")
