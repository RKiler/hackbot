"""Authoritative local target context and pure combined policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import json
from pathlib import Path
import re

from .domain import Target
from .logging import SecretRedactor
from .target_policy import (
    AutonomyAction, AutonomyPolicy, PolicyDecision, PolicyEvaluation,
    ProgramRules, RatePolicy, RiskLevel,
)
from .target_scope import (
    ProgramScope, ScopeDecision, ScopeResult, validate_package_id,
)


_SECRET_REFERENCE = re.compile(r"ref:[a-z][a-z0-9_-]{0,63}\Z")
_DOCUMENT_SECTIONS = frozenset({"scope", "program_rules", "context", "researcher_notes"})
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DECISION_PRIORITY = {
    PolicyDecision.ALLOW: 0,
    PolicyDecision.REQUIRE_APPROVAL: 1,
    PolicyDecision.DENY: 2,
}


class PackageStatus(StrEnum):
    TRACKED = "TRACKED"
    PAUSED = "PAUSED"
    ARCHIVED = "ARCHIVED"


def _short_text(value: str | None, maximum: int) -> None:
    if value is not None and (not isinstance(value, str) or not value or len(value) > maximum
                              or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("Invalid target context text")


def _strings(values: tuple[str, ...], *, count: int, maximum: int) -> None:
    if not isinstance(values, tuple) or len(values) > count:
        raise ValueError("Invalid target context list")
    for value in values:
        _short_text(value, maximum)


@dataclass(frozen=True, slots=True)
class TargetContext:
    description: str | None = field(default=None, repr=False)
    known_features: tuple[str, ...] = field(default=(), repr=False)
    terminology: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    research_priorities: tuple[str, ...] = field(default=(), repr=False)
    known_limitations: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        _short_text(self.description, 2048)
        _strings(self.known_features, count=50, maximum=128)
        _strings(self.research_priorities, count=50, maximum=256)
        _strings(self.known_limitations, count=50, maximum=256)
        if not isinstance(self.terminology, tuple) or len(self.terminology) > 50:
            raise ValueError("Invalid target terminology")
        for entry in self.terminology:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise ValueError("Invalid target terminology")
            _short_text(entry[0], 128)
            _short_text(entry[1], 256)

    def to_summary(self) -> dict[str, object]:
        return {
            "has_description": self.description is not None,
            "known_feature_count": len(self.known_features),
            "terminology_count": len(self.terminology),
            "research_priority_count": len(self.research_priorities),
            "known_limitation_count": len(self.known_limitations),
        }


@dataclass(frozen=True, slots=True)
class AccountReference:
    alias: str
    role_hint: str | None = field(default=None, repr=False)
    tenant_hint: str | None = field(default=None, repr=False)
    secret_ref: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        validate_package_id(self.alias)
        _short_text(self.role_hint, 128)
        _short_text(self.tenant_hint, 128)
        if self.secret_ref is not None and (not isinstance(self.secret_ref, str)
                                            or not _SECRET_REFERENCE.fullmatch(self.secret_ref)):
            raise ValueError("Account secret reference must be a ref: alias")

    def to_summary(self) -> dict[str, object]:
        return {"alias": self.alias, "has_secret_reference": self.secret_ref is not None}


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    scope: ScopeDecision
    program_rules: PolicyEvaluation
    autonomy: PolicyEvaluation
    result: PolicyDecision
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "scope": self.scope.to_dict(),
            "program_rules": self.program_rules.to_dict(),
            "autonomy": self.autonomy.to_dict(),
            "result": self.result.value,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class TargetPackage:
    id: str
    target: Target
    scope: ProgramScope
    rules: ProgramRules
    autonomy: AutonomyPolicy
    rate: RatePolicy
    status: PackageStatus
    version: int
    configured_at: datetime
    updated_at: datetime
    context: TargetContext = TargetContext()
    accounts: tuple[AccountReference, ...] = ()
    documents: tuple[tuple[str, str], ...] = ()
    package_dir: Path = field(default=Path("."), repr=False, compare=False)

    def __post_init__(self) -> None:
        validate_package_id(self.id)
        if not isinstance(self.target, Target) or not isinstance(self.scope, ProgramScope):
            raise ValueError("Invalid target-package link")
        if self.scope.package_id != self.id or self.target.root_domain is None:
            raise ValueError("Scope and target package disagree")
        if not isinstance(self.rules, ProgramRules) or not isinstance(self.autonomy, AutonomyPolicy) or not isinstance(self.rate, RatePolicy):
            raise ValueError("Invalid target package policy")
        if not isinstance(self.status, PackageStatus) or type(self.version) is not int or self.version != 1:
            raise ValueError("Unsupported target package status or version")
        for value in (self.configured_at, self.updated_at):
            if not isinstance(value, datetime) or value.tzinfo is None:
                raise ValueError("Package timestamps must be timezone-aware")
        if self.updated_at < self.configured_at:
            raise ValueError("Package update time precedes configuration")
        if not isinstance(self.context, TargetContext) or not isinstance(self.accounts, tuple) or len(self.accounts) > 20:
            raise ValueError("Invalid target package context or accounts")
        if any(not isinstance(item, AccountReference) for item in self.accounts):
            raise ValueError("Invalid account reference")
        aliases = [item.alias for item in self.accounts]
        if len(set(aliases)) != len(aliases):
            raise ValueError("Duplicate account alias")
        if not isinstance(self.documents, tuple) or len(self.documents) > 4:
            raise ValueError("Invalid target documents")
        for section, filename in self.documents:
            if section not in _DOCUMENT_SECTIONS or not isinstance(filename, str) or not _FILE_NAME.fullmatch(filename) or filename in {".", ".."}:
                raise ValueError("Invalid target document reference")
        if len({item[0] for item in self.documents}) != len(self.documents):
            raise ValueError("Duplicate target document section")

    @property
    def primary_domain(self) -> str:
        assert self.target.root_domain is not None
        return self.target.root_domain

    def evaluate_url(
        self, url: str, *, risk: RiskLevel,
        action: AutonomyAction | None = None, owned_test_object: bool = False,
    ) -> AuthorizationDecision:
        scope = self.scope.evaluate_url(url)
        program = self.rules.evaluate(risk, action)
        autonomy = self.autonomy.evaluate(risk, action, owned_test_object=owned_test_object)
        if self.status is not PackageStatus.TRACKED:
            return AuthorizationDecision(scope, program, autonomy, PolicyDecision.DENY, "package_not_tracked")
        if scope.result is not ScopeResult.IN_SCOPE:
            return AuthorizationDecision(scope, program, autonomy, PolicyDecision.DENY, "scope_not_affirmative")
        result = max((program.decision, autonomy.decision), key=_DECISION_PRIORITY.__getitem__)
        return AuthorizationDecision(scope, program, autonomy, result, "program_and_autonomy")

    def read_document(self, section: str, *, max_bytes: int = 65536) -> str | None:
        if section not in _DOCUMENT_SECTIONS:
            raise ValueError("Invalid target document section")
        if type(max_bytes) is not int or not 1 <= max_bytes <= 65536:
            raise ValueError("Invalid document read limit")
        mapping = dict(self.documents)
        filename = mapping.get(section)
        if filename is None:
            return None
        path = self.package_dir / filename
        if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
            raise ValueError("Invalid target document")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise ValueError("Cannot read target document") from None
        if len(content.encode("utf-8")) > max_bytes or SecretRedactor().text(content) != content:
            raise ValueError("Target document contains unsafe content")
        return content

    def to_dict(self) -> dict[str, object]:
        return {
            "authority": "TARGET_PACKAGE",
            "recon_inventory": "NOT_CONSULTED",
            "id": self.id,
            "target_id": self.target.id,
            "name": SecretRedactor().text(self.target.name),
            "primary_domain": self.primary_domain,
            "status": self.status.value,
            "version": self.version,
            "configured_at": self.configured_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "scope": self.scope.to_dict(),
            "program_rules": self.rules.to_dict(),
            "autonomy": self.autonomy.to_dict(),
            "rate": self.rate.to_dict(),
            "context": self.context.to_summary(),
            "accounts": [item.to_summary() for item in self.accounts],
            "documents": [section for section, _ in self.documents],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
