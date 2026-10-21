"""Mandatory deterministic pre-execution policy boundary; no executor."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Callable, Iterator, Protocol
from urllib.parse import urlsplit
import uuid

from .browser import BrowserSessionManager, BrowserStatus, VerificationStatus
from .identity import IdentityStatus
from .identity_registry import IdentityRegistry
from .policy_models import (
    ActionCategory, ActionDecision, ActorMode, ApprovalRequest, ProposedAction,
    SideEffect, new_action_id,
)
from .rate_limit import RateLimiter
from .target_package import PackageStatus, TargetPackage
from .target_policy import AutonomyAction, PolicyDecision, RiskLevel
from .target_scope import ScopeDecision, ScopeResult


POLICY_ENGINE_VERSION = "phase13-v1"
_RISK_ORDER = {
    RiskLevel.PASSIVE: 0, RiskLevel.SAFE_READ: 1, RiskLevel.BOUNDED_ACTIVE: 2,
    RiskLevel.STATE_CHANGING: 3, RiskLevel.DESTRUCTIVE: 4,
}
_SENSITIVE_SEGMENTS = frozenset({
    "delete", "remove", "destroy", "purge", "invite", "approve", "reject", "send",
    "execute", "trigger", "purchase", "checkout", "pay", "transfer", "revoke",
    "reset", "disable", "enable", "change-role", "change_role",
    "change_permissions", "upgrade_subscription",
})
_DANGEROUS_OBJECTS = frozenset({"organization", "organisation", "tenant", "account", "workspace"})
_EXTERNAL_OPERATIONS = frozenset({"invite", "send", "trigger", "execute", "webhook"})
_PERMISSION_OPERATIONS = frozenset({"change-role", "change_role", "change_permissions", "grant", "revoke", "assign_role"})
_FINANCIAL_OPERATIONS = frozenset({"purchase", "checkout", "pay", "transfer", "payout", "refund", "charge", "upgrade_subscription"})
_DESTRUCTIVE_OPERATIONS = frozenset({"destroy", "purge"})
_KNOWN_OBJECT_VERBS = frozenset({"create", "add", "make", "save", "update", "edit",
                                 "rename", "delete", "remove", "archive"})
_NETWORK_CATEGORIES = frozenset(ActionCategory) - {ActionCategory.PASSIVE_ANALYSIS}
_SUPERVISED_HUNT: ContextVar[tuple[str, str] | None] = ContextVar(
    "supervised_hunt_policy", default=None)


@contextmanager
def supervised_hunt_policy(package: TargetPackage) -> Iterator[None]:
    """Make a linked supervised campaign ask before higher-risk permitted actions."""
    token = _SUPERVISED_HUNT.set((package.target.id, package.id))
    try:
        yield
    finally:
        _SUPERVISED_HUNT.reset(token)


def _operation_tokens(value: str) -> tuple[str, ...]:
    """Normalize common RPC/camelCase spellings without interpreting request data."""
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return tuple(part for part in re.split(r"[^a-z0-9]+", split.lower()) if part)


class PolicyAudit(Protocol):
    def record(self, action: ProposedAction, decision: ActionDecision) -> ActionDecision: ...
    def approved_for(self, action: ProposedAction, policy_version: str,
                     now: datetime) -> ApprovalRequest | None: ...
    def get(self, approval_id: str, target_id: str, *,
            now: datetime | None = None) -> ApprovalRequest | None: ...


@dataclass(frozen=True, slots=True)
class Classification:
    side_effect: SideEffect
    risk: RiskLevel
    autonomy_action: AutonomyAction | None
    method_reason: str | None = None


class MethodPolicy:
    """Methods constrain a claim of safety; they never prove an action harmless."""

    @staticmethod
    def evaluate(action: ProposedAction) -> str | None:
        method = action.method
        if action.category is ActionCategory.PASSIVE_ANALYSIS:
            return "METHOD_CATEGORY_CONFLICT" if method is not None else None
        if action.category is ActionCategory.BROWSER_NAVIGATION and method is None:
            return None  # Normal navigation is GET.
        if method is None:
            return "METHOD_REQUIRED"
        if action.category is ActionCategory.SAFE_READ and method not in {"GET", "HEAD"}:
            return "METHOD_CATEGORY_CONFLICT"
        if action.category in {
            ActionCategory.OBJECT_CREATE, ActionCategory.OBJECT_UPDATE, ActionCategory.OBJECT_DELETE,
        } and method in {"GET", "HEAD", "OPTIONS"}:
            return "METHOD_CATEGORY_CONFLICT"
        if action.category in {ActionCategory.OBJECT_CREATE, ActionCategory.OBJECT_UPDATE} and method == "DELETE":
            return "METHOD_CATEGORY_CONFLICT"
        if action.category is ActionCategory.OBJECT_DELETE and method in {"PUT", "PATCH"}:
            return "METHOD_CATEGORY_CONFLICT"
        return None


def _risk_max(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    return left if _RISK_ORDER[left] >= _RISK_ORDER[right] else right


class SideEffectClassifier:
    """Client hints can raise risk; they never lower deterministic classification."""

    _CATEGORY_EFFECT = {
        ActionCategory.PASSIVE_ANALYSIS: SideEffect.PASSIVE,
        ActionCategory.OBJECT_CREATE: SideEffect.SAFE_CREATE,
        ActionCategory.OBJECT_UPDATE: SideEffect.SAFE_UPDATE,
        ActionCategory.OBJECT_DELETE: SideEffect.SAFE_DELETE,
        ActionCategory.MESSAGE_SEND: SideEffect.EXTERNAL_SIDE_EFFECT,
        ActionCategory.EXTERNAL_SIDE_EFFECT: SideEffect.EXTERNAL_SIDE_EFFECT,
        ActionCategory.PERMISSION_CHANGE: SideEffect.PERMISSION_CHANGE,
        ActionCategory.FINANCIAL: SideEffect.FINANCIAL,
        ActionCategory.DESTRUCTIVE: SideEffect.DESTRUCTIVE,
    }
    _EFFECT_RISK = {
        SideEffect.PASSIVE: RiskLevel.PASSIVE,
        SideEffect.SAFE_READ: RiskLevel.SAFE_READ,
        SideEffect.SAFE_CREATE: RiskLevel.STATE_CHANGING,
        SideEffect.SAFE_UPDATE: RiskLevel.STATE_CHANGING,
        SideEffect.SAFE_DELETE: RiskLevel.STATE_CHANGING,
        SideEffect.EXTERNAL_SIDE_EFFECT: RiskLevel.STATE_CHANGING,
        SideEffect.PERMISSION_CHANGE: RiskLevel.STATE_CHANGING,
        SideEffect.FINANCIAL: RiskLevel.STATE_CHANGING,
        SideEffect.DESTRUCTIVE: RiskLevel.DESTRUCTIVE,
        SideEffect.UNKNOWN: RiskLevel.BOUNDED_ACTIVE,
    }
    _EFFECT_ORDER = {
        SideEffect.PASSIVE: 0, SideEffect.SAFE_READ: 1, SideEffect.UNKNOWN: 2,
        SideEffect.SAFE_CREATE: 3, SideEffect.SAFE_UPDATE: 3, SideEffect.SAFE_DELETE: 3,
        SideEffect.EXTERNAL_SIDE_EFFECT: 4, SideEffect.PERMISSION_CHANGE: 5,
        SideEffect.FINANCIAL: 6, SideEffect.DESTRUCTIVE: 7,
    }

    def classify(self, action: ProposedAction) -> Classification:
        category, method = action.category, action.method
        method_reason = MethodPolicy.evaluate(action)
        if category is ActionCategory.PASSIVE_ANALYSIS:
            effect = SideEffect.PASSIVE
        elif category in self._CATEGORY_EFFECT:
            effect = self._CATEGORY_EFFECT[category]
        elif category in {ActionCategory.SAFE_READ, ActionCategory.HTTP_REQUEST,
                          ActionCategory.HTTP_REPLAY, ActionCategory.BROWSER_NAVIGATION,
                          ActionCategory.AUTHORIZATION_TEST}:
            if category is ActionCategory.BROWSER_NAVIGATION and method is None:
                method = "GET"
            if method is None:
                effect = SideEffect.UNKNOWN
            elif method in {"GET", "HEAD"}:
                effect = SideEffect.SAFE_READ
            else:
                effect = SideEffect.UNKNOWN
        else:
            effect = SideEffect.UNKNOWN

        if category is ActionCategory.FILE_UPLOAD:
            effect = SideEffect.UNKNOWN
        if category is ActionCategory.OBJECT_DELETE and action.object_type in _DANGEROUS_OBJECTS:
            effect = SideEffect.DESTRUCTIVE
        category_risk = self._EFFECT_RISK[effect]
        try:
            path = urlsplit(action.url).path if action.url else ""
        except ValueError:
            path = ""
        if category is not ActionCategory.PASSIVE_ANALYSIS:
            tokens = _operation_tokens(action.operation or "")
            path_tokens = tuple(token for segment in path.split("/")
                                for token in _operation_tokens(segment))
            words = set((*tokens, *path_tokens))
            joined = "".join(tokens)
            mutating = method not in {None, "GET", "HEAD", "OPTIONS"}
            if (words & _DESTRUCTIVE_OPERATIONS or joined in {"deletetenant", "deleteaccount",
                                                              "destroyworkspace", "purgedata"}):
                effect = SideEffect.DESTRUCTIVE
            elif (words & _FINANCIAL_OPERATIONS or joined in {"upgradeplan", "addpaymentmethod",
                                                                "issuefund", "transferbalance"}
                  or mutating and words & {"billing", "subscription", "subscriptions", "payments"}):
                effect = SideEffect.FINANCIAL
            elif (words & {"grant", "revoke", "permissions", "acl", "share"}
                  or joined in {"changerole", "grantadmin", "modifyacl", "shareresource",
                                "assignrole", "changepermissions"}
                  or mutating and words & {"role", "roles", "invitation_permissions"}):
                effect = SideEffect.PERMISSION_CHANGE
            elif (words & {"invite", "invitation", "invitations", "send", "webhook", "webhooks",
                            "sms", "email", "notification", "notifications", "publish",
                            "integration", "integrations"}
                  or joined in {"inviteuser", "sendemail", "sendsms", "sendwebhook",
                                "triggerintegration", "publishcontent"}):
                effect = SideEffect.EXTERNAL_SIDE_EFFECT
            elif words & _SENSITIVE_SEGMENTS and category not in {
                    ActionCategory.OBJECT_CREATE, ActionCategory.OBJECT_UPDATE,
                    ActionCategory.OBJECT_DELETE}:
                effect = SideEffect.UNKNOWN
            elif (category in {ActionCategory.OBJECT_CREATE, ActionCategory.OBJECT_UPDATE,
                               ActionCategory.OBJECT_DELETE} and tokens and
                  tokens[0] not in _KNOWN_OBJECT_VERBS):
                effect = SideEffect.UNKNOWN
        hint = action.side_effect_hint
        if hint is SideEffect.UNKNOWN and self._EFFECT_ORDER[effect] <= self._EFFECT_ORDER[SideEffect.SAFE_CREATE]:
            effect = SideEffect.UNKNOWN
        if (hint in {SideEffect.EXTERNAL_SIDE_EFFECT, SideEffect.PERMISSION_CHANGE,
                     SideEffect.FINANCIAL, SideEffect.DESTRUCTIVE}
                and self._EFFECT_ORDER[hint] > self._EFFECT_ORDER[effect]):
            effect = hint
        risk = _risk_max(category_risk, self._EFFECT_RISK[effect])
        if category is ActionCategory.FILE_UPLOAD:
            risk = _risk_max(risk, RiskLevel.STATE_CHANGING)
        if action.requested_risk is not None:
            risk = _risk_max(risk, action.requested_risk)

        autonomy_action = {
            SideEffect.SAFE_CREATE: AutonomyAction.CREATE_DISPOSABLE_OBJECT,
            SideEffect.SAFE_UPDATE: AutonomyAction.MODIFY_DISPOSABLE_OBJECT,
            SideEffect.SAFE_DELETE: AutonomyAction.DELETE_DISPOSABLE_OBJECT,
            SideEffect.EXTERNAL_SIDE_EFFECT: AutonomyAction.EXTERNAL_SIDE_EFFECT,
            SideEffect.PERMISSION_CHANGE: AutonomyAction.PERMISSION_CHANGE,
            SideEffect.FINANCIAL: AutonomyAction.FINANCIAL,
        }.get(effect)
        if effect is SideEffect.SAFE_CREATE and action.object_type in {"account", "user", "identity"}:
            autonomy_action = AutonomyAction.ACCOUNT_CREATION
        return Classification(effect, risk, autonomy_action, method_reason)


def _strict_url_reason(url: str) -> str | None:
    """Reject forms whose eventual interpretation can differ from the scope parser."""
    if not isinstance(url, str) or not 1 <= len(url) <= 4096:
        return "INVALID_URL"
    if any(ord(ch) <= 32 or ord(ch) == 127 or ch == "\\" for ch in url):
        return "AMBIGUOUS_URL"
    try:
        parsed = urlsplit(url)
        if (parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or "%" in parsed.netloc or parsed.netloc.endswith(":")):
            return "INVALID_URL"
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return "INVALID_URL"
    except ValueError:
        return "INVALID_URL"
    path = parsed.path or "/"
    if ("%" in path or ";" in path or "//" in path
            or any(segment in {".", ".."} for segment in path.split("/"))):
        return "AMBIGUOUS_URL"
    if re.search(r"%(?![0-9a-fA-F]{2})", parsed.query):
        return "AMBIGUOUS_URL"
    return None


class ScopeGuard:
    def evaluate(self, package: TargetPackage, action: ProposedAction) -> ScopeDecision | None:
        if action.category is ActionCategory.PASSIVE_ANALYSIS and action.url is None:
            return None
        if action.url is None:
            return ScopeDecision(ScopeResult.UNKNOWN, "missing_url", None, package.id)
        problem = _strict_url_reason(action.url)
        if problem:
            return ScopeDecision(ScopeResult.UNKNOWN, problem.lower(), None, package.id)
        return package.scope.evaluate_url(action.url)

    def redirect(self, package: TargetPackage, action: ProposedAction, destination: str) -> ScopeDecision:
        """Future executors must call this before following each redirect hop."""
        redirected = replace(action, url=destination)
        result = self.evaluate(package, redirected)
        assert result is not None
        return result


def policy_version(package: TargetPackage) -> str:
    data = {
        "engine": POLICY_ENGINE_VERSION, "package": package.id, "target": package.target.id,
        "updated": package.updated_at.isoformat(), "status": package.status.value,
        "scope": package.scope.to_dict(), "rules": asdict(package.rules),
        "autonomy": package.autonomy.to_dict(), "rate": package.rate.to_dict(),
    }
    digest = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return POLICY_ENGINE_VERSION + ":" + digest


class PolicyEngine:
    def __init__(self, *, registry: IdentityRegistry | None = None,
                 browser: BrowserSessionManager | None = None,
                 audit: PolicyAudit | None = None,
                 rate: RateLimiter | None = None,
                 owned_object: Callable[[ProposedAction], bool] | None = None) -> None:
        self.registry = registry
        self.browser = browser
        self.audit = audit
        self.rate = rate
        self.owned_object = owned_object
        self.scope = ScopeGuard()
        self.classifier = SideEffectClassifier()

    def evaluate_redirect(self, package: TargetPackage, action: ProposedAction,
                          destination: str, *, method: str | None = None,
                          record: bool = True, now: datetime | None = None) -> ActionDecision:
        """A redirect is a new action; original authorization never transfers."""
        redirected = replace(action, id=new_action_id(), url=destination,
                             method=method or action.method)
        return self.evaluate(package, redirected, record=record, now=now)

    def _identity_problem(self, action: ProposedAction) -> str | None:
        if action.actor is not ActorMode.AUTHENTICATED:
            return None
        if self.registry is None or self.browser is None:
            return "UNKNOWN_IDENTITY"
        identity = self.registry.get_identity(action.target_id, action.identity_id)
        if identity is None:
            return "UNKNOWN_IDENTITY"
        if identity.status is not IdentityStatus.ACTIVE:
            return "IDENTITY_NOT_ACTIVE"
        if action.session_id is None:
            return "UNVERIFIED_SESSION"
        try:
            session = self.browser.session_context(action.session_id)
        except (LookupError, ValueError):
            return "UNVERIFIED_SESSION"
        if session.target_id != action.target_id or session.identity_id != action.identity_id:
            return "SESSION_IDENTITY_MISMATCH"
        if (session.browser_status is not BrowserStatus.VALID
                or session.verification_status is not VerificationStatus.MATCH
                or session.authentication_status != "VALID" or not session.browser_available):
            return "UNVERIFIED_SESSION"
        return None

    def evaluate(self, package: TargetPackage, action: ProposedAction, *,
                 record: bool = True, now: datetime | None = None) -> ActionDecision:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("Policy time must be timezone-aware")
        classification = self.classifier.classify(action)
        scope = self.scope.evaluate(package, action)
        version = policy_version(package)
        result = PolicyDecision.DENY
        code = "POLICY_ERROR"
        matched_policy: str | None = None
        if action.target_id != package.target.id or action.package_id != package.id:
            code = "TARGET_MISMATCH"
        elif package.status is not PackageStatus.TRACKED:
            code = "TARGET_NOT_TRACKED"
        elif scope is not None and scope.result is not ScopeResult.IN_SCOPE:
            code = {
                "host_not_included": "HOST_OUT_OF_SCOPE",
                "excluded_host": "HOST_EXCLUDED",
                "excluded_path": "PATH_EXCLUDED",
                "path_not_included": "PATH_OUT_OF_SCOPE",
                "scheme_or_port_restricted": "SCHEME_OR_PORT_RESTRICTED",
            }.get(scope.reason, "UNKNOWN_SCOPE")
        elif action.category in _NETWORK_CATEGORIES and action.actor is ActorMode.LOCAL:
            code = "UNKNOWN_IDENTITY"
        elif ({action.category.value.lower(), action.operation or ""}
              & set(package.rules.forbidden_actions)):
            code = "PROGRAM_FORBIDDEN_ACTION"
        elif (action.vulnerability_class is not None
              and action.vulnerability_class in package.rules.excluded_vulnerability_classes):
            code = "VULNERABILITY_CLASS_EXCLUDED"
        elif classification.method_reason:
            code = classification.method_reason
        elif (problem := self._identity_problem(action)) is not None:
            code = problem
        else:
            owned = bool(self.owned_object(action)) if self.owned_object is not None else False
            if (not owned and (
                classification.autonomy_action in {
                    AutonomyAction.MODIFY_DISPOSABLE_OBJECT, AutonomyAction.DELETE_DISPOSABLE_OBJECT,
                } or action.cross_identity
            )):
                code = "OWNED_DISPOSABLE_OBJECT_REQUIRED"
            elif classification.side_effect is SideEffect.SAFE_CREATE and not action.disposable_intent:
                code = "DISPOSABLE_INTENT_REQUIRED"
            else:
                program = package.rules.evaluate(classification.risk, classification.autonomy_action)
                autonomy = package.autonomy.evaluate(
                    classification.risk, classification.autonomy_action, owned_test_object=owned)
                program_checks = [program]
                autonomy_checks = [autonomy]
                if action.cross_identity:
                    program_checks.append(package.rules.evaluate(
                        classification.risk, AutonomyAction.CROSS_IDENTITY_TEST))
                    autonomy_checks.append(package.autonomy.evaluate(
                        classification.risk, AutonomyAction.CROSS_IDENTITY_TEST,
                        owned_test_object=owned))
                if (action.category is ActionCategory.OBJECT_CREATE
                        and action.object_type in {"account", "user", "identity"}
                        and classification.autonomy_action is not AutonomyAction.ACCOUNT_CREATION):
                    program_checks.append(package.rules.evaluate(
                        classification.risk, AutonomyAction.ACCOUNT_CREATION))
                    autonomy_checks.append(package.autonomy.evaluate(
                        classification.risk, AutonomyAction.ACCOUNT_CREATION,
                        owned_test_object=owned))
                checks = program_checks + autonomy_checks
                matched_policy = "program+autonomy" + ("+cross_identity" if action.cross_identity else "")
                if any(check.decision is PolicyDecision.DENY for check in checks):
                    result = PolicyDecision.DENY
                    code = ("PROGRAM_POLICY_DENY" if any(
                        check.decision is PolicyDecision.DENY for check in program_checks)
                            else "AUTONOMY_POLICY_DENY")
                elif any(check.decision is PolicyDecision.REQUIRE_APPROVAL for check in checks):
                    result = PolicyDecision.REQUIRE_APPROVAL
                    code = {
                        SideEffect.PERMISSION_CHANGE: "PERMISSION_CHANGE",
                        SideEffect.EXTERNAL_SIDE_EFFECT: "EXTERNAL_SIDE_EFFECT",
                        SideEffect.FINANCIAL: "FINANCIAL_ACTION",
                        SideEffect.DESTRUCTIVE: "DESTRUCTIVE_ACTION",
                        SideEffect.UNKNOWN: "UNKNOWN_SIDE_EFFECT",
                    }.get(classification.side_effect, "POLICY_REQUIRES_APPROVAL")
                elif (_SUPERVISED_HUNT.get() == (package.target.id, package.id)
                      and (classification.risk not in {RiskLevel.PASSIVE,
                                                        RiskLevel.SAFE_READ}
                           or action.cross_identity)
                      and not (action.source == "object_factory"
                               and not action.cross_identity
                               and action.disposable_intent
                               and action.object_type not in _DANGEROUS_OBJECTS
                               and classification.side_effect in {
                                   SideEffect.SAFE_CREATE, SideEffect.SAFE_UPDATE,
                                   SideEffect.SAFE_DELETE}
                               and (classification.side_effect is SideEffect.SAFE_CREATE
                                    or owned))):
                    result = PolicyDecision.REQUIRE_APPROVAL
                    code = "SUPERVISED_APPROVAL_REQUIRED"
                elif classification.side_effect is SideEffect.UNKNOWN:
                    result = PolicyDecision.REQUIRE_APPROVAL
                    code = "UNKNOWN_SIDE_EFFECT"
                elif action.category is not ActionCategory.PASSIVE_ANALYSIS and self.rate is not None:
                    rate = self.rate.check(action.target_id, package.rate)
                    if not rate.allowed:
                        code = rate.reason_code
                    else:
                        result = PolicyDecision.ALLOW
                        code = "SAFE_READ_IN_SCOPE" if classification.side_effect is SideEffect.SAFE_READ else "ACTION_ALLOWED"
                else:
                    result = PolicyDecision.ALLOW
                    code = "PASSIVE_ALLOWED" if classification.side_effect is SideEffect.PASSIVE else (
                        "SAFE_READ_IN_SCOPE" if classification.side_effect is SideEffect.SAFE_READ else "ACTION_ALLOWED")

        approval_id = None
        if result is PolicyDecision.REQUIRE_APPROVAL and self.audit is not None:
            approved = self.audit.approved_for(action, version, current)
            if approved is not None:
                if self.rate is not None and action.category is not ActionCategory.PASSIVE_ANALYSIS:
                    rate = self.rate.check(action.target_id, package.rate)
                    if not rate.allowed:
                        result, code = PolicyDecision.DENY, rate.reason_code
                    else:
                        result, code, approval_id = PolicyDecision.ALLOW, "APPROVED_ONCE", approved.id
                else:
                    result, code, approval_id = PolicyDecision.ALLOW, "APPROVED_ONCE", approved.id
        decision = ActionDecision(
            "POLDEC-" + uuid.uuid4().hex, action.id, action.target_id, result, code,
            code.replace("_", " ").capitalize(), scope.result if scope else None,
            scope.matched_rule if scope else None, matched_policy, classification.risk,
            classification.side_effect, version, current, approval_id,
        )
        return self.audit.record(action, decision) if record and self.audit else decision
