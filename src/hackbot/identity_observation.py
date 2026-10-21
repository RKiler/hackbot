"""Promote a captured self response into observed, target-scoped identity facts."""

from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit

from .domain import ObservationState, Principal, TrafficSource
from .evidence import RedactionStatus
from .identity import MembershipStatus
from .identity_registry import IdentityRegistry
from .object_recipes import unique_json_pairs
from .store import EvidenceFactStore
from .target_package import AccountReference, TargetPackage
from .target_scope import ScopeResult
from .traffic import AuthState, ExchangeState, TrafficExchange


class IdentityObservationConflict(ValueError):
    """An attributed self response contradicts the configured account binding."""


class CapturedSelfObserver:
    """Never treats account metadata or a browser label alone as observed ownership."""

    def __init__(self, *, registry: IdentityRegistry, evidence: EvidenceFactStore) -> None:
        self.registry = registry
        self.evidence = evidence

    def observe(self, package: TargetPackage, account: AccountReference, *,
                identity_id: str, session_id: str, url: str,
                exchange: TrafficExchange) -> bool:
        parsed = urlsplit(url)
        if (parsed.path not in {"/api/me", "/api/v1/me", "/me", "/api/current-user"}
                or parsed.query or parsed.fragment or
                package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE or
                exchange.target_id != package.target.id or exchange.package_id != package.id or
                exchange.attribution.browser_session_id != session_id or
                exchange.source is not TrafficSource.BURP or
                exchange.capture_provider != "MONTOYA_V1" or
                exchange.scope_result is not ScopeResult.IN_SCOPE or
                exchange.state is not ExchangeState.COMPLETE or
                exchange.attribution.auth_state is not AuthState.VERIFIED or
                exchange.attribution.verified_identity_id != identity_id or
                exchange.request.record.method != "GET" or exchange.response is None or
                exchange.response.record.status_code != 200 or
                exchange.response.record.content_type != "application/json" or
                exchange.response.record.size_bytes > 8192 or
                exchange.response.body_evidence_id is None):
            return False
        request = self.evidence.get_evidence(exchange.request.observation_evidence_id)
        response = self.evidence.get_evidence(exchange.response.body_evidence_id)
        if (request is None or request.target_ref != package.target.id or
                response is None or response.target_ref != package.target.id or
                response.redaction_status is not RedactionStatus.ORIGINAL):
            return False
        try:
            observed_url = json.loads(self.evidence.read_content(
                request.evidence_id, allow_sensitive=True, max_bytes=8192),
                object_pairs_hook=unique_json_pairs)["url"]
            body = self.evidence.read_content(response.evidence_id,
                                              allow_sensitive=True, max_bytes=8192)
            payload = json.loads(body, object_pairs_hook=unique_json_pairs)
        except (ValueError, KeyError, TypeError, UnicodeError, PermissionError):
            return False
        if (observed_url != url or hashlib.sha256(body).hexdigest() !=
                exchange.response.body_hash or not isinstance(payload, dict)):
            return False
        if (payload.get("id") != account.alias or not isinstance(account.tenant_hint, str)
                or not isinstance(account.role_hint, str)):
            return False
        if (payload.get("tenant") != account.tenant_hint or
                payload.get("role") != account.role_hint):
            raise IdentityObservationConflict("Observed self identity conflicts with configured tenant or role")

        identity = self.registry.get_identity(package.target.id, account.alias)
        if identity is None or identity.id != identity_id:
            raise IdentityObservationConflict("Captured self identity does not match the registered account")
        memberships = self.registry.list_memberships(identity_id, limit=12).items
        configured = []
        for item in memberships:
            tenant = self.registry.get_tenant(package.target.id, item.tenant_id)
            roles = tuple(self.registry.get_role(package.target.id, role_id)
                          for role_id in item.role_ids)
            if (item.observation_state is ObservationState.CONFIGURED and
                    tenant and tenant.label == account.tenant_hint and
                    any(role and role.name == account.role_hint for role in roles)):
                configured.append(item)
        if len(configured) != 1:
            return False
        membership = configured[0]
        if identity.principal_id is not None:
            principal = self.registry.get_principal(package.target.id, identity.principal_id)
            if principal is None or principal.label != account.alias:
                raise IdentityObservationConflict("Observed principal conflicts with the account alias")
        else:
            if identity.principal_state is ObservationState.OBSERVED:
                raise IdentityObservationConflict("Observed identity has no linked principal")
            principal = self.registry.register_principal(
                Principal(target_id=package.target.id, label=account.alias))
        if (identity.principal_state is ObservationState.OBSERVED and
                any(item.observation_state is ObservationState.OBSERVED and
                    item.tenant_id == membership.tenant_id and
                    item.status is MembershipStatus.ACTIVE for item in memberships)):
            return True
        evidence_ids = (response.evidence_id,)
        if identity.principal_state is not ObservationState.OBSERVED:
            fact = self.evidence.create_fact(identity_id, "resolves_to", principal.id,
                                             confidence=1.0, evidence_ids=evidence_ids,
                                             source="AUTHENTICATED_SELF", target_ref=package.target.id)
            self.registry.link_principal(identity_id, principal.id,
                                         observation_state=ObservationState.OBSERVED,
                                         evidence_ids=evidence_ids, fact_id=fact.fact_id)
        if not any(item.observation_state is ObservationState.OBSERVED and
                   item.tenant_id == membership.tenant_id and
                   item.status is MembershipStatus.ACTIVE for item in memberships):
            fact = self.evidence.create_fact(identity_id, "member_of", membership.tenant_id,
                                             confidence=1.0, evidence_ids=evidence_ids,
                                             source="AUTHENTICATED_SELF", target_ref=package.target.id)
            self.registry.add_membership(identity_id, membership.tenant_id,
                                         role_ids=membership.role_ids,
                                         status=MembershipStatus.ACTIVE,
                                         observation_state=ObservationState.OBSERVED,
                                         evidence_ids=evidence_ids, fact_id=fact.fact_id)
        return True
