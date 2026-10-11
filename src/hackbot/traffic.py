"""Local, vendor-neutral HTTP observations. No network execution or replay."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import re
import sqlite3
from typing import Protocol, overload
from urllib.parse import unquote_plus, urlsplit

from .browser import BrowserSessionManager, BrowserStatus, VerificationStatus
from .config import AppConfig
from .domain import (ObservationState, RequestRecord, ResponseRecord, TrafficSource, new_entity_id,
                     normalize_content_type, normalize_method, normalize_url, validate_entity_id)
from .evidence import Evidence, EvidenceProvenance, EvidenceType, RedactionStatus, Retention, Sensitivity
from .identity import IdentityStatus
from .identity_registry import IdentityRegistry
from .logging import is_sensitive_key
from .recon import Page
from .store import EvidenceFactStore
from .target_package import TargetPackage
from .target_scope import ScopeResult


class TrafficError(ValueError):
    """Safe failure; never includes captured material."""


class AuthState(StrEnum):
    ANONYMOUS = "ANONYMOUS"
    VERIFIED = "VERIFIED"
    UNVERIFIED_IDENTITY = "UNVERIFIED_IDENTITY"


class ExchangeState(StrEnum):
    REQUEST_ONLY = "REQUEST_ONLY"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    ABORTED = "ABORTED"
    TIMEOUT = "TIMEOUT"


_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")
_PARAM_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")
_PROVIDER = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_HTTP_VERSION = re.compile(r"HTTP/(?:1\.0|1\.1|2|3)\Z")
_CREDENTIAL_BODY = re.compile(
    rb"(?i)(?:password|passwd|authorization|bearer[ \t]+|api[_-]?key|access[_-]?token|"
    rb"refresh[_-]?token|session[_-]?(?:id|token)|csrf|xsrf|client[_-]?secret|"
    rb"private[_-]?key|auth[_-]?token|id[_-]?token|jwt|credential|secret)"
)
_KNOWN_PATH = frozenset({
    "api", "v1", "v2", "v3", "graphql", "rpc", "users", "user", "accounts", "account",
    "orgs", "organizations", "projects", "teams", "members", "files", "download", "export",
    "reports", "report", "auth", "login", "logout", "settings", "profile", "status",
    "health", "admin", "public", "static", "assets", "search", "list", "detail",
})


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TrafficError("Traffic timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


@overload
def _digest(value: str | bytes) -> str: ...


@overload
def _digest(value: None) -> None: ...


def _digest(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def _headers(value: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, tuple) or len(value) > 128:
        raise TrafficError("Invalid HTTP header collection")
    for pair in value:
        if (not isinstance(pair, tuple) or len(pair) != 2 or not isinstance(pair[0], str)
                or not _HEADER_NAME.fullmatch(pair[0]) or not isinstance(pair[1], str)
                or len(pair[1]) > 16384 or any(char in pair[1] for char in "\r\n\x00")):
            raise TrafficError("Invalid HTTP header")
    return value


def _header_names(headers: tuple[tuple[str, str], ...]) -> tuple[str, ...]:
    return tuple(sorted({name.lower() for name, _ in headers if not _protected_header(name)}))


def _content_type(headers: tuple[tuple[str, str], ...]) -> str | None:
    for name, value in headers:
        if name.lower() == "content-type":
            try:
                return normalize_content_type(value)
            except ValueError:
                return None
    return None


def _protected_header(name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    return is_sensitive_key(name) or any(part in normalized for part in ("csrf", "xsrf", "auth", "signature"))


def _evidence_headers(headers: tuple[tuple[str, str], ...]) -> list[list[str]]:
    return [[name, "[AUTH_CONTEXT]" if _protected_header(name) else value] for name, value in headers]


def _query_names(query: str) -> tuple[str, ...]:
    names = set()
    for piece in re.split(r"[&;]", query):
        if not piece:
            continue
        try:
            decoded = unquote_plus(piece.split("=", 1)[0])
        except UnicodeDecodeError:
            decoded = ""
        names.add(decoded if _PARAM_NAME.fullmatch(decoded) else "{param:" + _digest(piece.split("=", 1)[0])[:12] + "}")
    return tuple(sorted(names))


def _protected_query(query: str) -> str:
    parts = []
    for piece in re.split(r"([&;])", query):
        if piece in {"&", ";"}:
            parts.append(piece)
            continue
        name, separator, value = piece.partition("=")
        decoded = unquote_plus(name)
        if separator and (is_sensitive_key(decoded) or any(part in decoded.lower() for part in
                      ("csrf", "xsrf", "signature", "auth", "code", "state", "nonce", "key"))):
            parts.append(name + separator + "[AUTH_CONTEXT]")
        else:
            parts.append(piece)
    return "".join(parts)


def _auth_material_present(headers: tuple[tuple[str, str], ...], query: str) -> bool:
    if any(_protected_header(name) for name, _ in headers):
        return True
    for piece in re.split(r"[&;]", query):
        name = unquote_plus(piece.split("=", 1)[0])
        if is_sensitive_key(name) or any(part in name.lower() for part in
                                         ("csrf", "xsrf", "signature", "auth", "code", "state", "nonce", "key")):
            return True
    return False


def _body_for_evidence(body: bytes) -> tuple[bytes, RedactionStatus]:
    if _CREDENTIAL_BODY.search(body):
        return b"[WITHHELD: credential-like body]", RedactionStatus.WITHHELD
    return body, RedactionStatus.ORIGINAL


def _path_shape(path: str) -> str:
    parts = []
    for segment in path.split("/"):
        if not segment:
            parts.append("")
        elif segment in _KNOWN_PATH:
            parts.append(segment)
        else:
            parts.append("{p:" + _digest(segment)[:12] + "}")
    return "/".join(parts)


def _structural_fingerprint(method: str, origin: str, path_shape: str,
                            query_names: tuple[str, ...], content_type: str | None,
                            operation_id: str | None) -> str:
    shape = [method, origin, path_shape, list(query_names), content_type, operation_id]
    return _digest(json.dumps(shape, separators=(",", ":"), ensure_ascii=True))


def _cursor_encode(target_id: str, kind: str, value: str | None, observed_at: str, exchange_id: str) -> str:
    data = json.dumps([1, target_id, kind, value, observed_at, exchange_id], separators=(",", ":"))
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def _cursor_decode(cursor: str | None, target_id: str, kind: str,
                   value: str | None) -> tuple[str, str] | None:
    if cursor is None:
        return None
    if not isinstance(cursor, str) or not 1 <= len(cursor) <= 2048:
        raise TrafficError("Invalid traffic cursor")
    try:
        raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
        parts = json.loads(raw)
        if not isinstance(parts, list) or len(parts) != 6 or parts[:4] != [1, target_id, kind, value]:
            raise ValueError
        datetime.fromisoformat(parts[4])
        validate_entity_id(parts[5], "EXCHANGE")
        return parts[4], parts[5]
    except (ValueError, TypeError, UnicodeDecodeError, binascii.Error):
        raise TrafficError("Invalid traffic cursor") from None


@dataclass(frozen=True, slots=True)
class CapturedRequest:
    method: str
    url: str = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    body: bytes | None = field(default=None, repr=False)
    observed_at: datetime | None = None
    http_version: str | None = None
    endpoint_id: str | None = None
    operation_id: str | None = None

    def __post_init__(self) -> None:
        try:
            normalize_method(self.method)
            normalize_url(self.url, schemes={"http", "https"})
            _headers(self.headers)
            if self.body is not None and not isinstance(self.body, bytes):
                raise ValueError
            if self.http_version is not None and not _HTTP_VERSION.fullmatch(self.http_version):
                raise ValueError
            if self.endpoint_id is not None:
                validate_entity_id(self.endpoint_id, "ENDPOINT")
            if self.operation_id is not None:
                prefix = self.operation_id.split("-", 1)[0]
                if prefix not in {"OPERATION", "GQL"}:
                    raise ValueError
                validate_entity_id(self.operation_id, prefix)
            if self.observed_at is not None:
                _utc(self.observed_at)
        except ValueError:
            raise TrafficError("Invalid captured request") from None


@dataclass(frozen=True, slots=True)
class CapturedResponse:
    status_code: int | None
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    body: bytes | None = field(default=None, repr=False)
    observed_at: datetime | None = None
    elapsed_ms: int | None = None
    http_version: str | None = None

    def __post_init__(self) -> None:
        if self.status_code is not None and (type(self.status_code) is not int or not 100 <= self.status_code <= 599):
            raise TrafficError("Invalid captured response")
        _headers(self.headers)
        if self.body is not None and not isinstance(self.body, bytes):
            raise TrafficError("Invalid captured response")
        if self.elapsed_ms is not None and (type(self.elapsed_ms) is not int or self.elapsed_ms < 0):
            raise TrafficError("Invalid captured response")
        if self.http_version is not None and not _HTTP_VERSION.fullmatch(self.http_version):
            raise TrafficError("Invalid captured response")
        if self.observed_at is not None:
            _utc(self.observed_at)


@dataclass(frozen=True, slots=True)
class CapturePacket:
    request: CapturedRequest = field(repr=False)
    response: CapturedResponse | None = field(default=None, repr=False)
    browser_session_id: str | None = None
    correlation_id: str | None = field(default=None, repr=False)
    browser_action_id: str | None = field(default=None, repr=False)
    provider_reference: str | None = field(default=None, repr=False)


class TrafficCaptureProvider(Protocol):
    """A provider yields a bounded batch; it does not authorize execution."""

    name: str
    source: TrafficSource

    def read_batch(self, *, limit: int) -> tuple[CapturePacket, ...]: ...


@dataclass(frozen=True, slots=True)
class TrafficAttribution:
    auth_state: AuthState
    declared_identity_id: str | None = None
    verified_identity_id: str | None = None
    principal_id: str | None = None
    principal_state: str | None = None
    declared_tenant_ids: tuple[str, ...] = ()
    declared_role_ids: tuple[str, ...] = ()
    browser_session_id: str | None = None
    auth_context_id: str | None = None

    @classmethod
    def anonymous(cls) -> TrafficAttribution:
        return cls(AuthState.ANONYMOUS)

    @classmethod
    def from_browser(cls, manager: BrowserSessionManager, session_id: str) -> TrafficAttribution:
        context = manager.session_context(session_id)
        if context.authentication_status == "ANONYMOUS":
            return cls(AuthState.ANONYMOUS, browser_session_id=context.browser_session_id)
        verified = (context.authentication_status == "VALID" and context.browser_available
                    and context.browser_status is BrowserStatus.VALID
                    and context.verification_status is VerificationStatus.MATCH)
        identity = manager.registry.get_identity(context.target_id, context.identity_id) if context.identity_id else None
        if not verified or identity is None or identity.status is not IdentityStatus.ACTIVE:
            return cls(AuthState.UNVERIFIED_IDENTITY, declared_identity_id=context.identity_id,
                       browser_session_id=context.browser_session_id, auth_context_id=context.auth_context_id)
        if not context.declared_memberships_complete:
            tenants, roles = (), ()
        else:
            tenants, roles = context.declared_tenant_ids, context.declared_role_ids
        observed_principal = (identity.principal_id
                              if identity.principal_state is ObservationState.OBSERVED else None)
        return cls(AuthState.VERIFIED, declared_identity_id=identity.id,
                   verified_identity_id=identity.id, principal_id=observed_principal,
                   principal_state=identity.principal_state.value if observed_principal else None,
                   declared_tenant_ids=tenants, declared_role_ids=roles,
                   browser_session_id=context.browser_session_id, auth_context_id=context.auth_context_id)

    def to_dict(self) -> dict[str, object]:
        return {"auth_state": self.auth_state.value, "declared_identity_id": self.declared_identity_id,
                "verified_identity_id": self.verified_identity_id, "principal_id": self.principal_id,
                "principal_state": self.principal_state,
                "declared_tenant_ids": list(self.declared_tenant_ids), "declared_role_ids": list(self.declared_role_ids),
                "browser_session_id": self.browser_session_id, "auth_context_id": self.auth_context_id}


@dataclass(frozen=True, slots=True)
class TrafficRequest:
    record: RequestRecord
    origin: str
    display_path: str
    path_fingerprint: str
    structural_fingerprint: str
    query_names: tuple[str, ...]
    header_names: tuple[str, ...]
    content_type: str | None
    http_version: str | None
    body_evidence_id: str | None
    observation_evidence_id: str
    body_size: int | None
    body_hash: str | None

    def to_dict(self) -> dict[str, object]:
        return {"id": self.record.id, "target_id": self.record.target_id,
                "method": self.record.method, "source": self.record.source.value,
                "origin": self.origin, "display_path": self.display_path,
                "query_names": list(self.query_names), "header_names": list(self.header_names),
                "content_type": self.content_type, "http_version": self.http_version,
                "endpoint_id": self.record.endpoint_id, "operation_id": self.record.operation_id,
                "structural_fingerprint": self.structural_fingerprint, "body_size": self.body_size,
                "body_hash": self.body_hash,
                "body_evidence_id": self.body_evidence_id,
                "observation_evidence_id": self.observation_evidence_id,
                "observed_at": self.record.observed_at.isoformat() if self.record.observed_at else None}


@dataclass(frozen=True, slots=True)
class TrafficResponse:
    record: ResponseRecord
    header_names: tuple[str, ...]
    body_evidence_id: str | None
    observation_evidence_id: str
    body_hash: str | None
    elapsed_ms: int | None
    http_version: str | None

    def to_dict(self) -> dict[str, object]:
        return {"id": self.record.id, "request_id": self.record.request_id,
                "status_code": self.record.status_code, "content_type": self.record.content_type,
                "body_size": self.record.size_bytes, "body_hash": self.body_hash,
                "header_names": list(self.header_names), "elapsed_ms": self.elapsed_ms,
                "http_version": self.http_version, "body_evidence_id": self.body_evidence_id,
                "observation_evidence_id": self.observation_evidence_id,
                "observed_at": self.record.observed_at.isoformat() if self.record.observed_at else None}


@dataclass(frozen=True, slots=True)
class TrafficExchange:
    id: str
    target_id: str
    package_id: str
    source: TrafficSource
    capture_provider: str
    request: TrafficRequest
    response: TrafficResponse | None
    attribution: TrafficAttribution
    scope_result: ScopeResult
    scope_reason: str
    state: ExchangeState
    sensitivity: Sensitivity
    retention: Retention
    observed_at: datetime
    provider_reference_hash: str | None = None
    browser_action_hash: str | None = None
    correlation_hash: str | None = None
    failure_reason: str | None = None

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        ids = [self.request.observation_evidence_id]
        if self.request.body_evidence_id:
            ids.append(self.request.body_evidence_id)
        if self.response:
            ids.append(self.response.observation_evidence_id)
            if self.response.body_evidence_id:
                ids.append(self.response.body_evidence_id)
        return tuple(ids)

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "target_id": self.target_id, "package_id": self.package_id,
                "source": self.source.value, "capture_provider": self.capture_provider,
                "request": self.request.to_dict(), "response": self.response.to_dict() if self.response else None,
                "attribution": self.attribution.to_dict(), "scope_result": self.scope_result.value,
                "scope_reason": self.scope_reason, "state": self.state.value,
                "sensitivity": self.sensitivity.value, "evidence_ids": list(self.evidence_ids),
                "observed_at": self.observed_at.isoformat(), "provider_reference_hash": self.provider_reference_hash,
                "browser_action_hash": self.browser_action_hash, "correlation_hash": self.correlation_hash,
                "failure_reason": self.failure_reason}


class TrafficStore:
    """BugHunter-owned traffic rows plus protected Phase 3 Evidence bytes."""

    def __init__(self, evidence: EvidenceFactStore, registry: IdentityRegistry | None = None) -> None:
        self.evidence = evidence
        self.registry = registry or IdentityRegistry(evidence)

    @classmethod
    def from_config(cls, config: AppConfig) -> TrafficStore:
        if not isinstance(config, AppConfig):
            raise TrafficError("Invalid BugHunter configuration")
        return cls(EvidenceFactStore.from_config(config))

    def initialize(self) -> None:
        self.evidence.initialize()

    def _limit(self, limit: int) -> int:
        if type(limit) is not int or limit < 1:
            raise TrafficError("Traffic page size must be positive")
        return min(limit, self.evidence.settings.max_page_size)

    def _target_check(self, target: TargetPackage) -> None:
        if not isinstance(target, TargetPackage):
            raise TrafficError("A Target Package is required")
        with self.evidence._connection() as connection:
            row = connection.execute("SELECT package_id FROM registry_targets WHERE target_id=? LIMIT 1",
                                     (target.target.id,)).fetchone()
        if row is None or row["package_id"] != target.id:
            raise TrafficError("Target Package is not registered locally")

    def _attribution(self, target_id: str, source: TrafficSource, *,
                     browser_manager: BrowserSessionManager | None, browser_session_id: str | None,
                     declared_identity_id: str | None, anonymous: bool,
                     auth_material_present: bool) -> TrafficAttribution:
        if type(anonymous) is not bool:
            raise TrafficError("Invalid anonymous capture marker")
        if browser_session_id is not None:
            if browser_manager is None or declared_identity_id is not None or anonymous:
                raise TrafficError("Browser attribution requires one session source")
            try:
                context = browser_manager.session_context(browser_session_id)
                if context.target_id != target_id:
                    raise TrafficError("Browser session belongs to another target")
                attribution = TrafficAttribution.from_browser(browser_manager, browser_session_id)
            except (ValueError, KeyError):
                raise TrafficError("Browser attribution is unavailable") from None
            if attribution.auth_state is AuthState.ANONYMOUS and auth_material_present:
                return TrafficAttribution(AuthState.UNVERIFIED_IDENTITY,
                                          browser_session_id=attribution.browser_session_id)
            return attribution
        if source is TrafficSource.BROWSER:
            raise TrafficError("Browser captures require a session")
        if declared_identity_id is None:
            return (TrafficAttribution.anonymous() if anonymous and not auth_material_present
                    else TrafficAttribution(AuthState.UNVERIFIED_IDENTITY))
        if anonymous:
            raise TrafficError("Anonymous capture cannot declare an identity")
        validate_entity_id(declared_identity_id, "IDENTITY")
        identity = self.registry.get_identity(target_id, declared_identity_id)
        if identity is None:
            raise TrafficError("Declared identity is not registered for target")
        return TrafficAttribution(AuthState.UNVERIFIED_IDENTITY, declared_identity_id=declared_identity_id)

    def _evidence(self, *, kind: str, content: bytes, target_id: str, source: TrafficSource,
                  provider: str, observed_at: datetime, retention: Retention,
                  provider_reference_hash: str | None,
                  redaction_status: RedactionStatus = RedactionStatus.ORIGINAL) -> Evidence:
        return self.evidence.create_evidence(
            kind, content, source="TRAFFIC_" + source.value,
            provenance=EvidenceProvenance(system="TRAFFIC", entity=provider,
                                          record_id=provider_reference_hash, observed_at=observed_at),
            target_ref=target_id, observed_at=observed_at,
            sensitivity=Sensitivity.SECRET, redaction_status=redaction_status, retention=retention,
        )

    def store_request(
        self, target: TargetPackage, request: CapturedRequest, *, source: TrafficSource,
        capture_provider: str, browser_manager: BrowserSessionManager | None = None,
        browser_session_id: str | None = None, declared_identity_id: str | None = None,
        anonymous: bool = False,
        provider_reference: str | None = None, browser_action_id: str | None = None,
        correlation_id: str | None = None, retention: Retention = Retention(),
        scope_source_url: str | None = None,
        auth_material_observed: bool = False,
    ) -> TrafficExchange:
        if not isinstance(request, CapturedRequest) or not isinstance(source, TrafficSource):
            raise TrafficError("Invalid traffic capture")
        provider = capture_provider.upper() if isinstance(capture_provider, str) else ""
        if not _PROVIDER.fullmatch(provider) or not isinstance(retention, Retention):
            raise TrafficError("Invalid traffic provider or retention")
        if retention.pinned and not retention.retain:
            raise TrafficError("Pinned traffic must be retained")
        if retention.expires_at is not None:
            _utc(retention.expires_at)
        if type(auth_material_observed) is not bool:
            raise TrafficError("Invalid capture authentication signal")
        for value in (provider_reference, browser_action_id, correlation_id):
            if value is not None and (not isinstance(value, str) or not value or len(value) > 2048):
                raise TrafficError("Invalid capture correlation metadata")
        self._target_check(target)
        normalized = normalize_url(request.url, schemes={"http", "https"})
        parsed = urlsplit(normalized)
        attribution = self._attribution(target.target.id, source, browser_manager=browser_manager,
                                        browser_session_id=browser_session_id,
                                        declared_identity_id=declared_identity_id, anonymous=anonymous,
                                        auth_material_present=(auth_material_observed
                                                               or _auth_material_present(request.headers, parsed.query)))
        observed = _utc(request.observed_at)
        origin = parsed.scheme + "://" + parsed.netloc
        display_path = _path_shape(parsed.path)
        query_names = _query_names(parsed.query)
        content_type = _content_type(request.headers)
        method = normalize_method(request.method)
        structural = _structural_fingerprint(method, origin, display_path, query_names,
                                             content_type, request.operation_id)
        provider_hash = _digest(provider_reference)
        scope = target.scope.evaluate_url(request.url)
        if scope_source_url is not None:
            try:
                source_parsed = urlsplit(normalize_url(scope_source_url, schemes={"http", "https"}))
            except ValueError:
                raise TrafficError("Invalid capture scope source") from None
            if (source_parsed.scheme, source_parsed.netloc) != (parsed.scheme, parsed.netloc):
                raise TrafficError("Capture scope source has a different origin")
            original_scope = target.scope.evaluate_url(scope_source_url)
            if original_scope.result is ScopeResult.IN_SCOPE:
                raise TrafficError("Capture scope source cannot upgrade scope")
            scope = original_scope

        body_evidence = None
        raw_body_hash = _digest(request.body)
        if request.body is not None:
            retained_body, redaction_status = _body_for_evidence(request.body)
            body_evidence = self._evidence(kind="HTTP_REQUEST_BODY", content=retained_body,
                                           target_id=target.target.id, source=source, provider=provider,
                                           observed_at=observed, retention=retention,
                                           provider_reference_hash=provider_hash,
                                           redaction_status=redaction_status)
        original = urlsplit(request.url)
        evidence_url = request.url.split("?", 1)[0] + ("?" + _protected_query(original.query) if "?" in request.url else "")
        observation = {
            "method": method, "url": evidence_url, "headers": _evidence_headers(request.headers),
            "http_version": request.http_version,
            "body_evidence_id": body_evidence.evidence_id if body_evidence else None,
            "body_sha256": raw_body_hash,
            "retained_body_sha256": body_evidence.content_hash if body_evidence else None,
        }
        observation_evidence = self._evidence(
            kind=EvidenceType.HTTP_REQUEST.value,
            content=json.dumps(observation, sort_keys=True, separators=(",", ":")).encode(),
            target_id=target.target.id, source=source, provider=provider, observed_at=observed,
            retention=retention, provider_reference_hash=provider_hash,
        )
        request_record = RequestRecord(
            target_id=target.target.id, method=method, source=source, url=None,
            principal_id=attribution.principal_id, endpoint_id=request.endpoint_id,
            operation_id=request.operation_id, artifact_hash=body_evidence.content_hash if body_evidence else None,
            evidence_ids=tuple(item for item in (observation_evidence.evidence_id,
                                                body_evidence.evidence_id if body_evidence else None) if item),
            observed_at=observed,
        )
        exchange_id = new_entity_id("EXCHANGE")
        try:
            with self.evidence._connection() as connection:
                connection.execute("""INSERT INTO traffic_requests
                    (request_id,target_id,source,method,principal_id,origin,display_path,path_fingerprint,
                     structural_fingerprint,query_names_json,header_names_json,content_type,http_version,
                     endpoint_id,operation_id,body_evidence_id,observation_evidence_id,body_size,body_hash,
                     artifact_hash,
                     observed_at,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                        request_record.id, target.target.id, source.value, method, attribution.principal_id,
                        origin, display_path,
                        _digest(display_path), structural, json.dumps(query_names),
                        json.dumps(_header_names(request.headers)), content_type, request.http_version,
                        request.endpoint_id, request.operation_id,
                        body_evidence.evidence_id if body_evidence else None,
                        observation_evidence.evidence_id,
                        len(request.body) if request.body is not None else None, raw_body_hash,
                        body_evidence.content_hash if body_evidence else None,
                        observed.isoformat(), request_record.created_at.isoformat(),
                    ))
                connection.execute("""INSERT INTO traffic_exchanges
                    (exchange_id,target_id,package_id,request_id,endpoint_id,operation_id,structural_fingerprint,
                     source,capture_provider,
                     provider_reference_hash,browser_action_hash,correlation_hash,auth_state,
                     declared_identity_id,verified_identity_id,principal_id,principal_state,
                     declared_tenant_ids_json,declared_role_ids_json,browser_session_id,auth_context_id,
                     scope_result,scope_reason,state,failure_reason,sensitivity,retain,expires_at,pinned,
                     finding_related,observed_at,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                        exchange_id, target.target.id, target.id, request_record.id,
                        request.endpoint_id, request.operation_id, structural, source.value, provider,
                        provider_hash, _digest(browser_action_id), _digest(correlation_id),
                        attribution.auth_state.value, attribution.declared_identity_id,
                        attribution.verified_identity_id, attribution.principal_id, attribution.principal_state,
                        json.dumps(attribution.declared_tenant_ids), json.dumps(attribution.declared_role_ids),
                        attribution.browser_session_id, attribution.auth_context_id,
                        scope.result.value, scope.reason, ExchangeState.REQUEST_ONLY.value, None,
                        Sensitivity.SECRET.value, int(retention.retain),
                        retention.expires_at.isoformat() if retention.expires_at else None,
                        int(retention.pinned), int(retention.finding_related),
                        observed.isoformat(), datetime.now(timezone.utc).isoformat(),
                    ))
        except sqlite3.Error:
            raise TrafficError("Traffic persistence failed") from None
        exchange = self.get_exchange(exchange_id)
        assert exchange is not None
        return exchange

    def store_response(self, exchange_id: str, response: CapturedResponse) -> TrafficExchange:
        if not isinstance(response, CapturedResponse):
            raise TrafficError("Invalid captured response")
        validate_entity_id(exchange_id, "EXCHANGE")
        exchange = self.get_exchange(exchange_id)
        if exchange is None or exchange.state is not ExchangeState.REQUEST_ONLY or exchange.response is not None:
            raise TrafficError("Traffic exchange cannot accept a response")
        observed = _utc(response.observed_at)
        body_evidence = None
        raw_body_hash = _digest(response.body)
        if response.body is not None:
            retained_body, redaction_status = _body_for_evidence(response.body)
            body_evidence = self._evidence(kind="HTTP_RESPONSE_BODY", content=retained_body,
                                           target_id=exchange.target_id, source=exchange.source,
                                           provider=exchange.capture_provider, observed_at=observed,
                                           retention=exchange.retention,
                                           provider_reference_hash=exchange.provider_reference_hash,
                                           redaction_status=redaction_status)
        observation = {
            "status_code": response.status_code, "headers": _evidence_headers(response.headers),
            "http_version": response.http_version, "elapsed_ms": response.elapsed_ms,
            "body_evidence_id": body_evidence.evidence_id if body_evidence else None,
            "body_sha256": raw_body_hash,
            "retained_body_sha256": body_evidence.content_hash if body_evidence else None,
        }
        observation_evidence = self._evidence(
            kind=EvidenceType.HTTP_RESPONSE.value,
            content=json.dumps(observation, sort_keys=True, separators=(",", ":")).encode(),
            target_id=exchange.target_id, source=exchange.source, provider=exchange.capture_provider,
            observed_at=observed, retention=exchange.retention,
            provider_reference_hash=exchange.provider_reference_hash,
        )
        record = ResponseRecord(
            target_id=exchange.target_id, request_id=exchange.request.record.id,
            source=exchange.source, status_code=response.status_code,
            content_type=_content_type(response.headers),
            size_bytes=len(response.body) if response.body is not None else None,
            artifact_hash=body_evidence.content_hash if body_evidence else None,
            evidence_ids=tuple(item for item in (observation_evidence.evidence_id,
                                                body_evidence.evidence_id if body_evidence else None) if item),
            observed_at=observed,
        )
        try:
            with self.evidence._connection() as connection:
                row = connection.execute("SELECT state FROM traffic_exchanges WHERE exchange_id=? LIMIT 1",
                                         (exchange_id,)).fetchone()
                if row is None or row["state"] != ExchangeState.REQUEST_ONLY.value:
                    raise TrafficError("Traffic exchange cannot accept a response")
                connection.execute("""INSERT INTO traffic_responses
                    (response_id,target_id,request_id,source,status_code,content_type,header_names_json,
                     body_size,body_hash,artifact_hash,body_evidence_id,observation_evidence_id,
                     elapsed_ms,http_version,observed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                         record.id, exchange.target_id, record.request_id, record.source.value,
                         record.status_code, record.content_type, json.dumps(_header_names(response.headers)),
                         record.size_bytes, raw_body_hash, record.artifact_hash,
                         body_evidence.evidence_id if body_evidence else None, observation_evidence.evidence_id,
                         response.elapsed_ms, response.http_version, observed.isoformat(), record.created_at.isoformat(),
                     ))
                connection.execute("UPDATE traffic_exchanges SET state=? WHERE exchange_id=?",
                                   (ExchangeState.COMPLETE.value, exchange_id))
        except sqlite3.Error:
            raise TrafficError("Traffic persistence failed") from None
        result = self.get_exchange(exchange_id)
        assert result is not None
        return result

    def store_exchange(self, target: TargetPackage, packet: CapturePacket, *,
                       source: TrafficSource, capture_provider: str,
                       browser_manager: BrowserSessionManager | None = None,
                       declared_identity_id: str | None = None,
                       anonymous: bool = False,
                       retention: Retention = Retention()) -> TrafficExchange:
        if not isinstance(packet, CapturePacket):
            raise TrafficError("Invalid traffic capture")
        exchange = self.store_request(
            target, packet.request, source=source, capture_provider=capture_provider,
            browser_manager=browser_manager, browser_session_id=packet.browser_session_id,
            declared_identity_id=declared_identity_id, anonymous=anonymous,
            provider_reference=packet.provider_reference,
            browser_action_id=packet.browser_action_id, correlation_id=packet.correlation_id,
            retention=retention,
        )
        return self.store_response(exchange.id, packet.response) if packet.response else exchange

    def mark_incomplete(self, exchange_id: str, state: ExchangeState) -> TrafficExchange:
        validate_entity_id(exchange_id, "EXCHANGE")
        if state not in {ExchangeState.FAILED, ExchangeState.ABORTED, ExchangeState.TIMEOUT}:
            raise TrafficError("Invalid incomplete traffic state")
        with self.evidence._connection() as connection:
            changed = connection.execute("UPDATE traffic_exchanges SET state=?,failure_reason=? "
                                         "WHERE exchange_id=? AND state='REQUEST_ONLY'",
                                         (state.value, state.value, exchange_id)).rowcount
        if changed != 1:
            raise TrafficError("Traffic exchange cannot change state")
        result = self.get_exchange(exchange_id)
        assert result is not None
        return result

    def get_request(self, request_id: str) -> TrafficRequest | None:
        validate_entity_id(request_id, "REQUEST")
        with self.evidence._connection() as connection:
            row = connection.execute("SELECT * FROM traffic_requests WHERE request_id=? LIMIT 1",
                                     (request_id,)).fetchone()
        if row is None:
            return None
        evidence_ids = tuple(item for item in (row["observation_evidence_id"], row["body_evidence_id"]) if item)
        record = RequestRecord(
            id=row["request_id"], target_id=row["target_id"], method=row["method"],
            source=TrafficSource(row["source"]), url=None, principal_id=row["principal_id"],
            endpoint_id=row["endpoint_id"],
            operation_id=row["operation_id"], artifact_hash=row["artifact_hash"],
            evidence_ids=evidence_ids, observed_at=datetime.fromisoformat(row["observed_at"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )
        return TrafficRequest(
            record=record, origin=row["origin"], display_path=row["display_path"],
            path_fingerprint=row["path_fingerprint"], structural_fingerprint=row["structural_fingerprint"],
            query_names=tuple(json.loads(row["query_names_json"])),
            header_names=tuple(json.loads(row["header_names_json"])),
            content_type=row["content_type"], http_version=row["http_version"],
            body_evidence_id=row["body_evidence_id"], observation_evidence_id=row["observation_evidence_id"],
            body_size=row["body_size"], body_hash=row["body_hash"],
        )

    def get_response(self, response_id: str) -> TrafficResponse | None:
        validate_entity_id(response_id, "RESPONSE")
        with self.evidence._connection() as connection:
            row = connection.execute("SELECT * FROM traffic_responses WHERE response_id=? LIMIT 1",
                                     (response_id,)).fetchone()
        if row is None:
            return None
        evidence_ids = tuple(item for item in (row["observation_evidence_id"], row["body_evidence_id"]) if item)
        record = ResponseRecord(
            id=row["response_id"], target_id=row["target_id"], request_id=row["request_id"],
            source=TrafficSource(row["source"]), status_code=row["status_code"],
            content_type=row["content_type"], size_bytes=row["body_size"],
            artifact_hash=row["artifact_hash"], evidence_ids=evidence_ids,
            observed_at=datetime.fromisoformat(row["observed_at"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )
        return TrafficResponse(record=record, header_names=tuple(json.loads(row["header_names_json"])),
                               body_evidence_id=row["body_evidence_id"],
                               observation_evidence_id=row["observation_evidence_id"],
                               body_hash=row["body_hash"],
                               elapsed_ms=row["elapsed_ms"], http_version=row["http_version"])

    def get_exchange(self, exchange_id: str) -> TrafficExchange | None:
        validate_entity_id(exchange_id, "EXCHANGE")
        with self.evidence._connection() as connection:
            row = connection.execute("""SELECT e.*,r.response_id FROM traffic_exchanges e
                LEFT JOIN traffic_responses r ON r.request_id=e.request_id
                WHERE e.exchange_id=? LIMIT 1""", (exchange_id,)).fetchone()
        if row is None:
            return None
        request = self.get_request(row["request_id"])
        assert request is not None
        response = self.get_response(row["response_id"]) if row["response_id"] else None
        attribution = TrafficAttribution(
            auth_state=AuthState(row["auth_state"]), declared_identity_id=row["declared_identity_id"],
            verified_identity_id=row["verified_identity_id"], principal_id=row["principal_id"],
            principal_state=row["principal_state"],
            declared_tenant_ids=tuple(json.loads(row["declared_tenant_ids_json"])),
            declared_role_ids=tuple(json.loads(row["declared_role_ids_json"])),
            browser_session_id=row["browser_session_id"], auth_context_id=row["auth_context_id"],
        )
        retention = Retention(retain=bool(row["retain"]),
                              expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                              pinned=bool(row["pinned"]), finding_related=bool(row["finding_related"]))
        return TrafficExchange(
            id=row["exchange_id"], target_id=row["target_id"], package_id=row["package_id"],
            source=TrafficSource(row["source"]), capture_provider=row["capture_provider"],
            request=request, response=response, attribution=attribution,
            scope_result=ScopeResult(row["scope_result"]), scope_reason=row["scope_reason"],
            state=ExchangeState(row["state"]), sensitivity=Sensitivity(row["sensitivity"]),
            retention=retention, observed_at=datetime.fromisoformat(row["observed_at"]),
            provider_reference_hash=row["provider_reference_hash"],
            browser_action_hash=row["browser_action_hash"], correlation_hash=row["correlation_hash"],
            failure_reason=row["failure_reason"],
        )

    def _list(self, target_id: str, kind: str, value: str | None, *, limit: int,
              cursor: str | None) -> Page[TrafficExchange]:
        validate_entity_id(target_id, "TARGET")
        maximum = self._limit(limit)
        marker = _cursor_decode(cursor, target_id, kind, value)
        column = {
            "target": None, "identity": "verified_identity_id", "declared_identity": "declared_identity_id",
            "session": "browser_session_id", "anonymous": "auth_state", "endpoint": "endpoint_id",
            "operation": "operation_id", "recent": None, "correlation": "correlation_hash",
            "browser_action": "browser_action_hash", "fingerprint": "structural_fingerprint",
        }[kind]
        sql = "SELECT exchange_id,observed_at FROM traffic_exchanges WHERE target_id=?"
        params: list[object] = [target_id]
        if column is not None:
            sql += f" AND {column}=?"
            params.append("ANONYMOUS" if kind == "anonymous" else value)
        if kind == "recent" and value is not None:
            sql += " AND observed_at>=?"
            params.append(value)
        if marker is not None:
            sql += " AND (observed_at<? OR (observed_at=? AND exchange_id<?))"
            params.extend((marker[0], marker[0], marker[1]))
        sql += " ORDER BY observed_at DESC,exchange_id DESC LIMIT ?"
        params.append(maximum + 1)
        with self.evidence._connection() as connection:
            rows = connection.execute(sql, params).fetchall()
        kept = rows[:maximum]
        next_cursor = (_cursor_encode(target_id, kind, value, kept[-1]["observed_at"], kept[-1]["exchange_id"])
                       if len(rows) > maximum else None)
        items = []
        for row in kept:
            item = self.get_exchange(row["exchange_id"])
            if item is None:
                raise TrafficError("Traffic exchange disappeared during a bounded read")
            items.append(item)
        return Page(tuple(items), next_cursor)

    def list_exchanges_for_target(self, target_id: str, *, limit: int = 20,
                                  cursor: str | None = None) -> Page[TrafficExchange]:
        return self._list(target_id, "target", None, limit=limit, cursor=cursor)

    def list_exchanges_for_identity(self, target_id: str, identity_id: str, *,
                                    limit: int = 20, cursor: str | None = None,
                                    verified_only: bool = True) -> Page[TrafficExchange]:
        validate_entity_id(identity_id, "IDENTITY")
        return self._list(target_id, "identity" if verified_only else "declared_identity", identity_id,
                          limit=limit, cursor=cursor)

    def list_exchanges_for_session(self, target_id: str, session_id: str, *,
                                   limit: int = 20, cursor: str | None = None) -> Page[TrafficExchange]:
        validate_entity_id(session_id, "BSESSION")
        return self._list(target_id, "session", session_id, limit=limit, cursor=cursor)

    def list_anonymous(self, target_id: str, *, limit: int = 20,
                       cursor: str | None = None) -> Page[TrafficExchange]:
        return self._list(target_id, "anonymous", "ANONYMOUS", limit=limit, cursor=cursor)

    def find_by_endpoint(self, target_id: str, endpoint_id: str, *, limit: int = 20,
                         cursor: str | None = None) -> Page[TrafficExchange]:
        validate_entity_id(endpoint_id, "ENDPOINT")
        return self._list(target_id, "endpoint", endpoint_id, limit=limit, cursor=cursor)

    def find_by_operation(self, target_id: str, operation_id: str, *, limit: int = 20,
                          cursor: str | None = None) -> Page[TrafficExchange]:
        prefix = operation_id.split("-", 1)[0] if isinstance(operation_id, str) else ""
        if prefix not in {"OPERATION", "GQL"}:
            raise TrafficError("Invalid traffic operation")
        validate_entity_id(operation_id, prefix)
        return self._list(target_id, "operation", operation_id, limit=limit, cursor=cursor)

    def find_by_fingerprint(self, target_id: str, fingerprint: str, *, limit: int = 20,
                            cursor: str | None = None) -> Page[TrafficExchange]:
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise TrafficError("Invalid structural fingerprint")
        return self._list(target_id, "fingerprint", fingerprint, limit=limit, cursor=cursor)

    def find_recent(self, target_id: str, *, since: datetime | None = None,
                    limit: int = 20, cursor: str | None = None) -> Page[TrafficExchange]:
        cutoff = _utc(since).isoformat() if since is not None else None
        return self._list(target_id, "recent", cutoff, limit=limit, cursor=cursor)

    def find_by_correlation(self, target_id: str, correlation_id: str, *, limit: int = 20,
                            cursor: str | None = None) -> Page[TrafficExchange]:
        if not isinstance(correlation_id, str) or not 1 <= len(correlation_id) <= 2048:
            raise TrafficError("Invalid traffic correlation")
        return self._list(target_id, "correlation", _digest(correlation_id), limit=limit, cursor=cursor)

    def find_by_browser_action(self, target_id: str, action_id: str, *, limit: int = 20,
                               cursor: str | None = None) -> Page[TrafficExchange]:
        if not isinstance(action_id, str) or not 1 <= len(action_id) <= 2048:
            raise TrafficError("Invalid browser action correlation")
        return self._list(target_id, "browser_action", _digest(action_id), limit=limit, cursor=cursor)

    def stats(self, target_id: str, *, sample_limit: int = 1000) -> dict[str, object]:
        validate_entity_id(target_id, "TARGET")
        if type(sample_limit) is not int or not 1 <= sample_limit <= 1000:
            raise TrafficError("Traffic statistics sample limit must be between 1 and 1000")
        with self.evidence._connection() as connection:
            rows = connection.execute("""SELECT e.source,e.auth_state,e.verified_identity_id,e.scope_result,
                q.method,q.origin,r.status_code FROM traffic_exchanges e
                JOIN traffic_requests q ON q.request_id=e.request_id
                LEFT JOIN traffic_responses r ON r.request_id=e.request_id
                WHERE e.target_id=? ORDER BY e.observed_at DESC,e.exchange_id DESC LIMIT ?""",
                (target_id, sample_limit + 1)).fetchall()
        sample = rows[:sample_limit]
        def counts(key: str) -> dict[str, int]:
            result: dict[str, int] = {}
            for row in sample:
                item = row[key]
                label = "NONE" if item is None else str(item)
                result[label] = result.get(label, 0) + 1
            return dict(sorted(result.items()))
        return {"target_id": target_id, "sample_count": len(sample), "sample_limit": sample_limit,
                "truncated": len(rows) > sample_limit,
                "methods": counts("method"), "statuses": counts("status_code"),
                "hosts": counts("origin"), "sources": counts("source"),
                "auth_states": counts("auth_state"), "verified_identities": counts("verified_identity_id"),
                "scope_results": counts("scope_result")}
