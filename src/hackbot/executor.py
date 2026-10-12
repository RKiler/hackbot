"""Single policy-gated HTTP boundary for future controlled experiments."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
from pathlib import Path
import re
import socket
import time
from typing import Callable, Protocol
from urllib.parse import urljoin, urlsplit
import uuid
import zlib

import requests

from .auth import AuthContextManager, AuthMechanism, AuthStatus
from .config import ExecutorSettings
from .domain import TrafficSource, normalize_content_type
from .evidence import EvidenceProvenance, EvidenceType, Sensitivity
from .logging import SecretRedactor, is_sensitive_key
from .permit_store import PermitError, PolicyPermitStore
from .policy import PolicyEngine
from .policy_models import ActionCategory, ActorMode, PolicyPermit, ProposedAction, new_action_id
from .rate_limit import ExperimentBudget, RateLimiter
from .secrets import SecretKind, SecretProvider, SecretUnavailable
from .target_loader import TargetPackageRepository
from .target_policy import PolicyDecision
from .traffic import CapturedRequest, CapturedResponse, ExchangeState, TrafficStore


_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")
_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
_BLOCKED_HEADERS = frozenset({"host", "cookie", "authorization", "proxy-authorization",
                              "content-length", "transfer-encoding", "connection", "expect",
                              "accept-encoding"})
_REDIRECTS = frozenset({301, 302, 303, 307, 308})


class ExecutionError(StrEnum):
    POLICY_DENIED = "POLICY_DENIED"
    SCOPE_DENIED = "SCOPE_DENIED"
    PERMIT_DENIED = "PERMIT_DENIED"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    DNS_ERROR = "DNS_ERROR"
    TLS_ERROR = "TLS_ERROR"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    REDIRECT_DENIED = "REDIRECT_DENIED"
    AUTH_UNAVAILABLE = "AUTH_UNAVAILABLE"
    TOKEN_REQUIRED = "TOKEN_REQUIRED"
    IDENTITY_UNVERIFIED = "IDENTITY_UNVERIFIED"
    BODY_LIMIT_EXCEEDED = "BODY_LIMIT_EXCEEDED"
    PROXY_UNAVAILABLE = "PROXY_UNAVAILABLE"
    DIRECT_DISABLED = "DIRECT_DISABLED"
    INVALID_REQUEST = "INVALID_REQUEST"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    OPERATOR_STOPPED = "OPERATOR_STOPPED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


@dataclass(frozen=True, slots=True)
class RequestTemplate:
    """Non-secret, immutable request shape. Auth is applied only by the executor."""

    method: str
    url: str = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    body: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.method not in _METHODS or not isinstance(self.url, str) or not 1 <= len(self.url) <= 4096:
            raise ValueError("Invalid request template")
        if not isinstance(self.headers, tuple) or len(self.headers) > 64:
            raise ValueError("Invalid request headers")
        seen: set[str] = set()
        for pair in self.headers:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ValueError("Invalid request header")
            name, value = pair
            if (not isinstance(name, str) or not _HEADER.fullmatch(name) or not isinstance(value, str)
                    or len(value) > 8192 or any(ord(char) < 32 or ord(char) == 127 for char in value)
                    or name.lower() in seen or name.lower() in _BLOCKED_HEADERS
                    or name.lower().startswith("x-hackbot-") or is_sensitive_key(name)
                    or SecretRedactor().text(value) != value):
                raise ValueError("Unsafe request header")
            seen.add(name.lower())
        if self.body is not None and not isinstance(self.body, bytes):
            raise ValueError("Invalid request body")
        if self.method in {"GET", "HEAD"} and self.body not in (None, b""):
            raise ValueError("GET and HEAD bodies are not supported")

    def fingerprint(self) -> str:
        data = [self.method, self.url, self.headers,
                hashlib.sha256(self.body).hexdigest() if self.body is not None else None]
        return hashlib.sha256(json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ProxyRoute:
    url: str = field(repr=False)
    ca_certificate: Path | None = None

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.url)
            port = parsed.port
        except (TypeError, ValueError):
            raise ValueError("Invalid proxy listener") from None
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or port is None
                or parsed.username or parsed.password or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment):
            raise ValueError("Proxy must be an explicit loopback HTTP listener")
        if self.ca_certificate is not None and (
            not isinstance(self.ca_certificate, Path) or not self.ca_certificate.is_absolute()
            or not self.ca_certificate.is_file()
        ):
            raise ValueError("Proxy CA must be an existing local file")


class ExecutionProxyProvider(Protocol):
    def route(self, action: ProposedAction) -> ProxyRoute | None: ...


class TokenResolver(Protocol):
    """Trusted per-request token source; values never enter plan snapshots."""

    def resolve(self, action: ProposedAction, header_name: str) -> str | None: ...


@dataclass(frozen=True, slots=True)
class RedirectHop:
    status_code: int
    destination_sha256: str
    followed: bool


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    execution_id: str
    action_id: str
    permit_id: str | None
    decision_id: str | None
    approval_id: str | None
    exchange_ids: tuple[str, ...]
    error: ExecutionError | None
    status_code: int | None
    content_type: str | None
    body_bytes_captured: int
    truncated: bool
    redirects: tuple[RedirectHop, ...]
    started_at: datetime
    finished_at: datetime
    evidence_ids: tuple[str, ...]
    artifact_evidence_id: str | None = None


class _Stop(Exception):
    def __init__(self, code: ExecutionError):
        self.code = code


def _bounded_body(response: requests.Response, limit: int, deadline: float) -> tuple[bytes, bool]:
    """Decode gzip/deflate incrementally with an output cap, including bombs."""
    encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
    if encoding not in {"identity", "gzip", "deflate", ""}:
        raise _Stop(ExecutionError.EXECUTION_ERROR)
    decoder = (zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else
               zlib.decompressobj() if encoding == "deflate" else None)
    chunks: list[bytes] = []
    size = 0
    compressed_size = 0
    compressed_cap = max(limit * 4, 8192)
    try:
        for raw in response.raw.stream(8192, decode_content=False):
            if time.monotonic() >= deadline:
                raise _Stop(ExecutionError.TIMEOUT)
            compressed_size += len(raw)
            if compressed_size > compressed_cap:
                return b"".join(chunks), True
            decoded = decoder.decompress(raw, limit + 1 - size) if decoder else raw
            if decoded:
                chunks.append(decoded[:max(0, limit - size)])
                size += len(decoded)
            if size > limit:
                return b"".join(chunks), True
        if decoder is not None:
            tail = decoder.flush(limit + 1 - size)
            if tail:
                chunks.append(tail[:max(0, limit - size)])
                size += len(tail)
    except zlib.error:
        raise _Stop(ExecutionError.EXECUTION_ERROR) from None
    return b"".join(chunks), size > limit


def _dns_failure(error: BaseException) -> bool:
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending and len(seen) < 8:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, socket.gaierror) or type(current).__name__ == "NameResolutionError":
            return True
        for child in (current.__cause__, current.__context__, getattr(current, "reason", None)):
            if isinstance(child, BaseException):
                pending.append(child)
    return False


class TrafficExecutor:
    """One trusted process must own this executor and its shared RateLimiter."""

    def __init__(self, *, targets: TargetPackageRepository, policy: PolicyEngine,
                 permits: PolicyPermitStore, rate: RateLimiter, traffic: TrafficStore,
                 auth: AuthContextManager, secrets: SecretProvider,
                 settings: ExecutorSettings, proxy: ExecutionProxyProvider | None = None,
                 browser: object | None = None,
                 token_resolver: TokenResolver | None = None) -> None:
        self.targets = targets
        self.policy = policy
        self.permits = permits
        self.rate = rate
        self.traffic = traffic
        self.auth = auth
        self.secrets = secrets
        self.settings = settings
        self.proxy = proxy
        self.browser = browser
        self.token_resolver = token_resolver

    def authorize(self, action: ProposedAction, template: RequestTemplate) -> PolicyPermit:
        """Trusted, local-only permit issuance; never exposed as raw URL API."""
        if not self._matches(action, template):
            raise PermitError("Request does not match proposed action")
        package = self.targets.get_target_package(action.package_id)
        if package is None or package.target.id != action.target_id:
            raise PermitError("Target package is unavailable")
        decision = self.policy.evaluate(package, action, record=True)
        if decision.result is not PolicyDecision.ALLOW:
            raise PermitError("Policy did not authorize the action")
        return self.permits.issue(action, decision, template.fingerprint())

    @staticmethod
    def _matches(action: ProposedAction, template: RequestTemplate) -> bool:
        return (action.actor is not ActorMode.LOCAL and action.url == template.url
                and action.method == template.method and action.category is not ActionCategory.PASSIVE_ANALYSIS)

    def _authentication(self, action: ProposedAction) -> tuple[str, str] | None:
        if action.actor is ActorMode.ANONYMOUS:
            return None
        if action.actor is not ActorMode.AUTHENTICATED or action.identity_id is None:
            raise _Stop(ExecutionError.IDENTITY_UNVERIFIED)
        context = self.auth.get(action.target_id, action.identity_id)
        if (context is None or context.status is not AuthStatus.VALID
                or context.browser_session_ref != action.session_id
                or context.expires_at is not None and context.expires_at <= datetime.now(timezone.utc)):
            raise _Stop(ExecutionError.AUTH_UNAVAILABLE)
        identity = self.auth.registry.get_identity(action.target_id, action.identity_id)
        if identity is None or identity.secret_ref != context.secret_ref:
            raise _Stop(ExecutionError.AUTH_UNAVAILABLE)
        if context.mechanism not in {AuthMechanism.COOKIE, AuthMechanism.BEARER, AuthMechanism.HEADER}:
            raise _Stop(ExecutionError.AUTH_UNAVAILABLE)
        if not context.secret_ref:
            raise _Stop(ExecutionError.AUTH_UNAVAILABLE)
        try:
            meta = self.secrets.metadata(context.secret_ref)
            expected = {AuthMechanism.COOKIE: {SecretKind.COOKIE},
                        AuthMechanism.BEARER: {SecretKind.BEARER_TOKEN},
                        AuthMechanism.HEADER: {SecretKind.API_TOKEN, SecretKind.HEADER_SET}}[context.mechanism]
            if not meta.available or meta.kind not in expected:
                raise _Stop(ExecutionError.AUTH_UNAVAILABLE)
            value = self.secrets.get(context.secret_ref).reveal(execution_boundary=True)
        except (SecretUnavailable, ValueError):
            raise _Stop(ExecutionError.AUTH_UNAVAILABLE) from None
        if not value or any(char in value for char in "\r\n\x00"):
            raise _Stop(ExecutionError.AUTH_UNAVAILABLE)
        if context.mechanism is AuthMechanism.COOKIE:
            return "Cookie", value
        if context.mechanism is AuthMechanism.BEARER:
            return "Authorization", "Bearer " + value
        # HEADER_SET cannot be safely interpreted without a named-header schema.
        if meta.kind is SecretKind.HEADER_SET:
            raise _Stop(ExecutionError.AUTH_UNAVAILABLE)
        return "X-API-Key", value

    def _route(self, action: ProposedAction) -> ProxyRoute | None:
        required = self.settings.capture_required
        if action.session_id and self.browser is not None:
            session = self.browser.get(action.session_id)  # type: ignore[attr-defined]
            required = required or bool(session and session.proxy_capture_required)
        route = self.proxy.route(action) if self.proxy else None
        if route is not None and not isinstance(route, ProxyRoute):
            raise _Stop(ExecutionError.PROXY_UNAVAILABLE)
        if required and route is None:
            raise _Stop(ExecutionError.PROXY_UNAVAILABLE)
        if route is None and not self.settings.allow_direct:
            raise _Stop(ExecutionError.DIRECT_DISABLED)
        return route

    def execute(self, action: ProposedAction, permit: PolicyPermit | None,
                template: RequestTemplate, *, experiment_id: str | None = None,
                budget: ExperimentBudget = ExperimentBudget(),
                max_dispatches: int | None = None,
                execution_id: str | None = None,
                continue_dispatch: Callable[[], bool] | None = None,
                on_dispatch: Callable[[str], bool] | None = None,
                token_header: str | None = None,
                artifact_capture_kind: str | None = None) -> ExecutionResult:
        start = datetime.now(timezone.utc)
        execution_id = execution_id or "EXEC-" + uuid.uuid4().hex
        exchange_ids: list[str] = []
        evidence_ids: list[str] = []
        redirects: list[RedirectHop] = []
        error: ExecutionError | None = None
        status: int | None = None
        content_type: str | None = None
        body_size = 0
        truncated = False
        artifact_evidence_id: str | None = None
        initial = permit if isinstance(permit, PolicyPermit) else None
        deadline = time.monotonic() + self.settings.overall_timeout_seconds
        try:
            if not isinstance(template, RequestTemplate) or not isinstance(action, ProposedAction):
                raise _Stop(ExecutionError.INVALID_REQUEST)
            self.permits.record_attempt(action, "EXECUTION_REQUESTED", "PRECHECK")
            if initial is None:
                raise _Stop(ExecutionError.PERMIT_DENIED)
            if not self._matches(action, template):
                raise _Stop(ExecutionError.INVALID_REQUEST)
            if template.body is not None and len(template.body) > self.settings.max_request_bytes:
                raise _Stop(ExecutionError.BODY_LIMIT_EXCEEDED)
            if not isinstance(experiment_id, (str, type(None))) or (experiment_id is not None
                    and (not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", experiment_id))):
                raise _Stop(ExecutionError.INVALID_REQUEST)
            if max_dispatches is not None and (type(max_dispatches) is not int or
                                               not 1 <= max_dispatches <= 10000):
                raise _Stop(ExecutionError.INVALID_REQUEST)
            if not isinstance(execution_id, str) or not re.fullmatch(r"EXEC-[0-9a-f]{32}", execution_id):
                raise _Stop(ExecutionError.INVALID_REQUEST)
            if token_header is not None and (token_header != "X-CSRF-Token" or
                                             template.method not in {"POST", "PUT", "PATCH", "DELETE"} or
                                             action.actor is not ActorMode.AUTHENTICATED):
                raise _Stop(ExecutionError.INVALID_REQUEST)
            if artifact_capture_kind is not None and (
                artifact_capture_kind not in {"JS", "SOURCE_MAP"}
                or template.method != "GET" or action.category is not ActionCategory.SAFE_READ
                or template.body not in (None, b"")
            ):
                raise _Stop(ExecutionError.INVALID_REQUEST)
            current_action, current_template, current_permit = action, template, initial
            hop_limit = min(self.settings.max_redirects + 1, max_dispatches or self.settings.max_redirects + 1)
            for hop in range(hop_limit):
                if continue_dispatch is not None and not continue_dispatch():
                    raise _Stop(ExecutionError.OPERATOR_STOPPED)
                if time.monotonic() >= deadline:
                    raise _Stop(ExecutionError.TIMEOUT)
                package = self.targets.get_target_package(current_action.package_id)
                if package is None or package.target.id != current_action.target_id:
                    raise _Stop(ExecutionError.POLICY_DENIED)
                self.permits.record(current_permit, "HOP_REQUESTED", "PRECHECK")
                decision = self.policy.evaluate(package, current_action, record=True)
                self.permits.record(current_permit, "POLICY_RECHECKED", decision.reason_code)
                if decision.result is not PolicyDecision.ALLOW:
                    raise _Stop(ExecutionError.SCOPE_DENIED if decision.reason_code in {
                        "HOST_OUT_OF_SCOPE", "HOST_EXCLUDED", "PATH_EXCLUDED", "PATH_OUT_OF_SCOPE",
                        "SCHEME_OR_PORT_RESTRICTED", "UNKNOWN_SCOPE"} else ExecutionError.POLICY_DENIED)
                if decision.policy_version != current_permit.policy_version:
                    raise _Stop(ExecutionError.POLICY_DENIED)
                mutation = current_template.method not in {"GET", "HEAD", "OPTIONS"}
                reservation = self.rate.reserve(
                    current_action.target_id, package.rate, experiment_id=experiment_id,
                    budget=budget, mutation=mutation,
                    creation=current_action.category is ActionCategory.OBJECT_CREATE,
                    retry=False,
                )
                if not reservation.allowed or reservation.reservation_id is None:
                    raise _Stop(ExecutionError.RATE_LIMITED)
                self.permits.record(current_permit, "RATE_RESERVED", "WITHIN_RATE_POLICY")
                try:
                    if not self.permits.consume(current_permit, current_action,
                                                current_template.fingerprint(), decision.policy_version):
                        raise _Stop(ExecutionError.PERMIT_DENIED)
                    auth_header = self._authentication(current_action)
                    route = self._route(current_action)
                    headers = dict(current_template.headers)
                    headers["Accept-Encoding"] = "gzip, deflate"
                    if auth_header:
                        headers[auth_header[0]] = auth_header[1]
                    if token_header is not None:
                        if self.token_resolver is None:
                            raise _Stop(ExecutionError.TOKEN_REQUIRED)
                        try:
                            token = self.token_resolver.resolve(current_action, token_header)
                        except Exception:
                            raise _Stop(ExecutionError.TOKEN_REQUIRED) from None
                        if (not isinstance(token, str) or not 1 <= len(token) <= 8192 or
                                any(ord(char) < 33 or ord(char) > 126 for char in token)):
                            raise _Stop(ExecutionError.TOKEN_REQUIRED)
                        headers[token_header] = token
                    captured = CapturedRequest(
                        method=current_template.method, url=current_template.url,
                        headers=tuple(headers.items()), body=current_template.body,
                    )
                    exchange = self.traffic.store_request(
                        package, captured, source=TrafficSource.HACKBOT, capture_provider="HACKBOT",
                        browser_manager=self.browser if current_action.session_id else None,
                        browser_session_id=current_action.session_id,
                        anonymous=current_action.actor is ActorMode.ANONYMOUS,
                        auth_material_observed=bool(auth_header),
                        correlation_id=execution_id,
                        provider_reference=current_permit.id,
                    )
                    exchange_ids.append(exchange.id)
                    evidence_ids.extend(exchange.request.record.evidence_ids)
                    if on_dispatch is not None and not on_dispatch(exchange.id):
                        self.traffic.mark_incomplete(exchange.id, ExchangeState.ABORTED)
                        raise _Stop(ExecutionError.OPERATOR_STOPPED if continue_dispatch is not None
                                    and not continue_dispatch() else ExecutionError.BUDGET_EXHAUSTED)
                    self.permits.record(current_permit, "REQUEST_DISPATCHED", "BOUND_REQUEST", exchange.id)
                    began = time.monotonic()
                    try:
                        with requests.Session() as session:
                            session.trust_env = False
                            session.headers.clear()
                            timeout = (min(self.settings.connect_timeout_seconds, max(0.1, deadline - began)),
                                       min(self.settings.read_timeout_seconds, max(0.1, deadline - began)))
                            kwargs = {"headers": headers, "data": current_template.body,
                                      "allow_redirects": False, "stream": True, "timeout": timeout,
                                      "verify": str(route.ca_certificate) if route and route.ca_certificate else True}
                            if route:
                                kwargs["proxies"] = {"http": route.url, "https": route.url}
                            with session.request(current_template.method, current_template.url, **kwargs) as response:
                                self.permits.record(current_permit, "REQUEST_SENT", "BOUND_REQUEST", exchange.id)
                                status = response.status_code
                                response_headers = tuple((str(k), str(v)) for k, v in response.headers.items())
                                try:
                                    content_type = normalize_content_type(response.headers["Content-Type"])
                                except (KeyError, ValueError):
                                    content_type = None
                                body, truncated = _bounded_body(response, self.settings.max_response_bytes,
                                                                deadline)
                                body_size = len(body)
                                if truncated:
                                    response_headers += (("X-BugHunter-Capture-Truncated", "true"),)
                                observation = CapturedResponse(
                                    status_code=status, headers=response_headers, body=body,
                                    elapsed_ms=int((time.monotonic() - began) * 1000),
                                )
                    except requests.exceptions.Timeout:
                        self.traffic.mark_incomplete(exchange.id, ExchangeState.TIMEOUT)
                        raise _Stop(ExecutionError.TIMEOUT) from None
                    except _Stop as stop:
                        state = ExchangeState.TIMEOUT if stop.code is ExecutionError.TIMEOUT else ExchangeState.FAILED
                        self.traffic.mark_incomplete(exchange.id, state)
                        raise
                    except requests.exceptions.SSLError:
                        self.traffic.mark_incomplete(exchange.id, ExchangeState.FAILED)
                        raise _Stop(ExecutionError.TLS_ERROR) from None
                    except requests.exceptions.ConnectionError as exc:
                        self.traffic.mark_incomplete(exchange.id, ExchangeState.FAILED)
                        reason = ExecutionError.DNS_ERROR if _dns_failure(exc) else ExecutionError.CONNECTION_ERROR
                        raise _Stop(reason) from None
                    except requests.exceptions.RequestException:
                        self.traffic.mark_incomplete(exchange.id, ExchangeState.FAILED)
                        raise _Stop(ExecutionError.EXECUTION_ERROR) from None
                    stored = self.traffic.store_response(exchange.id, observation)
                    if stored.response is not None:
                        evidence_ids.extend(stored.response.record.evidence_ids)
                    if artifact_capture_kind and status == 200 and body and not truncated:
                        path = urlsplit(current_template.url).path.lower()
                        is_html = content_type in {"text/html", "application/xhtml+xml"}
                        accepted = (
                            not is_html and (
                                artifact_capture_kind == "JS" and (
                                    content_type in {"application/javascript", "text/javascript", "application/x-javascript"}
                                    or path.endswith((".js", ".mjs", ".cjs"))
                                ) or artifact_capture_kind == "SOURCE_MAP" and (
                                    content_type in {"application/json", "text/plain"} and path.endswith(".map")
                                )
                            )
                        )
                        if accepted:
                            asset_evidence = self.traffic.evidence.create_evidence(
                                EvidenceType.JS_ASSET if artifact_capture_kind == "JS" else EvidenceType.SOURCE_MAP,
                                body, source="controlled_asset_fetch",
                                provenance=EvidenceProvenance(system="HACKBOT", entity="ASSET_FETCH",
                                                               record_id=exchange.id),
                                target_ref=current_action.target_id, sensitivity=Sensitivity.SENSITIVE,
                                metadata={"exchange_id": exchange.id, "asset_kind": artifact_capture_kind},
                            )
                            artifact_evidence_id = asset_evidence.evidence_id
                            evidence_ids.append(asset_evidence.evidence_id)
                    self.permits.record(current_permit, "RESPONSE_RECEIVED", "HTTP_RESPONSE", exchange.id)
                finally:
                    self.rate.release(reservation.reservation_id)
                if status not in _REDIRECTS or "Location" not in response.headers:
                    break
                try:
                    destination = urljoin(current_template.url, response.headers["Location"])
                except ValueError:
                    self.permits.record(current_permit, "REDIRECT_EVALUATED", "REDIRECT_DENIED", exchange.id)
                    raise _Stop(ExecutionError.REDIRECT_DENIED) from None
                destination_hash = hashlib.sha256(destination.encode()).hexdigest()
                if hop >= hop_limit - 1 or current_template.method not in {"GET", "HEAD"}:
                    redirects.append(RedirectHop(status, destination_hash, False))
                    budget_limited = (max_dispatches is not None and
                                      max_dispatches < self.settings.max_redirects + 1 and
                                      hop >= hop_limit - 1 and current_template.method in {"GET", "HEAD"})
                    code = ExecutionError.BUDGET_EXHAUSTED if budget_limited else ExecutionError.REDIRECT_DENIED
                    self.permits.record(current_permit, "REDIRECT_EVALUATED", code.value, exchange.id)
                    raise _Stop(code)
                if current_action.actor is ActorMode.AUTHENTICATED:
                    old, new = urlsplit(current_template.url), urlsplit(destination)
                    if (old.scheme, old.netloc) != (new.scheme, new.netloc):
                        redirects.append(RedirectHop(status, destination_hash, False))
                        self.permits.record(current_permit, "REDIRECT_EVALUATED", "REDIRECT_DENIED", exchange.id)
                        raise _Stop(ExecutionError.REDIRECT_DENIED)
                redirected = replace(current_action, id=new_action_id(), url=destination)
                redirected_template = replace(current_template, url=destination)
                try:
                    redirected_permit = self.authorize(redirected, redirected_template)
                except (PermitError, ValueError):
                    redirects.append(RedirectHop(status, destination_hash, False))
                    self.permits.record(current_permit, "REDIRECT_EVALUATED", "REDIRECT_DENIED", exchange.id)
                    raise _Stop(ExecutionError.REDIRECT_DENIED) from None
                redirects.append(RedirectHop(status, destination_hash, True))
                self.permits.record(current_permit, "REDIRECT_EVALUATED", "REDIRECT_ALLOWED", exchange.id)
                current_action, current_template, current_permit = redirected, redirected_template, redirected_permit
        except _Stop as stop:
            error = stop.code
            try:
                if initial is not None:
                    self.permits.record(initial, "EXECUTION_FAILED", error.value,
                                        exchange_ids[-1] if exchange_ids else None)
                elif isinstance(action, ProposedAction):
                    self.permits.record_attempt(action, "EXECUTION_FAILED", error.value)
            except Exception:
                error = ExecutionError.EXECUTION_ERROR
        except Exception:
            error = ExecutionError.EXECUTION_ERROR
            if initial is not None:
                if exchange_ids:
                    try:
                        opened = self.traffic.get_exchange(exchange_ids[-1])
                        if opened is not None and opened.state is ExchangeState.REQUEST_ONLY:
                            self.traffic.mark_incomplete(opened.id, ExchangeState.FAILED)
                    except Exception:
                        pass  # Preserve the original safe failure; local store recovery is separate.
                try:
                    self.permits.record(initial, "EXECUTION_FAILED", error.value,
                                        exchange_ids[-1] if exchange_ids else None)
                except Exception:
                    pass
        else:
            if initial is not None:
                try:
                    self.permits.record(initial, "EXECUTION_COMPLETED", "HTTP_RESPONSE",
                                        exchange_ids[-1] if exchange_ids else None)
                except Exception:
                    error = ExecutionError.EXECUTION_ERROR
        return ExecutionResult(
            execution_id, action.id if isinstance(action, ProposedAction) else "",
            initial.id if initial else None,
            initial.decision_id if initial else None, initial.approval_id if initial else None,
            tuple(exchange_ids), error, status, content_type, body_size, truncated,
            tuple(redirects), start, datetime.now(timezone.utc), tuple(evidence_ids),
            artifact_evidence_id,
        )
