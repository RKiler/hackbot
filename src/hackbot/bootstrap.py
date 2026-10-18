"""Bounded, deterministic target discovery without a recon prerequisite."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
import hashlib
import json
import re
import time
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .bootstrap_store import (BootstrapIdentityPolicy, BootstrapLimits, BootstrapMode,
                              BootstrapResult, BootstrapStatus, BootstrapStore,
                              DiscoveryState)
from .browser import BrowserSessionManager, BrowserStatus
from .domxss_maps import referenced_source_map
from .domxss_static import DOMStaticAnalyzer
from .domxss_store import DOMXSSStore
from .evidence import EvidenceProvenance, EvidenceType, RedactionStatus, Sensitivity
from .executor import ExecutionError, RequestTemplate, TrafficExecutor
from .hypotheses import HypothesisGenerator, HypothesisStore
from .exposure import ExposureSpecialist
from .policy_models import ActionCategory, ActorMode, ProposedAction
from .profile import AttackSurfaceProfiler, _FEATURES, _shape, _tokens
from .postmessage_static import PostMessageStaticAnalyzer
from .postmessage_store import PostMessageStore
from .recon import ReconRepository
from .recon_postgres import ReconQueryError
from .store import EvidenceFactStore
from .target_loader import TargetPackageRepository
from .target_package import TargetPackage
from .target_scope import ScopeResult
from .traffic import TrafficStore


_DANGEROUS = frozenset({
    "logout", "signout", "disconnect", "delete", "remove", "purchase", "checkout", "pay",
    "cancel", "unsubscribe", "revoke", "destroy", "accept", "approve", "reject",
    "confirm", "create", "update", "edit", "submit", "send", "reset", "activate",
    "redeem", "join", "leave", "transfer", "trigger", "run", "publish", "archive",
    "restore", "upload", "import", "start", "stop",
})
_TRACKING = frozenset({"gclid", "fbclid", "msclkid", "ref", "source", "campaign"})
_SAFE_QUERY = frozenset({"tab", "page", "view", "section", "lang", "v", "ver", "version", "build"})
_API_TOKENS = {"graphql": "API_GRAPHQL", "gql": "API_GRAPHQL", "api": "API_REST",
               "rpc": "API_RPC", "trpc": "API_RPC", "oauth": "API_OAUTH",
               "authorize": "API_OAUTH", "swagger": "API_OPENAPI", "openapi": "API_OPENAPI"}
_JS_ROUTE = re.compile(r"(?<![A-Za-z0-9])['\"](\/(?:api|graphql|gql|rpc|trpc|oauth|v[1-9]\/api)\/[A-Za-z0-9_./{}-]{0,150}|\/(?:graphql|gql|rpc|trpc))['\"]")
_JS_UI_ROUTE = re.compile(r"['\"](\/(?:dashboard|settings|integrations|team|admin|projects|workspace)(?:\/[A-Za-z0-9_./{}-]{0,120})?)['\"]")
_JS_MANIFEST_ROUTE = re.compile(r"['\"](\/[A-Za-z][A-Za-z0-9_./{}-]{1,120})['\"]")
_JS_SERVICE_WORKER = re.compile(r"serviceWorker\.register\(\s*['\"](\/[A-Za-z0-9_./-]{1,120})['\"]")
_JS_WEBSOCKET = re.compile(r"new\s+WebSocket\s*\(\s*['\"]((?:wss?):\/\/[^'\"\s]{1,512})['\"]")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:24]


def _safe_url(base: str, value: str, package: TargetPackage) -> str | None:
    """Canonicalize only safe observed navigation; no credential-bearing queries."""
    if not isinstance(value, str) or len(value) > 2048 or any(ord(ch) < 32 for ch in value):
        return None
    try:
        parsed = urlsplit(urljoin(base, value))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        path = parsed.path or "/"
        if any(part in path for part in ("%", "\\", ";", "//")) or any(
                part in {".", ".."} for part in path.split("/")):
            return None
        segments = path.lower().split("/")
        if any(token in _DANGEROUS for token in _tokens(path)) or any(
                re.sub(r"[^a-z]", "", segment) in _DANGEROUS for segment in segments):
            return None
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=16)
        if any(key.lower().startswith("utm_") or key.lower() in _TRACKING for key, _ in pairs):
            pairs = [(key, item) for key, item in pairs
                     if not key.lower().startswith("utm_") and key.lower() not in _TRACKING]
        if any(key.lower() not in _SAFE_QUERY or len(item) > 32 or
               not re.fullmatch(r"[A-Za-z0-9_.-]*", item) or
               any(token in _DANGEROUS for token in _tokens(item)) for key, item in pairs):
            return None
        normalized = urlunsplit((parsed.scheme, parsed.netloc.lower(), path,
                                 urlencode(sorted(pairs)), ""))
        if package.scope.evaluate_url(normalized).result is not ScopeResult.IN_SCOPE:
            return None
        return normalized
    except (ValueError, UnicodeError):
        return None


def _display(url: str) -> str:
    parsed = urlsplit(url)
    return ((parsed.hostname or "unknown") + _shape(parsed.path or "/"))[:180]


def _looks_like_html(body: bytes) -> bool:
    prefix = body[:256].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    return prefix.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<?xml"))


def _navigation_priority(url: str) -> tuple[int, str]:
    tokens = set(_tokens(urlsplit(url).path))
    score = len(tokens & {"dashboard", "settings", "integrations", "team", "admin",
                           "projects", "workspace"})
    return (-score, url)


@dataclass(frozen=True, slots=True)
class DiscoverySignal:
    source: str
    code: str
    surface_key: str
    display: str
    source_ref: str | None = None
    observed_url: str | None = None


class DiscoveryProvider(Protocol):
    name: str
    def collect(self, package: TargetPackage) -> tuple[DiscoverySignal, ...]: ...


class ManualDiscoveryProvider:
    name = "MANUAL"

    def collect(self, package: TargetPackage) -> tuple[DiscoverySignal, ...]:
        signals = []
        for value in package.context.known_features[:20]:
            for token in _tokens(value):
                feature = _FEATURES.get(token)
                if feature:
                    signals.append(DiscoverySignal(self.name, "FEATURE_" + token.upper(),
                                                   _hash(feature), feature, package.id))
        return tuple(signals[:20])


class ReconDiscoveryProvider:
    name = "RECON"

    def __init__(self, recon: ReconRepository | None) -> None:
        self.recon = recon

    def lookup(self, package: TargetPackage):
        if self.recon is None:
            return None, "NOT_CONFIGURED"
        try:
            target = self.recon.resolve_target(package.primary_domain)
        except ReconQueryError:
            return None, "RECON_UNAVAILABLE"
        return target, "RECON_BACKED" if target else "NO_RECON_HISTORY"

    def resolve(self, package: TargetPackage):
        return self.lookup(package)[0]

    def collect(self, package: TargetPackage) -> tuple[DiscoverySignal, ...]:
        target = self.resolve(package)
        if target is None or self.recon is None:
            return ()
        signals = []
        try:
            for host in self.recon.list_hosts(target.domain_id, limit=8).items:
                if package.scope.evaluate_url(host.url).result is not ScopeResult.IN_SCOPE:
                    continue
                signals.append(DiscoverySignal(self.name, "HOST_OBSERVED", _hash(host.url),
                                               _display(host.url), str(host.host_id)))
                for endpoint in self.recon.list_endpoints(target.domain_id, host.host_id, limit=8).items:
                    url = urljoin(host.url + "/", endpoint.path.lstrip("/"))
                    if package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
                        continue
                    code = next((_API_TOKENS[token] for token in _tokens(endpoint.path)
                                 if token in _API_TOKENS), "ENDPOINT_OBSERVED")
                    signals.append(DiscoverySignal(self.name, code, _hash(url),
                                                   _display(url), str(endpoint.endpoint_id)))
        except ReconQueryError:
            pass  # Current local discovery remains valid when the read-only accelerator fails.
        return tuple(signals[:80])


class TrafficDiscoveryProvider:
    name = "COLD_START_TRAFFIC"

    def __init__(self, traffic: TrafficStore) -> None:
        self.traffic = traffic

    def collect(self, package: TargetPackage) -> tuple[DiscoverySignal, ...]:
        signals = []
        for exchange in self.traffic.list_filtered(package.target.id, limit=30).items:
            if exchange.scope_result is not ScopeResult.IN_SCOPE:
                continue
            location = exchange.request.origin + exchange.request.display_path
            tokens = _tokens(exchange.request.display_path)
            websocket_upgrade = (exchange.response is not None and
                                 exchange.response.record.status_code == 101 and
                                 "upgrade" in exchange.request.header_names)
            code = ("API_WEBSOCKET" if websocket_upgrade else
                    next((_API_TOKENS[token] for token in tokens if token in _API_TOKENS),
                         "TRAFFIC_OBSERVED"))
            signals.append(DiscoverySignal(self.name, code, _hash(location),
                                           _display(location), exchange.id))
        return tuple(signals)


class BrowserDiscoveryProvider:
    name = "COLD_START_BROWSER"

    def __init__(self, browser: BrowserSessionManager, driver: object) -> None:
        self.browser = browser
        self.driver = driver

    def collect_session(self, package: TargetPackage, session_id: str) -> tuple[DiscoverySignal, ...]:
        context = self.browser.session_context(session_id)
        if (context.target_id != package.target.id or not context.browser_available or
                context.authentication_status != "VALID" or context.identity_id is None):
            return ()
        observe = getattr(self.driver, "observe_current_page", None)
        if not callable(observe):
            return ()
        page = observe(session_id)
        if not isinstance(page, dict):
            return ()
        url = _safe_url(page.get("url", ""), page.get("url", ""), package)
        if not url:
            return ()
        signals = [DiscoverySignal(self.name, "PAGE_OBSERVED", _hash(url), _display(url),
                                   session_id, url)]
        for value in tuple(page.get("scripts", ()))[:20]:
            script = _safe_url(url, value, package)
            if script:
                signals.append(DiscoverySignal(self.name, "JS_ASSET", _hash(script),
                                               _display(script), session_id, script))
        for value in tuple(page.get("links", ()))[:20]:
            link = _safe_url(url, value, package)
            if link:
                signals.append(DiscoverySignal(self.name, "LINK_OBSERVED", _hash(link),
                                               _display(link), session_id))
        for value in tuple(page.get("forms", ()))[:10]:
            action = _safe_url(url, value, package)
            if action:
                signals.append(DiscoverySignal(self.name, "FORM_OBSERVED", _hash(action),
                                               _display(action), session_id))
        return tuple(signals)

    def collect(self, package: TargetPackage) -> tuple[DiscoverySignal, ...]:
        return ()  # A selected, verified session is required; never inspect every account.


class JavaScriptDiscoveryProvider:
    name = "COLD_START_JS"

    def collect(self, package: TargetPackage) -> tuple[DiscoverySignal, ...]:
        return ()  # Body analysis requires a current, policy-gated artifact.

    def analyze(self, package: TargetPackage, asset_url: str, body: bytes,
                artifact_id: str) -> tuple[DiscoverySignal, ...]:
        sample = body[:1_048_576].decode("utf-8", "replace")
        signals: list[DiscoverySignal] = []
        for match in list(_JS_ROUTE.finditer(sample))[:32]:
            path = match.group(1)
            url = urljoin(asset_url, path)
            if package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
                continue
            code = next((_API_TOKENS[token] for token in _tokens(path) if token in _API_TOKENS),
                        "JS_ENDPOINT_HINT")
            signals.append(DiscoverySignal(self.name, code, _hash(url), _display(url), artifact_id))
            if "{id}" in path or re.search(r"/[0-9]{2,}(?:/|$)", path):
                signals.append(DiscoverySignal(self.name, "OBJECT_ID", _hash(url + "object-id"),
                                               _display(url), artifact_id))
        for match in list(_JS_UI_ROUTE.finditer(sample))[:16]:
            route = urljoin(asset_url, match.group(1))
            if package.scope.evaluate_url(route).result is ScopeResult.IN_SCOPE:
                signals.append(DiscoverySignal(self.name, "ROUTE_HINT", _hash(route),
                                               _display(route), artifact_id))
        if "manifest" in urlsplit(asset_url).path.lower():
            for match in list(_JS_MANIFEST_ROUTE.finditer(sample))[:32]:
                path = match.group(1)
                if path.startswith(("/_next/static/", "/static/")) or path.endswith((".js", ".css", ".map")):
                    continue
                route = urljoin(asset_url, path)
                if package.scope.evaluate_url(route).result is ScopeResult.IN_SCOPE:
                    signals.append(DiscoverySignal(self.name, "ROUTE_HINT", _hash(route),
                                                   _display(route), artifact_id))
        for match in list(_JS_SERVICE_WORKER.finditer(sample))[:4]:
            resource = urljoin(asset_url, match.group(1))
            if package.scope.evaluate_url(resource).result is ScopeResult.IN_SCOPE:
                signals.append(DiscoverySignal(self.name, "SERVICE_WORKER_REFERENCE", _hash(resource),
                                               _display(resource), artifact_id))
        for match in list(_JS_WEBSOCKET.finditer(sample))[:8]:
            websocket_url = match.group(1)
            try:
                parsed = urlsplit(websocket_url)
                scheme = "https" if parsed.scheme == "wss" else "http"
                scope_url = urlunsplit((scheme, parsed.netloc, parsed.path or "/", "", ""))
            except (ValueError, UnicodeError):
                continue
            if _safe_url(asset_url, scope_url, package):
                signals.append(DiscoverySignal(self.name, "API_WEBSOCKET",
                                               _hash(websocket_url), _display(websocket_url), artifact_id))
        for pattern, code in (("MessageChannel", "JS_MESSAGECHANNEL"),
                              ("postMessage", "JS_POSTMESSAGE"),
                              ("WebSocket", "API_WEBSOCKET"),
                              ("grpc-web", "API_GRPC_WEB"),
                              ("ApolloClient", "API_GRAPHQL"),
                              ("ApolloClient", "TECHNOLOGY_APOLLO"),
                              ("RelayEnvironment", "TECHNOLOGY_RELAY"),
                              ("Vue.createApp", "TECHNOLOGY_VUE"),
                              ("platformBrowserDynamic", "TECHNOLOGY_ANGULAR"),
                              ("__NEXT_DATA__", "TECHNOLOGY_NEXTJS"),
                              ("React.createElement", "TECHNOLOGY_REACT")):
            if pattern in sample:
                signals.append(DiscoverySignal(self.name, code, _hash(asset_url + pattern),
                                               code.lower().replace("_", " "), artifact_id))
        for token in _tokens(sample[:32768]):
            if token in _FEATURES:
                feature = _FEATURES[token]
                signals.append(DiscoverySignal(self.name, "FEATURE_" + token.upper(),
                                               _hash(asset_url + feature), feature, artifact_id))
                if len(signals) >= 64:
                    break
        return tuple(signals[:64])


class _HTMLSignals(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[tuple[str, str]] = []
        self.specs: list[str] = []
        self.markers: set[str] = set()
        self.inline_signals: set[str] = set()
        self.has_password_input = False
        self._inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if len(self.links) + len(self.scripts) + len(self.forms) > 200:
            return
        attributes = dict(attrs)
        if tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        elif tag == "script":
            if attributes.get("src"):
                self.scripts.append(attributes["src"])
                self._inline_script = False
            else:
                self._inline_script = True
            if attributes.get("id") == "__NEXT_DATA__":
                self.markers.add("NEXTJS")
        elif tag == "form":
            self.forms.append((attributes.get("method", "GET").upper(), attributes.get("action", "")))
        elif tag == "input" and (attributes.get("type") or "").lower() == "password":
            self.has_password_input = True
        elif tag == "link" and attributes.get("href"):
            href = attributes["href"]
            if href.endswith(("openapi.json", "swagger.json")):
                self.specs.append(href)
        elif tag == "meta" and attributes.get("name", "").lower() == "generator":
            generator = (attributes.get("content") or "").lower()
            for name in ("nextjs", "react", "vue", "angular"):
                if name in generator:
                    self.markers.add(name.upper())

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._inline_script = False

    def handle_data(self, data: str) -> None:
        if not self._inline_script or len(data) > 262_144:
            return
        for marker, code in (("postMessage", "JS_POSTMESSAGE"),
                             ("MessageChannel", "JS_MESSAGECHANNEL"),
                             ("WebSocket", "API_WEBSOCKET"),
                             ("/graphql", "API_GRAPHQL"),
                             ("__NUXT__", "TECHNOLOGY_NUXT")):
            if marker in data:
                self.inline_signals.add(code)


class TargetBootstrapper:
    """Service-owned finite discovery; active reads go exclusively through TrafficExecutor."""

    def __init__(self, *, targets: TargetPackageRepository, recon: ReconRepository | None,
                 ledger: BootstrapStore, evidence: EvidenceFactStore, traffic: TrafficStore,
                 browser: BrowserSessionManager, driver: object, executor: TrafficExecutor,
                 js: DOMXSSStore, postmessage: PostMessageStore,
                 exposure: ExposureSpecialist, profiles: HypothesisStore, registry: object) -> None:
        self.targets, self.recon, self.ledger = targets, recon, ledger
        self.evidence, self.traffic, self.browser, self.driver = evidence, traffic, browser, driver
        self.executor, self.js, self.profiles, self.registry = executor, js, profiles, registry
        self.postmessage, self.exposure = postmessage, exposure
        self.dom_analyzer = DOMStaticAnalyzer()
        self.message_analyzer = PostMessageStaticAnalyzer()
        self.manual = ManualDiscoveryProvider()
        self.recon_provider = ReconDiscoveryProvider(recon)
        self.traffic_provider = TrafficDiscoveryProvider(traffic)
        self.browser_provider = BrowserDiscoveryProvider(browser, driver)
        self.js_provider = JavaScriptDiscoveryProvider()

    def create(self, package_id: str, *, limits: BootstrapLimits = BootstrapLimits(),
               identity_policy: BootstrapIdentityPolicy = BootstrapIdentityPolicy.ANONYMOUS_PLUS_PRIMARY,
               identity_id: str | None = None,
               campaign_work_id: str | None = None) -> BootstrapResult:
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise LookupError("Target Package not found")
        if package.status.value != "TRACKED":
            raise ValueError("Target Package is not active")
        if identity_id and identity_policy is BootstrapIdentityPolicy.ANONYMOUS_ONLY:
            raise ValueError("Anonymous bootstrap cannot select an account")
        if identity_policy is BootstrapIdentityPolicy.PRIMARY_IDENTITY and identity_id is None:
            raise ValueError("A verified primary identity must be selected")
        recon_target = self.recon_provider.resolve(package)
        if identity_id is not None and self.browser.get_active_session(package.target.id, identity_id) is None:
            raise ValueError("Selected identity has no verified active browser session")
        return self.ledger.create(package.target.id, package.id,
                                  BootstrapMode.RECON_BACKED if recon_target else BootstrapMode.COLD_START,
                                  identity_policy, limits, identity_id=identity_id,
                                  recon_domain_id=recon_target.domain_id if recon_target else None,
                                  campaign_work_id=campaign_work_id)

    def capture_browser_signals(self, package: TargetPackage,
                                run: BootstrapResult) -> tuple[DiscoverySignal, ...]:
        """Snapshot an already open page on the browser-owning service thread."""
        if run.identity_policy is BootstrapIdentityPolicy.ANONYMOUS_ONLY:
            return ()
        session = (self.browser.get_active_session(run.target_id, run.identity_id)
                   if run.identity_id else None)
        if session is None and run.identity_policy is BootstrapIdentityPolicy.ANONYMOUS_PLUS_PRIMARY:
            for candidate in self.browser.list_sessions_for_target(run.target_id, limit=20).items:
                if candidate.identity_id:
                    session = self.browser.get_active_session(run.target_id, candidate.identity_id)
                    if session is not None:
                        break
        if session is None:
            return ()
        return self.browser_provider.collect_session(package, session.id)

    def _record(self, run: BootstrapResult, signal: DiscoverySignal, counts: dict[str, int]) -> None:
        # Derived metadata is safe to index. Original HTML/JS/traffic stays protected.
        content = json.dumps({"code": signal.code, "surface_key": signal.surface_key},
                             separators=(",", ":")).encode()
        observation = self.evidence.create_evidence(
            EvidenceType.BROWSER_EVENT, content, source="cold_start_bootstrap",
            provenance=EvidenceProvenance(system="HACKBOT", entity=signal.source,
                                           record_id=signal.source_ref),
            target_ref=run.target_id, sensitivity=Sensitivity.INTERNAL,
            metadata={"source": signal.source, "surface_digest": signal.surface_key})
        if not self.ledger.add_observation(run.bootstrap_id, run.target_id, signal.source,
                                           signal.code, signal.surface_key, signal.display,
                                           observation.evidence_id, signal.source_ref):
            return
        predicate = "uses_technology" if signal.code.startswith("TECHNOLOGY_") else "bootstrap_signal"
        value = signal.code.removeprefix("TECHNOLOGY_") if predicate == "uses_technology" else signal.code
        self.evidence.create_fact("bootstrap:" + signal.surface_key, predicate, value,
                                  confidence=0.65 if signal.source != "RECON" else 0.55,
                                  evidence_ids=(observation.evidence_id,), source=signal.source,
                                  target_ref=run.target_id)
        counts["facts_created"] += 1
        if signal.code.startswith("API_") or signal.code == "JS_ENDPOINT_HINT":
            counts["api_surfaces_observed"] += 1
        if signal.code.startswith("TECHNOLOGY_"):
            counts["technologies_detected"] += 1
        if signal.code.startswith("FEATURE_"):
            counts["features_detected"] += 1

    def _fetch(self, run: BootstrapResult, package: TargetPackage, url: str,
               kind: str | None, deadline: float):
        current = self.ledger.get(run.bootstrap_id, run.target_id)
        assert current is not None
        remaining = current.limits.max_requests - current.counts["requests_used"]
        if remaining <= 0:
            return None
        action = ProposedAction(package.target.id, package.id, ActionCategory.SAFE_READ,
                                ActorMode.ANONYMOUS, "cold_start_bootstrap",
                                "Bounded first-party discovery read", url=url, method="GET")
        template = RequestTemplate("GET", url)
        try:
            permit = self.executor.authorize(action, template)
        except (ValueError, RuntimeError):
            return None
        return self.executor.execute(
            action, permit, template, max_dispatches=min(remaining, run.limits.max_redirects + 1),
            artifact_capture_kind=kind,
            continue_dispatch=lambda: time.monotonic() < deadline and
                not self.ledger.cancelled(run.bootstrap_id, run.target_id),
            on_dispatch=lambda _exchange_id: self.ledger.reserve_request(run.bootstrap_id, run.target_id),
            redirect_guard=lambda destination: _safe_url(destination, destination, package) is not None,
        )

    def _body(self, exchange_id: str, max_bytes: int) -> bytes | None:
        exchange = self.traffic.get_exchange(exchange_id)
        if exchange is None or exchange.response is None or not exchange.response.body_evidence_id:
            return None
        record = self.evidence.get_evidence(exchange.response.body_evidence_id)
        if record is None or record.redaction_status is RedactionStatus.WITHHELD:
            return None
        try:
            return self.evidence.read_content(exchange.response.body_evidence_id,
                                              allow_sensitive=True, max_bytes=max_bytes)
        except (ValueError, OSError):
            return None

    def run(self, run_id: str, package_id: str, *, refresh: bool = False,
            browser_signals: tuple[DiscoverySignal, ...] | None = None) -> BootstrapResult:
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise LookupError("Target Package not found")
        run = self.ledger.get(run_id, package.target.id)
        if run is None or run.package_id != package.id or run.status is not BootstrapStatus.CREATED:
            raise ValueError("Bootstrap run is unavailable")
        self.ledger.transition(run_id, run.target_id, BootstrapStatus.RUNNING)
        counts = dict(run.counts)
        limits = run.limits
        deadline = time.monotonic() + limits.max_bootstrap_duration
        limitations: set[str] = set()
        stop_reason = "FRONTIER_EXHAUSTED"
        pages: deque[tuple[str, int]] = deque()
        js_urls: deque[str] = deque()
        map_urls: deque[tuple[str, str]] = deque()
        spec_urls: deque[str] = deque()
        visited: set[str] = set()
        seen_js: set[str] = set()
        exchanges: set[str] = set()
        auth_required = False
        browser_profiled = False

        try:
            _, recon_status = self.recon_provider.lookup(package)
            if recon_status == "RECON_UNAVAILABLE":
                limitations.add("RECON_UNAVAILABLE")
            for provider in (self.manual, self.recon_provider, self.traffic_provider):
                for signal in provider.collect(package):
                    self._record(run, signal, counts)
            if run.mode is BootstrapMode.COLD_START and recon_status == "NO_RECON_HISTORY":
                limitations.add("NO_RECON_HISTORY")
            elif run.mode is BootstrapMode.COLD_START and recon_status == "NOT_CONFIGURED":
                limitations.add("RECON_NOT_CONFIGURED")
            for host in package.scope.include_hosts[:8]:
                if host.pattern.startswith("*."):
                    continue  # Wildcard scope is not a host seed or subdomain authorization.
                schemes = host.schemes or package.scope.default_schemes
                for scheme in ("https", "http"):
                    if scheme not in schemes:
                        continue
                    port = (host.ports or package.scope.default_ports or ())
                    default = 443 if scheme == "https" else 80
                    selected = next((item for item in port if item == default), port[0] if port else default)
                    root = f"{scheme}://{host.pattern}" + (f":{selected}" if selected != default else "") + "/"
                    url = _safe_url(root, root, package)
                    if url:
                        pages.append((url, 0))
                        break
            if not pages:
                limitations.add("NO_EXACT_HOST_SEED")

            if run.identity_policy is not BootstrapIdentityPolicy.ANONYMOUS_ONLY:
                signals = browser_signals if browser_signals is not None else self.capture_browser_signals(package, run)
                browser_profiled = bool(signals)
                for signal in signals:
                    self._record(run, signal, counts)
                    if signal.code == "JS_ASSET" and signal.observed_url and signal.observed_url not in seen_js:
                        js_urls.append(signal.observed_url)
                        seen_js.add(signal.observed_url)
                        counts["js_assets_discovered"] += 1
                counts["authenticated_pages"] += int(browser_profiled)
                counts["pages_visited"] += int(browser_profiled)
                if not browser_profiled:
                    limitations.add("AUTHENTICATED_COVERAGE_UNAVAILABLE")
                    limitations.add("VERIFIED_BROWSER_UNAVAILABLE")

            while pages or js_urls or map_urls or spec_urls:
                if self.ledger.cancelled(run_id, run.target_id):
                    stop_reason = "CANCELLED"
                    break
                if time.monotonic() >= deadline:
                    stop_reason = "TIME_LIMIT"
                    limitations.add("TIME_LIMIT")
                    break
                current = self.ledger.get(run_id, run.target_id)
                assert current is not None
                if current.counts["requests_used"] >= limits.max_requests:
                    stop_reason = "REQUEST_BUDGET"
                    limitations.add("REQUEST_BUDGET_EXHAUSTED")
                    break

                if pages and counts["pages_visited"] < limits.max_pages:
                    url, depth = pages.popleft()
                    if url in visited:
                        continue
                    visited.add(url)
                    result = self._fetch(run, package, url, None, deadline)
                    if result is None:
                        limitations.add("POLICY_OR_EXECUTOR_UNAVAILABLE")
                        continue
                    exchanges.update(result.exchange_ids)
                    if result.error:
                        limitations.add(result.error.value)
                    if result.status_code in {401, 403} or urlsplit(url).path.lower().startswith(("/login", "/signin")):
                        auth_required = True
                        self._record(run, DiscoverySignal("COLD_START_TRAFFIC", "BOUNDARY_AUTHENTICATED",
                                      _hash(url + "auth-boundary"), _display(url),
                                      result.exchange_ids[-1] if result.exchange_ids else None), counts)
                    if (result.status_code != 200 or result.content_type not in
                            {"text/html", "application/xhtml+xml"} or result.truncated or not result.exchange_ids):
                        continue
                    body = self._body(result.exchange_ids[-1], min(limits.max_asset_bytes, 262_144))
                    if body is None:
                        limitations.add("HTML_BODY_UNAVAILABLE")
                        continue
                    counts["pages_visited"] += 1
                    counts["anonymous_pages"] += 1
                    self._record(run, DiscoverySignal("COLD_START_TRAFFIC", "PAGE_OBSERVED",
                                  _hash(url), _display(url), result.exchange_ids[-1]), counts)
                    html = _HTMLSignals()
                    html.feed(body.decode("utf-8", "replace"))
                    if html.has_password_input:
                        auth_required = True
                        self._record(run, DiscoverySignal("COLD_START_TRAFFIC", "BOUNDARY_AUTHENTICATED",
                                      _hash(url + "password-form"), _display(url),
                                      result.exchange_ids[-1]), counts)
                    for marker in html.markers:
                        self._record(run, DiscoverySignal("COLD_START_TRAFFIC", "TECHNOLOGY_" + marker,
                                      _hash(url + marker), marker, result.exchange_ids[-1]), counts)
                    for code in html.inline_signals:
                        self._record(run, DiscoverySignal("COLD_START_TRAFFIC", code,
                                      _hash(url + code), code.lower().replace("_", " "),
                                      result.exchange_ids[-1]), counts)
                    for raw in html.scripts[:limits.max_js_assets * 3]:
                        script = _safe_url(url, raw, package)
                        if script and script not in seen_js:
                            js_urls.append(script)
                            seen_js.add(script)
                            counts["js_assets_discovered"] += 1
                            self._record(run, DiscoverySignal("COLD_START_TRAFFIC", "JS_ASSET",
                                          _hash(script), _display(script), result.exchange_ids[-1]), counts)
                        elif script is None and raw.startswith(("https://", "http://")):
                            self._record(run, DiscoverySignal("COLD_START_TRAFFIC", "THIRD_PARTY_REFERENCE",
                                          _hash(raw), "external resource reference", result.exchange_ids[-1]), counts)
                    for method, action in html.forms[:10]:
                        if method == "GET" and any(token in _tokens(action) for token in ("login", "signin")):
                            auth_required = True
                        self._record(run, DiscoverySignal("COLD_START_TRAFFIC", "FORM_OBSERVED",
                                      _hash(url + action + method), "form " + method,
                                      result.exchange_ids[-1]), counts)
                    for raw in html.specs[:2]:
                        spec = _safe_url(url, raw, package)
                        if spec:
                            spec_urls.append(spec)
                    navigable: set[str] = set()
                    for raw in html.links[:40]:
                        link = _safe_url(url, raw, package)
                        if link:
                            navigable.add(link)
                        elif len(raw) > 2048:
                            continue
                        try:
                            parsed_link = urlsplit(urljoin(url, raw))
                            reference = urlunsplit((parsed_link.scheme, parsed_link.netloc,
                                                    parsed_link.path or "/", "", ""))
                            observed = link or (_safe_url(url, reference, package)
                                                if parsed_link.query else None)
                        except (ValueError, UnicodeError):
                            continue
                        if not observed:
                            continue
                        try:
                            parameters = parse_qsl(parsed_link.query, keep_blank_values=True,
                                                   max_num_fields=16)
                        except ValueError:
                            parameters = []
                        for name, value in parameters:
                            if (re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name) and
                                    not name.lower().startswith("utm_") and name.lower() not in _TRACKING):
                                self._record(run, DiscoverySignal("COLD_START_TRAFFIC",
                                    "PARAM_OBSERVED", _hash(observed + name),
                                    f"parameter {name} ({'nonempty' if value else 'empty'})",
                                    result.exchange_ids[-1]), counts)
                        for token in _tokens(urlsplit(observed).path):
                            api_code = _API_TOKENS.get(token)
                            if api_code:
                                self._record(run, DiscoverySignal("COLD_START_TRAFFIC",
                                    api_code, _hash(observed + api_code), _display(observed),
                                    result.exchange_ids[-1]), counts)
                            feature = _FEATURES.get(token)
                            if feature:
                                self._record(run, DiscoverySignal("COLD_START_TRAFFIC",
                                    "FEATURE_" + token.upper(), _hash(observed + feature),
                                    feature, result.exchange_ids[-1]), counts)
                    if depth < limits.max_navigation_depth:
                        for link in sorted(navigable, key=_navigation_priority):
                            if link not in visited and len(pages) < limits.max_pages * 4:
                                pages.append((link, depth + 1))
                    continue

                if js_urls and counts["js_assets_acquired"] < limits.max_js_assets:
                    url = js_urls.popleft()
                    previous_asset = self.js.cached_cold_start_asset(run.target_id, url)
                    asset = None if refresh else previous_asset
                    if asset is None:
                        result = self._fetch(run, package, url, "JS", deadline)
                        if result is None:
                            limitations.add("JS_POLICY_BLOCKED")
                            continue
                        exchanges.update(result.exchange_ids)
                        if result.error or result.status_code != 200 or result.truncated or not result.artifact_evidence_id:
                            limitations.add("JS_FETCH_UNAVAILABLE")
                            continue
                        try:
                            body = self.evidence.read_content(result.artifact_evidence_id,
                                                              allow_sensitive=True,
                                                              max_bytes=limits.max_asset_bytes)
                        except ValueError:
                            limitations.add("JS_ASSET_EXCEEDS_LIMIT")
                            continue
                        if _looks_like_html(body):
                            limitations.add("JS_NON_SCRIPT_RESPONSE")
                            continue
                        asset = self.js.record_artifact(target_id=run.target_id, asset_url=url, body=body,
                                                        recon_asset_id=None, recon_sha256=None,
                                                        source="CONTROLLED_HTTP",
                                                        retrieval_exchange_id=result.exchange_ids[-1],
                                                        capture_evidence_id=result.artifact_evidence_id)
                        if previous_asset and previous_asset.artifact_sha256 != asset.artifact_sha256:
                            counts["js_assets_changed"] += 1
                            self._record(run, DiscoverySignal("COLD_START_JS", "JS_HASH_CHANGED",
                                          _hash(url + asset.artifact_sha256), _display(url),
                                          asset.artifact_id), counts)
                    else:
                        try:
                            body = self.evidence.read_content(asset.evidence_id, allow_sensitive=True,
                                                              max_bytes=limits.max_asset_bytes)
                        except ValueError:
                            limitations.add("CACHED_JS_EXCEEDS_LIMIT")
                            continue
                    if _looks_like_html(body):
                        limitations.add("JS_NON_SCRIPT_RESPONSE")
                        continue
                    counts["js_assets_acquired"] += 1
                    self._record(run, DiscoverySignal("COLD_START_JS", "JS_ACQUIRED",
                                  _hash(url), _display(url), asset.artifact_id), counts)
                    for signal in self.js_provider.analyze(package, url, body, asset.artifact_id):
                        self._record(run, signal, counts)
                    if b"location" in body or b"postMessage" in body or b"MessageChannel" in body:
                        try:
                            _, analysis = self.js.analyze_asset(run.target_id, asset.artifact_id,
                                                                self.dom_analyzer)
                            if analysis.status == "PARSE_FAILED":
                                limitations.add("JS_DOM_PARSER_FAILURE")
                            if analysis.candidates:
                                self._record(run, DiscoverySignal("COLD_START_JS", "JS_DOM_CANDIDATE",
                                    _hash(url + "dom"), "static DOM candidate", asset.artifact_id), counts)
                        except (ValueError, OSError, RuntimeError):
                            limitations.add("JS_DOM_ANALYSIS_UNAVAILABLE")
                    if b"postMessage" in body or b"MessageChannel" in body:
                        try:
                            _, analysis = self.postmessage.analyze_asset(run.target_id, asset.artifact_id,
                                                                          self.message_analyzer)
                            if analysis.status == "PARSE_FAILED":
                                limitations.add("JS_MESSAGE_PARSER_FAILURE")
                            if analysis.candidates:
                                self._record(run, DiscoverySignal("COLD_START_JS", "JS_MESSAGE_CANDIDATE",
                                    _hash(url + "message"), "static messaging candidate", asset.artifact_id), counts)
                        except (ValueError, OSError, RuntimeError):
                            limitations.add("JS_MESSAGE_ANALYSIS_UNAVAILABLE")
                    if any(marker in body for marker in (b"api_key", b"API_KEY", b"client_secret",
                                                           b"CLIENT_SECRET", b"private_key")):
                        try:
                            analysis = self.exposure.analyze_js(package, asset.artifact_id,
                                                                 fixture_url=url)
                            if analysis.candidate_ids:
                                self._record(run, DiscoverySignal("COLD_START_JS", "JS_EXPOSURE_CANDIDATE",
                                    _hash(url + "exposure"), "static exposure candidate", asset.artifact_id), counts)
                        except (ValueError, OSError, RuntimeError):
                            limitations.add("JS_EXPOSURE_ANALYSIS_UNAVAILABLE")
                    map_url = referenced_source_map(url, body)
                    if map_url and _safe_url(url, map_url, package) == map_url and len(map_urls) < 2:
                        map_urls.append((map_url, asset.artifact_id))
                    elif map_url:
                        limitations.add("SOURCE_MAP_OUT_OF_SCOPE_OR_UNSAFE")
                    continue

                if map_urls:
                    url, asset_id = map_urls.popleft()
                    if self.js.get_source_map(run.target_id, asset_id):
                        counts["source_maps_acquired"] += 1
                        continue
                    result = self._fetch(run, package, url, "SOURCE_MAP", deadline)
                    if result and result.status_code == 200 and not result.truncated and result.artifact_evidence_id:
                        exchanges.update(result.exchange_ids)
                        try:
                            body = self.evidence.read_content(result.artifact_evidence_id,
                                                              allow_sensitive=True,
                                                              max_bytes=limits.max_asset_bytes)
                        except ValueError:
                            limitations.add("SOURCE_MAP_EXCEEDS_LIMIT")
                            continue
                        self.js.record_source_map(target_id=run.target_id, js_artifact_id=asset_id,
                                                  map_url=url, body=body, source="CONTROLLED_HTTP",
                                                  retrieval_exchange_id=result.exchange_ids[-1],
                                                  capture_evidence_id=result.artifact_evidence_id)
                        counts["source_maps_acquired"] += 1
                    else:
                        limitations.add("SOURCE_MAP_UNAVAILABLE")
                    continue

                if spec_urls:
                    url = spec_urls.popleft()
                    result = self._fetch(run, package, url, None, deadline)
                    if result:
                        exchanges.update(result.exchange_ids)
                        if result.status_code == 200 and not result.truncated and result.exchange_ids:
                            body = self._body(result.exchange_ids[-1], min(limits.max_asset_bytes, 262_144))
                            try:
                                data = json.loads(body) if body else None
                            except (ValueError, UnicodeError):
                                data = None
                            if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                                self._record(run, DiscoverySignal("COLD_START_TRAFFIC", "API_OPENAPI",
                                              _hash(url), _display(url), result.exchange_ids[-1]), counts)
                    continue

                break

            counts["requests_used"] = self.ledger.get(run_id, run.target_id).counts["requests_used"]
            counts["traffic_exchanges_recorded"] = len(exchanges)
            if pages:
                limitations.add("ROUTE_FRONTIER_UNVISITED")
            if js_urls:
                limitations.add("JS_ASSETS_UNVISITED")
            if map_urls:
                limitations.add("SOURCE_MAP_UNAVAILABLE")
            self.ledger.transition(run_id, run.target_id, BootstrapStatus.RUNNING,
                                   counts=counts, limitations=tuple(limitations))
            if stop_reason == "CANCELLED":
                status = BootstrapStatus.CANCELLED
            elif stop_reason in {"REQUEST_BUDGET", "TIME_LIMIT"}:
                status = BootstrapStatus.BUDGET_EXHAUSTED
            elif {"POLICY_OR_EXECUTOR_UNAVAILABLE", "DIRECT_DISABLED", "PROXY_UNAVAILABLE",
                  "POLICY_DENIED", "SCOPE_DENIED", "PERMIT_DENIED"} & limitations:
                status = (BootstrapStatus.PARTIAL if counts["pages_visited"] or
                          counts["traffic_exchanges_recorded"] else BootstrapStatus.BLOCKED)
            elif not counts["pages_visited"] and not browser_profiled and not counts["traffic_exchanges_recorded"]:
                status = BootstrapStatus.PARTIAL
            elif "HTML_BODY_UNAVAILABLE" in limitations:
                status = BootstrapStatus.PARTIAL
            elif (auth_required or "AUTHENTICATED_COVERAGE_UNAVAILABLE" in limitations) and not browser_profiled:
                status = BootstrapStatus.PARTIAL
                limitations.add("AUTHENTICATED_COVERAGE_UNAVAILABLE")
            else:
                status = BootstrapStatus.COMPLETED
            try:
                profile = AttackSurfaceProfiler(self.registry, self.evidence, self.traffic,
                                                self.recon, bootstrap=self.ledger).profile(package)
            except ReconQueryError:
                limitations.add("RECON_PROFILE_UNAVAILABLE")
                profile = AttackSurfaceProfiler(self.registry, self.evidence, self.traffic,
                                                None, bootstrap=self.ledger).profile(package)
            self.profiles.save_profile(profile)
            HypothesisGenerator(self.profiles).generate(profile)  # Passive only.
            result = self.ledger.transition(run_id, run.target_id, status,
                                            counts=counts, limitations=tuple(limitations),
                                            stop_reason=stop_reason)
            state = (DiscoveryState.RECON_BACKED if run.mode is BootstrapMode.RECON_BACKED else
                     DiscoveryState.BROWSER_PROFILED if browser_profiled else
                     DiscoveryState.TRAFFIC_PROFILED if counts["traffic_exchanges_recorded"] and
                     status is BootstrapStatus.COMPLETED else DiscoveryState.PARTIAL if
                     counts["pages_visited"] or counts["traffic_exchanges_recorded"] else
                     DiscoveryState.COLD_START)
            self.ledger.set_discovery_state(result, state)
            return result
        except Exception:
            current = self.ledger.get(run_id, run.target_id)
            if current and current.status is BootstrapStatus.RUNNING:
                self.ledger.transition(run_id, run.target_id, BootstrapStatus.FAILED,
                                       counts=counts, limitations=tuple(limitations | {"UNEXPECTED_FAILURE"}),
                                       stop_reason="UNEXPECTED_FAILURE")
            raise
