"""Bounded, passive attack-surface profiling for one authoritative Target Package."""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime
from enum import StrEnum
import hashlib
import re
from urllib.parse import urlsplit

from .evidence import FactStatus, Sensitivity
from .identity import IdentityStatus
from .recon import ReconRepository, ReconHost
from .target_package import TargetPackage
from .target_scope import ScopeResult
from .traffic import TrafficStore
from .identity_registry import IdentityRegistry
from .store import EvidenceFactStore
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .bootstrap_store import BootstrapStore


class SignalSource(StrEnum):
    RECON = "RECON"
    JS_ANALYSIS = "JS_ANALYSIS"
    TRAFFIC = "TRAFFIC"
    MANUAL = "MANUAL"
    TARGET_PACKAGE = "TARGET_PACKAGE"
    IDENTITY_REGISTRY = "IDENTITY_REGISTRY"
    FACT = "FACT"
    EVIDENCE = "EVIDENCE"
    COLD_START_BROWSER = "COLD_START_BROWSER"
    COLD_START_TRAFFIC = "COLD_START_TRAFFIC"
    COLD_START_JS = "COLD_START_JS"


@dataclass(frozen=True, slots=True)
class ProfileLimits:
    hosts: int = 12
    endpoints_per_host: int = 12
    js_per_host: int = 5
    analyses: int = 12
    parameter_pages: int = 20
    endpoint_references: int = 8
    traffic: int = 20
    facts: int = 16
    evidence: int = 12
    events: int = 24
    surfaces_per_type: int = 6
    signals: int = 120

    def __post_init__(self) -> None:
        caps = {"hosts": 25, "endpoints_per_host": 25, "js_per_host": 10,
                "analyses": 25, "parameter_pages": 50, "endpoint_references": 20,
                "traffic": 50, "facts": 50, "evidence": 50, "events": 50,
                "surfaces_per_type": 20, "signals": 200}
        if any(type(getattr(self, item.name)) is not int or not 1 <= getattr(self, item.name) <= caps[item.name]
               for item in fields(self)):
            raise ValueError("profile limits must be positive and bounded")


@dataclass(frozen=True, slots=True)
class SurfaceSignal:
    code: str
    source: SignalSource
    surface_key: str
    display: str
    source_table: str
    source_id: str
    observed_at: datetime | None = None
    confidence: float = 0.5
    feature: str | None = None
    object_type: str | None = None
    method: str | None = None
    status_code: int | None = None
    recent: bool = False
    evidence_ids: tuple[str, ...] = ()
    fact_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code, "source": self.source.value,
            "surface_key": self.surface_key, "display": self.display,
            "source_table": self.source_table, "source_id": self.source_id,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "confidence": self.confidence, "feature": self.feature,
            "object_type": self.object_type, "method": self.method,
            "status_code": self.status_code, "recent": self.recent,
            "evidence_ids": list(self.evidence_ids), "fact_ids": list(self.fact_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SurfaceSignal:
        observed = data.get("observed_at")
        return cls(
            code=str(data["code"]), source=SignalSource(data["source"]),
            surface_key=str(data["surface_key"]), display=str(data["display"]),
            source_table=str(data["source_table"]), source_id=str(data["source_id"]),
            observed_at=datetime.fromisoformat(str(observed)) if observed else None,
            confidence=float(data["confidence"]), feature=data.get("feature"),
            object_type=data.get("object_type"), method=data.get("method"),
            status_code=data.get("status_code"), recent=bool(data.get("recent")),
            evidence_ids=tuple(data.get("evidence_ids") or ()),
            fact_ids=tuple(data.get("fact_ids") or ()),
        )


@dataclass(frozen=True, slots=True)
class TargetProfile:
    target_id: str
    package_id: str
    root_domain: str
    package_status: str
    generated_at: datetime
    recon_domain_id: int | None
    recon_status: str
    technologies: tuple[str, ...]
    api_styles: tuple[str, ...]
    features: tuple[str, ...]
    boundaries: tuple[str, ...]
    object_types: tuple[str, ...]
    identity_capabilities: tuple[str, ...]
    recent_changes: int
    javascript_heavy: bool
    message_passing: bool
    source_map_count: int
    signals: tuple[SurfaceSignal, ...]
    coverage: dict[str, int | bool | str]
    gaps: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "target_id": self.target_id, "package_id": self.package_id,
            "root_domain": self.root_domain, "package_status": self.package_status,
            "generated_at": self.generated_at.isoformat(),
            "recon_domain_id": self.recon_domain_id, "recon_status": self.recon_status,
            "technologies": list(self.technologies), "api_styles": list(self.api_styles),
            "features": list(self.features), "boundaries": list(self.boundaries),
            "object_types": list(self.object_types),
            "identity_capabilities": list(self.identity_capabilities),
            "recent_changes": self.recent_changes,
            "javascript_heavy": self.javascript_heavy,
            "message_passing": self.message_passing,
            "source_map_count": self.source_map_count,
            "signals": [item.to_dict() for item in self.signals],
            "coverage": self.coverage, "gaps": list(self.gaps),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> TargetProfile:
        return cls(
            target_id=str(data["target_id"]), package_id=str(data["package_id"]),
            root_domain=str(data["root_domain"]), package_status=str(data["package_status"]),
            generated_at=datetime.fromisoformat(str(data["generated_at"])),
            recon_domain_id=data.get("recon_domain_id"),
            recon_status=str(data["recon_status"]),
            technologies=tuple(data["technologies"]), api_styles=tuple(data["api_styles"]),
            features=tuple(data["features"]), boundaries=tuple(data["boundaries"]),
            object_types=tuple(data["object_types"]),
            identity_capabilities=tuple(data["identity_capabilities"]),
            recent_changes=int(data["recent_changes"]),
            javascript_heavy=bool(data.get("javascript_heavy", False)),
            message_passing=bool(data.get("message_passing", False)),
            source_map_count=int(data.get("source_map_count", 0)),
            signals=tuple(SurfaceSignal.from_dict(item) for item in data["signals"]),
            coverage=dict(data["coverage"]), gaps=tuple(data["gaps"]),
        )


_FEATURES = {
    "organization": "organizations", "organizations": "organizations", "org": "organizations",
    "workspace": "workspaces", "workspaces": "workspaces",
    "project": "projects", "projects": "projects",
    "team": "teams", "teams": "teams",
    "role": "custom roles", "roles": "custom roles", "permission": "custom roles",
    "integration": "integrations", "integrations": "integrations",
    "webhook": "webhooks", "webhooks": "webhooks",
    "upload": "uploads", "uploads": "uploads", "import": "uploads",
    "export": "exports", "exports": "exports", "download": "exports",
    "share": "sharing", "sharing": "sharing",
    "billing": "billing", "invoice": "billing", "payment": "billing",
    "invite": "invitations", "invitation": "invitations",
    "admin": "admin functions", "console": "admin functions",
    "dashboard": "dashboards", "dashboards": "dashboards",
    "document": "documents", "documents": "documents", "file": "documents",
    "comment": "comments", "comments": "comments",
    "apikey": "API keys", "api_key": "API keys",
}
_OBJECTS = frozenset({"organization", "workspace", "project", "team", "user",
                      "account", "dashboard", "document", "file", "report", "invoice",
                      "integration", "webhook", "member", "comment", "role"})
_KNOWN_PATH = frozenset({"api", "v1", "v2", "v3", "graphql", "gql", "rpc", "trpc",
                         "admin", "internal", "debug", "console", "upload", "import",
                         "export", "download", "reports", "report", "files", "documents",
                         "users", "accounts", "teams", "projects", "workspaces",
                         "organizations", "members", "roles", "permissions", "integrations",
                         "webhooks", "oauth", "authorize", "callback", "token", "login",
                         "auth", "sharing", "billing", "invitations", "invites"})
_INTERNAL = frozenset({"internal", "admin", "debug", "console", "staging", "dev", "test"})


def _tokens(value: str) -> tuple[str, ...]:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value[:256])
    return tuple(part.lower() for part in re.split(r"[^A-Za-z0-9]+", separated) if part)


def _shape(path: str) -> str:
    parts = []
    for segment in path.split("/")[:12]:
        parts.append(segment.lower() if segment.lower() in _KNOWN_PATH else "{part}" if segment else "")
    return "/".join(parts)[:180]


def _key(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()[:24]


class AttackSurfaceProfiler:
    """Finite reads only. A missing recon adapter produces an explicit coverage gap."""

    def __init__(self, registry: IdentityRegistry, evidence: EvidenceFactStore,
                 traffic: TrafficStore, recon: ReconRepository | None = None,
                 limits: ProfileLimits = ProfileLimits(),
                 bootstrap: BootstrapStore | None = None) -> None:
        self.registry = registry
        self.evidence = evidence
        self.traffic = traffic
        self.recon = recon
        self.limits = limits
        self.bootstrap = bootstrap

    def profile(self, package: TargetPackage) -> TargetProfile:
        if not isinstance(package, TargetPackage):
            raise ValueError("An authoritative Target Package is required")
        target_id = package.target.id
        signals: list[SurfaceSignal] = []
        seen: set[tuple[str, str, str, str]] = set()
        coverage: dict[str, int | bool | str] = {
            "hosts_examined": 0, "hosts_out_of_scope": 0, "endpoints_examined": 0,
            "js_assets_examined": 0, "js_analyses_examined": 0,
            "parameter_pages": 0, "traffic_examined": 0, "facts_examined": 0,
            "endpoint_reference_pages": 0,
            "evidence_examined": 0, "events_examined": 0,
            "signals_truncated": False, "sampled_recon": False,
            "bootstrap_examined": 0,
        }
        gaps: set[str] = set()

        def add(item: SurfaceSignal) -> None:
            identity = (item.code, item.surface_key, item.source_table, item.source_id)
            if identity in seen:
                return
            if len(signals) >= self.limits.signals:
                coverage["signals_truncated"] = True
                return
            seen.add(identity)
            signals.append(item)

        if self.bootstrap is not None:
            bootstrap_seen: set[tuple[str, str, str]] = set()
            for item in self.bootstrap.list_observations(target_id, limit=100):
                coverage["bootstrap_examined"] += 1
                identity = (item.source, item.code, item.surface_key)
                if identity in bootstrap_seen:
                    continue
                bootstrap_seen.add(identity)
                if len(bootstrap_seen) > self.limits.signals // 2:
                    gaps.add("BOOTSTRAP_SIGNALS_SAMPLED")
                    break
                feature = item.display if item.code.startswith("FEATURE_") else None
                add(SurfaceSignal(item.code, SignalSource(item.source), item.surface_key,
                                  item.display, "bootstrap_observations", item.observation_id,
                                  item.observed_at, 0.65, feature=feature,
                                  evidence_ids=(item.evidence_id,)))
        self._local(package, add, coverage, gaps)
        recon_id = self._recon(package, add, coverage, gaps)
        technologies = {item.display for item in signals if item.code == "TECHNOLOGY"}
        technologies.update(item.code.removeprefix("TECHNOLOGY_") for item in signals
                            if item.code.startswith("TECHNOLOGY_"))
        api_styles = {item.code.removeprefix("API_") for item in signals if item.code.startswith("API_")}
        features = {item.feature for item in signals if item.feature}
        objects = {item.object_type for item in signals if item.object_type}
        boundaries = {item.code.removeprefix("BOUNDARY_") for item in signals
                      if item.code.startswith("BOUNDARY_")}
        capabilities = {item.code.removeprefix("IDENTITY_") for item in signals
                        if item.code.startswith("IDENTITY_")}
        if "CROSS_TENANT_PAIR" in capabilities:
            boundaries.add("TENANT")
        if "DIFFERENT_ROLE_PAIR" in capabilities:
            boundaries.add("ROLE")
        if "MULTIPLE" in capabilities or any(item.code == "BOUNDARY_AUTHENTICATED" for item in signals):
            boundaries.add("USER")
        if "organizations" in features:
            boundaries.add("ORGANIZATION_CANDIDATE")
        if "workspaces" in features:
            boundaries.add("WORKSPACE_CANDIDATE")
        if "custom roles" in features:
            boundaries.add("FEATURE_PERMISSION_CANDIDATE")
        if any(item.code in {"JS_POSTMESSAGE", "JS_MESSAGECHANNEL", "PARAM_REDIRECT"} for item in signals):
            boundaries.add("CROSS_ORIGIN_CANDIDATE")
        if any(item.code in {"JS_DOM_SINK", "PARAM_URL"} for item in signals):
            boundaries.add("CLIENT_SERVER_TRUST_CANDIDATE")
        if any(item.code in {"HOST_INTERNAL", "SURFACE_INTERNAL"} for item in signals):
            boundaries.add("INTERNAL_EXTERNAL_CANDIDATE")
        if any(item.code == "OBJECT_ID" for item in signals):
            boundaries.add("OBJECT_OWNERSHIP_CANDIDATE")
            gaps.add("OBJECT_OWNERSHIP_UNKNOWN")
        return TargetProfile(
            target_id=target_id, package_id=package.id, root_domain=package.primary_domain,
            package_status=package.status.value, generated_at=datetime.now().astimezone(),
            recon_domain_id=recon_id, recon_status="AVAILABLE" if recon_id else (
                "NOT_CONFIGURED" if self.recon is None else "NOT_FOUND"),
            technologies=tuple(sorted(technologies)), api_styles=tuple(sorted(api_styles)),
            features=tuple(sorted(features)), boundaries=tuple(sorted(boundaries)),
            object_types=tuple(sorted(objects)), identity_capabilities=tuple(sorted(capabilities)),
            recent_changes=len({item.surface_key for item in signals if item.recent}),
            javascript_heavy=sum(item.code == "JS_ASSET" for item in signals) >= 3,
            message_passing=any(item.code in {"JS_POSTMESSAGE", "JS_MESSAGECHANNEL"} for item in signals),
            source_map_count=sum(item.code == "SOURCE_MAP" for item in signals),
            signals=tuple(signals), coverage=coverage, gaps=tuple(sorted(gaps)),
        )

    def _local(self, package, add, coverage, gaps) -> None:
        target_id = package.target.id
        for value in package.context.known_features[:20]:
            for token in _tokens(value):
                feature = _FEATURES.get(token)
                if feature:
                    add(SurfaceSignal("FEATURE_CONTEXT", SignalSource.TARGET_PACKAGE,
                        _key(target_id, feature), feature, "target_package", package.id,
                        package.updated_at, 0.65, feature=feature))
        identities = self.registry.list_identities(target_id, limit=20)
        active = [item for item in identities.items if item.status is IdentityStatus.ACTIVE]
        if identities.next_cursor:
            gaps.add("IDENTITIES_SAMPLED")
        if active:
            add(SurfaceSignal("BOUNDARY_AUTHENTICATED", SignalSource.IDENTITY_REGISTRY,
                _key(target_id, "identities"), "configured owned identities",
                "registry_identities", target_id, confidence=0.7))
        if len(active) >= 2:
            add(SurfaceSignal("IDENTITY_MULTIPLE", SignalSource.IDENTITY_REGISTRY,
                _key(target_id, "identity-pair"), "multiple configured owned identities",
                "registry_identities", target_id, confidence=0.7))
        if self.registry.list_cross_tenant_identity_pairs(target_id, limit=1):
            add(SurfaceSignal("IDENTITY_CROSS_TENANT_PAIR", SignalSource.IDENTITY_REGISTRY,
                _key(target_id, "tenant-pair"), "configured disjoint-tenant identity pair",
                "registry_memberships", target_id, confidence=0.75))
        if self.registry.list_same_tenant_different_role_pairs(target_id, limit=1):
            add(SurfaceSignal("IDENTITY_DIFFERENT_ROLE_PAIR", SignalSource.IDENTITY_REGISTRY,
                _key(target_id, "role-pair"), "configured same-tenant role comparison",
                "registry_memberships", target_id, confidence=0.75))
        facts = self.evidence.list_facts_for_target(target_id, limit=self.limits.facts)
        coverage["facts_examined"] = len(facts.items)
        if facts.next_cursor:
            gaps.add("FACTS_SAMPLED")
        for fact in facts.items:
            if (fact.status is not FactStatus.ACTIVE or not fact.evidence_ids
                    or fact.sensitivity in {Sensitivity.SENSITIVE, Sensitivity.SECRET}):
                continue
            if fact.predicate == "uses_technology" and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.+-]{0,39}", fact.object):
                add(SurfaceSignal("TECHNOLOGY", SignalSource.FACT,
                    _key(target_id, fact.object.lower()), fact.object, "facts", fact.fact_id,
                    fact.observed_at, fact.confidence, evidence_ids=fact.evidence_ids,
                    fact_ids=(fact.fact_id,)))
            elif fact.predicate == "js_decoder" and fact.subject.startswith("js_asset:"):
                add(SurfaceSignal("JS_DECODER", SignalSource.FACT,
                    _key(target_id, fact.subject.removeprefix("js_asset:")), "decoder observed in selected JS asset",
                    "facts", fact.fact_id, fact.observed_at, fact.confidence,
                    evidence_ids=fact.evidence_ids, fact_ids=(fact.fact_id,)))
            elif fact.predicate == "js_messagechannel" and fact.subject.startswith("js_asset:"):
                add(SurfaceSignal("JS_MESSAGECHANNEL", SignalSource.FACT,
                    _key(target_id, fact.subject.removeprefix("js_asset:")), "MessageChannel observed in selected JS asset",
                    "facts", fact.fact_id, fact.observed_at, fact.confidence,
                    evidence_ids=fact.evidence_ids, fact_ids=(fact.fact_id,)))
        evidence_page = self.evidence.list_evidence_for_target(target_id, limit=self.limits.evidence)
        coverage["evidence_examined"] = len(evidence_page.items)
        if evidence_page.next_cursor:
            gaps.add("EVIDENCE_SAMPLED")
        for item in evidence_page.items:
            code = {"SOURCE_MAP": "SOURCE_MAP", "GRAPHQL_OPERATION": "API_GRAPHQL",
                    "AUTH_OBSERVATION": "BOUNDARY_AUTHENTICATED"}.get(item.evidence_type)
            if code:
                add(SurfaceSignal(code, SignalSource.EVIDENCE,
                    _key(target_id, item.evidence_id), code.lower().replace("_", " "),
                    "evidence", item.evidence_id, item.observed_at, 0.8,
                    evidence_ids=(item.evidence_id,)))
        traffic_page = self.traffic.list_filtered(target_id, limit=self.limits.traffic)
        coverage["traffic_examined"] = len(traffic_page.items)
        if traffic_page.next_cursor:
            gaps.add("TRAFFIC_SAMPLED")
        for exchange in traffic_page.items:
            if exchange.scope_result is not ScopeResult.IN_SCOPE:
                continue
            surface = _key(exchange.request.origin, exchange.request.display_path)
            common = dict(source=SignalSource.TRAFFIC, surface_key=surface,
                          display=exchange.request.origin + exchange.request.display_path,
                          source_table="traffic_exchanges", source_id=exchange.id,
                          observed_at=exchange.observed_at, confidence=0.85,
                          method=exchange.request.record.method,
                          status_code=exchange.response.record.status_code if exchange.response else None,
                          evidence_ids=exchange.evidence_ids[:2])
            add(SurfaceSignal("REQUEST_TEMPLATE", **common))
            if exchange.attribution.auth_state.value == "ANONYMOUS":
                add(SurfaceSignal("BOUNDARY_ANONYMOUS", **common))
            elif exchange.attribution.auth_state.value == "VERIFIED":
                add(SurfaceSignal("BOUNDARY_AUTHENTICATED", **common))
            if exchange.request.record.operation_id:
                add(SurfaceSignal("API_GRAPHQL", **common))

    def _recon(self, package, add, coverage, gaps) -> int | None:
        if self.recon is None:
            gaps.add("RECON_NOT_CONFIGURED")
            return None
        target = self.recon.resolve_target(package.primary_domain)
        if target is None:
            gaps.add("RECON_ROOT_NOT_FOUND")
            return None
        domain_id = target.domain_id
        deltas = []
        cursor = None
        for _ in range(3):
            snapshots = self.recon.list_scan_snapshots(domain_id, limit=8, cursor=cursor)
            deltas.extend(item for item in snapshots.items if not item.first_run)
            cursor = snapshots.next_cursor
            if len(deltas) >= 2 or not cursor:
                break
        deltas = deltas[:2]
        if cursor and len(deltas) < 2:
            gaps.add("DELTA_WINDOW_SAMPLED")
        events = []
        for snapshot in deltas:
            start = snapshot.started_at.replace(tzinfo=None)
            end = snapshot.finished_at.replace(tzinfo=None)
            if not start < end or (end - start).days > 31:
                gaps.add("DELTA_WINDOW_UNAVAILABLE")
                continue
            page = self.recon.list_asset_events(domain_id, start, end,
                                                limit=max(1, self.limits.events // max(len(deltas), 1)))
            events.extend(page.items)
            if page.next_cursor:
                gaps.add("DELTA_EVENTS_SAMPLED")
        events = events[:self.limits.events]
        coverage["events_examined"] = len(events)
        recent_entities = {(event.entity_type.lower(), event.entity_id) for event in events
                           if event.entity_id is not None}
        hosts: list[ReconHost] = []
        known_hosts = set()
        for event in events:
            if not event.location or not event.location.startswith(("https://", "http://")):
                continue
            parsed = urlsplit(event.location)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if package.scope.evaluate_url(origin).result is not ScopeResult.IN_SCOPE:
                continue
            host = self.recon.resolve_host(domain_id, origin)
            if host and host.host_id not in known_hosts and len(hosts) < self.limits.hosts:
                hosts.append(host); known_hosts.add(host.host_id)
        page = self.recon.list_hosts(domain_id, limit=self.limits.hosts)
        if page.next_cursor:
            coverage["sampled_recon"] = True
            gaps.add("HOSTS_SAMPLED")
        for host in page.items:
            if host.host_id not in known_hosts and len(hosts) < self.limits.hosts:
                hosts.append(host); known_hosts.add(host.host_id)
        analyses = 0
        parameter_pages = 0
        reference_pages = 0
        scoped_hosts = {}
        for host in hosts:
            coverage["hosts_examined"] += 1
            if package.scope.evaluate_url(host.url).result is not ScopeResult.IN_SCOPE:
                coverage["hosts_out_of_scope"] += 1
                continue
            scoped_hosts[host.host_id] = host
            host_tokens = set(_tokens(host.hostname))
            if host_tokens & _INTERNAL:
                add(SurfaceSignal("HOST_INTERNAL", SignalSource.RECON,
                    _key(host.url), host.hostname, "live_hosts", str(host.host_id),
                    host.provenance.observed_at, 0.6,
                    recent=("live_host", host.host_id) in recent_entities))
            endpoint_page = self.recon.list_endpoints(domain_id, host.host_id,
                                                       limit=self.limits.endpoints_per_host)
            if endpoint_page.next_cursor:
                coverage["sampled_recon"] = True
                gaps.add("ENDPOINTS_SAMPLED")
            for endpoint in endpoint_page.items:
                coverage["endpoints_examined"] += 1
                path = urlsplit(endpoint.path).path
                if not path.startswith("/") or path.startswith("//"):
                    continue
                if package.scope.evaluate_url(host.url.rstrip("/") + path).result is not ScopeResult.IN_SCOPE:
                    coverage["hosts_out_of_scope"] += 1
                    continue
                surface = _key(host.url, _shape(path))
                display = host.hostname + _shape(path)
                recent = ("endpoint", endpoint.endpoint_id) in recent_entities
                tokens = set(_tokens(path))
                feature = next((_FEATURES[token] for token in _tokens(path) if token in _FEATURES), None)
                object_type = next((token.rstrip("s") for token in _tokens(path)
                                    if token.rstrip("s") in _OBJECTS), None)
                common = dict(source=SignalSource.RECON, surface_key=surface, display=display,
                              source_table="endpoints", source_id=str(endpoint.endpoint_id),
                              observed_at=endpoint.provenance.observed_at, confidence=0.65,
                              feature=feature, object_type=object_type,
                              method=endpoint.method, status_code=endpoint.status_code, recent=recent)
                add(SurfaceSignal("ENDPOINT", **common))
                if re.search(r"/\{(?:id|[A-Za-z]+[Ii]d)\}(?:/|$)|/[0-9]{2,}(?:/|$)", path):
                    add(SurfaceSignal("OBJECT_ID", **common))
                if "graphql" in tokens or "gql" in tokens:
                    add(SurfaceSignal("API_GRAPHQL", **common))
                elif "api" in tokens:
                    add(SurfaceSignal("API_REST", **common))
                if tokens & {"admin", "internal", "debug", "console", "actuator"}:
                    add(SurfaceSignal("SURFACE_INTERNAL", **common))
                if tokens & {"export", "download", "report", "reports"}:
                    add(SurfaceSignal("FEATURE_DOWNLOAD", **common))
                if tokens & {"user", "users", "customer", "customers", "person", "people", "profile", "profiles"}:
                    add(SurfaceSignal("FEATURE_PII_OBJECT", **common))
                if tokens & {"upload", "import"}:
                    add(SurfaceSignal("FEATURE_UPLOAD", **common))
                if tokens & {"webhook", "webhooks"}:
                    add(SurfaceSignal("FEATURE_WEBHOOK", **common))
                if tokens & {"oauth", "authorize", "callback"}:
                    add(SurfaceSignal("API_OAUTH", **common))
                if endpoint.status_code in (401, 403):
                    add(SurfaceSignal("BOUNDARY_AUTHENTICATED", **common))
                if reference_pages < self.limits.endpoint_references and (
                    "graphql" in tokens or tokens & {"admin", "export", "download", "upload", "webhook"}
                    or object_type is not None
                ):
                    references = self.recon.list_endpoint_js_references(domain_id, endpoint.endpoint_id, limit=3)
                    reference_pages += 1
                    if references.next_cursor:
                        gaps.add("ENDPOINT_JS_REFERENCES_SAMPLED")
                    for reference in references.items:
                        add(SurfaceSignal("JS_REFERENCE", SignalSource.RECON, surface,
                            display, "endpoint_js_references", str(reference.reference_id),
                            reference.provenance.observed_at, 0.7, feature=feature,
                            object_type=object_type, method=endpoint.method, recent=recent))
                if parameter_pages < self.limits.parameter_pages:
                    parameters = self.recon.list_parameters(domain_id, endpoint.endpoint_id, limit=6)
                    parameter_pages += 1
                    if parameters.next_cursor:
                        gaps.add("PARAMETERS_SAMPLED")
                    for parameter in parameters.items:
                        p_tokens = _tokens(parameter.name)
                        stem = next((token for token in p_tokens if token in _OBJECTS), object_type)
                        if "id" in p_tokens or parameter.name.lower().endswith("id"):
                            add(SurfaceSignal("OBJECT_ID", **{**common, "source_table": "url_parameters",
                                "source_id": str(parameter.parameter_id), "object_type": stem}))
                        if set(p_tokens) & {"url", "uri", "webhook", "callback"}:
                            add(SurfaceSignal("PARAM_URL", **{**common, "source_table": "url_parameters",
                                "source_id": str(parameter.parameter_id)}))
                        if set(p_tokens) & {"redirect", "return", "next"}:
                            add(SurfaceSignal("PARAM_REDIRECT", **{**common, "source_table": "url_parameters",
                                "source_id": str(parameter.parameter_id)}))
            js_page = self.recon.list_js_assets(domain_id, host.host_id,
                                                 limit=self.limits.js_per_host)
            if js_page.next_cursor:
                coverage["sampled_recon"] = True
                gaps.add("JS_ASSETS_SAMPLED")
            for asset in js_page.items:
                coverage["js_assets_examined"] += 1
                if package.scope.evaluate_url(asset.asset_url).result is not ScopeResult.IN_SCOPE:
                    continue
                js_key = _key(package.target.id, str(asset.asset_id))
                js_display = host.hostname + " / JavaScript asset"
                recent = ("js_asset", asset.asset_id) in recent_entities
                base = dict(source=SignalSource.RECON, surface_key=js_key, display=js_display,
                            source_table="js_assets", source_id=str(asset.asset_id),
                            observed_at=asset.provenance.observed_at, confidence=0.55, recent=recent)
                if urlsplit(asset.asset_url).path.endswith(".map"):
                    if asset.http_status == 200:
                        add(SurfaceSignal("SOURCE_MAP", **base))
                    continue
                add(SurfaceSignal("JS_ASSET", **base))
                if analyses >= self.limits.analyses or asset.http_status != 200:
                    continue
                analysis = self.recon.get_js_analysis(domain_id, asset.asset_id)
                analyses += 1
                if analysis is None:
                    continue
                coverage["js_analyses_examined"] += 1
                base = {**base, "source": SignalSource.JS_ANALYSIS,
                        "source_table": "js_analysis_results", "source_id": str(analysis.analysis_id),
                        "confidence": 0.65}
                for count_name, code in (("graphql_operations", "API_GRAPHQL"),
                                         ("endpoint_paths", "JS_ENDPOINTS"),
                                         ("postmessage_usage", "JS_POSTMESSAGE"),
                                         ("dangerous_dom_sinks", "JS_DOM_SINK"),
                                         ("tokens_or_secret_like_strings", "JS_TOKEN_LIKE")):
                    if analysis.signal_counts.get(count_name, 0) > 0:
                        add(SurfaceSignal(code, **base))
        coverage["parameter_pages"] = parameter_pages
        coverage["endpoint_reference_pages"] = reference_pages
        if analyses >= self.limits.analyses:
            gaps.add("JS_ANALYSES_SAMPLED")
        for kind, code in (("graphql", "API_GRAPHQL"), ("openapi", "API_REST"),
                           ("websocket", "API_WEBSOCKET"), ("rpc", "API_RPC")):
            surfaces = self.recon.list_api_surfaces(domain_id, kind,
                                                    limit=self.limits.surfaces_per_type)
            if surfaces.next_cursor:
                gaps.add("API_SURFACES_SAMPLED")
            for item in surfaces.items:
                location = item.location
                if location.startswith("/") and item.host_id in scoped_hosts:
                    location = scoped_hosts[item.host_id].url.rstrip("/") + location
                if package.scope.evaluate_url(location).result is not ScopeResult.IN_SCOPE:
                    continue
                parsed = urlsplit(location)
                add(SurfaceSignal(code, SignalSource.RECON,
                    _key(parsed.scheme, parsed.netloc, _shape(parsed.path)),
                    parsed.hostname + _shape(parsed.path), "api_surfaces", str(item.surface_id),
                    item.provenance.observed_at, 0.7,
                    status_code=item.status_code,
                    recent=("api_surface", item.surface_id) in recent_entities))
        return domain_id
