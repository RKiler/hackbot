"""Vendor-neutral, read-only recon contract and compact records."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Generic, Protocol, TypeVar, runtime_checkable


T = TypeVar("T")


@dataclass(frozen=True)
class Provenance:
    source_table: str
    source_id: int
    observed_at: datetime | None
    qualification: str


@dataclass(frozen=True)
class Page(Generic[T]):
    items: tuple[T, ...]
    next_cursor: str | None


@dataclass(frozen=True)
class ReconTarget:
    domain_id: int
    root_domain: str
    active_in_recon: bool
    include_subdomains_in_recon: bool
    provenance: Provenance
    recon_present: bool = True


@dataclass(frozen=True)
class ReconHost:
    host_id: int
    domain_id: int
    hostname: str
    url: str = field(repr=False)
    status_code: int | None
    provenance: Provenance


@dataclass(frozen=True)
class ReconHostMembership:
    target: ReconTarget
    requested_host: str
    subdomain_id: int
    host_id: int | None


@dataclass(frozen=True)
class ReconWildcardCounts:
    known: int
    live: int
    latest_scan: int


@dataclass(frozen=True)
class ReconHostSignals:
    endpoint_count: int = 0
    js_count: int = 0
    api_count: int = 0
    recent_events: int = 0


@dataclass(frozen=True)
class ReconEndpoint:
    endpoint_id: int
    host_id: int
    path: str = field(repr=False)
    method: str | None
    status_code: int | None
    source: str | None
    provenance: Provenance


@dataclass(frozen=True)
class ReconParameter:
    parameter_id: int
    endpoint_id: int
    name: str
    risk_tags: tuple[str, ...]
    provenance: Provenance


@dataclass(frozen=True)
class ReconJsAsset:
    asset_id: int
    host_id: int
    asset_url: str = field(repr=False)
    latest_sha256: str | None
    size_bytes: int | None
    http_status: int | None
    provenance: Provenance


@dataclass(frozen=True)
class ReconJsAnalysis:
    analysis_id: int
    asset_id: int
    extraction_bytes: int
    signal_counts: dict[str, int]
    provenance: Provenance


@dataclass(frozen=True)
class ReconEndpointJsReference:
    reference_id: int
    endpoint_id: int
    asset_id: int
    provenance: Provenance


@dataclass(frozen=True)
class ReconApiSurface:
    surface_id: int
    domain_id: int
    host_id: int | None
    surface_type: str
    location: str = field(repr=False)
    status_code: int | None
    operations_count: int | None
    provenance: Provenance


@dataclass(frozen=True)
class ReconScanSnapshot:
    snapshot_id: int
    domain_id: int
    started_at: datetime
    finished_at: datetime
    first_run: bool
    provenance: Provenance


@dataclass(frozen=True)
class ReconAssetEvent:
    event_id: int
    domain_id: int
    event_type: str
    entity_type: str
    entity_id: int | None
    location: str | None = field(repr=False)
    severity: str | None
    provenance: Provenance
    first_seen: datetime | None = None
    content_sha256: str | None = None


@runtime_checkable
class ReconRepository(Protocol):
    """Read-only recon observations; no result authorizes active testing."""

    def resolve_target(self, identity: str | int) -> ReconTarget | None: ...
    def resolve_host_membership(self, hostname: str) -> ReconHostMembership | None: ...
    def resolve_host(self, domain_id: int, exact_url: str) -> ReconHost | None: ...
    def list_wildcard_hosts(self, domain_id: int, suffix: str, *, limit: int = 20, cursor: str | None = None) -> Page[ReconHost]: ...
    def wildcard_counts(self, domain_id: int, suffix: str) -> ReconWildcardCounts: ...
    def host_signals(self, domain_id: int, host_ids: tuple[int, ...]) -> dict[int, ReconHostSignals]: ...
    def list_hosts(self, domain_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconHost]: ...
    def list_endpoints(self, domain_id: int, host_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconEndpoint]: ...
    def list_parameters(self, domain_id: int, endpoint_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconParameter]: ...
    def list_js_assets(self, domain_id: int, host_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconJsAsset]: ...
    def get_js_asset(self, domain_id: int, asset_id: int) -> ReconJsAsset | None: ...
    def get_js_analysis(self, domain_id: int, asset_id: int) -> ReconJsAnalysis | None: ...
    def list_endpoint_js_references(self, domain_id: int, endpoint_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconEndpointJsReference]: ...
    def list_api_surfaces(self, domain_id: int, surface_type: str, *, host_id: int | None = None, limit: int = 20, cursor: str | None = None) -> Page[ReconApiSurface]: ...
    def list_scan_snapshots(self, domain_id: int, *, limit: int = 20, cursor: str | None = None) -> Page[ReconScanSnapshot]: ...
    def get_asset_event(self, domain_id: int, event_id: int) -> ReconAssetEvent | None: ...
    def list_asset_events(self, domain_id: int, window_start: datetime, window_end: datetime, *, limit: int = 20, cursor: str | None = None) -> Page[ReconAssetEvent]: ...
