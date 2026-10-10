"""Pure Phase 2 DTO to Phase 4 model mappings; no repository calls."""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlsplit

from .domain import (
    Endpoint, Host, JavaScriptAsset, Lifecycle, ObservationState, SourceRef,
    Target, normalize_hostname, normalize_path, normalize_url,
)
from .recon import Provenance, ReconEndpoint, ReconHost, ReconJsAsset, ReconTarget


def source_from_recon(provenance: Provenance) -> SourceRef:
    return SourceRef(
        provider="RECON", entity=provenance.source_table,
        record_id=str(provenance.source_id),
        observed_at=provenance.observed_at, qualification=provenance.qualification,
    )


def target_from_recon(
    record: ReconTarget, *, target_id: str, created_at: datetime,
    evidence_ids: tuple[str, ...] = (),
) -> Target:
    return Target(
        id=target_id, name=record.root_domain, root_domain=record.root_domain,
        external_ref=str(record.domain_id), observation_state=ObservationState.OBSERVED,
        lifecycle=Lifecycle.UNKNOWN, source_ref=source_from_recon(record.provenance),
        observed_at=record.provenance.observed_at, created_at=created_at,
        evidence_ids=evidence_ids,
    )


def host_from_recon(
    record: ReconHost, *, target_id: str, host_id: str, created_at: datetime,
    evidence_ids: tuple[str, ...] = (),
) -> Host:
    parsed = urlsplit(normalize_url(record.url, schemes={"http", "https"}))
    if normalize_hostname(record.hostname) != normalize_hostname(parsed.hostname or ""):
        raise ValueError("Recon host URL and hostname disagree")
    return Host(
        id=host_id, target_id=target_id, hostname=record.hostname,
        scheme=parsed.scheme, port=parsed.port,
        lifecycle=Lifecycle.UNKNOWN, observation_state=ObservationState.OBSERVED,
        source_ref=source_from_recon(record.provenance),
        observed_at=record.provenance.observed_at, created_at=created_at,
        evidence_ids=evidence_ids,
    )


def endpoint_from_recon(
    record: ReconEndpoint, *, target_id: str, host: Host, endpoint_id: str,
    created_at: datetime,
    evidence_ids: tuple[str, ...] = (),
) -> Endpoint:
    if host.target_id != target_id:
        raise ValueError("Recon endpoint target and host disagree")
    if host.source_ref and host.source_ref.provider == "RECON" and (
        host.source_ref.entity != "live_hosts" or host.source_ref.record_id != str(record.host_id)
    ):
        raise ValueError("Recon endpoint and host row disagree")
    raw = record.path
    if raw.startswith(("http://", "https://")):
        parsed = urlsplit(normalize_url(raw, schemes={"http", "https"}))
        if normalize_hostname(parsed.hostname or "") != host.hostname:
            raise ValueError("Recon endpoint points to a different host")
        path = parsed.path
    else:
        parsed = urlsplit(raw)
        if parsed.netloc or parsed.fragment:
            raise ValueError("Invalid recon endpoint path")
        path = parsed.path
    return Endpoint(
        id=endpoint_id, target_id=target_id, host_id=host.id,
        path=normalize_path(path or "/"), method=record.method,
        lifecycle=Lifecycle.UNKNOWN, observation_state=ObservationState.OBSERVED,
        source_ref=source_from_recon(record.provenance),
        observed_at=record.provenance.observed_at, created_at=created_at,
        evidence_ids=evidence_ids,
    )


def js_asset_from_recon(
    record: ReconJsAsset, *, target_id: str, host: Host, asset_id: str,
    created_at: datetime,
    evidence_ids: tuple[str, ...] = (),
) -> JavaScriptAsset:
    if host.target_id != target_id:
        raise ValueError("Recon JS target and host disagree")
    if host.source_ref and host.source_ref.provider == "RECON" and (
        host.source_ref.entity != "live_hosts" or host.source_ref.record_id != str(record.host_id)
    ):
        raise ValueError("Recon JS asset and host row disagree")
    return JavaScriptAsset(
        id=asset_id, target_id=target_id, host_id=host.id,
        url=record.asset_url, sha256=record.latest_sha256,
        size_bytes=record.size_bytes, http_status=record.http_status,
        lifecycle=Lifecycle.UNKNOWN, observation_state=ObservationState.OBSERVED,
        source_ref=source_from_recon(record.provenance),
        observed_at=record.provenance.observed_at, created_at=created_at,
        evidence_ids=evidence_ids,
    )
