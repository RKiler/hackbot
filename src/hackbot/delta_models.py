"""Typed, bounded state for continuous recon-delta hunting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
import re
import hashlib

from .planner_models import Specialist


class DeltaType(StrEnum):
    NEW_HOST = "NEW_HOST"
    NEW_ENDPOINT = "NEW_ENDPOINT"
    NEW_PARAMETER = "NEW_PARAMETER"
    NEW_JS_ASSET = "NEW_JS_ASSET"
    CHANGED_JS_HASH = "CHANGED_JS_HASH"
    NEW_API_SURFACE = "NEW_API_SURFACE"
    NEW_GRAPHQL_OPERATION = "NEW_GRAPHQL_OPERATION"
    NEW_SOURCE_MAP = "NEW_SOURCE_MAP"
    NEW_INTERNAL_SURFACE_SIGNAL = "NEW_INTERNAL_SURFACE_SIGNAL"
    NEW_DOWNLOAD_EXPORT_SURFACE = "NEW_DOWNLOAD_EXPORT_SURFACE"
    NEW_MESSAGE_HANDLER = "NEW_MESSAGE_HANDLER"
    NEW_DOM_SINK_OR_TRANSFORM = "NEW_DOM_SINK_OR_TRANSFORM"
    NEW_ADMIN_OR_PRIVILEGED_OPERATION = "NEW_ADMIN_OR_PRIVILEGED_OPERATION"
    NEW_TECHNOLOGY_SIGNAL = "NEW_TECHNOLOGY_SIGNAL"


class DeltaStatus(StrEnum):
    NEW = "NEW"
    CLASSIFIED = "CLASSIFIED"
    IGNORED = "IGNORED"
    DEFERRED = "DEFERRED"
    CAMPAIGN_READY = "CAMPAIGN_READY"
    CAMPAIGN_STARTED = "CAMPAIGN_STARTED"
    RESOLVED = "RESOLVED"
    SUPERSEDED = "SUPERSEDED"
    BLOCKED = "BLOCKED"


class WatchStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    IDLE = "IDLE"
    DEGRADED = "DEGRADED"
    PAUSED = "PAUSED"
    DISABLED = "DISABLED"
    FAILED = "FAILED"


class DeltaSource(StrEnum):
    RECON = "RECON"
    COLD_START = "COLD_START"


class DeltaCadence(StrEnum):
    HOURLY = "HOURLY"
    SIX_HOURLY = "SIX_HOURLY"
    DAILY = "DAILY"

    @property
    def seconds(self) -> int:
        return {self.HOURLY: 3600, self.SIX_HOURLY: 21600,
                self.DAILY: 86400}[self]


@dataclass(frozen=True, slots=True)
class ContinuousSettings:
    enabled: bool = False
    cadence: DeltaCadence = DeltaCadence.SIX_HOURLY
    minimum_relevance: int = 70
    cooldown_seconds: int = 86400
    daily_campaign_cap: int = 2
    request_cap: int = 12
    allowed_specialists: tuple[Specialist, ...] = tuple(Specialist)

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool or not isinstance(self.cadence, DeltaCadence):
            raise ValueError("Invalid continuous mode or cadence")
        for name, low, high in (
            ("minimum_relevance", 0, 100),
            ("cooldown_seconds", 3600, 604800),
            ("daily_campaign_cap", 0, 24),
            ("request_cap", 0, 40),
        ):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError("Invalid continuous " + name)
        if (not isinstance(self.allowed_specialists, tuple) or
                not self.allowed_specialists or
                len(set(self.allowed_specialists)) != len(self.allowed_specialists) or
                any(not isinstance(item, Specialist) for item in self.allowed_specialists)):
            raise ValueError("Invalid continuous specialists")

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "cadence": self.cadence.value,
                "allowed_specialists": [item.value for item in self.allowed_specialists]}


@dataclass(frozen=True, slots=True)
class DeltaSignal:
    delta_type: DeltaType
    source: DeltaSource
    source_ref: str
    entity_type: str
    entity_id: str | None
    location_hash: str
    display_location: str
    old_fingerprint: str | None
    new_fingerprint: str
    observed_at: str
    relevance: int
    specialist_hints: tuple[Specialist, ...]
    signal_tags: tuple[str, ...]
    semantic_hash: str | None = None
    artifact_id: str | None = None
    reason_code: str = "CLASSIFIED"

    def __post_init__(self) -> None:
        if (not isinstance(self.delta_type, DeltaType) or
                not isinstance(self.source, DeltaSource) or
                not 0 <= self.relevance <= 100 or
                any(not isinstance(item, Specialist) for item in self.specialist_hints)):
            raise ValueError("Invalid delta signal")


_DELTA_ID = re.compile(r"DELTA-[0-9a-f]{32}\Z")
_HYPOTHESIS_ID = re.compile(r"HYP-[0-9a-f]{32}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class DeltaFocus:
    """Exact, bounded seed for the ordinary Phase 31 campaign path."""

    delta_ids: tuple[str, ...]
    hypothesis_ids: tuple[str, ...]
    specialists: tuple[Specialist, ...]
    location_hash: str
    scope_url: str = field(repr=False)
    recon_asset_id: int | None = None
    automatic: bool = False

    def __post_init__(self) -> None:
        if (not 1 <= len(self.delta_ids) <= 4 or
                len(set(self.delta_ids)) != len(self.delta_ids) or
                any(not _DELTA_ID.fullmatch(item) for item in self.delta_ids) or
                not 1 <= len(self.hypothesis_ids) <= 8 or
                len(set(self.hypothesis_ids)) != len(self.hypothesis_ids) or
                any(not _HYPOTHESIS_ID.fullmatch(item) for item in self.hypothesis_ids) or
                not 1 <= len(self.specialists) <= 5 or
                len(set(self.specialists)) != len(self.specialists) or
                any(not isinstance(item, Specialist) for item in self.specialists) or
                not _HASH.fullmatch(self.location_hash) or
                not isinstance(self.scope_url, str) or
                not 1 <= len(self.scope_url) <= 4096 or
                hashlib.sha256(self.scope_url.encode()).hexdigest() != self.location_hash or
                (self.recon_asset_id is not None and
                 (type(self.recon_asset_id) is not int or self.recon_asset_id <= 0)) or
                type(self.automatic) is not bool):
            raise ValueError("Invalid focused delta campaign seed")
