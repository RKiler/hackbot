"""Bounded, target-scoped campaign state. No execution capabilities live here."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum

from .planner_models import PlannerMode


CAMPAIGN_VERSION = "31.1"


class CampaignStatus(StrEnum):
    CREATED = "CREATED"
    ASSESSING_READINESS = "ASSESSING_READINESS"
    RUNNING = "RUNNING"
    WAITING_LOGIN = "WAITING_LOGIN"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    WAITING_RESEARCH = "WAITING_RESEARCH"
    WAITING_HUMAN = "WAITING_HUMAN"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    TIME_EXHAUSTED = "TIME_EXHAUSTED"
    CLEANUP_REQUIRED = "CLEANUP_REQUIRED"


TERMINAL_CAMPAIGN_STATUSES = frozenset({
    CampaignStatus.COMPLETED, CampaignStatus.BLOCKED, CampaignStatus.FAILED,
    CampaignStatus.CANCELLED, CampaignStatus.BUDGET_EXHAUSTED,
    CampaignStatus.TIME_EXHAUSTED, CampaignStatus.CLEANUP_REQUIRED,
})


class CampaignPreset(StrEnum):
    SMALL = "SMALL"
    STANDARD = "STANDARD"
    HUNT = "HUNT"
    CUSTOM = "CUSTOM"


@dataclass(frozen=True, slots=True)
class CampaignLimits:
    max_cycles: int = 2
    seconds: int = 600
    requests: int = 20
    browser_actions: int = 8
    research_requests: int = 1
    tokens: int = 2000
    setup_objects: int = 1
    cleanup_reserve: int = 4

    def __post_init__(self) -> None:
        bounds = {
            "max_cycles": (1, 8), "seconds": (30, 14400),
            "requests": (0, 400), "browser_actions": (0, 160),
            "research_requests": (0, 8), "tokens": (0, 80000),
            "setup_objects": (0, 8), "cleanup_reserve": (0, 32),
        }
        for name, (low, high) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"Invalid campaign {name}")
        if self.cleanup_reserve > self.requests:
            raise ValueError("Campaign cleanup reserve exceeds request budget")
        if self.setup_objects and self.cleanup_reserve < self.setup_objects * 3:
            raise ValueError("Campaign cleanup reserve is too small for objects")

    @classmethod
    def preset(cls, value: CampaignPreset) -> CampaignLimits:
        if value is CampaignPreset.SMALL:
            return cls()
        if value is CampaignPreset.STANDARD:
            return cls(3, 1200, 48, 24, 2, 8000, 2, 6)
        if value is CampaignPreset.HUNT:
            return cls(8, 7200, 160, 64, 4, 24000, 4, 12)
        raise ValueError("CUSTOM requires explicit limits")

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CampaignUsage:
    requests: int = 0
    browser_actions: int = 0
    research_requests: int = 0
    tokens: int = 0
    setup_objects: int = 0
    cleanup_requests: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Campaign:
    id: str
    target_id: str
    package_id: str
    package_version: int
    policy_hash: str
    mode: PlannerMode
    status: CampaignStatus
    requested_by: str
    limits: CampaignLimits
    usage: CampaignUsage
    current_cycle: int
    stop_reason: str | None
    readiness_code: str | None
    coverage_digest: str | None
    campaign_version: str
    created_at: str
    started_at: str | None
    updated_at: str
    finished_at: str | None

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["mode"] = self.mode.value
        value["status"] = self.status.value
        return value


class CampaignWorkKind(StrEnum):
    BOOTSTRAP = "BOOTSTRAP"
    BEHAVIOUR = "BEHAVIOUR"
    RESEARCH = "RESEARCH"
    PLANNER = "PLANNER"
    CLEANUP = "CLEANUP"


class CampaignWorkStatus(StrEnum):
    INTENT = "INTENT"
    LINKED = "LINKED"
    COMPLETED = "COMPLETED"
    AMBIGUOUS = "AMBIGUOUS"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class CampaignWork:
    id: str
    campaign_id: str
    cycle: int
    kind: CampaignWorkKind
    status: CampaignWorkStatus
    child_id: str | None
    requests: int
    browser_actions: int
    research_requests: int
    tokens: int
    setup_objects: int
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["kind"] = self.kind.value
        value["status"] = self.status.value
        return value
