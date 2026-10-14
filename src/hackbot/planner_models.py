"""Target-scoped Phase 28 planning records; no execution capabilities."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
import re
from typing import Protocol


PLANNER_VERSION = "28.1"


class PlannerMode(StrEnum):
    ANALYZE_ONLY = "ANALYZE_ONLY"
    PLAN_ONLY = "PLAN_ONLY"
    BOUNDED_AUTONOMOUS = "BOUNDED_AUTONOMOUS"


class PlannerStatus(StrEnum):
    CREATED = "CREATED"
    LOADING_CONTEXT = "LOADING_CONTEXT"
    RANKING = "RANKING"
    RESOLVING_GAPS = "RESOLVING_GAPS"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING_RESEARCH = "WAITING_RESEARCH"
    WAITING_LOGIN = "WAITING_LOGIN"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    WAITING_HUMAN = "WAITING_HUMAN"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


TERMINAL_STATUSES = frozenset({
    PlannerStatus.COMPLETED, PlannerStatus.BLOCKED, PlannerStatus.FAILED,
    PlannerStatus.CANCELLED, PlannerStatus.BUDGET_EXHAUSTED,
})


class Specialist(StrEnum):
    AUTHORIZATION = "AUTHORIZATION"
    API_GRAPHQL = "API_GRAPHQL"
    DOM_XSS = "DOM_XSS"
    POSTMESSAGE = "POSTMESSAGE"
    EXPOSURE = "EXPOSURE"


class CandidateStatus(StrEnum):
    SELECTED = "SELECTED"
    DEFERRED = "DEFERRED"
    BLOCKED = "BLOCKED"
    DUPLICATE = "DUPLICATE"
    NEEDS_REFRESH = "NEEDS_REFRESH"
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    SKIPPED = "SKIPPED"


class PlannerTaskType(StrEnum):
    RESOLVE_IDENTITY = "RESOLVE_IDENTITY"
    RESOLVE_OBJECT = "RESOLVE_OBJECT"
    REFRESH_TRAFFIC = "REFRESH_TRAFFIC"
    REFRESH_ASSET = "REFRESH_ASSET"
    REQUEST_RESEARCH = "REQUEST_RESEARCH"
    CREATE_DISPOSABLE_OBJECT = "CREATE_DISPOSABLE_OBJECT"
    CREATE_PLAN = "CREATE_PLAN"
    RUN_PLAN = "RUN_PLAN"
    VALIDATE_RUN = "VALIDATE_RUN"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class PlannerTaskStatus(StrEnum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"


class KnowledgeGapCode(StrEnum):
    MISSING_IDENTITY = "MISSING_IDENTITY"
    MISSING_SECOND_TENANT = "MISSING_SECOND_TENANT"
    MISSING_OBJECT = "MISSING_OBJECT"
    OBJECT_OWNERSHIP_UNKNOWN = "OBJECT_OWNERSHIP_UNKNOWN"
    MISSING_REQUEST_TEMPLATE = "MISSING_REQUEST_TEMPLATE"
    MISSING_BROWSER_ROUTE = "MISSING_BROWSER_ROUTE"
    MISSING_RESEARCH = "MISSING_RESEARCH"
    UNKNOWN_PROTOCOL = "UNKNOWN_PROTOCOL"
    STALE_JS = "STALE_JS"
    STALE_TRAFFIC = "STALE_TRAFFIC"
    AUTH_REQUIRES_LOGIN = "AUTH_REQUIRES_LOGIN"
    TOKEN_REQUIRED = "TOKEN_REQUIRED"
    SIDE_EFFECT_UNKNOWN = "SIDE_EFFECT_UNKNOWN"
    BUDGET_TOO_LOW = "BUDGET_TOO_LOW"
    POLICY_BLOCKED = "POLICY_BLOCKED"


class CandidateOverride(StrEnum):
    NONE = "NONE"
    PIN = "PIN"
    DEPRIORITIZE = "DEPRIORITIZE"
    EXCLUDE = "EXCLUDE"


@dataclass(frozen=True, slots=True)
class PlannerLimits:
    requests: int = 20
    browser_actions: int = 12
    tokens: int = 2000
    seconds: int = 300
    candidates: int = 8
    per_specialist: int = 3
    portfolio: int = 100
    cleanup_reserve: int = 2
    exploration_percent: int = 10

    def __post_init__(self) -> None:
        bounds = {
            "requests": (0, 100), "browser_actions": (0, 50),
            "tokens": (0, 20000), "seconds": (1, 3600),
            "candidates": (1, 30), "per_specialist": (1, 15),
            "portfolio": (1, 200), "cleanup_reserve": (0, 20),
            "exploration_percent": (0, 30),
        }
        for name, (minimum, maximum) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"Invalid planner {name}")
        if self.cleanup_reserve > self.requests or self.per_specialist > self.candidates:
            raise ValueError("Planner reserves exceed total budget")

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PlannerUsage:
    requests: int = 0
    browser_actions: int = 0
    tokens: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PlannerRun:
    id: str
    target_id: str
    package_id: str
    package_version: int
    policy_hash: str
    mode: PlannerMode
    status: PlannerStatus
    limits: PlannerLimits
    usage: PlannerUsage
    readiness: dict[str, object]
    context_hash: str | None
    candidate_count: int
    selected_count: int
    plans_created: int
    plans_executed: int
    validations: int
    findings: int
    manual_reviews: int
    research_requests: int
    stop_reason: str | None
    planner_version: str
    started_at: str | None
    created_at: str
    updated_at: str
    finished_at: str | None

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["mode"] = self.mode.value
        value["status"] = self.status.value
        return value


@dataclass(frozen=True, slots=True)
class CandidateAssessment:
    """Bounded, non-evidentiary inputs behind one ranking decision."""

    identity_requirements: tuple[str, ...] = ()
    object_requirements: tuple[str, ...] = ()
    traffic_requirements: tuple[str, ...] = ()
    research_requirements: tuple[str, ...] = ()
    potential_impact: str = "UNSPECIFIED"
    confidence: int = 0
    prerequisite_readiness: str = "UNKNOWN"
    prior_related_outcomes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for values in (self.identity_requirements, self.object_requirements,
                       self.traffic_requirements, self.research_requirements,
                       self.prior_related_outcomes):
            if (type(values) is not tuple or len(values) > 8 or
                    any(type(value) is not str or
                        re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value) is None
                        for value in values)):
                raise ValueError("Invalid candidate assessment codes")
        if self.potential_impact not in {
                "UNSPECIFIED", "DATA_EXPOSURE", "UNAUTHORIZED_ACTION",
                "CLIENT_CODE_EXECUTION", "CROSS_ORIGIN_CAPABILITY",
                "CREDENTIAL_EXPOSURE"}:
            raise ValueError("Invalid potential impact")
        if type(self.confidence) is not int or not 0 <= self.confidence <= 100:
            raise ValueError("Invalid candidate confidence")
        if self.prerequisite_readiness not in {
                "UNKNOWN", "READY", "NEEDS_PREREQUISITES", "NEEDS_REFRESH"}:
            raise ValueError("Invalid prerequisite readiness")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> CandidateAssessment:
        if not value:
            return cls()
        return cls(
            identity_requirements=tuple(value.get("identity_requirements", ())),
            object_requirements=tuple(value.get("object_requirements", ())),
            traffic_requirements=tuple(value.get("traffic_requirements", ())),
            research_requirements=tuple(value.get("research_requirements", ())),
            potential_impact=value.get("potential_impact", "UNSPECIFIED"),
            confidence=value.get("confidence", 0),
            prerequisite_readiness=value.get("prerequisite_readiness", "UNKNOWN"),
            prior_related_outcomes=tuple(value.get("prior_related_outcomes", ())),
        )


@dataclass(frozen=True, slots=True)
class PlannerCandidate:
    id: str
    run_id: str
    target_id: str
    source_kind: str
    source_id: str
    hypothesis_id: str | None
    specialist: Specialist
    category: str
    root_cause_key: str
    surface_hash: str
    score: int
    expected_value: int
    priority: int
    estimated_requests: int
    estimated_browser: int
    estimated_tokens: int
    risk: str
    evidence_strength: int
    freshness: str
    gaps: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    source_refs: tuple[str, ...] = ()
    skill_ids: tuple[str, ...] = ()
    handoffs: tuple[str, ...] = ()
    status: CandidateStatus = CandidateStatus.DEFERRED
    related_candidate_id: str | None = None
    plan_id: str | None = None
    plan_run_id: str | None = None
    validation_id: str | None = None
    finding_id: str | None = None
    override: CandidateOverride = CandidateOverride.NONE
    override_specialist: str | None = None
    override_skill_id: str | None = None
    created_at: str = ""
    updated_at: str = ""
    state_hash: str = ""
    assessment: CandidateAssessment = field(default_factory=CandidateAssessment)

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        for name in ("specialist", "status", "override"):
            value[name] = getattr(self, name).value
        return value


@dataclass(frozen=True, slots=True)
class PlannerTask:
    id: str
    run_id: str
    candidate_id: str
    task_type: PlannerTaskType
    status: PlannerTaskStatus
    priority: int
    budget: dict[str, int] = field(default_factory=dict)
    dependencies: tuple[str, ...] = ()
    attempt: int = 0
    result_ref: str | None = None
    reason_code: str | None = None
    created_at: str = ""
    updated_at: str = ""
    started_at: str | None = None
    finished_at: str | None = None

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["task_type"] = self.task_type.value
        value["status"] = self.status.value
        return value


@dataclass(frozen=True, slots=True)
class PlannerAdvice:
    """A bounded ranking hint, never a scope or execution decision."""

    ordered_candidate_ids: tuple[str, ...]


class PlannerAdvisor(Protocol):
    def choose(self, candidates: tuple[dict[str, object], ...]) -> PlannerAdvice: ...
