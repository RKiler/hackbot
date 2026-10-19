"""Phase 33 benchmark contracts. Runtime inputs never contain answer keys."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import math
import re


BENCHMARK_VERSION = "33.18"
_ID = re.compile(r"[a-z][a-z0-9_-]{2,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def structured_root_fingerprint(category: BenchmarkCategory, operation: str,
                                boundary: str, object_type: str,
                                protocol: str) -> str:
    """Stable evaluator key; never substitutes for a validator confirmation."""
    if (not isinstance(category, BenchmarkCategory) or
            any(not isinstance(value, str) or not value or len(value) > 256
                for value in (operation, boundary, object_type, protocol))):
        raise ValueError("Invalid structured benchmark root")
    payload = json.dumps((category.value, operation, boundary, object_type,
                          protocol), separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


class BenchmarkCategory(StrEnum):
    OTHER = "OTHER"
    AUTHORIZATION = "AUTHORIZATION"
    CROSS_TENANT_BOLA = "CROSS_TENANT_BOLA"
    HORIZONTAL_IDOR = "HORIZONTAL_IDOR"
    VERTICAL_BFLA = "VERTICAL_BFLA"
    GRAPHQL_OBJECT_AUTH = "GRAPHQL_OBJECT_AUTH"
    GRAPHQL_FIELD_AUTH = "GRAPHQL_FIELD_AUTH"
    GRAPHQL_MUTATION_AUTH = "GRAPHQL_MUTATION_AUTH"
    NESTED_API_AUTH = "NESTED_API_AUTH"
    DOM_XSS = "DOM_XSS"
    CHECK_BEFORE_TRANSFORM_DOM_XSS = "CHECK_BEFORE_TRANSFORM_DOM_XSS"
    POSTMESSAGE = "POSTMESSAGE"
    MESSAGEPORT_RPC = "MESSAGEPORT_RPC"
    UNAUTHENTICATED_DOWNLOAD = "UNAUTHENTICATED_DOWNLOAD"
    UNAUTHENTICATED_RESOURCE = "UNAUTHENTICATED_RESOURCE"
    PII_EXPOSURE = "PII_EXPOSURE"
    CREDENTIAL_DISCLOSURE = "CREDENTIAL_DISCLOSURE"
    INTERNAL_VHOST = "INTERNAL_VHOST"
    SECURE_NEGATIVE_CASE = "SECURE_NEGATIVE_CASE"
    NOISY_FALSE_POSITIVE_CASE = "NOISY_FALSE_POSITIVE_CASE"


class BenchmarkSplit(StrEnum):
    DEVELOPMENT = "DEVELOPMENT"
    HELD_OUT = "HELD_OUT"


class BenchmarkFixtureKind(StrEnum):
    RECORDED_TRAFFIC = "RECORDED_TRAFFIC"
    LOCAL_OWNED_DOWNLOAD = "LOCAL_OWNED_DOWNLOAD"
    LOCAL_OWNED_WORKSPACE = "LOCAL_OWNED_WORKSPACE"
    LOCAL_CROSS_TENANT_READ = "LOCAL_CROSS_TENANT_READ"
    LOCAL_CROSS_TENANT_MUTATION = "LOCAL_CROSS_TENANT_MUTATION"
    LOCAL_MIXED_WORKSPACE = "LOCAL_MIXED_WORKSPACE"
    LOCAL_HORIZONTAL_READ = "LOCAL_HORIZONTAL_READ"
    LOCAL_GRAPHQL_OBJECT = "LOCAL_GRAPHQL_OBJECT"
    LOCAL_GRAPHQL_FIELD = "LOCAL_GRAPHQL_FIELD"
    LOCAL_DOM_XSS = "LOCAL_DOM_XSS"
    LOCAL_POSTMESSAGE = "LOCAL_POSTMESSAGE"


class BenchmarkDifficulty(StrEnum):
    BASIC = "BASIC"
    INTERMEDIATE = "INTERMEDIATE"
    ADVANCED = "ADVANCED"


class BenchmarkStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"
    AMBIGUOUS = "AMBIGUOUS"


class FailureStage(StrEnum):
    NOT_DISCOVERED = "NOT_DISCOVERED"
    HYPOTHESIS_MISSED = "HYPOTHESIS_MISSED"
    LOW_RANK = "LOW_RANK"
    WRONG_SPECIALIST = "WRONG_SPECIALIST"
    PREREQUISITE_FAILURE = "PREREQUISITE_FAILURE"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    VALIDATOR_REJECTED = "VALIDATOR_REJECTED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"


class CandidateProvenance(StrEnum):
    DETERMINISTIC = "DETERMINISTIC"
    MODEL_A = "MODEL_A"
    MODEL_B = "MODEL_B"
    BOTH = "BOTH"
    MANUAL = "MANUAL"


class ModelRole(StrEnum):
    PLANNER_ADVISOR = "PLANNER_ADVISOR"
    RESEARCH_SUMMARIZER = "RESEARCH_SUMMARIZER"
    HYPOTHESIS_REFINER = "HYPOTHESIS_REFINER"
    REPORT_PROSE = "REPORT_PROSE"
    FALSE_POSITIVE_CRITIC = "FALSE_POSITIVE_CRITIC"


class ModelLane(StrEnum):
    PRIMARY = "PRIMARY"
    CHALLENGER = "CHALLENGER"
    CRITIC = "CRITIC"


class GateOutcome(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NOT_MEASURED = "NOT_MEASURED"


class ReadinessConclusion(StrEnum):
    READY_FOR_SUPERVISED_PILOT = "READY_FOR_SUPERVISED_PILOT"
    READY_WITH_LIMITATIONS = "READY_WITH_LIMITATIONS"
    NOT_READY = "NOT_READY"


@dataclass(frozen=True, slots=True)
class BenchmarkBudget:
    requests: int = 20
    browser_actions: int = 8
    research_calls: int = 0
    tokens: int = 0
    seconds: int = 300

    def __post_init__(self) -> None:
        for name, maximum in (("requests", 400), ("browser_actions", 160),
                              ("research_calls", 8), ("tokens", 80000),
                              ("seconds", 14400)):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError(f"Invalid benchmark {name}")
        if self.seconds < 30:
            raise ValueError("Benchmark duration is too short")


@dataclass(frozen=True, slots=True)
class ModelSelection:
    role: ModelRole
    provider: str
    model: str
    lane: ModelLane = ModelLane.PRIMARY
    temperature: float | None = None
    reasoning: str | None = None
    input_usd_per_million: float | None = None
    output_usd_per_million: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.role, ModelRole) or not isinstance(self.lane, ModelLane):
            raise ValueError("Invalid benchmark model role or lane")
        if not _ID.fullmatch(self.provider) or not self.model or len(self.model) > 128:
            raise ValueError("Invalid benchmark model selection")
        if any(char in self.model for char in "\r\n\0"):
            raise ValueError("Invalid benchmark model name")
        if self.temperature is not None and (not isinstance(self.temperature, (int, float))
                                             or not math.isfinite(self.temperature)
                                             or not 0 <= self.temperature <= 2):
            raise ValueError("Invalid benchmark temperature")
        for value in (self.input_usd_per_million, self.output_usd_per_million):
            if value is not None and (not isinstance(value, (int, float)) or
                                      not math.isfinite(value) or not 0 <= value <= 10000):
                raise ValueError("Invalid benchmark price estimate")


@dataclass(frozen=True, slots=True)
class BenchmarkRunConfig:
    suite: str
    planner_mode: str = "ANALYZE_ONLY"
    trials: int = 1
    seed: int = 0
    models: tuple[ModelSelection, ...] = ()
    ablations: tuple[str, ...] = ()
    vps_usd_per_hour: float | None = None

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.suite):
            raise ValueError("Invalid benchmark suite")
        if self.planner_mode not in {"ANALYZE_ONLY", "PLAN_ONLY", "BOUNDED_AUTONOMOUS"}:
            raise ValueError("Invalid benchmark planner mode")
        if type(self.trials) is not int or not 1 <= self.trials <= 5:
            raise ValueError("Invalid benchmark trial count")
        if type(self.seed) is not int or not 0 <= self.seed <= 2**32 - 1:
            raise ValueError("Invalid benchmark seed")
        if len({(item.role, item.lane) for item in self.models}) != len(self.models):
            raise ValueError("Duplicate benchmark model role and lane")
        if self.vps_usd_per_hour is not None and (
                not isinstance(self.vps_usd_per_hour, (int, float)) or
                not math.isfinite(self.vps_usd_per_hour) or
                not 0 <= self.vps_usd_per_hour <= 10000):
            raise ValueError("Invalid benchmark VPS price estimate")
        allowed_ablations = {"NO_RESEARCH", "NO_BEHAVIOUR", "NO_MODEL", "NO_RECON",
                             "NO_CHALLENGER", "NO_TRAFFIC"}
        if (not isinstance(self.ablations, tuple) or
                any(item not in allowed_ablations for item in self.ablations) or
                len(set(self.ablations)) != len(self.ablations)):
            raise ValueError("Invalid benchmark ablation selection")

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> BenchmarkRunConfig:
        models = tuple(ModelSelection(
            role=ModelRole(item["role"]), provider=item["provider"],
            model=item["model"], lane=ModelLane(item["lane"]),
            temperature=item.get("temperature"), reasoning=item.get("reasoning"),
            input_usd_per_million=item.get("input_usd_per_million"),
            output_usd_per_million=item.get("output_usd_per_million"))
            for item in value["models"])
        return cls(suite=value["suite"], planner_mode=value["planner_mode"],
                   trials=value["trials"], seed=value["seed"], models=models,
                   ablations=tuple(value["ablations"]),
                   vps_usd_per_hour=value["vps_usd_per_hour"])


@dataclass(frozen=True, slots=True)
class VisibleBenchmarkCase:
    """Only this record and its referenced inputs may enter a target runtime."""

    case_id: str
    version: int
    fixture_id: str
    target_package: str
    scope_hosts: tuple[str, ...]
    identity_aliases: tuple[str, ...]
    input_files: tuple[str, ...]
    context_file: str | None
    budget: BenchmarkBudget
    visible_hash: str
    fixture_kind: BenchmarkFixtureKind = BenchmarkFixtureKind.RECORDED_TRAFFIC

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.case_id) or not _ID.fullmatch(self.fixture_id):
            raise ValueError("Invalid benchmark case or fixture ID")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("Invalid benchmark case version")
        if not _HASH.fullmatch(self.visible_hash):
            raise ValueError("Invalid benchmark fixture hash")
        if not isinstance(self.fixture_kind, BenchmarkFixtureKind):
            raise ValueError("Invalid benchmark fixture kind")
        if not self.scope_hosts or any(not host or "/" in host for host in self.scope_hosts):
            raise ValueError("Invalid benchmark scope")
        if not self.target_package or self.target_package.startswith("/") or ".." in self.target_package:
            raise ValueError("Unsafe target package path")
        for name in (*self.input_files, *((self.context_file,) if self.context_file else ())):
            if name.startswith("/") or ".." in name or "\\" in name:
                raise ValueError("Unsafe benchmark input path")


@dataclass(frozen=True, slots=True)
class ExpectedRootCause:
    category: BenchmarkCategory
    operation: str
    boundary: str
    object_type: str
    protocol: str
    fingerprint: str
    acceptable_categories: tuple[BenchmarkCategory, ...]
    candidate_fingerprints: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.operation or not self.boundary or not self.fingerprint:
            raise ValueError("Incomplete benchmark root cause")
        if not _HASH.fullmatch(self.fingerprint):
            raise ValueError("Invalid benchmark root-cause fingerprint")
        if (len(self.candidate_fingerprints) > 16 or
                len(set(self.candidate_fingerprints)) != len(self.candidate_fingerprints) or
                any(not _HASH.fullmatch(value) for value in self.candidate_fingerprints)):
            raise ValueError("Invalid benchmark candidate fingerprint")


@dataclass(frozen=True, slots=True)
class BenchmarkGroundTruth:
    """Evaluator-only answer key; never pass to campaign, planner, or advisor."""

    case_id: str
    version: int
    category: BenchmarkCategory
    difficulty: BenchmarkDifficulty
    split: BenchmarkSplit
    roots: tuple[ExpectedRootCause, ...]
    expected_specialist: str | None
    expected_skill_ids: tuple[str, ...]
    forbidden_interpretations: tuple[str, ...]
    known_controls: tuple[str, ...]
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.case_id) or type(self.version) is not int or self.version < 1:
            raise ValueError("Invalid benchmark ground truth")
        if self.category in {BenchmarkCategory.SECURE_NEGATIVE_CASE,
                             BenchmarkCategory.NOISY_FALSE_POSITIVE_CASE} and self.roots:
            raise ValueError("Secure benchmark cannot have vulnerable roots")


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    """Evaluator-side union. Callers must pass ``visible`` alone to a run."""

    visible: VisibleBenchmarkCase
    truth: BenchmarkGroundTruth = field(repr=False)

    def __post_init__(self) -> None:
        if (self.visible.case_id, self.visible.version) != (self.truth.case_id,
                                                            self.truth.version):
            raise ValueError("Benchmark answer key does not match visible case")
