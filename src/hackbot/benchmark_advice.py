"""Independent, bounded model-advice comparisons without execution authority."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Protocol

from .benchmark_models import CandidateProvenance, ModelRole
from .planner_models import PlannerAdvice, PlannerAdvisor


_MAX_CANDIDATES = 16
_MAX_PACKET_BYTES = 4096
_ALLOWED_FIELDS = frozenset({"candidate_id", "score", "specialist", "category",
                             "gaps", "evidence_strength"})
_CANDIDATE_ID = re.compile(r"PLCAND-[0-9a-f]{32}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_:-]{0,63}\Z")


@dataclass(frozen=True, slots=True)
class AdvicePacket:
    role: ModelRole
    candidates: tuple[dict[str, object], ...]

    def __post_init__(self) -> None:
        if not 1 <= len(self.candidates) <= _MAX_CANDIDATES:
            raise ValueError("Invalid model-advice candidate count")
        for item in self.candidates:
            if (not isinstance(item, dict) or set(item) != _ALLOWED_FIELDS or
                    not isinstance(item["candidate_id"], str) or
                    not isinstance(item["score"], int) or
                    not isinstance(item["specialist"], str) or
                    not isinstance(item["category"], str) or
                    not isinstance(item["gaps"], (tuple, list)) or
                    not isinstance(item["evidence_strength"], int)):
                raise ValueError("Invalid model-advice candidate")
            if (not _CANDIDATE_ID.fullmatch(item["candidate_id"]) or
                    type(item["score"]) is not int or not 0 <= item["score"] <= 1000 or
                    not _CODE.fullmatch(item["specialist"]) or
                    not _CODE.fullmatch(item["category"]) or
                    type(item["evidence_strength"]) is not int or
                    not 0 <= item["evidence_strength"] <= 100 or
                    len(item["gaps"]) > 12 or
                    any(not isinstance(gap, str) or not _CODE.fullmatch(gap)
                        for gap in item["gaps"])):
                raise ValueError("Model-advice packet contains non-code data")
        if len({item["candidate_id"] for item in self.candidates}) != len(self.candidates):
            raise ValueError("Duplicate model-advice candidate")
        if len(json.dumps(self.candidates, separators=(",", ":"))) > _MAX_PACKET_BYTES:
            raise ValueError("Model-advice packet too large")

    def clone(self) -> AdvicePacket:
        return AdvicePacket(self.role, tuple(json.loads(json.dumps(item))
                                             for item in self.candidates))


@dataclass(frozen=True, slots=True)
class ModelAdviceResult:
    ordered_candidate_ids: tuple[str, ...]
    rationale_codes: tuple[str, ...] = ()
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0


class ModelBenchmarkProvider(Protocol):
    name: str

    def advise(self, packet: AdvicePacket) -> ModelAdviceResult: ...


@dataclass(frozen=True, slots=True)
class ProviderObservation:
    provider: str
    status: str
    ordered_candidate_ids: tuple[str, ...]
    input_tokens: int
    output_tokens: int
    latency_ms: int
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    baseline_order: tuple[str, ...]
    primary: ProviderObservation
    challenger: ProviderObservation
    critic: ProviderObservation | None
    provenance: dict[str, CandidateProvenance]
    disagreement_count: int


def _observe(provider: ModelBenchmarkProvider | None, packet: AdvicePacket,
             baseline: tuple[str, ...]) -> ProviderObservation:
    if provider is None:
        return ProviderObservation("NOT_CONFIGURED", "NOT_CONFIGURED", (), 0, 0, 0)
    try:
        result = provider.advise(packet.clone())
    except Exception:
        return ProviderObservation(provider.name, "UNAVAILABLE", (), 0, 0, 0,
                                   "PROVIDER_EXCEPTION")
    if (type(result) is not ModelAdviceResult or
            len(result.ordered_candidate_ids) != len(baseline) or
            any(type(value) is not str for value in result.ordered_candidate_ids) or
            set(result.ordered_candidate_ids) != set(baseline) or
            len(set(result.ordered_candidate_ids)) != len(baseline) or
            any(type(value) is not int or value < 0 for value in
                (result.input_tokens, result.output_tokens, result.latency_ms)) or
            len(result.rationale_codes) > 8 or
            any(not isinstance(value, str) or len(value) > 64 or
                any(char in value for char in "\r\n\0") for value in result.rationale_codes)):
        return ProviderObservation(provider.name, "REJECTED", (), 0, 0, 0,
                                   "INVALID_STRUCTURED_ADVICE")
    return ProviderObservation(provider.name, "VALID", result.ordered_candidate_ids,
                               result.input_tokens, result.output_tokens,
                               result.latency_ms)


def compare_advisors(packet: AdvicePacket, *,
                     primary: ModelBenchmarkProvider | None,
                     challenger: ModelBenchmarkProvider | None,
                     critic: ModelBenchmarkProvider | None = None) -> ComparisonResult:
    """All advisors see the original packet, never another advisor's answer."""
    baseline = tuple(item["candidate_id"] for item in packet.candidates)
    first = _observe(primary, packet, baseline)
    second = _observe(challenger, packet, baseline)
    critical = (_observe(critic, AdvicePacket(ModelRole.FALSE_POSITIVE_CRITIC,
                                              packet.candidates), baseline)
                if critic else None)
    provenance = {}
    # This is ranking support, not proof that an advisor discovered the candidate.
    for candidate_id in baseline:
        a = first.status == "VALID" and candidate_id in first.ordered_candidate_ids[:3]
        b = second.status == "VALID" and candidate_id in second.ordered_candidate_ids[:3]
        provenance[candidate_id] = (CandidateProvenance.BOTH if a and b else
                                    CandidateProvenance.MODEL_A if a else
                                    CandidateProvenance.MODEL_B if b else
                                    CandidateProvenance.DETERMINISTIC)
    disagreement = (sum(a != b for a, b in zip(first.ordered_candidate_ids,
                                               second.ordered_candidate_ids))
                    if first.status == second.status == "VALID" else 0)
    return ComparisonResult(baseline, first, second, critical, provenance, disagreement)


class BenchmarkComparisonAdvisor(PlannerAdvisor):
    """Use primary ordering for a planner tie; independently observe other lanes."""

    def __init__(self, *, primary: ModelBenchmarkProvider | None,
                 challenger: ModelBenchmarkProvider | None,
                 critic: ModelBenchmarkProvider | None = None) -> None:
        self.primary = primary
        self.challenger = challenger
        self.critic = critic
        self.comparisons: list[ComparisonResult] = []

    def choose(self, candidates: tuple[dict[str, object], ...]) -> PlannerAdvice:
        comparison = compare_advisors(
            AdvicePacket(ModelRole.PLANNER_ADVISOR, candidates),
            primary=self.primary, challenger=self.challenger, critic=self.critic)
        self.comparisons.append(comparison)
        order = (comparison.primary.ordered_candidate_ids
                 if comparison.primary.status == "VALID" else comparison.baseline_order)
        return PlannerAdvice(order)


class BenchmarkPlannerAdvisor(PlannerAdvisor):
    """Adapter for Phase 28's existing advisory-only, near-tie ordering slot."""

    def __init__(self, provider: ModelBenchmarkProvider) -> None:
        self.provider = provider
        self.last_observation: ProviderObservation | None = None

    def choose(self, candidates: tuple[dict[str, object], ...]) -> PlannerAdvice:
        packet = AdvicePacket(ModelRole.PLANNER_ADVISOR, candidates)
        baseline = tuple(item["candidate_id"] for item in candidates)
        observation = _observe(self.provider, packet, baseline)
        self.last_observation = observation
        return PlannerAdvice(observation.ordered_candidate_ids if
                             observation.status == "VALID" else baseline)
