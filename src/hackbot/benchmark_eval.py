"""Answer-key evaluation of observed BugHunter records; never confirms a bug."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from collections import Counter, defaultdict
from typing import Iterable

from .benchmark_models import (
    BenchmarkCase, BenchmarkCategory, CandidateProvenance, ExpectedRootCause,
    FailureStage, ModelLane, ModelRole, structured_root_fingerprint,
)


@dataclass(frozen=True, slots=True)
class ObservedCandidate:
    candidate_id: str
    category: BenchmarkCategory
    specialist: str
    skill_ids: tuple[str, ...]
    rank: int
    root_fingerprint: str | None
    provenance: CandidateProvenance
    hypothesis_id: str | None = None
    plan_id: str | None = None
    executed: bool = False
    validated: bool = False
    engine_root_fingerprint: str | None = None


@dataclass(frozen=True, slots=True)
class ObservedFinding:
    finding_id: str
    validation_id: str
    plan_run_id: str
    planner_run_id: str
    campaign_id: str
    hypothesis_id: str
    category: BenchmarkCategory
    operation: str
    boundary: str
    object_type: str
    protocol: str
    root_fingerprint: str
    audit_complete: bool
    evidence_count: int
    control_count: int
    demonstrated_impact: bool
    reproduction_count: int
    report_status: str | None = None
    report_has_secret: bool = False
    report_has_fabrication: bool = False
    engine_root_fingerprint: str | None = None


@dataclass(frozen=True, slots=True)
class CaseUsage:
    requests: int = 0
    setup_requests: int = 0
    verification_requests: int = 0
    cleanup_requests: int = 0
    browser_actions: int = 0
    navigations: int = 0
    fresh_contexts: int = 0
    research_requests: int = 0
    research_cache_hits: int = 0
    research_sources: int = 0
    research_briefs_used: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    login_interventions: int = 0
    approvals: int = 0
    manual_reviews: int = 0
    manual_context_required: int = 0
    objects_created: int = 0
    objects_cleaned: int = 0
    orphaned_objects: int = 0
    safety_violations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if name != "safety_violations" and (type(value) is not int or value < 0):
                raise ValueError("Invalid benchmark usage")
        if self.objects_cleaned > self.objects_created:
            raise ValueError("Benchmark cleanup count exceeds creation count")


@dataclass(frozen=True, slots=True)
class ModelCallUsage:
    role: ModelRole
    lane: ModelLane
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    latency_ms: int

    def __post_init__(self) -> None:
        if (not self.provider or not self.model or
                any(type(value) is not int or value < 0 for value in
                    (self.input_tokens, self.output_tokens, self.latency_ms))):
            raise ValueError("Invalid benchmark model usage")


@dataclass(frozen=True, slots=True)
class ModelComparisonObservation:
    baseline_order: tuple[str, ...]
    primary_status: str
    primary_order: tuple[str, ...]
    challenger_status: str
    challenger_order: tuple[str, ...]
    critic_status: str
    critic_order: tuple[str, ...]
    disagreement_count: int
    provenance: dict[str, CandidateProvenance]

    def __post_init__(self) -> None:
        statuses = {"VALID", "REJECTED", "UNAVAILABLE", "NOT_CONFIGURED"}
        if (not self.baseline_order or len(set(self.baseline_order)) != len(self.baseline_order)
                or any(status not in statuses for status in (
                    self.primary_status, self.challenger_status, self.critic_status))
                or any(set(order) != set(self.baseline_order)
                       if status == "VALID" else bool(order)
                       for status, order in (
                           (self.primary_status, self.primary_order),
                           (self.challenger_status, self.challenger_order),
                           (self.critic_status, self.critic_order)))
                or type(self.disagreement_count) is not int or self.disagreement_count < 0
                or set(self.provenance) != set(self.baseline_order)
                or any(not isinstance(value, CandidateProvenance)
                       for value in self.provenance.values())):
            raise ValueError("Invalid benchmark model comparison")


@dataclass(frozen=True, slots=True)
class CaseTrace:
    case_id: str
    campaign_id: str | None
    candidates: tuple[ObservedCandidate, ...]
    findings: tuple[ObservedFinding, ...]
    usage: CaseUsage
    started_at: str
    finished_at: str
    planner_runs: int = 0
    plans_generated: int = 0
    plans_executed: int = 0
    validations: int = 0
    first_hypothesis_at: str | None = None
    first_plan_at: str | None = None
    first_confirmation_at: str | None = None
    failure_reason: str | None = None
    model_calls: tuple[ModelCallUsage, ...] = ()
    model_comparisons: tuple[ModelComparisonObservation, ...] = ()


@dataclass(frozen=True, slots=True)
class CaseEvaluation:
    case_id: str
    category: BenchmarkCategory
    expected_specialist: str | None
    expected_vulnerabilities: int
    detected_vulnerabilities: int
    false_confirmed_findings: int
    duplicate_confirmed_findings: int
    missed_vulnerabilities: int
    candidate_count: int
    false_candidate_count: int
    executed_plan_count: int
    false_executed_plan_count: int
    top_k: dict[str, int]
    correct_specialist: bool | None
    correct_skill: bool | None
    failure_stage: FailureStage | None
    finding_quality_pass: bool
    report_quality_pass: bool | None
    audit_quality_pass: bool
    usage: CaseUsage
    duration_seconds: float
    time_to_hypothesis_seconds: float | None
    time_to_plan_seconds: float | None
    time_to_confirmation_seconds: float | None
    autonomy: str
    model_calls: tuple[ModelCallUsage, ...] = ()
    model_comparisons: tuple[ModelComparisonObservation, ...] = ()
    matched_finding_ids: tuple[str, ...] = ()
    false_finding_ids: tuple[str, ...] = ()
    campaign_outcome: str | None = None
    matched_candidate_ranks: tuple[int | None, ...] = ()
    top_candidate_categories: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["failure_stage"] = self.failure_stage.value if self.failure_stage else None
        return value

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> CaseEvaluation:
        data = dict(value)
        data["category"] = BenchmarkCategory(data["category"])
        data["failure_stage"] = (FailureStage(data["failure_stage"])
                                 if data["failure_stage"] else None)
        usage = dict(data["usage"])
        usage["safety_violations"] = tuple(usage["safety_violations"])
        data["usage"] = CaseUsage(**usage)
        data["model_calls"] = tuple(ModelCallUsage(
            role=ModelRole(item["role"]), lane=ModelLane(item["lane"]),
            provider=item["provider"], model=item["model"],
            input_tokens=item["input_tokens"], output_tokens=item["output_tokens"],
            latency_ms=item["latency_ms"]) for item in data["model_calls"])
        data["model_comparisons"] = tuple(ModelComparisonObservation(
            baseline_order=tuple(item["baseline_order"]),
            primary_status=item["primary_status"],
            primary_order=tuple(item["primary_order"]),
            challenger_status=item["challenger_status"],
            challenger_order=tuple(item["challenger_order"]),
            critic_status=item["critic_status"],
            critic_order=tuple(item["critic_order"]),
            disagreement_count=item["disagreement_count"],
            provenance={key: CandidateProvenance(value)
                        for key, value in item["provenance"].items()})
            for item in data.get("model_comparisons", ()))
        data["matched_finding_ids"] = tuple(data["matched_finding_ids"])
        data["false_finding_ids"] = tuple(data["false_finding_ids"])
        data["matched_candidate_ranks"] = tuple(data.get("matched_candidate_ranks", ()))
        data["top_candidate_categories"] = tuple(data.get("top_candidate_categories", ()))
        return cls(**data)


def _elapsed(start: str, end: str | None) -> float | None:
    if end is None:
        return None
    elapsed = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
    return max(0.0, elapsed)


def _matches(candidate: ObservedCandidate | ObservedFinding,
             root: ExpectedRootCause) -> bool:
    if candidate.root_fingerprint is None:
        return False
    if candidate.category not in root.acceptable_categories:
        return False
    fingerprints = {root.fingerprint}
    if root.fingerprint == structured_root_fingerprint(
            root.category, root.operation, root.boundary,
            root.object_type, root.protocol):
        fingerprints.update(structured_root_fingerprint(
            category, root.operation, root.boundary,
            root.object_type, root.protocol)
            for category in root.acceptable_categories)
    if isinstance(candidate, ObservedFinding):
        return (candidate.root_fingerprint in fingerprints and
                candidate.operation == root.operation and
                candidate.boundary == root.boundary and
                candidate.object_type == root.object_type and
                candidate.protocol == root.protocol)
    return candidate.root_fingerprint in (*fingerprints, *root.candidate_fingerprints)


def _failure_stage(trace: CaseTrace, expected: tuple[ExpectedRootCause, ...]) -> FailureStage:
    if not trace.candidates:
        return FailureStage.NOT_DISCOVERED
    relevant = [item for item in trace.candidates if any(_matches(item, root) for root in expected)]
    if not relevant:
        return FailureStage.HYPOTHESIS_MISSED
    if min(item.rank for item in relevant) > 10:
        return FailureStage.LOW_RANK
    if (trace.failure_reason == "WRONG_SPECIALIST" or
            not any(item.specialist == _expected_specialist(root.category)
                    for item in relevant for root in expected if _matches(item, root))):
        return FailureStage.WRONG_SPECIALIST
    if trace.failure_reason == "POLICY_BLOCKED":
        return FailureStage.POLICY_BLOCKED
    if trace.failure_reason == "BUDGET_EXHAUSTED":
        return FailureStage.BUDGET_EXHAUSTED
    if trace.failure_reason == "MANUAL_REQUIRED":
        return FailureStage.MANUAL_REQUIRED
    if not any(item.plan_id for item in relevant):
        return FailureStage.PREREQUISITE_FAILURE
    if not any(item.executed for item in relevant):
        return FailureStage.EXECUTION_FAILED
    return FailureStage.VALIDATOR_REJECTED


def _expected_specialist(category: BenchmarkCategory) -> str:
    if category in {BenchmarkCategory.AUTHORIZATION, BenchmarkCategory.CROSS_TENANT_BOLA,
                    BenchmarkCategory.HORIZONTAL_IDOR, BenchmarkCategory.VERTICAL_BFLA}:
        return "AUTHORIZATION"
    if category in {BenchmarkCategory.GRAPHQL_OBJECT_AUTH, BenchmarkCategory.GRAPHQL_FIELD_AUTH,
                    BenchmarkCategory.GRAPHQL_MUTATION_AUTH, BenchmarkCategory.NESTED_API_AUTH}:
        return "API_GRAPHQL"
    if category in {BenchmarkCategory.DOM_XSS,
                    BenchmarkCategory.CHECK_BEFORE_TRANSFORM_DOM_XSS}:
        return "DOM_XSS"
    if category in {BenchmarkCategory.POSTMESSAGE, BenchmarkCategory.MESSAGEPORT_RPC}:
        return "POSTMESSAGE"
    return "EXPOSURE"


def evaluate_case(case: BenchmarkCase, trace: CaseTrace) -> CaseEvaluation:
    """A Finding counts only with exact structured root cause and a full audit link."""
    if case.visible.case_id != trace.case_id:
        raise ValueError("Case trace does not match hidden answer key")
    roots = case.truth.roots
    matched: set[int] = set()
    matched_ids: list[str] = []
    false_ids: list[str] = []
    duplicates = 0
    audit_pass = True
    finding_quality = True
    report_quality: bool | None = None
    for finding in trace.findings:
        valid_chain = (finding.audit_complete and all((finding.validation_id,
            finding.plan_run_id, finding.planner_run_id, finding.campaign_id,
            finding.hypothesis_id)))
        audit_pass &= bool(valid_chain)
        quality = (bool(valid_chain) and finding.evidence_count > 0 and
                   finding.control_count > 0 and finding.demonstrated_impact and
                   finding.reproduction_count > 0)
        finding_quality &= quality
        if finding.report_status is not None:
            report_ok = (finding.report_status == "READY" and not finding.report_has_secret
                         and not finding.report_has_fabrication)
            report_quality = report_ok if report_quality is None else report_quality and report_ok
        root_index = next((index for index, root in enumerate(roots)
                           if _matches(finding, root)), None)
        if root_index is None or not quality:
            false_ids.append(finding.finding_id)
        elif root_index in matched:
            duplicates += 1
        else:
            matched.add(root_index)
            matched_ids.append(finding.finding_id)

    matched_ranks = tuple(min((item.rank for item in trace.candidates
                               if _matches(item, root)), default=None)
                          for root in roots)
    top_k = {str(k): sum(rank is not None and rank <= k for rank in matched_ranks)
             for k in (1, 3, 5, 10)}
    top_categories = tuple(item.category.value for item in
                           sorted(trace.candidates, key=lambda item: item.rank)[:3])
    relevant = [item for item in trace.candidates if any(_matches(item, root) for root in roots)]
    expected_specialist = case.truth.expected_specialist
    specialist_ok = (None if not roots or expected_specialist is None else
                     any(item.specialist == expected_specialist for item in relevant))
    skill_ok = (None if not roots or not case.truth.expected_skill_ids else
                any(set(item.skill_ids).intersection(case.truth.expected_skill_ids)
                    for item in relevant))
    missing = len(roots) - len(matched)
    failure = _failure_stage(trace, roots) if missing else None
    false_candidates = sum(not any(_matches(item, root) for root in roots)
                           for item in trace.candidates)
    executed = [item for item in trace.candidates if item.executed]
    false_executed = sum(not any(_matches(item, root) for root in roots)
                         for item in executed)
    usage = trace.usage
    autonomy = ("MANUAL_ANALYSIS_REQUIRED" if usage.manual_reviews or
                usage.manual_context_required else
                "LOGIN_ASSISTED" if usage.login_interventions else
                "APPROVAL_ONLY" if usage.approvals else "FULLY_AUTONOMOUS")
    return CaseEvaluation(
        case_id=trace.case_id, category=case.truth.category,
        expected_specialist=expected_specialist,
        expected_vulnerabilities=len(roots),
        detected_vulnerabilities=len(matched), false_confirmed_findings=len(false_ids),
        duplicate_confirmed_findings=duplicates, missed_vulnerabilities=missing,
        candidate_count=len(trace.candidates), false_candidate_count=false_candidates,
        executed_plan_count=len(executed), false_executed_plan_count=false_executed,
        top_k=top_k, correct_specialist=specialist_ok, correct_skill=skill_ok,
        failure_stage=failure, finding_quality_pass=finding_quality,
        report_quality_pass=report_quality, audit_quality_pass=audit_pass,
        usage=usage, duration_seconds=_elapsed(trace.started_at, trace.finished_at) or 0.0,
        time_to_hypothesis_seconds=_elapsed(trace.started_at, trace.first_hypothesis_at),
        time_to_plan_seconds=_elapsed(trace.started_at, trace.first_plan_at),
        time_to_confirmation_seconds=_elapsed(trace.started_at, trace.first_confirmation_at),
        autonomy=autonomy, matched_finding_ids=tuple(matched_ids),
        false_finding_ids=tuple(false_ids), model_calls=trace.model_calls,
        model_comparisons=trace.model_comparisons,
        campaign_outcome=trace.failure_reason or "COMPLETED",
        matched_candidate_ranks=matched_ranks,
        top_candidate_categories=top_categories)


def trial_stability(cases: Iterable[CaseEvaluation]) -> dict[str, dict[str, object]]:
    """Describe repeated-case variation without collapsing misses into one score."""
    groups: dict[str, list[CaseEvaluation]] = defaultdict(list)
    for item in cases:
        groups[item.case_id].append(item)
    result = {}
    for case_id, rows in sorted(groups.items()):
        if len(rows) < 2:
            continue
        expected = sum(item.expected_vulnerabilities for item in rows)
        rank_data = (len({item.expected_vulnerabilities for item in rows}) == 1 and
                     all(len(item.matched_candidate_ranks) ==
                         item.expected_vulnerabilities for item in rows))
        rank_spans = None
        if rank_data and rows[0].expected_vulnerabilities:
            rank_spans = []
            for index in range(rows[0].expected_vulnerabilities):
                ranks = [item.matched_candidate_ranks[index] for item in rows
                         if item.matched_candidate_ranks[index] is not None]
                rank_spans.append({"min": min(ranks) if ranks else None,
                                   "max": max(ranks) if ranks else None,
                                   "missing_trials": len(rows) - len(ranks)})
        top_order_measured = all(item.top_candidate_categories or
                                 item.candidate_count == 0 for item in rows)
        result[case_id] = {
            "trials": len(rows),
            "confirmed_rate": (round(sum(item.detected_vulnerabilities for item in rows) /
                                     expected, 4) if expected else None),
            "top_3_rate": (round(sum(item.top_k["3"] for item in rows) /
                                 expected, 4) if expected else None),
            "root_rank_spans": rank_spans,
            "top_three_category_order_consistent": (
                len({item.top_candidate_categories for item in rows}) == 1
                if top_order_measured else None),
            "specialist_routing_consistent": (
                len({item.correct_specialist for item in rows}) == 1
                if all(item.correct_specialist is not None for item in rows)
                else None),
            "confirmation_consistent": len({
                (item.detected_vulnerabilities, item.false_confirmed_findings)
                for item in rows}) == 1,
            "campaign_outcome_consistent": len({item.campaign_outcome
                                                for item in rows}) == 1,
            "false_confirmed_trials": sum(item.false_confirmed_findings > 0
                                          for item in rows),
        }
    return result


def aggregate_metrics(cases: Iterable[CaseEvaluation]) -> dict[str, object]:
    items = tuple(cases)
    expected = sum(item.expected_vulnerabilities for item in items)
    detected = sum(item.detected_vulnerabilities for item in items)
    false = sum(item.false_confirmed_findings for item in items)
    duplicates = sum(item.duplicate_confirmed_findings for item in items)
    confirmed = detected + false + duplicates
    candidates = sum(item.candidate_count for item in items)
    false_candidates = sum(item.false_candidate_count for item in items)
    executed = sum(item.executed_plan_count for item in items)
    false_executed = sum(item.false_executed_plan_count for item in items)
    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None
    return {
        "cases": len(items), "expected_vulnerabilities": expected,
        "detected_vulnerabilities": detected, "missed_vulnerabilities": expected - detected,
        "false_confirmed_findings": false, "duplicate_confirmed_findings": duplicates,
        "precision": ratio(detected + duplicates, confirmed),
        "recall": ratio(detected, expected),
        "candidate_count": candidates, "false_candidate_count": false_candidates,
        "candidate_false_positive_rate": ratio(false_candidates, candidates),
        "executed_plan_count": executed, "false_executed_plan_count": false_executed,
        "executed_plan_false_positive_rate": ratio(false_executed, executed),
        "confirmed_finding_false_positive_rate": ratio(false, confirmed),
        "top_k_recall": {str(k): ratio(sum(item.top_k[str(k)] for item in items), expected)
                         for k in (1, 3, 5, 10)},
        "trial_stability": trial_stability(items),
        "specialist_routing_accuracy": ratio(sum(item.correct_specialist is True for item in items),
                                              sum(item.correct_specialist is not None for item in items)),
        "skill_routing_accuracy": ratio(sum(item.correct_skill is True for item in items),
                                         sum(item.correct_skill is not None for item in items)),
        "secure_cases_with_false_confirmations": sum(item.expected_vulnerabilities == 0 and
                                                     item.false_confirmed_findings > 0
                                                     for item in items),
        "safety_violations": sum(len(item.usage.safety_violations) for item in items),
        "orphaned_objects": sum(item.usage.orphaned_objects for item in items),
        "requests": sum(item.usage.requests for item in items),
        "setup_requests": sum(item.usage.setup_requests for item in items),
        "verification_requests": sum(item.usage.verification_requests for item in items),
        "cleanup_requests": sum(item.usage.cleanup_requests for item in items),
        "browser_actions": sum(item.usage.browser_actions for item in items),
        "navigations": sum(item.usage.navigations for item in items),
        "fresh_contexts": sum(item.usage.fresh_contexts for item in items),
        "research_requests": sum(item.usage.research_requests for item in items),
        "research_cache_hits": sum(item.usage.research_cache_hits for item in items),
        "research_cache_hit_rate": ratio(
            sum(item.usage.research_cache_hits for item in items),
            sum(item.usage.research_requests for item in items)),
        "research_sources": sum(item.usage.research_sources for item in items),
        "research_briefs_used": sum(item.usage.research_briefs_used for item in items),
        "login_interventions": sum(item.usage.login_interventions for item in items),
        "approvals": sum(item.usage.approvals for item in items),
        "manual_reviews": sum(item.usage.manual_reviews for item in items),
        "manual_context_required": sum(item.usage.manual_context_required for item in items),
        "objects_created": sum(item.usage.objects_created for item in items),
        "objects_cleaned": sum(item.usage.objects_cleaned for item in items),
        "tokens": sum(item.usage.input_tokens + item.usage.output_tokens for item in items),
        "requests_per_detection": ratio(sum(item.usage.requests for item in items), detected),
        "browser_actions_per_detection": ratio(sum(item.usage.browser_actions for item in items),
                                               detected),
        "tokens_per_detection": ratio(sum(item.usage.input_tokens + item.usage.output_tokens
                                          for item in items), detected),
        "duration_seconds": round(sum(item.duration_seconds for item in items), 3),
    }


def specialist_breakdown(cases: Iterable[CaseEvaluation]) -> tuple[dict[str, object], ...]:
    """Attribute positive-case yield only to its hidden expected specialist."""
    items = tuple(cases)
    names = ("AUTHORIZATION", "API_GRAPHQL", "DOM_XSS", "POSTMESSAGE", "EXPOSURE")
    rows = []
    for name in names:
        selected = tuple(item for item in items if item.expected_specialist == name)
        expected = sum(item.expected_vulnerabilities for item in selected)
        measured_routing = sum(item.correct_specialist is not None for item in selected)
        rows.append({
            "specialist": name, "cases": len(selected),
            "expected_vulnerabilities": expected,
            "detected_vulnerabilities": sum(item.detected_vulnerabilities for item in selected),
            "missed_vulnerabilities": sum(item.missed_vulnerabilities for item in selected),
            "candidate_count": sum(item.candidate_count for item in selected),
            "false_candidate_count": sum(item.false_candidate_count for item in selected),
            "false_confirmed_findings": sum(item.false_confirmed_findings for item in selected),
            "requests": sum(item.usage.requests for item in selected),
            "manual_context_required": sum(item.usage.manual_context_required for item in selected),
            "routing_accuracy": (round(sum(item.correct_specialist is True for item in selected)
                                       / measured_routing, 4) if measured_routing else None),
            "recall": (round(sum(item.detected_vulnerabilities for item in selected)
                             / expected, 4) if expected else None),
            "status": "MEASURED" if selected else "NOT_MEASURED",
        })
    return tuple(rows)


def model_usage_breakdown(cases: Iterable[CaseEvaluation]) -> tuple[dict[str, object], ...]:
    """Report actual calls and cost inputs, without attributing detections to a model."""
    groups: dict[tuple[str, str, str, str], Counter[str]] = defaultdict(Counter)
    for item in cases:
        for call in item.model_calls:
            key = (call.lane.value, call.role.value, call.provider, call.model)
            groups[key].update(calls=1, input_tokens=call.input_tokens,
                               output_tokens=call.output_tokens,
                               latency_ms=call.latency_ms)
    return tuple({"lane": lane, "role": role, "provider": provider,
                  "model": model, "quality": "NOT_MEASURED", **groups[key]}
                 for key in sorted(groups)
                 for lane, role, provider, model in (key,))


def model_comparison_breakdown(cases: Iterable[CaseEvaluation]) -> dict[str, object]:
    comparisons = tuple(comparison for item in cases
                        for comparison in item.model_comparisons)
    lanes = {name: Counter() for name in ("PRIMARY", "CHALLENGER", "CRITIC")}
    provenance = Counter()
    for comparison in comparisons:
        lanes["PRIMARY"][comparison.primary_status] += 1
        lanes["CHALLENGER"][comparison.challenger_status] += 1
        lanes["CRITIC"][comparison.critic_status] += 1
        provenance.update(value.value for value in comparison.provenance.values())
    return {
        "status": "MEASURED" if comparisons else "NOT_MEASURED",
        "comparison_packets": len(comparisons),
        "disagreement_positions": sum(item.disagreement_count for item in comparisons),
        "lane_statuses": {name: dict(sorted(counts.items()))
                          for name, counts in lanes.items()},
        "candidate_provenance": dict(sorted(provenance.items())),
        "quality": "NOT_MEASURED",
    }


def failure_stage_breakdown(cases: Iterable[CaseEvaluation]) -> dict[str, object]:
    items = tuple(cases)
    missed = tuple(item for item in items if item.missed_vulnerabilities)
    counts = Counter(item.failure_stage.value if item.failure_stage else "UNCLASSIFIED"
                     for item in missed)
    return {"missed_cases": len(missed), "missed_vulnerabilities": sum(
        item.missed_vulnerabilities for item in missed), "stages": dict(sorted(counts.items()))}
