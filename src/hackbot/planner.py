"""Deterministic portfolio selection for one explicit target-scoped planner run."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from urllib.parse import urlsplit

from .api_registry import APICandidate
from .api_registry import APIOperationRegistry
from .authorization_store import AuthorizationStore
from .domxss_store import DOMXSSStore
from .exposure_models import ExposureCategory, ExposureSource, ExposureStatus
from .exposure_store import ExposureStore
from .hypotheses import HypothesisStore
from .planner_context import PlannerContext, PlannerContextBuilder
from .planner_models import (
    CandidateAssessment, CandidateStatus, KnowledgeGapCode, PlannerAdvisor, PlannerAdvice,
    PlannerCandidate, PlannerLimits,
    PlannerMode, PlannerRun, PlannerStatus, PlannerTaskType, Specialist,
)
from .planner_store import PlannerStore
from .policy import policy_version
from .postmessage_store import PostMessageStore
from .skill_plans import SkillContextBuilder, SkillRouter
from .target_package import TargetPackage
from .target_scope import ScopeResult
from .traffic import TrafficStore
from .validation_store import ValidationStore


BROWSER_TRIAL_CAPS = {Specialist.DOM_XSS: 6, Specialist.POSTMESSAGE: 8}


def _digest(*parts: object) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, default=str).encode()).hexdigest()


def _surface(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        return (parsed.scheme.lower() + "://" + parsed.netloc.lower()
                + (parsed.path or "/").rstrip("/").lower())
    return value.lower().split("?", 1)[0].split("#", 1)[0][:256]


def _candidate_state(run: PlannerRun, context: PlannerContext, signal: _Signal,
                     brief_id: str | None) -> str:
    readiness = (sorted(context.verified_identity_ids), sorted(context.tenant_ids),
                 signal.object_id in context.ready_object_ids)
    return _digest(run.package_version, run.policy_hash, signal.source_kind,
                   signal.source_id, _surface(signal.surface), signal.boundary,
                   signal.helper, signal.freshness, signal.evidence_count,
                   signal.gaps, signal.refs, brief_id,
                   readiness if signal.specialist in {Specialist.AUTHORIZATION,
                                                     Specialist.API_GRAPHQL} else ())


@dataclass(frozen=True, slots=True)
class _Signal:
    source_kind: str
    source_id: str
    specialist: Specialist
    category: str
    surface: str
    boundary: str
    score: int
    confidence: int
    evidence_count: int
    freshness: str
    risk: str
    estimated_requests: int
    estimated_browser: int
    estimated_tokens: int
    gaps: tuple[str, ...]
    refs: tuple[str, ...]
    hypothesis_id: str | None = None
    object_id: str | None = None
    helper: str | None = None
    handoffs: tuple[str, ...] = ()

    def root_key(self, target_id: str) -> str:
        boundary = ("ANONYMOUS_PRIVATE_READ" if self.boundary in {
            "ANONYMOUS", "UNAUTHENTICATED_DOWNLOAD", "UNAUTHENTICATED_RESOURCE"}
            else self.boundary)
        object_id = "" if boundary == "ANONYMOUS_PRIVATE_READ" else self.object_id or ""
        return _digest(target_id, _surface(self.surface), boundary, object_id, self.helper or "")


_MISSING = {
    "second tenant": KnowledgeGapCode.MISSING_SECOND_TENANT,
    "multiple owned identities": KnowledgeGapCode.MISSING_IDENTITY,
    "different-role identity": KnowledgeGapCode.MISSING_IDENTITY,
    "owned objects": KnowledgeGapCode.MISSING_OBJECT,
    "owned protected file": KnowledgeGapCode.MISSING_OBJECT,
    "owned person-level fixture": KnowledgeGapCode.MISSING_OBJECT,
    "known ownership": KnowledgeGapCode.OBJECT_OWNERSHIP_UNKNOWN,
    "safe request template": KnowledgeGapCode.MISSING_REQUEST_TEMPLATE,
    "reachable route": KnowledgeGapCode.MISSING_BROWSER_ROUTE,
    "observed route": KnowledgeGapCode.MISSING_BROWSER_ROUTE,
    "current js body": KnowledgeGapCode.STALE_JS,
    "research": KnowledgeGapCode.MISSING_RESEARCH,
    "protocol": KnowledgeGapCode.UNKNOWN_PROTOCOL,
}


def _gap(value: str) -> str:
    if value in KnowledgeGapCode._value2member_map_:
        return value
    lowered = value.lower().replace("_", " ")
    return next((code.value for key, code in _MISSING.items() if key in lowered),
                KnowledgeGapCode.SIDE_EFFECT_UNKNOWN.value)


def _specialist(category: str) -> Specialist | None:
    if category in {"CROSS_TENANT", "ROLE_AUTHORIZATION", "BOLA", "IDOR", "BFLA"}:
        return Specialist.AUTHORIZATION
    if category in {"GRAPHQL_AUTHORIZATION", "API_AUTHORIZATION"}:
        return Specialist.API_GRAPHQL
    if category == "DOM_XSS":
        return Specialist.DOM_XSS
    if category == "POSTMESSAGE":
        return Specialist.POSTMESSAGE
    if category in {"EXPOSURE", "INTERNAL_SURFACE", "CREDENTIAL_EXPOSURE"}:
        return Specialist.EXPOSURE
    return None


def _potential_impact(signal: _Signal) -> str:
    if signal.specialist is Specialist.DOM_XSS:
        return "CLIENT_CODE_EXECUTION"
    if signal.specialist is Specialist.POSTMESSAGE:
        return "CROSS_ORIGIN_CAPABILITY"
    if signal.specialist is Specialist.EXPOSURE:
        return ("CREDENTIAL_EXPOSURE" if signal.category in {
            "JS_SECRET", "SOURCE_MAP_SECRET", "CREDENTIAL_DISCLOSURE"}
            else "DATA_EXPOSURE" if signal.category in {
                "UNAUTHENTICATED_RESOURCE", "UNAUTHENTICATED_DOWNLOAD",
                "PII_EXPOSURE", "OVEREXPOSED_API_RESPONSE"} else "UNSPECIFIED")
    if signal.specialist in {Specialist.AUTHORIZATION, Specialist.API_GRAPHQL}:
        return ("UNAUTHORIZED_ACTION" if signal.category in {
            "MUTATION_AUTH", "GRAPHQL_MUTATION", "BFLA", "HIDDEN_FUNCTION"}
            else "DATA_EXPOSURE")
    return "UNSPECIFIED"


def _assessment(signal: _Signal, gaps: tuple[str, ...],
                prior_outcomes: tuple[str, ...]) -> CandidateAssessment:
    identity = ()
    if signal.specialist in {Specialist.AUTHORIZATION, Specialist.API_GRAPHQL}:
        identity = ("VERIFIED_OWNER",)
        if signal.boundary != "ANONYMOUS":
            identity += ("VERIFIED_BOUNDARY",)
        if signal.boundary == "CROSS_TENANT":
            identity += ("SECOND_TENANT",)
    objects = ("VERIFIED_DISPOSABLE_OBJECT",) if signal.object_id else ()
    if KnowledgeGapCode.MISSING_OBJECT.value in gaps and not objects:
        objects = ("OWNED_OBJECT",)
    traffic = ()
    if signal.specialist in {Specialist.AUTHORIZATION, Specialist.API_GRAPHQL}:
        traffic = ("OBSERVED_OWNER_REQUEST",)
    elif signal.specialist in {Specialist.DOM_XSS, Specialist.POSTMESSAGE}:
        traffic = ("CURRENT_JS_ASSET",)
    elif signal.specialist is Specialist.EXPOSURE:
        traffic = ("SOURCE_OBSERVATION",)
    if KnowledgeGapCode.MISSING_BROWSER_ROUTE.value in gaps:
        traffic += ("REACHABLE_BROWSER_ROUTE",)
    research = ("CURRENT_RESEARCH_BRIEF",) if any(gap in {
        KnowledgeGapCode.MISSING_RESEARCH.value, KnowledgeGapCode.UNKNOWN_PROTOCOL.value}
        for gap in gaps) else ()
    readiness = ("NEEDS_REFRESH" if signal.freshness == "STALE" else
                 "NEEDS_PREREQUISITES" if gaps else
                 "READY" if signal.freshness == "CURRENT" else "UNKNOWN")
    return CandidateAssessment(
        identity_requirements=identity, object_requirements=objects,
        traffic_requirements=traffic, research_requirements=research,
        potential_impact=_potential_impact(signal), confidence=signal.confidence,
        prerequisite_readiness=readiness, prior_related_outcomes=prior_outcomes)


class CrossSpecialistPlanner:
    """Plans from bounded stores; it has no executor, permit writer, or browser driver."""

    def __init__(self, *, store: PlannerStore, context: PlannerContextBuilder,
                 hypotheses: HypothesisStore, authorization: AuthorizationStore,
                 api: APIOperationRegistry, dom: DOMXSSStore,
                 messages: PostMessageStore, exposure: ExposureStore,
                 traffic: TrafficStore, validations: ValidationStore,
                 skill_context: SkillContextBuilder, skill_router: SkillRouter,
                 advisor: PlannerAdvisor | None = None) -> None:
        self.store, self.context = store, context
        self.hypotheses, self.authorization, self.api = hypotheses, authorization, api
        self.dom, self.messages, self.exposure = dom, messages, exposure
        self.traffic, self.validations = traffic, validations
        self.skill_context, self.skill_router = skill_context, skill_router
        self.advisor = advisor

    def api_signal(self, package: TargetPackage, item: APICandidate) -> _Signal | None:
        operation = self.api.get_operation(package.target.id, item.operation_id)
        if (operation is None or operation.package_id != package.id or
                item.target_id != package.target.id):
            return None
        fresh = "CURRENT" if operation.state == "CURRENT" and item.status != "STALE" else "STALE"
        gaps = tuple(dict.fromkeys(_gap(part) for part in item.gaps))
        if fresh == "STALE":
            gaps = tuple(dict.fromkeys((*gaps, KnowledgeGapCode.STALE_TRAFFIC.value)))
        return _Signal("API_GRAPHQL", item.id, Specialist.API_GRAPHQL,
            item.category, operation.endpoint or operation.operation_key,
            "ANONYMOUS" if item.boundary_identity_id is None else item.category,
            item.score, 70 if operation.exchange_ids else 35,
            len(operation.evidence_ids), fresh,
            "MEDIUM" if operation.method not in {"GET", "HEAD"}
                and operation.type.value.endswith("MUTATION") else "LOW",
            9 if KnowledgeGapCode.MISSING_OBJECT.value in gaps else
            7 if item.category == "MUTATION_AUTH" else 5, 0, 0, gaps,
            tuple(dict.fromkeys((operation.id, *operation.exchange_ids[:2]))),
            item.hypothesis_id, item.test_object_id,
            helper=operation.operation_key if operation.type.value.startswith("GRAPHQL") else None,
            handoffs=(item.authorization_candidate_id,) if item.authorization_candidate_id else ())

    def _signals(self, package: TargetPackage, limit: int) -> tuple[_Signal, ...]:
        target_id = package.target.id
        each = min(50, max(8, (limit + 4) // 5))
        signals: list[_Signal] = []
        hypothesis_page = self.hypotheses.list(target_id, limit=min(50, each))
        for value in hypothesis_page["items"]:
            item = self.hypotheses.get(value["id"], target_id)
            if item is None or item.status.value in {"REJECTED", "BLOCKED"}:
                continue
            specialist = _specialist(item.category)
            if specialist is None:
                continue
            signals.append(_Signal("HYPOTHESIS", item.id, specialist, item.category,
                item.surface_key, item.boundary, item.priority, int(item.confidence * 100),
                len(item.evidence_ids), "UNKNOWN", "MEDIUM", 5 if specialist in {
                    Specialist.AUTHORIZATION, Specialist.API_GRAPHQL} else 0,
                BROWSER_TRIAL_CAPS.get(specialist, 0),
                0, tuple(dict.fromkeys(_gap(part) for part in item.missing)),
                tuple(item.evidence_ids[:6]), item.id))
        auth_controls = self.authorization.matrix(target_id, limit=100)
        for item in self.authorization.list_candidates(target_id, limit=each):
            if item.status in {"REJECTED", "BLOCKED", "VALIDATED"}:
                continue
            exchange = self.traffic.get_exchange(item.owner_exchange_id)
            surface = (exchange.request.origin + exchange.request.display_path
                       if exchange and exchange.target_id == target_id else item.operation_key)
            gaps = tuple(code for state, code in (
                ("NEEDS_OBJECT", "MISSING_OBJECT"), ("NEEDS_TEMPLATE", "MISSING_REQUEST_TEMPLATE"),
                ("NEEDS_SESSION", "AUTH_REQUIRES_LOGIN")) if item.status == state)
            if (item.boundary.value in {"CROSS_TENANT", "HORIZONTAL"} and
                    not any(row["operation_key"] == item.operation_key
                            and row["identity_id"] == item.boundary_identity_id
                            and row["test_object_id"] != item.test_object_id
                            and row["result"] == "OBSERVED_ALLOWED"
                            for row in auth_controls)):
                gaps = tuple(dict.fromkeys((*gaps, "MISSING_OBJECT")))
            signals.append(_Signal("AUTHORIZATION", item.id, Specialist.AUTHORIZATION,
                item.boundary.value, surface, item.boundary.value, item.score, 75,
                1 if exchange else 0, "CURRENT" if exchange else "UNKNOWN",
                "MEDIUM" if "MUTATION" in item.boundary.value else "LOW",
                9 if KnowledgeGapCode.MISSING_OBJECT.value in gaps else 5, 0, 0,
                gaps, (item.owner_exchange_id, item.test_object_id), item.hypothesis_id,
                item.test_object_id))
        for item in self.api.list_candidates(target_id, limit=min(100, each)):
            if item.status in {"REJECTED", "VALIDATED", "BLOCKED"}:
                continue
            signal = self.api_signal(package, item)
            if signal is not None:
                signals.append(signal)
        dom_page = self.dom.list_candidates(target_id, limit=min(50, each))
        for item in dom_page.items:
            if item.status.value in {"REJECTED", "RUNTIME_TESTED", "PARSE_FAILED"}:
                continue
            asset = self.dom.candidate_asset(target_id, item.candidate_id)
            current = bool(item.status.value != "STALE" and asset and asset.state == "CURRENT"
                           and asset.artifact_sha256 == item.asset_sha256)
            gaps = () if item.route else (KnowledgeGapCode.MISSING_BROWSER_ROUTE.value,)
            if not current:
                gaps += (KnowledgeGapCode.STALE_JS.value,)
            links = self.dom.candidate_links(target_id, item.candidate_id) or {}
            signals.append(_Signal("DOM_XSS", item.candidate_id, Specialist.DOM_XSS,
                "DOM_XSS", item.route or item.asset_sha256,
                "CLIENT_SERVER_TRUST", item.score, 65 if item.attacker_controlled else 25,
                len(item.evidence_ids), "CURRENT" if current else "STALE", "LOW", 0,
                BROWSER_TRIAL_CAPS[Specialist.DOM_XSS], 0,
                gaps, tuple(item.evidence_ids[:4]), links.get("hypothesis_id"),
                helper=f"{item.asset_sha256}:{item.source_location.line}:{item.sink_kind}"))
        message_page = self.messages.list_candidates(target_id, limit=min(50, each))
        for item in message_page.items:
            if item.status.value in {"REJECTED", "RUNTIME_TESTED"}:
                continue
            asset = self.messages.current_asset(target_id, item.candidate_id)
            current = bool(item.status.value != "STALE" and asset and asset.state == "CURRENT")
            gaps = () if item.route else (KnowledgeGapCode.MISSING_BROWSER_ROUTE.value,)
            if not current:
                gaps += (KnowledgeGapCode.STALE_JS.value,)
            links = self.messages.links(target_id, item.candidate_id) or {}
            signals.append(_Signal("POSTMESSAGE", item.candidate_id, Specialist.POSTMESSAGE,
                "POSTMESSAGE", item.route or item.handler_fingerprint,
                "CROSS_ORIGIN", item.priority,
                75 if item.port_bound or item.sensitive_operations else 30,
                len(item.evidence_ids), "CURRENT" if current else "STALE", "LOW", 0,
                BROWSER_TRIAL_CAPS[Specialist.POSTMESSAGE], 0,
                gaps, tuple(item.evidence_ids[:4]), links.get("hypothesis_id"),
                helper=item.handler_fingerprint,
                handoffs=self.messages.dom_xss_handoffs(target_id, item.candidate_id)[:4]))
        exposure_page = self.exposure.list(target_id, limit=min(100, each))
        for item in exposure_page.items:
            if item.status in {ExposureStatus.STALE, ExposureStatus.REJECTED_PUBLIC,
                               ExposureStatus.REJECTED_PLACEHOLDER}:
                continue
            if package.scope.evaluate_url(item.location).result is not ScopeResult.IN_SCOPE:
                continue
            links = self.exposure.links(target_id, item.candidate_id)
            anon = item.category in {ExposureCategory.UNAUTHENTICATED_RESOURCE,
                                     ExposureCategory.UNAUTHENTICATED_DOWNLOAD}
            surface = item.location
            if item.source is ExposureSource.TRAFFIC:
                exchange = self.traffic.get_exchange(item.endpoint_or_asset)
                if (exchange and exchange.target_id == target_id and
                        exchange.package_id == package.id and
                        exchange.scope_result is ScopeResult.IN_SCOPE and
                        item.location.startswith(exchange.request.origin + "/")):
                    surface = exchange.request.origin + exchange.request.display_path
            signals.append(_Signal("EXPOSURE", item.candidate_id, Specialist.EXPOSURE,
                item.category.value, surface,
                "ANONYMOUS" if anon else item.category.value,
                item.priority, item.confidence, len(item.evidence_ids),
                "CURRENT", "LOW" if anon else "MEDIUM",
                5 if anon else 0, 0, 0,
                tuple(dict.fromkeys(_gap(part) for part in item.verification_requirements
                                         if part in KnowledgeGapCode._value2member_map_)),
                tuple(item.evidence_ids[:4]), links.get("hypothesis_id")))
        linked_hypotheses = {item.hypothesis_id for item in signals
                             if item.source_kind != "HYPOTHESIS" and item.hypothesis_id}
        return tuple(item for item in signals if item.source_kind != "HYPOTHESIS"
                     or item.source_id not in linked_hypotheses)

    def _rank(self, run: PlannerRun, context: PlannerContext,
              signals: tuple[_Signal, ...]) -> tuple[PlannerCandidate, ...]:
        profile = self.hypotheses.latest_profile(run.target_id)
        research = self.context.research.list(run.target_id, limit=50).get("items", [])
        fresh_research = {item["gap_ref"]: item for item in research
                          if item.get("freshness") == "FRESH" and item.get("brief_id")}
        ranked: list[PlannerCandidate] = []
        for signal in signals:
            score = signal.score
            reasons: list[str] = []
            gap_ref = {"HYPOTHESIS": "hypothesis", "API_GRAPHQL": "api",
                       "EXPOSURE": "exposure"}.get(signal.source_kind)
            related_research = (fresh_research.get(f"{gap_ref}:{signal.source_id}")
                                if gap_ref else None)
            gaps = tuple(gap for gap in signal.gaps
                         if not (related_research and gap == "MISSING_RESEARCH"))
            if signal.specialist in {Specialist.AUTHORIZATION, Specialist.API_GRAPHQL}:
                if not context.verified_identity_ids:
                    gaps = (*gaps, KnowledgeGapCode.MISSING_IDENTITY.value)
                if (signal.boundary == "CROSS_TENANT" and
                        (len(context.verified_identity_ids) < 2 or
                         len(context.tenant_ids) < 2)):
                    gaps = (*gaps, KnowledgeGapCode.MISSING_SECOND_TENANT.value)
                if signal.object_id and signal.object_id not in context.ready_object_ids:
                    gaps = (*gaps, KnowledgeGapCode.MISSING_OBJECT.value)
            gaps = tuple(dict.fromkeys(gaps))
            if related_research:
                score += 3
                reasons.append("RESEARCH_MATCH")
            if signal.boundary in {"CROSS_TENANT", "ANONYMOUS", "UNAUTHENTICATED_DOWNLOAD"}:
                score += 8
                reasons.append("HIGH_VALUE_BOUNDARY")
            if signal.specialist is Specialist.DOM_XSS and signal.confidence >= 60:
                score += 6
                reasons.append("HIGH_CONFIDENCE_DOM_FLOW")
            if signal.specialist is Specialist.POSTMESSAGE and signal.confidence >= 70:
                score += 7
                reasons.append("MESSAGEPORT_CAPABILITY")
            if signal.freshness == "CURRENT":
                score += 5
                reasons.append("CURRENT_ASSET")
            elif signal.freshness == "STALE":
                score -= 25
                reasons.append("STALE_SOURCE")
            if signal.evidence_count:
                score += min(6, signal.evidence_count * 2)
                reasons.append("SOURCE_EVIDENCE")
            if signal.object_id and signal.object_id in context.ready_object_ids:
                score += 6
                reasons.append("OWNED_OBJECT_READY")
            if context.verified_identity_ids:
                score += min(4, len(context.verified_identity_ids) * 2)
            if signal.risk == "HIGH":
                score -= 20
            elif signal.risk == "MEDIUM":
                score -= 7
            score -= min(30, 7 * len(gaps))
            score -= signal.estimated_requests // 2 + signal.estimated_browser // 2
            score = max(0, min(100, score))
            estimated_tokens = signal.estimated_tokens + (
                500 if any(gap in {KnowledgeGapCode.MISSING_RESEARCH.value,
                                   KnowledgeGapCode.UNKNOWN_PROTOCOL.value} for gap in gaps) else 0)
            cost = signal.estimated_requests + signal.estimated_browser * 2 + estimated_tokens // 500
            skill_ids: tuple[str, ...] = ()
            hypothesis = (self.hypotheses.get(signal.hypothesis_id, run.target_id)
                          if signal.hypothesis_id else None)
            if hypothesis:
                try:
                    skill_context = self.skill_context.build(hypothesis, profile)
                    routed = self.skill_router.route(hypothesis, skill_context, limit=3)
                    skill_ids = tuple(item["skill"]["name"] for item in routed)
                    if routed:
                        outcomes = routed[0].get("validation_outcomes") or {}
                        samples = sum(value for value in outcomes.values()
                                      if type(value) is int and value > 0)
                        if samples >= 5:
                            confirmed = int(outcomes.get("CONFIRMED", 0))
                            rejected = int(outcomes.get("REJECTED", 0))
                            if confirmed >= max(2, samples // 5):
                                score = min(100, score + 3)
                                reasons.append("SKILL_HISTORY_SUPPORT")
                            elif rejected >= samples * 4 // 5:
                                score = max(0, score - 2)
                                reasons.append("SKILL_HISTORY_WEAK")
                except (LookupError, ValueError):
                    reasons.append("SKILL_CONTEXT_INCOMPLETE")
            root = signal.root_key(run.target_id)
            brief_id = related_research.get("brief_id") if related_research else None
            state_hash = _candidate_state(run, context, signal, brief_id)
            history = self.store.branch_memory(run.target_id, root, state_hash)
            status = CandidateStatus.DEFERRED
            if history:
                score = max(0, score - 30)
                reasons.append("PRIOR_BRANCH_OUTCOME")
                if any(item["outcome"] in {"CONFIRMED", "REJECTED", "DUPLICATE",
                                           "MANUAL_REVIEW", "FAILED"}
                       or (item["outcome"] == "BLOCKED" and item["reason_code"] not in {
                           "BUDGET_TOO_LOW", "TOKEN_BUDGET_LOW"})
                       for item in history):
                    status = CandidateStatus.SKIPPED
            if signal.hypothesis_id in context.confirmed_hypothesis_ids:
                status = CandidateStatus.SKIPPED
                reasons.append("EXISTING_CONFIRMED_FINDING")
            if signal.freshness == "STALE" and status is not CandidateStatus.SKIPPED:
                status = CandidateStatus.NEEDS_REFRESH
            prior_outcomes = tuple(dict.fromkeys(item["outcome"] for item in history))[:8]
            assessment = _assessment(signal, gaps, prior_outcomes)
            impact_weight = {
                "UNSPECIFIED": 0, "DATA_EXPOSURE": 8,
                "UNAUTHORIZED_ACTION": 10, "CLIENT_CODE_EXECUTION": 8,
                "CROSS_ORIGIN_CAPABILITY": 8, "CREDENTIAL_EXPOSURE": 10,
            }[assessment.potential_impact]
            expected = max(0, min(100, (score * 2 + assessment.confidence
                                         + impact_weight) // 3 - cost))
            candidate_id = "PLCAND-" + _digest(run.id, signal.source_kind, signal.source_id)[:32]
            source_refs = tuple(dict.fromkeys(
                ((brief_id,) if brief_id else ()) + signal.refs))[:8]
            ranked.append(PlannerCandidate(candidate_id, run.id, run.target_id,
                signal.source_kind, signal.source_id, signal.hypothesis_id,
                signal.specialist, signal.category, root, _digest(_surface(signal.surface)),
                score, expected, score, signal.estimated_requests,
                signal.estimated_browser, estimated_tokens, signal.risk,
                max(0, min(100, signal.confidence + min(10, signal.evidence_count * 2))),
                signal.freshness, gaps[:12], tuple(reasons[:12]),
                source_refs, skill_ids, signal.handoffs[:4], status,
                state_hash=state_hash, assessment=assessment))
        ranked.sort(key=lambda item: (-item.priority, -item.expected_value, item.id))
        if self.advisor is not None and len(ranked) > 1 and run.limits.tokens >= 200:
            # Only a tight deterministic score band is eligible; no raw source text is sent.
            top = ranked[0].priority
            tie = tuple(item for item in ranked if top - item.priority <= 5
                        and item.status is not CandidateStatus.SKIPPED)[:8]
            if len(tie) > 1 and self.store.reserve_budget(run.target_id, run.id, tokens=200):
                payload = tuple({"candidate_id": item.id, "score": item.score,
                                 "specialist": item.specialist.value,
                                 "category": item.category, "gaps": item.gaps,
                                 "evidence_strength": item.evidence_strength} for item in tie)
                try:
                    advice = self.advisor.choose(payload)
                except Exception:
                    advice = None
                ids = tuple(item.id for item in tie)
                if (type(advice) is PlannerAdvice and
                        len(advice.ordered_candidate_ids) == len(ids) and
                        all(type(value) is str for value in advice.ordered_candidate_ids) and
                        set(advice.ordered_candidate_ids) == set(ids) and
                        len(set(advice.ordered_candidate_ids)) == len(ids)):
                    position = {candidate_id: index for index, candidate_id in
                                enumerate(advice.ordered_candidate_ids)}
                    ranked.sort(key=lambda item: (0, position[item.id]) if item.id in position
                                else (1, -item.priority))
                    ranked = [replace(item, reason_codes=(*item.reason_codes,
                                                         "MODEL_TIE_BREAK"))
                              if item.id in position else item for item in ranked]
        primary: dict[str, str] = {}
        unique: list[PlannerCandidate] = []
        duplicates: dict[str, PlannerCandidate] = {}
        for item in ranked:
            if item.root_cause_key in primary:
                duplicates[item.id] = replace(
                    item, status=CandidateStatus.DUPLICATE,
                    related_candidate_id=primary[item.root_cause_key],
                    reason_codes=tuple((*item.reason_codes, "SAME_ROOT_CAUSE")))
            else:
                primary[item.root_cause_key] = item.id
                unique.append(item)
        spent_requests = spent_browser = spent_tokens = 0
        selected = 0
        by_specialist: dict[Specialist, int] = {}
        chosen: dict[str, PlannerCandidate] = {}
        leaders: dict[Specialist, PlannerCandidate] = {}
        for item in unique:
            if item.specialist not in leaders and item.score >= 50:
                leaders[item.specialist] = item
        order = [item for item in unique if leaders.get(item.specialist) == item]
        exploration_slots = (min(2, max(1, run.limits.candidates *
                                      run.limits.exploration_percent // 100))
                             if run.limits.exploration_percent else 0)
        exploratory = [item for item in unique if item not in order
                       and item.source_kind == "HYPOTHESIS"
                       and item.freshness == "CURRENT"
                       and item.status is CandidateStatus.DEFERRED
                       and item.evidence_strength >= 45 and item.priority >= 50]
        exploration_ids = {item.id for item in exploratory[:exploration_slots]}
        order.extend(exploratory[:exploration_slots])
        order.extend(item for item in unique if item not in order)
        for item in order:
            reason = list(item.reason_codes)
            status = item.status
            if status is not CandidateStatus.SKIPPED:
                budget_ok = (spent_requests + item.estimated_requests <=
                             run.limits.requests - run.limits.cleanup_reserve
                             and spent_browser + item.estimated_browser <= run.limits.browser_actions
                             and spent_tokens + item.estimated_tokens <=
                             run.limits.tokens - run.usage.tokens)
                if (selected < run.limits.candidates
                        and by_specialist.get(item.specialist, 0) < run.limits.per_specialist
                        and budget_ok):
                    status = (CandidateStatus.NEEDS_REFRESH if item.freshness == "STALE"
                              else CandidateStatus.SELECTED)
                    selected += 1
                    spent_requests += item.estimated_requests
                    spent_browser += item.estimated_browser
                    spent_tokens += item.estimated_tokens
                    by_specialist[item.specialist] = by_specialist.get(item.specialist, 0) + 1
                    reason.append("RANKED_WITHIN_BUDGET")
                    if item.id in exploration_ids:
                        reason.append("EXPLORATION_SLOT")
                elif not budget_ok:
                    reason.append("BUDGET_TOO_LOW")
            chosen[item.id] = replace(item, status=status, reason_codes=tuple(reason[:12]))
        return tuple(duplicates.get(item.id) or chosen[item.id] for item in ranked)

    def start(self, package: TargetPackage, *, mode: PlannerMode = PlannerMode.ANALYZE_ONLY,
              limits: PlannerLimits = PlannerLimits(),
              campaign_work_id: str | None = None,
              suppressed_roots: frozenset[tuple[str, str]] = frozenset()) -> PlannerRun:
        if not isinstance(package, TargetPackage):
            raise ValueError("Authoritative Target Package is required")
        run = self.store.create(package, mode, limits, policy_version(package),
                                campaign_work_id=campaign_work_id)
        self.store.transition(run.target_id, run.id, PlannerStatus.LOADING_CONTEXT,
                              "CONTEXT_STARTED", expected=(PlannerStatus.CREATED,))
        context = self.context.build(package, limits)
        self.store.transition(run.target_id, run.id, PlannerStatus.RANKING,
                              "CONTEXT_READY", expected=(PlannerStatus.LOADING_CONTEXT,))
        run = self.store.get(run.target_id, run.id)
        assert run is not None
        ranked = self._rank(run, context, self._signals(package, limits.portfolio))[:limits.portfolio]
        if suppressed_roots:
            ranked = tuple(replace(item, status=CandidateStatus.SKIPPED,
                                   reason_codes=(*item.reason_codes[:11], "CAMPAIGN_SUPPRESSED"))
                           if (item.root_cause_key, item.state_hash) in suppressed_roots
                           else item for item in ranked)
        run = self.store.save_portfolio(run, ranked, context.readiness,
                                        context.snapshot_hash, context)
        if mode is PlannerMode.ANALYZE_ONLY:
            return self.store.transition(run.target_id, run.id, PlannerStatus.COMPLETED,
                                         "ANALYSIS_COMPLETE", expected=(PlannerStatus.READY,))
        for item in ranked:
            if item.status in {CandidateStatus.SELECTED, CandidateStatus.NEEDS_REFRESH}:
                self.build_tasks(run, item)
        return self.store.get(run.target_id, run.id) or run

    def build_tasks(self, run: PlannerRun, item: PlannerCandidate) -> None:
        if run.mode is PlannerMode.ANALYZE_ONLY or item.run_id != run.id:
            raise ValueError("Planner task creation requires a selected active run")
        dependencies: tuple[str, ...] = ()
        gap_order = {
            "MISSING_IDENTITY": 0, "MISSING_SECOND_TENANT": 0,
            "AUTH_REQUIRES_LOGIN": 0, "STALE_JS": 1,
            "STALE_TRAFFIC": 1, "MISSING_REQUEST_TEMPLATE": 1,
            "MISSING_OBJECT": 2, "OBJECT_OWNERSHIP_UNKNOWN": 2,
            "MISSING_RESEARCH": 3, "UNKNOWN_PROTOCOL": 3,
        }
        gaps = sorted(dict.fromkeys(item.gaps[:12]),
                      key=lambda value: (gap_order.get(value, 4), value))[:5]
        if (item.freshness == "STALE" and item.specialist in
                {Specialist.DOM_XSS, Specialist.POSTMESSAGE} and
                KnowledgeGapCode.STALE_JS.value not in gaps):
            gaps.append(KnowledgeGapCode.STALE_JS.value)
        seen_types: set[PlannerTaskType] = set()
        for gap in gaps:
            task_type = (
                PlannerTaskType.RESOLVE_IDENTITY if gap in {
                    "MISSING_IDENTITY", "MISSING_SECOND_TENANT", "AUTH_REQUIRES_LOGIN"}
                else PlannerTaskType.RESOLVE_OBJECT if gap in {
                    "MISSING_OBJECT", "OBJECT_OWNERSHIP_UNKNOWN"}
                else PlannerTaskType.REFRESH_ASSET if gap == "STALE_JS"
                else PlannerTaskType.REFRESH_TRAFFIC if gap in {
                    "STALE_TRAFFIC", "MISSING_REQUEST_TEMPLATE"}
                else PlannerTaskType.REQUEST_RESEARCH if gap in {
                    "MISSING_RESEARCH", "UNKNOWN_PROTOCOL"}
                else PlannerTaskType.MANUAL_REVIEW)
            if task_type in seen_types:
                continue
            if (task_type is PlannerTaskType.RESOLVE_OBJECT and
                    run.mode is PlannerMode.BOUNDED_AUTONOMOUS):
                creation = self.store.add_task(
                    run, item, PlannerTaskType.CREATE_DISPOSABLE_OBJECT,
                    dependencies=dependencies, budget={"requests": 4})
                dependencies = (creation.id,)
            task = self.store.add_task(run, item, task_type, dependencies=dependencies)
            dependencies = (task.id,)
            seen_types.add(task_type)
        plan = self.store.add_task(run, item, PlannerTaskType.CREATE_PLAN,
                                   dependencies=dependencies)
        if run.mode is PlannerMode.BOUNDED_AUTONOMOUS:
            execute = self.store.add_task(run, item, PlannerTaskType.RUN_PLAN,
                                          dependencies=(plan.id,),
                                          budget={"requests": item.estimated_requests,
                                                  "browser_actions": item.estimated_browser,
                                                  "tokens": item.estimated_tokens})
            self.store.add_task(run, item, PlannerTaskType.VALIDATE_RUN,
                                dependencies=(execute.id,))
