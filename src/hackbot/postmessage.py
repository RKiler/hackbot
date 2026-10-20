"""Policy-scoped messaging specialist built on Phase 21 JS acquisition and Phase 15 plans."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from urllib.parse import urlsplit

from .domxss import DOMAcquisitionStatus, DOMAssetLead, DOMXSSSpecialist
from .domxss_static import DOMStaticAnalyzer
from .hypotheses import Hypothesis, HypothesisSource, HypothesisStatus, HypothesisStore
from .logging import SecretRedactor
from .postmessage_static import MessageCandidateStatus, PostMessageStaticAnalyzer
from .postmessage_store import PostMessageStore
from .skill_plans import SkillContextBuilder, SkillPlanner, SkillRouter
from .target_loader import TargetPackageRepository
from .target_recon import resolve_recon_target
from .target_scope import ScopeResult
from .traffic import ExchangeState, TrafficStore


@dataclass(frozen=True, slots=True)
class PreparedMessageProtocol:
    hypothesis: Hypothesis
    plan: dict[str, object]
    prerequisite_state: str


class PostMessageSpecialist:
    MAX_ASSETS = 16

    def __init__(self, *, dom: DOMXSSSpecialist, targets: TargetPackageRepository,
                 store: PostMessageStore, analyzer: PostMessageStaticAnalyzer | None = None) -> None:
        self.dom, self.targets, self.store = dom, targets, store
        self.analyzer = analyzer or PostMessageStaticAnalyzer()

    def _package(self, package_id: str):
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise ValueError("Authoritative Target Package is unavailable")
        return package

    def inventory(self, package_id: str) -> tuple[DOMAssetLead, ...]:
        package = self._package(package_id)
        recon = resolve_recon_target(package, self.dom.recon)
        if recon is None:
            return ()
        leads: list[DOMAssetLead] = []
        for item in self.dom.inventory(package_id):
            score, reasons = item.score, list(item.reasons)
            analysis = self.dom.recon.get_js_analysis(recon.domain_id, item.asset.asset_id)
            if analysis and any(analysis.signal_counts.get(name, 0) > 0 for name in
                                ("postmessage_usage", "message_listeners", "message_channels")):
                score += 20
                reasons.append("MESSAGING_SIGNAL")
            leads.append(DOMAssetLead(item.asset, min(score, 100), tuple(reasons)))
        leads.sort(key=lambda item: (-item.score, item.asset.asset_id))
        return tuple(leads[:self.MAX_ASSETS])

    def analyze_asset(self, package_id: str, recon_asset_id: int):
        lead = next((item for item in self.inventory(package_id)
                     if item.asset.asset_id == recon_asset_id), None)
        if lead is None:
            raise ValueError("Asset is not in the bounded first-party inventory")
        return self.refresh_observed_asset(package_id, recon_asset_id,
                                           recent_change="RECENT_DELTA" in lead.reasons)

    def refresh_observed_asset(self, package_id: str, recon_asset_id: int,
                               *, recent_change: bool = False,
                               include_source_map: bool = True):
        """Refresh one pinned recon asset through Phase 21 policy-gated acquisition."""
        package = self._package(package_id)
        recon_target = resolve_recon_target(package, self.dom.recon)
        if recon_target is None:
            raise ValueError("Recon target is unavailable")
        asset = self.dom.recon.get_js_asset(recon_target.domain_id, recon_asset_id)
        if (asset is None or asset.asset_id != recon_asset_id or
                package.scope.evaluate_url(asset.asset_url).result is not ScopeResult.IN_SCOPE):
            raise ValueError("Observed in-scope JavaScript asset is required")
        acquired = self.dom.acquire(package_id, asset)
        if (acquired.artifact is None or acquired.status not in {
                DOMAcquisitionStatus.RETRIEVED, DOMAcquisitionStatus.REUSED}):
            return acquired.status.value, None, None, acquired.reason_code
        analysis_id, analysis = self.store.analyze_asset(
            package.target.id, acquired.artifact.artifact_id, self.analyzer,
            recent_change=recent_change)
        if any("DOM_WRITE" in item.sensitive_operations for item in analysis.candidates):
            self.dom.store.analyze_asset(package.target.id, acquired.artifact.artifact_id,
                                         DOMStaticAnalyzer())
        if include_source_map and any(item.priority >= 75 for item in analysis.candidates):
            mapped = self.dom.acquire_source_map(package_id, asset, acquired.artifact)
            if mapped.source_map is not None:
                for item in analysis.candidates:
                    if item.priority >= 75:
                        try:
                            self.store.map_candidate(package.target.id, item.candidate_id,
                                                     mapped.source_map)
                        except ValueError:
                            continue
        return acquired.status.value, analysis_id, analysis, None

    def bind_observed_route(self, package_id: str, candidate_id: str,
                            exchange_id: str, traffic: TrafficStore):
        package = self._package(package_id)
        exchange = traffic.get_exchange(exchange_id)
        if (exchange is None or exchange.target_id != package.target.id
                or exchange.package_id != package_id
                or exchange.state is not ExchangeState.COMPLETE
                or exchange.request.record.method != "GET"
                or exchange.response is None or exchange.response.record.status_code != 200
                or exchange.response.record.content_type not in {"text/html", "application/xhtml+xml"}
                or exchange.request.query_names):
            raise ValueError("Observed successful in-scope page GET is required")
        route = traffic.observed_request_url(exchange)
        parsed = urlsplit(route) if route is not None else None
        if (route is None or parsed is None or parsed.username or parsed.password
                or parsed.query or parsed.fragment
                or "[" in route or "]" in route
                or SecretRedactor.from_environment().text(route) != route
                or package.scope.evaluate_url(route).result is not ScopeResult.IN_SCOPE):
            raise ValueError("Observed messaging route is unsafe or outside scope")
        return self.store.bind_route(package.target.id, candidate_id, route,
                                     exchange.request.observation_evidence_id)

    def prepare_candidate(self, package_id: str, candidate_id: str, *,
                          hypotheses: HypothesisStore, contexts: SkillContextBuilder,
                          router: SkillRouter, planner: SkillPlanner) -> PreparedMessageProtocol:
        package = self._package(package_id)
        item = self.store.get_candidate(package.target.id, candidate_id)
        asset = self.store.current_asset(package.target.id, candidate_id)
        if (item is None or asset is None or item.status not in {
                MessageCandidateStatus.STATIC_CANDIDATE, MessageCandidateStatus.RUNTIME_READY}
                or not item.message_types or item.priority < 60):
            raise ValueError("Current actionable messaging protocol required")
        evidence = self.store.evidence.get_evidence(asset.evidence_id)
        if evidence is None or evidence.target_ref != package.target.id:
            raise ValueError("Messaging artifact evidence unavailable")
        key = hashlib.sha256(json.dumps([package.target.id, item.handler_fingerprint,
                                         sorted(item.message_types)],
                                        separators=(",", ":")).encode()).hexdigest()[:32]
        now = datetime.now(timezone.utc)
        missing = () if item.route else ("reachable route",)
        hypothesis = hypotheses.upsert(Hypothesis(
            id="HYP-" + key, target_id=package.target.id, dedupe_key=key,
            category="POSTMESSAGE", statement="Current JavaScript exposes a cross-origin message protocol",
            status=(HypothesisStatus.READY_FOR_EXPERIMENT if not missing
                    else HypothesisStatus.NEEDS_RESEARCH),
            priority=item.priority, confidence=min(0.8, item.priority / 100),
            potential_impact="Potential unauthorized messaging capability; runtime impact unverified",
            risk="Static origin/source and port signals are leads, not a finding",
            surface_key="js:" + item.candidate_id, boundary="CROSS_ORIGIN",
            why_generated="Current handler and protocol candidate " + item.candidate_id,
            prerequisites=("current JS artifact", "message listener", "observed route",
                           "bounded foreign-origin browser controls"), missing=missing,
            future_experiment="Compare fixed foreign-origin and negative messaging controls",
            positive_signal="Untrusted origin obtains an authorized-only capability or data",
            negative_signal="Untrusted sender is denied or only public behavior occurs",
            skill_tags=("postmessage-trust-analysis",),
            source=HypothesisSource.DETERMINISTIC, producer="POSTMESSAGE_SPECIALIST_V1",
            evidence_ids=tuple(dict.fromkeys(item.evidence_ids)), fact_ids=(),
            created_at=now, updated_at=now,
        ))
        context = contexts.build(hypothesis, None, package=package)
        skill_id = "postmessage-trust-analysis"
        if not any(part["skill"]["name"] == skill_id for part in router.route(hypothesis, context)):
            raise ValueError("postMessage skill is unavailable")
        plan = planner.generate(package, hypothesis, context, skill_id)
        self.store.bind_plan(package.target.id, candidate_id, hypothesis.id, plan["id"])
        return PreparedMessageProtocol(hypothesis, plan, plan["prerequisites"]["state"])
