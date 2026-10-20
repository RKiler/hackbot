"""Target-scoped DOM XSS discovery and controlled JS acquisition coordinator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json

from .domxss_static import DOMAnalysis, DOMCandidateStatus, DOMStaticAnalyzer
from .domxss_store import DOMAssetRecord, DOMSourceMapRecord, DOMXSSStore
from .domxss_maps import MAX_SOURCE_MAP_BYTES, referenced_source_map
from .executor import RequestTemplate, TrafficExecutor
from .hypotheses import Hypothesis, HypothesisSource, HypothesisStatus, HypothesisStore
from .policy_models import ActionCategory, ActorMode, ProposedAction
from .profile import TargetProfile
from .recon import ReconJsAsset, ReconRepository
from .skill_plans import SkillContextBuilder, SkillPlanner, SkillRouter
from .target_loader import TargetPackageRepository
from .target_recon import ReconDomainResolver, resolve_recon_target
from .target_scope import ScopeResult
from .traffic import ExchangeState, TrafficStore
from .logging import SecretRedactor


class DOMAcquisitionStatus(StrEnum):
    REUSED = "REUSED"
    RETRIEVED = "RETRIEVED"
    BLOCKED = "BLOCKED"
    NOT_JAVASCRIPT = "NOT_JAVASCRIPT"
    RETRIEVAL_FAILED = "RETRIEVAL_FAILED"
    HASH_DRIFT = "HASH_DRIFT"


@dataclass(frozen=True, slots=True)
class DOMAssetLead:
    asset: ReconJsAsset
    score: int
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DOMAcquisition:
    status: DOMAcquisitionStatus
    artifact: DOMAssetRecord | None
    exchange_ids: tuple[str, ...]
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class DOMSourceMapAcquisition:
    status: DOMAcquisitionStatus
    source_map: DOMSourceMapRecord | None
    exchange_ids: tuple[str, ...]
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class DOMPreparedCandidate:
    hypothesis: Hypothesis
    plan: dict[str, object]
    selected_skill: str
    prerequisite_state: str


class DOMXSSSpecialist:
    """Never receives a raw HTTP client, browser eval, or target credentials."""

    MAX_HOSTS = 8
    MAX_ASSETS_PER_HOST = 8
    MAX_ASSETS = 16

    def __init__(self, *, recon: ReconRepository, targets: TargetPackageRepository,
                 executor: TrafficExecutor, store: DOMXSSStore,
                 analyzer: DOMStaticAnalyzer | None = None) -> None:
        self.recon = recon
        self.targets = targets
        self.executor = executor
        self.store = store
        self.analyzer = analyzer or DOMStaticAnalyzer()

    def _package(self, package_id: str):
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise ValueError("Authoritative Target Package is unavailable")
        return package

    def inventory(self, package_id: str) -> tuple[DOMAssetLead, ...]:
        package = self._package(package_id)
        recon_target = resolve_recon_target(package, self.recon)
        if recon_target is None:
            return ()
        recent_ids: set[int] = set()
        recent_order: list[int] = []
        snapshots = self.recon.list_scan_snapshots(recon_target.domain_id, limit=6).items
        for snapshot in [item for item in snapshots if not item.first_run][:2]:
            if snapshot.finished_at < snapshot.started_at:
                continue
            events = self.recon.list_asset_events(
                recon_target.domain_id, snapshot.started_at, snapshot.finished_at, limit=24,
            ).items
            for item in events:
                if (item.entity_id is not None and item.entity_id > 0
                        and item.entity_type.lower() in {"js_asset", "js_assets", "js_file", "javascript"}
                        and item.entity_id not in recent_ids):
                    recent_ids.add(item.entity_id)
                    recent_order.append(item.entity_id)
        assets_by_id: dict[int, ReconJsAsset] = {}
        for asset_id in recent_order[:24]:
            asset = self.recon.get_js_asset(recon_target.domain_id, asset_id)
            if asset is not None:
                assets_by_id[asset.asset_id] = asset
        hosts = ReconDomainResolver(self.recon).select_hosts(package).hosts[:self.MAX_HOSTS]
        for host in hosts:
            if package.scope.evaluate_url(host.url).result is not ScopeResult.IN_SCOPE:
                continue
            assets = self.recon.list_js_assets(recon_target.domain_id, host.host_id,
                                               limit=self.MAX_ASSETS_PER_HOST).items
            for asset in assets:
                assets_by_id.setdefault(asset.asset_id, asset)
        leads: list[DOMAssetLead] = []
        for asset in assets_by_id.values():
            if package.scope.evaluate_url(asset.asset_url).result is not ScopeResult.IN_SCOPE:
                continue
            score = 30
            reasons = ["FIRST_PARTY_JS_METADATA"]
            if asset.asset_id in recent_ids:
                score += 25
                reasons.append("RECENT_DELTA")
            if asset.latest_sha256:
                score += 10
                reasons.append("RECON_HASH_AVAILABLE")
            if asset.http_status == 200:
                score += 5
                reasons.append("OBSERVED_200")
            elif asset.http_status not in {401, 403}:
                score -= 15
                reasons.append("NON_200_ASSET")
            analysis = self.recon.get_js_analysis(recon_target.domain_id, asset.asset_id)
            if analysis is not None:
                signals = analysis.signal_counts
                if any(signals.get(key, 0) > 0 for key in
                       ("dangerous_dom_sinks", "dom_sinks", "xss_sinks")):
                    score += 15
                    reasons.append("JS_SINK_SIGNAL")
                if any(signals.get(key, 0) > 0 for key in
                       ("decoders", "url_parsers", "postmessage_usage")):
                    score += 10
                    reasons.append("JS_TRANSFORM_OR_SOURCE_SIGNAL")
            leads.append(DOMAssetLead(asset, max(0, min(score, 100)), tuple(reasons)))
        leads.sort(key=lambda item: (-item.score, item.asset.asset_id))
        return tuple(leads[:self.MAX_ASSETS])

    def _observed_asset(self, package_id: str, asset: ReconJsAsset) -> bool:
        package = self._package(package_id)
        recon_target = resolve_recon_target(package, self.recon)
        if recon_target is None:
            return False
        observed = self.recon.get_js_asset(recon_target.domain_id, asset.asset_id)
        return (observed is not None and observed.host_id == asset.host_id
                and observed.asset_url == asset.asset_url
                and observed.latest_sha256 == asset.latest_sha256)

    def acquire(self, package_id: str, asset: ReconJsAsset, *,
                identity_id: str | None = None, session_id: str | None = None) -> DOMAcquisition:
        package = self._package(package_id)
        if (package.scope.evaluate_url(asset.asset_url).result is not ScopeResult.IN_SCOPE
                or not self._observed_asset(package_id, asset)):
            return DOMAcquisition(DOMAcquisitionStatus.BLOCKED, None, (), "UNOBSERVED_OR_OUT_OF_SCOPE")
        if (identity_id is None) != (session_id is None):
            return DOMAcquisition(DOMAcquisitionStatus.BLOCKED, None, (), "INCOMPLETE_IDENTITY")
        cached = self.store.current_asset(package.target.id, asset.asset_url, asset.latest_sha256)
        if cached is not None:
            return DOMAcquisition(DOMAcquisitionStatus.REUSED, cached, ())
        action = ProposedAction(
            target_id=package.target.id, package_id=package.id,
            category=ActionCategory.SAFE_READ,
            actor=ActorMode.AUTHENTICATED if identity_id else ActorMode.ANONYMOUS,
            source="domxss_specialist", purpose="Retrieve one observed first-party JavaScript asset",
            url=asset.asset_url, method="GET", identity_id=identity_id, session_id=session_id,
            vulnerability_class="dom_xss",
        )
        template = RequestTemplate("GET", asset.asset_url)
        try:
            permit = self.executor.authorize(action, template)
        except (ValueError, RuntimeError):
            return DOMAcquisition(DOMAcquisitionStatus.BLOCKED, None, (), "POLICY_NOT_ALLOWED")
        result = self.executor.execute(action, permit, template, max_dispatches=3,
                                       artifact_capture_kind="JS")
        if result.error is not None:
            return DOMAcquisition(DOMAcquisitionStatus.RETRIEVAL_FAILED, None,
                                  result.exchange_ids, result.error.value)
        if result.status_code != 200 or result.truncated or not result.artifact_evidence_id:
            return DOMAcquisition(DOMAcquisitionStatus.NOT_JAVASCRIPT, None,
                                  result.exchange_ids, "NON_JS_OR_TRUNCATED")
        body = self.store.evidence.read_content(result.artifact_evidence_id,
                                                allow_sensitive=True, max_bytes=1_048_576)
        artifact = self.store.record_artifact(
            target_id=package.target.id, asset_url=asset.asset_url, body=body,
            recon_asset_id=asset.asset_id, recon_sha256=asset.latest_sha256,
            source="CONTROLLED_HTTP", retrieval_exchange_id=result.exchange_ids[-1],
            capture_evidence_id=result.artifact_evidence_id,
        )
        status = (DOMAcquisitionStatus.RETRIEVED if artifact.state == "CURRENT"
                  else DOMAcquisitionStatus.HASH_DRIFT)
        return DOMAcquisition(status, artifact, result.exchange_ids)

    def analyze(self, target_id: str, artifact_id: str) -> tuple[str, DOMAnalysis]:
        return self.store.analyze_asset(target_id, artifact_id, self.analyzer)

    def prepare_candidate(self, package_id: str, candidate_id: str, *,
                          hypotheses: HypothesisStore, contexts: SkillContextBuilder,
                          router: SkillRouter, planner: SkillPlanner,
                          profile: TargetProfile | None = None) -> DOMPreparedCandidate:
        """Route one current static trace through Phase 12/15 without starting traffic."""
        package = self._package(package_id)
        candidate = self.store.get_candidate(package.target.id, candidate_id)
        asset = self.store.candidate_asset(package.target.id, candidate_id)
        if (candidate is None or asset is None or asset.state != "CURRENT"
                or candidate.status not in {DOMCandidateStatus.STATICALLY_SUPPORTED,
                                            DOMCandidateStatus.RUNTIME_READY}
                or candidate.asset_sha256 != asset.artifact_sha256
                or asset.recon_sha256 != asset.artifact_sha256
                or not candidate.check_before_transform or not candidate.attacker_controlled
                or candidate.post_checks or candidate.sanitizers or candidate.unresolved_helper):
            raise ValueError("Current, supported DOM trace is required for planning")
        evidence = self.store.evidence.get_evidence(asset.evidence_id)
        if evidence is None or evidence.target_ref != package.target.id:
            raise ValueError("DOM artifact evidence is unavailable")
        key = hashlib.sha256(json.dumps([package.target.id, asset.asset_url_sha256,
                                         candidate.candidate_id, candidate.asset_sha256],
                                        separators=(",", ":")).encode()).hexdigest()[:32]
        now = datetime.now(timezone.utc)
        missing = () if candidate.route else ("reachable route",)
        hypothesis = hypotheses.upsert(Hypothesis(
            id="HYP-" + key, target_id=package.target.id, dedupe_key=key,
            category="DOM_XSS", statement="Current JavaScript contains a check-before-transform DOM flow",
            status=(HypothesisStatus.READY_FOR_EXPERIMENT if not missing
                    else HypothesisStatus.NEEDS_RESEARCH),
            priority=candidate.score, confidence=min(0.85, candidate.score / 100),
            potential_impact="Potential browser script execution; runtime impact unverified",
            risk="Static dataflow only; not a vulnerability finding",
            surface_key="js:" + candidate.candidate_id, boundary="CLIENT_SERVER_TRUST",
            why_generated="Current artifact and connected DOM candidate " + candidate.candidate_id,
            prerequisites=("current JS artifact", "attacker-controlled source", "reachable route",
                           "bounded browser proof"), missing=missing,
            future_experiment="Use policy-gated browser controls and harmless execution marker",
            positive_signal="Harmless marker executes only after the supported transformation",
            negative_signal="Final input is inert or current browser controls block execution",
            skill_tags=("check-before-transform-dom-xss",),
            source=HypothesisSource.DETERMINISTIC, producer="DOM_XSS_SPECIALIST_V1",
            evidence_ids=tuple(dict.fromkeys(candidate.evidence_ids)), fact_ids=(),
            created_at=now, updated_at=now,
        ))
        context = contexts.build(hypothesis, profile, package=package)
        routes = router.route(hypothesis, context)
        skill_id = "check-before-transform-dom-xss"
        if not any(item["skill"]["name"] == skill_id for item in routes):
            raise ValueError("DOM XSS skill is unavailable")
        plan = planner.generate(package, hypothesis, context, skill_id)
        self.store.bind_plan(package.target.id, candidate_id, hypothesis.id, plan["id"])
        return DOMPreparedCandidate(hypothesis, plan, skill_id, plan["prerequisites"]["state"])

    def bind_observed_route(self, package_id: str, candidate_id: str,
                            exchange_id: str, traffic: TrafficStore):
        """Use one current, successful in-scope page request as runtime entrypoint."""
        package = self._package(package_id)
        exchange = traffic.get_exchange(exchange_id)
        if (exchange is None or exchange.target_id != package.target.id
                or exchange.package_id != package_id
                or exchange.state is not ExchangeState.COMPLETE
                or exchange.request.record.method != "GET"
                or exchange.response is None or exchange.response.record.status_code != 200
                or exchange.response.record.content_type not in {"text/html", "application/xhtml+xml"}
                or exchange.request.query_names):
            raise ValueError("Observed successful page GET is required")
        route = traffic.observed_request_url(exchange)
        if (route is None or "[" in route or "]" in route
                or SecretRedactor.from_environment().text(route) != route
                or package.scope.evaluate_url(route).result is not ScopeResult.IN_SCOPE):
            raise ValueError("Observed route is unsafe or outside scope")
        return self.store.bind_route(package.target.id, candidate_id, route,
                                     exchange.request.observation_evidence_id)

    def acquire_source_map(self, package_id: str, js_asset: ReconJsAsset,
                           artifact: DOMAssetRecord, *, identity_id: str | None = None,
                           session_id: str | None = None) -> DOMSourceMapAcquisition:
        package = self._package(package_id)
        if (artifact.target_id != package.target.id or artifact.recon_asset_id != js_asset.asset_id
                or artifact.state == "STALE" or not self._observed_asset(package_id, js_asset)):
            return DOMSourceMapAcquisition(DOMAcquisitionStatus.BLOCKED, None, (), "STALE_OR_UNOBSERVED_JS")
        if (identity_id is None) != (session_id is None):
            return DOMSourceMapAcquisition(DOMAcquisitionStatus.BLOCKED, None, (), "INCOMPLETE_IDENTITY")
        body = self.store.evidence.read_content(artifact.evidence_id,
                                                allow_sensitive=True, max_bytes=1_048_576)
        map_url = referenced_source_map(js_asset.asset_url, body)
        if map_url is None:
            return DOMSourceMapAcquisition(DOMAcquisitionStatus.BLOCKED, None, (), "NO_DIRECT_MAP_REFERENCE")
        if package.scope.evaluate_url(map_url).result is not ScopeResult.IN_SCOPE:
            return DOMSourceMapAcquisition(DOMAcquisitionStatus.BLOCKED, None, (), "MAP_OUT_OF_SCOPE")
        existing = self.store.get_source_map(package.target.id, artifact.artifact_id)
        if existing and existing.map_url_sha256 == hashlib.sha256(map_url.encode()).hexdigest():
            self.store.evidence.artifacts.get_bytes(existing.map_sha256,
                                                    max_bytes=MAX_SOURCE_MAP_BYTES)
            return DOMSourceMapAcquisition(DOMAcquisitionStatus.REUSED, existing, ())
        action = ProposedAction(
            target_id=package.target.id, package_id=package.id,
            category=ActionCategory.SAFE_READ,
            actor=ActorMode.AUTHENTICATED if identity_id else ActorMode.ANONYMOUS,
            source="domxss_specialist", purpose="Retrieve one referenced first-party source map",
            url=map_url, method="GET", identity_id=identity_id, session_id=session_id,
            vulnerability_class="dom_xss",
        )
        template = RequestTemplate("GET", map_url)
        try:
            permit = self.executor.authorize(action, template)
        except (ValueError, RuntimeError):
            return DOMSourceMapAcquisition(DOMAcquisitionStatus.BLOCKED, None, (), "POLICY_NOT_ALLOWED")
        result = self.executor.execute(action, permit, template, max_dispatches=3,
                                       artifact_capture_kind="SOURCE_MAP")
        if result.error is not None:
            return DOMSourceMapAcquisition(DOMAcquisitionStatus.RETRIEVAL_FAILED, None,
                                           result.exchange_ids, result.error.value)
        if result.status_code != 200 or result.truncated or not result.artifact_evidence_id:
            return DOMSourceMapAcquisition(DOMAcquisitionStatus.NOT_JAVASCRIPT, None,
                                           result.exchange_ids, "NON_MAP_OR_TRUNCATED")
        map_body = self.store.evidence.read_content(result.artifact_evidence_id,
                                                    allow_sensitive=True,
                                                    max_bytes=MAX_SOURCE_MAP_BYTES)
        source_map = self.store.record_source_map(
            target_id=package.target.id, js_artifact_id=artifact.artifact_id,
            map_url=map_url, body=map_body, source="CONTROLLED_HTTP",
            retrieval_exchange_id=result.exchange_ids[-1],
            capture_evidence_id=result.artifact_evidence_id,
        )
        return DOMSourceMapAcquisition(DOMAcquisitionStatus.RETRIEVED, source_map,
                                       result.exchange_ids)
