"""Turn one current, relevant delta into an ordinary focused campaign."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import TYPE_CHECKING

from .campaign_models import CampaignLimits, CampaignStatus
from .delta_classifier import event_fingerprint, event_scope_url
from .delta_hypotheses import DeltaHypothesisBuilder
from .delta_models import DeltaFocus, DeltaSource, DeltaStatus
from .delta_store import DeltaStore
from .delta_watcher import DeltaWatcher
from .planner_models import PlannerMode, Specialist
from .recon_postgres import ReconQueryError
from .resources import ResourceError, WorkKind
from .target_package import TargetPackage
from .target_scope import ScopeResult

if TYPE_CHECKING:
    from .recon import ReconRepository
    from .service import BugHunterRuntime


class DeltaCoordinator:
    """Owns candidate selection, not HTTP execution or finding decisions."""

    def __init__(self, runtime: BugHunterRuntime, *,
                 recon: ReconRepository | None = None) -> None:
        self.runtime = runtime
        self.recon = recon if recon is not None else runtime.recon
        self.deltas = DeltaStore(runtime.store)
        self.builder = DeltaHypothesisBuilder(self.deltas, runtime.hypotheses)
        self.watcher = DeltaWatcher(self.deltas, self.recon,
                                    dom_assets=runtime.domxss_store,
                                    traffic=runtime.traffic)

    def check(self, package: TargetPackage, *, trigger: str = "MANUAL") -> dict[str, object]:
        watch = self.watcher.check(package, trigger=trigger)
        if watch["status"] == "IDLE":
            for delta_id in self.deltas.unmaterialized_candidates(package.target.id):
                self.builder.ensure_evidence(package, delta_id)
        campaign = (self.process_one(package) if watch["status"] == "IDLE" else
                    {"status": "WATCH_NOT_READY", "campaign_id": None})
        return {"watch": watch, "campaign": campaign}

    def _current_recon_source(self, package: TargetPackage,
                              candidate: dict[str, object]) -> tuple[str, int | None] | None:
        if candidate["source_kind"] != DeltaSource.RECON.value or self.recon is None:
            return None
        source_ref = str(candidate["source_ref"])
        if not source_ref.startswith("asset_events:") or not source_ref[13:].isdecimal():
            return None
        target = self.recon.resolve_target(package.primary_domain)
        if target is None or not target.active_in_recon:
            return None
        event = self.recon.get_asset_event(target.domain_id, int(source_ref[13:]))
        if event is None or not event.location:
            return None
        url = event_scope_url(event)
        if url is None:
            return None
        if (event.entity_type != candidate["entity_type"] or
                str(event.entity_id) != str(candidate["entity_id"]) or
                hashlib.sha256(url.encode()).hexdigest() != candidate["location_hash"] or
                event_fingerprint(event) != candidate["new_fingerprint"]):
            return None
        if package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
            return None
        asset_id = event.entity_id if event.entity_type == "js_asset" else None
        return url, asset_id

    def _current_cold_start_source(self, package: TargetPackage,
                                   candidate: dict[str, object]) -> tuple[str, None] | None:
        if candidate["source_kind"] != DeltaSource.COLD_START.value:
            return None
        prefix, sep, observation_id = str(candidate["source_ref"]).partition(":")
        if prefix != "bootstrap_observations" or not sep or not observation_id:
            return None
        with self.runtime.store._connection() as db:
            row = db.execute(
                "SELECT source_ref,surface_key FROM bootstrap_observations "
                "WHERE target_id=? AND observation_id=? AND source='COLD_START_JS' "
                "AND code='JS_ACQUIRED' LIMIT 1",
                (package.target.id, observation_id)).fetchone()
        if row is None or not row["source_ref"]:
            return None
        asset = self.runtime.domxss_store.get_asset(package.target.id, row["source_ref"])
        if (asset is None or asset.state != "CURRENT" or
                not asset.retrieval_exchange_id or
                asset.asset_url_sha256 != row["surface_key"] or
                asset.asset_url_sha256 != candidate["entity_id"] or
                asset.artifact_sha256 != candidate["new_fingerprint"]):
            return None
        exchange = self.runtime.traffic.get_exchange(asset.retrieval_exchange_id)
        if exchange is None or exchange.target_id != package.target.id:
            return None
        url = exchange.request.record.url
        if (url is None or hashlib.sha256(url.encode()).hexdigest() !=
                candidate["location_hash"] or
                package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE):
            return None
        return url, None

    def process_one(self, package: TargetPackage) -> dict[str, object]:
        """At most one bounded campaign per pass; no campaign for disabled targets."""
        settings = self.deltas.settings(package.target.id)
        if settings is None or not settings.enabled or settings.daily_campaign_cap == 0:
            return {"status": "DISABLED_OR_CAPPED", "campaign_id": None}
        for candidate in self.deltas.ready_candidates(
                package.target.id, minimum_relevance=settings.minimum_relevance,
                limit=20):
            result = self._start_candidate(package, candidate, automatic=True,
                                           mode=PlannerMode.ANALYZE_ONLY)
            if result["status"] not in {"NO_SPECIALIST", "SOURCE_BLOCKED",
                                        "NO_FOCUSED_HYPOTHESIS"}:
                return result
        return {"status": "NO_ELIGIBLE_DELTA", "campaign_id": None}

    def start_selected(self, package: TargetPackage, delta_id: str, *,
                       mode: PlannerMode = PlannerMode.ANALYZE_ONLY) -> dict[str, object]:
        """Explicitly start one reviewed delta through the ordinary campaign path."""
        if not isinstance(mode, PlannerMode):
            raise ValueError("Invalid focused campaign mode")
        self.deltas.ensure(package)
        candidate = self.deltas.get_candidate(package.target.id, delta_id)
        if candidate is None:
            raise LookupError("Delta candidate not found")
        if candidate["status"] not in {DeltaStatus.CLASSIFIED.value,
                                       DeltaStatus.CAMPAIGN_READY.value}:
            raise ValueError("Delta is not eligible for a focused campaign")
        return self._start_candidate(package, candidate, automatic=False, mode=mode)

    def _start_candidate(self, package: TargetPackage, candidate: dict[str, object], *,
                         automatic: bool, mode: PlannerMode) -> dict[str, object]:
        delta_id = str(candidate["delta_id"])
        settings = self.deltas.settings(package.target.id)
        assert settings is not None
        selected = tuple(Specialist(item) for item in candidate["specialist_hints"]
                         if not automatic or Specialist(item) in settings.allowed_specialists)
        if not selected:
            return {"status": "NO_SPECIALIST", "campaign_id": None}
        try:
            if candidate["source_kind"] == DeltaSource.RECON.value:
                if self.recon is None:
                    return {"status": "SOURCE_UNAVAILABLE", "campaign_id": None}
                current = self._current_recon_source(package, candidate)
            else:
                current = self._current_cold_start_source(package, candidate)
        except (ReconQueryError, OSError, LookupError):
            return {"status": "SOURCE_UNAVAILABLE", "campaign_id": None}
        if current is None:
            self.deltas.transition_candidate(package.target.id, delta_id,
                DeltaStatus.BLOCKED, "SOURCE_CHANGED_OR_OUT_OF_SCOPE")
            return {"status": "SOURCE_BLOCKED", "campaign_id": None,
                    "delta_id": delta_id}
        try:
            self.runtime.resources.admit(WorkKind.CAMPAIGN,
                                         active=self.runtime.campaign.active_count())
        except ResourceError as exc:
            return {"status": "RESOURCE_DEFERRED", "reason_code": exc.reason_code,
                    "campaign_id": None}
        hypothesis_ids = self.builder.materialize(package, delta_id,
                                                  specialists=selected)
        if not hypothesis_ids:
            self.deltas.transition_candidate(package.target.id, delta_id,
                DeltaStatus.DEFERRED, "NO_FOCUSED_HYPOTHESIS")
            return {"status": "NO_FOCUSED_HYPOTHESIS", "campaign_id": None}
        self.deltas.transition_candidate(package.target.id, delta_id,
                                         DeltaStatus.CAMPAIGN_READY, "EVIDENCE_READY")
        url, asset_id = current
        focus = DeltaFocus((delta_id,), hypothesis_ids, selected,
                           str(candidate["location_hash"]), url,
                           recon_asset_id=asset_id, automatic=automatic)
        limits = CampaignLimits(max_cycles=1, seconds=300,
                                requests=min(settings.request_cap, 12),
                                browser_actions=4, research_requests=0,
                                tokens=800, setup_objects=0, cleanup_reserve=0)
        try:
            campaign = self.runtime.campaign.start(
                package, mode=mode, limits=limits,
                requested_by="delta" if automatic else "dashboard_delta",
                focus=focus)
        except ResourceError as exc:
            return {"status": "RESOURCE_DEFERRED", "reason_code": exc.reason_code,
                    "campaign_id": None}
        except ValueError as exc:
            # CampaignStore enforces active-target, daily-cap, and cooldown
            # constraints in the same transaction that creates the campaign.
            return {"status": "ADMISSION_DEFERRED", "reason_code": str(exc)[:80],
                    "campaign_id": None}
        self._record_launch(package.target.id, campaign.id)
        try:
            self.runtime.launch_campaign(package.id, campaign.id)
        except ResourceError as exc:
            self.runtime.campaign.store.transition(
                package.target.id, campaign.id, CampaignStatus.PAUSED,
                exc.reason_code)
            return {"status": "CAMPAIGN_PAUSED", "campaign_id": campaign.id,
                    "delta_id": delta_id, "reason_code": exc.reason_code}
        return {"status": "CAMPAIGN_STARTED", "campaign_id": campaign.id,
                "delta_id": delta_id}

    def _record_launch(self, target_id: str, campaign_id: str) -> None:
        at = datetime.now(timezone.utc).isoformat()
        with self.runtime.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE continuous_targets SET last_campaign_at=?,updated_at=? "
                       "WHERE target_id=?", (at, at, target_id))
            db.execute("UPDATE delta_watch_runs SET campaigns_started=campaigns_started+1 "
                       "WHERE watch_id=(SELECT watch_id FROM delta_watch_runs WHERE target_id=? "
                       "ORDER BY started_at DESC LIMIT 1)", (target_id,))
