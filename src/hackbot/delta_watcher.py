"""Target-scoped, read-only recon-delta watcher with durable local checkpoints."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from typing import TYPE_CHECKING

from .delta_classifier import DeltaClassifier
from .delta_models import DeltaSource, WatchStatus
from .delta_semantics import js_semantics, new_asset_signals, semantic_additions
from .delta_store import DeltaStore
from .domxss_store import DOMXSSStore
from .recon import Provenance, ReconAssetEvent, ReconRepository
from .recon_postgres import ReconQueryError
from .target_package import PackageStatus, TargetPackage
from .target_recon import resolve_recon_target
from .target_scope import ScopeResult

if TYPE_CHECKING:
    from .traffic import TrafficStore


_PAGE_SIZE = 100
_MAX_WINDOW = timedelta(days=30)
_OVERLAP = timedelta(seconds=1)
_COLD_PAGE = 16


class ColdStartSourceError(RuntimeError):
    """A durable bootstrap observation cannot be verified from local records."""


def _naive(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed


class DeltaWatcher:
    """No HTTP executor, browser, or target credentials are reachable here."""

    def __init__(self, ledger: DeltaStore, recon: ReconRepository | None,
                 classifier: DeltaClassifier | None = None,
                 dom_assets: DOMXSSStore | None = None,
                 traffic: TrafficStore | None = None) -> None:
        self.ledger = ledger
        self.recon = recon
        self.classifier = classifier or DeltaClassifier()
        self.dom_assets = dom_assets
        self.traffic = traffic

    def _cold_start(self, package: TargetPackage, state: dict[str, object]) -> tuple[
            tuple, tuple, tuple[str, str] | None, int, bool, int]:
        target_id = package.target.id
        checkpoint_at = state["last_bootstrap_at"]
        if checkpoint_at is None:
            with self.ledger.store._connection() as db:
                latest = db.execute(
                    "SELECT observed_at,observation_id FROM bootstrap_observations "
                    "WHERE target_id=? AND source='COLD_START_JS' AND code='JS_ACQUIRED' "
                    "ORDER BY observed_at DESC,observation_id DESC LIMIT 1",
                    (target_id,)).fetchone()
            highwater = ((latest["observed_at"], latest["observation_id"]) if latest else
                         (datetime.now(timezone.utc).isoformat(), "0"))
            return (), (), highwater, 0, True, 0
        with self.ledger.store._connection() as db:
            rows = db.execute(
                "SELECT observation_id,source_ref,surface_key,observed_at "
                "FROM bootstrap_observations WHERE target_id=? "
                "AND source='COLD_START_JS' AND code='JS_ACQUIRED' "
                "AND (observed_at,observation_id)>(?,?) "
                "ORDER BY observed_at,observation_id LIMIT ?",
                (target_id, checkpoint_at, state["last_bootstrap_id"] or "0",
                 _COLD_PAGE + 1)).fetchall()
        batch, backlog = rows[:_COLD_PAGE], int(len(rows) > _COLD_PAGE)
        highwater = ((batch[-1]["observed_at"], batch[-1]["observation_id"])
                     if batch else None)
        signals = []
        observations = []
        for row in batch:
            if not row["source_ref"] or self.dom_assets is None or self.traffic is None:
                raise ColdStartSourceError("Cold-start JS provenance is unavailable")
            try:
                asset = self.dom_assets.get_asset(target_id, row["source_ref"])
                exchange = (self.traffic.get_exchange(asset.retrieval_exchange_id)
                            if asset and asset.retrieval_exchange_id else None)
                url = exchange.request.record.url if exchange else None
                if (asset is None or exchange is None or exchange.target_id != target_id or
                        url is None or asset.asset_url_sha256 != row["surface_key"] or
                        hashlib.sha256(url.encode()).hexdigest() != asset.asset_url_sha256):
                    raise ColdStartSourceError("Cold-start JS provenance changed")
                if package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
                    continue
                key = "js_asset:" + asset.asset_url_sha256
                previous = self.ledger.observation(target_id, DeltaSource.COLD_START, key)
                old = str(previous["fingerprint"]) if previous else None
                if old == asset.artifact_sha256:
                    continue
                old_semantic = (str(previous["semantic_hash"]) if previous and
                                previous["semantic_hash"] else None)
                current_semantic = None
                tags: tuple[str, ...] = ()
                try:
                    body = self.ledger.store.artifacts.get_bytes(
                        asset.artifact_sha256, max_bytes=1_048_576)
                    new_info = js_semantics(body)
                    current_semantic = new_info.fingerprint
                    tags = new_asset_signals(new_info)
                    if previous and previous["artifact_id"]:
                        prior = self.dom_assets.get_asset(
                            target_id, str(previous["artifact_id"]))
                        if prior:
                            old_body = self.ledger.store.artifacts.get_bytes(
                                prior.artifact_sha256, max_bytes=1_048_576)
                            tags = semantic_additions(js_semantics(old_body), new_info)
                except (OSError, ValueError):
                    current_semantic = None
                    tags = ()
                observed = datetime.fromisoformat(row["observed_at"])
                event_type = "js_asset_changed" if old else "new_js_asset"
                event = ReconAssetEvent(1, 1, event_type, "js_asset", 1, url,
                                        "medium", Provenance("bootstrap_observations",
                                        1, observed, "cold_start"),
                                        observed, asset.artifact_sha256)
                signal = self.classifier.classify_recon(
                    package, event, old_fingerprint=old,
                    old_semantic_hash=old_semantic, semantic_hash=current_semantic,
                    semantic_tags=tags)
                if signal is None:
                    continue
                signal = replace(signal, source=DeltaSource.COLD_START,
                                 source_ref="bootstrap_observations:" + row["observation_id"],
                                 entity_id=asset.asset_url_sha256, artifact_id=asset.artifact_id)
                signals.append(signal)
                observations.append((DeltaSource.COLD_START.value, key,
                                     signal.new_fingerprint, signal.semantic_hash,
                                     signal.artifact_id, signal.observed_at))
            except (LookupError, OSError, ValueError) as exc:
                raise ColdStartSourceError("Cold-start JS provenance cannot be read") from exc
        return tuple(signals), tuple(observations), highwater, backlog, False, len(batch)

    def check(self, package: TargetPackage, *, trigger: str = "MANUAL") -> dict[str, object]:
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("Target Package must be tracked")
        state = self.ledger.ensure(package)
        watch_id = self.ledger.begin_watch(package, trigger=trigger)
        try:
            return self._check(package, watch_id, state)
        except ColdStartSourceError:
            self.ledger.fail_watch(package, watch_id, "COLD_START_SOURCE_MISSING")
            return {"watch_id": watch_id, "status": WatchStatus.DEGRADED.value,
                    "error_code": "COLD_START_SOURCE_MISSING"}
        except (ReconQueryError, OSError):
            self.ledger.fail_watch(package, watch_id, "RECON_UNAVAILABLE")
            return {"watch_id": watch_id, "status": WatchStatus.DEGRADED.value,
                    "error_code": "RECON_UNAVAILABLE"}
        except BaseException:
            self.ledger.fail_watch(package, watch_id, "WATCH_FAILED")
            raise

    def _check(self, package: TargetPackage, watch_id: str,
               state: dict[str, object]) -> dict[str, object]:
        cold_signals, cold_observations, cold_highwater, cold_backlog, cold_baseline, cold_count = (
            self._cold_start(package, state))
        if self.recon is None:
            return self.ledger.finish_watch(
                package, watch_id, source=DeltaSource.COLD_START,
                signals=cold_signals, observations=cold_observations,
                bootstrap_highwater=cold_highwater, backlog_min_count=cold_backlog,
                events_scanned=cold_count,
                baseline=cold_baseline)
        target = resolve_recon_target(package, self.recon)
        if target is None or not target.active_in_recon:
            return self.ledger.finish_watch(
                package, watch_id, source=DeltaSource.COLD_START,
                signals=cold_signals, observations=cold_observations,
                bootstrap_highwater=cold_highwater, backlog_min_count=cold_backlog,
                events_scanned=cold_count,
                baseline=cold_baseline)
        domain_id = target.domain_id
        latest = self.recon.list_scan_snapshots(domain_id, limit=1).items
        snapshot_id = latest[0].snapshot_id if latest else None
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if state["last_event_at"] is None and state["backfill_cursor"] is None:
            # First observation is a baseline, not permission to hunt old events.
            return self.ledger.finish_watch(
                package, watch_id, source=DeltaSource.RECON, snapshot_id=snapshot_id,
                signals=cold_signals, observations=cold_observations,
                bootstrap_highwater=cold_highwater,
                backlog_min_count=cold_backlog,
                events_scanned=cold_count,
                event_highwater=(now.replace(tzinfo=timezone.utc).isoformat(), 0),
                baseline=True)
        if state["backfill_cursor"]:
            window_start = _naive(str(state["backfill_window_start"]))
            window_end = _naive(str(state["backfill_window_end"]))
            cursor = str(state["backfill_cursor"])
            highwater = (str(state["backfill_highwater_at"]),
                         int(state["backfill_highwater_id"]))
        else:
            prior = _naive(str(state["last_event_at"]))
            window_start = max(prior - _OVERLAP, now - _MAX_WINDOW)
            window_end = now + _OVERLAP
            cursor = None
            highwater = None
        page = self.recon.list_asset_events(domain_id, window_start, window_end,
                                            limit=_PAGE_SIZE, cursor=cursor)
        if highwater is None:
            first = page.items[0] if page.items else None
            stamp = (first.provenance.observed_at.replace(tzinfo=timezone.utc).isoformat()
                     if first and first.provenance.observed_at else
                     now.replace(tzinfo=timezone.utc).isoformat())
            highwater = (stamp, first.event_id if first else 0)
        signals = list(cold_signals)
        observations = list(cold_observations)
        baseline_at = _naive(str(state["last_event_at"]))
        for event in page.items:
            if event.event_type.startswith("new_") and event.first_seen and \
                    event.first_seen <= baseline_at:
                continue
            key = (f"js_asset:{event.entity_id}" if event.entity_type == "js_asset"
                   and event.entity_id is not None else f"asset_event:{event.event_id}")
            previous = self.ledger.observation(package.target.id, DeltaSource.RECON, key)
            old = str(previous["fingerprint"]) if previous else None
            new_semantic = None
            old_semantic = (str(previous["semantic_hash"]) if previous and
                            previous["semantic_hash"] else None)
            additions: tuple[str, ...] = ()
            artifact_id = None
            if (event.entity_type == "js_asset" and event.content_sha256 and
                    self.dom_assets is not None):
                try:
                    current = self.dom_assets.current_asset(
                        package.target.id, event.location or "", event.content_sha256)
                    if current:
                        artifact_id = current.artifact_id
                        body = self.ledger.store.artifacts.get_bytes(
                            current.artifact_sha256, max_bytes=1_048_576)
                        new_info = js_semantics(body)
                        new_semantic = new_info.fingerprint
                        if event.event_type == "new_js_asset":
                            additions = new_asset_signals(new_info)
                        if previous and previous["artifact_id"]:
                            older = self.dom_assets.get_asset(
                                package.target.id, str(previous["artifact_id"]))
                            if older:
                                old_body = self.ledger.store.artifacts.get_bytes(
                                    older.artifact_sha256, max_bytes=1_048_576)
                                additions = semantic_additions(js_semantics(old_body), new_info)
                except (OSError, ValueError):
                    # Missing/retired local body is unknown; watcher never refetches.
                    new_semantic = None
                    artifact_id = None
                    additions = ()
            signal = self.classifier.classify_recon(package, event, old_fingerprint=old,
                old_semantic_hash=old_semantic, semantic_hash=new_semantic,
                semantic_tags=additions)
            if signal is None:
                continue
            if artifact_id:
                signal = replace(signal, artifact_id=artifact_id)
            signals.append(signal)
            observations.append((DeltaSource.RECON.value, key,
                                 signal.new_fingerprint, signal.semantic_hash,
                                 signal.artifact_id, signal.observed_at))
        backfill = ((page.next_cursor, window_start.isoformat(), window_end.isoformat(),
                     highwater[0], highwater[1]) if page.next_cursor else None)
        return self.ledger.finish_watch(
            package, watch_id, source=DeltaSource.RECON, signals=tuple(signals),
            observations=tuple(observations), snapshot_id=snapshot_id,
            event_highwater=highwater, backfill=backfill,
            bootstrap_highwater=cold_highwater,
            backlog_min_count=(1 if page.next_cursor else 0) + cold_backlog,
            backlog_oldest_at=(page.items[-1].provenance.observed_at.replace(
                tzinfo=timezone.utc).isoformat() if page.next_cursor and page.items and
                page.items[-1].provenance.observed_at else
                str(state["last_bootstrap_at"]) if cold_backlog and
                state["last_bootstrap_at"] else None),
            events_scanned=cold_count + len(page.items))
