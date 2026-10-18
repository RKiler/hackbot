from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hackbot.campaign_models import CampaignLimits, CampaignStatus
from hackbot.bootstrap_store import (BootstrapIdentityPolicy, BootstrapLimits,
                                     BootstrapMode)
from hackbot.config import TargetSettings, load_config
from hackbot.delta_classifier import DeltaClassifier
from hackbot.delta_coordinator import DeltaCoordinator
from hackbot.delta_hypotheses import DeltaHypothesisBuilder
from hackbot.delta_models import (ContinuousSettings, DeltaFocus, DeltaSource, DeltaStatus,
                                  DeltaType, WatchStatus)
from hackbot.delta_scheduler import DeltaScheduler
from hackbot.delta_semantics import js_semantics, new_asset_signals, semantic_additions
from hackbot.delta_store import DeltaStore
from hackbot.delta_watcher import DeltaWatcher
from hackbot.evidence import EvidenceProvenance, EvidenceType
from hackbot.evidence_refs import has_evidence_reference
from hackbot.recon import Page, Provenance, ReconAssetEvent, ReconScanSnapshot, ReconTarget
from hackbot.recon_postgres import ReconQueryError
from hackbot.service import BugHunterRuntime, create_app
from hackbot.planner_models import PlannerMode, Specialist
from hackbot.policy import policy_version
from hackbot.resources import ResourceError
from hackbot.target_scope import HostRule


EXAMPLE = Path(__file__).parent / "examples/targets/example"
NOW = datetime(2026, 10, 18, 12, 0, 0)


class Phase32DeltaTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        shutil.copytree(EXAMPLE, root / "targets/example")
        base = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                    "XDG_STATE_HOME": str(root)})
        self.runtime = BugHunterRuntime(replace(base, targets=TargetSettings(root / "targets")),
                                        driver=SimpleNamespace(name="FAKE"), vnc_ready=lambda: False)
        self.package = self.runtime.package("example")
        self.runtime.registry.register_target(self.package)
        self.ledger = DeltaStore(self.runtime.store)
        self.classifier = DeltaClassifier()

    def event(self, event_type="new_endpoint", location="https://app.example.test/admin/roles",
              digest=None):
        return ReconAssetEvent(101, 7, event_type,
                               "js_asset" if "js" in event_type else "endpoint", 42,
                               location, "medium",
                               Provenance("asset_events", 101, NOW, "recon_event"),
                               NOW, digest)

    def test_default_disabled_and_idempotent_target(self):
        first = self.ledger.ensure(self.package)
        second = self.ledger.ensure(self.package)
        self.assertEqual(first, second)
        self.assertFalse(first["enabled"])
        self.assertEqual(first["status"], WatchStatus.DISABLED.value)
        self.assertEqual(self.ledger.due_targets(), ())
        self.assertEqual(len(first["settings"]["allowed_specialists"]), 5)

    def test_scope_and_sensitive_display(self):
        self.assertIsNone(self.classifier.classify_recon(
            self.package, self.event(location="https://outsider.example/admin")))
        signal = self.classifier.classify_recon(
            self.package, self.event(location="https://app.example.test/admin/12345678901?token=secret"))
        self.assertIsNotNone(signal)
        self.assertIn("{id}", signal.display_location)
        self.assertNotIn("secret", signal.display_location)
        self.assertGreaterEqual(signal.relevance, 60)
        short_token = self.classifier.classify_recon(
            self.package, self.event(location="https://app.example.test/admin/abc123"))
        self.assertEqual(short_token.display_location, "app.example.test/admin/{id}")

    def test_bare_subdomain_is_low_priority_and_never_a_live_host_claim(self):
        event = replace(self.event("new_subdomain", "dev.example.test"),
                        entity_type="subdomain")
        signal = self.classifier.classify_recon(self.package, event)
        self.assertEqual(signal.delta_type, DeltaType.NEW_HOST)
        self.assertIn("UNVERIFIED_HOST", signal.signal_tags)
        self.assertLess(signal.relevance, ContinuousSettings().minimum_relevance)
        self.assertEqual(signal.specialist_hints, ())
        self.assertIsNone(self.classifier.classify_recon(
            self.package, replace(event, location="dev.example.test@evil.test")))
        self.assertIsNone(self.classifier.classify_recon(
            self.package, replace(event, location="dev.outside.test")))

    def test_unchanged_semantics_suppressed(self):
        signal = self.classifier.classify_recon(
            self.package, self.event("js_asset_changed",
                                     "https://app.example.test/static/app.js", "b" * 64),
            old_fingerprint="a" * 64,
            old_semantic_hash="c" * 64, semantic_hash="c" * 64)
        self.assertEqual(signal.delta_type, DeltaType.CHANGED_JS_HASH)
        self.assertEqual(signal.relevance, 0)
        self.assertEqual(signal.reason_code, "SEMANTIC_UNCHANGED")

    def test_bounded_js_semantics_catches_messaging_and_config_changes(self):
        old = js_semantics(b"window.addEventListener('message', e => use(e.data));")
        changed = js_semantics(
            b"window.addEventListener('message', e => { if (e.origin) use(e.data); });"
            b"new MessageChannel(); decodeURIComponent(value); // sourceMappingURL=app.js.map\n"
            b"const client_secret = 'fixture-only';")
        self.assertNotEqual(old.fingerprint, changed.fingerprint)
        self.assertIn("MESSAGE_ORIGIN_REFERENCE_CHANGED", semantic_additions(old, changed))
        self.assertIn("MESSAGE_CHANNEL_ADDED", semantic_additions(old, changed))
        self.assertIn("DOM_TRANSFORM_ADDED", semantic_additions(old, changed))
        self.assertIn("SOURCE_MAP_ADDED", semantic_additions(old, changed))
        self.assertIn("CONFIG_PATTERN_ADDED", semantic_additions(old, changed))
        self.assertIn("HAS_CONFIG_PATTERN", new_asset_signals(changed))
        self.assertEqual(js_semantics(b"const x=1; window.addEventListener('message',e=>use(e.data));")
                         .fingerprint,
                         js_semantics(b"const x=2; window.addEventListener('message',e=>use(e.data));")
                         .fingerprint)

    def test_new_security_signal_after_signature_free_bundle_is_reviewable(self):
        old = js_semantics(b"const build = 1;")
        new = js_semantics(b'const op="mutation UpdateUser { updateUser(id:1) { id } }";')
        self.assertIsNone(old.fingerprint)
        tags = semantic_additions(old, new)
        self.assertIn("HAS_GRAPHQL_OPERATION", tags)
        signal = self.classifier.classify_recon(
            self.package, self.event("js_asset_changed",
                                     "https://app.example.test/static/app.js", "b" * 64),
            old_fingerprint="a" * 64, semantic_hash=new.fingerprint,
            semantic_tags=tags)
        self.assertEqual(signal.reason_code, "CLASSIFIED")
        self.assertIn(Specialist.API_GRAPHQL, signal.specialist_hints)
        self.assertGreaterEqual(signal.relevance, 70)

    def test_unknown_prior_hash_is_deferred(self):
        signal = self.classifier.classify_recon(
            self.package, self.event("js_asset_changed",
                                     "https://app.example.test/static/app.js", "b" * 64))
        self.assertEqual(signal.reason_code, "SEMANTIC_UNKNOWN")
        self.ledger.ensure(self.package)
        watch = self.ledger.begin_watch(self.package)
        result = self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                          signals=(signal,))
        self.assertEqual(result["candidates_created"], 1)
        item = self.ledger.list_candidates(target_id=self.package.target.id)[0]
        self.assertEqual(item["status"], DeltaStatus.DEFERRED.value)
        self.assertEqual(item["old_fingerprint"], None)

    def test_duplicate_event_and_restart_do_not_duplicate_candidate(self):
        signal = self.classifier.classify_recon(self.package, self.event())
        self.ledger.ensure(self.package)
        first = self.ledger.begin_watch(self.package)
        self.ledger.finish_watch(self.package, first, source=DeltaSource.RECON,
                                 signals=(signal,))
        second = self.ledger.begin_watch(self.package)
        result = self.ledger.finish_watch(self.package, second, source=DeltaSource.RECON,
                                          signals=(signal,))
        self.assertEqual(result["candidates_created"], 0)
        self.assertEqual(len(self.ledger.list_candidates(target_id=self.package.target.id)), 1)

    def test_delta_page_uses_bounded_filter_bound_cursor(self):
        self.ledger.ensure(self.package)
        signals = tuple(self.classifier.classify_recon(
            self.package, self.event(location=f"https://app.example.test/admin/item{i}"))
            for i in range(3))
        watch = self.ledger.begin_watch(self.package)
        self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                 signals=signals)
        first = self.ledger.page_candidates(target_id=self.package.target.id, limit=1)
        self.assertEqual(len(first["items"]), 1)
        self.assertIsNotNone(first["next_cursor"])
        second = self.ledger.page_candidates(target_id=self.package.target.id, limit=1,
                                             before=first["next_cursor"])
        self.assertNotEqual(first["items"][0]["delta_id"], second["items"][0]["delta_id"])
        with self.assertRaises(ValueError):
            self.ledger.page_candidates(target_id="another-target", limit=1,
                                        before=first["next_cursor"])
        with self.assertRaises(ValueError):
            self.ledger.page_candidates(target_id=self.package.target.id,
                                        status=DeltaStatus.IGNORED, limit=1,
                                        before=first["next_cursor"])

    def test_passive_delta_evidence_is_redacted_and_idempotent(self):
        signal = self.classifier.classify_recon(self.package, self.event())
        self.ledger.ensure(self.package)
        watch = self.ledger.begin_watch(self.package)
        self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                 signals=(signal,))
        delta_id = self.ledger.unmaterialized_candidates(self.package.target.id)[0]
        builder = DeltaHypothesisBuilder(self.ledger, self.runtime.hypotheses)
        first = builder.ensure_evidence(self.package, delta_id)
        self.assertEqual(first, builder.ensure_evidence(self.package, delta_id))
        self.assertEqual(self.ledger.get_candidate(self.package.target.id,
                                                   delta_id)["evidence_id"], first)
        self.assertEqual(self.ledger.unmaterialized_candidates(self.package.target.id), ())
        self.assertEqual(self.ledger.hypothesis_ids(self.package.target.id, delta_id), ())
        with self.runtime.store._connection() as db:
            self.assertTrue(has_evidence_reference(db, first))
            self.assertIsNotNone(db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='trigger' "
                "AND name='delta_candidate_evidence_no_retirement'").fetchone())

    def test_invalid_observation_rolls_back_checkpoint(self):
        self.ledger.ensure(self.package)
        watch = self.ledger.begin_watch(self.package)
        with self.assertRaises(ValueError):
            self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                     snapshot_id=999, observations=(("RECON", "bad?key",
                                     "a" * 64, None, None, NOW.isoformat()),))
        state = self.ledger.get(self.package.target.id)
        self.assertIsNone(state["last_snapshot_id"])
        self.assertEqual(state["status"], WatchStatus.RUNNING.value)
        self.ledger.fail_watch(self.package, watch, "INVALID_SOURCE")
        with self.assertRaises(ValueError):
            self.ledger.fail_watch(self.package, watch, "INVALID_SOURCE")

    def test_watcher_baseline_then_new_endpoint_and_repeat(self):
        class FakeRecon:
            events = ()
            fail = False
            def resolve_target(self, _domain):
                if self.fail:
                    raise ReconQueryError("offline")
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, NOW, "fixture"))
            def list_scan_snapshots(self, _domain_id, *, limit):
                self_outer.assertEqual(limit, 1)
                return Page((ReconScanSnapshot(99, 7, NOW, NOW, False,
                             Provenance("scan_snapshots", 99, NOW, "fixture")),), None)
            def list_asset_events(self, _domain_id, _start, _end, *, limit, cursor=None):
                self_outer.assertEqual(limit, 100)
                self_outer.assertIsNone(cursor)
                return Page(self.events, None)
        self_outer = self
        recon = FakeRecon()
        watcher = DeltaWatcher(self.ledger, recon)
        baseline = watcher.check(self.package)
        self.assertTrue(baseline["baseline"])
        self.assertEqual(baseline["candidates_created"], 0)
        after = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=1)
        recon.events = (ReconAssetEvent(102, 7, "new_endpoint", "endpoint", 53,
                         "https://app.example.test/admin/roles", "medium",
                         Provenance("asset_events", 102, after, "fixture"), after),)
        result = watcher.check(self.package)
        self.assertEqual(result["candidates_created"], 1)
        repeat = watcher.check(self.package)
        self.assertEqual(repeat["candidates_created"], 0)
        self.assertEqual(len(self.ledger.list_candidates(target_id=self.package.target.id)), 1)
        checkpoint = self.ledger.get(self.package.target.id)["last_event_at"]
        recon.fail = True
        offline = watcher.check(self.package)
        self.assertEqual(offline["status"], "DEGRADED")
        self.assertEqual(self.ledger.get(self.package.target.id)["last_event_at"], checkpoint)

    def test_watcher_persists_backlog_cursor_until_second_page(self):
        class FakeRecon:
            def resolve_target(self, _domain):
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, NOW, "fixture"))
            def list_scan_snapshots(self, _domain_id, *, limit):
                return Page((), None)
            def list_asset_events(self, _domain_id, _start, _end, *, limit, cursor=None):
                if cursor is None:
                    return Page((event1,), "cursor-next")
                self_outer.assertEqual(cursor, "cursor-next")
                return Page((event2,), None)
        self_outer = self
        self.ledger.ensure(self.package)
        baseline_watch = self.ledger.begin_watch(self.package)
        self.ledger.finish_watch(self.package, baseline_watch, source=DeltaSource.RECON,
                                 event_highwater=((datetime.now(timezone.utc) -
                                                   timedelta(hours=1)).isoformat(), 0),
                                 baseline=True)
        seen = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=1)
        event1 = ReconAssetEvent(301, 7, "new_endpoint", "endpoint", 301,
                  "https://app.example.test/admin/roles", "high",
                  Provenance("asset_events", 301, seen, "fixture"), seen)
        event2 = ReconAssetEvent(300, 7, "new_endpoint", "endpoint", 300,
                  "https://app.example.test/reports/export", "high",
                  Provenance("asset_events", 300, seen - timedelta(seconds=1), "fixture"),
                  seen - timedelta(seconds=1))
        watcher = DeltaWatcher(self.ledger, FakeRecon())
        first = watcher.check(self.package)
        self.assertEqual(first["events_scanned"], 1)
        self.assertEqual(first["backlog_min_count"], 1)
        state = self.ledger.get(self.package.target.id)
        self.assertEqual(state["backfill_cursor"], "cursor-next")
        self.assertEqual(state["last_event_id"], 0)
        self.assertIsNotNone(state["backlog_oldest_at"])
        second = watcher.check(self.package)
        self.assertEqual(second["events_scanned"], 1)
        self.assertEqual(second["backlog_min_count"], 0)
        state = self.ledger.get(self.package.target.id)
        self.assertIsNone(state["backfill_cursor"])
        self.assertIsNone(state["backlog_oldest_at"])
        self.assertEqual(state["last_event_id"], 301)
        self.assertEqual(len(self.ledger.list_candidates(target_id=self.package.target.id)), 2)
        stats = self.ledger.stats()
        self.assertEqual(stats["events_scanned"], 2)
        self.assertEqual(stats["classified_deltas"], 2)
        self.assertIsNotNone(stats["mean_time_to_detection_seconds"])
        self.assertIsNone(stats["backlog_age_seconds"])

    def test_hypotheses_are_passive_linked_and_idempotent(self):
        signal = self.classifier.classify_recon(
            self.package, self.event(location="https://app.example.test/admin/reports/export"))
        self.ledger.ensure(self.package)
        watch = self.ledger.begin_watch(self.package)
        self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                 signals=(signal,))
        candidate = self.ledger.list_candidates(target_id=self.package.target.id)[0]
        builder = DeltaHypothesisBuilder(self.ledger, self.runtime.hypotheses)
        first = builder.materialize(self.package, candidate["delta_id"])
        second = builder.materialize(self.package, candidate["delta_id"])
        self.assertEqual(first, second)
        self.assertEqual(len(first), 2)
        self.assertEqual(set(first), set(self.ledger.hypothesis_ids(
            self.package.target.id, candidate["delta_id"])))
        linked = self.ledger.get_candidate(self.package.target.id, candidate["delta_id"])
        self.assertIsNotNone(linked["evidence_id"])
        for hypothesis_id in first:
            item = self.runtime.hypotheses.get(hypothesis_id, self.package.target.id)
            self.assertEqual(item.evidence_ids, (linked["evidence_id"],))
            self.assertEqual(item.status.value, "NEW")

    def test_automatic_campaign_is_exactly_focused_and_bounded(self):
        location = "https://app.example.test/admin/reports/export"
        signal = self.classifier.classify_recon(self.package, self.event(location=location))
        self.ledger.configure(self.package, ContinuousSettings(enabled=True,
                              daily_campaign_cap=1, request_cap=12))
        watch = self.ledger.begin_watch(self.package)
        self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                 signals=(signal,))
        candidate = self.ledger.list_candidates(target_id=self.package.target.id)[0]
        hypothesis_ids = DeltaHypothesisBuilder(
            self.ledger, self.runtime.hypotheses).materialize(
                self.package, candidate["delta_id"])
        unrelated = self.runtime.hypotheses.add_manual(
            self.package.target.id, "ROLE_AUTHORIZATION", "Unrelated test route",
            "Check an unrelated owned route")
        focus = DeltaFocus((candidate["delta_id"],), hypothesis_ids,
                           tuple(Specialist(item) for item in candidate["specialist_hints"]),
                           candidate["location_hash"], location, automatic=True)
        limits = CampaignLimits(max_cycles=1, seconds=300, requests=12,
                                browser_actions=4, research_requests=0,
                                tokens=500, setup_objects=0, cleanup_reserve=0)
        with patch.object(self.runtime.resources, "admit", return_value=None), \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target request")):
            campaign = self.runtime.campaign.start(
                self.package, mode=PlannerMode.ANALYZE_ONLY, limits=limits,
                requested_by="delta", focus=focus)
            stored = self.runtime.campaign.store.delta_focus(
                self.package.target.id, campaign.id)
            self.assertEqual(set(stored["hypothesis_ids"]), set(hypothesis_ids))
            self.assertNotIn("scope_url", stored)
            for _ in range(5):
                campaign = self.runtime.campaign.advance(self.package, campaign.id)
                if campaign.status is CampaignStatus.COMPLETED:
                    break
        self.assertEqual(campaign.status, CampaignStatus.COMPLETED)
        works = self.runtime.campaign.store.works(self.package.target.id, campaign.id)
        self.assertEqual(len(works), 1)
        self.assertEqual(works[0].kind.value, "PLANNER")
        planner = self.runtime.planner_store.get(self.package.target.id, works[0].child_id)
        selected = self.runtime.planner_store.candidates(self.package.target.id, planner.id)
        self.assertTrue(selected)
        self.assertTrue(all(item.hypothesis_id in hypothesis_ids for item in selected))
        self.assertNotIn(unrelated.id, {item.hypothesis_id for item in selected})
        self.assertEqual(self.ledger.get_candidate(
            self.package.target.id, candidate["delta_id"])["campaign_id"], campaign.id)

    def test_focused_campaign_rejects_scope_change_atomically(self):
        location = "https://app.example.test/admin/reports/export"
        signal = self.classifier.classify_recon(self.package, self.event(location=location))
        self.ledger.ensure(self.package)
        watch = self.ledger.begin_watch(self.package)
        self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                 signals=(signal,))
        candidate = self.ledger.list_candidates(target_id=self.package.target.id)[0]
        hypothesis_ids = DeltaHypothesisBuilder(self.ledger, self.runtime.hypotheses).materialize(
            self.package, candidate["delta_id"])
        focus = DeltaFocus((candidate["delta_id"],), hypothesis_ids,
                           tuple(Specialist(item) for item in candidate["specialist_hints"]),
                           candidate["location_hash"], location)
        changed = replace(self.package, scope=replace(self.package.scope,
                          exclude_hosts=(*self.package.scope.exclude_hosts,
                                         HostRule("app.example.test"),)))
        with self.assertRaisesRegex(ValueError, "in-scope"):
            self.runtime.campaign.store.create(changed, PlannerMode.ANALYZE_ONLY,
                CampaignLimits(), policy_version(changed), "operator", focus=focus)
        self.assertEqual(self.runtime.campaign.store.list(target_id=self.package.target.id), ())

    def test_coordinator_launches_one_focused_campaign_and_never_repeats_it(self):
        event = self.event(location="https://app.example.test/admin/reports/export")
        signal = self.classifier.classify_recon(self.package, event)
        self.ledger.configure(self.package, ContinuousSettings(enabled=True,
                              daily_campaign_cap=1))
        watch = self.ledger.begin_watch(self.package)
        self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                 signals=(signal,))

        class Recon:
            def resolve_target(self, _domain):
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, NOW, "fixture"))
            def get_asset_event(self, domain_id, event_id):
                self_outer.assertEqual((domain_id, event_id), (7, 101))
                return event
        self_outer = self
        coordinator = DeltaCoordinator(self.runtime, recon=Recon())
        with patch.object(self.runtime.resources, "admit", return_value=None), \
             patch.object(self.runtime, "launch_campaign") as launch, \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target request")):
            first = coordinator.process_one(self.package)
            second = coordinator.process_one(self.package)
        self.assertEqual(first["status"], "CAMPAIGN_STARTED")
        self.assertEqual(second["status"], "NO_ELIGIBLE_DELTA")
        launch.assert_called_once()
        self.assertEqual(len(self.runtime.campaign.store.list(
            target_id=self.package.target.id)), 1)
        self.assertEqual(self.ledger.get_candidate(self.package.target.id,
            first["delta_id"])["campaign_id"], first["campaign_id"])

    def test_coordinator_defers_under_resource_pressure_without_campaign(self):
        event = self.event(location="https://app.example.test/admin/reports/export")
        signal = self.classifier.classify_recon(self.package, event)
        self.ledger.configure(self.package, ContinuousSettings(enabled=True))
        watch = self.ledger.begin_watch(self.package)
        self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                 signals=(signal,))
        class Recon:
            def resolve_target(self, _domain):
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, NOW, "fixture"))
            def get_asset_event(self, _domain_id, _event_id):
                return event
        with patch.object(self.runtime.resources, "admit",
                          side_effect=ResourceError("LOAD_HIGH")):
            result = DeltaCoordinator(self.runtime, recon=Recon()).process_one(self.package)
        self.assertEqual(result["status"], "RESOURCE_DEFERRED")
        self.assertEqual(self.runtime.campaign.store.list(target_id=self.package.target.id), ())

    def test_coordinator_blocks_scope_removed_before_launch(self):
        event = self.event(location="https://app.example.test/admin/reports/export")
        signal = self.classifier.classify_recon(self.package, event)
        self.ledger.configure(self.package, ContinuousSettings(enabled=True))
        watch = self.ledger.begin_watch(self.package)
        self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                 signals=(signal,))
        class Recon:
            def resolve_target(self, _domain):
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, NOW, "fixture"))
            def get_asset_event(self, _domain_id, _event_id):
                return event
        changed = replace(self.package, scope=replace(self.package.scope,
                          exclude_hosts=(*self.package.scope.exclude_hosts,
                                         HostRule("app.example.test"),)))
        result = DeltaCoordinator(self.runtime, recon=Recon()).process_one(changed)
        self.assertEqual(result["status"], "NO_ELIGIBLE_DELTA")
        self.assertEqual(self.ledger.list_candidates(target_id=self.package.target.id)[0]
                         ["status"], DeltaStatus.BLOCKED.value)
        self.assertEqual(self.runtime.campaign.store.list(target_id=self.package.target.id), ())

    def test_manual_delta_campaign_is_focused_and_needs_no_continuous_opt_in(self):
        event = self.event(location="https://app.example.test/admin/members")
        signal = self.classifier.classify_recon(self.package, event)
        self.ledger.ensure(self.package)
        watch = self.ledger.begin_watch(self.package)
        self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                 signals=(signal,))
        delta_id = self.ledger.list_candidates(target_id=self.package.target.id)[0]["delta_id"]

        class Recon:
            def resolve_target(self, _domain):
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, NOW, "fixture"))
            def get_asset_event(self, _domain_id, _event_id):
                return event

        coordinator = DeltaCoordinator(self.runtime, recon=Recon())
        with patch.object(self.runtime.resources, "admit", return_value=None), \
             patch.object(self.runtime, "launch_campaign") as launch:
            result = coordinator.start_selected(self.package, delta_id,
                                                mode=PlannerMode.PLAN_ONLY)
        self.assertEqual(result["status"], "CAMPAIGN_STARTED")
        launch.assert_called_once()
        campaign = self.runtime.campaign.store.get(self.package.target.id,
                                                   result["campaign_id"])
        self.assertEqual(campaign.mode, PlannerMode.PLAN_ONLY)
        self.assertEqual(campaign.limits.max_cycles, 1)
        self.assertEqual(self.runtime.campaign.store.delta_focus(
            self.package.target.id, campaign.id)["delta_ids"], (delta_id,))
        self.assertFalse(self.runtime.campaign.store.delta_focus(
            self.package.target.id, campaign.id)["automatic"])
        self.assertEqual(self.ledger.get_candidate(self.package.target.id,
                                                   delta_id)["status"], "CAMPAIGN_STARTED")

    def test_scheduler_persists_cadence_pause_and_resume(self):
        class Recon:
            def resolve_target(self, _domain):
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, NOW, "fixture"))
            def list_scan_snapshots(self, _domain_id, *, limit):
                return Page((), None)
        self.ledger.configure(self.package, ContinuousSettings(enabled=True))
        coordinator = DeltaCoordinator(self.runtime, recon=Recon())
        scheduler = DeltaScheduler(self.runtime, coordinator)
        with patch.object(self.runtime, "launch_campaign",
                          side_effect=AssertionError("unexpected campaign")):
            result = scheduler.tick()
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["watch"]["baseline"])
        self.assertEqual(result[0]["campaign"]["status"], "NO_ELIGIBLE_DELTA")
        self.assertEqual(scheduler.tick(), ())
        persisted = DeltaStore(self.runtime.store).get(self.package.target.id)
        self.assertIsNotNone(persisted["next_check_at"])
        self.assertEqual(persisted["status"], "IDLE")
        self.assertEqual(self.ledger.pause(self.package)["status"], "PAUSED")
        self.assertEqual(self.ledger.due_targets(), ())
        self.assertEqual(self.ledger.resume(self.package)["status"], "PENDING")
        self.assertEqual(self.ledger.due_targets(), (self.package.target.id,))

    def test_scheduler_does_not_degrade_concurrent_manual_watch(self):
        self.ledger.configure(self.package, ContinuousSettings(enabled=True))
        coordinator = DeltaCoordinator(self.runtime, recon=None)
        scheduler = DeltaScheduler(self.runtime, coordinator)

        def overlapping_check(_package, *, trigger):
            self.assertEqual(trigger, "SCHEDULED")
            self.ledger.begin_watch(self.package, trigger="MANUAL")
            raise ValueError("Watch already running")

        with patch.object(coordinator, "check", side_effect=overlapping_check):
            result = scheduler.tick()
        self.assertEqual(result, ({"target_id": self.package.target.id,
                                   "status": "WATCH_IN_PROGRESS"},))
        self.assertEqual(self.ledger.get(self.package.target.id)["status"], "RUNNING")

    def test_interrupted_watch_recovers_without_advancing_checkpoint(self):
        self.ledger.configure(self.package, ContinuousSettings(enabled=True))
        watch_id = self.ledger.begin_watch(self.package, trigger="SCHEDULED")
        before = self.ledger.get(self.package.target.id)
        recovered = DeltaStore(self.runtime.store).reconcile_interrupted()
        self.assertEqual(recovered, 1)
        self.assertEqual(DeltaStore(self.runtime.store).reconcile_interrupted(), 0)
        after = self.ledger.get(self.package.target.id)
        self.assertEqual(after["status"], "DEGRADED")
        self.assertEqual(after["error_code"], "INTERRUPTED_RESTART")
        self.assertEqual(after["last_event_at"], before["last_event_at"])
        self.assertEqual(after["last_bootstrap_at"], before["last_bootstrap_at"])
        with self.runtime.store._connection() as db:
            run = db.execute("SELECT status,error_code FROM delta_watch_runs "
                             "WHERE watch_id=?", (watch_id,)).fetchone()
        self.assertEqual((run["status"], run["error_code"]),
                         ("DEGRADED", "INTERRUPTED_RESTART"))
        self.assertEqual(self.ledger.due_targets(), (self.package.target.id,))

    def test_daily_cap_blocks_second_automatic_campaign(self):
        first_event = self.event(location="https://app.example.test/admin/reports/export")
        second_event = replace(self.event(
            location="https://app.example.test/admin/members"), event_id=102,
            provenance=Provenance("asset_events", 102, NOW, "fixture"))
        events = {101: first_event, 102: second_event}

        class Recon:
            def resolve_target(self, _domain):
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, NOW, "fixture"))
            def get_asset_event(self, _domain_id, event_id):
                return events[event_id]

        self.ledger.configure(self.package, ContinuousSettings(enabled=True,
                              daily_campaign_cap=1))
        coordinator = DeltaCoordinator(self.runtime, recon=Recon())
        with patch.object(self.runtime.resources, "admit", return_value=None), \
             patch.object(self.runtime, "launch_campaign"):
            for event in (first_event, second_event):
                watch = self.ledger.begin_watch(self.package)
                signal = self.classifier.classify_recon(self.package, event)
                self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                         signals=(signal,))
                result = coordinator.process_one(self.package)
                if event is first_event:
                    self.assertEqual(result["status"], "CAMPAIGN_STARTED")
                    self.runtime.campaign.store.transition(
                        self.package.target.id, result["campaign_id"],
                        CampaignStatus.COMPLETED, "FIXTURE_COMPLETE")
                else:
                    self.assertEqual(result["status"], "ADMISSION_DEFERRED")
                    self.assertIn("Daily", result["reason_code"])
        self.assertEqual(len(self.runtime.campaign.store.list(
            target_id=self.package.target.id)), 1)

    def test_meaningful_js_state_change_resets_cooldown_key(self):
        first = self.event("js_asset_changed",
                           "https://app.example.test/static/app.js", "b" * 64)
        second = replace(first, event_id=102, content_sha256="c" * 64,
                         provenance=Provenance("asset_events", 102, NOW, "fixture"))
        events = {101: first, 102: second}

        class Recon:
            def resolve_target(self, _domain):
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, NOW, "fixture"))
            def get_asset_event(self, _domain_id, event_id):
                return events[event_id]

        self.ledger.configure(self.package, ContinuousSettings(enabled=True,
                              daily_campaign_cap=2))
        coordinator = DeltaCoordinator(self.runtime, recon=Recon())
        with patch.object(self.runtime.resources, "admit", return_value=None), \
             patch.object(self.runtime, "launch_campaign"):
            campaigns = []
            for event, old, previous_semantic, semantic, tag in (
                    (first, "a" * 64, "d" * 64, "e" * 64, "MESSAGE_HANDLER_ADDED"),
                    (second, "b" * 64, "e" * 64, "f" * 64, "MESSAGE_CHANNEL_ADDED")):
                signal = self.classifier.classify_recon(
                    self.package, event, old_fingerprint=old,
                    old_semantic_hash=previous_semantic, semantic_hash=semantic,
                    semantic_tags=(tag,))
                watch = self.ledger.begin_watch(self.package)
                self.ledger.finish_watch(self.package, watch, source=DeltaSource.RECON,
                                         signals=(signal,))
                candidate = next(item for item in self.ledger.list_candidates(
                    target_id=self.package.target.id) if item["source_ref"] ==
                    f"asset_events:{event.event_id}")
                result = coordinator.start_selected(self.package, candidate["delta_id"])
                self.assertEqual(result["status"], "CAMPAIGN_STARTED")
                campaigns.append(result["campaign_id"])
                self.runtime.campaign.store.transition(
                    self.package.target.id, result["campaign_id"],
                    CampaignStatus.COMPLETED, "FIXTURE_COMPLETE")
        self.assertEqual(len(set(campaigns)), 2)

    def test_private_delta_api_settings_and_manual_check(self):
        client = create_app(runtime=self.runtime).test_client()
        root = "/v1/continuous/targets/example"
        state = client.get(root).get_json()
        self.assertFalse(state["enabled"])
        response = client.post(root + "/settings", json={
            "enabled": True, "cadence": "DAILY", "minimum_relevance": 85,
            "allowed_specialists": ["AUTHORIZATION", "EXPOSURE"]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["settings"]["cadence"], "DAILY")
        self.assertEqual(client.post(root + "/pause", json={}).get_json()["status"], "PAUSED")
        self.assertEqual(client.post(root + "/resume", json={}).get_json()["status"], "PENDING")
        self.runtime.delta.watcher.recon = None
        checked = client.post(root + "/check", json={}).get_json()
        self.assertEqual(checked["watch"]["status"], "IDLE")
        self.assertEqual(checked["watch"]["source"], "COLD_START")
        self.assertEqual(client.get("/v1/deltas?target=example").get_json()["items"], [])
        self.assertEqual(client.get("/v1/continuous/status").get_json()["enabled_targets"], 1)
        self.assertEqual(client.post(root + "/settings", json={"enabled": False})
                         .get_json()["status"], "DISABLED")

    def test_cold_start_js_then_recon_transition_keeps_one_watcher_identity(self):
        self.ledger.configure(self.package, ContinuousSettings(enabled=True))
        coordinator = DeltaCoordinator(self.runtime)
        coordinator.watcher.recon = None
        baseline = coordinator.check(self.package)
        self.assertTrue(baseline["watch"]["baseline"])

        run = self.runtime.bootstrap_store.create(
            self.package.target.id, self.package.id, BootstrapMode.COLD_START,
            BootstrapIdentityPolicy.ANONYMOUS_ONLY, BootstrapLimits())
        evidence = self.runtime.store.create_evidence(
            EvidenceType.BROWSER_EVENT, b"cold-start fixture", source="fixture",
            provenance=EvidenceProvenance(system="FIXTURE", entity="bootstrap_observation",
                                          record_id=run.bootstrap_id),
            target_ref=self.package.target.id)
        url = "https://app.example.test/static/new.js"
        body = b'window.addEventListener("message", function(event) { return event.data; });'
        artifact = self.runtime.store.artifacts.put_bytes(body)
        asset = SimpleNamespace(artifact_id="JSA-" + "a" * 32,
                                artifact_sha256=artifact.sha256,
                                asset_url_sha256=hashlib.sha256(url.encode()).hexdigest(),
                                retrieval_exchange_id="EX-" + "b" * 32,
                                state="CURRENT")
        with self.runtime.store._connection() as db:
            db.execute("INSERT INTO dom_js_artifacts(artifact_id,target_id,"
                       "asset_url_sha256,artifact_sha256,evidence_id,state,source,"
                       "retrieved_at) VALUES (?,?,?,?,?,?,?,?)",
                       (asset.artifact_id, self.package.target.id,
                        asset.asset_url_sha256, asset.artifact_sha256,
                        evidence.evidence_id, "CURRENT", "FIXTURE",
                        datetime.now(timezone.utc).isoformat()))
        exchange = SimpleNamespace(target_id=self.package.target.id,
                                   request=SimpleNamespace(record=SimpleNamespace(url=url)))
        self.runtime.bootstrap_store.add_observation(
            run.bootstrap_id, self.package.target.id, "COLD_START_JS", "JS_ACQUIRED",
            asset.asset_url_sha256, "app.example.test/static/new.js",
            evidence.evidence_id, asset.artifact_id)
        with patch.object(self.runtime.domxss_store, "get_asset", return_value=asset), \
             patch.object(self.runtime.traffic, "get_exchange", return_value=exchange), \
             patch.object(self.runtime.resources, "admit", return_value=None), \
             patch.object(self.runtime, "launch_campaign") as launch:
            changed = coordinator.check(self.package)
            self.assertEqual(changed["watch"]["candidates_created"], 1)
            self.assertEqual(changed["campaign"]["status"], "CAMPAIGN_STARTED")
            self.assertEqual(coordinator.check(self.package)["watch"]["candidates_created"], 0)
            class Recon:
                def resolve_target(self, _domain):
                    return ReconTarget(7, "example.test", True, True,
                                       Provenance("domains", 7, NOW, "fixture"))
                def list_scan_snapshots(self, _domain_id, *, limit):
                    return Page((), None)
            coordinator.watcher.recon = Recon()
            transitioned = coordinator.check(self.package)
        self.assertTrue(transitioned["watch"]["baseline"])
        self.assertEqual(transitioned["watch"]["candidates_created"], 0)
        self.assertEqual(len(self.ledger.list_candidates(target_id=self.package.target.id)), 1)
        launch.assert_called_once()

    def test_missing_cold_start_artifact_degrades_without_losing_checkpoint(self):
        coordinator = DeltaCoordinator(self.runtime)
        coordinator.watcher.recon = None
        baseline = coordinator.check(self.package)
        self.assertTrue(baseline["watch"]["baseline"])
        before = self.ledger.get(self.package.target.id)
        run = self.runtime.bootstrap_store.create(
            self.package.target.id, self.package.id, BootstrapMode.COLD_START,
            BootstrapIdentityPolicy.ANONYMOUS_ONLY, BootstrapLimits())
        evidence = self.runtime.store.create_evidence(
            EvidenceType.BROWSER_EVENT, b"missing cold-start artifact fixture",
            source="fixture", target_ref=self.package.target.id,
            provenance=EvidenceProvenance(system="FIXTURE", entity="bootstrap_observation",
                                          record_id=run.bootstrap_id))
        self.runtime.bootstrap_store.add_observation(
            run.bootstrap_id, self.package.target.id, "COLD_START_JS", "JS_ACQUIRED",
            "a" * 64, "app.example.test/static/missing.js", evidence.evidence_id,
            "JSA-" + "b" * 32)
        result = coordinator.check(self.package)
        self.assertEqual(result["watch"]["status"], "DEGRADED")
        self.assertEqual(result["watch"]["error_code"], "COLD_START_SOURCE_MISSING")
        after = self.ledger.get(self.package.target.id)
        self.assertEqual(after["last_bootstrap_at"], before["last_bootstrap_at"])
        self.assertEqual(after["last_bootstrap_id"], before["last_bootstrap_id"])
        self.assertEqual(self.ledger.list_candidates(target_id=self.package.target.id), ())

    def test_eight_snapshot_fixture_tracks_meaningful_changes_only(self):
        js_url = "https://app.example.test/static/app.js"
        base = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=1)
        bodies = (
            b'window.addEventListener("message", e => e.data); const build=1;',
            b'window.addEventListener("message", e => e.data); new MessageChannel();',
            b'window.addEventListener("message", e => e.data); new MessageChannel(); const build=2;',
            b'window.addEventListener("message", e => e.data); new MessageChannel(); '
            b'const op="mutation UpdateUser { updateUser(id:1) { id } }";',
            b'window.addEventListener("message", e => e.data); new MessageChannel(); '
            b'const op="mutation UpdateUser { updateUser(id:1) { id } }"; '
            b'window.addEventListener("message", x => x.data);',
        )
        assets_by_hash = {}
        assets_by_id = {}
        for index, body in enumerate(bodies):
            saved = self.runtime.store.artifacts.put_bytes(body)
            asset_id = "JSA-" + format(index + 1, "032x")
            evidence = self.runtime.store.create_evidence(
                EvidenceType.BROWSER_EVENT, b"synthetic JS fixture", source="fixture",
                target_ref=self.package.target.id,
                provenance=EvidenceProvenance(system="FIXTURE", entity="js_asset",
                                              record_id=asset_id))
            with self.runtime.store._connection() as db:
                db.execute("INSERT INTO dom_js_artifacts(artifact_id,target_id,"
                           "asset_url_sha256,artifact_sha256,evidence_id,state,source,"
                           "retrieved_at) VALUES (?,?,?,?,?,?,?,?)",
                           (asset_id, self.package.target.id,
                            hashlib.sha256(js_url.encode()).hexdigest(), saved.sha256,
                            evidence.evidence_id, "CURRENT", "FIXTURE",
                            datetime.now(timezone.utc).isoformat()))
            asset = SimpleNamespace(artifact_id=asset_id, artifact_sha256=saved.sha256)
            assets_by_hash[saved.sha256] = asset
            assets_by_id[asset_id] = asset

        class FakeAssets:
            def current_asset(self, _target_id, _url, digest):
                return assets_by_hash.get(digest)
            def get_asset(self, _target_id, asset_id):
                return assets_by_id.get(asset_id)

        def make_event(event_id, kind, url, digest=None):
            seen = base + timedelta(milliseconds=event_id)
            return ReconAssetEvent(event_id, 7, kind,
                                   "js_asset" if digest else "endpoint",
                                   42 if digest else event_id, url, "medium",
                                   Provenance("asset_events", event_id, seen, "fixture"),
                                   seen, digest)

        stages = {
            1: (), 2: (),
            3: (make_event(104, "new_js_asset", js_url, assets_by_id[
                "JSA-" + format(1, "032x")].artifact_sha256),
                make_event(103, "new_endpoint",
                           "https://app.example.test/admin/roles")),
            4: (make_event(105, "js_asset_changed", js_url, assets_by_id[
                "JSA-" + format(2, "032x")].artifact_sha256),),
            5: (make_event(106, "js_asset_changed", js_url, assets_by_id[
                "JSA-" + format(3, "032x")].artifact_sha256),),
            6: (make_event(107, "js_asset_changed", js_url, assets_by_id[
                "JSA-" + format(4, "032x")].artifact_sha256),),
            7: (make_event(108, "js_asset_changed", js_url, assets_by_id[
                "JSA-" + format(5, "032x")].artifact_sha256),),
            8: (make_event(109, "new_endpoint",
                           "https://app.example.test/reports/export"),),
        }

        class FakeRecon:
            stage = 1
            def resolve_target(self, _domain):
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, NOW, "fixture"))
            def list_scan_snapshots(self, _domain_id, *, limit):
                return Page((ReconScanSnapshot(self.stage, 7, NOW, NOW, False,
                             Provenance("scan_snapshots", self.stage, NOW, "fixture")),),
                            None)
            def list_asset_events(self, _domain_id, _start, _end, *, limit, cursor=None):
                return Page(stages[self.stage], None)

        recon = FakeRecon()
        watcher = DeltaWatcher(self.ledger, recon, dom_assets=FakeAssets())
        baseline = watcher.check(self.package)
        self.assertTrue(baseline["baseline"])
        self.assertEqual(baseline["candidates_created"], 0)
        outcomes = {}
        for stage in range(2, 9):
            recon.stage = stage
            outcomes[stage] = watcher.check(self.package)
        self.assertEqual(outcomes[2]["candidates_created"], 0)
        self.assertEqual(outcomes[3]["candidates_created"], 2)
        self.assertEqual(outcomes[4]["candidates_created"], 1)
        self.assertEqual(outcomes[5]["candidates_created"], 1)
        self.assertEqual(outcomes[6]["candidates_created"], 1)
        self.assertEqual(outcomes[7]["candidates_created"], 1)
        self.assertEqual(outcomes[8]["candidates_created"], 1)
        items = self.ledger.list_candidates(target_id=self.package.target.id, limit=20)
        by_event = {item["source_ref"]: item for item in items}
        self.assertEqual(by_event["asset_events:106"]["status"], "IGNORED")
        self.assertIn("GRAPHQL_OPERATION_ADDED", by_event["asset_events:107"]["signal_tags"])
        self.assertIn("MESSAGE_HANDLER_ADDED", by_event["asset_events:108"]["signal_tags"])
        self.assertIn("EXPOSURE_NAME", by_event["asset_events:109"]["signal_tags"])
        self.assertEqual(watcher.check(self.package)["candidates_created"], 0)


if __name__ == "__main__":
    unittest.main()
