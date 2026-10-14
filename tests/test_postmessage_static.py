"""Phase 22 static messaging triage uses local JavaScript fixtures only."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
import shutil
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from hackbot.artifacts import ArtifactStore
from hackbot.config import StoreSettings
from hackbot.domxss_store import DOMXSSStore
from hackbot.domxss import DOMAcquisition, DOMAcquisitionStatus
from hackbot.domxss_static import DOMStaticAnalyzer
from hackbot.identity_registry import IdentityRegistry
from hackbot.postmessage_static import (ANALYZER_VERSION, MessageAnalysis,
                                       PostMessageStaticAnalyzer, MessageCandidateStatus)
from hackbot.postmessage_store import PostMessageStore
from hackbot.postmessage import PostMessageSpecialist
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package


EXAMPLE = Path(__file__).parent / "examples/targets/example"
TWO_STAGE = b"""
window.addEventListener('message', function(event) {
  if (event.data.type === 'ACTIVATE') {
    const port = event.ports[0];
    port.onmessage = function(packet) {
      if (packet.data.method === 'readSynthetic') {
        port.postMessage({type: 'RESULT', value: syntheticCanary});
      }
    };
    event.source.postMessage({type: 'READY'}, '*');
  }
});
"""
STRICT = b"""
window.addEventListener('message', function(event) {
  if (event.origin !== 'https://trusted.example.test') return;
  if (event.source !== trustedFrame.contentWindow) return;
  if (event.data.type === 'ACTIVATE') event.source.postMessage({type: 'READY'}, event.origin);
});
"""
SUBSTRING = b"""
window.addEventListener('message', function(event) {
  if (!event.origin.includes('example.test')) return;
  if (event.data.type === 'ACTIVATE') event.source.postMessage({type: 'READY'}, '*');
});
"""
WRONG_ORDER = b"""
window.addEventListener('message', function(event) {
  event.source.postMessage({type: 'READY'}, '*');
  if (event.origin !== 'https://trusted.example.test') return;
});
"""
BAD_BRANCH = b"""
window.addEventListener('message', event => {
  if (event.origin !== 'https://trusted.example.test') console.log('different');
  if (event.data.type === 'ACTIVATE') event.source.postMessage({type:'READY'}, '*');
});
"""
POSITIVE_GUARD = b"""
window.addEventListener('message', event => {
  if (event.origin === 'https://trusted.example.test') {
    event.source.postMessage({type:'READY'}, '*');
  }
});
"""
UNRELATED_GUARD = b"""
window.addEventListener('message', event => {
  if (event.origin === 'https://trusted.example.test') console.log('trusted');
  event.source.postMessage({type:'READY'}, '*');
});
"""
COMPOSITE_GUARD = b"""
window.addEventListener('message', event => {
  if (event.origin !== 'https://trusted.example.test' &&
      event.source !== trustedFrame.contentWindow) return;
  event.source.postMessage({type:'READY'}, '*');
});
"""
OR_REJECT_GUARD = b"""
window.addEventListener('message', event => {
  if (!event.origin.includes('example.test') || event.data.type !== 'ACTIVATE') return;
  event.source.postMessage({type:'READY'}, '*');
});
"""
NULL_ORIGIN = b"""
window.addEventListener('message', event => {
  if (event.origin !== 'null') return;
  event.source.postMessage({type:'READY'}, '*');
});
"""
PARENT_ASSUMED = b"""
window.addEventListener('message', function(event) {
  const parentWindow = window.parent;
  if (event.origin !== location.origin) return;
  if (event.data.type === 'ACTIVATE' && event.ports[0]) {
    const port = event.ports[0];
    port.onmessage = packet => port.postMessage({type:'RESULT',value:syntheticCanary});
  }
});
"""
MESSAGE_HTML = b"""
window.addEventListener('message', function(event) {
  if (event.data.type === 'PREVIEW') {
    const html = event.data.html;
    document.body.innerHTML = html;
  }
});
"""
WORKER_CHANNELS = b"""
const worker = new Worker('/worker.js');
worker.onmessage = event => {
  if (event.data.type === 'RESULT') document.body.innerHTML = event.data.value;
};
worker.postMessage({type:'START'});
const shared = new SharedWorker('/shared.js');
shared.port.addEventListener('message', event => {
  if (event.data.type === 'READY') document.body.textContent = event.data.value;
});
const channel = new BroadcastChannel('updates');
channel.onmessage = event => {
  if (event.data.type === 'NOTICE') document.body.textContent = event.data.value;
};
channel.postMessage({type:'PING'});
"""
INDIRECT_LISTENER = b"""
const ACTIVATE = 'ACTIVATE';
const READY = 'READY';
function receive(event) {
  if (event.data.type === ACTIVATE) {
    event.source.postMessage({type: READY}, '*');
  }
}
"""
HANDLER_MAP = b"""
window.addEventListener('message', event => {
  const handlers = {
    readSynthetic(packet) { return document.body.textContent; },
    setPreview(packet) { document.body.textContent = packet.value; return 'done'; }
  };
  if (event.data.type === 'RPC') {
    const result = handlers[event.data.method](event.data);
    event.source.postMessage({type: 'RESULT', result}, '*');
  }
});
"""


@unittest.skipUnless(shutil.which("node"), "Node/Babel parser unavailable")
class PostMessageStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = PostMessageStaticAnalyzer()

    def analyze(self, body: bytes):
        return self.analyzer.analyze(target_id="TARGET-fixture", artifact_id="ASSET-fixture",
                                     body=body, evidence_id="EV-fixture")

    def test_two_stage_port_rpc_is_candidate_not_a_finding(self) -> None:
        result = self.analyze(TWO_STAGE)
        self.assertEqual(result.status, "ANALYZED")
        item = next(part for part in result.candidates if "ACTIVATE" in part.message_types)
        self.assertTrue(item.port_accepted)
        self.assertTrue(item.port_bound)
        self.assertIn("readSynthetic", item.rpc_methods)
        self.assertIn("type", item.payload_fields)
        self.assertEqual(item.rpc_details[0].name, "readSynthetic")
        self.assertEqual(item.rpc_details[0].result_shape, "OBJECT")
        self.assertEqual(item.rpc_details[0].capability, "READ")
        self.assertIn("REPLY:READY", item.protocol_sequence)
        self.assertEqual(item.origin_validation, "MISSING")
        self.assertEqual(item.status, MessageCandidateStatus.STATIC_CANDIDATE)
        self.assertGreaterEqual(item.priority, 75)

    def test_origin_and_source_checks_and_weak_origin(self) -> None:
        strict = self.analyze(STRICT).candidates[0]
        weak = self.analyze(SUBSTRING).candidates[0]
        self.assertEqual(strict.origin_validation, "EXACT")
        self.assertEqual(strict.source_validation, "IDENTITY")
        self.assertEqual(weak.origin_validation, "SUBSTRING")
        self.assertGreater(weak.priority, strict.priority)
        self.assertEqual(self.analyze(WRONG_ORDER).candidates[0].origin_validation, "MISSING")
        self.assertEqual(self.analyze(BAD_BRANCH).candidates[0].origin_validation,
                         "UNRESOLVED_BRANCH")

    def test_only_effect_guarding_checks_are_classified_as_strict(self) -> None:
        self.assertEqual(self.analyze(POSITIVE_GUARD).candidates[0].origin_validation,
                         "EXACT")
        self.assertEqual(self.analyze(UNRELATED_GUARD).candidates[0].origin_validation,
                         "UNRESOLVED_BRANCH")
        composite = self.analyze(COMPOSITE_GUARD).candidates[0]
        self.assertEqual(composite.origin_validation, "COMPOSITE_REVIEW")
        self.assertEqual(composite.source_validation, "COMPOSITE_REVIEW")
        self.assertEqual(self.analyze(OR_REJECT_GUARD).candidates[0].origin_validation,
                         "SUBSTRING")
        self.assertEqual(self.analyze(NULL_ORIGIN).candidates[0].origin_validation,
                         "NULL_ORIGIN_REVIEW")

    def test_no_signal_and_bounded_bytes(self) -> None:
        self.assertEqual(self.analyze(b"const value = 1;").status, "NO_MESSAGE_SIGNAL")
        self.assertEqual(self.analyze(b"postMessage" + b"x" * 1_048_576).status,
                         "ANALYSIS_LIMIT_REACHED")

    def test_parent_assumption_without_source_check_is_recorded(self) -> None:
        candidate = self.analyze(PARENT_ASSUMED).candidates[0]
        self.assertIn("PARENT", candidate.sender_contexts)
        self.assertEqual(candidate.source_validation, "MISSING")
        self.assertEqual(candidate.origin_validation, "EXACT_CURRENT_ORIGIN")
        self.assertTrue(candidate.port_accepted)

    def test_worker_and_broadcast_handlers_are_static_only(self) -> None:
        result = self.analyze(WORKER_CHANNELS)
        kinds = {item.transport_kind for item in result.candidates}
        self.assertEqual(kinds, {"WORKER", "SHARED_WORKER", "BROADCAST_CHANNEL"})
        self.assertTrue(all(item.status is MessageCandidateStatus.NEEDS_MANUAL_REVIEW
                            for item in result.candidates))
        self.assertEqual(result.senders, 2)

    def test_indirect_listener_forms_and_const_message_types(self) -> None:
        registrations = (
            b"window.addEventListener.call(window, 'message', receive);",
            b"window.addEventListener.apply(window, ['message', receive]);",
            b"Reflect.apply(window.addEventListener, window, ['message', receive]);",
            b"Object.defineProperty(window, 'onmessage', {value: receive});",
            b"Reflect.set(window, 'onmessage', receive);",
            b"Object.assign(window, {onmessage: receive});",
        )
        for registration in registrations:
            with self.subTest(registration=registration):
                result = self.analyze(INDIRECT_LISTENER + registration)
                self.assertEqual(result.status, "ANALYZED")
                self.assertEqual(len(result.candidates), 1)
                self.assertEqual(result.candidates[0].message_types, ("ACTIVATE",))
                self.assertEqual(result.candidates[0].reply_types, ("READY",))
                self.assertEqual(result.candidates[0].transport_kind, "WINDOW")

    def test_indirect_registration_rejects_mismatched_receiver(self) -> None:
        result = self.analyze(INDIRECT_LISTENER +
                              b"window.addEventListener.call(other, 'message', receive);")
        self.assertEqual(result.candidates, ())

    def test_message_driven_constant_handler_map_discovers_rpc_methods(self) -> None:
        result = self.analyze(HANDLER_MAP)
        self.assertEqual(len(result.candidates), 1)
        candidate = result.candidates[0]
        self.assertEqual(candidate.message_types, ("RPC",))
        self.assertEqual(set(candidate.rpc_methods), {"readSynthetic", "setPreview"})
        details = {item.name: item for item in candidate.rpc_details}
        self.assertEqual(details["readSynthetic"].capability, "READ")
        self.assertEqual(details["readSynthetic"].result_shape, "DYNAMIC")
        self.assertEqual(details["setPreview"].capability, "WRITE")
        self.assertEqual(details["setPreview"].result_shape, "STRING")


@unittest.skipUnless(shutil.which("node"), "Node/Babel parser unavailable")
class PostMessageStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.db = root / "state/bughunter.sqlite3"
        artifacts = root / "artifacts"
        self.evidence = EvidenceFactStore(self.db, ArtifactStore(artifacts), StoreSettings(artifacts))
        self.evidence.initialize()
        self.package = load_target_package(EXAMPLE)
        IdentityRegistry(self.evidence).register_target(self.package)
        self.target = self.package.target.id
        self.dom = DOMXSSStore(self.evidence)
        self.messages = PostMessageStore(self.evidence, self.dom)

    def record(self, url: str, body: bytes = TWO_STAGE):
        return self.dom.record_artifact(target_id=self.target, asset_url=url,
                                        body=body, recon_asset_id=42,
                                        recon_sha256=hashlib.sha256(body).hexdigest(),
                                        source="FIXTURE")

    def test_current_artifact_analysis_restart_and_duplicate_bundle(self) -> None:
        first = self.record("https://app.example.test/a.js")
        analysis_id, analysis = self.messages.analyze_asset(
            self.target, first.artifact_id, PostMessageStaticAnalyzer())
        item = next(part for part in analysis.candidates if "ACTIVATE" in part.message_types)
        self.assertEqual(self.messages.get_candidate(self.target, item.candidate_id), item)
        self.assertEqual(self.messages.current_asset(self.target, item.candidate_id), first)
        self.assertEqual(self.messages.analyze_asset(
            self.target, first.artifact_id, PostMessageStaticAnalyzer())[0], analysis_id)
        cached = self.messages.read_analysis(self.target, analysis_id)
        self.assertEqual(cached.senders, analysis.senders)
        self.assertEqual(cached.channels, analysis.channels)
        second = self.record("https://app.example.test/b.js")
        self.messages.analyze_asset(self.target, second.artifact_id, PostMessageStaticAnalyzer())
        merged = self.messages.get_candidate(self.target, item.candidate_id)
        self.assertEqual(len(merged.artifact_ids), 2)
        self.assertEqual(len(self.messages.list_candidates(self.target).items), 1)
        reopened = PostMessageStore(EvidenceFactStore(
            self.db, ArtifactStore(self.evidence.artifacts.root), self.evidence.settings),
            DOMXSSStore(self.evidence))
        self.assertEqual(reopened.get_candidate(self.target, item.candidate_id), merged)
        with self.assertRaises(ValueError):
            self.messages.get_candidate(self.target, "MSG-" + "f" * 33)

    def test_changed_hash_has_no_current_asset(self) -> None:
        first = self.record("https://app.example.test/a.js")
        _, analysis = self.messages.analyze_asset(self.target, first.artifact_id,
                                                  PostMessageStaticAnalyzer())
        item = analysis.candidates[0]
        self.record("https://app.example.test/a.js", TWO_STAGE + b"// changed")
        self.assertIsNone(self.messages.current_asset(self.target, item.candidate_id))

    def test_exact_observed_refresh_rejects_out_of_scope_and_skips_source_map(self) -> None:
        asset = self.record("https://app.example.test/a.js")
        recon_asset = SimpleNamespace(asset_id=42, asset_url="https://app.example.test/a.js")
        recon = SimpleNamespace(
            resolve_target=Mock(return_value=SimpleNamespace(domain_id=9)),
            get_js_asset=Mock(return_value=recon_asset))
        dom = SimpleNamespace(
            recon=recon, store=self.dom,
            acquire=Mock(return_value=DOMAcquisition(DOMAcquisitionStatus.REUSED, asset, ())),
            acquire_source_map=Mock())
        specialist = PostMessageSpecialist(
            dom=dom,
            targets=SimpleNamespace(get_target_package=lambda _: self.package),
            store=self.messages)
        status, analysis_id, analysis, reason = specialist.refresh_observed_asset(
            self.package.id, 42, include_source_map=False)
        self.assertEqual(status, "REUSED")
        self.assertIsNone(reason)
        self.assertIsNotNone(analysis_id)
        self.assertTrue(analysis.candidates)
        recon.get_js_asset.assert_called_once_with(9, 42)
        dom.acquire.assert_called_once_with(self.package.id, recon_asset)
        dom.acquire_source_map.assert_not_called()

        dom.acquire.return_value = DOMAcquisition(
            DOMAcquisitionStatus.HASH_DRIFT, asset, (), "RECON_HASH_DRIFT")
        drift_status, drift_id, drift_analysis, drift_reason = specialist.refresh_observed_asset(
            self.package.id, 42, include_source_map=False)
        self.assertEqual((drift_status, drift_id, drift_analysis, drift_reason),
                         ("HASH_DRIFT", None, None, "RECON_HASH_DRIFT"))

        recon.get_js_asset.return_value = SimpleNamespace(
            asset_id=42, asset_url="https://unrelated.example.net/a.js")
        dom.acquire.reset_mock()
        with self.assertRaises(ValueError):
            specialist.refresh_observed_asset(self.package.id, 42, include_source_map=False)
        dom.acquire.assert_not_called()

        recon.get_js_asset.return_value = SimpleNamespace(
            asset_id=43, asset_url="https://app.example.test/a.js")
        with self.assertRaises(ValueError):
            specialist.refresh_observed_asset(self.package.id, 42, include_source_map=False)
        dom.acquire.assert_not_called()

    def test_failed_parser_analysis_is_retried_without_losing_identity(self) -> None:
        asset = self.record("https://app.example.test/retry.js")

        class FlakyAnalyzer(PostMessageStaticAnalyzer):
            def __init__(self):
                super().__init__()
                self.calls = 0

            def analyze(self, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    return MessageAnalysis(kwargs["target_id"], kwargs["artifact_id"],
                                           hashlib.sha256(kwargs["body"]).hexdigest(),
                                           ANALYZER_VERSION, datetime.now(timezone.utc),
                                           "PARSE_FAILED", 0, 0, 0, (),
                                           reason="PARSER_UNAVAILABLE_OR_LIMIT")
                return super().analyze(**kwargs)

        analyzer = FlakyAnalyzer()
        first_id, failed = self.messages.analyze_asset(self.target, asset.artifact_id,
                                                        analyzer)
        self.assertEqual(failed.status, "PARSE_FAILED")
        second_id, recovered = self.messages.analyze_asset(self.target, asset.artifact_id,
                                                            analyzer)
        self.assertEqual(second_id, first_id)
        self.assertEqual(recovered.status, "ANALYZED")
        self.assertTrue(recovered.candidates)
        self.assertEqual(self.messages.analyze_asset(self.target, asset.artifact_id,
                                                    analyzer)[0], first_id)
        self.assertEqual(analyzer.calls, 2)

    def test_reanalysis_preserves_versions_and_requires_current_parser(self) -> None:
        asset = self.record("https://app.example.test/a.js")
        old_id, old = self.messages.analyze_asset(
            self.target, asset.artifact_id, PostMessageStaticAnalyzer())
        candidate_id = old.candidates[0].candidate_id
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE message_analysis_runs SET analyzer_version=? WHERE analysis_id=?",
                       ("1.1.0", old_id))
        self.assertIsNone(self.messages.current_asset(self.target, candidate_id))
        new_id, new = self.messages.analyze_asset(
            self.target, asset.artifact_id, PostMessageStaticAnalyzer())
        self.assertNotEqual(old_id, new_id)
        self.assertEqual(new.candidates[0].candidate_id, candidate_id)
        self.assertEqual(self.messages.current_asset(self.target, candidate_id), asset)
        self.assertEqual(self.messages.read_analysis(self.target, old_id).candidates[0].candidate_id,
                         candidate_id)
        with sqlite3.connect(self.db) as db:
            links = db.execute("SELECT analysis_id FROM message_candidate_assets "
                               "WHERE candidate_id=? AND artifact_id=?",
                               (candidate_id, asset.artifact_id)).fetchall()
        self.assertEqual({row[0] for row in links}, {old_id, new_id})

    def test_message_html_flow_routes_to_phase21_without_confirming(self) -> None:
        asset = self.record("https://app.example.test/preview.js", MESSAGE_HTML)
        _, messaging = self.messages.analyze_asset(
            self.target, asset.artifact_id, PostMessageStaticAnalyzer())
        _, dom = self.dom.analyze_asset(self.target, asset.artifact_id, DOMStaticAnalyzer())
        message = messaging.candidates[0]
        self.assertIn("DOM_WRITE", message.sensitive_operations)
        self.assertEqual(self.messages.dom_xss_handoffs(self.target, message.candidate_id),
                         tuple(item.candidate_id for item in dom.candidates
                               if item.source == "event.data.html" and
                               item.sink_kind == "HTML_EXECUTION"))
        self.assertFalse(dom.candidates[0].attacker_controlled)
