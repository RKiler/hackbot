"""Local-only Phase 22 plan/run/validator chain with deterministic browser observations."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Thread
import time
from types import SimpleNamespace as NS
from urllib.parse import urlsplit
import unittest
from unittest.mock import patch
import uuid

from hackbot.artifacts import ArtifactStore
from hackbot.browser import BrowserStatus, VerificationStatus
from hackbot.config import StoreSettings
from hackbot.domxss import DOMXSSSpecialist
from hackbot.domxss_store import DOMXSSStore
from hackbot.domxss_static import DOMStaticAnalyzer
from hackbot.domain import Tenant, TrafficSource
from hackbot.evidence import EvidenceProvenance, EvidenceType, Sensitivity
from hackbot.hypotheses import HypothesisStore
from hackbot.identity_registry import IdentityRegistry
from hackbot.identity import IdentityStatus
from hackbot.orchestrator import PlanOrchestrator
from hackbot.plan_runs import PlanRunStore
from hackbot.policy import PolicyEngine
from hackbot.policy_models import SideEffect
from hackbot.policy_store import PolicyStore
from hackbot.rate_limit import RateLimiter
from hackbot.postmessage import PostMessageSpecialist
from hackbot.postmessage_browser import (_TrialRequestGate, MessageBrowserObservation,
                                         MessageExperimentBinding,
                                         MessageVariant, PostMessageBrowserExperimentExecutor,
                                         lookalike_origin)
from hackbot.postmessage_static import (MessageCandidateStatus,
                                        PostMessageStaticAnalyzer)
from hackbot.postmessage_store import PostMessageStore
from hackbot.skill_plans import (MessagePlanBinding, PrerequisiteChecker,
                                SkillContextBuilder, SkillPlanStore, SkillPlanner,
                                SkillRouter)
from hackbot.skills import SkillRegistry
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import TargetPackageRepository, load_target_package
from hackbot.test_objects import CleanupStrategy, ObjectRegistry, ObjectState
from hackbot.traffic import (CapturePacket, CapturedRequest, CapturedResponse,
                             TrafficStore)
from hackbot.typed_mutations import MutationPhase, MutationType, TypedMutation
from hackbot.validation_store import ValidationStatus, ValidationStore
from hackbot.validator import DeterministicValidatorEngine, PostMessageValidator
from tests.test_domxss_runtime import NoTrafficExecutor
from tests.test_phase12 import FixtureRecon


EXAMPLES = Path(__file__).parent / "examples/targets"
CATALOG = Path(__file__).resolve().parents[1] / "src/hackbot/skill_catalog"
MARKER_HASH = hashlib.sha256(b"HACKBOT_SYNTHETIC_PRIVATE").hexdigest()
BRIDGE = b"""
window.addEventListener('message', function(event) {
  if (event.data.type !== 'ACTIVATE') return;
  const port = event.ports[0];
  if (!port) return;
  port.onmessage = function(packet) {
    if (packet.data.method === 'readSynthetic')
      port.postMessage({type: 'RESULT', value: syntheticCanary});
  };
  event.source.postMessage({type: 'READY'}, '*');
});
"""
SOURCE_ONLY = b"""
window.addEventListener('message', function(event) {
  const expectedParent = window.parent;
  if (event.origin !== location.origin || event.data.type !== 'ACTIVATE') return;
  const port = event.ports[0];
  if (!port) return;
  port.onmessage = function(packet) {
    if (packet.data.method === 'readSynthetic')
      port.postMessage({type: 'RESULT', value: syntheticCanary});
  };
});
"""
SUBSTRING = b"""
window.addEventListener('message', function(event) {
  if (!event.origin.includes('example.test') || event.data.type !== 'ACTIVATE') return;
  const port = event.ports[0];
  if (!port) return;
  port.onmessage = function(packet) {
    if (packet.data.method === 'readSynthetic')
      port.postMessage({type: 'RESULT', value: syntheticCanary});
  };
});
"""
PREFIX = b"""
window.addEventListener('message', function(event) {
  if (!event.origin.startsWith('https://api.example.test') || event.data.type !== 'ACTIVATE') return;
  const port = event.ports[0];
  if (!port) return;
  port.onmessage = function(packet) {
    if (packet.data.method === 'readSynthetic')
      port.postMessage({type: 'RESULT', value: syntheticCanary});
  };
});
"""
SUFFIX = b"""
window.addEventListener('message', function(event) {
  if (!event.origin.endsWith('example.test') || event.data.type !== 'ACTIVATE') return;
  const port = event.ports[0];
  if (!port) return;
  port.onmessage = function(packet) {
    if (packet.data.method === 'readSynthetic')
      port.postMessage({type: 'RESULT', value: syntheticCanary});
  };
});
"""
OPENER = b"""
window.addEventListener('message', function(event) {
  if (event.data.type !== 'ACTIVATE') return;
  const port = event.ports[0];
  if (!port) return;
  port.onmessage = function(packet) {
    if (packet.data.method === 'readSynthetic')
      port.postMessage({type: 'RESULT', value: syntheticCanary});
  };
  window.opener.postMessage({type: 'READY'}, '*');
});
"""
MESSAGE_DOM = b"""
window.addEventListener('message', event => {
  if (event.data.type !== 'PREVIEW') return;
  document.body.innerHTML = event.data.html;
});
"""
MESSAGE_DOM_ALIAS = b"""
window.addEventListener('message', event => {
  if (event.data.type !== 'PREVIEW') return;
  document.body.innerHTML = event.data.previewHtml;
});
"""


class FakeMessageDriver:
    def __init__(self, digest: str, mode: str) -> None:
        self.digest = digest
        self.mode = mode
        self.calls: list[MessageVariant] = []

    def is_running(self, _session_id: str) -> bool:
        return True

    def execute_message_trial(self, _session_id, binding, variant, gate, *,
                              authenticated, request_cap, timeout_ms):
        assert authenticated == (binding.identity_id is not None)
        assert request_cap >= 2 and timeout_ms >= 1000
        for url, navigation in ((binding.route_url, True),
                                (binding.asset_url, False)):
            ticket = gate(url, "GET", navigation)
            assert ticket
            gate.release(ticket)
        self.calls.append(variant)
        source_only = variant in {MessageVariant.WRONG_SOURCE,
                                  MessageVariant.FRESH_WRONG_SOURCE}
        proven = (variant is MessageVariant.TRUSTED or
                  self.mode in {"foreign", "dom_wrong_origin", "unattested",
                                "untransferred"} and variant in {
                      MessageVariant.ATTACKER_PORT, MessageVariant.UNRELATED,
                      MessageVariant.FRESH_REPRODUCTION} or
                  self.mode == "lookalike" and variant in {
                      MessageVariant.LOOKALIKE_ORIGIN,
                      MessageVariant.FRESH_LOOKALIKE_ORIGIN} or
                  self.mode == "source" and source_only)
        dom_mode = binding.dom_field is not None
        context_id = "MSGCTX-" + uuid.uuid4().hex
        message_count = 0 if variant is MessageVariant.NO_MESSAGE else 1
        port_count = 0 if dom_mode or variant in {MessageVariant.NO_MESSAGE,
                                                 MessageVariant.NO_PORT} else 1
        rpc_calls = int(bool((proven or variant is MessageVariant.WRONG_TYPE
                              and binding.allowed_method) and not dom_mode))
        events = ["SOURCE_ATTESTED"] if self.mode != "unattested" else []
        if port_count:
            events.append("PORT_CREATED")
        if message_count:
            events.append("MESSAGE_SENT")
            if port_count and self.mode != "untransferred":
                events.append("PORT_TRANSFERRED")
        if rpc_calls:
            events.append("RPC_SENT")
        if proven:
            events.append("DOM_EXECUTION" if dom_mode else "RPC_RESPONSE")
            if not dom_mode:
                events.append("OWNED_MATCH" if binding.owned_canary_value else "SYNTHETIC_MATCH")
        route_parts = urlsplit(binding.route_url)
        origin = (f"{route_parts.scheme}://{route_parts.netloc}" if source_only or
                  variant is MessageVariant.TRUSTED else
                  lookalike_origin(binding.route_url, binding.origin_probe_kind)
                  if variant in {MessageVariant.LOOKALIKE_ORIGIN,
                                 MessageVariant.FRESH_LOOKALIKE_ORIGIN} else
                  "http://attacker.fixture.invalid")
        return MessageBrowserObservation(
            context_id=context_id,
            attacker_origin=origin,
            source_relationship="SIBLING_FRAME" if source_only else
                                "FIXTURE_OPENER_OF_VICTIM" if binding.window_mode == "POPUP"
                                else "FIXTURE_PARENT_OF_VICTIM",
            source_attested=self.mode != "unattested",
            message_type=None if variant is MessageVariant.NO_MESSAGE else
                         "HACKBOT_UNRECOGNIZED_TYPE" if variant is MessageVariant.WRONG_TYPE
                         else binding.activation_type,
            message_count=message_count,
            port_count=port_count,
            rpc_calls=rpc_calls,
            event_trace=tuple((name, index) for index, name in enumerate(events)),
            capability_observed=proven,
            effect_kind=("DOM_EXECUTION" if dom_mode else
                         "OWNED_DATA" if binding.owned_canary_value else
                         "SYNTHETIC_DATA") if proven else None,
            effect_fingerprint=(hashlib.sha256(context_id.encode()).hexdigest()
                                if dom_mode else
                                hashlib.sha256(binding.owned_canary_value.encode()).hexdigest()
                                if binding.owned_canary_value else MARKER_HASH) if proven else None,
            victim_bundle_sha256=self.digest,
            response_status=200, frame_ancestors=None, x_frame_options=None,
            sandbox_flags=(), request_count=2, denial_count=0,
            marker_context="IFRAME" if proven and dom_mode else None,
            document_origin=("null" if self.mode ==
                             "dom_wrong_origin" else "https://api.example.test")
                            if proven and dom_mode else None,
        )


class FakeBrowserManager:
    def __init__(self, target_id: str, driver: FakeMessageDriver,
                 identity_id: str | None = None) -> None:
        self.driver = driver
        self.session = NS(id="BSESSION-" + "1" * 32,
                          target_id=target_id, identity_id=identity_id)

    def get(self, session_id: str):
        return self.session if session_id == self.session.id else None

    def session_context(self, _session_id: str):
        authenticated = self.session.identity_id is not None
        return NS(target_id=self.session.target_id, identity_id=self.session.identity_id,
                  browser_status=BrowserStatus.VALID if authenticated else BrowserStatus.RUNNING,
                  verification_status=VerificationStatus.MATCH if authenticated else None,
                  authentication_status="VALID" if authenticated else "ANONYMOUS",
                  browser_available=True)


class MessageRateGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.package = load_target_package(EXAMPLES / "example")
        self.clock = [0.0]
        self.rate = RateLimiter(clock=lambda: self.clock[0])
        self.policy = PolicyEngine(rate=self.rate)
        self.binding = MessageExperimentBinding(
            candidate_id="MSG-" + "a" * 32, run_id="RUN-" + "b" * 32,
            browser_session_id="BSESSION-fixture", route_url="https://api.example.test/preview",
            asset_url="https://api.example.test/bridge.js", activation_type="ACTIVATE",
            port_type=None, allowed_method=None, identity_id=None)

    def gate(self, *, timeout_ms: int = 500) -> _TrialRequestGate:
        return _TrialRequestGate(
            package=self.package, binding=self.binding, session_id="BSESSION-fixture",
            policy=self.policy, runs=NS(should_dispatch=lambda _run_id: True),
            request_cap=3, timeout_ms=timeout_ms, run_request_cap=3)

    def test_ephemeral_canary_is_excluded_from_binding_representation(self) -> None:
        secret = "hackbot-test-private-canary"
        binding = replace(self.binding, owned_canary_value=secret)
        self.assertNotIn(secret, repr(binding))

    def test_each_request_reserves_and_releases_shared_rate_capacity(self) -> None:
        gate = self.gate()
        first = gate(self.binding.route_url, "GET", True)
        self.assertIsNotNone(first)
        self.assertEqual(gate.reserved, 1)
        self.assertFalse(self.rate.check(self.package.target.id,
                                         self.package.rate).allowed)
        gate.release(first)
        self.clock[0] = 1.1
        second = gate(self.binding.asset_url, "GET", False)
        self.assertIsNotNone(second)
        gate.release(second)
        gate.close()
        self.assertEqual((gate.attempts, gate.reserved, gate.released, gate.denied),
                         (2, 2, 2, 0))
        self.assertEqual(len(gate.decisions), 2)

    def test_rate_exhaustion_blocks_without_a_second_reservation(self) -> None:
        gate = self.gate(timeout_ms=80)
        ticket = gate(self.binding.route_url, "GET", True)
        self.assertIsNotNone(ticket)
        gate.release(ticket)
        self.assertIsNone(gate(self.binding.asset_url, "GET", False))
        self.assertEqual((gate.reserved, gate.released, gate.denied), (1, 1, 1))
        gate.close()

    def test_concurrency_limit_denies_without_blocking_browser_callback(self) -> None:
        gate = self.gate()
        ticket = gate(self.binding.route_url, "GET", True)
        self.assertIsNotNone(ticket)
        with patch("hackbot.postmessage_browser.time.sleep",
                   side_effect=AssertionError("Browser callback must not wait on concurrency")):
            self.assertIsNone(gate(self.binding.asset_url, "GET", False))
        self.assertEqual((gate.reserved, gate.denied), (1, 1))
        gate.release(ticket)
        gate.close()
        self.assertEqual(gate.released, 1)


class PostMessageRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        artifacts = root / "artifacts"
        self.evidence = EvidenceFactStore(root / "state/db.sqlite3", ArtifactStore(artifacts),
                                          StoreSettings(artifacts))
        self.evidence.initialize()
        self.package = load_target_package(EXAMPLES / "example")
        self.target_id = self.package.target.id
        self.identities = IdentityRegistry(self.evidence)
        self.identities.register_target(self.package)
        self.targets = TargetPackageRepository(EXAMPLES)
        self.dom_store = DOMXSSStore(self.evidence)
        self.messages = PostMessageStore(self.evidence, self.dom_store)
        self.hypotheses = HypothesisStore(self.evidence)
        self.traffic = TrafficStore(self.evidence)
        self.contexts = SkillContextBuilder(self.evidence, self.identities,
                                            self.traffic, dom=self.dom_store,
                                            messages=self.messages)
        self.skills = SkillRegistry(CATALOG)
        self.skills.discover()
        self.checker = PrerequisiteChecker()
        self.router = SkillRouter(self.skills, self.checker)
        self.plans = SkillPlanStore(self.evidence)
        self.policy = PolicyEngine(audit=PolicyStore(self.evidence),
                                   rate=RateLimiter(clock=lambda: time.monotonic() * 1_000_000))
        self.objects = ObjectRegistry(self.evidence)
        self.planner = SkillPlanner(self.skills, self.checker, self.policy,
                                    self.plans, self.dom_store, self.messages, self.objects)
        self.runs = PlanRunStore(self.evidence)
        dom = DOMXSSSpecialist(recon=FixtureRecon(), targets=self.targets,
                               executor=NoTrafficExecutor(), store=self.dom_store)
        self.specialist = PostMessageSpecialist(dom=dom, targets=self.targets,
                                                store=self.messages)

    def _build(self, *, mode: str, body: bytes = BRIDGE,
               window_mode: str = "IFRAME", dom_field: str | None = None,
               route_host: str = "api.example.test", identity_id: str | None = None,
               owned_object_id: str | None = None):
        asset_url = f"https://{route_host}/bridge.js"
        route = f"https://{route_host}/preview"
        digest = hashlib.sha256(body).hexdigest()
        asset = self.dom_store.record_artifact(
            target_id=self.target_id, asset_url=asset_url, body=body,
            recon_asset_id=51, recon_sha256=digest, source="FIXTURE")
        if dom_field:
            self.dom_store.analyze_asset(self.target_id, asset.artifact_id,
                                         DOMStaticAnalyzer())
        _, analysis = self.messages.analyze_asset(
            self.target_id, asset.artifact_id, PostMessageStaticAnalyzer())
        candidate = analysis.candidates[0]
        route_evidence = self.evidence.create_evidence(
            EvidenceType.MANUAL_NOTE, b"fictional current page route", source="test_fixture",
            target_ref=self.target_id,
            provenance=EvidenceProvenance("FIXTURE", "PAGE_ROUTE", "preview"),
            sensitivity=Sensitivity.INTERNAL)
        self.messages.bind_route(self.target_id, candidate.candidate_id,
                                 route, route_evidence.evidence_id)
        prepared = self.specialist.prepare_candidate(
            "example", candidate.candidate_id, hypotheses=self.hypotheses,
            contexts=self.contexts, router=self.router, planner=self.planner)
        context = self.contexts.build(prepared.hypothesis, None, self.package)
        driver = FakeMessageDriver(digest, mode)
        browser = FakeBrowserManager(self.target_id, driver, identity_id)
        if identity_id is not None:
            self.policy.registry = self.identities
            self.policy.browser = browser
        bound = self.planner.bind_message(
            self.package, prepared.hypothesis, context,
            MessagePlanBinding(candidate.candidate_id, route, asset_url,
                               browser.session.id, identity_id,
                               "PREVIEW" if dom_field else "ACTIVATE", None,
                               None if dom_field else
                               "readCanary" if owned_object_id else "readSynthetic",
                               window_mode, dom_field, owned_object_id))
        executor = PostMessageBrowserExperimentExecutor(
            targets=self.targets, store=self.messages, browser=browser,
            driver=driver, policy=self.policy, runs=self.runs,
            evidence=self.evidence, objects=self.objects)
        orchestrator = PlanOrchestrator(
            runs=self.runs, targets=self.targets, hypotheses=self.hypotheses,
            context=self.contexts, checker=self.checker, registry=self.skills,
            policy=self.policy, approvals=PolicyStore(self.evidence),
            executor=NoTrafficExecutor(), traffic=self.traffic,
            evidence=self.evidence, messages=executor, objects=self.objects)
        started = orchestrator.start(bound["id"], "example")
        return orchestrator, started["run"]["id"], driver, candidate

    def _finish(self, orchestrator, run_id: str):
        for _ in range(8):
            detail = orchestrator.advance(run_id, "example")
            if detail["run"]["status"] == "COMPLETED":
                return detail
        self.fail("Messaging run did not complete")

    def _validate(self, run_id: str):
        validator = DeterministicValidatorEngine(
            runs=self.runs, traffic=self.traffic, evidence=self.evidence,
            identities=self.identities, hypotheses=self.hypotheses,
            results=ValidationStore(self.evidence), messages=self.messages,
            dom=self.dom_store, targets=self.targets)
        return validator.validate_run(run_id, self.target_id)

    def _owned_canary(self, *, with_facts: bool = True):
        identity = self.identities.register_identity(
            self.target_id, "message_owner", status=IdentityStatus.ACTIVE)
        tenant = self.identities.register_tenant(
            Tenant(target_id=self.target_id, label="message-fixture-tenant",
                   kind="organization"))
        marker = "hackbot-test-message-" + uuid.uuid4().hex[:12]
        item = self.objects.plan(
            target_id=self.target_id, package_id=self.package.id,
            object_type="project", creator_identity_id=identity.id,
            tenant_id=tenant.id, recipe_id="message-canary", recipe_hash="a" * 64,
            test_name=marker, cleanup_strategy=CleanupStrategy.AUTO_CLEANUP)
        observed = self.evidence.create_evidence(
            EvidenceType.OBJECT_OBSERVATION, b"local owned object creation and readback",
            source="test_fixture", target_ref=self.target_id,
            provenance=EvidenceProvenance("FIXTURE", "OWNED_OBJECT", item.id),
            sensitivity=Sensitivity.INTERNAL)
        external = self.evidence.create_evidence(
            "TEST_OBJECT_EXTERNAL_ID", b"local-disposable-object-id",
            source="test_fixture", target_ref=self.target_id,
            provenance=EvidenceProvenance("FIXTURE", "OWNED_OBJECT_ID", item.id),
            sensitivity=Sensitivity.SECRET)
        self.objects.transition(item.id, self.target_id,
                                frozenset({ObjectState.PLANNED}), ObjectState.CREATED,
                                "FIXTURE_CREATED", evidence_ids=(observed.evidence_id,),
                                external_id_hash=hashlib.sha256(
                                    (item.id + ":local-disposable-object-id").encode()).hexdigest(),
                                external_id_evidence_id=external.evidence_id)
        self.objects.transition(item.id, self.target_id,
                                frozenset({ObjectState.CREATED}), ObjectState.VERIFYING,
                                "FIXTURE_READBACK")
        item = self.objects.transition(
            item.id, self.target_id, frozenset({ObjectState.VERIFYING}),
            ObjectState.READY, "FIXTURE_VERIFIED",
            evidence_ids=(observed.evidence_id,))
        if with_facts:
            for predicate, value in (("created_by", identity.id),
                                     ("resource_tenant", tenant.id),
                                     ("disposable", "true")):
                self.evidence.create_fact(
                    item.id, predicate, value, confidence=1.0,
                    evidence_ids=(observed.evidence_id,), source="OBJECT_FACTORY",
                    target_ref=self.target_id)
        return identity, item

    def test_verified_owned_canary_confirms_without_persisting_value(self) -> None:
        identity, item = self._owned_canary()
        body = BRIDGE.replace(b"readSynthetic", b"readCanary")
        orchestrator, run_id, driver, candidate = self._build(
            mode="foreign", body=body, identity_id=identity.id,
            owned_object_id=item.id)
        self._finish(orchestrator, run_id)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED,
                         validation.reason_codes)
        self.assertIsNotNone(finding)
        self.assertIn(MessageVariant.FRESH_REPRODUCTION, driver.calls)
        self.assertEqual(self.objects.get(item.id, self.target_id).state,
                         ObjectState.CLEANUP_PENDING)
        links = self.messages.links(self.target_id, candidate.candidate_id)
        plan = self.plans.get(links["plan_id"], self.target_id)
        self.assertNotIn(item.test_name, json.dumps(plan))
        for evidence_id in validation.supporting_evidence_ids:
            record = self.evidence.get_evidence(evidence_id)
            if record.evidence_type == EvidenceType.MESSAGE_PROOF.value:
                self.assertNotIn(item.test_name, self.evidence.read_content(
                    evidence_id, allow_sensitive=True).decode())

    def test_read_named_rpc_with_write_effect_cannot_be_planned(self) -> None:
        body = BRIDGE.replace(
            b"port.postMessage({type: 'RESULT', value: syntheticCanary});",
            b"{ document.body.textContent = 'changed'; "
            b"port.postMessage({type: 'RESULT', value: syntheticCanary}); }")
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            self._build(mode="foreign", body=body)

    def test_local_typed_disposable_message_change_is_read_back_and_restored(self) -> None:
        try:
            from playwright.sync_api import expect, sync_playwright
        except ImportError:
            self.skipTest("Playwright optional dependency unavailable")
        binary = Path("/root/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome")
        if not binary.is_file():
            self.skipTest("Local Chromium fixture binary unavailable")
        identity, item = self._owned_canary()
        mutation = TypedMutation(
            target_id=self.target_id, operation_id="renameTestObject",
            test_object_id=item.id, object_type=item.object_type,
            creator_identity_id=identity.id, actor_identity_id=identity.id,
            tenant_id=item.tenant_id, mutation_type=MutationType.RENAME,
            field="name", value_label=TypedMutation.test_value(
                "RUN-" + "a" * 32, item.id, MutationPhase.BOUNDARY),
            expected_readback=TypedMutation.test_value(
                "RUN-" + "a" * 32, item.id, MutationPhase.BOUNDARY),
            cleanup_strategy="RESTORE", side_effect=SideEffect.SAFE_UPDATE,
            recipe_hash=item.recipe_hash,
            evidence_ids=item.verification_evidence_ids)
        external = self.evidence.read_content(
            item.external_id_evidence_id, allow_sensitive=True, max_bytes=256).decode("ascii")
        self.assertTrue(item.disposable)
        self.assertEqual(item.creator_identity_id, identity.id)
        self.assertEqual(hashlib.sha256((item.id + ":" + external).encode()).hexdigest(),
                         item.external_id_hash)
        victim_html = ("<!doctype html><div id='owned'></div><button id='restore'>Restore</button>"
                       "<script src='/bundle.js'></script>").encode()
        victim_js = f"""
const owned={{id:{json.dumps(external)},name:{json.dumps(item.test_name)}}};
const state=document.getElementById('owned');
state.setAttribute('data-name',owned.name);
document.getElementById('restore').onclick=()=>{{
  owned.name={json.dumps(item.test_name)};
  state.setAttribute('data-name',owned.name);
}};
window.addEventListener('message',event=>{{
  if(event.data?.type!=='ACTIVATE'||!event.ports[0])return;
  const port=event.ports[0];
  port.onmessage=packet=>{{
    if(packet.data?.method!=='renameTestObject'||packet.data.objectId!==owned.id)return;
    if(packet.data.name!=={json.dumps(mutation.value_label)})return;
    owned.name=packet.data.name;
    state.setAttribute('data-name',owned.name);
    port.postMessage({{type:'RESULT',value:'OK'}});
  }};
  event.source.postMessage({{type:'READY'}},event.origin);
}});
""".encode()

        class OwnedVictim(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/victim":
                    body, content_type = victim_html, "text/html"
                elif self.path == "/bundle.js":
                    body, content_type = victim_js, "application/javascript"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), OwnedVictim)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        sender = f"""<!doctype html><iframe id='victim' src={json.dumps(base + '/victim')}></iframe>
<script>
const frame=document.getElementById('victim');
frame.addEventListener('load',()=>{{
  const channel=new MessageChannel();
  window.addEventListener('message',event=>{{
    if(event.source!==frame.contentWindow||event.data?.type!=='READY')return;
    channel.port1.postMessage({{
      method:'renameTestObject',objectId:{json.dumps(external)},
      name:{json.dumps(mutation.value_label)}
    }});
  }},{{once:true}});
  frame.contentWindow.postMessage({{type:'ACTIVATE'}},'*',[channel.port2]);
}},{{once:true}});
</script>""".encode()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True,
                                                     executable_path=str(binary),
                                                     chromium_sandbox=False)
                try:
                    context = browser.new_context()
                    def local_route(route):
                        if route.request.url == "http://attacker.fixture.invalid/sender":
                            route.fulfill(status=200, content_type="text/html", body=sender)
                        elif (route.request.url in {base + "/victim", base + "/bundle.js"}
                              and route.request.method == "GET"):
                            route.fulfill(response=route.fetch(max_redirects=0))
                        else:
                            route.abort()
                    context.route("**/*", local_route)
                    page = context.new_page()
                    page.goto(base + "/victim")
                    expect(page.locator("#owned")).to_have_attribute(
                        "data-name", item.test_name)
                    page.goto("http://attacker.fixture.invalid/sender")
                    self.assertTrue(any(frame.url == base + "/victim"
                                        for frame in page.frames),
                                    [frame.url for frame in page.frames])
                    victim = page.frame_locator("#victim")
                    expect(victim.locator("#owned")).to_have_attribute(
                        "data-name", mutation.expected_readback)
                    victim.locator("#restore").click()
                    expect(victim.locator("#owned")).to_have_attribute(
                        "data-name", item.test_name)
                finally:
                    browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_owned_canary_without_verified_ownership_blocks_before_browser(self) -> None:
        identity, item = self._owned_canary(with_facts=False)
        body = BRIDGE.replace(b"readSynthetic", b"readCanary")
        orchestrator, run_id, driver, _ = self._build(
            mode="foreign", body=body, identity_id=identity.id,
            owned_object_id=item.id)
        detail = None
        for _ in range(8):
            detail = orchestrator.advance(run_id, "example")
            if detail["run"]["status"] == "BLOCKED":
                break
        self.assertIsNotNone(detail)
        self.assertEqual(detail["run"]["status"], "BLOCKED")
        self.assertEqual(driver.calls, [])
        self.assertEqual(self.objects.get(item.id, self.target_id).state,
                         ObjectState.CLEANUP_PENDING)

    def test_owned_canary_rejects_facts_with_foreign_target_evidence(self) -> None:
        identity, item = self._owned_canary(with_facts=False)
        foreign = self.evidence.create_evidence(
            EvidenceType.OBJECT_OBSERVATION, b"unrelated target fixture",
            source="test_fixture", target_ref="TARGET-" + "f" * 32,
            provenance=EvidenceProvenance("FIXTURE", "OTHER_TARGET", item.id),
            sensitivity=Sensitivity.INTERNAL)
        for predicate, value in (("created_by", identity.id),
                                 ("resource_tenant", item.tenant_id),
                                 ("disposable", "true")):
            self.evidence.create_fact(
                item.id, predicate, value, confidence=1.0,
                evidence_ids=(foreign.evidence_id,), source="OBJECT_FACTORY",
                target_ref=self.target_id)
        body = BRIDGE.replace(b"readSynthetic", b"readCanary")
        orchestrator, run_id, driver, _ = self._build(
            mode="foreign", body=body, identity_id=identity.id,
            owned_object_id=item.id)
        for _ in range(8):
            detail = orchestrator.advance(run_id, "example")
            if detail["run"]["status"] == "BLOCKED":
                break
        else:
            self.fail("Foreign target evidence did not block messaging")
        self.assertEqual(driver.calls, [])

    def test_owned_canary_with_mismatched_external_id_blocks_before_browser(self) -> None:
        identity, item = self._owned_canary()
        item = self.objects.transition(
            item.id, self.target_id, frozenset({ObjectState.READY}),
            ObjectState.READY, "FIXTURE_ID_MISMATCH",
            external_id_hash="b" * 64,
            external_id_evidence_id=item.external_id_evidence_id)
        body = BRIDGE.replace(b"readSynthetic", b"readCanary")
        orchestrator, run_id, driver, _ = self._build(
            mode="foreign", body=body, identity_id=identity.id,
            owned_object_id=item.id)
        detail = None
        for _ in range(8):
            detail = orchestrator.advance(run_id, "example")
            if detail["run"]["status"] == "BLOCKED":
                break
        self.assertIsNotNone(detail)
        self.assertEqual(detail["run"]["status"], "BLOCKED")
        self.assertEqual(driver.calls, [])

    def _anonymous_denial(self, path: str):
        observed = datetime.now(timezone.utc)
        return self.traffic.store_exchange(
            self.package,
            CapturePacket(
                CapturedRequest("GET", "https://api.example.test/objects/" + path,
                                observed_at=observed),
                CapturedResponse(403, observed_at=observed)),
            source=TrafficSource.HACKBOT, capture_provider="HACKBOT",
            anonymous=True)

    def test_nonfixture_owned_canary_rejects_assertion_and_wrong_object_denial(self) -> None:
        identity, item = self._owned_canary()
        self._anonymous_denial("different-object-id?tracking=local-disposable-object-id")
        body = BRIDGE.replace(b"readSynthetic", b"readCanary")
        orchestrator, run_id, _, candidate = self._build(
            mode="foreign", body=body, identity_id=identity.id,
            owned_object_id=item.id)
        self._finish(orchestrator, run_id)
        asset = self.messages.current_asset(self.target_id, candidate.candidate_id)
        with self.evidence._connection() as db:
            db.execute("UPDATE dom_js_artifacts SET source=? WHERE artifact_id=?",
                       ("CONTROLLED_HTTP", asset.artifact_id))
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.NEEDS_MANUAL_REVIEW)
        self.assertIn("MESSAGE_OWNED_DATA_PRIVACY_UNPROVEN", validation.reason_codes)
        self.assertIsNone(finding)
        private = self.evidence.create_evidence(
            EvidenceType.AUTH_OBSERVATION,
            b"local fixture owner read allowed; anonymous read denied",
            source="test_fixture", target_ref=self.target_id,
            provenance=EvidenceProvenance("FIXTURE", "ACCESS_CONTROL", item.id),
            sensitivity=Sensitivity.INTERNAL)
        for predicate, value in (("resource_visibility", "PRIVATE"),
                                 ("public_read_denied", "true")):
            self.evidence.create_fact(
                item.id, predicate, value, confidence=1.0,
                evidence_ids=(private.evidence_id,), source="AUTH_OBSERVATION",
                target_ref=self.target_id)
        unbound, finding = self._validate(run_id)
        self.assertEqual(unbound.status, ValidationStatus.NEEDS_MANUAL_REVIEW)
        self.assertIsNone(finding)

    def test_nonfixture_owned_canary_uses_matching_anonymous_denial(self) -> None:
        identity, item = self._owned_canary()
        matching_denial = self._anonymous_denial("local-disposable-object-id")
        body = BRIDGE.replace(b"readSynthetic", b"readCanary")
        orchestrator, run_id, _, candidate = self._build(
            mode="foreign", body=body, identity_id=identity.id,
            owned_object_id=item.id)
        self._finish(orchestrator, run_id)
        asset = self.messages.current_asset(self.target_id, candidate.candidate_id)
        with self.evidence._connection() as db:
            db.execute("UPDATE dom_js_artifacts SET source=? WHERE artifact_id=?",
                       ("CONTROLLED_HTTP", asset.artifact_id))
        private = self.evidence.create_evidence(
            EvidenceType.AUTH_OBSERVATION, b"local fixture private object baseline",
            source="test_fixture", target_ref=self.target_id,
            provenance=EvidenceProvenance("FIXTURE", "ACCESS_CONTROL", item.id),
            sensitivity=Sensitivity.INTERNAL)
        self.evidence.create_fact(
            item.id, "resource_visibility", "PRIVATE", confidence=1.0,
            evidence_ids=(private.evidence_id,), source="AUTH_OBSERVATION",
            target_ref=self.target_id)
        validated, finding = self._validate(run_id)
        self.assertEqual(validated.status, ValidationStatus.CONFIRMED,
                         validated.reason_codes)
        self.assertIsNotNone(finding)
        self.assertIn(private.evidence_id, validated.supporting_evidence_ids)
        self.assertIn(matching_denial.response.observation_evidence_id,
                      validated.supporting_evidence_ids)

    def test_trace_rejects_missing_or_forged_protocol_events(self) -> None:
        trial = {
            "source_attested": True, "message_count": 1, "port_count": 1,
            "rpc_calls": 1, "rpc_method": "readSynthetic",
            "effect_kind": "SYNTHETIC_DATA",
            "event_trace": [["SOURCE_ATTESTED", 0], ["PORT_CREATED", 1],
                            ["MESSAGE_SENT", 2], ["PORT_TRANSFERRED", 3],
                            ["RPC_SENT", 4], ["RPC_RESPONSE", 5],
                            ["SYNTHETIC_MATCH", 6]],
        }
        self.assertTrue(PostMessageValidator._trace_valid(trial, "readSynthetic"))
        trial["event_trace"] = [event for event in trial["event_trace"]
                                if event[0] != "PORT_CREATED"]
        self.assertFalse(PostMessageValidator._trace_valid(trial, "readSynthetic"))
        trial["event_trace"] = [["SOURCE_ATTESTED", 1], ["MESSAGE_SENT", 0]]
        self.assertFalse(PostMessageValidator._trace_valid(trial, "readSynthetic"))

    def test_skill_context_contains_only_bounded_protocol_metadata(self) -> None:
        _, _, _, candidate = self._build(mode="foreign")
        links = self.messages.links(self.target_id, candidate.candidate_id)
        hypothesis = self.hypotheses.get(links["hypothesis_id"], self.target_id)
        self.assertIsNotNone(hypothesis)
        context = self.contexts.build(hypothesis, None, self.package)
        packet = context.to_dict()["message_protocol"]
        self.assertEqual(packet["candidate_id"], candidate.candidate_id)
        self.assertEqual(packet["handler_slice"]["receives"], ["ACTIVATE"])
        self.assertIn("READY", packet["handler_slice"]["replies"])
        self.assertIn("RESULT", packet["handler_slice"]["replies"])
        self.assertEqual(packet["rpc_methods"], ["readSynthetic"])
        self.assertTrue(packet["accepts_port"])
        serialized = json.dumps(packet)
        self.assertLess(len(serialized), 2048)
        self.assertNotIn("syntheticCanary", serialized)
        self.assertNotIn("postMessage({", serialized)

    def test_port_capability_requires_transfer_evidence(self) -> None:
        orchestrator, run_id, _, _ = self._build(mode="untransferred")
        self._finish(orchestrator, run_id)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.NEEDS_MANUAL_REVIEW)
        self.assertIsNone(finding)

    def test_missing_origin_capability_confirms_with_full_audit_chain(self) -> None:
        orchestrator, run_id, driver, candidate = self._build(mode="foreign")
        detail = self._finish(orchestrator, run_id)
        self.assertEqual(detail["run"]["requests_consumed"], 7)
        self.assertEqual(driver.calls[-1], MessageVariant.FRESH_REPRODUCTION)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertEqual(validation.reproduction_count, 2)
        self.assertEqual(self.messages.links(self.target_id, candidate.candidate_id)["validation_id"],
                         validation.id)
        metrics = self.messages.metrics(self.target_id)
        self.assertGreaterEqual(metrics["handlers"], 1)
        self.assertEqual(metrics["rpc_methods"], 1)
        self.assertEqual(metrics["message_port_candidates"], 1)
        self.assertEqual(metrics["runtime_tests"], 7)
        self.assertEqual(metrics["messages_sent"], 6)
        self.assertEqual(metrics["rpc_calls"], 4)
        self.assertEqual(metrics["confirmed"], 1)
        self.assertEqual(self.plans.outcome_counts("postmessage-trust-analysis"),
                         {"CONFIRMED": 1})

    def test_synthetic_marker_does_not_confirm_controlled_http_asset(self) -> None:
        orchestrator, run_id, _, candidate = self._build(mode="foreign")
        self._finish(orchestrator, run_id)
        asset = self.messages.current_asset(self.target_id, candidate.candidate_id)
        self.assertIsNotNone(asset)
        with self.evidence._connection() as db:
            db.execute("UPDATE dom_js_artifacts SET source=? WHERE artifact_id=?",
                       ("CONTROLLED_HTTP", asset.artifact_id))
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.NEEDS_MANUAL_REVIEW)
        self.assertIn("MESSAGE_SYNTHETIC_FIXTURE_ONLY", validation.reason_codes)
        self.assertIsNone(finding)

    def test_candidate_run_validation_and_finding_survive_store_reopen(self) -> None:
        orchestrator, run_id, _, candidate = self._build(mode="foreign")
        self._finish(orchestrator, run_id)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        reopened = EvidenceFactStore(
            self.evidence.db_path, self.evidence.artifacts, self.evidence.settings)
        reopened.initialize()
        messages = PostMessageStore(reopened, DOMXSSStore(reopened))
        links = messages.links(self.target_id, candidate.candidate_id)
        self.assertIsNotNone(messages.current_asset(self.target_id, candidate.candidate_id))
        self.assertEqual(links["run_id"], run_id)
        self.assertEqual(links["validation_id"], validation.id)
        self.assertEqual(ValidationStore(reopened).get(validation.id, self.target_id).status,
                         ValidationStatus.CONFIRMED)
        with sqlite3.connect(reopened.db_path) as db:
            row = db.execute("""SELECT f.finding_id,v.validation_id,r.run_id,r.skill_id,
                h.hypothesis_id,c.candidate_id,a.artifact_id,a.artifact_sha256
                FROM findings f JOIN validations v ON v.validation_id=f.validation_id
                JOIN plan_runs r ON r.run_id=v.run_id
                JOIN hypotheses h ON h.hypothesis_id=r.hypothesis_id
                JOIN message_protocol_candidates c ON c.hypothesis_id=h.hypothesis_id
                JOIN message_candidate_assets x ON x.candidate_id=c.candidate_id
                JOIN dom_js_artifacts a ON a.artifact_id=x.artifact_id
                WHERE f.finding_id=? LIMIT 1""", (finding.id,)).fetchone()
        self.assertEqual(row[0:6], (finding.id, validation.id, run_id,
                                     "postmessage-trust-analysis", links["hypothesis_id"],
                                     candidate.candidate_id))
        self.assertEqual(row[7], self.messages.current_asset(
            self.target_id, candidate.candidate_id).artifact_sha256)

    def test_unattested_sender_blocks_runtime_proof(self) -> None:
        orchestrator, run_id, _, candidate = self._build(mode="unattested")
        for _ in range(8):
            detail = orchestrator.advance(run_id, "example")
            if detail["run"]["status"] == "BLOCKED":
                break
        else:
            self.fail("Unattested sender did not block the run")
        self.assertIsNone(self.messages.links(self.target_id, candidate.candidate_id)[
            "validation_id"])

    def test_missing_source_with_strict_origin_confirms_owned_fixture(self) -> None:
        orchestrator, run_id, driver, candidate = self._build(mode="source", body=SOURCE_ONLY)
        self.assertIn("PARENT", candidate.sender_contexts)
        self._finish(orchestrator, run_id)
        self.assertEqual(driver.calls[-1], MessageVariant.FRESH_WRONG_SOURCE)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertIn("WRONG_SOURCE", validation.controls_evaluated)

    def test_missing_source_nonfixture_needs_sender_control(self) -> None:
        orchestrator, run_id, driver, candidate = self._build(mode="source", body=SOURCE_ONLY)
        with self.evidence._connection() as db:
            db.execute("UPDATE dom_js_artifacts SET source='CONTROLLED_HTTP' "
                       "WHERE artifact_id=?", (self.messages.current_asset(
                           self.target_id, candidate.candidate_id).artifact_id,))
        self._finish(orchestrator, run_id)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.NEEDS_MANUAL_REVIEW)
        self.assertIsNone(finding)
        self.assertIn("MESSAGE_SAME_ORIGIN_SENDER_CONTROL_UNPROVEN", validation.reason_codes)

    def test_secure_bridge_is_rejected(self) -> None:
        orchestrator, run_id, driver, _ = self._build(mode="secure")
        self._finish(orchestrator, run_id)
        self.assertEqual(len(driver.calls), 6)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.REJECTED)
        self.assertIsNone(finding)
        self.assertEqual(self.messages.metrics(self.target_id)["rejected"], 1)

    def test_lookalike_origin_confirms_only_with_matching_fresh_proof(self) -> None:
        orchestrator, run_id, driver, candidate = self._build(
            mode="lookalike", body=SUBSTRING)
        self.assertEqual(candidate.origin_validation, "SUBSTRING")
        detail = self._finish(orchestrator, run_id)
        self.assertEqual(detail["run"]["requests_consumed"], 8)
        self.assertEqual(driver.calls[-1], MessageVariant.FRESH_LOOKALIKE_ORIGIN)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertIn("LOOKALIKE_ORIGIN", validation.controls_evaluated)

    def test_prefix_origin_probe_matches_frozen_weak_check(self) -> None:
        orchestrator, run_id, driver, candidate = self._build(
            mode="lookalike", body=PREFIX)
        self.assertEqual(candidate.origin_validation, "STARTSWITH")
        self._finish(orchestrator, run_id)
        self.assertEqual(driver.calls[-1], MessageVariant.FRESH_LOOKALIKE_ORIGIN)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)

    def test_suffix_origin_probe_stays_outside_authorized_wildcard(self) -> None:
        orchestrator, run_id, driver, candidate = self._build(
            mode="lookalike", body=SUFFIX, route_host="example.test")
        self.assertEqual(candidate.origin_validation, "ENDSWITH")
        self._finish(orchestrator, run_id)
        self.assertEqual(driver.calls[-1], MessageVariant.FRESH_LOOKALIKE_ORIGIN)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)

    def test_suffix_probe_inside_authorized_wildcard_requires_review(self) -> None:
        orchestrator, run_id, driver, candidate = self._build(
            mode="lookalike", body=SUFFIX)
        self.assertEqual(candidate.origin_validation, "ENDSWITH")
        self._finish(orchestrator, run_id)
        self.assertNotIn(MessageVariant.LOOKALIKE_ORIGIN, driver.calls)
        self.assertNotIn(MessageVariant.FRESH_LOOKALIKE_ORIGIN, driver.calls)
        self.assertEqual(self.messages.get_candidate(self.target_id, candidate.candidate_id).status,
                         MessageCandidateStatus.NEEDS_MANUAL_REVIEW)

    def test_foreign_origin_proof_skips_redundant_lookalike_trial(self) -> None:
        orchestrator, run_id, driver, _ = self._build(mode="foreign", body=SUBSTRING)
        self._finish(orchestrator, run_id)
        self.assertNotIn(MessageVariant.LOOKALIKE_ORIGIN, driver.calls)
        self.assertEqual(driver.calls[-1], MessageVariant.FRESH_REPRODUCTION)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)

    def test_popup_opener_plan_and_validation_chain(self) -> None:
        orchestrator, run_id, driver, candidate = self._build(
            mode="foreign", body=OPENER, window_mode="POPUP")
        self.assertIn("OPENER", candidate.sender_contexts)
        self._finish(orchestrator, run_id)
        self.assertNotIn(MessageVariant.WRONG_SOURCE, driver.calls)
        self.assertEqual(driver.calls[-1], MessageVariant.FRESH_REPRODUCTION)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)

    def test_message_html_handoff_is_confirmed_by_phase21_validator(self) -> None:
        orchestrator, run_id, driver, candidate = self._build(
            mode="foreign", body=MESSAGE_DOM, dom_field="html")
        handoffs = self.messages.dom_xss_handoffs(self.target_id,
                                                   candidate.candidate_id)
        self.assertEqual(len(handoffs), 1)
        self._finish(orchestrator, run_id)
        self.assertEqual(driver.calls[-1], MessageVariant.FRESH_REPRODUCTION)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIn("DOM_MESSAGE_BROWSER_EXECUTION_REPRODUCED", validation.reason_codes)
        self.assertEqual(finding.category, "DOM_XSS")
        self.assertIn(self.dom_store.get_candidate(self.target_id, handoffs[0]).evidence_ids[0],
                      validation.supporting_evidence_ids)

    def test_analyzer_selected_non_html_field_uses_phase21_handoff(self) -> None:
        orchestrator, run_id, _, candidate = self._build(
            mode="foreign", body=MESSAGE_DOM_ALIAS, dom_field="previewHtml")
        self.assertEqual(self.messages.dom_xss_field(self.target_id,
                                                     candidate.candidate_id), "previewHtml")
        self._finish(orchestrator, run_id)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertEqual(finding.category, "DOM_XSS")

    def test_message_html_marker_outside_victim_origin_is_not_confirmed(self) -> None:
        orchestrator, run_id, _, _ = self._build(
            mode="dom_wrong_origin", body=MESSAGE_DOM, dom_field="html")
        self._finish(orchestrator, run_id)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.NEEDS_MANUAL_REVIEW)
        self.assertIsNone(finding)

    def test_v18_dispatch_history_survives_variant_migration(self) -> None:
        orchestrator, run_id, _, _ = self._build(mode="foreign")
        self._finish(orchestrator, run_id)
        with sqlite3.connect(self.evidence.db_path) as db:
            for table in ("api_inventory_progress", "api_specialist_runs", "api_candidates", "api_operations"):
                db.execute(f"DROP TABLE {table}")
            db.execute("DROP INDEX api_js_artifacts_target_hash_state")
            for table in ("behaviour_observations", "behaviour_workflows", "behaviour_expectations",
                          "behaviour_profiles", "behaviour_runs", "bootstrap_observations",
                          "bootstrap_discovery_states", "bootstrap_runs"):
                db.execute(f"DROP TABLE {table}")
            before = db.execute("SELECT run_id,step_id,variant,accounted_at "
                                "FROM plan_message_dispatches ORDER BY variant").fetchall()
            db.execute("ALTER TABLE plan_message_dispatches RENAME TO plan_message_dispatches_v19")
            db.execute("""CREATE TABLE plan_message_dispatches (
                run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
                step_id TEXT NOT NULL REFERENCES plan_run_steps(step_id),
                variant TEXT NOT NULL CHECK (variant IN ('NO_MESSAGE','WRONG_TYPE','TRUSTED',
                    'UNRELATED','WRONG_SOURCE','NO_PORT','ATTACKER_PORT','FRESH_REPRODUCTION')),
                accounted_at TEXT NOT NULL,
                PRIMARY KEY(run_id,step_id,variant))""")
            db.execute("INSERT INTO plan_message_dispatches SELECT * "
                       "FROM plan_message_dispatches_v19")
            db.execute("DROP TABLE plan_message_dispatches_v19")
            for table in ("exposure_candidate_sources", "exposure_candidate_events",
                          "exposure_candidates"):
                db.execute(f"DROP TABLE {table}")
            db.execute("DROP TABLE message_runtime_trials")
            db.execute("ALTER TABLE message_analysis_runs DROP COLUMN sender_count")
            db.execute("ALTER TABLE message_analysis_runs DROP COLUMN channel_count")
            db.execute("PRAGMA user_version=18")
        self.evidence.initialize()
        with sqlite3.connect(self.evidence.db_path) as db:
            after = db.execute("SELECT run_id,step_id,variant,accounted_at "
                               "FROM plan_message_dispatches ORDER BY variant").fetchall()
            version = db.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(after, before)
        self.assertEqual(version, 34)
        validation, finding = self._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)


if __name__ == "__main__":
    unittest.main()
