"""Phase 22 browser fixtures use only a localhost victim and a locally fulfilled sender."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import unittest

from hackbot.browser import BrowserProxyConfig
from hackbot.browser_playwright import PlaywrightBrowserDriver
from hackbot.postmessage_browser import (MessageExperimentBinding, MessageVariant,
                                         lookalike_origin)


VICTIM_JS = b"""
window.addEventListener('message', event => {
  if (event.data.type !== 'ACTIVATE') return;
  const port = event.ports[0];
  if (!port) return;
  port.onmessage = packet => {
    if (packet.data.method === 'readSynthetic')
      port.postMessage({type:'RESULT',value:'HACKBOT_SYNTHETIC_PRIVATE'});
  };
  event.source.postMessage({type:'READY'}, '*');
});
"""


class _Victim(BaseHTTPRequestHandler):
    bundle = VICTIM_JS
    xfo = None
    csp = None
    redirect_route = False
    next_hits = 0
    victim_hits = 0
    write_attempts = 0

    def do_GET(self) -> None:
        if self.path == "/victim" and self.redirect_route:
            self.send_response(302)
            self.send_header("Location", "/victim-next")
            self.end_headers()
            return
        if self.path in {"/victim", "/victim-next"}:
            type(self).victim_hits += 1
            if self.path == "/victim-next":
                type(self).next_hits += 1
            body = b"<!doctype html><script src='/bundle.js'></script>"
            content_type = "text/html"
        elif self.path == "/bundle.js":
            body = self.bundle
            content_type = "application/javascript"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/victim" and self.xfo:
            self.send_header("X-Frame-Options", self.xfo)
        if self.path == "/victim" and self.csp:
            self.send_header("Content-Security-Policy", self.csp)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def do_PATCH(self) -> None:
        _Victim.write_attempts += 1
        self.send_response(204)
        self.end_headers()


class _SandboxedMessageDriver(PlaywrightBrowserDriver):
    @staticmethod
    def _message_fixture(binding, variant, marker=None, context_id=None):
        body = PlaywrightBrowserDriver._message_fixture(binding, variant, marker, context_id)
        needle = b"victim.id='victim'; victim.src=victimUrl;"
        if needle not in body:
            raise AssertionError("Victim iframe fixture changed")
        return body.replace(needle,
                            b"victim.id='victim'; victim.setAttribute('sandbox',"
                            b"'allow-scripts'); victim.src=victimUrl;")


class _CountingGate:
    def __init__(self, base: str) -> None:
        self.base = base
        self.issued = 0
        self.released = 0
        self.active: set[str] = set()
        self.urls: list[str] = []

    def __call__(self, url: str, method: str, _navigation: bool) -> str | None:
        if not url.startswith(self.base) or method != "GET":
            return None
        self.issued += 1
        self.urls.append(url)
        ticket = f"LOCAL-{self.issued}"
        self.active.add(ticket)
        return ticket

    def release(self, ticket: str) -> None:
        if ticket not in self.active:
            raise AssertionError("Browser released an unknown request ticket")
        self.active.remove(ticket)
        self.released += 1


class MessageFixtureTests(unittest.TestCase):
    def binding(self, base: str) -> MessageExperimentBinding:
        return MessageExperimentBinding(
            candidate_id="MSG-" + "a" * 32, run_id="RUN-" + "b" * 32,
            browser_session_id="SESSION-fixture", route_url=base + "/victim",
            asset_url=base + "/bundle.js", activation_type="ACTIVATE",
            port_type=None, allowed_method="readSynthetic", identity_id=None,
        )

    def test_fixed_fixture_has_no_secret_or_eval_surface(self) -> None:
        html = PlaywrightBrowserDriver._message_fixture(
            self.binding("http://127.0.0.1:12345"), MessageVariant.ATTACKER_PORT).decode()
        for forbidden in ("document.cookie", "localStorage", "sessionStorage", "eval(",
                          "new Function", "fetch(", "XMLHttpRequest"):
            self.assertNotIn(forbidden, html)
        self.assertIn("HACKBOT_SYNTHETIC_PRIVATE", html)
        with self.assertRaises(Exception):
            PlaywrightBrowserDriver._message_fixture(
                replace(self.binding("http://127.0.0.1:12345"), allowed_method="deleteAccount"),
                MessageVariant.ATTACKER_PORT)

    def test_ip_literal_suffix_probe_is_not_generated(self) -> None:
        with self.assertRaises(ValueError):
            lookalike_origin("http://127.0.0.1:12345/victim", "ENDSWITH")

    def test_actual_browser_cross_origin_port_fixture(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright optional dependency unavailable")
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Victim)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        playwright = sync_playwright().start()
        browser_binary = Path("/root/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome")
        if not browser_binary.is_file():
            playwright.stop()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.skipTest("Local Chromium fixture binary unavailable")
        driver = PlaywrightBrowserDriver(browser_binary)
        driver._playwright = playwright
        driver._contexts["SESSION-fixture"] = object()
        driver._proxy_settings["SESSION-fixture"] = BrowserProxyConfig()
        gate = _CountingGate(base)
        try:
            result = driver.execute_message_trial(
                "SESSION-fixture", self.binding(base), MessageVariant.ATTACKER_PORT,
                gate,
                authenticated=False, request_cap=8, timeout_ms=8000,
            )
            self.assertEqual(result.error_code, None)
            self.assertTrue(result.source_attested)
            self.assertTrue(result.capability_observed)
            self.assertEqual(result.effect_kind, "SYNTHETIC_DATA")
            self.assertEqual(result.victim_bundle_sha256, hashlib.sha256(VICTIM_JS).hexdigest())
            self.assertEqual(result.port_count, 1)
            self.assertEqual(result.rpc_calls, 1)
            self.assertEqual(result.denial_count, 0)
            self.assertEqual(gate.issued, result.request_count)
            self.assertEqual(gate.released, gate.issued)
            self.assertFalse(gate.active)
        finally:
            playwright.stop()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_redirect_fails_closed_before_an_unrouted_second_hop(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright optional dependency unavailable")
        browser_binary = Path("/root/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome")
        if not browser_binary.is_file():
            self.skipTest("Local Chromium fixture binary unavailable")
        handler = type("RedirectMessageVictim", (_Victim,),
                       {"redirect_route": True, "next_hits": 0})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        playwright = sync_playwright().start()
        driver = PlaywrightBrowserDriver(browser_binary)
        driver._playwright = playwright
        driver._contexts["SESSION-fixture"] = object()
        driver._proxy_settings["SESSION-fixture"] = BrowserProxyConfig()
        gate = _CountingGate(base)
        try:
            result = driver.execute_message_trial(
                "SESSION-fixture", self.binding(base), MessageVariant.ATTACKER_PORT,
                gate, authenticated=False, request_cap=8, timeout_ms=8000,
            )
            self.assertIn(base + "/victim", gate.urls)
            self.assertNotIn(base + "/victim-next", gate.urls)
            self.assertEqual(handler.next_hits, 0)
            self.assertGreaterEqual(result.denial_count, 1)
            self.assertEqual(gate.issued, result.request_count)
            self.assertEqual(gate.released, gate.issued)
            self.assertFalse(gate.active)
        finally:
            playwright.stop()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_policy_gate_exception_aborts_before_victim_request(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright optional dependency unavailable")
        browser_binary = Path("/root/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome")
        if not browser_binary.is_file():
            self.skipTest("Local Chromium fixture binary unavailable")
        handler = type("GateFailureVictim", (_Victim,), {"victim_hits": 0})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        playwright = sync_playwright().start()
        driver = PlaywrightBrowserDriver(browser_binary)
        driver._playwright = playwright
        driver._contexts["SESSION-fixture"] = object()
        driver._proxy_settings["SESSION-fixture"] = BrowserProxyConfig()

        def broken_gate(_url: str, _method: str, _navigation: bool) -> None:
            raise RuntimeError("local gate failure")

        try:
            result = driver.execute_message_trial(
                "SESSION-fixture", self.binding(base), MessageVariant.ATTACKER_PORT,
                broken_gate, authenticated=False, request_cap=8, timeout_ms=8000,
            )
            self.assertEqual(handler.victim_hits, 0)
            self.assertGreaterEqual(result.denial_count, 1)
            self.assertFalse(result.capability_observed)
        finally:
            playwright.stop()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def _browser_trials(self, bundle: bytes, variants: tuple[MessageVariant, ...], *,
                        port_type: str | None = None, window_mode: str = "IFRAME",
                        xfo: str | None = None, csp: str | None = None,
                        dom_field: str | None = None, sandbox_victim: bool = False,
                        origin_probe_kind: str = "SUBSTRING", host: str = "127.0.0.1",
                        owned_canary: str | None = None):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright optional dependency unavailable")
        browser_binary = Path("/root/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome")
        if not browser_binary.is_file():
            self.skipTest("Local Chromium fixture binary unavailable")
        handler = type("LocalMessageVictim", (_Victim,),
                       {"bundle": bundle, "xfo": xfo, "csp": csp})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://{host}:{server.server_port}"
        playwright = sync_playwright().start()
        driver = (_SandboxedMessageDriver if sandbox_victim else
                  PlaywrightBrowserDriver)(browser_binary)
        driver._playwright = playwright
        driver._contexts["SESSION-fixture"] = object()
        driver._proxy_settings["SESSION-fixture"] = BrowserProxyConfig()
        binding = replace(self.binding(base), port_type=port_type,
                          window_mode=window_mode, dom_field=dom_field,
                          origin_probe_kind=origin_probe_kind,
                          activation_type="PREVIEW" if dom_field else "ACTIVATE",
                          allowed_method=None if dom_field else
                          "readCanary" if owned_canary else "readSynthetic",
                          owned_canary_value=owned_canary)
        try:
            return [driver.execute_message_trial(
                "SESSION-fixture", binding, variant,
                lambda url, method, _navigation: url.startswith(base) and method == "GET",
                authenticated=False, request_cap=8, timeout_ms=8000,
            ) for variant in variants]
        finally:
            playwright.stop()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_missing_source_with_strict_origin_accepts_sibling(self) -> None:
        bundle = b"""
        const expectedParent = window.parent;
        window.addEventListener('message', event => {
          if (event.origin !== location.origin || event.data.type !== 'ACTIVATE') return;
          const port = event.ports[0];
          if (!port) return;
          port.onmessage = packet => {
            if (packet.data.method === 'readSynthetic')
              port.postMessage({type:'RESULT',value:'HACKBOT_SYNTHETIC_PRIVATE'});
          };
        });
        """
        trusted, sibling, foreign, fresh = self._browser_trials(bundle, (
            MessageVariant.TRUSTED, MessageVariant.WRONG_SOURCE,
            MessageVariant.ATTACKER_PORT, MessageVariant.FRESH_WRONG_SOURCE,
        ))
        self.assertTrue(trusted.capability_observed)
        self.assertTrue(sibling.capability_observed)
        self.assertEqual(sibling.source_relationship, "SIBLING_FRAME")
        self.assertTrue(sibling.source_attested)
        self.assertFalse(foreign.capability_observed)
        self.assertTrue(fresh.capability_observed)
        self.assertNotEqual(sibling.context_id, fresh.context_id)

    def test_strict_origin_and_source_reject_wrong_window(self) -> None:
        bundle = b"""
        window.addEventListener('message', event => {
          if (event.origin !== location.origin || event.source !== window.parent
              || event.data.type !== 'ACTIVATE') return;
          const port = event.ports[0];
          if (!port) return;
          port.onmessage = packet => {
            if (packet.data.method === 'readSynthetic')
              port.postMessage({type:'RESULT',value:'HACKBOT_SYNTHETIC_PRIVATE'});
          };
        });
        """
        trusted, sibling, foreign = self._browser_trials(bundle, (
            MessageVariant.TRUSTED, MessageVariant.WRONG_SOURCE,
            MessageVariant.ATTACKER_PORT,
        ))
        self.assertTrue(trusted.capability_observed)
        self.assertFalse(sibling.capability_observed)
        self.assertFalse(foreign.capability_observed)

    def test_substring_origin_accepts_unrelated_lookalike(self) -> None:
        bundle = b"""
        window.addEventListener('message', event => {
          if (!event.origin.includes('127.0.0.1') || event.data.type !== 'ACTIVATE') return;
          const port = event.ports[0];
          if (!port) return;
          port.onmessage = packet => {
            if (packet.data.method === 'readSynthetic')
              port.postMessage({type:'RESULT',value:'HACKBOT_SYNTHETIC_PRIVATE'});
          };
        });
        """
        trusted, unrelated, lookalike, fresh = self._browser_trials(bundle, (
            MessageVariant.TRUSTED, MessageVariant.ATTACKER_PORT,
            MessageVariant.LOOKALIKE_ORIGIN,
            MessageVariant.FRESH_LOOKALIKE_ORIGIN,
        ))
        self.assertTrue(trusted.capability_observed)
        self.assertFalse(unrelated.capability_observed)
        self.assertTrue(lookalike.capability_observed)
        self.assertIn(".attacker.fixture.invalid", lookalike.attacker_origin)
        self.assertTrue(fresh.capability_observed)
        self.assertNotEqual(lookalike.context_id, fresh.context_id)

    def test_prefix_origin_accepts_unrelated_lookalike(self) -> None:
        bundle = b"""
        window.addEventListener('message', event => {
          if (!event.origin.startsWith(location.protocol + '//' + location.hostname)
              || event.data.type !== 'ACTIVATE') return;
          const port = event.ports[0];
          if (!port) return;
          port.onmessage = packet => {
            if (packet.data.method === 'readSynthetic')
              port.postMessage({type:'RESULT',value:'HACKBOT_SYNTHETIC_PRIVATE'});
          };
        });
        """
        trusted, unrelated, lookalike = self._browser_trials(bundle, (
            MessageVariant.TRUSTED, MessageVariant.ATTACKER_PORT,
            MessageVariant.LOOKALIKE_ORIGIN,
        ), origin_probe_kind="STARTSWITH")
        self.assertTrue(trusted.capability_observed)
        self.assertFalse(unrelated.capability_observed)
        self.assertTrue(lookalike.capability_observed)
        self.assertTrue(lookalike.attacker_origin.startswith(
            "http://127.0.0.1.attacker.fixture.invalid:"))

    def test_suffix_origin_accepts_unrelated_lookalike(self) -> None:
        bundle = b"""
        window.addEventListener('message', event => {
          if (!event.origin.endsWith(location.host)
              || event.data.type !== 'ACTIVATE') return;
          const port = event.ports[0];
          if (!port) return;
          port.onmessage = packet => {
            if (packet.data.method === 'readSynthetic')
              port.postMessage({type:'RESULT',value:'HACKBOT_SYNTHETIC_PRIVATE'});
          };
        });
        """
        trusted, unrelated, lookalike = self._browser_trials(bundle, (
            MessageVariant.TRUSTED, MessageVariant.ATTACKER_PORT,
            MessageVariant.LOOKALIKE_ORIGIN,
        ), origin_probe_kind="ENDSWITH", host="localhost")
        self.assertTrue(trusted.capability_observed)
        self.assertFalse(unrelated.capability_observed)
        self.assertTrue(lookalike.capability_observed)
        self.assertTrue(lookalike.attacker_origin.endswith(trusted.attacker_origin.split('://')[1]))

    def test_two_stage_activation_then_port_and_controls(self) -> None:
        bundle = b"""
        window.addEventListener('message', event => {
          if (event.data.type === 'ACTIVATE') {
            event.source.postMessage({type:'READY'}, '*');
            return;
          }
          if (event.data.type !== 'CONNECT' || !event.ports[0]) return;
          const port = event.ports[0];
          port.onmessage = packet => {
            if (packet.data.method === 'readSynthetic')
              port.postMessage({type:'RESULT',value:'HACKBOT_SYNTHETIC_PRIVATE'});
          };
        });
        """
        no_message, wrong_type, no_port, attacker = self._browser_trials(bundle, (
            MessageVariant.NO_MESSAGE, MessageVariant.WRONG_TYPE,
            MessageVariant.NO_PORT, MessageVariant.ATTACKER_PORT,
        ), port_type="CONNECT")
        self.assertFalse(no_message.capability_observed)
        self.assertFalse(wrong_type.capability_observed)
        self.assertEqual(wrong_type.port_count, 1)
        self.assertEqual(wrong_type.rpc_calls, 1)
        self.assertFalse(no_port.capability_observed)
        self.assertTrue(attacker.capability_observed, repr(attacker))
        self.assertEqual(attacker.port_count, 1)
        self.assertEqual(attacker.rpc_calls, 1)
        events = [name for name, _ in attacker.event_trace]
        self.assertEqual(events[0], "SOURCE_ATTESTED")
        self.assertLess(events.index("MESSAGE_SENT"), events.index("READY_RECEIVED"))
        self.assertLess(events.index("READY_RECEIVED"), events.index("PORT_TRANSFERRED"))
        self.assertLess(events.index("PORT_TRANSFERRED"), events.index("RPC_SENT"))
        self.assertLess(events.index("RPC_SENT"), events.index("SYNTHETIC_MATCH"))
        self.assertEqual([name for name, _ in no_message.event_trace],
                         ["SOURCE_ATTESTED"])

    def test_owned_canary_is_matched_without_sending_it_in_the_message(self) -> None:
        canary = "hackbot-test-local-owned-001"
        bundle = b"""
        window.addEventListener('message', event => {
          if (event.data.type !== 'ACTIVATE' || !event.ports[0]) return;
          const port = event.ports[0];
          port.onmessage = packet => {
            if (packet.data.method === 'readCanary')
              port.postMessage({type:'RESULT',value:'hackbot-test-local-owned-001'});
          };
        });
        """
        binding = replace(self.binding("http://127.0.0.1:12345"),
                          allowed_method="readCanary", owned_canary_value=canary)
        fixture = PlaywrightBrowserDriver._message_fixture(
            binding, MessageVariant.ATTACKER_PORT).decode()
        self.assertIn("const ownedCanary=", fixture)
        self.assertIn("const message={type:kind}", fixture)
        self.assertNotIn("message.canary", fixture)
        no_message, wrong_type, trusted, attacker, fresh = self._browser_trials(
            bundle, (MessageVariant.NO_MESSAGE, MessageVariant.WRONG_TYPE,
                     MessageVariant.TRUSTED, MessageVariant.ATTACKER_PORT,
                     MessageVariant.FRESH_REPRODUCTION), owned_canary=canary)
        self.assertFalse(no_message.capability_observed)
        self.assertFalse(wrong_type.capability_observed)
        for trial in (trusted, attacker, fresh):
            self.assertTrue(trial.capability_observed)
            self.assertEqual(trial.effect_kind, "OWNED_DATA")
            self.assertEqual(trial.effect_fingerprint,
                             hashlib.sha256(canary.encode()).hexdigest())
            self.assertIn("OWNED_MATCH", [name for name, _ in trial.event_trace])

    def test_wrong_type_control_detects_type_agnostic_port_binding(self) -> None:
        bundle = b"""
        window.addEventListener('message', event => {
          const port = event.ports[0];
          if (!port) return;
          port.onmessage = packet => {
            if (packet.data.method === 'readSynthetic')
              port.postMessage({type:'RESULT',value:'HACKBOT_SYNTHETIC_PRIVATE'});
          };
        });
        """
        wrong_type, attacker = self._browser_trials(bundle, (
            MessageVariant.WRONG_TYPE, MessageVariant.ATTACKER_PORT))
        self.assertTrue(wrong_type.capability_observed)
        self.assertEqual(wrong_type.port_count, 1)
        self.assertEqual(wrong_type.rpc_calls, 1)
        self.assertTrue(attacker.capability_observed)

    def test_message_triggered_write_is_blocked_without_typed_disposable_binding(self) -> None:
        _Victim.write_attempts = 0
        bundle = b"""
        window.addEventListener('message', event => {
          if (event.data.type !== 'ACTIVATE') return;
          fetch('/mutable', {method:'PATCH', headers:{'Content-Type':'application/json'},
                             body:JSON.stringify({name:'hackbot-test-fixture'})});
        });
        """
        (attacker,) = self._browser_trials(bundle, (MessageVariant.ATTACKER_PORT,))
        self.assertTrue(attacker.source_attested)
        self.assertGreaterEqual(attacker.denial_count, 1)
        self.assertFalse(attacker.capability_observed)
        self.assertEqual(_Victim.write_attempts, 0)

    def test_popup_opener_works_when_framing_is_denied(self) -> None:
        bundle = b"""
        window.addEventListener('message', event => {
          if (event.data.type !== 'ACTIVATE') return;
          const port = event.ports[0];
          if (!port) return;
          port.onmessage = packet => {
            if (packet.data.method === 'readSynthetic')
              port.postMessage({type:'RESULT',value:'HACKBOT_SYNTHETIC_PRIVATE'});
          };
          window.opener.postMessage({type:'READY'}, '*');
        });
        """
        no_message, attacker = self._browser_trials(
            bundle, (MessageVariant.NO_MESSAGE, MessageVariant.ATTACKER_PORT),
            window_mode="POPUP", xfo="DENY",
            csp="default-src 'self'; frame-ancestors 'none'")
        self.assertFalse(no_message.capability_observed)
        self.assertTrue(attacker.capability_observed, repr(attacker))
        self.assertEqual(attacker.source_relationship, "FIXTURE_OPENER_OF_VICTIM")
        self.assertTrue(attacker.source_attested)
        self.assertEqual(attacker.x_frame_options, "DENY")
        self.assertEqual(attacker.frame_ancestors, "frame-ancestors 'none'")

    def test_message_to_dom_execution_uses_only_victim_marker(self) -> None:
        bundle = b"""
        window.addEventListener('message', event => {
          if (event.data.type !== 'PREVIEW') return;
          document.body.innerHTML = event.data.previewHtml;
        });
        """
        no_message, wrong_type, trusted, attacker, fresh = self._browser_trials(
            bundle, (MessageVariant.NO_MESSAGE, MessageVariant.WRONG_TYPE,
                     MessageVariant.TRUSTED, MessageVariant.UNRELATED,
                     MessageVariant.FRESH_REPRODUCTION), dom_field="previewHtml")
        self.assertFalse(no_message.capability_observed)
        self.assertFalse(wrong_type.capability_observed)
        self.assertTrue(trusted.capability_observed)
        self.assertTrue(attacker.capability_observed)
        self.assertEqual(attacker.effect_kind, "DOM_EXECUTION")
        self.assertEqual(attacker.marker_context, "IFRAME")
        self.assertTrue(attacker.document_origin.startswith("http://127.0.0.1:"))
        self.assertTrue(fresh.capability_observed)
        self.assertNotEqual(attacker.context_id, fresh.context_id)
        self.assertNotEqual(attacker.effect_fingerprint, fresh.effect_fingerprint)

    def test_sandboxed_target_url_is_not_treated_as_target_origin(self) -> None:
        bundle = b"""
        window.addEventListener('message', event => {
          if (event.data.type === 'PREVIEW')
            document.body.innerHTML = event.data.html;
        });
        """
        (attacker,) = self._browser_trials(
            bundle, (MessageVariant.UNRELATED,), dom_field="html", sandbox_victim=True)
        self.assertTrue(attacker.capability_observed, repr(attacker))
        self.assertEqual(attacker.effect_kind, "DOM_EXECUTION")
        self.assertEqual(attacker.document_origin, "null")


if __name__ == "__main__":
    unittest.main()
