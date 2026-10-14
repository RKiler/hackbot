"""Phase 9 uses fictional data and a local fake browser; no target traffic."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from io import StringIO
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.auth import AuthContextManager, AuthMechanism
from hackbot.browser import (BrowserSessionManager, IdentityObservation, IdentityVerificationRule)
from hackbot.cli import main
from hackbot.config import BrowserSettings, SecretSettings, StoreSettings
from hackbot.domain import ObservationState, Principal, Role, Tenant, TrafficSource, new_entity_id
from hackbot.evidence import EvidenceProvenance, EvidenceType, RedactionStatus, Retention, Sensitivity
from hackbot.identity import IdentityStatus, MembershipStatus
from hackbot.identity_registry import IdentityRegistry
from hackbot.secrets import RoutedSecretProvider
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package
from hackbot.target_scope import ScopeResult
from hackbot.traffic import (AuthState, CapturePacket, CapturedRequest, CapturedResponse,
                             ExchangeState, TrafficError, TrafficStore)


NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
EXAMPLE = Path(__file__).parent / "examples/targets/example"
SECRET_VALUES = ("bearer-very-secret", "cookie-very-secret", "api-key-very-secret",
                 "session-very-secret", "password-very-secret", "response-pii-very-secret")


class FakeBrowser:
    name = "FIXTURE"

    def __init__(self):
        self.running = set()
        self.observations = {}

    def start(self, session_id, profile, *, display, proxy):
        self.running.add(session_id)

    def stop(self, session_id):
        self.running.discard(session_id)

    def is_running(self, session_id):
        return session_id in self.running

    def apply_imported_session(self, session_id, material, allowed_url):
        raise AssertionError("No imported session is used in traffic fixtures")

    def observe_identity(self, session_id, rule):
        return self.observations.get(session_id, IdentityObservation())


class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.blobs = self.root / "blobs"
        self.db = self.root / "state/bughunter.sqlite3"
        self.evidence = EvidenceFactStore(self.db, ArtifactStore(self.blobs),
                                          StoreSettings(self.blobs, max_page_size=3))
        self.registry = IdentityRegistry(self.evidence)
        self.registry.initialize()
        self.package = load_target_package(EXAMPLE)
        self.registry.register_target(self.package)
        self.target = self.package.target.id
        self.traffic = TrafficStore(self.evidence, self.registry)
        self.driver = FakeBrowser()
        self.auth = AuthContextManager(self.registry, RoutedSecretProvider(SecretSettings(), {}))
        self.browser = BrowserSessionManager(
            self.registry, self.auth, self.driver,
            BrowserSettings(profile_root=self.root / "browser-profiles"),
        )

    def tearDown(self):
        self.temp.cleanup()

    def packet(self, *, url="https://app.example.test/api/v1/projects?id=123", method="GET",
               body=None, response_body=b'{"ok":true}', endpoint_id=None, operation_id=None,
               session_id=None):
        return CapturePacket(
            CapturedRequest(method, url, (("Accept", "application/json"),), body, NOW,
                            "HTTP/2", endpoint_id, operation_id),
            CapturedResponse(200, (("Content-Type", "application/json"),), response_body,
                             NOW + timedelta(milliseconds=8), 8, "HTTP/2"),
            browser_session_id=session_id, correlation_id="action-42", provider_reference="fixture-42",
        )

    def capture(self, packet=None, *, source=TrafficSource.FIXTURE, manager=None, declared=None):
        selected = packet or self.packet()
        return self.traffic.store_exchange(
            self.package, selected, source=source,
            capture_provider="LOCAL_FIXTURE", browser_manager=manager,
            declared_identity_id=declared,
            anonymous=selected.browser_session_id is None and declared is None,
        )

    def session(self, alias, *, user=None, expected=None, tenant="tenant-a"):
        identity = self.registry.register_identity(self.target, alias, status=IdentityStatus.ACTIVE)
        self.auth.prepare(self.target, identity.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        session = self.browser.create(self.target, identity.id)
        self.browser.start(session.id)
        self.browser.login_complete(session.id)
        self.driver.observations[session.id] = IdentityObservation(user_id=user or alias, tenant_id=tenant)
        rule = IdentityVerificationRule(self.target, identity.id, "[data-user]", None, "[data-tenant]",
                                        expected or alias, None, tenant)
        self.browser.verify(session.id, rule)
        return identity, session

    def test_complete_request_response_and_protected_evidence(self):
        exchange = self.capture()
        self.assertEqual((exchange.state, exchange.scope_result), (ExchangeState.COMPLETE, ScopeResult.IN_SCOPE))
        self.assertEqual(exchange.attribution.auth_state, AuthState.ANONYMOUS)
        self.assertEqual(exchange.request.record.source, TrafficSource.FIXTURE)
        self.assertIsNone(exchange.request.record.url)
        self.assertEqual(exchange.response.record.status_code, 200)
        self.assertEqual(exchange.response.record.content_type, "application/json")
        self.assertEqual(len(exchange.evidence_ids), 3)
        self.assertEqual(self.traffic.get_request(exchange.request.record.id), exchange.request)
        self.assertEqual(self.traffic.get_response(exchange.response.record.id), exchange.response)
        self.assertEqual(self.traffic.get_exchange(exchange.id), exchange)
        with self.assertRaises(PermissionError):
            self.evidence.read_content(exchange.response.body_evidence_id)
        self.assertEqual(self.evidence.read_content(exchange.response.body_evidence_id,
                                                    allow_sensitive=True), b'{"ok":true}')
        self.assertEqual(self.evidence.get_evidence(exchange.response.body_evidence_id).sensitivity,
                         Sensitivity.SECRET)

    def test_request_only_timeout_abort_and_failed_response(self):
        packet = CapturePacket(CapturedRequest("GET", "https://app.example.test/status", observed_at=NOW))
        first = self.capture(packet)
        self.assertIsNone(first.response)
        self.assertEqual(first.state, ExchangeState.REQUEST_ONLY)
        self.assertEqual(self.traffic.mark_incomplete(first.id, ExchangeState.TIMEOUT).state,
                         ExchangeState.TIMEOUT)
        self.assertIsNotNone(self.traffic.get_exchange(first.id).request.observation_evidence_id)
        with self.assertRaises(TrafficError):
            self.traffic.store_response(first.id, CapturedResponse(200))
        for state in (ExchangeState.FAILED, ExchangeState.ABORTED):
            item = self.capture(packet)
            self.assertEqual(self.traffic.mark_incomplete(item.id, state).state, state)

    def test_verified_unverified_wrong_and_anonymous_browser_attribution(self):
        identity, session = self.session("org1_admin")
        verified = self.capture(self.packet(session_id=session.id), source=TrafficSource.BROWSER,
                                manager=self.browser)
        self.assertEqual(verified.attribution.auth_state, AuthState.VERIFIED)
        self.assertEqual(verified.attribution.verified_identity_id, identity.id)
        self.assertEqual(verified.attribution.browser_session_id, session.id)
        self.assertIsNotNone(verified.attribution.auth_context_id)
        wrong, wrong_session = self.session("wrong_identity", user="other-user")
        result = self.capture(self.packet(session_id=wrong_session.id), source=TrafficSource.BROWSER,
                              manager=self.browser)
        self.assertEqual(result.attribution.auth_state, AuthState.UNVERIFIED_IDENTITY)
        self.assertEqual(result.attribution.declared_identity_id, wrong.id)
        self.assertIsNone(result.attribution.verified_identity_id)
        self.assertIsNone(result.attribution.principal_id)
        pending = self.registry.register_identity(self.target, "pending", status=IdentityStatus.ACTIVE)
        self.auth.prepare(self.target, pending.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        pending_session = self.browser.create(self.target, pending.id)
        self.browser.start(pending_session.id)
        pending_exchange = self.capture(self.packet(session_id=pending_session.id),
                                        source=TrafficSource.BROWSER, manager=self.browser)
        self.assertEqual(pending_exchange.attribution.auth_state, AuthState.UNVERIFIED_IDENTITY)
        anonymous_session = self.browser.create(self.target)
        self.browser.start(anonymous_session.id)
        anonymous = self.capture(self.packet(session_id=anonymous_session.id),
                                 source=TrafficSource.BROWSER, manager=self.browser)
        self.assertEqual(anonymous.attribution.auth_state, AuthState.ANONYMOUS)
        self.assertIsNone(anonymous.attribution.declared_identity_id)
        self.assertEqual(anonymous.attribution.browser_session_id, anonymous_session.id)

    def test_multiple_identity_tenant_role_metadata_and_separate_queries(self):
        tenant_a = self.registry.register_tenant(Tenant(target_id=self.target, label="tenant_a", kind="company"))
        tenant_b = self.registry.register_tenant(Tenant(target_id=self.target, label="tenant_b", kind="company"))
        admin_role = self.registry.register_role(Role(target_id=self.target, name="admin"))
        member_role = self.registry.register_role(Role(target_id=self.target, name="member"))
        records = []
        for alias, memberships in (
            ("org1_admin", ((tenant_a.id, admin_role.id), (tenant_b.id, member_role.id))),
            ("org1_member", ((tenant_a.id, member_role.id),)),
            ("org2_admin", ((tenant_b.id, admin_role.id),)),
        ):
            identity, session = self.session(alias, tenant="tenant-a" if alias != "org2_admin" else "tenant-b")
            for tenant_id, role_id in memberships:
                self.registry.add_membership(identity.id, tenant_id, role_ids=(role_id,),
                                             status=MembershipStatus.ACTIVE)
            exchange = self.capture(self.packet(session_id=session.id), source=TrafficSource.BROWSER,
                                    manager=self.browser)
            records.append((identity, session, exchange))
        self.assertEqual(set(records[0][2].attribution.declared_tenant_ids), {tenant_a.id, tenant_b.id})
        self.assertEqual(set(records[0][2].attribution.declared_role_ids), {admin_role.id, member_role.id})
        for identity, session, exchange in records:
            self.assertEqual(self.traffic.list_exchanges_for_identity(self.target, identity.id).items[0].id,
                             exchange.id)
            self.assertEqual(self.traffic.list_exchanges_for_session(self.target, session.id).items[0].id,
                             exchange.id)
        self.assertEqual(self.traffic.list_anonymous(self.target).items, ())

    def test_observed_principal_only_and_configured_principal_not_trusted(self):
        principal = self.registry.register_principal(Principal(target_id=self.target, label="owned_actor"))
        configured = self.registry.register_identity(self.target, "configured", status=IdentityStatus.ACTIVE,
                                                     principal_id=principal.id)
        self.auth.prepare(self.target, configured.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        session = self.browser.create(self.target, configured.id)
        self.browser.start(session.id)
        self.browser.login_complete(session.id)
        self.driver.observations[session.id] = IdentityObservation(user_id="configured", tenant_id="tenant-a")
        self.browser.verify(session.id, IdentityVerificationRule(
            self.target, configured.id, "[data-user]", None, "[data-tenant]",
            "configured", None, "tenant-a"))
        first = self.capture(self.packet(session_id=session.id), source=TrafficSource.BROWSER,
                             manager=self.browser)
        self.assertIsNone(first.attribution.principal_id)
        proof = self.evidence.create_evidence(
            EvidenceType.AUTH_OBSERVATION, b"synthetic identity proof", source="FIXTURE",
            provenance=EvidenceProvenance("FIXTURE", "identity", "owned", NOW),
            target_ref=self.target, sensitivity=Sensitivity.SECRET,
        )
        fact = self.evidence.create_fact(configured.id, "resolves_to", principal.id,
                                         confidence=1.0, evidence_ids=(proof.evidence_id,),
                                         source="FIXTURE", target_ref=self.target)
        self.registry.link_principal(configured.id, principal.id,
                                     observation_state=ObservationState.OBSERVED,
                                     evidence_ids=(proof.evidence_id,), fact_id=fact.fact_id)
        second = self.capture(self.packet(session_id=session.id), source=TrafficSource.BROWSER,
                              manager=self.browser)
        self.assertEqual(second.attribution.principal_id, principal.id)
        self.assertEqual(second.request.record.principal_id, principal.id)
        self.assertEqual(self.traffic.get_request(second.request.record.id).record.principal_id, principal.id)

    def test_target_scope_and_cross_target_browser_rejected(self):
        excluded = self.capture(self.packet(url="https://billing.example.test/status"))
        unknown = self.capture(self.packet(url="https://outside.invalid/status"))
        self.assertEqual(excluded.scope_result, ScopeResult.OUT_OF_SCOPE)
        self.assertEqual(unknown.scope_result, ScopeResult.UNKNOWN)
        self.assertIsNotNone(unknown.request.observation_evidence_id)
        other = self.registry.register_identity(self.target, "other", status=IdentityStatus.ACTIVE)
        self.auth.prepare(self.target, other.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        session = self.browser.create(self.target, other.id)
        with self.assertRaises(TrafficError):
            self.traffic.store_request(self.package, CapturedRequest("GET", "https://app.example.test/"),
                                       source=TrafficSource.BROWSER, capture_provider="FIXTURE",
                                       browser_session_id=new_entity_id("BSESSION"), browser_manager=self.browser)

    def test_secret_metadata_artifact_and_cli_safety(self):
        request = CapturedRequest(
            "POST", "https://app.example.test/api/login?token=session-very-secret&mode=fast",
            (("Authorization", "Bearer bearer-very-secret"), ("Cookie", "sid=cookie-very-secret"),
             ("X-API-Key", "api-key-very-secret"), ("Content-Type", "application/json")),
            b'{"password":"password-very-secret"}', NOW,
        )
        response = CapturedResponse(200, (("Set-Cookie", "sid=abc"),), b"response-pii-very-secret", NOW)
        exchange = self.capture(CapturePacket(request, response))
        self.assertEqual(exchange.attribution.auth_state, AuthState.UNVERIFIED_IDENTITY)
        output = repr(exchange) + json.dumps(exchange.to_dict()) + repr(request) + repr(response)
        self.assertNotIn("authorization", output.lower())
        self.assertNotIn("cookie", output.lower())
        for secret in SECRET_VALUES:
            self.assertNotIn(secret, output)
            self.assertNotIn(secret.encode(), self.db.read_bytes())
        observation = self.evidence.read_content(exchange.request.observation_evidence_id,
                                                  allow_sensitive=True)
        self.assertIn(b"[AUTH_CONTEXT]", observation)
        self.assertNotIn(b"session-very-secret", observation)
        self.assertNotIn(b"bearer-very-secret", observation)
        retained = self.evidence.read_content(exchange.request.body_evidence_id, allow_sensitive=True)
        self.assertEqual(retained, b"[WITHHELD: credential-like body]")
        self.assertEqual(self.evidence.get_evidence(exchange.request.body_evidence_id).redaction_status,
                         RedactionStatus.WITHHELD)
        self.assertEqual(exchange.request.body_hash, hashlib.sha256(request.body).hexdigest())
        self.assertEqual(exchange.request.body_size, len(request.body))
        self.assertNotEqual(exchange.request.body_hash, exchange.request.record.artifact_hash)
        blobs = b"".join(path.read_bytes() for path in self.blobs.rglob("*") if path.is_file())
        for secret in SECRET_VALUES[:-1]:
            self.assertNotIn(secret.encode(), blobs)
        self.assertEqual(self.evidence.get_evidence(exchange.response.body_evidence_id).sensitivity,
                         Sensitivity.SECRET)
        config = self.root / "config.toml"
        config.write_text(f'[paths]\nroot = "{self.root}"\n[targets]\nroot = "{EXAMPLE.parent}"\n'
                          f'[store]\nartifact_root = "{self.blobs}"\n')
        for args in (("traffic", "list", "example"), ("traffic", "show", exchange.id),
                     ("traffic", "stats", "example")):
            out, err = StringIO(), StringIO()
            code = main(["--config", str(config), *args], environ={"HOME": str(self.root)},
                        stdout=out, stderr=err)
            self.assertEqual((code, err.getvalue()), (0, ""))
            for secret in SECRET_VALUES:
                self.assertNotIn(secret, out.getvalue())

    def test_body_dedup_hash_and_retention(self):
        retention = Retention(retain=True, expires_at=NOW + timedelta(days=30), pinned=True)
        packet = self.packet(body=b"same synthetic request body", response_body=b"same synthetic response body")
        first = self.traffic.store_exchange(self.package, packet, source=TrafficSource.FIXTURE,
                                            capture_provider="FIXTURE", retention=retention)
        second = self.traffic.store_exchange(self.package, packet, source=TrafficSource.FIXTURE,
                                             capture_provider="FIXTURE", retention=retention)
        self.assertEqual(first.request.body_hash, second.request.body_hash)
        self.assertEqual(first.response.record.artifact_hash, second.response.record.artifact_hash)
        self.assertEqual(len(list(self.blobs.rglob(first.request.body_hash))), 1)
        self.assertTrue(first.retention.pinned)
        self.assertTrue(first.retention.finding_related is False)

    def test_fingerprint_structure_and_sensitive_values(self):
        one = self.capture(self.packet(url="https://app.example.test/api/users?token=one&id=1"))
        two = self.capture(self.packet(url="https://app.example.test/api/users?token=two&id=2"))
        path = self.capture(self.packet(url="https://app.example.test/api/projects?token=one&id=1"))
        method = self.capture(self.packet(url="https://app.example.test/api/users?token=one&id=1", method="POST"))
        params = self.capture(self.packet(url="https://app.example.test/api/users?token=one&other=1"))
        self.assertEqual(one.request.structural_fingerprint, two.request.structural_fingerprint)
        self.assertNotEqual(one.request.structural_fingerprint, path.request.structural_fingerprint)
        self.assertNotEqual(one.request.structural_fingerprint, method.request.structural_fingerprint)
        self.assertNotEqual(one.request.structural_fingerprint, params.request.structural_fingerprint)
        self.assertEqual(one.request.display_path, "/api/users")
        matches = self.traffic.find_by_fingerprint(self.target, one.request.structural_fingerprint)
        self.assertEqual({item.id for item in matches.items}, {one.id, two.id})
        encoded = self.capture(self.packet(url="https://app.example.test/API/%2F?token=one"))
        plain = self.capture(self.packet(url="https://app.example.test/API//?token=one"))
        self.assertNotEqual(encoded.request.structural_fingerprint, plain.request.structural_fingerprint)
        self.assertNotEqual(encoded.request.display_path, plain.request.display_path)

    def test_sources_and_correlations_are_vendor_neutral(self):
        for source in (TrafficSource.BURP, TrafficSource.HACKBOT, TrafficSource.HAR_IMPORT,
                       TrafficSource.MANUAL_IMPORT, TrafficSource.IMPORT, TrafficSource.FIXTURE):
            item = self.capture(source=source)
            self.assertEqual(item.source, source)
            self.assertEqual(item.capture_provider, "LOCAL_FIXTURE")
            self.assertEqual(item.attribution.auth_state, AuthState.ANONYMOUS)
        page = self.traffic.find_by_correlation(self.target, "action-42")
        self.assertEqual(len(page.items), 3)
        self.assertEqual(self.traffic.find_by_browser_action(self.target, "missing").items, ())
        self.assertNotIn("action-42", self.db.read_bytes().decode("latin1"))

    def test_unknown_import_is_not_implicitly_anonymous(self):
        packet = self.packet(url="https://app.example.test/api/users?id=123")
        unknown = self.traffic.store_exchange(self.package, packet, source=TrafficSource.HAR_IMPORT,
                                              capture_provider="LOCAL_FIXTURE")
        self.assertEqual(unknown.attribution.auth_state, AuthState.UNVERIFIED_IDENTITY)
        with_cookie = CapturePacket(CapturedRequest(
            "GET", "https://app.example.test/api/users", (("Cookie", "sid=synthetic"),), observed_at=NOW))
        declared_anonymous = self.traffic.store_exchange(
            self.package, with_cookie, source=TrafficSource.HAR_IMPORT,
            capture_provider="LOCAL_FIXTURE", anonymous=True)
        self.assertEqual(declared_anonymous.attribution.auth_state, AuthState.UNVERIFIED_IDENTITY)
        verified_anonymous = self.traffic.store_exchange(
            self.package, packet, source=TrafficSource.HAR_IMPORT,
            capture_provider="LOCAL_FIXTURE", anonymous=True)
        self.assertEqual(verified_anonymous.attribution.auth_state, AuthState.ANONYMOUS)
        semicolon = self.capture(self.packet(url="https://app.example.test/api/users?mode=fast;token=private"))
        observation = self.evidence.read_content(semicolon.request.observation_evidence_id,
                                                  allow_sensitive=True)
        self.assertNotIn(b"private", observation)
        self.assertEqual(semicolon.request.query_names, ("mode", "token"))
        anonymous_session = self.browser.create(self.target)
        self.browser.start(anonymous_session.id)
        browser_cookie = self.capture(CapturePacket(with_cookie.request, browser_session_id=anonymous_session.id),
                                      source=TrafficSource.BROWSER, manager=self.browser)
        self.assertEqual(browser_cookie.attribution.auth_state, AuthState.UNVERIFIED_IDENTITY)

    def test_credential_response_body_withheld_but_hash_retained(self):
        raw = b'{"access_token":"synthetic-do-not-store"}'
        item = self.capture(self.packet(response_body=raw))
        evidence = self.evidence.get_evidence(item.response.body_evidence_id)
        self.assertEqual(evidence.redaction_status, RedactionStatus.WITHHELD)
        self.assertEqual(item.response.body_hash, hashlib.sha256(raw).hexdigest())
        self.assertNotEqual(item.response.body_hash, item.response.record.artifact_hash)
        self.assertNotIn(b"synthetic-do-not-store", b"".join(
            path.read_bytes() for path in self.blobs.rglob("*") if path.is_file()))

    def test_other_token_names_are_withheld_from_protected_artifacts(self):
        for key in ("jwt", "authToken", "id_token", "secretValue", "credential"):
            raw = ('{"' + key + '":"synthetic-do-not-store"}').encode()
            item = self.capture(self.packet(body=raw, response_body=raw))
            self.assertEqual(self.evidence.get_evidence(item.request.body_evidence_id).redaction_status,
                             RedactionStatus.WITHHELD)
            self.assertEqual(self.evidence.get_evidence(item.response.body_evidence_id).redaction_status,
                             RedactionStatus.WITHHELD)
        self.assertNotIn(b"synthetic-do-not-store", b"".join(
            path.read_bytes() for path in self.blobs.rglob("*") if path.is_file()))

    def test_capture_errors_are_secret_safe(self):
        secret = "secret-error-sentinel"
        with self.assertRaises(TrafficError) as captured:
            CapturedRequest("GET", "https://app.example.test/", (("Cookie", secret + "\n"),))
        self.assertNotIn(secret, str(captured.exception))
        with self.assertRaises(TrafficError) as captured:
            CapturedRequest("GET", "https://app.example.test/?token=" + secret + "#fragment")
        self.assertNotIn(secret, str(captured.exception))

    def test_pagination_filters_recent_stats_and_reopen(self):
        endpoint_id, operation_id = new_entity_id("ENDPOINT"), new_entity_id("GQL")
        records = [self.capture(self.packet(endpoint_id=endpoint_id, operation_id=operation_id))
                   for _ in range(7)]
        page = self.traffic.list_exchanges_for_target(self.target, limit=2)
        self.assertEqual(len(page.items), 2)
        self.assertIsNotNone(page.next_cursor)
        self.assertEqual(len(self.traffic.list_exchanges_for_target(self.target, limit=100).items), 3)
        self.assertEqual(len(self.traffic.find_by_endpoint(self.target, endpoint_id).items), 3)
        self.assertEqual(len(self.traffic.find_by_operation(self.target, operation_id).items), 3)
        self.assertEqual(len(self.traffic.find_recent(self.target, since=NOW).items), 3)
        seen = []
        cursor = None
        while True:
            page = self.traffic.list_exchanges_for_target(self.target, limit=2, cursor=cursor)
            seen.extend(item.id for item in page.items)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        self.assertEqual(set(seen), {item.id for item in records})
        with self.assertRaises(TrafficError):
            self.traffic.list_anonymous(self.target, cursor=cursor)
        stats = self.traffic.stats(self.target, sample_limit=4)
        self.assertEqual(stats["sample_count"], 4)
        self.assertTrue(stats["truncated"])
        reopened = TrafficStore(EvidenceFactStore(self.db, ArtifactStore(self.blobs),
                                                  self.evidence.settings))
        self.assertEqual(reopened.get_exchange(records[0].id), records[0])

    def test_schema_indexes_migration_and_no_production_dependency(self):
        with sqlite3.connect(self.db) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 34)
            indexes = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'traffic_%'")}
            for name in ("traffic_exchanges_target_recent_idx", "traffic_exchanges_identity_recent_idx",
                         "traffic_exchanges_session_recent_idx", "traffic_exchanges_endpoint_recent_idx",
                         "traffic_exchanges_operation_recent_idx", "traffic_requests_target_fingerprint_idx",
                         "traffic_exchanges_fingerprint_recent_idx"):
                self.assertIn(name, indexes)
            plan = connection.execute("EXPLAIN QUERY PLAN SELECT exchange_id FROM traffic_exchanges "
                                      "WHERE target_id=? ORDER BY observed_at DESC,exchange_id DESC LIMIT 5",
                                      (self.target,)).fetchall()
        self.assertIn("traffic_exchanges_target_recent_idx", str(plan))
        self.traffic.initialize()
        with sqlite3.connect(self.db) as connection:
            for table in ("api_inventory_progress", "api_specialist_runs", "api_candidates", "api_operations"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("behaviour_observations", "behaviour_workflows", "behaviour_expectations",
                          "behaviour_profiles", "behaviour_runs", "bootstrap_observations",
                          "bootstrap_discovery_states", "bootstrap_runs"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("exposure_candidate_sources", "exposure_candidate_events",
                          "exposure_candidates"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("message_runtime_trials", "message_candidate_events",
                          "message_type_index", "message_candidate_assets",
                          "message_protocol_candidates", "message_analysis_runs",
                          "plan_message_dispatches"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("dom_candidate_events", "plan_dom_dispatches", "dom_flow_candidates",
                          "dom_analysis_runs", "dom_source_maps", "dom_js_artifacts"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("DROP TABLE authorization_mutation_results")
            for table in ("authorization_hunt_objects", "authorization_observations",
                          "authorization_hunt_candidates", "authorization_candidates",
                          "authorization_hunts"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("finding_status_events", "finding_duplicates", "finding_locations",
                          "finding_evidence", "findings", "validation_checks", "validations"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("plan_object_requirements", "test_object_operations",
                          "test_object_reservations", "test_object_events", "test_objects"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("plan_run_events", "plan_step_manual_links", "plan_step_results",
                          "plan_run_steps", "plan_runs"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("executor_events", "executor_permits"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("policy_events", "policy_approvals", "policy_decisions", "policy_actions"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("DROP TABLE skill_plan_selections")
            connection.execute("DROP TABLE skill_plans")
            for table in ("hypothesis_relationships", "hypothesis_events", "hypothesis_facts",
                          "hypothesis_evidence", "hypotheses", "profile_source_evidence", "target_profiles"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("DROP INDEX facts_target_recent_idx")
            connection.execute("DROP TABLE service_events")
            for table in ("burp_capture_index", "burp_listener_bindings", "burp_projects", "burp_bridge_health"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("DROP TABLE traffic_exchanges")
            connection.execute("DROP TABLE traffic_responses")
            connection.execute("DROP TABLE traffic_requests")
            connection.execute("ALTER TABLE browser_sessions DROP COLUMN proxy_capture_required")
            connection.execute("PRAGMA user_version=4")
        self.traffic.initialize()
        with sqlite3.connect(self.db) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 34)
            self.assertEqual(connection.execute("SELECT package_id FROM registry_targets WHERE target_id=?",
                                                (self.target,)).fetchone()[0], self.package.id)


if __name__ == "__main__":
    unittest.main()
