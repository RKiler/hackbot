import hashlib
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.auth import AuthContextManager, AuthMechanism
from hackbot.browser import BrowserSessionManager, IdentityObservation, IdentityVerificationRule
from hackbot.config import BrowserSettings, SecretSettings, StoreSettings
from hackbot.domxss_store import DOMXSSStore
from hackbot.domain import TrafficSource
from hackbot.exposure import ExposureSpecialist
from hackbot.exposure_models import ExposureCategory, ExposureStatus
from hackbot.exposure_static import ExposureStaticAnalyzer, MAX_MAP_SCAN_BYTES
from hackbot.exposure_store import ExposureStore
from hackbot.identity import IdentityStatus
from hackbot.identity_registry import IdentityRegistry
from hackbot.secrets import RoutedSecretProvider
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package
from hackbot.traffic import CapturePacket, CapturedRequest, CapturedResponse, TrafficStore
from tests.test_traffic import FakeBrowser, NOW


EXAMPLE = Path(__file__).parent / "examples/targets/example"
SECRET = "F1xtureOnly-AppPassword-z94TaE8QvM6P"
URL = "https://app.example.test/static/app.js?token=private-fixture-query"


class ExposureStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.db_path = root / "state/bughunter.sqlite3"
        artifacts = root / "artifacts"
        self.evidence = EvidenceFactStore(self.db_path, ArtifactStore(artifacts), StoreSettings(artifacts))
        self.evidence.initialize()
        self.package = load_target_package(EXAMPLE)
        IdentityRegistry(self.evidence).register_target(self.package)
        self.dom = DOMXSSStore(self.evidence)
        self.ledger = ExposureStore(self.evidence)
        self.specialist = ExposureSpecialist(dom=self.dom, store=self.ledger)

    def asset(self, body: bytes, *, url: str = URL):
        return self.dom.record_artifact(
            target_id=self.package.target.id, asset_url=url, body=body,
            recon_asset_id=1, recon_sha256=hashlib.sha256(body).hexdigest(), source="FIXTURE")

    def test_js_secret_public_identifier_placeholder_and_internal_host(self) -> None:
        body = (f'const client_secret = "{SECRET}"; '
                'const NEXT_PUBLIC_API_KEY = "pk_live_PublicClientIdentifier987"; '
                'const password = "changeme"; '
                'const api = "http://10.10.0.5:8080/admin";').encode()
        asset = self.asset(body)
        result = self.specialist.analyze_js(self.package, asset.artifact_id, fixture_url=URL)
        self.assertEqual(result.signals, 4)
        candidates = self.ledger.list(self.package.target.id).items
        self.assertEqual({item.status for item in candidates}, {
            ExposureStatus.FORMAT_VALID, ExposureStatus.REJECTED_PUBLIC,
            ExposureStatus.REJECTED_PLACEHOLDER, ExposureStatus.NEEDS_RESEARCH})
        self.assertTrue(any(item.category is ExposureCategory.INTERNAL_HOST_DISCLOSURE
                            and "NO_EXTERNAL_REACHABILITY_PROOF" in item.reason_codes
                            for item in candidates))
        self.assertEqual(self.ledger.metrics(self.package.target.id)["validations"], {})
        for item in candidates:
            self.assertNotIn(SECRET, repr(item))
            self.assertNotIn(SECRET, json.dumps(item.public_dict()))
            self.assertNotIn("private-fixture-query", item.location)
        with sqlite3.connect(self.db_path) as db:
            serialized = "\n".join(str(row) for row in db.execute("SELECT candidate_json FROM exposure_candidates"))
        self.assertNotIn(SECRET, serialized)
        self.assertNotIn("10.10.0.5", serialized)

    def test_source_map_secret_and_public_config(self) -> None:
        asset = self.asset(b"console.log('fixture')")
        body = json.dumps({"version": 3, "sources": ["app.ts"], "sourcesContent": [
            f'export const config = {{ "client_secret": "{SECRET}", '
            '"NEXT_PUBLIC_API_KEY": "pk_live_PublicClientIdentifier987" }};'
        ]}).encode()
        self.dom.record_source_map(target_id=self.package.target.id, js_artifact_id=asset.artifact_id,
                                   map_url="https://app.example.test/static/app.js.map",
                                   body=body, source="FIXTURE")
        result = self.specialist.analyze_source_map(self.package, asset.artifact_id, fixture_url=URL)
        self.assertEqual(result.signals, 2)
        statuses = {item.status for item in self.ledger.list(self.package.target.id).items}
        self.assertEqual(statuses, {ExposureStatus.FORMAT_VALID, ExposureStatus.REJECTED_PUBLIC})
        self.assertTrue(all(item.category is ExposureCategory.SOURCE_MAP_SECRET
                            for item in self.ledger.list(self.package.target.id).items))
        self.assertEqual(ExposureStaticAnalyzer().analyze_source_map(b"invalid").parse_error, True)
        self.assertTrue(ExposureStaticAnalyzer().analyze_source_map(b"x" * (MAX_MAP_SCAN_BYTES + 1)).truncated)

    def test_standalone_credential_private_key_and_signed_url(self) -> None:
        body = (
            'const note = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"; '
            'const pem = `-----BEGIN PRIVATE KEY-----\n'
            'SYNTHETICFIXTUREONLYBASE64DATANOTAREALKEY0123456789\n'
            '-----END PRIVATE KEY-----`; '
            'const signed = "https://storage.example.test/file?X-Amz-Signature=synthetic-fixture";'
        ).encode()
        analysis = ExposureStaticAnalyzer().analyze_js(body)
        classes = {item.credential_type for item in analysis.signals}
        self.assertEqual(classes, {"KNOWN_FORMAT_TOKEN", "PRIVATE_KEY", "SIGNED_URL"})
        for signal in analysis.signals:
            self.assertEqual(len(signal.fingerprint_sha256), 64)
            self.assertNotIn("synthetic-fixture", repr(signal))

    def test_stale_hash_is_rejected_and_lead_invalidated(self) -> None:
        body = f'const client_secret = "{SECRET}";'.encode()
        asset = self.asset(body)
        result = self.specialist.analyze_js(self.package, asset.artifact_id, fixture_url=URL)
        self.assertEqual(result.signals, 1)
        self.assertEqual(self.ledger.mark_artifact_stale(self.package.target.id, asset.artifact_id), 1)
        candidate = self.ledger.get(self.package.target.id, result.candidate_ids[0])
        self.assertEqual(candidate.status, ExposureStatus.STALE)
        self.asset(b"const client_secret='changed-value-1234567890';")
        with self.assertRaises(ValueError):
            self.specialist.analyze_js(self.package, asset.artifact_id, fixture_url=URL)

    def test_deduplication_and_target_scoped_pagination(self) -> None:
        body = f'const client_secret = "{SECRET}";'.encode()
        first = self.asset(body, url="https://app.example.test/static/one.js")
        second = self.asset(body, url="https://app.example.test/static/two.js")
        one = self.specialist.analyze_js(self.package, first.artifact_id,
                                         fixture_url="https://app.example.test/static/one.js")
        two = self.specialist.analyze_js(self.package, second.artifact_id,
                                         fixture_url="https://app.example.test/static/two.js")
        self.assertEqual(one.candidate_ids, two.candidate_ids)
        self.assertEqual(len(self.ledger.source_links(self.package.target.id, one.candidate_ids[0])), 2)
        self.assertEqual(self.ledger.mark_artifact_stale(self.package.target.id, first.artifact_id), 0)
        self.assertEqual(self.ledger.list("TARGET-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").items, ())
        self.assertEqual(len(self.ledger.list(self.package.target.id, limit=1).items), 1)
        with self.assertRaises(ValueError):
            self.ledger.list(self.package.target.id, cursor="invalid")

    def test_repeated_secret_uses_new_current_artifact_hash(self) -> None:
        first = self.asset(f'const client_secret="{SECRET}";'.encode(),
                           url="https://app.example.test/static/first.js")
        initial = self.specialist.analyze_js(
            self.package, first.artifact_id,
            fixture_url="https://app.example.test/static/first.js")
        self.assertEqual(self.ledger.mark_artifact_stale(
            self.package.target.id, first.artifact_id), 1)
        second = self.asset(f'/* updated */ const client_secret="{SECRET}";'.encode(),
                            url="https://app.example.test/static/second.js")
        updated = self.specialist.analyze_js(
            self.package, second.artifact_id,
            fixture_url="https://app.example.test/static/second.js")
        self.assertEqual(initial.candidate_ids, updated.candidate_ids)
        candidate = self.ledger.get(self.package.target.id, updated.candidate_ids[0])
        self.assertEqual(candidate.artifact_sha256, second.artifact_sha256)
        self.assertEqual(candidate.endpoint_or_asset, second.artifact_id)
        self.assertNotEqual(candidate.status, ExposureStatus.STALE)

    def test_no_network_or_credential_login_surface(self) -> None:
        self.assertFalse(hasattr(self.specialist, "login"))
        self.assertFalse(hasattr(self.specialist, "fetch"))
        self.assertFalse(hasattr(self.specialist, "probe_host"))

    def test_observed_admin_route_is_a_lead_without_path_scanning(self) -> None:
        calls = []

        class LocalRecon:
            def resolve_target(self, domain):
                return SimpleNamespace(domain_id=7)

            def list_scan_snapshots(self, domain_id, *, limit):
                return SimpleNamespace(items=())

            def list_hosts(self, domain_id, *, limit):
                return SimpleNamespace(items=(
                    SimpleNamespace(host_id=4, url="https://app.example.test/"),
                    SimpleNamespace(host_id=5, url="https://other.invalid/")))

            def list_endpoints(self, domain_id, host_id, *, limit):
                calls.append(host_id)
                return SimpleNamespace(items=(SimpleNamespace(
                    endpoint_id=21, path="/admin", method="GET", status_code=200),))

        specialist = ExposureSpecialist(dom=self.dom, store=self.ledger,
                                        recon=LocalRecon())
        result = specialist.discover_recon(self.package)
        self.assertEqual(calls, [4])
        self.assertEqual(result.signals, 1)
        candidate = self.ledger.get(self.package.target.id, result.candidate_ids[0])
        self.assertEqual(candidate.category, ExposureCategory.ADMIN_SURFACE)
        self.assertEqual(candidate.status, ExposureStatus.CANDIDATE)
        self.assertEqual(self.ledger.validation_state(self.package.target.id,
                                                      candidate.candidate_id), "UNVALIDATED")
        repeated = specialist.discover_recon(self.package)
        self.assertEqual(repeated.candidate_ids, result.candidate_ids)
        self.assertEqual(calls, [4, 4])
        self.assertEqual(len(self.ledger.source_links(self.package.target.id,
                                                      candidate.candidate_id)), 1)
        with sqlite3.connect(self.db_path) as db:
            count = db.execute("SELECT COUNT(*) FROM evidence WHERE source='exposure_recon_pointer'").fetchone()[0]
        self.assertEqual(count, 1)

    def test_traffic_owner_anonymous_private_field_is_a_lead_not_finding(self) -> None:
        registry = IdentityRegistry(self.evidence)
        traffic = TrafficStore(self.evidence, registry)
        driver = FakeBrowser()
        auth = AuthContextManager(registry, RoutedSecretProvider(SecretSettings(), {}))
        browser = BrowserSessionManager(
            registry, auth, driver, BrowserSettings(profile_root=Path(self.temp.name) / "profiles"))
        identity = registry.register_identity(self.package.target.id, "fixture_owner",
                                              status=IdentityStatus.ACTIVE)
        auth.prepare(self.package.target.id, identity.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        session = browser.create(self.package.target.id, identity.id)
        browser.start(session.id)
        browser.login_complete(session.id)
        driver.observations[session.id] = IdentityObservation(user_id="fixture_owner", tenant_id="fixture_tenant")
        browser.verify(session.id, IdentityVerificationRule(
            self.package.target.id, identity.id, "[data-user]", None, "[data-tenant]",
            "fixture_owner", None, "fixture_tenant"))
        body = b'{"email":"owned-fixture@example.test","user_id":"fixture-user"}'
        url = "https://app.example.test/api/profile/fixture-user"

        def packet(session_id):
            return CapturePacket(
                CapturedRequest("GET", url, (("Accept", "application/json"),), None, NOW),
                CapturedResponse(200, (("Content-Type", "application/json"),), body, NOW),
                browser_session_id=session_id, provider_reference="exposure-fixture")

        traffic.store_exchange(self.package, packet(session.id), source=TrafficSource.FIXTURE,
                               capture_provider="LOCAL_FIXTURE", browser_manager=browser)
        traffic.store_exchange(self.package, packet(None), source=TrafficSource.FIXTURE,
                               capture_provider="LOCAL_FIXTURE", anonymous=True)
        specialist = ExposureSpecialist(dom=self.dom, store=self.ledger, traffic=traffic)
        result = specialist.discover_traffic(self.package)
        self.assertEqual(result.signals, 1)
        candidate = self.ledger.get(self.package.target.id, result.candidate_ids[0])
        self.assertEqual(candidate.category, ExposureCategory.PII_EXPOSURE)
        self.assertEqual(candidate.status, ExposureStatus.NEEDS_MANUAL_REVIEW)
        self.assertEqual(candidate.pii_categories, ("ACCOUNT_METADATA", "EMAIL"))
        self.assertNotIn("owned-fixture@example.test", json.dumps(candidate.public_dict()))
