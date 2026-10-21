"""Local-only captured JavaScript inventory; no target network traffic."""

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.api_registry import APIOperationRegistry
from hackbot.api_specialist import APISpecialist
from hackbot.auth import AuthContextManager, AuthMechanism
from hackbot.browser import (BrowserProxyConfig, BrowserSessionManager,
                             IdentityObservation, IdentityVerificationRule)
from hackbot.captured_js import CapturedJSCollector
from hackbot.config import BrowserSettings, SecretSettings, StoreSettings
from hackbot.domain import TrafficSource
from hackbot.domxss_static import DOMStaticAnalyzer
from hackbot.domxss_store import DOMXSSStore
from hackbot.evidence import RedactionStatus
from hackbot.identity_registry import IdentityRegistry, IdentityStatus
from hackbot.secrets import RoutedSecretProvider
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package
from hackbot.traffic import (CapturePacket, CapturedRequest, CapturedResponse,
                             TrafficStore)


EXAMPLE = Path(__file__).parent / "examples/targets/example"
JS = (b'function render(){const p=new URLSearchParams(location.search).get("u");'
      b'if(!p.startsWith("javascript:")){iframe.src=decodeURIComponent(p)}}')


class _Browser:
    name = "FIXTURE"

    def __init__(self) -> None:
        self.running: set[str] = set()

    def start(self, session_id, _profile, *, display, proxy) -> None:
        self.running.add(session_id)

    def stop(self, session_id) -> None:
        self.running.discard(session_id)

    def is_running(self, session_id) -> bool:
        return session_id in self.running

    def observe_identity(self, _session_id, _rule) -> IdentityObservation:
        return IdentityObservation(user_id="org1_admin", tenant_id="org1")


class CapturedJSTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        artifacts = root / "artifacts"
        evidence = EvidenceFactStore(root / "state/bughunter.sqlite3",
                                     ArtifactStore(artifacts), StoreSettings(artifacts))
        evidence.initialize()
        self.package = load_target_package(EXAMPLE)
        registry = IdentityRegistry(evidence)
        registry.register_target(self.package)
        self.identity = registry.register_identity(
            self.package.target.id, "org1_admin", status=IdentityStatus.ACTIVE)
        auth = AuthContextManager(registry, RoutedSecretProvider(SecretSettings(), {}))
        auth.prepare(self.package.target.id, self.identity.id,
                     mechanism=AuthMechanism.MANUAL_LOGIN)
        self.browser = BrowserSessionManager(
            registry, auth, _Browser(), BrowserSettings(profile_root=root / "profiles"))
        proxy = BrowserProxyConfig(enabled=True, proxy_url="http://127.0.0.1:18080",
                                   reference="fixture", capture_required=True,
                                   guard_scope=self.package.scope)
        self.session = self.browser.create(self.package.target.id, self.identity.id,
                                           proxy=proxy)
        self.browser.start(self.session.id, proxy=proxy, package=self.package,
                           proxy_health_check=lambda _: True)
        self.traffic = TrafficStore(evidence, registry)
        self.js = DOMXSSStore(evidence)
        self.collector = CapturedJSCollector(
            browser=self.browser, traffic=self.traffic, js=self.js,
            analyzer=DOMStaticAnalyzer())

    def _verify(self) -> None:
        self.browser.login_complete(self.session.id)
        rule = IdentityVerificationRule(
            self.package.target.id, self.identity.id, "[data-user]", None,
            "[data-tenant]", "org1_admin", None, "org1")
        self.browser.verify(self.session.id, rule)

    def _capture(self, *, content_type: str = "application/javascript",
                 body: bytes = JS, url: str = "https://app.example.test/static/app.js"):
        now = datetime.now(timezone.utc)
        return self.traffic.store_exchange(
            self.package,
            CapturePacket(
                CapturedRequest("GET", url, observed_at=now, http_version="HTTP/1.1"),
                CapturedResponse(200, (("Content-Type", content_type),), body,
                                 observed_at=now, http_version="HTTP/1.1"),
                browser_session_id=self.session.id),
            source=TrafficSource.BURP, capture_provider="MONTOYA_V1",
            browser_manager=self.browser)

    def test_verified_burp_script_becomes_current_without_refetch(self) -> None:
        self._verify()
        exchange = self._capture()
        first = self.collector.collect(self.package, self.session.id)
        self.assertEqual((first.examined, len(first.acquired), first.analyzed), (1, 1, 1))
        asset = first.acquired[0]
        self.assertEqual((asset.state, asset.source, asset.retrieval_exchange_id),
                         ("CURRENT", "CAPTURED_BURP", exchange.id))
        self.assertEqual(self.js.evidence.read_content(asset.evidence_id,
                                                        allow_sensitive=True), JS)
        self.assertEqual(self.js.evidence.get_evidence(asset.evidence_id).redaction_status,
                         RedactionStatus.ORIGINAL)
        self.assertEqual(self.collector.collect(self.package, self.session.id).acquired[0], asset)
        self.assertEqual(len(self.js.list_current_assets(self.package.target.id)), 1)

    def test_unverified_or_non_js_capture_is_not_promoted(self) -> None:
        self._capture()
        with self.assertRaisesRegex(ValueError, "Verified captured browser"):
            self.collector.collect(self.package, self.session.id)
        self._verify()
        self._capture(content_type="text/html",
                      url="https://app.example.test/not-a-script")
        self.assertEqual(self.collector.collect(self.package, self.session.id).acquired, ())

    def test_cross_session_and_non_burp_provenance_are_rejected(self) -> None:
        self._verify()
        exchange = self._capture()
        with self.assertRaisesRegex(ValueError, "Controlled retrieval evidence"):
            self.js.record_artifact(
                target_id=self.package.target.id,
                asset_url="https://app.example.test/static/app.js", body=JS,
                recon_asset_id=None, recon_sha256=None, source="CAPTURED_BURP",
                retrieval_exchange_id=exchange.id,
                capture_evidence_id=exchange.response.body_evidence_id,
                capture_session_id="BSESSION-" + "f" * 32)

    def test_captured_bundle_feeds_api_and_graphql_inventory_without_recon(self) -> None:
        self._verify()
        self._capture(body=(
            b"fetch('/api/v1/documents',{method:'GET'});"
            b"const query=gql`query GetDocument($id:ID!){node(id:$id){id name}}`;"
        ))
        result = self.collector.collect(self.package, self.session.id)
        self.assertEqual(len(result.acquired), 1)
        api = APISpecialist(
            registry=APIOperationRegistry(self.js.evidence), traffic=self.traffic,
            evidence=self.js.evidence, js=self.js)
        profile = api.profile(self.package)
        self.assertGreaterEqual(profile["counts"]["js_operations"], 1)
        self.assertGreaterEqual(profile["queries"], 1)

    def test_clean_bundle_is_not_counted_as_analysis_failure(self) -> None:
        self._verify()
        self._capture(body=b"fetch('/api/documents',{method:'GET'});")
        result = self.collector.collect(self.package, self.session.id)
        self.assertEqual((result.analyzed, result.analysis_failures), (1, 0))

    def test_asset_cap_reports_incomplete_coverage(self) -> None:
        self._verify()
        self._capture(url="https://app.example.test/static/one.js")
        self._capture(url="https://app.example.test/static/two.js")
        result = self.collector.collect(self.package, self.session.id, max_assets=1)
        self.assertEqual(len(result.acquired), 1)
        self.assertTrue(result.truncated)


if __name__ == "__main__":
    unittest.main()
