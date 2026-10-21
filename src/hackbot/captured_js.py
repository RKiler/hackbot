"""Promote verified, captured browser scripts into the current JS inventory."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib

from .browser import BrowserSessionManager, BrowserStatus, VerificationStatus
from .domxss_static import DOMStaticAnalyzer, MAX_ASSET_BYTES
from .domxss_store import DOMAssetRecord, DOMXSSStore
from .domain import TrafficSource
from .evidence import (EvidenceProvenance, EvidenceType, RedactionStatus,
                       Retention, Sensitivity)
from .target_package import TargetPackage
from .target_scope import ScopeResult
from .traffic import AuthState, ExchangeState, TrafficStore


@dataclass(frozen=True, slots=True)
class CapturedJSResult:
    examined: int
    acquired: tuple[DOMAssetRecord, ...]
    analyzed: int
    truncated: bool
    analysis_failures: int = 0


class CapturedJSCollector:
    """Use only complete, verified Burp captures; never make a network request."""

    def __init__(self, *, browser: BrowserSessionManager, traffic: TrafficStore,
                 js: DOMXSSStore, analyzer: DOMStaticAnalyzer) -> None:
        self.browser = browser
        self.traffic = traffic
        self.js = js
        self.analyzer = analyzer

    def collect(self, package: TargetPackage, session_id: str, *,
                max_exchanges: int = 200, max_assets: int = 8) -> CapturedJSResult:
        if (type(max_exchanges) is not int or not 1 <= max_exchanges <= 500
                or type(max_assets) is not int or not 1 <= max_assets <= 24):
            raise ValueError("Invalid captured JS inventory bounds")
        context = self.browser.session_context(session_id)
        if (context.target_id != package.target.id or context.identity_id is None
                or context.browser_status is not BrowserStatus.VALID
                or context.verification_status is not VerificationStatus.MATCH
                or context.authentication_status != "VALID"
                or not context.proxy_enabled or not context.proxy_capture_required):
            raise ValueError("Verified captured browser session is required")
        acquired: list[DOMAssetRecord] = []
        seen: set[str] = set()
        examined = analyzed = analysis_failures = 0
        cursor = None
        early_stop = False
        while examined < max_exchanges and len(acquired) < max_assets:
            page = self.traffic.list_exchanges_for_session(
                package.target.id, session_id,
                limit=min(50, max_exchanges - examined), cursor=cursor)
            if not page.items:
                break
            for index, exchange in enumerate(page.items):
                examined += 1
                response = exchange.response
                if (exchange.package_id != package.id or exchange.source is not TrafficSource.BURP
                        or exchange.capture_provider != "MONTOYA_V1"
                        or exchange.state is not ExchangeState.COMPLETE
                        or exchange.scope_result is not ScopeResult.IN_SCOPE
                        or exchange.attribution.auth_state is not AuthState.VERIFIED
                        or exchange.attribution.browser_session_id != session_id
                        or exchange.attribution.verified_identity_id != context.identity_id
                        or exchange.request.record.method != "GET" or response is None
                        or response.record.status_code != 200
                        or response.record.content_type not in {
                            "application/javascript", "text/javascript",
                            "application/x-javascript", "application/ecmascript",
                            "text/ecmascript"}
                        or response.body_evidence_id is None
                        or response.record.size_bytes is None
                        or not 1 <= response.record.size_bytes <= MAX_ASSET_BYTES):
                    continue
                url = self.traffic.observed_request_url(exchange)
                if url is None or package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
                    continue
                if url in seen:
                    continue
                seen.add(url)
                observation = self.js.evidence.get_evidence(response.body_evidence_id)
                if (observation is None or observation.target_ref != package.target.id
                        or observation.redaction_status is not RedactionStatus.ORIGINAL):
                    continue
                try:
                    body = self.js.evidence.read_content(
                        response.body_evidence_id, allow_sensitive=True,
                        max_bytes=MAX_ASSET_BYTES)
                except (ValueError, PermissionError):
                    continue
                digest = hashlib.sha256(body).hexdigest()
                if (len(body) != response.record.size_bytes or digest != response.body_hash):
                    continue
                cached = self.js.current_asset(package.target.id, url, digest)
                if cached is not None and cached.source not in {
                        "CONTROLLED_HTTP", "CAPTURED_BURP"}:
                    cached = None
                if cached is None:
                    capture = self.js.evidence.create_evidence(
                        EvidenceType.JS_ASSET, body, source="captured_burp_js",
                        provenance=EvidenceProvenance(system="HACKBOT", entity="BURP_JS",
                                                      record_id=exchange.id),
                        target_ref=package.target.id, sensitivity=Sensitivity.SENSITIVE,
                        metadata={"asset_url_sha256": hashlib.sha256(url.encode()).hexdigest(),
                                  "capture_exchange_id": exchange.id,
                                  "retention_class": "REGENERABLE"},
                        retention=Retention(retain=True, expires_at=(
                            datetime.now(timezone.utc) +
                            timedelta(hours=self.js.js_retention_hours))),
                    )
                    cached = self.js.record_artifact(
                        target_id=package.target.id, asset_url=url, body=body,
                        recon_asset_id=None, recon_sha256=None, source="CAPTURED_BURP",
                        retrieval_exchange_id=exchange.id,
                        capture_evidence_id=capture.evidence_id,
                        capture_session_id=session_id)
                acquired.append(cached)
                _, analysis = self.js.analyze_asset(
                    package.target.id, cached.artifact_id, self.analyzer)
                if analysis.status in {"ANALYZED", "NO_CONNECTED_SIGNAL"}:
                    analyzed += 1
                else:
                    analysis_failures += 1
                if len(acquired) >= max_assets:
                    early_stop = index + 1 < len(page.items)
                    break
            cursor = page.next_cursor
            if cursor is None:
                break
        return CapturedJSResult(examined, tuple(acquired), analyzed,
                                early_stop or cursor is not None and (
                                    examined >= max_exchanges or len(acquired) >= max_assets),
                                analysis_failures)
