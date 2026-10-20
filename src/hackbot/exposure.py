"""Offline exposure candidate discovery from current artifacts and bounded recon."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

from .domxss_store import DOMAssetRecord, DOMXSSStore
from .domain import TrafficSource
from .executor import RequestTemplate
from .evidence import EvidenceProvenance, EvidenceType, FactStatus, Sensitivity
from .exposure_models import (CredentialMetadata, ExposureCandidate, ExposureCategory,
                              ExposureSource, ExposureStatus)
from .exposure_static import (ExposureStaticAnalyzer, MAX_JS_SCAN_BYTES, MAX_MAP_SCAN_BYTES,
                              StaticExposureAnalysis, StaticExposureSignal)
from .exposure_store import ExposureStore
from .hypotheses import Hypothesis, HypothesisSource, HypothesisStatus, HypothesisStore
from .profile import TargetProfile
from .recon import ReconRepository
from .skill_plans import AuthorizationPlanBinding, SkillContextBuilder, SkillPlanner, SkillRouter
from .target_package import TargetPackage
from .target_recon import ReconDomainResolver, resolve_recon_target
from .target_scope import ScopeResult
from .traffic import ExchangeState, TrafficStore
from .test_objects import ObjectRegistry, ObjectState


@dataclass(frozen=True, slots=True)
class ExposureAnalysisResult:
    candidate_ids: tuple[str, ...]
    signals: int
    bytes_examined: int
    truncated: bool
    parse_error: bool


@dataclass(frozen=True, slots=True)
class PreparedExposure:
    hypothesis_id: str
    plan_id: str
    plan_status: str


_BACKUP = re.compile(r"(?i)(?:^|[/._-])(?:backup|archive|dump|\.bak|\.zip|\.tar|\.sql)(?:$|[/._-])")
_DEBUG = re.compile(r"(?i)(?:^|[/._-])(?:debug|actuator|trace|diagnostic|profiler|stacktrace)(?:$|[/._-])")
_ADMIN = re.compile(r"(?i)(?:^|[/._-])(?:admin|internal|manager|console|backoffice)(?:$|[/._-])")
_CONFIG = re.compile(r"(?i)(?:^|[/._-])(?:\.env|config|settings|application\.ya?ml|"
                     r"application\.properties)(?:$|[/._-])")
_DOWNLOAD = re.compile(r"(?i)(?:^|[/._-])(?:download|export|attachment|report|file)(?:$|[/._-])")
_PII_FIELDS = {
    "email": "EMAIL", "email_address": "EMAIL", "phone": "PHONE",
    "phone_number": "PHONE", "first_name": "NAME", "last_name": "NAME",
    "full_name": "NAME", "address": "ADDRESS", "street": "ADDRESS",
    "date_of_birth": "DATE_OF_BIRTH", "dob": "DATE_OF_BIRTH",
    "ssn": "GOVERNMENT_ID", "national_id": "GOVERNMENT_ID",
    "passport_number": "GOVERNMENT_ID", "iban": "FINANCIAL_ID",
    "bank_account": "FINANCIAL_ID", "account_number": "FINANCIAL_ID",
    "user_id": "ACCOUNT_METADATA", "tenant_id": "ACCOUNT_METADATA",
}
_PUBLIC_PATH_PARTS = frozenset({
    "", "api", "v1", "v2", "v3", "static", "assets", "js", "maps", "source-maps",
    "download", "downloads", "export", "exports", "report", "reports", "file", "files",
    "attachment", "attachments", "profile", "users", "admin", "internal", "config",
    "debug", "actuator", "backup", "archive", "health", "settings",
})


def _pii_categories(body: bytes) -> tuple[str, ...]:
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return ()
    found: set[str] = set()
    pending = [data]
    inspected = 0
    while pending and inspected < 256:
        current = pending.pop()
        inspected += 1
        if isinstance(current, dict):
            for key, value in list(current.items())[:48]:
                normalized = re.sub(r"(?<!^)(?=[A-Z])", "_", str(key)).lower()
                category = _PII_FIELDS.get(normalized)
                if category and isinstance(value, (str, int)) and value:
                    found.add(category)
                if isinstance(value, (dict, list)) and len(pending) < 64:
                    pending.append(value)
        elif isinstance(current, list):
            pending.extend(item for item in current[:16] if isinstance(item, (dict, list)))
    return tuple(sorted(found))


def _safe_location(url: str) -> str:
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise ValueError("Exposure source URL is not a safe HTTP URL") from None
    if (parsed.scheme not in {"http", "https"} or not host
            or parsed.username or parsed.password):
        raise ValueError("Exposure source URL is not a safe HTTP URL")
    safe_segments = []
    for segment in parsed.path.split("/")[:16]:
        if segment.lower() in _PUBLIC_PATH_PARTS or re.fullmatch(
                r"(?:app|main|vendor|runtime|chunk)(?:[.-][A-Za-z0-9]{1,20})?\.(?:js|mjs|cjs|map|json)",
                segment, re.I):
            safe_segments.append(segment)
        else:
            safe_segments.append("_redacted_")
    host = host.lower()
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme, netloc, "/".join(safe_segments) or "/", "", ""))[:1024]


def _candidate_id(target_id: str, fingerprint: str) -> str:
    return "EXP-" + hashlib.sha256(f"{target_id}:{fingerprint}".encode()).hexdigest()[:32]


class ExposureSpecialist:
    """Produces evidence-linked leads. Only a later Phase 17 validation can confirm."""

    MAX_HOSTS = 12
    MAX_ENDPOINTS_PER_HOST = 12
    MAX_RECON_CANDIDATES = 32

    def list_field_exchanges(self, package: TargetPackage) -> tuple[dict[str, str], ...]:
        """Offer bounded verified JSON reads without exposing response content."""
        if self.traffic is None:
            return ()
        page = self.traffic.list_filtered(package.target.id, limit=50,
                                          method="GET", status="200")
        items: list[dict[str, str]] = []
        for exchange in page.items:
            if (exchange.package_id != package.id or
                    exchange.scope_result is not ScopeResult.IN_SCOPE or
                    exchange.state is not ExchangeState.COMPLETE or
                    exchange.response is None or
                    exchange.response.record.content_type != "application/json" or
                    exchange.attribution.auth_state.value != "VERIFIED" or
                    not exchange.attribution.verified_identity_id):
                continue
            try:
                record = json.loads(self.store.evidence.read_content(
                    exchange.request.observation_evidence_id,
                    allow_sensitive=True, max_bytes=8192))
                url = record["url"]
                if urlsplit(url).query or urlsplit(url).fragment:
                    continue
                location = _safe_location(url)
            except (KeyError, TypeError, ValueError, PermissionError,
                    json.JSONDecodeError):
                continue
            items.append({"exchange_id": exchange.id,
                          "identity_id": exchange.attribution.verified_identity_id,
                          "location": location})
        return tuple(items)

    def list_captured_responses(self, package: TargetPackage, *, limit: int = 30
                                ) -> tuple[dict[str, object], ...]:
        if self.traffic is None or type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Bounded TrafficStore capture inventory required")
        with self.store.evidence._connection() as db:
            rows = db.execute("""SELECT evidence_id,metadata_json,content_hash,content_size,
                created_at FROM (SELECT evidence_id,metadata_json,content_hash,content_size,
                    created_at,evidence_type,source FROM evidence WHERE target_ref=?
                    ORDER BY created_at DESC,evidence_id DESC LIMIT 500)
                WHERE evidence_type='HTTP_RESPONSE' AND source='controlled_asset_fetch'
                ORDER BY created_at DESC LIMIT ?""", (package.target.id, limit)).fetchall()
        items = []
        for row in rows:
            try:
                metadata = json.loads(row["metadata_json"])
                exchange_id = metadata["exchange_id"]
                if metadata.get("asset_kind") != "EXPOSURE":
                    continue
                exchange = self.traffic.get_exchange(exchange_id)
                if (exchange is None or exchange.target_id != package.target.id or
                        exchange.package_id != package.id or
                        exchange.scope_result is not ScopeResult.IN_SCOPE):
                    continue
                items.append({"exchange_id": exchange_id,
                              "artifact_evidence_id": row["evidence_id"],
                              "sha256": row["content_hash"],
                              "size_bytes": row["content_size"],
                              "created_at": row["created_at"]})
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
        return tuple(items)

    def __init__(self, *, dom: DOMXSSStore, store: ExposureStore,
                 recon: ReconRepository | None = None,
                 traffic: TrafficStore | None = None,
                 analyzer: ExposureStaticAnalyzer | None = None,
                 behaviour: "BehaviourStore | None" = None) -> None:
        self.dom, self.store, self.recon, self.traffic = dom, store, recon, traffic
        self.analyzer = analyzer or ExposureStaticAnalyzer()
        self.behaviour = behaviour

    def _asset_url(self, package: TargetPackage, asset: DOMAssetRecord,
                   fixture_url: str | None) -> str:
        if asset.target_id != package.target.id or asset.state != "CURRENT":
            raise ValueError("Current target JavaScript artifact is required")
        if asset.recon_sha256 != asset.artifact_sha256:
            raise ValueError("JavaScript artifact no longer matches the current recon hash")
        if asset.source == "FIXTURE":
            if fixture_url is None:
                raise ValueError("Fixture source URL is required")
            url = fixture_url
        else:
            if asset.source != "CONTROLLED_HTTP" or self.recon is None or asset.recon_asset_id is None:
                raise ValueError("Externally current JavaScript retrieval is required")
            target = resolve_recon_target(package, self.recon)
            if target is None:
                raise ValueError("Recon target is unavailable")
            current = self.recon.get_js_asset(target.domain_id, asset.recon_asset_id)
            if current is None or current.latest_sha256 != asset.artifact_sha256 or current.http_status != 200:
                raise ValueError("JavaScript recon hash is stale")
            url = current.asset_url
        if hashlib.sha256(url.encode()).hexdigest() != asset.asset_url_sha256:
            raise ValueError("JavaScript source URL does not match stored provenance")
        if package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
            raise ValueError("JavaScript source is outside authoritative target scope")
        return url

    def _source_current(self, package: TargetPackage, source: ExposureSource,
                        source_ref: str, artifact_sha256: str | None) -> bool:
        if source is ExposureSource.JS_ASSET:
            asset = self.dom.get_asset(package.target.id, source_ref)
        elif source is ExposureSource.SOURCE_MAP:
            source_map = self.dom.get_source_map_by_id(package.target.id, source_ref)
            if source_map is None or source_map.map_sha256 != artifact_sha256:
                return False
            asset = self.dom.get_asset(package.target.id, source_map.js_artifact_id)
        else:
            return True
        if (asset is None or asset.state != "CURRENT" or
                asset.recon_sha256 != asset.artifact_sha256 or
                source is ExposureSource.JS_ASSET and asset.artifact_sha256 != artifact_sha256):
            return False
        if asset.source == "FIXTURE":
            return True
        if asset.source != "CONTROLLED_HTTP" or self.recon is None or asset.recon_asset_id is None:
            return False
        target = resolve_recon_target(package, self.recon)
        if target is None:
            return False
        current = self.recon.get_js_asset(target.domain_id, asset.recon_asset_id)
        return bool(current is not None and current.http_status == 200 and
                    current.latest_sha256 == asset.artifact_sha256 and
                    package.scope.evaluate_url(current.asset_url).result is ScopeResult.IN_SCOPE)

    def current_candidate(self, package: TargetPackage,
                          candidate_id: str) -> ExposureCandidate | None:
        candidate = self.store.get(package.target.id, candidate_id)
        if candidate is None or candidate.status in {
                ExposureStatus.STALE, ExposureStatus.REJECTED_PUBLIC,
                ExposureStatus.REJECTED_PLACEHOLDER}:
            return None
        if candidate.source not in {ExposureSource.JS_ASSET, ExposureSource.SOURCE_MAP}:
            return candidate
        current = False
        for link in self.store.source_links(package.target.id, candidate_id):
            if link["source"] != candidate.source.value or not link["current"]:
                continue
            if self._source_current(package, candidate.source,
                                    str(link["source_ref"]), link["artifact_sha256"]):
                current = True
            else:
                self.store.mark_artifact_stale(package.target.id, str(link["source_ref"]))
        return candidate if current else None

    def vhost_reference(self, package: TargetPackage, candidate_id: str,
                        source_ref: str) -> str:
        """Re-derive an internal Host from the exact current protected source."""
        candidate = self.current_candidate(package, candidate_id)
        if (candidate is None or candidate.category is not ExposureCategory.INTERNAL_VHOST_CANDIDATE
                or candidate.artifact_sha256 is None
                or package.rules.internal_vhost_testing_allowed is not True):
            raise ValueError("Current explicitly authorized VHOST candidate required")
        link = next((item for item in self.store.source_links(package.target.id, candidate_id)
                     if item["current"] and item["source_ref"] == source_ref and
                     item["artifact_sha256"] == candidate.artifact_sha256 and
                     item["source"] == candidate.source.value), None)
        if link is None:
            raise ValueError("Current VHOST source link required")
        record = self.store.evidence.get_evidence(str(link["evidence_id"]))
        if (record is None or record.target_ref != package.target.id or
                record.content_hash != candidate.artifact_sha256 or
                record.sensitivity is not Sensitivity.SENSITIVE):
            raise ValueError("Protected VHOST source is unavailable")
        limit = MAX_JS_SCAN_BYTES if candidate.source is ExposureSource.JS_ASSET else MAX_MAP_SCAN_BYTES
        body = self.store.evidence.read_content(record.evidence_id, allow_sensitive=True,
                                                max_bytes=limit)
        if hashlib.sha256(body).hexdigest() != candidate.artifact_sha256:
            raise ValueError("VHOST source integrity failed")
        analysis = (self.analyzer.analyze_js(body) if candidate.source is ExposureSource.JS_ASSET
                    else self.analyzer.analyze_source_map(body))
        signal = next((item for item in analysis.signals
                       if item.category is ExposureCategory.INTERNAL_VHOST_CANDIDATE and
                       _candidate_id(package.target.id, item.category.value + ":" +
                                     item.fingerprint_sha256) == candidate_id), None)
        if signal is None or signal.referenced_host is None or analysis.truncated or analysis.parse_error:
            raise ValueError("VHOST hostname is not proven by the current source")
        return signal.referenced_host

    def resolve_vhost(self, package: TargetPackage, frozen: dict[str, str],
                      variant: str, run_id: str) -> RequestTemplate:
        if (variant not in {"NORMAL", "INVALID", "CANDIDATE"} or
                not isinstance(frozen, dict) or
                package.scope.evaluate_url(frozen.get("url", "")).result is not ScopeResult.IN_SCOPE):
            raise ValueError("Invalid scoped VHOST experiment")
        candidate = self.current_candidate(package, frozen["candidate_id"])
        if (candidate is None or candidate.location != frozen["url"] or
                candidate.artifact_sha256 != frozen["artifact_sha256"] or
                "_redacted_" in candidate.location):
            raise ValueError("VHOST destination or artifact is stale")
        host = self.vhost_reference(package, frozen["candidate_id"], frozen["source_ref"])
        if hashlib.sha256(host.encode()).hexdigest() != frozen["host_sha256"]:
            raise ValueError("VHOST host evidence changed")
        override = (None if variant == "NORMAL" else
                    "invalid-" + hashlib.sha256(run_id.encode()).hexdigest()[:16] + ".invalid"
                    if variant == "INVALID" else host)
        return RequestTemplate("GET", frozen["url"], host_override=override)

    def _save_signals(self, package: TargetPackage, analysis: StaticExposureAnalysis, *,
                      source: ExposureSource, source_ref: str, evidence_id: str,
                      artifact_sha256: str, location: str, recent_change: bool) -> ExposureAnalysisResult:
        target_id = package.target.id
        safe_location = _safe_location(location)
        ids = []
        now = datetime.now(timezone.utc)
        for signal in analysis.signals:
            status = signal.status
            if analysis.truncated and status not in {
                ExposureStatus.REJECTED_PUBLIC, ExposureStatus.REJECTED_PLACEHOLDER}:
                status = ExposureStatus.NEEDS_MANUAL_REVIEW
            confidence = signal.confidence
            priority = min(100, signal.priority + (10 if recent_change else 0))
            credential = (CredentialMetadata(
                signal.credential_type, signal.fingerprint_sha256, signal.value_length,
                signal.service_class, signal.potential_privilege, status)
                if signal.credential_type is not None and signal.value_length is not None else None)
            if signal.category in {ExposureCategory.INTERNAL_HOST_DISCLOSURE,
                                   ExposureCategory.INTERNAL_VHOST_CANDIDATE}:
                requirements = ("CURRENT_ARTIFACT", "FIRST_PARTY_REFERENCE",
                                "EXTERNAL_REACHABILITY", "PROTECTED_EFFECT")
            else:
                requirements = ("CURRENT_ARTIFACT", "NON_PUBLIC_SECRET_SEMANTICS",
                                "TARGET_SERVICE_RELEVANCE", "PHASE17_VALIDATION")
            candidate = ExposureCandidate(
                candidate_id=_candidate_id(target_id, signal.category.value + ":" +
                                           signal.fingerprint_sha256),
                target_id=target_id, category=signal.category, location=safe_location,
                endpoint_or_asset=source_ref, identity_context="ANONYMOUS",
                source=source, evidence_ids=(evidence_id,),
                sensitivity=(Sensitivity.SECRET if credential and status not in {
                    ExposureStatus.REJECTED_PUBLIC, ExposureStatus.REJECTED_PLACEHOLDER}
                    else Sensitivity.INTERNAL if credential else Sensitivity.SENSITIVE),
                confidence=confidence, priority=priority,
                verification_requirements=requirements, status=status,
                created_at=now, updated_at=now,
                reason_codes=signal.reason_codes + (("RECENT_DELTA",) if recent_change else ()),
                artifact_sha256=artifact_sha256, credential=credential,
            )
            self.store.save(candidate, source_ref=source_ref, evidence_id=evidence_id)
            ids.append(candidate.candidate_id)
        return ExposureAnalysisResult(tuple(ids), len(analysis.signals),
                                      analysis.bytes_examined, analysis.truncated,
                                      analysis.parse_error)

    def analyze_js(self, package: TargetPackage, artifact_id: str, *,
                   fixture_url: str | None = None, recent_change: bool = False
                   ) -> ExposureAnalysisResult:
        asset = self.dom.get_asset(package.target.id, artifact_id)
        if asset is None:
            raise ValueError("Unknown JavaScript artifact")
        url = self._asset_url(package, asset, fixture_url)
        body = self.dom.evidence.read_content(asset.evidence_id, allow_sensitive=True,
                                              max_bytes=MAX_JS_SCAN_BYTES)
        if hashlib.sha256(body).hexdigest() != asset.artifact_sha256:
            raise ValueError("JavaScript artifact integrity check failed")
        analysis = self.analyzer.analyze_js(body)
        return self._save_signals(package, analysis, source=ExposureSource.JS_ASSET,
                                  source_ref=artifact_id, evidence_id=asset.evidence_id,
                                  artifact_sha256=asset.artifact_sha256, location=url,
                                  recent_change=recent_change)

    def analyze_source_map(self, package: TargetPackage, js_artifact_id: str, *,
                           fixture_url: str | None = None, recent_change: bool = False
                           ) -> ExposureAnalysisResult:
        asset = self.dom.get_asset(package.target.id, js_artifact_id)
        if asset is None:
            raise ValueError("Unknown JavaScript artifact")
        url = self._asset_url(package, asset, fixture_url)
        source_map = self.dom.get_source_map(package.target.id, js_artifact_id)
        if source_map is None:
            raise ValueError("No source map is linked to this current JavaScript")
        body = self.dom.evidence.read_content(source_map.evidence_id, allow_sensitive=True,
                                              max_bytes=MAX_MAP_SCAN_BYTES)
        if hashlib.sha256(body).hexdigest() != source_map.map_sha256:
            raise ValueError("Source map integrity check failed")
        analysis = self.analyzer.analyze_source_map(body)
        return self._save_signals(package, analysis, source=ExposureSource.SOURCE_MAP,
                                  source_ref=source_map.map_id, evidence_id=source_map.evidence_id,
                                  artifact_sha256=source_map.map_sha256, location=url,
                                  recent_change=recent_change)

    def discover_recon(self, package: TargetPackage) -> ExposureAnalysisResult:
        """Bounded metadata discovery; does not fetch, fuzz, or test a route."""
        if self.recon is None:
            return ExposureAnalysisResult((), 0, 0, False, False)
        target = resolve_recon_target(package, self.recon)
        if target is None:
            return ExposureAnalysisResult((), 0, 0, False, False)
        recent_ids: set[int] = set()
        for snapshot in [item for item in self.recon.list_scan_snapshots(target.domain_id, limit=6).items
                         if not item.first_run][:2]:
            if snapshot.finished_at < snapshot.started_at:
                continue
            events = self.recon.list_asset_events(target.domain_id, snapshot.started_at,
                                                  snapshot.finished_at, limit=24).items
            recent_ids.update(item.entity_id for item in events
                              if item.entity_id and item.entity_type.lower() in {"endpoint", "endpoints"})
        ids: list[str] = []
        hosts = ReconDomainResolver(self.recon).select_hosts(package).hosts[:self.MAX_HOSTS]
        for host in hosts:
            if package.scope.evaluate_url(host.url).result is not ScopeResult.IN_SCOPE:
                continue
            for endpoint in self.recon.list_endpoints(target.domain_id, host.host_id,
                                                      limit=self.MAX_ENDPOINTS_PER_HOST).items:
                if len(ids) >= self.MAX_RECON_CANDIDATES:
                    break
                path = endpoint.path
                if not path.startswith("/") or path.startswith("//") or ".." in path.split("/"):
                    continue
                base_path = urlsplit(path).path
                url = urljoin(host.url.rstrip("/") + "/", base_path.lstrip("/"))
                if package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
                    continue
                category = (ExposureCategory.BACKUP_ARTIFACT if _BACKUP.search(base_path) else
                            ExposureCategory.DEBUG_ENDPOINT if _DEBUG.search(base_path) else
                            ExposureCategory.CONFIG_DISCLOSURE if _CONFIG.search(base_path) else
                            ExposureCategory.ADMIN_SURFACE if _ADMIN.search(base_path) else
                            ExposureCategory.UNAUTHENTICATED_DOWNLOAD if _DOWNLOAD.search(base_path) else None)
                if category is None:
                    continue
                source_ref = f"RECONEND-{endpoint.endpoint_id}"
                pointer = {"table": "endpoints", "id": endpoint.endpoint_id,
                           "host_id": host.host_id, "method": endpoint.method,
                           "status": endpoint.status_code}
                pointer_body = json.dumps(pointer, sort_keys=True).encode()
                candidate_id = _candidate_id(package.target.id,
                                             f"RECON:{category.value}:{host.host_id}:{base_path}")
                prior_ref = self.store.existing_recon_pointer(
                    package.target.id, candidate_id, source_ref,
                    hashlib.sha256(pointer_body).hexdigest())
                evidence = (self.store.evidence.get_evidence(prior_ref) if prior_ref else None)
                if evidence is None:
                    evidence = self.store.evidence.create_evidence(
                        EvidenceType.RECON_RECORD, pointer_body,
                        source="exposure_recon_pointer",
                        provenance=EvidenceProvenance(system="RECON", entity="endpoints",
                                                       record_id=str(endpoint.endpoint_id)),
                        target_ref=package.target.id, sensitivity=Sensitivity.INTERNAL,
                    )
                recent = endpoint.endpoint_id in recent_ids
                now = datetime.now(timezone.utc)
                priority = min(100, 25 + (15 if recent else 0) +
                               (15 if category in {ExposureCategory.BACKUP_ARTIFACT,
                                                   ExposureCategory.DEBUG_ENDPOINT} else 0))
                candidate = ExposureCandidate(
                    candidate_id=candidate_id,
                    target_id=package.target.id, category=category,
                    location=_safe_location(url), endpoint_or_asset=source_ref,
                    identity_context="UNKNOWN", source=ExposureSource.RECON,
                    evidence_ids=(evidence.evidence_id,), sensitivity=Sensitivity.INTERNAL,
                    confidence=25, priority=priority,
                    verification_requirements=("CURRENT_ROUTE", "PROTECTED_CONTENT",
                                               "AUTHORIZATION_CONTROL", "PHASE17_VALIDATION"),
                    status=ExposureStatus.CANDIDATE,
                    created_at=now, updated_at=now,
                    reason_codes=("OBSERVED_RECON_ROUTE",) + (("RECENT_DELTA",) if recent else ()),
                )
                self.store.save(candidate, source_ref=source_ref, evidence_id=evidence.evidence_id)
                ids.append(candidate.candidate_id)
            if len(ids) >= self.MAX_RECON_CANDIDATES:
                break
        return ExposureAnalysisResult(tuple(ids), len(ids), 0,
                                      len(ids) >= self.MAX_RECON_CANDIDATES, False)

    def discover_traffic(self, package: TargetPackage, *, limit: int = 100
                         ) -> ExposureAnalysisResult:
        """Compare retained, current GET observations without issuing new requests."""
        if self.traffic is None:
            return ExposureAnalysisResult((), 0, 0, False, False)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Traffic inspection limit must be 1..100")
        learned = self.behaviour.profile(package.target.id) if self.behaviour else None
        learned_exports = ({exchange_id for operation in learned.operations
                            if operation["action"] == "EXPORT"
                            for exchange_id in operation["exchange_ids"]} if learned else set())
        exchanges = []
        cursor = None
        while len(exchanges) < limit:
            page = self.traffic.list_exchanges_for_target(
                package.target.id, limit=min(50, limit - len(exchanges)), cursor=cursor)
            exchanges.extend(page.items)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        by_path: dict[str, list[tuple[object, str]]] = {}
        for exchange in exchanges:
            if (exchange.state is not ExchangeState.COMPLETE or exchange.response is None
                    or exchange.request.record.method not in {"GET", "HEAD"}
                    or exchange.scope_result is not ScopeResult.IN_SCOPE
                    or exchange.response.record.status_code != 200
                    or not exchange.response.body_hash
                    or not exchange.request.observation_evidence_id):
                continue
            try:
                observation = json.loads(self.store.evidence.read_content(
                    exchange.request.observation_evidence_id, allow_sensitive=True,
                    max_bytes=16_384))
                observed_url = observation["url"]
                if (not isinstance(observed_url, str) or
                        package.scope.evaluate_url(observed_url).result is not ScopeResult.IN_SCOPE):
                    continue
            except (KeyError, ValueError, PermissionError, json.JSONDecodeError):
                continue
            by_path.setdefault(observed_url, []).append((exchange, observed_url))
        ids: list[str] = []
        examined_bytes = 0
        for path, observations in by_path.items():
            owners = [item for item, _ in observations if item.attribution.verified_identity_id]
            anonymous = [item for item, _ in observations
                         if item.attribution.auth_state.value == "ANONYMOUS"]
            if not owners or not anonymous:
                continue
            for owner in owners[:2]:
                for boundary in anonymous[:2]:
                    if (owner.response is None or boundary.response is None or
                            not owner.response.body_hash or
                            owner.response.body_hash != boundary.response.body_hash or
                            not boundary.response.record.size_bytes or
                            boundary.response.record.size_bytes > 524_288):
                        continue
                    body = b""
                    if boundary.response.body_evidence_id:
                        try:
                            body = self.store.evidence.read_content(
                                boundary.response.body_evidence_id, allow_sensitive=True,
                                max_bytes=524_288)
                        except (ValueError, PermissionError, KeyError):
                            pass
                    examined_bytes += len(body)
                    categories = _pii_categories(body)
                    path_only = urlsplit(path).path
                    content_type = boundary.response.record.content_type or ""
                    if categories:
                        category = ExposureCategory.PII_EXPOSURE
                    elif _BACKUP.search(path_only):
                        category = ExposureCategory.BACKUP_ARTIFACT
                    elif _DEBUG.search(path_only):
                        category = ExposureCategory.DEBUG_ENDPOINT
                    elif _CONFIG.search(path_only):
                        category = ExposureCategory.CONFIG_DISCLOSURE
                    elif _DOWNLOAD.search(path_only) and content_type not in {"text/html", "application/xhtml+xml"}:
                        category = ExposureCategory.UNAUTHENTICATED_DOWNLOAD
                    else:
                        category = ExposureCategory.UNAUTHENTICATED_RESOURCE
                    evidence_ids = tuple(dict.fromkeys((
                        owner.request.observation_evidence_id,
                        owner.response.observation_evidence_id,
                        boundary.request.observation_evidence_id,
                        boundary.response.observation_evidence_id,
                        *(item for item in (owner.response.body_evidence_id,
                                             boundary.response.body_evidence_id) if item),
                    )))
                    now = datetime.now(timezone.utc)
                    candidate = ExposureCandidate(
                        candidate_id=_candidate_id(package.target.id,
                            f"TRAFFIC:{category.value}:{hashlib.sha256(path.encode()).hexdigest()}"),
                        target_id=package.target.id, category=category,
                        location=_safe_location(path), endpoint_or_asset=boundary.id,
                        identity_context="ANONYMOUS", source=ExposureSource.TRAFFIC,
                        evidence_ids=evidence_ids, sensitivity=(
                            Sensitivity.SENSITIVE if categories else Sensitivity.INTERNAL),
                        confidence=70 if categories else 55,
                        priority=min(100, (80 if categories else 65) +
                                     (5 if owner.id in learned_exports else 0)),
                        verification_requirements=("OWNED_CONTROL", "PRIVACY_EXPECTATION",
                                                   "INVALID_OBJECT_CONTROL", "FRESH_REPRODUCTION",
                                                   "PHASE17_VALIDATION"),
                        status=ExposureStatus.NEEDS_MANUAL_REVIEW,
                        created_at=now, updated_at=now,
                        reason_codes=("OWNER_ANONYMOUS_BODY_HASH_EQUAL",
                                      "PRIVACY_NOT_YET_PROVEN") +
                                     (("LEARNED_AUTHENTICATED_EXPORT_CONTROL",)
                                      if owner.id in learned_exports else ()),
                        pii_categories=categories,
                    )
                    self.store.save(candidate, source_ref=boundary.id,
                                    evidence_id=boundary.response.observation_evidence_id)
                    self.store.save(candidate, source_ref=owner.id,
                                    evidence_id=owner.response.observation_evidence_id)
                    ids.append(candidate.candidate_id)
                    break
                if len(ids) >= 32:
                    break
            if len(ids) >= 32:
                break
        return ExposureAnalysisResult(tuple(dict.fromkeys(ids)), len(ids), examined_bytes,
                                      len(exchanges) >= limit, False)

    def analyze_field_boundary(self, package: TargetPackage, *,
                               owner_exchange_id: str, member_exchange_id: str
                               ) -> ExposureAnalysisResult:
        """An equal owner/member response is a lead until a field policy is proven."""
        if self.traffic is None or owner_exchange_id == member_exchange_id:
            raise ValueError("Distinct owner and member exchanges required")
        owner = self.traffic.get_exchange(owner_exchange_id)
        member = self.traffic.get_exchange(member_exchange_id)
        if (owner is None or member is None or
                any(item.target_id != package.target.id or item.package_id != package.id or
                    item.state is not ExchangeState.COMPLETE or item.response is None or
                    item.scope_result is not ScopeResult.IN_SCOPE or
                    item.request.record.method != "GET" or
                    item.response.record.status_code != 200 or
                    item.response.record.content_type != "application/json" or
                    item.attribution.auth_state.value != "VERIFIED" or
                    not item.attribution.verified_identity_id
                    for item in (owner, member)) or
                owner.attribution.verified_identity_id == member.attribution.verified_identity_id or
                not owner.response.body_hash or
                owner.response.body_hash != member.response.body_hash):
            raise ValueError("Comparable verified owner/member JSON responses required")
        try:
            first = json.loads(self.store.evidence.read_content(
                owner.request.observation_evidence_id, allow_sensitive=True, max_bytes=8192))
            second = json.loads(self.store.evidence.read_content(
                member.request.observation_evidence_id, allow_sensitive=True, max_bytes=8192))
            url = first["url"]
            if (url != second["url"] or urlsplit(url).query or urlsplit(url).fragment or
                    package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE):
                raise ValueError
        except (KeyError, TypeError, ValueError, PermissionError, json.JSONDecodeError):
            raise ValueError("Exact scoped owner/member route required") from None
        now = datetime.now(timezone.utc)
        candidate = ExposureCandidate(
            candidate_id=_candidate_id(package.target.id,
                                       "FIELD:" + hashlib.sha256(url.encode()).hexdigest() + ":" +
                                       owner.response.body_hash),
            target_id=package.target.id, category=ExposureCategory.OVEREXPOSED_API_RESPONSE,
            location=_safe_location(url), endpoint_or_asset=owner.id,
            identity_context="AUTHENTICATED", source=ExposureSource.TRAFFIC,
            evidence_ids=tuple(dict.fromkeys((owner.request.observation_evidence_id,
                         owner.response.observation_evidence_id,
                         member.request.observation_evidence_id,
                         member.response.observation_evidence_id)))[:24],
            sensitivity=Sensitivity.SENSITIVE, confidence=50, priority=65,
            verification_requirements=("OWNED_OBJECT", "VERIFIED_ROLE_DIFFERENCE",
                                       "TRUSTED_FIELD_POLICY", "PHASE17_VALIDATION"),
            status=ExposureStatus.NEEDS_MANUAL_REVIEW,
            created_at=now, updated_at=now,
            reason_codes=("OWNER_MEMBER_BODY_HASH_EQUAL", "FIELD_POLICY_UNPROVEN"))
        self.store.save(candidate, source_ref=owner.id,
                        evidence_id=owner.response.observation_evidence_id)
        self.store.save(candidate, source_ref=member.id,
                        evidence_id=member.response.observation_evidence_id)
        return ExposureAnalysisResult((candidate.candidate_id,), 1, 0, False, False)

    def analyze_captured_response(self, package: TargetPackage, *,
                                  exchange_id: str, artifact_evidence_id: str
                                  ) -> ExposureAnalysisResult:
        """Classify only a protected body from an exact Phase 14 anonymous capture."""
        if self.traffic is None:
            raise ValueError("TrafficStore is required for response analysis")
        exchange = self.traffic.get_exchange(exchange_id)
        record = self.store.evidence.get_evidence(artifact_evidence_id)
        if (exchange is None or exchange.source is not TrafficSource.HACKBOT or
                exchange.target_id != package.target.id or
                exchange.package_id != package.id or exchange.state is not ExchangeState.COMPLETE or
                exchange.scope_result is not ScopeResult.IN_SCOPE or
                exchange.attribution.auth_state.value != "ANONYMOUS" or
                exchange.request.record.method != "GET" or exchange.response is None or
                exchange.response.record.status_code != 200 or
                not exchange.response.body_hash or record is None or
                record.target_ref != package.target.id or
                record.evidence_type != EvidenceType.HTTP_RESPONSE.value or
                record.source != "controlled_asset_fetch" or
                record.metadata.get("exchange_id") != exchange_id or
                record.metadata.get("asset_kind") != "EXPOSURE" or
                record.content_hash != exchange.response.body_hash or
                record.sensitivity is not Sensitivity.SENSITIVE or
                record.redaction_status.value != "ORIGINAL" or
                record.content_size > 65_536):
            raise ValueError("Exact protected anonymous Phase 14 capture required")
        try:
            request = json.loads(self.store.evidence.read_content(
                exchange.request.observation_evidence_id, allow_sensitive=True,
                max_bytes=8192))
            url = request["url"]
            if (not isinstance(url, str) or urlsplit(url).query or urlsplit(url).fragment or
                    package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE):
                raise ValueError
            body = self.store.evidence.read_content(record.evidence_id, allow_sensitive=True,
                                                    max_bytes=65_536)
        except (KeyError, TypeError, ValueError, PermissionError, json.JSONDecodeError):
            raise ValueError("Protected response or exact scoped URL unavailable") from None
        analysis = self.analyzer.analyze_js(body)
        path = urlsplit(url).path
        category = (ExposureCategory.BACKUP_ARTIFACT if _BACKUP.search(path) else
                    ExposureCategory.DEBUG_ENDPOINT if _DEBUG.search(path) else
                    ExposureCategory.CONFIG_DISCLOSURE if _CONFIG.search(path) else
                    ExposureCategory.CREDENTIAL_DISCLOSURE)
        credential_signal = next((item for item in sorted(
            analysis.signals, key=lambda value: -value.priority)
            if item.credential_type is not None and item.category is ExposureCategory.JS_SECRET), None)
        status = credential_signal.status if credential_signal else ExposureStatus.NEEDS_RESEARCH
        now = datetime.now(timezone.utc)
        candidate = ExposureCandidate(
            candidate_id=_candidate_id(package.target.id,
                                       "HTTP_EXPOSURE:" + category.value + ":" + record.content_hash),
            target_id=package.target.id, category=category,
            location=_safe_location(url), endpoint_or_asset=exchange.id,
            identity_context="ANONYMOUS", source=ExposureSource.TRAFFIC,
            evidence_ids=tuple(dict.fromkeys((record.evidence_id,
                       exchange.request.observation_evidence_id,
                       exchange.response.observation_evidence_id)))[:24],
            sensitivity=Sensitivity.SECRET if credential_signal else Sensitivity.INTERNAL,
            confidence=credential_signal.confidence if credential_signal else 20,
            priority=credential_signal.priority if credential_signal else 20,
            verification_requirements=("CURRENT_RESPONSE", "NON_PUBLIC_CREDENTIAL",
                                       "SAME_URL_REPRODUCTION", "PHASE17_VALIDATION"),
            status=status, created_at=now, updated_at=now,
            reason_codes=(("CONTROLLED_ANONYMOUS_RESPONSE",) +
                          (credential_signal.reason_codes if credential_signal else
                           ("SENSITIVITY_UNPROVEN",))),
            artifact_sha256=record.content_hash,
            credential=(CredentialMetadata(
                credential_signal.credential_type, credential_signal.fingerprint_sha256,
                credential_signal.value_length, credential_signal.service_class,
                credential_signal.potential_privilege, credential_signal.status)
                if credential_signal is not None and credential_signal.value_length is not None else None),
        )
        self.store.save(candidate, source_ref=exchange.id, evidence_id=record.evidence_id)
        return ExposureAnalysisResult((candidate.candidate_id,), len(analysis.signals),
                                      len(body), analysis.truncated, analysis.parse_error)

    def resolve_captured_response(self, package: TargetPackage,
                                  frozen: dict[str, str]) -> RequestTemplate:
        candidate = self.store.get(package.target.id, frozen["candidate_id"])
        exchange = self.traffic.get_exchange(frozen["source_ref"]) if self.traffic else None
        record = self.store.evidence.get_evidence(frozen["evidence_id"])
        if (candidate is None or candidate.source is not ExposureSource.TRAFFIC or
                candidate.endpoint_or_asset != frozen["source_ref"] or
                candidate.artifact_sha256 != frozen["artifact_sha256"] or
                candidate.status in {ExposureStatus.STALE, ExposureStatus.REJECTED_PUBLIC,
                                     ExposureStatus.REJECTED_PLACEHOLDER} or
                exchange is None or exchange.source is not TrafficSource.HACKBOT or
                exchange.state is not ExchangeState.COMPLETE or
                exchange.target_id != package.target.id or exchange.package_id != package.id or
                exchange.scope_result is not ScopeResult.IN_SCOPE or
                exchange.attribution.auth_state.value != "ANONYMOUS" or
                exchange.request.record.method != "GET" or exchange.response is None or
                exchange.response.record.status_code != 200 or
                exchange.response.body_hash != frozen["artifact_sha256"] or
                record is None or record.target_ref != package.target.id or
                record.evidence_type != EvidenceType.HTTP_RESPONSE.value or
                record.source != "controlled_asset_fetch" or
                record.metadata.get("exchange_id") != exchange.id or
                record.metadata.get("asset_kind") != "EXPOSURE" or
                record.content_hash != frozen["artifact_sha256"]):
            raise ValueError("Current controlled response binding required")
        try:
            observed = json.loads(self.store.evidence.read_content(
                exchange.request.observation_evidence_id, allow_sensitive=True,
                max_bytes=8192))
            url = observed["url"]
            if (not isinstance(url, str) or urlsplit(url).query or urlsplit(url).fragment or
                    _safe_location(url) != candidate.location or
                    package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE):
                raise ValueError
        except (KeyError, TypeError, ValueError, PermissionError, json.JSONDecodeError):
            raise ValueError("Exact scoped response URL unavailable") from None
        return RequestTemplate("GET", url)

    def prepare_candidate(self, package: TargetPackage, candidate_id: str, *,
                          hypotheses: HypothesisStore, contexts: SkillContextBuilder,
                          router: SkillRouter, planner: SkillPlanner,
                          profile: TargetProfile | None = None) -> PreparedExposure:
        """Freeze an evidence-linked Phase 12/15 plan; this sends no traffic."""
        candidate = self.store.get(package.target.id, candidate_id)
        if candidate is None or candidate.status in {
                ExposureStatus.STALE, ExposureStatus.REJECTED_PUBLIC,
                ExposureStatus.REJECTED_PLACEHOLDER}:
            raise ValueError("Current actionable exposure candidate required")
        if not candidate.evidence_ids or any(
                (record := self.store.evidence.get_evidence(ref)) is None or
                record.target_ref != package.target.id for ref in candidate.evidence_ids):
            raise ValueError("Candidate source evidence is unavailable")
        if candidate.source in {ExposureSource.JS_ASSET, ExposureSource.SOURCE_MAP} and not self.current_candidate(
                package, candidate_id):
            raise ValueError("Current source artifact link is required")
        skill_id = (
            "credential-disclosure"
            if candidate.source in {ExposureSource.JS_ASSET, ExposureSource.SOURCE_MAP}
            and candidate.credential is not None else
            "protected-response-exposure"
            if candidate.source is ExposureSource.TRAFFIC and candidate.credential is not None
            and candidate.artifact_sha256 is not None else
            "internal-vhost-access"
            if candidate.category is ExposureCategory.INTERNAL_VHOST_CANDIDATE and
            package.rules.internal_vhost_testing_allowed is True else
            "overexposed-api-response"
            if candidate.category is ExposureCategory.OVEREXPOSED_API_RESPONSE else
            "unauthenticated-sensitive-download"
            if candidate.category in {ExposureCategory.UNAUTHENTICATED_RESOURCE,
                                      ExposureCategory.UNAUTHENTICATED_DOWNLOAD,
                                      ExposureCategory.PII_EXPOSURE} else
            "internal-surface-candidate"
            if candidate.category in {ExposureCategory.INTERNAL_HOST_DISCLOSURE,
                                      ExposureCategory.INTERNAL_SERVICE,
                                      ExposureCategory.INTERNAL_VHOST_CANDIDATE,
                                      ExposureCategory.ADMIN_SURFACE} else
            "sensitive-data-exposure"
        )
        key = hashlib.sha256(f"{package.target.id}:{candidate_id}".encode()).hexdigest()[:32]
        now = datetime.now(timezone.utc)
        hypothesis = hypotheses.upsert(Hypothesis(
            id="HYP-" + key, target_id=package.target.id, dedupe_key=key,
            category=("CREDENTIAL_EXPOSURE" if candidate.credential else "EXPOSURE"),
            statement=f"Current {candidate.category.value.lower().replace('_', ' ')} signal requires privacy-boundary validation",
            status=HypothesisStatus.NEEDS_RESEARCH,
            priority=candidate.priority, confidence=min(0.8, candidate.confidence / 100),
            potential_impact="Possible non-public data or internal functionality exposure",
            risk="Static or observed metadata is not a confirmed vulnerability",
            surface_key="exposure:" + candidate_id, boundary="DATA_EXPOSURE",
            why_generated="Evidence-linked exposure candidate " + candidate_id,
            prerequisites=("authoritative scope", "current evidence", "protected-content control"),
            missing=("controlled verification",),
            future_experiment="Compare an authorized control and the smallest unauthorized read",
            positive_signal="Protected content or capability crosses an unauthorized boundary",
            negative_signal="Public, placeholder, denied, stale or unrelated content",
            skill_tags=(skill_id,), source=HypothesisSource.DETERMINISTIC,
            producer="EXPOSURE_SPECIALIST_V1", evidence_ids=candidate.evidence_ids[:16],
            fact_ids=(), created_at=now, updated_at=now,
        ))
        context = contexts.build(hypothesis, profile, package=package)
        if not any(item["skill"]["name"] == skill_id for item in router.route(hypothesis, context,
                                                                                limit=5)):
            raise ValueError("Exposure skill is unavailable")
        if skill_id == "credential-disclosure":
            plan = planner.bind_exposure_artifact(package, hypothesis, context, candidate_id)
        elif skill_id == "protected-response-exposure":
            plan = planner.bind_protected_response(package, hypothesis, context, candidate_id)
        elif skill_id == "internal-vhost-access":
            source = next((item for item in self.store.source_links(package.target.id, candidate_id)
                           if item["current"] and item["source"] == candidate.source.value), None)
            if source is None:
                raise ValueError("Current VHOST source is missing")
            host = self.vhost_reference(package, candidate_id, str(source["source_ref"]))
            plan = planner.bind_vhost(
                package, hypothesis, context, candidate_id,
                source_ref=str(source["source_ref"]),
                host_sha256=hashlib.sha256(host.encode()).hexdigest())
        else:
            plan = planner.generate(package, hypothesis, context, skill_id)
            self.store.bind_plan(package.target.id, candidate_id, hypothesis.id, plan["id"])
        return PreparedExposure(hypothesis.id, plan["id"], plan["status"])

    def bind_owned_read(self, package: TargetPackage, candidate_id: str, *,
                        test_object_id: str, owner_session_id: str,
                        objects: ObjectRegistry, hypotheses: HypothesisStore,
                        contexts: SkillContextBuilder, planner: SkillPlanner,
                        profile: TargetProfile | None = None) -> PreparedExposure:
        """Bind four Phase 16 GET controls to one previously observed owned object."""
        candidate = self.store.get(package.target.id, candidate_id)
        if (candidate is None or candidate.source is not ExposureSource.TRAFFIC
                or candidate.category not in {
                    ExposureCategory.UNAUTHENTICATED_RESOURCE,
                    ExposureCategory.UNAUTHENTICATED_DOWNLOAD,
                    ExposureCategory.PII_EXPOSURE,
                    ExposureCategory.CONFIG_DISCLOSURE,
                    ExposureCategory.BACKUP_ARTIFACT,
                    ExposureCategory.DEBUG_ENDPOINT,
                    ExposureCategory.OVEREXPOSED_API_RESPONSE}
                or candidate.status in {ExposureStatus.STALE, ExposureStatus.REJECTED_PUBLIC,
                                        ExposureStatus.REJECTED_PLACEHOLDER}):
            raise ValueError("Current observed exposure candidate required")
        item = objects.get(test_object_id, package.target.id)
        if (item is None or item.package_id != package.id or not item.disposable
                or item.state is not ObjectState.READY or not item.verified_at
                or not item.external_id_hash or not item.creator_identity_id):
            raise ValueError("Verified disposable owner object required")
        source = None
        for link in self.store.source_links(package.target.id, candidate_id):
            exchange = self.traffic.get_exchange(str(link["source_ref"])) if self.traffic else None
            if (exchange is not None and exchange.attribution.verified_identity_id ==
                    item.creator_identity_id and exchange.request.record.method == "GET" and
                    exchange.response is not None and exchange.response.record.status_code == 200 and
                    exchange.request.observation_evidence_id in candidate.evidence_ids):
                source = exchange
                break
        if source is None:
            raise ValueError("Candidate lacks a verified owner GET baseline")
        links = self.store.links(package.target.id, candidate_id)
        hypothesis = hypotheses.get(links["hypothesis_id"], package.target.id) if links["hypothesis_id"] else None
        if hypothesis is None:
            raise ValueError("Prepare the exposure hypothesis before binding")
        context = contexts.build(hypothesis, profile, package=package)
        if not any(identity["id"] == item.creator_identity_id and
                   identity["verified_session_id"] == owner_session_id
                   for identity in context.identities):
            raise ValueError("Owned identity session is not currently verified")
        sensitive = candidate.category in {
            ExposureCategory.PII_EXPOSURE, ExposureCategory.CONFIG_DISCLOSURE,
            ExposureCategory.DEBUG_ENDPOINT, ExposureCategory.OVEREXPOSED_API_RESPONSE}
        skill_id = "sensitive-data-exposure" if sensitive else "unauthenticated-sensitive-download"
        variants = (("CONTROL", "OWNER"), ("BOUNDARY", "ANONYMOUS"),
                    ("BOUNDARY", "ANONYMOUS"), ("OTHER", "INVALID_OBJECT"))
        bindings = tuple(AuthorizationPlanBinding(
            source_exchange_id=source.id, test_object_id=item.id,
            object_type=item.object_type, object_ref_hash=item.external_id_hash,
            method="GET", identity_id=None if variant == "ANONYMOUS" else item.creator_identity_id,
            session_id=None if variant == "ANONYMOUS" else owner_session_id,
            role=role, variant=variant, binding="EXPOSURE_OBJECT_PATH_V1",
        ) for role, variant in variants)
        plan = planner.bind_authorization(package, hypothesis, context, skill_id,
                                          bindings, request_cap=4)
        objects.add_requirement(
            plan_id=str(plan["id"]), target_id=package.target.id,
            object_type=item.object_type, recipe_id=item.recipe_id,
            identity_id=item.creator_identity_id, tenant_id=item.tenant_id,
            parent_id=item.parent_id, test_object_id=item.id)
        self.store.bind_plan(package.target.id, candidate_id, hypothesis.id, str(plan["id"]))
        return PreparedExposure(hypothesis.id, str(plan["id"]), str(plan["status"]))

    def bind_field_read(self, package: TargetPackage, candidate_id: str, *,
                        test_object_id: str, owner_session_id: str,
                        member_session_id: str, objects: ObjectRegistry,
                        hypotheses: HypothesisStore, contexts: SkillContextBuilder,
                        planner: SkillPlanner,
                        profile: TargetProfile | None = None) -> PreparedExposure:
        candidate = self.store.get(package.target.id, candidate_id)
        item = objects.get(test_object_id, package.target.id)
        if (candidate is None or candidate.category is not ExposureCategory.OVEREXPOSED_API_RESPONSE
                or candidate.source is not ExposureSource.TRAFFIC or item is None or
                item.package_id != package.id or not item.disposable or
                item.state is not ObjectState.READY or not item.verified_at or
                not item.external_id_hash):
            raise ValueError("Current owned field exposure candidate required")
        subject = hashlib.sha256(self.store.evidence.read_content(
            item.external_id_evidence_id, allow_sensitive=True,
            max_bytes=256)).hexdigest()
        field_facts = self.store.evidence.find_facts(subject, "field_visibility", limit=8).items
        has_field_policy = any(fact.target_ref == package.target.id and
                   fact.status is FactStatus.ACTIVE and fact.source != "MANUAL" and
                   fact.confidence >= 0.9 and fact.evidence_ids and
                   re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}:ROLE-[0-9a-f]{32}", fact.object)
                   for fact in field_facts)
        private_facts = self.store.evidence.find_facts(subject, "resource_visibility", limit=8).items
        sensitive_facts = self.store.evidence.find_facts(subject, "data_classification", limit=8).items
        has_private_policy = all(any(
            fact.target_ref == package.target.id and fact.status is FactStatus.ACTIVE and
            fact.source != "MANUAL" and fact.confidence >= 0.9 and fact.evidence_ids and
            fact.object == value for fact in facts)
            for facts, value in ((private_facts, "PRIVATE"), (sensitive_facts, "SENSITIVE")))
        if not has_field_policy and not has_private_policy:
            raise ValueError("Trusted restricted-field or private sensitive policy facts required")
        owner_source = None
        member_id = None
        for link in self.store.source_links(package.target.id, candidate_id):
            exchange = self.traffic.get_exchange(str(link["source_ref"])) if self.traffic else None
            if exchange is None:
                continue
            if exchange.attribution.verified_identity_id == item.creator_identity_id:
                owner_source = exchange
            elif exchange.attribution.verified_identity_id:
                member_id = exchange.attribution.verified_identity_id
        if owner_source is None or member_id is None:
            raise ValueError("Observed owner/member identities are missing")
        links = self.store.links(package.target.id, candidate_id)
        hypothesis = hypotheses.get(links["hypothesis_id"], package.target.id) if links["hypothesis_id"] else None
        if hypothesis is None:
            raise ValueError("Prepare the field hypothesis before binding")
        context = contexts.build(hypothesis, profile, package=package)
        if not any(identity["id"] == item.creator_identity_id and
                   identity["verified_session_id"] == owner_session_id
                   for identity in context.identities) or not any(
                       identity["id"] == member_id and
                       identity["verified_session_id"] == member_session_id
                       for identity in context.identities):
            raise ValueError("Verified owner and member sessions required")
        bindings = tuple(AuthorizationPlanBinding(
            source_exchange_id=owner_source.id, test_object_id=item.id,
            object_type=item.object_type, object_ref_hash=item.external_id_hash,
            method="GET", identity_id=item.creator_identity_id if variant != "FOREIGN" else member_id,
            session_id=owner_session_id if variant != "FOREIGN" else member_session_id,
            role=role, variant=variant)
            for role, variant in (("CONTROL", "OWNER"), ("BOUNDARY", "FOREIGN"),
                                  ("OTHER", "INVALID_OBJECT")))
        plan = planner.bind_authorization(package, hypothesis, context,
                                          "overexposed-api-response", bindings, request_cap=3)
        objects.add_requirement(
            plan_id=str(plan["id"]), target_id=package.target.id,
            object_type=item.object_type, recipe_id=item.recipe_id,
            identity_id=item.creator_identity_id, tenant_id=item.tenant_id,
            parent_id=item.parent_id, test_object_id=item.id)
        self.store.bind_plan(package.target.id, candidate_id, hypothesis.id, str(plan["id"]))
        return PreparedExposure(hypothesis.id, str(plan["id"]), str(plan["status"]))
