"""Conservative, deterministic classification of recon changes as hunt signals."""

from __future__ import annotations

import hashlib
import re
from datetime import timezone
from urllib.parse import urlsplit

from .delta_models import DeltaSignal, DeltaSource, DeltaType
from .planner_models import Specialist
from .recon import ReconAssetEvent
from .target_package import TargetPackage
from .target_scope import ScopeResult


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_AUTH = frozenset({"admin", "internal", "staff", "support", "roles", "permissions",
                   "members", "users", "accounts", "organizations", "teams", "invite"})
_EXPOSURE = frozenset({"export", "download", "report", "reports", "files", "backup",
                       "logs", "debug", "config", "credentials", "secrets"})
_IDENTITY = frozenset({"user", "users", "account", "accounts", "org", "organization",
                       "tenant", "workspace", "project", "member", "members", "role"})
_SAFE_PATH_WORDS = (_AUTH | _EXPOSURE | _IDENTITY |
                    frozenset({"api", "v1", "v2", "v3", "graphql", "static", "assets",
                               "auth", "login", "oauth", "sso", "callback", "webhook",
                               "upload", "import", "settings", "profile", "mobile"}))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def event_fingerprint(event: ReconAssetEvent) -> str | None:
    if event.entity_type == "js_asset" or event.event_type in {"new_js_asset", "js_asset_changed"}:
        return event.content_sha256 if event.content_sha256 and _DIGEST.fullmatch(event.content_sha256) else None
    if event.location is None:
        return None
    return _digest(f"{event.event_type}:{event.entity_type}:{event.entity_id}:{event.location}")


def event_scope_url(event: ReconAssetEvent) -> str | None:
    location = event.location
    if not location:
        return None
    if event.event_type != "new_subdomain":
        return location
    if (event.entity_type != "subdomain" or
            any(char in location for char in "/?#@:\\") or
            not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", location) or
            location.startswith(".") or location.endswith(".")):
        return None
    return "https://" + location + "/"


def _safe_location(url: str) -> str:
    """A display hint, not the original URL or a replayable request."""
    parsed = urlsplit(url)
    host = parsed.hostname or "unknown"
    segments = parsed.path.split("/")[:5]
    path = "/".join(part if not part or part.lower() in _SAFE_PATH_WORDS else "{id}"
                    for part in segments)
    return (host + path)[:512]


class DeltaClassifier:
    """Names and hashes rank work; they never establish a vulnerability."""

    def classify_recon(
        self, package: TargetPackage, event: ReconAssetEvent,
        *, old_fingerprint: str | None = None,
        old_semantic_hash: str | None = None,
        semantic_hash: str | None = None,
        semantic_tags: tuple[str, ...] = (),
    ) -> DeltaSignal | None:
        url = event_scope_url(event)
        if not url or package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE:
            return None
        kind = {
            "new_live_host": DeltaType.NEW_HOST,
            "new_subdomain": DeltaType.NEW_HOST,
            "new_endpoint": DeltaType.NEW_ENDPOINT,
            "new_js_asset": DeltaType.NEW_JS_ASSET,
            "js_asset_changed": DeltaType.CHANGED_JS_HASH,
            "api_surface_discovered": DeltaType.NEW_API_SURFACE,
            "host_fingerprint_changed": DeltaType.NEW_TECHNOLOGY_SIGNAL,
        }.get(event.event_type)
        if kind is None:
            return None
        fingerprint = event_fingerprint(event)
        if fingerprint is None:
            return None
        if old_fingerprint == fingerprint:
            return None
        if semantic_hash is not None and not _DIGEST.fullmatch(semantic_hash):
            raise ValueError("Invalid semantic hash")
        if old_semantic_hash is not None and not _DIGEST.fullmatch(old_semantic_hash):
            raise ValueError("Invalid previous semantic hash")

        parsed = urlsplit(url)
        words = frozenset(part.lower() for part in re.split(r"[^a-zA-Z]+", parsed.path)
                           if part)
        tags: set[str] = set()
        hints: set[Specialist] = set()
        relevance = {
            DeltaType.NEW_HOST: 30,
            DeltaType.NEW_ENDPOINT: 38,
            DeltaType.NEW_JS_ASSET: 40,
            DeltaType.CHANGED_JS_HASH: 45,
            DeltaType.NEW_API_SURFACE: 52,
            DeltaType.NEW_TECHNOLOGY_SIGNAL: 20,
        }[kind]
        if event.event_type == "new_subdomain":
            relevance = 15
            tags.add("UNVERIFIED_HOST")
        if words & _AUTH:
            relevance += 25
            tags.add("PRIVILEGED_NAME")
            hints.add(Specialist.AUTHORIZATION)
        if words & _EXPOSURE:
            relevance += 25
            tags.add("EXPOSURE_NAME")
            hints.add(Specialist.EXPOSURE)
        if words & _IDENTITY:
            relevance += 10
            tags.add("IDENTITY_NAME")
            hints.add(Specialist.AUTHORIZATION)
        if "graphql" in words or "graphql" in url.lower() and kind is DeltaType.NEW_API_SURFACE:
            relevance += 25
            tags.add("GRAPHQL_SURFACE")
            hints.add(Specialist.API_GRAPHQL)
        if kind in {DeltaType.NEW_JS_ASSET, DeltaType.CHANGED_JS_HASH}:
            if parsed.path.lower().endswith(".map"):
                kind = DeltaType.NEW_SOURCE_MAP
                relevance = min(relevance, 45)
                tags.add("SOURCE_MAP_METADATA")
            if old_semantic_hash and semantic_hash == old_semantic_hash:
                relevance = 0
                tags.add("SEMANTIC_UNCHANGED")
            elif semantic_hash is None or (kind is DeltaType.CHANGED_JS_HASH and
                                           old_semantic_hash is None and not semantic_tags):
                relevance = min(relevance, 55)
                tags.add("SEMANTIC_UNKNOWN")
            else:
                relevance += 15
                tags.add("SEMANTIC_CHANGED")
        for tag in semantic_tags:
            if tag in {"GRAPHQL_OPERATION_ADDED", "HAS_GRAPHQL_OPERATION"}:
                relevance += 25
                hints.add(Specialist.API_GRAPHQL)
            elif tag in {"MESSAGE_HANDLER_ADDED", "HAS_MESSAGE_HANDLER"}:
                relevance += 25
                hints.add(Specialist.POSTMESSAGE)
            elif tag in {"MESSAGE_CHANNEL_ADDED", "HAS_MESSAGE_CHANNEL",
                         "MESSAGE_ORIGIN_REFERENCE_CHANGED"}:
                relevance += 20
                hints.add(Specialist.POSTMESSAGE)
            elif tag in {"DOM_SINK_ADDED", "HAS_DOM_SINK"}:
                relevance += 25
                hints.add(Specialist.DOM_XSS)
            elif tag in {"DOM_TRANSFORM_ADDED", "HAS_DOM_TRANSFORM"}:
                relevance += 15
                hints.add(Specialist.DOM_XSS)
            elif tag in {"API_OPERATION_ADDED", "HAS_API_ROUTE"}:
                relevance += 20
                hints.update({Specialist.API_GRAPHQL, Specialist.AUTHORIZATION})
            elif tag in {"SOURCE_MAP_ADDED", "HAS_SOURCE_MAP_REF",
                         "CONFIG_PATTERN_ADDED", "HAS_CONFIG_PATTERN"}:
                relevance += 10
                hints.add(Specialist.EXPOSURE)
            else:
                raise ValueError("Unsupported semantic signal")
            tags.add(tag)
        if kind is DeltaType.CHANGED_JS_HASH and old_fingerprint is None:
            relevance = min(relevance, 55)
            tags.add("PRIOR_HASH_UNKNOWN")
        if kind in {DeltaType.NEW_JS_ASSET, DeltaType.CHANGED_JS_HASH} and not hints:
            relevance = min(relevance, 55)
            tags.add("NO_SECURITY_SEMANTIC_ADD")
        reason = ("SEMANTIC_UNCHANGED" if "SEMANTIC_UNCHANGED" in tags else
                  "SEMANTIC_UNKNOWN" if "SEMANTIC_UNKNOWN" in tags or
                  "PRIOR_HASH_UNKNOWN" in tags else "CLASSIFIED")
        at = event.provenance.observed_at
        if at is not None and at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        return DeltaSignal(
            delta_type=kind, source=DeltaSource.RECON,
            source_ref=f"asset_events:{event.event_id}",
            entity_type=event.entity_type,
            entity_id=str(event.entity_id) if event.entity_id is not None else None,
            location_hash=_digest(url), display_location=_safe_location(url),
            old_fingerprint=old_fingerprint, new_fingerprint=fingerprint,
            observed_at=at.isoformat() if at else "", relevance=min(relevance, 100),
            specialist_hints=tuple(sorted(hints, key=lambda item: item.value)),
            signal_tags=tuple(sorted(tags)), semantic_hash=semantic_hash,
            reason_code=reason,
        )
