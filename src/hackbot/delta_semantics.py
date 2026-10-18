"""Bounded security-oriented signatures for already saved JavaScript bodies."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .api_graphql import MAX_JS_BYTES, extract_js_api_artifacts, parse_operations


_MESSAGE = re.compile(rb"(?:addEventListener\s*\(\s*['\"]message['\"]|\.onmessage\s*=|"
                      rb"MessageChannel\s*\()")
_SINK = re.compile(rb"(?:\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|"
                   rb"\.srcdoc\s*=|\beval\s*\(|\bFunction\s*\()")
_TRANSFORM = re.compile(rb"(?:decodeURIComponent\s*\(|decodeURI\s*\(|\bunescape\s*\(|"
                        rb"\batob\s*\()")
_CHANNEL = re.compile(rb"(?:\bMessageChannel\s*\(|\bevent\.ports\b|\bport[12]?\.postMessage\s*\()")
_ORIGIN_GUARD = re.compile(rb"\b[A-Za-z_$][A-Za-z0-9_$]{0,31}\.origin\b")
_SOURCE_GUARD = re.compile(rb"\b[A-Za-z_$][A-Za-z0-9_$]{0,31}\.source\b")
_SOURCE_MAP = re.compile(rb"\bsourceMappingURL\s*=")
_CONFIG = re.compile(rb"(?:\bclient_secret\b|\bprivate_key\b|\bsecret_key\b|"
                     rb"\bDATABASE_URL\b|\bprocess\.env\b|\bimport\.meta\.env\b)", re.I)


@dataclass(frozen=True, slots=True)
class JSSemantics:
    fingerprint: str | None
    routes: frozenset[str]
    graphql_operations: frozenset[str]
    message_count: int
    sink_count: int
    transform_count: int
    channel_count: int = 0
    origin_guard_count: int = 0
    source_guard_count: int = 0
    source_map_count: int = 0
    config_count: int = 0


def js_semantics(body: bytes) -> JSSemantics:
    """Never execute target JS; unsupported/empty extraction is unknown, not clean."""
    if not isinstance(body, bytes) or len(body) > MAX_JS_BYTES:
        return JSSemantics(None, frozenset(), frozenset(), 0, 0, 0)
    documents, routes = extract_js_api_artifacts(body)
    operations: set[str] = set()
    for document, _line in documents:
        try:
            operations.update(f"{item.kind}:{item.name}:{','.join(item.root_fields)}"
                              for item in parse_operations(document))
        except ValueError:
            continue
    route_keys = frozenset(f"{item.method}:{item.path}" for item in routes)
    messages = len(_MESSAGE.findall(body))
    sinks = len(_SINK.findall(body))
    transforms = len(_TRANSFORM.findall(body))
    channels = len(_CHANNEL.findall(body))
    origin_guards = len(_ORIGIN_GUARD.findall(body))
    source_guards = len(_SOURCE_GUARD.findall(body))
    source_maps = len(_SOURCE_MAP.findall(body))
    configs = len(_CONFIG.findall(body))
    counts = (messages, sinks, transforms, channels, origin_guards,
              source_guards, source_maps, configs)
    if not (route_keys or operations or any(counts)):
        return JSSemantics(None, route_keys, frozenset(operations),
                           *counts)
    payload = (sorted(route_keys), sorted(operations), *counts)
    digest = hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()
    return JSSemantics(digest, route_keys, frozenset(operations),
                       *counts)


def semantic_additions(old: JSSemantics, new: JSSemantics) -> tuple[str, ...]:
    if new.fingerprint is None:
        return ()
    if old.fingerprint is None:
        return new_asset_signals(new)
    tags = []
    if new.graphql_operations - old.graphql_operations:
        tags.append("GRAPHQL_OPERATION_ADDED")
    if new.routes - old.routes:
        tags.append("API_OPERATION_ADDED")
    if new.message_count > old.message_count:
        tags.append("MESSAGE_HANDLER_ADDED")
    if new.channel_count > old.channel_count:
        tags.append("MESSAGE_CHANNEL_ADDED")
    if (new.origin_guard_count != old.origin_guard_count or
            new.source_guard_count != old.source_guard_count):
        tags.append("MESSAGE_ORIGIN_REFERENCE_CHANGED")
    if new.sink_count > old.sink_count:
        tags.append("DOM_SINK_ADDED")
    if new.transform_count > old.transform_count:
        tags.append("DOM_TRANSFORM_ADDED")
    if new.source_map_count > old.source_map_count:
        tags.append("SOURCE_MAP_ADDED")
    if new.config_count > old.config_count:
        tags.append("CONFIG_PATTERN_ADDED")
    return tuple(tags)


def new_asset_signals(value: JSSemantics) -> tuple[str, ...]:
    """Signals present in a newly observed body; not proof of exploitability."""
    if value.fingerprint is None:
        return ()
    tags = []
    if value.graphql_operations:
        tags.append("HAS_GRAPHQL_OPERATION")
    if value.routes:
        tags.append("HAS_API_ROUTE")
    if value.message_count:
        tags.append("HAS_MESSAGE_HANDLER")
    if value.channel_count:
        tags.append("HAS_MESSAGE_CHANNEL")
    if value.sink_count:
        tags.append("HAS_DOM_SINK")
    if value.transform_count:
        tags.append("HAS_DOM_TRANSFORM")
    if value.source_map_count:
        tags.append("HAS_SOURCE_MAP_REF")
    if value.config_count:
        tags.append("HAS_CONFIG_PATTERN")
    return tuple(tags)
