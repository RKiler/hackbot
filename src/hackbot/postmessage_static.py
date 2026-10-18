"""Bounded cross-origin messaging protocol reconstruction from the shared Babel parser."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
from importlib.resources import as_file, files
import json
import re
import subprocess

from .domxss_static import ANALYSIS_TIMEOUT_SECONDS, MAX_ASSET_BYTES, SourceLocation


ANALYZER_VERSION = "1.9.1"
MAX_HANDLERS = 64
MAX_PROTOCOLS = 32
MAX_RPC_METHODS = 16
_MESSAGE_HINT = re.compile(
    rb"postMessage|onmessage|MessageChannel|MessagePort|addEventListener|"
    rb"SharedWorker|BroadcastChannel"
)
_SENSITIVE = frozenset({"DOM_READ", "API_OR_RPC", "DOM_WRITE", "NAVIGATION"})


class MessageCandidateStatus(StrEnum):
    STATIC_CANDIDATE = "STATIC_CANDIDATE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    RUNTIME_READY = "RUNTIME_READY"
    RUNTIME_TESTED = "RUNTIME_TESTED"
    VALIDATION_READY = "VALIDATION_READY"
    REJECTED = "REJECTED"
    STALE = "STALE"


@dataclass(frozen=True, slots=True)
class TrustCheck:
    factor: str
    kind: str
    value: str | None
    location: SourceLocation


@dataclass(frozen=True, slots=True)
class RpcMethodInfo:
    name: str
    argument_fields: tuple[str, ...]
    result_shape: str
    capability: str
    authorization_assumptions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MessageProtocolCandidate:
    candidate_id: str
    target_id: str
    artifact_ids: tuple[str, ...]
    asset_hashes: tuple[str, ...]
    handler_fingerprint: str
    receiver: str
    receiver_location: SourceLocation
    message_types: tuple[str, ...]
    reply_types: tuple[str, ...]
    sender_contexts: tuple[str, ...]
    origin_checks: tuple[TrustCheck, ...]
    source_checks: tuple[TrustCheck, ...]
    port_accepted: bool
    port_created: bool
    port_bound: bool
    rpc_methods: tuple[str, ...]
    sensitive_operations: tuple[str, ...]
    protocol_sequence: tuple[str, ...]
    priority: int
    status: MessageCandidateStatus
    payload_fields: tuple[str, ...] = ()
    rpc_details: tuple[RpcMethodInfo, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    route: str | None = None
    source_map_sha256: str | None = None
    mapped_source: str | None = None
    runtime_status: str = "NOT_TESTED"
    recent_change: bool = False
    transport_kind: str = "WINDOW"

    @property
    def origin_validation(self) -> str:
        return self.origin_checks[0].kind if self.origin_checks else "MISSING"

    @property
    def source_validation(self) -> str:
        return self.source_checks[0].kind if self.source_checks else "MISSING"


@dataclass(frozen=True, slots=True)
class MessageAnalysis:
    target_id: str
    artifact_id: str
    asset_sha256: str
    analyzer_version: str
    analyzed_at: datetime
    status: str
    handlers: int
    senders: int
    channels: int
    candidates: tuple[MessageProtocolCandidate, ...]
    parse_errors: int = 0
    reason: str | None = None


def _location(value: object) -> SourceLocation:
    if (not isinstance(value, dict) or type(value.get("line")) is not int
            or type(value.get("column")) is not int or value["line"] < 1
            or value["column"] < 1):
        raise ValueError("Invalid message AST location")
    return SourceLocation(value["line"], value["column"])


def _short_strings(value: object, limit: int = 16) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("Invalid message AST strings")
    return tuple(item for item in value[:limit]
                 if isinstance(item, str) and 0 < len(item) <= 80 and "\x00" not in item)


def _checks(value: object, factor: str) -> tuple[TrustCheck, ...]:
    if not isinstance(value, list):
        raise ValueError("Invalid message trust checks")
    result: list[TrustCheck] = []
    for item in value[:8]:
        if not isinstance(item, dict) or item.get("factor") != factor:
            continue
        kind = item.get("kind")
        if not isinstance(kind, str) or len(kind) > 32:
            continue
        raw = item.get("value") if factor == "ORIGIN" else item.get("expected")
        safe = raw[:160] if isinstance(raw, str) and "\x00" not in raw else None
        result.append(TrustCheck(factor, kind, safe, _location(item.get("location"))))
    return tuple(result)


def _rpc_details(value: object, methods: tuple[str, ...],
                 origin: tuple[TrustCheck, ...], source: tuple[TrustCheck, ...]
                 ) -> tuple[RpcMethodInfo, ...]:
    if not isinstance(value, list):
        raise ValueError("Invalid RPC analysis")
    assumptions = tuple(name for name, checks in (("ORIGIN_CHECK", origin),
                                                  ("SOURCE_CHECK", source)) if checks)
    result = []
    for item in value[:MAX_RPC_METHODS]:
        if not isinstance(item, dict) or item.get("name") not in methods:
            continue
        shape, capability = item.get("result_shape"), item.get("capability")
        if shape not in {"NONE", "OBJECT", "STRING", "DYNAMIC", "UNKNOWN"} or capability not in {
                "READ", "WRITE", "UNKNOWN"}:
            continue
        result.append(RpcMethodInfo(item["name"],
                                    _short_strings(item.get("argument_fields", []), 8),
                                    shape, capability, assumptions))
    return tuple(result)


def _score(*, origin: tuple[TrustCheck, ...], source: tuple[TrustCheck, ...],
           port: bool, methods: tuple[str, ...], operations: tuple[str, ...],
           replies: tuple[str, ...], two_stage: bool, recent: bool) -> int:
    score = 20
    if not origin:
        score += 20
    elif any(check.kind in {"SUBSTRING", "STARTSWITH", "ENDSWITH",
                                "REGEX_REVIEW", "WEAK_COMPARISON", "UNRESOLVED",
                                "UNRESOLVED_BRANCH", "COMPOSITE_REVIEW",
                                "ALLOWLIST_REVIEW", "NULL_ORIGIN_REVIEW"}
             for check in origin):
        score += 15
    if not source and port:
        score += 10
    if port:
        score += 15
    if methods:
        score += 10
    if _SENSITIVE.intersection(operations):
        score += 10
    if "DOM_WRITE" in operations:
        score += 15
    if replies:
        score += 5
    if two_stage:
        score += 10
    if recent:
        score += 5
    if origin and all(check.kind in {"EXACT", "EXACT_CURRENT_ORIGIN"} for check in origin) and source:
        score -= 20
    return max(0, min(100, score))


class PostMessageStaticAnalyzer:
    """Bounded AST metadata extraction; no JavaScript execution or network access."""

    def __init__(self, *, node_binary: str = "node") -> None:
        self.node_binary = node_binary

    def analyze(self, *, target_id: str, artifact_id: str, body: bytes,
                evidence_id: str, recent_change: bool = False) -> MessageAnalysis:
        if not target_id or not artifact_id or not evidence_id or not isinstance(body, bytes):
            raise ValueError("Invalid messaging analysis input")
        digest = hashlib.sha256(body).hexdigest()
        now = datetime.now(timezone.utc)

        def empty(status: str, reason: str) -> MessageAnalysis:
            return MessageAnalysis(target_id, artifact_id, digest, ANALYZER_VERSION, now,
                                   status, 0, 0, 0, (), reason=reason)

        if len(body) > MAX_ASSET_BYTES:
            return empty("ANALYSIS_LIMIT_REACHED", "ASSET_TOO_LARGE")
        if not _MESSAGE_HINT.search(body):
            return empty("NO_MESSAGE_SIGNAL", "CHEAP_TRIAGE")
        try:
            helper = files("hackbot").joinpath("message_ast.cjs")
            with as_file(helper) as helper_path:
                process = subprocess.run(
                    [self.node_binary, "--max-old-space-size=128", str(helper_path)],
                    input=body, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=ANALYSIS_TIMEOUT_SECONDS, check=False,
                )
            if process.returncode != 0 or len(process.stdout) > 262_144:
                return empty("PARSE_FAILED", "PARSER_UNAVAILABLE_OR_LIMIT")
            parsed = json.loads(process.stdout)
        except subprocess.TimeoutExpired:
            return empty("PARSE_FAILED", "PARSER_TIMEOUT")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return empty("PARSE_FAILED", "PARSER_UNAVAILABLE_OR_LIMIT")
        if not isinstance(parsed, dict) or parsed.get("parse_error"):
            return empty("PARSE_FAILED", "MALFORMED_JAVASCRIPT")
        handlers, senders = parsed.get("handlers"), parsed.get("senders")
        if not isinstance(handlers, list) or not isinstance(senders, list):
            return empty("PARSE_FAILED", "INVALID_PARSER_RESULT")
        emitted = {item.get("message_type"): item for item in senders[:64]
                   if isinstance(item, dict) and isinstance(item.get("message_type"), str)}
        candidates: list[MessageProtocolCandidate] = []
        try:
            for handler in handlers[:MAX_HANDLERS]:
                if not isinstance(handler, dict):
                    continue
                fingerprint = handler.get("fingerprint")
                if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                    continue
                accepted = _short_strings(handler.get("accepted_types", []))
                replies = _short_strings(handler.get("reply_types", []))
                methods = _short_strings(handler.get("rpc_methods", []), MAX_RPC_METHODS)
                payload_fields = _short_strings(handler.get("payload_fields", []))
                operations = _short_strings(handler.get("operations", []))
                checks = handler.get("checks", [])
                origin = _checks(checks, "ORIGIN")
                source = _checks(checks, "SOURCE")
                rpc_details = _rpc_details(handler.get("rpc_details", []), methods,
                                           origin, source)
                receiver = handler.get("receiver")
                if not isinstance(receiver, str) or len(receiver) > 80:
                    continue
                transport_kind = handler.get("transport_kind", "WRAPPER_UNKNOWN")
                if transport_kind not in {"WINDOW", "WORKER", "SHARED_WORKER",
                                          "BROADCAST_CHANNEL", "MESSAGE_PORT",
                                          "SELF_CONTEXT_UNKNOWN", "WRAPPER_UNKNOWN"}:
                    continue
                port = handler.get("accepts_port") is True
                port_bound = handler.get("binds_port") is True
                sender_contexts = tuple(dict.fromkeys((
                    *_short_strings(handler.get("sender_contexts", []), 8),
                    *(item.get("sender", "") for name, item in emitted.items()
                      if name in accepted and isinstance(item.get("sender"), str)),
                )))[:8]
                two_stage = port and bool(replies) and (port_bound or bool(methods))
                sequence = tuple([f"RECEIVE:{name}" for name in accepted[:4]]
                                 + (["ACTIVATE"] if replies else [])
                                 + [f"REPLY:{name}" for name in replies[:4]]
                                 + (["ACCEPT_PORT", "BIND_RPC"] if port and port_bound else
                                    ["ACCEPT_PORT"] if port else [])
                                 + [f"RPC:{name}" for name in methods[:4]])
                priority = _score(origin=origin, source=source, port=port,
                                  methods=methods, operations=operations, replies=replies,
                                  two_stage=two_stage, recent=recent_change)
                if transport_kind != "WINDOW":
                    priority = min(priority, 59)
                status = (MessageCandidateStatus.STATIC_CANDIDATE
                          if priority >= 60 else MessageCandidateStatus.NEEDS_MANUAL_REVIEW)
                candidates.append(MessageProtocolCandidate(
                    candidate_id="MSG-" + hashlib.sha256(
                        (target_id + ":" + fingerprint +
                         (":" + transport_kind if transport_kind != "WINDOW" else "")).encode()
                    ).hexdigest()[:32],
                    target_id=target_id, artifact_ids=(artifact_id,), asset_hashes=(digest,),
                    handler_fingerprint=fingerprint, receiver=receiver,
                    receiver_location=_location(handler.get("location")),
                    message_types=accepted, reply_types=replies,
                    sender_contexts=sender_contexts, origin_checks=origin,
                    source_checks=source, port_accepted=port,
                    port_created=handler.get("creates_channel") is True,
                    port_bound=port_bound, rpc_methods=methods,
                    sensitive_operations=operations, protocol_sequence=sequence,
                    priority=priority, status=status, evidence_ids=(evidence_id,),
                    payload_fields=payload_fields, rpc_details=rpc_details,
                    recent_change=recent_change, transport_kind=transport_kind,
                ))
                if len(candidates) >= MAX_PROTOCOLS:
                    break
        except ValueError:
            return empty("PARSE_FAILED", "INVALID_PARSER_RESULT")
        return MessageAnalysis(target_id, artifact_id, digest, ANALYZER_VERSION, now,
                               "ANALYZED", min(len(handlers), MAX_HANDLERS),
                               min(len(senders), 64), min(int(parsed.get("channels", 0)), 64),
                               tuple(candidates), max(0, int(parsed.get("parse_errors", 0))))


def link_protocols(candidates: tuple[MessageProtocolCandidate, ...]
                   ) -> tuple[MessageProtocolCandidate, ...]:
    """Link sender/receiver constants across current assets without a graph database."""
    by_reply: dict[str, set[str]] = {}
    for item in candidates:
        for name in item.reply_types:
            by_reply.setdefault(name, set()).add(item.candidate_id)
    linked = []
    for item in candidates:
        predecessors = sorted({candidate for name in item.message_types
                               for candidate in by_reply.get(name, ())
                               if candidate != item.candidate_id})[:8]
        if predecessors:
            linked.append(replace(item, protocol_sequence=(
                *(f"AFTER:{candidate}" for candidate in predecessors),
                *item.protocol_sequence)))
        else:
            linked.append(item)
    return tuple(linked)
