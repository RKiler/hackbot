"""Local authenticated Montoya observation adapter; never executes target traffic."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
import sqlite3
import socketserver
import threading
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .burp import BurpError, BurpProxyProvider
from .config import BurpSettings
from .domain import TrafficSource
from .secrets import SecretProvider, SecretValue
from .target_package import TargetPackage
from .target_scope import ScopeResult
from .traffic import (CapturedRequest, CapturedResponse, ExchangeState,
                      TrafficError, TrafficExchange, TrafficStore, _auth_material_present)


_CAPTURE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_VERSION = "1.0"


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BurpError("Duplicate bridge field")
        result[key] = value
    return result


def _fields(value: object, required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value) or set(value) - required - optional:
        raise BurpError("Invalid bridge observation schema")
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 48:
        raise BurpError("Invalid bridge timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise BurpError("Invalid bridge timestamp") from None
    if result.tzinfo is None:
        raise BurpError("Invalid bridge timestamp")
    return result.astimezone(timezone.utc)


def _headers(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or len(value) > 128:
        raise BurpError("Invalid bridge headers")
    pairs = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2 or not all(isinstance(part, str) for part in item):
            raise BurpError("Invalid bridge headers")
        pairs.append((item[0], item[1]))
    return tuple(pairs)


def _body(value: object, max_event_bytes: int) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > max_event_bytes:
        raise BurpError("Invalid bridge body")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise BurpError("Invalid bridge body") from None
    if len(result) > max_event_bytes:
        raise BurpError("Invalid bridge body")
    return result


def _canonical_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class BurpObservation:
    capture_id: str
    event: str
    listener: str
    at: datetime
    bridge_version: str
    request: CapturedRequest = field(repr=False)
    request_digest: str
    response: CapturedResponse | None = field(default=None, repr=False)
    response_digest: str | None = None

    @classmethod
    def parse(cls, payload: bytes, max_event_bytes: int) -> BurpObservation:
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= max_event_bytes:
            raise BurpError("Bridge observation is oversized or empty")
        try:
            value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
            root = _fields(value, {"schema", "capture_id", "event", "listener", "at",
                                   "bridge_version", "request"}, {"response"})
            if root["schema"] != 1 or root["event"] not in {"REQUEST", "RESPONSE"}:
                raise BurpError("Unsupported bridge observation")
            capture_id = root["capture_id"]
            listener = root["listener"]
            version = root["bridge_version"]
            if (not isinstance(capture_id, str) or not _CAPTURE_ID.fullmatch(capture_id)
                    or not isinstance(listener, str) or not re.fullmatch(r"[A-Za-z0-9.:[\]_-]{1,128}", listener)
                    or not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", version)):
                raise BurpError("Invalid bridge capture metadata")
            request_data = _fields(root["request"], {"method", "url", "http_version", "headers", "body_b64"})
            timestamp = _timestamp(root["at"])
            request = CapturedRequest(
                method=request_data["method"], url=request_data["url"],
                http_version=request_data["http_version"], headers=_headers(request_data["headers"]),
                body=_body(request_data["body_b64"], max_event_bytes), observed_at=timestamp,
            )
            response_data = root.get("response")
            if root["event"] == "REQUEST" and response_data is not None:
                raise BurpError("Request observation cannot contain a response")
            if root["event"] == "RESPONSE" and response_data is None:
                raise BurpError("Response observation is incomplete")
            response = None
            response_digest = None
            if response_data is not None:
                item = _fields(response_data, {"status_code", "http_version", "headers", "body_b64"},
                               {"elapsed_ms"})
                response = CapturedResponse(
                    status_code=item["status_code"], headers=_headers(item["headers"]),
                    body=_body(item["body_b64"], max_event_bytes),
                    http_version=item["http_version"], observed_at=timestamp,
                    elapsed_ms=item.get("elapsed_ms"),
                )
                response_digest = _canonical_hash(item)
            return cls(capture_id, root["event"], listener, timestamp, version,
                       request, _canonical_hash(request_data), response, response_digest)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, KeyError, TrafficError,
                ValueError, OverflowError):
            raise BurpError("Invalid bridge observation") from None


@dataclass(frozen=True, slots=True)
class IngestResult:
    exchange_id: str | None
    state: str
    scope: str
    duplicate: bool = False

    def to_dict(self) -> dict[str, object]:
        return {"exchange_id": self.exchange_id, "state": self.state,
                "scope": self.scope, "duplicate": self.duplicate}


class BurpCaptureProvider:
    """Identity-aware adapter into Phase 9; no Burp-specific core records."""

    name = "MONTOYA_V1"
    source = TrafficSource.BURP

    def __init__(self, package: TargetPackage, proxy: BurpProxyProvider, traffic: TrafficStore) -> None:
        traffic._target_check(package)
        self.package = package
        self.proxy = proxy
        self.traffic = traffic
        self._lock = threading.RLock()

    def _existing_exchange(self, capture_id: str) -> TrafficExchange | None:
        provider_hash = hashlib.sha256(capture_id.encode()).hexdigest()
        with self.traffic.evidence._connection() as connection:
            row = connection.execute("""SELECT exchange_id FROM traffic_exchanges
                WHERE target_id=? AND source='BURP' AND provider_reference_hash=? LIMIT 1""",
                (self.package.target.id, provider_hash)).fetchone()
        return self.traffic.get_exchange(row["exchange_id"]) if row else None

    def _capture_is_retired(self, capture_id: str) -> bool:
        provider_hash = hashlib.sha256(capture_id.encode()).hexdigest()
        with self.traffic.evidence._connection() as connection:
            return connection.execute(
                "SELECT 1 FROM traffic_exchanges e "
                "JOIN traffic_payload_retirements r ON r.exchange_id=e.exchange_id "
                "WHERE e.target_id=? AND e.source='BURP' "
                "AND e.provider_reference_hash=? LIMIT 1",
                (self.package.target.id, provider_hash),
            ).fetchone() is not None

    def ingest_bytes(self, payload: bytes) -> IngestResult:
        observation = BurpObservation.parse(payload, self.proxy.settings.max_event_bytes)
        return self.ingest(observation)

    def ingest(self, observation: BurpObservation) -> IngestResult:
        try:
            return self._ingest(observation)
        except sqlite3.Error:
            raise BurpError("Bridge persistence unavailable") from None

    def _ingest(self, observation: BurpObservation) -> IngestResult:
        if not isinstance(observation, BurpObservation):
            raise BurpError("Invalid bridge observation")
        binding = self.proxy.resolve_listener(self.package.target.id, observation.listener)
        scope = self.package.scope.evaluate_url(observation.request.url).result
        if scope is not ScopeResult.IN_SCOPE and self.proxy.settings.third_party_capture == "DROP":
            return IngestResult(None, "DROPPED_BY_POLICY", scope.value)
        request = observation.request
        response = observation.response
        scope_source_url = None
        auth_material_observed = False
        if scope is not ScopeResult.IN_SCOPE:
            scope_source_url = request.url
            parsed = urlsplit(request.url)
            auth_material_observed = _auth_material_present(request.headers, parsed.query)
            public_url = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
            request = CapturedRequest(request.method, public_url, observed_at=request.observed_at,
                                      http_version=request.http_version)
            if response is not None:
                response = CapturedResponse(response.status_code, observed_at=response.observed_at,
                                            elapsed_ms=response.elapsed_ms, http_version=response.http_version)
        target_id = self.package.target.id
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if self._capture_is_retired(observation.capture_id):
                raise BurpError("Retired bridge capture cannot be replayed")
            with self.traffic.evidence._connection() as connection:
                connection.execute("""INSERT OR IGNORE INTO burp_capture_index
                    (target_id,capture_id,request_digest,listener_key,created_at,updated_at)
                    VALUES (?,?,?,?,?,?)""",
                    (target_id, observation.capture_id, observation.request_digest,
                     observation.listener, now, now))
                row = connection.execute("""SELECT request_digest,response_digest,listener_key,exchange_id
                    FROM burp_capture_index WHERE target_id=? AND capture_id=?""",
                    (target_id, observation.capture_id)).fetchone()
            if (row is None or row["request_digest"] != observation.request_digest
                    or row["listener_key"] != observation.listener):
                raise BurpError("Conflicting bridge capture ID")
            exchange = self.traffic.get_exchange(row["exchange_id"]) if row["exchange_id"] else None
            if exchange is None:
                exchange = self._existing_exchange(observation.capture_id)
            if exchange is not None and self._capture_is_retired(observation.capture_id):
                raise BurpError("Retired bridge capture cannot be replayed")
            duplicate = exchange is not None
            if exchange is None:
                try:
                    exchange = self.traffic.store_request(
                        self.package, request, source=TrafficSource.BURP, capture_provider=self.name,
                        browser_manager=self.proxy.browser, browser_session_id=binding.browser_session_id,
                        provider_reference=observation.capture_id,
                        scope_source_url=scope_source_url,
                        auth_material_observed=auth_material_observed,
                    )
                except TrafficError:
                    exchange = self._existing_exchange(observation.capture_id)
                    if exchange is None:
                        raise
            with self.traffic.evidence._connection() as connection:
                connection.execute("""UPDATE burp_capture_index SET exchange_id=?,updated_at=?
                    WHERE target_id=? AND capture_id=?""",
                    (exchange.id, now, target_id, observation.capture_id))
            if response is not None:
                with self.traffic.evidence._connection() as connection:
                    row = connection.execute("""SELECT response_digest FROM burp_capture_index
                        WHERE target_id=? AND capture_id=?""", (target_id, observation.capture_id)).fetchone()
                    if row["response_digest"] is not None and row["response_digest"] != observation.response_digest:
                        raise BurpError("Conflicting bridge response")
                    connection.execute("""UPDATE burp_capture_index SET response_digest=?,updated_at=?
                        WHERE target_id=? AND capture_id=?""",
                        (observation.response_digest, now, target_id, observation.capture_id))
                if exchange.response is None:
                    exchange = self.traffic.store_response(exchange.id, response)
                    duplicate = False
            self.proxy.heartbeat(target_id, observation.bridge_version)
            return IngestResult(exchange.id, exchange.state.value, scope.value, duplicate)


class _BoundedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler],
                 max_inflight: int) -> None:
        self._slots = threading.BoundedSemaphore(max_inflight)
        super().__init__(address, handler)

    def process_request(self, request: object, client_address: object) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: object, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class _BridgeHandler(BaseHTTPRequestHandler):
    server: BurpBridgeServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-Hackbot-Bridge-Token", "")
        return hmac.compare_digest(supplied.encode(), self.server._token)

    def _reply(self, status: int, data: dict[str, object]) -> None:
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return

    def do_GET(self) -> None:
        if not self._authorized():
            self._reply(401, {"error": "unauthorized"})
            return
        if self.path == "/v1/health":
            self._reply(200, {"status": "BRIDGE_RUNNING", "version": _VERSION})
        else:
            self._reply(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if not self._authorized():
            self._reply(401, {"error": "unauthorized"})
            return
        if self.path not in {"/v1/capture", "/v1/heartbeat"}:
            self._reply(404, {"error": "not_found"})
            return
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Type") != "application/json":
            self._reply(415, {"error": "invalid_content_type"})
            return
        length = self.headers.get("Content-Length", "")
        if not length.isascii() or not length.isdecimal():
            self._reply(411, {"error": "length_required"})
            return
        if len(length) > 10:
            self._reply(413, {"error": "event_too_large"})
            return
        size = int(length)
        if size < 1 or size > self.server.settings.max_event_bytes:
            self._reply(413, {"error": "event_too_large"})
            return
        self.connection.settimeout(5)
        try:
            payload = self.rfile.read(size)
            if len(payload) != size:
                self._reply(400, {"error": "invalid_event"})
                return
            if self.path == "/v1/heartbeat":
                value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
                data = _fields(value, {"version"}, {"dropped_events"})
                self.server.provider.proxy.heartbeat(self.server.provider.package.target.id,
                                                     data["version"], data.get("dropped_events"))
                self._reply(200, {"status": "ok"})
            else:
                result = self.server.provider.ingest_bytes(payload)
                self._reply(200 if result.duplicate else 201, result.to_dict())
        except (BurpError, TrafficError, ValueError, TypeError, UnicodeError, sqlite3.Error,
                json.JSONDecodeError, OSError):
            self._reply(400, {"error": "invalid_event"})


class BurpBridgeServer(_BoundedHTTPServer):
    """Explicitly started in a trusted BugHunter process, loopback only."""

    @classmethod
    def from_secret_provider(cls, settings: BurpSettings, provider: BurpCaptureProvider,
                             secrets: SecretProvider) -> BurpBridgeServer:
        if settings.bridge_secret_ref is None:
            raise BurpError("Bridge secret reference is unavailable")
        return cls(settings, provider, secrets.get(settings.bridge_secret_ref))

    def __init__(self, settings: BurpSettings, provider: BurpCaptureProvider,
                 token: SecretValue) -> None:
        if not isinstance(settings, BurpSettings) or not isinstance(provider, BurpCaptureProvider):
            raise BurpError("Invalid bridge configuration")
        if provider.proxy.settings != settings:
            raise BurpError("Bridge settings disagree with proxy settings")
        if not isinstance(token, SecretValue):
            raise BurpError("Bridge token is unavailable")
        value = token.reveal(execution_boundary=True)
        if re.fullmatch(r"[A-Za-z0-9._~-]{32,256}", value) is None:
            raise BurpError("Bridge token length is invalid")
        self.settings = settings
        self.provider = provider
        self._token = value.encode()
        super().__init__(("127.0.0.1", settings.bridge_port), _BridgeHandler, settings.max_inflight)
