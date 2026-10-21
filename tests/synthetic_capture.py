"""Loopback capture proxy for the synthetic Hunt acceptance target."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import socket
from threading import Thread
from urllib.parse import urlsplit

from hackbot.burp_bridge import BurpCaptureProvider, BurpObservation
from hackbot.traffic import CapturedRequest, CapturedResponse


_HOP_HEADERS = frozenset({"connection", "proxy-connection", "keep-alive",
                          "transfer-encoding", "te", "trailer", "upgrade"})


class _ProxyHandler(BaseHTTPRequestHandler):
    server: ThreadingHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_CONNECT(self) -> None:
        proxy = self.server.synthetic_proxy
        if self.path != proxy.fixture_netloc or proxy.provider is None:
            self.send_error(403)
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.close_connection = False
        self._fixture_tunnel = True
        self.handle_one_request()
        self.close_connection = True

    def do_GET(self) -> None:
        self._forward()

    def do_HEAD(self) -> None:
        self._forward()

    def do_POST(self) -> None:
        self._forward()

    def do_PATCH(self) -> None:
        self._forward()

    def do_DELETE(self) -> None:
        self._forward()

    def _forward(self) -> None:
        proxy = self.server.synthetic_proxy
        parsed = urlsplit(self.path)
        tunneled = getattr(self, "_fixture_tunnel", False)
        if tunneled:
            valid_url = (self.path.startswith("/") and not self.path.startswith("//")
                         and not parsed.scheme and not parsed.netloc
                         and self.headers.get("Host") == proxy.fixture_netloc)
            request_url = proxy.fixture_url + self.path
        else:
            valid_url = (parsed.scheme == "http" and parsed.netloc == proxy.fixture_netloc
                         and self.headers.get("Host") == proxy.fixture_netloc)
            request_url = self.path
        if (proxy.provider is None or not valid_url or parsed.username
                or parsed.password or parsed.fragment):
            self.send_error(403)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if size < 0 or size > 65_536 or self.headers.get("Transfer-Encoding"):
            self.send_error(413)
            return
        body = self.rfile.read(size) if size else None
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        headers = {key: value for key, value in self.headers.items()
                   if key.lower() not in _HOP_HEADERS}
        try:
            connection = http.client.HTTPConnection("127.0.0.1", proxy.fixture_port,
                                                    timeout=5)
            try:
                connection.request(self.command, path, body=body, headers=headers)
                upstream = connection.getresponse()
                payload = upstream.read(2_097_153)
                if len(payload) > 2_097_152:
                    raise ValueError("Fixture response exceeds capture limit")
                response_headers = tuple(upstream.getheaders())
                status = upstream.status
            finally:
                connection.close()
            now = datetime.now(timezone.utc)
            request = CapturedRequest(
                self.command, request_url, tuple(self.headers.items()), body,
                observed_at=now, http_version="HTTP/1.1")
            response = CapturedResponse(
                status, response_headers, payload, observed_at=now,
                http_version="HTTP/1.1")
            capture_id = "synthetic-" + secrets.token_hex(16)
            observation = BurpObservation(
                capture_id, "RESPONSE", f"127.0.0.1:{proxy.port}", now,
                "synthetic-test", request,
                hashlib.sha256((self.command + request_url).encode() + (body or b"")).hexdigest(),
                response, hashlib.sha256(payload).hexdigest())
            result = proxy.provider.ingest(observation)
            if result.exchange_id is None:
                raise ValueError("Synthetic capture was not stored")
        except (OSError, ValueError):
            self.send_error(502)
            return
        self.send_response(status)
        for key, value in response_headers:
            if key.lower() not in _HOP_HEADERS | {"content-length"}:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)


class SyntheticCaptureProxy:
    """A single Burp-compatible listener; it cannot forward outside the fixture."""

    def __init__(self, fixture_url: str, *, port: int = 0) -> None:
        parsed = urlsplit(fixture_url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
            raise ValueError("Synthetic capture requires a loopback fixture")
        if type(port) is not int or port != 0 and not 1024 <= port <= 65535:
            raise ValueError("Invalid synthetic capture port")
        self.fixture_netloc = parsed.netloc
        self.fixture_port = parsed.port
        self.fixture_url = f"http://{parsed.netloc}"
        self.provider: BurpCaptureProvider | None = None
        self._server = ThreadingHTTPServer(("127.0.0.1", port), _ProxyHandler)
        self._server.synthetic_proxy = self
        self._thread: Thread | None = None

    @property
    def port(self) -> int:
        return self._server.server_port

    def attach(self, package, runtime) -> None:
        self.provider = BurpCaptureProvider(package, runtime.burp, runtime.traffic)

    def __enter__(self) -> SyntheticCaptureProxy:
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


class SyntheticCapturePool:
    """Contiguous, isolated capture listeners for several owned identities."""

    def __init__(self, fixture_url: str, *, count: int) -> None:
        if type(count) is not int or not 1 <= count <= 4:
            raise ValueError("Invalid synthetic listener count")
        for _ in range(64):
            with socket.socket() as candidate:
                candidate.bind(("127.0.0.1", 0))
                first_port = candidate.getsockname()[1]
            if first_port + count > 65535:
                continue
            proxies = []
            try:
                for offset in range(count):
                    proxies.append(SyntheticCaptureProxy(
                        fixture_url, port=first_port + offset))
            except OSError:
                for proxy in proxies:
                    proxy._server.server_close()
                continue
            self.proxies = tuple(proxies)
            break
        else:
            raise OSError("No contiguous loopback capture ports are available")

    @property
    def first_port(self) -> int:
        return self.proxies[0].port

    @property
    def last_port(self) -> int:
        return self.proxies[-1].port

    def attach(self, package, runtime) -> None:
        for proxy in self.proxies:
            proxy.attach(package, runtime)

    def __enter__(self) -> SyntheticCapturePool:
        for proxy in self.proxies:
            proxy.__enter__()
        return self

    def __exit__(self, *_args: object) -> None:
        for proxy in reversed(self.proxies):
            proxy.__exit__(*_args)
