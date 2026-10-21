"""Loopback-only origin guard between Chromium and a capture proxy."""

from __future__ import annotations

import select
import socket
from socketserver import BaseRequestHandler, ThreadingTCPServer
from threading import BoundedSemaphore, Lock, Thread
from urllib.parse import urlsplit

from .target_scope import ProgramScope, ScopeResult


class BrowserProxyGuardError(ValueError):
    """A browser transport cannot be safely constrained."""


class _GuardServer(ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, scope: ProgramScope, upstream_port: int) -> None:
        self.scope = scope
        self.upstream_port = upstream_port
        self.closing = False
        self._lock = Lock()
        self._capacity = BoundedSemaphore(24)
        self._sockets: set[socket.socket] = set()
        self.allowed = 0
        self.denied = 0
        super().__init__(("127.0.0.1", 0), _GuardHandler)

    def verify_request(self, request: socket.socket, client_address: tuple[str, int]) -> bool:
        admitted = self._capacity.acquire(blocking=False)
        if not admitted:
            self.count(False)
        return admitted

    def process_request_thread(self, request: socket.socket,
                               client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._capacity.release()

    def track(self, connection: socket.socket) -> None:
        with self._lock:
            self._sockets.add(connection)

    def untrack(self, connection: socket.socket) -> None:
        with self._lock:
            self._sockets.discard(connection)

    def count(self, permitted: bool) -> None:
        with self._lock:
            if permitted:
                self.allowed += 1
            else:
                self.denied += 1

    def close_connections(self) -> None:
        with self._lock:
            self.closing = True
            sockets = tuple(self._sockets)
        for connection in sockets:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()


class _GuardHandler(BaseRequestHandler):
    server: _GuardServer

    @staticmethod
    def _authority(value: str, scheme: str, *, require_port: bool = False) -> tuple[str, int] | None:
        if not value or any(char in value for char in " /\\@?#\t\r\n"):
            return None
        try:
            parsed = urlsplit(f"{scheme}://{value}/")
            if (parsed.hostname is None or parsed.username is not None or parsed.password is not None
                    or parsed.netloc.endswith(":") or require_port and parsed.port is None):
                return None
            return parsed.hostname.lower(), parsed.port or (443 if scheme == "https" else 80)
        except ValueError:
            return None

    def _allowed(self, header: bytes) -> bool:
        try:
            lines = header.decode("iso-8859-1").split("\r\n")
            method, target, version = lines[0].split(" ")
            if not version.startswith("HTTP/1."):
                return False
            host_headers = [line[5:].strip() for line in lines[1:]
                            if line.lower().startswith("host:")]
            if len(host_headers) != 1:
                return False
            if method == "CONNECT":
                authority = self._authority(target, "https", require_port=True)
                if authority is None or self._authority(host_headers[0], "https") != authority:
                    return False
                host, port = authority
                url = f"https://{host}:{port}/"
            else:
                parsed = urlsplit(target)
                if (parsed.scheme != "http" or parsed.hostname is None or parsed.port is None
                        and parsed.netloc.endswith(":") or parsed.username is not None
                        or parsed.password is not None):
                    return False
                port = parsed.port or 80
                if self._authority(host_headers[0], "http") != (parsed.hostname.lower(), port):
                    return False
                url = target
            return self.server.scope.evaluate_url(url).result is ScopeResult.IN_SCOPE
        except (UnicodeError, ValueError):
            return False

    def handle(self) -> None:
        client = self.request
        self.server.track(client)
        upstream = None
        try:
            client.settimeout(8)
            header = bytearray()
            while b"\r\n\r\n" not in header and len(header) <= 16384:
                part = client.recv(4096)
                if not part:
                    return
                header.extend(part)
            boundary = header.find(b"\r\n\r\n")
            if boundary < 0 or boundary > 16384 or not self._allowed(header[:boundary]):
                self.server.count(False)
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            if self.server.closing:
                return
            upstream = socket.create_connection(("127.0.0.1", self.server.upstream_port), timeout=3)
            self.server.track(upstream)
            self.server.count(True)
            upstream.sendall(header)
            client.settimeout(15)
            upstream.settimeout(15)
            while not self.server.closing:
                readable, _, _ = select.select((client, upstream), (), (), 0.5)
                for source in readable:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    (upstream if source is client else client).sendall(chunk)
        except (OSError, ValueError):
            return
        finally:
            if upstream is not None:
                self.server.untrack(upstream)
                upstream.close()
            self.server.untrack(client)


class BrowserProxyGuard:
    """Only explicitly in-scope origins can reach the session's Burp listener.

    HTTPS path rules cannot be checked before CONNECT; reject such packages
    instead of silently treating an authorized host as an authorized path.
    """

    def __init__(self, scope: ProgramScope, upstream_url: str) -> None:
        if not isinstance(scope, ProgramScope) or scope.include_paths or scope.exclude_paths:
            raise BrowserProxyGuardError("Browser capture cannot enforce path-restricted scope")
        try:
            parsed = urlsplit(upstream_url)
            if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                    or parsed.port is None or parsed.username or parsed.password
                    or parsed.path or parsed.query or parsed.fragment):
                raise ValueError
        except ValueError:
            raise BrowserProxyGuardError("Browser capture requires a loopback HTTP proxy") from None
        self._server = _GuardServer(scope, parsed.port)
        self._thread = Thread(target=self._server.serve_forever, name="hackbot-proxy-guard", daemon=True)
        self._thread.start()

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    @property
    def counts(self) -> tuple[int, int]:
        return self._server.allowed, self._server.denied

    def close(self) -> None:
        self._server.close_connections()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)
