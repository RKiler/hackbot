"""Loopback-only browser targets for Phase 33 DOM and messaging pairs."""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from urllib.parse import parse_qs, urlsplit


_DOM_VULNERABLE = b"""
const iframe = document.getElementById('target');
function render() {
  const input = new URLSearchParams(location.search).get('next');
  if (!input.startsWith('javascript:')) {
    iframe.src = decodeURIComponent(input);
  }
}
render();
"""
_MESSAGE_VULNERABLE = b"""
window.addEventListener('message', event => {
  if (event.data.type !== 'ACTIVATE') return;
  const port = event.ports[0];
  if (!port) return;
  port.onmessage = packet => {
    if (packet.data.method === 'readSynthetic')
      port.postMessage({type:'RESULT',value:'HACKBOT_SYNTHETIC_PRIVATE'});
  };
  event.source.postMessage({type:'READY'}, '*');
});
"""
_MESSAGE_GUARDED = b"""
window.addEventListener('message', event => {
  if (event.origin !== window.location.origin) return;
  if (event.data.type !== 'ACTIVATE') return;
  const port = event.ports[0];
  if (!port) return;
  port.onmessage = packet => {
    if (packet.data.method === 'readSynthetic')
      port.postMessage({type:'RESULT',value:'HACKBOT_SYNTHETIC_PRIVATE'});
  };
  event.source.postMessage({type:'READY'}, event.origin);
});
"""


@dataclass(frozen=True, slots=True)
class BrowserFixtureRequest:
    method: str
    path: str
    status: int


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, family: str, secure: bool, max_requests: int) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.family = family
        self.secure = secure
        self.max_requests = max_requests
        self.requests: list[BrowserFixtureRequest] = []
        self.request_lock = Lock()


class _Handler(BaseHTTPRequestHandler):
    server_version = "BenchmarkBrowserFixture"
    sys_version = ""

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        server = self.server
        assert isinstance(server, _Server)
        parsed = urlsplit(self.path)
        path = parsed.path
        with server.request_lock:
            exhausted = len(server.requests) >= server.max_requests
        if exhausted:
            status, body, content_type = 429, b"request cap", "text/plain"
        elif self.headers.get("Host") != f"127.0.0.1:{server.server_port}":
            status, body, content_type = 421, b"wrong host", "text/plain"
        elif parsed.fragment or (parsed.query and path != "/preview"):
            status, body, content_type = 400, b"invalid query", "text/plain"
        elif path == "/preview" and server.family == "DOM":
            values = parse_qs(parsed.query, keep_blank_values=True)
            if set(values) - {"next"} or len(values.get("next", [])) > 1:
                status, body, content_type = 400, b"invalid query", "text/plain"
            else:
                status, body, content_type = (
                    200,
                    b'<!doctype html><iframe id="target"></iframe><script src="/bundle.js"></script>',
                    "text/html")
        elif path == "/bundle.js" and server.family == "DOM":
            status, body, content_type = (
                200, _DOM_VULNERABLE,
                "application/javascript")
        elif path == "/victim" and server.family == "MESSAGE":
            status, body, content_type = (
                200, b'<!doctype html><script src="/bundle.js"></script>',
                "text/html")
        elif path == "/bundle.js" and server.family == "MESSAGE":
            status, body, content_type = (
                200, _MESSAGE_GUARDED if server.secure else _MESSAGE_VULNERABLE,
                "application/javascript")
        else:
            status, body, content_type = 404, b"not found", "text/plain"
        with server.request_lock:
            server.requests.append(BrowserFixtureRequest("GET", path, status))
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if server.family == "DOM" and server.secure and path == "/preview":
            self.send_header("Content-Security-Policy", "script-src 'self'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self) -> None:
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True


class BenchmarkBrowserFixture:
    """One immutable synthetic browser target with a strict loopback boundary."""

    def __init__(self, *, family: str, secure: bool, max_requests: int = 96) -> None:
        if (family not in {"DOM", "MESSAGE"} or type(secure) is not bool or
                type(max_requests) is not int or not 1 <= max_requests <= 160):
            raise ValueError("Invalid browser benchmark fixture settings")
        self._server = _Server(family, secure, max_requests)
        self._thread: Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    @property
    def requests(self) -> tuple[BrowserFixtureRequest, ...]:
        with self._server.request_lock:
            return tuple(self._server.requests)

    def __enter__(self) -> BenchmarkBrowserFixture:
        if self._thread is not None:
            raise RuntimeError("Browser fixture already started")
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
