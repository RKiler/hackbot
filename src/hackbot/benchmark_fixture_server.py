"""Bounded loopback-only HTTP target for synthetic Phase 33 download cases."""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Lock, Thread
from urllib.parse import urlsplit


_FILE = (b'{"id":"owned-file","owner":"owner","visibility":"private",'
         b'"content":"owned-file-canary"}')
_INDEX = (b'<!doctype html><title>Fixture Files</title>'
          b'<a href="/api/files/owned-file/download">Download file</a>'
          b'<script src="/assets/app.js"></script>')
_JS = (b'const downloadPath="/api/files/owned-file/download";'
       b'fetch(downloadPath,{credentials:"include"});')
_GRAPHQL_QUERY = "query GetDocument($id:ID!){node(id:$id){id name owner tenant}}"
_GRAPHQL_FIELD_QUERY = (
    "query GetDocument($id:ID!){node(id:$id){id name owner tenant email}}")
_NOISY_ROUTES: dict[str, tuple[bytes, str]] = {
    "/admin/": (b'<!doctype html><title>Fixture Admin Sign In</title>'
                 b'<form><input name="username"></form>', "text/html"),
    "/graphql": (b'{"data":null,"errors":[{"message":"Query document required"}]}',
                 "application/json"),
    "/api/internal/config": (
        b'{"public":true,"apiKey":"pk_test_public_example","region":"test"}',
        "application/json"),
    "/api/files/public-sample/download": (
        b'{"id":"public-sample","visibility":"public","content":"fictional demo data"}',
        "application/json"),
    "/assets/noise.js": (
        b'window.addEventListener("message",event=>{'
        b'if(event.data?.type==="ping")event.source?.postMessage({type:"pong"},event.origin)'
        b'});document.querySelector("#status")?.insertAdjacentHTML("beforeend",'
        b'"<span>Ready</span>");const internalHost="internal.example.test";'
        b'const apiKey="pk_test_public_example";', "application/javascript"),
    "/assets/noise.js.map": (
        b'{"version":3,"file":"noise.js","sources":["noise.js"],'
        b'"names":[],"mappings":"","sourcesContent":['
        b'"const apiKey=\\"pk_test_public_example\\";"]}', "application/json"),
}


@dataclass(frozen=True, slots=True)
class FixtureRequest:
    method: str
    path: str
    actor: str
    status: int


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *, secure: bool, max_requests: int, noisy: bool,
                 access_mode: str) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.secure = secure
        self.noisy = noisy
        self.access_mode = access_mode
        self.max_requests = max_requests
        self.requests: list[FixtureRequest] = []
        self.request_lock = Lock()
        self.documents: dict[str, dict[str, str]] = {}
        self.next_document = 1


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "BenchmarkFixture"
    sys_version = ""

    def log_message(self, *args: object) -> None:
        pass

    def _respond(self, status: int, body: bytes, content_type: str,
                 *, include_body: bool = True) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        if include_body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _handle(self, *, head: bool = False) -> None:
        server = self.server
        assert isinstance(server, _Server)
        parsed = urlsplit(self.path)
        path = parsed.path
        actor = {"fixture_actor=owner": "OWNER",
                 "fixture_actor=foreign": "FOREIGN"}.get(
                     self.headers.get("Cookie"), "ANONYMOUS")
        tenant = (path.split("/", 4)[2] if path.startswith("/fixture/") and
                  len(path.split("/", 4)) >= 4 else None)
        valid_tenant = tenant == "tenant-a" or (
            tenant == "tenant-b" and server.access_mode in {
                "TENANT", "TENANT_MUTATION", "MIXED", "GRAPHQL", "GRAPHQL_FIELD"})
        with server.request_lock:
            too_many = len(server.requests) >= server.max_requests
        if too_many:
            status, body, content_type = 429, b"rate limited", "text/plain"
        elif self.headers.get("Host") != f"127.0.0.1:{server.server_port}":
            status, body, content_type = 421, b"wrong host", "text/plain"
        elif parsed.query or parsed.fragment:
            status, body, content_type = 400, b"invalid request", "text/plain"
        elif valid_tenant and path == f"/fixture/{tenant}/documents" and self.command == "POST":
            status, body, content_type = self._create_document(server, actor, tenant)
        elif valid_tenant and path.startswith(f"/fixture/{tenant}/documents/"):
            status, body, content_type = self._document(server, actor, path, tenant)
        elif (path == "/fixture/graphql" and
              server.access_mode in {"GRAPHQL", "GRAPHQL_FIELD"} and
              self.command == "POST"):
            status, body, content_type = self._graphql(server, actor)
        elif self.command not in {"GET", "HEAD"}:
            status, body, content_type = 405, b"method not allowed", "text/plain"
        elif path == "/":
            status, body, content_type = 200, _INDEX, "text/html"
        elif path == "/assets/app.js":
            status, body, content_type = 200, _JS, "application/javascript"
        elif server.noisy and path in _NOISY_ROUTES:
            body, content_type = _NOISY_ROUTES[path]
            status = 200
        elif path == "/api/files/owned-file/download" and server.access_mode == "EXPOSURE":
            if server.secure and actor != "OWNER":
                status, body, content_type = 403, b'{"error":"forbidden"}', "application/json"
            else:
                status, body, content_type = 200, _FILE, "application/json"
        else:
            status, body, content_type = 404, b'{"error":"not_found"}', "application/json"
        with server.request_lock:
            if len(server.requests) < server.max_requests + 1:
                server.requests.append(FixtureRequest(self.command, path, actor, status))
        self._respond(status, body, content_type, include_body=not head)

    def _read_json(self) -> dict[str, object] | None:
        try:
            size = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= size <= 1024:
                return None
            value = json.loads(self.rfile.read(size))
            return value if isinstance(value, dict) else None
        except (ValueError, UnicodeError):
            return None

    def _create_document(self, server: _Server, actor: str,
                         tenant: str) -> tuple[int, bytes, str]:
        content_type = "application/json"
        expected_actor = (actor if server.access_mode == "HORIZONTAL" and
                          tenant == "tenant-a" and actor in {"OWNER", "FOREIGN"}
                          else "OWNER" if tenant == "tenant-a" else "FOREIGN")
        if actor != expected_actor:
            return 403, b'{"error":"forbidden"}', content_type
        value = self._read_json()
        name = value.get("name") if value is not None else None
        if not isinstance(name, str) or not 4 <= len(name) <= 80 or any(
                char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in name):
            return 400, b'{"error":"invalid_name"}', content_type
        with server.request_lock:
            if len(server.documents) >= 8:
                return 429, b'{"error":"object_limit"}', content_type
            document_id = f"doc-{server.next_document}"
            server.next_document += 1
            document = {"id": document_id, "name": name,
                        "owner": expected_actor.lower() if expected_actor == "FOREIGN" else "owner",
                        "tenant": tenant, "type": "document",
                        "content": "owned-file-canary"}
            if server.access_mode == "GRAPHQL_FIELD":
                document["email"] = "synthetic-private@example.test"
            server.documents[document_id] = document
        return 201, json.dumps(document, sort_keys=True).encode(), content_type

    def _graphql(self, server: _Server, actor: str) -> tuple[int, bytes, str]:
        content_type = "application/json"
        value = self._read_json()
        variables = value.get("variables") if value is not None else None
        field_mode = server.access_mode == "GRAPHQL_FIELD"
        expected_query = _GRAPHQL_FIELD_QUERY if field_mode else _GRAPHQL_QUERY
        if (value is None or value.get("query") != expected_query or
                value.get("operationName") != "GetDocument" or
                not isinstance(variables, dict) or
                set(variables) != {"id"} or
                not isinstance(variables["id"], str)):
            return 400, b'{"errors":[{"message":"invalid_query"}]}', content_type
        with server.request_lock:
            document = server.documents.get(variables["id"])
        if document is None:
            result = {"data": {"node": None}}
        elif field_mode and actor != "ANONYMOUS":
            node = {key: document[key] for key in ("id", "name", "owner", "tenant")}
            if actor == document["owner"].upper() or not server.secure:
                node["email"] = document["email"]
                result = {"data": {"node": node}}
            else:
                node["email"] = None
                result = {"data": {"node": node}, "errors": [{
                    "message": "forbidden", "path": ["node", "email"],
                    "extensions": {"code": "FORBIDDEN"}}]}
        elif actor == document["owner"].upper() or (
                not server.secure and actor in {"OWNER", "FOREIGN"}):
            result = {"data": {"node": document}}
        else:
            result = {"data": {"node": None}, "errors": [{
                "message": "forbidden", "path": ["node"],
                "extensions": {"code": "FORBIDDEN"}}]}
        return 200, json.dumps(result, sort_keys=True).encode(), content_type

    def _document(self, server: _Server, actor: str,
                  path: str, tenant: str) -> tuple[int, bytes, str]:
        content_type = "application/json"
        document_id = path.removeprefix(f"/fixture/{tenant}/documents/")
        if not document_id or "/" in document_id:
            return 404, b'{"error":"not_found"}', content_type
        with server.request_lock:
            document = server.documents.get(document_id)
        if document is None or document["tenant"] != tenant:
            return 404, b'{"error":"not_found"}', content_type
        owner_actor = "OWNER" if document["owner"] == "owner" else "FOREIGN"
        if server.access_mode in {"TENANT", "HORIZONTAL"}:
            allowed = (actor == owner_actor or
                       (not server.secure and actor != "ANONYMOUS" and
                        self.command in {"GET", "HEAD"}))
        elif server.access_mode == "TENANT_MUTATION":
            allowed = (actor == owner_actor or
                       (not server.secure and actor != "ANONYMOUS" and
                        self.command == "PATCH"))
        elif server.access_mode == "MIXED":
            allowed = actor == owner_actor or (
                not server.secure and self.command in {"GET", "HEAD"} and
                ((tenant == "tenant-a" and actor == "ANONYMOUS") or
                 (tenant == "tenant-b" and actor == "OWNER")))
        elif server.access_mode in {"GRAPHQL", "GRAPHQL_FIELD"}:
            allowed = actor == owner_actor
        else:
            allowed = actor == "OWNER" or (
                not server.secure and self.command in {"GET", "HEAD"})
        if not allowed:
            return 403, b'{"error":"forbidden"}', content_type
        if self.command in {"GET", "HEAD"}:
            return 200, json.dumps(document, sort_keys=True).encode(), content_type
        if self.command == "PATCH":
            value = self._read_json()
            name = value.get("name") if value is not None else None
            if not isinstance(name, str) or not 4 <= len(name) <= 80 or any(
                    char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in name):
                return 400, b'{"error":"invalid_name"}', content_type
            with server.request_lock:
                document["name"] = name
            return 200, json.dumps(document, sort_keys=True).encode(), content_type
        if self.command == "DELETE":
            with server.request_lock:
                del server.documents[document_id]
            return 204, b"", content_type
        return 405, b'{"error":"method_not_allowed"}', content_type

    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle(head=True)

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()


class BenchmarkHTTPFixture:
    """Start exactly one immutable synthetic target; no real host is accepted."""

    def __init__(self, *, secure: bool, max_requests: int = 100,
                 noisy: bool = False, access_mode: str = "EXPOSURE") -> None:
        if (type(secure) is not bool or type(noisy) is not bool or
                type(max_requests) is not int or
                not 1 <= max_requests <= 400 or
                access_mode not in {"EXPOSURE", "TENANT", "TENANT_MUTATION",
                                    "HORIZONTAL", "MIXED", "GRAPHQL",
                                    "GRAPHQL_FIELD"}):
            raise ValueError("Invalid benchmark fixture settings")
        self._server = _Server(secure=secure, max_requests=max_requests, noisy=noisy,
                               access_mode=access_mode)
        self._thread: Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    @property
    def requests(self) -> tuple[FixtureRequest, ...]:
        with self._server.request_lock:
            return tuple(self._server.requests)

    @property
    def document_count(self) -> int:
        with self._server.request_lock:
            return len(self._server.documents)

    def __enter__(self) -> BenchmarkHTTPFixture:
        if self._thread is not None:
            raise RuntimeError("Benchmark fixture already started")
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
