"""Loopback-only two-tenant SaaS for the Hunt operator acceptance journey."""

from __future__ import annotations

from dataclasses import dataclass
import html
import re
import secrets
from threading import Lock, Thread

from flask import Flask, jsonify, make_response, request
from werkzeug.serving import make_server


ACCOUNTS = {
    "org1_admin": ("org1", "admin"),
    "org1_member": ("org1", "member"),
    "org2_admin": ("org2", "admin"),
}
LOGIN_PASSWORD = "local-synthetic-fixture-only"
GET_DOCUMENT = "query GetDocument($id: ID!) { document(id: $id) { id name tenant owner content } }"
RENAME_DOCUMENT = (
    "mutation RenameDocument($id: ID!, $name: String!) { "
    "renameDocument(id: $id, name: $name) { id name tenant owner } }"
)
APP_JS = (
    "const getDocument = " + repr(GET_DOCUMENT) + ";\n"
    "const renameDocument = " + repr(RENAME_DOCUMENT) + ";\n"
    "const apiRoutes = ['/api/me', '/api/documents', '/api/documents/{id}', "
    "'/api/documents/{id}/preview', '/graphql'];\n"
    "function currentUser() { return fetch('/api/me'); }\n"
    "function listDocuments() { return fetch('/api/documents'); }\n"
    "function readDocument(id) { return fetch('/api/documents/' + encodeURIComponent(id)); }\n"
    "function previewDocument(id) { return fetch('/api/documents/' + encodeURIComponent(id) + '/preview'); }\n"
    "function deleteDocument(id) { return fetch('/api/documents/' + encodeURIComponent(id), {method: 'DELETE'}); }\n"
    "function documentQuery(id) { return fetch('/graphql', {method: 'POST', "
    "headers: {'Content-Type': 'application/json'}, "
    "body: JSON.stringify({operationName: 'GetDocument', query: getDocument, "
    "variables: {id}})}); }\n"
    "window.syntheticSaas = {getDocument, renameDocument, apiRoutes};\n"
)


@dataclass(frozen=True, slots=True)
class FixtureRequest:
    method: str
    path: str
    actor: str | None
    status: int


class SyntheticSaaS:
    """No external dependencies or callbacks; all state is disposable in memory."""

    def __init__(self, *, vulnerable: bool = True, max_requests: int = 300) -> None:
        if type(vulnerable) is not bool or type(max_requests) is not int or not 1 <= max_requests <= 1000:
            raise ValueError("Invalid synthetic SaaS configuration")
        self.vulnerable = vulnerable
        self.max_requests = max_requests
        self._lock = Lock()
        self._requests: list[FixtureRequest] = []
        self._sessions: dict[str, str] = {}
        self._documents: dict[str, dict[str, object]] = {
            "doc-org1-seed": {"id": "doc-org1-seed", "name": "org1-seed",
                              "tenant": "org1", "owner": "org1_admin",
                              "content": "org1-private-marker", "disposable": False},
            "doc-org2-seed": {"id": "doc-org2-seed", "name": "org2-seed",
                              "tenant": "org2", "owner": "org2_admin",
                              "content": "org2-private-marker", "disposable": False},
        }
        self._next_document = 1
        app = Flask(__name__)
        self._register_routes(app)
        self._server = make_server("127.0.0.1", 0, app, threaded=True)
        self._thread: Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    @property
    def requests(self) -> tuple[FixtureRequest, ...]:
        with self._lock:
            return tuple(self._requests)

    @property
    def disposable_count(self) -> int:
        with self._lock:
            return sum(bool(item["disposable"]) for item in self._documents.values())

    def __enter__(self) -> SyntheticSaaS:
        if self._thread is not None:
            raise RuntimeError("Synthetic SaaS already started")
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _actor(self) -> str | None:
        token = request.cookies.get("synthetic_session")
        with self._lock:
            return self._sessions.get(token) if token else None

    @staticmethod
    def _public_document(document: dict[str, object]) -> dict[str, object]:
        return {key: document[key] for key in ("id", "name", "tenant", "owner", "content")}

    @staticmethod
    def _page(title: str, body: str) -> str:
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f"<title>{html.escape(title)}</title></head><body>"
            '<nav><a href="/app">Home</a> <a href="/projects">Projects</a> '
            '<a href="/documents">Documents</a> <a href="/settings">Settings</a></nav>'
            f"<main><h1>{html.escape(title)}</h1>{body}</main>"
            '<script src="/assets/app.js"></script></body></html>'
        )

    def _register_routes(self, app: Flask) -> None:
        @app.before_request
        def bound_request():
            if request.host != f"127.0.0.1:{self._server.server_port}":
                return jsonify(error="wrong_host"), 421
            with self._lock:
                if len(self._requests) >= self.max_requests:
                    return jsonify(error="fixture_budget_exhausted"), 429
            return None

        @app.after_request
        def record(response):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            with self._lock:
                if len(self._requests) <= self.max_requests:
                    self._requests.append(FixtureRequest(request.method, request.path,
                                                         self._actor_unlocked(request),
                                                         response.status_code))
            return response

        @app.get("/")
        def home():
            return self._page("Synthetic SaaS", '<a href="/login">Sign in</a>')

        @app.get("/login")
        def login_page():
            options = "".join(f'<option value="{alias}">{alias}</option>' for alias in ACCOUNTS)
            return self._page("Sign in", '<form action="/session/login" method="post">'
                              f'<label>Account<select name="alias">{options}</select></label>'
                              '<label>Password<input name="password" type="password"></label>'
                              '<button type="submit">Sign in</button></form>')

        @app.post("/session/login")
        def login():
            alias = request.form.get("alias")
            if alias not in ACCOUNTS or request.form.get("password") != LOGIN_PASSWORD:
                return jsonify(error="invalid_login"), 401
            token = secrets.token_urlsafe(32)
            with self._lock:
                self._sessions[token] = alias
            response = make_response("", 303)
            response.headers["Location"] = "/app"
            response.set_cookie("synthetic_session", token, httponly=True,
                                samesite="Strict", path="/")
            return response

        @app.post("/session/logout")
        def logout():
            token = request.cookies.get("synthetic_session")
            with self._lock:
                if token:
                    self._sessions.pop(token, None)
            response = make_response("", 303)
            response.headers["Location"] = "/login"
            response.delete_cookie("synthetic_session", path="/")
            return response

        @app.get("/assets/app.js")
        def js_asset():
            response = make_response(APP_JS)
            response.mimetype = "application/javascript"
            return response

        @app.get("/favicon.ico")
        def favicon():
            return "", 204

        @app.get("/app")
        def app_home():
            actor = self._actor()
            if actor is None:
                return jsonify(error="login_required"), 401
            tenant, role = ACCOUNTS[actor]
            return self._page("Workspace", f'<div data-role="{role}">'
                              f'<span data-user>{actor}</span> '
                              f'<span data-tenant>{tenant}</span></div>'
                              '<p>Workspace overview</p>')

        @app.get("/projects")
        def projects():
            actor = self._actor()
            if actor is None:
                return jsonify(error="login_required"), 401
            tenant = ACCOUNTS[actor][0]
            return self._page("Projects", f'<a href="/projects/{tenant}-primary">'
                              f'{tenant} primary project</a>')

        @app.get("/projects/<project_id>")
        def project(project_id: str):
            actor = self._actor()
            if actor is None:
                return jsonify(error="login_required"), 401
            tenant = ACCOUNTS[actor][0]
            if project_id != f"{tenant}-primary":
                return jsonify(error="not_found"), 404
            return self._page("Project", '<a href="/documents">Documents</a>')

        @app.get("/documents")
        def documents_page():
            actor = self._actor()
            if actor is None:
                return jsonify(error="login_required"), 401
            tenant = ACCOUNTS[actor][0]
            with self._lock:
                documents = [dict(item) for item in self._documents.values()
                             if item["tenant"] == tenant]
            links = "".join(f'<li><a href="/documents/{item["id"]}">'
                            f'{html.escape(str(item["name"]))}</a></li>' for item in documents)
            return self._page("Documents", f"<ul>{links}</ul>"
                              '<form action="/api/documents" method="post">'
                              '<label>Name<input name="name"></label>'
                              '<button type="submit">Create</button></form>')

        @app.get("/documents/<document_id>")
        def document_page(document_id: str):
            actor = self._actor()
            if actor is None:
                return jsonify(error="login_required"), 401
            with self._lock:
                document = self._documents.get(document_id)
                if document is None or document["tenant"] != ACCOUNTS[actor][0]:
                    return jsonify(error="not_found"), 404
                name = str(document["name"])
            return self._page("Document", f"<p>{html.escape(name)}</p>"
                              f'<a href="/api/documents/{document_id}">API detail</a> '
                              f'<a href="/api/documents/{document_id}/preview">Preview</a>')

        @app.get("/settings")
        def settings():
            actor = self._actor()
            if actor is None:
                return jsonify(error="login_required"), 401
            if ACCOUNTS[actor][1] != "admin":
                return jsonify(error="forbidden"), 403
            return self._page("Settings", '<button type="button">Workspace settings</button>')

        @app.get("/api/me")
        def me():
            actor = self._actor()
            if actor is None:
                return jsonify(error="login_required"), 401
            tenant, role = ACCOUNTS[actor]
            return jsonify(id=actor, tenant=tenant, role=role)

        @app.get("/api/documents")
        def list_documents():
            actor = self._actor()
            if actor is None:
                return jsonify(error="login_required"), 401
            with self._lock:
                items = [self._public_document(item) for item in self._documents.values()
                         if item["tenant"] == ACCOUNTS[actor][0]]
            return jsonify(items=items)

        @app.post("/api/documents")
        def create_document():
            actor = self._actor()
            if actor is None:
                return jsonify(error="login_required"), 401
            value = request.get_json(silent=True) if request.is_json else request.form
            name = value.get("name") if value is not None else None
            if not self._valid_name(name):
                return jsonify(error="invalid_name"), 400
            with self._lock:
                if self.disposable_count_unlocked() >= 12:
                    return jsonify(error="fixture_object_limit"), 429
                document_id = f"doc-test-{self._next_document}"
                self._next_document += 1
                document = {"id": document_id, "name": name,
                            "tenant": ACCOUNTS[actor][0], "owner": actor,
                            "content": "disposable-test-marker", "disposable": True}
                self._documents[document_id] = document
            return jsonify(self._public_document(document)), 201

        @app.route("/api/documents/<document_id>", methods=["GET", "PATCH", "DELETE"])
        def document_api(document_id: str):
            actor = self._actor()
            if actor is None:
                return jsonify(error="login_required"), 401
            with self._lock:
                document = self._documents.get(document_id)
                if document is None or document["tenant"] != ACCOUNTS[actor][0]:
                    return jsonify(error="not_found"), 404
                if request.method == "GET":
                    return jsonify(self._public_document(document))
                if document["owner"] != actor or not document["disposable"]:
                    return jsonify(error="forbidden"), 403
                if request.method == "DELETE":
                    del self._documents[document_id]
                    return "", 204
                value = request.get_json(silent=True)
                name = value.get("name") if isinstance(value, dict) else None
                if not self._valid_name(name):
                    return jsonify(error="invalid_name"), 400
                document["name"] = name
                return jsonify(self._public_document(document))

        @app.get("/api/documents/<document_id>/preview")
        def preview(document_id: str):
            actor = self._actor()
            if actor is None:
                return jsonify(error="login_required"), 401
            with self._lock:
                document = self._documents.get(document_id)
                if document is None:
                    return jsonify(error="not_found"), 404
                if not self.vulnerable and document["tenant"] != ACCOUNTS[actor][0]:
                    return jsonify(error="not_found"), 404
                return jsonify(self._public_document(document))

        @app.post("/graphql")
        def graphql():
            actor = self._actor()
            if actor is None:
                return jsonify(errors=[{"message": "login_required"}]), 401
            value = request.get_json(silent=True)
            if not isinstance(value, dict) or not isinstance(value.get("variables"), dict):
                return jsonify(errors=[{"message": "invalid_query"}]), 400
            variables = value["variables"]
            if value.get("operationName") == "GetDocument" and value.get("query") == GET_DOCUMENT:
                document_id = variables.get("id")
                if not isinstance(document_id, str):
                    return jsonify(errors=[{"message": "invalid_id"}]), 400
                with self._lock:
                    document = self._documents.get(document_id)
                    if document is None or document["tenant"] != ACCOUNTS[actor][0]:
                        return jsonify(data={"document": None}, errors=[{
                            "message": "forbidden", "path": ["document"]}])
                    return jsonify(data={"document": self._public_document(document)})
            if value.get("operationName") == "RenameDocument" and value.get("query") == RENAME_DOCUMENT:
                document_id, name = variables.get("id"), variables.get("name")
                if not isinstance(document_id, str) or not self._valid_name(name):
                    return jsonify(errors=[{"message": "invalid_variables"}]), 400
                with self._lock:
                    document = self._documents.get(document_id)
                    if (document is None or document["tenant"] != ACCOUNTS[actor][0]
                            or document["owner"] != actor or not document["disposable"]):
                        return jsonify(data={"renameDocument": None}, errors=[{
                            "message": "forbidden", "path": ["renameDocument"]}])
                    document["name"] = name
                    return jsonify(data={"renameDocument": self._public_document(document)})
            return jsonify(errors=[{"message": "unsupported_operation"}]), 400

    def _actor_unlocked(self, incoming_request) -> str | None:
        token = incoming_request.cookies.get("synthetic_session")
        return self._sessions.get(token) if token else None

    def disposable_count_unlocked(self) -> int:
        return sum(bool(item["disposable"]) for item in self._documents.values())

    @staticmethod
    def _valid_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"[a-z0-9-]{4,80}", name) is not None
