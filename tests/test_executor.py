from __future__ import annotations

from dataclasses import replace
from datetime import timedelta, datetime, timezone
import base64
import binascii
from functools import cache
import gzip
import hashlib
import http.client
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import select
import shutil
import socket
import ssl
import subprocess
from tempfile import TemporaryDirectory
import threading
import time
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.auth import AuthContextManager, AuthMechanism, AuthStatus
from hackbot.browser import (BrowserProxyConfig, BrowserSessionManager,
                            IdentityObservation, IdentityVerificationRule)
from hackbot.config import (BrowserSettings, ExecutorSettings, RetentionSettings,
                            SecretBindingConfig, SecretSettings, StoreSettings)
from hackbot.domxss import DOMAcquisitionStatus, DOMXSSSpecialist
from hackbot.domxss_store import DOMXSSStore
from hackbot.executor import (ExecutionError, ProxyRoute, RequestTemplate, TrafficExecutor)
from hackbot.identity import IdentityStatus
from hackbot.identity_registry import IdentityRegistry
from hackbot.permit_store import PermitError, PolicyPermitStore
from hackbot.policy import PolicyEngine
from hackbot.policy_models import ActionCategory, ActorMode, ProposedAction
from hackbot.policy_store import PolicyStore
from hackbot.rate_limit import ExperimentBudget, RateLimiter
from hackbot.recon import Page, Provenance, ReconJsAsset, ReconTarget
from hackbot.secrets import RoutedSecretProvider, SecretValue
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package
from hackbot.target_policy import RatePolicy
from hackbot.target_policy import PolicyDecision
from hackbot.target_scope import HostRule
from hackbot.traffic import AuthState, ExchangeState, TrafficStore


EXAMPLE = Path(__file__).parent / "examples/targets/example"
SECRET = "fixture-cookie=very-private-test-value"


@cache
def _empty_executor_schema() -> TemporaryDirectory:
    directory = TemporaryDirectory()
    root = Path(directory.name)
    blobs = root / "blobs"
    EvidenceFactStore(root / "state/bughunter.sqlite3", ArtifactStore(blobs),
                      StoreSettings(blobs)).initialize()
    return directory


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _answer(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def do_GET(self):
        self.server.received.append(("GET", self.path, self.headers.get("Cookie")))
        if self.path.startswith("/api/admin/projects/") and self.path.count("/") == 4:
            item = self.server.fixture_objects.get(self.path.rsplit("/", 1)[-1])
            if item is None or item["type"] != "project":
                return self._answer(404, b"{}", (("Content-Type", "application/json"),))
            if (getattr(self.server, "fixture_secure", False) and
                    self.headers.get("Cookie") != "fixture_actor=" + item["owner"]):
                return self._answer(403, b'{"error":"forbidden"}',
                                    (("Content-Type", "application/json"),))
            return self._answer(200, json.dumps(item).encode(),
                                (("Content-Type", "application/json"),))
        if self.path.startswith("/api/projects/") and self.path.count("/") == 3:
            item = self.server.fixture_objects.get(self.path.rsplit("/", 1)[-1])
            if item is None or item["type"] != "project":
                return self._answer(404, b"{}", (("Content-Type", "application/json"),))
            if (getattr(self.server, "fixture_secure", False) and
                    self.headers.get("Cookie") != "fixture_actor=" + item["owner"]):
                return self._answer(403, b'{"error":"forbidden"}',
                                    (("Content-Type", "application/json"),))
            return self._answer(200, json.dumps(item).encode(),
                                (("Content-Type", "application/json"),))
        if self.path == "/assets/app-vhost.js":
            normal = (b'const virtualHost = "http://admin.svc.internal"; '
                      b'const route = "/assets/app-vhost.js";')
            if self.headers.get("Host") == "admin.svc.internal":
                mode = getattr(self.server, "fixture_vhost_mode", "vulnerable")
                if mode == "secure":
                    return self._answer(403, b"denied", (("Content-Type", "text/plain"),))
                if mode == "title_only":
                    return self._answer(200, b'{"title":"Internal Admin"}',
                                        (("Content-Type", "application/json"),))
                return self._answer(200, b'{"client_secret":"FixtureOnlyInternal-z8Qp4Rm7Tn2Yv6Wk"}',
                                    (("Content-Type", "application/json"),))
            return self._answer(200, normal, (("Content-Type", "application/javascript"),))
        if self.path in {"/fixture/config.json", "/fixture/debug.txt",
                         "/fixture/backup.json", "/fixture/dummy.json"}:
            if getattr(self.server, "fixture_exposure_mode", "normal") == "deny":
                return self._answer(403, b"denied", (("Content-Type", "text/plain"),))
            if self.path == "/fixture/dummy.json":
                body = b'{"password":"changeme"}'
            elif self.path == "/fixture/debug.txt":
                body = (b'Traceback: fixture application.py line 7\n'
                        b'client_secret="FixtureOnlyDebug-z8Qp4Rm7Tn2Yv6Wk"')
            elif self.path == "/fixture/backup.json":
                body = b'{"client_secret":"FixtureOnlyBackup-z8Qp4Rm7Tn2Yv6Wk"}'
            else:
                body = b'{"client_secret":"FixtureOnlyConfig-z8Qp4Rm7Tn2Yv6Wk"}'
            if getattr(self.server, "fixture_exposure_mode", "normal") == "changed":
                body = b'{"status":"public"}'
            content_type = "text/plain" if self.path.endswith(".txt") else "application/json"
            return self._answer(200, body, (("Content-Type", content_type),))
        if self.path == "/assets/app.js":
            return self._answer(200, b'const api_key="fixture-secret";location.search;iframe.src;\n'
                                b'//# sourceMappingURL=app.js.map',
                                (("Content-Type", "application/javascript"),))
        if self.path == "/assets/app.js.map":
            return self._answer(200, b'{"version":3,"sources":["app.js"],"mappings":"AAAA"}',
                                (("Content-Type", "application/json"),))
        if self.path == "/assets/fallback.js":
            return self._answer(200, b"<html>fallback</html>", (("Content-Type", "text/html"),))
        if self.path.startswith("/fixture/"):
            parts = self.path.split("/")
            if (len(parts) == 6 and parts[3] == "projects" and parts[4] == "batch"):
                identifiers = parts[5].split(",")
                if len(identifiers) != 2 or identifiers[0] == identifiers[1]:
                    return self._answer(400, b"{}", (("Content-Type", "application/json"),))
                items = []
                for identifier in identifiers:
                    item = self.server.fixture_objects.get(identifier)
                    if item is None or item["type"] != "project":
                        continue
                    if (getattr(self.server, "fixture_batch_vulnerable", False) or
                            self.headers.get("Cookie") == "fixture_actor=" + item["owner"]):
                        items.append(item)
                return self._answer(200, json.dumps({"items": items}).encode(),
                                    (("Content-Type", "application/json"),))
            if (len(parts) == 7 and parts[3] == "projects" and
                    parts[5] == "dashboards"):
                parent = self.server.fixture_objects.get(parts[4])
                child = self.server.fixture_objects.get(parts[6])
                if (parent is None or child is None or parent["type"] != "project" or
                        child["type"] != "dashboard" or
                        child.get("parentId") is None):
                    return self._answer(404, b"{}", (("Content-Type", "application/json"),))
                cookie = self.headers.get("Cookie")
                child_owner = cookie == "fixture_actor=" + child["owner"]
                parent_owner = cookie == "fixture_actor=" + parent["owner"]
                if (not child_owner and not (getattr(self.server, "fixture_nested_vulnerable", False)
                                             and parent_owner)):
                    return self._answer(403, b'{"error":"forbidden"}',
                                        (("Content-Type", "application/json"),))
                body = {key: child[key] for key in ("id", "parentId", "owner", "tenant")}
                return self._answer(200, json.dumps(body).encode(),
                                    (("Content-Type", "application/json"),))
            if len(parts) == 5 and parts[3] in {"projects", "dashboards", "documents"}:
                item = self.server.fixture_objects.get(parts[4])
                if item is None or item["tenant"] != parts[2] or item["type"] != parts[3][:-1]:
                    return self._answer(404, b"{}", (("Content-Type", "application/json"),))
                if getattr(self.server, "fixture_drop_get_response", False):
                    self.server.fixture_drop_get_response = False
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                if getattr(self.server, "fixture_fail_next_get", False):
                    self.server.fixture_fail_next_get = False
                    return self._answer(503, b'{"error":"read unavailable"}',
                                        (("Content-Type", "application/json"),))
                if getattr(self.server, "fixture_secure", False) and (
                    self.headers.get("Cookie") != "fixture_actor=" + item["owner"]
                ):
                    return self._answer(403, b'{"error":"forbidden"}',
                                        (("Content-Type", "application/json"),))
                return self._answer(200, json.dumps(item).encode(), (("Content-Type", "application/json"),))
        if self.path in {"/validated/object-a", "/validated/object-a-alt"}:
            return self._answer(200, b'{"id":"object-a","tenantId":"tenant-a","payload":"owned-fixture"}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/object-b":
            return self._answer(200, b'{"id":"object-b","tenantId":"tenant-b","payload":"other-fixture"}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/object-c":
            return self._answer(200, b'{"id":"object-c","tenantId":"tenant-a","payload":"role-fixture"}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/private-file":
            return self._answer(200, b"disposable-fixture-file", (("Content-Type", "application/octet-stream"),))
        if self.path == "/validated/example-key":
            return self._answer(200, b'{"api_key":"example"}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/missing":
            return self._answer(404, b"missing", (("Content-Type", "text/plain"),))
        if self.path == "/validated/denied":
            return self._answer(403, b"denied", (("Content-Type", "text/plain"),))
        if self.path == "/validated/graphql":
            return self._answer(200, b'{"data":{"node":{"id":"object-a","tenantId":"tenant-a"}}}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/graphql-invalid":
            return self._answer(200, b'{"data":{"node":null},"errors":[{"message":"not found"}]}',
                                (("Content-Type", "application/json"),))
        if self.path == "/tenant-a/object-a":
            allowed = self.headers.get("Cookie") == "fixture_actor=tenant_a_admin"
            return self._answer(200 if allowed else 403, b"owned-object-a" if allowed else b"denied")
        if self.path == "/tenant-b/object-b":
            allowed = self.headers.get("Cookie") == "fixture_actor=tenant_b_admin"
            return self._answer(200 if allowed else 403, b"owned-object-b" if allowed else b"denied")
        if self.path == "/redirect-out":
            return self._answer(302, headers=(("Location", "http://localhost:9/foreign"),))
        if self.path == "/redirect-in":
            return self._answer(302, headers=(("Location", "/ok"),))
        if self.path == "/large":
            return self._answer(200, b"A" * 10000)
        if self.path == "/gzip":
            body = gzip.compress(b"B" * 10000)
            return self._answer(200, body, (("Content-Encoding", "gzip"),))
        if self.path == "/sleep":
            time.sleep(0.4)
        if self.path == "/cookie":
            return self._answer(200 if self.headers.get("Cookie") == SECRET else 401, b"fixture")
        return self._answer(200, b"fixture", (("Content-Type", "text/plain"),))

    def do_POST(self):
        self.server.received.append(("POST", self.path, self.headers.get("Cookie")))
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        if self.path == "/fixture/graphql":
            try:
                payload = json.loads(body)
                if isinstance(payload, list):
                    if len(payload) != 2 or any(not isinstance(part, dict) or
                            not isinstance(part.get("variables"), dict) or
                            not isinstance(part["variables"].get("id"), str) for part in payload):
                        raise ValueError
                    result = []
                    for part in payload:
                        item = self.server.fixture_objects.get(part["variables"]["id"])
                        if item is None:
                            result.append({"data": {"chosen": None},
                                           "errors": [{"message": "not found"}]})
                        elif (getattr(self.server, "fixture_batch_secure", False) and
                              self.headers.get("Cookie") != "fixture_actor=" + item["owner"]):
                            result.append({"data": {"chosen": None},
                                           "errors": [{"message": "forbidden",
                                                       "extensions": {"code": "FORBIDDEN"}}]})
                        else:
                            result.append({"data": {"chosen": item}})
                    return self._answer(200, json.dumps(result).encode(),
                                        (("Content-Type", "application/json"),))
                if isinstance(payload.get("variables", {}).get("ids"), list):
                    ids = payload["variables"]["ids"]
                    if len(ids) != 2 or any(not isinstance(value, str) for value in ids):
                        raise ValueError
                    nodes = []
                    errors = []
                    for index, value in enumerate(ids):
                        item = self.server.fixture_objects.get(value)
                        if item is None:
                            nodes.append(None)
                            errors.append({"message": "not found", "path": ["chosen", index]})
                        elif (getattr(self.server, "fixture_batch_secure", False) and
                              self.headers.get("Cookie") != "fixture_actor=" + item["owner"]):
                            nodes.append(None)
                            errors.append({"message": "forbidden", "path": ["chosen", index],
                                           "extensions": {"code": "FORBIDDEN"}})
                        else:
                            nodes.append(item)
                    result = {"data": {"chosen": nodes}}
                    if errors:
                        result["errors"] = errors
                    return self._answer(200, json.dumps(result).encode(),
                                        (("Content-Type", "application/json"),))
                value = payload["variables"]["id"]
            except (AttributeError, KeyError, TypeError, ValueError):
                return self._answer(400, b'{}', (("Content-Type", "application/json"),))
            if getattr(self.server, "fixture_global_lookup", False):
                try:
                    decoded = base64.b64decode(value, validate=True).decode("ascii")
                    typename, separator, identifier = decoded.partition(":")
                    value = identifier if separator and typename == "Project" else ""
                except (TypeError, ValueError, UnicodeError, binascii.Error):
                    value = ""
            item = self.server.fixture_objects.get(value)
            if item is None:
                result = {"data": {"node": None}, "errors": [{"message": "not found"}]}
            elif (str(payload.get("query", "")).lstrip().startswith("mutation ") and
                  "parentId" in payload.get("variables", {})):
                parent_id = payload["variables"]["parentId"]
                parent = self.server.fixture_objects.get(parent_id)
                name = payload["variables"].get("name")
                cookie = self.headers.get("Cookie")
                if (parent is None or parent.get("type") != "project" or
                        not isinstance(name, str)):
                    result = {"data": {"renameDashboard": None},
                              "errors": [{"message": "invalid parent or name"}]}
                elif (cookie != "fixture_actor=" + parent["owner"] or
                      (getattr(self.server, "fixture_nested_mutation_secure", False) and
                       (item.get("parentId") != parent_id or
                        cookie != "fixture_actor=" + item["owner"]))):
                    result = {"data": {"renameDashboard": None},
                              "errors": [{"message": "forbidden",
                                          "extensions": {"code": "FORBIDDEN"}}]}
                else:
                    if not getattr(self.server, "fixture_noop_mutation", False):
                        item["name"] = name
                    result = {"data": {"renameDashboard": {
                        key: item[key] for key in ("id", "name", "parentId")}}}
            elif (getattr(self.server, "fixture_secure", False) and
                  self.headers.get("Cookie") != "fixture_actor=" + item["owner"]):
                result = {"data": {"node": None}, "errors": [{"message": "forbidden"}]}
            else:
                if str(payload.get("query", "")).lstrip().startswith("mutation "):
                    name = payload["variables"].get("name", payload["variables"].get("newName"))
                    if not isinstance(name, str):
                        return self._answer(400, b'{}', (("Content-Type", "application/json"),))
                    if not getattr(self.server, "fixture_noop_mutation", False) and not (
                            getattr(self.server, "fixture_graphql_boundary_noop", False) and
                            self.headers.get("Cookie") == "fixture_actor=tenant_b_admin"):
                        item["name"] = name
                node = item
                if getattr(self.server, "fixture_nested_children", None) is not None:
                    children = [self.server.fixture_objects[key] for key in
                                self.server.fixture_nested_children.get(value, ())
                                if key in self.server.fixture_objects]
                    if getattr(self.server, "fixture_nested_secure", False):
                        children = [child for child in children if
                                    self.headers.get("Cookie") ==
                                    "fixture_actor=" + child["owner"]]
                    node = {**item, "dashboards": children}
                if getattr(self.server, "fixture_nested_profile", False):
                    node = {**node, "profile": dict(item.get("profile", {}))}
                result = {"data": {"node": node}}
                if (getattr(self.server, "fixture_field_secure", False) and
                        self.headers.get("Cookie") != "fixture_actor=" + item["owner"]):
                    field_path = (["node", "profile", "email"] if
                                  getattr(self.server, "fixture_nested_profile", False) else
                                  ["node", "email"])
                    denied_node = ({**node, "profile": {**node["profile"], "email": None}}
                                   if len(field_path) == 3 else {**node, "email": None})
                    result = {"data": {"node": denied_node}, "errors": [
                        {"message": "forbidden", "path": field_path,
                         "extensions": {"code": "FORBIDDEN"}}]}
                elif getattr(self.server, "fixture_partial_error", False):
                    result["errors"] = [{"message": "unrelated error", "path": ["other"],
                                         "extensions": {"code": "FORBIDDEN"}}]
            return self._answer(200, json.dumps(result).encode(),
                                (("Content-Type", "application/json"),))
        parts = self.path.split("/")
        if (len(parts) == 6 and parts[1] == "fixture" and
                parts[3] in {"projects", "dashboards"} and parts[5] == "rename"):
            item = self.server.fixture_objects.get(parts[4])
            if item is None or item["tenant"] != parts[2]:
                return self._answer(404)
            if (getattr(self.server, "fixture_secure", False) and
                    self.headers.get("Cookie") != "fixture_actor=" + item["owner"]):
                return self._answer(403, b'{"error":"forbidden"}',
                                    (("Content-Type", "application/json"),))
            try:
                value = json.loads(body)
            except ValueError:
                return self._answer(400)
            if (not isinstance(value, dict) or set(value) != {"name"} or
                    not isinstance(value["name"], str)):
                return self._answer(400)
            if not getattr(self.server, "fixture_noop_mutation", False):
                item["name"] = value["name"]
            return self._answer(200, json.dumps(item).encode(),
                                (("Content-Type", "application/json"),))
        if self.path.startswith("/fixture/"):
            parts = self.path.split("/")
            if len(parts) == 4 and parts[3] in {"projects", "dashboards", "documents", "projects-ambiguous"}:
                try:
                    data = json.loads(body)
                except ValueError:
                    return self._answer(400)
                if not isinstance(data, dict) or not isinstance(data.get("name"), str):
                    return self._answer(400)
                cookie = self.headers.get("Cookie") or ""
                identity = ("tenant_a_admin" if parts[2] == "tenant-a" else "tenant_b_admin") \
                    if cookie == SECRET else cookie.removeprefix("fixture_actor=")
                if identity not in {"tenant_a_admin", "tenant_a_member", "tenant_b_admin"}:
                    return self._answer(401)
                value = f"fixture{len(self.server.fixture_objects) + 1}"
                item = {"id": value, "name": data["name"], "owner": identity,
                        "tenant": parts[2], "type": "project" if parts[3] == "projects-ambiguous"
                        else parts[3][:-1]}
                self.server.fixture_objects[value] = item
                if self.path.endswith("projects-ambiguous"):
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                return self._answer(201, json.dumps(item).encode(), (("Content-Type", "application/json"),))
        if self.path == "/validated/graphql":
            return self._answer(200, b'{"data":{"node":{"id":"object-a","tenantId":"tenant-a"}}}',
                                (("Content-Type", "application/json"),))
        if self.path == "/validated/graphql-invalid":
            return self._answer(200, b'{"data":{"node":null},"errors":[{"message":"not found"}]}',
                                (("Content-Type", "application/json"),))
        if self.path == "/create":
            self.server.created.append(body)
        self._answer(201, b"created")

    def do_PATCH(self):
        self.server.received.append(("PATCH", self.path, self.headers.get("Cookie")))
        parts = self.path.split("/")
        if len(parts) == 5 and parts[3] in {"projects", "dashboards"}:
            item = self.server.fixture_objects.get(parts[4])
            if item is not None and item["tenant"] == parts[2]:
                if (getattr(self.server, "fixture_csrf_required", False) and
                        self.headers.get("X-CSRF-Token") != "fixture-csrf-secret-token"):
                    return self._answer(403, b'{"error":"csrf"}',
                                        (("Content-Type", "application/json"),))
                if (getattr(self.server, "fixture_secure", False) and
                        self.headers.get("Cookie") != "fixture_actor=" + item["owner"]):
                    return self._answer(403, b'{"error":"forbidden"}',
                                        (("Content-Type", "application/json"),))
                data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                if (getattr(self.server, "fixture_mass_assignment_enabled", False) and
                        set(data) == {"can_share_test"} and
                        type(data["can_share_test"]) is bool and
                        item.get("can_share_test") is not None):
                    item["can_share_test"] = data["can_share_test"]
                    return self._answer(200, json.dumps(item).encode(),
                                        (("Content-Type", "application/json"),))
                if (getattr(self.server, "fixture_fail_restore", False) and
                        data.get("name") == getattr(self.server, "fixture_restore_value", None)):
                    return self._answer(403, b'{"error":"restore blocked"}',
                                        (("Content-Type", "application/json"),))
                if not getattr(self.server, "fixture_noop_mutation", False):
                    item["name"] = data.get("name", item["name"])
                if getattr(self.server, "fixture_fail_mutation_readback", False):
                    self.server.fixture_fail_mutation_readback = False
                    self.server.fixture_fail_next_get = True
                if getattr(self.server, "fixture_drop_patch_response", False):
                    self.server.fixture_drop_patch_response = False
                    if getattr(self.server, "fixture_drop_recovery_get", False):
                        self.server.fixture_drop_get_response = True
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                return self._answer(200, json.dumps(item).encode(), (("Content-Type", "application/json"),))
        self._answer(404)

    def do_DELETE(self):
        self.server.received.append(("DELETE", self.path, self.headers.get("Cookie")))
        parts = self.path.split("/")
        if len(parts) == 5 and parts[3] in {"projects", "dashboards"}:
            item = self.server.fixture_objects.get(parts[4])
            if item is not None and item["tenant"] == parts[2]:
                if (getattr(self.server, "fixture_csrf_required", False) and
                        self.headers.get("X-CSRF-Token") != "fixture-csrf-secret-token"):
                    return self._answer(403, b'{"error":"csrf"}',
                                        (("Content-Type", "application/json"),))
                if (getattr(self.server, "fixture_secure", False) and
                        self.headers.get("Cookie") != "fixture_actor=" + item["owner"]):
                    return self._answer(403, b'{"error":"forbidden"}',
                                        (("Content-Type", "application/json"),))
                del self.server.fixture_objects[parts[4]]
                if self.server.drop_delete_response:
                    self.server.drop_delete_response = False
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                return self._answer(204)
        self._answer(404)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.received.append(self.path)
        target = self.server.target
        connection = http.client.HTTPConnection("127.0.0.1", target.server_port, timeout=1)
        try:
            cookie_request = self.path.endswith("/cookie")
            connection.request("GET", "/cookie" if cookie_request else "/ok",
                               headers={"Cookie": self.headers.get("Cookie", "")}
                               if cookie_request else {})
            response = connection.getresponse()
            body = response.read()
        finally:
            connection.close()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TunnelProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_CONNECT(self):
        self.server.received.append(self.path)
        if self.path != f"127.0.0.1:{self.server.target.server_port}":
            self.send_error(403)
            return
        with socket.create_connection(("127.0.0.1", self.server.target.server_port), timeout=3) as upstream:
            self.send_response(200, "Connection Established")
            self.end_headers()
            while True:
                ready, _, _ = select.select((self.connection, upstream), (), (), 5)
                if not ready:
                    break
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is self.connection else self.connection).sendall(data)


class FakeDriver:
    name = "FIXTURE"

    def __init__(self):
        self.running = set()
        self.observations = {}

    def start(self, session_id, profile, *, display, proxy):
        self.running.add(session_id)

    def stop(self, session_id):
        self.running.discard(session_id)

    def is_running(self, session_id):
        return session_id in self.running

    def is_available(self):
        return True

    def observe_identity(self, session_id, rule):
        return self.observations.get(session_id, IdentityObservation())


class FakeTargets:
    def __init__(self, package):
        self.package = package

    def get_target_package(self, package_id):
        return self.package if self.package.id == package_id else None


class ExecutorFixture(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        self.server.received = []
        self.server.created = []
        self.server.fixture_objects = {}
        self.server.fixture_global_lookup = False
        self.server.fixture_nested_children = None
        self.server.fixture_nested_secure = False
        self.server.fixture_batch_secure = False
        self.server.fixture_secure = False
        self.server.fixture_noop_mutation = False
        self.server.fixture_graphql_boundary_noop = False
        self.server.fixture_csrf_required = False
        self.server.fixture_drop_patch_response = False
        self.server.fixture_drop_get_response = False
        self.server.fixture_drop_recovery_get = False
        self.server.fixture_nested_vulnerable = False
        self.server.fixture_batch_vulnerable = False
        self.server.fixture_fail_restore = False
        self.server.fixture_fail_mutation_readback = False
        self.server.fixture_fail_next_get = False
        self.server.fixture_restore_value = None
        self.server.drop_delete_response = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        base_package = load_target_package(EXAMPLE)
        self.package = replace(
            base_package,
            scope=replace(base_package.scope, include_hosts=(HostRule("127.0.0.1"),),
                          exclude_hosts=(), exclude_paths=(), default_schemes=("http",),
                          default_ports=(self.server.server_port,)),
            rate=RatePolicy(requests_per_second=100, requests_per_minute=100,
                            max_concurrency=2, burst=100),
        )
        self.targets = FakeTargets(self.package)
        blobs = self.root / "blobs"
        database = self.root / "state/bughunter.sqlite3"
        database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(Path(_empty_executor_schema().name) / "state/bughunter.sqlite3", database)
        self.store = EvidenceFactStore(self.root / "state/bughunter.sqlite3",
                                       ArtifactStore(blobs), StoreSettings(blobs))
        self.store.initialize()
        self.registry = IdentityRegistry(self.store)
        self.registry.register_target(self.package)
        self.secret_env = {"HACKBOT_SECRET_COOKIE": SECRET}
        self.provider = RoutedSecretProvider(
            SecretSettings(bindings=(SecretBindingConfig(
                "ref:fixture_cookie", "env:HACKBOT_SECRET_COOKIE", "COOKIE"),)),
            self.secret_env,
        )
        self.auth = AuthContextManager(self.registry, self.provider)
        self.driver = FakeDriver()
        self.browser = BrowserSessionManager(
            self.registry, self.auth, self.driver,
            BrowserSettings(profile_root=self.root / "profiles"),
        )
        self.rate = RateLimiter()
        self.policy = PolicyEngine(registry=self.registry, browser=self.browser,
                                   audit=PolicyStore(self.store), rate=self.rate)
        self.permits = PolicyPermitStore(self.store)
        self.traffic = TrafficStore(self.store, self.registry)
        self.executor = TrafficExecutor(
            targets=self.targets, policy=self.policy, permits=self.permits,
            rate=self.rate, traffic=self.traffic, auth=self.auth, secrets=self.provider,
            settings=ExecutorSettings(allow_direct=True, max_response_bytes=1024,
                                      connect_timeout_seconds=5, read_timeout_seconds=10,
                                      overall_timeout_seconds=60),
            browser=self.browser,
        )

    def action(self, path="/ok", *, method="GET", actor=ActorMode.ANONYMOUS,
               identity_id=None, session_id=None, category=ActionCategory.SAFE_READ):
        return ProposedAction(
            target_id=self.package.target.id, package_id=self.package.id,
            category=category, actor=actor, source="unit_test", purpose="Local fixture check",
            url=self.base + path, method=method, identity_id=identity_id, session_id=session_id,
        )

    def run_action(self, action, *, template=None, permit=None, **kwargs):
        template = template or RequestTemplate(action.method, action.url)
        permit = permit or self.executor.authorize(action, template)
        return self.executor.execute(action, permit, template, **kwargs)

    def owned_session(self, alias, *, secret_ref="ref:fixture_cookie"):
        identity = self.registry.register_identity(
            self.package.target.id, alias, status=IdentityStatus.ACTIVE,
            secret_ref=secret_ref,
        )
        self.auth.prepare(self.package.target.id, identity.id)
        session = self.browser.create(self.package.target.id, identity.id)
        self.browser.start(session.id)
        self.browser.login_complete(session.id)
        self.driver.observations[session.id] = IdentityObservation(user_id=alias, tenant_id=alias)
        rule = IdentityVerificationRule(self.package.target.id, identity.id,
                                        "[data-user]", None, "[data-tenant]", alias, None, alias)
        self.browser.verify(session.id, rule)
        return identity, session

class ExecutorTests(ExecutorFixture):
    def test_captured_https_transport_scope_redirect_and_budget(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl is required for the local TLS fixture")
        cert, key = self.root / "fixture.crt", self.root / "fixture.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-subj", "/CN=127.0.0.1",
                        "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        https = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        https.received = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        https.socket = context.wrap_socket(https.socket, server_side=True)
        https_thread = threading.Thread(target=https.serve_forever, daemon=True)
        https_thread.start()
        self.addCleanup(https.server_close)
        self.addCleanup(https.shutdown)
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), TunnelProxyHandler)
        proxy.received = []
        proxy.target = https
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        proxy_thread.start()
        self.addCleanup(proxy.server_close)
        self.addCleanup(proxy.shutdown)

        self.base = f"https://127.0.0.1:{https.server_port}"
        self.package = replace(self.package, scope=replace(
            self.package.scope, include_hosts=(HostRule("127.0.0.1", ("https",),
                                                        (https.server_port,)),),
            default_schemes=("https",), default_ports=(https.server_port,)))
        self.targets.package = self.package

        class LocalCaptureRoute:
            def route(self, _action):
                return ProxyRoute(f"http://127.0.0.1:{proxy.server_port}", cert)

        self.executor.proxy = LocalCaptureRoute()
        self.executor.settings = replace(self.executor.settings,
                                         allow_direct=False, capture_required=True)
        result = self.run_action(self.action())
        self.assertEqual((result.error, result.status_code), (None, 200))
        self.assertEqual(proxy.received, [f"127.0.0.1:{https.server_port}"])
        self.assertEqual(https.received[0][1], "/ok")
        exchange = self.traffic.get_exchange(result.exchange_ids[0])
        self.assertEqual(exchange.attribution.auth_state, AuthState.ANONYMOUS)
        self.assertIsNotNone(exchange.response)

        before = len(proxy.received)
        with self.assertRaises(PermitError):
            self.run_action(replace(self.action(), url=f"https://localhost:{https.server_port}/ok"))
        self.assertEqual(len(proxy.received), before)
        redirected = self.run_action(self.action("/redirect-out"))
        self.assertEqual(redirected.error, ExecutionError.REDIRECT_DENIED)
        self.assertEqual(len(proxy.received), before + 1)
        first = self.run_action(self.action(), experiment_id="https_budget",
                                budget=ExperimentBudget(max_requests=1))
        self.assertIsNone(first.error)
        before = len(proxy.received)
        second = self.run_action(self.action(), experiment_id="https_budget",
                                 budget=ExperimentBudget(max_requests=1))
        self.assertIn(second.error, {ExecutionError.POLICY_DENIED, ExecutionError.RATE_LIMITED})
        self.assertEqual(len(proxy.received), before)

    def test_empty_schema_seed_keeps_fixture_databases_isolated(self):
        other = ExecutorFixture(methodName="runTest")
        other.setUp()
        self.addCleanup(other.doCleanups)
        self.assertNotEqual(self.store.db_path, other.store.db_path)
        with self.store._connection() as db:
            db.execute("CREATE TABLE fixture_isolation (marker TEXT)")
        with other.store._connection() as db:
            self.assertIsNone(db.execute(
                "SELECT name FROM sqlite_master WHERE name='fixture_isolation'").fetchone())

    def test_plain_request_fingerprint_remains_backward_compatible(self):
        url = self.base + "/fixture"
        expected = hashlib.sha256(json.dumps(
            ["GET", url, (), None], separators=(",", ":"),
            ensure_ascii=True).encode()).hexdigest()
        self.assertEqual(RequestTemplate("GET", url).fingerprint(), expected)
        self.assertNotEqual(RequestTemplate("GET", url, host_override="admin.internal").fingerprint(),
                            expected)

    def test_no_permit_wrong_binding_expiry_and_reuse_send_zero_extra(self):
        action = self.action()
        template = RequestTemplate("GET", action.url)
        denied = self.executor.execute(action, None, template)
        self.assertEqual(denied.error, ExecutionError.PERMIT_DENIED)
        self.assertEqual(self.server.received, [])
        with self.store._connection() as db:
            rows = db.execute("SELECT event_type FROM executor_events WHERE action_id=? ORDER BY event_id",
                              (action.id,)).fetchall()
        self.assertEqual([row[0] for row in rows], ["EXECUTION_REQUESTED", "EXECUTION_FAILED"])
        permit = self.executor.authorize(action, template)
        with self.store._connection() as db:
            issued, expires = db.execute(
                "SELECT issued_at,expires_at FROM executor_permits WHERE permit_id=?",
                (permit.id,),
            ).fetchone()
        self.assertEqual(datetime.fromisoformat(expires) - datetime.fromisoformat(issued),
                         timedelta(seconds=30))
        wrong = replace(permit, target_id="TARGET-" + "9" * 32)
        self.assertEqual(self.executor.execute(action, wrong, template).error, ExecutionError.PERMIT_DENIED)
        wrong_identity = replace(permit, identity_id="IDENTITY-" + "8" * 32)
        self.assertEqual(self.executor.execute(action, wrong_identity, template).error, ExecutionError.PERMIT_DENIED)
        expired = replace(permit, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        self.assertEqual(self.executor.execute(action, expired, template).error, ExecutionError.PERMIT_DENIED)
        changed = replace(template, headers=(("Accept", "application/json"),))
        self.assertEqual(self.executor.execute(action, permit, changed).error, ExecutionError.PERMIT_DENIED)
        self.assertEqual(self.server.received, [])
        good = self.executor.execute(action, permit, template)
        self.assertEqual((good.error, good.status_code), (None, 200))
        self.assertEqual(self.executor.execute(action, permit, template).error, ExecutionError.PERMIT_DENIED)
        self.assertEqual(len(self.server.received), 1)
        self.assertEqual(self.traffic.get_exchange(good.exchange_ids[0]).state, ExchangeState.COMPLETE)

    def test_protected_asset_capture_is_typed_and_local_only(self):
        self.executor.retention = RetentionSettings(js_artifact_hours=24, source_map_hours=48)
        action = self.action("/assets/app.js")
        started = datetime.now(timezone.utc)
        result = self.run_action(action, artifact_capture_kind="JS")
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.artifact_evidence_id)
        self.assertIn(b"fixture-secret", self.store.read_content(
            result.artifact_evidence_id, allow_sensitive=True))
        self.assertEqual(len(result.exchange_ids), 1)
        js_evidence = self.store.get_evidence(result.artifact_evidence_id)
        self.assertEqual(js_evidence.metadata["retention_class"], "REGENERABLE")
        self.assertTrue(js_evidence.retention.retain)
        self.assertLessEqual(started + timedelta(hours=24), js_evidence.retention.expires_at)
        self.assertLessEqual(js_evidence.retention.expires_at,
                             datetime.now(timezone.utc) + timedelta(hours=24))

        map_action = self.action("/assets/app.js.map")
        map_started = datetime.now(timezone.utc)
        source_map = self.run_action(map_action, artifact_capture_kind="SOURCE_MAP")
        self.assertIsNotNone(source_map.artifact_evidence_id)
        map_evidence = self.store.get_evidence(source_map.artifact_evidence_id)
        self.assertEqual(map_evidence.metadata["retention_class"], "REGENERABLE")
        self.assertLessEqual(map_started + timedelta(hours=48), map_evidence.retention.expires_at)
        self.assertLessEqual(map_evidence.retention.expires_at,
                             datetime.now(timezone.utc) + timedelta(hours=48))

        exposure = self.run_action(self.action("/fixture/config.json"), artifact_capture_kind="EXPOSURE")
        exposure_evidence = self.store.get_evidence(exposure.artifact_evidence_id)
        self.assertIsNone(exposure_evidence.retention.expires_at)
        self.assertNotIn("retention_class", exposure_evidence.metadata)
        fallback = self.run_action(self.action("/assets/fallback.js"), artifact_capture_kind="JS")
        self.assertIsNone(fallback.artifact_evidence_id)
        invalid = self.run_action(self.action("/assets/app.js"), artifact_capture_kind="SOURCE_MAP")
        self.assertIsNone(invalid.artifact_evidence_id)

    def test_dom_specialist_acquires_once_through_policy_executor(self):
        body = (b'const api_key="fixture-secret";location.search;iframe.src;\n'
                b'//# sourceMappingURL=app.js.map')
        digest = hashlib.sha256(body).hexdigest()
        asset = ReconJsAsset(91, 7, self.base + "/assets/app.js", digest, len(body), 200,
                             Provenance("js_assets", 91, None, "fixture"))

        class LocalRecon:
            def resolve_target(self, _name):
                return ReconTarget(7, "example.test", True, True,
                                   Provenance("domains", 7, None, "fixture"))

            def list_js_assets(self, _domain_id, _host_id, *, limit, cursor=None):
                return Page((asset,), None)

            def get_js_asset(self, _domain_id, asset_id):
                return asset if asset_id == asset.asset_id else None

        specialist = DOMXSSSpecialist(recon=LocalRecon(), targets=self.targets,
                                      executor=self.executor, store=DOMXSSStore(self.store))
        first = specialist.acquire(self.package.id, asset)
        self.assertEqual(first.status, DOMAcquisitionStatus.RETRIEVED)
        self.assertEqual(first.artifact.artifact_sha256, digest)
        self.assertIsNotNone(self.store.get_evidence(first.artifact.evidence_id).retention.expires_at)
        self.assertEqual(len(first.exchange_ids), 1)
        self.assertEqual(len(self.server.received), 1)
        second = specialist.acquire(self.package.id, asset)
        self.assertEqual(second.status, DOMAcquisitionStatus.REUSED)
        self.assertEqual(len(self.server.received), 1)
        source_map = specialist.acquire_source_map(self.package.id, asset, first.artifact)
        self.assertEqual(source_map.status, DOMAcquisitionStatus.RETRIEVED)
        self.assertIsNotNone(self.store.get_evidence(source_map.source_map.evidence_id).retention.expires_at)
        self.assertEqual(len(self.server.received), 2)
        reused_map = specialist.acquire_source_map(self.package.id, asset, first.artifact)
        self.assertEqual(reused_map.status, DOMAcquisitionStatus.REUSED)
        self.assertEqual(len(self.server.received), 2)

        with self.store._connection() as db:
            retired_at = (datetime.now(timezone.utc) + timedelta(days=91)).isoformat()
            for evidence_id in (first.artifact.evidence_id, source_map.source_map.evidence_id):
                db.execute(
                    "INSERT INTO evidence_payload_retirements "
                    "(evidence_id,retired_at,retention_class,actor,reason) "
                    "VALUES (?,?,?,?,?)",
                    (evidence_id, retired_at, "REGENERABLE", "fixture", "expired-asset"),
                )
        refreshed = specialist.acquire(self.package.id, asset)
        self.assertEqual(refreshed.status, DOMAcquisitionStatus.RETRIEVED)
        self.assertEqual(refreshed.artifact.artifact_id, first.artifact.artifact_id)
        self.assertNotEqual(refreshed.artifact.evidence_id, first.artifact.evidence_id)
        self.assertEqual(len(self.server.received), 3)
        refreshed_map = specialist.acquire_source_map(self.package.id, asset, refreshed.artifact)
        self.assertEqual(refreshed_map.status, DOMAcquisitionStatus.RETRIEVED)
        self.assertEqual(refreshed_map.source_map.map_id, source_map.source_map.map_id)
        self.assertNotEqual(refreshed_map.source_map.evidence_id, source_map.source_map.evidence_id)
        self.assertEqual(len(self.server.received), 4)

    def test_scope_policy_change_and_redirects(self):
        out = self.action("/redirect-out")
        result = self.run_action(out)
        self.assertEqual(result.error, ExecutionError.REDIRECT_DENIED)
        self.assertEqual(len(self.server.received), 1)
        self.assertEqual(len(result.redirects), 1)
        self.assertFalse(result.redirects[0].followed)
        inside = self.run_action(self.action("/redirect-in"))
        self.assertIsNone(inside.error)
        self.assertEqual([row[1] for row in self.server.received[-2:]], ["/redirect-in", "/ok"])
        action = self.action()
        template = RequestTemplate("GET", action.url)
        permit = self.executor.authorize(action, template)
        self.targets.package = replace(self.package, scope=replace(
            self.package.scope, include_hosts=(HostRule("localhost"),)))
        before = len(self.server.received)
        denied = self.executor.execute(action, permit, template)
        self.assertIn(denied.error, {ExecutionError.SCOPE_DENIED, ExecutionError.POLICY_DENIED})
        self.assertEqual(len(self.server.received), before)

    def test_anonymous_and_verified_cookie_isolation(self):
        identity, session = self.owned_session("tenant_a_admin")
        auth_action = self.action("/cookie", actor=ActorMode.AUTHENTICATED,
                                  identity_id=identity.id, session_id=session.id)
        authenticated = self.run_action(auth_action)
        self.assertEqual((authenticated.error, authenticated.status_code), (None, 200))
        self.assertEqual(self.traffic.get_exchange(authenticated.exchange_ids[0]).attribution.auth_state,
                         AuthState.VERIFIED)
        self.assertNotIn(SECRET.encode(), self.store.db_path.read_bytes())
        anonymous = self.run_action(self.action("/cookie"))
        self.assertEqual((anonymous.error, anonymous.status_code), (None, 401))
        self.assertIsNone(self.server.received[-1][2])
        self.assertNotIn(SECRET, repr(authenticated))
        self.assertNotIn(SECRET, repr(self.traffic.get_exchange(authenticated.exchange_ids[0])))

    def test_unverified_expired_missing_and_manual_auth_send_nothing(self):
        identity, session = self.owned_session("tenant_a_member")
        action = self.action("/cookie", actor=ActorMode.AUTHENTICATED,
                             identity_id=identity.id, session_id=session.id)
        template = RequestTemplate("GET", action.url)
        permit = self.executor.authorize(action, template)
        self.auth.set_status(self.package.target.id, identity.id, AuthStatus.EXPIRED)
        self.assertIn(self.executor.execute(action, permit, template).error,
                      {ExecutionError.POLICY_DENIED, ExecutionError.AUTH_UNAVAILABLE})
        self.assertEqual(self.server.received, [])
        self.driver.running.clear()
        with self.assertRaises(PermitError):
            self.executor.authorize(replace(action, id=action.id.replace("a", "b", 1)), template)

    def test_missing_secret_and_manual_login_do_not_send(self):
        identity, session = self.owned_session("tenant_b_admin")
        action = self.action("/cookie", actor=ActorMode.AUTHENTICATED,
                             identity_id=identity.id, session_id=session.id)
        template = RequestTemplate("GET", action.url)
        permit = self.executor.authorize(action, template)
        self.secret_env.clear()
        self.assertEqual(self.executor.execute(action, permit, template).error,
                         ExecutionError.AUTH_UNAVAILABLE)
        self.assertEqual(self.server.received, [])
        self.assertEqual(self.executor.execute(action, permit, template).error,
                         ExecutionError.PERMIT_DENIED)

        manual = self.registry.register_identity(
            self.package.target.id, "manual_user", status=IdentityStatus.ACTIVE)
        self.auth.prepare(self.package.target.id, manual.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        browser_session = self.browser.create(self.package.target.id, manual.id)
        self.browser.start(browser_session.id)
        self.browser.login_complete(browser_session.id)
        self.driver.observations[browser_session.id] = IdentityObservation(user_id="manual_user")
        self.browser.verify(browser_session.id, IdentityVerificationRule(
            self.package.target.id, manual.id, "[data-user]", None, None,
            "manual_user", None, None))
        manual_action = self.action(actor=ActorMode.AUTHENTICATED,
                                    identity_id=manual.id, session_id=browser_session.id)
        self.assertEqual(self.run_action(manual_action).error, ExecutionError.AUTH_UNAVAILABLE)
        self.assertEqual(self.server.received, [])

    def test_manual_browser_cookie_requires_verified_captured_session(self):
        identity = self.registry.register_identity(
            self.package.target.id, "captured_manual", status=IdentityStatus.ACTIVE)
        self.auth.prepare(self.package.target.id, identity.id,
                          mechanism=AuthMechanism.MANUAL_LOGIN)
        proxy = BrowserProxyConfig(enabled=True, proxy_url="http://127.0.0.1:38080",
                                   capture_required=True, guard_scope=self.package.scope)
        session = self.browser.create(self.package.target.id, identity.id, proxy=proxy)
        self.browser.start(session.id, proxy=proxy, package=self.package,
                           proxy_health_check=lambda _proxy: True)
        self.browser.login_complete(session.id)
        self.driver.observations[session.id] = IdentityObservation(user_id="captured_manual")
        self.browser.verify(session.id, IdentityVerificationRule(
            self.package.target.id, identity.id, "[data-user]", None, None,
            "captured_manual", None, None))
        action = self.action("/cookie", actor=ActorMode.AUTHENTICATED,
                             identity_id=identity.id, session_id=session.id)
        self.assertEqual(self.run_action(action).error, ExecutionError.AUTH_UNAVAILABLE)
        self.assertEqual(self.server.received, [])

        self.driver.cookie_header_for = lambda browser_id, url: SecretValue(
            "fixture-cookie=owned" if browser_id == session.id and url == action.url else "")
        self.assertEqual(self.executor._authentication(action),
                         ("Cookie", "fixture-cookie=owned"))
        proxy_server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        proxy_server.received = []
        proxy_server.target = self.server
        proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
        proxy_thread.start()
        self.addCleanup(proxy_server.server_close)
        self.addCleanup(proxy_server.shutdown)

        class LocalCaptureRoute:
            def route(self, _action):
                return ProxyRoute(f"http://127.0.0.1:{proxy_server.server_port}")

        self.executor.proxy = LocalCaptureRoute()
        self.executor.settings = replace(self.executor.settings,
                                         allow_direct=False, capture_required=True)
        self.assertEqual(self.run_action(action).status_code, 200)
        self.assertEqual(self.server.received[-1],
                         ("GET", "/cookie", "fixture-cookie=owned"))
        dispatched_count = len(self.server.received)
        self.driver.cookie_header_for = lambda *_args: "fixture-cookie=wrong-type"
        self.assertEqual(self.run_action(action).error, ExecutionError.AUTH_UNAVAILABLE)
        self.driver.cookie_header_for = lambda *_args: SecretValue("bad\r\nheader")
        self.assertEqual(self.run_action(action).error, ExecutionError.AUTH_UNAVAILABLE)
        self.assertEqual(len(self.server.received), dispatched_count)
        self.browser.stop(session.id)
        self.driver.cookie_header_for = lambda *_args: SecretValue("fixture-cookie=owned")
        with self.assertRaises(PermitError):
            self.run_action(action)
        self.assertEqual(len(self.server.received), dispatched_count)

    def test_body_cap_gzip_and_timeout(self):
        for path in ("/large", "/gzip"):
            result = self.run_action(self.action(path))
            self.assertIsNone(result.error)
            self.assertTrue(result.truncated)
            self.assertEqual(result.body_bytes_captured, 1024)
            exposure = self.run_action(self.action(path), artifact_capture_kind="EXPOSURE")
            self.assertIsNone(exposure.error)
            self.assertTrue(exposure.truncated)
            self.assertIsNone(exposure.artifact_evidence_id)
        self.executor.settings = replace(self.executor.settings, connect_timeout_seconds=0.2,
                                         read_timeout_seconds=0.2, overall_timeout_seconds=2)
        timeout = self.run_action(self.action("/sleep"))
        self.assertEqual(timeout.error, ExecutionError.TIMEOUT)
        self.assertEqual(self.traffic.get_exchange(timeout.exchange_ids[0]).state, ExchangeState.TIMEOUT)

    def test_budget_rate_proxy_and_direct_mode(self):
        first = self.run_action(self.action(), experiment_id="test_budget",
                                budget=ExperimentBudget(max_requests=1))
        self.assertIsNone(first.error)
        second = self.run_action(self.action(), experiment_id="test_budget",
                                 budget=ExperimentBudget(max_requests=1))
        self.assertIn(second.error, {ExecutionError.POLICY_DENIED, ExecutionError.RATE_LIMITED})
        before = len(self.server.received)
        self.executor.settings = ExecutorSettings(allow_direct=False, capture_required=True)
        blocked = self.run_action(self.action())
        self.assertEqual(blocked.error, ExecutionError.PROXY_UNAVAILABLE)
        self.assertEqual(len(self.server.received), before)

    def test_proxy_route_and_approval_backed_post(self):
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        proxy.received = []
        proxy.target = self.server
        worker = threading.Thread(target=proxy.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(proxy.server_close)
        self.addCleanup(proxy.shutdown)

        class LocalProxy:
            def route(self, action):
                return ProxyRoute(f"http://127.0.0.1:{proxy.server_port}")

        self.executor.proxy = LocalProxy()
        self.executor.settings = ExecutorSettings(capture_required=True, max_response_bytes=1024)
        result = self.run_action(self.action())
        self.assertIsNone(result.error)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(proxy.received), 1)
        self.assertEqual(self.server.received[-1][1], "/ok")

        self.executor.proxy = None
        self.executor.settings = ExecutorSettings(allow_direct=True, max_response_bytes=1024)
        self.targets.package = replace(
            self.package, autonomy=replace(self.package.autonomy,
                                           state_changing=PolicyDecision.REQUIRE_APPROVAL,
                                           create_disposable_objects=PolicyDecision.REQUIRE_APPROVAL),
        )
        action = self.action("/create", method="POST", category=ActionCategory.OBJECT_CREATE)
        action = replace(action, disposable_intent=True, object_type="fixture")
        template = RequestTemplate("POST", action.url, (("Content-Type", "application/json"),), b'{"name":"fixture"}')
        decision = self.policy.evaluate(self.targets.package, action, record=True)
        self.assertEqual(decision.result, PolicyDecision.REQUIRE_APPROVAL)
        PolicyStore(self.store).decide(decision.approval_id, action.target_id, approve=True)
        permit = self.executor.authorize(action, template)
        executed = self.executor.execute(action, permit, template)
        self.assertEqual((executed.error, executed.status_code, executed.approval_id),
                         (None, 201, decision.approval_id))
        self.assertEqual(PolicyStore(self.store).get(decision.approval_id, action.target_id).status.value,
                         "CONSUMED")
        self.assertEqual(self.server.received[-1][:2], ("POST", "/create"))
        self.assertEqual(self.server.created, [b'{"name":"fixture"}'])

    def test_shared_rate_concurrency_blocks_second_request(self):
        self.targets.package = replace(self.package, rate=replace(self.package.rate, max_concurrency=1))
        first_action = self.action()
        first_template = RequestTemplate("GET", first_action.url)
        first_permit = self.executor.authorize(first_action, first_template)
        outcome = []
        reserved = threading.Event()
        release = threading.Event()

        def hold_reserved_slot(_exchange_id):
            reserved.set()
            return release.wait(timeout=60)

        worker = threading.Thread(target=lambda: outcome.append(
            self.executor.execute(first_action, first_permit, first_template,
                                  on_dispatch=hold_reserved_slot)), daemon=True)
        worker.start()
        try:
            self.assertTrue(reserved.wait(timeout=60))
            self.assertEqual(self.server.received, [])
            second_action = self.action()
            second_template = RequestTemplate("GET", second_action.url)
            # The shared Phase 13 limiter denies issuance or execution while first is in flight.
            try:
                second_permit = self.executor.authorize(second_action, second_template)
            except PermitError:
                second_permit = None
            if second_permit is not None:
                self.assertIn(self.executor.execute(second_action, second_permit, second_template).error,
                              {ExecutionError.POLICY_DENIED, ExecutionError.RATE_LIMITED})
            self.assertEqual(self.server.received, [])
        finally:
            release.set()
            worker.join(timeout=60)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(self.server.received), 1)
        self.assertEqual((outcome[0].error, outcome[0].status_code), (None, 200))
        self.assertFalse(worker.is_alive())

    def test_template_header_validation(self):
        for header in (("Host", "other.test"), ("Authorization", "Bearer hidden"),
                       ("X-API-Key", "hidden"), ("X-HackBot-Correlation", "bad"),
                       ("Accept", "ok\r\nInjected: yes")):
            with self.assertRaises(ValueError):
                RequestTemplate("GET", self.base + "/ok", (header,))


if __name__ == "__main__":
    unittest.main()
