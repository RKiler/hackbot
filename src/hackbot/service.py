"""Private, single-process BugHunter control plane. No target traffic is issued here."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import importlib.util
import json
import socket
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from . import __version__
from .auth import AuthContextManager, AuthMechanism
from .browser import (BrowserError, BrowserSession, BrowserSessionManager,
                      BrowserStatus, IdentityVerificationRule)
from .browser_playwright import PlaywrightBrowserDriver
from .burp import BurpProxyProvider
from .config import AppConfig, load_config
from .identity_registry import IdentityRegistry
from .logging import create_logger
from .secrets import RoutedSecretProvider
from .store import EvidenceFactStore, StoreNotInitialized, StoreSchemaError
from .target_loader import TargetPackageRepository
from .target_package import PackageStatus, TargetPackage
from .traffic import TrafficStore


_AUDIT_EVENTS = frozenset({
    "target_registered", "identities_imported", "auth_prepared", "browser_created",
    "browser_start_requested", "browser_started", "manual_login_completed",
    "identity_verification_finished", "browser_stopped", "browser_reconciled",
})


@dataclass(frozen=True, slots=True)
class PageRequest:
    limit: int
    cursor: str | None

    @classmethod
    def parse(cls, *, maximum: int = 50) -> PageRequest:
        raw = request.args.get("limit", "20")
        if not raw.isdecimal():
            raise ValueError("invalid pagination")
        limit = int(raw)
        if not 1 <= limit <= maximum:
            raise ValueError("invalid pagination")
        cursor = request.args.get("cursor") or None
        if cursor is not None and (len(cursor) > 512 or any(ord(ch) < 32 for ch in cursor)):
            raise ValueError("invalid pagination")
        return cls(limit, cursor)


class BugHunterRuntime:
    """One trusted process owns all in-memory browser handles."""

    def __init__(self, config: AppConfig, *, driver: Any | None = None,
                 vnc_ready: Callable[[], bool] | None = None) -> None:
        self.config = config
        self.store = EvidenceFactStore.from_config(config)
        self.store.initialize()
        self.registry = IdentityRegistry(self.store)
        self.auth = AuthContextManager(self.registry, RoutedSecretProvider(config.secrets))
        self.driver = driver or PlaywrightBrowserDriver(config.browser.chromium_executable)
        self.browser = BrowserSessionManager(self.registry, self.auth, self.driver, config.browser)
        self.traffic = TrafficStore(self.store, self.registry)
        self.burp = BurpProxyProvider(config.burp, self.traffic, self.browser)
        self.targets = TargetPackageRepository(config.targets.root)
        self.logger = create_logger(level=config.log_level)
        self._vnc_ready = vnc_ready or self._probe_vnc
        self.reconcile_on_startup()

    def _probe_vnc(self) -> bool:
        if not self.config.browser.vnc_url:
            return False
        parsed = urlsplit(self.config.browser.vnc_url)
        try:
            with socket.create_connection(("127.0.0.1", parsed.port), timeout=0.2):
                return True
        except OSError:
            return False

    def reconcile_on_startup(self) -> int:
        """Fail closed after process restart; never reuse an unowned browser handle."""
        changed = 0
        marker = ""
        while True:
            with self.store._connection() as connection:
                rows = connection.execute(
                    "SELECT session_id FROM browser_sessions WHERE session_id>? "
                    "AND status IN ('STARTING','RUNNING','WAITING_LOGIN','VERIFYING_IDENTITY',"
                    "'NEEDS_MANUAL_REVIEW','VALID') ORDER BY session_id LIMIT 100",
                    (marker,),
                ).fetchall()
            if not rows:
                break
            for row in rows:
                marker = row["session_id"]
                before = self.browser.get(marker)
                after = self.browser.reconcile_stale(marker)
                if before and before.status != after.status:
                    changed += 1
            if len(rows) < 100:
                break
        return changed

    def package(self, package_id: str) -> TargetPackage:
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise LookupError("target not found")
        return package

    def audit(self, event_type: str, *, target_id: str | None = None,
              identity_id: str | None = None, session_id: str | None = None) -> None:
        if event_type not in _AUDIT_EVENTS:
            raise ValueError("invalid activity event")
        at = datetime.now(timezone.utc).isoformat()
        with self.store._connection() as connection:
            connection.execute(
                "INSERT INTO service_events(occurred_at,event_type,target_id,identity_id,session_id) "
                "VALUES (?,?,?,?,?)", (at, event_type, target_id, identity_id, session_id),
            )
        self.logger.info(event_type, extra={"context": {
            "target_id": target_id, "identity_id": identity_id, "browser_ref": session_id,
        }})

    def activity(self, page: PageRequest) -> dict[str, object]:
        if page.cursor is not None and not page.cursor.isdecimal():
            raise ValueError("invalid activity cursor")
        sql = "SELECT id,occurred_at,event_type,target_id,identity_id,session_id FROM service_events"
        params: list[object] = []
        if page.cursor:
            sql += " WHERE id<?"
            params.append(int(page.cursor))
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(page.limit + 1)
        with self.store._connection() as connection:
            rows = connection.execute(sql, params).fetchall()
        items = [dict(row) for row in rows[:page.limit]]
        return {"items": items, "next_cursor": str(items[-1]["id"]) if len(rows) > page.limit else None}

    def health(self) -> dict[str, object]:
        with self.store._connection() as connection:
            connection.execute("SELECT 1").fetchone()
        browser_installed = importlib.util.find_spec("playwright") is not None
        return {"status": "ok", "version": __version__, "checks": {
            "bughunter_store": "ok", "browser_manager": "ready" if browser_installed else "dependency_missing",
            "vnc": "ready" if self._vnc_ready() else "not_running",
            "traffic_store": "ok", "burp": self.burp.availability().value,
        }, "recon_integration": "not_connected"}

    def overview(self) -> dict[str, object]:
        with self.store._connection() as connection:
            counts = {label: connection.execute(sql).fetchone()[0] for label, sql in {
                "identities": "SELECT count(*) FROM registry_identities",
                "browser_sessions": "SELECT count(*) FROM browser_sessions WHERE status NOT IN ('STOPPED','FAILED','EXPIRED')",
                "reauth_required": "SELECT count(*) FROM browser_sessions WHERE status='REAUTH_REQUIRED'",
                "traffic": "SELECT count(*) FROM traffic_exchanges",
            }.items()}
        count = 0
        cursor = None
        while count <= 1000:
            page = self.targets.list_target_packages(limit=100, cursor=cursor)
            count += len(page.items)
            cursor = page.next_cursor
            if cursor is None:
                break
        return {"targets": count, "targets_truncated": cursor is not None, **counts,
                "burp": self.burp.availability().value, "activity": self.activity(PageRequest(8, None))["items"]}

    def target_summary(self, package: TargetPackage) -> dict[str, object]:
        with self.store._connection() as connection:
            counts = {
                "identities": connection.execute("SELECT count(*) FROM registry_identities WHERE target_id=?",
                                                 (package.target.id,)).fetchone()[0],
                "browser_sessions": connection.execute("SELECT count(*) FROM browser_sessions WHERE target_id=?",
                                                        (package.target.id,)).fetchone()[0],
                "traffic": connection.execute("SELECT count(*) FROM traffic_exchanges WHERE target_id=?",
                                               (package.target.id,)).fetchone()[0],
            }
        return {"id": package.id, "target_id": package.target.id, "name": package.to_dict()["name"],
                "primary_domain": package.primary_domain, "status": package.status.value,
                "scope_summary": {"included_hosts": len(package.scope.include_hosts),
                                  "excluded_hosts": len(package.scope.exclude_hosts)},
                "counts": counts, "authority": "TARGET_PACKAGE"}

    def identity_summary(self, target_id: str, identity_id: str) -> dict[str, object]:
        identity = self.registry.get_identity(target_id, identity_id)
        if identity is None:
            raise LookupError("identity not found")
        memberships = self.registry.list_memberships(identity.id, limit=20)
        member_rows = []
        for membership in memberships.items:
            tenant = self.registry.get_tenant(target_id, membership.tenant_id)
            roles = [self.registry.get_role(target_id, role_id) for role_id in membership.role_ids]
            member_rows.append({"tenant_id": membership.tenant_id,
                                "tenant": tenant.label if tenant else None,
                                "roles": [role.name for role in roles if role],
                                "status": membership.status.value,
                                "observation_state": membership.observation_state.value})
        context = self.auth.get(target_id, identity.id)
        session = self.browser.get_session_for_identity(target_id, identity.id)
        return {"identity": identity.to_dict(), "memberships": member_rows,
                "memberships_truncated": memberships.next_cursor is not None,
                "auth": context.to_dict() if context else None,
                "browser": self.session_summary(session) if session else None}

    def session_summary(self, session: BrowserSession) -> dict[str, object]:
        result = session.to_dict()
        result["browser_running"] = self.driver.is_running(session.id)
        result["vnc_available"] = bool(session.status is BrowserStatus.WAITING_LOGIN and self._vnc_ready())
        result["vnc_url"] = (self.config.browser.vnc_url if result["vnc_available"] else None)
        return result

    def verification_rule(self, package: TargetPackage, identity_id: str) -> IdentityVerificationRule | None:
        """Optional private, server-side rule; never accept expected identity from the client."""
        identity = self.registry.get_identity(package.target.id, identity_id)
        if identity is None:
            return None
        path = package.package_dir / "verification.json"
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
            raise ValueError("invalid verification rule file")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or len(payload) > 20:
                raise ValueError
            item = payload.get(identity.alias)
            if item is None:
                return None
            allowed = {"user_id_selector", "email_selector", "tenant_selector",
                       "expected_user_id", "expected_email", "expected_tenant_id"}
            if not isinstance(item, dict) or set(item) - allowed or any(
                not isinstance(value, str) or not 1 <= len(value) <= 256 for value in item.values()
            ):
                raise ValueError
            return IdentityVerificationRule(target_id=package.target.id,
                                            identity_id=identity_id, **item)
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError("invalid verification rule file") from None


def _body(allowed: frozenset[str]) -> dict[str, Any]:
    value = request.get_json(silent=True)
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("invalid request body")
    return value


def create_app(config: AppConfig | None = None, *, runtime: BugHunterRuntime | None = None) -> Flask:
    """WSGI factory. Bind with exactly one worker on a private Unix socket."""
    service = runtime or BugHunterRuntime(config or load_config())
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16_384
    app.config["JSON_SORT_KEYS"] = True

    @app.after_request
    def no_store(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.errorhandler(LookupError)
    def not_found(_exc):
        return jsonify(error="not_found"), 404

    @app.errorhandler((ValueError))
    def bad_request(_exc):
        return jsonify(error="invalid_request"), 400

    @app.errorhandler(StoreNotInitialized)
    @app.errorhandler(StoreSchemaError)
    def unavailable(_exc):
        return jsonify(error="service_unavailable"), 503

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error="request_rejected"), exc.code

    @app.errorhandler(Exception)
    def internal(_exc):
        service.logger.error("service_request_failed")
        return jsonify(error="internal_error"), 500

    @app.get("/v1/health")
    def health():
        return jsonify(service.health())

    @app.get("/v1/status")
    def status():
        return jsonify({"version": __version__, "runtime": "single_process",
                        "browser": service.health()["checks"]["browser_manager"],
                        "burp": service.burp.status(), "recon_integration": "not_connected"})

    @app.get("/v1/overview")
    def overview():
        return jsonify(service.overview())

    @app.get("/v1/activity")
    def activity():
        return jsonify(service.activity(PageRequest.parse()))

    @app.get("/v1/targets")
    def targets():
        page = PageRequest.parse()
        result = service.targets.list_target_packages(limit=page.limit, cursor=page.cursor)
        return jsonify({"items": [service.target_summary(item) for item in result.items],
                        "next_cursor": result.next_cursor})

    @app.get("/v1/targets/<package_id>")
    def target(package_id: str):
        return jsonify(service.target_summary(service.package(package_id)))

    @app.get("/v1/targets/<package_id>/scope")
    def scope(package_id: str):
        package = service.package(package_id)
        return jsonify({"authority": "AUTHORIZED_TARGET_SCOPE", "recon_inventory": "NOT_AUTHORIZATION",
                        "target_id": package.target.id, "package_status": package.status.value,
                        "scope": package.scope.to_dict(),
                        "program_rules": package.rules.to_dict()})

    @app.post("/v1/targets/<package_id>/import-identities")
    def import_identities(package_id: str):
        _body(frozenset())
        package = service.package(package_id)
        service.registry.register_target(package)
        service.audit("target_registered", target_id=package.target.id)
        identities = service.registry.import_package_accounts(package)
        service.audit("identities_imported", target_id=package.target.id)
        return jsonify({"imported": len(identities), "target_id": package.target.id}), 201

    @app.get("/v1/targets/<package_id>/identities")
    def identities(package_id: str):
        package = service.package(package_id)
        page = PageRequest.parse()
        result = service.registry.list_identities(package.target.id, limit=page.limit, cursor=page.cursor)
        return jsonify({"items": [service.identity_summary(package.target.id, item.id) for item in result.items],
                        "next_cursor": result.next_cursor})

    def scoped_identity(identity_id: str):
        package = service.package(request.args.get("target", ""))
        item = service.registry.get_identity(package.target.id, identity_id)
        if item is None:
            raise LookupError("identity not found")
        return package, item

    @app.get("/v1/identities/<identity_id>")
    def identity(identity_id: str):
        package, item = scoped_identity(identity_id)
        return jsonify(service.identity_summary(package.target.id, item.id))

    @app.get("/v1/identities/<identity_id>/auth-status")
    def auth_status(identity_id: str):
        package, item = scoped_identity(identity_id)
        context = service.auth.get(package.target.id, item.id)
        return jsonify({"identity_id": item.id, "auth": context.to_dict() if context else None})

    @app.post("/v1/identities/<identity_id>/prepare-auth")
    def prepare_auth(identity_id: str):
        body = _body(frozenset({"target", "mechanism"}))
        package = service.package(body.get("target", ""))
        identity = service.registry.get_identity(package.target.id, identity_id)
        if identity is None or package.status is not PackageStatus.TRACKED:
            raise LookupError("identity not found")
        if body.get("mechanism") != "MANUAL_LOGIN":
            raise ValueError("unsupported mechanism")
        context = service.auth.prepare(package.target.id, identity.id,
                                       mechanism=AuthMechanism.MANUAL_LOGIN)
        service.audit("auth_prepared", target_id=package.target.id, identity_id=identity.id)
        return jsonify({"identity_id": identity.id, "auth": context.to_dict()})

    @app.get("/v1/browser/sessions")
    def sessions():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse(maximum=service.config.browser.max_page_size)
        result = service.browser.list_sessions_for_target(package.target.id,
                                                          limit=page.limit, cursor=page.cursor)
        return jsonify({"items": [service.session_summary(item) for item in result.items],
                        "next_cursor": result.next_cursor})

    @app.post("/v1/browser/sessions")
    def create_session():
        body = _body(frozenset({"target", "identity_id", "anonymous"}))
        package = service.package(body.get("target", ""))
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("target is not active")
        anonymous = body.get("anonymous", False)
        identity_id = body.get("identity_id")
        if type(anonymous) is not bool or anonymous == bool(identity_id):
            raise ValueError("invalid session identity")
        session = service.browser.create(package.target.id, None if anonymous else identity_id)
        service.audit("browser_created", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(session)), 201

    def scoped_session(session_id: str):
        package = service.package(request.args.get("target", ""))
        session = service.browser.get(session_id)
        if session is None or session.target_id != package.target.id:
            raise LookupError("session not found")
        return package, session

    @app.get("/v1/browser/sessions/<session_id>")
    def session_detail(session_id: str):
        _, session = scoped_session(session_id)
        return jsonify(service.session_summary(session))

    @app.post("/v1/browser/sessions/<session_id>/start")
    def start_session(session_id: str):
        _body(frozenset())
        package, session = scoped_session(session_id)
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("target is not active")
        if session.identity_id and service.config.browser.display and not service._vnc_ready():
            return jsonify(error="vnc_not_ready"), 409
        service.audit("browser_start_requested", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        updated = service.browser.start(session.id, package=package)
        service.audit("browser_started", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(updated))

    @app.post("/v1/browser/sessions/<session_id>/login-complete")
    def login_complete(session_id: str):
        _body(frozenset())
        package, session = scoped_session(session_id)
        updated = service.browser.login_complete(session.id)
        service.audit("manual_login_completed", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        rule = service.verification_rule(package, session.identity_id)
        verified = service.browser.verify(updated.id, rule)
        service.audit("identity_verification_finished", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(verified))

    @app.post("/v1/browser/sessions/<session_id>/verify")
    def verify_session(session_id: str):
        _body(frozenset())
        package, session = scoped_session(session_id)
        rule = service.verification_rule(package, session.identity_id)
        verified = service.browser.verify(session.id, rule)
        service.audit("identity_verification_finished", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(verified))

    @app.post("/v1/browser/sessions/<session_id>/stop")
    def stop_session(session_id: str):
        _body(frozenset())
        package, session = scoped_session(session_id)
        updated = service.browser.stop(session.id)
        service.audit("browser_stopped", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(updated))

    @app.post("/v1/browser/sessions/<session_id>/reconcile")
    def reconcile_session(session_id: str):
        _body(frozenset())
        package, session = scoped_session(session_id)
        updated = service.browser.reconcile_stale(session.id)
        service.audit("browser_reconciled", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(updated))

    @app.get("/v1/traffic")
    def traffic():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse()
        allowed_filters = ("identity", "session", "method", "status", "source", "scope")
        filters = {key: request.args[key] for key in allowed_filters if key in request.args}
        result = service.traffic.list_filtered(package.target.id, limit=page.limit,
                                               cursor=page.cursor, **filters)
        return jsonify({"items": [item.to_dict() for item in result.items],
                        "next_cursor": result.next_cursor})

    @app.get("/v1/traffic/stats")
    def traffic_stats():
        package = service.package(request.args.get("target", ""))
        return jsonify(service.traffic.stats(package.target.id))

    @app.get("/v1/traffic/<exchange_id>")
    def traffic_detail(exchange_id: str):
        package = service.package(request.args.get("target", ""))
        item = service.traffic.get_exchange(exchange_id)
        if item is None or item.target_id != package.target.id:
            raise LookupError("exchange not found")
        return jsonify(item.to_dict())

    @app.get("/v1/burp/status")
    def burp_status():
        target = request.args.get("target")
        package = service.package(target) if target else None
        return jsonify(service.burp.status(package.target.id if package else None))

    @app.get("/v1/evidence/<evidence_id>")
    def evidence(evidence_id: str):
        package = service.package(request.args.get("target", ""))
        item = service.store.get_evidence(evidence_id)
        if item is None or item.target_ref != package.target.id:
            raise LookupError("evidence not found")
        return jsonify(item.to_reference())

    return app
