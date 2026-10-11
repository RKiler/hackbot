"""Burp deployment metadata and trusted listener-to-browser routing only."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
import re
import socket
import sqlite3

from .browser import BrowserError, BrowserProxyConfig, BrowserSession, BrowserSessionManager, BrowserStatus
from .config import BurpSettings
from .domain import new_entity_id, validate_entity_id
from .target_package import TargetPackage
from .traffic import TrafficStore


class BurpError(ValueError):
    """Value-free Burp integration failure."""


class BurpAvailability(StrEnum):
    BURP_NOT_INSTALLED = "BURP_NOT_INSTALLED"
    BURP_PRESENT_BUT_NOT_AUTOMATABLE = "BURP_PRESENT_BUT_NOT_AUTOMATABLE"
    BURP_AVAILABLE = "BURP_AVAILABLE"
    BURP_REQUIRES_OPERATOR_SETUP = "BURP_REQUIRES_OPERATOR_SETUP"


class CaptureStatus(StrEnum):
    BURP_UNAVAILABLE = "BURP_UNAVAILABLE"
    BURP_STOPPED = "BURP_STOPPED"
    BURP_RUNNING = "BURP_RUNNING"
    BRIDGE_CONNECTED = "BRIDGE_CONNECTED"
    BRIDGE_DISCONNECTED = "BRIDGE_DISCONNECTED"


_LISTENER_KEY = re.compile(r"[A-Za-z0-9.:[\]_-]{1,128}\Z")
_ACTIVE_BROWSER = frozenset({BrowserStatus.RUNNING, BrowserStatus.WAITING_LOGIN,
                             BrowserStatus.VERIFYING_IDENTITY, BrowserStatus.NEEDS_MANUAL_REVIEW,
                             BrowserStatus.REAUTH_REQUIRED, BrowserStatus.VALID})


@dataclass(frozen=True, slots=True)
class BurpListenerBinding:
    id: str
    target_id: str
    browser_session_id: str
    listener_key: str
    proxy_port: int
    state: str
    created_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "target_id": self.target_id,
                "browser_session_id": self.browser_session_id,
                "listener_key": self.listener_key, "proxy_port": self.proxy_port,
                "state": self.state, "created_at": self.created_at.isoformat()}


class BurpProxyProvider:
    """Local Burp process reference; listener identity is never inferred from cookies."""

    def __init__(self, settings: BurpSettings, traffic: TrafficStore,
                 browser: BrowserSessionManager | None = None) -> None:
        if not isinstance(settings, BurpSettings):
            raise BurpError("Invalid Burp configuration")
        self.settings = settings
        self.traffic = traffic
        self.browser = browser

    def availability(self) -> BurpAvailability:
        if self.settings.installation_jar is None or not self.settings.installation_jar.is_file():
            return BurpAvailability.BURP_NOT_INSTALLED
        if not self.settings.enabled or self.settings.bridge_secret_ref is None:
            return BurpAvailability.BURP_REQUIRES_OPERATOR_SETUP
        return BurpAvailability.BURP_PRESENT_BUT_NOT_AUTOMATABLE

    def _project_path(self, target_id: str) -> Path:
        validate_entity_id(target_id, "TARGET")
        return self.settings.project_root / target_id / "project.burp"

    def register_project(self, package: TargetPackage) -> Path:
        self.traffic._target_check(package)
        root = self.settings.project_root
        if root.is_symlink() or (root.exists() and not root.is_dir()):
            raise BurpError("Burp project root is unavailable")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        marker = root / ".bughunter-burp-projects"
        if not marker.exists():
            if any(root.iterdir()):
                raise BurpError("Burp project root is not BugHunter-owned")
            marker.touch(mode=0o600)
        if marker.is_symlink() or not marker.is_file():
            raise BurpError("Burp project marker is invalid")
        root.chmod(0o700)
        directory = root / package.target.id
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise BurpError("Burp target project directory is invalid")
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
        project = self._project_path(package.target.id)
        now = datetime.now(timezone.utc).isoformat()
        with self.traffic.evidence._connection() as connection:
            existing = connection.execute("SELECT package_id,project_path FROM burp_projects WHERE target_id=?",
                                          (package.target.id,)).fetchone()
            if existing is not None and (existing["package_id"] != package.id
                                         or existing["project_path"] != str(project)):
                raise BurpError("Burp target project metadata disagrees")
            connection.execute("""INSERT OR IGNORE INTO burp_projects
                (target_id,package_id,project_path,created_at,updated_at) VALUES (?,?,?,?,?)""",
                (package.target.id, package.id, str(project), now, now))
        return project

    def proxy_config(self, port: int) -> BrowserProxyConfig:
        if type(port) is not int or not self.settings.listener_start <= port <= self.settings.listener_end:
            raise BurpError("Burp listener port is outside configured range")
        return BrowserProxyConfig(enabled=True, proxy_url=f"http://127.0.0.1:{port}",
                                  reference=f"burp_{port}", capture_required=True,
                                  ca_reference="ref:burp_ca" if self.settings.ca_certificate else None,
                                  ca_certificate=self.settings.ca_certificate)

    def provision_session(self, package: TargetPackage, identity_id: str | None = None, *,
                          port: int | None = None, listener_key: str | None = None) -> tuple[BrowserSession, BurpListenerBinding]:
        if not self.settings.enabled or self.browser is None:
            raise BurpError("Burp session provisioning is unavailable")
        self.register_project(package)
        if port is None:
            with self.traffic.evidence._connection() as connection:
                occupied = {row[0] for row in connection.execute(
                    "SELECT proxy_port FROM burp_listener_bindings WHERE state='ACTIVE'")}
            port = next((candidate for candidate in range(self.settings.listener_start,
                        self.settings.listener_end + 1) if candidate not in occupied), None)
        if port is None:
            raise BurpError("No Burp listener port is available")
        proxy = self.proxy_config(port)
        key = f"127.0.0.1:{port}"
        if listener_key is not None and listener_key != key:
            raise BurpError("Burp listener must match its loopback proxy endpoint")
        session = self.browser.create(package.target.id, identity_id, proxy=proxy)
        now = datetime.now(timezone.utc)
        binding_id = new_entity_id("BURPBIND")
        try:
            with self.traffic.evidence._connection() as connection:
                connection.execute("""INSERT INTO burp_listener_bindings
                    (binding_id,target_id,browser_session_id,listener_key,proxy_port,state,created_at,updated_at)
                    VALUES (?,?,?,?,?,'ACTIVE',?,?)""",
                    (binding_id, package.target.id, session.id, key, port, now.isoformat(), now.isoformat()))
        except sqlite3.IntegrityError:
            self.browser.destroy(session.id, purge_profile=True)
            raise BurpError("Burp listener is already allocated") from None
        return session, BurpListenerBinding(binding_id, package.target.id, session.id, key, port, "ACTIVE", now)

    def binding_for_session(self, session_id: str) -> BurpListenerBinding | None:
        validate_entity_id(session_id, "BSESSION")
        with self.traffic.evidence._connection() as connection:
            row = connection.execute("SELECT * FROM burp_listener_bindings WHERE browser_session_id=?",
                                     (session_id,)).fetchone()
        return self._binding(row) if row else None

    def resolve_listener(self, target_id: str, listener_key: str) -> BurpListenerBinding:
        validate_entity_id(target_id, "TARGET")
        if not isinstance(listener_key, str) or not _LISTENER_KEY.fullmatch(listener_key):
            raise BurpError("Invalid Burp listener identifier")
        with self.traffic.evidence._connection() as connection:
            row = connection.execute("""SELECT * FROM burp_listener_bindings
                WHERE target_id=? AND listener_key=? AND state='ACTIVE' LIMIT 1""",
                (target_id, listener_key)).fetchone()
        if row is None or self.browser is None:
            raise BurpError("Unknown Burp listener")
        binding = self._binding(row)
        session = self.browser.get(binding.browser_session_id)
        if (session is None or session.target_id != target_id or session.status not in _ACTIVE_BROWSER
                or not session.proxy_capture_required or session.proxy_ref != f"burp_{binding.proxy_port}"
                or not self.browser.driver.is_running(session.id)):
            raise BurpError("Burp listener session is stale")
        return binding

    @staticmethod
    def _binding(row: sqlite3.Row) -> BurpListenerBinding:
        return BurpListenerBinding(row["binding_id"], row["target_id"], row["browser_session_id"],
                                   row["listener_key"], row["proxy_port"], row["state"],
                                   datetime.fromisoformat(row["created_at"]))

    def list_bindings(self, target_id: str, *, limit: int = 50) -> tuple[BurpListenerBinding, ...]:
        validate_entity_id(target_id, "TARGET")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise BurpError("Invalid Burp listener page limit")
        with self.traffic.evidence._connection() as connection:
            rows = connection.execute("""SELECT * FROM burp_listener_bindings WHERE target_id=?
                ORDER BY created_at DESC,binding_id DESC LIMIT ?""", (target_id, limit)).fetchall()
        return tuple(self._binding(row) for row in rows)

    def release(self, session_id: str) -> None:
        binding = self.binding_for_session(session_id)
        if binding is None or binding.state != "ACTIVE":
            return
        if self.browser is not None:
            session = self.browser.get(session_id)
            if session is not None and session.status in _ACTIVE_BROWSER and self.browser.driver.is_running(session_id):
                raise BurpError("Stop the browser before releasing its listener")
        with self.traffic.evidence._connection() as connection:
            connection.execute("""UPDATE burp_listener_bindings SET state='RELEASED',updated_at=?
                WHERE binding_id=? AND state='ACTIVE'""",
                (datetime.now(timezone.utc).isoformat(), binding.id))

    def heartbeat(self, target_id: str, version: str, dropped_events: int | None = None) -> None:
        validate_entity_id(target_id, "TARGET")
        if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", version):
            raise BurpError("Invalid bridge version")
        if dropped_events is not None and (type(dropped_events) is not int
                                           or not 0 <= dropped_events <= 2**63 - 1):
            raise BurpError("Invalid bridge drop count")
        now = datetime.now(timezone.utc).isoformat()
        with self.traffic.evidence._connection() as connection:
            connection.execute("""INSERT INTO burp_bridge_health(target_id,bridge_version,dropped_events,last_seen_at)
                VALUES (?,?,COALESCE(?,0),?) ON CONFLICT(target_id) DO UPDATE SET
                bridge_version=excluded.bridge_version,
                dropped_events=COALESCE(?,burp_bridge_health.dropped_events),
                last_seen_at=excluded.last_seen_at""",
                (target_id, version, dropped_events, now, dropped_events))

    def bridge_connected(self, target_id: str) -> bool:
        validate_entity_id(target_id, "TARGET")
        with self.traffic.evidence._connection() as connection:
            row = connection.execute("SELECT last_seen_at FROM burp_bridge_health WHERE target_id=?",
                                     (target_id,)).fetchone()
        return row is not None and datetime.fromisoformat(row["last_seen_at"]) >= datetime.now(timezone.utc) - timedelta(seconds=90)

    def listener_reachable(self, port: int) -> bool:
        if type(port) is not int or not self.settings.listener_start <= port <= self.settings.listener_end:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            return False

    def ready(self, session_id: str) -> bool:
        binding = self.binding_for_session(session_id)
        return bool(self.settings.enabled and binding is not None and binding.state == "ACTIVE"
                    and self.bridge_connected(binding.target_id) and self.listener_reachable(binding.proxy_port))

    def start_browser(self, session_id: str, *, package: TargetPackage | None = None) -> BrowserSession:
        if self.browser is None:
            raise BurpError("Browser manager is unavailable")
        binding = self.binding_for_session(session_id)
        if binding is None or binding.state != "ACTIVE":
            raise BurpError("Burp listener is unavailable")
        proxy = self.proxy_config(binding.proxy_port)
        return self.browser.start(session_id, proxy=proxy, package=package,
                                  proxy_health_check=lambda _: self.ready(session_id))

    def status(self, target_id: str | None = None) -> dict[str, object]:
        available = self.availability()
        connected = self.bridge_connected(target_id) if target_id is not None else False
        bindings = self.list_bindings(target_id) if target_id is not None else ()
        reachable = sum(self.listener_reachable(item.proxy_port) for item in bindings if item.state == "ACTIVE")
        captured = None
        last_capture_at = None
        if target_id is not None:
            with self.traffic.evidence._connection() as connection:
                captured = connection.execute(
                    "SELECT count(*) FROM burp_capture_index WHERE target_id=? AND exchange_id IS NOT NULL",
                    (target_id,),
                ).fetchone()[0]
                row = connection.execute("""SELECT observed_at FROM traffic_exchanges
                    WHERE target_id=? AND source='BURP'
                    ORDER BY observed_at DESC,exchange_id DESC LIMIT 1""",
                    (target_id,)).fetchone()
                last_capture_at = row["observed_at"] if row else None
                bridge_row = connection.execute("""SELECT dropped_events,last_seen_at
                    FROM burp_bridge_health WHERE target_id=?""", (target_id,)).fetchone()
                dropped_events = bridge_row["dropped_events"] if bridge_row else 0
                last_heartbeat_at = bridge_row["last_seen_at"] if bridge_row else None
        else:
            dropped_events = None
            last_heartbeat_at = None
        state = (CaptureStatus.BURP_UNAVAILABLE if available is BurpAvailability.BURP_NOT_INSTALLED
                 else CaptureStatus.BRIDGE_CONNECTED if connected and reachable
                 else CaptureStatus.BRIDGE_DISCONNECTED if connected or reachable
                 else CaptureStatus.BURP_STOPPED)
        return {"availability": available.value, "status": state.value,
                "bridge_connected": connected, "configured_listeners": len(bindings),
                "reachable_listeners": reachable, "target_id": target_id,
                "captured_exchanges": captured, "last_capture_at": last_capture_at,
                "dropped_events": dropped_events, "last_heartbeat_at": last_heartbeat_at}


class BurpExecutionProxyAdapter:
    """Optional executor route backed by a ready Phase 10 session listener."""

    def __init__(self, provider: BurpProxyProvider) -> None:
        self.provider = provider

    def route(self, action: object):
        from .executor import ProxyRoute
        session_id = getattr(action, "session_id", None)
        target_id = getattr(action, "target_id", None)
        if not isinstance(session_id, str) or not isinstance(target_id, str):
            return None
        binding = self.provider.binding_for_session(session_id)
        if (binding is None or binding.target_id != target_id or binding.state != "ACTIVE"
                or not self.provider.ready(session_id)):
            return None
        return ProxyRoute(f"http://127.0.0.1:{binding.proxy_port}",
                          self.provider.settings.ca_certificate)
