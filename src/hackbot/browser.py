"""Isolated browser sessions; target traffic is never initiated by this manager."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import os
from pathlib import Path
import re
import shutil
import sqlite3
from typing import Callable, Protocol
from urllib.parse import urlsplit

from .auth import AuthContextManager, AuthMechanism, AuthPreparation, AuthStatus
from .config import BrowserSettings
from .domain import new_entity_id, validate_entity_id
from .identity import IdentityStatus
from .identity_registry import IdentityRegistry
from .recon import Page
from .secrets import SecretValue
from .target_package import PackageStatus, TargetPackage
from .target_scope import ScopeResult


class BrowserError(ValueError):
    """Safe browser error; never includes browser or secret material."""


class BrowserStatus(StrEnum):
    CREATED = "CREATED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    WAITING_LOGIN = "WAITING_LOGIN"
    VERIFYING_IDENTITY = "VERIFYING_IDENTITY"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    REAUTH_REQUIRED = "REAUTH_REQUIRED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


class VerificationStatus(StrEnum):
    UNVERIFIED = "UNVERIFIED"
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNKNOWN = "UNKNOWN"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class BrowserProxyConfig:
    enabled: bool = False
    proxy_url: str | None = field(default=None, repr=False)
    ca_reference: str | None = field(default=None, repr=False)
    reference: str | None = None
    capture_required: bool = False
    ca_certificate: Path | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise BrowserError("Invalid proxy configuration")
        if self.enabled:
            if not isinstance(self.proxy_url, str):
                raise BrowserError("Proxy endpoint is required")
            try:
                parsed = urlsplit(self.proxy_url)
                valid = (parsed.scheme in {"http", "https", "socks5"} and parsed.hostname
                         and parsed.port and not parsed.username and not parsed.password
                         and not parsed.path and not parsed.query and not parsed.fragment)
            except ValueError:
                valid = False
            if not valid:
                raise BrowserError("Invalid proxy endpoint")
        elif self.proxy_url is not None:
            raise BrowserError("Disabled proxy cannot specify an endpoint")
        if self.reference is not None and not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", self.reference):
            raise BrowserError("Invalid proxy reference")
        if self.ca_reference is not None and not re.fullmatch(r"ref:[a-z][a-z0-9_-]{0,63}", self.ca_reference):
            raise BrowserError("Invalid CA reference")
        if type(self.capture_required) is not bool or (self.capture_required and not self.enabled):
            raise BrowserError("Invalid capture-required proxy configuration")
        if self.ca_certificate is not None and (not isinstance(self.ca_certificate, Path)
                or not self.ca_certificate.is_absolute() or ".." in self.ca_certificate.parts
                or not self.enabled):
            raise BrowserError("Invalid profile CA certificate reference")


@dataclass(frozen=True, slots=True)
class BrowserSession:
    id: str
    target_id: str
    identity_id: str | None
    auth_context_id: str | None
    driver: str
    profile_ref: str
    status: BrowserStatus
    verification_status: VerificationStatus
    proxy_enabled: bool
    proxy_ref: str | None
    proxy_capture_required: bool
    vnc_ref: str | None
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    last_verified_at: datetime | None = None
    last_used_at: datetime | None = None

    def __post_init__(self) -> None:
        validate_entity_id(self.id, "BSESSION")
        validate_entity_id(self.target_id, "TARGET")
        if (self.identity_id is None) != (self.auth_context_id is None):
            raise BrowserError("Identity and AuthContext must be linked together")
        if self.identity_id is not None:
            validate_entity_id(self.identity_id, "IDENTITY")
            validate_entity_id(self.auth_context_id, "AUTHCTX")
        if not isinstance(self.driver, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,31}", self.driver) or not isinstance(self.status, BrowserStatus):
            raise BrowserError("Invalid browser driver or status")
        if not isinstance(self.verification_status, VerificationStatus):
            raise BrowserError("Invalid verification status")
        if (self.status is BrowserStatus.VALID) != (self.verification_status is VerificationStatus.MATCH):
            raise BrowserError("Verified browser status requires an identity match")
        if self.identity_id is None and (self.status in {BrowserStatus.VALID, BrowserStatus.WAITING_LOGIN}
                                         or self.verification_status is VerificationStatus.MATCH):
            raise BrowserError("Anonymous browser cannot be authenticated")
        if not re.fullmatch(r"(?:TARGET-[0-9a-f]{32}/)?(?:IDENTITY-[0-9a-f]{32}|anonymous)/BSESSION-[0-9a-f]{32}", self.profile_ref):
            raise BrowserError("Invalid profile reference")
        if self.profile_ref != f"{self.target_id}/{self.identity_id or 'anonymous'}/{self.id}":
            raise BrowserError("Profile reference disagrees with session identity")
        for value in (self.created_at, self.updated_at, self.expires_at, self.last_verified_at, self.last_used_at):
            if value is not None and (not isinstance(value, datetime) or value.tzinfo is None):
                raise BrowserError("Browser timestamps must be timezone-aware")
        if self.updated_at < self.created_at:
            raise BrowserError("Invalid browser chronology")
        if type(self.proxy_capture_required) is not bool or (self.proxy_capture_required and not self.proxy_enabled):
            raise BrowserError("Invalid browser capture requirement")

    @property
    def anonymous(self) -> bool:
        return self.identity_id is None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id, "target_id": self.target_id, "identity_id": self.identity_id,
            "auth_context_id": self.auth_context_id, "driver": self.driver,
            "profile_ref": self.profile_ref, "anonymous": self.anonymous,
            "status": self.status.value, "verification_status": self.verification_status.value,
            "proxy_enabled": self.proxy_enabled, "proxy_ref": self.proxy_ref,
            "proxy_capture_required": self.proxy_capture_required,
            "vnc_ref": self.vnc_ref, "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_verified_at": self.last_verified_at.isoformat() if self.last_verified_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }


@dataclass(frozen=True, slots=True)
class IdentityVerificationRule:
    target_id: str
    identity_id: str
    user_id_selector: str | None = None
    email_selector: str | None = None
    tenant_selector: str | None = None
    expected_user_id: str | None = field(default=None, repr=False)
    expected_email: str | None = field(default=None, repr=False)
    expected_tenant_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        validate_entity_id(self.target_id, "TARGET")
        validate_entity_id(self.identity_id, "IDENTITY")
        if not ((self.expected_user_id and self.user_id_selector) or (self.expected_email and self.email_selector)):
            raise BrowserError("Verification requires an expected account identifier and selector")
        if bool(self.expected_user_id) != bool(self.user_id_selector) or bool(self.expected_email) != bool(self.email_selector):
            raise BrowserError("Identity expectations and selectors must be paired")
        if bool(self.expected_tenant_id) != bool(self.tenant_selector):
            raise BrowserError("Tenant expectation and selector must be paired")
        for selector in (self.user_id_selector, self.email_selector, self.tenant_selector):
            if selector is not None and (not isinstance(selector, str) or not 1 <= len(selector) <= 256
                                         or any(ord(char) < 32 for char in selector)):
                raise BrowserError("Invalid identity selector")


@dataclass(frozen=True, slots=True)
class IdentityObservation:
    user_id: str | None = field(default=None, repr=False)
    email: str | None = field(default=None, repr=False)
    tenant_id: str | None = field(default=None, repr=False)


class SessionVerifier(Protocol):
    def verify(self, rule: IdentityVerificationRule, observation: IdentityObservation) -> VerificationStatus: ...


class ExactSessionVerifier:
    def verify(self, rule: IdentityVerificationRule, observation: IdentityObservation) -> VerificationStatus:
        checks = []
        if rule.expected_user_id is not None:
            checks.append((rule.expected_user_id, observation.user_id))
        if rule.expected_email is not None:
            checks.append((rule.expected_email.casefold(), observation.email.casefold() if observation.email else None))
        if rule.expected_tenant_id is not None:
            checks.append((rule.expected_tenant_id, observation.tenant_id))
        if any(actual is None for _, actual in checks):
            return VerificationStatus.UNKNOWN
        return VerificationStatus.MATCH if all(expected == actual for expected, actual in checks) else VerificationStatus.MISMATCH


class BrowserDriver(Protocol):
    name: str
    def start(self, session_id: str, profile: Path, *, display: str | None,
              proxy: BrowserProxyConfig) -> None: ...
    def stop(self, session_id: str) -> None: ...
    def is_running(self, session_id: str) -> bool: ...
    def apply_imported_session(self, session_id: str, material: SecretValue,
                               allowed_url: Callable[[str], bool]) -> None: ...
    def observe_identity(self, session_id: str, rule: IdentityVerificationRule) -> IdentityObservation: ...


class ProfileStore:
    _MARKER = ".hackbot-browser-profiles"

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
            raise BrowserError("Profile root must be absolute")
        if any(part.is_symlink() for part in (root, *root.parents)):
            raise BrowserError("Profile root may not traverse a symlink")
        self.root = root

    def path(self, session: BrowserSession, *, create: bool = False) -> Path:
        pieces = (session.target_id, session.identity_id or "anonymous", session.id)
        current = self.root
        if create:
            if self.root.exists() and (self.root.is_symlink() or not self.root.is_dir()):
                raise BrowserError("Unsafe browser profile root")
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            marker = self.root / self._MARKER
            if marker.is_symlink() or (marker.exists() and
                                      (not marker.is_file() or marker.stat().st_size > 64
                                       or marker.read_text() != "bughunter-profiles-v1\n")):
                raise BrowserError("Browser profile root is not BugHunter-owned")
            if not marker.exists():
                if any(self.root.iterdir()):
                    raise BrowserError("Browser profile root is not BugHunter-owned")
                try:
                    handle = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(handle, "w") as output:
                        output.write("bughunter-profiles-v1\n")
                except OSError:
                    raise BrowserError("Cannot initialize browser profile root") from None
        elif self.root.exists() and (self.root.is_symlink() or (self.root / self._MARKER).is_symlink()
                                      or not (self.root / self._MARKER).is_file()):
            raise BrowserError("Browser profile root is not BugHunter-owned")
        for part in (None, *pieces):
            if part is not None:
                current = current / part
                if create:
                    current.mkdir(mode=0o700, exist_ok=True)
            if current.is_symlink() or (current.exists() and not current.is_dir()):
                raise BrowserError("Unsafe browser profile path")
            if create:
                os.chmod(current, 0o700)
        return current

    def delete(self, session: BrowserSession) -> None:
        path = self.path(session)
        if path.exists():
            shutil.rmtree(path)


@dataclass(frozen=True, slots=True)
class SessionContext:
    browser_session_id: str
    target_id: str
    identity_id: str | None
    auth_context_id: str | None
    browser_status: BrowserStatus
    verification_status: VerificationStatus
    browser_available: bool
    authentication_status: str
    proxy_enabled: bool
    proxy_capture_required: bool
    vnc_login_available: bool
    last_verified_at: datetime | None
    declared_tenant_ids: tuple[str, ...] = ()
    declared_role_ids: tuple[str, ...] = ()
    declared_memberships_complete: bool = True

    def to_dict(self) -> dict[str, object]:
        return {"browser_session_id": self.browser_session_id, "target_id": self.target_id,
                "identity_id": self.identity_id, "auth_context_id": self.auth_context_id,
                "browser_status": self.browser_status.value,
                "verification_status": self.verification_status.value,
                "browser_available": self.browser_available,
                "authentication_status": self.authentication_status,
                "proxy_enabled": self.proxy_enabled,
                "proxy_capture_required": self.proxy_capture_required,
                "vnc_login_available": self.vnc_login_available,
                "last_verified_at": self.last_verified_at.isoformat() if self.last_verified_at else None,
                "declared_tenant_ids": list(self.declared_tenant_ids),
                "declared_role_ids": list(self.declared_role_ids),
                "declared_memberships_complete": self.declared_memberships_complete}


def _row(row: sqlite3.Row) -> BrowserSession:
    def dt(key: str) -> datetime | None:
        return datetime.fromisoformat(row[key]) if row[key] else None
    return BrowserSession(
        id=row["session_id"], target_id=row["target_id"], identity_id=row["identity_id"],
        auth_context_id=row["auth_context_id"], driver=row["driver"], profile_ref=row["profile_ref"],
        status=BrowserStatus(row["status"]), verification_status=VerificationStatus(row["verification_status"]),
        proxy_enabled=bool(row["proxy_enabled"]), proxy_ref=row["proxy_ref"],
        proxy_capture_required=bool(row["proxy_capture_required"]), vnc_ref=row["vnc_ref"],
        created_at=dt("created_at"), updated_at=dt("updated_at"), expires_at=dt("expires_at"),
        last_verified_at=dt("last_verified_at"), last_used_at=dt("last_used_at"),
    )


class BrowserSessionManager:
    """Local metadata orchestration. Driver is the only browser/secret execution boundary."""

    def __init__(self, registry: IdentityRegistry, auth: AuthContextManager,
                 driver: BrowserDriver, settings: BrowserSettings,
                 *, verifier: SessionVerifier | None = None) -> None:
        self.registry = registry
        self.auth = auth
        self.driver = driver
        self.settings = settings
        self.profiles = ProfileStore(settings.profile_root)
        self.verifier = verifier or ExactSessionVerifier()
        if not isinstance(driver.name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,31}", driver.name):
            raise BrowserError("Invalid browser driver name")

    def get(self, session_id: str) -> BrowserSession | None:
        validate_entity_id(session_id, "BSESSION")
        with self.registry.store._connection() as connection:
            row = connection.execute("SELECT * FROM browser_sessions WHERE session_id=?", (session_id,)).fetchone()
        return _row(row) if row else None

    def _required(self, session_id: str) -> BrowserSession:
        session = self.get(session_id)
        if session is None:
            raise BrowserError("Browser session not found")
        return session

    def create(self, target_id: str, identity_id: str | None = None,
               *, proxy: BrowserProxyConfig = BrowserProxyConfig()) -> BrowserSession:
        validate_entity_id(target_id, "TARGET")
        if not isinstance(proxy, BrowserProxyConfig):
            raise BrowserError("Invalid proxy configuration")
        context = None
        if identity_id is not None:
            validate_entity_id(identity_id, "IDENTITY")
            identity = self.registry.get_identity(target_id, identity_id)
            if identity is None or identity.status is not IdentityStatus.ACTIVE:
                raise BrowserError("Active target identity is required")
            context = self.auth.get(target_id, identity_id)
            if context is None or context.status in {AuthStatus.INVALID, AuthStatus.LOCKED, AuthStatus.EXPIRED}:
                raise BrowserError("Usable prepared AuthContext is required")
            if context.mechanism not in {
                AuthMechanism.MANUAL_LOGIN, AuthMechanism.IMPORTED_SESSION,
                AuthMechanism.COOKIE, AuthMechanism.BEARER, AuthMechanism.HEADER,
            }:
                raise BrowserError("Browser authentication mechanism is unsupported")
        now = datetime.now(timezone.utc)
        session_id = new_entity_id("BSESSION")
        session = BrowserSession(
            id=session_id, target_id=target_id, identity_id=identity_id,
            auth_context_id=context.id if context else None, driver=self.driver.name,
            profile_ref=f"{target_id}/{identity_id or 'anonymous'}/{session_id}",
            status=BrowserStatus.CREATED, verification_status=VerificationStatus.UNVERIFIED,
            proxy_enabled=proxy.enabled, proxy_ref=proxy.reference,
            proxy_capture_required=proxy.capture_required,
            vnc_ref=self.settings.vnc_url if identity_id is not None else None,
            created_at=now, updated_at=now,
        )
        with self.registry.store._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.registry._require_target(connection, target_id)
            if identity_id is not None:
                identity_row = connection.execute("""SELECT status FROM registry_identities
                    WHERE target_id=? AND identity_id=?""", (target_id, identity_id)).fetchone()
                context_row = connection.execute("""SELECT auth_context_id,status,mechanism FROM auth_contexts
                    WHERE target_id=? AND identity_id=?""", (target_id, identity_id)).fetchone()
                if (identity_row is None or identity_row["status"] != IdentityStatus.ACTIVE.value
                        or context_row is None or context_row["auth_context_id"] != context.id
                        or context_row["status"] in {AuthStatus.INVALID.value, AuthStatus.LOCKED.value,
                                                      AuthStatus.EXPIRED.value}
                        or context_row["mechanism"] != context.mechanism.value):
                    raise BrowserError("Identity or AuthContext changed during session creation")
            active = connection.execute("""SELECT count(*) FROM browser_sessions
                WHERE target_id=? AND status NOT IN ('STOPPED','FAILED','EXPIRED')""", (target_id,)).fetchone()[0]
            if active >= self.settings.max_sessions:
                raise BrowserError("Browser session limit reached")
            connection.execute("""INSERT INTO browser_sessions
                (session_id,target_id,identity_id,auth_context_id,driver,profile_ref,status,
                 verification_status,proxy_enabled,proxy_ref,proxy_capture_required,vnc_ref,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (session.id, target_id, identity_id, session.auth_context_id, session.driver,
                 session.profile_ref, session.status.value, session.verification_status.value,
                 int(session.proxy_enabled), session.proxy_ref, int(session.proxy_capture_required), session.vnc_ref,
                 now.isoformat(), now.isoformat()))
            self._event(connection, session.id, "browser_created", now)
        try:
            self.profiles.path(session, create=True)
        except Exception:
            self._transition(session, BrowserStatus.FAILED, "browser_failed")
            raise
        return session

    @staticmethod
    def _event(connection: sqlite3.Connection, session_id: str, event: str, at: datetime) -> None:
        connection.execute("""INSERT INTO browser_session_events(session_id,event_type,occurred_at)
            VALUES (?,?,?)""", (session_id, event, at.isoformat()))

    def _transition(self, session: BrowserSession, status: BrowserStatus, event: str | tuple[str, ...],
                    verification: VerificationStatus | None = None,
                    *, verified_at: datetime | None = None) -> BrowserSession:
        now = max(datetime.now(timezone.utc), session.updated_at + timedelta(microseconds=1))
        with self.registry.store._connection() as connection:
            updated = connection.execute("""UPDATE browser_sessions SET status=?,verification_status=?,
                updated_at=?,last_verified_at=COALESCE(?,last_verified_at)
                WHERE session_id=? AND updated_at=?""",
                (status.value, (verification or session.verification_status).value, now.isoformat(),
                 verified_at.isoformat() if verified_at else None, session.id,
                 session.updated_at.isoformat())).rowcount
            if updated != 1:
                raise BrowserError("Browser session changed concurrently")
            for item in (event,) if isinstance(event, str) else event:
                self._event(connection, session.id, item, now)
        result = self.get(session.id)
        assert result is not None
        return result

    def start(self, session_id: str, *, proxy: BrowserProxyConfig = BrowserProxyConfig(),
              package: TargetPackage | None = None,
              proxy_health_check: Callable[[BrowserProxyConfig], bool] | None = None) -> BrowserSession:
        session = self._required(session_id)
        if session.driver != self.driver.name:
            raise BrowserError("Browser driver does not match stored session")
        if session.status not in {BrowserStatus.CREATED, BrowserStatus.STOPPED, BrowserStatus.FAILED,
                                  BrowserStatus.REAUTH_REQUIRED, BrowserStatus.EXPIRED}:
            raise BrowserError("Browser session cannot start from this state")
        if (session.proxy_enabled != proxy.enabled or session.proxy_capture_required != proxy.capture_required
                or (session.proxy_ref and proxy.reference != session.proxy_ref)):
            raise BrowserError("Configured proxy does not match session")
        if session.proxy_capture_required:
            if proxy_health_check is None:
                raise BrowserError("Capture-required proxy has no health check")
            try:
                healthy = proxy_health_check(proxy)
            except Exception:
                healthy = False
            if healthy is not True:
                raise BrowserError("Capture-required proxy is unavailable")
        context = self.auth.get(session.target_id, session.identity_id) if session.identity_id else None
        if session.identity_id is not None and (context is None or context.id != session.auth_context_id):
            raise BrowserError("Browser AuthContext is no longer current")
        if session.identity_id is not None:
            identity = self.registry.get_identity(session.target_id, session.identity_id)
            if identity is None or identity.status is not IdentityStatus.ACTIVE:
                raise BrowserError("Active target identity is required")
        if context is not None and context.status in {AuthStatus.INVALID, AuthStatus.LOCKED}:
            raise BrowserError("AuthContext cannot start a browser")
        session = self._transition(session, BrowserStatus.STARTING, "browser_starting",
                                   VerificationStatus.UNVERIFIED)
        try:
            self.driver.start(session.id, self.profiles.path(session, create=True),
                              display=self.settings.display, proxy=proxy)
            if context is None:
                return self._transition(session, BrowserStatus.RUNNING, "browser_started")
            if context.mechanism in {
                AuthMechanism.MANUAL_LOGIN, AuthMechanism.COOKIE,
                AuthMechanism.BEARER, AuthMechanism.HEADER,
            }:
                return self._transition(session, BrowserStatus.WAITING_LOGIN, "manual_login_requested")
            if context.mechanism is AuthMechanism.IMPORTED_SESSION:
                if context.preparation is not AuthPreparation.IMPORTED_SESSION_REFERENCE_AVAILABLE or not context.secret_ref:
                    raise BrowserError("Imported session material is unavailable")
                if (package is None or package.target.id != session.target_id
                        or package.status is not PackageStatus.TRACKED):
                    raise BrowserError("Import requires an active matching TargetPackage")
                material = self.auth.secrets.get(context.secret_ref)
                self.driver.apply_imported_session(
                    session.id, material,
                    lambda url: package.scope.evaluate_url(url).result is ScopeResult.IN_SCOPE,
                )
                return self._transition(session, BrowserStatus.VERIFYING_IDENTITY,
                                        "identity_verification_started")
            raise BrowserError("Unsupported browser authentication mechanism")
        except Exception:
            try:
                self.driver.stop(session.id)
            finally:
                self._transition(session, BrowserStatus.FAILED, "browser_failed")
            raise BrowserError("Browser launch or import failed") from None

    def login_complete(self, session_id: str) -> BrowserSession:
        session = self._required(session_id)
        if session.status is not BrowserStatus.WAITING_LOGIN or not self.driver.is_running(session_id):
            raise BrowserError("Manual login is not waiting in a running browser")
        return self._transition(session, BrowserStatus.VERIFYING_IDENTITY,
                                ("login_completed", "identity_verification_started"))

    def verify(self, session_id: str, rule: IdentityVerificationRule | None) -> BrowserSession:
        session = self._required(session_id)
        if session.status not in {BrowserStatus.VERIFYING_IDENTITY, BrowserStatus.NEEDS_MANUAL_REVIEW}:
            raise BrowserError("Browser session is not awaiting identity verification")
        if not self.driver.is_running(session_id):
            raise BrowserError("Browser is not running")
        if session.expires_at is not None and session.expires_at <= datetime.now(timezone.utc):
            return self.expire(session_id)
        if rule is None:
            return self._transition(session, BrowserStatus.NEEDS_MANUAL_REVIEW,
                                    "identity_verification_unknown", VerificationStatus.UNKNOWN)
        if session.identity_id != rule.identity_id or session.target_id != rule.target_id:
            raise BrowserError("Verification rule belongs to another identity")
        identity = self.registry.get_identity(session.target_id, session.identity_id)
        if identity is None or identity.status is not IdentityStatus.ACTIVE:
            raise BrowserError("Active target identity is required")
        try:
            observation = self.driver.observe_identity(session_id, rule)
            verdict = self.verifier.verify(rule, observation)
        except Exception:
            verdict = VerificationStatus.UNKNOWN
        if verdict is VerificationStatus.MATCH:
            context = self.auth.get(session.target_id, session.identity_id)
            if context is None or context.id != session.auth_context_id:
                raise BrowserError("AuthContext changed during verification")
            now = max(datetime.now(timezone.utc), session.updated_at + timedelta(microseconds=1),
                      context.updated_at + timedelta(microseconds=1))
            with self.registry.store._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                identity_row = connection.execute("""SELECT status FROM registry_identities
                    WHERE target_id=? AND identity_id=?""",
                    (session.target_id, session.identity_id)).fetchone()
                if identity_row is None or identity_row["status"] != IdentityStatus.ACTIVE.value:
                    raise BrowserError("Identity changed during session verification")
                self.auth._mark_verified_in_transaction(connection, context, session.id, now)
                updated = connection.execute("""UPDATE browser_sessions SET status='VALID',
                    verification_status='MATCH',updated_at=?,last_verified_at=?
                    WHERE session_id=? AND updated_at=?""",
                    (now.isoformat(), now.isoformat(), session.id, session.updated_at.isoformat())).rowcount
                if updated != 1:
                    raise BrowserError("Browser session changed during verification")
                self._event(connection, session.id, "identity_verified", now)
            return self._required(session.id)
        if verdict is VerificationStatus.MISMATCH:
            result = self._transition(session, BrowserStatus.REAUTH_REQUIRED,
                                      "identity_verification_failed", verdict)
            context = self.auth.get(session.target_id, session.identity_id)
            if context is not None and (context.status is not AuthStatus.VALID
                                        or context.browser_session_ref == session.id):
                self.auth.mark_reauth_required(session.target_id, session.identity_id)
            return result
        return self._transition(session, BrowserStatus.NEEDS_MANUAL_REVIEW,
                                "identity_verification_unknown", VerificationStatus.UNKNOWN)

    def stop(self, session_id: str) -> BrowserSession:
        session = self._required(session_id)
        if session.status is BrowserStatus.STOPPED:
            return session
        if session.status in {BrowserStatus.STARTING, BrowserStatus.RUNNING, BrowserStatus.WAITING_LOGIN,
                              BrowserStatus.VERIFYING_IDENTITY, BrowserStatus.NEEDS_MANUAL_REVIEW,
                              BrowserStatus.VALID} and not self.driver.is_running(session.id):
            raise BrowserError("Browser process is not controlled by this manager instance")
        try:
            self.driver.stop(session.id)
        except Exception:
            raise BrowserError("Browser stop failed") from None
        result = self._transition(session, BrowserStatus.STOPPED, "browser_stopped",
                                  VerificationStatus.UNVERIFIED)
        if session.identity_id is not None:
            context = self.auth.get(session.target_id, session.identity_id)
            if context is not None and context.status is AuthStatus.VALID and context.browser_session_ref == session.id:
                self.auth.mark_reauth_required(session.target_id, session.identity_id)
        return result

    def restart(self, session_id: str, *, proxy: BrowserProxyConfig = BrowserProxyConfig(),
                package: TargetPackage | None = None,
                proxy_health_check: Callable[[BrowserProxyConfig], bool] | None = None) -> BrowserSession:
        self.stop(session_id)
        return self.start(session_id, proxy=proxy, package=package, proxy_health_check=proxy_health_check)

    def expire(self, session_id: str) -> BrowserSession:
        session = self._required(session_id)
        result = self._transition(session, BrowserStatus.EXPIRED, "session_expired",
                                  VerificationStatus.EXPIRED)
        if session.identity_id is not None:
            context = self.auth.get(session.target_id, session.identity_id)
            if (context is not None and context.status not in {AuthStatus.INVALID, AuthStatus.LOCKED}
                    and (context.status is not AuthStatus.VALID or context.browser_session_ref == session.id)):
                self.auth.expire(session.target_id, session.identity_id)
        return result

    def set_expiry(self, session_id: str, expires_at: datetime) -> BrowserSession:
        session = self._required(session_id)
        if not isinstance(expires_at, datetime) or expires_at.tzinfo is None:
            raise BrowserError("Expiry must be timezone-aware")
        now = max(datetime.now(timezone.utc), session.updated_at + timedelta(microseconds=1))
        with self.registry.store._connection() as connection:
            updated = connection.execute("""UPDATE browser_sessions SET expires_at=?,updated_at=?
                WHERE session_id=? AND updated_at=?""",
                (expires_at.isoformat(), now.isoformat(), session.id, session.updated_at.isoformat())).rowcount
            if updated != 1:
                raise BrowserError("Browser session changed concurrently")
            self._event(connection, session.id, "expiry_recorded", now)
        if expires_at <= now:
            return self.expire(session_id)
        return self._required(session_id)

    def destroy(self, session_id: str, *, purge_profile: bool = False) -> None:
        session = self.stop(session_id)
        if purge_profile or session.anonymous:
            self.profiles.delete(session)
        with self.registry.store._connection() as connection:
            connection.execute("DELETE FROM browser_session_events WHERE session_id=?", (session_id,))
            connection.execute("DELETE FROM browser_sessions WHERE session_id=?", (session_id,))

    def reconcile_stale(self, session_id: str) -> BrowserSession:
        """Fail closed after an unobserved browser exit or manager process restart."""
        session = self._required(session_id)
        if self.driver.is_running(session_id):
            return session
        if session.status not in {BrowserStatus.STARTING, BrowserStatus.RUNNING,
                                  BrowserStatus.WAITING_LOGIN, BrowserStatus.VERIFYING_IDENTITY,
                                  BrowserStatus.NEEDS_MANUAL_REVIEW, BrowserStatus.VALID}:
            return session
        result = self._transition(session, BrowserStatus.REAUTH_REQUIRED,
                                  "browser_process_unavailable", VerificationStatus.UNVERIFIED)
        if session.identity_id is not None:
            context = self.auth.get(session.target_id, session.identity_id)
            if context is not None and context.browser_session_ref == session.id:
                self.auth.mark_reauth_required(session.target_id, session.identity_id)
        return result

    def list_sessions_for_target(self, target_id: str, *, limit: int = 20,
                                 cursor: str | None = None) -> Page[BrowserSession]:
        validate_entity_id(target_id, "TARGET")
        if type(limit) is not int or not 1 <= limit <= self.settings.max_page_size:
            raise BrowserError("Invalid browser page size")
        with self.registry.store._connection() as connection:
            if cursor is not None:
                validate_entity_id(cursor, "BSESSION")
                marker = connection.execute("""SELECT created_at FROM browser_sessions
                    WHERE target_id=? AND session_id=?""", (target_id, cursor)).fetchone()
                if marker is None:
                    raise BrowserError("Invalid browser cursor")
                rows = connection.execute("""SELECT * FROM browser_sessions WHERE target_id=?
                    AND (created_at < ? OR (created_at = ? AND session_id < ?))
                    ORDER BY created_at DESC,session_id DESC LIMIT ?""",
                    (target_id, marker["created_at"], marker["created_at"], cursor, limit + 1)).fetchall()
            else:
                rows = connection.execute("""SELECT * FROM browser_sessions WHERE target_id=?
                    ORDER BY created_at DESC,session_id DESC LIMIT ?""", (target_id, limit + 1)).fetchall()
        return Page(tuple(_row(row) for row in rows[:limit]), rows[limit - 1]["session_id"] if len(rows) > limit else None)

    def get_session_for_identity(self, target_id: str, identity_id: str) -> BrowserSession | None:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(identity_id, "IDENTITY")
        with self.registry.store._connection() as connection:
            row = connection.execute("""SELECT * FROM browser_sessions WHERE target_id=? AND identity_id=?
                ORDER BY created_at DESC,session_id DESC LIMIT 1""", (target_id, identity_id)).fetchone()
        return _row(row) if row else None

    def get_active_session(self, target_id: str, identity_id: str) -> BrowserSession | None:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(identity_id, "IDENTITY")
        with self.registry.store._connection() as connection:
            row = connection.execute("""SELECT * FROM browser_sessions WHERE target_id=? AND identity_id=?
                AND status='VALID' ORDER BY created_at DESC,session_id DESC LIMIT 1""",
                (target_id, identity_id)).fetchone()
        session = _row(row) if row else None
        if session is None or not self.driver.is_running(session.id):
            return None
        if session.expires_at is not None and session.expires_at <= datetime.now(timezone.utc):
            return None
        context = self.auth.get(target_id, identity_id)
        if context is None or context.browser_session_ref != session.id or context.status is not AuthStatus.VALID:
            return None
        identity = self.registry.get_identity(target_id, identity_id)
        if identity is None or identity.status is not IdentityStatus.ACTIVE:
            return None
        return session

    def session_context(self, session_id: str) -> SessionContext:
        session = self._required(session_id)
        available = self.driver.is_running(session.id)
        valid = (session.identity_id is not None and session.status is BrowserStatus.VALID
                 and self.get_active_session(session.target_id, session.identity_id) == session)
        memberships = self.registry.list_memberships(session.identity_id, limit=20) if session.identity_id else None
        tenant_ids = tuple(item.tenant_id for item in memberships.items) if memberships else ()
        role_ids = tuple(sorted({role for item in memberships.items for role in item.role_ids})) if memberships else ()
        return SessionContext(
            browser_session_id=session.id, target_id=session.target_id,
            identity_id=session.identity_id, auth_context_id=session.auth_context_id,
            browser_status=session.status, verification_status=session.verification_status,
            browser_available=available,
            authentication_status=("ANONYMOUS" if session.anonymous else "VALID" if valid
                                   else "EXPIRED" if session.status is BrowserStatus.EXPIRED
                                   else "REAUTH_REQUIRED" if session.status is BrowserStatus.REAUTH_REQUIRED
                                   else "UNVERIFIED"),
            proxy_enabled=session.proxy_enabled,
            proxy_capture_required=session.proxy_capture_required,
            vnc_login_available=bool(session.vnc_ref and available and session.status is BrowserStatus.WAITING_LOGIN),
            last_verified_at=session.last_verified_at,
            declared_tenant_ids=tenant_ids, declared_role_ids=role_ids,
            declared_memberships_complete=memberships is None or memberships.next_cursor is None,
        )
