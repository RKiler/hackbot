"""Local authentication metadata. No login, session capture, or target traffic."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import sqlite3

from .domain import new_entity_id, validate_entity_id
from .identity import AccountSource, IdentityStatus, validate_secret_ref
from .identity_registry import IdentityRegistry
from .secrets import PROVIDER_LABELS, SecretKind, SecretMetadata, SecretProvider, SecretUnavailable


class AuthMechanism(StrEnum):
    USERNAME_PASSWORD = "USERNAME_PASSWORD"
    COOKIE = "COOKIE"
    BEARER = "BEARER"
    HEADER = "HEADER"
    LOGIN_FILE = "LOGIN_FILE"
    MANUAL_LOGIN = "MANUAL_LOGIN"
    IMPORTED_SESSION = "IMPORTED_SESSION"
    UNKNOWN = "UNKNOWN"


class AuthStatus(StrEnum):
    UNINITIALIZED = "UNINITIALIZED"
    READY = "READY"
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    REAUTH_REQUIRED = "REAUTH_REQUIRED"
    INVALID = "INVALID"
    LOCKED = "LOCKED"
    UNKNOWN = "UNKNOWN"


class AuthPreparation(StrEnum):
    READY = "READY"
    MANUAL_LOGIN_REQUIRED = "MANUAL_LOGIN_REQUIRED"
    IMPORTED_SESSION_REFERENCE_AVAILABLE = "IMPORTED_SESSION_REFERENCE_AVAILABLE"
    MISSING_SECRET = "MISSING_SECRET"
    DISABLED = "DISABLED"
    UNSUPPORTED_PROVIDER = "UNSUPPORTED_PROVIDER"
    UNKNOWN = "UNKNOWN"


_KIND_TO_MECHANISM = {
    SecretKind.PASSWORD: AuthMechanism.USERNAME_PASSWORD,
    SecretKind.COOKIE: AuthMechanism.COOKIE,
    SecretKind.BEARER_TOKEN: AuthMechanism.BEARER,
    SecretKind.API_TOKEN: AuthMechanism.HEADER,
    SecretKind.HEADER_SET: AuthMechanism.HEADER,
    SecretKind.LOGIN_DESCRIPTOR: AuthMechanism.MANUAL_LOGIN,
    SecretKind.SESSION_IMPORT_REFERENCE: AuthMechanism.IMPORTED_SESSION,
}


def _timestamp(value: datetime | None) -> None:
    if value is not None and (not isinstance(value, datetime) or value.tzinfo is None):
        raise ValueError("AuthContext timestamps must be timezone-aware")


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthContext:
    target_id: str
    identity_id: str
    mechanism: AuthMechanism
    status: AuthStatus
    preparation: AuthPreparation = AuthPreparation.UNKNOWN
    secret_ref: str | None = field(default=None, repr=False)
    provider: str | None = None
    browser_session_ref: str | None = field(default=None, repr=False)
    csrf_metadata_ref: str | None = field(default=None, repr=False)
    evidence_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    id: str = field(default_factory=lambda: new_entity_id("AUTHCTX"))

    def __post_init__(self) -> None:
        for value, prefix in ((self.id, "AUTHCTX"), (self.target_id, "TARGET"),
                              (self.identity_id, "IDENTITY")):
            validate_entity_id(value, prefix)
        if not isinstance(self.mechanism, AuthMechanism) or not isinstance(self.status, AuthStatus):
            raise ValueError("Invalid authentication mechanism or status")
        if not isinstance(self.preparation, AuthPreparation):
            raise ValueError("Invalid authentication preparation")
        validate_secret_ref(self.secret_ref)
        for ref in (self.browser_session_ref, self.csrf_metadata_ref):
            validate_secret_ref(ref)
        if self.evidence_id is not None:
            validate_entity_id(self.evidence_id, "EV")
        if self.provider is not None and self.provider not in PROVIDER_LABELS:
            raise ValueError("Invalid authentication provider")
        for value in (self.created_at, self.updated_at, self.expires_at):
            _timestamp(value)
        if self.updated_at < self.created_at or (self.expires_at is not None and self.expires_at < self.created_at):
            raise ValueError("Invalid AuthContext chronology")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "identity_id": self.identity_id,
            "mechanism": self.mechanism.value,
            "status": self.status.value,
            "preparation": self.preparation.value,
            "provider": self.provider,
            "has_secret_reference": self.secret_ref is not None,
            "has_browser_session_reference": self.browser_session_ref is not None,
            "has_csrf_metadata_reference": self.csrf_metadata_ref is not None,
            "evidence_id": self.evidence_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


def _from_row(row: sqlite3.Row) -> AuthContext:
    return AuthContext(
        id=row["auth_context_id"], target_id=row["target_id"], identity_id=row["identity_id"],
        mechanism=AuthMechanism(row["mechanism"]), status=AuthStatus(row["status"]),
        preparation=AuthPreparation(row["preparation"]), secret_ref=row["secret_ref"],
        provider=row["provider"], browser_session_ref=row["browser_session_ref"],
        csrf_metadata_ref=row["csrf_metadata_ref"], evidence_id=row["evidence_id"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
    )


class AuthContextManager:
    def __init__(self, registry: IdentityRegistry, secrets: SecretProvider) -> None:
        self.registry = registry
        self.secrets = secrets

    def get(self, target_id: str, identity_id: str) -> AuthContext | None:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(identity_id, "IDENTITY")
        with self.registry.store._connection() as connection:
            row = connection.execute(
                "SELECT * FROM auth_contexts WHERE target_id=? AND identity_id=? LIMIT 1",
                (target_id, identity_id),
            ).fetchone()
        return _from_row(row) if row else None

    def prepare(self, target_id: str, identity_id: str, *,
                mechanism: AuthMechanism | None = None) -> AuthContext:
        validate_entity_id(target_id, "TARGET")
        validate_entity_id(identity_id, "IDENTITY")
        identity = self.registry.get_identity(target_id, identity_id)
        if identity is None:
            raise ValueError("Identity is not registered for target")
        if mechanism is not None and not isinstance(mechanism, AuthMechanism):
            raise ValueError("Invalid authentication mechanism")
        previous = self.get(target_id, identity_id)

        details: SecretMetadata | None = None
        provider_error = False
        missing = False
        if identity.status is IdentityStatus.ACTIVE and identity.secret_ref is not None:
            try:
                details = self.secrets.metadata(identity.secret_ref)
            except SecretUnavailable:
                missing = True
            except Exception:
                provider_error = True
        if mechanism is not None:
            selected = mechanism
        elif (previous is not None and previous.secret_ref == identity.secret_ref
              and previous.mechanism is not AuthMechanism.UNKNOWN):
            selected = previous.mechanism
        elif details is not None:
            selected = _KIND_TO_MECHANISM.get(details.kind, AuthMechanism.UNKNOWN)
        elif identity.account_source is AccountSource.IMPORTED_SESSION:
            selected = AuthMechanism.IMPORTED_SESSION
        else:
            selected = AuthMechanism.UNKNOWN

        if identity.status is IdentityStatus.DISABLED:
            status, preparation = AuthStatus.LOCKED, AuthPreparation.DISABLED
        elif identity.status is not IdentityStatus.ACTIVE:
            status, preparation = AuthStatus.REAUTH_REQUIRED, AuthPreparation.UNKNOWN
        elif selected is AuthMechanism.MANUAL_LOGIN:
            status, preparation = AuthStatus.REAUTH_REQUIRED, AuthPreparation.MANUAL_LOGIN_REQUIRED
        elif selected is AuthMechanism.IMPORTED_SESSION:
            status = AuthStatus.REAUTH_REQUIRED
            preparation = (AuthPreparation.IMPORTED_SESSION_REFERENCE_AVAILABLE if identity.secret_ref is not None
                           and not provider_error and not missing else AuthPreparation.MISSING_SECRET)
        elif provider_error:
            status, preparation = AuthStatus.INVALID, AuthPreparation.UNSUPPORTED_PROVIDER
        elif missing or details is None or not details.available:
            status, preparation = AuthStatus.REAUTH_REQUIRED, AuthPreparation.MISSING_SECRET
        elif selected is AuthMechanism.UNKNOWN or _KIND_TO_MECHANISM.get(details.kind) is not selected:
            status, preparation = AuthStatus.INVALID, AuthPreparation.UNSUPPORTED_PROVIDER
        else:
            status, preparation = AuthStatus.READY, AuthPreparation.READY

        now = datetime.now(timezone.utc)
        with self.registry.store._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current_identity = connection.execute(
                """SELECT status,secret_ref,account_source FROM registry_identities
                WHERE target_id=? AND identity_id=? LIMIT 1""",
                (target_id, identity_id),
            ).fetchone()
            if (current_identity is None or current_identity["status"] != identity.status.value
                    or current_identity["secret_ref"] != identity.secret_ref
                    or current_identity["account_source"] != identity.account_source.value):
                raise ValueError("Identity changed during auth preparation")
            row = connection.execute(
                "SELECT * FROM auth_contexts WHERE target_id=? AND identity_id=? LIMIT 1",
                (target_id, identity_id),
            ).fetchone()
            prior = _from_row(row) if row else None
            if (previous is None) != (prior is None) or (
                previous is not None and prior is not None and previous.updated_at != prior.updated_at
            ):
                raise ValueError("AuthContext changed during auth preparation")
            if prior is not None:
                now = max(now, prior.updated_at + timedelta(microseconds=1))
            context = AuthContext(
                id=prior.id if prior else new_entity_id("AUTHCTX"), target_id=target_id,
                identity_id=identity_id, mechanism=selected, status=status, preparation=preparation,
                secret_ref=identity.secret_ref, provider=details.provider if details else None,
                created_at=prior.created_at if prior else now, updated_at=now,
            )
            if prior:
                connection.execute("""UPDATE auth_contexts SET mechanism=?,status=?,preparation=?,secret_ref=?,
                    provider=?,browser_session_ref=NULL,csrf_metadata_ref=NULL,evidence_id=NULL,
                    updated_at=?,expires_at=NULL WHERE auth_context_id=?""",
                    (selected.value, status.value, preparation.value, identity.secret_ref,
                     context.provider, now.isoformat(), prior.id))
            else:
                connection.execute("""INSERT INTO auth_contexts
                    (auth_context_id,target_id,identity_id,mechanism,status,preparation,secret_ref,provider,
                     browser_session_ref,csrf_metadata_ref,evidence_id,created_at,updated_at,expires_at)
                    VALUES (?,?,?,?,?,?,?,?,NULL,NULL,NULL,?,?,NULL)""",
                    (context.id, target_id, identity_id, selected.value, status.value, preparation.value,
                     identity.secret_ref, context.provider, now.isoformat(), now.isoformat()))
            connection.execute("""INSERT INTO auth_context_events
                (auth_context_id,event_type,old_status,new_status,occurred_at) VALUES (?,?,?,?,?)""",
                (context.id, "PREPARED", prior.status.value if prior else None, status.value, now.isoformat()))
        return context

    def set_status(self, target_id: str, identity_id: str, status: AuthStatus) -> AuthContext:
        if (not isinstance(status, AuthStatus) or status not in {
            AuthStatus.EXPIRED, AuthStatus.REAUTH_REQUIRED, AuthStatus.INVALID,
            AuthStatus.LOCKED, AuthStatus.UNKNOWN,
        }):
            raise ValueError("Phase 7 cannot assert verified or ready session state")
        current = self.get(target_id, identity_id)
        if current is None:
            raise ValueError("AuthContext is not prepared")
        now = max(datetime.now(timezone.utc), current.updated_at + timedelta(microseconds=1))
        with self.registry.store._connection() as connection:
            updated = connection.execute("""UPDATE auth_contexts SET status=?,updated_at=?
                WHERE auth_context_id=? AND updated_at=?""",
                (status.value, now.isoformat(), current.id, current.updated_at.isoformat())).rowcount
            if updated != 1:
                raise ValueError("AuthContext changed since it was read")
            connection.execute("""INSERT INTO auth_context_events
                (auth_context_id,event_type,old_status,new_status,occurred_at) VALUES (?,?,?,?,?)""",
                (current.id, "STATUS_CHANGED", current.status.value, status.value, now.isoformat()))
        result = self.get(target_id, identity_id)
        assert result is not None
        return result

    def expire(self, target_id: str, identity_id: str) -> AuthContext:
        return self.set_status(target_id, identity_id, AuthStatus.EXPIRED)

    def mark_reauth_required(self, target_id: str, identity_id: str) -> AuthContext:
        return self.set_status(target_id, identity_id, AuthStatus.REAUTH_REQUIRED)
