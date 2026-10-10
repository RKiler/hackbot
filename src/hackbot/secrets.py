"""Execution-boundary secret references and protected in-process values."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hmac
import os
import re
from typing import Mapping, Protocol

from .config import SecretSettings
from .identity import validate_secret_ref


class SecretError(ValueError):
    """A safe, value-free provider error."""


class SecretUnavailable(SecretError):
    pass


class SecretKind(StrEnum):
    PASSWORD = "PASSWORD"
    COOKIE = "COOKIE"
    BEARER_TOKEN = "BEARER_TOKEN"
    API_TOKEN = "API_TOKEN"
    LOGIN_DESCRIPTOR = "LOGIN_DESCRIPTOR"
    HEADER_SET = "HEADER_SET"
    SESSION_IMPORT_REFERENCE = "SESSION_IMPORT_REFERENCE"
    UNKNOWN = "UNKNOWN"


PROVIDER_LABELS = frozenset({"ENV", "MANUAL", "DOCKER_SECRETS", "SYSTEM_KEYRING",
                             "VAULT", "CLOUD_SECRET_MANAGER"})


class SecretValue:
    """Opaque in ordinary output; reveal is an explicit execution-only operation."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value:
            raise SecretError("Secret value is unavailable")
        self.__value = value

    def reveal(self, *, execution_boundary: bool = False) -> str:
        if execution_boundary is not True:
            raise SecretError("Secret reveal requires a trusted execution boundary")
        return self.__value

    def __repr__(self) -> str:
        return "SecretValue([REDACTED])"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SecretValue) and hmac.compare_digest(
            self.__value.encode("utf-8"), other.__value.encode("utf-8")
        )

    __hash__ = None

    def __copy__(self) -> SecretValue:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> SecretValue:
        return self

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("SecretValue cannot be serialized")


@dataclass(frozen=True, slots=True)
class SecretMetadata:
    provider: str
    kind: SecretKind
    available: bool

    def __post_init__(self) -> None:
        if self.provider not in PROVIDER_LABELS or not isinstance(self.kind, SecretKind) or type(self.available) is not bool:
            raise SecretError("Invalid secret provider metadata")

    def to_dict(self) -> dict[str, object]:
        return {"provider": self.provider, "kind": self.kind.value, "available": self.available}


class SecretProvider(Protocol):
    def get(self, secret_ref: str) -> SecretValue: ...
    def exists(self, secret_ref: str) -> bool: ...
    def metadata(self, secret_ref: str) -> SecretMetadata: ...


_ENV_REF = re.compile(r"env:([A-Z][A-Z0-9_]*)\Z")
_MANUAL_REF = re.compile(r"manual:[a-z][a-z0-9_-]{0,63}\Z")


class EnvironmentSecretProvider:
    def __init__(self, allowed_prefixes: tuple[str, ...], environ: Mapping[str, str] | None = None) -> None:
        if not allowed_prefixes or any(not re.fullmatch(r"[A-Z][A-Z0-9_]*_", part) for part in allowed_prefixes):
            raise SecretError("Invalid environment provider configuration")
        self._prefixes = allowed_prefixes
        self._environ = os.environ if environ is None else environ

    def _name(self, ref: str) -> str:
        match = _ENV_REF.fullmatch(ref) if isinstance(ref, str) else None
        if match is None or not any(match[1].startswith(prefix) for prefix in self._prefixes):
            raise SecretError("Environment secret reference is not allowed")
        return match[1]

    def exists(self, secret_ref: str) -> bool:
        name = self._name(secret_ref)
        try:
            return bool(self._environ.get(name))
        except Exception:
            raise SecretError("Secret availability check failed") from None

    def get(self, secret_ref: str) -> SecretValue:
        name = self._name(secret_ref)
        try:
            value = self._environ.get(name)
        except Exception:
            raise SecretError("Secret resolution failed") from None
        if not value:
            raise SecretUnavailable("Secret is unavailable")
        return SecretValue(value)

    def metadata(self, secret_ref: str) -> SecretMetadata:
        self._name(secret_ref)
        return SecretMetadata("ENV", SecretKind.UNKNOWN, self.exists(secret_ref))


class ManualLoginSecretProvider:
    """Metadata marker only. Human login and session import are later phases."""

    def get(self, secret_ref: str) -> SecretValue:
        self._validate(secret_ref)
        raise SecretUnavailable("Manual login has no resolvable secret")

    def exists(self, secret_ref: str) -> bool:
        self._validate(secret_ref)
        return False

    def metadata(self, secret_ref: str) -> SecretMetadata:
        self._validate(secret_ref)
        return SecretMetadata("MANUAL", SecretKind.LOGIN_DESCRIPTOR, False)

    @staticmethod
    def _validate(secret_ref: str) -> None:
        if not isinstance(secret_ref, str) or not _MANUAL_REF.fullmatch(secret_ref):
            raise SecretError("Invalid manual login reference")


class RoutedSecretProvider:
    """Maps Phase 6 opaque refs to explicit provider refs; never enumerates values."""

    def __init__(self, settings: SecretSettings, environ: Mapping[str, str] | None = None) -> None:
        self._bindings = {binding.ref: binding for binding in settings.bindings}
        self._env = EnvironmentSecretProvider(settings.allowed_env_prefixes, environ)
        self._manual = ManualLoginSecretProvider()

    def _route(self, secret_ref: str) -> tuple[SecretProvider, str, SecretKind]:
        validate_secret_ref(secret_ref)
        binding = self._bindings.get(secret_ref)
        if binding is None:
            raise SecretUnavailable("Secret reference is not configured")
        provider_ref = binding.provider_ref
        if provider_ref.startswith("env:"):
            return self._env, provider_ref, SecretKind(binding.kind)
        if provider_ref.startswith("manual:"):
            return self._manual, provider_ref, SecretKind(binding.kind)
        raise SecretError("Secret provider is unsupported")

    def exists(self, secret_ref: str) -> bool:
        provider, provider_ref, _ = self._route(secret_ref)
        return provider.exists(provider_ref)

    def metadata(self, secret_ref: str) -> SecretMetadata:
        provider, provider_ref, kind = self._route(secret_ref)
        details = provider.metadata(provider_ref)
        return SecretMetadata(details.provider, kind, details.available)

    def get(self, secret_ref: str) -> SecretValue:
        provider, provider_ref, _ = self._route(secret_ref)
        return provider.get(provider_ref)


@dataclass(frozen=True, slots=True)
class UsernamePasswordCredential:
    password: SecretValue = field(repr=False)
    username: SecretValue | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.password, SecretValue) or (self.username is not None
                                                        and not isinstance(self.username, SecretValue)):
            raise SecretError("Credential fields require protected values")

    def to_dict(self) -> dict[str, object]:
        return {"kind": "USERNAME_PASSWORD", "username_present": self.username is not None}


@dataclass(frozen=True, slots=True)
class CookieCredential:
    cookie: SecretValue = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.cookie, SecretValue):
            raise SecretError("Credential fields require protected values")

    def to_dict(self) -> dict[str, object]:
        return {"kind": "COOKIE"}


@dataclass(frozen=True, slots=True)
class BearerCredential:
    token: SecretValue = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.token, SecretValue):
            raise SecretError("Credential fields require protected values")

    def to_dict(self) -> dict[str, object]:
        return {"kind": "BEARER"}


@dataclass(frozen=True, slots=True)
class HeaderCredential:
    headers: tuple[tuple[str, SecretValue], ...] = field(repr=False)

    def __post_init__(self) -> None:
        if not self.headers or any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", name)
                                   or not isinstance(value, SecretValue) for name, value in self.headers):
            raise SecretError("Invalid protected header descriptor")

    def to_dict(self) -> dict[str, object]:
        return {"kind": "HEADER", "header_count": len(self.headers)}


@dataclass(frozen=True, slots=True)
class ManualLoginCredential:
    def to_dict(self) -> dict[str, object]:
        return {"kind": "MANUAL_LOGIN"}


@dataclass(frozen=True, slots=True)
class ImportedSessionCredential:
    import_ref: str = field(repr=False)

    def __post_init__(self) -> None:
        validate_secret_ref(self.import_ref)

    def to_dict(self) -> dict[str, object]:
        return {"kind": "IMPORTED_SESSION", "has_import_reference": True}


@dataclass(frozen=True, slots=True)
class LoginFileCredential:
    login_ref: str = field(repr=False)

    def __post_init__(self) -> None:
        validate_secret_ref(self.login_ref)

    def to_dict(self) -> dict[str, object]:
        return {"kind": "LOGIN_FILE", "has_login_reference": True}


CredentialDescriptor = (UsernamePasswordCredential | CookieCredential | BearerCredential
                        | HeaderCredential | ManualLoginCredential | ImportedSessionCredential
                        | LoginFileCredential)
