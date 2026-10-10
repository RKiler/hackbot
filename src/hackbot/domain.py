"""Phase 4 logical application models; no recon, traffic, or identity side effects."""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import StrEnum
import ipaddress
import json
import math
import re
from urllib.parse import urlsplit, urlunsplit
import uuid

from .evidence import Sensitivity
from .logging import SecretRedactor


_UUID_NAMESPACE = re.compile(r"[A-Z][A-Z0-9_]*-[0-9a-f]{32}\Z")
_EVIDENCE_ID = re.compile(r"EV-[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PREDICATE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_PROVIDER = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_METHOD = re.compile(r"[A-Z][A-Z0-9_-]{0,31}\Z")
_MIME = re.compile(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+\Z")
_GRAPHQL_NAME = re.compile(r"[_A-Za-z][_A-Za-z0-9]*\Z")
_MAX_EVIDENCE_LINKS = 16


def new_entity_id(prefix: str) -> str:
    if not _PROVIDER.fullmatch(prefix):
        raise ValueError("Invalid entity namespace")
    return f"{prefix}-{uuid.uuid4().hex}"


def validate_entity_id(value: str, prefix: str) -> str:
    if not isinstance(value, str) or not _UUID_NAMESPACE.fullmatch(value) or not value.startswith(prefix + "-"):
        raise ValueError(f"Invalid {prefix} identifier")
    return value


def _optional_id(value: str | None, prefix: str) -> None:
    if value is not None:
        validate_entity_id(value, prefix)


def _text(value: str, label: str, maximum: int = 256, *, strip: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Invalid {label}")
    result = value.strip() if strip else value
    if not result or len(result) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in result):
        raise ValueError(f"Invalid {label}")
    return result


def _optional_text(value: str | None, label: str, maximum: int = 256, *, strip: bool = True) -> str | None:
    return None if value is None else _text(value, label, maximum, strip=strip)


def normalize_hostname(value: str) -> str:
    raw = _text(value, "hostname", 255).rstrip(".")
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        return ipaddress.ip_address(raw).compressed.lower()
    except ValueError:
        pass
    try:
        name = raw.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid hostname") from None
    if len(name) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in name.split(".")):
        raise ValueError("Invalid hostname")
    return name


def normalize_scheme(value: str | None) -> str | None:
    if value is None:
        return None
    scheme = _text(value, "scheme", 8).lower()
    if scheme not in {"http", "https", "ws", "wss"}:
        raise ValueError("Unsupported scheme")
    return scheme


def _port(value: int | None) -> int | None:
    if value is not None and (type(value) is not int or not 1 <= value <= 65535):
        raise ValueError("Invalid port")
    return value


def _origin(scheme: str, hostname: str, port: int | None) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    default = {"http": 80, "ws": 80, "https": 443, "wss": 443}[scheme]
    suffix = f":{port}" if port is not None and port != default else ""
    return f"{scheme}://{host}{suffix}"


def normalize_url(value: str, *, schemes: set[str] | None = None) -> str:
    raw = _text(value, "URL", 4096, strip=False)
    try:
        parsed = urlsplit(raw)
        scheme = normalize_scheme(parsed.scheme)
        if scheme is None or (schemes is not None and scheme not in schemes):
            raise ValueError
        if not parsed.netloc or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError
        hostname = normalize_hostname(parsed.hostname or "")
        port = _port(parsed.port)
    except ValueError:
        raise ValueError("Invalid URL reference") from None
    return urlunsplit((scheme, _origin(scheme, hostname, port).split("://", 1)[1], parsed.path or "/", parsed.query, ""))


def normalize_path(value: str) -> str:
    path = _text(value, "endpoint path", 2048, strip=False)
    if "://" in path or "?" in path or "#" in path or any(char.isspace() for char in path):
        raise ValueError("Endpoint path must not contain an origin or query")
    return path if path.startswith("/") else "/" + path


def normalize_method(value: str) -> str:
    method = _text(value, "HTTP method", 32).upper()
    if not _METHOD.fullmatch(method):
        raise ValueError("Invalid HTTP method")
    return method


def normalize_kind(value: str) -> str:
    kind = re.sub(r"[\s-]+", "_", _text(value, "kind", 64).lower())
    if not _PREDICATE.fullmatch(kind):
        raise ValueError("Invalid kind")
    return kind


def normalize_graphql_type(value: GraphQLOperationType | str) -> GraphQLOperationType:
    if isinstance(value, GraphQLOperationType):
        return value
    if not isinstance(value, str):
        raise ValueError("Invalid GraphQL operation type")
    try:
        return GraphQLOperationType(value.strip().upper())
    except ValueError:
        raise ValueError("Invalid GraphQL operation type") from None


def normalize_content_type(value: str) -> str:
    mime = _text(value, "content type", 256).split(";", 1)[0].strip().lower()
    if not _MIME.fullmatch(mime):
        raise ValueError("Invalid content type")
    return mime


def _hash(value: str | None) -> None:
    if value is not None and (not isinstance(value, str) or not _DIGEST.fullmatch(value)):
        raise ValueError("Invalid SHA-256 artifact reference")


def _evidence(ids: tuple[str, ...]) -> None:
    if not isinstance(ids, tuple) or len(ids) > _MAX_EVIDENCE_LINKS:
        raise ValueError("Invalid evidence references")
    if any(not isinstance(item, str) or not _EVIDENCE_ID.fullmatch(item) for item in ids):
        raise ValueError("Invalid evidence identifier")
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate evidence identifier")


def _timestamps(created_at: datetime, observed_at: datetime | None) -> None:
    if not isinstance(created_at, datetime) or created_at.tzinfo is None:
        raise ValueError("Creation time must be timezone-aware")
    if observed_at is not None and not isinstance(observed_at, datetime):
        raise ValueError("Invalid observation time")


def _base(
    entity_id: str, prefix: str, target_id: str | None, evidence_ids: tuple[str, ...],
    observation_state: ObservationState, source_ref: SourceRef | None,
    observed_at: datetime | None, created_at: datetime,
) -> None:
    validate_entity_id(entity_id, prefix)
    _optional_id(target_id, "TARGET")
    _evidence(evidence_ids)
    if not isinstance(observation_state, ObservationState) or (source_ref is not None and not isinstance(source_ref, SourceRef)):
        raise ValueError("Invalid observation state or source")
    _timestamps(created_at, observed_at)


def _serialized(value: object, include_private: bool) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: (
                "[REDACTED]" if item.metadata.get("private") and not include_private and getattr(value, item.name) is not None
                else _serialized(getattr(value, item.name), include_private)
            )
            for item in fields(value)
        }
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, tuple):
        return [_serialized(item, include_private) for item in value]
    return value


class DomainRecord:
    """Default serialization is safe for context/logs; private data is opt-in."""

    def to_dict(self, *, include_private: bool = False) -> dict[str, object]:
        result = _serialized(self, include_private)
        assert isinstance(result, dict)
        if include_private:
            return result
        sanitized = SecretRedactor().data(result)
        assert isinstance(sanitized, dict)
        return sanitized

    def to_json(self, *, include_private: bool = False) -> str:
        return json.dumps(self.to_dict(include_private=include_private), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def to_reference(self) -> dict[str, object]:
        result: dict[str, object] = {"id": getattr(self, "id"), "type": type(self).__name__}
        target_id = getattr(self, "target_id", None)
        if target_id is not None:
            result["target_id"] = target_id
        evidence_ids = getattr(self, "evidence_ids", ())
        if evidence_ids:
            result["evidence_ids"] = list(evidence_ids)
        return result


class ObservationState(StrEnum):
    CONFIGURED = "CONFIGURED"
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"


class Lifecycle(StrEnum):
    UNKNOWN = "UNKNOWN"
    CURRENT = "CURRENT"
    HISTORICAL = "HISTORICAL"
    RETIRED = "RETIRED"


class ObjectLifecycle(StrEnum):
    UNKNOWN = "UNKNOWN"
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    DELETED = "DELETED"


class ParameterLocation(StrEnum):
    PATH = "PATH"
    QUERY = "QUERY"
    BODY = "BODY"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    GRAPHQL_VARIABLE = "GRAPHQL_VARIABLE"
    RPC_ARGUMENT = "RPC_ARGUMENT"


class EndpointCategory(StrEnum):
    HTTP = "HTTP"
    GRAPHQL = "GRAPHQL"
    RPC = "RPC"
    WEBSOCKET = "WEBSOCKET"
    UNKNOWN = "UNKNOWN"


class OperationKind(StrEnum):
    HTTP = "HTTP"
    GRAPHQL = "GRAPHQL"
    RPC = "RPC"
    UI = "UI"
    UNKNOWN = "UNKNOWN"


class GraphQLOperationType(StrEnum):
    QUERY = "QUERY"
    MUTATION = "MUTATION"
    SUBSCRIPTION = "SUBSCRIPTION"
    UNKNOWN = "UNKNOWN"


class TrafficSource(StrEnum):
    BURP = "BURP"
    BROWSER = "BROWSER"
    HACKBOT = "HACKBOT"
    IMPORT = "IMPORT"
    HAR_IMPORT = "HAR_IMPORT"
    MANUAL_IMPORT = "MANUAL_IMPORT"
    FIXTURE = "FIXTURE"


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceRef(DomainRecord):
    provider: str
    entity: str | None = None
    record_id: str | None = field(default=None, repr=False, metadata={"private": True})
    observed_at: datetime | None = None
    qualification: str | None = field(default=None, repr=False, metadata={"private": True})

    def __post_init__(self) -> None:
        provider = _text(self.provider, "source provider", 64).upper()
        if not _PROVIDER.fullmatch(provider):
            raise ValueError("Invalid source provider")
        object.__setattr__(self, "provider", provider)
        _optional_text(self.entity, "source entity", 128)
        _optional_text(self.record_id, "source record ID", 512, strip=False)
        _optional_text(self.qualification, "source qualification", 256)
        if self.observed_at is not None and not isinstance(self.observed_at, datetime):
            raise ValueError("Invalid source timestamp")

    def to_reference(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "entity": self.entity,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class Target(DomainRecord):
    name: str = field(repr=False, metadata={"private": True})
    root_domain: str | None = None
    external_ref: str | None = field(default=None, repr=False, metadata={"private": True})
    lifecycle: Lifecycle = Lifecycle.UNKNOWN
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("TARGET"))

    def __post_init__(self) -> None:
        _base(self.id, "TARGET", None, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        object.__setattr__(self, "name", _text(self.name, "target name"))
        if self.root_domain is not None:
            object.__setattr__(self, "root_domain", normalize_hostname(self.root_domain))
        _optional_text(self.external_ref, "target external reference", 512, strip=False)
        if not isinstance(self.lifecycle, Lifecycle):
            raise ValueError("Invalid target lifecycle")


@dataclass(frozen=True, slots=True, kw_only=True)
class Host(DomainRecord):
    target_id: str
    hostname: str
    scheme: str | None = None
    port: int | None = None
    lifecycle: Lifecycle = Lifecycle.UNKNOWN
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("HOST"))

    def __post_init__(self) -> None:
        _base(self.id, "HOST", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        object.__setattr__(self, "hostname", normalize_hostname(self.hostname))
        object.__setattr__(self, "scheme", normalize_scheme(self.scheme))
        _port(self.port)
        if not isinstance(self.lifecycle, Lifecycle):
            raise ValueError("Invalid host lifecycle")

    @property
    def origin(self) -> str | None:
        return _origin(self.scheme, self.hostname, self.port) if self.scheme else None


@dataclass(frozen=True, slots=True, kw_only=True)
class Endpoint(DomainRecord):
    target_id: str
    host_id: str
    path: str = field(repr=False, metadata={"private": True})
    method: str | None = None
    category: EndpointCategory = EndpointCategory.HTTP
    lifecycle: Lifecycle = Lifecycle.UNKNOWN
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("ENDPOINT"))

    def __post_init__(self) -> None:
        _base(self.id, "ENDPOINT", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        validate_entity_id(self.host_id, "HOST")
        object.__setattr__(self, "path", normalize_path(self.path))
        if self.method is not None:
            object.__setattr__(self, "method", normalize_method(self.method))
        if not isinstance(self.category, EndpointCategory) or not isinstance(self.lifecycle, Lifecycle):
            raise ValueError("Invalid endpoint category or lifecycle")


@dataclass(frozen=True, slots=True, kw_only=True)
class Parameter(DomainRecord):
    target_id: str
    name: str
    location: ParameterLocation
    endpoint_id: str | None = None
    operation_id: str | None = None
    data_type_hint: str | None = None
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("PARAM"))

    def __post_init__(self) -> None:
        _base(self.id, "PARAM", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        if self.endpoint_id is None and self.operation_id is None:
            raise ValueError("Parameter needs an endpoint or operation")
        _optional_id(self.endpoint_id, "ENDPOINT")
        if self.operation_id is not None:
            if not isinstance(self.operation_id, str) or not any(
                self.operation_id.startswith(prefix + "-") for prefix in ("OPERATION", "GQL")
            ):
                raise ValueError("Invalid parameter operation reference")
            validate_entity_id(self.operation_id, self.operation_id.split("-", 1)[0])
        _text(self.name, "parameter name", 256, strip=False)
        if not isinstance(self.location, ParameterLocation) or not isinstance(self.sensitivity, Sensitivity):
            raise ValueError("Invalid parameter location or sensitivity")
        _optional_text(self.data_type_hint, "parameter type hint", 64)


@dataclass(frozen=True, slots=True, kw_only=True)
class JavaScriptAsset(DomainRecord):
    target_id: str
    host_id: str
    url: str = field(repr=False, metadata={"private": True})
    sha256: str | None = None
    size_bytes: int | None = None
    http_status: int | None = None
    artifact_hash: str | None = None
    lifecycle: Lifecycle = Lifecycle.UNKNOWN
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("JS"))

    def __post_init__(self) -> None:
        _base(self.id, "JS", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        validate_entity_id(self.host_id, "HOST")
        object.__setattr__(self, "url", normalize_url(self.url, schemes={"http", "https"}))
        _hash(self.sha256)
        _hash(self.artifact_hash)
        if self.size_bytes is not None and (type(self.size_bytes) is not int or self.size_bytes < 0):
            raise ValueError("Invalid JS size")
        if self.http_status is not None and (type(self.http_status) is not int or not 100 <= self.http_status <= 599):
            raise ValueError("Invalid JS HTTP status")
        if not isinstance(self.lifecycle, Lifecycle):
            raise ValueError("Invalid JS lifecycle")


@dataclass(frozen=True, slots=True, kw_only=True)
class Principal(DomainRecord):
    target_id: str
    label: str = field(repr=False, metadata={"private": True})
    external_user_id: str | None = field(default=None, repr=False, metadata={"private": True})
    lifecycle: Lifecycle = Lifecycle.UNKNOWN
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("PRINCIPAL"))

    def __post_init__(self) -> None:
        _base(self.id, "PRINCIPAL", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        object.__setattr__(self, "label", _text(self.label, "principal label"))
        _optional_text(self.external_user_id, "external user ID", 1024, strip=False)
        if not isinstance(self.lifecycle, Lifecycle):
            raise ValueError("Invalid principal lifecycle")


@dataclass(frozen=True, slots=True, kw_only=True)
class Role(DomainRecord):
    target_id: str
    name: str = field(repr=False, metadata={"private": True})
    external_role_id: str | None = field(default=None, repr=False, metadata={"private": True})
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("ROLE"))

    def __post_init__(self) -> None:
        _base(self.id, "ROLE", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        object.__setattr__(self, "name", _text(self.name, "role name"))
        _optional_text(self.external_role_id, "external role ID", 1024, strip=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class Tenant(DomainRecord):
    target_id: str
    label: str = field(repr=False, metadata={"private": True})
    kind: str
    external_id: str | None = field(default=None, repr=False, metadata={"private": True})
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("TENANT"))

    def __post_init__(self) -> None:
        _base(self.id, "TENANT", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        object.__setattr__(self, "label", _text(self.label, "tenant label"))
        object.__setattr__(self, "kind", normalize_kind(self.kind))
        _optional_text(self.external_id, "tenant external ID", 1024, strip=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class ObjectReference(DomainRecord):
    target_id: str
    object_type: str
    external_id: str | None = field(default=None, repr=False, metadata={"private": True})
    tenant_id_hint: str | None = None
    owner_principal_id_hint: str | None = None
    creator_principal_id_hint: str | None = None
    disposable: bool = False
    lifecycle: ObjectLifecycle = ObjectLifecycle.UNKNOWN
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("OBJECT"))

    def __post_init__(self) -> None:
        _base(self.id, "OBJECT", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        object.__setattr__(self, "object_type", normalize_kind(self.object_type))
        _optional_text(self.external_id, "object external ID", 1024, strip=False)
        _optional_id(self.tenant_id_hint, "TENANT")
        _optional_id(self.owner_principal_id_hint, "PRINCIPAL")
        _optional_id(self.creator_principal_id_hint, "PRINCIPAL")
        if type(self.disposable) is not bool or not isinstance(self.lifecycle, ObjectLifecycle):
            raise ValueError("Invalid object lifecycle or disposable flag")
        if self.observation_state is not ObservationState.CONFIGURED and (
            self.tenant_id_hint or self.owner_principal_id_hint or self.creator_principal_id_hint
        ) and not self.evidence_ids:
            raise ValueError("Observed ownership hints require evidence")


@dataclass(frozen=True, slots=True, kw_only=True)
class Feature(DomainRecord):
    target_id: str
    name: str
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("FEATURE"))

    def __post_init__(self) -> None:
        _base(self.id, "FEATURE", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        object.__setattr__(self, "name", normalize_kind(self.name))


@dataclass(frozen=True, slots=True, kw_only=True)
class Operation(DomainRecord):
    target_id: str
    name: str = field(repr=False, metadata={"private": True})
    kind: OperationKind = OperationKind.UNKNOWN
    endpoint_id: str | None = None
    graphql_operation_id: str | None = None
    feature_id: str | None = None
    acts_on_type: str | None = None
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("OPERATION"))

    def __post_init__(self) -> None:
        _base(self.id, "OPERATION", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        object.__setattr__(self, "name", _text(self.name, "operation name"))
        if not isinstance(self.kind, OperationKind):
            raise ValueError("Invalid operation kind")
        _optional_id(self.endpoint_id, "ENDPOINT")
        _optional_id(self.graphql_operation_id, "GQL")
        _optional_id(self.feature_id, "FEATURE")
        if self.acts_on_type is not None:
            object.__setattr__(self, "acts_on_type", normalize_kind(self.acts_on_type))


@dataclass(frozen=True, slots=True, kw_only=True)
class GraphQLOperation(DomainRecord):
    target_id: str
    operation_type: GraphQLOperationType | str
    name: str | None = field(default=None, repr=False, metadata={"private": True})
    variable_names: tuple[str, ...] = ()
    document_artifact_hash: str | None = None
    source_js_asset_id: str | None = None
    observed_in_traffic: bool = False
    observation_state: ObservationState = ObservationState.CONFIGURED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("GQL"))

    def __post_init__(self) -> None:
        _base(self.id, "GQL", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        object.__setattr__(self, "operation_type", normalize_graphql_type(self.operation_type))
        _optional_text(self.name, "GraphQL operation name", 256)
        if not isinstance(self.variable_names, tuple) or len(self.variable_names) > 64:
            raise ValueError("Invalid GraphQL variable names")
        for name in self.variable_names:
            if not _GRAPHQL_NAME.fullmatch(_text(name, "GraphQL variable name", 128)):
                raise ValueError("Invalid GraphQL variable name")
        if len(set(self.variable_names)) != len(self.variable_names):
            raise ValueError("Duplicate GraphQL variable name")
        _hash(self.document_artifact_hash)
        _optional_id(self.source_js_asset_id, "JS")
        if type(self.observed_in_traffic) is not bool:
            raise ValueError("Invalid traffic observation marker")


@dataclass(frozen=True, slots=True, kw_only=True)
class RequestRecord(DomainRecord):
    target_id: str
    method: str
    source: TrafficSource
    url: str | None = field(default=None, repr=False, metadata={"private": True})
    principal_id: str | None = None
    endpoint_id: str | None = None
    operation_id: str | None = None
    correlation_id: str | None = field(default=None, repr=False, metadata={"private": True})
    artifact_hash: str | None = None
    evidence_ids: tuple[str, ...] = ()
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("REQUEST"))

    def __post_init__(self) -> None:
        _base(self.id, "REQUEST", self.target_id, self.evidence_ids, ObservationState.OBSERVED, None, self.observed_at, self.created_at)
        object.__setattr__(self, "method", normalize_method(self.method))
        if not isinstance(self.source, TrafficSource):
            raise ValueError("Invalid traffic source")
        if self.url is not None:
            object.__setattr__(self, "url", normalize_url(self.url))
        _optional_id(self.principal_id, "PRINCIPAL")
        _optional_id(self.endpoint_id, "ENDPOINT")
        if self.operation_id is not None:
            if not isinstance(self.operation_id, str):
                raise ValueError("Invalid traffic operation reference")
            prefix = self.operation_id.split("-", 1)[0]
            if prefix not in {"OPERATION", "GQL"}:
                raise ValueError("Invalid traffic operation reference")
            validate_entity_id(self.operation_id, prefix)
        _optional_text(self.correlation_id, "correlation ID", 128, strip=False)
        _hash(self.artifact_hash)

    @property
    def origin_reference(self) -> str | None:
        if self.url is None:
            return None
        parsed = urlsplit(self.url)
        return _origin(parsed.scheme, normalize_hostname(parsed.hostname or ""), parsed.port)


@dataclass(frozen=True, slots=True, kw_only=True)
class ResponseRecord(DomainRecord):
    target_id: str
    request_id: str
    source: TrafficSource
    status_code: int | None = None
    content_type: str | None = None
    size_bytes: int | None = None
    correlation_id: str | None = field(default=None, repr=False, metadata={"private": True})
    artifact_hash: str | None = None
    evidence_ids: tuple[str, ...] = ()
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("RESPONSE"))

    def __post_init__(self) -> None:
        _base(self.id, "RESPONSE", self.target_id, self.evidence_ids, ObservationState.OBSERVED, None, self.observed_at, self.created_at)
        validate_entity_id(self.request_id, "REQUEST")
        if not isinstance(self.source, TrafficSource):
            raise ValueError("Invalid traffic source")
        if self.status_code is not None and (type(self.status_code) is not int or not 100 <= self.status_code <= 599):
            raise ValueError("Invalid response status")
        if self.content_type is not None:
            object.__setattr__(self, "content_type", normalize_content_type(self.content_type))
        if self.size_bytes is not None and (type(self.size_bytes) is not int or self.size_bytes < 0):
            raise ValueError("Invalid response size")
        _optional_text(self.correlation_id, "correlation ID", 128, strip=False)
        _hash(self.artifact_hash)


@dataclass(frozen=True, slots=True, kw_only=True)
class Technology(DomainRecord):
    target_id: str
    name: str
    confidence: float
    host_id: str | None = None
    version_hint: str | None = field(default=None, repr=False, metadata={"private": True})
    observation_state: ObservationState = ObservationState.INFERRED
    evidence_ids: tuple[str, ...] = ()
    source_ref: SourceRef | None = None
    observed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: new_entity_id("TECH"))

    def __post_init__(self) -> None:
        _base(self.id, "TECH", self.target_id, self.evidence_ids, self.observation_state, self.source_ref, self.observed_at, self.created_at)
        object.__setattr__(self, "name", _text(self.name, "technology name"))
        _optional_id(self.host_id, "HOST")
        _optional_text(self.version_hint, "technology version", 128)
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)) or not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1:
            raise ValueError("Technology confidence must be between 0 and 1")
