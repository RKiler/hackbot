"""Deterministic, package-owned program scope. No recon or network access."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import re
from urllib.parse import urlsplit

from .domain import normalize_hostname, normalize_path, normalize_scheme


_PACKAGE_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_URL_SCHEMES = frozenset({"http", "https", "ws", "wss"})
_DEFAULT_PORT = {"http": 80, "https": 443, "ws": 80, "wss": 443}


class ScopeResult(StrEnum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"


class ScopeSourceKind(StrEnum):
    HACKERONE = "HACKERONE"
    BUGCROWD = "BUGCROWD"
    PRIVATE_DOCUMENT = "PRIVATE_DOCUMENT"
    RESEARCHER = "RESEARCHER"
    IMPORTED_SCOPE = "IMPORTED_SCOPE"


class PathMatch(StrEnum):
    EXACT = "EXACT"
    PREFIX = "PREFIX"


def validate_package_id(value: str) -> str:
    if not isinstance(value, str) or not _PACKAGE_ID.fullmatch(value):
        raise ValueError("Invalid target package ID")
    return value


def _schemes(value: tuple[str, ...] | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, tuple) or not value or len(value) > 4:
        raise ValueError("Invalid scheme restrictions")
    normalized = tuple(normalize_scheme(item) for item in value)
    if any(item not in _URL_SCHEMES for item in normalized) or len(set(normalized)) != len(normalized):
        raise ValueError("Invalid scheme restrictions")
    return normalized


def _ports(value: tuple[int, ...] | None) -> tuple[int, ...] | None:
    if value is None:
        return None
    if not isinstance(value, tuple) or not value or len(value) > 32:
        raise ValueError("Invalid port restrictions")
    if any(type(item) is not int or not 1 <= item <= 65535 for item in value) or len(set(value)) != len(value):
        raise ValueError("Invalid port restrictions")
    return value


def _host_pattern(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid host pattern")
    if value.endswith(".."):
        raise ValueError("Invalid host pattern")
    if value.startswith("*."):
        return "*." + normalize_hostname(value[2:])
    if "*" in value:
        raise ValueError("Invalid host pattern")
    return normalize_hostname(value)


@dataclass(frozen=True, slots=True)
class HostRule:
    pattern: str
    schemes: tuple[str, ...] | None = None
    ports: tuple[int, ...] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "pattern", _host_pattern(self.pattern))
        object.__setattr__(self, "schemes", _schemes(self.schemes))
        object.__setattr__(self, "ports", _ports(self.ports))

    def matches_host(self, hostname: str) -> bool:
        if self.pattern.startswith("*."):
            apex = self.pattern[2:]
            return hostname.endswith("." + apex) and hostname != apex
        return hostname == self.pattern

    def matches_origin(
        self, hostname: str, scheme: str, port: int,
        default_schemes: tuple[str, ...], default_ports: tuple[int, ...] | None,
    ) -> bool:
        if not self.matches_host(hostname) or scheme not in (self.schemes or default_schemes):
            return False
        ports = self.ports or default_ports
        return port in ports if ports is not None else port == _DEFAULT_PORT[scheme]

    def display(self) -> str:
        suffix = ""
        if self.schemes is not None:
            suffix += " schemes=" + ",".join(self.schemes)
        if self.ports is not None:
            suffix += " ports=" + ",".join(str(port) for port in self.ports)
        return self.pattern + suffix


def _ambiguous_path(path: str) -> bool:
    return ("%" in path or "\\" in path or ";" in path or "//" in path
            or any(part in {".", ".."} for part in path.split("/")))


@dataclass(frozen=True, slots=True)
class PathRule:
    path: str
    match: PathMatch = PathMatch.PREFIX
    host: str | None = None

    def __post_init__(self) -> None:
        normalized = normalize_path(self.path)
        if _ambiguous_path(normalized):
            raise ValueError("Ambiguous scope path rule")
        object.__setattr__(self, "path", normalized)
        if not isinstance(self.match, PathMatch):
            raise ValueError("Invalid path match type")
        if self.host is not None:
            object.__setattr__(self, "host", _host_pattern(self.host))

    def matches(self, hostname: str, path: str) -> bool:
        if self.host is not None and not HostRule(self.host).matches_host(hostname):
            return False
        if self.match is PathMatch.EXACT:
            return path == self.path
        return self.path == "/" or path == self.path or path.startswith(self.path.rstrip("/") + "/")

    def display(self) -> str:
        return f"{self.host or '*'} {self.match.value} {self.path}"


@dataclass(frozen=True, slots=True)
class ScopeProvenance:
    kind: ScopeSourceKind
    source_file: str
    configured_at: datetime
    reference: str | None = field(default=None, repr=False)
    operator: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ScopeSourceKind):
            raise ValueError("Invalid scope source kind")
        if not isinstance(self.source_file, str) or not self.source_file or len(self.source_file) > 128:
            raise ValueError("Invalid scope source file")
        if not isinstance(self.configured_at, datetime) or self.configured_at.tzinfo is None:
            raise ValueError("Scope timestamp must be timezone-aware")
        for value in (self.reference, self.operator):
            if value is not None and (not isinstance(value, str) or not value or len(value) > 2048
                                      or any(ord(char) < 32 for char in value)):
                raise ValueError("Invalid scope provenance")

    def to_reference(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "source_file": self.source_file,
            "configured_at": self.configured_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    result: ScopeResult
    reason: str
    matched_rule: str | None
    package_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "result": self.result.value,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "package_id": self.package_id,
        }


@dataclass(frozen=True, slots=True)
class ProgramScope:
    package_id: str
    include_hosts: tuple[HostRule, ...]
    provenance: ScopeProvenance
    exclude_hosts: tuple[HostRule, ...] = ()
    include_paths: tuple[PathRule, ...] = ()
    exclude_paths: tuple[PathRule, ...] = ()
    default_schemes: tuple[str, ...] = ("http", "https")
    default_ports: tuple[int, ...] | None = None

    def __post_init__(self) -> None:
        validate_package_id(self.package_id)
        if not isinstance(self.provenance, ScopeProvenance):
            raise ValueError("Scope provenance is required")
        for rules, rule_type in ((self.include_hosts, HostRule), (self.exclude_hosts, HostRule),
                                 (self.include_paths, PathRule), (self.exclude_paths, PathRule)):
            if not isinstance(rules, tuple) or len(rules) > 100 or any(not isinstance(rule, rule_type) for rule in rules):
                raise ValueError("Invalid scope rules")
        if not self.include_hosts:
            raise ValueError("At least one explicit included host is required")
        schemes = _schemes(self.default_schemes)
        if schemes is None:
            raise ValueError("Default schemes are required")
        object.__setattr__(self, "default_schemes", schemes)
        object.__setattr__(self, "default_ports", _ports(self.default_ports))

    def _decision(self, result: ScopeResult, reason: str, rule: str | None = None) -> ScopeDecision:
        return ScopeDecision(result, reason, rule, self.package_id)

    def evaluate_url(self, url: str) -> ScopeDecision:
        if not isinstance(url, str) or not 1 <= len(url) <= 4096 or any(ord(char) < 32 or ord(char) == 127 for char in url):
            return self._decision(ScopeResult.UNKNOWN, "invalid_url")
        try:
            parsed = urlsplit(url)
            scheme = normalize_scheme(parsed.scheme)
            if (scheme not in _URL_SCHEMES or not parsed.netloc or parsed.username is not None
                    or parsed.password is not None or parsed.fragment or parsed.netloc.endswith(":")):
                raise ValueError
            hostname = normalize_hostname(parsed.hostname or "")
            if (parsed.hostname or "").endswith(".."):
                raise ValueError
            port = _DEFAULT_PORT[scheme] if parsed.port is None else parsed.port
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            return self._decision(ScopeResult.UNKNOWN, "invalid_url")

        for rule in self.exclude_hosts:
            if rule.matches_host(hostname) and (rule.schemes is None or scheme in rule.schemes) and (rule.ports is None or port in rule.ports):
                return self._decision(ScopeResult.OUT_OF_SCOPE, "excluded_host", rule.display())
        host_matches = [rule for rule in self.include_hosts if rule.matches_host(hostname)]
        if not host_matches:
            return self._decision(ScopeResult.UNKNOWN, "host_not_included")
        matching_origin = next((rule for rule in host_matches if rule.matches_origin(
            hostname, scheme, port, self.default_schemes, self.default_ports)), None)
        if matching_origin is None:
            return self._decision(ScopeResult.OUT_OF_SCOPE, "scheme_or_port_restricted",
                                  host_matches[0].display())

        path = parsed.path or "/"
        if self.include_paths or self.exclude_paths:
            if _ambiguous_path(path):
                return self._decision(ScopeResult.UNKNOWN, "ambiguous_path")
            for rule in self.exclude_paths:
                if rule.matches(hostname, path):
                    return self._decision(ScopeResult.OUT_OF_SCOPE, "excluded_path", rule.display())
            if self.include_paths:
                match = next((rule for rule in self.include_paths if rule.matches(hostname, path)), None)
                if match is None:
                    return self._decision(ScopeResult.OUT_OF_SCOPE, "path_not_included")
                return self._decision(ScopeResult.IN_SCOPE, "included_path", match.display())
        return self._decision(ScopeResult.IN_SCOPE, "included_host", matching_origin.display())

    def to_dict(self) -> dict[str, object]:
        return {
            "package_id": self.package_id,
            "include_hosts": [rule.display() for rule in self.include_hosts],
            "exclude_hosts": [rule.display() for rule in self.exclude_hosts],
            "include_paths": [rule.display() for rule in self.include_paths],
            "exclude_paths": [rule.display() for rule in self.exclude_paths],
            "default_schemes": list(self.default_schemes),
            "default_ports": list(self.default_ports) if self.default_ports else None,
            "provenance": self.provenance.to_reference(),
        }
