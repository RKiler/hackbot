"""Strict, bounded local Target Package loading and listing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import heapq
import os
from pathlib import Path
import re
import stat
from typing import Iterator, Mapping

import yaml

from .domain import Lifecycle, ObservationState, SourceRef, Target
from .logging import SecretRedactor, is_sensitive_key
from .target_package import (
    AccountReference, PackageStatus, TargetContext, TargetPackage,
)
from .target_policy import AutonomyPolicy, PolicyDecision, ProgramRules, RatePolicy
from .target_scope import (
    HostRule, PathMatch, PathRule, ProgramScope, ScopeProvenance,
    ScopeSourceKind, validate_package_id,
)


class TargetPackageError(ValueError):
    """Invalid local target package. Messages never include source values."""


_DEFAULT_DOCUMENTS = {
    "scope": "scope.md",
    "program_rules": "program_rules.md",
    "context": "context.md",
    "researcher_notes": "researcher_notes.md",
}
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class _StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent: object, index: object) -> yaml.Node:
        if self.check_event(yaml.AliasEvent):
            raise yaml.YAMLError("aliases are disabled")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[str, object]:
        if not isinstance(node, yaml.MappingNode):
            raise yaml.YAMLError("mapping expected")
        result: dict[str, object] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key == "<<" or key in result:
                raise yaml.YAMLError("duplicate or invalid YAML key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _read_bytes(path: Path, maximum: int) -> bytes:
    try:
        if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > maximum:
            raise TargetPackageError("Invalid target package file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            data = handle.read(maximum + 1)
        if len(data) > maximum:
            raise TargetPackageError("Target package file is too large")
        return data
    except (OSError, ValueError):
        raise TargetPackageError("Cannot read target package file") from None


def _reject_secret_fields(value: object, *, accounts: bool = False) -> None:
    redactor = SecretRedactor()

    def walk(item: object) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TargetPackageError("Invalid target package key")
                if is_sensitive_key(key) and not (accounts and key == "secret_ref"):
                    raise TargetPackageError("Credential-like target package field is forbidden")
                walk(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                walk(child)
        elif isinstance(item, str) and redactor.text(item) != item:
            raise TargetPackageError("Credential-like target package value is forbidden")

    walk(value)


def _load_yaml(path: Path, maximum: int, *, accounts: bool = False) -> dict[str, object]:
    data = _read_bytes(path, maximum)
    try:
        result = yaml.load(data.decode("utf-8"), Loader=_StrictLoader)
    except (UnicodeError, yaml.YAMLError, RecursionError):
        raise TargetPackageError("Malformed target package YAML") from None
    if not isinstance(result, dict):
        raise TargetPackageError("Target package YAML must be a mapping")
    _reject_secret_fields(result, accounts=accounts)
    return result


def _mapping(value: object, allowed: set[str], label: str, *, required: set[str] | None = None) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) - allowed or (required and not required <= set(value)):
        raise TargetPackageError(f"Invalid {label} configuration")
    return value


def _sequence(value: object, label: str, maximum: int = 100) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        raise TargetPackageError(f"Invalid {label} list")
    return value


def _string(value: object, label: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise TargetPackageError(f"Invalid {label}")
    return value


def _strings(value: object, label: str, *, maximum_items: int = 50, maximum_text: int = 256) -> tuple[str, ...]:
    return tuple(_string(item, label, maximum_text) for item in _sequence(value, label, maximum_items))


def _timestamp(value: object, label: str) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise TargetPackageError(f"Invalid {label}") from None
    else:
        raise TargetPackageError(f"Invalid {label}")
    if result.tzinfo is None:
        raise TargetPackageError(f"{label} needs a timezone")
    return result


def _enum(value: object, enum_type: type, label: str) -> object:
    if not isinstance(value, str):
        raise TargetPackageError(f"Invalid {label}")
    try:
        return enum_type(value.upper())
    except ValueError:
        raise TargetPackageError(f"Invalid {label}") from None


def _host_rule(value: object) -> HostRule:
    if isinstance(value, str):
        data: dict[str, object] = {"host": value}
    else:
        data = _mapping(value, {"host", "schemes", "ports"}, "host rule", required={"host"})
    schemes = tuple(_sequence(data["schemes"], "host rule schemes", 4)) if "schemes" in data else None
    ports = tuple(_sequence(data["ports"], "host rule ports", 32)) if "ports" in data else None
    return HostRule(pattern=data["host"], schemes=schemes, ports=ports)


def _path_rule(value: object) -> PathRule:
    data = _mapping(value, {"host", "path", "match"}, "path rule", required={"path"})
    return PathRule(path=data["path"], host=data.get("host"),
                    match=_enum(data.get("match", "PREFIX"), PathMatch, "path match"))


def _scope(data: object, package_id: str, source: ScopeProvenance) -> ProgramScope:
    value = _mapping(data, {"include", "exclude", "include_paths", "exclude_paths", "schemes", "ports"},
                     "scope", required={"include"})
    return ProgramScope(
        package_id=package_id,
        include_hosts=tuple(_host_rule(item) for item in _sequence(value["include"], "included hosts")),
        exclude_hosts=tuple(_host_rule(item) for item in _sequence(value.get("exclude", []), "excluded hosts")),
        include_paths=tuple(_path_rule(item) for item in _sequence(value.get("include_paths", []), "included paths")),
        exclude_paths=tuple(_path_rule(item) for item in _sequence(value.get("exclude_paths", []), "excluded paths")),
        default_schemes=tuple(_sequence(value["schemes"], "scope schemes", 4)) if "schemes" in value else ("http", "https"),
        default_ports=tuple(_sequence(value["ports"], "scope ports", 32)) if "ports" in value else None,
        provenance=source,
    )


def _policy_decision(value: object) -> PolicyDecision:
    if type(value) is bool:
        return PolicyDecision.ALLOW if value else PolicyDecision.DENY
    if isinstance(value, str):
        return _enum(value, PolicyDecision, "autonomy decision")
    if isinstance(value, dict):
        choices = {"allow": PolicyDecision.ALLOW, "deny": PolicyDecision.DENY,
                   "require_approval": PolicyDecision.REQUIRE_APPROVAL}
        if len(value) != 1 or next(iter(value)) not in choices or type(next(iter(value.values()))) is not bool:
            raise TargetPackageError("Invalid autonomy decision")
        key, enabled = next(iter(value.items()))
        return choices[key] if enabled else PolicyDecision.DENY
    raise TargetPackageError("Invalid autonomy decision")


def _autonomy(data: object) -> AutonomyPolicy:
    fields = set(AutonomyPolicy.__dataclass_fields__)
    value = _mapping(data, fields, "autonomy")
    parsed: dict[str, object] = {}
    for key, item in value.items():
        if key == "owned_test_objects_only":
            if type(item) is not bool:
                raise TargetPackageError("Invalid owned-object policy")
            parsed[key] = item
        else:
            parsed[key] = _policy_decision(item)
    return AutonomyPolicy(**parsed)


def _labels(value: object, label: str) -> tuple[str, ...]:
    items = _strings(value, label, maximum_items=50, maximum_text=128)
    return tuple(re.sub(r"[\s-]+", "_", item.strip().lower()) for item in items)


def _rules(data: object) -> ProgramRules:
    allowed = {"automated_testing_allowed", "account_creation_allowed",
               "internal_vhost_testing_allowed",
               "excluded_vulnerability_classes", "forbidden_actions", "third_party_restrictions",
               "data_handling_restrictions", "special_testing_notes"}
    value = _mapping(data, allowed, "program rules")
    return ProgramRules(
        automated_testing_allowed=value.get("automated_testing_allowed"),
        account_creation_allowed=value.get("account_creation_allowed"),
        internal_vhost_testing_allowed=value.get("internal_vhost_testing_allowed", False),
        excluded_vulnerability_classes=_labels(value.get("excluded_vulnerability_classes", []), "excluded vulnerability class"),
        forbidden_actions=_labels(value.get("forbidden_actions", []), "forbidden action"),
        third_party_restrictions=value.get("third_party_restrictions"),
        data_handling_restrictions=value.get("data_handling_restrictions"),
        special_testing_notes=_strings(value.get("special_testing_notes", []), "special testing note",
                                       maximum_items=20, maximum_text=512),
    )


def _rate(data: object) -> RatePolicy:
    value = _mapping(data, {"requests_per_second", "requests_per_minute", "max_concurrency", "burst"}, "rate")
    return RatePolicy(**value)


def _context(data: object) -> TargetContext:
    value = _mapping(data, {"description", "known_features", "terminology", "research_priorities", "known_limitations"},
                     "target context")
    terminology_value = value.get("terminology", {})
    if not isinstance(terminology_value, dict) or len(terminology_value) > 50:
        raise TargetPackageError("Invalid terminology configuration")
    return TargetContext(
        description=value.get("description"),
        known_features=_strings(value.get("known_features", []), "known feature", maximum_text=128),
        terminology=tuple((key, item) for key, item in terminology_value.items()),
        research_priorities=_strings(value.get("research_priorities", []), "research priority"),
        known_limitations=_strings(value.get("known_limitations", []), "known limitation"),
    )


def _document_names(folder: Path, data: object) -> tuple[tuple[str, str], ...]:
    value = _mapping(data, set(_DEFAULT_DOCUMENTS), "document references")
    entries: list[tuple[str, str]] = []
    for section, default in _DEFAULT_DOCUMENTS.items():
        filename = value.get(section, default)
        if not isinstance(filename, str) or not _FILE_NAME.fullmatch(filename) or filename in {".", ".."}:
            raise TargetPackageError("Invalid target document name")
        if section in value or (folder / filename).exists():
            path = folder / filename
            content = _read_bytes(path, 65536)
            try:
                decoded = content.decode("utf-8")
            except UnicodeError:
                raise TargetPackageError("Invalid target document encoding") from None
            if SecretRedactor().text(decoded) != decoded:
                raise TargetPackageError("Credential-like target document content is forbidden")
            entries.append((section, filename))
    return tuple(entries)


def _accounts(folder: Path, filename: str) -> tuple[AccountReference, ...]:
    value = _mapping(_load_yaml(folder / filename, 16384, accounts=True), {"accounts"}, "account metadata",
                     required={"accounts"})
    entries = value["accounts"]
    if not isinstance(entries, dict) or len(entries) > 20:
        raise TargetPackageError("Invalid account metadata")
    result = []
    for alias, raw in entries.items():
        entry = _mapping(raw, {"role", "tenant", "secret_ref"}, "account reference")
        result.append(AccountReference(alias=alias, role_hint=entry.get("role"),
                                       tenant_hint=entry.get("tenant"), secret_ref=entry.get("secret_ref")))
    return tuple(result)


def load_target_package(path: Path) -> TargetPackage:
    """Read one local package only. No recon lookup or target request."""
    folder = path if path.is_dir() else path.parent
    if path.name != "target.yaml" and not path.is_dir():
        raise TargetPackageError("Target package path must be a directory or target.yaml")
    try:
        folder = folder.resolve(strict=True)
        if not folder.is_dir():
            raise ValueError
    except (OSError, ValueError):
        raise TargetPackageError("Target package directory is unavailable") from None
    data = _load_yaml(folder / "target.yaml", 65536)
    required = {"version", "id", "target_id", "name", "primary_domain", "configured_at", "source", "scope", "rules", "autonomy", "rate"}
    value = _mapping(data, required | {"updated_at", "status", "context", "files", "accounts_file"},
                     "target package", required=required)
    package_id = validate_package_id(value["id"])
    if folder.name != package_id:
        raise TargetPackageError("Target package directory and ID disagree")
    configured = _timestamp(value["configured_at"], "configured_at")
    updated = _timestamp(value.get("updated_at", value["configured_at"]), "updated_at")
    source_data = _mapping(value["source"], {"kind", "reference", "operator"}, "scope source",
                           required={"kind", "operator"})
    source = ScopeProvenance(
        kind=_enum(source_data["kind"], ScopeSourceKind, "scope source kind"),
        source_file="target.yaml", configured_at=configured,
        reference=source_data.get("reference"),
        operator=_string(source_data["operator"], "scope operator", 128),
    )
    target = Target(
        id=value["target_id"], name=value["name"], root_domain=value["primary_domain"],
        observation_state=ObservationState.CONFIGURED, lifecycle=Lifecycle.UNKNOWN,
        source_ref=SourceRef(provider=source.kind.value, entity="target_package", record_id=package_id,
                             observed_at=configured), created_at=configured,
    )
    files = _document_names(folder, value.get("files", {}))
    account_name = value.get("accounts_file", "accounts.yaml")
    if not isinstance(account_name, str) or not _FILE_NAME.fullmatch(account_name) or account_name in {".", ".."}:
        raise TargetPackageError("Invalid account metadata filename")
    accounts = _accounts(folder, account_name) if (folder / account_name).exists() or "accounts_file" in value else ()
    return TargetPackage(
        id=package_id, target=target, scope=_scope(value["scope"], package_id, source),
        rules=_rules(value["rules"]), autonomy=_autonomy(value["autonomy"]), rate=_rate(value["rate"]),
        status=_enum(value.get("status", "TRACKED"), PackageStatus, "package status"),
        version=value["version"], configured_at=configured, updated_at=updated,
        context=_context(value.get("context", {})), accounts=accounts,
        documents=files, package_dir=folder,
    )


@dataclass(frozen=True, slots=True)
class TargetPage:
    items: tuple[TargetPackage, ...]
    next_cursor: str | None


class TargetPackageRepository:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve(strict=False)

    def get_target_package(self, package_id: str) -> TargetPackage | None:
        validate_package_id(package_id)
        path = self.root / package_id
        if not path.exists():
            return None
        if path.is_symlink() or path.resolve(strict=True).parent != self.root:
            raise TargetPackageError("Unsafe target package directory")
        return load_target_package(path)

    def list_target_packages(self, *, limit: int = 20, cursor: str | None = None) -> TargetPage:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid target package page size")
        if cursor is not None:
            validate_package_id(cursor)
        if not self.root.exists():
            return TargetPage((), None)
        if not self.root.is_dir():
            raise TargetPackageError("Target package root is not a directory")

        def names() -> Iterator[str]:
            with os.scandir(self.root) as entries:
                for entry in entries:
                    if not entry.is_dir(follow_symlinks=False) or not _FILE_NAME.fullmatch(entry.name):
                        continue
                    if cursor is not None and entry.name <= cursor:
                        continue
                    if (Path(entry.path) / "target.yaml").is_file():
                        yield entry.name

        selected = heapq.nsmallest(limit + 1, names())
        packages = tuple(self.get_target_package(name) for name in selected[:limit])
        return TargetPage(tuple(item for item in packages if item is not None),
                          selected[limit - 1] if len(selected) > limit else None)


def get_target_package(root: Path, package_id: str) -> TargetPackage | None:
    return TargetPackageRepository(root).get_target_package(package_id)


def list_target_packages(root: Path, *, limit: int = 20, cursor: str | None = None) -> TargetPage:
    return TargetPackageRepository(root).list_target_packages(limit=limit, cursor=cursor)
