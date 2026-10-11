"""Manually reviewed, data-only recipes for disposable fixture operations."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from .config import ObjectSettings
from .domain import validate_entity_id
from .executor import RequestTemplate
from .logging import SecretRedactor, is_sensitive_key
from .policy import _strict_url_reason
from .policy_models import SideEffect
from .test_objects import CleanupStrategy


_LABEL = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_POINTER = re.compile(r"(?:/(?:[A-Za-z0-9_-]|~[01]){1,80}){1,12}\Z")
_PLACEHOLDERS = frozenset({"$test_name", "$parent_id", "$object_id"})
_EXTERNAL_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_PROVISIONING_TYPES = frozenset({"account", "user", "identity", "tenant", "organization",
                                 "organisation", "workspace"})


def _mapping(value: object, allowed: set[str], required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - allowed or required - set(value):
        raise ValueError("invalid object recipe shape")
    return value


def _validate_body(value: object, *, depth: int = 0) -> None:
    if depth > 8:
        raise ValueError("recipe body is too deep")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or is_sensitive_key(key) or len(key) > 80:
                raise ValueError("recipe contains a secret-like field")
            _validate_body(item, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 32:
            raise ValueError("recipe body is too large")
        for item in value:
            _validate_body(item, depth=depth + 1)
    elif isinstance(value, str):
        if len(value) > 512 or (value.startswith("$") and value not in _PLACEHOLDERS):
            raise ValueError("invalid recipe body value")
        if SecretRedactor().text(value) != value:
            raise ValueError("recipe body contains credential-like data")
    elif value is not None and type(value) not in {bool, int, float}:
        raise ValueError("invalid recipe body value")


def json_pointer(value: object, pointer: str) -> object:
    if not isinstance(pointer, str) or not _POINTER.fullmatch(pointer):
        raise ValueError("invalid recipe JSON pointer")
    item = value
    for raw in pointer.split("/")[1:]:
        key = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(item, dict):
            item = item[key]
        elif isinstance(item, list) and key.isdecimal():
            item = item[int(key)]
        else:
            raise ValueError("recipe response path is missing")
    return item


def external_id(value: object) -> str:
    if not isinstance(value, str) or not _EXTERNAL_ID.fullmatch(value):
        raise ValueError("unsafe or missing object identifier")
    return value


@dataclass(frozen=True, slots=True)
class RecipeOperation:
    method: str
    url: str
    operation: str
    body: object | None = None
    side_effect: SideEffect | None = None

    def __post_init__(self) -> None:
        if self.method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("invalid recipe method")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_:-]{0,127}", self.operation):
            raise ValueError("invalid recipe operation")
        if self.side_effect is not None and not isinstance(self.side_effect, SideEffect):
            raise ValueError("invalid recipe side effect")
        candidate = self.url.replace("{object_id}", "fixture123").replace("{parent_id}", "fixture123")
        if (_strict_url_reason(candidate) is not None or self.url.count("{object_id}") > 1
                or self.url.count("{parent_id}") > 1 or
                re.search(r"\{[^}]*\}", candidate) is not None):
            raise ValueError("invalid recipe URL")
        if urlsplit(candidate).query:
            raise ValueError("recipe URLs must not contain query strings")
        _validate_body(self.body)
        if self.body is not None and self.method in {"GET", "HEAD"}:
            raise ValueError("read operation cannot have a body")

    def template(self, *, test_name: str, parent_id: str | None = None,
                 object_id: str | None = None) -> RequestTemplate:
        values = {"$test_name": test_name, "$parent_id": parent_id, "$object_id": object_id}
        url = self.url
        for token, value in (("{parent_id}", parent_id), ("{object_id}", object_id)):
            if token in url:
                if value is None:
                    raise ValueError("recipe prerequisite identifier is missing")
                url = url.replace(token, external_id(value))
        if _strict_url_reason(url) is not None:
            raise ValueError("rendered recipe URL is unsafe")

        def render(value: object) -> object:
            if isinstance(value, str) and value in values:
                actual = values[value]
                if actual is None:
                    raise ValueError("recipe prerequisite value is missing")
                return actual
            if isinstance(value, dict):
                return {key: render(item) for key, item in value.items()}
            if isinstance(value, list):
                return [render(item) for item in value]
            return value

        body = json.dumps(render(self.body), separators=(",", ":")).encode() if self.body is not None else None
        if body is not None and len(body) > 16384:
            raise ValueError("rendered recipe body exceeds limit")
        return RequestTemplate(self.method, url,
                               (("Content-Type", "application/json"),) if body else (), body)


@dataclass(frozen=True, slots=True)
class ObjectRecipe:
    id: str
    target_id: str
    package_id: str
    object_type: str
    protocol: str
    create: RecipeOperation
    verify: RecipeOperation
    cleanup: RecipeOperation | None
    update: RecipeOperation | None
    id_pointer: str
    verify_id_pointer: str
    verify_name_pointer: str
    verify_owner_pointer: str
    verify_tenant_pointer: str
    expected_owner: str
    expected_tenant: str
    parent_type: str | None
    cleanup_strategy: CleanupStrategy
    source: str
    sha256: str

    @classmethod
    def from_json(cls, data: object) -> ObjectRecipe:
        obj = _mapping(data, {"id", "target_id", "package_id", "object_type", "protocol",
                              "create", "verify", "cleanup", "update", "id_pointer",
                              "verify_id_pointer", "verify_name_pointer", "verify_owner_pointer",
                              "verify_tenant_pointer", "expected_owner", "expected_tenant",
                              "parent_type", "cleanup_strategy", "source"},
                       {"id", "target_id", "package_id", "object_type", "protocol", "create",
                        "verify", "id_pointer", "verify_id_pointer", "verify_name_pointer",
                        "verify_owner_pointer", "verify_tenant_pointer", "expected_owner",
                        "expected_tenant", "cleanup_strategy", "source"})
        validate_entity_id(obj["target_id"], "TARGET")
        for key in ("id", "package_id", "object_type", "source"):
            if not isinstance(obj[key], str) or not _LABEL.fullmatch(obj[key]):
                raise ValueError("invalid object recipe label")
        if obj["object_type"] in _PROVISIONING_TYPES:
            raise ValueError("account or tenant provisioning is outside the object factory")
        parent_type = obj.get("parent_type")
        if parent_type is not None and (not isinstance(parent_type, str) or not _LABEL.fullmatch(parent_type)):
            raise ValueError("invalid parent type")
        if obj["protocol"] not in {"REST", "GRAPHQL", "RPC"}:
            raise ValueError("invalid recipe protocol")
        for key in ("expected_owner", "expected_tenant"):
            if (not isinstance(obj[key], str) or not _EXTERNAL_ID.fullmatch(obj[key]) or
                    SecretRedactor().text(obj[key]) != obj[key]):
                raise ValueError("invalid expected fixture identity")
        pointers = tuple(obj[key] for key in ("id_pointer", "verify_id_pointer", "verify_name_pointer",
                                                "verify_owner_pointer", "verify_tenant_pointer"))
        if any(not isinstance(pointer, str) or not _POINTER.fullmatch(pointer) for pointer in pointers):
            raise ValueError("invalid recipe extraction pointer")

        def operation(key: str) -> RecipeOperation | None:
            raw = obj.get(key)
            if raw is None:
                return None
            value = _mapping(raw, {"method", "url", "operation", "body", "side_effect"},
                             {"method", "url", "operation"})
            if "side_effect" in value:
                value = {**value, "side_effect": SideEffect(value["side_effect"])}
            return RecipeOperation(**value)

        create, verify, cleanup, update = (operation(key) for key in ("create", "verify", "cleanup", "update"))
        assert create is not None and verify is not None
        strategy = CleanupStrategy(obj["cleanup_strategy"])
        if (create.method not in {"POST", "PUT"} or verify.method != "GET" or
                cleanup is not None and cleanup.method != "DELETE" or
                update is not None and update.method not in {"PATCH", "PUT"} or
                strategy is CleanupStrategy.AUTO_CLEANUP and cleanup is None or
                strategy is CleanupStrategy.NO_CLEANUP_REQUIRED and cleanup is not None or
                "{object_id}" not in verify.url or
                update is not None and "{object_id}" not in update.url or
                cleanup is not None and "{object_id}" not in cleanup.url):
            raise ValueError("unsupported object recipe operation")
        fingerprint = hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return cls(obj["id"], obj["target_id"], obj["package_id"], obj["object_type"],
                   obj["protocol"], create, verify, cleanup, update, *pointers,
                   obj["expected_owner"], obj["expected_tenant"],
                   parent_type, strategy, obj["source"], fingerprint)


class RecipeCatalog:
    def __init__(self, settings: ObjectSettings) -> None:
        self.settings = settings

    def get(self, package_id: str, recipe_id: str) -> ObjectRecipe | None:
        if not _LABEL.fullmatch(package_id) or not _LABEL.fullmatch(recipe_id):
            raise ValueError("invalid recipe selection")
        root = self.settings.recipe_root.resolve()
        path = (root / package_id / (recipe_id + ".json")).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            return None
        if path.stat().st_size > 65536:
            raise ValueError("recipe file is too large")
        try:
            recipe = ObjectRecipe.from_json(json.loads(path.read_text(encoding="utf-8")))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid recipe file") from exc
        if recipe.package_id != package_id or recipe.id != recipe_id:
            raise ValueError("recipe identity mismatch")
        return recipe

    def list_for_package(self, package_id: str) -> tuple[dict[str, str], ...]:
        if not _LABEL.fullmatch(package_id):
            raise ValueError("invalid package")
        folder = (self.settings.recipe_root.resolve() / package_id).resolve()
        if not folder.is_relative_to(self.settings.recipe_root.resolve()) or not folder.is_dir():
            return ()
        items: list[dict[str, str]] = []
        for path in sorted(folder.glob("*.json"))[:50]:
            if not _LABEL.fullmatch(path.stem):
                continue
            recipe = self.get(package_id, path.stem)
            if recipe is not None:
                items.append({"id": recipe.id, "object_type": recipe.object_type,
                              "protocol": recipe.protocol, "cleanup_strategy": recipe.cleanup_strategy.value})
        return tuple(items)
