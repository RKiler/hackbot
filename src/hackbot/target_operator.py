"""Operator-safe TargetPackage file creation and account metadata updates."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
import shutil
import stat
from tempfile import TemporaryDirectory

import yaml

from .domain import new_entity_id, normalize_hostname
from .target_loader import (TargetPackageRepository, _load_yaml, _read_bytes,
                            load_target_package)
from .target_package import AccountReference, TargetPackage
from .target_policy import (AUTONOMY_ACTION_FIELDS, AUTONOMY_RISK_FIELDS,
                            PolicyDecision, RatePolicy)
from .target_scope import HostRule, ScopeSourceKind, validate_package_id


class TargetSetupError(ValueError):
    def __init__(self, code: str, field: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.field = field


def _object(value: object, fields: set[str], field: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) - fields:
        raise TargetSetupError("invalid_field", field)
    return value


def _text(value: object, field: str, maximum: int = 256) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise TargetSetupError("invalid_field", field)
    return value.strip()


def _hosts(value: object, field: str, *, required: bool) -> list[str]:
    if not isinstance(value, list) or len(value) > 100 or (required and not value):
        raise TargetSetupError("invalid_field", field)
    try:
        hosts = [HostRule(_text(item, field, 255)).pattern for item in value]
    except ValueError:
        raise TargetSetupError("invalid_field", field) from None
    if len(set(hosts)) != len(hosts):
        raise TargetSetupError("duplicate_host", field)
    return hosts


def _yaml_bytes(value: dict[str, object]) -> bytes:
    return yaml.safe_dump(value, sort_keys=False, allow_unicode=False).encode("utf-8")


def _write_exclusive(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _sync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class TargetPackageOperator:
    """Persist only the existing target.yaml/accounts.yaml format, never recon data."""

    def __init__(self, repository: TargetPackageRepository) -> None:
        self.repository = repository

    def create(self, body: object) -> TargetPackage:
        data = _object(body, {"name", "id", "primary_domain", "scope", "source", "rules",
                              "autonomy", "rate", "confirmed"}, "target")
        if data.get("confirmed") is not True:
            raise TargetSetupError("confirmation_required", "confirmed")
        try:
            package_id = validate_package_id(data.get("id"))
        except ValueError:
            raise TargetSetupError("invalid_field", "id") from None
        name = _text(data.get("name"), "name")
        try:
            primary = normalize_hostname(_text(data.get("primary_domain"), "primary_domain", 255))
        except ValueError:
            raise TargetSetupError("invalid_field", "primary_domain") from None
        scope = _object(data.get("scope"), {"include", "exclude", "schemes", "ports"}, "scope")
        included = _hosts(scope.get("include"), "scope.include", required=True)
        excluded = _hosts(scope.get("exclude", []), "scope.exclude", required=False)
        if set(included) & set(excluded):
            raise TargetSetupError("conflicting_host", "scope.exclude")
        if primary not in included or any(HostRule(host).matches_host(primary) for host in excluded):
            raise TargetSetupError("primary_host_must_be_included", "primary_domain")
        schemes = scope.get("schemes", ["https"])
        ports = scope.get("ports", [443])
        if (not isinstance(schemes, list) or not schemes or len(schemes) > 2
                or any(item not in {"http", "https"} for item in schemes)
                or len(set(schemes)) != len(schemes)):
            raise TargetSetupError("invalid_field", "scope.schemes")
        if (not isinstance(ports, list) or not ports or len(ports) > 32
                or any(type(item) is not int or not 1 <= item <= 65535 for item in ports)
                or len(set(ports)) != len(ports)):
            raise TargetSetupError("invalid_field", "scope.ports")
        source = _object(data.get("source"), {"kind", "reference", "operator"}, "source")
        try:
            kind = ScopeSourceKind(source.get("kind"))
        except ValueError:
            raise TargetSetupError("invalid_field", "source.kind") from None
        reference = _text(source.get("reference"), "source.reference", 2048)
        operator = _text(source.get("operator"), "source.operator", 128)
        rules = _object(data.get("rules"), {"automated_testing_allowed", "account_creation_allowed",
                                             "data_handling_restrictions", "forbidden_actions"}, "rules")
        if (type(rules.get("automated_testing_allowed")) is not bool
                or type(rules.get("account_creation_allowed")) is not bool):
            raise TargetSetupError("invalid_field", "rules")
        restrictions = rules.get("data_handling_restrictions")
        if restrictions is not None and restrictions != "":
            restrictions = _text(restrictions, "rules.data_handling_restrictions", 2048)
        else:
            restrictions = None
        forbidden = rules.get("forbidden_actions", [])
        if not isinstance(forbidden, list) or len(forbidden) > 50:
            raise TargetSetupError("invalid_field", "rules.forbidden_actions")
        forbidden = [_text(item, "rules.forbidden_actions", 128) for item in forbidden]
        policy = _object(data.get("autonomy"),
                         set(AUTONOMY_RISK_FIELDS + AUTONOMY_ACTION_FIELDS), "autonomy")
        if not set(AUTONOMY_RISK_FIELDS).issubset(policy):
            raise TargetSetupError("invalid_field", "autonomy")
        for field in policy:
            if not isinstance(policy[field], str) or policy[field] not in {item.value for item in PolicyDecision}:
                raise TargetSetupError("invalid_field", f"autonomy.{field}")
        rate = _object(data.get("rate"), set(RatePolicy.__dataclass_fields__), "rate")
        if set(rate) != set(RatePolicy.__dataclass_fields__):
            raise TargetSetupError("invalid_field", "rate")
        try:
            RatePolicy(**rate)
        except (TypeError, ValueError):
            raise TargetSetupError("invalid_field", "rate") from None

        now = datetime.now(timezone.utc).isoformat()
        document: dict[str, object] = {
            "version": 1, "id": package_id, "target_id": new_entity_id("TARGET"),
            "name": name, "primary_domain": primary, "status": "TRACKED",
            "configured_at": now, "updated_at": now,
            "source": {"kind": kind.value, "reference": reference, "operator": operator},
            "scope": {"include": included, "exclude": excluded, "schemes": schemes, "ports": ports},
            "rules": {"automated_testing_allowed": rules["automated_testing_allowed"],
                      "account_creation_allowed": rules["account_creation_allowed"],
                      "forbidden_actions": forbidden,
                      **({"data_handling_restrictions": restrictions} if restrictions else {})},
            "autonomy": policy, "rate": rate,
        }
        root = self.repository.root
        if root.is_symlink():
            raise TargetSetupError("unsafe_target_root")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not root.is_dir():
            raise TargetSetupError("unsafe_target_root")
        with TemporaryDirectory(prefix=".target-stage-", dir=root) as temp:
            staging = Path(temp) / package_id
            staging.mkdir(mode=0o700)
            _write_exclusive(staging / "target.yaml", _yaml_bytes(document))
            try:
                validated = load_target_package(staging)
            except ValueError:
                raise TargetSetupError("invalid_target_package") from None
            document["rules"]["forbidden_actions"] = list(validated.rules.forbidden_actions)
            content = _yaml_bytes(document)
            (staging / "target.yaml").unlink()
            _write_exclusive(staging / "target.yaml", content)
            load_target_package(staging)
            final = root / package_id
            try:
                os.mkdir(final, 0o700)
            except FileExistsError:
                raise TargetSetupError("duplicate_target", "id") from None
            try:
                os.replace(staging / "target.yaml", final / "target.yaml")
                _sync_dir(final)
                _sync_dir(root)
                return load_target_package(final)
            except BaseException:
                (final / "target.yaml").unlink(missing_ok=True)
                final.rmdir()
                raise

    def accounts(self, package_id: str) -> tuple[AccountReference, ...]:
        package = self.repository.get_target_package(package_id)
        if package is None:
            raise LookupError("target package not found")
        return package.accounts

    def delete(self, package_id: str) -> None:
        """Remove only a validated file-backed package; registries remain historical."""
        try:
            slug = validate_package_id(package_id)
        except ValueError:
            raise TargetSetupError("invalid_field", "id") from None
        root = self.repository.root
        path = root / slug
        if (root.is_symlink() or not root.is_dir() or path.is_symlink()
                or not path.is_dir()):
            raise TargetSetupError("unsafe_target_path")
        if self.repository.get_target_package(slug) is None:
            raise LookupError("target package not found")
        entries = list(path.iterdir())
        if len(entries) > 32 or any(not stat.S_ISREG(item.lstat().st_mode) for item in entries):
            raise TargetSetupError("unsafe_target_path")
        if not shutil.rmtree.avoids_symlink_attacks:
            raise TargetSetupError("unsafe_target_path")
        hidden = root / (".deleted-target-" + secrets.token_hex(16))
        os.replace(path, hidden)
        _sync_dir(root)
        shutil.rmtree(hidden)
        _sync_dir(root)

    def save_accounts(self, package_id: str, value: object, *, registered_aliases: set[str]) -> TargetPackage:
        package = self.repository.get_target_package(package_id)
        if package is None:
            raise LookupError("target package not found")
        data = _object(value, {"accounts"}, "accounts")
        rows = data.get("accounts")
        if not isinstance(rows, list) or len(rows) > 20:
            raise TargetSetupError("invalid_field", "accounts")
        accounts: dict[str, dict[str, str]] = {}
        for raw in rows:
            row = _object(raw, {"alias", "tenant", "role"}, "accounts")
            try:
                alias = validate_package_id(row.get("alias"))
            except ValueError:
                raise TargetSetupError("invalid_field", "accounts.alias") from None
            try:
                tenant = _text(row["tenant"], "accounts.tenant", 128) if row.get("tenant") else None
                role = _text(row["role"], "accounts.role", 128) if row.get("role") else None
                AccountReference(alias, role_hint=role, tenant_hint=tenant)
            except (ValueError, KeyError):
                raise TargetSetupError("invalid_field", "accounts") from None
            if role and not tenant:
                raise TargetSetupError("role_requires_tenant", "accounts.role")
            if alias in accounts:
                raise TargetSetupError("duplicate_account", "accounts.alias")
            accounts[alias] = {**({"tenant": tenant} if tenant else {}),
                               **({"role": role} if role else {})}
        previous = {item.alias: item for item in package.accounts}
        for alias in registered_aliases:
            old = previous.get(alias)
            new = accounts.get(alias)
            if (old is None or new is None or new.get("tenant") != old.tenant_hint
                    or new.get("role") != old.role_hint):
                raise TargetSetupError("registered_account_immutable", "accounts")
        target_doc = _load_yaml(package.package_dir / "target.yaml", 65536)
        name = target_doc.get("accounts_file", "accounts.yaml")
        if not isinstance(name, str) or "/" in name or "\\" in name or name in {".", ".."}:
            raise TargetSetupError("unsafe_account_file")
        account_path = package.package_dir / name
        if account_path.is_symlink():
            raise TargetSetupError("unsafe_account_file")
        for old in package.accounts:
            if old.alias in accounts and old.secret_ref is not None:
                accounts[old.alias]["secret_ref"] = old.secret_ref
        content = _yaml_bytes({"accounts": accounts})
        with TemporaryDirectory(prefix=".accounts-stage-", dir=self.repository.root) as temp:
            staging = Path(temp) / package.id
            staging.mkdir(mode=0o700)
            _write_exclusive(staging / "target.yaml", _read_bytes(package.package_dir / "target.yaml", 65536))
            _write_exclusive(staging / name, content)
            try:
                validated = load_target_package(staging)
            except ValueError:
                raise TargetSetupError("invalid_account_metadata", "accounts") from None
            if len(validated.accounts) != len(accounts):
                raise TargetSetupError("invalid_account_metadata", "accounts")
        temporary = package.package_dir / (".accounts-" + secrets.token_hex(12))
        try:
            _write_exclusive(temporary, content)
            if account_path.is_symlink():
                raise TargetSetupError("unsafe_account_file")
            os.replace(temporary, account_path)
            _sync_dir(package.package_dir)
            return load_target_package(package.package_dir)
        finally:
            temporary.unlink(missing_ok=True)
