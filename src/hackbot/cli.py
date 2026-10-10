"""Read-only local command-line interface."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import Mapping, Sequence, TextIO

from . import __version__
from .config import AppConfig, ConfigError, load_config
from .identity_registry import IdentityRegistry
from .logging import SecretRedactor
from .store import StoreNotInitialized, StoreSchemaError
from .target_loader import TargetPackageRepository, load_target_package


def _nearest_existing(path: Path) -> Path:
    current = path
    while not current.exists() and current != current.parent:
        current = current.parent
    return current


def _local_root_check(config: AppConfig) -> str:
    root = config.paths.root
    if root.exists():
        if not root.is_dir():
            return "not_a_directory"
        return "writable" if os.access(root, os.W_OK | os.X_OK) else "not_writable"
    ancestor = _nearest_existing(root)
    if not ancestor.is_dir() or not os.access(ancestor, os.W_OK | os.X_OK):
        return "parent_not_writable"
    return "not_initialized"


def _health(config: AppConfig) -> dict[str, object]:
    root_check = _local_root_check(config)
    return {
        "status": "ok" if root_check in {"writable", "not_initialized"} else "error",
        "version": __version__,
        "checks": {
            "configuration": "valid",
            "local_root": root_check,
            "python": "ok" if sys.version_info >= (3, 11) else "unsupported",
        },
        "recon_integration": "adapter_available_not_checked",
    }


def _status(config: AppConfig) -> dict[str, object]:
    paths = config.paths
    return {
        "version": __version__,
        "phase": 6,
        "runtime": "local_cli_recon_adapter_evidence_fact_store_domain_models_target_packages_and_identity_registry",
        "recon_integration": "adapter_available_not_connected",
        "identity_registry": "local_metadata_only_not_checked",
        "target_packages": {
            "authority": "TARGET_PACKAGE",
            "recon_inventory": "NOT_CONSULTED",
            "root": str(config.targets.root) if config.targets else None,
        },
        "evidence_store": {
            "path": str(paths.state / "bughunter.sqlite3"),
            "exists": (paths.state / "bughunter.sqlite3").is_file(),
            "artifact_root": str(config.store.artifact_root) if config.store else None,
        },
        "local_paths": {
            name: {"path": str(path), "exists": path.is_dir()}
            for name, path in (
                ("root", paths.root),
                ("state", paths.state),
                ("artifacts", paths.artifacts),
                ("logs", paths.logs),
                ("evidence", paths.evidence),
                ("temporary", paths.temporary),
            )
        },
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    parser = argparse.ArgumentParser(prog="hackbot", description="BugHunter Agent foundation")
    parser.add_argument("--config", type=Path, help="local TOML configuration file")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="print installed version")
    commands.add_parser("health", help="check local configuration and prerequisites")
    commands.add_parser("status", help="show local BugHunter state")
    target = commands.add_parser("target", help="inspect local authoritative target packages")
    target_commands = target.add_subparsers(dest="target_command", required=True)
    target_commands.add_parser("validate", help="validate one package directory").add_argument("path", type=Path)
    target_commands.add_parser("show", help="show one configured package").add_argument("id")
    identity = commands.add_parser("identity", help="inspect local identity metadata")
    identity_commands = identity.add_subparsers(dest="identity_command", required=True)
    list_command = identity_commands.add_parser("list", help="list a target's identities")
    list_command.add_argument("target")
    list_command.add_argument("--limit", type=int, default=20)
    list_command.add_argument("--cursor")
    identity_commands.add_parser("import", help="import declared account metadata into local state").add_argument("target")
    show_command = identity_commands.add_parser("show", help="show an identity and its memberships")
    show_command.add_argument("target")
    show_command.add_argument("alias")
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"hackbot {__version__}", file=out)
        return 0

    try:
        config = load_config(args.config, environ=environ)
    except ConfigError as exc:
        print(f"hackbot: {exc}", file=err)
        return 2

    if args.command == "target":
        try:
            if args.target_command == "validate":
                package = load_target_package(args.path)
            else:
                assert config.targets is not None
                package = TargetPackageRepository(config.targets.root).get_target_package(args.id)
                if package is None:
                    print("hackbot: target package not found", file=err)
                    return 1
        except (ValueError, OSError, TypeError):
            print("hackbot: invalid target package or package configuration", file=err)
            return 2
        print(package.to_json(), file=out)
        return 0

    if args.command == "identity":
        try:
            assert config.targets is not None
            package = TargetPackageRepository(config.targets.root).get_target_package(args.target)
            if package is None:
                print("hackbot: target package not found", file=err)
                return 1
            registry = IdentityRegistry.from_config(config)
            if args.identity_command == "import":
                registry.initialize()
                imported = registry.import_package_accounts(package)
                result = {
                    "authority": "TARGET_PACKAGE_AND_LOCAL_IDENTITY_REGISTRY",
                    "recon_inventory": "NOT_CONSULTED",
                    "target": package.id,
                    "imported_aliases": [item.alias for item in imported],
                    "count": len(imported),
                }
                print(json.dumps(result, sort_keys=True), file=out)
                return 0
            if registry.target_id_for_package(package.id) != package.target.id:
                print("hackbot: target is not registered in local identity state", file=err)
                return 1
            if args.identity_command == "list":
                page = registry.list_identities(package.target.id, limit=args.limit, cursor=args.cursor)
                result = {
                    "authority": "TARGET_PACKAGE_AND_LOCAL_IDENTITY_REGISTRY",
                    "recon_inventory": "NOT_CONSULTED",
                    "target": package.id,
                    "items": [item.to_dict() for item in page.items],
                    "next_cursor": page.next_cursor,
                }
            else:
                record = registry.get_identity(package.target.id, args.alias)
                if record is None:
                    print("hackbot: identity not found for target", file=err)
                    return 1
                memberships = registry.list_memberships(record.id, limit=50)
                principal_links = registry.list_principal_links(record.id, limit=50)
                redactor = SecretRedactor()
                relationships = []
                for membership in memberships.items:
                    tenant = registry.get_tenant(package.target.id, membership.tenant_id)
                    roles = [registry.get_role(package.target.id, role_id) for role_id in membership.role_ids]
                    relationships.append({
                        **membership.to_dict(),
                        "tenant_label": redactor.text(tenant.label) if tenant else None,
                        "roles": [{"id": role.id, "name": redactor.text(role.name)}
                                  for role in roles if role is not None],
                    })
                result = {
                    "authority": "TARGET_PACKAGE_AND_LOCAL_IDENTITY_REGISTRY",
                    "recon_inventory": "NOT_CONSULTED",
                    "target": package.id,
                    "identity": record.to_dict(),
                    "principal_links": [link.to_dict() for link in principal_links.items],
                    "principal_conflict_in_page": len({link.principal_id for link in principal_links.items}) > 1,
                    "principal_links_next_cursor": principal_links.next_cursor,
                    "memberships": relationships,
                    "memberships_next_cursor": memberships.next_cursor,
                }
        except (ValueError, OSError, TypeError, sqlite3.Error, StoreNotInitialized, StoreSchemaError):
            print("hackbot: identity registry is unavailable or input is invalid", file=err)
            return 2
        print(json.dumps(result, sort_keys=True), file=out)
        return 0

    result = _health(config) if args.command == "health" else _status(config)
    print(json.dumps(result, sort_keys=True), file=out)
    return 0 if args.command == "status" or result["status"] == "ok" else 1
