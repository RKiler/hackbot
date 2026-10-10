"""Read-only local command-line interface."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Mapping, Sequence, TextIO

from . import __version__
from .config import AppConfig, ConfigError, load_config
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
        "phase": 5,
        "runtime": "local_cli_recon_adapter_evidence_fact_store_domain_models_and_target_packages",
        "recon_integration": "adapter_available_not_connected",
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

    result = _health(config) if args.command == "health" else _status(config)
    print(json.dumps(result, sort_keys=True), file=out)
    return 0 if args.command == "status" or result["status"] == "ok" else 1
