"""Local CLI; only explicit identity/browser operations mutate BugHunter state."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import Mapping, Sequence, TextIO

from . import __version__
from .auth import AuthContextManager
from .browser import BrowserError, BrowserSessionManager
from .browser_playwright import PlaywrightBrowserDriver
from .burp import BurpError, BurpProxyProvider
from .config import AppConfig, ConfigError, load_config
from .identity_registry import IdentityRegistry
from .logging import SecretRedactor
from .policy import PolicyEngine
from .policy_models import ActionCategory, ActorMode, ProposedAction
from .policy_store import PolicyStore
from .secrets import RoutedSecretProvider, SecretError
from .store import EvidenceFactStore, StoreNotInitialized, StoreSchemaError
from .target_loader import TargetPackageRepository, load_target_package
from .traffic import TrafficError, TrafficExchange, TrafficStore


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
        "phase": 13,
        "runtime": "local_cli_metadata_only_private_service_separate",
        "service": "not_checked_use_private_api_status",
        "recon_integration": "adapter_available_not_connected",
        "identity_registry": "local_metadata_only_not_checked",
        "auth_contexts": "local_metadata_only_not_checked",
        "browser_sessions": "local_metadata_only_not_checked",
        "browser": {
            "profile_root": str(config.browser.profile_root) if config.browser else None,
            "dedicated_display_configured": bool(config.browser and config.browser.display),
            "vnc_configured": bool(config.browser and config.browser.vnc_url),
        },
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


def _traffic_identity_alias(store: TrafficStore, exchange: TrafficExchange) -> str:
    if exchange.attribution.verified_identity_id is None:
        return exchange.attribution.auth_state.value
    identity = store.registry.get_identity(exchange.target_id, exchange.attribution.verified_identity_id)
    return identity.alias if identity is not None else "VERIFIED_IDENTITY_UNAVAILABLE"


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
    auth = commands.add_parser("auth", help="inspect local authentication metadata")
    auth_commands = auth.add_subparsers(dest="auth_command", required=True)
    auth_status = auth_commands.add_parser("status", help="show a local AuthContext without secrets")
    auth_status.add_argument("target")
    auth_status.add_argument("identity")
    secret = commands.add_parser("secret", help="inspect configured secret availability")
    secret_commands = secret.add_subparsers(dest="secret_command", required=True)
    secret_commands.add_parser("check", help="check availability without showing a value").add_argument("secret_ref")
    browser = commands.add_parser("browser", help="inspect or manage local browser session metadata")
    browser_commands = browser.add_subparsers(dest="browser_command", required=True)
    browser_list = browser_commands.add_parser("list", help="list a target's local browser sessions")
    browser_list.add_argument("target")
    browser_list.add_argument("--limit", type=int, default=20)
    browser_list.add_argument("--cursor")
    browser_status = browser_commands.add_parser("status", help="show one local browser session")
    browser_status.add_argument("session")
    browser_create = browser_commands.add_parser("create", help="create an isolated profile; does not launch")
    browser_create.add_argument("target")
    browser_create.add_argument("identity", nargs="?")
    browser_create.add_argument("--anonymous", action="store_true")
    browser_stop = browser_commands.add_parser("stop", help="stop a local browser session")
    browser_stop.add_argument("session")
    browser_reconcile = browser_commands.add_parser("reconcile", help="fail closed if a browser process is unavailable")
    browser_reconcile.add_argument("session")
    traffic = commands.add_parser("traffic", help="inspect local protected traffic metadata")
    traffic_commands = traffic.add_subparsers(dest="traffic_command", required=True)
    traffic_list = traffic_commands.add_parser("list", help="page a target's exchanges")
    traffic_list.add_argument("target")
    traffic_list.add_argument("--limit", type=int, default=20)
    traffic_list.add_argument("--cursor")
    traffic_show = traffic_commands.add_parser("show", help="show one redacted exchange")
    traffic_show.add_argument("exchange")
    traffic_stats = traffic_commands.add_parser("stats", help="bounded target traffic sample")
    traffic_stats.add_argument("target")
    traffic_stats.add_argument("--sample-limit", type=int, default=1000)
    burp = commands.add_parser("burp", help="inspect local Burp capture metadata")
    burp_commands = burp.add_subparsers(dest="burp_command", required=True)
    burp_commands.add_parser("check", help="check configured local Burp availability")
    burp_status = burp_commands.add_parser("status", help="show local Burp capture status")
    burp_status.add_argument("target", nargs="?")
    burp_listeners = burp_commands.add_parser("listeners", help="list target listener bindings")
    burp_listeners.add_argument("target")
    burp_listeners.add_argument("--limit", type=int, default=50)
    burp_bridge = burp_commands.add_parser("bridge", help="inspect local bridge heartbeat")
    burp_bridge_commands = burp_bridge.add_subparsers(dest="burp_bridge_command", required=True)
    burp_bridge_status = burp_bridge_commands.add_parser("status", help="show target bridge status")
    burp_bridge_status.add_argument("target")
    policy = commands.add_parser("policy", help="simulate deterministic policy without sending traffic")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    policy_check = policy_commands.add_parser("check", help="check one hypothetical action")
    policy_check.add_argument("target")
    policy_check.add_argument("url")
    policy_check.add_argument("--action", choices=("safe-read", "http-request", "browser-navigation"),
                              default="safe-read")
    policy_check.add_argument("--method", choices=("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"),
                              default="GET")
    approvals = commands.add_parser("approvals", help="inspect local target-scoped approvals")
    approvals_commands = approvals.add_subparsers(dest="approvals_command", required=True)
    approvals_list = approvals_commands.add_parser("list", help="list approval requests")
    approvals_list.add_argument("target")
    approvals_list.add_argument("--limit", type=int, default=20)
    approvals_list.add_argument("--cursor")
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"hackbot {__version__}", file=out)
        return 0

    try:
        config = load_config(args.config, environ=environ)
    except ConfigError as exc:
        print(f"hackbot: {exc}", file=err)
        return 2

    if args.command in {"policy", "approvals"}:
        try:
            assert config.targets is not None
            package = TargetPackageRepository(config.targets.root).get_target_package(args.target)
            if package is None:
                print("hackbot: target package not found", file=err)
                return 1
            store = EvidenceFactStore.from_config(config)
            if args.command == "policy":
                store.initialize()
                category = {
                    "safe-read": ActionCategory.SAFE_READ,
                    "http-request": ActionCategory.HTTP_REQUEST,
                    "browser-navigation": ActionCategory.BROWSER_NAVIGATION,
                }[args.action]
                action = ProposedAction(
                    target_id=package.target.id, package_id=package.id, category=category,
                    actor=ActorMode.ANONYMOUS, source="operator_cli",
                    purpose="Operator policy simulation", url=args.url, method=args.method,
                )
                decision = PolicyEngine(audit=PolicyStore(store)).evaluate(package, action)
                result = {"action_id": action.id, "decision": decision.to_dict(),
                          "simulation_only": True, "request_sent": False}
            else:
                result = PolicyStore(store).list(package.target.id, limit=args.limit,
                                                 cursor=args.cursor)
        except (ValueError, TypeError, OSError, StoreNotInitialized, StoreSchemaError,
                sqlite3.Error):
            print("hackbot: policy metadata is unavailable or input is invalid", file=err)
            return 2
        print(json.dumps(result, sort_keys=True), file=out)
        return 0

    if args.command == "burp":
        assert config.burp is not None
        if args.burp_command == "check":
            provider = BurpProxyProvider(config.burp, TrafficStore.from_config(config))
            print(json.dumps({"enabled": config.burp.enabled,
                              "availability": provider.availability().value,
                              "bridge_configured": config.burp.bridge_secret_ref is not None,
                              "ca_configured": config.burp.ca_certificate is not None},
                             sort_keys=True), file=out)
            return 0
        try:
            assert config.targets is not None
            target_name = getattr(args, "target", None)
            package = TargetPackageRepository(config.targets.root).get_target_package(target_name) if target_name else None
            if target_name and package is None:
                print("hackbot: target package not found", file=err)
                return 1
            provider = BurpProxyProvider(config.burp, TrafficStore.from_config(config))
            target_id = package.target.id if package else None
            if args.burp_command == "listeners":
                result = {"target": package.id,
                          "items": [item.to_dict() for item in provider.list_bindings(target_id, limit=args.limit)]}
            elif args.burp_command == "bridge":
                state = provider.status(target_id)
                result = {"target": package.id, "connected": state["bridge_connected"],
                          "dropped_events": state["dropped_events"],
                          "last_heartbeat_at": state["last_heartbeat_at"]}
            else:
                result = provider.status(target_id)
        except (BurpError, ValueError, OSError, TypeError, sqlite3.Error,
                StoreNotInitialized, StoreSchemaError):
            print("hackbot: Burp metadata is unavailable or input is invalid", file=err)
            return 2
        print(json.dumps(result, sort_keys=True), file=out)
        return 0

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

    if args.command == "secret":
        try:
            assert config.secrets is not None
            metadata = RoutedSecretProvider(config.secrets, environ).metadata(args.secret_ref)
            result = metadata.to_dict()
        except (SecretError, ValueError):
            result = {"available": False, "provider": None, "kind": "UNKNOWN"}
        print(json.dumps(result, sort_keys=True), file=out)
        return 0 if result["available"] else 1

    if args.command == "traffic":
        try:
            assert config.targets is not None
            store = TrafficStore.from_config(config)
            if args.traffic_command == "show":
                exchange = store.get_exchange(args.exchange)
                if exchange is None:
                    print("hackbot: exchange not found", file=err)
                    return 1
                result = exchange.to_dict()
                result["identity_alias"] = _traffic_identity_alias(store, exchange)
            else:
                package = TargetPackageRepository(config.targets.root).get_target_package(args.target)
                if package is None:
                    print("hackbot: target package not found", file=err)
                    return 1
                if args.traffic_command == "list":
                    page = store.list_exchanges_for_target(package.target.id, limit=args.limit, cursor=args.cursor)
                    result = {"target": package.id, "items": [
                        {"id": item.id, "method": item.request.record.method,
                         "origin": item.request.origin, "path": item.request.display_path,
                         "status": item.response.record.status_code if item.response else None,
                         "identity_alias": _traffic_identity_alias(store, item),
                         "auth_state": item.attribution.auth_state.value,
                         "declared_tenant_ids": list(item.attribution.declared_tenant_ids),
                         "declared_role_ids": list(item.attribution.declared_role_ids),
                         "source": item.source.value, "observed_at": item.observed_at.isoformat(),
                         "fingerprint": item.request.structural_fingerprint,
                         "scope": item.scope_result.value, "state": item.state.value}
                        for item in page.items], "next_cursor": page.next_cursor}
                else:
                    result = store.stats(package.target.id, sample_limit=args.sample_limit)
        except (TrafficError, ValueError, OSError, TypeError, sqlite3.Error,
                StoreNotInitialized, StoreSchemaError):
            print("hackbot: traffic metadata is unavailable or input is invalid", file=err)
            return 2
        print(json.dumps(result, sort_keys=True), file=out)
        return 0

    if args.command == "browser":
        try:
            assert config.browser is not None and config.secrets is not None and config.targets is not None
            registry = IdentityRegistry.from_config(config)
            manager = BrowserSessionManager(
                registry, AuthContextManager(registry, RoutedSecretProvider(config.secrets, environ)),
                PlaywrightBrowserDriver(config.browser.chromium_executable), config.browser,
            )
            if args.browser_command in {"list", "create"}:
                package = TargetPackageRepository(config.targets.root).get_target_package(args.target)
                if package is None or registry.target_id_for_package(package.id) != package.target.id:
                    print("hackbot: target is not registered locally", file=err)
                    return 1
                if args.browser_command == "list":
                    page = manager.list_sessions_for_target(package.target.id, limit=args.limit, cursor=args.cursor)
                    result = {"items": [item.to_dict() for item in page.items], "next_cursor": page.next_cursor}
                else:
                    if args.anonymous and args.identity or not args.anonymous and not args.identity:
                        raise BrowserError("Specify one identity or --anonymous")
                    identity_record = None if args.anonymous else registry.get_identity(package.target.id, args.identity)
                    if not args.anonymous and identity_record is None:
                        print("hackbot: identity not registered for target", file=err)
                        return 1
                    result = manager.create(package.target.id, identity_record.id if identity_record else None).to_dict()
            elif args.browser_command == "status":
                session = manager.get(args.session)
                if session is None:
                    print("hackbot: browser session not found", file=err)
                    return 1
                result = {"session": session.to_dict(), "context": manager.session_context(session.id).to_dict()}
            elif args.browser_command == "stop":
                result = manager.stop(args.session).to_dict()
            else:
                result = manager.reconcile_stale(args.session).to_dict()
        except (ValueError, OSError, TypeError, sqlite3.Error, StoreNotInitialized, StoreSchemaError):
            print("hackbot: browser metadata is unavailable or input is invalid", file=err)
            return 2
        print(json.dumps(result, sort_keys=True), file=out)
        return 0

    if args.command == "auth":
        try:
            assert config.targets is not None and config.secrets is not None
            package = TargetPackageRepository(config.targets.root).get_target_package(args.target)
            if package is None:
                print("hackbot: target package not found", file=err)
                return 1
            registry = IdentityRegistry.from_config(config)
            identity_record = registry.get_identity(package.target.id, args.identity)
            if identity_record is None:
                print("hackbot: identity not found for target", file=err)
                return 1
            context = AuthContextManager(registry, RoutedSecretProvider(config.secrets, environ)).get(
                package.target.id, identity_record.id
            )
            result = context.to_dict() if context else {
                "target_id": package.target.id, "identity_id": identity_record.id,
                "status": "UNINITIALIZED", "preparation": "UNKNOWN",
            }
        except (ValueError, OSError, TypeError, sqlite3.Error, StoreNotInitialized, StoreSchemaError):
            print("hackbot: authentication metadata is unavailable or input is invalid", file=err)
            return 2
        print(json.dumps(result, sort_keys=True), file=out)
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
