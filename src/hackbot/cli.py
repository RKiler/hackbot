"""Local CLI; only explicit identity/browser operations mutate BugHunter state."""

from __future__ import annotations

import argparse
from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
from typing import Mapping, Sequence, TextIO

from . import __version__
from .auth import AuthContextManager
from .backup import BackupError, BackupManager
from .backup_crypto import BackupCryptoError
from .browser import BrowserError, BrowserSessionManager
from .browser_playwright import PlaywrightBrowserDriver
from .burp import BurpError, BurpProxyProvider
from .burp_storage import inspect_burp_storage
from .config import AppConfig, ConfigError, ResourceSettings, load_config
from .db_maintenance import DatabaseCheckError, check_database
from .dom_refs import DOMReferenceError
from .dom_retention import DOMPayloadPolicy, DOMPayloadRetirementManager
from .evidence_refs import EvidenceReferenceError
from .identity_registry import IdentityRegistry
from .logging import SecretRedactor
from .policy import PolicyEngine
from .policy_models import ActionCategory, ActorMode, ProposedAction
from .policy_store import PolicyStore
from .retention import ArtifactGarbageCollector, OrphanPolicy
from .evidence_retention import EvidencePayloadPolicy, EvidencePayloadRetirementManager
from .research_retention import ResearchBriefRetentionManager, ResearchBriefRetentionPolicy
from .traffic_retention import TrafficPayloadPolicy, TrafficPayloadRetirementManager
from .traffic_refs import TrafficReferenceError
from .resources import ResourceBudgetManager, ResourceError, ResourceSnapshot
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
        "phase": 30,
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


class _PrivateConnection(http.client.HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=5)
        self.socket_path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def _operations_status() -> dict[str, object]:
    return _private_operations_request("GET", "/v1/operations")


def _private_operations_request(method: str, path: str,
                                payload: dict[str, object] | None = None) -> dict[str, object]:
    connection = _PrivateConnection("/run/bughunter-agent/control.sock")
    try:
        body = json.dumps(payload, sort_keys=True) if payload is not None else None
        headers = {"Host": "localhost"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read(524_289)
        if (response.status not in {200, 202} or len(response_body) > 524_288
                or "application/json" not in response.getheader("Content-Type", "")):
            raise OSError("Private operations status is unavailable")
        result = json.loads(response_body)
        if not isinstance(result, dict):
            raise ValueError("Invalid private operations response")
        return result
    finally:
        connection.close()


def _storage_status(config: AppConfig) -> dict[str, object]:
    from .store import _SCHEMA_VERSION

    try:
        resource = ResourceBudgetManager(config.paths.root,
                                         config.resources or ResourceSettings(),
                                         system_disk_path=Path("/")).snapshot()
    except ResourceError as exc:
        resource = ResourceSnapshot(0, 0, 100, None, "BLOCKED", (exc.reason_code,))
    database = config.paths.state / "bughunter.sqlite3"
    if database.is_symlink():
        raise ValueError("Unsafe BugHunter database path")
    actual_schema = None
    if database.is_file():
        from urllib.parse import quote
        with closing(sqlite3.connect("file:" + quote(str(database), safe="/") + "?mode=ro",
                                     uri=True, timeout=5)) as db:
            actual_schema = db.execute("PRAGMA user_version").fetchone()[0]
    wal = database.parent / (database.name + "-wal")
    backup = (BackupManager.from_config(config).latest_metadata()
              if config.backup is not None else {"state": "NOT_CONFIGURED"})
    return {"resources": resource.to_dict(),
            "database_bytes": database.stat().st_size if database.is_file() else 0,
            "wal_bytes": wal.stat().st_size if wal.is_file() and not wal.is_symlink() else 0,
            "schema_actual": actual_schema, "schema_expected": _SCHEMA_VERSION,
            "backup": backup}


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
    ops = commands.add_parser("ops", help="inspect the private BugHunter control plane")
    ops_commands = ops.add_subparsers(dest="ops_command", required=True)
    ops_commands.add_parser("status", help="read live operations status without target requests")
    ops_commands.add_parser("maintenance-status", help="read local maintenance task state")
    disabled_plan = ops_commands.add_parser(
        "disabled-profile-plan", help="review old profiles for one disabled identity")
    disabled_plan.add_argument("target_id")
    disabled_plan.add_argument("identity_id")
    disabled_run = ops_commands.add_parser(
        "disabled-profile-run", help="run a reviewed disabled-identity profile cleanup")
    disabled_run.add_argument("target_id")
    disabled_run.add_argument("identity_id")
    disabled_run.add_argument("review_id")
    disabled_run.add_argument("--confirmed", action="store_true", required=True)
    named_plan = ops_commands.add_parser(
        "named-profile-plan", help="review one old terminal active-identity profile")
    named_plan.add_argument("target_id")
    named_plan.add_argument("identity_id")
    named_plan.add_argument("session_id")
    named_run = ops_commands.add_parser(
        "named-profile-run", help="remove one reviewed active-identity profile")
    named_run.add_argument("target_id")
    named_run.add_argument("identity_id")
    named_run.add_argument("session_id")
    named_run.add_argument("review_id")
    named_run.add_argument("--confirmed", action="store_true", required=True)
    storage = commands.add_parser("storage", help="inspect local BugHunter storage")
    storage_commands = storage.add_subparsers(dest="storage_command", required=True)
    storage_commands.add_parser("status", help="read disk, database, and backup metadata")
    storage_commands.add_parser("check", help="read-only SQLite integrity and schema check")
    storage_commands.add_parser("startup-check", help="read-only service schema compatibility gate")
    backup = commands.add_parser("backup", help="manage BugHunter-owned local backups")
    backup_commands = backup.add_subparsers(dest="backup_command", required=True)
    backup_commands.add_parser("create", help="create a consistent local backup")
    backup_list = backup_commands.add_parser("list", help="list bounded local backup history")
    backup_list.add_argument("--limit", type=int, default=20)
    backup_verify = backup_commands.add_parser("verify", help="verify one backup and its hashes")
    backup_verify.add_argument("backup_id")
    backup_stage = backup_commands.add_parser("stage", help="stage a verified copy; never replace live state")
    backup_stage.add_argument("backup_id")
    backup_rehearse = backup_commands.add_parser(
        "rehearse", help="verify and migrate an isolated backup copy, then remove the staging files")
    backup_rehearse.add_argument("backup_id")
    backup_rehearse.add_argument("--max-values", type=int, default=250_000)
    backup_rehearse.add_argument("--max-seconds", type=float, default=60.0)
    backup_audit = backup_commands.add_parser(
        "audit-json-indexes", help="audit reference indexes on a verified staged backup copy")
    backup_audit.add_argument("backup_id")
    backup_audit.add_argument("--max-values", type=int, default=250_000)
    backup_audit.add_argument("--max-seconds", type=float, default=60.0)
    backup_commands.add_parser("prune-plan", help="preview old backup generations")
    backup_prune = backup_commands.add_parser("prune", help="remove generations beyond retention")
    backup_prune.add_argument("--confirmed", action="store_true")
    backup_commands.add_parser("incomplete-plan", help="preview stale unfinished backup staging")
    backup_incomplete = backup_commands.add_parser(
        "incomplete-cleanup", help="remove stale unfinished backup staging")
    backup_incomplete.add_argument("--confirmed", action="store_true")
    backup_commands.add_parser(
        "restore-staging-plan", help="preview stale decrypted restore stages")
    backup_restore_cleanup = backup_commands.add_parser(
        "restore-staging-cleanup", help="remove one reviewed stale decrypted restore stage")
    backup_restore_cleanup.add_argument("name")
    backup_restore_cleanup.add_argument("--confirmed", action="store_true")
    retention = commands.add_parser("retention", help="plan or run bounded local artifact cleanup")
    retention_commands = retention.add_subparsers(dest="retention_command", required=True)
    retention_commands.add_parser("plan", help="dry-run aged unreferenced artifact cleanup")
    retention_run = retention_commands.add_parser("run", help="remove aged unreferenced artifacts")
    retention_run.add_argument("--confirmed", action="store_true")
    retention_commands.add_parser("evidence-plan", help="review expired standalone Evidence payloads")
    evidence_run = retention_commands.add_parser("evidence-run", help="retire reviewed Evidence payloads")
    evidence_run.add_argument("--confirmed", action="store_true")
    dom_plan = retention_commands.add_parser("dom-plan", help="review expired DOM asset payloads")
    dom_plan.add_argument("--kind", choices=("JS", "SOURCE_MAP"), required=True)
    dom_plan.add_argument("--after")
    dom_run = retention_commands.add_parser("dom-run", help="retire reviewed DOM Evidence payloads")
    dom_run.add_argument("--kind", choices=("JS", "SOURCE_MAP"), required=True)
    dom_run.add_argument("--confirmed", action="store_true")
    retention_commands.add_parser("traffic-plan", help="review expired TrafficStore payloads")
    traffic_run = retention_commands.add_parser("traffic-run", help="retire reviewed TrafficStore payloads")
    traffic_run.add_argument("--confirmed", action="store_true")
    retention_commands.add_parser("research-plan", help="review expired unlinked ResearchBrief cache payloads")
    research_run = retention_commands.add_parser("research-run", help="retire reviewed ResearchBrief cache payloads")
    research_run.add_argument("--confirmed", action="store_true")
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
    burp_commands.add_parser("storage", help="inspect bounded Burp runtime storage usage")
    burp_commands.add_parser("temp-plan", help="review abandoned Burp launcher temp directories")
    burp_temp_run = burp_commands.add_parser(
        "temp-run", help="remove only recently reviewed abandoned Burp launcher temp directories")
    burp_temp_run.add_argument("review_id")
    burp_temp_run.add_argument("--confirmed", action="store_true")
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
    benchmark = commands.add_parser("benchmark", help="synthetic-only evaluation")
    benchmark.add_argument("--fixtures-root", type=Path,
                           default=Path(__file__).resolve().parents[2] / "benchmarks")
    benchmark_commands = benchmark.add_subparsers(dest="benchmark_command", required=True)
    benchmark_commands.add_parser("list", help="list synthetic benchmark suites")
    benchmark_coverage = benchmark_commands.add_parser(
        "coverage", help="audit low-resource fixture pairs without running targets")
    benchmark_coverage.add_argument("suite")
    benchmark_run = benchmark_commands.add_parser("run", help="run a deterministic synthetic suite")
    benchmark_run.add_argument("suite")
    benchmark_run.add_argument("--mode", choices=("offline", "local"), default="offline")
    benchmark_run.add_argument("--trials", type=int, default=1,
                               help="bounded repeated trials (1-5; default 1)")
    benchmark_run.add_argument("--seed", type=int, default=0,
                               help="recorded random seed for reproducibility")
    benchmark_run.add_argument("--ablation", action="append", default=[],
                               choices=("NO_TRAFFIC", "NO_MODEL", "NO_CHALLENGER"),
                               help="operator-invoked, suite-specific ablation")
    benchmark_run.add_argument("--fake-providers", action="store_true",
                               help="synthetic primary/challenger ordering diagnostic")
    benchmark_resume = benchmark_commands.add_parser(
        "resume", help="resume pending synthetic cases without replaying an ambiguous case")
    benchmark_resume.add_argument("run_id")
    benchmark_show = benchmark_commands.add_parser("show", help="show one benchmark report")
    benchmark_show.add_argument("run_id")
    benchmark_compare = benchmark_commands.add_parser("compare", help="compare two benchmark runs")
    benchmark_compare.add_argument("baseline_id")
    benchmark_compare.add_argument("current_id")
    readiness = commands.add_parser("readiness", help="show synthetic evaluation readiness")
    readiness.add_argument("run_id", nargs="?")
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"hackbot {__version__}", file=out)
        return 0

    try:
        config = load_config(args.config, environ=environ)
    except ConfigError as exc:
        print(f"hackbot: {exc}", file=err)
        return 2

    if args.command in {"benchmark", "readiness"}:
        from .benchmark_catalog import BenchmarkCatalog
        from .benchmark_compare import compare_reports
        from .benchmark_fake_provider import FixtureOrderingProvider
        from .benchmark_models import (BenchmarkRunConfig, ModelLane, ModelRole,
                                       ModelSelection)
        from .benchmark_report import build_benchmark_report, write_benchmark_report
        from .benchmark_local_runner import BenchmarkLocalRunner
        from .benchmark_runner import BenchmarkOfflineRunner
        from .benchmark_store import BenchmarkStore
        from .store import _SCHEMA_VERSION

        state = BenchmarkStore(config.paths.state / "benchmark.sqlite3")
        exit_code = 0
        try:
            if args.command == "benchmark" and args.benchmark_command in {"list", "coverage", "run", "resume"}:
                fixture_root = args.fixtures_root.resolve(strict=True)
                catalog = BenchmarkCatalog(fixture_root / "visible", fixture_root / "truth")
                if args.benchmark_command == "list":
                    result = {"label": "SYNTHETIC / EVALUATION", "suites": [
                        {"name": name, "case_count": len(catalog.suite(name))}
                        for name in catalog.suites()]}
                elif args.benchmark_command == "coverage":
                    from .benchmark_acceptance import assess_low_resource_fixture_coverage
                    result = assess_low_resource_fixture_coverage(
                        catalog, args.suite).to_dict()
                    result["label"] = "SYNTHETIC / EVALUATION"
                else:
                    work_root = config.paths.artifacts / "benchmark-work"
                    if args.benchmark_command == "run":
                        mode = args.mode
                        selections = (
                            ModelSelection(ModelRole.PLANNER_ADVISOR, "fixture", "primary",
                                           lane=ModelLane.PRIMARY),
                            ModelSelection(ModelRole.PLANNER_ADVISOR, "fixture", "challenger",
                                           lane=ModelLane.CHALLENGER),
                        ) if args.fake_providers else ()
                    else:
                        state.initialize()
                        prior = state.get(args.run_id)
                        if prior is None:
                            raise LookupError("Benchmark run unavailable")
                        selections = BenchmarkRunConfig.from_dict(prior["config"]).models
                        mode = {"SYNTHETIC_OFFLINE": "offline",
                                "SYNTHETIC_LOCAL": "local"}.get(
                                    prior["environment"].get("mode"))
                    if mode == "local":
                        providers = {}
                        for selection in selections:
                            if selection.provider == "fixture" and selection.model in {
                                    "primary", "challenger"}:
                                providers[(selection.role, selection.lane,
                                           selection.provider, selection.model)] = (
                                               FixtureOrderingProvider(
                                                   reverse=selection.lane is
                                                   ModelLane.CHALLENGER))
                        runner = BenchmarkLocalRunner(
                            catalog, state, work_root, fixture_root / "harness",
                            providers=providers)
                    elif mode == "offline":
                        runner = BenchmarkOfflineRunner(catalog, state, work_root)
                    else:
                        raise ValueError("Unknown benchmark mode")
                    run_id = (runner.run(BenchmarkRunConfig(
                                         args.suite, trials=args.trials, seed=args.seed,
                                         ablations=tuple(args.ablation),
                                         models=selections,
                                         planner_mode=(
                                             "BOUNDED_AUTONOMOUS" if mode == "local"
                                             else "ANALYZE_ONLY")),
                                         bughunter_version=__version__,
                                         bughunter_schema=_SCHEMA_VERSION)
                              if args.benchmark_command == "run" else
                              runner.resume(args.run_id))
                    report = build_benchmark_report(state, run_id)
                    json_path, md_path = write_benchmark_report(
                        report, config.paths.artifacts / "benchmark-reports")
                    result = {"run_id": run_id, "status": report["status"],
                              "readiness": report["readiness"]["conclusion"],
                              "report_json": str(json_path), "report_markdown": str(md_path)}
                    if report["status"] != "COMPLETED":
                        exit_code = 1
            elif args.command == "benchmark" and args.benchmark_command == "show":
                result = build_benchmark_report(state, args.run_id)
            elif args.command == "benchmark" and args.benchmark_command == "compare":
                before = build_benchmark_report(state, args.baseline_id)
                after = build_benchmark_report(state, args.current_id)
                result = compare_reports(before, after)
                result["label"] = "SYNTHETIC / EVALUATION"
                result["readiness"] = after["readiness"]["conclusion"]
            else:
                run_id = args.run_id
                if run_id is None:
                    latest = state.list(limit=1)
                    if not latest:
                        raise LookupError("No benchmark runs")
                    run_id = latest[0]["run_id"]
                report = build_benchmark_report(state, run_id)
                result = {"run_id": run_id, "readiness": report["readiness"],
                          "case_status_counts": report["case_status_counts"]}
        except (OSError, ValueError, LookupError, TypeError, KeyError, sqlite3.Error):
            print("hackbot: synthetic benchmark unavailable or invalid", file=err)
            return 2
        print(json.dumps(result, sort_keys=True), file=out)
        return exit_code

    if args.command == "ops":
        try:
            if args.ops_command == "status":
                result = _operations_status()
            elif args.ops_command == "maintenance-status":
                result = _private_operations_request("GET", "/v1/operations/maintenance")
            else:
                payload: dict[str, object] = {
                    "action": {
                        "disabled-profile-plan": "DISABLED_PROFILE_PLAN",
                        "disabled-profile-run": "DISABLED_PROFILE_RUN",
                        "named-profile-plan": "NAMED_PROFILE_PLAN",
                        "named-profile-run": "NAMED_PROFILE_RUN",
                    }[args.ops_command],
                    "target_id": args.target_id,
                    "identity_id": args.identity_id,
                }
                if args.ops_command.startswith("named-profile-"):
                    payload["session_id"] = args.session_id
                if args.ops_command in {"disabled-profile-run", "named-profile-run"}:
                    payload.update({"review_id": args.review_id, "confirmed": args.confirmed})
                result = _private_operations_request("POST", "/v1/operations/maintenance", payload)
        except (OSError, ValueError, json.JSONDecodeError, http.client.HTTPException):
            print("hackbot: private operations status unavailable", file=err)
            return 2
        print(json.dumps(result, sort_keys=True), file=out)
        return 0

    if args.command == "storage":
        try:
            if args.storage_command == "startup-check":
                result = EvidenceFactStore.from_config(config).service_schema_status()
            elif args.storage_command == "check":
                from .store import _SCHEMA_VERSION
                result = check_database(config.paths.state / "bughunter.sqlite3",
                                        expected_schema=_SCHEMA_VERSION).to_dict()
            else:
                result = _storage_status(config)
        except (OSError, ValueError, sqlite3.Error, BackupError, ResourceError,
                DatabaseCheckError):
            print("hackbot: local storage status unavailable", file=err)
            return 2
        print(json.dumps(result, sort_keys=True), file=out)
        if args.storage_command == "startup-check":
            return 0 if result["state"] in {"READY", "FRESH"} else 1
        return 0 if args.storage_command != "check" or result["state"] == "OK" else 2

    if args.command == "backup":
        try:
            manager = BackupManager.from_config(config)
            if args.backup_command == "create":
                result: object = manager.create().to_dict()
            elif args.backup_command == "list":
                result = {"items": [item.to_dict() for item in manager.list(limit=args.limit)]}
            elif args.backup_command == "verify":
                result = manager.verify(args.backup_id, record=True).to_dict()
            elif args.backup_command == "rehearse":
                result = manager.rehearse_upgrade(
                    args.backup_id, max_values=args.max_values,
                    max_seconds=args.max_seconds)
            elif args.backup_command == "audit-json-indexes":
                result = manager.audit_json_indexes(
                    args.backup_id, max_values=args.max_values,
                    max_seconds=args.max_seconds)
            elif args.backup_command == "prune-plan":
                result = manager.prune_plan()
            elif args.backup_command == "prune":
                result = manager.prune(confirmed=args.confirmed)
            elif args.backup_command == "incomplete-plan":
                result = manager.incomplete_plan()
            elif args.backup_command == "incomplete-cleanup":
                result = manager.cleanup_incomplete(confirmed=args.confirmed)
            elif args.backup_command == "restore-staging-plan":
                result = manager.stale_restore_plan()
            elif args.backup_command == "restore-staging-cleanup":
                result = manager.cleanup_stale_restore(args.name, confirmed=args.confirmed)
            else:
                result = {"staged_at": str(manager.stage_restore(args.backup_id)),
                          "active_state_replaced": False}
        except (BackupError, BackupCryptoError, DatabaseCheckError, StoreSchemaError,
                ValueError, OSError, sqlite3.Error):
            print("hackbot: backup operation failed or input is invalid", file=err)
            return 2
        print(json.dumps(result, sort_keys=True), file=out)
        return 2 if args.backup_command == "audit-json-indexes" and not result["matches"] else 0

    if args.command == "retention":
        try:
            assert config.retention is not None
            store = EvidenceFactStore.from_config(config)
            if args.retention_command in {"dom-plan", "dom-run"}:
                scan = min(config.retention.max_scan_entries, 100)
                dom_manager = DOMPayloadRetirementManager(
                    store,
                    DOMPayloadPolicy(config.retention.orphan_grace_hours, scan,
                                     min(config.retention.max_delete_files, scan, 25)),
                    audit_path=config.paths.logs / "dom-retirement-audit.jsonl",
                )
                result = (dom_manager.plan(args.kind, after=args.after).to_dict()
                          if args.retention_command == "dom-plan"
                          else dom_manager.run(args.kind, confirmed=args.confirmed))
            elif args.retention_command.startswith("evidence-"):
                evidence_manager = EvidencePayloadRetirementManager(
                    store,
                    EvidencePayloadPolicy(config.retention.orphan_grace_hours,
                                          min(config.retention.max_scan_entries, 250),
                                          min(config.retention.max_delete_files, 25)),
                    config.paths.logs / "evidence-retirement-audit.jsonl",
                )
                result = (evidence_manager.plan().to_dict()
                          if args.retention_command == "evidence-plan"
                          else evidence_manager.run(confirmed=args.confirmed))
            elif args.retention_command.startswith("traffic-"):
                traffic_manager = TrafficPayloadRetirementManager(
                    store,
                    TrafficPayloadPolicy(config.retention.orphan_grace_hours,
                                         min(config.retention.max_scan_entries, 250),
                                         min(config.retention.max_delete_files, 25)),
                    config.paths.logs / "traffic-retirement-audit.jsonl",
                )
                result = (traffic_manager.plan().to_dict()
                          if args.retention_command == "traffic-plan"
                          else traffic_manager.run(confirmed=args.confirmed))
            elif args.retention_command.startswith("research-"):
                research_manager = ResearchBriefRetentionManager(
                    store,
                    ResearchBriefRetentionPolicy(config.retention.research_brief_grace_days,
                                                 min(config.retention.max_scan_entries, 250),
                                                 min(config.retention.max_scan_entries,
                                                     config.retention.max_delete_files, 25)),
                    config.paths.logs / "research-retirement-audit.jsonl",
                )
                result = (research_manager.plan().to_dict()
                          if args.retention_command == "research-plan"
                          else research_manager.run(confirmed=args.confirmed))
            else:
                manager = ArtifactGarbageCollector(
                    store,
                    OrphanPolicy(config.retention.orphan_grace_hours,
                                 config.retention.max_scan_entries,
                                 config.retention.max_delete_files,
                                 config.retention.orphan_scan_timeout_seconds),
                    config.paths.logs / "retention-audit.jsonl",
                )
                result = (manager.plan().to_dict() if args.retention_command == "plan"
                          else manager.run(confirmed=args.confirmed))
        except (ValueError, OSError, sqlite3.Error, StoreNotInitialized, StoreSchemaError,
                DOMReferenceError, EvidenceReferenceError, TrafficReferenceError):
            print("hackbot: retention operation failed or input is invalid", file=err)
            return 2
        print(json.dumps(result, sort_keys=True), file=out)
        return 0

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
        if args.burp_command == "storage":
            root = config.burp.runtime_root if config.burp is not None else None
            result = (inspect_burp_storage(root).to_dict() if root is not None
                      else {"state": "UNAVAILABLE"})
            print(json.dumps(result, sort_keys=True), file=out)
            return 0 if result["state"] != "UNAVAILABLE" else 2
        assert config.burp is not None
        if args.burp_command in {"temp-plan", "temp-run"}:
            from .burp_temp import BurpTempCollector, BurpTempError
            try:
                assert config.burp.runtime_root is not None
                collector = BurpTempCollector(
                    config.burp.runtime_root,
                    config.paths.state / "burp-temp-review.json",
                    config.paths.logs / "burp-temp-audit.jsonl")
                result = (collector.plan().to_dict() if args.burp_command == "temp-plan"
                          else collector.run(args.review_id, confirmed=args.confirmed))
            except (BurpTempError, OSError, ValueError):
                print("hackbot: Burp temporary cleanup is unavailable or unreviewed", file=err)
                return 2
            print(json.dumps(result, sort_keys=True), file=out)
            return 0
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
