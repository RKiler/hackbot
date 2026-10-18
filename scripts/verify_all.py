#!/usr/bin/env python3
"""Run every BugHunter test module in isolated, auditable segments."""

from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import fcntl
import hashlib
from importlib import metadata
import json
import math
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
GROUPS: dict[str, tuple[str, ...]] = {
    "unit-fast": (
        "test_cli.py", "test_config.py", "test_domain.py", "test_logging.py",
        "test_target_package.py", "test_policy.py", "test_skills.py",
        "test_domxss_maps.py", "test_domxss_static.py", "test_postmessage_static.py",
        "test_exposure_static.py", "test_research_sources.py", "test_test_matrix.py",
        "test_resources.py", "test_db_maintenance.py", "test_process_health.py",
        "test_systemd_unit.py", "test_burp_storage.py", "test_notification_recovery.py",
    ),
    "store-migrations": (
        "test_store.py", "test_backup.py", "test_retention.py", "test_maintenance.py",
        "test_finding_evidence_hold.py",
        "test_auth.py", "test_identity_registry.py",
        "test_traffic.py", "test_planner_store.py", "test_domxss_store.py",
        "test_recon.py", "test_object_factory.py", "test_phase12.py",
        "test_profile_retention.py", "test_research_retention.py",
    ),
    "api-specialists": (
        "test_api_graphql.py", "test_api_runtime.py", "test_api_specialist.py",
    ),
    "authorization-specialists": (
        "test_authorization.py", "test_authorization_mutations.py",
    ),
    "surface-specialists": (
        "test_domxss_runtime.py", "test_domxss_specialist.py", "test_exposure_runtime.py",
        "test_postmessage_runtime.py",
    ),
    "workflow-specialists": (
        "test_behaviour.py", "test_bootstrap.py", "test_planner_multisurface.py",
        "test_research.py", "test_campaign_flow.py", "test_campaign_store.py",
    ),
    "execution-specialists": (
        "test_executor.py", "test_orchestrator.py", "test_typed_mutations.py",
        "test_validator.py",
    ),
    "browser": (
        "test_browser.py", "test_browser_playwright_integration.py",
        "test_domxss_playwright_fixture.py", "test_domxss_browser.py",
        "test_postmessage_browser.py",
    ),
    "service-gateway": (
        "test_service.py", "test_phase29.py", "test_burp.py",
    ),
}


def validate_manifest() -> dict[str, object]:
    discovered = {path.name for path in (ROOT / "tests").glob("test_*.py")}
    assigned = [name for group in GROUPS.values() for name in group]
    duplicate = sorted({name for name in assigned if assigned.count(name) != 1})
    missing = sorted(discovered - set(assigned))
    unknown = sorted(set(assigned) - discovered)
    if missing or duplicate or unknown:
        raise ValueError(json.dumps({"missing": missing, "duplicate": duplicate,
                                     "unknown": unknown}, sort_keys=True))
    return {"module_count": len(discovered), "groups": {
        group: len(files) for group, files in GROUPS.items()}}


def source_fingerprint() -> str:
    """Bind resumed segment results to the exact executable/test/deploy tree."""
    digest = hashlib.sha256()
    digest.update(sys.version.encode())
    digest.update(str(Path(sys.executable).resolve()).encode())
    packages = sorted((str(item.metadata.get("Name") or "").lower(), item.version)
                      for item in metadata.distributions())
    digest.update(json.dumps(packages, separators=(",", ":")).encode())
    paths = [ROOT / "pyproject.toml"]
    for directory in ("src", "tests", "scripts", "deploy"):
        paths.extend((ROOT / directory).rglob("*"))
    for path in sorted(paths):
        if any(part in {"__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        if path.is_symlink():
            raise ValueError("test source contains a symlink")
        if not path.is_file():
            continue
        if path.stat().st_size > 10_000_000:
            raise ValueError("test source exceeds fingerprint limit")
        digest.update(str(path.relative_to(ROOT)).encode())
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _read_resume(path: Path, fingerprint: str, manifest: dict[str, object]) -> dict[str, object]:
    if not path.exists() and not path.is_symlink():
        return {"version": 1, "fingerprint": fingerprint, "manifest": manifest,
                "results": {}, "module_results": {}}
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size > 65_536:
        raise ValueError("unsafe test-matrix resume file")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise ValueError("invalid test-matrix resume file") from None
    modules = {filename: group for group, files in GROUPS.items() for filename in files}
    module_results = state.get("module_results", {}) if isinstance(state, dict) else None
    if (not isinstance(state, dict) or state.get("version") != 1 or
            state.get("fingerprint") != fingerprint or state.get("manifest") != manifest or
            not isinstance(state.get("results"), dict) or
            set(state["results"]) - set(GROUPS) or
            any(not isinstance(item, dict) or item.get("group") != name or
                item.get("exit_code") != 0 or item.get("modules") != len(GROUPS[name]) or
                type(item.get("elapsed_seconds")) not in (int, float) or
                not math.isfinite(item["elapsed_seconds"]) or
                item["elapsed_seconds"] < 0 or
                not isinstance(item.get("completed_at"), str)
                for name, item in state["results"].items()) or
            not isinstance(module_results, dict) or
            any(filename not in modules or not isinstance(item, dict) or
                item.get("group") != modules[filename] or item.get("exit_code") != 0 or
                type(item.get("elapsed_seconds")) not in (int, float) or
                not math.isfinite(item["elapsed_seconds"]) or
                item["elapsed_seconds"] < 0 or
                not isinstance(item.get("completed_at"), str)
                for filename, item in module_results.items()) or
            any(any(filename not in module_results for filename in GROUPS[name])
                for name in state["results"])):
        raise ValueError("test-matrix resume file does not match current source and manifest")
    state["module_results"] = module_results
    return state


def _write_resume(path: Path, state: dict[str, object]) -> None:
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or path.is_symlink():
        raise ValueError("unsafe test-matrix resume path")
    fd, temporary = tempfile.mkstemp(prefix=".matrix-", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def _resume_lock(path: Path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if os.fstat(fd).st_nlink != 1:
            raise ValueError("unsafe test-matrix lock")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("test-matrix resume file is already in use") from None
        yield
    finally:
        os.close(fd)


def _cpu_ticks(pid: int) -> int | None:
    """Read only the test runner's CPU time; child-browser work is not included."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return int(fields[11]) + int(fields[12])
    except (OSError, IndexError, ValueError):
        return None


def _stop_test_group(process: subprocess.Popen[bytes]) -> None:
    """Stop only the dedicated pytest process group after runner interruption."""
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    # Do not reap the group leader before the final signal: its PID then cannot
    # be reused for an unrelated process group during cleanup.
    time.sleep(2)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=10)


def run_group(name: str, files: tuple[str, ...], *, stall_warning_seconds: int) -> dict[str, object]:
    command = [sys.executable, "-m", "pytest", "-q", "--maxfail=1", "--durations=5",
               *(str(ROOT / "tests" / name) for name in files)]
    started = time.monotonic()
    last_output = started
    warned = False
    print(f"\n== {name}: {len(files)} modules ==", flush=True)
    with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, bufsize=0,
                          start_new_session=True) as process:
        try:
            assert process.stdout is not None
            fd = process.stdout.fileno()
            baseline_cpu = _cpu_ticks(process.pid)
            while True:
                ready, _, _ = select.select([fd], [], [], 5)
                if ready:
                    chunk = os.read(fd, 8192)
                    if chunk:
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
                        last_output = time.monotonic()
                        warned = False
                        baseline_cpu = _cpu_ticks(process.pid)
                    elif process.poll() is not None:
                        break
                if process.poll() is not None and not ready:
                    break
                if not warned and time.monotonic() - last_output >= stall_warning_seconds:
                    current_cpu = _cpu_ticks(process.pid)
                    cpu_progress = ("unknown" if current_cpu is None or baseline_cpu is None
                                    else str(max(0, current_cpu - baseline_cpu)) + " ticks")
                    print(f"\nWARNING: {name} has produced no output for "
                          f"{stall_warning_seconds}s; pytest CPU progress: {cpu_progress}. "
                          "Process remains under observation.", flush=True)
                    warned = True
            code = process.wait()
        except BaseException:
            _stop_test_group(process)
            raise
    result = {"group": name, "modules": len(files), "exit_code": code,
              "elapsed_seconds": round(time.monotonic() - started, 1)}
    print("MATRIX_GROUP " + json.dumps(result, sort_keys=True), flush=True)
    return result


def run_checkpointed_module(name: str, filename: str, *, state: dict[str, object],
                            path: Path, fingerprint: str,
                            stall_warning_seconds: int) -> dict[str, object]:
    module_results = state["module_results"]
    saved = module_results.get(filename)
    if saved is not None:
        print(f"== {name}/{filename}: verified prior pass for identical source ==", flush=True)
        return saved
    result = run_group(f"{name}/{filename}", (filename,),
                       stall_warning_seconds=stall_warning_seconds)
    if source_fingerprint() != fingerprint:
        raise ValueError("test source or dependencies changed during module")
    if result["exit_code"] != 0:
        return result
    saved = {"group": name, "exit_code": 0,
             "elapsed_seconds": result["elapsed_seconds"],
             "completed_at": datetime.now(timezone.utc).isoformat()}
    module_results[filename] = saved
    _write_resume(path, state)
    return saved


def complete_checkpointed_group(name: str, *, state: dict[str, object],
                                path: Path) -> dict[str, object] | None:
    saved = state["results"].get(name)
    if saved is not None:
        return saved
    files = GROUPS[name]
    if any(filename not in state["module_results"] for filename in files):
        return None
    elapsed = sum(state["module_results"][filename]["elapsed_seconds"] for filename in files)
    group_result = {"group": name, "modules": len(files), "exit_code": 0,
                    "elapsed_seconds": round(elapsed, 1),
                    "completed_at": datetime.now(timezone.utc).isoformat()}
    state["results"][name] = group_result
    _write_resume(path, state)
    print("MATRIX_GROUP " + json.dumps(group_result, sort_keys=True), flush=True)
    return group_result


def run_checkpointed_group(name: str, files: tuple[str, ...], *, state: dict[str, object],
                           path: Path, fingerprint: str,
                           stall_warning_seconds: int) -> dict[str, object]:
    elapsed = 0.0
    completed = 0
    for filename in files:
        result = run_checkpointed_module(
            name, filename, state=state, path=path, fingerprint=fingerprint,
            stall_warning_seconds=stall_warning_seconds)
        elapsed += result["elapsed_seconds"]
        if result["exit_code"] != 0:
            return {"group": name, "modules": len(files),
                    "completed_modules": completed, "exit_code": result["exit_code"],
                    "elapsed_seconds": round(elapsed, 1)}
        completed += 1
    group_result = complete_checkpointed_group(name, state=state, path=path)
    assert group_result is not None
    return group_result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--group", choices=tuple(GROUPS))
    parser.add_argument("--module", choices=tuple(
        filename for files in GROUPS.values() for filename in files))
    parser.add_argument("--resume-file", type=Path,
                        help="Save passing modules and groups, reusing only identical source/dependencies")
    parser.add_argument("--stall-warning-seconds", type=int, default=180)
    args = parser.parse_args(argv)
    if args.stall_warning_seconds < 60:
        parser.error("stall warning must be at least 60 seconds")
    if args.module is not None and (args.group is not None or args.resume_file is None or
                                    args.manifest_only):
        parser.error("--module requires --resume-file and cannot combine with --group or --manifest-only")
    try:
        manifest = validate_manifest()
    except ValueError as exc:
        print(f"test manifest invalid: {exc}", file=sys.stderr)
        return 2
    print("MATRIX_MANIFEST " + json.dumps(manifest, sort_keys=True), flush=True)
    if args.manifest_only:
        return 0
    selected = {args.group: GROUPS[args.group]} if args.group else GROUPS
    raw_path = args.resume_file.expanduser() if args.resume_file is not None else None
    if raw_path is not None and raw_path.is_symlink():
        parser.error("resume file must not be a symlink")
    path = raw_path.resolve(strict=False) if raw_path is not None else None
    results: list[dict[str, object]] = []
    try:
        with _resume_lock(path) if path is not None else nullcontext():
            fingerprint = source_fingerprint() if path is not None else None
            state = _read_resume(path, fingerprint, manifest) if path is not None else None
            if args.module is not None:
                assert state is not None and path is not None and fingerprint is not None
                name = next(group for group, files in GROUPS.items() if args.module in files)
                result = run_checkpointed_module(
                    name, args.module, state=state, path=path, fingerprint=fingerprint,
                    stall_warning_seconds=args.stall_warning_seconds)
                if result["exit_code"] == 0:
                    complete_checkpointed_group(name, state=state, path=path)
                results.append({"group": f"{name}/{args.module}", "modules": 1,
                                "exit_code": result["exit_code"],
                                "elapsed_seconds": result["elapsed_seconds"]})
            else:
                for name, files in selected.items():
                    saved = state["results"].get(name) if state is not None else None
                    if saved is not None:
                        print(f"== {name}: verified prior pass for identical source ==", flush=True)
                        results.append({**saved, "reused": True})
                        continue
                    if path is not None:
                        assert state is not None and fingerprint is not None
                        result = run_checkpointed_group(
                            name, files, state=state, path=path, fingerprint=fingerprint,
                            stall_warning_seconds=args.stall_warning_seconds)
                    else:
                        result = run_group(name, files,
                                           stall_warning_seconds=args.stall_warning_seconds)
                    results.append(result)
            if path is not None and source_fingerprint() != fingerprint:
                raise ValueError("test source or dependencies changed during matrix")
    except (OSError, ValueError) as exc:
        print(f"test matrix cannot resume: {exc}", file=sys.stderr)
        return 2
    complete = args.group is None and args.module is None and (
        set(state["results"]) == set(GROUPS) if path is not None and state is not None
        else (sum(item["modules"] for item in results) == manifest["module_count"]
              and all(item["exit_code"] == 0 for item in results)))
    passed = all(item["exit_code"] == 0 for item in results)
    print("MATRIX_RESULT " + json.dumps({
        "at": datetime.now(timezone.utc).isoformat(), "complete": complete,
        "passed": passed, "results": results,
    }, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    def _terminate_requested(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _terminate_requested)
    raise SystemExit(main())
