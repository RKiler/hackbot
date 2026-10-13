#!/usr/bin/env python3
"""Run Burp Community's in-memory project on a private Xvfb display."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import time


WIZARD_TITLE = r"^Burp Suite Community Edition v[0-9.]+$"
PROJECT_TITLE = r"^Burp Suite Community Edition v.* - Temporary Project$"


def windows(title: str) -> list[str]:
    try:
        result = subprocess.run(
            ["xdotool", "search", "--onlyvisible", "--name", title],
            capture_output=True, text=True, check=False, timeout=8,
        )
    except subprocess.TimeoutExpired:
        return []
    if result.returncode not in (0, 1):
        raise RuntimeError("Burp display inspection failed")
    return [line for line in result.stdout.splitlines() if line.isdecimal()]


def listener_ready(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def start_temporary_project(window_id: str) -> None:
    subprocess.run(["xdotool", "windowactivate", "--sync", window_id], check=True, timeout=5)
    time.sleep(0.5)
    subprocess.run(["xdotool", "key", "--clearmodifiers", "shift+Tab"], check=True, timeout=5)
    subprocess.run(["xdotool", "key", "space"], check=True, timeout=5)


def wait_for_project(java: subprocess.Popen[bytes], port: int, *, seconds: int) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if java.poll() is not None:
            return False
        if windows(PROJECT_TITLE) and listener_ready(port):
            return True
        time.sleep(1)
    return False


def terminate(child: subprocess.Popen[bytes] | None) -> None:
    if child is None or child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=20)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jar", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--project-config", type=Path, required=True)
    parser.add_argument("--user-config", type=Path, required=True)
    parser.add_argument("--listener-port", type=int, required=True)
    args = parser.parse_args()
    if not os.environ.get("DISPLAY") or not re.fullmatch(
        r"[A-Za-z0-9._~-]{32,256}", os.environ.get("HACKBOT_SECRET_BURP_BRIDGE", "")
    ):
        raise SystemExit("Private display or bridge credential is unavailable")
    if not all(path.is_file() for path in (args.jar, args.project_config, args.user_config)):
        raise SystemExit("Burp installation or configuration is unavailable")
    if not 1024 <= args.listener_port <= 65535:
        raise SystemExit("Invalid Burp listener port")
    runtime = args.runtime_root.resolve(strict=True)
    if not runtime.is_dir() or not (runtime / "tmp").is_dir():
        raise SystemExit("Burp runtime directory is unavailable")

    def stop(_signal: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    fluxbox: subprocess.Popen[bytes] | None = None
    java: subprocess.Popen[bytes] | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="community-", dir=runtime / "tmp") as temp:
            fluxbox = subprocess.Popen(
                ["fluxbox", "-no-slit", "-no-toolbar"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            java = subprocess.Popen([
                "java", "-Xms128m", "-Xmx768m", f"-Duser.home={runtime}",
                f"-Djava.io.tmpdir={temp}", "-jar", str(args.jar),
                f"--data-dir={runtime / 'data'}",
                f"--config-file={args.project_config}",
                f"--user-config-file={args.user_config}",
                "--disable-auto-update",
            ], stdin=subprocess.DEVNULL)
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline and java.poll() is None:
                wizard = windows(WIZARD_TITLE)
                if wizard:
                    start_temporary_project(wizard[0])
                    break
                if windows(PROJECT_TITLE) and listener_ready(args.listener_port):
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Burp Community startup wizard was not available")
            if not wait_for_project(java, args.listener_port, seconds=240):
                raise RuntimeError("Burp Community project or loopback listener did not start")
            print("Burp Community temporary project and loopback listener ready", flush=True)
            while java.poll() is None:
                time.sleep(1)
            return 1
    except KeyboardInterrupt:
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as failure:
        print(f"Burp Community startup failed: {failure}", flush=True)
        return 1
    finally:
        terminate(java)
        terminate(fluxbox)


if __name__ == "__main__":
    raise SystemExit(main())
