"""Bound new heavy work without blocking evidence, cleanup, or operator reads."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
import os
from pathlib import Path
import shutil
from typing import Callable

from .config import ResourceSettings


class ResourceError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class WorkKind(str, Enum):
    PLANNER = "PLANNER"
    PLAN = "PLAN"
    BROWSER = "BROWSER"
    BOOTSTRAP = "BOOTSTRAP"
    LEARNING = "LEARNING"
    RESEARCH = "RESEARCH"


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    disk_total_bytes: int
    disk_free_bytes: int
    disk_used_percent: int
    memory_available_bytes: int | None
    state: str
    warnings: tuple[str, ...]
    system_disk_total_bytes: int | None = None
    system_disk_free_bytes: int | None = None
    system_disk_used_percent: int | None = None
    load_per_cpu: float | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "disk_total_bytes": self.disk_total_bytes,
            "disk_free_bytes": self.disk_free_bytes,
            "disk_used_percent": self.disk_used_percent,
            "memory_available_bytes": self.memory_available_bytes,
            "state": self.state, "warnings": list(self.warnings),
            "system_disk_total_bytes": self.system_disk_total_bytes,
            "system_disk_free_bytes": self.system_disk_free_bytes,
            "system_disk_used_percent": self.system_disk_used_percent,
            "load_per_cpu": self.load_per_cpu,
        }


def _host_memory_available() -> int | None:
    try:
        with Path("/proc/meminfo").open(encoding="ascii") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except (OSError, UnicodeError, ValueError, IndexError):
        return None
    return None


def _cgroup_memory_available(*, membership: Path = Path("/proc/self/cgroup"),
                             root: Path = Path("/sys/fs/cgroup")) -> int | None:
    if not root.is_dir():
        return None
    try:
        lines = membership.read_text(encoding="ascii").splitlines()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError):
        raise ValueError("Cannot read cgroup membership") from None
    groups = [line[3:] for line in lines if line.startswith("0::")]
    if not groups:
        return None
    if len(groups) != 1 or not groups[0].startswith("/"):
        raise ValueError("Invalid cgroup membership")
    parts = groups[0].split("/")[1:] if groups[0] != "/" else []
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Invalid cgroup path")
    current = root.joinpath(*parts)
    if not current.is_dir():
        raise ValueError("Cgroup memory path is unavailable")
    remaining = None
    while True:
        limit_path = current / "memory.max"
        usage_path = current / "memory.current"
        try:
            if limit_path.is_file():
                limit_text = limit_path.read_text(encoding="ascii").strip()
                if limit_text != "max":
                    used_text = usage_path.read_text(encoding="ascii").strip()
                    if not limit_text.isdecimal() or not used_text.isdecimal():
                        raise ValueError("Invalid cgroup memory metric")
                    limit = int(limit_text)
                    used = int(used_text)
                    if limit <= 0:
                        raise ValueError("Invalid cgroup memory limit")
                    available = max(0, limit - used)
                    remaining = available if remaining is None else min(remaining, available)
            elif usage_path.exists():
                raise ValueError("Incomplete cgroup memory metric")
        except (OSError, UnicodeError):
            raise ValueError("Cannot read cgroup memory metric") from None
        if current == root:
            return remaining
        current = current.parent


def _memory_available() -> int | None:
    host = _host_memory_available()
    if host is None:
        return None
    try:
        cgroup = _cgroup_memory_available()
    except ValueError:
        return None
    return min(host, cgroup) if cgroup is not None else host


def _load_per_cpu() -> float | None:
    try:
        cpus = (len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity")
                else os.cpu_count())
        return os.getloadavg()[0] / cpus if cpus else None
    except (OSError, ValueError, TypeError, AttributeError, NotImplementedError):
        return None


class ResourceBudgetManager:
    def __init__(self, root: Path, settings: ResourceSettings,
                 *, disk_usage: Callable[[Path], shutil._ntuple_diskusage] = shutil.disk_usage,
                 memory_available: Callable[[], int | None] = _memory_available,
                 load_per_cpu: Callable[[], float | None] = _load_per_cpu,
                 system_disk_path: Path | None = None) -> None:
        self.root = root
        self.settings = settings
        self._disk_usage = disk_usage
        self._memory_available = memory_available
        self._load_per_cpu = load_per_cpu
        self.system_disk_path = system_disk_path

    def snapshot(self) -> ResourceSnapshot:
        path = self.root
        if not path.is_dir():
            raise ResourceError("STORAGE_UNAVAILABLE")
        if self.settings.required_mount is not None:
            mount = Path(self.settings.required_mount)
            try:
                mounted = (os.path.ismount(mount) and
                           path.resolve(strict=True).is_relative_to(mount.resolve(strict=True)))
            except OSError:
                mounted = False
            if not mounted:
                raise ResourceError("REQUIRED_MOUNT_UNAVAILABLE")
        try:
            disk = self._disk_usage(path)
        except (OSError, ValueError):
            raise ResourceError("STORAGE_UNAVAILABLE") from None
        total, used, free = disk.total, disk.used, disk.free
        if total <= 0:
            raise ResourceError("STORAGE_UNAVAILABLE")
        percent = int((used * 100 + total - 1) // total)
        system_total = system_free = system_percent = None
        if self.system_disk_path is not None:
            system_root = self.system_disk_path
            if not system_root.is_dir():
                raise ResourceError("SYSTEM_STORAGE_UNAVAILABLE")
            if system_root.resolve() == path.resolve():
                system_total, system_free, system_percent = total, free, percent
            else:
                try:
                    system_disk = self._disk_usage(system_root)
                except (OSError, ValueError):
                    raise ResourceError("SYSTEM_STORAGE_UNAVAILABLE") from None
                system_total, system_free = system_disk.total, system_disk.free
                if system_total <= 0:
                    raise ResourceError("SYSTEM_STORAGE_UNAVAILABLE")
                system_percent = int((system_disk.used * 100 + system_total - 1)
                                     // system_total)
        memory = self._memory_available()
        try:
            load = self._load_per_cpu()
        except (OSError, ValueError, TypeError, AttributeError, NotImplementedError):
            load = None
        if type(load) not in (int, float) or not math.isfinite(load) or load < 0:
            load = None
        warnings = []
        if percent >= self.settings.critical_disk_percent or free < self.settings.min_free_disk_bytes:
            warnings.append("CRITICAL_DISK")
        elif percent >= self.settings.high_disk_percent:
            warnings.append("HIGH_DISK")
        elif percent >= self.settings.warning_disk_percent:
            warnings.append("LOW_DISK")
        if system_percent is not None and self.system_disk_path.resolve() != path.resolve():
            if (system_percent >= self.settings.critical_disk_percent or
                    system_free < self.settings.min_free_system_disk_bytes):
                warnings.append("CRITICAL_SYSTEM_DISK")
            elif system_percent >= self.settings.high_disk_percent:
                warnings.append("HIGH_SYSTEM_DISK")
            elif system_percent >= self.settings.warning_disk_percent:
                warnings.append("LOW_SYSTEM_DISK")
        if memory is None:
            warnings.append("MEMORY_STATUS_UNKNOWN")
        elif memory < self.settings.min_available_memory_bytes:
            warnings.append("LOW_MEMORY")
        if self.settings.high_load_per_cpu is not None:
            if load is None:
                warnings.append("LOAD_STATUS_UNKNOWN")
            elif load >= self.settings.critical_load_per_cpu:
                warnings.append("CRITICAL_LOAD")
            elif load >= self.settings.high_load_per_cpu:
                warnings.append("HIGH_LOAD")
        state = ("BLOCKED" if "CRITICAL_DISK" in warnings or
                 "CRITICAL_SYSTEM_DISK" in warnings or "CRITICAL_LOAD" in warnings else
                 "DEGRADED" if warnings else "OK")
        return ResourceSnapshot(total, free, percent, memory, state, tuple(warnings),
                                system_total, system_free, system_percent, load)

    def admit(self, kind: WorkKind, *, active: int) -> ResourceSnapshot:
        if not isinstance(kind, WorkKind) or type(active) is not int or active < 0:
            raise ValueError("Invalid work admission request")
        caps = {
            WorkKind.PLANNER: self.settings.max_planner_runs,
            WorkKind.PLAN: self.settings.max_plan_runs,
            WorkKind.BROWSER: self.settings.max_browser_sessions,
            WorkKind.BOOTSTRAP: self.settings.max_bootstrap_runs,
            WorkKind.LEARNING: self.settings.max_learning_runs,
            WorkKind.RESEARCH: self.settings.max_research_requests,
        }
        if active >= caps[kind]:
            raise ResourceError("CONCURRENCY_LIMIT")
        snapshot = self.snapshot()
        if "CRITICAL_DISK" in snapshot.warnings:
            raise ResourceError("CRITICAL_DISK")
        if "CRITICAL_SYSTEM_DISK" in snapshot.warnings:
            raise ResourceError("CRITICAL_SYSTEM_DISK")
        if "HIGH_DISK" in snapshot.warnings:
            raise ResourceError("HIGH_DISK")
        if "HIGH_SYSTEM_DISK" in snapshot.warnings:
            raise ResourceError("HIGH_SYSTEM_DISK")
        if snapshot.memory_available_bytes is None:
            raise ResourceError("MEMORY_STATUS_UNKNOWN")
        if "LOW_MEMORY" in snapshot.warnings:
            raise ResourceError("LOW_MEMORY")
        if "LOAD_STATUS_UNKNOWN" in snapshot.warnings:
            raise ResourceError("LOAD_STATUS_UNKNOWN")
        if "CRITICAL_LOAD" in snapshot.warnings:
            raise ResourceError("CRITICAL_LOAD")
        if "HIGH_LOAD" in snapshot.warnings and kind is not WorkKind.PLAN:
            raise ResourceError("HIGH_LOAD")
        return snapshot
