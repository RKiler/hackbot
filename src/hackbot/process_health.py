"""Read-only inventory of processes in BugHunter-owned systemd cgroups."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


_UNITS = ("bughunter-agent.service", "bughunter-burp.service", "bughunter-vnc.service")
# /proc/<pid>/comm exposes at most 15 characters of a process name.
_BROWSER_NAMES = frozenset({"chrome", "chromium", "chromium-browser",
                            "chrome-headless-sh", "headless_shell",
                            "chromium-browse", "chrome-headless"})
_DISPLAY_NAMES = frozenset({"Xvfb", "Xorg", "x11vnc", "websockify", "fluxbox"})
_MAX_CGROUPS_PER_UNIT = 64
_MAX_PIDS_PER_UNIT = 512
_MAX_CGROUP_PROCS_BYTES = 32_768


@dataclass(frozen=True, slots=True)
class OwnedProcessStatus:
    state: str
    service_processes: dict[str, int]
    browser_pids: tuple[int, ...]
    suspected_orphan_browser_pids: tuple[int, ...]
    agent_display_pids: tuple[int, ...]
    vnc_display_pids: tuple[int, ...]
    suspected_orphan_display_pids: tuple[int, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "service_processes": dict(self.service_processes),
            "browser_processes": len(self.browser_pids),
            "suspected_orphan_browser_pids": list(self.suspected_orphan_browser_pids),
            "agent_display_pids": list(self.agent_display_pids),
            "vnc_display_pids": list(self.vnc_display_pids),
            "suspected_orphan_display_pids": list(self.suspected_orphan_display_pids),
        }


def _unit_pids(group: Path) -> set[int]:
    if group.is_symlink() or not group.is_dir():
        raise ValueError("Unsafe service cgroup")
    pending = [group]
    seen = 0
    pids: set[int] = set()
    while pending:
        current = pending.pop()
        seen += 1
        if seen > _MAX_CGROUPS_PER_UNIT:
            raise ValueError("Service cgroup inventory exceeds bound")
        path = current / "cgroup.procs"
        if current.is_symlink() or path.is_symlink():
            raise ValueError("Unsafe service cgroup")
        with path.open("r", encoding="ascii") as handle:
            raw = handle.read(_MAX_CGROUP_PROCS_BYTES + 1)
        if len(raw) > _MAX_CGROUP_PROCS_BYTES:
            raise ValueError("Service cgroup process list exceeds bound")
        for value in raw.splitlines():
            if not value.isdecimal():
                raise ValueError("Invalid service cgroup process list")
            pid = int(value)
            if not 0 < pid <= 2_147_483_647:
                raise ValueError("Invalid service cgroup PID")
            pids.add(pid)
            if len(pids) > _MAX_PIDS_PER_UNIT:
                raise ValueError("Service cgroup process inventory exceeds bound")
        for child in current.iterdir():
            if child.is_symlink():
                raise ValueError("Unsafe service cgroup child")
            if child.is_dir():
                pending.append(child)
                if seen + len(pending) > _MAX_CGROUPS_PER_UNIT:
                    raise ValueError("Service cgroup inventory exceeds bound")
    return pids


def inspect_owned_processes(*, cgroup_root: Path = Path("/sys/fs/cgroup/system.slice"),
                            proc_root: Path = Path("/proc"),
                            active_browser_sessions: int | None = None) -> OwnedProcessStatus:
    """Never reads command lines or sends signals; unknown ownership stays unknown."""
    if active_browser_sessions is not None and active_browser_sessions < 0:
        raise ValueError("Invalid active browser count")
    counts: dict[str, int] = {}
    browser_pids: list[int] = []
    agent_display_pids: list[int] = []
    vnc_display_pids: list[int] = []
    known = True
    agent_known = True
    for unit in _UNITS:
        group = cgroup_root / unit
        try:
            pids = _unit_pids(group)
            counts[unit] = len(pids)
            if unit == "bughunter-burp.service":
                continue
            for pid in pids:
                name_path = proc_root / str(pid) / "comm"
                if name_path.is_symlink():
                    known = False
                    if unit == "bughunter-agent.service":
                        agent_known = False
                    continue
                try:
                    name = name_path.read_text(encoding="ascii").strip()
                except (OSError, UnicodeError):
                    known = False
                    if unit == "bughunter-agent.service":
                        agent_known = False
                    continue
                if not name:
                    known = False
                    if unit == "bughunter-agent.service":
                        agent_known = False
                    continue
                if unit == "bughunter-agent.service" and name in _BROWSER_NAMES:
                    browser_pids.append(pid)
                if name in _DISPLAY_NAMES:
                    (agent_display_pids if unit == "bughunter-agent.service"
                     else vnc_display_pids).append(pid)
        except (OSError, UnicodeError, ValueError):
            counts[unit] = 0
            known = False
            if unit == "bughunter-agent.service":
                agent_known = False
    browser_pids.sort()
    agent_display_pids.sort()
    vnc_display_pids.sort()
    orphans = tuple(browser_pids) if active_browser_sessions == 0 and agent_known else ()
    display_orphans = (tuple(agent_display_pids)
                       if active_browser_sessions == 0 and agent_known else ())
    return OwnedProcessStatus("OK" if known else "UNKNOWN", counts,
                              tuple(browser_pids), orphans, tuple(agent_display_pids),
                              tuple(vnc_display_pids), display_orphans)
