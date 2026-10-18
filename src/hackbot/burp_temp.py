"""Reviewed cleanup of abandoned Burp Community launcher temp projects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Callable
from typing import Iterator
import uuid


_PROJECT = re.compile(r"community-[a-z0-9_]{8}\Z")
_REVIEW = re.compile(r"BTR-[0-9a-f]{32}\Z")


class BurpTempError(RuntimeError):
    """Cleanup could not prove the reviewed directory is safe to remove."""


@dataclass(frozen=True, slots=True)
class BurpTempPolicy:
    grace_hours: int = 24
    max_root_entries: int = 1000
    max_tree_entries: int = 10_000
    max_candidates: int = 20

    def __post_init__(self) -> None:
        if (type(self.grace_hours) is not int or not 1 <= self.grace_hours <= 8760 or
                type(self.max_root_entries) is not int or
                not 1 <= self.max_root_entries <= 100_000 or
                type(self.max_tree_entries) is not int or
                not 1 <= self.max_tree_entries <= 100_000 or
                type(self.max_candidates) is not int or
                not 1 <= self.max_candidates <= 1000):
            raise ValueError("Invalid Burp temporary retention policy")


@dataclass(frozen=True, slots=True)
class BurpTempPlan:
    review_id: str
    candidates: tuple[str, ...]
    estimated_bytes: int
    scanned: int
    truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {"class": "ABANDONED_BURP_COMMUNITY_TEMP", "dry_run": True,
                "review_id": self.review_id, "candidates": self.candidates,
                "candidate_count": len(self.candidates),
                "estimated_bytes": self.estimated_bytes,
                "scanned": self.scanned, "truncated": self.truncated}


def _require_burp_stopped(root: Path) -> None:
    try:
        result = subprocess.run(
            ["systemctl", "show", "bughunter-burp.service", "-p", "ActiveState", "--value"],
            capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BurpTempError("Burp service state is unavailable") from exc
    if result.returncode != 0 or result.stdout.strip() not in {"inactive", "failed"}:
        raise BurpTempError("Burp service must be stopped")
    prefix = (str(root / "tmp") + os.sep).encode()
    root_bytes = str(root).encode()
    try:
        processes = 0
        for entry in os.scandir("/proc"):
            if not entry.name.isdecimal():
                continue
            processes += 1
            if processes > 10_000:
                raise BurpTempError("Burp process inventory is incomplete")
            try:
                command = (Path(entry.path) / "cmdline").read_bytes()
            except (FileNotFoundError, ProcessLookupError):
                continue
            if ((b"-Djava.io.tmpdir=" + prefix) in command or
                    (b"run_community.py" in command and root_bytes in command)):
                raise BurpTempError("Burp runtime process is still active")
    except OSError as exc:
        raise BurpTempError("Burp process inventory is unavailable") from exc


class BurpTempCollector:
    """Remove only old launcher-owned temp directories after operator review."""

    def __init__(self, runtime_root: Path, review_path: Path, audit_path: Path,
                 policy: BurpTempPolicy = BurpTempPolicy(),
                 require_stopped: Callable[[Path], None] = _require_burp_stopped) -> None:
        self.runtime_root = runtime_root
        self.review_path = review_path
        self.audit_path = audit_path
        self.policy = policy
        self.require_stopped = require_stopped

    def _tmp_root(self) -> Path:
        root = self.runtime_root
        tmp = root / "tmp"
        data = root / "data"
        if root.name != "burp-runtime":
            raise BurpTempError("Invalid Burp runtime root")
        for path in (root, tmp, data):
            try:
                info = path.lstat()
            except OSError as exc:
                raise BurpTempError("Burp runtime layout is unavailable") from exc
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                raise BurpTempError("Unsafe Burp runtime layout")
        return tmp

    @contextmanager
    def _hold(self, tmp: Path, *, shared: bool) -> Iterator[None]:
        path = tmp / ".community-maintenance.lock"
        created = False
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            created = True
        except FileExistsError:
            fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise BurpTempError("Unsafe Burp maintenance lock")
            owner = tmp.stat()
            if created and os.geteuid() == 0:
                os.fchown(fd, owner.st_uid, owner.st_gid)
                info = os.fstat(fd)
            if info.st_uid != owner.st_uid or info.st_mode & 0o077:
                raise BurpTempError("Unsafe Burp maintenance lock")
            try:
                fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) |
                            fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BurpTempError("Burp runtime is active") from exc
            yield
        finally:
            os.close(fd)

    def _tree(self, path: Path, device: int) -> tuple[int, int, int, str]:
        pending = [(path, ".")]
        records: list[tuple[object, ...]] = []
        total_bytes = count = newest = 0
        while pending:
            node, relative = pending.pop()
            try:
                info = node.lstat()
            except OSError as exc:
                raise BurpTempError("Burp temp tree changed during review") from exc
            if info.st_dev != device or info.st_nlink != 1 and not stat.S_ISDIR(info.st_mode):
                raise BurpTempError("Unsafe Burp temp entry")
            if stat.S_ISDIR(info.st_mode):
                kind = "dir"
            elif stat.S_ISREG(info.st_mode):
                kind = "file"
                total_bytes += info.st_size
            else:
                raise BurpTempError("Unsafe Burp temp entry")
            count += 1
            if count > self.policy.max_tree_entries:
                raise BurpTempError("Burp temp tree exceeds review limit")
            newest = max(newest, info.st_mtime_ns)
            records.append((relative, kind, info.st_dev, info.st_ino,
                            info.st_mtime_ns, info.st_size if kind == "file" else 0))
            if kind == "dir":
                try:
                    with os.scandir(node) as iterator:
                        children = []
                        for entry in iterator:
                            children.append(entry.name)
                            if count + len(children) > self.policy.max_tree_entries:
                                raise BurpTempError("Burp temp tree exceeds review limit")
                except OSError as exc:
                    raise BurpTempError("Burp temp tree is unreadable") from exc
                for name in children:
                    pending.append((node / name, name if relative == "." else f"{relative}/{name}"))
        records.sort()
        digest = hashlib.sha256(json.dumps(records, separators=(",", ":")).encode()).hexdigest()
        return total_bytes, count, newest, digest

    def _write_review(self, value: dict[str, object]) -> None:
        path = self.review_path
        parent = path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if parent.is_symlink() or path.is_symlink() or not parent.is_dir():
            raise BurpTempError("Unsafe Burp review path")
        fd, temporary = tempfile.mkstemp(prefix=".burp-temp-review-", dir=parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, sort_keys=True)
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

    def _read_review(self) -> dict[str, object]:
        path = self.review_path
        try:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_mode & 0o077 or info.st_size > 32_768):
                raise BurpTempError("Unsafe Burp review file")
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise BurpTempError("Burp review is unavailable") from exc
        if (not isinstance(value, dict) or
                not isinstance(value.get("review_id"), str) or
                not _REVIEW.fullmatch(value["review_id"]) or
                type(value.get("at")) not in (int, float) or
                not isinstance(value.get("entries"), list) or
                len(value["entries"]) > self.policy.max_candidates):
            raise BurpTempError("Invalid Burp review")
        names: set[str] = set()
        for entry in value["entries"]:
            if (not isinstance(entry, dict) or
                    not isinstance(entry.get("name"), str) or
                    not _PROJECT.fullmatch(entry["name"]) or
                    entry["name"] in names or
                    not isinstance(entry.get("fingerprint"), str) or
                    not re.fullmatch(r"[0-9a-f]{64}", entry["fingerprint"]) or
                    type(entry.get("bytes")) is not int or entry["bytes"] < 0):
                raise BurpTempError("Invalid Burp review")
            names.add(entry["name"])
        return value

    def _audit(self, stage: str, review_id: str, count: int) -> None:
        parent = self.audit_path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if parent.is_symlink() or self.audit_path.is_symlink():
            raise BurpTempError("Unsafe Burp audit path")
        record = {"at": datetime.now(timezone.utc).isoformat(),
                  "action": "BURP_TEMP_COLLECTION", "stage": stage,
                  "review_id": review_id, "removed": count}
        fd = os.open(self.audit_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise BurpTempError("Unsafe Burp audit file")
            os.fchmod(fd, 0o600)
            os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def plan(self, *, now: float | None = None) -> BurpTempPlan:
        current = time.time() if now is None else now
        tmp = self._tmp_root()
        with self._hold(tmp, shared=True):
            device = tmp.stat().st_dev
            with os.scandir(tmp) as iterator:
                names = []
                for entry in iterator:
                    names.append(entry.name)
                    if len(names) > self.policy.max_root_entries:
                        raise BurpTempError("Burp temp root exceeds review limit")
            candidates = []
            scanned = 0
            truncated = False
            for name in sorted(names):
                if not _PROJECT.fullmatch(name):
                    continue
                scanned += 1
                size, _count, newest, fingerprint = self._tree(tmp / name, device)
                if newest > (current - self.policy.grace_hours * 3600) * 1_000_000_000:
                    continue
                if len(candidates) >= self.policy.max_candidates:
                    truncated = True
                    break
                candidates.append({"name": name, "bytes": size, "fingerprint": fingerprint})
            review_id = "BTR-" + uuid.uuid4().hex
            self._write_review({"review_id": review_id, "at": current, "entries": candidates})
            return BurpTempPlan(review_id, tuple(item["name"] for item in candidates),
                                sum(item["bytes"] for item in candidates), scanned, truncated)

    def run(self, review_id: str, *, confirmed: bool,
            now: float | None = None) -> dict[str, object]:
        if confirmed is not True or not isinstance(review_id, str) or not _REVIEW.fullmatch(review_id):
            raise BurpTempError("Burp temp cleanup requires a reviewed confirmation")
        current = time.time() if now is None else now
        tmp = self._tmp_root()
        with self._hold(tmp, shared=False):
            review = self._read_review()
            if (review["review_id"] != review_id or not review["entries"] or
                    not 0 <= current - review["at"] <= 900):
                raise BurpTempError("Burp temp review is stale or consumed")
            self.require_stopped(self.runtime_root)
            device = tmp.stat().st_dev
            for item in review["entries"]:
                size, _count, newest, fingerprint = self._tree(tmp / item["name"], device)
                if (size != item["bytes"] or fingerprint != item["fingerprint"] or
                        newest > (current - self.policy.grace_hours * 3600) * 1_000_000_000):
                    raise BurpTempError("Burp temp tree changed after review")
            if not shutil.rmtree.avoids_symlink_attacks:
                raise BurpTempError("Safe Burp temp removal is unavailable")
            self._audit("STARTED", review_id, 0)
            removed = 0
            for item in review["entries"]:
                self.require_stopped(self.runtime_root)
                shutil.rmtree(tmp / item["name"])
                removed += 1
            self._write_review({"review_id": review_id, "at": current, "entries": []})
            self._audit("COMPLETED", review_id, removed)
            return {"removed": removed, "reclaimed_estimate_bytes": sum(
                item["bytes"] for item in review["entries"]), "review_id": review_id}
