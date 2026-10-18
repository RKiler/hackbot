"""Bounded, read-only inventory of BugHunter's Burp runtime files."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import time


@dataclass(frozen=True, slots=True)
class BurpStorageStatus:
    state: str
    scanned_entries: int
    files: int
    directories: int
    symlinks_skipped: int
    estimated_bytes: int
    data_estimated_bytes: int
    temp_estimated_bytes: int
    other_estimated_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "scanned_entries": self.scanned_entries,
            "files": self.files,
            "directories": self.directories,
            "symlinks_skipped": self.symlinks_skipped,
            "estimated_bytes": self.estimated_bytes,
            "data_estimated_bytes": self.data_estimated_bytes,
            "temp_estimated_bytes": self.temp_estimated_bytes,
            "other_estimated_bytes": self.other_estimated_bytes,
        }


def inspect_burp_storage(root: Path, *, max_entries: int = 4096,
                         max_seconds: float = 0.5) -> BurpStorageStatus:
    """Return bounded logical-byte estimates; never read contents or follow links."""
    if not 1 <= max_entries <= 100_000 or not 0 < max_seconds <= 30:
        raise ValueError("Invalid Burp storage inventory limit")
    empty = BurpStorageStatus("UNAVAILABLE", 0, 0, 0, 0, 0, 0, 0, 0)
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            return empty
        deadline = time.monotonic() + max_seconds
        pending = [(root, "other")]
        scanned = files = directories = symlinks = 0
        sizes = {"data": 0, "tmp": 0, "other": 0}
        partial = False
        while pending:
            directory, category = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    if scanned >= max_entries or time.monotonic() >= deadline:
                        partial = True
                        break
                    scanned += 1
                    kind = (entry.name if directory == root and entry.name in {"data", "tmp"}
                            else category)
                    details = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(details.st_mode):
                        symlinks += 1
                        partial = True
                    elif stat.S_ISDIR(details.st_mode):
                        directories += 1
                        pending.append((Path(entry.path), kind))
                    elif stat.S_ISREG(details.st_mode):
                        files += 1
                        sizes[kind] += details.st_size
                    else:
                        partial = True
            if partial and (scanned >= max_entries or time.monotonic() >= deadline):
                break
        return BurpStorageStatus(
            "PARTIAL" if partial else "COMPLETE", scanned, files, directories,
            symlinks, sum(sizes.values()), sizes["data"], sizes["tmp"], sizes["other"])
    except (OSError, ValueError):
        return empty
