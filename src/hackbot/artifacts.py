"""Local, content-addressed artifact bytes. No caller-supplied paths."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import tempfile


class ArtifactIntegrityError(RuntimeError):
    """An existing artifact does not match its digest or is unsafe to read."""


@dataclass(frozen=True)
class ArtifactRef:
    sha256: str
    size_bytes: int


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve(strict=False)

    def path_for(self, digest: str) -> Path:
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Invalid SHA-256 artifact identifier")
        return self.root / "sha256" / digest[:2] / digest

    def _prepare_parent(self, parent: Path) -> None:
        for directory in (self.root, self.root / "sha256", parent):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if directory.is_symlink() or not directory.is_dir():
                raise ArtifactIntegrityError("Unsafe artifact directory")

    def _verified_size(self, digest: str) -> int:
        path = self.path_for(digest)
        if path.is_symlink():
            raise ArtifactIntegrityError("Unsafe artifact link")
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except (OSError, ValueError) as exc:
            raise ArtifactIntegrityError("Cannot open artifact") from None
        try:
            actual = hashlib.sha256()
            size = 0
            with os.fdopen(fd, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    actual.update(chunk)
                    size += len(chunk)
            if actual.hexdigest() != digest:
                raise ArtifactIntegrityError("Artifact digest mismatch")
            return size
        except OSError:
            raise ArtifactIntegrityError("Cannot verify artifact") from None

    def put_bytes(self, content: bytes) -> ArtifactRef:
        if not isinstance(content, bytes):
            raise TypeError("Artifact content must be bytes")
        digest = hashlib.sha256(content).hexdigest()
        destination = self.path_for(digest)
        self._prepare_parent(destination.parent)
        if destination.exists() or destination.is_symlink():
            size = self._verified_size(digest)
            return ArtifactRef(digest, size)

        fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=destination.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, destination, follow_symlinks=False)
            except FileExistsError:
                if self._verified_size(digest) != len(content):
                    raise ArtifactIntegrityError("Existing artifact size mismatch")
            return ArtifactRef(digest, len(content))
        finally:
            Path(temporary).unlink(missing_ok=True)

    def get_bytes(self, digest: str, *, max_bytes: int = 1024 * 1024) -> bytes:
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("Invalid artifact read limit")
        path = self.path_for(digest)
        if path.is_symlink():
            raise ArtifactIntegrityError("Unsafe artifact link")
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            raise ArtifactIntegrityError("Cannot open artifact") from None
        try:
            with os.fdopen(fd, "rb") as handle:
                content = handle.read(max_bytes + 1)
                if len(content) > max_bytes:
                    raise ValueError("Artifact exceeds explicit read limit")
            if hashlib.sha256(content).hexdigest() != digest:
                raise ArtifactIntegrityError("Artifact digest mismatch")
            return content
        except OSError:
            raise ArtifactIntegrityError("Cannot read artifact") from None
