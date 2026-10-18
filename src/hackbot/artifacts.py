"""Local, content-addressed artifact bytes. No caller-supplied paths."""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Iterator


class ArtifactIntegrityError(RuntimeError):
    """An existing artifact does not match its digest or is unsafe to read."""


class ArtifactLimitError(ValueError):
    """An artifact exceeds the configured local write budget."""


@dataclass(frozen=True)
class ArtifactRef:
    sha256: str
    size_bytes: int


class ArtifactStore:
    def __init__(self, root: Path, *, max_blob_bytes: int = 134_217_728) -> None:
        if type(max_blob_bytes) is not int or max_blob_bytes <= 0:
            raise ValueError("Invalid artifact write limit")
        self.root = root.expanduser().resolve(strict=False)
        self.max_blob_bytes = max_blob_bytes

    def prepare(self) -> None:
        """Create and validate the private content-addressed root at startup."""
        self._prepare_parent(self.root / "sha256")

    def path_for(self, digest: str) -> Path:
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Invalid SHA-256 artifact identifier")
        return self.root / "sha256" / digest[:2] / digest

    @contextmanager
    def hold(self, *, shared: bool = False) -> Iterator[None]:
        """Coordinate artifact writers and garbage collection across processes."""
        self._prepare_parent(self.root / "sha256")
        lock_path = self.root / ".artifact.lock"
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.fchmod(fd, 0o600)
        except OSError:
            raise ArtifactIntegrityError("Cannot open artifact lock") from None
        try:
            fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _prepare_parent(self, parent: Path) -> None:
        for directory in (self.root, self.root / "sha256", parent):
            existed = directory.exists() or directory.is_symlink()
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if directory.is_symlink() or not directory.is_dir():
                raise ArtifactIntegrityError("Unsafe artifact directory")
            if not existed:
                self._fsync_directory(directory.parent)

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        try:
            fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                         getattr(os, "O_NOFOLLOW", 0))
            try:
                if not stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise ArtifactIntegrityError("Unsafe artifact directory")
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            raise ArtifactIntegrityError("Cannot sync artifact directory") from None

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
        if len(content) > self.max_blob_bytes:
            raise ArtifactLimitError("Artifact exceeds configured write limit")
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
            else:
                self._fsync_directory(destination.parent)
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
