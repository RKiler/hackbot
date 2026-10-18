"""OpenPGP symmetric file encryption with a SecretProvider-managed key."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import shutil
import subprocess

from .secrets import SecretProvider


class BackupCryptoError(RuntimeError):
    pass


class GPGBackupCrypto:
    def __init__(self, provider: SecretProvider, secret_ref: str) -> None:
        self.provider = provider
        self.secret_ref = secret_ref

    def _passphrase(self) -> bytes:
        try:
            text = self.provider.get(self.secret_ref).reveal(execution_boundary=True)
            raw = base64.b64decode(text, validate=True)
        except Exception:
            raise BackupCryptoError("Backup encryption key is unavailable") from None
        if len(raw) != 32:
            raise BackupCryptoError("Backup encryption key must be 32 random bytes")
        return text.encode("ascii")

    def _run(self, operation: str, source: Path, destination: Path, home: Path,
             *, max_output_bytes: int | None = None) -> None:
        executable = shutil.which("gpg")
        if executable is None or source.is_symlink() or destination.exists() or destination.is_symlink():
            raise BackupCryptoError("Backup encryption is unavailable")
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(home, 0o700)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        read_fd, write_fd = os.pipe()
        completed = False
        try:
            os.write(write_fd, self._passphrase() + b"\n")
            os.close(write_fd)
            write_fd = -1
            command = [executable, "--homedir", str(home), "--no-options", "--batch", "--yes",
                       "--quiet", "--no-symkey-cache", "--pinentry-mode", "loopback",
                       "--passphrase-fd", str(read_fd), "--output", str(destination)]
            if operation == "encrypt":
                command.extend(["--symmetric", "--cipher-algo", "AES256",
                                "--s2k-mode", "3", "--s2k-digest-algo", "SHA256",
                                "--s2k-count", "65536", str(source)])
            elif operation == "decrypt":
                if type(max_output_bytes) is not int or max_output_bytes < 0:
                    raise BackupCryptoError("Invalid backup plaintext size")
                command.extend(["--max-output", str(max(1, max_output_bytes)),
                                "--decrypt", str(source)])
            else:
                raise BackupCryptoError("Invalid backup crypto operation")
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, pass_fds=(read_fd,),
                                    timeout=120, check=False, umask=0o077)
            if result.returncode != 0 or not destination.is_file():
                raise BackupCryptoError("Backup encryption or decryption failed")
            os.chmod(destination, 0o600)
            completed = True
        except (OSError, subprocess.TimeoutExpired):
            raise BackupCryptoError("Backup encryption or decryption failed") from None
        finally:
            if not completed:
                try:
                    destination.unlink(missing_ok=True)
                except OSError:
                    pass
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

    def encrypt(self, source: Path, destination: Path, home: Path) -> None:
        self._run("encrypt", source, destination, home)

    def decrypt(self, source: Path, destination: Path, home: Path,
                *, max_output_bytes: int) -> None:
        self._run("decrypt", source, destination, home,
                  max_output_bytes=max_output_bytes)
