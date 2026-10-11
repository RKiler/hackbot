"""Explicit public-CA trust for one isolated Chromium profile, never system trust."""

from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import ssl
import subprocess


class ProfileTrustError(ValueError):
    """Value-free profile trust failure."""


def install_profile_ca(profile: Path, certificate: Path) -> None:
    if (not isinstance(profile, Path) or not profile.is_dir() or not isinstance(certificate, Path)
            or not certificate.is_absolute() or not certificate.is_file()
            or certificate.is_symlink()):
        raise ProfileTrustError("Profile CA input is unavailable")
    try:
        pem = certificate.read_bytes()
        if (len(pem) > 65536 or pem.count(b"-----BEGIN CERTIFICATE-----") != 1
                or b"PRIVATE KEY" in pem):
            raise ValueError
        der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
    except (OSError, UnicodeError, ValueError):
        raise ProfileTrustError("Profile CA certificate is invalid") from None
    certutil = shutil.which("certutil")
    if certutil is None:
        raise ProfileTrustError("NSS certutil is required for profile-only CA trust")
    home = profile.parent
    db = home / ".pki" / "nssdb"
    db.mkdir(parents=True, exist_ok=True, mode=0o700)
    db.chmod(0o700)
    nickname = "BugHunter-" + hashlib.sha256(der).hexdigest()[:16]
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C"}

    def run(*args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run([certutil, *args], env=env, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=10, check=False)

    try:
        if not (db / "cert9.db").exists() and run("-N", "--empty-password", "-d", "sql:" + str(db)).returncode != 0:
            raise ProfileTrustError("Profile NSS database initialization failed")
        if run("-L", "-d", "sql:" + str(db), "-n", nickname).returncode == 0:
            return
        if run("-A", "-d", "sql:" + str(db), "-n", nickname,
               "-t", "C,,", "-i", str(certificate)).returncode != 0:
            raise ProfileTrustError("Profile CA import failed")
    except (OSError, subprocess.TimeoutExpired):
        raise ProfileTrustError("Profile CA import failed") from None
