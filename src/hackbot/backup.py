"""Consistent, inspectable backups of BugHunter-owned state and artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import closing, contextmanager, nullcontext
from datetime import datetime, timezone
import fcntl
import hashlib
from itertools import chain
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
import uuid
from typing import Any
from urllib.parse import quote

from . import __version__
from .artifact_refs import (EVIDENCE_ARTIFACT_REFERENCES,
                            verify_artifact_reference_schema)
from .dom_guard_schema import verify_dom_retirement_guards
from .dom_refs import DOMReferenceError
from .artifacts import ArtifactStore
from .backup_crypto import BackupCryptoError, GPGBackupCrypto
from .config import AppConfig, BackupSettings, StoreSettings
from .db_maintenance import check_database
from .evidence_refs import evidence_reference_inventory, EvidenceReferenceError
from .evidence_json_index_schema import verify_evidence_json_index
from .json_reference_audit import (ReferenceIndexAuditError,
                                   audit_json_reference_indexes)
from .secrets import RoutedSecretProvider, SecretProvider
from .store import EvidenceFactStore, StoreSchemaError, _SCHEMA_VERSION
from .traffic_guard_schema import (verify_traffic_retirement_guards,
                                   verify_traffic_json_index)
from .traffic_refs import TrafficReferenceError


class BackupError(RuntimeError):
    """A backup is unsafe, incomplete, or fails verification."""


_BACKUP_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z")
_RESTORE_STAGE = re.compile(r"restore-[A-Za-z0-9_]{8}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_EVIDENCE_ID = re.compile(r"EV-[0-9a-f]{32}\Z")
_SUPPORTED_SCHEMAS = frozenset(range(34, _SCHEMA_VERSION + 1))
_ARTIFACT_SELECTION_VERSION = 4
_MAX_BACKUP_ARTIFACTS = 50_000
_MAX_MANIFEST_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class BackupSummary:
    backup_id: str
    created_at: str
    artifact_mode: str
    schema_version: int
    file_count: int
    total_bytes: int
    verified: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "backup_id": self.backup_id, "created_at": self.created_at,
            "artifact_mode": self.artifact_mode, "schema_version": self.schema_version,
            "file_count": self.file_count, "total_bytes": self.total_bytes,
            "verified": self.verified,
        }


class BackupManager:
    """Back up a SQLite snapshot and only its digest-addressed linked blobs."""

    def __init__(self, store: EvidenceFactStore, settings: BackupSettings,
                 report_artifacts: ArtifactStore,
                 secret_provider: SecretProvider | None = None,
                 min_free_bytes: int = 2_147_483_648,
                 *, required_mount: Path | None = None) -> None:
        self.store = store
        self.settings = settings
        self.report_artifacts = report_artifacts
        if type(min_free_bytes) is not int or min_free_bytes < 0:
            raise ValueError("Invalid backup free-space reserve")
        self.min_free_bytes = min_free_bytes
        self.required_mount = required_mount
        self.crypto = (GPGBackupCrypto(secret_provider, settings.encryption_secret_ref)
                       if settings.encryption_secret_ref and secret_provider else None)
        if settings.encryption_secret_ref and self.crypto is None:
            raise BackupError("Backup encryption provider is unavailable")

    @classmethod
    def from_config(cls, config: AppConfig) -> BackupManager:
        if config.backup is None:
            raise BackupError("Backup configuration is unavailable")
        return cls(EvidenceFactStore.from_config(config), config.backup,
                   ArtifactStore(config.paths.artifacts / "reports"),
                   RoutedSecretProvider(config.secrets) if config.secrets else None,
                   config.resources.min_free_disk_bytes if config.resources else 2_147_483_648,
                   required_mount=(Path(config.resources.required_mount)
                                   if config.resources and config.resources.required_mount else None))

    def _require_state_mount(self) -> None:
        if self.required_mount is None:
            return
        try:
            mount = self.required_mount.resolve(strict=True)
            mounted = (os.path.ismount(mount) and
                       self.store.db_path.resolve(strict=True).is_relative_to(mount) and
                       self.store.artifacts.root.resolve(strict=False).is_relative_to(mount))
        except (OSError, ValueError):
            mounted = False
        if not mounted:
            raise BackupError("Required state mount is unavailable")

    def _require_capacity(self, additional_bytes: int) -> None:
        try:
            free = shutil.disk_usage(self._root()).free
        except (OSError, ValueError):
            raise BackupError("Backup storage capacity is unavailable") from None
        if free < self.min_free_bytes + additional_bytes:
            raise BackupError("Insufficient free space for backup")

    @staticmethod
    def _materialized_bytes(manifest: dict[str, Any], *, encrypted: bool) -> int:
        entries = manifest.get("files")
        if not isinstance(entries, list) or not 1 <= len(entries) <= _MAX_BACKUP_ARTIFACTS + 1:
            raise BackupError("Backup manifest is incompatible")
        field = "plaintext_bytes" if encrypted else "bytes"
        total = 0
        for entry in entries:
            if not isinstance(entry, dict) or type(entry.get(field)) is not int or entry[field] < 0:
                raise BackupError("Invalid backup file entry")
            total += entry[field]
        return total

    @staticmethod
    def _artifact_size(source: Path) -> int:
        for directory in (source.parent, source.parent.parent, source.parent.parent.parent):
            if directory.is_symlink() or not directory.is_dir():
                raise BackupError("Unsafe backup artifact directory")
        try:
            details = source.lstat()
        except OSError:
            raise BackupError("Backup artifact is unavailable") from None
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise BackupError("Unsafe backup artifact entry")
        return details.st_size

    def _root(self, *, create: bool = False) -> Path:
        root = self.settings.root
        if root.is_symlink():
            raise BackupError("Unsafe backup root")
        if create:
            root.mkdir(parents=True, mode=0o700, exist_ok=True)
            os.chmod(root, 0o700)
        if not root.is_dir():
            raise BackupError("Backup root is unavailable")
        return root

    @contextmanager
    def _hold(self, *, shared: bool = False):
        root = self._root()
        try:
            fd = os.open(root / ".backup.lock", os.O_CREAT | os.O_RDWR |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.fchmod(fd, 0o600)
        except OSError:
            raise BackupError("Cannot lock backup inventory") from None
        try:
            fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _audit(self, action: str, backup_id: str, **details: object) -> None:
        root = self._root(create=True)
        event = {"at": datetime.now(timezone.utc).isoformat(), "action": action,
                 "backup_id": backup_id, **details}
        try:
            fd = os.open(root / "maintenance-audit.jsonl", os.O_CREAT | os.O_WRONLY |
                         os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "ab") as handle:
                handle.write((json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            raise BackupError("Cannot audit backup action") from None

    @staticmethod
    def _hash_file(path: Path) -> tuple[str, int]:
        if path.is_symlink() or not path.is_file():
            raise BackupError("Unsafe or missing backup file")
        digest = hashlib.sha256()
        size = 0
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
        except OSError:
            raise BackupError("Cannot read backup file") from None
        return digest.hexdigest(), size

    @classmethod
    def _copy_digest(cls, source: Path, destination: Path, expected: str) -> dict[str, object]:
        if not _DIGEST.fullmatch(expected):
            raise BackupError("Invalid artifact reference")
        if source.is_symlink() or not source.is_file() or destination.exists():
            raise BackupError("Unsafe artifact backup path")
        destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        try:
            source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(source_fd, "rb") as input_handle:
                dest_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(dest_fd, "wb") as output_handle:
                    shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
                    output_handle.flush()
                    os.fsync(output_handle.fileno())
        except OSError:
            raise BackupError("Cannot copy artifact into backup") from None
        actual, size = cls._hash_file(destination)
        if actual != expected:
            raise BackupError("Artifact hash changed during backup")
        return {"path": destination.as_posix(), "sha256": actual, "bytes": size}

    @staticmethod
    def _finding_validation_evidence_ids(snapshot: sqlite3.Connection) -> set[str]:
        ids: set[str] = set()
        linked = """EXISTS (SELECT 1 FROM findings f WHERE f.validation_id=v.validation_id)
                 OR EXISTS (SELECT 1 FROM finding_locations fl
                            WHERE fl.validation_id=v.validation_id)
                 OR EXISTS (SELECT 1 FROM finding_duplicates fd
                            WHERE fd.validation_id=v.validation_id)"""
        validations = snapshot.execute(
            "SELECT v.supporting_evidence_json,v.contradicting_evidence_json "
            f"FROM validations v WHERE {linked}")
        checks = snapshot.execute(
            "SELECT vc.evidence_ids_json FROM validation_checks vc "
            "JOIN validations v ON v.validation_id=vc.validation_id "
            f"WHERE {linked}")
        for row in chain(validations, checks):
            for raw in row:
                try:
                    values = json.loads(raw)
                except (TypeError, ValueError):
                    raise BackupError("Finding validation evidence references are invalid") from None
                if (not isinstance(values, list) or len(values) > 64 or
                        any(not isinstance(value, str) or not _EVIDENCE_ID.fullmatch(value)
                            for value in values)):
                    raise BackupError("Finding validation evidence references are invalid")
                ids.update(values)
                if len(ids) > _MAX_BACKUP_ARTIFACTS:
                    raise BackupError("Backup artifact selection exceeds limit")
        return ids

    @staticmethod
    def _add_artifact_hashes(selected: set[str], rows: Any) -> None:
        for row in rows:
            selected.add(row[0])
            if len(selected) > _MAX_BACKUP_ARTIFACTS:
                raise BackupError("Backup artifact selection exceeds limit")

    def _artifact_hashes(self, snapshot: sqlite3.Connection, mode: str,
                         selection_version: int = _ARTIFACT_SELECTION_VERSION
                         ) -> tuple[list[str], list[str], dict[str, int]]:
        try:
            verify_artifact_reference_schema(snapshot)
            evidence_reference_inventory(snapshot)
            if snapshot.execute("PRAGMA user_version").fetchone()[0] >= 42:
                verify_traffic_retirement_guards(snapshot)
            if snapshot.execute("PRAGMA user_version").fetchone()[0] >= 43:
                verify_traffic_json_index(snapshot)
            if snapshot.execute("PRAGMA user_version").fetchone()[0] >= 44:
                verify_evidence_json_index(snapshot)
            if snapshot.execute("PRAGMA user_version").fetchone()[0] >= 45:
                from .research_retention import verify_research_retirement_schema
                verify_research_retirement_schema(snapshot)
            if snapshot.execute("PRAGMA user_version").fetchone()[0] >= 46:
                verify_dom_retirement_guards(snapshot)
        except (ValueError, EvidenceReferenceError):
            raise BackupError("Artifact reference schema requires review") from None
        tables = {row[0] for row in snapshot.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        counts = {
            name: snapshot.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
            if name in tables else 0
            for name in ("evidence", "traffic_exchanges", "findings", "report_drafts", "planner_runs")
        }
        if mode == "ALL":
            evidence_hashes: set[str] = set()
            if selection_version >= 4 and "evidence_payload_retirements" in tables:
                from .retention import ArtifactGarbageCollector
                try:
                    for table, column in EVIDENCE_ARTIFACT_REFERENCES:
                        if table not in tables:
                            continue
                        after = ""
                        while True:
                            page = snapshot.execute(
                                f"SELECT DISTINCT {column} FROM {table} "
                                f"WHERE {column}>? ORDER BY {column} LIMIT 512",
                                (after,),
                            ).fetchall()
                            for row in page:
                                digest = row[0]
                                if (digest not in evidence_hashes and
                                        ArtifactGarbageCollector._referenced(snapshot, digest)):
                                    evidence_hashes.add(digest)
                                    if len(evidence_hashes) > _MAX_BACKUP_ARTIFACTS:
                                        raise BackupError("Backup artifact selection exceeds limit")
                            if len(page) < 512:
                                break
                            after = page[-1][0]
                except (ValueError, DOMReferenceError, EvidenceReferenceError,
                        TrafficReferenceError, sqlite3.Error):
                    raise BackupError("Artifact reachability check is incomplete") from None
            else:
                for table, column in EVIDENCE_ARTIFACT_REFERENCES:
                    if table in tables:
                        if (table == "evidence" and selection_version >= 3 and
                                "evidence_payload_retirements" in tables):
                            rows = snapshot.execute(
                                "SELECT DISTINCT e.artifact_hash FROM evidence e "
                                "WHERE e.artifact_hash IS NOT NULL AND NOT EXISTS ("
                                "SELECT 1 FROM evidence_payload_retirements r "
                                "WHERE r.evidence_id=e.evidence_id) LIMIT ?",
                                (_MAX_BACKUP_ARTIFACTS + 1,),
                            )
                        else:
                            rows = snapshot.execute(
                                f"SELECT DISTINCT {column} FROM {table} "
                                f"WHERE {column} IS NOT NULL LIMIT ?",
                                (_MAX_BACKUP_ARTIFACTS + 1,),
                            )
                        self._add_artifact_hashes(evidence_hashes, rows)
        else:
            rows = snapshot.execute("""
                SELECT DISTINCT e.artifact_hash FROM evidence e
                WHERE e.artifact_hash IS NOT NULL AND (
                    EXISTS (SELECT 1 FROM finding_evidence fe WHERE fe.evidence_id=e.evidence_id)
                    OR EXISTS (SELECT 1 FROM evidence_policy_events p WHERE p.evidence_id=e.evidence_id
                               AND p.event_id=(SELECT max(event_id) FROM evidence_policy_events
                                               WHERE evidence_id=e.evidence_id)
                               AND (p.pinned=1 OR p.finding_related=1))
                ) ORDER BY e.artifact_hash LIMIT ?
            """, (_MAX_BACKUP_ARTIFACTS + 1,))
            evidence_hashes: set[str] = set()
            self._add_artifact_hashes(evidence_hashes, rows)
            if selection_version >= 2:
                referenced_ids = sorted(self._finding_validation_evidence_ids(snapshot))
                for offset in range(0, len(referenced_ids), 500):
                    batch = referenced_ids[offset:offset + 500]
                    marks = ",".join("?" for _ in batch)
                    found = snapshot.execute(
                        f"SELECT evidence_id,artifact_hash FROM evidence "
                        f"WHERE evidence_id IN ({marks})", batch).fetchall()
                    if len(found) != len(batch):
                        raise BackupError("Finding validation evidence is missing")
                    self._add_artifact_hashes(evidence_hashes,
                                              ((row[1],) for row in found if row[1] is not None))
        report_hashes: set[str] = set()
        if "report_drafts" in tables:
            self._add_artifact_hashes(report_hashes, snapshot.execute(
                "SELECT DISTINCT content_sha256 FROM report_drafts "
                "ORDER BY content_sha256 LIMIT ?", (_MAX_BACKUP_ARTIFACTS + 1,),
            ))
        if len(evidence_hashes) + len(report_hashes) > _MAX_BACKUP_ARTIFACTS:
            raise BackupError("Backup artifact selection exceeds limit")
        return sorted(evidence_hashes), sorted(report_hashes), counts

    @staticmethod
    def _reject_unencrypted_secrets(snapshot: sqlite3.Connection) -> None:
        if snapshot.execute(
                "SELECT 1 FROM evidence WHERE sensitivity='SECRET' LIMIT 1"
        ).fetchone() is not None:
            raise BackupError("Secret evidence requires encrypted backup support")

    def create(self) -> BackupSummary:
        self._require_state_mount()
        self._root(create=True)
        with self._hold():
            backup_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
            self._audit("BACKUP_STARTED", backup_id)
            try:
                with (self.store.artifacts.hold(shared=True),
                      self.report_artifacts.hold(shared=True)):
                    return self._create_locked(backup_id)
            except Exception as exc:
                try:
                    self._audit("BACKUP_FAILED", backup_id, error_type=type(exc).__name__)
                except BackupError:
                    pass
                raise

    def _create_locked(self, backup_id: str) -> BackupSummary:
        root = self._root(create=True)
        if not self.store.db_path.is_file() or self.store.db_path.is_symlink():
            raise BackupError("BugHunter state database is unavailable")
        database_bytes = self.store.db_path.stat().st_size
        self._require_capacity(max(database_bytes, 1_048_576) *
                               (2 if self.crypto else 1))
        staging = Path(tempfile.mkdtemp(prefix=".pending-", dir=root))
        os.chmod(staging, 0o700)
        destination = root / backup_id
        try:
            database = staging / "state.sqlite3"
            source_uri = "file:" + quote(str(self.store.db_path), safe="/") + "?mode=ro"
            with closing(sqlite3.connect(source_uri, uri=True, timeout=5)) as source:
                with closing(sqlite3.connect(database)) as target:
                    source.backup(target, pages=256, sleep=0.1)
            os.chmod(database, 0o600)
            with closing(sqlite3.connect(f"file:{quote(str(database), safe='/')}?mode=ro", uri=True)) as snapshot:
                if snapshot.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise BackupError("SQLite snapshot failed integrity check")
                if snapshot.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise BackupError("SQLite snapshot has broken references")
                version = snapshot.execute("PRAGMA user_version").fetchone()[0]
                if version not in _SUPPORTED_SCHEMAS:
                    raise StoreSchemaError("Unsupported backup schema version")
                evidence_hashes, report_hashes, counts = self._artifact_hashes(
                    snapshot, self.settings.artifact_mode)
                if self.crypto is None:
                    self._reject_unencrypted_secrets(snapshot)
            if len(evidence_hashes) + len(report_hashes) > _MAX_BACKUP_ARTIFACTS:
                raise BackupError("Backup artifact selection exceeds limit")
            artifact_bytes = 0
            largest_file = database.stat().st_size
            for hashes, artifact_store in (
                    (evidence_hashes, self.store.artifacts),
                    (report_hashes, self.report_artifacts)):
                for artifact_hash in hashes:
                    size = self._artifact_size(artifact_store.path_for(artifact_hash))
                    artifact_bytes += size
                    largest_file = max(largest_file, size)
            verify_bytes = database.stat().st_size + artifact_bytes + 1_048_576
            self._require_capacity(artifact_bytes +
                                   (max(largest_file, verify_bytes) if self.crypto else 0))
            files: list[dict[str, object]] = []
            digest, size = self._hash_file(database)
            files.append({"path": "state.sqlite3", "sha256": digest, "bytes": size})
            for category, hashes, artifact_store in (
                ("evidence", evidence_hashes, self.store.artifacts),
                ("reports", report_hashes, self.report_artifacts),
            ):
                for artifact_hash in hashes:
                    relative = Path("artifacts") / category / "sha256" / artifact_hash[:2] / artifact_hash
                    entry = self._copy_digest(artifact_store.path_for(artifact_hash),
                                              staging / relative, artifact_hash)
                    entry["path"] = relative.as_posix()
                    files.append(entry)
            if self.crypto is not None:
                encrypted_files = []
                home = staging / ".gpg-home"
                try:
                    for entry in files:
                        source = staging / entry["path"]
                        destination_file = source.with_name(source.name + ".gpg")
                        self.crypto.encrypt(source, destination_file, home)
                        source.unlink()
                        encrypted_hash, encrypted_size = self._hash_file(destination_file)
                        encrypted_files.append({"path": entry["path"] + ".gpg",
                                                "sha256": encrypted_hash,
                                                "bytes": encrypted_size,
                                                "plaintext_sha256": entry["sha256"],
                                                "plaintext_bytes": entry["bytes"]})
                finally:
                    if home.exists():
                        shutil.rmtree(home)
                files = encrypted_files
            manifest = {
                "format": 1, "backup_id": backup_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "bughunter_version": __version__, "schema_version": version,
                "artifact_mode": self.settings.artifact_mode,
                "artifact_selection_version": _ARTIFACT_SELECTION_VERSION,
                "encryption": "OPENPGP_GPG_AES256" if self.crypto else "NONE",
                "included_classes": ["SQLITE_STATE", "REPORT_DRAFTS", "EVIDENCE_ARTIFACTS"],
                "counts": counts, "files": files,
                "browser_profiles_included": False, "burp_runtime_included": False,
            }
            manifest_path = staging / "manifest.json"
            with manifest_path.open("x", encoding="utf-8") as handle:
                os.chmod(manifest_path, 0o600)
                json.dump(manifest, handle, sort_keys=True, indent=2)
                handle.write("\n")
                if handle.tell() > _MAX_MANIFEST_BYTES:
                    raise BackupError("Backup manifest exceeds size limit")
                handle.flush()
                os.fsync(handle.fileno())
            if destination.exists() or destination.is_symlink():
                raise BackupError("Backup identifier already exists")
            result = self._verify_unlocked(backup_id, directory=staging)
            staging.rename(destination)
            self._record_verification(backup_id)
            self._audit("BACKUP_CREATED", backup_id, schema_version=version,
                        file_count=result.file_count, verified=result.verified)
            return result
        except BackupCryptoError:
            if staging.exists():
                shutil.rmtree(staging)
            raise BackupError("Backup encryption failed") from None
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            raise

    def _directory(self, backup_id: str) -> Path:
        if not isinstance(backup_id, str) or not _BACKUP_ID.fullmatch(backup_id):
            raise BackupError("Invalid backup identifier")
        path = self._root() / backup_id
        if path.is_symlink() or not path.is_dir():
            raise BackupError("Backup is unavailable")
        return path

    def verify(self, backup_id: str, *, record: bool = False) -> BackupSummary:
        with self._hold(shared=True):
            summary = self._verify_unlocked(backup_id)
            if record:
                self._record_verification(backup_id)
            return summary

    def _record_verification(self, backup_id: str) -> None:
        directory = self._directory(backup_id)
        manifest_hash, _ = self._hash_file(directory / "manifest.json")
        marker = directory / "verification.json"
        fd, temporary = tempfile.mkstemp(prefix=".verification-", dir=directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"verified_at": datetime.now(timezone.utc).isoformat(),
                           "manifest_sha256": manifest_hash}, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            if marker.is_symlink():
                raise BackupError("Unsafe backup verification marker")
            os.replace(temporary, marker)
            self._audit("BACKUP_VERIFIED", backup_id)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def _verify_unlocked(self, backup_id: str, *, directory: Path | None = None) -> BackupSummary:
        directory = self._directory(backup_id) if directory is None else directory
        manifest_path = directory / "manifest.json"
        if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > _MAX_MANIFEST_BYTES:
            raise BackupError("Backup manifest is unavailable")
        try:
            manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise BackupError("Backup manifest is invalid") from None
        if (manifest.get("format") != 1 or manifest.get("backup_id") != backup_id
                or manifest.get("schema_version") not in _SUPPORTED_SCHEMAS
                or manifest.get("artifact_mode") not in {"ALL", "FINDING_LINKED"}
                or type(manifest.get("artifact_selection_version", 1)) is not int
                or manifest.get("artifact_selection_version", 1) not in {1, 2, 3, 4}
                or manifest.get("encryption", "NONE") not in {"NONE", "OPENPGP_GPG_AES256"}
                or not isinstance(manifest.get("bughunter_version"), str)
                or not isinstance(manifest.get("counts"), dict)
                or not isinstance(manifest.get("files"), list)
                or not 1 <= len(manifest["files"]) <= _MAX_BACKUP_ARTIFACTS + 1):
            raise BackupError("Backup manifest is incompatible")
        try:
            created = datetime.fromisoformat(manifest["created_at"])
            if created.tzinfo is None:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise BackupError("Backup timestamp is invalid") from None
        encrypted = manifest.get("encryption") == "OPENPGP_GPG_AES256"
        if encrypted and self.crypto is None:
            raise BackupError("Backup decryption key is unavailable")
        if encrypted:
            self._require_capacity(self._materialized_bytes(manifest, encrypted=True)
                                   + 1_048_576)
        seen: set[str] = set()
        total = 0
        context = (tempfile.TemporaryDirectory(prefix=".verify-", dir=self._root())
                   if encrypted else nullcontext(str(directory)))
        with context as materialized:
            materialized_root = Path(materialized)
            for entry in manifest["files"]:
                if not isinstance(entry, dict):
                    raise BackupError("Invalid backup file entry")
                raw = entry.get("path")
                expected = entry.get("sha256")
                size = entry.get("bytes")
                if (not isinstance(raw, str) or raw.startswith("/") or "\\" in raw
                        or any(part in {"", ".", ".."} for part in raw.split("/"))
                        or not isinstance(expected, str) or not _DIGEST.fullmatch(expected)
                        or type(size) is not int or size < 0):
                    raise BackupError("Invalid backup file entry")
                plain = raw[:-4] if encrypted and raw.endswith(".gpg") else raw
                plain_hash = entry.get("plaintext_sha256") if encrypted else expected
                plain_size = entry.get("plaintext_bytes") if encrypted else size
                if (encrypted and (not raw.endswith(".gpg") or
                                   not isinstance(plain_hash, str) or
                                   not _DIGEST.fullmatch(plain_hash) or
                                   type(plain_size) is not int or plain_size < 0)):
                    raise BackupError("Invalid encrypted backup entry")
                if plain in seen:
                    raise BackupError("Duplicate backup file entry")
                if plain != "state.sqlite3":
                    parts = plain.split("/")
                    if (len(parts) != 5 or parts[:2] not in
                            (["artifacts", "evidence"], ["artifacts", "reports"])
                            or parts[2] != "sha256" or parts[3] != plain_hash[:2]
                            or parts[4] != plain_hash):
                        raise BackupError("Invalid backup artifact path")
                path = directory / raw
                if any(parent.is_symlink() for parent in path.parents if parent != directory.parent):
                    raise BackupError("Unsafe backup file path")
                actual, actual_size = self._hash_file(path)
                if actual != expected or actual_size != size:
                    raise BackupError("Backup file hash mismatch")
                if encrypted:
                    destination = materialized_root / plain
                    assert self.crypto is not None
                    try:
                        self.crypto.decrypt(path, destination, materialized_root / ".gpg-home",
                                            max_output_bytes=plain_size)
                    except BackupCryptoError:
                        raise BackupError("Backup decryption failed") from None
                    digest, decoded_size = self._hash_file(destination)
                    if digest != plain_hash or decoded_size != plain_size:
                        raise BackupError("Backup plaintext hash mismatch")
                seen.add(plain)
                total += size
            if "state.sqlite3" not in seen:
                raise BackupError("Backup state is missing")
            database = materialized_root / "state.sqlite3"
            try:
                with closing(sqlite3.connect(f"file:{quote(str(database), safe='/')}?mode=ro", uri=True)) as snapshot:
                    if snapshot.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                        raise BackupError("Backup SQLite integrity check failed")
                    if snapshot.execute("PRAGMA foreign_key_check").fetchone() is not None:
                        raise BackupError("Backup SQLite has broken references")
                    if snapshot.execute("PRAGMA user_version").fetchone()[0] != manifest["schema_version"]:
                        raise BackupError("Backup schema version mismatch")
                    if not encrypted:
                        self._reject_unencrypted_secrets(snapshot)
                    evidence_hashes, report_hashes, counts = self._artifact_hashes(
                        snapshot, manifest["artifact_mode"],
                        manifest.get("artifact_selection_version", 1))
            except sqlite3.Error:
                raise BackupError("Backup SQLite state is invalid") from None
            required = {f"artifacts/evidence/sha256/{value[:2]}/{value}" for value in evidence_hashes}
            required.update(f"artifacts/reports/sha256/{value[:2]}/{value}" for value in report_hashes)
            if required != seen - {"state.sqlite3"} or counts != manifest["counts"]:
                raise BackupError("Backup references or counts do not match state")
        return BackupSummary(backup_id, manifest["created_at"], manifest["artifact_mode"],
                             manifest["schema_version"], len(seen), total, True)

    def list(self, *, limit: int = 50) -> list[BackupSummary]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid backup list limit")
        names = self._generation_names()
        result = []
        for name in names[:limit]:
            try:
                result.append(self.verify(name))
            except BackupError:
                result.append(BackupSummary(name, "unknown", "unknown", 0, 0, 0, False))
        return result

    def _generation_names(self) -> list[str]:
        if not self.settings.root.exists():
            return []
        paths = []
        for entry in self._root().iterdir():
            if not _BACKUP_ID.fullmatch(entry.name):
                continue
            if entry.is_symlink() or not entry.is_dir():
                raise BackupError("Unsafe backup generation entry")
            paths.append(entry)
            if len(paths) > 10_000:
                raise BackupError("Backup inventory exceeds maintenance bound")

        def created_key(entry: Path) -> tuple[int, str, str]:
            manifest = entry / "manifest.json"
            try:
                if manifest.is_symlink() or manifest.stat().st_size > _MAX_MANIFEST_BYTES:
                    raise ValueError
                document = json.loads(manifest.read_text(encoding="utf-8"))
                stamp = datetime.fromisoformat(document["created_at"])
                if document.get("backup_id") != entry.name or stamp.tzinfo is None:
                    raise ValueError
                return (0, stamp.astimezone(timezone.utc).isoformat(), entry.name)
            except (OSError, UnicodeError, ValueError, KeyError, TypeError):
                return (1, entry.name[:16], entry.name)

        paths.sort(key=created_key, reverse=True)
        return [entry.name for entry in paths]

    def incomplete_plan(self, *, grace_hours: int = 24) -> dict[str, object]:
        """Preview stale, private backup staging directories left by a crash."""
        if type(grace_hours) is not int or not 1 <= grace_hours <= 168:
            raise ValueError("Invalid incomplete-backup grace period")
        if not self.settings.root.exists():
            return {"candidates": [], "estimated_bytes": 0}
        with self._hold(shared=True):
            return self._incomplete_plan_unlocked(grace_hours)

    def _incomplete_plan_unlocked(self, grace_hours: int) -> dict[str, object]:
        root = self._root()
        cutoff = datetime.now(timezone.utc).timestamp() - grace_hours * 3600
        candidates: list[str] = []
        total_bytes = 0
        inspected = 0
        for entry in root.iterdir():
            if not re.fullmatch(r"\.pending-[A-Za-z0-9_]{8}", entry.name):
                continue
            details = entry.lstat()
            if not stat.S_ISDIR(details.st_mode) or details.st_mtime > cutoff:
                continue
            if len(candidates) >= 100:
                raise BackupError("Incomplete backup inventory exceeds maintenance bound")
            for current, dirs, files in os.walk(entry, followlinks=False):
                for name in dirs + files:
                    inspected += 1
                    if inspected > 100_000:
                        raise BackupError("Incomplete backup tree exceeds maintenance bound")
                    item = Path(current) / name
                    item_details = item.lstat()
                    if not (stat.S_ISDIR(item_details.st_mode) or
                            stat.S_ISREG(item_details.st_mode)):
                        raise BackupError("Unsafe incomplete backup entry")
                    if stat.S_ISREG(item_details.st_mode):
                        total_bytes += item_details.st_size
            candidates.append(entry.name)
        return {"candidates": sorted(candidates), "estimated_bytes": total_bytes}

    def cleanup_incomplete(self, *, confirmed: bool, grace_hours: int = 24) -> dict[str, object]:
        if confirmed is not True:
            raise BackupError("Incomplete backup cleanup requires explicit confirmation")
        if type(grace_hours) is not int or not 1 <= grace_hours <= 168:
            raise ValueError("Invalid incomplete-backup grace period")
        if not self.settings.root.exists():
            return {"removed": [], "reclaimed_bytes": 0}
        with self._hold():
            plan = self._incomplete_plan_unlocked(grace_hours)
            if plan["candidates"]:
                self._audit("BACKUP_INCOMPLETE_CLEANUP_STARTED", "", count=len(plan["candidates"]))
            for name in plan["candidates"]:
                directory = self._root() / name
                if directory.is_symlink() or not directory.is_dir():
                    raise BackupError("Incomplete backup changed during cleanup")
                shutil.rmtree(directory)
                self._audit("BACKUP_INCOMPLETE_REMOVED", "", staging=name)
            return {"removed": plan["candidates"], "reclaimed_bytes": plan["estimated_bytes"]}

    def stale_restore_plan(self, *, grace_hours: int = 24) -> dict[str, object]:
        """Preview only old decrypted restore stages, never completed backups."""
        if type(grace_hours) is not int or not 1 <= grace_hours <= 168:
            raise ValueError("Invalid restore-stage grace period")
        if not self.settings.root.exists():
            return {"candidates": [], "estimated_bytes": 0}
        with self._hold(shared=True):
            return self._stale_restore_plan_unlocked(grace_hours)

    def _stale_restore_plan_unlocked(self, grace_hours: int) -> dict[str, object]:
        root = self._root() / "restore-staging"
        if not root.exists() and not root.is_symlink():
            return {"candidates": [], "estimated_bytes": 0}
        if root.is_symlink() or not root.is_dir():
            raise BackupError("Unsafe restore staging root")
        cutoff = datetime.now(timezone.utc).timestamp() - grace_hours * 3600
        candidates: list[dict[str, object]] = []
        inspected = total = 0
        for entry in root.iterdir():
            if not _RESTORE_STAGE.fullmatch(entry.name):
                continue
            details = entry.lstat()
            if not stat.S_ISDIR(details.st_mode):
                raise BackupError("Unsafe restore staging entry")
            if details.st_mtime > cutoff:
                continue
            if len(candidates) >= 100:
                raise BackupError("Restore staging inventory exceeds maintenance bound")
            size = 0
            for current, dirs, files in os.walk(entry, followlinks=False):
                for name in dirs + files:
                    inspected += 1
                    if inspected > 100_000:
                        raise BackupError("Restore staging tree exceeds maintenance bound")
                    item = Path(current) / name
                    item_details = item.lstat()
                    if not (stat.S_ISDIR(item_details.st_mode) or
                            stat.S_ISREG(item_details.st_mode)):
                        raise BackupError("Unsafe restore staging entry")
                    if stat.S_ISREG(item_details.st_mode):
                        size += item_details.st_size
            total += size
            candidates.append({"name": entry.name, "bytes": size})
        candidates.sort(key=lambda item: item["name"])
        return {"candidates": candidates, "estimated_bytes": total}

    def cleanup_stale_restore(self, name: str, *, confirmed: bool,
                              grace_hours: int = 24) -> dict[str, object]:
        if confirmed is not True or not isinstance(name, str) or not _RESTORE_STAGE.fullmatch(name):
            raise BackupError("Restore-stage cleanup requires an exact reviewed name and confirmation")
        if type(grace_hours) is not int or not 1 <= grace_hours <= 168:
            raise ValueError("Invalid restore-stage grace period")
        with self._hold():
            plan = self._stale_restore_plan_unlocked(grace_hours)
            match = next((item for item in plan["candidates"] if item["name"] == name), None)
            if match is None:
                raise BackupError("Restore stage is not eligible for cleanup")
            directory = self._root() / "restore-staging" / name
            if directory.is_symlink() or not directory.is_dir():
                raise BackupError("Restore stage changed during cleanup")
            shutil.rmtree(directory)
            self._audit("BACKUP_RESTORE_STAGE_REMOVED", "", staging=name,
                        reclaimed_bytes=match["bytes"])
            return {"removed": name, "reclaimed_bytes": match["bytes"]}

    def prune_plan(self) -> dict[str, object]:
        """Preview completed generations beyond the configured retention count."""
        names = self._generation_names()
        for name in names:
            self._verify_unlocked(name)
        root = self.settings.root
        eligible = names[self.settings.keep_generations:]
        total = 0
        for name in eligible:
            directory = root / name
            for current, dirs, files in os.walk(directory, followlinks=False):
                for item in dirs + files:
                    details = (Path(current) / item).lstat()
                    if stat.S_ISLNK(details.st_mode) or not (
                            stat.S_ISDIR(details.st_mode) or stat.S_ISREG(details.st_mode)):
                        raise BackupError("Unsafe backup generation entry")
                    if stat.S_ISREG(details.st_mode):
                        total += details.st_size
        return {"keep_generations": self.settings.keep_generations,
                "retained": names[:self.settings.keep_generations],
                "eligible": eligible, "estimated_bytes": total}

    def prune(self, *, confirmed: bool) -> dict[str, object]:
        """Delete only old completed generations after a retained one verifies."""
        if confirmed is not True:
            raise BackupError("Backup pruning requires explicit confirmation")
        if not self.settings.root.exists():
            return {"removed": [], "reclaimed_bytes": 0}
        with self._hold():
            return self._prune_unlocked()

    def _prune_unlocked(self) -> dict[str, object]:
        plan = self.prune_plan()
        eligible = plan["eligible"]
        if not eligible:
            return {"removed": [], "reclaimed_bytes": 0}
        verified_retained = False
        for name in plan["retained"]:
            try:
                self._verify_unlocked(name)
            except BackupError:
                continue
            verified_retained = True
            break
        if not verified_retained:
            raise BackupError("No retained generation passed verification")
        root = self._root()
        removed = []
        for name in eligible:
            directory = root / name
            if directory.is_symlink() or not directory.is_dir():
                raise BackupError("Backup generation changed during pruning")
            shutil.rmtree(directory)
            removed.append(name)
            self._audit("BACKUP_GENERATION_PRUNED", name)
        return {"removed": removed, "reclaimed_bytes": plan["estimated_bytes"]}

    def latest_metadata(self) -> dict[str, object]:
        """Cheap dashboard metadata; never implies that file hashes were verified."""
        if not self.settings.root.exists():
            return {"state": "MISSING", "backup_id": None, "age_hours": None,
                    "size_bytes": None, "keep_generations": self.settings.keep_generations,
                    "verification": "NOT_CHECKED", "encryption": None}
        root = self._root()
        names = self._generation_names()
        if not names:
            return {"state": "MISSING", "backup_id": None, "age_hours": None,
                    "size_bytes": None, "keep_generations": self.settings.keep_generations,
                    "verification": "NOT_CHECKED", "encryption": None}
        backup_id = names[0]
        manifest_path = root / backup_id / "manifest.json"
        try:
            if (manifest_path.is_symlink() or not manifest_path.is_file()
                    or manifest_path.stat().st_size > _MAX_MANIFEST_BYTES):
                raise ValueError
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            created = datetime.fromisoformat(manifest["created_at"])
            if (manifest.get("backup_id") != backup_id or created.tzinfo is None
                    or not isinstance(manifest.get("files"), list)
                    or manifest.get("encryption", "NONE") not in {"NONE", "OPENPGP_GPG_AES256"}):
                raise ValueError
            size = sum(entry["bytes"] for entry in manifest["files"])
            if type(size) is not int or size < 0:
                raise ValueError
            age = max(0, int((datetime.now(timezone.utc) - created).total_seconds() // 3600))
            state = "RECORDED_UNVERIFIED"
            encryption = manifest.get("encryption", "NONE")
        except (OSError, UnicodeError, ValueError, KeyError, TypeError):
            size = age = None
            state = "INVALID_METADATA"
            encryption = None
        verification = "NOT_CHECKED"
        verified_at = None
        marker = root / backup_id / "verification.json"
        try:
            if marker.is_file() and not marker.is_symlink() and marker.stat().st_size <= 4096:
                record = json.loads(marker.read_text(encoding="utf-8"))
                manifest_hash, _ = self._hash_file(manifest_path)
                verified = datetime.fromisoformat(record["verified_at"])
                if (verified.tzinfo is not None and
                        record.get("manifest_sha256") == manifest_hash):
                    verification = "LAST_VERIFIED"
                    verified_at = verified.isoformat()
                    if state == "RECORDED_UNVERIFIED":
                        state = "RECORDED"
        except (OSError, UnicodeError, ValueError, KeyError, TypeError, BackupError):
            verification = "MARKER_INVALID"
        return {"state": state, "backup_id": backup_id, "age_hours": age,
                "size_bytes": size, "keep_generations": self.settings.keep_generations,
                "verification": verification, "verified_at": verified_at,
                "encryption": encryption}

    def stage_restore(self, backup_id: str) -> Path:
        """Verify and copy into a new private directory; never replace active state."""
        with self._hold(shared=True):
            return self._stage_restore_unlocked(backup_id)

    def rehearse_upgrade(self, backup_id: str, *, max_values: int = 250_000,
                         max_seconds: float = 60.0) -> dict[str, object]:
        """Migrate a verified staged copy and remove its decrypted files afterward."""
        staged = self.stage_restore(backup_id)
        database = staged / "state.sqlite3"
        tables = ("evidence", "findings", "report_drafts", "planner_runs", "test_objects")

        def snapshot() -> tuple[int, dict[str, int]]:
            uri = "file:" + quote(str(database), safe="/") + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
                connection.execute("PRAGMA query_only=ON")
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                present = {row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                counts = {table: int(connection.execute(
                    f"SELECT count(*) FROM {table}").fetchone()[0]) if table in present else 0
                    for table in tables}
            return version, counts

        try:
            before_version, before_counts = snapshot()
            before = check_database(database, expected_schema=before_version,
                                    required_tables=frozenset({"evidence", "findings"}))
            if before.state != "OK" or before_version not in _SUPPORTED_SCHEMAS:
                raise BackupError("Staged database failed pre-upgrade checks")
            artifact_root = staged / "artifacts/evidence"
            restored = EvidenceFactStore(
                database, ArtifactStore(artifact_root),
                StoreSettings(artifact_root, self.store.settings.max_inline_bytes,
                              self.store.settings.max_page_size),
            )
            restored.initialize(allow_existing_migration=True)
            after = check_database(database, expected_schema=_SCHEMA_VERSION)
            after_version, after_counts = snapshot()
            if after.state != "OK" or after_counts != before_counts:
                raise BackupError("Staged database failed post-upgrade checks")
            uri = "file:" + quote(str(database), safe="/") + "?mode=ro"
            try:
                with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
                    connection.execute("PRAGMA query_only=ON")
                    reference_audit = audit_json_reference_indexes(
                        connection, max_values=max_values, max_seconds=max_seconds)
            except ReferenceIndexAuditError as exc:
                raise BackupError("Staged JSON reference index audit is incomplete") from exc
            if not reference_audit.matches:
                raise BackupError("Staged JSON reference indexes do not match source rows")
            self._audit("BACKUP_UPGRADE_REHEARSED", backup_id,
                        from_schema=before_version, to_schema=after_version,
                        json_values=reference_audit.scanned_values)
            return {"backup_id": backup_id, "from_schema": before_version,
                    "to_schema": after_version, "integrity": "OK",
                    "preserved_counts": after_counts,
                    "json_reference_audit": {
                        "matches": True, "scanned_values": reference_audit.scanned_values,
                        "evidence_ids": reference_audit.evidence_ids,
                        "traffic_ids": reference_audit.traffic_ids},
                    "active_state_replaced": False}
        finally:
            shutil.rmtree(staged)

    def audit_json_indexes(self, backup_id: str, *, max_values: int = 250_000,
                           max_seconds: float = 60.0) -> dict[str, object]:
        """Audit derived reference counts on a verified isolated restore copy."""
        staged = self.stage_restore(backup_id)
        try:
            database = staged / "state.sqlite3"
            uri = "file:" + quote(str(database), safe="/") + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
                connection.execute("PRAGMA query_only=ON")
                if connection.execute("PRAGMA user_version").fetchone()[0] < 44:
                    raise BackupError("JSON reference index audit requires schema 44")
                result = audit_json_reference_indexes(
                    connection, max_values=max_values, max_seconds=max_seconds)
            output = {"backup_id": backup_id, "matches": result.matches,
                      "scanned_values": result.scanned_values,
                      "json_columns": result.json_columns,
                      "evidence_ids": result.evidence_ids,
                      "traffic_ids": result.traffic_ids,
                      "evidence_mismatches": result.evidence_mismatches,
                      "traffic_mismatches": result.traffic_mismatches,
                      "active_state_replaced": False}
            self._audit("BACKUP_JSON_INDEX_AUDITED", backup_id,
                        matches=result.matches, scanned_values=result.scanned_values)
            return output
        except ReferenceIndexAuditError as exc:
            raise BackupError("JSON reference index audit is incomplete") from exc
        finally:
            shutil.rmtree(staged)

    def _stage_restore_unlocked(self, backup_id: str) -> Path:
        self._verify_unlocked(backup_id)
        directory = self._directory(backup_id)
        with (directory / "manifest.json").open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        encrypted = manifest.get("encryption") == "OPENPGP_GPG_AES256"
        self._require_capacity(self._materialized_bytes(manifest, encrypted=encrypted)
                               + 1_048_576)
        staging_root = self._root(create=True) / "restore-staging"
        staging_root.mkdir(mode=0o700, exist_ok=True)
        if staging_root.is_symlink():
            raise BackupError("Unsafe restore staging root")
        destination = Path(tempfile.mkdtemp(prefix="restore-", dir=staging_root))
        os.chmod(destination, 0o700)
        try:
            for entry in manifest["files"]:
                source = directory / entry["path"]
                plain = entry["path"][:-4] if encrypted else entry["path"]
                target = destination / plain
                if encrypted:
                    assert self.crypto is not None
                    self.crypto.decrypt(source, target, destination / ".gpg-home",
                                        max_output_bytes=entry["plaintext_bytes"])
                    digest, size = self._hash_file(target)
                    if digest != entry["plaintext_sha256"] or size != entry["plaintext_bytes"]:
                        raise BackupError("Restored plaintext hash mismatch")
                else:
                    self._copy_digest(source, target, entry["sha256"])
            home = destination / ".gpg-home"
            if home.exists():
                shutil.rmtree(home)
            shutil.copy2(directory / "manifest.json", destination / "manifest.json")
            os.chmod(destination / "manifest.json", 0o600)
            self._audit("BACKUP_RESTORE_STAGED", backup_id)
            return destination
        except Exception:
            shutil.rmtree(destination)
            raise
