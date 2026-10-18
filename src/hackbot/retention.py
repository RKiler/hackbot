"""Bounded, reference-checked collection of abandoned evidence blobs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from heapq import nsmallest
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from typing import Iterator
import uuid

from .artifact_refs import (EVIDENCE_ARTIFACT_REFERENCES,
                            verify_artifact_reference_schema)
from .dom_guard_schema import verify_dom_retirement_guards
from .dom_refs import (RetiredDOMOwner, has_external_dom_reference,
                       retired_dom_owner)
from .evidence_refs import evidence_reference_inventory, has_evidence_reference
from .store import EvidenceFactStore
from .traffic_guard_schema import verify_traffic_retirement_guards
from .traffic_refs import (has_external_traffic_reference,
                           retired_traffic_owner)


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_BUCKET = re.compile(r"[0-9a-f]{2}\Z")
_TEMP = re.compile(r"\.tmp-[A-Za-z0-9_-]{6,32}\Z")


@dataclass(frozen=True, slots=True)
class OrphanPolicy:
    grace_hours: int = 24
    max_scan_entries: int = 10_000
    max_delete_files: int = 100
    max_scan_seconds: float = 30.0

    def __post_init__(self) -> None:
        if (type(self.grace_hours) is not int or not 1 <= self.grace_hours <= 8760
                or type(self.max_scan_entries) is not int
                or not 1 <= self.max_scan_entries <= 1_000_000
                or type(self.max_delete_files) is not int
                or not 1 <= self.max_delete_files <= 10_000
                or type(self.max_scan_seconds) not in (int, float)
                or not 0.1 <= self.max_scan_seconds <= 300):
            raise ValueError("Invalid artifact collection policy")


@dataclass(frozen=True, slots=True)
class CollectionPlan:
    digests: tuple[str, ...]
    temporary_files: tuple[str, ...]
    scanned: int
    estimated_bytes: int
    truncated: bool
    scan_start: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {"class": "UNREFERENCED_ARTIFACT", "dry_run": True,
                "digests": self.digests, "temporary_files": self.temporary_files,
                "scanned": self.scanned,
                "candidate_count": len(self.digests) + len(self.temporary_files),
                "estimated_bytes": self.estimated_bytes,
                "truncated": self.truncated}


class ArtifactGarbageCollector:
    """Never expires Evidence rows or reachable content; removes only aged orphans."""

    def __init__(self, store: EvidenceFactStore, policy: OrphanPolicy = OrphanPolicy(),
                 audit_path: Path | None = None, cursor_path: Path | None = None) -> None:
        self.store = store
        self.policy = policy
        self.audit_path = audit_path
        self.cursor_path = cursor_path or store.db_path.parent / "artifact-scan-cursor.json"

    @staticmethod
    def _valid_cursor(value: object) -> bool:
        if value is None:
            return True
        if not isinstance(value, str) or "/" not in value:
            return False
        bucket, name = value.split("/", 1)
        return bool(_BUCKET.fullmatch(bucket) and
                    ((_DIGEST.fullmatch(name) and name[:2] == bucket) or
                     _TEMP.fullmatch(name)))

    def _read_cursor(self) -> dict[str, object]:
        path = self.cursor_path
        if not path.exists() and not path.is_symlink():
            return {"next_after": None, "review": None}
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size > 2_000_000:
            raise ValueError("Unsafe artifact scan cursor")
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise ValueError("Invalid artifact scan cursor") from None
        if not isinstance(state, dict) or not self._valid_cursor(state.get("next_after")):
            raise ValueError("Invalid artifact scan cursor")
        review = state.get("review")
        if review is not None:
            if (not isinstance(review, dict) or
                    not self._valid_cursor(review.get("scan_start")) or
                    not isinstance(review.get("at"), (int, float)) or
                    not isinstance(review.get("digests"), list) or
                    not isinstance(review.get("temporary_files"), list) or
                    len(review["digests"]) + len(review["temporary_files"]) >
                        self.policy.max_delete_files or
                    any(not isinstance(item, str) or not _DIGEST.fullmatch(item)
                        for item in review["digests"]) or
                    any(not self._valid_cursor(item) or not item.split("/", 1)[1].startswith(".tmp-")
                        for item in review["temporary_files"])):
                raise ValueError("Invalid artifact scan cursor")
        return {"next_after": state.get("next_after"), "review": review}

    def _write_cursor(self, state: dict[str, object]) -> None:
        path = self.cursor_path
        parent = path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or path.is_symlink():
            raise ValueError("Unsafe artifact scan cursor path")
        fd, temporary = tempfile.mkstemp(prefix=".artifact-cursor-", dir=parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True)
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

    @staticmethod
    def _referenced(db: object, digest: str) -> bool:
        version = db.execute("PRAGMA user_version").fetchone()
        dom_guarded = bool(version and version[0] >= 46)
        dom_live: dict[str, bool] = {}

        def traffic_link_is_live(evidence_id: str) -> bool:
            owner = retired_traffic_owner(db, evidence_id)
            if owner is None:
                return True
            if has_external_traffic_reference(
                db, exchange_id=owner.exchange_id, request_id=owner.request_id,
                response_id=owner.response_id,
            ):
                return True
            return has_evidence_reference(
                db, evidence_id, allowed_traffic_request_id=owner.request_id)

        def dom_link_is_live(owner: RetiredDOMOwner, *, kind: str | None = None) -> bool:
            if (owner.artifact_sha256 != digest or
                    (kind is not None and owner.kind != kind)):
                return True
            if owner.evidence_id not in dom_live:
                dom_live[owner.evidence_id] = (
                    has_external_dom_reference(db, owner.owner_id) or
                    has_evidence_reference(
                        db, owner.evidence_id,
                        allowed_dom_artifact_id=owner.owner_id if owner.kind == "JS" else None,
                        allowed_dom_map_id=owner.owner_id if owner.kind == "SOURCE_MAP" else None,
                    )
                )
            return dom_live[owner.evidence_id]

        for table, column in EVIDENCE_ARTIFACT_REFERENCES:
            if table == "evidence":
                found = db.execute(
                    "SELECT 1 FROM evidence e WHERE e.artifact_hash=? AND NOT EXISTS ("
                    "SELECT 1 FROM evidence_payload_retirements r "
                    "WHERE r.evidence_id=e.evidence_id) LIMIT 1", (digest,)
                ).fetchone()
                if not found:
                    for row in db.execute(
                        "SELECT e.evidence_id FROM evidence e "
                        "JOIN evidence_payload_retirements r ON r.evidence_id=e.evidence_id "
                        "WHERE e.artifact_hash=?", (digest,)
                    ):
                        dom_owner = retired_dom_owner(db, row[0]) if dom_guarded else None
                        traffic_owner = retired_traffic_owner(db, row[0])
                        if ((dom_owner is not None and dom_link_is_live(dom_owner)) or
                                (traffic_owner is not None and traffic_link_is_live(row[0])) or
                                (dom_owner is None and traffic_owner is None and
                                 has_evidence_reference(db, row[0]))):
                            return True
            elif table in {"traffic_requests", "traffic_responses"}:
                for row in db.execute(
                    f"SELECT body_evidence_id FROM {table} WHERE {column}=?",
                    (digest,),
                ):
                    if (row[0] is None or
                            db.execute("SELECT 1 FROM evidence WHERE evidence_id=? "
                                       "AND artifact_hash=? LIMIT 1",
                                       (row[0], digest)).fetchone() is None or
                            traffic_link_is_live(row[0])):
                        return True
                continue
            elif table in {"dom_js_artifacts", "dom_source_maps"} and dom_guarded:
                kind = "JS" if table == "dom_js_artifacts" else "SOURCE_MAP"
                for row in db.execute(
                    f"SELECT evidence_id FROM {table} WHERE {column}=?", (digest,),
                ):
                    owner = retired_dom_owner(db, row[0])
                    if owner is None or dom_link_is_live(owner, kind=kind):
                        return True
                continue
            else:
                found = db.execute(
                    f"SELECT 1 FROM {table} WHERE {column}=? LIMIT 1", (digest,)
                ).fetchone()
            if found:
                return True
        return False

    @staticmethod
    def _verify_reference_guards(db: object) -> None:
        verify_artifact_reference_schema(db)
        evidence_reference_inventory(db)
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version >= 42:
            verify_traffic_retirement_guards(db)
        if version >= 46:
            verify_dom_retirement_guards(db)

    def _candidates(self, db: object, cutoff: float, after: str | None = None
                    ) -> tuple[tuple[str, ...], tuple[str, ...], int, int, bool, str | None]:
        deadline = time.monotonic() + self.policy.max_scan_seconds

        def check_deadline() -> None:
            if time.monotonic() >= deadline:
                raise ValueError("Artifact scan deadline exceeded; no cleanup was authorized")

        self._verify_reference_guards(db)
        check_deadline()
        if not self._valid_cursor(after):
            raise ValueError("Invalid artifact scan cursor")
        root = self.store.artifacts.root / "sha256"
        if not root.exists():
            return (), (), 0, 0, False, None
        if root.is_symlink() or not root.is_dir():
            raise ValueError("Unsafe artifact root")
        digests: list[str] = []
        temporary: list[str] = []
        bytes_found = scanned = 0
        last_key: str | None = after
        buckets: list[Path] = []
        for bucket in root.iterdir():
            check_deadline()
            if (len(buckets) >= 256 or bucket.is_symlink() or not bucket.is_dir() or
                    not _BUCKET.fullmatch(bucket.name)):
                raise ValueError("Unsafe artifact bucket")
            buckets.append(bucket)
        buckets.sort()

        def entries() -> Iterator[tuple[str, Path, Path]]:
            for wrap in (False, True) if after is not None else (False,):
                for bucket in buckets:
                    if after is not None and (
                            (not wrap and bucket.name < after[:2]) or
                            (wrap and bucket.name > after[:2])):
                        continue
                    def eligible_entries() -> Iterator[Path]:
                        for path in bucket.iterdir():
                            check_deadline()
                            if after is None or ((f"{bucket.name}/{path.name}" <= after) == wrap):
                                yield path

                    for path in nsmallest(self.policy.max_scan_entries + 1, eligible_entries(),
                                          key=lambda item: item.name):
                        check_deadline()
                        key = f"{bucket.name}/{path.name}"
                        yield key, bucket, path

        for key, bucket, path in entries():
            check_deadline()
            if scanned >= self.policy.max_scan_entries:
                return tuple(digests), tuple(temporary), scanned, bytes_found, True, last_key
            scanned += 1
            last_key = key
            if path.name.startswith(".tmp-"):
                if not _TEMP.fullmatch(path.name):
                    raise ValueError("Unsafe artifact temporary filename")
                details = path.lstat()
                if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                    raise ValueError("Unsafe artifact temporary entry")
                if details.st_mtime <= cutoff:
                    temporary.append(f"{bucket.name}/{path.name}")
                    bytes_found += details.st_size
                    if len(digests) + len(temporary) >= self.policy.max_delete_files:
                        return tuple(digests), tuple(temporary), scanned, bytes_found, True, last_key
                continue
            if not _DIGEST.fullmatch(path.name) or path.name[:2] != bucket.name:
                raise ValueError("Unsafe artifact filename")
            details = path.lstat()
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise ValueError("Unsafe artifact entry")
            if details.st_mtime > cutoff or self._referenced(db, path.name):
                continue
            check_deadline()
            digests.append(path.name)
            bytes_found += details.st_size
            if len(digests) + len(temporary) >= self.policy.max_delete_files:
                return tuple(digests), tuple(temporary), scanned, bytes_found, True, last_key
        return tuple(digests), tuple(temporary), scanned, bytes_found, False, None

    def plan(self, *, now: float | None = None) -> CollectionPlan:
        current = time.time() if now is None else now
        if not self.store.artifacts.root.exists():
            return CollectionPlan((), (), 0, 0, False)
        with self.store.artifacts.hold():
            state = self._read_cursor()
            start = state["next_after"]
            self._write_cursor({"next_after": start, "review": None})
            with self.store._connection() as db:
                digests, temporary, scanned, size, truncated, end = self._candidates(
                    db, current - self.policy.grace_hours * 3600, start)
            self._write_cursor({"next_after": end if truncated else None,
                                "review": {"at": current, "scan_start": start,
                                           "digests": digests, "temporary_files": temporary}})
        return CollectionPlan(digests, temporary, scanned, size, truncated, start)

    def run(self, *, confirmed: bool, now: float | None = None,
            approved_plan: CollectionPlan | None = None) -> dict[str, object]:
        if confirmed is not True:
            raise ValueError("Collection requires explicit confirmation")
        if approved_plan is not None and not isinstance(approved_plan, CollectionPlan):
            raise ValueError("Invalid approved artifact collection plan")
        current = time.time() if now is None else now
        removed = 0
        reclaimed = 0
        if not self.store.artifacts.root.exists():
            return {"removed": 0, "reclaimed_bytes": 0, "truncated": False}
        with self.store.artifacts.hold():
            state = self._read_cursor()
            review = state["review"]
            if not isinstance(review, dict) or not 0 <= current - review["at"] <= 900:
                raise ValueError("Collection requires a recent dry-run review")
            if approved_plan is not None:
                if (approved_plan.scan_start != review["scan_start"] or
                        tuple(approved_plan.digests) != tuple(review["digests"]) or
                        tuple(approved_plan.temporary_files) != tuple(review["temporary_files"])):
                    raise ValueError("Collection plan does not match the current review")
                start = approved_plan.scan_start
                approved_digests = set(approved_plan.digests)
                approved_temporary = set(approved_plan.temporary_files)
            else:
                start = review["scan_start"]
                approved_digests = set(review["digests"])
                approved_temporary = set(review["temporary_files"])
            with self.store._connection() as db:
                digests, temporary, _, _, truncated, _ = self._candidates(
                    db, current - self.policy.grace_hours * 3600, start)
                if approved_digests is not None and approved_temporary is not None:
                    digests = tuple(digest for digest in digests if digest in approved_digests)
                    temporary = tuple(name for name in temporary if name in approved_temporary)
                db.execute("BEGIN IMMEDIATE")
                self._verify_reference_guards(db)
                operation_id = "RET-" + uuid.uuid4().hex
                self._audit(operation_id, "STARTED", 0, 0, truncated)
                for digest in digests:
                    if self._referenced(db, digest):
                        continue
                    path = self.store.artifacts.path_for(digest)
                    details = path.lstat()
                    if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
                            or details.st_mtime > current - self.policy.grace_hours * 3600):
                        continue
                    path.unlink()
                    removed += 1
                    reclaimed += details.st_size
                root = self.store.artifacts.root / "sha256"
                for relative in temporary:
                    bucket, name = relative.split("/", 1)
                    if not _BUCKET.fullmatch(bucket) or not _TEMP.fullmatch(name):
                        raise ValueError("Unsafe artifact temporary filename")
                    path = root / bucket / name
                    details = path.lstat()
                    if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
                            or details.st_mtime > current - self.policy.grace_hours * 3600):
                        continue
                    path.unlink()
                    removed += 1
                    reclaimed += details.st_size
            if isinstance(review, dict):
                self._write_cursor({"next_after": state["next_after"], "review": None})
            self._audit(operation_id, "COMPLETED", removed, reclaimed, truncated)
        return {"removed": removed, "reclaimed_bytes": reclaimed, "truncated": truncated}

    def _audit(self, operation_id: str, stage: str, removed: int,
               reclaimed: int, truncated: bool) -> None:
        if self.audit_path is None:
            return
        parent = self.audit_path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if parent.is_symlink() or self.audit_path.is_symlink():
            raise ValueError("Unsafe maintenance audit path")
        event = {"at": datetime.now(timezone.utc).isoformat(),
                 "action": "ORPHAN_ARTIFACT_COLLECTION", "operation_id": operation_id,
                 "stage": stage, "removed": removed,
                 "reclaimed_bytes": reclaimed, "truncated": truncated}
        fd = os.open(self.audit_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
