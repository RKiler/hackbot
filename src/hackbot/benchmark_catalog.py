"""Versioned synthetic benchmark manifests with an evaluator-only answer store."""

from __future__ import annotations

from dataclasses import fields
import hashlib
import json
from pathlib import Path
import re

from .benchmark_models import (
    BenchmarkBudget, BenchmarkCase, BenchmarkCategory, BenchmarkDifficulty,
    BenchmarkFixtureKind, BenchmarkGroundTruth, BenchmarkSplit,
    ExpectedRootCause, VisibleBenchmarkCase,
)


_CASE_ID = re.compile(r"[a-z][a-z0-9_-]{2,63}\Z")
_MAX_MANIFEST = 64 * 1024
_MAX_INPUT = 1024 * 1024
_ANSWER_FIELD = re.compile(
    rb"(?i)\b(?:ground[_-]?truth|expected[_-]?root[_-]?cause|"
    rb"expected[_-]?specialist|validation[_-]?answer|answer[_-]?key)\b")


def _json_file(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_MANIFEST:
        raise ValueError("Benchmark manifest unavailable or oversized")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Invalid benchmark manifest")
    return data


def _exact(record: dict[str, object], cls: type) -> None:
    allowed = {item.name for item in fields(cls)}
    if set(record) != allowed:
        raise ValueError("Unexpected or missing benchmark manifest fields")


def _safe_input(case_root: Path, name: str) -> Path:
    parts = Path(name).parts
    if not parts or any(part in {".", ".."} for part in parts):
        raise ValueError("Unsafe benchmark input path")
    candidate = case_root
    for part in parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError("Symlinked benchmark input")
    if not candidate.resolve(strict=True).is_relative_to(case_root.resolve(strict=True)):
        raise ValueError("Benchmark input escapes visible root")
    return candidate


class BenchmarkCatalog:
    """The runner loads visible inputs; only the evaluator loads ground truth."""

    def __init__(self, visible_root: Path, truth_root: Path | None = None) -> None:
        self.visible_root = visible_root.resolve(strict=True)
        self.truth_root = truth_root.resolve(strict=True) if truth_root else None
        if not self.visible_root.is_dir() or (self.truth_root and not self.truth_root.is_dir()):
            raise ValueError("Invalid benchmark fixture roots")
        if self.truth_root and (self.truth_root == self.visible_root or
                                self.truth_root.is_relative_to(self.visible_root) or
                                self.visible_root.is_relative_to(self.truth_root)):
            raise ValueError("Visible and hidden benchmark roots must be separate")

    def suite(self, name: str) -> tuple[str, ...]:
        if not _CASE_ID.fullmatch(name):
            raise ValueError("Invalid benchmark suite")
        suites = _json_file(self.visible_root / "suites.json")
        members = suites.get(name)
        if not isinstance(members, list) or not members or len(members) > 256:
            raise ValueError("Unknown or empty benchmark suite")
        if any(not isinstance(item, str) or not _CASE_ID.fullmatch(item)
               for item in members) or len(set(members)) != len(members):
            raise ValueError("Invalid benchmark suite membership")
        return tuple(members)

    def suites(self) -> tuple[str, ...]:
        return tuple(sorted(_json_file(self.visible_root / "suites.json")))

    def visible(self, case_id: str) -> VisibleBenchmarkCase:
        if not _CASE_ID.fullmatch(case_id):
            raise ValueError("Invalid benchmark case ID")
        case_root = self.visible_root / case_id
        if case_root.is_symlink() or not case_root.is_dir():
            raise ValueError("Benchmark case directory unavailable")
        raw = _json_file(case_root / "case.json")
        required = {field.name for field in fields(VisibleBenchmarkCase)} - {"fixture_kind"}
        if not required <= set(raw) or set(raw) - (required | {"fixture_kind"}):
            raise ValueError("Unexpected or missing benchmark case fields")
        if raw["case_id"] != case_id:
            raise ValueError("Benchmark case ID mismatch")
        budget = raw["budget"]
        if not isinstance(budget, dict):
            raise ValueError("Invalid benchmark budget")
        _exact(budget, BenchmarkBudget)
        for name in ("scope_hosts", "identity_aliases", "input_files"):
            values = raw[name]
            if (not isinstance(values, list) or len(values) > 100 or
                    any(not isinstance(item, str) or not item for item in values) or
                    len(set(values)) != len(values)):
                raise ValueError("Invalid benchmark input list")
        if raw["context_file"] is not None and not isinstance(raw["context_file"], str):
            raise ValueError("Invalid benchmark context file")
        case = VisibleBenchmarkCase(
            case_id=case_id, version=raw["version"], fixture_id=raw["fixture_id"],
            target_package=raw["target_package"], scope_hosts=tuple(raw["scope_hosts"]),
            identity_aliases=tuple(raw["identity_aliases"]),
            input_files=tuple(raw["input_files"]), context_file=raw["context_file"],
            budget=BenchmarkBudget(**budget), visible_hash=raw["visible_hash"],
            fixture_kind=BenchmarkFixtureKind(raw.get("fixture_kind", "RECORDED_TRAFFIC")))
        expected = self._hash_inputs(case_root, case)
        if expected != case.visible_hash:
            raise ValueError("Benchmark visible inputs changed without version update")
        return case

    @staticmethod
    def _hash_inputs(case_root: Path, case: VisibleBenchmarkCase) -> str:
        digest = hashlib.sha256()
        paths = (case.target_package, *case.input_files,
                 *((case.context_file,) if case.context_file else ()))
        if len(set(paths)) != len(paths):
            raise ValueError("Duplicate benchmark input")
        for name in sorted(paths):
            path = _safe_input(case_root, name)
            if not path.is_file() or path.stat().st_size > _MAX_INPUT:
                raise ValueError("Benchmark input unavailable or oversized")
            digest.update(name.encode("ascii") + b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        return digest.hexdigest()

    def visible_files(self, case_id: str) -> tuple[Path, ...]:
        case = self.visible(case_id)
        root = self.visible_root / case_id
        return tuple(_safe_input(root, name) for name in
                     (case.target_package, *case.input_files,
                      *((case.context_file,) if case.context_file else ())))

    def ground_truth(self, case_id: str) -> BenchmarkGroundTruth:
        if self.truth_root is None or not _CASE_ID.fullmatch(case_id):
            raise ValueError("Benchmark answer store unavailable")
        raw = _json_file(self.truth_root / (case_id + ".json"))
        _exact(raw, BenchmarkGroundTruth)
        roots_raw = raw["roots"]
        if not isinstance(roots_raw, list):
            raise ValueError("Invalid benchmark answer roots")
        roots = []
        for item in roots_raw:
            if not isinstance(item, dict):
                raise ValueError("Invalid benchmark answer root")
            required = {field.name for field in fields(ExpectedRootCause)} - {
                "candidate_fingerprints"}
            if not required <= set(item) or set(item) - (required | {
                    "candidate_fingerprints"}):
                raise ValueError("Unexpected or missing benchmark answer fields")
            roots.append(ExpectedRootCause(
                category=BenchmarkCategory(item["category"]), operation=item["operation"],
                boundary=item["boundary"], object_type=item["object_type"],
                protocol=item["protocol"], fingerprint=item["fingerprint"],
                acceptable_categories=tuple(BenchmarkCategory(value) for value in
                                            item["acceptable_categories"]),
                candidate_fingerprints=tuple(item.get("candidate_fingerprints", ()))))
        return BenchmarkGroundTruth(
            case_id=raw["case_id"], version=raw["version"],
            category=BenchmarkCategory(raw["category"]),
            difficulty=BenchmarkDifficulty(raw["difficulty"]),
            split=BenchmarkSplit(raw["split"]), roots=tuple(roots),
            expected_specialist=raw["expected_specialist"],
            expected_skill_ids=tuple(raw["expected_skill_ids"]),
            forbidden_interpretations=tuple(raw["forbidden_interpretations"]),
            known_controls=tuple(raw["known_controls"]), tags=tuple(raw["tags"]))

    def evaluator_case(self, case_id: str) -> BenchmarkCase:
        return BenchmarkCase(self.visible(case_id), self.ground_truth(case_id))

    def audit_visible_inputs(self, case_id: str) -> tuple[str, ...]:
        """Reject exact answer markers in the bytes given to a target runtime."""
        truth = self.ground_truth(case_id)
        visible = b"\n".join(path.read_bytes() for path in self.visible_files(case_id))
        needles = [value for root in truth.roots for value in
                   (root.fingerprint, *root.candidate_fingerprints)]
        needles.extend(item for item in truth.forbidden_interpretations if len(item) >= 12)
        leaked = [value for value in needles if value.encode("utf-8") in visible]
        if _ANSWER_FIELD.search(visible):
            leaked.append("EVALUATOR_ONLY_FIELD")
        return tuple(leaked)
