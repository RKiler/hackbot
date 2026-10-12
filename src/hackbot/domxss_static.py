"""Bounded, deterministic DOM dataflow triage; no target code is executed."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
from importlib.resources import as_file, files
import json
import re
import subprocess
from typing import Any


ANALYZER_VERSION = "1.0.0"
MAX_ASSET_BYTES = 1_048_576
MAX_CANDIDATES = 16
ANALYSIS_TIMEOUT_SECONDS = 5
_SOURCE_HINT = re.compile(
    rb"location|document\.(?:URL|documentURI|referrer)|window\.name|"
    rb"URLSearchParams|(?:router|route)\.(?:query|params)|(?:event|messageEvent)\.data"
)
_SINK_HINT = re.compile(
    rb"innerHTML|outerHTML|srcdoc|\.src\b|\.href\b|location|"
    rb"insertAdjacentHTML|document\.write|\beval\s*\(|setAttribute"
)


class DOMCandidateStatus(StrEnum):
    DISCOVERED = "DISCOVERED"
    TRACING = "TRACING"
    STATICALLY_SUPPORTED = "STATICALLY_SUPPORTED"
    RUNTIME_READY = "RUNTIME_READY"
    RUNTIME_TESTED = "RUNTIME_TESTED"
    REJECTED = "REJECTED"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    VALIDATION_READY = "VALIDATION_READY"
    ANALYSIS_LIMIT_REACHED = "ANALYSIS_LIMIT_REACHED"
    PARSE_FAILED = "PARSE_FAILED"
    STALE = "STALE"


@dataclass(frozen=True, slots=True)
class SourceLocation:
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class FlowStep:
    operation: str
    location: SourceLocation


@dataclass(frozen=True, slots=True)
class DOMFlowCandidate:
    candidate_id: str
    target_id: str
    recon_asset_id: int | None
    asset_sha256: str
    source: str
    source_location: SourceLocation
    validation: tuple[FlowStep, ...]
    transforms: tuple[FlowStep, ...]
    sink: str
    sink_kind: str
    sink_location: SourceLocation
    attacker_controlled: bool
    score: int
    status: DOMCandidateStatus
    analyzer_version: str
    evidence_ids: tuple[str, ...] = ()
    route: str | None = None
    source_map_sha256: str | None = None
    mapped_source: str | None = None
    post_checks: tuple[FlowStep, ...] = ()
    sanitizers: tuple[FlowStep, ...] = ()
    unresolved_helper: bool = False

    @property
    def check_before_transform(self) -> bool:
        if not self.validation or not self.transforms:
            return False
        check = self.validation[0].location
        transform = self.transforms[0].location
        return (check.line, check.column) < (transform.line, transform.column)


@dataclass(frozen=True, slots=True)
class DOMAnalysis:
    target_id: str
    recon_asset_id: int | None
    asset_sha256: str
    analyzer_version: str
    analyzed_at: datetime
    status: str
    candidates: tuple[DOMFlowCandidate, ...]
    parse_errors: int = 0
    reason: str | None = None


def _location(value: dict[str, Any] | None) -> SourceLocation:
    if not isinstance(value, dict):
        raise ValueError("Missing AST location")
    line, column = value.get("line"), value.get("column")
    if type(line) is not int or type(column) is not int or line < 1 or column < 1:
        raise ValueError("Invalid AST location")
    return SourceLocation(line, column)


def _steps(values: object, key: str) -> tuple[FlowStep, ...]:
    if not isinstance(values, list) or len(values) > 12:
        raise ValueError("Invalid AST flow steps")
    result: list[FlowStep] = []
    for item in values:
        if not isinstance(item, dict) or not isinstance(item.get(key), str):
            raise ValueError("Invalid AST flow step")
        result.append(FlowStep(item[key][:160], _location(item.get("location"))))
    return tuple(result)


class DOMStaticAnalyzer:
    """Run a proven Babel parser in a memory- and time-bounded child process."""

    def __init__(self, *, node_binary: str = "node") -> None:
        self.node_binary = node_binary

    def analyze(self, *, target_id: str, body: bytes,
                recon_asset_id: int | None = None) -> DOMAnalysis:
        if not isinstance(target_id, str) or not target_id or not isinstance(body, bytes):
            raise ValueError("Invalid DOM analysis input")
        if recon_asset_id is not None and (type(recon_asset_id) is not int or recon_asset_id <= 0):
            raise ValueError("Invalid recon asset ID")
        digest = hashlib.sha256(body).hexdigest()
        now = datetime.now(timezone.utc)

        def empty(status: str, reason: str | None = None) -> DOMAnalysis:
            return DOMAnalysis(target_id, recon_asset_id, digest, ANALYZER_VERSION,
                               now, status, (), reason=reason)

        if len(body) > MAX_ASSET_BYTES:
            return empty(DOMCandidateStatus.ANALYSIS_LIMIT_REACHED.value, "ASSET_TOO_LARGE")
        if not _SOURCE_HINT.search(body) or not _SINK_HINT.search(body):
            return empty("NO_CONNECTED_SIGNAL", "CHEAP_TRIAGE")
        try:
            helper = files("hackbot").joinpath("dom_ast.cjs")
            with as_file(helper) as helper_path:
                process = subprocess.run(
                    [self.node_binary, "--max-old-space-size=128", str(helper_path)],
                    input=body, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=ANALYSIS_TIMEOUT_SECONDS, check=False,
                )
            if process.returncode != 0 or len(process.stdout) > 262_144:
                return empty(DOMCandidateStatus.PARSE_FAILED.value, "PARSER_UNAVAILABLE_OR_LIMIT")
            parsed = json.loads(process.stdout)
        except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError, json.JSONDecodeError):
            return empty(DOMCandidateStatus.PARSE_FAILED.value, "PARSER_UNAVAILABLE_OR_LIMIT")
        if not isinstance(parsed, dict) or parsed.get("parse_error"):
            return empty(DOMCandidateStatus.PARSE_FAILED.value, "MALFORMED_JAVASCRIPT")
        flows = parsed.get("flows", [])
        if not isinstance(flows, list):
            return empty(DOMCandidateStatus.PARSE_FAILED.value, "INVALID_PARSER_RESULT")
        candidates: list[DOMFlowCandidate] = []
        try:
            for flow in flows[:MAX_CANDIDATES]:
                if not isinstance(flow, dict):
                    continue
                source, sink, sink_kind = flow.get("source"), flow.get("sink"), flow.get("sink_kind")
                if not all(isinstance(value, str) and value for value in (source, sink, sink_kind)):
                    continue
                source_loc = _location(flow.get("source_loc"))
                sink_loc = _location(flow.get("sink_loc"))
                checks = _steps(flow.get("validations", []), "check")
                transforms = _steps(flow.get("transformations", []), "operation")
                post_checks = _steps(flow.get("post_checks", []), "check")
                sanitizers = _steps(flow.get("sanitizers", []), "operation")
                unresolved = flow.get("unresolved_helper") is True
                controlled = flow.get("attacker_controlled") is True
                score = 25 + (20 if controlled else 0) + (15 if checks else 0)
                score += 15 if transforms else 0
                score += 10 if sink_kind == "HTML_EXECUTION" else 5
                score -= 25 if sanitizers or post_checks or unresolved else 0
                score = min(score, 100)
                if sanitizers and sanitizers[-1].operation == "encodeURIComponent":
                    status = DOMCandidateStatus.REJECTED
                elif sanitizers or post_checks or unresolved:
                    status = DOMCandidateStatus.NEEDS_MANUAL_REVIEW
                elif controlled and checks and transforms:
                    status = DOMCandidateStatus.STATICALLY_SUPPORTED
                else:
                    status = DOMCandidateStatus.TRACING
                key = json.dumps([target_id, recon_asset_id, digest, source, source_loc.line,
                                  source_loc.column, sink, sink_loc.line, sink_loc.column,
                                  [step.operation for step in checks],
                                  [step.operation for step in transforms],
                                  [step.operation for step in post_checks],
                                  [step.operation for step in sanitizers], unresolved,
                                  ANALYZER_VERSION],
                                 separators=(",", ":"))
                candidates.append(DOMFlowCandidate(
                    candidate_id="DOM-" + hashlib.sha256(key.encode()).hexdigest()[:32],
                    target_id=target_id, recon_asset_id=recon_asset_id, asset_sha256=digest,
                    source=source, source_location=source_loc, validation=checks,
                    transforms=transforms, sink=sink, sink_kind=sink_kind,
                    sink_location=sink_loc, attacker_controlled=controlled,
                    score=score, status=status, analyzer_version=ANALYZER_VERSION,
                    post_checks=post_checks, sanitizers=sanitizers,
                    unresolved_helper=unresolved,
                ))
        except ValueError:
            return empty(DOMCandidateStatus.PARSE_FAILED.value, "INVALID_PARSER_RESULT")
        return DOMAnalysis(target_id, recon_asset_id, digest, ANALYZER_VERSION, now,
                           "ANALYZED", tuple(candidates),
                           parse_errors=int(parsed.get("parse_errors", 0)))
