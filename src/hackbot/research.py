"""Bounded, advisory security research over structured BugHunter knowledge gaps.

This module deliberately has no traffic executor, target HTTP client, or Finding
dependency. External material is untrusted data, not instructions or proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
from html.parser import HTMLParser
import json
import re
import sqlite3
import time
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit
import uuid

from .evidence import EvidenceProvenance, EvidenceType, RedactionStatus, Sensitivity
from .logging import SecretRedactor
from .store import EvidenceFactStore


class GapType(StrEnum):
    UNKNOWN_TECHNOLOGY = "UNKNOWN_TECHNOLOGY"
    UNKNOWN_FRAMEWORK = "UNKNOWN_FRAMEWORK"
    UNKNOWN_PROTOCOL = "UNKNOWN_PROTOCOL"
    UNKNOWN_SECURITY_PRIMITIVE = "UNKNOWN_SECURITY_PRIMITIVE"
    UNKNOWN_OBJECT_RELATIONSHIP = "UNKNOWN_OBJECT_RELATIONSHIP"
    UNKNOWN_PRODUCT_CONCEPT = "UNKNOWN_PRODUCT_CONCEPT"
    SKILL_GAP = "SKILL_GAP"
    LOW_HYPOTHESIS_CONFIDENCE = "LOW_HYPOTHESIS_CONFIDENCE"
    NEW_FRAMEWORK = "NEW_FRAMEWORK"
    NEW_API_STYLE = "NEW_API_STYLE"
    UNKNOWN_AUTH_MECHANISM = "UNKNOWN_AUTH_MECHANISM"


class ResearchStatus(StrEnum):
    PENDING = "PENDING"
    CACHE_HIT = "CACHE_HIT"
    RESEARCHING = "RESEARCHING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    STALE = "STALE"
    CANCELLED = "CANCELLED"


class SourceType(StrEnum):
    PERSONAL_FINDING = "PERSONAL_FINDING"
    HACKERONE_REPORT = "HACKERONE_REPORT"
    SECURITY_RESEARCH = "SECURITY_RESEARCH"
    PORTSWIGGER = "PORTSWIGGER"
    OWASP = "OWASP"
    VENDOR_DOCUMENTATION = "VENDOR_DOCUMENTATION"
    ACADEMIC_PAPER = "ACADEMIC_PAPER"
    GITHUB_SECURITY_RESEARCH = "GITHUB_SECURITY_RESEARCH"
    RESEARCHER_WRITEUP = "RESEARCHER_WRITEUP"
    TARGET_DOCUMENTATION = "TARGET_DOCUMENTATION"
    SKILL = "SKILL"
    HACKBOT_OBSERVATION = "HACKBOT_OBSERVATION"
    MANUAL = "MANUAL"


QUALITY = {
    SourceType.PERSONAL_FINDING: 90, SourceType.HACKERONE_REPORT: 85,
    SourceType.SECURITY_RESEARCH: 85, SourceType.PORTSWIGGER: 85,
    SourceType.OWASP: 85, SourceType.VENDOR_DOCUMENTATION: 85,
    SourceType.ACADEMIC_PAPER: 80, SourceType.GITHUB_SECURITY_RESEARCH: 65,
    SourceType.RESEARCHER_WRITEUP: 55, SourceType.TARGET_DOCUMENTATION: 65,
    SourceType.SKILL: 70, SourceType.HACKBOT_OBSERVATION: 40,
    SourceType.MANUAL: 50,
}
RESEARCH_VERSION = "1"
_SAFE_TERM = re.compile(r"[A-Za-z][A-Za-z0-9 ._+/#-]{1,119}\Z")
_ID = re.compile(r"(?:HYP|EXP|APIC)-[0-9a-f]{32}\Z")
_SENSITIVE = re.compile(
    r"(?i)(?:bearer\s+\S+|(?:password|cookie|secret|token|api[_-]?key)\s*[:=]\s*\S+|"
    r"[A-Za-z0-9_-]{28,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}|"
    r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|https?://\S+|[0-9a-f]{24,})"
)
_INSTRUCTION = re.compile(r"(?i)(ignore (?:all|previous)|system prompt|execute |run command|curl |wget |"
                          r"sudo |chmod |bash |sh -c|<script|```|<[^>]+>)")
_LABELS = ("precondition", "root cause", "discovery signal", "testing methodology",
           "control", "impact", "false positive", "security boundary", "implementation detail")
_RELATION = re.compile(r"\b([A-Z][A-Za-z0-9_]{2,30})\s*(?:->|→|belongs to)\s*"
                       r"([A-Z][A-Za-z0-9_]{2,30})\b")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clean(value: str, maximum: int = 500) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid research text")
    result = " ".join(value.split())[:maximum]
    result = SecretRedactor.from_environment().text(_SENSITIVE.sub("[REDACTED]", result))
    return result


def _public_term(value: str) -> str | None:
    if not isinstance(value, str) or not _SAFE_TERM.fullmatch(value):
        return None
    if _SENSITIVE.search(value):
        return None
    # Hostnames, private object IDs and paths are never sent to public search.
    if ".com" in value.lower() or ".io" in value.lower() or "/api/" in value.lower():
        return None
    return value.strip()


def _canonical_url(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        parts = urlsplit(raw)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port:
            return None
    except ValueError:
        return None
    if not re.fullmatch(r"[a-zA-Z0-9.-]{4,180}", parts.hostname) or ".." in parts.hostname:
        return None
    return urlunsplit(("https", parts.hostname.lower(), parts.path or "/", "", ""))


@dataclass(frozen=True, slots=True)
class ResearchBudget:
    max_searches: int = 1
    max_sources: int = 4
    max_fetched_bytes: int = 32_768
    max_tokens: int = 1500
    max_duration_seconds: int = 20

    def __post_init__(self) -> None:
        for name, maximum in (("max_searches", 3), ("max_sources", 8),
                              ("max_fetched_bytes", 131_072), ("max_tokens", 4000),
                              ("max_duration_seconds", 60)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid research budget")

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class ResearchRequest:
    request_id: str
    target_id: str | None
    gap_ref: str
    gap_type: GapType
    topic: str
    technology: str | None
    security_category: str | None
    specialist: str
    hypothesis_id: str | None
    cache_key: str
    status: ResearchStatus
    budget: ResearchBudget
    external_allowed: bool
    private_target: bool
    cancel_requested: bool
    brief_id: str | None
    error_code: str | None
    created_at: str
    updated_at: str
    usage: dict[str, int]

    @classmethod
    def from_row(cls, row: dict[str, object]) -> ResearchRequest:
        return cls(str(row["request_id"]), row["target_id"], str(row["gap_ref"]),
                   GapType(row["gap_type"]), str(row["topic"]), row["technology"],
                   row["security_category"], str(row["specialist"]), row["hypothesis_id"],
                   str(row["cache_key"]), ResearchStatus(row["status"]),
                   ResearchBudget(**json.loads(row["budget_json"])),
                   bool(row["external_allowed"]), bool(row["private_target"]),
                   bool(row["cancel_requested"]), row["brief_id"], row["error_code"],
                   str(row["created_at"]), str(row["updated_at"]),
                   json.loads(row["usage_json"]))

    def public_dict(self) -> dict[str, object]:
        return {"request_id": self.request_id, "target_id": self.target_id,
                "gap_ref": self.gap_ref, "gap_type": self.gap_type.value,
                "topic": self.topic, "specialist": self.specialist,
                "hypothesis_id": self.hypothesis_id, "status": self.status.value,
                "brief_id": self.brief_id, "error_code": self.error_code,
                "created_at": self.created_at, "updated_at": self.updated_at,
                "usage": self.usage}


@dataclass(frozen=True, slots=True)
class KnowledgeGap:
    gap_ref: str
    target_id: str
    gap_type: GapType
    topic: str
    technology: str | None
    security_category: str | None
    specialist: str
    hypothesis_id: str | None
    priority: int

    def to_dict(self) -> dict[str, object]:
        return {"gap_ref": self.gap_ref, "target_id": self.target_id,
                "gap_type": self.gap_type.value, "topic": self.topic,
                "technology": self.technology, "security_category": self.security_category,
                "specialist": self.specialist, "hypothesis_id": self.hypothesis_id,
                "priority": self.priority}


@dataclass(frozen=True, slots=True)
class SourceMaterial:
    source_type: SourceType
    title: str
    publisher: str
    text: str
    url: str | None = None
    published_at: str | None = None
    content_level: str = "FULL"


@dataclass(frozen=True, slots=True)
class SourceReference:
    source_id: str
    source_type: SourceType
    title: str
    publisher: str
    url: str | None
    published_at: str | None
    retrieved_at: str
    quality: int

    def to_dict(self) -> dict[str, object]:
        return {"source_id": self.source_id, "source_type": self.source_type.value,
                "title": self.title, "publisher": self.publisher, "url": self.url,
                "published_at": self.published_at, "retrieved_at": self.retrieved_at,
                "quality": self.quality}


class ResearchProvider(Protocol):
    def search(self, query: str, *, limit: int, byte_limit: int, deadline: float) -> tuple[SourceMaterial, ...]: ...


@dataclass(frozen=True, slots=True)
class ResearchBrief:
    brief_id: str
    request_id: str
    cache_key: str
    version: int
    content_hash: str
    target_id: str | None
    topic: str
    summary: str
    technology: str | None
    vulnerability_classes: tuple[str, ...]
    patterns: tuple[str, ...]
    implementation_details: tuple[str, ...]
    boundaries: tuple[str, ...]
    false_positives: tuple[str, ...]
    static_signals: tuple[str, ...]
    runtime_controls: tuple[str, ...]
    ontology_relationships: tuple[str, ...]
    limitations: tuple[str, ...]
    conflicts: tuple[str, ...]
    recommended_skills: tuple[str, ...]
    source_ids: tuple[str, ...]
    source_quality: int
    retrieved_at: str
    expires_at: str

    def to_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class EphemeralSkillProposal:
    proposal_id: str
    brief_id: str
    name: str
    description: str
    triggers: tuple[str, ...]
    prerequisites: tuple[str, ...]
    methodology: tuple[str, ...]
    controls: tuple[str, ...]
    confirmation_requirements: tuple[str, ...]
    source_ids: tuple[str, ...]
    target_specific: bool = True
    status: str = "ADVISORY"

    def to_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hidden = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript", "svg"}:
            self.hidden += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)


def _extract_patterns(material: SourceMaterial) -> tuple[str, ...]:
    parser = _TextExtractor()
    parser.feed(material.text[:16_384])
    text = " ".join(parser.parts)
    fragments = re.split(r"(?<=[.!?])\s+|\n+", text)
    selected: list[str] = []
    for fragment in fragments[:100]:
        item = _clean(fragment, 200)
        if 20 <= len(item) <= 200 and not _INSTRUCTION.search(item) and (
            any(label in item.lower() for label in _LABELS) or
            any(word in item.lower() for word in ("authorization", "origin", "validation", "graphql", "oauth"))
        ):
            selected.append(item)
        if len(selected) >= 3:
            break
    return tuple(selected)


class ResearchStore:
    def __init__(self, evidence: EvidenceFactStore) -> None:
        self.evidence = evidence

    def gaps(self, target_id: str, *, limit: int = 50) -> tuple[KnowledgeGap, ...]:
        if not 1 <= limit <= 100:
            raise ValueError("invalid gap limit")
        result: list[KnowledgeGap] = []
        with self.evidence._connection() as db:
            rows = db.execute("SELECT hypothesis_id,category,statement,priority FROM hypotheses "
                              "WHERE target_id=? AND status='NEEDS_RESEARCH' "
                              "ORDER BY priority DESC,hypothesis_id LIMIT ?", (target_id, limit)).fetchall()
            for row in rows:
                category = row["category"]
                kind = GapType(category) if category in GapType._value2member_map_ else GapType.LOW_HYPOTHESIS_CONFIDENCE
                result.append(KnowledgeGap("hypothesis:" + row["hypothesis_id"], target_id,
                    kind, _clean(row["statement"], 160), None, category, "hypothesis",
                    row["hypothesis_id"], row["priority"]))
            remaining = limit - len(result)
            if remaining:
                rows = db.execute("SELECT candidate_id,category,priority,status FROM exposure_candidates "
                                  "WHERE target_id=? AND status='NEEDS_RESEARCH' "
                                  "ORDER BY priority DESC,candidate_id LIMIT ?", (target_id, remaining)).fetchall()
                for row in rows:
                    result.append(KnowledgeGap("exposure:" + row["candidate_id"], target_id,
                        GapType.UNKNOWN_SECURITY_PRIMITIVE, row["category"].replace("_", " ").lower(),
                        None, row["category"], "exposure", None, row["priority"]))
            remaining = limit - len(result)
            if remaining:
                rows = db.execute("SELECT c.candidate_id,c.category,c.score,c.gaps_json,o.operation_type "
                    "FROM api_candidates c JOIN api_operations o ON o.operation_id=c.operation_id "
                    "WHERE c.target_id=? AND c.status IN ('REVIEW','BLOCKED','CANDIDATE') "
                    "ORDER BY c.score DESC,c.candidate_id LIMIT ?", (target_id, min(remaining * 3, 100))).fetchall()
                for row in rows:
                    if "NEEDS_RESEARCH" not in json.loads(row["gaps_json"]):
                        continue
                    result.append(KnowledgeGap("api:" + row["candidate_id"], target_id,
                        GapType.NEW_API_STYLE, row["operation_type"].replace("_", " ").lower() + " authorization",
                        row["operation_type"], row["category"], "api", None, row["score"]))
                    if len(result) >= limit:
                        break
        return tuple(result)

    def find_gap(self, target_id: str, gap_ref: str) -> KnowledgeGap:
        if not isinstance(gap_ref, str) or len(gap_ref) > 80:
            raise ValueError("invalid gap reference")
        prefix, separator, identifier = gap_ref.partition(":")
        if not separator or not _ID.fullmatch(identifier):
            raise LookupError("structured research gap not found")
        with self.evidence._connection() as db:
            if prefix == "hypothesis" and identifier.startswith("HYP-"):
                row = db.execute("SELECT category,statement,priority FROM hypotheses WHERE target_id=? "
                                 "AND hypothesis_id=? AND status='NEEDS_RESEARCH'",
                                 (target_id, identifier)).fetchone()
                if row:
                    kind = GapType(row["category"]) if row["category"] in GapType._value2member_map_ else GapType.LOW_HYPOTHESIS_CONFIDENCE
                    return KnowledgeGap(gap_ref, target_id, kind, _clean(row["statement"], 160),
                                        None, row["category"], "hypothesis", identifier, row["priority"])
            elif prefix == "exposure" and identifier.startswith("EXP-"):
                row = db.execute("SELECT category,priority FROM exposure_candidates WHERE target_id=? "
                                 "AND candidate_id=? AND status='NEEDS_RESEARCH'",
                                 (target_id, identifier)).fetchone()
                if row:
                    return KnowledgeGap(gap_ref, target_id, GapType.UNKNOWN_SECURITY_PRIMITIVE,
                                        row["category"].replace("_", " ").lower(), None,
                                        row["category"], "exposure", None, row["priority"])
            elif prefix == "api" and identifier.startswith("APIC-"):
                row = db.execute("SELECT c.category,c.score,c.gaps_json,o.operation_type "
                                 "FROM api_candidates c JOIN api_operations o ON o.operation_id=c.operation_id "
                                 "WHERE c.target_id=? AND c.candidate_id=? "
                                 "AND c.status IN ('REVIEW','BLOCKED','CANDIDATE')",
                                 (target_id, identifier)).fetchone()
                if row and "NEEDS_RESEARCH" in json.loads(row["gaps_json"]):
                    return KnowledgeGap(gap_ref, target_id, GapType.NEW_API_STYLE,
                                        row["operation_type"].replace("_", " ").lower() + " authorization",
                                        row["operation_type"], row["category"], "api", None, row["score"])
        raise LookupError("structured research gap not found")

    def cached(self, cache_key: str) -> dict[str, object] | None:
        with self.evidence._connection() as db:
            row = db.execute("SELECT * FROM research_briefs WHERE cache_key=? "
                             "ORDER BY version DESC LIMIT 1", (cache_key,)).fetchone()
            return dict(row) if row else None

    def active_for_cache(self, cache_key: str, target_id: str) -> dict[str, object] | None:
        with self.evidence._connection() as db:
            row = db.execute("SELECT request_id,status,brief_id FROM research_requests "
                             "WHERE cache_key=? AND target_id=? AND status IN ('PENDING','RESEARCHING') "
                             "ORDER BY created_at DESC LIMIT 1", (cache_key,target_id)).fetchone()
            return dict(row) if row else None

    def create_request(self, gap: KnowledgeGap, budget: ResearchBudget, *, external: bool,
                       private_target: bool, cache_key: str) -> str:
        request_id = "RREQ-" + uuid.uuid4().hex
        now = _now().isoformat()
        with self.evidence._connection() as db:
            db.execute("INSERT INTO research_requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (request_id, gap.target_id, gap.gap_ref, gap.gap_type.value, gap.topic,
                        gap.technology, gap.security_category, gap.specialist, gap.hypothesis_id,
                        cache_key, ResearchStatus.PENDING.value, json.dumps(budget.to_dict()),
                        int(external), int(private_target), 0, None, None, now, now,
                        json.dumps({"searches": 0, "sources": 0, "source_bytes": 0,
                                    "input_tokens_estimated": 0, "output_tokens_estimated": 0,
                                    "model_calls": 0})))
        return request_id

    def request(self, target_id: str, request_id: str) -> dict[str, object] | None:
        with self.evidence._connection() as db:
            row = db.execute("SELECT * FROM research_requests WHERE target_id=? AND request_id=?",
                             (target_id, request_id)).fetchone()
            return dict(row) if row else None

    def typed_request(self, target_id: str, request_id: str) -> ResearchRequest | None:
        row = self.request(target_id, request_id)
        return ResearchRequest.from_row(row) if row else None

    def record_usage(self, request_id: str, *, searches: int, sources: int,
                     source_bytes: int, input_tokens: int, output_tokens: int) -> None:
        usage = {"searches": searches, "sources": sources, "source_bytes": source_bytes,
                 "input_tokens_estimated": input_tokens,
                 "output_tokens_estimated": output_tokens, "model_calls": 0}
        with self.evidence._connection() as db:
            db.execute("UPDATE research_requests SET usage_json=? WHERE request_id=?",
                       (json.dumps(usage, sort_keys=True), request_id))

    def transition(self, request_id: str, status: ResearchStatus, *, brief_id: str | None = None,
                   error_code: str | None = None) -> None:
        with self.evidence._connection() as db:
            db.execute("UPDATE research_requests SET status=?,brief_id=COALESCE(?,brief_id),"
                       "error_code=?,updated_at=? WHERE request_id=? AND cancel_requested=0",
                       (status.value, brief_id, error_code, _now().isoformat(), request_id))

    def link_cached(self, gap: KnowledgeGap, cached: dict[str, object]) -> None:
        if not gap.hypothesis_id:
            return
        brief = json.loads(cached["payload_json"])
        guidance = json.dumps({"skills": brief["recommended_skills"],
                               "false_positives": brief["false_positives"],
                               "advisory_only": True})
        with self.evidence._connection() as db:
            db.execute("INSERT OR IGNORE INTO research_hypothesis_links "
                       "(hypothesis_id,brief_id,guidance_json,created_at) "
                       "SELECT hypothesis_id,?,?,? FROM hypotheses "
                       "WHERE hypothesis_id=? AND target_id=?",
                       (cached["brief_id"], guidance, _now().isoformat(),
                        gap.hypothesis_id, gap.target_id))

    def cancel(self, target_id: str, request_id: str) -> bool:
        with self.evidence._connection() as db:
            row = db.execute("UPDATE research_requests SET cancel_requested=1,status='CANCELLED',"
                             "updated_at=? WHERE target_id=? AND request_id=? "
                             "AND status IN ('PENDING','RESEARCHING')",
                             (_now().isoformat(), target_id, request_id))
            return row.rowcount == 1

    def reconcile_interrupted(self) -> int:
        with self.evidence._connection() as db:
            result = db.execute("UPDATE research_requests SET status='PARTIAL',"
                                "error_code='INTERRUPTED',updated_at=? WHERE status='RESEARCHING'",
                                (_now().isoformat(),))
            return result.rowcount

    def cancelled(self, request_id: str) -> bool:
        with self.evidence._connection() as db:
            row = db.execute("SELECT cancel_requested FROM research_requests WHERE request_id=?",
                             (request_id,)).fetchone()
            return not row or bool(row[0])

    def save_brief(self, brief: ResearchBrief, sources: tuple[SourceReference, ...],
                   proposal: EphemeralSkillProposal | None, status: ResearchStatus) -> None:
        payload = json.dumps(brief.to_dict(), sort_keys=True, separators=(",", ":"))
        with self.evidence._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            request = db.execute("SELECT cancel_requested,status FROM research_requests WHERE request_id=?",
                                 (brief.request_id,)).fetchone()
            if not request or request["cancel_requested"] or request["status"] != ResearchStatus.RESEARCHING.value:
                raise RuntimeError("research request is no longer active")
            db.execute("INSERT INTO research_briefs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       (brief.brief_id, brief.cache_key, brief.version, brief.content_hash,
                        brief.topic, brief.target_id, brief.summary, payload, brief.source_quality,
                        brief.retrieved_at, brief.expires_at, brief.request_id))
            for source in sources:
                db.execute("INSERT OR IGNORE INTO research_sources VALUES (?,?,?,?,?,?,?,?,?)",
                           (source.source_id, source.url, source.source_type.value, source.title,
                            source.publisher, source.published_at, source.retrieved_at,
                            source.quality, source.source_id))
                db.execute("INSERT INTO research_brief_sources VALUES (?,?,?)",
                           (brief.brief_id, source.source_id, source.retrieved_at))
            if proposal:
                db.execute("INSERT INTO research_skill_proposals VALUES (?,?,?,?,?,?)",
                           (proposal.proposal_id, brief.brief_id, proposal.name,
                            json.dumps(proposal.to_dict()), proposal.status, brief.retrieved_at))
            row = db.execute("SELECT hypothesis_id FROM research_requests WHERE request_id=?",
                             (brief.request_id,)).fetchone()
            if row and row[0]:
                db.execute("INSERT OR IGNORE INTO research_hypothesis_links VALUES (?,?,?,?)",
                           (row[0], brief.brief_id,
                            json.dumps({"skills": brief.recommended_skills,
                                        "false_positives": brief.false_positives,
                                        "advisory_only": True}), brief.retrieved_at))
            db.execute("UPDATE research_requests SET status=?,brief_id=?,updated_at=? WHERE request_id=?",
                       (status.value, brief.brief_id, brief.retrieved_at, brief.request_id))
        for source in sources:
            reference = {"brief_id": brief.brief_id, "source_id": source.source_id,
                         "source_type": source.source_type.value, "url": source.url,
                         "title": source.title, "retrieved_at": source.retrieved_at}
            evidence = self.evidence.create_evidence(
                EvidenceType.RESEARCH_REFERENCE,
                json.dumps(reference, sort_keys=True).encode(), source="RESEARCH_COORDINATOR",
                provenance=EvidenceProvenance(system="RESEARCH", entity="source_reference",
                                              record_id=source.source_id,
                                              qualification="documentation only; not runtime proof"),
                target_ref=brief.target_id, sensitivity=Sensitivity.PUBLIC,
                redaction_status=RedactionStatus.REDACTED)
            self.evidence.create_fact(
                brief.brief_id, "research_reference", source.source_id,
                confidence=source.quality / 100, evidence_ids=(evidence.evidence_id,),
                source="DOCUMENTED" if source.source_type in {SourceType.SKILL,
                    SourceType.MANUAL, SourceType.TARGET_DOCUMENTATION} else "RESEARCHED",
                target_ref=brief.target_id, sensitivity=Sensitivity.PUBLIC)
            if brief.target_id:
                for relation in brief.ontology_relationships:
                    if not relation.endswith(f"[source:{source.source_id}]"):
                        continue
                    match = _RELATION.search(relation)
                    if match:
                        self.evidence.create_fact(match[1], "documented_relation", match[2],
                            confidence=source.quality / 100, evidence_ids=(evidence.evidence_id,),
                            source="DOCUMENTED", target_ref=brief.target_id,
                            sensitivity=Sensitivity.PUBLIC)

    def brief(self, target_id: str, brief_id: str) -> dict[str, object] | None:
        with self.evidence._connection() as db:
            row = db.execute("SELECT * FROM research_briefs WHERE brief_id=? AND "
                             "(target_id=? OR target_id IS NULL)", (brief_id, target_id)).fetchone()
            if not row:
                return None
            item = json.loads(row["payload_json"])
            sources = db.execute("SELECT s.source_id,s.canonical_url,s.source_type,s.title,s.publisher,"
                                 "s.published_at,bs.retrieved_at,s.quality FROM research_sources s "
                                 "JOIN research_brief_sources bs "
                                 "ON bs.source_id=s.source_id WHERE bs.brief_id=? ORDER BY s.quality DESC",
                                 (brief_id,)).fetchall()
            proposal = db.execute("SELECT payload_json FROM research_skill_proposals WHERE brief_id=?",
                                  (brief_id,)).fetchone()
        item["sources"] = [dict(s) for s in sources]
        item["ephemeral_skill_proposal"] = json.loads(proposal[0]) if proposal else None
        item["freshness"] = self.freshness(item["retrieved_at"], item["expires_at"])
        return item

    @staticmethod
    def freshness(retrieved_at: str, expires_at: str) -> str:
        start = datetime.fromisoformat(retrieved_at)
        end = datetime.fromisoformat(expires_at)
        now = _now()
        if now >= end:
            return "EXPIRED"
        return "STALE" if now >= start + (end - start) * 0.8 else "FRESH"

    def list(self, target_id: str, *, limit: int = 20) -> dict[str, object]:
        if not 1 <= limit <= 100:
            raise ValueError("invalid page size")
        with self.evidence._connection() as db:
            rows = db.execute("SELECT r.request_id,r.gap_ref,r.gap_type,r.topic,r.status,r.brief_id,"
                              "r.created_at,b.expires_at,b.quality,b.payload_json "
                              "FROM research_requests r LEFT JOIN research_briefs b ON b.brief_id=r.brief_id "
                              "WHERE r.target_id=? ORDER BY r.created_at DESC,r.request_id DESC LIMIT ?",
                              (target_id, limit)).fetchall()
        items = []
        for row in rows:
            item = {key: row[key] for key in ("request_id", "gap_ref", "gap_type", "topic",
                                            "status", "brief_id", "created_at", "quality")}
            item["freshness"] = self.freshness(json.loads(row["payload_json"])["retrieved_at"],
                                               row["expires_at"]) if row["brief_id"] else None
            item["recommended_skills"] = json.loads(row["payload_json"]).get("recommended_skills", []) if row["payload_json"] else []
            items.append(item)
        return {"items": items, "limit": limit}

    def metrics(self, target_id: str) -> dict[str, int]:
        with self.evidence._connection() as db:
            requests = db.execute("SELECT count(*) FROM research_requests WHERE target_id=?", (target_id,)).fetchone()[0]
            briefs = db.execute("SELECT count(DISTINCT brief_id) FROM research_requests "
                                "WHERE target_id=? AND brief_id IS NOT NULL", (target_id,)).fetchone()[0]
            recommendations = db.execute("SELECT count(*) FROM research_hypothesis_links l JOIN hypotheses h "
                                         "ON h.hypothesis_id=l.hypothesis_id WHERE h.target_id=?",
                                         (target_id,)).fetchone()[0]
            later_confirmed = db.execute("SELECT count(DISTINCT l.brief_id) FROM research_hypothesis_links l "
                "JOIN findings f ON f.hypothesis_id=l.hypothesis_id "
                "JOIN hypotheses h ON h.hypothesis_id=l.hypothesis_id "
                "JOIN research_briefs b ON b.brief_id=l.brief_id "
                "WHERE h.target_id=? AND f.created_at>b.retrieved_at", (target_id,)).fetchone()[0]
        return {"requests": requests, "briefs": briefs, "hypothesis_recommendations": recommendations,
                "later_confirmed_links": later_confirmed}


class ResearchCoordinator:
    """No execution authority. Providers return source data only."""

    def __init__(self, store: ResearchStore, *, local_providers: tuple[ResearchProvider, ...] = (),
                 web_provider: ResearchProvider | None = None, skill_names: tuple[str, ...] = ()) -> None:
        self.store = store
        self.local_providers = local_providers
        self.web_provider = web_provider
        self.skill_names = frozenset(skill_names)

    @staticmethod
    def cache_key(gap: KnowledgeGap, *, private_target: bool) -> str:
        public_topic = gap.technology if private_target else (gap.technology or gap.topic)
        generic = (gap.gap_type not in {GapType.UNKNOWN_OBJECT_RELATIONSHIP,
                                       GapType.UNKNOWN_PRODUCT_CONCEPT}
                   and _public_term(public_topic) is not None)
        stable = [RESEARCH_VERSION, gap.gap_type.value, gap.security_category or "",
                  gap.technology or "", (gap.technology or gap.topic).lower().strip()]
        if not generic:
            stable.append(gap.target_id)
        return hashlib.sha256(json.dumps(stable).encode()).hexdigest()

    def submit(self, gap: KnowledgeGap, *, budget: ResearchBudget | None = None,
               external: bool = False, private_target: bool = True,
               refresh: bool = False) -> dict[str, object]:
        budget = budget or ResearchBudget()
        key = self.cache_key(gap, private_target=private_target)
        cached = self.store.cached(key)
        active = self.store.active_for_cache(key, gap.target_id)
        if active:
            return active
        try:
            request_id = self.store.create_request(gap, budget, external=external,
                                                   private_target=private_target, cache_key=key)
        except sqlite3.IntegrityError:
            active = self.store.active_for_cache(key, gap.target_id)
            if active:
                return active
            raise
        if cached and not refresh and datetime.fromisoformat(cached["expires_at"]) > _now():
            self.store.transition(request_id, ResearchStatus.CACHE_HIT, brief_id=cached["brief_id"])
            self.store.link_cached(gap, cached)
            return {"request_id": request_id, "status": "CACHE_HIT", "brief_id": cached["brief_id"]}
        return {"request_id": request_id, "status": "PENDING", "brief_id": None}

    def run(self, gap: KnowledgeGap, request_id: str) -> dict[str, object]:
        request = self.store.typed_request(gap.target_id, request_id)
        if not request:
            raise LookupError("research request not found")
        if request.status is not ResearchStatus.PENDING:
            return {"request_id": request_id, "status": request.status.value, "brief_id": request.brief_id}
        budget = request.budget
        deadline = time.monotonic() + budget.max_duration_seconds
        self.store.transition(request_id, ResearchStatus.RESEARCHING)
        seen: set[str] = set()
        seen_bodies: set[str] = set()
        materials: list[SourceMaterial] = []
        fetched_bytes = 0
        failed = False
        searches = 0
        snippet_only = False
        # Private target statements may contain confidential product or object names.
        # Only an explicitly structured, sanitized technology may leave this process.
        query = _public_term(gap.technology if request.private_target else
                             (gap.technology or gap.topic))
        category = _public_term(gap.security_category or "security")
        query = _public_term(query + " " + (category or "security") + " documentation") if query else None
        reserve_external = int(bool(request.external_allowed and self.web_provider and query
                                    and budget.max_sources > 1))
        def collect(provider: ResearchProvider, *, reserve: int = 0) -> None:
            nonlocal fetched_bytes, failed
            if self.store.cancelled(request_id):
                return
            remaining = budget.max_sources - reserve - len(materials)
            if time.monotonic() >= deadline or remaining <= 0:
                return
            try:
                values = provider.search(query or "", limit=remaining,
                                         byte_limit=budget.max_fetched_bytes - fetched_bytes,
                                         deadline=deadline)
            except Exception:
                failed = True
                return
            for value in values:
                if self.store.cancelled(request_id):
                    return
                size = len(value.text.encode("utf-8"))
                if size > budget.max_fetched_bytes - fetched_bytes:
                    break
                url = _canonical_url(value.url)
                key = url or hashlib.sha256((value.publisher + value.title).lower().encode()).hexdigest()
                body_key = hashlib.sha256(" ".join(value.text.split()).lower().encode()).hexdigest()
                if key in seen or body_key in seen_bodies:
                    continue
                seen.add(key)
                seen_bodies.add(body_key)
                materials.append(value)
                fetched_bytes += size
                if len(materials) >= budget.max_sources - reserve:
                    break
        for provider in self.local_providers:
            collect(provider, reserve=reserve_external)
        locally_answered = any(QUALITY[item.source_type] >= 80 and _extract_patterns(item)
                               for item in materials)
        if request.external_allowed and self.web_provider and query and not locally_answered:
            searches = 1
            collect(self.web_provider)
        snippet_only = bool(materials) and all(item.content_level == "SNIPPET" for item in materials)
        if self.store.cancelled(request_id):
            return {"request_id": request_id, "status": "CANCELLED", "brief_id": None}
        if not materials:
            status = ResearchStatus.PARTIAL if failed else ResearchStatus.BLOCKED
            self.store.record_usage(request_id, searches=searches, sources=0,
                                    source_bytes=fetched_bytes, input_tokens=0, output_tokens=0)
            self.store.transition(request_id, status, error_code="PROVIDER_UNAVAILABLE" if failed else "NO_RELEVANT_SOURCES")
            return {"request_id": request_id, "status": status.value, "brief_id": None}
        sources: list[SourceReference] = []
        patterns: list[str] = []
        token_estimate = 0
        for item in materials:
            if time.monotonic() >= deadline or self.store.cancelled(request_id):
                break
            title = _clean(item.title, 180)
            publisher = _clean(item.publisher, 80)
            url = _canonical_url(item.url)
            source_id = "RSRC-" + hashlib.sha256((url or publisher + title).encode()).hexdigest()[:32]
            quality = QUALITY[item.source_type]
            sources.append(SourceReference(source_id, item.source_type, title, publisher,
                                           url, item.published_at, _now().isoformat(), quality))
            for pattern in _extract_patterns(item):
                cost = max(1, len(pattern.split()) * 2)
                if token_estimate + cost > budget.max_tokens:
                    break
                patterns.append(f"{pattern} [source:{source_id}]")
                token_estimate += cost
        if self.store.cancelled(request_id):
            return {"request_id": request_id, "status": "CANCELLED", "brief_id": None}
        if not sources:
            self.store.transition(request_id, ResearchStatus.PARTIAL, error_code="BUDGET_EXHAUSTED")
            return {"request_id": request_id, "status": "PARTIAL", "brief_id": None}
        skill_hints = tuple(name for name in sorted(self.skill_names)
                            if any(term in name for term in (gap.security_category or "").lower().split("_")))[:4]
        patterns = list(dict.fromkeys(patterns))[:8]
        def classify(label: str) -> tuple[str, ...]:
            return tuple(pattern for pattern in patterns if label in pattern.lower())[:4]
        implementation = classify("implementation detail")
        boundaries = classify("security boundary")
        false_positives = classify("false positive")
        static_signals = classify("discovery signal")
        runtime_controls = tuple(dict.fromkeys((*classify("control"),
            "Establish an owned baseline and a negative control before testing.")))[:5]
        ontology = []
        if gap.gap_type in {GapType.UNKNOWN_OBJECT_RELATIONSHIP, GapType.UNKNOWN_PRODUCT_CONCEPT}:
            for material in materials:
                if material.source_type not in {SourceType.TARGET_DOCUMENTATION, SourceType.MANUAL}:
                    continue
                source_url = _canonical_url(material.url)
                source_id = "RSRC-" + hashlib.sha256(
                    (source_url or _clean(material.publisher, 80) + _clean(material.title, 180)).encode()
                ).hexdigest()[:32]
                for child, parent in _RELATION.findall(material.text[:4096]):
                    ontology.append(f"{child} -> {parent} [source:{source_id}]")
                    if len(ontology) >= 8:
                        break
        ontology = list(dict.fromkeys(ontology))[:8]
        negatives = [p for p in patterns if "does not require" in p.lower()]
        positives = [p for p in patterns if ("requires" in p.lower() or "required" in p.lower())
                     and "does not require" not in p.lower()]
        conflicts = ("Sources disagree on a required control: "
                     + re.search(r"\[source:RSRC-[0-9a-f]{32}\]", negatives[0]).group()
                     + " versus "
                     + re.search(r"\[source:RSRC-[0-9a-f]{32}\]", positives[0]).group()
                     + ". Verify the current implementation.",) if negatives and positives else ()
        limits = ["Research is advisory; target behavior and authorization remain unverified."]
        if failed:
            limits.append("At least one source provider failed; coverage may be partial.")
        if any(item.content_level == "SNIPPET" for item in materials):
            limits.append("Some source claims came from search snippets; read the cited page before testing.")
        if not patterns:
            limits.append("Sources were identified, but no compact security pattern was extracted.")
        quality = round(sum(s.quality for s in sources) / len(sources))
        now = _now()
        ttl = timedelta(days=7 if gap.gap_type in {GapType.NEW_FRAMEWORK, GapType.NEW_API_STYLE} else 30)
        old = self.store.cached(request.cache_key)
        version = int(old["version"]) + 1 if old else 1
        brief_id = "RBRF-" + uuid.uuid4().hex
        target_specific = gap.gap_type in {GapType.UNKNOWN_OBJECT_RELATIONSHIP,
                                          GapType.UNKNOWN_PRODUCT_CONCEPT} or query is None
        brief_topic = gap.topic if target_specific else (gap.technology or gap.topic)
        summary = _clean(f"Source-backed research for {brief_topic}: {len(sources)} source(s), "
                         f"{len(patterns)} compact pattern(s).", 240)
        fingerprint = hashlib.sha256(json.dumps([brief_topic, gap.technology, summary,
            patterns, implementation, boundaries, false_positives, static_signals,
            runtime_controls, ontology, limits, conflicts, skill_hints, [s.source_id for s in sources]],
                                             sort_keys=True).encode()).hexdigest()
        brief = ResearchBrief(brief_id, request_id, request.cache_key, version,
            fingerprint, gap.target_id if target_specific else None,
            _clean(brief_topic, 160), summary, gap.technology,
            (gap.security_category,) if gap.security_category else (), tuple(patterns),
            implementation, boundaries, false_positives, static_signals, runtime_controls,
            tuple(ontology),
            tuple(limits), conflicts, skill_hints, tuple(s.source_id for s in sources),
            quality, now.isoformat(), (now + ttl).isoformat())
        proposal = None
        if gap.gap_type is GapType.SKILL_GAP and not skill_hints:
            proposal = EphemeralSkillProposal("RSP-" + uuid.uuid4().hex, brief_id,
                "research-" + re.sub(r"[^a-z0-9]+", "-", gap.topic.lower()).strip("-")[:40],
                "Advisory skill candidate requiring researcher review and Phase 15 validation.",
                (gap.gap_type.value,), ("Current target context",), tuple(patterns[:3]),
                ("Owned baseline", "Negative control"),
                ("Independent runtime verification",), brief.source_ids)
        status = ResearchStatus.PARTIAL if failed or not patterns or snippet_only else ResearchStatus.COMPLETED
        try:
            self.store.save_brief(brief, tuple(sources), proposal, status)
        except RuntimeError:
            if self.store.cancelled(request_id):
                return {"request_id": request_id, "status": "CANCELLED", "brief_id": None}
            raise
        self.store.record_usage(request_id, searches=searches, sources=len(sources),
                                source_bytes=fetched_bytes,
                                input_tokens=sum(max(1, len(item.text.split()) * 2) for item in materials),
                                output_tokens=token_estimate)
        return {"request_id": request_id, "status": status.value, "brief_id": brief_id}
