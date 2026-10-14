"""Passive, deterministic hypotheses. A hypothesis is never a confirmed finding."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import re
from typing import Mapping, Protocol

from .evidence import EvidenceProvenance, EvidenceType, RedactionStatus, Sensitivity
from .logging import SecretRedactor
from .profile import SurfaceSignal, TargetProfile
from .store import EvidenceFactStore


class HypothesisStatus(StrEnum):
    NEW = "NEW"
    ENRICHING = "ENRICHING"
    READY = "READY"
    NEEDS_RESEARCH = "NEEDS_RESEARCH"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    READY_FOR_EXPERIMENT = "READY_FOR_EXPERIMENT"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"


class HypothesisSource(StrEnum):
    DETERMINISTIC = "DETERMINISTIC"
    MANUAL = "MANUAL"


@dataclass(frozen=True, slots=True)
class Hypothesis:
    id: str
    target_id: str
    dedupe_key: str
    category: str
    statement: str
    status: HypothesisStatus
    priority: int
    confidence: float
    potential_impact: str
    risk: str
    surface_key: str
    boundary: str
    why_generated: str
    prerequisites: tuple[str, ...]
    missing: tuple[str, ...]
    future_experiment: str
    positive_signal: str
    negative_signal: str
    skill_tags: tuple[str, ...]
    source: HypothesisSource
    producer: str
    evidence_ids: tuple[str, ...]
    fact_ids: tuple[str, ...]
    created_at: datetime
    updated_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id, "target_id": self.target_id, "category": self.category,
            "statement": self.statement, "status": self.status.value,
            "priority": self.priority, "confidence": self.confidence,
            "potential_impact": self.potential_impact, "risk": self.risk,
            "surface_key": self.surface_key, "boundary": self.boundary,
            "why_generated": self.why_generated,
            "prerequisites": list(self.prerequisites), "missing": list(self.missing),
            "prerequisite_state": "READY" if not self.missing else "MISSING",
            "future_experiment": self.future_experiment,
            "positive_signal": self.positive_signal, "negative_signal": self.negative_signal,
            "skill_tags": list(self.skill_tags), "source": self.source.value,
            "producer": self.producer, "evidence_ids": list(self.evidence_ids),
            "fact_ids": list(self.fact_ids), "evidence_count": len(self.evidence_ids),
            "created_at": self.created_at.isoformat(), "updated_at": self.updated_at.isoformat(),
        }


class HypothesisProposalProvider(Protocol):
    """Future optional model boundary; Phase 12 never invokes a provider."""

    def propose(self, profile: TargetProfile, context: Mapping[str, object]) -> tuple[Hypothesis, ...]: ...


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(*values: str) -> str:
    return hashlib.sha256("\x1f".join(values).encode()).hexdigest()[:32]


def _json(values: tuple[str, ...]) -> str:
    return json.dumps(values, separators=(",", ":"))


def _safe_text(value: str, maximum: int = 500) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 for c in value):
        raise ValueError("invalid hypothesis text")
    if SecretRedactor.from_environment().text(value) != value:
        raise ValueError("hypothesis text contains credential material")
    return value


class HypothesisStore:
    """BugHunter-owned SQLite. All generated rows require target-matched evidence."""

    def __init__(self, evidence: EvidenceFactStore) -> None:
        self.evidence = evidence

    def save_profile(self, profile: TargetProfile) -> str:
        payload = json.dumps(profile.to_dict(), sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode()).hexdigest()
        profile_id = "PROF-" + digest[:32]
        with self.evidence._connection() as db:
            db.execute("INSERT OR IGNORE INTO target_profiles VALUES (?,?,?,?,?,?)",
                       (profile_id, profile.target_id, profile.package_id,
                        profile.generated_at.isoformat(), payload, digest))
        return profile_id

    def latest_profile(self, target_id: str) -> TargetProfile | None:
        record = self.latest_profile_record(target_id)
        return record[1] if record else None

    def latest_profile_record(self, target_id: str) -> tuple[str, TargetProfile] | None:
        with self.evidence._connection() as db:
            row = db.execute("SELECT profile_id,profile_json FROM target_profiles WHERE target_id=? "
                             "ORDER BY generated_at DESC,profile_id DESC LIMIT 1", (target_id,)).fetchone()
        return (row["profile_id"], TargetProfile.from_dict(json.loads(row["profile_json"]))) if row else None

    def evidence_for_signal(self, target_id: str, signal: SurfaceSignal) -> tuple[str, ...]:
        if signal.evidence_ids:
            return signal.evidence_ids
        observed = signal.observed_at
        if observed is not None and observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        observed_key = observed.isoformat() if observed else ""
        key = (target_id, signal.source.value, signal.source_table, signal.source_id,
               observed_key, signal.code, signal.surface_key)
        with self.evidence._connection() as db:
            row = db.execute("SELECT evidence_id FROM profile_source_evidence WHERE "
                             "target_id=? AND source_kind=? AND source_table=? AND source_id=? "
                             "AND observed_at=? AND signal_code=? AND surface_key=?", key).fetchone()
        if row:
            return (row[0],)
        # Retain only a compact observation pointer, never fetched target content.
        content = json.dumps({"code": signal.code, "surface_key": signal.surface_key,
                              "source_table": signal.source_table, "source_id": signal.source_id},
                             sort_keys=True).encode()
        evidence = self.evidence.create_evidence(
            EvidenceType.RECON_RECORD if signal.source.value in {"RECON", "JS_ANALYSIS"} else EvidenceType.MANUAL_NOTE,
            content, source="PASSIVE_PROFILE", target_ref=target_id,
            provenance=EvidenceProvenance(system=signal.source.value, entity=signal.source_table,
                                          record_id=signal.source_id, observed_at=observed,
                                          qualification="passive metadata only"),
            observed_at=observed, sensitivity=Sensitivity.INTERNAL,
            redaction_status=RedactionStatus.REDACTED)
        with self.evidence._connection() as db:
            db.execute("INSERT OR IGNORE INTO profile_source_evidence VALUES (?,?,?,?,?,?,?,?)",
                       (*key, evidence.evidence_id))
            row = db.execute("SELECT evidence_id FROM profile_source_evidence WHERE "
                             "target_id=? AND source_kind=? AND source_table=? AND source_id=? "
                             "AND observed_at=? AND signal_code=? AND surface_key=?", key).fetchone()
        return (row[0],)

    def _validate_links(self, item: Hypothesis) -> None:
        if item.source is HypothesisSource.DETERMINISTIC and not (item.evidence_ids or item.fact_ids):
            raise ValueError("generated hypothesis requires supporting evidence")
        with self.evidence._connection() as db:
            for evidence_id in item.evidence_ids:
                row = db.execute("SELECT target_ref FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
                if row is None or row[0] != item.target_id:
                    raise ValueError("evidence target mismatch")
            for fact_id in item.fact_ids:
                row = db.execute("SELECT target_ref FROM facts WHERE fact_id=?", (fact_id,)).fetchone()
                if row is None or row[0] != item.target_id:
                    raise ValueError("fact target mismatch")

    def upsert(self, item: Hypothesis) -> Hypothesis:
        if not isinstance(item.status, HypothesisStatus) or not 0 <= item.priority <= 100 or not 0 <= item.confidence <= 1:
            raise ValueError("invalid hypothesis")
        self._validate_links(item)
        with self.evidence._connection() as db:
            row = db.execute("SELECT hypothesis_id,status,priority,source FROM hypotheses "
                             "WHERE target_id=? AND dedupe_key=?", (item.target_id, item.dedupe_key)).fetchone()
            if row:
                existing = self.get(row[0])
                assert existing is not None
                if existing.source is HypothesisSource.MANUAL or existing.status is HypothesisStatus.REJECTED:
                    return existing
                status = item.status
                priority = item.priority
                if status != existing.status or priority != existing.priority:
                    db.execute("UPDATE hypotheses SET status=?,priority=?,updated_at=? WHERE hypothesis_id=?",
                               (status.value, priority, _now().isoformat(), existing.id))
                    db.execute("INSERT INTO hypothesis_events "
                               "(hypothesis_id,changed_at,actor,event_type,old_status,new_status,old_priority,new_priority,reason) "
                               "VALUES (?,?,?,?,?,?,?,?,?)",
                               (existing.id, _now().isoformat(), item.producer, "REPROFILE",
                                existing.status.value, status.value, existing.priority, priority,
                                "deterministic profile or prerequisite change"))
                for evidence_id in item.evidence_ids:
                    db.execute("INSERT OR IGNORE INTO hypothesis_evidence VALUES (?,?)", (existing.id, evidence_id))
                for fact_id in item.fact_ids:
                    db.execute("INSERT OR IGNORE INTO hypothesis_facts VALUES (?,?)", (existing.id, fact_id))
                result_id = existing.id
            else:
                db.execute("""INSERT INTO hypotheses VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    item.id, item.target_id, item.dedupe_key, item.category, item.statement, item.status.value,
                    item.priority, item.confidence, item.potential_impact, item.risk, item.surface_key,
                    item.boundary, item.why_generated, _json(item.prerequisites), _json(item.missing),
                    item.future_experiment, item.positive_signal, item.negative_signal, _json(item.skill_tags),
                    item.source.value, item.producer, item.created_at.isoformat(), item.updated_at.isoformat()))
                for evidence_id in item.evidence_ids:
                    db.execute("INSERT INTO hypothesis_evidence VALUES (?,?)", (item.id, evidence_id))
                for fact_id in item.fact_ids:
                    db.execute("INSERT INTO hypothesis_facts VALUES (?,?)", (item.id, fact_id))
                db.execute("INSERT INTO hypothesis_events "
                           "(hypothesis_id,changed_at,actor,event_type,new_status,new_priority,reason) "
                           "VALUES (?,?,?,?,?,?,?)", (item.id, item.created_at.isoformat(),
                                                       item.producer, "CREATED", item.status.value,
                                                       item.priority, "passive hypothesis created"))
                result_id = item.id
        result = self.get(result_id)
        assert result is not None
        return result

    def _row(self, db, row) -> Hypothesis:
        evidence = tuple(r[0] for r in db.execute("SELECT evidence_id FROM hypothesis_evidence WHERE hypothesis_id=? "
                                                  "ORDER BY evidence_id LIMIT 32", (row["hypothesis_id"],)))
        facts = tuple(r[0] for r in db.execute("SELECT fact_id FROM hypothesis_facts WHERE hypothesis_id=? "
                                               "ORDER BY fact_id LIMIT 32", (row["hypothesis_id"],)))
        return Hypothesis(row["hypothesis_id"], row["target_id"], row["dedupe_key"], row["category"],
                          row["statement"], HypothesisStatus(row["status"]), row["priority"],
                          row["confidence"], row["potential_impact"], row["risk"], row["surface_key"],
                          row["boundary"], row["why_generated"], tuple(json.loads(row["prerequisites_json"])),
                          tuple(json.loads(row["missing_json"])), row["future_experiment"],
                          row["positive_signal"], row["negative_signal"], tuple(json.loads(row["skill_tags_json"])),
                          HypothesisSource(row["source"]), row["producer"], evidence, facts,
                          datetime.fromisoformat(row["created_at"]), datetime.fromisoformat(row["updated_at"]))

    def get(self, hypothesis_id: str, target_id: str | None = None) -> Hypothesis | None:
        with self.evidence._connection() as db:
            row = db.execute("SELECT * FROM hypotheses WHERE hypothesis_id=?" +
                             (" AND target_id=?" if target_id else ""),
                             (hypothesis_id, target_id) if target_id else (hypothesis_id,)).fetchone()
            return self._row(db, row) if row else None

    def list(self, target_id: str, *, limit: int = 20, cursor: str | None = None,
             status: str | None = None, category: str | None = None) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("invalid page size")
        if status is not None:
            HypothesisStatus(status)
        if category is not None and not re.fullmatch(r"[A-Z_]{2,40}", category):
            raise ValueError("invalid category")
        if cursor is not None and not re.fullmatch(r"(?:100|[0-9]{1,2}):HYP-[0-9a-f]{32}", cursor):
            raise ValueError("invalid cursor")
        clauses = ["target_id=?"]
        args: list[object] = [target_id]
        if status:
            clauses.append("status=?"); args.append(status)
        if category:
            clauses.append("category=?"); args.append(category)
        if cursor:
            rank, identifier = cursor.split(":", 1)
            clauses.append("(priority<? OR (priority=? AND hypothesis_id<?))")
            args.extend((int(rank), int(rank), identifier))
        args.append(limit + 1)
        with self.evidence._connection() as db:
            rows = db.execute("SELECT * FROM hypotheses WHERE " + " AND ".join(clauses) +
                              " ORDER BY priority DESC,hypothesis_id DESC LIMIT ?", args).fetchall()
            items = [self._row(db, row) for row in rows[:limit]]
        return {"items": [item.to_dict() for item in items],
                "next_cursor": f"{items[-1].priority}:{items[-1].id}" if len(rows) > limit else None}

    def history(self, hypothesis_id: str, target_id: str) -> tuple[dict[str, object], ...]:
        if self.get(hypothesis_id, target_id) is None:
            raise LookupError("hypothesis not found")
        with self.evidence._connection() as db:
            rows = db.execute("SELECT changed_at,actor,event_type,old_status,new_status,old_priority,new_priority,reason "
                              "FROM hypothesis_events WHERE hypothesis_id=? ORDER BY event_id DESC LIMIT 30",
                              (hypothesis_id,)).fetchall()
        return tuple(dict(row) for row in rows)

    def relate(self, first_id: str, second_id: str, relation: str, target_id: str) -> None:
        if relation not in {"DUPLICATE_OF", "DEPENDS_ON", "VARIANT_OF", "SUPERSEDES"} or first_id == second_id:
            raise ValueError("invalid relationship")
        if self.get(first_id, target_id) is None or self.get(second_id, target_id) is None:
            raise LookupError("hypothesis not found")
        with self.evidence._connection() as db:
            db.execute("INSERT OR IGNORE INTO hypothesis_relationships VALUES (?,?,?,?)",
                       (first_id, second_id, relation, _now().isoformat()))

    def relationships(self, hypothesis_id: str, target_id: str) -> tuple[dict[str, str], ...]:
        if self.get(hypothesis_id, target_id) is None:
            raise LookupError("hypothesis not found")
        with self.evidence._connection() as db:
            rows = db.execute("SELECT related_id,relation,created_at FROM hypothesis_relationships "
                              "WHERE hypothesis_id=? LIMIT 20", (hypothesis_id,)).fetchall()
        return tuple(dict(row) for row in rows)

    def add_manual(self, target_id: str, category: str, statement: str,
                   future_experiment: str) -> Hypothesis:
        if not re.fullmatch(r"[A-Z_]{2,40}", category):
            raise ValueError("invalid category")
        statement = _safe_text(statement)
        future_experiment = _safe_text(future_experiment)
        key = _digest(target_id, "MANUAL", category, " ".join(statement.lower().split()))
        now = _now()
        return self.upsert(Hypothesis("HYP-" + key, target_id, key, category, statement,
            HypothesisStatus.NEW, 30, 0.3, "Unverified", "Requires manual assessment",
            "manual:" + key, "UNSPECIFIED", "Researcher-created; no observed target behavior implied",
            ("authoritative scope",), ("supporting evidence not yet linked",), future_experiment,
            "A controlled future experiment demonstrates the effect",
            "A controlled future experiment denies the effect", (), HypothesisSource.MANUAL,
            "RESEARCHER", (), (), now, now))


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    category: str
    statement: str
    boundary: str
    impact: str
    experiment: str
    positive: str
    negative: str
    skill: str
    base: int
    prerequisites: tuple[str, ...]


RULES = {
    "CROSS_TENANT": Rule("CROSS_TENANT", "CROSS_TENANT", "Tenant-scoped object access may lack ownership enforcement",
        "TENANT", "Potential cross-tenant data access", "Compare an owned object from each tenant under both owned identities",
        "Foreign tenant identity receives protected object data", "Foreign tenant identity is denied without protected data",
        "cross-tenant-object-authorization", 75,
        ("second tenant identity", "owned objects with known ownership", "safe request template", "active scope permission")),
    "ROLE_ADMIN": Rule("ROLE_ADMIN", "ROLE_AUTHORIZATION", "Role-limited identity may reach an administrative operation",
        "ROLE", "Potential privilege escalation", "Compare observed admin operation using owned lower role and admin controls",
        "Lower role completes protected operation", "Backend denies lower role without side effect",
        "function-level-authorization", 72,
        ("different-role identity pair", "safe request template", "disposable object for writes", "active scope permission")),
    "GRAPHQL": Rule("GRAPHQL", "GRAPHQL_AUTHORIZATION", "GraphQL object or mutation authorization may differ by identity",
        "USER", "Potential protected field or action exposure", "Compare a known operation across controlled identities",
        "Unauthorized identity receives protected field or effect", "Resolver denies unauthorized access",
        "graphql-object-authorization", 65,
        ("multiple owned identities", "known GraphQL operation", "safe request template", "active scope permission")),
    "POSTMESSAGE": Rule("POSTMESSAGE", "POSTMESSAGE", "MessageChannel handshake may trust an unverified cross-origin sender",
        "CROSS_ORIGIN", "Potential privileged channel exposure", "Review origin/source checks and later use an owned browser proof",
        "Foreign origin obtains privileged data or capability", "Untrusted origin cannot establish the channel",
        "postmessage-capability", 65,
        ("current JS body", "reachable message flow", "active scope permission")),
    "DOM_XSS": Rule("DOM_XSS", "DOM_XSS", "Decoder and DOM sink may form an unsafe browser dataflow",
        "CLIENT_SERVER_TRUST", "Potential script execution", "Trace source through decoder to sink, then use a harmless owned-browser proof",
        "Attacker input reaches executable sink in current browser", "Final value is safely encoded or blocked",
        "check-before-transform-dom-xss", 60,
        ("current JS body", "attacker-controlled source", "reachable sink", "active scope permission")),
    "DOWNLOAD": Rule("DOWNLOAD", "EXPOSURE", "Download or export authorization may differ from its parent surface",
        "AUTHENTICATED", "Potential private file disclosure", "Compare owned download and anonymous or lower-role control",
        "Unauthorized actor receives protected file bytes", "Unauthorized actor receives no protected content",
        "unauthenticated-download", 68,
        ("owned protected file", "safe request template", "active scope permission")),
    "PII_EXPORT": Rule("PII_EXPORT", "EXPOSURE", "Person-level export may expose private records across an access boundary",
        "AUTHENTICATED", "Potential personal-data disclosure", "Compare an owned person-level export with denied controls",
        "Unauthorized actor receives private person-level records", "Backend denies access without private records",
        "sensitive-export-review", 62,
        ("owned person-level fixture", "safe request template", "active scope permission")),
    "INTERNAL_HOST": Rule("INTERNAL_HOST", "INTERNAL_SURFACE", "In-scope internal-looking host may expose restricted functions",
        "INTERNAL_EXTERNAL", "Potential administrative exposure", "Determine intended access policy and inspect a bounded current response",
        "Restricted capability is reachable without required role", "Access is blocked or surface is public by design",
        "internal-surface-review", 55,
        ("observed route", "intended access policy", "active scope permission")),
    "INTERNAL_ROUTE": Rule("INTERNAL_ROUTE", "INTERNAL_SURFACE", "Administrative route may rely on client-only restriction",
        "ROLE", "Potential administrative exposure", "Compare observed route under authorized and lower-role owned identities",
        "Lower role obtains restricted data or action", "Backend denies restricted operation",
        "internal-surface-review", 53,
        ("different-role identity pair", "safe request template", "active scope permission")),
    "CREDENTIAL_EXPOSURE": Rule("CREDENTIAL_EXPOSURE", "EXPOSURE", "JavaScript token-like string may be a non-public credential",
        "CLIENT_SERVER_TRUST", "Potential secret exposure", "Review current bundle context offline without using the value",
        "Non-public privileged credential is present in delivered asset", "Value is public client config or placeholder",
        "client-secret-review", 45,
        ("current JS body", "credential classification")),
    "URL_PARAMETER": Rule("URL_PARAMETER", "SSRF", "URL input may cause a server-side fetch across a trust boundary",
        "CLIENT_SERVER_TRUST", "Potential server-side fetch", "Identify observed server-side fetch semantics before any controlled callback",
        "Server performs an unauthorized fetch", "Input is client-only or server enforces destination policy",
        "ssrf-candidate", 43,
        ("server-side fetch evidence", "safe request template", "active scope permission")),
    "REDIRECT_PARAMETER": Rule("REDIRECT_PARAMETER", "OPEN_REDIRECT", "Redirect input may permit unintended external navigation",
        "CROSS_ORIGIN", "Potential redirect chain", "Inspect observed navigation semantics and controlled destination policy",
        "Untrusted destination is accepted", "Destination is rejected or constrained",
        "open-redirect-review", 35,
        ("redirect behavior evidence", "active scope permission")),
}


class HypothesisGenerator:
    def __init__(self, store: HypothesisStore) -> None:
        self.store = store

    def generate(self, profile: TargetProfile) -> tuple[Hypothesis, ...]:
        signals = profile.signals
        by_code: dict[str, list[SurfaceSignal]] = {}
        for signal in signals:
            by_code.setdefault(signal.code, []).append(signal)
        result: list[Hypothesis] = []
        global_auth = by_code.get("BOUNDARY_AUTHENTICATED", [])
        identity_pair = by_code.get("IDENTITY_CROSS_TENANT_PAIR", [])
        role_pair = by_code.get("IDENTITY_DIFFERENT_ROLE_PAIR", [])
        request_keys = {s.surface_key for s in by_code.get("REQUEST_TEMPLATE", [])}

        def emit(name: str, primary: SurfaceSignal, supporting: tuple[SurfaceSignal, ...]) -> None:
            rule = RULES[name]
            references = tuple(s for s in by_code.get("JS_REFERENCE", [])
                               if s.surface_key == primary.surface_key)[:1]
            matched = (primary, *supporting, *references)
            # A target/package identifier alone is never sufficient support.
            if not matched:
                return
            evidence_ids: set[str] = set()
            fact_ids: set[str] = set()
            for signal in matched:
                evidence_ids.update(self.store.evidence_for_signal(profile.target_id, signal))
                fact_ids.update(signal.fact_ids)
            if not evidence_ids and not fact_ids:
                return
            missing: list[str] = []
            for prereq in rule.prerequisites:
                if prereq == "second tenant identity" and identity_pair:
                    continue
                if prereq == "different-role identity pair" and role_pair:
                    continue
                if prereq == "multiple owned identities" and by_code.get("IDENTITY_MULTIPLE"):
                    continue
                if prereq == "safe request template" and primary.surface_key in request_keys:
                    continue
                if prereq == "active scope permission" and profile.package_status == "TRACKED":
                    continue
                if prereq == "known GraphQL operation" and by_code.get("API_GRAPHQL"):
                    continue
                missing.append(prereq)
            if "second tenant identity" in missing or "different-role identity pair" in missing:
                status = HypothesisStatus.BLOCKED
            elif missing:
                status = HypothesisStatus.ENRICHING
            else:
                status = HypothesisStatus.READY_FOR_EXPERIMENT
            observed = primary.source.value in {"RECON", "TRAFFIC", "JS_ANALYSIS", "EVIDENCE", "FACT"}
            priority = min(100, max(0, rule.base + (6 if observed else 0) +
                                    (8 if any(s.recent for s in matched) else 0) +
                                    (5 if any(s.source.value == "TRAFFIC" for s in matched) else 0) +
                                    (3 if references else 0) -
                                    min(30, len(missing) * 5)))
            confidence = min(0.9, round(sum(s.confidence for s in matched) / len(matched), 2))
            surface = primary.surface_key
            key = _digest(profile.target_id, rule.name, surface, rule.boundary)
            now = _now()
            hypothesis = Hypothesis("HYP-" + key, profile.target_id, key, rule.category,
                rule.statement, status, priority, confidence, rule.impact,
                "Unverified hypothesis; no severity assigned", surface, rule.boundary,
                "Deterministic rule " + rule.name + " from " + ", ".join(sorted({s.source.value for s in matched})),
                rule.prerequisites, tuple(missing), rule.experiment, rule.positive, rule.negative,
                (rule.skill,), HypothesisSource.DETERMINISTIC, "PASSIVE_RULES_V1",
                tuple(sorted(evidence_ids)), tuple(sorted(fact_ids)), now, now)
            result.append(self.store.upsert(hypothesis))

        for signal in by_code.get("OBJECT_ID", []):
            if identity_pair:
                emit("CROSS_TENANT", signal, (identity_pair[0],))
        for signal in by_code.get("SURFACE_INTERNAL", []):
            if role_pair:
                emit("ROLE_ADMIN", signal, (role_pair[0],))
            else:
                emit("INTERNAL_ROUTE", signal, ())
        for signal in by_code.get("API_GRAPHQL", []):
            if by_code.get("IDENTITY_MULTIPLE"):
                emit("GRAPHQL", signal, (by_code["IDENTITY_MULTIPLE"][0],))
        for signal in by_code.get("JS_POSTMESSAGE", []):
            peer = next((s for s in by_code.get("JS_MESSAGECHANNEL", []) if s.surface_key == signal.surface_key), None)
            if peer:
                emit("POSTMESSAGE", signal, (peer,))
        for signal in by_code.get("JS_DOM_SINK", []):
            peer = next((s for s in by_code.get("JS_DECODER", []) if s.surface_key == signal.surface_key), None)
            if peer:
                emit("DOM_XSS", signal, (peer,))
        for signal in by_code.get("FEATURE_DOWNLOAD", []):
            if global_auth:
                emit("DOWNLOAD", signal, (global_auth[0],))
            peer = next((s for s in by_code.get("FEATURE_PII_OBJECT", [])
                         if s.surface_key == signal.surface_key), None)
            if peer:
                emit("PII_EXPORT", signal, (peer,))
        for signal in by_code.get("HOST_INTERNAL", []):
            emit("INTERNAL_HOST", signal, ())
        for signal in by_code.get("JS_TOKEN_LIKE", []):
            emit("CREDENTIAL_EXPOSURE", signal, ())
        for signal in by_code.get("PARAM_URL", []):
            emit("URL_PARAMETER", signal, ())
        for signal in by_code.get("PARAM_REDIRECT", []):
            emit("REDIRECT_PARAMETER", signal, ())
        # Unknown technology remains an explicit research task, not a guessed exploit.
        for signal in by_code.get("TECHNOLOGY", []):
            if signal.display.lower() in {"rest", "graphql", "websocket", "oauth", "react", "vue", "angular"}:
                continue
            key = _digest(profile.target_id, "RESEARCH", signal.surface_key)
            evidence_ids = self.store.evidence_for_signal(profile.target_id, signal)
            now = _now()
            result.append(self.store.upsert(Hypothesis("HYP-" + key, profile.target_id, key,
                "UNKNOWN", "Unfamiliar technology needs source-backed security review",
                HypothesisStatus.NEEDS_RESEARCH, 20, signal.confidence, "Unknown",
                "No exploitability implied", signal.surface_key, "UNKNOWN",
                "Observed technology fact requires interpretation", ("technology documentation",),
                ("technology documentation",), "Research exact deployment and security model later",
                "A concrete security boundary is identified", "Technology is unrelated to target exposure",
                (), HypothesisSource.DETERMINISTIC, "PASSIVE_RULES_V1", evidence_ids,
                signal.fact_ids, now, now)))
        return tuple({item.id: item for item in result}.values())


class ContextPacketBuilder:
    """Finite references for later reasoning. No source bodies, tokens, or corpus dumps."""

    def __init__(self, store: HypothesisStore) -> None:
        self.store = store

    def build(self, hypothesis: Hypothesis, profile: TargetProfile | None) -> dict[str, object]:
        signals = [s for s in profile.signals if s.surface_key == hypothesis.surface_key][:4] if profile else []
        evidence = []
        for evidence_id in hypothesis.evidence_ids[:6]:
            item = self.store.evidence.get_evidence(evidence_id)
            if item and item.target_ref == hypothesis.target_id:
                evidence.append(item.to_reference())
        facts = []
        for fact_id in hypothesis.fact_ids[:4]:
            item = self.store.evidence.get_fact(fact_id)
            if item and item.target_ref == hypothesis.target_id:
                facts.append(item.to_reference())
        return {"hypothesis": hypothesis.to_dict(), "profile": {
                    "target_id": profile.target_id, "features": profile.features[:10],
                    "boundaries": profile.boundaries[:10], "gaps": profile.gaps[:10],
                } if profile else None,
                "signals": [s.to_dict() for s in signals], "evidence": evidence, "facts": facts}
