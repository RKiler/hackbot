"""BugHunter-owned DOM XSS artifact and static candidate ledger."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import re
import uuid
from urllib.parse import urlsplit

from .domxss_static import (
    ANALYZER_VERSION, DOMAnalysis, DOMCandidateStatus, DOMFlowCandidate, DOMStaticAnalyzer,
    FlowStep, MAX_ASSET_BYTES, SourceLocation,
)
from .domxss_maps import MAX_SOURCE_MAP_BYTES, map_locations
from .evidence import EvidenceProvenance, EvidenceType, Sensitivity
from .store import EvidenceFactStore


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_CANDIDATE_ID = re.compile(r"DOM-[0-9a-f]{32}\Z")


@dataclass(frozen=True, slots=True)
class DOMAssetRecord:
    artifact_id: str
    target_id: str
    recon_asset_id: int | None
    asset_url_sha256: str
    recon_sha256: str | None
    artifact_sha256: str
    evidence_id: str
    retrieval_exchange_id: str | None
    state: str
    source: str
    retrieved_at: datetime


@dataclass(frozen=True, slots=True)
class DOMCandidatePage:
    items: tuple[DOMFlowCandidate, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class DOMSourceMapRecord:
    map_id: str
    target_id: str
    js_artifact_id: str
    map_url_sha256: str
    map_sha256: str
    evidence_id: str
    retrieval_exchange_id: str | None
    retrieved_at: datetime


def _candidate_from_row(row: object) -> DOMFlowCandidate:
    data = json.loads(row["candidate_json"])
    data["source_location"] = SourceLocation(**data["source_location"])
    data["sink_location"] = SourceLocation(**data["sink_location"])
    data["validation"] = tuple(FlowStep(step["operation"], SourceLocation(**step["location"]))
                               for step in data["validation"])
    data["transforms"] = tuple(FlowStep(step["operation"], SourceLocation(**step["location"]))
                               for step in data["transforms"])
    data["post_checks"] = tuple(FlowStep(step["operation"], SourceLocation(**step["location"]))
                                for step in data.get("post_checks", ()))
    data["sanitizers"] = tuple(FlowStep(step["operation"], SourceLocation(**step["location"]))
                                for step in data.get("sanitizers", ()))
    data["evidence_ids"] = tuple(data.get("evidence_ids", ()))
    data["status"] = DOMCandidateStatus(row["status"])
    return DOMFlowCandidate(**data)


class DOMXSSStore:
    """No network access; active artifact bytes must arrive from a trusted executor."""

    def __init__(self, evidence: EvidenceFactStore) -> None:
        self.evidence = evidence

    def _verify_exchange(self, target_id: str, exchange_id: str, digest: str,
                         size: int) -> None:
        with self.evidence._connection() as connection:
            exchange = connection.execute("""
                SELECT e.target_id,e.source,e.state,r.status_code,r.body_hash,r.body_size
                FROM traffic_exchanges e JOIN traffic_responses r ON r.request_id=e.request_id
                WHERE e.exchange_id=? LIMIT 1
            """, (exchange_id,)).fetchone()
        if (exchange is None or exchange["target_id"] != target_id or exchange["source"] != "HACKBOT"
                or exchange["state"] != "COMPLETE" or exchange["status_code"] != 200
                or exchange["body_hash"] != digest or exchange["body_size"] != size):
            raise ValueError("Controlled retrieval evidence does not match artifact")

    @staticmethod
    def _asset(row: object) -> DOMAssetRecord:
        return DOMAssetRecord(
            artifact_id=row["artifact_id"], target_id=row["target_id"],
            recon_asset_id=row["recon_asset_id"], asset_url_sha256=row["asset_url_sha256"],
            recon_sha256=row["recon_sha256"], artifact_sha256=row["artifact_sha256"],
            evidence_id=row["evidence_id"], retrieval_exchange_id=row["retrieval_exchange_id"],
            state=row["state"], source=row["source"],
            retrieved_at=datetime.fromisoformat(row["retrieved_at"]),
        )

    def current_asset(self, target_id: str, asset_url: str,
                      recon_sha256: str | None) -> DOMAssetRecord | None:
        """Reuse only an intact artifact matching the current recon hash."""
        if recon_sha256 is None or not _HASH.fullmatch(recon_sha256):
            return None
        url_hash = hashlib.sha256(asset_url.encode()).hexdigest()
        with self.evidence._connection() as connection:
            row = connection.execute("""
                SELECT * FROM dom_js_artifacts WHERE target_id=? AND asset_url_sha256=?
                  AND artifact_sha256=? AND state='CURRENT'
                ORDER BY retrieved_at DESC LIMIT 1
            """, (target_id, url_hash, recon_sha256)).fetchone()
        if row is None:
            return None
        asset = self._asset(row)
        self.evidence.artifacts.get_bytes(asset.artifact_sha256, max_bytes=MAX_ASSET_BYTES)
        return asset

    def record_artifact(self, *, target_id: str, asset_url: str, body: bytes,
                        recon_asset_id: int | None, recon_sha256: str | None,
                        source: str, retrieval_exchange_id: str | None = None,
                        capture_evidence_id: str | None = None) -> DOMAssetRecord:
        if not isinstance(body, bytes) or len(body) > MAX_ASSET_BYTES:
            raise ValueError("JS artifact exceeds Phase 21 size limit")
        if source not in {"CONTROLLED_HTTP", "FIXTURE", "IMPORTED"}:
            raise ValueError("Invalid JS artifact source")
        if source == "CONTROLLED_HTTP" and (not retrieval_exchange_id or not capture_evidence_id):
            raise ValueError("Controlled retrieval requires traffic and protected capture evidence")
        if source != "CONTROLLED_HTTP" and (retrieval_exchange_id or capture_evidence_id):
            raise ValueError("Only controlled retrieval may cite a traffic exchange")
        try:
            parsed = urlsplit(asset_url)
            valid_url = (parsed.scheme in {"http", "https"} and bool(parsed.hostname)
                         and not parsed.username and not parsed.password and not parsed.fragment)
        except ValueError:
            valid_url = False
        if not valid_url:
            raise ValueError("Invalid JavaScript asset URL")
        if recon_sha256 is not None and not _HASH.fullmatch(recon_sha256):
            raise ValueError("Invalid recon hash")
        if recon_asset_id is not None and (type(recon_asset_id) is not int or recon_asset_id <= 0):
            raise ValueError("Invalid recon asset ID")
        digest = hashlib.sha256(body).hexdigest()
        url_hash = hashlib.sha256(asset_url.encode()).hexdigest()
        if retrieval_exchange_id:
            self._verify_exchange(target_id, retrieval_exchange_id, digest, len(body))
        with self.evidence._connection() as connection:
            row = connection.execute("""
                SELECT * FROM dom_js_artifacts WHERE target_id=? AND asset_url_sha256=?
                  AND artifact_sha256=? LIMIT 1
            """, (target_id, url_hash, digest)).fetchone()
        if row is not None and row["state"] == "CURRENT" and source != "CONTROLLED_HTTP":
            self.evidence.artifacts.get_bytes(digest, max_bytes=MAX_ASSET_BYTES)
            return self._asset(row)
        if capture_evidence_id:
            observation = self.evidence.get_evidence(capture_evidence_id)
            if (observation is None or observation.target_ref != target_id
                    or observation.evidence_type != EvidenceType.JS_ASSET.value
                    or observation.content_hash != digest or observation.content_size != len(body)
                    or observation.sensitivity is not Sensitivity.SENSITIVE
                    or observation.provenance.record_id != retrieval_exchange_id):
                raise ValueError("Protected capture evidence does not match artifact")
        elif row is not None:
            observation = self.evidence.get_evidence(row["evidence_id"])
            if observation is None or observation.content_hash != digest:
                raise ValueError("Cached artifact evidence is unavailable")
        else:
            observation = self.evidence.create_evidence(
                EvidenceType.JS_ASSET, body, source="domxss_artifact",
                provenance=EvidenceProvenance(system="HACKBOT", entity="JS_ARTIFACT",
                                               record_id=str(recon_asset_id or "local")),
                target_ref=target_id, sensitivity=Sensitivity.SENSITIVE,
                metadata={"asset_url_sha256": url_hash, "recon_asset_id": recon_asset_id},
            )
        state = ("UNVERIFIED_CURRENT" if recon_sha256 is None else
                 "CURRENT" if recon_sha256 == digest else "RECON_HASH_DRIFT")
        now = datetime.now(timezone.utc)
        artifact_id = "DOMART-" + uuid.uuid4().hex
        with self.evidence._connection() as connection:
            if state == "CURRENT" or source == "CONTROLLED_HTTP":
                stale = connection.execute("""
                    SELECT artifact_id FROM dom_js_artifacts WHERE target_id=? AND asset_url_sha256=?
                      AND artifact_sha256<>? AND state='CURRENT'
                """, (target_id, url_hash, digest)).fetchall()
                for old in stale:
                    connection.execute("UPDATE dom_js_artifacts SET state='STALE' WHERE artifact_id=?",
                                       (old["artifact_id"],))
                    connection.execute("""
                        UPDATE dom_flow_candidates SET status='STALE',updated_at=?
                        WHERE artifact_id=? AND status NOT IN ('STALE','REJECTED')
                    """, (now.isoformat(), old["artifact_id"]))
            if row is None:
                connection.execute("""
                    INSERT INTO dom_js_artifacts (artifact_id,target_id,recon_asset_id,asset_url_sha256,
                      recon_sha256,artifact_sha256,evidence_id,retrieval_exchange_id,state,source,retrieved_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """, (artifact_id, target_id, recon_asset_id, url_hash, recon_sha256,
                      digest, observation.evidence_id, retrieval_exchange_id, state, source, now.isoformat()))
            else:
                artifact_id = row["artifact_id"]
                connection.execute("""
                    UPDATE dom_js_artifacts SET state=?,recon_sha256=?,evidence_id=?,
                      retrieval_exchange_id=?,source=?,retrieved_at=? WHERE artifact_id=?
                """, (state, recon_sha256, observation.evidence_id,
                      retrieval_exchange_id, source, now.isoformat(), artifact_id))
        result = self.get_asset(target_id, artifact_id)
        assert result is not None
        return result

    def get_asset(self, target_id: str, artifact_id: str) -> DOMAssetRecord | None:
        with self.evidence._connection() as connection:
            row = connection.execute("SELECT * FROM dom_js_artifacts WHERE target_id=? AND artifact_id=? LIMIT 1",
                                     (target_id, artifact_id)).fetchone()
        return self._asset(row) if row else None

    def get_source_map(self, target_id: str, js_artifact_id: str) -> DOMSourceMapRecord | None:
        with self.evidence._connection() as connection:
            row = connection.execute("""
                SELECT * FROM dom_source_maps WHERE target_id=? AND js_artifact_id=?
                ORDER BY retrieved_at DESC LIMIT 1
            """, (target_id, js_artifact_id)).fetchone()
        if row is None:
            return None
        return DOMSourceMapRecord(
            row["map_id"], row["target_id"], row["js_artifact_id"], row["map_url_sha256"],
            row["map_sha256"], row["evidence_id"], row["retrieval_exchange_id"],
            datetime.fromisoformat(row["retrieved_at"]),
        )

    def record_source_map(self, *, target_id: str, js_artifact_id: str, map_url: str,
                          body: bytes, source: str, retrieval_exchange_id: str | None = None,
                          capture_evidence_id: str | None = None) -> DOMSourceMapRecord:
        asset = self.get_asset(target_id, js_artifact_id)
        if asset is None or asset.state == "STALE":
            raise ValueError("Current JavaScript artifact is required")
        if not isinstance(body, bytes) or len(body) > MAX_SOURCE_MAP_BYTES:
            raise ValueError("Source map exceeds Phase 21 limit")
        if source not in {"CONTROLLED_HTTP", "FIXTURE"}:
            raise ValueError("Invalid source-map source")
        if source == "CONTROLLED_HTTP" and (not retrieval_exchange_id or not capture_evidence_id):
            raise ValueError("Controlled source map requires capture evidence")
        if source == "FIXTURE" and (retrieval_exchange_id or capture_evidence_id):
            raise ValueError("Fixture source map cannot cite a traffic exchange")
        try:
            parsed = urlsplit(map_url)
            valid = (parsed.scheme in {"http", "https"} and bool(parsed.hostname)
                     and not parsed.username and not parsed.password and not parsed.fragment)
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("Invalid source-map URL")
        digest = hashlib.sha256(body).hexdigest()
        url_hash = hashlib.sha256(map_url.encode()).hexdigest()
        with self.evidence._connection() as connection:
            existing = connection.execute("""
                SELECT * FROM dom_source_maps WHERE target_id=? AND js_artifact_id=?
                  AND map_url_sha256=? AND map_sha256=? LIMIT 1
            """, (target_id, js_artifact_id, url_hash, digest)).fetchone()
        if existing:
            return DOMSourceMapRecord(
                existing["map_id"], target_id, js_artifact_id, url_hash, digest,
                existing["evidence_id"], existing["retrieval_exchange_id"],
                datetime.fromisoformat(existing["retrieved_at"]),
            )
        if retrieval_exchange_id:
            self._verify_exchange(target_id, retrieval_exchange_id, digest, len(body))
            observation = self.evidence.get_evidence(capture_evidence_id)
            if (observation is None or observation.target_ref != target_id
                    or observation.evidence_type != EvidenceType.SOURCE_MAP.value
                    or observation.content_hash != digest or observation.content_size != len(body)
                    or observation.sensitivity is not Sensitivity.SENSITIVE
                    or observation.provenance.record_id != retrieval_exchange_id):
                raise ValueError("Protected map evidence does not match retrieval")
        else:
            observation = self.evidence.create_evidence(
                EvidenceType.SOURCE_MAP, body, source="domxss_source_map",
                provenance=EvidenceProvenance(system="HACKBOT", entity="SOURCE_MAP",
                                               record_id=js_artifact_id),
                target_ref=target_id, sensitivity=Sensitivity.SENSITIVE,
                metadata={"js_artifact_id": js_artifact_id, "map_url_sha256": url_hash},
            )
        map_id = "DOMMAP-" + uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        with self.evidence._connection() as connection:
            connection.execute("""
                INSERT INTO dom_source_maps (map_id,target_id,js_artifact_id,map_url_sha256,
                  map_sha256,evidence_id,retrieval_exchange_id,retrieved_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (map_id, target_id, js_artifact_id, url_hash, digest, observation.evidence_id,
                  retrieval_exchange_id, now))
        result = self.get_source_map(target_id, js_artifact_id)
        assert result is not None
        return result

    def map_candidate(self, target_id: str, candidate_id: str,
                      source_map: DOMSourceMapRecord) -> DOMFlowCandidate:
        candidate = self.get_candidate(target_id, candidate_id)
        if candidate is None or candidate.status is DOMCandidateStatus.STALE:
            raise ValueError("Current candidate is required")
        if source_map.target_id != target_id:
            raise ValueError("Source map belongs to another target")
        with self.evidence._connection() as connection:
            row = connection.execute("""
                SELECT artifact_id,candidate_json FROM dom_flow_candidates
                WHERE target_id=? AND candidate_id=? LIMIT 1
            """, (target_id, candidate_id)).fetchone()
        if row is None or row["artifact_id"] != source_map.js_artifact_id:
            raise ValueError("Source map is not bound to candidate bundle")
        body = self.evidence.read_content(source_map.evidence_id, allow_sensitive=True,
                                          max_bytes=MAX_SOURCE_MAP_BYTES)
        mapped = map_locations(body, (candidate.source_location, candidate.sink_location))
        sink = mapped[1]
        updated = replace(candidate, source_map_sha256=source_map.map_sha256,
                          mapped_source=(f"{sink.source}:{sink.line}:{sink.column}" if sink else None),
                          evidence_ids=tuple(dict.fromkeys((*candidate.evidence_ids, source_map.evidence_id))))
        with self.evidence._connection() as connection:
            connection.execute("UPDATE dom_flow_candidates SET candidate_json=?,updated_at=? WHERE candidate_id=?",
                               (json.dumps(asdict(updated), sort_keys=True),
                                datetime.now(timezone.utc).isoformat(), candidate_id))
        return updated

    def analyze_asset(self, target_id: str, artifact_id: str,
                      analyzer: DOMStaticAnalyzer) -> tuple[str, DOMAnalysis]:
        asset = self.get_asset(target_id, artifact_id)
        if asset is None:
            raise ValueError("Unknown target JS artifact")
        with self.evidence._connection() as connection:
            previous = connection.execute("""
                SELECT analysis_id FROM dom_analysis_runs WHERE artifact_id=? AND analyzer_version=? LIMIT 1
            """, (artifact_id, ANALYZER_VERSION)).fetchone()
        if previous is not None:
            return previous["analysis_id"], self._read_analysis(target_id, previous["analysis_id"])
        body = self.evidence.read_content(asset.evidence_id, allow_sensitive=True,
                                          max_bytes=MAX_ASSET_BYTES)
        analysis = analyzer.analyze(target_id=target_id, body=body,
                                    recon_asset_id=asset.recon_asset_id)
        if analysis.asset_sha256 != asset.artifact_sha256:
            raise ValueError("Artifact changed during analysis")
        analysis_id = "DOMAN-" + uuid.uuid4().hex
        with self.evidence._connection() as connection:
            connection.execute("""
                INSERT INTO dom_analysis_runs (analysis_id,target_id,artifact_id,analyzer_version,
                  status,parse_errors,candidate_count,analyzed_at) VALUES (?,?,?,?,?,?,?,?)
            """, (analysis_id, target_id, artifact_id, analysis.analyzer_version,
                  analysis.status, analysis.parse_errors, len(analysis.candidates),
                  analysis.analyzed_at.isoformat()))
            for candidate in analysis.candidates:
                candidate = replace(candidate, evidence_ids=(asset.evidence_id,))
                connection.execute("""
                    INSERT INTO dom_flow_candidates (candidate_id,target_id,artifact_id,analysis_id,score,
                      status,candidate_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)
                """, (candidate.candidate_id, target_id, artifact_id, analysis_id, candidate.score,
                      candidate.status.value, json.dumps(asdict(candidate), sort_keys=True),
                      analysis.analyzed_at.isoformat(), analysis.analyzed_at.isoformat()))
                connection.execute("""
                    INSERT INTO dom_candidate_events (candidate_id,old_status,new_status,reason_code,changed_at)
                    VALUES (?,?,?,?,?)
                """, (candidate.candidate_id, None, candidate.status.value, "STATIC_ANALYSIS",
                      analysis.analyzed_at.isoformat()))
        return analysis_id, replace(analysis, candidates=tuple(
            replace(item, evidence_ids=(asset.evidence_id,)) for item in analysis.candidates))

    def _read_analysis(self, target_id: str, analysis_id: str) -> DOMAnalysis:
        with self.evidence._connection() as connection:
            row = connection.execute("SELECT * FROM dom_analysis_runs WHERE target_id=? AND analysis_id=? LIMIT 1",
                                     (target_id, analysis_id)).fetchone()
            if row is None:
                raise ValueError("Unknown analysis")
            asset = connection.execute("SELECT * FROM dom_js_artifacts WHERE artifact_id=? LIMIT 1",
                                       (row["artifact_id"],)).fetchone()
            items = connection.execute("""
                SELECT * FROM dom_flow_candidates WHERE analysis_id=? ORDER BY score DESC,candidate_id LIMIT 16
            """, (analysis_id,)).fetchall()
        return DOMAnalysis(target_id, asset["recon_asset_id"], asset["artifact_sha256"],
                           row["analyzer_version"], datetime.fromisoformat(row["analyzed_at"]),
                           row["status"], tuple(_candidate_from_row(item) for item in items),
                           parse_errors=row["parse_errors"])

    def get_candidate(self, target_id: str, candidate_id: str) -> DOMFlowCandidate | None:
        if not _CANDIDATE_ID.fullmatch(candidate_id):
            raise ValueError("Invalid DOM candidate ID")
        with self.evidence._connection() as connection:
            row = connection.execute("SELECT * FROM dom_flow_candidates WHERE target_id=? AND candidate_id=? LIMIT 1",
                                     (target_id, candidate_id)).fetchone()
        return _candidate_from_row(row) if row else None

    def candidate_asset(self, target_id: str, candidate_id: str) -> DOMAssetRecord | None:
        if not _CANDIDATE_ID.fullmatch(candidate_id):
            raise ValueError("Invalid DOM candidate ID")
        with self.evidence._connection() as connection:
            row = connection.execute("""
                SELECT a.* FROM dom_flow_candidates c
                JOIN dom_js_artifacts a ON a.artifact_id=c.artifact_id
                WHERE c.target_id=? AND c.candidate_id=? AND a.target_id=? LIMIT 1
            """, (target_id, candidate_id, target_id)).fetchone()
        return self._asset(row) if row else None

    def candidate_links(self, target_id: str, candidate_id: str) -> dict[str, str | None] | None:
        if not _CANDIDATE_ID.fullmatch(candidate_id):
            raise ValueError("Invalid DOM candidate ID")
        with self.evidence._connection() as connection:
            row = connection.execute("""
                SELECT hypothesis_id,plan_id,run_id,validation_id
                FROM dom_flow_candidates WHERE target_id=? AND candidate_id=? LIMIT 1
            """, (target_id, candidate_id)).fetchone()
        return dict(row) if row else None

    def bind_route(self, target_id: str, candidate_id: str, route_url: str,
                   evidence_id: str) -> DOMFlowCandidate:
        candidate = self.get_candidate(target_id, candidate_id)
        asset = self.candidate_asset(target_id, candidate_id)
        evidence = self.evidence.get_evidence(evidence_id)
        if (candidate is None or asset is None or asset.state != "CURRENT"
                or candidate.status not in {DOMCandidateStatus.STATICALLY_SUPPORTED,
                                            DOMCandidateStatus.RUNTIME_READY}
                or candidate.route not in {None, route_url}
                or evidence is None or evidence.target_ref != target_id):
            raise ValueError("Current DOM candidate and target evidence are required")
        updated = replace(candidate, route=route_url,
                          evidence_ids=tuple(dict.fromkeys((*candidate.evidence_ids, evidence_id))))
        with self.evidence._connection() as connection:
            connection.execute("UPDATE dom_flow_candidates SET candidate_json=?,updated_at=? WHERE candidate_id=?",
                               (json.dumps(asdict(updated), sort_keys=True),
                                datetime.now(timezone.utc).isoformat(), candidate_id))
        return updated

    def bind_plan(self, target_id: str, candidate_id: str, hypothesis_id: str,
                  plan_id: str) -> None:
        if not _CANDIDATE_ID.fullmatch(candidate_id):
            raise ValueError("Invalid DOM candidate ID")
        with self.evidence._connection() as connection:
            row = connection.execute("""
                SELECT c.status,c.hypothesis_id,c.plan_id,c.run_id,a.state,a.artifact_sha256,
                       a.recon_sha256
                FROM dom_flow_candidates c JOIN dom_js_artifacts a ON a.artifact_id=c.artifact_id
                WHERE c.target_id=? AND c.candidate_id=? AND a.target_id=? LIMIT 1
            """, (target_id, candidate_id, target_id)).fetchone()
            hypothesis = connection.execute("""
                SELECT target_id FROM hypotheses WHERE hypothesis_id=? LIMIT 1
            """, (hypothesis_id,)).fetchone()
            plan = connection.execute("""
                SELECT target_id,hypothesis_id,skill_id FROM skill_plans
                WHERE plan_id=? LIMIT 1
            """, (plan_id,)).fetchone()
            if (row is None or row["state"] != "CURRENT"
                    or row["artifact_sha256"] != row["recon_sha256"]
                    or row["status"] not in {"STATICALLY_SUPPORTED", "RUNTIME_READY"}
                    or hypothesis is None or hypothesis["target_id"] != target_id
                    or plan is None or plan["target_id"] != target_id
                    or plan["hypothesis_id"] != hypothesis_id
                    or plan["skill_id"] != "check-before-transform-dom-xss"
                    or row["hypothesis_id"] not in {None, hypothesis_id}
                    or (row["plan_id"] not in {None, plan_id} and row["run_id"] is not None)):
                raise ValueError("DOM candidate plan binding mismatch")
            connection.execute("""
                UPDATE dom_flow_candidates SET hypothesis_id=?,plan_id=?,updated_at=?
                WHERE target_id=? AND candidate_id=?
            """, (hypothesis_id, plan_id, datetime.now(timezone.utc).isoformat(),
                  target_id, candidate_id))

    def bind_run(self, target_id: str, candidate_id: str, run_id: str) -> None:
        with self.evidence._connection() as connection:
            candidate = connection.execute("""
                SELECT plan_id,run_id FROM dom_flow_candidates
                WHERE target_id=? AND candidate_id=? LIMIT 1
            """, (target_id, candidate_id)).fetchone()
            run = connection.execute("""
                SELECT plan_id,target_id FROM plan_runs WHERE run_id=? LIMIT 1
            """, (run_id,)).fetchone()
            if (candidate is None or not candidate["plan_id"] or
                    candidate["run_id"] not in {None, run_id} or run is None or
                    run["plan_id"] != candidate["plan_id"] or run["target_id"] != target_id):
                raise ValueError("DOM candidate run binding mismatch")
            connection.execute("""
                UPDATE dom_flow_candidates SET run_id=?,updated_at=?
                WHERE target_id=? AND candidate_id=?
            """, (run_id, datetime.now(timezone.utc).isoformat(), target_id, candidate_id))

    def bind_validation(self, target_id: str, candidate_id: str,
                        run_id: str, validation_id: str) -> None:
        if not _CANDIDATE_ID.fullmatch(candidate_id):
            raise ValueError("Invalid DOM candidate ID")
        with self.evidence._connection() as connection:
            row = connection.execute("""
                SELECT c.run_id,v.target_id AS validation_target,v.run_id AS validation_run
                FROM dom_flow_candidates c JOIN validations v ON v.validation_id=?
                WHERE c.target_id=? AND c.candidate_id=? LIMIT 1
            """, (validation_id, target_id, candidate_id)).fetchone()
            if (row is None or row["run_id"] != run_id or
                    row["validation_target"] != target_id or row["validation_run"] != run_id):
                raise ValueError("DOM validation chain mismatch")
            connection.execute("""
                UPDATE dom_flow_candidates SET validation_id=?,updated_at=?
                WHERE target_id=? AND candidate_id=?
            """, (validation_id, datetime.now(timezone.utc).isoformat(),
                  target_id, candidate_id))

    def list_candidates(self, target_id: str, *, limit: int = 20,
                        cursor: str | None = None) -> DOMCandidatePage:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Invalid DOM candidate page size")
        where, args = "", [target_id]
        if cursor is not None:
            match = re.fullmatch(r"(\d{1,3}):(DOM-[0-9a-f]{32})", cursor)
            if not match or int(match.group(1)) > 100:
                raise ValueError("Invalid DOM candidate cursor")
            score, candidate_id = int(match.group(1)), match.group(2)
            where = "AND (score<? OR (score=? AND candidate_id>?))"
            args.extend((score, score, candidate_id))
        with self.evidence._connection() as connection:
            rows = connection.execute(f"""
                SELECT * FROM dom_flow_candidates WHERE target_id=? {where}
                ORDER BY score DESC,candidate_id LIMIT ?
            """, (*args, limit + 1)).fetchall()
        items = tuple(_candidate_from_row(row) for row in rows[:limit])
        next_cursor = (f"{rows[limit-1]['score']}:{rows[limit-1]['candidate_id']}"
                       if len(rows) > limit else None)
        return DOMCandidatePage(items, next_cursor)

    def set_candidate_status(self, target_id: str, candidate_id: str,
                             status: DOMCandidateStatus, reason_code: str) -> DOMFlowCandidate:
        if status is DOMCandidateStatus.STATICALLY_SUPPORTED or not re.fullmatch(r"[A-Z0-9_]{3,64}", reason_code):
            raise ValueError("Invalid DOM candidate transition")
        now = datetime.now(timezone.utc).isoformat()
        with self.evidence._connection() as connection:
            old = connection.execute("SELECT status FROM dom_flow_candidates WHERE target_id=? AND candidate_id=?",
                                     (target_id, candidate_id)).fetchone()
            if old is None:
                raise ValueError("Unknown DOM candidate")
            if old["status"] != status.value:
                connection.execute("UPDATE dom_flow_candidates SET status=?,updated_at=? WHERE candidate_id=?",
                                   (status.value, now, candidate_id))
                connection.execute("""
                    INSERT INTO dom_candidate_events (candidate_id,old_status,new_status,reason_code,changed_at)
                    VALUES (?,?,?,?,?)
                """, (candidate_id, old["status"], status.value, reason_code, now))
        result = self.get_candidate(target_id, candidate_id)
        assert result is not None
        return result
