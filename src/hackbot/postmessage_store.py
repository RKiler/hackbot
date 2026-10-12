"""BugHunter-owned messaging metadata linked to current Phase 21 JS artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
import re
import uuid

from .domxss_store import DOMAssetRecord, DOMXSSStore
from .domxss_maps import MAX_SOURCE_MAP_BYTES, map_locations
from .domxss_static import MAX_ASSET_BYTES, SourceLocation
from .postmessage_static import (ANALYZER_VERSION, MessageAnalysis, MessageCandidateStatus,
                                 MessageProtocolCandidate, PostMessageStaticAnalyzer,
                                 RpcMethodInfo, TrustCheck)
from .store import EvidenceFactStore


_ID = re.compile(r"MSG-[0-9a-f]{32}\Z")


@dataclass(frozen=True, slots=True)
class MessageCandidatePage:
    items: tuple[MessageProtocolCandidate, ...]
    next_cursor: str | None


def _candidate(row) -> MessageProtocolCandidate:
    data = json.loads(row["candidate_json"])
    data["status"] = MessageCandidateStatus(row["status"])
    data.setdefault("transport_kind", "WINDOW")
    data["receiver_location"] = SourceLocation(**data["receiver_location"])
    for name in ("origin_checks", "source_checks"):
        data[name] = tuple(TrustCheck(**{**item, "location": SourceLocation(**item["location"])})
                           for item in data[name])
    for name in ("artifact_ids", "asset_hashes", "message_types", "reply_types",
                 "sender_contexts", "rpc_methods", "sensitive_operations",
                 "protocol_sequence", "evidence_ids", "payload_fields"):
        data[name] = tuple(data.get(name, ()))
    data["rpc_details"] = tuple(RpcMethodInfo(
        name=item["name"], argument_fields=tuple(item["argument_fields"]),
        result_shape=item["result_shape"], capability=item["capability"],
        authorization_assumptions=tuple(item["authorization_assumptions"]))
        for item in data.get("rpc_details", ()))
    return MessageProtocolCandidate(**data)


class PostMessageStore:
    def __init__(self, evidence: EvidenceFactStore, dom: DOMXSSStore) -> None:
        self.evidence, self.dom = evidence, dom

    def analyze_asset(self, target_id: str, artifact_id: str,
                      analyzer: PostMessageStaticAnalyzer, *, recent_change: bool = False
                      ) -> tuple[str, MessageAnalysis]:
        asset = self.dom.get_asset(target_id, artifact_id)
        if asset is None or asset.state not in {"CURRENT", "UNVERIFIED_CURRENT"}:
            raise ValueError("Current target JS artifact required")
        with self.evidence._connection() as db:
            prior = db.execute("""SELECT analysis_id,status FROM message_analysis_runs
                WHERE artifact_id=? AND analyzer_version=? LIMIT 1""",
                (artifact_id, ANALYZER_VERSION)).fetchone()
        if prior and prior["status"] != "PARSE_FAILED":
            return prior["analysis_id"], self.read_analysis(target_id, prior["analysis_id"])
        body = self.evidence.read_content(asset.evidence_id, allow_sensitive=True,
                                          max_bytes=MAX_ASSET_BYTES)
        analysis = analyzer.analyze(target_id=target_id, artifact_id=artifact_id,
                                    body=body, evidence_id=asset.evidence_id,
                                    recent_change=recent_change)
        if analysis.asset_sha256 != asset.artifact_sha256:
            raise ValueError("Messaging artifact changed during analysis")
        analysis_id = prior["analysis_id"] if prior else "MSGAN-" + uuid.uuid4().hex
        now = analysis.analyzed_at.isoformat()
        with self.evidence._connection() as db:
            if prior:
                db.execute("""UPDATE message_analysis_runs SET status=?,parse_errors=?,
                    handler_count=?,protocol_count=?,sender_count=?,channel_count=?,analyzed_at=?
                    WHERE analysis_id=? AND target_id=? AND status='PARSE_FAILED'""",
                    (analysis.status, analysis.parse_errors, analysis.handlers,
                     len(analysis.candidates), analysis.senders, analysis.channels,
                     now, analysis_id, target_id))
            else:
                db.execute("""INSERT INTO message_analysis_runs
                    (analysis_id,target_id,artifact_id,analyzer_version,status,parse_errors,
                     handler_count,protocol_count,sender_count,channel_count,analyzed_at)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (analysis_id, target_id, artifact_id, ANALYZER_VERSION, analysis.status,
                     analysis.parse_errors, analysis.handlers, len(analysis.candidates),
                     analysis.senders, analysis.channels, now))
            for item in analysis.candidates:
                existing = db.execute("""SELECT * FROM message_protocol_candidates
                    WHERE candidate_id=? LIMIT 1""", (item.candidate_id,)).fetchone()
                if existing is not None:
                    if existing["target_id"] != target_id:
                        raise ValueError("Cross-target messaging candidate collision")
                    old = _candidate(existing)
                    merged = replace(item,
                        artifact_ids=tuple(dict.fromkeys((*old.artifact_ids, artifact_id)))[:16],
                        asset_hashes=tuple(dict.fromkeys((*old.asset_hashes, asset.artifact_sha256)))[:16],
                        evidence_ids=tuple(dict.fromkeys((*old.evidence_ids, asset.evidence_id)))[:16],
                        route=old.route, source_map_sha256=old.source_map_sha256,
                        mapped_source=old.mapped_source, runtime_status=old.runtime_status,
                        status=old.status if old.status not in {
                            MessageCandidateStatus.STALE, MessageCandidateStatus.REJECTED}
                            else item.status,
                        priority=max(old.priority, item.priority))
                    db.execute("""UPDATE message_protocol_candidates SET candidate_json=?,
                        priority=?,status=?,updated_at=? WHERE candidate_id=?""",
                        (json.dumps(asdict(merged), sort_keys=True), merged.priority,
                         merged.status.value, now, item.candidate_id))
                else:
                    db.execute("""INSERT INTO message_protocol_candidates
                        (candidate_id,target_id,priority,status,candidate_json,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?)""",
                        (item.candidate_id, target_id, item.priority, item.status.value,
                         json.dumps(asdict(item), sort_keys=True), now, now))
                    db.execute("""INSERT INTO message_candidate_events
                        (candidate_id,old_status,new_status,reason_code,changed_at)
                        VALUES (?,?,?,?,?)""",
                        (item.candidate_id, None, item.status.value, "STATIC_ANALYSIS", now))
                db.execute("""INSERT OR IGNORE INTO message_candidate_assets
                    (candidate_id,artifact_id,analysis_id) VALUES (?,?,?)""",
                    (item.candidate_id, artifact_id, analysis_id))
                for direction, names in (("RECEIVE", item.message_types), ("REPLY", item.reply_types)):
                    for name in names:
                        db.execute("""INSERT OR IGNORE INTO message_type_index
                            (target_id,type_name,candidate_id,direction) VALUES (?,?,?,?)""",
                            (target_id, name, item.candidate_id, direction))
        return analysis_id, analysis

    def read_analysis(self, target_id: str, analysis_id: str) -> MessageAnalysis:
        with self.evidence._connection() as db:
            row = db.execute("""SELECT r.*,a.artifact_sha256 FROM message_analysis_runs r
                JOIN dom_js_artifacts a ON a.artifact_id=r.artifact_id
                WHERE r.target_id=? AND r.analysis_id=? AND a.target_id=? LIMIT 1""",
                (target_id, analysis_id, target_id)).fetchone()
            if row is None:
                raise ValueError("Unknown messaging analysis")
            items = db.execute("""SELECT c.* FROM message_protocol_candidates c
                JOIN message_candidate_assets a ON a.candidate_id=c.candidate_id
                WHERE a.analysis_id=? AND c.target_id=? ORDER BY c.priority DESC,c.candidate_id LIMIT 32""",
                (analysis_id, target_id)).fetchall()
        return MessageAnalysis(target_id, row["artifact_id"], row["artifact_sha256"],
                               row["analyzer_version"], datetime.fromisoformat(row["analyzed_at"]),
                               row["status"], row["handler_count"], row["sender_count"],
                               row["channel_count"],
                               tuple(_candidate(item) for item in items), row["parse_errors"])

    def record_trial(self, *, target_id: str, candidate_id: str, run_id: str,
                     evidence_id: str, variant: str, message_count: int,
                     port_count: int, rpc_calls: int, capability_observed: bool) -> None:
        if (not _ID.fullmatch(candidate_id) or not 0 <= message_count <= 3
                or not 0 <= port_count <= 1 or not 0 <= rpc_calls <= 1
                or type(capability_observed) is not bool):
            raise ValueError("Invalid messaging trial metadata")
        evidence = self.evidence.get_evidence(evidence_id)
        if (evidence is None or evidence.target_ref != target_id
                or evidence.evidence_type != "MESSAGE_PROOF"
                or evidence.provenance.record_id != candidate_id):
            raise ValueError("Messaging trial evidence is not target-bound")
        with self.evidence._connection() as db:
            run = db.execute("SELECT target_id FROM plan_runs WHERE run_id=?", (run_id,)).fetchone()
            if run is None or run["target_id"] != target_id:
                raise ValueError("Messaging trial run is not target-bound")
            db.execute("""INSERT INTO message_runtime_trials
                (evidence_id,target_id,candidate_id,run_id,variant,message_count,port_count,
                 rpc_calls,capability_observed,recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (evidence_id, target_id, candidate_id, run_id, variant,
                 message_count, port_count, rpc_calls, int(capability_observed),
                 datetime.now(timezone.utc).isoformat()))

    def metrics(self, target_id: str) -> dict[str, object]:
        with self.evidence._connection() as db:
            analyzed = db.execute("""SELECT coalesce(sum(handler_count),0),count(*),
                coalesce(sum(sender_count),0),coalesce(sum(channel_count),0)
                FROM message_analysis_runs WHERE target_id=?""", (target_id,)).fetchone()
            protocols = db.execute("""SELECT count(*),
                coalesce(sum(CASE WHEN json_extract(candidate_json,'$.port_accepted')=1
                    THEN 1 ELSE 0 END),0),
                coalesce(sum(json_array_length(candidate_json,'$.rpc_methods')),0)
                FROM message_protocol_candidates WHERE target_id=?""", (target_id,)).fetchone()
            trials = db.execute("""SELECT count(*),coalesce(sum(message_count),0),
                coalesce(sum(rpc_calls),0) FROM message_runtime_trials WHERE target_id=?""",
                (target_id,)).fetchone()
            validations = db.execute("""SELECT status,count(*) AS total FROM validations
                WHERE target_id=? AND skill_id='postmessage-trust-analysis'
                GROUP BY status""", (target_id,)).fetchall()
            candidate_status = db.execute("""SELECT status,count(*) AS total
                FROM message_protocol_candidates WHERE target_id=? GROUP BY status""",
                (target_id,)).fetchall()
        by_status = {row["status"]: row["total"] for row in candidate_status}
        by_validation = {row["status"]: row["total"] for row in validations}
        return {"target_id": target_id, "handlers": analyzed[0],
                "assets_analyzed": analyzed[1], "senders": analyzed[2],
                "message_channels": analyzed[3], "protocols": protocols[0],
                "message_port_candidates": protocols[1], "rpc_methods": protocols[2],
                "runtime_tests": trials[0], "messages_sent": trials[1],
                "rpc_calls": trials[2], "confirmed": by_validation.get("CONFIRMED", 0),
                "rejected": by_validation.get("REJECTED", 0),
                "manual_review": by_validation.get("NEEDS_MANUAL_REVIEW", 0),
                "static_needs_review": by_status.get("NEEDS_MANUAL_REVIEW", 0),
                "by_status": by_status}

    def get_candidate(self, target_id: str, candidate_id: str) -> MessageProtocolCandidate | None:
        if not _ID.fullmatch(candidate_id):
            raise ValueError("Invalid messaging candidate ID")
        with self.evidence._connection() as db:
            row = db.execute("""SELECT * FROM message_protocol_candidates
                WHERE target_id=? AND candidate_id=? LIMIT 1""", (target_id, candidate_id)).fetchone()
        return _candidate(row) if row else None

    def current_asset(self, target_id: str, candidate_id: str) -> DOMAssetRecord | None:
        if not _ID.fullmatch(candidate_id):
            raise ValueError("Invalid messaging candidate ID")
        with self.evidence._connection() as db:
            row = db.execute("""SELECT a.artifact_id FROM message_candidate_assets x
                JOIN message_protocol_candidates c ON c.candidate_id=x.candidate_id
                JOIN dom_js_artifacts a ON a.artifact_id=x.artifact_id
                JOIN message_analysis_runs r ON r.analysis_id=x.analysis_id
                WHERE c.target_id=? AND c.candidate_id=? AND a.target_id=?
                    AND r.target_id=? AND r.analyzer_version=?
                    AND a.state='CURRENT' AND a.recon_sha256=a.artifact_sha256
                ORDER BY a.retrieved_at DESC LIMIT 1""",
                (target_id, candidate_id, target_id, target_id, ANALYZER_VERSION)).fetchone()
        return self.dom.get_asset(target_id, row["artifact_id"]) if row else None

    def map_candidate(self, target_id: str, candidate_id: str, source_map) -> MessageProtocolCandidate:
        item = self.get_candidate(target_id, candidate_id)
        asset = self.current_asset(target_id, candidate_id)
        if (item is None or asset is None or source_map.target_id != target_id
                or source_map.js_artifact_id != asset.artifact_id):
            raise ValueError("Source map does not match current messaging artifact")
        body = self.evidence.artifacts.get_bytes(source_map.map_sha256,
                                                 max_bytes=MAX_SOURCE_MAP_BYTES)
        mapped = map_locations(body, (item.receiver_location,))[0]
        if mapped is None:
            raise ValueError("Messaging handler source could not be mapped")
        updated = replace(item, mapped_source=f"{mapped.source}:{mapped.line}:{mapped.column}",
                          source_map_sha256=source_map.map_sha256,
                          evidence_ids=tuple(dict.fromkeys(
                              (*item.evidence_ids, source_map.evidence_id)))[:16])
        with self.evidence._connection() as db:
            db.execute("""UPDATE message_protocol_candidates SET candidate_json=?,updated_at=?
                WHERE target_id=? AND candidate_id=?""",
                (json.dumps(asdict(updated), sort_keys=True), datetime.now(timezone.utc).isoformat(),
                 target_id, candidate_id))
        return updated

    def related_protocols(self, target_id: str, candidate_id: str) -> tuple[str, ...]:
        item = self.get_candidate(target_id, candidate_id)
        if item is None:
            raise ValueError("Unknown messaging candidate")
        with self.evidence._connection() as db:
            rows = db.execute("""SELECT DISTINCT i.candidate_id FROM message_type_index i
                WHERE i.target_id=? AND i.direction='RECEIVE' AND i.type_name IN (
                    SELECT type_name FROM message_type_index
                    WHERE target_id=? AND candidate_id=? AND direction='REPLY')
                AND i.candidate_id<>? ORDER BY i.candidate_id LIMIT 8""",
                (target_id, target_id, candidate_id, candidate_id)).fetchall()
        return tuple(row["candidate_id"] for row in rows)

    def dom_xss_handoffs(self, target_id: str, candidate_id: str) -> tuple[str, ...]:
        """Return connected Phase 21 message-source flows on the same current asset.

        This is a routing hint only; Phase 21's browser validator owns XSS proof.
        """
        item = self.get_candidate(target_id, candidate_id)
        asset = self.current_asset(target_id, candidate_id)
        if item is None or asset is None or "DOM_WRITE" not in item.sensitive_operations:
            return ()
        with self.evidence._connection() as db:
            rows = db.execute("""SELECT d.candidate_id FROM dom_flow_candidates d
                WHERE d.target_id=? AND d.artifact_id=?
                  AND json_extract(d.candidate_json,'$.sink_kind')='HTML_EXECUTION'
                  AND (json_extract(d.candidate_json,'$.source') IN
                      ('event.data','e.data','messageEvent.data')
                    OR json_extract(d.candidate_json,'$.source') LIKE 'event.data.%'
                    OR json_extract(d.candidate_json,'$.source') LIKE 'e.data.%'
                    OR json_extract(d.candidate_json,'$.source') LIKE 'messageEvent.data.%')
                ORDER BY d.score DESC,d.candidate_id LIMIT 8""",
                (target_id, asset.artifact_id)).fetchall()
        return tuple(row["candidate_id"] for row in rows)

    def dom_xss_field(self, target_id: str, candidate_id: str) -> str | None:
        """Select one current analyzer-linked message property, never caller input."""
        item = self.get_candidate(target_id, candidate_id)
        if item is None:
            return None
        reserved = {"type", "event", "action", "kind", "method", "__proto__",
                    "constructor", "prototype"}
        for flow_id in self.dom_xss_handoffs(target_id, candidate_id):
            flow = self.dom.get_candidate(target_id, flow_id)
            match = re.fullmatch(r"(?:event|e|messageEvent)\.data\.([A-Za-z_$][A-Za-z0-9_$]{0,63})",
                                 flow.source) if flow is not None else None
            if match and match.group(1) in item.payload_fields and match.group(1) not in reserved:
                return match.group(1)
        return None

    def links(self, target_id: str, candidate_id: str) -> dict[str, str | None] | None:
        if not _ID.fullmatch(candidate_id):
            raise ValueError("Invalid messaging candidate ID")
        with self.evidence._connection() as db:
            row = db.execute("""SELECT hypothesis_id,plan_id,run_id,validation_id
                FROM message_protocol_candidates WHERE target_id=? AND candidate_id=? LIMIT 1""",
                (target_id, candidate_id)).fetchone()
        return dict(row) if row else None

    def list_candidates(self, target_id: str, *, limit: int = 20,
                        cursor: str | None = None) -> MessageCandidatePage:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Invalid messaging candidate page size")
        where, args = "", [target_id]
        if cursor is not None:
            match = re.fullmatch(r"(\d{1,3}):(MSG-[0-9a-f]{32})", cursor)
            if not match or int(match.group(1)) > 100:
                raise ValueError("Invalid messaging candidate cursor")
            score, candidate_id = int(match.group(1)), match.group(2)
            where = "AND (priority<? OR (priority=? AND candidate_id>?))"
            args.extend((score, score, candidate_id))
        with self.evidence._connection() as db:
            rows = db.execute(f"""SELECT * FROM message_protocol_candidates WHERE target_id=? {where}
                ORDER BY priority DESC,candidate_id LIMIT ?""", (*args, limit + 1)).fetchall()
        items = tuple(_candidate(row) for row in rows[:limit])
        next_cursor = (f"{rows[limit-1]['priority']}:{rows[limit-1]['candidate_id']}"
                       if len(rows) > limit else None)
        return MessageCandidatePage(items, next_cursor)

    def bind_route(self, target_id: str, candidate_id: str, route: str,
                   evidence_id: str) -> MessageProtocolCandidate:
        item = self.get_candidate(target_id, candidate_id)
        asset = self.current_asset(target_id, candidate_id)
        evidence = self.evidence.get_evidence(evidence_id)
        if (item is None or asset is None or item.route not in {None, route}
                or evidence is None or evidence.target_ref != target_id):
            raise ValueError("Current messaging candidate and route evidence required")
        updated = replace(item, route=route,
                          evidence_ids=tuple(dict.fromkeys((*item.evidence_ids, evidence_id)))[:16])
        with self.evidence._connection() as db:
            db.execute("""UPDATE message_protocol_candidates SET candidate_json=?,updated_at=?
                WHERE target_id=? AND candidate_id=?""",
                (json.dumps(asdict(updated), sort_keys=True), datetime.now(timezone.utc).isoformat(),
                 target_id, candidate_id))
        return updated

    def bind_plan(self, target_id: str, candidate_id: str, hypothesis_id: str,
                  plan_id: str) -> None:
        if self.current_asset(target_id, candidate_id) is None:
            raise ValueError("Current messaging asset required")
        with self.evidence._connection() as db:
            row = db.execute("""SELECT c.hypothesis_id,c.plan_id,c.run_id,
                p.skill_id,p.target_id,p.hypothesis_id AS plan_hypothesis
                FROM message_protocol_candidates c JOIN skill_plans p ON p.plan_id=?
                WHERE c.target_id=? AND c.candidate_id=? LIMIT 1""",
                (plan_id, target_id, candidate_id)).fetchone()
            if (row is None or row["skill_id"] != "postmessage-trust-analysis"
                    or row["target_id"] != target_id or row["plan_hypothesis"] != hypothesis_id
                    or row["hypothesis_id"] not in {None, hypothesis_id}
                    or (row["plan_id"] not in {None, plan_id} and row["run_id"] is not None)):
                raise ValueError("Messaging plan binding mismatch")
            db.execute("""UPDATE message_protocol_candidates SET hypothesis_id=?,plan_id=?,updated_at=?
                WHERE target_id=? AND candidate_id=?""",
                (hypothesis_id, plan_id, datetime.now(timezone.utc).isoformat(),
                 target_id, candidate_id))

    def bind_run(self, target_id: str, candidate_id: str, run_id: str) -> None:
        with self.evidence._connection() as db:
            row = db.execute("""SELECT c.plan_id,c.run_id,r.plan_id AS run_plan,r.target_id AS run_target
                FROM message_protocol_candidates c JOIN plan_runs r ON r.run_id=?
                WHERE c.target_id=? AND c.candidate_id=? LIMIT 1""",
                (run_id, target_id, candidate_id)).fetchone()
            if (row is None or not row["plan_id"] or row["run_id"] not in {None, run_id}
                    or row["run_plan"] != row["plan_id"] or row["run_target"] != target_id):
                raise ValueError("Messaging run binding mismatch")
            db.execute("""UPDATE message_protocol_candidates SET run_id=?,updated_at=?
                WHERE target_id=? AND candidate_id=?""",
                (run_id, datetime.now(timezone.utc).isoformat(), target_id, candidate_id))

    def bind_validation(self, target_id: str, candidate_id: str,
                        run_id: str, validation_id: str) -> None:
        with self.evidence._connection() as db:
            row = db.execute("""SELECT c.run_id,v.target_id AS validation_target,
                v.run_id AS validation_run FROM message_protocol_candidates c
                JOIN validations v ON v.validation_id=?
                WHERE c.target_id=? AND c.candidate_id=? LIMIT 1""",
                (validation_id, target_id, candidate_id)).fetchone()
            if (row is None or row["run_id"] != run_id or row["validation_target"] != target_id
                    or row["validation_run"] != run_id):
                raise ValueError("Messaging validation chain mismatch")
            db.execute("""UPDATE message_protocol_candidates SET validation_id=?,updated_at=?
                WHERE target_id=? AND candidate_id=?""",
                (validation_id, datetime.now(timezone.utc).isoformat(), target_id, candidate_id))

    def set_status(self, target_id: str, candidate_id: str,
                   status: MessageCandidateStatus, reason_code: str) -> MessageProtocolCandidate:
        if not re.fullmatch(r"[A-Z0-9_]{3,64}", reason_code):
            raise ValueError("Invalid messaging status reason")
        item = self.get_candidate(target_id, candidate_id)
        if item is None:
            raise ValueError("Unknown messaging candidate")
        updated = replace(item, status=status, runtime_status=reason_code)
        now = datetime.now(timezone.utc).isoformat()
        with self.evidence._connection() as db:
            db.execute("""UPDATE message_protocol_candidates SET status=?,candidate_json=?,updated_at=?
                WHERE target_id=? AND candidate_id=?""",
                (status.value, json.dumps(asdict(updated), sort_keys=True), now,
                 target_id, candidate_id))
            if item.status != status:
                db.execute("""INSERT INTO message_candidate_events
                    (candidate_id,old_status,new_status,reason_code,changed_at)
                    VALUES (?,?,?,?,?)""",
                    (candidate_id, item.status.value, status.value, reason_code, now))
        return updated
