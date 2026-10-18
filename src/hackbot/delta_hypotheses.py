"""Turn a current delta into bounded, evidence-backed passive hypotheses."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json

from .delta_models import DeltaStatus
from .delta_store import DeltaStore
from .evidence import EvidenceProvenance, EvidenceType, RedactionStatus, Sensitivity
from .hypotheses import Hypothesis, HypothesisSource, HypothesisStatus, HypothesisStore
from .planner_models import Specialist
from .target_package import TargetPackage


_CATEGORIES = {
    Specialist.AUTHORIZATION: "ROLE_AUTHORIZATION",
    Specialist.API_GRAPHQL: "GRAPHQL_AUTHORIZATION",
    Specialist.DOM_XSS: "DOM_XSS",
    Specialist.POSTMESSAGE: "POSTMESSAGE",
    Specialist.EXPOSURE: "EXPOSURE",
}
_BOUNDARIES = {
    Specialist.AUTHORIZATION: "ROLE",
    Specialist.API_GRAPHQL: "USER",
    Specialist.DOM_XSS: "CLIENT_SERVER_TRUST",
    Specialist.POSTMESSAGE: "CROSS_ORIGIN",
    Specialist.EXPOSURE: "AUTHENTICATED",
}
_MISSING = {
    Specialist.AUTHORIZATION: ("multiple owned identities", "safe request template"),
    Specialist.API_GRAPHQL: ("known GraphQL operation", "safe request template"),
    Specialist.DOM_XSS: ("attacker-controlled source", "reachable route"),
    Specialist.POSTMESSAGE: ("reachable message flow", "controlled foreign origin"),
    Specialist.EXPOSURE: ("expected access model", "safe request template"),
}


class DeltaHypothesisBuilder:
    def __init__(self, deltas: DeltaStore, hypotheses: HypothesisStore) -> None:
        self.deltas = deltas
        self.hypotheses = hypotheses

    def materialize(self, package: TargetPackage, delta_id: str,
                    *, specialists: tuple[Specialist, ...] | None = None) -> tuple[str, ...]:
        target_id = package.target.id
        candidate = self.deltas.get_candidate(target_id, delta_id)
        if candidate is None:
            raise LookupError("Delta candidate not found")
        if candidate["status"] not in {DeltaStatus.CLASSIFIED.value,
                                       DeltaStatus.CAMPAIGN_READY.value}:
            return ()
        selected = tuple(Specialist(item) for item in candidate["specialist_hints"])
        if specialists is not None:
            selected = tuple(item for item in selected if item in specialists)
        if not selected:
            return ()
        evidence_id = self.ensure_evidence(package, delta_id, candidate=candidate)
        now = datetime.now(timezone.utc)
        result = []
        for specialist in selected:
            key = hashlib.sha256("\x1f".join((target_id, str(candidate["location_hash"]),
                str(candidate["new_fingerprint"]), specialist.value)).encode()).hexdigest()[:32]
            category = _CATEGORIES[specialist]
            missing = _MISSING[specialist]
            item = Hypothesis(
                "HYP-" + key, target_id, key, category,
                f"A new {specialist.value.lower().replace('_', ' ')} surface may cross a trust boundary",
                HypothesisStatus.NEW, min(100, int(candidate["relevance"])), 0.35,
                "UNVERIFIED", "SAFE_READ", str(candidate["display_location"]),
                _BOUNDARIES[specialist],
                "A current in-scope recon change is a lead, not proof of a defect",
                ("current TargetPackage scope",), missing,
                "Obtain a genuine current request or browser flow, then compare owned controls",
                "Controlled differential demonstrates unauthorized impact",
                "Controlled differential enforces the intended boundary",
                (), HypothesisSource.DETERMINISTIC, "DELTA_WATCHER",
                (str(evidence_id),), (), now, now)
            saved = self.hypotheses.upsert(item)
            self.deltas.link_hypothesis(target_id, delta_id, saved.id)
            result.append(saved.id)
        return tuple(result)

    def ensure_evidence(self, package: TargetPackage, delta_id: str,
                        *, candidate: dict[str, object] | None = None) -> str:
        target_id = package.target.id
        candidate = candidate or self.deltas.get_candidate(target_id, delta_id)
        if candidate is None:
            raise LookupError("Delta candidate not found")
        evidence_id = candidate["evidence_id"]
        if evidence_id is None:
            source_ref = str(candidate["source_ref"])
            observed = datetime.fromisoformat(str(candidate["observed_at"]))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            content = json.dumps({
                "delta_id": delta_id,
                "delta_type": candidate["delta_type"],
                "source_ref": source_ref,
                "location_hash": candidate["location_hash"],
                "old_fingerprint": candidate["old_fingerprint"],
                "new_fingerprint": candidate["new_fingerprint"],
                "signal_tags": candidate["signal_tags"],
                "classification": "PASSIVE_LEAD_NOT_VULNERABILITY",
            }, sort_keys=True, separators=(",", ":")).encode("ascii")
            evidence = self.deltas.store.create_evidence(
                EvidenceType.RECON_RECORD, content, source="DELTA_WATCHER",
                target_ref=target_id, observed_at=observed,
                provenance=EvidenceProvenance(
                    system=str(candidate["source_kind"]), entity="delta_candidate",
                    record_id=source_ref, observed_at=observed,
                    qualification="bounded metadata; no vulnerability claim"),
                sensitivity=Sensitivity.INTERNAL,
                redaction_status=RedactionStatus.REDACTED)
            self.deltas.link_evidence(target_id, delta_id, evidence.evidence_id)
            evidence_id = evidence.evidence_id
        return str(evidence_id)
