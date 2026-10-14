"""Bounded metadata context for one explicit cross-specialist planner run."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .behaviour import BehaviourStore
from .bootstrap_store import BootstrapStore
from .browser import BrowserSessionManager, BrowserStatus
from .domain import ObservationState
from .evidence import FactStatus
from .hypotheses import HypothesisStore
from .identity import MembershipStatus
from .identity_registry import IdentityRegistry
from .planner_models import PlannerLimits
from .recon import ReconRepository
from .recon_postgres import ReconQueryError
from .research import ResearchStore
from .test_objects import ObjectRegistry, ObjectState
from .target_package import TargetPackage
from .traffic import TrafficStore
from .validation_store import ValidationStore


_FACT_PRIORITY = {
    "created_by": 5, "resource_tenant": 5, "owned_by": 5,
    "belongs_to": 4, "member_of": 4, "resolves_to": 4,
    "data_classification": 4, "graphql_operation": 3,
}


@dataclass(frozen=True, slots=True)
class PlannerContext:
    target_id: str
    package_id: str
    profile_id: str | None
    behaviour_run_id: str | None
    recon_status: str
    identity_ids: tuple[str, ...]
    verified_identity_ids: tuple[str, ...]
    tenant_ids: tuple[str, ...]
    ready_object_ids: tuple[str, ...]
    recent_exchange_ids: tuple[str, ...]
    recent_fact_ids: tuple[str, ...]
    research_brief_ids: tuple[str, ...]
    confirmed_hypothesis_ids: tuple[str, ...]
    coverage: dict[str, object]
    readiness: dict[str, object]
    snapshot_hash: str

    def audit_refs(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        return (
            ("TARGET_PROFILE", (self.profile_id,) if self.profile_id else ()),
            ("BEHAVIOUR", (self.behaviour_run_id,) if self.behaviour_run_id else ()),
            ("TRAFFIC", self.recent_exchange_ids),
            ("FACT", self.recent_fact_ids),
            ("RESEARCH", self.research_brief_ids),
        )

    def public_dict(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id, "behaviour_run_id": self.behaviour_run_id,
            "recon_status": self.recon_status, "identity_count": len(self.identity_ids),
            "verified_identity_count": len(self.verified_identity_ids),
            "tenant_count": len(self.tenant_ids), "ready_object_count": len(self.ready_object_ids),
            "recent_traffic_count": len(self.recent_exchange_ids),
            "fact_count": len(self.recent_fact_ids), "research_brief_count": len(self.research_brief_ids),
            "confirmed_hypothesis_count": len(self.confirmed_hypothesis_ids),
            "coverage": self.coverage, "readiness": self.readiness,
            "snapshot_hash": self.snapshot_hash,
        }


class PlannerContextBuilder:
    """Reads IDs and safe summaries only; no Evidence body or raw recon corpus."""

    def __init__(self, *, hypotheses: HypothesisStore, behaviour: BehaviourStore,
                 bootstrap: BootstrapStore, identities: IdentityRegistry,
                 browser: BrowserSessionManager, objects: ObjectRegistry,
                 traffic: TrafficStore, research: ResearchStore,
                 validations: ValidationStore,
                 recon: ReconRepository | None = None) -> None:
        self.hypotheses, self.behaviour, self.bootstrap = hypotheses, behaviour, bootstrap
        self.identities, self.browser, self.objects = identities, browser, objects
        self.traffic, self.research, self.validations = traffic, research, validations
        self.recon = recon

    def build(self, package: TargetPackage, limits: PlannerLimits) -> PlannerContext:
        target_id = package.target.id
        profile_record = self.hypotheses.latest_profile_record(target_id)
        profile = profile_record[1] if profile_record else None
        learned = self.behaviour.profile(target_id)
        identity_page = self.identities.list_identities(target_id, limit=12)
        identity_ids = tuple(item.id for item in identity_page.items)
        sessions = self.browser.list_sessions_for_target(target_id, limit=20)
        verified = tuple(dict.fromkeys(
            item.identity_id for item in sessions.items
            if item.identity_id and item.status is BrowserStatus.VALID
            and item.identity_id in identity_ids))[:12]
        tenant_ids: list[str] = []
        for identity_id in verified[:8]:
            for membership in self.identities.list_memberships(identity_id, limit=8).items:
                if (membership.status is MembershipStatus.ACTIVE and
                        membership.observation_state is ObservationState.OBSERVED and
                        membership.tenant_id not in tenant_ids):
                    tenant_ids.append(membership.tenant_id)
        objects = self.objects.list_for_target(target_id, limit=30, state=ObjectState.READY)
        ready = tuple(item.id for item in objects.items if item.disposable and item.verified_at)[:20]
        exchanges = self.traffic.list_exchanges_for_target(target_id, limit=24)
        traffic_ids = tuple(item.id for item in exchanges.items if item.package_id == package.id)[:20]
        facts = self.hypotheses.evidence.list_facts_for_target(target_id, limit=48)
        useful_facts = (item for item in facts.items
                        if item.status is FactStatus.ACTIVE and item.confidence >= 0.8
                        and item.evidence_ids)
        ranked_facts = sorted(useful_facts, key=lambda item: (
            -_FACT_PRIORITY.get(item.predicate, 0), -item.confidence,
            -item.observed_at.timestamp(), item.fact_id))
        fact_ids = tuple(item.fact_id for item in ranked_facts[:16])
        open_gaps = self.research.gaps(target_id, limit=12)
        gap_refs = {item.gap_ref for item in open_gaps}
        research = self.research.list(target_id, limit=24).get("items", [])
        brief_ids = tuple(item["brief_id"] for item in research
                          if item.get("brief_id") and item.get("freshness") == "FRESH"
                          and item.get("gap_ref") in gap_refs)[:8]
        findings = self.validations.list_findings(target_id, limit=20).get("items", [])
        confirmed_hypotheses = tuple(dict.fromkeys(
            item["hypothesis_id"] for item in findings if item.get("hypothesis_id")))[:20]
        discovery = self.bootstrap.discovery_state(target_id)
        recon_domain_id = None
        latest_snapshot_id = None
        if self.recon is not None:
            try:
                recon_target = self.recon.resolve_target(package.primary_domain)
                if recon_target is not None:
                    recon_domain_id = recon_target.domain_id
                    snapshots = self.recon.list_scan_snapshots(recon_target.domain_id, limit=2)
                    latest_snapshot_id = snapshots.items[0].snapshot_id if snapshots.items else None
            except ReconQueryError:
                pass
        recon_status = (str(discovery["state"]) if discovery else
                        profile.recon_status if profile else "UNKNOWN")
        if latest_snapshot_id is not None:
            recon_status = "RECON_BACKED"
        coverage = {
            "profile": bool(profile), "behaviour": learned.coverage.get("state", "NONE") if learned else "NONE",
            "recon": recon_status, "traffic_sampled": len(traffic_ids),
            "recon_domain_id": recon_domain_id, "latest_snapshot_id": latest_snapshot_id,
            "identity_sample_truncated": identity_page.next_cursor is not None,
            "object_sample_truncated": objects.next_cursor is not None,
            "traffic_sample_truncated": exchanges.next_cursor is not None,
        }
        readiness = {
            "scope_ready": package.status.value == "TRACKED",
            "identity_coverage": "MULTI_TENANT" if len(tenant_ids) >= 2 and len(verified) >= 2
                else "OWNED_IDENTITY" if verified else "LOGIN_NEEDED" if identity_ids else "NONE",
            "behaviour_coverage": coverage["behaviour"],
            "traffic_coverage": "PRESENT" if traffic_ids else "NONE",
            "object_ownership": "VERIFIED" if ready else "UNKNOWN",
            "specialist_coverage": "PARTIAL" if profile or learned else "NONE",
            "research_gaps": len(open_gaps),
        }
        recommendations = []
        if not profile:
            recommendations.append("BOOTSTRAP_TARGET_PROFILE")
        if not verified:
            recommendations.append("VERIFY_OWNED_SESSION" if identity_ids
                                   else "REGISTER_OWNED_IDENTITY_IF_NEEDED")
        if learned is None or learned.coverage.get("state") == "NONE":
            recommendations.append("LEARN_NORMAL_BEHAVIOUR")
        if not traffic_ids:
            recommendations.append("CAPTURE_NORMAL_TRAFFIC")
        if not ready:
            recommendations.append("ESTABLISH_DISPOSABLE_FIXTURE")
        readiness["recommendations"] = recommendations
        packed = [package.id, str(package.version), package.updated_at.isoformat(),
                  profile.generated_at.isoformat() if profile else "", learned.run_id if learned else "",
                  sorted(verified), sorted(ready), traffic_ids[:8], fact_ids[:8], brief_ids,
                  confirmed_hypotheses, readiness]
        digest = hashlib.sha256(json.dumps(packed, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return PlannerContext(target_id, package.id,
                              profile_record[0] if profile_record else None,
                              learned.run_id if learned else None, recon_status,
                              identity_ids, verified, tuple(tenant_ids[:12]), ready,
                              traffic_ids, fact_ids, brief_ids, confirmed_hypotheses,
                              coverage, readiness, digest)
