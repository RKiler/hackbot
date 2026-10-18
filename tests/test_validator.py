"""Phase 17 deterministic validation against policy-gated loopback runs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from dataclasses import replace
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

from hackbot.artifacts import ArtifactStore
from hackbot.auth import AuthContextManager
from hackbot.browser import IdentityObservation, IdentityVerificationRule
from hackbot.config import SecretBindingConfig, SecretSettings
from hackbot.campaign_models import CampaignLimits, CampaignStatus, CampaignWorkKind
from hackbot.campaign_store import CampaignStore
from hackbot.delta_models import DeltaFocus, DeltaSignal, DeltaSource, DeltaType
from hackbot.delta_store import DeltaStore
from hackbot.domain import ObservationState, Principal, Role, Tenant
from hackbot.evidence import EvidenceProvenance, EvidenceType, Retention, Sensitivity
from hackbot.finding_workflow import FindingWorkflow
from hackbot.hypotheses import HypothesisStore
from hackbot.planner import CrossSpecialistPlanner, _Signal, _candidate_state
from hackbot.planner_models import (CandidateStatus, PlannerCandidate, PlannerLimits,
                                    PlannerMode, PlannerStatus, PlannerTaskStatus,
                                    PlannerTaskType, Specialist)
from hackbot.planner_runner import PlannerRunner
from hackbot.planner_store import PlannerStore
from hackbot.notification_store import NotificationStore
from hackbot.permit_store import PolicyPermitStore
from hackbot.policy import policy_version
from hackbot.identity import IdentityStatus, MembershipStatus
from hackbot.response_compare import ResponseComparator
from hackbot.recon import Page
from hackbot.reports import ReportStore
from hackbot.secrets import RoutedSecretProvider
from hackbot.validation_store import ValidationStatus, ValidationStore
from hackbot.validator import DeterministicValidatorEngine
from hackbot.service import create_app
from tests import test_orchestrator as orchestrator_fixture
from tests.schema_utils import drop_phase30_schema


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class _ComposedFixturePermitStore(PolicyPermitStore):
    def issue(self, action, decision, request_fingerprint, *,
              now: datetime | None = None, ttl_seconds: int = 120):
        return super().issue(action, decision, request_fingerprint,
                             now=now, ttl_seconds=ttl_seconds)


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self.work = orchestrator_fixture.OrchestratorTests(
            methodName="test_scope_and_policy_changed_send_zero_requests")
        self.work.setUp()
        self.addCleanup(self.work.doCleanups)
        self.fx = self.work.fixture
        self.fx.permits = _ComposedFixturePermitStore(self.fx.store)
        self.fx.executor.permits = self.fx.permits
        # Composed local requests need headroom under shared VPS contention.
        self.fx.executor.settings = replace(
            self.fx.executor.settings,
            connect_timeout_seconds=15.0,
            read_timeout_seconds=15.0,
            overall_timeout_seconds=120.0,
        )
        self.target = self.fx.package.target.id
        hypothesis = HypothesisStore(self.fx.store).add_manual(
            self.target, "AUTHORIZATION", "Controlled fixture authorization boundary",
            "Compare controlled owner and foreign actor")
        self.work.hypotheses.id = hypothesis.id
        self.work.context.hypothesis_id = hypothesis.id
        self.results = ValidationStore(self.fx.store)
        self.validator = DeterministicValidatorEngine(
            runs=self.work.runs, traffic=self.fx.traffic, evidence=self.fx.store,
            identities=self.fx.registry, hypotheses=HypothesisStore(self.fx.store),
            results=self.results)
        aliases = ("tenant_a_owner", "tenant_a_member", "tenant_b_admin")
        bindings = tuple(SecretBindingConfig(
            f"ref:{alias}", f"env:HACKBOT_SECRET_{alias.upper()}", "COOKIE") for alias in aliases)
        provider = RoutedSecretProvider(SecretSettings(bindings=bindings), {
            f"HACKBOT_SECRET_{alias.upper()}": f"fixture_actor={alias}" for alias in aliases})
        self.fx.auth = AuthContextManager(self.fx.registry, provider)
        self.fx.browser.auth = self.fx.auth
        self.fx.executor.auth = self.fx.auth
        self.fx.executor.secrets = provider
        self.tenants = {
            label: self.fx.registry.register_tenant(Tenant(
                target_id=self.target, label=label, kind="ORG", external_id=label))
            for label in ("tenant-a", "tenant-b")}
        self.roles = {
            label: self.fx.registry.register_role(Role(target_id=self.target, name=label))
            for label in ("admin", "member")}
        self.actors = {}
        for alias in aliases:
            identity = self.fx.registry.register_identity(
                self.target, alias, status=IdentityStatus.ACTIVE, secret_ref=f"ref:{alias}")
            self.fx.auth.prepare(self.target, identity.id)
            session = self.fx.browser.create(self.target, identity.id)
            self.fx.browser.start(session.id)
            self.fx.browser.login_complete(session.id)
            tenant_label = "tenant-b" if alias.startswith("tenant_b") else "tenant-a"
            self.fx.driver.observations[session.id] = IdentityObservation(
                user_id=alias, tenant_id=tenant_label)
            rule = IdentityVerificationRule(self.target, identity.id, "[data-user]", None,
                                            "[data-tenant]", alias, None, tenant_label)
            self.fx.browser.verify(session.id, rule)
            tenant = self.tenants[tenant_label]
            role = self.roles["member" if alias.endswith("member") else "admin"]
            evidence = self._evidence(f"membership:{alias}:{tenant_label}")
            fact = self.fx.store.create_fact(identity.id, "member_of", tenant.id, confidence=1,
                                             evidence_ids=(evidence,), source="FIXTURE",
                                             target_ref=self.target)
            self.fx.registry.add_membership(
                identity.id, tenant.id, status=MembershipStatus.ACTIVE, role_ids=(role.id,),
                observation_state=ObservationState.OBSERVED, evidence_ids=(evidence,), fact_id=fact.fact_id)
            self.actors[alias] = (identity, session)
        self.work.context.flags.update({"verified_sessions", "multiple_tenants", "known_ownership"})
        self.work.context.identities = tuple(
            {"id": identity.id, "verified_session_id": session.id}
            for identity, session in self.actors.values())

    def _evidence(self, content: str) -> str:
        return self.fx.store.create_evidence(
            "TEST_ASSERTION", content.encode(), source="FIXTURE",
            provenance=EvidenceProvenance(system="FIXTURE"), target_ref=self.target,
            sensitivity=Sensitivity.INTERNAL).evidence_id

    def fact(self, object_hash: str, predicate: str, value: str) -> None:
        reference = self._evidence(f"{predicate}:{value}")
        self.fx.store.create_fact(object_hash, predicate, value, confidence=1,
                                  evidence_ids=(reference,), source="FIXTURE", target_ref=self.target)

    def protected(self, *, policy="TENANT_ONLY", visibility="PRIVATE", object_name="object-a") -> str:
        object_hash = digest(object_name)
        self.fact(object_hash, "resource_visibility", visibility)
        self.fact(object_hash, "access_policy", policy)
        self.fact(object_hash, "resource_tenant", self.tenants["tenant-a"].id)
        self.fact(object_hash, "resource_tenant_marker", digest("tenant-a"))
        return object_hash

    def action(self, path: str, alias: str | None, role: str, object_hash: str,
               *, vulnerability="CROSS_TENANT", control_kind=None, operation=None):
        identity, session = self.actors[alias] if alias else (None, None)
        return self.work.action(
            path, actor="AUTHENTICATED" if alias else "ANONYMOUS",
            identity=identity.id if identity else None, session=session.id if session else None,
            role=role, vulnerability=vulnerability, object_ref_hash=object_hash,
            object_type="fixture_record", control_kind=control_kind, operation=operation)

    def run_fixture(self, skill: str, actions: list[tuple[dict, dict]]) -> str:
        plan = self.work.plan(actions, skill_name=skill,
                              workflow=[{"type": "EXECUTE_REQUEST"} for _ in actions] +
                                       [{"type": "COMPARE_RESPONSE"}],
                              comparisons=[{"control_slot": 0, "boundary_slot": 1}],
                              budget=len(actions), category="authorization")
        run_id = self.work.start(plan)
        for _ in range(len(actions) + 4):
            result = self.work.advance(run_id)
            if result["run"]["status"] == "COMPLETED":
                return run_id
            if result["run"]["status"] in {"BLOCKED", "REJECTED", "FAILED", "BUDGET_EXHAUSTED"}:
                reason = result["timeline"][-1]["reason_code"] if result["timeline"] else "UNKNOWN"
                step = result["steps"][len(result["steps"]) - 1]
                for item in reversed(result["steps"]):
                    if item["status"] == "FAILED":
                        step = item
                        break
                error_class = step["result"]["error_class"] if step["result"] else None
                self.fail(f"fixture run failed: {result['run']['status']} ({reason}; "
                          f"{step['safe_reason']}; {error_class})")
        self.fail("fixture run did not complete")

    def auth_run(self, *, skill="cross-tenant-object-authorization", boundary_alias="tenant_b_admin",
                 boundary_path="/validated/object-a", control_path="/validated/object-a",
                 visibility="PRIVATE", object_name="object-a") -> str:
        object_hash = self.protected(visibility=visibility, object_name=object_name,
                                     policy="OWNER_ONLY" if skill == "horizontal-object-authorization" else
                                     "ROLE_RESTRICTED" if skill in {"vertical-role-authorization",
                                                                    "hidden-function-authorization"} else "TENANT_ONLY")
        if skill == "horizontal-object-authorization":
            self._principals()
            self.fact(object_hash, "resource_owner", self.principals["tenant_a_owner"].id)
        if skill in {"vertical-role-authorization", "hidden-function-authorization"}:
            self.fact(object_hash, "required_role", self.roles["admin"].id)
        actions = [self.action(control_path, "tenant_a_owner", "CONTROL", object_hash),
                   self.action(boundary_path, boundary_alias, "BOUNDARY", object_hash),
                   self.action(boundary_path, boundary_alias, "BOUNDARY", object_hash),
                   self.action("/validated/missing", boundary_alias, "OTHER", digest("missing"),
                               control_kind="INVALID_OBJECT")]
        return self.run_fixture(skill, actions)

    def _principals(self):
        self.principals = {}
        for alias in ("tenant_a_owner", "tenant_a_member"):
            identity, _ = self.actors[alias]
            principal = self.fx.registry.register_principal(
                Principal(target_id=self.target, label=alias))
            reference = self._evidence(f"principal:{alias}")
            fact = self.fx.store.create_fact(identity.id, "resolves_to", principal.id,
                                             confidence=1, evidence_ids=(reference,),
                                             source="FIXTURE", target_ref=self.target)
            self.fx.registry.link_principal(identity.id, principal.id,
                                            observation_state=ObservationState.OBSERVED,
                                            evidence_ids=(reference,), fact_id=fact.fact_id)
            self.principals[alias] = principal

    def test_cross_tenant_confirmation_audit_and_duplicate(self):
        run_id = self.auth_run()
        sent_before = len(self.fx.server.received)
        with patch("requests.sessions.Session.send", side_effect=AssertionError("validator sent traffic")):
            result, finding = self.validator.validate_run(run_id, self.target)
            again, same = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.reproduction_count, 2)
        self.assertEqual(again.id, result.id)
        self.assertEqual(same.id, finding.id)
        self.assertEqual(len(self.fx.server.received), sent_before)
        self.assertTrue(finding.evidence_ids)
        for evidence_id in finding.evidence_ids:
            policy = self.fx.store.get_evidence(evidence_id).retention
            self.assertTrue(policy.retain)
            self.assertTrue(policy.pinned)
            self.assertTrue(policy.finding_related)
            self.assertIsNone(policy.expires_at)
            with self.assertRaises(ValueError):
                self.fx.store.set_retention(
                    evidence_id, Retention(retain=False), actor="FIXTURE",
                    reason="must_not_release_confirmed_evidence")
            with self.fx.store._connection() as db:
                with self.assertRaises(sqlite3.IntegrityError):
                    db.execute(
                        "INSERT INTO evidence_policy_events "
                        "(evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason) "
                        "VALUES (?,0,NULL,0,0,datetime('now'),'FIXTURE','direct_release')",
                        (evidence_id,))
        with self.fx.store._connection() as db:
            chain = db.execute(
                "SELECT f.finding_id,v.validation_id,r.run_id,p.plan_id,h.hypothesis_id,"
                "p.skill_id,a.action_id,d.decision_id,pm.permit_id,e.exchange_id "
                "FROM findings f JOIN validations v ON v.validation_id=f.validation_id "
                "JOIN plan_runs r ON r.run_id=v.run_id JOIN skill_plans p ON p.plan_id=r.plan_id "
                "JOIN hypotheses h ON h.hypothesis_id=v.hypothesis_id "
                "JOIN plan_run_steps s ON s.run_id=r.run_id AND s.role='BOUNDARY' "
                "JOIN policy_actions a ON a.action_id=s.action_id "
                "JOIN policy_decisions d ON d.decision_id=s.decision_id "
                "JOIN executor_permits pm ON pm.permit_id=s.permit_id "
                "JOIN executor_events ev ON ev.permit_id=pm.permit_id "
                "JOIN traffic_exchanges e ON e.exchange_id=ev.exchange_id "
                "WHERE f.finding_id=? AND ev.event_type='REQUEST_SENT' LIMIT 1",
                (finding.id,)).fetchone()
        self.assertIsNotNone(chain)
        self.assertEqual(chain["run_id"], run_id)
        second_run = self.auth_run()
        duplicate, original = self.validator.validate_run(second_run, self.target)
        self.assertEqual(duplicate.status, ValidationStatus.DUPLICATE_CANDIDATE)
        self.assertEqual(original.id, finding.id)
        for evidence_id in duplicate.supporting_evidence_ids:
            self.assertTrue(self.fx.store.get_evidence(evidence_id).retention.pinned)
        self.assertEqual(self.results.stats(self.target)["findings"], 1)
        ledger = PlannerStore(self.fx.store)
        run = ledger.create(self.fx.package, PlannerMode.BOUNDED_AUTONOMOUS,
                            PlannerLimits(), policy_version(self.fx.package))
        ledger.transition(self.target, run.id, PlannerStatus.LOADING_CONTEXT,
                          "CONTEXT_STARTED")
        candidate = PlannerCandidate(
            "PLCAND-" + "e" * 32, run.id, self.target, "HYPOTHESIS",
            self.work.hypotheses.id, self.work.hypotheses.id,
            Specialist.AUTHORIZATION, "CROSS_TENANT", digest("duplicate-root"),
            digest("duplicate-surface"), 85, 70, 85, 5, 0, 0,
            "LOW", 80, "CURRENT", status=CandidateStatus.SELECTED)
        run = ledger.save_portfolio(run, (candidate,), {}, digest("duplicate-state"))
        second_child = self.work.runs.get(second_run, self.target)
        candidate = ledger.update_candidate(
            self.target, run.id, candidate.id, status=CandidateStatus.RUNNING,
            hypothesis_id=self.work.hypotheses.id, plan_id=second_child.plan_id,
            plan_run_id=second_run)
        task = ledger.add_task(run, candidate, PlannerTaskType.VALIDATE_RUN)
        claimed = ledger.claim_task(self.target, run.id, task.id)
        runner = PlannerRunner(
            planner=None, store=ledger, hypotheses=None, contexts=None, router=None,
            skill_planner=None, authorization=None, api=None, dom=None, messages=None,
            exposure=None, research=None, objects=None, object_factory=None,
            browser=None, orchestrator=SimpleNamespace(runs=self.work.runs),
            validator=self.validator)
        runner._validate(run, claimed, candidate)
        disposition = ledger.candidate(self.target, run.id, candidate.id)
        self.assertEqual(disposition.status, CandidateStatus.DUPLICATE)
        self.assertEqual(disposition.validation_id, duplicate.id)
        self.assertIsNone(disposition.finding_id)
        self.assertEqual(ledger.get(self.target, run.id).manual_reviews, 0)
        self.assertEqual(ledger.get(self.target, run.id).findings, 0)
        self.assertEqual(ledger.branch_memory(self.target, candidate.root_cause_key,
                                              run.context_hash)[0]["outcome"], "DUPLICATE")

        held_id = finding.evidence_ids[0]
        with self.fx.store._connection() as db:
            drop_phase30_schema(db)
            db.execute(
                "INSERT INTO evidence_policy_events "
                "(evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason) "
                "VALUES (?,0,NULL,0,0,datetime('now'),'FIXTURE','legacy_unpinned')",
                (held_id,))
            db.execute("PRAGMA user_version=37")
            self.assertEqual(db.execute(
                "SELECT pinned FROM evidence_policy_events WHERE evidence_id=? "
                "ORDER BY event_id DESC LIMIT 1", (held_id,)).fetchone()[0], 0)
        self.fx.store.initialize(allow_existing_migration=True)
        self.assertTrue(self.fx.store.get_evidence(held_id).retention.pinned)
        with self.fx.store._connection() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 48)

    def test_planner_child_confirmation_retains_full_policy_audit_chain(self):
        child_id = self.auth_run()
        child = self.work.runs.get(child_id, self.target)
        ledger = PlannerStore(self.fx.store)
        run = ledger.create(self.fx.package, PlannerMode.BOUNDED_AUTONOMOUS,
                            PlannerLimits(), policy_version(self.fx.package))
        ledger.transition(self.target, run.id, PlannerStatus.LOADING_CONTEXT,
                          "CONTEXT_STARTED")
        root = digest("planner-confirmed-root")
        candidate = PlannerCandidate(
            "PLCAND-" + "a" * 32, run.id, self.target, "HYPOTHESIS",
            self.work.hypotheses.id, self.work.hypotheses.id,
            Specialist.AUTHORIZATION, "CROSS_TENANT", root, digest("surface"),
            90, 85, 90, 5, 0, 0, "LOW", 90, "CURRENT",
            status=CandidateStatus.SELECTED)
        sibling = replace(candidate, id="PLCAND-" + "b" * 32,
                          source_kind="AUTHORIZATION", source_id="AUTHC-" + "c" * 32)
        run = ledger.save_portfolio(run, (candidate, sibling), {}, digest("state"))
        candidate = ledger.update_candidate(
            self.target, run.id, candidate.id,
            hypothesis_id=self.work.hypotheses.id, plan_id=child.plan_id,
            plan_run_id=child_id, status=CandidateStatus.RUNNING)
        validate_task = ledger.add_task(run, candidate, PlannerTaskType.VALIDATE_RUN)
        claimed = ledger.claim_task(self.target, run.id, validate_task.id)
        delta_ledger = DeltaStore(self.fx.store)
        delta_ledger.ensure(self.fx.package)
        source_url = self.fx.base + "/validated/owned"
        signal = DeltaSignal(
            DeltaType.NEW_ENDPOINT, DeltaSource.RECON, "asset_events:1",
            "endpoint", "1", digest(source_url), "127.0.0.1/validated/owned",
            None, digest("fixture-endpoint"), datetime.now().astimezone().isoformat(),
            90, (Specialist.AUTHORIZATION,), ("PRIVILEGED_NAME",))
        watch_id = delta_ledger.begin_watch(self.fx.package, trigger="FIXTURE")
        delta_ledger.finish_watch(self.fx.package, watch_id, source=DeltaSource.RECON,
                                  signals=(signal,))
        delta_id = delta_ledger.list_candidates(target_id=self.target)[0]["delta_id"]
        passive = self.fx.store.create_evidence(
            EvidenceType.RECON_RECORD, b"synthetic endpoint delta; not a finding",
            source="FIXTURE", target_ref=self.target,
            provenance=EvidenceProvenance(system="FIXTURE", entity="delta"))
        delta_ledger.link_evidence(self.target, delta_id, passive.evidence_id)
        delta_ledger.link_hypothesis(self.target, delta_id, self.work.hypotheses.id)
        campaigns = CampaignStore(self.fx.store)
        policy_hash = policy_version(self.fx.package)
        focused = campaigns.create(
            self.fx.package, PlannerMode.BOUNDED_AUTONOMOUS, CampaignLimits(),
            policy_hash, "fixture", focus=DeltaFocus(
                (delta_id,), (self.work.hypotheses.id,),
                (Specialist.AUTHORIZATION,), digest(source_url), source_url))
        campaigns.transition(self.target, focused.id, CampaignStatus.RUNNING,
                             "FIXTURE_READY", package=self.fx.package,
                             policy_hash=policy_hash)
        campaigns.begin_cycle(self.fx.package, focused.id, policy_hash)
        work = campaigns.reserve_work(self.target, focused.id,
                                      CampaignWorkKind.PLANNER, requests=5)
        campaigns.link_child(self.target, focused.id, work.id, run.id)
        runner = PlannerRunner(
            planner=None, store=ledger, hypotheses=None, contexts=None, router=None,
            skill_planner=None, authorization=None, api=None, dom=None, messages=None,
            exposure=None, research=None, objects=None, object_factory=None,
            browser=None, orchestrator=SimpleNamespace(runs=self.work.runs),
            validator=self.validator)
        runner._validate(run, claimed, candidate)
        confirmed = ledger.candidate(self.target, run.id, candidate.id)
        self.assertEqual(confirmed.status, CandidateStatus.VALIDATED)
        self.assertIsNotNone(confirmed.finding_id)
        self.assertEqual(ledger.candidate(self.target, run.id, sibling.id).status,
                         CandidateStatus.DUPLICATE)
        self.assertEqual(ledger.branch_memory(self.target, root, run.context_hash)[0]["outcome"],
                         "CONFIRMED")
        self.assertEqual(ledger.task(self.target, run.id, validate_task.id).status,
                         PlannerTaskStatus.COMPLETED)
        self.assertGreater(ledger.metrics(self.target, run.id)["child_request_slots_consumed"], 0)
        with self.fx.store._connection() as db:
            chain = db.execute(
                "SELECT dc.delta_id,cmp.campaign_id,pr.run_id AS planner_run_id,"
                "c.candidate_id,t.task_id,"
                "f.finding_id,v.validation_id,r.run_id,p.plan_id,p.skill_id,"
                "h.hypothesis_id,d.decision_id,pm.permit_id,e.exchange_id "
                "FROM delta_candidates dc JOIN delta_campaign_focus_deltas fd "
                "ON fd.delta_id=dc.delta_id "
                "JOIN campaigns cmp ON cmp.campaign_id=fd.campaign_id "
                "JOIN campaign_work cw ON cw.campaign_id=cmp.campaign_id "
                "AND cw.kind='PLANNER' "
                "JOIN planner_runs pr ON pr.run_id=cw.child_id "
                "JOIN planner_candidates c ON c.run_id=pr.run_id "
                "JOIN planner_tasks t ON t.candidate_id=c.candidate_id "
                "JOIN findings f ON f.finding_id=c.finding_id "
                "JOIN validations v ON v.validation_id=f.validation_id "
                "JOIN plan_runs r ON r.run_id=v.run_id "
                "JOIN skill_plans p ON p.plan_id=r.plan_id "
                "JOIN hypotheses h ON h.hypothesis_id=p.hypothesis_id "
                "JOIN plan_run_steps s ON s.run_id=r.run_id AND s.role='BOUNDARY' "
                "JOIN policy_decisions d ON d.decision_id=s.decision_id "
                "JOIN executor_permits pm ON pm.permit_id=s.permit_id "
                "JOIN executor_events ev ON ev.permit_id=pm.permit_id "
                "JOIN traffic_exchanges e ON e.exchange_id=ev.exchange_id "
                "WHERE dc.delta_id=? AND pr.run_id=? AND c.candidate_id=? "
                "AND t.task_type='VALIDATE_RUN' AND ev.event_type='REQUEST_SENT' LIMIT 1",
                (delta_id, run.id, candidate.id)).fetchone()
        self.assertIsNotNone(chain)
        self.assertEqual(chain["delta_id"], delta_id)
        self.assertEqual(chain["campaign_id"], focused.id)
        self.assertEqual(chain["run_id"], child_id)
        self.assertEqual(chain["finding_id"], confirmed.finding_id)
        self.assertEqual(delta_ledger.stats()["findings_from_deltas"], 1)

    def test_planner_remembers_real_rejection_for_unchanged_target_state(self):
        child_id = self.auth_run(boundary_path="/validated/denied")
        child = self.work.runs.get(child_id, self.target)
        ledger = PlannerStore(self.fx.store)
        run = ledger.create(self.fx.package, PlannerMode.BOUNDED_AUTONOMOUS,
                            PlannerLimits(), policy_version(self.fx.package))
        ledger.transition(self.target, run.id, PlannerStatus.LOADING_CONTEXT,
                          "CONTEXT_STARTED")
        signal = _Signal("HYPOTHESIS", self.work.hypotheses.id,
                         Specialist.AUTHORIZATION, "CROSS_TENANT",
                         "https://fixture.test/validated/denied", "CROSS_TENANT",
                         90, 80, 2, "CURRENT", "LOW", 5, 0, 0, (), ())
        context = SimpleNamespace(snapshot_hash=digest("same-target-state"),
                                  verified_identity_ids=(), tenant_ids=(),
                                  ready_object_ids=(), confirmed_hypothesis_ids=())
        candidate = PlannerCandidate(
            "PLCAND-" + "d" * 32, run.id, self.target, "HYPOTHESIS",
            self.work.hypotheses.id, self.work.hypotheses.id,
            Specialist.AUTHORIZATION, "CROSS_TENANT", signal.root_key(self.target),
            digest("denied-surface"), 90, 80, 90, 5, 0, 0,
            "LOW", 80, "CURRENT", status=CandidateStatus.SELECTED,
            state_hash=_candidate_state(run, context, signal, None))
        state_hash = digest("same-target-state")
        run = ledger.save_portfolio(run, (candidate,), {}, state_hash)
        candidate = ledger.update_candidate(
            self.target, run.id, candidate.id, status=CandidateStatus.RUNNING,
            hypothesis_id=self.work.hypotheses.id, plan_id=child.plan_id,
            plan_run_id=child_id)
        task = ledger.add_task(run, candidate, PlannerTaskType.VALIDATE_RUN)
        claimed = ledger.claim_task(self.target, run.id, task.id)
        runner = PlannerRunner(
            planner=None, store=ledger, hypotheses=None, contexts=None, router=None,
            skill_planner=None, authorization=None, api=None, dom=None, messages=None,
            exposure=None, research=None, objects=None, object_factory=None,
            browser=None, orchestrator=SimpleNamespace(runs=self.work.runs),
            validator=self.validator)
        runner._validate(run, claimed, candidate)
        self.assertEqual(ledger.candidate(self.target, run.id, candidate.id).status,
                         CandidateStatus.REJECTED)
        self.assertEqual(ledger.branch_memory(self.target, candidate.root_cause_key,
                                              candidate.state_hash)[0]["outcome"], "REJECTED")
        ledger.transition(self.target, run.id, PlannerStatus.COMPLETED, "ALL_BRANCHES_SETTLED")
        next_run = ledger.create(self.fx.package, PlannerMode.ANALYZE_ONLY,
                                 PlannerLimits(), policy_version(self.fx.package))
        planner = CrossSpecialistPlanner(
            store=ledger, context=SimpleNamespace(research=SimpleNamespace(
                list=lambda *_args, **_kwargs: {"items": []})),
            hypotheses=HypothesisStore(self.fx.store), authorization=None,
            api=None, dom=None, messages=None, exposure=None, traffic=None,
            validations=None, skill_context=None, skill_router=None)
        ranked = planner._rank(next_run, context, (signal,))
        self.assertEqual(ranked[0].status, CandidateStatus.SKIPPED)
        self.assertIn("PRIOR_BRANCH_OUTCOME", ranked[0].reason_codes)

    def test_denied_public_and_control_failure_never_confirm(self):
        denied = self.auth_run(boundary_path="/validated/denied")
        rejected, finding = self.validator.validate_run(denied, self.target)
        self.assertEqual(rejected.status, ValidationStatus.REJECTED)
        self.assertIsNone(finding)
        public = self.auth_run(visibility="PUBLIC", object_name="object-b",
                               control_path="/validated/object-b", boundary_path="/validated/object-b")
        public_result, _ = self.validator.validate_run(public, self.target)
        self.assertEqual(public_result.status, ValidationStatus.REJECTED)
        self.assertIn("INTENTIONALLY_PUBLIC", public_result.reason_codes)
        context = self.validator._context(self.work.runs.get(denied, self.target))
        failed_owner = replace(context.observations[0], features=replace(
            context.observations[0].features, status_code=403))
        invalid_context = replace(context, observations=(failed_owner, *context.observations[1:]))
        decision = self.validator.registry.select("cross-tenant-object-authorization").evaluate(
            invalid_context, self.validator)
        self.assertEqual(decision.status, ValidationStatus.INVALID_TEST)

    def test_horizontal_and_vertical(self):
        for skill, alias in (("horizontal-object-authorization", "tenant_a_member"),
                             ("vertical-role-authorization", "tenant_a_member"),
                             ("hidden-function-authorization", "tenant_a_member")):
            with self.subTest(skill=skill):
                role_skill = skill != "horizontal-object-authorization"
                run_id = self.auth_run(
                    skill=skill, boundary_alias=alias,
                    object_name="object-c" if role_skill else "object-a",
                    control_path="/validated/object-c" if role_skill else "/validated/object-a",
                    boundary_path="/validated/object-c" if role_skill else "/validated/object-a")
                result, finding = self.validator.validate_run(run_id, self.target)
                self.assertEqual(result.status, ValidationStatus.CONFIRMED)
                self.assertIsNotNone(finding)

    def test_anonymous_download_and_sensitive_metadata(self):
        object_hash = self.protected(object_name="private-file")
        self.fact(object_hash, "data_classification", "PROTECTED_FILE")
        run_id = self.run_fixture("unauthenticated-sensitive-download", [
            self.action("/validated/private-file", "tenant_a_owner", "CONTROL", object_hash),
            self.action("/validated/private-file", None, "BOUNDARY", object_hash),
            self.action("/validated/private-file", None, "BOUNDARY", object_hash),
            self.action("/validated/missing", None, "OTHER", digest("missing"),
                        control_kind="INVALID_OBJECT")])
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertNotIn("disposable-fixture-file", json.dumps(finding.to_dict()))
        self.assertNotIn("disposable-fixture-file", json.dumps(result.to_dict()))

    def test_graphql_data_not_http_200_alone(self):
        object_hash = self.protected()
        self.fact(object_hash, "graphql_operation", "protected_node")
        actions = [self.action("/validated/graphql", "tenant_a_owner", "CONTROL", object_hash,
                               operation="protected_node"),
                   self.action("/validated/graphql", "tenant_b_admin", "BOUNDARY", object_hash,
                               operation="protected_node"),
                   self.action("/validated/graphql", "tenant_b_admin", "BOUNDARY", object_hash,
                               operation="protected_node"),
                   self.action("/validated/graphql-invalid", "tenant_b_admin", "OTHER",
                               digest("missing"), control_kind="INVALID_OBJECT",
                               operation="protected_node")]
        run_id = self.run_fixture("graphql-object-authorization", actions)
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)

        context = self.validator._context(self.work.runs.get(run_id, self.target))
        denied = replace(context.observations[1], features=replace(
            context.observations[1].features, graphql_data_present=False,
            graphql_errors_present=True))
        denied_again = replace(context.observations[2], features=denied.features)
        invalid_negative = replace(context.observations[3], features=replace(
            context.observations[3].features, graphql_data_present=True,
            graphql_errors_present=False))
        invalid_context = replace(context, observations=(
            context.observations[0], denied, denied_again, invalid_negative))
        decision = self.validator.registry.select("graphql-object-authorization").evaluate(
            invalid_context, self.validator)
        self.assertEqual(decision.status, ValidationStatus.INVALID_TEST)
        self.assertIn("NEGATIVE_CONTROL_FAILED", decision.reasons)

    def test_validation_rows_are_append_only(self):
        run_id = self.auth_run()
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertIsNotNone(finding)
        with self.fx.store._connection() as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE validations SET status='REJECTED' WHERE validation_id=?",
                           (result.id,))
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM validation_checks WHERE validation_id=?", (result.id,))

    def test_same_root_cause_across_distinct_routes_is_one_finding(self):
        self.fact(self.protected(), "root_cause_key", "shared-fixture-helper")
        first_run = self.auth_run()
        first, finding = self.validator.validate_run(first_run, self.target)
        self.assertEqual(first.status, ValidationStatus.CONFIRMED)
        second_run = self.auth_run(boundary_path="/validated/object-a-alt",
                                   control_path="/validated/object-a-alt")
        duplicate, original = self.validator.validate_run(second_run, self.target)
        self.assertEqual(duplicate.status, ValidationStatus.DUPLICATE_CANDIDATE)
        self.assertEqual(original.id, finding.id)
        self.assertEqual(len(original.locations), 2)
        self.assertEqual(self.results.stats(self.target)["findings"], 1)

    def test_sample_credential_and_client_side_without_browser_proof(self):
        object_hash = self.protected(object_name="example-key")
        self.fact(object_hash, "data_classification", "CREDENTIAL")
        self.fact(object_hash, "sample_data", "TRUE")
        run_id = self.run_fixture("sensitive-data-exposure", [
            self.action("/validated/example-key", "tenant_a_owner", "CONTROL", object_hash),
            self.action("/validated/example-key", None, "BOUNDARY", object_hash),
            self.action("/validated/example-key", None, "BOUNDARY", object_hash),
            self.action("/validated/missing", None, "OTHER", digest("missing"),
                        control_kind="INVALID_OBJECT")])
        result, finding = self.validator.validate_run(run_id, self.target)
        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertIn("TEST_DATA_ONLY", result.reason_codes)
        self.assertIsNone(finding)
        from hackbot.validator import ClientSideValidator
        context = self.validator._context(self.work.runs.get(run_id, self.target))
        for skill in ("check-before-transform-dom-xss", "postmessage-trust-analysis"):
            decision = ClientSideValidator(skill).evaluate(context, self.validator)
            self.assertEqual(decision.status, ValidationStatus.INSUFFICIENT_EVIDENCE)
            self.assertFalse(decision.supporting_evidence_ids)

    def test_private_api_target_scoping_and_manual_review(self):
        run_id = self.auth_run()
        events = []
        def scoped_package(package_id):
            if package_id != self.fx.package.id:
                raise LookupError("target not found")
            return self.fx.package
        service = SimpleNamespace(package=scoped_package, run_store=self.work.runs,
                                  validator=self.validator, validations=self.results,
                                  store=self.fx.store,
                                  report_store=ReportStore(self.fx.store, ArtifactStore(
                                      self.fx.root / "artifacts" / "reports")),
                                  workflow=FindingWorkflow(self.fx.store, self.results),
                                  notification_store=NotificationStore(self.fx.store),
                                  audit=lambda event, **kwargs: events.append(event),
                                  logger=SimpleNamespace(error=lambda *args, **kwargs: None))
        client = create_app(runtime=service).test_client()
        self.assertEqual(client.get("/v1/findings?target=unknown").status_code, 404)
        self.assertEqual(client.post(f"/v1/runs/{run_id}/validate", json={"target": "unknown"}).status_code, 404)
        before = len(self.fx.server.received)
        with patch("requests.sessions.Session.send", side_effect=AssertionError("validator sent traffic")):
            response = client.post(f"/v1/runs/{run_id}/validate", json={"target": "example"})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(len(self.fx.server.received), before)
        payload = response.get_json()
        self.assertEqual(payload["validation"]["status"], "CONFIRMED")
        self.assertFalse(payload["request_sent"])
        finding_id = payload["finding"]["id"]
        validation_id = payload["validation"]["id"]
        self.assertEqual(client.get("/v1/findings?target=example").get_json()["items"][0]["id"], finding_id)
        self.assertEqual(client.get(f"/v1/findings/{finding_id}?target=example").get_json()["finding"]["id"],
                         finding_id)
        self.assertEqual(client.get(f"/v1/validations/{validation_id}?target=example")
                         .get_json()["validation"]["id"], validation_id)
        self.assertEqual(client.get(f"/v1/findings/{finding_id}?target=unknown").status_code, 404)
        self.assertIn("finding_created", events)
        evidence_id = payload["validation"]["supporting_evidence_ids"][0]
        manual = self.validator.record_manual(run_id, self.target,
                                              ValidationStatus.NEEDS_MANUAL_REVIEW,
                                              (evidence_id,), "RESEARCHER_REVIEW")
        self.assertEqual(manual.source, "MANUAL")
        self.assertEqual(self.results.stats(self.target)["findings"], 1)

    def test_response_comparator_exact_volatile_paths_preserve_identity(self):
        from hackbot.response_compare import _walk
        volatile = frozenset({"/requestId", "/timestamp"})
        def normalized(value):
            return _walk(value, "", volatile, [0], set(), set())
        self.assertEqual(normalized({"requestId": "a", "timestamp": "now", "id": "x"}),
                         normalized({"requestId": "b", "timestamp": "later", "id": "x"}))
        self.assertNotEqual(normalized({"requestId": "a", "tenantId": "a", "id": "x"}),
                            normalized({"requestId": "b", "tenantId": "b", "id": "x"}))
        with self.assertRaises(ValueError):
            ResponseComparator(self.fx.store, volatile_json_paths=frozenset({"/id"}))
        with self.assertRaises(ValueError):
            ResponseComparator(self.fx.store, volatile_json_paths=frozenset({"/data/node/tenantId"}))

    def test_paginated_fact_relationship_is_not_trusted_as_complete(self):
        with patch.object(self.fx.store, "find_facts", return_value=Page((), "more")):
            value, evidence = self.validator.fact_value("resource-hash", "resource_visibility",
                                                        self.target)
        self.assertIsNone(value)
        self.assertEqual(evidence, ())

