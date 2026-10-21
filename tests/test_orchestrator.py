"""Phase 16 tests use only an in-process loopback fixture."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hackbot.orchestrator import PlanOrchestrator, PlanRunError
from hackbot.plan_runs import PlanRunStore
from hackbot.evidence import EvidenceProvenance, EvidenceType, Sensitivity
from hackbot.auth import AuthContextManager
from hackbot.browser import IdentityObservation, IdentityVerificationRule
from hackbot.config import SecretBindingConfig, SecretSettings
from hackbot.identity import IdentityStatus
from hackbot.secrets import RoutedSecretProvider
from hackbot.policy_models import ApprovalStatus
from hackbot.rate_limit import RateLimiter
from hackbot.skill_plans import PrerequisiteChecker, SkillContext
from hackbot.skills import SkillRegistry
from hackbot.target_policy import PolicyDecision, RatePolicy
from hackbot.target_scope import HostRule
from hackbot.executor import RequestTemplate
from hackbot.hypotheses import HypothesisStore
from tests import test_executor as executor_fixture


CATALOG = Path(__file__).resolve().parents[1] / "src/hackbot/skill_catalog"


class FakeHypotheses:
    def __init__(self, target_id: str):
        self.target_id = target_id
        self.id = "HYP-" + "1" * 32

    def get(self, hypothesis_id: str, target_id: str):
        return SimpleNamespace(id=self.id, target_id=self.target_id) if (
            hypothesis_id == self.id and target_id == self.target_id) else None

    def latest_profile(self, target_id: str):
        return None


class FakeContext:
    def __init__(self, target_id: str, hypothesis_id: str):
        self.target_id, self.hypothesis_id = target_id, hypothesis_id
        self.flags = {"in_scope_target"}
        self.identities: tuple[dict[str, object], ...] = ()
        self.evidence: tuple[dict[str, object], ...] = ()

    def build(self, hypothesis, profile, package):
        return SkillContext(self.target_id, self.hypothesis_id, "FIXTURE", "OWNERSHIP",
                            "/owned", (), (), (), self.evidence, (), (), self.identities,
                            frozenset(self.flags), ())


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = executor_fixture.ExecutorTests(methodName="test_template_header_validation")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self._generation = 0
        fx = self.fixture
        self.hypotheses = FakeHypotheses(fx.package.target.id)
        self.context = FakeContext(fx.package.target.id, self.hypotheses.id)
        self.runs = PlanRunStore(fx.store)
        self.engine = PlanOrchestrator(
            runs=self.runs, targets=fx.targets, hypotheses=self.hypotheses,
            context=self.context, checker=PrerequisiteChecker(), registry=SkillRegistry(CATALOG),
            policy=fx.policy, approvals=fx.policy.audit, executor=fx.executor,
            traffic=fx.traffic, evidence=fx.store)

    def action(self, path="/ok", *, method="GET", category="SAFE_READ", actor="ANONYMOUS",
               identity=None, session=None, role="OTHER", vulnerability="EXPOSURE",
               **extra):
        template = RequestTemplate(method, self.fixture.base + path)
        descriptor = {"category": category, "actor": actor, "identity_id": identity,
                      "session_id": session, "method": method, "role": role,
                      "request_template_fingerprint": template.fingerprint(),
                      "vulnerability_class": vulnerability.lower(), "simulation_only": True,
                      **extra}
        shape = {"method": method, "url": template.url, "fingerprint": template.fingerprint(),
                 "authentication": "EXECUTOR_SUPPLIED"}
        return descriptor, shape

    def plan(self, actions, *, workflow=None, budget=None, category="exposure",
             required=None, comparisons=None, status="READY_FOR_MANUAL_REVIEW",
             skill_name=None):
        fx = self.fixture
        plan_id = "PLAN-" + __import__("uuid").uuid4().hex
        rows = list(actions)
        skill = self.engine.registry.select(skill_name) if skill_name else None
        workflow = workflow or [{"type": "EXECUTE_REQUEST", "description": "Fixture request"}
                                for _ in rows]
        classes = sorted({item[0]["vulnerability_class"].upper() for item in rows}) or ["EXPOSURE"]
        payload = {"id": plan_id, "target_id": fx.package.target.id,
                   "hypothesis_id": self.hypotheses.id,
                   "skill_id": skill.metadata.name if skill else "fixture-skill",
                   "skill_version": skill.metadata.version if skill else "1.0.0",
                   "skill_hash": skill.content_hash if skill else "a" * 64,
                   "skill_category": category, "vulnerability_classes": classes,
                   "required_prerequisites": required or ["in_scope_target"],
                   "prerequisites": {"state": "READY", "missing": [], "satisfied": ["in_scope_target"]},
                   "status": status, "steps": workflow,
                   "proposed_actions": [item[0] for item in rows],
                   "request_templates": [item[1] for item in rows],
                   "request_budget": budget if budget is not None else max(1, len(rows)),
                   "token_budget": 1000, "controls": ["Owned fixture control"],
                   "required_validators": list(skill.metadata.required_validators) if skill else [],
                   "confirmation_requirements": list(skill.confirmation_requirements) if skill else [],
                   "rejection_conditions": list(skill.rejection_conditions) if skill else [],
                   "comparison_pairs": comparisons or []}
        self._generation += 1
        with fx.store._connection() as db:
            db.execute("INSERT INTO skill_plans VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (plan_id, payload["target_id"], payload["hypothesis_id"], payload["skill_id"],
                        payload["skill_version"], payload["skill_hash"], self._generation, 0, status,
                        datetime.now(timezone.utc).isoformat(),
                        json.dumps(payload, sort_keys=True, separators=(",", ":"))))
        return plan_id

    def start(self, plan_id):
        return self.engine.start(plan_id, self.fixture.package.id)["run"]["id"]

    def advance(self, run_id):
        return self.engine.advance(run_id, self.fixture.package.id)

    def test_anonymous_download_control_comparison_and_audit_chain(self):
        fx = self.fixture
        persisted = HypothesisStore(fx.store).add_manual(
            fx.package.target.id, "EXPOSURE", "Fixture download authorization boundary",
            "Compare owner and anonymous fixture responses")
        self.hypotheses.id = persisted.id
        self.context.hypothesis_id = persisted.id
        owner, session = fx.owned_session("owner_a")
        self.context.identities = ({"id": owner.id, "verified_session_id": session.id},)
        self.context.flags.add("verified_sessions")
        plan_id = self.plan([
            self.action("/cookie", actor="AUTHENTICATED", identity=owner.id,
                        session=session.id, role="CONTROL"),
            self.action("/cookie", role="BOUNDARY")],
            workflow=[{"type": "EXECUTE_REQUEST", "description": "Owner control"},
                      {"type": "EXECUTE_REQUEST", "description": "Anonymous boundary"},
                      {"type": "COMPARE_RESPONSE", "description": "Compare metadata"}],
            required=["in_scope_target", "verified_sessions"],
            comparisons=[{"control_slot": 0, "boundary_slot": 1}],
            skill_name="unauthenticated-sensitive-download")
        run_id = self.start(plan_id)
        for _ in range(4):
            result = self.advance(run_id)
        self.assertEqual(result["run"]["status"], "COMPLETED")
        self.assertEqual(result["run"]["finding_status"], "UNVALIDATED")
        self.assertEqual(result["run"]["requests_consumed"], 2)
        self.assertEqual([item[1] for item in fx.server.received], ["/cookie", "/cookie"])
        self.assertEqual(fx.server.received[0][2], executor_fixture.SECRET)
        self.assertIsNone(fx.server.received[1][2])
        steps = result["steps"]
        self.assertEqual((steps[1]["result"]["status_code"], steps[2]["result"]["status_code"]),
                         (200, 401))
        self.assertEqual(steps[2]["control_step_id"], steps[1]["id"])
        self.assertIn("status_equal=False", steps[3]["result"]["safe_summary"])
        self.assertTrue(steps[1]["result"]["traffic_exchange_ids"])
        self.assertTrue(steps[1]["result"]["evidence_ids"])
        self.assertTrue(steps[1]["decision_id"] and steps[1]["permit_id"])
        with fx.store._connection() as db:
            chain = db.execute(
                "SELECT h.hypothesis_id,p.skill_id,p.skill_hash,r.run_id,s.step_id,"
                "a.action_id,d.decision_id,pm.permit_id,x.exchange_id,"
                "q.observation_evidence_id AS request_evidence,"
                "z.observation_evidence_id AS response_evidence "
                "FROM hypotheses h JOIN skill_plans p ON p.hypothesis_id=h.hypothesis_id "
                "JOIN plan_runs r ON r.plan_id=p.plan_id "
                "JOIN plan_run_steps s ON s.run_id=r.run_id "
                "JOIN policy_actions a ON a.action_id=s.action_id "
                "JOIN policy_decisions d ON d.decision_id=s.decision_id AND d.action_id=a.action_id "
                "JOIN executor_permits pm ON pm.permit_id=s.permit_id AND pm.action_id=a.action_id "
                "JOIN executor_events ev ON ev.permit_id=pm.permit_id AND ev.event_type='REQUEST_DISPATCHED' "
                "JOIN traffic_exchanges x ON x.exchange_id=ev.exchange_id "
                "JOIN traffic_requests q ON q.request_id=x.request_id "
                "JOIN traffic_responses z ON z.request_id=q.request_id "
                "WHERE r.run_id=? AND s.step_id=?", (run_id, steps[1]["id"])).fetchone()
            self.assertIsNotNone(chain)
            self.assertEqual(chain["hypothesis_id"], persisted.id)
            self.assertEqual(chain["skill_id"], "unauthenticated-sensitive-download")
            self.assertEqual(chain["run_id"], run_id)
            self.assertEqual(chain["exchange_id"], steps[1]["result"]["traffic_exchange_ids"][0])
            self.assertEqual(db.execute("SELECT count(*) FROM evidence WHERE evidence_id IN (?,?)",
                                        (chain["request_evidence"], chain["response_evidence"]))
                             .fetchone()[0], 2)
            self.assertIsNotNone(db.execute("SELECT 1 FROM evidence WHERE evidence_id=?",
                                             (steps[1]["result"]["evidence_ids"][-1],)).fetchone())
        self.assertNotIn(executor_fixture.SECRET.encode(), fx.store.db_path.read_bytes())

    def test_active_plan_waits_for_target_rate_slot_before_next_step(self):
        fx = self.fixture
        fx.package = replace(fx.package, rate=RatePolicy(
            requests_per_second=1, requests_per_minute=30,
            max_concurrency=1, burst=1))
        fx.targets.package = fx.package
        clock = [0.0]
        limiter = RateLimiter(clock=lambda: clock[0])
        fx.policy.rate = limiter
        fx.executor.rate = limiter
        plan_id = self.plan([self.action(), self.action()])
        run_id = self.start(plan_id)

        def advance_clock(seconds: float) -> None:
            clock[0] += seconds

        with patch("hackbot.orchestrator.time.sleep", side_effect=advance_clock) as sleep:
            for _ in range(3):
                result = self.advance(run_id)
        self.assertEqual(result["run"]["status"], "COMPLETED")
        self.assertEqual(result["run"]["requests_consumed"], 2)
        self.assertTrue(sleep.called)
        self.assertGreaterEqual(clock[0], 1.0)

    def test_three_identity_two_tenant_control_and_boundary_fixture(self):
        fx = self.fixture
        aliases = ("tenant_a_admin", "tenant_a_member", "tenant_b_admin")
        bindings = tuple(SecretBindingConfig(f"ref:{alias}",
                                            f"env:HACKBOT_SECRET_{alias.upper()}", "COOKIE")
                         for alias in aliases)
        provider = RoutedSecretProvider(SecretSettings(bindings=bindings), {
            f"HACKBOT_SECRET_{alias.upper()}": f"fixture_actor={alias}" for alias in aliases})
        fx.auth = AuthContextManager(fx.registry, provider)
        fx.browser.auth = fx.auth
        fx.executor.auth = fx.auth
        fx.executor.secrets = provider
        actors = {}
        for alias in aliases:
            identity = fx.registry.register_identity(fx.package.target.id, alias,
                                                     status=IdentityStatus.ACTIVE,
                                                     secret_ref=f"ref:{alias}")
            fx.auth.prepare(fx.package.target.id, identity.id)
            session = fx.browser.create(fx.package.target.id, identity.id)
            fx.browser.start(session.id)
            fx.browser.login_complete(session.id)
            tenant = "tenant_b" if alias.startswith("tenant_b") else "tenant_a"
            fx.driver.observations[session.id] = IdentityObservation(user_id=alias, tenant_id=tenant)
            rule = IdentityVerificationRule(fx.package.target.id, identity.id,
                                            "[data-user]", None, "[data-tenant]", alias, None, tenant)
            fx.browser.verify(session.id, rule)
            actors[alias] = (identity, session)
        self.context.flags.update({"verified_sessions", "multiple_tenants", "known_ownership"})
        self.context.identities = tuple({"id": identity.id, "verified_session_id": session.id}
                                        for identity, session in actors.values())
        def bound(alias, path, role):
            identity, session = actors[alias]
            return self.action(path, actor="AUTHENTICATED", identity=identity.id,
                               session=session.id, role=role, vulnerability="CROSS_TENANT")
        plan_id = self.plan([
            bound("tenant_a_admin", "/tenant-a/object-a", "CONTROL"),
            bound("tenant_a_member", "/tenant-a/object-a", "BOUNDARY"),
            bound("tenant_b_admin", "/tenant-a/object-a", "BOUNDARY"),
            bound("tenant_b_admin", "/tenant-b/object-b", "CONTROL")],
            workflow=[{"type": "EXECUTE_REQUEST"} for _ in range(4)] +
                     [{"type": "COMPARE_RESPONSE"}], budget=4, category="authorization",
            required=["in_scope_target", "multiple_tenants", "known_ownership", "verified_sessions"],
            comparisons=[{"control_slot": 0, "boundary_slot": 2}])
        run_id = self.start(plan_id)
        result = None
        for _ in range(6):
            result = self.advance(run_id)
        assert result is not None
        self.assertEqual(result["run"]["status"], "COMPLETED")
        self.assertEqual(result["run"]["requests_consumed"], 4)
        self.assertEqual([row["result"]["status_code"] for row in result["steps"][1:5]],
                         [200, 403, 403, 200])
        self.assertEqual(result["steps"][2]["control_step_id"], result["steps"][1]["id"])
        self.assertEqual(result["steps"][3]["control_step_id"], result["steps"][1]["id"])
        self.assertEqual(len(fx.server.received), 4)
        self.assertNotIn(b"fixture_actor=", fx.store.db_path.read_bytes())

    def test_scope_and_policy_changed_send_zero_requests(self):
        for change in ("scope", "policy"):
            with self.subTest(change=change):
                self.fixture.server.received.clear()
                plan_id = self.plan([self.action()])
                run_id = self.start(plan_id)
                self.advance(run_id)
                before = self.fixture.targets.package
                if change == "scope":
                    self.fixture.targets.package = replace(before, scope=replace(
                        before.scope, include_hosts=(HostRule("localhost"),)))
                else:
                    self.fixture.targets.package = replace(before, autonomy=replace(
                        before.autonomy, safe_read=PolicyDecision.DENY))
                blocked = self.advance(run_id)
                self.assertEqual(blocked["run"]["status"], "BLOCKED")
                self.assertEqual(self.fixture.server.received, [])
                self.fixture.targets.package = before

    def test_missing_capture_proxy_blocks_without_dispatch(self):
        fx = self.fixture
        fx.executor.settings = replace(fx.executor.settings,
                                       allow_direct=False, capture_required=True)
        run_id = self.start(self.plan([self.action()]))
        self.advance(run_id)
        blocked = self.advance(run_id)
        self.assertEqual(blocked["run"]["status"], "BLOCKED")
        self.assertEqual(blocked["steps"][1]["safe_reason"], "CAPTURE_UNAVAILABLE")
        self.assertEqual(blocked["run"]["requests_consumed"], 0)
        self.assertEqual(fx.server.received, [])

    def test_redirects_consume_budget_and_third_request_is_not_sent(self):
        plan_id = self.plan([self.action("/redirect-in"), self.action("/ok")], budget=2)
        run_id = self.start(plan_id)
        self.advance(run_id)
        after_first = self.advance(run_id)
        self.assertEqual(after_first["run"]["requests_consumed"], 2)
        self.assertEqual(len(self.fixture.server.received), 2)
        blocked = self.advance(run_id)
        self.assertEqual(blocked["run"]["status"], "BUDGET_EXHAUSTED")
        self.assertEqual(len(self.fixture.server.received), 2)

    def test_redirect_at_final_budget_slot_reports_exhaustion(self):
        run_id = self.start(self.plan([self.action("/redirect-in")], budget=1))
        self.advance(run_id)
        result = self.advance(run_id)
        self.assertEqual(result["run"]["status"], "BUDGET_EXHAUSTED")
        self.assertEqual(result["run"]["requests_consumed"], 1)
        self.assertEqual(result["steps"][1]["result"]["error_class"], "BUDGET_EXHAUSTED")
        self.assertEqual([item[1] for item in self.fixture.server.received], ["/redirect-in"])

    def test_each_dispatch_is_accounted_before_wire_send(self):
        fx = self.fixture
        run_id = self.start(self.plan([self.action("/redirect-in")], budget=2))
        self.advance(run_id)
        observed = []
        original = fx.executor.permits.record

        def inspect_dispatch(*args, **kwargs):
            if args[1] == "REQUEST_DISPATCHED":
                current = self.runs.get(run_id, fx.package.target.id)
                assert current is not None
                observed.append(current.requests_consumed)
            return original(*args, **kwargs)

        with patch.object(fx.executor.permits, "record", side_effect=inspect_dispatch):
            result = self.advance(run_id)
        self.assertEqual(result["run"]["status"], "COMPLETED")
        self.assertEqual(observed, [1, 2])
        self.assertEqual(result["run"]["requests_consumed"], 2)
        self.assertEqual(sum(event["event_type"] == "DISPATCH_ACCOUNTED"
                             for event in result["timeline"]), 2)

    def test_cancel_between_request_record_and_wire_send(self):
        fx = self.fixture
        run_id = self.start(self.plan([self.action()], budget=1))
        self.advance(run_id)
        original = fx.traffic.store_request

        def cancel_before_dispatch(*args, **kwargs):
            exchange = original(*args, **kwargs)
            self.engine.cancel(run_id, fx.package.id)
            return exchange

        with patch.object(fx.traffic, "store_request", side_effect=cancel_before_dispatch):
            result = self.advance(run_id)
        self.assertEqual(result["run"]["status"], "CANCELLED")
        self.assertEqual(result["run"]["requests_consumed"], 1)
        self.assertEqual(result["steps"][1]["result"]["error_class"], "OPERATOR_STOPPED")
        self.assertEqual(len(result["steps"][1]["result"]["traffic_exchange_ids"]), 1)
        self.assertEqual(fx.server.received, [])

    def test_cancel_after_first_redirect_hop_stops_future_dispatches(self):
        fx = self.fixture
        run_id = self.start(self.plan([self.action("/redirect-in")], budget=2))
        self.advance(run_id)
        original = fx.traffic.store_response

        def cancel_after_response(*args, **kwargs):
            stored = original(*args, **kwargs)
            self.engine.cancel(run_id, fx.package.id)
            return stored

        with patch.object(fx.traffic, "store_response", side_effect=cancel_after_response):
            result = self.advance(run_id)
        self.assertEqual(result["run"]["status"], "CANCELLED")
        self.assertEqual(result["run"]["requests_consumed"], 1)
        self.assertEqual(result["steps"][1]["result"]["error_class"], "OPERATOR_STOPPED")
        self.assertEqual([item[1] for item in fx.server.received], ["/redirect-in"])

    def test_approval_pause_resume_and_exactly_one_post(self):
        fx = self.fixture
        fx.targets.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, state_changing=PolicyDecision.REQUIRE_APPROVAL,
            create_disposable_objects=PolicyDecision.REQUIRE_APPROVAL))
        plan_id = self.plan([self.action("/create", method="POST", category="OBJECT_CREATE",
                                         disposable_intent=True, object_type="fixture")],
                            status="REQUIRE_APPROVAL")
        run_id = self.start(plan_id)
        self.advance(run_id)
        waiting = self.advance(run_id)
        self.assertEqual(waiting["run"]["status"], "WAITING_APPROVAL")
        self.assertEqual(fx.server.received, [])
        approval_id = waiting["run"]["approval_id"]
        self.assertEqual(self.runs.approval_run(approval_id, fx.package.target.id)["run_id"], run_id)
        fx.policy.audit.decide(approval_id, fx.package.target.id, approve=True)
        self.runs.approval_decision(approval_id, fx.package.target.id, granted=True)
        ready = self.engine.resume(run_id, fx.package.id)
        self.assertEqual(ready["run"]["status"], "READY")
        finished = self.advance(run_id)
        self.assertEqual(finished["run"]["status"], "COMPLETED")
        self.assertEqual(finished["run"]["requests_consumed"], 1)
        self.assertEqual(fx.server.received, [("POST", "/create", None)])
        self.assertEqual(fx.policy.audit.get(approval_id, fx.package.target.id).status,
                         ApprovalStatus.CONSUMED)
        with fx.store._connection() as db:
            permit = db.execute("SELECT approval_id,consumed_at FROM executor_permits WHERE permit_id=?",
                                (finished["steps"][1]["permit_id"],)).fetchone()
            self.assertEqual(permit["approval_id"], approval_id)
            self.assertIsNotNone(permit["consumed_at"])
        self.assertEqual(len(finished["steps"][1]["result"]["traffic_exchange_ids"]), 1)
        self.assertIn("APPROVAL_GRANTED", {item["event_type"] for item in finished["timeline"]})
        self.assertIn("EXECUTION_FINISHED", {item["event_type"] for item in finished["timeline"]})

    def test_approval_expiry_blocks_without_execution(self):
        fx = self.fixture
        fx.targets.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, state_changing=PolicyDecision.REQUIRE_APPROVAL,
            create_disposable_objects=PolicyDecision.REQUIRE_APPROVAL))
        run_id = self.start(self.plan([self.action("/create", method="POST", category="OBJECT_CREATE",
                                                 disposable_intent=True, object_type="fixture")]))
        self.advance(run_id)
        approval_id = self.advance(run_id)["run"]["approval_id"]
        with fx.store._connection() as db:
            db.execute("UPDATE policy_approvals SET expires_at=? WHERE approval_id=?",
                       ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), approval_id))
        resumed = self.engine.resume(run_id, fx.package.id)
        self.assertEqual(resumed["run"]["status"], "BLOCKED")
        self.assertEqual(fx.server.received, [])

    def test_paused_approval_rejection_stops_run(self):
        fx = self.fixture
        fx.targets.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, state_changing=PolicyDecision.REQUIRE_APPROVAL,
            create_disposable_objects=PolicyDecision.REQUIRE_APPROVAL))
        run_id = self.start(self.plan([self.action("/create", method="POST", category="OBJECT_CREATE",
                                                 disposable_intent=True, object_type="fixture")],
                                      status="REQUIRE_APPROVAL"))
        self.advance(run_id)
        approval_id = self.advance(run_id)["run"]["approval_id"]
        self.assertEqual(self.engine.pause(run_id, fx.package.id)["run"]["status"], "PAUSED")
        self.assertEqual(self.engine.resume(run_id, fx.package.id)["run"]["status"], "WAITING_APPROVAL")
        self.assertEqual(self.engine.pause(run_id, fx.package.id)["run"]["status"], "PAUSED")
        fx.policy.audit.decide(approval_id, fx.package.target.id, approve=False)
        self.assertEqual(self.engine.resume(run_id, fx.package.id)["run"]["status"], "REJECTED")
        self.assertEqual(fx.server.received, [])

    def test_plan_snapshot_change_blocks_and_skill_change_does_not_regenerate(self):
        fx = self.fixture
        run_id = self.start(self.plan([self.action()]))
        self.engine.registry = SimpleNamespace(select=lambda _: (_ for _ in ()).throw(
            AssertionError("current skill must not be reloaded")))
        self.advance(run_id)
        with fx.store._connection() as db:
            plan = db.execute("SELECT plan_json FROM skill_plans WHERE plan_id=(SELECT plan_id "
                              "FROM plan_runs WHERE run_id=?)", (run_id,)).fetchone()[0]
            db.execute("UPDATE skill_plans SET plan_json=? WHERE plan_id=(SELECT plan_id FROM "
                       "plan_runs WHERE run_id=?)", (plan + " ", run_id))
        with self.assertRaises(PlanRunError):
            self.advance(run_id)
        self.assertEqual(self.runs.get(run_id, fx.package.target.id).status.value, "BLOCKED")
        self.assertEqual(fx.server.received, [])

    def test_wrong_identity_or_stale_prerequisite_blocks(self):
        fx = self.fixture
        owner, session = fx.owned_session("owned_fixture")
        self.context.flags.add("verified_sessions")
        self.context.identities = ({"id": owner.id, "verified_session_id": session.id},)
        plan_id = self.plan([self.action("/cookie", actor="AUTHENTICATED", identity=owner.id,
                                         session=session.id)], required=["in_scope_target", "verified_sessions"])
        run_id = self.start(plan_id)
        self.advance(run_id)
        self.context.identities = ({"id": owner.id, "verified_session_id": None},)
        self.context.flags.discard("verified_sessions")
        blocked = self.advance(run_id)
        self.assertEqual(blocked["run"]["status"], "BLOCKED")
        self.assertEqual(fx.server.received, [])

    def test_crash_after_dispatch_never_replays(self):
        fx = self.fixture
        run_id = self.start(self.plan([self.action()]))
        self.advance(run_id)
        original = fx.executor.execute

        def sent_then_lost(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("simulated process loss after request")

        with patch.object(fx.executor, "execute", side_effect=sent_then_lost):
            recovered = self.advance(run_id)
        self.assertEqual(recovered["run"]["status"], "WAITING_HUMAN")
        self.assertEqual(recovered["run"]["requests_consumed"], 1)
        self.assertEqual(len(fx.server.received), 1)
        self.assertEqual(len(recovered["steps"][1]["result"]["traffic_exchange_ids"]), 1)
        self.assertTrue(recovered["steps"][1]["result"]["evidence_ids"])
        self.assertEqual(PlanRunStore(fx.store).reconcile(), 0)
        with self.assertRaises(PlanRunError):
            self.advance(run_id)
        self.assertEqual(len(fx.server.received), 1)

    def test_ambiguous_post_is_not_retried(self):
        fx = self.fixture
        fx.targets.package = replace(fx.package, autonomy=replace(
            fx.package.autonomy, state_changing=PolicyDecision.ALLOW,
            create_disposable_objects=PolicyDecision.ALLOW))
        run_id = self.start(self.plan([self.action("/create", method="POST", category="OBJECT_CREATE",
                                                 disposable_intent=True, object_type="fixture")]))
        self.advance(run_id)
        original = fx.executor.execute

        def sent_then_lost(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("simulated response loss")

        with patch.object(fx.executor, "execute", side_effect=sent_then_lost):
            recovered = self.advance(run_id)
        self.assertEqual(recovered["run"]["status"], "WAITING_HUMAN")
        self.assertEqual(len(fx.server.received), 1)
        original = recovered["steps"][1]["result"]
        with self.assertRaises(ValueError):
            self.engine.complete_human_step(run_id, fx.package.id, recovered["steps"][1]["id"],
                                            evidence_ids=tuple(original["evidence_ids"]))
        note = fx.store.create_evidence(EvidenceType.EXPERIMENT_RESULT,
                                        b"Independent fixture read-back reviewed by operator.",
                                        source="FIXTURE", target_ref=fx.package.target.id,
                                        provenance=EvidenceProvenance("BUGHUNTER", "manual_review", run_id),
                                        sensitivity=Sensitivity.INTERNAL)
        completed = self.engine.complete_human_step(run_id, fx.package.id,
                                                    recovered["steps"][1]["id"],
                                                    evidence_ids=(note.evidence_id,))
        self.assertEqual(completed["run"]["status"], "COMPLETED")
        self.assertEqual(completed["steps"][1]["result"], original)
        self.assertEqual(completed["steps"][1]["manual_review"]["evidence_ids"], [note.evidence_id])
        with self.assertRaises(PlanRunError):
            self.advance(run_id)
        self.assertEqual(len(fx.server.received), 1)

    def test_pause_cancel_idempotency_and_unsupported_step(self):
        plan_id = self.plan([self.action()])
        first = self.start(plan_id)
        self.assertEqual(self.start(plan_id), first)
        paused = self.engine.pause(first, self.fixture.package.id)
        self.assertEqual(paused["run"]["status"], "PAUSED")
        with self.assertRaises(PlanRunError):
            self.advance(first)
        resumed = self.engine.resume(first, self.fixture.package.id)
        self.assertEqual(resumed["run"]["status"], "READY")
        cancelled = self.engine.cancel(first, self.fixture.package.id)
        self.assertEqual(cancelled["run"]["status"], "CANCELLED")
        self.assertEqual(self.fixture.server.received, [])
        other = self.plan([], workflow=[{"type": "UNKNOWN_STEP", "description": "No code"}])
        run_id = self.start(other)
        self.advance(run_id)
        blocked = self.advance(run_id)
        self.assertEqual(blocked["run"]["status"], "BLOCKED")
        self.assertEqual(blocked["steps"][1]["safe_reason"], "BLOCKED_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
