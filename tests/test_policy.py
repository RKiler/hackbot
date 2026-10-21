from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import json
import shutil
import unittest
import uuid

from hackbot.browser import BrowserStatus, SessionContext, VerificationStatus
from hackbot.cli import main
from hackbot.config import TargetSettings, load_config
from hackbot.identity import IdentityStatus
from hackbot.policy import (PolicyEngine, ScopeGuard, SideEffectClassifier,
                            policy_version, supervised_hunt_policy)
from hackbot.policy_models import (
    ActionCategory, ActorMode, ApprovalStatus, ProposedAction, SideEffect,
)
from hackbot.policy_store import PolicyStore
from hackbot.rate_limit import ExperimentBudget, RateLimiter
from hackbot.service import BugHunterRuntime, create_app
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package
from hackbot.target_policy import AutonomyPolicy, PolicyDecision, RatePolicy, RiskLevel
from hackbot.target_scope import HostRule, ScopeResult


EXAMPLE = Path(__file__).parent / "examples/targets/example"
NOW = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)
IDENTITY = "IDENTITY-" + "2" * 32
SESSION = "BSESSION-" + "3" * 32


class FakeRegistry:
    def __init__(self, *, status=IdentityStatus.ACTIVE, target_id=None):
        self.status = status
        self.target_id = target_id

    def get_identity(self, target_id, identity_id):
        if self.target_id is not None and target_id != self.target_id:
            return None
        return SimpleNamespace(status=self.status) if identity_id == IDENTITY else None


class FakeBrowser:
    def __init__(self, target_id, *, verified=True, identity_id=IDENTITY):
        self.target_id = target_id
        self.verified = verified
        self.identity_id = identity_id

    def session_context(self, session_id):
        if session_id != SESSION:
            raise ValueError("missing")
        return SessionContext(
            SESSION, self.target_id, self.identity_id, "AUTHCTX-" + "4" * 32,
            BrowserStatus.VALID if self.verified else BrowserStatus.WAITING_LOGIN,
            VerificationStatus.MATCH if self.verified else VerificationStatus.UNVERIFIED,
            self.verified, "VALID" if self.verified else "UNVERIFIED",
            False, False, False, NOW,
        )


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        config = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                      "XDG_STATE_HOME": str(root)})
        self.store = EvidenceFactStore.from_config(config)
        self.store.initialize()
        self.audit = PolicyStore(self.store)
        self.package = load_target_package(EXAMPLE)
        self.target_id = self.package.target.id
        self.engine = PolicyEngine(audit=self.audit)

    def action(self, url="https://api.example.test/api/profile", *,
               category=ActionCategory.SAFE_READ, actor=ActorMode.ANONYMOUS,
               method="GET", **kwargs):
        return ProposedAction(
            target_id=self.target_id, package_id=self.package.id,
            category=category, actor=actor, source="unit_test",
            purpose="Fixture policy check", url=url, method=method,
            created_at=NOW, **kwargs,
        )

    def evaluate(self, action, *, engine=None, package=None):
        return (engine or self.engine).evaluate(package or self.package, action, now=NOW)

    def test_scope_exact_wildcard_exclusion_and_recon_independence(self):
        for url in ("https://example.test/", "https://a.example.test/",
                    "https://deep.a.example.test/"):
            self.assertEqual(self.evaluate(self.action(url)).result, PolicyDecision.ALLOW)
        for url in ("https://billing.example.test/", "https://example.test.attacker.test/",
                    "https://notexample.test/", "https://api.example.test/internal/config"):
            self.assertEqual(self.evaluate(self.action(url)).result, PolicyDecision.DENY)
        # A recon row has no input path into the evaluator; adding one does not authorize a host.
        recon_row = SimpleNamespace(hostname="example.test.attacker.test", status_code=200)
        self.assertEqual(recon_row.status_code, 200)
        self.assertEqual(self.evaluate(self.action("https://" + recon_row.hostname)).reason_code,
                         "HOST_OUT_OF_SCOPE")
        self.assertEqual(self.evaluate(self.action("https://example.test/")).result,
                         PolicyDecision.ALLOW)  # No recon record is required.

    def test_scheme_port_path_case_idna_and_invalid_url(self):
        self.assertEqual(self.evaluate(self.action("HTTPS://API.EXAMPLE.TEST/api/profile")).result,
                         PolicyDecision.ALLOW)
        idna_package = replace(self.package, scope=replace(
            self.package.scope, include_hosts=(HostRule("bücher.example.test"),),
            exclude_hosts=(), exclude_paths=()))
        self.assertEqual(self.evaluate(
            self.action("https://xn--bcher-kva.example.test/"), package=idna_package).result,
            PolicyDecision.ALLOW)
        self.assertEqual(self.evaluate(self.action("https://api.example.test:444/api/profile")).reason_code,
                         "SCHEME_OR_PORT_RESTRICTED")
        self.assertEqual(self.evaluate(self.action("http://api.example.test/api/profile")).reason_code,
                         "SCHEME_OR_PORT_RESTRICTED")
        for url in ("https://api.example.test@evil.test/", "https://api.example.test/%2e%2e/x",
                    "https://api.example.test/a/../b", "https://api.example.test//x",
                    "https://api.example.test/a\\b", "https://api.example.test/?q=%ZZ",
                    "javascript:alert(1)", "https:///missing-host", "https://api.example.test/#x"):
            self.assertEqual(self.evaluate(self.action(url)).result, PolicyDecision.DENY, url)
        self.assertEqual(self.evaluate(self.action("https://api.example.test/INTERNAL")).result,
                         PolicyDecision.ALLOW)
        self.assertEqual(self.evaluate(self.action("https://api.example.test/internalx")).result,
                         PolicyDecision.ALLOW)
        self.assertEqual(self.evaluate(self.action("https://api.example.test/internal")).result,
                         PolicyDecision.DENY)

    def test_redirect_is_rechecked_not_inherited(self):
        action = self.action()
        scope = ScopeGuard()
        self.assertEqual(scope.evaluate(self.package, action).result, ScopeResult.IN_SCOPE)
        self.assertIs(scope.redirect(self.package, action, "https://thirdparty.test/").result,
                      ScopeResult.UNKNOWN)
        redirected = self.engine.evaluate_redirect(
            self.package, action, "https://thirdparty.test/", now=NOW)
        self.assertEqual(redirected.result, PolicyDecision.DENY)
        self.assertNotEqual(redirected.action_id, action.id)

    def test_method_side_effect_and_risk(self):
        classifier = SideEffectClassifier()
        self.assertEqual(classifier.classify(self.action()).side_effect, SideEffect.SAFE_READ)
        self.assertEqual(classifier.classify(self.action(
            category=ActionCategory.HTTP_REQUEST, method="POST")).side_effect, SideEffect.UNKNOWN)
        self.assertEqual(self.evaluate(self.action(
            category=ActionCategory.HTTP_REQUEST, method="POST")).result, PolicyDecision.REQUIRE_APPROVAL)
        self.assertEqual(self.evaluate(self.action(
            category=ActionCategory.SAFE_READ, method="POST")).reason_code, "METHOD_CATEGORY_CONFLICT")
        self.assertEqual(self.evaluate(self.action(
            category=ActionCategory.OBJECT_CREATE, method=None,
            disposable_intent=True)).reason_code, "METHOD_REQUIRED")
        self.assertEqual(self.evaluate(self.action(
            category=ActionCategory.OBJECT_CREATE, method="DELETE",
            disposable_intent=True)).reason_code, "METHOD_CATEGORY_CONFLICT")
        self.assertEqual(self.evaluate(self.action(
            category=ActionCategory.OBJECT_UPDATE, method="DELETE")).reason_code,
            "METHOD_CATEGORY_CONFLICT")
        self.assertEqual(classifier.classify(self.action(
            category=ActionCategory.OBJECT_CREATE, method="POST", disposable_intent=True)).risk,
            RiskLevel.STATE_CHANGING)
        self.assertEqual(classifier.classify(self.action(
            category=ActionCategory.PERMISSION_CHANGE, method="POST")).side_effect,
            SideEffect.PERMISSION_CHANGE)
        self.assertEqual(classifier.classify(self.action(
            category=ActionCategory.FINANCIAL, method="POST")).side_effect, SideEffect.FINANCIAL)
        self.assertEqual(classifier.classify(self.action(
            category=ActionCategory.DESTRUCTIVE, method="DELETE")).risk, RiskLevel.DESTRUCTIVE)
        self.assertEqual(self.evaluate(self.action(category=ActionCategory.FINANCIAL,
                                                   method="POST")).result, PolicyDecision.DENY)
        self.assertEqual(self.evaluate(self.action(category=ActionCategory.DESTRUCTIVE,
                                                   method="DELETE")).result, PolicyDecision.DENY)
        self.assertEqual(self.evaluate(self.action(
            "https://api.example.test/delete", side_effect_hint=SideEffect.SAFE_READ)).result,
            PolicyDecision.REQUIRE_APPROVAL)
        self.assertEqual(self.evaluate(self.action(
            category=ActionCategory.HTTP_REQUEST, method="POST",
            side_effect_hint=SideEffect.FINANCIAL)).result, PolicyDecision.DENY)
        self.assertEqual(self.evaluate(self.action(
            category=ActionCategory.HTTP_REQUEST, method="POST",
            side_effect_hint=SideEffect.SAFE_CREATE)).reason_code, "UNKNOWN_SIDE_EFFECT")
        self.assertEqual(self.evaluate(self.action(
            "https://api.example.test/api/invite", category=ActionCategory.OBJECT_CREATE,
            method="POST", disposable_intent=True)).side_effect, SideEffect.EXTERNAL_SIDE_EFFECT)
        self.assertEqual(self.evaluate(self.action(
            category=ActionCategory.OBJECT_UPDATE, method="PATCH",
            operation="change_role")).side_effect, SideEffect.PERMISSION_CHANGE)
        self.assertEqual(self.evaluate(self.action(
            "https://api.example.test/api/checkout", category=ActionCategory.OBJECT_CREATE,
            method="POST", disposable_intent=True)).result, PolicyDecision.DENY)
        self.assertEqual(self.evaluate(self.action(
            category=ActionCategory.OBJECT_CREATE, method="POST", operation="purge",
            disposable_intent=True)).result, PolicyDecision.DENY)
        self.assertEqual(self.evaluate(self.action(
            operation="credential_stuffing")).reason_code, "PROGRAM_FORBIDDEN_ACTION")
        self.assertEqual(self.evaluate(self.action(
            vulnerability_class="social_engineering")).reason_code, "VULNERABILITY_CLASS_EXCLUDED")

    def test_disposable_ownership_is_trusted_not_client_assertion(self):
        autonomy = replace(self.package.autonomy, state_changing=PolicyDecision.ALLOW,
                           modify_disposable_objects=PolicyDecision.ALLOW,
                           create_disposable_objects=PolicyDecision.ALLOW)
        package = replace(self.package, autonomy=autonomy)
        action = self.action(category=ActionCategory.OBJECT_UPDATE, method="PATCH",
                             object_type="dashboard", object_ref_hash="a" * 64,
                             disposable_intent=True)
        self.assertEqual(self.evaluate(action, package=package).reason_code,
                         "OWNED_DISPOSABLE_OBJECT_REQUIRED")
        owned_engine = PolicyEngine(audit=self.audit, owned_object=lambda _: True)
        self.assertEqual(self.evaluate(action, engine=owned_engine, package=package).result,
                         PolicyDecision.ALLOW)
        create = self.action(category=ActionCategory.OBJECT_CREATE, method="POST",
                             object_type="dashboard", disposable_intent=True)
        self.assertEqual(self.evaluate(create, package=package).result, PolicyDecision.ALLOW)
        account = self.action(category=ActionCategory.OBJECT_CREATE, method="POST",
                              object_type="account", disposable_intent=True)
        self.assertEqual(self.evaluate(account, package=package).result, PolicyDecision.DENY)
        account_policy = replace(package, autonomy=replace(package.autonomy,
                                                           account_creation=PolicyDecision.ALLOW))
        self.assertEqual(self.evaluate(account, package=account_policy).reason_code,
                         "PROGRAM_POLICY_DENY")
        invite_account = self.action(
            "https://api.example.test/api/invite", category=ActionCategory.OBJECT_CREATE,
            method="POST", object_type="account", disposable_intent=True)
        self.assertEqual(self.evaluate(invite_account, package=package).result, PolicyDecision.DENY)
        self.assertEqual(self.evaluate(replace(create, id="ACTION-" + "a" * 32,
                                               disposable_intent=False), package=package).result,
                         PolicyDecision.DENY)

    def test_supervised_context_requires_approval_without_relaxing_package_policy(self):
        package = replace(self.package, autonomy=replace(
            self.package.autonomy, state_changing=PolicyDecision.ALLOW,
            create_disposable_objects=PolicyDecision.ALLOW,
            modify_disposable_objects=PolicyDecision.ALLOW,
            delete_disposable_objects=PolicyDecision.ALLOW))
        create = self.action(category=ActionCategory.OBJECT_CREATE, method="POST",
                             object_type="dashboard", disposable_intent=True)
        self.assertEqual(self.evaluate(create, package=package).result, PolicyDecision.ALLOW)
        with supervised_hunt_policy(package):
            decision = self.evaluate(replace(create, id="ACTION-" + "b" * 32), package=package)
            self.assertEqual(decision.result, PolicyDecision.REQUIRE_APPROVAL)
            self.assertEqual(decision.reason_code, "SUPERVISED_APPROVAL_REQUIRED")
            factory_create = replace(create, id="ACTION-" + "d" * 32,
                                     source="object_factory")
            self.assertEqual(self.evaluate(factory_create, package=package).result,
                             PolicyDecision.ALLOW)
            owned_engine = PolicyEngine(audit=self.audit, owned_object=lambda _: True)
            for category, method, operation in (
                    (ActionCategory.OBJECT_UPDATE, "PATCH", "renameDashboard"),
                    (ActionCategory.OBJECT_DELETE, "DELETE", "deleteDashboard")):
                action = replace(factory_create, id="ACTION-" + uuid.uuid4().hex,
                                 category=category, method=method,
                                 operation=operation, object_ref_hash="a" * 64)
                self.assertEqual(self.evaluate(action, engine=owned_engine,
                                               package=package).result,
                                 PolicyDecision.ALLOW)
            self.assertEqual(self.evaluate(replace(factory_create,
                                                   id="ACTION-" + "e" * 32,
                                                   cross_identity=True),
                                           package=package).result,
                             PolicyDecision.DENY)
            self.assertEqual(self.evaluate(self.action(), package=package).result,
                             PolicyDecision.ALLOW)
            self.assertEqual(self.evaluate(self.action("https://unrelated.test/"),
                                           package=package).result, PolicyDecision.DENY)
            denied = replace(package, autonomy=replace(package.autonomy,
                                                       state_changing=PolicyDecision.DENY))
            self.assertEqual(self.evaluate(self.action(
                category=ActionCategory.OBJECT_CREATE, method="POST",
                object_type="dashboard", disposable_intent=True),
                package=denied).result, PolicyDecision.DENY)
        self.assertEqual(self.evaluate(replace(create, id="ACTION-" + "c" * 32),
                                       package=package).result, PolicyDecision.ALLOW)

    def test_identity_verified_unverified_disabled_wrong_target_anonymous(self):
        action = self.action(actor=ActorMode.AUTHENTICATED, identity_id=IDENTITY, session_id=SESSION)
        verified = PolicyEngine(audit=self.audit, registry=FakeRegistry(),
                                browser=FakeBrowser(self.target_id))
        self.assertEqual(self.evaluate(action, engine=verified).result, PolicyDecision.ALLOW)
        unverified = PolicyEngine(audit=self.audit, registry=FakeRegistry(),
                                  browser=FakeBrowser(self.target_id, verified=False))
        self.assertEqual(self.evaluate(action, engine=unverified).reason_code, "UNVERIFIED_SESSION")
        disabled = PolicyEngine(audit=self.audit, registry=FakeRegistry(status=IdentityStatus.DISABLED),
                                browser=FakeBrowser(self.target_id))
        self.assertEqual(self.evaluate(action, engine=disabled).reason_code, "IDENTITY_NOT_ACTIVE")
        wrong = PolicyEngine(audit=self.audit, registry=FakeRegistry(),
                             browser=FakeBrowser("TARGET-" + "f" * 32))
        self.assertEqual(self.evaluate(action, engine=wrong).reason_code, "SESSION_IDENTITY_MISMATCH")
        self.assertEqual(self.evaluate(self.action()).result, PolicyDecision.ALLOW)

    def test_approval_lifecycle_exact_binding_expiry_duplicate_and_history(self):
        action = self.action(category=ActionCategory.PERMISSION_CHANGE, method="POST",
                             operation="change_role", object_type="role")
        decision = self.evaluate(action)
        self.assertEqual(decision.result, PolicyDecision.REQUIRE_APPROVAL)
        approval = self.audit.get(decision.approval_id, self.target_id, now=NOW)
        self.assertEqual(approval.status, ApprovalStatus.PENDING)
        approved = self.audit.decide(approval.id, self.target_id, approve=True, now=NOW)
        self.assertEqual(approved.status, ApprovalStatus.APPROVED_ONCE)
        self.assertEqual(self.audit.decide(approval.id, self.target_id, approve=True, now=NOW).status,
                         ApprovalStatus.APPROVED_ONCE)
        allowed = self.evaluate(action)
        self.assertEqual(allowed.reason_code, "APPROVED_ONCE")
        self.assertFalse(self.audit.claim_once(replace(action, id="ACTION-" + "a" * 32),
                                               policy_version(self.package), approval.id, now=NOW))
        self.assertFalse(self.audit.claim_once(action, "wrong-policy", approval.id, now=NOW))
        self.assertTrue(self.audit.claim_once(action, policy_version(self.package), approval.id, now=NOW))
        self.assertFalse(self.audit.claim_once(action, policy_version(self.package), approval.id, now=NOW))
        self.assertEqual(self.audit.get(approval.id, self.target_id, now=NOW).status, ApprovalStatus.CONSUMED)
        self.assertGreaterEqual(len(self.audit.history(self.target_id, action.id)), 5)
        with self.assertRaises(LookupError):
            self.audit.decide(approval.id, "TARGET-" + "f" * 32, approve=True, now=NOW)
        second = self.action(category=ActionCategory.PERMISSION_CHANGE, method="POST")
        second_decision = self.evaluate(second)
        self.assertEqual(self.audit.decide(second_decision.approval_id, self.target_id,
                                           approve=False, now=NOW).status, ApprovalStatus.REJECTED)
        expired = self.action(category=ActionCategory.PERMISSION_CHANGE, method="POST")
        expired_decision = self.evaluate(expired)
        self.assertEqual(self.audit.decide(expired_decision.approval_id, self.target_id,
                                           approve=True, now=NOW + timedelta(hours=1)).status,
                         ApprovalStatus.EXPIRED)

    def test_approval_does_not_bypass_rate_policy(self):
        action = self.action(category=ActionCategory.PERMISSION_CHANGE, method="POST")
        pending = self.evaluate(action)
        self.audit.decide(pending.approval_id, self.target_id, approve=True, now=NOW)
        limiter = RateLimiter(clock=lambda: 0.0)
        reserved = limiter.reserve(self.target_id, self.package.rate)
        self.assertTrue(reserved.allowed)
        engine = PolicyEngine(audit=self.audit, rate=limiter)
        self.assertEqual(self.evaluate(action, engine=engine).result, PolicyDecision.DENY)

    def test_audit_excludes_raw_url_and_secret_value(self):
        action = self.action("https://api.example.test/api/profile?token=SENSITIVE_TEST_VALUE")
        decision = self.evaluate(action)
        self.assertEqual(decision.result, PolicyDecision.ALLOW)
        with self.store._connection() as db:
            rows = db.execute(
                "SELECT sql FROM sqlite_master WHERE name IN ('policy_actions','policy_decisions')"
            ).fetchall()
            values = db.execute("SELECT * FROM policy_actions").fetchall()
        self.assertNotIn("SENSITIVE_TEST_VALUE", str([tuple(row) for row in values]))
        self.assertNotIn("SENSITIVE_TEST_VALUE", json.dumps(decision.to_dict()))
        self.assertNotIn("url", " ".join(row["sql"] for row in rows).lower())


class RateTests(unittest.TestCase):
    def test_burst_per_target_minute_concurrency_and_budgets(self):
        now = [0.0]
        limiter = RateLimiter(clock=lambda: now[0])
        policy = RatePolicy(requests_per_second=1, requests_per_minute=2,
                            max_concurrency=1, burst=2)
        first = limiter.reserve("target-a", policy, experiment_id="exp")
        self.assertTrue(first.allowed)
        self.assertEqual(limiter.reserve("target-a", policy).reason_code, "CONCURRENCY_LIMIT")
        self.assertEqual(limiter.retry_after_seconds("target-a", policy), 0.1)
        self.assertTrue(limiter.reserve("target-b", policy).allowed)
        self.assertTrue(limiter.release(first.reservation_id))
        second = limiter.reserve("target-a", policy, experiment_id="exp")
        self.assertTrue(second.allowed)
        limiter.release(second.reservation_id)
        now[0] = 1.0
        self.assertEqual(limiter.reserve("target-a", policy).reason_code, "RATE_PER_MINUTE")
        self.assertAlmostEqual(limiter.retry_after_seconds("target-a", policy), 59.0)
        now[0] = 60.0
        self.assertEqual(limiter.retry_after_seconds("target-a", policy), 0.0)
        self.assertTrue(limiter.reserve("target-a", policy).allowed)
        limited = RateLimiter(clock=lambda: now[0])
        budget = ExperimentBudget(max_requests=1, max_mutations=1, max_creations=1, max_retries=0)
        one = limited.reserve("target-c", policy, experiment_id="exp", budget=budget, mutation=True)
        self.assertTrue(one.allowed)
        limited.release(one.reservation_id)
        self.assertEqual(limited.reserve("target-c", policy, experiment_id="exp",
                                         budget=budget).reason_code, "EXPERIMENT_REQUEST_BUDGET")
        self.assertIsNone(limited.retry_after_seconds(
            "target-c", policy, experiment_id="exp", budget=budget))


class PolicyApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        targets = root / "targets"
        shutil.copytree(EXAMPLE, targets / "example")
        config = replace(load_config(environ={
            "HOME": str(root), "XDG_CONFIG_HOME": str(root), "XDG_STATE_HOME": str(root),
        }), targets=TargetSettings(targets))
        self.runtime = BugHunterRuntime(config, vnc_ready=lambda: False)
        self.client = create_app(runtime=self.runtime).test_client()

    def test_policy_display_simulation_approval_and_safe_serialization(self):
        policy = self.client.get("/v1/targets/example/policy")
        self.assertEqual(policy.status_code, 200)
        self.assertEqual(policy.json["authority"], "TARGET_PACKAGE")
        self.assertEqual(policy.json["autonomy"]["financial"], "DENY")
        self.assertEqual(policy.json["rate"]["requests_per_minute"], 30)
        body = {
            "target": "example", "category": "PERMISSION_CHANGE", "actor": "ANONYMOUS",
            "url": "https://api.example.test/api/roles?token=PRIVATE_TEST_MARKER",
            "method": "POST", "operation": "change_role",
        }
        response = self.client.post("/v1/policy/evaluate", json=body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["decision"]["result"], "REQUIRE_APPROVAL")
        self.assertTrue(response.json["simulation_only"])
        self.assertFalse(response.json["request_sent"])
        self.assertNotIn(b"PRIVATE_TEST_MARKER", response.data)
        approval_id = response.json["decision"]["approval_id"]
        listed = self.client.get("/v1/approvals?target=example")
        self.assertEqual(listed.json["items"][0]["id"], approval_id)
        self.assertNotIn(b"PRIVATE_TEST_MARKER", listed.data)
        approved = self.client.post(f"/v1/approvals/{approval_id}/approve", json={"target": "example"})
        self.assertEqual(approved.json["approval"]["status"], "APPROVED_ONCE")
        self.assertFalse(approved.json["execution_started"])
        same_action = self.client.post("/v1/policy/evaluate", json={
            **body, "action_id": response.json["action_id"],
        })
        self.assertEqual(same_action.json["decision"]["reason_code"], "APPROVED_ONCE")
        self.assertEqual(self.client.post("/v1/policy/evaluate", json={
            **body, "action_id": response.json["action_id"], "url": "https://api.example.test/other",
        }).status_code, 400)
        self.assertEqual(self.client.post(f"/v1/approvals/{approval_id}/approve",
                                          json={"target": "example"}).status_code, 200)
        self.assertEqual(self.client.post(f"/v1/approvals/{approval_id}/reject",
                                          json={"target": "example"}).status_code, 400)
        history = self.client.get(f"/v1/policy/actions/{response.json['action_id']}/history?target=example")
        self.assertEqual(history.status_code, 200)
        self.assertGreaterEqual(len(history.json["items"]), 4)
        self.assertNotIn(b"PRIVATE_TEST_MARKER", history.data)

    def test_api_cannot_trust_client_scope_or_risk(self):
        body = {"target": "example", "category": "SAFE_READ", "actor": "ANONYMOUS",
                "url": "https://example.test.attacker.test/", "method": "GET",
                "requested_risk": "PASSIVE"}
        response = self.client.post("/v1/policy/evaluate", json=body)
        self.assertEqual(response.json["decision"]["result"], "DENY")
        self.assertEqual(response.json["decision"]["reason_code"], "HOST_OUT_OF_SCOPE")
        body["url"] = "https://api.example.test/api/profile"
        body["category"] = "FINANCIAL"
        body["method"] = "POST"
        self.assertEqual(self.client.post("/v1/policy/evaluate", json=body).json["decision"]["result"],
                         "DENY")
        body["category"] = "SAFE_READ"
        body["method"] = "GET"
        body["actor"] = "AUTHENTICATED"
        body["identity_id"] = IDENTITY
        body["session_id"] = SESSION
        self.assertEqual(self.client.post("/v1/policy/evaluate", json=body).json["decision"]["result"],
                         "DENY")
        self.assertEqual(self.client.post("/v1/policy/evaluate", json={**body, "scope_ok": True}).status_code,
                         400)

    def test_cli_policy_check_and_approvals_list_are_local(self):
        root = Path(self.temp.name)
        config_file = root / "config.toml"
        config_file.write_text('[targets]\nroot = "' + str(root / "targets") + '"\n')
        environment = {
            "HOME": str(root), "XDG_CONFIG_HOME": str(root), "XDG_STATE_HOME": str(root),
        }
        out, err = StringIO(), StringIO()
        code = main(["--config", str(config_file), "policy", "check", "example",
                     "https://api.example.test/api/profile?token=CLI_SECRET_MARKER",
                     "--action", "safe-read"], environ=environment, stdout=out, stderr=err)
        self.assertEqual((code, err.getvalue()), (0, ""))
        self.assertEqual(json.loads(out.getvalue())["decision"]["result"], "ALLOW")
        self.assertNotIn("CLI_SECRET_MARKER", out.getvalue())
        out, err = StringIO(), StringIO()
        code = main(["--config", str(config_file), "approvals", "list", "example"],
                    environ=environment, stdout=out, stderr=err)
        self.assertEqual((code, err.getvalue()), (0, ""))
        self.assertEqual(json.loads(out.getvalue())["items"], [])


if __name__ == "__main__":
    unittest.main()
