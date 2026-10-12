from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from hackbot.config import load_config
from hackbot.policy import PolicyEngine
from hackbot.skill_plans import (PrerequisiteChecker, PrerequisiteState, SkillContext,
                                SkillContextBuilder, SkillPlanStore, SkillPlanner, SkillRouter)
from hackbot.skills import SkillError, SkillRegistry
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import TargetPackageRepository


CATALOG = Path(__file__).resolve().parents[1] / "src/hackbot/skill_catalog"
EXAMPLES = Path(__file__).parent / "examples/targets"


def context(*, flags=(), category="CROSS_TENANT", boundary="TENANT", traffic=(), identities=()):
    return SkillContext("TARGET-11111111111141118111111111111111", "HYP-" + "1" * 32,
                        category, boundary, "/api/objects/owned", (), (), (), (), (),
                        tuple(traffic), tuple(identities), frozenset(flags), ())


def hypothesis(category="CROSS_TENANT", boundary="TENANT"):
    return NS(id="HYP-" + "1" * 32, target_id="TARGET-11111111111141118111111111111111",
              category=category, boundary=boundary, skill_tags=(), surface_key="/api/objects/owned")


class SkillRegistryTests(unittest.TestCase):
    def test_metadata_only_then_selected_body_and_hash(self):
        registry = SkillRegistry(CATALOG)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("body read during discovery")):
            entries = registry.discover()
        self.assertEqual(len(entries), 18)
        self.assertEqual(len({entry.name for entry in entries}), 18)
        selected = registry.select("cross-tenant-object-authorization")
        self.assertEqual(len(selected.content_hash), 64)
        self.assertTrue(selected.controls)
        self.assertTrue(selected.confirmation_requirements)
        self.assertNotIn("methodology", entries[0].to_dict())

    def test_rejects_duplicate_invalid_budget_and_execution_mode(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = CATALOG / "core/authorization/cross-tenant-object-authorization/SKILL.md"
            first = root / "core/authorization/cross-tenant-object-authorization/SKILL.md"
            first.parent.mkdir(parents=True)
            shutil.copy(source, first)
            registry = SkillRegistry(root)
            self.assertEqual(len(registry.discover()), 1)
            second = root / "personal/cross-tenant-object-authorization/SKILL.md"
            second.parent.mkdir(parents=True)
            second.write_text(source.read_text().replace("source: CORE", "source: PERSONAL"))
            with self.assertRaisesRegex(SkillError, "duplicate"):
                registry.discover()
            second.unlink()
            for old, new in (("request_budget: 6", "request_budget: unlimited"),
                             ("risk: MEDIUM", "risk: UNSPECIFIED"),
                             ("execution_mode: PLAN_ONLY", "execution_mode: SHELL"),
                             ("name: cross-tenant-object-authorization", "name: invalid/id")):
                first.write_text(source.read_text().replace(old, new))
                with self.assertRaises(SkillError):
                    registry.discover()
            personal = root / "personal/cross-tenant-object-authorization/SKILL.md"
            first.unlink()
            personal.parent.mkdir(parents=True, exist_ok=True)
            personal.write_text(source.read_text().replace("source: CORE", "source: PERSONAL"))
            self.assertEqual(SkillRegistry(root).select("cross-tenant-object-authorization").metadata.source,
                             "PERSONAL")

    def test_hash_changes_with_body_and_versions_are_retained(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = CATALOG / "core/exposure/internal-surface-candidate/SKILL.md"
            dest = root / "core/exposure/internal-surface-candidate/SKILL.md"
            dest.parent.mkdir(parents=True)
            shutil.copy(source, dest)
            registry = SkillRegistry(root)
            before = registry.select("internal-surface-candidate").content_hash
            dest.write_text(dest.read_text().replace("version: 1.0.0", "version: 1.0.1"))
            with self.assertRaises(SkillError):
                registry.select("internal-surface-candidate")
            registry.discover()
            after = registry.select("internal-surface-candidate")
            self.assertNotEqual(before, after.content_hash)
            self.assertEqual(after.metadata.version, "1.0.1")


class SkillPlanningTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.registry = SkillRegistry(CATALOG)
        self.registry.discover()
        root = Path(self.temp.name)
        config = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                      "XDG_STATE_HOME": str(root)})
        self.store = EvidenceFactStore.from_config(config)
        self.store.initialize()
        self.plans = SkillPlanStore(self.store)
        self.package = TargetPackageRepository(EXAMPLES).get_target_package("example")
        self.assertIsNotNone(self.package)
        self.target = self.package.target.id

    def test_router_bounded_and_distinguishes_graphql_mutation(self):
        router = SkillRouter(self.registry)
        result = router.route(hypothesis("GRAPHQL_AUTHORIZATION", "OWNER"),
                              context(category="GRAPHQL_AUTHORIZATION", boundary="OWNER",
                                      flags={"graphql_operation"}), limit=2)
        self.assertLessEqual(len(result), 2)
        self.assertEqual(result[0]["skill"]["name"], "graphql-object-authorization")
        self.assertIn("graphql-mutation", result[1]["skill"]["name"])
        self.assertFalse(result[0]["metrics_available"])

    def test_prerequisite_states_and_authorization_boundaries(self):
        checker = PrerequisiteChecker()
        cross = self.registry.metadata("cross-tenant-object-authorization")
        flags = set(cross.prerequisites)
        identities = ({"verified_session_id": "BSESSION-a"}, {"verified_session_id": "BSESSION-b"})
        self.assertEqual(checker.check(cross, context(flags=flags, identities=identities)).state,
                         PrerequisiteState.READY)
        flags.remove("multiple_tenants")
        self.assertEqual(checker.check(cross, context(flags=flags, identities=identities)).state,
                         PrerequisiteState.MISSING_IDENTITY)
        flags.add("multiple_tenants")
        flags.remove("known_ownership")
        self.assertEqual(checker.check(cross, context(flags=flags, identities=identities)).state,
                         PrerequisiteState.MISSING_OBJECT)
        horizontal = self.registry.metadata("horizontal-object-authorization")
        self.assertIn("multiple_principals", horizontal.prerequisites)
        self.assertNotIn("multiple_tenants", horizontal.prerequisites)
        vertical = self.registry.metadata("vertical-role-authorization")
        self.assertIn("multiple_roles", vertical.prerequisites)
        self.assertNotIn("multiple_tenants", vertical.prerequisites)
        dom = self.registry.metadata("check-before-transform-dom-xss")
        self.assertEqual(checker.check(dom, context(flags={"in_scope_target"})).state,
                         PrerequisiteState.MISSING_RESEARCH)
        message = self.registry.metadata("postmessage-trust-analysis")
        self.assertNotIn("dangerous_dom_sink", message.prerequisites)
        graph = self.registry.metadata("graphql-object-authorization")
        self.assertIn("graphql_operation", checker.check(graph, context(flags={"in_scope_target"})).missing)
        mutation = self.registry.metadata("graphql-mutation-authorization")
        self.assertIn("graphql_mutation", checker.check(mutation, context(flags={"in_scope_target",
                                                                           "graphql_operation"})).missing)
        download = self.registry.metadata("unauthenticated-sensitive-download")
        self.assertNotIn("anonymous_access", download.prerequisites)
        self.assertEqual(checker.check(download, context(flags=set(download.prerequisites))).state,
                         PrerequisiteState.READY)
        internal = self.registry.metadata("internal-surface-candidate")
        self.assertEqual(internal.request_budget, 0)

    def test_context_is_bounded_and_excludes_evidence_bodies(self):
        evidence = NS(evidence_id="EV-" + "1" * 32, target_ref=self.target,
                      evidence_type="HTTP_RESPONSE", sensitivity=NS(value="SECRET"),
                      raw_body="password=must-not-appear")
        store = NS(get_evidence=lambda _: evidence, get_fact=lambda _: None)
        page = NS(items=(), next_cursor=None)
        registry = NS(list_identities=lambda *args, **kwargs: page)
        traffic = NS(find_recent=lambda *args, **kwargs: page)
        builder = SkillContextBuilder(store, registry, traffic)
        h = NS(id="HYP-" + "1" * 32, target_id=self.target, category="EXPOSURE",
               boundary="AUTHENTICATED", surface_key="/private", evidence_ids=(evidence.evidence_id,) * 20,
               fact_ids=(), missing=())
        built = builder.build(h, None, self.package)
        self.assertEqual(len(built.evidence), 4)
        self.assertNotIn("must-not-appear", str(built.to_dict()))
        self.assertIn("in_scope_target", built.flags)

    def test_context_identity_pair_and_graphql_mutation_are_evidence_based(self):
        identities = [NS(id="IDENTITY-" + char * 32, principal_id="PRINCIPAL-" + char * 32,
                         status=NS(value="ACTIVE")) for char in ("1", "2")]
        memberships = {
            identities[0].id: [NS(tenant_id="TENANT-A", role_ids=("ROLE-ADMIN",), status=NS(value="ACTIVE"))],
            identities[1].id: [NS(tenant_id="TENANT-B", role_ids=("ROLE-MEMBER",), status=NS(value="ACTIVE"))],
        }
        registry = NS(list_identities=lambda *args, **kwargs: NS(items=identities),
                      list_memberships=lambda identity_id, **kwargs: NS(items=memberships[identity_id]))
        req = NS(display_path="/graphql", origin="https://example.test",
                 record=NS(method="POST", endpoint_id=None, operation_id="GraphQLQuery"))
        exchange = NS(id="EXCHANGE-1", request=req,
                      attribution=NS(auth_state=NS(value="VERIFIED"), verified_identity_id=identities[0].id),
                      response=None)
        traffic = NS(find_recent=lambda *args, **kwargs: NS(items=(exchange,)))
        browser = NS(get_session_for_identity=lambda target, identity: NS(id="BSESSION-" + identity[-32:]),
                     session_context=lambda session: NS(authentication_status="VALID", browser_available=True,
                                                        browser_status=NS(value="VALID"),
                                                        verification_status=NS(value="MATCH")))
        builder = SkillContextBuilder(NS(get_evidence=lambda _: None, get_fact=lambda _: None),
                                      registry, traffic, browser)
        h = NS(id="HYP-" + "1" * 32, target_id=self.target, category="GRAPHQL_AUTHORIZATION",
               boundary="TENANT", surface_key="/graphql", evidence_ids=(), fact_ids=(), missing=())
        profile = NS(target_id=self.target, signals=(NS(code="API_GRAPHQL", surface_key="/graphql"),),
                     technologies=("GraphQL",), features=(), recon_domain_id=None)
        built = builder.build(h, profile, self.package)
        self.assertIn("multiple_tenants", built.flags)
        self.assertIn("multiple_roles", built.flags)
        self.assertIn("graphql_operation", built.flags)
        self.assertNotIn("graphql_mutation", built.flags)  # POST is not proof of a mutation.
        self.assertEqual(len(built.traffic), 1)
        memberships[identities[1].id] = memberships[identities[0].id]
        shared = builder.build(h, profile, self.package)
        self.assertNotIn("multiple_tenants", shared.flags)
        mutation = NS(**{**vars(h), "category": "GRAPHQL_MUTATION"})
        self.assertIn("graphql_mutation", builder.build(mutation, profile, self.package).flags)

    def test_plan_dedupe_version_snapshot_and_policy_only(self):
        calls = []
        class FakePolicy:
            def evaluate(self, package, action, *, record):
                calls.append((action, record))
                return NS(to_dict=lambda: {"result": "ALLOW", "reason_code": "TEST"})
        planner = SkillPlanner(self.registry, PrerequisiteChecker(), FakePolicy(), self.plans)
        meta = self.registry.metadata("unauthenticated-sensitive-download")
        ctx = replace(context(category="EXPOSURE", boundary="AUTHENTICATED",
                              flags=meta.prerequisites,
                              traffic=({"method": "GET", "origin": "https://example.com",
                                        "display_path": "/api/objects/owned", "auth_state": "VERIFIED"},)),
                      target_id=self.target)
        h = NS(id=ctx.hypothesis_id, target_id=self.target)
        first = planner.generate(self.package, h, ctx, meta.name)
        self.assertEqual(len(calls), 1)
        self.assertFalse(calls[0][1])
        self.assertEqual(first["proposed_actions"][0]["policy"]["result"], "ALLOW")
        self.assertFalse(first["execution_started"])
        self.assertEqual(first["request_templates"][0]["authentication"], "EXECUTOR_SUPPLIED")
        again = planner.generate(self.package, h, ctx, meta.name)
        self.assertEqual(again["id"], first["id"])
        manual_same = planner.generate(self.package, h, ctx, meta.name, manual_selection=True)
        self.assertEqual(manual_same["id"], first["id"])
        self.assertEqual([entry["manual"] for entry in manual_same["selection_history"]], [False, True])
        regenerated = planner.generate(self.package, h, ctx, meta.name, regenerate=True, manual_selection=True)
        self.assertNotEqual(regenerated["id"], first["id"])
        self.assertTrue(regenerated["manual_selection"])
        self.assertEqual(self.plans.get(first["id"], self.target)["skill_hash"], first["skill_hash"])
        self.assertIsNone(self.plans.get(first["id"], "TARGET-" + "2" * 32))

    def test_real_phase13_policy_is_simulated_without_a_permit(self):
        planner = SkillPlanner(self.registry, PrerequisiteChecker(), PolicyEngine(), self.plans)
        meta = self.registry.metadata("unauthenticated-sensitive-download")
        ctx = replace(context(category="EXPOSURE", boundary="AUTHENTICATED",
                              flags=meta.prerequisites,
                              traffic=({"method": "GET", "origin": "https://example.test",
                                        "display_path": "/api/objects/owned"},)), target_id=self.target)
        plan = planner.generate(self.package, NS(id=ctx.hypothesis_id, target_id=self.target), ctx,
                                meta.name)
        action = plan["proposed_actions"][0]
        self.assertTrue(action["simulation_only"])
        self.assertIn(action["policy"]["result"], {"ALLOW", "DENY", "REQUIRE_APPROVAL"})
        self.assertFalse(plan["execution_started"])
        with self.store._connection() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM executor_permits").fetchone()[0], 0)

    def test_authenticated_action_snapshot_keeps_exact_session_binding(self):
        class AllowPolicy:
            def evaluate(self, package, action, *, record):
                return NS(to_dict=lambda: {"result": "ALLOW", "reason_code": "TEST"})

        selected = replace(self.registry.select("unauthenticated-sensitive-download"),
                           action_intents=("AUTHORIZATION_TEST",))
        registry = NS(select=lambda name: selected)
        planner = SkillPlanner(registry, PrerequisiteChecker(), AllowPolicy(), self.plans)
        identity_id = "IDENTITY-" + "a" * 32
        session_id = "BSESSION-" + "b" * 32
        ctx = replace(context(category="EXPOSURE", boundary="AUTHENTICATED",
                              flags=selected.metadata.prerequisites,
                              identities=({"id": identity_id, "verified_session_id": session_id},),
                              traffic=({"method": "GET", "origin": "https://example.test",
                                        "display_path": "/api/objects/owned"},)), target_id=self.target)
        plan = planner.generate(self.package, NS(id=ctx.hypothesis_id, target_id=self.target), ctx,
                                selected.metadata.name)
        action = plan["proposed_actions"][0]
        self.assertEqual(action["identity_id"], identity_id)
        self.assertEqual(action["session_id"], session_id)
        self.assertEqual(plan["request_templates"][0]["authentication"], "EXECUTOR_SUPPLIED")

    def test_query_and_high_entropy_path_do_not_become_templates(self):
        planner = SkillPlanner(self.registry, PrerequisiteChecker(), PolicyEngine(), self.plans)
        for path in ("/download?token=secret", "/download/abcdefghijklmnopqrstuvwxyz0123456789"):
            ctx = context(traffic=({"method": "GET", "origin": "https://example.test",
                                    "display_path": path},))
            self.assertIsNone(planner._template(ctx))

    def test_authorization_plan_never_chooses_unbound_foreign_object(self):
        class NoPolicy:
            def evaluate(self, *_args, **_kwargs):
                raise AssertionError("unbound authorization request was proposed")
        planner = SkillPlanner(self.registry, PrerequisiteChecker(), NoPolicy(), self.plans)
        meta = self.registry.metadata("cross-tenant-object-authorization")
        identities = ({"verified_session_id": "BSESSION-a", "id": "IDENTITY-a"},
                      {"verified_session_id": "BSESSION-b", "id": "IDENTITY-b"})
        ctx = replace(context(flags=meta.prerequisites, identities=identities,
                              traffic=({"method": "GET", "origin": "https://example.test",
                                        "display_path": "/api/objects/owned"},)), target_id=self.target)
        plan = planner.generate(self.package, NS(id=ctx.hypothesis_id, target_id=self.target), ctx, meta.name)
        self.assertEqual(plan["status"], "NEEDS_ACTOR_OBJECT_BINDING")
        self.assertEqual(plan["proposed_actions"], [])

    def test_static_dom_candidate_is_unvalidated_and_no_request(self):
        class NoPolicy:
            def evaluate(self, *_args, **_kwargs):
                raise AssertionError("no active action should be produced")
        planner = SkillPlanner(self.registry, PrerequisiteChecker(), NoPolicy(), self.plans)
        ctx = replace(context(category="DOM_XSS", boundary="CLIENT_SERVER_TRUST",
                              flags={"in_scope_target", "current_js", "dangerous_dom_sink"}),
                      target_id=self.target)
        plan = planner.generate(self.package, NS(id=ctx.hypothesis_id, target_id=self.target), ctx,
                                "check-before-transform-dom-xss")
        self.assertEqual(plan["status"], "BLOCKED_PREREQUISITES")
        self.assertEqual(plan["finding_status"], "UNVALIDATED")
        self.assertEqual(plan["proposed_actions"], [])

    def test_skill_source_has_no_executor_or_network_imports(self):
        source = (Path(__file__).resolve().parents[1] / "src/hackbot/skills.py").read_text()
        planner = (Path(__file__).resolve().parents[1] / "src/hackbot/skill_plans.py").read_text()
        for forbidden in ("import requests", "import httpx", "import socket", "urllib.request",
                          "TrafficExecutor(", ".executor.execute(", "self.executor.execute("):
            self.assertNotIn(forbidden, source + planner)


if __name__ == "__main__":
    unittest.main()
