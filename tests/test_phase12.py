from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import shutil
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from hackbot.config import TargetSettings, load_config
from hackbot.evidence import EvidenceProvenance, EvidenceType, Sensitivity
from hackbot.hypotheses import ContextPacketBuilder, HypothesisGenerator, HypothesisStatus, HypothesisStore
from hackbot.profile import AttackSurfaceProfiler, ProfileLimits, SignalSource
from hackbot.recon import (Page, Provenance, ReconApiSurface, ReconAssetEvent,
                          ReconEndpoint, ReconEndpointJsReference, ReconHost, ReconJsAnalysis, ReconJsAsset,
                          ReconParameter, ReconScanSnapshot, ReconTarget)
from hackbot.service import BugHunterRuntime, create_app
from hackbot.target_scope import ScopeResult


EXAMPLE = Path(__file__).parent / "examples/targets/example"
NOW = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)


def prov(table: str, id: int) -> Provenance:
    return Provenance(table, id, NOW, "fixture")


class FixtureRecon:
    """Finite in-memory recon; any unanticipated method is a test failure."""

    def __init__(self) -> None:
        self.calls = []
        self.hosts = [
            ReconHost(1, 7, "api.example.test", "https://api.example.test", 200, prov("live_hosts", 1)),
            ReconHost(2, 7, "internal.example.test", "https://internal.example.test", 200, prov("live_hosts", 2)),
            ReconHost(3, 7, "billing.example.test", "https://billing.example.test", 200, prov("live_hosts", 3)),
        ]
        self.endpoints = {
            1: [
                ReconEndpoint(11, 1, "/api/projects/{id}", "GET", 200, "fixture", prov("endpoints", 11)),
                ReconEndpoint(12, 1, "/graphql", "POST", 200, "fixture", prov("endpoints", 12)),
                ReconEndpoint(13, 1, "/api/admin/roles", "POST", 403, "fixture", prov("endpoints", 13)),
                ReconEndpoint(14, 1, "/api/reports/download", "GET", 401, "fixture", prov("endpoints", 14)),
                ReconEndpoint(15, 1, "/internal/config", "GET", 200, "fixture", prov("endpoints", 15)),
                ReconEndpoint(16, 1, "/api/users/export", "GET", 403, "fixture", prov("endpoints", 16)),
            ],
            2: [ReconEndpoint(21, 2, "/debug", "GET", 200, "fixture", prov("endpoints", 21))],
            3: [ReconEndpoint(31, 3, "/api/admin", "GET", 200, "fixture", prov("endpoints", 31))],
        }

    def resolve_target(self, name):
        self.calls.append(("resolve_target", name))
        return ReconTarget(7, "example.test", True, True, prov("domains", 7))

    def resolve_host(self, domain_id, exact_url):
        self.calls.append(("resolve_host", exact_url))
        return next((item for item in self.hosts if item.url == exact_url), None)

    def list_hosts(self, domain_id, *, limit, cursor=None):
        self.calls.append(("list_hosts", limit))
        return Page(tuple(self.hosts[:limit]), None)

    def list_endpoints(self, domain_id, host_id, *, limit, cursor=None):
        self.calls.append(("list_endpoints", host_id, limit))
        return Page(tuple(self.endpoints.get(host_id, [])[:limit]), None)

    def list_parameters(self, domain_id, endpoint_id, *, limit, cursor=None):
        self.calls.append(("list_parameters", endpoint_id, limit))
        rows = [ReconParameter(111, endpoint_id, "projectId", (), prov("url_parameters", 111))] if endpoint_id == 11 else []
        return Page(tuple(rows[:limit]), None)

    def list_endpoint_js_references(self, domain_id, endpoint_id, *, limit, cursor=None):
        self.calls.append(("list_endpoint_js_references", endpoint_id, limit))
        rows = [ReconEndpointJsReference(121, 11, 51, prov("endpoint_js_references", 121))] if endpoint_id == 11 else []
        return Page(tuple(rows[:limit]), None)

    def list_js_assets(self, domain_id, host_id, *, limit, cursor=None):
        self.calls.append(("list_js_assets", host_id, limit))
        rows = [ReconJsAsset(51, 1, "https://api.example.test/static/app.js", "a" * 64,
                             1024, 200, prov("js_assets", 51))] if host_id == 1 else []
        return Page(tuple(rows[:limit]), None)

    def get_js_analysis(self, domain_id, asset_id):
        self.calls.append(("get_js_analysis", asset_id))
        return ReconJsAnalysis(61, asset_id, 1000, {"graphql_operations": 2,
            "postmessage_usage": 1, "dangerous_dom_sinks": 1,
            "tokens_or_secret_like_strings": 1}, prov("js_analysis_results", 61))

    def list_api_surfaces(self, domain_id, surface_type, *, limit, cursor=None):
        self.calls.append(("list_api_surfaces", surface_type, limit))
        rows = [ReconApiSurface(71, 7, 1, "graphql", "https://api.example.test/graphql",
                                 200, 2, prov("api_surfaces", 71))] if surface_type == "graphql" else []
        return Page(tuple(rows[:limit]), None)

    def list_scan_snapshots(self, domain_id, *, limit, cursor=None):
        self.calls.append(("list_scan_snapshots", limit))
        return Page((ReconScanSnapshot(81, 7, NOW - timedelta(hours=2), NOW - timedelta(hours=1),
                                       False, prov("scan_snapshots", 81)),), None)

    def list_asset_events(self, domain_id, window_start, window_end, *, limit, cursor=None):
        self.calls.append(("list_asset_events", limit))
        return Page((ReconAssetEvent(91, 7, "new", "endpoint", 11,
                                     "https://api.example.test/api/projects/1", "medium",
                                     prov("asset_events", 91)),), None)


class Phase12Tests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        targets = root / "targets"
        shutil.copytree(EXAMPLE, targets / "example")
        config = replace(load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                              "XDG_STATE_HOME": str(root)}), targets=TargetSettings(targets))
        self.runtime = BugHunterRuntime(config, vnc_ready=lambda: False)
        self.package = self.runtime.package("example")
        self.runtime.registry.register_target(self.package)
        self.runtime.registry.import_package_accounts(self.package)
        self.recon = FixtureRecon()
        self.runtime.recon = self.recon

    def profile(self):
        return AttackSurfaceProfiler(self.runtime.registry, self.runtime.store,
                                     self.runtime.traffic, self.recon).profile(self.package)

    def test_limits_and_target_package_required(self):
        with self.assertRaises(ValueError):
            ProfileLimits(hosts=1000000)
        with self.assertRaises(ValueError):
            AttackSurfaceProfiler(self.runtime.registry, self.runtime.store,
                                  self.runtime.traffic, self.recon).profile(None)

    def test_javascript_heavy_and_source_map_are_sample_indicators(self):
        original = self.recon.list_js_assets
        def many(domain_id, host_id, *, limit, cursor=None):
            if host_id != 1:
                return original(domain_id, host_id, limit=limit, cursor=cursor)
            assets = [ReconJsAsset(i, 1, f"https://api.example.test/static/{i}.js",
                                   str(i) * 64, 1024, 200, prov("js_assets", i)) for i in (51, 52, 53)]
            assets.append(ReconJsAsset(54, 1, "https://api.example.test/static/app.js.map",
                                      "f" * 64, 1024, 200, prov("js_assets", 54)))
            return Page(tuple(assets[:limit]), None)
        self.recon.list_js_assets = many
        profile = self.profile()
        self.assertTrue(profile.javascript_heavy)
        self.assertTrue(profile.message_passing)
        self.assertEqual(profile.source_map_count, 1)
        self.assertEqual(profile.coverage["js_analyses_examined"], 3)

    def test_anonymous_and_authenticated_boundary_from_traffic_metadata(self):
        class FixtureTraffic:
            def list_filtered(self, target_id, *, limit):
                def exchange(number, state):
                    request = SimpleNamespace(origin="https://api.example.test",
                        display_path="/api/projects/{id}",
                        record=SimpleNamespace(method="GET", operation_id=None))
                    return SimpleNamespace(id=f"EX-{number}", request=request,
                        response=SimpleNamespace(record=SimpleNamespace(status_code=200)),
                        attribution=SimpleNamespace(auth_state=SimpleNamespace(value=state)),
                        scope_result=ScopeResult.IN_SCOPE, evidence_ids=(), observed_at=NOW)
                return Page((exchange(1, "ANONYMOUS"), exchange(2, "VERIFIED")), None)
        profile = AttackSurfaceProfiler(self.runtime.registry, self.runtime.store,
                    FixtureTraffic(), None).profile(self.package)
        self.assertIn("ANONYMOUS", profile.boundaries)
        self.assertIn("AUTHENTICATED", profile.boundaries)

    def test_sensitive_fact_values_never_enter_profile_or_hypotheses(self):
        evidence = self.runtime.store.create_evidence(EvidenceType.MANUAL_NOTE, b"secret fixture",
            source="FIXTURE", target_ref=self.package.target.id,
            provenance=EvidenceProvenance("FIXTURE", "secret", "1", NOW, "offline"),
            sensitivity=Sensitivity.SECRET)
        self.runtime.store.create_fact("target:example", "uses_technology", "PrivateCredentialValue",
            confidence=0.8, evidence_ids=(evidence.evidence_id,), source="FIXTURE",
            target_ref=self.package.target.id, sensitivity=Sensitivity.SECRET)
        profile = self.profile()
        self.assertNotIn("PrivateCredentialValue", json.dumps(profile.to_dict()))
        generated = HypothesisGenerator(self.runtime.hypotheses).generate(profile)
        self.assertNotIn("PrivateCredentialValue", json.dumps([item.to_dict() for item in generated]))

    def test_profile_signals_scope_deltas_and_bounded_reads(self):
        profile = self.profile()
        codes = {item.code for item in profile.signals}
        self.assertIn("API_GRAPHQL", codes)
        self.assertIn("API_REST", codes)
        self.assertIn("JS_POSTMESSAGE", codes)
        self.assertIn("BOUNDARY_AUTHENTICATED", codes)
        self.assertIn("HOST_INTERNAL", codes)
        self.assertIn("IDENTITY_CROSS_TENANT_PAIR", codes)
        self.assertIn("IDENTITY_DIFFERENT_ROLE_PAIR", codes)
        self.assertIn("CROSS_ORIGIN_CANDIDATE", profile.boundaries)
        self.assertIn("INTERNAL_EXTERNAL_CANDIDATE", profile.boundaries)
        self.assertIn("OBJECT_OWNERSHIP_UNKNOWN", profile.gaps)
        self.assertIn("project", profile.object_types)
        self.assertEqual(profile.recent_changes, 1)  # several signals from one changed surface
        self.assertFalse(any("billing.example.test" in s.display for s in profile.signals))
        self.assertFalse(any("/internal/config" in s.display for s in profile.signals))
        self.assertLessEqual(profile.coverage["endpoints_examined"], 36)
        self.assertLessEqual(profile.coverage["js_analyses_examined"], 12)
        self.assertTrue(all(call[0] in {"resolve_target", "resolve_host", "list_hosts", "list_endpoints",
                  "list_parameters", "list_endpoint_js_references", "list_js_assets", "get_js_analysis", "list_api_surfaces",
                  "list_scan_snapshots", "list_asset_events"} for call in self.recon.calls))

    def test_rules_evidence_dedup_persistence_and_priority(self):
        ev = self.runtime.store.create_evidence(EvidenceType.JS_SNIPPET, b"fixture only",
            source="FIXTURE", target_ref=self.package.target.id,
            provenance=EvidenceProvenance("FIXTURE", "js_assets", "51", NOW, "offline"))
        self.runtime.store.create_fact("js_asset:51", "js_decoder", "decodeURIComponent",
            confidence=0.8, evidence_ids=(ev.evidence_id,), source="FIXTURE",
            target_ref=self.package.target.id)
        self.runtime.store.create_fact("js_asset:51", "js_messagechannel", "MessageChannel",
            confidence=0.8, evidence_ids=(ev.evidence_id,), source="FIXTURE",
            target_ref=self.package.target.id)
        profile = self.profile()
        self.runtime.hypotheses.save_profile(profile)
        generated = HypothesisGenerator(self.runtime.hypotheses).generate(profile)
        categories = {item.category for item in generated}
        for category in ("CROSS_TENANT", "ROLE_AUTHORIZATION", "GRAPHQL_AUTHORIZATION",
                         "POSTMESSAGE", "DOM_XSS", "EXPOSURE", "INTERNAL_SURFACE"):
            self.assertIn(category, categories)
        self.assertTrue(any("person-level" in item.statement.lower() for item in generated))
        self.assertTrue(all(item.evidence_ids or item.fact_ids for item in generated))
        self.assertTrue(all(item.status is not HypothesisStatus.READY_FOR_EXPERIMENT for item in generated))
        self.assertGreater(next(i.priority for i in generated if i.category == "CROSS_TENANT"),
                           next(i.priority for i in generated if i.category == "EXPOSURE" and "token" in i.statement.lower()))
        second = HypothesisGenerator(self.runtime.hypotheses).generate(profile)
        self.assertEqual({i.id for i in generated}, {i.id for i in second})
        self.assertEqual(len(self.runtime.hypotheses.list(profile.target_id, limit=50)["items"]), len(generated))
        weakened = replace(profile, package_status="PAUSED",
                           signals=tuple(replace(signal, recent=False) for signal in profile.signals))
        revised = HypothesisGenerator(self.runtime.hypotheses).generate(weakened)
        original = next(item for item in generated if item.category == "CROSS_TENANT")
        updated = next(item for item in revised if item.id == original.id)
        self.assertLess(updated.priority, original.priority)
        self.assertEqual(self.runtime.hypotheses.history(original.id, profile.target_id)[0]["event_type"], "REPROFILE")
        with self.assertRaises(ValueError):
            self.runtime.hypotheses.upsert(replace(original, target_id="OTHER-TARGET"))
        no_tenant_pair = replace(profile, signals=tuple(signal for signal in profile.signals
            if signal.code != "IDENTITY_CROSS_TENANT_PAIR"))
        self.assertNotIn("CROSS_TENANT", {item.category for item in
            HypothesisGenerator(self.runtime.hypotheses).generate(no_tenant_pair)})
        self.assertIsNotNone(self.runtime.hypotheses.latest_profile(profile.target_id))
        packet = ContextPacketBuilder(self.runtime.hypotheses).build(generated[0], profile)
        self.assertLessEqual(len(packet["signals"]), 4)
        self.assertLessEqual(len(packet["evidence"]), 6)
        self.assertNotIn("fixture only", json.dumps(packet))

    def test_manual_history_relationship_and_no_confirmation(self):
        store = self.runtime.hypotheses
        a = store.add_manual(self.package.target.id, "AUTHORIZATION", "Review project scope", "Compare owned roles")
        b = store.add_manual(self.package.target.id, "AUTHORIZATION", "Review sharing scope", "Compare owned roles")
        self.assertEqual(a.id, store.add_manual(self.package.target.id, "AUTHORIZATION",
                         "Review project scope", "Compare owned roles").id)
        store.relate(a.id, b.id, "VARIANT_OF", self.package.target.id)
        self.assertEqual(store.relationships(a.id, self.package.target.id)[0]["related_id"], b.id)
        self.assertEqual(store.history(a.id, self.package.target.id)[0]["event_type"], "CREATED")
        with self.assertRaises(ValueError):
            store.add_manual(self.package.target.id, "AUTHORIZATION", "Bearer test-secret", "Review")
        with self.runtime.store._connection() as db:
            with self.assertRaises(Exception):
                db.execute("UPDATE hypotheses SET status='CONFIRMED' WHERE hypothesis_id=?", (a.id,))

    def test_api_requires_package_and_stays_passive(self):
        app = create_app(runtime=self.runtime)
        client = app.test_client()
        self.assertEqual(client.get("/v1/targets/example/profile").get_json()["profile"], None)
        self.assertEqual(client.post("/v1/targets/missing/profile", json={}).status_code, 404)
        response = client.post("/v1/targets/example/profile", json={})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertGreater(response.get_json()["hypotheses_generated"], 0)
        self.assertEqual(client.get("/v1/targets/example/profile").status_code, 200)
        page = client.get("/v1/hypotheses?target=example").get_json()
        self.assertTrue(page["items"])
        item = page["items"][0]
        self.assertEqual(client.get(f"/v1/hypotheses/{item['id']}?target=example").status_code, 200)
        self.assertEqual(client.post("/v1/hypotheses/manual", json={"target": "example",
            "category": "UNKNOWN", "statement": "Review protocol", "future_experiment": "Read docs"}).status_code, 201)
        self.assertEqual(client.get("/v1/hypotheses?target=missing").status_code, 404)
        self.assertTrue(all(not name.startswith(("send", "execute", "replay", "browse")) for name, *_ in self.recon.calls))


if __name__ == "__main__":
    unittest.main()
