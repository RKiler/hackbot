"""Phase 26 inventory uses only local captured traffic and saved JS fixtures."""

from __future__ import annotations

import unittest
import hashlib
import json
from datetime import timedelta

from hackbot.api_registry import APICandidate, APIOperationRegistry, APIOperationType
from hackbot.api_specialist import APIAnalysisLimits, APISpecialist
from hackbot.domxss_store import DOMXSSStore
from hackbot.domain import TrafficSource
from hackbot.evidence import EvidenceProvenance
from hackbot.traffic import CapturedRequest, CapturedResponse
from tests import test_behaviour as _behaviour_fixture


class APISpecialistInventoryTests(unittest.TestCase):
    def setUp(self):
        self.fx = _behaviour_fixture.BehaviourTests(
            methodName="test_role_feature_absence_is_not_denial_and_explicit_denial_is_recorded")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.js = DOMXSSStore(self.fx.evidence)
        self.registry = APIOperationRegistry(self.fx.evidence)
        self.specialist = APISpecialist(registry=self.registry, traffic=self.fx.traffic,
                                        evidence=self.fx.evidence, js=self.js,
                                        behaviour=self.fx.ledger)

    def test_observed_graphql_and_saved_js_without_target_requests(self):
        _, session = self.fx.session("admin_a", self.fx.tenant_a, self.fx.admin)
        before = len(self.fx.driver.running)
        exchange = self.fx.capture("https://app.example.test/graphql", session=session,
            method="POST", request_body=(b'{"operationName":"GetProject",'
            b'"query":"query GetProject($id:ID!){node(id:$id){id name __typename}}",'
            b'"variables":{"id":"fixture-owned"}}'),
            body=b'{"data":{"node":{"id":"fixture-owned","name":"fixture",'
                 b'"__typename":"Project"}}}')
        js_body = b"const query=gql`query HiddenProject($id:ID!){node(id:$id){id name}}`;"
        self.js.record_artifact(target_id=self.fx.target,
            asset_url="https://app.example.test/static/app.js",
            body=js_body, recon_asset_id=None,
            recon_sha256=hashlib.sha256(js_body).hexdigest(), source="FIXTURE")
        summary = self.specialist.profile(self.fx.package, limits=APIAnalysisLimits(
            traffic=5, js_assets=5, recon_surfaces=3, candidates=8))
        operations = self.registry.list_operations(self.fx.target)
        self.assertIn("GRAPHQL_QUERY", summary["surface_types"])
        self.assertEqual(len(operations), 2)
        observed = next(item for item in operations if item.name == "GetProject")
        self.assertEqual(observed.exchange_ids, (exchange.id,))
        self.assertEqual(observed.identity_ids, (session.identity_id,))
        self.assertEqual(observed.variables, ("id",))
        self.assertEqual(observed.to_dict()["returned_object_types"], ["Project"])
        name_field = next(field for field in observed.fields if field.name == "name")
        self.assertEqual(name_field.parent_type, "Project")
        self.assertEqual(name_field.observed_identity_ids, (session.identity_id,))
        hidden = next(item for item in operations if item.name == "HiddenProject")
        self.assertEqual(hidden.endpoint, "")
        self.assertTrue(hidden.source_asset_hash)
        self.assertEqual(len(self.fx.driver.running), before)

    def test_js_only_name_collision_does_not_borrow_observed_endpoint(self):
        self.fx.capture("https://app.example.test/graphql", method="POST",
                        request_body=(b'{"operationName":"SharedName","query":'
                                      b'"query SharedName($id:ID!){node(id:$id){id name}}",'
                                      b'"variables":{"id":"fixture-owned"}}'),
                        body=b'{"data":{"node":{"id":"fixture-owned","name":"fixture"}}}')
        js_body = b"const query=gql`query SharedName($id:ID!){node(id:$id){id privateNote}}`;"
        self.js.record_artifact(target_id=self.fx.target,
            asset_url="https://app.example.test/static/other.js",
            body=js_body, recon_asset_id=None,
            recon_sha256=hashlib.sha256(js_body).hexdigest(), source="FIXTURE")
        self.specialist.profile(self.fx.package)
        operations = [item for item in self.registry.list_operations(self.fx.target)
                      if item.name == "SharedName"]
        self.assertEqual(len(operations), 2)
        self.assertEqual(sum(bool(item.endpoint) for item in operations), 1)
        js_operation = next(item for item in operations if item.source_asset_hash)
        self.assertEqual(js_operation.endpoint, "")
        self.assertEqual(js_operation.exchange_ids, ())

    def test_manual_context_is_target_scoped_and_never_executable(self):
        proof = self.fx.evidence.create_evidence(
            "API_HYPOTHESIS", b"Synthetic researcher note about an API route",
            source="RESEARCHER", provenance=EvidenceProvenance("RESEARCHER", "note"),
            target_ref=self.fx.target)
        before = len(self.fx.driver.running)
        hint = self.specialist.record_manual_hint(
            self.fx.package, endpoint="https://app.example.test/api/v1/admin/export",
            evidence_id=proof.evidence_id, name="ExportHint", method="POST")
        self.assertEqual(hint.type, APIOperationType.UNKNOWN)
        self.assertEqual(hint.exchange_ids, ())
        self.assertEqual(hint.evidence_ids, (proof.evidence_id,))
        candidates = self.specialist.generate(self.fx.package)
        manual = next(item for item in candidates if item.operation_id == hint.id)
        self.assertEqual(manual.status, "PLAN_ONLY")
        self.assertIn("OPERATION_DOCUMENT_MISSING", manual.gaps)
        self.assertEqual(len(self.fx.driver.running), before)
        with self.assertRaises(ValueError):
            self.specialist.record_manual_hint(
                self.fx.package, endpoint="https://outsider.invalid/api/v1/admin/export",
                evidence_id=proof.evidence_id)
        with self.assertRaises(ValueError):
            self.specialist.record_manual_hint(
                self.fx.package, endpoint="https://app.example.test/api/v1/admin/export?token=bad",
                evidence_id=proof.evidence_id)

    def test_hidden_rest_route_from_current_js_is_a_plan_only_hint(self):
        body = b"fetch('/api/v1/admin/export',{method:'POST'});"
        self.js.record_artifact(target_id=self.fx.target,
            asset_url="https://app.example.test/static/admin.js", body=body,
            recon_asset_id=None, recon_sha256=hashlib.sha256(body).hexdigest(),
            source="FIXTURE")
        before = len(self.fx.driver.running)
        candidates = self.specialist.generate(self.fx.package)
        operation = next(item for item in self.registry.list_operations(self.fx.target)
                         if item.name == "JS_POST_api_v1_admin_export")
        self.assertEqual(operation.type, APIOperationType.REST)
        self.assertEqual(operation.endpoint, "/api/v1/admin/export")
        self.assertEqual(operation.exchange_ids, ())
        lead = next(item for item in candidates if item.operation_id == operation.id)
        self.assertEqual(lead.status, "PLAN_ONLY")
        self.assertIn("CONTROL_MISSING", lead.gaps)
        self.assertEqual(len(self.fx.driver.running), before)

    def test_replaced_js_retires_removed_operation_and_candidate_without_requests(self):
        asset_url = "https://app.example.test/static/replaced.js"
        original = b"fetch('/api/v1/admin/export',{method:'POST'});"
        replacement = b"window.applicationVersion='next';"
        self.js.record_artifact(target_id=self.fx.target, asset_url=asset_url,
            body=original, recon_asset_id=None,
            recon_sha256=hashlib.sha256(original).hexdigest(), source="FIXTURE")
        candidates = self.specialist.generate(self.fx.package)
        operation = next(item for item in self.registry.list_operations(self.fx.target)
                         if item.name == "JS_POST_api_v1_admin_export")
        lead = next(item for item in candidates if item.operation_id == operation.id)
        self.assertEqual(lead.status, "PLAN_ONLY")
        before = len(self.fx.driver.running)
        self.js.record_artifact(target_id=self.fx.target, asset_url=asset_url,
            body=replacement, recon_asset_id=None,
            recon_sha256=hashlib.sha256(replacement).hexdigest(), source="FIXTURE")
        self.specialist.profile(self.fx.package)
        self.assertEqual(self.registry.get_operation(self.fx.target, operation.id).state, "STALE")
        self.assertEqual(self.registry.get_candidate(self.fx.target, lead.id).status, "STALE")
        self.assertEqual(len(self.fx.driver.running), before)

        reintroduced = b"fetch('/api/v1/admin/export',{method:'POST'});window.version='3';"
        self.js.record_artifact(target_id=self.fx.target, asset_url=asset_url,
            body=reintroduced, recon_asset_id=None,
            recon_sha256=hashlib.sha256(reintroduced).hexdigest(), source="FIXTURE")
        refreshed = self.specialist.generate(self.fx.package)
        current = self.registry.get_operation(self.fx.target, operation.id)
        self.assertEqual(current.state, "CURRENT")
        self.assertEqual(self.registry.get_candidate(self.fx.target, lead.id).status,
                         "PLAN_ONLY")
        self.assertIn(lead.id, {item.id for item in refreshed})
        self.assertEqual(len(self.fx.driver.running), before)

    def test_js_reconciliation_preserves_traffic_observed_operation(self):
        exchange = self.fx.capture("https://app.example.test/api/v1/projects/owned",
                                   method="GET", body=b'{"id":"owned"}')
        self.specialist.profile(self.fx.package)
        operation = next(item for item in self.registry.list_operations(self.fx.target)
                         if exchange.id in item.exchange_ids)
        self.assertEqual(self.registry.expire_missing_js_operations(self.fx.target), 0)
        self.assertEqual(self.registry.get_operation(self.fx.target, operation.id).state,
                         "CURRENT")

    def test_candidate_is_gap_labeled_without_owned_object(self):
        self.fx.capture("https://app.example.test/api/v1/projects/owned", method="GET",
                        body=b'{"id":"owned"}')
        candidates = self.specialist.generate(self.fx.package, limits=APIAnalysisLimits(
            traffic=5, js_assets=5, recon_surfaces=3, candidates=8))
        self.assertTrue(candidates)
        self.assertTrue(all("OBJECT_OWNERSHIP_UNKNOWN" in item.gaps for item in candidates))
        self.assertTrue(all(item.status == "PLAN_ONLY" for item in candidates))
        self.assertLessEqual(len(candidates), 8)

    def test_captured_credentials_do_not_enter_api_metadata(self):
        _, session = self.fx.session("admin_a", self.fx.tenant_a, self.fx.admin)
        secret = "FixtureBearer-9a8b7c6d5e4f3g2h"
        request = self.fx.traffic.store_request(
            self.fx.package, CapturedRequest(
                "POST", "https://app.example.test/graphql",
                headers=(("Authorization", "Bearer " + secret),
                         ("Cookie", "sid=" + secret),
                         ("Content-Type", "application/json")),
                body=json.dumps({"query": "query GetProject($id:ID!){node(id:$id){id name}}",
                                 "variables": {"id": "fixture-owned"},
                                 "operationName": "GetProject"}).encode()),
            source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
            browser_manager=self.fx.browser, browser_session_id=session.id,
            auth_material_observed=True)
        self.fx.traffic.store_response(request.id, CapturedResponse(
            200, (("Content-Type", "application/json"),),
            b'{"data":{"node":{"id":"fixture-owned","name":"synthetic"}}}'))
        candidates = self.specialist.generate(self.fx.package)
        operations = self.registry.list_operations(self.fx.target)
        self.assertTrue(operations)
        serialized = json.dumps({"operations": [item.to_dict() for item in operations],
                                 "candidates": [item.to_dict() for item in candidates]})
        self.assertNotIn(secret, serialized)
        self.assertNotIn("Bearer ", serialized)
        self.assertNotIn("sid=", serialized)

    def test_candidate_preserves_exact_behaviour_run_provenance(self):
        _, session = self.fx.session("admin_a", self.fx.tenant_a, self.fx.admin)
        self.fx.capture("https://app.example.test/api/v1/projects/owned", session=session,
                        method="GET", body=b'{"id":"owned"}')
        _, learned = self.fx.learn()
        candidates = self.specialist.generate(self.fx.package)
        self.assertTrue(candidates)
        self.assertTrue(all(item.behaviour_run_id == learned.run_id for item in candidates))

    def test_multi_root_graphql_query_cannot_be_ready_for_read_binding(self):
        _, session = self.fx.session("admin_a", self.fx.tenant_a, self.fx.admin)
        self.fx.capture("https://app.example.test/graphql", session=session, method="POST",
            request_body=(b'{"operationName":"Mixed","query":'
                          b'"query Mixed($id:ID!){node(id:$id){id} account{id email}}",'
                          b'"variables":{"id":"fixture-owned"}}'),
            body=b'{"data":{"node":{"id":"fixture-owned"},"account":null}}')
        candidates = self.specialist.generate(self.fx.package)
        self.assertTrue(candidates)
        self.assertTrue(all("EXACT_SINGLE_ROOT_REQUIRED" in item.gaps
                            for item in candidates if item.category in {"OBJECT_AUTH", "FIELD_AUTH"}))
        self.assertTrue(all(item.status != "READY" for item in candidates))

    def test_unverified_imported_javascript_is_not_operation_authority(self):
        body = b"const q=gql`query ForeignUsers { users { id } }`;"
        self.js.record_artifact(target_id=self.fx.target,
            asset_url="https://unrelated.example.invalid/app.js", body=body,
            recon_asset_id=None, recon_sha256=hashlib.sha256(body).hexdigest(),
            source="IMPORTED")
        before = self.registry.counts(self.fx.target)["operations_current"]
        summary = self.specialist.profile(self.fx.package)
        self.assertEqual(self.registry.counts(self.fx.target)["operations_current"], before)
        self.assertIn("JS_SCOPE_UNVERIFIED", summary["gaps"])

    def test_observed_query_selection_variants_remain_current(self):
        _, session = self.fx.session("admin_a", self.fx.tenant_a, self.fx.admin)
        self.fx.capture("https://app.example.test/graphql", session=session, method="POST",
            request_body=b'{"operationName":"GetProject","query":"query GetProject{id}"}',
            body=b'{"data":{"id":"one"}}')
        self.specialist.profile(self.fx.package)
        first = self.registry.list_operations(self.fx.target)[0]
        self.fx.capture("https://app.example.test/graphql", session=session, method="POST",
            request_body=b'{"operationName":"GetProject","query":"query GetProject{id name}"}',
            body=b'{"data":{"id":"one","name":"fixture"}}')
        self.specialist.profile(self.fx.package)
        self.assertEqual(self.registry.get_operation(self.fx.target, first.id).state, "CURRENT")
        self.assertEqual(self.registry.counts(self.fx.target)["operations_current"], 2)

    def test_retired_traffic_template_requires_a_new_exact_capture_to_reopen(self):
        _, session = self.fx.session("admin_a", self.fx.tenant_a, self.fx.admin)
        request_body = b'{"operationName":"Read","query":"query Read{id}"}'
        response_body = b'{"data":{"id":"fixture"}}'
        self.fx.capture("https://app.example.test/graphql", session=session,
                        method="POST", request_body=request_body, body=response_body)
        self.specialist.profile(self.fx.package)
        operation = next(item for item in self.registry.list_operations(self.fx.target)
                         if item.name == "Read")
        with self.fx.evidence._connection() as db:
            db.execute("UPDATE api_operations SET state='STALE' WHERE operation_id=?",
                       (operation.id,))
        self.specialist.profile(self.fx.package)
        self.assertEqual(self.registry.get_operation(self.fx.target, operation.id).state,
                         "STALE")
        self.fx.capture("https://app.example.test/graphql", session=session,
                        method="POST", request_body=request_body, body=response_body,
                        observed_at=_behaviour_fixture.NOW + timedelta(seconds=1))
        self.specialist.profile(self.fx.package)
        self.assertEqual(self.registry.get_operation(self.fx.target, operation.id).state,
                         "CURRENT")
        self.assertEqual(len(self.registry.get_operation(self.fx.target, operation.id).exchange_ids), 2)

    def test_bounded_exchange_refs_keep_recent_capture_and_old_replay_stays_stale(self):
        args = dict(target_id=self.fx.target, package_id=self.fx.package.id,
                    name="Read", kind=APIOperationType.GRAPHQL_QUERY,
                    endpoint="https://app.example.test/graphql", method="POST",
                    version_hash="a" * 64)
        for index in range(17):
            operation = self.registry.upsert_operation(
                **args, exchange_ids=(f"exchange-{index}",),
                observed_at=f"2026-01-01T00:00:{index:02d}+00:00")
        self.assertEqual(len(operation.exchange_ids), 16)
        self.assertEqual(operation.exchange_ids[0], "exchange-16")
        self.assertNotIn("exchange-0", operation.exchange_ids)
        with self.fx.evidence._connection() as db:
            db.execute("UPDATE api_operations SET state='STALE' WHERE operation_id=?",
                       (operation.id,))
        replay = self.registry.upsert_operation(
            **args, exchange_ids=("exchange-0",),
            observed_at="2026-01-01T00:00:00+00:00")
        self.assertEqual(replay.state, "STALE")
        self.assertNotIn("exchange-0", replay.exchange_ids)
        fresh = self.registry.upsert_operation(
            **args, exchange_ids=("exchange-17",),
            observed_at="2026-01-01T00:00:17+00:00")
        self.assertEqual(fresh.state, "CURRENT")
        self.assertEqual(fresh.exchange_ids[0], "exchange-17")

    def test_inventory_continues_through_older_traffic_without_network_requests(self):
        for index in range(4):
            self.fx.capture(f"https://app.example.test/api/v1/page_{index}",
                            observed_at=_behaviour_fixture.NOW + timedelta(seconds=index))
        before = len(self.fx.driver.running)
        limits = APIAnalysisLimits(traffic=1, js_assets=1, recon_surfaces=1, candidates=4)
        for expected in range(1, 5):
            self.specialist.profile(self.fx.package, limits=limits)
            self.assertEqual(self.registry.counts(self.fx.target)["operations_current"], expected)
        self.assertIsNone(self.registry.progress(self.fx.target,
                                                self.fx.package.id).traffic_cursor)
        self.assertEqual(len(self.fx.driver.running), before)

    def test_inventory_continues_through_older_current_js_assets(self):
        for index in range(4):
            body = ("const q=gql`query Hidden" + str(index) +
                    "($id:ID!){node(id:$id){id}}`;").encode()
            self.js.record_artifact(target_id=self.fx.target,
                asset_url=f"https://app.example.test/static/chunk-{index}.js",
                body=body, recon_asset_id=None,
                recon_sha256=hashlib.sha256(body).hexdigest(), source="FIXTURE")
        limits = APIAnalysisLimits(traffic=1, js_assets=1, recon_surfaces=1, candidates=4)
        for expected in range(1, 5):
            self.specialist.profile(self.fx.package, limits=limits)
            self.assertEqual(self.registry.counts(self.fx.target)["operations_current"], expected)
        self.assertIsNone(self.registry.progress(self.fx.target,
                                                self.fx.package.id).js_cursor)
        _, cursor = self.js.page_current_assets(self.fx.target, limit=1)
        self.assertIsNotNone(cursor)
        with self.assertRaisesRegex(ValueError, "cursor"):
            self.js.page_current_assets("TARGET-other", limit=1, cursor=cursor)

    def test_dense_js_asset_does_not_trap_inventory_on_one_page(self):
        older = b"const older=gql`query Older($id:ID!){node(id:$id){id}}`;"
        newer = b"".join(
            (f"const q{index}=gql`query New{index}($id:ID!)"
             "{node(id:$id){id}}`;").encode()
            for index in range(5))
        for name, body in (("older", older), ("newer", newer)):
            self.js.record_artifact(target_id=self.fx.target,
                asset_url=f"https://app.example.test/static/{name}.js",
                body=body, recon_asset_id=None,
                recon_sha256=hashlib.sha256(body).hexdigest(), source="FIXTURE")
        limits = APIAnalysisLimits(traffic=1, js_assets=1, recon_surfaces=1, candidates=4)
        first = self.specialist.profile(self.fx.package, limits=limits)
        self.assertIn("JS_EXTRACTION_LIMIT", first["gaps"])
        self.assertIsNotNone(self.registry.progress(self.fx.target,
                                                    self.fx.package.id).js_cursor)
        self.specialist.profile(self.fx.package, limits=limits)
        self.assertIn("New4", {item.name for item in self.registry.list_operations(self.fx.target)})
        self.assertNotIn("Older", {item.name for item in self.registry.list_operations(self.fx.target)})
        self.specialist.profile(self.fx.package, limits=limits)
        self.assertIn("Older", {item.name for item in self.registry.list_operations(self.fx.target)})
        self.assertIsNone(self.registry.progress(self.fx.target,
                                                self.fx.package.id).js_cursor)

    def test_dense_js_asset_resumes_beyond_twenty_four_documents(self):
        body = b"".join(
            (f"const q{index}=gql`query Dense{index}($id:ID!)"
             "{node(id:$id){id}}`;" ).encode() for index in range(30))
        body += b"fetch('/api/v1/after-documents',{method:'POST'});"
        self.js.record_artifact(
            target_id=self.fx.target,
            asset_url="https://app.example.test/static/dense.js",
            body=body, recon_asset_id=None,
            recon_sha256=hashlib.sha256(body).hexdigest(), source="FIXTURE")
        limits = APIAnalysisLimits(traffic=1, js_assets=1, recon_surfaces=1, candidates=4)
        for _ in range(12):
            self.specialist.profile(self.fx.package, limits=limits)
            if self.registry.progress(self.fx.target, self.fx.package.id).js_cursor is None:
                break
        names = {item.name for item in self.registry.list_operations(self.fx.target, limit=100)}
        self.assertTrue({f"Dense{index}" for index in range(30)} <= names)
        self.assertIn("JS_POST_api_v1_after_documents", names)
        self.assertIsNone(self.registry.progress(self.fx.target,
                                                self.fx.package.id).js_cursor)

    def test_js_resume_cursor_is_target_bound(self):
        token = self.specialist._js_resume_token(
            self.fx.target, "DOMART-" + "a" * 32, None, 17)
        self.assertEqual(self.specialist._js_resume(token, self.fx.target),
                         (None, "DOMART-" + "a" * 32, 17))
        with self.assertRaisesRegex(ValueError, "resume cursor"):
            self.specialist._js_resume(token, "TARGET-other")

    def test_candidate_generation_continues_past_first_operation(self):
        for index in range(4):
            self.registry.upsert_operation(
                target_id=self.fx.target, package_id=self.fx.package.id,
                name=f"Read{index}", kind=APIOperationType.REST,
                endpoint=f"https://app.example.test/api/v1/item_{index}",
                method="GET", version_hash=hashlib.sha256(str(index).encode()).hexdigest(),
                observed_at=f"2026-01-01T00:00:0{index}+00:00")
        limits = APIAnalysisLimits(traffic=1, js_assets=1, recon_surfaces=1, candidates=1)
        seen = []
        for _ in range(4):
            page = self.specialist.generate(self.fx.package, limits=limits)
            self.assertEqual(len(page), 1)
            seen.append(page[0].operation_id)
        self.assertEqual(len(set(seen)), 4)
        self.assertIsNone(self.registry.progress(self.fx.target,
                                                self.fx.package.id).operation_cursor)

    def test_new_operation_is_considered_while_older_backlog_advances(self):
        for index in range(30):
            self.registry.upsert_operation(
                target_id=self.fx.target, package_id=self.fx.package.id,
                name=f"Read{index}", kind=APIOperationType.REST,
                endpoint=f"https://app.example.test/api/v1/item_{index}",
                method="GET", version_hash=hashlib.sha256(str(index).encode()).hexdigest(),
                observed_at=f"2026-01-01T00:00:{index:02d}+00:00")
        limits = APIAnalysisLimits(traffic=1, js_assets=1, recon_surfaces=1, candidates=12)
        first = self.specialist.generate(self.fx.package, limits=limits)
        self.assertEqual(len(first), 12)
        first_ids = {item.operation_id for item in first}
        latest = self.registry.upsert_operation(
            target_id=self.fx.target, package_id=self.fx.package.id,
            name="NewRead", kind=APIOperationType.REST,
            endpoint="https://app.example.test/api/v1/item_new", method="GET",
            version_hash="b" * 64, observed_at="2026-01-01T00:00:31+00:00")
        second = self.specialist.generate(self.fx.package, limits=limits)
        second_ids = {item.operation_id for item in second}
        self.assertIn(latest.id, second_ids)
        self.assertTrue(second_ids - first_ids - {latest.id})

    def test_operation_and_candidate_keyset_pages_do_not_repeat_rows(self):
        for number in range(5):
            operation = self.registry.upsert_operation(
                target_id=self.fx.target, package_id=self.fx.package.id,
                name=f"ReadItem{number}", kind=APIOperationType.REST,
                endpoint=f"https://app.example.test/api/items/{number}",
                method="GET", version_hash=hashlib.sha256(str(number).encode()).hexdigest(),
                observed_at=f"2026-01-01T00:00:0{number}+00:00")
            self.registry.upsert_candidate(APICandidate(
                id=f"APIC-page-{number}", target_id=self.fx.target,
                operation_id=operation.id, category="OBJECT_AUTH",
                boundary_identity_id=None, owner_identity_id=None,
                test_object_id=None, owner_exchange_id=None, field_path=None,
                score=70 + number, reasons=("FIXTURE",),
                gaps=("OBJECT_OWNERSHIP_UNKNOWN",), status="PLAN_ONLY"))
        for pager in (self.registry.page_operations, self.registry.page_candidates):
            cursor = None
            seen = []
            for _ in range(3):
                rows, cursor = pager(self.fx.target, limit=2, cursor=cursor)
                seen.extend(row.id for row in rows)
            self.assertEqual(len(seen), 5)
            self.assertEqual(len(set(seen)), 5)
            self.assertIsNone(cursor)
        _, cursor = self.registry.page_operations(self.fx.target, limit=1)
        with self.assertRaises(ValueError):
            self.registry.page_operations("other-target", limit=1, cursor=cursor)
        with self.assertRaises(ValueError):
            self.registry.page_candidates(self.fx.target, limit=1, cursor="bad!")
        selected = next(item for item in self.registry.list_operations(self.fx.target)
                        if item.name == "ReadItem0")
        other = next(item for item in self.registry.list_operations(self.fx.target)
                     if item.name == "ReadItem1")
        self.registry.upsert_candidate(APICandidate(
            id="APIC-page-extra", target_id=self.fx.target,
            operation_id=selected.id, category="FIELD_AUTH",
            boundary_identity_id=None, owner_identity_id=None,
            test_object_id=None, owner_exchange_id=None, field_path="/privateNote",
            score=85, reasons=("FIXTURE",), gaps=("FIELD_EXPECTATION_UNKNOWN",),
            status="PLAN_ONLY"))
        first, cursor = self.registry.page_candidates(
            self.fx.target, limit=1, operation_id=selected.id)
        self.assertEqual(len(first), 1)
        self.assertIsNotNone(cursor)
        second, done = self.registry.page_candidates(
            self.fx.target, limit=1, operation_id=selected.id, cursor=cursor)
        self.assertEqual(len(second), 1)
        self.assertIsNone(done)
        self.assertNotEqual(first[0].id, second[0].id)
        with self.assertRaises(ValueError):
            self.registry.page_candidates(self.fx.target, limit=1,
                                          operation_id=other.id, cursor=cursor)
        counts = self.registry.counts(self.fx.target)
        self.assertEqual(counts["operations_discovered"], 5)
        self.assertEqual(counts["operations_observed"], 0)
        self.assertEqual(counts["operations_tested"], 0)

    def test_exact_operation_analysis_reaches_older_inventory_without_requests(self):
        selected = None
        for number in range(101):
            operation = self.registry.upsert_operation(
                target_id=self.fx.target, package_id=self.fx.package.id,
                name=f"ReadOlder{number}", kind=APIOperationType.REST,
                endpoint=f"https://app.example.test/api/items/{number}",
                method="GET", version_hash=hashlib.sha256(str(number).encode()).hexdigest(),
                observed_at=f"2026-01-01T00:{number // 60:02d}:{number % 60:02d}+00:00")
            if number == 0:
                selected = operation
        self.assertNotIn(selected.id,
                         {item.id for item in self.registry.list_operations(self.fx.target, limit=100)})
        before = len(self.fx.driver.running)
        candidates = self.specialist.generate(self.fx.package, operation_id=selected.id)
        self.assertTrue(candidates)
        self.assertEqual({item.operation_id for item in candidates}, {selected.id})
        self.assertEqual(len(self.fx.driver.running), before)
        with self.assertRaises(ValueError):
            self.specialist.generate(self.fx.package, operation_id="APIO-foreign")
