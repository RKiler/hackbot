from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace as NS
import unittest

from hackbot.benchmark_models import BenchmarkCategory, structured_root_fingerprint
from hackbot.benchmark_trace import (_authorization_category, _candidate_category,
                                     _candidate_root, _category, _graphql_finding_root,
                                     _operation,
                                     collect_case_trace)
from hackbot.api_registry import APIOperationType
from hackbot.campaign_models import CampaignWorkKind
from hackbot.domain import ObservationState
from hackbot.identity import MembershipStatus
from hackbot.validation_store import FindingStatus, ValidationStatus


class Store:
    def __init__(self, item):
        self.item = item

    def get(self, *args):
        return self.item

    def get_finding(self, *args):
        return self.item


class PlannerStore(Store):
    def candidates(self, *args, **kwargs):
        return self.item[1]

    def get(self, *args):
        return self.item[0]


class CampaignStore:
    def works(self, *args):
        return (NS(kind=CampaignWorkKind.PLANNER, child_id="PLANNER-1"),)


def fixture(*, broken: bool = False, confirmed: bool = True):
    now = datetime(2026, 10, 18, tzinfo=timezone.utc)
    candidate = NS(id="CAND-1", category="EXPOSURE", specialist=NS(value="EXPOSURE"),
                   skill_ids=("download",), root_cause_key="a" * 64,
                   source_kind="HYPOTHESIS",
                   hypothesis_id="HYP-1", plan_id="PLAN-1", plan_run_id="RUN-1",
                   validation_id="VAL-1", finding_id="FIND-1", run_id="PLANNER-1")
    plan = {"id": "PLAN-1", "hypothesis_id": "HYP-1",
            "created_at": now.isoformat(),
            "request_templates": [{"method": "GET", "url": "https://app.test/private/export"}]}
    finding = NS(id="FIND-1", target_id="TARGET-1", validation_id="VAL-1",
                 hypothesis_id="HYP-1", category="UNAUTHENTICATED_DOWNLOAD",
                 status=FindingStatus.CONFIRMED, object_type="report",
                 root_cause_fingerprint="b" * 64,
                 evidence_ids=("EVIDENCE-1",), demonstrated_impact="PRIVATE_REPORT_READ",
                 created_at=now.isoformat())
    validation = NS(id="VAL-1", target_id="TARGET-1", status=ValidationStatus.CONFIRMED
                    if confirmed else ValidationStatus.REJECTED,
                    source="DETERMINISTIC", hypothesis_id="HYP-1", plan_id="PLAN-1",
                    run_id="RUN-1" if not broken else "RUN-OTHER",
                    supporting_evidence_ids=("EVIDENCE-1",),
                    controls_evaluated=("OWNER", "ANONYMOUS"),
                    demonstrated_impact="PRIVATE_REPORT_READ", reproduction_count=1)
    runtime = NS(
        campaign=NS(store=CampaignStore()),
        planner_store=PlannerStore((NS(target_id="TARGET-1", candidate_count=1),
                                    (candidate,))),
        hypotheses=Store(NS(id="HYP-1", target_id="TARGET-1", boundary="ANONYMOUS_READ",
                            surface_key="/private/export", created_at=now)),
        skill_plans=Store(plan),
        run_store=Store(NS(id="RUN-1", target_id="TARGET-1", plan_id="PLAN-1",
                           hypothesis_id="HYP-1", started_at=now.isoformat())),
        validations=Store(validation))
    runtime.validations.get_finding = lambda *args: finding
    campaign = NS(id="CAMPAIGN-1", target_id="TARGET-1",
                  status=NS(value="COMPLETED"),
                  usage=NS(requests=2, browser_actions=0, research_requests=0))
    return runtime, campaign


class BenchmarkTraceTests(unittest.TestCase):
    def test_collects_confirmed_finding_with_stored_chain(self):
        runtime, campaign = fixture()
        trace = collect_case_trace(runtime, "download_exposed", campaign,
                                   "2026-10-18T00:00:00+00:00",
                                   "2026-10-18T00:00:10+00:00")
        self.assertEqual(len(trace.findings), 1)
        self.assertTrue(trace.findings[0].audit_complete)
        self.assertEqual(trace.findings[0].operation, "GET /private/export")
        self.assertEqual(trace.findings[0].protocol, "HTTP")
        self.assertEqual(trace.candidates[0].category,
                         BenchmarkCategory.UNAUTHENTICATED_DOWNLOAD)
        self.assertEqual(trace.plans_executed, 1)
        self.assertEqual(trace.usage.requests, 2)

    def test_broken_link_is_not_audited_as_complete(self):
        runtime, campaign = fixture(broken=True)
        trace = collect_case_trace(runtime, "download_exposed", campaign,
                                   "2026-10-18T00:00:00+00:00",
                                   "2026-10-18T00:00:10+00:00")
        self.assertEqual(len(trace.findings), 1)
        self.assertFalse(trace.findings[0].audit_complete)

    def test_rejected_validation_does_not_become_a_finding(self):
        runtime, campaign = fixture(confirmed=False)
        trace = collect_case_trace(runtime, "download_exposed", campaign,
                                   "2026-10-18T00:00:00+00:00",
                                   "2026-10-18T00:00:10+00:00")
        self.assertEqual(trace.findings, ())
        self.assertEqual(trace.validations, 1)

    def test_typed_mutation_projection_uses_pinned_recipe_and_tenant_boundary(self):
        recipe = NS(sha256="a" * 64, target_id="TARGET-1",
                    mutations=(NS(mutation_type=NS(value="RENAME"),
                                   write=NS(method="PATCH", url=(
                                       "http://127.0.0.1:1234/fixture/tenant-b/"
                                       "documents/{object_id}"))),))
        item = NS(package_id="benchmark", recipe_id="document_foreign",
                  recipe_hash=recipe.sha256, verified_at="2026-10-18T00:00:00Z")
        runtime = NS(objects=Store(item),
                     object_factory=NS(recipes=Store(recipe)))
        plan = {"skill_id": "typed-authorization-mutation",
                "request_templates": [
                    {"binding": "AUTHORIZATION_RECIPE_MUTATION_V1",
                     "stage": "BEFORE_READ", "method": "GET"},
                    {"binding": "AUTHORIZATION_RECIPE_MUTATION_V1",
                     "stage": "BOUNDARY_MUTATE", "method": "PATCH",
                     "mutation_type": "RENAME", "recipe_hash": recipe.sha256,
                     "test_object_id": "TESTOBJ-1"}]}
        self.assertEqual(_operation(runtime, "TARGET-1", plan, "/opaque", "TENANT"),
                         ("PATCH /fixture/{tenant}/documents/{object_id}", "HTTP"))
        self.assertEqual(_authorization_category("AUTHORIZATION_MUTATION", "TENANT", plan),
                         BenchmarkCategory.CROSS_TENANT_BOLA)
        plan["request_templates"][1]["recipe_hash"] = "b" * 64
        self.assertEqual(_operation(runtime, "TARGET-1", plan, "/opaque", "TENANT"),
                         ("/opaque", "UNKNOWN"))

    def test_unplanned_horizontal_candidate_uses_only_verified_owner_route(self):
        self.assertEqual(_category("HORIZONTAL"), BenchmarkCategory.HORIZONTAL_IDOR)
        self.assertEqual(_category("VERTICAL"), BenchmarkCategory.VERTICAL_BFLA)
        self.assertEqual(_category("HIDDEN_FUNCTION"), BenchmarkCategory.VERTICAL_BFLA)
        url = "http://127.0.0.1:1234/fixture/tenant-a/documents/doc-1"
        source = NS(boundary=NS(value="HORIZONTAL"), test_object_id="TESTOBJ-1",
                    owner_exchange_id="EXCHANGE-1", owner_identity_id="IDENTITY-1")
        item = NS(verified_at="2026-10-18T00:00:00Z",
                  creator_identity_id="IDENTITY-1", package_id="benchmark",
                  recipe_id="document_owner", recipe_hash="b" * 64,
                  object_type="document")
        exchange = NS(response=NS(record=NS(status_code=200)),
                      attribution=NS(verified_identity_id="IDENTITY-1"),
                      package_id="benchmark", request=NS(record=NS(method="GET")))
        recipe = NS(sha256="b" * 64, target_id="TARGET-1",
                    verify=NS(method="GET", url=(
                        "http://127.0.0.1:1234/fixture/tenant-a/"
                        "documents/{object_id}")), mutations=())
        runtime = NS(
            authorization=NS(ledger=NS(get_candidate=lambda *_args: source),
                             _request_url=lambda _exchange, _store: url),
            objects=Store(item), traffic=NS(get_exchange=lambda *_args: exchange),
            object_factory=NS(recipes=Store(recipe),
                              _external_id=lambda _item: "doc-1"),
            store=object())
        candidate = NS(root_cause_key="a" * 64, source_kind="AUTHORIZATION",
                       source_id="AUTHCAND-1", target_id="TARGET-1")
        expected = structured_root_fingerprint(
            BenchmarkCategory.HORIZONTAL_IDOR,
            "GET /fixture/tenant-a/documents/{object_id}",
            "OBJECT", "document", "HTTP")
        self.assertEqual(_candidate_root(runtime, candidate, None,
                                         BenchmarkCategory.HORIZONTAL_IDOR), expected)
        self.assertEqual(_candidate_root(runtime, candidate, NS(boundary="TENANT"),
                                         BenchmarkCategory.HORIZONTAL_IDOR), "a" * 64)
        item.recipe_hash = "c" * 64
        self.assertEqual(_candidate_root(runtime, candidate, None,
                                         BenchmarkCategory.HORIZONTAL_IDOR), "a" * 64)

    def test_graphql_candidate_projection_requires_owned_capture_and_separate_tenant(self):
        source = NS(id="APIC-1", category="OBJECT_AUTH", operation_id="API-OP",
                    test_object_id="TESTOBJ-1", owner_exchange_id="EXCHANGE-1",
                    owner_identity_id="IDENTITY-1", boundary_identity_id="IDENTITY-2",
                    field_path=None)
        operation = NS(id="API-OP", version_hash="v" * 64,
                       type=APIOperationType.GRAPHQL_QUERY, state="CURRENT",
                       method="POST", endpoint="http://127.0.0.1:1234/{p:redacted}/graphql",
                       exchange_ids=("EXCHANGE-1",), package_id="benchmark")
        item = NS(id="TESTOBJ-1", target_id="TARGET-1", package_id="benchmark",
                  object_type="document", creator_identity_id="IDENTITY-1",
                  owner_principal_id=None, tenant_id="TENANT-1", parent_id=None,
                  external_id_hash="e" * 64, verification_evidence_ids=("EVIDENCE-1",),
                  disposable=True, verified_at="2026-10-18T00:00:00Z",
                  recipe_id="document_owner", recipe_hash="b" * 64)
        recipe = NS(sha256="b" * 64, target_id="TARGET-1")
        observed = NS(semantic_owner_success=True, protocol="GRAPHQL",
                      graphql_kind="QUERY", owner_identity_id="IDENTITY-1",
                      object_id="TESTOBJ-1", method="POST",
                      display_path="/{p:redacted}/graphql",
                      origin="http://127.0.0.1:1234")
        def membership(tenant):
            return NS(target_id="TARGET-1", tenant_id=tenant,
                      status=MembershipStatus.ACTIVE,
                      observation_state=ObservationState.OBSERVED)
        pages = {"IDENTITY-1": NS(items=(membership("TENANT-1"),), next_cursor=None),
                 "IDENTITY-2": NS(items=(membership("TENANT-2"),), next_cursor=None)}
        runtime = NS(
            api_operations=NS(get_candidate=lambda *_args: source,
                              get_operation=lambda *_args: operation),
            objects=Store(item), object_factory=NS(recipes=Store(recipe)),
            package=lambda _id: NS(),
            authorization=NS(observed_operation=lambda *_args: observed,
                             _request_url=lambda *_args:
                             "http://127.0.0.1:1234/fixture/graphql"),
            traffic=NS(get_exchange=lambda *_args: NS()), store=object(),
            registry=NS(list_memberships=lambda identity, **_kwargs: pages[identity]))
        candidate = NS(root_cause_key="a" * 64, source_kind="API_GRAPHQL",
                       source_id="API-CAND-1", target_id="TARGET-1",
                       category="OBJECT_AUTH")
        category = _candidate_category(runtime, candidate)
        self.assertEqual(category, BenchmarkCategory.GRAPHQL_OBJECT_AUTH)
        expected = structured_root_fingerprint(
            category, "POST /fixture/graphql", "TENANT", "document", "HTTP")
        self.assertEqual(_candidate_root(runtime, candidate, None, category), expected)
        plan = {"skill_id": "api-observed-read",
                "api_binding": {"candidate_id": source.id,
                                "category": "OBJECT_AUTH",
                                "operation_id": operation.id,
                                "version_hash": operation.version_hash,
                                "field_path": ""},
                "request_templates": [{"binding": "API_OBSERVED_READ_V1",
                                       "source_exchange_id": source.owner_exchange_id,
                                       "test_object_id": source.test_object_id,
                                       "operation_id": operation.id,
                                       "field_path": ""}]}
        finding = NS(category="API_AUTHORIZATION", object_type="document")
        self.assertEqual(_graphql_finding_root(runtime, candidate, plan, finding, "TENANT"),
                         (BenchmarkCategory.GRAPHQL_OBJECT_AUTH,
                          "POST /fixture/graphql", "HTTP"))
        source.category = candidate.category = "FIELD_AUTH"
        source.field_path = "/node/email"
        operation.fields = (NS(path="/node/email"),)
        runtime.api = NS(_trusted_field_expectation=lambda *_args: True)
        plan["api_binding"].update(category="FIELD_AUTH", field_path="/node/email")
        plan["request_templates"][0]["field_path"] = "/node/email"
        field_category = _candidate_category(runtime, candidate)
        self.assertEqual(field_category, BenchmarkCategory.GRAPHQL_FIELD_AUTH)
        self.assertEqual(_candidate_root(runtime, candidate, None, field_category),
                         structured_root_fingerprint(
                             field_category, "POST /fixture/graphql", "TENANT",
                             "document", "HTTP"))
        self.assertEqual(_graphql_finding_root(runtime, candidate, plan, finding, "TENANT"),
                         (BenchmarkCategory.GRAPHQL_FIELD_AUTH,
                          "POST /fixture/graphql", "HTTP"))
        runtime.api = NS(_trusted_field_expectation=lambda *_args: False)
        self.assertEqual(_candidate_root(runtime, candidate, None, field_category), "a" * 64)
        self.assertIsNone(_graphql_finding_root(runtime, candidate, plan,
                                                finding, "TENANT"))
        source.category = candidate.category = "OBJECT_AUTH"
        source.field_path = None
        plan["api_binding"].update(category="OBJECT_AUTH", field_path="")
        plan["request_templates"][0]["field_path"] = ""
        plan["api_binding"]["version_hash"] = "wrong"
        self.assertIsNone(_graphql_finding_root(runtime, candidate, plan,
                                                finding, "TENANT"))
        plan["api_binding"]["version_hash"] = operation.version_hash
        finding.category = "OTHER"
        self.assertIsNone(_graphql_finding_root(runtime, candidate, plan,
                                                finding, "TENANT"))
        finding.category = "API_AUTHORIZATION"
        item.recipe_hash = "c" * 64
        self.assertEqual(_candidate_root(runtime, candidate, None, category), "a" * 64)
        item.recipe_hash = recipe.sha256
        observed.semantic_owner_success = False
        self.assertEqual(_candidate_root(runtime, candidate, None, category), "a" * 64)
        observed.semantic_owner_success = True
        pages["IDENTITY-2"] = NS(items=(membership("TENANT-1"),), next_cursor=None)
        self.assertEqual(_candidate_root(runtime, candidate, None, category), "a" * 64)
        source.test_object_id = None
        self.assertEqual(_candidate_root(runtime, candidate, None, category), "a" * 64)
