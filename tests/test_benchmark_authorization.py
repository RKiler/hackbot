from __future__ import annotations

from types import SimpleNamespace as NS
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from hackbot.api_registry import APIOperationType
from hackbot.benchmark_authorization import (_approve_graphql_fixture_wait,
                                             run_cross_tenant_campaign)
from hackbot.campaign import CampaignCoordinator
from hackbot.campaign_models import CampaignWorkKind, CampaignWorkStatus
from hackbot.policy_models import ActionCategory


class SyntheticApprovalTests(unittest.TestCase):
    def test_paused_campaign_is_cancelled_before_fixture_cleanup(self):
        package = (Path(__file__).resolve().parents[1] / "benchmarks/visible/"
                   "local_mutation_b/package/target.yaml")
        with TemporaryDirectory() as directory:
            with patch.object(CampaignCoordinator, "advance", autospec=True,
                              side_effect=lambda coordinator, target, campaign_id:
                              coordinator.pause(target, campaign_id)):
                trace = run_cross_tenant_campaign(
                    package, Path(directory), secure=True, mutation=True,
                    case_id="paused_fixture_cleanup", max_requests=80)
        self.assertEqual(trace.failure_reason, "PAUSED")
        self.assertEqual(trace.usage.objects_created, 2)
        self.assertEqual(trace.usage.objects_cleaned, 2)
        self.assertEqual(trace.usage.orphaned_objects, 0)
        self.assertEqual(trace.usage.safety_violations, ())

    def test_only_matching_pending_graphql_query_is_approved(self):
        target_id = "TARGET-1"
        exact_url = "http://127.0.0.1:1234/fixture/graphql"
        work = NS(kind=CampaignWorkKind.PLANNER,
                  status=CampaignWorkStatus.LINKED, child_id="PLRUN-1")
        planner = NS(id="PLRUN-1", status=NS(value="WAITING_APPROVAL"))
        candidate = NS(source_kind="API_GRAPHQL", plan_run_id="RUN-1",
                       plan_id="PLAN-1", source_id="APIC-1", hypothesis_id="HYP-1")
        run = NS(status=NS(value="WAITING_APPROVAL"), approval_id="APPROVAL-1")
        source = NS(id="APIC-1", category="OBJECT_AUTH", operation_id="APIO-1",
                    owner_exchange_id="EXCHANGE-1", owner_identity_id="IDENTITY-1",
                    boundary_identity_id="IDENTITY-2")
        operation = NS(id="APIO-1", type=APIOperationType.GRAPHQL_QUERY,
                       method="POST", state="CURRENT", version_hash="a" * 64)
        plan = {"skill_id": "api-observed-read",
                "api_binding": {"candidate_id": source.id,
                                "category": source.category,
                                "operation_id": operation.id,
                                "version_hash": operation.version_hash},
                "request_templates": [{"binding": "API_OBSERVED_READ_V1",
                                       "source_exchange_id": source.owner_exchange_id,
                                       "operation_id": operation.id}]}
        approval = NS(status=NS(value="PENDING"), target_id=target_id,
                      category=ActionCategory.AUTHORIZATION_TEST,
                      operation=operation.id, identity_id=source.owner_identity_id,
                      hypothesis_id=candidate.hypothesis_id, id="APPROVAL-1")
        decisions = []
        resumes = []
        runtime = NS(
            campaign=NS(
                store=NS(works=lambda *_args: (work,)),
                resume=lambda *_args: resumes.append("resumed") or planner),
            planner_store=NS(get=lambda *_args: planner,
                             candidates=lambda *_args, **_kwargs: (candidate,)),
            run_store=NS(get=lambda *_args: run,
                         approval_decision=lambda *_args, **_kwargs:
                         decisions.append("run_decision")),
            skill_plans=NS(get=lambda *_args: plan),
            api_operations=NS(get_candidate=lambda *_args: source,
                              get_operation=lambda *_args: operation),
            traffic=NS(get_exchange=lambda *_args: NS()),
            authorization=NS(_request_url=lambda *_args: exact_url),
            policy_store=NS(get=lambda *_args: approval,
                            decide=lambda *_args, **_kwargs:
                            decisions.append("approved")),
            store=object())
        package = NS(target=NS(id=target_id))
        campaign = NS(id="CAMPAIGN-1")

        approval.operation = "OTHER-OPERATION"
        with self.assertRaisesRegex(RuntimeError, "no matching pending query"):
            _approve_graphql_fixture_wait(runtime, package, campaign, exact_url)
        self.assertEqual(decisions, [])

        approval.operation = operation.id
        approval.category = ActionCategory.OBJECT_UPDATE
        with self.assertRaisesRegex(RuntimeError, "no matching pending query"):
            _approve_graphql_fixture_wait(runtime, package, campaign, exact_url)
        self.assertEqual(decisions, [])

        approval.category = ActionCategory.AUTHORIZATION_TEST
        plan["api_binding"]["version_hash"] = "wrong"
        with self.assertRaisesRegex(RuntimeError, "no matching pending query"):
            _approve_graphql_fixture_wait(runtime, package, campaign, exact_url)
        self.assertEqual(decisions, [])

        plan["api_binding"]["version_hash"] = operation.version_hash
        result = _approve_graphql_fixture_wait(runtime, package, campaign, exact_url)
        self.assertIs(result, planner)
        self.assertEqual(decisions, ["approved", "run_decision"])
        self.assertEqual(resumes, ["resumed"])
