"""Scored, loopback-only cross-tenant read benchmark."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from http.client import HTTPConnection
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from .api_specialist import APIAnalysisLimits
from .api_registry import APIOperationType
from .authorization_store import AuthorizationMode
from .benchmark_eval import CaseTrace
from .benchmark_fixture_server import (BenchmarkHTTPFixture, _GRAPHQL_FIELD_QUERY,
                                       _GRAPHQL_QUERY)
from .benchmark_local import (_BenchmarkDriver, _actor, _read, _stage_package,
                              _stage_recipe)
from .benchmark_trace import collect_case_trace
from .campaign_models import (CampaignLimits, CampaignWorkKind,
                              CampaignWorkStatus, TERMINAL_CAMPAIGN_STATUSES)
from .config import (ExecutorSettings, NotificationSettings, ObjectSettings,
                     TargetSettings, load_config)
from .hypotheses import HypothesisGenerator
from .planner_models import PlannerMode
from .policy_models import ActionCategory
from .profile import AttackSurfaceProfiler
from .service import BugHunterRuntime
from .test_objects import ObjectState
from .domain import TrafficSource
from .traffic import CapturedRequest, CapturedResponse


def _approve_graphql_fixture_wait(runtime: BugHunterRuntime, package: object,
                                  campaign: object, exact_url: str,
                                  *, field_mode: bool = False) -> object:
    """Record one explicit synthetic decision for an observed loopback query plan."""
    for work in runtime.campaign.store.works(package.target.id, campaign.id):
        if (work.kind is not CampaignWorkKind.PLANNER or
                work.status is not CampaignWorkStatus.LINKED or not work.child_id):
            continue
        planner = runtime.planner_store.get(package.target.id, work.child_id)
        if planner is None or planner.status.value != "WAITING_APPROVAL":
            continue
        for candidate in runtime.planner_store.candidates(
                package.target.id, planner.id, limit=200):
            if (candidate.source_kind != "API_GRAPHQL" or
                    not candidate.plan_run_id or not candidate.plan_id):
                continue
            run = runtime.run_store.get(candidate.plan_run_id, package.target.id)
            plan = runtime.skill_plans.get(candidate.plan_id, package.target.id)
            source = runtime.api_operations.get_candidate(
                package.target.id, candidate.source_id)
            operation = (runtime.api_operations.get_operation(
                package.target.id, source.operation_id) if source else None)
            owner_exchange = (runtime.traffic.get_exchange(source.owner_exchange_id)
                              if source and source.owner_exchange_id else None)
            owner_url = (runtime.authorization._request_url(owner_exchange, runtime.store)
                         if owner_exchange is not None else None)
            binding = plan.get("api_binding") if plan is not None else None
            templates = plan.get("request_templates") if plan is not None else None
            if (run is None or run.status.value != "WAITING_APPROVAL" or
                    not run.approval_id or plan is None or
                    plan.get("skill_id") != "api-observed-read" or
                    source is None or source.category not in (
                        {"OBJECT_AUTH", "FIELD_AUTH"} if field_mode else
                        {"OBJECT_AUTH"}) or
                    (source.category == "FIELD_AUTH" and
                     source.field_path != "/node/email") or
                    operation is None or operation.type is not APIOperationType.GRAPHQL_QUERY or
                    operation.method != "POST" or operation.state != "CURRENT" or
                    owner_url != exact_url or
                    not isinstance(binding, dict) or
                    binding.get("candidate_id") != source.id or
                    binding.get("category") != source.category or
                    binding.get("operation_id") != operation.id or
                    binding.get("version_hash") != operation.version_hash or
                    not isinstance(templates, list) or not templates or
                    not isinstance(templates[0], dict) or
                    templates[0].get("binding") != "API_OBSERVED_READ_V1" or
                    templates[0].get("source_exchange_id") != source.owner_exchange_id or
                    templates[0].get("operation_id") != operation.id):
                continue
            approval = runtime.policy_store.get(run.approval_id, package.target.id)
            if (approval is None or approval.status.value != "PENDING" or
                    approval.target_id != package.target.id or
                    approval.category is not ActionCategory.AUTHORIZATION_TEST or
                    approval.operation != operation.id or
                    approval.identity_id not in {source.owner_identity_id,
                                                 source.boundary_identity_id} or
                    approval.hypothesis_id != candidate.hypothesis_id):
                continue
            runtime.policy_store.decide(approval.id, package.target.id, approve=True)
            runtime.run_store.approval_decision(
                approval.id, package.target.id, granted=True)
            return runtime.campaign.resume(package, campaign.id)
    raise RuntimeError("Synthetic GraphQL approval had no matching pending query")


def _record_graphql_owner_query(runtime: BugHunterRuntime, package: object,
                                fixture: BenchmarkHTTPFixture, item: object,
                                alias: str, session: object, *, field_mode: bool = False) -> None:
    external = runtime.object_factory._external_id(item)
    body = json.dumps({"query": _GRAPHQL_FIELD_QUERY if field_mode else _GRAPHQL_QUERY,
                       "operationName": "GetDocument",
                       "variables": {"id": external}},
                      separators=(",", ":")).encode("ascii")
    url = fixture.base_url + "/fixture/graphql"
    connection = HTTPConnection("127.0.0.1", fixture._server.server_port, timeout=5)
    try:
        connection.request("POST", "/fixture/graphql", body=body,
                           headers={"Content-Type": "application/json",
                                    "Cookie": f"fixture_actor={alias}"})
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError("Synthetic GraphQL owner control failed")
        payload = response.read(8193)
    finally:
        connection.close()
    if (len(payload) > 8192 or
            json.loads(payload).get("data", {}).get("node", {}).get("id") != external):
        raise RuntimeError("Synthetic GraphQL owner object mismatch")
    exchange = runtime.traffic.store_request(
        package, CapturedRequest(
            "POST", url, headers=(("Content-Type", "application/json"),),
            body=body, operation_id="GQL-" + "1" * 32),
        source=TrafficSource.FIXTURE, capture_provider="FIXTURE",
        browser_manager=runtime.browser, browser_session_id=session.id,
        auth_material_observed=True)
    runtime.traffic.store_response(
        exchange.id, CapturedResponse(
            200, (("Content-Type", "application/json"),), payload))


def run_cross_tenant_campaign(package_template: Path, work_root: Path, *,
                              secure: bool, case_id: str,
                              max_requests: int = 80,
                              mutation: bool = False,
                              mixed: bool = False,
                              horizontal: bool = False,
                              graphql: bool = False,
                              graphql_field: bool = False,
                              approve_graphql_fixture: bool = False) -> CaseTrace:
    """Run the existing specialist and Campaign path against owned fixtures."""
    if (type(secure) is not bool or type(mutation) is not bool or
            type(mixed) is not bool or type(horizontal) is not bool or
            type(graphql) is not bool or type(graphql_field) is not bool or
            type(approve_graphql_fixture) is not bool or
            (approve_graphql_fixture and not (graphql or graphql_field)) or
            sum((mutation, mixed, horizontal, graphql, graphql_field)) > 1 or
            not 20 <= max_requests <= 80):
        raise ValueError("Invalid cross-tenant benchmark parameters")
    work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with BenchmarkHTTPFixture(secure=secure, access_mode=(
            "GRAPHQL_FIELD" if graphql_field else "GRAPHQL" if graphql else
            "MIXED" if mixed else
            "HORIZONTAL" if horizontal else
            "TENANT_MUTATION" if mutation else "TENANT"),
                              noisy=mixed, max_requests=max_requests) as fixture:
        with TemporaryDirectory(prefix="local-authz-", dir=work_root) as directory:
            root = Path(directory)
            _stage_package(package_template, root / "targets/benchmark/target.yaml",
                           fixture._server.server_port, cross_identity=True)
            env = {"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_STATE_HOME": str(root), "HACKBOT_HOME": str(root / "runtime")}
            settings = replace(
                load_config(environ=env), targets=TargetSettings(root / "targets"),
                objects=ObjectSettings(root / "recipes"), recon=None,
                notifications=NotificationSettings(),
                executor=ExecutorSettings(allow_direct=True, max_redirects=0,
                                          max_response_bytes=8192))
            runtime = BugHunterRuntime(settings, driver=_BenchmarkDriver(),
                                       vnc_ready=lambda: False)
            package = runtime.package("benchmark")
            if (package.scope.evaluate_url(fixture.base_url + "/").result.value !=
                    "IN_SCOPE" or package.scope.include_hosts[0].pattern != "127.0.0.1"):
                raise ValueError("Cross-tenant fixture scope is not loopback-only")
            runtime.registry.register_target(package)
            owner_actor = _actor(runtime, package, alias="owner",
                                 tenant_label="tenant-a")
            foreign_tenant_label = "tenant-a" if horizontal else "tenant-b"
            foreign_actor = _actor(
                runtime, package, alias="foreign",
                tenant_label=foreign_tenant_label,
                existing_tenant=owner_actor[2] if horizontal else None)
            actors = ((*owner_actor, "owner", "tenant-a"),
                      (*foreign_actor, "foreign", foreign_tenant_label))
            created = []
            campaign_trace = None
            campaign = None
            cleanup_errors = 0
            cancel_errors = 0
            approvals = 0
            try:
                for identity, session, tenant, alias, tenant_label in actors:
                    recipe_id = f"document_{alias}"
                    _stage_recipe(root / "recipes", fixture.base_url, package.target.id,
                                  recipe_id=recipe_id, alias=alias,
                                  tenant_label=tenant_label,
                                  include_rename_mutation=mutation)
                    resolved = runtime.object_factory.resolve(
                        package_id=package.id, recipe_id=recipe_id,
                        identity_id=identity.id, tenant_id=tenant.id,
                        session_id=session.id,
                        purpose="Synthetic cross-tenant benchmark setup")
                    if resolved.outcome != "READY" or resolved.item is None:
                        raise RuntimeError("Cross-tenant fixture setup failed: " +
                                           resolved.outcome + ":" + resolved.reason)
                    item = resolved.item
                    created.append((item, session))
                    if mutation:
                        updated = runtime.object_factory.update_name(
                            item.id, package.target.id, session_id=session.id)
                        if updated.outcome != "READY" or updated.item is None:
                            raise RuntimeError("Cross-tenant owner mutation failed: " +
                                               updated.outcome + ":" + updated.reason)
                    external = runtime.object_factory._external_id(item)
                    facts = ([("resource_visibility", "SHARED"),
                              ("access_policy", "PUBLIC_METADATA_PRIVATE_FIELD"),
                              ("data_classification", "SENSITIVE"),
                              ("field_visibility", "email")]
                             if graphql_field else
                             [("resource_visibility", "PRIVATE"),
                              ("access_policy", "TENANT_ONLY"),
                              ("resource_tenant", tenant.id)])
                    if mixed and tenant_label == "tenant-a":
                        facts.append(("data_classification", "PROTECTED_FILE"))
                    for predicate, value in facts:
                        runtime.store.create_fact(
                            hashlib.sha256(external.encode()).hexdigest(),
                            predicate, value, confidence=1.0,
                            evidence_ids=(item.verification_evidence_ids[0],),
                            source="FIXTURE", target_ref=package.target.id)
                    owner_url = (fixture.base_url +
                                 f"/fixture/{tenant_label}/documents/{external}")
                    owner_read = _read(runtime, package, owner_url,
                                       identity=identity, session=session)
                    if owner_read.error is not None:
                        raise RuntimeError("Cross-tenant owner read failed")
                    if graphql or graphql_field:
                        _record_graphql_owner_query(
                            runtime, package, fixture, item, alias, session,
                            field_mode=graphql_field)
                    if mixed and tenant_label == "tenant-a":
                        anonymous = _read(runtime, package, owner_url)
                        if anonymous.error is not None:
                            raise RuntimeError("Mixed fixture anonymous read failed")
                if mixed:
                    for path in ("/admin/", "/graphql", "/api/internal/config",
                                 "/api/files/public-sample/download",
                                 "/assets/noise.js", "/assets/noise.js.map"):
                        for identity, session in ((actors[0][0], actors[0][1]),
                                                  (None, None)):
                            observed = _read(runtime, package, fixture.base_url + path,
                                             identity=identity, session=session)
                            if observed.error is not None:
                                raise RuntimeError("Mixed fixture noise read failed")
                    runtime.exposure.discover_traffic(package)
                if graphql or graphql_field:
                    runtime.api.generate(package, limits=APIAnalysisLimits(
                        traffic=20, js_assets=1, recon_surfaces=1, candidates=8))
                else:
                    runtime.authorization.start_hunt(
                        package, mode=AuthorizationMode.MANUAL,
                        candidate_limit=8 if mutation or mixed or horizontal else 1,
                        request_budget=7 if mutation else 6)
                started = datetime.now(timezone.utc).isoformat()
                profile = AttackSurfaceProfiler(
                    runtime.registry, runtime.store, runtime.traffic,
                    bootstrap=runtime.bootstrap_store).profile(package)
                runtime.hypotheses.save_profile(profile)
                HypothesisGenerator(runtime.hypotheses).generate(profile)
                campaign = runtime.campaign.start(
                    package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
                    limits=CampaignLimits(max_cycles=1, seconds=240 if mutation or mixed or horizontal or graphql or graphql_field else 180,
                                          requests=48 if mutation else 32 if mixed or horizontal or graphql or graphql_field else 24,
                                          browser_actions=0,
                                          research_requests=0, tokens=0,
                                          setup_objects=0, cleanup_reserve=0),
                    requested_by="benchmark")
                for _ in range(80):
                    campaign = runtime.campaign.advance(package, campaign.id)
                    if (approve_graphql_fixture and
                            campaign.status.value == "WAITING_APPROVAL"):
                        if approvals >= 8:
                            raise RuntimeError("Synthetic GraphQL approval limit exceeded")
                        campaign = _approve_graphql_fixture_wait(
                            runtime, package, campaign,
                            fixture.base_url + "/fixture/graphql",
                            field_mode=graphql_field)
                        approvals += 1
                        continue
                    if (campaign.status in TERMINAL_CAMPAIGN_STATUSES or
                            campaign.status.value.startswith("WAITING_") or
                            campaign.status.value == "PAUSED"):
                        break
                campaign_trace = collect_case_trace(
                    runtime, case_id, campaign, started,
                    datetime.now(timezone.utc).isoformat())
            finally:
                if (campaign is not None and
                        (campaign.status.value.startswith("WAITING_") or
                         campaign.status.value == "PAUSED")):
                    try:
                        runtime.campaign.cancel(package, campaign.id)
                    except Exception:
                        cancel_errors += 1
                for item, session in reversed(created):
                    try:
                        current = runtime.objects.get(item.id, package.target.id)
                        if current is None or current.state is not ObjectState.CLEANED:
                            runtime.object_factory.cleanup(
                                item.id, package.target.id, session_id=session.id)
                    except Exception:
                        cleanup_errors += 1
            if campaign_trace is None:
                raise RuntimeError("Cross-tenant campaign trace unavailable")
            requests = fixture.requests
            exchanges = runtime.traffic.list_exchanges_for_target(
                package.target.id, limit=120).items
            outside = sum(exchange.request.origin != fixture.base_url
                          for exchange in exchanges)
            if outside:
                raise RuntimeError("Cross-tenant benchmark attempted non-loopback traffic")
            if len(requests) > max_requests:
                raise RuntimeError("Cross-tenant benchmark exceeded request budget")
            cleaned_count = 0
            for item, _ in created:
                current = runtime.objects.get(item.id, package.target.id)
                if current is not None and current.state is ObjectState.CLEANED:
                    cleaned_count += 1
            orphaned_count = max(len(created) - cleaned_count, fixture.document_count)
            usage = replace(
                campaign_trace.usage, requests=len(requests),
                setup_requests=sum(entry.method == "POST" for entry in requests),
                verification_requests=sum(entry.method in {"GET", "HEAD"}
                                          for entry in requests),
                cleanup_requests=sum(entry.method == "DELETE" for entry in requests),
                objects_created=len(created),
                objects_cleaned=cleaned_count,
                approvals=approvals + int(
                    campaign_trace.failure_reason == "WAITING_APPROVAL"),
                orphaned_objects=orphaned_count,
                safety_violations=(*campaign_trace.usage.safety_violations,
                                   *(("CLEANUP_EXCEPTION",) if cleanup_errors else ()),
                                   *(("TEARDOWN_CANCEL_EXCEPTION",)
                                     if cancel_errors else ()),
                                   *(("ORPHANED_FIXTURE_OBJECT",)
                                     if orphaned_count else ())))
            return replace(campaign_trace, usage=usage,
                           finished_at=datetime.now(timezone.utc).isoformat())
