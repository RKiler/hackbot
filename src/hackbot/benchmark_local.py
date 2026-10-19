"""Synthetic local validation probe; not a blind-discovery benchmark runner."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from .benchmark_fixture_server import BenchmarkHTTPFixture
from .benchmark_eval import CaseTrace
from .benchmark_trace import collect_case_trace
from .browser import IdentityObservation, IdentityVerificationRule
from .campaign_models import CampaignLimits, TERMINAL_CAMPAIGN_STATUSES
from .config import (ExecutorSettings, NotificationSettings, ObjectSettings,
                     SecretBindingConfig, SecretSettings, TargetSettings, load_config)
from .domain import ObservationState, Principal, Tenant, TrafficSource
from .evidence import EvidenceProvenance
from .executor import RequestTemplate
from .hypotheses import HypothesisGenerator
from .identity import IdentityStatus, MembershipStatus
from .planner_models import PlannerMode
from .planner_models import PlannerAdvisor
from .policy_models import ActionCategory, ActorMode, ProposedAction
from .profile import AttackSurfaceProfiler
from .secrets import RoutedSecretProvider
from .service import BugHunterRuntime
from .traffic import CapturedRequest, CapturedResponse
from .validation_store import ValidationStatus


class _BenchmarkDriver:
    name = "SYNTHETIC_FIXTURE"

    def __init__(self) -> None:
        self.running: set[str] = set()
        self.identities: dict[str, IdentityObservation] = {}

    def register(self, session_id: str, user_id: str, tenant_id: str) -> None:
        self.identities[session_id] = IdentityObservation(
            user_id=user_id, tenant_id=tenant_id)

    def start(self, session_id: str, profile: Path, *, display: str | None,
              proxy: object) -> None:
        self.running.add(session_id)

    def stop(self, session_id: str) -> None:
        self.running.discard(session_id)

    def is_running(self, session_id: str) -> bool:
        return session_id in self.running

    def is_available(self) -> bool:
        return True

    def observe_identity(self, session_id: str,
                         rule: IdentityVerificationRule) -> IdentityObservation:
        return self.identities[session_id]


@dataclass(frozen=True, slots=True)
class LocalValidationResult:
    secure: bool
    stale_observation: bool
    validation_status: str | None
    finding_id: str | None
    finding_category: str | None
    evidence_count: int
    requests: int
    setup_requests: int
    verification_requests: int
    cleanup_requests: int
    objects_created: int
    objects_cleaned: int
    orphaned_objects: int
    outside_loopback: int
    audit_chain_complete: bool
    campaign_status: str | None = None
    campaign_candidates: int = 0
    campaign_selected: int = 0
    campaign_validations: int = 0
    campaign_findings: int = 0
    campaign_stop_reason: str | None = None
    campaign_trace: CaseTrace | None = field(default=None, repr=False)


def _stage_package(source: Path, destination: Path, port: int, *,
                   cross_identity: bool = False, read_only: bool = False) -> None:
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 65_536:
        raise ValueError("Invalid local benchmark package template")
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    if (not isinstance(data, dict) or data.get("id") != "benchmark" or
            data.get("primary_domain") != "benchmark.test"):
        raise ValueError("Unexpected local benchmark package template")
    scope = data.get("scope")
    autonomy = data.get("autonomy")
    rate = data.get("rate")
    if (not isinstance(scope, dict) or not isinstance(autonomy, dict)
            or not isinstance(rate, dict)):
        raise ValueError("Invalid local benchmark package policy")
    scope.update({"include": ["127.0.0.1"], "exclude": [], "schemes": ["http"],
                  "ports": [port]})
    autonomy.update({"safe_read": "ALLOW", "bounded_active": "ALLOW",
                     "state_changing": "DENY" if read_only else "ALLOW",
                     "create_disposable_objects": "DENY" if read_only else "ALLOW",
                     "modify_disposable_objects": "DENY" if read_only else "ALLOW",
                     "delete_disposable_objects": "DENY" if read_only else "ALLOW"})
    if cross_identity:
        autonomy["cross_identity_testing"] = "ALLOW"
    rate.update({"requests_per_second": 10, "requests_per_minute": 40,
                 "max_concurrency": 1, "burst": 10})
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination.write_text(yaml.safe_dump(data, sort_keys=True), encoding="utf-8")
    os.chmod(destination, 0o600)


def _stage_recipe(root: Path, base_url: str, target_id: str, *,
                  recipe_id: str = "owned_document", alias: str = "owner",
                  tenant_label: str = "tenant-a",
                  include_rename_mutation: bool = False) -> None:
    path = root / "benchmark" / (recipe_id + ".json")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    import json
    recipe = {
        "id": recipe_id, "target_id": target_id, "package_id": "benchmark",
        "object_type": "document", "protocol": "REST", "source": "manual_fixture",
        "expected_owner": alias, "expected_tenant": tenant_label,
        "create": {"method": "POST", "url": base_url + f"/fixture/{tenant_label}/documents",
                   "operation": "createDocument", "body": {"name": "$test_name"}},
        "verify": {"method": "GET", "url": base_url + f"/fixture/{tenant_label}/documents/{{object_id}}",
                   "operation": "readDocument"},
        "update": {"method": "PATCH", "url": base_url + f"/fixture/{tenant_label}/documents/{{object_id}}",
                   "operation": "renameDocument", "body": {"name": "$test_name"}},
        "cleanup": {"method": "DELETE", "url": base_url + f"/fixture/{tenant_label}/documents/{{object_id}}",
                    "operation": "deleteDocument"},
        "id_pointer": "/id", "verify_id_pointer": "/id",
        "verify_name_pointer": "/name", "verify_owner_pointer": "/owner",
        "verify_tenant_pointer": "/tenant", "cleanup_strategy": "AUTO_CLEANUP",
    }
    if include_rename_mutation:
        recipe["mutations"] = [{
            "type": "RENAME", "field": "name", "write": recipe["update"],
            "readback": recipe["verify"], "readback_pointer": "/name",
            "restore": recipe["update"], "side_effect": "SAFE_UPDATE",
            "identity_requirement": "VERIFIED_DISPOSABLE_OWNER_AND_BOUNDARY",
        }]
    path.write_text(json.dumps(recipe, sort_keys=True), encoding="utf-8")
    os.chmod(path, 0o600)


def _actor(runtime: BugHunterRuntime, package: object, *,
           alias: str = "owner", tenant_label: str = "tenant-a",
           existing_tenant: Tenant | None = None):
    target_id = package.target.id
    provider = RoutedSecretProvider(
        SecretSettings(bindings=tuple(SecretBindingConfig(
            f"ref:fixture_{name}", f"env:HACKBOT_SECRET_FIXTURE_{name.upper()}",
            "COOKIE") for name in ("owner", "foreign"))),
        {"HACKBOT_SECRET_FIXTURE_OWNER": "fixture_actor=owner",
         "HACKBOT_SECRET_FIXTURE_FOREIGN": "fixture_actor=foreign"})
    runtime.auth.secrets = provider
    runtime.executor.secrets = provider
    identity = runtime.registry.register_identity(
        target_id, alias, status=IdentityStatus.ACTIVE,
        secret_ref=f"ref:fixture_{alias}")
    runtime.auth.prepare(target_id, identity.id)
    session = runtime.browser.create(target_id, identity.id)
    runtime.browser.driver.register(session.id, alias, tenant_label)
    runtime.browser.start(session.id)
    runtime.browser.login_complete(session.id)
    rule = IdentityVerificationRule(target_id, identity.id, "[data-user]", None,
                                    "[data-tenant]", alias, None, tenant_label)
    runtime.browser.verify(session.id, rule)
    principal = runtime.registry.register_principal(
        Principal(target_id=target_id, label=alias))
    proof = runtime.store.create_evidence(
        "TEST_ASSERTION", b"synthetic-owner", source="FIXTURE",
        provenance=EvidenceProvenance(system="FIXTURE"), target_ref=target_id)
    relation = runtime.store.create_fact(
        identity.id, "resolves_to", principal.id, confidence=1,
        evidence_ids=(proof.evidence_id,), source="FIXTURE", target_ref=target_id)
    runtime.registry.link_principal(
        identity.id, principal.id, observation_state=ObservationState.OBSERVED,
        evidence_ids=(proof.evidence_id,), fact_id=relation.fact_id)
    if existing_tenant is not None:
        if (existing_tenant.target_id != target_id or
                existing_tenant.label != tenant_label):
            raise ValueError("Synthetic identity tenant mismatch")
        tenant = existing_tenant
    else:
        tenant = runtime.registry.register_tenant(
            Tenant(target_id=target_id, label=tenant_label, kind="organization"))
    membership = runtime.store.create_fact(
        identity.id, "member_of", tenant.id, confidence=1,
        evidence_ids=(proof.evidence_id,), source="FIXTURE", target_ref=target_id)
    runtime.registry.add_membership(
        identity.id, tenant.id, status=MembershipStatus.ACTIVE,
        observation_state=ObservationState.OBSERVED,
        evidence_ids=(proof.evidence_id,), fact_id=membership.fact_id)
    return identity, session, tenant


def _read(runtime: BugHunterRuntime, package: object, url: str, *,
          identity: object | None = None, session: object | None = None):
    action = ProposedAction(
        target_id=package.target.id, package_id=package.id,
        category=ActionCategory.SAFE_READ,
        actor=ActorMode.AUTHENTICATED if identity else ActorMode.ANONYMOUS,
        source="benchmark", purpose="Synthetic owned download control",
        url=url, method="GET", identity_id=identity.id if identity else None,
        session_id=session.id if session else None)
    template = RequestTemplate("GET", url)
    permit = runtime.executor.authorize(action, template)
    return runtime.executor.execute(action, permit, template)


def run_owned_download_validation(package_template: Path, work_root: Path,
                                  *, secure: bool,
                                  stale_observation: bool = False,
                                  campaign_probe: bool = False,
                                  case_id: str | None = None,
                                  noisy: bool = False,
                                  planner_advisor: PlannerAdvisor | None = None,
                                  token_budget: int = 0) -> LocalValidationResult:
    """Loopback probe; only the campaign mode exercises planner discovery."""
    if stale_observation and not secure:
        raise ValueError("Stale-observation control requires a secure current target")
    if noisy and (not campaign_probe or stale_observation):
        raise ValueError("Noisy fixture requires a current campaign")
    if (type(token_budget) is not int or token_budget < 0 or
            (planner_advisor is not None and token_budget < 200)):
        raise ValueError("Invalid local benchmark token budget")
    work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with BenchmarkHTTPFixture(secure=secure, max_requests=40, noisy=noisy) as fixture:
        with TemporaryDirectory(prefix="local-validator-", dir=work_root) as directory:
            root = Path(directory)
            _stage_package(package_template, root / "targets/benchmark/target.yaml",
                           fixture._server.server_port)
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
            runtime.planner.advisor = planner_advisor
            package = runtime.package("benchmark")
            if (package.scope.evaluate_url(fixture.base_url + "/").result.value !=
                    "IN_SCOPE" or package.scope.include_hosts[0].pattern != "127.0.0.1"):
                raise ValueError("Local fixture scope is not loopback-only")
            runtime.registry.register_target(package)
            identity, session, tenant = _actor(runtime, package)
            _stage_recipe(root / "recipes", fixture.base_url, package.target.id)
            created = runtime.object_factory.resolve(
                package_id=package.id, recipe_id="owned_document",
                identity_id=identity.id, tenant_id=tenant.id, session_id=session.id,
                purpose="Synthetic benchmark fixture setup")
            if created.outcome != "READY" or created.item is None:
                raise RuntimeError("Local fixture object setup failed: " +
                                   created.outcome + ":" + created.reason +
                                   ":" + str(tuple((entry.method, entry.path, entry.status)
                                                   for entry in fixture.requests)))
            item = created.item
            validation_status = None
            finding = None
            evidence_count = 0
            audit = False
            campaign_status = campaign_stop_reason = None
            campaign_candidates = campaign_selected = 0
            campaign_validations = campaign_findings = 0
            campaign_trace = None
            try:
                external = runtime.object_factory._external_id(item)
                url = fixture.base_url + "/fixture/tenant-a/documents/" + external
                for predicate, value in (("resource_visibility", "PRIVATE"),
                                         ("data_classification", "PROTECTED_FILE")):
                    runtime.store.create_fact(
                        hashlib.sha256(external.encode()).hexdigest(),
                        predicate, value, confidence=1.0,
                        evidence_ids=(item.verification_evidence_ids[0],),
                        source="FIXTURE", target_ref=package.target.id)
                owner_read = _read(runtime, package, url, identity=identity, session=session)
                anonymous_read = _read(runtime, package, url)
                if owner_read.error is not None or anonymous_read.error is not None:
                    raise RuntimeError("Local fixture baseline read failed")
                if noisy:
                    for path in ("/admin/", "/graphql", "/api/internal/config",
                                 "/api/files/public-sample/download",
                                 "/assets/noise.js", "/assets/noise.js.map"):
                        for actor_identity, actor_session in ((identity, session),
                                                              (None, None)):
                            response = _read(runtime, package, fixture.base_url + path,
                                             identity=actor_identity,
                                             session=actor_session)
                            if response.error is not None:
                                raise RuntimeError("Local noisy fixture read failed")
                if stale_observation:
                    owner_exchange = runtime.traffic.get_exchange(owner_read.exchange_ids[0])
                    if (owner_exchange is None or owner_exchange.response is None or
                            owner_exchange.response.body_evidence_id is None):
                        raise RuntimeError("Local fixture owner baseline unavailable")
                    historical_body = runtime.store.read_content(
                        owner_exchange.response.body_evidence_id,
                        allow_sensitive=True, max_bytes=8192)
                    historical = runtime.traffic.store_request(
                        package, CapturedRequest("GET", url),
                        source=TrafficSource.FIXTURE,
                        capture_provider="BENCHMARK_STALE_CONTROL", anonymous=True)
                    runtime.traffic.store_response(
                        historical.id, CapturedResponse(200,
                        (("Content-Type", "application/json"),), historical_body))
                discovered = runtime.exposure.discover_traffic(package)
                if campaign_probe:
                    campaign_started = datetime.now(timezone.utc).isoformat()
                    profile = AttackSurfaceProfiler(
                        runtime.registry, runtime.store, runtime.traffic,
                        bootstrap=runtime.bootstrap_store).profile(package)
                    runtime.hypotheses.save_profile(profile)
                    HypothesisGenerator(runtime.hypotheses).generate(profile)
                    campaign = runtime.campaign.start(
                        package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
                        limits=CampaignLimits(max_cycles=1, seconds=180,
                                              requests=20, browser_actions=0,
                                              research_requests=0,
                                              tokens=token_budget,
                                              setup_objects=0, cleanup_reserve=0),
                        requested_by="benchmark")
                    for _ in range(80):
                        campaign = runtime.campaign.advance(package, campaign.id)
                        if (campaign.status in TERMINAL_CAMPAIGN_STATUSES or
                                campaign.status.value.startswith("WAITING_") or
                                campaign.status.value == "PAUSED"):
                            break
                    detail = runtime.campaign.detail(package, campaign.id)
                    campaign_status = campaign.status.value
                    campaign_stop_reason = campaign.stop_reason or next(
                        (task["reason_code"] for task in detail["active_tasks"]
                         if task["reason_code"]), None)
                    metrics = detail["metrics"]
                    campaign_candidates = metrics["candidates_considered"]
                    campaign_selected = metrics["candidates_selected"]
                    campaign_validations = metrics["validations"]
                    campaign_findings = metrics["findings"]
                    campaign_trace = collect_case_trace(
                        runtime, case_id or ("local_download_guarded" if secure else
                        "local_download_exposed"), campaign, campaign_started,
                        datetime.now(timezone.utc).isoformat())
                    if campaign_trace.findings:
                        observed = campaign_trace.findings[0]
                        finding = runtime.validations.get_finding(
                            observed.finding_id, package.target.id)
                        validation = runtime.validations.get(
                            observed.validation_id, package.target.id)
                        validation_status = validation.status.value if validation else None
                        evidence_count = observed.evidence_count
                        audit = observed.audit_complete
                elif secure and not stale_observation:
                    if discovered.candidate_ids:
                        raise RuntimeError("Secure fixture generated an exposure candidate")
                else:
                    if len(discovered.candidate_ids) != 1:
                        raise RuntimeError("Local fixture exposure candidate missing")
                    candidate_id = discovered.candidate_ids[0]
                    runtime.exposure.prepare_candidate(
                        package, candidate_id, hypotheses=runtime.hypotheses,
                        contexts=runtime.skill_context, router=runtime.skill_router,
                        planner=runtime.skill_planner)
                    bound = runtime.exposure.bind_owned_read(
                        package, candidate_id, test_object_id=item.id,
                        owner_session_id=session.id, objects=runtime.objects,
                        hypotheses=runtime.hypotheses, contexts=runtime.skill_context,
                        planner=runtime.skill_planner)
                    state = runtime.orchestrator.start(bound.plan_id, package.id)
                    for _ in range(12):
                        if state["run"]["status"] == "COMPLETED":
                            break
                        state = runtime.orchestrator.advance(state["run"]["id"], package.id)
                    if state["run"]["status"] != "COMPLETED":
                        raise RuntimeError("Synthetic validation plan did not complete")
                    validation, finding = runtime.validator.validate_run(
                        state["run"]["id"], package.target.id)
                    validation_status = validation.status.value
                    evidence_count = len(validation.supporting_evidence_ids)
                    if secure and finding is not None:
                        raise RuntimeError("Secure current fixture produced a finding")
                    audit = bool(finding and validation.status is ValidationStatus.CONFIRMED and
                                 finding.validation_id == validation.id and
                                 validation.run_id == state["run"]["id"] and
                                 validation.plan_id == bound.plan_id and
                                 validation.hypothesis_id == bound.hypothesis_id)
            finally:
                cleanup = runtime.object_factory.cleanup(
                    item.id, package.target.id, session_id=session.id)
            requests = fixture.requests
            exchanges = runtime.traffic.list_exchanges_for_target(
                package.target.id, limit=100).items
            outside = sum(exchange.request.origin != fixture.base_url
                          for exchange in exchanges)
            if outside:
                raise RuntimeError("Synthetic benchmark attempted non-loopback traffic")
            return LocalValidationResult(
                secure=secure, stale_observation=stale_observation,
                validation_status=validation_status,
                finding_id=finding.id if finding else None,
                finding_category=finding.category if finding else None,
                evidence_count=evidence_count, requests=len(requests),
                setup_requests=sum(entry.method == "POST" for entry in requests),
                verification_requests=sum(entry.method in {"GET", "HEAD"}
                                          for entry in requests),
                cleanup_requests=sum(entry.method == "DELETE" for entry in requests),
                objects_created=1, objects_cleaned=int(cleanup.outcome == "CLEANED"),
                orphaned_objects=int(cleanup.outcome != "CLEANED" or fixture.document_count != 0),
                outside_loopback=outside, audit_chain_complete=audit,
                campaign_status=campaign_status,
                campaign_candidates=campaign_candidates,
                campaign_selected=campaign_selected,
                campaign_validations=campaign_validations,
                campaign_findings=campaign_findings,
                campaign_stop_reason=campaign_stop_reason,
                campaign_trace=campaign_trace)
