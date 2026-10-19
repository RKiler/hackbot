"""Scored loopback-only campaign benchmarks with a separate fixture harness."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Mapping

from .benchmark_advice import BenchmarkComparisonAdvisor, ModelBenchmarkProvider
from .benchmark_authorization import run_cross_tenant_campaign
from .benchmark_browser import run_browser_campaign
from .benchmark_catalog import BenchmarkCatalog
from .benchmark_eval import (CaseTrace, ModelCallUsage,
                             ModelComparisonObservation)
from .benchmark_local import run_owned_download_validation
from .benchmark_models import (BENCHMARK_VERSION, BenchmarkFixtureKind,
                               BenchmarkRunConfig, ModelLane, ModelRole,
                               VisibleBenchmarkCase)
from .benchmark_runner import BenchmarkOfflineRunner, _now
from .benchmark_store import BenchmarkStore


class BenchmarkLocalRunner(BenchmarkOfflineRunner):
    """Exercise Campaign through Phase 17 against disposable loopback objects."""

    def __init__(self, catalog: BenchmarkCatalog, store: BenchmarkStore,
                 work_root: Path, harness_root: Path, *,
                 providers: Mapping[tuple[ModelRole, ModelLane, str, str],
                                    ModelBenchmarkProvider] | None = None) -> None:
        super().__init__(catalog, store, work_root)
        self.harness_root = harness_root.resolve(strict=True)
        if (not self.harness_root.is_dir() or
                self.harness_root == catalog.visible_root or
                self.harness_root == catalog.truth_root or
                self.harness_root.is_relative_to(catalog.visible_root) or
                self.harness_root.is_relative_to(catalog.truth_root)):
            raise ValueError("Fixture harness must be separate from visible and truth roots")
        self._harness_hashes: dict[str, str] = {}
        self.providers = dict(providers or {})

    def _harness(self, case_id: str) -> tuple[str, str]:
        path = self.harness_root / (case_id + ".json")
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
            raise ValueError("Local benchmark harness unavailable")
        raw = path.read_bytes()
        control = json.loads(raw)
        if (not isinstance(control, dict) or
                set(control) != {"case_id", "version", "server_mode"} or
                control["case_id"] != case_id or
                type(control["version"]) is not int or control["version"] != 1 or
                control["server_mode"] not in {"VULNERABLE", "GUARDED",
                                               "NOISY_GUARDED", "NOISY_VULNERABLE",
                                               "TENANT_VULNERABLE", "TENANT_GUARDED",
                                               "TENANT_MUTATION_VULNERABLE",
                                               "TENANT_MUTATION_GUARDED",
                                               "MIXED_VULNERABLE", "MIXED_GUARDED",
                                               "HORIZONTAL_VULNERABLE",
                                               "HORIZONTAL_GUARDED",
                                               "GRAPHQL_VULNERABLE",
                                               "GRAPHQL_GUARDED",
                                               "GRAPHQL_FIELD_VULNERABLE",
                                               "GRAPHQL_FIELD_GUARDED",
                                               "DOM_VULNERABLE", "DOM_GUARDED",
                                               "MESSAGE_VULNERABLE", "MESSAGE_GUARDED"}):
            raise ValueError("Invalid local benchmark harness")
        return control["server_mode"], hashlib.sha256(raw).hexdigest()

    def _members(self, config: BenchmarkRunConfig) -> tuple[tuple[str, str], ...]:
        if config.planner_mode != "BOUNDED_AUTONOMOUS":
            raise ValueError("Local runner accepts bounded campaigns only")
        if set(config.ablations) - {"NO_MODEL", "NO_CHALLENGER"}:
            raise ValueError("Unsupported local benchmark ablation")
        if config.ablations and not config.models:
            raise ValueError("Model ablation requires selected model lanes")
        if "NO_CHALLENGER" in config.ablations and not any(
                item.lane is ModelLane.CHALLENGER for item in config.models):
            raise ValueError("NO_CHALLENGER requires a challenger lane")
        if (config.suite in {"local-graphql-approved", "local-graphql-field-approved"} and
                any(self.catalog.visible(case_id).fixture_kind is not
                    (BenchmarkFixtureKind.LOCAL_GRAPHQL_OBJECT if
                     config.suite == "local-graphql-approved" else
                     BenchmarkFixtureKind.LOCAL_GRAPHQL_FIELD)
                    for case_id in self.catalog.suite(config.suite))):
            raise ValueError("Synthetic approval suite contains a non-GraphQL case")
        for selection in config.models:
            suppressed = ("NO_MODEL" in config.ablations or
                          "NO_CHALLENGER" in config.ablations and
                          selection.lane is ModelLane.CHALLENGER)
            if ((selection.role, selection.lane) not in {
                    (ModelRole.PLANNER_ADVISOR, ModelLane.PRIMARY),
                    (ModelRole.PLANNER_ADVISOR, ModelLane.CHALLENGER),
                    (ModelRole.FALSE_POSITIVE_CRITIC, ModelLane.CRITIC)} or
                    (not suppressed and (selection.role, selection.lane,
                                         selection.provider, selection.model)
                     not in self.providers)):
                raise ValueError("Benchmark model provider is not configured")
        rows = []
        for case_id in self.catalog.suite(config.suite):
            case = self.catalog.visible(case_id)
            if (case.fixture_kind not in {
                    BenchmarkFixtureKind.LOCAL_OWNED_DOWNLOAD,
                    BenchmarkFixtureKind.LOCAL_OWNED_WORKSPACE,
                    BenchmarkFixtureKind.LOCAL_CROSS_TENANT_READ,
                    BenchmarkFixtureKind.LOCAL_CROSS_TENANT_MUTATION,
                    BenchmarkFixtureKind.LOCAL_MIXED_WORKSPACE,
                    BenchmarkFixtureKind.LOCAL_HORIZONTAL_READ,
                    BenchmarkFixtureKind.LOCAL_GRAPHQL_OBJECT,
                    BenchmarkFixtureKind.LOCAL_GRAPHQL_FIELD,
                    BenchmarkFixtureKind.LOCAL_DOM_XSS,
                    BenchmarkFixtureKind.LOCAL_POSTMESSAGE} or
                    case.fixture_id != "benchmark" or
                    case.target_package != "package/target.yaml" or
                    case.scope_hosts != ("127.0.0.1",) or
                    case.identity_aliases != (() if case.fixture_kind in {
                        BenchmarkFixtureKind.LOCAL_DOM_XSS,
                        BenchmarkFixtureKind.LOCAL_POSTMESSAGE} else
                        ("owner", "foreign") if
                    case.fixture_kind in {BenchmarkFixtureKind.LOCAL_CROSS_TENANT_READ,
                                          BenchmarkFixtureKind.LOCAL_CROSS_TENANT_MUTATION,
                                          BenchmarkFixtureKind.LOCAL_MIXED_WORKSPACE,
                                          BenchmarkFixtureKind.LOCAL_HORIZONTAL_READ,
                                          BenchmarkFixtureKind.LOCAL_GRAPHQL_OBJECT,
                                          BenchmarkFixtureKind.LOCAL_GRAPHQL_FIELD}
                    else ("owner",)) or case.input_files or
                    case.context_file or case.budget.requests > (
                        80 if case.fixture_kind is
                        BenchmarkFixtureKind.LOCAL_CROSS_TENANT_MUTATION or
                        case.fixture_kind in {BenchmarkFixtureKind.LOCAL_MIXED_WORKSPACE,
                                              BenchmarkFixtureKind.LOCAL_HORIZONTAL_READ,
                                              BenchmarkFixtureKind.LOCAL_GRAPHQL_OBJECT,
                                              BenchmarkFixtureKind.LOCAL_GRAPHQL_FIELD}
                        else 40) or
                    (config.models and case.fixture_kind is
                     BenchmarkFixtureKind.LOCAL_CROSS_TENANT_READ) or
                    (config.models and case.fixture_kind is
                     BenchmarkFixtureKind.LOCAL_CROSS_TENANT_MUTATION) or
                    (config.models and case.fixture_kind is
                     BenchmarkFixtureKind.LOCAL_MIXED_WORKSPACE) or
                    (config.models and case.fixture_kind is
                     BenchmarkFixtureKind.LOCAL_HORIZONTAL_READ) or
                    (config.models and case.fixture_kind is
                     BenchmarkFixtureKind.LOCAL_GRAPHQL_OBJECT) or
                    (config.models and case.fixture_kind is
                     BenchmarkFixtureKind.LOCAL_GRAPHQL_FIELD) or
                    (config.models and case.fixture_kind in {
                        BenchmarkFixtureKind.LOCAL_DOM_XSS,
                        BenchmarkFixtureKind.LOCAL_POSTMESSAGE}) or
                    (config.models and case.budget.tokens < 200)):
                raise ValueError("Unsupported local benchmark case")
            if self.catalog.audit_visible_inputs(case_id):
                raise ValueError("Benchmark answer key leaked into visible fixture")
            rows.append((case_id, case.visible_hash))
        return tuple(rows)

    def run(self, config: BenchmarkRunConfig, *, bughunter_version: str,
            bughunter_schema: int) -> str:
        members = self._members(config)
        with self._lock():
            self.store.initialize()
            self._harness_hashes = {case_id: self._harness(case_id)[1]
                                    for case_id, _ in members}
            run_id = self.store.create(
                config, members, benchmark_version=BENCHMARK_VERSION,
                bughunter_version=bughunter_version, bughunter_schema=bughunter_schema,
                environment={"mode": "SYNTHETIC_LOCAL", "network": "LOOPBACK_ONLY",
                             "answer_root_in_runtime": False,
                             "synthetic_operator_approval": config.suite in {
                                 "local-graphql-approved", "local-graphql-field-approved"},
                             "harness_hashes": self._harness_hashes})
            self._execute(run_id)
            return run_id

    def resume(self, run_id: str) -> str:
        with self._lock():
            self.store.initialize()
            run = self.store.get(run_id)
            if run is None or run["environment"].get("mode") != "SYNTHETIC_LOCAL":
                raise ValueError("Benchmark run is not a local fixture run")
            config = BenchmarkRunConfig.from_dict(run["config"])
            members = self._members(config)
            rows = self.store.cases(run_id, limit=256)
            if (len(rows) != len(members) * config.trials or
                    {(item["case_id"], item["visible_hash"]) for item in rows}
                    != set(members)):
                raise ValueError("Benchmark case set or fixture has changed")
            expected = run["environment"].get("harness_hashes")
            if (not isinstance(expected, dict) or
                    expected != {case_id: self._harness(case_id)[1]
                                 for case_id, _ in members}):
                raise ValueError("Benchmark harness changed since run start")
            self._harness_hashes = expected
            self.store.reconcile_interrupted(run_id)
            self._execute(run_id)
            return run_id

    def _run_case(self, case: VisibleBenchmarkCase,
                  config: BenchmarkRunConfig) -> CaseTrace:
        mode, digest = self._harness(case.case_id)
        if digest != self._harness_hashes.get(case.case_id):
            raise ValueError("Benchmark harness changed during run")
        selected = {(item.role, item.lane): item for item in config.models}
        def provider(role: ModelRole, lane: ModelLane) -> ModelBenchmarkProvider | None:
            if ("NO_MODEL" in config.ablations or
                    "NO_CHALLENGER" in config.ablations and
                    lane is ModelLane.CHALLENGER):
                return None
            item = selected.get((role, lane))
            return (self.providers[(role, lane, item.provider, item.model)]
                    if item else None)
        advisor = (BenchmarkComparisonAdvisor(
            primary=provider(ModelRole.PLANNER_ADVISOR, ModelLane.PRIMARY),
            challenger=provider(ModelRole.PLANNER_ADVISOR, ModelLane.CHALLENGER),
            critic=provider(ModelRole.FALSE_POSITIVE_CRITIC, ModelLane.CRITIC))
            if config.models and "NO_MODEL" not in config.ablations else None)
        package = self.catalog.visible_root / case.case_id / case.target_package
        if case.fixture_kind in {BenchmarkFixtureKind.LOCAL_DOM_XSS,
                                 BenchmarkFixtureKind.LOCAL_POSTMESSAGE}:
            family = ("DOM" if case.fixture_kind is BenchmarkFixtureKind.LOCAL_DOM_XSS
                      else "MESSAGE")
            if mode not in {family + "_VULNERABLE", family + "_GUARDED"}:
                raise ValueError("Browser harness mode mismatch")
            trace = run_browser_campaign(
                package, self.work_root, family=family,
                secure=mode.endswith("_GUARDED"), case_id=case.case_id,
                max_requests=case.budget.requests)
        elif case.fixture_kind in {BenchmarkFixtureKind.LOCAL_CROSS_TENANT_READ,
                                 BenchmarkFixtureKind.LOCAL_CROSS_TENANT_MUTATION,
                                 BenchmarkFixtureKind.LOCAL_MIXED_WORKSPACE,
                                 BenchmarkFixtureKind.LOCAL_HORIZONTAL_READ,
                                 BenchmarkFixtureKind.LOCAL_GRAPHQL_OBJECT,
                                 BenchmarkFixtureKind.LOCAL_GRAPHQL_FIELD}:
            mutation = case.fixture_kind is BenchmarkFixtureKind.LOCAL_CROSS_TENANT_MUTATION
            mixed = case.fixture_kind is BenchmarkFixtureKind.LOCAL_MIXED_WORKSPACE
            horizontal = case.fixture_kind is BenchmarkFixtureKind.LOCAL_HORIZONTAL_READ
            graphql = case.fixture_kind is BenchmarkFixtureKind.LOCAL_GRAPHQL_OBJECT
            graphql_field = case.fixture_kind is BenchmarkFixtureKind.LOCAL_GRAPHQL_FIELD
            allowed_modes = ({"GRAPHQL_FIELD_VULNERABLE", "GRAPHQL_FIELD_GUARDED"}
                             if graphql_field else
                             {"GRAPHQL_VULNERABLE", "GRAPHQL_GUARDED"} if graphql else
                             {"HORIZONTAL_VULNERABLE", "HORIZONTAL_GUARDED"} if horizontal else
                             {"MIXED_VULNERABLE", "MIXED_GUARDED"} if mixed else
                             {"TENANT_MUTATION_VULNERABLE", "TENANT_MUTATION_GUARDED"}
                             if mutation else {"TENANT_VULNERABLE", "TENANT_GUARDED"})
            if mode not in allowed_modes:
                raise ValueError("Cross-tenant harness mode mismatch")
            trace = run_cross_tenant_campaign(
                package, self.work_root,
                secure=mode in {"TENANT_GUARDED", "TENANT_MUTATION_GUARDED",
                                "MIXED_GUARDED", "HORIZONTAL_GUARDED",
                                "GRAPHQL_GUARDED", "GRAPHQL_FIELD_GUARDED"},
                case_id=case.case_id, max_requests=case.budget.requests,
                mutation=mutation, mixed=mixed, horizontal=horizontal,
                graphql=graphql, graphql_field=graphql_field,
                approve_graphql_fixture=(
                    graphql and config.suite == "local-graphql-approved" or
                    graphql_field and config.suite == "local-graphql-field-approved"))
        else:
            if mode not in {"VULNERABLE", "GUARDED", "NOISY_GUARDED",
                            "NOISY_VULNERABLE"}:
                raise ValueError("Download harness mode mismatch")
            result = run_owned_download_validation(
                package, self.work_root,
                secure=mode not in {"VULNERABLE", "NOISY_VULNERABLE"},
                campaign_probe=True, case_id=case.case_id,
                noisy=mode in {"NOISY_GUARDED", "NOISY_VULNERABLE"},
                planner_advisor=advisor, token_budget=case.budget.tokens)
            if result.campaign_trace is None:
                raise ValueError("Local benchmark campaign trace unavailable")
            trace = result.campaign_trace
            trace = replace(trace, usage=replace(
                trace.usage, requests=result.requests,
                setup_requests=result.setup_requests,
                verification_requests=result.verification_requests,
                cleanup_requests=result.cleanup_requests,
                objects_created=result.objects_created,
                objects_cleaned=result.objects_cleaned,
                orphaned_objects=result.orphaned_objects,
                manual_context_required=int(result.campaign_status == "WAITING_HUMAN"),
                safety_violations=("NON_LOOPBACK_REQUEST",)
                if result.outside_loopback else ()))
        if trace.usage.requests > case.budget.requests:
            raise ValueError("Local benchmark exceeded request budget")
        if self._harness(case.case_id)[1] != digest:
            raise ValueError("Benchmark harness changed during case")
        calls = []
        comparisons = []
        if advisor is not None:
            for comparison in advisor.comparisons:
                comparisons.append(ModelComparisonObservation(
                    baseline_order=comparison.baseline_order,
                    primary_status=comparison.primary.status,
                    primary_order=comparison.primary.ordered_candidate_ids,
                    challenger_status=comparison.challenger.status,
                    challenger_order=comparison.challenger.ordered_candidate_ids,
                    critic_status=(comparison.critic.status if comparison.critic
                                   else "NOT_CONFIGURED"),
                    critic_order=(comparison.critic.ordered_candidate_ids
                                  if comparison.critic else ()),
                    disagreement_count=comparison.disagreement_count,
                    provenance=comparison.provenance))
                for role, lane, observation in (
                        (ModelRole.PLANNER_ADVISOR, ModelLane.PRIMARY,
                         comparison.primary),
                        (ModelRole.PLANNER_ADVISOR, ModelLane.CHALLENGER,
                         comparison.challenger),
                        (ModelRole.FALSE_POSITIVE_CRITIC, ModelLane.CRITIC,
                         comparison.critic)):
                    selection = selected.get((role, lane))
                    if selection is not None and observation is not None and \
                            observation.status == "VALID":
                        calls.append(ModelCallUsage(
                            role, lane, selection.provider, selection.model,
                            observation.input_tokens, observation.output_tokens,
                            observation.latency_ms))
        if sum(call.input_tokens + call.output_tokens for call in calls) > case.budget.tokens:
            raise ValueError("Benchmark model token budget exceeded")
        usage = replace(trace.usage,
                        input_tokens=sum(call.input_tokens for call in calls),
                        output_tokens=sum(call.output_tokens for call in calls),
                        manual_context_required=int(trace.failure_reason == "WAITING_HUMAN"))
        return replace(trace, usage=usage, model_calls=tuple(calls),
                       model_comparisons=tuple(comparisons),
                       finished_at=_now())
