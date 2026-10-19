"""Isolated, offline Phase 33 campaign runner for blind synthetic fixtures.

This path exercises BugHunter's normal passive profile and campaign pipeline.
It intentionally has no active-target executor; active local fixture validation
is a separate benchmark mode and must not be inferred from this result.
"""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timezone
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from .benchmark_catalog import BenchmarkCatalog
from .benchmark_eval import CaseTrace, evaluate_case
from .benchmark_models import (BENCHMARK_VERSION, BenchmarkFixtureKind,
                               BenchmarkRunConfig, BenchmarkStatus,
                               VisibleBenchmarkCase)
from .benchmark_trace import collect_case_trace
from .benchmark_store import BenchmarkStore
from .resources import ResourceError
from .campaign_models import CampaignLimits, TERMINAL_CAMPAIGN_STATUSES
from .config import NotificationSettings, TargetSettings, load_config
from .domain import TrafficSource
from .hypotheses import HypothesisGenerator
from .planner_models import PlannerMode
from .profile import AttackSurfaceProfiler
from .service import BugHunterRuntime
from .traffic import CapturedRequest, CapturedResponse


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fixture_traffic(path: Path) -> tuple[dict[str, object], ...]:
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Oversized benchmark traffic input")
    data = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(data, list) or len(data) > 100 or
            any(not isinstance(item, dict) or
                not {"method", "url", "status"} <= set(item) or
                set(item) - {"method", "url", "status", "body", "content_type"} or
                not isinstance(item["method"], str) or
                not isinstance(item["url"], str) or
                type(item["status"]) is not int or
                ("body" in item and (not isinstance(item["body"], str) or
                                     len(item["body"]) > 4096)) or
                ("content_type" in item and item["content_type"] not in
                 {"application/json", "text/plain", "text/html"}) for item in data)):
        raise ValueError("Invalid benchmark traffic input")
    return tuple(data)


class BenchmarkOfflineRunner:
    """No model, browser or live HTTP calls; fixture traffic is imported locally."""

    def __init__(self, catalog: BenchmarkCatalog, store: BenchmarkStore,
                 work_root: Path) -> None:
        if catalog.truth_root is None:
            raise ValueError("Evaluation requires a separate answer store")
        self.catalog = catalog
        self.store = store
        self.work_root = work_root.resolve(strict=False)

    def run(self, config: BenchmarkRunConfig, *, bughunter_version: str,
            bughunter_schema: int) -> str:
        if config.planner_mode != "ANALYZE_ONLY" or config.models:
            raise ValueError("Offline runner accepts deterministic analysis only")
        if set(config.ablations) - {"NO_TRAFFIC"}:
            raise ValueError("Offline runner supports only NO_TRAFFIC ablation")
        members = self.catalog.suite(config.suite)
        if any(self.catalog.visible(case_id).fixture_kind is not
               BenchmarkFixtureKind.RECORDED_TRAFFIC for case_id in members):
            raise ValueError("Offline runner cannot execute local active fixtures")
        cases = tuple((case_id, self.catalog.visible(case_id).visible_hash)
                      for case_id in members)
        for case_id in members:
            leaks = self.catalog.audit_visible_inputs(case_id)
            if leaks:
                raise ValueError("Benchmark answer key leaked into visible fixture")
        with self._lock():
            self.store.initialize()
            run_id = self.store.create(
                config, cases, benchmark_version=BENCHMARK_VERSION,
                bughunter_version=bughunter_version, bughunter_schema=bughunter_schema,
                environment={"mode": "SYNTHETIC_OFFLINE", "network": "DISABLED",
                             "answer_root_in_runtime": False})
            self._execute(run_id)
            return run_id

    def resume(self, run_id: str) -> str:
        """Continue pending cases; mark an interrupted claim ambiguous, never replay it."""
        with self._lock():
            self.store.initialize()
            run = self.store.get(run_id)
            if run is None or run["environment"].get("mode") != "SYNTHETIC_OFFLINE":
                raise ValueError("Benchmark run is not an offline fixture run")
            config = BenchmarkRunConfig.from_dict(run["config"])
            if config.planner_mode != "ANALYZE_ONLY" or config.models:
                raise ValueError("Benchmark run configuration is not offline")
            if set(config.ablations) - {"NO_TRAFFIC"}:
                raise ValueError("Offline runner supports only NO_TRAFFIC ablation")
            members = self.catalog.suite(config.suite)
            if any(self.catalog.visible(case_id).fixture_kind is not
                   BenchmarkFixtureKind.RECORDED_TRAFFIC for case_id in members):
                raise ValueError("Offline runner cannot resume local active fixtures")
            rows = []
            for offset in range(0, 1280, 100):
                page = self.store.cases(run_id, limit=100, offset=offset)
                rows.extend(page)
                if len(page) < 100:
                    break
            if (len(rows) != len(members) * config.trials or
                    {item["case_id"] for item in rows} != set(members)):
                raise ValueError("Benchmark run case set has changed")
            for item in rows:
                if self.catalog.visible(item["case_id"]).visible_hash != item["visible_hash"]:
                    raise ValueError("Benchmark fixture changed since run start")
            self.store.reconcile_interrupted(run_id)
            self._execute(run_id)
            return run_id

    @contextmanager
    def _lock(self):
        self.work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.work_root, 0o700)
        path = self.work_root / ".benchmark-run.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def _execute(self, run_id: str) -> None:
        run = self.store.get(run_id)
        if run is None:
            raise ValueError("Benchmark run unavailable")
        config = BenchmarkRunConfig.from_dict(run["config"])
        while claimed := self.store.claim(run_id):
            case_id = str(claimed["case_id"])
            trial = int(claimed["trial"])
            try:
                visible = self.catalog.visible(case_id)
                if visible.visible_hash != claimed["visible_hash"]:
                    raise ValueError("Benchmark fixture changed during run")
                trace = self._run_case(visible, config)
                result = evaluate_case(self.catalog.evaluator_case(case_id), trace)
                self.store.finish_case(run_id, case_id, trial,
                                       status=BenchmarkStatus.COMPLETED,
                                       campaign_id=trace.campaign_id,
                                       trace=asdict(trace), evaluation=result.to_dict())
            except Exception as exc:
                # No raw exception text: it can contain fixture or credential content.
                self.store.finish_case(run_id, case_id, trial,
                                       status=BenchmarkStatus.FAILED,
                                       campaign_id=None, trace=None, evaluation=None,
                                       error_code=(exc.reason_code if isinstance(exc, ResourceError)
                                                   else type(exc).__name__))
        self.store.finalize(run_id)

    def _run_case(self, case: VisibleBenchmarkCase,
                  config: BenchmarkRunConfig) -> CaseTrace:
        if any(not host.endswith(".test") for host in case.scope_hosts):
            raise ValueError("Offline benchmark host is not synthetic")
        source = self.catalog.visible_root / case.case_id
        started = _now()
        with TemporaryDirectory(prefix="benchmark-", dir=self.work_root) as directory:
            root = Path(directory)
            package_dir = root / "targets" / case.fixture_id
            package_dir.mkdir(parents=True)
            for name in (case.target_package, *case.input_files,
                         *((case.context_file,) if case.context_file else ())):
                if name.startswith("package/"):
                    destination = package_dir / name.removeprefix("package/")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source / name, destination)
            if case.target_package != "package/target.yaml":
                raise ValueError("Benchmark package must use package/target.yaml")
            env = {"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_STATE_HOME": str(root), "HACKBOT_HOME": str(root / "runtime")}
            settings = replace(load_config(environ=env),
                               targets=TargetSettings(root / "targets"), recon=None,
                               notifications=NotificationSettings())
            runtime = BugHunterRuntime(settings, driver=SimpleNamespace(name="BENCHMARK"),
                                       vnc_ready=lambda: False)
            package = runtime.package(case.fixture_id)
            if (package.primary_domain not in case.scope_hosts or
                    not package.primary_domain.endswith(".test")):
                raise ValueError("Synthetic package scope mismatch")
            if (not all(rule.pattern in case.scope_hosts and
                        not rule.pattern.startswith("*.")
                        for rule in package.scope.include_hosts)):
                raise ValueError("Synthetic package has undeclared scope")
            runtime.registry.register_target(package)
            for name in case.input_files:
                if name != "traffic.json" or "NO_TRAFFIC" in config.ablations:
                    continue
                for row in _fixture_traffic(source / name):
                    if not any(row["url"].startswith("http://" + host + "/") or
                               row["url"].startswith("https://" + host + "/")
                               for host in case.scope_hosts):
                        raise ValueError("Out-of-scope benchmark fixture traffic")
                    exchange = runtime.traffic.store_request(
                        package, CapturedRequest(row["method"], row["url"]),
                        source=TrafficSource.FIXTURE, capture_provider="BENCHMARK",
                        anonymous=True)
                    runtime.traffic.store_response(
                        exchange.id, CapturedResponse(
                            row["status"],
                            headers=(("Content-Type", row["content_type"]),)
                            if row.get("content_type") else (),
                            body=row["body"].encode("utf-8") if "body" in row else None))
            profile = AttackSurfaceProfiler(
                runtime.registry, runtime.store, runtime.traffic,
                bootstrap=runtime.bootstrap_store).profile(package)
            runtime.hypotheses.save_profile(profile)
            HypothesisGenerator(runtime.hypotheses).generate(profile)
            campaign = runtime.campaign.start(
                package, mode=PlannerMode.ANALYZE_ONLY,
                limits=CampaignLimits(max_cycles=1, seconds=case.budget.seconds,
                                      requests=0, browser_actions=0,
                                      research_requests=0, tokens=0,
                                      setup_objects=0, cleanup_reserve=0),
                requested_by="benchmark")
            for _ in range(12):
                if campaign.status in TERMINAL_CAMPAIGN_STATUSES:
                    break
                campaign = runtime.campaign.advance(package, campaign.id)
            return collect_case_trace(runtime, case.case_id, campaign, started, _now())
