"""Scored browser-specialist campaigns against disposable loopback pages."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
from tempfile import TemporaryDirectory

from .benchmark_browser_fixture import BenchmarkBrowserFixture
from .benchmark_eval import CaseTrace
from .benchmark_local import _read, _stage_package
from .benchmark_trace import collect_case_trace
from .campaign_models import CampaignLimits, TERMINAL_CAMPAIGN_STATUSES
from .config import (ExecutorSettings, NotificationSettings, TargetSettings,
                     load_config)
from .domxss import DOMXSSSpecialist
from .domxss_static import DOMCandidateStatus
from .hypotheses import HypothesisGenerator
from .planner_models import PlannerMode
from .postmessage import PostMessageSpecialist
from .postmessage_static import MessageCandidateStatus, PostMessageStaticAnalyzer
from .profile import AttackSurfaceProfiler
from .service import BugHunterRuntime
from .skill_plans import DOMPlanBinding, MessagePlanBinding
from .target_scope import ScopeResult


_CHROMIUM = Path("/root/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome")
_QUERY_GET = re.compile(
    rb"URLSearchParams\s*\(\s*(?:window\.)?location\.search\s*\)\s*"
    rb"\.get\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_-]{0,39})['\"]\s*\)")


class _NoRecon:
    def __getattr__(self, name: str):
        raise AssertionError("Browser benchmark must not access production recon: " + name)


def _response_body(runtime: BugHunterRuntime, exchange_id: str) -> bytes:
    exchange = runtime.traffic.get_exchange(exchange_id)
    if (exchange is None or exchange.response is None or
            exchange.response.record.status_code != 200 or
            exchange.response.body_evidence_id is None):
        raise ValueError("Synthetic browser asset was not retrieved")
    return runtime.store.read_content(exchange.response.body_evidence_id,
                                      allow_sensitive=True, max_bytes=1_048_576)


def run_browser_campaign(package_template: Path, work_root: Path, *,
                         family: str, secure: bool, case_id: str,
                         max_requests: int) -> CaseTrace:
    """Run one current JS analysis and one bounded browser-capable campaign."""
    if family not in {"DOM", "MESSAGE"} or not _CHROMIUM.is_file():
        raise ValueError("Synthetic browser family or Chromium unavailable")
    work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with BenchmarkBrowserFixture(family=family, secure=secure,
                                 max_requests=max_requests) as fixture:
        with TemporaryDirectory(prefix="local-browser-", dir=work_root) as directory:
            root = Path(directory)
            _stage_package(package_template, root / "targets/benchmark/target.yaml",
                           fixture._server.server_port, read_only=True)
            env = {"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_STATE_HOME": str(root),
                   "HACKBOT_HOME": str(root / "runtime")}
            default = load_config(environ=env)
            settings = replace(
                default, targets=TargetSettings(root / "targets"), recon=None,
                notifications=NotificationSettings(),
                browser=replace(default.browser, chromium_executable=_CHROMIUM),
                executor=ExecutorSettings(allow_direct=True, max_redirects=0,
                                          max_response_bytes=8192))
            runtime = BugHunterRuntime(settings, vnc_ready=lambda: False)
            package = runtime.package("benchmark")
            if (package.scope.evaluate_url(fixture.base_url + "/").result is not
                    ScopeResult.IN_SCOPE or
                    package.scope.include_hosts[0].pattern != "127.0.0.1"):
                raise ValueError("Browser fixture scope is not loopback-only")
            runtime.registry.register_target(package)
            session = runtime.browser.create(package.target.id)
            runtime.browser.start(session.id)
            try:
                route = fixture.base_url + ("/preview" if family == "DOM" else "/victim")
                asset_url = fixture.base_url + "/bundle.js"
                page = _read(runtime, package, route)
                asset_response = _read(runtime, package, asset_url)
                if (page.error is not None or asset_response.error is not None or
                        not page.exchange_ids or not asset_response.exchange_ids):
                    raise ValueError("Synthetic browser setup request failed")
                body = _response_body(runtime, asset_response.exchange_ids[0])
                digest = hashlib.sha256(body).hexdigest()
                artifact = runtime.domxss_store.record_artifact(
                    target_id=package.target.id, asset_url=asset_url, body=body,
                    recon_asset_id=None, recon_sha256=digest, source="FIXTURE")
                dom = DOMXSSSpecialist(recon=_NoRecon(), targets=runtime.targets,
                                       executor=runtime.executor,
                                       store=runtime.domxss_store)
                runtime.domxss = dom
                runtime.planner_runner.dom = dom
                if family == "DOM":
                    _, analysis = dom.analyze(package.target.id, artifact.artifact_id)
                    names = set(_QUERY_GET.findall(body))
                    if len(names) != 1:
                        raise ValueError("Observed JavaScript has no unique query input")
                    input_name = next(iter(names)).decode("ascii")
                    for candidate in analysis.candidates:
                        if (candidate.status is not DOMCandidateStatus.STATICALLY_SUPPORTED
                                or candidate.source != "location.search"):
                            continue
                        dom.bind_observed_route(package.id, candidate.candidate_id,
                                                page.exchange_ids[0], runtime.traffic)
                        prepared = dom.prepare_candidate(
                            package.id, candidate.candidate_id,
                            hypotheses=runtime.hypotheses, contexts=runtime.skill_context,
                            router=runtime.skill_router, planner=runtime.skill_planner)
                        context = runtime.skill_context.build(
                            prepared.hypothesis, None, package=package)
                        runtime.skill_planner.bind_dom(
                            package, prepared.hypothesis, context,
                            DOMPlanBinding(candidate.candidate_id, route, asset_url,
                                           session.id, None, "QUERY", input_name))
                else:
                    messages = PostMessageSpecialist(dom=dom, targets=runtime.targets,
                                                     store=runtime.postmessage_store)
                    runtime.postmessage = messages
                    runtime.planner_runner.messages = messages
                    _, analysis = runtime.postmessage_store.analyze_asset(
                        package.target.id, artifact.artifact_id,
                        PostMessageStaticAnalyzer())
                    for candidate in analysis.candidates:
                        read_methods = [item.name for item in candidate.rpc_details
                                        if item.capability == "READ"]
                        if (candidate.status is not MessageCandidateStatus.STATIC_CANDIDATE or
                                candidate.priority < 60 or
                                len(candidate.message_types) != 1 or
                                len(read_methods) != 1):
                            continue
                        activation_type = candidate.message_types[0]
                        read_method = read_methods[0]
                        messages.bind_observed_route(
                            package.id, candidate.candidate_id,
                            page.exchange_ids[0], runtime.traffic)
                        prepared = messages.prepare_candidate(
                            package.id, candidate.candidate_id,
                            hypotheses=runtime.hypotheses, contexts=runtime.skill_context,
                            router=runtime.skill_router, planner=runtime.skill_planner)
                        context = runtime.skill_context.build(
                            prepared.hypothesis, None, package=package)
                        runtime.skill_planner.bind_message(
                            package, prepared.hypothesis, context,
                            MessagePlanBinding(candidate.candidate_id, route, asset_url,
                                               session.id, None, activation_type, None,
                                               read_method))
                started = datetime.now(timezone.utc).isoformat()
                profile = AttackSurfaceProfiler(
                    runtime.registry, runtime.store, runtime.traffic,
                    bootstrap=runtime.bootstrap_store).profile(package)
                runtime.hypotheses.save_profile(profile)
                HypothesisGenerator(runtime.hypotheses).generate(profile)
                campaign = runtime.campaign.start(
                    package, mode=PlannerMode.BOUNDED_AUTONOMOUS,
                    limits=CampaignLimits(max_cycles=1, seconds=240,
                                          requests=20, browser_actions=12,
                                          research_requests=0, tokens=0,
                                          setup_objects=0, cleanup_reserve=0),
                    requested_by="benchmark")
                for _ in range(100):
                    campaign = runtime.campaign.advance(package, campaign.id)
                    if (campaign.status in TERMINAL_CAMPAIGN_STATUSES or
                            campaign.status.value.startswith("WAITING_") or
                            campaign.status.value == "PAUSED"):
                        break
                trace = collect_case_trace(
                    runtime, case_id, campaign, started,
                    datetime.now(timezone.utc).isoformat())
                count = len(fixture.requests)
                return replace(trace, usage=replace(
                    trace.usage, requests=count, setup_requests=2,
                    verification_requests=max(0, count - 2),
                    cleanup_requests=0))
            finally:
                runtime.browser.stop(session.id)
