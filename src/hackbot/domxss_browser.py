"""Typed, policy-gated browser experiments for current DOM XSS candidates."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
import re
from typing import Callable, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import uuid

from .browser import BrowserSessionManager, BrowserStatus, VerificationStatus
from .domxss_static import DOMCandidateStatus
from .domxss_store import DOMXSSStore
from .evidence import EvidenceProvenance, EvidenceType, RedactionStatus, Sensitivity
from .plan_runs import PlanRunStore, RunStatus, RuntimeStepStatus, RuntimeStepType
from .policy import PolicyEngine
from .policy_models import ActionCategory, ActorMode, ProposedAction
from .store import EvidenceFactStore
from .target_loader import TargetPackageRepository
from .target_policy import PolicyDecision
from .target_scope import ScopeResult


class DOMInputKind(StrEnum):
    QUERY = "QUERY"
    FRAGMENT = "FRAGMENT"


class DOMVariant(StrEnum):
    INERT = "INERT"
    BENIGN = "BENIGN"
    DIRECT_DANGEROUS = "DIRECT_DANGEROUS"
    ENCODED_ONCE = "ENCODED_ONCE"
    ENCODED_TWICE = "ENCODED_TWICE"
    FRESH_REPRODUCTION = "FRESH_REPRODUCTION"


@dataclass(frozen=True, slots=True)
class DOMExperimentBinding:
    candidate_id: str
    run_id: str
    browser_session_id: str
    route_url: str
    asset_url: str
    input_kind: DOMInputKind
    input_name: str | None = None


@dataclass(frozen=True, slots=True)
class DOMBrowserObservation:
    context_id: str
    marker_observed: bool
    marker_context: str | None
    document_origin: str | None
    response_status: int | None
    bundle_sha256: str | None
    csp_present: bool
    trusted_types_enforced: bool
    sandbox_flags: tuple[str, ...]
    browser_blocked: bool
    navigation_only: bool
    request_count: int
    denial_count: int
    error_code: str | None = None


class DOMBrowserDriver(Protocol):
    """Implementations must call gate for every request, redirect, and popup request."""

    def execute_dom_variant(self, session_id: str, url: str, marker: str,
                            expected_asset_url: str,
                            gate: Callable[[str, str, bool], bool], *,
                            authenticated: bool, request_cap: int,
                            timeout_ms: int) -> DOMBrowserObservation: ...


@dataclass(frozen=True, slots=True)
class DOMTrial:
    variant: DOMVariant
    evidence_id: str
    observation: DOMBrowserObservation
    policy_decision_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DOMExperimentResult:
    candidate_id: str
    run_id: str
    status: str
    trials: tuple[DOMTrial, ...]
    proof_evidence_ids: tuple[str, ...]


class DOMBrowserExperimentExecutor:
    """The only active DOM proof entrypoint; no arbitrary payload or JS eval API."""

    MAX_REQUESTS_PER_VARIANT = 24
    MAX_VARIANTS = 5
    TIMEOUT_MS = 12_000

    def __init__(self, *, targets: TargetPackageRepository, store: DOMXSSStore,
                 browser: BrowserSessionManager, driver: DOMBrowserDriver,
                 policy: PolicyEngine, runs: PlanRunStore,
                 evidence: EvidenceFactStore) -> None:
        self.targets = targets
        self.store = store
        self.browser = browser
        self.driver = driver
        self.policy = policy
        self.runs = runs
        self.evidence = evidence

    @staticmethod
    def _url(route: str, kind: DOMInputKind, name: str | None, value: str) -> str:
        parts = urlsplit(route)
        if kind is DOMInputKind.QUERY:
            assert name is not None
            query = urlencode((*parse_qsl(parts.query, keep_blank_values=True), (name, value)))
            return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, value))

    @staticmethod
    def _payload(variant: DOMVariant, marker: str, sink_kind: str, route: str) -> str:
        if variant is DOMVariant.INERT:
            return "HACKBOT_DOM_PROBE_" + marker
        if variant is DOMVariant.BENIGN:
            parts = urlsplit(route)
            return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        if sink_kind == "HTML_EXECUTION":
            raw = ("<img src=x onerror=\"document.documentElement.setAttribute("
                   f"'data-hackbot-dom-proof','{marker}')\">")
        else:
            raw = ("javascript:document.documentElement.setAttribute("
                   f"'data-hackbot-dom-proof','{marker}');void(0)")
        if variant is DOMVariant.DIRECT_DANGEROUS:
            return raw
        once = raw.replace(":", "%3A").replace("<", "%3C").replace(">", "%3E")
        if variant in {DOMVariant.ENCODED_ONCE, DOMVariant.FRESH_REPRODUCTION}:
            return once
        if variant is DOMVariant.ENCODED_TWICE:
            return once.replace("%", "%25")
        raise ValueError("Unsupported DOM variant")

    def run(self, package_id: str, binding: DOMExperimentBinding) -> DOMExperimentResult:
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise ValueError("Target Package unavailable")
        target_id = package.target.id
        candidate = self.store.get_candidate(target_id, binding.candidate_id)
        artifact = self.store.candidate_asset(target_id, binding.candidate_id)
        run = self.runs.get(binding.run_id, target_id)
        session = self.browser.get(binding.browser_session_id)
        if (candidate is None or artifact is None or artifact.state != "CURRENT"
                or artifact.recon_sha256 != artifact.artifact_sha256
                or candidate.asset_sha256 != artifact.artifact_sha256
                or candidate.status not in {DOMCandidateStatus.STATICALLY_SUPPORTED,
                                            DOMCandidateStatus.RUNTIME_READY}
                or not candidate.check_before_transform or not candidate.attacker_controlled
                or candidate.post_checks or candidate.sanitizers or candidate.unresolved_helper
                or candidate.route is None or candidate.route != binding.route_url
                or hashlib.sha256(binding.asset_url.encode()).hexdigest() != artifact.asset_url_sha256
                or run is None or run.package_id != package_id
                or run.status is not RunStatus.RUNNING
                or session is None or session.target_id != target_id
                or not self.driver or not self.browser.driver.is_running(session.id)):
            raise ValueError("DOM runtime prerequisites are not current")
        step = self.runs.current_step(run)
        if (step is None or step.type != RuntimeStepType.VERIFY_BROWSER.value
                or step.status is not RuntimeStepStatus.EXECUTING
                or not self.runs.should_dispatch(run.id)):
            raise ValueError("DOM browser proof requires a claimed Phase 16 step")
        with self.evidence._connection() as connection:
            row = connection.execute("""
                SELECT plan_id,hypothesis_id FROM dom_flow_candidates
                WHERE target_id=? AND candidate_id=? LIMIT 1
            """, (target_id, binding.candidate_id)).fetchone()
        if row is None or row["plan_id"] != run.plan_id or row["hypothesis_id"] != run.hypothesis_id:
            raise ValueError("DOM run is not bound to candidate and plan")
        context = self.browser.session_context(session.id)
        if session.identity_id is not None and (
                context.authentication_status != "VALID" or
                context.browser_status is not BrowserStatus.VALID or
                context.verification_status is not VerificationStatus.MATCH):
            raise ValueError("Verified owned browser session required")
        if (session.identity_id is None and
                context.browser_status not in {BrowserStatus.RUNNING, BrowserStatus.CREATED}):
            raise ValueError("Running anonymous browser session required")
        if (binding.input_kind is DOMInputKind.QUERY and
                (candidate.source != "location.search" or not binding.input_name or
                 not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,39}", binding.input_name))):
            raise ValueError("Candidate query input is not bound")
        if binding.input_kind is DOMInputKind.FRAGMENT and (
                candidate.source != "location.hash" or binding.input_name is not None):
            raise ValueError("Candidate fragment input is not bound")
        parts = urlsplit(binding.route_url)
        if (parts.scheme not in {"http", "https"} or not parts.hostname or
                parts.username or parts.password or parts.query or parts.fragment or
                package.scope.evaluate_url(binding.route_url).result is not ScopeResult.IN_SCOPE):
            raise ValueError("Route is not a clean in-scope browser fixture")
        asset_parts = urlsplit(binding.asset_url)
        if (asset_parts.query or asset_parts.fragment or asset_parts.username
                or asset_parts.password or
                package.scope.evaluate_url(binding.asset_url).result is not ScopeResult.IN_SCOPE):
            raise ValueError("Analyzed bundle is not currently in scope")
        transform_names = tuple(step.operation for step in candidate.transforms)
        decodes = sum(name in {"decodeURIComponent", "decodeURI", "unescape"}
                      for name in transform_names)
        if decodes < 1:
            raise ValueError("No supported decode semantics for bounded proof")
        self.store.bind_run(target_id, binding.candidate_id, run.id)
        variants = [DOMVariant.INERT, DOMVariant.BENIGN, DOMVariant.DIRECT_DANGEROUS,
                    DOMVariant.ENCODED_ONCE]
        if decodes >= 2:
            variants.append(DOMVariant.ENCODED_TWICE)
        marker = uuid.uuid4().hex
        trials: list[DOMTrial] = []
        proof_variant: DOMVariant | None = None
        for variant in variants[:self.MAX_VARIANTS]:
            trial = self._trial(package, session.id, session.identity_id, binding,
                                candidate.sink_kind, variant, marker)
            trials.append(trial)
            if trial.observation.bundle_sha256 != candidate.asset_sha256:
                status = (DOMCandidateStatus.STALE if trial.observation.bundle_sha256
                          else DOMCandidateStatus.NEEDS_MANUAL_REVIEW)
                self.store.set_candidate_status(target_id, binding.candidate_id,
                                                status, "BUNDLE_NOT_CURRENT_ON_ROUTE")
                return DOMExperimentResult(binding.candidate_id, binding.run_id,
                                           "BUNDLE_NOT_CURRENT_ON_ROUTE", tuple(trials), ())
            if trial.observation.marker_observed:
                if variant in {DOMVariant.INERT, DOMVariant.BENIGN,
                               DOMVariant.DIRECT_DANGEROUS}:
                    self.store.set_candidate_status(target_id, binding.candidate_id,
                                                    DOMCandidateStatus.NEEDS_MANUAL_REVIEW,
                                                    "DOM_CONTROL_INVALID")
                    return DOMExperimentResult(binding.candidate_id, binding.run_id,
                                               "CONTROL_INVALID", tuple(trials), ())
                proof_variant = variant
                break
            if trial.observation.error_code:
                self.store.set_candidate_status(target_id, binding.candidate_id,
                                                DOMCandidateStatus.NEEDS_MANUAL_REVIEW,
                                                "DOM_BROWSER_BLOCKED")
                return DOMExperimentResult(binding.candidate_id, binding.run_id,
                                           "BLOCKED", tuple(trials), ())
        if proof_variant is None:
            uncertain = any(item.observation.denial_count or
                            item.observation.browser_blocked for item in trials)
            status = (DOMCandidateStatus.NEEDS_MANUAL_REVIEW if uncertain
                      else DOMCandidateStatus.RUNTIME_TESTED)
            self.store.set_candidate_status(target_id, binding.candidate_id, status,
                                            "BROWSER_BLOCKED_OR_INCOMPLETE" if uncertain
                                            else "NO_BROWSER_EXECUTION")
            return DOMExperimentResult(binding.candidate_id, binding.run_id,
                                       "NEEDS_MANUAL_REVIEW" if uncertain else "NO_EXECUTION",
                                       tuple(trials), ())
        repro = self._trial(package, session.id, session.identity_id, binding,
                            candidate.sink_kind, DOMVariant.FRESH_REPRODUCTION,
                            uuid.uuid4().hex, double=proof_variant is DOMVariant.ENCODED_TWICE)
        trials.append(repro)
        if repro.observation.bundle_sha256 != candidate.asset_sha256:
            self.store.set_candidate_status(target_id, binding.candidate_id,
                                            DOMCandidateStatus.STALE,
                                            "BUNDLE_CHANGED_ON_REPRODUCTION")
            return DOMExperimentResult(binding.candidate_id, binding.run_id,
                                       "BUNDLE_CHANGED_ON_REPRODUCTION", tuple(trials), ())
        unique_contexts = len({item.observation.context_id for item in trials}) == len(trials)
        if not repro.observation.marker_observed or not unique_contexts:
            self.store.set_candidate_status(target_id, binding.candidate_id,
                                            DOMCandidateStatus.NEEDS_MANUAL_REVIEW,
                                            "FRESH_REPRODUCTION_FAILED")
            return DOMExperimentResult(binding.candidate_id, binding.run_id,
                                       "REPRODUCTION_FAILED", tuple(trials), ())
        self.store.set_candidate_status(target_id, binding.candidate_id,
                                        DOMCandidateStatus.VALIDATION_READY,
                                        "BROWSER_PROOF_OBSERVED")
        return DOMExperimentResult(binding.candidate_id, binding.run_id,
                                   "VALIDATION_READY", tuple(trials),
                                   (trials[-2].evidence_id, repro.evidence_id))

    def _trial(self, package, session_id: str, identity_id: str | None,
               binding: DOMExperimentBinding, sink_kind: str, variant: DOMVariant,
               marker: str, *, double: bool = False) -> DOMTrial:
        payload_variant = (DOMVariant.ENCODED_TWICE if double else DOMVariant.ENCODED_ONCE)
        if variant is not DOMVariant.FRESH_REPRODUCTION:
            payload_variant = variant
        value = self._payload(payload_variant, marker, sink_kind, binding.route_url)
        probe_url = self._url(binding.route_url, binding.input_kind, binding.input_name, value)
        decisions: list[str] = []
        count = 0
        denied = 0

        def gate(url: str, method: str, navigation: bool) -> bool:
            nonlocal count, denied
            count += 1
            if (not self.runs.should_dispatch(binding.run_id)
                    or count > self.MAX_REQUESTS_PER_VARIANT or method not in {"GET", "HEAD"}):
                denied += 1
                return False
            parts = urlsplit(url)
            cleaned = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
            if package.scope.evaluate_url(cleaned).result is not ScopeResult.IN_SCOPE:
                denied += 1
                return False
            action = ProposedAction(
                target_id=package.target.id, package_id=package.id,
                category=(ActionCategory.BROWSER_NAVIGATION if navigation
                          else ActionCategory.SAFE_READ),
                actor=(ActorMode.AUTHENTICATED if identity_id else ActorMode.ANONYMOUS),
                source="domxss_browser", purpose="Bounded DOM XSS browser proof",
                url=cleaned, method=method, identity_id=identity_id,
                session_id=session_id if identity_id else None,
                vulnerability_class="dom_xss",
            )
            decision = self.policy.evaluate(package, action, record=True)
            decisions.append(decision.id)
            if decision.result is not PolicyDecision.ALLOW:
                denied += 1
                return False
            return True

        if not gate(probe_url, "GET", True):
            raise ValueError("DOM proof navigation denied by policy")
        current_run = self.runs.get(binding.run_id, package.target.id)
        current_step = self.runs.current_step(current_run) if current_run else None
        if (current_step is None or not self.runs.account_dom_dispatch(
                binding.run_id, current_step.id, variant.value)):
            raise ValueError("DOM browser navigation budget exhausted or step not claimed")
        observation = self.driver.execute_dom_variant(
            session_id, probe_url, marker, binding.asset_url, gate,
            authenticated=identity_id is not None,
            request_cap=self.MAX_REQUESTS_PER_VARIANT,
            timeout_ms=self.TIMEOUT_MS,
        )
        if (observation.request_count > self.MAX_REQUESTS_PER_VARIANT or
                observation.denial_count < denied):
            raise ValueError("Browser driver did not enforce request budget")
        metadata = {
            "candidate_id": binding.candidate_id, "run_id": binding.run_id,
            "browser_session_id": session_id,
            "route_url_sha256": hashlib.sha256(binding.route_url.encode()).hexdigest(),
            "asset_url_sha256": hashlib.sha256(binding.asset_url.encode()).hexdigest(),
            "input_kind": binding.input_kind.value,
            "input_name": binding.input_name,
            "variant": variant.value,
            "payload_variant": payload_variant.value,
            "probe_url_sha256": hashlib.sha256(probe_url.encode()).hexdigest(),
            "marker_sha256": hashlib.sha256(marker.encode()).hexdigest(),
            "context_id": observation.context_id,
            "marker_observed": observation.marker_observed,
            "marker_context": observation.marker_context,
            "document_origin": observation.document_origin,
            "response_status": observation.response_status,
            "bundle_sha256": observation.bundle_sha256,
            "csp_present": observation.csp_present,
            "trusted_types_enforced": observation.trusted_types_enforced,
            "sandbox_flags": list(observation.sandbox_flags[:8]),
            "browser_blocked": observation.browser_blocked,
            "navigation_only": observation.navigation_only,
            "request_count": observation.request_count,
            "denial_count": observation.denial_count,
            "error_code": observation.error_code,
            "policy_decision_ids": decisions[:self.MAX_REQUESTS_PER_VARIANT + 1],
        }
        evidence = self.evidence.create_evidence(
            EvidenceType.DOM_PROOF, json.dumps(metadata, sort_keys=True).encode(),
            source="domxss_browser", target_ref=package.target.id,
            provenance=EvidenceProvenance(system="HACKBOT", entity="DOM_BROWSER_EXPERIMENT",
                                          record_id=binding.candidate_id),
            sensitivity=Sensitivity.INTERNAL,
            redaction_status=RedactionStatus.REDACTED,
        )
        return DOMTrial(variant, evidence.evidence_id, observation, tuple(decisions))
