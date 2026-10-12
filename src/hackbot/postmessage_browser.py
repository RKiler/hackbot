"""Bounded, policy-gated browser trials for a frozen messaging protocol."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import ipaddress
import json
import re
import time
from typing import Callable, Protocol
from urllib.parse import urlsplit, urlunsplit

from .browser import BrowserSessionManager, BrowserStatus, VerificationStatus
from .evidence import (EvidenceProvenance, EvidenceType, FactStatus,
                       RedactionStatus, Sensitivity)
from .plan_runs import PlanRunStore, RunStatus, RuntimeStepStatus, RuntimeStepType
from .policy import PolicyEngine
from .policy_models import ActionCategory, ActorMode, ProposedAction
from .postmessage_static import MessageCandidateStatus
from .postmessage_store import PostMessageStore
from .rate_limit import ExperimentBudget
from .store import EvidenceFactStore
from .target_loader import TargetPackageRepository
from .target_package import TargetPackage
from .target_policy import PolicyDecision
from .target_scope import ScopeResult
from .test_objects import ObjectRegistry, ObjectState, TestObject


class MessageVariant(StrEnum):
    NO_MESSAGE = "NO_MESSAGE"
    WRONG_TYPE = "WRONG_TYPE"
    TRUSTED = "TRUSTED"
    WRONG_SOURCE = "WRONG_SOURCE"
    NO_PORT = "NO_PORT"
    UNRELATED = "UNRELATED"
    ATTACKER_PORT = "ATTACKER_PORT"
    LOOKALIKE_ORIGIN = "LOOKALIKE_ORIGIN"
    FRESH_REPRODUCTION = "FRESH_REPRODUCTION"
    FRESH_WRONG_SOURCE = "FRESH_WRONG_SOURCE"
    FRESH_LOOKALIKE_ORIGIN = "FRESH_LOOKALIKE_ORIGIN"


def lookalike_origin(route_url: str, check_kind: str) -> str:
    """Build a local-only browser origin matching one observed weak check shape."""
    parsed = urlsplit(route_url)
    host = parsed.hostname
    if (parsed.scheme not in {"http", "https"} or not host
            or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host)
            or parsed.username or parsed.password
            or check_kind not in {"SUBSTRING", "STARTSWITH", "ENDSWITH",
                                  "REGEX_REVIEW", "WEAK_COMPARISON"}):
        raise ValueError("Unsupported messaging origin probe")
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError as exc:
        raise ValueError("Unsupported messaging origin probe") from exc
    if check_kind == "ENDSWITH":
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("Suffix probe is unsupported for IP-literal hosts")
        return f"{parsed.scheme}://evil-{host}{port}"
    return f"{parsed.scheme}://{host}.attacker.fixture.invalid{port}"


def verified_owned_canary(objects: ObjectRegistry, evidence: EvidenceFactStore, *,
                          target_id: str, package_id: str, plan_id: str, run_id: str,
                          identity_id: str, object_id: str, canary_sha256: str,
                          verified_at: str, active: bool) -> TestObject | None:
    """Resolve one Phase 18 owner-verified object without exposing its name to a plan."""
    try:
        item = objects.get(object_id, target_id)
    except ValueError:
        return None
    if (item is None or item.package_id != package_id
            or item.creator_identity_id != identity_id or not item.disposable
            or item.verified_at != verified_at or not item.verification_evidence_ids
            or not item.external_id_hash or not item.external_id_evidence_id
            or hashlib.sha256(item.test_name.encode()).hexdigest() != canary_sha256
            or item.state not in ({ObjectState.IN_USE} if active else {
                ObjectState.IN_USE, ObjectState.CLEANUP_PENDING, ObjectState.CLEANED})):
        return None
    linked_ids = (*item.verification_evidence_ids, item.external_id_evidence_id)
    linked = [evidence.get_evidence(ref) for ref in linked_ids]
    if (any(record is None or record.target_ref != target_id for record in linked)
            or linked[-1].evidence_type != "TEST_OBJECT_EXTERNAL_ID"):
        return None
    try:
        external = evidence.read_content(item.external_id_evidence_id,
                                         allow_sensitive=True, max_bytes=256).decode("ascii")
    except (KeyError, ValueError, UnicodeDecodeError, PermissionError):
        return None
    if hashlib.sha256((item.id + ":" + external).encode()).hexdigest() != item.external_id_hash:
        return None
    if not any(requirement["test_object_id"] == item.id
               for requirement in objects.requirements(plan_id, target_id)):
        return None
    with evidence._connection() as db:
        reservation = db.execute("SELECT status,created_at,expires_at,released_at "
                                 "FROM test_object_reservations WHERE test_object_id=? "
                                 "AND holder_run_id=? ORDER BY created_at DESC LIMIT 1",
                                 (item.id, run_id)).fetchone()
    if reservation is None or reservation["status"] not in {"ACTIVE", "RELEASED"} or active and (
            reservation["status"] != "ACTIVE"
            or reservation["expires_at"] <= datetime.now(timezone.utc).isoformat()):
        return None
    if active:
        try:
            checked = datetime.fromisoformat(verified_at)
        except ValueError:
            return None
        if (checked.tzinfo is None or checked > datetime.now(timezone.utc)
                or datetime.now(timezone.utc) - checked > timedelta(minutes=15)):
            return None
    for predicate, value in (("created_by", identity_id),
                             ("resource_tenant", item.tenant_id),
                             ("disposable", "true")):
        facts = evidence.find_facts(item.id, predicate, limit=8).items
        if not any(fact.target_ref == target_id and fact.status is FactStatus.ACTIVE
                   and fact.source == "OBJECT_FACTORY" and fact.confidence >= 0.9
                   and fact.evidence_ids and fact.object == value
                   and all((record := evidence.get_evidence(ref)) is not None
                           and record.target_ref == target_id
                           for ref in fact.evidence_ids) for fact in facts):
            return None
    return item


@dataclass(frozen=True, slots=True)
class MessageExperimentBinding:
    candidate_id: str
    run_id: str
    browser_session_id: str
    route_url: str
    asset_url: str
    activation_type: str
    port_type: str | None
    allowed_method: str | None
    identity_id: str | None
    window_mode: str = "IFRAME"
    dom_field: str | None = None
    origin_probe_kind: str = "SUBSTRING"
    owned_object_id: str | None = None
    owned_canary_sha256: str | None = None
    owned_verified_at: str | None = None
    owned_canary_value: str | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class MessageBrowserObservation:
    context_id: str
    attacker_origin: str
    source_relationship: str
    message_type: str | None
    message_count: int
    port_count: int
    rpc_calls: int
    capability_observed: bool
    effect_kind: str | None
    effect_fingerprint: str | None
    victim_bundle_sha256: str | None
    response_status: int | None
    frame_ancestors: str | None
    x_frame_options: str | None
    sandbox_flags: tuple[str, ...]
    request_count: int
    denial_count: int
    error_code: str | None = None
    marker_context: str | None = None
    document_origin: str | None = None
    source_attested: bool = False
    event_trace: tuple[tuple[str, int], ...] = ()


class MessageBrowserDriver(Protocol):
    """A driver may send only fixed, typed fixture variants, never arbitrary JS."""

    def execute_message_trial(self, session_id: str, binding: MessageExperimentBinding,
                              variant: MessageVariant,
                              gate: Callable[[str, str, bool], str | None], *,
                              authenticated: bool, request_cap: int,
                              timeout_ms: int) -> MessageBrowserObservation: ...


@dataclass(frozen=True, slots=True)
class MessageTrial:
    variant: MessageVariant
    evidence_id: str
    observation: MessageBrowserObservation
    policy_decision_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MessageExperimentResult:
    candidate_id: str
    run_id: str
    status: str
    trials: tuple[MessageTrial, ...]
    proof_evidence_ids: tuple[str, ...]


class _TrialRequestGate:
    """One policy decision and one shared rate reservation per browser request."""

    def __init__(self, *, package: TargetPackage, binding: MessageExperimentBinding,
                 session_id: str, policy: PolicyEngine, runs: PlanRunStore,
                 request_cap: int, timeout_ms: int, run_request_cap: int) -> None:
        if policy.rate is None:
            raise ValueError("Messaging browser requires the shared Phase 14 rate limiter")
        self.package, self.binding, self.session_id = package, binding, session_id
        self.policy, self.runs = policy, runs
        self.request_cap = request_cap
        self.deadline = time.monotonic() + timeout_ms / 1000
        self.budget = ExperimentBudget(max_requests=run_request_cap)
        self.decisions: list[str] = []
        self.attempts = 0
        self.denied = 0
        self.reserved = 0
        self.released = 0
        self._active: set[str] = set()

    def __call__(self, url: str, method: str, navigation: bool) -> str | None:
        self.attempts += 1
        if (not self.runs.should_dispatch(self.binding.run_id)
                or self.attempts > self.request_cap or method not in {"GET", "HEAD"}
                or time.monotonic() >= self.deadline):
            self.denied += 1
            return None
        parsed = urlsplit(url)
        clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        if self.package.scope.evaluate_url(clean).result is not ScopeResult.IN_SCOPE:
            self.denied += 1
            return None
        assert self.policy.rate is not None
        rate = self.policy.rate
        while True:
            available = rate.check(self.package.target.id, self.package.rate,
                                   experiment_id=self.binding.run_id, budget=self.budget)
            if available.allowed:
                break
            remaining = self.deadline - time.monotonic()
            if available.reason_code != "RATE_PER_SECOND" or remaining <= 0.05:
                self.denied += 1
                return None
            time.sleep(min(0.25, remaining))
        action = ProposedAction(
            target_id=self.package.target.id, package_id=self.package.id,
            category=(ActionCategory.BROWSER_NAVIGATION if navigation
                      else ActionCategory.SAFE_READ),
            actor=(ActorMode.AUTHENTICATED if self.binding.identity_id else ActorMode.ANONYMOUS),
            source="postmessage_browser", purpose="Bounded messaging browser proof",
            url=clean, method=method, identity_id=self.binding.identity_id,
            session_id=self.session_id if self.binding.identity_id else None,
            vulnerability_class="postmessage",
        )
        decision = self.policy.evaluate(self.package, action, record=True)
        self.decisions.append(decision.id)
        if decision.result is not PolicyDecision.ALLOW:
            self.denied += 1
            return None
        reservation = rate.reserve(self.package.target.id, self.package.rate,
                                   experiment_id=self.binding.run_id, budget=self.budget)
        if not reservation.allowed or reservation.reservation_id is None:
            self.denied += 1
            return None
        self.reserved += 1
        self._active.add(reservation.reservation_id)
        return reservation.reservation_id

    def release(self, ticket: str) -> None:
        if ticket in self._active:
            self._active.remove(ticket)
            assert self.policy.rate is not None
            self.policy.rate.release(ticket)
            self.released += 1

    def close(self) -> None:
        for ticket in tuple(self._active):
            self.release(ticket)


class PostMessageBrowserExperimentExecutor:
    MAX_REQUESTS_PER_TRIAL = 24
    MAX_TRIALS = 8
    TIMEOUT_MS = 12_000
    SAFE_METHODS = frozenset({"ping", "getVersion", "getStatus", "readSynthetic", "readCanary"})
    PROOF_EFFECTS = frozenset({"SYNTHETIC_DATA", "OWNED_DATA", "PROTECTED_READ_ONLY_RPC",
                               "PRIVILEGED_UI", "OWNED_DISPOSABLE_STATE", "DOM_EXECUTION"})
    TRACE_EVENTS = frozenset({"SOURCE_ATTESTED", "PORT_CREATED", "MESSAGE_SENT",
                              "PORT_TRANSFERRED", "READY_RECEIVED", "RPC_SENT",
                              "RPC_RESPONSE", "SYNTHETIC_MATCH", "OWNED_MATCH",
                              "DOM_EXECUTION"})

    @classmethod
    def trace_is_valid(cls, trace: object, *, source_attested: object,
                       message_count: object, port_count: object, rpc_calls: object,
                       effect_kind: object) -> bool:
        if (type(source_attested) is not bool
                or any(type(value) is not int or value < 0 for value in
                       (message_count, port_count, rpc_calls))
                or not isinstance(trace, (list, tuple)) or not 1 <= len(trace) <= 16
                or any(not isinstance(entry, (list, tuple)) or len(entry) != 2
                       or not isinstance(entry[0], str)
                       or entry[0] not in cls.TRACE_EVENTS or type(entry[1]) is not int
                       or not 0 <= entry[1] <= cls.TIMEOUT_MS for entry in trace)):
            return False
        names = [entry[0] for entry in trace]
        if (any(trace[index][1] > trace[index + 1][1]
                for index in range(len(trace) - 1))
                or names.count("SOURCE_ATTESTED") != int(source_attested)
                or source_attested and names[0] != "SOURCE_ATTESTED"
                or names.count("MESSAGE_SENT") != message_count
                or names.count("PORT_CREATED") != port_count
                or names.count("PORT_TRANSFERRED") > port_count
                or names.count("RPC_SENT") != rpc_calls):
            return False
        for index, name in enumerate(names):
            prior = names[:index]
            if name == "PORT_TRANSFERRED" and (
                    "PORT_CREATED" not in prior or "MESSAGE_SENT" not in prior):
                return False
            if name == "RPC_SENT" and (
                    "PORT_CREATED" not in prior or "MESSAGE_SENT" not in prior):
                return False
            if name == "RPC_RESPONSE" and rpc_calls and "RPC_SENT" not in prior:
                return False
            if name == "SYNTHETIC_MATCH" and "RPC_RESPONSE" not in prior:
                return False
            if name == "OWNED_MATCH" and "RPC_RESPONSE" not in prior:
                return False
            if name == "DOM_EXECUTION" and "MESSAGE_SENT" not in prior:
                return False
        return ((effect_kind != "SYNTHETIC_DATA" or "SYNTHETIC_MATCH" in names)
                and (effect_kind != "OWNED_DATA" or "OWNED_MATCH" in names)
                and (effect_kind != "DOM_EXECUTION" or "DOM_EXECUTION" in names))

    def __init__(self, *, targets: TargetPackageRepository, store: PostMessageStore,
                 browser: BrowserSessionManager, driver: MessageBrowserDriver,
                 policy: PolicyEngine, runs: PlanRunStore,
                 evidence: EvidenceFactStore,
                 objects: ObjectRegistry | None = None) -> None:
        if policy.rate is None:
            raise ValueError("Messaging browser requires the shared Phase 14 rate limiter")
        self.targets, self.store, self.browser = targets, store, browser
        self.driver, self.policy, self.runs, self.evidence = driver, policy, runs, evidence
        self.objects = objects

    def run(self, package_id: str, binding: MessageExperimentBinding) -> MessageExperimentResult:
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise ValueError("Authoritative Target Package unavailable")
        target_id = package.target.id
        candidate = self.store.get_candidate(target_id, binding.candidate_id)
        asset = self.store.current_asset(target_id, binding.candidate_id)
        run = self.runs.get(binding.run_id, target_id)
        session = self.browser.get(binding.browser_session_id)
        if (candidate is None or asset is None or run is None or session is None
                or candidate.transport_kind != "WINDOW"
                or candidate.status not in {MessageCandidateStatus.STATIC_CANDIDATE,
                                            MessageCandidateStatus.RUNTIME_READY}
                or candidate.route != binding.route_url
                or binding.activation_type not in candidate.message_types
                or binding.port_type not in (None, *candidate.message_types)
                or binding.allowed_method not in (None, *candidate.rpc_methods)
                or binding.allowed_method not in (None, *self.SAFE_METHODS)
                or binding.allowed_method is not None and not any(
                    method.name == binding.allowed_method and method.capability == "READ"
                    for method in candidate.rpc_details)
                or binding.owned_canary_value is not None
                or binding.window_mode not in {"IFRAME", "POPUP"}
                or binding.window_mode == "POPUP" and "OPENER" not in candidate.sender_contexts
                or binding.dom_field is not None and (
                    binding.dom_field != self.store.dom_xss_field(target_id,
                                                                   binding.candidate_id) or
                    binding.allowed_method is not None or binding.port_type is not None)
                or binding.owned_object_id is not None and (
                    binding.identity_id is None or binding.allowed_method != "readCanary"
                    or binding.dom_field is not None)
                or hashlib.sha256(binding.asset_url.encode()).hexdigest() != asset.asset_url_sha256
                or asset.recon_sha256 != asset.artifact_sha256
                or run.package_id != package_id or run.status is not RunStatus.RUNNING
                or run.skill_id != "postmessage-trust-analysis"
                or session.target_id != target_id or session.identity_id != binding.identity_id
                or not self.browser.driver.is_running(session.id)):
            raise ValueError("Messaging runtime prerequisites are not current")
        step = self.runs.current_step(run)
        if (step is None or step.type != RuntimeStepType.VERIFY_BROWSER.value
                or step.status is not RuntimeStepStatus.EXECUTING
                or not self.runs.should_dispatch(run.id)):
            raise ValueError("Messaging proof requires a claimed Phase 16 browser step")
        snapshot = self.runs.snapshot(run.plan_id, target_id).data
        frozen = snapshot.get("message_binding")
        if (not isinstance(frozen, dict) or frozen.get("candidate_id") != binding.candidate_id
                or frozen.get("route_url") != binding.route_url
                or frozen.get("asset_url") != binding.asset_url
                or frozen.get("browser_session_id") != binding.browser_session_id
                or frozen.get("identity_id") != (binding.identity_id or "")
                or frozen.get("activation_type") != binding.activation_type
                or frozen.get("port_type") != (binding.port_type or "")
                or frozen.get("allowed_method") != (binding.allowed_method or "")
                or frozen.get("window_mode") != binding.window_mode
                or frozen.get("dom_field") != (binding.dom_field or "")
                or frozen.get("owned_object_id", "") != (binding.owned_object_id or "")
                or frozen.get("owned_canary_sha256", "") !=
                (binding.owned_canary_sha256 or "")
                or frozen.get("owned_verified_at", "") !=
                (binding.owned_verified_at or "")):
            raise ValueError("Messaging trial does not match frozen plan")
        links = self.store.links(target_id, binding.candidate_id)
        if not links or links["plan_id"] != run.plan_id or links["hypothesis_id"] != run.hypothesis_id:
            raise ValueError("Messaging candidate and run are not linked")
        context = self.browser.session_context(session.id)
        if binding.identity_id and (context.authentication_status != "VALID"
                or context.browser_status is not BrowserStatus.VALID
                or context.verification_status is not VerificationStatus.MATCH):
            raise ValueError("Verified owned browser session required")
        if not binding.identity_id and context.browser_status not in {
                BrowserStatus.RUNNING, BrowserStatus.CREATED}:
            raise ValueError("Running anonymous browser session required")
        for url in (binding.route_url, binding.asset_url):
            parsed = urlsplit(url)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or package.scope.evaluate_url(url).result is not ScopeResult.IN_SCOPE):
                raise ValueError("Messaging route or asset is not clean and in scope")

        if binding.owned_object_id is not None:
            if self.objects is None or binding.identity_id is None:
                raise ValueError("Owned messaging canary registry is unavailable")
            owned = verified_owned_canary(
                self.objects, self.evidence, target_id=target_id, package_id=package_id,
                plan_id=run.plan_id, run_id=run.id, identity_id=binding.identity_id,
                object_id=binding.owned_object_id,
                canary_sha256=binding.owned_canary_sha256 or "",
                verified_at=binding.owned_verified_at or "", active=True)
            if owned is None:
                raise ValueError("Owned messaging canary is not current and reserved")
            binding = replace(binding, owned_canary_value=owned.test_name)

        binding = replace(binding, origin_probe_kind=candidate.origin_validation)

        self.store.bind_run(target_id, binding.candidate_id, run.id)
        variants = [MessageVariant.NO_MESSAGE, MessageVariant.WRONG_TYPE, MessageVariant.TRUSTED]
        if candidate.port_accepted:
            variants.append(MessageVariant.NO_PORT)
        if binding.window_mode == "IFRAME":
            variants.append(MessageVariant.WRONG_SOURCE)
        probe = MessageVariant.ATTACKER_PORT if candidate.port_accepted else MessageVariant.UNRELATED
        variants.append(probe)
        weak_origin = candidate.origin_validation in {
            "SUBSTRING", "STARTSWITH", "ENDSWITH", "REGEX_REVIEW", "WEAK_COMPARISON"}
        probe_available = False
        if weak_origin:
            try:
                probe_origin = lookalike_origin(binding.route_url,
                                                candidate.origin_validation)
                probe_available = (package.scope.evaluate_url(probe_origin + "/").result
                                   is not ScopeResult.IN_SCOPE)
            except ValueError:
                pass
        if probe_available:
            variants.append(MessageVariant.LOOKALIKE_ORIGIN)
        if len(variants) + 1 > self.MAX_TRIALS:
            raise ValueError("Messaging trial budget would be exceeded")
        trials: list[MessageTrial] = []
        for variant in variants:
            trial = self._trial(package, session.id, binding, variant)
            trials.append(trial)
            if trial.observation.victim_bundle_sha256 != asset.artifact_sha256:
                self.store.set_status(target_id, binding.candidate_id,
                                      MessageCandidateStatus.STALE, "BUNDLE_CHANGED_ON_ROUTE")
                return MessageExperimentResult(binding.candidate_id, run.id,
                                               "BUNDLE_CHANGED_ON_ROUTE", tuple(trials), ())
            if trial.observation.error_code or trial.observation.denial_count:
                self.store.set_status(target_id, binding.candidate_id,
                                      MessageCandidateStatus.NEEDS_MANUAL_REVIEW,
                                      "BROWSER_OR_POLICY_BLOCKED")
                return MessageExperimentResult(binding.candidate_id, run.id,
                                               "BLOCKED", tuple(trials), ())
            if variant in {MessageVariant.NO_MESSAGE, MessageVariant.WRONG_TYPE,
                           MessageVariant.NO_PORT} and trial.observation.capability_observed:
                self.store.set_status(target_id, binding.candidate_id,
                                      MessageCandidateStatus.NEEDS_MANUAL_REVIEW,
                                      "NEGATIVE_CONTROL_INVALID")
                return MessageExperimentResult(binding.candidate_id, run.id,
                                               "CONTROL_INVALID", tuple(trials), ())
            if (variant is MessageVariant.WRONG_TYPE and candidate.port_accepted
                    and (trial.observation.port_count != 1 or binding.allowed_method
                         and trial.observation.rpc_calls != 1)):
                self.store.set_status(target_id, binding.candidate_id,
                                      MessageCandidateStatus.NEEDS_MANUAL_REVIEW,
                                      "WRONG_TYPE_CONTROL_NOT_EQUIVALENT")
                return MessageExperimentResult(binding.candidate_id, run.id,
                                               "CONTROL_INVALID", tuple(trials), ())
            if (variant is probe and trial.observation.capability_observed
                    and trial.observation.effect_kind in self.PROOF_EFFECTS
                    and trials[2].observation.capability_observed
                    and trials[2].observation.effect_kind == trial.observation.effect_kind):
                break
        foreign = next(item for item in trials if item.variant is probe)
        lookalike = next((item for item in trials
                          if item.variant is MessageVariant.LOOKALIKE_ORIGIN), None)
        wrong_source = next((item for item in trials
                             if item.variant is MessageVariant.WRONG_SOURCE), None)
        boundary = next((item for item in (foreign, lookalike, wrong_source)
                         if item is not None and item.observation.capability_observed
                         and item.observation.effect_kind in self.PROOF_EFFECTS), None)
        trusted = trials[2]
        if (boundary is None or not trusted.observation.capability_observed
                or trusted.observation.effect_kind != boundary.observation.effect_kind):
            self.store.set_status(target_id, binding.candidate_id,
                                  MessageCandidateStatus.NEEDS_MANUAL_REVIEW
                                  if boundary is not None or weak_origin and not probe_available
                                  else MessageCandidateStatus.RUNTIME_TESTED,
                                  "TRUSTED_CONTROL_MISSING" if boundary is not None
                                  else "LOOKALIKE_ORIGIN_UNAVAILABLE"
                                  if weak_origin and not probe_available
                                  else "NO_UNAUTHORIZED_MESSAGING_EFFECT")
            return MessageExperimentResult(binding.candidate_id, run.id,
                                           "TRUSTED_CONTROL_MISSING" if boundary is not None
                                           else "LOOKALIKE_ORIGIN_UNAVAILABLE"
                                           if weak_origin and not probe_available
                                           else "NO_CAPABILITY", tuple(trials), ())
        reproduction = self._trial(package, session.id, binding,
                                   MessageVariant.FRESH_WRONG_SOURCE
                                   if boundary.variant is MessageVariant.WRONG_SOURCE
                                   else MessageVariant.FRESH_LOOKALIKE_ORIGIN
                                   if boundary.variant is MessageVariant.LOOKALIKE_ORIGIN
                                   else MessageVariant.FRESH_REPRODUCTION)
        trials.append(reproduction)
        if (reproduction.observation.victim_bundle_sha256 != asset.artifact_sha256
                or not reproduction.observation.capability_observed
                or reproduction.observation.effect_kind != boundary.observation.effect_kind
                or reproduction.observation.attacker_origin != boundary.observation.attacker_origin
                or reproduction.observation.source_relationship != boundary.observation.source_relationship
                or len({item.observation.context_id for item in trials}) != len(trials)):
            self.store.set_status(target_id, binding.candidate_id,
                                  MessageCandidateStatus.NEEDS_MANUAL_REVIEW,
                                  "FRESH_REPRODUCTION_FAILED")
            return MessageExperimentResult(binding.candidate_id, run.id,
                                           "REPRODUCTION_FAILED", tuple(trials), ())
        self.store.set_status(target_id, binding.candidate_id,
                              MessageCandidateStatus.VALIDATION_READY,
                              "UNAUTHORIZED_MESSAGE_CAPABILITY_REPRODUCED")
        return MessageExperimentResult(binding.candidate_id, run.id,
                                       "VALIDATION_READY", tuple(trials),
                                       (boundary.evidence_id, reproduction.evidence_id))

    def _trial(self, package, session_id: str, binding: MessageExperimentBinding,
               variant: MessageVariant) -> MessageTrial:
        run = self.runs.get(binding.run_id, package.target.id)
        step = self.runs.current_step(run) if run else None
        if step is None or not self.runs.account_message_dispatch(
                binding.run_id, step.id, variant.value):
            raise ValueError("Messaging browser trial budget exhausted or step not claimed")
        gate = _TrialRequestGate(
            package=package, binding=binding, session_id=session_id, policy=self.policy,
            runs=self.runs, request_cap=self.MAX_REQUESTS_PER_TRIAL,
            timeout_ms=self.TIMEOUT_MS,
            run_request_cap=self.MAX_TRIALS * self.MAX_REQUESTS_PER_TRIAL)
        try:
            observation = self.driver.execute_message_trial(
                session_id, binding, variant, gate, authenticated=binding.identity_id is not None,
                request_cap=self.MAX_REQUESTS_PER_TRIAL, timeout_ms=self.TIMEOUT_MS,
            )
        finally:
            gate.close()
        trace = observation.event_trace
        valid_trace = self.trace_is_valid(
            trace, source_attested=observation.source_attested,
            message_count=observation.message_count, port_count=observation.port_count,
            rpc_calls=observation.rpc_calls, effect_kind=observation.effect_kind)
        if (observation.request_count != gate.attempts
                or observation.request_count > self.MAX_REQUESTS_PER_TRIAL
                or observation.denial_count < gate.denied
                or gate.reserved != gate.released
                or observation.message_count > 3 or observation.port_count > 1
                or observation.rpc_calls > 1
                or observation.message_count > 0 and not observation.source_attested
                or not valid_trace):
            raise ValueError("Messaging driver did not enforce bounded fixture")
        metadata = {
            "candidate_id": binding.candidate_id, "run_id": binding.run_id,
            "browser_session_id": session_id,
            "route_sha256": hashlib.sha256(binding.route_url.encode()).hexdigest(),
            "asset_sha256": hashlib.sha256(binding.asset_url.encode()).hexdigest(),
            "variant": variant.value, "context_id": observation.context_id,
            "attacker_origin": observation.attacker_origin,
            "source_relationship": observation.source_relationship,
            "source_attested": observation.source_attested,
            "message_type": observation.message_type,
            "message_count": observation.message_count,
            "port_count": observation.port_count,
            "rpc_calls": observation.rpc_calls,
            "rpc_method": binding.allowed_method,
            "event_trace": [list(entry) for entry in trace],
            "capability_observed": observation.capability_observed,
            "effect_kind": observation.effect_kind,
            "effect_fingerprint": observation.effect_fingerprint,
            "owned_object_id": binding.owned_object_id,
            "owned_canary_sha256": binding.owned_canary_sha256,
            "marker_context": observation.marker_context,
            "document_origin": observation.document_origin,
            "victim_bundle_sha256": observation.victim_bundle_sha256,
            "response_status": observation.response_status,
            "frame_ancestors": observation.frame_ancestors,
            "x_frame_options": observation.x_frame_options,
            "sandbox_flags": list(observation.sandbox_flags[:8]),
            "request_count": observation.request_count,
            "denial_count": observation.denial_count,
            "error_code": observation.error_code,
            "rate_reserved_count": gate.reserved,
            "rate_released_count": gate.released,
            "rate_limiter": "PHASE14_SHARED",
            "policy_decision_ids": gate.decisions[:self.MAX_REQUESTS_PER_TRIAL],
        }
        evidence = self.evidence.create_evidence(
            EvidenceType.MESSAGE_PROOF, json.dumps(metadata, sort_keys=True).encode(),
            source="postmessage_browser", target_ref=package.target.id,
            provenance=EvidenceProvenance(system="HACKBOT", entity="MESSAGE_BROWSER_EXPERIMENT",
                                          record_id=binding.candidate_id),
            sensitivity=(Sensitivity.SENSITIVE if binding.identity_id else Sensitivity.INTERNAL),
            redaction_status=RedactionStatus.REDACTED,
        )
        self.store.record_trial(
            target_id=package.target.id, candidate_id=binding.candidate_id,
            run_id=binding.run_id, evidence_id=evidence.evidence_id,
            variant=variant.value, message_count=observation.message_count,
            port_count=observation.port_count, rpc_calls=observation.rpc_calls,
            capability_observed=observation.capability_observed,
        )
        return MessageTrial(variant, evidence.evidence_id, observation,
                            tuple(gate.decisions))
