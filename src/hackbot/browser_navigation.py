"""Policy-gated, Burp-captured read navigation for authenticated mapping."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Callable, Protocol

from .browser import BrowserSessionManager, BrowserStatus, VerificationStatus
from .browser_playwright import BrowserNavigationObservation
from .bootstrap import _safe_url
from .burp import BurpProxyProvider
from .executor import RequestTemplate
from .permit_store import PolicyPermitStore
from .policy import PolicyEngine, policy_version
from .policy_models import (ActionCategory, ActorMode, PolicyPermit, ProposedAction)
from .rate_limit import ExperimentBudget, RateLimiter
from .target_package import TargetPackage
from .target_policy import PolicyDecision
from .target_scope import ScopeResult
from .traffic import TrafficStore


class BrowserNavigationError(ValueError):
    """Safe, secret-free reason a mapped navigation cannot continue."""


class BrowserNavigationBudgetReached(BrowserNavigationError):
    """The bounded map spent its allocation; capture and identity remain valid."""


class NavigationDriver(Protocol):
    def navigate_readonly(self, session_id: str, url: str,
                          gate: Callable[[str, str, bool], object],
                          redirect_allowed: Callable[[str], bool], *,
                          request_cap: int, timeout_ms: int,
                          response_cap: int) -> BrowserNavigationObservation: ...


@dataclass(frozen=True, slots=True)
class BrowserRequestTicket:
    permit: PolicyPermit
    reservation_id: str


class BrowserRequestGate:
    """One decision, permit, and rate reservation for each actual browser request."""

    def __init__(self, package: TargetPackage, session_id: str, identity_id: str,
                 policy: PolicyEngine, permits: PolicyPermitStore,
                 rate: RateLimiter, burp: BurpProxyProvider,
                 experiment_id: str, budget: ExperimentBudget) -> None:
        self.package = package
        self.session_id = session_id
        self.identity_id = identity_id
        self.policy = policy
        self.permits = permits
        self.rate = rate
        self.burp = burp
        self.experiment_id = experiment_id
        self.budget = budget
        self.authorized_count = 0

    def __call__(self, url: str, method: str, navigation: bool) -> BrowserRequestTicket | None:
        if method not in {"GET", "HEAD"} or not self.burp.ready(self.session_id):
            return None
        try:
            action = ProposedAction(
                target_id=self.package.target.id, package_id=self.package.id,
                category=(ActionCategory.BROWSER_NAVIGATION if navigation else ActionCategory.SAFE_READ),
                actor=ActorMode.AUTHENTICATED, source="application_mapper",
                purpose="Bounded authenticated application mapping",
                url=url, method=method, identity_id=self.identity_id,
                session_id=self.session_id)
            scope = self.policy.scope.evaluate(self.package, action)
            if scope is None or scope.result is not ScopeResult.IN_SCOPE:
                self.policy.evaluate(self.package, action, record=True)
                return None
            deadline = time.monotonic() + min(
                2.5, max(0.5, 1.0 / self.package.rate.requests_per_second + 0.25))
            while True:
                pace = self.rate.check(action.target_id, self.package.rate,
                                       experiment_id=self.experiment_id,
                                       budget=self.budget)
                if pace.allowed:
                    break
                if (pace.reason_code not in {"RATE_PER_SECOND", "CONCURRENCY_LIMIT"}
                        or time.monotonic() >= deadline):
                    return None
                time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
            decision = self.policy.evaluate(self.package, action, record=True)
            if decision.result is not PolicyDecision.ALLOW:
                return None
            reservation = self.rate.reserve(
                action.target_id, self.package.rate,
                experiment_id=self.experiment_id, budget=self.budget)
            if not reservation.allowed or reservation.reservation_id is None:
                return None
            committed = False
            try:
                fingerprint = RequestTemplate(method, url).fingerprint()
                permit = self.permits.issue(action, decision, fingerprint)
                if not self.permits.consume(permit, action, fingerprint,
                                            policy_version(self.package)):
                    return None
                self.authorized_count += 1
                committed = True
                return BrowserRequestTicket(permit, reservation.reservation_id)
            finally:
                if not committed:
                    self.rate.release(reservation.reservation_id)
        except (ValueError, LookupError):
            return None

    def release(self, ticket: BrowserRequestTicket, succeeded: bool) -> None:
        self.rate.release(ticket.reservation_id)
        self.permits.record(ticket.permit, "BROWSER_REQUEST_COMPLETE" if succeeded
                            else "BROWSER_REQUEST_FAILED", "POLICY_ALLOW" if succeeded
                            else "NETWORK_FAILED")


class BrowserActionExecutor:
    """Execute a single mapped page only through a captured, verified session."""

    def __init__(self, *, browser: BrowserSessionManager,
                 driver: NavigationDriver, burp: BurpProxyProvider,
                 policy: PolicyEngine, permits: PolicyPermitStore,
                 rate: RateLimiter, traffic: TrafficStore) -> None:
        self.browser = browser
        self.driver = driver
        self.burp = burp
        self.policy = policy
        self.permits = permits
        self.rate = rate
        self.traffic = traffic

    def navigate(self, package: TargetPackage, session_id: str, url: str, *,
                 experiment_id: str, request_cap: int = 24,
                 total_request_budget: int | None = None,
                 timeout_ms: int = 20000) -> BrowserNavigationObservation:
        context = self.browser.session_context(session_id)
        if (context.target_id != package.target.id or context.identity_id is None
                or context.browser_status is not BrowserStatus.VALID
                or context.verification_status is not VerificationStatus.MATCH
                or context.authentication_status != "VALID"
                or not context.browser_available or not context.proxy_enabled
                or not context.proxy_capture_required or not self.burp.ready(session_id)):
            raise BrowserNavigationError("Verified captured browser session is required")
        if not 1 <= request_cap <= 96 or not 1000 <= timeout_ms <= 30000:
            raise BrowserNavigationError("Invalid browser mapping budget")
        total = total_request_budget if total_request_budget is not None else request_cap
        if type(total) is not int or not request_cap <= total <= 10000:
            raise BrowserNavigationError("Invalid browser mapping total budget")
        if _safe_url(url, url, package) != url:
            raise BrowserNavigationError("Unsafe browser mapping URL")
        budget = ExperimentBudget(max_requests=total, max_mutations=0,
                                  max_creations=0, max_retries=0)
        # Wait outside Playwright's per-page timeout so a full minute window does
        # not turn an authorized document request into a failed navigation.
        deadline = time.monotonic() + 61.0
        while True:
            delay = self.rate.retry_after_seconds(
                package.target.id, package.rate, experiment_id=experiment_id,
                budget=budget)
            if delay is None:
                outcome = self.rate.check(package.target.id, package.rate,
                                          experiment_id=experiment_id, budget=budget)
                if outcome.reason_code == "EXPERIMENT_REQUEST_BUDGET":
                    raise BrowserNavigationBudgetReached("Browser mapping request budget reached")
                raise BrowserNavigationError("Browser mapping request capacity unavailable")
            if delay <= 0:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BrowserNavigationError("Browser mapping rate wait exceeded")
            time.sleep(min(max(0.01, delay + 0.01), remaining))
        gate = BrowserRequestGate(
            package, session_id, context.identity_id, self.policy, self.permits,
            self.rate, self.burp, experiment_id,
            budget)

        def redirect_allowed(destination: str) -> bool:
            if _safe_url(destination, destination, package) != destination:
                return False
            action = ProposedAction(
                target_id=package.target.id, package_id=package.id,
                category=ActionCategory.BROWSER_NAVIGATION,
                actor=ActorMode.AUTHENTICATED, source="application_mapper",
                purpose="Check browser redirect scope", url=destination,
                method="GET", identity_id=context.identity_id,
                session_id=session_id)
            scope = self.policy.scope.evaluate(package, action)
            return scope is not None and scope.result is ScopeResult.IN_SCOPE

        before = {item.id for item in self.traffic.list_exchanges_for_session(
            package.target.id, session_id, limit=50).items}
        observation = self.driver.navigate_readonly(
            session_id, url, gate, redirect_allowed, request_cap=request_cap,
            timeout_ms=timeout_ms, response_cap=2_097_152)
        if gate.authorized_count:
            for _ in range(10):
                after = self.traffic.list_exchanges_for_session(
                    package.target.id, session_id, limit=50).items
                if any(item.id not in before for item in after):
                    break
                time.sleep(0.2)
            else:
                raise BrowserNavigationError("Captured browser traffic was not recorded")
        return observation
