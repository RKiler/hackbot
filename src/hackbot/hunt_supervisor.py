"""Prepare a target-scoped hunt using existing local capture and identity owners."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import hashlib
import time
from typing import TYPE_CHECKING

from .auth import AuthMechanism, AuthStatus
from .api_specialist import APIAnalysisLimits
from .application_mapper import MappingLimits
from .browser import BrowserError, BrowserStatus
from .browser_navigation import BrowserNavigationError
from .burp import BurpError
from .campaign_models import CampaignLimits, CampaignPreset, CampaignStatus
from .domain import ObservationState
from .hunt_store import HuntMode, HuntRun, HuntState, HuntStore
from .identity_observation import CapturedSelfObserver, IdentityObservationConflict
from .planner_models import PlannerMode
from .policy import policy_version
from .recon_postgres import ReconQueryError
from .recipe_learning import ObservedRecipeLearner
from .resources import (RECOVERABLE_CAMPAIGN_PAUSE_REASONS, ResourceError,
                        WorkKind)
from .target_package import PackageStatus, TargetPackage
from .target_policy import PolicyDecision
from .target_recon import ReconDomainResolver
from .test_objects import CleanupStrategy, ObjectState

if TYPE_CHECKING:
    from .service import BugHunterRuntime


class HuntSupervisor:
    """Owns preparation state, not traffic execution or finding confirmation."""

    _PENDING_LOGIN = frozenset({BrowserStatus.WAITING_LOGIN})
    _AWAITING_VERIFICATION = frozenset({BrowserStatus.VERIFYING_IDENTITY,
                                        BrowserStatus.NEEDS_MANUAL_REVIEW})

    def __init__(self, runtime: BugHunterRuntime) -> None:
        self.runtime = runtime
        self.store = HuntStore(runtime.store)

    def reconcile_interrupted(self) -> int:
        """Mark interrupted work for safe re-preparation without dispatching traffic."""
        changed = 0
        cursor = None
        while True:
            page = self.store.active(after_hunt_id=cursor)
            for run in page:
                cursor = run.id
                if run.state in {HuntState.WAITING_APPROVAL, HuntState.WAITING_HUMAN,
                                 HuntState.PAUSED_RESOURCE_PRESSURE}:
                    continue
                try:
                    package = self.runtime.package(run.package_id)
                except (LookupError, ValueError):
                    self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                          "TARGET_PACKAGE_UNAVAILABLE")
                    changed += 1
                    continue
                if (package.target.id != run.target_id or package.status is not PackageStatus.TRACKED
                        or package.version != run.package_version
                        or policy_version(package) != run.policy_hash):
                    self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                          "PACKAGE_POLICY_CHANGED")
                    changed += 1
                    continue
                if run.state is HuntState.HUNTING:
                    if run.campaign_id is None:
                        self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                              "CAMPAIGN_START_UNCONFIRMED")
                        changed += 1
                        continue
                    campaign = self.runtime.campaign.store.get(run.target_id,
                                                               run.campaign_id)
                    if campaign is None or campaign.package_id != run.package_id:
                        self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                              "CAMPAIGN_LINK_UNAVAILABLE")
                        changed += 1
                        continue
                    if campaign.status in {CampaignStatus.COMPLETED,
                                           CampaignStatus.CANCELLED}:
                        pending = any(
                            (item := self.runtime.objects.get(row["test_object_id"],
                                                              run.target_id)) is None or
                            item.state not in {ObjectState.CLEANED, ObjectState.PLANNED}
                            for row in self.store.fixtures(run.target_id, run.id))
                        self.store.transition(
                            run.target_id, run.id,
                            HuntState.WAITING_HUMAN if pending else HuntState.COMPLETE,
                            "FIXTURE_CLEANUP_PENDING" if pending else
                            "CAMPAIGN_" + campaign.status.value)
                        changed += 1
                        continue
                    if campaign.status in {CampaignStatus.BLOCKED, CampaignStatus.FAILED,
                                           CampaignStatus.CLEANUP_REQUIRED,
                                           CampaignStatus.BUDGET_EXHAUSTED,
                                           CampaignStatus.TIME_EXHAUSTED}:
                        self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                              "CAMPAIGN_REVIEW_REQUIRED")
                        changed += 1
                        continue
                    if (campaign.status is CampaignStatus.PAUSED and
                            campaign.readiness_code in
                            RECOVERABLE_CAMPAIGN_PAUSE_REASONS):
                        self.store.transition(run.target_id, run.id,
                                              HuntState.PAUSED_RESOURCE_PRESSURE,
                                              "CAMPAIGN_RESOURCE_PRESSURE")
                        changed += 1
                        continue
                if run.state in {HuntState.READY, HuntState.MAPPING, HuntState.HUNTING,
                                 HuntState.LOGIN_REQUIRED}:
                    self.store.transition(run.target_id, run.id, HuntState.PREPARING,
                                          "PROCESS_RESTART_REPREPARE")
                    changed += 1
            if len(page) < 100:
                break
        return changed

    def start(self, package: TargetPackage, *, mode: HuntMode = HuntMode.SUPERVISED,
              requested_by: str = "operator") -> HuntRun:
        run = self.create(package, mode=mode, requested_by=requested_by)
        return self.advance(package, run.id)

    def create(self, package: TargetPackage, *, mode: HuntMode = HuntMode.SUPERVISED,
               requested_by: str = "operator") -> HuntRun:
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("TargetPackage is not tracked")
        if (mode is not HuntMode.PLAN_ONLY and
                package.rules.automated_testing_allowed is not True):
            raise ValueError("Program must explicitly allow automated testing")
        self.runtime.registry.register_target(package)
        return self.store.create(package, mode, requested_by=requested_by)

    def identity_updated(self, package: TargetPackage, *, verified: bool) -> HuntRun | None:
        """Persist the login handoff; the service schedules the next local step."""
        run = self.store.current(package.target.id)
        if run is None or run.package_id != package.id:
            return None
        if verified and (run.state is HuntState.LOGIN_REQUIRED or
                         run.state is HuntState.WAITING_HUMAN and run.reason_code ==
                         "IDENTITY_CONFIRMATION_REQUIRED"):
            return self.store.transition(run.target_id, run.id, HuntState.PREPARING,
                                         "IDENTITY_CONFIRMED_REPREPARE")
        if not verified and run.state is HuntState.LOGIN_REQUIRED:
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "IDENTITY_CONFIRMATION_REQUIRED")
        return run

    def _capture_ready(self, session_id: str, *, timeout_seconds: float = 32.0) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while True:
            if self.runtime.burp.ready(session_id):
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(1.0, remaining))

    def _prepare_anonymous_capture(self, package: TargetPackage, run: HuntRun) -> HuntRun:
        if not self.runtime.config.burp.enabled:
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "BURP_CAPTURE_NOT_CONFIGURED")
        if not self.runtime._vnc_ready():
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "VISIBLE_BROWSER_UNAVAILABLE")
        try:
            self.runtime.ensure_burp_bridge(package)
            if self.runtime.burp.anonymous_capture_binding(run.target_id) is not None:
                return self.store.transition(run.target_id, run.id, HuntState.READY,
                                             "ANONYMOUS_CAPTURE_READY")
            cursor = None
            for _ in range(5):
                page = self.runtime.browser.list_sessions_for_target(
                    run.target_id, limit=20, cursor=cursor)
                for session in page.items:
                    if session.identity_id is not None:
                        continue
                    if (session.status is BrowserStatus.RUNNING and
                            self.runtime.driver.is_running(session.id)):
                        return self.store.transition(run.target_id, run.id,
                                                     HuntState.WAITING_HUMAN,
                                                     "ANONYMOUS_CAPTURE_REVIEW_REQUIRED")
                    self.runtime.delete_browser_session(package, session)
                cursor = page.next_cursor
                if cursor is None:
                    break
            if cursor is not None:
                return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                             "ANONYMOUS_SESSION_INVENTORY_INCOMPLETE")
            with self.runtime.store._connection() as db:
                active = db.execute(
                    "SELECT count(*) FROM browser_sessions AS s WHERE status NOT IN "
                    "('STOPPED','FAILED','EXPIRED') AND NOT EXISTS "
                    "(SELECT 1 FROM browser_session_events AS e WHERE "
                    "e.session_id=s.session_id AND e.event_type='browser_deleted')"
                ).fetchone()[0]
            self.runtime.resources.admit(WorkKind.BROWSER, active=active)
            session, _ = self.runtime.burp.provision_session(package)
            try:
                if not self._capture_ready(session.id):
                    raise BurpError("Anonymous capture transport did not become ready")
                started = self.runtime.burp.start_browser(session.id, package=package)
            except (BurpError, BrowserError, ValueError):
                self.runtime.delete_browser_session(package, session)
                raise
            if (started.status is not BrowserStatus.RUNNING or
                    not self.runtime.burp.ready(started.id)):
                self.runtime.delete_browser_session(package, started)
                raise BurpError("Anonymous capture did not become ready")
        except ResourceError:
            return self.store.transition(run.target_id, run.id,
                                         HuntState.PAUSED_RESOURCE_PRESSURE,
                                         "BROWSER_CAPACITY_UNAVAILABLE")
        except (BurpError, BrowserError, ValueError, LookupError):
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "ANONYMOUS_CAPTURE_UNAVAILABLE")
        return self.store.transition(run.target_id, run.id, HuntState.READY,
                                     "ANONYMOUS_CAPTURE_READY")

    def advance(self, package: TargetPackage, hunt_id: str) -> HuntRun:
        run = self.store.get(package.target.id, hunt_id)
        if run is None or run.package_id != package.id:
            raise LookupError("Hunt not found")
        if run.state in {HuntState.COMPLETE, HuntState.FAILED}:
            return run
        if (run.package_version != package.version or
                run.policy_hash != policy_version(package)):
            if run.state is HuntState.WAITING_HUMAN:
                return run
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "PACKAGE_POLICY_CHANGED")
        if run.state is HuntState.PAUSED_RESOURCE_PRESSURE:
            run = self.store.transition(run.target_id, run.id, HuntState.PREPARING,
                                        "RESOURCE_RETRY")
        if run.state not in {HuntState.PREPARING, HuntState.LOGIN_REQUIRED}:
            return run

        if run.state is HuntState.PREPARING:
            if self.runtime.recon is not None:
                try:
                    ReconDomainResolver(self.runtime.recon).select_hosts(package)
                except ReconQueryError:
                    pass  # Recon absence never changes package scope or testing permission.
            self.runtime.registry.import_package_accounts(package)
        if run.mode is HuntMode.PLAN_ONLY:
            return self.store.transition(run.target_id, run.id, HuntState.READY,
                                         "PASSIVE_PREPARATION_READY")
        if not package.accounts:
            return self._prepare_anonymous_capture(package, run)
        if not self.runtime.config.burp.enabled:
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "BURP_CAPTURE_NOT_CONFIGURED")
        if not self.runtime._vnc_ready():
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "VISIBLE_BROWSER_UNAVAILABLE")

        pending_login = False
        for account in package.accounts:
            identity = self.runtime.registry.get_identity(run.target_id, account.alias)
            if identity is None:
                return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                             "ACCOUNT_REGISTRATION_INCOMPLETE")
            active = self.runtime.browser.get_active_session(run.target_id, identity.id)
            if active is not None and self.runtime.burp.ready(active.id):
                if self.runtime.browser.verification_method(active.id) == "OPERATOR_CONFIRMED":
                    rule = self.runtime.verification_rule(package, identity.id)
                    if rule is not None:
                        verified = self.runtime.browser.reverify_automatic(active.id, rule)
                        if verified.status is BrowserStatus.REAUTH_REQUIRED:
                            return self.store.transition(run.target_id, run.id,
                                                         HuntState.WAITING_HUMAN,
                                                         "IDENTITY_CONFLICT")
                continue
            session = self.runtime.browser.get_session_for_identity(run.target_id, identity.id)
            if session is not None:
                binding = self.runtime.burp.binding_for_session(session.id)
                running = self.runtime.driver.is_running(session.id)
                if (binding is not None and binding.state == "ACTIVE" and running
                        and self.runtime.burp.ready(session.id)):
                    if session.status in self._PENDING_LOGIN:
                        pending_login = True
                        continue
                    if session.status in self._AWAITING_VERIFICATION:
                        rule = self.runtime.verification_rule(package, identity.id)
                        verified = self.runtime.browser.verify(session.id, rule)
                        if verified.status is BrowserStatus.VALID and self.runtime.burp.ready(session.id):
                            continue
                        return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                                     "IDENTITY_CONFIRMATION_REQUIRED")
                try:
                    self.runtime.delete_browser_session(package, session)
                except (ValueError, LookupError, BurpError):
                    return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                                 "SESSION_RECONCILIATION_REQUIRED")
                session = None

            try:
                with self.runtime.store._connection() as db:
                    active_count = db.execute(
                        "SELECT count(*) FROM browser_sessions AS s WHERE status NOT IN "
                        "('STOPPED','FAILED','EXPIRED') AND NOT EXISTS "
                        "(SELECT 1 FROM browser_session_events AS e WHERE "
                        "e.session_id=s.session_id AND e.event_type='browser_deleted')"
                    ).fetchone()[0]
                self.runtime.resources.admit(WorkKind.BROWSER, active=active_count)
            except ResourceError:
                if pending_login:
                    break
                return self.store.transition(run.target_id, run.id,
                                             HuntState.PAUSED_RESOURCE_PRESSURE,
                                             "BROWSER_CAPACITY_UNAVAILABLE")
            context = self.runtime.auth.get(run.target_id, identity.id)
            if context is None or context.status in {AuthStatus.INVALID, AuthStatus.LOCKED,
                                                     AuthStatus.EXPIRED, AuthStatus.VALID}:
                self.runtime.auth.prepare(run.target_id, identity.id,
                                          mechanism=AuthMechanism.MANUAL_LOGIN)
            try:
                self.runtime.ensure_burp_bridge(package)
                session, _ = self.runtime.burp.provision_session(package, identity.id)
                if not self._capture_ready(session.id):
                    raise BurpError("Capture transport did not become ready")
                started = self.runtime.burp.start_browser(session.id, package=package)
            except (BurpError, ValueError, ResourceError):
                if session is not None and session.identity_id == identity.id:
                    try:
                        self.runtime.delete_browser_session(package, session)
                    except (ValueError, LookupError, BurpError):
                        pass
                return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                             "CAPTURE_SESSION_UNAVAILABLE")
            if started.status is BrowserStatus.WAITING_LOGIN:
                pending_login = True
            elif started.status is BrowserStatus.VERIFYING_IDENTITY:
                rule = self.runtime.verification_rule(package, identity.id)
                verified = self.runtime.browser.verify(started.id, rule)
                if verified.status is not BrowserStatus.VALID:
                    return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                                 "IDENTITY_CONFIRMATION_REQUIRED")
            else:
                return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                             "SESSION_NOT_READY")
        if pending_login:
            if run.state is HuntState.LOGIN_REQUIRED:
                return run
            return self.store.transition(run.target_id, run.id, HuntState.LOGIN_REQUIRED,
                                         "ACCOUNT_LOGIN_REQUIRED")
        return self.store.transition(run.target_id, run.id, HuntState.READY,
                                     "CAPTURED_SESSIONS_READY")

    def map_ready(self, package: TargetPackage, hunt_id: str) -> HuntRun:
        """Resume bounded read mapping for verified accounts, one durable session at a time."""
        run = self.store.get(package.target.id, hunt_id)
        if run is None or run.package_id != package.id:
            raise LookupError("Hunt not found")
        if (run.mode is HuntMode.PLAN_ONLY or not package.accounts
                or run.state is HuntState.READY and run.reason_code in {
                    "MAPPING_COMPLETE", "MAPPING_PARTIAL"}):
            return run
        if run.state not in {HuntState.READY, HuntState.MAPPING}:
            return run
        if (run.package_version != package.version or
                run.policy_hash != policy_version(package)):
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "PACKAGE_POLICY_CHANGED")
        if run.state is HuntState.READY:
            run = self.store.transition(run.target_id, run.id, HuntState.MAPPING,
                                        "AUTHENTICATED_MAPPING_STARTED")
        mapped = {item["browser_session_id"] for item in self.store.mapping_sessions(
            run.target_id, run.id)}
        for account in package.accounts:
            identity = self.runtime.registry.get_identity(run.target_id, account.alias)
            if identity is None:
                return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                             "ACCOUNT_REGISTRATION_INCOMPLETE")
            session = self.runtime.browser.get_active_session(run.target_id, identity.id)
            if session is None or not self.runtime.burp.ready(session.id):
                return self.store.transition(run.target_id, run.id, HuntState.PREPARING,
                                             "MAPPING_SESSION_REPREPARE")
            if session.id in mapped:
                continue
            if self.runtime.resources.snapshot().state != "OK":
                return self.store.transition(run.target_id, run.id,
                                             HuntState.PAUSED_RESOURCE_PRESSURE,
                                             "MAPPING_RESOURCE_PRESSURE")
            try:
                result = self.runtime.application_mapper.map_session(
                    package, session.id,
                    experiment_id=f"{run.id}:{session.id}",
                    limits=MappingLimits())
            except BrowserNavigationError:
                return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                             "MAPPING_CAPTURE_REVIEW_REQUIRED")
            if result.session_id != session.id:
                return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                             "MAPPING_SESSION_MISMATCH")
            if "CAPTURE_OR_IDENTITY_LOST" not in result.blocked:
                try:
                    scripts = self.runtime.captured_js.collect(package, session.id)
                except ValueError:
                    return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                                 "JS_CAPTURE_REVIEW_REQUIRED")
                gaps = tuple(code for code, present in (
                    ("JS_CAPTURE_LIMIT_REACHED", scripts.truncated),
                    ("JS_ANALYSIS_INCOMPLETE", scripts.analysis_failures > 0)) if present)
                result = replace(
                    result,
                    evidence_ids=tuple(dict.fromkeys((
                        *result.evidence_ids,
                        *(asset.evidence_id for asset in scripts.acquired)))),
                    blocked=tuple(dict.fromkeys((*result.blocked, *gaps))))
            self.store.record_mapping(run.target_id, run.id, result)
            if "CAPTURE_OR_IDENTITY_LOST" in result.blocked:
                return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                             "MAPPING_CAPTURE_REVIEW_REQUIRED")
            mapped.add(session.id)
        rows = self.store.mapping_sessions(run.target_id, run.id)
        inventory_incomplete = False
        learner = ObservedRecipeLearner(
            evidence=self.runtime.store, traffic=self.runtime.traffic,
            js=self.runtime.domxss_store,
            catalog=self.runtime.object_factory.recipes)
        since = datetime.fromisoformat(run.created_at)
        self_urls = learner.current_self_urls(package, since)
        self_observer = CapturedSelfObserver(
            registry=self.runtime.registry, evidence=self.runtime.store)
        for account in package.accounts:
            identity = self.runtime.registry.get_identity(run.target_id, account.alias)
            session = (self.runtime.browser.get_active_session(run.target_id, identity.id)
                       if identity else None)
            if session is None:
                return self.store.transition(run.target_id, run.id, HuntState.PREPARING,
                                             "MAPPING_SESSION_REPREPARE")
            try:
                learner.learn(package, account, session_id=session.id,
                              identity_id=identity.id,
                              since=since)
            except (ValueError, OSError):
                return self.store.transition(run.target_id, run.id,
                                             HuntState.WAITING_HUMAN,
                                             "RECIPE_REVIEW_REQUIRED")
            if self_urls and account.tenant_hint and account.role_hint:
                url = self_urls[0]
                prior = {item.id for item in self.runtime.traffic.list_exchanges_for_session(
                    run.target_id, session.id, limit=50).items}
                try:
                    observed = self.runtime.browser_navigation.navigate(
                        package, session.id, url,
                        experiment_id=f"{run.id}:self:{session.id}",
                        request_cap=4, total_request_budget=4)
                except BrowserNavigationError:
                    inventory_incomplete = True
                    continue
                if observed.status_code != 200 or observed.url != url:
                    inventory_incomplete = True
                    continue
                try:
                    promoted = any(
                        item.id not in prior and item.observed_at >= since and
                        self_observer.observe(package, account,
                                              identity_id=identity.id,
                                              session_id=session.id, url=url,
                                              exchange=item)
                        for item in self.runtime.traffic.list_exchanges_for_session(
                            run.target_id, session.id, limit=50).items)
                except IdentityObservationConflict:
                    return self.store.transition(run.target_id, run.id,
                                                 HuntState.WAITING_HUMAN,
                                                 "IDENTITY_CONFLICT")
                if not promoted:
                    inventory_incomplete = True
        try:
            inventory = self.runtime.api.profile(
                package, limits=APIAnalysisLimits(traffic=100, js_assets=30,
                                                  recon_surfaces=12))
            self.runtime.api.generate(
                package, limits=APIAnalysisLimits(traffic=1, js_assets=1,
                                                  recon_surfaces=1, candidates=12),
                mode="PLAN_ONLY")
            expected_gaps = {"RECON_UNAVAILABLE", "RECON_TARGET_MISSING",
                             "OPERATION_ENDPOINT_UNKNOWN"}
            inventory_incomplete = bool(set(inventory["gaps"]) - expected_gaps or
                                        any(inventory["inventory_more"].values()))
        except (ValueError, LookupError, OSError):
            inventory_incomplete = True
        reason = ("MAPPING_COMPLETE" if any(row["pages_observed"] for row in rows)
                  and all(row["blocked_count"] == 0 for row in rows)
                  and not inventory_incomplete
                  else "MAPPING_PARTIAL")
        return self.store.transition(run.target_id, run.id, HuntState.READY, reason)

    def prepare_fixtures(self, package: TargetPackage, hunt_id: str) -> HuntRun:
        """Create two owned controls only after durable hunt linkage and observed identity."""
        run = self.store.get(package.target.id, hunt_id)
        if run is None or run.package_id != package.id:
            raise LookupError("Hunt not found")
        if run.state is not HuntState.READY or run.reason_code not in {
                "MAPPING_COMPLETE", "MAPPING_PARTIAL"}:
            return run
        if run.mode not in {HuntMode.SUPERVISED, HuntMode.RESEARCHER_AUTONOMOUS}:
            return run
        policy = package.autonomy
        if (package.rules.automated_testing_allowed is not True or
                policy.state_changing is not PolicyDecision.ALLOW or
                policy.create_disposable_objects is not PolicyDecision.ALLOW or
                policy.delete_disposable_objects is not PolicyDecision.ALLOW or
                not policy.owned_test_objects_only):
            return run
        if (run.package_version != package.version or
                run.policy_hash != policy_version(package)):
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "PACKAGE_POLICY_CHANGED")
        catalog = self.runtime.object_factory.recipes
        recipes = tuple(catalog.get(package.id, entry["id"])
                        for entry in catalog.list_for_package(package.id))
        recipes = tuple(recipe for recipe in recipes if recipe is not None and
                        recipe.source == "learned_form_js" and
                        recipe.cleanup_strategy is CleanupStrategy.AUTO_CLEANUP and
                        recipe.cleanup is not None and recipe.parent_type is None)
        existing = {(row["tenant_id"], row["object_type"]): row
                    for row in self.store.fixtures(run.target_id, run.id)}
        learner = ObservedRecipeLearner(
            evidence=self.runtime.store, traffic=self.runtime.traffic,
            js=self.runtime.domxss_store, catalog=catalog)
        since = datetime.fromisoformat(run.created_at)
        selected_tenants: set[str] = set()
        created = 0
        policy_controls = []
        for account in package.accounts:
            if not account.tenant_hint or account.tenant_hint in selected_tenants:
                continue
            identity = self.runtime.registry.get_identity(run.target_id, account.alias)
            if identity is None or identity.principal_state is not ObservationState.OBSERVED:
                continue
            membership = None
            for item in self.runtime.registry.list_memberships(identity.id, limit=12).items:
                tenant = self.runtime.registry.get_tenant(run.target_id, item.tenant_id)
                if (item.observation_state is ObservationState.OBSERVED and
                        tenant is not None and tenant.label == account.tenant_hint):
                    membership = item
                    break
            if membership is None:
                continue
            recipe = next((item for item in recipes
                           if item.expected_owner == account.alias and
                           item.expected_tenant == account.tenant_hint), None)
            if recipe is None:
                continue
            session = self.runtime.browser.get_active_session(run.target_id, identity.id)
            if session is None or not self.runtime.burp.ready(session.id):
                return self.store.transition(run.target_id, run.id, HuntState.PREPARING,
                                             "FIXTURE_SESSION_REPREPARE")
            selected_tenants.add(account.tenant_hint)
            row = existing.get((membership.tenant_id, recipe.object_type))
            if row is None:
                try:
                    planned = self.runtime.object_factory.plan_disposable(
                        package_id=package.id, recipe_id=recipe.id,
                        identity_id=identity.id, tenant_id=membership.tenant_id,
                        session_id=session.id, purpose="Hunt-owned authorization control",
                        reuse_ready=False)
                    if (planned.outcome != "PLANNED" or planned.item is None or
                            not self.store.track_fixture(run.target_id, run.id,
                                                         planned.item)):
                        raise ValueError("Fixture plan was not durably linked")
                    item = planned.item
                except ValueError:
                    return self.store.transition(run.target_id, run.id,
                                                 HuntState.WAITING_HUMAN,
                                                 "FIXTURE_PLAN_REVIEW_REQUIRED")
            else:
                item = self.runtime.objects.get(row["test_object_id"], run.target_id)
                if (item is None or item.creator_identity_id != identity.id or
                        item.tenant_id != membership.tenant_id or
                        item.recipe_hash != recipe.sha256):
                    return self.store.transition(run.target_id, run.id,
                                                 HuntState.WAITING_HUMAN,
                                                 "FIXTURE_BINDING_CONFLICT")
            if item.state is ObjectState.PLANNED:
                result = self.runtime.object_factory.create(item.id, run.target_id,
                                                            session_id=session.id)
            elif item.state in {ObjectState.CREATED, ObjectState.VERIFYING}:
                result = self.runtime.object_factory.verify(item.id, run.target_id,
                                                            session_id=session.id)
            elif item.state is ObjectState.READY and item.verified_at:
                result = None
            else:
                return self.store.transition(run.target_id, run.id,
                                             HuntState.WAITING_HUMAN,
                                             "FIXTURE_STATE_REVIEW_REQUIRED")
            if result is not None and result.outcome != "READY":
                return self.store.transition(run.target_id, run.id,
                                             HuntState.WAITING_HUMAN,
                                             "FIXTURE_CREATE_" + result.outcome)
            if result is not None:
                assert result.item is not None
                item = result.item
            external = None
            try:
                external = self.runtime.object_factory.verified_external_id(
                    item.id, run.target_id)
                reads = learner.current_object_read_urls(
                    package, recipe, external, since)
            except (ValueError, PermissionError):
                reads = ()
            for url in reads[:1]:
                if learner.has_captured_owner_read(package, session.id,
                                                   identity.id, url, since):
                    continue
                try:
                    self.runtime.browser_navigation.navigate(
                        package, session.id, url,
                        experiment_id=f"{run.id}:object-read:{item.id}",
                        request_cap=2, total_request_budget=2)
                except BrowserNavigationError:
                    break  # A JS route hint is optional until a real owner control succeeds.
            if external is not None:
                policy_controls.append((item, recipe, external, session.id, identity.id))
            created += 1
            if created >= 2:
                break
        if created:
            self._learn_fixture_tenant_policy(package, run, learner,
                                              tuple(policy_controls), since)
            self.runtime.api.profile(package, limits=APIAnalysisLimits(
                traffic=100, js_assets=30, recon_surfaces=12))
            self.runtime.api.generate(package, limits=APIAnalysisLimits(
                traffic=1, js_assets=1, recon_surfaces=1, candidates=12),
                mode="PLAN_ONLY")
        return run

    def _learn_fixture_tenant_policy(self, package: TargetPackage, run: HuntRun,
                                     learner: ObservedRecipeLearner,
                                     controls: tuple, since: datetime) -> None:
        if package.autonomy.cross_identity_testing is not PolicyDecision.ALLOW:
            return
        actors = []
        for account in package.accounts:
            identity = self.runtime.registry.get_identity(run.target_id, account.alias)
            if identity is None or identity.principal_state is not ObservationState.OBSERVED:
                continue
            session = self.runtime.browser.get_active_session(run.target_id, identity.id)
            if session is None or not self.runtime.burp.ready(session.id):
                continue
            tenants = {membership.tenant_id for membership in
                       self.runtime.registry.list_memberships(identity.id, limit=12).items
                       if membership.observation_state is ObservationState.OBSERVED}
            if tenants:
                actors.append((identity.id, session.id, tenants))
        for item, recipe, external, owner_session, owner_id in controls:
            subject = hashlib.sha256(external.encode()).hexdigest()
            if any(fact.object == "TENANT_ONLY" and fact.target_ref == run.target_id
                   for fact in self.runtime.store.find_facts(
                       subject, "access_policy", limit=8).items):
                continue
            peer = next(((session, identity) for identity, session, tenants in actors
                         if identity != owner_id and item.tenant_id in tenants), None)
            foreign = next(((session, identity) for identity, session, tenants in actors
                            if item.tenant_id not in tenants), None)
            if peer is None or foreign is None:
                continue
            try:
                url = recipe.verify.template(
                    test_name=item.test_name, object_id=external).url
                for label, (session_id, identity_id) in (
                        ("peer", peer), ("foreign", foreign)):
                    if learner.captured_read(package, session_id, identity_id,
                                             url, since) is not None:
                        continue
                    self.runtime.browser_navigation.navigate(
                        package, session_id, url,
                        experiment_id=f"{run.id}:policy:{item.id}:{label}",
                        request_cap=1, total_request_budget=1)
                learner.record_tenant_private_control(
                    package, item, recipe, external, item.tenant_id,
                    owner=(owner_session, owner_id), same_tenant=peer,
                    foreign=foreign, since=since)
            except (BrowserNavigationError, ValueError, PermissionError):
                continue
            break  # One independently controlled tenant boundary is enough for this pass.

    def handoff_ready(self, package: TargetPackage, hunt_id: str) -> HuntRun:
        """Create and link one existing-architecture campaign after preparation."""
        run = self.store.get(package.target.id, hunt_id)
        if run is None or run.package_id != package.id:
            raise LookupError("Hunt not found")
        if run.state is not HuntState.READY:
            return run
        if (run.package_version != package.version or
                run.policy_hash != policy_version(package)):
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "PACKAGE_POLICY_CHANGED")
        if package.accounts and run.mode is not HuntMode.PLAN_ONLY and run.reason_code not in {
                "MAPPING_COMPLETE", "MAPPING_PARTIAL"}:
            return run
        if run.mode is HuntMode.ADVANCED:
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "ADVANCED_CAMPAIGN_CONFIGURATION_REQUIRED")
        if run.campaign_id is not None:
            campaign = self.runtime.campaign.store.get(run.target_id, run.campaign_id)
            if (campaign is None or campaign.package_id != run.package_id or
                    campaign.package_version != run.package_version or
                    campaign.policy_hash != run.policy_hash):
                return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                             "CAMPAIGN_LINK_UNAVAILABLE")
            if campaign.status not in {CampaignStatus.CREATED,
                                       CampaignStatus.ASSESSING_READINESS,
                                       CampaignStatus.RUNNING}:
                return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                             "CAMPAIGN_REVIEW_REQUIRED")
            return self.store.transition(run.target_id, run.id, HuntState.HUNTING,
                                         "CAMPAIGN_RECONCILED")

        run = self.store.transition(run.target_id, run.id, HuntState.HUNTING,
                                    "CAMPAIGN_STARTING")
        mode = (PlannerMode.PLAN_ONLY if run.mode is HuntMode.PLAN_ONLY else
                PlannerMode.BOUNDED_AUTONOMOUS)
        try:
            campaign = self.runtime.campaign.start(
                package, mode=mode,
                limits=CampaignLimits.preset(
                    CampaignPreset.STANDARD if run.mode is HuntMode.PLAN_ONLY
                    else CampaignPreset.HUNT),
                requested_by=run.requested_by)
            return self.store.link_campaign(run.target_id, run.id, campaign.id)
        except ResourceError:
            return self.store.transition(run.target_id, run.id,
                                         HuntState.PAUSED_RESOURCE_PRESSURE,
                                         "CAMPAIGN_CAPACITY_UNAVAILABLE")
        except (LookupError, ValueError):
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "CAMPAIGN_START_UNCONFIRMED")

    def sync_campaign(self, package: TargetPackage, campaign_id: str) -> HuntRun | None:
        """Reflect a settled campaign state without weakening its own audit trail."""
        run = self.store.for_campaign(package.target.id, campaign_id)
        if run is None or run.package_id != package.id or run.state is not HuntState.HUNTING:
            return run
        campaign = self.runtime.campaign.store.get(run.target_id, campaign_id)
        if campaign is None:
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "CAMPAIGN_LINK_UNAVAILABLE")
        if campaign.status in {CampaignStatus.COMPLETED, CampaignStatus.CANCELLED}:
            cleanup = self._cleanup_fixtures(package, run)
            if cleanup != "CLEANED":
                return self.store.transition(run.target_id, run.id,
                                             HuntState.WAITING_HUMAN, cleanup)
            return self.store.transition(run.target_id, run.id, HuntState.COMPLETE,
                                         "CAMPAIGN_" + campaign.status.value)
        if campaign.status is CampaignStatus.WAITING_APPROVAL:
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_APPROVAL,
                                         "CAMPAIGN_APPROVAL_REQUIRED")
        if campaign.status is CampaignStatus.WAITING_LOGIN:
            return self.store.transition(run.target_id, run.id, HuntState.LOGIN_REQUIRED,
                                         "CAMPAIGN_LOGIN_REQUIRED")
        if (campaign.status is CampaignStatus.PAUSED and
                campaign.readiness_code in RECOVERABLE_CAMPAIGN_PAUSE_REASONS):
            return self.store.transition(run.target_id, run.id,
                                         HuntState.PAUSED_RESOURCE_PRESSURE,
                                         "CAMPAIGN_RESOURCE_PRESSURE")
        if campaign.status in {CampaignStatus.WAITING_HUMAN, CampaignStatus.PAUSED,
                               CampaignStatus.BLOCKED, CampaignStatus.FAILED,
                               CampaignStatus.CLEANUP_REQUIRED,
                               CampaignStatus.BUDGET_EXHAUSTED,
                               CampaignStatus.TIME_EXHAUSTED}:
            return self.store.transition(run.target_id, run.id, HuntState.WAITING_HUMAN,
                                         "CAMPAIGN_REVIEW_REQUIRED")
        return run

    def _cleanup_fixtures(self, package: TargetPackage, run: HuntRun) -> str:
        """Finish only hunt-owned disposable cleanup; never infer remote deletion."""
        for row in self.store.fixtures(run.target_id, run.id):
            item = self.runtime.objects.get(row["test_object_id"], run.target_id)
            if item is None or item.package_id != package.id:
                return "FIXTURE_BINDING_CONFLICT"
            if item.state is ObjectState.CLEANED:
                continue
            if item.state is ObjectState.PLANNED:
                continue  # A local intent never dispatched a create request.
            session = self.runtime.browser.get_active_session(
                run.target_id, item.creator_identity_id)
            if session is None or not self.runtime.burp.ready(session.id):
                return "FIXTURE_CLEANUP_LOGIN_REQUIRED"
            if item.state in {ObjectState.READY, ObjectState.CLEANUP_PENDING}:
                try:
                    result = self.runtime.object_factory.cleanup(
                        item.id, run.target_id, session_id=session.id)
                except (ValueError, LookupError):
                    return "FIXTURE_CLEANUP_REVIEW_REQUIRED"
            elif item.state is ObjectState.CLEANING:
                try:
                    result = self.runtime.object_factory.verify_cleanup(
                        item.id, run.target_id, session_id=session.id)
                except (ValueError, LookupError):
                    return "FIXTURE_CLEANUP_REVIEW_REQUIRED"
            else:
                return "FIXTURE_CLEANUP_REVIEW_REQUIRED"
            if result.outcome != "CLEANED":
                return "FIXTURE_CLEANUP_REVIEW_REQUIRED"
        return "CLEANED"

    def needs_you(self, package: TargetPackage, hunt_id: str) -> tuple[dict[str, str], ...]:
        run = self.store.get(package.target.id, hunt_id)
        if run is None or run.package_id != package.id:
            raise LookupError("Hunt not found")
        if run.state not in {HuntState.LOGIN_REQUIRED, HuntState.WAITING_HUMAN,
                             HuntState.WAITING_APPROVAL}:
            return ()
        items = []
        for account in package.accounts:
            identity = self.runtime.registry.get_identity(run.target_id, account.alias)
            session = (self.runtime.browser.get_session_for_identity(run.target_id, identity.id)
                       if identity else None)
            if session and session.status is BrowserStatus.WAITING_LOGIN:
                items.append({"kind": "LOGIN_REQUIRED", "alias": account.alias,
                              "session_id": session.id})
            elif session and session.status is BrowserStatus.NEEDS_MANUAL_REVIEW:
                items.append({"kind": "CONFIRM_IDENTITY", "alias": account.alias,
                              "session_id": session.id})
        if run.state is HuntState.WAITING_APPROVAL:
            items.append({"kind": "APPROVAL_REQUIRED", "reason_code":
                          run.reason_code or "ACTION_APPROVAL_REQUIRED"})
        elif run.state is HuntState.WAITING_HUMAN and not items:
            items.append({"kind": "HUMAN_REVIEW", "reason_code":
                          run.reason_code or "HUMAN_REVIEW_REQUIRED"})
        return tuple(items)
