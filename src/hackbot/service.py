"""Private, single-process BugHunter control plane and explicit plan-step owner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import socket
import time
import uuid
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Any, Callable
from urllib.parse import urlsplit

from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

from . import __version__
from .auth import AuthContextManager, AuthMechanism
from .backup import BackupError, BackupManager
from .authorization import AuthorizationSpecialist
from .authorization_store import AuthorizationMode, AuthorizationStore, HuntStatus
from .api_registry import APIOperationRegistry
from .api_specialist import APIAnalysisLimits, APISpecialist
from .browser import (BrowserError, BrowserSession, BrowserSessionManager,
                      BrowserStatus, IdentityVerificationRule)
from .browser_playwright import PlaywrightBrowserDriver
from .bootstrap import TargetBootstrapper
from .bootstrap_store import (BootstrapIdentityPolicy, BootstrapLimits, BootstrapStatus,
                              BootstrapStore)
from .behaviour import BehaviourStore, LearningLimits, LearningStatus, NormalBehaviourLearner
from .burp import BurpError, BurpExecutionProxyAdapter, BurpProxyProvider
from .burp_storage import inspect_burp_storage
from .burp_bridge import BurpBridgeServer, BurpCaptureProvider
from .campaign import CampaignCoordinator
from .campaign_models import (CampaignLimits, CampaignPreset, CampaignStatus,
                              TERMINAL_CAMPAIGN_STATUSES)
from .delta_coordinator import DeltaCoordinator
from .delta_models import ContinuousSettings, DeltaCadence, DeltaStatus
from .delta_scheduler import DeltaScheduler
from .config import (AppConfig, ConfigError, ExecutorSettings, NotificationSettings,
                     ObjectSettings, ResourceSettings, load_config)
from .domxss import DOMXSSSpecialist
from .domxss_browser import DOMBrowserExperimentExecutor
from .domxss_store import DOMXSSStore
from .exposure import ExposureSpecialist
from .exposure_models import ExposureCategory, ExposureStatus
from .exposure_store import ExposureStore
from .postmessage import PostMessageSpecialist
from .postmessage_browser import PostMessageBrowserExperimentExecutor
from .postmessage_store import PostMessageStore
from .process_health import inspect_owned_processes
from .profile_retention import BrowserProfileCollector, ProfileRetentionPolicy
from .executor import TrafficExecutor
from .hypotheses import ContextPacketBuilder, HypothesisGenerator, HypothesisStore
from .identity_registry import IdentityRegistry
from .finding_workflow import FindingWorkflow
from .logging import SecretRedactor, create_logger
from .maintenance import MaintenanceCoordinator, MaintenanceError
from .notification_store import NotificationPriority, NotificationStore, NotificationType
from .notifications import ConsoleNotifier, DiscordNotifier, NotificationManager, SMTPNotifier
from .policy import PolicyEngine, policy_version
from .policy_models import ActionCategory, ActorMode, ApprovalStatus, ProposedAction, SideEffect
from .policy_store import PolicyStore
from .permit_store import PolicyPermitStore
from .plan_runs import PlanRunStore, RunStatus
from .planner import CrossSpecialistPlanner
from .planner_context import PlannerContextBuilder
from .planner_models import (CandidateOverride, CandidateStatus, PlannerLimits,
                             PlannerMode, PlannerStatus, PlannerTaskStatus, Specialist)
from .planner_runner import PlannerRunner
from .planner_store import MAX_RUN_TASKS, PlannerStore
from .orchestrator import PlanOrchestrator
from .object_factory import ObjectFactory
from .mutation_results import MutationResultStore
from .mutation_results import value_hash
from .object_recipes import RecipeCatalog
from .typed_mutations import MutationPhase, TypedMutation
from .test_objects import ObjectRegistry, ObjectState
from .profile import AttackSurfaceProfiler
from .rate_limit import RateLimiter
from .research import ResearchBudget, ResearchCoordinator, ResearchStatus, ResearchStore
from .research_sources import BraveWebResearchProvider, FindingKnowledgeProvider, SkillKnowledgeProvider
from .retention import ArtifactGarbageCollector, OrphanPolicy
from .reports import ReportGenerator, ReportStore
from .resources import ResourceBudgetManager, ResourceError, ResourceSnapshot, WorkKind
from .recon_postgres import PostgresReconRepository
from .secrets import RoutedSecretProvider
from .skills import SkillRegistry
from .skill_plans import (DOMPlanBinding, MessagePlanBinding, PrerequisiteChecker, SkillContextBuilder,
                          SkillPlanStore, SkillPlanner, SkillRouter)
from .store import EvidenceFactStore, StoreNotInitialized, StoreSchemaError, _SCHEMA_VERSION
from .artifacts import ArtifactStore
from .target_loader import TargetPackageRepository
from .target_package import PackageStatus, TargetPackage
from .target_policy import RiskLevel
from .traffic import TrafficRetentionPolicy, TrafficStore
from .validation_store import FindingStatus, ValidationStatus, ValidationStore
from .validator import DeterministicValidatorEngine, ValidatorRegistry


_AUDIT_EVENTS = frozenset({
    "target_registered", "identities_imported", "auth_prepared", "browser_created",
    "browser_start_requested", "browser_started", "manual_login_completed",
    "identity_verification_finished", "browser_stopped", "browser_reconciled",
    "validation_started", "validation_confirmed", "validation_rejected",
    "validation_review_required", "validation_insufficient", "validation_duplicate",
    "finding_created",
})


@dataclass(frozen=True, slots=True)
class PageRequest:
    limit: int
    cursor: str | None

    @classmethod
    def parse(cls, *, maximum: int = 50) -> PageRequest:
        raw = request.args.get("limit", "20")
        if not raw.isdecimal():
            raise ValueError("invalid pagination")
        limit = int(raw)
        if not 1 <= limit <= maximum:
            raise ValueError("invalid pagination")
        cursor = request.args.get("cursor") or None
        if cursor is not None and (len(cursor) > 512 or any(ord(ch) < 32 for ch in cursor)):
            raise ValueError("invalid pagination")
        return cls(limit, cursor)


class BugHunterRuntime:
    """One trusted process owns all in-memory browser handles."""

    def __init__(self, config: AppConfig, *, driver: Any | None = None,
                 vnc_ready: Callable[[], bool] | None = None) -> None:
        self.config = config
        self.started_monotonic = time.monotonic()
        self.resources = ResourceBudgetManager(config.paths.root,
                                               config.resources or ResourceSettings(),
                                               system_disk_path=Path("/"))
        if self.resources.settings.required_mount is not None:
            self.resources.snapshot()
            artifact_root = (config.store.artifact_root if config.store is not None
                             else config.paths.evidence)
            try:
                mount = Path(self.resources.settings.required_mount).resolve(strict=True)
                on_mount = artifact_root.resolve().is_relative_to(mount)
            except OSError:
                on_mount = False
            if not on_mount:
                raise ResourceError("ARTIFACT_STORAGE_OUTSIDE_REQUIRED_MOUNT")
        self.store = EvidenceFactStore.from_config(config)
        self.store.initialize(allow_existing_migration=False)
        self.store.artifacts.prepare()
        self.registry = IdentityRegistry(self.store)
        self.auth = AuthContextManager(self.registry, RoutedSecretProvider(config.secrets))
        self.driver = driver or PlaywrightBrowserDriver(config.browser.chromium_executable)
        self.browser = BrowserSessionManager(self.registry, self.auth, self.driver, config.browser)
        self.maintenance = MaintenanceCoordinator(
            config.paths.state / "maintenance.json", BackupManager.from_config(config),
            ArtifactGarbageCollector(
                self.store,
                OrphanPolicy(config.retention.orphan_grace_hours,
                             config.retention.max_scan_entries,
                             config.retention.max_delete_files,
                             config.retention.orphan_scan_timeout_seconds),
                config.paths.logs / "retention-audit.jsonl",
            ),
            BrowserProfileCollector(
                self.browser,
                ProfileRetentionPolicy(
                    config.retention.anonymous_profile_grace_hours,
                    config.retention.max_profile_scan,
                    config.retention.max_profile_delete,
                    disabled_identity_grace_hours=
                        config.retention.disabled_identity_profile_grace_hours,
                    active_identity_grace_hours=
                        config.retention.active_identity_profile_grace_hours),
                self._profile_process_safe,
                config.paths.logs / "profile-retention-audit.jsonl",
            ),
        )
        self.traffic = TrafficStore(
            self.store, self.registry,
            retention_policy=(TrafficRetentionPolicy.from_settings(config.retention)
                              if config.retention is not None else None),
        )
        self.burp = BurpProxyProvider(config.burp, self.traffic, self.browser)
        self._burp_bridge_lock = Lock()
        self._burp_bridge: BurpBridgeServer | None = None
        self._burp_bridge_target: str | None = None
        self._burp_bridge_thread: Thread | None = None
        self.targets = TargetPackageRepository(config.targets.root)
        self.hypotheses = HypothesisStore(self.store)
        self.domxss_store = DOMXSSStore(
            self.store, js_retention_hours=config.retention.js_artifact_hours,
            source_map_retention_hours=config.retention.source_map_hours)
        self.bootstrap_store = BootstrapStore(self.store)
        self.behaviour_store = BehaviourStore(self.store)
        self.exposure_store = ExposureStore(self.store)
        self.api_operations = APIOperationRegistry(self.store)
        self.postmessage_store = PostMessageStore(self.store, self.domxss_store)
        self.skills = SkillRegistry(config.skills.root if config.skills else Path(__file__).resolve().parent / "skill_catalog")
        self.research_store = ResearchStore(self.store)
        self.research_store.reconcile_interrupted()
        web_research = None
        if config.research and config.research.enabled and config.research.search_secret_ref:
            web_research = BraveWebResearchProvider(
                self.auth.secrets, config.research.search_secret_ref,
                allowed_hosts=config.research.allowed_source_hosts,
                forbidden_host=self._is_target_host)
        self.research = ResearchCoordinator(
            self.research_store,
            local_providers=(SkillKnowledgeProvider(self.skills), FindingKnowledgeProvider(self.store)),
            web_provider=web_research,
            skill_names=tuple(item.name for item in self.skills.discover()))
        self._research_threads: dict[str, Thread] = {}
        self._research_lock = Lock()
        self.skill_checker = PrerequisiteChecker()
        self.skill_plans = SkillPlanStore(self.store)
        self.skill_router = SkillRouter(self.skills, self.skill_checker,
                                        self.skill_plans.outcome_counts)
        self.policy_store = PolicyStore(self.store)
        self.rate = RateLimiter()
        self.policy = PolicyEngine(registry=self.registry, browser=self.browser,
                                   audit=self.policy_store, rate=self.rate)
        self.objects = ObjectRegistry(self.store)
        self.policy.owned_object = self.objects.owned_for_action
        self.skill_planner = SkillPlanner(self.skills, self.skill_checker, self.policy,
                                         self.skill_plans, self.domxss_store,
                                         self.postmessage_store, self.objects,
                                         self.exposure_store)
        self.permits = PolicyPermitStore(self.store)
        self.executor = TrafficExecutor(
            targets=self.targets, policy=self.policy, permits=self.permits,
            rate=self.rate, traffic=self.traffic, auth=self.auth,
            secrets=self.auth.secrets, settings=config.executor or ExecutorSettings(),
            proxy=BurpExecutionProxyAdapter(self.burp), browser=self.browser,
            retention=config.retention,
        )
        self.recon = None
        self._recon_probe_lock = Lock()
        self._recon_probe_until = 0.0
        self._recon_probe_state = "UNKNOWN"
        try:
            self.recon = PostgresReconRepository.from_config(config)
        except ConfigError:
            pass  # Local-only service stays usable; profile records the recon gap.
        self.exposure = ExposureSpecialist(dom=self.domxss_store, store=self.exposure_store,
                                           recon=self.recon, traffic=self.traffic,
                                           behaviour=self.behaviour_store)
        self.bootstrap = TargetBootstrapper(
            targets=self.targets, recon=self.recon, ledger=self.bootstrap_store,
            evidence=self.store, traffic=self.traffic, browser=self.browser,
            driver=self.driver, executor=self.executor, js=self.domxss_store,
            postmessage=self.postmessage_store, exposure=self.exposure,
            profiles=self.hypotheses, registry=self.registry)
        self._bootstrap_threads: dict[str, Thread] = {}
        self.skill_context = SkillContextBuilder(self.store, self.registry, self.traffic,
                                                 self.browser, self.recon, self.objects,
                                                 self.domxss_store, self.postmessage_store,
                                                 self.exposure_store)
        self.domxss = (DOMXSSSpecialist(recon=self.recon, targets=self.targets,
                                       executor=self.executor, store=self.domxss_store)
                       if self.recon is not None else None)
        self.postmessage = (PostMessageSpecialist(dom=self.domxss, targets=self.targets,
                                                  store=self.postmessage_store)
                            if self.domxss is not None else None)
        self.run_store = PlanRunStore(self.store)
        self.domxss_browser = DOMBrowserExperimentExecutor(
            targets=self.targets, store=self.domxss_store, browser=self.browser,
            driver=self.driver, policy=self.policy, runs=self.run_store,
            evidence=self.store)
        self.postmessage_browser = PostMessageBrowserExperimentExecutor(
            targets=self.targets, store=self.postmessage_store, browser=self.browser,
            driver=self.driver, policy=self.policy, runs=self.run_store,
            evidence=self.store, objects=self.objects)
        object_settings = config.objects or ObjectSettings(config.paths.root / "recipes")
        self.object_factory = ObjectFactory(
            objects=self.objects, recipes=RecipeCatalog(object_settings), policy=self.policy,
            executor=self.executor, targets=self.targets, traffic=self.traffic,
            settings=object_settings)
        self.behaviour = NormalBehaviourLearner(
            self.behaviour_store, self.traffic, self.registry, self.browser,
            self.objects, self.store, self.recon)
        self._behaviour_threads: dict[str, Thread] = {}
        self.mutation_results = MutationResultStore(self.store)
        self.validations = ValidationStore(self.store)
        self.workflow = FindingWorkflow(self.store, self.validations)
        self.notification_store = NotificationStore(self.store)
        self.report_store = ReportStore(
            self.store, ArtifactStore(
                config.paths.artifacts / "reports",
                max_blob_bytes=(config.resources.max_artifact_bytes
                                if config.resources else 134_217_728)))
        self.report_generator = ReportGenerator(
            store=self.store, drafts=self.report_store, validations=self.validations,
            runs=self.run_store, traffic=self.traffic, targets=self.targets,
            objects=self.objects, dom=self.domxss_store, messages=self.postmessage_store,
            exposure=self.exposure_store, api=self.api_operations)
        self.validator_registry = ValidatorRegistry()
        self.validator = DeterministicValidatorEngine(
            runs=self.run_store, traffic=self.traffic, evidence=self.store,
            identities=self.registry, hypotheses=self.hypotheses,
            results=self.validations, registry=self.validator_registry,
            dom=self.domxss_store, messages=self.postmessage_store,
            targets=self.targets, exposure=self.exposure,
            api_operations=self.api_operations)
        self.orchestrator = PlanOrchestrator(
            runs=self.run_store, targets=self.targets, hypotheses=self.hypotheses,
            context=self.skill_context, checker=self.skill_checker, registry=self.skills,
            policy=self.policy, approvals=self.policy_store, executor=self.executor,
            traffic=self.traffic, evidence=self.store, objects=self.objects,
            recipes=self.object_factory.recipes, mutations=self.mutation_results,
            dom=self.domxss_browser, messages=self.postmessage_browser,
            exposure=self.exposure, api_operations=self.api_operations)
        self.authorization_ledger = AuthorizationStore(self.store)
        self.authorization = AuthorizationSpecialist(
            identities=self.registry, browser=self.browser, objects=self.objects,
            traffic=self.traffic, evidence=self.store, hypotheses=self.hypotheses,
            ledger=self.authorization_ledger, recon=self.recon, context=self.skill_context,
            router=self.skill_router, planner=self.skill_planner,
            orchestrator=self.orchestrator, validator=self.validator,
            factory=self.object_factory, behaviour=self.behaviour_store)
        self.api = APISpecialist(
            registry=self.api_operations, traffic=self.traffic, evidence=self.store,
            js=self.domxss_store, behaviour=self.behaviour_store,
            recon=self.recon, authorization=self.authorization)
        self.planner_store = PlannerStore(self.store)
        self.planner_context = PlannerContextBuilder(
            hypotheses=self.hypotheses, behaviour=self.behaviour_store,
            bootstrap=self.bootstrap_store, identities=self.registry,
            browser=self.browser, objects=self.objects, traffic=self.traffic,
            research=self.research_store, validations=self.validations, recon=self.recon)
        self.planner = CrossSpecialistPlanner(
            store=self.planner_store, context=self.planner_context,
            hypotheses=self.hypotheses, authorization=self.authorization_ledger,
            api=self.api_operations, dom=self.domxss_store,
            messages=self.postmessage_store, exposure=self.exposure_store,
            traffic=self.traffic, validations=self.validations,
            skill_context=self.skill_context, skill_router=self.skill_router)
        self.planner_runner = PlannerRunner(
            planner=self.planner, store=self.planner_store,
            hypotheses=self.hypotheses, contexts=self.skill_context,
            router=self.skill_router, skill_planner=self.skill_planner,
            authorization=self.authorization, api=self.api,
            dom=self.domxss, messages=self.postmessage, exposure=self.exposure,
            research=self.research, objects=self.objects, object_factory=self.object_factory,
            browser=self.browser, orchestrator=self.orchestrator, validator=self.validator)
        self._planner_lock = Lock()
        self._planner_threads: dict[str, Thread] = {}
        self.campaign = CampaignCoordinator(self)
        self._campaign_lock = Lock()
        self._campaign_threads: dict[str, Thread] = {}
        self.delta = DeltaCoordinator(self)
        self.delta_scheduler = DeltaScheduler(self, self.delta)
        self.logger = create_logger(level=config.log_level)
        notification_settings = config.notifications or NotificationSettings()
        providers = []
        if notification_settings.discord_secret_ref:
            providers.append(DiscordNotifier(self.auth.secrets,
                                             notification_settings.discord_secret_ref))
        if notification_settings.smtp_host:
            providers.append(SMTPNotifier(notification_settings, self.auth.secrets))
        if notification_settings.console_enabled:
            providers.append(ConsoleNotifier(self.logger))
        self.notifications = NotificationManager(
            self.notification_store, self.validations, self.run_store, self.traffic,
            notification_settings, tuple(providers))
        self.notification_store.reconcile_inflight()
        self._notification_wakeup = Event()
        self._notification_thread: Thread | None = None
        self._vnc_ready = vnc_ready or self._probe_vnc
        while self.objects.reconcile():
            pass
        self.reconcile_on_startup()
        self.bootstrap_store.reconcile()
        self.behaviour_store.reconcile()
        while self.run_store.reconcile():
            pass
        while self.mutation_results.reconcile():
            pass
        while self.authorization_ledger.reconcile_runs():
            pass
        self.planner_store.reconcile_interrupted()
        cursor = ""
        while True:
            recoverable = self.planner_store.restartable(after_run_id=cursor)
            if not recoverable:
                break
            for run in recoverable:
                try:
                    package = self.package(run.package_id)
                    self.planner_runner._current(package, run)
                    ambiguous = {task.candidate_id for task in self.planner_store.tasks(
                        run.target_id, run.id, limit=MAX_RUN_TASKS)
                        if task.status is PlannerTaskStatus.WAITING
                        and task.reason_code == "AMBIGUOUS_RESTART"}
                    for candidate in self.planner_store.candidates(
                            run.target_id, run.id, limit=run.limits.portfolio):
                        if candidate.status in {CandidateStatus.SELECTED,
                                                CandidateStatus.NEEDS_REFRESH} and candidate.id not in ambiguous:
                            self.planner.build_tasks(run, candidate)
                    current = self.planner_store.get(run.target_id, run.id)
                    if current and current.status is PlannerStatus.READY:
                        self.planner_store.transition(
                            run.target_id, run.id, PlannerStatus.PAUSED,
                            "RECOVERY_OPERATOR_RESUME_REQUIRED",
                            expected=(PlannerStatus.READY,))
                except (LookupError, ValueError):
                    self.planner_store.transition(run.target_id, run.id,
                                                  PlannerStatus.PAUSED,
                                                  "RECOVERY_PREREQUISITE_CHANGED")
            cursor = recoverable[-1].id
            if len(recoverable) < 50:
                break
        self.campaign.store.reconcile_interrupted()
        if providers:
            self._notification_thread = Thread(target=self._notification_work, daemon=True,
                                               name="bughunter-notifications")
            self._notification_thread.start()
            self._notification_wakeup.set()

    def _notification_work(self) -> None:
        while True:
            self._notification_wakeup.wait(timeout=15)
            self._notification_wakeup.clear()
            try:
                self.notifications.process(max_messages=20)
            except Exception:
                self.logger.error("notification_worker_failed")

    def record_planner_notification(self, target_id: str, run_id: str,
                                    result: dict[str, object]) -> None:
        run = result.get("run")
        task = result.get("task")
        if not isinstance(run, dict) or run.get("id") != run_id:
            return
        reason = task.get("reason_code") if isinstance(task, dict) else result.get("reason")
        try:
            if run.get("status") == "WAITING_LOGIN" and reason == "LOGIN_REQUIRED":
                self.notification_store.enqueue(
                    target_id=target_id, event_type=NotificationType.AUTH_REQUIRES_LOGIN,
                    source_kind="PLANNER", source_id=run_id,
                    priority=NotificationPriority.NORMAL)
                self._notification_wakeup.set()
            if run.get("status") == "COMPLETED" and any(
                    item.finding_id and self.validations.get_finding(item.finding_id, target_id)
                    for item in self.planner_store.candidates(target_id, run_id, limit=200)):
                self.notification_store.enqueue(
                    target_id=target_id,
                    event_type=NotificationType.PLANNER_COMPLETED_WITH_FINDINGS,
                    source_kind="PLANNER", source_id=run_id,
                    priority=NotificationPriority.NORMAL)
                self._notification_wakeup.set()
        except (LookupError, ValueError, OSError):
            self.logger.error("planner_notification_record_failed")

    def launch_planner(self, package_id: str, run_id: str) -> None:
        with self._planner_lock:
            existing = self._planner_threads.get(run_id)
            if existing and existing.is_alive():
                return
            self.resources.admit(WorkKind.PLANNER,
                                 active=sum(thread.is_alive() for thread in self._planner_threads.values()))
            thread = Thread(target=self._planner_work, args=(package_id, run_id), daemon=True,
                            name="planner-" + run_id[-8:])
            self._planner_threads[run_id] = thread
            thread.start()

    def _planner_work(self, package_id: str, run_id: str) -> None:
        try:
            for _ in range(MAX_RUN_TASKS * 8):
                with self._planner_lock:
                    package = self.package(package_id)
                    self.resources.admit(WorkKind.PLANNER, active=0)
                    result = self.planner_runner.advance(package, run_id)
                    self.record_planner_notification(package.target.id, run_id, result)
                if result["run"]["status"] not in {"READY", "RUNNING"} or result["task"] is None:
                    break
            else:
                with self._planner_lock:
                    run = self.planner_store.get(self.package(package_id).target.id, run_id)
                    if run and run.status in {PlannerStatus.READY, PlannerStatus.RUNNING}:
                        self.planner_runner.pause(self.package(package_id), run_id)
                self.logger.warning("planner_step_limit_reached")
        except Exception:
            self.logger.error("planner_worker_failed")
            with self._planner_lock:
                try:
                    package = self.package(package_id)
                    run = self.planner_store.get(package.target.id, run_id)
                    if run and run.status in {PlannerStatus.READY, PlannerStatus.RUNNING}:
                        self.planner_runner.pause(package, run_id)
                except Exception:
                    pass
        finally:
            with self._planner_lock:
                self._planner_threads.pop(run_id, None)

    def launch_campaign(self, package_id: str, campaign_id: str) -> None:
        with self._campaign_lock:
            existing = self._campaign_threads.get(campaign_id)
            if existing and existing.is_alive():
                return
            self.resources.admit(
                WorkKind.CAMPAIGN,
                active=sum(thread.is_alive() for key, thread in
                           self._campaign_threads.items() if key != campaign_id))
            thread = Thread(target=self._campaign_work,
                            args=(package_id, campaign_id), daemon=True,
                            name="campaign-" + campaign_id[-8:])
            self._campaign_threads[campaign_id] = thread
            thread.start()

    def _campaign_work(self, package_id: str, campaign_id: str) -> None:
        try:
            for _ in range(MAX_RUN_TASKS * 8):
                with self._campaign_lock:
                    package = self.package(package_id)
                    campaign = self.campaign.advance(package, campaign_id)
                if campaign.status not in {CampaignStatus.CREATED,
                                           CampaignStatus.ASSESSING_READINESS,
                                           CampaignStatus.RUNNING}:
                    break
            else:
                with self._campaign_lock:
                    package = self.package(package_id)
                    campaign = self.campaign.store.get(package.target.id, campaign_id)
                    if campaign and campaign.status is CampaignStatus.RUNNING:
                        self.campaign.pause(package, campaign_id)
                self.logger.warning("campaign_step_limit_reached")
        except Exception:
            self.logger.error("campaign_worker_failed")
            with self._campaign_lock:
                try:
                    package = self.package(package_id)
                    campaign = self.campaign.store.get(package.target.id, campaign_id)
                    if campaign and campaign.status not in TERMINAL_CAMPAIGN_STATUSES:
                        self.campaign.store.transition(
                            campaign.target_id, campaign.id,
                            CampaignStatus.PAUSED, "WORKER_ERROR")
                except Exception:
                    self.logger.error("campaign_pause_failed")
        finally:
            with self._campaign_lock:
                self._campaign_threads.pop(campaign_id, None)

    def _probe_vnc(self) -> bool:
        if not self.config.browser.vnc_url:
            return False
        parsed = urlsplit(self.config.browser.vnc_url)
        try:
            with socket.create_connection(("127.0.0.1", parsed.port), timeout=0.2):
                return True
        except OSError:
            return False

    @staticmethod
    def _profile_process_safe() -> bool:
        status = inspect_owned_processes()
        return status.state == "OK" and not status.browser_pids and not status.agent_display_pids

    def reconcile_on_startup(self) -> int:
        """Fail closed after process restart; never reuse an unowned browser handle."""
        self.burp.reconcile_cold_start()
        changed = 0
        marker = ""
        while True:
            with self.store._connection() as connection:
                rows = connection.execute(
                    "SELECT session_id FROM browser_sessions WHERE session_id>? "
                    "AND status IN ('STARTING','RUNNING','WAITING_LOGIN','VERIFYING_IDENTITY',"
                    "'NEEDS_MANUAL_REVIEW','VALID') ORDER BY session_id LIMIT 100",
                    (marker,),
                ).fetchall()
            if not rows:
                break
            for row in rows:
                marker = row["session_id"]
                before = self.browser.get(marker)
                after = self.browser.reconcile_stale(marker)
                if before and before.status != after.status:
                    changed += 1
            if len(rows) < 100:
                break
        return changed

    def ensure_burp_bridge(self, package: TargetPackage) -> None:
        """Start one target-scoped, authenticated loopback bridge in this browser owner."""
        if not self.config.burp.enabled or self.config.burp.installation_jar is None:
            raise BurpError("Burp capture is not configured")
        if package.status is not PackageStatus.TRACKED:
            raise BurpError("Burp target is not active")
        with self._burp_bridge_lock:
            if self._burp_bridge is not None:
                if self._burp_bridge_target != package.target.id:
                    raise BurpError("Burp bridge is already assigned to another target")
                if self._burp_bridge_thread is None or not self._burp_bridge_thread.is_alive():
                    raise BurpError("Burp bridge is unavailable")
                return
            provider = BurpCaptureProvider(package, self.burp, self.traffic)
            server = BurpBridgeServer.from_secret_provider(self.config.burp, provider, self.auth.secrets)
            thread = Thread(target=server.serve_forever, name="hackbot-burp-bridge", daemon=True)
            thread.start()
            if not thread.is_alive():
                server.server_close()
                raise BurpError("Burp bridge failed to start")
            self._burp_bridge = server
            self._burp_bridge_target = package.target.id
            self._burp_bridge_thread = thread

    def close_burp_bridge(self) -> None:
        with self._burp_bridge_lock:
            server = self._burp_bridge
            thread = self._burp_bridge_thread
            self._burp_bridge = None
            self._burp_bridge_target = None
            self._burp_bridge_thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)

    def package(self, package_id: str) -> TargetPackage:
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise LookupError("target not found")
        return package

    def _is_target_host(self, host: str) -> bool:
        cursor = None
        for _ in range(10):
            page = self.targets.list_target_packages(limit=100, cursor=cursor)
            if any(host == package.target.root_domain or
                   host.endswith("." + package.target.root_domain) or any(
                rule.matches_host(host) for rule in package.scope.include_hosts
            ) for package in page.items):
                return True
            cursor = page.next_cursor
            if cursor is None:
                return False
        return True  # Fail closed when the package inventory exceeds the bound.

    def audit(self, event_type: str, *, target_id: str | None = None,
              identity_id: str | None = None, session_id: str | None = None) -> None:
        if event_type not in _AUDIT_EVENTS:
            raise ValueError("invalid activity event")
        at = datetime.now(timezone.utc).isoformat()
        with self.store._connection() as connection:
            connection.execute(
                "INSERT INTO service_events(occurred_at,event_type,target_id,identity_id,session_id) "
                "VALUES (?,?,?,?,?)", (at, event_type, target_id, identity_id, session_id),
            )
        self.logger.info(event_type, extra={"context": {
            "target_id": target_id, "identity_id": identity_id, "browser_ref": session_id,
        }})

    def activity(self, page: PageRequest) -> dict[str, object]:
        if page.cursor is not None and not page.cursor.isdecimal():
            raise ValueError("invalid activity cursor")
        sql = "SELECT id,occurred_at,event_type,target_id,identity_id,session_id FROM service_events"
        params: list[object] = []
        if page.cursor:
            sql += " WHERE id<?"
            params.append(int(page.cursor))
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(page.limit + 1)
        with self.store._connection() as connection:
            rows = connection.execute(sql, params).fetchall()
        items = [dict(row) for row in rows[:page.limit]]
        return {"items": items, "next_cursor": str(items[-1]["id"]) if len(rows) > page.limit else None}

    def recon_health(self) -> str:
        if self.recon is None:
            return "DISCONNECTED"
        with self._recon_probe_lock:
            now = time.monotonic()
            if now >= self._recon_probe_until:
                try:
                    self._recon_probe_state = "OK" if self.recon.probe() else "FAILED"
                except Exception:
                    self._recon_probe_state = "DISCONNECTED"
                self._recon_probe_until = time.monotonic() + 30.0
            return self._recon_probe_state

    def health(self) -> dict[str, object]:
        try:
            with self.store._connection() as connection:
                connection.execute("SELECT 1").fetchone()
            store_state = "ok"
        except Exception:
            store_state = "failed"
        browser_installed = importlib.util.find_spec("playwright") is not None
        try:
            notifier = self.notifications.status()
            notifier_state = ("degraded" if notifier["delivery"]["failed"] > 0 or
                              notifier["delivery"]["needs_review"] > 0 or
                              notifier["delivery"].get("sending", 0) > 0 else
                              "configured" if self.notifications.providers else "disabled")
        except Exception:
            notifier_state = "failed"
        try:
            objects = self.objects.stats()
        except Exception:
            objects = {"cleanup_pending": None, "orphaned": None}
        try:
            resource = self.resources.snapshot()
            resource_state = resource.state
        except ResourceError:
            resource_state = "FAILED"
        recon_state = self.recon_health()
        recon_degraded = self.recon is not None and recon_state != "OK"
        degraded = (store_state != "ok" or notifier_state in {"degraded", "failed"} or
                    resource_state != "OK" or recon_degraded or
                    objects["cleanup_pending"] is None)
        return {"status": "degraded" if degraded else "ok", "version": __version__, "checks": {
            "bughunter_store": store_state,
            "browser_manager": "ready" if browser_installed else "dependency_missing",
            "vnc": "ready" if self._vnc_ready() else "not_running",
            "traffic_store": store_state, "orchestrator": "ready", "validator": "ready",
            "object_factory": "ready", "object_cleanup_pending": objects["cleanup_pending"],
            "object_orphans": objects["orphaned"],
            "burp": self.burp.availability().value,
            "notifier": notifier_state,
            "resources": resource_state,
            "recon": recon_state,
        }, "recon_integration": recon_state}

    def readiness(self) -> dict[str, object]:
        """Local readiness only; optional providers never make the control plane disappear."""
        checks: dict[str, object] = {}
        try:
            with self.store._connection() as connection:
                connection.execute("SELECT 1").fetchone()
                schema = connection.execute("PRAGMA user_version").fetchone()[0]
            checks["state_database"] = "OK" if schema == _SCHEMA_VERSION else "FAILED"
        except Exception:
            checks["state_database"] = "FAILED"
        checks["artifact_root"] = ("OK" if self.store.artifacts.root.is_dir() else "FAILED")
        try:
            resources = self.resources.snapshot()
            checks["resources"] = resources.state
        except ResourceError:
            checks["resources"] = "FAILED"
        checks["recon"] = self.recon_health() if self.recon is not None else "DISABLED"
        checks["burp"] = self.burp.availability().value
        essential_ok = checks["state_database"] == "OK" and checks["artifact_root"] == "OK"
        degraded = (checks["resources"] != "OK" or
                    checks["recon"] not in {"OK", "DISABLED"})
        return {"state": "NOT_READY" if not essential_ok else
                         "DEGRADED" if degraded else "READY",
                "checks": checks, "version": __version__}

    def overview(self) -> dict[str, object]:
        with self.store._connection() as connection:
            counts = {label: connection.execute(sql).fetchone()[0] for label, sql in {
                "identities": "SELECT count(*) FROM registry_identities",
                "browser_sessions": "SELECT count(*) FROM browser_sessions WHERE status NOT IN ('STOPPED','FAILED','EXPIRED')",
                "reauth_required": "SELECT count(*) FROM browser_sessions WHERE status='REAUTH_REQUIRED'",
                "traffic": "SELECT count(*) FROM traffic_exchanges",
            }.items()}
        count = 0
        cursor = None
        while count <= 1000:
            page = self.targets.list_target_packages(limit=100, cursor=cursor)
            count += len(page.items)
            cursor = page.next_cursor
            if cursor is None:
                break
        return {"targets": count, "targets_truncated": cursor is not None, **counts,
                "plan_runs": self.run_store.stats(), "validation": self.validations.stats(),
                "notifications": self.notifications.status(), "reports": self.report_store.stats(),
                "finding_outcomes": self.workflow.metrics(),
                "objects": self.objects.stats(),
                "burp": self.burp.availability().value, "activity": self.activity(PageRequest(8, None))["items"]}

    def operations(self) -> dict[str, object]:
        try:
            resource = self.resources.snapshot()
        except ResourceError as exc:
            resource = ResourceSnapshot(0, 0, 100, None, "BLOCKED", (exc.reason_code,))
        with self.store._connection() as db:
            schema = db.execute("PRAGMA user_version").fetchone()[0]
            counts = {label: db.execute(sql).fetchone()[0] for label, sql in {
                "evidence": "SELECT count(*) FROM evidence",
                "traffic": "SELECT count(*) FROM traffic_exchanges",
                "findings": "SELECT count(*) FROM findings",
                "report_drafts": "SELECT count(*) FROM report_drafts",
                "planner_active": "SELECT count(*) FROM planner_runs WHERE status NOT IN "
                                  "('COMPLETED','BLOCKED','FAILED','CANCELLED','BUDGET_EXHAUSTED')",
                "plan_active": "SELECT count(*) FROM plan_runs WHERE status NOT IN "
                               "('COMPLETED','REJECTED','FAILED','BUDGET_EXHAUSTED','CANCELLED')",
                "browser_active": "SELECT count(*) FROM browser_sessions WHERE status IN "
                                  "('STARTING','RUNNING','WAITING_LOGIN','VERIFYING_IDENTITY',"
                                  "'NEEDS_MANUAL_REVIEW','VALID')",
                "browser_reauth_required": "SELECT count(*) FROM browser_sessions "
                                           "WHERE status='REAUTH_REQUIRED'",
                "research_active": "SELECT count(*) FROM research_requests WHERE status IN "
                                   "('PENDING','RESEARCHING')",
                "confirmed_findings": "SELECT count(*) FROM findings WHERE status IN "
                                      "('CONFIRMED','READY_FOR_REPORT','SUBMITTED','TRIAGED','RESOLVED','REWARDED')",
            }.items()}
            artifact_stats = db.execute(
                "SELECT count(*),COALESCE(sum(content_size),0) FROM "
                "(SELECT artifact_hash,max(content_size) AS content_size FROM evidence "
                "WHERE artifact_hash IS NOT NULL GROUP BY artifact_hash)"
            ).fetchone()
            recent_research = db.execute(
                "SELECT external_allowed,status,error_code,usage_json,updated_at FROM research_requests "
                "WHERE status IN ('COMPLETED','PARTIAL','FAILED','BLOCKED') "
                "ORDER BY rowid DESC LIMIT 64"
            ).fetchall()
        database = self.store.db_path
        try:
            notifier = self.notifications.status()
        except Exception:
            notifier = {"configured_providers": [item.name for item in self.notifications.providers],
                        "discord_configured": any(item.name == "discord" for item in self.notifications.providers),
                        "smtp_configured": any(item.name == "smtp" for item in self.notifications.providers),
                        "manual_review_enabled": self.notifications.settings.manual_review_enabled,
                        "triage_enabled": self.notifications.settings.triage_enabled,
                        "delivery": {"events": None, "sent": None, "deduped": None,
                                     "pending": None, "sending": None,
                                     "failed": None, "needs_review": None}}
        try:
            burp = self.burp.status()
        except Exception:
            burp = {"availability": "UNKNOWN", "status": "BURP_UNAVAILABLE",
                    "bridge_connected": False, "configured_listeners": None,
                    "reachable_listeners": None, "target_id": None,
                    "proxy_listener_capacity": None, "proxy_listeners_reachable": None,
                    "installed_version": None, "captured_exchanges": None,
                    "last_capture_at": None, "dropped_events": None,
                    "last_heartbeat_at": None}
        burp_root = (self.config.burp.runtime_root
                     if self.config.burp and self.config.burp.enabled else None)
        burp_storage = (inspect_burp_storage(burp_root).to_dict()
                        if burp_root is not None else
                        {"state": "DISABLED" if not self.config.burp or
                         not self.config.burp.enabled else "UNAVAILABLE"})
        try:
            objects = self.objects.stats()
        except Exception:
            objects = {"cleanup_pending": None, "orphaned": None}
        active_count = getattr(self.driver, "active_session_count", None)
        if callable(active_count):
            counts["browser_active"] = active_count()
        processes = inspect_owned_processes(
            active_browser_sessions=active_count() if callable(active_count) else None).to_dict()
        try:
            backup = BackupManager.from_config(self.config).latest_metadata()
        except (BackupError, OSError):
            backup = {"state": "UNAVAILABLE", "backup_id": None, "age_hours": None,
                      "size_bytes": None, "keep_generations": None,
                      "verification": "NOT_CHECKED"}
        warnings = list(resource.warnings)
        if backup["state"] == "MISSING":
            warnings.append("BACKUP_MISSING")
        elif backup["state"] == "UNAVAILABLE" or backup["state"] == "INVALID_METADATA":
            warnings.append("BACKUP_UNAVAILABLE")
        elif backup["age_hours"] is not None and backup["age_hours"] > 48:
            warnings.append("STALE_BACKUP")
        if objects["orphaned"]:
            warnings.append("ORPHAN_OBJECTS")
        if objects["cleanup_pending"] is None or objects["orphaned"] is None:
            warnings.append("OBJECT_STATUS_UNAVAILABLE")
        if (notifier["delivery"]["failed"] is None or notifier["delivery"]["failed"] or
                notifier["delivery"]["needs_review"] or notifier["delivery"].get("sending", 0)):
            warnings.append("NOTIFIER_FAILURE")
        if self.config.burp and self.config.burp.enabled and burp["status"] in {
                "BURP_STOPPED", "BURP_UNAVAILABLE"}:
            warnings.append("BURP_DOWN")
        if self.config.burp and self.config.burp.enabled and burp_storage["state"] != "COMPLETE":
            warnings.append("BURP_STORAGE_INVENTORY_INCOMPLETE")
        if self.recon is None:
            warnings.append("RECON_DISCONNECTED")
        recon_state = self.recon_health()
        if self.recon is not None and recon_state != "OK":
            warnings.append("RECON_DISCONNECTED")
        browser_dependency = (getattr(self.driver, "name", None) != "PLAYWRIGHT" or
                              importlib.util.find_spec("playwright") is not None)
        try:
            vnc_available = self._vnc_ready()
        except Exception:
            vnc_available = False
        if not browser_dependency or not vnc_available:
            warnings.append("BROWSER_UNAVAILABLE")
        research_enabled = bool(self.config.research and self.config.research.enabled)
        external_configured = research_enabled and self.research.web_provider is not None
        external_attempts = []
        for row in recent_research:
            if not row["external_allowed"] or row["status"] in {"PENDING", "RESEARCHING"}:
                continue
            try:
                usage = json.loads(row["usage_json"])
                if isinstance(usage, dict) and type(usage.get("searches")) is int and usage["searches"] > 0:
                    external_attempts.append(row)
            except (TypeError, ValueError):
                continue
        last_external = max(external_attempts, key=lambda row: row["updated_at"], default=None)
        last_research = max(
            (row for row in recent_research if row["status"] in
             {"COMPLETED", "PARTIAL", "FAILED", "BLOCKED"}),
            key=lambda row: row["updated_at"], default=None)
        external_failed = bool(external_configured and last_external and
                               last_external["error_code"] in {
                                   "EXTERNAL_PROVIDER_UNAVAILABLE",
                                   "MULTIPLE_PROVIDERS_UNAVAILABLE"})
        local_failed = bool(self.research.local_providers and last_research and
                            last_research["error_code"] in {
                                "LOCAL_PROVIDER_UNAVAILABLE", "MULTIPLE_PROVIDERS_UNAVAILABLE"})
        legacy_provider_failed = bool(last_research and
                                      last_research["error_code"] == "PROVIDER_UNAVAILABLE")
        research_execution_failed = bool(last_research and last_research["error_code"] in {
            "RESEARCH_FAILED", "INTERRUPTED"})
        if external_failed or local_failed or legacy_provider_failed:
            warnings.append("RESEARCH_PROVIDER_UNAVAILABLE")
        if local_failed:
            warnings.append("RESEARCH_LOCAL_PROVIDER_UNAVAILABLE")
        if research_execution_failed:
            warnings.append("RESEARCH_EXECUTION_FAILURE")
        components = {
            "state_database": "OK" if schema == _SCHEMA_VERSION else "FAILED",
            "artifact_store": "OK" if self.store.artifacts.root.is_dir() and
            not any(code in resource.warnings for code in
                    ("STORAGE_UNAVAILABLE", "REQUIRED_MOUNT_UNAVAILABLE")) else "BLOCKED",
            "recon": "DISABLED" if self.recon is None else
                     "OK" if recon_state == "OK" else "DEGRADED",
            "burp": "DISABLED" if not self.config.burp or not self.config.burp.enabled else
                    "FAILED" if burp["status"] in {"BURP_UNAVAILABLE", "BURP_STOPPED"} else
                    "DEGRADED" if burp["status"] == "BRIDGE_DISCONNECTED" or
                    (burp["configured_listeners"] is not None and
                     burp["reachable_listeners"] is not None and
                     burp["reachable_listeners"] < burp["configured_listeners"]) else "OK",
            "burp_storage": "DISABLED" if not self.config.burp or not self.config.burp.enabled else
                            "OK" if burp_storage["state"] == "COMPLETE" else "DEGRADED",
            "browser_manager": "OK" if browser_dependency and vnc_available else "DEGRADED",
            "object_cleanup": "DEGRADED" if "OBJECT_STATUS_UNAVAILABLE" in warnings else "OK",
            "research": "DEGRADED" if external_failed or local_failed or legacy_provider_failed or
                        research_execution_failed else "OK",
            "research_local": "DISABLED" if not self.research.local_providers else
                              "UNVERIFIED" if last_research is None or
                              research_execution_failed or legacy_provider_failed else
                              "DEGRADED" if local_failed else "OK",
            "research_external": "DISABLED" if not external_configured else
                                 "UNVERIFIED" if last_external is None or
                                 last_external["error_code"] == "PROVIDER_UNAVAILABLE" else
                                 "DEGRADED" if external_failed else "OK",
            "notifier": "DEGRADED" if "NOTIFIER_FAILURE" in warnings else
                        "DISABLED" if not self.notifications.providers else "OK",
        }
        if processes["state"] == "UNKNOWN":
            warnings.append("PROCESS_INVENTORY_UNAVAILABLE")
        if processes["suspected_orphan_browser_pids"]:
            warnings.append("SUSPECTED_BROWSER_ORPHAN")
        if processes["suspected_orphan_display_pids"] or (
                not vnc_available and processes["vnc_display_pids"]):
            warnings.append("SUSPECTED_DISPLAY_ORPHAN")
        maintenance = self.maintenance.status()
        if maintenance.get("status") in {"FAILED", "INTERRUPTED"}:
            warnings.append("MAINTENANCE_REVIEW")
        return {
            "at": datetime.now(timezone.utc).isoformat(),
            "version": __version__, "uptime_seconds": int(time.monotonic() - self.started_monotonic),
            "state": "BLOCKED" if resource.state == "BLOCKED" else "DEGRADED" if warnings else "OK",
            "warnings": warnings,
            "components": components,
            "storage": {"database_bytes": database.stat().st_size,
                        "wal_bytes": (database.parent / (database.name + "-wal")).stat().st_size
                        if (database.parent / (database.name + "-wal")).is_file() else 0,
                        "schema_actual": schema, "schema_expected": _SCHEMA_VERSION,
                        "artifact_count": artifact_stats[0],
                        "artifact_logical_bytes": artifact_stats[1]},
            "resources": resource.to_dict(),
            "counts": counts, "objects": objects, "burp": burp,
            "burp_storage": burp_storage,
            "processes": processes,
            "notifications": notifier, "backup": backup,
            "maintenance": maintenance,
            "retention": {"mode": "ORPHAN_AND_REVIEWED_TERMINAL_PROFILES",
                          "orphan_grace_hours": self.config.retention.orphan_grace_hours,
                          "orphan_scan_timeout_seconds":
                              self.config.retention.orphan_scan_timeout_seconds,
                          "traffic": {
                              "anonymous_hours": self.config.retention.traffic_anonymous_hours,
                              "authenticated_hours": self.config.retention.traffic_authenticated_hours,
                              "execution_hours": self.config.retention.traffic_execution_hours,
                              "target_override_count": len(self.config.retention.traffic_target_hours),
                              "payload_cleanup": "CLI_REVIEWED",
                              "physical_gc": "SEPARATE_REVIEW"},
                          "anonymous_profile_grace_hours":
                              self.config.retention.anonymous_profile_grace_hours,
                          "disabled_identity_profile_grace_hours":
                              self.config.retention.disabled_identity_profile_grace_hours,
                          "active_identity_profile_grace_hours":
                              self.config.retention.active_identity_profile_grace_hours},
            "recon": recon_state,
            "research": "CONFIGURED" if self.config.research and self.config.research.enabled else "DISABLED",
        }

    def target_summary(self, package: TargetPackage) -> dict[str, object]:
        with self.store._connection() as connection:
            counts = {
                "identities": connection.execute("SELECT count(*) FROM registry_identities WHERE target_id=?",
                                                 (package.target.id,)).fetchone()[0],
                "browser_sessions": connection.execute("SELECT count(*) FROM browser_sessions WHERE target_id=?",
                                                        (package.target.id,)).fetchone()[0],
                "traffic": connection.execute("SELECT count(*) FROM traffic_exchanges WHERE target_id=?",
                                               (package.target.id,)).fetchone()[0],
                "dom_xss_candidates": connection.execute(
                    "SELECT count(*) FROM dom_flow_candidates WHERE target_id=?",
                    (package.target.id,)).fetchone()[0],
                "dom_xss_high_priority": connection.execute(
                    "SELECT count(*) FROM dom_flow_candidates WHERE target_id=? AND score>=75 "
                    "AND status NOT IN ('STALE','REJECTED')",
                    (package.target.id,)).fetchone()[0],
            }
        discovery = self.bootstrap_store.discovery_state(package.target.id)
        return {"id": package.id, "target_id": package.target.id, "name": package.to_dict()["name"],
                "primary_domain": package.primary_domain, "status": package.status.value,
                "discovery_state": discovery["state"] if discovery else "UNBOOTSTRAPPED",
                "scope_summary": {"included_hosts": len(package.scope.include_hosts),
                                  "excluded_hosts": len(package.scope.exclude_hosts)},
                "counts": counts, "authority": "TARGET_PACKAGE"}

    def identity_summary(self, target_id: str, identity_id: str) -> dict[str, object]:
        identity = self.registry.get_identity(target_id, identity_id)
        if identity is None:
            raise LookupError("identity not found")
        memberships = self.registry.list_memberships(identity.id, limit=20)
        member_rows = []
        for membership in memberships.items:
            tenant = self.registry.get_tenant(target_id, membership.tenant_id)
            roles = [self.registry.get_role(target_id, role_id) for role_id in membership.role_ids]
            member_rows.append({"tenant_id": membership.tenant_id,
                                "tenant": tenant.label if tenant else None,
                                "roles": [role.name for role in roles if role],
                                "status": membership.status.value,
                                "observation_state": membership.observation_state.value})
        context = self.auth.get(target_id, identity.id)
        session = self.browser.get_session_for_identity(target_id, identity.id)
        return {"identity": identity.to_dict(), "memberships": member_rows,
                "memberships_truncated": memberships.next_cursor is not None,
                "auth": context.to_dict() if context else None,
                "browser": self.session_summary(session) if session else None}

    def session_summary(self, session: BrowserSession) -> dict[str, object]:
        result = session.to_dict()
        binding = self.burp.binding_for_session(session.id)
        result["capture_provider"] = "BURP" if binding is not None else "DIRECT"
        result["capture_listener"] = binding.listener_key if binding is not None else None
        result["browser_running"] = self.driver.is_running(session.id)
        result["vnc_available"] = bool(session.status is BrowserStatus.WAITING_LOGIN and self._vnc_ready())
        result["vnc_url"] = (self.config.browser.vnc_url if result["vnc_available"] else None)
        return result

    def verification_rule(self, package: TargetPackage, identity_id: str) -> IdentityVerificationRule | None:
        """Optional private, server-side rule; never accept expected identity from the client."""
        identity = self.registry.get_identity(package.target.id, identity_id)
        if identity is None:
            return None
        path = package.package_dir / "verification.json"
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
            raise ValueError("invalid verification rule file")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or len(payload) > 20:
                raise ValueError
            item = payload.get(identity.alias)
            if item is None:
                return None
            allowed = {"user_id_selector", "email_selector", "tenant_selector",
                       "expected_user_id", "expected_email", "expected_tenant_id"}
            if not isinstance(item, dict) or set(item) - allowed or any(
                not isinstance(value, str) or not 1 <= len(value) <= 256 for value in item.values()
            ):
                raise ValueError
            return IdentityVerificationRule(target_id=package.target.id,
                                            identity_id=identity_id, **item)
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError("invalid verification rule file") from None


def _body(allowed: frozenset[str]) -> dict[str, Any]:
    value = request.get_json(silent=True)
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("invalid request body")
    return value


def _dom_candidate_view(candidate, links: dict[str, str | None] | None = None) -> dict[str, object]:
    return {
        "id": candidate.candidate_id,
        "target_id": candidate.target_id,
        "recon_asset_id": candidate.recon_asset_id,
        "asset_sha256": candidate.asset_sha256,
        "source": candidate.source,
        "source_line": candidate.source_location.line,
        "checks": [step.operation for step in candidate.validation],
        "transforms": [step.operation for step in candidate.transforms],
        "post_checks": [step.operation for step in candidate.post_checks],
        "sanitizers": [step.operation for step in candidate.sanitizers],
        "sink": candidate.sink,
        "sink_kind": candidate.sink_kind,
        "sink_line": candidate.sink_location.line,
        "check_before_transform": candidate.check_before_transform,
        "attacker_controlled": candidate.attacker_controlled,
        "score": candidate.score,
        "status": candidate.status.value,
        "route": candidate.route,
        "mapped_source": candidate.mapped_source,
        "source_map_sha256": candidate.source_map_sha256,
        "evidence_ids": list(candidate.evidence_ids[:16]),
        "links": links or {},
    }


def _message_candidate_view(candidate, links: dict[str, str | None] | None = None,
                            related: tuple[str, ...] = ()) -> dict[str, object]:
    redactor = SecretRedactor.from_environment()
    return {
        "id": candidate.candidate_id, "target_id": candidate.target_id,
        "asset_hashes": list(candidate.asset_hashes[:16]),
        "artifact_ids": list(candidate.artifact_ids[:16]),
        "message_types": [redactor.text(value) for value in candidate.message_types[:16]],
        "reply_types": [redactor.text(value) for value in candidate.reply_types[:16]],
        "receiver": redactor.text(candidate.receiver),
        "transport_kind": candidate.transport_kind,
        "receiver_line": candidate.receiver_location.line,
        "origin_checks": [{"kind": item.kind, "line": item.location.line}
                          for item in candidate.origin_checks],
        "source_checks": [{"kind": item.kind, "line": item.location.line}
                          for item in candidate.source_checks],
        "origin_validation": candidate.origin_validation,
        "source_validation": candidate.source_validation,
        "port_accepted": candidate.port_accepted, "port_created": candidate.port_created,
        "port_bound": candidate.port_bound,
        "rpc_methods": [redactor.text(value) for value in candidate.rpc_methods[:16]],
        "rpc_details": [{"name": redactor.text(item.name),
                         "argument_fields": [redactor.text(field) for field in item.argument_fields],
                         "result_shape": item.result_shape, "capability": item.capability,
                         "authorization_assumptions": list(item.authorization_assumptions)}
                        for item in candidate.rpc_details[:16]],
        "payload_fields": [redactor.text(value) for value in candidate.payload_fields[:16]],
        "sensitive_operations": list(candidate.sensitive_operations[:16]),
        "protocol_sequence": [redactor.text(value) for value in candidate.protocol_sequence[:24]],
        "sender_contexts": [redactor.text(value) for value in candidate.sender_contexts[:8]],
        "related_protocols": list(related), "priority": candidate.priority,
        "status": candidate.status.value, "runtime_status": candidate.runtime_status,
        "route": redactor.text(candidate.route) if candidate.route else None,
        "source_map_sha256": candidate.source_map_sha256,
        "mapped_source": redactor.text(candidate.mapped_source) if candidate.mapped_source else None,
        "evidence_ids": list(candidate.evidence_ids[:16]), "links": links or {},
    }


def create_app(config: AppConfig | None = None, *, runtime: BugHunterRuntime | None = None) -> Flask:
    """WSGI factory. Bind with exactly one worker on a private Unix socket."""
    service = runtime or BugHunterRuntime(config or load_config())
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 70_000
    app.config["JSON_SORT_KEYS"] = True
    if runtime is None:
        service.delta_scheduler.start()

    @app.after_request
    def no_store(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if request.path == "/domxss" or request.path.startswith("/domxss/assets/"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        return response

    @app.get("/domxss")
    def domxss_view():
        return send_from_directory(Path(__file__).resolve().parent / "ui", "domxss.html")

    @app.get("/domxss/assets/<name>")
    def domxss_asset(name: str):
        if name not in {"domxss.css", "domxss.js"}:
            raise LookupError("asset not found")
        return send_from_directory(Path(__file__).resolve().parent / "ui", name)

    @app.errorhandler(LookupError)
    def not_found(_exc):
        return jsonify(error="not_found"), 404

    @app.errorhandler((ValueError))
    def bad_request(_exc):
        return jsonify(error="invalid_request"), 400

    @app.errorhandler(StoreNotInitialized)
    @app.errorhandler(StoreSchemaError)
    def unavailable(_exc):
        return jsonify(error="service_unavailable"), 503

    @app.errorhandler(ResourceError)
    def resource_unavailable(exc):
        return jsonify(error="resource_unavailable", reason_code=exc.reason_code), 503

    @app.errorhandler(MaintenanceError)
    def maintenance_rejected(exc):
        status = 409 if exc.reason_code == "MAINTENANCE_BUSY" else 503 if (
            exc.reason_code == "CORRUPT_MAINTENANCE_STATE") else 400
        return jsonify(error="maintenance_rejected", reason_code=exc.reason_code), status

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error="request_rejected"), exc.code

    @app.errorhandler(Exception)
    def internal(_exc):
        service.logger.error("service_request_failed")
        return jsonify(error="internal_error"), 500

    @app.get("/v1/health")
    def health():
        return jsonify(service.health())

    @app.get("/v1/ready")
    def readiness():
        result = service.readiness()
        return jsonify(result), 503 if result["state"] == "NOT_READY" else 200

    @app.get("/v1/operations")
    def operations():
        return jsonify(service.operations())

    @app.get("/v1/operations/maintenance")
    def maintenance_status():
        return jsonify(service.maintenance.status())

    @app.post("/v1/operations/maintenance")
    def maintenance_start():
        data = _body(frozenset({"action", "backup_id", "review_id", "confirmed",
                                "target_id", "identity_id", "session_id"}))
        if not isinstance(data.get("action"), str) or type(data.get("confirmed", False)) is not bool:
            raise ValueError("invalid maintenance action")
        return jsonify(service.maintenance.start(
            data["action"], backup_id=data.get("backup_id"),
            review_id=data.get("review_id"),
            confirmed=data.get("confirmed", False),
            target_id=data.get("target_id"),
            identity_id=data.get("identity_id"),
            session_id=data.get("session_id"))), 202

    @app.get("/v1/status")
    def status():
        return jsonify({"version": __version__, "runtime": "single_process",
                        "browser": service.health()["checks"]["browser_manager"],
                        "burp": service.burp.status(),
                        "orchestrator": {"mode": "explicit_one_step", **service.run_store.stats()},
                        "validator": {"mode": "deterministic_evidence_only", **service.validations.stats()},
                        "campaigns": {"mode": "explicit_bounded", **service.campaign.store.stats()},
                        "notifications": service.notifications.status(),
                        "reports": service.report_store.stats(),
                        "object_factory": {"mode": "known_recipes_only", **service.objects.stats()},
                        "recon_integration": service.recon_health()})

    @app.get("/v1/overview")
    def overview():
        return jsonify(service.overview())

    @app.get("/v1/exposure/<package_id>/candidates")
    def exposure_candidates(package_id: str):
        package = service.package(package_id)
        page = PageRequest.parse(maximum=100)
        category_text = request.args.get("category")
        status_text = request.args.get("status")
        category = ExposureCategory(category_text) if category_text else None
        candidate_status = ExposureStatus(status_text) if status_text else None
        result = service.exposure_store.list(package.target.id, category=category,
                                             status=candidate_status, limit=page.limit,
                                             cursor=page.cursor)
        return jsonify({"items": [{**item.public_dict(), "finding_status":
                        service.exposure_store.validation_state(package.target.id, item.candidate_id)}
                        for item in result.items],
                        "next_cursor": result.next_cursor})

    @app.get("/v1/exposure/<package_id>/candidates/<candidate_id>")
    def exposure_candidate(package_id: str, candidate_id: str):
        package = service.package(package_id)
        candidate = service.exposure_store.get(package.target.id, candidate_id)
        if candidate is None:
            raise LookupError("candidate not found")
        return jsonify({"candidate": {**candidate.public_dict(), "finding_status":
                        service.exposure_store.validation_state(package.target.id, candidate_id)},
                        "sources": service.exposure_store.source_links(package.target.id,
                                                                     candidate_id),
                        "links": service.exposure_store.links(package.target.id, candidate_id)})

    @app.get("/v1/exposure/<package_id>/metrics")
    def exposure_metrics(package_id: str):
        package = service.package(package_id)
        return jsonify(service.exposure_store.metrics(package.target.id))

    @app.get("/v1/exposure/<package_id>/artifacts")
    def exposure_artifacts(package_id: str):
        package = service.package(package_id)
        items = service.domxss_store.list_current_assets(package.target.id)
        return jsonify({"items": [{"artifact_id": item.artifact_id,
                                  "sha256": item.artifact_sha256,
                                  "has_source_map": service.domxss_store.get_source_map(
                                      package.target.id, item.artifact_id) is not None,
                                  "retrieved_at": item.retrieved_at.isoformat()}
                                 for item in items], "bounded": True})

    @app.get("/v1/exposure/<package_id>/captures")
    def exposure_captures(package_id: str):
        package = service.package(package_id)
        return jsonify({"items": service.exposure.list_captured_responses(package),
                        "bounded": True})

    @app.get("/v1/exposure/<package_id>/field-exchanges")
    def exposure_field_exchanges(package_id: str):
        package = service.package(package_id)
        return jsonify({"items": service.exposure.list_field_exchanges(package),
                        "bounded": True})

    @app.post("/v1/exposure/<package_id>/discover")
    def exposure_discover(package_id: str):
        package = service.package(package_id)
        data = _body(frozenset({"source"}))
        source = data.get("source")
        if source == "recon":
            result = service.exposure.discover_recon(package)
        elif source == "traffic":
            result = service.exposure.discover_traffic(package)
        else:
            raise ValueError("invalid exposure discovery source")
        return jsonify({"candidate_ids": list(result.candidate_ids),
                        "signals": result.signals, "bytes_examined": result.bytes_examined,
                        "truncated": result.truncated, "parse_error": result.parse_error,
                        "network_requests_sent": 0})

    @app.post("/v1/exposure/<package_id>/analyze")
    def exposure_analyze(package_id: str):
        package = service.package(package_id)
        data = _body(frozenset({"kind", "artifact_id", "recent_change"}))
        artifact_id = data.get("artifact_id")
        recent_change = data.get("recent_change", False)
        if not isinstance(artifact_id, str) or type(recent_change) is not bool:
            raise ValueError("invalid exposure analysis input")
        if data.get("kind") == "js":
            result = service.exposure.analyze_js(package, artifact_id,
                                                 recent_change=recent_change)
        elif data.get("kind") == "source_map":
            result = service.exposure.analyze_source_map(package, artifact_id,
                                                         recent_change=recent_change)
        else:
            raise ValueError("invalid exposure artifact kind")
        return jsonify({"candidate_ids": list(result.candidate_ids),
                        "signals": result.signals, "bytes_examined": result.bytes_examined,
                        "truncated": result.truncated, "parse_error": result.parse_error,
                        "network_requests_sent": 0})

    @app.post("/v1/exposure/<package_id>/analyze-response")
    def exposure_analyze_response(package_id: str):
        package = service.package(package_id)
        data = _body(frozenset({"exchange_id", "artifact_evidence_id"}))
        exchange_id, evidence_id = data.get("exchange_id"), data.get("artifact_evidence_id")
        if not isinstance(exchange_id, str) or not isinstance(evidence_id, str):
            raise ValueError("opaque capture IDs required")
        result = service.exposure.analyze_captured_response(
            package, exchange_id=exchange_id, artifact_evidence_id=evidence_id)
        return jsonify({"candidate_ids": list(result.candidate_ids),
                        "signals": result.signals, "bytes_examined": result.bytes_examined,
                        "network_requests_sent": 0})

    @app.post("/v1/exposure/<package_id>/analyze-field")
    def exposure_analyze_field(package_id: str):
        package = service.package(package_id)
        data = _body(frozenset({"owner_exchange_id", "member_exchange_id"}))
        owner, member = data.get("owner_exchange_id"), data.get("member_exchange_id")
        if not isinstance(owner, str) or not isinstance(member, str):
            raise ValueError("opaque exchange IDs required")
        result = service.exposure.analyze_field_boundary(
            package, owner_exchange_id=owner, member_exchange_id=member)
        return jsonify({"candidate_ids": list(result.candidate_ids),
                        "signals": result.signals, "network_requests_sent": 0})

    @app.post("/v1/exposure/<package_id>/candidates/<candidate_id>/prepare")
    def exposure_prepare(package_id: str, candidate_id: str):
        package = service.package(package_id)
        _body(frozenset())
        prepared = service.exposure.prepare_candidate(
            package, candidate_id, hypotheses=service.hypotheses,
            contexts=service.skill_context, router=service.skill_router,
            planner=service.skill_planner)
        return jsonify({"hypothesis_id": prepared.hypothesis_id,
                        "plan_id": prepared.plan_id, "plan_status": prepared.plan_status,
                        "network_requests_sent": 0})

    @app.post("/v1/exposure/<package_id>/candidates/<candidate_id>/bind-read")
    def exposure_bind_read(package_id: str, candidate_id: str):
        package = service.package(package_id)
        data = _body(frozenset({"test_object_id", "owner_session_id"}))
        test_object_id, owner_session_id = data.get("test_object_id"), data.get("owner_session_id")
        if not isinstance(test_object_id, str) or not isinstance(owner_session_id, str):
            raise ValueError("invalid owned exposure binding")
        prepared = service.exposure.bind_owned_read(
            package, candidate_id, test_object_id=test_object_id,
            owner_session_id=owner_session_id, objects=service.objects,
            hypotheses=service.hypotheses, contexts=service.skill_context,
            planner=service.skill_planner)
        return jsonify({"hypothesis_id": prepared.hypothesis_id,
                        "plan_id": prepared.plan_id, "plan_status": prepared.plan_status,
                        "network_requests_sent": 0})

    @app.post("/v1/exposure/<package_id>/candidates/<candidate_id>/bind-field")
    def exposure_bind_field(package_id: str, candidate_id: str):
        package = service.package(package_id)
        data = _body(frozenset({"test_object_id", "owner_session_id",
                               "member_session_id"}))
        object_id = data.get("test_object_id")
        owner = data.get("owner_session_id")
        member = data.get("member_session_id")
        if not all(isinstance(item, str) for item in (object_id, owner, member)):
            raise ValueError("owned object and verified session IDs required")
        prepared = service.exposure.bind_field_read(
            package, candidate_id, test_object_id=object_id,
            owner_session_id=owner, member_session_id=member,
            objects=service.objects, hypotheses=service.hypotheses,
            contexts=service.skill_context, planner=service.skill_planner)
        return jsonify({"hypothesis_id": prepared.hypothesis_id,
                        "plan_id": prepared.plan_id, "plan_status": prepared.plan_status,
                        "network_requests_sent": 0})

    @app.get("/v1/activity")
    def activity():
        return jsonify(service.activity(PageRequest.parse()))

    @app.get("/v1/targets")
    def targets():
        page = PageRequest.parse()
        result = service.targets.list_target_packages(limit=page.limit, cursor=page.cursor)
        return jsonify({"items": [service.target_summary(item) for item in result.items],
                        "next_cursor": result.next_cursor})

    @app.get("/v1/targets/<package_id>")
    def target(package_id: str):
        return jsonify(service.target_summary(service.package(package_id)))

    @app.get("/v1/targets/<package_id>/bootstrap")
    def bootstrap_status(package_id: str):
        package = service.package(package_id)
        _, recon_status = service.bootstrap.recon_provider.lookup(package)
        state = service.bootstrap_store.discovery_state(package.target.id)
        runs = service.bootstrap_store.list_runs(package.target.id, limit=10)
        return jsonify({"target_id": package.target.id,
                        "recon_availability": recon_status,
                        "discovery_state": state["state"] if state else (
                            "RECON_BACKED" if recon_status == "RECON_BACKED" else "COLD_START"),
                        "latest": runs[0].to_dict() if runs else None,
                        "history": [run.to_dict() for run in runs]})

    @app.post("/v1/targets/<package_id>/bootstrap")
    def bootstrap_start(package_id: str):
        package = service.package(package_id)
        data = _body(frozenset({"identity_policy", "identity_id", "limits", "refresh"}))
        try:
            policy = BootstrapIdentityPolicy(data.get("identity_policy", "anonymous_plus_primary"))
        except ValueError:
            raise ValueError("invalid identity policy") from None
        values = data.get("limits", {})
        if not isinstance(values, dict) or set(values) - set(BootstrapLimits.__dataclass_fields__):
            raise ValueError("invalid bootstrap limits")
        limits = BootstrapLimits(**values)
        identity_id = data.get("identity_id")
        if identity_id is not None and not isinstance(identity_id, str):
            raise ValueError("invalid bootstrap identity")
        refresh = data.get("refresh", False)
        if type(refresh) is not bool:
            raise ValueError("invalid refresh flag")
        service.resources.admit(WorkKind.BOOTSTRAP,
                                active=sum(thread.is_alive() for thread in service._bootstrap_threads.values()))
        run = service.bootstrap.create(package.id, limits=limits, identity_policy=policy,
                                       identity_id=identity_id)
        try:
            browser_signals = service.bootstrap.capture_browser_signals(package, run)
        except Exception:
            service.logger.warning("bootstrap_browser_observation_unavailable", extra={"context": {
                "target_id": package.target.id, "run_id": run.bootstrap_id}})
            browser_signals = ()

        def work() -> None:
            try:
                service.bootstrap.run(run.bootstrap_id, package.id, refresh=refresh,
                                      browser_signals=browser_signals)
            except Exception:
                service.logger.error("bootstrap_run_failed", extra={"context": {
                    "target_id": package.target.id, "run_id": run.bootstrap_id}})
            finally:
                service._bootstrap_threads.pop(run.bootstrap_id, None)

        thread = Thread(target=work, name="bootstrap-" + run.bootstrap_id[-8:], daemon=True)
        service._bootstrap_threads[run.bootstrap_id] = thread
        try:
            thread.start()
        except RuntimeError:
            service._bootstrap_threads.pop(run.bootstrap_id, None)
            service.bootstrap_store.transition(
                run.bootstrap_id, run.target_id, BootstrapStatus.FAILED,
                limitations=("WORKER_START_FAILED",), stop_reason="WORKER_START_FAILED")
            raise
        return jsonify(run.to_dict()), 201

    @app.get("/v1/targets/<package_id>/bootstrap/<run_id>")
    def bootstrap_detail(package_id: str, run_id: str):
        package = service.package(package_id)
        run = service.bootstrap_store.get(run_id, package.target.id)
        if run is None:
            raise LookupError("bootstrap run not found")
        observations = service.bootstrap_store.list_observations(package.target.id,
                                                                  run_id=run_id, limit=80)
        return jsonify({"run": run.to_dict(),
                        "observations": [item.to_dict() for item in observations],
                        "observations_truncated": len(observations) == 80})

    @app.post("/v1/targets/<package_id>/bootstrap/<run_id>/cancel")
    def bootstrap_cancel(package_id: str, run_id: str):
        _body(frozenset())
        package = service.package(package_id)
        if not service.bootstrap_store.request_cancel(run_id, package.target.id):
            raise ValueError("bootstrap run is not active")
        return jsonify({"bootstrap_id": run_id, "cancel_requested": True})

    @app.get("/v1/targets/<package_id>/scope")
    def scope(package_id: str):
        package = service.package(package_id)
        return jsonify({"authority": "AUTHORIZED_TARGET_SCOPE", "recon_inventory": "NOT_AUTHORIZATION",
                        "target_id": package.target.id, "package_status": package.status.value,
                        "scope": package.scope.to_dict(),
                        "program_rules": package.rules.to_dict()})

    @app.get("/v1/targets/<package_id>/policy")
    def target_policy(package_id: str):
        package = service.package(package_id)
        return jsonify({"target_id": package.target.id, "package_status": package.status.value,
                        "scope": package.scope.to_dict(), "program_rules": package.rules.to_dict(),
                        "autonomy": package.autonomy.to_dict(), "rate": package.rate.to_dict(),
                        "authority": "TARGET_PACKAGE", "recon_inventory": "NOT_AUTHORIZATION"})

    @app.get("/v1/domxss/<package_id>/inventory")
    def domxss_inventory(package_id: str):
        package = service.package(package_id)
        if service.domxss is None:
            return jsonify(error="recon_unavailable"), 503
        items = []
        for lead in service.domxss.inventory(package_id):
            asset = lead.asset
            items.append({"recon_asset_id": asset.asset_id,
                          "host": urlsplit(asset.asset_url).hostname,
                          "asset_url_sha256": hashlib.sha256(asset.asset_url.encode()).hexdigest(),
                          "latest_sha256": asset.latest_sha256,
                          "score": lead.score, "reasons": list(lead.reasons)})
        return jsonify({"target_id": package.target.id, "items": items, "bounded": True})

    @app.get("/v1/domxss/<package_id>/candidates")
    def domxss_candidates(package_id: str):
        package = service.package(package_id)
        page = PageRequest.parse()
        candidates = service.domxss_store.list_candidates(
            package.target.id, limit=page.limit, cursor=page.cursor)
        return jsonify({"target_id": package.target.id,
                        "items": [_dom_candidate_view(item) for item in candidates.items],
                        "next_cursor": candidates.next_cursor})

    @app.get("/v1/domxss/<package_id>/metrics")
    def domxss_metrics(package_id: str):
        package = service.package(package_id)
        with service.store._connection() as db:
            assets = db.execute("SELECT count(*) FROM dom_analysis_runs WHERE target_id=?",
                                (package.target.id,)).fetchone()[0]
            rows = db.execute("""
                SELECT status,count(*) AS total FROM dom_flow_candidates
                WHERE target_id=? GROUP BY status
            """, (package.target.id,)).fetchall()
            browser_actions = db.execute("""
                SELECT count(*) FROM plan_dom_dispatches d JOIN plan_runs r ON r.run_id=d.run_id
                WHERE r.target_id=?
            """, (package.target.id,)).fetchone()[0]
            confirmed = db.execute("""
                SELECT count(*) FROM validations WHERE target_id=? AND skill_id=? AND status=?
            """, (package.target.id, "check-before-transform-dom-xss",
                  "CONFIRMED")).fetchone()[0]
        statuses = {row["status"]: row["total"] for row in rows}
        return jsonify({"target_id": package.target.id, "assets_analyzed": assets,
                        "candidates": sum(statuses.values()), "by_status": statuses,
                        "browser_actions": browser_actions, "confirmed": confirmed,
                        "rejected": statuses.get("REJECTED", 0) + statuses.get("RUNTIME_TESTED", 0),
                        "manual_review": statuses.get("NEEDS_MANUAL_REVIEW", 0)})

    @app.get("/v1/domxss/<package_id>/candidates/<candidate_id>")
    def domxss_candidate(package_id: str, candidate_id: str):
        package = service.package(package_id)
        item = service.domxss_store.get_candidate(package.target.id, candidate_id)
        if item is None:
            raise LookupError("candidate not found")
        return jsonify(_dom_candidate_view(
            item, service.domxss_store.candidate_links(package.target.id, candidate_id)))

    @app.get("/v1/domxss/<package_id>/candidates/<candidate_id>/runtime")
    def domxss_runtime(package_id: str, candidate_id: str):
        package = service.package(package_id)
        links = service.domxss_store.candidate_links(package.target.id, candidate_id)
        if links is None:
            raise LookupError("candidate not found")
        run = service.run_store.get(links["run_id"], package.target.id) if links["run_id"] else None
        validation = (service.validations.get(links["validation_id"], package.target.id)
                      if links["validation_id"] else None)
        trials = []
        if run is not None:
            for step in service.run_store.steps(run.id):
                if step.type != "VERIFY_BROWSER":
                    continue
                result = service.run_store.result(step.id)
                for ref in result.evidence_ids[:6] if result else ():
                    evidence = service.store.get_evidence(ref)
                    if (evidence is None or evidence.target_ref != package.target.id
                            or evidence.evidence_type != "DOM_PROOF"):
                        continue
                    try:
                        record = json.loads(service.store.read_content(ref, max_bytes=8192))
                    except (ValueError, UnicodeError, PermissionError):
                        continue
                    trials.append({"variant": record.get("variant"),
                                   "marker_observed": record.get("marker_observed"),
                                   "marker_context": record.get("marker_context"),
                                   "document_origin": record.get("document_origin"),
                                   "csp_present": record.get("csp_present"),
                                   "trusted_types_enforced": record.get("trusted_types_enforced"),
                                   "sandbox_flags": record.get("sandbox_flags"),
                                   "browser_blocked": record.get("browser_blocked"),
                                   "navigation_only": record.get("navigation_only"),
                                   "response_status": record.get("response_status"),
                                   "request_count": record.get("request_count"),
                                   "evidence_id": ref})
        return jsonify({"target_id": package.target.id, "links": links,
                        "run_status": run.status.value if run else None,
                        "validation_status": validation.status.value if validation else None,
                        "trials": trials})

    @app.post("/v1/domxss/<package_id>/analyze")
    def domxss_analyze(package_id: str):
        body = _body(frozenset({"recon_asset_id"}))
        package = service.package(package_id)
        asset_id = body.get("recon_asset_id")
        if type(asset_id) is not int or asset_id <= 0:
            raise ValueError("invalid recon asset")
        if service.domxss is None:
            return jsonify(error="recon_unavailable"), 503
        lead = next((item for item in service.domxss.inventory(package_id)
                     if item.asset.asset_id == asset_id), None)
        if lead is None:
            raise LookupError("asset not in bounded in-scope inventory")
        result = service.domxss.acquire(package_id, lead.asset)
        if result.artifact is None or result.status.value not in {"REUSED", "RETRIEVED"}:
            return jsonify({"target_id": package.target.id, "status": result.status.value,
                            "reason_code": result.reason_code,
                            "exchange_ids": list(result.exchange_ids)}), 202
        analysis_id, analysis = service.domxss.analyze(package.target.id,
                                                      result.artifact.artifact_id)
        source_map_status = "NOT_REQUESTED"
        mapped_ids: list[str] = []
        if any(item.score >= 75 for item in analysis.candidates):
            mapped = service.domxss.acquire_source_map(package_id, lead.asset, result.artifact)
            source_map_status = mapped.status.value
            if mapped.source_map is not None:
                for item in analysis.candidates:
                    if item.score < 75:
                        continue
                    try:
                        service.domxss_store.map_candidate(package.target.id, item.candidate_id,
                                                           mapped.source_map)
                    except ValueError:
                        source_map_status = "MAPPING_FAILED"
                        continue
                    mapped_ids.append(item.candidate_id)
        return jsonify({"target_id": package.target.id, "status": analysis.status,
                        "analysis_id": analysis_id, "asset_sha256": analysis.asset_sha256,
                        "candidate_ids": [item.candidate_id for item in analysis.candidates],
                        "parse_errors": analysis.parse_errors,
                        "source_map_status": source_map_status,
                        "mapped_candidate_ids": mapped_ids}), 201

    @app.post("/v1/domxss/<package_id>/candidates/<candidate_id>/route")
    def domxss_bind_route(package_id: str, candidate_id: str):
        body = _body(frozenset({"exchange_id"}))
        if not isinstance(body.get("exchange_id"), str) or service.domxss is None:
            raise ValueError("observed exchange required")
        item = service.domxss.bind_observed_route(
            package_id, candidate_id, body["exchange_id"], service.traffic)
        return jsonify(_dom_candidate_view(item))

    @app.post("/v1/domxss/<package_id>/candidates/<candidate_id>/prepare")
    def domxss_prepare(package_id: str, candidate_id: str):
        _body(frozenset())
        if service.domxss is None:
            return jsonify(error="recon_unavailable"), 503
        prepared = service.domxss.prepare_candidate(
            package_id, candidate_id, hypotheses=service.hypotheses,
            contexts=service.skill_context, router=service.skill_router,
            planner=service.skill_planner)
        return jsonify({"hypothesis_id": prepared.hypothesis.id,
                        "plan_id": prepared.plan["id"],
                        "skill_id": prepared.selected_skill,
                        "prerequisite_state": prepared.prerequisite_state}), 201

    @app.post("/v1/domxss/<package_id>/candidates/<candidate_id>/bind-plan")
    def domxss_bind_plan(package_id: str, candidate_id: str):
        body = _body(frozenset({"browser_session_id", "input_kind", "input_name"}))
        package = service.package(package_id)
        candidate = service.domxss_store.get_candidate(package.target.id, candidate_id)
        asset = service.domxss_store.candidate_asset(package.target.id, candidate_id)
        links = service.domxss_store.candidate_links(package.target.id, candidate_id)
        if candidate is None or asset is None or links is None or not links["hypothesis_id"]:
            raise LookupError("prepared candidate not found")
        if service.domxss is None:
            return jsonify(error="recon_unavailable"), 503
        lead = next((item for item in service.domxss.inventory(package_id)
                     if item.asset.asset_id == asset.recon_asset_id and
                     hashlib.sha256(item.asset.asset_url.encode()).hexdigest()
                     == asset.asset_url_sha256), None)
        session_id = body.get("browser_session_id")
        session = service.browser.get(session_id) if isinstance(session_id, str) else None
        if lead is None or session is None or session.target_id != package.target.id or not candidate.route:
            raise ValueError("current asset and target browser session required")
        hypothesis = service.hypotheses.get(links["hypothesis_id"], package.target.id)
        if hypothesis is None:
            raise ValueError("DOM hypothesis unavailable")
        context = service.skill_context.build(hypothesis, None, package=package)
        plan = service.skill_planner.bind_dom(
            package, hypothesis, context,
            DOMPlanBinding(candidate_id, candidate.route, lead.asset.asset_url,
                           session.id, session.identity_id, body.get("input_kind"),
                           body.get("input_name")))
        return jsonify({"plan_id": plan["id"], "status": plan["status"]}), 201

    @app.get("/v1/postmessage/<package_id>/inventory")
    def postmessage_inventory(package_id: str):
        package = service.package(package_id)
        if service.postmessage is None:
            return jsonify(error="recon_unavailable"), 503
        return jsonify({"target_id": package.target.id, "bounded": True,
                        "items": [{"recon_asset_id": lead.asset.asset_id,
                                   "host": urlsplit(lead.asset.asset_url).hostname,
                                   "asset_url_sha256": hashlib.sha256(
                                       lead.asset.asset_url.encode()).hexdigest(),
                                   "latest_sha256": lead.asset.latest_sha256,
                                   "score": lead.score, "reasons": list(lead.reasons)}
                                  for lead in service.postmessage.inventory(package_id)]})

    @app.get("/v1/postmessage/<package_id>/candidates")
    def postmessage_candidates(package_id: str):
        package = service.package(package_id)
        page = PageRequest.parse()
        result = service.postmessage_store.list_candidates(
            package.target.id, limit=page.limit, cursor=page.cursor)
        return jsonify({"target_id": package.target.id,
                        "items": [_message_candidate_view(item) for item in result.items],
                        "next_cursor": result.next_cursor})

    @app.get("/v1/postmessage/<package_id>/metrics")
    def postmessage_metrics(package_id: str):
        package = service.package(package_id)
        return jsonify(service.postmessage_store.metrics(package.target.id))

    @app.get("/v1/postmessage/<package_id>/candidates/<candidate_id>")
    def postmessage_candidate(package_id: str, candidate_id: str):
        package = service.package(package_id)
        item = service.postmessage_store.get_candidate(package.target.id, candidate_id)
        if item is None:
            raise LookupError("candidate not found")
        view = _message_candidate_view(
            item, service.postmessage_store.links(package.target.id, candidate_id),
            service.postmessage_store.related_protocols(package.target.id, candidate_id))
        view["dom_xss_handoffs"] = list(service.postmessage_store.dom_xss_handoffs(
            package.target.id, candidate_id))
        return jsonify(view)

    @app.get("/v1/postmessage/<package_id>/candidates/<candidate_id>/runtime")
    def postmessage_runtime(package_id: str, candidate_id: str):
        package = service.package(package_id)
        links = service.postmessage_store.links(package.target.id, candidate_id)
        if links is None:
            raise LookupError("candidate not found")
        run = service.run_store.get(links["run_id"], package.target.id) if links["run_id"] else None
        validation = (service.validations.get(links["validation_id"], package.target.id)
                      if links["validation_id"] else None)
        trials = []
        if run is not None:
            for step in service.run_store.steps(run.id):
                if step.type != "VERIFY_BROWSER":
                    continue
                result = service.run_store.result(step.id)
                for ref in result.evidence_ids[:8] if result else ():
                    evidence = service.store.get_evidence(ref)
                    if (evidence is None or evidence.target_ref != package.target.id
                            or evidence.evidence_type != "MESSAGE_PROOF"):
                        continue
                    try:
                        record = json.loads(service.store.read_content(ref, max_bytes=8192))
                    except (ValueError, UnicodeError, PermissionError):
                        continue
                    trials.append({key: record.get(key) for key in (
                        "variant", "context_id", "attacker_origin", "source_relationship",
                        "message_type", "message_count", "port_count", "rpc_calls",
                        "capability_observed", "effect_kind", "victim_bundle_sha256",
                        "response_status", "frame_ancestors", "x_frame_options",
                        "sandbox_flags", "request_count", "denial_count", "error_code")}
                        | {"evidence_id": ref})
        return jsonify({"target_id": package.target.id, "links": links,
                        "run_status": run.status.value if run else None,
                        "validation_status": validation.status.value if validation else None,
                        "trials": trials})

    @app.post("/v1/postmessage/<package_id>/analyze")
    def postmessage_analyze(package_id: str):
        body = _body(frozenset({"recon_asset_id"}))
        package = service.package(package_id)
        asset_id = body.get("recon_asset_id")
        if type(asset_id) is not int or asset_id <= 0:
            raise ValueError("invalid recon asset")
        if service.postmessage is None:
            return jsonify(error="recon_unavailable"), 503
        status, analysis_id, analysis, reason = service.postmessage.analyze_asset(
            package_id, asset_id)
        return jsonify({"target_id": package.target.id, "status": status,
                        "analysis_id": analysis_id, "reason_code": reason,
                        "candidate_ids": [item.candidate_id for item in analysis.candidates]
                        if analysis else []}), 201 if analysis else 202

    @app.post("/v1/postmessage/<package_id>/candidates/<candidate_id>/route")
    def postmessage_route(package_id: str, candidate_id: str):
        body = _body(frozenset({"exchange_id"}))
        if service.postmessage is None or not isinstance(body.get("exchange_id"), str):
            raise ValueError("observed exchange required")
        item = service.postmessage.bind_observed_route(
            package_id, candidate_id, body["exchange_id"], service.traffic)
        return jsonify(_message_candidate_view(item))

    @app.post("/v1/postmessage/<package_id>/candidates/<candidate_id>/prepare")
    def postmessage_prepare(package_id: str, candidate_id: str):
        _body(frozenset())
        if service.postmessage is None:
            return jsonify(error="recon_unavailable"), 503
        prepared = service.postmessage.prepare_candidate(
            package_id, candidate_id, hypotheses=service.hypotheses,
            contexts=service.skill_context, router=service.skill_router,
            planner=service.skill_planner)
        return jsonify({"hypothesis_id": prepared.hypothesis.id,
                        "plan_id": prepared.plan["id"],
                        "prerequisite_state": prepared.prerequisite_state}), 201

    @app.post("/v1/postmessage/<package_id>/candidates/<candidate_id>/bind-plan")
    def postmessage_bind_plan(package_id: str, candidate_id: str):
        body = _body(frozenset({"browser_session_id", "activation_type",
                                "port_type", "allowed_method", "owned_object_id"}))
        package = service.package(package_id)
        candidate = service.postmessage_store.get_candidate(package.target.id, candidate_id)
        asset = service.postmessage_store.current_asset(package.target.id, candidate_id)
        links = service.postmessage_store.links(package.target.id, candidate_id)
        session_id = body.get("browser_session_id")
        session = service.browser.get(session_id) if isinstance(session_id, str) else None
        if (candidate is None or asset is None or links is None or not links["hypothesis_id"]
                or not candidate.route or session is None or session.target_id != package.target.id
                or service.postmessage is None):
            raise ValueError("Current messaging candidate and browser session required")
        lead = next((item for item in service.postmessage.inventory(package_id)
                     if item.asset.asset_id == asset.recon_asset_id
                     and hashlib.sha256(item.asset.asset_url.encode()).hexdigest()
                     == asset.asset_url_sha256), None)
        if lead is None:
            raise ValueError("Current messaging bundle is not in bounded inventory")
        hypothesis = service.hypotheses.get(links["hypothesis_id"], package.target.id)
        if hypothesis is None:
            raise ValueError("Messaging hypothesis unavailable")
        context = service.skill_context.build(hypothesis, None, package=package)
        dom_field = (service.postmessage_store.dom_xss_field(package.target.id,
                                                              candidate_id)
                     if body.get("allowed_method") is None and body.get("port_type") is None
                     else None)
        plan = service.skill_planner.bind_message(
            package, hypothesis, context,
            MessagePlanBinding(candidate_id, candidate.route, lead.asset.asset_url,
                               session.id, session.identity_id, body.get("activation_type"),
                               body.get("port_type"), body.get("allowed_method"),
                               "POPUP" if "OPENER" in candidate.sender_contexts
                               and "PARENT" not in candidate.sender_contexts else "IFRAME",
                               dom_field, body.get("owned_object_id")))
        return jsonify({"plan_id": plan["id"], "status": plan["status"]}), 201

    @app.get("/v1/objects/recipes")
    def object_recipes():
        package = service.package(request.args.get("target", ""))
        return jsonify({"items": service.object_factory.recipes.list_for_package(package.id)})

    @app.get("/v1/objects")
    def list_objects():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse()
        raw_status = request.args.get("status")
        status = ObjectState(raw_status) if raw_status else None
        result = service.objects.list_for_target(
            package.target.id, limit=page.limit, cursor=page.cursor, state=status,
            object_type=request.args.get("type") or None,
            tenant_id=request.args.get("tenant") or None,
            identity_id=request.args.get("identity") or None,
            cleanup_only=request.args.get("cleanup") == "pending")
        return jsonify({"items": [item.to_dict() for item in result.items],
                        "next_cursor": result.next_cursor,
                        "stats": service.objects.stats(package.target.id)})

    @app.get("/v1/objects/<object_id>")
    def object_detail(object_id: str):
        package = service.package(request.args.get("target", ""))
        item = service.objects.get(object_id, package.target.id)
        if item is None:
            raise LookupError("object not found")
        mutations = service.mutation_results.list_for_object(item.id, item.target_id)
        latest = mutations[0].run_id if mutations else None
        current = [entry for entry in mutations if entry.run_id == latest]
        restored = any(entry.phase.value == "RESTORE" and entry.verified_effect
                       for entry in current)
        mutated = any(entry.phase.value in {"OWNER_CONTROL", "BOUNDARY"} and
                      entry.verified_effect for entry in current)
        state = "RESTORED" if restored else "MUTATED_REVIEW_REQUIRED" if mutated else "UNCHANGED_OR_UNVERIFIED"
        return jsonify({"object": item.to_dict(), "events": service.objects.events(item.id, item.target_id),
                        "active_reservation_run": service.objects.active_reservation(item.id),
                        "mutation_state": state,
                        "latest_readback": next((entry.to_dict() for entry in current
                                                 if entry.readback_exchange_id), None),
                        "mutation_history": [entry.to_dict() for entry in mutations]})

    @app.post("/v1/objects")
    def create_object():
        body = _body(frozenset({"target", "recipe_id", "identity_id", "tenant_id", "session_id",
                                "purpose", "parent_id", "plan_id", "run_id", "hypothesis_id"}))
        package = service.package(body.get("target", ""))
        for field in ("recipe_id", "identity_id", "tenant_id", "session_id", "purpose"):
            if not isinstance(body.get(field), str):
                raise ValueError("missing object creation context")
        result = service.object_factory.resolve(
            package_id=package.id, recipe_id=body["recipe_id"], identity_id=body["identity_id"],
            tenant_id=body["tenant_id"], session_id=body["session_id"], purpose=body["purpose"],
            parent_id=body.get("parent_id"), plan_id=body.get("plan_id"),
            run_id=body.get("run_id"), hypothesis_id=body.get("hypothesis_id"))
        return jsonify(result.to_dict()), 201 if result.outcome == "READY" else 202

    @app.post("/v1/objects/<object_id>/cleanup")
    def cleanup_object(object_id: str):
        body = _body(frozenset({"target", "session_id"}))
        package = service.package(body.get("target", ""))
        if not isinstance(body.get("session_id"), str):
            raise ValueError("verified session required")
        result = service.object_factory.cleanup(object_id, package.target.id,
                                                session_id=body["session_id"])
        if result.outcome in {"CLEANUP_FAILED", "MANUAL_CLEANUP_REQUIRED"} and result.item:
            try:
                service.notification_store.enqueue(
                    target_id=package.target.id, event_type=NotificationType.CLEANUP_FAILURE,
                    source_kind="OBJECT", source_id=object_id,
                    priority=NotificationPriority.HIGH)
                service._notification_wakeup.set()
            except (LookupError, ValueError, OSError):
                service.logger.error("cleanup_notification_record_failed")
        return jsonify(result.to_dict()), 200 if result.outcome == "CLEANED" else 202

    @app.post("/v1/objects/<object_id>/create")
    def resume_object_creation(object_id: str):
        body = _body(frozenset({"target", "session_id"}))
        package = service.package(body.get("target", ""))
        if not isinstance(body.get("session_id"), str):
            raise ValueError("verified session required")
        result = service.object_factory.create(object_id, package.target.id,
                                               session_id=body["session_id"])
        return jsonify(result.to_dict()), 200 if result.outcome == "READY" else 202

    @app.post("/v1/objects/<object_id>/mark-cleaned")
    def manually_cleaned_object(object_id: str):
        body = _body(frozenset({"target", "reason"}))
        package = service.package(body.get("target", ""))
        item = service.objects.mark_manual_cleaned(object_id, package.target.id,
                                                   reason=body.get("reason", "MANUAL_CONFIRMATION"))
        return jsonify({"object": item.to_dict(), "source": "MANUAL"})

    @app.post("/v1/policy/evaluate")
    def evaluate_policy():
        body = _body(frozenset({"target", "category", "actor", "url", "method", "purpose",
                                "hypothesis_id", "identity_id", "session_id", "operation",
                                "vulnerability_class",
                                "object_type", "object_ref_hash", "disposable_intent",
                                "cross_identity", "side_effect_hint", "requested_risk",
                                "action_id"}))
        package = service.package(body.get("target", ""))
        hypothesis_id = body.get("hypothesis_id")
        if hypothesis_id is not None and service.hypotheses.get(hypothesis_id, package.target.id) is None:
            raise ValueError("invalid hypothesis reference")
        category = ActionCategory(body.get("category"))
        actor = ActorMode(body.get("actor", "ANONYMOUS"))
        action_values = {
            "target_id": package.target.id, "package_id": package.id,
            "category": category, "actor": actor, "source": "operator_ui",
            "purpose": body.get("purpose", "Operator policy simulation"),
            "url": body.get("url"), "method": body.get("method"),
            "hypothesis_id": hypothesis_id, "identity_id": body.get("identity_id"),
            "session_id": body.get("session_id"), "operation": body.get("operation"),
            "vulnerability_class": body.get("vulnerability_class"),
            "object_type": body.get("object_type"), "object_ref_hash": body.get("object_ref_hash"),
            "disposable_intent": body.get("disposable_intent", False),
            "cross_identity": body.get("cross_identity", False),
            "side_effect_hint": SideEffect(body["side_effect_hint"]) if body.get("side_effect_hint") else None,
            "requested_risk": RiskLevel(body["requested_risk"]) if body.get("requested_risk") else None,
        }
        if body.get("action_id") is not None:
            action_values["id"] = body["action_id"]
        action = ProposedAction(**action_values)
        decision = service.policy.evaluate(package, action)
        return jsonify({"action_id": action.id, "decision": decision.to_dict(),
                        "simulation_only": True, "request_sent": False})

    @app.get("/v1/approvals")
    def approvals():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse()
        result = service.policy_store.list(package.target.id, limit=page.limit,
                                           cursor=page.cursor)
        for item in result["items"]:
            item["plan_run"] = service.run_store.approval_run(item["id"], package.target.id)
        return jsonify(result)

    @app.post("/v1/approvals/<approval_id>/approve")
    def approve_once(approval_id: str):
        body = _body(frozenset({"target"}))
        package = service.package(body.get("target", ""))
        current = service.policy_store.get(approval_id, package.target.id)
        if current is None:
            raise LookupError("approval not found")
        if package.status is not PackageStatus.TRACKED or current.policy_version != policy_version(package):
            raise ValueError("approval policy is stale")
        approval = service.policy_store.decide(approval_id, package.target.id, approve=True)
        if current.status != approval.status and approval.status is ApprovalStatus.APPROVED_ONCE:
            service.run_store.approval_decision(approval_id, package.target.id, granted=True)
        return jsonify({"approval": approval.to_dict(), "execution_started": False}), (
            409 if approval.status.value == "EXPIRED" else 200)

    @app.post("/v1/approvals/<approval_id>/reject")
    def reject_approval(approval_id: str):
        body = _body(frozenset({"target"}))
        package = service.package(body.get("target", ""))
        current = service.policy_store.get(approval_id, package.target.id)
        if current is None:
            raise LookupError("approval not found")
        approval = service.policy_store.decide(approval_id, package.target.id, approve=False)
        if current.status != approval.status and approval.status is ApprovalStatus.REJECTED:
            service.run_store.approval_decision(approval_id, package.target.id, granted=False)
        return jsonify({"approval": approval.to_dict(), "execution_started": False}), (
            409 if approval.status.value == "EXPIRED" else 200)

    @app.get("/v1/policy/actions/<action_id>/history")
    def policy_history(action_id: str):
        package = service.package(request.args.get("target", ""))
        return jsonify({"items": service.policy_store.history(package.target.id, action_id)})

    @app.get("/v1/targets/<package_id>/profile")
    def target_profile(package_id: str):
        package = service.package(package_id)
        profile = service.hypotheses.latest_profile(package.target.id)
        return jsonify({"profile": profile.to_dict() if profile else None,
                        "message": "Profile Target to generate a passive snapshot" if profile is None else None})

    @app.get("/v1/targets/<package_id>/behaviour")
    def behaviour_profile(package_id: str):
        package = service.package(package_id)
        profile = service.behaviour_store.profile(package.target.id)
        return jsonify({"profile": profile.to_dict() if profile else None,
                        "runs": [item.to_dict() for item in service.behaviour_store.list_runs(package.target.id)],
                        "message": "Start learning from existing traffic" if profile is None else None})

    @app.get("/v1/targets/<package_id>/behaviour/coverage")
    def behaviour_coverage(package_id: str):
        package = service.package(package_id)
        profile = service.behaviour_store.profile(package.target.id)
        return jsonify({"coverage": profile.coverage if profile else {"state": "NONE"},
                        "gaps": list(profile.gaps) if profile else []})

    @app.get("/v1/targets/<package_id>/behaviour/features")
    def behaviour_features(package_id: str):
        package = service.package(package_id)
        profile = service.behaviour_store.profile(package.target.id)
        return jsonify({"items": list(profile.features) if profile else []})

    @app.get("/v1/targets/<package_id>/behaviour/workflows")
    def behaviour_workflows(package_id: str):
        package = service.package(package_id)
        profile = service.behaviour_store.profile(package.target.id)
        return jsonify({"items": list(profile.workflows) if profile else []})

    @app.get("/v1/targets/<package_id>/behaviour/matrix")
    def behaviour_matrix(package_id: str):
        package = service.package(package_id)
        profile = service.behaviour_store.profile(package.target.id)
        return jsonify({"role_feature": list(profile.role_feature_matrix) if profile else [],
                        "role_operation": list(profile.role_operation_matrix) if profile else [],
                        "expectations": list(profile.expected_access) if profile else []})

    @app.get("/v1/targets/<package_id>/behaviour/gaps")
    def behaviour_gaps(package_id: str):
        package = service.package(package_id)
        profile = service.behaviour_store.profile(package.target.id)
        return jsonify({"items": list(profile.gaps) if profile else []})

    @app.get("/v1/targets/<package_id>/behaviour/runs/<run_id>")
    def behaviour_run(package_id: str, run_id: str):
        package = service.package(package_id)
        run = service.behaviour_store.get_run(package.target.id, run_id)
        if run is None:
            raise LookupError("Learning run not found")
        return jsonify(run.to_dict())

    @app.post("/v1/targets/<package_id>/behaviour")
    @app.post("/v1/targets/<package_id>/behaviour/refresh")
    def behaviour_start(package_id: str):
        package = service.package(package_id)
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or set(data) - {"limits"}:
            raise ValueError("Invalid learning request")
        raw_limits = data.get("limits") or {}
        if not isinstance(raw_limits, dict) or set(raw_limits) - set(LearningLimits.__dataclass_fields__):
            raise ValueError("Invalid learning limits")
        limits = LearningLimits(**raw_limits)
        service.resources.admit(WorkKind.LEARNING,
                                active=sum(thread.is_alive() for thread in service._behaviour_threads.values()))
        run = service.behaviour.create(package, limits)

        def work() -> None:
            try:
                source = service.hypotheses.latest_profile(package.target.id)
                if source is None:
                    source = AttackSurfaceProfiler(service.registry, service.store, service.traffic,
                                                    service.recon, bootstrap=service.bootstrap_store).profile(package)
                service.behaviour.run(package, run.run_id, target_profile=source)
            except Exception:
                current = service.behaviour_store.get_run(package.target.id, run.run_id)
                if current and current.status in {LearningStatus.CREATED, LearningStatus.READY,
                                                  LearningStatus.RUNNING}:
                    service.behaviour_store.transition(package.target.id, run.run_id,
                                                       LearningStatus.FAILED, reason="LEARNING_FAILED")
                service.logger.error("behaviour_learning_failed", extra={"context": {
                    "target_id": package.target.id, "run_id": run.run_id}})
            finally:
                service._behaviour_threads.pop(run.run_id, None)

        thread = Thread(target=work, name="behaviour-" + run.run_id[-8:], daemon=True)
        service._behaviour_threads[run.run_id] = thread
        thread.start()
        return jsonify(run.to_dict()), 202

    @app.post("/v1/targets/<package_id>/behaviour/runs/<run_id>/cancel")
    def behaviour_cancel(package_id: str, run_id: str):
        package = service.package(package_id)
        if not service.behaviour_store.request_cancel(package.target.id, run_id):
            raise ValueError("Learning run is not active")
        return jsonify({"run_id": run_id, "cancel_requested": True})

    @app.post("/v1/targets/<package_id>/behaviour/expectations")
    def behaviour_expectation(package_id: str):
        package = service.package(package_id)
        service.registry.register_target(package)
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or set(data) - {"role_id", "feature", "action", "expected_access", "provenance"}:
            raise ValueError("Invalid expectation request")
        service.behaviour_store.set_expectation(package.target.id, role_id=data.get("role_id"),
            feature=data["feature"], action=data.get("action"), expected_access=data["expected_access"],
            provenance=data.get("provenance", "RESEARCHER"))
        return jsonify({"saved": True}), 201

    @app.get("/v1/research/<package_id>/gaps")
    def research_gaps(package_id: str):
        package = service.package(package_id)
        limit = PageRequest.parse(maximum=100).limit
        return jsonify({"items": [gap.to_dict() for gap in service.research_store.gaps(
            package.target.id, limit=limit)]})

    @app.get("/v1/research/<package_id>/requests")
    def research_requests(package_id: str):
        package = service.package(package_id)
        return jsonify(service.research_store.list(
            package.target.id, limit=PageRequest.parse(maximum=100).limit))

    @app.get("/v1/research/<package_id>/metrics")
    def research_metrics(package_id: str):
        package = service.package(package_id)
        return jsonify(service.research_store.metrics(package.target.id))

    @app.get("/v1/research/<package_id>/requests/<request_id>")
    def research_request(package_id: str, request_id: str):
        package = service.package(package_id)
        item = service.research_store.request(package.target.id, request_id)
        if item is None:
            raise LookupError("research request not found")
        return jsonify({key: item[key] for key in
                        ("request_id", "gap_ref", "gap_type", "topic", "specialist",
                         "hypothesis_id", "status", "brief_id", "error_code", "created_at", "updated_at")})

    @app.get("/v1/research/<package_id>/briefs/<brief_id>")
    def research_brief(package_id: str, brief_id: str):
        package = service.package(package_id)
        item = service.research_store.brief(package.target.id, brief_id)
        if item is None:
            raise LookupError("research brief not found")
        return jsonify(item)

    def _start_research(package_id: str, gap_ref: str, *, refresh: bool,
                        external: bool, budget: ResearchBudget):
        package = service.package(package_id)
        gap = service.research_store.find_gap(package.target.id, gap_ref)
        with service._research_lock:
            result = service.research.submit(gap, budget=budget, external=external,
                                             private_target=True, refresh=refresh)
            if result["status"] != "PENDING" or result["request_id"] in service._research_threads:
                return jsonify(result), 200
            try:
                service.resources.admit(
                    WorkKind.RESEARCH,
                    active=sum(thread.is_alive() for thread in service._research_threads.values()))
            except ResourceError as exc:
                service.research_store.transition(result["request_id"], ResearchStatus.BLOCKED,
                                                  error_code=exc.reason_code)
                raise

            def work() -> None:
                try:
                    service.research.run(gap, result["request_id"])
                except Exception:
                    service.research_store.transition(result["request_id"],
                                                      ResearchStatus.FAILED,
                                                      error_code="RESEARCH_FAILED")
                    service.logger.error("research_failed")
                finally:
                    with service._research_lock:
                        service._research_threads.pop(result["request_id"], None)

            thread = Thread(target=work, name="research-" + result["request_id"][-8:], daemon=True)
            service._research_threads[result["request_id"]] = thread
            thread.start()
        return jsonify(result), 202

    @app.post("/v1/research/<package_id>/requests")
    def research_start(package_id: str):
        data = _body(frozenset({"gap_ref", "external", "budget"}))
        gap_ref = data.get("gap_ref")
        if not isinstance(gap_ref, str):
            raise ValueError("invalid gap reference")
        external = data.get("external", False)
        if type(external) is not bool:
            raise ValueError("invalid external flag")
        raw_budget = data.get("budget", {})
        if not isinstance(raw_budget, dict):
            raise ValueError("invalid research budget")
        if set(raw_budget) - set(ResearchBudget.__dataclass_fields__):
            raise ValueError("invalid research budget")
        budget = ResearchBudget(**raw_budget)
        return _start_research(package_id, gap_ref, refresh=False, external=external, budget=budget)

    @app.post("/v1/research/<package_id>/briefs/<brief_id>/refresh")
    def research_refresh(package_id: str, brief_id: str):
        data = _body(frozenset({"external"}))
        if type(data.get("external", False)) is not bool:
            raise ValueError("invalid external flag")
        package = service.package(package_id)
        brief = service.research_store.brief(package.target.id, brief_id)
        if brief is None:
            raise LookupError("research brief not found")
        if brief["freshness"] == "FRESH":
            raise ValueError("only stale research may be refreshed")
        previous = service.research_store.request(package.target.id, brief["request_id"])
        if previous is None:
            raise LookupError("research request not found")
        return _start_research(package_id, previous["gap_ref"], refresh=True,
                               external=data.get("external", False),
                               budget=ResearchBudget())

    @app.post("/v1/research/<package_id>/requests/<request_id>/cancel")
    def research_cancel(package_id: str, request_id: str):
        _body(frozenset())
        package = service.package(package_id)
        if not service.research_store.cancel(package.target.id, request_id):
            raise LookupError("active research request not found")
        return jsonify({"request_id": request_id, "status": "CANCELLED"})

    @app.get("/v1/campaigns")
    def campaign_list():
        page = PageRequest.parse(maximum=50)
        package_id = request.args.get("target")
        target_id = service.package(package_id).target.id if package_id else None
        campaigns = service.campaign.store.list(target_id=target_id,
                                                limit=page.limit, before=page.cursor)
        counts = service.campaign.store.finding_counts(tuple(item.id for item in campaigns))
        return jsonify({"items": [{**item.to_dict(), "finding_count": counts.get(item.id, 0)}
                                  for item in campaigns]})

    @app.get("/v1/continuous/status")
    def continuous_status():
        return jsonify({"mode": "explicit_opt_in", **service.delta.deltas.stats()})

    @app.get("/v1/continuous/targets/<package_id>")
    def continuous_target(package_id: str):
        package = service.package(package_id)
        state = service.delta.deltas.get(package.target.id)
        return jsonify(state or {"target_id": package.target.id,
                                 "enabled": False, "status": "DISABLED",
                                 "settings": ContinuousSettings().to_dict()})

    @app.post("/v1/continuous/targets/<package_id>/settings")
    def continuous_settings(package_id: str):
        package = service.package(package_id)
        data = _body(frozenset({"enabled", "cadence", "minimum_relevance",
                                "cooldown_seconds", "daily_campaign_cap",
                                "request_cap", "allowed_specialists"}))
        current = service.delta.deltas.settings(package.target.id) or ContinuousSettings()
        values = current.to_dict()
        values.update(data)
        values["cadence"] = DeltaCadence(values["cadence"])
        if not isinstance(values["allowed_specialists"], list):
            raise ValueError("Invalid continuous specialists")
        values["allowed_specialists"] = tuple(
            Specialist(item) for item in values["allowed_specialists"])
        return jsonify(service.delta.deltas.configure(package, ContinuousSettings(**values)))

    @app.post("/v1/continuous/targets/<package_id>/pause")
    def continuous_pause(package_id: str):
        _body(frozenset())
        return jsonify(service.delta.deltas.pause(service.package(package_id)))

    @app.post("/v1/continuous/targets/<package_id>/resume")
    def continuous_resume(package_id: str):
        _body(frozenset())
        return jsonify(service.delta.deltas.resume(service.package(package_id)))

    @app.post("/v1/continuous/targets/<package_id>/check")
    def continuous_check(package_id: str):
        _body(frozenset())
        return jsonify(service.delta.check(service.package(package_id)))

    @app.get("/v1/deltas")
    def delta_list():
        page = PageRequest.parse(maximum=100)
        package_id = request.args.get("target")
        target_id = service.package(package_id).target.id if package_id else None
        raw_status = request.args.get("status")
        status_filter = DeltaStatus(raw_status) if raw_status else None
        return jsonify(service.delta.deltas.page_candidates(
            target_id=target_id, status=status_filter, limit=page.limit,
            before=page.cursor))

    @app.get("/v1/deltas/<delta_id>")
    def delta_detail(delta_id: str):
        package_id = request.args.get("target")
        if not package_id:
            raise ValueError("Delta detail requires a target")
        package = service.package(package_id)
        item = service.delta.deltas.get_candidate(package.target.id, delta_id)
        if item is None:
            raise LookupError("Delta not found")
        item["hypothesis_ids"] = service.delta.deltas.hypothesis_ids(
            package.target.id, delta_id)
        return jsonify(item)

    @app.post("/v1/deltas/<delta_id>/campaigns")
    def delta_campaign_start(delta_id: str):
        data = _body(frozenset({"target", "mode"}))
        package_id = data.get("target")
        if not isinstance(package_id, str):
            raise ValueError("Focused campaign requires a target")
        mode = PlannerMode(data.get("mode", PlannerMode.ANALYZE_ONLY.value))
        result = service.delta.start_selected(service.package(package_id),
                                              delta_id, mode=mode)
        return jsonify(result), 201 if result["campaign_id"] else 200

    @app.post("/v1/campaigns")
    def campaign_start():
        payload = _body(frozenset({"target", "mode", "preset", "limits"}))
        package_id = payload.get("target")
        if not isinstance(package_id, str):
            raise ValueError("Campaign target is required")
        package = service.package(package_id)
        mode = PlannerMode(payload.get("mode", PlannerMode.ANALYZE_ONLY.value))
        preset = CampaignPreset(payload.get("preset", CampaignPreset.SMALL.value))
        if preset is CampaignPreset.CUSTOM:
            raw = payload.get("limits")
            if (not isinstance(raw, dict) or
                    set(raw) != set(CampaignLimits.__dataclass_fields__)):
                raise ValueError("Custom campaign limits require every field")
            limits = CampaignLimits(**raw)
        else:
            if "limits" in payload:
                raise ValueError("Preset limits cannot be overridden")
            limits = CampaignLimits.preset(preset)
        campaign = service.campaign.start(package, mode=mode, limits=limits,
                                          requested_by="dashboard")
        try:
            service.launch_campaign(package.id, campaign.id)
        except ResourceError as exc:
            campaign = service.campaign.store.transition(
                campaign.target_id, campaign.id, CampaignStatus.PAUSED,
                exc.reason_code)
        return jsonify(campaign.to_dict()), 201

    def campaign_package(campaign_id: str) -> TargetPackage:
        campaign = service.campaign.store.find(campaign_id)
        if campaign is None:
            raise LookupError("Campaign not found")
        package = service.package(campaign.package_id)
        if package.target.id != campaign.target_id:
            raise LookupError("Campaign target mismatch")
        return package

    @app.get("/v1/campaigns/<campaign_id>")
    def campaign_detail(campaign_id: str):
        package = campaign_package(campaign_id)
        return jsonify(service.campaign.detail(package, campaign_id))

    @app.post("/v1/campaigns/<campaign_id>/pause")
    def campaign_pause(campaign_id: str):
        _body(frozenset())
        package = campaign_package(campaign_id)
        with service._campaign_lock:
            result = service.campaign.pause(package, campaign_id)
        return jsonify(result.to_dict())

    @app.post("/v1/campaigns/<campaign_id>/resume")
    def campaign_resume(campaign_id: str):
        _body(frozenset())
        package = campaign_package(campaign_id)
        with service._campaign_lock:
            result = service.campaign.resume(package, campaign_id)
        if result.status in {CampaignStatus.RUNNING, CampaignStatus.ASSESSING_READINESS}:
            service.launch_campaign(package.id, campaign_id)
        return jsonify(result.to_dict())

    @app.post("/v1/campaigns/<campaign_id>/cancel")
    def campaign_cancel(campaign_id: str):
        _body(frozenset())
        package = campaign_package(campaign_id)
        with service._campaign_lock:
            result = service.campaign.cancel(package, campaign_id)
        return jsonify(result.to_dict())

    @app.get("/v1/planner/<package_id>/runs")
    def planner_runs(package_id: str):
        package = service.package(package_id)
        page = PageRequest.parse(maximum=50)
        if page.cursor:
            raise ValueError("planner run cursor is not supported")
        return jsonify({"items": [item.to_dict() for item in
                        service.planner_store.list(package.target.id, limit=page.limit)]})

    @app.post("/v1/planner/<package_id>/runs")
    def planner_start(package_id: str):
        package = service.package(package_id)
        payload = _body(frozenset({"mode", "limits"}))
        mode = PlannerMode(payload.get("mode", PlannerMode.ANALYZE_ONLY.value))
        raw_limits = payload.get("limits", {})
        if not isinstance(raw_limits, dict) or set(raw_limits) - set(PlannerLimits.__dataclass_fields__):
            raise ValueError("invalid planner limits")
        limits = PlannerLimits(**raw_limits)
        service.resources.admit(WorkKind.PLANNER,
                                active=sum(thread.is_alive() for thread in service._planner_threads.values()))
        run = service.planner.start(package, mode=mode, limits=limits)
        if mode is not PlannerMode.ANALYZE_ONLY:
            service.launch_planner(package.id, run.id)
        return jsonify(run.to_dict()), 201

    @app.get("/v1/planner/<package_id>/runs/<run_id>")
    def planner_detail(package_id: str, run_id: str):
        package = service.package(package_id)
        run = service.planner_store.get(package.target.id, run_id)
        if run is None:
            raise LookupError("planner run not found")
        candidates = service.planner_store.candidates(package.target.id, run_id,
                                                       limit=min(200, run.limits.portfolio))
        tasks = service.planner_store.tasks(package.target.id, run_id, limit=MAX_RUN_TASKS)
        login_requirements = []
        for item in tasks:
            if item.reason_code != "LOGIN_REQUIRED" or not item.result_ref:
                continue
            identity_id = item.result_ref if item.result_ref.startswith("IDENTITY-") else None
            if item.result_ref.startswith("TESTOBJ-"):
                owned = service.objects.get(item.result_ref, package.target.id)
                if owned is not None and owned.package_id == package.id:
                    identity_id = owned.creator_identity_id
            identity = (service.registry.get_identity(package.target.id, identity_id)
                        if identity_id else None)
            if identity is not None:
                login_requirements.append({"task_id": item.id, "identity_id": identity.id,
                                           "account_alias": identity.alias})
        research_briefs = tuple(dict.fromkeys(
            item.result_ref for item in tasks
            if item.result_ref and item.result_ref.startswith("RBRF-") and (
                item.task_type.value == "REQUEST_RESEARCH" and item.status.value == "COMPLETED"
                or item.task_type.value == "CREATE_PLAN" and item.status.value == "WAITING")))
        return jsonify({"run": run.to_dict(),
                        "metrics": service.planner_store.metrics(package.target.id, run_id),
                        "candidates": [item.to_dict() for item in candidates],
                        "tasks": [item.to_dict() for item in tasks],
                        "login_requirements": login_requirements,
                        "events": service.planner_store.events(package.target.id, run_id, limit=50),
                        "findings": [item.finding_id for item in candidates if item.finding_id],
                        "research_briefs": research_briefs})

    @app.post("/v1/planner/<package_id>/runs/<run_id>/advance")
    def planner_advance(package_id: str, run_id: str):
        _body(frozenset())
        package = service.package(package_id)
        with service._planner_lock:
            result = service.planner_runner.advance(package, run_id)
            service.record_planner_notification(package.target.id, run_id, result)
        return jsonify(result)

    @app.post("/v1/planner/<package_id>/runs/<run_id>/pause")
    def planner_pause(package_id: str, run_id: str):
        _body(frozenset())
        package = service.package(package_id)
        with service._planner_lock:
            run = service.planner_runner.pause(package, run_id)
        return jsonify(run.to_dict())

    @app.post("/v1/planner/<package_id>/runs/<run_id>/resume")
    def planner_resume(package_id: str, run_id: str):
        _body(frozenset())
        package = service.package(package_id)
        with service._planner_lock:
            run = service.planner_runner.resume(package, run_id)
        if run.status.value in {"READY", "RUNNING"}:
            service.launch_planner(package.id, run_id)
        return jsonify(run.to_dict())

    @app.post("/v1/planner/<package_id>/runs/<run_id>/cancel")
    def planner_cancel(package_id: str, run_id: str):
        _body(frozenset())
        package = service.package(package_id)
        with service._planner_lock:
            run = service.planner_runner.cancel(package, run_id)
        return jsonify(run.to_dict())

    @app.get("/v1/planner/<package_id>/runs/<run_id>/candidates")
    def planner_candidates(package_id: str, run_id: str):
        package = service.package(package_id)
        if service.planner_store.get(package.target.id, run_id) is None:
            raise LookupError("planner run not found")
        return jsonify({"items": [item.to_dict() for item in
                        service.planner_store.candidates(package.target.id, run_id, limit=200)]})

    @app.get("/v1/planner/<package_id>/runs/<run_id>/candidates/<candidate_id>/relationships")
    def planner_relationships(package_id: str, run_id: str, candidate_id: str):
        package = service.package(package_id)
        if service.planner_store.candidate(package.target.id, run_id, candidate_id) is None:
            raise LookupError("planner candidate not found")
        return jsonify({"items": service.planner_store.relationships(
            package.target.id, run_id, candidate_id)})

    @app.get("/v1/planner/<package_id>/runs/<run_id>/tasks")
    def planner_tasks(package_id: str, run_id: str):
        package = service.package(package_id)
        if service.planner_store.get(package.target.id, run_id) is None:
            raise LookupError("planner run not found")
        return jsonify({"items": [item.to_dict() for item in
                        service.planner_store.tasks(package.target.id, run_id, limit=MAX_RUN_TASKS)]})

    @app.post("/v1/planner/<package_id>/runs/<run_id>/candidates/<candidate_id>/override")
    def planner_override(package_id: str, run_id: str, candidate_id: str):
        payload = _body(frozenset({"choice", "specialist", "skill_id"}))
        choice = CandidateOverride(payload["choice"])
        specialist = Specialist(payload["specialist"]) if payload.get("specialist") else None
        skill_id = payload.get("skill_id")
        if skill_id is not None and not isinstance(skill_id, str):
            raise ValueError("invalid skill override")
        package = service.package(package_id)
        with service._planner_lock:
            item = service.planner_runner.override(package, run_id, candidate_id, choice,
                                                   specialist=specialist, skill_id=skill_id)
        return jsonify(item.to_dict())

    @app.get("/v1/api/<package_id>/coverage")
    def api_coverage(package_id: str):
        package = service.package(package_id)
        counts = service.api_operations.counts(package.target.id)
        types = service.api_operations.operation_type_counts(package.target.id)
        progress = service.api_operations.progress(package.target.id, package.id)
        return jsonify({"counts": counts, "metrics": service.api_operations.metrics(package.target.id),
                        "queries": types.get("GRAPHQL_QUERY", 0),
                        "mutations": types.get("GRAPHQL_MUTATION", 0),
                        "surface_types": sorted(types),
                        "inventory_more": {"traffic": progress.traffic_cursor is not None,
                                           "js": progress.js_cursor is not None,
                                           "operations": progress.operation_cursor is not None},
                        "coverage_note": "Observed and current-JS operations only; schema coverage is not exhaustive."})

    @app.get("/v1/api/<package_id>/operations")
    def api_operations(package_id: str):
        package = service.package(package_id)
        page = PageRequest.parse()
        state = request.args.get("state", "CURRENT")
        items, next_cursor = service.api_operations.page_operations(
            package.target.id, limit=page.limit, state=state, cursor=page.cursor)
        return jsonify({"items": [item.to_dict() for item in items],
                        "next_cursor": next_cursor})

    @app.get("/v1/api/<package_id>/operations/<operation_id>")
    def api_operation_detail(package_id: str, operation_id: str):
        package = service.package(package_id)
        item = service.api_operations.get_operation(package.target.id, operation_id)
        if item is None:
            raise LookupError("API operation not found")
        candidates, next_cursor = service.api_operations.page_candidates(
            package.target.id, limit=50, operation_id=item.id)
        return jsonify({"operation": item.to_dict(),
                        "candidates": [entry.to_dict() for entry in candidates],
                        "next_cursor": next_cursor})

    @app.get("/v1/api/<package_id>/candidates")
    def api_candidates(package_id: str):
        package = service.package(package_id)
        page = PageRequest.parse()
        operation_id = request.args.get("operation_id")
        if operation_id and service.api_operations.get_operation(package.target.id,
                                                                  operation_id) is None:
            raise LookupError("API operation not found")
        items, next_cursor = service.api_operations.page_candidates(
            package.target.id, limit=page.limit, cursor=page.cursor,
            operation_id=operation_id)
        return jsonify({"items": [item.to_dict() for item in items],
                        "next_cursor": next_cursor})

    @app.get("/v1/api/<package_id>/candidates/<candidate_id>")
    def api_candidate_detail(package_id: str, candidate_id: str):
        package = service.package(package_id)
        item = service.api_operations.get_candidate(package.target.id, candidate_id)
        if item is None:
            raise LookupError("API candidate not found")
        operation = service.api_operations.get_operation(package.target.id, item.operation_id)
        return jsonify({"candidate": item.to_dict(),
                        "operation": operation.to_dict() if operation else None})

    @app.post("/v1/api/<package_id>/analyze")
    def api_analyze(package_id: str):
        package = service.package(package_id)
        body = _body(frozenset({"limits", "mode", "operation_id"}))
        raw_limits = body.get("limits") or {}
        if not isinstance(raw_limits, dict) or set(raw_limits) - set(APIAnalysisLimits.__dataclass_fields__):
            raise ValueError("Invalid API analysis limits")
        limits = APIAnalysisLimits(**raw_limits)
        mode = body.get("mode", "PLAN_ONLY")
        operation_id = body.get("operation_id")
        if operation_id is not None and not isinstance(operation_id, str):
            raise ValueError("Invalid API operation ID")
        candidates = service.api.generate(package, limits=limits, mode=mode,
                                          operation_id=operation_id)
        return jsonify({"items": [item.to_dict() for item in candidates],
                        "coverage": service.api_operations.counts(package.target.id)}), 201

    @app.post("/v1/api/<package_id>/candidates/<candidate_id>/prepare")
    def api_prepare_candidate(package_id: str, candidate_id: str):
        package = service.package(package_id)
        _body(frozenset())
        return jsonify(service.api.prepare_candidate(package, candidate_id).to_dict())

    @app.post("/v1/api/<package_id>/candidates/<candidate_id>/start")
    def api_start_candidate(package_id: str, candidate_id: str):
        package = service.package(package_id)
        _body(frozenset())
        return jsonify(service.api.start_candidate(package, candidate_id)), 201

    @app.post("/v1/api/<package_id>/candidates/<candidate_id>/advance")
    def api_advance_candidate(package_id: str, candidate_id: str):
        package = service.package(package_id)
        _body(frozenset())
        return jsonify(service.api.advance_candidate(package, candidate_id))

    @app.get("/v1/authorization/<package_id>/profile")
    def authorization_profile(package_id: str):
        package = service.package(package_id)
        return jsonify(service.authorization.profile(package).to_dict())

    @app.get("/v1/authorization/<package_id>/hunts")
    def authorization_hunts(package_id: str):
        package = service.package(package_id)
        page = PageRequest.parse()
        return jsonify({"items": [item.to_dict() for item in
                                  service.authorization_ledger.list_hunts(package.target.id,
                                                                          limit=page.limit)]})

    @app.post("/v1/authorization/<package_id>/hunts")
    def start_authorization_hunt(package_id: str):
        body = _body(frozenset({"mode", "candidate_limit", "request_budget"}))
        package = service.package(package_id)
        mode = AuthorizationMode(body.get("mode", "PLAN_ONLY"))
        return jsonify(service.authorization.start_hunt(
            package, mode=mode, candidate_limit=body.get("candidate_limit", 12),
            request_budget=body.get("request_budget", 20))), 201

    @app.get("/v1/authorization/<package_id>/candidates")
    def authorization_candidates(package_id: str):
        package = service.package(package_id)
        page = PageRequest.parse()
        hunt_id = request.args.get("hunt_id")
        if hunt_id and service.authorization_ledger.get_hunt(hunt_id, package.target.id) is None:
            raise LookupError("authorization hunt not found")
        items = []
        for item in service.authorization_ledger.list_candidates(
                package.target.id, limit=page.limit, hunt_id=hunt_id):
            row = item.to_dict()
            exchange = service.traffic.get_exchange(item.owner_exchange_id)
            row["evidence_ids"] = (list(exchange.evidence_ids[:4]) if exchange is not None and
                                   exchange.target_id == package.target.id else [])
            method = exchange.request.record.method if exchange is not None else None
            row["test_type"] = (
                "NESTED_READ" if item.boundary.value == "PARENT_CHILD" else
                "BATCH_READ" if "BATCH_READ_EXACT_OBSERVED" in item.reasons else
                "TYPED_MUTATION" if method in {"PATCH", "PUT"} or
                item.boundary.value == "GRAPHQL_MUTATION" else "SINGLE_OBJECT_READ")
            records = (service.mutation_results.list_for_run(item.run_id, package.target.id)
                       if item.run_id else ())
            phases = {entry.phase: entry for entry in records}
            row["owner_readback_status"] = (phases[MutationPhase.OWNER_CONTROL].status.value
                                            if MutationPhase.OWNER_CONTROL in phases else None)
            row["readback_status"] = (phases[MutationPhase.BOUNDARY].status.value
                                      if MutationPhase.BOUNDARY in phases else None)
            row["restore_status"] = (phases[MutationPhase.RESTORE].status.value
                                     if MutationPhase.RESTORE in phases else None)
            items.append(row)
        return jsonify({"items": items})

    @app.get("/v1/authorization/<package_id>/matrix")
    def authorization_matrix(package_id: str):
        package = service.package(package_id)
        page = PageRequest.parse(maximum=100)
        return jsonify({"items": list(service.authorization_ledger.matrix(
            package.target.id, limit=page.limit))})

    @app.get("/v1/authorization/<package_id>/metrics")
    def authorization_metrics(package_id: str):
        package = service.package(package_id)
        metrics = service.authorization_ledger.stats(
            package.target.id, hunt_id=request.args.get("hunt_id") or None)
        metrics["typed_mutations"] = service.mutation_results.stats(package.target.id)
        with service.store._connection() as db:
            rows = db.execute("SELECT sum(boundary='PARENT_CHILD') AS nested,"
                              "sum(reasons_json LIKE '%BATCH_READ_EXACT_OBSERVED%') AS batch "
                              "FROM authorization_candidates WHERE target_id=?",
                              (package.target.id,)).fetchone()
            mutation_candidates = db.execute(
                "SELECT count(*) FROM authorization_candidates c "
                "JOIN traffic_exchanges e ON e.exchange_id=c.owner_exchange_id "
                "JOIN traffic_requests r ON r.request_id=e.request_id "
                "WHERE c.target_id=? AND (r.method IN ('PATCH','PUT') OR "
                "c.boundary='GRAPHQL_MUTATION')",
                (package.target.id,)).fetchone()[0]
            mutation_plans = db.execute(
                "SELECT count(*) FROM authorization_candidates c JOIN skill_plans p "
                "ON p.plan_id=c.plan_id WHERE c.target_id=? AND "
                "p.skill_id='typed-authorization-mutation'",
                (package.target.id,)).fetchone()[0]
        metrics["nested_candidates"] = rows["nested"] or 0
        metrics["batch_candidates"] = rows["batch"] or 0
        metrics["mutation_candidates"] = mutation_candidates
        metrics["mutation_plans"] = mutation_plans
        return jsonify(metrics)

    @app.post("/v1/authorization/<package_id>/candidates/<candidate_id>/prepare")
    def prepare_authorization_candidate(package_id: str, candidate_id: str):
        _body(frozenset())
        package = service.package(package_id)
        return jsonify(service.authorization.prepare(candidate_id, package).to_dict())

    @app.post("/v1/authorization/<package_id>/candidates/<candidate_id>/start")
    def run_authorization_candidate(package_id: str, candidate_id: str):
        _body(frozenset())
        package = service.package(package_id)
        return jsonify(service.authorization.start_candidate(candidate_id, package)), 201

    @app.post("/v1/authorization/<package_id>/candidates/<candidate_id>/advance")
    def advance_authorization_candidate(package_id: str, candidate_id: str):
        _body(frozenset())
        package = service.package(package_id)
        return jsonify(service.authorization.advance_candidate(candidate_id, package))

    @app.post("/v1/authorization/<package_id>/hunts/<hunt_id>/pause")
    @app.post("/v1/authorization/<package_id>/hunts/<hunt_id>/cancel")
    def stop_authorization_hunt(package_id: str, hunt_id: str):
        _body(frozenset())
        package = service.package(package_id)
        hunt = service.authorization_ledger.get_hunt(hunt_id, package.target.id)
        if hunt is None or hunt.status not in {HuntStatus.READY, HuntStatus.RUNNING,
                                                HuntStatus.PAUSED}:
            raise ValueError("authorization hunt is not active")
        cancel = request.path.endswith("/cancel")
        for candidate in service.authorization_ledger.list_candidates(package.target.id,
                                                                        hunt_id=hunt_id, limit=50):
            if candidate.hunt_id != hunt_id or not candidate.run_id:
                continue
            run = service.run_store.get(candidate.run_id, package.target.id)
            if run and run.status in {RunStatus.CREATED, RunStatus.READY, RunStatus.RUNNING,
                                      RunStatus.WAITING_APPROVAL, RunStatus.WAITING_HUMAN}:
                (service.orchestrator.cancel if cancel else service.orchestrator.pause)(
                    run.id, package.id)
        target_status = HuntStatus.CANCELLED if cancel else HuntStatus.PAUSED
        updated = service.authorization_ledger.transition(
            hunt.id, hunt.target_id, hunt.status, target_status)
        if cancel:
            service.authorization.cleanup_created_objects(hunt.id, hunt.target_id)
        return jsonify(updated.to_dict())

    @app.post("/v1/targets/<package_id>/profile")
    def profile_target(package_id: str):
        _body(frozenset())
        package = service.package(package_id)
        profile = AttackSurfaceProfiler(service.registry, service.store, service.traffic,
                                        service.recon, bootstrap=service.bootstrap_store).profile(package)
        service.hypotheses.save_profile(profile)
        generated = HypothesisGenerator(service.hypotheses).generate(profile)
        service.logger.info("passive_profile_completed", extra={"context": {
            "target_id": package.target.id, "signals": len(profile.signals),
            "hypotheses": len(generated)}})
        return jsonify({"profile": profile.to_dict(), "hypotheses_generated": len(generated)})

    @app.get("/v1/hypotheses")
    def hypotheses():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse()
        return jsonify(service.hypotheses.list(package.target.id, limit=page.limit,
                      cursor=page.cursor, status=request.args.get("status"),
                      category=request.args.get("category")))

    @app.get("/v1/hypotheses/<hypothesis_id>")
    def hypothesis_detail(hypothesis_id: str):
        package = service.package(request.args.get("target", ""))
        item = service.hypotheses.get(hypothesis_id, package.target.id)
        if item is None:
            raise LookupError("hypothesis not found")
        profile = service.hypotheses.latest_profile(package.target.id)
        context = service.skill_context.build(item, profile, package)
        return jsonify({"hypothesis": item.to_dict(),
                        "context": ContextPacketBuilder(service.hypotheses).build(
                            item, profile),
                        "recommended_skills": service.skill_router.route(item, context),
                        "history": service.hypotheses.history(item.id, package.target.id),
                        "relationships": service.hypotheses.relationships(item.id, package.target.id)})

    @app.get("/v1/skills")
    def skills_list():
        counts = service.skill_plans.usage_counts()
        return jsonify({"items": [{**skill.to_dict(), "usage_count": counts.get(skill.name, 0),
                                   "validation_outcomes": service.skill_plans.outcome_counts(skill.name),
                                   "status": "PLAN_ONLY"} for skill in service.skills.discover()]})

    @app.get("/v1/skills/<skill_id>")
    def skill_detail(skill_id: str):
        detail = service.skills.select(skill_id).detail()
        detail["usage_count"] = service.skill_plans.usage_counts().get(skill_id, 0)
        detail["validation_outcomes"] = service.skill_plans.outcome_counts(skill_id)
        return jsonify(detail)

    @app.post("/v1/hypotheses/<hypothesis_id>/skills/route")
    def route_skill(hypothesis_id: str):
        body = _body(frozenset({"target"}))
        package = service.package(body.get("target", ""))
        item = service.hypotheses.get(hypothesis_id, package.target.id)
        if item is None:
            raise LookupError("hypothesis not found")
        context = service.skill_context.build(item, service.hypotheses.latest_profile(package.target.id), package)
        return jsonify({"hypothesis_id": item.id, "candidates": service.skill_router.route(item, context),
                        "simulation_only": True})

    @app.post("/v1/hypotheses/<hypothesis_id>/plan")
    def create_skill_plan(hypothesis_id: str):
        body = _body(frozenset({"target", "skill_id", "regenerate", "selection"}))
        package = service.package(body.get("target", ""))
        item = service.hypotheses.get(hypothesis_id, package.target.id)
        if item is None:
            raise LookupError("hypothesis not found")
        profile = service.hypotheses.latest_profile(package.target.id)
        context = service.skill_context.build(item, profile, package)
        selected = body.get("skill_id")
        selection = body.get("selection", "AUTO")
        if selection not in {"AUTO", "RECOMMENDED", "MANUAL"}:
            raise ValueError("invalid skill selection")
        manual = selection == "MANUAL"
        if selected is None:
            if selection != "AUTO":
                raise ValueError("skill selection requires an ID")
            ranked = service.skill_router.route(item, context, limit=1)
            if not ranked:
                raise ValueError("no relevant skill")
            selected = ranked[0]["skill"]["name"]
        elif selection == "RECOMMENDED" and selected not in {
            candidate["skill"]["name"] for candidate in service.skill_router.route(item, context)
        }:
            raise ValueError("skill is not a current recommendation")
        elif selection == "AUTO":
            raise ValueError("explicit skill requires a selection type")
        if not isinstance(selected, str) or not isinstance(body.get("regenerate", False), bool):
            raise ValueError("invalid plan request")
        context = service.skill_context.build(item, profile, package, service.skills.metadata(selected))
        plan = service.skill_planner.generate(package, item, context, selected,
                                               manual_selection=manual,
                                               regenerate=body.get("regenerate", False))
        return jsonify(plan), 201

    @app.get("/v1/plans/<plan_id>")
    def skill_plan_detail(plan_id: str):
        package = service.package(request.args.get("target", ""))
        plan = service.skill_plans.get(plan_id, package.target.id)
        if plan is None:
            raise LookupError("plan not found")
        return jsonify(plan)

    @app.get("/v1/plans/<plan_id>/objects")
    def plan_objects(plan_id: str):
        package = service.package(request.args.get("target", ""))
        service.run_store.snapshot(plan_id, package.target.id)
        return jsonify({"items": service.objects.requirements(plan_id, package.target.id)})

    @app.post("/v1/plans/<plan_id>/objects")
    def add_plan_object(plan_id: str):
        body = _body(frozenset({"target", "recipe_id", "identity_id", "tenant_id", "parent_id"}))
        package = service.package(body.get("target", ""))
        service.run_store.snapshot(plan_id, package.target.id)
        recipe = service.object_factory.recipes.get(package.id, body.get("recipe_id", ""))
        if recipe is None or recipe.target_id != package.target.id:
            raise ValueError("known object recipe required")
        requirement_id = service.objects.add_requirement(
            plan_id=plan_id, target_id=package.target.id, object_type=recipe.object_type,
            recipe_id=recipe.id, identity_id=body.get("identity_id", ""),
            tenant_id=body.get("tenant_id", ""), parent_id=body.get("parent_id"))
        return jsonify({"requirement_id": requirement_id}), 201

    @app.post("/v1/plans/<plan_id>/runs")
    def start_plan_run(plan_id: str):
        body = _body(frozenset({"target", "rerun"}))
        if type(body.get("rerun", False)) is not bool:
            raise ValueError("invalid rerun option")
        package = service.package(body.get("target", ""))
        with service.store._connection() as db:
            active = db.execute("SELECT count(*) FROM plan_runs WHERE status NOT IN "
                                "('COMPLETED','REJECTED','FAILED','BUDGET_EXHAUSTED','CANCELLED')").fetchone()[0]
        service.resources.admit(WorkKind.PLAN, active=active)
        return jsonify(service.orchestrator.start(plan_id, package.id,
                                                 rerun=body.get("rerun", False))), 201

    @app.get("/v1/plans/<plan_id>/runs")
    def list_plan_runs_for_plan(plan_id: str):
        package = service.package(request.args.get("target", ""))
        if service.skill_plans.get(plan_id, package.target.id) is None:
            raise LookupError("plan not found")
        page = PageRequest.parse()
        return jsonify(service.run_store.list_for_plan(plan_id, package.target.id,
                                                       limit=page.limit, cursor=page.cursor))

    @app.get("/v1/runs")
    def list_plan_runs():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse()
        return jsonify(service.run_store.list(package.target.id, limit=page.limit,
                                             cursor=page.cursor))

    @app.get("/v1/runs/<run_id>")
    def show_plan_run(run_id: str):
        package = service.package(request.args.get("target", ""))
        detail = service.orchestrator.detail(run_id, package.id)
        latest = service.validations.latest_for_run(run_id, package.target.id)
        detail["validation"] = latest.to_dict() if latest else None
        detail["run"]["finding_status"] = (latest.status.value if latest else
                                               "READY_FOR_VALIDATION" if detail["run"]["status"] == "COMPLETED"
                                               else "UNVALIDATED")
        records = service.mutation_results.list_for_run(run_id, package.target.id)
        detail["mutation_results"] = [item.to_dict() for item in records]
        detail["mutation_cleanup_status"] = (
            "RESTORED" if any(item.phase.value == "RESTORE" and item.verified_effect
                              for item in records) else
            "REVIEW_REQUIRED" if any(item.verified_effect for item in records) else
            "NOT_APPLICABLE")
        detail["mutation_approval"] = None
        if detail["run"]["skill_id"] == "typed-authorization-mutation":
            plan = service.run_store.snapshot(detail["run"]["plan_id"], package.target.id).data
            shapes = plan.get("request_templates", [])
            actions = plan.get("proposed_actions", [])
            if len(shapes) == 7 and len(actions) == 7:
                shape = shapes[0]
                item = service.objects.get(shape.get("test_object_id", ""), package.target.id)
                recipe = (service.object_factory.recipes.get(package.id, item.recipe_id)
                          if item is not None else None)
                mutation = (next((entry for entry in recipe.mutations
                                  if entry.mutation_type.value == shape.get("mutation_type")), None)
                            if recipe is not None and recipe.sha256 == item.recipe_hash else None)
                if item is not None and mutation is not None:
                    next_value = TypedMutation.test_value(run_id, item.id, MutationPhase.BOUNDARY)
                    detail["mutation_approval"] = {
                        "object_id": item.id, "object_type": item.object_type,
                        "disposable": item.disposable, "object_state": item.state.value,
                        "field": mutation.field, "action": mutation.mutation_type.value,
                        "old_summary": "sha256:" + value_hash(item.test_name)[:12],
                        "new_summary": "sha256:" + value_hash(next_value)[:12],
                        "acting_identity_id": actions[3].get("identity_id"),
                        "risk": plan.get("risk"), "cleanup_strategy": "RESTORE",
                        "recipe_current": recipe.sha256 == shape.get("recipe_hash"),
                    }
        return jsonify(detail)

    @app.post("/v1/runs/<run_id>/validate")
    def validate_plan_run(run_id: str):
        body = _body(frozenset({"target"}))
        package = service.package(body.get("target", ""))
        run = service.run_store.get(run_id, package.target.id)
        if run is None:
            raise LookupError("run not found")
        if run.status is not RunStatus.COMPLETED:
            raise ValueError("only completed runs may be validated")
        service.audit("validation_started", target_id=package.target.id)
        result, finding = service.validator.validate_run(run_id, package.target.id)
        event = {
            ValidationStatus.CONFIRMED: "validation_confirmed",
            ValidationStatus.REJECTED: "validation_rejected",
            ValidationStatus.NEEDS_MANUAL_REVIEW: "validation_review_required",
            ValidationStatus.INVALID_TEST: "validation_review_required",
            ValidationStatus.INSUFFICIENT_EVIDENCE: "validation_insufficient",
            ValidationStatus.DUPLICATE_CANDIDATE: "validation_duplicate",
        }[result.status]
        service.audit(event, target_id=package.target.id)
        if result.status is ValidationStatus.CONFIRMED and finding is not None:
            service.audit("finding_created", target_id=package.target.id)
        if result.status in {ValidationStatus.CONFIRMED, ValidationStatus.NEEDS_MANUAL_REVIEW}:
            wakeup = getattr(service, "_notification_wakeup", None)
            if wakeup is not None:
                wakeup.set()
        return jsonify({"validation": result.to_dict(),
                        "finding": finding.to_dict() if finding else None,
                        "request_sent": False})

    @app.get("/v1/validations")
    def list_validations():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse()
        raw = request.args.get("status")
        status = ValidationStatus(raw) if raw else None
        return jsonify(service.validations.list(package.target.id, limit=page.limit,
                                                cursor=page.cursor, status=status))

    @app.get("/v1/validations/<validation_id>")
    def validation_detail(validation_id: str):
        package = service.package(request.args.get("target", ""))
        result = service.validations.get(validation_id, package.target.id)
        if result is None:
            raise LookupError("validation not found")
        finding = service.validations.finding_for_validation(result.id, package.target.id)
        return jsonify({"validation": result.to_dict(),
                        "finding": finding.to_dict() if finding else None})

    @app.get("/v1/findings")
    def list_findings():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse()
        raw = request.args.get("status")
        status = FindingStatus(raw) if raw else None
        result = service.validations.list_findings(package.target.id, limit=page.limit,
                                                    cursor=page.cursor, status=status)
        for item in result["items"]:
            latest = service.report_store.latest(item["id"], package.target.id)
            attempt = service.report_store.latest_attempt(item["id"], package.target.id)
            item["latest_draft"] = latest.to_dict() if latest else None
            item["report_readiness"] = attempt["readiness"] if attempt else "NOT_GENERATED"
            with service.store._connection() as db:
                submission = db.execute("SELECT platform,external_report_id,submitted_at,"
                    "triage_status,reward_amount,reward_currency FROM finding_submission_metadata "
                    "WHERE finding_id=?", (item["id"],)).fetchone()
                notification = db.execute("SELECT d.status FROM notification_events e "
                    "LEFT JOIN notification_deliveries d ON d.event_id=e.event_id "
                    "WHERE e.finding_id=? AND e.event_type='CONFIRMED_FINDING' "
                    "ORDER BY d.sent_at DESC LIMIT 1", (item["id"],)).fetchone()
            item["submission"] = dict(submission) if submission else None
            item["notification_status"] = (notification[0] if notification and notification[0]
                                           else "NOT_CONFIGURED")
        return jsonify(result)

    @app.get("/v1/findings/<finding_id>")
    def finding_detail(finding_id: str):
        package = service.package(request.args.get("target", ""))
        finding = service.validations.get_finding(finding_id, package.target.id)
        if finding is None:
            raise LookupError("finding not found")
        result = service.validations.get(finding.validation_id, package.target.id)
        latest = service.report_store.latest(finding_id, package.target.id)
        attempt = service.report_store.latest_attempt(finding_id, package.target.id)
        return jsonify({"finding": finding.to_dict(),
                        "validation": result.to_dict() if result else None,
                        "workflow": service.workflow.detail(finding_id, package.target.id),
                        "latest_draft": latest.to_dict() if latest else None,
                        "report_attempt": attempt,
                        "notifications": service.notification_store.for_finding(
                            finding_id, package.target.id, limit=20)})

    @app.post("/v1/findings/<finding_id>/workflow")
    def finding_transition(finding_id: str):
        body = _body(frozenset({"target", "status", "expected_version", "actor_alias", "note",
                                "platform", "program", "external_report_id",
                                "external_duplicate_ref", "reward_amount", "reward_currency",
                                "triage_status"}))
        package = service.package(body.get("target", ""))
        status = FindingStatus(body.get("status", ""))
        result = service.workflow.transition(
            finding_id, package.target.id, status,
            expected_version=body.get("expected_version"),
            actor_alias=body.get("actor_alias"), note=body.get("note"),
            platform=body.get("platform"), program=body.get("program"),
            external_report_id=body.get("external_report_id"),
            external_duplicate_ref=body.get("external_duplicate_ref"),
            reward_amount=body.get("reward_amount"),
            reward_currency=body.get("reward_currency"),
            triage_status=body.get("triage_status"))
        service._notification_wakeup.set()
        return jsonify(result)

    @app.post("/v1/findings/<finding_id>/report")
    def generate_report(finding_id: str):
        body = _body(frozenset({"target"}))
        package = service.package(body.get("target", ""))
        return jsonify(service.report_generator.generate(finding_id, package.target.id).to_dict())

    @app.get("/v1/reports")
    def list_reports():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse()
        result = service.report_store.list(package.target.id, limit=page.limit,
                                           cursor=page.cursor)
        for item in result["items"]:
            finding = service.validations.get_finding(item["finding_id"], package.target.id)
            item["finding_title"] = finding.title if finding else None
            item["category"] = finding.category if finding else None
            item["workflow_state"] = finding.status.value if finding else None
        return jsonify(result)

    @app.get("/v1/reports/<report_id>")
    def report_detail(report_id: str):
        package = service.package(request.args.get("target", ""))
        draft = service.report_store.get(report_id, package.target.id)
        if draft is None:
            raise LookupError("report not found")
        return jsonify({"report": draft.to_dict(),
                        "markdown": service.report_store.markdown(report_id, package.target.id)})

    @app.get("/v1/reports/<report_id>/download")
    def download_report(report_id: str):
        package = service.package(request.args.get("target", ""))
        content = service.report_store.markdown(report_id, package.target.id)
        response = Response(content, content_type="text/plain; charset=utf-8")
        response.headers["Content-Disposition"] = f'attachment; filename="{report_id}.md"'
        return response

    @app.post("/v1/reports/<report_id>/edit")
    def edit_report(report_id: str):
        body = _body(frozenset({"target", "content", "expected_version", "researcher_reviewed"}))
        package = service.package(body.get("target", ""))
        draft = service.report_store.edit(
            report_id, package.target.id, body.get("content"),
            expected_version=body.get("expected_version"),
            researcher_reviewed=body.get("researcher_reviewed", False))
        return jsonify({"report": draft.to_dict()})

    @app.get("/v1/notifications/status")
    def notification_status():
        package = service.package(request.args.get("target", ""))
        return jsonify(service.notifications.status(package.target.id))

    @app.get("/v1/notifications")
    def notification_history():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse()
        return jsonify(service.notification_store.list_events(package.target.id,
                                                               limit=page.limit,
                                                               cursor=page.cursor))

    @app.post("/v1/notifications/test")
    def notification_test():
        body = _body(frozenset({"target"}))
        package = service.package(body.get("target", ""))
        event = service.notification_store.enqueue(
            target_id=package.target.id, event_type=NotificationType.TEST,
            source_kind="TEST", source_id="TEST-" + uuid.uuid4().hex,
            priority=NotificationPriority.LOW)
        service._notification_wakeup.set()
        return jsonify({"event": event.to_dict(), "label": "TEST"})

    @app.post("/v1/runs/<run_id>/advance")
    def advance_plan_run(run_id: str):
        body = _body(frozenset({"target"}))
        package = service.package(body.get("target", ""))
        return jsonify(service.orchestrator.advance(run_id, package.id))

    @app.post("/v1/runs/<run_id>/pause")
    def pause_plan_run(run_id: str):
        body = _body(frozenset({"target"}))
        package = service.package(body.get("target", ""))
        return jsonify(service.orchestrator.pause(run_id, package.id))

    @app.post("/v1/runs/<run_id>/resume")
    def resume_plan_run(run_id: str):
        body = _body(frozenset({"target"}))
        package = service.package(body.get("target", ""))
        return jsonify(service.orchestrator.resume(run_id, package.id))

    @app.post("/v1/runs/<run_id>/cancel")
    def cancel_plan_run(run_id: str):
        body = _body(frozenset({"target"}))
        package = service.package(body.get("target", ""))
        return jsonify(service.orchestrator.cancel(run_id, package.id))

    @app.post("/v1/runs/<run_id>/steps/<step_id>/complete")
    def complete_plan_run_step(run_id: str, step_id: str):
        body = _body(frozenset({"target", "evidence_ids", "exchange_id"}))
        if (not isinstance(body.get("evidence_ids", []), list) or
                any(not isinstance(item, str) for item in body.get("evidence_ids", [])) or
                body.get("exchange_id") is not None and not isinstance(body["exchange_id"], str)):
            raise ValueError("invalid evidence references")
        package = service.package(body.get("target", ""))
        return jsonify(service.orchestrator.complete_human_step(
            run_id, package.id, step_id, evidence_ids=tuple(body.get("evidence_ids", [])),
            exchange_id=body.get("exchange_id")))

    @app.post("/v1/hypotheses/manual")
    def manual_hypothesis():
        body = _body(frozenset({"target", "category", "statement", "future_experiment"}))
        package = service.package(body.get("target", ""))
        item = service.hypotheses.add_manual(package.target.id, body.get("category"),
                                             body.get("statement"), body.get("future_experiment"))
        return jsonify(item.to_dict()), 201

    @app.post("/v1/targets/<package_id>/import-identities")
    def import_identities(package_id: str):
        _body(frozenset())
        package = service.package(package_id)
        service.registry.register_target(package)
        service.audit("target_registered", target_id=package.target.id)
        identities = service.registry.import_package_accounts(package)
        service.audit("identities_imported", target_id=package.target.id)
        return jsonify({"imported": len(identities), "target_id": package.target.id}), 201

    @app.get("/v1/targets/<package_id>/identities")
    def identities(package_id: str):
        package = service.package(package_id)
        page = PageRequest.parse()
        result = service.registry.list_identities(package.target.id, limit=page.limit, cursor=page.cursor)
        return jsonify({"items": [service.identity_summary(package.target.id, item.id) for item in result.items],
                        "next_cursor": result.next_cursor})

    def scoped_identity(identity_id: str):
        package = service.package(request.args.get("target", ""))
        item = service.registry.get_identity(package.target.id, identity_id)
        if item is None:
            raise LookupError("identity not found")
        return package, item

    @app.get("/v1/identities/<identity_id>")
    def identity(identity_id: str):
        package, item = scoped_identity(identity_id)
        return jsonify(service.identity_summary(package.target.id, item.id))

    @app.get("/v1/identities/<identity_id>/auth-status")
    def auth_status(identity_id: str):
        package, item = scoped_identity(identity_id)
        context = service.auth.get(package.target.id, item.id)
        return jsonify({"identity_id": item.id, "auth": context.to_dict() if context else None})

    @app.post("/v1/identities/<identity_id>/prepare-auth")
    def prepare_auth(identity_id: str):
        body = _body(frozenset({"target", "mechanism"}))
        package = service.package(body.get("target", ""))
        identity = service.registry.get_identity(package.target.id, identity_id)
        if identity is None or package.status is not PackageStatus.TRACKED:
            raise LookupError("identity not found")
        if body.get("mechanism") != "MANUAL_LOGIN":
            raise ValueError("unsupported mechanism")
        context = service.auth.prepare(package.target.id, identity.id,
                                       mechanism=AuthMechanism.MANUAL_LOGIN)
        service.audit("auth_prepared", target_id=package.target.id, identity_id=identity.id)
        return jsonify({"identity_id": identity.id, "auth": context.to_dict()})

    @app.get("/v1/browser/sessions")
    def sessions():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse(maximum=service.config.browser.max_page_size)
        result = service.browser.list_sessions_for_target(package.target.id,
                                                          limit=page.limit, cursor=page.cursor)
        return jsonify({"items": [service.session_summary(item) for item in result.items],
                        "next_cursor": result.next_cursor})

    @app.post("/v1/browser/sessions")
    def create_session():
        body = _body(frozenset({"target", "identity_id", "anonymous", "capture_provider"}))
        package = service.package(body.get("target", ""))
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("target is not active")
        anonymous = body.get("anonymous", False)
        identity_id = body.get("identity_id")
        if type(anonymous) is not bool or anonymous == bool(identity_id):
            raise ValueError("invalid session identity")
        with service.store._connection() as connection:
            active_sessions = connection.execute(
                "SELECT count(*) FROM browser_sessions WHERE status NOT IN ('STOPPED','FAILED','EXPIRED')"
            ).fetchone()[0]
        service.resources.admit(WorkKind.BROWSER, active=active_sessions)
        capture_provider = body.get("capture_provider", "DIRECT")
        if capture_provider == "BURP":
            service.ensure_burp_bridge(package)
            session, _ = service.burp.provision_session(
                package, None if anonymous else identity_id)
        elif capture_provider == "DIRECT":
            session = service.browser.create(package.target.id, None if anonymous else identity_id)
        else:
            raise ValueError("invalid capture provider")
        service.audit("browser_created", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(session)), 201

    def scoped_session(session_id: str):
        package = service.package(request.args.get("target", ""))
        session = service.browser.get(session_id)
        if session is None or session.target_id != package.target.id:
            raise LookupError("session not found")
        return package, session

    @app.get("/v1/browser/sessions/<session_id>")
    def session_detail(session_id: str):
        _, session = scoped_session(session_id)
        return jsonify(service.session_summary(session))

    @app.post("/v1/browser/sessions/<session_id>/start")
    def start_session(session_id: str):
        _body(frozenset())
        package, session = scoped_session(session_id)
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("target is not active")
        with service.store._connection() as connection:
            running = connection.execute(
                "SELECT count(*) FROM browser_sessions WHERE status IN "
                "('STARTING','RUNNING','WAITING_LOGIN','VERIFYING_IDENTITY','NEEDS_MANUAL_REVIEW','VALID')"
            ).fetchone()[0]
        service.resources.admit(WorkKind.BROWSER, active=running)
        if session.identity_id and service.config.browser.display and not service._vnc_ready():
            return jsonify(error="vnc_not_ready"), 409
        service.audit("browser_start_requested", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        binding = service.burp.binding_for_session(session.id)
        if binding is not None:
            if binding.state != "ACTIVE":
                raise BurpError("Burp listener is no longer active")
            service.ensure_burp_bridge(package)
            updated = service.burp.start_browser(session.id, package=package)
        else:
            updated = service.browser.start(session.id, package=package)
        service.audit("browser_started", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(updated))

    @app.post("/v1/browser/sessions/<session_id>/login-complete")
    def login_complete(session_id: str):
        _body(frozenset())
        package, session = scoped_session(session_id)
        updated = service.browser.login_complete(session.id)
        service.audit("manual_login_completed", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        rule = service.verification_rule(package, session.identity_id)
        verified = service.browser.verify(updated.id, rule)
        service.audit("identity_verification_finished", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(verified))

    @app.post("/v1/browser/sessions/<session_id>/verify")
    def verify_session(session_id: str):
        _body(frozenset())
        package, session = scoped_session(session_id)
        rule = service.verification_rule(package, session.identity_id)
        verified = service.browser.verify(session.id, rule)
        service.audit("identity_verification_finished", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(verified))

    @app.post("/v1/browser/sessions/<session_id>/stop")
    def stop_session(session_id: str):
        _body(frozenset())
        package, session = scoped_session(session_id)
        updated = service.browser.stop(session.id)
        service.audit("browser_stopped", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(updated))

    @app.post("/v1/browser/sessions/<session_id>/reconcile")
    def reconcile_session(session_id: str):
        _body(frozenset())
        package, session = scoped_session(session_id)
        updated = service.browser.reconcile_stale(session.id)
        service.audit("browser_reconciled", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
        return jsonify(service.session_summary(updated))

    @app.get("/v1/traffic")
    def traffic():
        package = service.package(request.args.get("target", ""))
        page = PageRequest.parse()
        allowed_filters = ("identity", "session", "method", "status", "source", "scope")
        filters = {key: request.args[key] for key in allowed_filters if key in request.args}
        result = service.traffic.list_filtered(package.target.id, limit=page.limit,
                                               cursor=page.cursor, **filters)
        return jsonify({"items": [item.to_dict() for item in result.items],
                        "next_cursor": result.next_cursor})

    @app.get("/v1/traffic/stats")
    def traffic_stats():
        package = service.package(request.args.get("target", ""))
        return jsonify(service.traffic.stats(package.target.id))

    @app.get("/v1/traffic/<exchange_id>")
    def traffic_detail(exchange_id: str):
        package = service.package(request.args.get("target", ""))
        item = service.traffic.get_exchange(exchange_id)
        if item is None or item.target_id != package.target.id:
            raise LookupError("exchange not found")
        return jsonify(item.to_dict())

    @app.get("/v1/burp/status")
    def burp_status():
        target = request.args.get("target")
        package = service.package(target) if target else None
        return jsonify(service.burp.status(package.target.id if package else None))

    @app.get("/v1/evidence/<evidence_id>")
    def evidence(evidence_id: str):
        package = service.package(request.args.get("target", ""))
        item = service.store.get_evidence(evidence_id)
        if item is None or item.target_ref != package.target.id:
            raise LookupError("evidence not found")
        return jsonify(item.to_reference())

    return app
