"""Private, single-process BugHunter control plane and explicit plan-step owner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import socket
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

from . import __version__
from .auth import AuthContextManager, AuthMechanism
from .authorization import AuthorizationSpecialist
from .authorization_store import AuthorizationMode, AuthorizationStore, HuntStatus
from .browser import (BrowserError, BrowserSession, BrowserSessionManager,
                      BrowserStatus, IdentityVerificationRule)
from .browser_playwright import PlaywrightBrowserDriver
from .burp import BurpExecutionProxyAdapter, BurpProxyProvider
from .config import AppConfig, ConfigError, ExecutorSettings, ObjectSettings, load_config
from .domxss import DOMXSSSpecialist
from .domxss_browser import DOMBrowserExperimentExecutor
from .domxss_store import DOMXSSStore
from .exposure import ExposureSpecialist
from .exposure_models import ExposureCategory, ExposureStatus
from .exposure_store import ExposureStore
from .postmessage import PostMessageSpecialist
from .postmessage_browser import PostMessageBrowserExperimentExecutor
from .postmessage_store import PostMessageStore
from .executor import TrafficExecutor
from .hypotheses import ContextPacketBuilder, HypothesisGenerator, HypothesisStore
from .identity_registry import IdentityRegistry
from .logging import SecretRedactor, create_logger
from .policy import PolicyEngine, policy_version
from .policy_models import ActionCategory, ActorMode, ApprovalStatus, ProposedAction, SideEffect
from .policy_store import PolicyStore
from .permit_store import PolicyPermitStore
from .plan_runs import PlanRunStore, RunStatus
from .orchestrator import PlanOrchestrator
from .object_factory import ObjectFactory
from .mutation_results import MutationResultStore
from .mutation_results import value_hash
from .object_recipes import RecipeCatalog
from .typed_mutations import MutationPhase, TypedMutation
from .test_objects import ObjectRegistry, ObjectState
from .profile import AttackSurfaceProfiler
from .rate_limit import RateLimiter
from .recon_postgres import PostgresReconRepository
from .secrets import RoutedSecretProvider
from .skills import SkillRegistry
from .skill_plans import (DOMPlanBinding, MessagePlanBinding, PrerequisiteChecker, SkillContextBuilder,
                          SkillPlanStore, SkillPlanner, SkillRouter)
from .store import EvidenceFactStore, StoreNotInitialized, StoreSchemaError
from .target_loader import TargetPackageRepository
from .target_package import PackageStatus, TargetPackage
from .target_policy import RiskLevel
from .traffic import TrafficStore
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
        self.store = EvidenceFactStore.from_config(config)
        self.store.initialize()
        self.registry = IdentityRegistry(self.store)
        self.auth = AuthContextManager(self.registry, RoutedSecretProvider(config.secrets))
        self.driver = driver or PlaywrightBrowserDriver(config.browser.chromium_executable)
        self.browser = BrowserSessionManager(self.registry, self.auth, self.driver, config.browser)
        self.traffic = TrafficStore(self.store, self.registry)
        self.burp = BurpProxyProvider(config.burp, self.traffic, self.browser)
        self.targets = TargetPackageRepository(config.targets.root)
        self.hypotheses = HypothesisStore(self.store)
        self.domxss_store = DOMXSSStore(self.store)
        self.exposure_store = ExposureStore(self.store)
        self.postmessage_store = PostMessageStore(self.store, self.domxss_store)
        self.skills = SkillRegistry(config.skills.root if config.skills else Path(__file__).resolve().parent / "skill_catalog")
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
        )
        self.recon = None
        try:
            self.recon = PostgresReconRepository.from_config(config)
        except ConfigError:
            pass  # Local-only service stays usable; profile records the recon gap.
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
        self.exposure = ExposureSpecialist(dom=self.domxss_store, store=self.exposure_store,
                                           recon=self.recon, traffic=self.traffic)
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
        self.mutation_results = MutationResultStore(self.store)
        self.validations = ValidationStore(self.store)
        self.validator_registry = ValidatorRegistry()
        self.validator = DeterministicValidatorEngine(
            runs=self.run_store, traffic=self.traffic, evidence=self.store,
            identities=self.registry, hypotheses=self.hypotheses,
            results=self.validations, registry=self.validator_registry,
            dom=self.domxss_store, messages=self.postmessage_store,
            targets=self.targets, exposure=self.exposure)
        self.orchestrator = PlanOrchestrator(
            runs=self.run_store, targets=self.targets, hypotheses=self.hypotheses,
            context=self.skill_context, checker=self.skill_checker, registry=self.skills,
            policy=self.policy, approvals=self.policy_store, executor=self.executor,
            traffic=self.traffic, evidence=self.store, objects=self.objects,
            recipes=self.object_factory.recipes, mutations=self.mutation_results,
            dom=self.domxss_browser, messages=self.postmessage_browser,
            exposure=self.exposure)
        self.authorization_ledger = AuthorizationStore(self.store)
        self.authorization = AuthorizationSpecialist(
            identities=self.registry, browser=self.browser, objects=self.objects,
            traffic=self.traffic, evidence=self.store, hypotheses=self.hypotheses,
            ledger=self.authorization_ledger, recon=self.recon, context=self.skill_context,
            router=self.skill_router, planner=self.skill_planner,
            orchestrator=self.orchestrator, validator=self.validator,
            factory=self.object_factory)
        self.logger = create_logger(level=config.log_level)
        self._vnc_ready = vnc_ready or self._probe_vnc
        while self.objects.reconcile():
            pass
        self.reconcile_on_startup()
        while self.run_store.reconcile():
            pass
        while self.mutation_results.reconcile():
            pass
        while self.authorization_ledger.reconcile_runs():
            pass

    def _probe_vnc(self) -> bool:
        if not self.config.browser.vnc_url:
            return False
        parsed = urlsplit(self.config.browser.vnc_url)
        try:
            with socket.create_connection(("127.0.0.1", parsed.port), timeout=0.2):
                return True
        except OSError:
            return False

    def reconcile_on_startup(self) -> int:
        """Fail closed after process restart; never reuse an unowned browser handle."""
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

    def package(self, package_id: str) -> TargetPackage:
        package = self.targets.get_target_package(package_id)
        if package is None:
            raise LookupError("target not found")
        return package

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

    def health(self) -> dict[str, object]:
        with self.store._connection() as connection:
            connection.execute("SELECT 1").fetchone()
        browser_installed = importlib.util.find_spec("playwright") is not None
        return {"status": "ok", "version": __version__, "checks": {
            "bughunter_store": "ok", "browser_manager": "ready" if browser_installed else "dependency_missing",
            "vnc": "ready" if self._vnc_ready() else "not_running",
            "traffic_store": "ok", "orchestrator": "ready", "validator": "ready",
            "object_factory": "ready", "object_cleanup_pending": self.objects.stats()["cleanup_pending"],
            "object_orphans": self.objects.stats()["orphaned"],
            "burp": self.burp.availability().value,
        }, "recon_integration": "configured_read_only" if self.recon else "not_connected"}

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
                "objects": self.objects.stats(),
                "burp": self.burp.availability().value, "activity": self.activity(PageRequest(8, None))["items"]}

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
        return {"id": package.id, "target_id": package.target.id, "name": package.to_dict()["name"],
                "primary_domain": package.primary_domain, "status": package.status.value,
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
    app.config["MAX_CONTENT_LENGTH"] = 16_384
    app.config["JSON_SORT_KEYS"] = True

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

    @app.get("/v1/status")
    def status():
        return jsonify({"version": __version__, "runtime": "single_process",
                        "browser": service.health()["checks"]["browser_manager"],
                        "burp": service.burp.status(),
                        "orchestrator": {"mode": "explicit_one_step", **service.run_store.stats()},
                        "validator": {"mode": "deterministic_evidence_only", **service.validations.stats()},
                        "object_factory": {"mode": "known_recipes_only", **service.objects.stats()},
                        "recon_integration": "configured_read_only" if service.recon else "not_connected"})

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
                                        service.recon).profile(package)
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
        return jsonify(service.validations.list_findings(package.target.id, limit=page.limit,
                                                         cursor=page.cursor, status=status))

    @app.get("/v1/findings/<finding_id>")
    def finding_detail(finding_id: str):
        package = service.package(request.args.get("target", ""))
        finding = service.validations.get_finding(finding_id, package.target.id)
        if finding is None:
            raise LookupError("finding not found")
        result = service.validations.get(finding.validation_id, package.target.id)
        return jsonify({"finding": finding.to_dict(),
                        "validation": result.to_dict() if result else None})

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
        body = _body(frozenset({"target", "identity_id", "anonymous"}))
        package = service.package(body.get("target", ""))
        if package.status is not PackageStatus.TRACKED:
            raise ValueError("target is not active")
        anonymous = body.get("anonymous", False)
        identity_id = body.get("identity_id")
        if type(anonymous) is not bool or anonymous == bool(identity_id):
            raise ValueError("invalid session identity")
        session = service.browser.create(package.target.id, None if anonymous else identity_id)
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
        if session.identity_id and service.config.browser.display and not service._vnc_ready():
            return jsonify(error="vnc_not_ready"), 409
        service.audit("browser_start_requested", target_id=package.target.id,
                      identity_id=session.identity_id, session_id=session.id)
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
