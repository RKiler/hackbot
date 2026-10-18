"""Bounded, restart-safe notification dispatch from the durable BugHunter outbox."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
import json
import logging
import re
import smtplib
import ssl
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .config import NotificationSettings
from .notification_store import (DeliveryStatus, NotificationEvent, NotificationStore,
                                 NotificationType)
from .plan_runs import PlanRunStore
from .safe_output import safe_text
from .secrets import SecretProvider, SecretUnavailable
from .target_scope import ScopeResult
from .traffic import TrafficStore
from .validation_store import ValidationStore


@dataclass(frozen=True, slots=True)
class NotificationMessage:
    title: str
    body: str
    event_id: str


@dataclass(frozen=True, slots=True)
class DeliveryError(Exception):
    code: str
    retryable: bool = False
    uncertain: bool = False


class NotifierProvider(Protocol):
    name: str

    def send(self, message: NotificationMessage) -> None: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class DiscordNotifier:
    name = "discord"

    def __init__(self, secrets: SecretProvider, secret_ref: str) -> None:
        self._secrets = secrets
        self._secret_ref = secret_ref

    def send(self, message: NotificationMessage) -> None:
        try:
            url = self._secrets.get(self._secret_ref).reveal(execution_boundary=True)
        except SecretUnavailable:
            raise DeliveryError("PROVIDER_SECRET_UNAVAILABLE", retryable=True) from None
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname not in {"discord.com", "discordapp.com"}
                or parsed.port is not None or parsed.username or parsed.password
                or parsed.query or parsed.fragment
                or not re.fullmatch(r"/api/webhooks/\d{6,32}/[A-Za-z0-9_-]{30,200}", parsed.path)):
            raise DeliveryError("INVALID_DISCORD_WEBHOOK")
        content = safe_text(f"{message.title}\n{message.body}", limit=1600)
        data = json.dumps({"content": content, "allowed_mentions": {"parse": []}},
                          separators=(",", ":")).encode("utf-8")
        request = Request(url, data=data, headers={"Content-Type": "application/json"},
                          method="POST")
        try:
            with build_opener(_NoRedirect()).open(request, timeout=5) as response:
                if response.status not in {200, 204}:
                    raise DeliveryError("DISCORD_RESPONSE_REJECTED")
        except HTTPError as exc:
            if exc.code == 429 or 500 <= exc.code <= 599:
                raise DeliveryError("DISCORD_TRANSIENT", retryable=True) from None
            raise DeliveryError("DISCORD_REJECTED") from None
        except (TimeoutError, OSError, URLError):
            raise DeliveryError("DISCORD_DELIVERY_UNCERTAIN", uncertain=True) from None


class SMTPNotifier:
    name = "smtp"

    def __init__(self, settings: NotificationSettings, secrets: SecretProvider) -> None:
        if settings.smtp_host is None or settings.smtp_sender is None or settings.smtp_recipient is None:
            raise ValueError("SMTP notifier is not configured")
        self._settings = settings
        self._secrets = secrets

    def send(self, message: NotificationMessage) -> None:
        settings = self._settings
        assert settings.smtp_host and settings.smtp_sender and settings.smtp_recipient
        email = EmailMessage()
        email["From"] = settings.smtp_sender
        email["To"] = settings.smtp_recipient
        email["Subject"] = safe_text(message.title, limit=120)
        email.set_content(safe_text(message.body, limit=3000))
        try:
            with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port,
                                  timeout=5, context=ssl.create_default_context()) as smtp:
                if settings.smtp_username and settings.smtp_password_ref:
                    try:
                        password = self._secrets.get(settings.smtp_password_ref).reveal(
                            execution_boundary=True)
                    except SecretUnavailable:
                        raise DeliveryError("PROVIDER_SECRET_UNAVAILABLE", retryable=True) from None
                    smtp.login(settings.smtp_username, password)
                smtp.send_message(email)
        except smtplib.SMTPAuthenticationError:
            raise DeliveryError("SMTP_AUTH_FAILED") from None
        except (TimeoutError, OSError, smtplib.SMTPException):
            raise DeliveryError("SMTP_DELIVERY_UNCERTAIN", uncertain=True) from None


class ConsoleNotifier:
    name = "console"

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def send(self, message: NotificationMessage) -> None:
        self._logger.info("notification sent", extra={"context": {
            "event_id": message.event_id if re.fullmatch(r"NOTIF-[0-9a-f]{32}",
                                                        message.event_id) else "[invalid]"}})


_DEFAULT_EVENTS = (
    NotificationType.CONFIRMED_FINDING,
    NotificationType.FINDING_READY_FOR_REPORT,
    NotificationType.CLEANUP_FAILURE,
    NotificationType.AUTH_REQUIRES_LOGIN,
    NotificationType.PLANNER_COMPLETED_WITH_FINDINGS,
    NotificationType.TEST,
)
_SAFE_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,100}\Z")


def _code(value: object, fallback: str) -> str:
    return value if isinstance(value, str) and _SAFE_CODE.fullmatch(value) else fallback


class NotificationManager:
    def __init__(self, outbox: NotificationStore, validations: ValidationStore,
                 runs: PlanRunStore, traffic: TrafficStore, settings: NotificationSettings,
                 providers: tuple[NotifierProvider, ...]) -> None:
        self.outbox = outbox
        self.validations = validations
        self.runs = runs
        self.traffic = traffic
        self.settings = settings
        self.providers = providers
        if len(providers) > 4 or len({item.name for item in providers}) != len(providers):
            raise ValueError("duplicate or excessive notification providers")

    def status(self, target_id: str | None = None) -> dict[str, object]:
        return {"configured_providers": [item.name for item in self.providers],
                "discord_configured": any(item.name == "discord" for item in self.providers),
                "smtp_configured": any(item.name == "smtp" for item in self.providers),
                "manual_review_enabled": self.settings.manual_review_enabled,
                "triage_enabled": self.settings.triage_enabled,
                "delivery": self.outbox.stats(target_id)}

    def _eligible(self) -> tuple[NotificationType, ...]:
        types = list(_DEFAULT_EVENTS)
        if self.settings.manual_review_enabled:
            types.append(NotificationType.MANUAL_REVIEW_REQUIRED)
        if self.settings.triage_enabled:
            types.append(NotificationType.FINDING_TRIAGE_CHANGED)
        return tuple(types)

    def _affected_surface(self, run_id: str, target_id: str) -> str | None:
        run = self.runs.get(run_id, target_id)
        if run is None:
            return None
        for step in self.runs.steps(run.id):
            if step.role != "BOUNDARY" or not step.result_id:
                continue
            result = self.runs.result(step.id)
            if result is None:
                continue
            for exchange_id in result.exchange_ids[:4]:
                exchange = self.traffic.get_exchange(exchange_id)
                if (exchange is not None and exchange.target_id == target_id and
                        exchange.scope_result is ScopeResult.IN_SCOPE):
                    request = exchange.request
                    parsed = urlsplit(request.origin)
                    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or
                            parsed.username or parsed.password):
                        continue
                    return request.record.method + " " + request.origin + request.display_path
        plan = self.runs.snapshot(run.plan_id, target_id).data
        for key in ("dom_binding", "message_binding", "exposure_binding"):
            binding = plan.get(key)
            if not isinstance(binding, dict):
                continue
            route = binding.get("route_url") or binding.get("url")
            if not isinstance(route, str):
                continue
            parsed = urlsplit(route)
            if (parsed.scheme in {"http", "https"} and parsed.hostname and
                    not parsed.username and not parsed.password):
                return parsed.scheme + "://" + parsed.netloc
        return None

    def _message(self, event: NotificationEvent) -> NotificationMessage:
        if event.event_type is NotificationType.TEST:
            return NotificationMessage("[TEST] BugHunter notification",
                                       "Operator-requested provider check; no vulnerability data.", event.id)
        if event.finding_id:
            finding = self.validations.get_finding(event.finding_id, event.target_id)
            if finding is None:
                raise DeliveryError("FINDING_NOT_FOUND")
            validation = self.validations.get(finding.validation_id, event.target_id)
            if validation is None or validation.status.value != "CONFIRMED" or validation.source != "DETERMINISTIC":
                raise DeliveryError("FINDING_NOT_CONFIRMED")
            run = self.runs.get(validation.run_id, event.target_id)
            link = ""
            if run is not None and self.settings.dashboard_base_url:
                link = ("\nDashboard: " + self.settings.dashboard_base_url.rstrip("/") +
                        "/hackbot/findings?target=" + quote(run.package_id, safe="") +
                        "&id=" + quote(finding.id, safe=""))
            category = _code(finding.category, "SECURITY_FINDING")
            impact = _code(validation.demonstrated_impact, "VERIFIED_EFFECT_RECORDED")
            surface = self._affected_surface(validation.run_id, event.target_id)
            title = (f"[{event.event_type.value}] " +
                     safe_text(finding.title, limit=100, markdown=True))
            body = (f"Target: {event.target_id}\nCategory: {category}"
                    f"\nFinding: {finding.id}\nDemonstrated impact: {impact}"
                    "\nAffected surface: " +
                    (safe_text(surface, limit=300) if surface else
                     "route unavailable; fingerprint " + finding.surface_fingerprint[:16]) + link)
            return NotificationMessage(title, body, event.id)
        if event.event_type is NotificationType.MANUAL_REVIEW_REQUIRED:
            validation = self.validations.get(event.validation_id or "", event.target_id)
            if validation is None or validation.status.value != "NEEDS_MANUAL_REVIEW":
                raise DeliveryError("REVIEW_SOURCE_NOT_FOUND")
            reason = ", ".join(_code(item, "REVIEW_REQUIRED")
                               for item in validation.reason_codes[:3])
            return NotificationMessage("[UNCONFIRMED / NEEDS MANUAL REVIEW] BugHunter lead",
                f"Target: {event.target_id}\nValidation: {validation.id}\n"
                f"Reason: {reason or 'REVIEW_REQUIRED'}", event.id)
        return NotificationMessage(f"[OPERATIONAL] {event.event_type.value}",
                                   f"Target: {event.target_id}\nReference: {event.source_id}", event.id)

    def process(self, *, max_messages: int = 20) -> int:
        if type(max_messages) is not int or not 1 <= max_messages <= 100:
            raise ValueError("invalid notification batch")
        delivered = 0
        processed = 0
        for provider in self.providers:
            events = self.outbox.unprepared_events(provider.name, self._eligible(),
                                                    limit=min(max_messages, 50))
            for event in events:
                self.outbox.prepare_deliveries(event.id, (provider.name,))
            while processed < max_messages:
                claimed = self.outbox.claim(provider.name, hourly_cap=self.settings.hourly_cap,
                                            target_daily_cap=self.settings.target_daily_cap)
                if claimed is None:
                    break
                processed += 1
                delivery, event = claimed
                try:
                    provider.send(self._message(event))
                except DeliveryError as exc:
                    status = (DeliveryStatus.NEEDS_REVIEW if exc.uncertain else
                              DeliveryStatus.RETRY if exc.retryable else DeliveryStatus.FAILED)
                    self.outbox.finish(delivery.id, status, error_code=exc.code,
                                       retry_seconds=min(60 * delivery.attempt_count, 3600))
                except Exception:
                    self.outbox.finish(delivery.id, DeliveryStatus.NEEDS_REVIEW,
                                       error_code="PROVIDER_EXCEPTION_UNCERTAIN")
                else:
                    self.outbox.finish(delivery.id, DeliveryStatus.SENT)
                    delivered += 1
        return delivered
