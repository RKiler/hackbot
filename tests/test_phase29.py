"""Phase 29 local-only lifecycle, notification, and evidence-report fixtures."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from hackbot.artifacts import ArtifactStore
from hackbot.config import NotificationSettings, StoreSettings
from hackbot.evidence import EvidenceProvenance, EvidenceType, Sensitivity
from hackbot.finding_workflow import FindingWorkflow
from hackbot.notification_store import (DeliveryStatus, NotificationPriority,
                                       NotificationStore, NotificationType)
from hackbot.notifications import (DeliveryError, DiscordNotifier, NotificationManager,
                                   NotificationMessage, SMTPNotifier)
from hackbot.reports import ReportGenerator, ReportProvenance, ReportReadiness, ReportStore
from hackbot.store import EvidenceFactStore
from hackbot.validation_store import FindingStatus, ValidationStatus, ValidationStore
from tests import test_api_runtime as api_fixture
from tests import test_domxss_runtime as dom_fixture
from tests import test_exposure_runtime as exposure_fixture
from tests import test_postmessage_runtime as message_fixture
from tests import test_validator as validator_fixture


class FakeNotifier:
    name = "fake"

    def __init__(self) -> None:
        self.messages: list[NotificationMessage] = []

    def send(self, message: NotificationMessage) -> None:
        self.messages.append(message)


class FakeSecrets:
    def __init__(self, value: str) -> None:
        self.value = value

    def get(self, _reference: str):
        return SimpleNamespace(reveal=lambda **_kwargs: self.value)


class Phase29Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = validator_fixture.ValidatorTests(
            methodName="test_cross_tenant_confirmation_audit_and_duplicate")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.target_id = self.fixture.target
        self.store = self.fixture.fx.store
        self.notifier = FakeNotifier()
        self.outbox = NotificationStore(self.store)
        self.manager = NotificationManager(self.outbox, self.fixture.results,
            self.fixture.work.runs, self.fixture.fx.traffic, NotificationSettings(), (self.notifier,))
        self.drafts = ReportStore(self.store, ArtifactStore(
            self.fixture.fx.root / "artifacts" / "reports"))
        self.generator = ReportGenerator(
            store=self.store, drafts=self.drafts, validations=self.fixture.results,
            runs=self.fixture.work.runs, traffic=self.fixture.fx.traffic,
            targets=self.fixture.fx.targets)
        self.workflow = FindingWorkflow(self.store, self.fixture.results)

    def confirmed(self):
        run_id = self.fixture.auth_run()
        result, finding = self.fixture.validator.validate_run(run_id, self.target_id)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNotNone(finding)
        return result, finding

    def test_confirmed_outbox_delivery_once_after_restart(self):
        result, finding = self.confirmed()
        self.assertEqual(self.outbox.stats(self.target_id)["events"], 1)
        self.assertEqual(self.manager.process(), 1)
        self.assertEqual(len(self.notifier.messages), 1)
        self.assertIn(finding.id, self.notifier.messages[0].body)
        self.assertIn("Affected surface: GET http://", self.notifier.messages[0].body)
        self.assertNotIn("object-a", self.notifier.messages[0].body)
        restarted = NotificationManager(NotificationStore(self.store), self.fixture.results,
            self.fixture.work.runs, self.fixture.fx.traffic, NotificationSettings(), (self.notifier,))
        self.assertEqual(restarted.process(), 0)
        self.assertEqual(len(self.notifier.messages), 1)
        same_result, same_finding = self.fixture.validator.validate_run(result.run_id, self.target_id)
        self.assertEqual(same_finding.id, finding.id)
        self.assertEqual(same_result.id, result.id)
        self.assertEqual(self.outbox.stats(self.target_id)["events"], 1)

    def test_duplicate_root_cause_does_not_enqueue_new_confirmed(self):
        _, finding = self.confirmed()
        second_run = self.fixture.auth_run()
        duplicate, original = self.fixture.validator.validate_run(second_run, self.target_id)
        self.assertEqual(duplicate.status, ValidationStatus.DUPLICATE_CANDIDATE)
        self.assertEqual(original.id, finding.id)
        self.assertEqual(self.outbox.stats(self.target_id)["events"], 1)
        self.assertEqual(self.outbox.stats(self.target_id)["deduped"], 1)

    def test_repeated_event_is_deduped_and_counted(self):
        source_id = "TEST-" + uuid.uuid4().hex
        first = self.outbox.enqueue(target_id=self.target_id,
            event_type=NotificationType.TEST, source_kind="TEST", source_id=source_id,
            priority=NotificationPriority.LOW)
        second = self.outbox.enqueue(target_id=self.target_id,
            event_type=NotificationType.TEST, source_kind="TEST", source_id=source_id,
            priority=NotificationPriority.LOW)
        self.assertEqual(first.id, second.id)
        self.assertEqual(self.outbox.stats(self.target_id)["deduped"], 1)
        with self.assertRaises(ValueError):
            self.outbox.enqueue(target_id=self.target_id,
                event_type=NotificationType.AUTH_REQUIRES_LOGIN, source_kind="TEST",
                source_id=source_id, priority=NotificationPriority.LOW)

    def test_rejected_candidate_has_no_confirmed_notification(self):
        run_id = self.fixture.auth_run(visibility="PUBLIC")
        result, finding = self.fixture.validator.validate_run(run_id, self.target_id)
        self.assertNotEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertIsNone(finding)
        self.assertEqual(self.manager.process(), 0)
        self.assertEqual(self.notifier.messages, [])

    def test_notification_redacts_synthetic_secret_and_pii(self):
        _, finding = self.confirmed()
        with self.store._connection() as db:
            db.execute("UPDATE findings SET title=?,demonstrated_impact=? WHERE finding_id=?",
                       ("Leak to alice@example.test *bold*",
                        "Cookie: synthetic-session-12345 ", finding.id))
        self.assertEqual(self.manager.process(), 1)
        message = self.notifier.messages[0]
        self.assertNotIn("alice@example.test", message.title)
        self.assertIn("REDACTED", message.title)
        self.assertIn("\\*bold\\*", message.title)
        self.assertNotIn("synthetic-session-12345", message.body)
        self.assertIn(finding.id, message.body)

    def test_discord_adapter_sends_only_redacted_text_without_mentions(self):
        url = "https://discord.com/api/webhooks/123456/" + "A" * 40
        provider = DiscordNotifier(FakeSecrets(url), "ref:discord_fixture")
        with patch("hackbot.notifications.build_opener") as factory:
            factory.return_value.open.return_value.__enter__.return_value.status = 204
            provider.send(NotificationMessage("Finding for alice@example.test",
                "Cookie: synthetic-session-12345", "NOTIF-" + uuid.uuid4().hex))
            request = factory.return_value.open.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(payload["allowed_mentions"], {"parse": []})
        self.assertNotIn("alice@example.test", payload["content"])
        self.assertNotIn("synthetic-session-12345", payload["content"])

    def test_smtp_adapter_uses_secret_ref_and_sends_no_attachment(self):
        settings = NotificationSettings(smtp_host="mail.example.test",
            smtp_sender="bot@example.test", smtp_recipient="hunter@example.test",
            smtp_username="bot", smtp_password_ref="ref:smtp_fixture")
        provider = SMTPNotifier(settings, FakeSecrets("fixture-password"))
        with patch("hackbot.notifications.smtplib.SMTP_SSL") as factory:
            sender = factory.return_value.__enter__.return_value
            provider.send(NotificationMessage("Finding for alice@example.test",
                "Authorization: Bearer synthetic-session-12345",
                "NOTIF-" + uuid.uuid4().hex))
            sender.login.assert_called_once_with("bot", "fixture-password")
            mail = sender.send_message.call_args.args[0]
        self.assertNotIn("alice@example.test", mail.as_string())
        self.assertNotIn("synthetic-session-12345", mail.as_string())
        self.assertEqual(list(mail.iter_attachments()), [])

    def test_notification_secret_references_are_absent_from_config_repr(self):
        settings = NotificationSettings(
            discord_secret_ref="ref:discord_fixture", smtp_host="mail.example.test",
            smtp_sender="bot@example.test", smtp_recipient="hunter@example.test",
            smtp_username="bot", smtp_password_ref="ref:smtp_fixture")
        rendered = repr(settings)
        self.assertNotIn("discord_fixture", rendered)
        self.assertNotIn("smtp_fixture", rendered)
        self.assertNotIn("password", rendered)

    def test_target_daily_cap_holds_excess_notifications(self):
        limited = NotificationManager(self.outbox, self.fixture.results,
            self.fixture.work.runs, self.fixture.fx.traffic,
            NotificationSettings(target_daily_cap=1), (self.notifier,))
        for _ in range(2):
            self.outbox.enqueue(target_id=self.target_id, event_type=NotificationType.TEST,
                source_kind="TEST", source_id="TEST-" + uuid.uuid4().hex,
                priority=NotificationPriority.LOW)
        self.assertEqual(limited.process(), 1)
        self.assertEqual(limited.process(), 0)
        self.assertEqual(self.outbox.stats(self.target_id)["pending"], 1)

    def test_confirmed_event_precedes_older_low_priority_event(self):
        self.outbox.enqueue(target_id=self.target_id, event_type=NotificationType.TEST,
            source_kind="TEST", source_id="TEST-" + uuid.uuid4().hex,
            priority=NotificationPriority.LOW)
        _, finding = self.confirmed()
        self.assertEqual(self.manager.process(max_messages=1), 1)
        self.assertIn(finding.id, self.notifier.messages[0].body)
        self.assertEqual(self.manager.process(max_messages=1), 1)
        self.assertIn("TEST", self.notifier.messages[1].title)

    def test_crash_during_send_requires_review_without_auto_replay(self):
        self.confirmed()
        event = self.outbox.unprepared_events("fake", self.manager._eligible())[0]
        self.outbox.prepare_deliveries(event.id, ("fake",))
        claimed = self.outbox.claim("fake")
        self.assertIsNotNone(claimed)
        self.assertEqual(self.outbox.reconcile_inflight(), 1)
        self.assertEqual(self.manager.process(), 0)
        self.assertEqual(self.outbox.stats(self.target_id)["needs_review"], 1)
        self.assertEqual(self.notifier.messages, [])

    def test_transient_provider_failure_is_bounded_and_preserves_finding(self):
        _, finding = self.confirmed()

        class FailingNotifier(FakeNotifier):
            def send(self, message: NotificationMessage) -> None:
                raise DeliveryError("TRANSIENT", retryable=True)

        manager = NotificationManager(self.outbox, self.fixture.results,
            self.fixture.work.runs, self.fixture.fx.traffic,
            NotificationSettings(), (FailingNotifier(),))
        for _ in range(3):
            self.assertEqual(manager.process(), 0)
            with self.store._connection() as db:
                db.execute("UPDATE notification_deliveries SET next_attempt_at=? "
                           "WHERE status='RETRY'", ("2000-01-01T00:00:00+00:00",))
        self.assertEqual(manager.process(), 0)
        delivery = self.outbox.for_finding(finding.id, self.target_id)[0]["deliveries"][0]
        self.assertEqual(delivery["status"], "FAILED")
        self.assertEqual(delivery["attempt_count"], 3)
        self.assertEqual(self.fixture.results.get_finding(finding.id, self.target_id).status,
                         FindingStatus.CONFIRMED)

    def test_cross_tenant_report_is_evidence_backed_and_idempotent(self):
        result, finding = self.confirmed()
        first = self.generator.generate(finding.id, self.target_id)
        self.assertEqual(first.readiness, ReportReadiness.READY, first.quality_codes)
        self.assertIsNotNone(first.draft)
        report = self.drafts.markdown(first.draft.id, self.target_id)
        self.assertIn("## Steps to Reproduce", report)
        self.assertIn("tenant isolation boundary", report)
        self.assertIn("a controlled account in another tenant", report)
        self.assertIn("read protected test-object data", report)
        self.assertIn(result.id, report)
        self.assertIn("**Demonstrated:**", report)
        self.assertNotIn("**Potential, not demonstrated:**", report)
        self.assertIn("OWNER", report)
        self.assertIn("Authorization actors and boundary", report)
        self.assertIn(self.fixture.actors["tenant_a_owner"][0].id, report)
        self.assertIn(self.fixture.actors["tenant_b_admin"][0].id, report)
        second = self.generator.generate(finding.id, self.target_id)
        self.assertEqual(second.draft.id, first.draft.id)
        self.assertEqual(first.draft.version, 1)

    def test_missing_steps_blocks_ready_report(self):
        _, finding = self.confirmed()
        with patch.object(self.generator.runs, "steps", return_value=()):
            outcome = self.generator.generate(finding.id, self.target_id)
        self.assertEqual(outcome.readiness, ReportReadiness.NEEDS_EVIDENCE)
        self.assertIn("EXECUTED_REPRODUCTION_STEPS_MISSING", outcome.quality_codes)
        self.assertIsNone(outcome.draft)
        with self.assertRaises(ValueError):
            self.workflow.transition(finding.id, self.target_id,
                FindingStatus.READY_FOR_REPORT, expected_version=0)
        self.assertNotIn("READY_FOR_REPORT", self.workflow.detail(
            finding.id, self.target_id)["allowed_transitions"])

    def test_unmapped_effect_requires_manual_review(self):
        result, finding = self.confirmed()
        original_get = self.generator.validations.get

        def changed_validation(validation_id, target_id):
            current = original_get(validation_id, target_id)
            return (replace(current, demonstrated_impact="UNMAPPED_EFFECT")
                    if current and current.id == result.id else current)

        with patch.object(self.generator.validations, "get", side_effect=changed_validation):
            outcome = self.generator.generate(finding.id, self.target_id)
        self.assertEqual(outcome.readiness, ReportReadiness.NEEDS_MANUAL_REVIEW)
        self.assertIn("SUMMARY_BOUNDARY_OR_ACTOR_UNAVAILABLE", outcome.quality_codes)

    def test_failed_regeneration_invalidates_older_ready_draft(self):
        _, finding = self.confirmed()
        ready = self.generator.generate(finding.id, self.target_id)
        self.assertEqual(ready.readiness, ReportReadiness.READY)
        with patch.object(self.generator.runs, "steps", return_value=()):
            failed = self.generator.generate(finding.id, self.target_id)
        self.assertEqual(failed.readiness, ReportReadiness.NEEDS_EVIDENCE)
        self.assertEqual(self.drafts.latest(finding.id, self.target_id).id, ready.draft.id)
        self.assertEqual(self.drafts.latest_attempt(finding.id, self.target_id)["readiness"],
                         "NEEDS_EVIDENCE")
        with self.assertRaises(ValueError):
            self.workflow.transition(finding.id, self.target_id,
                FindingStatus.READY_FOR_REPORT, expected_version=0)
        self.assertNotIn("READY_FOR_REPORT", self.workflow.detail(
            finding.id, self.target_id)["allowed_transitions"])
        with patch.object(self.generator.runs, "steps", return_value=()):
            repeated = self.generator.generate(finding.id, self.target_id)
        self.assertEqual(repeated.quality_codes, failed.quality_codes)
        with self.store._connection() as db:
            attempts = db.execute("SELECT count(*) FROM report_attempts WHERE finding_id=?",
                                  (finding.id,)).fetchone()[0]
        self.assertEqual(attempts, 2)

    def test_workflow_version_and_manual_outcomes(self):
        _, finding = self.confirmed()
        with self.assertRaises(ValueError):
            self.workflow.transition(finding.id, self.target_id, FindingStatus.READY_FOR_REPORT,
                                     expected_version=0)
        outcome = self.generator.generate(finding.id, self.target_id)
        self.assertEqual(outcome.readiness, ReportReadiness.READY)
        ready = self.workflow.transition(finding.id, self.target_id,
                                         FindingStatus.READY_FOR_REPORT, expected_version=0)
        self.assertEqual(ready["workflow_version"], 1)
        with self.assertRaises(ValueError):
            self.workflow.transition(finding.id, self.target_id,
                                     FindingStatus.SUBMITTED, expected_version=0,
                                     platform="HackerOne", external_report_id="12345")
        submitted = self.workflow.transition(finding.id, self.target_id,
            FindingStatus.SUBMITTED, expected_version=1,
            platform="HackerOne", program="Fixture", external_report_id="12345")
        self.assertEqual(submitted["submission"]["external_report_id"], "12345")
        triaged = self.workflow.transition(finding.id, self.target_id,
            FindingStatus.TRIAGED, expected_version=2, triage_status="ACCEPTED")
        self.assertEqual(triaged["workflow_version"], 3)
        self.assertEqual(self.workflow.metrics(self.target_id)["accepted"], 1)
        self.assertEqual(triaged["lineage"]["skill_id"], "cross-tenant-object-authorization")
        self.assertEqual(triaged["lineage"]["plan_run_id"],
                         self.fixture.results.get(finding.validation_id, self.target_id).run_id)
        rewarded = self.workflow.transition(finding.id, self.target_id,
            FindingStatus.REWARDED, expected_version=3,
            reward_amount="100.00", reward_currency="USD")
        self.assertEqual(rewarded["submission"]["reward_amount"], "100.00")
        self.assertEqual(rewarded["submission"]["reward_currency"], "USD")

    def test_report_edits_are_new_versions_and_secrets_are_redacted(self):
        _, finding = self.confirmed()
        with self.store._connection() as db:
            db.execute("UPDATE findings SET title=?, safe_summary=? WHERE finding_id=?",
                       ("Leak to person@example.com", "Cookie: sample-session-12345",
                        finding.id))
        outcome = self.generator.generate(finding.id, self.target_id)
        report = self.drafts.markdown(outcome.draft.id, self.target_id)
        self.assertNotIn("person@example.com", report)
        self.assertNotIn("sample-session-12345", report)
        edited = self.drafts.edit(outcome.draft.id, self.target_id,
            report + "\nResearcher note: user@example.com Authorization: Bearer token123\n",
            expected_version=1)
        self.assertEqual(edited.version, 2)
        self.assertEqual(edited.provenance, ReportProvenance.MANUALLY_EDITED)
        self.assertEqual(edited.readiness, ReportReadiness.NEEDS_MANUAL_REVIEW)
        self.assertEqual(self.drafts.latest_attempt(finding.id, self.target_id)["readiness"],
                         "NEEDS_MANUAL_REVIEW")
        self.assertNotIn("user@example.com", self.drafts.markdown(edited.id, self.target_id))
        self.assertNotIn("token123", self.drafts.markdown(edited.id, self.target_id))
        self.assertEqual(self.drafts.get(outcome.draft.id, self.target_id).version, 1)
        with self.assertRaises(ValueError):
            self.drafts.edit(outcome.draft.id, self.target_id, report + "\nAnother edit\n",
                             expected_version=1)

    def test_unresolved_lowercase_placeholder_blocks_reviewed_edit(self):
        _, finding = self.confirmed()
        draft = self.generator.generate(finding.id, self.target_id).draft
        with self.assertRaisesRegex(ValueError, "placeholder"):
            self.drafts.edit(draft.id, self.target_id,
                self.drafts.markdown(draft.id, self.target_id) + "\n<insert_private_name>\n",
                expected_version=1, researcher_reviewed=True)
        with self.assertRaisesRegex(ValueError, "line limits"):
            self.drafts.edit(draft.id, self.target_id, "note\n" * 501,
                             expected_version=1)
        with self.assertRaisesRegex(ValueError, "evidence sections"):
            self.drafts.edit(draft.id, self.target_id, "# Short note\n",
                             expected_version=1, researcher_reviewed=True)

    def test_new_evidence_creates_new_immutable_report_version(self):
        _, finding = self.confirmed()
        first = self.generator.generate(finding.id, self.target_id).draft
        evidence = self.store.create_evidence(
            EvidenceType.MANUAL_NOTE, b"Synthetic follow-up control",
            source="test_fixture", target_ref=self.target_id,
            provenance=EvidenceProvenance("FIXTURE", "FOLLOW_UP", "phase29"),
            sensitivity=Sensitivity.INTERNAL)
        with self.store._connection() as db:
            db.execute("INSERT INTO finding_evidence(finding_id,evidence_id) VALUES (?,?)",
                       (finding.id, evidence.evidence_id))
        second = self.generator.generate(finding.id, self.target_id).draft
        self.assertEqual(second.version, 2)
        self.assertNotEqual(second.id, first.id)
        self.assertIn(evidence.evidence_id, self.drafts.markdown(second.id, self.target_id))
        self.assertNotIn(evidence.evidence_id, self.drafts.markdown(first.id, self.target_id))

    def test_manual_duplicate_and_informative_outcomes_are_audited(self):
        _, finding = self.confirmed()
        duplicate = self.workflow.transition(finding.id, self.target_id,
            FindingStatus.DUPLICATE, expected_version=0,
            external_duplicate_ref="prior_123", note="Same boundary")
        self.assertEqual(duplicate["finding"]["status"], "DUPLICATE")
        self.assertEqual(duplicate["submission"]["external_duplicate_ref"], "prior_123")
        self.assertEqual(duplicate["history"][0]["status"], "DUPLICATE")
        with self.assertRaises(ValueError):
            self.workflow.transition(finding.id, self.target_id,
                FindingStatus.REWARDED, expected_version=1,
                reward_amount="100", reward_currency="USD")


class NotificationRateLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        blobs = root / "blobs"
        store = EvidenceFactStore(root / "state.sqlite3", ArtifactStore(blobs),
                                  StoreSettings(blobs))
        store.initialize()
        self.outbox = NotificationStore(store)

    def _queued(self, target: str, provider: str):
        event = self.outbox.enqueue(target_id=target, event_type=NotificationType.TEST,
            source_kind="TEST", source_id="TEST-" + uuid.uuid4().hex,
            priority=NotificationPriority.LOW)
        self.outbox.prepare_deliveries(event.id, (provider,))

    def test_failed_sends_count_toward_hourly_and_target_daily_caps(self):
        for target in ("target-a", "target-a", "target-b"):
            self._queued(target, "fake")
        delivery, _ = self.outbox.claim("fake", hourly_cap=2, target_daily_cap=1)
        self.outbox.finish(delivery.id, DeliveryStatus.FAILED, error_code="FAKE_FAILURE")
        delivery, event = self.outbox.claim("fake", hourly_cap=2, target_daily_cap=1)
        self.assertEqual(event.target_id, "target-b")
        self.outbox.finish(delivery.id, DeliveryStatus.FAILED, error_code="FAKE_FAILURE")
        self.assertIsNone(self.outbox.claim("fake", hourly_cap=2, target_daily_cap=1))
        self.assertEqual(self.outbox.stats()["failed"], 2)

    def test_inflight_send_reserves_rate_capacity(self):
        self._queued("target-a", "fake")
        self._queued("target-a", "fake")
        self.assertIsNotNone(self.outbox.claim("fake", hourly_cap=1, target_daily_cap=1))
        self.assertIsNone(self.outbox.claim("fake", hourly_cap=1, target_daily_cap=1))


class SpecialistReportTests(unittest.TestCase):
    def _generator(self, *, store, runs, traffic, targets, **specialists):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        drafts = ReportStore(store, ArtifactStore(Path(temporary.name)))
        return ReportGenerator(store=store, drafts=drafts,
                               validations=ValidationStore(store), runs=runs,
                               traffic=traffic, targets=targets, **specialists), drafts

    def test_dom_xss_report_uses_trace_controls_and_browser_proof(self):
        fixture = dom_fixture.DOMRuntimeTests(
            "test_plan_run_controls_proof_fresh_reproduction_and_no_http_executor")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        orchestrator, run_id, _, candidate = fixture._build()
        for _ in range(5):
            orchestrator.advance(run_id, "example")
        validation, finding = fixture._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        generator, drafts = self._generator(store=fixture.evidence, runs=fixture.runs,
            traffic=fixture.traffic, targets=fixture.targets, dom=fixture.dom)
        outcome = generator.generate(finding.id, fixture.target_id)
        self.assertEqual(outcome.readiness, ReportReadiness.READY, outcome.quality_codes)
        content = drafts.markdown(outcome.draft.id, fixture.target_id)
        self.assertIn("browser input-to-execution boundary", content)
        self.assertIn("execute script in the target browser origin", content)
        self.assertIn("DOM source-to-sink trace", content)
        self.assertIn(candidate.asset_sha256, content)
        self.assertIn("decodeURIComponent", content)
        self.assertIn("iframe", content)
        self.assertIn("Controls evaluated", content)
        self.assertIn("Runtime execution variants", content)
        self.assertIn("Browser controls: CSP present", content)
        artifact = fixture.dom.candidate_asset(fixture.target_id, candidate.candidate_id)
        with fixture.evidence._connection() as db:
            db.execute("UPDATE dom_js_artifacts SET state='STALE' WHERE artifact_id=?",
                       (artifact.artifact_id,))
        stale = generator.generate(finding.id, fixture.target_id)
        self.assertEqual(stale.readiness, ReportReadiness.NEEDS_MANUAL_REVIEW)
        self.assertIn("DOM_ASSET_NOT_CURRENT", stale.quality_codes)

    def test_message_report_uses_origin_port_rpc_and_runtime_proof(self):
        fixture = message_fixture.PostMessageRuntimeTests(
            "test_missing_origin_capability_confirms_with_full_audit_chain")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        orchestrator, run_id, _, candidate = fixture._build(mode="foreign")
        fixture._finish(orchestrator, run_id)
        validation, finding = fixture._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        generator, drafts = self._generator(store=fixture.evidence, runs=fixture.runs,
            traffic=fixture.traffic, targets=fixture.targets, messages=fixture.messages)
        outcome = generator.generate(finding.id, fixture.target_id)
        self.assertEqual(outcome.readiness, ReportReadiness.READY, outcome.quality_codes)
        content = drafts.markdown(outcome.draft.id, fixture.target_id)
        self.assertIn("cross-origin messaging trust boundary", content)
        self.assertIn("receive synthetic protected fixture data across origins", content)
        self.assertIn("Cross-origin messaging protocol", content)
        self.assertIn("Origin check", content)
        self.assertIn("Source check", content)
        self.assertIn("MessagePort", content)
        self.assertIn("readSynthetic", content)
        self.assertIn("Runtime capability variants", content)
        self.assertIn("Sender/source relationship", content)
        asset = fixture.messages.dom.get_asset(fixture.target_id, candidate.artifact_ids[0])
        with fixture.evidence._connection() as db:
            db.execute("UPDATE dom_js_artifacts SET state='STALE' WHERE artifact_id=?",
                       (asset.artifact_id,))
        stale = generator.generate(finding.id, fixture.target_id)
        self.assertEqual(stale.readiness, ReportReadiness.NEEDS_MANUAL_REVIEW)
        self.assertIn("MESSAGING_ASSET_NOT_CURRENT", stale.quality_codes)

    def test_manual_review_alert_is_opt_in_and_explicitly_unconfirmed(self):
        fixture = message_fixture.PostMessageRuntimeTests(
            "test_missing_source_nonfixture_needs_sender_control")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        orchestrator, run_id, _, candidate = fixture._build(
            mode="source", body=message_fixture.SOURCE_ONLY)
        artifact = fixture.messages.current_asset(fixture.target_id, candidate.candidate_id)
        with fixture.evidence._connection() as db:
            db.execute("UPDATE dom_js_artifacts SET source='CONTROLLED_HTTP' WHERE artifact_id=?",
                       (artifact.artifact_id,))
        fixture._finish(orchestrator, run_id)
        validation, finding = fixture._validate(run_id)
        self.assertEqual(validation.status, ValidationStatus.NEEDS_MANUAL_REVIEW)
        self.assertTrue(validation.supporting_evidence_ids)
        self.assertIsNone(finding)
        outbox = NotificationStore(fixture.evidence)
        fake = FakeNotifier()
        default = NotificationManager(outbox, ValidationStore(fixture.evidence),
            fixture.runs, fixture.traffic, NotificationSettings(), (fake,))
        self.assertEqual(default.process(), 0)
        opted_in = NotificationManager(outbox, ValidationStore(fixture.evidence),
            fixture.runs, fixture.traffic,
            NotificationSettings(manual_review_enabled=True), (fake,))
        self.assertEqual(opted_in.process(), 1)
        self.assertEqual(len(fake.messages), 1)
        self.assertIn("UNCONFIRMED", fake.messages[0].title)
        self.assertNotIn("CONFIRMED_FINDING", fake.messages[0].title)

    def test_exposure_report_redacts_protected_pii(self):
        fixture = exposure_fixture.ExposureRuntimeTests(
            "test_private_profile_pii_confirms_without_exposing_value")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        run_id, _ = fixture._run(secure=False, pii=True)
        validation, finding = fixture.validator.validate_run(run_id, fixture.target)
        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        generator, drafts = self._generator(store=fixture.fx.store, runs=fixture.runs,
            traffic=fixture.fx.traffic, targets=fixture.fx.targets,
            exposure=fixture.ledger, objects=fixture.fx.objects)
        outcome = generator.generate(finding.id, fixture.target)
        self.assertEqual(outcome.readiness, ReportReadiness.READY, outcome.quality_codes)
        content = drafts.markdown(outcome.draft.id, fixture.target)
        self.assertIn("public-to-protected-content boundary", content)
        self.assertIn("an unauthenticated requester", content)
        self.assertIn("Protected resource", content)
        self.assertIn("Sensitive response bytes are intentionally omitted", content)
        self.assertNotIn("owned-profile@example.test", content)

    def test_api_graphql_report_includes_operation_and_semantic_result(self):
        fixture = api_fixture.APIReadPlanningTests("test_graphql_foreign_object_read_is_confirmed")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        result = fixture._run_local_query(secure=False)
        self.assertEqual(result["result"]["status"], ValidationStatus.CONFIRMED.value)
        finding_id = result["finding"]["id"]
        fx = fixture.case.fx
        operation = next(item for item in fixture.registry.list_operations(fixture.case.target)
                         if item.name == "GetProject")
        self.assertIsNotNone(operation.document_evidence_id)
        generator, drafts = self._generator(store=fx.store,
            runs=fixture.case.specialist.orchestrator.runs,
            traffic=fx.traffic, targets=fx.targets, objects=fx.objects,
            api=fixture.registry)
        outcome = generator.generate(finding_id, fixture.case.target)
        self.assertIn(outcome.readiness,
                      {ReportReadiness.READY, ReportReadiness.NEEDS_MANUAL_REVIEW},
                      outcome.quality_codes)
        content = drafts.markdown(outcome.draft.id, fixture.case.target)
        self.assertIn("read protected test-object data", content)
        self.assertIn("API operation", content)
        self.assertIn("GetProject", content)
        self.assertIn("Semantic result", content)
        self.assertIn("Protected owner data matched the foreign actor's GraphQL", content)
        self.assertIn("Variables", content)
        self.assertIn("Sanitized observed query/mutation", content)
        self.assertIn("query GetProject", content)
        self.assertNotIn("\"variables\"", content)
        self.assertNotIn(fixture.case.specialist._external_id(fixture.owned), content)
        malformed = fx.store.create_evidence(
            EvidenceType.MANUAL_NOTE, b'{"query":"query {"}',
            source="test_fixture", target_ref=fixture.case.target,
            provenance=EvidenceProvenance("FIXTURE", "GRAPHQL_DOCUMENT", "phase29"),
            sensitivity=Sensitivity.INTERNAL)
        with fx.store._connection() as db:
            db.execute("UPDATE api_operations SET document_evidence_id=? WHERE operation_id=?",
                       (malformed.evidence_id, operation.id))
        withheld = generator.generate(finding_id, fixture.case.target)
        self.assertEqual(withheld.readiness, ReportReadiness.NEEDS_MANUAL_REVIEW)
        self.assertIn("GRAPHQL_DOCUMENT_WITHHELD", withheld.quality_codes)


if __name__ == "__main__":
    unittest.main()
