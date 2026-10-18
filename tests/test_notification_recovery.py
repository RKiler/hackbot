"""Bounded, local-only notification recovery fixtures."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import uuid

from hackbot.artifacts import ArtifactStore
from hackbot.config import StoreSettings
from hackbot.notification_store import (DeliveryStatus, NotificationPriority,
                                        NotificationStore, NotificationType)
from hackbot.store import EvidenceFactStore


class NotificationRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.blobs = self.root / "blobs"
        self.db_path = self.root / "state" / "bughunter.sqlite3"
        self.settings = StoreSettings(self.blobs)
        self.store = EvidenceFactStore(self.db_path, ArtifactStore(self.blobs), self.settings)
        self.store.initialize()
        self.target_id = "TARGET-" + uuid.uuid4().hex
        self.outbox = NotificationStore(self.store)

    def _event(self) -> str:
        event = self.outbox.enqueue(
            target_id=self.target_id, event_type=NotificationType.TEST,
            source_kind="TEST", source_id="TEST-" + uuid.uuid4().hex,
            priority=NotificationPriority.LOW,
        )
        self.outbox.prepare_deliveries(event.id, ("fixture",))
        return event.id

    def _reopened(self) -> NotificationStore:
        store = EvidenceFactStore(self.db_path, ArtifactStore(self.blobs), self.settings)
        return NotificationStore(store)

    def test_inflight_recovery_is_batched_visible_and_never_auto_resends(self) -> None:
        for _ in range(3):
            self._event()
            claimed = self.outbox.claim("fixture")
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed[0].status, DeliveryStatus.SENDING)
        self.assertEqual(self.outbox.stats(self.target_id)["sending"], 3)

        restarted = self._reopened()
        self.assertEqual(restarted.reconcile_inflight(batch_size=2), 3)
        self.assertEqual(restarted.reconcile_inflight(batch_size=2), 0)
        self.assertIsNone(restarted.claim("fixture"))
        self.assertEqual(restarted.stats(self.target_id)["sending"], 0)
        self.assertEqual(restarted.stats(self.target_id)["needs_review"], 3)
        with restarted.store._connection() as db:
            rows = db.execute(
                "SELECT status,error_code FROM notification_attempts ORDER BY attempt_id"
            ).fetchall()
        self.assertEqual([(row[0], row[1]) for row in rows],
                         [("NEEDS_REVIEW", "IN_FLIGHT_AFTER_RESTART")] * 3)

    def test_pending_delivery_survives_restart_and_is_claimed_once(self) -> None:
        self._event()
        restarted = self._reopened()
        self.assertEqual(restarted.reconcile_inflight(batch_size=1), 0)
        claimed = restarted.claim("fixture")
        self.assertIsNotNone(claimed)
        restarted.finish(claimed[0].id, DeliveryStatus.SENT)
        self.assertIsNone(restarted.claim("fixture"))
        self.assertEqual(restarted.stats(self.target_id)["sent"], 1)

    def test_recovery_batch_must_be_bounded(self) -> None:
        for invalid in (0, 1001, True):
            with self.assertRaises(ValueError):
                self.outbox.reconcile_inflight(batch_size=invalid)


if __name__ == "__main__":
    unittest.main()
