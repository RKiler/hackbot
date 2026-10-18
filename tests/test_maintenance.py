from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import json
import unittest
from unittest.mock import patch

from hackbot.maintenance import MaintenanceCoordinator, MaintenanceError
from hackbot.profile_retention import (DisabledProfileRetentionPlan,
                                       NamedProfileRetentionPlan, ProfileRetentionPlan)
from hackbot.retention import CollectionPlan


class FakeBackup:
    def __init__(self):
        self.calls = []
        self.wait = None
        self.started = Event()

    def create(self):
        self.calls.append("create")
        self.started.set()
        if self.wait is not None:
            self.wait.wait(timeout=5)
        return FakeSummary()

    def verify(self, backup_id, *, record=False):
        self.calls.append(("verify", backup_id, record))
        return FakeSummary()


class FakeSummary:
    def to_dict(self):
        return {"backup_id": "20261015T000000Z-12345678", "verified": True}


class FakeRetention:
    def __init__(self):
        self.calls = []
        self.candidates = ("a" * 64,)

    def plan(self):
        self.calls.append("plan")
        return CollectionPlan(self.candidates, (), len(self.candidates), 17, False)

    def run(self, *, confirmed, approved_plan=None):
        self.calls.append(("run", confirmed, approved_plan.digests))
        return {"removed": 1, "reclaimed_bytes": 17}


class FakeProfiles:
    def __init__(self):
        self.calls = []

    def plan(self):
        self.calls.append("plan")
        return ProfileRetentionPlan(("BSESSION-" + "a" * 32,), 23, 1, False)

    def run(self, *, confirmed, approved_plan=None):
        self.calls.append(("run", confirmed, approved_plan.session_ids))
        return {"removed": 1, "reclaimed_bytes": 23}

    def plan_disabled(self, target_id, identity_id):
        self.calls.append(("plan_disabled", target_id, identity_id))
        return DisabledProfileRetentionPlan(
            target_id, identity_id, ("BSESSION-" + "b" * 32,), 29, 1, False)

    def run_disabled(self, target_id, identity_id, *, confirmed, approved_plan):
        self.calls.append(("run_disabled", target_id, identity_id, confirmed,
                           approved_plan.session_ids))
        return {"removed": 1, "reclaimed_bytes": 29}

    def plan_named(self, target_id, identity_id, session_id):
        self.calls.append(("plan_named", target_id, identity_id, session_id))
        return NamedProfileRetentionPlan(target_id, identity_id, (session_id,), 31)

    def run_named(self, target_id, identity_id, session_id, *, confirmed, approved_plan):
        self.calls.append(("run_named", target_id, identity_id, session_id, confirmed,
                           approved_plan.session_ids))
        return {"removed": 1, "reclaimed_bytes": 31}


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state" / "maintenance.json"
        self.backup = FakeBackup()
        self.retention = FakeRetention()
        self.manager = MaintenanceCoordinator(self.path, self.backup, self.retention)

    def test_local_plan_is_bounded_and_persists_without_digest(self):
        self.assertEqual(self.manager.status()["status"], "IDLE")
        started = self.manager.start("RETENTION_PLAN")
        self.assertEqual(started["action"], "RETENTION_PLAN")
        self.manager.wait_for_test()
        done = self.manager.status()
        self.assertEqual(done["status"], "COMPLETED")
        self.assertEqual(done["result"]["estimated_bytes"], 17)
        self.assertEqual(done["result"]["candidate_preview"],
                         ["sha256:" + "a" * 16 + "..."])
        self.assertNotIn("a" * 64, self.path.read_text())
        self.assertEqual(self.retention.calls, ["plan"])

    def test_only_one_action_runs_at_once(self):
        gate = Event()
        self.backup.wait = gate
        self.manager.start("BACKUP_CREATE")
        self.assertTrue(self.backup.started.wait(timeout=2))
        with self.assertRaisesRegex(MaintenanceError, "MAINTENANCE_BUSY"):
            self.manager.start("RETENTION_PLAN")
        gate.set()
        self.manager.wait_for_test()
        self.assertEqual(self.manager.status()["status"], "COMPLETED")
        self.assertEqual(self.backup.calls, ["create"])

    def test_restart_marks_running_action_interrupted_without_replay(self):
        self.path.parent.mkdir()
        self.path.write_text(json.dumps({"id": "MAINT-" + "1" * 32,
                                         "action": "BACKUP_CREATE", "status": "RUNNING",
                                         "created_at": "2026-10-15T00:00:00+00:00"}))
        restored = MaintenanceCoordinator(self.path, self.backup, self.retention)
        self.assertEqual(restored.status()["status"], "INTERRUPTED")
        self.assertEqual(restored.status()["reason_code"], "PROCESS_RESTART")
        self.assertEqual(self.backup.calls, [])

    def test_validation_and_explicit_cleanup_confirmation(self):
        with self.assertRaisesRegex(MaintenanceError, "CONFIRMATION_REQUIRED"):
            self.manager.start("RETENTION_RUN")
        with self.assertRaisesRegex(MaintenanceError, "INVALID_BACKUP_ID"):
            self.manager.start("BACKUP_VERIFY", backup_id="../../state")
        with self.assertRaisesRegex(MaintenanceError, "INVALID_REVIEW_ID"):
            self.manager.start("RETENTION_RUN", confirmed=True)
        review_id = self.manager.start("RETENTION_PLAN")["id"]
        self.manager.wait_for_test()
        self.manager.start("RETENTION_RUN", confirmed=True, review_id=review_id)
        self.manager.wait_for_test()
        self.assertEqual(self.retention.calls, ["plan", ("run", True, ("a" * 64,))])
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            self.manager.start("RETENTION_RUN", confirmed=True, review_id=review_id)

    def test_profile_cleanup_has_separate_review_and_confirmation(self):
        profiles = FakeProfiles()
        manager = MaintenanceCoordinator(self.path, self.backup, self.retention, profiles)
        review_id = manager.start("PROFILE_PLAN")["id"]
        manager.wait_for_test()
        self.assertEqual(manager.status()["result"]["candidate_count"], 1)
        self.assertEqual(manager.status()["result"]["candidate_preview"],
                         ["session:BSESSION-" + "a" * 9 + "..."])
        self.assertNotIn("BSESSION-" + "a" * 32, self.path.read_text())
        with self.assertRaisesRegex(MaintenanceError, "CONFIRMATION_REQUIRED"):
            manager.start("PROFILE_RUN")
        manager.start("PROFILE_RUN", confirmed=True, review_id=review_id)
        manager.wait_for_test()
        self.assertEqual(manager.status()["result"]["removed"], 1)
        self.assertEqual(profiles.calls, ["plan", ("run", True,
                                                ("BSESSION-" + "a" * 32,))])

    def test_disabled_profile_cleanup_requires_exact_identity_and_review(self):
        profiles = FakeProfiles()
        manager = MaintenanceCoordinator(self.path, self.backup, self.retention, profiles)
        target_id = "TARGET-" + "1" * 32
        identity_id = "IDENTITY-" + "2" * 32
        with self.assertRaisesRegex(MaintenanceError, "INVALID_PROFILE_IDENTITY"):
            manager.start("DISABLED_PROFILE_PLAN")
        review_id = manager.start("DISABLED_PROFILE_PLAN", target_id=target_id,
                                  identity_id=identity_id)["id"]
        manager.wait_for_test()
        self.assertEqual(manager.status()["result"]["candidate_count"], 1)
        with self.assertRaisesRegex(MaintenanceError, "CONFIRMATION_REQUIRED"):
            manager.start("DISABLED_PROFILE_RUN", target_id=target_id,
                          identity_id=identity_id, review_id=review_id)
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            manager.start("DISABLED_PROFILE_RUN", target_id=target_id,
                          identity_id="IDENTITY-" + "3" * 32,
                          review_id=review_id, confirmed=True)
        manager.start("DISABLED_PROFILE_RUN", target_id=target_id,
                      identity_id=identity_id, review_id=review_id, confirmed=True)
        manager.wait_for_test()
        self.assertEqual(manager.status()["result"]["removed"], 1)
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            manager.start("DISABLED_PROFILE_RUN", target_id=target_id,
                          identity_id=identity_id, review_id=review_id, confirmed=True)
        self.assertEqual(profiles.calls, [
            ("plan_disabled", target_id, identity_id),
            ("run_disabled", target_id, identity_id, True,
             ("BSESSION-" + "b" * 32,)),
        ])

    def test_named_profile_cleanup_requires_exact_one_use_review(self):
        profiles = FakeProfiles()
        manager = MaintenanceCoordinator(self.path, self.backup, self.retention, profiles)
        target_id = "TARGET-" + "1" * 32
        identity_id = "IDENTITY-" + "2" * 32
        session_id = "BSESSION-" + "3" * 32
        with self.assertRaisesRegex(MaintenanceError, "INVALID_PROFILE_SESSION"):
            manager.start("NAMED_PROFILE_PLAN", target_id=target_id,
                          identity_id=identity_id)
        review_id = manager.start("NAMED_PROFILE_PLAN", target_id=target_id,
                                  identity_id=identity_id, session_id=session_id)["id"]
        manager.wait_for_test()
        self.assertEqual(manager.status()["result"]["candidate_count"], 1)
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            manager.start("NAMED_PROFILE_RUN", target_id=target_id,
                          identity_id=identity_id, session_id="BSESSION-" + "4" * 32,
                          review_id=review_id, confirmed=True)
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            restored = MaintenanceCoordinator(self.path, self.backup, self.retention,
                                              profiles)
            restored.start("NAMED_PROFILE_RUN", target_id=target_id,
                           identity_id=identity_id, session_id=session_id,
                           review_id=review_id, confirmed=True)
        manager.start("NAMED_PROFILE_RUN", target_id=target_id,
                      identity_id=identity_id, session_id=session_id,
                      review_id=review_id, confirmed=True)
        manager.wait_for_test()
        self.assertEqual(manager.status()["result"]["removed"], 1)
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            manager.start("NAMED_PROFILE_RUN", target_id=target_id,
                          identity_id=identity_id, session_id=session_id,
                          review_id=review_id, confirmed=True)
        self.assertEqual(profiles.calls, [
            ("plan_named", target_id, identity_id, session_id),
            ("run_named", target_id, identity_id, session_id, True, (session_id,)),
        ])

    def test_review_is_bound_to_latest_task_and_process_lifetime(self):
        first = self.manager.start("RETENTION_PLAN")["id"]
        self.manager.wait_for_test()
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            self.manager.start("RETENTION_RUN", confirmed=True,
                               review_id="MAINT-" + "0" * 32)
        restored = MaintenanceCoordinator(self.path, self.backup, self.retention)
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            restored.start("RETENTION_RUN", confirmed=True, review_id=first)
        second = self.manager.start("RETENTION_PLAN")["id"]
        self.manager.wait_for_test()
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            self.manager.start("RETENTION_RUN", confirmed=True, review_id=first)
        self.manager.start("BACKUP_CREATE")
        self.manager.wait_for_test()
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            self.manager.start("RETENTION_RUN", confirmed=True, review_id=second)

    def test_empty_review_does_not_authorize_cleanup(self):
        self.retention.candidates = ()
        review_id = self.manager.start("RETENTION_PLAN")["id"]
        self.manager.wait_for_test()
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            self.manager.start("RETENTION_RUN", confirmed=True, review_id=review_id)

    def test_expired_review_does_not_authorize_cleanup(self):
        review_id = self.manager.start("RETENTION_PLAN")["id"]
        self.manager.wait_for_test()
        self.manager._current["finished_at"] = "2020-01-01T00:00:00+00:00"
        with self.assertRaisesRegex(MaintenanceError, "REVIEW_REQUIRED"):
            self.manager.start("RETENTION_RUN", confirmed=True, review_id=review_id)

    def test_failure_state_does_not_record_exception_secret(self):
        self.backup.create = lambda: (_ for _ in ()).throw(RuntimeError("fixture-secret"))
        self.manager.start("BACKUP_CREATE")
        self.manager.wait_for_test()
        self.assertEqual(self.manager.status()["status"], "FAILED")
        self.assertNotIn("fixture-secret", self.path.read_text())

    def test_symlink_state_is_not_followed(self):
        target = Path(self.temp.name) / "outside"
        target.write_text("protected")
        self.path.parent.mkdir()
        self.path.symlink_to(target)
        blocked = MaintenanceCoordinator(self.path, self.backup, self.retention)
        self.assertEqual(blocked.status()["reason_code"], "CORRUPT_MAINTENANCE_STATE")
        with self.assertRaises(MaintenanceError):
            blocked.start("RETENTION_PLAN")
        self.assertEqual(target.read_text(), "protected")

    def test_failed_running_state_write_prevents_action(self):
        original = self.manager._write
        writes = 0

        def fail_after_queue(state):
            nonlocal writes
            writes += 1
            if writes > 1:
                raise OSError("fixture-secret")
            original(state)

        with patch.object(self.manager, "_write", side_effect=fail_after_queue):
            self.manager.start("BACKUP_CREATE")
            self.manager.wait_for_test()
        self.assertEqual(self.backup.calls, [])
        self.assertEqual(self.manager.status()["status"], "INTERRUPTED")
        self.assertEqual(self.manager.status()["reason_code"], "PERSISTENCE_UNAVAILABLE")
        self.assertNotIn("fixture-secret", str(self.manager.status()))

    def test_failed_completion_write_marks_ambiguous_action(self):
        original = self.manager._write
        writes = 0

        def fail_completion(state):
            nonlocal writes
            writes += 1
            if writes > 2:
                raise OSError("fixture-secret")
            original(state)

        with patch.object(self.manager, "_write", side_effect=fail_completion):
            self.manager.start("BACKUP_CREATE")
            self.manager.wait_for_test()
        self.assertEqual(self.backup.calls, ["create"])
        self.assertEqual(self.manager.status()["status"], "INTERRUPTED")
        self.assertEqual(self.manager.status()["reason_code"], "PERSISTENCE_UNAVAILABLE")
        self.assertEqual(json.loads(self.path.read_text())["status"], "RUNNING")
