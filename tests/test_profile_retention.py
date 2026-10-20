from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
import unittest
from unittest.mock import patch

from hackbot.artifacts import ArtifactStore
from hackbot.auth import AuthContextManager, AuthMechanism
from hackbot.browser import BrowserSessionManager
from hackbot.config import BrowserSettings, SecretSettings, StoreSettings
from hackbot.identity import IdentityStatus
from hackbot.identity_registry import IdentityRegistry
from hackbot.profile_retention import (BrowserProfileCollector, ProfileRetentionError,
                                       ProfileRetentionPolicy)
from hackbot.secrets import RoutedSecretProvider
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class Driver:
    name = "FAKE"

    def __init__(self):
        self.running = set()

    def start(self, session_id, _profile, *, display, proxy):
        self.running.add(session_id)

    def stop(self, session_id):
        self.running.discard(session_id)

    def is_running(self, session_id):
        return session_id in self.running


class ProfileRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.store = EvidenceFactStore(root / "state/bughunter.sqlite3",
                                       ArtifactStore(root / "artifacts"),
                                       StoreSettings(root / "artifacts"))
        self.registry = IdentityRegistry(self.store)
        self.registry.initialize()
        package = load_target_package(EXAMPLE)
        self.registry.register_target(package)
        self.target_id = package.target.id
        self.driver = Driver()
        self.browser = BrowserSessionManager(
            self.registry, AuthContextManager(self.registry, RoutedSecretProvider(SecretSettings())),
            self.driver, BrowserSettings(profile_root=root / "profiles"))
        self.safe = True
        self.collector = BrowserProfileCollector(
            self.browser, ProfileRetentionPolicy(24, 100, 10),
            lambda: self.safe, root / "logs/profile-retention.jsonl")

    def terminal_anonymous(self):
        session = self.browser.create(self.target_id)
        self.browser.start(session.id)
        self.browser.stop(session.id)
        path = self.browser.profiles.path(session)
        (path / "cache.bin").write_bytes(b"temporary browser cache")
        old = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
        with self.store._connection() as db:
            db.execute("UPDATE browser_sessions SET created_at=?,updated_at=? WHERE session_id=?",
                       (old, old, session.id))
        return session, path

    def test_terminal_anonymous_profile_requires_confirmation_and_preserves_metadata(self):
        session, path = self.terminal_anonymous()
        plan = self.collector.plan()
        self.assertEqual(plan.session_ids, (session.id,))
        self.assertEqual(plan.estimated_bytes, len(b"temporary browser cache"))
        with self.assertRaises(ProfileRetentionError):
            self.collector.run(confirmed=False)
        self.assertTrue(path.exists())
        result = self.collector.run(confirmed=True)
        self.assertEqual(result["removed"], 1)
        self.assertFalse(path.exists())
        self.assertIsNotNone(self.browser.get(session.id))
        self.assertEqual(self.collector.plan().session_ids, ())

    def test_retired_session_profile_waits_for_reviewed_retention(self):
        session, path = self.terminal_anonymous()
        self.browser.retire(session.id)
        self.assertIsNone(self.browser.get(session.id))
        self.assertTrue(path.exists())
        plan = self.collector.plan()
        self.assertEqual(plan.session_ids, (session.id,))
        with self.assertRaises(ProfileRetentionError):
            self.collector.run(confirmed=False, approved_plan=plan)
        self.assertTrue(path.exists())
        self.assertEqual(self.collector.run(confirmed=True, approved_plan=plan)["removed"], 1)
        self.assertFalse(path.exists())
        self.assertIsNotNone(self.browser.get_for_retention(session.id))

    def test_process_uncertainty_or_running_session_prevents_cleanup(self):
        session, path = self.terminal_anonymous()
        self.safe = False
        with self.assertRaises(ProfileRetentionError):
            self.collector.plan()
        with self.assertRaises(ProfileRetentionError):
            self.collector.run(confirmed=True)
        self.safe = True
        self.driver.running.add(session.id)
        self.assertEqual(self.collector.plan().session_ids, ())
        self.assertTrue(path.exists())

    def test_named_identity_profile_is_not_selected(self):
        identity = self.registry.register_identity(self.target_id, "owned_member",
                                                   status=IdentityStatus.ACTIVE)
        self.browser.auth.prepare(self.target_id, identity.id,
                                  mechanism=AuthMechanism.MANUAL_LOGIN)
        session = self.browser.create(self.target_id, identity.id)
        self.browser.start(session.id)
        self.browser.stop(session.id)
        old = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
        with self.store._connection() as db:
            db.execute("UPDATE browser_sessions SET created_at=?,updated_at=? WHERE session_id=?",
                       (old, old, session.id))
        path = self.browser.profiles.path(session)
        self.assertEqual(self.collector.plan().session_ids, ())
        self.collector.run(confirmed=True)
        self.assertTrue(path.is_dir())

    def terminal_named(self):
        identity = self.registry.register_identity(self.target_id, "disabled_member",
                                                   status=IdentityStatus.ACTIVE)
        self.browser.auth.prepare(self.target_id, identity.id,
                                  mechanism=AuthMechanism.MANUAL_LOGIN)
        session = self.browser.create(self.target_id, identity.id)
        self.browser.start(session.id)
        self.browser.stop(session.id)
        path = self.browser.profiles.path(session)
        (path / "session-cache.bin").write_bytes(b"owned session data")
        old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        with self.store._connection() as db:
            db.execute("UPDATE browser_sessions SET created_at=?,updated_at=? WHERE session_id=?",
                       (old, old, session.id))
        return identity, session, path, old

    def age_named_session(self, session_id, *, days=31):
        old = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self.store._connection() as db:
            db.execute("UPDATE browser_sessions SET created_at=?,updated_at=? WHERE session_id=?",
                       (old, old, session_id))

    def test_active_identity_profile_requires_exact_old_session_and_review(self):
        identity, session, path, _ = self.terminal_named()
        self.assertEqual(self.collector.plan_named(self.target_id, identity.id,
                                                   session.id).session_ids, ())
        self.age_named_session(session.id)
        reviewed = self.collector.plan_named(self.target_id, identity.id, session.id)
        self.assertEqual(reviewed.session_ids, (session.id,))
        self.assertEqual(reviewed.estimated_bytes, len(b"owned session data"))
        self.assertEqual(self.collector.plan().session_ids, ())
        with self.assertRaises(ProfileRetentionError):
            self.collector.run_named(self.target_id, identity.id, session.id,
                                     confirmed=False, approved_plan=reviewed)
        with self.assertRaises(ProfileRetentionError):
            self.collector.run_named(self.target_id, identity.id,
                                     "BSESSION-" + "0" * 32, confirmed=True,
                                     approved_plan=reviewed)
        self.assertTrue(path.exists())
        result = self.collector.run_named(self.target_id, identity.id, session.id,
                                          confirmed=True, approved_plan=reviewed)
        self.assertEqual(result["removed"], 1)
        self.assertFalse(path.exists())
        self.assertIsNotNone(self.browser.get(session.id))
        self.assertIn("TERMINAL_ACTIVE_IDENTITY_BROWSER_PROFILE",
                      self.collector.audit_path.read_text())

    def test_named_review_fails_closed_after_recent_use_or_auth_binding(self):
        identity, session, path, _ = self.terminal_named()
        self.age_named_session(session.id)
        reviewed = self.collector.plan_named(self.target_id, identity.id, session.id)
        with self.store._connection() as db:
            db.execute("UPDATE browser_sessions SET last_used_at=? WHERE session_id=?",
                       (datetime.now(timezone.utc).isoformat(), session.id))
        with self.assertRaises(ProfileRetentionError):
            self.collector.run_named(self.target_id, identity.id, session.id,
                                     confirmed=True, approved_plan=reviewed)
        with self.store._connection() as db:
            db.execute("UPDATE browser_sessions SET last_used_at=NULL WHERE session_id=?",
                       (session.id,))
            db.execute("UPDATE auth_contexts SET status='VALID',browser_session_ref=? "
                       "WHERE target_id=? AND identity_id=?",
                       (session.id, self.target_id, identity.id))
        self.assertEqual(self.collector.plan_named(self.target_id, identity.id,
                                                   session.id).session_ids, ())
        self.assertTrue(path.exists())

    def test_named_cleanup_and_browser_start_are_serialized(self):
        identity, session, path, _ = self.terminal_named()
        self.age_named_session(session.id)
        reviewed = self.collector.plan_named(self.target_id, identity.id, session.id)
        deleting = Event()
        release = Event()
        attempting_start = Event()
        started = Event()
        errors = []
        cleanup_errors = []
        original_delete = self.browser.profiles.delete

        def held_delete(value):
            deleting.set()
            if not release.wait(timeout=3):
                raise AssertionError("cleanup fixture timed out")
            original_delete(value)

        def launch():
            try:
                attempting_start.set()
                self.browser.start(session.id)
                started.set()
            except Exception as exc:
                errors.append(exc)

        def cleanup_profile():
            try:
                self.collector.run_named(self.target_id, identity.id, session.id,
                                         confirmed=True, approved_plan=reviewed)
            except Exception as exc:
                cleanup_errors.append(exc)

        with patch.object(self.browser.profiles, "delete", side_effect=held_delete):
            cleanup = Thread(target=cleanup_profile)
            cleanup.start()
            self.assertTrue(deleting.wait(timeout=2))
            browser = Thread(target=launch)
            browser.start()
            self.assertTrue(attempting_start.wait(timeout=2))
            self.assertFalse(started.wait(timeout=0.1))
            self.assertNotIn(session.id, self.driver.running)
            release.set()
            cleanup.join(timeout=3)
            browser.join(timeout=3)
        self.assertFalse(cleanup.is_alive())
        self.assertFalse(browser.is_alive())
        self.assertEqual(cleanup_errors, [])
        self.assertEqual(errors, [])
        self.assertTrue(started.is_set())
        self.assertTrue(path.exists())

    def test_disabled_identity_requires_grace_review_and_confirmation(self):
        identity, session, path, old = self.terminal_named()
        with self.assertRaises(ProfileRetentionError):
            self.collector.plan_disabled(self.target_id, identity.id)
        self.registry.disable_identity(identity.id)
        with self.assertRaises(ProfileRetentionError):
            self.collector.plan_disabled(self.target_id, identity.id)
        with self.store._connection() as db:
            db.execute("UPDATE registry_identities SET created_at=?,updated_at=? WHERE identity_id=?",
                       (old, old, identity.id))
        reviewed = self.collector.plan_disabled(self.target_id, identity.id)
        self.assertEqual(reviewed.session_ids, (session.id,))
        self.assertEqual(reviewed.estimated_bytes, len(b"owned session data"))
        self.assertEqual(self.collector.plan().session_ids, ())
        with self.assertRaises(ProfileRetentionError):
            self.collector.run_disabled(self.target_id, identity.id, confirmed=False,
                                        approved_plan=reviewed)
        self.assertTrue(path.exists())
        outcome = self.collector.run_disabled(self.target_id, identity.id, confirmed=True,
                                              approved_plan=reviewed)
        self.assertEqual(outcome["removed"], 1)
        self.assertFalse(path.exists())
        self.assertIsNotNone(self.browser.get(session.id))
        self.assertIn("TERMINAL_DISABLED_IDENTITY_BROWSER_PROFILE",
                      self.collector.audit_path.read_text())

    def test_reenabled_or_busy_identity_cannot_be_cleaned_from_old_review(self):
        identity, session, path, old = self.terminal_named()
        self.registry.disable_identity(identity.id)
        with self.store._connection() as db:
            db.execute("UPDATE registry_identities SET created_at=?,updated_at=? WHERE identity_id=?",
                       (old, old, identity.id))
        reviewed = self.collector.plan_disabled(self.target_id, identity.id)
        self.safe = False
        with self.assertRaises(ProfileRetentionError):
            self.collector.run_disabled(self.target_id, identity.id, confirmed=True,
                                        approved_plan=reviewed)
        self.safe = True
        self.registry.enable_identity(identity.id)
        with self.assertRaises(ProfileRetentionError):
            self.collector.run_disabled(self.target_id, identity.id, confirmed=True,
                                        approved_plan=reviewed)
        self.assertTrue(path.exists())

    def test_disabled_review_is_bound_to_exact_identity_and_sessions(self):
        identity, session, path, old = self.terminal_named()
        self.registry.disable_identity(identity.id)
        with self.store._connection() as db:
            db.execute("UPDATE registry_identities SET created_at=?,updated_at=? WHERE identity_id=?",
                       (old, old, identity.id))
        reviewed = self.collector.plan_disabled(self.target_id, identity.id)
        with self.assertRaises(ProfileRetentionError):
            self.collector.run_disabled(self.target_id, "IDENTITY-" + "a" * 32,
                                        confirmed=True, approved_plan=reviewed)
        self.assertTrue(path.exists())

    def test_disabled_cleanup_does_not_include_profile_eligible_after_review(self):
        identity, first, first_path, old = self.terminal_named()
        second = self.browser.create(self.target_id, identity.id)
        self.browser.start(second.id)
        self.browser.stop(second.id)
        second_path = self.browser.profiles.path(second)
        (second_path / "cache.bin").write_bytes(b"newer session")
        self.registry.disable_identity(identity.id)
        with self.store._connection() as db:
            db.execute("UPDATE registry_identities SET created_at=?,updated_at=? WHERE identity_id=?",
                       (old, old, identity.id))
        reviewed = self.collector.plan_disabled(self.target_id, identity.id)
        self.assertEqual(reviewed.session_ids, (first.id,))
        with self.store._connection() as db:
            db.execute("UPDATE browser_sessions SET created_at=?,updated_at=? WHERE session_id=?",
                       (old, old, second.id))
        self.assertEqual(set(self.collector.plan_disabled(self.target_id, identity.id).session_ids),
                         {first.id, second.id})
        outcome = self.collector.run_disabled(self.target_id, identity.id, confirmed=True,
                                              approved_plan=reviewed)
        self.assertEqual(outcome["removed"], 1)
        self.assertFalse(first_path.exists())
        self.assertTrue(second_path.exists())

    def test_recent_named_session_use_keeps_profile_despite_old_terminal_status(self):
        identity, session, path, old = self.terminal_named()
        self.registry.disable_identity(identity.id)
        with self.store._connection() as db:
            db.execute("UPDATE registry_identities SET created_at=?,updated_at=? WHERE identity_id=?",
                       (old, old, identity.id))
            db.execute("UPDATE browser_sessions SET last_used_at=? WHERE session_id=?",
                       (datetime.now(timezone.utc).isoformat(), session.id))
        reviewed = self.collector.plan_disabled(self.target_id, identity.id)
        self.assertEqual(reviewed.session_ids, ())
        self.assertTrue(path.exists())

    def test_timestamp_offset_cannot_make_recent_use_look_expired(self):
        identity, session, path, old = self.terminal_named()
        self.registry.disable_identity(identity.id)
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        recent_local = (cutoff + timedelta(hours=1)).astimezone(
            timezone(timedelta(hours=-5))).isoformat()
        with self.store._connection() as db:
            db.execute("UPDATE registry_identities SET created_at=?,updated_at=? WHERE identity_id=?",
                       (old, old, identity.id))
            db.execute("UPDATE browser_sessions SET last_used_at=? WHERE session_id=?",
                       (recent_local, session.id))
        self.assertEqual(self.collector.plan_disabled(self.target_id, identity.id).session_ids, ())
        self.assertTrue(path.exists())

    def test_internal_symlink_is_removed_without_following_target(self):
        session, path = self.terminal_anonymous()
        outside = Path(self.temp.name) / "outside"
        outside.write_bytes(b"preserve")
        (path / "browser-lock").symlink_to(outside)
        self.assertEqual(self.collector.plan().session_ids, (session.id,))
        self.collector.run(confirmed=True)
        self.assertEqual(outside.read_bytes(), b"preserve")

    def test_confirmed_cleanup_does_not_expand_beyond_reviewed_profiles(self):
        first, first_path = self.terminal_anonymous()
        reviewed = self.collector.plan()
        second, second_path = self.terminal_anonymous()
        self.assertEqual(set(self.collector.plan().session_ids), {first.id, second.id})
        result = self.collector.run(confirmed=True, approved_plan=reviewed)
        self.assertEqual(result["removed"], 1)
        self.assertFalse(first_path.exists())
        self.assertTrue(second_path.exists())
