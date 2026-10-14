from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.auth import AuthContextManager, AuthMechanism, AuthStatus
from hackbot.browser import (
    BrowserError, BrowserProxyConfig, BrowserSessionManager, BrowserStatus,
    ExactSessionVerifier, IdentityObservation, IdentityVerificationRule,
    ProfileStore, VerificationStatus,
)
from hackbot.browser_playwright import PlaywrightBrowserDriver
from hackbot.cli import main
from hackbot.config import (BrowserSettings, ConfigError, SecretBindingConfig,
                            SecretSettings, StoreSettings, load_config)
from hackbot.identity import AccountSource, IdentityStatus
from hackbot.identity_registry import IdentityRegistry
from hackbot.secrets import RoutedSecretProvider, SecretValue
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package


EXAMPLE = Path(__file__).parent / "examples/targets/example"
SECRET = "fake-cookie-secret-phase8-ABCD"


class FakeBrowserDriver:
    name = "FAKE"

    def __init__(self) -> None:
        self.running: dict[str, Path] = {}
        self.cookies: dict[str, str] = {}
        self.observations: dict[str, IdentityObservation] = {}
        self.fail_start = False
        self.fail_import = False

    def start(self, session_id, profile, *, display, proxy):
        if self.fail_start:
            raise RuntimeError(SECRET)
        self.running[session_id] = profile

    def stop(self, session_id):
        self.running.pop(session_id, None)

    def is_running(self, session_id):
        return session_id in self.running

    def apply_imported_session(self, session_id, material, allowed_url):
        if self.fail_import or not allowed_url("https://app.example.test/"):
            raise RuntimeError(SECRET)
        if allowed_url("https://attacker.invalid/"):
            raise RuntimeError("scope bypass")
        self.cookies[session_id] = material.reveal(execution_boundary=True)

    def observe_identity(self, session_id, rule):
        return self.observations.get(session_id, IdentityObservation())


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceFactStore(self.root / "state/bughunter.sqlite3",
                                       ArtifactStore(self.root / "artifacts"),
                                       StoreSettings(self.root / "artifacts"))
        self.registry = IdentityRegistry(self.store)
        self.registry.initialize()
        self.package = load_target_package(EXAMPLE)
        self.registry.register_target(self.package)
        self.target = self.package.target.id
        self.env = {"HACKBOT_SECRET_IMPORT": SECRET}
        self.provider = RoutedSecretProvider(SecretSettings(bindings=(
            SecretBindingConfig("ref:imported", "env:HACKBOT_SECRET_IMPORT", "SESSION_IMPORT_REFERENCE"),
        )), self.env)
        self.auth = AuthContextManager(self.registry, self.provider)
        self.driver = FakeBrowserDriver()
        self.settings = BrowserSettings(profile_root=self.root / "profiles", display=":101",
                                        vnc_url="http://127.0.0.1:6081/vnc.html")
        self.manager = BrowserSessionManager(self.registry, self.auth, self.driver, self.settings)

    def tearDown(self):
        self.temp.cleanup()

    def manual(self, alias):
        identity = self.registry.register_identity(self.target, alias, status=IdentityStatus.ACTIVE)
        context = self.auth.prepare(self.target, identity.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        return identity, context

    def rule(self, identity, *, user="user-a", tenant="tenant-a"):
        return IdentityVerificationRule(
            target_id=self.target, identity_id=identity.id,
            expected_user_id=user, user_id_selector="[data-user]",
            expected_tenant_id=tenant, tenant_selector="[data-tenant]",
        )

    def test_manual_login_requires_exact_identity_and_tenant(self):
        identity, context = self.manual("admin_a")
        session = self.manager.create(self.target, identity.id)
        self.assertEqual(session.auth_context_id, context.id)
        self.assertEqual(self.manager.start(session.id).status, BrowserStatus.WAITING_LOGIN)
        self.assertEqual(self.manager.session_context(session.id).authentication_status, "UNVERIFIED")
        self.assertTrue(self.manager.session_context(session.id).vnc_login_available)
        self.assertEqual(self.manager.login_complete(session.id).status, BrowserStatus.VERIFYING_IDENTITY)
        self.assertEqual(self.manager.verify(session.id, None).status, BrowserStatus.NEEDS_MANUAL_REVIEW)
        self.assertEqual(self.auth.get(self.target, identity.id).status, AuthStatus.REAUTH_REQUIRED)
        self.driver.observations[session.id] = IdentityObservation(user_id="user-a", tenant_id="tenant-a")
        valid = self.manager.verify(session.id, self.rule(identity))
        self.assertEqual((valid.status, valid.verification_status), (BrowserStatus.VALID, VerificationStatus.MATCH))
        self.assertEqual(self.auth.get(self.target, identity.id).status, AuthStatus.VALID)
        self.assertEqual(self.manager.get_active_session(self.target, identity.id).id, session.id)
        self.assertEqual(self.manager.session_context(session.id).authentication_status, "VALID")
        self.assertEqual(self.manager.stop(session.id).status, BrowserStatus.STOPPED)
        self.assertIsNone(self.manager.get_active_session(self.target, identity.id))
        self.assertEqual(self.auth.get(self.target, identity.id).status, AuthStatus.REAUTH_REQUIRED)
        self.assertEqual(self.manager.restart(session.id).status, BrowserStatus.WAITING_LOGIN)

    def test_wrong_identity_and_wrong_tenant_are_rejected(self):
        for alias, observation in (
            ("wrong_user", IdentityObservation(user_id="user-b", tenant_id="tenant-a")),
            ("wrong_tenant", IdentityObservation(user_id="user-a", tenant_id="tenant-b")),
        ):
            with self.subTest(alias=alias):
                identity, _ = self.manual(alias)
                session = self.manager.create(self.target, identity.id)
                self.manager.start(session.id)
                self.manager.login_complete(session.id)
                self.driver.observations[session.id] = observation
                result = self.manager.verify(session.id, self.rule(identity))
                self.assertEqual((result.status, result.verification_status),
                                 (BrowserStatus.REAUTH_REQUIRED, VerificationStatus.MISMATCH))
                self.assertIsNone(self.manager.get_active_session(self.target, identity.id))

    def test_wrong_rule_and_disabled_identity_cannot_verify(self):
        identity, _ = self.manual("first")
        other, _ = self.manual("second")
        session = self.manager.create(self.target, identity.id)
        self.manager.start(session.id)
        self.manager.login_complete(session.id)
        self.driver.observations[session.id] = IdentityObservation(user_id="user-a", tenant_id="tenant-a")
        with self.assertRaises(BrowserError):
            self.manager.verify(session.id, self.rule(other))
        self.registry.disable_identity(identity.id)
        with self.assertRaises(BrowserError):
            self.manager.verify(session.id, self.rule(identity))
        self.assertNotEqual(self.manager.get(session.id).status, BrowserStatus.VALID)

    def test_wrong_second_session_does_not_invalidate_verified_first_session(self):
        identity, _ = self.manual("dual")
        first = self.manager.create(self.target, identity.id)
        self.manager.start(first.id)
        self.manager.login_complete(first.id)
        self.driver.observations[first.id] = IdentityObservation(user_id="user-a", tenant_id="tenant-a")
        self.manager.verify(first.id, self.rule(identity))
        second = self.manager.create(self.target, identity.id)
        self.manager.start(second.id)
        self.manager.login_complete(second.id)
        self.driver.observations[second.id] = IdentityObservation(user_id="wrong", tenant_id="tenant-a")
        self.assertEqual(self.manager.verify(second.id, self.rule(identity)).status, BrowserStatus.REAUTH_REQUIRED)
        self.assertEqual(self.auth.get(self.target, identity.id).status, AuthStatus.VALID)
        self.assertEqual(self.manager.get_active_session(self.target, identity.id).id, first.id)

    def test_isolation_anonymous_and_cross_target(self):
        identities = [self.manual(alias)[0] for alias in ("admin_a", "member_a", "admin_b")]
        sessions = [self.manager.create(self.target, identity.id) for identity in identities]
        anonymous = self.manager.create(self.target)
        sessions.append(anonymous)
        paths = [self.manager.profiles.path(session) for session in sessions]
        self.assertEqual(len(set(paths)), 4)
        self.assertEqual(len({session.id for session in sessions}), 4)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o700 for path in paths))
        self.assertEqual(self.manager.start(anonymous.id).status, BrowserStatus.RUNNING)
        self.assertEqual(self.manager.session_context(anonymous.id).authentication_status, "ANONYMOUS")
        self.assertIsNone(anonymous.identity_id)
        self.assertIsNone(anonymous.auth_context_id)
        self.manager.destroy(anonymous.id)
        self.assertFalse(paths[-1].exists())
        second = "TARGET-" + "f" * 32
        cross = replace(sessions[0], target_id=second,
                        profile_ref=f"{second}/{identities[0].id}/{sessions[0].id}")
        self.assertNotEqual(self.manager.profiles.path(sessions[0]), self.manager.profiles.path(cross))

    def test_imported_session_isolated_and_never_persisted(self):
        identity = self.registry.register_identity(self.target, "imported", status=IdentityStatus.ACTIVE,
                                                   account_source=AccountSource.IMPORTED_SESSION,
                                                   secret_ref="ref:imported")
        context = self.auth.prepare(self.target, identity.id)
        self.assertEqual(context.status, AuthStatus.REAUTH_REQUIRED)
        session = self.manager.create(self.target, identity.id)
        result = self.manager.start(session.id, package=self.package)
        self.assertEqual(result.status, BrowserStatus.VERIFYING_IDENTITY)
        self.assertEqual(self.driver.cookies[session.id], SECRET)
        self.assertNotIn(SECRET, repr(result) + json.dumps(result.to_dict()) + str(asdict(self.manager.session_context(session.id))))
        self.assertNotIn(SECRET.encode(), self.store.db_path.read_bytes())
        self.assertEqual(self.manager.verify(session.id, self.rule(identity)).status, BrowserStatus.NEEDS_MANUAL_REVIEW)
        other, _ = self.manual("other")
        other_session = self.manager.create(self.target, other.id)
        self.assertNotIn(other_session.id, self.driver.cookies)

    def test_import_invalid_missing_and_failed_launch_fail_closed(self):
        identity = self.registry.register_identity(self.target, "imported", status=IdentityStatus.ACTIVE,
                                                   account_source=AccountSource.IMPORTED_SESSION,
                                                   secret_ref="ref:imported")
        self.auth.prepare(self.target, identity.id)
        session = self.manager.create(self.target, identity.id)
        with self.assertRaises(BrowserError):
            self.manager.start(session.id)
        self.assertEqual(self.manager.get(session.id).status, BrowserStatus.FAILED)
        self.driver.fail_import = True
        with self.assertRaises(BrowserError) as captured:
            self.manager.start(session.id, package=self.package)
        self.assertNotIn(SECRET, str(captured.exception))
        self.env.clear()
        self.auth.prepare(self.target, identity.id)
        another = self.manager.create(self.target, identity.id)
        with self.assertRaises(BrowserError):
            self.manager.start(another.id, package=self.package)
        manual, _ = self.manual("manual")
        self.driver.fail_start = True
        failed = self.manager.create(self.target, manual.id)
        with self.assertRaises(BrowserError) as captured:
            self.manager.start(failed.id)
        self.assertNotIn(SECRET, str(captured.exception))

    def test_expiry_stale_browser_and_reopen_persistence(self):
        identity, _ = self.manual("expiry")
        session = self.manager.create(self.target, identity.id)
        self.manager.start(session.id)
        self.manager.login_complete(session.id)
        self.driver.observations[session.id] = IdentityObservation(user_id="user-a", tenant_id="tenant-a")
        self.manager.verify(session.id, self.rule(identity))
        later = self.manager.set_expiry(session.id, datetime.now(timezone.utc) + timedelta(minutes=5))
        self.assertIsNotNone(later.expires_at)
        self.driver.stop(session.id)
        self.assertIsNone(self.manager.get_active_session(self.target, identity.id))
        self.assertEqual(self.manager.reconcile_stale(session.id).status, BrowserStatus.REAUTH_REQUIRED)
        reopened = BrowserSessionManager(self.registry, self.auth, FakeBrowserDriver(), self.settings)
        self.assertEqual(reopened.get(session.id).id, session.id)
        self.assertFalse(reopened.session_context(session.id).browser_available)
        self.assertEqual(reopened.expire(session.id).status, BrowserStatus.EXPIRED)
        self.assertEqual(self.auth.get(self.target, identity.id).status, AuthStatus.EXPIRED)
        self.assertEqual(reopened.stop(session.id).status, BrowserStatus.STOPPED)
        self.assertEqual(self.auth.get(self.target, identity.id).status, AuthStatus.EXPIRED)

    def test_destroy_preserves_authenticated_profile_unless_purged(self):
        identity, _ = self.manual("cleanup")
        preserved = self.manager.create(self.target, identity.id)
        preserved_path = self.manager.profiles.path(preserved)
        self.manager.destroy(preserved.id)
        self.assertIsNone(self.manager.get(preserved.id))
        self.assertTrue(preserved_path.exists())
        purged = self.manager.create(self.target, identity.id)
        purged_path = self.manager.profiles.path(purged)
        self.manager.destroy(purged.id, purge_profile=True)
        self.assertFalse(purged_path.exists())

    def test_profile_safety_proxy_and_pagination(self):
        with self.assertRaises(BrowserError):
            ProfileStore(Path("/tmp/../profiles"))
        with self.assertRaises(BrowserError):
            BrowserProxyConfig(enabled=True, proxy_url="http://user:pass@127.0.0.1:8080")
        proxy = BrowserProxyConfig(enabled=True, proxy_url="http://127.0.0.1:8080", reference="local_proxy")
        self.assertNotIn("127.0.0.1", repr(proxy))
        anonymous = self.manager.create(self.target, proxy=proxy)
        self.assertTrue(anonymous.to_dict()["proxy_enabled"])
        self.assertNotIn("127.0.0.1", json.dumps(anonymous.to_dict()))
        self.assertEqual(self.manager.start(anonymous.id, proxy=proxy).status, BrowserStatus.RUNNING)
        identity, _ = self.manual("many")
        first = self.manager.create(self.target, identity.id)
        second = self.manager.create(self.target, identity.id)
        page = self.manager.list_sessions_for_target(self.target, limit=1)
        self.assertEqual(page.items[0].id, second.id)
        self.assertEqual(page.next_cursor, second.id)
        page2 = self.manager.list_sessions_for_target(self.target, limit=1, cursor=page.next_cursor)
        self.assertEqual(page2.items[0].id, first.id)
        with self.assertRaises(ValueError):
            self.manager.list_sessions_for_target(self.target, cursor="../../etc/passwd")
        profile = self.manager.profiles.path(first)
        profile.rmdir()
        profile.symlink_to(self.root)
        with self.assertRaises(BrowserError):
            self.manager.profiles.path(first, create=True)

    def test_browser_config_and_owned_root_reject_shared_recon_paths(self):
        config = self.root / "config.toml"
        config.write_text('[browser]\ndisplay = ":101"\nvnc_url = "http://127.0.0.1:6081/vnc.html"\n'
                          f'chromium_executable = "{self.root}/chromium"\n')
        loaded = load_config(config, environ={"HOME": str(self.root)})
        self.assertEqual(loaded.browser.display, ":101")
        self.assertEqual(loaded.browser.chromium_executable, self.root / "chromium")
        for text in ('display = ":99"', 'display = ":101"\nvnc_url = "http://127.0.0.1:6080/vnc.html"',
                     'display = ":101"\nvnc_url = "http://public.example:6081/vnc.html"',
                     'profile_root = "/tmp/../unsafe"'):
            config.write_text("[browser]\n" + text + "\n")
            with self.assertRaises(ConfigError):
                load_config(config, environ={"HOME": str(self.root)})
        occupied = self.root / "occupied"
        occupied.mkdir()
        (occupied / "recon-session").write_text("existing data")
        identity, _ = self.manual("no_adoption")
        foreign_manager = BrowserSessionManager(self.registry, self.auth, self.driver,
                                                BrowserSettings(profile_root=occupied))
        with self.assertRaises(BrowserError):
            foreign_manager.create(self.target, identity.id)
        self.assertEqual((occupied / "recon-session").read_text(), "existing data")
        symlink_parent = self.root / "linked_parent"
        symlink_parent.symlink_to(occupied, target_is_directory=True)
        with self.assertRaises(BrowserError):
            ProfileStore(symlink_parent / "new_profiles")

    def test_browser_sqlite_schema_has_no_raw_auth_columns(self):
        with sqlite3.connect(self.store.db_path) as connection:
            names = [row[1] for table in ("browser_sessions", "browser_session_events")
                     for row in connection.execute(f"PRAGMA table_info({table})")]
        self.assertFalse({"password", "cookie", "authorization", "bearer_token", "api_key",
                          "local_storage", "session_storage", "raw_session_state"} & set(names))

    def test_v3_to_v4_migration_preserves_auth_metadata(self):
        identity, context = self.manual("preserved")
        with sqlite3.connect(self.store.db_path) as connection:
            for table in ("api_inventory_progress", "api_specialist_runs", "api_candidates", "api_operations"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("behaviour_observations", "behaviour_workflows", "behaviour_expectations",
                          "behaviour_profiles", "behaviour_runs", "bootstrap_observations",
                          "bootstrap_discovery_states", "bootstrap_runs"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("exposure_candidate_sources", "exposure_candidate_events",
                          "exposure_candidates"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("message_runtime_trials", "message_candidate_events",
                          "message_type_index", "message_candidate_assets",
                          "message_protocol_candidates", "message_analysis_runs",
                          "plan_message_dispatches"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("dom_candidate_events", "plan_dom_dispatches", "dom_flow_candidates",
                          "dom_analysis_runs", "dom_source_maps", "dom_js_artifacts"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("DROP TABLE authorization_mutation_results")
            for table in ("authorization_hunt_objects", "authorization_observations",
                          "authorization_hunt_candidates",
                          "authorization_candidates", "authorization_hunts"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("finding_status_events", "finding_duplicates", "finding_locations",
                          "finding_evidence", "findings", "validation_checks", "validations"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("plan_object_requirements", "test_object_operations",
                          "test_object_reservations", "test_object_events", "test_objects"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("plan_run_events", "plan_step_manual_links", "plan_step_results",
                          "plan_run_steps", "plan_runs"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("executor_events", "executor_permits"):
                connection.execute(f"DROP TABLE {table}")
            for table in ("policy_events", "policy_approvals", "policy_decisions", "policy_actions"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("DROP TABLE skill_plan_selections")
            connection.execute("DROP TABLE skill_plans")
            for table in ("hypothesis_relationships", "hypothesis_events", "hypothesis_facts",
                          "hypothesis_evidence", "hypotheses", "profile_source_evidence", "target_profiles"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("DROP INDEX facts_target_recent_idx")
            connection.execute("DROP TABLE service_events")
            for table in ("burp_capture_index", "burp_listener_bindings", "burp_projects", "burp_bridge_health"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("DROP TABLE traffic_exchanges")
            connection.execute("DROP TABLE traffic_responses")
            connection.execute("DROP TABLE traffic_requests")
            connection.execute("DROP TABLE browser_session_events")
            connection.execute("DROP TABLE browser_sessions")
            connection.execute("PRAGMA user_version=3")
        self.store.initialize()
        with sqlite3.connect(self.store.db_path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 34)
        self.assertEqual(self.auth.get(self.target, identity.id).id, context.id)

    def test_playwright_import_adapter_rejects_foreign_or_malformed_before_cookies(self):
        class CookieContext:
            def __init__(self):
                self.cookies = []
            def add_cookies(self, cookies):
                self.cookies.extend(cookies)

        driver = PlaywrightBrowserDriver()
        fake = CookieContext()
        driver._contexts["fixture"] = fake
        good = json.dumps({"format": "hackbot-cookie-v1", "cookies": [
            {"url": "https://app.example.com/", "name": "sid", "value": SECRET},
        ]})
        driver.apply_imported_session("fixture", SecretValue(good), lambda url: url == "https://app.example.com/")
        self.assertEqual(fake.cookies[0]["value"], SECRET)
        bad = json.dumps({"format": "hackbot-cookie-v1", "cookies": [
            {"url": "https://outside.invalid/", "name": "sid", "value": SECRET},
        ]})
        with self.assertRaises(BrowserError) as captured:
            driver.apply_imported_session("fixture", SecretValue(bad), lambda url: url == "https://app.example.com/")
        self.assertNotIn(SECRET, str(captured.exception))
        self.assertEqual(len(fake.cookies), 1)

    def test_cli_safe_metadata_commands(self):
        config = self.root / "config.toml"
        config.write_text(f'[paths]\nroot = "{self.root}"\n[targets]\nroot = "{EXAMPLE.parent}"\n')
        out, err = StringIO(), StringIO()
        code = main(["--config", str(config), "browser", "create", "example", "--anonymous"],
                    environ={"HOME": str(self.root)}, stdout=out, stderr=err)
        self.assertEqual((code, err.getvalue()), (0, ""))
        created = json.loads(out.getvalue())
        self.assertTrue(created["anonymous"])
        for command in (["status", created["id"]], ["list", "example"],
                        ["reconcile", created["id"]], ["stop", created["id"]]):
            out, err = StringIO(), StringIO()
            code = main(["--config", str(config), "browser", *command],
                        environ={"HOME": str(self.root)}, stdout=out, stderr=err)
            self.assertEqual((code, err.getvalue()), (0, ""))
            self.assertNotIn(SECRET, out.getvalue())


if __name__ == "__main__":
    unittest.main()
