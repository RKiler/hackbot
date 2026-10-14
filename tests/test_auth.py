from dataclasses import asdict
from datetime import datetime, timezone
from io import StringIO
import json
from pathlib import Path
import pickle
import sqlite3
from tempfile import TemporaryDirectory
import traceback
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.auth import AuthContext, AuthContextManager, AuthMechanism, AuthPreparation, AuthStatus
from hackbot.cli import main
from hackbot.config import ConfigError, SecretBindingConfig, SecretSettings, StoreSettings, load_config
from hackbot.identity import AccountSource, IdentityStatus
from hackbot.identity_registry import IdentityRegistry
from hackbot.logging import create_logger
from hackbot.secrets import (
    BearerCredential, CookieCredential, EnvironmentSecretProvider, HeaderCredential,
    ImportedSessionCredential, LoginFileCredential, ManualLoginCredential, ManualLoginSecretProvider,
    RoutedSecretProvider, SecretError, SecretKind, SecretMetadata, SecretUnavailable, SecretValue,
    UsernamePasswordCredential,
)
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package


EXAMPLE = Path(__file__).parent / "examples/targets/example"
FIXTURE_VALUE = "fake-phase7-secret-value"


class SecretValueTests(unittest.TestCase):
    def test_output_and_explicit_reveal(self):
        value = SecretValue(FIXTURE_VALUE)
        self.assertNotIn(FIXTURE_VALUE, repr(value) + str(value) + f"{value}")
        self.assertEqual(value, SecretValue(FIXTURE_VALUE))
        self.assertNotEqual(value, SecretValue("other-fixture"))
        self.assertEqual(SecretValue("p\u00e4ss"), SecretValue("p\u00e4ss"))
        with self.assertRaises(SecretError):
            value.reveal()
        self.assertEqual(value.reveal(execution_boundary=True), FIXTURE_VALUE)
        with self.assertRaises(TypeError):
            hash(value)

    def test_json_dataclass_dump_and_pickle_are_safe(self):
        value = SecretValue(FIXTURE_VALUE)
        with self.assertRaises(TypeError):
            json.dumps(value)
        with self.assertRaises(TypeError):
            pickle.dumps(value)
        descriptor = CookieCredential(value)
        self.assertNotIn(FIXTURE_VALUE, repr(descriptor) + str(asdict(descriptor)))
        with self.assertRaises(TypeError):
            json.dumps(asdict(descriptor))

    def test_credential_descriptors_reject_raw_strings_and_redact(self):
        value = SecretValue(FIXTURE_VALUE)
        descriptors = (
            UsernamePasswordCredential(password=value, username=SecretValue("fake-user")),
            CookieCredential(value), BearerCredential(value),
            HeaderCredential((("Authorization", value),)), ManualLoginCredential(),
            ImportedSessionCredential("ref:imported_fixture"), LoginFileCredential("ref:login_fixture"),
        )
        for descriptor in descriptors:
            with self.subTest(type=type(descriptor).__name__):
                rendered = repr(descriptor) + str(asdict(descriptor)) + json.dumps(descriptor.to_dict())
                self.assertNotIn(FIXTURE_VALUE, rendered)
                self.assertNotIn("fake-user", rendered)
        for constructor in (lambda: UsernamePasswordCredential(password=FIXTURE_VALUE),
                            lambda: CookieCredential(FIXTURE_VALUE),
                            lambda: BearerCredential(FIXTURE_VALUE),
                            lambda: HeaderCredential((("Authorization", FIXTURE_VALUE),))):
            with self.assertRaises(SecretError):
                constructor()
        with self.assertRaises(ValueError):
            ImportedSessionCredential("../../cookie-jar")
        with self.assertRaises(ValueError):
            LoginFileCredential("../../credentials.json")


class ProviderTests(unittest.TestCase):
    def test_env_lookup_is_explicit_prefix_restricted_and_no_enumeration(self):
        provider = EnvironmentSecretProvider(("HACKBOT_SECRET_",),
                                             {"HACKBOT_SECRET_TEST": FIXTURE_VALUE, "AWS_SECRET_KEY": "other"})
        self.assertTrue(provider.exists("env:HACKBOT_SECRET_TEST"))
        self.assertEqual(provider.get("env:HACKBOT_SECRET_TEST").reveal(execution_boundary=True), FIXTURE_VALUE)
        self.assertEqual(provider.metadata("env:HACKBOT_SECRET_TEST").provider, "ENV")
        for ref in ("env:AWS_SECRET_KEY", "env:../../etc/passwd", "env:HACKBOT_SECRET_bad", "file:/etc/passwd"):
            with self.subTest(ref=ref), self.assertRaises(SecretError):
                provider.get(ref)
        with self.assertRaises(SecretUnavailable):
            provider.get("env:HACKBOT_SECRET_MISSING")
        self.assertFalse(hasattr(provider, "list"))

    def test_manual_provider_is_metadata_only(self):
        manual = ManualLoginSecretProvider()
        self.assertFalse(manual.exists("manual:fixture"))
        self.assertEqual(manual.metadata("manual:fixture").kind, SecretKind.LOGIN_DESCRIPTOR)
        with self.assertRaises(SecretUnavailable):
            manual.get("manual:fixture")

    def test_opaque_routing_rotation_and_invalid_provider(self):
        settings = SecretSettings(bindings=(SecretBindingConfig("example/org1_admin", "env:HACKBOT_SECRET_TEST", "COOKIE"),))
        environment = {"HACKBOT_SECRET_TEST": "fake-old"}
        router = RoutedSecretProvider(settings, environment)
        self.assertEqual(router.metadata("example/org1_admin").kind, SecretKind.COOKIE)
        self.assertEqual(router.get("example/org1_admin").reveal(execution_boundary=True), "fake-old")
        environment["HACKBOT_SECRET_TEST"] = "fake-new"
        self.assertEqual(router.get("example/org1_admin").reveal(execution_boundary=True), "fake-new")
        with self.assertRaises(SecretUnavailable):
            router.get("ref:unconfigured")
        with self.assertRaises(ValueError):
            router.get("../../etc/passwd")
        with self.assertRaises(ConfigError):
            SecretBindingConfig("ref:bad", "file:/etc/passwd", "COOKIE")
        with self.assertRaises(ConfigError):
            SecretSettings(bindings=(SecretBindingConfig("ref:bad", "env:AWS_SECRET_KEY", "COOKIE"),))

    def test_provider_errors_never_print_secret(self):
        class FailingEnv(dict):
            def get(self, key, default=None):
                raise RuntimeError(FIXTURE_VALUE)

        provider = EnvironmentSecretProvider(("HACKBOT_SECRET_",), FailingEnv())
        for action in (provider.exists, provider.get, provider.metadata):
            with self.assertRaises(SecretError) as captured:
                action("env:HACKBOT_SECRET_TEST")
            self.assertNotIn(FIXTURE_VALUE, str(captured.exception))
            self.assertNotIn(FIXTURE_VALUE, "".join(traceback.format_exception(captured.exception)))
        with self.assertRaises(SecretError):
            SecretMetadata(FIXTURE_VALUE, SecretKind.COOKIE, True)

    def test_typed_config_rejects_raw_values_and_unsupported_sources(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('[secrets]\nallowed_env_prefixes = ["HACKBOT_SECRET_"]\n'
                            '[secrets.references."example/org1_admin"]\n'
                            'provider_ref = "env:HACKBOT_SECRET_TEST"\nkind = "COOKIE"\n')
            config = load_config(path, environ={"HOME": directory})
            self.assertEqual(config.secrets.bindings[0].kind, "COOKIE")
            for text in ('provider_ref = "file:/etc/passwd"',
                         'provider_ref = "env:AWS_SECRET_KEY"',
                         'provider_ref = "fake-phase7-secret-value"'):
                path.write_text('[secrets.references."example/org1_admin"]\n' + text + '\n')
                with self.assertRaises(ConfigError) as captured:
                    load_config(path, environ={"HOME": directory})
                self.assertNotIn(FIXTURE_VALUE, str(captured.exception))


class AuthManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.path = root / "state/bughunter.sqlite3"
        settings = StoreSettings(root / "artifacts")
        self.store = EvidenceFactStore(self.path, ArtifactStore(root / "artifacts"), settings)
        self.registry = IdentityRegistry(self.store)
        self.registry.initialize()
        self.package = load_target_package(EXAMPLE)
        self.registry.register_target(self.package)
        self.target_id = self.package.target.id
        self.env = {"HACKBOT_SECRET_TEST": FIXTURE_VALUE}
        self.binding = SecretSettings(bindings=(
            SecretBindingConfig("ref:fixture_admin", "env:HACKBOT_SECRET_TEST", "COOKIE"),
        ))
        self.provider = RoutedSecretProvider(self.binding, self.env)
        self.manager = AuthContextManager(self.registry, self.provider)

    def tearDown(self):
        self.temp.cleanup()

    def _identity(self, alias, **kwargs):
        return self.registry.register_identity(self.target_id, alias, status=IdentityStatus.ACTIVE, **kwargs)

    def test_ready_is_not_valid_and_context_is_stable(self):
        identity = self._identity("owned", secret_ref="ref:fixture_admin")
        first = self.manager.prepare(self.target_id, identity.id)
        self.assertEqual((first.mechanism, first.status, first.preparation),
                         (AuthMechanism.COOKIE, AuthStatus.READY, AuthPreparation.READY))
        self.assertEqual(self.manager.get(self.target_id, identity.id), first)
        second = self.manager.prepare(self.target_id, identity.id)
        self.assertEqual(first.id, second.id)
        self.assertGreater(second.updated_at, first.updated_at)
        self.assertNotIn(FIXTURE_VALUE, repr(second) + str(asdict(second)) + json.dumps(second.to_dict()))
        self.assertNotIn("ref:fixture_admin", json.dumps(second.to_dict()))
        with self.assertRaises(ValueError):
            self.manager.set_status(self.target_id, identity.id, AuthStatus.VALID)

    def test_missing_secret_reauth_and_rotation_without_identity_change(self):
        identity = self._identity("owned", secret_ref="ref:fixture_admin")
        self.env.clear()
        missing = self.manager.prepare(self.target_id, identity.id)
        self.assertEqual((missing.status, missing.preparation),
                         (AuthStatus.REAUTH_REQUIRED, AuthPreparation.MISSING_SECRET))
        self.env["HACKBOT_SECRET_TEST"] = FIXTURE_VALUE
        ready = self.manager.prepare(self.target_id, identity.id)
        self.assertEqual(ready.status, AuthStatus.READY)
        self.assertEqual(ready.id, missing.id)
        self.assertEqual(identity.id, ready.identity_id)

    def test_manual_without_password_and_imported_reference(self):
        manual = self._identity("manual")
        context = self.manager.prepare(self.target_id, manual.id, mechanism=AuthMechanism.MANUAL_LOGIN)
        self.assertEqual((context.status, context.preparation),
                         (AuthStatus.REAUTH_REQUIRED, AuthPreparation.MANUAL_LOGIN_REQUIRED))
        repeated = self.manager.prepare(self.target_id, manual.id)
        self.assertEqual((repeated.id, repeated.mechanism, repeated.preparation),
                         (context.id, AuthMechanism.MANUAL_LOGIN, AuthPreparation.MANUAL_LOGIN_REQUIRED))
        imported = self._identity("imported", account_source=AccountSource.IMPORTED_SESSION,
                                  secret_ref="ref:imported_fixture")
        pending = self.manager.prepare(self.target_id, imported.id)
        self.assertEqual((pending.mechanism, pending.preparation),
                         (AuthMechanism.IMPORTED_SESSION, AuthPreparation.MISSING_SECRET))
        self.assertNotEqual(pending.status, AuthStatus.VALID)
        provider = RoutedSecretProvider(SecretSettings(bindings=(
            SecretBindingConfig("ref:imported_fixture", "manual:imported_fixture", "SESSION_IMPORT_REFERENCE"),
        )), {})
        configured = AuthContextManager(self.registry, provider).prepare(self.target_id, imported.id)
        self.assertEqual(configured.preparation, AuthPreparation.MISSING_SECRET)
        self.assertEqual(configured.status, AuthStatus.REAUTH_REQUIRED)
        available = RoutedSecretProvider(SecretSettings(bindings=(
            SecretBindingConfig("ref:imported_fixture", "env:HACKBOT_SECRET_SESSION", "SESSION_IMPORT_REFERENCE"),
        )), {"HACKBOT_SECRET_SESSION": "fake-import-material"})
        self.assertEqual(AuthContextManager(self.registry, available).prepare(self.target_id, imported.id).preparation,
                         AuthPreparation.IMPORTED_SESSION_REFERENCE_AVAILABLE)

    def test_disabled_pending_wrong_target_and_unknown_provider(self):
        disabled = self._identity("disabled", secret_ref="ref:fixture_admin")
        self.registry.disable_identity(disabled.id)
        locked = self.manager.prepare(self.target_id, disabled.id)
        self.assertEqual((locked.status, locked.preparation),
                         (AuthStatus.LOCKED, AuthPreparation.DISABLED))
        pending = self.registry.register_identity(self.target_id, "pending", status=IdentityStatus.PENDING,
                                                  secret_ref="ref:fixture_admin")
        self.assertEqual(self.manager.prepare(self.target_id, pending.id).status, AuthStatus.REAUTH_REQUIRED)
        with self.assertRaises(ValueError):
            self.manager.prepare(self.target_id, "IDENTITY-" + "0" * 32)
        self.assertIsNone(self.manager.get("TARGET-" + "0" * 32, disabled.id))
        unbound = self._identity("unbound", secret_ref="ref:unconfigured")
        self.assertEqual(self.manager.prepare(self.target_id, unbound.id).preparation,
                         AuthPreparation.MISSING_SECRET)

    def test_identity_change_during_prepare_cannot_leave_ready_context(self):
        identity = self._identity("race", secret_ref="ref:fixture_admin")

        class ChangingProvider:
            def metadata(inner, ref):
                self.registry.disable_identity(identity.id)
                return SecretMetadata("ENV", SecretKind.COOKIE, True)

        with self.assertRaisesRegex(ValueError, "Identity changed"):
            AuthContextManager(self.registry, ChangingProvider()).prepare(self.target_id, identity.id)
        self.assertIsNone(self.manager.get(self.target_id, identity.id))
        self.assertEqual(self.manager.prepare(self.target_id, identity.id).status, AuthStatus.LOCKED)

    def test_provider_exception_is_sanitized_and_no_secret_is_persisted(self):
        class LeakyProvider:
            def metadata(self, ref):
                raise RuntimeError(FIXTURE_VALUE)

        identity = self._identity("broken", secret_ref="ref:fixture_admin")
        result = AuthContextManager(self.registry, LeakyProvider()).prepare(self.target_id, identity.id)
        self.assertEqual(result.preparation, AuthPreparation.UNSUPPORTED_PROVIDER)
        with sqlite3.connect(self.path) as connection:
            dump = "\n".join(connection.iterdump())
        self.assertNotIn(FIXTURE_VALUE, dump)
        self.assertIn("ref:fixture_admin", dump)

    def test_expire_reauth_and_reopen_preserve_metadata(self):
        identity = self._identity("owned", secret_ref="ref:fixture_admin")
        first = self.manager.prepare(self.target_id, identity.id)
        expired = self.manager.expire(self.target_id, identity.id)
        self.assertEqual(expired.status, AuthStatus.EXPIRED)
        reauth = self.manager.mark_reauth_required(self.target_id, identity.id)
        self.assertEqual(reauth.status, AuthStatus.REAUTH_REQUIRED)
        self.assertEqual(reauth.id, first.id)
        reopened = AuthContextManager(IdentityRegistry(self.store), self.provider)
        self.assertEqual(reopened.get(self.target_id, identity.id), reauth)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM auth_context_events").fetchone()[0], 3)

    def test_model_validates_refs_and_chronology(self):
        identity = self._identity("owned")
        now = datetime.now(timezone.utc)
        context = AuthContext(target_id=self.target_id, identity_id=identity.id,
                              mechanism=AuthMechanism.MANUAL_LOGIN, status=AuthStatus.REAUTH_REQUIRED,
                              created_at=now, updated_at=now, expires_at=now)
        self.assertIsNotNone(context.expires_at)
        with self.assertRaises(ValueError):
            AuthContext(target_id=self.target_id, identity_id=identity.id,
                        mechanism=AuthMechanism.COOKIE, status=AuthStatus.READY, secret_ref="password=bad")

    def test_schema_migrates_v2_and_has_only_opaque_references(self):
        identity = self._identity("preserved")
        with sqlite3.connect(self.path) as connection:
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
            connection.execute("DROP TABLE auth_context_events")
            connection.execute("DROP TABLE auth_contexts")
            connection.execute("PRAGMA user_version=2")
        self.store.initialize()
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 34)
            names = {row[1] for row in connection.execute("PRAGMA table_info(auth_contexts)")}
        self.assertIn("secret_ref", names)
        self.assertEqual(self.registry.get_identity(self.target_id, identity.id), identity)
        for forbidden in ("password", "cookie", "access_token", "refresh_token", "api_key",
                          "authorization", "mfa_secret", "session_value", "session_state"):
            self.assertNotIn(forbidden, names)

    def test_logging_and_cli_never_emit_secret(self):
        stream = StringIO()
        logger = create_logger(stream=stream, environ={"HACKBOT_SECRET_TEST": FIXTURE_VALUE})
        logger.info("resolved", extra={"context": {"Authorization": "Bearer " + FIXTURE_VALUE,
                                                  "nested": {"cookie": FIXTURE_VALUE}}})
        logger.info("wrapper=%s", SecretValue(FIXTURE_VALUE))
        self.assertNotIn(FIXTURE_VALUE, stream.getvalue())
        separate = StringIO()
        create_logger(stream=separate, environ={}).info("wrapper=%s", SecretValue(FIXTURE_VALUE))
        self.assertNotIn(FIXTURE_VALUE, separate.getvalue())
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.write_text(f'[paths]\nroot = "{self.temp.name}"\n'
                              f'[targets]\nroot = "{EXAMPLE.parent}"\n'
                              '[secrets.references."ref:fixture_admin"]\n'
                              'provider_ref = "env:HACKBOT_SECRET_TEST"\nkind = "COOKIE"\n')
            env = {"HOME": directory, "HACKBOT_SECRET_TEST": FIXTURE_VALUE,
                   "HACKBOT_RECON_DSN": "invalid://fixture"}
            output, error = StringIO(), StringIO()
            code = main(["--config", str(config), "secret", "check", "ref:fixture_admin"],
                        environ=env, stdout=output, stderr=error)
            self.assertEqual((code, error.getvalue()), (0, ""))
            self.assertTrue(json.loads(output.getvalue())["available"])
            self.assertNotIn(FIXTURE_VALUE, output.getvalue())
            owned = self._identity("owned", secret_ref="ref:fixture_admin")
            output, error = StringIO(), StringIO()
            code = main(["--config", str(config), "auth", "status", "example", "owned"],
                        environ=env, stdout=output, stderr=error)
            self.assertEqual((code, error.getvalue()), (0, ""))
            self.assertEqual(json.loads(output.getvalue())["status"], "UNINITIALIZED")
            self.manager.prepare(self.target_id, owned.id)
            output, error = StringIO(), StringIO()
            code = main(["--config", str(config), "auth", "status", "example", "owned"],
                        environ=env, stdout=output, stderr=error)
            self.assertEqual((code, error.getvalue()), (0, ""))
            self.assertEqual(json.loads(output.getvalue())["status"], "READY")
            self.assertNotIn(FIXTURE_VALUE, output.getvalue())
            output, error = StringIO(), StringIO()
            code = main(["--config", str(config), "secret", "check", "ref:unknown"],
                        environ=env, stdout=output, stderr=error)
            self.assertEqual((code, error.getvalue()), (1, ""))
            self.assertFalse(json.loads(output.getvalue())["available"])
            self.assertNotIn(FIXTURE_VALUE, output.getvalue())
            self.assertNotIn(FIXTURE_VALUE, output.getvalue() + error.getvalue())
