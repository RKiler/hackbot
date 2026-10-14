from dataclasses import replace
from datetime import datetime, timezone
from io import StringIO
import json
from pathlib import Path
import shutil
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from hackbot.artifacts import ArtifactStore
from hackbot.config import StoreSettings
from hackbot.cli import main
from hackbot.domain import ObservationState, Principal, Role, Target, Tenant
from hackbot.evidence import EvidenceProvenance, EvidenceType, FactStatus
from hackbot.identity import AccountSource, IdentityStatus, MembershipStatus
from hackbot.identity_registry import IdentityRegistry, RegistryConflict
from hackbot.logging import create_logger
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import TargetPackageError, load_target_package
from hackbot.target_package import AccountReference
from hackbot.target_scope import HostRule


EXAMPLE = Path(__file__).parent / "examples/targets/example"
NOW = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)


class IdentityRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_path = root / "state/bughunter.sqlite3"
        settings = StoreSettings(root / "artifacts", max_page_size=2)
        self.store = EvidenceFactStore(self.db_path, ArtifactStore(root / "artifacts"), settings)
        self.registry = IdentityRegistry(self.store)
        self.package = load_target_package(EXAMPLE)
        self.registry.initialize()
        self.registry.register_target(self.package)
        self.target_id = self.package.target.id

    def tearDown(self):
        self.temp.cleanup()

    def _tenant(self, name):
        tenant = Tenant(target_id=self.target_id, label=name, kind="organization")
        return self.registry.register_tenant(tenant)

    def _role(self, name):
        role = Role(target_id=self.target_id, name=name)
        return self.registry.register_role(role)

    def _identity(self, alias, **kwargs):
        return self.registry.register_identity(self.target_id, alias, status=IdentityStatus.ACTIVE,
                                               account_source=AccountSource.RESEARCHER_PROVIDED, **kwargs)

    def _evidence(self, target_id=None):
        return self.store.create_evidence(
            EvidenceType.MANUAL_NOTE, b"fictional identity observation", source="FIXTURE",
            provenance=EvidenceProvenance("FIXTURE", "identity", "local", NOW, "observed"),
            target_ref=target_id or self.target_id,
        )

    def test_registration_stable_id_unknown_principal_and_alias_scope(self):
        first = self._identity("org1_admin", secret_ref="example/org1_admin")
        self.assertRegex(first.id, r"^IDENTITY-[0-9a-f]{32}$")
        self.assertIsNone(first.principal_id)
        self.assertEqual(first.secret_ref, "example/org1_admin")
        self.assertEqual(self.registry.get_identity(self.target_id, "org1_admin"), first)
        self.assertEqual(self.registry.get_identity(self.target_id, first.id), first)
        with self.assertRaises(RegistryConflict):
            self._identity("org1_admin")
        second_target = Target(name="Second fictional program", root_domain="other.test")
        second = replace(self.package, id="other", target=second_target,
                         scope=replace(self.package.scope, package_id="other",
                                       include_hosts=(HostRule("other.test"),)))
        self.registry.register_target(second)
        other_identity = self.registry.register_identity(second.target.id, "org1_admin")
        self.assertNotEqual(first.id, other_identity.id)
        self.assertIsNone(self.registry.get_identity(second.target.id, first.id))
        self.assertEqual(self.registry.target_id_for_package("example"), self.target_id)

    def test_enabled_disabled_and_safe_update(self):
        identity = self._identity("user_a", metadata={"purpose": "owned fixture", "tags": ["admin"]})
        disabled = self.registry.disable_identity(identity.id)
        self.assertEqual(disabled.status, IdentityStatus.DISABLED)
        enabled = self.registry.enable_identity(identity.id)
        self.assertEqual(enabled.status, IdentityStatus.ACTIVE)
        updated = self.registry.update_identity(identity.id, {"purpose": "role test", "tags": ("member",),
                                                         "secret_ref": "ref:local_alias"},
                                                expected_updated_at=enabled.updated_at)
        self.assertEqual(updated.purpose, "role test")
        self.assertEqual(updated.tags, ("member",))
        self.assertEqual(updated.secret_ref, "ref:local_alias")
        with self.assertRaises(RegistryConflict):
            self.registry.update_identity(identity.id, {"status": IdentityStatus.DISABLED},
                                          expected_updated_at=identity.updated_at)
        with self.assertRaises(ValueError):
            self.registry.update_identity(identity.id, {"account_source": AccountSource.PROGRAM_PROVIDED})

    def test_secret_field_and_value_rejection_and_safe_serialization(self):
        fields = ("password", "passwd", "cookie", "cookies", "authorization", "bearer",
                  "bearer_token", "access_token", "refresh_token", "api_key", "mfa_secret", "totp_secret")
        for field in fields:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self._identity("no_secret", metadata={field: "sensitive-value"})
        identity = self._identity("owned", secret_ref="example/owned")
        for field in fields:
            with self.subTest(update_field=field), self.assertRaises(ValueError):
                self.registry.update_identity(identity.id, {field: "sensitive-value"})
        for secret in ("Bearer abc123", "Authorization: abc123", "password=abc123"):
            with self.subTest(secret=secret), self.assertRaises(ValueError):
                self._identity("bad", metadata={"purpose": secret})
        with self.assertRaises(ValueError):
            self._identity("bad_ref", secret_ref="Bearer abc123")
        rendered = json.dumps(identity.to_dict())
        self.assertNotIn("example/owned", rendered)
        self.assertNotIn("password", rendered)
        self.assertTrue(identity.to_dict()["has_secret_reference"])
        self.assertNotIn("example/owned", repr(identity))
        stream = StringIO()
        logger = create_logger(stream=stream, environ={"HACKBOT_SECRET": "raw-sentinel"})
        logger.info("identity summary", extra={"context": identity.to_dict()})
        self.assertNotIn("example/owned", stream.getvalue())
        self.assertNotIn("raw-sentinel", stream.getvalue())

    def test_principal_is_phase4_model_and_can_be_linked_later(self):
        identity = self._identity("user_a")
        principal = self.registry.register_principal(Principal(target_id=self.target_id, label="user_a"))
        self.assertEqual(self.registry.get_principal(self.target_id, principal.id), principal)
        link = self.registry.link_principal(identity.id, principal.id)
        self.assertRegex(link.id, r"^PRINCIPAL_LINK-[0-9a-f]{32}$")
        self.assertEqual(self.registry.get_identity(self.target_id, identity.id).principal_id, principal.id)
        self.assertEqual(self.registry.list_identities_for_principal(self.target_id, principal.id).items[0].id,
                         identity.id)
        self.assertEqual(self.registry.list_principal_links(identity.id).items[0].principal_id, principal.id)
        other = self.registry.register_principal(Principal(target_id=self.target_id, label="user_b"))
        evidence = self._evidence()
        fact = self.store.create_fact(identity.id, "resolves_to", other.id, confidence=0.65,
                                      evidence_ids=(evidence.evidence_id,), source="FIXTURE",
                                      target_ref=self.target_id)
        observed = self.registry.link_principal(identity.id, other.id,
                                                observation_state=ObservationState.OBSERVED,
                                                evidence_ids=(evidence.evidence_id,), fact_id=fact.fact_id)
        self.assertEqual(observed.observation_state, ObservationState.OBSERVED)
        self.assertEqual(len(self.registry.list_principal_links(identity.id).items), 2)
        self.assertEqual(self.registry.get_identity(self.target_id, identity.id).principal_id, principal.id)
        self.assertEqual(self.registry.list_identities_for_principal(self.target_id, principal.id).items, ())
        with self.assertRaises(RegistryConflict):
            self.registry.link_principal(identity.id, other.id,
                                         observation_state=ObservationState.OBSERVED,
                                         evidence_ids=(evidence.evidence_id,), fact_id=fact.fact_id)

    def test_memberships_multiple_tenants_and_tenant_scoped_roles(self):
        admin = self._role("admin")
        member = self._role("member")
        tenant_a = self._tenant("org1")
        tenant_b = self._tenant("org2")
        identity = self._identity("shared_user")
        first = self.registry.add_membership(identity.id, tenant_a.id, role_ids=(admin.id, member.id),
                                             status=MembershipStatus.ACTIVE, is_primary=True)
        second = self.registry.add_membership(identity.id, tenant_b.id, role_ids=(member.id,),
                                              status=MembershipStatus.ACTIVE)
        self.assertRegex(first.id, r"^MEMBERSHIP-[0-9a-f]{32}$")
        self.assertEqual(set(self.registry.get_membership(first.id).role_ids), {admin.id, member.id})
        self.assertEqual(self.registry.get_membership(second.id).role_ids, (member.id,))
        self.assertTrue(self.registry.get_membership(first.id).is_primary)
        self.assertFalse(self.registry.get_membership(second.id).is_primary)
        self.assertEqual(self.registry.get_tenant(self.target_id, tenant_a.id).label, "org1")
        self.assertEqual(self.registry.get_role(self.target_id, admin.id).name, "admin")
        with self.assertRaises(RegistryConflict):
            self.registry.add_membership(identity.id, tenant_b.id, status=MembershipStatus.ACTIVE,
                                         is_primary=True)
        inactive = self.registry.set_membership_status(first.id, MembershipStatus.INACTIVE)
        self.assertFalse(inactive.is_primary)
        self.assertEqual(self.registry.set_membership_roles(second.id, (admin.id,)).role_ids, (admin.id,))

    def test_roleless_membership_and_cross_target_refs(self):
        tenant = self._tenant("org1")
        identity = self._identity("viewer")
        membership = self.registry.add_membership(identity.id, tenant.id, status=MembershipStatus.ACTIVE)
        self.assertEqual(membership.role_ids, ())
        with self.assertRaises(ValueError):
            self.registry.add_membership(identity.id, tenant.id, role_ids=("ROLE-" + "1" * 32,))
        with self.assertRaises(ValueError):
            self.registry.add_membership(identity.id, "TENANT-" + "2" * 32)

    def test_configured_and_observed_are_separate_and_fact_backed(self):
        tenant = self._tenant("org1")
        role = self._role("admin")
        identity = self._identity("owner")
        configured = self.registry.add_membership(identity.id, tenant.id, role_ids=(role.id,),
                                                   status=MembershipStatus.ACTIVE, is_primary=True)
        evidence = self._evidence()
        fact = self.store.create_fact(identity.id, "member_of", tenant.id, confidence=0.7,
                                      evidence_ids=(evidence.evidence_id,), source="FIXTURE",
                                      target_ref=self.target_id)
        observed = self.registry.add_membership(identity.id, tenant.id, role_ids=(),
                                                 status=MembershipStatus.ACTIVE,
                                                 observation_state=ObservationState.OBSERVED,
                                                 evidence_ids=(evidence.evidence_id,), fact_id=fact.fact_id)
        self.assertNotEqual(configured.id, observed.id)
        self.assertEqual(len(self.registry.list_memberships(identity.id).items), 2)
        self.assertEqual(self.registry.get_membership(configured.id).role_ids, (role.id,))
        self.assertEqual(self.registry.get_membership(observed.id).role_ids, ())
        with self.assertRaises(RegistryConflict):
            self.registry.add_membership(identity.id, tenant.id,
                                         observation_state=ObservationState.OBSERVED,
                                         evidence_ids=(evidence.evidence_id,), fact_id=fact.fact_id)
        with self.assertRaises(RegistryConflict):
            self.registry.set_membership_roles(observed.id, (role.id,))
        with self.assertRaises(ValueError):
            self.registry.add_membership(identity.id, tenant.id,
                                         observation_state=ObservationState.OBSERVED,
                                         evidence_ids=(evidence.evidence_id,))
        wrong = self.store.create_fact(identity.id, "member_of", "TENANT-" + "9" * 32,
                                       confidence=0.4, evidence_ids=(evidence.evidence_id,),
                                       source="FIXTURE", target_ref=self.target_id)
        with self.assertRaises(ValueError):
            self.registry.add_membership(identity.id, tenant.id,
                                         observation_state=ObservationState.OBSERVED,
                                         evidence_ids=(evidence.evidence_id,), fact_id=wrong.fact_id)
        self.store.change_fact_status(fact.fact_id, FactStatus.RETRACTED,
                                      producer="MANUAL", reason="fixture correction")
        with self.assertRaises(ValueError):
            self.registry.add_membership(identity.id, tenant.id,
                                         observation_state=ObservationState.OBSERVED,
                                         evidence_ids=(evidence.evidence_id,), fact_id=fact.fact_id)

    def test_bounded_queries_and_comparison_sets(self):
        tenant_a = self._tenant("org1")
        tenant_b = self._tenant("org2")
        admin = self._role("admin")
        member = self._role("member")
        a = self._identity("a_admin")
        b = self._identity("b_member")
        c = self._identity("c_admin")
        self.registry.add_membership(a.id, tenant_a.id, role_ids=(admin.id,), status=MembershipStatus.ACTIVE)
        self.registry.add_membership(b.id, tenant_a.id, role_ids=(member.id,), status=MembershipStatus.ACTIVE)
        self.registry.add_membership(c.id, tenant_b.id, role_ids=(admin.id,), status=MembershipStatus.ACTIVE)
        page = self.registry.list_identities(self.target_id, limit=1)
        self.assertEqual(len(page.items), 1)
        self.assertEqual(page.items[0].alias, "a_admin")
        self.assertEqual(self.registry.list_identities(self.target_id, limit=1, cursor=page.next_cursor).items[0].alias,
                         "b_member")
        self.assertEqual({x.alias for x in self.registry.list_identities_for_tenant(self.target_id, tenant_a.id).items},
                         {"a_admin", "b_member"})
        self.assertEqual({x.alias for x in self.registry.list_identities_with_role(self.target_id, admin.id,
                                                                                     tenant_id=tenant_a.id).items},
                         {"a_admin"})
        same = self.registry.list_same_tenant_different_role_pairs(self.target_id, limit=1)
        self.assertEqual(len(same), 1)
        self.assertEqual({same[0].left_identity_id, same[0].right_identity_id}, {a.id, b.id})
        cross = self.registry.list_cross_tenant_identity_pairs(self.target_id, limit=10)
        self.assertEqual({frozenset((x.left_identity_id, x.right_identity_id)) for x in cross},
                         {frozenset((a.id, c.id)), frozenset((b.id, c.id))})
        self.registry.add_membership(b.id, tenant_b.id, role_ids=(member.id,), status=MembershipStatus.ACTIVE)
        cross = self.registry.list_cross_tenant_identity_pairs(self.target_id, limit=10)
        self.assertEqual({frozenset((x.left_identity_id, x.right_identity_id)) for x in cross},
                         {frozenset((a.id, c.id))})
        self.registry.disable_identity(b.id)
        self.assertEqual(len(self.registry.list_same_tenant_different_role_pairs(self.target_id)), 0)
        with self.assertRaises(ValueError):
            self.registry.list_identities(self.target_id, limit=0)

    def test_package_import_reopen_and_idempotency(self):
        imported = self.registry.import_package_accounts(self.package)
        self.assertEqual({item.alias for item in imported}, {"org1_admin", "org1_member", "org2_admin"})
        self.assertEqual(len(self.registry.import_package_accounts(self.package)), 3)
        self.assertEqual(self.registry.get_identity(self.target_id, "org1_admin").secret_ref, "ref:fixture_admin")
        tenants = {item.alias: self.registry.list_memberships(item.id).items[0].tenant_id for item in imported}
        self.assertEqual(tenants["org1_admin"], tenants["org1_member"])
        self.assertNotEqual(tenants["org1_admin"], tenants["org2_admin"])
        reopened_store = EvidenceFactStore(self.db_path, self.store.artifacts, self.store.settings)
        reopened = IdentityRegistry(reopened_store)
        first_page = reopened.list_identities(self.target_id, limit=10)
        second_page = reopened.list_identities(self.target_id, limit=10, cursor=first_page.next_cursor)
        self.assertEqual(len(first_page.items) + len(second_page.items), 3)
        self.assertEqual(len(reopened.list_same_tenant_different_role_pairs(self.target_id)), 1)
        self.assertEqual(len(reopened.list_cross_tenant_identity_pairs(self.target_id)), 2)

    def test_package_unknown_tenant_and_invalid_role_hint(self):
        unknown = replace(self.package, accounts=(AccountReference(alias="no_tenant"),))
        identity = self.registry.import_package_accounts(unknown)[0]
        self.assertEqual(self.registry.list_memberships(identity.id).items, ())
        bad = replace(self.package, accounts=(AccountReference(alias="bad", role_hint="admin"),))
        with self.assertRaises(ValueError):
            self.registry.import_package_accounts(bad)
        self.assertIsNone(self.registry.get_identity(self.target_id, "bad"))

    def test_package_file_rejects_credential_fields_before_registry_import(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory) / "example"
            shutil.copytree(EXAMPLE, folder)
            accounts = folder / "accounts.yaml"
            accounts.write_text("accounts:\n  owned:\n    tenant: org1\n    role: admin\n    cookie: fictional-secret\n")
            with self.assertRaises(TargetPackageError):
                load_target_package(folder)
            self.assertEqual(self.registry.list_identities(self.target_id).items, ())

    def test_cli_list_show_and_secret_safe_output(self):
        self.registry.import_package_accounts(self.package)
        with TemporaryDirectory() as directory:
            target_root = Path(directory) / "targets"
            target_root.mkdir()
            shutil.copytree(EXAMPLE, target_root / "example")
            config = Path(directory) / "config.toml"
            config.write_text(f'[paths]\nroot = "{Path(self.temp.name)}"\n'
                              f'[targets]\nroot = "{target_root}"\n')
            for command in (["identity", "list", "example"],
                            ["identity", "show", "example", "org1_admin"]):
                output, errors = StringIO(), StringIO()
                code = main(["--config", str(config), *command],
                            environ={"HOME": directory, "HACKBOT_RECON_DSN": "invalid://raw-secret"},
                            stdout=output, stderr=errors)
                self.assertEqual((code, errors.getvalue()), (0, ""))
                body = json.loads(output.getvalue())
                self.assertEqual(body["recon_inventory"], "NOT_CONSULTED")
                self.assertNotIn("ref:fixture_admin", output.getvalue())
                self.assertNotIn("invalid://raw-secret", output.getvalue())
            self.assertEqual(body["identity"]["alias"], "org1_admin")
            self.assertEqual(body["memberships"][0]["tenant_label"], "org1")
            self.assertEqual(body["memberships"][0]["roles"][0]["name"], "admin")
            output, errors = StringIO(), StringIO()
            code = main(["--config", str(config), "identity", "show", "example", "missing"],
                        environ={"HOME": directory}, stdout=output, stderr=errors)
            self.assertEqual(code, 1)
            self.assertEqual(output.getvalue(), "")

    def test_cli_import_is_explicit_local_only_and_idempotent(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target_root = root / "targets"
            target_root.mkdir()
            shutil.copytree(EXAMPLE, target_root / "example")
            config = root / "config.toml"
            state_root = root / "local_state"
            config.write_text(f'[paths]\nroot = "{state_root}"\n'
                              f'[targets]\nroot = "{target_root}"\n')
            output, errors = StringIO(), StringIO()
            code = main(["--config", str(config), "identity", "list", "example"],
                        environ={"HOME": directory}, stdout=output, stderr=errors)
            self.assertEqual(code, 2)
            self.assertFalse(state_root.exists())
            for _ in range(2):
                output, errors = StringIO(), StringIO()
                code = main(["--config", str(config), "identity", "import", "example"],
                            environ={"HOME": directory, "HACKBOT_RECON_DSN": "invalid://secret"},
                            stdout=output, stderr=errors)
                self.assertEqual((code, errors.getvalue()), (0, ""))
                self.assertEqual(json.loads(output.getvalue())["count"], 3)
                self.assertNotIn("ref:fixture_admin", output.getvalue())
            self.assertTrue((state_root / "state/bughunter.sqlite3").is_file())
            output, errors = StringIO(), StringIO()
            code = main(["--config", str(config), "identity", "list", "example"],
                        environ={"HOME": directory}, stdout=output, stderr=errors)
            self.assertEqual((code, errors.getvalue()), (0, ""))
            self.assertEqual(len(json.loads(output.getvalue())["items"]), 3)

    def test_migration_from_phase3_schema_preserves_fact_rows(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "bughunter.sqlite3"
            sql = (Path(__file__).parents[1] / "src/hackbot/migrations/001_evidence_facts.sql").read_text()
            with sqlite3.connect(path) as connection:
                connection.executescript(sql)
                connection.execute("PRAGMA user_version=1")
                connection.execute("""INSERT INTO facts
                    (fact_id,subject,predicate,object_ref,confidence,source,observed_at,created_at,target_ref,sensitivity)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    ("FA-" + "1" * 32, "subject", "is_test", "object", 0.5, "MANUAL",
                     NOW.isoformat(), NOW.isoformat(), None, "INTERNAL"))
            settings = StoreSettings(Path(directory) / "artifacts")
            store = EvidenceFactStore(path, ArtifactStore(settings.artifact_root), settings)
            IdentityRegistry(store).initialize()
            with sqlite3.connect(path) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 34)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM facts").fetchone()[0], 1)

    def test_sqlite_schema_has_no_credential_or_session_columns(self):
        with sqlite3.connect(self.db_path) as connection:
            schema = " ".join(row[0] for row in connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name LIKE 'registry_%'"))
        columns = []
        with sqlite3.connect(self.db_path) as connection:
            for table in ("registry_targets", "registry_principals", "registry_tenants", "registry_roles",
                          "registry_identities", "registry_principal_links", "registry_memberships",
                          "registry_membership_roles"):
                columns.extend(row[1] for row in connection.execute(f"PRAGMA table_info({table})"))
        for forbidden in ("password", "cookie", "authorization", "bearer_token", "access_token",
                          "refresh_token", "api_key", "mfa_secret", "session_state", "browser_storage"):
            self.assertNotIn(forbidden, columns)
        self.assertIn("secret_ref", columns)
        self.assertIn("CREATE TABLE registry_identities", schema)


if __name__ == "__main__":
    unittest.main()
