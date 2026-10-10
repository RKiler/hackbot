from dataclasses import replace
from datetime import datetime, timezone
from io import StringIO
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

import yaml

from hackbot.cli import main
from hackbot.config import load_config
from hackbot.recon import Provenance, ReconTarget
from hackbot.target_loader import (
    TargetPackageError, TargetPackageRepository, load_target_package,
)
from hackbot.target_policy import (
    AutonomyAction, AutonomyPolicy, PolicyDecision, ProgramRules, RatePolicy, RiskLevel,
)
from hackbot.target_recon import resolve_recon_target
from hackbot.target_scope import (
    HostRule, PathMatch, PathRule, ProgramScope, ScopeResult,
)


EXAMPLE = Path(__file__).parent / "examples/targets/example"


def fixture():
    return load_target_package(EXAMPLE)


def edited_package(changes):
    directory = TemporaryDirectory()
    folder = Path(directory.name) / "example"
    shutil.copytree(EXAMPLE, folder)
    config = yaml.safe_load((folder / "target.yaml").read_text())
    changes(config)
    (folder / "target.yaml").write_text(yaml.safe_dump(config))
    return directory, folder


class TargetScopeTests(unittest.TestCase):
    def setUp(self):
        self.package = fixture()
        self.scope = self.package.scope

    def result(self, url):
        return self.scope.evaluate_url(url).result

    def test_exact_and_wildcard_descendants_but_not_hostile_suffixes(self):
        for url in ("https://example.test/", "https://api.example.test/",
                    "https://deep.api.example.test/"):
            self.assertEqual(self.result(url), ScopeResult.IN_SCOPE)
        for url in ("https://notexample.test/", "https://example.test.attacker.test/",
                    "https://attackerexample.test/", "https://fooexample.test/",
                    "https://example.test../"):
            self.assertNotEqual(self.result(url), ScopeResult.IN_SCOPE)
        wildcard_only = replace(self.scope, include_hosts=(HostRule("*.example.test"),))
        self.assertEqual(wildcard_only.evaluate_url("https://example.test/").result, ScopeResult.UNKNOWN)
        self.assertEqual(wildcard_only.evaluate_url("https://a.example.test/").result, ScopeResult.IN_SCOPE)

    def test_explicit_exclusion_overrides_wildcard(self):
        decision = self.scope.evaluate_url("https://billing.example.test/")
        self.assertEqual(decision.result, ScopeResult.OUT_OF_SCOPE)
        self.assertEqual(decision.reason, "excluded_host")
        self.assertEqual(decision.matched_rule, "billing.example.test")
        self.assertEqual(decision.package_id, "example")

    def test_case_trailing_dot_and_idna(self):
        self.assertEqual(self.result("HTTPS://API.EXAMPLE.TEST./x"), ScopeResult.IN_SCOPE)
        idna = replace(self.scope, include_hosts=(HostRule("bücher.example.test"),))
        self.assertEqual(idna.evaluate_url("https://xn--bcher-kva.example.test/").result, ScopeResult.IN_SCOPE)
        self.assertEqual(idna.evaluate_url("https://BÜCHER.EXAMPLE.TEST./").result, ScopeResult.IN_SCOPE)

    def test_scheme_and_port_restrictions(self):
        for url in ("http://api.example.test/", "https://api.example.test:8443/"):
            self.assertEqual(self.result(url), ScopeResult.OUT_OF_SCOPE)
        self.assertEqual(self.result("https://api.example.test:443/"), ScopeResult.IN_SCOPE)
        self.assertEqual(self.result("https://api.example.test:0/"), ScopeResult.UNKNOWN)
        self.assertEqual(self.result("https://api.example.test:/"), ScopeResult.UNKNOWN)
        self.assertEqual(self.result("https://api.example.test:99999/"), ScopeResult.UNKNOWN)
        custom = replace(self.scope, include_hosts=(HostRule("api.example.test", schemes=("http",), ports=(8080,)),),
                         default_schemes=("https",), default_ports=(443,))
        self.assertEqual(custom.evaluate_url("http://api.example.test:8080/").result, ScopeResult.IN_SCOPE)
        self.assertEqual(custom.evaluate_url("https://api.example.test/").result, ScopeResult.OUT_OF_SCOPE)
        with self.assertRaises(ValueError):
            replace(self.scope, default_schemes=None)

    def test_path_inclusion_exclusion_and_ambiguity(self):
        self.assertEqual(self.result("https://api.example.test/internal/x"), ScopeResult.OUT_OF_SCOPE)
        self.assertEqual(self.result("https://api.example.test/internalized"), ScopeResult.IN_SCOPE)
        scoped = replace(self.scope, include_paths=(PathRule("/api", host="api.example.test"),),
                         exclude_paths=(PathRule("/api/private", host="api.example.test"),))
        self.assertEqual(scoped.evaluate_url("https://api.example.test/api").result, ScopeResult.IN_SCOPE)
        self.assertEqual(scoped.evaluate_url("https://api.example.test/api/public?q=1").result, ScopeResult.IN_SCOPE)
        self.assertEqual(scoped.evaluate_url("https://api.example.test/apix").result, ScopeResult.OUT_OF_SCOPE)
        self.assertEqual(scoped.evaluate_url("https://api.example.test/api/private/x").result, ScopeResult.OUT_OF_SCOPE)
        self.assertEqual(scoped.evaluate_url("https://example.test/api").result, ScopeResult.OUT_OF_SCOPE)
        exact = replace(self.scope, include_paths=(PathRule("/api", match=PathMatch.EXACT),))
        self.assertEqual(exact.evaluate_url("https://example.test/api/x").result, ScopeResult.OUT_OF_SCOPE)
        for path in ("/api/%2e%2e/private", "/api//private", "/api/../private", "/api/;private", "/api/\\private"):
            self.assertEqual(scoped.evaluate_url("https://api.example.test" + path).result, ScopeResult.UNKNOWN)

    def test_malformed_url_never_authorized(self):
        for url in ("https://example.test.attacker.test", "https://user@example.test/",
                    "https://example.test/#fragment", "https://example.test/\n", "ftp://example.test/"):
            self.assertNotEqual(self.result(url), ScopeResult.IN_SCOPE)

    def test_provenance_and_safe_serialization(self):
        summary = self.scope.to_dict()
        self.assertEqual(summary["provenance"]["source_file"], "target.yaml")
        self.assertEqual(summary["provenance"]["kind"], "RESEARCHER")
        self.assertNotIn("fixture-operator", json.dumps(summary))
        self.assertNotIn("local-fixture-policy", json.dumps(summary))


class TargetPolicyTests(unittest.TestCase):
    def test_autonomy_precedence_owned_objects_and_risk_floor(self):
        policy = AutonomyPolicy(safe_read=PolicyDecision.ALLOW,
                                state_changing=PolicyDecision.ALLOW,
                                create_disposable_objects=PolicyDecision.ALLOW,
                                cross_identity_testing=PolicyDecision.ALLOW)
        self.assertEqual(policy.evaluate(RiskLevel.SAFE_READ).decision, PolicyDecision.ALLOW)
        self.assertEqual(policy.evaluate(RiskLevel.STATE_CHANGING, AutonomyAction.CREATE_DISPOSABLE_OBJECT).decision,
                         PolicyDecision.ALLOW)
        self.assertEqual(policy.evaluate(RiskLevel.SAFE_READ, AutonomyAction.CREATE_DISPOSABLE_OBJECT).decision,
                         PolicyDecision.DENY)
        self.assertEqual(policy.evaluate(RiskLevel.PASSIVE, AutonomyAction.FINANCIAL).decision, PolicyDecision.DENY)
        self.assertEqual(policy.evaluate(RiskLevel.SAFE_READ, AutonomyAction.CROSS_IDENTITY_TEST).decision,
                         PolicyDecision.DENY)
        self.assertEqual(policy.evaluate(RiskLevel.SAFE_READ, AutonomyAction.CROSS_IDENTITY_TEST,
                                         owned_test_object=True).decision, PolicyDecision.ALLOW)
        self.assertEqual(policy.evaluate(RiskLevel.STATE_CHANGING, AutonomyAction.MODIFY_DISPOSABLE_OBJECT,
                                         owned_test_object=True).decision, PolicyDecision.DENY)

    def test_program_rules_and_package_combination(self):
        package = fixture()
        self.assertEqual(package.rules.excluded_vulnerability_classes, ("social_engineering",))
        self.assertEqual(package.rules.forbidden_actions, ("credential_stuffing",))
        self.assertEqual(package.evaluate_url("https://api.example.test/", risk=RiskLevel.SAFE_READ).result,
                         PolicyDecision.ALLOW)
        self.assertEqual(package.evaluate_url("https://billing.example.test/", risk=RiskLevel.SAFE_READ).result,
                         PolicyDecision.DENY)
        self.assertEqual(package.evaluate_url("https://api.example.test/", risk=RiskLevel.STATE_CHANGING,
                                              action=AutonomyAction.ACCOUNT_CREATION).result, PolicyDecision.DENY)
        self.assertEqual(replace(package, status=package.status.PAUSED).evaluate_url(
            "https://api.example.test/", risk=RiskLevel.SAFE_READ).result, PolicyDecision.DENY)
        unknown = replace(package, rules=ProgramRules(), autonomy=AutonomyPolicy(safe_read=PolicyDecision.ALLOW))
        self.assertEqual(unknown.evaluate_url("https://api.example.test/", risk=RiskLevel.SAFE_READ).result,
                         PolicyDecision.REQUIRE_APPROVAL)

    def test_rate_policy_validation(self):
        self.assertEqual(RatePolicy(0.5, 15, 2, 2).max_concurrency, 2)
        for kwargs in ({"requests_per_second": 0}, {"requests_per_second": float("nan")},
                       {"requests_per_minute": 0}, {"max_concurrency": 0}, {"burst": -1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                RatePolicy(**kwargs)


class TargetLoaderTests(unittest.TestCase):
    def test_valid_fixture_and_safe_summary(self):
        package = fixture()
        self.assertEqual(package.target.id, "TARGET-11111111111141118111111111111111")
        self.assertEqual(package.primary_domain, "example.test")
        self.assertEqual(package.version, 1)
        self.assertEqual(package.configured_at, datetime(2026, 10, 10, 12, tzinfo=timezone.utc))
        self.assertEqual(package.context.description, "Fictional application used only for local package tests.")
        self.assertIn("never included", package.read_document("researcher_notes"))
        self.assertEqual(len(package.accounts), 2)
        self.assertEqual(package.accounts[0].secret_ref, "ref:fixture_admin")
        summary = package.to_json()
        for forbidden in ("fixture_admin", "fixture-operator", "local-fixture-policy", "No live target",
                          "Fictional application used"):
            self.assertNotIn(forbidden, summary)
        self.assertEqual(json.loads(summary)["recon_inventory"], "NOT_CONSULTED")

    def test_missing_fields_and_invalid_config(self):
        variants = [lambda d: d.pop("scope"), lambda d: d["scope"].update(include=[]),
                    lambda d: d.update(version=2), lambda d: d.update(primary_domain="bad domain"),
                    lambda d: d.update(updated_at="2020-01-01T00:00:00Z"),
                    lambda d: d["rate"].update(max_concurrency=0)]
        for change in variants:
            with self.subTest(change=change):
                directory, folder = edited_package(change)
                try:
                    with self.assertRaises(ValueError):
                        load_target_package(folder)
                finally:
                    directory.cleanup()

    def test_rejects_malformed_yaml_duplicates_and_aliases(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory) / "example"
            shutil.copytree(EXAMPLE, folder)
            config = folder / "target.yaml"
            for contents in ("version: [", "id: example\nid: example\n", "a: &x x\nb: *x\n"):
                config.write_text(contents)
                with self.assertRaises(TargetPackageError):
                    load_target_package(folder)

    def test_rejects_secret_fields_and_values(self):
        changes = [lambda d: d.update(password="raw-secret"),
                   lambda d: d["context"].update(api_key="raw-secret"),
                   lambda d: d["context"].update(description="Bearer abc123"),
                   lambda d: d["source"].update(reference="Authorization: abc123")]
        for change in changes:
            directory, folder = edited_package(change)
            try:
                with self.assertRaises(TargetPackageError) as caught:
                    load_target_package(folder)
                self.assertNotIn("raw-secret", str(caught.exception))
                self.assertNotIn("abc123", str(caught.exception))
            finally:
                directory.cleanup()

    def test_accounts_metadata_rejects_credentials_and_bad_reference(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory) / "example"
            shutil.copytree(EXAMPLE, folder)
            accounts = folder / "accounts.yaml"
            for text in ("accounts:\n  owner:\n    cookie: secret\n",
                         "accounts:\n  owner:\n    secret_ref: plaintext-value\n",
                         "accounts:\n  owner:\n    secret_ref: ref:ok\n    password: secret\n"):
                accounts.write_text(text)
                with self.assertRaises(ValueError):
                    load_target_package(folder)

    def test_document_rejects_plaintext_secret_and_symlink(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory) / "example"
            shutil.copytree(EXAMPLE, folder)
            notes = folder / "context.md"
            notes.write_text("password: test-value")
            with self.assertRaises(TargetPackageError):
                load_target_package(folder)
            notes.unlink()
            notes.symlink_to(EXAMPLE / "context.md")
            with self.assertRaises(TargetPackageError):
                load_target_package(folder)

    def test_optional_files_are_optional(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory) / "example"
            shutil.copytree(EXAMPLE, folder)
            for filename in ("scope.md", "program_rules.md", "context.md", "researcher_notes.md", "accounts.yaml"):
                (folder / filename).unlink()
            package = load_target_package(folder)
            self.assertEqual(package.documents, ())
            self.assertEqual(package.accounts, ())

    def test_repository_get_list_pagination_and_id_validation(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("alpha", "beta", "gamma"):
                folder = root / name
                shutil.copytree(EXAMPLE, folder)
                config = yaml.safe_load((folder / "target.yaml").read_text())
                config["id"] = name
                (folder / "target.yaml").write_text(yaml.safe_dump(config))
            repo = TargetPackageRepository(root)
            first = repo.list_target_packages(limit=2)
            self.assertEqual([item.id for item in first.items], ["alpha", "beta"])
            self.assertEqual(first.next_cursor, "beta")
            second = repo.list_target_packages(limit=2, cursor=first.next_cursor)
            self.assertEqual([item.id for item in second.items], ["gamma"])
            self.assertIsNone(second.next_cursor)
            self.assertIsNone(repo.get_target_package("missing"))
            with self.assertRaises(ValueError):
                repo.get_target_package("../example")

    def test_recon_link_never_grants_scope(self):
        package = fixture()
        class FakeRecon:
            def __init__(self, record):
                self.record = record
                self.queries = []

            def resolve_target(self, identity):
                self.queries.append(identity)
                return self.record

        record = ReconTarget(1, "example.test", True, True, Provenance("domains", 1, None, "fixture"))
        repo = FakeRecon(record)
        self.assertIs(resolve_recon_target(package, repo), record)
        self.assertEqual(repo.queries, ["example.test"])
        self.assertEqual(package.scope.evaluate_url("https://billing.example.test/").result, ScopeResult.OUT_OF_SCOPE)
        self.assertNotEqual(package.scope.evaluate_url("https://example.test.attacker.test/").result, ScopeResult.IN_SCOPE)
        absent = FakeRecon(None)
        self.assertIsNone(resolve_recon_target(package, absent))
        self.assertEqual(package.scope.evaluate_url("https://api.example.test/").result, ScopeResult.IN_SCOPE)

    def test_cli_validate_and_show_without_recon_connection(self):
        output, errors = StringIO(), StringIO()
        code = main(["target", "validate", str(EXAMPLE)], environ={"HOME": "/nonexistent"},
                    stdout=output, stderr=errors)
        self.assertEqual((code, errors.getvalue()), (0, ""))
        self.assertEqual(json.loads(output.getvalue())["authority"], "TARGET_PACKAGE")
        with TemporaryDirectory() as directory:
            root = Path(directory) / "targets"
            root.mkdir()
            shutil.copytree(EXAMPLE, root / "example")
            config = Path(directory) / "config.toml"
            config.write_text(f'[targets]\nroot = "{root}"\n')
            loaded = load_config(config, environ={"HOME": directory})
            self.assertEqual(loaded.targets.root, root)
            output, errors = StringIO(), StringIO()
            code = main(["--config", str(config), "target", "show", "example"],
                        environ={"HOME": directory, "HACKBOT_RECON_DSN": "invalid://secret"},
                        stdout=output, stderr=errors)
            self.assertEqual((code, errors.getvalue()), (0, ""))
            self.assertEqual(json.loads(output.getvalue())["recon_inventory"], "NOT_CONSULTED")
            self.assertNotIn("invalid://secret", output.getvalue())
            output, errors = StringIO(), StringIO()
            code = main(["--config", str(config), "target", "show", "../example"],
                        environ={"HOME": directory}, stdout=output, stderr=errors)
            self.assertEqual(code, 2)
            self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
