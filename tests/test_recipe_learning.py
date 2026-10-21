from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime, timezone
import json
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from hackbot.api_graphql import JSAPIRoute
from hackbot.config import ObjectSettings
from hackbot.object_recipes import RecipeCatalog
from hackbot.recipe_learning import ObservedRecipeLearner, infer_name_only_rest_recipe
from hackbot.target_loader import load_target_package
from hackbot.target_package import AccountReference
from hackbot.test_objects import ObjectState


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class RecipeLearningTests(unittest.TestCase):
    def setUp(self):
        self.package = load_target_package(EXAMPLE)
        self.account = AccountReference("org1_admin", "admin", "org1")
        self.form = {"action": "https://api.example.test/api/documents", "method": "POST",
                     "fields": [{"name": "name", "type": "text"}]}
        self.routes = (
            JSAPIRoute("/api/documents/{id}", "GET", 1),
            JSAPIRoute("/api/documents/{id}", "DELETE", 2),
        )
        self.owner_url = "https://api.example.test/api/documents/doc-seed-1"
        self.owner = {"id": "doc-seed-1", "name": "Existing document",
                      "owner": "org1_admin", "tenant": "org1"}

    def infer(self, **overrides):
        values = {"form": self.form, "routes": self.routes,
                  "owner_url": self.owner_url, "owner_response": self.owner}
        values.update(overrides)
        return infer_name_only_rest_recipe(self.package, self.account, **values)

    def test_correlated_observations_build_validated_form_recipe(self):
        learned = self.infer()
        self.assertIsNotNone(learned)
        recipe, payload = learned
        self.assertEqual(recipe.object_type, "document")
        self.assertEqual(recipe.cleanup_strategy.value, "AUTO_CLEANUP")
        self.assertEqual(recipe.create.template(test_name="hackbot-test-a&b").body,
                         b"name=hackbot-test-a%26b")
        self.assertEqual(recipe.verify.template(test_name="unused", object_id="doc-test-1").url,
                         "https://api.example.test/api/documents/doc-test-1")
        self.assertEqual(payload["expected_owner"], "org1_admin")

    def test_learned_catalog_write_is_atomic_and_never_overwrites(self):
        recipe, payload = self.infer()
        with TemporaryDirectory() as directory:
            catalog = RecipeCatalog(ObjectSettings(Path(directory) / "recipes"))
            self.assertEqual(catalog.add_learned(self.package, payload).sha256,
                             recipe.sha256)
            self.assertEqual(catalog.add_learned(self.package, payload).sha256,
                             recipe.sha256)
            self.assertEqual(catalog.get(self.package.id, recipe.id).sha256,
                             recipe.sha256)
            path = catalog.settings.recipe_root / self.package.id / (recipe.id + ".json")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ValueError, "conflicts"):
                catalog.add_learned(self.package, {**payload,
                    "expected_tenant": "other-tenant"})
            self.assertEqual(catalog.get(self.package.id, recipe.id).sha256,
                             recipe.sha256)

    def test_learned_catalog_rejects_symlink_and_scope_confusion(self):
        recipe, payload = self.infer()
        with TemporaryDirectory() as directory:
            root = Path(directory) / "recipes"
            root.mkdir()
            (root / self.package.id).symlink_to(Path(directory), target_is_directory=True)
            catalog = RecipeCatalog(ObjectSettings(root))
            with self.assertRaises(OSError):
                catalog.add_learned(self.package, payload)
            (root / self.package.id).unlink()
            with self.assertRaisesRegex(ValueError, "outside target scope"):
                catalog.add_learned(self.package, {**payload, "create": {
                    **payload["create"], "url": "https://outside.invalid/api/documents"}})

    def test_rejects_missing_cleanup_or_unverified_owner(self):
        self.assertIsNone(self.infer(routes=self.routes[:1]))
        self.assertIsNone(self.infer(owner_response={**self.owner, "tenant": "org2"}))
        self.assertIsNone(self.infer(owner_url=self.owner_url + "/preview"))

    def test_rejects_ambiguous_or_sensitive_form(self):
        self.assertIsNone(self.infer(form={**self.form, "fields": [
            {"name": "name", "type": "text"}, {"name": "role", "type": "select"}]}))
        self.assertIsNone(self.infer(form={**self.form,
                                           "action": "https://api.example.test/api/invites"}))
        self.assertIsNone(self.infer(form={**self.form,
                                           "action": "https://outside.invalid/api/documents"}))
        self.assertIsNone(self.infer(form={**self.form,
                                           "action": self.form["action"] + "?token=x"}))

    def test_current_object_read_requires_matching_js_route_and_scope(self):
        recipe, _ = self.infer()
        learner = ObservedRecipeLearner(evidence=None, traffic=None, js=None,
                                        catalog=None)
        routes = {"https://api.example.test": (
            JSAPIRoute("/api/documents/{id}/preview", "GET", 1),
            JSAPIRoute("/api/documents/{id}/delete", "POST", 2),
            JSAPIRoute("/api/other/{id}/preview", "GET", 3))}
        with patch.object(learner, "_routes", return_value=routes):
            self.assertEqual(learner.current_object_read_urls(
                self.package, recipe, "doc-test-1", datetime.now(timezone.utc)),
                ("https://api.example.test/api/documents/doc-test-1/preview",))
            with self.assertRaises(ValueError):
                learner.current_object_read_urls(
                    self.package, recipe, "../foreign", datetime.now(timezone.utc))

    def test_tenant_policy_requires_captured_owner_peer_and_foreign_denial(self):
        recipe, _ = self.infer()
        item = SimpleNamespace(target_id=self.package.target.id,
                               package_id=self.package.id, state=ObjectState.READY,
                               verified_at=datetime.now(timezone.utc).isoformat(),
                               tenant_id="TENANT-org1", test_name="hunt-owned")
        document = {"id": "doc-test-1", "name": item.test_name,
                    "owner": "org1_admin", "tenant": "org1"}
        bodies = {"owner": json.dumps(document).encode(),
                  "peer": json.dumps(document).encode(),
                  "foreign": b'{"error":"not_found"}'}

        def exchange(label, status):
            return SimpleNamespace(response=SimpleNamespace(
                record=SimpleNamespace(status_code=status,
                                       size_bytes=len(bodies[label])),
                body_evidence_id=label,
                observation_evidence_id="EV-" + label))

        evidence = MagicMock()
        evidence.read_content.side_effect = lambda evidence_id, **_: bodies[evidence_id]
        evidence.find_facts.return_value = SimpleNamespace(items=())
        learner = ObservedRecipeLearner(evidence=evidence, traffic=None, js=None,
                                        catalog=None)
        controls = (exchange("owner", 200), exchange("peer", 200),
                    exchange("foreign", 404))
        actors = {"owner": ("session-a", "identity-a"),
                  "same_tenant": ("session-b", "identity-b"),
                  "foreign": ("session-c", "identity-c")}
        with patch.object(learner, "captured_read", side_effect=controls):
            self.assertTrue(learner.record_tenant_private_control(
                self.package, item, recipe, "doc-test-1", item.tenant_id,
                since=datetime.now(timezone.utc), **actors))
        self.assertEqual({call.args[1:3] for call in evidence.create_fact.call_args_list},
                         {("resource_tenant", item.tenant_id),
                          ("resource_visibility", "PRIVATE"),
                          ("access_policy", "TENANT_ONLY")})
        evidence.create_fact.reset_mock()
        with patch.object(learner, "captured_read", side_effect=(
                controls[0], controls[1], exchange("foreign", 200))):
            self.assertFalse(learner.record_tenant_private_control(
                self.package, item, recipe, "doc-test-1", item.tenant_id,
                since=datetime.now(timezone.utc), **actors))
        evidence.create_fact.assert_not_called()


if __name__ == "__main__":
    unittest.main()
