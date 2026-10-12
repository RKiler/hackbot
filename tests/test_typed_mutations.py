from __future__ import annotations

import hashlib
import unittest

from hackbot.object_recipes import ObjectRecipe
from hackbot.policy_models import SideEffect
from hackbot.typed_mutations import (BatchBinding, MutationPhase, MutationType,
                                     NestedBinding, TypedMutation)


class TypedMutationTests(unittest.TestCase):
    def test_deterministic_safe_values_and_field_rejection(self):
        value = TypedMutation.test_value("RUN-" + "a" * 32,
                                         "TESTOBJ-" + "b" * 32,
                                         MutationPhase.BOUNDARY)
        self.assertRegex(value, r"^hackbot-test-[0-9a-f]{12}$")
        self.assertEqual(value, TypedMutation.test_value("RUN-" + "a" * 32,
                                                          "TESTOBJ-" + "b" * 32,
                                                          MutationPhase.BOUNDARY))
        args = dict(target_id="TARGET-" + "a" * 32, operation_id="renameFixture",
                    test_object_id="TESTOBJ-" + "b" * 32, object_type="project",
                    creator_identity_id="IDENTITY-" + "c" * 32,
                    actor_identity_id="IDENTITY-" + "d" * 32,
                    tenant_id="TENANT-" + "e" * 32,
                    mutation_type=MutationType.RENAME, field="name", value_label=value,
                    expected_readback=value, cleanup_strategy="RESTORE",
                    side_effect=SideEffect.SAFE_UPDATE, recipe_hash="f" * 64)
        mutation = TypedMutation(**args)
        self.assertEqual(mutation.value_label, value)
        for field in ("owner_id", "role", "tenant.id", "billing_plan", "password", "name;delete"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                TypedMutation(**{**args, "field": field})
        with self.assertRaises(ValueError):
            TypedMutation(**{**args, "side_effect": SideEffect.PERMISSION_CHANGE})

    def test_nested_evidence_and_batch_cap(self):
        parent, child, third, fourth = ("TESTOBJ-" + digit * 32 for digit in "abcd")
        tenant_a, tenant_b = "TENANT-" + "a" * 32, "TENANT-" + "b" * 32
        actor = "IDENTITY-" + "a" * 32
        with self.assertRaises(ValueError):
            NestedBinding(parent, child, tenant_a, tenant_b, "readChild", ())
        self.assertEqual(NestedBinding(parent, child, tenant_a, tenant_b, "readChild",
                                       ("EV-" + "a" * 32,)).child_test_object_id, child)
        valid = BatchBinding("readBatch", (parent, child, third), actor, (parent,), 4)
        self.assertEqual(valid.maximum, 3)
        for ids in ((parent,), (parent, parent), (parent, child, third, fourth)):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                BatchBinding("readBatch", ids, actor, (parent,), 4)
        with self.assertRaises(ValueError):
            BatchBinding("readBatch", (parent, child), actor, (parent,), 4, maximum=6)
        with self.assertRaises(ValueError):
            NestedBinding(parent, child, "a", tenant_b, "readChild", ("EV-" + "a" * 32,))


class MutationRecipeTests(unittest.TestCase):
    @staticmethod
    def recipe():
        base = "http://127.0.0.1:8800/fixture/tenant-a/projects"
        read = {"method": "GET", "url": base + "/{object_id}",
                "operation": "readFixture"}
        write = {"method": "PATCH", "url": base + "/{object_id}",
                 "operation": "renameFixture", "body": {"name": "$test_name"}}
        return {"id": "project", "target_id": "TARGET-" + "a" * 32,
                "package_id": "fixture", "object_type": "project", "protocol": "REST",
                "source": "manual_fixture", "expected_owner": "owner",
                "expected_tenant": "tenant-a", "create": {
                    "method": "POST", "url": base, "operation": "createProject",
                    "body": {"name": "$test_name"}}, "verify": read,
                "cleanup": {"method": "DELETE", "url": base + "/{object_id}",
                            "operation": "deleteProject"},
                "update": write, "id_pointer": "/id", "verify_id_pointer": "/id",
                "verify_name_pointer": "/name", "verify_owner_pointer": "/owner",
                "verify_tenant_pointer": "/tenant", "cleanup_strategy": "AUTO_CLEANUP",
                "mutations": [{"type": "RENAME", "field": "name", "write": write,
                               "readback": read, "readback_pointer": "/name",
                               "restore": write, "side_effect": "SAFE_UPDATE",
                               "identity_requirement":
                               "VERIFIED_DISPOSABLE_OWNER_AND_BOUNDARY"}]}

    def test_reviewed_mutation_recipe(self):
        recipe = ObjectRecipe.from_json(self.recipe())
        self.assertEqual(recipe.mutations[0].mutation_type, MutationType.RENAME)
        self.assertRegex(recipe.sha256, r"^[0-9a-f]{64}$")

    def test_rejects_unreviewed_fields_bodies_and_routes(self):
        for change in ("role", "owner_id", "billing_plan"):
            with self.subTest(field=change), self.assertRaises(ValueError):
                data = self.recipe()
                data["mutations"][0]["field"] = change
                ObjectRecipe.from_json(data)
        data = self.recipe()
        data["mutations"][0]["write"]["body"] = {"name": "$test_name", "role": "admin"}
        with self.assertRaises(ValueError):
            ObjectRecipe.from_json(data)
        data = self.recipe()
        data["mutations"][0]["readback"]["url"] += "/other"
        with self.assertRaises(ValueError):
            ObjectRecipe.from_json(data)


if __name__ == "__main__":
    unittest.main()
