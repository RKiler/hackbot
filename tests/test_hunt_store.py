from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.campaign_models import CampaignLimits
from hackbot.campaign_store import CampaignStore
from hackbot.config import load_config
from hackbot.hunt_store import HuntMode, HuntState, HuntStore
from hackbot.identity_registry import IdentityRegistry
from hackbot.planner_models import PlannerMode
from hackbot.policy import policy_version
from hackbot.store import EvidenceFactStore
from hackbot.target_loader import load_target_package
from hackbot.test_objects import CleanupStrategy, ObjectRegistry


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class HuntStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        config = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                      "XDG_STATE_HOME": str(root)})
        self.store = EvidenceFactStore.from_config(config)
        self.store.initialize()
        self.package = load_target_package(EXAMPLE)
        IdentityRegistry(self.store).register_target(self.package)
        self.hunts = HuntStore(self.store)

    def test_creation_is_persistent_target_scoped_and_exclusive(self) -> None:
        run = self.hunts.create(self.package)
        self.assertEqual(run.state, HuntState.PREPARING)
        self.assertEqual(run.mode, HuntMode.SUPERVISED)
        self.assertEqual(run.policy_hash, policy_version(self.package))
        self.assertEqual(HuntStore(self.store).current(run.target_id), run)
        self.assertEqual(self.hunts.active(), (run,))
        with self.assertRaisesRegex(ValueError, "active hunt"):
            self.hunts.create(self.package, HuntMode.RESEARCHER_AUTONOMOUS)
        self.assertIsNone(self.hunts.get("TARGET-" + "a" * 32, run.id))
        self.assertEqual(self.hunts.events(run.target_id, run.id)[0]["reason_code"],
                         "OPERATOR_STARTED")

    def test_transition_history_and_terminal_release(self) -> None:
        run = self.hunts.create(self.package)
        run = self.hunts.transition(run.target_id, run.id, HuntState.LOGIN_REQUIRED,
                                    "ACCOUNT_LOGIN_REQUIRED")
        run = self.hunts.transition(run.target_id, run.id, HuntState.READY,
                                    "SESSION_VERIFIED")
        run = self.hunts.transition(run.target_id, run.id, HuntState.MAPPING,
                                    "MAPPING_STARTED")
        run = self.hunts.transition(run.target_id, run.id, HuntState.HUNTING,
                                    "MAPPING_COMPLETE")
        with self.assertRaisesRegex(ValueError, "Invalid hunt state transition"):
            self.hunts.transition(run.target_id, run.id, HuntState.READY,
                                  "INVALID_REWIND")
        run = self.hunts.transition(run.target_id, run.id, HuntState.COMPLETE,
                                    "FRONTIER_SETTLED")
        self.assertIsNotNone(run.finished_at)
        self.assertEqual(self.hunts.active(), ())
        self.assertEqual(len(self.hunts.events(run.target_id, run.id)), 6)
        with self.assertRaises(ValueError):
            self.hunts.transition(run.target_id, run.id, HuntState.HUNTING,
                                  "UNAUTHORIZED_RESUME")
        next_run = self.hunts.create(self.package)
        self.assertNotEqual(next_run.id, run.id)

    def test_invalid_reason_and_campaign_link_require_current_target(self) -> None:
        run = self.hunts.create(self.package)
        with self.assertRaises(ValueError):
            self.hunts.transition(run.target_id, run.id, HuntState.READY,
                                  "token=do-not-log")
        campaign = CampaignStore(self.store).create(
            self.package, PlannerMode.PLAN_ONLY, CampaignLimits(),
            policy_version(self.package), "operator")
        with self.assertRaisesRegex(ValueError, "cannot link"):
            self.hunts.link_campaign(run.target_id, run.id, campaign.id)
        run = self.hunts.transition(run.target_id, run.id, HuntState.READY,
                                    "PREPARATION_COMPLETE")
        run = self.hunts.transition(run.target_id, run.id, HuntState.HUNTING,
                                    "PLAN_STARTED")
        with self.store._connection() as db:
            db.execute("UPDATE campaigns SET policy_hash=? WHERE campaign_id=?",
                       ("incorrect:hash", campaign.id))
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.hunts.link_campaign(run.target_id, run.id, campaign.id)
        with self.store._connection() as db:
            db.execute("UPDATE campaigns SET policy_hash=? WHERE campaign_id=?",
                       (policy_version(self.package), campaign.id))
        run = self.hunts.link_campaign(run.target_id, run.id, campaign.id)
        self.assertEqual(run.campaign_id, campaign.id)
        with self.assertRaisesRegex(ValueError, "cannot link"):
            self.hunts.link_campaign(run.target_id, run.id, campaign.id)

    def test_fixture_intent_is_durable_and_cannot_be_replaced(self) -> None:
        registry = IdentityRegistry(self.store)
        registry.import_package_accounts(self.package)
        identity = registry.get_identity(self.package.target.id, "org1_admin")
        self.assertIsNotNone(identity)
        tenant_id = registry.list_memberships(identity.id, limit=4).items[0].tenant_id
        run = self.hunts.create(self.package)
        run = self.hunts.transition(run.target_id, run.id, HuntState.READY,
                                    "MAPPING_COMPLETE")
        objects = ObjectRegistry(self.store)

        def plan():
            return objects.plan(
                target_id=run.target_id, package_id=self.package.id,
                object_type="document", creator_identity_id=identity.id,
                tenant_id=tenant_id, recipe_id="learned_document",
                recipe_hash="a" * 64, test_name="hackbot-test-fixture",
                cleanup_strategy=CleanupStrategy.AUTO_CLEANUP)

        first = plan()
        self.assertTrue(self.hunts.track_fixture(run.target_id, run.id, first))
        self.assertTrue(self.hunts.track_fixture(run.target_id, run.id, first))
        self.assertEqual(self.hunts.fixtures(run.target_id, run.id)[0]["test_object_id"],
                         first.id)
        second = plan()
        self.assertFalse(self.hunts.track_fixture(run.target_id, run.id, second))
        with self.assertRaises(ValueError):
            self.hunts.track_fixture("TARGET-" + "a" * 32, run.id, second)


if __name__ == "__main__":
    unittest.main()
