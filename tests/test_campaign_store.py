from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from hackbot.campaign_models import (
    CampaignLimits, CampaignStatus, CampaignWorkKind, CampaignWorkStatus,
)
from hackbot.campaign_store import CampaignStore
from hackbot.config import TargetSettings, load_config
from hackbot.planner_models import PlannerMode
from hackbot.policy import policy_version
from hackbot.planner_models import PlannerLimits
from hackbot.service import BugHunterRuntime


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class CampaignStoreTests(unittest.TestCase):
    def test_cleanup_reserve_covers_each_allowed_disposable_object(self):
        with self.assertRaisesRegex(ValueError, "cleanup reserve"):
            CampaignLimits(requests=20, setup_objects=2, cleanup_reserve=4)
        self.assertEqual(CampaignLimits(requests=20, setup_objects=2,
                                        cleanup_reserve=6).cleanup_reserve, 6)

    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        shutil.copytree(EXAMPLE, root / "targets/example")
        base = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                    "XDG_STATE_HOME": str(root)})
        self.runtime = BugHunterRuntime(replace(base, targets=TargetSettings(root / "targets")),
                                        driver=SimpleNamespace(name="FAKE"), vnc_ready=lambda: False)
        self.package = self.runtime.package("example")
        self.runtime.registry.register_target(self.package)
        self.ledger = CampaignStore(self.runtime.store)
        self.policy_hash = policy_version(self.package)

    def start(self, limits=CampaignLimits()):
        campaign = self.ledger.create(self.package, PlannerMode.BOUNDED_AUTONOMOUS,
                                      limits, self.policy_hash, "operator")
        return self.ledger.transition(self.package.target.id, campaign.id,
                                      CampaignStatus.RUNNING, "READY",
                                      package=self.package, policy_hash=self.policy_hash)

    def test_persistent_target_lock_and_bounded_work(self):
        campaign = self.start(CampaignLimits(2, 600, 10, 2, 1, 100, 1, 4))
        self.ledger.begin_cycle(self.package, campaign.id, self.policy_hash)
        work = self.ledger.reserve_work(campaign.target_id, campaign.id,
                                        CampaignWorkKind.PLANNER, requests=6,
                                        browser_actions=2, tokens=100)
        self.assertEqual(work.status, CampaignWorkStatus.INTENT)
        with self.assertRaises(ValueError):
            self.ledger.reserve_work(campaign.target_id, campaign.id,
                                     CampaignWorkKind.PLANNER, requests=1)
        self.assertEqual(self.ledger.get(campaign.target_id, campaign.id).usage.requests, 6)
        with self.assertRaises(Exception):
            self.start()
        self.ledger.reserve_work(campaign.target_id, campaign.id,
                                 CampaignWorkKind.CLEANUP, requests=4)
        self.assertEqual(self.ledger.get(campaign.target_id, campaign.id).usage.cleanup_requests, 4)
        self.assertEqual(len(self.ledger.events(campaign.target_id, campaign.id)), 5)

    def test_crash_preserves_ambiguous_intent_without_refund(self):
        campaign = self.start()
        self.ledger.begin_cycle(self.package, campaign.id, self.policy_hash)
        work = self.ledger.reserve_work(campaign.target_id, campaign.id,
                                        CampaignWorkKind.PLANNER, requests=5)
        another = CampaignStore(self.runtime.store)
        self.assertEqual(another.reconcile_interrupted(), 1)
        self.assertEqual(another.reconcile_interrupted(), 0)
        self.assertEqual(another.work(campaign.target_id, campaign.id, work.id).status,
                         CampaignWorkStatus.AMBIGUOUS)
        self.assertEqual(another.get(campaign.target_id, campaign.id).usage.requests, 5)
        with self.assertRaises(ValueError):
            another.link_child(campaign.target_id, campaign.id, work.id,
                               "PLRUN-" + "a" * 32)

    def test_scope_target_and_suppression_version(self):
        campaign = self.start()
        self.assertIsNone(self.ledger.get("other-target", campaign.id))
        root, state = "a" * 64, "b" * 64
        self.assertTrue(self.ledger.suppress(campaign.target_id, campaign.id,
                                             root, state, "REJECTED"))
        self.assertFalse(self.ledger.suppress(campaign.target_id, campaign.id,
                                              root, state, "REJECTED"))
        self.assertTrue(self.ledger.suppress(campaign.target_id, campaign.id,
                                             root, "c" * 64, "REJECTED"))
        self.assertEqual(len(self.ledger.suppressions(campaign.target_id, campaign.id)), 2)
        with self.assertRaises(LookupError):
            self.ledger.suppress("other-target", campaign.id, root, state, "CONFIRMED")

    def test_terminal_archive_hides_default_list_without_deleting_history(self):
        campaign = self.start()
        with self.assertRaises(ValueError):
            self.ledger.archive(campaign.id, campaign.target_id)
        self.ledger.transition(campaign.target_id, campaign.id, CampaignStatus.CANCELLED,
                               "OPERATOR_CANCEL", package=self.package,
                               policy_hash=self.policy_hash)
        self.assertTrue(self.ledger.archive(campaign.id, campaign.target_id))
        self.assertFalse(self.ledger.archive(campaign.id, campaign.target_id))
        self.assertNotIn(campaign.id, [item.id for item in self.ledger.list(target_id=campaign.target_id)])
        self.assertIn(campaign.id, [item.id for item in self.ledger.list(
            target_id=campaign.target_id, include_archived=True)])
        self.assertIsNotNone(self.ledger.get(campaign.target_id, campaign.id))
        self.assertTrue(any(item["event_type"] == "operator_archived" for item in
                            self.ledger.events(campaign.target_id, campaign.id)))

    def test_cycle_cap_and_policy_change_fail_closed(self):
        campaign = self.start(CampaignLimits(1, 600, 20, 8, 1, 2000, 1, 4))
        with self.assertRaises(ValueError):
            self.ledger.begin_cycle(self.package, campaign.id, "changed")
        self.ledger.begin_cycle(self.package, campaign.id, self.policy_hash)
        with self.assertRaises(ValueError):
            self.ledger.begin_cycle(self.package, campaign.id, self.policy_hash)

    def test_planner_child_link_is_atomic(self):
        campaign = self.start()
        self.ledger.begin_cycle(self.package, campaign.id, self.policy_hash)
        work = self.ledger.reserve_work(campaign.target_id, campaign.id,
                                        CampaignWorkKind.PLANNER, requests=5)
        child = self.runtime.planner_store.create(
            self.package, PlannerMode.PLAN_ONLY,
            PlannerLimits(requests=5, cleanup_reserve=0), self.policy_hash,
            campaign_work_id=work.id)
        linked = self.ledger.work(campaign.target_id, campaign.id, work.id)
        self.assertEqual(linked.child_id, child.id)
        self.assertEqual(linked.status, CampaignWorkStatus.LINKED)
        with self.runtime.store._connection() as db:
            row = db.execute("SELECT planner_run_id FROM campaign_cycles WHERE "
                             "campaign_id=? AND cycle_number=1", (campaign.id,)).fetchone()
        self.assertEqual(row[0], child.id)
        self.assertEqual(self.ledger.reconcile_interrupted(), 1)
        self.assertEqual(self.ledger.work(campaign.target_id, campaign.id, work.id).status,
                         CampaignWorkStatus.LINKED)

    def test_wrong_target_child_cannot_be_linked(self):
        campaign = self.start()
        self.ledger.begin_cycle(self.package, campaign.id, self.policy_hash)
        work = self.ledger.reserve_work(campaign.target_id, campaign.id,
                                        CampaignWorkKind.PLANNER, requests=5)
        with self.assertRaises(ValueError):
            self.runtime.planner_store.create(
                self.package, PlannerMode.PLAN_ONLY,
                PlannerLimits(requests=5, cleanup_reserve=0), self.policy_hash,
                campaign_work_id="CMPWORK-" + "f" * 32)
        self.assertEqual(self.runtime.planner_store.list(campaign.target_id), ())
        self.assertEqual(self.ledger.work(campaign.target_id, campaign.id, work.id).status,
                         CampaignWorkStatus.INTENT)


if __name__ == "__main__":
    unittest.main()
