from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import sqlite3
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest

from hackbot.config import TargetSettings, load_config
from hackbot.planner_models import (CandidateStatus, PlannerCandidate, PlannerLimits,
                                    PlannerMode, PlannerStatus, PlannerTaskType, Specialist)
from hackbot.policy import policy_version
from hackbot.research import (GapType, KnowledgeGap, ResearchCoordinator,
                              ResearchBudget, ResearchStore, SourceMaterial, SourceType)
from hackbot.research_retention import (ResearchBriefRetentionManager,
                                       ResearchBriefRetentionPolicy)
from hackbot.research_sources import ManualResearchProvider
from hackbot.service import BugHunterRuntime
from tests.schema_utils import drop_research_retirement_schema


EXAMPLE = Path(__file__).parent / "examples/targets/example"


class ResearchBriefRetentionTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        targets = root / "targets"
        shutil.copytree(EXAMPLE, targets / "example")
        base = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                    "XDG_STATE_HOME": str(root)})
        config = replace(base, targets=TargetSettings(targets))
        self.runtime = BugHunterRuntime(config, driver=SimpleNamespace(name="FAKE"),
                                        vnc_ready=lambda: False)
        package = self.runtime.package("example")
        self.runtime.registry.register_target(package)
        self.target_id = package.target.id
        self.store = ResearchStore(self.runtime.store)
        self.gap = KnowledgeGap("hypothesis:HYP-" + "a" * 32, self.target_id,
                                GapType.UNKNOWN_PROTOCOL, "GraphQL authorization", "GraphQL",
                                "authorization", "api", None, 80)
        source = SourceMaterial(SourceType.VENDOR_DOCUMENTATION, "GraphQL authorization",
            "graphql.org", "Security boundary: each field resolver checks object access.",
            "https://graphql.org/learn/authorization/")
        self.runner = ResearchCoordinator(self.store,
            local_providers=(ManualResearchProvider((source,)),), skill_names=())
        self.manager = ResearchBriefRetentionManager(
            self.runtime.store, ResearchBriefRetentionPolicy(grace_days=30, max_scan_entries=50,
                                                              max_retire=10),
            audit_path=root / "logs" / "research-retention.jsonl")

    def _brief(self, gap=None):
        gap = gap or self.gap
        request = self.runner.submit(gap, refresh=True)
        return self.runner.run(gap, request["request_id"])["brief_id"]

    def _expire(self, brief_id):
        old = (datetime.now(timezone.utc) - timedelta(days=70)).isoformat()
        with self.runtime.store._connection() as db:
            db.execute("UPDATE research_briefs SET expires_at=?,retrieved_at=?,"
                       "payload_json=json_set(payload_json,'$.expires_at',?,'$.retrieved_at',?) "
                       "WHERE brief_id=?", (old, old, old, old, brief_id))

    def _portfolio(self, source_refs=()):
        package = self.runtime.package("example")
        store = self.runtime.planner_store
        run = store.create(package, PlannerMode.PLAN_ONLY, PlannerLimits(),
                           policy_version(package))
        store.transition(run.target_id, run.id, PlannerStatus.LOADING_CONTEXT,
                         "CONTEXT_STARTED")
        candidate = PlannerCandidate(
            "PLCAND-" + "a" * 32, run.id, run.target_id, "AUTHORIZATION",
            "AUTHC-" + "b" * 32, None, Specialist.AUTHORIZATION,
            "CROSS_TENANT", "c" * 64, "d" * 64, 80, 75, 80, 5, 0, 0,
            "LOW", 75, "CURRENT", source_refs=tuple(source_refs),
            status=CandidateStatus.SELECTED)
        store.save_portfolio(run, (candidate,), {}, "e" * 64)
        return candidate

    def test_expired_unlinked_payload_requires_review_and_keeps_history(self):
        brief_id = self._brief()
        self.assertEqual(self.manager.plan().brief_ids, ())
        self._expire(brief_id)
        plan = self.manager.plan()
        self.assertEqual(plan.brief_ids, (brief_id,))
        self.assertGreater(plan.logical_bytes, 0)
        with self.assertRaisesRegex(ValueError, "confirmation"):
            self.manager.run(confirmed=False)
        self.assertEqual(self.manager.run(confirmed=True)["retired"], 1)
        self.assertEqual(self.store.brief(self.target_id, brief_id)["freshness"], "RETIRED")
        self.assertEqual(self.store.list(self.target_id)["items"][0]["freshness"], "RETIRED")
        with self.runtime.store._connection() as db:
            self.assertEqual(db.execute("SELECT payload_json FROM research_briefs WHERE brief_id=?",
                                        (brief_id,)).fetchone()[0], "{}")
            self.assertEqual(db.execute("SELECT count(*) FROM research_brief_sources WHERE brief_id=?",
                                        (brief_id,)).fetchone()[0], 1)
        fresh = self._brief()
        self.assertNotEqual(fresh, brief_id)
        self.assertEqual(self.store.brief(self.target_id, fresh)["version"], 2)
        retired = self.store.brief(self.target_id, brief_id)
        self.assertFalse(retired["content_available"])
        self.assertEqual(len(retired["sources"]), 1)
        hypothesis = self.runtime.hypotheses.add_manual(
            self.target_id, "UNKNOWN_PROTOCOL", "GraphQL boundary", "Review the boundary")
        with self.runtime.store._connection() as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("INSERT INTO research_hypothesis_links VALUES (?,?,?,?)",
                           (hypothesis.id, brief_id, "{}", datetime.now(timezone.utc).isoformat()))

    def test_hypothesis_and_proposal_links_hold_expired_briefs(self):
        hypothesis = self.runtime.hypotheses.add_manual(
            self.target_id, "UNKNOWN_PROTOCOL", "GraphQL boundary", "Review the boundary")
        linked_gap = replace(self.gap, hypothesis_id=hypothesis.id,
                             gap_ref="hypothesis:" + hypothesis.id)
        linked = self._brief(linked_gap)
        self._expire(linked)
        self.assertNotIn(linked, self.manager.plan().brief_ids)
        proposal_gap = replace(self.gap, gap_type=GapType.SKILL_GAP,
                               security_category=None, topic="Unfamiliar integration")
        proposed = self._brief(proposal_gap)
        self._expire(proposed)
        with self.runtime.store._connection() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM research_skill_proposals "
                                        "WHERE brief_id=?", (proposed,)).fetchone()[0], 1)
        self.assertNotIn(proposed, self.manager.plan().brief_ids)

    def test_new_link_between_plan_and_run_blocks_retirement(self):
        brief_id = self._brief()
        self._expire(brief_id)
        self.assertIn(brief_id, self.manager.plan().brief_ids)
        hypothesis = self.runtime.hypotheses.add_manual(
            self.target_id, "UNKNOWN_PROTOCOL", "GraphQL boundary", "Review the boundary")
        with self.runtime.store._connection() as db:
            db.execute("INSERT INTO research_hypothesis_links VALUES (?,?,?,?)",
                       (hypothesis.id, brief_id, "{}", datetime.now(timezone.utc).isoformat()))
        self.assertEqual(self.manager.run(confirmed=True)["retired"], 0)
        self.assertIsNone(self.store.cached(self.runner.cache_key(self.gap, private_target=True))["retired_at"])

    def test_payload_change_after_review_is_not_retired(self):
        brief_id = self._brief()
        self._expire(brief_id)
        self.assertIn(brief_id, self.manager.plan().brief_ids)
        with self.runtime.store._connection() as db:
            db.execute("UPDATE research_briefs SET payload_json=json_set(payload_json,"
                       "'$.summary','new unreviewed advisory') WHERE brief_id=?", (brief_id,))
        self.assertEqual(self.manager.run(confirmed=True)["retired"], 0)
        with self.runtime.store._connection() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM research_brief_payload_retirements "
                                        "WHERE brief_id=?", (brief_id,)).fetchone()[0], 0)

    def test_planner_candidate_reference_is_indexed_and_blocks_retirement(self):
        brief_id = self._brief()
        self._expire(brief_id)
        candidate = self._portfolio((brief_id,))
        with self.runtime.store._connection() as db:
            self.assertEqual(db.execute("SELECT brief_id FROM planner_candidate_research_refs "
                                        "WHERE candidate_id=?", (candidate.id,)).fetchone()[0], brief_id)
        self.assertNotIn(brief_id, self.manager.plan().brief_ids)
        with self.runtime.store._connection() as db:
            db.execute("UPDATE planner_candidates SET source_refs_json='[]' WHERE candidate_id=?",
                       (candidate.id,))
        self.assertIn(brief_id, self.manager.plan().brief_ids)
        self.assertEqual(self.manager.run(confirmed=True)["retired"], 1)
        with self.runtime.store._connection() as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE planner_candidates SET source_refs_json=? WHERE candidate_id=?",
                           ('["' + brief_id + '"]', candidate.id))

    def test_reference_index_drift_does_not_make_linked_brief_eligible(self):
        brief_id = self._brief()
        self._expire(brief_id)
        candidate = self._portfolio((brief_id,))
        with self.runtime.store._connection() as db:
            self.runtime.planner_store._event(
                db, candidate.run_id, "CONTEXT_REFERENCED", "RESEARCH", refs=(brief_id,))
            db.execute("DELETE FROM planner_candidate_research_refs WHERE candidate_id=?",
                       (candidate.id,))
            db.execute("DELETE FROM planner_event_research_refs WHERE brief_id=?",
                       (brief_id,))
        self.assertNotIn(brief_id, self.manager.plan().brief_ids)
        with self.runtime.store._connection() as db:
            db.execute("UPDATE planner_candidates SET source_refs_json='[]' WHERE candidate_id=?",
                       (candidate.id,))
        self.assertNotIn(brief_id, self.manager.plan().brief_ids)

    def test_planner_task_result_holds_brief_and_late_link_is_rejected(self):
        brief_id = self._brief()
        self._expire(brief_id)
        candidate = self._portfolio()
        store = self.runtime.planner_store
        run = store.get(self.target_id, candidate.run_id)
        task = store.add_task(run, candidate, PlannerTaskType.REQUEST_RESEARCH)
        with self.runtime.store._connection() as db:
            db.execute("UPDATE planner_tasks SET result_ref=? WHERE task_id=?",
                       (brief_id, task.id))
        self.assertNotIn(brief_id, self.manager.plan().brief_ids)
        with self.runtime.store._connection() as db:
            db.execute("UPDATE planner_tasks SET result_ref=NULL WHERE task_id=?", (task.id,))
        self.assertIn(brief_id, self.manager.plan().brief_ids)
        self.assertEqual(self.manager.run(confirmed=True)["retired"], 1)
        with self.runtime.store._connection() as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE planner_tasks SET result_ref=? WHERE task_id=?",
                           (brief_id, task.id))

    def test_planner_context_event_holds_brief_and_rejects_late_link(self):
        held = self._brief()
        self._expire(held)
        candidate = self._portfolio()
        with self.runtime.store._connection() as db:
            self.runtime.planner_store._event(
                db, candidate.run_id, "CONTEXT_REFERENCED", "RESEARCH", refs=(held,))
            self.assertEqual(db.execute("SELECT brief_id FROM planner_event_research_refs "
                                        "WHERE brief_id=?", (held,)).fetchone()[0], held)
        self.assertNotIn(held, self.manager.plan().brief_ids)
        retired = self._brief()
        self._expire(retired)
        self.assertIn(retired, self.manager.plan().brief_ids)
        self.assertEqual(self.manager.run(confirmed=True)["retired"], 1)
        with self.runtime.store._connection() as db:
            with self.assertRaises(sqlite3.IntegrityError):
                self.runtime.planner_store._event(
                    db, candidate.run_id, "CONTEXT_REFERENCED", "RESEARCH", refs=(retired,))

    def test_schema_44_upgrade_backfills_existing_planner_event_hold(self):
        brief_id = self._brief()
        candidate = self._portfolio()
        with sqlite3.connect(self.runtime.store.db_path) as db:
            drop_research_retirement_schema(db)
            db.execute("PRAGMA user_version=44")
            db.execute("INSERT INTO planner_events(run_id,candidate_id,task_id,event_type,"
                       "reason_code,safe_refs_json,occurred_at) VALUES (?,?,?,?,?,?,?)",
                       (candidate.run_id, None, None, "CONTEXT_REFERENCED", "RESEARCH",
                        '["' + brief_id + '"]', datetime.now(timezone.utc).isoformat()))
        self.runtime.store.initialize(allow_existing_migration=True)
        self._expire(brief_id)
        with self.runtime.store._connection() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM planner_event_research_refs "
                                        "WHERE brief_id=?", (brief_id,)).fetchone()[0], 1)
        self.assertNotIn(brief_id, self.manager.plan().brief_ids)

    def test_missing_guard_fails_closed_before_retirement(self):
        brief_id = self._brief()
        self._expire(brief_id)
        self.assertIn(brief_id, self.manager.plan().brief_ids)
        with self.runtime.store._connection() as db:
            db.execute("DROP TRIGGER research_ref_candidate_insert_guard")
        with self.assertRaisesRegex(ValueError, "guards"):
            self.manager.run(confirmed=True)
        with self.runtime.store._connection() as db:
            self.assertNotEqual(db.execute("SELECT payload_json FROM research_briefs WHERE brief_id=?",
                                           (brief_id,)).fetchone()[0], "{}")
            self.assertEqual(db.execute("SELECT count(*) FROM research_brief_payload_retirements")
                             .fetchone()[0], 0)

    def test_review_expires_and_plan_file_is_private(self):
        brief_id = self._brief()
        self._expire(brief_id)
        now = time.time()
        self.assertIn(brief_id, self.manager.plan(now=now).brief_ids)
        self.assertEqual(self.manager.review_path.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ValueError, "recent dry-run"):
            self.manager.run(confirmed=True, now=now + 901)

    def test_retired_payload_cannot_be_reused_even_if_metadata_is_made_fresh(self):
        brief_id = self._brief()
        self._expire(brief_id)
        self.assertIn(brief_id, self.manager.plan().brief_ids)
        self.assertEqual(self.manager.run(confirmed=True)["retired"], 1)
        future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        with self.runtime.store._connection() as db:
            db.execute("UPDATE research_briefs SET expires_at=? WHERE brief_id=?",
                       (future, brief_id))
        key = self.runner.cache_key(self.gap, private_target=True)
        request_id = self.store.create_request(
            self.gap, ResearchBudget(), external=False, private_target=True, cache_key=key)
        self.assertFalse(self.store.use_cached(self.gap, request_id, brief_id))
        self.assertEqual(self.store.request(self.target_id, request_id)["status"], "PENDING")
        with self.runtime.store._connection() as db:
            self.assertIsNone(db.execute("SELECT brief_id FROM research_requests WHERE request_id=?",
                                         (request_id,)).fetchone()[0])


if __name__ == "__main__":
    unittest.main()
