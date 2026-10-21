from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.benchmark_catalog import BenchmarkCatalog
from hackbot.benchmark_advice import ModelAdviceResult
from hackbot.benchmark_local_runner import BenchmarkLocalRunner
from hackbot.benchmark_models import (BENCHMARK_VERSION, BenchmarkRunConfig,
                                     ModelLane, ModelRole, ModelSelection)
from hackbot.benchmark_report import build_benchmark_report
from hackbot.benchmark_store import BenchmarkStore


BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"


class BenchmarkLocalRunnerTests(unittest.TestCase):
    def test_browser_specialist_pairs_use_current_browser_proof(self):
        for suite, vulnerable_id, guarded_id, operation in (
            ("local-dom", "local_dom_a", "local_dom_b", "GET /preview"),
            ("local-postmessage", "local_message_a", "local_message_b",
             "MESSAGE /victim"),
        ):
            with self.subTest(suite=suite):
                run_id = self.runner.run(BenchmarkRunConfig(
                    suite, planner_mode="BOUNDED_AUTONOMOUS"),
                    bughunter_version="test", bughunter_schema=48)
                cases = {row["case_id"]: row for row in self.store.cases(run_id)}
                self.assertEqual({row["status"] for row in cases.values()}, {"COMPLETED"})
                positive = cases[vulnerable_id]["evaluation"]
                negative = cases[guarded_id]["evaluation"]
                self.assertEqual(positive["detected_vulnerabilities"], 1,
                                 (suite, cases[vulnerable_id]["trace"]))
                self.assertEqual(positive["false_confirmed_findings"], 0)
                self.assertEqual(positive["top_k"]["1"], 1)
                self.assertTrue(positive["audit_quality_pass"])
                self.assertEqual(cases[vulnerable_id]["trace"]["findings"][0][
                    "operation"], operation)
                self.assertEqual(negative["false_confirmed_findings"], 0)
                self.assertEqual(negative["detected_vulnerabilities"], 0)
                for case in cases.values():
                    self.assertEqual(case["evaluation"]["usage"]["safety_violations"], [])
                    self.assertEqual(case["evaluation"]["usage"]["objects_created"], 0)
                    self.assertLessEqual(case["evaluation"]["usage"]["requests"], 40)

    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.catalog = BenchmarkCatalog(BENCHMARKS / "visible", BENCHMARKS / "truth")
        self.store = BenchmarkStore(self.root / "state/benchmark.sqlite3")
        self.runner = BenchmarkLocalRunner(
            self.catalog, self.store, self.root / "work", BENCHMARKS / "harness")

    def test_scored_campaign_pair_uses_actual_validator_and_cleanup(self):
        run_id = self.runner.run(BenchmarkRunConfig(
            "local-smoke", planner_mode="BOUNDED_AUTONOMOUS"),
            bughunter_version="test", bughunter_schema=48)
        cases = {row["case_id"]: row for row in self.store.cases(run_id)}
        self.assertEqual({row["status"] for row in cases.values()}, {"COMPLETED"})
        exposed = cases["local_download_a"]["evaluation"]
        guarded = cases["local_download_b"]["evaluation"]
        self.assertEqual(exposed["detected_vulnerabilities"], 1)
        self.assertEqual(exposed["false_confirmed_findings"], 0)
        self.assertEqual(exposed["top_k"]["1"], 1)
        self.assertTrue(exposed["correct_specialist"])
        self.assertEqual(exposed["false_candidate_count"], 0)
        self.assertEqual(guarded["detected_vulnerabilities"], 0)
        self.assertEqual(guarded["false_confirmed_findings"], 0)
        self.assertEqual(exposed["usage"]["objects_cleaned"], 1)
        self.assertEqual(guarded["usage"]["objects_cleaned"], 1)
        self.assertEqual(exposed["usage"]["orphaned_objects"], 0)
        self.assertEqual(guarded["usage"]["orphaned_objects"], 0)
        report = build_benchmark_report(self.store, run_id)
        self.assertEqual(report["metrics"]["precision"], 1.0)
        self.assertEqual(report["metrics"]["recall"], 1.0)
        self.assertEqual(report["metrics"]["top_k_recall"]["1"], 1.0)
        self.assertEqual(report["readiness"]["conclusion"], "NOT_READY")

    def test_cross_tenant_pair_uses_owned_controls_and_real_validator(self):
        run_id = self.runner.run(BenchmarkRunConfig(
            "local-authorization", planner_mode="BOUNDED_AUTONOMOUS"),
            bughunter_version="test", bughunter_schema=48)
        cases = {row["case_id"]: row for row in self.store.cases(run_id)}
        self.assertEqual({row["status"] for row in cases.values()}, {"COMPLETED"})
        vulnerable = cases["local_tenant_a"]["evaluation"]
        guarded = cases["local_tenant_b"]["evaluation"]
        self.assertEqual(vulnerable["detected_vulnerabilities"], 1)
        self.assertEqual(vulnerable["missed_vulnerabilities"], 0)
        self.assertEqual(vulnerable["top_k"]["1"], 1)
        self.assertTrue(vulnerable["correct_specialist"])
        self.assertTrue(vulnerable["correct_skill"])
        self.assertTrue(vulnerable["audit_quality_pass"])
        self.assertTrue(vulnerable["finding_quality_pass"])
        self.assertEqual(vulnerable["false_confirmed_findings"], 0)
        self.assertEqual(guarded["detected_vulnerabilities"], 0)
        self.assertEqual(guarded["false_confirmed_findings"], 0)
        for case in cases.values():
            usage = case["evaluation"]["usage"]
            self.assertEqual(usage["objects_created"], 2)
            self.assertEqual(usage["objects_cleaned"], 2)
            self.assertEqual(usage["orphaned_objects"], 0)
            self.assertLessEqual(usage["requests"], 40)
            self.assertEqual(usage["safety_violations"], [])
            self.assertIsNone(case["trace"]["failure_reason"])
        report = build_benchmark_report(self.store, run_id)
        self.assertEqual(report["metrics"]["precision"], 1.0)
        self.assertEqual(report["metrics"]["recall"], 1.0)

    def test_cross_tenant_mutation_pair_preserves_misses_and_secure_control(self):
        run_id = self.runner.run(BenchmarkRunConfig(
            "local-authorization-mutation", planner_mode="BOUNDED_AUTONOMOUS"),
            bughunter_version="test", bughunter_schema=48)
        cases = {row["case_id"]: row for row in self.store.cases(run_id)}
        self.assertEqual({row["status"] for row in cases.values()}, {"COMPLETED"})
        vulnerable = cases["local_mutation_a"]["evaluation"]
        guarded = cases["local_mutation_b"]["evaluation"]
        self.assertEqual(vulnerable["expected_vulnerabilities"], 1)
        self.assertEqual(vulnerable["detected_vulnerabilities"] +
                         vulnerable["missed_vulnerabilities"], 1)
        self.assertEqual(vulnerable["false_confirmed_findings"], 0)
        self.assertEqual(guarded["detected_vulnerabilities"], 0)
        self.assertEqual(guarded["false_confirmed_findings"], 0)
        if vulnerable["detected_vulnerabilities"]:
            self.assertEqual(cases["local_mutation_a"]["trace"]["findings"][0][
                "operation"], "PATCH /fixture/{tenant}/documents/{object_id}")
            self.assertTrue(vulnerable["audit_quality_pass"])
        for case in cases.values():
            usage = case["evaluation"]["usage"]
            self.assertEqual(usage["objects_created"], 2)
            self.assertEqual(usage["objects_cleaned"], 2)
            self.assertEqual(usage["orphaned_objects"], 0)
            self.assertLessEqual(usage["requests"], 80)
            self.assertEqual(usage["safety_violations"], [])

    def test_mixed_surface_pair_scores_two_roots_without_rewarding_noise(self):
        run_id = self.runner.run(BenchmarkRunConfig(
            "local-mixed", planner_mode="BOUNDED_AUTONOMOUS"),
            bughunter_version="test", bughunter_schema=48)
        cases = {row["case_id"]: row for row in self.store.cases(run_id)}
        self.assertEqual({row["status"] for row in cases.values()}, {"COMPLETED"})
        vulnerable = cases["local_mixed_a"]["evaluation"]
        guarded = cases["local_mixed_b"]["evaluation"]
        self.assertEqual(vulnerable["expected_vulnerabilities"], 2)
        self.assertEqual(vulnerable["detected_vulnerabilities"] +
                         vulnerable["missed_vulnerabilities"], 2)
        self.assertEqual(vulnerable["false_confirmed_findings"], 0)
        self.assertGreaterEqual(vulnerable["candidate_count"], 2)
        self.assertEqual(guarded["expected_vulnerabilities"], 0)
        self.assertEqual(guarded["detected_vulnerabilities"], 0)
        self.assertEqual(guarded["false_confirmed_findings"], 0)
        for case in cases.values():
            usage = case["evaluation"]["usage"]
            self.assertEqual(usage["objects_created"], 2)
            self.assertEqual(usage["objects_cleaned"], 2)
            self.assertEqual(usage["orphaned_objects"], 0)
            self.assertLessEqual(usage["requests"], 80)
            self.assertEqual(usage["safety_violations"], [])
        report = build_benchmark_report(self.store, run_id)
        self.assertEqual(report["readiness"]["conclusion"], "NOT_READY")

    def test_same_tenant_pair_keeps_horizontal_miss_and_secure_control(self):
        run_id = self.runner.run(BenchmarkRunConfig(
            "local-horizontal", planner_mode="BOUNDED_AUTONOMOUS"),
            bughunter_version="test", bughunter_schema=48)
        cases = {row["case_id"]: row for row in self.store.cases(run_id)}
        self.assertEqual({row["status"] for row in cases.values()}, {"COMPLETED"})
        vulnerable = cases["local_horizontal_a"]["evaluation"]
        guarded = cases["local_horizontal_b"]["evaluation"]
        self.assertEqual(vulnerable["expected_vulnerabilities"], 1)
        self.assertEqual(vulnerable["detected_vulnerabilities"] +
                         vulnerable["missed_vulnerabilities"], 1)
        self.assertEqual(vulnerable["false_confirmed_findings"], 0)
        self.assertGreaterEqual(vulnerable["candidate_count"], 1)
        self.assertEqual(vulnerable["top_k"]["1"], 1)
        self.assertTrue(vulnerable["correct_specialist"])
        self.assertTrue(vulnerable["correct_skill"])
        self.assertEqual(guarded["expected_vulnerabilities"], 0)
        self.assertEqual(guarded["detected_vulnerabilities"], 0)
        self.assertEqual(guarded["false_confirmed_findings"], 0)
        for case in cases.values():
            usage = case["evaluation"]["usage"]
            self.assertEqual(usage["objects_created"], 2)
            self.assertEqual(usage["objects_cleaned"], 2)
            self.assertEqual(usage["orphaned_objects"], 0)
            self.assertLessEqual(usage["requests"], 80)
            self.assertEqual(usage["safety_violations"], [])

    def test_graphql_pair_records_policy_wait_without_orphaning_objects(self):
        run_id = self.runner.run(BenchmarkRunConfig(
            "local-graphql-object", planner_mode="BOUNDED_AUTONOMOUS"),
            bughunter_version="test", bughunter_schema=48)
        cases = {row["case_id"]: row for row in self.store.cases(run_id)}
        self.assertEqual({row["status"] for row in cases.values()}, {"COMPLETED"}, cases)
        vulnerable = cases["local_graphql_a"]["evaluation"]
        guarded = cases["local_graphql_b"]["evaluation"]
        self.assertEqual(vulnerable["expected_vulnerabilities"], 1)
        self.assertEqual(vulnerable["detected_vulnerabilities"] +
                         vulnerable["missed_vulnerabilities"], 1)
        self.assertEqual(vulnerable["top_k"]["10"], 1)
        self.assertTrue(vulnerable["correct_specialist"])
        self.assertTrue(vulnerable["correct_skill"])
        self.assertEqual(guarded["expected_vulnerabilities"], 0)
        self.assertEqual(guarded["false_confirmed_findings"], 0)
        for case in cases.values():
            usage = case["evaluation"]["usage"]
            self.assertEqual(usage["objects_created"], 2)
            self.assertEqual(usage["objects_cleaned"], 2)
            self.assertEqual(usage["orphaned_objects"], 0)
            self.assertLessEqual(usage["requests"], 80)
            self.assertEqual(usage["safety_violations"], [])
            if case["trace"]["failure_reason"] == "WAITING_APPROVAL":
                self.assertEqual(usage["approvals"], 1)
                self.assertEqual(case["evaluation"]["autonomy"], "APPROVAL_ONLY")

    def test_synthetic_approved_graphql_pair_reaches_validator(self):
        run_id = self.runner.run(BenchmarkRunConfig(
            "local-graphql-approved", planner_mode="BOUNDED_AUTONOMOUS"),
            bughunter_version="test", bughunter_schema=48)
        cases = {row["case_id"]: row for row in self.store.cases(run_id)}
        self.assertEqual({row["status"] for row in cases.values()}, {"COMPLETED"}, cases)
        vulnerable = cases["local_graphql_a"]["evaluation"]
        guarded = cases["local_graphql_b"]["evaluation"]
        self.assertEqual(vulnerable["detected_vulnerabilities"], 1)
        self.assertEqual(vulnerable["missed_vulnerabilities"], 0)
        self.assertTrue(vulnerable["audit_quality_pass"])
        self.assertTrue(vulnerable["finding_quality_pass"])
        self.assertEqual(guarded["false_confirmed_findings"], 0)
        self.assertEqual(guarded["detected_vulnerabilities"], 0)
        for case in cases.values():
            usage = case["evaluation"]["usage"]
            self.assertGreaterEqual(usage["approvals"], 1)
            self.assertLessEqual(usage["approvals"], 8)
            self.assertEqual(usage["objects_created"], 2)
            self.assertEqual(usage["objects_cleaned"], 2)
            self.assertEqual(usage["orphaned_objects"], 0)
            self.assertEqual(usage["safety_violations"], [])
            self.assertLessEqual(usage["requests"], 80)
        self.assertTrue(self.store.get(run_id)["environment"]["synthetic_operator_approval"])

    def test_graphql_field_pair_scores_misses_and_secure_control(self):
        run_id = self.runner.run(BenchmarkRunConfig(
            "local-graphql-field-approved", planner_mode="BOUNDED_AUTONOMOUS"),
            bughunter_version="test", bughunter_schema=48)
        cases = {row["case_id"]: row for row in self.store.cases(run_id)}
        self.assertEqual({row["status"] for row in cases.values()}, {"COMPLETED"}, cases)
        vulnerable = cases["local_graphql_field_a"]["evaluation"]
        guarded = cases["local_graphql_field_b"]["evaluation"]
        self.assertEqual(vulnerable["expected_vulnerabilities"], 1)
        self.assertEqual(vulnerable["detected_vulnerabilities"] +
                         vulnerable["missed_vulnerabilities"], 1)
        self.assertEqual(vulnerable["top_k"]["10"], 1)
        self.assertTrue(vulnerable["correct_specialist"])
        self.assertEqual(guarded["expected_vulnerabilities"], 0)
        self.assertEqual(guarded["false_confirmed_findings"], 0)
        for case in cases.values():
            usage = case["evaluation"]["usage"]
            self.assertEqual(usage["objects_created"], 2)
            self.assertEqual(usage["objects_cleaned"], 2)
            self.assertEqual(usage["orphaned_objects"], 0)
            self.assertLessEqual(usage["requests"], 80)
            self.assertEqual(usage["safety_violations"], [])
        self.assertTrue(self.store.get(run_id)["environment"]["synthetic_operator_approval"])

    def test_resume_marks_interrupted_case_ambiguous_without_replaying_it(self):
        self.store.initialize()
        config = BenchmarkRunConfig("local-noisy-secure",
                                    planner_mode="BOUNDED_AUTONOMOUS")
        case_id = "local_surface_c"
        visible_hash = self.catalog.visible(case_id).visible_hash
        harness_hash = self.runner._harness(case_id)[1]
        run_id = self.store.create(
            config, ((case_id, visible_hash),), benchmark_version=BENCHMARK_VERSION,
            bughunter_version="test", bughunter_schema=48,
            environment={"mode": "SYNTHETIC_LOCAL", "network": "LOOPBACK_ONLY",
                         "answer_root_in_runtime": False,
                         "harness_hashes": {case_id: harness_hash}})
        self.store.claim(run_id)
        self.runner.resume(run_id)
        case = self.store.cases(run_id)[0]
        self.assertEqual(case["status"], "AMBIGUOUS")
        self.assertIsNone(case["trace"])
        self.assertEqual(self.store.get(run_id)["status"], "AMBIGUOUS")

    def test_noisy_secure_case_exposes_review_load_without_false_confirmation(self):
        run_id = self.runner.run(BenchmarkRunConfig(
            "local-noisy-secure", planner_mode="BOUNDED_AUTONOMOUS"),
            bughunter_version="test", bughunter_schema=48)
        case = self.store.cases(run_id)[0]
        evaluation = case["evaluation"]
        self.assertEqual(case["status"], "COMPLETED")
        self.assertEqual(evaluation["expected_vulnerabilities"], 0)
        self.assertEqual(evaluation["false_confirmed_findings"], 0)
        self.assertGreaterEqual(evaluation["false_candidate_count"], 1)
        self.assertEqual(evaluation["campaign_outcome"], "WAITING_HUMAN")
        self.assertEqual(evaluation["usage"]["manual_context_required"], 1)
        self.assertEqual(evaluation["autonomy"], "MANUAL_ANALYSIS_REQUIRED")
        self.assertEqual(evaluation["usage"]["orphaned_objects"], 0)
        report = build_benchmark_report(self.store, run_id)
        self.assertIn("MANUAL_WAIT_NOT_AUTOMATIC_REJECTION", report["limitations"])
        self.assertEqual(report["metrics"]["manual_context_required"], 1)

    def test_rejects_harness_change_before_resuming(self):
        self.store.initialize()
        config = BenchmarkRunConfig("local-noisy-secure",
                                    planner_mode="BOUNDED_AUTONOMOUS")
        case_id = "local_surface_c"
        run_id = self.store.create(
            config, ((case_id, self.catalog.visible(case_id).visible_hash),),
            benchmark_version=BENCHMARK_VERSION, bughunter_version="test",
            bughunter_schema=48,
            environment={"mode": "SYNTHETIC_LOCAL", "network": "LOOPBACK_ONLY",
                         "answer_root_in_runtime": False,
                         "harness_hashes": {case_id: "0" * 64}})
        with self.assertRaisesRegex(ValueError, "harness changed"):
            self.runner.resume(run_id)
        self.assertEqual(self.store.cases(run_id)[0]["status"], "PENDING")

    def test_independent_fake_model_lanes_use_same_live_planner_packet(self):
        class FakeProvider:
            name = "fake"

            def __init__(self, reverse=False):
                self.reverse = reverse
                self.packets = []

            def advise(self, packet):
                ids = tuple(item["candidate_id"] for item in packet.candidates)
                self.packets.append((packet.role, ids))
                return ModelAdviceResult(ids[::-1] if self.reverse else ids,
                                         input_tokens=20, output_tokens=10,
                                         latency_ms=1)

        primary, challenger, critic = FakeProvider(), FakeProvider(True), FakeProvider()
        selections = (
            ModelSelection(ModelRole.PLANNER_ADVISOR, "fake", "primary",
                           lane=ModelLane.PRIMARY),
            ModelSelection(ModelRole.PLANNER_ADVISOR, "fake", "challenger",
                           lane=ModelLane.CHALLENGER),
            ModelSelection(ModelRole.FALSE_POSITIVE_CRITIC, "fake", "critic",
                           lane=ModelLane.CRITIC),
        )
        providers = {
            (item.role, item.lane, item.provider, item.model): provider
            for item, provider in zip(selections, (primary, challenger, critic))
        }
        runner = BenchmarkLocalRunner(self.catalog, self.store,
                                      self.root / "work", BENCHMARKS / "harness",
                                      providers=providers)
        run_id = runner.run(BenchmarkRunConfig(
            "local-advice", planner_mode="BOUNDED_AUTONOMOUS", models=selections),
            bughunter_version="test", bughunter_schema=48)
        rows = self.store.cases(run_id)
        self.assertEqual({row["status"] for row in rows}, {"COMPLETED"})
        self.assertEqual(len(primary.packets), 2)
        self.assertEqual([item[1] for item in primary.packets],
                         [item[1] for item in challenger.packets])
        self.assertEqual([item[1] for item in primary.packets],
                         [item[1] for item in critic.packets])
        self.assertTrue(all(item[0] is ModelRole.FALSE_POSITIVE_CRITIC
                            for item in critic.packets))
        for row in rows:
            self.assertEqual(len(row["trace"]["model_calls"]), 3)
            self.assertEqual(len(row["trace"]["model_comparisons"]), 1)
            self.assertEqual(row["trace"]["model_comparisons"][0][
                "challenger_status"], "VALID")
            self.assertEqual(row["evaluation"]["usage"]["input_tokens"], 60)
            self.assertEqual(row["evaluation"]["usage"]["output_tokens"], 30)
            self.assertEqual(row["evaluation"]["usage"]["orphaned_objects"], 0)
        by_id = {row["case_id"]: row["evaluation"] for row in rows}
        self.assertEqual(by_id["local_advice_d"]["expected_vulnerabilities"], 1)
        self.assertEqual(
            by_id["local_advice_d"]["detected_vulnerabilities"] +
            by_id["local_advice_d"]["missed_vulnerabilities"], 1)
        self.assertEqual(by_id["local_advice_d"]["false_confirmed_findings"], 0)
        self.assertEqual(by_id["local_advice_e"]["false_confirmed_findings"], 0)
        report = build_benchmark_report(self.store, run_id)
        self.assertEqual(report["model_mode"], "CONFIGURED_MODEL_LANES")
        self.assertEqual(sum(item["calls"] for item in report["model_usage"]), 6)
        self.assertEqual(report["model_comparison"]["comparison_packets"], 2)
        self.assertEqual(report["model_comparison"]["lane_statuses"]["CRITIC"],
                         {"VALID": 2})
        self.assertNotIn("MODEL_ADVISOR_NOT_INVOKED", report["limitations"])

    def test_model_provider_and_visible_token_budget_are_required(self):
        selection = ModelSelection(ModelRole.PLANNER_ADVISOR, "fake", "primary")
        configured = BenchmarkRunConfig(
            "local-advice", planner_mode="BOUNDED_AUTONOMOUS",
            models=(selection,))
        with self.assertRaisesRegex(ValueError, "provider is not configured"):
            self.runner.run(configured, bughunter_version="test", bughunter_schema=48)
        provider = type("Fake", (), {"name": "fake"})()
        runner = BenchmarkLocalRunner(
            self.catalog, self.store, self.root / "work", BENCHMARKS / "harness",
            providers={(selection.role, selection.lane, selection.provider,
                        selection.model): provider})
        with self.assertRaisesRegex(ValueError, "Unsupported local benchmark case"):
            runner.run(BenchmarkRunConfig(
                "local-smoke", planner_mode="BOUNDED_AUTONOMOUS",
                models=(selection,)), bughunter_version="test", bughunter_schema=48)

    def test_model_lane_ablations_suppress_only_selected_advice(self):
        class FakeProvider:
            name = "fake"

            def __init__(self):
                self.calls = 0

            def advise(self, packet):
                self.calls += 1
                return ModelAdviceResult(
                    tuple(item["candidate_id"] for item in packet.candidates),
                    input_tokens=2, output_tokens=1, latency_ms=1)

        primary, challenger = FakeProvider(), FakeProvider()
        selections = (
            ModelSelection(ModelRole.PLANNER_ADVISOR, "fake", "primary",
                           lane=ModelLane.PRIMARY),
            ModelSelection(ModelRole.PLANNER_ADVISOR, "fake", "challenger",
                           lane=ModelLane.CHALLENGER),
        )
        providers = {
            (selections[0].role, selections[0].lane, "fake", "primary"): primary,
            (selections[1].role, selections[1].lane, "fake", "challenger"): challenger,
        }
        runner = BenchmarkLocalRunner(self.catalog, self.store,
                                      self.root / "work", BENCHMARKS / "harness",
                                      providers=providers)
        config = BenchmarkRunConfig(
            "local-advice", planner_mode="BOUNDED_AUTONOMOUS",
            models=selections, ablations=("NO_CHALLENGER",))
        run_id = runner.run(config, bughunter_version="test", bughunter_schema=48)
        rows = self.store.cases(run_id)
        self.assertEqual({row["status"] for row in rows}, {"COMPLETED"})
        self.assertGreater(primary.calls, 0)
        self.assertEqual(challenger.calls, 0)
        self.assertTrue(all(len(row["trace"]["model_calls"]) == 1 for row in rows))
        self.assertEqual(build_benchmark_report(self.store, run_id)["ablations"],
                         ["NO_CHALLENGER"])

        model_free = BenchmarkLocalRunner(self.catalog, self.store,
                                          self.root / "work", BENCHMARKS / "harness")
        no_model = BenchmarkRunConfig(
            "local-advice", planner_mode="BOUNDED_AUTONOMOUS",
            models=selections, ablations=("NO_MODEL",))
        run_id = model_free.run(no_model, bughunter_version="test", bughunter_schema=48)
        rows = self.store.cases(run_id)
        self.assertEqual({row["status"] for row in rows}, {"COMPLETED"})
        self.assertTrue(all(not row["trace"]["model_calls"] for row in rows))
        self.assertEqual(build_benchmark_report(self.store, run_id)["model_mode"],
                         "DETERMINISTIC_ONLY")

        with self.assertRaisesRegex(ValueError, "Unsupported local benchmark ablation"):
            runner.run(BenchmarkRunConfig(
                "local-advice", planner_mode="BOUNDED_AUTONOMOUS",
                models=selections, ablations=("NO_TRAFFIC",)),
                bughunter_version="test", bughunter_schema=48)


if __name__ == "__main__":
    unittest.main()
