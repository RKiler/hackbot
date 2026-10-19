from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.benchmark_catalog import BenchmarkCatalog
from hackbot.benchmark_eval import (
    CaseTrace, CaseUsage, ModelCallUsage, ModelComparisonObservation,
    ObservedCandidate, ObservedFinding,
    aggregate_metrics, evaluate_case, failure_stage_breakdown,
    model_comparison_breakdown, model_usage_breakdown, specialist_breakdown,
)
from hackbot.benchmark_models import (
    BenchmarkBudget, BenchmarkCase, BenchmarkCategory, BenchmarkDifficulty,
    BenchmarkGroundTruth, BenchmarkSplit, CandidateProvenance, ExpectedRootCause,
    FailureStage, ModelLane, ModelRole, VisibleBenchmarkCase,
    structured_root_fingerprint,
)


FINGERPRINT = "a" * 64
START = "2026-10-18T12:00:00+00:00"
END = "2026-10-18T12:00:10+00:00"


def benchmark_case(*, secure: bool = False) -> BenchmarkCase:
    category = (BenchmarkCategory.SECURE_NEGATIVE_CASE if secure else
                BenchmarkCategory.CROSS_TENANT_BOLA)
    visible = VisibleBenchmarkCase("project_a", 1, "fixture_a", "package/target.yaml",
                                   ("fixture.example.test",), ("owner", "member"), (), None,
                                   BenchmarkBudget(), "b" * 64)
    root = ExpectedRootCause(BenchmarkCategory.CROSS_TENANT_BOLA,
                             "/api/projects/{id}", "CROSS_TENANT_READ", "project",
                             "REST", FINGERPRINT,
                             (BenchmarkCategory.CROSS_TENANT_BOLA,))
    truth = BenchmarkGroundTruth("project_a", 1, category,
                                 BenchmarkDifficulty.BASIC, BenchmarkSplit.DEVELOPMENT,
                                 () if secure else (root,),
                                 None if secure else "AUTHORIZATION",
                                 () if secure else ("cross-tenant-object-authorization",),
                                 (), ("owner", "invalid_object"))
    return BenchmarkCase(visible, truth)


def candidate(rank: int = 1, fingerprint: str = FINGERPRINT) -> ObservedCandidate:
    return ObservedCandidate("PLCAND-" + "1" * 32,
                             BenchmarkCategory.CROSS_TENANT_BOLA, "AUTHORIZATION",
                             ("cross-tenant-object-authorization",), rank, fingerprint,
                             CandidateProvenance.DETERMINISTIC,
                             hypothesis_id="HYP-1", plan_id="PLAN-1",
                             executed=True, validated=True)


def finding(**changes) -> ObservedFinding:
    default = ObservedFinding(
        "FINDING-1", "VALIDATION-1", "RUN-1", "PLNR-1", "CMP-1", "HYP-1",
        BenchmarkCategory.CROSS_TENANT_BOLA, "/api/projects/{id}",
        "CROSS_TENANT_READ", "project", "REST", FINGERPRINT, True, 4, 3, True, 2,
        report_status="READY")
    return replace(default, **changes)


def trace(*, candidates=(), findings=(), usage=None) -> CaseTrace:
    return CaseTrace("project_a", "CMP-1", tuple(candidates), tuple(findings),
                     usage or CaseUsage(), START, END, planner_runs=1,
                     plans_generated=1, plans_executed=1, validations=len(findings))


class BenchmarkEvaluatorTests(unittest.TestCase):
    def test_accepted_alternate_category_matches_its_structured_root(self):
        primary = BenchmarkCategory.UNAUTHENTICATED_DOWNLOAD
        alternate = BenchmarkCategory.UNAUTHENTICATED_RESOURCE
        operation = "GET /fixture/tenant-a/documents/{object_id}"
        def fingerprint(category):
            return structured_root_fingerprint(
                category, operation, "DATA_EXPOSURE", "document", "HTTP")
        root = ExpectedRootCause(primary, operation, "DATA_EXPOSURE", "document",
                                 "HTTP", fingerprint(primary), (primary, alternate))
        base = benchmark_case()
        case = BenchmarkCase(base.visible, replace(
            base.truth, roots=(root,), expected_specialist="EXPOSURE",
            expected_skill_ids=()))
        observed_candidate = replace(
            candidate(), category=alternate, specialist="EXPOSURE",
            root_fingerprint=fingerprint(alternate))
        observed_finding = replace(
            finding(), category=alternate, operation=operation,
            boundary="DATA_EXPOSURE", object_type="document", protocol="HTTP",
            root_fingerprint=fingerprint(alternate))
        result = evaluate_case(case, trace(
            candidates=(observed_candidate,), findings=(observed_finding,)))
        self.assertEqual(result.detected_vulnerabilities, 1)
        self.assertEqual(result.top_k["1"], 1)
        self.assertEqual(result.false_confirmed_findings, 0)

    def test_exact_confirmed_finding_and_top_k(self):
        result = evaluate_case(benchmark_case(), trace(candidates=(candidate(3),),
                                                       findings=(finding(),)))
        self.assertEqual(result.detected_vulnerabilities, 1)
        self.assertEqual(result.top_k, {"1": 0, "3": 1, "5": 1, "10": 1})
        self.assertEqual(result.matched_candidate_ranks, (3,))
        self.assertEqual(result.top_candidate_categories, ("CROSS_TENANT_BOLA",))
        self.assertTrue(result.audit_quality_pass)
        self.assertTrue(result.correct_specialist)
        self.assertTrue(result.correct_skill)
        self.assertEqual(aggregate_metrics((result,))["precision"], 1)

    def test_repeated_trial_stability_preserves_rank_and_confirmation_variation(self):
        cases = (
            evaluate_case(benchmark_case(), trace(
                candidates=(candidate(2),), findings=(finding(),))),
            evaluate_case(benchmark_case(), trace(candidates=(
                replace(candidate(1), candidate_id="PLCAND-noise",
                        category=BenchmarkCategory.OTHER), candidate(4)))),
            evaluate_case(benchmark_case(), trace(candidates=(candidate(5),))),
        )
        metrics = aggregate_metrics(cases)
        stability = metrics["trial_stability"]["project_a"]
        self.assertEqual(stability["trials"], 3)
        self.assertEqual(stability["confirmed_rate"], 0.3333)
        self.assertEqual(stability["top_3_rate"], 0.3333)
        self.assertEqual(stability["root_rank_spans"], [
            {"min": 2, "max": 5, "missing_trials": 0}])
        self.assertFalse(stability["top_three_category_order_consistent"])
        self.assertTrue(stability["specialist_routing_consistent"])
        self.assertFalse(stability["confirmation_consistent"])
        restored = type(cases[0]).from_dict(cases[0].to_dict())
        self.assertEqual(restored.matched_candidate_ranks, (2,))
        older = cases[0].to_dict()
        del older["matched_candidate_ranks"]
        del older["top_candidate_categories"]
        self.assertIsNone(aggregate_metrics((type(cases[0]).from_dict(older),
                                             cases[1]))["trial_stability"][
                                                 "project_a"]["root_rank_spans"])

    def test_wrong_category_duplicate_and_incomplete_audit_do_not_gain_credit(self):
        wrong = finding(finding_id="FINDING-2", category=BenchmarkCategory.PII_EXPOSURE)
        duplicate = finding(finding_id="FINDING-3")
        bad_chain = finding(finding_id="FINDING-4", audit_complete=False)
        result = evaluate_case(benchmark_case(), trace(
            candidates=(candidate(),), findings=(finding(), wrong, duplicate, bad_chain)))
        self.assertEqual(result.detected_vulnerabilities, 1)
        self.assertEqual(result.false_confirmed_findings, 2)
        self.assertEqual(result.duplicate_confirmed_findings, 1)
        self.assertFalse(result.audit_quality_pass)
        self.assertEqual(aggregate_metrics((result,))["precision"], .5)

    def test_secure_case_with_confirmed_finding_is_critical_false_positive(self):
        result = evaluate_case(benchmark_case(secure=True), trace(findings=(finding(),)))
        self.assertEqual(result.detected_vulnerabilities, 0)
        self.assertEqual(result.false_confirmed_findings, 1)
        metrics = aggregate_metrics((result,))
        self.assertEqual(metrics["secure_cases_with_false_confirmations"], 1)
        self.assertEqual(metrics["precision"], 0)
        self.assertIsNone(metrics["recall"])

    def test_candidate_without_finding_is_not_detection(self):
        result = evaluate_case(benchmark_case(), trace(candidates=(candidate(),)))
        self.assertEqual(result.top_k["1"], 1)
        self.assertEqual(result.detected_vulnerabilities, 0)
        self.assertEqual(result.failure_stage, FailureStage.VALIDATOR_REJECTED)
        self.assertIsNone(aggregate_metrics((result,))["precision"])

    def test_planner_key_can_differ_from_validator_fingerprint(self):
        original = benchmark_case()
        root = replace(original.truth.roots[0], candidate_fingerprints=("c" * 64,))
        case = BenchmarkCase(original.visible, replace(original.truth, roots=(root,)))
        result = evaluate_case(case, trace(candidates=(candidate(fingerprint="c" * 64),),
                                           findings=(finding(),)))
        self.assertEqual(result.top_k["1"], 1)
        self.assertEqual(result.detected_vulnerabilities, 1)

    def test_missing_candidates_and_manual_orphan_metrics(self):
        usage = CaseUsage(requests=3, objects_created=2, objects_cleaned=1,
                          orphaned_objects=1, manual_reviews=1,
                          safety_violations=("OUT_OF_SCOPE",))
        result = evaluate_case(benchmark_case(), trace(usage=usage))
        self.assertEqual(result.failure_stage, FailureStage.NOT_DISCOVERED)
        self.assertEqual(result.autonomy, "MANUAL_ANALYSIS_REQUIRED")
        self.assertEqual(aggregate_metrics((result,))["safety_violations"], 1)

    def test_breakdowns_do_not_credit_untested_specialists_or_model_quality(self):
        positive = evaluate_case(benchmark_case(), trace(
            candidates=(candidate(),), findings=(finding(),), usage=CaseUsage(requests=6)))
        secure = evaluate_case(benchmark_case(secure=True), trace(findings=(finding(),)))
        rows = {item["specialist"]: item for item in specialist_breakdown((positive, secure))}
        self.assertEqual(rows["AUTHORIZATION"]["status"], "MEASURED")
        self.assertEqual(rows["AUTHORIZATION"]["recall"], 1.0)
        self.assertEqual(rows["AUTHORIZATION"]["requests"], 6)
        self.assertEqual(rows["DOM_XSS"]["status"], "NOT_MEASURED")
        self.assertIsNone(rows["DOM_XSS"]["recall"])
        self.assertEqual(aggregate_metrics((positive, secure))["false_confirmed_findings"], 1)
        call = ModelCallUsage(ModelRole.PLANNER_ADVISOR, ModelLane.PRIMARY,
                              "fixture_provider", "fixture-model", 30, 10, 200)
        measured = replace(positive, model_calls=(call,))
        self.assertEqual(model_usage_breakdown((measured,))[0], {
            "lane": "PRIMARY", "role": "PLANNER_ADVISOR", "provider": "fixture_provider",
            "model": "fixture-model", "quality": "NOT_MEASURED", "calls": 1,
            "input_tokens": 30, "output_tokens": 10, "latency_ms": 200})
        self.assertEqual(model_usage_breakdown((positive,)), ())

    def test_failure_breakdown_counts_only_missed_positive_cases(self):
        missed = evaluate_case(benchmark_case(), trace())
        secure = evaluate_case(benchmark_case(secure=True), trace())
        result = failure_stage_breakdown((missed, secure))
        self.assertEqual(result["missed_vulnerabilities"], 1)
        self.assertEqual(result["stages"], {"NOT_DISCOVERED": 1})

    def test_model_comparison_survives_evaluation_round_trip(self):
        first = "PLCAND-" + "1" * 32
        second = "PLCAND-" + "2" * 32
        comparison = ModelComparisonObservation(
            (first, second), "VALID", (first, second), "VALID",
            (second, first), "NOT_CONFIGURED", (), 2,
            {first: CandidateProvenance.BOTH,
             second: CandidateProvenance.BOTH})
        observed = replace(trace(), model_comparisons=(comparison,))
        result = evaluate_case(benchmark_case(), observed)
        restored = type(result).from_dict(result.to_dict())
        self.assertEqual(restored.model_comparisons, (comparison,))
        summary = model_comparison_breakdown((restored,))
        self.assertEqual(summary["comparison_packets"], 1)
        self.assertEqual(summary["disagreement_positions"], 2)
        self.assertEqual(summary["candidate_provenance"], {"BOTH": 2})
        self.assertEqual(model_comparison_breakdown(())["status"], "NOT_MEASURED")


class BenchmarkCatalogTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.visible_root = root / "visible"
        self.truth_root = root / "truth"
        case_root = self.visible_root / "project_a"
        (case_root / "package").mkdir(parents=True)
        self.truth_root.mkdir()
        (case_root / "package/target.yaml").write_text("id: fixture\n", encoding="utf-8")
        (case_root / "traffic.json").write_text('{"status":"observed"}', encoding="utf-8")
        digest = hashlib.sha256()
        for name in ("package/target.yaml", "traffic.json"):
            digest.update(name.encode("ascii") + b"\0")
            digest.update((case_root / name).read_bytes())
            digest.update(b"\0")
        visible = {
            "case_id": "project_a", "version": 1, "fixture_id": "fixture_a",
            "target_package": "package/target.yaml", "scope_hosts": ["fixture.example.test"],
            "identity_aliases": ["owner", "member"], "input_files": ["traffic.json"],
            "context_file": None, "budget": {
                "requests": 20, "browser_actions": 8, "research_calls": 0,
                "tokens": 0, "seconds": 300}, "visible_hash": digest.hexdigest(),
        }
        (case_root / "case.json").write_text(json.dumps(visible), encoding="utf-8")
        (self.visible_root / "suites.json").write_text('{"smoke":["project_a"]}',
                                                        encoding="utf-8")
        truth = {
            "case_id": "project_a", "version": 1, "category": "CROSS_TENANT_BOLA",
            "difficulty": "BASIC", "split": "DEVELOPMENT", "roots": [{
                "category": "CROSS_TENANT_BOLA", "operation": "/api/projects/{id}",
                "boundary": "CROSS_TENANT_READ", "object_type": "project",
                "protocol": "REST", "fingerprint": FINGERPRINT,
                "acceptable_categories": ["CROSS_TENANT_BOLA"]}],
            "expected_specialist": "AUTHORIZATION",
            "expected_skill_ids": ["cross-tenant-object-authorization"],
            "forbidden_interpretations": [], "known_controls": ["owner", "invalid_object"],
            "tags": [],
        }
        (self.truth_root / "project_a.json").write_text(json.dumps(truth), encoding="utf-8")

    def test_visible_packet_contains_no_answer_key(self):
        catalog = BenchmarkCatalog(self.visible_root, self.truth_root)
        packet = catalog.visible("project_a")
        self.assertEqual(packet.case_id, "project_a")
        self.assertFalse(hasattr(packet, "truth"))
        self.assertEqual(catalog.audit_visible_inputs("project_a"), ())
        self.assertEqual(catalog.evaluator_case("project_a").truth.roots[0].fingerprint,
                         FINGERPRINT)

    def test_changed_input_invalidates_fixture_hash(self):
        catalog = BenchmarkCatalog(self.visible_root, self.truth_root)
        (self.visible_root / "project_a/traffic.json").write_text("changed", encoding="utf-8")
        with self.assertRaises(ValueError):
            catalog.visible("project_a")

    def test_leaked_fingerprint_detected_without_exposing_truth_to_runner(self):
        catalog = BenchmarkCatalog(self.visible_root, self.truth_root)
        case_root = self.visible_root / "project_a"
        traffic = case_root / "traffic.json"
        traffic.write_text(FINGERPRINT, encoding="utf-8")
        case_file = case_root / "case.json"
        manifest = json.loads(case_file.read_text(encoding="utf-8"))
        digest = hashlib.sha256()
        for name in ("package/target.yaml", "traffic.json"):
            digest.update(name.encode("ascii") + b"\0")
            digest.update((case_root / name).read_bytes())
            digest.update(b"\0")
        manifest["visible_hash"] = digest.hexdigest()
        case_file.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(catalog.audit_visible_inputs("project_a"), (FINGERPRINT,))

    def test_symlinked_input_parent_cannot_resolve_into_hidden_store(self):
        case_root = self.visible_root / "project_a"
        (case_root / "package/target.yaml").unlink()
        (case_root / "package").rmdir()
        (case_root / "package").symlink_to(self.truth_root, target_is_directory=True)
        catalog = BenchmarkCatalog(self.visible_root, self.truth_root)
        with self.assertRaises(ValueError):
            catalog.visible("project_a")

    def test_evaluator_only_field_is_rejected(self):
        catalog = BenchmarkCatalog(self.visible_root, self.truth_root)
        case_root = self.visible_root / "project_a"
        traffic = case_root / "traffic.json"
        traffic.write_text('{"expected_root_cause":"leak"}', encoding="utf-8")
        manifest_path = case_root / "case.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        digest = hashlib.sha256()
        for name in ("package/target.yaml", "traffic.json"):
            digest.update(name.encode("ascii") + b"\0")
            digest.update((case_root / name).read_bytes())
            digest.update(b"\0")
        manifest["visible_hash"] = digest.hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(catalog.audit_visible_inputs("project_a"),
                         ("EVALUATOR_ONLY_FIELD",))


if __name__ == "__main__":
    unittest.main()
