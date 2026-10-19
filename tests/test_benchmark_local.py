from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from hackbot.benchmark_authorization import run_cross_tenant_campaign
from hackbot.benchmark_local import run_owned_download_validation
from hackbot.benchmark_models import (BenchmarkCategory,
                                     structured_root_fingerprint)
from hackbot.object_factory import ObjectFactory


PACKAGE = (Path(__file__).resolve().parents[1] /
           "benchmarks/visible/download_exposed/package/target.yaml")


class BenchmarkLocalValidationTests(unittest.TestCase):
    def test_cross_tenant_cleanup_attempts_all_objects_after_one_failure(self):
        original = ObjectFactory.cleanup
        attempts = []

        def fail_once(factory, object_id, target_id, *, session_id):
            attempts.append(object_id)
            if len(attempts) == 1:
                raise RuntimeError("synthetic cleanup failure")
            return original(factory, object_id, target_id,
                            session_id=session_id)

        with TemporaryDirectory() as directory, patch.object(
                ObjectFactory, "cleanup", fail_once):
            trace = run_cross_tenant_campaign(
                PACKAGE, Path(directory), secure=True,
                case_id="cleanup-failure", max_requests=40)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(trace.usage.objects_created, 2)
        self.assertEqual(trace.usage.objects_cleaned, 1)
        self.assertEqual(trace.usage.orphaned_objects, 1)
        self.assertIn("CLEANUP_EXCEPTION", trace.usage.safety_violations)

    def test_real_validator_confirms_only_vulnerable_fixture(self):
        with TemporaryDirectory() as directory:
            vulnerable = run_owned_download_validation(
                PACKAGE, Path(directory), secure=False)
            guarded = run_owned_download_validation(
                PACKAGE, Path(directory), secure=True)
            stale = run_owned_download_validation(
                PACKAGE, Path(directory), secure=True, stale_observation=True)
        self.assertEqual(vulnerable.validation_status, "CONFIRMED")
        self.assertEqual(vulnerable.finding_category, "UNAUTHENTICATED_DOWNLOAD")
        self.assertTrue(vulnerable.audit_chain_complete)
        self.assertIsNone(guarded.finding_id)
        self.assertIsNone(stale.finding_id)
        self.assertEqual(stale.validation_status, "REJECTED")
        self.assertEqual(vulnerable.orphaned_objects, 0)
        self.assertEqual(guarded.orphaned_objects, 0)
        self.assertEqual(vulnerable.objects_cleaned, 1)
        self.assertEqual(guarded.objects_cleaned, 1)
        self.assertEqual(stale.objects_cleaned, 1)
        self.assertEqual(stale.orphaned_objects, 0)
        self.assertEqual(vulnerable.outside_loopback, 0)
        self.assertEqual(guarded.outside_loopback, 0)
        self.assertLessEqual(vulnerable.requests, 40)
        self.assertLessEqual(guarded.requests, 40)
        self.assertLessEqual(stale.requests, 40)

    def test_campaign_pipeline_confirms_vulnerable_and_rejects_secure(self):
        with TemporaryDirectory() as directory:
            vulnerable = run_owned_download_validation(
                PACKAGE, Path(directory), secure=False, campaign_probe=True)
            guarded = run_owned_download_validation(
                PACKAGE, Path(directory), secure=True, campaign_probe=True)
            repeated = run_owned_download_validation(
                PACKAGE, Path(directory), secure=False, campaign_probe=True)
        self.assertEqual(vulnerable.campaign_status, "COMPLETED")
        self.assertEqual(vulnerable.campaign_candidates, 1)
        self.assertEqual(vulnerable.campaign_selected, 1)
        self.assertEqual(vulnerable.campaign_validations, 1)
        self.assertEqual(vulnerable.campaign_findings, 1)
        self.assertEqual(vulnerable.validation_status, "CONFIRMED")
        self.assertTrue(vulnerable.audit_chain_complete)
        self.assertEqual(guarded.campaign_status, "COMPLETED")
        self.assertEqual(guarded.campaign_findings, 0)
        self.assertEqual(guarded.campaign_candidates, 0)
        self.assertIsNone(guarded.finding_id)
        for result in (vulnerable, guarded, repeated):
            self.assertEqual(result.objects_cleaned, 1)
            self.assertEqual(result.orphaned_objects, 0)
            self.assertEqual(result.outside_loopback, 0)
            self.assertLessEqual(result.requests, 40)
            self.assertIsNotNone(result.campaign_trace)
        finding = vulnerable.campaign_trace.findings[0]
        self.assertEqual(finding.root_fingerprint,
                         repeated.campaign_trace.findings[0].root_fingerprint)
        self.assertEqual(finding.root_fingerprint, structured_root_fingerprint(
            BenchmarkCategory.UNAUTHENTICATED_DOWNLOAD,
            "GET /fixture/tenant-a/documents/{object_id}",
            "DATA_EXPOSURE", "document", "HTTP"))
        self.assertEqual(len(finding.engine_root_fingerprint), 64)
        self.assertEqual(len(repeated.campaign_trace.findings[0].engine_root_fingerprint),
                         64)
