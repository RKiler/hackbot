from io import StringIO
from contextlib import redirect_stderr
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from hackbot.cli import main
from hackbot.burp_storage import BurpStorageStatus


class CliTests(unittest.TestCase):
    def _run(self, args: list[str], env: dict[str, str]) -> tuple[int, str, str]:
        output, errors = StringIO(), StringIO()
        code = main(args, environ=env, stdout=output, stderr=errors)
        return code, output.getvalue(), errors.getvalue()

    def test_version_ignores_invalid_config(self) -> None:
        code, output, errors = self._run(["version"], {"HACKBOT_CONFIG": "/nonexistent"})
        self.assertEqual((code, errors), (0, ""))
        self.assertRegex(output, r"^hackbot \d+\.\d+\.\d+\n$")

    def test_health_is_read_only_without_production_db(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "state-root"
            code, output, errors = self._run(
                ["health"],
                {"HOME": directory, "HACKBOT_HOME": str(root), "RECON_DB_DSN": "invalid://secret"},
            )
            self.assertEqual((code, errors), (0, ""))
            body = json.loads(output)
            self.assertEqual(body["status"], "ok")
            self.assertEqual(body["checks"]["local_root"], "not_initialized")
            self.assertEqual(body["recon_integration"], "adapter_available_not_checked")
            self.assertFalse(root.exists())

    def test_status_only_reports_local_paths(self) -> None:
        with TemporaryDirectory() as directory:
            code, output, errors = self._run(["status"], {"HOME": directory})
            body = json.loads(output)
            self.assertEqual((code, errors), (0, ""))
            self.assertEqual(body["phase"], 30)
            self.assertEqual(body["service"], "not_checked_use_private_api_status")
            self.assertEqual(body["recon_integration"], "adapter_available_not_connected")
            self.assertFalse(body["evidence_store"]["exists"])
            self.assertEqual(body["evidence_store"]["artifact_root"],
                             str(Path(directory) / ".local/state/bughunter-agent/artifacts/evidence"))
            self.assertFalse(body["local_paths"]["evidence"]["exists"])
            self.assertFalse((Path(directory) / ".local").exists())

    def test_invalid_config_returns_error_without_value(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('[logging]\nlevel = "private-value"\n')
            code, output, errors = self._run(["--config", str(path), "health"], {"HOME": directory})
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertIn("Unsupported logging level", errors)
            self.assertNotIn("private-value", errors)

    def test_health_rejects_file_as_state_root(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "occupied"
            root.write_text("not a directory")
            code, output, _ = self._run(["health"], {"HOME": directory, "HACKBOT_HOME": str(root)})
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output)["checks"]["local_root"], "not_a_directory")

    def test_storage_status_is_read_only_and_does_not_require_recon(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "state-root"
            code, output, errors = self._run(
                ["storage", "status"],
                {"HOME": directory, "HACKBOT_HOME": str(root),
                 "RECON_DB_DSN": "invalid://fixture-secret"},
            )
            self.assertEqual((code, errors), (0, ""))
            body = json.loads(output)
            self.assertIsNone(body["schema_actual"])
            self.assertEqual(body["database_bytes"], 0)
            self.assertEqual(body["resources"]["state"], "BLOCKED")
            self.assertIn("STORAGE_UNAVAILABLE", body["resources"]["warnings"])
            self.assertFalse(root.exists())
            self.assertNotIn("fixture-secret", output)

    def test_ops_status_uses_private_status_only(self) -> None:
        with patch("hackbot.cli._operations_status", return_value={"state": "DEGRADED"}) as reader:
            code, output, errors = self._run(["ops", "status"], {"HOME": "/tmp"})
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(json.loads(output)["state"], "DEGRADED")
        reader.assert_called_once_with()

    def test_burp_storage_is_local_and_does_not_require_recon(self) -> None:
        status = BurpStorageStatus("COMPLETE", 2, 1, 1, 0, 7, 7, 0, 0)
        with patch("hackbot.cli.inspect_burp_storage", return_value=status) as inspect:
            code, output, errors = self._run(
                ["burp", "storage"], {"HOME": "/tmp", "RECON_DB_DSN": "invalid://secret"})
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(json.loads(output)["data_estimated_bytes"], 7)
        self.assertNotIn("secret", output)
        inspect.assert_called_once()

    def test_disabled_profile_cli_requires_confirmation_and_private_review(self) -> None:
        target_id = "TARGET-" + "1" * 32
        identity_id = "IDENTITY-" + "2" * 32
        review_id = "MAINT-" + "3" * 32
        with patch("hackbot.cli._private_operations_request",
                   return_value={"id": review_id, "status": "QUEUED"}) as request:
            code, output, errors = self._run(
                ["ops", "disabled-profile-plan", target_id, identity_id], {"HOME": "/tmp"})
            self.assertEqual((code, errors), (0, ""))
            self.assertEqual(json.loads(output)["id"], review_id)
            request.assert_called_once_with("POST", "/v1/operations/maintenance", {
                "action": "DISABLED_PROFILE_PLAN", "target_id": target_id,
                "identity_id": identity_id})
        with patch("hackbot.cli._private_operations_request",
                   return_value={"status": "COMPLETED"}) as request:
            code, output, errors = self._run(
                ["ops", "disabled-profile-run", target_id, identity_id, review_id,
                 "--confirmed"], {"HOME": "/tmp"})
            self.assertEqual((code, errors), (0, ""))
            request.assert_called_once_with("POST", "/v1/operations/maintenance", {
                "action": "DISABLED_PROFILE_RUN", "target_id": target_id,
                "identity_id": identity_id, "review_id": review_id, "confirmed": True})
        argument_errors = StringIO()
        with redirect_stderr(argument_errors), self.assertRaises(SystemExit) as missing_confirmation:
            self._run(["ops", "disabled-profile-run", target_id, identity_id,
                       review_id], {"HOME": "/tmp"})
        self.assertEqual(missing_confirmation.exception.code, 2)
        self.assertIn("--confirmed", argument_errors.getvalue())

    def test_named_profile_cli_binds_exact_session_to_private_review(self) -> None:
        target_id = "TARGET-" + "1" * 32
        identity_id = "IDENTITY-" + "2" * 32
        session_id = "BSESSION-" + "3" * 32
        review_id = "MAINT-" + "4" * 32
        with patch("hackbot.cli._private_operations_request",
                   return_value={"id": review_id}) as request:
            code, _, errors = self._run(
                ["ops", "named-profile-plan", target_id, identity_id, session_id],
                {"HOME": "/tmp"})
            self.assertEqual((code, errors), (0, ""))
            request.assert_called_once_with("POST", "/v1/operations/maintenance", {
                "action": "NAMED_PROFILE_PLAN", "target_id": target_id,
                "identity_id": identity_id, "session_id": session_id})
        with patch("hackbot.cli._private_operations_request",
                   return_value={"status": "COMPLETED"}) as request:
            code, _, errors = self._run(
                ["ops", "named-profile-run", target_id, identity_id, session_id,
                 review_id, "--confirmed"], {"HOME": "/tmp"})
            self.assertEqual((code, errors), (0, ""))
            request.assert_called_once_with("POST", "/v1/operations/maintenance", {
                "action": "NAMED_PROFILE_RUN", "target_id": target_id,
                "identity_id": identity_id, "session_id": session_id,
                "review_id": review_id, "confirmed": True})

    def test_storage_check_reports_integrity_state_without_recon(self) -> None:
        with patch("hackbot.cli.check_database") as check:
            check.return_value.to_dict.return_value = {"state": "SCHEMA_MISMATCH"}
            code, output, errors = self._run(
                ["storage", "check"], {"HOME": "/tmp", "RECON_DB_DSN": "secret-fixture"})
        self.assertEqual(code, 2)
        self.assertEqual(errors, "")
        self.assertEqual(json.loads(output)["state"], "SCHEMA_MISMATCH")
        self.assertNotIn("secret-fixture", output)
        check.assert_called_once()

    def test_storage_startup_check_skips_old_schema_without_secret_output(self) -> None:
        with patch("hackbot.cli.EvidenceFactStore.from_config") as factory:
            factory.return_value.service_schema_status.return_value = {
                "state": "MIGRATION_REQUIRED", "actual_schema": 34,
                "expected_schema": 45}
            code, output, errors = self._run(
                ["storage", "startup-check"],
                {"HOME": "/tmp", "RECON_DB_DSN": "private-fixture"})
        self.assertEqual((code, errors), (1, ""))
        self.assertEqual(json.loads(output)["state"], "MIGRATION_REQUIRED")
        self.assertNotIn("private-fixture", output)
        with patch("hackbot.cli.EvidenceFactStore.from_config") as factory:
            factory.return_value.service_schema_status.return_value = {
                "state": "FRESH", "actual_schema": None, "expected_schema": 45}
            code, output, errors = self._run(["storage", "startup-check"], {"HOME": "/tmp"})
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(json.loads(output)["state"], "FRESH")

    def test_research_retention_cli_requires_reviewed_confirmation(self) -> None:
        with TemporaryDirectory() as directory:
            with patch("hackbot.cli.EvidenceFactStore.from_config"), patch(
                "hackbot.cli.ResearchBriefRetentionManager"
            ) as manager:
                manager.return_value.plan.return_value.to_dict.return_value = {
                    "dry_run": True, "candidate_count": 0}
                manager.return_value.run.return_value = {"retired": 0}
                code, output, errors = self._run(
                    ["retention", "research-plan"], {"HOME": directory})
                self.assertEqual((code, errors), (0, ""))
                self.assertTrue(json.loads(output)["dry_run"])
                manager.return_value.plan.assert_called_once_with()
                code, output, errors = self._run(
                    ["retention", "research-run", "--confirmed"], {"HOME": directory})
                self.assertEqual((code, errors), (0, ""))
                self.assertEqual(json.loads(output)["retired"], 0)
                manager.return_value.run.assert_called_once_with(confirmed=True)
