from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.cli import main


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
            self.assertEqual(body["phase"], 2)
            self.assertEqual(body["recon_integration"], "adapter_available_not_connected")
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
