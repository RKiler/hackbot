import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_all.py"
SPEC = importlib.util.spec_from_file_location("bughunter_test_matrix", SCRIPT)
assert SPEC and SPEC.loader
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class TestMatrixTests(unittest.TestCase):
    def test_interrupted_segment_stops_its_process_group(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import signal,time; "
             "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
             "print('ready', flush=True); time.sleep(60)"],
            start_new_session=True, stdout=subprocess.PIPE,
        )
        try:
            self.assertEqual(process.stdout.readline(), b"ready\n")
            MATRIX._stop_test_group(process)
            self.assertIsNotNone(process.returncode)
            self.assertLess(process.returncode, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()

    def test_cpu_progress_probe_is_nonfatal(self):
        self.assertIsNone(MATRIX._cpu_ticks(-1))
        current = MATRIX._cpu_ticks(os.getpid())
        if Path("/proc/self/stat").exists():
            self.assertIsInstance(current, int)
            self.assertGreaterEqual(current, 0)

    def test_every_repository_test_module_has_exactly_one_group(self):
        manifest = MATRIX.validate_manifest()
        self.assertEqual(manifest["module_count"], sum(manifest["groups"].values()))
        self.assertGreaterEqual(manifest["module_count"], 40)

    def test_unassigned_module_fails_manifest(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tests").mkdir()
            (root / "tests" / "test_new_unassigned.py").touch()
            with patch.object(MATRIX, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "test_new_unassigned.py"):
                    MATRIX.validate_manifest()

    def test_duplicate_assignment_fails_manifest(self):
        with patch.dict(MATRIX.GROUPS, {"unit-fast": MATRIX.GROUPS["unit-fast"] + ("test_cli.py",)}):
            with self.assertRaisesRegex(ValueError, "duplicate"):
                MATRIX.validate_manifest()

    def test_mutation_fixture_does_not_reexport_another_test_case(self):
        from tests import test_authorization_mutations

        imported_cases = [name for name, value in vars(test_authorization_mutations).items()
                          if isinstance(value, type) and issubclass(value, unittest.TestCase)
                          and value.__module__ != test_authorization_mutations.__name__]
        self.assertEqual(imported_cases, [])

    def test_fingerprint_changes_with_source_and_ignores_pycache(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "module.py").write_text("value = 1\n")
            (root / "pyproject.toml").write_text("[project]\nname = 'fixture'\n")
            with patch.object(MATRIX, "ROOT", root), patch.object(
                    MATRIX.metadata, "distributions", return_value=[]):
                before = MATRIX.source_fingerprint()
                (root / "src" / "__pycache__").mkdir()
                (root / "src" / "__pycache__" / "module.pyc").write_bytes(b"cache")
                self.assertEqual(MATRIX.source_fingerprint(), before)
                (root / "src" / "module.py").write_text("value = 2\n")
                self.assertNotEqual(MATRIX.source_fingerprint(), before)

    def test_resume_reuses_only_completed_matching_segments(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "matrix.json"
            groups = {"first": ("test_first.py",), "second": ("test_second.py",)}
            manifest = {"module_count": 2, "groups": {"first": 1, "second": 1}}
            def completed(name, files, **_kwargs):
                return {"group": name, "modules": len(files), "exit_code": 0,
                        "elapsed_seconds": 1.0}
            with patch.object(MATRIX, "GROUPS", groups), patch.object(
                    MATRIX, "validate_manifest", return_value=manifest), patch.object(
                    MATRIX, "source_fingerprint", return_value="fingerprint"), patch.object(
                    MATRIX, "run_group", side_effect=completed) as run, redirect_stdout(io.StringIO()):
                self.assertEqual(MATRIX.main(["--resume-file", str(path)]), 0)
                self.assertEqual(run.call_count, 2)
            saved = json.loads(path.read_text())
            self.assertEqual(set(saved["results"]), {"first", "second"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with patch.object(MATRIX, "GROUPS", groups), patch.object(
                    MATRIX, "validate_manifest", return_value=manifest), patch.object(
                    MATRIX, "source_fingerprint", return_value="fingerprint"), patch.object(
                    MATRIX, "run_group") as run, redirect_stdout(io.StringIO()):
                self.assertEqual(MATRIX.main(["--resume-file", str(path)]), 0)
                run.assert_not_called()
            with patch.object(MATRIX, "GROUPS", groups), patch.object(
                    MATRIX, "validate_manifest", return_value=manifest), patch.object(
                    MATRIX, "source_fingerprint", return_value="different"), patch.object(
                    MATRIX, "run_group") as run, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(MATRIX.main(["--resume-file", str(path)]), 2)
                run.assert_not_called()

    def test_interrupted_matrix_keeps_only_completed_group(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "matrix.json"
            groups = {"first": ("test_first.py",), "second": ("test_second.py",)}
            manifest = {"module_count": 2, "groups": {"first": 1, "second": 1}}
            first = {"group": "first", "modules": 1, "exit_code": 0,
                     "elapsed_seconds": 1.0}
            with patch.object(MATRIX, "GROUPS", groups), patch.object(
                    MATRIX, "validate_manifest", return_value=manifest), patch.object(
                    MATRIX, "source_fingerprint", return_value="fingerprint"), patch.object(
                    MATRIX, "run_group", side_effect=[first, KeyboardInterrupt]), redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    MATRIX.main(["--resume-file", str(path)])
            self.assertEqual(set(json.loads(path.read_text())["results"]), {"first"})

    def test_interrupted_group_resumes_only_unfinished_modules(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "matrix.json"
            groups = {"service": ("test_first.py", "test_second.py", "test_third.py")}
            manifest = {"module_count": 3, "groups": {"service": 3}}
            passed = {"group": "module", "modules": 1, "exit_code": 0,
                      "elapsed_seconds": 1.0}
            with patch.object(MATRIX, "GROUPS", groups), patch.object(
                    MATRIX, "validate_manifest", return_value=manifest), patch.object(
                    MATRIX, "source_fingerprint", return_value="fingerprint"), patch.object(
                    MATRIX, "run_group", side_effect=[passed, KeyboardInterrupt]), \
                    redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    MATRIX.main(["--resume-file", str(path)])
            saved = json.loads(path.read_text())
            self.assertEqual(set(saved["module_results"]), {"test_first.py"})
            self.assertEqual(saved["results"], {})
            with patch.object(MATRIX, "GROUPS", groups), patch.object(
                    MATRIX, "validate_manifest", return_value=manifest), patch.object(
                    MATRIX, "source_fingerprint", return_value="fingerprint"), patch.object(
                    MATRIX, "run_group", return_value=passed) as run, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(MATRIX.main(["--resume-file", str(path)]), 0)
                self.assertEqual(run.call_count, 2)
            saved = json.loads(path.read_text())
            self.assertEqual(set(saved["module_results"]), set(groups["service"]))
            self.assertEqual(set(saved["results"]), {"service"})

    def test_selected_modules_complete_group_only_after_every_pass(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "matrix.json"
            groups = {"service": ("test_first.py", "test_second.py")}
            manifest = {"module_count": 2, "groups": {"service": 2}}
            passed = {"group": "module", "modules": 1, "exit_code": 0,
                      "elapsed_seconds": 1.0}
            with patch.object(MATRIX, "GROUPS", groups), patch.object(
                    MATRIX, "validate_manifest", return_value=manifest), patch.object(
                    MATRIX, "source_fingerprint", return_value="fingerprint"), patch.object(
                    MATRIX, "run_group", return_value=passed) as run, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(MATRIX.main(["--module", "test_second.py",
                                              "--resume-file", str(path)]), 0)
                saved = json.loads(path.read_text())
                self.assertEqual(set(saved["module_results"]), {"test_second.py"})
                self.assertEqual(saved["results"], {})
                self.assertEqual(MATRIX.main(["--module", "test_first.py",
                                              "--resume-file", str(path)]), 0)
                self.assertEqual(run.call_count, 2)
                saved = json.loads(path.read_text())
                self.assertEqual(set(saved["module_results"]), set(groups["service"]))
                self.assertEqual(set(saved["results"]), {"service"})
                self.assertEqual(MATRIX.main(["--resume-file", str(path)]), 0)
                self.assertEqual(run.call_count, 2)

    def test_selected_module_requires_resume_and_no_group(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                MATRIX.main(["--module", "test_cli.py"])
            self.assertEqual(error.exception.code, 2)
            with self.assertRaises(SystemExit) as error:
                MATRIX.main(["--module", "test_cli.py", "--group", "unit-fast",
                             "--resume-file", "unused.json"])
            self.assertEqual(error.exception.code, 2)

    def test_failed_module_does_not_complete_group(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "matrix.json"
            groups = {"service": ("test_first.py", "test_second.py")}
            manifest = {"module_count": 2, "groups": {"service": 2}}
            passed = {"group": "module", "modules": 1, "exit_code": 0,
                      "elapsed_seconds": 1.0}
            failed = {**passed, "exit_code": 1}
            with patch.object(MATRIX, "GROUPS", groups), patch.object(
                    MATRIX, "validate_manifest", return_value=manifest), patch.object(
                    MATRIX, "source_fingerprint", return_value="fingerprint"), patch.object(
                    MATRIX, "run_group", side_effect=[passed, failed]), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(MATRIX.main(["--resume-file", str(path)]), 1)
            saved = json.loads(path.read_text())
            self.assertEqual(set(saved["module_results"]), {"test_first.py"})
            self.assertEqual(saved["results"], {})

    def test_resume_rejects_mismatched_or_invalid_pass_records(self):
        groups = {"service": ("test_first.py",)}
        manifest = {"module_count": 1, "groups": {"service": 1}}
        valid = {
            "version": 1, "fingerprint": "fingerprint", "manifest": manifest,
            "results": {"service": {"group": "service", "modules": 1,
                                    "exit_code": 0, "elapsed_seconds": 1.0,
                                    "completed_at": "2026-10-17T00:00:00+00:00"}},
            "module_results": {"test_first.py": {"group": "service", "exit_code": 0,
                                                 "elapsed_seconds": 1.0,
                                                 "completed_at": "2026-10-17T00:00:00+00:00"}},
        }
        with TemporaryDirectory() as temp, patch.object(MATRIX, "GROUPS", groups):
            path = Path(temp) / "resume.json"
            for field, key, value in (
                ("results", "group", "other"),
                ("results", "elapsed_seconds", -1),
                ("results", "elapsed_seconds", float("nan")),
                ("module_results", "group", "other"),
                ("module_results", "elapsed_seconds", float("inf")),
            ):
                with self.subTest(field=field, key=key, value=value):
                    state = json.loads(json.dumps(valid))
                    record = state[field]["service" if field == "results" else "test_first.py"]
                    record[key] = value
                    path.write_text(json.dumps(state))
                    with self.assertRaisesRegex(ValueError, "resume file does not match"):
                        MATRIX._read_resume(path, "fingerprint", manifest)
            state = json.loads(json.dumps(valid))
            state["module_results"]["test_unknown.py"] = state["module_results"]["test_first.py"]
            path.write_text(json.dumps(state))
            with self.assertRaisesRegex(ValueError, "resume file does not match"):
                MATRIX._read_resume(path, "fingerprint", manifest)
            state = json.loads(json.dumps(valid))
            state["module_results"] = {}
            path.write_text(json.dumps(state))
            with self.assertRaisesRegex(ValueError, "resume file does not match"):
                MATRIX._read_resume(path, "fingerprint", manifest)

    def test_changed_source_during_segment_is_not_credited(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "matrix.json"
            groups = {"first": ("test_first.py",)}
            manifest = {"module_count": 1, "groups": {"first": 1}}
            first = {"group": "first", "modules": 1, "exit_code": 0,
                     "elapsed_seconds": 1.0}
            with patch.object(MATRIX, "GROUPS", groups), patch.object(
                    MATRIX, "validate_manifest", return_value=manifest), patch.object(
                    MATRIX, "source_fingerprint", side_effect=["before", "after"]), patch.object(
                    MATRIX, "run_group", return_value=first), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(MATRIX.main(["--resume-file", str(path)]), 2)
            self.assertFalse(path.exists())
