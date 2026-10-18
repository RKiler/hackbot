from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.burp_storage import inspect_burp_storage


class BurpStorageTests(unittest.TestCase):
    def test_bounded_inventory_separates_persistent_data_and_launcher_temp(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "burp-runtime"
            browser = root / "data" / "burpbrowser"
            browser.mkdir(parents=True)
            (browser / "browser.bin").write_bytes(b"browser")
            project = root / "tmp" / "community-12345678"
            project.mkdir(parents=True)
            (project / "project.tmp").write_bytes(b"temp")
            (root / "setup.png").write_bytes(b"image")
            result = inspect_burp_storage(root, max_seconds=5)
            self.assertEqual(result.state, "COMPLETE")
            self.assertEqual(result.files, 3)
            self.assertEqual(result.data_estimated_bytes, 7)
            self.assertEqual(result.temp_estimated_bytes, 4)
            self.assertEqual(result.other_estimated_bytes, 5)
            self.assertEqual(result.estimated_bytes, 16)
            self.assertNotIn(str(root), str(result.to_dict()))

    def test_symlinks_are_not_followed_or_counted_as_contents(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "burp-runtime"
            root.mkdir()
            outside = base / "outside"
            outside.mkdir()
            (outside / "secret.bin").write_bytes(b"not-burp-data")
            (root / "data").symlink_to(outside, target_is_directory=True)
            result = inspect_burp_storage(root, max_seconds=5)
            self.assertEqual(result.state, "PARTIAL")
            self.assertEqual(result.symlinks_skipped, 1)
            self.assertEqual(result.estimated_bytes, 0)
            self.assertEqual(inspect_burp_storage(root / "data").state, "UNAVAILABLE")

    def test_limits_and_missing_runtime_are_explicit(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "burp-runtime"
            root.mkdir()
            for index in range(10):
                (root / f"file-{index}").write_bytes(b"x")
            result = inspect_burp_storage(root, max_entries=2, max_seconds=5)
            self.assertEqual(result.state, "PARTIAL")
            self.assertEqual(result.scanned_entries, 2)
            self.assertEqual(inspect_burp_storage(root / "missing").state, "UNAVAILABLE")
            with self.assertRaises(ValueError):
                inspect_burp_storage(root, max_entries=0)
