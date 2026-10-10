from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def test_default_paths_are_local_and_not_created(self) -> None:
        with TemporaryDirectory() as directory:
            home = Path(directory)
            config = load_config(environ={"HOME": str(home)})
            self.assertEqual(config.paths.config_file, home / ".config/bughunter-agent/config.toml")
            self.assertEqual(config.paths.root, home / ".local/state/bughunter-agent")
            self.assertEqual(config.paths.evidence, config.paths.artifacts / "evidence")
            self.assertFalse(config.paths.root.exists())

    def test_toml_and_relative_root(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('[paths]\nroot = "data"\n[logging]\nlevel = "debug"\n')
            config = load_config(path, environ={"HOME": directory})
            self.assertEqual(config.paths.root, Path(directory) / "data")
            self.assertEqual(config.log_level, "DEBUG")

    def test_environment_path_overrides(self) -> None:
        with TemporaryDirectory() as directory:
            config = load_config(environ={"HOME": directory, "HACKBOT_HOME": "my-state"})
            self.assertEqual(config.paths.root, Path.cwd() / "my-state")

    def test_explicit_missing_file_is_invalid(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaises(ConfigError):
                load_config(Path(directory) / "missing.toml", environ={"HOME": directory})

    def test_invalid_configurations_reject_without_echoing_values(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            for body in (
                '[logging]\nlevel = "private-value"\n',
                '[paths]\nroot = 12\n',
                '[paths]\nroot = ""\n',
                '[database]\npassword = "private-value"\n',
                '[logging]\nlevel = [\n',
            ):
                with self.subTest(body=body.splitlines()[0]):
                    path.write_text(body)
                    with self.assertRaises(ConfigError) as captured:
                        load_config(path, environ={"HOME": directory})
                    self.assertNotIn("private-value", str(captured.exception))
