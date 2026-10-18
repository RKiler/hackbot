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

    def test_skill_catalog_root_is_explicit_and_validated(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            default = load_config(environ={"HOME": directory})
            self.assertTrue((default.skills.root / "core").is_dir())
            path.write_text('[skills]\nroot = "research-skills"\n')
            configured = load_config(path, environ={"HOME": directory})
            self.assertEqual(configured.skills.root, Path(directory) / "research-skills")
            path.write_text('[skills]\nroot = 23\n')
            with self.assertRaises(ConfigError):
                load_config(path, environ={"HOME": directory})

    def test_store_path_and_limits(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('[store]\nartifact_root = "blob-store"\nmax_inline_bytes = 16\nmax_page_size = 7\n')
            config = load_config(path, environ={"HOME": directory})
            self.assertEqual(config.store.artifact_root, Path(directory) / "blob-store")
            self.assertEqual(config.store.max_inline_bytes, 16)
            self.assertEqual(config.store.max_page_size, 7)
            path.write_text('[store]\nmax_inline_bytes = 16385\n')
            with self.assertRaises(ConfigError):
                load_config(path, environ={"HOME": directory})

    def test_environment_path_overrides(self) -> None:
        with TemporaryDirectory() as directory:
            config = load_config(environ={"HOME": directory, "HACKBOT_HOME": "my-state"})
            self.assertEqual(config.paths.root, Path.cwd() / "my-state")

    def test_executor_defaults_and_validation(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('[executor]\nallow_direct = true\nmax_redirects = 2\n')
            config = load_config(path, environ={"HOME": directory})
            self.assertTrue(config.executor.allow_direct)
            self.assertFalse(config.executor.capture_required)
            self.assertEqual(config.executor.max_redirects, 2)
            for body in ('[executor]\nallow_direct = "yes"\n',
                         '[executor]\nread_timeout_seconds = 0\n',
                         '[executor]\nmax_response_bytes = 99999999\n',
                         '[executor]\nproxy_url = "http://foreign.test"\n'):
                path.write_text(body)
                with self.assertRaises(ConfigError):
                    load_config(path, environ={"HOME": directory})

    def test_object_factory_settings_are_bounded(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('[objects]\nrecipe_root = "approved-recipes"\ncleanup_request_budget = 3\n')
            config = load_config(path, environ={"HOME": directory})
            self.assertEqual(config.objects.recipe_root, Path(directory) / "approved-recipes")
            self.assertEqual(config.objects.cleanup_request_budget, 3)
            for body in ('[objects]\nmax_creation_depth = 0\n',
                         '[objects]\ncleanup_request_budget = 100\n',
                         '[objects]\nname_prefix = "secret=private-value"\n'):
                path.write_text(body)
                with self.assertRaises(ConfigError) as captured:
                    load_config(path, environ={"HOME": directory})
                self.assertNotIn("private-value", str(captured.exception))

    def test_named_profile_grace_is_typed_and_bounded(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            self.assertEqual(load_config(environ={"HOME": directory}).retention
                             .active_identity_profile_grace_hours, 720)
            path.write_text("[retention]\nactive_identity_profile_grace_hours = 960\n")
            self.assertEqual(load_config(path, environ={"HOME": directory}).retention
                             .active_identity_profile_grace_hours, 960)
            for value in ("0", "8761", '"720"', "true"):
                path.write_text("[retention]\nactive_identity_profile_grace_hours = " + value + "\n")
                with self.subTest(value=value), self.assertRaises(ConfigError):
                    load_config(path, environ={"HOME": directory})

    def test_orphan_scan_timeout_is_typed_and_bounded(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text("[retention]\norphan_scan_timeout_seconds = 45\n")
            self.assertEqual(load_config(path, environ={"HOME": directory}).retention
                             .orphan_scan_timeout_seconds, 45)
            for value in ("0", "301", '"30"', "true"):
                path.write_text("[retention]\norphan_scan_timeout_seconds = " + value + "\n")
                with self.subTest(value=value), self.assertRaises(ConfigError):
                    load_config(path, environ={"HOME": directory})

    def test_traffic_retention_hours_and_target_override_are_validated(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            target_id = "TARGET-" + "a" * 32
            path.write_text(
                "[retention]\ntraffic_anonymous_hours = 48\n"
                "traffic_authenticated_hours = 240\ntraffic_execution_hours = 720\n"
                f"[retention.traffic_target_hours]\n\"{target_id}\" = 96\n"
            )
            configured = load_config(path, environ={"HOME": directory}).retention
            self.assertEqual(configured.traffic_anonymous_hours, 48)
            self.assertEqual(configured.traffic_target_hours[target_id], 96)
            for body in (
                "[retention]\ntraffic_anonymous_hours = 0\n",
                "[retention]\ntraffic_execution_hours = true\n",
                "[retention.traffic_target_hours]\n\"bad-target\" = 24\n",
                f"[retention.traffic_target_hours]\n\"{target_id}\" = 0\n",
            ):
                path.write_text(body)
                with self.subTest(body=body), self.assertRaises(ConfigError):
                    load_config(path, environ={"HOME": directory})

    def test_research_brief_retention_grace_is_typed_and_bounded(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            self.assertEqual(load_config(environ={"HOME": directory}).retention
                             .research_brief_grace_days, 30)
            path.write_text("[retention]\nresearch_brief_grace_days = 60\n")
            self.assertEqual(load_config(path, environ={"HOME": directory}).retention
                             .research_brief_grace_days, 60)
            for value in ("0", "3651", '"30"', "true"):
                path.write_text("[retention]\nresearch_brief_grace_days = " + value + "\n")
                with self.subTest(value=value), self.assertRaises(ConfigError):
                    load_config(path, environ={"HOME": directory})

    def test_dom_asset_retention_periods_are_typed_and_bounded(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            defaults = load_config(environ={"HOME": directory}).retention
            self.assertEqual((defaults.js_artifact_hours, defaults.source_map_hours),
                             (2160, 2160))
            path.write_text("[retention]\njs_artifact_hours = 720\nsource_map_hours = 1440\n")
            configured = load_config(path, environ={"HOME": directory}).retention
            self.assertEqual((configured.js_artifact_hours, configured.source_map_hours),
                             (720, 1440))
            for field in ("js_artifact_hours", "source_map_hours"):
                for value in ("0", "87601", '"720"', "true"):
                    path.write_text(f"[retention]\n{field} = {value}\n")
                    with self.subTest(field=field, value=value), self.assertRaises(ConfigError):
                        load_config(path, environ={"HOME": directory})

    def test_cpu_load_gate_is_explicitly_configured(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            self.assertIsNone(load_config(environ={"HOME": directory}).resources
                              .high_load_per_cpu)
            path.write_text("[resources]\nhigh_load_per_cpu = 4.0\n"
                            "critical_load_per_cpu = 8.0\n")
            configured = load_config(path, environ={"HOME": directory})
            self.assertEqual(configured.resources.high_load_per_cpu, 4.0)
            self.assertEqual(configured.resources.critical_load_per_cpu, 8.0)
            path.write_text("[resources]\nhigh_load_per_cpu = 4.0\n")
            with self.assertRaises(ConfigError):
                load_config(path, environ={"HOME": directory})

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
