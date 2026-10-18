from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from hackbot.config import ConfigError, ResourceSettings
from hackbot.resources import (ResourceBudgetManager, ResourceError, WorkKind,
                               _cgroup_memory_available, _load_per_cpu, _memory_available)


class Disk:
    def __init__(self, used: int, total: int = 1000):
        self.total = total
        self.used = used
        self.free = total - used


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = ResourceSettings(min_free_disk_bytes=0,
                                         min_available_memory_bytes=100)

    def manager(self, *, used=50, memory=1000):
        return ResourceBudgetManager(self.root, self.settings,
                                     disk_usage=lambda _path: Disk(used),
                                     memory_available=lambda: memory)

    def test_normal_and_warning_snapshot(self):
        self.assertEqual(self.manager().snapshot().state, "OK")
        snapshot = self.manager(used=800).snapshot()
        self.assertEqual(snapshot.state, "DEGRADED")
        self.assertEqual(snapshot.warnings, ("LOW_DISK",))
        self.manager(used=800).admit(WorkKind.BROWSER, active=0)

    def test_high_and_critical_disk_block_new_work(self):
        for used, reason in ((900, "HIGH_DISK"), (950, "CRITICAL_DISK")):
            with self.subTest(used=used):
                with self.assertRaises(ResourceError) as error:
                    self.manager(used=used).admit(WorkKind.PLANNER, active=0)
                self.assertEqual(error.exception.reason_code, reason)

    def test_system_disk_pressure_blocks_new_heavy_work_independently(self):
        system_root = self.root / "system"
        system_root.mkdir()
        settings = ResourceSettings(min_free_disk_bytes=0,
                                    min_free_system_disk_bytes=0,
                                    min_available_memory_bytes=100)
        for system_used, reason in ((800, "LOW_SYSTEM_DISK"),
                                    (900, "HIGH_SYSTEM_DISK"),
                                    (950, "CRITICAL_SYSTEM_DISK")):
            with self.subTest(system_used=system_used):
                manager = ResourceBudgetManager(
                    self.root, settings,
                    disk_usage=lambda path: Disk(system_used if path == system_root else 50),
                    memory_available=lambda: 1000,
                    system_disk_path=system_root,
                )
                snapshot = manager.snapshot()
                self.assertEqual(snapshot.system_disk_free_bytes, 1000 - system_used)
                self.assertIn(reason, snapshot.warnings)
                if reason == "LOW_SYSTEM_DISK":
                    self.assertEqual(manager.admit(WorkKind.PLANNER, active=0).state,
                                     "DEGRADED")
                else:
                    with self.assertRaises(ResourceError) as error:
                        manager.admit(WorkKind.PLANNER, active=0)
                    self.assertEqual(error.exception.reason_code, reason)

    def test_missing_system_disk_is_fail_closed(self):
        manager = ResourceBudgetManager(
            self.root, self.settings, disk_usage=lambda _path: Disk(50),
            memory_available=lambda: 1000,
            system_disk_path=self.root / "missing",
        )
        with self.assertRaises(ResourceError) as error:
            manager.admit(WorkKind.BROWSER, active=0)
        self.assertEqual(error.exception.reason_code, "SYSTEM_STORAGE_UNAVAILABLE")

    def test_system_disk_free_reserve_is_enforced_below_percent_threshold(self):
        system_root = self.root / "system"
        system_root.mkdir()
        settings = ResourceSettings(min_free_disk_bytes=0,
                                    min_free_system_disk_bytes=980,
                                    min_available_memory_bytes=100)
        manager = ResourceBudgetManager(
            self.root, settings,
            disk_usage=lambda _path: Disk(50),
            memory_available=lambda: 1000,
            system_disk_path=system_root,
        )
        with self.assertRaises(ResourceError) as error:
            manager.admit(WorkKind.PLANNER, active=0)
        self.assertEqual(error.exception.reason_code, "CRITICAL_SYSTEM_DISK")

    def test_memory_and_cap_block_new_heavy_work(self):
        with self.assertRaises(ResourceError) as error:
            self.manager(memory=50).admit(WorkKind.BROWSER, active=0)
        self.assertEqual(error.exception.reason_code, "LOW_MEMORY")
        with self.assertRaises(ResourceError) as error:
            self.manager().admit(WorkKind.PLANNER, active=1)
        self.assertEqual(error.exception.reason_code, "CONCURRENCY_LIMIT")

    def test_cgroup_memory_uses_smallest_remaining_limit(self):
        root = self.root / "cgroup"
        child = root / "system.slice" / "agent.service"
        child.mkdir(parents=True)
        membership = self.root / "membership"
        membership.write_text("0::/system.slice/agent.service\n", encoding="ascii")
        (root / "memory.max").write_text("max\n", encoding="ascii")
        (root / "system.slice" / "memory.max").write_text("1000\n", encoding="ascii")
        (root / "system.slice" / "memory.current").write_text("700\n", encoding="ascii")
        (child / "memory.max").write_text("500\n", encoding="ascii")
        (child / "memory.current").write_text("450\n", encoding="ascii")
        self.assertEqual(_cgroup_memory_available(membership=membership, root=root), 50)

        membership.write_text("0::/\n", encoding="ascii")
        self.assertIsNone(_cgroup_memory_available(membership=membership, root=root))

    def test_cgroup_memory_invalid_metrics_fail_closed(self):
        root = self.root / "cgroup"
        root.mkdir()
        membership = self.root / "membership"
        membership.write_text("0::/\n", encoding="ascii")
        (root / "memory.max").write_text("1000\n", encoding="ascii")
        with self.assertRaises(ValueError):
            _cgroup_memory_available(membership=membership, root=root)
        (root / "memory.current").write_text("not-a-number\n", encoding="ascii")
        with self.assertRaises(ValueError):
            _cgroup_memory_available(membership=membership, root=root)

    def test_memory_admission_uses_cgroup_headroom(self):
        with patch("hackbot.resources._host_memory_available", return_value=1000), \
                patch("hackbot.resources._cgroup_memory_available", return_value=50):
            self.assertEqual(_memory_available(), 50)
            manager = ResourceBudgetManager(self.root, self.settings,
                                            disk_usage=lambda _path: Disk(50),
                                            memory_available=_memory_available)
            with self.assertRaises(ResourceError) as error:
                manager.admit(WorkKind.BROWSER, active=0)
            self.assertEqual(error.exception.reason_code, "LOW_MEMORY")
        with patch("hackbot.resources._host_memory_available", return_value=1000), \
                patch("hackbot.resources._cgroup_memory_available", side_effect=ValueError):
            self.assertIsNone(_memory_available())

    def test_configured_cpu_load_sheds_new_work_by_priority(self):
        settings = ResourceSettings(min_free_disk_bytes=0,
                                    min_available_memory_bytes=100,
                                    high_load_per_cpu=4.0,
                                    critical_load_per_cpu=8.0)

        def manager(load):
            return ResourceBudgetManager(
                self.root, settings, disk_usage=lambda _path: Disk(50),
                memory_available=lambda: 1000, load_per_cpu=lambda: load)

        self.assertEqual(manager(3.9).admit(WorkKind.BROWSER, active=0).state, "OK")
        high = manager(4.0)
        self.assertEqual(high.snapshot().to_dict()["load_per_cpu"], 4.0)
        self.assertEqual(high.snapshot().warnings, ("HIGH_LOAD",))
        self.assertEqual(high.admit(WorkKind.PLAN, active=0).state, "DEGRADED")
        for kind in (WorkKind.PLANNER, WorkKind.BROWSER, WorkKind.BOOTSTRAP,
                     WorkKind.LEARNING, WorkKind.RESEARCH):
            with self.subTest(kind=kind), self.assertRaises(ResourceError) as error:
                high.admit(kind, active=0)
            self.assertEqual(error.exception.reason_code, "HIGH_LOAD")
        critical = manager(8.0)
        self.assertEqual(critical.snapshot().state, "BLOCKED")
        with self.assertRaises(ResourceError) as error:
            critical.admit(WorkKind.PLAN, active=0)
        self.assertEqual(error.exception.reason_code, "CRITICAL_LOAD")
        with self.assertRaises(ResourceError) as error:
            manager(None).admit(WorkKind.PLAN, active=0)
        self.assertEqual(error.exception.reason_code, "LOAD_STATUS_UNKNOWN")

    def test_cpu_load_sample_uses_available_cpu_count(self):
        with patch("hackbot.resources.os.sched_getaffinity", return_value={0, 1}), \
                patch("hackbot.resources.os.getloadavg", return_value=(9.0, 2.0, 1.0)):
            self.assertEqual(_load_per_cpu(), 4.5)
        with patch("hackbot.resources.os.getloadavg", side_effect=OSError):
            self.assertIsNone(_load_per_cpu())

    def test_invalid_resource_configuration_is_rejected(self):
        with self.assertRaises(ConfigError):
            ResourceSettings(warning_disk_percent=95, high_disk_percent=90)
        with self.assertRaises(ConfigError):
            ResourceSettings(required_mount="relative/mount")
        with self.assertRaises(ConfigError):
            ResourceSettings(min_free_system_disk_bytes=-1)
        with self.assertRaises(ConfigError):
            ResourceSettings(high_load_per_cpu=4.0)
        with self.assertRaises(ConfigError):
            ResourceSettings(high_load_per_cpu=8.0, critical_load_per_cpu=4.0)

    def test_missing_storage_root_never_falls_back_to_parent_disk(self):
        manager = ResourceBudgetManager(
            self.root / "missing", self.settings,
            disk_usage=lambda _path: self.fail("parent disk must not be measured"),
            memory_available=lambda: 1000)
        with self.assertRaises(ResourceError) as error:
            manager.admit(WorkKind.PLANNER, active=0)
        self.assertEqual(error.exception.reason_code, "STORAGE_UNAVAILABLE")

    def test_required_mount_is_checked_before_admission(self):
        settings = ResourceSettings(min_free_disk_bytes=0,
                                    min_available_memory_bytes=100,
                                    required_mount=str(self.root))
        manager = ResourceBudgetManager(self.root, settings,
            disk_usage=lambda _path: Disk(50), memory_available=lambda: 1000)
        with patch("hackbot.resources.os.path.ismount", return_value=False):
            with self.assertRaises(ResourceError) as error:
                manager.admit(WorkKind.BROWSER, active=0)
        self.assertEqual(error.exception.reason_code, "REQUIRED_MOUNT_UNAVAILABLE")
        with patch("hackbot.resources.os.path.ismount", return_value=True):
            self.assertEqual(manager.admit(WorkKind.BROWSER, active=0).state, "OK")
        wrong_root = ResourceBudgetManager(self.root.parent, settings,
            disk_usage=lambda _path: self.fail("wrong disk must not be measured"),
            memory_available=lambda: 1000)
        with patch("hackbot.resources.os.path.ismount", return_value=True):
            with self.assertRaises(ResourceError) as error:
                wrong_root.admit(WorkKind.BROWSER, active=0)
        self.assertEqual(error.exception.reason_code, "REQUIRED_MOUNT_UNAVAILABLE")
