from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hackbot.process_health import inspect_owned_processes


class ProcessHealthTests(unittest.TestCase):
    def test_only_exact_owned_cgroup_browsers_are_identified(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "cgroups"
            proc = root / "proc"
            for unit, pids in (
                ("bughunter-agent.service", "101\n102\n"),
                ("bughunter-burp.service", "201\n"),
                ("bughunter-vnc.service", "301\n"),
            ):
                folder = groups / unit
                folder.mkdir(parents=True)
                (folder / "cgroup.procs").write_text(pids)
            for pid, name in ((101, "chrome"), (102, "python"), (201, "java"),
                              (301, "Xvfb"), (999, "chrome")):
                folder = proc / str(pid)
                folder.mkdir(parents=True)
                (folder / "comm").write_text(name + "\n")
            idle = inspect_owned_processes(cgroup_root=groups, proc_root=proc,
                                           active_browser_sessions=0)
            self.assertEqual(idle.state, "OK")
            self.assertEqual(idle.browser_pids, (101,))
            self.assertEqual(idle.suspected_orphan_browser_pids, (101,))
            self.assertEqual(idle.service_processes["bughunter-vnc.service"], 1)
            self.assertEqual(idle.vnc_display_pids, (301,))
            active = inspect_owned_processes(cgroup_root=groups, proc_root=proc,
                                             active_browser_sessions=1)
            self.assertEqual(active.suspected_orphan_browser_pids, ())

    def test_linux_comm_truncation_does_not_hide_owned_browsers(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "cgroups"
            proc = root / "proc"
            for unit, pids in (("bughunter-agent.service", "101\n102\n103\n"),
                               ("bughunter-burp.service", ""),
                               ("bughunter-vnc.service", "")):
                folder = groups / unit
                folder.mkdir(parents=True)
                (folder / "cgroup.procs").write_text(pids)
            for pid, name in ((101, "chrome-headless"),
                              (102, "chromium-browse"), (103, "python"),
                              (999, "chrome-headless")):
                folder = proc / str(pid)
                folder.mkdir(parents=True)
                (folder / "comm").write_text(name + "\n")
            result = inspect_owned_processes(cgroup_root=groups, proc_root=proc,
                                             active_browser_sessions=0)
            self.assertEqual(result.state, "OK")
            self.assertEqual(result.browser_pids, (101, 102))
            self.assertEqual(result.suspected_orphan_browser_pids, (101, 102))

    def test_missing_or_symlinked_agent_group_never_claims_browser_ownership(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "cgroups"
            proc = root / "proc"
            outside = root / "unrelated"
            outside.mkdir()
            (outside / "cgroup.procs").write_text("999\n")
            (groups / "bughunter-agent.service").parent.mkdir()
            (groups / "bughunter-agent.service").symlink_to(outside, target_is_directory=True)
            (proc / "999").mkdir(parents=True)
            (proc / "999" / "comm").write_text("chrome\n")
            result = inspect_owned_processes(cgroup_root=groups, proc_root=proc,
                                             active_browser_sessions=0)
            self.assertEqual(result.state, "UNKNOWN")
            self.assertEqual(result.browser_pids, ())
            self.assertEqual(result.suspected_orphan_browser_pids, ())

    def test_unreadable_agent_process_name_is_unknown_and_blocks_cleanup(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "cgroups"
            proc = root / "proc"
            for unit, pids in (("bughunter-agent.service", "101\n102\n"),
                               ("bughunter-burp.service", ""),
                               ("bughunter-vnc.service", "")):
                folder = groups / unit
                folder.mkdir(parents=True)
                (folder / "cgroup.procs").write_text(pids)
            (proc / "101").mkdir(parents=True)
            (proc / "101" / "comm").write_text("chrome-headless-sh\n")
            (proc / "102").mkdir(parents=True)
            result = inspect_owned_processes(cgroup_root=groups, proc_root=proc,
                                             active_browser_sessions=0)
            self.assertEqual(result.state, "UNKNOWN")
            self.assertEqual(result.browser_pids, (101,))
            self.assertEqual(result.suspected_orphan_browser_pids, ())

    def test_child_cgroup_browser_is_included_before_profile_cleanup(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "cgroups"
            proc = root / "proc"
            for unit in ("bughunter-agent.service", "bughunter-burp.service",
                         "bughunter-vnc.service"):
                folder = groups / unit
                folder.mkdir(parents=True)
                (folder / "cgroup.procs").write_text("101\n" if unit ==
                                                        "bughunter-agent.service" else "")
            child = groups / "bughunter-agent.service" / "browser-scope"
            child.mkdir()
            (child / "cgroup.procs").write_text("102\n")
            for pid, name in ((101, "python"), (102, "chrome")):
                folder = proc / str(pid)
                folder.mkdir(parents=True)
                (folder / "comm").write_text(name + "\n")
            result = inspect_owned_processes(cgroup_root=groups, proc_root=proc,
                                             active_browser_sessions=0)
            self.assertEqual(result.state, "OK")
            self.assertEqual(result.service_processes["bughunter-agent.service"], 2)
            self.assertEqual(result.browser_pids, (102,))
            self.assertEqual(result.suspected_orphan_browser_pids, (102,))

    def test_unsafe_child_cgroup_keeps_process_inventory_unknown(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "cgroups"
            proc = root / "proc"
            for unit in ("bughunter-agent.service", "bughunter-burp.service",
                         "bughunter-vnc.service"):
                folder = groups / unit
                folder.mkdir(parents=True)
                (folder / "cgroup.procs").write_text("")
            outside = root / "outside"
            outside.mkdir()
            (outside / "cgroup.procs").write_text("999\n")
            (groups / "bughunter-agent.service" / "browser-scope").symlink_to(
                outside, target_is_directory=True)
            result = inspect_owned_processes(cgroup_root=groups, proc_root=proc,
                                             active_browser_sessions=0)
            self.assertEqual(result.state, "UNKNOWN")
            self.assertEqual(result.browser_pids, ())
            self.assertEqual(result.suspected_orphan_browser_pids, ())

    def test_agent_display_orphans_are_distinct_from_expected_vnc_processes(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "cgroups"
            proc = root / "proc"
            for unit, pids in (("bughunter-agent.service", "101\n102\n"),
                               ("bughunter-burp.service", ""),
                               ("bughunter-vnc.service", "201\n202\n")):
                folder = groups / unit
                folder.mkdir(parents=True)
                (folder / "cgroup.procs").write_text(pids)
            for pid, name in ((101, "Xvfb"), (102, "websockify"),
                              (201, "Xvfb"), (202, "x11vnc")):
                folder = proc / str(pid)
                folder.mkdir(parents=True)
                (folder / "comm").write_text(name + "\n")
            idle = inspect_owned_processes(cgroup_root=groups, proc_root=proc,
                                           active_browser_sessions=0)
            self.assertEqual(idle.state, "OK")
            self.assertEqual(idle.agent_display_pids, (101, 102))
            self.assertEqual(idle.vnc_display_pids, (201, 202))
            self.assertEqual(idle.suspected_orphan_display_pids, (101, 102))
            active = inspect_owned_processes(cgroup_root=groups, proc_root=proc,
                                             active_browser_sessions=1)
            self.assertEqual(active.suspected_orphan_display_pids, ())
