from configparser import RawConfigParser
from pathlib import Path
import unittest


UNIT = Path(__file__).parents[1] / "deploy/systemd/bughunter-agent.service"
JOURNAL_BUDGET = Path(__file__).parents[1] / "deploy/journald/90-vps-journal-budget.conf"
VNC_UNIT = Path(__file__).parents[1] / "deploy/systemd/bughunter-vnc.service"
VNC_LOGROTATE = Path(__file__).parents[1] / "deploy/logrotate/bughunter-vnc"
VNC_LAUNCHER = Path(__file__).parents[1] / "scripts/start_browser_vnc.sh"


class ProductionUnitTests(unittest.TestCase):
    def test_agent_unit_protects_source_and_preserves_block_storage(self):
        config = RawConfigParser(strict=False)
        config.read(UNIT)
        service = config["Service"]
        self.assertEqual(config["Unit"]["ConditionPathExists"],
                         "/root/codex_artifacts/bughunter-agent/state/bughunter.sqlite3")
        self.assertEqual(service["NoNewPrivileges"], "true")
        self.assertEqual(service["PrivateTmp"], "true")
        self.assertEqual(service["ProtectSystem"], "strict")
        self.assertEqual(service["ProtectHome"], "read-only")
        self.assertEqual(service["ReadWritePaths"],
                         "/root/codex_artifacts/bughunter-agent")
        self.assertEqual(service["CapabilityBoundingSet"], "")
        self.assertEqual(service["AmbientCapabilities"], "")
        self.assertEqual(service["RuntimeDirectory"], "bughunter-agent")
        self.assertEqual(service["RuntimeDirectoryPreserve"], "yes")
        self.assertEqual(service["LogRateLimitIntervalSec"], "30s")
        self.assertEqual(service["LogRateLimitBurst"], "300")
        self.assertIn("storage startup-check", service["ExecCondition"])

    def test_host_journal_budget_is_bounded_without_forced_age_expiry(self):
        config = RawConfigParser()
        self.assertEqual(config.read(JOURNAL_BUDGET), [str(JOURNAL_BUDGET)])
        journal = config["Journal"]
        self.assertEqual(journal["SystemMaxUse"], "4G")
        self.assertEqual(journal["SystemKeepFree"], "10G")
        self.assertEqual(journal["RuntimeMaxUse"], "512M")
        self.assertNotIn("MaxRetentionSec", journal)

    def test_vnc_file_logs_rotate_until_launcher_uses_journald(self):
        config = RawConfigParser(strict=False)
        self.assertEqual(config.read(VNC_UNIT), [str(VNC_UNIT)])
        self.assertEqual(config["Service"]["LogRateLimitIntervalSec"], "30s")
        self.assertEqual(config["Service"]["LogRateLimitBurst"], "300")
        launcher = VNC_LAUNCHER.read_text(encoding="utf-8")
        rotation = VNC_LOGROTATE.read_text(encoding="utf-8")
        for name in ("xvfb", "fluxbox", "x11vnc", "websockify"):
            self.assertNotIn(f'{name}.log', launcher)
            self.assertIn(f'/browser-vnc/{name}.log', rotation)
        for directive in ("weekly", "maxsize 10M", "rotate 4", "compress",
                          "copytruncate", "su root root"):
            self.assertIn(directive, rotation)


if __name__ == "__main__":
    unittest.main()
