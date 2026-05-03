import datetime as dt
import os
import sys
import tempfile
import unittest


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import legacy_automation_auditor as auditor  # noqa: E402


class LegacyAutomationAuditorTests(unittest.TestCase):
    def test_add_flags_marks_old_privileged_tasks_high(self):
        now = dt.datetime(2026, 5, 3, tzinfo=dt.timezone.utc)
        old_timestamp = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc).timestamp()

        task = auditor.add_flags(
            {"mtime_epoch": old_timestamp, "runs_as_privileged": True},
            days=180,
            now=now,
        )

        self.assertTrue(task["suspicious"])
        self.assertEqual(task["severity"], "high")
        self.assertEqual(task["flags"], ["old_definition", "privileged"])

    def test_parse_user_cron_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write("# comment\n")
            handle.write("SHELL=/bin/bash\n")
            handle.write("0 2 * * * /usr/local/bin/backup.sh --quiet\n")
            path = handle.name

        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))

        tasks = auditor.parse_cron_file(
            path=path,
            default_user="alice",
            source_type="test",
            system_format=False,
            warnings=[],
        )

        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["schedule"], "0 2 * * *")
        self.assertEqual(tasks[0]["run_user"], "alice")
        self.assertEqual(tasks[0]["command_path"], "/usr/local/bin/backup.sh")

    def test_parse_system_cron_file_with_nickname_schedule(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write("@reboot root /opt/startup.sh\n")
            path = handle.name

        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))

        tasks = auditor.parse_cron_file(
            path=path,
            default_user=None,
            source_type="test",
            system_format=True,
            warnings=[],
        )

        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["schedule"], "@reboot")
        self.assertEqual(tasks[0]["run_user"], "root")
        self.assertTrue(tasks[0]["runs_as_privileged"])

    def test_filter_tasks_can_hide_windows_builtins(self):
        tasks = [
            {
                "platform": "windows",
                "name": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
                "command": "%windir%\\system32\\defrag.exe",
                "suspicious": True,
            },
            {
                "platform": "windows",
                "name": "\\CustomAuditTask",
                "command": "C:\\Tools\\audit.exe",
                "suspicious": True,
            },
        ]

        filtered = auditor.filter_tasks(tasks, only_suspicious=True, hide_windows_builtin=True)

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["name"], "\\CustomAuditTask")


if __name__ == "__main__":
    unittest.main()
