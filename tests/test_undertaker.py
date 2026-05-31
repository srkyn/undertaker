import datetime as dt
import os
import sys
import tempfile
import unittest


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import undertaker as auditor  # noqa: E402


class LegacyAutomationAuditorTests(unittest.TestCase):
    def test_version_is_defined(self):
        self.assertRegex(auditor.VERSION, r"^\d+\.\d+\.\d+$")

    def test_is_root_like_handles_domain_qualified_windows_accounts(self):
        self.assertTrue(auditor.is_root_like("NT AUTHORITY\\SYSTEM"))
        self.assertTrue(auditor.is_root_like("BUILTIN\\Administrators"))
        self.assertFalse(auditor.is_root_like("DOMAIN\\analyst"))

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
        self.assertEqual(len(task["risk_reasons"]), 2)

    def test_apply_allowlist_suppresses_matching_task(self):
        tasks = [
            {
                "name": "known-maintenance",
                "source": "/etc/cron.d/known",
                "command_path": "/usr/local/bin/known",
                "command": "/usr/local/bin/known",
                "flags": ["privileged"],
                "risk_reasons": ["Task runs as root."],
                "suspicious": True,
                "severity": "medium",
            }
        ]

        auditor.apply_allowlist(tasks, ["known-maintenance"])

        self.assertFalse(tasks[0]["suspicious"])
        self.assertEqual(tasks[0]["severity"], "none")
        self.assertTrue(tasks[0]["allowlisted"])
        self.assertEqual(tasks[0]["allowlist_match"], "known-maintenance")

    def test_build_payload_summarizes_filtered_tasks(self):
        tasks = [
            {"suspicious": True, "severity": "high"},
            {"suspicious": False, "severity": "none"},
        ]

        payload = auditor.build_payload(tasks, warnings=[{"source": "x", "error": "y"}], days=90)

        self.assertEqual(payload["threshold_days"], 90)
        self.assertEqual(payload["summary"]["total"], 2)
        self.assertEqual(payload["summary"]["suspicious"], 1)
        self.assertEqual(payload["summary"]["high_severity"], 1)
        self.assertEqual(len(payload["warnings"]), 1)

    def test_command_path_exists_handles_present_missing_and_empty_paths(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            path = handle.name

        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))

        self.assertTrue(auditor.command_path_exists(path))
        self.assertFalse(auditor.command_path_exists(os.path.join(tempfile.gettempdir(), "missing-undertaker-bin")))
        self.assertIsNone(auditor.command_path_exists(""))

    def test_first_command_token_strips_outer_quotes(self):
        command = '"C:\\Program Files\\Example\\task.exe" --quiet'

        self.assertEqual(auditor.first_command_token(command), "C:\\Program Files\\Example\\task.exe")

    def test_first_action_path_preserves_unquoted_paths_with_spaces(self):
        action_paths = "C:\\Program Files\\Example\\task.exe ; C:\\Tools\\next.exe"

        self.assertEqual(auditor.first_action_path(action_paths), "C:\\Program Files\\Example\\task.exe")

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

    def test_parse_cron_fixture(self):
        path = os.path.join(PROJECT_ROOT, "tests", "fixtures", "cron", "system-cron")

        tasks = auditor.parse_cron_file(
            path=path,
            default_user=None,
            source_type="fixture",
            system_format=True,
            warnings=[],
        )

        self.assertEqual(len(tasks), 2)
        self.assertEqual(tasks[0]["run_user"], "root")
        self.assertEqual(tasks[1]["schedule"], "@daily")
        self.assertEqual(tasks[1]["run_user"], "appuser")

    def test_parse_system_cron_file_with_user_field(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write("*/15 * * * * www-data /srv/app/cleanup.sh\n")
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
        self.assertEqual(tasks[0]["schedule"], "*/15 * * * *")
        self.assertEqual(tasks[0]["run_user"], "www-data")
        self.assertFalse(tasks[0]["runs_as_privileged"])

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

    def test_parse_systemd_timer_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write("[Timer]\n")
            handle.write("OnCalendar=daily\n")
            handle.write("OnCalendar=Mon *-*-* 03:00:00\n")
            handle.write("Unit=undertaker.service\n")
            path = handle.name

        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))

        schedule, unit_name = auditor.parse_systemd_timer_file(path, warnings=[])

        self.assertEqual(schedule, "daily; Mon *-*-* 03:00:00")
        self.assertEqual(unit_name, "undertaker.service")

    def test_parse_systemd_timer_fixture(self):
        timer_path = os.path.join(PROJECT_ROOT, "tests", "fixtures", "systemd", "legacy-cleanup.timer")
        service_path = os.path.join(PROJECT_ROOT, "tests", "fixtures", "systemd", "legacy-cleanup.service")

        schedule, unit_name = auditor.parse_systemd_timer_file(timer_path, warnings=[])
        service_user = auditor.parse_systemd_service_user(service_path, warnings=[])

        self.assertEqual(schedule, "Sun *-*-* 02:30:00")
        self.assertEqual(unit_name, "legacy-cleanup.service")
        self.assertEqual(service_user, "cleanup")

    def test_parse_systemd_service_user(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write("[Service]\n")
            handle.write("User=undertaker\n")
            path = handle.name

        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))

        self.assertEqual(auditor.parse_systemd_service_user(path, warnings=[]), "undertaker")

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

    def test_add_path_checks_adds_existence_field(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            path = handle.name

        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))

        tasks = auditor.add_path_checks([{"command_path": path}])

        self.assertTrue(tasks[0]["command_path_exists"])

    def test_add_path_checks_flags_missing_paths(self):
        missing = os.path.join(tempfile.gettempdir(), "missing-undertaker-command")

        tasks = auditor.add_path_checks(
            [{"command_path": missing, "flags": [], "suspicious": False, "severity": "none"}]
        )

        self.assertFalse(tasks[0]["command_path_exists"])
        self.assertIn("missing_command_path", tasks[0]["flags"])
        self.assertTrue(tasks[0]["suspicious"])
        self.assertEqual(tasks[0]["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
