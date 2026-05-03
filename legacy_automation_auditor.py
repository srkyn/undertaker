#!/usr/bin/env python3
"""
legacy_automation_auditor.py

Find old and/or high-privilege scheduled automations on Linux, with optional
Windows Scheduled Task support when run on Windows.

The scanner is intentionally best-effort: cron, systemd, and Windows task
definitions vary by platform and permission level. Unreadable files and command
failures are recorded as warnings instead of stopping the audit.
"""

import argparse
import datetime as dt
import glob
import json
import os
import platform
import re
import shutil
import shlex
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple


Task = Dict[str, Any]
Warning = Dict[str, str]


CRON_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
SYSTEMD_ON_CALENDAR_RE = re.compile(r"^\s*OnCalendar\s*=\s*(.+?)\s*$", re.IGNORECASE)
SYSTEMD_UNIT_RE = re.compile(r"^\s*Unit\s*=\s*(.+?)\s*$", re.IGNORECASE)
SYSTEMD_USER_RE = re.compile(r"^\s*User\s*=\s*(.+?)\s*$", re.IGNORECASE)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_from_timestamp(timestamp: Optional[float]) -> Optional[str]:
    if timestamp is None:
        return None
    return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()


def safe_stat(path: str, warnings: List[Warning]) -> Optional[os.stat_result]:
    try:
        return os.stat(path)
    except OSError as exc:
        warnings.append({"source": path, "error": str(exc)})
        return None


def safe_read_text(path: str, warnings: List[Warning]) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError as exc:
        warnings.append({"source": path, "error": str(exc)})
        return None


def run_command(args: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


def owner_name_from_uid(uid: Optional[int]) -> Optional[str]:
    if uid is None:
        return None
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def is_root_like(value: Optional[str]) -> bool:
    if not value:
        return False
    normalized = value.strip().lower()
    return normalized in {"root", "0", "administrator", "administrators", "system", "localsystem"}


def first_command_token(command: str) -> str:
    command = command.strip()
    if not command:
        return ""
    try:
        return shlex.split(command, posix=(os.name != "nt"))[0]
    except ValueError:
        return command.split()[0]


def add_flags(task: Task, days: int, now: dt.datetime) -> Task:
    mtime = task.get("mtime_epoch")
    age_days: Optional[int] = None
    age_suspicious = False

    if isinstance(mtime, (int, float)):
        modified = dt.datetime.fromtimestamp(mtime, dt.timezone.utc)
        age_days = max(0, (now - modified).days)
        age_suspicious = age_days > days

    privileged = bool(task.get("runs_as_privileged"))
    flags: List[str] = []
    if age_suspicious:
        flags.append("old_definition")
    if privileged:
        flags.append("privileged")

    severity = "none"
    if age_suspicious and privileged:
        severity = "high"
    elif age_suspicious or privileged:
        severity = "medium"

    task["age_days"] = age_days
    task["flags"] = flags
    task["suspicious"] = bool(flags)
    task["severity"] = severity
    return task


def parse_cron_file(
    path: str,
    default_user: Optional[str],
    source_type: str,
    system_format: bool,
    warnings: List[Warning],
) -> List[Task]:
    text = safe_read_text(path, warnings)
    stat = safe_stat(path, warnings)
    if text is None:
        return []

    tasks: List[Task] = []
    owner = owner_name_from_uid(stat.st_uid) if stat else default_user
    mtime = stat.st_mtime if stat else None

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or CRON_ENV_RE.match(line):
            continue

        parts = line.split()
        run_user = default_user
        schedule = ""
        command_index = 0

        if parts[0].startswith("@"):
            schedule = parts[0]
            command_index = 1
            if system_format:
                if len(parts) < 3:
                    continue
                run_user = parts[1]
                command_index = 2
        else:
            if len(parts) < 6:
                continue

            schedule = " ".join(parts[:5])
            command_index = 5

            # /etc/crontab and /etc/cron.d entries include a user field after
            # the five schedule fields. Per-user crontabs do not.
            if system_format:
                if len(parts) < 7:
                    continue
                run_user = parts[5]
                command_index = 6

        command = " ".join(parts[command_index:])
        if not command:
            continue

        name = f"{os.path.basename(path)}:{lineno}"
        tasks.append(
            {
                "platform": "linux",
                "type": "cron",
                "name": name,
                "command": command,
                "command_path": first_command_token(command),
                "privilege_level": run_user or owner or "unknown",
                "runs_as_privileged": is_root_like(run_user or owner),
                "owner": owner,
                "run_user": run_user,
                "schedule": schedule,
                "source": path,
                "line": lineno,
                "source_type": source_type,
                "mtime_epoch": mtime,
                "mtime": iso_from_timestamp(mtime),
            }
        )

    return tasks


def task_for_periodic_cron_file(path: str, period: str, warnings: List[Warning]) -> Optional[Task]:
    stat = safe_stat(path, warnings)
    if not stat or not os.path.isfile(path):
        return None
    mode = stat.st_mode
    if not (mode & 0o111):
        return None

    owner = owner_name_from_uid(stat.st_uid)
    return {
        "platform": "linux",
        "type": "cron-periodic",
        "name": os.path.basename(path),
        "command": path,
        "command_path": path,
        "privilege_level": "root",
        "runs_as_privileged": True,
        "owner": owner,
        "run_user": "root",
        "schedule": period,
        "source": path,
        "line": None,
        "source_type": f"/etc/cron.{period}",
        "mtime_epoch": stat.st_mtime,
        "mtime": iso_from_timestamp(stat.st_mtime),
    }


def scan_linux_cron(warnings: List[Warning]) -> List[Task]:
    tasks: List[Task] = []

    cron_sources = [
        ("/etc/crontab", None, "/etc/crontab", True),
    ]

    for path in sorted(glob.glob("/etc/cron.d/*")):
        if os.path.isfile(path):
            cron_sources.append((path, None, "/etc/cron.d", True))

    for spool_dir in ("/var/spool/cron/crontabs", "/var/spool/cron"):
        for path in sorted(glob.glob(os.path.join(spool_dir, "*"))):
            if os.path.isfile(path):
                user = os.path.basename(path)
                cron_sources.append((path, user, spool_dir, False))

    seen = set()
    for path, default_user, source_type, system_format in cron_sources:
        if path in seen:
            continue
        seen.add(path)
        tasks.extend(parse_cron_file(path, default_user, source_type, system_format, warnings))

    for period in ("hourly", "daily", "weekly", "monthly"):
        for path in sorted(glob.glob(f"/etc/cron.{period}/*")):
            task = task_for_periodic_cron_file(path, period, warnings)
            if task:
                tasks.append(task)

    return tasks


def find_unit_file(unit_name: str, warnings: List[Warning]) -> Tuple[Optional[str], Optional[float]]:
    rc, stdout, stderr = run_command(["systemctl", "show", unit_name, "-p", "FragmentPath", "--value"])
    if rc == 0:
        path = stdout.strip()
        if path and path != "n/a":
            stat = safe_stat(path, warnings)
            return path, stat.st_mtime if stat else None
    elif stderr.strip():
        warnings.append({"source": unit_name, "error": stderr.strip()})
    return None, None


def parse_systemd_timer_file(path: str, warnings: List[Warning]) -> Tuple[Optional[str], Optional[str]]:
    text = safe_read_text(path, warnings)
    if not text:
        return None, None

    on_calendar = []
    unit_name = None
    for line in text.splitlines():
        calendar_match = SYSTEMD_ON_CALENDAR_RE.match(line)
        if calendar_match:
            on_calendar.append(calendar_match.group(1).strip())
        unit_match = SYSTEMD_UNIT_RE.match(line)
        if unit_match:
            unit_name = unit_match.group(1).strip()

    return "; ".join(on_calendar) if on_calendar else None, unit_name


def parse_systemd_service_user(service_path: Optional[str], warnings: List[Warning]) -> Optional[str]:
    if not service_path:
        return None
    text = safe_read_text(service_path, warnings)
    if not text:
        return None
    for line in text.splitlines():
        match = SYSTEMD_USER_RE.match(line)
        if match:
            return match.group(1).strip()
    return None


def scan_linux_systemd_timers(warnings: List[Warning]) -> List[Task]:
    rc, stdout, stderr = run_command(
        ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"], timeout=30
    )
    if rc != 0:
        if stderr.strip():
            warnings.append({"source": "systemctl list-timers", "error": stderr.strip()})
        return []

    tasks: List[Task] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        timer_name = next((part for part in parts if part.endswith(".timer")), None)
        if not timer_name:
            continue

        timer_path, timer_mtime = find_unit_file(timer_name, warnings)
        schedule, service_name = parse_systemd_timer_file(timer_path, warnings) if timer_path else (None, None)
        if not service_name:
            service_name = timer_name[:-6] + ".service"

        service_path, _ = find_unit_file(service_name, warnings)
        service_user = parse_systemd_service_user(service_path, warnings)
        run_user = service_user or "root"
        timer_stat = safe_stat(timer_path, warnings) if timer_path else None

        tasks.append(
            {
                "platform": "linux",
                "type": "systemd-timer",
                "name": timer_name,
                "command": service_name,
                "command_path": service_path or service_name,
                "privilege_level": run_user,
                "runs_as_privileged": is_root_like(run_user),
                "owner": owner_name_from_uid(timer_stat.st_uid) if timer_stat else None,
                "run_user": run_user,
                "schedule": schedule or "see systemctl list-timers",
                "source": timer_path or timer_name,
                "line": None,
                "source_type": "systemd timer",
                "mtime_epoch": timer_mtime,
                "mtime": iso_from_timestamp(timer_mtime),
                "service_unit": service_name,
                "service_source": service_path,
            }
        )

    return tasks


def scan_linux(warnings: List[Warning]) -> List[Task]:
    tasks = []
    tasks.extend(scan_linux_cron(warnings))
    tasks.extend(scan_linux_systemd_timers(warnings))
    return tasks


def windows_task_timestamp(task_path: Optional[str]) -> Tuple[Optional[float], Optional[str]]:
    if not task_path:
        return None, None

    normalized = task_path.strip("\\").replace("/", "\\")
    full_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks", normalized)
    try:
        stat = os.stat(full_path)
        return stat.st_mtime, full_path
    except OSError:
        return None, full_path


def scan_windows_scheduled_tasks(warnings: List[Warning]) -> List[Task]:
    ps_script = r"""
$ErrorActionPreference = 'Continue'
Get-ScheduledTask | ForEach-Object {
    $principal = $_.Principal
    $actions = @($_.Actions | ForEach-Object {
        $execute = $_.Execute
        $arguments = $_.Arguments
        if ($arguments) { "$execute $arguments" } else { "$execute" }
    }) -join ' ; '
    $triggers = @($_.Triggers | ForEach-Object { if ($_ -ne $null) { $_.ToString() } }) -join ' ; '
    [PSCustomObject]@{
        TaskName = $_.TaskName
        TaskPath = $_.TaskPath
        UserId = $principal.UserId
        RunLevel = $principal.RunLevel.ToString()
        Actions = $actions
        Triggers = $triggers
    }
} | ConvertTo-Json -Depth 5
"""
    candidates = [shell for shell in ("powershell.exe", "powershell", "pwsh.exe", "pwsh") if shutil.which(shell)]
    if not candidates:
        warnings.append({"source": "Get-ScheduledTask", "error": "No PowerShell executable found"})
        return []

    rc, stdout, stderr = 1, "", ""
    for shell in candidates:
        command = [shell, "-NoProfile", "-Command", ps_script]
        if shell.lower().startswith("powershell"):
            command = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script]
        rc, stdout, stderr = run_command(command, timeout=60)
        if rc == 0 and stdout.strip():
            break

    if rc != 0:
        warnings.append({"source": "Get-ScheduledTask", "error": stderr.strip() or "PowerShell command failed"})
        return []
    if not stdout.strip():
        warnings.append({"source": "Get-ScheduledTask", "error": stderr.strip() or "PowerShell returned no task data"})
        return []

    try:
        data = json.loads(stdout) if stdout.strip() else []
    except json.JSONDecodeError as exc:
        warnings.append({"source": "Get-ScheduledTask", "error": f"Could not parse JSON: {exc}"})
        return []

    if isinstance(data, dict):
        data = [data]

    tasks: List[Task] = []
    for item in data:
        task_path = (item.get("TaskPath") or "\\") + (item.get("TaskName") or "")
        mtime, source_file = windows_task_timestamp(task_path)
        user_id = item.get("UserId") or "unknown"
        run_level = item.get("RunLevel") or "unknown"
        privileged = is_root_like(user_id) or str(run_level).lower() in {"highest", "highestavailable", "1"}

        tasks.append(
            {
                "platform": "windows",
                "type": "scheduled-task",
                "name": task_path,
                "command": item.get("Actions") or "",
                "command_path": first_command_token(item.get("Actions") or ""),
                "privilege_level": f"{user_id} ({run_level})",
                "runs_as_privileged": privileged,
                "owner": user_id,
                "run_user": user_id,
                "schedule": item.get("Triggers") or "",
                "source": source_file or task_path,
                "line": None,
                "source_type": "Windows Scheduled Task",
                "mtime_epoch": mtime,
                "mtime": iso_from_timestamp(mtime),
            }
        )

    return tasks


def scan_all(warnings: List[Warning]) -> List[Task]:
    system = platform.system().lower()
    if system == "linux":
        return scan_linux(warnings)
    if system == "windows":
        return scan_windows_scheduled_tasks(warnings)
    warnings.append({"source": "platform", "error": f"Unsupported platform: {platform.system()}"})
    return []


def trim(value: Any, width: int) -> str:
    text = "" if value is None else str(value)
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


def print_table(tasks: List[Task]) -> None:
    headers = ["Severity", "Type", "Name", "Run As", "Age", "Schedule", "Command/Source"]
    rows = []
    for task in sorted(tasks, key=lambda item: (item.get("severity") != "high", item.get("severity") != "medium", item.get("name") or "")):
        rows.append(
            [
                task.get("severity", "none").upper(),
                task.get("type", ""),
                trim(task.get("name", ""), 34),
                trim(task.get("privilege_level", ""), 24),
                "" if task.get("age_days") is None else f"{task['age_days']}d",
                trim(task.get("schedule", ""), 28),
                trim(task.get("command") or task.get("source", ""), 44),
            ]
        )

    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    fmt = "  ".join(f"{{:<{width}}}" for width in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * width for width in widths]))
    for row in rows:
        print(fmt.format(*row))


def write_json(path: str, tasks: List[Task], warnings: List[Warning], days: int) -> None:
    payload = {
        "generated_at": utc_now().isoformat(),
        "threshold_days": days,
        "summary": {
            "total": len(tasks),
            "suspicious": sum(1 for task in tasks if task.get("suspicious")),
            "high_severity": sum(1 for task in tasks if task.get("severity") == "high"),
        },
        "tasks": tasks,
        "warnings": warnings,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find old and/or high-privilege scheduled automations on Linux and Windows."
    )
    parser.add_argument("--days", type=int, default=180, help="Age threshold in days. Default: 180.")
    parser.add_argument("--output", default="results.json", help="JSON output path. Default: results.json.")
    parser.add_argument("--no-json", action="store_true", help="Do not write JSON output.")
    return parser.parse_args(argv)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    warnings: List[Warning] = []

    if args.days < 0:
        print("--days must be zero or greater", file=sys.stderr)
        return 2

    now = utc_now()
    tasks = [add_flags(task, args.days, now) for task in scan_all(warnings)]

    print_table(tasks)

    suspicious_count = sum(1 for task in tasks if task.get("suspicious"))
    high_count = sum(1 for task in tasks if task.get("severity") == "high")
    print(f"\nFound {len(tasks)} tasks, {suspicious_count} suspicious ({high_count} high severity).")

    if warnings:
        print(f"Warnings: {len(warnings)} collection issue(s). See JSON output for details." if not args.no_json else f"Warnings: {len(warnings)} collection issue(s).")

    if not args.no_json:
        try:
            write_json(args.output, tasks, warnings, args.days)
            print(f"Wrote JSON results to {args.output}")
        except OSError as exc:
            print(f"Could not write JSON output {args.output}: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
