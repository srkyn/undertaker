#!/usr/bin/env python3
"""
undertaker.py

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


VERSION = "0.3.1"


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
    except (ImportError, KeyError, OSError):
        return str(uid)


def is_root_like(value: Optional[str]) -> bool:
    if not value:
        return False
    normalized = value.strip().lower()
    privileged_names = {"root", "0", "administrator", "administrators", "system", "localsystem"}
    return (
        normalized in privileged_names
        or normalized.endswith("\\administrator")
        or normalized.endswith("\\administrators")
        or normalized.endswith("\\system")
        or normalized.endswith("\\localsystem")
    )


def first_command_token(command: str) -> str:
    command = command.strip()
    if not command:
        return ""
    try:
        return shlex.split(command, posix=(os.name != "nt"))[0].strip("\"'")
    except ValueError:
        return command.split()[0].strip("\"'")


def first_action_path(action_paths: str) -> str:
    action_paths = action_paths.strip()
    if not action_paths:
        return ""
    return action_paths.split(" ; ", 1)[0].strip().strip("\"'")


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
    risk_reasons: List[str] = []
    if age_suspicious:
        flags.append("old_definition")
        risk_reasons.append(f"Task definition is older than {days} days.")
    if privileged:
        flags.append("privileged")
        risk_reasons.append(f"Task runs as {task.get('privilege_level') or task.get('run_user') or 'a privileged account'}.")

    severity = "none"
    if age_suspicious and privileged:
        severity = "high"
    elif age_suspicious or privileged:
        severity = "medium"

    task["age_days"] = age_days
    task["flags"] = flags
    task["risk_reasons"] = risk_reasons
    task["suspicious"] = bool(flags)
    task["severity"] = severity
    return task


def build_payload(tasks: List[Task], warnings: List[Warning], days: int) -> Dict[str, Any]:
    return {
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


def command_path_exists(command_path: str) -> Optional[bool]:
    if not command_path:
        return None

    expanded = os.path.expandvars(os.path.expanduser(command_path.strip().strip('"')))
    if not expanded:
        return None

    if os.path.isabs(expanded) or os.path.dirname(expanded):
        return os.path.exists(expanded)

    return shutil.which(expanded) is not None


def task_identity(task: Task) -> List[str]:
    values = [
        task.get("name"),
        task.get("source"),
        task.get("command_path"),
        task.get("command"),
    ]
    return [str(value).lower() for value in values if value]


def load_allowlist(path: Optional[str], warnings: List[Warning]) -> List[str]:
    if not path:
        return []

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append({"source": path, "error": f"Could not load allowlist: {exc}"})
        return []

    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("allowlist", [])
    else:
        warnings.append({"source": path, "error": "Allowlist must be a list or an object with an allowlist key"})
        return []

    return [str(entry).lower() for entry in entries if str(entry).strip()]


def apply_allowlist(tasks: List[Task], allowlist: List[str]) -> List[Task]:
    if not allowlist:
        return tasks

    for task in tasks:
        identities = task_identity(task)
        matched = next((entry for entry in allowlist if any(entry in identity for identity in identities)), None)
        if not matched:
            continue

        task["allowlisted"] = True
        task["allowlist_match"] = matched
        task["flags"] = []
        task["risk_reasons"] = [f"Suppressed by allowlist entry: {matched}"]
        task["suspicious"] = False
        task["severity"] = "none"

    return tasks


def add_path_checks(tasks: List[Task]) -> List[Task]:
    for task in tasks:
        exists = command_path_exists(str(task.get("command_path") or ""))
        task["command_path_exists"] = exists
        if exists is False:
            flags = task.setdefault("flags", [])
            if "missing_command_path" not in flags:
                flags.append("missing_command_path")
            risk_reasons = task.setdefault("risk_reasons", [])
            risk_reasons.append("Extracted command path does not appear to exist.")
            task["suspicious"] = True
            if task.get("severity") == "none":
                task["severity"] = "medium"
    return tasks


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
    $info = $_ | Get-ScheduledTaskInfo
    $principal = $_.Principal
    $actions = @($_.Actions | ForEach-Object {
        $execute = $_.Execute
        $arguments = $_.Arguments
        if ($arguments) { "$execute $arguments" } else { "$execute" }
    }) -join ' ; '
    $actionPaths = @($_.Actions | ForEach-Object { $_.Execute }) -join ' ; '
    $triggers = @($_.Triggers | ForEach-Object { if ($_ -ne $null) { $_.ToString() } }) -join ' ; '
    [PSCustomObject]@{
        TaskName = $_.TaskName
        TaskPath = $_.TaskPath
        UserId = $principal.UserId
        RunLevel = $principal.RunLevel.ToString()
        Actions = $actions
        ActionPaths = $actionPaths
        Triggers = $triggers
        LastRunTime = if ($info) { $info.LastRunTime } else { $null }
        LastTaskResult = if ($info) { $info.LastTaskResult } else { $null }
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
        command = item.get("Actions") or ""
        command_path = first_action_path(item.get("ActionPaths") or "") or first_command_token(command)

        tasks.append(
            {
                "platform": "windows",
                "type": "scheduled-task",
                "name": task_path,
                "command": command,
                "command_path": command_path,
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
                "last_run_time": item.get("LastRunTime"),
                "last_task_result": item.get("LastTaskResult"),
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


def is_windows_builtin_task(task: Task) -> bool:
    if task.get("platform") != "windows":
        return False

    name = str(task.get("name") or "").lower()
    command = str(task.get("command") or "").lower()
    source = str(task.get("source") or "").lower()

    return (
        name.startswith("\\microsoft\\windows\\")
        or "\\windows\\system32\\tasks\\microsoft\\windows\\" in source
        or command.startswith("%windir%\\")
        or command.startswith("%systemroot%\\")
        or command.startswith("c:\\windows\\")
    )


def filter_tasks(tasks: List[Task], only_suspicious: bool, hide_windows_builtin: bool) -> List[Task]:
    filtered = []
    for task in tasks:
        if only_suspicious and not task.get("suspicious"):
            continue
        if hide_windows_builtin and is_windows_builtin_task(task):
            continue
        filtered.append(task)
    return filtered


def trim(value: Any, width: int) -> str:
    text = "" if value is None else str(value)
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


def print_table(tasks: List[Task]) -> None:
    headers = ["Severity", "Type", "Name", "Run As", "Age", "Schedule", "Command/Source"]
    include_path_status = any("command_path_exists" in task for task in tasks)
    if include_path_status:
        headers.insert(6, "Path")

    rows = []
    for task in sorted(tasks, key=lambda item: (item.get("severity") != "high", item.get("severity") != "medium", item.get("name") or "")):
        row = [
            task.get("severity", "none").upper(),
            task.get("type", ""),
            trim(task.get("name", ""), 34),
            trim(task.get("privilege_level", ""), 24),
            "" if task.get("age_days") is None else f"{task['age_days']}d",
            trim(task.get("schedule", ""), 28),
        ]
        if include_path_status:
            exists = task.get("command_path_exists")
            row.append("yes" if exists is True else "no" if exists is False else "n/a")
        row.append(trim(task.get("command") or task.get("source", ""), 44))
        rows.append(row)

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
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(build_payload(tasks, warnings, days), handle, indent=2, sort_keys=True)


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="uk",
        description="Find old and/or high-privilege scheduled automations on Linux and Windows."
    )
    parser.add_argument("-d", "--days", type=int, default=180, help="Age threshold in days. Default: 180.")
    parser.add_argument("-o", "--output", default="results.json", help="JSON output path. Default: results.json.")
    parser.add_argument("-n", "--no-json", action="store_true", help="Do not write JSON output.")
    parser.add_argument(
        "-f", "--format",
        choices=("table", "json"),
        default="table",
        help="Output format for stdout. Default: table.",
    )
    parser.add_argument(
        "-p", "--check-paths",
        action="store_true",
        help="Check whether extracted command paths appear to exist.",
    )
    parser.add_argument(
        "-a", "--allowlist",
        help="Path to a JSON allowlist. Entries are matched against task name, source, command path, and command.",
    )
    parser.add_argument("--version", action="version", version=f"Undertaker {VERSION}")
    parser.add_argument("-s", "--only-suspicious", action="store_true", help="Only include suspicious tasks in output.")
    parser.add_argument(
        "-w", "--hide-windows-builtin",
        action="store_true",
        help="Hide obvious built-in Microsoft Windows tasks from output.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    warnings: List[Warning] = []

    if args.days < 0:
        print("--days must be zero or greater", file=sys.stderr)
        return 2

    now = utc_now()
    tasks = [add_flags(task, args.days, now) for task in scan_all(warnings)]
    if args.check_paths:
        add_path_checks(tasks)
    apply_allowlist(tasks, load_allowlist(args.allowlist, warnings))
    output_tasks = filter_tasks(tasks, args.only_suspicious, args.hide_windows_builtin)

    if args.format == "json":
        print(json.dumps(build_payload(output_tasks, warnings, args.days), indent=2, sort_keys=True))
    else:
        print_table(output_tasks)

        suspicious_count = sum(1 for task in tasks if task.get("suspicious"))
        high_count = sum(1 for task in tasks if task.get("severity") == "high")
        print(f"\nFound {len(tasks)} tasks, {suspicious_count} suspicious ({high_count} high severity).")
        if len(output_tasks) != len(tasks):
            print(f"Displayed {len(output_tasks)} task(s) after filters.")

        if warnings:
            print(f"Warnings: {len(warnings)} collection issue(s). See JSON output for details." if not args.no_json else f"Warnings: {len(warnings)} collection issue(s).")

    if not args.no_json:
        try:
            write_json(args.output, output_tasks, warnings, args.days)
            print(f"Wrote JSON results to {args.output}", file=sys.stderr if args.format == "json" else sys.stdout)
        except OSError as exc:
            print(f"Could not write JSON output {args.output}: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
