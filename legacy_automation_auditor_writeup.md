# Undertaker: Legacy Automation Auditor

Find old, privileged scheduled jobs before they become operational risk.

## Plain-English Summary

Undertaker is a Python tool that looks for scheduled jobs that may have been forgotten but still run automatically. On Linux, that means cron jobs and systemd timers. On Windows, that means Scheduled Tasks.

The goal is simple: find automation that is old, powerful, or both.

This matters because scheduled jobs often run quietly in the background. They may restart services, run maintenance scripts, move files, launch applications, update software, or perform administrative tasks. Over time, people forget why a task was created, who owns it, or whether it still needs elevated permissions. A forgotten scheduled job with high privileges can become a security and operations risk.

The script does not delete, disable, or modify anything. It only audits and reports.

## Why This Project Exists

Many security reviews focus on users, passwords, open ports, or installed software. Scheduled automation is easier to overlook. That is a problem because scheduled jobs can:

- Run as `root`, `SYSTEM`, or Administrator.
- Execute scripts from paths that may no longer be maintained.
- Continue running after the original project, tool, or employee is gone.
- Become a persistence mechanism if abused by malware or an attacker.
- Break systems if an old script still runs against changed files, services, or APIs.

This project was built to answer a practical question:

> "What automatic tasks still exist on this machine, how old are their definitions, and do any of them run with high privileges?"

That makes it useful for home lab audits, endpoint hygiene, small business IT reviews, blue-team practice, and portfolio demonstration.

## What The Script Checks

The script is named `legacy_automation_auditor.py`.

It scans different places depending on the operating system.

On Linux, it checks:

- `/etc/crontab`
- `/etc/cron.d/*`
- User crontab spool locations such as `/var/spool/cron` and `/var/spool/cron/crontabs`
- Periodic cron directories such as `/etc/cron.hourly`, `/etc/cron.daily`, `/etc/cron.weekly`, and `/etc/cron.monthly`
- systemd timers through `systemctl list-timers`
- systemd timer unit files and related service units when available

On Windows, it checks:

- Windows Scheduled Tasks using PowerShell's `Get-ScheduledTask`
- Task names and paths
- Task actions
- Trigger information
- Run user and run level
- The task definition file timestamp under `C:\Windows\System32\Tasks`

## What Information It Collects

For each scheduled job, the auditor tries to collect:

- Task name
- Task type, such as cron, systemd timer, or Windows scheduled task
- Command or executable path
- User or account the task runs as
- Whether it appears privileged
- Owner, when available
- Schedule expression or trigger type, when easy to extract
- Source file or task definition location
- Last modified time of the task definition
- Approximate age in days
- Suspicion flags
- Severity

The script is intentionally best-effort. Some task definitions may require administrator or root permissions to read fully. If the script cannot read something, it records a warning instead of crashing.

## How Suspicious Tasks Are Flagged

The script uses two simple rules.

First, it checks age. If the task definition was last modified more than a configured number of days ago, it gets an `old_definition` flag. The default threshold is 180 days.

Second, it checks privilege. If the task appears to run as `root`, `SYSTEM`, Administrator, or with the highest Windows run level, it gets a `privileged` flag.

Severity is assigned like this:

- `none`: No suspicious condition found.
- `medium`: The task is old or privileged.
- `high`: The task is both old and privileged.

This does not mean every flagged task is malicious. Many normal operating system tasks are privileged. The purpose is to prioritize review. A task marked `high` deserves human attention because it combines two risk factors: age and elevated permissions.

## How To Run It

Basic run:

```bash
python legacy_automation_auditor.py
```

Use a different age threshold:

```bash
python legacy_automation_auditor.py --days 90
```

Write JSON to a specific file:

```bash
python legacy_automation_auditor.py --output results.json
```

Print only the table and skip JSON output:

```bash
python legacy_automation_auditor.py --no-json
```

Show only suspicious tasks:

```bash
python legacy_automation_auditor.py --only-suspicious
```

Hide obvious built-in Microsoft Windows tasks:

```bash
python legacy_automation_auditor.py --hide-windows-builtin
```

The script prints a summary like:

```text
Found X tasks, Y suspicious (Z high severity).
```

## What We Saw On This Machine

This project was tested on a personal Windows machine. The Windows Scheduled Tasks scan worked and produced a table of scheduled tasks.

In the local smoke test, the script found:

- 166 scheduled tasks
- 111 suspicious tasks
- 0 high severity tasks

The suspicious count was mostly caused by privileged Windows tasks. That is expected on Windows because many built-in Microsoft maintenance tasks run as `SYSTEM` or with elevated run levels.

The important result was not "111 bad tasks." The important result was that the tool successfully separated tasks into review categories without modifying the machine.

For a real review, the next step would be to focus on non-Microsoft tasks, unusual executable paths, user-created tasks, old definitions, and anything running with the highest privilege level.

## Why A Lot Of Windows Tasks Look Suspicious

Windows has many built-in scheduled tasks. Some handle updates, diagnostics, telemetry, cleanup, indexing, security maintenance, time synchronization, and device management.

Many of those tasks run as `SYSTEM` because they need operating system-level access. That is normal.

This tool deliberately flags privileged tasks anyway because privilege is still relevant. A privileged task may be legitimate, but it has more impact if misconfigured or abused. The auditor's job is not to declare guilt automatically. Its job is to create a short list for human review.

For an IT audience, the correct interpretation is:

> "Privilege is a risk signal, not proof of compromise."

## Why Last Modified Time Matters

The last modified timestamp tells us when the task definition was last changed. It does not prove when the task last ran, and it does not prove whether the task is still needed.

It is still useful because old task definitions can indicate:

- Legacy scripts nobody owns anymore.
- Startup tasks left behind by removed software.
- Maintenance jobs that were created for temporary use.
- Automation that has not been reviewed in a long time.

The script uses modification age as a triage signal. It helps decide what to review first.

## Why The Tool Is Read-Only

The auditor is designed to be safe. It does not disable tasks, delete files, change schedules, or edit permissions.

That is intentional. Scheduled tasks can be important. Disabling the wrong one can break updates, monitoring, backups, or business workflows. A good audit tool should identify risk first and leave remediation to a deliberate human decision.

## Technical Design

The script uses only Python standard libraries.

Important modules include:

- `argparse` for command-line options
- `datetime` for age calculations
- `glob` and `os` for filesystem scanning
- `json` for structured output
- `platform` to choose Linux or Windows behavior
- `subprocess` to call `systemctl` on Linux and PowerShell on Windows
- `shlex` to extract the first command token where possible

The code is organized into scanner functions:

- `scan_linux_cron()`
- `scan_linux_systemd_timers()`
- `scan_windows_scheduled_tasks()`
- `scan_all()`

Each scanner returns task dictionaries with a consistent structure. The flagging logic is handled separately by `add_flags()`, which keeps collection and risk scoring separate.

That separation makes the script easier to extend. For example, another scanner could be added later for macOS `launchd` jobs without rewriting the scoring or output logic.

## Linux Notes

Linux scheduled automation is split across several mechanisms.

Cron is older and commonly stores jobs in text files. System-level cron jobs often include a user field, while per-user crontabs usually do not. The script handles both formats.

The auditor also supports cron nickname schedules such as:

- `@reboot`
- `@hourly`
- `@daily`
- `@weekly`
- `@monthly`

systemd timers are newer and are managed through systemd unit files. The script uses `systemctl list-timers` to discover timers, then tries to inspect the timer unit and related service unit to find schedule and user information.

If a systemd service does not specify a `User=`, it generally runs as root. The script treats that as privileged.

## Windows Notes

Windows Scheduled Tasks are queried through PowerShell. The script uses `Get-ScheduledTask`, then converts the task data to JSON so Python can parse it cleanly.

For each task, the script tries to identify:

- Task path and name
- Action command
- Trigger type
- Principal user
- Run level
- Task definition file modification time

Windows run levels can be reported as `Limited` or `Highest`. Tasks running as `SYSTEM`, Administrator, or with the highest run level are treated as privileged.

## Limitations

This project is realistic about what it can and cannot know.

It does not prove a task is malicious.

It does not prove a task is safe.

It does not parse every possible cron or systemd syntax perfectly.

It may miss tasks the current user does not have permission to read.

It uses task definition modification time, not last execution time.

It does not inspect the contents of scripts launched by scheduled jobs.

It does not verify whether command paths still exist.

These limitations are acceptable for a first-pass auditor. The tool is meant to identify review candidates, not replace a full incident response investigation.

## Good Follow-Up Improvements

Useful future improvements would include:

- Add CSV output for spreadsheet review.
- Check whether referenced command paths exist.
- Hash task target scripts or executables.
- Report last run time where the platform exposes it reliably.
- Add macOS `launchd` support.
- Add allowlist support for known-good tasks.
- Add tests with sample cron, systemd, and Windows task fixtures.

## Naming Note

The project uses "Undertaker" as the memorable public name and `legacy_automation_auditor.py` as the explicit command-line script name. That keeps the branding distinct without making the terminal workflow cute or unclear.

## How To Explain This In An Interview

A concise explanation would be:

> "I built Undertaker, a Python audit tool that inventories scheduled automation across Linux and Windows. It looks for cron jobs, systemd timers, and Windows Scheduled Tasks, then flags tasks that are old, privileged, or both. The idea is to help identify forgotten background jobs that may create operational or security risk. It is read-only, produces both table and JSON output, and handles permission errors gracefully."

A more technical explanation would be:

> "The script separates collection from scoring. Platform-specific scanner functions normalize cron entries, systemd timers, and Windows Scheduled Tasks into a common task schema. A separate scoring function applies age and privilege rules, which makes the output consistent across operating systems and keeps the risk logic easy to change."

## Why This Is A Strong Portfolio Project

This is a practical security engineering project because it shows:

- Python scripting ability
- Cross-platform thinking
- Operating system knowledge
- Security triage logic
- Defensive tooling mindset
- Clean CLI design
- JSON output for automation
- Safe read-only behavior
- Awareness of limitations

It is not flashy for the sake of being flashy. It solves a real problem that administrators, security analysts, and engineers recognize: old automation is easy to forget and can quietly become risky.
