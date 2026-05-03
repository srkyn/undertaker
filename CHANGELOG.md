# Changelog

## v0.1.0 - Initial Public Release

Undertaker is ready as a first public release.

### Added

- Linux cron discovery for system crontabs, `/etc/cron.d`, user spool locations, and periodic cron directories.
- Linux systemd timer discovery through `systemctl list-timers`.
- Windows Scheduled Task discovery through PowerShell `Get-ScheduledTask`.
- Suspicion scoring for old task definitions and privileged execution contexts.
- High severity classification when a task is both old and privileged.
- Human-readable table output.
- JSON output with task details, flags, summary counts, and collection warnings.
- `--days`, `--output`, `--no-json`, `--only-suspicious`, and `--hide-windows-builtin` CLI options.
- Unit tests for scoring, cron parsing, nickname schedules, and Windows built-in filtering.
- GitHub Actions CI across Python 3.8 and 3.12.
- Installable CLI metadata through `pyproject.toml`.
- GitHub issue templates for bug reports and feature requests.
- Security policy for safe reporting expectations.

### Notes

- Undertaker is read-only. It does not disable, delete, or modify scheduled tasks.
- Findings are triage signals, not proof of compromise.
- Some task details may be unavailable without elevated permissions.
