# Changelog

## v0.3.1 - CLI Correctness

### Fixed

- Kept JSON stdout clean when `--format json` also writes a JSON file.
- Recognized domain-qualified Windows privileged accounts such as `NT AUTHORITY\SYSTEM`.
- Moved the allowlist example explanation into a `_comment` field instead of an allowlist entry.

## v0.3.0 - Triage Depth

### Added

- `risk_reasons` field for clearer JSON explanations.
- `--allowlist` support for suppressing known-good scheduled jobs.
- Example allowlist file.
- Windows `last_run_time` and `last_task_result` fields when available.
- Fixture-based cron and systemd parser tests.

## v0.2.0 - Pipeline And Verification Improvements

### Added

- `--format json` for structured stdout output.
- `--check-paths` to optionally check whether extracted command paths appear to exist.
- Shared JSON payload builder for file and stdout output.
- `missing_command_path` flag when `--check-paths` finds a missing command path.
- Path existence status in table output when `--check-paths` is enabled.
- Additional parser tests for system cron, systemd timers, systemd service users, path checks, and JSON payload summaries.

## v0.1.1 - Polish Release

### Added

- `--version` CLI option.
- README trust signals for release, CI, Python version, and license.
- README summary of JSON output fields.
- CI check for the installed CLI version command.

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
