# Security Policy

Undertaker is a read-only audit tool. It inventories scheduled automation and reports review signals; it should not modify, disable, or delete scheduled jobs.

## Supported Versions

Security fixes are handled on the latest released version.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting A Security Issue

Please open a private security advisory on GitHub if you find a vulnerability in Undertaker itself.

Do not include secrets, private task definitions, internal hostnames, or sensitive command output in public issues.

## Scope

In scope:

- Unsafe behavior in the tool itself.
- Incorrect handling of task data that could expose sensitive information beyond the local user's permissions.
- Bugs that could cause the tool to modify the host unexpectedly.

Out of scope:

- A scheduled task on your own system being flagged as suspicious.
- Platform permission errors when the current user cannot read protected task definitions.
- Requests to identify whether a specific scheduled task is malicious without supporting evidence.

