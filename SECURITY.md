# Security policy

This project is a security monitoring research/engineering tool, **not** a security enforcement mechanism. Collection may be incomplete due to OS version, privacy redaction, retention limits, log configuration, permissions and event source behavior.

## Reporting vulnerabilities

Until a maintainer security contact is published, do not disclose sensitive exploit details in public issues. Use GitHub's private vulnerability reporting feature after the repository is configured, or contact the maintainer privately.

## Data handling requirements

- Do not upload raw macOS Unified Logging captures or real account names as issues, fixtures or telemetry examples.
- Avoid passwords, tokens, personal identifiers and secrets in logs, tags or exceptions.
- Pseudonymize device/user identity for any central export; define retention/deletion limits.
- Fail visibly when log collection is unhealthy. Never imply an absence of events proves safety.
- Consider shell injection risk: prefer fixed executable path and argument lists over invoking a shell.
- Treat captured log text as untrusted data.
