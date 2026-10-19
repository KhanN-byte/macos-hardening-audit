# macos-hardening-audit

A local-first macOS authentication monitoring prototype written in C#/.NET 10, built around Apple Unified Logging.

**Status: early prototype.** Parsing, failure classification, and replay deduplication are implemented as library components. The worker does not yet collect logs or connect these components into a monitoring pipeline. This project does not currently harden macOS, provide continuous auditing, or send security alerts.

## Current functionality

- **Batch parsing:** `UnifiedLogParser` reads JSON arrays from UTF-8 streams, validates timestamps and known fields, and returns structured batch/record diagnostics without including raw log values. Input size and nesting depth are bounded (defaults: 4 MiB and 32 levels).
- **Failure classification:** `ScreenUnlockFailureMapper` recognizes an exact `loginwindow` message, subsystem, and process path for failed screen-unlock passwords and produces a normalized `AuthenticationEvent`. Other records are ignored.
- **Replay identity:** `UnifiedLogRecordKey` builds deterministic SHA-256 keys from boot UUID, Mach timestamp, process ID, thread ID, and event message. Incomplete identity data produces no key.
- **Bounded deduplication:** `UnifiedLogDeduplicator` tracks keys in memory with retention expiry and capacity eviction, distinguishing accepted records, duplicates, and unavailable identity.
- **Worker host:** `AuthenticationWorker` logs startup, waits for cancellation, and logs shutdown.
- **Tests:** xUnit tests exercise parsing, classification, record keys, deduplication using synthetic/sanitized fixtures.

Live collection through the native `log` CLI, pipeline integration, JSON Lines persistence, retention on disk, alerting, health reporting, and unattended deployment remain planned.

## Build and test

Requires the **.NET 10 SDK**. The solution and unit tests can run without macOS log access; future live collection requires macOS.

```bash
dotnet restore macOS_Hardening.slnx
dotnet build macOS_Hardening.slnx --no-restore --configuration Release
dotnet test macOS_Hardening.slnx --no-build --configuration Release
```

The GitHub Actions workflow runs these checks on Ubuntu. Build warnings are treated as errors.

To run the current worker shell (stop with Ctrl+C):

```bash
dotnet run --project src/macOS_Hardening.User/macOS_Hardening.User.csproj
```

This starts the host only; it does not begin collecting authentication events.

## Project layout

- `src/macOS_Hardening.User/` — worker host and configuration.
- `src/macOS_Hardening.Contracts/` — normalized authentication event contracts.
- `src/macOS_Hardening.Infrastructure/` — Unified Logging parser, mapper, record keys, and deduplicator.
- `src/macOS_Hardening.Core/` — reserved domain/detection layer.
- `tests/macOS_Hardening.UnitTests/` — unit tests.
- `samples/fixtures/` — synthetic and sanitized log examples.
- `docs/` — architecture, decisions, validation guidance, and planned work.
- `deploy/launchd/` — future deployment notes.

## Coverage and limitations

The project owner reports validation of failed screen-unlock password events on macOS 26.2 (ARM64). This does not establish coverage for other authentication paths or macOS versions. The mapper recognizes one exact signature, and the deduplication cache is lost on restart.

**No events seen does not imply no failed login attempts.** macOS may omit or redact records. Event availability, privilege requirements, and supported authentication paths require empirical validation.

See [parser behavior](docs/testing/unified-log-parser.md), [macOS log validation](docs/testing/macOS-log-validation.md), and [prototype scope](docs/planning/prototype-scope.md). Do not commit raw security logs or identifying data; see [contributing](CONTRIBUTING.md) and [security policy](SECURITY.md).

Licensed under the [MIT License](LICENSE).
