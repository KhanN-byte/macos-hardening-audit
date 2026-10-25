# macos-hardening-audit

A local-first macOS authentication monitoring prototype written in C#/.NET 10, built around Apple Unified Logging.

**Status: prototype in development.** Opt-in continuous collection connects parsing, failure classification, replay deduplication, local JSONL persistence, and repeated-failure alerts in the User worker. This project monitors one validated authentication signal; it does not change or harden macOS settings.

## Current functionality

- **Batch parsing:** `UnifiedLogParser` reads JSON arrays from UTF-8 streams, validates timestamps and known fields, and returns structured batch/record diagnostics without including raw log values. Input size and nesting depth are bounded (defaults: 4 MiB and 32 levels).
- **Failure classification:** `ScreenUnlockFailureMapper` recognizes an exact `loginwindow` message, subsystem, and process path for failed screen-unlock passwords and produces a normalized `AuthenticationEvent`. Other records are ignored.
- **Replay identity:** `UnifiedLogRecordKey` builds deterministic SHA-256 keys from boot UUID, Mach timestamp, process ID, thread ID, and event message. Incomplete identity data produces no key.
- **Bounded deduplication:** `UnifiedLogDeduplicator` tracks keys in memory with retention expiry and capacity eviction, distinguishing accepted records, duplicates, and unavailable identity.
- **Continuous collection:** A native process adapter runs `log stream` without a shell. An incremental reader handles the observed banner and JSON array, with bounded records and buffering, concurrent stderr draining, capped restart delays, and child-process cleanup.
- **Local persistence:** Normalized authentication events and generated alerts are written to rotating JSON Lines files with retention, restart recovery, and owner-only Unix permissions.
- **Repeated-failure detection:** Core applies configurable Warning, Severe, and Critical thresholds within an event-time window, including cooldown suppression and severity escalation.
- **Worker host:** `AuthenticationWorker` respects the monitoring opt-in and connects collection, mapping, deduplication, persistence, detection, and structured logging.
- **Tests:** xUnit tests exercise parsing, classification, record keys, deduplication, streaming, collector lifecycle, and worker integration using synthetic/sanitized data.

Full health metrics and unattended deployment remain planned. Restart gaps are reported but not backfilled.

## Build and test

Requires the **.NET 10 SDK**. The solution and unit tests can run without macOS log access; live collection requires macOS.

```bash
dotnet restore macOS_Hardening.slnx
dotnet build macOS_Hardening.slnx --no-restore --configuration Release
dotnet test macOS_Hardening.slnx --no-build --configuration Release
```

The GitHub Actions workflow runs these checks on Ubuntu. Build warnings are treated as errors.

To run the host with monitoring disabled by default (stop with Ctrl+C):

```bash
dotnet run --project src/macOS_Hardening.User/macOS_Hardening.User.csproj
```

To opt into continuous collection for a manual validation run:

```bash
dotnet run --project src/macOS_Hardening.User -c Release -- --Monitoring:Enabled=true
```

Follow the [continuous collection and alert verification guide](docs/testing/continuous-collection.md). Do not equate an idle or started process with complete authentication coverage.

## Project layout

- `src/macOS_Hardening.User/` — worker host and configuration.
- `src/macOS_Hardening.Contracts/` — normalized authentication event contracts.
- `src/macOS_Hardening.Infrastructure/` — Unified Logging collector, parser, mapper, record keys, and deduplicator.
- `src/macOS_Hardening.Core/` — repeated-failure detection and domain logic.
- `tests/macOS_Hardening.UnitTests/` — unit tests.
- `samples/fixtures/` — synthetic and sanitized log examples.
- `docs/` — architecture, decisions, validation guidance, and planned work.
- `deploy/launchd/` — future deployment notes.

## Coverage and limitations

The project owner reports validation of failed screen-unlock password events on macOS 26.2 (ARM64). This does not establish coverage for other authentication paths or macOS versions. The mapper recognizes one exact signature, and the deduplication cache is lost on restart.

**No events seen does not imply no failed login attempts.** macOS may omit or redact records. Event availability, privilege requirements, and supported authentication paths require empirical validation.

See [parser behavior](docs/testing/unified-log-parser.md), [macOS log validation](docs/testing/macOS-log-validation.md), and [prototype scope](docs/planning/prototype-scope.md). Do not commit raw security logs or identifying data; see [contributing](CONTRIBUTING.md) and [security policy](SECURITY.md).

Licensed under the [MIT License](LICENSE).
