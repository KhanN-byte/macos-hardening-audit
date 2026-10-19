# Prototype architecture

One .NET Worker Service process hosted by `macOS_Hardening.User`, organized into four existing projects:

| Project | Responsibilities | Project references |
| --- | --- | --- |
| User | Program, dependency composition, background workers, configuration | Core, Infrastructure |
| Core | Security detection, domain logic and domain models | Contracts |
| Contracts | Normalized security event contracts | None |
| Infrastructure | Unified Logging collection, raw log models, parsing, persistence | Contracts |

`Program.cs` registers `AuthenticationWorker`, which logs startup, waits for cancellation, and logs shutdown. `Infrastructure/UnifiedLogging/UnifiedLogEntry.cs` holds the existing raw Apple log record model with validated timestamps and nullable process IDs. The Infrastructure batch parser validates bounded JSON arrays and returns raw entries with safe diagnostics. No collector, detector, or persistence implementation exists yet. See [parser behavior](../testing/unified-log-parser.md). Empty responsibility folders are retained with `.gitkeep`; no speculative contracts or abstractions are introduced.

Intended future flow:

`macOS log CLI -> Infrastructure collector/parser -> Contracts events -> Core detection -> Infrastructure persistence`

User will compose and orchestrate these components. Core must not depend on platform collection or storage. Contracts must remain independent of raw Apple log schemas. Structured logging and observability will use the existing hosting facilities and standard-library APIs.

Only supported event patterns should become classified authentication events. Unknown/redacted entries must remain distinguishable. Collection liveness is independent from login failure count. Failed screen-unlock password events were validated by the project owner on macOS 26.2 (ARM64); other authentication paths require separate validation.

Future, **not implemented**: collection, security-event normalization, detection, JSONL persistence, bounded channels, and metrics. Durable event queues, SQLite, OTLP, Grafana, and launchd remain outside this reorganization.
