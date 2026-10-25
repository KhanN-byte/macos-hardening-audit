# Prototype architecture

One .NET Worker Service process hosted by `macOS_Hardening.User`, organized into four existing projects:

| Project | Responsibilities | Project references |
| --- | --- | --- |
| User | Program, dependency composition, background workers, configuration | Core, Infrastructure |
| Core | Security detection, domain logic and domain models | Contracts |
| Contracts | Normalized security event contracts | None |
| Infrastructure | Unified Logging collection, raw log models, parsing, persistence | Contracts |

`Program.cs` configures an opt-in `AuthenticationWorker`. Infrastructure owns a native process adapter, bounded collector with restart backoff, an incremental reader for the observed live JSON array framing, and local JSONL storage. The stream reader and batch parser share raw-record validation. The worker maps supported failures, suppresses replayed records, persists normalized events, and passes them to Core for repeated-failure detection.

Current flow:

`macOS log stream -> bounded Infrastructure collector/parser -> failure mapper -> deduplicator -> JSONL persistence -> Core detector -> structured alert logging`

The User project owns composition and lifecycle. Contracts remain independent of Apple JSON. Core does not depend on collection or storage. The deduplicator is retained across connections but only in memory. Recent normalized events and the latest alert are recovered from storage after restart so the detector retains its active window and cooldown. Collection interruption is reported separately from authentication failures.

See [batch parsing](../testing/unified-log-parser.md) and [continuous collection configuration and verification](../testing/continuous-collection.md).

Only supported event patterns should become classified authentication events. Unknown/redacted entries must remain distinguishable. Collection liveness is independent from login failure count. Failed screen-unlock password events were validated by the project owner on macOS 26.2 (ARM64); other authentication paths require separate validation.

Future work includes collection health metrics and launchd deployment. Historical backfill, durable event queues, SQLite, OTLP, Grafana, and centralized exporters remain outside the current prototype.
