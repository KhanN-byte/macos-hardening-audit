# Continuous collection, persistence, and alerting

## Implemented scope

The User worker orchestrates `UnifiedLogCollector` -> `UnifiedLogStreamReader` -> shared raw-record validation -> `ScreenUnlockFailureMapper` -> `UnifiedLogDeduplicator` -> `JsonlSecurityEventStore` -> `RepeatedFailureDetector`. Accepted failures produce structured logs and durable normalized records. Configurable Warning, Severe, and Critical alerts are persisted and logged when thresholds are reached within the detection window.

Monitoring stays disabled by default. The worker logs that state and never starts the collector. Enable only for a deliberate validation run. Configuration is read at startup; changes require restart.

## Observed framing and parsing contract

The supplied macOS live capture had a `Filtering the log data using "..."` status line on stdout followed by a multiline JSON array, containing three explicit failures and six companion messages. Stderr was empty. The stream reader accepts this one optional bounded banner or a bare array. It does not split records by newline or strip arbitrary non-JSON text.

Completed objects are validated and delivered without waiting for the final array bracket. String escaping, nested structures, and split UTF-8 reads are handled; System.Text.Json validates completed objects. Semantic record errors are reported and processing continues. Invalid framing, malformed object JSON, depth/size violations, and an incomplete array at EOF interrupt collection and cause a restart. Already emitted records cannot be rolled back if later input is truncated. Batch parser behavior remains unchanged.

Live output can contain an empty `bootUUID`. The parser treats an empty value as unavailable while continuing to reject malformed nonempty UUIDs. Before delivery, the live collector fills a missing value from macOS `kern.bootsessionuuid`, read once through `/usr/sbin/sysctl`. A lookup failure interrupts collection rather than allowing records with unreliable deduplication identity. Historical records that already contain a boot UUID are preserved.

Records must be JSON objects. Alternative formats, NDJSON, and primitive array elements are unsupported. Timestamp support remains the fixture-backed six-fractional-digit compact-offset format. Per-connection diagnostic indexes wrap after Int32.MaxValue and are not record identities.

## Process lifecycle and limits

The native adapter requires macOS and runs the configured executable directly with ProcessStartInfo.ArgumentList (no shell): `stream --style json --level info --predicate <configured predicate>`. Tests use a small process interface to simulate streams; no extra packages are needed.

Stdout and stderr are read concurrently. Raw stderr is never logged or accumulated; the first stderr chunk in each connection produces a warning while remaining chunks are drained. Stream records and collection notifications use a bounded channel with wait/backpressure, not silent application-level drops. Backpressure can still lead to upstream OS loss; completeness is not guaranteed.

Unexpected exits, even exit code zero, and supported collection failures trigger exponential restart delays capped by configuration. Stable runs reset the delay. Cancellation interrupts reads, queued writes, and restart waits. Stopping or abandoning enumeration disposes the child process; the native adapter kills a remaining child process tree and waits within the shutdown deadline. If cleanup cannot be confirmed, the collector fails the worker instead of starting overlapping children.

No heartbeat is inferred from quiet logs. A process-start message does not prove healthy coverage. Interruptions warn of potential loss. There is no historical replay/backfill in Phase 3, so records during gaps can be lost. Failure identity unavailable produces an explicit warning and the failure is excluded from accepted-event processing.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| Monitoring:Enabled | false | Explicit collection opt-in |
| Monitoring:DeduplicationRetentionSeconds | 600 | First-acceptance retention window |
| Monitoring:DeduplicationCapacity | 10000 | Maximum remembered keys |
| Monitoring:FailedAttemptsThreshold | 3 | Warning threshold |
| Monitoring:SevereAttemptsThreshold | 5 | Severe threshold |
| Monitoring:CriticalAttemptsThreshold | 10 | Critical threshold |
| Monitoring:DetectionWindowMinutes | 5 | Sliding event-time detection window |
| Monitoring:AlertCooldownMinutes | 5 | Repeated-alert suppression period |
| Storage:Directory | ./data | JSONL directory relative to the User content root |
| Storage:RetentionDays | 7 | Stored-file retention applied at startup |
| Storage:MaxFileBytes | 10485760 | Maximum target size before file rotation |
| Collection:ExecutablePath | /usr/bin/log | Absolute native executable path |
| Collection:Predicate | eventMessage CONTAINS "authFailWithMessage:" | Validated investigation scope |
| Collection:BufferCapacity | 128 | Queued records/notifications |
| Collection:MaxRecordBytes | 262144 | Per-object UTF-8 cap |
| Collection:MaxDepth | 32 | Nesting cap inside each object |
| Collection:InitialRestartSeconds | 1 | Initial delay after interruption |
| Collection:MaxRestartSeconds | 30 | Maximum delay |
| Collection:StableRunSeconds | 60 | Run duration that resets backoff |
| Collection:ShutdownSeconds | 5 | Child shutdown/drain deadline |

The preamble limit is 4096 bytes. Limits are validated before collection. Deduplication is shared across reconnections within this worker run, but expires or evicts records and is cleared on application restart. Recent normalized events and the latest alert are recovered from JSONL storage so detector window and cooldown behavior survive restart. Replay identities themselves are not persisted.

Storage files rotate by UTC date and configured size. On Unix, the directory is owner-only (`0700`) and files are owner-readable/writable (`0600`). Retention removes only expired files matching the application's filename pattern. Malformed lines are counted and ignored during recovery; valid lines remain usable. Raw Unified Logging messages are not stored in the normalized event or alert records.

## Automated verification

From the repository root:

```sh
dotnet build macOS_Hardening.slnx --no-restore -c Release
dotnet test macOS_Hardening.slnx --no-build --no-restore -c Release
```

Focused tests cover fragmented streams and early delivery, banner handling, escaping, invalid/truncated JSON, byte/depth limits, record rejection, stderr draining and failure, capped backoff and reset, queue-full cancellation, fatal cleanup failure, disabled monitoring, worker mapping/deduplication, detector thresholds and cooldown, restart restoration, JSONL recovery, malformed records, rotation, and retention. All process test data is synthetic; no actual credentials or device identifiers are stored.

## Manual acceptance on your Mac

1. Run with defaults and confirm the disabled message. Stop with Ctrl+C.
2. Start an enabled validation run:

   ```sh
   dotnet run --project src/macOS_Hardening.User -c Release --no-build -- --Monitoring:Enabled=true
   ```

3. Lock your screen, enter controlled incorrect passwords, then unlock correctly. Confirm one `Authentication failure observed` message per attempt. When a configured threshold is reached, confirm the corresponding Warning, Severe, or Critical alert contains the expected count and window. Companion UI messages should produce no additional failures. Confirm timestamps match the controlled attempts. Success/Touch ID/SSH detection is not implemented.
4. Press Ctrl+C. Confirm the monitoring-stopped message and process exit. No collector child should remain.
5. Inspect the configured storage directory. Confirm JSONL event and alert records exist and contain normalized fields rather than raw log messages.
6. Optionally verify visible start failures without changing saved configuration:

   ```sh
   dotnet run --project src/macOS_Hardening.User -c Release --no-build -- --Monitoring:Enabled=true --Collection:ExecutablePath=/nonexistent/log
   ```

   Confirm interruption warnings with increasing, capped delays, then Ctrl+C. Do not expect authentication events during this test.

Automation confirmed native startup and shutdown in both modes. The project owner validated live Warning, Severe, and Critical escalation from controlled failed screen-unlock attempts on macOS 26.2 ARM64. This does not prove native CLI timing or authentication coverage on every macOS version.
