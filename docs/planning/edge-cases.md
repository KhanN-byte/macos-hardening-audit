# Edge-case register

| Case | Risk | Planned handling/test |
| --- | --- | --- |
| Login failure produces no unified log entry | False-negative monitoring | Explicit source-coverage matrix, unsupported event types |
| Private/redacted fields | Incorrect attribution | Null fields, no guessing, dedicated unknown classification |
| Record wording differs per OS release | Broken parsing | Versioned parser fixtures, diagnostics for unknown patterns |
| `log` tool exits or hangs | Monitoring blind spot | Watchdog, bounded restart backoff, health alert |
| Invalid JSON / multiline output / large message | Parser failure | Incremental parsing, size limit, dead-letter aggregate counters |
| stderr flood or child process deadlock | Collection stalls | Drain stderr concurrently; bounded buffers |
| User crash / Mac sleep or reboot | Time gaps | Persist checkpoint, replay bounded window, report coverage gap |
| Stream-to-replay overlap | Duplicate alerts | Stable event fingerprint where possible + bounded dedupe |
| Two events with same timestamp | Lost events under watermark | Timestamp plus source cursor/fingerprint, overlap replay |
| Clock rollback / timezone change | Incorrect alert windows | UTC timestamps, monotonic durations where applicable |
| Very large historical log query | CPU / memory / battery surge | Bounded replay, cancellation, batch budget |
| Unified log retention purges old entries | Irrecoverable data gaps | Gap marker and report; no promise of guaranteed reconstruction |
| Wrong permissions or missing `log` executable | Silent zero events | Fail health readiness; diagnostic permissions path |
| Malicious/untrusted log strings | Injection into dashboards | Treat strings as data; structured encoding, length caps |
| Attacker repeatedly triggers failures | Memory growth / alert flood | Bounded key cardinality, TTL, cooldown, rate limiting |
| Common/unknown usernames | Misleading user-specific detections | Source-aware aggregation and privacy filtering |
| SSH, sudo, unlock mixed with console login | False positives | Distinct event types and explicit source provenance |
| Disk full / readonly store | Lost checkpoints | Backpressure + explicit degraded mode and counters |
| Collector running twice | Duplicate events | Single-instance process policy and lease/lock |
| macOS log permissions change after OS update | Sudden blindness | Startup and ongoing capability self-test |
| Remote telemetry destination unavailable | Unbounded retries | Offline local-first buffering and bounded export policy |
| High-cardinality labels | Telemetry backend overload | No user/device IDs as metrics tags |
| Mac sleeps and wakes | Misleading availability alerts | Sleep-aware uptime and gap classification |
| Events arrive out-of-order | Wrong detection windows | Event-time tolerant windows, late-event policy |
| Configuration corrupted | User cannot start | Validate at startup, fail with explicit status |
| Unexpected secret in raw log | Privacy leakage | No raw payload telemetry by default; redact before persistence |
