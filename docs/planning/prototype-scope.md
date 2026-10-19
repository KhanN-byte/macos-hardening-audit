# Prototype scope and constraints

## Fixed decisions

- Name: `macOS_Hardening`; path: `CodeDevelopment/CSharpApp/macOS_Hardening`.
- Data source: Apple Unified Logging via built-in `log` executable, **no** Endpoint Security API.
- Local-first, single macOS endpoint; no collector server or cloud dependency.
- .NET 10 Worker Service host with Core, Contracts, and Infrastructure class libraries and one xUnit test project.
- Built-in logging, metrics, JSON serialization, process control; JSONL local event output.
- Run manually during MVP investigation; launchd deployment is later.

## Out of scope for first prototype

- Grafana, Loki, Prometheus, OTLP exporter, Docker, SQLite, remote alerts, GUI, native bridges.
- Claims of complete event capture; remediation/blocking; fleet management.

## Validation gates before implementation

1. Inventory macOS releases and authentication scenarios to support.
2. Collect sanitized test records for console failures and at least one negative/unsupported example.
3. Verify JSON record boundaries and representative metadata from `log show`/`log stream`.
4. Document permission requirements and actual effects of privacy redaction.
5. Choose stream versus bounded polling, and a recoverable checkpoint policy.
6. Define how data gaps, duplicate entries, log rotation, and time anomalies are represented.
7. Decide where JSONL output goes and document file permissions/rotation/retention.

## Prototype acceptance criteria

- Collect and parse tested event patterns without silently treating unknown data as failures.
- Detection tested with synthetic failures and cooldown/deduplication.
- Collector restarts and reports degraded health on failures.
- Bounded memory and log retention; cancellation and shutdown supported.
- Clear known-limitations and coverage matrix published for each tested macOS release.
