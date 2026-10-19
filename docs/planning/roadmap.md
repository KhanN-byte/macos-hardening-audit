# Roadmap

- Phase 0: decide prototype constraints, collect representative sanitized macOS Unified Logging samples, publish coverage matrix.
- Phase 1: single-process collector, parsers, normalized events, JSONL output, unit tests.
- Phase 2: threshold detection, bounded queue, deduplication, log rotation, health and metrics.
- Phase 3: unattended `launchd` deployment, failure recovery, on-device system tests.
- Phase 4 (optional): SQLite and centralized observability/exporters, only if usage justifies them.
