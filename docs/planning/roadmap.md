# Roadmap

- Phase 0 — complete: establish the repository structure, prototype constraints, sanitized fixtures, and documented coverage limits.
- Phase 1 — complete: parse bounded Unified Logging JSON and normalize validated screen-unlock password failures.
- Phase 2 — complete: create deterministic record identities and bounded in-memory replay deduplication.
- Phase 3 — complete: collect continuously from `log stream` with bounded framing, diagnostics, restart backoff, and process cleanup.
- Phase 4 — complete: persist normalized events and alerts locally, restore recent detector state, and generate configurable Warning, Severe, and Critical alerts.
- Phase 5 — planned: add explicit collection health and local operational observability without introducing external monitoring services.
- Phase 6 — planned: validate and package unattended `launchd` deployment, including sleep/wake and restart behavior.
- Optional later work: evaluate SQLite or centralized exporters only if prototype usage justifies the added dependencies.
