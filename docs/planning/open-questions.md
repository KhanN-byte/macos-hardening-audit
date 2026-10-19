# Open questions — resolve before functional implementation

These are intentionally unresolved; record accepted answers in ADRs and issue milestones.

| ID | Question | Initial recommendation | Priority |
| --- | --- | --- | --- |
| Q01 | Which exact macOS versions, architectures and devices? | Start with current supported Apple Silicon macOS; define minimum version after testing | Blocker |
| Q02 | What qualifies as a 'failed login': console loginwindow, unlock, SSH, sudo, screensaver, FileVault, Touch ID? | Start with explicitly validated console password logins; split other mechanisms | Blocker |
| Q03 | Can macOS Unified Logging reliably reveal each required failure without private-data access? | Validate with manually generated test events and record coverage | Blocker |
| Q04 | Is this single-device local-only, or multi-device remote fleet? | MVP local-first; design contracts for future remote ingestion | Blocker |
| Q05 | Should collection run as user LaunchAgent or privileged LaunchDaemon? | Least privilege validated on-device; avoid root unless strictly needed | Blocker |
| Q06 | What is the evidence model when fields are private/redacted/missing? | Unknown fields remain null; add confidence and source metadata | Blocker |
| Q07 | How should streaming reconnect + historical backfill avoid missed/duplicate events? | Durable watermark, overlap replay, stable fingerprint with explicit uncertainty | High |
| Q08 | Is JSON format stable enough and are `log show` and `log stream` consistent? | Test exact output on supported versions before parser design | Blocker |
| Q09 | What are data retention, encryption, identities and privacy constraints? | Minimize, encrypt sensitive local storage, configurable retention | High |
| Q10 | What detection thresholds and alert cooldowns should ship? | Configurable and conservative; documented false-positive behavior | High |
| Q11 | Where are logs, metrics and traces exported? | Local first, opt-in remote future OpenTelemetry exports | High |
| Q12 | Offline operation: how large can disk queue grow and what on exhaustion? | Bounded queue, explicit degradation, never silently drop | High |
| Q13 | Who receives alerts and through which channels? | Local audit initially; remote notification later | Medium |
| Q14 | How is installed binary signed, notarized, upgraded and uninstalled? | Document `launchd` launch lifecycle and permissions before releases | High |
| Q15 | What performance, battery and memory budgets are acceptable? | Establish baselines on a real Mac and enforce regression tests | High |
| Q16 | How will actual system tests avoid recording personal credentials? | Dedicated test account, synthetic fixtures in repo, sanitize captured evidence | Blocker |
| Q17 | Will project be OSS-only or offer production support guarantees? | OSS with clear limitations; do not market as full audit coverage | Medium |
| Q18 | Is FileVault preboot authentication explicitly out of scope? | Treat as unsupported until proven visible after boot | High |
| Q19 | How do we establish log time, ordering, clock jumps and reboot boundaries? | UTC normalization with observed ingest timestamp and boot/session info | High |
| Q20 | What should happen when no macOS source is usable? | Unsupported/unhealthy state with clear remediation, no misleading green status | Blocker |
