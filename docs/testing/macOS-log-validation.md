# macOS Unified Logging feasibility test plan

**No live capture data belongs in this repository.** Conduct tests only on Macs/accounts you own or are authorized to administer.

1. Record macOS version/build, architecture, permission context, and whether log tooling is available.
2. Start with historical discovery: `log show --last 10m --style json --info --predicate 'process == "loginwindow" OR process == "SecurityAgent"'`.
3. Run a controlled failed login against a dedicated test account and compare before/after logs. Do not place passwords in terminal commands or fixtures.
4. Run a separate unlock test. Do not assume same source or semantics.
5. Only after evidence supports it, try `log stream --style json --level info --predicate 'process == "loginwindow" OR process == "SecurityAgent"'` while generating another controlled failure.
6. Check stdout/stderr, JSON shape, timestamps, process/category names, privacy placeholders, available username, and whether events persist in `log show`.
7. Repeat as least-privileged user and elevated context if authorized; document differences.
8. Repeat on other supported OS versions and on sleep/wake/reboot.
9. Keep a coverage matrix: observed / absent / redacted / ambiguous / not tested. Only **sanitized, synthetic** equivalents may become repository fixtures.

## Caveat

Predicates above are exploratory. Actual macOS failure records may originate from other processes, be private, or not be emitted at all. Discovery should include alternative predicates and bounded exploratory searches, not rely solely on these examples.

## Exit gate

Do not implement or advertise a failed-login alert until at least one event type has repeatable, testable evidence, a documented parser contract and an explicit false-negative/coverage statement.
