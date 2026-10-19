# Unified Logging parser fixtures

`sanitized-batch.json` is a transformed derivative of two complete objects from the project owner's supplied `log show --style json` transcript: one ordinary log event and one time-sync event. The original transcript has command/status text before the array and an incomplete final record. It is not stored here, and recovery of incomplete transcripts is not parser behavior.

Keys, nesting, nulls, empty strings, and value types are retained. Dates, identifiers, nonempty paths, subsystem/category names, and messages are replaced with synthetic values. Standard event/message type labels are retained. These are sanitized derivatives, not verbatim captures or evidence of failed-unlock detection. The file's timestamp has the observed six-digit fraction and compact numeric offset. OS/version provenance is the owner's stated macOS 26.2 ARM64 baseline, not independently verified from this transcript.

Additional malformed and boundary cases in unit tests are explicitly synthetic. Never add raw captures, credentials, account names, or device identifiers.

## Synthetic failed-unlock mapping fixture

`synthetic-unlock-batch.json` is synthetic test data based on the three message patterns previously inspected in the owner's controlled capture. It is not an authentic or sanitized capture: the original Desktop file had been overwritten with an empty array when these tests were added. Dates and spacing between records are invented. The known system process path, subsystem, category, message type, and observed message texts are retained. No user/device identifiers are included.

The scenario models five incorrect password attempts, each represented by one explicit failure marker and two companion UI messages. Expected output: five normalized failure events and ten ignored records. This does not validate successful unlocks, live capture coverage, or replay deduplication. Other mapper unit inputs are also synthetic.

Run `dotnet test macOS_Hardening.slnx -c Release --filter FullyQualifiedName~ScreenUnlockFailureMapperTests` from the repository root to exercise the mapper tests.
