# Unified Logging batch parser

`UnifiedLogParser` lives in Infrastructure and uses System.Text.Json. It maps exact, case-sensitive Apple keys to `UnifiedLogEntry`; `processID` maps to nullable `ProcessId`. Timestamp is required. Other modeled fields are optional; unknown fields are ignored. Time-sync events are accepted without authentication classification. Raw entries are never detection results.

Supported timestamp format: `yyyy-MM-dd HH:mm:ss.ffffff±HHmm`, matching the supplied transcript. Parsing uses invariant culture and preserves the offset. Missing offsets, invalid dates, and other fractional precision are rejected, never guessed or truncated. This is intentionally a narrow fixture-backed format.

Call `await new UnifiedLogParser().ParseBatchAsync(stream, cancellationToken)`. The caller owns the stream. Defaults are 4 MiB UTF-8 input and JSON depth 32, overridable through `UnifiedLogParserOptions`. Input is buffered and parsed as one document; memory usage includes both the buffer and document/model objects and is larger than the input-byte cap. Cancellation is observed on reads and between records; the bounded synchronous document parse itself is not interruptible.

Results distinguish Success, RecordErrors, and BatchFailure. Invalid individual records produce one diagnostic per rejected record with its zero-based index and an allowlisted field name. Valid entries retain order and duplicates. Missing/invalid timestamps, invalid property types, negative/out-of-range PIDs, and duplicate modeled keys reject the record. PID zero is valid. Empty arrays succeed. All-invalid arrays have RecordErrors. Invalid syntax, depth violations, and truncated JSON yield InvalidJson; incorrect roots yield InvalidRoot; byte-limit violations yield InputTooLarge. Batch failures return no partial entries. Depth errors intentionally share InvalidJson with syntax errors. Cancellation and I/O exceptions propagate.

Diagnostics do not contain raw values or exception messages. The parser emits no logs. Do not log or serialize entire raw entries in production diagnostics: messages and paths may be sensitive.

The input must be one complete JSON array. Command echoes, status text, comments, trailing commas, NDJSON, and incomplete streams are unsupported. Do not strip arbitrary prefixes to make malformed inputs appear valid. A future collector must separately validate live framing; asynchronous batch input does not imply incremental event delivery.

## Validation

Run from the repository root:

```sh
dotnet restore macOS_Hardening.slnx
dotnet build macOS_Hardening.slnx --no-restore -c Release
dotnet test macOS_Hardening.slnx --no-build --no-restore -c Release
```

To validate the fixture path specifically, append `--filter FullyQualifiedName~SanitizedCaptureMapsFieldsAndAllowsTimeSyncRecords` to the test command. Inspect the fixture and assertions together: two records must be accepted, the first PID is 42, the second lacks messageType, and the timestamp maps to 15:30 UTC with fractional seconds preserved. No live macOS collection or detection is performed.

## Optional record identity metadata

The parser maps `bootUUID` to nullable `Guid`, and `machTimestamp` and `threadID` to nullable `ulong`. Missing or explicit null fields remain null. UUID strings must use the hyphenated D format; unsigned integers must be JSON numbers in the UInt64 range. Invalid values reject the record with `InvalidFieldValue`; repeated modeled keys yield `DuplicateField`. Zero values are preserved, not treated as missing. These fields do not yet establish a unique identity or implement deduplication.
