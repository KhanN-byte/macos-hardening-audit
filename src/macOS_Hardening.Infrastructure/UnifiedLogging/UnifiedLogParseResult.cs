// Describes batch outcomes and diagnostics without including raw log values.

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public enum UnifiedLogParseStatus { Success, RecordErrors, BatchFailure }

public enum UnifiedLogParseError
{
    InvalidJson, InvalidRoot, InputTooLarge, InvalidRecord,
    DuplicateField, MissingTimestamp, InvalidTimestamp, InvalidFieldType, InvalidProcessId,
    InvalidFieldValue
}

// Field names are allowlisted; diagnostics never include raw values or exception messages.
public sealed record UnifiedLogParseDiagnostic(
    UnifiedLogParseError Code, int? RecordIndex = null, string? Field = null);

public sealed record UnifiedLogParseResult(
    UnifiedLogParseStatus Status,
    IReadOnlyList<UnifiedLogEntry> Entries,
    IReadOnlyList<UnifiedLogParseDiagnostic> Diagnostics);
