// Carries raw records or safe collection diagnostics without exposing stderr payloads.

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public enum UnifiedLogCollectionKind { ProcessStarted, Record, RecordRejected, StandardError, RestartScheduled }

public sealed record UnifiedLogCollectionItem(
    UnifiedLogCollectionKind Kind,
    UnifiedLogEntry? Entry = null,
    UnifiedLogParseDiagnostic? Diagnostic = null,
    int? ExitCode = null,
    string? FailureType = null,
    TimeSpan? RestartDelay = null);
