// Configures process collection, buffering, and bounded restart delays.

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public sealed class UnifiedLogCollectionOptions
{
    public string ExecutablePath { get; set; } = "/usr/bin/log";
    public string Predicate { get; set; } = "eventMessage CONTAINS \"authFailWithMessage:\"";
    public int BufferCapacity { get; set; } = 128;
    public int MaxRecordBytes { get; set; } = 262144;
    public int MaxDepth { get; set; } = 32;
    public int InitialRestartSeconds { get; set; } = 1;
    public int MaxRestartSeconds { get; set; } = 30;
    public int StableRunSeconds { get; set; } = 60;
    public int ShutdownSeconds { get; set; } = 5;

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(ExecutablePath) || !Path.IsPathFullyQualified(ExecutablePath))
            throw new ArgumentException("Collection executable must be an absolute path.");
        if (string.IsNullOrWhiteSpace(Predicate) || Predicate.Length > 4096)
            throw new ArgumentException("Collection predicate must contain 1 to 4096 characters.");
        if (BufferCapacity is < 1 or > 4096 || MaxRecordBytes is < 256 or > 4194304 ||
            MaxDepth is < 1 or > 128 || InitialRestartSeconds < 1 ||
            MaxRestartSeconds < InitialRestartSeconds || MaxRestartSeconds > 3600 ||
            StableRunSeconds is < 1 or > 86400 || ShutdownSeconds is < 1 or > 60)
            throw new ArgumentOutOfRangeException(nameof(UnifiedLogCollectionOptions), "Invalid collection limits.");
    }
}
