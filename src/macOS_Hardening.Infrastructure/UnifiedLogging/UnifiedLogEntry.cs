// Holds selected raw Apple log fields before authentication classification.

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public sealed record UnifiedLogEntry
{
    public required DateTimeOffset Timestamp { get; init; }
    public int? ProcessId { get; init; }
    public string? Subsystem { get; init; }
    public string? Category { get; init; }
    public string? EventMessage { get; init; }
    public string? ProcessImagePath { get; init; }
    public string? MessageType { get; init; }
    public Guid? BootUuid { get; init; }
    public ulong? MachTimestamp { get; init;}
    public ulong? ThreadId { get; init;}

}
