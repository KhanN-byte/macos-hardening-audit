// Carries a normalized repeated-failure alert independently of collection and storage.

namespace macOS_Hardening.Contracts.Models;

public sealed record SecurityAlert
{
    public required AuthEventType EventType { get; init; }
    public required AlertSeverity Severity { get; init; }
    public required int AttemptCount { get; init; }
    public required DateTimeOffset WindowStart { get; init; }
    public required DateTimeOffset WindowEnd { get; init; }
    public required string Source { get; init; }
}
