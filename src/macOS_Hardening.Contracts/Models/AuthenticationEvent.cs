// Carries a normalized authentication event independently of Apple log formats.

namespace macOS_Hardening.Contracts.Models;

public sealed record AuthenticationEvent
{
    public required DateTimeOffset Timestamp { get; init;}

    public required AuthEventType EventType { get; init;}

    public required string Source { get; init;}

}
