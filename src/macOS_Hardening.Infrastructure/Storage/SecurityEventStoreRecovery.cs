// Reports usable persisted state and malformed records found during recovery.

using macOS_Hardening.Contracts.Models;

namespace macOS_Hardening.Infrastructure.Storage;

public sealed record SecurityEventStoreRecovery(
    IReadOnlyList<AuthenticationEvent> Events,
    SecurityAlert? LatestAlert,
    int MalformedRecordCount);
