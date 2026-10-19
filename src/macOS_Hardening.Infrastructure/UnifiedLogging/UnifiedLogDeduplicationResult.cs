namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public enum UnifiedLogDeduplicationResult
{
    IdentityUnavailable = 0,
    Accepted = 1,
    Duplicate = 2
}
