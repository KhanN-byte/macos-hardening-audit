// Controls monitoring opt-in and the lifetime of replay protection.

namespace macOS_Hardening.User;

public sealed class MonitoringOptions
{
    public bool Enabled { get; set; }
    public int DeduplicationRetentionSeconds { get; set; } = 600;
    public int DeduplicationCapacity { get; set; } = 10000;
    public int FailedAttemptsThreshold { get; set; } = 5;
    public int SevereAttemptsThreshold { get; set; } = 10;
    public int CriticalAttemptsThreshold { get; set; } = 15;
    public int DetectionWindowMinutes { get; set; } = 5;
    public int AlertCooldownMinutes { get; set; } = 5;

    public void Validate()
    {
        if (DeduplicationRetentionSeconds is < 1 or > 86400 ||
            DeduplicationCapacity is < 1 or > 1000000)
            throw new ArgumentOutOfRangeException(nameof(MonitoringOptions), "Invalid deduplication limits.");
        if (DetectionWindowMinutes is < 1 or > 1440 || AlertCooldownMinutes is < 0 or > 1440)
            throw new ArgumentOutOfRangeException(nameof(MonitoringOptions), "Invalid detection time limits.");
        if (FailedAttemptsThreshold < 1 || SevereAttemptsThreshold <= FailedAttemptsThreshold ||
            CriticalAttemptsThreshold <= SevereAttemptsThreshold)
            throw new ArgumentOutOfRangeException(nameof(MonitoringOptions), "Alert thresholds must be positive and strictly increasing.");
    }
}
