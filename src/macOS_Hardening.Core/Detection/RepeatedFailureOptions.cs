// Defines and validates the thresholds used for repeated authentication failure alerts.

namespace macOS_Hardening.Core.Detection;

public sealed class RepeatedFailureOptions
{
    public TimeSpan DetectionWindow { get; init; } = TimeSpan.FromMinutes(5);
    public TimeSpan AlertCooldown { get; init; } = TimeSpan.FromMinutes(5);
    public int WarningThreshold { get; init; } = 5;
    public int SevereThreshold { get; init; } = 10;
    public int CriticalThreshold { get; init; } = 15;

    public void Validate()
    {
        if (DetectionWindow <= TimeSpan.Zero || AlertCooldown < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(RepeatedFailureOptions), "Detection window must be positive and cooldown cannot be negative.");
        if (WarningThreshold < 1 || SevereThreshold <= WarningThreshold || CriticalThreshold <= SevereThreshold)
            throw new ArgumentOutOfRangeException(nameof(RepeatedFailureOptions), "Alert thresholds must be positive and strictly increasing.");
    }
}
