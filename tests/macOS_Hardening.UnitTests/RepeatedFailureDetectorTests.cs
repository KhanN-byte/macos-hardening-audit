// Verifies sliding-window thresholds, escalation, cooldown, and restart restoration.

using macOS_Hardening.Contracts.Models;
using macOS_Hardening.Core.Detection;
using Xunit;

namespace macOS_Hardening.UnitTests;

public sealed class RepeatedFailureDetectorTests
{
    [Fact]
    public void EmitsAtThresholdsAndSuppressesRepeatedAlertsDuringCooldown()
    {
        var detector = Detector();
        var start = DateTimeOffset.Parse("2026-10-24T12:00:00Z");

        Assert.Null(detector.Observe(Event(start)));
        Assert.Null(detector.Observe(Event(start.AddSeconds(1))));
        var warning = detector.Observe(Event(start.AddSeconds(2)));
        Assert.Equal(AlertSeverity.Warning, warning?.Severity);
        Assert.Null(detector.Observe(Event(start.AddSeconds(3))));
        Assert.Equal(AlertSeverity.Severe, detector.Observe(Event(start.AddSeconds(4)))?.Severity);
        Assert.Equal(AlertSeverity.Critical, detector.Observe(Event(start.AddSeconds(5)))?.Severity);
        Assert.Null(detector.Observe(Event(start.AddSeconds(6))));
    }

    [Fact]
    public void RemovesFailuresOutsideWindow()
    {
        var detector = Detector();
        var start = DateTimeOffset.Parse("2026-10-24T12:00:00Z");
        detector.Observe(Event(start));
        detector.Observe(Event(start.AddSeconds(1)));

        Assert.Null(detector.Observe(Event(start.AddMinutes(6))));
    }

    [Fact]
    public void RestoredAlertPreventsDuplicateAfterRestart()
    {
        var start = DateTimeOffset.Parse("2026-10-24T12:00:00Z");
        var events = new[] { Event(start), Event(start.AddSeconds(1)), Event(start.AddSeconds(2)) };
        var previous = new SecurityAlert
        {
            EventType = AuthEventType.FailedPasswordScreenUnlock,
            Severity = AlertSeverity.Warning,
            AttemptCount = 3,
            WindowStart = start,
            WindowEnd = start.AddSeconds(2),
            Source = "test"
        };
        var detector = Detector();
        detector.Restore(events, previous);

        Assert.Null(detector.Observe(Event(start.AddSeconds(3))));
        Assert.Equal(AlertSeverity.Severe, detector.Observe(Event(start.AddSeconds(4)))?.Severity);
    }

    private static RepeatedFailureDetector Detector() => new(new RepeatedFailureOptions
    {
        DetectionWindow = TimeSpan.FromMinutes(5),
        AlertCooldown = TimeSpan.FromMinutes(5),
        WarningThreshold = 3,
        SevereThreshold = 5,
        CriticalThreshold = 6
    });

    private static AuthenticationEvent Event(DateTimeOffset timestamp) => new()
    {
        Timestamp = timestamp,
        EventType = AuthEventType.FailedPasswordScreenUnlock,
        Source = "test"
    };
}
