// Detects escalating authentication failures within a bounded event-time window.

using macOS_Hardening.Contracts.Models;

namespace macOS_Hardening.Core.Detection;

public sealed class RepeatedFailureDetector
{
    private readonly RepeatedFailureOptions options;
    private readonly List<DateTimeOffset> failures = [];
    private SecurityAlert? latestAlert;

    public RepeatedFailureDetector(RepeatedFailureOptions options)
    {
        options.Validate();
        this.options = options;
    }

    public SecurityAlert? Observe(AuthenticationEvent authenticationEvent)
    {
        ArgumentNullException.ThrowIfNull(authenticationEvent);
        if (authenticationEvent.EventType != AuthEventType.FailedPasswordScreenUnlock) return null;

        Insert(authenticationEvent.Timestamp);
        RemoveBefore(authenticationEvent.Timestamp - options.DetectionWindow);
        var severity = SeverityFor(failures.Count);
        if (severity is null) return null;

        var escalated = latestAlert is null || severity > latestAlert.Severity;
        var cooldownElapsed = latestAlert is null || authenticationEvent.Timestamp - latestAlert.WindowEnd >= options.AlertCooldown;
        if (!escalated && !cooldownElapsed) return null;

        latestAlert = new SecurityAlert
        {
            EventType = authenticationEvent.EventType,
            Severity = severity.Value,
            AttemptCount = failures.Count,
            WindowStart = failures[0],
            WindowEnd = authenticationEvent.Timestamp,
            Source = authenticationEvent.Source
        };
        return latestAlert;
    }

    public void Restore(IEnumerable<AuthenticationEvent> events, SecurityAlert? lastAlert = null)
    {
        ArgumentNullException.ThrowIfNull(events);
        failures.Clear();
        foreach (var item in events.Where(item => item.EventType == AuthEventType.FailedPasswordScreenUnlock))
            Insert(item.Timestamp);
        latestAlert = lastAlert;
    }

    private AlertSeverity? SeverityFor(int count) => count >= options.CriticalThreshold
        ? AlertSeverity.Critical
        : count >= options.SevereThreshold
            ? AlertSeverity.Severe
            : count >= options.WarningThreshold ? AlertSeverity.Warning : null;

    private void Insert(DateTimeOffset timestamp)
    {
        var index = failures.BinarySearch(timestamp);
        failures.Insert(index < 0 ? ~index : index, timestamp);
    }

    private void RemoveBefore(DateTimeOffset cutoff)
    {
        var count = failures.TakeWhile(timestamp => timestamp < cutoff).Count();
        if (count > 0) failures.RemoveRange(0, count);
    }
}
