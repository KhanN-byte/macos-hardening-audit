// Orchestrates opt-in collection, persistence, and repeated-failure alerting.

using macOS_Hardening.Contracts.Models;
using macOS_Hardening.Core.Detection;
using macOS_Hardening.Infrastructure.Storage;
using macOS_Hardening.Infrastructure.UnifiedLogging;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace macOS_Hardening.User.Workers;

public sealed class AuthenticationWorker(
    ILogger<AuthenticationWorker> logger,
    MonitoringOptions options,
    UnifiedLogCollector collector,
    ScreenUnlockFailureMapper mapper,
    UnifiedLogDeduplicator deduplicator,
    ISecurityEventStore store,
    RepeatedFailureDetector detector) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Enabled)
        {
            logger.LogInformation("Authentication monitoring is disabled. Set Monitoring:Enabled to true to collect.");
            return;
        }

        logger.LogInformation("Authentication monitoring starting; coverage is limited to validated password screen-unlock failures.");
        try
        {
            await store.InitializeAsync(stoppingToken);
            var recovery = await store.RecoverAsync(DateTimeOffset.UtcNow.AddMinutes(-options.DetectionWindowMinutes), stoppingToken);
            detector.Restore(recovery.Events, recovery.LatestAlert);
            if (recovery.MalformedRecordCount > 0)
                logger.LogWarning("Ignored {MalformedRecordCount} malformed persisted security records during recovery.", recovery.MalformedRecordCount);

            await foreach (var item in collector.ReadAsync(stoppingToken))
            {
                switch (item.Kind)
                {
                    case UnifiedLogCollectionKind.ProcessStarted:
                        logger.LogInformation("Unified Logging process started. Process startup does not establish collection coverage.");
                        break;
                    case UnifiedLogCollectionKind.StandardError:
                        logger.LogWarning("Unified Logging emitted stderr; collection may be degraded. Raw stderr is suppressed.");
                        break;
                    case UnifiedLogCollectionKind.RestartScheduled:
                        logger.LogWarning("Collection interrupted. ExitCode={ExitCode} FailureType={FailureType} RestartDelay={RestartDelay}. Events during the gap may be lost.",
                            item.ExitCode, item.FailureType, item.RestartDelay);
                        break;
                    case UnifiedLogCollectionKind.RecordRejected:
                        logger.LogWarning("Unified Logging record rejected. Code={Code} RecordIndex={RecordIndex} Field={Field}",
                            item.Diagnostic?.Code, item.Diagnostic?.RecordIndex, item.Diagnostic?.Field);
                        break;
                    case UnifiedLogCollectionKind.Record:
                        var entry = item.Entry!;
                        var authenticationEvent = mapper.Map(entry);
                        if (authenticationEvent is null) break;
                        var result = deduplicator.CheckAndRemember(entry);
                        if (result == UnifiedLogDeduplicationResult.IdentityUnavailable)
                        {
                            logger.LogWarning("Supported failure excluded from processing because its record identity is unavailable.");
                            break;
                        }
                        if (result == UnifiedLogDeduplicationResult.Duplicate) break;
                        await store.AppendAsync(authenticationEvent, stoppingToken);
                        logger.LogInformation("Authentication failure observed. EventTimestamp={EventTimestamp} EventType={EventType} Source={Source}",
                            authenticationEvent.Timestamp, authenticationEvent.EventType, authenticationEvent.Source);
                        var alert = detector.Observe(authenticationEvent);
                        if (alert is not null)
                        {
                            await store.AppendAsync(alert, stoppingToken);
                            LogAlert(alert);
                        }
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { logger.LogInformation("Authentication monitoring stopped."); }
    }

    private void LogAlert(SecurityAlert alert)
    {
        var message = "Repeated authentication failures detected. Severity={Severity} AttemptCount={AttemptCount} WindowStart={WindowStart} WindowEnd={WindowEnd} EventType={EventType} Source={Source}";
        var arguments = new object?[] { alert.Severity, alert.AttemptCount, alert.WindowStart, alert.WindowEnd, alert.EventType, alert.Source };
        switch (alert.Severity)
        {
            case AlertSeverity.Warning: logger.LogWarning(message, arguments); break;
            case AlertSeverity.Severe: logger.LogError(message, arguments); break;
            case AlertSeverity.Critical: logger.LogCritical(message, arguments); break;
        }
    }
}
