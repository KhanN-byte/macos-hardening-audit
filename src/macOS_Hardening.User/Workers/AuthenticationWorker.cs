// Logs worker startup and shutdown; event collection is not connected yet.

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace macOS_Hardening.User.Workers;

public sealed class AuthenticationWorker(
    ILogger<AuthenticationWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        logger.LogInformation(
            "macOS Hardening authentication monitoring started.");

        try
        {
            await Task.Delay(
                Timeout.InfiniteTimeSpan,
                stoppingToken);
        }
        catch (OperationCanceledException ex)
            when (stoppingToken.IsCancellationRequested)
        {
            logger.LogInformation(
                ex, "macOS Hardening authentication monitoring stopped. Reason: {Error}", ex.Message);
        }
    }
}
