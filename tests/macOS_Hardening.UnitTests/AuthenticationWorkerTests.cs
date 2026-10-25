// Tests monitoring opt-in and the connected worker using synthetic process output.

using System.Collections.Concurrent;
using macOS_Hardening.Contracts.Models;
using macOS_Hardening.Core.Detection;
using macOS_Hardening.Infrastructure.Storage;
using macOS_Hardening.Infrastructure.UnifiedLogging;
using macOS_Hardening.User;
using macOS_Hardening.User.Workers;
using Microsoft.Extensions.Logging;
using Xunit;
using static macOS_Hardening.UnitTests.CollectionTestSupport;

namespace macOS_Hardening.UnitTests;

public sealed class AuthenticationWorkerTests
{
    [Fact]
    public async Task DisabledMonitoringNeverStartsProcess()
    {
        var factory = new Factory(_ => throw new InvalidOperationException());
        var logger = new CaptureLogger();
        using var worker = Worker(factory, logger, enabled: false);
        await worker.StartAsync(default);
        await worker.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, factory.Starts);
        Assert.Contains(logger.Messages, text => text.Contains("disabled"));
    }

    [Fact]
    public async Task WorkerReportsOneFailureRejectsMissingIdentityAndStopsChild()
    {
        var record = Record();
        var missingIdentity = record.Replace("\"threadID\":99", "\"threadID\":null");
        var child = new Child(new Input("[" + string.Join(',', record, record, missingIdentity, Record("PRIVATE unrelated")), holdOpen: true));
        var factory = new Factory(_ => child);
        var logger = new CaptureLogger();
        using var worker = Worker(factory, logger, enabled: true);
        await worker.StartAsync(default);
        try
        {
            await logger.IdentityUnavailable.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await worker.StopAsync(timeout.Token);
        }
        Assert.Single(logger.Messages, text => text.StartsWith("Authentication failure observed."));
        Assert.DoesNotContain(logger.Messages, text => text.Contains("PRIVATE") || text.Contains("INCORRECT password"));
        Assert.True(child.Disposed.Task.IsCompleted);
    }

    [Fact]
    public void InvalidConfigurationIsRejectedBeforeCollection()
    {
        Assert.Throws<ArgumentException>(() => new UnifiedLogCollectionOptions { ExecutablePath = "log" }.Validate());
        Assert.Throws<ArgumentException>(() => new UnifiedLogCollectionOptions { Predicate = "" }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnifiedLogCollectionOptions { BufferCapacity = 0 }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnifiedLogCollectionOptions { InitialRestartSeconds = 5, MaxRestartSeconds = 1 }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() => new MonitoringOptions { DeduplicationCapacity = 0 }.Validate());
    }

    private static AuthenticationWorker Worker(Factory factory, CaptureLogger logger, bool enabled) => new(
        logger, new MonitoringOptions { Enabled = enabled }, new UnifiedLogCollector(factory, new()),
        new ScreenUnlockFailureMapper(), new UnifiedLogDeduplicator(TimeSpan.FromMinutes(10), 10), new MemoryStore(),
        new RepeatedFailureDetector(new RepeatedFailureOptions()));

    private sealed class MemoryStore : ISecurityEventStore
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task AppendAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task AppendAsync(SecurityAlert alert, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<SecurityEventStoreRecovery> RecoverAsync(DateTimeOffset since, CancellationToken cancellationToken) =>
            Task.FromResult(new SecurityEventStoreRecovery([], null, 0));
    }

    private sealed class CaptureLogger : ILogger<AuthenticationWorker>
    {
        internal ConcurrentQueue<string> Messages { get; } = new();
        internal TaskCompletionSource IdentityUnavailable { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, error);
            Messages.Enqueue(message);
            if (message.Contains("identity is unavailable")) IdentityUnavailable.TrySetResult();
        }
    }
}
