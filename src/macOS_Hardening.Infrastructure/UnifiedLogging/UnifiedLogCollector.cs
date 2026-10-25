// Collects with bounded backpressure and restarts interrupted streams with capped backoff.

using System.Runtime.CompilerServices;
using System.Threading.Channels;

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public sealed class UnifiedLogCollector
{
    // Cleanup failure is fatal: restarting could leave overlapping collector processes.
    public sealed class CleanupException : Exception
    {
        public CleanupException()
            : base("Collector cleanup failed; stopping to avoid overlapping processes.") { }
    }

    private readonly IUnifiedLogProcessFactory factory;
    private readonly ISystemBootIdProvider bootIdProvider;
    private readonly UnifiedLogCollectionOptions options;
    private readonly TimeProvider clock;

    public UnifiedLogCollector(IUnifiedLogProcessFactory factory,
        UnifiedLogCollectionOptions options, TimeProvider? clock = null,
        ISystemBootIdProvider? bootIdProvider = null)
    {
        options.Validate();
        this.factory = factory;
        this.options = options;
        this.clock = clock ?? TimeProvider.System;
        this.bootIdProvider = bootIdProvider ?? new MacOsSystemBootIdProvider();
    }

    public async IAsyncEnumerable<UnifiedLogCollectionItem> ReadAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var channel = Channel.CreateBounded<UnifiedLogCollectionItem>(new BoundedChannelOptions(options.BufferCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = false
        });
        var producer = ProduceAsync(channel.Writer, stop.Token);
        try
        {
            await foreach (var item in channel.Reader.ReadAllAsync(cancellationToken)) yield return item;
        }
        finally
        {
            await stop.CancelAsync();
            await producer;
        }
    }

    private async Task ProduceAsync(ChannelWriter<UnifiedLogCollectionItem> writer, CancellationToken token)
    {
        var delay = TimeSpan.FromSeconds(options.InitialRestartSeconds);
        try
        {
            while (true)
            {
                token.ThrowIfCancellationRequested();
                var started = clock.GetTimestamp();
                int? exitCode = null;
                string? failure = null;
                try { exitCode = await RunOnceAsync(writer, token); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (Exception ex) when (ex is not (OutOfMemoryException or CleanupException))
                {
                    // Do not forward exception messages: they can contain raw log data or paths.
                    failure = ex.GetType().Name;
                }
                token.ThrowIfCancellationRequested();
                if (clock.GetElapsedTime(started) >= TimeSpan.FromSeconds(options.StableRunSeconds))
                    delay = TimeSpan.FromSeconds(options.InitialRestartSeconds);
                await writer.WriteAsync(new(UnifiedLogCollectionKind.RestartScheduled,
                    ExitCode: exitCode, FailureType: failure, RestartDelay: delay), token);
                await Task.Delay(delay, clock, token);
                delay = TimeSpan.FromSeconds(Math.Min(options.MaxRestartSeconds, delay.TotalSeconds * 2));
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        finally { writer.TryComplete(); }
    }

    private async Task<int> RunOnceAsync(ChannelWriter<UnifiedLogCollectionItem> writer, CancellationToken token)
    {
        var process = factory.Start(options);
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(token);
        Task stderr = Task.CompletedTask;
        try
        {
            await writer.WriteAsync(new(UnifiedLogCollectionKind.ProcessStarted), token);
            stderr = DrainErrorsAsync(process.StandardError, writer, attempt);
            var reader = new UnifiedLogStreamReader(options.MaxRecordBytes, options.MaxDepth);
            await foreach (var parsed in reader.ReadAsync(process.StandardOutput, attempt.Token))
            {
                foreach (var entry in parsed.Entries)
                {
                    var completedEntry = entry.BootUuid is null
                        ? entry with { BootUuid = bootIdProvider.GetCurrentBootId() }
                        : entry;
                    await writer.WriteAsync(new(UnifiedLogCollectionKind.Record, Entry: completedEntry), attempt.Token);
                }
                foreach (var diagnostic in parsed.Diagnostics)
                    await writer.WriteAsync(new(UnifiedLogCollectionKind.RecordRejected, Diagnostic: diagnostic), attempt.Token);
            }
            // A closed array/pipe must not leave a living child holding the collector forever.
            var code = await process.WaitForExitAsync(attempt.Token)
                .WaitAsync(TimeSpan.FromSeconds(options.ShutdownSeconds), token);
            await stderr.WaitAsync(TimeSpan.FromSeconds(options.ShutdownSeconds), token);
            return code;
        }
        finally
        {
            await attempt.CancelAsync();
            var cleanupFailed = false;
            try { await process.DisposeAsync(); }
            catch (Exception ex) when (ex is not OutOfMemoryException) { cleanupFailed = true; }
            try { await stderr.WaitAsync(TimeSpan.FromSeconds(options.ShutdownSeconds)); }
            catch (OperationCanceledException) when (attempt.IsCancellationRequested) { }
            catch (TimeoutException) { cleanupFailed = true; }
            catch (Exception) when (cleanupFailed) { }
            if (cleanupFailed) throw new CleanupException();
        }
    }

    private static async Task DrainErrorsAsync(Stream stream,
        ChannelWriter<UnifiedLogCollectionItem> writer, CancellationTokenSource attempt)
    {
        try
        {
            var buffer = new byte[4096];
            var reported = false;
            while (await stream.ReadAsync(buffer, attempt.Token) != 0)
            {
                if (reported) continue;
                reported = true;
                await writer.WriteAsync(new(UnifiedLogCollectionKind.StandardError), attempt.Token);
            }
        }
        catch
        {
            await attempt.CancelAsync();
            throw;
        }
    }
}
