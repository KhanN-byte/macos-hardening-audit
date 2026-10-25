// Tests collection lifecycle, bounded delivery, diagnostics, and retry behavior with simulated processes.

using macOS_Hardening.Infrastructure.UnifiedLogging;
using Xunit;
using static macOS_Hardening.UnitTests.CollectionTestSupport;

namespace macOS_Hardening.UnitTests;

public sealed class UnifiedLogCollectorTests
{
    [Fact]
    public async Task EmptyLiveBootUuidUsesCurrentBootId()
    {
        var expected = Guid.Parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        var bootId = new BootIdProvider(expected);
        var json = "[" + Record().Replace(
            "\"bootUUID\":\"12345678-9abc-4def-8123-123456789abc\"",
            "\"bootUUID\":\"\"") + "]";
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var collector = new UnifiedLogCollector(
            new Factory(_ => new Child(new Input(json))), new(),
            bootIdProvider: bootId);

        await foreach (var item in collector.ReadAsync(stop.Token))
        {
            if (item.Kind != UnifiedLogCollectionKind.Record) continue;
            Assert.Equal(expected, item.Entry!.BootUuid);
            Assert.NotNull(UnifiedLogRecordKey.Create(item.Entry));
            break;
        }

        Assert.Equal(1, bootId.Calls);
    }

    [Fact]
    public async Task SuppliedBootUuidIsPreservedWithoutProviderLookup()
    {
        var bootId = new BootIdProvider(Guid.NewGuid());
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var collector = new UnifiedLogCollector(
            new Factory(_ => new Child(new Input("[" + Record() + "]"))), new(),
            bootIdProvider: bootId);

        await foreach (var item in collector.ReadAsync(stop.Token))
        {
            if (item.Kind != UnifiedLogCollectionKind.Record) continue;
            Assert.Equal(Guid.Parse("12345678-9abc-4def-8123-123456789abc"), item.Entry!.BootUuid);
            break;
        }

        Assert.Equal(0, bootId.Calls);
    }

    [Fact]
    public async Task ReadsStdoutAndDrainsStderrWithoutExposingPayload()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var error = new Input(new string('x', 100000), chunk: 256);
        var child = new Child(new Input("[" + Record() + "]", 1), error, 17);
        var factory = new Factory(_ => child);
        await using var items = new UnifiedLogCollector(factory, new()).ReadAsync(stop.Token).GetAsyncEnumerator();
        var received = new List<UnifiedLogCollectionItem>();
        while (await items.MoveNextAsync())
        {
            received.Add(items.Current);
            if (items.Current.Kind == UnifiedLogCollectionKind.RestartScheduled) break;
        }
        Assert.Single(received, x => x.Kind == UnifiedLogCollectionKind.Record);
        Assert.Single(received, x => x.Kind == UnifiedLogCollectionKind.StandardError);
        Assert.Equal(17, received.Last().ExitCode);
        Assert.Equal(100000, error.Consumed);
        Assert.True(child.Disposed.Task.IsCompleted);
    }

    [Fact]
    public async Task StartFailuresUseCappedBackoffAndSafeDiagnostics()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var clock = new FastClock();
        var factory = new Factory(_ => throw new IOException("PRIVATE"));
        var collector = new UnifiedLogCollector(factory, new() { MaxRestartSeconds = 4 }, clock);
        await using var items = collector.ReadAsync(stop.Token).GetAsyncEnumerator();
        var delays = new List<double>();
        while (delays.Count < 4 && await items.MoveNextAsync())
        {
            Assert.Equal(UnifiedLogCollectionKind.RestartScheduled, items.Current.Kind);
            Assert.Equal("IOException", items.Current.FailureType);
            delays.Add(items.Current.RestartDelay!.Value.TotalSeconds);
        }
        Assert.Equal(new double[] { 1, 2, 4, 4 }, delays);
    }

    [Fact]
    public async Task StableConnectionResetsBackoff()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var clock = new FastClock();
        var factory = new Factory(attempt =>
        {
            if (attempt <= 2) throw new IOException();
            clock.Timestamp += TimeSpan.FromSeconds(60).Ticks;
            return new Child(new Input("[]"));
        });
        await using var items = new UnifiedLogCollector(factory, new(), clock).ReadAsync(stop.Token).GetAsyncEnumerator();
        var delays = new List<double>();
        while (delays.Count < 3 && await items.MoveNextAsync())
            if (items.Current.Kind == UnifiedLogCollectionKind.RestartScheduled)
                delays.Add(items.Current.RestartDelay!.Value.TotalSeconds);
        Assert.Equal(new double[] { 1, 2, 1 }, delays);
    }

    [Fact]
    public async Task MalformedStreamDisposesChildAndRestarts()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var first = new Child(new Input("["));
        var second = new Child(new Input("[" + Record(), holdOpen: true));
        var factory = new Factory(attempt => attempt == 1 ? first : second);
        var observed = new List<UnifiedLogCollectionItem>();
        await foreach (var item in new UnifiedLogCollector(factory, new(), new FastClock()).ReadAsync(stop.Token))
        {
            observed.Add(item);
            if (item.Kind == UnifiedLogCollectionKind.Record) break;
        }
        Assert.Contains(observed, x => x.FailureType == "InvalidDataException");
        Assert.True(first.Disposed.Task.IsCompleted);
        Assert.True(second.Disposed.Task.IsCompleted);
    }

    [Fact]
    public async Task RecordValidationErrorsDoNotRestartConnection()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var factory = new Factory(_ => new Child(new Input("[{}," + Record(), holdOpen: true)));
        var observed = new List<UnifiedLogCollectionItem>();
        await foreach (var item in new UnifiedLogCollector(factory, new()).ReadAsync(stop.Token))
        {
            observed.Add(item);
            if (item.Kind == UnifiedLogCollectionKind.Record) break;
        }
        Assert.Contains(observed, x => x.Diagnostic?.Code == UnifiedLogParseError.MissingTimestamp);
        Assert.Equal(1, factory.Starts);
    }

    [Fact]
    public async Task CancellationUnblocksFullQueueAndDisposesProcess()
    {
        var child = new Child(new Input("[" + string.Join(',', Enumerable.Repeat(Record(), 50)) + "]"));
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var factory = new Factory(_ => child);
        var items = new UnifiedLogCollector(factory, new() { BufferCapacity = 1 }).ReadAsync(stop.Token).GetAsyncEnumerator();
        Assert.True(await items.MoveNextAsync());
        // Producer can fill one slot and then must wait for the consumer.
        await items.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(child.Disposed.Task.IsCompleted);
        Assert.Equal(1, factory.Starts);
    }

    [Fact]
    public async Task StderrReadFailureInterruptsBlockedStdout()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var child = new Child(new Input("", holdOpen: true), new Input("", fail: true));
        await foreach (var item in new UnifiedLogCollector(new Factory(_ => child), new()).ReadAsync(stop.Token))
        {
            if (item.Kind != UnifiedLogCollectionKind.RestartScheduled) continue;
            Assert.Equal("IOException", item.FailureType);
            Assert.True(child.Disposed.Task.IsCompleted);
            break;
        }
    }
    [Fact]
    public async Task CleanupFailureStopsInsteadOfStartingAnotherProcess()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var factory = new Factory(_ => new Child(new Input("[]"), failCleanup: true));
        var collector = new UnifiedLogCollector(factory, new());
        await Assert.ThrowsAsync<UnifiedLogCollector.CleanupException>(async () =>
        {
            await foreach (var item in collector.ReadAsync(stop.Token))
                Assert.NotEqual(UnifiedLogCollectionKind.RestartScheduled, item.Kind);
        });
        Assert.Equal(1, factory.Starts);
    }

}
