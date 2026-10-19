// Tests duplicate detection, expiry, and capacity without real-time waits.

using macOS_Hardening.Infrastructure.UnifiedLogging;
using Xunit;

namespace macOS_Hardening.UnitTests;

public sealed class UnifiedLogDeduplicatorTests
{
    private static UnifiedLogEntry Record(ulong timestamp = 100) => new()
    {
        Timestamp = new DateTimeOffset(
            2026, 1, 15, 9, 30, 0, TimeSpan.Zero),
        BootUuid = Guid.Parse("12345678-9abc-4def-8123-123456789abc"),
        MachTimestamp = timestamp,
        ProcessId = 42,
        ThreadId = 99,
        EventMessage = "Synthetic failure"
    };

    [Fact]
    public void AcceptsDistinctRecordsAndRejectsReplays()
    {
        var cache = new UnifiedLogDeduplicator(
            TimeSpan.FromMinutes(1), 10, new ManualTimeProvider());

        Assert.Equal(
            UnifiedLogDeduplicationResult.Accepted,
            cache.CheckAndRemember(Record()));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Duplicate,
            cache.CheckAndRemember(Record()));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Accepted,
            cache.CheckAndRemember(Record(101)));
    }

    [Fact]
    public void ExpiresAtBoundaryWithoutRefreshingOnDuplicate()
    {
        var clock = new ManualTimeProvider();
        var cache = new UnifiedLogDeduplicator(
            TimeSpan.FromSeconds(10), 10, clock);

        Assert.Equal(
            UnifiedLogDeduplicationResult.Accepted,
            cache.CheckAndRemember(Record()));

        clock.Advance(TimeSpan.FromSeconds(10) - TimeSpan.FromTicks(1));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Duplicate,
            cache.CheckAndRemember(Record()));

        clock.Advance(TimeSpan.FromTicks(1));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Accepted,
            cache.CheckAndRemember(Record()));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Duplicate,
            cache.CheckAndRemember(Record()));
    }

    [Fact]
    public void CapacityEvictsOldestAcceptanceEvenAfterReplay()
    {
        var cache = new UnifiedLogDeduplicator(
            TimeSpan.FromMinutes(1), 2, new ManualTimeProvider());

        cache.CheckAndRemember(Record(1));
        cache.CheckAndRemember(Record(2));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Duplicate,
            cache.CheckAndRemember(Record(1)));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Accepted,
            cache.CheckAndRemember(Record(3)));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Duplicate,
            cache.CheckAndRemember(Record(2)));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Accepted,
            cache.CheckAndRemember(Record(1)));
    }

    [Fact]
    public void ExpiryRemovesOldRecordsAndPreservesUnexpiredRecords()
    {
        var clock = new ManualTimeProvider();
        var cache = new UnifiedLogDeduplicator(
            TimeSpan.FromSeconds(10), 3, clock);

        cache.CheckAndRemember(Record(1));
        cache.CheckAndRemember(Record(2));

        clock.Advance(TimeSpan.FromSeconds(5));
        cache.CheckAndRemember(Record(3));

        clock.Advance(TimeSpan.FromSeconds(5));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Accepted,
            cache.CheckAndRemember(Record(4)));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Accepted,
            cache.CheckAndRemember(Record(5)));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Duplicate,
            cache.CheckAndRemember(Record(3)));
    }

    [Fact]
    public void MissingIdentityDoesNotConsumeCapacity()
    {
        var cache = new UnifiedLogDeduplicator(
            TimeSpan.FromMinutes(1), 1, new ManualTimeProvider());

        cache.CheckAndRemember(Record());

        var incomplete = Record(101) with { BootUuid = null };

        Assert.Equal(
            UnifiedLogDeduplicationResult.IdentityUnavailable,
            cache.CheckAndRemember(incomplete));

        Assert.Equal(
            UnifiedLogDeduplicationResult.IdentityUnavailable,
            cache.CheckAndRemember(incomplete));

        Assert.Equal(
            UnifiedLogDeduplicationResult.Duplicate,
            cache.CheckAndRemember(Record()));
    }

    [Fact]
    public void NullInputThrows()
    {
        var cache = new UnifiedLogDeduplicator(
            TimeSpan.FromMinutes(1), 10, new ManualTimeProvider());

        Assert.Throws<ArgumentNullException>(
            () => cache.CheckAndRemember(null!));
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-1, 1)]
    [InlineData(1, 0)]
    [InlineData(1, -1)]
    public void InvalidLimitsAreRejected(int seconds, int capacity)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new UnifiedLogDeduplicator(
                TimeSpan.FromSeconds(seconds), capacity));
    }

    [Fact]
    public void ParallelSubmissionsAcceptSameRecordOnlyOnce()
    {
        var cache = new UnifiedLogDeduplicator(
            TimeSpan.FromMinutes(1), 10, new ManualTimeProvider());

        var results = new UnifiedLogDeduplicationResult[32];

        Parallel.For(0, results.Length, index =>
        {
            results[index] = cache.CheckAndRemember(Record());
        });

        Assert.Equal(1, results.Count(
            result => result == UnifiedLogDeduplicationResult.Accepted));

        Assert.Equal(31, results.Count(
            result => result == UnifiedLogDeduplicationResult.Duplicate));
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private long timestamp;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => timestamp;

        public void Advance(TimeSpan elapsed) => timestamp += elapsed.Ticks;
    }
}
