// Tracks recently seen record keys using bounded, in-memory storage.

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public sealed class UnifiedLogDeduplicator
{
    private readonly TimeSpan retention;
    private readonly int capacity;
    private readonly TimeProvider timeProvider;

    private readonly Dictionary<string, long> seen =
        new(StringComparer.Ordinal);

    private readonly Queue<string> insertionOrder = new();
    private readonly object gate = new();

    public UnifiedLogDeduplicator(
        TimeSpan retention,
        int capacity,
        TimeProvider? timeProvider = null)
    {
        if (retention <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(retention));

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);

        this.retention = retention;
        this.capacity = capacity;
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public UnifiedLogDeduplicationResult CheckAndRemember(
        UnifiedLogEntry entry)
    {
        var key = UnifiedLogRecordKey.Create(entry);

        lock (gate)
        {
            var now = timeProvider.GetTimestamp();
            RemoveExpired(now);

            if (key is null)
                return UnifiedLogDeduplicationResult.IdentityUnavailable;

            if (seen.ContainsKey(key))
                return UnifiedLogDeduplicationResult.Duplicate;

            if (seen.Count >= capacity)
            {
                var oldestKey = insertionOrder.Dequeue();
                seen.Remove(oldestKey);
            }

            seen.Add(key, now);
            insertionOrder.Enqueue(key);

            return UnifiedLogDeduplicationResult.Accepted;
        }
    }

    private void RemoveExpired(long now)
    {
        while (insertionOrder.TryPeek(out var key))
        {
            var firstSeen = seen[key];

            if (timeProvider.GetElapsedTime(firstSeen, now) < retention)
                break;

            insertionOrder.Dequeue();
            seen.Remove(key);
        }
    }
}
