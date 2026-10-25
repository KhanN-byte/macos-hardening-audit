// Verifies local persistence, rotation, recovery, and malformed-record isolation.

using macOS_Hardening.Contracts.Models;
using macOS_Hardening.Infrastructure.Storage;
using Xunit;

namespace macOS_Hardening.UnitTests;

public sealed class JsonlSecurityEventStoreTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), $"macos-hardening-{Guid.NewGuid():N}");

    [Fact]
    public async Task PersistsAndRecoversEventsAndLatestAlert()
    {
        using var store = Store();
        await store.InitializeAsync(default);
        var timestamp = DateTimeOffset.UtcNow;
        var authenticationEvent = Event(timestamp);
        var alert = Alert(timestamp);

        await store.AppendAsync(authenticationEvent, default);
        await store.AppendAsync(alert, default);
        var recovery = await store.RecoverAsync(timestamp.AddMinutes(-1), default);

        Assert.Equal(authenticationEvent, Assert.Single(recovery.Events));
        Assert.Equal(alert, recovery.LatestAlert);
        Assert.Equal(0, recovery.MalformedRecordCount);
    }

    [Fact]
    public async Task MalformedLineDoesNotPreventRecovery()
    {
        using var store = Store();
        await store.InitializeAsync(default);
        var timestamp = DateTimeOffset.UtcNow;
        await store.AppendAsync(Event(timestamp), default);
        var file = Assert.Single(Directory.GetFiles(directory, "*.jsonl"));
        await File.AppendAllTextAsync(file, "{invalid json}" + Environment.NewLine);

        var recovery = await store.RecoverAsync(timestamp.AddMinutes(-1), default);

        Assert.Single(recovery.Events);
        Assert.Equal(1, recovery.MalformedRecordCount);
    }

    [Fact]
    public async Task RotatesWhenCurrentFileWouldExceedLimit()
    {
        using var store = Store(maxFileBytes: 1024);
        await store.InitializeAsync(default);
        for (var index = 0; index < 12; index++) await store.AppendAsync(Event(DateTimeOffset.UtcNow.AddSeconds(index)), default);

        Assert.True(Directory.GetFiles(directory, "*.jsonl").Length > 1);
    }

    [Fact]
    public async Task InitializationRemovesOnlyExpiredStoreFiles()
    {
        Directory.CreateDirectory(directory);
        var expired = Path.Combine(directory, "security-events-20200101-000.jsonl");
        var unrelated = Path.Combine(directory, "keep.txt");
        await File.WriteAllTextAsync(expired, "old");
        await File.WriteAllTextAsync(unrelated, "keep");
        File.SetLastWriteTimeUtc(expired, DateTime.UtcNow.AddDays(-8));
        using var store = Store();

        await store.InitializeAsync(default);

        Assert.False(File.Exists(expired));
        Assert.True(File.Exists(unrelated));
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }

    private JsonlSecurityEventStore Store(long maxFileBytes = 10 * 1024 * 1024) => new(new SecurityEventStoreOptions
    {
        Directory = directory,
        RetentionDays = 7,
        MaxFileBytes = maxFileBytes
    });

    private static AuthenticationEvent Event(DateTimeOffset timestamp) => new()
    {
        Timestamp = timestamp,
        EventType = AuthEventType.FailedPasswordScreenUnlock,
        Source = "test"
    };

    private static SecurityAlert Alert(DateTimeOffset timestamp) => new()
    {
        EventType = AuthEventType.FailedPasswordScreenUnlock,
        Severity = AlertSeverity.Warning,
        AttemptCount = 5,
        WindowStart = timestamp.AddMinutes(-1),
        WindowEnd = timestamp,
        Source = "test"
    };
}
