// Verifies that replayed JSON batches do not count failures twice.

using System.Text;
using System.Text.Json;
using macOS_Hardening.Contracts.Models;
using macOS_Hardening.Infrastructure.UnifiedLogging;
using Xunit;

namespace macOS_Hardening.UnitTests;

public sealed class UnifiedLoggingIntegrationTests
{
    [Fact]
    public async Task ReplayedBatchCountsEachFailureOnlyOnce()
    {
        var json = CreateSyntheticBatch();
        var parser = new UnifiedLogParser();
        var mapper = new ScreenUnlockFailureMapper();
        var deduplicator = new UnifiedLogDeduplicator(
            TimeSpan.FromMinutes(10), capacity: 20,
            timeProvider: new FixedTimeProvider());
        var acceptedEvents = new List<AuthenticationEvent>();
        int iter;

        for (iter = 0; iter < 2; iter++)
        {
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
            var parsed = await parser.ParseBatchAsync(stream);
            Assert.Equal(UnifiedLogParseStatus.Success, parsed.Status);
            Assert.Empty(parsed.Diagnostics);
            Assert.Equal(15, parsed.Entries.Count);

            var ignored = 0;
            var accepted = 0;
            var duplicates = 0;
            foreach (var entry in parsed.Entries)
            {
                var authenticationEvent = mapper.Map(entry);
                if (authenticationEvent is null)
                {
                    ignored++;
                    continue;
                }

                var result = deduplicator.CheckAndRemember(entry);
                Assert.Equal(iter == 0
                    ? UnifiedLogDeduplicationResult.Accepted
                    : UnifiedLogDeduplicationResult.Duplicate, result);

                if (result == UnifiedLogDeduplicationResult.Accepted)
                {
                    accepted++;
                    acceptedEvents.Add(authenticationEvent);
                    Assert.Equal(entry.Timestamp, authenticationEvent.Timestamp);
                    Assert.Equal(entry.Timestamp.Offset, authenticationEvent.Timestamp.Offset);
                    Assert.Equal(AuthEventType.FailedPasswordScreenUnlock, authenticationEvent.EventType);
                    Assert.Equal("macos.unified-logging", authenticationEvent.Source);
                }
                else
                {
                    duplicates++;
                }
            }

            Assert.Equal(10, ignored);
            Assert.Equal(iter == 0 ? 5 : 0, accepted);
            Assert.Equal(iter == 0 ? 0 : 5, duplicates);
            Assert.Equal(5, acceptedEvents.Count);
        }

        Assert.Equal(5, acceptedEvents.Select(e => e.Timestamp).Distinct().Count());
    }

    private static string CreateSyntheticBatch()
    {
        const string prefix = "-[LWDefaultScreenLockUI authFailWithMessage:] | ";
        // Preserve the indentation present in the observed companion messages.
        string[] messages =
        [
            prefix + "enter. INCORRECT password",
            prefix + "     setEnabled:YES",
            prefix + "     Set _windowControllerActionInProgress = NO"
        ];

        // Invented identity values; message patterns match the observed sample.
        var records = Enumerable.Range(0, 15).Select(index => new
        {
            timestamp = FormattableString.Invariant(
                $"2026-01-15 09:30:{index:00}.000000-0600"),
            bootUUID = "12345678-9abc-4def-8123-123456789abc",
            machTimestamp = 1_000_000UL + (ulong)index,
            processID = 42,
            threadID = 99,
            eventMessage = messages[index % messages.Length],
            processImagePath = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
            subsystem = "com.apple.loginwindow.logging",
            category = "Standard",
            messageType = "Default"
        });
        return JsonSerializer.Serialize(records);
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        public override long GetTimestamp() => 0;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    }
}
