// Tests failure mapping and rejection of unrelated or incomplete records.

using macOS_Hardening.Contracts.Models;
using macOS_Hardening.Infrastructure.UnifiedLogging;
using Xunit;

namespace macOS_Hardening.UnitTests;

public sealed class ScreenUnlockFailureMapperTests
{
    private readonly ScreenUnlockFailureMapper mapper = new();

    // Synthetic unit-test input using the signature observed in the controlled capture.
    private static UnifiedLogEntry Failure() => new()
    {
        Timestamp = new DateTimeOffset(2026, 1, 15, 9, 30, 0, TimeSpan.FromHours(-6)).AddTicks(1234560),
        EventMessage = "-[LWDefaultScreenLockUI authFailWithMessage:] | enter. INCORRECT password",
        ProcessImagePath = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
        Subsystem = "com.apple.loginwindow.logging"
    };

    [Fact]
    public void MatchingFailureMapsContractAndPreservesTimestampOffset()
    {
        var entry = Failure();
        var result = Assert.IsType<AuthenticationEvent>(mapper.Map(entry));

        Assert.Equal(entry.Timestamp, result.Timestamp);
        Assert.Equal(entry.Timestamp.Offset, result.Timestamp.Offset);
        Assert.Equal(AuthEventType.FailedPasswordScreenUnlock, result.EventType);
        Assert.Equal("macos.unified-logging", result.Source);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("enter. INCORRECT password")]
    [InlineData("Unrelated error")]
    [InlineData("-[LWDefaultScreenLockUI authFailWithMessage:] |      setEnabled:YES")]
    [InlineData("-[LWDefaultScreenLockUI authFailWithMessage:] |      Set _windowControllerActionInProgress = NO")]
    public void NonmatchingMessageIsIgnored(string? message)
    {
        Assert.Null(mapper.Map(Failure() with { EventMessage = message }));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("com.apple.opendirectoryd")]
    [InlineData("COM.APPLE.LOGINWINDOW.LOGGING")]
    public void NonmatchingSubsystemIsIgnored(string? subsystem)
    {
        Assert.Null(mapper.Map(Failure() with { Subsystem = subsystem }));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("/usr/libexec/opendirectoryd")]
    [InlineData("/tmp/loginwindow")]
    public void NonmatchingProcessIsIgnored(string? path)
    {
        Assert.Null(mapper.Map(Failure() with { ProcessImagePath = path }));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("Standard", "Default")]
    [InlineData("OtherCategory", "Info")]
    public void CategoryAndLogLevelDoNotDetermineFailure(string? category, string? messageType)
    {
        Assert.NotNull(mapper.Map(Failure() with { Category = category, MessageType = messageType }));
    }

    [Fact]
    public void NullInputThrows()
    {
        Assert.Throws<ArgumentNullException>(() => mapper.Map(null!));
    }

    [Fact]
    public async Task SyntheticBatchMapsFiveFailureMarkersAndIgnoresTenCompanionMessages()
    {
        await using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "Fixtures", "synthetic-unlock-batch.json"));
        var parsed = await new UnifiedLogParser().ParseBatchAsync(stream);
        Assert.Equal(UnifiedLogParseStatus.Success, parsed.Status);
        Assert.Empty(parsed.Diagnostics);
        Assert.Equal(15, parsed.Entries.Count);

        var mapped = parsed.Entries.Select(mapper.Map).ToArray();
        Assert.Equal(5, mapped.Count(x => x is not null));
        for (var index = 0; index < mapped.Length; index++)
        {
            // In the observed capture each failure marker precedes two UI-state records.
            if (index % 3 == 0)
            {
                var result = Assert.IsType<AuthenticationEvent>(mapped[index]);
                Assert.Equal(parsed.Entries[index].Timestamp, result.Timestamp);
                Assert.Equal(parsed.Entries[index].Timestamp.Offset, result.Timestamp.Offset);
                Assert.Equal(AuthEventType.FailedPasswordScreenUnlock, result.EventType);
                Assert.Equal("macos.unified-logging", result.Source);
            }
            else
            {
                Assert.Null(mapped[index]);
            }
        }
    }
}
