// Tests record-key stability, identity validation, and separation of distinct records.

using System.Globalization;
using System.Text;
using macOS_Hardening.Infrastructure.UnifiedLogging;
using Xunit;

namespace macOS_Hardening.UnitTests;

public sealed class UnifiedLogRecordKeyTests
{
    // Synthetic identity values; no real device identifiers are used.
    private static UnifiedLogEntry Record() => new()
    {
        Timestamp = new DateTimeOffset(2026, 1, 15, 9, 30, 0, TimeSpan.FromHours(-6)),
        BootUuid = Guid.Parse("12345678-9abc-4def-8123-123456789abc"),
        MachTimestamp = 123456789012345UL,
        ProcessId = 42,
        ThreadId = 987654321UL,
        EventMessage = "Synthetic failure message"
    };

    [Fact]
    public void ReplayedRecordProducesSameSha256Key()
    {
        var original = Record();
        var key = UnifiedLogRecordKey.Create(original);
        Assert.NotNull(key);
        Assert.Matches("\\A[0-9A-F]{64}\\z", key);
        Assert.Equal(key, UnifiedLogRecordKey.Create(original with { }));
        Assert.Equal(key, UnifiedLogRecordKey.Create(Record()));
    }

    [Theory]
    [InlineData("boot")]
    [InlineData("mach")]
    [InlineData("process")]
    [InlineData("thread")]
    [InlineData("message")]
    public void EachIdentityFieldDistinguishesRecords(string field)
    {
        var original = Record();
        var changed = field switch
        {
            "boot" => original with { BootUuid = Guid.Parse("22345678-9abc-4def-8123-123456789abc") },
            "mach" => original with { MachTimestamp = original.MachTimestamp + 1 },
            "process" => original with { ProcessId = original.ProcessId + 1 },
            "thread" => original with { ThreadId = original.ThreadId + 1 },
            "message" => original with { EventMessage = "Different synthetic message" },
            _ => throw new ArgumentOutOfRangeException(nameof(field))
        };
        var changedKey = UnifiedLogRecordKey.Create(changed);
        Assert.NotNull(changedKey);
        Assert.NotEqual(UnifiedLogRecordKey.Create(original), changedKey);
    }

    [Theory]
    [InlineData("missingBoot")]
    [InlineData("emptyBoot")]
    [InlineData("missingMach")]
    [InlineData("missingProcess")]
    [InlineData("negativeProcess")]
    [InlineData("missingThread")]
    [InlineData("missingMessage")]
    [InlineData("emptyMessage")]
    public void IncompleteOrInvalidIdentityHasNoKey(string scenario)
    {
        var record = Record();
        var invalid = scenario switch
        {
            "missingBoot" => record with { BootUuid = null },
            "emptyBoot" => record with { BootUuid = Guid.Empty },
            "missingMach" => record with { MachTimestamp = null },
            "missingProcess" => record with { ProcessId = null },
            "negativeProcess" => record with { ProcessId = -1 },
            "missingThread" => record with { ThreadId = null },
            "missingMessage" => record with { EventMessage = null },
            "emptyMessage" => record with { EventMessage = "" },
            _ => throw new ArgumentOutOfRangeException(nameof(scenario))
        };
        Assert.Null(UnifiedLogRecordKey.Create(invalid));
    }

    [Fact]
    public void NullInputThrows() =>
        Assert.Throws<ArgumentNullException>(() => UnifiedLogRecordKey.Create(null!));

    [Fact]
    public void ZeroAndMaximumNumericValuesAreAccepted()
    {
        var zero = Record() with { MachTimestamp = 0, ProcessId = 0, ThreadId = 0 };
        var maximum = Record() with { MachTimestamp = ulong.MaxValue, ProcessId = int.MaxValue, ThreadId = ulong.MaxValue };
        var zeroKey = UnifiedLogRecordKey.Create(zero);
        var maximumKey = UnifiedLogRecordKey.Create(maximum);
        Assert.NotNull(zeroKey);
        Assert.NotNull(maximumKey);
        Assert.NotEqual(zeroKey, maximumKey);
    }

    [Fact]
    public void NonIdentityMetadataDoesNotChangeKey()
    {
        var original = Record();
        var changed = original with
        {
            Timestamp = original.Timestamp.AddHours(1),
            Subsystem = "synthetic.subsystem",
            Category = "Other",
            ProcessImagePath = "/synthetic/path",
            MessageType = "Info"
        };
        Assert.Equal(UnifiedLogRecordKey.Create(original), UnifiedLogRecordKey.Create(changed));
    }

    [Theory]
    [InlineData("fr-FR")]
    [InlineData("ar-SA")]
    public void KeyDoesNotDependOnCurrentCulture(string culture)
    {
        var originalCulture = CultureInfo.CurrentCulture;
        var record = Record();
        var expected = UnifiedLogRecordKey.Create(record);
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
            Assert.Equal(expected, UnifiedLogRecordKey.Create(record));
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }

    [Theory]
    [InlineData("Synthetic failure message ")]
    [InlineData("synthetic failure message")]
    [InlineData("Synthetic failure message\n")]
    [InlineData("Synthetic failure message \"quoted\" | 世界")]
    public void MessageContentIsNotNormalized(string message)
    {
        var original = Record();
        var changedKey = UnifiedLogRecordKey.Create(original with { EventMessage = message });
        Assert.NotNull(changedKey);
        Assert.NotEqual(UnifiedLogRecordKey.Create(original), changedKey);
    }

    [Fact]
    public async Task ParsedGuidCasingDoesNotChangeKeyAndSeparateAttemptsRemainDistinct()
    {
        // Two synthetic captures of the same event, plus a separate event with a later mach timestamp.
        const string json = """
            [
              {"timestamp":"2026-01-15 09:30:00.123456-0600","bootUUID":"12345678-9ABC-4DEF-8123-123456789ABC","machTimestamp":100,"processID":42,"threadID":99,"eventMessage":"Synthetic failure"},
              {"timestamp":"2026-01-15 09:30:00.123456-0600","bootUUID":"12345678-9abc-4def-8123-123456789abc","machTimestamp":100,"processID":42,"threadID":99,"eventMessage":"Synthetic failure"},
              {"timestamp":"2026-01-15 09:30:01.123456-0600","bootUUID":"12345678-9abc-4def-8123-123456789abc","machTimestamp":200,"processID":42,"threadID":99,"eventMessage":"Synthetic failure"}
            ]
            """;
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        var result = await new UnifiedLogParser().ParseBatchAsync(stream);
        Assert.Equal(UnifiedLogParseStatus.Success, result.Status);
        Assert.Equal(3, result.Entries.Count);
        var keys = result.Entries.Select(UnifiedLogRecordKey.Create).ToArray();
        Assert.All(keys, key => Assert.NotNull(key));
        Assert.Equal(keys[0], keys[1]);
        Assert.NotEqual(keys[0], keys[2]);
    }
}
