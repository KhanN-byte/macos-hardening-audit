// Tests batch parsing, timestamp handling, malformed input, and stream boundaries.

using System.Globalization;
using System.Text;
using macOS_Hardening.Infrastructure.UnifiedLogging;
using Xunit;

namespace macOS_Hardening.UnitTests;

public sealed class UnifiedLogParserTests
{
    private const string Timestamp = "2026-01-15 09:30:00.123456-0600";
    private static string Record(string extra = "") => "{\"timestamp\":\"" + Timestamp + "\"" + extra + "}";
    private static async Task<UnifiedLogParseResult> Parse(string json, UnifiedLogParserOptions? options = null)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        return await new UnifiedLogParser(options).ParseBatchAsync(stream);
    }

    [Fact]
    public async Task SanitizedCaptureMapsFieldsAndAllowsTimeSyncRecords()
    {
        await using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "Fixtures", "sanitized-batch.json"));
        var result = await new UnifiedLogParser().ParseBatchAsync(stream);
        Assert.Equal(UnifiedLogParseStatus.Success, result.Status);
        Assert.Equal(2, result.Entries.Count);
        var entry = result.Entries[0];
        Assert.Equal(42, entry.ProcessId);
        Assert.Equal("SANITIZED", entry.Subsystem);
        Assert.Equal("SANITIZED", entry.Category);
        Assert.Equal("SANITIZED", entry.EventMessage);
        Assert.Equal("/synthetic/example", entry.ProcessImagePath);
        Assert.Equal("Default", entry.MessageType);
        Assert.Null(result.Entries[1].MessageType);
        Assert.Equal(0, result.Entries[1].ProcessId);
        Assert.Equal(TimeSpan.FromHours(-6), entry.Timestamp.Offset);
        Assert.Equal(new DateTimeOffset(2026, 1, 15, 15, 30, 0, TimeSpan.Zero).AddTicks(1234560), entry.Timestamp.ToUniversalTime());
    }

    [Theory]
    [InlineData("+0530", 330)]
    [InlineData("-0700", -420)]
    [InlineData("+0000", 0)]
    public async Task TimestampIsCultureIndependent(string offset, int minutes)
    {
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
            var result = await Parse("[" + Record().Replace("-0600", offset) + "]");
            Assert.Equal(TimeSpan.FromMinutes(minutes), Assert.Single(result.Entries).Timestamp.Offset);
        }
        finally { CultureInfo.CurrentCulture = previous; }
    }

    [Theory]
    [InlineData("2026-01-15 09:30:00.123456")]
    [InlineData("2026-02-30 09:30:00.123456-0600")]
    [InlineData("2026-01-15 09:30:00.123456+1500")]
    [InlineData("2026-01-15 09:30:00.1234567-0600")]
    [InlineData("2026-01-15 09:30:00.12345678-0600")]
    [InlineData("2026-01-15T09:30:00.123456-0600")]
    public async Task UnsupportedTimestampIsRejected(string timestamp)
    {
        var result = await Parse("[" + Record().Replace(Timestamp, timestamp) + "]");
        Assert.Equal(UnifiedLogParseError.InvalidTimestamp, Assert.Single(result.Diagnostics).Code);
        Assert.Empty(result.Entries);
    }

    [Theory]
    [InlineData("{}", UnifiedLogParseError.MissingTimestamp)]
    [InlineData("null", UnifiedLogParseError.InvalidRecord)]
    [InlineData("42", UnifiedLogParseError.InvalidRecord)]
    [InlineData("[]", UnifiedLogParseError.InvalidRecord)]
    [InlineData("{\"timestamp\":null}", UnifiedLogParseError.InvalidTimestamp)]
    [InlineData("{\"timestamp\":42}", UnifiedLogParseError.InvalidTimestamp)]
    public async Task InvalidRecordsHaveIndexedDiagnostics(string record, UnifiedLogParseError error)
    {
        var result = await Parse("[" + Record() + "," + record + "," + Record() + "]");
        Assert.Equal(UnifiedLogParseStatus.RecordErrors, result.Status);
        Assert.Equal(2, result.Entries.Count);
        Assert.Equal(new UnifiedLogParseDiagnostic(error, 1,
            error == UnifiedLogParseError.InvalidRecord ? null : "timestamp"), Assert.Single(result.Diagnostics));
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("2147483648")]
    [InlineData("1.5")]
    [InlineData("\"42\"")]
    [InlineData("true")]
    public async Task InvalidProcessIdIsRejected(string value)
    {
        var result = await Parse("[" + Record(",\"processID\":" + value) + "]");
        Assert.Equal(UnifiedLogParseError.InvalidProcessId, Assert.Single(result.Diagnostics).Code);
    }

    [Fact]
    public async Task OptionalFieldsUnknownFieldsAndEscapedMessagesArePreserved()
    {
        var message = "<private> \"quoted\"\n世界";
        var json = "[" + Record(",\"processID\":null,\"category\":null,\"messageType\":\"FutureType\",\"unknown\":{\"nested\":[1]},\"eventMessage\":"
            + System.Text.Json.JsonSerializer.Serialize(message)) + "]";
        var entry = Assert.Single((await Parse(json)).Entries);
        Assert.Null(entry.ProcessId);
        Assert.Null(entry.Category);
        Assert.Null(entry.Subsystem);
        Assert.Equal("FutureType", entry.MessageType);
        Assert.Equal(message, entry.EventMessage);
    }

    [Theory]
    [InlineData("subsystem")]
    [InlineData("category")]
    [InlineData("eventMessage")]
    [InlineData("processImagePath")]
    [InlineData("messageType")]
    public async Task InvalidStringTypesAreRejected(string field)
    {
        var result = await Parse("[" + Record(",\"" + field + "\":42") + "]");
        Assert.Equal(UnifiedLogParseError.InvalidFieldType, Assert.Single(result.Diagnostics).Code);
    }

    [Fact]
    public async Task DuplicateKnownPropertiesAreRejectedWithoutLeakingValues()
    {
        var result = await Parse("[" + Record(",\"eventMessage\":\"SECRET\",\"eventMessage\":\"OTHER\"") + "]");
        Assert.Equal(new UnifiedLogParseDiagnostic(UnifiedLogParseError.DuplicateField, 0, "eventMessage"), Assert.Single(result.Diagnostics));
        Assert.DoesNotContain("SECRET", System.Text.Json.JsonSerializer.Serialize(result));
    }

    [Theory]
    [InlineData("")]
    [InlineData("[{")]
    [InlineData("[{},]")]
    [InlineData("[] garbage")]
    [InlineData("log show --style json\n[]")]
    public async Task InvalidDocumentsFailWithoutPartialResults(string json)
    {
        var result = await Parse(json);
        Assert.Equal(UnifiedLogParseStatus.BatchFailure, result.Status);
        Assert.Empty(result.Entries);
        Assert.Equal(UnifiedLogParseError.InvalidJson, Assert.Single(result.Diagnostics).Code);
    }

    [Fact]
    public async Task TruncationAfterValidRecordStillFailsWholeBatch()
    {
        var result = await Parse("[" + Record() + ",{");
        Assert.Equal(UnifiedLogParseStatus.BatchFailure, result.Status);
        Assert.Empty(result.Entries);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("42")]
    public async Task WrongRootFails(string json) => Assert.Equal(UnifiedLogParseError.InvalidRoot,
        Assert.Single((await Parse(json)).Diagnostics).Code);

    [Fact]
    public async Task EmptyAllInvalidAndDuplicateRecordsRemainDistinct()
    {
        Assert.Equal(UnifiedLogParseStatus.Success, (await Parse("[]")).Status);
        Assert.Equal(UnifiedLogParseStatus.RecordErrors, (await Parse("[{}]")).Status);
        var result = await Parse("[" + Record(",\"processID\":1") + "," + Record(",\"processID\":2") + "," + Record(",\"processID\":1") + "]");
        Assert.Equal(new int?[] { 1, 2, 1 }, result.Entries.Select(x => x.ProcessId));
    }

    [Fact]
    public async Task ByteAndDepthLimitsAreEnforced()
    {
        Assert.Equal(UnifiedLogParseStatus.Success, (await Parse("[]", new() { MaxInputBytes = 2 })).Status);
        Assert.Equal(UnifiedLogParseError.InputTooLarge, Assert.Single((await Parse("[] ", new() { MaxInputBytes = 2 })).Diagnostics).Code);
        Assert.Equal(UnifiedLogParseError.InvalidJson, Assert.Single((await Parse("[[[]]]", new() { MaxDepth = 2 })).Diagnostics).Code);
        using var stream = new ShortReadStream(Encoding.UTF8.GetBytes("[] "));
        Assert.Equal(UnifiedLogParseError.InputTooLarge, Assert.Single((await new UnifiedLogParser(new() { MaxInputBytes = 2 }).ParseBatchAsync(stream)).Diagnostics).Code);
    }

    [Fact]
    public async Task ShortReadsNonSeekableStreamsAndOwnershipAreSupported()
    {
        using var stream = new ShortReadStream(Encoding.UTF8.GetBytes("[" + Record() + "]"));
        Assert.Single((await new UnifiedLogParser().ParseBatchAsync(stream)).Entries);
        Assert.True(stream.CanRead);
    }

    [Fact]
    public async Task CancellationAndIoErrorsPropagate()
    {
        using var source = new CancellationTokenSource();
        source.Cancel();
        using var stream = new MemoryStream();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new UnifiedLogParser().ParseBatchAsync(stream, source.Token));
        using var failing = new ShortReadStream([], fail: true);
        await Assert.ThrowsAsync<IOException>(() => new UnifiedLogParser().ParseBatchAsync(failing));
        using var midRead = new ShortReadStream([], cancel: true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new UnifiedLogParser().ParseBatchAsync(midRead));
    }

    [Fact]
    public void InvalidOptionsAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnifiedLogParser(new() { MaxInputBytes = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnifiedLogParser(new() { MaxDepth = 0 }));
    }

    [Fact]
    public async Task IdentityFieldsPreserveGuidAndFullUnsignedRange()
    {
        var result = await Parse("[" + Record(",\"bootUUID\":\"12345678-9ABC-4DEF-8123-123456789ABC\",\"machTimestamp\":18446744073709551615,\"threadID\":18446744073709551615") + "]");
        Assert.Equal(UnifiedLogParseStatus.Success, result.Status);
        var entry = Assert.Single(result.Entries);
        Assert.Equal(Guid.Parse("12345678-9abc-4def-8123-123456789abc"), entry.BootUuid);
        Assert.Equal(ulong.MaxValue, entry.MachTimestamp);
        Assert.Equal(ulong.MaxValue, entry.ThreadId);
    }

    [Theory]
    [InlineData("")]
    [InlineData(",\"bootUUID\":\"\"")]
    [InlineData(",\"bootUUID\":null,\"machTimestamp\":null,\"threadID\":null")]
    public async Task MissingOrNullIdentityFieldsRemainNull(string fields)
    {
        var result = await Parse("[" + Record(fields) + "]");
        Assert.Equal(UnifiedLogParseStatus.Success, result.Status);
        var entry = Assert.Single(result.Entries);
        Assert.Null(entry.BootUuid);
        Assert.Null(entry.MachTimestamp);
        Assert.Null(entry.ThreadId);
    }

    [Fact]
    public async Task ZeroIdentityValuesAreDistinctFromMissingValues()
    {
        var result = await Parse("[" + Record(",\"bootUUID\":\"00000000-0000-0000-0000-000000000000\",\"machTimestamp\":0,\"threadID\":0") + "]");
        Assert.Equal(UnifiedLogParseStatus.Success, result.Status);
        var entry = Assert.Single(result.Entries);
        Assert.Equal(Guid.Empty, entry.BootUuid);
        Assert.Equal(0UL, entry.MachTimestamp);
        Assert.Equal(0UL, entry.ThreadId);
    }

    [Theory]
    [InlineData("bootUUID", "\"invalid-private-value\"")]
    [InlineData("bootUUID", "42")]
    [InlineData("bootUUID", "{}")]
    [InlineData("bootUUID", "\"123456789abc4def8123123456789abc\"")]
    [InlineData("machTimestamp", "-1")]
    [InlineData("machTimestamp", "1.5")]
    [InlineData("machTimestamp", "18446744073709551616")]
    [InlineData("machTimestamp", "\"42\"")]
    [InlineData("machTimestamp", "true")]
    [InlineData("threadID", "-1")]
    [InlineData("threadID", "1.5")]
    [InlineData("threadID", "18446744073709551616")]
    [InlineData("threadID", "\"42\"")]
    [InlineData("threadID", "[]")]
    public async Task InvalidIdentityFieldsRejectOnlyTheirRecord(string field, string value)
    {
        var result = await Parse("[" + Record() + "," + Record(",\"" + field + "\":" + value) + "," + Record() + "]");
        Assert.Equal(UnifiedLogParseStatus.RecordErrors, result.Status);
        Assert.Equal(2, result.Entries.Count);
        Assert.Equal(new UnifiedLogParseDiagnostic(UnifiedLogParseError.InvalidFieldValue, 1, field),
            Assert.Single(result.Diagnostics));
    }

    [Theory]
    [InlineData("bootUUID")]
    [InlineData("machTimestamp")]
    [InlineData("threadID")]
    public async Task DuplicateIdentityFieldsAreRejected(string field)
    {
        var result = await Parse("[" + Record(",\"" + field + "\":null,\"" + field + "\":null") + "]");
        Assert.Empty(result.Entries);
        Assert.Equal(new UnifiedLogParseDiagnostic(UnifiedLogParseError.DuplicateField, 0, field),
            Assert.Single(result.Diagnostics));
    }

    private sealed class ShortReadStream(byte[] bytes, bool fail = false, bool cancel = false) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (fail) throw new IOException("Synthetic I/O failure");
            if (cancel) throw new OperationCanceledException();
            return base.ReadAsync(buffer[..Math.Min(3, buffer.Length)], cancellationToken);
        }
    }
}
