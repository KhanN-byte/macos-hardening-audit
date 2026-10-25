// Tests the observed live array framing, partial input, limits, and record validation.

using System.Text.Json;
using macOS_Hardening.Infrastructure.UnifiedLogging;
using Xunit;
using static macOS_Hardening.UnitTests.CollectionTestSupport;

namespace macOS_Hardening.UnitTests;

public sealed class UnifiedLogStreamReaderTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8192)]
    public async Task BannerAndFragmentedMultilineObjectsReuseRecordValidation(int chunk)
    {
        var message = "braces { [ ] } and \"quotes\" \\ newline\n世界";
        using var stream = new Input("Filtering the log data using \"test\"\r\n[\n" + Record(message) + ",{}," + Record() + "\n]", chunk);
        var results = await ReadAll(stream);
        Assert.Equal(3, results.Count);
        Assert.Equal(message, Assert.Single(results[0].Entries).EventMessage);
        Assert.Equal(UnifiedLogParseError.MissingTimestamp, Assert.Single(results[1].Diagnostics).Code);
        Assert.Equal(1, results[1].Diagnostics[0].RecordIndex);
        Assert.Single(results[2].Entries);
    }

    [Fact]
    public async Task DeliversRecordBeforeClosingArrayAndCancelsPendingRead()
    {
        using var stop = new CancellationTokenSource();
        using var input = new Input("[" + Record(), holdOpen: true);
        await using var iterator = new UnifiedLogStreamReader().ReadAsync(input, stop.Token).GetAsyncEnumerator();
        Assert.True(await iterator.MoveNextAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Single(iterator.Current.Entries);
        var pending = iterator.MoveNextAsync().AsTask();
        await input.Waiting.Task.WaitAsync(TimeSpan.FromSeconds(5));
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
    }

    [Theory]
    [InlineData("")]
    [InlineData("[{")]
    [InlineData("garbage[]")]
    [InlineData("Filtering unexpected text\n[]")]
    [InlineData("[{},]")]
    [InlineData("[{}{}]")]
    [InlineData("[] trailing")]
    [InlineData("[42]")]
    public async Task MalformedFramingFailsExplicitly(string text)
    {
        using var input = new Input(text, 1);
        await Assert.ThrowsAsync<InvalidDataException>(() => ReadAll(input));
    }

    [Fact]
    public async Task InvalidJsonInsideCompleteFrameFails()
    {
        using var input = new Input("[{\"timestamp\":invalid}]");
        await Assert.ThrowsAnyAsync<JsonException>(() => ReadAll(input));
    }

    [Fact]
    public async Task EmptyArraySucceedsAndCallerRetainsStream()
    {
        using var input = new MemoryStream("[]"u8.ToArray());
        Assert.Empty(await ReadAll(input));
        Assert.True(input.CanRead);
    }

    [Fact]
    public async Task LimitsApplyToRecordsDepthAndBanner()
    {
        using var record = new Input("[" + Record() + "]");
        await Assert.ThrowsAsync<InvalidDataException>(() => ReadAll(record, new(64)));
        using var deep = new Input("[{\"extra\":[[[]]]}]");
        await Assert.ThrowsAsync<InvalidDataException>(() => ReadAll(deep, new(1024, 2)));
        using var banner = new Input("Filtering the log data using \"" + new string('x', 4096) + "\"\n[]");
        await Assert.ThrowsAsync<InvalidDataException>(() => ReadAll(banner));
    }

    private static async Task<List<UnifiedLogParseResult>> ReadAll(Stream input, UnifiedLogStreamReader? reader = null)
    {
        var results = new List<UnifiedLogParseResult>();
        await foreach (var result in (reader ?? new()).ReadAsync(input)) results.Add(result);
        return results;
    }
}
