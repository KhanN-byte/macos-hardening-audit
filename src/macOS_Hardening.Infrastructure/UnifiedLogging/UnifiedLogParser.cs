// Parses bounded JSON batches into raw log entries and record-level diagnostics.

using System.Globalization;
using System.Text.Json;

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public sealed class UnifiedLogParser
{
    private readonly UnifiedLogParserOptions options;

    public UnifiedLogParser(UnifiedLogParserOptions? options = null)
    {
        this.options = options ?? new();
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(this.options.MaxInputBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(this.options.MaxDepth);
    }

    // The caller owns the input stream. A batch is returned only after complete JSON validation.
    public async Task<UnifiedLogParseResult> ParseBatchAsync(
        Stream utf8Json, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(utf8Json);
        cancellationToken.ThrowIfCancellationRequested();
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            // Read at most one byte beyond the limit, including on non-seekable streams.
            var length = (int)Math.Min(chunk.Length, options.MaxInputBytes - buffer.Length + 1L);
            var count = await utf8Json.ReadAsync(chunk.AsMemory(0, length), cancellationToken);
            if (count == 0) break;
            if (buffer.Length + count > options.MaxInputBytes)
                return Failure(UnifiedLogParseError.InputTooLarge);
            buffer.Write(chunk, 0, count);
        }
        cancellationToken.ThrowIfCancellationRequested();

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(buffer.GetBuffer().AsMemory(0, (int)buffer.Length),
                new JsonDocumentOptions { MaxDepth = options.MaxDepth });
        }
        catch (JsonException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Failure(UnifiedLogParseError.InvalidJson);
        }

        using (document)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (document.RootElement.ValueKind != JsonValueKind.Array)
                return Failure(UnifiedLogParseError.InvalidRoot);
            var entries = new List<UnifiedLogEntry>();
            var diagnostics = new List<UnifiedLogParseDiagnostic>();
            var index = 0;
            foreach (var element in document.RootElement.EnumerateArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                ReadRecord(element, index++, entries, diagnostics);
            }
            return new(diagnostics.Count == 0 ? UnifiedLogParseStatus.Success : UnifiedLogParseStatus.RecordErrors,
                entries.AsReadOnly(), diagnostics.AsReadOnly());
        }
    }

    private static UnifiedLogParseResult Failure(UnifiedLogParseError code) =>
        new(UnifiedLogParseStatus.BatchFailure, Array.Empty<UnifiedLogEntry>(),
            Array.AsReadOnly(new[] { new UnifiedLogParseDiagnostic(code) }));

    // Shared by batch and live readers after JSON framing has been validated.
    internal static UnifiedLogParseResult ParseRecord(JsonElement element, int index)
    {
        var entries = new List<UnifiedLogEntry>();
        var diagnostics = new List<UnifiedLogParseDiagnostic>();
        ReadRecord(element, index, entries, diagnostics);
        return new(diagnostics.Count == 0 ? UnifiedLogParseStatus.Success : UnifiedLogParseStatus.RecordErrors,
            entries.AsReadOnly(), diagnostics.AsReadOnly());
    }

    private static bool IsKnown(string name) => name is "timestamp" or "processID" or
        "subsystem" or "category" or "eventMessage" or "processImagePath" or "messageType" or "bootUUID" or "machTimestamp" or "threadID";

    private static void ReadRecord(JsonElement element, int index,
        List<UnifiedLogEntry> entries, List<UnifiedLogParseDiagnostic> diagnostics)
    {
        void Error(UnifiedLogParseError code, string? field = null) => diagnostics.Add(new(code, index, field));
        if (element.ValueKind != JsonValueKind.Object)
        {
            Error(UnifiedLogParseError.InvalidRecord);
            return;
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (IsKnown(property.Name) && !seen.Add(property.Name))
            {
                Error(UnifiedLogParseError.DuplicateField, property.Name);
                return;
            }
        }
        if (!element.TryGetProperty("timestamp", out var timestamp))
        {
            Error(UnifiedLogParseError.MissingTimestamp, "timestamp");
            return;
        }
        if (timestamp.ValueKind != JsonValueKind.String || !TryTimestamp(timestamp.GetString()!, out var time))
        {
            Error(UnifiedLogParseError.InvalidTimestamp, "timestamp");
            return;
        }
        int? processId = null;
        if (element.TryGetProperty("processID", out var pid) && pid.ValueKind != JsonValueKind.Null)
        {
            if (pid.ValueKind != JsonValueKind.Number || !pid.TryGetInt32(out var number) || number < 0)
            {
                Error(UnifiedLogParseError.InvalidProcessId, "processID");
                return;
            }
            processId = number;
        }
        Guid? bootUuid = null;
        if (element.TryGetProperty("bootUUID", out var boot) && boot.ValueKind != JsonValueKind.Null)
        {
            if (boot.ValueKind != JsonValueKind.String)
            {
                Error(UnifiedLogParseError.InvalidFieldValue, "bootUUID");
                return;
            }

            var value = boot.GetString();
            if (!string.IsNullOrEmpty(value))
            {
                if (!Guid.TryParseExact(value, "D", out var parsedBootUuid))
                {
                    Error(UnifiedLogParseError.InvalidFieldValue, "bootUUID");
                    return;
                }
                bootUuid = parsedBootUuid;
            }
        }

        bool TryReadUInt64(string name, out ulong? value)
        {
            value = null;
            if (!element.TryGetProperty(name, out var property) || property.ValueKind == JsonValueKind.Null)
                return true;

            if (property.ValueKind != JsonValueKind.Number || !property.TryGetUInt64(out var number))
            {
                Error(UnifiedLogParseError.InvalidFieldValue, name);
                return false;
            }
            value = number;
            return true;
        }

        if (!TryReadUInt64("machTimestamp", out var machTimestamp) ||
            !TryReadUInt64("threadID", out var threadId))
            return;

        foreach (var name in seen)
        {
            if (name is "timestamp" or "processID" or "bootUUID" or "machTimestamp" or "threadID") continue;
            if (element.GetProperty(name).ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
            {
                Error(UnifiedLogParseError.InvalidFieldType, name);
                return;
            }
        }
        string? Text(string name) => element.TryGetProperty(name, out var value) ? value.GetString() : null;
        entries.Add(new UnifiedLogEntry
        {
            Timestamp = time, ProcessId = processId, Subsystem = Text("subsystem"),
            Category = Text("category"), EventMessage = Text("eventMessage"),
            ProcessImagePath = Text("processImagePath"), MessageType = Text("messageType"),
            BootUuid = bootUuid, MachTimestamp = machTimestamp, ThreadId = threadId
        });
    }

    private static bool TryTimestamp(string value, out DateTimeOffset timestamp)
    {
        timestamp = default;
        // Fixture-backed Apple format: six fractional digits and an explicit ±HHmm offset.
        if (value.Length != 31 || value[26] is not ('+' or '-')) return false;
        var normalized = value.Insert(29, ":");
        return DateTimeOffset.TryParseExact(normalized, "yyyy-MM-dd HH:mm:ss.ffffffzzz",
            CultureInfo.InvariantCulture, DateTimeStyles.None, out timestamp);
    }
}
