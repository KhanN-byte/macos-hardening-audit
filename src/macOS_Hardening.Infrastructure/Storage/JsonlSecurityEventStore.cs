// Persists normalized events and alerts as rotating, recoverable JSON Lines files.

using System.Text.Json;
using macOS_Hardening.Contracts.Models;

namespace macOS_Hardening.Infrastructure.Storage;

public sealed class JsonlSecurityEventStore(SecurityEventStoreOptions options) : ISecurityEventStore, IDisposable
{
    private const string FilePrefix = "security-events-";
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly JsonSerializerOptions serializerOptions = new(JsonSerializerDefaults.Web);

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        options.Validate();
        System.IO.Directory.CreateDirectory(options.Directory);
        SetDirectoryPermissions();
        await DeleteExpiredFilesAsync(cancellationToken);
    }

    public Task AppendAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken) =>
        AppendEnvelopeAsync(new StoredRecord { Kind = "authenticationEvent", AuthenticationEvent = authenticationEvent }, cancellationToken);

    public Task AppendAsync(SecurityAlert alert, CancellationToken cancellationToken) =>
        AppendEnvelopeAsync(new StoredRecord { Kind = "securityAlert", SecurityAlert = alert }, cancellationToken);

    public async Task<SecurityEventStoreRecovery> RecoverAsync(DateTimeOffset since, CancellationToken cancellationToken)
    {
        var events = new List<AuthenticationEvent>();
        SecurityAlert? latestAlert = null;
        var malformed = 0;
        foreach (var path in EnumerateFiles())
        {
            await foreach (var line in File.ReadLinesAsync(path, cancellationToken))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var record = JsonSerializer.Deserialize<StoredRecord>(line, serializerOptions);
                    if (record?.Kind == "authenticationEvent" && record.AuthenticationEvent is { } authenticationEvent)
                    {
                        if (authenticationEvent.Timestamp >= since) events.Add(authenticationEvent);
                    }
                    else if (record?.Kind == "securityAlert" && record.SecurityAlert is { } alert)
                    {
                        if (latestAlert is null || alert.WindowEnd > latestAlert.WindowEnd) latestAlert = alert;
                    }
                    else malformed++;
                }
                catch (JsonException) { malformed++; }
            }
        }
        events.Sort((left, right) => left.Timestamp.CompareTo(right.Timestamp));
        return new(events, latestAlert, malformed);
    }

    public void Dispose() => gate.Dispose();

    private async Task AppendEnvelopeAsync(StoredRecord record, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var line = JsonSerializer.Serialize(record, serializerOptions) + Environment.NewLine;
            var path = SelectCurrentFile(DateTimeOffset.UtcNow, System.Text.Encoding.UTF8.GetByteCount(line));
            await File.AppendAllTextAsync(path, line, cancellationToken);
            SetFilePermissions(path);
        }
        finally { gate.Release(); }
    }

    private string SelectCurrentFile(DateTimeOffset now, int newBytes)
    {
        var date = now.UtcDateTime.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture);
        for (var sequence = 0; ; sequence++)
        {
            var path = Path.Combine(options.Directory, $"{FilePrefix}{date}-{sequence:D3}.jsonl");
            if (!File.Exists(path) || new FileInfo(path).Length + newBytes <= options.MaxFileBytes) return path;
        }
    }

    private IEnumerable<string> EnumerateFiles() => System.IO.Directory
        .EnumerateFiles(options.Directory, $"{FilePrefix}????????-???.jsonl", SearchOption.TopDirectoryOnly)
        .Order(StringComparer.Ordinal);

    private Task DeleteExpiredFilesAsync(CancellationToken cancellationToken)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-options.RetentionDays);
        foreach (var path in EnumerateFiles())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (File.GetLastWriteTimeUtc(path) < cutoff.UtcDateTime) File.Delete(path);
        }
        return Task.CompletedTask;
    }

    private void SetDirectoryPermissions()
    {
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(options.Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private static void SetFilePermissions(string path)
    {
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private sealed record StoredRecord
    {
        public int Version { get; init; } = 1;
        public required string Kind { get; init; }
        public AuthenticationEvent? AuthenticationEvent { get; init; }
        public SecurityAlert? SecurityAlert { get; init; }
    }
}
