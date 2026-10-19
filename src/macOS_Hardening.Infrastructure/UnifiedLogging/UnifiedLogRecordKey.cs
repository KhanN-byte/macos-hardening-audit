// Create deterministic keys for identiftying replayed Unified Loggin records.

using System.Security.Cryptography;
using System.Text.Json;

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public static class UnifiedLogRecordKey
{

    public static string? Create (UnifiedLogEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

          if (entry.BootUuid is not Guid bootUuid ||
            bootUuid == Guid.Empty ||
            entry.MachTimestamp is not ulong machTimestamp ||
            entry.ThreadId is not ulong threadId ||
            entry.ProcessId is not int processId ||
            processId < 0 ||
            string.IsNullOrEmpty(entry.EventMessage))
        {
            return null;
        }

        using var buffer = new MemoryStream();

        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartArray();

            // Version the encoding so future changes are explicit.
            writer.WriteNumberValue(1);
            writer.WriteStringValue(bootUuid);
            writer.WriteNumberValue(machTimestamp);
            writer.WriteNumberValue(processId);
            writer.WriteNumberValue(threadId);
            writer.WriteStringValue(entry.EventMessage);

            writer.WriteEndArray();
            writer.Flush();
        }

        var hash = SHA256.HashData(buffer.GetBuffer().AsSpan(0, (int)buffer.Length));

        return Convert.ToHexString(hash);
    }
}
