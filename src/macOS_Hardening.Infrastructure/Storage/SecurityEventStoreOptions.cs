// Configures bounded local JSON Lines storage for normalized security records.

namespace macOS_Hardening.Infrastructure.Storage;

public sealed class SecurityEventStoreOptions
{
    public string Directory { get; set; } = "./data";
    public int RetentionDays { get; set; } = 7;
    public long MaxFileBytes { get; set; } = 10 * 1024 * 1024;

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Directory)) throw new ArgumentException("Storage directory is required.", nameof(Directory));
        if (RetentionDays is < 1 or > 3650) throw new ArgumentOutOfRangeException(nameof(RetentionDays));
        if (MaxFileBytes is < 1024 or > 1024L * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(MaxFileBytes));
    }
}
