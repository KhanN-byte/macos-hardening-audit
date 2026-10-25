// Reads the current macOS boot-session UUID once and validates its shape.

using System.Diagnostics;

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public sealed class MacOsSystemBootIdProvider : ISystemBootIdProvider
{
    private readonly Lazy<Guid> bootId = new(ReadBootId,
        LazyThreadSafetyMode.ExecutionAndPublication);

    public Guid GetCurrentBootId() => bootId.Value;

    private static Guid ReadBootId()
    {
        if (!OperatingSystem.IsMacOS())
            throw new PlatformNotSupportedException("Boot-session UUID lookup requires macOS.");

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("/usr/sbin/sysctl")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                ArgumentList = { "-n", "kern.bootsessionuuid" }
            }
        };

        if (!process.Start())
            throw new IOException("Unable to read the current boot-session UUID.");

        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0 || error.Length != 0 ||
            !Guid.TryParseExact(output.Trim(), "D", out var result) ||
            result == Guid.Empty)
            throw new IOException("The current boot-session UUID is unavailable.");

        return result;
    }
}
