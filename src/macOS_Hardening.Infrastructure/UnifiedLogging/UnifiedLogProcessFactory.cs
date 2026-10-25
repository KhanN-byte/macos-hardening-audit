// Starts the native log command without a shell and owns child-process cleanup.

using System.Diagnostics;

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public sealed class UnifiedLogProcessFactory : IUnifiedLogProcessFactory
{
    public IUnifiedLogProcess Start(UnifiedLogCollectionOptions options)
    {
        options.Validate();
        if (!OperatingSystem.IsMacOS())
            throw new PlatformNotSupportedException("Unified Logging collection requires macOS.");
        var info = new ProcessStartInfo(options.ExecutablePath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in new[] { "stream", "--style", "json", "--level", "info", "--predicate", options.Predicate })
            info.ArgumentList.Add(argument);
        var process = new Process { StartInfo = info };
        try
        {
            if (!process.Start()) throw new IOException("Unable to start log process.");
            return new NativeProcess(process, TimeSpan.FromSeconds(options.ShutdownSeconds));
        }
        catch { process.Dispose(); throw; }
    }

    private sealed class NativeProcess(Process process, TimeSpan shutdown) : IUnifiedLogProcess
    {
        public Stream StandardOutput => process.StandardOutput.BaseStream;
        public Stream StandardError => process.StandardError.BaseStream;

        public async Task<int> WaitForExitAsync(CancellationToken cancellationToken)
        {
            await process.WaitForExitAsync(cancellationToken);
            return process.ExitCode;
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                catch (InvalidOperationException) { /* Process exited between the check and kill. */ }
                await process.WaitForExitAsync().WaitAsync(shutdown);
            }
            finally { process.Dispose(); }
        }
    }
}
