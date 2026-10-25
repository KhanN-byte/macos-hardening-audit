// Isolates native process I/O so collector behavior can be tested without macOS logs.

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public interface IUnifiedLogProcess : IAsyncDisposable
{
    Stream StandardOutput { get; }
    Stream StandardError { get; }
    Task<int> WaitForExitAsync(CancellationToken cancellationToken);
}

public interface IUnifiedLogProcessFactory
{
    IUnifiedLogProcess Start(UnifiedLogCollectionOptions options);
}
