// Defines durable operations required by the monitoring worker.

using macOS_Hardening.Contracts.Models;

namespace macOS_Hardening.Infrastructure.Storage;

public interface ISecurityEventStore
{
    Task InitializeAsync(CancellationToken cancellationToken);
    Task AppendAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken);
    Task AppendAsync(SecurityAlert alert, CancellationToken cancellationToken);
    Task<SecurityEventStoreRecovery> RecoverAsync(DateTimeOffset since, CancellationToken cancellationToken);
}
