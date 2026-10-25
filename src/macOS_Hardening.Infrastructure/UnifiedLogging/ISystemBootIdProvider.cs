// Supplies a stable identifier for the current boot when live records omit it.

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public interface ISystemBootIdProvider
{
    Guid GetCurrentBootId();
}
