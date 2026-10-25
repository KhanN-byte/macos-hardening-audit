// Defines the user-facing urgency assigned to a repeated authentication failure alert.

namespace macOS_Hardening.Contracts.Models;

public enum AlertSeverity
{
    Warning = 1,
    Severe = 2,
    Critical = 3
}
