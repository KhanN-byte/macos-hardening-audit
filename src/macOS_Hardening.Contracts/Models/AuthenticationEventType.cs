// Defines authentication event classifications, with Unknown as the default.


namespace macOS_Hardening.Contracts.Models;

public enum AuthEventType
{

    Unknown = 0,
    FailedPasswordScreenUnlock = 1
}
