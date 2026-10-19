// Maps the verified loginwindow failure signature to a normalized authentication event.

using macOS_Hardening.Contracts.Models;

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public sealed class ScreenUnlockFailureMapper
{
private const string ErrMsg = "-[LWDefaultScreenLockUI authFailWithMessage:] | enter. INCORRECT password";
private const string filePath = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow";
private const string subsystemPath = "com.apple.loginwindow.logging";
    public AuthenticationEvent? Map (UnifiedLogEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (entry.EventMessage == ErrMsg && entry.Subsystem == subsystemPath && entry.ProcessImagePath == filePath)
           {
               return new AuthenticationEvent
               {
                   Timestamp = entry.Timestamp,
                   EventType = AuthEventType.FailedPasswordScreenUnlock,
                   Source = "macos.unified-logging"
               };
           }
           return null;
    }
}
