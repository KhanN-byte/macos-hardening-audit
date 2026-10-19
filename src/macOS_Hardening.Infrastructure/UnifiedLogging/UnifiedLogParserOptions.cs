// Sets input-size and nesting limits for batch JSON parsing.

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public sealed record UnifiedLogParserOptions
{
    public int MaxInputBytes { get; init; } = 4 * 1024 * 1024;
    public int MaxDepth { get; init; } = 32;
}
