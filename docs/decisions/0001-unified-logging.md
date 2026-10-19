# ADR-0001: Use Apple Unified Logging

**Status:** Accepted

## Decision

Use the built-in macOS Unified Logging system, accessed initially via the `log` command, to discover and collect candidate authentication records. Do not use the Endpoint Security framework or native extensions.

## Rationale

Reduced entitlement and native bridge complexity; supports a C#-first implementation.

## Constraints

The unified log is not equivalent to a complete authenticated-audit event feed. Different macOS versions and authentication paths may omit, redact or change messages. Event parsing requires tested empirical fixtures and per-source confidence. We must report unsupported/unobservable events and collection failures.

## Revisit if

Evidence shows required failed-login coverage is not obtainable using the Unified Logging source alone; revisit product claims/scope rather than silently switching sources.
