# ADR 0002: Minimal .NET Worker host and project boundaries

Status: Accepted; updated to reflect the project owner’s requested architecture.

Use one .NET 10 Worker Service host (User), three class libraries (Core, Contracts, Infrastructure), and the existing xUnit test project. This supersedes the earlier single-assembly decision. Reuse the existing projects rather than creating duplicates.

User owns composition, background workers, and configuration. Core owns security detection and domain logic. Contracts owns normalized security event models. Infrastructure owns macOS Unified Logging collection, raw log models, parsing, and persistence.

User references Core and Infrastructure. Core and Infrastructure reference Contracts. Contracts has no project dependencies; Core does not reference Infrastructure. Add further references only when implemented responsibilities require them.

Keep Microsoft.Extensions.Hosting as the only direct runtime NuGet dependency; prefer standard-library APIs. This separation introduces no new detection features, services, databases, or abstractions.
