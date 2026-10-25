// Configures the host and connects opt-in Unified Logging collection.

using macOS_Hardening.Core.Detection;
using macOS_Hardening.Infrastructure.Storage;
using macOS_Hardening.Infrastructure.UnifiedLogging;
using macOS_Hardening.User;
using macOS_Hardening.User.Workers;

var builder = Host.CreateApplicationBuilder(args);
var monitoring = builder.Configuration.GetSection("Monitoring").Get<MonitoringOptions>() ?? new();
var collection = builder.Configuration.GetSection("Collection").Get<UnifiedLogCollectionOptions>() ?? new();
var storage = builder.Configuration.GetSection("Storage").Get<SecurityEventStoreOptions>() ?? new();
if (!Path.IsPathRooted(storage.Directory))
    storage.Directory = Path.GetFullPath(storage.Directory, builder.Environment.ContentRootPath);
monitoring.Validate();
collection.Validate();
storage.Validate();

builder.Services.AddSingleton(monitoring);
builder.Services.AddSingleton(collection);
builder.Services.AddSingleton(storage);
builder.Services.AddSingleton(new RepeatedFailureOptions
{
    DetectionWindow = TimeSpan.FromMinutes(monitoring.DetectionWindowMinutes),
    AlertCooldown = TimeSpan.FromMinutes(monitoring.AlertCooldownMinutes),
    WarningThreshold = monitoring.FailedAttemptsThreshold,
    SevereThreshold = monitoring.SevereAttemptsThreshold,
    CriticalThreshold = monitoring.CriticalAttemptsThreshold
});
builder.Services.AddSingleton<RepeatedFailureDetector>();
builder.Services.AddSingleton<ISecurityEventStore, JsonlSecurityEventStore>();
builder.Services.AddSingleton<IUnifiedLogProcessFactory, UnifiedLogProcessFactory>();
builder.Services.AddSingleton<ISystemBootIdProvider, MacOsSystemBootIdProvider>();
builder.Services.AddSingleton<UnifiedLogCollector>();
builder.Services.AddSingleton<ScreenUnlockFailureMapper>();
builder.Services.AddSingleton(new UnifiedLogDeduplicator(
    TimeSpan.FromSeconds(monitoring.DeduplicationRetentionSeconds), monitoring.DeduplicationCapacity));
builder.Services.AddHostedService<AuthenticationWorker>();

using var host = builder.Build();
await host.RunAsync();
