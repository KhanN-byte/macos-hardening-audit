// Configures and runs the worker host.

using macOS_Hardening.User.Workers;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddHostedService<AuthenticationWorker>();

var host = builder.Build();

await host.RunAsync();
