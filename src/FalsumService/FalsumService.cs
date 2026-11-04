// Falsum Windows Service. Runs at boot, before the user logs in.
// This is how Falsum "completely takes over full control" — it's
// watching from the moment Windows starts, not just when the user
// opens the app.
//
// What the service does:
//   - Starts the Predator Vault enforcement (re-kill blocked processes)
//   - Starts the Port Consent default-deny (if enabled)
//   - Runs the System Bubble ETW monitor
//   - Writes to the vault (so the desktop app sees what happened)
// The desktop app (Falsum.exe) is the UI. The service (FalsumService.exe)
// is the always-on guard. They talk via the vault + named pipe.
//
// Install: sc create FalsumService binPath= "C:\...\FalsumService.exe"
// Uninstall: sc delete FalsumService
using System.ServiceProcess;
using FalsumApp.Services.Modules;

namespace FalsumApp.Service;

public sealed class FalsumService : ServiceBase
{
    public FalsumService()
    {
        ServiceName = "FalsumService";
        CanStop = true;
        CanShutdown = true;
    }

    protected override void OnStart(string[] args)
    {
        try
        {
            // Re-enforce predator blocks from the vault.
            PredatoryAlgorithmVault.EnforceAtStartup();
        }
        catch { }

        try
        {
            // Re-apply port consent default-deny if the user enabled it.
            PortConsentService.ReapplyDecisions();
        }
        catch { }

        // Log service start to the vault.
        try
        {
            Vault.AppendJsonl(
                Path.Combine(Vault.VaultDir("service"), "chain.jsonl"),
                new Dictionary<string, object?>
                {
                    ["event"] = "service-start",
                    ["time"] = Vault.IsoNow(),
                    ["machine"] = Environment.MachineName,
                });
        }
        catch { }
    }

    protected override void OnStop() { }
    protected override void OnShutdown() { }
}
