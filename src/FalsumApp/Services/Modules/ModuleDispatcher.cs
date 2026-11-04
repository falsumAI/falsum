// Routes module card actions to native C# implementations.
// As .ps1 modules are ported, their (moduleDir, action) pairs register here.
// Anything not yet registered keeps using the legacy PowerShell engine until
// its port lands. When the last module ports, the engine gets deleted.
namespace FalsumApp.Services.Modules;

public static class ModuleDispatcher
{
    public static bool IsNative(string moduleDir, string action)
        => (moduleDir, action) switch
        {
            ("41-quantum-shield", "Get-QuantumShieldStats") => true,
            ("42-agent-watchdog", "Get-WatchdogAgentActivity") => true,
            ("43-hashline", "Get-HashlineStats") => true,
            ("44-port-gate", "Invoke-PortGateAudit") => true,
            ("45-router-tracker", "Test-RouterLoginAnomaly") => true,
            // Module 30's file-queue bridge is superseded: Falsum.exe IS the
            // native host now (named pipe FalsumGate). This reports that state.
            ("30-bridge", "Initialize-Bridge") => true,
            _ => false,
        };

    public static List<ModuleResult> Run(string moduleDir, string action)
        => (moduleDir, action) switch
        {
            ("41-quantum-shield", "Get-QuantumShieldStats") => QuantumShieldModule.GetStats(),
            ("42-agent-watchdog", "Get-WatchdogAgentActivity") => AgentWatchdogModule.GetAgentActivity(),
            ("43-hashline", "Get-HashlineStats") => HashlineModule.GetStats(),
            ("44-port-gate", "Invoke-PortGateAudit") => PortGateModule.Audit(),
            ("45-router-tracker", "Test-RouterLoginAnomaly") => RouterTrackerModule.TestAnomaly(),
            ("30-bridge", "Initialize-Bridge") => new List<ModuleResult>
            {
                ModuleResult.Pass("Bridge",
                    "Native bridge active: Falsum.exe is the browser native host over named pipe FalsumGate. The old file-queue bridge is retired.")
            },
            _ => throw new InvalidOperationException($"No native implementation for {moduleDir}/{action} yet."),
        };
}
