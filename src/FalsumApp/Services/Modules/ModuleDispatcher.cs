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
            ("26-defender-watch", "Invoke-DefenderWatch") => true,
            ("21-malware-hunter", "Start-MalwareHunt") => true,
            ("27-memory-forensics", "Read-ProcessMemoryBytes") => true,
            ("28-task-killer", "Invoke-TaskKillerAudit") => true,
            ("29-registry-fix", "Invoke-RegistryFixScan") => true,
            ("31-gate", "Invoke-GateAudit") => true,
            ("32-port-control", "Invoke-PortControlWorkflow") => true,
            ("33-command-center", "Test-CommandCenterHygiene") => true,
            ("35-loop-breaker", "Invoke-FalsumLoopBreaker") => true,
            ("36-satellite", "Invoke-FalsumSatelliteScan") => true,
            ("37-datagate", "Get-FalsumDataSummary") => true,
            ("39-chrome-internals", "Invoke-FalsumChromeInternalsScan") => true,
            ("40-browser-liberator", "Get-FalsumBrowserPolicies") => true,
            ("09-broker-eradicator", "Test-BrokerTableValidation") => true,
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
            ("26-defender-watch", "Invoke-DefenderWatch") => DefenderWatchModule.Watch(),
            ("21-malware-hunter", "Start-MalwareHunt") => MalwareHunterModule.Hunt(),
            ("27-memory-forensics", "Read-ProcessMemoryBytes") => MemoryForensicsModule.Overview(),
            ("28-task-killer", "Invoke-TaskKillerAudit") => TaskKillerModule.Audit(),
            ("29-registry-fix", "Invoke-RegistryFixScan") => RegistryFixModule.Scan(),
            ("31-gate", "Invoke-GateAudit") => GateModule.Audit(),
            ("32-port-control", "Invoke-PortControlWorkflow") => PortControlModule.Invoke(),
            ("33-command-center", "Test-CommandCenterHygiene") => CommandCenterModule.Hygiene(),
            ("35-loop-breaker", "Invoke-FalsumLoopBreaker") => LoopBreakerModule.Invoke(),
            ("36-satellite", "Invoke-FalsumSatelliteScan") => SatelliteModule.Scan(),
            ("37-datagate", "Get-FalsumDataSummary") => DataGateModule.GetSummary(),
            ("39-chrome-internals", "Invoke-FalsumChromeInternalsScan") => ChromeInternalsModule.Scan(),
            ("40-browser-liberator", "Get-FalsumBrowserPolicies") => BrowserPolicyScan(),
            ("09-broker-eradicator", "Test-BrokerTableValidation") => BrokerEradicatorModule.Validate(),
            ("30-bridge", "Initialize-Bridge") => new List<ModuleResult>
            {
                ModuleResult.Pass("Bridge",
                    "Native bridge active: Falsum.exe is the browser native host over named pipe FalsumGate. The old file-queue bridge is retired.")
            },
            _ => throw new InvalidOperationException($"No native implementation for {moduleDir}/{action} yet."),
        };

    /// <summary>
    /// Module 40's card action delegates to the existing native
    /// BrowserControlService (policy scan), which already covers it.
    /// </summary>
    private static List<ModuleResult> BrowserPolicyScan()
    {
        var svc = new FalsumApp.Services.BrowserControlService();
        svc.ScanForPolicies();
        var results = new List<ModuleResult>();
        if (svc.DetectedPolicies.Count == 0)
        {
            results.Add(ModuleResult.Pass("BrowserLiberator", "No browser policies locking your settings."));
            return results;
        }
        results.Add(ModuleResult.Fail("BrowserLiberator",
            $"{svc.DetectedPolicies.Count} policies locking browser settings: " +
            string.Join("; ", svc.DetectedPolicies.Take(8).Select(p => $"{p.Name}={p.Value} ({p.Scope})")),
            svc.DetectedPolicies.ToList()));
        return results;
    }
}
