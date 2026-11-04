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
            ("00-coherence-core", "Test-Coherence") => true,
            ("15-web-proxy", "Get-ProxyState") => true,
            ("22-tracker-block", "Test-TrackerBlockHealth") => true,
            ("23-fraud-pack", "New-FraudManifest") => true,
            ("25-purge", "Invoke-PurgeScan") => true,
            ("12-timeline-vault", "New-Vault") => true,
            ("19-wifi-router", "Test-RouterPorts") => true,
            ("08-breach-cleaner", "Test-HibpConnection") => true,
            ("18-scam-shield", "Start-ScamCheck") => true,
            ("16-mail-shield", "Test-PhishingSignals") => true,
            ("17-photo-scrub", "Test-PhotoScrubHygiene") => true,
            ("01-evidence-sweep", "Test-SweepHygiene") => true,
            ("02-packet-witness", "Start-Capture") => true,
            ("03-netscan", "Test-TargetSpec") => true,
            ("04-osint-attribution", "Test-OsintInput") => true,
            ("05-people-track", "Test-Username") => true,
            ("14-bugbounty", "Start-BountyRecon") => true,
            ("06-vuln-check", "Test-WeakConfigs") => true,
            ("07-php-shield", "Test-PhpInstalls") => true,
            ("10-trap-network", "Start-TrapListener") => true,
            ("11-active-defense", "Start-Backtrace") => true,
            ("13-native-chat", "Get-ModelStatus") => true,
            ("38-learning-ai", "Start-FalsumChatLoop") => true,
            ("24-mobile-shield", "Invoke-BackupStalkerwareScan") => true,
            ("20-backup-shield", "New-BackupPlan") => true,
            ("46-vscode-gate", "Invoke-VSCodeGateAudit") => true,
            ("47-cert-verifier", "Invoke-CertAudit") => true,
            ("48-group-policy", "Invoke-GroupPolicyAudit") => true,
            ("49-binary-translator", "Invoke-BinaryTranslate") => true,
            ("50-predator-vault", "Invoke-PredatorScan") => true,
            ("50-predator-vault", "Invoke-PredatorBlock") => true,
            ("51-superintelligence", "Invoke-SuperintelligenceAudit") => true,
            ("52-complaint-engine", "Invoke-ComplaintAudit") => true,
            ("53-fraud-patterns", "Invoke-FraudDetect") => true,
            ("54-badactor-stamp", "Invoke-StampAudit") => true,
            ("55-knowledge-updater", "Invoke-KnowledgeAudit") => true,
            ("55-knowledge-updater", "Invoke-KnowledgeUpdate") => true,
            ("56-fleet", "Invoke-FleetAudit") => true,
            ("57-ram-manager", "Invoke-RamAudit") => true,
            ("58-local-rag", "Invoke-RagAudit") => true,
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
            ("00-coherence-core", "Test-Coherence") => CoherenceModule.Hygiene(),
            ("15-web-proxy", "Get-ProxyState") => WebProxyModule.GetProxyState(),
            ("22-tracker-block", "Test-TrackerBlockHealth") => TrackerBlockModule.Health(),
            ("23-fraud-pack", "New-FraudManifest") => FraudPackModule.SealManifest(),
            ("25-purge", "Invoke-PurgeScan") => PurgeModule.Scan(),
            ("12-timeline-vault", "New-Vault") => TimelineVaultModule.NewVault(),
            ("19-wifi-router", "Test-RouterPorts") => WifiRouterModule.TestRouterPorts(),
            ("08-breach-cleaner", "Test-HibpConnection") => BreachCleanerModule.TestHibpConnection(),
            ("18-scam-shield", "Start-ScamCheck") => ScamShieldModule.Hygiene(),
            ("16-mail-shield", "Test-PhishingSignals") => MailShieldModule.Hygiene(),
            ("17-photo-scrub", "Test-PhotoScrubHygiene") => PhotoScrubModule.Hygiene(),
            ("01-evidence-sweep", "Test-SweepHygiene") => EvidenceSweepModule.Hygiene(),
            ("02-packet-witness", "Start-Capture") => PacketWitnessModule.PreFlight(),
            ("03-netscan", "Test-TargetSpec") => NetScanModule.ValidateDefault(),
            ("04-osint-attribution", "Test-OsintInput") => OsintAttributionModule.Hygiene(),
            ("05-people-track", "Test-Username") => PeopleTrackModule.Hygiene(),
            ("14-bugbounty", "Start-BountyRecon") => BugBountyModule.ScopeStatus(),
            ("06-vuln-check", "Test-WeakConfigs") => VulnCheckModule.TestWeakConfigs(),
            ("07-php-shield", "Test-PhpInstalls") => PhpShieldModule.Scan(),
            ("10-trap-network", "Start-TrapListener") => TrapNetworkModule.Catalog(),
            ("11-active-defense", "Start-Backtrace") => ActiveDefenseModule.GateCheck(),
            ("13-native-chat", "Get-ModelStatus") => NativeChatModule.ModelStatus(),
            ("38-learning-ai", "Start-FalsumChatLoop") => LearningAiModule.Health(),
            ("24-mobile-shield", "Invoke-BackupStalkerwareScan") => MobileShieldModule.ScanBackups(),
            ("20-backup-shield", "New-BackupPlan") => BackupShieldModule.DefaultPlanCheck(),
            ("46-vscode-gate", "Invoke-VSCodeGateAudit") => VSCodeGateModule.Audit(),
            ("47-cert-verifier", "Invoke-CertAudit") => CertVerifierModule.Audit(),
            ("48-group-policy", "Invoke-GroupPolicyAudit") => GroupPolicyModule.AuditPolicies(),
            ("49-binary-translator", "Invoke-BinaryTranslate") => BinaryTranslatorModule.TranslateFile(
                System.Reflection.Assembly.GetExecutingAssembly().Location),
            ("50-predator-vault", "Invoke-PredatorScan") => PredatoryAlgorithmVault.Scan(),
            ("50-predator-vault", "Invoke-PredatorBlock") => PredatoryAlgorithmVault.BlockAll(),
            ("51-superintelligence", "Invoke-SuperintelligenceAudit") => SuperintelligenceModule.Audit(),
            ("52-complaint-engine", "Invoke-ComplaintAudit") => ComplaintEngineModule.Audit(),
            ("53-fraud-patterns", "Invoke-FraudDetect") => FraudPatternModule.Detect(),
            ("54-badactor-stamp", "Invoke-StampAudit") => BadActorStampModule.Audit(),
            ("55-knowledge-updater", "Invoke-KnowledgeAudit") => KnowledgeUpdaterModule.Audit(),
            ("55-knowledge-updater", "Invoke-KnowledgeUpdate") => KnowledgeUpdaterModule.CheckForUpdates(),
            ("56-fleet", "Invoke-FleetAudit") => FleetModule.Audit(),
            ("57-ram-manager", "Invoke-RamAudit") => RamManagerModule.Audit(),
            ("58-local-rag", "Invoke-RagAudit") => LocalRagModule.Audit(),
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
