using System.Windows;
using System.Windows.Controls;
using FalsumApp.Models;
using FalsumApp.Services;

namespace FalsumApp.Views;

public partial class MainWindow : Window
{
    private PowerShellEngine _engine;
    private readonly string _modulesPath;
    private NativeMessagingHost? _nativeHost;

    public MainWindow()
    {
        InitializeComponent();

        // Modules are deployed alongside the .exe
        _modulesPath = System.IO.Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "modules");

        _engine = new PowerShellEngine(_modulesPath);

        // Start the native messaging bridge so the browser extension can talk to us.
        // Runs on a background thread — Chrome launches us, not the other way around.
        StartNativeBridge();

        LoadModuleCards();
        StatusText.Text = "Ready. Your data never leaves this computer.";
    }

    /// <summary>
    /// Start the native messaging host for the browser extension.
    /// The extension connects via stdin/stdout when Chrome launches the host.
    /// </summary>
    private void StartNativeBridge()
    {
        try
        {
            _nativeHost = new NativeMessagingHost();
            _nativeHost.OnShowDesktopRequested += (s, e) =>
            {
                Dispatcher.Invoke(() =>
                {
                    if (WindowState == WindowState.Minimized)
                        WindowState = WindowState.Normal;
                    Activate();
                    StatusText.Text = "Browser extension requested: showing Falsum.";
                });
            };
            _nativeHost.OnScanRequested += (s, e) =>
            {
                Dispatcher.Invoke(() =>
                {
                    StatusText.Text = "Browser extension requested: running protection scan...";
                    RunProtectAll();
                });
            };

            // Run the listener on a background thread — it blocks on stdin
            var thread = new System.Threading.Thread(_nativeHost.Start)
            {
                IsBackground = true,
                Name = "NativeMessagingHost"
            };
            thread.Start();
        }
        catch (Exception ex)
        {
            // Bridge failure shouldn't kill the app — the extension just won't connect
            StatusText.Text = $"Browser bridge failed to start: {ex.Message}";
        }
    }

    private void LoadModuleCards()
    {
        var cards = new List<ModuleCard>
        {
            // === ONE-CLICK PROTECTION ===
            new() { Icon = "🛡️", Title = "Protect Me", Description = "One click. Falsum checks everything and fixes what it can.", ModuleDir = "", Action = "ProtectAll" },

            // === LOCAL AI (Gregg's drift math = the beast) ===
            new() { Icon = "🤖", Title = "AI Chat", Description = "Talk to your local AI. It learns from corrections and self-corrects with drift math.", ModuleDir = "38-learning-ai", Action = "Start-FalsumChatLoop" },
            new() { Icon = "🧠", Title = "Coherence Core", Description = "Drift measurement and evidence scoring. The math that makes it a beast.", ModuleDir = "00-coherence-core", Action = "Test-Coherence" },

            // === EVIDENCE & TRUTH ===
            new() { Icon = "📦", Title = "Evidence Vault", Description = "Tamper-evident log of everything Falsum finds.", ModuleDir = "12-timeline-vault", Action = "New-Vault" },
            new() { Icon = "🔍", Title = "Evidence Sweep", Description = "Sweep your system for evidence of tampering.", ModuleDir = "01-evidence-sweep", Action = "Test-SweepHygiene" },
            new() { Icon = "📡", Title = "Packet Witness", Description = "Capture and verify network traffic.", ModuleDir = "02-packet-witness", Action = "Start-Capture" },

            // === NETWORK DEFENSE ===
            new() { Icon = "🌐", Title = "Network Watch", Description = "See every connection. Block what you don't trust.", ModuleDir = "37-datagate", Action = "Get-FalsumDataSummary" },
            new() { Icon = "🗺️", Title = "Net Scan", Description = "Map your network. Find every device.", ModuleDir = "03-netscan", Action = "Test-TargetSpec" },
            new() { Icon = "🔌", Title = "Port Control", Description = "You control every TCP/UDP port. Global and local.", ModuleDir = "32-port-control", Action = "Invoke-PortControlWorkflow" },
            new() { Icon = "📶", Title = "Wi-Fi & Router", Description = "Secure your Wi-Fi. Audit your router.", ModuleDir = "19-wifi-router", Action = "Test-RouterPorts" },
            new() { Icon = "🛰️", Title = "Satellite Watch", Description = "Bluetooth and satellite exfiltration detection.", ModuleDir = "36-satellite", Action = "Invoke-FalsumSatelliteScan" },

            // === ACTIVE DEFENSE ===
            new() { Icon = "⚔️", Title = "Active Defense", Description = "Backtrace attackers. Kill hostile sessions. File abuse reports.", ModuleDir = "11-active-defense", Action = "Start-Backtrace" },
            new() { Icon = "🪤", Title = "Trap Network", Description = "Honeypots that catch intruders and mark them permanently.", ModuleDir = "10-trap-network", Action = "Start-TrapListener" },
            new() { Icon = "🧹", Title = "Break Loops", Description = "Kill software that reinstalls itself. Fix phantom networks.", ModuleDir = "35-loop-breaker", Action = "Invoke-FalsumLoopBreaker" },

            // === MALWARE & SYSTEM ===
            new() { Icon = "🦠", Title = "Malware Hunter", Description = "Find and kill malware, RATs, infostealers.", ModuleDir = "21-malware-hunter", Action = "Start-MalwareHunt" },
            new() { Icon = "💀", Title = "Purge", Description = "Remove unattributed binaries and persistence.", ModuleDir = "25-purge", Action = "Invoke-PurgeScan" },
            new() { Icon = "🔪", Title = "Task Killer", Description = "Kill background tasks that shouldn't be running.", ModuleDir = "28-task-killer", Action = "Invoke-TaskKillerAudit" },
            new() { Icon = "🧬", Title = "Memory Forensics", Description = "Deep memory analysis. Find what's hiding.", ModuleDir = "27-memory-forensics", Action = "Read-ProcessMemoryBytes" },
            new() { Icon = "🛡️", Title = "Defender Watch", Description = "Monitor Windows Defender. Catch tampering.", ModuleDir = "26-defender-watch", Action = "Invoke-DefenderWatch" },
            new() { Icon = "🚪", Title = "Gate", Description = "Gate every automation sector: scheduled tasks, services, registry, WMI.", ModuleDir = "31-gate", Action = "Invoke-GateAudit" },
            new() { Icon = "🔧", Title = "Registry Fix", Description = "Find and fix broken registry entries.", ModuleDir = "29-registry-fix", Action = "Invoke-RegistryFixScan" },
            new() { Icon = "💾", Title = "Backup Shield", Description = "Protect your backups from ransomware.", ModuleDir = "20-backup-shield", Action = "New-BackupPlan" },

            // === VULNERABILITIES ===
            new() { Icon = "🔎", Title = "Find Problems", Description = "Vulnerabilities, weak configs, unpatched software.", ModuleDir = "06-vuln-check", Action = "Test-WeakConfigs" },
            new() { Icon = "🐘", Title = "PHP Shield", Description = "Secure PHP installations. Block common attacks.", ModuleDir = "07-php-shield", Action = "Test-PhpInstalls" },

            // === SCAMS & FRAUD ===
            new() { Icon = "🎣", Title = "Scam Shield", Description = "Detect phishing, romance scams, tech support scams, investment fraud.", ModuleDir = "18-scam-shield", Action = "Start-ScamCheck" },
            new() { Icon = "📧", Title = "Mail Shield", Description = "Analyze email headers. Catch phishing and spoofing.", ModuleDir = "16-mail-shield", Action = "Test-PhishingSignals" },
            new() { Icon = "💸", Title = "Fraud Pack", Description = "Document fraud for law enforcement. Build your case file.", ModuleDir = "23-fraud-pack", Action = "New-FraudManifest" },
            new() { Icon = "🩸", Title = "Breach Cleaner", Description = "Check if your data was breached. Clean up the damage.", ModuleDir = "08-breach-cleaner", Action = "Start-HibpPace" },

            // === PRIVACY ===
            new() { Icon = "🗑️", Title = "Broker Purge", Description = "Remove your data from 958 data brokers.", ModuleDir = "09-broker-eradicator", Action = "Start-FalsumOneClickBrokerPurge" },
            new() { Icon = "👁️", Title = "Browser Shield", Description = "Every tracker and fingerprint attempt, reported here.", ModuleDir = "", Action = "OpenBrowserShield" },
            new() { Icon = "🚫", Title = "Tracker Block", Description = "Block trackers at the hosts file level.", ModuleDir = "22-tracker-block", Action = "Test-TrackerBlockHealth" },
            new() { Icon = "📷", Title = "Photo Scrub", Description = "Strip metadata from photos before sharing.", ModuleDir = "17-photo-scrub", Action = "Test-PhotoScrubHygiene" },
            new() { Icon = "📱", Title = "Mobile Shield", Description = "Detect stalkerware and mobile spyware.", ModuleDir = "24-mobile-shield", Action = "Invoke-BackupStalkerwareScan" },
            new() { Icon = "🔓", Title = "Browser Control", Description = "Unlock greyed-out Chrome settings. Remove phantom policies.", ModuleDir = "40-browser-liberator", Action = "Get-FalsumBrowserPolicies" },
            new() { Icon = "🌐", Title = "Chrome Internals", Description = "Inspect your real Chrome profile from disk.", ModuleDir = "39-chrome-internals", Action = "Invoke-FalsumChromeInternalsScan" },
            new() { Icon = "🔒", Title = "Web Proxy", Description = "Inspect encrypted traffic on your own machine.", ModuleDir = "15-web-proxy", Action = "Get-ProxyState" },

            // === OSINT & RESEARCH ===
            new() { Icon = "🕵️", Title = "OSINT Attribution", Description = "Attribute attacks. Find who's behind them.", ModuleDir = "04-osint-attribution", Action = "Test-OsintInput" },
            new() { Icon = "👥", Title = "People Track", Description = "Track usernames across platforms.", ModuleDir = "05-people-track", Action = "Test-Username" },
            new() { Icon = "💰", Title = "Bug Bounty", Description = "Find bugs. Get paid. Scope-locked, always legal.", ModuleDir = "14-bugbounty", Action = "Start-BountyRecon" },

            // === GOVERNMENT & PRIOR ART ===
            new() { Icon = "🏛️", Title = "Government AI Watch", Description = "Every sector where government AI watches you — and how Falsum protects you.", ModuleDir = "", Action = "OpenGovernmentWatch" },
            new() { Icon = "📜", Title = "Prior Art Vault", Description = "Timestamp your inventions. Kill their patents. Your name can never be stripped.", ModuleDir = "", Action = "OpenPriorArt" },

            // === EARLIER APPS (integrated into the super app) ===
            new() { Icon = "⚡", Title = "Quantum Shield", Description = "Witness-only transmission logging. SHA-384 hash-chained. See what leaves your machine.", ModuleDir = "41-quantum-shield", Action = "Get-QuantumShieldStats" },
            new() { Icon = "📹", Title = "Agent Watchdog", Description = "Bodycam for AI agents. Tamper-evident log. No agents in your browser, period.", ModuleDir = "42-agent-watchdog", Action = "Get-WatchdogAgentActivity" },
            new() { Icon = "〰️", Title = "Hashline", Description = "Hash every byte of browser traffic. SHA-256 per body. Integrity before it leaves the router.", ModuleDir = "43-hashline", Action = "Get-HashlineStats" },
            new() { Icon = "🚧", Title = "Port Gate", Description = "Firewall companion. Audit, enforce, mark bad actors permanently.", ModuleDir = "44-port-gate", Action = "Invoke-PortGateAudit" },
            new() { Icon = "📡", Title = "Router Tracker", Description = "Log every router login. Catch unauthorized access.", ModuleDir = "45-router-tracker", Action = "Test-RouterLoginAnomaly" },

            // === COMMAND ===
            new() { Icon = "⌨️", Title = "Command Center", Description = "Direct system control. Every CMD capability, better.", ModuleDir = "33-command-center", Action = "Test-CommandCenterHygiene" },
            new() { Icon = "🌉", Title = "Bridge", Description = "Connect Falsum to your other tools.", ModuleDir = "30-bridge", Action = "Initialize-Bridge" },

            // === NATIVE C# SERVICES (no scripts — real code) ===
            new() { Icon = "⚡", Title = "Energy Fraud Detector", Description = "Find what's burning your power. Miners, spyware, telemetry — caught by energy.", ModuleDir = "", Action = "NativeEnergyFraud" },
            new() { Icon = "👻", Title = "Hidden File Hunter", Description = "Find everything Windows hides. Alternate Data Streams, system files — all exposed.", ModuleDir = "", Action = "NativeHiddenFiles" },
            new() { Icon = "📥", Title = "Download Tracker", Description = "Every file your browsers downloaded. Hashed, risk-scored, tracked.", ModuleDir = "", Action = "NativeDownloadTracker" },
            new() { Icon = "🌐", Title = "Network Commander", Description = "Full network control via CMD. Interfaces, firewall, DNS, Wi-Fi, ports — plain language.", ModuleDir = "", Action = "NativeNetworkCommander" },
            new() { Icon = "📲", Title = "Infrastructure Detector", Description = "Is your Windows PC running cell tower software? Find out and kill it.", ModuleDir = "", Action = "NativeInfrastructureDetector" },
        };

        ModuleCards.ItemsSource = cards;
    }

    private void ModuleCard_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button button && button.Tag is ModuleCard card)
        {
            // Announce to screen readers
            System.Windows.Automation.AutomationProperties.SetName(button, $"{card.Title}, activated");
            RunModuleAction(card);
        }
    }

    private void RunModuleAction(ModuleCard card)
    {
        StatusText.Text = $"Running: {card.Title}...";
        StatusDot.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Orange);

        try
        {
            if (card.Action == "ProtectAll")
            {
                // FULL PROTECTION SEQUENCE — runs every safe scan module in order.
                // Read-only scans first, then gates, then fixes with backup.
                StatusText.Text = "Running full protection scan...";
                RunProtectAll();
            }
            else if (card.Action == "Start-FalsumChatLoop")
            {
                var chatWindow = new AIChatWindow();
                chatWindow.Show();
                StatusText.Text = "AI Chat: opened.";
            }
            else if (!string.IsNullOrEmpty(card.ModuleDir))
            {
                var results = _engine.RunModule(card.ModuleDir, card.Action);
                StatusText.Text = $"{card.Title}: complete. {results.Count} results.";
            }
            else if (card.Action == "OpenBrowserControl")
            {
                var browserWindow = new BrowserControlWindow();
                browserWindow.ShowDialog();
                StatusText.Text = "Browser Control: closed.";
            }
            else if (card.Action == "OpenGovernmentWatch")
            {
                var govWindow = new GovernmentWatchWindow();
                govWindow.Show();
                StatusText.Text = "Government AI Watch: opened.";
            }
            else if (card.Action == "OpenPriorArt")
            {
                var priorArtWindow = new PriorArtWindow();
                priorArtWindow.Show();
                StatusText.Text = "Prior Art Vault: opened.";
            }
            else if (card.Action == "NativeEnergyFraud")
            {
                RunNativeEnergyFraud();
            }
            else if (card.Action == "NativeHiddenFiles")
            {
                RunNativeHiddenFiles();
            }
            else if (card.Action == "NativeDownloadTracker")
            {
                RunNativeDownloadTracker();
            }
            else if (card.Action == "NativeNetworkCommander")
            {
                RunNativeNetworkCommander();
            }
            else if (card.Action == "NativeInfrastructureDetector")
            {
                RunNativeInfrastructureDetector();
            }
            else
            {
                // UI-only actions (browser shield, vault viewer, etc.)
                StatusText.Text = $"{card.Title}: opening...";
            }

            StatusDot.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Green);
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Error: {ex.Message}";
            StatusDot.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Red);
        }
    }

    /// <summary>
    /// PROTECT ALL — the one-click protection sequence.
    /// Runs every safe module in dependency order. Nothing destructive runs
    /// without the module's own safety gates (backup-first, admin checks).
    /// </summary>
    private void RunProtectAll()
    {
        // (moduleDir, action, displayName) — read-only scans first, gates last
        var sequence = new (string dir, string action, string name)[]
        {
            ("06-vuln-check", "Test-WeakConfigs", "Vulnerability scan"),
            ("26-defender-watch", "Invoke-DefenderWatch", "Defender status"),
            ("21-malware-hunter", "Start-MalwareHunt", "Malware hunt"),
            ("31-gate", "Invoke-GateAudit", "Automation gates"),
            ("32-port-control", "Invoke-PortControlWorkflow", "Port audit"),
            ("19-wifi-router", "Test-RouterPorts", "Router audit"),
            ("22-tracker-block", "Test-TrackerBlockHealth", "Tracker blocks"),
            ("09-broker-eradicator", "Test-BrokerTableValidation", "Broker list check"),
            ("16-mail-shield", "Test-PhishingSignals", "Phishing signals"),
            ("08-breach-cleaner", "Test-HibpConnection", "Breach check"),
            ("29-registry-fix", "Invoke-RegistryFixScan", "Registry audit"),
            ("28-task-killer", "Invoke-TaskKillerAudit", "Background tasks"),
            ("25-purge", "Invoke-PurgeScan", "Unattributed binaries"),
            ("37-datagate", "Get-FalsumDataSummary", "Data movement"),
            ("36-satellite", "Invoke-FalsumSatelliteScan", "Satellite/Bluetooth"),
            ("35-loop-breaker", "Invoke-FalsumLoopBreaker", "Loop breaker"),
            ("40-browser-liberator", "Get-FalsumBrowserPolicies", "Browser policies"),
            ("39-chrome-internals", "Invoke-FalsumChromeInternalsScan", "Chrome internals"),
            ("00-coherence-core", "Test-Coherence", "Coherence check"),
            ("12-timeline-vault", "New-Vault", "Evidence vault"),
        };

        int completed = 0;
        int failed = 0;

        foreach (var (dir, action, name) in sequence)
        {
            try
            {
                StatusText.Text = $"Protect All ({completed + 1}/{sequence.Length}): {name}...";
                var results = _engine.RunModule(dir, action);
                completed++;
            }
            catch (Exception ex)
            {
                failed++;
                StatusText.Text = $"Protect All: {name} failed — {ex.Message}. Continuing...";
            }
        }

        StatusText.Text = failed == 0
            ? $"Protect All complete. {completed} modules ran clean."
            : $"Protect All complete. {completed} ran, {failed} had errors. Check each module.";
        StatusDot.Fill = new System.Windows.Media.SolidColorBrush(
            failed == 0 ? System.Windows.Media.Colors.Green : System.Windows.Media.Colors.Orange);
    }

    private void OpenAIChat_Click(object sender, RoutedEventArgs e)
    {
        var chatWindow = new AIChatWindow();
        chatWindow.Show();
        StatusText.Text = "AI Chat: opened.";
    }

    private void OpenSettings_Click(object sender, RoutedEventArgs e)
    {
        var settingsWindow = new SettingsWindow();
        settingsWindow.ShowDialog();
        StatusText.Text = "Settings: closed.";
    }

    protected override void OnClosed(EventArgs e)
    {
        _engine?.Dispose();
        base.OnClosed(e);
    }

    // ========================================================================
    // NATIVE C# SERVICES — real code, no scripts
    // ========================================================================

    private string GetVaultPath()
    {
        return System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "vault");
    }

    /// <summary>
    /// Energy Fraud Detector: find what's burning power that shouldn't be.
    /// </summary>
    private void RunNativeEnergyFraud()
    {
        StatusText.Text = "Energy Fraud: scanning for power anomalies...";
        try
        {
            var service = new Services.EnergyFraudService(GetVaultPath());
            var anomalies = service.DetectAnomalousProcesses();

            if (anomalies.Count == 0)
            {
                StatusText.Text = "Energy Fraud: no anomalies found. Your power usage looks clean.";
            }
            else
            {
                StatusText.Text = $"Energy Fraud: {anomalies.Count} suspicious process(es) found. Check the vault.";
                service.SaveToVault(new Services.EnergyReport
                {
                    Timestamp = DateTime.UtcNow,
                    Findings = anomalies
                });
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Energy Fraud error: {ex.Message}";
        }
    }

    /// <summary>
    /// Hidden File Hunter: expose everything Windows is hiding.
    /// </summary>
    private void RunNativeHiddenFiles()
    {
        StatusText.Text = "Hidden Files: scanning your drives...";
        try
        {
            var service = new Services.HiddenFileService(GetVaultPath());
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var report = service.ScanDirectory(userProfile, recursive: true);

            if (report.HiddenFiles.Count == 0)
            {
                StatusText.Text = "Hidden Files: nothing hidden found. Your files are all visible.";
            }
            else
            {
                var adsCount = report.HiddenFiles.Count(f => f.HasAlternateStreams);
                StatusText.Text = $"Hidden Files: {report.HiddenFiles.Count} hidden item(s), " +
                    $"{adsCount} with secret data streams. Check the vault for details.";
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Hidden Files error: {ex.Message}";
        }
    }

    /// <summary>
    /// Download Tracker: every file your browsers downloaded, hashed and scored.
    /// </summary>
    private void RunNativeDownloadTracker()
    {
        StatusText.Text = "Download Tracker: scanning downloads...";
        try
        {
            // NativeMessagingHost is created for the bridge; pass null bridge for standalone scan
            var service = new Services.BrowserDownloadService(GetVaultPath(), null!);
            var files = service.ScanDownloadFolders();
            var history = service.GetDownloadHistory();

            var highRisk = files.Count(f => f.RiskLevel.StartsWith("HIGH"));
            StatusText.Text = $"Download Tracker: {files.Count} file(s) scanned, " +
                $"{highRisk} high-risk. {history.Downloads.Count} browser download records.";
            service.SaveToVault(history);
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Download Tracker error: {ex.Message}";
        }
    }

    /// <summary>
    /// Network Commander: full network control in plain language.
    /// </summary>
    private void RunNativeNetworkCommander()
    {
        StatusText.Text = "Network Commander: mapping your network...";
        try
        {
            var service = new Services.NetworkCommandService();
            var diag = service.FullDiagnostic();

            var connected = diag.Interfaces.Count(i => i.IsConnected);
            var listeners = diag.ListeningPorts.Count;
            var connections = diag.ActiveConnections.Count;

            StatusText.Text = $"Network: {connected} interface(s) up, " +
                $"{connections} active connection(s), {listeners} listening port(s).";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Network Commander error: {ex.Message}";
        }
    }

    /// <summary>
    /// Infrastructure Detector: is your Windows PC running cell tower software?
    /// </summary>
    private void RunNativeInfrastructureDetector()
    {
        StatusText.Text = "Infrastructure Detector: scanning for mobile infrastructure...";
        try
        {
            var service = new Services.InfrastructureDetectorService();
            var report = service.Scan();

            if (report.Findings.Count == 0)
            {
                StatusText.Text = "Infrastructure: clean. No mobile infrastructure found on this PC.";
            }
            else
            {
                var critical = report.Findings.Count(f => f.Severity == "critical");
                StatusText.Text = $"Infrastructure: {report.Findings.Count} finding(s), " +
                    $"{critical} critical. Your PC may be running phone infrastructure.";
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Infrastructure Detector error: {ex.Message}";
        }
    }
}
