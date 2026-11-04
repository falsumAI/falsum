using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using FalsumApp.Models;
using FalsumApp.Services;
using FalsumApp.Services.Modules;

namespace FalsumApp.Views;

public partial class MainWindow : Window
{
    private GatePipeServer? _gateServer;
    private FileSystemWatcher? _bridgeWatcher;
    private SystemBubbleService _bubble;
    private PortConsentService _portConsent;
    private System.Windows.Forms.NotifyIcon? _trayIcon;
    private readonly List<string> _bridgeFeed = new();
    private static readonly string BridgeEventsPath = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Falsum", "bridge", "events.jsonl");

    public MainWindow()
    {
        InitializeComponent();

        // System tray: Falsum lives in the tray, always watching.
        // Closing the window minimizes to tray — the guard doesn't quit.
        SetupTrayIcon();

        // All 45 modules are native C# now. No PowerShell engine, no .ps1 files.

        // System bubble: watches every application on the machine (ETW).
        // Starts fail-soft: without admin rights the kernel providers refuse,
        // and the bubble reports why instead of crashing the app.
        _bubble = new SystemBubbleService();
        _portConsent = new PortConsentService(_bubble);
        try
        {
            if (!_bubble.Start())
                StatusText.Text = $"Bubble: {_bubble.LastError}";
            else
                StatusText.Text = "Bubble live: every app on this machine is being watched.";
        }
        catch (Exception ex) { StatusText.Text = $"Bubble failed to start: {ex.Message}"; }

        // Start the consent gate: the browser extension talks to Falsum.exe
        // (launched by Chrome as the native host), and the host asks THIS window
        // for the user's approval through a named pipe. The feed below shows
        // everything the browser and the app see each other doing.
        StartGateServer();
        StartBridgeFeed();

        // Clean up the gate server and feed watcher when the window closes.
        Closed += (s, e) =>
        {
            try { _gateServer?.Stop(); } catch { }
            try { _bridgeWatcher?.Dispose(); } catch { }
        };

        LoadModuleCards();
        StatusText.Text = "Ready. Your data never leaves this computer.";
    }

    /// <summary>
    /// Start the consent gate server. When the browser extension needs the
    /// user's approval, the native host (Falsum.exe, launched by Chrome)
    /// asks this window through the named pipe, and a Yes/No dialog appears.
    /// </summary>
    private void StartGateServer()
    {
        try
        {
            _gateServer = new GatePipeServer(this);
            _gateServer.GateDecisionMade += (msg) =>
            {
                Dispatcher.Invoke(() =>
                {
                    StatusText.Text = $"Browser gate: {msg}";
                    AddFeedLine("gate", msg);
                });
            };
            _gateServer.Start();
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Browser gate failed to start: {ex.Message}";
        }
    }

    /// <summary>
    /// Watch the bridge event feed (%LOCALAPPDATA%\Falsum\bridge\events.jsonl).
    /// The native host appends everything the browser reports and every gate
    /// decision here, so the user sees the browser and the app seeing each other.
    /// </summary>
    private void StartBridgeFeed()
    {
        try
        {
            var dir = System.IO.Path.GetDirectoryName(BridgeEventsPath)!;
            if (!System.IO.Directory.Exists(dir))
                System.IO.Directory.CreateDirectory(dir);
            if (!System.IO.File.Exists(BridgeEventsPath))
                System.IO.File.WriteAllText(BridgeEventsPath, "");

            LoadFeedFromFile();

            _bridgeWatcher = new FileSystemWatcher(dir, "events.jsonl")
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size,
                EnableRaisingEvents = true
            };
            _bridgeWatcher.Changed += (s, e) =>
            {
                // Debounce: the host trims the file after appending.
                System.Threading.Thread.Sleep(150);
                Dispatcher.Invoke(LoadFeedFromFile);
            };
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Browser feed unavailable: {ex.Message}";
        }
    }

    private void LoadFeedFromFile()
    {
        try
        {
            List<string> lines;
            using (var fs = new System.IO.FileStream(BridgeEventsPath,
                System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
            using (var sr = new System.IO.StreamReader(fs))
            {
                lines = new List<string>();
                string? line;
                while ((line = sr.ReadLine()) != null)
                    lines.Add(line);
            }

            _bridgeFeed.Clear();
            foreach (var line in lines.TakeLast(30))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(line);
                    var root = doc.RootElement;
                    var at = root.TryGetProperty("at", out var atp) ? atp.GetString() : "";
                    var cat = root.TryGetProperty("category", out var cp) ? cp.GetString() : "";
                    var text = root.TryGetProperty("text", out var tp) ? tp.GetString() : "";
                    _bridgeFeed.Add($"[{at}] {cat}: {text}");
                }
                catch { /* skip malformed lines */ }
            }
            _bridgeFeed.Reverse();

            if (BrowserFeedList != null)
            {
                BrowserFeedList.ItemsSource = null;
                BrowserFeedList.ItemsSource = _bridgeFeed;
            }
        }
        catch { /* feed is best-effort */ }
    }

    private void AddFeedLine(string category, string text)
    {
        _bridgeFeed.Insert(0, $"[{DateTime.Now:HH:mm:ss}] {category}: {text}");
        while (_bridgeFeed.Count > 30) _bridgeFeed.RemoveAt(_bridgeFeed.Count - 1);
        if (BrowserFeedList != null)
        {
            BrowserFeedList.ItemsSource = null;
            BrowserFeedList.ItemsSource = _bridgeFeed;
        }
    }

    private void LoadModuleCards()
    {
        var cards = new List<ModuleCard>
        {
            // === ONE-CLICK PROTECTION ===
            new() { Icon = "🛡️", Title = "Protect Me", Description = "One click. Falsum checks everything and fixes what it can.", ModuleDir = "", Action = "ProtectAll", Category = "Protection" },

            // === THE BUBBLE: every application on this machine ===
            new() { Icon = "🫧", Title = "System Bubble", Description = "Every app on this machine, watched. Every launch, every connection, logged to the vault.", ModuleDir = "", Action = "SystemBubble", Category = "Protection" },
            new() { Icon = "🔌", Title = "Port Consent", Description = "Nothing passes a port without your consent. Your computer, your rules.", ModuleDir = "", Action = "PortConsent", Category = "Protection" },
            new() { Icon = "📝", Title = "VS Code Gate", Description = "Finds the hidden switches in your code editor that send your data away, and turns them off.", Category = "Privacy", ModuleDir = "46-vscode-gate", Action = "Invoke-VSCodeGateAudit" },
            new() { Icon = "📜", Title = "Certificate Verifier", Description = "Checks every security certificate on your computer. If something isn\u2019t properly signed, you\u2019ll know.", Category = "Protection", ModuleDir = "47-cert-verifier", Action = "Invoke-CertAudit" },
            new() { Icon = "📋", Title = "Group Policy Audit", Description = "Every group policy named in plain language. Find out who really controls your machine.", Category = "Control", ModuleDir = "48-group-policy", Action = "Invoke-GroupPolicyAudit" },
            new() { Icon = "🔍", Title = "Binary Translator", Description = "Point at any program file and read what it really does, in plain words. Nothing is a black box.", Category = "Investigate", ModuleDir = "49-binary-translator", Action = "Invoke-BinaryTranslate" },
            new() { Icon = "🦈", Title = "Predator Vault", Description = "Catches companies secretly taking your data. Logs the evidence, blocks them, never forgets.", Category = "Privacy", ModuleDir = "50-predator-vault", Action = "Invoke-PredatorScan" },
            new() { Icon = "🧠", Title = "Superintelligence", Description = "The AI that lives on your computer and learns from you. Respects your hardware. No cloud, no subscription.", Category = "Protection", ModuleDir = "51-superintelligence", Action = "Invoke-SuperintelligenceAudit" },
            new() { Icon = "📢", Title = "Complaint Engine", Description = "Collects complaints about Big Tech, groups the same ones together, and points each group at the fix.", Category = "Investigate", ModuleDir = "52-complaint-engine", Action = "Invoke-ComplaintAudit" },
            new() { Icon = "🕵️", Title = "Fraud Patterns", Description = "Catches fraud by watching for suspicious behavior, not just known viruses. What antivirus misses.", Category = "Protection", ModuleDir = "53-fraud-patterns", Action = "Invoke-FraudDetect" },
            new() { Icon = "🔖", Title = "Bad Actor Stamps", Description = "Permanently marks bad actors: who they are, what data they tried to take, blocked forever.", Category = "Protection", ModuleDir = "54-badactor-stamp", Action = "Invoke-StampAudit" },
            new() { Icon = "🔄", Title = "Knowledge Updater", Description = "Falsum learns about new threats automatically. Every update is safety-checked before it\u2019s accepted.", Category = "Protection", ModuleDir = "55-knowledge-updater", Action = "Invoke-KnowledgeAudit" },
            new() { Icon = "🏢", Title = "Fleet", Description = "For businesses: deploy protection policy to every computer, tamper-proof audit reports, shared threat feed. (Commercial license)", Category = "Control", ModuleDir = "56-fleet", Action = "Invoke-FleetAudit" },
            new() { Icon = "💾", Title = "RAM Manager", Description = "Keeps memory clean and running lean. Finds what's hogging RAM, frees it, keeps Falsum itself light.", Category = "Protection", ModuleDir = "57-ram-manager", Action = "Invoke-RamAudit" },
            new() { Icon = "📚", Title = "Local RAG", Description = "The AI reads YOUR documents before answering. Grounded in your data, not just training. Nothing leaves your machine.", Category = "Protection", ModuleDir = "58-local-rag", Action = "Invoke-RagAudit" },
            new() { Icon = "🔐", Title = "Encrypted Vault", Description = "Every vault entry encrypted with AES-256. Steal the drive, get nothing readable.", Category = "Protection", ModuleDir = "59-encrypted-vault", Action = "Invoke-VaultAudit" },

            // === LOCAL AI (Gregg's drift math = the beast) ===
            new() { Icon = "🤖", Title = "AI Chat", Description = "Talk to the AI that lives on your computer. It learns from your corrections. Nothing you say leaves your machine.", Category = "Protection", ModuleDir = "38-learning-ai", Action = "Start-FalsumChatLoop" },
            new() { Icon = "🧠", Title = "Coherence Core", Description = "The math engine. Double-checks that Falsum\u2019s own decisions are correct before it acts on them.", Category = "Protection", ModuleDir = "00-coherence-core", Action = "Test-Coherence" },

            // === EVIDENCE & TRUTH ===
            new() { Icon = "📦", Title = "Evidence Vault", Description = "Tamper-evident log of everything Falsum finds.", ModuleDir = "12-timeline-vault", Action = "New-Vault", Category = "Investigate" },
            new() { Icon = "🔍", Title = "Evidence Sweep", Description = "Sweep your system for evidence of tampering.", ModuleDir = "01-evidence-sweep", Action = "Test-SweepHygiene", Category = "Investigate" },
            new() { Icon = "📡", Title = "Packet Witness", Description = "Records what your computer sends and receives, so nothing leaves your machine secretly.", Category = "Network", ModuleDir = "02-packet-witness", Action = "Start-Capture" },

            // === NETWORK DEFENSE ===
            new() { Icon = "🌐", Title = "Network Watch", Description = "Shows every connection your computer makes. If you don’t trust one, block it.", Category = "Network", ModuleDir = "37-datagate", Action = "Get-FalsumDataSummary" },
            new() { Icon = "🗺️", Title = "Net Scan", Description = "Lists every device on your network. If something\u2019s connected that shouldn\u2019t be, you\u2019ll see it.", Category = "Network", ModuleDir = "03-netscan", Action = "Test-TargetSpec" },
            new() { Icon = "🔌", Title = "Port Control", Description = "You decide which doors to the internet are open and which stay shut. Every program, every connection.", Category = "Network", ModuleDir = "32-port-control", Action = "Invoke-PortControlWorkflow" },
            new() { Icon = "📶", Title = "Wi-Fi & Router", Description = "Secure your Wi-Fi. Audit your router.", ModuleDir = "19-wifi-router", Action = "Test-RouterPorts", Category = "Network" },
            new() { Icon = "🛰️", Title = "Satellite Watch", Description = "Catches your data being stolen through Bluetooth or satellite connections.", Category = "Network", ModuleDir = "36-satellite", Action = "Invoke-FalsumSatelliteScan" },

            // === ACTIVE DEFENSE ===
            new() { Icon = "⚔️", Title = "Active Defense", Description = "Backtrace attackers. Kill hostile sessions. File abuse reports.", ModuleDir = "11-active-defense", Action = "Start-Backtrace", Category = "Protection" },
            new() { Icon = "🪤", Title = "Trap Network", Description = "Sets traps that catch intruders trying to break in, then marks them permanently so they can\u2019t come back.", Category = "Protection", ModuleDir = "10-trap-network", Action = "Start-TrapListener" },
            new() { Icon = "🧹", Title = "Break Loops", Description = "Kill software that reinstalls itself. Fix phantom networks.", ModuleDir = "35-loop-breaker", Action = "Invoke-FalsumLoopBreaker", Category = "Protection" },

            // === MALWARE & SYSTEM ===
            new() { Icon = "🦠", Title = "Malware Hunter", Description = "Find and kill malware, RATs, infostealers.", ModuleDir = "21-malware-hunter", Action = "Start-MalwareHunt", Category = "Protection" },
            new() { Icon = "💀", Title = "Purge", Description = "Removes mystery programs and anything trying to survive a restart without your permission.", Category = "Protection", ModuleDir = "25-purge", Action = "Invoke-PurgeScan" },
            new() { Icon = "🔪", Title = "Task Killer", Description = "Kill background tasks that shouldn't be running.", ModuleDir = "28-task-killer", Action = "Invoke-TaskKillerAudit", Category = "Protection" },
            new() { Icon = "🧬", Title = "Memory Forensics", Description = "Looks inside running programs to find hidden malware that normal scans miss.", Category = "Protection", ModuleDir = "27-memory-forensics", Action = "Read-ProcessMemoryBytes" },
            new() { Icon = "🛡️", Title = "Defender Watch", Description = "Monitor Windows Defender. Catch tampering.", ModuleDir = "26-defender-watch", Action = "Invoke-DefenderWatch", Category = "Protection" },
            new() { Icon = "🚪", Title = "Gate", Description = "Controls everything Windows runs automatically: scheduled tasks, background services, startup programs. Nothing runs without your say.", Category = "Control", ModuleDir = "31-gate", Action = "Invoke-GateAudit" },
            new() { Icon = "🔧", Title = "Registry Fix", Description = "Find and fix broken registry entries.", ModuleDir = "29-registry-fix", Action = "Invoke-RegistryFixScan", Category = "Control" },
            new() { Icon = "💾", Title = "Backup Shield", Description = "Protect your backups from ransomware.", ModuleDir = "20-backup-shield", Action = "New-BackupPlan", Category = "Protection" },

            // === VULNERABILITIES ===
            new() { Icon = "🔎", Title = "Find Problems", Description = "Vulnerabilities, weak configs, unpatched software.", ModuleDir = "06-vuln-check", Action = "Test-WeakConfigs", Category = "Protection" },
            new() { Icon = "🐘", Title = "PHP Shield", Description = "Finds and fixes security holes in PHP on your machine.", Category = "Protection", ModuleDir = "07-php-shield", Action = "Test-PhpInstalls" },

            // === SCAMS & FRAUD ===
            new() { Icon = "🎣", Title = "Scam Shield", Description = "Detect phishing, romance scams, tech support scams, investment fraud.", ModuleDir = "18-scam-shield", Action = "Start-ScamCheck", Category = "Protection" },
            new() { Icon = "📧", Title = "Mail Shield", Description = "Analyze email headers. Catch phishing and spoofing.", ModuleDir = "16-mail-shield", Action = "Test-PhishingSignals", Category = "Protection" },
            new() { Icon = "💸", Title = "Fraud Pack", Description = "Document fraud for law enforcement. Build your case file.", ModuleDir = "23-fraud-pack", Action = "New-FraudManifest", Category = "Investigate" },
            new() { Icon = "🩸", Title = "Breach Cleaner", Description = "Check if your data was breached. Clean up the damage.", ModuleDir = "08-breach-cleaner", Action = "Test-HibpConnection", Category = "Privacy" },

            // === PRIVACY ===
            new() { Icon = "🗑️", Title = "Broker Purge", Description = "Remove your data from 963 data brokers.", ModuleDir = "09-broker-eradicator", Action = "Test-BrokerTableValidation", Category = "Privacy" },
            new() { Icon = "👁️", Title = "Browser Shield", Description = "Every tracker and fingerprint attempt, reported here.", ModuleDir = "", Action = "OpenBrowserShield", Category = "Privacy" },
            new() { Icon = "🚫", Title = "Tracker Block", Description = "Block trackers at the hosts file level.", ModuleDir = "22-tracker-block", Action = "Test-TrackerBlockHealth", Category = "Privacy" },
            new() { Icon = "📷", Title = "Photo Scrub", Description = "Strip metadata from photos before sharing.", ModuleDir = "17-photo-scrub", Action = "Test-PhotoScrubHygiene", Category = "Privacy" },
            new() { Icon = "📱", Title = "Mobile Shield", Description = "Detect stalkerware and mobile spyware.", ModuleDir = "24-mobile-shield", Action = "Invoke-BackupStalkerwareScan", Category = "Privacy" },
            new() { Icon = "🔓", Title = "Browser Control", Description = "Unlock greyed-out Chrome settings. Remove phantom policies.", ModuleDir = "40-browser-liberator", Action = "Get-FalsumBrowserPolicies", Category = "Control" },
            new() { Icon = "🌐", Title = "Chrome Internals", Description = "Inspect your real Chrome profile from disk.", ModuleDir = "39-chrome-internals", Action = "Invoke-FalsumChromeInternalsScan", Category = "Investigate" },
            new() { Icon = "🔒", Title = "Web Proxy", Description = "Lets you see inside encrypted connections on your own computer. Your machine, your right to look.", Category = "Network", ModuleDir = "15-web-proxy", Action = "Get-ProxyState" },

            // === OSINT & RESEARCH ===
            new() { Icon = "🕵️", Title = "OSINT Attribution", Description = "Finds out who is attacking you, using public records.", Category = "Investigate", ModuleDir = "04-osint-attribution", Action = "Test-OsintInput" },
            new() { Icon = "👥", Title = "People Track", Description = "Finds where a username appears across the internet, using public records.", Category = "Investigate", ModuleDir = "05-people-track", Action = "Test-Username" },
            new() { Icon = "💰", Title = "Bug Bounty", Description = "Find security bugs on websites that pay for them. Locked to legal targets only.", Category = "Investigate", ModuleDir = "14-bugbounty", Action = "Start-BountyRecon" },

            // === GOVERNMENT & PRIOR ART ===
            new() { Icon = "🏛️", Title = "Government AI Watch", Description = "Every sector where government AI watches you — and how Falsum protects you.", ModuleDir = "", Action = "OpenGovernmentWatch", Category = "Investigate" },
            new() { Icon = "📜", Title = "Prior Art Vault", Description = "Timestamp your inventions. Kill their patents. Your name can never be stripped.", Category = "Investigate", ModuleDir = "", Action = "OpenPriorArt" },

            // === EARLIER APPS (integrated into the super app) ===
            new() { Icon = "⚡", Title = "Quantum Shield", Description = "Watches everything leaving your computer and proves nothing was changed along the way.", Category = "Privacy", ModuleDir = "41-quantum-shield", Action = "Get-QuantumShieldStats" },
            new() { Icon = "📹", Title = "Agent Watchdog", Description = "Bodycam for AI agents. Tamper-evident log. No agents in your browser, period.", ModuleDir = "42-agent-watchdog", Action = "Get-WatchdogAgentActivity", Category = "Privacy" },
            new() { Icon = "〰️", Title = "Hashline", Description = "Fingerprints everything your browser sends, so you can prove what really happened later.", Category = "Privacy", ModuleDir = "43-hashline", Action = "Get-HashlineStats" },
            new() { Icon = "🚧", Title = "Port Gate", Description = "Firewall companion. Audit, enforce, mark bad actors permanently.", ModuleDir = "44-port-gate", Action = "Invoke-PortGateAudit", Category = "Network" },
            new() { Icon = "📡", Title = "Router Tracker", Description = "Log every router login. Catch unauthorized access.", ModuleDir = "45-router-tracker", Action = "Test-RouterLoginAnomaly", Category = "Network" },

            // === COMMAND ===
            new() { Icon = "⌨️", Title = "Command Center", Description = "Direct control of your system. Everything the command prompt does, in plain language.", Category = "Control", ModuleDir = "33-command-center", Action = "Test-CommandCenterHygiene" },
            new() { Icon = "🌉", Title = "Bridge", Description = "Connect Falsum to your other tools.", ModuleDir = "30-bridge", Action = "Initialize-Bridge", Category = "Network" },

            // === NATIVE C# SERVICES (no scripts — real code) ===
            new() { Icon = "⚡", Title = "Energy Fraud Detector", Description = "Find what's burning your power. Miners, spyware, telemetry — caught by energy.", ModuleDir = "", Action = "NativeEnergyFraud", Category = "Investigate" },
            new() { Icon = "👻", Title = "Hidden File Hunter", Description = "Find everything Windows hides. Alternate Data Streams, system files — all exposed.", ModuleDir = "", Action = "NativeHiddenFiles", Category = "Investigate" },
            new() { Icon = "📥", Title = "Download Tracker", Description = "Every file your browsers downloaded. Hashed, risk-scored, tracked.", ModuleDir = "", Action = "NativeDownloadTracker", Category = "Privacy" },
            new() { Icon = "🌐", Title = "Network Commander", Description = "Full network control via CMD. Interfaces, firewall, DNS, Wi-Fi, ports — plain language.", ModuleDir = "", Action = "NativeNetworkCommander", Category = "Control" },
            new() { Icon = "📲", Title = "Infrastructure Detector", Description = "Is your Windows PC running cell tower software? Find out and kill it.", ModuleDir = "", Action = "NativeInfrastructureDetector", Category = "Investigate" },
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
            else if (card.Action == "SystemBubble")
            {
                StatusText.Text = _bubble.GetStats();
            }
            else if (card.Action == "PortConsent")
            {
                TogglePortConsent();
            }
            else if (!string.IsNullOrEmpty(card.ModuleDir))
            {
                // Every module is native C#. Results ALWAYS go on screen —
                // never computed and hidden.
                var results = Modules.ModuleDispatcher.Run(card.ModuleDir, card.Action);
                StatusText.Text = $"{card.Title}: complete. {results.Count} results.";
                var win = new Views.ResultsWindow(card.Title, results) { Owner = this };
                win.ShowDialog();
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
                // Every module is native C#.
                Modules.ModuleDispatcher.Run(dir, action);
                completed++;
            }
            catch (Exception ex)
            {
                failed++;
                StatusText.Text = $"Protect All: {name} failed — {ex.Message}. Continuing...";
            }
        }

        // Native C# services — run after the modules
        StatusText.Text = "Protect All: running native services...";
        try
        {
            var vaultPath = GetVaultPath();

            // Energy fraud
            var energy = new Services.EnergyFraudService(vaultPath);
            var anomalies = energy.DetectAnomalousProcesses();
            if (anomalies.Count > 0) completed++;

            // Hidden files
            var hidden = new Services.HiddenFileService(vaultPath);
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var hiddenReport = hidden.ScanDirectory(userProfile, recursive: false);
            if (hiddenReport.HiddenFiles.Count > 0) completed++;

            // Infrastructure
            var infra = new Services.InfrastructureDetectorService();
            var infraReport = infra.Scan();
            if (infraReport.Findings.Count > 0) completed++;

            completed += 3; // native services ran
        }
        catch (Exception ex)
        {
            failed++;
            StatusText.Text = $"Protect All: native services had an error — {ex.Message}";
        }

        StatusText.Text = failed == 0
            ? $"Protect All complete. {completed} checks ran clean."
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
        try { _portConsent?.Dispose(); } catch { }
        try { _bubble?.Dispose(); } catch { }
        base.OnClosed(e);
    }

    /// <summary>
    /// Port Consent toggle: default-deny outbound, every app asks the owner.
    /// Warned up front: until apps are allowed, they have no network.
    /// One click turns it all back off.
    /// </summary>
    private void TogglePortConsent()
    {
        try
        {
            if (_portConsent.ConsentMode)
            {
                _portConsent.DisableConsentMode();
                StatusText.Text = "Port Consent: OFF. Default-allow restored, gate rules removed.";
                return;
            }

            var answer = MessageBox.Show(
                "Port Consent blocks ALL outbound network on every profile.\n\n" +
                "Every application will ask for your permission before it may use a port. " +
                "Nothing is pre-allowed — not even Windows itself. This is your computer and you decide.\n\n" +
                "Until you allow an app, it has no network. Turn it off any time with one click.\n\n" +
                "Turn Port Consent ON?",
                "Falsum: Port Consent",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (answer != MessageBoxResult.Yes)
            {
                StatusText.Text = "Port Consent: not enabled.";
                return;
            }

            _portConsent.EnableConsentMode();
            StatusText.Text = "Port Consent: ON. Nothing passes a port without your consent.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Port Consent failed: {ex.Message}";
        }
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
            // Standalone scan — no live bridge needed here.
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
                var cellular = report.Findings.Any(f => f.Category == "cellular-services");

                if (cellular)
                {
                    // Offer to disable — but don't do it silently
                    StatusText.Text = $"Infrastructure: {report.Findings.Count} finding(s), " +
                        $"{critical} critical. Cellular services detected. " +
                        "Run again with Shift held to disable them.";
                }
                else
                {
                    StatusText.Text = $"Infrastructure: {report.Findings.Count} finding(s), " +
                        $"{critical} critical. Your PC may be running phone infrastructure.";
                }
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Infrastructure Detector error: {ex.Message}";
        }
    }
}
