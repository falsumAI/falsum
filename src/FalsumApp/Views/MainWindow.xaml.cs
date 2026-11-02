using System.Windows;
using System.Windows.Controls;
using FalsumApp.Models;
using FalsumApp.Services;

namespace FalsumApp.Views;

public partial class MainWindow : Window
{
    private PowerShellEngine _engine;
    private readonly string _modulesPath;

    public MainWindow()
    {
        InitializeComponent();

        // Modules are deployed alongside the .exe
        _modulesPath = System.IO.Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "modules");

        _engine = new PowerShellEngine(_modulesPath);

        LoadModuleCards();
        StatusText.Text = "Ready. Your data never leaves this computer.";
    }

    private void LoadModuleCards()
    {
        var cards = new List<ModuleCard>
        {
            new() { Icon = "🛡️", Title = "Protect Me", Description = "One click. Falsum checks everything and fixes what it can.", ModuleDir = "", Action = "ProtectAll" },
            new() { Icon = "🔍", Title = "Find Problems", Description = "Vulnerabilities, malware, trackers, weak settings.", ModuleDir = "06-vuln-check", Action = "Test-WeakConfigs" },
            new() { Icon = "🌐", Title = "Network Watch", Description = "See every connection. Block what you don't trust.", ModuleDir = "37-datagate", Action = "Get-FalsumDataSummary" },
            new() { Icon = "👁️", Title = "Browser Shield", Description = "Every tracker and fingerprint attempt, reported here.", ModuleDir = "", Action = "OpenBrowserShield" },
            new() { Icon = "🧹", Title = "Break Loops", Description = "Kill software that reinstalls itself. Fix phantom networks.", ModuleDir = "35-loop-breaker", Action = "Invoke-FalsumLoopBreaker" },
            new() { Icon = "📡", Title = "Satellite Watch", Description = "Bluetooth and satellite exfiltration detection.", ModuleDir = "36-satellite", Action = "Invoke-FalsumSatelliteScan" },
            new() { Icon = "🗑️", Title = "Broker Purge", Description = "Remove your data from 958 data brokers.", ModuleDir = "09-broker-eradicator", Action = "Start-FalsumOneClickBrokerPurge" },
            new() { Icon = "🤖", Title = "AI Chat", Description = "Talk to your local AI. It learns from corrections.", ModuleDir = "38-learning-ai", Action = "Start-FalsumChatLoop" },
            new() { Icon = "📦", Title = "Evidence Vault", Description = "Tamper-evident log of everything Falsum finds.", ModuleDir = "12-timeline-vault", Action = "OpenVault" },
            new() { Icon = "🔓", Title = "Browser Control", Description = "Unlock greyed-out Chrome settings. Remove phantom policies.", ModuleDir = "", Action = "OpenBrowserControl" },
        };

        ModuleCards.ItemsSource = cards;
    }

    private void ModuleCard_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (sender is Border border && border.Tag is ModuleCard card)
        {
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
                // Run full protection sequence
                StatusText.Text = "Running full protection scan...";
                // TODO: orchestrate all modules
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

    private void OpenAIChat_Click(object sender, RoutedEventArgs e)
    {
        // TODO: Open AI chat window
        StatusText.Text = "AI Chat: starting local model...";
    }

    private void OpenSettings_Click(object sender, RoutedEventArgs e)
    {
        // TODO: Open settings
        StatusText.Text = "Settings: not yet implemented.";
    }

    protected override void OnClosed(EventArgs e)
    {
        _engine?.Dispose();
        base.OnClosed(e);
    }
}
