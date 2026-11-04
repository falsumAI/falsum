using System.Diagnostics;
using System.IO;
using System.Windows;
using FalsumApp.Services;

namespace FalsumApp.Views;

public partial class SettingsWindow : Window
{
    private readonly LocalAIService _ai;
    private readonly string _falsumDir;

    public SettingsWindow()
    {
        InitializeComponent();
        _ai = new LocalAIService();
        _falsumDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Falsum");

        VaultPathText.Text = $"Vault location: {Path.Combine(_falsumDir, "vault")}";
        _ = RefreshStatus();
    }

    private async Task RefreshStatus()
    {
        // AI server status
        var aiRunning = await _ai.IsServerRunning();
        Dispatcher.Invoke(() =>
        {
            if (aiRunning)
            {
                AIStatusDot.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Green);
                AIStatusText.Text = "AI server is running";
            }
            else
            {
                AIStatusDot.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Red);
                AIStatusText.Text = "AI server is not running";
            }
        });

        // Extension bridge status — check if native host manifest is registered
        var manifestPath = Path.Combine(_falsumDir, "bridge", "com.falsum.native.json");
        Dispatcher.Invoke(() =>
        {
            ExtensionStatusText.Text = File.Exists(manifestPath)
                ? "Browser bridge is installed"
                : "Browser bridge is not installed";
        });
    }

    private void StartAIButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var llamaExe = Path.Combine(_falsumDir, "tools", "llama-server.exe");
            var modelPath = Path.Combine(_falsumDir, "ai", "model.gguf");

            if (!File.Exists(llamaExe))
            {
                System.Windows.MessageBox.Show("llama-server.exe not found. Run the installer to download it.",
                    "Falsum", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!File.Exists(modelPath))
            {
                System.Windows.MessageBox.Show("No AI model found. Place a GGUF model at:\n" + modelPath,
                    "Falsum", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = llamaExe,
                Arguments = $"-m \"{modelPath}\" --port 8080",
                UseShellExecute = false,
                CreateNoWindow = true,
            });

            AIStatusText.Text = "Starting AI server...";
            _ = Task.Delay(3000).ContinueWith(_ => RefreshStatus());
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Failed to start AI server: {ex.Message}",
                "Falsum", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void StopAIButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("llama-server"))
                p.Kill();
            _ = RefreshStatus();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Failed to stop AI server: {ex.Message}",
                "Falsum", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void InstallExtensionButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            // The installer script registers the native messaging host
            var scriptPath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory, "Install-NativeHost.ps1");

            if (!File.Exists(scriptPath))
            {
                System.Windows.MessageBox.Show("Bridge installer not found. Re-run the Falsum installer.",
                    "Falsum", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-ExecutionPolicy Bypass -File \"{scriptPath}\"",
                UseShellExecute = true,
                Verb = "runas", // Needs admin to write registry
            });

            System.Windows.MessageBox.Show("Bridge installer launched. Follow the prompts, then load the extension in Chrome.",
                "Falsum", MessageBoxButton.OK, MessageBoxImage.Information);
            _ = Task.Delay(5000).ContinueWith(_ => RefreshStatus());
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Failed to launch bridge installer: {ex.Message}",
                "Falsum", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OpenVaultButton_Click(object sender, RoutedEventArgs e)
    {
        var vaultDir = Path.Combine(_falsumDir, "vault");
        if (!Directory.Exists(vaultDir))
            Directory.CreateDirectory(vaultDir);
        Process.Start(new ProcessStartInfo
        {
            FileName = vaultDir,
            UseShellExecute = true,
        });
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
