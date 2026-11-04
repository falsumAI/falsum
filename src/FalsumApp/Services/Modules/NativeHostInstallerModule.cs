// Native Host Installer. Replaces Install-NativeHost.ps1.
// Gregg's order: no PowerShell in the product. The installer is C#.
//
// What it does:
//   1. Takes the Chrome extension ID (32 chars, from chrome://extensions).
//   2. Writes the native messaging manifest pointing DIRECTLY at Falsum.exe.
//   3. Registers it for Chrome and Edge in the Windows registry.
// Chrome launches Falsum.exe itself as the host — no scripts, no wrappers.
//
// Run from Falsum: the Browser Shield card offers "Install Browser Link".
using System.Text.Json;
using Microsoft.Win32;

namespace FalsumApp.Services.Modules;

public static class NativeHostInstallerModule
{
    private const string HostName = "com.falsum.native";

    /// <summary>
    /// Installs the native messaging host for Chrome and Edge.
    /// Returns the manifest path, or an error message.
    /// </summary>
    public static (bool Ok, string Message) Install(string extensionId, string exePath)
    {
        // Validate extension ID.
        if (string.IsNullOrWhiteSpace(extensionId) ||
            extensionId.Length != 32 ||
            !extensionId.All(c => c >= 'a' && c <= 'z'))
            return (false, "Invalid extension ID. Must be 32 lowercase letters from chrome://extensions.");

        if (!File.Exists(exePath))
            return (false, $"Falsum.exe not found at: {exePath}");

        try
        {
            string hostDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Falsum", "native-host");
            Directory.CreateDirectory(hostDir);
            string manifestPath = Path.Combine(hostDir, $"{HostName}.json");

            var manifest = new
            {
                name = HostName,
                description = "Falsum native messaging host",
                path = exePath,
                type = "stdio",
                allowed_origins = new[] { $"chrome-extension://{extensionId}/" },
            };
            File.WriteAllText(manifestPath,
                JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));

            // Register for Chrome and Edge.
            foreach (var browser in new[] { "Chrome", "Edge" })
            {
                string regPath = $@"SOFTWARE\Google\{browser}\NativeMessagingHosts\{HostName}";
                // Edge uses a different key.
                if (browser == "Edge")
                    regPath = $@"SOFTWARE\Microsoft\Edge\NativeMessagingHosts\{HostName}";
                using var key = Registry.CurrentUser.CreateSubKey(regPath);
                key?.SetValue("", manifestPath);
            }

            return (true, $"Native host installed. Manifest: {manifestPath}. " +
                "Chrome and Edge can now talk to Falsum.");
        }
        catch (Exception ex)
        {
            return (false, $"Install failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Removes the native messaging host registration.
    /// </summary>
    public static (bool Ok, string Message) Uninstall()
    {
        try
        {
            foreach (var regPath in new[]
            {
                $@"SOFTWARE\Google\Chrome\NativeMessagingHosts\{HostName}",
                $@"SOFTWARE\Microsoft\Edge\NativeMessagingHosts\{HostName}",
            })
            {
                try { Registry.CurrentUser.DeleteSubKeyTree(regPath, false); }
                catch { }
            }
            return (true, "Native host uninstalled.");
        }
        catch (Exception ex)
        {
            return (false, $"Uninstall failed: {ex.Message}");
        }
    }

    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();
        string manifestPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "native-host", $"{HostName}.json");
        results.Add(File.Exists(manifestPath)
            ? ModuleResult.Pass("NativeHost",
                $"Browser link installed: {manifestPath}. " +
                "The extension talks directly to Falsum.exe — no scripts.")
            : ModuleResult.Warn("NativeHost",
                "Browser link not installed. Run Install from the Browser Shield " +
                "card to connect the extension to Falsum."));
        return results;
    }
}
