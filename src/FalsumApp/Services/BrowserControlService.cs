using Microsoft.Win32;
using System.Collections.ObjectModel;

namespace FalsumApp.Services;

/// <summary>
/// Browser control — runs inside the C# app, not as a .ps1 file.
/// Finds and removes the enterprise policies greying out Chrome settings.
/// </summary>
public class BrowserControlService
{
    public ObservableCollection<BrowserPolicy> DetectedPolicies { get; } = new();

    private readonly string[] _policyRoots = new[]
    {
        @"SOFTWARE\Policies\Google\Chrome",
        @"SOFTWARE\Policies\Microsoft\Edge",
    };

    /// <summary>
    /// Scan registry for browser policies locking the user's settings.
    /// </summary>
    public void ScanForPolicies()
    {
        DetectedPolicies.Clear();

        foreach (var root in _policyRoots)
        {
            // Check HKLM (machine-wide, needs admin to remove)
            ScanHive(Registry.LocalMachine, root, "Machine");
            // Check HKCU (user-level)
            ScanHive(Registry.CurrentUser, root, "User");
        }

        // Check forced extensions
        ScanHive(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", "Machine");
        ScanHive(Registry.CurrentUser, @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", "User");
    }

    private void ScanHive(RegistryKey hive, string path, string scope)
    {
        try
        {
            using var key = hive.OpenSubKey(path);
            if (key == null) return;

            foreach (var valueName in key.GetValueNames())
            {
                var value = key.GetValue(valueName);
                DetectedPolicies.Add(new BrowserPolicy
                {
                    Hive = hive.Name,
                    Path = path,
                    Name = valueName,
                    Value = value?.ToString() ?? "",
                    Scope = scope,
                    Description = DescribePolicy(valueName, value?.ToString() ?? "")
                });
            }
        }
        catch { /* Access denied — needs admin */ }
    }

    private string DescribePolicy(string name, string value)
    {
        // Plain-language descriptions of what each policy locks
        return name switch
        {
            "HomepageLocation" => "Locks your homepage — you can't change it",
            "DefaultSearchProviderEnabled" => "Locks your search engine",
            "PasswordManagerEnabled" => "Disables Chrome's password manager",
            "SafeBrowsingEnabled" => "Controls Safe Browsing (greyed out in settings)",
            "WebRTCIPHandlingPolicy" => "Controls whether WebRTC leaks your local IP",
            "SyncDisabled" => "Disables or forces browser sync",
            "ExtensionInstallForcelist" => "Forces extensions you can't remove",
            "BrowserSignin" => "Controls Google sign-in (greyed out)",
            "IncognitoModeAvailability" => "Disables or forces Incognito mode",
            "DefaultCookiesSetting" => "Locks cookie settings",
            "DefaultGeolocationSetting" => "Locks location permissions",
            _ => $"Locks '{name}' in Chrome settings"
        };
    }

    /// <summary>
    /// Remove all detected policies. Backs up first.
    /// </summary>
    public (int removed, string backupPath) RemoveAllPolicies()
    {
        var backupDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "vault", $"policy-backup-{DateTime.Now:yyyyMMdd-HHmmss}");
        Directory.CreateDirectory(backupDir);

        int removed = 0;

        foreach (var root in _policyRoots)
        {
            // Backup HKLM
            BackupKey(Registry.LocalMachine, root, backupDir);
            // Backup HKCU
            BackupKey(Registry.CurrentUser, root, backupDir);

            // Remove HKLM (needs admin)
            if (RemoveKey(Registry.LocalMachine, root)) removed++;
            // Remove HKCU
            if (RemoveKey(Registry.CurrentUser, root)) removed++;
        }

        // Clear the detected list
        DetectedPolicies.Clear();

        return (removed, backupDir);
    }

    private void BackupKey(RegistryKey hive, string path, string backupDir)
    {
        try
        {
            using var key = hive.OpenSubKey(path);
            if (key == null) return;

            var safeName = $"{hive.Name.Replace("HKEY_", "")}_{path.Replace('\\', '_')}.txt";
            var backupFile = Path.Combine(backupDir, safeName);

            using var writer = new StreamWriter(backupFile);
            writer.WriteLine($"[{hive.Name}\\{path}]");
            writer.WriteLine($"Backed up: {DateTime.Now:o}");
            writer.WriteLine();
            foreach (var valueName in key.GetValueNames())
            {
                writer.WriteLine($"{valueName}={key.GetValue(valueName)}");
            }
        }
        catch { }
    }

    private bool RemoveKey(RegistryKey hive, string path)
    {
        try
        {
            // Get parent and key name
            var lastSlash = path.LastIndexOf('\\');
            var parentPath = path.Substring(0, lastSlash);
            var keyName = path.Substring(lastSlash + 1);

            using var parent = hive.OpenSubKey(parentPath, writable: true);
            if (parent == null) return false;

            parent.DeleteSubKeyTree(keyName, throwOnMissingSubKey: false);
            return true;
        }
        catch
        {
            return false; // Likely needs admin for HKLM
        }
    }
}

public class BrowserPolicy
{
    public string Hive { get; set; } = "";
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public string Scope { get; set; } = "";
    public string Description { get; set; } = "";
}
