using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.IO;

namespace FalsumApp.Services;

/// <summary>
/// Windows system policy liberator — removes the "your organization" locks
/// that block downloads, installations, and system changes.
/// Runs inside the C# app.
/// </summary>
public class SystemPolicyService
{
    public ObservableCollection<SystemPolicy> DetectedPolicies { get; } = new();

    // Registry locations where "your organization" policies hide
    private readonly (string hive, string path, string description)[] _policyLocations = new[]
    {
        ("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\System",
            "SmartScreen and system behavior locks"),
        ("HKLM", @"SOFTWARE\Policies\Microsoft\Windows Defender",
            "Windows Defender locks (may block downloads)"),
        ("HKLM", @"SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen",
            "SmartScreen download blocking"),
        ("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments",
            "Attachment/download zone blocking (SaveZoneInformation)"),
        ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            "System-wide policy locks"),
        ("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Policies",
            "User-level policy locks"),
        ("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Installer",
            "Windows Installer blocks (can't install software)"),
        ("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Appx",
            "App installation blocks"),
    };

    public void ScanForPolicies()
    {
        DetectedPolicies.Clear();

        foreach (var (hiveName, path, category) in _policyLocations)
        {
            var hive = hiveName == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;

            try
            {
                using var key = hive.OpenSubKey(path);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName);
                    DetectedPolicies.Add(new SystemPolicy
                    {
                        Hive = hiveName,
                        Path = path,
                        Name = valueName,
                        Value = value?.ToString() ?? "",
                        Category = category,
                        Description = DescribePolicy(valueName, value?.ToString() ?? "")
                    });
                }

                // Also check subkeys
                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    using var subKey = key.OpenSubKey(subKeyName);
                    if (subKey == null) continue;
                    foreach (var valueName in subKey.GetValueNames())
                    {
                        var value = subKey.GetValue(valueName);
                        DetectedPolicies.Add(new SystemPolicy
                        {
                            Hive = hiveName,
                            Path = $"{path}\\{subKeyName}",
                            Name = valueName,
                            Value = value?.ToString() ?? "",
                            Category = category,
                            Description = DescribePolicy(valueName, value?.ToString() ?? "")
                        });
                    }
                }
            }
            catch { /* Needs admin */ }
        }
    }

    private string DescribePolicy(string name, string value)
    {
        return name switch
        {
            "EnableSmartScreen" => value == "0"
                ? "SmartScreen disabled by policy"
                : "SmartScreen controlled by policy — can block downloads",
            "SaveZoneInformation" => "Blocks or marks downloaded files (the 'organization blocks download' culprit)",
            "DisableAntiSpyware" => "Windows Defender disabled by policy",
            "DisableRealtimeMonitoring" => "Real-time protection disabled by policy",
            "AllowStorageSenseGlobal" => "Storage Sense controlled by policy",
            "NoControlPanel" => "Control Panel blocked by policy",
            "DisableRegistryTools" => "Registry Editor blocked — you can't even fix this manually",
            "DisableTaskMgr" => "Task Manager blocked by policy",
            _ => $"Policy '{name}' is controlling your system"
        };
    }

    public (int removed, string backupPath) RemoveAllPolicies()
    {
        var backupDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "vault", $"syspolicy-backup-{DateTime.Now:yyyyMMdd-HHmmss}");
        Directory.CreateDirectory(backupDir);

        int removed = 0;

        foreach (var (hiveName, path, _) in _policyLocations)
        {
            var hive = hiveName == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;

            BackupKey(hive, hiveName, path, backupDir);

            if (RemoveKey(hive, path)) removed++;
        }

        DetectedPolicies.Clear();
        return (removed, backupDir);
    }

    private void BackupKey(RegistryKey hive, string hiveName, string path, string backupDir)
    {
        try
        {
            using var key = hive.OpenSubKey(path);
            if (key == null) return;

            var safeName = $"{hiveName}_{path.Replace('\\', '_')}.txt";
            var backupFile = Path.Combine(backupDir, safeName);

            using var writer = new StreamWriter(backupFile);
            writer.WriteLine($"[{hiveName}\\{path}]");
            writer.WriteLine($"Backed up: {DateTime.Now:o}\n");

            WriteKeyRecursive(writer, key, "");
        }
        catch { }
    }

    private void WriteKeyRecursive(StreamWriter writer, RegistryKey key, string indent)
    {
        foreach (var valueName in key.GetValueNames())
        {
            writer.WriteLine($"{indent}{valueName}={key.GetValue(valueName)}");
        }
        foreach (var subKeyName in key.GetSubKeyNames())
        {
            using var subKey = key.OpenSubKey(subKeyName);
            if (subKey != null)
            {
                writer.WriteLine($"{indent}[{subKeyName}]");
                WriteKeyRecursive(writer, subKey, indent + "  ");
            }
        }
    }

    private bool RemoveKey(RegistryKey hive, string path)
    {
        try
        {
            var lastSlash = path.LastIndexOf('\\');
            var parentPath = path.Substring(0, lastSlash);
            var keyName = path.Substring(lastSlash + 1);

            using var parent = hive.OpenSubKey(parentPath, writable: true);
            if (parent == null) return false;

            parent.DeleteSubKeyTree(keyName, throwOnMissingSubKey: false);
            return true;
        }
        catch { return false; }
    }
}

public class SystemPolicy
{
    public string Hive { get; set; } = "";
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
}
