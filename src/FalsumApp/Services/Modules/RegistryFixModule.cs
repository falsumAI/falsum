// Module 29: Registry Fix. Faithful C# port of Falsum-RegistryFix.ps1.
// Finds bad autostart entries: empty, nameless, or orphaned (pointing at
// missing files). Audit-only by default; removal is explicit and backed up.
using System.Text;
using Microsoft.Win32;

namespace FalsumApp.Services.Modules;

public sealed class BadRegistryEntry
{
    public string KeyPath = "";
    public string ValueName = "";
    public string Data = "";
    public string Issues = "";
    public bool Protected;
}

public static class RegistryFixModule
{
    private static readonly string[] ScanKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    };

    private static readonly string[] ProtectedPaths =
    {
        @"C:\Windows\System32", @"C:\Windows\SysWOW64",
        @"C:\Windows\WinSxS", @"C:\Windows\",
    };

    private static (RegistryKey root, string subkey, string label)[] AllKeys()
    {
        var list = new List<(RegistryKey, string, string)>();
        foreach (var k in ScanKeys)
        {
            list.Add((Registry.LocalMachine, k, "HKLM:\\" + k));
            list.Add((Registry.CurrentUser, k, "HKCU:\\" + k));
        }
        return list.ToArray();
    }

    private static bool IsProtected(string data)
    {
        if (string.IsNullOrWhiteSpace(data)) return false;
        string expanded = Environment.ExpandEnvironmentVariables(data);
        return ProtectedPaths.Any(p =>
            expanded.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsOrphaned(string data)
    {
        if (string.IsNullOrWhiteSpace(data)) return false;
        string path = data.Trim();
        if (path.StartsWith('"'))
        {
            int end = path.IndexOf('"', 1);
            if (end > 0) path = path.Substring(1, end - 1);
        }
        else if (!File.Exists(path) && !Directory.Exists(path))
        {
            path = path.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
        }
        path = Environment.ExpandEnvironmentVariables(path);
        return !string.IsNullOrWhiteSpace(path) && !File.Exists(path) && !Directory.Exists(path);
    }

    public static List<BadRegistryEntry> FindBadEntries()
    {
        var findings = new List<BadRegistryEntry>();
        foreach (var (root, subkey, label) in AllKeys())
        {
            RegistryKey? key = null;
            try { key = root.OpenSubKey(subkey); }
            catch { continue; }
            if (key == null) continue;
            using (key)
            {
                string[] names;
                try { names = key.GetValueNames(); } catch { continue; }
                foreach (var name in names)
                {
                    object? raw;
                    try { raw = key.GetValue(name); } catch { continue; }
                    string data = raw is string[] arr ? string.Join(";", arr) : raw?.ToString() ?? "";
                    var issues = new List<string>();
                    if (string.IsNullOrWhiteSpace(data)) issues.Add("EMPTY: value has no data");
                    if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(data))
                        issues.Add("NAMELESS: no name and no data");
                    if (!string.IsNullOrWhiteSpace(data) && IsOrphaned(data))
                        issues.Add("ORPHANED: points to missing file");
                    if (issues.Count > 0)
                        findings.Add(new BadRegistryEntry
                        {
                            KeyPath = label, ValueName = name, Data = data,
                            Issues = string.Join("; ", issues),
                            Protected = IsProtected(data),
                        });
                }
            }
        }
        return findings;
    }

    /// <summary>
    /// Remove one bad entry. Backs up the value to the vault first.
    /// Refuses protected entries.
    /// </summary>
    public static string RemoveEntry(string keyLabel, string valueName)
    {
        var found = FindBadEntries().FirstOrDefault(f =>
            f.KeyPath == keyLabel && f.ValueName == valueName)
            ?? throw new InvalidOperationException("Entry not found in scan results");
        if (found.Protected)
            throw new InvalidOperationException("Refusing to remove protected system entry");

        // Backup.
        string backupDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "regfix-backup");
        Directory.CreateDirectory(backupDir);
        string backupFile = Path.Combine(backupDir,
            $"regfix-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.txt");
        File.WriteAllText(backupFile,
            $"[{found.KeyPath}]\n\"{found.ValueName}\"={found.Data}\n", Encoding.UTF8);

        // Remove.
        RegistryKey root = keyLabel.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase)
            ? Registry.LocalMachine : Registry.CurrentUser;
        string subkey = keyLabel.Substring(6); // strip "HKLM:\" / "HKCU:\"
        using var key = root.OpenSubKey(subkey, writable: true)
            ?? throw new InvalidOperationException("Cannot open key for writing");
        key.DeleteValue(valueName, throwOnMissingValue: false);
        return $"Removed {keyLabel} \\ {valueName} (backup: {backupFile})";
    }

    /// <summary>Card action "Invoke-RegistryFixScan". Audit only.</summary>
    public static List<ModuleResult> Scan()
    {
        var findings = FindBadEntries();
        var results = new List<ModuleResult>();
        if (findings.Count == 0)
        {
            results.Add(ModuleResult.Pass("RegistryFix", "No bad autostart entries found."));
            return results;
        }
        int removable = findings.Count(f => !f.Protected);
        results.Add(ModuleResult.Fail("RegistryFix",
            $"{findings.Count} bad entries ({removable} removable, {findings.Count - removable} protected): " +
            string.Join("; ", findings.Take(5).Select(f => $"{f.KeyPath}\\{f.ValueName}: {f.Issues}")),
            findings));
        return results;
    }
}
