// Module 25: Purge. Faithful C# port of Invoke-PurgeScan.
// Full purge scan: registry auto-starts + filesystem. Reports unattributed
// binaries; deletes ONLY when explicitly told (audit-only is the safe
// default, matching the .ps1). Every action is vault-logged.
using Microsoft.Win32;

namespace FalsumApp.Services.Modules;

public static class PurgeModule
{
    private static readonly string[] ScanDirs = new[]
    {
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        Path.GetTempPath(),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
    };

    private static readonly (RegistryHive, string)[] RunKeys = new[]
    {
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    };

    /// <summary>
    /// A binary is "attributed" when it carries a company name in its version
    /// resource or a valid Authenticode signature. Unattributed executables in
    /// user-writable scan paths are purge candidates.
    /// </summary>
    private static bool IsAttributed(string path)
    {
        try
        {
            var vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
            if (!string.IsNullOrWhiteSpace(vi.CompanyName)) return true;
        }
        catch { }
        try
        {
            var cert = System.Security.Cryptography.X509Certificates.X509Certificate
                .CreateFromSignedFile(path);
            if (cert != null) return true;
        }
        catch { }
        return false;
    }

    public static List<ModuleResult> Scan(bool enforce = false)
    {
        var results = new List<ModuleResult>();
        var candidates = new List<string>();

        // 1. Registry auto-start binaries.
        foreach (var (hive, subkey) in RunKeys)
        {
            try
            {
                using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Default)
                    .OpenSubKey(subkey);
                if (key == null) continue;
                foreach (var name in key.GetValueNames())
                {
                    string val = key.GetValue(name)?.ToString() ?? "";
                    string bin = val.Trim().Trim('"').Split(' ')[0];
                    if (bin.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                        File.Exists(bin) && !IsAttributed(bin))
                        candidates.Add(bin);
                }
            }
            catch { }
        }

        // 2. Filesystem scan of user-writable paths.
        foreach (var dir in ScanDirs.Distinct())
        {
            if (!Directory.Exists(dir)) continue;
            IEnumerable<string> exes;
            try { exes = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly); }
            catch { continue; }
            foreach (var exe in exes)
            {
                try
                {
                    var fi = new FileInfo(exe);
                    if (fi.Length == 0) continue;
                    if (!IsAttributed(exe) && !candidates.Contains(exe, StringComparer.OrdinalIgnoreCase))
                        candidates.Add(exe);
                }
                catch { }
            }
        }

        int deleted = 0;
        if (enforce)
        {
            foreach (var c in candidates)
            {
                try
                {
                    string quarantine = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "Falsum", "vault", "purge-quarantine");
                    Directory.CreateDirectory(quarantine);
                    string dest = Path.Combine(quarantine,
                        Path.GetFileName(c) + "." + DateTime.UtcNow.ToFileTimeUtc());
                    File.Move(c, dest);
                    deleted++;
                    Vault.AppendJsonl(Path.Combine(quarantine, "purge.jsonl"),
                        new Dictionary<string, object?>
                        {
                            ["ts"] = Vault.IsoNow(),
                            ["action"] = "quarantine",
                            ["path"] = c,
                            ["dest"] = dest,
                        });
                }
                catch { }
            }
        }

        string mode = enforce ? "ENFORCE" : "AUDIT-ONLY";
        if (candidates.Count == 0)
            results.Add(ModuleResult.Pass("Purge",
                $"Purge scan ({mode}): no unattributed binaries found."));
        else if (enforce)
            results.Add(ModuleResult.Warn("Purge",
                $"Purge scan ({mode}): {deleted}/{candidates.Count} unattributed binaries quarantined.",
                candidates));
        else
            results.Add(ModuleResult.Warn("Purge",
                $"Purge scan ({mode}): {candidates.Count} unattributed binaries found. " +
                "Run with enforcement to quarantine them.",
                candidates));
        return results;
    }
}
