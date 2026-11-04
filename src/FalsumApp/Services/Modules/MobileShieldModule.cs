// Module 24: Mobile Shield. Faithful C# port of Invoke-BackupStalkerwareScan.
// Scans for stalkerware indicators: package-name match against the shipped
// table (49 known spouseware packages), plus suspicious-profile checks.
// Read-only. Every finding ships the removal step (Better-Way Law).
// The card action scans the common phone-backup locations on this PC.
namespace FalsumApp.Services.Modules;

public static class MobileShieldModule
{
    public sealed class Finding
    {
        public string Severity = "High";
        public string Title = "";
        public string Evidence = "";
        public string Removal = "";
    }

    private static readonly string[] BackupRoots = new[]
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Apple Computer", "MobileSync", "Backup"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Android"),
    };

    /// <summary>
    /// Scans a directory tree for stalkerware package-name indicators.
    /// </summary>
    public static List<Finding> ScanPath(string root, int maxFiles = 50000)
    {
        var findings = new List<Finding>();
        if (!Directory.Exists(root)) return findings;
        int seen = 0;
        var pkgs = MobileShieldData.Packages
            .ToDictionary(p => p.Package, StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                if (++seen > maxFiles) break;
                string name = Path.GetFileName(file);
                // Android dumps: scan directory names under Android/data.
                string dir = Path.GetDirectoryName(file) ?? "";
                foreach (var pkg in pkgs.Values)
                {
                    if (dir.Contains(pkg.Package, StringComparison.OrdinalIgnoreCase) ||
                        name.Contains(pkg.Package, StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(new Finding
                        {
                            Title = $"Stalkerware indicator: {pkg.Name}",
                            Evidence = $"Package {pkg.Package} found at {file}. {pkg.Notes}",
                            Removal = $"Uninstall {pkg.Package} from the phone immediately. " +
                                      "Then change all passwords from a clean device and check for unknown device-management profiles.",
                        });
                        break;
                    }
                }
                // iOS: suspicious .mobileconfig profiles.
                if (name.EndsWith(".mobileconfig", StringComparison.OrdinalIgnoreCase))
                    findings.Add(new Finding
                    {
                        Severity = "Medium",
                        Title = "Configuration profile in backup",
                        Evidence = file,
                        Removal = "On the iPhone: Settings > General > VPN & Device Management — remove any profile you did not install yourself.",
                    });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (PathTooLongException) { }
        return findings;
    }

    /// <summary>
    /// Card action "Invoke-BackupStalkerwareScan": scans the common phone
    /// backup locations on this PC.
    /// </summary>
    public static List<ModuleResult> ScanBackups()
    {
        var results = new List<ModuleResult>();
        var all = new List<Finding>();
        foreach (var root in BackupRoots)
            all.AddRange(ScanPath(root));
        if (all.Count == 0)
            results.Add(ModuleResult.Pass("MobileShield",
                $"Scanned {BackupRoots.Length} backup location(s). No stalkerware indicators found. " +
                $"Table: {MobileShieldData.Packages.Length} known packages (dated {MobileShieldData.TableDate})."));
        else
            foreach (var x in all.Take(20))
                results.Add(ModuleResult.Fail("MobileShield",
                    $"{x.Severity}: {x.Title} — {x.Evidence} Removal: {x.Removal}"));
        return results;
    }
}
