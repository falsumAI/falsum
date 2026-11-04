using System.IO;
// Module 20: Backup Shield. Faithful C# port of New-BackupPlan's safety gates.
// Creates a versioned backup plan. The safety rules are the point:
//   - every source must exist
//   - the destination must exist
//   - the destination must NOT overlap a source (a mirror into an
//     overlapping tree grows forever or eats its own output)
//   - KeepVersions >= 1
// No backup runs until the user starts one. The card action validates a
// default plan for the user's Documents folder.
namespace FalsumApp.Services.Modules;

public static class BackupShieldModule
{
    public sealed class BackupPlan
    {
        public string Name = "default";
        public string[] SourceDirs = Array.Empty<string>();
        public string Destination = "";
        public int KeepVersions = 4;
    }

    private static string PlansDir =>
        Path.Combine(Vault.VaultDir("backup-shield"), "plans");

    /// <summary>True when the destination is inside (or equal to) any source.</summary>
    public static bool Overlaps(string[] sources, string dest)
    {
        string d = Path.GetFullPath(dest).TrimEnd(Path.DirectorySeparatorChar)
            .ToLowerInvariant();
        foreach (var s in sources)
        {
            string src = Path.GetFullPath(s).TrimEnd(Path.DirectorySeparatorChar)
                .ToLowerInvariant();
            if (d == src || d.StartsWith(src + Path.DirectorySeparatorChar))
                return true;
        }
        return false;
    }

    /// <summary>Validates and saves a backup plan. Throws on any safety violation.</summary>
    public static BackupPlan NewPlan(string[] sourceDirs, string destination,
        string name = "default", int keepVersions = 4)
    {
        foreach (var s in sourceDirs)
            if (!Directory.Exists(s))
                throw new ArgumentException($"Source not found: {s}");
        if (!Directory.Exists(destination))
            throw new ArgumentException($"Destination not found: {destination}");
        if (Overlaps(sourceDirs, destination))
            throw new ArgumentException(
                "Destination overlaps a source dir. A mirror into an overlapping tree " +
                "grows forever or eats its own output. Pick a destination OUTSIDE every source.");
        if (keepVersions < 1)
            throw new ArgumentException("KeepVersions must be >= 1.");
        var plan = new BackupPlan
        {
            Name = name, SourceDirs = sourceDirs,
            Destination = destination, KeepVersions = keepVersions,
        };
        Directory.CreateDirectory(PlansDir);
        string planFile = Path.Combine(PlansDir, name + ".json");
        var json = "{\n" +
            $"  \"name\": \"{name}\",\n" +
            "  \"sources\": [" + string.Join(", ",
                sourceDirs.Select(s => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"")) + "],\n" +
            $"  \"destination\": \"{destination.Replace("\\", "\\\\").Replace("\"", "\\\"")}\",\n" +
            $"  \"keepVersions\": {keepVersions},\n" +
            $"  \"createdUtc\": \"{DateTime.UtcNow:o}\"\n}}";
        File.WriteAllText(planFile, json);
        Vault.AppendJsonl(Path.Combine(PlansDir, "plans.jsonl"),
            new Dictionary<string, object?>
            {
                ["ts"] = Vault.IsoNow(),
                ["action"] = "new-plan",
                ["name"] = name,
                ["destination"] = destination,
            });
        return plan;
    }

    /// <summary>
    /// Card action "New-BackupPlan": validates the safety gates on a default
    /// plan (Documents -> first removable drive, else reports what is missing).
    /// </summary>
    public static List<ModuleResult> DefaultPlanCheck()
    {
        var results = new List<ModuleResult>();
        string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var removable = DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
            .Select(d => d.RootDirectory.FullName)
            .FirstOrDefault();
        if (removable == null)
        {
            results.Add(ModuleResult.Warn("BackupShield",
                "No removable drive found. Plug in a USB drive to create a backup plan. " +
                $"Default source would be: {docs}"));
            return results;
        }
        try
        {
            var plan = NewPlan(new[] { docs }, removable, "default", 4);
            results.Add(ModuleResult.Pass("BackupShield",
                $"Backup plan 'default' validated and saved: {docs} -> {removable} " +
                $"(keep {plan.KeepVersions} versions). No backup runs until you start one.",
                new { source = docs, destination = removable }));
        }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Fail("BackupShield",
                "Backup plan failed safety gates: " + ex.Message));
        }
        return results;
    }
}
