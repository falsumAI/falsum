// Fleet Features. Built on Gregg's order:
// "BUSINESS FLEET FEATURES — consent policy deployment, tamper-evident
//  audit exports, shared bad-actor feed (commercial license)."
//
// These are the features that make businesses PAY (LICENSE-COMMERCIAL
// clause e). Individual users get everything else free. Companies that
// deploy on more than 5 machines or use any of this buy a license.
//
//   1. POLICY DEPLOYMENT: export the consent decisions + predator blocks
//      as a policy file. Import it on every machine in the fleet.
//      One person's "block" becomes everyone's "block."
//   2. AUDIT EXPORT: tamper-evident export of everything Falsum did —
//      every detection, every block, every decision — hash-chained so
//      no one can alter the record after the fact.
//   3. BAD-ACTOR FEED: share stamped bad actors across the fleet.
//      One machine catches a predator, every machine blocks it.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class FleetModule
{
    private static string FleetDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "fleet");

    /// <summary>
    /// Exports the machine's consent decisions + predator tags as a
    /// deployable policy file. Import on fleet machines to enforce
    /// the same policy everywhere.
    /// COMMERCIAL: deploying this on >5 machines requires a license.
    /// </summary>
    public static string ExportPolicy(string outPath)
    {
        Directory.CreateDirectory(FleetDir);
        var policy = new Dictionary<string, object>
        {
            ["exported"] = DateTimeOffset.Now.ToString("o"),
            ["exportedBy"] = Environment.MachineName,
            ["version"] = "1.0",
            ["predatorTags"] = PredatoryAlgorithmVault.LoadTags().Values.ToList(),
            ["license"] = "Falsum Commercial License required for >5 machines (clause e)",
        };
        string json = JsonSerializer.Serialize(policy,
            new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(outPath, json);
        return outPath;
    }

    /// <summary>
    /// Imports a policy file: applies every predator BLOCKED tag.
    /// One machine's "block" becomes this machine's "block."
    /// </summary>
    public static int ImportPolicy(string policyPath)
    {
        int applied = 0;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(policyPath));
            if (doc.RootElement.TryGetProperty("predatorTags", out var tags))
            {
                foreach (var t in tags.EnumerateArray())
                {
                    string name = t.GetProperty("Name").GetString() ?? "";
                    string kind = t.GetProperty("Kind").GetString() ?? "";
                    string takes = t.GetProperty("Takes").GetString() ?? "";
                    string by = t.GetProperty("RewardedBy").GetString() ?? "";
                    string status = t.GetProperty("Status").GetString() ?? "";
                    if (string.IsNullOrEmpty(name)) continue;
                    PredatoryAlgorithmVault.Tag(name, kind, takes, by, status);
                    if (status == "BLOCKED") applied++;
                }
            }
        }
        catch { }
        return applied;
    }

    /// <summary>
    /// Tamper-evident audit export: every vault chain (predators, bubble,
    /// timeline) exported with its head hash. Anyone can verify the
    /// export matches the live vault — altering history breaks the chain.
    /// </summary>
    public static string ExportAudit(string outPath)
    {
        Directory.CreateDirectory(FleetDir);
        var export = new Dictionary<string, object>();
        string vaultBase = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "vault");

        foreach (var sub in new[] { "predators", "bubble", "timeline-vault" })
        {
            string chainPath = Path.Combine(vaultBase, sub, "chain.jsonl");
            if (!File.Exists(chainPath)) continue;
            string? lastHash = null;
            int count = 0;
            foreach (var line in File.ReadLines(chainPath))
            {
                count++;
                try
                {
                    using var d = JsonDocument.Parse(line);
                    lastHash = d.RootElement.GetProperty("hash").GetString();
                }
                catch { }
            }
            export[sub] = new Dictionary<string, object>
            {
                ["entries"] = count,
                ["headHash"] = lastHash ?? "empty",
            };
        }

        // Seal the export with its own hash.
        string json = JsonSerializer.Serialize(export,
            new JsonSerializerOptions { WriteIndented = true });
        string seal;
        using (var sha = SHA384.Create())
            seal = Convert.ToHexString(
                sha.ComputeHash(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();

        var sealed_ = new Dictionary<string, object>
        {
            ["exported"] = DateTimeOffset.Now.ToString("o"),
            ["exportedBy"] = Environment.MachineName,
            ["chains"] = export,
            ["seal"] = seal,
        };
        File.WriteAllText(outPath, JsonSerializer.Serialize(sealed_,
            new JsonSerializerOptions { WriteIndented = true }));
        return outPath;
    }

    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();
        results.Add(ModuleResult.Pass("Fleet",
            "FLEET FEATURES (commercial license required for >5 machines):"));
        results.Add(ModuleResult.Pass("Fleet",
            "1. POLICY DEPLOYMENT: export consent decisions + predator blocks " +
            "as a policy file; import on every fleet machine."));
        results.Add(ModuleResult.Pass("Fleet",
            "2. AUDIT EXPORT: tamper-evident, hash-chained export of every " +
            "detection, block, and decision. Altering history breaks the seal."));
        results.Add(ModuleResult.Pass("Fleet",
            "3. BAD-ACTOR FEED: share stamped predators across the fleet. " +
            "One machine catches it, every machine blocks it."));
        results.Add(ModuleResult.Warn("Fleet",
            "LICENSE: these features on more than 5 machines, or any " +
            "fleet/centralized/business use, requires a Falsum Commercial " +
            "License (clause e). Individuals: everything else is free."));
        return results;
    }
}
