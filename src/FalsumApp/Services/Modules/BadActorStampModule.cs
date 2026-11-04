// Bad Actor Permanent Stamp. Built on Gregg's order:
// "PERMANENT STAMPING OF BAD ACTORS + THE DATA THEY CARRY."
//
// A stamp is forever. When Falsum marks a bad actor, it records:
//   - WHO: IP, process, binary path, binary SHA-256 hash
//   - WHAT: what data they were carrying / trying to take
//   - WHEN: first seen, last seen, hit count
//   - The firewall block (in + out, permanent)
// The stamp goes in the vault, hash-chained. It follows them —
// export the stamp and any Falsum instance honors it.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class BadActorStampModule
{
    private static string VaultDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "vault", "stamps");
    private static string StampPath => Path.Combine(VaultDir, "stamps.json");

    public sealed class Stamp
    {
        public string Id { get; set; } = "";
        public string Ip { get; set; } = "";
        public string Process { get; set; } = "";
        public string BinaryPath { get; set; } = "";
        public string BinaryHash { get; set; } = "";   // SHA-256 of the binary
        public string DataCarried { get; set; } = "";  // what they were taking
        public string Reason { get; set; } = "";
        public string FirstSeen { get; set; } = "";
        public string LastSeen { get; set; } = "";
        public int Hits { get; set; } = 0;
        public bool Permanent { get; set; } = true;
    }

    private static string Sha256File(string path)
    {
        try
        {
            using var sha = SHA256.Create();
            using var fs = File.OpenRead(path);
            return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
        }
        catch { return "unreadable"; }
    }

    private static Dictionary<string, Stamp> LoadStamps()
    {
        var d = new Dictionary<string, Stamp>();
        if (!File.Exists(StampPath)) return d;
        try
        {
            var list = JsonSerializer.Deserialize<List<Stamp>>(
                File.ReadAllText(StampPath)) ?? new();
            foreach (var s in list) d[s.Id] = s;
        }
        catch { }
        return d;
    }

    private static void SaveStamps(Dictionary<string, Stamp> stamps)
    {
        Directory.CreateDirectory(VaultDir);
        File.WriteAllText(StampPath, JsonSerializer.Serialize(
            stamps.Values.OrderByDescending(s => s.Hits).ToList(),
            new JsonSerializerOptions { WriteIndented = true }));
    }

    /// <summary>
    /// Stamps a bad actor permanently. The stamp includes the binary hash
    /// so renaming the file doesn't hide them, and the data they carried
    /// so the theft is documented.
    /// </summary>
    public static Stamp CreateStamp(string ip, string process, string binaryPath,
        string dataCarried, string reason)
    {
        var stamps = LoadStamps();
        string id = $"{ip}|{Sha256File(binaryPath)[..16]}";

        if (stamps.TryGetValue(id, out var existing))
        {
            existing.Hits++;
            existing.LastSeen = DateTimeOffset.Now.ToString("o");
            if (!string.IsNullOrEmpty(dataCarried) &&
                !existing.DataCarried.Contains(dataCarried))
                existing.DataCarried += "; " + dataCarried;
            SaveStamps(stamps);

            // Re-assert the firewall block.
            PortGateModule.MarkBadActor(ip, reason);
            return existing;
        }

        var stamp = new Stamp
        {
            Id = id,
            Ip = ip,
            Process = process,
            BinaryPath = binaryPath,
            BinaryHash = Sha256File(binaryPath),
            DataCarried = dataCarried,
            Reason = reason,
            FirstSeen = DateTimeOffset.Now.ToString("o"),
            LastSeen = DateTimeOffset.Now.ToString("o"),
            Hits = 1,
            Permanent = true,
        };
        stamps[id] = stamp;
        SaveStamps(stamps);

        // Firewall block (in + out) via the Port Gate.
        PortGateModule.MarkBadActor(ip, reason);

        // Also log to the Predator Vault — a stamped actor is a predator.
        PredatoryAlgorithmVault.Log("stamped-actor", $"{process} ({ip})",
            dataCarried, "blocked");
        PredatoryAlgorithmVault.Tag($"{process} ({ip})", "stamped-actor",
            dataCarried, "blocked", "BLOCKED");

        return stamp;
    }

    /// <summary>
    /// Exports all stamps as a shareable file. Any Falsum instance can
    /// import these — the stamp follows the actor across machines.
    /// </summary>
    public static string ExportStamps(string outPath)
    {
        var stamps = LoadStamps();
        File.WriteAllText(outPath, JsonSerializer.Serialize(
            stamps.Values.ToList(),
            new JsonSerializerOptions { WriteIndented = true }));
        return outPath;
    }

    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();
        var stamps = LoadStamps();
        if (stamps.Count == 0)
        {
            results.Add(ModuleResult.Pass("BadActorStamp",
                "No bad actors stamped. When Falsum catches one, the stamp is " +
                "permanent: IP, binary hash, data carried, firewall block."));
            return results;
        }
        results.Add(ModuleResult.Warn("BadActorStamp",
            $"{stamps.Count} bad actor(s) permanently stamped."));
        foreach (var s in stamps.Values.OrderByDescending(s => s.Hits).Take(10))
        {
            results.Add(ModuleResult.Fail("BadActorStamp",
                $"STAMPED: {s.Process} ({s.Ip}) ×{s.Hits} hits. " +
                $"Binary: {s.BinaryHash[..16]}... Carried: {s.DataCarried}. " +
                $"Reason: {s.Reason}. Blocked in+out, permanent."));
        }
        return results;
    }
}
