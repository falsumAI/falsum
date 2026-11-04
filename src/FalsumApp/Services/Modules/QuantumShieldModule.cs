// Module 41: Quantum Shield. Faithful C# port of Falsum-QuantumShield.ps1.
// Witness-only transmission logging with SHA-384 hash-chained ledger.
// v6 semantics: redaction is OUT. It logs what leaves, doesn't modify it.
//
// CHAIN FORMAT (must stay byte-identical to the .ps1 so old vaults verify):
//   genesis prev = "QS-GENESIS"
//   canonical    = "{i}|{ts}|{site}|{endpoint}|{bodyLength}|{bodyHash}|{prev}"
//   hash         = SHA384hex( UTF8( canonical + "|" + prev ) )
//   i            = DateTime.UtcNow.ToFileTimeUtc()  (Int64, decimal in JSON)
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class QuantumShieldModule
{
    private const string VaultName = "quantum-shield";
    private const string Genesis = "QS-GENESIS";

    private static string ChainPath() => Path.Combine(Vault.VaultDir(VaultName), "chain.jsonl");

    public static Dictionary<string, object?> NewEntry(string site, string endpoint, string bodyHash, int bodyLength)
    {
        var prev = Genesis;
        var lastLine = Vault.ReadLastLine(ChainPath());
        if (lastLine != null)
        {
            try
            {
                using var doc = JsonDocument.Parse(lastLine);
                if (doc.RootElement.TryGetProperty("hash", out var h))
                    prev = h.GetString() ?? Genesis;
            }
            catch { /* corrupt tail: restart chain from genesis */ }
        }

        long i = DateTime.UtcNow.ToFileTimeUtc();
        string ts = Vault.IsoNow();

        var entry = new Dictionary<string, object?>
        {
            ["i"] = i,
            ["ts"] = ts,
            ["site"] = site,
            ["endpoint"] = endpoint,
            ["bodyLength"] = bodyLength,
            ["bodyHash"] = bodyHash,
            ["prev"] = prev,
        };
        string canonical = $"{i}|{ts}|{site}|{endpoint}|{bodyLength}|{bodyHash}|{prev}";
        entry["hash"] = Vault.Sha384Hex(canonical + "|" + prev);

        Vault.AppendJsonl(ChainPath(), entry);
        return entry;
    }

    public static (bool ok, int count, string message) TestChain()
    {
        string path = ChainPath();
        if (!File.Exists(path)) return (true, 0, "No entries yet");

        string? prevHash = null;
        int count = 0;
        foreach (var doc in Vault.ReadJsonl(path))
        {
            using (doc)
            {
                var r = doc.RootElement;
                long i = r.GetProperty("i").GetInt64();
                string ts = r.GetProperty("ts").GetString() ?? "";
                string site = r.GetProperty("site").GetString() ?? "";
                string endpoint = r.GetProperty("endpoint").GetString() ?? "";
                int bodyLength = r.GetProperty("bodyLength").GetInt32();
                string bodyHash = r.GetProperty("bodyHash").GetString() ?? "";
                string prev = r.GetProperty("prev").GetString() ?? "";
                string hash = r.GetProperty("hash").GetString() ?? "";

                string canonical = $"{i}|{ts}|{site}|{endpoint}|{bodyLength}|{bodyHash}|{prev}";
                string computed = Vault.Sha384Hex(canonical + "|" + prev);
                if (!string.Equals(computed, hash, StringComparison.OrdinalIgnoreCase))
                    return (false, count, $"Hash mismatch at entry {count} - chain broken");
                if (count > 0 && !string.Equals(prev, prevHash, StringComparison.Ordinal))
                    return (false, count, $"Chain link broken at entry {count}");

                prevHash = hash;
                count++;
            }
        }
        return (true, count, $"Chain verified: {count} entries");
    }

    /// <summary>Card action "Get-QuantumShieldStats".</summary>
    public static List<ModuleResult> GetStats()
    {
        string path = ChainPath();
        var docs = Vault.ReadJsonl(path);
        var results = new List<ModuleResult>();
        if (docs.Count == 0)
        {
            results.Add(ModuleResult.Pass("QuantumShield", "No entries yet. The shield starts logging when traffic is witnessed."));
            return results;
        }

        var perSite = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        string lastTs = "";
        foreach (var doc in docs)
        {
            using (doc)
            {
                var r = doc.RootElement;
                string site = r.TryGetProperty("site", out var s) ? s.GetString() ?? "(unknown)" : "(unknown)";
                perSite[site] = perSite.TryGetValue(site, out var c) ? c + 1 : 1;
                if (r.TryGetProperty("ts", out var t)) lastTs = t.GetString() ?? lastTs;
            }
        }

        var (ok, count, message) = TestChain();
        string top = string.Join(", ", perSite.OrderByDescending(kv => kv.Value).Take(5)
            .Select(kv => $"{kv.Key} ({kv.Value})"));
        results.Add(ModuleResult.Pass("QuantumShield",
            $"{count} witnessed transmissions across {perSite.Count} sites. Chain: {(ok ? "valid" : "BROKEN - " + message)}. Top: {top}. Last: {lastTs}.",
            new { entries = count, sites = perSite.Count, chainValid = ok }));
        return results;
    }
}
