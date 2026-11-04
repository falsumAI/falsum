// Module 42: Agent Watchdog. Faithful C# port of Falsum-AgentWatchdog.ps1.
// Bodycam for AI agents on the user's property.
// Tamper-evident SHA-384 hash-chained log. Human vs agent via isTrusted:
// untrusted events are treated as potential agent activity.
// Hard line: no agents in the browser, period. End consumer first.
//
// CHAIN FORMAT (must stay byte-identical to the .ps1 so old vaults verify):
//   genesis prev = "AW-GENESIS"
//   canonical    = "{seq}|{t}|{cat}|{act}|{trusted}|{page}|{target}|{prev}"
//   hash         = SHA384hex( UTF8( canonical + "|" + prev ) )
//   trusted renders as "True"/"False" (PowerShell bool interpolation).
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class AgentWatchdogModule
{
    private const string VaultName = "agent-watchdog";
    private const string Genesis = "AW-GENESIS";

    private static string ChainPath() => Path.Combine(Vault.VaultDir(VaultName), "chain.jsonl");

    public static Dictionary<string, object?> NewEntry(
        string category, string action, bool isTrusted,
        string page = "", string target = "", string details = "")
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

        long seq = DateTime.UtcNow.ToFileTimeUtc();
        string t = Vault.IsoNow();
        string trustedStr = isTrusted ? "True" : "False";
        bool agent = !isTrusted; // Untrusted events = potential agent activity

        var entry = new Dictionary<string, object?>
        {
            ["seq"] = seq,
            ["t"] = t,
            ["cat"] = category,
            ["act"] = action,
            ["trusted"] = isTrusted,
            ["agent"] = agent,
            ["page"] = page,
            ["target"] = target,
            ["details"] = details,
            ["prev"] = prev,
        };
        string canonical = $"{seq}|{t}|{category}|{action}|{trustedStr}|{page}|{target}|{prev}";
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
                long seq = r.GetProperty("seq").GetInt64();
                string t = r.GetProperty("t").GetString() ?? "";
                string cat = r.GetProperty("cat").GetString() ?? "";
                string act = r.GetProperty("act").GetString() ?? "";
                bool trusted = r.GetProperty("trusted").GetBoolean();
                string page = r.GetProperty("page").GetString() ?? "";
                string target = r.GetProperty("target").GetString() ?? "";
                string prev = r.GetProperty("prev").GetString() ?? "";
                string hash = r.GetProperty("hash").GetString() ?? "";

                string canonical = $"{seq}|{t}|{cat}|{act}|{(trusted ? "True" : "False")}|{page}|{target}|{prev}";
                string computed = Vault.Sha384Hex(canonical + "|" + prev);
                if (!string.Equals(computed, hash, StringComparison.OrdinalIgnoreCase))
                    return (false, count, $"Tamper detected at entry {count}");
                if (count > 0 && !string.Equals(prev, prevHash, StringComparison.Ordinal))
                    return (false, count, $"Chain broken at entry {count}");

                prevHash = hash;
                count++;
            }
        }
        return (true, count, $"Chain verified: {count} entries");
    }

    /// <summary>Card action "Get-WatchdogAgentActivity". Returns untrusted (agent) entries.</summary>
    public static List<ModuleResult> GetAgentActivity(int lastN = 50)
    {
        var results = new List<ModuleResult>();
        var docs = Vault.ReadJsonl(ChainPath());
        if (docs.Count == 0)
        {
            results.Add(ModuleResult.Pass("AgentWatchdog", "No events logged yet."));
            return results;
        }

        var tail = docs.Skip(Math.Max(0, docs.Count - lastN)).ToList();
        int agentCount = 0;
        var samples = new List<string>();
        foreach (var doc in tail)
        {
            using (doc)
            {
                var r = doc.RootElement;
                bool agent = r.TryGetProperty("agent", out var a) && a.GetBoolean();
                if (!agent) continue;
                agentCount++;
                if (samples.Count < 5)
                {
                    string act = r.TryGetProperty("act", out var ac) ? ac.GetString() ?? "" : "";
                    string page = r.TryGetProperty("page", out var p) ? p.GetString() ?? "" : "";
                    samples.Add($"{act} on {page}");
                }
            }
        }
        foreach (var d in docs)
            if (!tail.Contains(d)) d.Dispose();

        var (ok, count, message) = TestChain();
        string msg = agentCount == 0
            ? $"No agent activity in the last {tail.Count} events. Chain: {(ok ? "valid" : "BROKEN - " + message)}."
            : $"{agentCount} untrusted (agent) events in the last {tail.Count}. Chain: {(ok ? "valid" : "BROKEN - " + message)}. Latest: {string.Join("; ", samples)}.";
        results.Add(agentCount == 0
            ? ModuleResult.Pass("AgentWatchdog", msg, new { agentEvents = agentCount, chainValid = ok })
            : ModuleResult.Fail("AgentWatchdog", msg));
        return results;
    }

    public static string ExportEvidencePack(string? outputPath = null)
    {
        string path = ChainPath();
        if (!File.Exists(path)) throw new InvalidOperationException("No watchdog data to export");

        outputPath ??= Vault.DesktopPath(Vault.Timestamped("watchdog-evidence", "json"));

        var docs = Vault.ReadJsonl(path);
        var entries = new List<Dictionary<string, object?>>();
        int agentCount = 0;
        foreach (var doc in docs)
        {
            using (doc)
            {
                var dict = new Dictionary<string, object?>();
                foreach (var p in doc.RootElement.EnumerateObject())
                    dict[p.Name] = p.Value.ToString();
                entries.Add(dict);
                if (doc.RootElement.TryGetProperty("agent", out var a) && a.GetBoolean()) agentCount++;
            }
        }
        var (ok, count, _) = TestChain();
        var pack = new Dictionary<string, object?>
        {
            ["exported"] = Vault.IsoNow(),
            ["chainValid"] = ok,
            ["entryCount"] = count,
            ["agentActivityCount"] = agentCount,
            ["entries"] = entries,
        };
        File.WriteAllText(outputPath,
            System.Text.Json.JsonSerializer.Serialize(pack, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }),
            System.Text.Encoding.UTF8);
        return outputPath;
    }
}
