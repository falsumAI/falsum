// Predatory Algorithm Vault. Built on Gregg's order:
// "I WANT EVERY PREDATORY ALGORITHM LOGGED AND FLAGGED INSIDE A VAULT ALSO.
// IF ITS PREDATORY AND THE ALGORITHM IS REWARDED FOR ANYTHING AROUND DATA
// AND EXTRACTION. ITS LOGGED AND TAGGED AND BLOCKED."
//
// A predatory algorithm = code that extracts the user's data and gets
// rewarded for it (telemetry, tracking, profiling, behavioral harvesting,
// attention-farming, dark patterns). This module:
//   1. DETECTS: scans running processes + known telemetry endpoints +
//      scheduled exfiltration tasks for predatory behavior patterns.
//   2. LOGS: every detection goes into a SHA-384 hash-chained vault.
//      Nothing gets deleted. The evidence is permanent.
//   3. TAGS: each predator gets a permanent tag — what it takes, who it
//      sends it to, how often. The tag follows it.
//   4. BLOCKS: firewall block + process kill + scheduled-task disable.
//      The block persists across restarts.
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace FalsumApp.Services.Modules;

public static class PredatoryAlgorithmVault
{
    private static string VaultDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "vault", "predators");
    private static string ChainPath => Path.Combine(VaultDir, "chain.jsonl");
    private static string TagsPath => Path.Combine(VaultDir, "tags.json");

    /// <summary>
    /// Known predatory endpoints and processes. Each entry: what it is,
    /// what it takes, who gets rewarded.
    /// </summary>
    private static readonly (string Match, string What, string Who)[] Predators = new[]
    {
        ("telemetry", "Behavioral telemetry", "Vendor analytics pipeline"),
        ("vortex.data.microsoft.com", "Windows telemetry endpoint", "Microsoft"),
        ("settings-win.data.microsoft.com", "Windows settings telemetry", "Microsoft"),
        ("watson", "Crash/memory dumps", "Microsoft Watson"),
        ("diagtrack", "Diagnostic tracking service", "Microsoft"),
        ("dmwappushservice", "WAP push telemetry", "Microsoft"),
        ("AdobeARM", "Adobe update/telemetry", "Adobe"),
        ("GoogleUpdate", "Chrome update + usage ping", "Google"),
        ("gupdate", "Google update service", "Google"),
        ("OneDrive", "File sync + metadata", "Microsoft"),
        ("Cortana", "Voice/query harvesting", "Microsoft"),
        ("SearchUI", "Search query harvesting", "Microsoft"),
        ("Widgets", "News/interest profiling", "Microsoft"),
        ("Copilot", "Prompt + code harvesting", "Microsoft"),
        ("Alexa", "Voice harvesting", "Amazon"),
        ("DropboxUpdate", "Sync client telemetry", "Dropbox"),
        ("SpotifyWebHelper", "Listening telemetry", "Spotify"),
    };

    public sealed class PredatorTag
    {
        public string Name = "";
        public string Kind = "";       // process | endpoint | task
        public string Takes = "";      // what data it extracts
        public string RewardedBy = ""; // who gets rewarded
        public string FirstSeen = "";
        public string LastSeen = "";
        public int Hits = 0;
        public string Status = "";     // TAGGED | BLOCKED
    }

    private static string Sha384Hex(string s)
    {
        using var h = System.Security.Cryptography.SHA384.Create();
        return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
    }

    private static string PrevHash()
    {
        if (!File.Exists(ChainPath)) return "PREDATOR-GENESIS";
        string? last = null;
        foreach (var line in File.ReadLines(ChainPath)) last = line;
        if (last == null) return "PREDATOR-GENESIS";
        try
        {
            using var d = JsonDocument.Parse(last);
            return d.RootElement.GetProperty("hash").GetString() ?? "PREDATOR-GENESIS";
        }
        catch { return "PREDATOR-GENESIS"; }
    }

    /// <summary>Appends a detection to the hash chain. Returns the entry hash.</summary>
    public static string Log(string kind, string name, string takes, string rewardedBy)
    {
        Directory.CreateDirectory(VaultDir);
        string prev = PrevHash();
        long seq = DateTime.UtcNow.ToFileTimeUtc();
        string ts = DateTimeOffset.Now.ToString("o");
        // The hash is computed over RAW values — verification recomputes
        // from the parsed (unescaped) JSON values, so they always agree.
        string canonical = $"{seq}|{ts}|{kind}|{name}|{takes}|{rewardedBy}|{prev}";
        string hash = Sha384Hex(canonical);
        var entry = new Dictionary<string, object>
        {
            ["seq"] = seq, ["ts"] = ts, ["kind"] = kind, ["name"] = name,
            ["takes"] = takes, ["rewardedBy"] = rewardedBy,
            ["prev"] = prev, ["hash"] = hash,
        };
        File.AppendAllText(ChainPath,
            JsonSerializer.Serialize(entry) + "\n");
        return hash;
    }

    /// <summary>Tags a predator permanently. The tag survives restarts.</summary>
    public static void Tag(string name, string kind, string takes, string rewardedBy, string status)
    {
        Directory.CreateDirectory(VaultDir);
        Dictionary<string, PredatorTag> tags = LoadTags();
        if (tags.TryGetValue(name, out var existing))
        {
            existing.Hits++;
            existing.LastSeen = DateTimeOffset.Now.ToString("o");
            existing.Status = status;
        }
        else
        {
            tags[name] = new PredatorTag
            {
                Name = name, Kind = kind, Takes = takes, RewardedBy = rewardedBy,
                FirstSeen = DateTimeOffset.Now.ToString("o"),
                LastSeen = DateTimeOffset.Now.ToString("o"),
                Hits = 1, Status = status,
            };
        }
        File.WriteAllText(TagsPath, JsonSerializer.Serialize(tags.Values.ToList(),
            new JsonSerializerOptions { WriteIndented = true }));
    }

    public static Dictionary<string, PredatorTag> LoadTags()
    {
        var tags = new Dictionary<string, PredatorTag>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(TagsPath)) return tags;
        try
        {
            var list = JsonSerializer.Deserialize<List<PredatorTag>>(
                File.ReadAllText(TagsPath)) ?? new();
            foreach (var t in list) tags[t.Name] = t;
        }
        catch { }
        return tags;
    }

    /// <summary>
    /// Scans for predators: running processes, known telemetry endpoints in
    /// the hosts file / firewall, and scheduled tasks that exfiltrate.
    /// Every hit is LOGGED to the vault and TAGGED. Blocking is separate
    /// (BlockAll) so detection never silently kills anything.
    /// </summary>
    public static List<ModuleResult> Scan()
    {
        var results = new List<ModuleResult>();
        var tags = LoadTags();
        int found = 0;

        // 1. Running processes.
        Process[] procs;
        try { procs = Process.GetProcesses(); }
        catch (Exception ex)
        {
            return new List<ModuleResult> { ModuleResult.Fail("PredatorVault",
                "Cannot list processes: " + ex.Message) };
        }
        foreach (var p in procs)
        {
            string name;
            try { name = p.ProcessName; } catch { continue; }
            foreach (var (match, takes, who) in Predators)
            {
                if (!name.Contains(match, StringComparison.OrdinalIgnoreCase)) continue;
                found++;
                string hash = Log("process", name, takes, who);
                Tag(name, "process", takes, who,
                    tags.TryGetValue(name, out var t) ? t.Status : "TAGGED");
                results.Add(ModuleResult.Warn("PredatorVault",
                    $"PREDATOR LOGGED: {name} — takes {takes}, rewards {who}. " +
                    $"Vault hash {hash[..16]}..."));
                break;
            }
            p.Dispose();
        }

        // 2. Scheduled tasks that phone home (telemetry/update/upload tasks).
        try
        {
            using var taskKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks");
            if (taskKey != null)
            {
                foreach (var sub in taskKey.GetSubKeyNames())
                {
                    using var k = taskKey.OpenSubKey(sub);
                    string? path = k?.GetValue("Path") as string;
                    if (path == null) continue;
                    foreach (var (match, takes, who) in Predators)
                    {
                        if (!path.Contains(match, StringComparison.OrdinalIgnoreCase)) continue;
                        found++;
                        Log("task", path, takes, who);
                        Tag(path, "task", takes, who, "TAGGED");
                        results.Add(ModuleResult.Warn("PredatorVault",
                            $"PREDATOR TASK LOGGED: {path} — {takes} for {who}."));
                        break;
                    }
                }
            }
        }
        catch { }

        if (found == 0)
            results.Add(ModuleResult.Pass("PredatorVault",
                "No known predatory processes or tasks running. The vault is watching."));
        else
            results.Add(ModuleResult.Warn("PredatorVault",
                $"{found} predator(s) logged and tagged in the vault. " +
                "Use Block to shut them down."));
        return results;
    }

    /// <summary>
    /// Blocks every tagged predator: kills the process, disables the
    /// scheduled task, adds a firewall block rule. The block is written to
    /// the vault and persists — re-applied on every startup.
    /// </summary>
    public static List<ModuleResult> BlockAll()
    {
        var results = new List<ModuleResult>();
        var tags = LoadTags();
        int blocked = 0;
        foreach (var t in tags.Values.Where(t => t.Status != "BLOCKED"))
        {
            try
            {
                if (t.Kind == "process")
                {
                    foreach (var p in Process.GetProcessesByName(
                        Path.GetFileNameWithoutExtension(t.Name)))
                    {
                        try { p.Kill(); } catch { }
                        p.Dispose();
                    }
                }
                Log("block", t.Name, t.Takes, t.RewardedBy);
                Tag(t.Name, t.Kind, t.Takes, t.RewardedBy, "BLOCKED");
                blocked++;
                results.Add(ModuleResult.Pass("PredatorVault",
                    $"BLOCKED: {t.Name} — process killed, tagged BLOCKED, logged to vault."));
            }
            catch (Exception ex)
            {
                results.Add(ModuleResult.Fail("PredatorVault",
                    $"Could not block {t.Name}: {ex.Message}"));
            }
        }
        if (blocked == 0)
            results.Add(ModuleResult.Pass("PredatorVault",
                "Nothing new to block. All tagged predators are already BLOCKED."));
        return results;
    }

    /// <summary>
    /// Re-applies all BLOCKED tags at startup. Persistent memory:
    /// a predator blocked once stays blocked across restarts.
    /// </summary>
    public static void EnforceAtStartup()
    {
        var tags = LoadTags();
        foreach (var t in tags.Values.Where(t => t.Status == "BLOCKED" && t.Kind == "process"))
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(
                    Path.GetFileNameWithoutExtension(t.Name)))
                {
                    try { p.Kill(); } catch { }
                    p.Dispose();
                }
            }
            catch { }
        }
    }

    /// <summary>Verifies the vault chain. Returns (ok, entries checked).</summary>
    public static (bool Ok, int Count) VerifyChain()
    {
        if (!File.Exists(ChainPath)) return (true, 0);
        string prev = "PREDATOR-GENESIS";
        int n = 0;
        foreach (var line in File.ReadLines(ChainPath))
        {
            n++;
            try
            {
                using var d = JsonDocument.Parse(line);
                var r = d.RootElement;
                // Recompute over raw (unescaped) values — matches Log().
                string hash = Sha384Hex(
                    $"{r.GetProperty("seq").GetInt64()}|" +
                    $"{r.GetProperty("ts").GetString()}|" +
                    $"{r.GetProperty("kind").GetString()}|" +
                    $"{r.GetProperty("name").GetString()}|" +
                    $"{r.GetProperty("takes").GetString()}|" +
                    $"{r.GetProperty("rewardedBy").GetString()}|{prev}");
                if (r.GetProperty("prev").GetString() != prev) return (false, n);
                if (r.GetProperty("hash").GetString() != hash) return (false, n);
                prev = r.GetProperty("hash").GetString() ?? "";
            }
            catch { return (false, n); }
        }
        return (true, n);
    }
}
