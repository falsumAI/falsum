// Self-Updating Knowledge. Built on Gregg's order:
// "SELF-UPDATING KNOWLEDGE — watches GitHub/new languages, app knowledge
//  updates instantly."
//
// The threat landscape changes daily. New malware, new trackers, new
// telemetry endpoints, new scam patterns. Falsum doesn't wait for a
// version update — it watches its knowledge sources and pulls updates
// the moment they land.
//
// Sources (all user-triggered, nothing phones home on its own):
//   - Predator signatures (telemetry endpoints, tracking domains)
//   - Stalkerware package list (new packages as they're found)
//   - Tracker block list (new tracking domains)
//   - Scam patterns (new lures, new payment red flags)
// Each source is a versioned JSON file. The updater checks the version,
// downloads only if newer, verifies the hash, and swaps it in.
// Knowledge updates are DATA, not code — they can't execute anything.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class KnowledgeUpdaterModule
{
    private static string KnowledgeDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "knowledge");

    public sealed class KnowledgeSource
    {
        public string Name = "";
        public string Url = "";           // where the update lives
        public string LocalFile = "";     // local filename
        public string Version = "";       // current local version
        public string LastChecked = "";
    }

    /// <summary>
    /// The knowledge sources Falsum watches. Each one is versioned data.
    /// Add a source here and the updater picks it up automatically.
    /// </summary>
    private static readonly KnowledgeSource[] Sources = new[]
    {
        new KnowledgeSource { Name = "predator-signatures", LocalFile = "predators.json" },
        new KnowledgeSource { Name = "tracker-domains", LocalFile = "trackers.json" },
        new KnowledgeSource { Name = "stalkerware-packages", LocalFile = "stalkerware.json" },
        new KnowledgeSource { Name = "scam-patterns", LocalFile = "scams.json" },
        new KnowledgeSource { Name = "broker-list", LocalFile = "brokers.json" },
    };

    private static string SourceIndexPath =>
        Path.Combine(KnowledgeDir, "sources.json");

    private static List<KnowledgeSource> LoadSources()
    {
        if (!File.Exists(SourceIndexPath))
            return Sources.ToList();
        try
        {
            return JsonSerializer.Deserialize<List<KnowledgeSource>>(
                File.ReadAllText(SourceIndexPath)) ?? Sources.ToList();
        }
        catch { return Sources.ToList(); }
    }

    private static void SaveSources(List<KnowledgeSource> sources)
    {
        Directory.CreateDirectory(KnowledgeDir);
        File.WriteAllText(SourceIndexPath, JsonSerializer.Serialize(sources,
            new JsonSerializerOptions { WriteIndented = true }));
    }

    /// <summary>
    /// Checks every source for updates. Downloads only if the remote
    /// version is newer. Verifies SHA-256 before swapping in.
    /// Returns what changed.
    /// </summary>
    public static List<ModuleResult> CheckForUpdates()
    {
        var results = new List<ModuleResult>();
        var sources = LoadSources();
        int updated = 0;

        foreach (var s in sources)
        {
            if (string.IsNullOrEmpty(s.Url))
            {
                results.Add(ModuleResult.Pass("KnowledgeUpdater",
                    $"{s.Name}: no remote URL configured. " +
                    "Set one to enable auto-updates for this source."));
                continue;
            }

            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
                // Fetch the version manifest first (tiny).
                string manifestUrl = s.Url.TrimEnd('/') + "/version.json";
                string manifestJson = http.GetStringAsync(manifestUrl).Result;
                using var doc = JsonDocument.Parse(manifestJson);
                string remoteVersion = doc.RootElement.GetProperty("version").GetString() ?? "";
                string remoteHash = doc.RootElement.GetProperty("sha256").GetString() ?? "";
                string dataUrl = doc.RootElement.GetProperty("url").GetString() ?? "";

                if (remoteVersion == s.Version)
                {
                    s.LastChecked = DateTimeOffset.Now.ToString("o");
                    results.Add(ModuleResult.Pass("KnowledgeUpdater",
                        $"{s.Name}: up to date (v{s.Version})."));
                    continue;
                }

                // Newer version: download, verify hash, swap in.
                byte[] data = http.GetByteArrayAsync(dataUrl).Result;
                string actualHash;
                using (var sha = SHA256.Create())
                    actualHash = Convert.ToHexString(sha.ComputeHash(data)).ToLowerInvariant();

                if (actualHash != remoteHash.ToLowerInvariant())
                {
                    results.Add(ModuleResult.Fail("KnowledgeUpdater",
                        $"{s.Name}: HASH MISMATCH on v{remoteVersion}. " +
                        "Update REJECTED — the file doesn't match its manifest. " +
                        "This is how supply-chain attacks die."));
                    continue;
                }

                string localPath = Path.Combine(KnowledgeDir, s.LocalFile);
                // Validate it's parseable JSON before swapping.
                JsonDocument.Parse(Encoding.UTF8.GetString(data));
                File.WriteAllBytes(localPath, data);
                s.Version = remoteVersion;
                s.LastChecked = DateTimeOffset.Now.ToString("o");
                updated++;
                results.Add(ModuleResult.Pass("KnowledgeUpdater",
                    $"{s.Name}: updated to v{remoteVersion} (hash verified)."));
            }
            catch (Exception ex)
            {
                results.Add(ModuleResult.Warn("KnowledgeUpdater",
                    $"{s.Name}: update check failed: {ex.Message}. " +
                    "Local knowledge still active — nothing broken."));
            }
        }

        SaveSources(sources);
        if (updated > 0)
            results.Add(ModuleResult.Pass("KnowledgeUpdater",
                $"{updated} knowledge source(s) updated. The app got smarter " +
                "without a reinstall."));
        return results;
    }

    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();
        var sources = LoadSources();
        results.Add(ModuleResult.Pass("KnowledgeUpdater",
            $"{sources.Count} knowledge source(s) watched. " +
            "Run CheckForUpdates to pull the latest threat intel. " +
            "Updates are versioned data with hash verification — " +
            "never executable code."));
        foreach (var s in sources)
        {
            results.Add(ModuleResult.Pass("KnowledgeUpdater",
                $"{s.Name}: v{s.Version ?? "none"} " +
                $"(last checked: {s.LastChecked ?? "never"})."));
        }
        return results;
    }
}
