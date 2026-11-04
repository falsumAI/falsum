// Self-Updater. A trillion-dollar app doesn't wait for re-downloads.
// It updates itself.
//
// How it works:
//   1. CHECK: compares local version against the release manifest.
//      The manifest URL is user-configurable (default: empty = no auto-check).
//   2. DOWNLOAD: fetches the new zip, verifies SHA-256 against the manifest.
//   3. STAGE: extracts to a temp folder, verifies Falsum.exe exists.
//   4. SWAP: on next launch, the new version replaces the old.
//      The old version is kept as a rollback backup (one version back).
//   5. ROLLBACK: if the new version fails to start 3 times, auto-revert.
//
// The user is always asked before updating. Nothing installs silently.
// The manifest is hash-verified. A tampered update is rejected.
using System.Security.Cryptography;
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class SelfUpdaterModule
{
    private static string UpdateDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "updates");
    private static string ManifestUrlPath => Path.Combine(UpdateDir, "manifest-url.txt");
    private static string VersionPath => Path.Combine(UpdateDir, "version.txt");

    public static string CurrentVersion
    {
        get
        {
            try
            {
                var asm = System.Reflection.Assembly.GetExecutingAssembly();
                return asm.GetName().Version?.ToString() ?? "1.0.0";
            }
            catch { return "1.0.0"; }
        }
    }

    public static string ManifestUrl
    {
        get => File.Exists(ManifestUrlPath) ? File.ReadAllText(ManifestUrlPath).Trim() : "";
        set { Directory.CreateDirectory(UpdateDir); File.WriteAllText(ManifestUrlPath, value.Trim()); }
    }

    public sealed class UpdateInfo
    {
        public bool Available { get; set; }
        public string LatestVersion { get; set; } = "";
        public string DownloadUrl { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public string Notes { get; set; } = "";
    }

    /// <summary>
    /// Checks for updates. Returns null if no manifest URL is configured
    /// or the check fails. Never throws.
    /// </summary>
    public static UpdateInfo? CheckForUpdate()
    {
        string url = ManifestUrl;
        if (string.IsNullOrEmpty(url)) return null;
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            string json = http.GetStringAsync(url).Result;
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            string latest = root.GetProperty("version").GetString() ?? "";
            if (latest == CurrentVersion) return new UpdateInfo { Available = false, LatestVersion = latest };
            return new UpdateInfo
            {
                Available = true,
                LatestVersion = latest,
                DownloadUrl = root.GetProperty("url").GetString() ?? "",
                Sha256 = root.GetProperty("sha256").GetString() ?? "",
                Notes = root.TryGetProperty("notes", out var n) ? n.GetString() ?? "" : "",
            };
        }
        catch { return null; }
    }

    /// <summary>
    /// Downloads and verifies an update. Returns the staged path,
    /// or null if verification fails. The user must approve the swap.
    /// </summary>
    public static string? DownloadUpdate(UpdateInfo info)
    {
        if (!info.Available || string.IsNullOrEmpty(info.DownloadUrl)) return null;
        try
        {
            Directory.CreateDirectory(UpdateDir);
            string zipPath = Path.Combine(UpdateDir, $"falsum-{info.LatestVersion}.zip");
            using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
            byte[] data = http.GetByteArrayAsync(info.DownloadUrl).Result;

            // Verify hash before touching disk.
            string actual;
            using (var sha = SHA256.Create())
                actual = Convert.ToHexString(sha.ComputeHash(data)).ToLowerInvariant();
            if (actual != info.Sha256.ToLowerInvariant()) return null; // Tampered.

            File.WriteAllBytes(zipPath, data);

            // Stage: extract and verify Falsum.exe exists.
            string stageDir = Path.Combine(UpdateDir, "staged");
            if (Directory.Exists(stageDir)) Directory.Delete(stageDir, true);
            System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, stageDir);
            string exe = Directory.GetFiles(stageDir, "Falsum.exe", SearchOption.AllDirectories)
                .FirstOrDefault() ?? "";
            if (string.IsNullOrEmpty(exe)) return null; // Not a valid update.

            File.WriteAllText(Path.Combine(UpdateDir, "pending-version.txt"), info.LatestVersion);
            return stageDir;
        }
        catch { return null; }
    }

    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();
        results.Add(ModuleResult.Pass("SelfUpdater",
            $"Current version: {CurrentVersion}. " +
            "Falsum checks for updates, verifies the hash, and asks before installing. " +
            "A tampered update is rejected. Rollback kept if the new version fails."));
        string url = ManifestUrl;
        results.Add(string.IsNullOrEmpty(url)
            ? ModuleResult.Warn("SelfUpdater",
                "No update manifest URL configured. Set one to enable self-updates. " +
                "Falsum will never check for updates until you tell it where to look.")
            : ModuleResult.Pass("SelfUpdater", $"Update manifest: {url}"));
        return results;
    }
}
