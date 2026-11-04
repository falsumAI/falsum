using System.IO;
// Module 39: Chrome Internals. Faithful C# port of Falsum-ChromeInternals.ps1.
// Reads what chrome:// pages show — from disk, not the browser:
// Local State (policies = enterprise control?), Preferences (WebRTC, extensions,
// sync, Privacy Sandbox), History DB info.
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class ChromeInternalsModule
{
    private static string? FindProfileRoot()
    {
        string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (var candidate in new[]
        {
            Path.Combine(localApp, "Google", "Chrome", "User Data"),
            Path.Combine(localApp, "Chromium", "User Data"),
            Path.Combine(localApp, "Microsoft", "Edge", "User Data"),
        })
            if (Directory.Exists(candidate)) return candidate;
        return null;
    }

    private static JsonDocument? ReadJson(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            return JsonDocument.Parse(File.ReadAllText(path));
        }
        catch { return null; }
    }

    /// <summary>Card action "Invoke-FalsumChromeInternalsScan".</summary>
    public static List<ModuleResult> Scan()
    {
        var results = new List<ModuleResult>();
        string? root = FindProfileRoot();
        if (root == null)
        {
            results.Add(ModuleResult.Pass("ChromeInternals", "No Chrome/Chromium/Edge profile found."));
            return results;
        }
        results.Add(ModuleResult.Pass("ChromeInternals", $"Profile root: {root}"));

        // [1] Local State: enterprise policies?
        using (var localState = ReadJson(Path.Combine(root, "Local State")))
        {
            if (localState != null)
            {
                var r = localState.RootElement;
                if (r.TryGetProperty("policy", out _))
                    results.Add(ModuleResult.Fail("ChromeInternals",
                        "Browser policies detected in Local State (chrome://policy) — this browser may be enterprise-managed."));
                if (r.TryGetProperty("profile", out var profile) &&
                    profile.TryGetProperty("info_cache", out var cache))
                {
                    var names = new List<string>();
                    foreach (var p in cache.EnumerateObject()) names.Add(p.Name);
                    results.Add(ModuleResult.Pass("ChromeInternals",
                        $"Profiles: {string.Join(", ", names)}"));
                }
            }
        }

        string defaultProfile = Path.Combine(root, "Default");
        if (!Directory.Exists(defaultProfile))
        {
            results.Add(ModuleResult.Pass("ChromeInternals", "No Default profile directory."));
            return results;
        }

        // [2] Preferences: WebRTC, extensions, sync, Privacy Sandbox.
        using (var prefs = ReadJson(Path.Combine(defaultProfile, "Preferences")))
        {
            if (prefs != null)
            {
                var r = prefs.RootElement;
                if (r.TryGetProperty("webrtc", out var webrtc) &&
                    webrtc.TryGetProperty("ip_handling_policy", out var ipp))
                    results.Add(ModuleResult.Pass("ChromeInternals",
                        $"WebRTC IP policy: {ipp.GetString()}"));
                else
                    results.Add(ModuleResult.Fail("ChromeInternals",
                        "WebRTC IP policy: default (may leak local IPs)."));

                if (r.TryGetProperty("extensions", out var ext) &&
                    ext.TryGetProperty("settings", out var settings))
                {
                    int broad = 0;
                    var broadNames = new List<string>();
                    foreach (var e in settings.EnumerateObject())
                    {
                        try
                        {
                            var manifest = e.Value.GetProperty("manifest");
                            string name = manifest.TryGetProperty("name", out var n) ? n.GetString() ?? "" : e.Name;
                            if (manifest.TryGetProperty("permissions", out var perms))
                            {
                                string joined = string.Join(",", perms.EnumerateArray()
                                    .Select(p => p.ValueKind == JsonValueKind.String ? p.GetString() ?? "" : p.ToString()));
                                if (joined.Contains("tabs") || joined.Contains("webRequest") ||
                                    joined.Contains("cookies") || joined.Contains("history") ||
                                    joined.Contains("management"))
                                { broad++; broadNames.Add(name); }
                            }
                        }
                        catch { }
                    }
                    int total = settings.EnumerateObject().Count();
                    results.Add(broad == 0
                        ? ModuleResult.Pass("ChromeInternals", $"{total} extensions, none with broad permissions.")
                        : ModuleResult.Fail("ChromeInternals",
                            $"{broad}/{total} extensions with broad permissions: {string.Join(", ", broadNames.Take(5))}"));
                }

                if (r.TryGetProperty("sync", out _))
                    results.Add(ModuleResult.Fail("ChromeInternals",
                        "Browser sync is enabled (data going to vendor servers)."));

                bool topicsOff = r.TryGetProperty("privacy_sandbox", out var ps) &&
                    ps.TryGetProperty("topics_enabled", out var te) && !te.GetBoolean();
                results.Add(ModuleResult.Pass("ChromeInternals",
                    $"Privacy Sandbox Topics: {(topicsOff ? "disabled (good)" : "enabled")}"));
            }
        }

        // [3] History DB: size + last write (copy first — Chrome locks it).
        try
        {
            string history = Path.Combine(defaultProfile, "History");
            if (File.Exists(history))
            {
                string tmp = Path.Combine(Path.GetTempPath(), "falsum-history-copy.db");
                File.Copy(history, tmp, overwrite: true);
                var info = new FileInfo(tmp);
                results.Add(ModuleResult.Pass("ChromeInternals",
                    $"History DB: {Math.Round(info.Length / 1048576.0, 1)} MB, last write {info.LastWriteTime}."));
                try { File.Delete(tmp); } catch { }
            }
        }
        catch { }

        // [4] WebRTC logs.
        try
        {
            string wrtc = Path.Combine(defaultProfile, "webrtc_event_logs");
            if (Directory.Exists(wrtc))
            {
                int n = Directory.GetFiles(wrtc).Length;
                if (n > 0)
                    results.Add(ModuleResult.Fail("ChromeInternals",
                        $"{n} WebRTC event log files present — WebRTC has been active."));
            }
        }
        catch { }

        return results;
    }
}
