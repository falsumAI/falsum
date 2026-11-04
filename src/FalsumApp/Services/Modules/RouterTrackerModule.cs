// Module 45: Router Tracker. Faithful C# port of Falsum-RouterTracker.ps1.
// Captures router login events. The user installs, tries the router login with
// the log open, and exports JSON. NEVER stores passwords — by design.
using System.Text;
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class RouterTrackerModule
{
    private const string VaultName = "router-tracker";

    private static string LogPath() => Path.Combine(Vault.VaultDir(VaultName), "logins.jsonl");

    public static Dictionary<string, object?> NewLoginEntry(
        string routerIp, string username, bool success,
        string userAgent = "", string details = "")
    {
        var entry = new Dictionary<string, object?>
        {
            ["ts"] = Vault.IsoNow(),
            ["routerIp"] = routerIp,
            ["username"] = username,
            ["success"] = success,
            ["userAgent"] = userAgent,
            ["details"] = details,
        };
        Vault.AppendJsonl(LogPath(), entry);
        return entry;
    }

    public static List<Dictionary<string, object?>> GetHistory(int lastN = 100)
    {
        var docs = Vault.ReadJsonl(LogPath());
        var list = new List<Dictionary<string, object?>>();
        foreach (var doc in docs)
        {
            using (doc)
            {
                // Keep only the tail; still dispose every document.
                var d = new Dictionary<string, object?>();
                foreach (var p in doc.RootElement.EnumerateObject())
                    d[p.Name] = Vault.ElementToObject(p.Value);
                list.Add(d);
            }
        }
        if (list.Count > lastN)
            list = list.Skip(list.Count - lastN).ToList();
        return list;
    }

    private static bool IsFailure(Dictionary<string, object?> e)
        => !(e.TryGetValue("success", out var v) && v is bool b && b);

    /// <summary>
    /// Card action "Test-RouterLoginAnomaly". Flags: brute-force failure runs,
    /// many distinct user agents, logins at unusual hours (11pm-5am).
    /// </summary>
    public static List<ModuleResult> TestAnomaly()
    {
        var results = new List<ModuleResult>();
        var history = GetHistory(100);
        if (history.Count == 0)
        {
            results.Add(ModuleResult.Pass("RouterTracker", "No login history."));
            return results;
        }

        var anomalies = new List<string>();
        int failures = history.Count(IsFailure);
        if (failures > 5)
            anomalies.Add($"Multiple failed logins ({failures}) - possible brute force");

        int agents = history.Select(e => e.TryGetValue("userAgent", out var v) ? v?.ToString() ?? "" : "")
            .Distinct(StringComparer.Ordinal).Count();
        if (agents > 3)
            anomalies.Add($"Multiple different user agents ({agents}) - possible unauthorized access");

        int night = 0;
        foreach (var e in history)
        {
            if (e.TryGetValue("ts", out var v) && DateTimeOffset.TryParse(v?.ToString(), out var dto))
            {
                int h = dto.Hour;
                if (h < 5 || h > 23) night++;
            }
        }
        if (night > 0)
            anomalies.Add($"{night} logins during unusual hours (11pm-5am)");

        string msg = anomalies.Count == 0
            ? $"{history.Count} logins checked, no anomalies."
            : $"{history.Count} logins, {failures} failed. Anomalies: {string.Join("; ", anomalies)}";
        results.Add(anomalies.Count == 0
            ? ModuleResult.Pass("RouterTracker", msg, new { totalLogins = history.Count, failedLogins = failures })
            : ModuleResult.Fail("RouterTracker", msg));
        return results;
    }

    public static string ExportJson(string? outputPath = null)
    {
        outputPath ??= Vault.DesktopPath(Vault.Timestamped("router-logins", "json"));
        var history = GetHistory(1000);
        // Reuse anomaly logic on the wider set via a lightweight recompute.
        var pack = new Dictionary<string, object?>
        {
            ["exported"] = Vault.IsoNow(),
            ["logins"] = history,
        };
        File.WriteAllText(outputPath,
            JsonSerializer.Serialize(pack, new JsonSerializerOptions { WriteIndented = true }),
            Encoding.UTF8);
        return outputPath;
    }
}
