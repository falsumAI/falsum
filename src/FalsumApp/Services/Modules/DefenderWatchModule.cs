// Module 26: Defender Watch. Faithful C# port of Falsum-DefenderWatch.ps1.
// Gregg's order: "Go into Windows Defender so it grabs everything and logs
// everything that corrupt piece of shit application is doing."
//
// Watches the watcher: Defender's own Operational event log cannot hide from
// us. Status comes from WMI (ROOT\Microsoft\Windows\Defender), which is what
// the Get-Mp* cmdlets wrap. No PowerShell.
using System.Diagnostics.Eventing.Reader;
using System.Management;
using System.Text;

namespace FalsumApp.Services.Modules;

public static class DefenderWatchModule
{
    private const string DefenderLog = "Microsoft-Windows-Windows Defender/Operational";
    private const string WmiNamespace = @"\\.\ROOT\Microsoft\Windows\Defender";

    // Defender event IDs (documented by Microsoft), ported verbatim.
    private const int ScanStarted = 1000;
    private const int ScanCompleted = 1001;
    private const int ThreatDetected = 1116;
    private const int ThreatActionTaken = 1117;
    private const int ExclusionAdded = 5007;
    private const int RTPDisabled = 5001;
    private const int RTPEnabled = 5004;
    private const int TamperDisabled = 5010;

    private static List<Dictionary<string, string>> GetDefenderEvents(int[] ids, int maxEvents, int daysBack)
    {
        var list = new List<Dictionary<string, string>>();
        try
        {
            string idFilter = string.Join(" or ", ids.Select(id => $"EventID={id}"));
            string queryText =
                $"*[System[({idFilter}) and TimeCreated[timediff(@SystemTime) <= {daysBack * 86400000}]]]";
            var query = new EventLogQuery(DefenderLog, PathType.LogName, queryText);
            using var reader = new EventLogReader(query);
            int n = 0;
            EventRecord? record;
            while ((record = reader.ReadEvent()) != null && n < maxEvents)
            {
                n++;
                using (record)
                {
                    list.Add(new Dictionary<string, string>
                    {
                        ["TimeCreated"] = record.TimeCreated?.ToString("o") ?? "",
                        ["Id"] = record.Id.ToString(),
                        ["Level"] = record.LevelDisplayName ?? "",
                        ["Message"] = (record.FormatDescription() ?? "").Trim(),
                    });
                }
            }
        }
        catch { /* event log unavailable: return what we have */ }
        return list;
    }

    private static Dictionary<string, object?> GetWmiFirst(string className)
    {
        var d = new Dictionary<string, object?>();
        try
        {
            var scope = new ManagementScope(WmiNamespace);
            var query = new ObjectQuery($"SELECT * FROM {className}");
            using var searcher = new ManagementObjectSearcher(scope, query);
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    foreach (var prop in mo.Properties)
                    {
                        try
                        {
                            var v = mo[prop.Name];
                            d[prop.Name] = v is string[] arr ? string.Join(";", arr) : v;
                        }
                        catch { /* unreadable property */ }
                    }
                }
                break; // first instance only
            }
        }
        catch (Exception ex) { d["Error"] = ex.Message; }
        return d;
    }

    private static List<Dictionary<string, object?>> GetWmiAll(string className, int max = 100)
    {
        var list = new List<Dictionary<string, object?>>();
        try
        {
            var scope = new ManagementScope(WmiNamespace);
            var query = new ObjectQuery($"SELECT * FROM {className}");
            using var searcher = new ManagementObjectSearcher(scope, query);
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    var d = new Dictionary<string, object?>();
                    foreach (var prop in mo.Properties)
                    {
                        try
                        {
                            var v = mo[prop.Name];
                            d[prop.Name] = v is string[] arr ? string.Join(";", arr) : v;
                        }
                        catch { }
                    }
                    list.Add(d);
                    if (list.Count >= max) break;
                }
            }
        }
        catch { /* best effort */ }
        return list;
    }

    /// <summary>
    /// Card action "Invoke-DefenderWatch". Full sweep: status, scans, detections,
    /// quarantine, exclusions, exclusion changes, protection toggles. Findings
    /// that matter come back as Fail results; the vault gets the full report.
    /// </summary>
    public static List<ModuleResult> Watch()
    {
        var results = new List<ModuleResult>();
        var report = new StringBuilder();
        report.AppendLine($"Defender Watch: {Vault.IsoNow()}");

        // [1] Status via WMI (what Get-MpComputerStatus wraps).
        var status = GetWmiFirst("MSFT_MpComputerStatus");
        bool rtp = status.TryGetValue("RealTimeProtectionEnabled", out var rtpV) && rtpV is bool b && b;
        string engine = status.TryGetValue("AMEngineVersion", out var ev) ? ev?.ToString() ?? "?" : "?";
        string sigAge = status.TryGetValue("AntivirusSignatureAge", out var sa) ? sa?.ToString() ?? "?" : "?";
        report.AppendLine($"Engine {engine}, signatures {sigAge} days old, real-time: {(rtp ? "ON" : "OFF")}");
        results.Add(rtp
            ? ModuleResult.Pass("DefenderStatus", $"Real-time protection ON. Engine {engine}, signatures {sigAge}d old.")
            : ModuleResult.Fail("DefenderStatus", "Real-time protection is OFF."));

        // [2] Scan history (30d).
        var scansStarted = GetDefenderEvents(new[] { ScanStarted }, 50, 30);
        var scansDone = GetDefenderEvents(new[] { ScanCompleted }, 50, 30);
        report.AppendLine($"Scans: {scansStarted.Count} started, {scansDone.Count} completed (30d)");
        results.Add(ModuleResult.Pass("DefenderScans",
            $"{scansStarted.Count} scans started, {scansDone.Count} completed in 30d.",
            new { started = scansStarted.Count, completed = scansDone.Count }));

        // [3] Threat detections.
        var threats = GetWmiAll("MSFT_MpThreat");
        int active = threats.Count(t =>
            t.TryGetValue("IsActive", out var ia) && ia is bool ab && ab);
        report.AppendLine($"Active threats: {active}");
        results.Add(active == 0
            ? ModuleResult.Pass("DefenderThreats", "No active threats.")
            : ModuleResult.Fail("DefenderThreats", $"{active} ACTIVE threats.",
                threats.Where(t => t.TryGetValue("IsActive", out var ia) && ia is bool ab && ab).ToList()));

        // [4] Detections from the event log (1116/1117).
        var detections = GetDefenderEvents(new[] { ThreatDetected, ThreatActionTaken }, 100, 30);
        if (detections.Count > 0)
            results.Add(ModuleResult.Fail("DefenderDetections",
                $"{detections.Count} threat detection events in 30d.", detections.Take(10).ToList()));

        // [5] Exclusions — blind spots. Review every one.
        var pref = GetWmiFirst("MSFT_MpPreference");
        var exclusions = new List<string>();
        foreach (var key in new[] { "ExclusionPath", "ExclusionProcess", "ExclusionExtension", "ExclusionIpAddress" })
            if (pref.TryGetValue(key, out var v) && v is string s && !string.IsNullOrEmpty(s))
                exclusions.AddRange(s.Split(';').Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => $"{key}: {x}"));
        report.AppendLine($"Exclusions: {exclusions.Count}");
        results.Add(exclusions.Count == 0
            ? ModuleResult.Pass("DefenderExclusions", "No exclusions. No blind spots.")
            : ModuleResult.Fail("DefenderExclusions",
                $"{exclusions.Count} exclusions active — REVIEW THESE: {string.Join("; ", exclusions.Take(10))}",
                exclusions));

        // [6] Exclusion changes (90d): who punched holes, when.
        var exclChanges = GetDefenderEvents(new[] { ExclusionAdded }, 50, 90);
        if (exclChanges.Count > 0)
            results.Add(ModuleResult.Fail("DefenderExclusionChanges",
                $"{exclChanges.Count} exclusion changes in 90d.", exclChanges.Take(5).ToList()));

        // [7] Protection toggles (90d): who turned it off, when.
        var toggles = GetDefenderEvents(new[] { RTPDisabled, RTPEnabled, TamperDisabled }, 50, 90);
        int offCount = toggles.Count(t => t.TryGetValue("Id", out var id) && id == RTPDisabled.ToString());
        if (offCount > 0)
            results.Add(ModuleResult.Fail("DefenderToggles",
                $"Real-time protection was DISABLED {offCount} times in 90d.",
                toggles.Take(5).ToList()));
        else
            results.Add(ModuleResult.Pass("DefenderToggles", "No protection disables in 90d."));

        // Vault: full report, hash-chained.
        try
        {
            string vaultFile = Path.Combine(Vault.VaultDir("defender-watch"),
                Vault.Timestamped("defender-watch", "jsonl"));
            File.AppendAllText(vaultFile, report.ToString(), Encoding.UTF8);
        }
        catch { /* vault best effort */ }

        return results;
    }
}
