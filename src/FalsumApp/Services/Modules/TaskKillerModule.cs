// Module 28: Task Killer. Faithful C# port of Falsum-TaskKiller.ps1.
// Shows the user everything running; they pick what dies. Kill candidates
// are flagged; system-critical processes are never killable.
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public static class TaskKillerModule
{
    private static readonly string[] SystemCriticalProcesses =
    {
        "csrss", "wininit", "services", "lsass", "lsm", "smss", "winlogon",
        "dwm", "explorer", "taskhostw", "sihost", "ctfmon", "conhost",
        "svchost", "RuntimeBroker", "SearchIndexer", "MsMpEng", "NisSrv",
        "spoolsv", "audiodg", "WUDFHost", "dllhost", "WmiPrvSE",
        "System", "Registry", "Memory Compression", "Secure System",
    };

    private sealed record KillEntry(string Name, string Category, string Reason);
    private static readonly KillEntry[] TaskKillList =
    {
        new("OneDriveSetup", "Bloatware", "OneDrive installer residue"),
        new("HP*", "Bloatware", "HP preinstalled utilities"),
        new("Dell*", "Bloatware", "Dell preinstalled utilities"),
        new("Lenovo*", "Bloatware", "Lenovo preinstalled utilities"),
        new("Asus*", "Bloatware", "ASUS preinstalled utilities"),
        new("AdobeARM", "Updater", "Adobe updater (runs on launch anyway)"),
        new("GoogleUpdate", "Updater", "Google updater (Chrome checks on launch)"),
        new("gupdate*", "Updater", "Google update service residue"),
        new("CompatTelRunner", "Telemetry", "Windows compatibility telemetry"),
        new("DiagTrack", "Telemetry", "Diagnostics tracking"),
        new("Cortana", "Bloatware", "Cortana background (deprecated)"),
        new("GameBar*", "Bloatware", "Xbox Game Bar (unless gaming)"),
    };

    private static bool IsSystemCritical(string name)
        => SystemCriticalProcesses.Any(c => string.Equals(c, name, StringComparison.OrdinalIgnoreCase));

    private static KillEntry? KillCandidate(string name)
    {
        if (IsSystemCritical(name)) return null;
        foreach (var e in TaskKillList)
        {
            string pattern = "^" + Regex.Escape(e.Name).Replace(@"\*", ".*") + "$";
            if (Regex.IsMatch(name, pattern, RegexOptions.IgnoreCase)) return e;
        }
        return null;
    }

    public sealed class TaskInfo
    {
        public int Id; public string Name = ""; public double RamMb;
        public string Path = ""; public bool IsSystemCritical;
        public bool KillCandidate; public string KillCategory = ""; public string KillReason = "";
    }

    public static List<TaskInfo> GetBackgroundTasks()
    {
        var list = new List<TaskInfo>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                string name = p.ProcessName;
                bool critical = IsSystemCritical(name);
                var kill = critical ? null : KillCandidate(name);
                double ram = 0;
                try { ram = Math.Round(p.WorkingSet64 / 1048576.0, 1); } catch { }
                string path = "[access denied]";
                try { path = p.MainModule?.FileName ?? path; } catch { }
                list.Add(new TaskInfo
                {
                    Id = p.Id, Name = name, RamMb = ram, Path = path,
                    IsSystemCritical = critical,
                    KillCandidate = kill != null,
                    KillCategory = kill?.Category ?? "",
                    KillReason = kill?.Reason ?? "",
                });
                p.Dispose();
            }
            catch { }
        }
        return list.OrderByDescending(t => t.RamMb).ToList();
    }

    /// <summary>Kill one process. NEVER kills system-critical. Logs to vault.</summary>
    public static string StopBackgroundTask(int pid, string reason)
    {
        Process? p = null;
        try { p = Process.GetProcessById(pid); }
        catch { throw new InvalidOperationException($"No process with PID {pid}"); }
        using (p)
        {
            if (IsSystemCritical(p.ProcessName))
                throw new InvalidOperationException($"Refusing to kill system-critical {p.ProcessName}");
            string name = p.ProcessName;
            p.Kill(true);
            try
            {
                Vault.AppendJsonl(
                    Path.Combine(Vault.VaultDir("task-killer"), "kills.jsonl"),
                    new Dictionary<string, object?>
                    {
                        ["ts"] = Vault.IsoNow(), ["pid"] = pid,
                        ["name"] = name, ["reason"] = reason,
                    });
            }
            catch { }
            return $"Killed {name} (PID {pid})";
        }
    }

    /// <summary>Card action "Invoke-TaskKillerAudit".</summary>
    public static List<ModuleResult> Audit()
    {
        var tasks = GetBackgroundTasks();
        var candidates = tasks.Where(t => t.KillCandidate).ToList();
        double totalRam = Math.Round(tasks.Sum(t => t.RamMb));
        var results = new List<ModuleResult>();
        string msg = $"{tasks.Count} processes, {totalRam} MB RAM. {candidates.Count} kill candidates.";
        if (candidates.Count > 0)
            msg += " Top: " + string.Join("; ",
                candidates.Take(5).Select(c => $"PID {c.Id} {c.Name} ({c.RamMb} MB, {c.KillReason})"));
        results.Add(candidates.Count == 0
            ? ModuleResult.Pass("TaskKiller", msg)
            : ModuleResult.Fail("TaskKiller", msg,
                candidates.Select(c => new { c.Id, c.Name, c.RamMb, c.KillReason }).ToList()));
        return results;
    }
}
