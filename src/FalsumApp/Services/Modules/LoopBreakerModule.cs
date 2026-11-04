// Module 35: Loop Breaker. Faithful C# port of Falsum-LoopBreaker.ps1.
// Solves the two loops Gregg struggled to get rid of:
//   1. SOFTWARE LOOP: programs that reinstall themselves, won't uninstall, keep coming back
//   2. NETWORK LOOP: phantom network configs that revert, connections that won't die
// Audit is read-only; breaking a loop is explicit.
using System.Management;
using System.Text;
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public sealed class LoopFinding
{
    public string Type = "";
    public string Name = "";
    public string Path = "";
    public string Description = "";
}

public static class LoopBreakerModule
{
    public static List<LoopFinding> FindSoftwareLoops()
    {
        var loops = new List<LoopFinding>();

        // Reinstall scheduled tasks: update/install/repair/maintain pointing at an exe.
        try
        {
            var t = Type.GetTypeFromProgID("Schedule.Service");
            if (t != null)
            {
                dynamic svc = Activator.CreateInstance(t)!;
                svc.Connect();
                var queue = new Queue<dynamic>();
                queue.Enqueue(svc.GetFolder("\\"));
                while (queue.Count > 0)
                {
                    dynamic folder = queue.Dequeue();
                    try
                    {
                        foreach (dynamic sub in folder.GetFolders(0)) queue.Enqueue(sub);
                        foreach (dynamic task in folder.GetTasks(1))
                        {
                            try
                            {
                                string name = (task.Name as string) ?? "";
                                if (!Regex.IsMatch(name, "update|install|repair|maintain", RegexOptions.IgnoreCase))
                                    continue;
                                string state = "";
                                try { state = task.State.ToString(); } catch { }
                                if (!state.Contains("Ready", StringComparison.OrdinalIgnoreCase)) continue;
                                foreach (dynamic action in task.Definition.Actions)
                                {
                                    int type;
                                    try { type = (int)action.Type; } catch { continue; }
                                    if (type != 0) continue;
                                    string exec = (action.Path as string) ?? "";
                                    if (exec.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(exec))
                                        loops.Add(new LoopFinding
                                        {
                                            Type = "ScheduledReinstall", Name = name, Path = exec,
                                            Description = "Scheduled task may reinstall software",
                                        });
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        // Services with restart-on-failure (sc qfailure shows RESTART).
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"\\.\ROOT\CIMV2"),
                new ObjectQuery("SELECT Name,State,StartMode,PathName FROM Win32_Service WHERE StartMode='Auto' AND State='Running'"));
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    string name = mo["Name"]?.ToString() ?? "";
                    try
                    {
                        var psi = new System.Diagnostics.ProcessStartInfo("sc.exe", $"qfailure \"{name}\"")
                        {
                            CreateNoWindow = true, UseShellExecute = false,
                            RedirectStandardOutput = true,
                        };
                        using var p = System.Diagnostics.Process.Start(psi);
                        string output = p?.StandardOutput.ReadToEnd() ?? "";
                        p?.WaitForExit(10000);
                        if (output.Contains("RESTART", StringComparison.OrdinalIgnoreCase))
                            loops.Add(new LoopFinding
                            {
                                Type = "ServiceRestartLoop", Name = name,
                                Path = mo["PathName"]?.ToString() ?? "",
                                Description = "Service auto-restarts on failure (potential loop)",
                            });
                    }
                    catch { }
                }
            }
        }
        catch { }

        return loops;
    }

    public static List<LoopFinding> FindNetworkLoops()
    {
        var loops = new List<LoopFinding>();

        // Hosts file: any non-comment, non-localhost entry is suspicious.
        // (Gregg's case: hosts null-routed vortex.data.microsoft.com.)
        try
        {
            string hostsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "drivers", "etc", "hosts");
            if (File.Exists(hostsPath))
            {
                var suspicious = File.ReadLines(hostsPath, Encoding.UTF8)
                    .Where(l => !Regex.IsMatch(l, @"^\s*#") && l.Trim().Length > 0
                        && !l.Contains("localhost", StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (suspicious.Count > 0)
                    loops.Add(new LoopFinding
                    {
                        Type = "HostsFile", Name = "hosts",
                        Path = hostsPath,
                        Description = $"Non-standard hosts entries (may block or redirect traffic): {string.Join("; ", suspicious.Take(5))}",
                    });
            }
        }
        catch { }

        // Persistent static routes with a real next hop.
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("route.exe", "print -4")
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true,
            };
            using var p = System.Diagnostics.Process.Start(psi);
            string output = p?.StandardOutput.ReadToEnd() ?? "";
            p?.WaitForExit(10000);
            // Persistent routes section.
            var m = Regex.Match(output, @"Persistent Routes:([\s\S]*?)(?=\r?\n\r?\n|\z)");
            if (m.Success)
            {
                var entries = m.Groups[1].Value.Split('\n')
                    .Select(l => l.Trim())
                    .Where(l => Regex.IsMatch(l, @"^\d+\.\d+\.\d+\.\d+"))
                    .ToList();
                if (entries.Count > 0)
                    loops.Add(new LoopFinding
                    {
                        Type = "PersistentRoutes", Name = "static-routes", Path = "",
                        Description = $"{entries.Count} persistent static routes: {string.Join("; ", entries.Take(5))}",
                    });
            }
        }
        catch { }

        return loops;
    }

    /// <summary>Card action "Invoke-FalsumLoopBreaker". Audit only; breaking is explicit.</summary>
    public static List<ModuleResult> Invoke()
    {
        var results = new List<ModuleResult>();
        var software = FindSoftwareLoops();
        var network = FindNetworkLoops();

        if (software.Count == 0)
            results.Add(ModuleResult.Pass("LoopBreaker", "No software loops found."));
        else
            results.Add(ModuleResult.Fail("LoopBreaker",
                $"{software.Count} potential software loops: " +
                string.Join("; ", software.Take(5).Select(l => $"{l.Type}: {l.Name}")),
                software));

        if (network.Count == 0)
            results.Add(ModuleResult.Pass("LoopBreaker", "No network loops found."));
        else
            results.Add(ModuleResult.Fail("LoopBreaker",
                $"{network.Count} potential network loops: " +
                string.Join("; ", network.Take(5).Select(l => $"{l.Type}: {l.Description}")),
                network));

        // Vault.
        try
        {
            string vf = Path.Combine(Vault.VaultDir("loop-breaker"),
                Vault.Timestamped("loops", "jsonl"));
            foreach (var l in software.Concat(network))
                Vault.AppendJsonl(vf, new Dictionary<string, object?>
                {
                    ["ts"] = Vault.IsoNow(), ["type"] = l.Type,
                    ["name"] = l.Name, ["path"] = l.Path,
                    ["description"] = l.Description,
                });
        }
        catch { }

        return results;
    }
}
