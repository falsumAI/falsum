// Module 31: Gate. Faithful C# port of Falsum-Gate.ps1.
// Audits ALL automation sectors in one pass: Task Scheduler, Services,
// Registry Run keys, WMI event consumers, Startup folders. The gate sees
// everything that can launch code without the user clicking.
using System.Management;
using Microsoft.Win32;

namespace FalsumApp.Services.Modules;

public static class GateModule
{
    public sealed class SectorReport
    {
        public string Sector = "";
        public int Count;
        public List<string> Items { get; } = new();
    }

    private static SectorReport TaskSchedulerSector()
    {
        var r = new SectorReport { Sector = "TaskScheduler" };
        try
        {
            var t = Type.GetTypeFromProgID("Schedule.Service");
            if (t == null) return r;
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
                            r.Count++;
                            if (r.Items.Count < 20)
                                r.Items.Add($"{task.Path} [{task.State}]");
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        catch { }
        return r;
    }

    private static SectorReport ServicesSector()
    {
        var r = new SectorReport { Sector = "Services" };
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"\\.\ROOT\CIMV2"),
                new ObjectQuery("SELECT Name FROM Win32_Service WHERE StartMode='Auto'"));
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    r.Count++;
                    if (r.Items.Count < 20) r.Items.Add(mo["Name"]?.ToString() ?? "");
                }
            }
        }
        catch { }
        return r;
    }

    private static SectorReport RegistrySector()
    {
        var r = new SectorReport { Sector = "RegistryRunKeys" };
        var keys = new (RegistryKey root, string subkey)[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        };
        foreach (var (root, subkey) in keys)
        {
            try
            {
                using var key = root.OpenSubKey(subkey);
                if (key == null) continue;
                foreach (var name in key.GetValueNames())
                {
                    r.Count++;
                    if (r.Items.Count < 20) r.Items.Add($"{subkey}\\{name}");
                }
            }
            catch { }
        }
        return r;
    }

    private static SectorReport WmiSector()
    {
        var r = new SectorReport { Sector = "WmiEventConsumers" };
        try
        {
            var scope = new ManagementScope(@"\\.\ROOT\subscription");
            using var fs = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Name FROM __EventFilter"));
            foreach (ManagementObject mo in fs.Get())
            {
                using (mo) { r.Count++; if (r.Items.Count < 20) r.Items.Add("Filter: " + mo["Name"]?.ToString()); }
            }
            using var cs = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT __RELPATH FROM CommandLineEventConsumer"));
            foreach (ManagementObject mo in cs.Get())
            {
                using (mo) { r.Count++; if (r.Items.Count < 20) r.Items.Add("Consumer: " + mo["__RELPATH"]?.ToString()); }
            }
        }
        catch { /* namespace missing: zero */ }
        return r;
    }

    private static SectorReport StartupFolderSector()
    {
        var r = new SectorReport { Sector = "StartupFolder" };
        foreach (var dir in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        })
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var f in Directory.GetFiles(dir))
                {
                    r.Count++;
                    if (r.Items.Count < 20) r.Items.Add(f);
                }
            }
            catch { }
        }
        return r;
    }

    /// <summary>Card action "Invoke-GateAudit".</summary>
    public static List<ModuleResult> Audit()
    {
        var sectors = new[]
        {
            TaskSchedulerSector(), ServicesSector(), RegistrySector(),
            WmiSector(), StartupFolderSector(),
        };
        var results = new List<ModuleResult>();
        foreach (var s in sectors)
        {
            bool alert = (s.Sector == "WmiEventConsumers" && s.Count > 0);
            string msg = $"{s.Sector}: {s.Count} entries" +
                (s.Items.Count > 0 ? ". Sample: " + string.Join("; ", s.Items.Take(3)) : ".");
            results.Add(alert
                ? ModuleResult.Fail("Gate", msg + " (WMI event consumers are fileless persistence — inspect.)", s)
                : ModuleResult.Pass("Gate", msg, new { sector = s.Sector, count = s.Count }));
        }
        return results;
    }
}
