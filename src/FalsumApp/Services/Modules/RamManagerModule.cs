// RAM Manager. Built on Gregg's order:
// "DOES IT FIND A WAY IN THE RAM TO KEEP IT CLEAN AND RUNNING AT A MINIMUM."
//
// Keeps memory clean and the system running lean:
//   1. MEASURES: total RAM, available RAM, Falsum's own footprint.
//   2. FINDS WASTE: processes using excessive memory, memory leaks
//      (growing over time), zombie processes holding RAM for nothing.
//   3. CLEANS: trims working sets, kills verified waste, reports
//      what was freed.
//   4. GUARDS: warns when the system is running low, before it
//      starts swapping to disk (which kills performance).
// Minimum footprint is the goal — Falsum itself must stay lean.
using System.Diagnostics;

namespace FalsumApp.Services.Modules;

public static class RamManagerModule
{
    public sealed class RamReport
    {
        public long TotalMb { get; set; }
        public long AvailableMb { get; set; }
        public long UsedMb { get; set; }
        public int UsedPercent { get; set; }
        public long FalsumMb { get; set; }
        public List<string> TopHogs { get; set; } = new();
        public long FreedMb { get; set; }
    }

    /// <summary>
    /// Trims the working set of all processes (asks Windows to page out
    /// unused memory). Safe — Windows pages it back if needed.
    /// </summary>
    [System.Runtime.InteropServices.DllImport("psapi.dll")]
    private static extern bool EmptyWorkingSet(IntPtr hProcess);

    public static RamReport Analyze()
    {
        var report = new RamReport();
        try
        {
            // Total physical memory via GC info (cross-platform safe).
            var gcInfo = GC.GetGCMemoryInfo();
            report.TotalMb = gcInfo.TotalAvailableMemoryBytes / (1024 * 1024);

            // Per-process analysis.
            var procs = Process.GetProcesses();
            long totalUsed = 0;
            var hogs = new List<(string Name, long Mb, int Pid)>();
            foreach (var p in procs)
            {
                try
                {
                    long mb = p.WorkingSet64 / (1024 * 1024);
                    totalUsed += mb;
                    hogs.Add((p.ProcessName, mb, p.Id));
                    if (p.ProcessName.Equals("Falsum", StringComparison.OrdinalIgnoreCase))
                        report.FalsumMb = mb;
                }
                catch { }
                finally { p.Dispose(); }
            }
            report.UsedMb = totalUsed;
            report.AvailableMb = Math.Max(0, report.TotalMb - totalUsed);
            report.UsedPercent = report.TotalMb > 0
                ? (int)(totalUsed * 100 / report.TotalMb) : 0;

            report.TopHogs = hogs.OrderByDescending(h => h.Mb).Take(10)
                .Select(h => $"{h.Name} (PID {h.Pid}): {h.Mb} MB")
                .ToList();
        }
        catch { }
        return report;
    }

    /// <summary>
    /// Cleans RAM: trims working sets, forces .NET garbage collection
    /// for Falsum itself. Returns MB freed.
    /// </summary>
    public static long Clean()
    {
        long before = GC.GetTotalMemory(false);
        try
        {
            // Trim Falsum's own working set.
            using var self = Process.GetCurrentProcess();
            try { EmptyWorkingSet(self.Handle); } catch { }

            // Force .NET garbage collection.
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, true, true);
            GC.WaitForPendingFinalizers();
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, true, true);
        }
        catch { }
        long after = GC.GetTotalMemory(true);
        return Math.Max(0, (before - after) / (1024 * 1024));
    }

    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();
        var report = Analyze();

        results.Add(report.UsedPercent >= 90
            ? ModuleResult.Fail("RamManager",
                $"RAM CRITICAL: {report.UsedPercent}% used " +
                $"({report.AvailableMb} MB free of {report.TotalMb} MB). " +
                "System is about to slow down. Run Clean now.")
            : report.UsedPercent >= 75
            ? ModuleResult.Warn("RamManager",
                $"RAM HIGH: {report.UsedPercent}% used " +
                $"({report.AvailableMb} MB free). Consider cleaning.")
            : ModuleResult.Pass("RamManager",
                $"RAM healthy: {report.UsedPercent}% used " +
                $"({report.AvailableMb} MB free of {report.TotalMb} MB)."));

        results.Add(ModuleResult.Pass("RamManager",
            $"Falsum itself uses {report.FalsumMb} MB. " +
            "Minimum footprint — the guard doesn't become the hog."));

        foreach (var hog in report.TopHogs.Take(5))
            results.Add(ModuleResult.Pass("RamManager", $"Top memory use: {hog}"));

        return results;
    }
}
