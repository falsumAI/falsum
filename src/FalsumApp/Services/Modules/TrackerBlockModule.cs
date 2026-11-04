// Module 22: Tracker Block. Faithful C# port of Test-TrackerBlockHealth.
// Reads Falsum-managed blocks from the hosts file (between the FALSUM-BLOCK
// markers) and verifies EVERY managed domain currently resolves to 0.0.0.0.
// A domain that resolves elsewhere means the block is leaking.
using System.Net;
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public static class TrackerBlockModule
{
    private const string BlockStart = "# FALSUM-BLOCK-START";
    private const string BlockEnd = "# FALSUM-BLOCK-END";

    private static string HostsPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"drivers\etc\hosts");

    private static List<string> GetTrackerBlocks()
    {
        var domains = new List<string>();
        try
        {
            bool inBlock = false;
            foreach (var line in File.ReadLines(HostsPath))
            {
                if (line.Trim() == BlockStart) { inBlock = true; continue; }
                if (line.Trim() == BlockEnd) { inBlock = false; continue; }
                if (inBlock)
                {
                    var m = Regex.Match(line, @"^\s*0\.0\.0\.0\s+(\S+)");
                    if (m.Success) domains.Add(m.Groups[1].Value);
                }
            }
        }
        catch { /* unreadable hosts = no blocks we can verify */ }
        return domains;
    }

    public static List<ModuleResult> Health()
    {
        var results = new List<ModuleResult>();
        var current = GetTrackerBlocks();
        if (current.Count == 0)
        {
            results.Add(ModuleResult.Pass("TrackerBlock",
                "Health: no Falsum-managed blocks to check."));
            return results;
        }
        var leaking = new List<string>();
        foreach (var d in current)
        {
            bool ok = false;
            try
            {
                var addrs = Dns.GetHostAddresses(d);
                ok = addrs.Any(a => a.ToString() == "0.0.0.0");
            }
            catch { ok = false; }
            if (!ok) leaking.Add(d);
        }
        if (leaking.Count == 0)
            results.Add(ModuleResult.Pass("TrackerBlock",
                $"HEALTH: all {current.Count} blocks resolve to 0.0.0.0.",
                new { total = current.Count }));
        else
            results.Add(ModuleResult.Fail("TrackerBlock",
                $"HEALTH: {leaking.Count} of {current.Count} blocks NOT resolving to 0.0.0.0: " +
                string.Join(", ", leaking.Take(10)),
                leaking));
        return results;
    }
}
