// Module 33: Command Center. The .ps1's Test-CommandCenterHygiene was a stub
// that always returned Passed=true. This port is honest: it verifies the
// command center can actually reach the system tools it drives.
using System.Diagnostics;

namespace FalsumApp.Services.Modules;

public static class CommandCenterModule
{
    private static readonly string[] RequiredTools =
    {
        "cmd.exe", "sc.exe", "netstat.exe", "tasklist.exe",
        "auditpol.exe", "route.exe", "ipconfig.exe",
    };

    /// <summary>Card action "Test-CommandCenterHygiene".</summary>
    public static List<ModuleResult> Hygiene()
    {
        var results = new List<ModuleResult>();
        var missing = new List<string>();
        string sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
        foreach (var tool in RequiredTools)
            if (!File.Exists(Path.Combine(sysDir, tool))) missing.Add(tool);

        // Can we actually launch one?
        bool canLaunch = false;
        string launchError = "";
        try
        {
            var psi = new ProcessStartInfo(Path.Combine(sysDir, "cmd.exe"), "/c echo ok")
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true,
            };
            using var p = Process.Start(psi);
            string output = p?.StandardOutput.ReadToEnd() ?? "";
            p?.WaitForExit(10000);
            canLaunch = output.Contains("ok");
        }
        catch (Exception ex) { launchError = ex.Message; }

        if (missing.Count == 0 && canLaunch)
            results.Add(ModuleResult.Pass("CommandCenter",
                $"Command center operational: {RequiredTools.Length} system tools present, process launch works."));
        else
            results.Add(ModuleResult.Fail("CommandCenter",
                $"Missing tools: {string.Join(", ", missing)}. Launch test: {(canLaunch ? "ok" : "FAILED " + launchError)}"));
        return results;
    }
}
