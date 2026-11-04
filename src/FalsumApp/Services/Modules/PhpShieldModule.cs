// Module 07: PHP Shield. Faithful C# port of the PHP install discovery.
// Finds every PHP on the box: PATH, common stack paths (XAMPP/WAMP/Laragon),
// and the registry (HKLM\SOFTWARE\PHP IniFilePath). Each hit is versioned by
// running php.exe -v with evidence preserved.
using System.Diagnostics;
using Microsoft.Win32;

namespace FalsumApp.Services.Modules;

public static class PhpShieldModule
{
    public sealed class PhpInstall
    {
        public string Exe = "";
        public string Source = "";
        public bool IsActive;
        public string Version = "";
    }

    private static readonly string[] CommonPaths = new[]
    {
        @"C:\php\php.exe",
        @"C:\xampp\php\php.exe",
        @"C:\wamp64\bin\php\php.exe",
        @"C:\wamp\bin\php\php.exe",
        @"C:\laragon\bin\php\php.exe",
    };

    private static string? VersionOf(string exe)
    {
        try
        {
            var psi = new ProcessStartInfo(exe, "-v")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return null;
            string out_ = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            var m = System.Text.RegularExpressions.Regex.Match(out_,
                @"PHP\s+([0-9]+\.[0-9]+\.[0-9]+)");
            return m.Success ? m.Groups[1].Value : null;
        }
        catch { return null; }
    }

    public static List<PhpInstall> Discover()
    {
        var found = new Dictionary<string, PhpInstall>(StringComparer.OrdinalIgnoreCase);

        // 1. PATH
        try
        {
            string? path = Environment.GetEnvironmentVariable("PATH");
            foreach (var dir in (path ?? "").Split(';'))
            {
                string cand = Path.Combine(dir.Trim(), "php.exe");
                if (File.Exists(cand) && !found.ContainsKey(cand))
                    found[cand] = new PhpInstall { Exe = cand, Source = "PATH", IsActive = true };
            }
        }
        catch { }

        // 2. Common stack paths.
        foreach (var cand in CommonPaths)
            if (File.Exists(cand) && !found.ContainsKey(cand))
                found[cand] = new PhpInstall { Exe = cand, Source = "common-path" };
        // WAMP/Laragon versioned subdirs.
        foreach (var root in new[] {
            @"C:\wamp64\bin\php", @"C:\wamp\bin\php", @"C:\laragon\bin\php" })
        {
            try
            {
                if (!Directory.Exists(root)) continue;
                foreach (var cand in Directory.GetFiles(root, "php.exe",
                    SearchOption.AllDirectories).Take(10))
                    if (!found.ContainsKey(cand))
                        found[cand] = new PhpInstall { Exe = cand, Source = "stack-dir" };
            }
            catch { }
        }

        // 3. Registry: HKLM\SOFTWARE\PHP (+WOW6432Node) IniFilePath.
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view)
                    .OpenSubKey(@"SOFTWARE\PHP");
                var ini = k?.GetValue("IniFilePath")?.ToString();
                if (!string.IsNullOrEmpty(ini))
                {
                    string dir = Path.GetDirectoryName(ini) ?? "";
                    string cand = Path.Combine(dir, "php.exe");
                    if (File.Exists(cand) && !found.ContainsKey(cand))
                        found[cand] = new PhpInstall { Exe = cand, Source = "registry" };
                }
            }
            catch { }
        }

        var list = found.Values.ToList();
        foreach (var inst in list)
            inst.Version = VersionOf(inst.Exe) ?? "unknown";
        return list;
    }

    /// <summary>Card action "Test-PhpInstalls".</summary>
    public static List<ModuleResult> Scan()
    {
        var results = new List<ModuleResult>();
        var installs = Discover();
        if (installs.Count == 0)
        {
            results.Add(ModuleResult.Pass("PhpShield", "No PHP installs found on this machine."));
            return results;
        }
        foreach (var i in installs)
            results.Add(ModuleResult.Pass("PhpShield",
                $"PHP {i.Version} at {i.Exe} (source: {i.Source}{(i.IsActive ? ", active on PATH" : "")}).",
                new { exe = i.Exe, version = i.Version, source = i.Source }));
        return results;
    }
}
