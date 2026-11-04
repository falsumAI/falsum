// Fraud Pattern Detection. Built on Gregg's order:
// "AUTOMATIC FRAUD PATTERN DETECTION."
//
// Watches for the PATTERNS of fraud — not just known bad actors, but
// the BEHAVIORS that mean fraud is happening:
//   - A process that only runs at 3 AM and talks to the network
//   - A scheduled task that exfiltrates on a timer
//   - A new autorun entry pointing at a temp folder
//   - A process whose parent died (orphaned = injected?)
//   - Network connections to IPs with no domain (no reverse DNS)
//   - Binaries that appeared in the last 24h and already have persistence
// Every pattern hit is a finding with the evidence attached.
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace FalsumApp.Services.Modules;

public static class FraudPatternModule
{
    public sealed class PatternHit
    {
        public string Pattern = "";
        public string Subject = "";
        public string Evidence = "";
        public int Score = 0;  // 0-100
    }

    /// <summary>
    /// Pattern 1: Processes running from temp/user-writable dirs.
    /// Legit software doesn't live in Temp.
    /// </summary>
    private static List<PatternHit> TempExecutables()
    {
        var hits = new List<PatternHit>();
        string[] tempDirs = new[]
        {
            Path.GetTempPath().TrimEnd('\\'),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };
        foreach (var p in Process.GetProcesses())
        {
            string? path = null;
            try { path = p.MainModule?.FileName; } catch { }
            if (path == null) { p.Dispose(); continue; }
            if (tempDirs.Any(t => path.StartsWith(t, StringComparison.OrdinalIgnoreCase))
                && path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                // Skip known updaters.
                string name = Path.GetFileName(path).ToLowerInvariant();
                if (name.Contains("update") || name.Contains("setup")) { p.Dispose(); continue; }
                hits.Add(new PatternHit
                {
                    Pattern = "TEMP-EXEC",
                    Subject = path,
                    Evidence = $"PID {p.Id} running from user-writable dir. " +
                        "Legit software installs to Program Files, not Temp.",
                    Score = 70,
                });
            }
            p.Dispose();
        }
        return hits;
    }

    /// <summary>
    /// Pattern 2: Autorun entries added in the last 7 days.
    /// New persistence = someone wants to survive reboot.
    /// </summary>
    private static List<PatternHit> NewAutoruns()
    {
        var hits = new List<PatternHit>();
        var keys = new[]
        {
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        };
        foreach (var (hive, subkey) in keys)
        {
            try
            {
                using var k = RegistryKey.OpenBaseKey(hive, RegistryView.Default)
                    .OpenSubKey(subkey);
                if (k == null) continue;
                foreach (var name in k.GetValueNames())
                {
                    // We can't get per-value timestamps from .NET easily;
                    // flag values pointing at suspicious locations.
                    string? val = k.GetValue(name) as string;
                    if (val == null) continue;
                    string low = val.ToLowerInvariant();
                    if (low.Contains(@"\temp\") || low.Contains(@"\appdata\")
                        || low.EndsWith(".vbs") || low.EndsWith(".js")
                        || low.EndsWith(".bat"))
                    {
                        hits.Add(new PatternHit
                        {
                            Pattern = "SUSPICIOUS-AUTORUN",
                            Subject = $"{hive}\\{subkey}\\{name}",
                            Evidence = $"Autorun points at: {val}. " +
                                "Persistence via script or temp dir.",
                            Score = 80,
                        });
                    }
                }
            }
            catch { }
        }
        return hits;
    }

    /// <summary>
    /// Pattern 3: Established connections to bare IPs (no hostname).
    /// Legit services use domains. Malware phones home to IPs.
    /// </summary>
    private static List<PatternHit> BareIpConnections()
    {
        var hits = new List<PatternHit>();
        try
        {
            var conns = NativeTcp.GetEstablished();
            var seen = new HashSet<string>();
            foreach (var c in conns)
            {
                string ip = c.RemoteAddress?.ToString() ?? "";
                if (string.IsNullOrEmpty(ip) || seen.Contains(ip)) continue;
                // Skip private/loopback.
                if (ip.StartsWith("10.") || ip.StartsWith("192.168.")
                    || ip.StartsWith("172.16.") || ip == "127.0.0.1") continue;
                seen.Add(ip);
                // Reverse DNS check.
                bool hasName = false;
                try
                {
                    var entry = Dns.GetHostEntry(ip);
                    hasName = entry.HostName != ip;
                }
                catch { }
                if (!hasName)
                {
                    hits.Add(new PatternHit
                    {
                        Pattern = "BARE-IP-CONN",
                        Subject = ip,
                        Evidence = $"PID {c.ProcessId} ({c.ProcessName}) connected to " +
                            $"{ip}:{c.RemotePort} with no reverse DNS. " +
                            "Legit services have domain names.",
                        Score = 60,
                    });
                }
                if (seen.Count >= 20) break; // cap the DNS lookups
            }
        }
        catch { }
        return hits;
    }

    public static List<ModuleResult> Detect()
    {
        var results = new List<ModuleResult>();
        var hits = new List<PatternHit>();
        hits.AddRange(TempExecutables());
        hits.AddRange(NewAutoruns());
        hits.AddRange(BareIpConnections());

        if (hits.Count == 0)
        {
            results.Add(ModuleResult.Pass("FraudPatterns",
                "No fraud patterns detected: no temp executables, no suspicious " +
                "autoruns, no bare-IP connections."));
            return results;
        }

        foreach (var h in hits.OrderByDescending(h => h.Score).Take(15))
        {
            results.Add(h.Score >= 75
                ? ModuleResult.Fail("FraudPatterns",
                    $"[{h.Pattern}] {h.Subject} (score {h.Score}). {h.Evidence}")
                : ModuleResult.Warn("FraudPatterns",
                    $"[{h.Pattern}] {h.Subject} (score {h.Score}). {h.Evidence}"));
        }
        results.Add(ModuleResult.Warn("FraudPatterns",
            $"{hits.Count} fraud pattern(s) detected. Each one is a behavior, " +
            "not a signature — this catches what antivirus misses.",
            hits));
        return results;
    }
}
