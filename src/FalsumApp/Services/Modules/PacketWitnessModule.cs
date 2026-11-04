// Module 02: Packet Witness. Faithful C# port of the Start-Capture pre-flight.
// pktmon (Windows 10 19041+) is the capture engine. The card action runs the
// pre-flight: pktmon must exist, no capture may already be running. A live
// capture needs admin + an output dir and is started from the capture UI;
// this gate keeps a card click from silently doing nothing.
using System.Diagnostics;

namespace FalsumApp.Services.Modules;

public static class PacketWitnessModule
{
    private static string? PktmonVersion()
    {
        try
        {
            var psi = new ProcessStartInfo("pktmon", "version")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return null;
            string out_ = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10000);
            if (p.ExitCode != 0) return null;
            var m = System.Text.RegularExpressions.Regex.Match(out_,
                @"version[:\s]+([0-9.]+)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : out_.Trim().Split('\n')[0].Trim();
        }
        catch { return null; }
    }

    private static bool CaptureActive()
    {
        try
        {
            var psi = new ProcessStartInfo("pktmon", "list")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return false;
            string out_ = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10000);
            return out_.Contains("Active", StringComparison.OrdinalIgnoreCase) &&
                   !out_.Contains("No active", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    /// <summary>
    /// Card action "Start-Capture": pre-flight gate. Reports whether the
    /// machine can capture and where a capture would be written.
    /// </summary>
    public static List<ModuleResult> PreFlight(string? outDir = null)
    {
        var results = new List<ModuleResult>();
        string? ver = PktmonVersion();
        if (ver == null)
        {
            results.Add(ModuleResult.Fail("PacketWitness",
                "pktmon not found on this build. Packet witness needs Windows 10 build 19041+ or Windows 11."));
            return results;
        }
        if (CaptureActive())
        {
            results.Add(ModuleResult.Warn("PacketWitness",
                $"pktmon {ver}: a capture is already running. Stop it first (pktmon stop from an elevated shell).",
                new { pktmon = ver }));
            return results;
        }
        string dir = outDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "vault", "packet-witness");
        try { Directory.CreateDirectory(dir); } catch { }
        results.Add(ModuleResult.Pass("PacketWitness",
            $"pktmon {ver}: ready. Captures are written to {dir} (run as admin to start one).",
            new { pktmon = ver, outDir = dir }));
        return results;
    }
}
