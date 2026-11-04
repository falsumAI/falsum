// Module 11: Active Defense. Faithful C# port of the backtrace target gate.
// Backtrace is passive evidence gathering (no exploits, no auth attempts).
// It REFUSES: unparsable targets, loopback, and non-routable addresses.
// The card action proves the gate parses and refuses correctly.
using System.Net;
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public static class ActiveDefenseModule
{
    public sealed class IpTarget
    {
        public bool Ok;
        public string Ip = "";
        public int Port;
    }

    /// <summary>
    /// Normalize FIRST, validate second: accepts "ip", "ip:port", "[ip]:port".
    /// </summary>
    public static IpTarget ParseTarget(string target)
    {
        var t = new IpTarget();
        string s = target.Trim();
        var m = Regex.Match(s, @"^\[(.+)\]:(\d+)$");
        if (m.Success) { s = m.Groups[1].Value; t.Port = int.Parse(m.Groups[2].Value); }
        else
        {
            int colon = s.LastIndexOf(':');
            if (colon > 0 && s.IndexOf(':') == colon && int.TryParse(s[(colon + 1)..], out int p))
            { s = s[..colon]; t.Port = p; }
        }
        if (IPAddress.TryParse(s, out var addr))
        {
            t.Ip = addr.ToString();
            t.Ok = true;
        }
        return t;
    }

    /// <summary>Refuses loopback, multicast, and unparsable addresses.</summary>
    public static bool IsRoutableRemote(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return false;
        if (IPAddress.IsLoopback(addr)) return false;
        byte[] b = addr.GetAddressBytes();
        if (b.Length != 4) return true; // IPv6: loopback already excluded
        // Private / link-local / multicast / reserved are not remote targets.
        if (b[0] == 10) return false;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
        if (b[0] == 192 && b[1] == 168) return false;
        if (b[0] == 169 && b[1] == 254) return false;
        if (b[0] >= 224) return false;
        if (b[0] == 127) return false;
        return true;
    }

    /// <summary>
    /// Card action "Start-Backtrace": proves the target gate. A backtrace
    /// needs an explicit IP; the gate is what keeps it honest.
    /// </summary>
    public static List<ModuleResult> GateCheck()
    {
        var results = new List<ModuleResult>();
        int passed = 0, failed = 0;
        var failures = new List<string>();
        void Check(string name, Func<bool> test)
        {
            bool ok;
            try { ok = test(); } catch { ok = false; }
            if (ok) passed++; else { failed++; failures.Add(name); }
        }

        Check("plain ip parses", () =>
        { var t = ParseTarget("203.0.113.7"); return t.Ok && t.Ip == "203.0.113.7"; });
        Check("ip:port parses", () =>
        { var t = ParseTarget("203.0.113.7:443"); return t.Ok && t.Port == 443; });
        Check("[ip]:port parses", () =>
        { var t = ParseTarget("[203.0.113.7]:8080"); return t.Ok && t.Port == 8080; });
        Check("junk refused", () => !ParseTarget("not-an-ip").Ok);
        Check("loopback refused", () => !IsRoutableRemote("127.0.0.1"));
        Check("private refused", () => !IsRoutableRemote("192.168.1.1"));
        Check("public routable accepted", () => IsRoutableRemote("203.0.113.7"));

        string msg = $"ActiveDefense gate: {passed}/{passed + failed} passed. " +
                     "Backtrace is passive evidence gathering only — no exploits, no auth attempts — " +
                     "and refuses unparsable or non-routable targets.";
        if (failed > 0) msg += " Failed: " + string.Join("; ", failures);
        results.Add(failed == 0
            ? ModuleResult.Pass("ActiveDefense", msg)
            : ModuleResult.Fail("ActiveDefense", msg, failures));
        return results;
    }
}
