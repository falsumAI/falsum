// Module 04: OSINT Attribution. Faithful C# port of Test-OsintInput.
// Classifies and validates a target before any query runs: IP, domain, or
// invalid. Stops the classic crt.sh-on-an-IP waste and junk-string lookups.
// Internationalized domains are converted to punycode (IDNA) so DNS, RDAP
// and crt.sh queries run against the ASCII form the wire uses.
using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public static class OsintAttributionModule
{
    public sealed class TargetCheck
    {
        public bool Valid;
        public string Kind = "unknown"; // "ip" | "domain" | "unknown"
        public string Value = "";
        public string Note = "";
    }

    public static TargetCheck CheckInput(string target)
    {
        string t = target.Trim().TrimEnd('.');
        if (IPAddress.TryParse(t, out _))
            return new TargetCheck { Valid = true, Kind = "ip", Value = t };
        if (IsDomain(t))
            return new TargetCheck { Valid = true, Kind = "domain", Value = t.ToLowerInvariant() };
        if (Regex.IsMatch(t, @"[^\x00-\x7F]"))
        {
            try
            {
                string ascii = new IdnMapping().GetAscii(t);
                if (IsDomain(ascii))
                    return new TargetCheck
                    {
                        Valid = true, Kind = "domain",
                        Value = ascii.ToLowerInvariant(), Note = "idn:" + t,
                    };
            }
            catch { }
        }
        return new TargetCheck
        {
            Valid = false, Kind = "unknown", Value = t,
            Note = "not a valid IP address or domain name",
        };
    }

    private static bool IsDomain(string t)
        => Regex.IsMatch(t,
                @"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
                RegexOptions.IgnoreCase)
            || Regex.IsMatch(t, @"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$",
                RegexOptions.IgnoreCase);

    /// <summary>
    /// Card action "Test-OsintInput": validates the classifier itself on
    /// known-good and known-bad inputs (offline self-test).
    /// </summary>
    public static List<ModuleResult> Hygiene()
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

        Check("ipv4 classified", () =>
        { var c = CheckInput("8.8.8.8"); return c.Valid && c.Kind == "ip"; });
        Check("domain classified", () =>
        { var c = CheckInput("example.com"); return c.Valid && c.Kind == "domain"; });
        Check("trailing dot accepted", () =>
        { var c = CheckInput("example.com."); return c.Valid && c.Kind == "domain"; });
        Check("single label accepted", () =>
        { var c = CheckInput("localhost"); return c.Valid; });
        Check("junk rejected", () =>
        { var c = CheckInput("not a target!!!"); return !c.Valid; });
        Check("empty rejected", () =>
        { var c = CheckInput(""); return !c.Valid; });

        string msg = $"OsintAttribution hygiene: {passed}/{passed + failed} passed.";
        if (failed > 0) msg += " Failed: " + string.Join("; ", failures);
        results.Add(failed == 0
            ? ModuleResult.Pass("OsintAttribution", msg)
            : ModuleResult.Fail("OsintAttribution", msg, failures));
        return results;
    }
}
