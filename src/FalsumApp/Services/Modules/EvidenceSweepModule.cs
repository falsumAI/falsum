// Module 01: Evidence Sweep. Faithful C# port of Test-SweepHygiene.
// Offline self-test battery for the evidence-sweep plumbing:
// UTC stamp shape, hotfix-date null guards, Chrome profile-dir validation,
// by-design file exemptions, verify-verdict mapping.
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public static class EvidenceSweepModule
{
    /// <summary>One source of truth for evidence timestamps: UTC with trailing Z.</summary>
    public static string UtcStamp()
        => DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + "Z";

    /// <summary>Hotfix InstalledOn is null on some rows — "unknown" keeps the row alive.</summary>
    public static string HotfixDate(DateTime? installedOn)
        => installedOn.HasValue ? installedOn.Value.ToString("yyyy-MM-dd") : "unknown";

    /// <summary>
    /// Valid Chromium profile directory names. Everything else under
    /// "User Data" (Crash Reports, ShaderCache, ...) is skipped.
    /// </summary>
    public static bool IsChromeProfileDir(string name)
    {
        if (name == "Default") return true;
        if (name == "Guest Profile") return true;
        return Regex.IsMatch(name, @"^Profile \d+$");
    }

    /// <summary>
    /// Files the design itself puts in a sweep dir that must NOT be flagged
    /// [EXTRA] on a later verify.
    /// </summary>
    public static bool IsExpectedByDesign(string fileName)
    {
        if (string.Equals(fileName, "MANIFEST.csv", StringComparison.OrdinalIgnoreCase)) return true;
        if (string.Equals(fileName, "MANIFEST-HASH.txt", StringComparison.OrdinalIgnoreCase)) return true;
        return fileName.Length >= 17 &&
               fileName.StartsWith("VERIFY-REPORT-", StringComparison.OrdinalIgnoreCase) &&
               fileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase);
    }

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

        Check("stamp-format-utc-z", () =>
            Regex.IsMatch(UtcStamp(), @"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z$"));
        Check("hotfix-date-present", () =>
            HotfixDate(new DateTime(2026, 10, 14)) == "2026-10-14");
        Check("hotfix-date-null", () => HotfixDate(null) == "unknown");
        Check("profile-default", () => IsChromeProfileDir("Default"));
        Check("profile-guest", () => IsChromeProfileDir("Guest Profile"));
        Check("profile-numbered", () => IsChromeProfileDir("Profile 3"));
        Check("profile-bad-number", () => !IsChromeProfileDir("Profile X"));
        Check("profile-crash-reports", () => !IsChromeProfileDir("Crash Reports"));
        Check("profile-trailing-space", () => !IsChromeProfileDir("Default "));
        Check("profile-empty", () => !IsChromeProfileDir(""));
        Check("bydesign-manifest", () => IsExpectedByDesign("MANIFEST.csv"));
        Check("bydesign-hash-receipt", () => IsExpectedByDesign("MANIFEST-HASH.txt"));
        Check("bydesign-verify-report", () => IsExpectedByDesign("VERIFY-REPORT-20261030_093900.txt"));
        Check("bydesign-step-file", () => !IsExpectedByDesign("01-systeminfo.txt"));
        Check("bydesign-case-insensitive", () => IsExpectedByDesign("manifest.csv"));
        Check("bydesign-report-wildcard-ci", () => IsExpectedByDesign("verify-report-x.txt"));

        string msg = $"EvidenceSweep hygiene: {passed}/{passed + failed} passed.";
        if (failed > 0) msg += " Failed: " + string.Join("; ", failures);
        results.Add(failed == 0
            ? ModuleResult.Pass("EvidenceSweep", msg)
            : ModuleResult.Fail("EvidenceSweep", msg, failures));
        return results;
    }
}
