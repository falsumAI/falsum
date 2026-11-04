// Module 05: People Track. Faithful C# port of Test-Username's input gate.
// A username scan must never be told to do something silly: the handle must
// be letters, digits, . _ - only, max 64 chars; concurrency is clamped
// 1..64. The full parallel HTTP enumeration runs against the site table;
// the card action validates the gate itself.
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public static class PeopleTrackModule
{
    /// <summary>
    /// Throws unless the username is a safe handle. Returns clamped
    /// (concurrency, timeoutSec).
    /// </summary>
    public static (int Concurrency, int TimeoutSec) ValidateScan(
        string username, int maxConcurrency = 10, int timeoutSec = 12)
    {
        if (!Regex.IsMatch(username, @"^[A-Za-z0-9._-]{1,64}$"))
            throw new ArgumentException(
                $"Username '{username}' is not a safe handle (letters, digits, . _ - only, max 64 chars).");
        int conc = Math.Clamp(maxConcurrency, 1, 64);
        int to = Math.Max(1, timeoutSec);
        return (conc, to);
    }

    /// <summary>
    /// Card action "Test-Username": proves the input gate accepts good
    /// handles and rejects bad ones (offline self-test).
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

        Check("good handle accepted", () =>
        { ValidateScan("john.doe_99"); return true; });
        Check("space rejected", () =>
        { try { ValidateScan("john doe"); return false; } catch { return true; } });
        Check("empty rejected", () =>
        { try { ValidateScan(""); return false; } catch { return true; } });
        Check("too long rejected", () =>
        { try { ValidateScan(new string('a', 65)); return false; } catch { return true; } });
        Check("concurrency clamped high", () =>
        { var (c, _) = ValidateScan("x", 999); return c == 64; });
        Check("concurrency clamped low", () =>
        { var (c, _) = ValidateScan("x", 0); return c == 1; });

        string msg = $"PeopleTrack hygiene: {passed}/{passed + failed} passed.";
        if (failed > 0) msg += " Failed: " + string.Join("; ", failures);
        results.Add(failed == 0
            ? ModuleResult.Pass("PeopleTrack", msg)
            : ModuleResult.Fail("PeopleTrack", msg, failures));
        return results;
    }
}
