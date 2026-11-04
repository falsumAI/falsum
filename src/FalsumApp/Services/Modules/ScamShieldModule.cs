// Module 18: Scam Shield. Faithful C# port of Falsum-ScamShield.ps1's
// scoring engine + offline hygiene battery. Checklist data lives in
// ScamShieldData.cs (extracted verbatim: 9 scam types, 37 weighted steps,
// 20 payment-demand terms).
// Scoring: an UNSAFE answer adds the step's full weight; 'u'/blank (unknown)
// adds half (per-step rounding); the safe answer adds 0.
// Level: Critical >=60%, High >=40%, Medium >=15% of max, else Low.
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public static class ScamShieldModule
{
    public sealed class StepResult
    {
        public string Id = "";
        public string Question = "";
        public string SafeAnswer = "";
        public string Answer = "";
        public bool Failed;
        public bool Unknown;
        public int Points;
        public string How = "";
    }

    public sealed class CheckResult
    {
        public string Type = "";
        public int Score;
        public int MaxPoints;
        public string Level = "";
        public List<StepResult> Steps { get; } = new();
    }

    public static string ToLevel(int score, int max)
    {
        if (max <= 0) return "Low";
        double pct = 100.0 * score / max;
        if (pct >= 60) return "Critical";
        if (pct >= 40) return "High";
        if (pct >= 15) return "Medium";
        return "Low";
    }

    public static int MaxPoints(string type)
        => ScamShieldData.Checklists.TryGetValue(type, out var steps)
            ? steps.Sum(s => s.W) : 0;

    /// <summary>
    /// Scores a scam checklist. Answers map step Id -> 'y'/'n'/'u'/blank.
    /// Unknown ('u'/blank) scores half weight per step — unverified is half
    /// a red flag, not zero.
    /// </summary>
    public static CheckResult Check(string type, Dictionary<string, string>? answers = null)
    {
        var result = new CheckResult { Type = type };
        if (!ScamShieldData.Checklists.TryGetValue(type, out var steps))
            throw new ArgumentException($"Unknown scam type: {type}");
        answers ??= new Dictionary<string, string>();
        foreach (var s in steps)
        {
            string a = answers.TryGetValue(s.Id, out var v)
                ? v.Trim().ToLowerInvariant() : "";
            bool failed = a != s.Good && a != "u" && a != "";
            bool unknown = !failed && (a == "u" || a == "");
            int pts = failed ? s.W : unknown ? (int)Math.Round(s.W / 2.0) : 0;
            result.Score += pts;
            result.Steps.Add(new StepResult
            {
                Id = s.Id, Question = s.Q, SafeAnswer = s.Good,
                Answer = a, Failed = failed, Unknown = unknown,
                Points = pts, How = s.How,
            });
        }
        result.MaxPoints = MaxPoints(type);
        result.Level = ToLevel(result.Score, result.MaxPoints);
        return result;
    }

    /// <summary>
    /// Scans free text for scam payment demands. Word-boundary matching
    /// ("cryptography" does NOT trip "crypto"); trailing-s tolerant.
    /// </summary>
    public static List<(string Term, int Weight, string Why)> PaymentRedFlags(string text)
    {
        var hits = new List<(string, int, string)>();
        foreach (var p in ScamShieldData.PaymentTerms)
        {
            string pat = @"\b" + Regex.Escape(p.Term) + "s?\\b";
            if (Regex.IsMatch(text, pat, RegexOptions.IgnoreCase))
                hits.Add((p.Term, p.W, p.Why));
        }
        return hits;
    }

    /// <summary>
    /// Totals payment-demand weight: >=50 Critical, >=25 High, >0 Flagged.
    /// </summary>
    public static (int Total, string Level) PaymentRiskScore(string text)
    {
        int total = PaymentRedFlags(text).Sum(h => h.Weight);
        string level = total >= 50 ? "Critical" : total >= 25 ? "High"
            : total > 0 ? "Flagged" : "Clean";
        return (total, level);
    }

    /// <summary>
    /// Card action "Start-ScamCheck": runs the offline hygiene battery.
    /// No network, no interaction — proves the engine scores correctly.
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

        // Checklist shape + polarity on every type.
        foreach (var t in ScamShieldData.Checklists.Keys)
        {
            var cl = ScamShieldData.Checklists[t];
            Check($"checklist {t} non-empty", () => cl.Length >= 3);
            Check($"checklist {t} weights positive", () => cl.Sum(s => s.W) > 0);
            Check($"checklist {t} polarity on every step",
                () => cl.All(s => s.Good == "y" || s.Good == "n"));
            Check($"checklist {t} max points > 0", () => MaxPoints(t) > 0);
        }
        // Spot polarity.
        var rom = ScamShieldData.Checklists["romance"];
        Check("polarity R3 (asked for money) safe=n",
            () => rom.First(s => s.Id == "R3").Good == "n");
        Check("polarity R5 (avoiding meeting) safe=n",
            () => rom.First(s => s.Id == "R5").Good == "n");
        var tech = ScamShieldData.Checklists["techsupport"];
        Check("polarity T3 (gift cards) safe=n",
            () => tech.First(s => s.Id == "T3").Good == "n");
        var vis = ScamShieldData.Checklists["vishing"];
        Check("polarity V1 (verify known number) safe=y",
            () => vis.First(s => s.Id == "V1").Good == "y");
        var smi = ScamShieldData.Checklists["smishing"];
        Check("polarity S3 (domain matches) safe=y",
            () => smi.First(s => s.Id == "S3").Good == "y");

        // Level boundaries.
        Check("level 60/100 = Critical", () => ToLevel(60, 100) == "Critical");
        Check("level 59/100 = High", () => ToLevel(59, 100) == "High");
        Check("level 40/100 = High", () => ToLevel(40, 100) == "High");
        Check("level 39/100 = Medium", () => ToLevel(39, 100) == "Medium");
        Check("level 15/100 = Medium", () => ToLevel(15, 100) == "Medium");
        Check("level 14/100 = Low", () => ToLevel(14, 100) == "Low");
        Check("level 0/100 = Low", () => ToLevel(0, 100) == "Low");
        Check("level max=0 guard", () => ToLevel(5, 0) == "Low");

        // Romance: all-unsafe -> Critical at max; all-safe -> Low.
        var wrong = new Dictionary<string, string>
            { ["R1"] = "n", ["R2"] = "n", ["R3"] = "y", ["R4"] = "n", ["R5"] = "y" };
        var v = Check("romance", wrong);
        Check("romance all-unsafe = Critical", () => v.Level == "Critical");
        Check("romance score = max", () => v.Score == v.MaxPoints);
        var right = new Dictionary<string, string>
            { ["R1"] = "y", ["R2"] = "y", ["R3"] = "n", ["R4"] = "y", ["R5"] = "n" };
        var v2 = Check("romance", right);
        Check("romance all-safe = Low", () => v2.Level == "Low");
        // Unknown answers score half per step.
        var unk = new Dictionary<string, string>
            { ["R1"] = "u", ["R2"] = "u", ["R3"] = "u", ["R4"] = "u", ["R5"] = "u" };
        var v3 = Check("romance", unk);
        int expHalf = rom.Sum(s => (int)Math.Round(s.W / 2.0));
        Check("romance all-unknown scores half (per-step)", () => v3.Score == expHalf);
        // Mixed polarity: R3='n' (no money ask) must score 0.
        var v4 = Check("romance", right);
        Check("R3='n' (no money ask) scores 0",
            () => v4.Steps.First(s => s.Id == "R3").Points == 0);

        // Payment flags: weighted, word-boundary.
        var hits = PaymentRedFlags("please pay with steam cards and bitcoin urgently");
        Check("payment flags caught >=2", () => hits.Count >= 2);
        Check("steam card weight 35",
            () => hits.FirstOrDefault(h => h.Term == "steam card").Weight == 35);

        string msg = $"ScamShield hygiene: {passed}/{passed + failed} passed.";
        if (failed > 0) msg += " Failed: " + string.Join("; ", failures);
        results.Add(failed == 0
            ? ModuleResult.Pass("ScamShield", msg)
            : ModuleResult.Fail("ScamShield", msg, failures));
        return results;
    }
}
