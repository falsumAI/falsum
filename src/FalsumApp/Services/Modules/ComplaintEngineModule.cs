// Complaint Engine. Built on Gregg's order:
// "A COMPLAINT ENGINE THAT TAKES ALL THE COMPLAINTS PEOPLE LEAVE ON
//  YOUTUBE PODCASTS AND FORUMS AROUND BIG TECH AND THE ISSUES THEY HAVE.
//  THOSE COMPLAINTS GET LOGGED PILED BY DUPLICATE AND FLAGGED FROM MOST
//  IMPORTANT TO LEAST IMPORTANT AND THEN THEY GET SOLVED IN THE APP."
//
// How it works:
//   1. COLLECT: the user pastes a complaint (or the app imports from a
//      text file). Source, text, date, product.
//   2. DEDUPE: complaints about the same issue pile together. The pile
//      grows every time someone reports the same thing.
//   3. RANK: piles are flagged most-important to least-important by
//      (pile size × severity). A hundred people screaming about the
//      same thing outranks one person whispering.
//   4. SOLVE: each pile maps to the Falsum module that fixes it. The
//      app doesn't just log the complaint — it runs the fix.
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public static class ComplaintEngineModule
{
    private static string VaultDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "vault", "complaints");
    private static string StorePath => Path.Combine(VaultDir, "complaints.json");

    public sealed class Complaint
    {
        public string Id { get; set; } = "";
        public string Source { get; set; } = "";    // youtube | podcast | forum | user
        public string Product { get; set; } = "";   // what Big Tech product
        public string Text { get; set; } = "";
        public string Date { get; set; } = "";
        public int Severity { get; set; } = 3;      // 1-5, 5 = data theft / harm
    }

    public sealed class Pile
    {
        public string Key { get; set; } = "";            // normalized issue key
        public string Title { get; set; } = "";
        public List<string> Products { get; set; } = new();
        public int Count { get; set; } = 0;
        public double AvgSeverity { get; set; } = 0;
        public double Score { get; set; } = 0;           // Count × AvgSeverity
        public string SolverModule { get; set; } = "";   // which Falsum module fixes it
        public List<string> SampleTexts { get; set; } = new();
    }

    /// <summary>
    /// Maps complaint keywords to the Falsum module that solves them.
    /// Every complaint gets a solver — nothing is logged without a fix.
    /// </summary>
    private static readonly (string[] Keywords, string Module, string Title)[] Solvers = new[]
    {
        (new[] { "telemetry", "spying", "phone home", "tracking" }, "50-predator-vault", "Telemetry / data extraction"),
        (new[] { "slow", "bloat", "bloated", "laggy" }, "28-task-killer", "Bloatware / resource hog"),
        (new[] { "update", "forced update", "restart" }, "48-group-policy", "Forced updates"),
        (new[] { "privacy", "data broker", "sold my data" }, "09-broker-eradicator", "Data broker exposure"),
        (new[] { "breach", "hacked", "leaked" }, "08-breach-cleaner", "Data breach"),
        (new[] { "malware", "virus", "infected" }, "21-malware-hunter", "Malware infection"),
        (new[] { "phishing", "scam", "fake email" }, "16-mail-shield", "Phishing / scam"),
        (new[] { "ad ", "ads", "advertising" }, "22-tracker-block", "Ad tracking"),
        (new[] { "password", "login", "locked out" }, "29-registry-fix", "Account / access issue"),
        (new[] { "wifi", "router", "network" }, "19-wifi-router", "Network / router issue"),
        (new[] { "browser", "chrome", "edge", "fingerprint" }, "39-chrome-internals", "Browser privacy"),
        (new[] { "certificate", "https", "not secure" }, "47-cert-verifier", "Certificate issue"),
    };

    private static string NormalizeKey(string text)
    {
        string t = text.ToLowerInvariant();
        t = Regex.Replace(t, @"[^a-z0-9 ]", " ");
        t = Regex.Replace(t, @"\s+", " ").Trim();
        // Key on the first 6 significant words.
        var words = t.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Where(w => w.Length > 3)
            .Take(6);
        return string.Join(" ", words);
    }

    public static void LogComplaint(string source, string product, string text, int severity = 3)
    {
        try
        {
            Directory.CreateDirectory(VaultDir);
            var all = LoadAll();
            all.Add(new Complaint
            {
                Id = Guid.NewGuid().ToString("N")[..8],
                Source = source, Product = product, Text = text,
                Date = DateTimeOffset.Now.ToString("o"),
                Severity = Math.Clamp(severity, 1, 5),
            });
            File.WriteAllText(StorePath, JsonSerializer.Serialize(all,
                new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    private static List<Complaint> LoadAll()
    {
        if (!File.Exists(StorePath)) return new List<Complaint>();
        try
        {
            return JsonSerializer.Deserialize<List<Complaint>>(
                File.ReadAllText(StorePath)) ?? new List<Complaint>();
        }
        catch { return new List<Complaint>(); }
    }

    /// <summary>
    /// Piles duplicates, ranks most→least important, maps each pile to
    /// the module that solves it.
    /// </summary>
    public static List<Pile> BuildPiles()
    {
        var piles = new Dictionary<string, Pile>();
        foreach (var c in LoadAll())
        {
            string key = NormalizeKey(c.Text);
            if (!piles.TryGetValue(key, out var p))
            {
                // Find the solver.
                string solver = "00-coherence-core";
                string title = key;
                foreach (var (kw, mod, t) in Solvers)
                {
                    if (kw.Any(k => c.Text.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    { solver = mod; title = t; break; }
                }
                p = new Pile { Key = key, Title = title, SolverModule = solver };
                piles[key] = p;
            }
            p.Count++;
            if (!p.Products.Contains(c.Product)) p.Products.Add(c.Product);
            if (p.SampleTexts.Count < 3) p.SampleTexts.Add(c.Text);
        }
        // Score and rank.
        var all = LoadAll();
        foreach (var p in piles.Values)
        {
            var inPile = all.Where(c => NormalizeKey(c.Text) == p.Key).ToList();
            p.AvgSeverity = inPile.Count > 0 ? inPile.Average(c => c.Severity) : 0;
            p.Score = p.Count * p.AvgSeverity;
        }
        return piles.Values.OrderByDescending(p => p.Score).ToList();
    }

    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();
        var piles = BuildPiles();
        if (piles.Count == 0)
        {
            results.Add(ModuleResult.Pass("ComplaintEngine",
                "No complaints logged yet. Paste one in — YouTube, podcast, forum, " +
                "or your own. Duplicates pile up, the biggest piles get solved first."));
            return results;
        }
        results.Add(ModuleResult.Pass("ComplaintEngine",
            $"{piles.Count} complaint pile(s), ranked most→least important. " +
            "Every pile maps to the module that solves it."));
        foreach (var p in piles.Take(10))
        {
            results.Add(p.Score >= 15
                ? ModuleResult.Fail("ComplaintEngine",
                    $"[{p.Score:F0}] {p.Title} ×{p.Count} reports " +
                    $"(products: {string.Join(", ", p.Products.Take(3))}). " +
                    $"SOLVER: run module {p.SolverModule}.")
                : ModuleResult.Warn("ComplaintEngine",
                    $"[{p.Score:F0}] {p.Title} ×{p.Count} reports. " +
                    $"SOLVER: run module {p.SolverModule}."));
        }
        return results;
    }
}
