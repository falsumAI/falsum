// Module 16: Mail Shield. Faithful C# port of Falsum-MailShield.ps1's
// phishing-signal engine: brand table, confusable normalization, edit-
// distance typosquat detection, address parsing, and the weighted signal
// battery. Verdict: Critical >=80, High >=45, Medium >=20, else Low.
// Never a binary "safe" stamp — absence of signals is not proof.
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public static class MailShieldModule
{
    public static readonly string[] Brands = new[]
    {
        "paypal.com","microsoft.com","apple.com","amazon.com","google.com","gmail.com",
        "outlook.com","live.com","hotmail.com","yahoo.com","aol.com",
        "chase.com","bankofamerica.com","wellsfargo.com","citibank.com","capitalone.com",
        "usps.com","ups.com","fedex.com","dhl.com",
        "irs.gov","ssa.gov",
        "netflix.com","ebay.com","walmart.com","target.com","costco.com",
        "facebook.com","meta.com","instagram.com","linkedin.com","whatsapp.com",
        "dropbox.com","adobe.com","zoom.us",
        "sharepoint.com","onedrive.com","office.com","office365.com","teams.microsoft.com",
        "venmo.com","cash.app","zellepay.com","coinbase.com",
        "bestbuy.com","homedepot.com","lowes.com","samsclub.com",
        "americanexpress.com","discover.com","navyfederal.org","usaa.com",
        "appleid.apple.com","icloud.com",
        "xfinity.com","spectrum.com","att.com","verizon.com","t-mobile.com",
        "geico.com","statefarm.com","progressive.com",
        "delta.com","united.com","americanairlines.com","southwest.com",
    };

    public static readonly string[] UrgentPhrases = new[]
    {
        "act now","immediate action","account suspended","account locked",
        "verify your account","unusual activity","suspicious activity",
        "final notice","last chance","expires today","within 24 hours",
        "click here immediately","confirm your identity","update your payment",
        "your account will be closed","security alert","unauthorized access",
    };

    /// <summary>Pure edit distance (insert/delete/substitute). O(m*n) time, O(n) memory.</summary>
    public static int Levenshtein(string a, string b)
    {
        if (a == b) return 0;
        int m = a.Length, n = b.Length;
        if (m == 0) return n;
        if (n == 0) return m;
        var prev = new int[n + 1];
        var curr = new int[n + 1];
        for (int j = 0; j <= n; j++) prev[j] = j;
        for (int i = 1; i <= m; i++)
        {
            curr[0] = i;
            for (int j = 1; j <= n; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                curr[j] = Math.Min(prev[j] + 1, Math.Min(curr[j - 1] + 1, prev[j - 1] + cost));
            }
            (prev, curr) = (curr, prev);
        }
        return prev[n];
    }

    /// <summary>
    /// Flags typosquat / homograph / punycode lookalikes of known brands.
    /// Pure string logic — no network.
    /// </summary>
    public static List<string> LookalikeVerdict(string domain)
    {
        string d = domain.ToLowerInvariant();
        var findings = new List<string>();
        if (d.StartsWith("xn--"))
            findings.Add($"Punycode/homograph domain: {d} (non-ASCII disguised as ASCII)");
        string norm = d.Replace("0", "o").Replace("1", "l").Replace("5", "s")
            .Replace("8", "b").Replace("rn", "m").Replace("vv", "w").Replace("cl", "d");
        foreach (var brand in Brands)
        {
            if (d == brand) continue;
            string brandBase = Regex.Replace(brand, @"\.com$", "");
            if (norm == brand || norm == brandBase)
                findings.Add($"Lookalike of {brand} : {d}");
            else
            {
                string stem = Regex.Replace(brand, @"\..*$", "");
                if (d.Contains(stem) && d != brand && !d.EndsWith("." + brand))
                    findings.Add($"Contains brand string '{stem}' but is not {brand} : {d} (inspect)");
            }
        }
        // Edit-distance typosquats the normalizer misses.
        foreach (var brand in Brands)
        {
            if (d == brand || d.EndsWith("." + brand)) continue;
            int dist = Levenshtein(d, brand);
            if (dist > 0 && dist <= 2)
                findings.Add($"Edit-distance lookalike of {brand} : {d} (distance {dist})");
        }
        return findings;
    }

    public sealed class AddressParts
    {
        public string Display = "";
        public string Address = "";
        public string Domain = "";
    }

    public static AddressParts ParseAddress(string field)
    {
        var p = new AddressParts();
        var m = Regex.Match(field, @"^\s*""?(.*?)""?\s*<([^>]+)>\s*$");
        if (m.Success)
        {
            p.Display = m.Groups[1].Value.Trim('"', ' ');
            p.Address = m.Groups[2].Value.Trim().ToLowerInvariant();
        }
        else
        {
            int lt = field.LastIndexOf('<'), gt = field.LastIndexOf('>');
            if (lt >= 0 && gt > lt)
            {
                p.Display = field[..lt].Trim().Trim('"');
                p.Address = field.Substring(lt + 1, gt - lt - 1).Trim().ToLowerInvariant();
            }
            else p.Address = field.Trim().ToLowerInvariant();
        }
        var dm = Regex.Match(p.Address, @"@(.+)$");
        if (dm.Success) p.Domain = dm.Groups[1].Value.ToLowerInvariant();
        return p;
    }

    public sealed class Signal
    {
        public string Name = "";
        public int Weight;
        public string Detail = "";
    }

    /// <summary>
    /// Weighted phishing-signal battery over parsed email fields.
    /// </summary>
    public static List<Signal> CheckSignals(
        string fromHeader, string? replyToHeader, string subject, string body,
        string? authResults = null, IEnumerable<string>? links = null)
    {
        var signals = new List<Signal>();
        void Add(string name, int weight, string detail)
            => signals.Add(new Signal { Name = name, Weight = weight, Detail = detail });

        var from = ParseAddress(fromHeader);
        if (!string.IsNullOrEmpty(replyToHeader))
        {
            var rt = ParseAddress(replyToHeader);
            if (rt.Address != "" && rt.Address != from.Address)
                Add("Reply-To differs from From", 25,
                    $"From: {from.Address} / Reply-To: {rt.Address}");
        }
        // Display-name brand spoof.
        if (from.Display != "" && from.Domain != "")
        {
            string dl = from.Display.ToLowerInvariant();
            foreach (var brand in Brands)
            {
                string bname = brand.Split('.')[0];
                if (dl.Contains(bname) && from.Domain != brand &&
                    !from.Domain.EndsWith("." + brand))
                {
                    Add("Display-name brand spoof", 30,
                        $"Display '{from.Display}' claims {brand} but sender domain is {from.Domain}");
                    break;
                }
            }
        }
        // Lookalike sender domain.
        bool lookalikeHit = false;
        foreach (var f in LookalikeVerdict(from.Domain))
        {
            if (f.StartsWith("Punycode")) { Add("Homograph sender domain", 35, f); lookalikeHit = true; }
            else if (f.StartsWith("Lookalike")) { Add("Lookalike sender domain", 30, f); lookalikeHit = true; }
            else if (f.StartsWith("Edit-distance") && !lookalikeHit) { Add("Edit-distance lookalike sender domain", 30, f); lookalikeHit = true; }
            else if (!f.StartsWith("Edit-distance")) Add("Brand-string in domain (inspect)", 10, f);
        }
        // Authentication results.
        if (string.IsNullOrWhiteSpace(authResults))
            Add("No Authentication-Results header", 8,
                "Cannot verify SPF/DKIM/DMARC from headers present");
        else
        {
            string ar = authResults.ToLowerInvariant();
            if (ar.Contains("spf=fail")) Add("SPF fail", 25, authResults);
            if (ar.Contains("dkim=fail")) Add("DKIM fail", 25, authResults);
            if (ar.Contains("dmarc=fail")) Add("DMARC fail", 20, authResults);
        }
        // Urgency language.
        string urgText = (subject + " " + body).ToLowerInvariant();
        foreach (var phrase in UrgentPhrases)
            if (urgText.Contains(phrase)) { Add("Urgency language", 10, $"Phrase: '{phrase}'"); break; }
        // Link anchor/href mismatch + lookalike link domains.
        if (links != null)
        {
            foreach (var link in links)
            {
                try
                {
                    var u = new Uri(link);
                    string hrefHost = u.Host.ToLowerInvariant();
                    foreach (var f in LookalikeVerdict(hrefHost))
                    {
                        if (f.StartsWith("Punycode")) Add("Homograph link domain", 35, f);
                        else if (f.StartsWith("Lookalike")) Add("Lookalike link domain", 30, f);
                    }
                }
                catch { }
            }
        }
        return signals;
    }

    public static string VerdictLevel(int score)
        => score >= 80 ? "Critical" : score >= 45 ? "High"
            : score >= 20 ? "Medium" : "Low";

    /// <summary>
    /// Card action "Test-PhishingSignals": runs the offline hygiene battery.
    /// No network — proves the signal engine scores correctly.
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

        Check("typosquat paypa1.com flagged",
            () => LookalikeVerdict("paypa1.com").Any(f => f.StartsWith("Lookalike")));
        Check("punycode flagged",
            () => LookalikeVerdict("xn--paypl-4ve.com").Any(f => f.StartsWith("Punycode")));
        Check("legit paypal.com clean",
            () => LookalikeVerdict("paypal.com").Count == 0);
        Check("address parse", () =>
        {
            var p = ParseAddress("\"PayPal\" <spoof@evil.example>");
            return p.Display == "PayPal" && p.Domain == "evil.example";
        });
        Check("synthetic phish scores High/Critical", () =>
        {
            var sigs = CheckSignals(
                "\"PayPal\" <security@paypa1.com>",
                "harvest@evil.example",
                "Act now: unusual activity",
                "Act now, your account will be closed within 24 hours. https://paypal.com/login",
                "spf=fail dkim=fail",
                new[] { "http://paypa1.com/login" });
            int score = sigs.Sum(s => s.Weight);
            return VerdictLevel(score) is "High" or "Critical";
        });
        Check("reply-to mismatch signal",
            () => CheckSignals("a@x.com", "b@evil.example", "s", "b", "spf=pass")
                .Any(s => s.Name.StartsWith("Reply-To")));
        Check("clean mail scores Low", () =>
        {
            var sigs = CheckSignals(
                "\"Mom\" <mom@example.com>", null, "Sunday dinner",
                "See you Sunday.",
                "spf=pass; dkim=pass; dmarc=pass");
            return VerdictLevel(sigs.Sum(s => s.Weight)) == "Low";
        });

        string msg = $"MailShield hygiene: {passed}/{passed + failed} passed.";
        if (failed > 0) msg += " Failed: " + string.Join("; ", failures);
        results.Add(failed == 0
            ? ModuleResult.Pass("MailShield", msg)
            : ModuleResult.Fail("MailShield", msg, failures));
        return results;
    }
}
