// Module 00: Coherence Core. Faithful C# port of Falsum-Coherence.ps1.
// Gregg's drift-math verification battery: 21 pure-logic cross-checks that
// score how well two evidence items agree (0-100 + reasons). Unknown check
// type -> 50, "no check defined". All checks are pure: no network, no clock,
// deterministic.
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public sealed class CoherenceResult
{
    public int Score;
    public List<string> Reasons { get; } = new();
}

public static class CoherenceModule
{
    private static string S(Dictionary<string, object?> d, string key)
        => d.TryGetValue(key, out var v) ? v?.ToString() ?? "" : "";

    /// <summary>
    /// Run one named check against two evidence-data dictionaries.
    /// Returns score 0-100 with reason strings.
    /// </summary>
    public static CoherenceResult TestCoherence(
        Dictionary<string, object?> a, Dictionary<string, object?> b,
        string check, Dictionary<string, object?>? checkParams = null)
    {
        var r = new CoherenceResult { Score = 50 };
        checkParams ??= new Dictionary<string, object?>();
        switch (check)
        {
            case "process-port":
            {
                string pa = S(a, "process").ToLowerInvariant(), pb = S(b, "process").ToLowerInvariant();
                string porta = S(a, "port"), portb = S(b, "port");
                if (porta == portb && pa == pb && pa != "")
                { r.Score = 100; r.Reasons.Add($"process '{pa}' claims port {porta}; independent source agrees"); }
                else if (porta == portb && pa != pb)
                { r.Score = 20; r.Reasons.Add($"DRIFT: port {porta} claimed by '{pa}' but source B says '{pb}'"); }
                else if (porta != portb)
                { r.Score = 30; r.Reasons.Add($"DRIFT: port mismatch ({porta} vs {portb})"); }
                else r.Reasons.Add("insufficient data for process-port check");
                break;
            }
            case "dns-sni":
            {
                string da = S(a, "dns").ToLowerInvariant().TrimEnd('.');
                string db = S(b, "sni").ToLowerInvariant().TrimEnd('.');
                if (da != "" && da == db) { r.Score = 100; r.Reasons.Add($"DNS query '{da}' matches TLS SNI"); }
                else if (da != "" && db != "") { r.Score = 15; r.Reasons.Add($"DRIFT: DNS '{da}' but TLS went to '{db}' — possible hijack or tunnel"); }
                else r.Reasons.Add("insufficient data for dns-sni check");
                break;
            }
            case "rdap-asn":
            {
                string oa = S(a, "rdapOrg").ToLowerInvariant(), ob = S(b, "asnOrg").ToLowerInvariant();
                if (oa != "" && (oa == ob || oa.Contains(ob) || ob.Contains(oa)))
                { r.Score = 90; r.Reasons.Add($"RDAP org '{S(a, "rdapOrg")}' consistent with ASN org '{S(b, "asnOrg")}'"); }
                else if (oa != "" && ob != "") { r.Score = 35; r.Reasons.Add($"DIVERGED: RDAP '{S(a, "rdapOrg")}' vs ASN '{S(b, "asnOrg")}' — attribution uncertain"); }
                else r.Reasons.Add("insufficient data for rdap-asn check");
                break;
            }
            case "hash-match":
            {
                string ha = S(a, "sha256").ToLowerInvariant(), hb = S(b, "sha256").ToLowerInvariant();
                if (ha != "" && ha == hb) { r.Score = 100; r.Reasons.Add("hashes identical — integrity verified"); }
                else if (ha != "" && hb != "") { r.Score = 0; r.Reasons.Add("HASH MISMATCH — data altered between sources"); }
                else r.Reasons.Add("insufficient data for hash-match check");
                break;
            }
            case "time-order":
            {
                if (DateTime.TryParse(S(a, "utc"), out var ta) && DateTime.TryParse(S(b, "utc"), out var tb))
                {
                    if (ta <= tb) { r.Score = 100; r.Reasons.Add("timeline consistent: A precedes B"); }
                    else { r.Score = 25; r.Reasons.Add("DRIFT: A claims earlier event but timestamp is later"); }
                }
                else r.Reasons.Add("unparseable timestamps for time-order check");
                break;
            }
            case "ip-match":
            {
                static string Norm(string raw)
                {
                    var v = raw.Trim().ToLowerInvariant();
                    int pct = v.IndexOf('%');
                    if (pct >= 0) v = v[..pct];
                    if (v.StartsWith("::ffff:")) v = v[7..];
                    return v;
                }
                string ia = Norm(S(a, "ip")), ib = Norm(S(b, "ip"));
                if (ia != "" && ia == ib) { r.Score = 100; r.Reasons.Add($"IP '{ia}' identical across sources"); }
                else if (ia != "" && ib != "") { r.Score = 0; r.Reasons.Add($"IP MISMATCH: '{ia}' vs '{ib}' — different hosts"); }
                else r.Reasons.Add("insufficient data for ip-match check");
                break;
            }
            case "domain-cert":
            {
                string da = S(a, "domain").ToLowerInvariant().Trim().TrimEnd('.');
                string cb = S(b, "certName").ToLowerInvariant().Trim().TrimEnd('.');
                bool matched = false, wild = false;
                if (da != "" && cb != "")
                {
                    if (da == cb) matched = true;
                    else if (cb.StartsWith("*."))
                    {
                        wild = true;
                        string suffix = cb[2..];
                        if (da.EndsWith("." + suffix))
                        {
                            string extra = da[..(da.Length - suffix.Length - 1)];
                            if (extra != "" && !extra.Contains('.')) matched = true;
                        }
                    }
                }
                if (matched && !wild) { r.Score = 100; r.Reasons.Add($"cert name '{cb}' exactly covers '{da}'"); }
                else if (matched) { r.Score = 100; r.Reasons.Add($"wildcard cert '{cb}' covers '{da}'"); }
                else if (wild) { r.Score = 35; r.Reasons.Add($"DRIFT: wildcard '{cb}' does not cover '{da}' (deeper than one label or different suffix)"); }
                else if (da != "" && cb != "") { r.Score = 35; r.Reasons.Add($"DRIFT: cert '{cb}' does not name '{da}' — possible spoof or misissue"); }
                else r.Reasons.Add("insufficient data for domain-cert check");
                break;
            }
            case "port-service":
            {
                if (int.TryParse(S(a, "port"), out int port) && S(b, "service").Trim() != "")
                {
                    string svc = S(b, "service").ToLowerInvariant().Trim();
                    if (CoherenceTables.PortService.TryGetValue(port, out var expected))
                    {
                        var aliases = expected.Split('/');
                        if (aliases.Contains(svc) || expected == svc)
                        { r.Score = 100; r.Reasons.Add($"port {port} runs '{svc}' per service table"); }
                        else { r.Score = 30; r.Reasons.Add($"DRIFT: port {port} is '{expected}' per table but source claims '{svc}'"); }
                    }
                    else r.Reasons.Add($"port {port} not in service table — no check possible");
                }
                else r.Reasons.Add("insufficient data for port-service check");
                break;
            }
            case "cert-time":
            {
                if (DateTime.TryParse(S(a, "notBefore"), out var nb) &&
                    DateTime.TryParse(S(a, "notAfter"), out var na) &&
                    DateTime.TryParse(S(b, "utc"), out var ev))
                {
                    if (ev >= nb && ev <= na) { r.Score = 100; r.Reasons.Add("event inside certificate validity window"); }
                    else if (ev < nb) { r.Score = 25; r.Reasons.Add($"DRIFT: event predates certificate validity (notBefore {S(a, "notBefore")})"); }
                    else { r.Score = 25; r.Reasons.Add($"DRIFT: certificate expired before event (notAfter {S(a, "notAfter")})"); }
                }
                else r.Reasons.Add("unparseable timestamps for cert-time check");
                break;
            }
            case "ip-subnet":
            {
                try
                {
                    string ipStr = S(a, "ip").Trim(), cidr = S(b, "cidr").Trim();
                    var addr = IPAddress.Parse(ipStr);
                    var parts = cidr.Split('/');
                    if (parts.Length != 2) throw new FormatException($"CIDR '{cidr}' must be in address/prefix form (e.g. 10.0.0.0/8)");
                    var net = IPAddress.Parse(parts[0]);
                    int bits = int.Parse(parts[1]);
                    if (addr.AddressFamily != net.AddressFamily) throw new FormatException("address and network are different IP families");
                    if (bits < 0 || bits > 32) throw new FormatException("prefix length must be 0-32");
                    byte[] ab = addr.GetAddressBytes(), nb = net.GetAddressBytes();
                    if (ab.Length != 4) throw new FormatException("IPv6 not supported by this check — returns no verdict rather than a guess");
                    bool inNet = true;
                    for (int i = 0; i < 4; i++)
                    {
                        int bitsLeft = Math.Max(0, Math.Min(8, bits - 8 * i));
                        int oct = bitsLeft > 0 ? (int)(256 - Math.Pow(2, 8 - bitsLeft)) : 0;
                        if ((ab[i] & oct) != (nb[i] & oct)) { inNet = false; break; }
                    }
                    if (inNet) { r.Score = 100; r.Reasons.Add($"'{ipStr}' is inside claimed network '{cidr}'"); }
                    else { r.Score = 0; r.Reasons.Add($"DRIFT: '{ipStr}' is OUTSIDE claimed network '{cidr}' — spoof or wrong scope"); }
                }
                catch (Exception ex) { r.Reasons.Add($"ip-subnet check failed: {ex.Message}"); }
                break;
            }
            case "time-skew":
            {
                double maxSec = 5;
                if (checkParams.TryGetValue("MaxSeconds", out var ms) && ms != null)
                    double.TryParse(ms.ToString(), out maxSec);
                if (DateTime.TryParse(S(a, "utc"), out var ta) && DateTime.TryParse(S(b, "utc"), out var tb))
                {
                    double skew = Math.Abs((ta - tb).TotalSeconds);
                    if (skew <= maxSec) { r.Score = 100; r.Reasons.Add($"witness timestamps agree within {Math.Round(skew, 2)}s (limit {maxSec}s)"); }
                    else { r.Score = 20; r.Reasons.Add($"DRIFT: witness timestamps skew {Math.Round(skew, 1)}s > {maxSec}s — different events or clock tampering"); }
                }
                else r.Reasons.Add("unparseable timestamps for time-skew check");
                break;
            }
            case "domain-age":
            {
                double maxDays = 30;
                if (checkParams.TryGetValue("MaxAgeDays", out var md) && md != null)
                    double.TryParse(md.ToString(), out maxDays);
                if (DateTime.TryParse(S(a, "registered"), out var reg) && DateTime.TryParse(S(b, "utc"), out var ev))
                {
                    double age = (ev - reg).TotalDays;
                    if (age < 0) { r.Score = 35; r.Reasons.Add("DRIFT: event predates domain registration — impossible timeline"); }
                    else if (age <= maxDays) { r.Score = 15; r.Reasons.Add($"DRIFT: domain was {Math.Round(age, 1)} days old at event (<= {maxDays}) — throwaway/phishing pattern"); }
                    else { r.Score = 100; r.Reasons.Add($"domain was {Math.Round(age, 0)} days old at event — established"); }
                }
                else r.Reasons.Add("unparseable dates for domain-age check");
                break;
            }
            case "ttl-os":
            {
                if (int.TryParse(S(a, "ttl"), out int ttl) && S(b, "os").Trim() != "")
                {
                    string os = S(b, "os").ToLowerInvariant().Trim();
                    string expect = (ttl >= 63 && ttl <= 64) ? "unix-like"
                        : (ttl >= 127 && ttl <= 128) ? "windows"
                        : (ttl >= 254 && ttl <= 255) ? "network-gear" : "";
                    if (expect == "") { r.Score = 50; r.Reasons.Add($"TTL {ttl} not in a known OS fingerprint band (64/128/255) — no verdict"); }
                    else
                    {
                        bool unixHit = Regex.IsMatch(os, "linux|unix|bsd|mac|darwin|android|ios");
                        bool winHit = Regex.IsMatch(os, "windows|microsoft");
                        bool netHit = Regex.IsMatch(os, "cisco|juniper|router|switch|network");
                        bool fits = (expect == "unix-like" && unixHit) || (expect == "windows" && winHit) || (expect == "network-gear" && netHit);
                        if (fits) { r.Score = 100; r.Reasons.Add($"TTL {ttl} fits claimed OS family '{S(b, "os")}' (heuristic)"); }
                        else { r.Score = 40; r.Reasons.Add($"DRIFT: TTL {ttl} implies {expect} stack but source claims '{S(b, "os")}' — possible NAT or OS spoof (heuristic)"); }
                    }
                }
                else r.Reasons.Add("insufficient data for ttl-os check");
                break;
            }
            case "url-domain":
            {
                try
                {
                    string raw = S(a, "url").Trim();
                    if (raw != "" && !Regex.IsMatch(raw, @"^[a-zA-Z][a-zA-Z0-9+.-]*://")) raw = "http://" + raw;
                    var u = new Uri(raw);
                    string uh = u.Host.ToLowerInvariant().Trim().TrimEnd('.');
                    string dom = S(b, "domain").ToLowerInvariant().Trim().TrimEnd('.');
                    if (uh == "" || dom == "") r.Reasons.Add("insufficient data for url-domain check");
                    else if (uh == dom || uh.EndsWith("." + dom))
                    { r.Score = 100; r.Reasons.Add($"URL host '{uh}' matches claimed domain '{dom}'"); }
                    else { r.Score = 30; r.Reasons.Add($"DRIFT: URL host '{uh}' is not the claimed domain '{dom}' — lookalike or redirect risk"); }
                }
                catch { r.Reasons.Add($"url-domain check failed: unparseable URL '{S(a, "url")}'"); }
                break;
            }
            case "email-domain":
            {
                string em = S(a, "email").Trim();
                int lt = em.LastIndexOf('<'), gt = em.LastIndexOf('>');
                if (lt >= 0 && gt > lt) em = em.Substring(lt + 1, gt - lt - 1).Trim();
                string dom = S(b, "domain").ToLowerInvariant().Trim().TrimEnd('.');
                int at = em.LastIndexOf('@');
                if (at > 0 && dom != "")
                {
                    string mailDom = em[(at + 1)..].ToLowerInvariant().Trim().TrimEnd('.');
                    if (mailDom == dom || mailDom.EndsWith("." + dom))
                    { r.Score = 100; r.Reasons.Add($"sender domain '{mailDom}' matches '{dom}'"); }
                    else { r.Score = 30; r.Reasons.Add($"DRIFT: email from '{mailDom}' claims to represent '{dom}' — spoof risk (heuristic)"); }
                }
                else r.Reasons.Add("insufficient data for email-domain check");
                break;
            }
            case "port-banner":
            {
                if (int.TryParse(S(a, "port"), out int port) && S(b, "banner").Trim() != "")
                {
                    string banner = S(b, "banner").ToLowerInvariant().Trim();
                    if (CoherenceTables.PortKeywords.TryGetValue(port, out var kws))
                    {
                        bool hit = kws.Any(k => banner.Contains(k));
                        if (hit) { r.Score = 100; r.Reasons.Add($"banner on port {port} matches expected service keywords"); }
                        else { r.Score = 35; r.Reasons.Add($"DRIFT: port {port} banner '{S(b, "banner")}' carries none of the expected service keywords — mislabeled or tunneled service"); }
                    }
                    else r.Reasons.Add($"port {port} has no keyword entry — no check possible");
                }
                else r.Reasons.Add("insufficient data for port-banner check");
                break;
            }
            case "mac-vendor":
            {
                string m = Regex.Replace(S(a, "mac").ToUpperInvariant(), "[^0-9A-F]", "");
                string vendor = S(b, "vendor").Trim();
                if (m.Length >= 6 && vendor != "")
                {
                    string oui = m[..6];
                    if (CoherenceTables.OuiVendor.TryGetValue(oui, out var known))
                    {
                        string vl = vendor.ToLowerInvariant();
                        if (known.ToLowerInvariant().Contains(vl) || vl.Contains(known.ToLowerInvariant()))
                        { r.Score = 100; r.Reasons.Add($"OUI {oui} -> '{known}' matches claimed vendor '{vendor}'"); }
                        else { r.Score = 40; r.Reasons.Add($"DRIFT: OUI {oui} is '{known}' but source claims '{vendor}' — spoofed MAC or wrong inventory"); }
                    }
                    else { r.Score = 50; r.Reasons.Add($"OUI {oui} not in shipped vendor table — no verdict"); }
                }
                else r.Reasons.Add("insufficient data for mac-vendor check");
                break;
            }
            case "hash-verify":
            {
                string claimed = S(b, "sha256").ToLowerInvariant().Trim();
                if (claimed != "" && a != null)
                {
                    if (!Regex.IsMatch(claimed, "^[0-9a-f]{64}$"))
                    { r.Score = 0; r.Reasons.Add($"MALFORMED: claimed hash '{claimed}' is not a 64-char hex SHA-256 — integrity cannot be evaluated, re-collect the hash"); }
                    else
                    {
                        string actual = Vault.Sha256Hex(Encoding.UTF8.GetBytes(CanonicalJson(a)));
                        if (actual == claimed) { r.Score = 100; r.Reasons.Add("recomputed SHA-256 matches claimed value — bytes intact"); }
                        else { r.Score = 0; r.Reasons.Add($"HASH MISMATCH: claimed {claimed[..16]}... but data hashes to {actual[..16]}... — bytes were altered after hashing"); }
                    }
                }
                else r.Reasons.Add("insufficient data for hash-verify check (needs A.data + B.sha256)");
                break;
            }
            case "geo-agree":
            {
                string ga = S(a, "geoA").Trim(), gb = S(b, "geoB").Trim();
                if (ga != "" && gb != "")
                {
                    string na = CountryName(ga), nb = CountryName(gb);
                    if (na == nb) { r.Score = 90; r.Reasons.Add($"geo sources agree: '{ga}' / '{gb}' -> {na}"); }
                    else { r.Score = 35; r.Reasons.Add($"DIVERGED: geo '{ga}' vs '{gb}' — anycast, VPN egress, or stale DB"); }
                }
                else r.Reasons.Add("insufficient data for geo-agree check");
                break;
            }
            case "file-magic":
            {
                string ext = S(a, "extension").ToLowerInvariant().Trim().TrimStart('.');
                string magic = Regex.Replace(S(b, "magicHex").ToUpperInvariant(), "[^0-9A-F]", "");
                if (ext != "" && magic != "")
                {
                    if (CoherenceTables.FileMagic.TryGetValue(ext, out var entry))
                    {
                        if (entry.Text) { r.Score = 50; r.Reasons.Add($".{ext} is a text format — magic-byte check not applicable"); }
                        else if (entry.Sigs.Any(s => magic.StartsWith(s)))
                        {
                            string shown = magic[..Math.Min(8, magic.Length)];
                            r.Score = 100; r.Reasons.Add($".{ext} magic {shown}... matches {entry.Name} signature");
                        }
                        else
                        {
                            string actual = "unrecognized binary";
                            foreach (var sig in CoherenceTables.MagicType.Keys.OrderByDescending(k => k.Length))
                                if (magic.StartsWith(sig)) { actual = CoherenceTables.MagicType[sig]; break; }
                            string shown = magic[..Math.Min(8, magic.Length)];
                            r.Score = 0;
                            r.Reasons.Add($"MISMATCH: file claims '.{ext}' ({entry.Name}) but first bytes {shown}... read as '{actual}' — renamed binary / double-extension signal");
                        }
                    }
                    else { r.Score = 50; r.Reasons.Add($".{ext} not in shipped magic table — no verdict"); }
                }
                else r.Reasons.Add("insufficient data for file-magic check (needs extension + magicHex)");
                break;
            }
            case "cert-issuer":
            {
                string iss = S(a, "issuer").Trim(), sub = S(b, "subject").Trim();
                if (iss != "" && sub != "")
                {
                    if (iss == sub)
                    { r.Score = 40; r.Reasons.Add("self-signed certificate (issuer == subject) — fine for dev/lab, suspect on a public login page"); }
                    else
                    {
                        var hit = CoherenceTables.TrustedCa.FirstOrDefault(row =>
                            iss.Contains(row.Keyword, StringComparison.OrdinalIgnoreCase));
                        if (hit.Keyword != null) { r.Score = 100; r.Reasons.Add($"issuer '{iss}' matches known public CA ({hit.Ca})"); }
                        else { r.Score = 50; r.Reasons.Add($"issuer '{iss}' not in shipped CA table — no verdict (private/enterprise CAs are legitimate)"); }
                    }
                }
                else r.Reasons.Add("insufficient data for cert-issuer check");
                break;
            }
            default:
                r.Score = 50;
                r.Reasons.Add("no check defined");
                break;
        }
        return r;
    }

    private static string CountryName(string geo)
    {
        string g = geo.Trim().ToLowerInvariant();
        if (CoherenceTables.Country.TryGetValue(g, out var name)) return name;
        return g;
    }

    /// <summary>
    /// Canonical JSON: keys sorted, invariant formatting. Matches the .ps1's
    /// ConvertTo-CanonicalJson for the string/number/bool/date cases that the
    /// hash-verify check uses.
    /// </summary>
    public static string CanonicalJson(Dictionary<string, object?> obj)
    {
        var sb = new StringBuilder();
        sb.Append('{');
        bool first = true;
        foreach (var key in obj.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            if (!first) sb.Append(',');
            first = false;
            sb.Append(JsonEscape(key));
            sb.Append(':');
            sb.Append(CanonicalValue(obj[key]));
        }
        sb.Append('}');
        return sb.ToString();
    }

    private static string CanonicalValue(object? v) => v switch
    {
        null => "null",
        string s => JsonEscape(s),
        bool b => b ? "true" : "false",
        DateTime dt => JsonEscape(dt.Kind == DateTimeKind.Utc
            ? dt.ToString("o") : dt.Kind == DateTimeKind.Local
            ? dt.ToUniversalTime().ToString("o")
            : dt.ToString("yyyy-MM-ddTHH:mm:ss.fffffff\\Z")),
        DateTimeOffset dto => JsonEscape(dto.ToUniversalTime().ToString("o")),
        byte n => n.ToString(System.Globalization.CultureInfo.InvariantCulture),
        short n => n.ToString(System.Globalization.CultureInfo.InvariantCulture),
        int n => n.ToString(System.Globalization.CultureInfo.InvariantCulture),
        long n => n.ToString(System.Globalization.CultureInfo.InvariantCulture),
        float n => n.ToString("R", System.Globalization.CultureInfo.InvariantCulture),
        double n => n.ToString("R", System.Globalization.CultureInfo.InvariantCulture),
        decimal n => n.ToString(System.Globalization.CultureInfo.InvariantCulture),
        Dictionary<string, object?> d => CanonicalJson(d),
        _ => JsonEscape(v.ToString() ?? ""),
    };

    private static string JsonEscape(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in s)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (c < 0x20) sb.Append($"\\u{(int)c:X4}");
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    /// <summary>
    /// Card action "Test-Coherence": runs the offline self-test battery.
    /// A module whose plumbing can't prove itself offline has no business going live.
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

        // hash-match: identical and mismatch
        Check("hash-match identical", () =>
            TestCoherence(
                new() { ["sha256"] = "abc" }, new() { ["sha256"] = "ABC" },
                "hash-match").Score == 100);
        Check("hash-match mismatch", () =>
            TestCoherence(
                new() { ["sha256"] = "abc" }, new() { ["sha256"] = "def" },
                "hash-match").Score == 0);
        // ip-match normalization
        Check("ip-match ::ffff: normalized", () =>
            TestCoherence(
                new() { ["ip"] = "::ffff:1.2.3.4" }, new() { ["ip"] = "1.2.3.4" },
                "ip-match").Score == 100);
        // time-order
        Check("time-order consistent", () =>
            TestCoherence(
                new() { ["utc"] = "2026-01-01T00:00:00Z" }, new() { ["utc"] = "2026-01-02T00:00:00Z" },
                "time-order").Score == 100);
        // domain-cert wildcard
        Check("domain-cert wildcard", () =>
            TestCoherence(
                new() { ["domain"] = "a.example.com" }, new() { ["certName"] = "*.example.com" },
                "domain-cert").Score == 100);
        Check("domain-cert deep wildcard rejected", () =>
            TestCoherence(
                new() { ["domain"] = "a.b.example.com" }, new() { ["certName"] = "*.example.com" },
                "domain-cert").Score == 35);
        // ip-subnet
        Check("ip-subnet inside", () =>
            TestCoherence(
                new() { ["ip"] = "10.1.2.3" }, new() { ["cidr"] = "10.0.0.0/8" },
                "ip-subnet").Score == 100);
        Check("ip-subnet outside", () =>
            TestCoherence(
                new() { ["ip"] = "11.1.2.3" }, new() { ["cidr"] = "10.0.0.0/8" },
                "ip-subnet").Score == 0);
        // hash-verify round-trip
        Check("hash-verify round-trip", () =>
        {
            var data = new Dictionary<string, object?> { ["b"] = (object?)"x", ["a"] = (object?)"y" };
            string h = Vault.Sha256Hex(Encoding.UTF8.GetBytes(CanonicalJson(data)));
            return TestCoherence(data, new() { ["sha256"] = h }, "hash-verify").Score == 100;
        });
        // canonical: key order independent
        Check("canonical key order independent", () =>
            CanonicalJson(new() { ["b"] = (object?)"1", ["a"] = (object?)"2" }) ==
            CanonicalJson(new() { ["a"] = (object?)"2", ["b"] = (object?)"1" }));
        // file-magic
        Check("file-magic exe", () =>
            TestCoherence(
                new() { ["extension"] = "exe" }, new() { ["magicHex"] = "4D5A90" },
                "file-magic").Score == 100);
        Check("file-magic mismatch", () =>
            TestCoherence(
                new() { ["extension"] = "pdf" }, new() { ["magicHex"] = "4D5A90" },
                "file-magic").Score == 0);
        // unknown check
        Check("unknown check neutral", () =>
            TestCoherence(new(), new(), "no-such-check").Score == 50);
        // url-domain
        Check("url-domain match", () =>
            TestCoherence(
                new() { ["url"] = "https://a.example.com/x" }, new() { ["domain"] = "example.com" },
                "url-domain").Score == 100);
        // port-service
        Check("port-service http", () =>
            TestCoherence(
                new() { ["port"] = "80" }, new() { ["service"] = "http" },
                "port-service").Score == 100);

        string msg = $"Coherence hygiene: {passed}/{passed + failed} passed.";
        if (failed > 0) msg += " Failed: " + string.Join("; ", failures);
        results.Add(failed == 0
            ? ModuleResult.Pass("Coherence", msg)
            : ModuleResult.Fail("Coherence", msg, failures));
        return results;
    }
}
