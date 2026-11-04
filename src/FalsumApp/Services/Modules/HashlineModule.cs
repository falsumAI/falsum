using System.IO;
// Module 43: Hashline. Faithful C# port of Falsum-Hashline.ps1.
// Browser-traffic hasher. SHA-256 per body, SHA-384 hash-chained ledger.
// Standing requirement: data integrity checked before traffic leaves the router.
//
// CHAIN FORMAT (must stay byte-identical to the .ps1 so old vaults verify):
//   genesis prev = "HL-GENESIS"
//   canonical    = "{ts}|{url}|{method}|{bodyHash}|{bodyLength}|{remoteIp}|{remotePort}|{prev}"
//   hash         = SHA384hex( UTF8( canonical + "|" + prev ) )
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class HashlineModule
{
    private const string VaultName = "hashline";
    private const string Genesis = "HL-GENESIS";

    // AI endpoint directory - known AI service domains for traffic labeling.
    // Ported verbatim from the .ps1.
    private static readonly string[] AIEndpoints =
    {
        "chat.openai.com", "api.openai.com",
        "claude.ai", "api.anthropic.com",
        "gemini.google.com", "generativelanguage.googleapis.com",
        "copilot.microsoft.com", "copilot.cloud.microsoft",
        "grok.x.ai", "api.x.ai",
        "chat.deepseek.com", "api.deepseek.com",
        "meta.ai", "www.meta.ai",
    };

    private static string ChainPath() => Path.Combine(Vault.VaultDir(VaultName), "chain.jsonl");

    public static Dictionary<string, object?> NewEntry(
        string url, string method = "GET", byte[]? body = null,
        string remoteIp = "", int remotePort = 0)
    {
        body ??= Array.Empty<byte>();
        string bodyHash = body.Length > 0 ? Vault.Sha256Hex(body) : "";

        var prev = Genesis;
        var lastLine = Vault.ReadLastLine(ChainPath());
        if (lastLine != null)
        {
            try
            {
                using var doc = JsonDocument.Parse(lastLine);
                if (doc.RootElement.TryGetProperty("hash", out var h))
                    prev = h.GetString() ?? Genesis;
            }
            catch { /* corrupt tail: restart chain from genesis */ }
        }

        string ts = Vault.IsoNow();
        var entry = new Dictionary<string, object?>
        {
            ["ts"] = ts,
            ["url"] = url,
            ["method"] = method,
            ["bodyHash"] = bodyHash,
            ["bodyLength"] = body.Length,
            ["remoteIp"] = remoteIp,
            ["remotePort"] = remotePort,
            ["prev"] = prev,
        };
        string canonical = $"{ts}|{url}|{method}|{bodyHash}|{body.Length}|{remoteIp}|{remotePort}|{prev}";
        entry["hash"] = Vault.Sha384Hex(canonical + "|" + prev);

        Vault.AppendJsonl(ChainPath(), entry);
        return entry;
    }

    public static (bool match, string expected, string actual) TestIntegrity(byte[] data, string expectedHash)
    {
        string actual = Vault.Sha256Hex(data);
        return (string.Equals(actual, expectedHash, StringComparison.OrdinalIgnoreCase), expectedHash, actual);
    }

    public static bool IsAIEndpoint(string url)
    {
        foreach (var domain in AIEndpoints)
            if (url.Contains(domain, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>Card action "Get-HashlineStats".</summary>
    public static List<ModuleResult> GetStats()
    {
        var results = new List<ModuleResult>();
        var docs = Vault.ReadJsonl(ChainPath());
        if (docs.Count == 0)
        {
            results.Add(ModuleResult.Pass("Hashline", "No traffic hashed yet."));
            return results;
        }

        int aiCount = 0;
        var oddPorts = new List<string>();
        foreach (var doc in docs)
        {
            using (doc)
            {
                var r = doc.RootElement;
                string url = r.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
                int port = r.TryGetProperty("remotePort", out var p) ? p.GetInt32() : 0;
                if (IsAIEndpoint(url)) aiCount++;
                if (port != 80 && port != 443 && port != 0 && oddPorts.Count < 20)
                {
                    string ip = r.TryGetProperty("remoteIp", out var ip2) ? ip2.GetString() ?? "" : "";
                    oddPorts.Add($"{url} ({ip}:{port})");
                }
            }
        }

        string msg = $"{docs.Count} hashed transmissions. AI endpoints: {aiCount}. Non-standard ports: {oddPorts.Count}."
            + (oddPorts.Count > 0 ? " Flagged: " + string.Join("; ", oddPorts) : "");
        results.Add(ModuleResult.Pass("Hashline", msg,
            new { totalEntries = docs.Count, aiEndpoints = aiCount, nonStandardPorts = oddPorts.Count }));
        return results;
    }
}
