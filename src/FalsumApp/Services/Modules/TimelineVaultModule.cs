// Module 12: Timeline Vault. Faithful C# port of New-Vault.
// Creates the evidence vault with a hash-chained genesis entry.
// The genesis JSON is byte-identical to the .ps1's ConvertTo-Json -Compress
// output so chains verify across implementations:
//   check-line: {"seq":0,"utc":"...","type":"genesis","prev":"GENESIS","data":{"note":"..."}}
//   sha384 = SHA384hex(check-line)
//   stored:   {"seq":0,"utc":"...","type":"genesis","sha384":"...","prev":"GENESIS","data":{"note":"..."}}
using System.Text;

namespace FalsumApp.Services.Modules;

public static class TimelineVaultModule
{
    private static string DefaultVaultPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "vault", "timeline");

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
    /// Card/ProtectAll action "New-Vault": create the vault if missing.
    /// Idempotent — an existing non-empty ledger is left untouched.
    /// </summary>
    public static List<ModuleResult> NewVault(string? path = null)
    {
        var results = new List<ModuleResult>();
        try
        {
            string dir = path ?? DefaultVaultPath;
            Directory.CreateDirectory(dir);
            string ledger = Path.Combine(dir, "ledger.jsonl");
            bool empty = !File.Exists(ledger) ||
                         string.IsNullOrWhiteSpace(File.ReadAllText(ledger, Encoding.UTF8));
            if (!empty)
            {
                results.Add(ModuleResult.Pass("TimelineVault",
                    $"Vault already exists: {ledger}"));
                return results;
            }
            string utc = DateTime.UtcNow.ToString("o");
            string check = "{\"seq\":0,\"utc\":" + JsonEscape(utc) +
                           ",\"type\":\"genesis\",\"prev\":\"GENESIS\"," +
                           "\"data\":{\"note\":\"BLACKBOX evidence vault created\"}}";
            string sha384 = Vault.Sha384Hex(check);
            string line = "{\"seq\":0,\"utc\":" + JsonEscape(utc) +
                          ",\"type\":\"genesis\",\"sha384\":\"" + sha384 +
                          "\",\"prev\":\"GENESIS\"," +
                          "\"data\":{\"note\":\"BLACKBOX evidence vault created\"}}";
            File.WriteAllText(ledger, line + Environment.NewLine, new UTF8Encoding(false));
            results.Add(ModuleResult.Pass("TimelineVault",
                $"Vault created: {ledger} (genesis seq 0)",
                new { ledger, genesisSha384 = sha384 }));
        }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Fail("TimelineVault",
                "Could not create vault: " + ex.Message));
        }
        return results;
    }
}
