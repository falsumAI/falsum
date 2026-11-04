// Module 14: Bug Bounty. Faithful C# port of the Scope Law gate.
// PASSIVE recon only — and it REFUSES without a registered scope record.
// The scope registry lives at %LOCALAPPDATA%\Falsum\vault\bounty\
// bounty-registry.json. Each record: Program, Target, ScopeUrl,
// AuthorizedNote, ScopePublic, RegisteredUtc, RegisteredBy.
// The card action reports the registry state: how many scope records exist
// and whether any target is currently authorized.
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class BugBountyModule
{
    private static string RegistryPath =>
        Path.Combine(Vault.VaultDir("bounty"), "bounty-registry.json");

    public sealed class ScopeRecord
    {
        public string Program = "";
        public string Target = "";
        public string ScopeUrl = "";
        public string RegisteredUtc = "";
    }

    public static List<ScopeRecord> GetScopes()
    {
        var list = new List<ScopeRecord>();
        try
        {
            string p = RegistryPath;
            if (!File.Exists(p)) return list;
            string raw = File.ReadAllText(p);
            if (string.IsNullOrWhiteSpace(raw)) return list;
            using var doc = JsonDocument.Parse(raw);
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                list.Add(new ScopeRecord
                {
                    Program = el.TryGetProperty("Program", out var pr) ? pr.GetString() ?? "" : "",
                    Target = el.TryGetProperty("Target", out var tg) ? tg.GetString() ?? "" : "",
                    ScopeUrl = el.TryGetProperty("ScopeUrl", out var su) ? su.GetString() ?? "" : "",
                    RegisteredUtc = el.TryGetProperty("RegisteredUtc", out var ru) ? ru.GetString() ?? "" : "",
                });
            }
        }
        catch { }
        return list;
    }

    /// <summary>
    /// The gate. True only when a scope record exists for program+target.
    /// </summary>
    public static bool IsScopeRegistered(string name, string target)
        => GetScopes().Any(r =>
            string.Equals(r.Program, name, StringComparison.OrdinalIgnoreCase) &&
            (string.Equals(r.Target, target, StringComparison.OrdinalIgnoreCase) ||
             target.EndsWith("." + r.Target, StringComparison.OrdinalIgnoreCase) ||
             r.Target.EndsWith("." + target, StringComparison.OrdinalIgnoreCase)));

    /// <summary>
    /// Card action "Start-BountyRecon": reports scope-law state. Recon
    /// itself needs a program+target and refuses without a scope record —
    /// a card click shows what is currently authorized.
    /// </summary>
    public static List<ModuleResult> ScopeStatus()
    {
        var results = new List<ModuleResult>();
        var scopes = GetScopes();
        if (scopes.Count == 0)
        {
            results.Add(ModuleResult.Pass("BugBounty",
                "Scope Law: no scope records registered. Passive recon will REFUSE " +
                "until a program's published scope page is registered. " +
                $"Registry: {RegistryPath}"));
            return results;
        }
        var lines = scopes.Select(s =>
            $"{s.Program} -> {s.Target} (scope: {(s.ScopeUrl == "" ? "not recorded" : s.ScopeUrl)})");
        results.Add(ModuleResult.Pass("BugBounty",
            $"Scope Law: {scopes.Count} scope record(s) registered. Passive recon " +
            "authorized for: " + string.Join("; ", lines),
            scopes));
        return results;
    }
}
