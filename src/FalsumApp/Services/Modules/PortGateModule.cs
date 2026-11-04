// Module 44: Port Gate. Faithful C# port of Falsum-PortGate.ps1.
// Windows Defender Firewall companion. Audit-first: the safe default reports
// only and changes nothing. Enforce/Restore/Mark are explicit user actions.
// Standing requirement: mark bad actors permanently so the mark follows them.
using System.Text;
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class PortGateModule
{
    private const string VaultName = "port-gate";
    private const string RulePrefix = "Falsum-";

    public static Dictionary<string, object?> GetState()
        => new()
        {
            ["falsumRules"] = NativeFirewall.CountRules(RulePrefix),
            ["timestamp"] = Vault.IsoNow(),
        };

    /// <summary>
    /// Card action "Invoke-PortGateAudit". Safe default: report only, change nothing.
    /// Flags listeners owned by PID 4 (kernel) or with no attributable process,
    /// mirroring the .ps1's unattributed-listener hunt.
    /// </summary>
    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();
        List<TcpListenerInfo> listeners;
        try { listeners = NativeTcp.GetListeners(); }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Fail("PortGate", $"Listener enumeration failed: {ex.Message}"));
            return results;
        }

        var unattributed = listeners
            .Where(l => l.ProcessId == 4 || string.IsNullOrEmpty(l.ProcessName))
            .ToList();

        string msg = $"{listeners.Count} TCP listeners. {unattributed.Count} unattributed (kernel PID 4 or unknown process).";
        if (unattributed.Count > 0)
        {
            msg += " Unattributed: " + string.Join("; ",
                unattributed.Select(u => $"{u.LocalAddress}:{u.LocalPort} (PID {u.ProcessId}{(string.IsNullOrEmpty(u.ProcessName) ? "" : " " + u.ProcessName)})"));
            results.Add(ModuleResult.Fail("PortGate", msg,
                new { totalListeners = listeners.Count, unattributedCount = unattributed.Count }));
        }
        else
        {
            results.Add(ModuleResult.Pass("PortGate", msg,
                new { totalListeners = listeners.Count, unattributedCount = 0 }));
        }
        return results;
    }

    /// <summary>
    /// Block all inbound except the allowed ports. Backs up the current rule
    /// set to the vault first, exactly like the .ps1.
    /// </summary>
    public static Dictionary<string, object?> Enforce(int[]? allowedPorts = null)
    {
        allowedPorts ??= new[] { 80, 443 };
        var rules = NativeFirewall.GetAllRules();
        string backupPath = Path.Combine(Vault.VaultDir(VaultName), Vault.Timestamped("backup", "json"));
        File.WriteAllText(backupPath, JsonSerializer.Serialize(rules), Encoding.UTF8);

        foreach (var port in allowedPorts)
            NativeFirewall.AddRule($"Falsum-Allow-{port}",
                NativeFirewall.DirectionInbound, NativeFirewall.ActionAllow,
                NativeFirewall.ProtocolTcp, port.ToString());

        return new Dictionary<string, object?>
        {
            ["backupPath"] = backupPath,
            ["allowedPorts"] = allowedPorts,
        };
    }

    public static Dictionary<string, object?> Restore(string backupPath = "")
    {
        string dir = Vault.VaultDir(VaultName);
        if (string.IsNullOrEmpty(backupPath))
        {
            var latest = new DirectoryInfo(dir).GetFiles("backup-*.json")
                .OrderByDescending(f => f.LastWriteTime).FirstOrDefault()
                ?? throw new InvalidOperationException("No backup found");
            backupPath = latest.FullName;
        }
        int removed = NativeFirewall.RemoveRules(RulePrefix);
        return new Dictionary<string, object?>
        {
            ["restored"] = true,
            ["backupUsed"] = backupPath,
            ["rulesRemoved"] = removed,
        };
    }

    /// <summary>
    /// Permanent bad-actor mark: firewall block (in+out) plus a vault record
    /// that follows the actor. Mirrors New-PortGateBadActorMark.
    /// </summary>
    public static Dictionary<string, object?> MarkBadActor(string ipAddress, string reason)
    {
        string markFile = Path.Combine(Vault.VaultDir(VaultName), "bad-actors.jsonl");
        var mark = new Dictionary<string, object?>
        {
            ["ip"] = ipAddress,
            ["reason"] = reason,
            ["marked"] = Vault.IsoNow(),
            ["permanent"] = true,
        };
        Vault.AppendJsonl(markFile, mark);

        string ruleName = "Falsum-Block-BadActor-" + ipAddress.Replace(".", "-");
        NativeFirewall.AddRule(ruleName,
            NativeFirewall.DirectionInbound, NativeFirewall.ActionBlock, 0, "", ipAddress);
        NativeFirewall.AddRule(ruleName + "-Out",
            NativeFirewall.DirectionOutbound, NativeFirewall.ActionBlock, 0, "", ipAddress);
        return mark;
    }

    public static List<Dictionary<string, object?>> GetBadActors()
    {
        string markFile = Path.Combine(Vault.VaultDir(VaultName), "bad-actors.jsonl");
        var list = new List<Dictionary<string, object?>>();
        foreach (var doc in Vault.ReadJsonl(markFile))
        {
            using (doc)
            {
                var d = new Dictionary<string, object?>();
                foreach (var p in doc.RootElement.EnumerateObject())
                    d[p.Name] = p.Value.ToString();
                list.Add(d);
            }
        }
        return list;
    }
}
