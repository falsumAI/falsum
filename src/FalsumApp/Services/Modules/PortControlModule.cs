// Module 32: Port Control. Faithful C# port of the non-interactive core of
// Falsum-PortControl.ps1 (the .ps1's menu was interactive Read-Host; the app
// drives these primitives directly, and Port Consent handles the prompting).
using System.Text;

namespace FalsumApp.Services.Modules;

public static class PortControlModule
{
    public sealed class PortInfo
    {
        public int Port; public string Address = "";
        public int ProcessId; public string ProcessName = "";
    }

    public static List<PortInfo> GetListeningPorts()
        => NativeTcp.GetListeners()
            .Select(l => new PortInfo
            {
                Port = l.LocalPort,
                Address = l.LocalAddress.ToString(),
                ProcessId = l.ProcessId,
                ProcessName = l.ProcessName,
            })
            .OrderBy(p => p.Port)
            .ToList();

    public static string BlockPort(int port, string direction = "Inbound")
    {
        if (port < 1 || port > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        int dir = direction.Equals("Outbound", StringComparison.OrdinalIgnoreCase)
            ? NativeFirewall.DirectionOutbound : NativeFirewall.DirectionInbound;
        NativeFirewall.AddRule($"Falsum-PortControl-Block-{port}-{direction}",
            dir, NativeFirewall.ActionBlock, NativeFirewall.ProtocolTcp, port.ToString());
        return $"Blocked TCP port {port} ({direction})";
    }

    public static string UnblockPort(int port)
    {
        int removed = NativeFirewall.RemoveRules($"Falsum-PortControl-Block-{port}-");
        return removed > 0 ? $"Unblocked TCP port {port} ({removed} rules removed)"
                           : $"No Falsum block rules found for port {port}";
    }

    public static List<Dictionary<string, string>> MyRules()
    {
        var all = NativeFirewall.GetAllRules();
        return all.Where(r => r.TryGetValue("DisplayName", out var n) &&
                              n.StartsWith("Falsum-", StringComparison.OrdinalIgnoreCase)).ToList();
    }

    /// <summary>Card action "Invoke-PortControlWorkflow": port inventory.</summary>
    public static List<ModuleResult> Invoke()
    {
        var results = new List<ModuleResult>();
        List<PortInfo> ports;
        try { ports = GetListeningPorts(); }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Fail("PortControl", $"Port enumeration failed: {ex.Message}"));
            return results;
        }
        var mine = MyRules();
        string msg = $"{ports.Count} listening ports. {mine.Count} Falsum firewall rules. " +
            string.Join("; ", ports.Take(8).Select(p => $"{p.Port}/{p.ProcessName}"));
        results.Add(ModuleResult.Pass("PortControl", msg,
            new { ports = ports.Count, falsumRules = mine.Count }));
        return results;
    }
}
