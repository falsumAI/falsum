// Module 37: DataGate. Faithful C# port of Falsum-DataGate.ps1.
// Quick summary: how much data is leaving, to where. Flags connections to
// non-standard ports and non-private destinations.
using System.Net;

namespace FalsumApp.Services.Modules;

public static class DataGateModule
{
    private static bool IsPrivate(IPAddress addr)
    {
        if (addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        byte[] b = addr.GetAddressBytes();
        return b[0] == 10
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168);
    }

    /// <summary>Card action "Get-FalsumDataSummary".</summary>
    public static List<ModuleResult> GetSummary()
    {
        var results = new List<ModuleResult>();
        List<TcpConnectionInfo> conns;
        try { conns = NativeTcp.GetEstablished(); }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Fail("DataGate", $"Connection enumeration failed: {ex.Message}"));
            return results;
        }

        int uniqueDests = conns.Select(c => c.RemoteAddress.ToString()).Distinct().Count();
        var suspicious = conns.Where(c =>
            c.RemotePort != 80 && c.RemotePort != 443 && c.RemotePort != 53 &&
            !IsPrivate(c.RemoteAddress)).ToList();

        string msg = $"{conns.Count} established connections to {uniqueDests} destinations. " +
                     $"{suspicious.Count} to unusual ports/destinations.";
        if (suspicious.Count > 0)
            msg += " Flagged: " + string.Join("; ",
                suspicious.Take(5).Select(s => $"{s.ProcessName} → {s.RemoteAddress}:{s.RemotePort}"));

        results.Add(suspicious.Count == 0
            ? ModuleResult.Pass("DataGate", msg,
                new { totalConnections = conns.Count, uniqueDestinations = uniqueDests })
            : ModuleResult.Fail("DataGate", msg,
                suspicious.Select(s => new
                {
                    proc = s.ProcessName, pid = s.ProcessId,
                    dst = s.RemoteAddress.ToString(), port = s.RemotePort,
                }).ToList()));
        return results;
    }
}
