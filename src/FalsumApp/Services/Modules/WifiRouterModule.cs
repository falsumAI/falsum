// Module 19: WiFi Router. Faithful C# port of Test-RouterPorts.
// Read-only probe of the gateway's admin surface from the LAN side.
// Open telnet/HTTP admin on the LAN side is the finding; the fix is the
// checklist in the message. Never logs in, never changes anything.
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace FalsumApp.Services.Modules;

public static class WifiRouterModule
{
    private static string? GetDefaultGateway()
    {
        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            var props = nic.GetIPProperties();
            var gw = props.GatewayAddresses
                .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
            if (gw != null) return gw.Address.ToString();
        }
        return null;
    }

    private static bool IsPortOpen(string host, int port, int timeoutMs = 1500)
    {
        using var c = new TcpClient();
        try
        {
            var iar = c.BeginConnect(host, port, null, null);
            bool open = iar.AsyncWaitHandle.WaitOne(timeoutMs);
            if (open) c.EndConnect(iar);
            return open;
        }
        catch { return false; }
    }

    public static List<ModuleResult> TestRouterPorts(string? gateway = null)
    {
        var results = new List<ModuleResult>();
        gateway ??= GetDefaultGateway();
        if (gateway == null)
        {
            results.Add(ModuleResult.Fail("WifiRouter", "No gateway found."));
            return results;
        }
        int[] ports = { 80, 443, 8080, 8443, 7547, 22, 23, 3389, 53 };
        var open = new List<string>();
        foreach (int p in ports)
        {
            bool isOpen = IsPortOpen(gateway, p);
            string note = "";
            if (isOpen && p == 23) note = "TELNET open on gateway — plaintext admin, disable it";
            if (isOpen && p == 80) note = "HTTP admin reachable — ensure HTTPS-only + strong password";
            if (isOpen && p == 7547) note = "TR-069 (7547) open — ISP remote management; on your own router disable CWMP, on ISP-leased gear you cannot";
            if (isOpen && p == 22) note = "SSH admin open on gateway — ensure strong creds, disable if unused";
            if (isOpen)
                open.Add(note != "" ? $"port {p}: {note}" : $"port {p}: open");
        }
        if (open.Count == 0)
            results.Add(ModuleResult.Pass("WifiRouter",
                $"Gateway {gateway}: no admin ports reachable from the LAN. Clean.",
                new { gateway }));
        else
            results.Add(ModuleResult.Warn("WifiRouter",
                $"Gateway {gateway}: {open.Count} admin port(s) open on the LAN side. " +
                string.Join("; ", open),
                new { gateway, open }));
        return results;
    }
}
