// Module 03: Net Scan. Faithful C# port of Test-TargetSpec.
// Validates a scan target: IP, hostname, or subnet:CIDR. The card action
// validates the machine's own LAN subnet so a click always does something
// real. Prefix rules: IPv4 /16../30, IPv6 /48../128 (enumeration needs
// /120 or narrower — a /64 holds 18 quintillion addresses).
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public static class NetScanModule
{
    public sealed class TargetSpec
    {
        public bool Valid;
        public string Kind = "";   // "subnet" | "ip" | "hostname"
        public string Value = "";
    }

    public static TargetSpec ValidateTarget(string target)
    {
        string t = target.Trim();
        if (t.Length > 1 && t.EndsWith("."))
            t = t[..^1]; // trailing-dot FQDN is legal DNS
        if (t.StartsWith("subnet:", StringComparison.OrdinalIgnoreCase))
        {
            string cidr = t[7..];
            var parts = cidr.Split('/');
            if (parts.Length != 2)
                throw new ArgumentException($"Bad subnet spec '{target}' — use subnet:10.0.0.0/24");
            IPAddress parsed;
            try { parsed = IPAddress.Parse(parts[0]); }
            catch (Exception ex) { throw new ArgumentException($"Bad subnet IP in '{target}': {ex.Message}"); }
            if (!int.TryParse(parts[1], out int prefix))
                throw new ArgumentException($"Bad prefix in '{target}' — use /16../30 (IPv4) or /48../128 (IPv6)");
            if (parsed.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (prefix < 48 || prefix > 128)
                    throw new ArgumentException($"IPv6 prefix /48../128 supported (got /{prefix} in '{target}'). Enumeration needs /120 or narrower.");
            }
            else if (prefix < 16 || prefix > 30)
                throw new ArgumentException($"Prefix /16../30 supported (got /{prefix} in '{target}')");
            return new TargetSpec { Valid = true, Kind = "subnet", Value = cidr };
        }
        try
        {
            IPAddress.Parse(t);
            return new TargetSpec { Valid = true, Kind = "ip", Value = t };
        }
        catch { }
        if (t.Length <= 253 &&
            Regex.IsMatch(t, @"^[A-Za-z0-9]([A-Za-z0-9\.\-]{0,251}[A-Za-z0-9])?$"))
            return new TargetSpec { Valid = true, Kind = "hostname", Value = t };
        throw new ArgumentException($"Bad target '{target}' — use an IP, a hostname, or subnet:10.0.0.0/24");
    }

    private static string? LocalSubnet()
    {
        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                if (IPAddress.IsLoopback(ua.Address)) continue;
                byte[] ip = ua.Address.GetAddressBytes();
                byte[] mask = ua.IPv4Mask.GetAddressBytes();
                byte[] net = new byte[4];
                int ones = 0;
                for (int i = 0; i < 4; i++)
                {
                    net[i] = (byte)(ip[i] & mask[i]);
                    ones += Convert.ToString(mask[i], 2).Count(c => c == '1');
                }
                if (ones < 16) ones = 24;
                if (ones > 30) ones = 24;
                return $"subnet:{net[0]}.{net[1]}.{net[2]}.{net[3]}/{ones}";
            }
        }
        return null;
    }

    /// <summary>
    /// Card action "Test-TargetSpec": validates this machine's own LAN
    /// subnet as the default scan target.
    /// </summary>
    public static List<ModuleResult> ValidateDefault()
    {
        var results = new List<ModuleResult>();
        try
        {
            string? subnet = LocalSubnet();
            if (subnet == null)
            {
                results.Add(ModuleResult.Fail("NetScan", "No LAN interface found."));
                return results;
            }
            var spec = ValidateTarget(subnet);
            results.Add(ModuleResult.Pass("NetScan",
                $"Default scan target valid: {spec.Value} ({spec.Kind}).",
                new { target = spec.Value, kind = spec.Kind }));
        }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Fail("NetScan", ex.Message));
        }
        return results;
    }
}
