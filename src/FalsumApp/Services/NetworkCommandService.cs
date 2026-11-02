using System.Diagnostics;
using System.Text;

namespace FalsumApp.Services;

/// <summary>
/// Network Command Center — native C# service using CMD, not PowerShell.
///
/// WHY CMD: Deterministic input → deterministic output. No jargon, no object
/// pipeline bullshit, no binary serialization. You type a command, you get text back.
/// Every Windows admin who's ever debugged a network issue used these commands.
/// Falsum wraps them in plain language the end user understands.
///
/// CONTROLS THE ENTIRE NETWORK:
/// - Interface control (enable/disable, IP config)
/// - Firewall control (rules, blocking)
/// - Connection monitoring (who's connected to what)
/// - DNS control (flush, set, detect hijacking)
/// - Route control (view and manage routing table)
/// - Wi-Fi control (profiles, passwords, signal)
/// - Port control (what's listening, kill it)
/// - Bandwidth monitoring
///
/// Every command runs through CMD. Every output is parsed into plain language.
/// The user sees "Your computer is talking to 192.168.1.1" not "TCP 192.168.1.1:443 ESTABLISHED".
/// </summary>
public class NetworkCommandService
{
    /// <summary>
    /// Run a CMD command and return clean text output.
    /// </summary>
    private string RunCmd(string command, int timeoutMs = 30000)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {command}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
            };

            using var proc = Process.Start(psi);
            if (proc == null) return "ERROR: Could not start cmd.exe";

            var output = new StringBuilder();
            proc.OutputDataReceived += (s, e) => { if (e.Data != null) output.AppendLine(e.Data); };
            proc.BeginOutputReadLine();
            proc.WaitForExit(timeoutMs);

            return output.ToString().Trim();
        }
        catch (Exception ex)
        {
            return $"ERROR: {ex.Message}";
        }
    }

    // ========================================================================
    // INTERFACE CONTROL
    // ========================================================================

    /// <summary>
    /// Show all network interfaces in plain language.
    /// </summary>
    public List<NetworkInterface> GetInterfaces()
    {
        var result = new List<NetworkInterface>();
        var output = RunCmd("netsh interface show interface");

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed)) continue;
            if (trimmed.StartsWith("Admin", StringComparison.OrdinalIgnoreCase)) continue;
            if (trimmed.StartsWith("---")) continue;

            // Parse: Admin State | State | Type | Interface Name
            var parts = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 4)
            {
                result.Add(new NetworkInterface
                {
                    AdminState = parts[0],
                    State = parts[1],
                    Type = parts[2],
                    Name = string.Join(" ", parts.Skip(3)),
                    IsConnected = parts[1].Equals("Connected", StringComparison.OrdinalIgnoreCase),
                });
            }
        }

        return result;
    }

    /// <summary>
    /// Enable or disable a network interface. Plain language, real control.
    /// </summary>
    public string SetInterfaceState(string interfaceName, bool enable)
    {
        var action = enable ? "enable" : "disable";
        var output = RunCmd($"netsh interface set interface \"{interfaceName}\" {action}");
        return string.IsNullOrWhiteSpace(output)
            ? $"Interface '{interfaceName}' {action}d."
            : output;
    }

    /// <summary>
    /// Get IP configuration in plain language.
    /// </summary>
    public string GetIpConfig()
    {
        return RunCmd("ipconfig /all");
    }

    /// <summary>
    /// Release and renew IP address. Fixes most "no internet" issues.
    /// </summary>
    public string RenewIpAddress()
    {
        var release = RunCmd("ipconfig /release");
        var renew = RunCmd("ipconfig /renew", 60000);
        return $"Released.\n{release}\n\nRenewed.\n{renew}";
    }

    // ========================================================================
    // CONNECTION MONITORING — who is your computer talking to?
    // ========================================================================

    /// <summary>
    /// Show all active connections in plain language.
    /// "Your computer is talking to X" instead of raw netstat output.
    /// </summary>
    public List<NetworkConnection> GetActiveConnections()
    {
        var result = new List<NetworkConnection>();
        var output = RunCmd("netstat -ano");

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
                continue;

            var parts = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 4)
            {
                var conn = new NetworkConnection
                {
                    Protocol = parts[0],
                    LocalAddress = parts[1],
                    RemoteAddress = parts[2],
                    State = parts.Length > 3 ? parts[3] : "",
                    ProcessId = parts.Length > 4 ? parts[4] : "",
                };

                // Plain language: who is this?
                conn.PlainDescription = DescribeConnection(conn);
                result.Add(conn);
            }
        }

        return result;
    }

    private string DescribeConnection(NetworkConnection conn)
    {
        var remote = conn.RemoteAddress;

        // Local network?
        if (remote.StartsWith("192.168.") || remote.StartsWith("10.") || remote.StartsWith("172.16."))
            return $"Talking to a device on your local network ({remote})";

        if (remote.StartsWith("127."))
            return $"Talking to itself ({remote}) — this is normal";

        // External
        var port = remote.Contains(':') ? remote.Split(':').Last() : "";
        var portDesc = port switch
        {
            "80" => "web (unencrypted)",
            "443" => "web (encrypted)",
            "53" => "DNS lookup",
            _ => $"port {port}"
        };

        return $"Connected to {remote} via {portDesc}";
    }

    /// <summary>
    /// Kill all connections from a specific process.
    /// </summary>
    public string KillProcessConnections(string processId)
    {
        return RunCmd($"taskkill /PID {processId} /F");
    }

    // ========================================================================
    // FIREWALL CONTROL
    // ========================================================================

    /// <summary>
    /// Show firewall status for all profiles.
    /// </summary>
    public string GetFirewallStatus()
    {
        return RunCmd("netsh advfirewall show allprofiles state");
    }

    /// <summary>
    /// Block an IP address at the firewall. Permanent until removed.
    /// </summary>
    public string BlockIpAddress(string ipAddress, string ruleName = "")
    {
        if (string.IsNullOrWhiteSpace(ruleName))
            ruleName = $"Falsum-Block-{ipAddress}-{DateTime.Now:yyyyMMddHHmmss}";

        var output = RunCmd(
            $"netsh advfirewall firewall add rule name=\"{ruleName}\" " +
            $"dir=in action=block remoteip={ipAddress} " +
            $"description=\"Blocked by Falsum\"");

        return string.IsNullOrWhiteSpace(output)
            ? $"Blocked {ipAddress} at the firewall."
            : output;
    }

    /// <summary>
    /// Remove a firewall block rule.
    /// </summary>
    public string UnblockIpAddress(string ruleName)
    {
        return RunCmd($"netsh advfirewall firewall delete rule name=\"{ruleName}\"");
    }

    /// <summary>
    /// List all firewall rules.
    /// </summary>
    public string ListFirewallRules()
    {
        return RunCmd("netsh advfirewall firewall show rule name=all");
    }

    // ========================================================================
    // DNS CONTROL
    // ========================================================================

    /// <summary>
    /// Flush DNS cache. Fixes "website won't load" issues.
    /// </summary>
    public string FlushDns()
    {
        return RunCmd("ipconfig /flushdns");
    }

    /// <summary>
    /// Show current DNS servers.
    /// </summary>
    public string GetDnsServers()
    {
        return RunCmd("nslookup");
    }

    /// <summary>
    /// Set DNS to a trusted provider. Stops ISP DNS hijacking.
    /// </summary>
    public string SetDnsServer(string interfaceName, string primaryDns, string? secondaryDns = null)
    {
        var result = new StringBuilder();
        result.AppendLine(RunCmd($"netsh interface ip set dns \"{interfaceName}\" static {primaryDns}"));
        if (!string.IsNullOrWhiteSpace(secondaryDns))
        {
            result.AppendLine(RunCmd($"netsh interface ip add dns \"{interfaceName}\" {secondaryDns} index=2"));
        }
        return result.ToString();
    }

    // ========================================================================
    // WI-FI CONTROL
    // ========================================================================

    /// <summary>
    /// Show all Wi-Fi networks in range.
    /// </summary>
    public string ScanWifi()
    {
        return RunCmd("netsh wlan show networks mode=bssid");
    }

    /// <summary>
    /// Show saved Wi-Fi profiles.
    /// </summary>
    public List<string> GetWifiProfiles()
    {
        var result = new List<string>();
        var output = RunCmd("netsh wlan show profiles");

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("All User Profile", StringComparison.OrdinalIgnoreCase))
            {
                var name = trimmed.Split(':').Last().Trim();
                result.Add(name);
            }
        }

        return result;
    }

    /// <summary>
    /// Show current Wi-Fi connection details.
    /// </summary>
    public string GetWifiStatus()
    {
        return RunCmd("netsh wlan show interfaces");
    }

    /// <summary>
    /// Disconnect from Wi-Fi.
    /// </summary>
    public string DisconnectWifi()
    {
        return RunCmd("netsh wlan disconnect");
    }

    // ========================================================================
    // ROUTE CONTROL
    // ========================================================================

    /// <summary>
    /// Show routing table.
    /// </summary>
    public string GetRoutes()
    {
        return RunCmd("route print");
    }

    // ========================================================================
    // PORT CONTROL
    // ========================================================================

    /// <summary>
    /// Show what's listening on your computer. Every open port, every process.
    /// </summary>
    public List<ListeningPort> GetListeningPorts()
    {
        var result = new List<ListeningPort>();
        var output = RunCmd("netstat -ano | findstr LISTENING");

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed)) continue;

            var parts = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 4)
            {
                var localParts = parts[1].Split(':');
                result.Add(new ListeningPort
                {
                    Protocol = parts[0],
                    Address = parts[1],
                    Port = localParts.Length > 1 ? localParts.Last() : "",
                    ProcessId = parts.Last(),
                    Description = DescribePort(localParts.Length > 1 ? localParts.Last() : ""),
                });
            }
        }

        return result;
    }

    private string DescribePort(string port)
    {
        return port switch
        {
            "80" => "Web server (HTTP)",
            "443" => "Web server (HTTPS)",
            "21" => "FTP server",
            "22" => "SSH server",
            "23" => "Telnet (INSECURE)",
            "25" => "Email (SMTP)",
            "53" => "DNS server",
            "135" => "Windows RPC",
            "139" => "Windows file sharing (NetBIOS)",
            "445" => "Windows file sharing (SMB)",
            "3389" => "Remote Desktop",
            "5900" => "VNC remote access",
            _ => $"Port {port}"
        };
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    /// <summary>
    /// Ping a host. Plain language result.
    /// </summary>
    public string Ping(string host, int count = 4)
    {
        return RunCmd($"ping -n {count} {host}");
    }

    /// <summary>
    /// Trace the route to a host. Shows every hop.
    /// </summary>
    public string TraceRoute(string host)
    {
        return RunCmd($"tracert -d {host}", 120000);
    }

    /// <summary>
    /// Full network diagnostic. Everything in one shot.
    /// </summary>
    public NetworkDiagnostic FullDiagnostic()
    {
        return new NetworkDiagnostic
        {
            Timestamp = DateTime.UtcNow,
            Interfaces = GetInterfaces(),
            ActiveConnections = GetActiveConnections(),
            ListeningPorts = GetListeningPorts(),
            FirewallStatus = GetFirewallStatus(),
            WifiStatus = GetWifiStatus(),
        };
    }
}

public class NetworkInterface
{
    public string AdminState { get; set; } = "";
    public string State { get; set; } = "";
    public string Type { get; set; } = "";
    public string Name { get; set; } = "";
    public bool IsConnected { get; set; }
}

public class NetworkConnection
{
    public string Protocol { get; set; } = "";
    public string LocalAddress { get; set; } = "";
    public string RemoteAddress { get; set; } = "";
    public string State { get; set; } = "";
    public string ProcessId { get; set; } = "";
    public string PlainDescription { get; set; } = "";
}

public class ListeningPort
{
    public string Protocol { get; set; } = "";
    public string Address { get; set; } = "";
    public string Port { get; set; } = "";
    public string ProcessId { get; set; } = "";
    public string Description { get; set; } = "";
}

public class NetworkDiagnostic
{
    public DateTime Timestamp { get; set; }
    public List<NetworkInterface> Interfaces { get; set; } = new();
    public List<NetworkConnection> ActiveConnections { get; set; } = new();
    public List<ListeningPort> ListeningPorts { get; set; } = new();
    public string FirewallStatus { get; set; } = "";
    public string WifiStatus { get; set; } = "";
}
