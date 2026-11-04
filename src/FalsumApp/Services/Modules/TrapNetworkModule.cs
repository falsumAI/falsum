// Module 10: Trap Network. Faithful C# port of the trap-profile catalog.
// Decoy listeners bind ONLY the user's own interfaces (default 127.0.0.1).
// Never outbound. The card action lists the available decoy profiles;
// starting a listener needs an explicit profile choice.
using System.Diagnostics;

namespace FalsumApp.Services.Modules;

public static class TrapNetworkModule
{
    public sealed class TrapProfile
    {
        public string Name = "";
        public int[] Ports = Array.Empty<int>();
        public string Mode = "";
        public string Note = "";
    }

    public static readonly TrapProfile[] Profiles = new[]
    {
        new TrapProfile { Name = "ssh", Ports = new[] { 2222 }, Mode = "banner",
            Note = "Fake SSH banner; real SSH clients disconnect on their own." },
        new TrapProfile { Name = "telnet", Ports = new[] { 2323 }, Mode = "telnet",
            Note = "Two-stage: login prompt, then password prompt, then refuse." },
        new TrapProfile { Name = "http", Ports = new[] { 8080 }, Mode = "http",
            Note = "Reads the request headers, answers 401, closes." },
        new TrapProfile { Name = "ftp", Ports = new[] { 2121 }, Mode = "banner",
            Note = "One command read, one refusal, close." },
        new TrapProfile { Name = "smtp", Ports = new[] { 2525 }, Mode = "banner",
            Note = "One command read, one refusal, close." },
        new TrapProfile { Name = "pop3", Ports = new[] { 2110 }, Mode = "banner",
            Note = "One command read, one refusal, close." },
        new TrapProfile { Name = "imap", Ports = new[] { 2143 }, Mode = "banner",
            Note = "One command read, one refusal, close." },
        new TrapProfile { Name = "rdp", Ports = new[] { 23389 }, Mode = "banner",
            Note = "Fake RDP pre-handshake; logs the knock, refuses." },
        new TrapProfile { Name = "mssql", Ports = new[] { 21433 }, Mode = "banner",
            Note = "Fake TDS pre-login; logs the knock, refuses." },
    };

    /// <summary>
    /// Card action "Start-TrapListener": reports the decoy catalog and which
    /// trap ports are currently free to bind. Listeners bind 127.0.0.1 only.
    /// </summary>
    public static List<ModuleResult> Catalog()
    {
        var results = new List<ModuleResult>();
        var lines = new List<string>();
        foreach (var p in Profiles)
        {
            bool free = true;
            foreach (int port in p.Ports)
            {
                try
                {
                    var l = new System.Net.Sockets.TcpListener(
                        System.Net.IPAddress.Loopback, port);
                    l.Start(); l.Stop();
                }
                catch { free = false; break; }
            }
            lines.Add($"{p.Name} (ports {string.Join(",", p.Ports)}): " +
                      (free ? "free to bind" : "PORT IN USE") + $" — {p.Note}");
        }
        results.Add(ModuleResult.Pass("TrapNetwork",
            $"Decoy trap catalog ({Profiles.Length} profiles). All bind 127.0.0.1 only, never outbound. " +
            string.Join(" | ", lines),
            Profiles.Select(p => p.Name).ToArray()));
        return results;
    }
}
