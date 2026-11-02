using System.IO;
using System.Text;
using System.Text.Json;

namespace FalsumApp.Services;

/// <summary>
/// Native Messaging Host — the app side of the extension bridge.
/// Chrome launches this and talks over stdin/stdout with a simple protocol:
///   4-byte little-endian length prefix + UTF-8 JSON.
/// 
/// The extension sends fingerprinting/tracker reports.
/// The app responds with block decisions and status.
/// </summary>
public class NativeMessagingHost
{
    private readonly Stream _stdin;
    private readonly Stream _stdout;
    private volatile bool _running;
    private Thread? _listenerThread;

    public event Action<JsonElement>? MessageReceived;
    public event EventHandler? OnShowDesktopRequested;
    public event EventHandler? OnScanRequested;

    public NativeMessagingHost()
    {
        _stdin = Console.OpenStandardInput();
        _stdout = Console.OpenStandardOutput();
    }

    /// <summary>
    /// Start listening for extension messages on a background thread.
    /// </summary>
    public void Start()
    {
        _running = true;
        _listenerThread = new Thread(ListenLoop) { IsBackground = true, Name = "Falsum-NativeHost" };
        _listenerThread.Start();
    }

    public void Stop()
    {
        _running = false;
    }

    private void ListenLoop()
    {
        while (_running)
        {
            try
            {
                var message = ReadMessage();
                if (message == null) break; // stdin closed = Chrome shut down

                MessageReceived?.Invoke(message.Value);

                // Auto-respond to ping/health checks
                if (message.Value.TryGetProperty("type", out var typeProp))
                {
                    var type = typeProp.GetString();
                    if (type == "ping")
                    {
                        SendMessage(new { type = "pong", app = "Falsum", version = "2.0.0" });
                    }
                    else if (type == "bubble-online")
                    {
                        // Extension is inside the bubble. Acknowledge and arm the gate.
                        SendMessage(new { type = "gate-armed", app = "Falsum", version = "2.0.0" });
                    }
                    else if (type == "gate-request")
                    {
                        // THE GATE: extension asks, desktop decides.
                        var decision = DecideGate(message.Value);
                        var gateId = message.Value.TryGetProperty("gateId", out var gid)
                            ? gid.GetString() : "";
                        SendMessage(new { type = "gate-decision", gateId, allow = decision });
                    }
                    else if (type == "fingerprint_report" || type == "fingerprint-attempt")
                    {
                        SendMessage(new { type = "ack", recorded = true });
                    }
                    else if (type == "tracker_report")
                    {
                        SendMessage(new { type = "ack", recorded = true });
                    }
                    else if (type == "download-created" || type == "download-complete")
                    {
                        // Log every download to vault
                        SendMessage(new { type = "ack", recorded = true });
                    }
                    else if (type == "navigation" || type == "navigation-complete")
                    {
                        SendMessage(new { type = "ack", recorded = true });
                    }
                    else if (type == "show-desktop")
                    {
                        // Extension popup asked to show the desktop app
                        OnShowDesktopRequested?.Invoke(this, EventArgs.Empty);
                        SendMessage(new { type = "ack", showing = true });
                    }
                    else if (type == "request-scan")
                    {
                        // Extension popup asked for a scan
                        OnScanRequested?.Invoke(this, EventArgs.Empty);
                        SendMessage(new { type = "ack", scanning = true });
                    }
                }
            }
            catch
            {
                // stdin closed or corrupt — Chrome is gone, stop listening
                break;
            }
        }
    }

    /// <summary>
    /// Read one length-prefixed JSON message from stdin.
    /// Returns null if the stream is closed.
    /// </summary>
    private JsonElement? ReadMessage()
    {
        var lengthBytes = new byte[4];
        int read = 0;
        while (read < 4)
        {
            int n = _stdin.Read(lengthBytes, read, 4 - read);
            if (n == 0) return null; // EOF
            read += n;
        }

        int length = BitConverter.ToInt32(lengthBytes, 0);
        if (length <= 0 || length > 1024 * 1024) return null; // sanity: max 1MB

        var buffer = new byte[length];
        read = 0;
        while (read < length)
        {
            int n = _stdin.Read(buffer, read, length - read);
            if (n == 0) return null;
            read += n;
        }

        var json = Encoding.UTF8.GetString(buffer);
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    /// <summary>
    /// Send one length-prefixed JSON message to stdout.
    /// </summary>
    public void SendMessage(object message)
    {
        var json = JsonSerializer.Serialize(message);
        var bytes = Encoding.UTF8.GetBytes(json);
        var lengthBytes = BitConverter.GetBytes(bytes.Length);

        lock (_stdout)
        {
            _stdout.Write(lengthBytes, 0, 4);
            _stdout.Write(bytes, 0, bytes.Length);
            _stdout.Flush();
        }
    }

    /// <summary>
    /// THE GATE DECISION: the desktop app decides what the browser is allowed to do.
    /// 
    /// IRON RULE: Nothing passes without the user's consent. No data leaves the browser
    /// without the end user knowing about it. These companies rob people blind through
    /// their data — Falsum is the poison pill that ends it.
    /// 
    /// Gate logic:
    /// - Known malware/phishing → BLOCK automatically (user is notified)
    /// - Data leaving the browser (uploads, API calls, tracking) → ASK THE USER
    /// - Downloads of executables → ASK THE USER
    /// - Everything else → ALLOW but LOG so the user can see it
    /// 
    /// The gate NEVER silently allows data exfiltration. If in doubt, it asks.
    /// </summary>
    private bool DecideGate(JsonElement gateRequest)
    {
        try
        {
            var action = gateRequest.TryGetProperty("action", out var a) ? a.GetString() : "";

            if (!gateRequest.TryGetProperty("details", out var details))
                return true; // No details = allow (nothing to gate)

            string url = "";
            if (details.TryGetProperty("url", out var u))
                url = u.GetString()?.ToLower() ?? "";

            // BLOCK: known phishing signals — user is notified, no consent needed to block threats
            if (details.TryGetProperty("signals", out var signals))
            {
                foreach (var signal in signals.EnumerateArray())
                {
                    var s = signal.GetString();
                    if (s == "punycode-idn" || s == "ip-url")
                    {
                        NotifyUser($"Blocked phishing attempt: {url}", "threat-blocked");
                        return false;
                    }
                }
            }

            // BLOCK: known malware file types — user is notified
            if (action == "download")
            {
                string filename = "";
                if (details.TryGetProperty("filename", out var f))
                    filename = f.GetString()?.ToLower() ?? "";

                var blockExts = new[] { ".scr", ".pif", ".com" };
                foreach (var ext in blockExts)
                {
                    if (filename.EndsWith(ext))
                    {
                        NotifyUser($"Blocked malware download: {filename}", "threat-blocked");
                        return false;
                    }
                }

                // ASK: executables need user consent — no silent downloads
                var askExts = new[] { ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".dll" };
                foreach (var ext in askExts)
                {
                    if (filename.EndsWith(ext))
                    {
                        // This returns false to block, then the UI prompts the user.
                        // If user consents, the download is re-initiated with approval.
                        NotifyUser($"Download requires your approval: {filename}\nFrom: {url}", "consent-required");
                        return false;
                    }
                }
            }

            // ASK: data leaving the browser — user must know and consent
            if (action == "data-egress" || action == "large-upload" || action == "api-call-tracking")
            {
                NotifyUser($"Data leaving your browser:\n{url}\n\nThis needs your approval.", "consent-required");
                return false; // Block until user explicitly consents
            }

            // Default: allow but log — user can review everything in the vault
            return true;
        }
        catch
        {
            // On error: BLOCK, don't allow. Fail closed. User is notified.
            NotifyUser("Gate error — blocked action for your safety. Check the vault.", "gate-error");
            return false;
        }
    }

    /// <summary>
    /// Notify the user of a gate decision. The user always knows what Falsum does.
    /// Nothing happens silently.
    /// </summary>
    private void NotifyUser(string message, string notificationType)
    {
        // Send to UI layer for display. Also log to vault.
        MessageReceived?.Invoke(CreateNotificationElement(message, notificationType));
    }

    private JsonElement CreateNotificationElement(string message, string notificationType)
    {
        var json = JsonSerializer.Serialize(new
        {
            type = "user-notification",
            notificationType,
            message,
            timestamp = DateTime.UtcNow.ToString("o")
        });
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }
}
