using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.Text.Json;

namespace FalsumApp.Services;

/// <summary>
/// Native Messaging Host — the app side of the extension bridge.
///
/// HOW IT RUNS: Chrome/Edge launches Falsum.exe directly (the native host
/// manifest points at the .exe). App.xaml.cs sees the chrome-extension://
/// argument and calls RunLoop() with no window. This process lives only as
/// long as the browser keeps the pipe open.
///
/// PROTOCOL (Chrome native messaging): 4-byte little-endian length prefix
/// + UTF-8 JSON, both directions, over stdin/stdout.
///
/// GATE MODEL — the iron rules:
/// 1. Known threats (phishing signals, malware file types) → BLOCK in-process,
///    user is notified. No consent needed to block an attack.
/// 2. Data leaving the browser / executables → ASK the desktop UI through the
///    named pipe "FalsumGate". The user decides. Nothing passes silently.
/// 3. If the desktop UI isn't running or doesn't answer in time → BLOCK.
///    Fail closed, always. The user is notified and can see it in the feed.
/// 4. Everything is appended to %LOCALAPPDATA%\Falsum\bridge\events.jsonl so
///    the desktop app shows the browser and the app seeing each other.
///
/// The extension side mirrors this in browser-extension/background.js.
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

    private const string PipeName = "FalsumGate";
    private static readonly string BridgeDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Falsum", "bridge");
    private static readonly string EventsPath = Path.Combine(BridgeDir, "events.jsonl");

    public NativeMessagingHost()
    {
        _stdin = Console.OpenStandardInput();
        _stdout = Console.OpenStandardOutput();
    }

    /// <summary>
    /// Blocking message loop for native-host mode (called by App.xaml.cs).
    /// Returns when Chrome closes stdin.
    /// </summary>
    public void RunLoop()
    {
        _running = true;
        ListenLoop();
    }

    /// <summary>
    /// Start listening on a background thread (legacy entry; the GUI no longer
    /// uses this — Chrome launches a separate host process).
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
        LogBridge("host", "Native host started. Browser is inside the bubble.");
        while (_running)
        {
            try
            {
                var message = ReadMessage();
                if (message == null) break; // stdin closed = Chrome shut down

                MessageReceived?.Invoke(message.Value);
                HandleMessage(message.Value);
            }
            catch
            {
                // stdin closed or corrupt — Chrome is gone, stop listening
                break;
            }
        }
        LogBridge("host", "Native host stopped. Browser closed the pipe.");
    }

    private void HandleMessage(JsonElement message)
    {
        if (!message.TryGetProperty("type", out var typeProp)) return;
        var type = typeProp.GetString();

        switch (type)
        {
            case "ping":
                SendMessage(new { type = "pong", app = "Falsum", version = "2.0.0" });
                break;

            case "bubble-online":
                // Extension is inside the bubble. Acknowledge and arm the gate.
                LogBridge("gate", "Browser bubble connected. Gate armed.");
                SendMessage(new { type = "gate-armed", app = "Falsum", version = "2.0.0" });
                break;

            case "gate-request":
                // THE GATE: extension asks, desktop decides.
                var gateId = message.TryGetProperty("gateId", out var gid) ? gid.GetString() ?? "" : "";
                var action = message.TryGetProperty("action", out var a) ? a.GetString() ?? "" : "";
                var decision = DecideGate(message);
                LogBridge("gate", $"Gate {(decision ? "ALLOWED" : "BLOCKED")}: {action} {ShortDetail(message)}");
                SendMessage(new { type = "gate-decision", gateId, allow = decision });
                break;

            case "navigation-gate-block":
                // Extension couldn't cancel the navigation itself — push the block
                // back so the content script blocks the page on load.
                var blockUrl = message.TryGetProperty("url", out var bu) ? bu.GetString() ?? "" : "";
                var host = HostOf(blockUrl);
                if (!string.IsNullOrEmpty(host))
                {
                    LogBridge("threat", $"Pushed page block to browser: {host}");
                    SendMessage(new { type = "block-url", pattern = host });
                }
                break;

            case "gate-bypassed-block":
                // Extension blocked something while the desktop was unreachable.
                LogBridge("gate", $"Browser blocked while gate unreachable: {ShortDetail(message)}");
                break;

            case "gate-timeout-block":
                LogBridge("gate", $"Browser blocked on gate timeout: {ShortDetail(message)}");
                break;

            case "download-blocked":
                LogBridge("threat", $"Download blocked by gate: {ShortDetail(message)}");
                break;

            case "navigation-blocked-local":
                LogBridge("threat", $"Navigation blocked (local blocklist): {ShortDetail(message)}");
                break;

            case "large-upload":
                {
                    var url = message.TryGetProperty("url", out var lu) ? lu.GetString() ?? "" : "";
                    var size = message.TryGetProperty("bodySize", out var bs) ? bs.GetInt64() : 0;
                    LogBridge("data", $"Large upload seen: {size} bytes → {url}");
                    break;
                }

            case "user-notification":
                // Pass-through: already logged by NotifyUser.
                break;

            // Fire-and-forget telemetry — logged to the bridge feed, no reply needed.
            case "fingerprint_report":
            case "fingerprint-attempt":
            case "tracker_report":
            case "tracking-cookie":
            case "download-created":
            case "download-complete":
            case "navigation":
            case "navigation-complete":
            case "network-request":
            case "bubble-heartbeat":
            case "shield-armed":
                LogBridge("browser", $"{type}: {ShortDetail(message)}");
                break;

            case "show-desktop":
                OnShowDesktopRequested?.Invoke(this, EventArgs.Empty);
                SendMessage(new { type = "ack", showing = true });
                break;

            case "request-scan":
                OnScanRequested?.Invoke(this, EventArgs.Empty);
                SendMessage(new { type = "ack", scanning = true });
                break;

            default:
                LogBridge("browser", $"Unknown message type: {type}");
                break;
        }
    }

    /// <summary>
    /// THE GATE DECISION.
    ///
    /// IRON RULE: Nothing passes without the user's consent. No data leaves the
    /// browser without the end user knowing about it.
    ///
    /// - Known phishing signals / malware types → BLOCK in-process, notify user.
    /// - Executables, data egress → ASK the desktop UI via named pipe.
    /// - UI unreachable or silent → BLOCK (fail closed), notify + log.
    /// - Everything else → ALLOW but LOG so the user can review it.
    /// </summary>
    private bool DecideGate(JsonElement gateRequest)
    {
        try
        {
            var action = gateRequest.TryGetProperty("action", out var a) ? a.GetString() ?? "" : "";
            var gateId = gateRequest.TryGetProperty("gateId", out var g) ? g.GetString() ?? "" : "";

            if (!gateRequest.TryGetProperty("details", out var details))
                return true; // No details = nothing to gate, allow.

            string url = "";
            if (details.TryGetProperty("url", out var u))
                url = u.GetString()?.ToLower() ?? "";

            // BLOCK: known phishing signals — no consent needed to block an attack.
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

            // BLOCK: known malware file types.
            if (action == "download")
            {
                string filename = "";
                if (details.TryGetProperty("filename", out var f))
                    filename = f.GetString()?.ToLower() ?? "";

                foreach (var ext in new[] { ".scr", ".pif", ".com" })
                {
                    if (filename.EndsWith(ext, StringComparison.Ordinal))
                    {
                        NotifyUser($"Blocked malware download: {filename}", "threat-blocked");
                        return false;
                    }
                }

                // ASK: executables need the user's explicit consent.
                foreach (var ext in new[] { ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".dll", ".lnk" })
                {
                    if (filename.EndsWith(ext, StringComparison.Ordinal))
                        return AskUser(gateId, action, details,
                            $"A download needs your approval:\n{filename}\nFrom: {url}\n\nAllow this download?");
                }
            }

            // ASK: data leaving the browser — the user must know and consent.
            if (action == "data-egress" || action == "large-upload" || action == "api-call-tracking")
            {
                return AskUser(gateId, action, details,
                    $"Data is leaving your browser:\n{url}\n\nFalsum blocked it until you approve. Allow?");
            }

            // ASK: suspicious navigation the heuristics flagged.
            if (action == "navigation")
            {
                if (details.TryGetProperty("signals", out var navSignals) && navSignals.GetArrayLength() > 0)
                {
                    return AskUser(gateId, action, details,
                        $"This page looks suspicious:\n{url}\n\nAllow it to load?");
                }
                return true;
            }

            // Default: allow but log — the user reviews everything in the feed.
            return true;
        }
        catch
        {
            // On error: BLOCK, don't allow. Fail closed.
            NotifyUser("Gate error — blocked an action for your safety. Check the browser feed.", "gate-error");
            return false;
        }
    }

    /// <summary>
    /// Ask the desktop UI for a consent decision over the named pipe.
    /// Returns false (block) if the UI isn't running or doesn't answer in time.
    /// The whole exchange is bounded by a 4-second cancellation token — the
    /// extension times out at 5s, and a stuck read must NEVER hang the host.
    /// </summary>
    private bool AskUser(string gateId, string action, JsonElement details, string prompt)
    {
        NotifyUser(prompt, "consent-required");

        try
        {
            bool? answer = AskUserAsync(gateId, action, prompt, details).GetAwaiter().GetResult();
            if (answer.HasValue)
            {
                LogBridge("gate", $"User {(answer.Value ? "ALLOWED" : "BLOCKED")}: {action}");
                return answer.Value;
            }
        }
        catch
        {
            // Pipe missing, broken, or timed out = desktop UI not answering. Fail closed.
        }

        LogBridge("gate", $"No answer from desktop UI — BLOCKED: {action}");
        return false;
    }

    private async Task<bool?> AskUserAsync(string gateId, string action, string prompt, JsonElement details)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var token = cts.Token;

        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut);
        await pipe.ConnectAsync(token);

        var request = JsonSerializer.Serialize(new
        {
            kind = "gate",
            gateId,
            action,
            prompt,
            details = details.GetRawText()
        });
        await WritePipeMessageAsync(pipe, request, token);

        var response = await ReadPipeMessageAsync(pipe, token);
        if (response == null) return null;

        using var doc = JsonDocument.Parse(response);
        if (doc.RootElement.TryGetProperty("allow", out var allowProp))
            return allowProp.GetBoolean();
        return null;
    }

    private static async Task WritePipeMessageAsync(PipeStream pipe, string json, CancellationToken token)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var len = BitConverter.GetBytes(bytes.Length);
        await pipe.WriteAsync(len, 0, 4, token);
        await pipe.WriteAsync(bytes, 0, bytes.Length, token);
        await pipe.FlushAsync(token);
    }

    private static async Task<string?> ReadPipeMessageAsync(PipeStream pipe, CancellationToken token)
    {
        var lenBytes = new byte[4];
        int read = 0;
        while (read < 4)
        {
            int n = await pipe.ReadAsync(lenBytes, read, 4 - read, token);
            if (n == 0) return null;
            read += n;
        }

        int length = BitConverter.ToInt32(lenBytes, 0);
        if (length <= 0 || length > 1024 * 1024) return null;

        var buffer = new byte[length];
        read = 0;
        while (read < length)
        {
            int n = await pipe.ReadAsync(buffer, read, length - read, token);
            if (n == 0) return null;
            read += n;
        }
        return Encoding.UTF8.GetString(buffer);
    }

    /// <summary>
    /// Notify the user. In host mode there is no window, so the notification
    /// goes to the bridge feed (the desktop app shows it) AND back to the
    /// extension, which raises a browser notification. The user always knows.
    /// </summary>
    private void NotifyUser(string message, string notificationType)
    {
        LogBridge("notify", $"[{notificationType}] {message}");
        SendMessage(new
        {
            type = "user-notification",
            notificationType,
            message,
            timestamp = DateTime.UtcNow.ToString("o")
        });
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

    /// <summary>
    /// Append one event to the bridge feed the desktop app displays.
    /// Best-effort: never let logging break the gate.
    /// </summary>
    private static void LogBridge(string category, string text)
    {
        try
        {
            Directory.CreateDirectory(BridgeDir);
            var line = JsonSerializer.Serialize(new
            {
                at = DateTime.Now.ToString("HH:mm:ss"),
                category,
                text = text.Length > 300 ? text[..300] : text
            });
            lock (typeof(NativeMessagingHost))
            {
                File.AppendAllText(EventsPath, line + Environment.NewLine, Encoding.UTF8);
            }
            // Trim the feed so it never grows forever (keep last ~500 events).
            try
            {
                var lines = File.ReadAllLines(EventsPath);
                if (lines.Length > 500)
                    File.WriteAllLines(EventsPath, lines[^500..], Encoding.UTF8);
            }
            catch { }
        }
        catch { }
    }

    private static string ShortDetail(JsonElement message)
    {
        try
        {
            if (message.TryGetProperty("url", out var u))
                return u.GetString() ?? "";
            if (message.TryGetProperty("details", out var d) && d.TryGetProperty("url", out var du))
                return du.GetString() ?? "";
            if (message.TryGetProperty("filename", out var f))
                return f.GetString() ?? "";
            if (message.TryGetProperty("details", out var d2) && d2.TryGetProperty("filename", out var df))
                return df.GetString() ?? "";
        }
        catch { }
        return "";
    }

    private static string HostOf(string url)
    {
        try
        {
            return new Uri(url).Host.ToLowerInvariant();
        }
        catch { return ""; }
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
}
