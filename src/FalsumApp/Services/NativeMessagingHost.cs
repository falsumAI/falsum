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
                        SendMessage(new { type = "pong", app = "Falsum", version = "1.0.0" });
                    }
                    else if (type == "fingerprint_report")
                    {
                        // Log the fingerprinting attempt to the evidence vault
                        // The extension already blocked/spoofed it; we record it.
                        SendMessage(new { type = "ack", recorded = true });
                    }
                    else if (type == "tracker_report")
                    {
                        SendMessage(new { type = "ack", recorded = true });
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
}
