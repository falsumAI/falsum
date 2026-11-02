using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Text;
using System.Text.Json;
using System.Windows;

namespace FalsumApp.Services;

/// <summary>
/// GatePipeServer — the desktop UI side of the consent gate.
///
/// The native host (Falsum.exe launched by Chrome, no window) cannot ask the
/// user anything itself. When it needs consent, it connects to this named
/// pipe ("FalsumGate") and waits for the user's answer.
///
/// This server pops a plain-language Yes/No dialog. The dialog is a standard
/// MessageBox, which screen readers announce — a blind user gets the same
/// question, in words, as everyone else.
///
/// If the user answers in time, their answer goes back to the host, which
/// forwards it to the browser extension. If anything fails, the host blocks
/// (fail closed) — the dialog timing out never lets anything through.
/// </summary>
public class GatePipeServer
{
    private const string PipeName = "FalsumGate";
    private volatile bool _running;
    private Thread? _serverThread;
    private readonly Window _owner;

    public event Action<string>? GateDecisionMade; // "ALLOWED: ..." / "BLOCKED: ..." for the feed

    public GatePipeServer(Window owner)
    {
        _owner = owner;
    }

    public void Start()
    {
        _running = true;
        _serverThread = new Thread(ServerLoop) { IsBackground = true, Name = "FalsumGatePipe" };
        _serverThread.Start();
    }

    public void Stop()
    {
        _running = false;
    }

    private void ServerLoop()
    {
        while (_running)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = new NamedPipeServerStream(
                    PipeName, PipeDirection.InOut, 4,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                server.WaitForConnection();

                var requestJson = ReadPipeMessage(server);
                if (requestJson == null) continue;

                bool allow = false;
                string action = "";
                try
                {
                    using var doc = JsonDocument.Parse(requestJson);
                    var root = doc.RootElement;
                    action = root.TryGetProperty("action", out var ap) ? ap.GetString() ?? "" : "";
                    var prompt = root.TryGetProperty("prompt", out var pp) ? pp.GetString() ?? "Allow this?" : "Allow this?";

                    // Ask the user on the UI thread. MessageBox is announced by
                    // screen readers — accessible by design.
                    _owner.Dispatcher.Invoke(() =>
                    {
                        var result = MessageBox.Show(
                            _owner,
                            prompt,
                            "Falsum — your approval needed",
                            MessageBoxButton.YesNo,
                            MessageBoxImage.Warning,
                            MessageBoxResult.No);
                        allow = result == MessageBoxResult.Yes;
                    });
                }
                catch
                {
                    allow = false; // Any failure = block.
                }

                var response = JsonSerializer.Serialize(new { allow });
                WritePipeMessage(server, response);
                GateDecisionMade?.Invoke($"{(allow ? "ALLOWED" : "BLOCKED")}: {action} (your answer)");
            }
            catch
            {
                // Pipe errors are transient — keep serving.
                Thread.Sleep(250);
            }
            finally
            {
                try
                {
                    if (server?.IsConnected == true) server.Disconnect();
                    server?.Dispose();
                }
                catch { }
            }
        }
    }

    private static void WritePipeMessage(PipeStream pipe, string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var len = BitConverter.GetBytes(bytes.Length);
        pipe.Write(len, 0, 4);
        pipe.Write(bytes, 0, bytes.Length);
        pipe.Flush();
        try { pipe.WaitForPipeDrain(); } catch { }
    }

    private static string? ReadPipeMessage(PipeStream pipe)
    {
        try
        {
            var lenBytes = new byte[4];
            int read = 0;
            while (read < 4)
            {
                int n = pipe.Read(lenBytes, read, 4 - read);
                if (n == 0) return null;
                read += n;
            }
            int length = BitConverter.ToInt32(lenBytes, 0);
            if (length <= 0 || length > 1024 * 1024) return null;
            var buffer = new byte[length];
            read = 0;
            while (read < length)
            {
                int n = pipe.Read(buffer, read, length - read);
                if (n == 0) return null;
                read += n;
            }
            return Encoding.UTF8.GetString(buffer);
        }
        catch { return null; }
    }
}
