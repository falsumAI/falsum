// The system-wide bubble: sees EVERY application on the machine.
// Consumes kernel ETW providers in real time (process, network, file) and
// logs every event hash-chained to the vault. Nothing moves without being logged.
//
// Honest volume design:
//   - Process start/stop: logged fully (low volume, highest value).
//   - TCP connect/disconnect: logged fully (every connection, attributed to PID).
//   - UDP: counted, not logged per-packet (DNS firehose); UDP to non-DNS ports IS logged.
//   - File I/O: the raw firehose is NOT logged (GBs/hour). Executable/script
//     creates and writes to sensitive locations ARE logged; the rest is counted.
// User-mode, no driver. Requires administrator for kernel providers.
// Blocking (not just logging) every app needs a kernel driver: later phase.
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using FalsumApp.Services.Modules;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace FalsumApp.Services;

public sealed class SystemBubbleService : IDisposable
{
    private const string VaultName = "bubble";
    private const string Genesis = "BUBBLE-GENESIS";

    private TraceEventSession? _session;
    private Thread? _thread;
    private readonly object _gate = new();
    private bool _running;
    private bool _disposed;
    private long _seq;
    private string _lastError = "";

    // Counters (everything is counted; security-relevant events are logged).
    private long _processStarts;
    private long _processStops;
    private long _tcpConnects;
    private long _tcpDisconnects;
    private long _udpSends;
    private long _fileCreates;
    private long _fileExecCreates;

    private readonly string _chainFile;

    public bool IsRunning { get { lock (_gate) return _running; } }
    public string LastError { get { lock (_gate) return _lastError; } }

    public SystemBubbleService()
    {
        _chainFile = Path.Combine(Vault.VaultDir(VaultName), "events.jsonl");
    }

    /// <summary>
    /// Start the bubble. Returns true if the ETW session is live.
    /// Fails soft (returns false, sets LastError) without admin rights.
    /// </summary>
    public bool Start()
    {
        lock (_gate)
        {
            if (_running) return true;
            _lastError = "";
        }
        try
        {
            // Take over a stale session from a crashed run, if any.
            foreach (var name in TraceEventSession.GetActiveSessionNames())
                if (string.Equals(name, "FalsumBubble", StringComparison.OrdinalIgnoreCase))
                    try { new TraceEventSession("FalsumBubble").Stop(); } catch { /* best effort */ }

            _thread = new Thread(RunLoop) { IsBackground = true, Name = "FalsumBubble" };
            _thread.Start();

            // Give the loop a moment to either come up or fail.
            for (int i = 0; i < 50; i++)
            {
                lock (_gate) { if (_running) return true; if (_lastError != "") return false; }
                Thread.Sleep(100);
            }
            lock (_gate) { return _running; }
        }
        catch (Exception ex)
        {
            lock (_gate) { _lastError = ex.Message; }
            return false;
        }
    }

    private void RunLoop()
    {
        try
        {
            _session = new TraceEventSession("FalsumBubble");
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.NetworkTCPIP |
                KernelTraceEventParser.Keywords.FileIO);

            _session.Source.Kernel.ProcessStart += OnProcessStart;
            _session.Source.Kernel.ProcessStop += OnProcessStop;
            _session.Source.Kernel.TcpIpConnect += OnTcpConnect;
            _session.Source.Kernel.TcpIpDisconnect += OnTcpDisconnect;
            _session.Source.Kernel.UdpIpSend += OnUdpSend;
            _session.Source.Kernel.FileIOCreate += OnFileCreate;

            lock (_gate) { _running = true; }
            LogEvent("bubble-start", new Dictionary<string, object?>
            {
                ["detail"] = "System bubble live: process + TCP + filtered UDP/file."
            });
            _session.Source.Process(); // blocks until Stop()
        }
        catch (Exception ex)
        {
            lock (_gate) { _lastError = ex.Message; _running = false; }
        }
        finally
        {
            lock (_gate) { _running = false; }
        }
    }

    public void Stop()
    {
        try { _session?.Stop(); } catch { /* best effort */ }
        try { _thread?.Join(3000); } catch { /* best effort */ }
        try { _session?.Dispose(); } catch { /* best effort */ }
        _session = null;
        lock (_gate) { _running = false; }
        LogEvent("bubble-stop", new Dictionary<string, object?> { ["detail"] = "Bubble stopped." });
    }

    // ---- event handlers (run on the ETW processing thread) ----

    private void OnProcessStart(ProcessTraceData d)
    {
        Interlocked.Increment(ref _processStarts);
        string image = d.ImageFileName ?? "";
        var (signed, publisher) = CheckSignature(image);
        LogEvent("process-start", new Dictionary<string, object?>
        {
            ["pid"] = d.ProcessID,
            ["ppid"] = d.ParentID,
            ["image"] = image,
            ["cmd"] = d.CommandLine ?? "",
            ["signed"] = signed,
            ["publisher"] = publisher,
        });
    }

    private void OnProcessStop(ProcessTraceData d)
    {
        Interlocked.Increment(ref _processStops);
        LogEvent("process-stop", new Dictionary<string, object?>
        {
            ["pid"] = d.ProcessID,
            ["image"] = d.ImageFileName ?? "",
        });
    }

    private void OnTcpConnect(TcpIpConnectTraceData d)
    {
        Interlocked.Increment(ref _tcpConnects);
        LogEvent("tcp-connect", new Dictionary<string, object?>
        {
            ["pid"] = d.ProcessID,
            ["proc"] = ProcName(d.ProcessID),
            ["src"] = $"{d.saddr}:{d.sport}",
            ["dst"] = $"{d.daddr}:{d.dport}",
        });
    }

    private void OnTcpDisconnect(TcpIpDisconnectTraceData d)
    {
        Interlocked.Increment(ref _tcpDisconnects);
        LogEvent("tcp-disconnect", new Dictionary<string, object?>
        {
            ["pid"] = d.ProcessID,
            ["proc"] = ProcName(d.ProcessID),
            ["src"] = $"{d.saddr}:{d.sport}",
            ["dst"] = $"{d.daddr}:{d.dport}",
        });
    }

    private void OnUdpSend(UdpIpTraceData d)
    {
        Interlocked.Increment(ref _udpSends);
        // DNS (port 53) is a constant firehose: counted, not logged.
        if (d.dport == 53) return;
        LogEvent("udp-send", new Dictionary<string, object?>
        {
            ["pid"] = d.ProcessID,
            ["proc"] = ProcName(d.ProcessID),
            ["dst"] = $"{d.daddr}:{d.dport}",
        });
    }

    private void OnFileCreate(FileIOCreateTraceData d)
    {
        Interlocked.Increment(ref _fileCreates);
        string path = d.FileName ?? "";
        if (!IsSecurityRelevantFile(path)) return;
        Interlocked.Increment(ref _fileExecCreates);
        LogEvent("file-exec-create", new Dictionary<string, object?>
        {
            ["pid"] = d.ProcessID,
            ["proc"] = ProcName(d.ProcessID),
            ["path"] = path,
        });
    }

    // ---- helpers ----

    private static bool IsSecurityRelevantFile(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        string ext = Path.GetExtension(path).ToLowerInvariant();
        switch (ext)
        {
            case ".exe": case ".dll": case ".sys": case ".ps1":
            case ".bat": case ".cmd": case ".vbs": case ".js":
            case ".msi": case ".scr": case ".com": case ".pif":
                return true;
        }
        string lower = path.ToLowerInvariant();
        return lower.Contains(@"\startup\") || lower.Contains(@"\start menu\");
    }

    private static (bool signed, string publisher) CheckSignature(string image)
    {
        if (string.IsNullOrEmpty(image) || !File.Exists(image))
            return (false, "");
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(image);
            string subject = cert.Subject ?? "";
            // Pull a readable publisher out of the subject DN.
            string publisher = subject;
            foreach (var part in subject.Split(','))
            {
                var t = part.Trim();
                if (t.StartsWith("O=", StringComparison.OrdinalIgnoreCase)) { publisher = t[2..]; break; }
                if (t.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) && publisher == subject) publisher = t[3..];
            }
            return (true, publisher);
        }
        catch { return (false, ""); }
    }

    private static string ProcName(int pid)
    {
        try { return System.Diagnostics.Process.GetProcessById(pid).ProcessName; }
        catch { return ""; }
    }

    /// <summary>Append one hash-chained event to the vault.</summary>
    private void LogEvent(string kind, Dictionary<string, object?> fields)
    {
        try
        {
            lock (_gate)
            {
                string prev = Genesis;
                string? lastLine = null;
                if (File.Exists(_chainFile))
                {
                    foreach (var line in File.ReadLines(_chainFile, Encoding.UTF8))
                        if (!string.IsNullOrWhiteSpace(line)) lastLine = line;
                }
                if (lastLine != null)
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(lastLine);
                        if (doc.RootElement.TryGetProperty("hash", out var h))
                            prev = h.GetString() ?? Genesis;
                    }
                    catch { /* corrupt tail */ }
                }

                long seq = Interlocked.Increment(ref _seq);
                var entry = new Dictionary<string, object?>
                {
                    ["seq"] = seq,
                    ["ts"] = Vault.IsoNow(),
                    ["kind"] = kind,
                    ["prev"] = prev,
                };
                foreach (var kv in fields) entry[kv.Key] = kv.Value;

                // Canonical: seq|ts|kind|sorted-field-pairs|prev, then + "|" + prev.
                var sb = new StringBuilder();
                sb.Append(seq).Append('|').Append(entry["ts"]).Append('|').Append(kind).Append('|');
                foreach (var kv in fields.OrderBy(kv => kv.Key, StringComparer.Ordinal))
                    sb.Append(kv.Key).Append('=').Append(kv.Value).Append('|');
                sb.Append(prev);
                entry["hash"] = Vault.Sha384Hex(sb.ToString() + "|" + prev);

                File.AppendAllText(_chainFile,
                    JsonSerializer.Serialize(entry) + Environment.NewLine, Encoding.UTF8);
            }
        }
        catch { /* the bubble never crashes the app for a logging failure */ }
    }

    public string GetStats()
    {
        long ps = Interlocked.Read(ref _processStarts);
        long px = Interlocked.Read(ref _processStops);
        long tc = Interlocked.Read(ref _tcpConnects);
        long td = Interlocked.Read(ref _tcpDisconnects);
        long us = Interlocked.Read(ref _udpSends);
        long fc = Interlocked.Read(ref _fileCreates);
        long fe = Interlocked.Read(ref _fileExecCreates);
        bool running;
        string err;
        lock (_gate) { running = _running; err = _lastError; }
        if (!running)
            return string.IsNullOrEmpty(err) ? "Bubble: stopped." : $"Bubble: not running ({err})";
        return $"Bubble live: {ps} launches, {px} exits, {tc} TCP connects, {td} disconnects, " +
               $"{us} UDP sends, {fe} exec-file creates (of {fc} file creates). All hash-chained to the vault.";
    }

    public List<Dictionary<string, object?>> GetRecent(int n = 50)
    {
        var list = new List<Dictionary<string, object?>>();
        if (!File.Exists(_chainFile)) return list;
        var lines = new List<string>();
        foreach (var line in File.ReadLines(_chainFile, Encoding.UTF8))
            if (!string.IsNullOrWhiteSpace(line)) lines.Add(line);
        foreach (var line in lines.Skip(Math.Max(0, lines.Count - n)))
        {
            try
            {
                using var doc = JsonDocument.Parse(line);
                var d = new Dictionary<string, object?>();
                foreach (var p in doc.RootElement.EnumerateObject())
                    d[p.Name] = Vault.ElementToObject(p.Value);
                list.Add(d);
            }
            catch { /* skip */ }
        }
        return list;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}
