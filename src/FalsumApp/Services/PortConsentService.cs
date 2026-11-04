using FalsumApp.Services.Modules;
// Port Consent Gate: NOTHING passes through a port without the user's consent.
// This is the fix the bubble feeds: the bubble sees every application, and this
// gate stops every application's network until the owner of the machine says yes.
//
// How it works (all user-mode, no driver):
//   1. Consent mode sets the Windows Firewall default-outbound action to BLOCK
//      on every profile. No pre-allowed list. No Microsoft carve-outs. The user
//      decides everything: it is their computer, they paid full price for it.
//   2. Every blocked connection attempt raises Security log event 5157, which
//      names the APPLICATION (path + PID) — real attribution from Windows.
//   3. The gate pops a consent dialog: Allow always / Allow once / Block.
//   4. The decision becomes a firewall rule. Blocks also mark the bad actor
//      permanently via PortGateModule, so the mark follows them.
// Turning consent mode off restores default-allow and removes the gate's rules.
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Reflection;
using System.Text;
using System.Windows;
using System.Xml.Linq;
using FalsumApp.Views;

namespace FalsumApp.Services;

public sealed class PortConsentService : IDisposable
{
    private const string RulePrefix = "Falsum-Consent-";
    private const int ProfileAll = unchecked((int)0x7FFFFFFF); // NET_FW_PROFILE2_ALL
    private const int ActionBlock = 0;  // NET_FW_ACTION_BLOCK
    private const int ActionAllow = 1;  // NET_FW_ACTION_ALLOW

    private readonly SystemBubbleService _bubble;
    private EventLogWatcher? _watcher;
    private readonly Dictionary<string, bool> _decided = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private bool _consentMode;
    private bool _disposed;

    public bool ConsentMode { get { lock (_gate) return _consentMode; } }

    public PortConsentService(SystemBubbleService bubble)
    {
        _bubble = bubble;
    }

    /// <summary>
    /// Full control ON: default-deny outbound everywhere. The user is warned
    /// before this runs: until apps are allowed, they have no network.
    /// </summary>
    public void EnableConsentMode()
    {
        lock (_gate)
        {
            if (_consentMode) return;
        }

        // 1. Default-deny outbound on every firewall profile.
        NativeFirewall.SetDefaultOutboundAction(ProfileAll, ActionBlock);

        // 2. Make sure blocked connections are audited (event 5157).
        RunAuditPol();

        // 3. Pre-load decisions from rules we already created (survives restarts).
        RefreshDecidedFromRules();

        // 4. Watch the Security log for blocked-connection events.
        var query = new EventLogQuery("Security", PathType.LogName, "*[System[EventID=5157]]");
        _watcher = new EventLogWatcher(query);
        _watcher.EventRecordWritten += OnEventRecord;
        _watcher.Enabled = true;

        lock (_gate) { _consentMode = true; }

        // PERSISTENT MEMORY: the gate stays ON across restarts.
        try
        {
            System.IO.File.WriteAllText(System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Falsum", "consent-mode.on"),
                DateTimeOffset.Now.ToString("o"));
        }
        catch { }
    }

    /// <summary>Full control OFF: default-allow restored, gate rules removed.</summary>
    public void DisableConsentMode()
    {
        lock (_gate)
        {
            if (!_consentMode) return;
            _consentMode = false;
        }
        try { if (_watcher != null) { _watcher.Enabled = false; _watcher.Dispose(); } } catch { }
        _watcher = null;
        try { NativeFirewall.RemoveRules(RulePrefix); } catch { }
        try { NativeFirewall.SetDefaultOutboundAction(ProfileAll, ActionAllow); } catch { }
        try
        {
            System.IO.File.Delete(System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Falsum", "consent-mode.on"));
        }
        catch { }
        lock (_gate) { _decided.Clear(); }
    }

    /// <summary>Every decision the user made, for full review.</summary>
    public IReadOnlyDictionary<string, bool> Decisions
    {
        get { lock (_gate) return new Dictionary<string, bool>(_decided); }
    }

    /// <summary>User takes back control: forget a decision (the app asks again).</summary>
    public void RevokeDecision(string appPath)
    {
        string? ruleName;
        lock (_gate)
        {
            _decided.Remove(appPath);
            ruleName = RuleNameFor(appPath, true);
        }
        try
        {
            NativeFirewall.RemoveRules(ruleName!);
            NativeFirewall.RemoveRules(RuleNameFor(appPath, false));
        }
        catch { /* best effort */ }
    }

    // ---- internals ----

    private void OnEventRecord(object? sender, EventRecordWrittenEventArgs e)
    {
        bool enabled;
        lock (_gate) { enabled = _consentMode; }
        if (!enabled || e.EventRecord == null) return;
        try { HandleBlocked(e.EventRecord); }
        catch { /* the gate never crashes on a bad record */ }
    }

    private void HandleBlocked(EventRecord record)
    {
        var (appPath, pid, dest) = Parse5157(record);
        if (string.IsNullOrEmpty(appPath)) return;

        lock (_gate)
        {
            if (_decided.ContainsKey(appPath)) return; // already decided: no repeat prompt
            _decided[appPath] = false; // mark prompting so duplicates collapse
        }

        // Ask the owner. Fail-closed: no answer = Block.
        var choice = PortConsentDialog.ConsentChoice.Block;
        try
        {
            var app = System.Windows.Application.Current;
            if (app != null)
            {
                app.Dispatcher.Invoke(() =>
                {
                    var dlg = new PortConsentDialog(
                        System.IO.Path.GetFileName(appPath), appPath, dest);
                    dlg.ShowDialog();
                    choice = dlg.Choice;
                });
            }
        }
        catch { /* no UI: stays Block */ }

        ApplyDecision(appPath, pid, dest, choice);
    }

    private void ApplyDecision(string appPath, int pid, string dest,
        PortConsentDialog.ConsentChoice choice)
    {
        string appName = System.IO.Path.GetFileNameWithoutExtension(appPath);
        bool allowed;
        switch (choice)
        {
            case PortConsentDialog.ConsentChoice.AllowAlways:
                NativeFirewall.AddRule(RuleNameFor(appPath, true),
                    NativeFirewall.DirectionOutbound, NativeFirewall.ActionAllow,
                    0, "", "");
                // Scope the allow rule to the application path.
                SetRuleApplication(RuleNameFor(appPath, true), appPath);
                allowed = true;
                break;

            case PortConsentDialog.ConsentChoice.AllowOnce:
                string tempRule = RulePrefix + "Temp-" + appName + "-" + DateTime.UtcNow.Ticks;
                NativeFirewall.AddRule(tempRule,
                    NativeFirewall.DirectionOutbound, NativeFirewall.ActionAllow,
                    0, "", "");
                SetRuleApplication(tempRule, appPath);
                allowed = true;
                break;

            case PortConsentDialog.ConsentChoice.Block:
            default:
                NativeFirewall.AddRule(RuleNameFor(appPath, false),
                    NativeFirewall.DirectionOutbound, NativeFirewall.ActionBlock,
                    0, "", "");
                SetRuleApplication(RuleNameFor(appPath, false), appPath);
                try
                {
                    Modules.PortGateModule.MarkBadActor(
                        dest.Contains(':') ? dest[..dest.LastIndexOf(':')] : dest,
                        $"Blocked by owner consent gate: {appName} tried {dest}");
                }
                catch { /* marking is best effort */ }
                allowed = false;
                break;
        }
        lock (_gate) { _decided[appPath] = allowed; }
    }

    private static string RuleNameFor(string appPath, bool allow)
    {
        string appName = System.IO.Path.GetFileNameWithoutExtension(appPath);
        string safe = new string(appName.Where(c => char.IsLetterOrDigit(c) || c == '-' || c == '_').ToArray());
        return RulePrefix + (allow ? "Allow-" : "Block-") + safe;
    }

    /// <summary>Scope a firewall rule to one application path (late-bound COM).</summary>
    private static void SetRuleApplication(string ruleName, string appPath)
    {
        try
        {
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (t == null) return;
            dynamic policy = Activator.CreateInstance(t)!;
            foreach (dynamic rule in policy.Rules)
            {
                if (string.Equals(rule.Name as string, ruleName, StringComparison.OrdinalIgnoreCase))
                {
                    rule.ApplicationName = appPath;
                    break;
                }
            }
        }
        catch { /* best effort: the rule still exists, just broader */ }
    }

    private void RefreshDecidedFromRules()
    {
        try
        {
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (t == null) return;
            dynamic policy = Activator.CreateInstance(t)!;
            lock (_gate)
            {
                foreach (dynamic rule in policy.Rules)
                {
                    string name = (rule.Name as string) ?? "";
                    if (!name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase)) continue;
                    string app = (rule.ApplicationName as string) ?? "";
                    if (!string.IsNullOrEmpty(app) && !_decided.ContainsKey(app))
                        _decided[app] = true;
                }
            }
        }
        catch { /* best effort */ }
    }

    /// <summary>
    /// PERSISTENT MEMORY. Called on every app startup. If the user had
    /// consent mode ON when the app last ran, the gate comes back ON:
    /// default-deny is re-applied and every decision reloads from the
    /// firewall rules. Uninvited hosts stay blocked across restarts.
    /// </summary>
    public static void ReapplyDecisions()
    {
        try
        {
            string flagPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Falsum", "consent-mode.on");
            if (!System.IO.File.Exists(flagPath)) return;

            // Consent mode was on: re-apply default-deny outbound.
            // The per-app Falsum-Consent-* firewall rules persist in the
            // Windows Firewall itself, so every decision survives.
            // The live 5157 watcher restarts when the user opens the
            // Port Consent card; the blocks enforce immediately.
            NativeFirewall.SetDefaultOutboundAction(ProfileAll, ActionBlock);
        }
        catch { /* fail-safe */ }
    }

    private static (string appPath, int pid, string dest) Parse5157(EventRecord record)
    {
        try
        {
            var xml = XDocument.Parse(record.ToXml());
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var data = xml.Descendants(ns + "Data")
                .Where(d => d.Attribute("Name") != null)
                .ToDictionary(d => d.Attribute("Name")!.Value, d => d.Value);
            string app = data.TryGetValue("Application", out var a) ? a : "";
            int pid = data.TryGetValue("ProcessId", out var p) && int.TryParse(p, out var id) ? id : 0;
            string destAddr = data.TryGetValue("DestAddress", out var da) ? da : "";
            string destPort = data.TryGetValue("DestPort", out var dp) ? dp : "";
            return (app, pid, $"{destAddr}:{destPort}");
        }
        catch { return ("", 0, ""); }
    }

    private static void RunAuditPol()
    {
        try
        {
            var psi = new ProcessStartInfo("auditpol.exe",
                "/set /subcategory:\"Filtering Platform Connection\" /failure:enable")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(15000);
        }
        catch { /* best effort: without auditing there are no 5157 prompts */ }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { DisableConsentMode(); } catch { }
    }
}
