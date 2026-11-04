// VS Code Gate. New module per Gregg's order: "YOU BETTER LEARN HOW TO
// GATE VS CODE TOO."
// Audits the editor that builds the code:
//   - settings.json: telemetry, hidden switches, auto-update, remote tunnels
//   - installed extensions: what they can do
//   - the remote-control websocket Codex opened (from the export findings)
// Nothing is a black box — every switch gets a name and a verdict.
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class VSCodeGateModule
{
    private static string VSCodeDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Code", "User");

    private static string SettingsPath => Path.Combine(VSCodeDir, "settings.json");
    private static string ExtensionsDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".vscode", "extensions");

    /// <summary>Known telemetry / remote-access / auto-behavior switches.</summary>
    private static readonly (string Key, string Risk, string Fix)[] WatchedSwitches = new[]
    {
        ("telemetry.telemetryLevel", "Telemetry level: off/none is private; error/crash/all phone home.",
            "Set \"telemetry.telemetryLevel\": \"off\"."),
        ("telemetry.enableCrashReporter", "Crash reporter sends dumps to Microsoft.",
            "Set \"telemetry.enableCrashReporter\": false."),
        ("telemetry.enableTelemetry", "Legacy telemetry master switch.",
            "Set \"telemetry.enableTelemetry\": false."),
        ("workbench.settings.enableNaturalLanguageSearch", "Settings search queries sent to a cloud service.",
            "Set \"workbench.settings.enableNaturalLanguageSearch\": false."),
        ("remote.autoForwardPorts", "Automatically forwards local ports to remote — silent exposure.",
            "Set \"remote.autoForwardPorts\": false."),
        ("remote.restoreForwardedPorts", "Re-opens forwarded ports on reconnect.",
            "Set \"remote.restoreForwardedPorts\": false."),
        ("extensions.autoUpdate", "Extensions update silently — a compromised extension updates itself onto you.",
            "Set \"extensions.autoUpdate\": false and review updates manually."),
        ("extensions.autoCheckUpdates", "Checks for extension updates (network call).",
            "Set \"extensions.autoCheckUpdates\": false if you want zero chatter."),
        ("update.mode", "VS Code auto-updates itself.",
            "Set \"update.mode\": \"manual\" to control when it changes."),
        ("terminal.integrated.allowChords", "Not a risk — keybinding feature.",
            ""),
        ("security.workspace.trust.enabled", "Workspace trust gates code execution.",
            "Keep enabled. Disabling lets any opened folder run code."),
        ("chat.agent.enabled", "Built-in AI agent can act in the editor.",
            "Disable if you do not use it."),
        ("github.copilot.enable", "Copilot sends your code to the cloud.",
            "Disable per-language or entirely if you want local-only."),
    };

    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();

        // 1. settings.json switches.
        if (!File.Exists(SettingsPath))
        {
            results.Add(ModuleResult.Warn("VSCodeGate",
                $"No settings.json at {SettingsPath}. VS Code runs on defaults — " +
                "defaults phone home (telemetry) and auto-update."));
        }
        else
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(SettingsPath));
                var root = doc.RootElement;
                int risky = 0;
                foreach (var (key, risk, fix) in WatchedSwitches)
                {
                    if (string.IsNullOrEmpty(fix)) continue; // informational only
                    bool present = root.TryGetProperty(key, out var val);
                    string valStr = present ? val.ToString() : "(not set — default applies)";
                    // Telemetry defaults are ON unless explicitly off.
                    bool bad = key.StartsWith("telemetry.")
                        ? (!present || valStr is not ("off" or "\"off\"" or "false"))
                        : !present;
                    if (key == "telemetry.telemetryLevel")
                        bad = !present || (val.GetString() is not ("off" or "none"));
                    if (bad)
                    {
                        risky++;
                        results.Add(ModuleResult.Warn("VSCodeGate",
                            $"{key} = {valStr}. {risk} Fix: {fix}"));
                    }
                }
                if (risky == 0)
                    results.Add(ModuleResult.Pass("VSCodeGate",
                        "settings.json: all watched switches are locked down."));
            }
            catch (Exception ex)
            {
                results.Add(ModuleResult.Fail("VSCodeGate",
                    "Could not parse settings.json: " + ex.Message));
            }
        }

        // 2. Installed extensions.
        try
        {
            if (Directory.Exists(ExtensionsDir))
            {
                var exts = Directory.GetDirectories(ExtensionsDir)
                    .Select(Path.GetFileName)
                    .Where(n => n != null)
                    .ToList();
                var risky = exts.Where(n =>
                    n!.Contains("codex", StringComparison.OrdinalIgnoreCase) ||
                    n!.Contains("copilot", StringComparison.OrdinalIgnoreCase) ||
                    n!.Contains("remote", StringComparison.OrdinalIgnoreCase))
                    .ToList();
                results.Add(ModuleResult.Pass("VSCodeGate",
                    $"{exts.Count} extension(s) installed.",
                    exts));
                foreach (var r in risky)
                    results.Add(ModuleResult.Warn("VSCodeGate",
                        $"Extension '{r}' has remote/cloud capability. " +
                        "Verify you installed it and it is the version you expect."));
            }
            else
                results.Add(ModuleResult.Pass("VSCodeGate", "No extensions directory found."));
        }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Fail("VSCodeGate",
                "Could not list extensions: " + ex.Message));
        }

        // 3. Codex remote-control check (from the export findings).
        try
        {
            string codexDb = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".codex", "state_5.sqlite");
            results.Add(File.Exists(codexDb)
                ? ModuleResult.Warn("VSCodeGate",
                    "Codex local data found (~/.codex). If you did not authorize remote " +
                    "control, check its config for remote-control enrollments.",
                    new { path = codexDb })
                : ModuleResult.Pass("VSCodeGate", "No Codex local data found."));
        }
        catch { }

        return results;
    }
}
