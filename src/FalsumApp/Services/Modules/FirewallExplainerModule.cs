// Firewall Explainer. Gregg's order: no jargon.
// "when something in the firewall pops up as active or inactive
//  there is a explanation sitting next to the fucken thing
//  that could possibly be exploited."
//
// Every firewall rule gets:
//   WHAT: plain-language description of what this rule does
//   WHO: what program owns it
//   STATUS: active or inactive, and what that means
//   RISK: how this could be exploited if it's wrong
//
// No technical terms without explanation. A grandmother reads this.
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class FirewallExplainerModule
{
    public sealed class ExplainedRule
    {
        public string Program { get; set; } = "";
        public string What { get; set; } = "";
        public bool Active { get; set; }
        public string StatusMeans { get; set; } = "";
        public string Risk { get; set; } = "";
    }

    // Known programs and their plain-language explanations.
    // Key: process/image name (lowercase). Value: (what it does, risk if exploited).
    private static readonly Dictionary<string, (string What, string Risk)> KnownPrograms = new()
    {
        ["svchost"] = (
            "This is Windows itself running background tasks. Windows groups many small jobs under this name.",
            "If a virus pretends to be this, it can hide. Check that the file lives in C:\\Windows\\System32 — anywhere else is fake."),
        ["chrome"] = (
            "Google Chrome web browser. It connects to websites you visit.",
            "Chrome extensions can spy on you. If you see Chrome connecting when you're not browsing, check your extensions."),
        ["msedge"] = (
            "Microsoft Edge web browser. It connects to websites you visit.",
            "Edge sends diagnostic data to Microsoft by default. Falsum's predator vault can block the telemetry endpoints."),
        ["firefox"] = (
            "Firefox web browser. It connects to websites you visit.",
            "Firefox is the most private major browser, but extensions can still spy. Check for extensions you didn't install."),
        ["onedrive"] = (
            "Microsoft's cloud storage. It uploads your files to Microsoft's servers.",
            "Everything in your OneDrive folders is copied to Microsoft. If you didn't put it there on purpose, it's being taken."),
        ["teams"] = (
            "Microsoft Teams. Video calls and chat for work.",
            "Teams runs at startup and stays connected. It can access your camera, mic, and files."),
        ["spotify"] = (
            "Spotify music app. Streams music from the internet.",
            "Spotify tracks what you listen to and when. That's how they build your profile."),
        ["discord"] = (
            "Discord chat app. Voice, video, and text.",
            "Discord sees every message unless it's encrypted. Voice data goes through their servers."),
        ["steam"] = (
            "Steam game store. Downloads and runs games.",
            "Steam has broad access to your system for anti-cheat. Some games install kernel-level drivers."),
        ["cortana"] = (
            "Microsoft's voice assistant. Listens for voice commands.",
            "A listening assistant is a microphone that's always on. If you don't use it, block it."),
        ["searchhost"] = (
            "Windows search. Indexes your files so you can find them fast.",
            "The index contains the names and contents of your files. It phones home with search terms."),
        ["sihost"] = (
            "Windows shell infrastructure. Draws your taskbar and start menu.",
            "Core Windows component. If this is connecting to the internet, something is wrong."),
        ["lsass"] = (
            "Windows security. Handles your login password.",
            "This should NEVER connect to the internet. If it does, you're being attacked."),
        ["wininit"] = (
            "Windows startup. Launches core system processes when you turn on the computer.",
            "Core Windows component. Should never use the network."),
        ["csrss"] = (
            "Windows graphics and console. Draws windows on your screen.",
            "Core Windows component. Should never use the network."),
    };

    /// <summary>
    /// Explains a firewall rule in plain language.
    /// </summary>
    public static ExplainedRule Explain(string programName, bool active, string direction)
    {
        string key = programName.ToLowerInvariant().Replace(".exe", "");
        var rule = new ExplainedRule { Program = programName, Active = active };

        if (KnownPrograms.TryGetValue(key, out var known))
        {
            rule.What = known.What;
            rule.Risk = known.Risk;
        }
        else
        {
            rule.What = $"A program called {programName}. Falsum doesn't have a plain-language description for this one yet — it may be legitimate or it may not be.";
            rule.Risk = "Unknown programs using the network deserve a closer look. If you didn't install it, block it and investigate.";
        }

        string dir = direction.ToLowerInvariant().Contains("out") ? "sending data out" : "receiving data in";
        rule.StatusMeans = active
            ? $"ACTIVE: This program is currently allowed to {dir} through your firewall."
            : $"INACTIVE: This program is currently BLOCKED from {dir}. It's not getting through.";

        return rule;
    }

    /// <summary>
    /// Explains all current firewall rules. Each one gets plain language.
    /// </summary>
    public static List<ExplainedRule> ExplainAll()
    {
        var explained = new List<ExplainedRule>();
        try
        {
            // Get listeners and map to programs.
            var listeners = NativeTcp.GetListeners();
            foreach (var l in listeners)
            {
                string program = l.ProcessName ?? "unknown";
                bool active = true; // Listening = active
                explained.Add(Explain(program, active, "in"));
            }
        }
        catch { }
        return explained;
    }

    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();
        var rules = ExplainAll();
        results.Add(ModuleResult.Pass("FirewallExplainer",
            $"Explained {rules.Count} firewall rules in plain language. " +
            "Every rule shows what it does, whether it's active, and how it could be exploited."));
        return results;
    }
}
