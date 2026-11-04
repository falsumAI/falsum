using System.IO;
// First-Run Wizard. Built for the user Gregg described:
// "a 5 year old worried about there data... or the parent."
// "can an old woman who's going blind actually use this application?"
//
// When Falsum runs for the first time, it doesn't dump 59 cards
// on the user. It walks through:
//   1. WHAT: "I'm Falsum. I protect your computer and your data."
//   2. HOW: "I watch every program. I ask before anything uses your network."
//   3. PROMISE: "Nothing I learn leaves this computer. Ever."
//   4. ACTION: "Click Protect Me. I'll check everything and fix what I can."
//
// Every step is screen-reader announced. Every step is plain language.
// The wizard runs once. A "take the tour again" button replays it.
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class FirstRunWizardModule
{
    private static string FlagPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "wizard-done.flag");

    public static bool HasRun => File.Exists(FlagPath);

    public static void MarkDone()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FlagPath)!);
            File.WriteAllText(FlagPath, DateTimeOffset.Now.ToString("o"));
        }
        catch { }
    }

    public sealed class WizardStep
    {
        public string Title { get; set; } = "";
        public string Body { get; set; } = "";
        public string ActionLabel { get; set; } = "";
    }

    public static List<WizardStep> GetSteps() => new()
    {
        new WizardStep
        {
            Title = "I'm Falsum",
            Body = "I'm a free program that protects your computer and your data. " +
                "I was built so that no company can secretly take what's yours. " +
                "I run on your computer, not in someone else's cloud.",
            ActionLabel = "Next",
        },
        new WizardStep
        {
            Title = "What I watch",
            Body = "I watch every program on this computer. When a program tries " +
                "to use the internet, I ask you first. Nothing gets out without " +
                "your permission. If a company tries to take your data secretly, " +
                "I catch them, I log the evidence, and I block them.",
            ActionLabel = "Next",
        },
        new WizardStep
        {
            Title = "Your data stays yours",
            Body = "Everything I learn about your computer stays on your computer. " +
                "I don't send reports anywhere. I don't have an account for you. " +
                "I don't track you. The only person who sees what I find is you.",
            ActionLabel = "Next",
        },
        new WizardStep
        {
            Title = "Let's protect you",
            Body = "Click the Protect Me button. I'll check your entire computer — " +
                "programs, network, settings, everything — and fix what I can. " +
                "It takes a few minutes. You can watch everything I do.",
            ActionLabel = "Protect Me",
        },
    };

    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();
        results.Add(HasRun
            ? ModuleResult.Pass("FirstRun",
                "Welcome wizard completed. The user was guided through " +
                "what Falsum does, in plain language, screen-reader announced.")
            : ModuleResult.Warn("FirstRun",
                "Welcome wizard has not run yet. It will guide the user " +
                "through Falsum's protection on first launch."));
        return results;
    }
}
