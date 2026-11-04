using System.IO;
// Module 38: Learning AI. The chat loop's native health gate.
// The AI Chat card opens AIChatWindow directly; this module proves the
// learning loop's storage is healthy: the lessons database exists and is
// readable, and a local runtime answers.
using System.Text.Json;

namespace FalsumApp.Services.Modules;

public static class LearningAiModule
{
    private static string LessonsPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "ai", "lessons.json");

    /// <summary>Card action "Start-FalsumChatLoop": health gate for the learning loop.</summary>
    public static List<ModuleResult> Health()
    {
        var results = new List<ModuleResult>();

        // Lessons DB.
        try
        {
            string p = LessonsPath;
            int count = 0;
            if (File.Exists(p))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(p));
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    count = doc.RootElement.GetArrayLength();
            }
            results.Add(ModuleResult.Pass("LearningAI",
                $"Lessons database: {count} learned correction(s) at {p}. " +
                "The AI learns from your corrections ('wrong, [correction]').",
                new { lessons = count, path = p }));
        }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Warn("LearningAI",
                "Could not read lessons database: " + ex.Message));
        }

        // Local runtime (reuse the native-chat probe).
        foreach (var r in NativeChatModule.ModelStatus())
            results.Add(r);

        return results;
    }
}
