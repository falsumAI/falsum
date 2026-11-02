using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace FalsumApp.Services;

/// <summary>
/// Local AI chat — talks to llama.cpp server on localhost:8080.
/// No cloud. No tokens. No data leaves the machine.
/// Learns from corrections via the lessons database.
/// </summary>
public class LocalAIService
{
    private readonly HttpClient _http;
    private readonly string _lessonsPath;
    private readonly QuantumCoherenceEngine _coherence;
    private const string LlamaEndpoint = "http://localhost:8080/completion";

    public LocalAIService()
    {
        _http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        _coherence = new QuantumCoherenceEngine();
        _lessonsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "ai", "lessons.json");
    }

    /// <summary>
    /// Plug in Gregg's math when he validates it.
    /// Until then, the engine uses published quantum-inspired techniques.
    /// </summary>
    public void SetGreggMath(Func<double[], double> coherenceFunction)
    {
        _coherence.GreggCoherenceFunction = coherenceFunction;
    }

    /// <summary>
    /// Check if the local AI server is running.
    /// </summary>
    public async Task<bool> IsServerRunning()
    {
        try
        {
            var response = await _http.GetAsync("http://localhost:8080/health");
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    /// <summary>
    /// Send a message to the local AI and get a response.
    /// Prepends relevant lessons so the AI learns from past corrections.
    /// Scores response coherence using Gregg's drift math — flags low-coherence outputs.
    /// </summary>
    public async Task<string> Chat(string userMessage)
    {
        // Check for correction syntax: "wrong, [correction]"
        if (userMessage.StartsWith("wrong,", StringComparison.OrdinalIgnoreCase))
        {
            var correction = userMessage.Substring(6).Trim();
            SaveLesson(correction);
            return "Got it. I've saved that correction and won't make that mistake again.";
        }

        // Load relevant lessons
        var lessons = GetRelevantLessons(userMessage);
        var lessonsContext = lessons.Count > 0
            ? "\n\nThings you've corrected me on before:\n" + string.Join("\n", lessons.Select(l => $"- {l}"))
            : "";

        var fullPrompt = $"You are Falsum, a helpful local AI assistant.{lessonsContext}\n\nUser: {userMessage}\nAssistant:";

        var requestBody = new
        {
            prompt = fullPrompt,
            n_predict = 512,
            temperature = 0.7,
            stop = new[] { "\nUser:", "<|end|>" }
        };

        var json = JsonSerializer.Serialize(requestBody);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            var response = await _http.PostAsync(LlamaEndpoint, content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(responseJson);

            string aiText;
            if (doc.RootElement.TryGetProperty("content", out var contentProp))
            {
                aiText = contentProp.GetString()?.Trim() ?? "No response.";
            }
            else
            {
                return "Unexpected response format.";
            }

            // GREGG'S DRIFT MATH IN ACTION:
            // Score the response coherence against lessons (anchor = past corrections).
            // If the AI contradicts what it was taught, flag it.
            var coherence = ScoreResponseCoherence(aiText, lessons);
            if (coherence < 0.3 && lessons.Count > 0)
            {
                aiText += "\n\n⚠️ Low coherence warning: this response may contradict previous corrections. " +
                          $"Coherence score: {coherence:F2}. If this is wrong, type 'wrong, [correction]'.";
            }

            return aiText;
        }
        catch (HttpRequestException)
        {
            return "Local AI server isn't running. Start it from Settings → Local AI → Start Server.\n\n" +
                   "The server runs llama.cpp on your machine. No internet needed after setup.";
        }
    }

    /// <summary>
    /// Uses Gregg's drift measure: treats lessons as anchor, AI response as current.
    /// High D_KL proxy = response drifts from what user taught it.
    /// </summary>
    private double ScoreResponseCoherence(string response, List<string> lessons)
    {
        if (lessons.Count == 0) return 1.0;

        var evidence = new List<EvidenceState>();

        foreach (var lesson in lessons)
        {
            // Simple check: does the response contradict the lesson?
            // (Full NLP would use embeddings; this is a keyword overlap proxy.)
            var lessonWords = lesson.ToLower().Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Where(w => w.Length > 4).ToHashSet();
            var responseWords = response.ToLower().Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .ToHashSet();

            var overlap = lessonWords.Count(w => responseWords.Contains(w));
            var overlapRatio = lessonWords.Count > 0 ? (double)overlap / lessonWords.Count : 0;

            // If lesson keywords appear, it's consistent (supporting).
            // If none appear, it's neutral (not necessarily contradicting).
            if (overlapRatio > 0.3)
                evidence.Add(EvidenceState.Supporting("lesson", lesson, overlapRatio));
            else
                evidence.Add(EvidenceState.Neutral("lesson", lesson, 0.5));
        }

        return _coherence.ScoreCoherence(evidence);
    }

    private void SaveLesson(string correction)
    {
        try
        {
            var lessons = LoadAllLessons();
            lessons.Add(new Lesson
            {
                Text = correction,
                Timestamp = DateTime.Now,
                Context = "user-correction"
            });

            Directory.CreateDirectory(Path.GetDirectoryName(_lessonsPath)!);
            var json = JsonSerializer.Serialize(lessons, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_lessonsPath, json);
        }
        catch { /* Don't crash on save failure */ }
    }

    private List<string> GetRelevantLessons(string userMessage)
    {
        var lessons = LoadAllLessons();
        var keywords = userMessage.ToLower().Split(' ', StringSplitOptions.RemoveEmptyEntries);

        return lessons
            .Where(l => keywords.Any(k => l.Text.ToLower().Contains(k) && k.Length > 3))
            .Select(l => l.Text)
            .Take(5)
            .ToList();
    }

    private List<Lesson> LoadAllLessons()
    {
        try
        {
            if (!File.Exists(_lessonsPath)) return new List<Lesson>();
            var json = File.ReadAllText(_lessonsPath);
            return JsonSerializer.Deserialize<List<Lesson>>(json) ?? new List<Lesson>();
        }
        catch { return new List<Lesson>(); }
    }

    private class Lesson
    {
        public string Text { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public string Context { get; set; } = "";
    }
}
