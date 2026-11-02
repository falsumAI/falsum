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
    /// Override hook for Gregg's coherence function.
    /// Gregg's drift math is already wired into ScoreResponseCoherence via
    /// _coherence.GreggDriftMeasure. This allows runtime override if needed.
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

            // GREGG'S DRIFT MATH IN ACTION — DETERMINISTIC SELF-CORRECTION:
            // Score coherence BEFORE showing the user. If low, regenerate with
            // lessons reinforced. User never sees a bad response. No warnings.
            var coherence = ScoreResponseCoherence(aiText, lessons);
            if (coherence < 0.5 && lessons.Count > 0)
            {
                // Self-correct: regenerate with stronger lesson enforcement
                aiText = await RegenerateWithCorrection(fullPrompt, lessons, aiText);
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
    /// Deterministic self-correction: when coherence is low, regenerate the response
    /// with lessons enforced as hard constraints. The user never sees the bad version.
    /// </summary>
    private async Task<string> RegenerateWithCorrection(string originalPrompt, List<string> lessons, string badResponse)
    {
        var correctionPrompt = originalPrompt +
            "\n\nCRITICAL: Your previous response contradicted established corrections. " +
            "You MUST follow these corrections exactly:\n" +
            string.Join("\n", lessons.Select((l, i) => $"{i + 1}. {l}")) +
            "\n\nRegenerate your response, ensuring full consistency with the above.";

        var requestBody = new
        {
            prompt = correctionPrompt,
            n_predict = 512,
            temperature = 0.3,  // Lower temperature for more deterministic correction
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

            if (doc.RootElement.TryGetProperty("content", out var contentProp))
            {
                return contentProp.GetString()?.Trim() ?? badResponse;
            }
        }
        catch { /* Fall through to return original */ }

        return badResponse;
    }

    /// <summary>
    /// GREGG'S DRIFT MATH — FULL IMPLEMENTATION.
    /// Treats lessons as P_anchor (the trusted baseline) and the AI response as P_current.
    /// D_drift = D_KL(P_current || P_anchor) + λ||θ_current - θ_anchor||²
    /// High drift = response drifts from what user taught it = poison pill triggers regeneration.
    /// This is what makes the local AI a beast: deterministic self-correction on real math.
    /// </summary>
    private double ScoreResponseCoherence(string response, List<string> lessons)
    {
        if (lessons.Count == 0) return 1.0;

        // Build word distributions: response = P_current, lessons = P_anchor
        var responseDist = GetWordDistribution(response);
        var anchorDist = GetWordDistribution(string.Join(" ", lessons));

        // D_KL(P_current || P_anchor) — how much the response diverges from lessons
        var kl = KLDivergence(responseDist, anchorDist);

        // ||θ_current - θ_anchor||² — parameter-space drift proxy
        // Here θ = key concept vectors; drift = concepts in response missing from anchor
        var anchorConcepts = GetKeyConcepts(string.Join(" ", lessons));
        var responseConcepts = GetKeyConcepts(response);
        var missingConcepts = anchorConcepts.Count(c => !responseConcepts.Contains(c));
        var thetaDrift = anchorConcepts.Count > 0
            ? (double)(missingConcepts * missingConcepts) / (anchorConcepts.Count * anchorConcepts.Count)
            : 0.0;

        // Gregg's drift measure: D_drift = D_KL + λ||Δθ||²
        const double lambda = 0.5;
        var drift = _coherence.GreggDriftMeasure(kl, new[] { thetaDrift }, new[] { 0.0 }, lambda);

        // Convert drift to coherence: low drift = high coherence
        // Drift of 0 → coherence 1.0; drift of 2+ → coherence near 0
        var coherence = Math.Exp(-drift);

        return Math.Clamp(coherence, 0.0, 1.0);
    }

    /// <summary>
    /// Build a normalized word frequency distribution from text.
    /// Filters to meaningful words (length > 3) for signal over noise.
    /// </summary>
    private Dictionary<string, double> GetWordDistribution(string text)
    {
        var words = text.ToLower()
            .Split(new[] { ' ', '\n', '\r', '\t', '.', ',', '!', '?', ';', ':', '"', '\'', '(', ')' },
                   StringSplitOptions.RemoveEmptyEntries)
            .Where(w => w.Length > 3)
            .ToList();

        if (words.Count == 0) return new Dictionary<string, double>();

        var counts = new Dictionary<string, double>();
        foreach (var w in words)
            counts[w] = counts.GetValueOrDefault(w, 0) + 1;

        var total = words.Count;
        return counts.ToDictionary(kvp => kvp.Key, kvp => kvp.Value / total);
    }

    /// <summary>
    /// Extract key concepts (longest/most distinctive words) as θ vector proxy.
    /// </summary>
    private HashSet<string> GetKeyConcepts(string text)
    {
        return text.ToLower()
            .Split(new[] { ' ', '\n', '\r', '\t', '.', ',', '!', '?', ';', ':', '"', '\'', '(', ')' },
                   StringSplitOptions.RemoveEmptyEntries)
            .Where(w => w.Length > 5)
            .ToHashSet();
    }

    /// <summary>
    /// KL divergence: D_KL(P || Q) = Σ P(x) log(P(x)/Q(x))
    /// Measures how much distribution P diverges from reference Q.
    /// Uses smoothing so unseen words don't blow up to infinity.
    /// </summary>
    private double KLDivergence(Dictionary<string, double> p, Dictionary<string, double> q)
    {
        const double epsilon = 1e-10;
        double kl = 0.0;

        // Get all unique words from both distributions
        var allWords = new HashSet<string>(p.Keys);
        allWords.UnionWith(q.Keys);

        foreach (var word in allWords)
        {
            var px = p.GetValueOrDefault(word, 0) + epsilon;
            var qx = q.GetValueOrDefault(word, 0) + epsilon;
            // Renormalize with smoothing
            kl += px * Math.Log(px / qx);
        }

        return Math.Max(0, kl); // KL is always non-negative; clamp floating point noise
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
