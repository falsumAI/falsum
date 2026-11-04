// Module 13: Native Chat. Faithful C# port of Get-ModelStatus.
// Probes every configured local model runtime: llama.cpp (:8080), Jan
// (:1337), Ollama (:11434). The mouthpiece rule holds: the local model
// never decides truth — it summarizes what the deterministic engine computed.
using System.Net.Http;

namespace FalsumApp.Services.Modules;

public static class NativeChatModule
{
    public sealed class Endpoint
    {
        public string Name = "";
        public string BaseUrl = "";
        public string HealthPath = "";
        public string HealthKind = ""; // llamacpp | openai-models | ollama-tags
    }

    public static readonly Endpoint[] Endpoints = new[]
    {
        new Endpoint { Name = "llama.cpp", BaseUrl = "http://localhost:8080",
            HealthPath = "/health", HealthKind = "llamacpp" },
        new Endpoint { Name = "Jan", BaseUrl = "http://localhost:1337",
            HealthPath = "/v1/models", HealthKind = "openai-models" },
        new Endpoint { Name = "Ollama", BaseUrl = "http://localhost:11434",
            HealthPath = "/api/tags", HealthKind = "ollama-tags" },
    };

    private static bool Probe(Endpoint ep, int timeoutSec = 5)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSec) };
            var resp = http.GetAsync(ep.BaseUrl.TrimEnd('/') + ep.HealthPath)
                .GetAwaiter().GetResult();
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    /// <summary>Probes all configured local runtimes. One result per endpoint.</summary>
    public static List<ModuleResult> ModelStatus()
    {
        var results = new List<ModuleResult>();
        int up = 0;
        foreach (var ep in Endpoints)
        {
            bool reachable = Probe(ep);
            if (reachable) up++;
            results.Add(reachable
                ? ModuleResult.Pass("NativeChat",
                    $"{ep.Name} is UP at {ep.BaseUrl}.",
                    new { endpoint = ep.Name, url = ep.BaseUrl })
                : ModuleResult.Pass("NativeChat",
                    $"{ep.Name} not reachable at {ep.BaseUrl}. " +
                    (ep.Name == "llama.cpp"
                        ? "Start your llama.cpp server on :8080 to enable local chat."
                        : "Install/start it to use as a fallback runtime."),
                    new { endpoint = ep.Name, url = ep.BaseUrl }));
        }
        results.Add(up > 0
            ? ModuleResult.Pass("NativeChat", $"{up}/{Endpoints.Length} local model runtimes reachable.")
            : ModuleResult.Warn("NativeChat",
                "No local model runtime reachable. AI Chat needs llama.cpp, Jan, or Ollama running on localhost."));
        return results;
    }
}
