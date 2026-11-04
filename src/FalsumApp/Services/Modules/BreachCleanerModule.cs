using System.IO;
// Module 08: Breach Cleaner. Faithful C# port of Test-HibpConnection.
// Cheap auth check against the HIBP subscription endpoint. The API key is
// read from %APPDATA%\Falsum\hibp.key (one line, no quotes) — the value is
// NEVER written to console, log, vault, or report; it goes only into the
// HTTP header, exactly like the .ps1.
using System.Net;
using System.Net.Http;

namespace FalsumApp.Services.Modules;

public static class BreachCleanerModule
{
    private static string KeyFilePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Falsum", "hibp.key");

    public static List<ModuleResult> TestHibpConnection()
    {
        var results = new List<ModuleResult>();
        string keyFile = KeyFilePath;
        if (!File.Exists(keyFile))
        {
            results.Add(ModuleResult.Warn("BreachCleaner",
                $"HIBP key file not found: {keyFile}. " +
                "Create it with your HIBP API key (one line, no quotes) to enable breach checks.",
                new { keyFile }));
            return results;
        }
        string key;
        try { key = File.ReadAllText(keyFile).Trim(); }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Fail("BreachCleaner",
                "Failed to read key file: " + ex.Message));
            return results;
        }
        if (string.IsNullOrWhiteSpace(key))
        {
            results.Add(ModuleResult.Warn("BreachCleaner",
                "HIBP key file is empty or still a placeholder."));
            return results;
        }
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            var req = new HttpRequestMessage(HttpMethod.Get,
                "https://haveibeenpwned.com/api/v3/subscription/status");
            req.Headers.Add("hibp-api-key", key);
            req.Headers.UserAgent.ParseAdd("Falsum/1.1.0");
            var resp = http.Send(req);
            if (resp.StatusCode == HttpStatusCode.OK)
                results.Add(ModuleResult.Pass("BreachCleaner",
                    "HIBP key accepted. Breach-check API is reachable."));
            else if (resp.StatusCode == HttpStatusCode.Unauthorized)
                results.Add(ModuleResult.Fail("BreachCleaner",
                    "HIBP rejected the key (401 Unauthorized) — check the key file."));
            else
                results.Add(ModuleResult.Fail("BreachCleaner",
                    $"HIBP returned {(int)resp.StatusCode} {resp.ReasonPhrase}."));
        }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Fail("BreachCleaner",
                "HIBP connection failed: " + ex.Message));
        }
        return results;
    }
}
