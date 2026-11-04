// Shared file / JSON / crypto primitives ported from the .ps1 vault modules.
// Vault layout matches the PowerShell modules exactly:
//   %LOCALAPPDATA%\Falsum\vault\<name>\chain.jsonl
// so vaults written by the old .ps1 code verify under this code and vice versa.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FalsumApp.Services.Modules;

internal static class Vault
{
    public static string VaultDir(string name)
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "vault", name);
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static string Sha384Hex(string text)
        => Convert.ToHexString(SHA384.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    public static string Sha256Hex(byte[] bytes)
        => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    public static void AppendJsonl(string path, Dictionary<string, object?> entry)
        => File.AppendAllText(path, JsonSerializer.Serialize(entry) + Environment.NewLine, Encoding.UTF8);

    /// <summary>Last non-empty line of a JSONL file, or null.</summary>
    public static string? ReadLastLine(string path)
    {
        if (!File.Exists(path)) return null;
        string? last = null;
        foreach (var line in File.ReadLines(path, Encoding.UTF8))
            if (!string.IsNullOrWhiteSpace(line)) last = line;
        return last;
    }

    /// <summary>All parseable JSONL documents; corrupt lines are skipped.</summary>
    public static List<JsonDocument> ReadJsonl(string path)
    {
        var docs = new List<JsonDocument>();
        if (!File.Exists(path)) return docs;
        foreach (var line in File.ReadLines(path, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try { docs.Add(JsonDocument.Parse(line)); } catch { /* skip corrupt lines */ }
        }
        return docs;
    }

    /// <summary>Round-trip ('o') timestamp in local time, matching (Get-Date).ToString('o').</summary>
    public static string IsoNow() => DateTimeOffset.Now.ToString("o");

    /// <summary>
    /// Convert a JsonElement to a plain .NET value (string/bool/long/double/null).
    /// Use this instead of JsonElement.ToString(), which returns raw JSON text
    /// (strings come back WITH quotes and would break parsing).
    /// </summary>
    public static object? ElementToObject(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => e.TryGetInt64(out var l) ? (object)l : e.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        _ => e.GetRawText(),
    };

    public static string DesktopPath(string fileName)
        => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), fileName);

    public static string Timestamped(string prefix, string extension)
        => $"{prefix}-{DateTime.Now:yyyyMMdd-HHmmss}.{extension}";
}
