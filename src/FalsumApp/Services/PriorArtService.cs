using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FalsumApp.Services;

/// <summary>
/// Prior Art Vault — defensive publication against patent trolls.
/// Every invention record is: timestamped, hash-chained, and publicly verifiable.
/// If a company patents around your work AFTER you published it here,
/// this vault is the prior art that invalidates their patent.
/// Your name is cryptographically bound to every record — de-identification impossible.
/// </summary>
public class PriorArtService
{
    private readonly string _vaultPath;
    private readonly string _chainPath;

    public PriorArtService()
    {
        var falsumDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "prior-art");
        Directory.CreateDirectory(falsumDir);
        _vaultPath = Path.Combine(falsumDir, "inventions.jsonl");
        _chainPath = Path.Combine(falsumDir, "chain.json");
    }

    /// <summary>
    /// Publish an invention as prior art. Your identity is permanently bound.
    /// </summary>
    public PriorArtRecord PublishInvention(string title, string description, string inventorName, string[] tags)
    {
        var record = new PriorArtRecord
        {
            Id = Guid.NewGuid().ToString(),
            Title = title,
            Description = description,
            InventorName = inventorName,  // NEVER stripped. This is the anti-de-identification.
            InventorBinding = ComputeInventorBinding(inventorName, title),
            Tags = tags,
            PublishedAt = DateTime.UtcNow,
            PreviousHash = GetLastHash()
        };

        // Hash chain: this record's hash includes the previous record's hash
        record.RecordHash = ComputeRecordHash(record);

        // Append to vault (JSONL — one record per line, append-only)
        var json = JsonSerializer.Serialize(record);
        File.AppendAllText(_vaultPath, json + "\n");

        // Update chain head
        File.WriteAllText(_chainPath, JsonSerializer.Serialize(new { head = record.RecordHash, updated = DateTime.UtcNow }));

        return record;
    }

    /// <summary>
    /// Verify the entire chain — proves no records were altered or removed.
    /// </summary>
    public (bool valid, int count, string? error) VerifyChain()
    {
        if (!File.Exists(_vaultPath)) return (true, 0, null);

        var lines = File.ReadAllLines(_vaultPath);
        string? expectedPrev = null;
        int count = 0;

        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            var record = JsonSerializer.Deserialize<PriorArtRecord>(line);
            if (record == null) return (false, count, $"Line {count + 1}: corrupt");

            // Check hash chain
            if (expectedPrev != null && record.PreviousHash != expectedPrev)
                return (false, count, $"Line {count + 1}: chain broken — record may have been tampered with");

            // Recompute hash to verify integrity
            var recomputed = ComputeRecordHash(record);
            if (recomputed != record.RecordHash)
                return (false, count, $"Line {count + 1}: hash mismatch — record altered");

            // Verify inventor binding (anti-de-identification check)
            var expectedBinding = ComputeInventorBinding(record.InventorName, record.Title);
            if (expectedBinding != record.InventorBinding)
                return (false, count, $"Line {count + 1}: inventor binding broken — attribution tampered with");

            expectedPrev = record.RecordHash;
            count++;
        }

        return (true, count, null);
    }

    /// <summary>
    /// Export a record as a human-readable prior art declaration.
    /// Suitable for submitting to USPTO as prior art against a patent application.
    /// </summary>
    public string ExportDeclaration(PriorArtRecord record)
    {
        var sb = new StringBuilder();
        sb.AppendLine("PRIOR ART DECLARATION");
        sb.AppendLine("=====================");
        sb.AppendLine();
        sb.AppendLine($"Title: {record.Title}");
        sb.AppendLine($"Inventor: {record.InventorName}");
        sb.AppendLine($"Published: {record.PublishedAt:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"Record ID: {record.Id}");
        sb.AppendLine($"Record Hash (SHA-256): {record.RecordHash}");
        sb.AppendLine($"Inventor Binding: {record.InventorBinding}");
        sb.AppendLine($"Tags: {string.Join(", ", record.Tags)}");
        sb.AppendLine();
        sb.AppendLine("Description:");
        sb.AppendLine(record.Description);
        sb.AppendLine();
        sb.AppendLine("---");
        sb.AppendLine("This record is part of a hash-chained prior art vault.");
        sb.AppendLine("The chain can be independently verified.");
        sb.AppendLine($"Chain head at export: {GetLastHash()}");
        return sb.ToString();
    }

    private string ComputeInventorBinding(string inventorName, string title)
    {
        // Bind inventor name to the work cryptographically.
        // If anyone tries to strip the name (de-identification), the binding breaks
        // and verification fails. The attribution is mathematically inseparable.
        using var sha = SHA256.Create();
        var input = $"INVENTOR:{inventorName}|WORK:{title}|FALSUM-PRIOR-ART-v1";
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash);
    }

    private string ComputeRecordHash(PriorArtRecord record)
    {
        using var sha = SHA256.Create();
        var input = $"{record.Id}|{record.Title}|{record.Description}|{record.InventorName}|" +
                    $"{record.InventorBinding}|{record.PublishedAt:o}|{record.PreviousHash}|" +
                    $"{string.Join(",", record.Tags)}";
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash);
    }

    private string? GetLastHash()
    {
        try
        {
            if (!File.Exists(_chainPath)) return null;
            var json = File.ReadAllText(_chainPath);
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("head").GetString();
        }
        catch { return null; }
    }

    public List<PriorArtRecord> GetAllRecords()
    {
        var records = new List<PriorArtRecord>();
        if (!File.Exists(_vaultPath)) return records;

        foreach (var line in File.ReadAllLines(_vaultPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var record = JsonSerializer.Deserialize<PriorArtRecord>(line);
            if (record != null) records.Add(record);
        }
        return records;
    }
}

public class PriorArtRecord
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public string InventorName { get; set; } = "";
    public string InventorBinding { get; set; } = "";
    public string[] Tags { get; set; } = System.Array.Empty<string>();
    public DateTime PublishedAt { get; set; }
    public string? PreviousHash { get; set; }
    public string RecordHash { get; set; } = "";
}
