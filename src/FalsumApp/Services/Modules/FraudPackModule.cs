using System.IO;
// Module 23: Fraud Pack. Faithful C# port of New-FraudManifest.
// Re-seals the fraud-pack directory: SHA-256 of every pack file ->
// MANIFEST.txt, plus out-of-band MANIFEST-HASH.txt (SHA-256 of the manifest
// itself). The manifest proves WHICH files existed; the manifest hash proves
// the manifest wasn't rewritten after a file was tampered with.
// MANIFEST.txt and MANIFEST-HASH.txt are the seal, not the cargo — they are
// excluded from their own listing.
using System.Security.Cryptography;
using System.Text;

namespace FalsumApp.Services.Modules;

public static class FraudPackModule
{
    private static string DefaultPackDir =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Falsum", "vault", "fraud-pack");

    public static List<ModuleResult> SealManifest(string? packDir = null)
    {
        var results = new List<ModuleResult>();
        string dir = packDir ?? DefaultPackDir;
        try
        {
            Directory.CreateDirectory(dir);
            var files = new DirectoryInfo(dir).GetFiles()
                .Where(f => f.Name != "MANIFEST.txt" && f.Name != "MANIFEST-HASH.txt")
                .OrderBy(f => f.Name, StringComparer.Ordinal)
                .ToList();
            var lines = new List<string>
            {
                "# Falsum fraud-pack manifest — SHA-256 per file, sealed " +
                DateTime.UtcNow.ToString("o")
            };
            using var sha = SHA256.Create();
            foreach (var f in files)
            {
                byte[] hash = sha.ComputeHash(File.ReadAllBytes(f.FullName));
                lines.Add(Convert.ToHexString(hash).ToLowerInvariant() + "  " + f.Name);
            }
            string mf = Path.Combine(dir, "MANIFEST.txt");
            File.WriteAllLines(mf, lines, Encoding.UTF8);
            string mhash = Convert.ToHexString(sha.ComputeHash(File.ReadAllBytes(mf))).ToLowerInvariant();
            File.WriteAllText(Path.Combine(dir, "MANIFEST-HASH.txt"), mhash, Encoding.ASCII);
            results.Add(ModuleResult.Pass("FraudPack",
                $"Manifest sealed: {files.Count} files, MANIFEST-HASH {mhash}",
                new { fileCount = files.Count, manifestHash = mhash, packDir = dir }));
        }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Fail("FraudPack",
                "ERROR sealing manifest: " + ex.Message));
        }
        return results;
    }
}
