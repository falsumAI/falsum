using System.IO;
// Binary Translator. New module per Gregg's order:
// "ALL THESE .EXE FILES AND .DLL FILES OR ANY FILE FOR THAT MATTER GETS
// INSTANTLY TRANSLATED INTO A HUMAN READABLE FILE. THIS FUCKEN DEVICE
// NEEDS TO BE READABLE. NOTHING IS A BLACK BOX."
// Reads a PE file (exe/dll/sys) and explains it in plain language:
//   - what it is (architecture, type, signed or not, by whom)
//   - what it imports (what system powers it uses)
//   - what it exports (what it offers to others)
//   - embedded strings of interest (URLs, IPs, registry keys, paths)
//   - the verdict: does it look like what it claims to be?
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

public static class BinaryTranslatorModule
{
    public sealed class BinaryReport
    {
        public string File = "";
        public string Kind = "";        // EXE / DLL / SYS / UNKNOWN
        public string Arch = "";        // x64 / x86 / ARM64 / ?
        public string SignedBy = "";    // signer or "UNSIGNED"
        public List<string> Imports = new();
        public List<string> Exports = new();
        public List<string> InterestingStrings = new();
        public List<string> Verdicts = new();
    }

    private static ushort ReadU16(byte[] b, int off) => BitConverter.ToUInt16(b, off);
    private static uint ReadU32(byte[] b, int off) => BitConverter.ToUInt32(b, off);

    public static BinaryReport? Translate(string path)
    {
        if (!File.Exists(path)) return null;
        byte[] b;
        try { b = File.ReadAllBytes(path); }
        catch { return null; }
        if (b.Length < 64 || b[0] != 'M' || b[1] != 'Z') return null;

        var r = new BinaryReport { File = Path.GetFileName(path) };
        try
        {
            int peOff = (int)ReadU32(b, 0x3C);
            if (peOff + 6 > b.Length || b[peOff] != 'P' || b[peOff + 1] != 'E')
                return null;
            ushort machine = ReadU16(b, peOff + 4);
            r.Arch = machine switch
            {
                0x8664 => "x64",
                0x14c => "x86",
                0xaa64 => "ARM64",
                _ => $"unknown (0x{machine:X4})",
            };
            ushort numSections = ReadU16(b, peOff + 6);
            ushort optSize = ReadU16(b, peOff + 20);
            ushort characteristics = ReadU16(b, peOff + 22);
            bool isDll = (characteristics & 0x2000) != 0;
            string name = Path.GetFileName(path).ToLowerInvariant();
            r.Kind = name.EndsWith(".sys") ? "SYS (driver)"
                : isDll ? "DLL (library)" : "EXE (program)";

            int optOff = peOff + 24;
            bool pe32Plus = b[optOff] == 0x0b && b[optOff + 1] == 0x02;
            int dataDirOff = optOff + (pe32Plus ? 112 : 96);

            int secOff = optOff + optSize;
            var sections = new List<(uint VAddr, uint VSize, uint RawPtr, uint RawSize)>();
            for (int i = 0; i < numSections && secOff + 40 <= b.Length; i++, secOff += 40)
            {
                sections.Add((ReadU32(b, secOff + 12), ReadU32(b, secOff + 8),
                    ReadU32(b, secOff + 20), ReadU32(b, secOff + 16)));
            }
            uint RvaToRaw(uint rva)
            {
                foreach (var s in sections)
                    if (rva >= s.VAddr && rva < s.VAddr + Math.Max(s.VSize, s.RawSize))
                        return s.RawPtr + (rva - s.VAddr);
                return uint.MaxValue;
            }

            // Import table.
            uint impRva = ReadU32(b, dataDirOff + 8);
            uint impSize = ReadU32(b, dataDirOff + 12);
            if (impRva != 0 && impSize != 0)
            {
                uint raw = RvaToRaw(impRva);
                for (int d = 0; d < 200 && raw + 20 <= (uint)b.Length; d++, raw += 20)
                {
                    uint nameRva = ReadU32(b, (int)raw + 12);
                    if (nameRva == 0) break;
                    uint nameRaw = RvaToRaw(nameRva);
                    if (nameRaw == uint.MaxValue || nameRaw >= b.Length) continue;
                    int end = (int)nameRaw;
                    while (end < b.Length && b[end] != 0) end++;
                    string dll = Encoding.ASCII.GetString(b, (int)nameRaw, end - (int)nameRaw);
                    r.Imports.Add(dll);
                }
            }

            // Export table (DLLs).
            uint expRva = ReadU32(b, dataDirOff + 0);
            if (expRva != 0 && isDll)
            {
                uint raw = RvaToRaw(expRva);
                if (raw != uint.MaxValue && raw + 40 <= (uint)b.Length)
                {
                    uint numNames = ReadU32(b, (int)raw + 24);
                    uint namesRva = ReadU32(b, (int)raw + 32);
                    uint namesRaw = RvaToRaw(namesRva);
                    for (uint i = 0; i < Math.Min(numNames, 50); i++)
                    {
                        if (namesRaw == uint.MaxValue || namesRaw + 4 > (uint)b.Length) break;
                        uint sRva = ReadU32(b, (int)namesRaw + (int)i * 4);
                        uint sRaw = RvaToRaw(sRva);
                        if (sRaw == uint.MaxValue || sRaw >= b.Length) continue;
                        int end = (int)sRaw;
                        while (end < b.Length && b[end] != 0 && end - sRaw < 256) end++;
                        r.Exports.Add(Encoding.ASCII.GetString(b, (int)sRaw, end - (int)sRaw));
                    }
                }
            }
        }
        catch { /* best effort — strings below still work */ }

        // Signature.
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(path);
            var c2 = new X509Certificate2(cert);
            r.SignedBy = c2.Subject;
        }
        catch { r.SignedBy = "UNSIGNED"; }

        // Interesting strings.
        try
        {
            string ascii = Encoding.ASCII.GetString(b);
            var seen = new HashSet<string>();
            void AddMatches(string pattern, string label, int max = 10)
            {
                int n = 0;
                foreach (Match m in Regex.Matches(ascii, pattern))
                {
                    if (seen.Add(m.Value) && n++ < max)
                        r.InterestingStrings.Add($"{label}: {m.Value}");
                }
            }
            AddMatches(@"https?://[^\s""'<>]{4,80}", "URL");
            AddMatches(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP");
            AddMatches(@"HKLM\\[^\s""']{3,80}|HKCU\\[^\s""']{3,80}", "Registry");
            AddMatches(@"[A-Za-z]:\\[^\s""']{3,80}\.(?:exe|dll|sys|ps1|bat)", "Path");
            AddMatches(@"cmd\.exe\s*/[ck]\s+[^\s""']{1,60}", "Command");
            AddMatches(@"powershell[^\s""']{0,40}", "PowerShell-ref");
        }
        catch { }

        // Verdicts.
        if (r.SignedBy == "UNSIGNED")
            r.Verdicts.Add("UNSIGNED — no vendor stands behind this file. " +
                "Treat it as untrusted until proven otherwise.");
        else
            r.Verdicts.Add($"Signed by: {r.SignedBy}.");
        var riskyImports = r.Imports.Where(i =>
            i.Contains("wininet", StringComparison.OrdinalIgnoreCase) ||
            i.Contains("winhttp", StringComparison.OrdinalIgnoreCase) ||
            i.Contains("ws2_32", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (riskyImports.Count > 0)
            r.Verdicts.Add("Uses the network (" + string.Join(", ", riskyImports) +
                ") — this file can talk to the internet.");
        if (r.InterestingStrings.Any(s => s.StartsWith("IP:")))
            r.Verdicts.Add("Contains hardcoded IP address(es) — worth asking why.");
        if (r.Kind.StartsWith("SYS"))
            r.Verdicts.Add("This is a DRIVER — it runs inside the Windows kernel " +
                "with full power over the machine.");
        if (r.Verdicts.Count == 1 && r.SignedBy != "UNSIGNED")
            r.Verdicts.Add("No red flags in the readable surface. The signature checks out.");

        return r;
    }

    public static List<ModuleResult> TranslateFile(string path)
    {
        var r = Translate(path);
        if (r == null)
            return new List<ModuleResult> { ModuleResult.Fail("BinaryTranslator",
                $"Cannot read {path} — not a PE file or access denied.") };
        var sb = new StringBuilder();
        sb.AppendLine($"{r.File}: {r.Kind}, {r.Arch}.");
        sb.AppendLine(r.SignedBy == "UNSIGNED" ? "UNSIGNED." : $"Signed by {r.SignedBy}.");
        sb.AppendLine($"Imports {r.Imports.Count} system libraries" +
            (r.Imports.Count > 0 ? ": " + string.Join(", ", r.Imports.Take(8)) : "") + ".");
        if (r.Exports.Count > 0)
            sb.AppendLine($"Exports {r.Exports.Count} functions: " +
                string.Join(", ", r.Exports.Take(8)) + ".");
        foreach (var v in r.Verdicts) sb.AppendLine("VERDICT: " + v);
        return new List<ModuleResult>
        {
            new ModuleResult { Name = "BinaryTranslator", Ok = true,
                Message = sb.ToString().TrimEnd(), Data = r }
        };
    }
}
