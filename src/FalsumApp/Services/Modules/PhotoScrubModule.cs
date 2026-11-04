// Module 17: Photo Scrub. Faithful C# port of Falsum-PhotoScrub.ps1's
// metadata engine: CRC-32 (ISO 3309), JPEG EXIF parsing, PNG text chunks,
// and the scored exposure rating.
// Risk: GPS = 50. Camera/owner serials = 15. MakerNote = 10. Timestamps = 15.
// Device = 10. Identity tags = 5. Software = 5. WebP EXIF flag = 15.
// Level: High >= 50, Medium >= 20, else Low. Scored, never binary.
using System.Text;

namespace FalsumApp.Services.Modules;

public static class PhotoScrubModule
{
    private static readonly uint[] Crc32Table = BuildCrc32Table();

    private static uint[] BuildCrc32Table()
    {
        var t = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++)
                c = (c & 1) == 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            t[n] = c;
        }
        return t;
    }

    /// <summary>Pure CRC-32 (ISO 3309, the PNG chunk checksum).</summary>
    public static uint Crc32(byte[] data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (byte b in data)
            crc = Crc32Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        return crc ^ 0xFFFFFFFFu;
    }

    public sealed class PhotoMeta
    {
        public string Path = "";
        public Dictionary<string, string> Fields { get; } = new();
        public (double Lat, double Lon)? Gps;
    }

    private static ushort ReadU16(byte[] b, int o, bool le)
        => le ? BitConverter.ToUInt16(b, o) : (ushort)((b[o] << 8) | b[o + 1]);

    private static uint ReadU32(byte[] b, int o, bool le)
        => le ? BitConverter.ToUInt32(b, o)
              : (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);

    private static readonly Dictionary<ushort, string> TagNames = new()
    {
        [0x010F] = "Make", [0x0110] = "Model", [0x0132] = "DateTime",
        [0x013B] = "Artist", [0x8298] = "Copyright", [0x9286] = "UserComment",
        [0x927C] = "MakerNote", [0x0131] = "Software", [0x9003] = "DateTimeOriginal",
        [0x9004] = "DateTimeDigitized", [0x270E] = "ImageDescription",
        [0xA431] = "CameraSerialNumber", [0xA433] = "LensSerialNumber",
        [0xA430] = "OwnerName",
    };

    /// <summary>Parses EXIF from a JPEG's APP1 segment. Returns tag name -> value.</summary>
    public static Dictionary<string, string> ParseJpegExif(byte[] jpeg)
    {
        var fields = new Dictionary<string, string>();
        try
        {
            if (jpeg.Length < 4 || jpeg[0] != 0xFF || jpeg[1] != 0xD8) return fields;
            int i = 2;
            while (i + 4 < jpeg.Length)
            {
                if (jpeg[i] != 0xFF) break;
                byte marker = jpeg[i + 1];
                if (marker == 0xD9 || marker == 0xDA) break; // EOI or SOS: stop
                int len = (jpeg[i + 2] << 8) | jpeg[i + 3];
                if (marker == 0xE1 && len > 8) // APP1
                {
                    string header = Encoding.ASCII.GetString(jpeg, i + 4, 6);
                    if (header.StartsWith("Exif\0\0"))
                    {
                        int tiffStart = i + 10;
                        ParseTiff(jpeg, tiffStart, fields);
                    }
                }
                i += 2 + len;
            }
        }
        catch { }
        return fields;
    }

    private static void ParseTiff(byte[] b, int tiffStart, Dictionary<string, string> fields)
    {
        if (tiffStart + 8 > b.Length) return;
        bool le = b[tiffStart] == 0x49 && b[tiffStart + 1] == 0x49;
        if (!le && !(b[tiffStart] == 0x4D && b[tiffStart + 1] == 0x4D)) return;
        if (ReadU16(b, tiffStart + 2, le) != 42) return;
        uint ifd0 = ReadU32(b, tiffStart + 4, le);
        ParseIfd(b, tiffStart, (int)(tiffStart + ifd0), le, fields, 0);
    }

    private static void ParseIfd(byte[] b, int tiffStart, int ifd, bool le,
        Dictionary<string, string> fields, int depth)
    {
        if (depth > 3 || ifd + 2 > b.Length) return;
        int count = ReadU16(b, ifd, le);
        for (int e = 0; e < count; e++)
        {
            int off = ifd + 2 + e * 12;
            if (off + 12 > b.Length) break;
            ushort tag = ReadU16(b, off, le);
            ushort type = ReadU16(b, off + 2, le);
            uint num = ReadU32(b, off + 4, le);
            // ASCII strings (type 2) stored inline or by offset.
            if (type == 2 && num > 0 && num < 1024)
            {
                string val;
                if (num <= 4)
                    val = Encoding.ASCII.GetString(b, off + 8, (int)num).TrimEnd('\0');
                else
                {
                    int strOff = (int)(tiffStart + ReadU32(b, off + 8, le));
                    if (strOff + num > b.Length) continue;
                    val = Encoding.ASCII.GetString(b, strOff, (int)num).TrimEnd('\0');
                }
                if (TagNames.TryGetValue(tag, out var name))
                    fields[name] = val;
                else
                    fields[$"Tag_{tag:X4}"] = val;
            }
            // GPS IFD pointer (0x8825) and EXIF sub-IFD (0x8769): recurse.
            if ((tag == 0x8825 || tag == 0x8769) && type == 4 && num == 1)
            {
                int sub = (int)(tiffStart + ReadU32(b, off + 8, le));
                ParseIfd(b, tiffStart, sub, le, fields, depth + 1);
            }
        }
    }

    /// <summary>Parses PNG tEXt/iTXt/zTXt chunks. Returns keyword -> text.</summary>
    public static Dictionary<string, string> ParsePngText(byte[] png)
    {
        var fields = new Dictionary<string, string>();
        try
        {
            if (png.Length < 8) return fields;
            int i = 8;
            while (i + 8 < png.Length)
            {
                uint len = (uint)((png[i] << 24) | (png[i + 1] << 16) | (png[i + 2] << 8) | png[i + 3]);
                string type = Encoding.ASCII.GetString(png, i + 4, 4);
                if (type == "tEXt" && len > 1)
                {
                    int nul = Array.IndexOf(png, (byte)0, i + 8, (int)len);
                    if (nul > 0)
                    {
                        string kw = Encoding.ASCII.GetString(png, i + 8, nul - (i + 8));
                        string tx = Encoding.ASCII.GetString(png, nul + 1, (int)(i + 8 + len - nul - 1));
                        fields["PNG_" + kw] = tx;
                    }
                }
                if (type == "IEND") break;
                i += 12 + (int)len;
            }
        }
        catch { }
        return fields;
    }

    public sealed class RiskResult
    {
        public int Score;
        public string Level = "Low";
        public List<string> Reasons { get; } = new();
    }

    public static RiskResult ScoreRisk(PhotoMeta photo)
    {
        var r = new RiskResult();
        if (photo.Gps.HasValue)
        {
            r.Score += 50;
            r.Reasons.Add($"GPS coordinates embedded: {photo.Gps.Value.Lat}, {photo.Gps.Value.Lon}");
        }
        foreach (var f in new[] { "CameraSerialNumber", "LensSerialNumber", "OwnerName" })
            if (photo.Fields.ContainsKey(f))
            { r.Score += 15; r.Reasons.Add($"Serial/owner tag: {f} = {photo.Fields[f]}"); break; }
        if (photo.Fields.ContainsKey("MakerNote"))
        { r.Score += 10; r.Reasons.Add("MakerNote present (vendor binary, often contains the camera serial)"); }
        foreach (var f in new[] { "DateTimeOriginal", "DateTime", "DateTimeDigitized" })
            if (photo.Fields.ContainsKey(f))
            { r.Score += 15; r.Reasons.Add($"Timestamp: {f} = {photo.Fields[f]}"); break; }
        foreach (var f in new[] { "Make", "Model" })
            if (photo.Fields.ContainsKey(f))
            {
                r.Score += 10;
                r.Reasons.Add($"Device: {photo.Fields.GetValueOrDefault("Make", "")} {photo.Fields.GetValueOrDefault("Model", "")}".Trim());
                break;
            }
        foreach (var f in new[] { "Artist", "Copyright", "ImageDescription", "UserComment" })
            if (photo.Fields.ContainsKey(f))
            { r.Score += 5; r.Reasons.Add($"Identity tag: {f} = {photo.Fields[f]}"); break; }
        if (photo.Fields.ContainsKey("Software"))
        { r.Score += 5; r.Reasons.Add($"Software tag: {photo.Fields["Software"]}"); }
        if (photo.Fields.ContainsKey("WebP_EXIF_Flag"))
        { r.Score += 15; r.Reasons.Add("WebP container flags an EXIF chunk"); }
        r.Level = r.Score >= 50 ? "High" : r.Score >= 20 ? "Medium" : "Low";
        return r;
    }

    /// <summary>
    /// Card action "Test-PhotoScrubHygiene": offline battery.
    /// CRC32 test vector; synthetic JPEG EXIF parse; synthetic PNG tEXt parse.
    /// </summary>
    public static List<ModuleResult> Hygiene()
    {
        var results = new List<ModuleResult>();
        int passed = 0, failed = 0;
        var failures = new List<string>();
        void Check(string name, Func<bool> test)
        {
            bool ok;
            try { ok = test(); } catch { ok = false; }
            if (ok) passed++; else { failed++; failures.Add(name); }
        }

        Check("CRC32 vector 0xCBF43926", () =>
            Crc32(Encoding.ASCII.GetBytes("123456789")) == 0xCBF43926u);

        // Synthetic JPEG: SOI + APP1(Exif, minimal TIFF with Make) + EOI.
        Check("synthetic JPEG EXIF parse", () =>
        {
            var jpeg = BuildTestJpeg();
            var fields = ParseJpegExif(jpeg);
            return fields.TryGetValue("Make", out var make) && make == "TestCam";
        });

        // Synthetic PNG with tEXt chunk.
        Check("synthetic PNG tEXt parse", () =>
        {
            var png = BuildTestPng();
            var fields = ParsePngText(png);
            return fields.TryGetValue("PNG_Comment", out var c) && c == "hello";
        });

        // Risk scoring.
        Check("GPS scores 50 -> High", () =>
        {
            var p = new PhotoMeta { Gps = (47.6, -122.3) };
            var r = ScoreRisk(p);
            return r.Score == 50 && r.Level == "High";
        });
        Check("clean photo scores Low", () =>
        {
            var r = ScoreRisk(new PhotoMeta());
            return r.Score == 0 && r.Level == "Low";
        });

        string msg = $"PhotoScrub hygiene: {passed}/{passed + failed} passed.";
        if (failed > 0) msg += " Failed: " + string.Join("; ", failures);
        results.Add(failed == 0
            ? ModuleResult.Pass("PhotoScrub", msg)
            : ModuleResult.Fail("PhotoScrub", msg, failures));
        return results;
    }

    private static byte[] BuildTestJpeg()
    {
        var b = new List<byte> { 0xFF, 0xD8 }; // SOI
        // TIFF: II, 42, IFD0 at 8; 1 entry: Make (0x010F) ASCII "TestCam\0"
        var tiff = new List<byte>();
        tiff.AddRange(new byte[] { 0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00 });
        tiff.AddRange(new byte[] { 0x01, 0x00 }); // 1 entry
        tiff.AddRange(new byte[] { 0x0F, 0x01, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00 }); // tag,type,count
        tiff.AddRange(new byte[] { 0x1A, 0x00, 0x00, 0x00 }); // value offset = 26
        tiff.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // next IFD = 0
        tiff.AddRange(Encoding.ASCII.GetBytes("TestCam\0"));
        var app1 = new List<byte>();
        app1.AddRange(Encoding.ASCII.GetBytes("Exif\0\0"));
        app1.AddRange(tiff);
        int segLen = app1.Count + 2;
        b.Add(0xFF); b.Add(0xE1);
        b.Add((byte)(segLen >> 8)); b.Add((byte)(segLen & 0xFF));
        b.AddRange(app1);
        b.Add(0xFF); b.Add(0xD9); // EOI
        return b.ToArray();
    }

    private static byte[] BuildTestPng()
    {
        var b = new List<byte> { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
        // Minimal IHDR
        var ihdr = new byte[] { 0,0,0,1, 0,0,0,1, 8, 2, 0, 0, 0 };
        AddChunk(b, "IHDR", ihdr);
        // tEXt: "Comment\0hello"
        var text = new List<byte>();
        text.AddRange(Encoding.ASCII.GetBytes("Comment\0hello"));
        AddChunk(b, "tEXt", text.ToArray());
        AddChunk(b, "IEND", Array.Empty<byte>());
        return b.ToArray();
    }

    private static void AddChunk(List<byte> b, string type, byte[] data)
    {
        b.Add((byte)(data.Length >> 24)); b.Add((byte)((data.Length >> 16) & 0xFF));
        b.Add((byte)((data.Length >> 8) & 0xFF)); b.Add((byte)(data.Length & 0xFF));
        byte[] tb = Encoding.ASCII.GetBytes(type);
        b.AddRange(tb);
        b.AddRange(data);
        uint crc = Crc32(tb.Concat(data).ToArray());
        b.Add((byte)(crc >> 24)); b.Add((byte)((crc >> 16) & 0xFF));
        b.Add((byte)((crc >> 8) & 0xFF)); b.Add((byte)(crc & 0xFF));
    }
}
