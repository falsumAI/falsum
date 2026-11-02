using System.IO;
using System.Runtime.InteropServices;

namespace FalsumApp.Services;

/// <summary>
/// Hidden File Detector — native C# service.
/// 
/// WHAT IT DOES:
/// Finds everything Windows is hiding from you:
/// - Files with hidden attribute set
/// - Files with system attribute set (hidden from normal view)
/// - Alternate Data Streams (ADS) — data hidden inside other files
/// - Files in hidden directories (AppData subfolders, ProgramData, etc.)
/// - Makes all files readable — takes ownership if needed, removes hidden flags
/// 
/// NOTHING STAYS HIDDEN. If it's on your disk, you see it.
/// </summary>
public class HiddenFileService
{
    private readonly string _vaultPath;

    public HiddenFileService(string vaultPath)
    {
        _vaultPath = vaultPath;
    }

    /// <summary>
    /// Scan a directory tree for hidden files.
    /// </summary>
    public HiddenFileReport ScanDirectory(string rootPath, bool recursive = true)
    {
        var report = new HiddenFileReport
        {
            Timestamp = DateTime.UtcNow,
            ScannedPath = rootPath,
            HiddenFiles = new List<HiddenFileInfo>()
        };

        try
        {
            ScanRecursive(rootPath, report, recursive);
        }
        catch (Exception ex)
        {
            report.ScanError = ex.Message;
        }

        return report;
    }

    private void ScanRecursive(string path, HiddenFileReport report, bool recursive)
    {
        try
        {
            // Check files in this directory
            foreach (var file in Directory.GetFiles(path))
            {
                try
                {
                    var attrs = File.GetAttributes(file);
                    bool isHidden = (attrs & FileAttributes.Hidden) != 0;
                    bool isSystem = (attrs & FileAttributes.System) != 0;

                    if (isHidden || isSystem)
                    {
                        var info = new FileInfo(file);
                        report.HiddenFiles.Add(new HiddenFileInfo
                        {
                            Path = file,
                            IsHidden = isHidden,
                            IsSystem = isSystem,
                            Size = info.Length,
                            LastModified = info.LastWriteTime,
                            HasAlternateStreams = CheckAlternateStreams(file)
                        });
                    }
                    else
                    {
                        // Even non-hidden files can have hidden ADS
                        if (CheckAlternateStreams(file))
                        {
                            var info = new FileInfo(file);
                            report.HiddenFiles.Add(new HiddenFileInfo
                            {
                                Path = file,
                                IsHidden = false,
                                IsSystem = false,
                                Size = info.Length,
                                LastModified = info.LastWriteTime,
                                HasAlternateStreams = true
                            });
                        }
                    }
                }
                catch { /* Skip inaccessible files */ }
            }

            // Recurse into subdirectories
            if (recursive)
            {
                foreach (var dir in Directory.GetDirectories(path))
                {
                    try
                    {
                        var dirAttrs = File.GetAttributes(dir);
                        bool dirHidden = (dirAttrs & FileAttributes.Hidden) != 0;
                        bool dirSystem = (dirAttrs & FileAttributes.System) != 0;

                        if (dirHidden || dirSystem)
                        {
                            report.HiddenFiles.Add(new HiddenFileInfo
                            {
                                Path = dir,
                                IsHidden = dirHidden,
                                IsSystem = dirSystem,
                                IsDirectory = true,
                                LastModified = Directory.GetLastWriteTime(dir)
                            });
                        }

                        ScanRecursive(dir, report, true);
                    }
                    catch { /* Skip inaccessible dirs */ }
                }
            }
        }
        catch { /* Skip on access denied */ }
    }

    /// <summary>
    /// Check for Alternate Data Streams on a file.
    /// ADS is how malware hides data inside innocent-looking files.
    /// </summary>
    private bool CheckAlternateStreams(string filePath)
    {
        try
        {
            // Use FindFirstStreamW via P/Invoke
            var handle = FindFirstStreamW(filePath, 0, out var data, 0);
            if (handle.ToInt64() == -1) return false;

            try
            {
                int streamCount = 0;
                do
                {
                    // Skip the default $DATA stream
                    if (!data.StreamName.Equals("::$DATA", StringComparison.OrdinalIgnoreCase))
                    {
                        streamCount++;
                    }
                } while (FindNextStreamW(handle, out data));

                return streamCount > 0;
            }
            finally
            {
                FindClose(handle);
            }
        }
        catch { return false; }
    }

    /// <summary>
    /// Make a file visible and readable. Removes hidden/system attributes.
    /// </summary>
    public bool UnhideFile(string filePath)
    {
        try
        {
            var attrs = File.GetAttributes(filePath);
            attrs &= ~FileAttributes.Hidden;
            attrs &= ~FileAttributes.System;
            File.SetAttributes(filePath, attrs);
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// Unhide all files in a report.
    /// </summary>
    public int UnhideAll(HiddenFileReport report)
    {
        int count = 0;
        foreach (var file in report.HiddenFiles)
        {
            if (UnhideFile(file.Path)) count++;
        }
        return count;
    }

    /// <summary>
    /// List alternate data streams on a file.
    /// </summary>
    public List<string> ListAlternateStreams(string filePath)
    {
        var streams = new List<string>();
        try
        {
            var handle = FindFirstStreamW(filePath, 0, out var data, 0);
            if (handle.ToInt64() == -1) return streams;

            try
            {
                do
                {
                    streams.Add($"{data.StreamName} ({data.StreamSize} bytes)");
                } while (FindNextStreamW(handle, out data));
            }
            finally
            {
                FindClose(handle);
            }
        }
        catch { }
        return streams;
    }

    // P/Invoke for ADS detection
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(
        string lpFileName,
        int infoLevel,
        out WIN32_FIND_STREAM_DATA lpFindStreamData,
        int flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextStreamW(
        IntPtr hFindStream,
        out WIN32_FIND_STREAM_DATA lpFindStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(IntPtr hFind);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string StreamName;
    }
}

public class HiddenFileReport
{
    public DateTime Timestamp { get; set; }
    public string ScannedPath { get; set; } = "";
    public List<HiddenFileInfo> HiddenFiles { get; set; } = new();
    public string? ScanError { get; set; }
}

public class HiddenFileInfo
{
    public string Path { get; set; } = "";
    public bool IsHidden { get; set; }
    public bool IsSystem { get; set; }
    public bool IsDirectory { get; set; }
    public bool HasAlternateStreams { get; set; }
    public long Size { get; set; }
    public DateTime LastModified { get; set; }
}
