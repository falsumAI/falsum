// Module 27: Memory Forensics. Faithful C# port of Falsum-MemoryForensics.ps1 /
// Falsum-DeepMemory.ps1. Native P/Invoke memory reader (ReadProcessMemory)
// plus a process-memory overview for the card action.
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace FalsumApp.Services.Modules;

public static class MemoryForensicsModule
{
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>Read raw bytes from a process's memory. Returns null on failure.</summary>
    public static byte[]? ReadProcessMemoryBytes(int processId, string hexAddress, int length = 256)
    {
        IntPtr h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, (uint)processId);
        if (h == IntPtr.Zero) return null;
        try
        {
            long addr = Convert.ToInt64(hexAddress.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? hexAddress[2..] : hexAddress, 16);
            var buffer = new byte[length];
            bool ok = ReadProcessMemory(h, new IntPtr(addr), buffer, (uint)length, out uint read);
            if (ok && read > 0)
            {
                var result = new byte[read];
                Array.Copy(buffer, result, read);
                return result;
            }
            return null;
        }
        catch { return null; }
        finally { CloseHandle(h); }
    }

    /// <summary>
    /// Card action "Read-ProcessMemoryBytes" (no args): process-memory overview.
    /// Flags processes with no executable path or unreadable images — the
    /// user-mode-visible part of "what's hiding."
    /// </summary>
    public static List<ModuleResult> Overview()
    {
        var results = new List<ModuleResult>();
        int checkedCount = 0;
        int hidden = 0;
        var samples = new List<string>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                checkedCount++;
                string? path = null;
                try { path = p.MainModule?.FileName; } catch { }
                if (string.IsNullOrEmpty(path))
                {
                    hidden++;
                    if (samples.Count < 10) samples.Add($"{p.ProcessName} (PID {p.Id})");
                }
                p.Dispose();
            }
            catch { }
        }
        string msg = $"{checkedCount} processes checked. {hidden} with no visible image path.";
        if (hidden > 0) msg += " Sample: " + string.Join("; ", samples);
        results.Add(hidden == 0
            ? ModuleResult.Pass("MemoryForensics", msg)
            : ModuleResult.Fail("MemoryForensics", msg));
        return results;
    }
}
