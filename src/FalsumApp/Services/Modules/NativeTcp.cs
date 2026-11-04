// Native TCP listener enumeration via GetExtendedTcpTable (iphlpapi).
// Replaces Get-NetTCPConnection from the Port Gate .ps1 module.
// Returns listeners WITH owning PIDs, which IPGlobalProperties alone cannot do.
using System.Net;
using System.Runtime.InteropServices;

namespace FalsumApp.Services.Modules;

internal sealed record TcpListenerInfo(IPAddress LocalAddress, int LocalPort, int ProcessId, string ProcessName);

internal static class NativeTcp
{
    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint MIB_TCP_STATE_LISTEN = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    public static List<TcpListenerInfo> GetListeners()
    {
        var result = new List<TcpListenerInfo>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return result;

        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            uint ret = GetExtendedTcpTable(buf, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return result;

            int count = Marshal.ReadInt32(buf);
            IntPtr rowPtr = IntPtr.Add(buf, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                if (row.state == MIB_TCP_STATE_LISTEN)
                {
                    // Port is stored big-endian in the DWORD.
                    int port = (int)(((row.localPort >> 8) & 0xFF) | ((row.localPort << 8) & 0xFF00));
                    int pid = (int)row.owningPid;
                    string name = "";
                    try { name = System.Diagnostics.Process.GetProcessById(pid).ProcessName; }
                    catch { /* exited or access denied: leave unnamed */ }
                    result.Add(new TcpListenerInfo(new IPAddress(row.localAddr), port, pid, name));
                }
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return result;
    }
}
