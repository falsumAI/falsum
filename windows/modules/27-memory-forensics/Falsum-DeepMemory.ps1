<#
.SYNOPSIS
    Deep Memory Reader — P/Invoke to actually read RAM.
    Separate file to avoid breaking the main module.
#>

# Only define if not already defined (avoid redefinition errors)
if (-not ([System.Management.Automation.PSTypeName]'MemReader').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class MemReader {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesRead);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
}
"@ -ErrorAction SilentlyContinue
}

function Read-ProcessMemoryBytes {
    <#
    .SYNOPSIS
        Read raw bytes from a process's memory. Deep RAM access.
    #>
    param(
        [int]$ProcessId,
        [string]$HexAddress,
        [int]$Length = 256
    )
    try {
        $hProcess = [MemReader]::OpenProcess(0x0010 -bor 0x0400, $false, [uint32]$ProcessId)
        if ($hProcess -eq [IntPtr]::Zero) { return $null }
        
        $addr = [Convert]::ToInt64($HexAddress, 16)
        $buffer = New-Object byte[] $Length
        [uint32]$read = 0
        $ok = [MemReader]::ReadProcessMemory($hProcess, [IntPtr]::new($addr), $buffer, [uint32]$Length, [ref]$read)
        [MemReader]::CloseHandle($hProcess) | Out-Null
        
        if ($ok -and $read -gt 0) {
            return $buffer[0..($read-1)]
        }
        return $null
    }
    catch { return $null }
}

function Search-MemoryForString {
    <#
    .SYNOPSIS
        Search process memory for a string pattern.
    #>
    param(
        [int]$ProcessId,
        [string]$Pattern,
        [int]$MaxMB = 10
    )
    # This is a simplified version - full implementation would enumerate regions
    # For now, returns empty (placeholder for full VirtualQueryEx implementation)
    Write-Warning "Full memory search requires VirtualQueryEx enumeration - not yet implemented"
    return @()
}
