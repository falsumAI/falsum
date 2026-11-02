<#
.SYNOPSIS
    Falsum Active Defense — the retributive/forensic arm of the tool.
    (Poison pill for the "managed threat response" subscription tier: they
    charge per incident to investigate and report; this investigates,
    builds the abuse pack, and blocks the actor locally, for nothing.)

.DESCRIPTION
    All work happens on the user's OWN machine and network — the user is
    sovereign there. This module never touches anyone else's system. It:

      Start-Backtrace      passive look-back at a hostile IP: TCP port
                           probes, banners, reverse DNS, RDAP record,
                           RDAP abuse-contact extraction — an evidence
                           report, not a probe of a system we have no
                           business in.
      Get-AbuseContact     pulls the published abuse-desk email/name from
                           the IP's RDAP "abuse" role, so New-AbusePack
                           files to the right desk.
      Get-SuspiciousPortTable
                           the threat-hunt indicator table as one shared
                           object — the hunt and the self-test read the
                           same rows, so they cannot drift apart.
      Get-EstablishedSession
                           lists ESTABLISHED TCP connections with process
                           names — the local view of hostile sessions.
      Close-TcpConnection  kills the INDIVIDUAL TCP connection (SetTcpEntry
                           P/Invoke, admin) instead of the whole process —
                           the precise fix when a browser tab, not the
                           browser, is the problem.
      Stop-HostileSession  kills a hostile session by process or remote
                           address. LOCAL ONLY. Requires admin + confirm.
                           -CloseOnly closes connections instead of
                           killing processes.
      New-AbusePack        builds an abuse-report bundle for an IP,
                           addressed to the RDAP abuse contact: backtrace
                           report, trap/vault evidence excerpts, SHA-256
                           manifest, zipped and ready to file.
      Add-BadActor         permanent mark: JSON blocklist + Windows
                           Defender Firewall inbound block rule
                           (Gregg's requirement: the mark follows them —
                           the blocklist exports as CSV or JSON so the mark
                           can be shared and re-applied anywhere).
      Test-IsMarked        one-line membership check against the blocklist.
      Get-DefenseSummary   marked actors, enforced firewall rules, live
                           sessions, elevation state — one screen.
      Remove-BadActor / Get-BadActorList / Export-BadActorList
                           manage the list.
      ConvertTo-DefenseIpTarget
                           parses "ip", "ip:port", "[ip]:port" — users paste
                           targets with ports; every public function
                           normalizes BEFORE validating, so a pasted
                           "8.8.8.8:443" no longer dies in Test-ValidIp.
      Get-DefenseOutDir    evidence-dir picker that never returns empty:
                           MyDocuments can resolve empty (Server Core /
                           redirected profiles — the bug class mail-shield,
                           fraud-pack and php-shield already fixed), so the
                           chain is MyDocuments -> CommonApplicationData ->
                           repo-relative fallback.
      Get-BacktracePortTable
                           the 43-port backtrace probe table as ONE shared
                           object (Start-Backtrace defaults to it; the
                           hygiene battery validates the same object — the
                           table the scan uses is the table the test reads).
      Confirm-ProcessTerminated / Confirm-SessionClosed
                           Better-Way Law proofs: a kill/close that ships no
                           verification is a claim, not a fix. Stop/Close
                           paths verify the termination actually took
                           effect and report VERIFIED vs STILL-RUNNING.

    THE BETTER-WAY LAW: a detection ships its fix. The fix here is
    Stop-HostileSession (kill what is on my wire) + Add-BadActor (block
    the IP at my firewall and mark it permanently) + New-AbusePack (give
    the abuse desk a ready-to-send case, because evidence that doesn't
    get filed is evidence that doesn't exist).

    MANUAL TRIGGER ONLY. Nothing here runs on a schedule or fires on its
    own. Every destructive action (kill, block) is admin-gated and asks
    for explicit confirmation.

    LEGAL LINE (printed on load, also at the top of every report this
    module emits): unauthorized access to someone else's system is a
    federal crime under the CFAA even if they attacked first. This module
    observes, documents, blocks locally, and files reports. It never
    counter-attacks.

    PowerShell 5.1 compatible. Zero external dependencies. All vault
    entries go through Add-VaultEntry with type "active-defense".

.USAGE
    . .\Falsum-ActiveDefense.ps1
    Start-Backtrace -IpAddress 45.155.206.13 -VaultPath "C:\Falsum\vault"
    Get-EstablishedSession
    Close-TcpConnection -RemoteAddress 45.155.206.13
    Stop-HostileSession -RemoteAddress 45.155.206.13 -CloseOnly -Confirm:$false
    New-AbusePack -IpAddress 45.155.206.13 -EvidenceDir "C:\Falsum\abuse"
    Add-BadActor -IpAddress 45.155.206.13 -Reason "SSH brute-force on trap" -Evidence "traps port 2222 log"
    Test-IsMarked -IpAddress 45.155.206.13
    Get-DefenseSummary
    Export-BadActorList -Path "C:\Falsum\badactors.csv"
    Export-BadActorList -Path "C:\Falsum\badactors.json" -AsJson
    (IPs above are examples — substitute the real hostile IP.)
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# THE LEGAL LINE. Read it. It is the whole ethic of this module.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "==============================================================================" -ForegroundColor DarkRed
Write-Host "  LEGAL: unauthorized access to someone else's system is a federal crime" -ForegroundColor Red
Write-Host "  under the CFAA even if they attacked first. This module observes, documents," -ForegroundColor Red
Write-Host "  blocks locally, and files abuse reports. It never counter-attacks." -ForegroundColor Red
Write-Host "==============================================================================" -ForegroundColor DarkRed
Write-Host ""

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
$script:ModuleDir     = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:VaultModule   = Join-Path (Join-Path $script:ModuleDir '..\12-timeline-vault') 'Falsum-Vault.ps1'
$script:NetScanModule = Join-Path (Join-Path $script:ModuleDir '..\03-netscan') 'Falsum-NetScan.ps1'
$script:OsintModule   = Join-Path (Join-Path $script:ModuleDir '..\04-osint-attribution') 'Falsum-Osint.ps1'
$script:VaultLoaded   = $false
$script:NetScanLoaded = $false
$script:OsintLoaded   = $false

function Import-VaultModule {
    # Mirrors the pattern in Falsum-Traps.ps1: dot-source the vault once.
    if ($script:VaultLoaded) { return $true }
    if (-not (Test-Path $script:VaultModule)) {
        Write-Host "  [!] Vault module not found at $($script:VaultModule); events will not be vault-logged." -ForegroundColor DarkYellow
        return $false
    }
    try {
        . $script:VaultModule
        $script:VaultLoaded = $true
        return $true
    } catch {
        Write-Host "  [!] Failed to load vault module: $_" -ForegroundColor DarkYellow
        return $false
    }
}

function Import-NetScanModule {
    if ($script:NetScanLoaded) { return $true }
    if (-not (Test-Path $script:NetScanModule)) { return $false }
    try { . $script:NetScanModule; $script:NetScanLoaded = $true; return $true }
    catch { return $false }
}

function Import-OsintModule {
    if ($script:OsintLoaded) { return $true }
    if (-not (Test-Path $script:OsintModule)) { return $false }
    try { . $script:OsintModule; $script:OsintLoaded = $true; return $true }
    catch { return $false }
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch { return $false }
}

function Get-Sha256HexA {
    param([Parameter(Mandatory=$true)][string]$text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $hash  = (New-Object System.Security.Cryptography.SHA256Managed).ComputeHash($bytes)
    return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLower()
}

function Write-VaultDefenseEvent {
    param(
        [Parameter(Mandatory=$true)][string]$VaultPath,
        [Parameter(Mandatory=$true)][string]$EventName,
        [Parameter(Mandatory=$true)]$Data
    )
    # Best-effort vault logging: never fails the operation it records.
    try {
        if (-not (Import-VaultModule)) { return $false }
        $vault = New-Vault -path $VaultPath
        Add-VaultEntry -vault $vault -type "active-defense" -data (@{ event = $EventName; payload = $Data }) | Out-Null
        return $true
    } catch {
        Write-Host "  [!] Vault logging failed (non-fatal): $_" -ForegroundColor DarkYellow
        return $false
    }
}

# ---------------------------------------------------------------------------
# Get-DefenseOutDir — an evidence dir that NEVER comes back empty.
# Bug class mail-shield v1.2 / fraud-pack v1.1 / php-shield v1.3 fixed:
# [Environment]::GetFolderPath('MyDocuments') can resolve empty on
# Server Core or redirected profiles, and Join-Path with an empty parent
# silently builds a RELATIVE path the user never finds. Fallback chain:
# MyDocuments\Falsum\evidence -> CommonApplicationData\Falsum\evidence
# -> repo-relative .\Falsum-evidence. -DocumentsDir/-CommonAppDataDir
# are injectable so the offline battery can prove every branch.
# ---------------------------------------------------------------------------
function Get-DefenseOutDir {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)][string]$DocumentsDir = "",
        [Parameter(Mandatory=$false)][string]$CommonAppDataDir = ""
    )
    if ($DocumentsDir -eq "") {
        try { $DocumentsDir = [Environment]::GetFolderPath('MyDocuments') } catch { $DocumentsDir = "" }
    }
    if (-not [string]::IsNullOrWhiteSpace($DocumentsDir)) {
        return (Join-Path $DocumentsDir 'Falsum\evidence')
    }
    if ($CommonAppDataDir -eq "") {
        try { $CommonAppDataDir = [Environment]::GetFolderPath('CommonApplicationData') } catch { $CommonAppDataDir = "" }
    }
    if (-not [string]::IsNullOrWhiteSpace($CommonAppDataDir)) {
        return (Join-Path $CommonAppDataDir 'Falsum\evidence')
    }
    return (Join-Path $script:ModuleDir '..\..\Falsum-evidence')
}

function Test-ValidIp {
    param([Parameter(Mandatory=$true)][string]$Ip)
    try {
        $addr = [System.Net.IPAddress]::Parse($Ip)
        # IPv4 only for this module's tooling (firewall rules, SetTcpEntry).
        if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
        # Refuse localhost / loopback: a backtrace of 127.0.0.1 is a
        # backtrace of yourself — pointless.
        if ([System.Net.IPAddress]::IsLoopback($addr)) { return $false }
        $b = $addr.GetAddressBytes()
        # Refuse ranges that are never real remote attackers:
        #   0.0.0.0/8        "this network"
        #   192.0.2.0/24     TEST-NET-1 (documentation)
        #   198.51.100.0/24  TEST-NET-2 (documentation)
        #   203.0.113.0/24   TEST-NET-3 (documentation)
        #   192.0.0.0/24     IETF protocol assignments
        #   192.88.99.0/24   6to4 relay (deprecated)
        #   224.0.0.0/4      multicast — no unicast backtrace exists
        #   240.0.0.0/4      reserved for future use
        #   169.254.0.0/16   link-local — never a real remote attacker
        #   100.64.0.0/10    CGNAT shared space — ISP-internal, never the attacker
        if ($b[0] -eq 0) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -eq 2) { return $false }
        if ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) { return $false }
        if ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -eq 0) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 88 -and $b[2] -eq 99) { return $false }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
        if ($b[0] -eq 100 -and (($b[1] -band 0xC0) -eq 64)) { return $false }
        if ($b[0] -ge 224) { return $false }
        # Private LAN ranges stay ALLOWED: real attacks come from the LAN too.
        return $true
    } catch { return $false }
}

# ---------------------------------------------------------------------------
# ConvertTo-NetworkByteOrderPort — htons for SetTcpEntry. MIB_TCPROW stores
# ports as a DWORD equal to htons(port): port 80 -> 0x5000 (20480),
# port 443 -> 0xBB01 (47873). A naive "port shl 8" is wrong (off by the
# low byte); this does the true byte swap.
# ---------------------------------------------------------------------------
function ConvertTo-NetworkByteOrderPort {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][int]$Port)
    if ($Port -lt 0 -or $Port -gt 65535) { throw "Port out of range: $Port" }
    return [uint32](((($Port -band 0xFF) -shl 8) -bor (($Port -shr 8) -band 0xFF)) -band 0xFFFF)
}

# ---------------------------------------------------------------------------
# ConvertTo-DefenseIpTarget — pure parser. Users paste targets as "ip",
# "ip:port" or "[ip]:port" (copied from logs, netstat, alerts); before
# v1.3 every one of those strings died inside Test-ValidIp with "not a
# routable remote IP". Every public function normalizes FIRST, then
# validates. Pure: no network, no admin. The parser is SYNTACTIC only —
# "notanip:80" parses Ok with Ip="notanip"; Test-ValidIp still does the
# semantic gate afterwards. Port 1-65535 or absent; anything else is
# Ok=$false (never a guess).
# ---------------------------------------------------------------------------
function ConvertTo-DefenseIpTarget {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Target)
    $t = "$Target".Trim()
    # Strip one layer of IPv6-style brackets: [8.8.8.8]:443
    if ($t.StartsWith('[') -and $t.Contains(']')) {
        $closeIdx = $t.IndexOf(']')
        $ipPart = $t.Substring(1, $closeIdx - 1).Trim()
        $rest = $t.Substring($closeIdx + 1).Trim()
        if ($rest -eq "") {
            return [pscustomobject]@{ Ok = $true; Ip = $ipPart; Port = 0 }
        }
        if ($rest -match '^\s*:\s*(\d{1,5})\s*$') {
            $p = [int]$Matches[1]
            if ($p -ge 1 -and $p -le 65535) {
                return [pscustomobject]@{ Ok = $true; Ip = $ipPart; Port = $p }
            }
        }
        return [pscustomobject]@{ Ok = $false; Ip = ""; Port = 0 }
    }
    # Plain "ip" or "ip:port". A trailing colon with no digits ("8.8.8.8:")
    # fails the match -> Ok=$false (never silently treated as "any port").
    if ($t -match '^(?<ip>[^:\[\]]+?)(?::(?<port>\d{1,5}))?$') {
        $ipPart = $Matches['ip'].Trim()
        $portPart = "$($Matches['port'])"
        if ($ipPart -eq "") {
            return [pscustomobject]@{ Ok = $false; Ip = ""; Port = 0 }
        }
        if ($portPart -eq "") {
            return [pscustomobject]@{ Ok = $true; Ip = $ipPart; Port = 0 }
        }
        $p = [int]$portPart
        if ($p -ge 1 -and $p -le 65535) {
            return [pscustomobject]@{ Ok = $true; Ip = $ipPart; Port = $p }
        }
        return [pscustomobject]@{ Ok = $false; Ip = ""; Port = 0 }
    }
    return [pscustomobject]@{ Ok = $false; Ip = ""; Port = 0 }
}

# ---------------------------------------------------------------------------
# Get-AbuseContact — the missing link for filing. Pulls the published
# abuse-desk email (and name) from the IP's RDAP "abuse" role via rdap.org.
# Read-only HTTPS, no auth, no account. This is what makes New-AbusePack
# address the letter to a real desk instead of a blank page.
# ---------------------------------------------------------------------------
function Get-AbuseContact {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$IpAddress)
    $contacts = @()
    try {
        $resp = Invoke-RestMethod -Uri "https://rdap.org/ip/$IpAddress" -TimeoutSec 15 `
            -UserAgent "Falsum-ActiveDefense/1.0"
        foreach ($ent in @($resp.entities)) {
            if ($null -eq $ent) { continue }
            if (@($ent.roles) -notcontains 'abuse') { continue }
            $fn = ""; $email = ""
            foreach ($v in @($ent.vcardArray)) {
                if ($v -is [System.Collections.IList] -and $v.Count -gt 1) {
                    foreach ($prop in @($v[1])) {
                        if ($prop -is [System.Collections.IList] -and $prop.Count -ge 4) {
                            $name = "$($prop[0])".ToLower()
                            if ($name -eq 'fn' -and $fn -eq "") { $fn = "$($prop[3])" }
                            if ($name -eq 'email' -and $email -eq "") { $email = "$($prop[3])" }
                        }
                    }
                }
            }
            if ($email -ne "" -or $fn -ne "") {
                $contacts += [pscustomobject]@{ email = $email; fn = $fn }
            }
        }
        if ($contacts.Count -eq 0) {
            Write-Host "  [i] No RDAP 'abuse' role published for $IpAddress." -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [!] Abuse-contact lookup failed (non-fatal): $_" -ForegroundColor DarkYellow
    }
    return @($contacts)
}

# ---------------------------------------------------------------------------
# Confirm-ProcessTerminated — the PROOF for Stop-HostileSession. A kill
# that ships no verification is a claim, not a fix (Better-Way Law):
# after Stop-Process, poll Get-Process for up to -TimeoutSec seconds and
# say VERIFIED or STILL-RUNNING. A PID Get-Process can no longer see is
# treated as terminated. Pure-ish: no admin, read-only.
# ---------------------------------------------------------------------------
function Confirm-ProcessTerminated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][int]$ProcessId,
        [Parameter(Mandatory=$false)][int]$TimeoutSec = 5
    )
    try {
        $deadline = (Get-Date).AddSeconds($TimeoutSec)
        do {
            try {
                $null = Get-Process -Id $ProcessId -ErrorAction Stop
                Start-Sleep -Milliseconds 500
            } catch {
                return $true   # process object gone = terminated
            }
        } while ((Get-Date) -lt $deadline)
        return $false          # still visible after the whole window
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Confirm-SessionClosed — the PROOF for Close-TcpConnection. Re-queries
# the established sessions (up to 3 polls, 1s apart) and confirms the
# (remote, port, pid) tuple is gone. Returns $false when enumeration
# itself fails — "could not verify" is a finding, never a pass.
# ---------------------------------------------------------------------------
function Confirm-SessionClosed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$RemoteAddress,
        [Parameter(Mandatory=$false)][int]$RemotePort = 0,
        [Parameter(Mandatory=$false)][int]$ProcessId = 0
    )
    for ($i = 0; $i -lt 3; $i++) {
        try {
            $sess = @(Get-EstablishedSession -RemoteAddress $RemoteAddress)
        } catch {
            return $false
        }
        if ($RemotePort -gt 0) { $sess = @($sess | Where-Object { $_.RemotePort -eq $RemotePort }) }
        if ($ProcessId -gt 0)  { $sess = @($sess | Where-Object { $_.ProcessId -eq $ProcessId }) }
        if ($sess.Count -eq 0) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

# ---------------------------------------------------------------------------
# Close-TcpConnection — THE PRECISE FIX. Closes individual ESTABLISHED TCP
# connections (iphlpapi SetTcpEntry, MIB_TCP_STATE_DELETE_TCB) instead of
# killing the whole process. LOCAL ONLY: nothing is sent to the remote end;
# the local TCB entry is torn down, which RSTs the socket. Admin required.
# IPv4 only (MIB_TCPROW is a v4 structure); v6 sessions are skipped with
# a clear note.
# ---------------------------------------------------------------------------
function Close-TcpConnection {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory=$false)][string]$RemoteAddress = "",
        [Parameter(Mandatory=$false)][int]$RemotePort = 0,
        [Parameter(Mandatory=$false)][int]$ProcessId = 0,
        [Parameter(Mandatory=$false)][string]$VaultPath = ""
    )
    if (-not (Test-IsAdmin)) {
        throw "Close-TcpConnection requires elevation: SetTcpEntry is an admin act. Re-run as Administrator."
    }
    # Normalize FIRST, validate second: "8.8.8.8:443" and "[8.8.8.8]:443"
    # are accepted; the port fills -RemotePort when it was not given.
    if ($RemoteAddress -ne "") {
        $tgt = ConvertTo-DefenseIpTarget -Target $RemoteAddress
        if (-not $tgt.Ok) {
            throw "Could not parse '$RemoteAddress' as an IP (optionally ip:port)."
        }
        $RemoteAddress = $tgt.Ip
        if ($RemotePort -eq 0 -and $tgt.Port -gt 0) { $RemotePort = $tgt.Port }
    }
    if ($RemoteAddress -ne "" -and -not (Test-ValidIp $RemoteAddress)) {
        throw "Refusing: '$RemoteAddress' is not a routable remote IP."
    }
    if ($RemoteAddress -eq "" -and $ProcessId -eq 0) {
        throw "Specify -RemoteAddress or -ProcessId. Run Get-EstablishedSession first to see what is on your wire."
    }

    # Load the P/Invoke type once per session (Add-Type errors on reload).
    if (-not ([System.Management.Automation.PSTypeName]'TcpKiller').Type) {
        $cs = @"
using System;
using System.Runtime.InteropServices;
public static class TcpKiller {
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }
    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint SetTcpEntry(ref MIB_TCPROW pTcpRow);
}
"@
        try {
            Add-Type -TypeDefinition $cs -ErrorAction Stop
        } catch {
            throw "Could not load TcpKiller P/Invoke type: $_"
        }
    }

    $sessions = @(Get-EstablishedSession)
    if ($RemoteAddress -ne "") { $sessions = @($sessions | Where-Object { $_.RemoteAddress -eq $RemoteAddress }) }
    if ($RemotePort -gt 0)      { $sessions = @($sessions | Where-Object { $_.RemotePort -eq $RemotePort }) }
    if ($ProcessId -gt 0)       { $sessions = @($sessions | Where-Object { $_.ProcessId -eq $ProcessId }) }
    if ($sessions.Count -eq 0) {
        Write-Host "  No matching established sessions to close." -ForegroundColor Gray
        return @()
    }

    $closed = @()
    foreach ($s in $sessions) {
        try {
            $la = [System.Net.IPAddress]::Parse($s.LocalAddress)
            $ra = [System.Net.IPAddress]::Parse($s.RemoteAddress)
            if ($la.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
                $ra.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                Write-Host "  [i] Skipping non-IPv4 session $($s.RemoteAddress):$($s.RemotePort) (MIB_TCPROW is v4-only)." -ForegroundColor Gray
                continue
            }
            $row = New-Object TcpKiller+MIB_TCPROW
            $row.dwState      = 12  # MIB_TCP_STATE_DELETE_TCB
            $row.dwLocalAddr  = [BitConverter]::ToUInt32($la.GetAddressBytes(), 0)
            $row.dwRemoteAddr = [BitConverter]::ToUInt32($ra.GetAddressBytes(), 0)
            $row.dwLocalPort  = ConvertTo-NetworkByteOrderPort -Port $s.LocalPort
            $row.dwRemotePort = ConvertTo-NetworkByteOrderPort -Port $s.RemotePort
            $desc = "$($s.RemoteAddress):$($s.RemotePort) (PID $($s.ProcessId) $($s.ProcessName))"
            if ($PSCmdlet.ShouldProcess($desc, "Close TCP connection (local TCB teardown)")) {
                $rc = [TcpKiller]::SetTcpEntry([ref]$row)
                if ($rc -eq 0) {
                    Write-Host "  [-] Closed connection $desc" -ForegroundColor Red
                    $closed += $s
                } else {
                    Write-Host "  [!] SetTcpEntry failed for $desc (Win32 error $rc)." -ForegroundColor DarkYellow
                }
            }
        } catch {
            Write-Host "  [!] Close failed for $($s.RemoteAddress):$($s.RemotePort): $_" -ForegroundColor DarkYellow
        }
    }
    # Better-Way Law proof: verify every closed tuple is actually gone, or
    # say so. (Skipped under -WhatIf — nothing happened, nothing to prove.)
    foreach ($s in $closed) {
        try {
            $v = Confirm-SessionClosed -RemoteAddress $s.RemoteAddress -RemotePort $s.RemotePort -ProcessId $s.ProcessId
        } catch { $v = $false }
        $s | Add-Member -NotePropertyName 'Verified' -NotePropertyValue ([bool]$v) -Force
        if ($v) {
            $s | Add-Member -NotePropertyName 'VerifyNote' -NotePropertyValue 'VERIFIED: tuple gone on re-query' -Force
        } else {
            $s | Add-Member -NotePropertyName 'VerifyNote' -NotePropertyValue 'UNVERIFIED: still present on re-query — the socket may have re-established' -Force
        }
    }
    if ($closed.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($VaultPath)) {
        Write-VaultDefenseEvent -VaultPath $VaultPath -EventName "tcp-connections-closed" -Data (@{
            targets = @($closed | ForEach-Object {
                "$($_.RemoteAddress):$($_.RemotePort) PID $($_.ProcessId) ($($_.ProcessName))"
            })
        }) | Out-Null
    }
    return @($closed)
}

# ---------------------------------------------------------------------------
# Get-BacktracePortTable — ONE source of truth for the backtrace probe
# ports (was a 40-port literal buried inside Start-Backtrace, invisible
# to the self-test). The scan defaults to it and the hygiene battery
# validates THIS object — the table the scan uses is the table the test
# reads, so they can never drift apart (same pattern as
# Get-SuspiciousPortTable for the hunt).
# ---------------------------------------------------------------------------
function Get-BacktracePortTable {
    [CmdletBinding()]
    param()
    $rows = @(
        @(21,'ftp','cleartext credential service'),
        @(22,'ssh','brute-force / tunnel target'),
        @(23,'telnet','legacy cleartext, never legitimate'),
        @(25,'smtp','spam-relay abuse surface'),
        @(53,'dns','DNS service'),
        @(80,'http','web admin panels'),
        @(110,'pop3','cleartext mail'),
        @(135,'rpc','Windows RPC lateral-movement surface'),
        @(139,'netbios','legacy Windows sharing'),
        @(143,'imap','cleartext mail'),
        @(443,'https','web admin panels'),
        @(445,'smb','ransomware lateral-movement classic'),
        @(465,'smtps','mail submission'),
        @(587,'smtp-sub','mail submission'),
        @(993,'imaps','mail'),
        @(995,'pop3s','mail'),
        @(1194,'openvpn','VPN endpoint'),
        @(1433,'mssql','database brute force'),
        @(1434,'mssql-udp','SQL Slammer surface'),
        @(1723,'pptp','legacy VPN'),
        @(2375,'docker','unauthenticated Docker API = host takeover'),
        @(2376,'docker-tls','Docker API'),
        @(3306,'mysql','database brute force'),
        @(3389,'rdp','RDP brute force / ransomware entry'),
        @(4444,'metasploit','default Meterpreter listener'),
        @(5432,'postgres','database brute force'),
        @(5555,'adb/hp','Android ADB / HP Data Protector abuse'),
        @(5900,'vnc','VNC brute force'),
        @(5985,'winrm','Windows remote management'),
        @(5986,'winrm-https','Windows remote management'),
        @(6379,'redis','unauthenticated = remote code exec'),
        @(6667,'irc','classic botnet C2'),
        @(8080,'alt-http','alt-web admin panels'),
        @(8443,'alt-https','alt-web admin panels'),
        @(8888,'alt-http','alt-web admin panels'),
        @(9001,'tor/alt','Tor / alt-web service'),
        @(9200,'elasticsearch','unauthenticated query surface'),
        @(11211,'memcached','DDoS amplifier / unauthenticated'),
        @(27017,'mongodb','historically unauthenticated, ransom-wiped'),
        @(31337,'backdoor','historic backdoor port'),
        @(7547,'tr069','TR-069 ISP remote management — Mirai-class takeover port'),
        @(7001,'weblogic','Oracle WebLogic console — RCE-prone admin surface'),
        @(61616,'activemq','Apache ActiveMQ — unauthenticated management / RCE surface')
    )
    foreach ($r in $rows) {
        [pscustomobject]@{ Port = [int]$r[0]; Service = "$($r[1])"; Why = "$($r[2])" }
    }
}

# ---------------------------------------------------------------------------
# 1. Start-Backtrace — the look-back. Passive evidence gathering about a
#    hostile remote IP: port probes, banners, reverse DNS, RDAP record.
#    Never exploits, never authenticates, never sends payloads beyond a
#    normal TCP connect and banner read.
# ---------------------------------------------------------------------------
function Start-Backtrace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$IpAddress,
        [Parameter(Mandatory=$false)][string]$VaultPath = "",
        [Parameter(Mandatory=$false)][string]$EvidenceDir = "",
        [Parameter(Mandatory=$false)][int[]]$Ports,
        [Parameter(Mandatory=$false)][int]$TimeoutMs = 1500
    )
    # Normalize FIRST, validate second: accept "ip", "ip:port", "[ip]:port"
    # (v1.3 — pasted targets with ports no longer die in Test-ValidIp).
    $btTarget = ConvertTo-DefenseIpTarget -Target $IpAddress
    if (-not $btTarget.Ok) {
        throw "Refusing backtrace: could not parse '$IpAddress' as an IP (optionally ip:port)."
    }
    $IpAddress = $btTarget.Ip
    if (-not (Test-ValidIp $IpAddress)) {
        throw "Refusing backtrace: '$IpAddress' is not a routable remote IP (loopback or unparsable)."
    }
    if ($null -eq $Ports) {
        # Suspicious-remote-port table (43): the ports attackers actually
        # use — brute-force services, exposed databases, management
        # interfaces, and classic backdoor/C2 ports.
        $Ports = @(Get-BacktracePortTable | ForEach-Object { $_.Port })
    }
    Write-Host "[*] Backtracing $IpAddress (passive evidence gather, no exploits, no auth attempts)..." -ForegroundColor Cyan

    $report = [ordered]@{
        ip           = $IpAddress
        utc          = (Get-Date).ToUniversalTime().ToString("o")
        tool         = "Falsum-ActiveDefense/Start-Backtrace"
        openPorts    = @()
        reverseDns   = ""
        rdap         = $null
        abuseContacts= @()
        notes        = @()
    }

    # --- Step 1: reverse DNS (harmless, local resolver) ---
    try {
        Write-Host "  [1/4] Reverse DNS..." -ForegroundColor Gray
        $haveNet = Import-NetScanModule
        if ($haveNet) {
            $rd = Get-ReverseDns $IpAddress
        } else {
            try { $rd = ([System.Net.Dns]::GetHostEntry($IpAddress)).HostName } catch { $rd = "" }
        }
        $report.reverseDns = $rd
        if ([string]::IsNullOrWhiteSpace($rd)) { $report.notes += "No PTR record — IP has no published reverse name." }
        else { Write-Host "        PTR: $rd" -ForegroundColor Gray }
    } catch {
        $report.notes += "Reverse DNS failed: $_"
    }

    # --- Step 2: TCP port probe + banner grab (plain connects only) ---
    try {
        Write-Host "  [2/4] Port probe ($($Ports.Count) ports, plain TCP connect + banner read, ${TimeoutMs}ms timeout)..." -ForegroundColor Gray
        $open = @()
        foreach ($port in $Ports) {
            try {
                $client = New-Object System.Net.Sockets.TcpClient
                try {
                    $iar = $client.BeginConnect($IpAddress, $port, $null, $null)
                    $ok  = $iar.AsyncWaitHandle.WaitOne($TimeoutMs)
                    if ($ok -and $client.Connected) {
                        $banner = ""
                        try {
                            $client.ReceiveTimeout = 1200
                            $stream = $client.GetStream()
                            # nudge HTTP-ish ports; others: wait for self-announcing banner
                            if ($port -in @(80, 8080, 8000, 8888, 5000, 3000)) {
                                $req = "HEAD / HTTP/1.0`r`nHost: $IpAddress`r`n`r`n"
                                $bytes = [Text.Encoding]::ASCII.GetBytes($req)
                                $stream.Write($bytes, 0, $bytes.Length)
                            }
                            $buf = New-Object byte[] 2048
                            $read = $stream.Read($buf, 0, $buf.Length)
                            if ($read -gt 0) {
                                $text = [Text.Encoding]::ASCII.GetString($buf, 0, $read)
                                $text = $text -replace "[^\x20-\x7e\r\n]", ""
                                $first = ($text -split "`r?`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -First 1)
                                if ($null -ne $first) {
                                    if ($first.Length -gt 120) { $first = $first.Substring(0, 120) }
                                    $banner = $first.Trim()
                                }
                            }
                        } catch { $banner = "" }
                        $open += [pscustomobject]@{ port = $port; banner = $banner }
                        Write-Host "        OPEN: $port $banner" -ForegroundColor Yellow
                    }
                } finally {
                    $client.Close()
                }
            } catch { <# closed or filtered: not evidence, skip #> }
        }
        $report.openPorts = $open
        if ($open.Count -eq 0) { $report.notes += "No probed ports responded (filtered, down, or firewalled at the remote end)." }
    } catch {
        $report.notes += "Port probe failed: $_"
    }

    # --- Step 3: RDAP record (public registration data, read-only HTTP) ---
    try {
        Write-Host "  [3/4] RDAP record..." -ForegroundColor Gray
        $haveOsint = Import-OsintModule
        if ($haveOsint) {
            $rdap = Get-RdapIp $IpAddress
            if ($null -ne $rdap) {
                $report.rdap = $rdap
                Write-Host "        RDAP: registry/network identified (see report)." -ForegroundColor Gray
            } else {
                $report.notes += "RDAP returned no record."
            }
        } else {
            # Inline fallback: direct rdap.org query, minimal fields.
            $url  = "https://rdap.org/ip/$IpAddress"
            $resp = Invoke-RestMethod -Uri $url -TimeoutSec 15 -UserAgent "Falsum-ActiveDefense/1.0"
            $org  = ""
            try {
                foreach ($ent in $resp.entities) {
                    if ($ent.roles -contains 'registrant') {
                        foreach ($v in $ent.vCards) { foreach ($part in $v) { if ($part -contains 'org' -or $part -contains 'fn') { $org = ($part | Select-Object -Last 1) } } }
                    }
                }
            } catch { }
            $report.rdap = @{ name = $resp.name; country = $resp.country; org = $org }
        }
    } catch {
        $report.notes += "RDAP query failed: $_"
    }

    # --- Step 4: abuse contacts (who the report gets filed to) ---
    try {
        Write-Host "  [4/4] Abuse contacts (RDAP 'abuse' role)..." -ForegroundColor Gray
        $abuse = @(Get-AbuseContact -IpAddress $IpAddress)
        $report.abuseContacts = $abuse
        foreach ($c in $abuse) {
            Write-Host "        abuse desk: $($c.email) ($($c.fn))" -ForegroundColor Gray
        }
        if ($abuse.Count -eq 0) {
            $report.notes += "No RDAP abuse contact published for this IP — file via the provider's abuse form."
        }
    } catch {
        $report.notes += "Abuse-contact lookup failed: $_"
    }

    # --- Persist + vault ---
    # v1.3: never Join-Path off an empty MyDocuments (Server Core /
    # redirected profiles) — Get-DefenseOutDir carries the fallback chain.
    if ([string]::IsNullOrWhiteSpace($EvidenceDir)) {
        $EvidenceDir = Get-DefenseOutDir
    }
    try {
        if (-not (Test-Path $EvidenceDir)) { New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null }
        $safe  = ($IpAddress -replace '[^0-9a-zA-Z.-]', '_')
        $path  = Join-Path $EvidenceDir ("backtrace-$safe-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".json")
        ($report | ConvertTo-Json -Depth 8) | Out-File -FilePath $path -Encoding utf8
        Write-Host "[+] Backtrace report written: $path" -ForegroundColor Green
        $report | Add-Member -NotePropertyName 'reportPath' -NotePropertyValue $path -Force
    } catch {
        Write-Host "  [!] Could not persist report file: $_" -ForegroundColor DarkYellow
    }
    if (-not [string]::IsNullOrWhiteSpace($VaultPath)) {
        Write-VaultDefenseEvent -VaultPath $VaultPath -EventName "backtrace" -Data $report | Out-Null
        Write-Host "[+] Vault-logged (type: active-defense, event: backtrace)." -ForegroundColor Green
    }
    Write-Host "[*] Done. $($report.openPorts.Count) open port(s) found. This report is evidence, not a license to act." -ForegroundColor Cyan
    return $report
}

# ---------------------------------------------------------------------------
# 2. Get-EstablishedSession — the local view: every ESTABLISHED TCP
#    connection, with owning process. This is how you SEE a hostile
#    session on your own wire before you kill it.
# ---------------------------------------------------------------------------
function Get-EstablishedSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)][string]$RemoteAddress = ""
    )
    Write-Host "[*] Enumerating ESTABLISHED TCP sessions..." -ForegroundColor Cyan
    $out = @()
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction Stop
        $procs = @{}
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $procs[$p.Id] = $p.ProcessName }
        foreach ($c in $conns) {
            if ($RemoteAddress -ne "" -and $c.RemoteAddress -ne $RemoteAddress) { continue }
            $name = ""
            if ($procs.ContainsKey($c.OwningProcess)) { $name = $procs[$c.OwningProcess] }
            $out += [pscustomobject]@{
                LocalAddress  = $c.LocalAddress
                LocalPort     = $c.LocalPort
                RemoteAddress = $c.RemoteAddress
                RemotePort    = $c.RemotePort
                ProcessId     = $c.OwningProcess
                ProcessName   = $name
            }
        }
        Write-Host "  Found $($out.Count) established session(s)." -ForegroundColor Gray
    } catch {
        throw "Get-NetTCPConnection failed (needs Windows 8+/2012+ and read rights): $_"
    }
    return $out
}

# ---------------------------------------------------------------------------
# 3. Stop-HostileSession — THE FIX on my wire. Kills a hostile session by
#    remote IP or by local process id. LOCAL ONLY: it never sends a single
#    packet to the remote end — it just terminates the local socket owner.
#    Requires admin + explicit confirmation. Vault-logged.
# ---------------------------------------------------------------------------
function Stop-HostileSession {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory=$false)][string]$RemoteAddress = "",
        [Parameter(Mandatory=$false)][int]$ProcessId = 0,
        [Parameter(Mandatory=$false)][switch]$CloseOnly,
        [Parameter(Mandatory=$false)][string]$VaultPath = ""
    )
    if (-not (Test-IsAdmin)) {
        throw "Stop-HostileSession requires elevation: killing processes is an admin act. Re-run as Administrator."
    }
    if ($RemoteAddress -eq "" -and $ProcessId -eq 0) {
        throw "Specify -RemoteAddress or -ProcessId. Run Get-EstablishedSession first to see what is on your wire."
    }
    # Normalize FIRST, validate second (v1.3): "8.8.8.8:443" is accepted;
    # the port narrows the CloseOnly close to that one connection.
    $killTargetIp = $RemoteAddress
    $killTargetPort = 0
    if ($RemoteAddress -ne "") {
        $kt = ConvertTo-DefenseIpTarget -Target $RemoteAddress
        if (-not $kt.Ok) {
            throw "Could not parse '$RemoteAddress' as an IP (optionally ip:port)."
        }
        $killTargetIp = $kt.Ip
        $killTargetPort = $kt.Port
    }
    if ($killTargetIp -ne "" -and -not (Test-ValidIp $killTargetIp)) {
        throw "Refusing: '$killTargetIp' is not a routable remote IP."
    }

    # Precise fix first: close the hostile connection(s), keep the process.
    if ($CloseOnly) {
        Write-Host "[*] CloseOnly: closing hostile connection(s) without killing any process..." -ForegroundColor Cyan
        # v1.3: propagate -WhatIf into the nested destructive call — a
        # preview that still closes connections is not a preview.
        $closed = @(Close-TcpConnection -RemoteAddress $killTargetIp -RemotePort $killTargetPort `
            -ProcessId $ProcessId -VaultPath $VaultPath -WhatIf:$WhatIfPreference)
        $killed = @($closed | ForEach-Object {
            [pscustomobject]@{
                ProcessId    = $_.ProcessId
                ProcessName  = $_.ProcessName
                RemoteAddress= $_.RemoteAddress
                Method       = "connection-closed"
                Verified     = $_.Verified
                VerifyNote   = $_.VerifyNote
            }
        })
        if ($killed.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($VaultPath)) {
            Write-VaultDefenseEvent -VaultPath $VaultPath -EventName "hostile-session-closed" -Data (@{ targets = $killed }) | Out-Null
        }
        if ($killed.Count -eq 0) {
            Write-Host "  No connections closed — nothing matched or nothing was established." -ForegroundColor Gray
        }
        return $killed
    }

    $killed = @()
    try {
        if ($killTargetIp -ne "") {
            Write-Host "[*] Hunting sessions from $killTargetIp ..." -ForegroundColor Cyan
            $sess = Get-EstablishedSession -RemoteAddress $killTargetIp
            # v1.4 REAL SCOPING FIX: a parsed port (e.g. -RemoteAddress
            # "8.8.8.8:443") used to be dropped here — the kill enumerated
            # sessions by IP only and killed EVERY process holding ANY
            # session to that IP. When a port was given, narrow the kill
            # to the PIDs that actually hold the ip:port tuple.
            if ($killTargetPort -gt 0) {
                $sess = @($sess | Where-Object { $_.RemotePort -eq $killTargetPort })
                Write-Host "  Port narrowed to ${killTargetPort}: $($sess.Count) matching session(s)." -ForegroundColor Gray
            }
            if ($sess.Count -eq 0) {
                $scope = if ($killTargetPort -gt 0) { "$killTargetIp port $killTargetPort" } else { $killTargetIp }
                Write-Host "  No established sessions from $scope right now." -ForegroundColor Gray
                return $killed
            }
            $targets = @{}; foreach ($s in $sess) { $targets[$s.ProcessId] = $s.ProcessName }
            # NOTE (v1.3): this loop used to read "foreach ($pid in ...)".
            # $PID is a READ-ONLY automatic variable (the host process id),
            # so the loop threw "Cannot overwrite variable PID because it is
            # read-only or constant" and the kill-by-RemoteAddress path NEVER
            # worked. The loop variable is now $procId.
            foreach ($procId in $targets.Keys) {
                $pname = $targets[$procId]
                if ($PSCmdlet.ShouldProcess("PID $procId ($pname)", "Terminate hostile session process")) {
                    Stop-Process -Id $procId -Force -ErrorAction Stop
                    Write-Host "  [-] Killed PID $procId ($pname)" -ForegroundColor Red
                    # Better-Way Law proof (v1.3): a kill that ships no
                    # verification is a claim, not a fix.
                    $verified = Confirm-ProcessTerminated -ProcessId $procId -TimeoutSec 5
                    if ($verified) {
                        Write-Host "      VERIFIED: PID $procId terminated." -ForegroundColor Green
                        $vNote = "VERIFIED: terminated on re-query"
                    } else {
                        Write-Host "      [!] UNVERIFIED: PID $procId still visible after 5s — re-run or check manually." -ForegroundColor DarkYellow
                        $vNote = "UNVERIFIED: still visible after 5s"
                    }
                    $killed += [pscustomobject]@{ ProcessId = $procId; ProcessName = $pname; RemoteAddress = $killTargetIp; Verified = $verified; VerifyNote = $vNote }
                }
            }
        } else {
            $proc = Get-Process -Id $ProcessId -ErrorAction Stop
            if ($PSCmdlet.ShouldProcess("PID $ProcessId ($($proc.ProcessName))", "Terminate process")) {
                Stop-Process -Id $ProcessId -Force -ErrorAction Stop
                Write-Host "  [-] Killed PID $ProcessId ($($proc.ProcessName))" -ForegroundColor Red
                $verified = Confirm-ProcessTerminated -ProcessId $ProcessId -TimeoutSec 5
                if ($verified) {
                    Write-Host "      VERIFIED: PID $ProcessId terminated." -ForegroundColor Green
                    $vNote = "VERIFIED: terminated on re-query"
                } else {
                    Write-Host "      [!] UNVERIFIED: PID $ProcessId still visible after 5s — re-run or check manually." -ForegroundColor DarkYellow
                    $vNote = "UNVERIFIED: still visible after 5s"
                }
                $killed += [pscustomobject]@{ ProcessId = $ProcessId; ProcessName = $proc.ProcessName; RemoteAddress = "(all)"; Verified = $verified; VerifyNote = $vNote }
            }
        }
    } catch {
        throw "Stop-HostileSession failed: $_"
    }
    if ($killed.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($VaultPath)) {
        Write-VaultDefenseEvent -VaultPath $VaultPath -EventName "hostile-session-killed" -Data (@{ targets = $killed }) | Out-Null
    }
    return $killed
}

# ---------------------------------------------------------------------------
# 4. New-AbusePack — evidence that gets FILED. Builds a ready-to-send abuse
#    report bundle for an IP: backtrace report, trap/vault evidence
#    excerpts, SHA-256 manifest, zipped. Filing is part of the defense —
#    reports that never get sent change nothing.
# ---------------------------------------------------------------------------
function New-AbusePack {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$IpAddress,
        [Parameter(Mandatory=$true)][string]$EvidenceDir,
        [Parameter(Mandatory=$false)][string]$BacktracePath = "",
        [Parameter(Mandatory=$false)][string]$TrapLogDir = "",
        [Parameter(Mandatory=$false)][string]$ReporterName = "",
        [Parameter(Mandatory=$false)][string]$VaultPath = ""
    )
    # Normalize FIRST, validate second (v1.3): "8.8.8.8:443" is accepted.
    $apTarget = ConvertTo-DefenseIpTarget -Target $IpAddress
    if (-not $apTarget.Ok) {
        throw "Refusing abuse pack: could not parse '$IpAddress' as an IP (optionally ip:port)."
    }
    $IpAddress = $apTarget.Ip
    if (-not (Test-ValidIp $IpAddress)) {
        throw "Refusing abuse pack: '$IpAddress' is not a routable remote IP."
    }
    Write-Host "[*] Building abuse pack for $IpAddress ..." -ForegroundColor Cyan
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safe  = ($IpAddress -replace '[^0-9a-zA-Z.-]', '_')
    $pack  = Join-Path $EvidenceDir ("abuse-pack-$safe-$stamp")
    try {
        New-Item -ItemType Directory -Path $pack -Force | Out-Null
    } catch {
        throw "Could not create pack directory $pack : $_"
    }
    $files = @()

    # --- 1. Backtrace (fresh if none supplied) ---
    try {
        if ([string]::IsNullOrWhiteSpace($BacktracePath)) {
            Write-Host "  [1/4] Running fresh backtrace..." -ForegroundColor Gray
            $bt = Start-Backtrace -IpAddress $IpAddress -EvidenceDir $pack
            $BacktracePath = $bt.reportPath
        }
        if (-not [string]::IsNullOrWhiteSpace($BacktracePath) -and (Test-Path $BacktracePath)) {
            Copy-Item $BacktracePath (Join-Path $pack 'backtrace.json') -Force
            $files += 'backtrace.json'
        }
    } catch {
        Write-Host "  [!] Backtrace step failed (pack continues): $_" -ForegroundColor DarkYellow
    }

    # --- 2. Trap/vault evidence excerpts for this IP ---
    try {
        Write-Host "  [2/4] Gathering evidence excerpts mentioning $IpAddress ..." -ForegroundColor Gray
        $excerpts = @()
        if (-not [string]::IsNullOrWhiteSpace($TrapLogDir) -and (Test-Path $TrapLogDir)) {
            foreach ($f in (Get-ChildItem -Path $TrapLogDir -Filter '*.jsonl' -ErrorAction SilentlyContinue)) {
                # Flood guard: a runaway listener can leave multi-GB logs;
                # Select-String over one would stall the pack. Same 100MB
                # rule the trap module uses for its own readers.
                $skipFile = $false
                try { if ($f.Length -gt 104857600) { $skipFile = $true } } catch { }
                if ($skipFile) {
                    $excerpts += "[$($f.Name)] SKIPPED: log over 100MB — excerpt from the trap module's capped reader instead."
                    continue
                }
                $hits = Select-String -Path $f.FullName -Pattern ([regex]::Escape($IpAddress)) -SimpleMatch -ErrorAction SilentlyContinue
                foreach ($h in $hits) { $excerpts += "[$($f.Name):$($h.LineNumber)] $($h.Line.Trim())" }
            }
        }
        ("Evidence excerpts for IP: $IpAddress`r`nCollected UTC: " + (Get-Date).ToUniversalTime().ToString("o") + "`r`n`r`n" +
         "SOURCE: local trap listeners / vault entries on the reporter's own machine.`r`n" +
         "INTERPRETATION: these lines prove the IP connected to decoy services on the`r`n" +
         "reporter's property. They are observation, not accusation of a person.`r`n`r`n" +
         (($excerpts -join "`r`n"))) | Out-File -FilePath (Join-Path $pack 'evidence-excerpts.txt') -Encoding utf8
        $files += 'evidence-excerpts.txt'
        Write-Host "        $($excerpts.Count) excerpt line(s)." -ForegroundColor Gray
    } catch {
        Write-Host "  [!] Excerpt step failed (pack continues): $_" -ForegroundColor DarkYellow
    }

    # --- 3. The abuse report letter (addressed to the RDAP abuse desk) ---
    try {
        Write-Host "  [3/4] Writing abuse report letter..." -ForegroundColor Gray
        $org = ""
        $toAddrs = @()
        try {
            $btj = Get-Content (Join-Path $pack 'backtrace.json') -Raw | ConvertFrom-Json
            if ($null -ne $btj.rdap) { $org = "$($btj.rdap.org) / $($btj.rdap.name) $($btj.rdap.country)" }
            foreach ($c in @($btj.abuseContacts)) {
                if ($null -ne $c -and "$($c.email)" -ne "") { $toAddrs += "$($c.email)" }
            }
        } catch { }
        if ($toAddrs.Count -eq 0) {
            # Backtrace step may have been skipped; query the desk directly.
            foreach ($c in @(Get-AbuseContact -IpAddress $IpAddress)) {
                if ($c.email -ne "") { $toAddrs += $c.email }
            }
        }
        if ($toAddrs.Count -eq 0) {
            # Last resort: match the RDAP org against the provider abuse-desk
            # table. Best effort — verify the address before filing.
            try {
                $btj2 = Get-Content (Join-Path $pack 'backtrace.json') -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                $orgName = ""
                if ($null -ne $btj2 -and $null -ne $btj2.rdap) { $orgName = "$($btj2.rdap.org) $($btj2.rdap.name)" }
                $desk = Get-ProviderAbuseDesk -OrgName $orgName
                if ($null -ne $desk) { $toAddrs += "$($desk.AbuseEmail)  [provider desk table — VERIFY on the provider's site before filing]" }
            } catch { }
        }
        $toLine = if ($toAddrs.Count -gt 0) { ($toAddrs | Select-Object -Unique) -join ", " } `
                  else { "(no abuse contact published — file via the provider's abuse form)" }
        $letter = @"
ABUSE REPORT
============
Date (UTC):        $((Get-Date).ToUniversalTime().ToString("o"))
To (abuse desk):   $toLine
Subject IP:        $IpAddress
Attribution data:  $org
Reporter:          $ReporterName

SUMMARY
-------
The IP address $IpAddress was observed connecting to services on the
reporter's own machine without authorization (see evidence-excerpts.txt).
A technical backtrace is attached (backtrace.json).

REQUESTED ACTION
----------------
Please investigate the activity originating from $IpAddress on your
network and take appropriate action under your acceptable-use policy.

EVIDENCE INTEGRITY
------------------
Every file in this pack is listed with its SHA-256 hash in MANIFEST.txt.
The evidence was collected on the reporter's own property by passive
observation only. No system belonging to anyone else was accessed.

LEGAL NOTE
----------
Unauthorized access to someone else's system is a federal crime under the
CFAA even if they attacked first. This report is the lawful response:
observe, document, block locally, report.
"@
        $letter | Out-File -FilePath (Join-Path $pack 'abuse-report.txt') -Encoding utf8
        $files += 'abuse-report.txt'
    } catch {
        throw "Could not write abuse report letter: $_"
    }

    # --- 4. SHA-256 manifest + zip ---
    try {
        Write-Host "  [4/4] Hashing and zipping..." -ForegroundColor Gray
        $manifest = @()
        foreach ($fn in $files) {
            $fp = Join-Path $pack $fn
            if (Test-Path $fp) {
                $h = (Get-FileHash -Path $fp -Algorithm SHA256).Hash.ToLower()
                $manifest += "$h  $fn"
            }
        }
        $manifest -join "`r`n" | Out-File -FilePath (Join-Path $pack 'MANIFEST.txt') -Encoding utf8
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = "$pack.zip"
        if (Test-Path $zip) { Remove-Item $zip -Force }
        [System.IO.Compression.ZipFile]::CreateFromDirectory($pack, $zip)
        $zipHash = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLower()
        Write-Host "[+] Abuse pack: $zip" -ForegroundColor Green
        Write-Host "    SHA-256: $zipHash" -ForegroundColor Gray
    } catch {
        throw "Manifest/zip step failed: $_"
    }
    if (-not [string]::IsNullOrWhiteSpace($VaultPath)) {
        Write-VaultDefenseEvent -VaultPath $VaultPath -EventName "abuse-pack-built" -Data (@{ ip = $IpAddress; zip = $zip; sha256 = $zipHash }) | Out-Null
    }
    return [pscustomobject]@{ PackDir = $pack; Zip = $zip; Sha256 = $zipHash; Ip = $IpAddress }
}

# ---------------------------------------------------------------------------
# 5. Add-BadActor — THE PERMANENT MARK. Appends the IP to a persistent JSON
#    blocklist, writes a Windows Defender Firewall inbound block rule (the
#    mark enforced on your own gate), and the list exports as CSV so the
#    mark can be shared and re-applied anywhere. Better-Way Law: the block
#    rule IS the fix that ships with the detection.
# ---------------------------------------------------------------------------
function Get-BlocklistPath {
    $base = $env:ProgramData
    if ([string]::IsNullOrWhiteSpace($base)) { $base = [Environment]::GetFolderPath('CommonApplicationData') }
    if ([string]::IsNullOrWhiteSpace($base)) { $base = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Falsum' }
    $dir = Join-Path $base 'Falsum'
    try { if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null } } catch { }
    return Join-Path $dir 'badactors.json'
}

function Get-BadActorList {
    $path = Get-BlocklistPath
    try {
        if (-not (Test-Path $path)) { return @() }
        $raw = Get-Content $path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $list = $raw | ConvertFrom-Json
        if ($null -eq $list) { return @() }
        if ($list -isnot [System.Array]) { return @($list) }
        return $list
    } catch {
        Write-Host "  [!] Blocklist read failed: $_" -ForegroundColor DarkYellow
        return @()
    }
}

function Test-IsMarked {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$IpAddress)
    # v1.4: normalize FIRST, validate second — a pasted "8.8.8.8:443" used
    # to compare the raw string against bare-IP entries and reported NOT
    # marked for a marked IP. Unparseable input falls back to the raw
    # trimmed string (never throws — this is a one-line membership check).
    $tgt = ConvertTo-DefenseIpTarget -Target $IpAddress
    $ip = if ($tgt.Ok) { $tgt.Ip } else { "$IpAddress".Trim() }
    foreach ($e in @(Get-BadActorList)) {
        if ($e.ip -eq $ip) { return $true }
    }
    return $false
}

function Get-DefenseSummary {
    [CmdletBinding()]
    param()
    Write-Host "[*] Active Defense summary" -ForegroundColor Cyan
    $marked = @(Get-BadActorList)
    $rules  = @(Get-NetFirewallRule -DisplayName "Falsum-Block-*" -ErrorAction SilentlyContinue)
    $sess   = @()
    try { $sess = @(Get-EstablishedSession) } catch {
        Write-Host "  [!] Session enumeration unavailable here: $_" -ForegroundColor DarkYellow
    }
    Write-Host "  Marked bad actors      : $($marked.Count)" -ForegroundColor Gray
    Write-Host "  Enforced firewall rules: $($rules.Count)" -ForegroundColor Gray
    Write-Host "  Established sessions   : $($sess.Count)" -ForegroundColor Gray
    Write-Host "  Elevated (admin)       : $(Test-IsAdmin)" -ForegroundColor Gray
    if ($marked.Count -ne $rules.Count) {
        Write-Host "  [!] Drift: $($marked.Count) marked vs $($rules.Count) firewall rules —" -ForegroundColor DarkYellow
        Write-Host "      run Sync-FirewallBlockRules (elevated) to repair the drift." -ForegroundColor DarkYellow
    }
    return [pscustomobject]@{
        MarkedActors       = $marked.Count
        FirewallBlockRules = $rules.Count
        EstablishedSessions= $sess.Count
        Elevated           = (Test-IsAdmin)
    }
}

function Add-BadActor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$IpAddress,
        [Parameter(Mandatory=$true)][string]$Reason,
        [Parameter(Mandatory=$false)][string]$Evidence = "",
        [Parameter(Mandatory=$false)][switch]$SkipFirewall,
        [Parameter(Mandatory=$false)][string]$VaultPath = ""
    )
    # v1.4: normalize FIRST, validate second — pasted targets like
    # "8.8.8.8:443" or "[8.8.8.8]:443" used to die in Test-ValidIp here
    # even though every sibling function (Backtrace/AbusePack/Stop/Close)
    # already normalized. The port is irrelevant to a block: the mark is
    # on the IP.
    $baTarget = ConvertTo-DefenseIpTarget -Target $IpAddress
    if (-not $baTarget.Ok) {
        throw "Refusing: could not parse '$IpAddress' as an IP (optionally ip:port)."
    }
    $IpAddress = $baTarget.Ip
    if (-not (Test-ValidIp $IpAddress)) {
        throw "Refusing: '$IpAddress' is not a routable remote IP."
    }
    Write-Host "[*] Marking bad actor: $IpAddress" -ForegroundColor Cyan

    # --- 1. Persistent JSON mark (never silently overwritten) ---
    try {
        $list  = @(Get-BadActorList)
        $found = $false
        foreach ($e in $list) { if ($e.ip -eq $IpAddress) { $found = $true; break } }
        if (-not $found) {
            $entry = [pscustomobject]@{
                ip       = $IpAddress
                reason   = $Reason
                evidence = $Evidence
                markedUtc= (Get-Date).ToUniversalTime().ToString("o")
                status   = "blocked-locally"
            }
            $list += $entry
            $path  = Get-BlocklistPath
            ($list | ConvertTo-Json -Depth 5) | Out-File -FilePath $path -Encoding utf8
            Write-Host "  [+] Marked permanently in blocklist: $path" -ForegroundColor Green
        } else {
            Write-Host "  [=] Already marked — existing entry kept (marks are never downgraded)." -ForegroundColor Gray
        }
    } catch {
        throw "Blocklist write failed: $_"
    }

    # --- 2. The enforced fix: Windows Defender Firewall inbound block ---
    $fwRule = $false
    if (-not $SkipFirewall) {
        if (-not (Test-IsAdmin)) {
            Write-Host "  [!] Not elevated: firewall rule skipped. Re-run as Administrator" -ForegroundColor DarkYellow
            Write-Host "      to enforce the block, or run: Add-BadActor -IpAddress $IpAddress -Reason 'x' -Evidence 'y'" -ForegroundColor DarkYellow
        } else {
            try {
                $ruleName = "Falsum-Block-$IpAddress"
                $exists = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                if ($null -eq $exists) {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block `
                        -RemoteAddress $IpAddress -Description "Falsum bad-actor mark: $Reason" `
                        -ErrorAction Stop | Out-Null
                    Write-Host "  [+] Firewall inbound block rule created: $ruleName" -ForegroundColor Green
                    $fwRule = $true
                } else {
                    Write-Host "  [=] Firewall rule already exists: $ruleName" -ForegroundColor Gray
                    $fwRule = $true
                }
            } catch {
                Write-Host "  [!] Firewall rule creation failed: $_" -ForegroundColor DarkYellow
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($VaultPath)) {
        Write-VaultDefenseEvent -VaultPath $VaultPath -EventName "bad-actor-marked" -Data (@{
            ip = $IpAddress; reason = $Reason; evidence = $Evidence; firewallRule = $fwRule
        }) | Out-Null
    }
    Write-Host "[*] Done. The mark persists in the blocklist and exports via Export-BadActorList —" -ForegroundColor Cyan
    Write-Host "    it follows them wherever the list goes." -ForegroundColor Cyan
}

function Remove-BadActor {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory=$true)][string]$IpAddress,
        [Parameter(Mandatory=$false)][string]$VaultPath = ""
    )
    if (-not (Test-IsAdmin)) {
        throw "Remove-BadActor requires elevation (firewall rule removal). Re-run as Administrator."
    }
    # v1.4: normalize FIRST — a pasted "8.8.8.8:443" used to miss the bare
    # IP entry and report "nothing to remove" for a marked IP.
    $rbTarget = ConvertTo-DefenseIpTarget -Target $IpAddress
    if (-not $rbTarget.Ok) {
        throw "Refusing: could not parse '$IpAddress' as an IP (optionally ip:port)."
    }
    $IpAddress = $rbTarget.Ip
    $removed = $false
    try {
        $list = @(Get-BadActorList)
        $kept = @($list | Where-Object { $_.ip -ne $IpAddress })
        if ($kept.Count -ne $list.Count) {
            $path = Get-BlocklistPath
            ($kept | ConvertTo-Json -Depth 5) | Out-File -FilePath $path -Encoding utf8
            Write-Host "  [-] Removed from blocklist: $IpAddress" -ForegroundColor Yellow
            $removed = $true
        }
        $ruleName = "Falsum-Block-$IpAddress"
        $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($null -ne $rule) {
            if ($PSCmdlet.ShouldProcess($ruleName, "Remove firewall block rule")) {
                Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
                Write-Host "  [-] Removed firewall rule: $ruleName" -ForegroundColor Yellow
                $removed = $true
            }
        }
        if (-not $removed) { Write-Host "  [=] Nothing to remove: $IpAddress was not marked." -ForegroundColor Gray }
    } catch {
        throw "Remove-BadActor failed: $_"
    }
    if ($removed -and -not [string]::IsNullOrWhiteSpace($VaultPath)) {
        Write-VaultDefenseEvent -VaultPath $VaultPath -EventName "bad-actor-unmarked" -Data (@{ ip = $IpAddress }) | Out-Null
    }
}

function Export-BadActorList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$false)][switch]$AsJson
    )
    $list = @(Get-BadActorList)
    try {
        if ($AsJson) {
            ($list | ConvertTo-Json -Depth 5) | Out-File -FilePath $Path -Encoding utf8 -Force
        } else {
            $list | Select-Object ip, reason, evidence, markedUtc, status | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force
        }
        $fmt = if ($AsJson) { "JSON" } else { "CSV" }
        Write-Host "[+] Exported $($list.Count) marked actor(s) ($fmt) to $Path" -ForegroundColor Green
    } catch {
        throw "Export failed: $_"
    }
    return $Path
}

# ---------------------------------------------------------------------------
# Test-DeskKeyMatch — pure provider-key matcher. Replaces the old bare
# `$orgName.Contains($key)` which false-matched: "aws" fired on "Pawsey",
# "cogent" on "Cogentrix", "amazon" on "Amazons". A key now matches only
# on delimiter boundaries (start/end or a non-alphanumeric on both sides
# that is not consumed by a longer word), so "amazon-02" still matches
# 'amazon' but "awsome" does not match 'aws'. Pure: offline-testable.
# ---------------------------------------------------------------------------
function Test-DeskKeyMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$OrgName,
        [Parameter(Mandatory=$true)][string]$Key
    )
    if ([string]::IsNullOrWhiteSpace($OrgName) -or [string]::IsNullOrWhiteSpace($Key)) { return $false }
    $o = $OrgName.ToLower()
    $k = $Key.ToLower()
    $startAt = 0
    while ($true) {
        $idx = $o.IndexOf($k, $startAt, [System.StringComparison]::Ordinal)
        if ($idx -lt 0) { return $false }
        $beforeOk = $true
        if ($idx -gt 0) {
            $bc = "$($o[$idx - 1])"
            if ($bc -match '^[a-z0-9]$') { $beforeOk = $false }
        }
        $afterOk = $true
        $afterIdx = $idx + $k.Length
        if ($afterIdx -lt $o.Length) {
            $ac = "$($o[$afterIdx])"
            if ($ac -match '^[a-z0-9]$') { $afterOk = $false }
        }
        if ($beforeOk -and $afterOk) { return $true }
        $startAt = $idx + 1
    }
}

# ---------------------------------------------------------------------------
# 6. Get-ProviderAbuseDesk — when RDAP publishes no abuse contact, match the
#    RDAP org name against a shipped table of major hosting providers'
#    abuse desks. BEST EFFORT: these addresses change; the table comment
#    says so and New-AbusePack flags any table-derived address with a
#    VERIFY note. RDAP 'abuse' role (Get-AbuseContact) remains the primary.
# ---------------------------------------------------------------------------
function Get-ProviderAbuseDesk {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$OrgName)
    $table = @(
        @{ keys = @('cloudflare');                email = 'abuse@cloudflare.com';       form = 'https://www.cloudflare.com/abuse/form' },
        @{ keys = @('amazon','aws','ec2');         email = 'ec2-abuse@amazon.com';        form = 'https://aws.amazon.com/security/vulnerability-reporting/' },
        @{ keys = @('google','gcp','googlecloud'); email = '';                           form = 'https://support.google.com/code/contact/cloud_platform_report' },
        @{ keys = @('microsoft','azure');         email = 'abuse@microsoft.com';         form = 'https://msrc.microsoft.com/report/abuse' },
        @{ keys = @('digitalocean');              email = 'abuse@digitalocean.com';      form = '' },
        @{ keys = @('hetzner');                   email = 'abuse@hetzner.de';            form = 'https://www.hetzner.com/legal/report-abuse' },
        @{ keys = @('ovh');                       email = 'abuse@ovh.net';                form = 'https://www.ovh.com/abuse/' },
        @{ keys = @('linode','akamai');           email = 'abuse@linode.com';            form = 'https://www.akamai.com/legal/compliance' },
        @{ keys = @('vultr','choopa','constant company'); email = 'abuse@vultr.com';     form = '' },
        @{ keys = @('contabo');                   email = 'abuse@contabo.com';           form = '' },
        @{ keys = @('leaseweb');                  email = 'abuse@leaseweb.com';          form = 'https://www.leaseweb.com/en/report-abuse' },
        @{ keys = @('quadranet');                 email = 'abuse@quadranet.com';         form = '' },
        @{ keys = @('m247');                      email = 'abuse@m247.com';              form = '' },
        @{ keys = @('datacamp','cdn77');          email = 'abuse@datacamp.co.uk';        form = '' },
        @{ keys = @('tencent');                   email = 'cloudabuse@tencent.com';      form = '' },
        @{ keys = @('alibaba');                   email = 'cloudabuse@alibaba-inc.com';  form = '' },
        @{ keys = @('namecheap');                 email = 'abuse@namecheap.com';         form = '' },
        @{ keys = @('godaddy');                   email = 'abuse@godaddy.com';           form = 'https://www.godaddy.com/report-abuse' },
        @{ keys = @('fastly');                    email = 'abuse@fastly.com';            form = '' },
        @{ keys = @('i3d','i3d.net');             email = 'abuse@i3d.net';               form = '' },
        @{ keys = @('hurricane','he.net');        email = 'abuse@he.net';                form = '' },
        @{ keys = @('cogent');                    email = 'abuse@cogentco.com';          form = '' },
        @{ keys = @('lumen','centurylink');       email = 'abuse@lumen.com';             form = '' },
        @{ keys = @('zayo');                      email = 'abuse@zayo.com';              form = '' },
        @{ keys = @('hostinger');                 email = 'abuse@hostinger.com';         form = '' },
        @{ keys = @('bluehost');                  email = 'abuse@bluehost.com';          form = '' },
        @{ keys = @('ionos','1&1');               email = 'abuse@ionos.com';             form = '' },
        @{ keys = @('phoenixnap');                email = 'abuse@phoenixnap.com';        form = '' },
        @{ keys = @('psychz');                    email = 'abuse@psychz.net';            form = '' },
        @{ keys = @('sharktech');                 email = 'abuse@sharktech.net';         form = '' },
        @{ keys = @('worldstream');               email = 'abuse@worldstream.nl';        form = '' },
        @{ keys = @('nforce');                    email = 'abuse@nforce.com';            form = '' },
        @{ keys = @('dedipath');                  email = 'abuse@dedipath.com';          form = '' },
        @{ keys = @('upcloud');                   email = 'abuse@upcloud.com';           form = '' }
    )
    if ([string]::IsNullOrWhiteSpace($OrgName)) { return $null }
    foreach ($row in $table) {
        foreach ($k in $row.keys) {
            # v1.4: boundary-aware match (Test-DeskKeyMatch) — the old
            # $low.Contains($k) false-matched ("aws" on "Pawsey").
            if (Test-DeskKeyMatch -OrgName $OrgName -Key $k) {
                return [pscustomobject]@{ Provider = $row.keys[0]; AbuseEmail = $row.email; AbuseForm = $row.form }
            }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Get-SuspiciousPortTable — ONE source of truth for the threat-hunt
# indicator ports (was a 31-row table copied in two places; the copies
# could drift — a scanner the tool does not list is a scanner it misses).
# Returned as objects with Port / Service / Why so both the hunt and the
# hygiene battery read the same rows. Better-Way Law: the battery tests
# the table the hunt actually uses.
# ---------------------------------------------------------------------------
function Get-SuspiciousPortTable {
    [CmdletBinding()]
    param()
    $rows = @(
        @(22,'ssh','brute-force / tunnel target'),
        @(23,'telnet','legacy cleartext, never legitimate inbound/outbound to unknown'),
        @(21,'ftp','cleartext credential service'),
        @(25,'smtp','spam-relay abuse from compromised hosts'),
        @(53,'dns','DNS tunneling endpoint'),
        @(135,'rpc','Windows RPC — lateral movement surface'),
        @(139,'netbios','legacy Windows sharing'),
        @(445,'smb','ransomware lateral movement classic'),
        @(1433,'mssql','database brute force'),
        @(1434,'mssql-udp','SQL Slammer surface'),
        @(3306,'mysql','database brute force'),
        @(5432,'postgres','database brute force'),
        @(27017,'mongodb','historically unauthenticated, ransom-wiped'),
        @(6379,'redis','unauthenticated = remote code exec'),
        @(9200,'elasticsearch','unauthenticated query surface'),
        @(11211,'memcached','DDoS amplifier / unauthenticated'),
        @(2375,'docker','unauthenticated Docker API = host takeover'),
        @(2376,'docker-tls','Docker API'),
        @(3389,'rdp','RDP brute force / ransomware entry'),
        @(5900,'vnc','VNC brute force'),
        @(5985,'winrm','Windows remote management'),
        @(5986,'winrm-https','Windows remote management'),
        @(4444,'metasploit','default Meterpreter listener'),
        @(6667,'irc','classic botnet C2'),
        @(31337,'backdoor','historic backdoor port'),
        @(1337,'shell','leetspeak shells / webshells'),
        @(1234,'netbus','classic RAT'),
        @(5555,'adb/hp','Android ADB / HP Data Protector abuse'),
        @(9001,'tor/alt','Tor / alt-web service'),
        @(8080,'alt-http','alt-web admin panels'),
        @(8443,'alt-https','alt-web admin panels')
    )
    foreach ($r in $rows) {
        [pscustomobject]@{ Port = [int]$r[0]; Service = "$($r[1])"; Why = "$($r[2])" }
    }
}

# ---------------------------------------------------------------------------
# Test-AuthenticodeVerdict — pure classifier over Get-AuthenticodeSignature
# .Status. Maps the raw status string to signed / unsigned / tampered /
# unknown (never a guess: anything unrecognized is 'unknown', not
# 'signed'). Pure: the hunt's live call is wrapped in try/catch and this
# function is what the battery proves.
# ---------------------------------------------------------------------------
function Test-AuthenticodeVerdict {
    [CmdletBinding()]
    param([Parameter(Mandatory=$false)][string]$Status = "")
    switch ("$Status") {
        'Valid'        { return 'signed' }
        'NotSigned'    { return 'unsigned' }
        'HashMismatch' { return 'tampered' }
        'NotTrusted'   { return 'tampered' }
        default        { return 'unknown' }
    }
}

# ---------------------------------------------------------------------------
# 7. Get-HostileSessionReport — THREAT HUNT on your own wire. Takes the
#    ESTABLISHED sessions and scores each against shipped indicator tables:
#      - remote IP is on your permanent blocklist (marked bad actor)
#      - remote port is a known attacker-service indicator
#      - owning process runs from a user-writable dir (temp/downloads/
#        desktop/appdata-temp) — a classic malware posture
#    Read-only. Never claims a person is guilty; the indicators say
#    "look here," and then you look. Better-Way Law: each indicator row
#    prints the exact follow-up command to run.
# ---------------------------------------------------------------------------
function Get-HostileSessionReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)][string]$VaultPath = ""
    )
    Write-Host "[*] Threat-hunt pass over established sessions (read-only)..." -ForegroundColor Cyan

    # Indicator table: Get-SuspiciousPortTable (single source of truth —
    # the hygiene battery validates this same table, so hunt and test
    # cannot drift apart).
    $indicatorPorts = @(Get-SuspiciousPortTable)

    $writableDirs = @(
        [System.IO.Path]::GetTempPath(),
        (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'),
        (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Desktop'),
        (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Temp')
    ) | ForEach-Object { $_.ToLower().TrimEnd('\') + '\' }

    $rows = @()
    $markedMap = @{}
    try { foreach ($e in @(Get-BadActorList)) { $markedMap["$($e.ip)"] = $true } } catch { }

    $sessions = @()
    try { $sessions = @(Get-EstablishedSession) } catch {
        throw "Session enumeration failed: $_"
    }

    $procPaths = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        try { $procPaths[$p.Id] = $p.Path } catch { }
    }

    foreach ($s in $sessions) {
        $indicators = @()
        $followups  = @()

        if ($markedMap.ContainsKey("$($s.RemoteAddress)")) {
            $indicators += "MARKED: remote IP is on your permanent bad-actor blocklist"
            $followups  += "Stop-HostileSession -RemoteAddress $($s.RemoteAddress) -CloseOnly"
        }
        foreach ($ind in $indicatorPorts) {
            if ($s.RemotePort -eq $ind.Port) {
                $indicators += "SUSPICIOUS-PORT: $($ind.Port)/$($ind.Service) — $($ind.Why)"
                $followups  += "Start-Backtrace -IpAddress $($s.RemoteAddress)"
                break
            }
        }
        $pPath = ""
        if ($procPaths.ContainsKey($s.ProcessId)) { $pPath = "$($procPaths[$s.ProcessId])" }
        $pLow = $pPath.ToLower()
        $writableHit = $false
        if ($pLow -ne "") {
            foreach ($d in $writableDirs) {
                if ($pLow.StartsWith($d)) { $writableHit = $true; break }
            }
        }
        if ($writableHit) {
            $indicators += "WEIRD-PATH: process '$($s.ProcessName)' runs from user-writable dir: $pPath"
            $followups  += "Get-FileHash -Path '$pPath' -Algorithm SHA256  (then scan via New-AbusePack evidence)"
            # v1.4: code-signature signal. An unsigned (or signature-
            # tampered) binary sitting in a user-writable directory is the
            # classic malware posture. Read-only; the live call never
            # throws — unreadable signatures classify 'unknown', never
            # 'signed'.
            try {
                $sigStatus = (Get-AuthenticodeSignature -FilePath $pPath -ErrorAction Stop).Status
            } catch { $sigStatus = "" }
            $sigVerdict = Test-AuthenticodeVerdict -Status "$sigStatus"
            if ($sigVerdict -eq 'unsigned') {
                $indicators += "UNSIGNED: '$($s.ProcessName)' is not code-signed (status: NotSigned)"
                $followups  += "Stop-HostileSession -ProcessId $($s.ProcessId) -CloseOnly"
            } elseif ($sigVerdict -eq 'tampered') {
                $indicators += "TAMPERED-SIGNATURE: '$($s.ProcessName)' signature status: $sigStatus"
                $followups  += "Stop-HostileSession -ProcessId $($s.ProcessId) -CloseOnly"
            }
        } elseif ($pLow -eq "") {
            $indicators += "UNKNOWN-PATH: could not resolve owning process path (protected process?)"
            $followups  += "Run elevated; Get-Process -Id $($s.ProcessId) | Select-Object Path"
        }

        if ($indicators.Count -gt 0) {
            $rows += [pscustomobject]@{
                RemoteAddress = $s.RemoteAddress
                RemotePort    = $s.RemotePort
                ProcessName   = $s.ProcessName
                ProcessId     = $s.ProcessId
                Indicators    = ($indicators -join ' | ')
                FollowUp      = ($followups | Select-Object -Unique) -join '; '
            }
        }
    }

    Write-Host "  $($sessions.Count) session(s) scanned, $($rows.Count) flagged." -ForegroundColor Gray
    foreach ($r in $rows) {
        Write-Host "  [!] $($r.RemoteAddress):$($r.RemotePort) [$($r.ProcessName) PID $($r.ProcessId)]" -ForegroundColor Yellow
        Write-Host "        $($r.Indicators)" -ForegroundColor DarkYellow
        Write-Host "        fix: $($r.FollowUp)" -ForegroundColor Gray
    }
    if ($rows.Count -eq 0) { Write-Host "  Clean: no indicators on any established session." -ForegroundColor Green }
    if (-not [string]::IsNullOrWhiteSpace($VaultPath)) {
        Write-VaultDefenseEvent -VaultPath $VaultPath -EventName "hostile-session-report" -Data (@{
            scanned = $sessions.Count; flagged = $rows.Count
            flags   = @($rows | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort) [$($_.ProcessName)] $($_.Indicators)" })
        }) | Out-Null
    }
    return @($rows)
}

# ---------------------------------------------------------------------------
# 8. Sync-FirewallBlockRules — DRIFT REPAIR. Ensures every marked IP has its
#    Windows Defender Firewall inbound block rule (fixes the drift that
#    Get-DefenseSummary reports), and with -RemoveStale drops rules for
#    IPs that are no longer marked. Admin required. Better-Way Law: the
#    summary said "repair the drift" — this is the repair.
# ---------------------------------------------------------------------------
function Sync-FirewallBlockRules {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory=$false)][switch]$RemoveStale,
        [Parameter(Mandatory=$false)][string]$VaultPath = ""
    )
    if (-not (Test-IsAdmin)) {
        throw "Sync-FirewallBlockRules requires elevation: firewall rules are an admin act. Re-run as Administrator."
    }
    Write-Host "[*] Syncing firewall block rules with the permanent blocklist..." -ForegroundColor Cyan
    $created = 0; $removed = 0
    try {
        $marked = @(Get-BadActorList)
        $markedMap = @{}
        foreach ($e in $marked) { $markedMap["$($e.ip)"] = $true }
        foreach ($e in $marked) {
            try {
                $ruleName = "Falsum-Block-$($e.ip)"
                $exists = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                if ($null -eq $exists) {
                    if ($PSCmdlet.ShouldProcess($ruleName, "Create inbound block rule")) {
                        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block `
                            -RemoteAddress $e.ip -Description "Falsum bad-actor mark (sync): $($e.reason)" `
                            -ErrorAction Stop | Out-Null
                        Write-Host "  [+] Created missing rule: $ruleName" -ForegroundColor Green
                        $created++
                    }
                }
            } catch {
                Write-Host "  [!] Could not create rule for $($e.ip): $_" -ForegroundColor DarkYellow
            }
        }
        if ($RemoveStale) {
            $rules = @(Get-NetFirewallRule -DisplayName "Falsum-Block-*" -ErrorAction SilentlyContinue)
            foreach ($r in $rules) {
                $ip = ($r.DisplayName -replace '^Falsum-Block-', '')
                if (-not $markedMap.ContainsKey($ip)) {
                    if ($PSCmdlet.ShouldProcess($r.DisplayName, "Remove stale block rule")) {
                        Remove-NetFirewallRule -DisplayName $r.DisplayName -ErrorAction Stop
                        Write-Host "  [-] Removed stale rule: $($r.DisplayName)" -ForegroundColor Yellow
                        $removed++
                    }
                }
            }
        }
        Write-Host "[*] Done: $created rule(s) created, $removed stale rule(s) removed." -ForegroundColor Cyan
    } catch {
        throw "Sync-FirewallBlockRules failed: $_"
    }
    if (-not [string]::IsNullOrWhiteSpace($VaultPath)) {
        Write-VaultDefenseEvent -VaultPath $VaultPath -EventName "firewall-rules-synced" -Data (@{
            created = $created; removed = $removed
        }) | Out-Null
    }
    return [pscustomobject]@{ Created = $created; Removed = $removed }
}

# ---------------------------------------------------------------------------
# 9. Import-BadActorList — shared marks come IN. Imports a JSON or CSV list
#    of bad-actor marks (same shape Export-BadActorList writes), validates
#    every IP, dedups against existing marks, and appends only the new
#    ones. This is how the mark follows bad actors across machines: export
#    on one, import on another. Never silently downgrades existing entries.
# ---------------------------------------------------------------------------
function Import-BadActorList {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$false)][switch]$AsCsv,
        [Parameter(Mandatory=$false)][string]$VaultPath = ""
    )
    if (-not (Test-Path $Path)) { throw "Import file not found: $Path" }
    Write-Host "[*] Importing shared bad-actor marks from $Path ..." -ForegroundColor Cyan
    $added = 0; $skippedDup = 0; $skippedBad = 0
    try {
        if ($AsCsv) {
            $incoming = @(Import-Csv -Path $Path -ErrorAction Stop)
        } else {
            $raw = Get-Content $Path -Raw -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($raw)) { throw "File is empty." }
            $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($parsed -is [System.Array]) { $incoming = @($parsed) } else { $incoming = @($parsed) }
        }
        $list = @(Get-BadActorList)
        $existing = @{}
        foreach ($e in $list) { $existing["$($e.ip)"] = $true }
        $changed = $false
        foreach ($m in $incoming) {
            $ip = "$($m.ip)".Trim()
            if ([string]::IsNullOrWhiteSpace($ip)) { $skippedBad++; continue }
            if (-not (Test-ValidIp $ip)) {
                Write-Host "  [!] Skipping invalid/non-routable IP in import: $ip" -ForegroundColor DarkYellow
                $skippedBad++; continue
            }
            if ($existing.ContainsKey($ip)) { $skippedDup++; continue }
            $desc = "Import mark for $ip"
            if ($PSCmdlet.ShouldProcess($desc, "Add to permanent blocklist")) {
                $entry = [pscustomobject]@{
                    ip        = $ip
                    reason    = "$($m.reason)"
                    evidence  = "$($m.evidence)"
                    markedUtc = (Get-Date).ToUniversalTime().ToString("o")
                    status    = "blocked-locally"
                }
                $list += $entry
                $existing[$ip] = $true
                $added++; $changed = $true
            }
        }
        if ($changed) {
            $path = Get-BlocklistPath
            ($list | ConvertTo-Json -Depth 5) | Out-File -FilePath $path -Encoding utf8
            Write-Host "  [+] Wrote updated blocklist: $path" -ForegroundColor Green
        }
        Write-Host "[*] Import done: $added added, $skippedDup duplicate(s) skipped, $skippedBad invalid row(s) skipped." -ForegroundColor Cyan
    } catch {
        throw "Import-BadActorList failed: $_"
    }
    if (-not [string]::IsNullOrWhiteSpace($VaultPath)) {
        Write-VaultDefenseEvent -VaultPath $VaultPath -EventName "bad-actor-list-imported" -Data (@{
            source = $Path; added = $added; duplicates = $skippedDup; invalid = $skippedBad
        }) | Out-Null
    }
    return [pscustomobject]@{ Added = $added; DuplicatesSkipped = $skippedDup; InvalidSkipped = $skippedBad }
}

# ---------------------------------------------------------------------------
# 10. Export-DefenseReport — the posture on one page. Marked actors,
#    firewall drift, hostile-session indicators, elevation. Exports
#    JSON + human-readable txt, each SHA-256 hashed. Read-only.
# ---------------------------------------------------------------------------
function Export-DefenseReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$false)][string]$VaultPath = ""
    )
    Write-Host "[*] Building defense posture report..." -ForegroundColor Cyan
    try {
        $marked = @(Get-BadActorList)
        $rules  = @(Get-NetFirewallRule -DisplayName "Falsum-Block-*" -ErrorAction SilentlyContinue)
        $hunts  = @()
        try { $hunts = @(Get-HostileSessionReport) } catch {
            Write-Host "  [!] Session hunt unavailable: $_" -ForegroundColor DarkYellow
        }
        $markedIps = @{}; foreach ($e in $marked) { $markedIps["$($e.ip)"] = $true }
        $driftIps = @()
        foreach ($e in $marked) {
            $rn = "Falsum-Block-$($e.ip)"
            if (@($rules | Where-Object { $_.DisplayName -eq $rn }).Count -eq 0) { $driftIps += $e.ip }
        }
        $report = [ordered]@{
            utc              = (Get-Date).ToUniversalTime().ToString("o")
            tool             = "Falsum-ActiveDefense/Export-DefenseReport"
            elevated         = (Test-IsAdmin)
            markedActors     = $marked.Count
            firewallRules    = $rules.Count
            driftMissingRule = @($driftIps)
            indicatorsFound  = $hunts.Count
            flaggedSessions  = @($hunts | ForEach-Object {
                "$($_.RemoteAddress):$($_.RemotePort) [$($_.ProcessName)] $($_.Indicators)"
            })
            markedList       = @($marked | ForEach-Object {
                [pscustomobject]@{ ip = $_.ip; reason = $_.reason; markedUtc = $_.markedUtc }
            })
        }
        $dir = Split-Path -Parent $Path
        if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $jsonPath = $Path
        if ($jsonPath -notmatch '\.json$') { $jsonPath = "$Path.json" }
        ($report | ConvertTo-Json -Depth 6) | Out-File -FilePath $jsonPath -Encoding utf8 -Force
        $txtPath = [System.IO.Path]::ChangeExtension($jsonPath, '.txt')
        $txt = @(
            "BLACKBOX ACTIVE DEFENSE POSTURE REPORT",
            "UTC: $($report.utc)",
            "Elevated: $($report.elevated)",
            "",
            "Marked bad actors: $($report.markedActors)",
            "Firewall block rules: $($report.firewallRules)",
            "Drift (marked, rule missing): " + $(if ($driftIps.Count -eq 0) { "(none — run Sync-FirewallBlockRules if drift appears)" } else { $driftIps -join ', ' }),
            "",
            "Established-session indicators: $($report.indicatorsFound)",
            ($hunts | ForEach-Object { "  [!] $($_.RemoteAddress):$($_.RemotePort) [$($_.ProcessName)] $($_.Indicators)" })
        ) -join "`r`n"
        $txt | Out-File -FilePath $txtPath -Encoding utf8 -Force
        $jh = (Get-FileHash -Path $jsonPath -Algorithm SHA256).Hash.ToLower()
        $th = (Get-FileHash -Path $txtPath -Algorithm SHA256).Hash.ToLower()
        Write-Host "[+] $jsonPath (SHA-256 $jh)" -ForegroundColor Green
        Write-Host "[+] $txtPath (SHA-256 $th)" -ForegroundColor Green
    } catch {
        throw "Export-DefenseReport failed: $_"
    }
    if (-not [string]::IsNullOrWhiteSpace($VaultPath)) {
        Write-VaultDefenseEvent -VaultPath $VaultPath -EventName "defense-report-exported" -Data (@{
            json = $jsonPath; txt = $txtPath; sha256Json = $jh; sha256Txt = $th
        }) | Out-Null
    }
    return [pscustomobject]@{ Json = $jsonPath; Txt = $txtPath; Sha256Json = $jh; Sha256Txt = $th }
}

# ---------------------------------------------------------------------------
# 11. Test-ActiveDefenseHygiene — self-test. Runs a battery of checks over
#    the module's own logic (IP validation, port byte-swap, indicator
#    tables, provider-desk table, blocklist-path shape) and reports
#    pass/fail per check. Deterministic, no network, no admin needed.
# ---------------------------------------------------------------------------
function Test-ActiveDefenseHygiene {
    [CmdletBinding()]
    param()
    Write-Host "[*] Active-defense self-test (no network, no admin)..." -ForegroundColor Cyan
    # -----------------------------------------------------------------------
    # Scope-safe result collection: &$add RUNS IN A CHILD SCOPE, so an
    # assignment like "$results += ..." inside it would silently vanish —
    # v1.1's battery printed 0/0 and always passed, a false green this
    # module exists to kill. The scriptblock RETURNS the row; the caller
    # appends the OUTPUT:  $results += &$add "name" $pass "detail"
    # -----------------------------------------------------------------------
    $results = @()
    $add = { param($name, $pass, $detail)
        [pscustomobject]@{ Check = $name; Pass = [bool]$pass; Detail = "$detail" }
    }

    # --- IP validation battery ---
    $ipCases = @(
        @('127.0.0.1',        $false, 'loopback must refuse'),
        @('8.8.8.8',          $true,  'public routable allowed'),
        @('192.168.1.10',     $true,  'private LAN allowed (LAN attacks are real)'),
        @('10.0.0.5',         $true,  'private LAN allowed'),
        @('224.0.0.1',        $false, 'multicast must refuse'),
        @('240.1.2.3',        $false, 'reserved must refuse'),
        @('0.1.2.3',          $false, '0.0.0.0/8 must refuse'),
        @('192.0.2.55',       $false, 'TEST-NET-1 must refuse'),
        @('198.51.100.9',     $false, 'TEST-NET-2 must refuse'),
        @('203.0.113.9',      $false, 'TEST-NET-3 must refuse'),
        @('999.1.1.1',        $false, 'garbage must refuse'),
        @('not-an-ip',        $false, 'garbage must refuse'),
        @('::1',              $false, 'IPv6 refused (tooling is v4-only)')
    )
    $ipFails = 0
    foreach ($c in $ipCases) {
        $got = Test-ValidIp $c[0]
        if ($got -ne $c[1]) { $ipFails++; $results += &$add ("Test-ValidIp $($c[0])") $false "expected $($c[1]), got $got — $($c[2])" }
    }
    if ($ipFails -eq 0) { $results += &$add "Test-ValidIp battery (13 cases)" $true "all pass" }

    # --- Port byte-swap ---
    $swapCases = @(
        @(80, 20480),   # 0x0050 -> 0x5000
        @(443, 47873),  # 0x01BB -> 0xBB01
        @(22, 5632),    # 0x0016 -> 0x1600
        @(8080, 36895)  # 0x1F90 -> 0x901F
    )
    $swapFails = 0
    foreach ($c in $swapCases) {
        try {
            $got = ConvertTo-NetworkByteOrderPort -Port $c[0]
            if ($got -ne $c[1]) { $swapFails++; $results += &$add "Port swap $($c[0])" $false "expected $($c[1]), got $got" }
        } catch { $swapFails++; $results += &$add "Port swap $($c[0])" $false "$_" }
    }
    if ($swapFails -eq 0) { $results += &$add "Port byte-swap (4 cases)" $true "all pass" }
    try { ConvertTo-NetworkByteOrderPort -Port 99999 | Out-Null
        $results += &$add "Port range guard" $false "accepted out-of-range port"
    } catch { $results += &$add "Port range guard" $true "rejects out-of-range port" }

    # --- Scope-safety regression: the pattern this battery runs on ---
    # A scriptblock invoked with & runs in a CHILD scope; capturing its
    # OUTPUT is what makes results survive. Prove it here, not by faith.
    $probe = @(&$add "scope-safety-probe" $true "output-capture probe")
    $results += &$add "Scope-safety pattern" ($probe.Count -eq 1 -and $probe[0].Check -eq "scope-safety-probe" -and $probe[0].Pass) "captured $($probe.Count) row(s) from child scope"

    # --- Provider desk table sanity: use the function's own table via known matches ---
    $d1 = Get-ProviderAbuseDesk -OrgName "Hetzner Online GmbH"
    $results += &$add "Provider desk: Hetzner" ($null -ne $d1 -and $d1.AbuseEmail -eq 'abuse@hetzner.de') "got: $($d1.AbuseEmail)"
    $d2 = Get-ProviderAbuseDesk -OrgName "AMAZON-02"
    $results += &$add "Provider desk: AWS" ($null -ne $d2 -and $d2.AbuseEmail -eq 'ec2-abuse@amazon.com') "got: $($d2.AbuseEmail)"
    $d5 = Get-ProviderAbuseDesk -OrgName "Hostinger International Ltd"
    $results += &$add "Provider desk: Hostinger" ($null -ne $d5 -and $d5.AbuseEmail -eq 'abuse@hostinger.com') "got: $($d5.AbuseEmail)"
    $d6 = Get-ProviderAbuseDesk -OrgName "Bluehost Inc."
    $results += &$add "Provider desk: Bluehost" ($null -ne $d6 -and $d6.AbuseEmail -eq 'abuse@bluehost.com') "got: $($d6.AbuseEmail)"
    $d7 = Get-ProviderAbuseDesk -OrgName "1&1 IONOS SE"
    $results += &$add "Provider desk: IONOS" ($null -ne $d7 -and $d7.AbuseEmail -eq 'abuse@ionos.com') "got: $($d7.AbuseEmail)"
    $d8 = Get-ProviderAbuseDesk -OrgName "Psychz Networks"
    $results += &$add "Provider desk: Psychz" ($null -ne $d8 -and $d8.AbuseEmail -eq 'abuse@psychz.net') "got: $($d8.AbuseEmail)"
    $d3 = Get-ProviderAbuseDesk -OrgName "Some Unknown ISP LLC"
    $results += &$add "Provider desk: unknown" ($null -eq $d3) "returns null for unknown org"
    $d4 = Get-ProviderAbuseDesk -OrgName ""
    $results += &$add "Provider desk: empty" ($null -eq $d4) "returns null for empty input"

    # --- Suspicious indicator-port table: THE table the hunt reads ---
    # Get-SuspiciousPortTable is the single source; the battery validates
    # that exact object, so hunt and test can never drift apart.
    $ptRows = @(Get-SuspiciousPortTable)
    $ptPorts = @($ptRows | ForEach-Object { $_.Port })
    $ptDup = @($ptPorts | Group-Object | Where-Object { $_.Count -gt 1 })
    $ptOor = @($ptPorts | Where-Object { $_ -lt 1 -or $_ -gt 65535 })
    $ptBadShape = @($ptRows | Where-Object { [string]::IsNullOrWhiteSpace($_.Service) -or [string]::IsNullOrWhiteSpace($_.Why) })
    $results += &$add "Indicator port table (single source)" `
        ($ptRows.Count -eq 31 -and $ptDup.Count -eq 0 -and $ptOor.Count -eq 0 -and $ptBadShape.Count -eq 0) `
        "$($ptRows.Count) rows, $($ptDup.Count) dup, $($ptOor.Count) out-of-range, $($ptBadShape.Count) shapeless"

    # --- Blocklist path shape ---
    $bp = Get-BlocklistPath
    $results += &$add "Blocklist path" ($bp -match 'badactors\.json$') "path: $bp"

    $passed = @($results | Where-Object { $_.Pass }).Count
    $failed = @($results | Where-Object { -not $_.Pass }).Count
    Write-Host "  $passed passed, $failed failed." -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Red' })
    foreach ($r in $results) {
        $mark = if ($r.Pass) { '[+]' } else { '[X]' }
        Write-Host "  $mark $($r.Check) — $($r.Detail)" -ForegroundColor $(if ($r.Pass) { 'Gray' } else { 'Red' })
    }
    return $failed -eq 0
}

# ---------------------------------------------------------------------------
# Boot notice
# ---------------------------------------------------------------------------
Write-Host "Falsum Active Defense loaded. $(@(Get-BadActorList).Count) actor(s) currently marked." -ForegroundColor DarkCyan
