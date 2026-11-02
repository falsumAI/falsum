<#
.SYNOPSIS
    Sentinel-VulnCheck.ps1 — local vulnerability and weak-config audit for
    the user's own Windows machine (the poison-pill security workstation).

.DESCRIPTION
    Audits the LOCAL machine only:
      - Windows Update status (last install date, pending count via the
        Windows Update Agent COM API, AU policy), wuauserv service state,
        baseline-KB freshness warning (the shipped table is frozen)
      - Installed cumulative update vs the shipped October-2026 baseline KB
        table (KB5127648 / KB5126653 / KB5127646 / KB513413x), plus OS
        end-of-updates detection (Win10, 24H2 Home/Pro, 23H2 Ent/Edu)
      - Weak configurations: SMBv1, LLMNR, NetBIOS-NS, RDP exposure,
        UAC level, Windows Defender real-time protection (third-party-AV
        aware — no false alarm when another AV owns the machine), firewall
        profiles, SMB signing, PowerShell v2 engine, AutoRun on removable
        media, guest accounts, unquoted service paths, open Wi-Fi, Secure
        Boot
      - Locally exposed risky services (listening sockets mapped to owning
        process) + optional cross-reference of a netscan report
      - Installed software vs a hardcoded EOL / known-bad-version table
        (Flash, Java 6/7, Python 2/3.9, Silverlight, QuickTime, Skype,
        old 7-Zip / WinRAR with published CVEs, PuTTY, Git, Node.js,
        Chrome/Edge/Firefox below current)

    THE BETTER-WAY LAW: every detection ships its fix. Each finding carries
    a FixCommand naming the matching Repair-* function in this file. Repairs
    are admin-gated, confirm-prompted (ConfirmImpact=High), and describe
    rollback. Default audit runs change NOTHING.

    PowerShell 5.1 compatible. Zero external dependencies. Local only —
    no scanning of other machines, no outbound active tests.

.NOTES
    Run from an elevated PowerShell for full coverage:
      powershell -ExecutionPolicy Bypass -File Sentinel-VulnCheck.ps1
    Hardening pass 2026-10-30: +9 checks (firewall profiles, wuauserv,
    guest/never-expire accounts, AutoRun, PSv2 engine, SMB signing,
    unquoted service paths, open Wi-Fi, Secure Boot) +8 repairs,
    Defender check is third-party-AV aware (no false Critical), baseline
    table carries a staleness warning, risky-port table 16->31 rows,
    EOL table 10->18 rows, HKCU software coverage.
    Hardening pass 2026-10-30 ~05:53 MDT (v1.2): +8 checks (TLS/SSL legacy
    protocols, BitLocker, admin shares, local password policy incl. lockout
    threshold, Remote Registry, WinRM unencrypted traffic, SMB server-side
    signing, remote-access tool review) + UDP listener coverage
    ($script:RiskyUdpPorts, Get-ExposedUdpServices) +9 repairs
    (Repair-DisableWeakTls, Repair-EnableBitLockerOsDrive,
    Repair-AdminShareDisable, Repair-RequirePasswordFor,
    Repair-LockoutThreshold, Repair-ExpireLocalPasswords,
    Repair-DisableRemoteRegistry, Repair-WinRMDenyUnencrypted,
    Repair-SmbServerSigningRequire) +6 EOL rows (Python 3.10, KeePass,
    TeamViewer, Wireshark, .NET 4.5.2-4.6.1).
    Hardening pass 2026-10-30 ~07:05 MDT (v1.3): CLOSED the unquoted-path
    false-positive — Test-UnquotedServicePaths now walks each path's
    directories with Get-Acl and only cries High when a user-writable
    segment precedes the exe (Get-UnquotedPathVerdict, pure + testable);
    NEW privesc-class checks: AlwaysInstallElevated (Critical, real SYSTEM
    vector) + repair, LSA Protection / RunAsPPL + repair, Credential Guard
    status, RDP-without-NLA escalation of the RDP check + repair; Defender
    tamper-protection check; firewall profiles now also flag
    DefaultInboundAction != Block; BitLocker flags missing RecoveryPassword
    protector; RiskyPorts 31->35 rows (4444, 11211, 7001, 5555),
    HighRiskPorts +4444/11211; EOL table 23->27 rows (WinSCP
    CVE-2023-48795, LibreOffice CVE-2024-5261, Adobe Acrobat/Reader APSB,
    Oracle VM VirtualBox CPU); NEW Test-VulnCheckHygiene offline battery
    (scope-safe result collection) wired into launcher option-18, the vuln
    menu, and tests/Test-All.ps1.
    Hardening pass 2026-10-30 ~11:00 MDT (v1.4): NEW credential-hygiene +
    logon-posture class — 8 checks (autologon plaintext password,
    WDigest caching, remote-UAC bypass, anonymous enumeration, cached
    logon count, screen lock, Defender exclusions, privileged group
    census) + 8 pure predicates + 8 Repair-* fixes; wired into
    New-VulnReport; battery section 9 (~40 cases); launcher vuln menu
    gains option 4 (credential-hygiene mini-audit).
#>

[CmdletBinding()]
param(
    [string]$NetScanReportPath = "",
    [string]$ReportOutDir = "$env:USERPROFILE\Sentinel\reports",
    [switch]$ExportReport
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Test-IsElevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function New-VulnFinding {
    param(
        [string]$Severity,   # Critical | High | Medium | Low | Info
        [string]$Category,
        [string]$Title,
        [string]$Evidence,
        [string]$FixGuidance,
        [string]$FixCommand = ""
    )
    [pscustomobject]@{
        Severity    = $Severity
        Category    = $Category
        Title       = $Title
        Evidence    = $Evidence
        FixGuidance = $FixGuidance
        FixCommand  = $FixCommand
        CheckedAt   = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Compare-VersionStrings {
    param([string]$A, [string]$B)
    # Returns -1 if A<B, 0 if equal, 1 if A>B. Numeric-aware, suffix-safe.
    try {
        $pa = $A -replace '[^\d\.]', '' -split '\.'
        $pb = $B -replace '[^\d\.]', '' -split '\.'
        $n = [Math]::Max($pa.Count, $pb.Count)
        for ($i = 0; $i -lt $n; $i++) {
            $x = 0; $y = 0
            if ($i -lt $pa.Count -and $pa[$i] -ne '') { [int]::TryParse($pa[$i], [ref]$x) | Out-Null }
            if ($i -lt $pb.Count -and $pb[$i] -ne '') { [int]::TryParse($pb[$i], [ref]$y) | Out-Null }
            if ($x -lt $y) { return -1 }
            if ($x -gt $y) { return  1 }
        }
        return 0
    } catch { return 0 }
}

# ---------------------------------------------------------------------------
# Pure-logic helpers (no Windows calls — testable offline by the hygiene
# battery). Live data stays in the Test-* functions; the CLASSIFICATION
# lives here so it can be proven correct without a Windows machine.
# ---------------------------------------------------------------------------

function Get-PortRiskSeverity {
    # Risk classification for a TCP port from the shipped tables. Pure.
    param([int]$Port)
    if (-not $script:RiskyPorts.ContainsKey($Port)) { return 'None' }
    if ($script:HighRiskPorts -contains $Port) { return 'High' }
    return 'Medium'
}

function ConvertFrom-NetAccountsLockout {
    # Parses "Lockout threshold" out of `net accounts` text. Returns the
    # integer, -1 for "Never" (lockout disabled), $null when unparseable.
    param([string]$NetAccountsText)
    $m = [regex]::Match($NetAccountsText, '(?im)^\s*Lockout threshold\s*:\s*(\S+)')
    if (-not $m.Success) { return $null }
    $v = $m.Groups[1].Value.Trim()
    if ($v -eq 'Never') { return -1 }
    $n = 0
    if ([int]::TryParse($v, [ref]$n)) { return $n }
    return $null
}

function Get-UnquotedPathVerdict {
    # Classifies ONE service ImagePath against the writable-segment list.
    # Pure logic; Test-UnquotedServicePaths gathers the live segments via
    # Get-Acl and hands them in. Verdicts:
    #   clean                — quoted, or no space, or exe segment spaceless
    #   exploitable          — unquoted + a user-writable dir precedes the exe
    #   unquoted-not-writable— unquoted but every segment is admin-only
    #   unparseable          — no .exe boundary found
    param(
        [string]$PathName,
        [string[]]$WritableSegments = @()
    )
    $p = $PathName.Trim()
    $out = [pscustomobject]@{
        Quoted          = $false
        HasSpace        = ($p -match '\s')
        ExePath         = ''
        WritableSegment = ''
        Verdict         = 'clean'
    }
    if ($p.StartsWith('"')) { $out.Quoted = $true; return $out }
    if (-not $out.HasSpace) { return $out }
    $m = [regex]::Match($p, '(?i)^(.+?\.exe)\b')
    if (-not $m.Success) { $out.Verdict = 'unparseable'; return $out }
    $exe = $m.Groups[1].Value
    $out.ExePath = $exe
    if ($exe -notmatch '\s') { return $out }   # spaces only in the args, not the binary
    $dir = $exe.Substring(0, $exe.LastIndexOf('\'))
    foreach ($w in $WritableSegments) {
        $wl = $w.ToLower(); $dl = $dir.ToLower()
        if ($dl -eq $wl -or $dl.StartsWith($wl + '\')) {
            $out.WritableSegment = $w
            $out.Verdict = 'exploitable'
            return $out
        }
    }
    $out.Verdict = 'unquoted-not-writable'
    return $out
}

function Get-WritablePathSegments {
    # Live (Windows-only): walks the directory ancestors of the exe named in
    # $PathName and returns those writable by non-administrators (Users,
    # Everyone, Authenticated Users, Interactive). Inherited ACEs count —
    # that is how the real attack works. Results are cached by directory.
    param([string]$PathName)
    if (-not $script:WritableDirCache) { $script:WritableDirCache = @{} }
    $found = @()
    try {
        $m = [regex]::Match($PathName.Trim(), '(?i)^(.+?\.exe)\b')
        if (-not $m.Success) { return @() }
        $cur = Split-Path $m.Groups[1].Value -Parent
        $root = [System.IO.Path]::GetPathRoot($cur)
        $parts = @()
        while ($cur -and $cur.ToLower() -ne $root.ToLower()) {
            $parts = @($cur) + $parts
            $cur = Split-Path $cur -Parent
        }
        $writeBits = [System.Security.AccessControl.FileSystemRights]::Write -bor `
                     [System.Security.AccessControl.FileSystemRights]::Modify -bor `
                     [System.Security.AccessControl.FileSystemRights]::FullControl
        foreach ($d in $parts) {
            if ($script:WritableDirCache.ContainsKey($d)) {
                if ($script:WritableDirCache[$d]) { $found += $d }
                continue
            }
            $writable = $false
            try {
                $acl = Get-Acl -Path $d -ErrorAction Stop
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    $id = [string]$ace.IdentityReference
                    $nonAdmin = $id -match 'BUILTIN\\Users|Everyone|NT AUTHORITY\\Authenticated Users|NT AUTHORITY\\INTERACTIVE'
                    if ($nonAdmin -and (($ace.FileSystemRights -band $writeBits) -ne 0)) {
                        $writable = $true; break
                    }
                }
            } catch { }
            $script:WritableDirCache[$d] = $writable
            if ($writable) { $found += $d }
        }
    } catch { }
    return $found
}

function Get-OsReleaseInfo {
    $info = @{ BuildPrefix = ''; Build = ''; Edition = ''; Caption = ''; Version = '' }
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $info.Build    = [string]$os.BuildNumber
        $info.Caption  = [string]$os.Caption
        $info.Version  = [string]$os.Version
        if ($info.Build.Length -ge 5) { $info.BuildPrefix = $info.Build.Substring(0,5) }
    } catch { }
    try {
        $rk = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($rk.EditionID) { $info.Edition = [string]$rk.EditionID }
        if ($rk.DisplayVersion) { $info.Version = [string]$rk.DisplayVersion }
    } catch { }
    return $info
}

# ---------------------------------------------------------------------------
# Baseline KB table — verified against Microsoft's October 2026 releases
# (Patch Tuesday 2026-10-13 + out-of-band 2026-10-26 eMudhra certificate-
# trust updates). This table ships FROZEN with the module. Refresh it each
# Patch Tuesday from the Microsoft Update Catalog / release-health pages.
# $script:BaselineTableDate feeds the staleness warning: a frozen table
# that is never refreshed becomes a lie, so the audit says so out loud.
# ---------------------------------------------------------------------------

$script:BaselineTableDate = '2026-10-13'

$script:BaselineKbs = @{
    # build-prefix -> @{ SecurityKB=..; OobKB=..; Note=.. }
    '26300' = @{ SecurityKB = 'KB5127648'; OobKB = 'KB5134133'; Note = 'Win11 26H2 -> build 26300.9711' }
    '26200' = @{ SecurityKB = 'KB5127648'; OobKB = 'KB5134133'; Note = 'Win11 25H2 -> build 26200.9711' }
    '26100' = @{ SecurityKB = 'KB5127648'; OobKB = 'KB5134133'; Note = 'Win11 24H2 -> build 26100.9711 (Home/Pro END OF UPDATES 2026-10-13)' }
    '28000' = @{ SecurityKB = 'KB5127646'; OobKB = 'KB5134134'; Note = 'Win11 26H1 (Arm) -> build 28000.3231' }
    '22631' = @{ SecurityKB = 'KB5126653'; OobKB = 'KB5134130'; Note = 'Win11 23H2 -> build 22631.7652 (Ent/Edu END OF UPDATES 2026-11-10)' }
    '22621' = @{ SecurityKB = 'KB5126653'; OobKB = 'KB5134130'; Note = 'Win11 23H2 -> build 22621.7652 (Ent/Edu END OF UPDATES 2026-11-10)' }
}

function Get-WindowsUpdateStatus {
    Write-Host '[*] Checking Windows Update status...' -ForegroundColor Cyan
    $findings = @()
    $os = Get-OsReleaseInfo

    # Last installed update via Get-HotFix
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } |
                    Sort-Object InstalledOn -Descending
        $installedIds = @($hotfixes | ForEach-Object { $_.HotFixID })
        if ($hotfixes.Count -gt 0) {
            $last = $hotfixes[0]
            $ageDays = ((Get-Date) - $last.InstalledOn).Days
            $ev = "Last update installed: $($last.HotFixID) on $($last.InstalledOn.ToString('yyyy-MM-dd')) ($ageDays days ago); $($installedIds.Count) hotfixes recorded."
            if ($ageDays -gt 45) {
                $findings += New-VulnFinding -Severity 'High' -Category 'WindowsUpdate' `
                    -Title 'No Windows update installed in 45+ days' -Evidence $ev `
                    -FixGuidance 'Run Windows Update now: Settings > Windows Update > Check for updates, or Start-WindowsUpdateScan/Install-WindowsUpdates.' `
                    -FixCommand 'Install-WindowsUpdates'
            } else {
                $findings += New-VulnFinding -Severity 'Info' -Category 'WindowsUpdate' `
                    -Title 'Recent update installed' -Evidence $ev `
                    -FixGuidance 'None needed.' -FixCommand ''
            }
        } else {
            $findings += New-VulnFinding -Severity 'High' -Category 'WindowsUpdate' `
                -Title 'No hotfix history found' -Evidence 'Get-HotFix returned no dated entries.' `
                -FixGuidance 'Run Windows Update immediately.' -FixCommand 'Install-WindowsUpdates'
        }
    } catch {
        $installedIds = @()
        $findings += New-VulnFinding -Severity 'Medium' -Category 'WindowsUpdate' `
            -Title 'Could not read hotfix history' -Evidence $_.Exception.Message `
            -FixGuidance 'Run Windows Update manually to confirm patch state.' -FixCommand ''
    }

    # Pending updates via Windows Update Agent COM API
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $searcher = $session.CreateUpdateSearcher()
        $result   = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $pending  = @($result.Updates | Where-Object { -not $_.IsDownloaded -or -not $_.IsInstalled })
        $critCount = @($pending | Where-Object { $_.MsrcSeverity -eq 'Critical' }).Count
        $ev = "$($pending.Count) pending update(s), $critCount rated Critical by MSRC."
        if ($pending.Count -gt 0) {
            $sev = if ($critCount -gt 0) { 'High' } else { 'Medium' }
            $titles = ($pending | Select-Object -First 5 -ExpandProperty Title) -join '; '
            $findings += New-VulnFinding -Severity $sev -Category 'WindowsUpdate' `
                -Title 'Pending Windows updates' -Evidence "$ev Sample: $titles" `
                -FixGuidance 'Install pending updates: Settings > Windows Update, or Install-WindowsUpdates.' `
                -FixCommand 'Install-WindowsUpdates'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WindowsUpdate' `
                -Title 'No pending updates' -Evidence $ev `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Medium' -Category 'WindowsUpdate' `
            -Title 'Windows Update Agent query failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check the Windows Update service (wuauserv) and run Settings > Windows Update manually.' -FixCommand ''
    }

    # Baseline KB check vs shipped October-2026 table
    try {
        $entry = $script:BaselineKbs[$os.BuildPrefix]
        if ($entry) {
            $missing = @()
            foreach ($kb in @($entry.SecurityKB, $entry.OobKB)) {
                if ($installedIds -notcontains $kb) { $missing += $kb }
            }
            if ($missing.Count -gt 0) {
                $findings += New-VulnFinding -Severity 'High' -Category 'BaselineKB' `
                    -Title "Missing October 2026 cumulative update(s): $($missing -join ', ')" `
                    -Evidence "$($entry.Note). Expected: $($entry.SecurityKB) (security) and/or $($entry.OobKB) (cert-trust OOB). Installed set does not contain: $($missing -join ', ')." `
                    -FixGuidance 'Install via Windows Update, or download from the Microsoft Update Catalog.' `
                    -FixCommand 'Install-WindowsUpdates'
            } else {
                $findings += New-VulnFinding -Severity 'Info' -Category 'BaselineKB' `
                    -Title 'October 2026 baseline KBs present' `
                    -Evidence "$($entry.SecurityKB) and $($entry.OobKB) both installed. $($entry.Note)." `
                    -FixGuidance 'None needed.' -FixCommand ''
            }
        } elseif ($os.Build -like '1904*') {
            $findings += New-VulnFinding -Severity 'Critical' -Category 'BaselineKB' `
                -Title 'Windows 10 is end of support (2025-10-14)' `
                -Evidence "OS build $($os.Build) ($($os.Caption)). Microsoft ended Windows 10 support on 2025-10-14; no security fixes ship." `
                -FixGuidance 'Upgrade to a supported Windows 11 version immediately. This machine gets no security patches.' -FixCommand ''
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'BaselineKB' `
                -Title 'Build not in baseline table' `
                -Evidence "Build prefix $($os.BuildPrefix) has no shipped baseline entry; the table covers Win11 23H2/24H2/25H2/26H1/26H2 as of Oct 2026." `
                -FixGuidance 'Verify your build against Microsoft release-health pages.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Medium' -Category 'BaselineKB' `
            -Title 'Baseline KB check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check installed updates manually against the October 2026 Patch Tuesday KBs.' -FixCommand ''
    }

    # OS end-of-updates conditions
    try {
        if ($os.BuildPrefix -eq '26100' -and $os.Edition -match '^(Core|Professional)$') {
            $findings += New-VulnFinding -Severity 'Critical' -Category 'WindowsUpdate' `
                -Title 'Windows 11 24H2 Home/Pro reached end of updates (2026-10-13)' `
                -Evidence "Edition $($os.Edition) on build 26100 no longer receives updates per Microsoft release-health." `
                -FixGuidance 'Move to Windows 11 25H2 or 26H2 to keep receiving security fixes.' -FixCommand ''
        }
        if (($os.BuildPrefix -eq '22631' -or $os.BuildPrefix -eq '22621') -and $os.Edition -match 'Enterprise|Education') {
            $findings += New-VulnFinding -Severity 'High' -Category 'WindowsUpdate' `
                -Title 'Windows 11 23H2 Enterprise/Education ends updates 2026-11-10' `
                -Evidence "Edition $($os.Edition) on build $($os.Build); last updates November 10, 2026." `
                -FixGuidance 'Plan the move to a supported Windows 11 version before the cutoff.' -FixCommand ''
        }
    } catch { }

    # Baseline-table freshness — a frozen table that is never refreshed lies.
    try {
        $tableAge = ((Get-Date) - [datetime]$script:BaselineTableDate).Days
        if ($tableAge -gt 35) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'BaselineKB' `
                -Title "Baseline KB table is $tableAge days old" `
                -Evidence "Shipped table dated $($script:BaselineTableDate) (October 2026 Patch Tuesday + OOB). A newer Patch Tuesday may have shipped." `
                -FixGuidance 'Verify the current build against Microsoft release-health pages. The module author refreshes this table monthly.' -FixCommand ''
        }
    } catch { }

    return $findings
}

function Start-WindowsUpdateScan {
    [CmdletBinding()]
    param()
    Write-Host '[*] Scanning for pending updates (read-only)...' -ForegroundColor Cyan
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result   = $searcher.Search("IsInstalled=0 and Type='Software'")
        foreach ($u in $result.Updates) {
            Write-Host "  PENDING: $($u.Title) [MSRC: $($u.MsrcSeverity)]"
        }
        Write-Host "[+] $($result.Updates.Count) pending update(s) found."
    } catch { Write-Host "[-] Scan failed: $($_.Exception.Message)" -ForegroundColor Red }
}

function Install-WindowsUpdates {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([switch]$IncludeOptional)
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation. Re-run as Administrator.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('Windows Update', 'Download and install all pending updates')) {
        try {
            $session  = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $filter   = "IsInstalled=0 and Type='Software'"
            if (-not $IncludeOptional) { $filter += " and BrowseOnly=0" }
            $result = $searcher.Search($filter)
            if ($result.Updates.Count -eq 0) { Write-Host '[+] Nothing to install.'; return }
            $downloader = $session.CreateUpdateDownloader()
            $downloader.Updates = $result.Updates
            Write-Host "[*] Downloading $($result.Updates.Count) update(s)..."
            $downloader.Download() | Out-Null
            $installer = $session.CreateUpdateInstaller()
            $installer.Updates = $result.Updates
            Write-Host '[*] Installing...'
            $ir = $installer.Install()
            Write-Host "[+] Install result: $($ir.ResultCode) (2=Succeeded, 3=SucceededWithErrors). RebootRequired=$($ir.RebootRequired)"
            if ($ir.RebootRequired) { Write-Host '[!] A reboot is required to finish.' -ForegroundColor Yellow }
        } catch { Write-Host "[-] Install failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

# ---------------------------------------------------------------------------
# Weak configuration checks — each ships its Repair-* fix (Better-Way Law)
# ---------------------------------------------------------------------------

function Test-WeakConfigs {
    Write-Host '[*] Checking weak configurations...' -ForegroundColor Cyan
    $findings = @()

    # SMBv1
    try {
        $smb1 = $false
        try {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
            $smb1 = ($feat.State -eq 'Enabled')
        } catch {
            $r = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -ErrorAction SilentlyContinue
            if ($r -and $r.SMB1 -eq 1) { $smb1 = $true }
        }
        if ($smb1) {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'SMBv1 is enabled' -Evidence 'SMB1Protocol optional feature is Enabled. SMBv1 has no encryption and enabled WannaCry/NotPetya-class worms.' `
                -FixGuidance 'Disable SMBv1: Repair-Smb1Disable. Rollback: Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.' `
                -FixCommand 'Repair-Smb1Disable'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'SMBv1 disabled' -Evidence 'SMB1Protocol not enabled.' -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'SMBv1 check inconclusive' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually: Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.' -FixCommand ''
    }

    # LLMNR
    try {
        $llmnr = $true
        $r = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue
        if ($r -and $r.EnableMulticast -eq 0) { $llmnr = $false }
        if ($llmnr) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title 'LLMNR is enabled' -Evidence 'EnableMulticast is not set to 0. LLMNR answers name queries on the LAN and enables responder-style credential capture.' `
                -FixGuidance 'Disable via Group Policy or Repair-LlmnrDisable. Rollback: remove the EnableMulticast=0 value.' `
                -FixCommand 'Repair-LlmnrDisable'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'LLMNR disabled' -Evidence 'EnableMulticast=0 policy present.' -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' -Title 'LLMNR check inconclusive' `
            -Evidence $_.Exception.Message -FixGuidance 'Verify manually in registry.' -FixCommand ''
    }

    # NetBIOS over TCP/IP (name-service poisoning sibling of LLMNR)
    try {
        $nbns = @()
        $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction Stop
        foreach ($a in $adapters) {
            if ($a.TcpipNetbiosOptions -eq 0 -or $a.TcpipNetbiosOptions -eq 1) { $nbns += $a.Description }
        }
        if ($nbns.Count -gt 0) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title 'NetBIOS over TCP/IP enabled on adapters' `
                -Evidence "Adapters with NetBT enabled: $($nbns -join '; '). NBT-NS enables the same responder-style poisoning as LLMNR." `
                -FixGuidance 'Set NetBIOS to "Disable" in adapter IPv4 > Advanced > WINS, or Repair-NetBiosDisable. Rollback: set TcpipNetbiosOptions back to 0/1.' `
                -FixCommand 'Repair-NetBiosDisable'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'NetBIOS over TCP/IP disabled' -Evidence 'All IP-enabled adapters have NetBT disabled (option 2).' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' -Title 'NetBIOS check inconclusive' `
            -Evidence $_.Exception.Message -FixGuidance 'Verify manually.' -FixCommand ''
    }

    # RDP exposure
    try {
        $rdpDeny = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
        $rdpOn = ($rdpDeny -and $rdpDeny.fDenyTSConnections -eq 0)
        $fwRules = @()
        try {
            $fwRules = Get-NetFirewallRule -ErrorAction Stop | Where-Object {
                $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and
                ($_.DisplayName -match 'Remote Desktop|RDP') }
        } catch { }
        if ($rdpOn) {
            $portOpen = $false
            try {
                $c = New-Object Net.Sockets.TcpClient
                $iar = $c.BeginConnect('127.0.0.1', 3389, $null, $null)
                $portOpen = $iar.AsyncWaitHandle.WaitOne(1500)
                $c.Close()
            } catch { }
            $ev = "fDenyTSConnections=0 (RDP allowed). Firewall rules: $(@($fwRules | ForEach-Object DisplayName) -join '; '). Local 3389 reachable: $portOpen."
            $sev = if ($portOpen) { 'High' } else { 'Medium' }
            $findings += New-VulnFinding -Severity $sev -Category 'WeakConfig' `
                -Title 'Remote Desktop is enabled' -Evidence $ev `
                -FixGuidance 'If RDP is not needed: disable in Settings > System > Remote Desktop, or Repair-RdpDisable. If needed: require NLA, use a VPN, restrict firewall scope. Rollback: re-enable the same way.' `
                -FixCommand 'Repair-RdpDisable'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'Remote Desktop disabled' -Evidence 'fDenyTSConnections=1.' -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' -Title 'RDP check inconclusive' `
            -Evidence $_.Exception.Message -FixGuidance 'Verify manually.' -FixCommand ''
    }

    # UAC level
    try {
        $lua = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction SilentlyContinue
        $cpb = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue
        $level = 'unknown'
        $weak  = $false
        if ($lua -and $lua.EnableLUA -eq 0) { $level = 'disabled'; $weak = $true }
        elseif ($cpb) {
            switch ($cpb.ConsentPromptBehaviorAdmin) {
                0 { $level = 'never notify (weakest)'; $weak = $true }
                1 { $level = 'prompt for credentials on secure desktop' }
                2 { $level = 'prompt for consent on secure desktop' }
                5 { $level = 'prompt for consent (non-admin changes)' }
            }
        }
        if ($weak) {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title "UAC is weakened: $level" `
                -Evidence "EnableLUA=$($lua.EnableLUA), ConsentPromptBehaviorAdmin=$($cpb.ConsentPromptBehaviorAdmin). Malware can silently elevate." `
                -FixGuidance 'Set UAC to at least "prompt for consent": Repair-UacHarden. Rollback: restore previous values.' `
                -FixCommand 'Repair-UacHarden'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title "UAC at acceptable level: $level" -Evidence "EnableLUA=$($lua.EnableLUA), ConsentPromptBehaviorAdmin=$($cpb.ConsentPromptBehaviorAdmin)." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' -Title 'UAC check inconclusive' `
            -Evidence $_.Exception.Message -FixGuidance 'Verify manually.' -FixCommand ''
    }

    # Defender real-time protection — third-party-AV aware. A machine whose
    # registered AV provider is someone else's product is NOT "unprotected";
    # the old code cried Critical there. Check SecurityCenter2 first.
    try {
        $thirdPartyAv = $null
        try {
            $avProducts = Get-CimInstance -Namespace 'ROOT\SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop
            foreach ($av in $avProducts) {
                # productState state byte (bits 16-23): 0x6 = enabled.
                # Empirical: enabled products report 0x6xxxx (e.g. 397312 =
                # on+current, 393472 = on+outdated); disabled report 0x4xxxx.
                $avState = ($av.productState -band 0xF0000)
                if ($av.displayName -notmatch 'Windows Defender' -and $avState -eq 0x60000) {
                    $thirdPartyAv = [string]$av.displayName
                }
            }
        } catch { }
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $rt = $mp.RealTimeProtectionEnabled
        $defsAge = $null
        try { $defsAge = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days } catch { }
        if (-not $rt) {
            if ($thirdPartyAv) {
                $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                    -Title "Defender off — third-party AV owns protection ($thirdPartyAv)" `
                    -Evidence "RealTimeProtectionEnabled=$rt, but SecurityCenter2 reports '$thirdPartyAv' as the enabled provider. This is expected, not a gap." `
                    -FixGuidance 'None needed — confirm the third-party product is actually updating.' -FixCommand ''
            } else {
                $findings += New-VulnFinding -Severity 'Critical' -Category 'WeakConfig' `
                    -Title 'Defender real-time protection is OFF' `
                    -Evidence "RealTimeProtectionEnabled=$rt. Signatures last updated: $($mp.AntivirusSignatureLastUpdated). No other AV provider registered." `
                    -FixGuidance 'Re-enable: Repair-DefenderRealTime. If a third-party AV owns protection, confirm it is actually running. Rollback: Set-MpPreference -DisableRealtimeMonitoring $true (not recommended).' `
                    -FixCommand 'Repair-DefenderRealTime'
            }
        } elseif ($defsAge -ne $null -and $defsAge -gt 7) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title "Defender signatures are $defsAge days old" `
                -Evidence "AntivirusSignatureLastUpdated=$($mp.AntivirusSignatureLastUpdated)." `
                -FixGuidance 'Update-DefenderSignatures via Repair-DefenderRealTime -UpdateSignatures.' `
                -FixCommand 'Repair-DefenderRealTime'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'Defender real-time protection on' `
                -Evidence "Signatures current as of $($mp.AntivirusSignatureLastUpdated)." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
            -Title 'Defender status unreadable' -Evidence $_.Exception.Message `
            -FixGuidance 'Open Windows Security and confirm real-time protection is on.' -FixCommand ''
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Additional hardening checks (added 2026-10-30). Each detection ships its
# Repair-* fix right below (Better-Way Law).
# ---------------------------------------------------------------------------

function Test-FirewallProfiles {
    Write-Host '[*] Checking Windows Firewall profiles...' -ForegroundColor Cyan
    $findings = @()
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $off = @($profiles | Where-Object { $_.Enabled -ne $true -and $_.Enabled -ne 'True' })
        foreach ($p in $off) {
            $findings += New-VulnFinding -Severity 'Critical' -Category 'WeakConfig' `
                -Title "Windows Firewall $($p.Name) profile is OFF" `
                -Evidence "Profile $($p.Name): Enabled=$($p.Enabled), DefaultInboundAction=$($p.DefaultInboundAction). Host firewall is the last local barrier." `
                -FixGuidance 'Re-enable all profiles: Repair-FirewallEnable. Rollback: Set-NetFirewallProfile -Name <Profile> -Enabled False.' `
                -FixCommand 'Repair-FirewallEnable'
        }
        # v1.3: a profile that is ON but defaults to ALLOW inbound is a
        # firewall in name only. Flag each one that is not Block.
        foreach ($p in ($profiles | Where-Object { $_.Enabled -eq $true -or $_.Enabled -eq 'True' })) {
            if ($p.DefaultInboundAction -ne 'Block') {
                $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                    -Title "Firewall $($p.Name) profile defaults to ALLOW inbound" `
                    -Evidence "Profile $($p.Name): Enabled=$($p.Enabled), DefaultInboundAction=$($p.DefaultInboundAction). New inbound connections are allowed by default — the profile protects nothing it was not told about." `
                    -FixGuidance 'Set the default to Block: Repair-FirewallDefaultDeny. Rollback: Set-NetFirewallProfile -Name <Profile> -DefaultInboundAction Allow.' `
                    -FixCommand 'Repair-FirewallDefaultDeny'
            }
        }
        if ($off.Count -eq 0) {
            $names = ($profiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', '
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'All firewall profiles on' -Evidence $names `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'Firewall profile check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check wf.msc manually.' -FixCommand ''
    }
    return $findings
}

function Test-WindowsUpdateService {
    Write-Host '[*] Checking Windows Update service...' -ForegroundColor Cyan
    $findings = @()
    try {
        $svc = Get-Service -Name 'wuauserv' -ErrorAction Stop
        $startMode = ''
        try { $startMode = (Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -ErrorAction Stop).StartMode } catch { }
        # Note: wuauserv is legitimately Stopped+Manual (trigger-start) when
        # idle. Only Disabled is a finding.
        if ($startMode -eq 'Disabled') {
            $findings += New-VulnFinding -Severity 'High' -Category 'WindowsUpdate' `
                -Title 'Windows Update service is DISABLED' `
                -Evidence "wuauserv StartMode=Disabled, Status=$($svc.Status). Updates cannot install." `
                -FixGuidance 'Restore the service: Repair-WindowsUpdateService. Rollback: Set-Service wuauserv -StartupType Disabled.' `
                -FixCommand 'Repair-WindowsUpdateService'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WindowsUpdate' `
                -Title 'Windows Update service available' `
                -Evidence "wuauserv Status=$($svc.Status), StartMode=$startMode." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Medium' -Category 'WindowsUpdate' `
            -Title 'Windows Update service check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify wuauserv exists and can start: services.msc.' -FixCommand ''
    }
    return $findings
}

function Test-GuestAccounts {
    Write-Host '[*] Checking guest and local accounts...' -ForegroundColor Cyan
    $findings = @()
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'Guest account is enabled' `
                -Evidence 'Guest is enabled. It is a classic unauthenticated foothold.' `
                -FixGuidance 'Disable it: Repair-GuestDisable. Rollback: Enable-LocalUser -Name Guest.' `
                -FixCommand 'Repair-GuestDisable'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'Guest account disabled' -Evidence 'Guest not present or disabled.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'Guest account check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually: Get-LocalUser -Name Guest.' -FixCommand ''
    }
    try {
        $neverExp = @()
        foreach ($u in (Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -and $_.PasswordNeverExpires })) {
            $neverExp += $u.Name
        }
        if ($neverExp.Count -gt 0) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title 'Local accounts with passwords that never expire' `
                -Evidence "Accounts: $($neverExp -join ', '). Stale passwords are credential-theft targets." `
                -FixGuidance 'Rotate the passwords and clear the flag: Repair-ExpireLocalPasswords.' `
                -FixCommand 'Repair-ExpireLocalPasswords'
        }
    } catch { }
    return $findings
}

function Test-AutoRun {
    Write-Host '[*] Checking AutoRun/AutoPlay on removable media...' -ForegroundColor Cyan
    $findings = @()
    try {
        # 0xFF (255) = AutoRun disabled on all drive types. Anything else
        # lets a plugged-in USB run code.
        $weak = $false
        $vals = @()
        foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
                            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) {
            $r = Get-ItemProperty $hive -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue
            if ($r) { $vals += "$hive=$($r.NoDriveTypeAutoRun)"; if ([int]$r.NoDriveTypeAutoRun -ne 255) { $weak = $true } }
            else { $vals += "$hive=(not set)"; $weak = $true }
        }
        if ($weak) {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'AutoRun is not fully disabled' `
                -Evidence "$($vals -join '; '). A malicious USB stick can auto-execute." `
                -FixGuidance 'Disable everywhere: Repair-AutoRunDisable. Rollback: delete NoDriveTypeAutoRun or set 149 (XP-era default).' `
                -FixCommand 'Repair-AutoRunDisable'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'AutoRun disabled on all drive types' -Evidence ($vals -join '; ') `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'AutoRun check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually in the registry.' -FixCommand ''
    }
    return $findings
}

function Test-PowerShellV2 {
    Write-Host '[*] Checking for PowerShell v2 engine...' -ForegroundColor Cyan
    $findings = @()
    try {
        $found = $false
        foreach ($feat in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
            try {
                $f = Get-WindowsOptionalFeature -Online -FeatureName $feat -ErrorAction Stop
                if ($f.State -eq 'Enabled') {
                    $found = $true
                    $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                        -Title "PowerShell v2 engine installed ($feat)" `
                        -Evidence 'PSv2 has no AMSI/script-block logging and is the classic downgrade-attack target for bypassing modern defenses.' `
                        -FixGuidance "Remove it: Repair-PowerShellV2Disable. Rollback: Enable-WindowsOptionalFeature -Online -FeatureName $feat." `
                        -FixCommand 'Repair-PowerShellV2Disable'
                }
            } catch { }
        }
        if (-not $found) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'PowerShell v2 engine absent' -Evidence 'No PSv2 optional feature enabled.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'PowerShell v2 check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually: Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root.' -FixCommand ''
    }
    return $findings
}

function Test-SmbSigning {
    Write-Host '[*] Checking SMB signing requirement...' -ForegroundColor Cyan
    $findings = @()
    try {
        $r = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue
        $val = -1
        if ($r) { $val = [int]$r.RequireSecuritySignature }
        if ($val -ne 1) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title 'SMB signing not required on outbound connections' `
                -Evidence "LanmanWorkstation RequireSecuritySignature=$val (0/absent). Unsigned SMB allows NTLM relay attacks." `
                -FixGuidance 'Require signing: Repair-SmbSigningRequire (reboot to take effect). Rollback: set RequireSecuritySignature back to 0.' `
                -FixCommand 'Repair-SmbSigningRequire'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'SMB signing required' -Evidence 'RequireSecuritySignature=1.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'SMB signing check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually in the registry.' -FixCommand ''
    }
    return $findings
}

function Test-UnquotedServicePaths {
    # v1.3: the old code flagged EVERY unquoted path with spaces. That is
    # the textbook rule, but it cries wolf when no path segment is
    # user-writable — nothing lower-privileged can plant there. The new
    # code walks each path's directories with Get-Acl and only rates the
    # finding High when a non-admin-writable segment actually precedes the
    # exe (Get-UnquotedPathVerdict, pure logic — see the hygiene battery).
    Write-Host '[*] Checking for unquoted service paths...' -ForegroundColor Cyan
    $findings = @()
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.PathName }
        $exploitable = 0; $hardened = 0; $checked = 0
        foreach ($s in $svcs) {
            $p = $s.PathName.Trim()
            if ($p.StartsWith('"') -or $p -notmatch '\s') { $checked++; continue }
            $writable = Get-WritablePathSegments -PathName $p
            $verdict = Get-UnquotedPathVerdict -PathName $p -WritableSegments $writable
            $checked++
            if ($verdict.Verdict -eq 'exploitable') {
                $exploitable++
                $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                    -Title "Unquoted service path (EXPLOITABLE): $($s.Name)" `
                    -Evidence "ImagePath: $p. Segment '$($verdict.WritableSegment)' is writable by a non-administrator, so a planted binary at that level runs as SYSTEM." `
                    -FixGuidance "Quote the binary path: Repair-UnquotedServicePath -ServiceName '$($s.Name)'." `
                    -FixCommand "Repair-UnquotedServicePath -ServiceName '$($s.Name)'"
            } elseif ($verdict.Verdict -eq 'unquoted-not-writable') {
                $hardened++
                $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                    -Title "Unquoted service path (not currently writable): $($s.Name)" `
                    -Evidence "ImagePath: $p. No segment is user-writable today, but ACLs change — quoting is the permanent fix." `
                    -FixGuidance "Quote the binary path: Repair-UnquotedServicePath -ServiceName '$($s.Name)'." `
                    -FixCommand "Repair-UnquotedServicePath -ServiceName '$($s.Name)'"
            } elseif ($verdict.Verdict -eq 'unparseable') {
                $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
                    -Title "Unparseable service path: $($s.Name)" -Evidence "ImagePath: $p." `
                    -FixGuidance 'Inspect the ImagePath manually; quote the binary if it contains spaces.' -FixCommand ''
            }
        }
        if ($exploitable -eq 0 -and $hardened -eq 0) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'No unquoted service paths' -Evidence "$checked services checked." `
                -FixGuidance 'None needed.' -FixCommand ''
        } else {
            Write-Host ("  [!] {0} exploitable, {1} unquoted-but-hardened" -f $exploitable, $hardened) -ForegroundColor Yellow
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'Service-path check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check manually: wmic service get name,pathname' -FixCommand ''
    }
    return $findings
}

function Test-OpenWifi {
    Write-Host '[*] Checking Wi-Fi encryption...' -ForegroundColor Cyan
    $findings = @()
    try {
        $raw = netsh wlan show interfaces 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) {
            return @(New-VulnFinding -Severity 'Info' -Category 'Network' `
                -Title 'No Wi-Fi interface' -Evidence 'netsh wlan show interfaces returned no data (wired or no WLAN).' `
                -FixGuidance 'None needed.' -FixCommand '')
        }
        $open = @()
        $blocks = ($raw -join "`n") -split '(?m)^\s*Name\s*:'
        foreach ($b in $blocks) {
            # \b anchors matter: "disconnected" must NOT match "connected".
            if ($b -match '(?im)^\s*State\s*:\s*connected\s*$' -and $b -match '(?im)^\s*Authentication\s*:\s*Open\s*$') {
                $ssid = ''
                $mm = [regex]::Match($b, '(?im)^\s*SSID\s*:\s*(.+?)\s*$')
                if ($mm.Success) { $ssid = $mm.Groups[1].Value.Trim() }
                $open += $ssid
            }
        }
        if ($open.Count -gt 0) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'Network' `
                -Title 'Connected to an open (unencrypted) Wi-Fi network' `
                -Evidence "Open SSID(s): $($open -join ', '). Traffic on open Wi-Fi is readable to anyone in range." `
                -FixGuidance 'Use a VPN on open networks, or move to WPA2/WPA3. Avoid sensitive logins without a VPN.' -FixCommand ''
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'Network' `
                -Title 'No open Wi-Fi connection' -Evidence 'No connected interface uses Open authentication.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'Network' `
            -Title 'Wi-Fi check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually: netsh wlan show interfaces.' -FixCommand ''
    }
    return $findings
}

function Get-SecureBootStatus {
    Write-Host '[*] Checking Secure Boot...' -ForegroundColor Cyan
    try {
        $r = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled' -ErrorAction Stop
        if ([int]$r.UEFISecureBootEnabled -eq 1) {
            return @(New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
                -Title 'Secure Boot is on' -Evidence 'UEFISecureBootEnabled=1.' `
                -FixGuidance 'None needed.' -FixCommand '')
        }
        return @(New-VulnFinding -Severity 'Medium' -Category 'PlatformSecurity' `
            -Title 'Secure Boot is OFF' -Evidence 'UEFISecureBootEnabled=0. The machine can boot unsigned bootloaders and bootkits.' `
            -FixGuidance 'Enable Secure Boot in the UEFI firmware settings.' -FixCommand '')
    } catch {
        return @(New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
            -Title 'Secure Boot state unknown' -Evidence $_.Exception.Message `
            -FixGuidance 'Check firmware settings manually.' -FixCommand '')
    }
}

# ---------------------------------------------------------------------------
# Hardening pass v1.2 (2026-10-30 ~05:53 MDT): platform and protocol checks.
# Each detection ships its Repair-* fix (Better-Way Law). All read-only by
# default; repairs are admin-gated + confirm-prompted.
# ---------------------------------------------------------------------------

function Test-TlsProtocols {
    Write-Host '[*] Checking legacy TLS/SSL protocol state...' -ForegroundColor Cyan
    $findings = @()
    try {
        # Honesty rule: only flag what is EXPLICITLY enabled in the registry.
        # Absent keys = OS default applies (disabled by default on Win11
        # 22H2+ / Server 2022+ for TLS 1.0/1.1). No false alarms.
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
        $legacy = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')
        $weak = @()
        $okInfo = @()
        foreach ($proto in $legacy) {
            foreach ($side in @('Client', 'Server')) {
                $k = Join-Path (Join-Path $base $proto) $side
                $r = Get-ItemProperty $k -ErrorAction SilentlyContinue
                if (-not $r) { continue }
                if ($r.Enabled -eq 1 -and $r.DisabledByDefault -ne 1) {
                    $weak += "$proto/$side"
                } else {
                    $okInfo += "$proto/$side disabled"
                }
            }
        }
        if ($weak.Count -gt 0) {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'Legacy TLS/SSL protocols explicitly enabled' `
                -Evidence "Enabled in SCHANNEL registry: $($weak -join ', '). SSL 2.0/3.0 and TLS 1.0/1.1 carry published protocol flaws (POODLE, BEAST-class, weak ciphers)." `
                -FixGuidance 'Disable them: Repair-DisableWeakTls (sets Enabled=0/DisabledByDefault=1, reboot). Rollback: delete the Enabled/DisabledByDefault values to restore OS default.' `
                -FixCommand 'Repair-DisableWeakTls'
        } else {
            $note = if ($okInfo.Count -gt 0) { $okInfo -join '; ' } else { 'no explicit protocol keys; OS default applies (TLS 1.0/1.1 disabled by default on Win11 22H2+)' }
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'No legacy TLS/SSL protocol explicitly enabled' -Evidence $note `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'TLS protocol check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually in the SCHANNEL registry.' -FixCommand ''
    }
    return $findings
}

function Repair-DisableWeakTls {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('SCHANNEL', 'Disable SSL 2.0/3.0 and TLS 1.0/1.1 client+server')) {
        try {
            $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
            foreach ($proto in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')) {
                foreach ($side in @('Client', 'Server')) {
                    $k = Join-Path (Join-Path $base $proto) $side
                    if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
                    Set-ItemProperty -Path $k -Name 'Enabled' -Value 0 -Type DWord
                    Set-ItemProperty -Path $k -Name 'DisabledByDefault' -Value 1 -Type DWord
                    Write-Host "  Disabled $proto/$side"
                }
            }
            Write-Host '[+] Legacy protocols disabled. REBOOT required. Rollback: delete the Enabled/DisabledByDefault values.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-BitLockerStatusVerdict {
    # Pure classifier: exactly one verdict per drive state. This is the
    # regression guard for the v1.3 bug where the 'NOT encrypted' finding
    # was appended INSIDE the FullyEncrypted branch, so an encrypted drive
    # got contradictory findings ("encrypted" AND "NOT encrypted").
    [CmdletBinding()]
    param([string]$VolumeStatus = '', [bool]$HasRecovery = $false)
    if ($VolumeStatus -eq '') { return 'unreadable' }
    if ($VolumeStatus -eq 'FullyEncrypted') {
        if ($HasRecovery) { return 'encrypted-ok' }
        return 'no-recovery'
    }
    return 'not-encrypted'
}

function Test-BitLocker {
    Write-Host '[*] Checking BitLocker on the OS drive...' -ForegroundColor Cyan
    $findings = @()
    try {
        $vol = $null
        try { $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch { }
        if (-not $vol) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
                -Title 'BitLocker status unreadable' -Evidence 'Get-BitLockerVolume returned no data (BitLocker feature may be absent on this edition).' `
                -FixGuidance 'Check Settings > Privacy & security > Device encryption manually.' -FixCommand ''
        } elseif ($vol.VolumeStatus -eq 'FullyEncrypted') {
            # v1.3: encrypted is not enough — without a RecoveryPassword
            # protector, a TPM hiccup or board swap turns the disk into a
            # brick. Flag the missing protector honestly.
            $hasRecovery = $false
            try {
                foreach ($kp in $vol.KeyProtector) {
                    if ([string]$kp.KeyProtectorType -match 'RecoveryPassword') { $hasRecovery = $true }
                }
            } catch { }
            $verdict = Test-BitLockerStatusVerdict -VolumeStatus $vol.VolumeStatus -HasRecovery $hasRecovery
            if ($verdict -eq 'encrypted-ok') {
                $findings += New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
                    -Title 'OS drive is BitLocker-encrypted' -Evidence "$($vol.MountPoint): $($vol.VolumeStatus), ProtectionStatus=$($vol.ProtectionStatus), RecoveryPassword protector present." `
                    -FixGuidance 'None needed — keep the recovery key somewhere safe off this machine.' -FixCommand ''
            } elseif ($verdict -eq 'no-recovery') {
                $findings += New-VulnFinding -Severity 'High' -Category 'PlatformSecurity' `
                    -Title 'BitLocker encrypted but NO recovery password protector' `
                    -Evidence "$($vol.MountPoint): $($vol.VolumeStatus), ProtectionStatus=$($vol.ProtectionStatus). No RecoveryPassword key protector — lose the TPM state and the data is unrecoverable." `
                    -FixGuidance 'Add one now: Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector, then copy the key OFF this machine.' `
                    -FixCommand ''
            } else {
                $findings += New-VulnFinding -Severity 'High' -Category 'PlatformSecurity' `
                    -Title 'OS drive is NOT encrypted' `
                    -Evidence "$($vol.MountPoint): $($vol.VolumeStatus). A stolen or seized disk gives up everything without full-disk encryption." `
                    -FixGuidance 'Encrypt it: Repair-EnableBitLockerOsDrive (requires TPM; interactive). Save the recovery key off-machine before starting.' `
                    -FixCommand 'Repair-EnableBitLockerOsDrive'
            }
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'PlatformSecurity' `
            -Title 'BitLocker check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check manually: manage-bde -status.' -FixCommand ''
    }
    return $findings
}

function Repair-EnableBitLockerOsDrive {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([string]$RecoveryKeyPath = '')
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    # Server Core / redirected profiles: the Desktop special folder can
    # resolve empty; never build a recovery-key path the user can't find.
    if ([string]::IsNullOrWhiteSpace($RecoveryKeyPath)) {
        $desk = [Environment]::GetFolderPath('Desktop')
        if ([string]::IsNullOrWhiteSpace($desk)) { $desk = (Get-Location).Path }
        $RecoveryKeyPath = Join-Path $desk 'BitLocker-Recovery-Key.txt'
    }
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if (-not ($tpm.TpmPresent -and $tpm.TpmReady)) {
            Write-Host '[-] TPM is not present/ready. BitLocker without a TPM needs a startup PIN/USB key — see manage-bde -protectors -add.' -ForegroundColor Red
            return
        }
    } catch { Write-Host "[-] TPM check failed: $($_.Exception.Message)" -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess($env:SystemDrive, 'Enable BitLocker with a recovery password protector')) {
        try {
            $key = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -ErrorAction Stop
            $key.RecoveryPassword | Set-Content $RecoveryKeyPath -Encoding UTF8
            Write-Host "[+] Recovery key saved to: $RecoveryKeyPath  — COPY IT OFF THIS MACHINE NOW." -ForegroundColor Yellow
            Enable-BitLocker -MountPoint $env:SystemDrive -TpmProtector -ErrorAction Stop | Out-Null
            Write-Host '[+] BitLocker encryption started. It runs in the background; do not power off until done.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-AdminShares {
    Write-Host '[*] Checking administrative shares...' -ForegroundColor Cyan
    $findings = @()
    try {
        $raw = net share 2>$null
        $shares = @()
        if ($LASTEXITCODE -eq 0 -and $raw) {
            foreach ($line in $raw) {
                if ($line -match '^\s*(\S+?\$)\s+') { $shares += $matches[1] }
            }
        }
        $disk = @($shares | Where-Object { $_ -match '^[A-Za-z]\$$' })
        if ($disk.Count -gt 0 -or ($shares -contains 'ADMIN$')) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title 'Administrative shares are exposed' `
                -Evidence "Shares present: $($shares -join ', '). Hidden admin shares are a classic lateral-movement target for any credential the attacker lands." `
                -FixGuidance 'Disable them: Repair-AdminShareDisable (AutoShareWks=0, reboot; IPC$ stays by design). If you remote-admin this machine, use WinRM/SSH instead. Rollback: delete AutoShareWks or set 1.' `
                -FixCommand 'Repair-AdminShareDisable'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'No administrative shares exposed' -Evidence "net share reports: $($shares -join ', ')" `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'Admin-share check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually: net share.' -FixCommand ''
    }
    return $findings
}

function Repair-AdminShareDisable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('admin shares', 'Set AutoShareWks=0 (disables ADMIN$, C$, etc. — IPC$ remains)')) {
        try {
            $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Set-ItemProperty -Path $p -Name 'AutoShareWks' -Value 0 -Type DWord
            Write-Host '[+] Administrative shares disabled. REBOOT required. Rollback: delete AutoShareWks or set 1.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-LocalPasswordPolicy {
    Write-Host '[*] Checking local account password policy...' -ForegroundColor Cyan
    $findings = @()
    try {
        foreach ($u in (Get-LocalUser -ErrorAction Stop)) {
            if (-not $u.Enabled) { continue }
            # PasswordNotRequired = blank password allowed. Critical.
            if ($u.PasswordRequired -eq $false -and $u.Name -ne 'Guest' -and $u.Name -ne 'DefaultAccount') {
                $findings += New-VulnFinding -Severity 'Critical' -Category 'WeakConfig' `
                    -Title "Account '$($u.Name)' is not required to have a password" `
                    -Evidence "Get-LocalUser shows PasswordRequired=false for an enabled account. A blank password is a free login." `
                    -FixGuidance "Require a password: Repair-RequirePasswordFor -UserName '$($u.Name)'. Then set a real password for the account. Rollback: net user <name> /passwordreq:no." `
                    -FixCommand "Repair-RequirePasswordFor -UserName '$($u.Name)'"
            }
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'Local password-policy check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually: Get-LocalUser | Select Name, Enabled, PasswordRequired.' -FixCommand ''
    }
    # Account lockout threshold: 0 = never locks out = unlimited password guessing.
    # Parsed by the pure ConvertFrom-NetAccountsLockout (hygiene-tested).
    try {
        $raw = net accounts 2>$null
        $thresh = $null
        if ($LASTEXITCODE -eq 0 -and $raw) {
            $thresh = ConvertFrom-NetAccountsLockout -NetAccountsText ($raw -join "`n")
        }
        if ($thresh -eq -1 -or $thresh -eq 0) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title 'Account lockout is disabled (threshold: Never/0)' `
                -Evidence 'net accounts reports no effective lockout threshold. An attacker can guess passwords forever with no lockout.' `
                -FixGuidance 'Set a lockout policy: Repair-LockoutThreshold (5 bad attempts, 30-min lockout). Rollback: net accounts /lockoutthreshold:0.' `
                -FixCommand 'Repair-LockoutThreshold'
        } elseif ($thresh -ne $null) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title "Account lockout policy present (threshold: $thresh)" -Evidence "net accounts: Lockout threshold=$thresh." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch { }
    return $findings
}

function Repair-RequirePasswordFor {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true)][string]$UserName)
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess($UserName, 'Require a password (net user /passwordreq:yes)')) {
        $out = & net user "$UserName" /passwordreq:yes 2>&1
        Write-Host "  net user: $($out -join ' ')"
        Write-Host '[!] Now set a REAL password for this account: net user <name> <newpassword>. Blank is no longer allowed.' -ForegroundColor Yellow
    }
}

function Repair-LockoutThreshold {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([int]$Attempts = 5, [int]$Minutes = 30)
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($Attempts -lt 1 -or $Attempts -gt 999) { Write-Host '[-] Attempts must be 1-999.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('account lockout', "threshold=$Attempts, duration/window=$Minutes min")) {
        $out = & net accounts /lockoutthreshold:$Attempts /lockoutduration:$Minutes /lockoutwindow:$Minutes 2>&1
        Write-Host "  net accounts: $($out -join ' ')"
        Write-Host '[+] Lockout policy set. Rollback: net accounts /lockoutthreshold:0' -ForegroundColor Green
    }
}

function Repair-ExpireLocalPasswords {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('local users', 'Clear PasswordNeverExpires on all enabled accounts')) {
        try {
            foreach ($u in (Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -and $_.PasswordNeverExpires })) {
                Set-LocalUser -Name $u.Name -PasswordNeverExpires $false -ErrorAction Stop
                Write-Host "  Cleared on $($u.Name)"
            }
            Write-Host '[+] Password expiry enforced. Users will be prompted to rotate on next expiry cycle.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-RemoteRegistry {
    Write-Host '[*] Checking Remote Registry service...' -ForegroundColor Cyan
    $findings = @()
    try {
        $svc = Get-Service -Name 'RemoteRegistry' -ErrorAction Stop
        $mode = ''
        try { $mode = (Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction Stop).StartMode } catch { }
        if ($svc.Status -eq 'Running') {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'Remote Registry service is RUNNING' `
                -Evidence "RemoteRegistry status=Running, StartMode=$mode. Lets any authenticated remote user read/write your registry — a lateral-movement primitive." `
                -FixGuidance 'Disable it: Repair-DisableRemoteRegistry. Almost nothing legitimate needs this on a workstation. Rollback: Set-Service RemoteRegistry -StartupType Manual.' `
                -FixCommand 'Repair-DisableRemoteRegistry'
        } elseif ($mode -eq 'Auto') {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title 'Remote Registry service set to Automatic' -Evidence "Status=$($svc.Status), StartMode=Auto." `
                -FixGuidance 'Disable it: Repair-DisableRemoteRegistry.' -FixCommand 'Repair-DisableRemoteRegistry'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'Remote Registry service not running' -Evidence "Status=$($svc.Status), StartMode=$mode." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'Remote Registry check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually: Get-Service RemoteRegistry.' -FixCommand ''
    }
    return $findings
}

function Repair-DisableRemoteRegistry {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('RemoteRegistry', 'Stop and disable')) {
        try {
            Stop-Service -Name 'RemoteRegistry' -Force -ErrorAction SilentlyContinue
            Set-Service -Name 'RemoteRegistry' -StartupType Disabled -ErrorAction Stop
            Write-Host '[+] Remote Registry stopped and disabled. Rollback: Set-Service RemoteRegistry -StartupType Manual' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-WinRMEncryption {
    Write-Host '[*] Checking WinRM unencrypted-traffic policy...' -ForegroundColor Cyan
    $findings = @()
    try {
        $weak = @()
        foreach ($side in @('Client', 'Service')) {
            $r = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\$side" -Name 'AllowUnencrypted' -ErrorAction SilentlyContinue
            if ($r -and [int]$r.AllowUnencrypted -eq 1) { $weak += $side }
        }
        if ($weak.Count -gt 0) {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'WinRM allows unencrypted traffic' `
                -Evidence "AllowUnencrypted=1 on: $($weak -join ', '). Credentials and session data cross the wire in cleartext." `
                -FixGuidance 'Deny it: Repair-WinRMDenyUnencrypted. Rollback: set AllowUnencrypted back to 1.' `
                -FixCommand 'Repair-WinRMDenyUnencrypted'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'WinRM unencrypted traffic not allowed' -Evidence 'No AllowUnencrypted=1 policy found.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'WinRM encryption check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually in the WinRM policy registry.' -FixCommand ''
    }
    return $findings
}

function Repair-WinRMDenyUnencrypted {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('WinRM', 'Set AllowUnencrypted=0 for client and service')) {
        try {
            foreach ($side in @('Client', 'Service')) {
                $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\$side"
                if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                Set-ItemProperty -Path $p -Name 'AllowUnencrypted' -Value 0 -Type DWord
            }
            Write-Host '[+] WinRM unencrypted traffic denied. Rollback: set AllowUnencrypted back to 1.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-SmbServerSigning {
    Write-Host '[*] Checking SMB server-side signing requirement...' -ForegroundColor Cyan
    $findings = @()
    try {
        $r = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue
        $val = -1
        if ($r) { $val = [int]$r.RequireSecuritySignature }
        if ($val -ne 1) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title 'SMB signing not required on inbound connections (server side)' `
                -Evidence "LanmanServer RequireSecuritySignature=$val (0/absent). Inbound SMB sessions can be relayed." `
                -FixGuidance 'Require signing: Repair-SmbServerSigningRequire (reboot; very old SMB clients will stop connecting — that is the point). Rollback: set RequireSecuritySignature back to 0.' `
                -FixCommand 'Repair-SmbServerSigningRequire'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'SMB server-side signing required' -Evidence 'RequireSecuritySignature=1.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'SMB server-signing check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually in the registry.' -FixCommand ''
    }
    return $findings
}

function Repair-SmbServerSigningRequire {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('SMB server', 'Require SMB security signatures (LanmanServer)')) {
        try {
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord
            Write-Host '[+] SMB server-side signing required. Reboot to take effect. Rollback: set RequireSecuritySignature back to 0.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

# ---------------------------------------------------------------------------
# Hardening pass v1.3 (2026-10-30 ~07:05 MDT): privilege-escalation class
# and credential-theft primitives. Every detection ships its Repair-*
# fix (Better-Way Law). Read-only by default; repairs admin-gated +
# confirm-prompted.
# ---------------------------------------------------------------------------

function Test-AlwaysInstallElevated {
    # The classic MSI-to-SYSTEM vector: AlwaysInstallElevated=1 under BOTH
    # HKLM and HKCU lets any standard user install a crafted MSI as SYSTEM.
    Write-Host '[*] Checking AlwaysInstallElevated policy...' -ForegroundColor Cyan
    $findings = @()
    try {
        $hklm = 0; $hkcu = 0
        $r1 = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
        $r2 = Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
        if ($r1) { $hklm = [int]$r1.AlwaysInstallElevated }
        if ($r2) { $hkcu = [int]$r2.AlwaysInstallElevated }
        if ($hklm -eq 1 -and $hkcu -eq 1) {
            $findings += New-VulnFinding -Severity 'Critical' -Category 'WeakConfig' `
                -Title 'AlwaysInstallElevated enabled (HKLM + HKCU)' `
                -Evidence 'Both machine and user Installer policies set AlwaysInstallElevated=1. Any standard user can run a crafted MSI as SYSTEM — a textbook privilege escalation.' `
                -FixGuidance 'Remove the policy pair: Repair-AlwaysInstallElevatedRemove. Rollback: re-create both values set to 1 (never do this).' `
                -FixCommand 'Repair-AlwaysInstallElevatedRemove'
        } elseif ($hklm -eq 1 -or $hkcu -eq 1) {
            $side = if ($hklm -eq 1) { 'HKLM only' } else { 'HKCU only' }
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title "AlwaysInstallElevated half-set ($side)" `
                -Evidence "Only $side sets AlwaysInstallElevated=1; the vector needs both sides. Clean it up anyway so a future change cannot complete the pair." `
                -FixGuidance 'Remove the value: Repair-AlwaysInstallElevatedRemove.' `
                -FixCommand 'Repair-AlwaysInstallElevatedRemove'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'AlwaysInstallElevated not set' -Evidence 'Neither Installer policy sets AlwaysInstallElevated.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'AlwaysInstallElevated check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually in the Installer policy registry.' -FixCommand ''
    }
    return $findings
}

function Repair-AlwaysInstallElevatedRemove {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('Installer policy', 'Remove AlwaysInstallElevated from HKLM and HKCU')) {
        try {
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
            Write-Host '[+] AlwaysInstallElevated removed from both policy hives.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-LsaProtection {
    # RunAsPPL=1 puts LSASS in a protected process — Mimikatz-class
    # credential dumping gets harder. Off = the front door is open.
    Write-Host '[*] Checking LSA Protection (RunAsPPL)...' -ForegroundColor Cyan
    $findings = @()
    try {
        $r = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue
        $val = -1
        if ($r) { $val = [int]$r.RunAsPPL }
        if ($val -eq 1) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
                -Title 'LSA Protection is on (RunAsPPL=1)' -Evidence 'LSASS runs as a protected process; in-memory credential dumping is significantly harder.' `
                -FixGuidance 'None needed.' -FixCommand ''
        } else {
            $findings += New-VulnFinding -Severity 'High' -Category 'PlatformSecurity' `
                -Title 'LSA Protection is OFF' `
                -Evidence "RunAsPPL=$val (absent/0). LSASS memory is readable by admin processes — the classic credential-dumping target." `
                -FixGuidance 'Enable it: Repair-LsaProtectionEnable (reboot; also sets the UEFI-lock variant when supported). Rollback: delete RunAsPPL / set 0.' `
                -FixCommand 'Repair-LsaProtectionEnable'
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'PlatformSecurity' `
            -Title 'LSA Protection check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually: Lsa registry key, RunAsPPL.' -FixCommand ''
    }
    return $findings
}

function Repair-LsaProtectionEnable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('LSA Protection', 'Set RunAsPPL=1 (reboot required)')) {
        try {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord
            try { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPLBoot' -Value 1 -Type DWord } catch { }
            Write-Host '[+] LSA Protection enabled (RunAsPPL=1). REBOOT required. Rollback: set RunAsPPL=0.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Get-CredentialGuardStatus {
    # Credential Guard isolates secrets in a VBS enclave. Bit 1 of
    # Win32_DeviceGuard.SecurityServicesRunning = running.
    Write-Host '[*] Checking Credential Guard...' -ForegroundColor Cyan
    try {
        $dg = Get-CimInstance Win32_DeviceGuard -ErrorAction Stop
        $configured = ($dg.SecurityServicesConfigured -band 1) -eq 1
        $running    = ($dg.SecurityServicesRunning -band 1) -eq 1
        if ($running) {
            return @(New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
                -Title 'Credential Guard is running' -Evidence 'Win32_DeviceGuard reports SecurityServicesRunning bit 1 set.' `
                -FixGuidance 'None needed.' -FixCommand '')
        }
        if ($configured) {
            return @(New-VulnFinding -Severity 'Medium' -Category 'PlatformSecurity' `
                -Title 'Credential Guard configured but not running' -Evidence 'SecurityServicesConfigured has bit 1, SecurityServicesRunning does not. Reboot, or check VBS readiness.' `
                -FixGuidance 'Reboot and re-check; confirm virtualization is enabled in firmware and VBS is not blocked by policy.' -FixCommand '')
        }
        return @(New-VulnFinding -Severity 'Medium' -Category 'PlatformSecurity' `
            -Title 'Credential Guard is not enabled' `
            -Evidence 'No Credential Guard bit configured. On supported hardware (TPM 2.0, UEFI, virtualization) this is the strongest credential-theft mitigation Windows ships.' `
            -FixGuidance 'Enable via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security > Credential Guard. Requires a reboot and capable hardware.' -FixCommand '')
    } catch {
        return @(New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
            -Title 'Credential Guard state unknown' -Evidence $_.Exception.Message `
            -FixGuidance 'Check manually: msinfo32, or Get-CimInstance Win32_DeviceGuard.' -FixCommand '')
    }
}

function Test-RdpNla {
    # If Remote Desktop is on, NLA must be on: without it, anyone can
    # complete the RDP handshake and hammer credentials anonymously.
    Write-Host '[*] Checking RDP Network Level Authentication...' -ForegroundColor Cyan
    $findings = @()
    try {
        $rdpDeny = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
        $rdpOn = ($rdpDeny -and $rdpDeny.fDenyTSConnections -eq 0)
        if (-not $rdpOn) {
            return @(New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'RDP is off — NLA check not applicable' -Evidence 'fDenyTSConnections=1.' `
                -FixGuidance 'None needed.' -FixCommand '')
        }
        $r = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthenticationRequired' -ErrorAction SilentlyContinue
        $val = -1
        if ($r) { $val = [int]$r.UserAuthenticationRequired }
        if ($val -eq 1) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'RDP requires Network Level Authentication' -Evidence 'UserAuthenticationRequired=1.' `
                -FixGuidance 'None needed.' -FixCommand ''
        } else {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'RDP is on WITHOUT Network Level Authentication' `
                -Evidence "RDP allowed (fDenyTSConnections=0) but UserAuthenticationRequired=$val. Pre-authentication attack surface and anonymous credential guessing are enabled." `
                -FixGuidance 'Require NLA: Repair-RdpRequireNla. Rollback: set UserAuthenticationRequired=0.' `
                -FixCommand 'Repair-RdpRequireNla'
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'RDP NLA check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually in the RDP-Tcp registry key.' -FixCommand ''
    }
    return $findings
}

function Repair-RdpRequireNla {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('RDP', 'Require Network Level Authentication')) {
        try {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthenticationRequired' -Value 1 -Type DWord
            Write-Host '[+] RDP now requires Network Level Authentication. Rollback: set UserAuthenticationRequired=0.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Get-DefenderTamperStatus {
    # Tamper Protection stops malware (and careless admins) from flipping
    # Defender off via the registry. Off = one registry write away from
    # no antivirus.
    Write-Host '[*] Checking Defender tamper protection...' -ForegroundColor Cyan
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $tp = $null
        if ($mp.PSObject.Properties.Name -contains 'IsTamperProtected') { $tp = $mp.IsTamperProtected }
        if ($tp -eq $true) {
            return @(New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'Defender tamper protection is on' -Evidence 'Get-MpComputerStatus reports IsTamperProtected=True.' `
                -FixGuidance 'None needed.' -FixCommand '')
        }
        if ($tp -eq $false) {
            return @(New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title 'Defender tamper protection is OFF' `
                -Evidence 'IsTamperProtected=False. Malware or a single registry write can disable real-time protection silently.' `
                -FixGuidance 'Enable in Windows Security > Virus & threat protection > Manage settings > Tamper Protection (Microsoft may gate this behind Intune on managed machines).' -FixCommand '')
        }
        return @(New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
            -Title 'Tamper protection state not reported' -Evidence 'IsTamperProtected property absent on this build.' `
            -FixGuidance 'Check Windows Security manually.' -FixCommand '')
    } catch {
        return @(New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'Tamper protection check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually in Windows Security.' -FixCommand '')
    }
}

function Repair-FirewallDefaultDeny {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('Windows Firewall', 'Set DefaultInboundAction=Block on Domain, Private, Public profiles')) {
        try {
            Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -ErrorAction Stop
            Write-Host '[+] Default inbound action set to Block on all profiles. Rollback: Set-NetFirewallProfile -Profile <Name> -DefaultInboundAction Allow' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

# UDP listeners: Get-NetTCPConnection misses UDP entirely. Risky UDP services
# (no auth by default, amplification, enumeration) get their own table.
$script:RiskyUdpPorts = @{
    53   = 'DNS server (cache poisoning / amplification if misconfigured)'
    67   = 'DHCP server (rogue-DHCP target if unauthorized)'
    69   = 'TFTP (no authentication, config/firmware theft)'
    123  = 'NTP server (amplification abuse)'
    137  = 'NetBIOS name service (poisoning target)'
    161  = 'SNMP (default community strings leak device config)'
    500  = 'IKE (verify it is your VPN, not a stranger)'
    4500 = 'IKE NAT-T (verify it is your VPN)'
    1434 = 'MSSQL Browser UDP (instance enumeration)'
    1900 = 'SSDP (UPnP discovery — often exposes device info)'
    5353 = 'mDNS (exposes hostname/services on the LAN)'
}

function Get-ExposedUdpServices {
    Write-Host '[*] Checking exposed UDP services...' -ForegroundColor Cyan
    $findings = @()
    try {
        $listeners = Get-NetUDPConnection -ErrorAction Stop
        foreach ($l in $listeners) {
            $port = [int]$l.LocalPort
            if ($script:RiskyUdpPorts.ContainsKey($port)) {
                $procName = ''
                try { $procName = (Get-Process -Id $l.OwningProcess -ErrorAction Stop).ProcessName } catch { $procName = "PID $($l.OwningProcess)" }
                $addr = $l.LocalAddress.ToString()
                $scope = if ($addr -eq '0.0.0.0' -or $addr -eq '::') { 'ALL INTERFACES' } else { $addr }
                $sev = if ($port -in @(69, 137, 161, 1434)) { 'High' } else { 'Medium' }
                $findings += New-VulnFinding -Severity $sev -Category 'ExposedService' `
                    -Title "Risky UDP service listening: port $port ($($script:RiskyUdpPorts[$port]))" `
                    -Evidence "Bound to $scope (UDP), owned by $procName." `
                    -FixGuidance 'If unneeded: stop/disable the service. If needed: firewall it to trusted hosts only.' `
                    -FixCommand ''
            }
        }
        if ($findings.Count -eq 0) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'ExposedService' `
                -Title 'No risky UDP listening ports found' -Evidence 'None of the tracked risky UDP ports are in Listen state.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'ExposedService' `
            -Title 'UDP listener check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Run netstat -ano -p UDP manually.' -FixCommand ''
    }
    return $findings
}

function Test-RemoteAccessTools {
    Write-Host '[*] Checking for remote-access tools...' -ForegroundColor Cyan
    $findings = @()
    try {
        $patterns = @('TeamViewer', 'AnyDesk', 'RustDesk', 'LogMeIn', 'GoToMyPC',
            'ScreenConnect', 'Splashtop', 'Chrome Remote Desktop',
            'RealVNC', 'TightVNC', 'UltraVNC', 'Remote Utilities',
            'NoMachine', 'Parsec', 'DWService')
        $apps = Get-InstalledSoftware
        $hits = 0
        foreach ($app in $apps) {
            foreach ($pat in $patterns) {
                if ($app.Name -match [regex]::Escape($pat)) {
                    $hits++
                    $findings += New-VulnFinding -Severity 'Info' -Category 'RemoteAccess' `
                        -Title "Remote-access tool installed: $($app.Name)" `
                        -Evidence "Version: $($app.Version). Remote-access tools are high-value persistence for attackers — verify YOU installed it, that it is current, and that unattended access requires a strong password + 2FA." `
                        -FixGuidance 'If unneeded: uninstall it. If needed: update it, disable unattended access or lock it to your account with 2FA.' -FixCommand ''
                    break
                }
            }
        }
        if ($hits -eq 0) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'RemoteAccess' `
                -Title 'No remote-access tools found' -Evidence 'No known remote-access product matched installed software.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'RemoteAccess' `
            -Title 'Remote-access tool check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually.' -FixCommand ''
    }
    return $findings
}

# ---- Repairs (Better-Way Law). Admin-gated, confirm-prompted. ----

function Repair-Smb1Disable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('SMBv1', 'Disable SMB1Protocol optional feature')) {
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
            Write-Host '[+] SMBv1 disabled. Reboot to complete. Rollback: Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Repair-LlmnrDisable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('LLMNR', 'Set EnableMulticast=0 policy')) {
        try {
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
            Set-ItemProperty -Path $p -Name 'EnableMulticast' -Value 0 -Type DWord
            Write-Host '[+] LLMNR disabled via policy. Rollback: remove EnableMulticast or set to 1.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Repair-NetBiosDisable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('NetBIOS', 'Disable NetBT on all IP-enabled adapters')) {
        try {
            $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE'
            foreach ($a in $adapters) {
                $r = Invoke-CimMethod -InputObject $a -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 }
                Write-Host "  $($a.Description): result $($r.ReturnValue) (0=success)"
            }
            Write-Host '[+] NetBIOS over TCP/IP disabled. Rollback: SetTcpipNetbios 0 (default) or 1 (enabled).' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Repair-RdpDisable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('RDP', 'Disable Remote Desktop (fDenyTSConnections=1)')) {
        try {
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -Type DWord
            Write-Host '[+] Remote Desktop disabled. Rollback: set fDenyTSConnections=0.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Repair-UacHarden {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('UAC', 'Set EnableLUA=1, ConsentPromptBehaviorAdmin=2')) {
        try {
            $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Set-ItemProperty -Path $p -Name 'EnableLUA' -Value 1 -Type DWord
            Set-ItemProperty -Path $p -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord
            Write-Host '[+] UAC hardened (prompt for consent on secure desktop). Reboot to take full effect. Rollback: restore prior values.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Repair-DefenderRealTime {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([switch]$UpdateSignatures)
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('Defender', 'Re-enable real-time protection')) {
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Write-Host '[+] Defender real-time protection re-enabled.' -ForegroundColor Green
            if ($UpdateSignatures) { Update-MpSignature -ErrorAction Stop; Write-Host '[+] Signatures updated.' -ForegroundColor Green }
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

# ---- Repairs for the hardening checks (Better-Way Law). ----

function Repair-FirewallEnable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('Windows Firewall', 'Enable Domain, Private, Public profiles')) {
        try {
            Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction Stop
            Write-Host '[+] All firewall profiles enabled. Rollback: Set-NetFirewallProfile -Name <Profile> -Enabled False' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Repair-WindowsUpdateService {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('wuauserv', 'Restore Windows Update service to Manual and start it')) {
        try {
            Set-Service -Name 'wuauserv' -StartupType Manual -ErrorAction Stop
            Start-Service -Name 'wuauserv' -ErrorAction Stop
            Write-Host '[+] wuauserv restored (Manual) and started.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Repair-GuestDisable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('Guest account', 'Disable')) {
        try {
            Disable-LocalUser -Name 'Guest' -ErrorAction Stop
            Write-Host '[+] Guest account disabled. Rollback: Enable-LocalUser -Name Guest' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Repair-AutoRunDisable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('AutoRun', 'Set NoDriveTypeAutoRun=255 (disabled on all drive types)')) {
        try {
            $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
            Set-ItemProperty -Path $p -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord
            Write-Host '[+] AutoRun disabled on all drive types. Rollback: delete NoDriveTypeAutoRun or set 149.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Repair-PowerShellV2Disable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('PowerShell v2', 'Remove PSv2 optional features')) {
        try {
            foreach ($feat in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
                try { Disable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction Stop | Out-Null; Write-Host "  Disabled $feat" }
                catch { Write-Host "  $feat : $($_.Exception.Message)" }
            }
            Write-Host '[+] PowerShell v2 engine removed. Reboot to complete.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Repair-SmbSigningRequire {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('SMB signing', 'Require SMB security signatures (LanmanWorkstation)')) {
        try {
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord
            Write-Host '[+] SMB signing required. Reboot to take effect. Rollback: set RequireSecuritySignature back to 0.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Repair-UnquotedServicePath {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    try {
        $filter = "Name='" + $ServiceName.Replace("'", "''") + "'"
        $svc = Get-CimInstance Win32_Service -Filter $filter -ErrorAction Stop
        if (-not $svc -or -not $svc.PathName) { Write-Host '[-] Service not found.' -ForegroundColor Red; return }
        $p = $svc.PathName.Trim()
        $m = [regex]::Match($p, '(?i)^(.+?\.exe)\b(.*)$')
        if (-not $m.Success) { Write-Host '[-] Could not split the executable path.' -ForegroundColor Red; return }
        $newPath = '"' + $m.Groups[1].Value + '"' + $m.Groups[2].Value
        if ($PSCmdlet.ShouldProcess($ServiceName, "Set ImagePath to $newPath")) {
            $out = & sc.exe config "$ServiceName" binpath= "$newPath" 2>&1
            Write-Host "  sc.exe: $($out -join ' ')"
            Write-Host '[+] Service path quoted. Test the service starts, then reboot to confirm.' -ForegroundColor Green
            Write-Host "  Rollback: sc.exe config `"$ServiceName`" binpath= `"$p`"" -ForegroundColor Gray
        }
    } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
}

# ---------------------------------------------------------------------------
# Exposed local services — listening sockets + risky-port check
# ---------------------------------------------------------------------------

$script:RiskyPorts = @{
    21   = 'FTP (cleartext credentials)'
    23   = 'Telnet (cleartext, never expose)'
    25   = 'SMTP (open relay / spam source if misconfigured)'
    53   = 'DNS server (cache poisoning / amplification if misconfigured)'
    69   = 'TFTP (no authentication, config/firmware theft)'
    135  = 'RPC endpoint mapper'
    137  = 'NetBIOS name service (poisoning target)'
    139  = 'NetBIOS session'
    161  = 'SNMP (default community strings leak device config)'
    389  = 'LDAP (anonymous binds leak directory contents)'
    445  = 'SMB (lateral movement target)'
    1433 = 'MSSQL (brute-force target)'
    1434 = 'MSSQL Browser UDP (instance enumeration)'
    2375 = 'Docker API unauthenticated (instant host takeover)'
    2376 = 'Docker API (TLS, still high value — verify certs)'
    3000 = 'Dev server (often no auth, debug info leaks)'
    3306 = 'MySQL (brute-force target)'
    3389 = 'RDP (brute-force target)'
    5432 = 'PostgreSQL (brute-force target)'
    5601 = 'Kibana (default-credential logins common)'
    5900 = 'VNC (often weak auth)'
    5985 = 'WinRM HTTP (lateral movement)'
    5986 = 'WinRM HTTPS'
    6379 = 'Redis (no auth by default)'
    8000 = 'HTTP alt / dev server (check what serves it)'
    8080 = 'HTTP alt (check what serves it)'
    8443 = 'HTTPS alt (check what serves it)'
    9000 = 'App server / PHP-FPM / Jenkins agent (identify it)'
    9200 = 'Elasticsearch HTTP (no auth by default)'
    9300 = 'Elasticsearch transport'
    10000= 'Webmin (admin panel, brute-force target)'
    27017= 'MongoDB (no auth by default)'
    4444 = 'Metasploit default listener port (suspicious if you did not open it)'
    5555 = 'ADB debug bridge (often unauthorized; Android tooling backdoor)'
    7001 = 'WebLogic admin console (brute-force / deserialization CVEs)'
    11211= 'Memcached (no auth, UDP amplification abuse)'
}

# Ports whose exposure is treated as High rather than Medium.
$script:HighRiskPorts = @(21, 23, 25, 137, 445, 1433, 1434, 2375, 3389, 4444, 6379, 9200, 11211, 27017)

function Get-ExposedLocalServices {
    Write-Host '[*] Checking exposed local services...' -ForegroundColor Cyan
    $findings = @()
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop
        foreach ($l in $listeners) {
            $port = [int]$l.LocalPort
            if ($script:RiskyPorts.ContainsKey($port)) {
                $procName = ''
                try { $procName = (Get-Process -Id $l.OwningProcess -ErrorAction Stop).ProcessName } catch { $procName = "PID $($l.OwningProcess)" }
                $addr = $l.LocalAddress.ToString()
                $scope = if ($addr -eq '0.0.0.0' -or $addr -eq '::') { 'ALL INTERFACES' } else { $addr }
                $sev = Get-PortRiskSeverity -Port $port
                $findings += New-VulnFinding -Severity $sev -Category 'ExposedService' `
                    -Title "Risky service listening: port $port ($($script:RiskyPorts[$port]))" `
                    -Evidence "Bound to $scope, owned by $procName." `
                    -FixGuidance 'If unneeded: stop/disable the service. If needed: bind to 127.0.0.1 only and firewall it to trusted hosts.' `
                    -FixCommand ''
            }
        }
        if ($findings.Count -eq 0) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'ExposedService' `
                -Title 'No risky listening ports found' -Evidence 'None of the tracked risky ports are in Listen state.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'ExposedService' `
            -Title 'Listening-socket check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Run netstat -ano manually and compare against the risky-port table.' -FixCommand ''
    }
    return $findings
}

function Import-NetScanReport {
    param([string]$Path)
    Write-Host '[*] Cross-referencing netscan report...' -ForegroundColor Cyan
    $findings = @()
    try {
        if (-not (Test-Path $Path)) {
            return @(New-VulnFinding -Severity 'Info' -Category 'NetScanXRef' `
                -Title 'No netscan report supplied' -Evidence "Path '$Path' not found; pass -NetScanReportPath." `
                -FixGuidance 'Run the netscan module and pass its report path for LAN cross-reference.' -FixCommand '')
        }
        $data = Get-Content $Path -Raw | ConvertFrom-Json
        $hosts = @()
        if ($data.hosts) { $hosts = $data.hosts } elseif ($data -is [array]) { $hosts = $data }
        foreach ($h in $hosts) {
            $ports = @()
            if ($h.openPorts) { $ports = $h.openPorts } elseif ($h.ports) { $ports = $h.ports }
            foreach ($p in $ports) {
                $pn = 0
                if ($p -is [int]) { $pn = $p } elseif ($p.port) { $pn = [int]$p.port }
                if ($script:RiskyPorts.ContainsKey($pn)) {
                    $findings += New-VulnFinding -Severity 'High' -Category 'NetScanXRef' `
                        -Title "LAN host $($h.host) exposes port $pn ($($script:RiskyPorts[$pn]))" `
                        -Evidence "From netscan report '$Path'." `
                        -FixGuidance 'Verify the host needs that port; firewall or disable it.' -FixCommand ''
                }
            }
        }
        if ($findings.Count -eq 0) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'NetScanXRef' `
                -Title 'Netscan cross-reference clean' -Evidence "No tracked risky ports in report '$Path'." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'NetScanXRef' `
            -Title 'Netscan report parse failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check the report path and JSON format.' -FixCommand ''
    }
    return $findings
}

# ---------------------------------------------------------------------------
# Installed software vs EOL / known-bad-version table
# ---------------------------------------------------------------------------

$script:EolSoftware = @(
    @{ Pattern = 'Adobe Flash Player';        Match = 'any';     MinSafe = $null;   Severity = 'Critical'; Reason = 'Flash is end-of-life since 2020-12-31 and is unpatched. Uninstall it.' },
    @{ Pattern = 'Microsoft Silverlight';     Match = 'any';     MinSafe = $null;   Severity = 'High';     Reason = 'Silverlight support ended 2021-10-12. Uninstall it.' },
    @{ Pattern = 'QuickTime';                 Match = 'any';     MinSafe = $null;   Severity = 'High';     Reason = 'QuickTime for Windows is end-of-life since 2016 with known unpatched flaws. Uninstall it.' },
    @{ Pattern = 'Java 7';                    Match = 'any';     MinSafe = $null;   Severity = 'High';     Reason = 'Java 7 is end-of-life and unpatched. Remove or upgrade.' },
    @{ Pattern = 'Java\(TM\) 6|Java 6';       Match = 'any';     MinSafe = $null;   Severity = 'High';     Reason = 'Java 6 is end-of-life and unpatched. Remove or upgrade.' },
    @{ Pattern = 'Python 2';                  Match = 'any';     MinSafe = $null;   Severity = 'High';     Reason = 'Python 2 reached EOL 2020-01-01. Migrate to Python 3.' },
    @{ Pattern = '7-Zip';                     Match = 'version';  MinSafe = '24.07'; Severity = 'High';     Reason = '7-Zip below 24.07 is affected by CVE-2024-11477 (MotW bypass, fixed in 24.07). Upgrade.' },
    @{ Pattern = 'WinRAR';                    Match = 'version';  MinSafe = '7.13';  Severity = 'High';     Reason = 'WinRAR below 7.13 is affected by CVE-2025-8088 (ADS path traversal dropping payloads into Startup, CISA KEV, exploited by APTs in the wild; fixed in 7.13) and earlier RCE CVEs (CVE-2023-38831 class). Upgrade to 7.13+.' },
    @{ Pattern = 'VLC media player';          Match = 'version';  MinSafe = '3.0.20';Severity = 'Medium';   Reason = 'Older VLC builds carry published codec CVEs. Upgrade to current.' },
    @{ Pattern = 'Notepad\+\+';               Match = 'version';  MinSafe = '8.6';   Severity = 'Medium';   Reason = 'Older Notepad++ builds carry published installer/plugin CVEs. Upgrade.' },
    @{ Pattern = 'Skype';                     Match = 'any';      MinSafe = $null;   Severity = 'High';     Reason = 'Skype was retired by Microsoft on 2025-05-05. Unpatched and unsupported — uninstall it.' },
    @{ Pattern = 'PuTTY';                     Match = 'version';  MinSafe = '0.81';  Severity = 'High';     Reason = 'PuTTY below 0.81 is affected by CVE-2024-31497 (NIST P-521 private-key recovery from signatures, fixed in 0.81). Upgrade.' },
    @{ Pattern = '^Git$|^Git ';               Match = 'version';  MinSafe = '2.46';  Severity = 'High';     Reason = 'Git for Windows below 2.45.1 is affected by published RCE CVEs (CVE-2024-32002 class). Upgrade.' },
    @{ Pattern = 'Google Chrome';             Match = 'version';  MinSafe = '141';   Severity = 'Medium';   Reason = 'Older Chrome builds carry published CVEs; Chrome auto-updates, but verify it is actually updating.' },
    @{ Pattern = 'Microsoft Edge';            Match = 'version';  MinSafe = '141';   Severity = 'Medium';   Reason = 'Older Edge builds carry published Chromium CVEs; verify it is actually updating.' },
    @{ Pattern = 'Mozilla Firefox';           Match = 'version';  MinSafe = '144';   Severity = 'Medium';   Reason = 'Older Firefox builds carry published CVEs; verify it is actually updating.' },
    @{ Pattern = '^Node\.js';                 Match = 'version';  MinSafe = '22.0';  Severity = 'High';     Reason = 'Node.js 20.x and earlier reached end of life (April 2026) and receive no security fixes. Upgrade to 22 LTS or newer.' },
    @{ Pattern = 'Python 3\.9';               Match = 'any';      MinSafe = $null;   Severity = 'High';     Reason = 'Python 3.9 reached EOL 2025-10-31 and receives no security fixes. Upgrade to 3.11 or newer.' },
    @{ Pattern = 'Python 3\.10';              Match = 'any';      MinSafe = $null;   Severity = 'High';     Reason = 'Python 3.10 reached EOL 2026-10-04 and receives no security fixes. Upgrade to 3.11 or newer.' },
    @{ Pattern = 'KeePass';                   Match = 'version';  MinSafe = '2.54';  Severity = 'High';     Reason = 'KeePass below 2.54 is affected by CVE-2023-32784 (master-password recovery from memory dump). Upgrade.' },
    @{ Pattern = '^TeamViewer';               Match = 'version';  MinSafe = '15.8.3';Severity = 'High';     Reason = 'TeamViewer below 15.8.3 is affected by CVE-2020-13699 (URI-handler password relay attack). Upgrade.' },
    @{ Pattern = '^Wireshark';                Match = 'version';  MinSafe = '4.4.0'; Severity = 'High';     Reason = 'Older Wireshark builds carry published dissector CVEs. Upgrade to 4.4.0 or newer.' },
    @{ Pattern = 'Microsoft \.NET Framework 4\.'; Match = 'version'; MinSafe = '4.7'; Severity = 'High';     Reason = '.NET Framework 4.5.2 through 4.6.1 reached end of support 2026-04-28 and receive no security fixes. Move to 4.7.2+.' },
    @{ Pattern = '^WinSCP';                  Match = 'version';  MinSafe = '6.1';   Severity = 'High';     Reason = 'WinSCP below 6.1 is affected by CVE-2023-48795 (Terrapin prefix-truncation attack against SSH). Upgrade.' },
    @{ Pattern = '^LibreOffice';              Match = 'version';  MinSafe = '24.2.2';Severity = 'High';     Reason = 'LibreOffice below 24.2.2/7.6.7 is affected by CVE-2024-5261 (macro URI-scheme validation bypass). Upgrade.' },
    @{ Pattern = 'Adobe (Acrobat|Reader)';    Match = 'version';  MinSafe = '25.001';Severity = 'High';     Reason = 'Older Acrobat/Reader builds carry published remote-code CVEs in Adobe quarterly APSB bulletins. Stay on the current continuous track.' },
    @{ Pattern = 'Oracle VM VirtualBox';      Match = 'version';  MinSafe = '7.1';  Severity = 'High';     Reason = 'Older VirtualBox builds carry published guest-to-host escape CVEs in Oracle quarterly Critical Patch Updates. Upgrade.' }
)

function Get-InstalledSoftware {
    $apps = @()
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($p in $paths) {
        try {
            $apps += Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
                     ForEach-Object { [pscustomobject]@{ Name = [string]$_.DisplayName; Version = [string]$_.DisplayVersion } }
        } catch { }
    }
    return $apps
}

function Test-SoftwareEol {
    Write-Host '[*] Checking installed software against EOL table...' -ForegroundColor Cyan
    $findings = @()
    $apps = Get-InstalledSoftware
    $hits = 0
    foreach ($rule in $script:EolSoftware) {
        foreach ($app in $apps) {
            if ($app.Name -match $rule.Pattern) {
                $flag = $false
                if ($rule.Match -eq 'any') { $flag = $true }
                elseif ($rule.Match -eq 'version' -and $app.Version) {
                    if ((Compare-VersionStrings $app.Version $rule.MinSafe) -lt 0) { $flag = $true }
                }
                if ($flag) {
                    $hits++
                    $findings += New-VulnFinding -Severity $rule.Severity -Category 'SoftwareEOL' `
                        -Title "$($app.Name) $($app.Version) — EOL or known-vulnerable" `
                        -Evidence "Matched rule '$($rule.Pattern)'. $($rule.Reason)" `
                        -FixGuidance "Uninstall via Settings > Apps, or upgrade to $($rule.MinSafe) or newer." `
                        -FixCommand ''
                }
            }
        }
    }
    if ($hits -eq 0) {
        $findings += New-VulnFinding -Severity 'Info' -Category 'SoftwareEOL' `
            -Title 'No EOL software matched' -Evidence "$($apps.Count) installed applications scanned against the EOL table." `
            -FixGuidance 'None needed.' -FixCommand ''
    }
    return $findings
}

# ---------------------------------------------------------------------------
# Hardening pass v1.4 (2026-10-30 ~10:33 MDT): platform-defense checks.
# Gaps closed: (1) Defender ASR rules were never audited — the table ships
# 15 well-known GUIDs VERIFIED this run against the Microsoft Learn "ASR
# rules reference" matrix; several remembered-from-memory GUIDs were WRONG
# (LSASS was not 7674BA52, email-content was not D1E49AAC, USB was not
# 9E6C4E1F, Office-comms was not 26190899-as-Adobe) and are corrected here.
# (2) System-wide exploit protection (DEP/mandatory ASLR/SEHOP) never read.
# (3) No BYOVD (bring-your-own-vulnerable-driver) watch table — now 20 rows
# keyed to driver service names. (4) No local admin census, no password
# posture, no TPM status. Each detection ships its Repair-* fix (Better-Way
# Law). ASR and exploit-protection repairs are ConfirmImpact=High + reboot
# noted where it applies.
# ---------------------------------------------------------------------------

function Get-AsrRuleTable {
    # Microsoft's published ASR rule GUIDs (verified 2026-10-30 against the
    # Microsoft Learn ASR rules reference matrix). Recommended = the subset
    # safe to enable on a home machine without breaking normal Office use.
    @(
        [pscustomobject]@{ Guid = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'; Name = 'Block all Office applications from creating child processes';       Recommended = $true }
        [pscustomobject]@{ Guid = '3B576869-A4EC-4529-8536-B80A7769E899'; Name = 'Block Office applications from creating executable content';          Recommended = $true }
        [pscustomobject]@{ Guid = '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'; Name = 'Block Office applications from injecting code into other processes';  Recommended = $true }
        [pscustomobject]@{ Guid = '26190899-1602-49E8-8B27-EB1D0A1CE869'; Name = 'Block Office communication applications from creating child processes'; Recommended = $true }
        [pscustomobject]@{ Guid = '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C'; Name = 'Block Adobe Reader from creating child processes';                     Recommended = $true }
        [pscustomobject]@{ Guid = '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'; Name = 'Block credential stealing from LSASS';                                   Recommended = $true }
        [pscustomobject]@{ Guid = 'D1E49AAC-8F56-4280-B9BA-993A6D77406C'; Name = 'Block process creations from PSExec and WMI';                             Recommended = $true }
        [pscustomobject]@{ Guid = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'; Name = 'Block Win32 API calls from Office macros';                               Recommended = $true }
        [pscustomobject]@{ Guid = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'; Name = 'Block execution of potentially obfuscated scripts';                        Recommended = $true }
        [pscustomobject]@{ Guid = 'D3E037E1-3EB8-44C8-A917-57927947596D'; Name = 'Block JavaScript/VBScript from launching downloaded executable content'; Recommended = $true }
        [pscustomobject]@{ Guid = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'; Name = 'Block executable content from email client and webmail';                  Recommended = $true }
        [pscustomobject]@{ Guid = 'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'; Name = 'Block untrusted and unsigned processes that run from USB';                 Recommended = $true }
        [pscustomobject]@{ Guid = '01443614-CD74-433A-B99E-2ECDC07BFC25'; Name = 'Block executables unless they meet prevalence/age/trusted criteria';      Recommended = $true }
        [pscustomobject]@{ Guid = 'C1DB55AB-C21A-4637-BB23-A12568109D35'; Name = 'Use advanced protection against ransomware';                                Recommended = $true }
        [pscustomobject]@{ Guid = '56A863A9-875E-4185-98A7-B882C64B5CE5'; Name = 'Block abuse of exploited vulnerable signed drivers';                       Recommended = $true }
    )
}

function Test-AsrRuleCoverage {
    # Pure classifier. Defender keeps Ids and Actions as parallel arrays:
    # 0=Disable, 1=Block, 2=Audit, 6=Warn. Unmanaged = a shipped rule the
    # policy never mentions. Returns counts only — no verdict here.
    [CmdletBinding()]
    param([array]$RuleIds, [array]$RuleActions, [array]$Table)
    $ids = @($RuleIds | ForEach-Object { [string]$_ })
    $acts = @($RuleActions)
    $blocked = 0; $audited = 0; $disabled = 0; $unmanaged = 0
    foreach ($row in $Table) {
        $idx = -1
        for ($i = 0; $i -lt $ids.Count; $i++) {
            if ($ids[$i].ToLower() -eq $row.Guid.ToLower()) { $idx = $i; break }
        }
        if ($idx -lt 0 -or $idx -ge $acts.Count) { $unmanaged++; continue }
        $a = 0
        try { $a = [int]$acts[$idx] } catch { $a = 0 }
        if ($a -eq 1) { $blocked++ }
        elseif ($a -eq 2 -or $a -eq 6) { $audited++ }
        else { $disabled++ }
    }
    return [pscustomobject]@{
        Total = $Table.Count; Blocked = $blocked; Audited = $audited
        Disabled = $disabled; Unmanaged = $unmanaged
    }
}

function Test-AsrRules {
    Write-Host '[*] Checking Defender ASR rule coverage...' -ForegroundColor Cyan
    $findings = @()
    try {
        if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
                -Title 'ASR coverage unknown (Defender cmdlets unavailable)' `
                -Evidence 'Get-MpPreference not found — Defender Antivirus cmdlets are not exposed on this machine.' `
                -FixGuidance 'Check Windows Security > App & browser control > Exploit protection manually.' -FixCommand ''
            return $findings
        }
        $pref = Get-MpPreference -ErrorAction Stop
        $rec = @(Get-AsrRuleTable | Where-Object { $_.Recommended })
        $cov = Test-AsrRuleCoverage -RuleIds $pref.AttackSurfaceReductionRules_Ids `
                                   -RuleActions $pref.AttackSurfaceReductionRules_Actions -Table $rec
        $ev = "Recommended ASR rules: Blocked=$($cov.Blocked), Audit/Warn=$($cov.Audited), Disabled=$($cov.Disabled), Unmanaged=$($cov.Unmanaged) of $($cov.Total)."
        if ($cov.Blocked -eq 0 -and $cov.Audited -eq 0) {
            $findings += New-VulnFinding -Severity 'High' -Category 'PlatformSecurity' `
                -Title 'Defender ASR rules not enabled at all' `
                -Evidence "$ev None of the recommended behavioral rules (Office macro child processes, obfuscated scripts, LSASS credential theft, USB executables) are enforcing or even auditing." `
                -FixGuidance 'Enable the recommended set: Repair-EnableAsrRules (Block mode; -AuditOnly to log first without blocking). Rollback: Add-MpPreference -AttackSurfaceReductionRules_Ids <guid> -AttackSurfaceReductionRules_Actions @(0).' `
                -FixCommand 'Repair-EnableAsrRules'
        } elseif ($cov.Blocked -lt ($rec.Count / 2)) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'PlatformSecurity' `
                -Title 'Defender ASR coverage is partial' `
                -Evidence $ev `
                -FixGuidance 'Enable the recommended set: Repair-EnableAsrRules. Start with -AuditOnly to watch for false blocks, then switch to Block.' `
                -FixCommand 'Repair-EnableAsrRules'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
                -Title 'Defender ASR coverage looks healthy' -Evidence $ev `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'PlatformSecurity' `
            -Title 'ASR rule check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually in Windows Security > App & browser control.' -FixCommand ''
    }
    return $findings
}

function Repair-EnableAsrRules {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([switch]$AuditOnly)
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) { Write-Host '[-] Defender cmdlets unavailable.' -ForegroundColor Red; return }
    $mode = if ($AuditOnly) { 2 } else { 1 }
    $rules = @(Get-AsrRuleTable | Where-Object { $_.Recommended })
    $what = if ($AuditOnly) { 'AUDIT mode (log only)' } else { 'BLOCK mode' }
    if ($PSCmdlet.ShouldProcess('Defender ASR rules', "Enable $($rules.Count) recommended rules in $what")) {
        try {
            $ids = @($rules | ForEach-Object { $_.Guid })
            $acts = @()
            foreach ($i in 1..$rules.Count) { $acts += $mode }
            Add-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $acts -ErrorAction Stop
            Write-Host ("[+] {0} ASR rules set to {1}." -f $rules.Count, $what) -ForegroundColor Green
            Write-Host '[i] If you use Office macros daily, run a week in Audit mode before Block.' -ForegroundColor Gray
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-SystemExploitProtection {
    Write-Host '[*] Checking system-wide exploit protection...' -ForegroundColor Cyan
    $findings = @()
    try {
        if (-not (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue)) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
                -Title 'System exploit protection unknown' -Evidence 'Get-ProcessMitigation unavailable (needs Windows 10+).' `
                -FixGuidance 'None.' -FixCommand ''
            return $findings
        }
        $m = Get-ProcessMitigation -System -ErrorAction Stop
        $depOn = $false;   try { $depOn = [bool]$m.DEP.Enable } catch { }
        $aslrOn = $false;  try { $aslrOn = [bool]$m.ASLR.ForceRelocateImages } catch { }
        $sehopOn = $false; try { $sehopOn = [bool]$m.SEHOP.Enable } catch { }
        $off = @()
        if (-not $depOn) { $off += 'DEP' }
        if (-not $aslrOn) { $off += 'mandatory ASLR (ForceRelocateImages)' }
        if (-not $sehopOn) { $off += 'SEHOP' }
        if ($off.Count -gt 0) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'PlatformSecurity' `
                -Title 'System exploit protections disabled' `
                -Evidence "Disabled at system level: $($off -join ', '). These stop whole classes of memory-corruption exploits." `
                -FixGuidance 'Re-enable: Repair-EnableSystemExploitProtection (reboot required). Rollback: Set-ProcessMitigation -System -Disable <flag>.' `
                -FixCommand 'Repair-EnableSystemExploitProtection'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
                -Title 'System exploit protections on' -Evidence 'DEP, mandatory ASLR and SEHOP are enabled system-wide.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'PlatformSecurity' `
            -Title 'Exploit protection check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Verify manually in Windows Security > App & browser control > Exploit protection.' -FixCommand ''
    }
    return $findings
}

function Repair-EnableSystemExploitProtection {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if (-not (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue)) { Write-Host '[-] Process mitigation cmdlets unavailable.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('system exploit protection', 'Enable DEP, SEHOP, mandatory ASLR (reboot required)')) {
        try {
            Set-ProcessMitigation -System -Enable DEP, SEHOP, ForceRelocateImages -ErrorAction Stop
            Write-Host '[+] System exploit protections enabled. REBOOT to take effect.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Get-ByovdDriverTable {
    # A subset of the public loldrivers.io catalog: signed drivers with
    # legitimate uses that are routinely ABUSED (bring-your-own-vulnerable-
    # driver — used to disable EDR/AV from userland). Honest limit: service-
    # name matching only; hundreds more drivers exist upstream.
    @(
        [pscustomobject]@{ File = 'WinRing0x64.sys';   Note = 'BYOVD staple (MSI-leak tooling). ALSO legit: OpenHardwareMonitor/fan control — investigate, not auto-guilty.' }
        [pscustomobject]@{ File = 'RTCore64.sys';      Note = 'MSI Afterburner. Longest-running BYOVD primitive (arbitrary physical memory R/W).' }
        [pscustomobject]@{ File = 'RTCore32.sys';      Note = '32-bit variant of RTCore64.' }
        [pscustomobject]@{ File = 'dbutil_2_3.sys';    Note = 'Dell DBUtilDrv2. CVE-2021-21551 (arbitrary memory R/W as SYSTEM). Remove Dell firmware tooling if unused.' }
        [pscustomobject]@{ File = 'ESEADriver2.sys';   Note = 'Dell, routinely abused by BYOVD loaders.' }
        [pscustomobject]@{ File = 'gdrv.sys';          Note = 'GIGABYTE. CVE-2018-19320.' }
        [pscustomobject]@{ File = 'gwiopm.sys';        Note = 'GIGABYTE, same vulnerable family as gdrv.' }
        [pscustomobject]@{ File = 'inpoutx64.sys';     Note = 'Logix4u InpOut32 — direct port I/O, ransomware favorite.' }
        [pscustomobject]@{ File = 'NTIOLib_X64.sys';   Note = 'MSI, physical memory access from userland.' }
        [pscustomobject]@{ File = 'ATSZIO64.sys';      Note = 'ASUS, signed driver with R/W primitives, abused.' }
        [pscustomobject]@{ File = 'AsUpIO64.sys';      Note = 'ASUS, abused in BYOVD chains.' }
        [pscustomobject]@{ File = 'AsIO2.sys';         Note = 'ASUS, R/W primitive.' }
        [pscustomobject]@{ File = 'AsIO3.sys';         Note = 'ASUS, R/W primitive.' }
        [pscustomobject]@{ File = 'GlckIo2.sys';       Note = 'ASUS, abused.' }
        [pscustomobject]@{ File = 'iqvw64e.sys';       Note = 'Intel Ethernet diagnostics. CVE-2015-2291.' }
        [pscustomobject]@{ File = 'amsdk.sys';         Note = 'Zemana AntiMalware. BYOVD staple (process termination).' }
        [pscustomobject]@{ File = 'aswArPot.sys';      Note = 'Avast Anti-Rootkit. Abused to kill EDR.' }
        [pscustomobject]@{ File = 'dbk64.sys';         Note = 'Cheat Engine. Maps physical memory; dual-use, abused by stealers.' }
        [pscustomobject]@{ File = 'KProcessHacker.sys'; Note = 'Process Hacker. Dual-use; abused for handle manipulation.' }
        [pscustomobject]@{ File = 'hmpalert.sys';      Note = 'Sophos HitmanPro.Alert. Abused in the Ragnar Locker BYOVD attack.' }
    )
}

function Test-ByovdDriverRow {
    # Pure row classifier: a watch-listed driver present on the box is a
    # finding whether or not it is currently loaded.
    [CmdletBinding()]
    param([string]$ServiceName, [string]$State)
    if ([string]::IsNullOrWhiteSpace($ServiceName)) { return 'absent' }
    if ("$State".ToLower() -eq 'running') { return 'flag-running' }
    return 'flag-present'
}

function Test-ByovdDrivers {
    Write-Host '[*] Checking for known abused (BYOVD) drivers...' -ForegroundColor Cyan
    $findings = @()
    try {
        $drivers = @(Get-WmiObject -Class Win32_SystemDriver -ErrorAction Stop)
        $hits = @()
        foreach ($row in (Get-ByovdDriverTable)) {
            $base = [System.IO.Path]::GetFileNameWithoutExtension($row.File)
            foreach ($d in $drivers) {
                $pn = ''
                try { $pn = [System.IO.Path]::GetFileNameWithoutExtension(([string]$d.PathName).Trim('"')) } catch { }
                if ("$($d.Name)".ToLower().StartsWith($base.ToLower()) -or $pn.ToLower() -eq $base.ToLower()) {
                    $v = Test-ByovdDriverRow -ServiceName $d.Name -State $d.State
                    $hits += [pscustomobject]@{ Service = $d.Name; State = $d.State; Verdict = $v; Note = $row.Note }
                    break
                }
            }
        }
        foreach ($h in $hits) {
            $sev = if ($h.Verdict -eq 'flag-running') { 'High' } else { 'Medium' }
            $stateWord = if ($h.Verdict -eq 'flag-running') { 'LOADED AND RUNNING' } else { 'installed but not running' }
            $findings += New-VulnFinding -Severity $sev -Category 'VulnerableDriver' `
                -Title "Known abused driver $($h.Service) is $stateWord" `
                -Evidence "Driver $($h.Service) (state $($h.State)) is on the BYOVD watch list. $($h.Note)" `
                -FixGuidance "If you do not need the owning tool, disable the driver: Repair-ByovdDriverDisable -ServiceName $($h.Service). Legit uses exist (fan control, hardware monitoring) — verify before disabling. Rollback: sc.exe config $($h.Service) start= demand." `
                -FixCommand 'Repair-ByovdDriverDisable'
        }
        if ($hits.Count -eq 0) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'VulnerableDriver' `
                -Title 'No known abused drivers found' -Evidence "$($drivers.Count) drivers enumerated; none match the BYOVD watch table." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'VulnerableDriver' `
            -Title 'BYOVD driver check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Enumerate drivers manually: Get-WmiObject Win32_SystemDriver.' -FixCommand ''
    }
    return $findings
}

function Repair-ByovdDriverDisable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess("driver $ServiceName", 'Disable driver start (blocks BYOVD loading)')) {
        try {
            $out = & sc.exe config $ServiceName start= disabled 2>&1
            Write-Host "  sc.exe config: $($out -join ' ')"
            $stopOut = & sc.exe stop $ServiceName 2>&1
            Write-Host "  sc.exe stop: $($stopOut -join ' ')"
            Write-Host '[+] Driver disabled. Rollback: sc.exe config <name> start= demand' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-AdminCountVerdict {
    # Pure classifier for the local Administrators census.
    [CmdletBinding()]
    param([int]$Count)
    if ($Count -le 2) { return 'clean' }
    if ($Count -le 4) { return 'review' }
    return 'excessive'
}

function Test-LocalAdminCensus {
    Write-Host '[*] Census of local Administrators...' -ForegroundColor Cyan
    $findings = @()
    try {
        $g = [ADSI]'WinNT://./Administrators,group'
        $members = @($g.Members() | ForEach-Object {
            try { [string]$_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) } catch { '' }
        } | Where-Object { $_ -ne '' })
        $v = Test-AdminCountVerdict -Count $members.Count
        $list = $members -join ', '
        if ($v -eq 'excessive') {
            $findings += New-VulnFinding -Severity 'High' -Category 'AccountSecurity' `
                -Title "Excessive local admins ($($members.Count))" `
                -Evidence "Local Administrators has $($members.Count) members: $list. Every admin is a full-compromise primitive." `
                -FixGuidance 'Demote accounts that do not need admin: lusrmgr.msc, or Remove-LocalGroupMember -Group Administrators -Member <name>.' `
                -FixCommand ''
        } elseif ($v -eq 'review') {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'AccountSecurity' `
                -Title "Multiple local admins ($($members.Count))" `
                -Evidence "Local Administrators: $list. Confirm each one needs admin rights." `
                -FixGuidance 'Demote unneeded accounts: Remove-LocalGroupMember -Group Administrators -Member <name>.' `
                -FixCommand ''
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'AccountSecurity' `
                -Title 'Local admin count looks normal' -Evidence "Local Administrators: $list." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'AccountSecurity' `
            -Title 'Admin census failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check manually: lusrmgr.msc > Groups > Administrators.' -FixCommand ''
    }
    return $findings
}

function Test-LocalPasswordRisk {
    Write-Host '[*] Checking local account password posture...' -ForegroundColor Cyan
    $findings = @()
    try {
        if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'AccountSecurity' `
                -Title 'Password posture unknown (Get-LocalUser unavailable)' `
                -Evidence 'The LocalAccounts cmdlets are not exposed on this machine.' `
                -FixGuidance 'Check manually: lusrmgr.msc > Users.' -FixCommand ''
            return $findings
        }
        $flagged = 0
        foreach ($u in (Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled })) {
            if ($u.PasswordRequired -eq $false) {
                $flagged++
                $findings += New-VulnFinding -Severity 'High' -Category 'AccountSecurity' `
                    -Title "Account '$($u.Name)' does not require a password" `
                    -Evidence "Enabled account $($u.Name) has PasswordRequired=false — local logon needs no password at all." `
                    -FixGuidance 'Require one: net user <name> /passwordreq:yes (admin). Rollback: net user <name> /passwordreq:no.' `
                    -FixCommand ''
            } elseif ($u.PasswordNeverExpires -eq $true) {
                $flagged++
                $findings += New-VulnFinding -Severity 'Medium' -Category 'AccountSecurity' `
                    -Title "Account '$($u.Name)' password never expires" `
                    -Evidence "Enabled account $($u.Name) has PasswordNeverExpires=true — a stolen hash stays valid forever." `
                    -FixGuidance 'Enforce expiry: Repair-ExpireLocalPasswords.' `
                    -FixCommand 'Repair-ExpireLocalPasswords'
            }
        }
        if ($flagged -eq 0) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'AccountSecurity' `
                -Title 'Local account password posture looks healthy' `
                -Evidence 'Every enabled local account requires a password and expires it.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'AccountSecurity' `
            -Title 'Password posture check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check manually: lusrmgr.msc > Users.' -FixCommand ''
    }
    return $findings
}

function Get-TpmStatus {
    Write-Host '[*] Checking TPM...' -ForegroundColor Cyan
    $findings = @()
    try {
        if (-not (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
                -Title 'TPM state unknown (Get-Tpm unavailable)' -Evidence 'The TPM cmdlet is not exposed (pre-Windows 8).' `
                -FixGuidance 'Check firmware settings manually.' -FixCommand ''
            return $findings
        }
        $t = Get-Tpm -ErrorAction Stop
        if ($t.TpmReady) {
            $findings += New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
                -Title 'TPM present and ready' -Evidence "TpmPresent=$($t.TpmPresent), TpmReady=$($t.TpmReady), TpmEnabled=$($t.TpmEnabled)." `
                -FixGuidance 'None needed.' -FixCommand ''
        } elseif ($t.TpmPresent) {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'PlatformSecurity' `
                -Title 'TPM present but not ready' `
                -Evidence "TpmPresent=$($t.TpmPresent), TpmReady=$($t.TpmReady), TpmEnabled=$($t.TpmEnabled). BitLocker cannot use an uninitialized TPM." `
                -FixGuidance 'Initialize it: tpm.msc (Clear/Prepare), or enable in firmware settings.' `
                -FixCommand ''
        } else {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'PlatformSecurity' `
                -Title 'No TPM detected' `
                -Evidence 'Get-Tpm reports no TPM. BitLocker and Device Encryption are unavailable; credential storage is weaker.' `
                -FixGuidance 'Enable the firmware TPM (AMD fTPM / Intel PTT) in BIOS settings if the board has one.' `
                -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Info' -Category 'PlatformSecurity' `
            -Title 'TPM state unknown' -Evidence $_.Exception.Message `
            -FixGuidance 'Check firmware settings manually.' -FixCommand ''
    }
    return $findings
}

# ---------------------------------------------------------------------------
# Credential-hygiene + logon-posture checks (hardening v1.4, 2026-10-30).
# A vuln audit that never looks at HOW you log on misses the easiest
# compromise paths: plaintext passwords in Winlogon, WDigest credential
# caching, remote-UAC bypass, anonymous enumeration, oversized cached-
# logon stores, no screen lock, Defender exclusions that neuter the AV,
# and dangerous local group memberships. Each check is a live registry/
# group read behind a pure predicate the battery can prove; each
# detection ships its Repair-* fix (Better-Way Law).
# ---------------------------------------------------------------------------

function Test-AutoLogonVerdict {
    # Pure classifier. -1 = AutoAdminLogon absent (default: autologon off).
    [CmdletBinding()]
    param([int]$AutoAdminLogon = -1, [bool]$HasDefaultPassword = $false)
    if ($AutoAdminLogon -eq 1 -and $HasDefaultPassword) { return 'critical' }
    if ($AutoAdminLogon -eq 1) { return 'auto-no-password' }
    return 'clean'
}

function Test-AutoLogon {
    # Autologon with a plaintext password under Winlogon: anyone who can
    # read the registry (or mount the disk offline) owns that account.
    Write-Host '[*] Checking Windows autologon...' -ForegroundColor Cyan
    $findings = @()
    try {
        $r = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
        $val = -1
        if ($r -and $null -ne $r.AutoAdminLogon) { $val = [int]$r.AutoAdminLogon }
        $hasPw = ($r -and $null -ne $r.DefaultPassword -and "$($r.DefaultPassword)" -ne '')
        $v = Test-AutoLogonVerdict -AutoAdminLogon $val -HasDefaultPassword ([bool]$hasPw)
        if ($v -eq 'critical') {
            $findings += New-VulnFinding -Severity 'Critical' -Category 'CredentialHygiene' `
                -Title 'Autologon stores a plaintext password in the registry' `
                -Evidence 'Winlogon AutoAdminLogon=1 with a DefaultPassword value present. The password sits in clear text under HKLM\...\Winlogon — readable by any admin process and by anyone who mounts the disk offline.' `
                -FixGuidance 'Kill it: Repair-DisableAutoLogon (removes AutoAdminLogon + DefaultPassword). Rollback: recreate the values — never store a plaintext password there.' `
                -FixCommand 'Repair-DisableAutoLogon'
        } elseif ($v -eq 'auto-no-password') {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'CredentialHygiene' `
                -Title 'Autologon enabled without a stored password' `
                -Evidence 'AutoAdminLogon=1 but no DefaultPassword value — the machine still logs a user in unattended at boot.' `
                -FixGuidance 'Disable: Repair-DisableAutoLogon.' `
                -FixCommand 'Repair-DisableAutoLogon'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'CredentialHygiene' `
                -Title 'Autologon is off' -Evidence 'Winlogon AutoAdminLogon is not 1.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'CredentialHygiene' `
            -Title 'Autologon check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check manually: Winlogon registry key, AutoAdminLogon.' -FixCommand ''
    }
    return $findings
}

function Repair-DisableAutoLogon {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('Winlogon autologon', 'Remove AutoAdminLogon + DefaultPassword values')) {
        try {
            $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            Remove-ItemProperty -Path $key -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $key -Name 'DefaultPassword' -ErrorAction SilentlyContinue
            Write-Host '[+] Autologon disabled; plaintext password value removed. Rollback: recreate the values (not recommended).' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-WDigestVerdict {
    # Pure classifier. -1 = UseLogonCredential absent (default since
    # Win8.1: disabled). Anything other than 1 is not credential caching.
    [CmdletBinding()]
    param([int]$Value = -1)
    if ($Value -eq 1) { return 'enabled' }
    return 'disabled'
}

function Test-WDigest {
    # WDigest UseLogonCredential=1 keeps plaintext passwords in LSASS
    # memory — the Mimikatz happy path. Off by default since 8.1, but
    # re-enabled by some legacy SSO guidance and third-party software.
    Write-Host '[*] Checking WDigest credential caching...' -ForegroundColor Cyan
    $findings = @()
    try {
        $r = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -ErrorAction SilentlyContinue
        $val = -1
        if ($r) { $val = [int]$r.UseLogonCredential }
        if ((Test-WDigestVerdict -Value $val) -eq 'enabled') {
            $findings += New-VulnFinding -Severity 'High' -Category 'CredentialHygiene' `
                -Title 'WDigest plaintext credential caching is ON' `
                -Evidence 'SecurityProviders\WDigest UseLogonCredential=1. LSASS keeps reversible passwords in memory — credential dumping tools harvest them.' `
                -FixGuidance 'Turn it off: Repair-DisableWDigest (sets UseLogonCredential=0; no reboot needed for new logons). Rollback: delete the value or set 1.' `
                -FixCommand 'Repair-DisableWDigest'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'CredentialHygiene' `
                -Title 'WDigest credential caching is off' -Evidence "UseLogonCredential=$val (absent/0 = disabled)." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'CredentialHygiene' `
            -Title 'WDigest check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check manually: SecurityProviders\WDigest registry.' -FixCommand ''
    }
    return $findings
}

function Repair-DisableWDigest {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('WDigest', 'Set UseLogonCredential=0')) {
        try {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord
            Write-Host '[+] WDigest credential caching disabled. Applies to new logons. Rollback: delete UseLogonCredential.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-RemoteUacVerdict {
    # Pure classifier. -1 = LocalAccountTokenFilterPolicy absent
    # (default: remote UAC enforced, filtered token).
    [CmdletBinding()]
    param([int]$Value = -1)
    if ($Value -eq 1) { return 'bypassed' }
    return 'enforced'
}

function Test-RemoteUacBypass {
    # LocalAccountTokenFilterPolicy=1 gives remote local admins a FULL
    # token over the network — remote UAC is bypassed, PSEXEC-style
    # lateral movement gets easier.
    Write-Host '[*] Checking remote UAC (LocalAccountTokenFilterPolicy)...' -ForegroundColor Cyan
    $findings = @()
    try {
        $r = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue
        $val = -1
        if ($r) { $val = [int]$r.LocalAccountTokenFilterPolicy }
        if ((Test-RemoteUacVerdict -Value $val) -eq 'bypassed') {
            $findings += New-VulnFinding -Severity 'High' -Category 'CredentialHygiene' `
                -Title 'Remote UAC bypass enabled (LocalAccountTokenFilterPolicy=1)' `
                -Evidence 'LocalAccountTokenFilterPolicy=1. Remote connections from local admin accounts get a full (unfiltered) token — the remote-UAC gate is open, which eases lateral movement.' `
                -FixGuidance 'Restore the default: Repair-RestoreRemoteUac (deletes the value). Rollback: recreate it set to 1.' `
                -FixCommand 'Repair-RestoreRemoteUac'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'CredentialHygiene' `
                -Title 'Remote UAC enforced' -Evidence "LocalAccountTokenFilterPolicy=$val (absent/0 = filtered token)." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'CredentialHygiene' `
            -Title 'Remote UAC check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check manually: System policies registry.' -FixCommand ''
    }
    return $findings
}

function Repair-RestoreRemoteUac {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('Remote UAC policy', 'Delete LocalAccountTokenFilterPolicy (restore default)')) {
        try {
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue
            Write-Host '[+] Remote UAC restored to default (filtered token). Rollback: recreate the value set to 1.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-AnonymousVerdict {
    # Pure classifier over LSA anonymous-access hardening values.
    [CmdletBinding()]
    param([int]$RestrictAnonymous = 0, [int]$EveryoneIncludesAnonymous = 0)
    if ($EveryoneIncludesAnonymous -eq 1) { return 'everyone-anonymous' }
    if ($RestrictAnonymous -eq 0) { return 'enumerable' }
    return 'hardened'
}

function Test-AnonymousEnumeration {
    # RestrictAnonymous=0 (the client default) lets anonymous users
    # enumerate SAM accounts and shares; EveryoneIncludesAnonymous=1 is
    # worse — anonymous rides along in the Everyone group.
    Write-Host '[*] Checking anonymous enumeration hardening...' -ForegroundColor Cyan
    $findings = @()
    try {
        $r1 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -ErrorAction SilentlyContinue
        $r2 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -ErrorAction SilentlyContinue
        $ra = 0; $eia = 0
        if ($r1) { $ra = [int]$r1.RestrictAnonymous }
        if ($r2) { $eia = [int]$r2.EveryoneIncludesAnonymous }
        $v = Test-AnonymousVerdict -RestrictAnonymous $ra -EveryoneIncludesAnonymous $eia
        if ($v -eq 'everyone-anonymous') {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'Anonymous users are inside the Everyone group' `
                -Evidence "EveryoneIncludesAnonymous=1. Anonymous connections inherit every permission granted to Everyone — share and resource ACLs are effectively open." `
                -FixGuidance 'Harden: Repair-HardenAnonymousAccess (EveryoneIncludesAnonymous=0, RestrictAnonymous=1). Rollback: restore prior values.' `
                -FixCommand 'Repair-HardenAnonymousAccess'
        } elseif ($v -eq 'enumerable') {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title 'Anonymous SAM/share enumeration allowed' `
                -Evidence "RestrictAnonymous=0 (client default). Anonymous users can enumerate account names and share names — recon fuel." `
                -FixGuidance 'Harden: Repair-HardenAnonymousAccess (RestrictAnonymous=1; level 2 breaks legacy clients — not set automatically).' `
                -FixCommand 'Repair-HardenAnonymousAccess'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'Anonymous access hardened' -Evidence "RestrictAnonymous=$ra, EveryoneIncludesAnonymous=$eia." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'Anonymous enumeration check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check manually: Lsa registry key.' -FixCommand ''
    }
    return $findings
}

function Repair-HardenAnonymousAccess {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('LSA anonymous access', 'RestrictAnonymous=1, EveryoneIncludesAnonymous=0')) {
        try {
            $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            Set-ItemProperty -Path $key -Name 'RestrictAnonymous' -Value 1 -Type DWord
            Set-ItemProperty -Path $key -Name 'EveryoneIncludesAnonymous' -Value 0 -Type DWord
            Write-Host '[+] Anonymous access hardened (RestrictAnonymous=1). Rollback: RestrictAnonymous=0.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-CachedLogonsVerdict {
    # Pure classifier. -1 = CachedLogonsCount absent (default: "10").
    [CmdletBinding()]
    param([int]$Count = -1)
    if ($Count -eq -1) { $Count = 10 }
    if ($Count -le 4) { return 'clean' }
    return 'review'
}

function Test-CachedLogonsCount {
    # Cached domain credentials let a stolen machine (or its SAM/SECURITY
    # hives) be attacked offline. The default of 10 is generous; 4 or
    # fewer keeps usability while shrinking the target.
    Write-Host '[*] Checking cached logon count...' -ForegroundColor Cyan
    $findings = @()
    try {
        $r = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -ErrorAction SilentlyContinue
        $val = -1
        if ($r) { $val = [int]$r.CachedLogonsCount }
        if ((Test-CachedLogonsVerdict -Count $val) -eq 'review') {
            $shown = if ($val -eq -1) { '10 (default)' } else { "$val" }
            $findings += New-VulnFinding -Severity 'Medium' -Category 'CredentialHygiene' `
                -Title "Cached logon count is high ($shown)" `
                -Evidence "CachedLogonsCount=$shown. Each cached verifier is an offline-crackable target on a lost or stolen machine." `
                -FixGuidance 'Reduce: Repair-ReduceCachedLogons (sets 4). Rollback: set back to 10.' `
                -FixCommand 'Repair-ReduceCachedLogons'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'CredentialHygiene' `
                -Title 'Cached logon count looks tight' -Evidence "CachedLogonsCount=$val." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'CredentialHygiene' `
            -Title 'Cached logon check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check manually: Winlogon CachedLogonsCount.' -FixCommand ''
    }
    return $findings
}

function Repair-ReduceCachedLogons {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    if ($PSCmdlet.ShouldProcess('Cached logons', 'Set CachedLogonsCount=4')) {
        try {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Value '4' -Type String
            Write-Host '[+] CachedLogonsCount set to 4. Rollback: set back to 10.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-ScreenLockVerdict {
    # Pure classifier. TimeoutSec -1 = value absent (default 600).
    # IsSecure $null = value absent.
    [CmdletBinding()]
    param([int]$TimeoutSec = -1, [object]$IsSecure = $null)
    $sec = "$IsSecure"
    if ($sec -eq '0' -or $sec -eq 'False' -or $sec -eq 'false') { return 'no-lock' }
    $t = if ($TimeoutSec -eq -1) { 600 } else { $TimeoutSec }
    if ($t -gt 900) { return 'long-timeout' }
    return 'clean'
}

function Test-ScreenLock {
    # A workstation that never locks is a physical-access gift: walk up,
    # sit down, own the session. Secure lock at a short timeout is free.
    Write-Host '[*] Checking screen lock posture...' -ForegroundColor Cyan
    $findings = @()
    try {
        $r = Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue
        $to = -1; $sec = $null
        if ($r) {
            if ($null -ne $r.ScreenSaveTimeOut) { $to = [int]$r.ScreenSaveTimeOut }
            if ($null -ne $r.ScreenSaverIsSecure) { $sec = $r.ScreenSaverIsSecure }
        }
        $v = Test-ScreenLockVerdict -TimeoutSec $to -IsSecure $sec
        if ($v -eq 'no-lock') {
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title 'Screen saver lock is OFF' `
                -Evidence "ScreenSaverIsSecure=$sec. The session never locks on idle — anyone with physical access inherits the logged-on session." `
                -FixGuidance 'Lock it: Repair-EnableScreenLock (300s timeout, password required). Rollback: ScreenSaverIsSecure=0.' `
                -FixCommand 'Repair-EnableScreenLock'
        } elseif ($v -eq 'long-timeout') {
            $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
                -Title "Screen lock timeout is long ($to s)" `
                -Evidence "ScreenSaveTimeOut=$to seconds (>900). The unattended window is wide." `
                -FixGuidance 'Shorten: Repair-EnableScreenLock (300s). Rollback: set ScreenSaveTimeOut back.' `
                -FixCommand 'Repair-EnableScreenLock'
        } else {
            $shown = if ($to -eq -1) { '600 (default)' } else { "$to" }
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'Screen lock looks healthy' -Evidence "ScreenSaveTimeOut=$shown, ScreenSaverIsSecure=$sec." `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'Screen lock check failed' -Evidence $_.Exception.Message `
            -FixGuidance 'Check manually: Settings > Personalization > Lock screen.' -FixCommand ''
    }
    return $findings
}

function Repair-EnableScreenLock {
    # Per-user setting (HKCU) — no elevation required, applies to the
    # account running it.
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if ($PSCmdlet.ShouldProcess('Screen lock', 'ScreenSaveTimeOut=300, ScreenSaverIsSecure=1')) {
        try {
            Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveTimeOut' -Value '300' -Type String
            Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaverIsSecure' -Value '1' -Type String
            Write-Host '[+] Screen lock: 5-minute timeout, password required on resume. Applies to the current user. Rollback: set ScreenSaverIsSecure=0.' -ForegroundColor Green
        } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Test-DefenderExclusionRisk {
    # Pure classifier for one Defender exclusion path.
    [CmdletBinding()]
    param([string]$Path = '')
    $p = "$Path".Trim()
    if ($p -eq '') { return 'clean' }
    if ($p -match '^[A-Za-z]:\\?$' -or $p -eq '\' -or $p -eq '/') { return 'root' }
    if ($p -match '^[A-Za-z]:\\(Windows|WinNT|Program Files|Program Files \(x86\)|ProgramData|System32|SysWOW64)($|\\)') { return 'system' }
    return 'review'
}

function Get-DefenderHighRiskExtensionTable {
    # Executable/script extensions. A file-extension exclusion tells the
    # scanner to ignore that type EVERYWHERE — malware installers add
    # exactly these. One source of truth for the classifier + battery.
    return @('exe','dll','ps1','psm1','vbs','vbe','js','jse','bat','cmd','msi','scr','com','pif','hta','wsf','wsh','jar')
}

function Get-DefenderLolBinProcessTable {
    # Process-name exclusions for these neuter behavioral monitoring on
    # living-off-the-land binaries — the adversary's favorite toolbox.
    return @('powershell.exe','powershell_ise.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe','certutil.exe','bitsadmin.exe')
}

function Test-DefenderChannelExclusionRisk {
    # Pure classifier for Defender ExclusionExtension / ExclusionProcess /
    # ExclusionIpAddress values (the channels the old audit never read —
    # v1.3 only examined ExclusionPath). 'dangerous' = a whole malware
    # class lands un-scanned; 'high' = a LOLBin runs un-monitored;
    # 'review' = narrower but still a hole; 'clean' = empty value.
    [CmdletBinding()]
    param([string]$Channel = '', [string]$Value = '')
    $v = "$Value".Trim()
    if ($v -eq '') { return 'clean' }
    switch ("$Channel".ToLower()) {
        'extension' {
            $ext = $v.TrimStart('.').ToLower()
            if ($ext -in (Get-DefenderHighRiskExtensionTable)) { return 'dangerous' }
            return 'review'
        }
        'process' {
            if ($v.ToLower() -in (Get-DefenderLolBinProcessTable)) { return 'high' }
            return 'review'
        }
        'ip' { return 'review' }
        default { return 'review' }
    }
}

function Test-DefenderExclusions {
    # Exclusions neuter the scanner for whatever they cover. v1.3 only
    # read ExclusionPath; v1.4 reads ALL four channels — a whole-drive
    # path OR an ExclusionExtension '.exe' OR an ExclusionProcess
    # 'powershell.exe' is each an AV bypass wearing a config hat, and
    # malware installers add exactly these to survive.
    Write-Host '[*] Checking Defender exclusions (all four channels)...' -ForegroundColor Cyan
    $findings = @()
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        $pathRows = @(@($mp.ExclusionPath) | ForEach-Object {
            [pscustomobject]@{ Channel = 'path'; Value = $_; Risk = (Test-DefenderExclusionRisk -Path $_) }
        })
        $extRows = @(@($mp.ExclusionExtension) | ForEach-Object {
            [pscustomobject]@{ Channel = 'extension'; Value = $_; Risk = (Test-DefenderChannelExclusionRisk -Channel 'extension' -Value $_) }
        })
        $procRows = @(@($mp.ExclusionProcess) | ForEach-Object {
            [pscustomobject]@{ Channel = 'process'; Value = $_; Risk = (Test-DefenderChannelExclusionRisk -Channel 'process' -Value $_) }
        })
        $ipRows = @(@($mp.ExclusionIpAddress) | ForEach-Object {
            [pscustomobject]@{ Channel = 'ip'; Value = $_; Risk = (Test-DefenderChannelExclusionRisk -Channel 'ip' -Value $_) }
        })
        $roots  = @($pathRows | Where-Object { $_.Risk -eq 'root' })
        $sys    = @($pathRows | Where-Object { $_.Risk -eq 'system' })
        $others = @($pathRows | Where-Object { $_.Risk -eq 'review' })
        $dangerExt = @($extRows | Where-Object { $_.Risk -eq 'dangerous' })
        $highProc  = @($procRows | Where-Object { $_.Risk -eq 'high' })
        $reviewChan = @($extRows + $procRows + $ipRows | Where-Object { $_.Risk -eq 'review' })
        if ($roots.Count -gt 0) {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'Defender excludes a whole drive' `
                -Evidence "Root-level exclusion(s): $($roots.Value -join '; '). The scanner ignores the entire drive — check whether you or software added this." `
                -FixGuidance 'Remove what you did not authorize: Repair-RemoveDefenderExclusion (interactive, per-channel confirm). Rollback: Add-MpPreference -ExclusionPath <path>.' `
                -FixCommand 'Repair-RemoveDefenderExclusion'
        } elseif ($sys.Count -gt 0) {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'Defender excludes system directories' `
                -Evidence "System exclusion(s): $($sys.Value -join '; '). Malware drops into exactly these places." `
                -FixGuidance 'Remove what you did not authorize: Repair-RemoveDefenderExclusion.' `
                -FixCommand 'Repair-RemoveDefenderExclusion'
        } elseif ($dangerExt.Count -gt 0) {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'Defender excludes executable file extensions' `
                -Evidence "Extension exclusion(s): $($dangerExt.Value -join '; '). The scanner ignores these file types EVERYWHERE — a malware-installer signature move." `
                -FixGuidance 'Remove what you did not authorize: Repair-RemoveDefenderExclusion. Rollback: Add-MpPreference -ExclusionExtension <ext>.' `
                -FixCommand 'Repair-RemoveDefenderExclusion'
        } elseif ($highProc.Count -gt 0) {
            $findings += New-VulnFinding -Severity 'High' -Category 'WeakConfig' `
                -Title 'Defender excludes living-off-the-land processes' `
                -Evidence "Process exclusion(s): $($highProc.Value -join '; '). Behavioral monitoring is blind to these — the adversary's favorite toolbox." `
                -FixGuidance 'Remove what you did not authorize: Repair-RemoveDefenderExclusion. Rollback: Add-MpPreference -ExclusionProcess <name>.' `
                -FixCommand 'Repair-RemoveDefenderExclusion'
        } elseif ($others.Count + $reviewChan.Count -gt 0) {
            $all = @($others + $reviewChan | ForEach-Object { "$($_.Channel):$($_.Value)" })
            $findings += New-VulnFinding -Severity 'Medium' -Category 'WeakConfig' `
                -Title "$($all.Count) Defender exclusion(s) present" `
                -Evidence "Exclusions: $($all -join '; '). Each one is a hole in the scanner — confirm every entry is yours." `
                -FixGuidance 'Prune: Repair-RemoveDefenderExclusion.' `
                -FixCommand 'Repair-RemoveDefenderExclusion'
        } else {
            $findings += New-VulnFinding -Severity 'Info' -Category 'WeakConfig' `
                -Title 'No Defender exclusions on any channel' -Evidence 'Get-MpPreference reports no path/extension/process/IP exclusions.' `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    } catch {
        $findings += New-VulnFinding -Severity 'Low' -Category 'WeakConfig' `
            -Title 'Defender exclusions unreadable' `
            -Evidence "Get-MpPreference failed: $($_.Exception.Message) (usually needs elevation, or a third-party AV owns protection)." `
            -FixGuidance 'Re-run elevated, or check Windows Security > Exclusions manually.' -FixCommand ''
    }
    return $findings
}

function Repair-RemoveDefenderExclusion {
    # Interactive: lists exclusions across all four channels, removes only
    # the ones the user picks, via the matching Remove-MpPreference switch.
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Test-IsElevated)) { Write-Host '[-] Requires elevation.' -ForegroundColor Red; return }
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        $rows = @()
        foreach ($p in @($mp.ExclusionPath))      { $rows += [pscustomobject]@{ Channel = 'path';      Value = $p; Risk = (Test-DefenderExclusionRisk -Path $p) } }
        foreach ($e in @($mp.ExclusionExtension)) { $rows += [pscustomobject]@{ Channel = 'extension'; Value = $e; Risk = (Test-DefenderChannelExclusionRisk -Channel 'extension' -Value $e) } }
        foreach ($r in @($mp.ExclusionProcess))   { $rows += [pscustomobject]@{ Channel = 'process';   Value = $r; Risk = (Test-DefenderChannelExclusionRisk -Channel 'process' -Value $r) } }
        foreach ($i in @($mp.ExclusionIpAddress)) { $rows += [pscustomobject]@{ Channel = 'ip';        Value = $i; Risk = (Test-DefenderChannelExclusionRisk -Channel 'ip' -Value $i) } }
        if ($rows.Count -eq 0) { Write-Host '[+] No exclusions to remove.' -ForegroundColor Green; return }
        for ($i = 0; $i -lt $rows.Count; $i++) {
            Write-Host ("  {0}) [{1}/{2}] {3}" -f ($i + 1), $rows[$i].Channel, $rows[$i].Risk, $rows[$i].Value)
        }
        $pick = Read-Host 'Remove which number (0 = none)'
        $n = 0
        if ([int]::TryParse($pick, [ref]$n) -and $n -ge 1 -and $n -le $rows.Count) {
            $target = $rows[$n - 1]
            $label = "$($target.Channel):$($target.Value)"
            if ($PSCmdlet.ShouldProcess($label, 'Remove Defender exclusion')) {
                switch ($target.Channel) {
                    'path'      { Remove-MpPreference -ExclusionPath $target.Value -ErrorAction Stop;      $undo = "Add-MpPreference -ExclusionPath '$($target.Value)'" }
                    'extension' { Remove-MpPreference -ExclusionExtension $target.Value -ErrorAction Stop; $undo = "Add-MpPreference -ExclusionExtension '$($target.Value)'" }
                    'process'   { Remove-MpPreference -ExclusionProcess $target.Value -ErrorAction Stop;   $undo = "Add-MpPreference -ExclusionProcess '$($target.Value)'" }
                    'ip'        { Remove-MpPreference -ExclusionIpAddress $target.Value -ErrorAction Stop;  $undo = "Add-MpPreference -ExclusionIpAddress '$($target.Value)'" }
                }
                Write-Host "[+] Removed exclusion: $label. Rollback: $undo." -ForegroundColor Green
            }
        } else { Write-Host '[-] Nothing removed.' -ForegroundColor Yellow }
    } catch { Write-Host "[-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
}

function Test-PrivilegedGroupVerdict {
    # Pure classifier for dangerous local groups.
    [CmdletBinding()]
    param([string]$Group = '', [int]$Count = 0)
    $g = "$Group".ToLower()
    if ($g -eq 'backup operators' -or $g -eq 'hyper-v administrators') {
        if ($Count -gt 0) { return 'dangerous' }
        return 'clean'
    }
    if ($g -eq 'remote management users') {
        if ($Count -gt 0) { return 'review' }
        return 'clean'
    }
    if ($g -eq 'remote desktop users') {
        if ($Count -gt 3) { return 'review' }
        return 'clean'
    }
    if ($g -eq 'dcom users') {
        if ($Count -gt 0) { return 'review' }
        return 'clean'
    }
    return 'unknown'
}

function Test-PrivilegedGroupCensus {
    # Administrators get a census already; these are the OTHER dangerous
    # groups: Backup Operators can read the SAM/SECURITY hives (full
    # credential theft), Hyper-V Administrators escape to SYSTEM via the
    # hypervisor, Remote Management Users get WinRM, Remote Desktop Users
    # get interactive logon, DCOM Users get remote activation.
    Write-Host '[*] Census of privileged local groups...' -ForegroundColor Cyan
    $findings = @()
    $groups = @('Backup Operators', 'Remote Desktop Users', 'Remote Management Users', 'DCOM Users', 'Hyper-V Administrators')
    foreach ($gname in $groups) {
        try {
            $g = [ADSI]"WinNT://./$gname,group"
            $members = @($g.Members() | ForEach-Object {
                try { [string]$_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) } catch { '' }
            } | Where-Object { $_ -ne '' })
            $v = Test-PrivilegedGroupVerdict -Group $gname -Count $members.Count
            $list = if ($members.Count -gt 0) { $members -join ', ' } else { '(empty)' }
            if ($v -eq 'dangerous') {
                $why = if ($gname -eq 'Backup Operators') {
                    'can read the SAM and SECURITY hives — a credential-theft primitive one backup away'
                } else {
                    'can manage Hyper-V and escape to SYSTEM through the virtualization stack'
                }
                $findings += New-VulnFinding -Severity 'High' -Category 'AccountSecurity' `
                    -Title "Dangerous group '$gname' has members ($($members.Count))" `
                    -Evidence "$gname members: $list. This group $why." `
                    -FixGuidance "Remove who does not belong: Remove-LocalGroupMember -Group '$gname' -Member <name> (admin). Rollback: Add-LocalGroupMember." `
                    -FixCommand ''
            } elseif ($v -eq 'review') {
                $findings += New-VulnFinding -Severity 'Medium' -Category 'AccountSecurity' `
                    -Title "Group '$gname' membership worth a look ($($members.Count))" `
                    -Evidence "$gname members: $list. This group grants a meaningful remote/interactive primitive." `
                    -FixGuidance "Trim it: Remove-LocalGroupMember -Group '$gname' -Member <name> (admin)." `
                    -FixCommand ''
            } else {
                $findings += New-VulnFinding -Severity 'Info' -Category 'AccountSecurity' `
                    -Title "Group '$gname' looks fine" -Evidence "Members: $list." `
                    -FixGuidance 'None needed.' -FixCommand ''
            }
        } catch {
            $findings += New-VulnFinding -Severity 'Info' -Category 'AccountSecurity' `
                -Title "Group '$gname' not present or unreadable" `
                -Evidence "The group could not be enumerated on this machine: $($_.Exception.Message)" `
                -FixGuidance 'None needed.' -FixCommand ''
        }
    }
    return $findings
}

# ---------------------------------------------------------------------------
# Offline self-test battery (no network, no admin, no Windows APIs).
# Proves the classification logic the audit stands on: version compare,
# port-risk table, EOL table sanity, unquoted-path verdicts, lockout
# parsing, ASR coverage, admin verdicts, BYOVD table/rows. Scope-safe:
# each $mk scriptblock's OUTPUT is collected ($results += &$mk ...),
# never child-scope $results += inside &$add. Returns $true only when
# every check passes.
# ---------------------------------------------------------------------------

function Test-VulnCheckHygiene {
    [CmdletBinding()]
    param()
    Write-Host '[*] Vuln-check self-test (offline, no admin)...' -ForegroundColor Cyan
    $results = @()
    $mk = {
        param($name, $pass, $detail)
        [pscustomobject]@{ Check = $name; Pass = [bool]$pass; Detail = "$detail" }
    }

    # 1. Version compare (Compare-VersionStrings)
    $vcases = @(
        @{ A = '1.10'; B = '1.9';   Want =  1; Note = 'numeric segments, not lexicographic' },
        @{ A = '24.07'; B = '24.07'; Want =  0; Note = 'equality' },
        @{ A = '7.12'; B = '7.13';  Want = -1; Note = 'less-than' },
        @{ A = '25.001.20693'; B = '25.001'; Want = 1; Note = 'longer build wins' },
        @{ A = '6.1p2'; B = '6.1';  Want =  1; Note = 'letters stripped, trailing digit kept (6.1p2 -> 6.12), no crash' },
        @{ A = '141';   B = '140.0.0.0'; Want = 1; Note = 'unequal segment counts' }
    )
    foreach ($c in $vcases) {
        $got = Compare-VersionStrings $c.A $c.B
        $results += &$mk "version: $($c.A) vs $($c.B)" ($got -eq $c.Want) "$($c.Note) -> got $got"
    }

    # 2. Port risk classification (Get-PortRiskSeverity)
    $pcases = @(
        @{ Port = 445;   Want = 'High' },
        @{ Port = 3389;  Want = 'High' },
        @{ Port = 4444;  Want = 'High' },
        @{ Port = 11211; Want = 'High' },
        @{ Port = 8080;  Want = 'Medium' },
        @{ Port = 53;    Want = 'Medium' },
        @{ Port = 9999;  Want = 'None' }
    )
    foreach ($c in $pcases) {
        $got = Get-PortRiskSeverity -Port $c.Port
        $results += &$mk "port-risk: $($c.Port)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }
    # HighRiskPorts must be a subset of RiskyPorts (a High port with no
    # description would lie in the report).
    $orphan = @($script:HighRiskPorts | Where-Object { -not $script:RiskyPorts.ContainsKey($_) })
    $results += &$mk 'port-table: HighRisk subset of RiskyPorts' ($orphan.Count -eq 0) "orphans: $($orphan -join ',')"
    $badKeys = @($script:RiskyPorts.Keys | Where-Object { $_ -lt 1 -or $_ -gt 65535 })
    $results += &$mk 'port-table: keys in 1-65535' ($badKeys.Count -eq 0) "bad: $($badKeys -join ',')"
    $emptyDesc = @($script:RiskyPorts.Keys | Where-Object { [string]::IsNullOrWhiteSpace($script:RiskyPorts[$_]) })
    $results += &$mk 'port-table: every row has a description' ($emptyDesc.Count -eq 0) "empty: $($emptyDesc -join ',')"

    # 3. EOL table sanity
    $pats = @($script:EolSoftware | ForEach-Object { $_.Pattern })
    $dups = @($pats | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    $results += &$mk 'eol-table: unique patterns' ($dups.Count -eq 0) "dups: $($dups -join ',')"
    $badSev = @($script:EolSoftware | Where-Object { $_.Severity -notin @('Critical','High','Medium','Low','Info') })
    $results += &$mk 'eol-table: valid severities' ($badSev.Count -eq 0) "bad: $($badSev.Count)"
    $noMin = @($script:EolSoftware | Where-Object { $_.Match -eq 'version' -and [string]::IsNullOrWhiteSpace($_.MinSafe) })
    $results += &$mk 'eol-table: version rows carry MinSafe' ($noMin.Count -eq 0) "missing: $($noMin.Count)"
    $badMode = @($script:EolSoftware | Where-Object { $_.Match -notin @('any','version') })
    $results += &$mk 'eol-table: valid match modes' ($badMode.Count -eq 0) "bad: $($badMode.Count)"

    # 4. Unquoted-path verdicts (Get-UnquotedPathVerdict, synthetic)
    $ucases = @(
        @{ Path = '"C:\Program Files\App\svc.exe" -k netsvcs'; W = @(); Want = 'clean'; Note = 'quoted path' },
        @{ Path = 'C:\Windows\System32\svchost.exe -k netsvcs'; W = @(); Want = 'clean'; Note = 'no space at all' },
        @{ Path = 'C:\Program Files\My App\svc.exe'; W = @('C:\Program Files\My App'); Want = 'exploitable'; Note = 'writable dir precedes exe' },
        @{ Path = 'C:\Program Files\My App\svc.exe'; W = @('C:\Other'); Want = 'unquoted-not-writable'; Note = 'writable dir unrelated' },
        @{ Path = 'C:\My Dir\svc.exe'; W = @(); Want = 'unquoted-not-writable'; Note = 'unquoted, nothing writable' },
        @{ Path = 'C:\My Dir\svc'; W = @('C:\My Dir'); Want = 'unparseable'; Note = 'no .exe boundary' },
        @{ Path = 'C:\Tools\svc.exe --config "C:\My Dir\cfg"'; W = @('C:\Tools'); Want = 'clean'; Note = 'space only in args' }
    )
    foreach ($c in $ucases) {
        $v = Get-UnquotedPathVerdict -PathName $c.Path -WritableSegments $c.W
        $results += &$mk "unquoted-verdict: $($c.Note)" ($v.Verdict -eq $c.Want) "want $($c.Want), got $($v.Verdict)"
    }

    # 5. Lockout parsing (ConvertFrom-NetAccountsLockout)
    $lcases = @(
        @{ Text = "Lockout threshold:          Never"; Want = -1 },
        @{ Text = "Lockout threshold:          5";     Want = 5 },
        @{ Text = "Lockout threshold:          0";     Want = 0 },
        @{ Text = "some other text entirely";          Want = $null }
    )
    foreach ($c in $lcases) {
        $got = ConvertFrom-NetAccountsLockout -NetAccountsText $c.Text
        $ok = if ($c.Want -eq $null) { $got -eq $null } else { $got -eq $c.Want }
        $results += &$mk "lockout-parse: '$($c.Text)'" $ok "want $($c.Want), got $got"
    }

    # 6. ASR coverage (Test-AsrRuleCoverage, pure)
    $miniTable = @(
        [pscustomobject]@{ Guid = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'; Name = 'A'; Recommended = $true },
        [pscustomobject]@{ Guid = '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'; Name = 'B'; Recommended = $true }
    )
    $acases = @(
        @{ Ids = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A','9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'); Acts = @(1,2); F = 'Blocked';   Want = 1; Note = 'block count over mini table' },
        @{ Ids = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A','9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'); Acts = @(1,2); F = 'Audited';   Want = 1; Note = 'audit count over mini table' },
        @{ Ids = @('d4f940ab-401b-4efc-aadc-ad5f3c50688a');                                    Acts = @(1);    F = 'Blocked';   Want = 1; Note = 'GUID match is case-insensitive' },
        @{ Ids = @();                                                                       Acts = @();    F = 'Unmanaged'; Want = 2; Note = 'no policy at all -> all unmanaged' },
        @{ Ids = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A');                                  Acts = @(0);    F = 'Disabled';  Want = 1; Note = 'explicit disable counts as disabled' },
        @{ Ids = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A','9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'); Acts = @(1); F = 'Unmanaged'; Want = 1; Note = 'short actions array -> unmanaged, not crash' },
        @{ Ids = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A');                                  Acts = @(6);    F = 'Audited';   Want = 1; Note = 'warn (6) counts with audit' }
    )
    foreach ($c in $acases) {
        $cov = Test-AsrRuleCoverage -RuleIds $c.Ids -RuleActions $c.Acts -Table $miniTable
        $got = $cov.($c.F)
        $results += &$mk "asr-coverage: $($c.Note)" ($got -eq $c.Want) "want $($c.F)=$($c.Want), got $got"
    }
    # ASR table sanity (shipped GUIDs — verified against Microsoft Learn 2026-10-30)
    $asrTable = Get-AsrRuleTable
    $guidRe = '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
    $badGuid = @($asrTable | Where-Object { $_.Guid -notmatch $guidRe })
    $dupGuid = @($asrTable.Guid | ForEach-Object { $_.ToLower() } | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    $noName = @($asrTable | Where-Object { [string]::IsNullOrWhiteSpace($_.Name) })
    $rec = @($asrTable | Where-Object { $_.Recommended }).Count
    $results += &$mk 'asr-table: 15 shipped rows' ($asrTable.Count -eq 15) "rows=$($asrTable.Count)"
    $results += &$mk 'asr-table: valid GUID format' ($badGuid.Count -eq 0) "bad: $($badGuid.Count)"
    $results += &$mk 'asr-table: unique GUIDs' ($dupGuid.Count -eq 0) "dups: $($dupGuid -join ',')"
    $results += &$mk 'asr-table: every row named' ($noName.Count -eq 0) "unnamed: $($noName.Count)"
    $results += &$mk 'asr-table: 15 recommended' ($rec -eq 15) "recommended=$rec"

    # 7. Admin census verdicts (Test-AdminCountVerdict, pure)
    $adc = @(
        @{ Count = 1; Want = 'clean' }, @{ Count = 2; Want = 'clean' },
        @{ Count = 3; Want = 'review' }, @{ Count = 4; Want = 'review' },
        @{ Count = 5; Want = 'excessive' }, @{ Count = 12; Want = 'excessive' }
    )
    foreach ($c in $adc) {
        $got = Test-AdminCountVerdict -Count $c.Count
        $results += &$mk "admin-verdict: count $($c.Count)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }

    # 8. BYOVD table + row classifier
    $bvTable = Get-ByovdDriverTable
    $bvDup = @($bvTable.File | ForEach-Object { $_.ToLower() } | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    $bvBad = @($bvTable | Where-Object { $_.File -notlike '*.sys' -or [string]::IsNullOrWhiteSpace($_.Note) })
    $results += &$mk 'byovd-table: 20 shipped rows' ($bvTable.Count -eq 20) "rows=$($bvTable.Count)"
    $results += &$mk 'byovd-table: unique .sys files, every row noted' (($bvDup.Count -eq 0) -and ($bvBad.Count -eq 0)) "dups=$($bvDup.Count) bad=$($bvBad.Count)"
    $bvCases = @(
        @{ Name = 'RTCore64'; State = 'Running'; Want = 'flag-running' },
        @{ Name = 'RTCore64'; State = 'Stopped'; Want = 'flag-present' },
        @{ Name = 'gdrv';     State = 'RUNNING'; Want = 'flag-running' },
        @{ Name = '';         State = 'Running'; Want = 'absent' }
    )
    foreach ($c in $bvCases) {
        $got = Test-ByovdDriverRow -ServiceName $c.Name -State $c.State
        $results += &$mk "byovd-row: $($c.Name)/$($c.State)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }

    # 9. Credential-hygiene + logon-posture predicates (v1.4)
    $alCases = @(
        @{ A = 1;  Pw = $true;  Want = 'critical' },
        @{ A = 1;  Pw = $false; Want = 'auto-no-password' },
        @{ A = -1; Pw = $false; Want = 'clean' },
        @{ A = 0;  Pw = $false; Want = 'clean' },
        @{ A = 1;  Pw = $true;  Want = 'critical' }
    )
    foreach ($c in $alCases) {
        $got = Test-AutoLogonVerdict -AutoAdminLogon $c.A -HasDefaultPassword $c.Pw
        $results += &$mk "autologon-verdict: A=$($c.A) pw=$($c.Pw)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }
    $wdCases = @(
        @{ V = 1;  Want = 'enabled' },
        @{ V = -1; Want = 'disabled' },
        @{ V = 0;  Want = 'disabled' },
        @{ V = 2;  Want = 'disabled' }
    )
    foreach ($c in $wdCases) {
        $got = Test-WDigestVerdict -Value $c.V
        $results += &$mk "wdigest-verdict: V=$($c.V)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }
    $ruCases = @(
        @{ V = 1;  Want = 'bypassed' },
        @{ V = -1; Want = 'enforced' },
        @{ V = 0;  Want = 'enforced' }
    )
    foreach ($c in $ruCases) {
        $got = Test-RemoteUacVerdict -Value $c.V
        $results += &$mk "remoteuac-verdict: V=$($c.V)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }
    $anCases = @(
        @{ RA = 0; EIA = 0; Want = 'enumerable' },
        @{ RA = 1; EIA = 0; Want = 'hardened' },
        @{ RA = 0; EIA = 1; Want = 'everyone-anonymous' },
        @{ RA = 2; EIA = 0; Want = 'hardened' }
    )
    foreach ($c in $anCases) {
        $got = Test-AnonymousVerdict -RestrictAnonymous $c.RA -EveryoneIncludesAnonymous $c.EIA
        $results += &$mk "anon-verdict: RA=$($c.RA) EIA=$($c.EIA)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }
    $clCases = @(
        @{ C = -1; Want = 'review' },
        @{ C = 10; Want = 'review' },
        @{ C = 4;  Want = 'clean' },
        @{ C = 0;  Want = 'clean' },
        @{ C = 2;  Want = 'clean' }
    )
    foreach ($c in $clCases) {
        $got = Test-CachedLogonsVerdict -Count $c.C
        $results += &$mk "cachedlogons-verdict: C=$($c.C)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }
    $slCases = @(
        @{ T = -1;   S = '1';   Want = 'clean' },
        @{ T = 300;  S = '1';   Want = 'clean' },
        @{ T = 1800; S = '1';   Want = 'long-timeout' },
        @{ T = -1;   S = '0';   Want = 'no-lock' },
        @{ T = 60;   S = $null; Want = 'clean' }
    )
    foreach ($c in $slCases) {
        $got = Test-ScreenLockVerdict -TimeoutSec $c.T -IsSecure $c.S
        $results += &$mk "screenlock-verdict: T=$($c.T) S=$($c.S)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }
    $deCases = @(
        @{ P = 'C:\';                      Want = 'root' },
        @{ P = 'C:';                       Want = 'root' },
        @{ P = 'C:\Windows';               Want = 'system' },
        @{ P = 'C:\Program Files\App';     Want = 'system' },
        @{ P = 'C:\Windows\System32\drivers'; Want = 'system' },
        @{ P = 'D:\Downloads';             Want = 'review' },
        @{ P = '';                         Want = 'clean' }
    )
    foreach ($c in $deCases) {
        $got = Test-DefenderExclusionRisk -Path $c.P
        $results += &$mk "defexcl-risk: '$($c.P)'" ($got -eq $c.Want) "want $($c.Want), got $got"
    }
    $pgCases = @(
        @{ G = 'Backup Operators';        C = 1; Want = 'dangerous' },
        @{ G = 'Hyper-V Administrators';  C = 1; Want = 'dangerous' },
        @{ G = 'Backup Operators';        C = 0; Want = 'clean' },
        @{ G = 'Remote Desktop Users';    C = 5; Want = 'review' },
        @{ G = 'Remote Desktop Users';    C = 2; Want = 'clean' },
        @{ G = 'Remote Management Users'; C = 1; Want = 'review' },
        @{ G = 'DCOM Users';              C = 0; Want = 'clean' },
        @{ G = 'Some Other Group';        C = 1; Want = 'unknown' }
    )
    foreach ($c in $pgCases) {
        $got = Test-PrivilegedGroupVerdict -Group $c.G -Count $c.C
        $results += &$mk "privgroup-verdict: $($c.G)/$($c.C)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }
    # BitLocker status verdicts (Test-BitLockerStatusVerdict). The v1.3
    # false-positive lived here: the 'NOT encrypted' finding was emitted
    # inside the FullyEncrypted branch. The classifier must return exactly
    # one verdict — the live function switches on it.
    $blCases = @(
        @{ S = 'FullyEncrypted';     R = $true;  Want = 'encrypted-ok';   Note = 'encrypted + recovery protector' },
        @{ S = 'FullyEncrypted';     R = $false; Want = 'no-recovery';    Note = 'encrypted but brick risk' },
        @{ S = 'FullyDecrypted';     R = $false; Want = 'not-encrypted';  Note = 'unprotected disk' },
        @{ S = 'EncryptionInProgress'; R = $false; Want = 'not-encrypted'; Note = 'incomplete is unprotected' },
        @{ S = 'DecryptionInProgress'; R = $false; Want = 'not-encrypted'; Note = 'decrypting is unprotected' },
        @{ S = '';                   R = $false; Want = 'unreadable';     Note = 'empty status' }
    )
    foreach ($c in $blCases) {
        $got = Test-BitLockerStatusVerdict -VolumeStatus $c.S -HasRecovery $c.R
        $results += &$mk "bitlocker-verdict: $($c.Note)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }
    # Defender exclusion channels (Test-DefenderChannelExclusionRisk).
    # v1.3 never read extension/process/IP exclusions at all.
    $dcCases = @(
        @{ Ch = 'extension'; V = '.exe';            Want = 'dangerous'; Note = 'exe extension exclusion' },
        @{ Ch = 'extension'; V = 'ps1';             Want = 'dangerous'; Note = 'no leading dot, case-proof' },
        @{ Ch = 'extension'; V = '.PS1';            Want = 'dangerous'; Note = 'uppercase extension' },
        @{ Ch = 'extension'; V = '.tmp';            Want = 'review';    Note = 'benign extension still a hole' },
        @{ Ch = 'extension'; V = '';                Want = 'clean';     Note = 'empty value' },
        @{ Ch = 'process';   V = 'powershell.exe';  Want = 'high';      Note = 'LOLBin process exclusion' },
        @{ Ch = 'process';   V = 'POWERSHELL.EXE';  Want = 'high';      Note = 'case-proof LOLBin match' },
        @{ Ch = 'process';   V = 'myapp.exe';       Want = 'review';    Note = 'unknown process exclusion' },
        @{ Ch = 'process';   V = 'C:\\Tools\\app.exe'; Want = 'review'; Note = 'path-valued process exclusion' },
        @{ Ch = 'ip';        V = '10.0.0.5';        Want = 'review';    Note = 'IP exclusion' },
        @{ Ch = 'ip';        V = '';                Want = 'clean';     Note = 'empty value' },
        @{ Ch = 'bogus';     V = 'x';               Want = 'review';    Note = 'unknown channel never guesses clean' }
    )
    foreach ($c in $dcCases) {
        $got = Test-DefenderChannelExclusionRisk -Channel $c.Ch -Value $c.V
        $results += &$mk "defchan-risk: $($c.Note)" ($got -eq $c.Want) "want $($c.Want), got $got"
    }
    # Extension + LOLBin tables: unique, non-empty, sane entries.
    $hxExts = Get-DefenderHighRiskExtensionTable
    $dupExt = @($hxExts | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    $results += &$mk 'defchan-table: extensions unique' ($dupExt.Count -eq 0) "dups: $($dupExt -join ',')"
    $results += &$mk 'defchan-table: extensions non-empty' ($hxExts.Count -ge 10) "count: $($hxExts.Count)"
    $badExt = @($hxExts | Where-Object { $_ -match '\.' -or $_ -ne $_.ToLower() })
    $results += &$mk 'defchan-table: extensions bare lowercase, no dots' ($badExt.Count -eq 0) "bad: $($badExt -join ',')"
    $hxLol = Get-DefenderLolBinProcessTable
    $dupLol = @($hxLol | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    $results += &$mk 'defchan-table: lolbin unique' ($dupLol.Count -eq 0) "dups: $($dupLol -join ',')"
    $badLol = @($hxLol | Where-Object { $_ -notmatch '\.exe$' })
    $results += &$mk 'defchan-table: lolbin all .exe names' ($badLol.Count -eq 0) "bad: $($badLol -join ',')"

    # Report
    $failed = @($results | Where-Object { -not $_.Pass })
    foreach ($r in $results) {
        $tag = if ($r.Pass) { 'PASS' } else { 'FAIL' }
        $col = if ($r.Pass) { 'DarkGreen' } else { 'Red' }
        Write-Host ("  [{0}] {1} — {2}" -f $tag, $r.Check, $r.Detail) -ForegroundColor $col
    }
    Write-Host ("[+] Vuln-check hygiene: {0}/{1} passed" -f ($results.Count - $failed.Count), $results.Count) -ForegroundColor $(if ($failed.Count -eq 0) { 'Green' } else { 'Red' })
    return ($failed.Count -eq 0)
}

# ---------------------------------------------------------------------------
# Report assembly + export
# ---------------------------------------------------------------------------

function New-VulnReport {
    [CmdletBinding()]
    param([string]$NetScanReportPath = '')
    Write-Host '=== Sentinel Vulnerability Audit ===' -ForegroundColor Green
    $all = @()
    $all += Get-WindowsUpdateStatus
    $all += Test-WindowsUpdateService
    $all += Test-WeakConfigs
    $all += Test-FirewallProfiles
    $all += Test-AutoRun
    $all += Test-PowerShellV2
    $all += Test-SmbSigning
    $all += Test-UnquotedServicePaths
    $all += Test-GuestAccounts
    $all += Test-LocalPasswordPolicy
    $all += Test-OpenWifi
    $all += Get-SecureBootStatus
    $all += Test-BitLocker
    $all += Test-TlsProtocols
    $all += Test-AdminShares
    $all += Test-RemoteRegistry
    $all += Test-WinRMEncryption
    $all += Test-SmbServerSigning
    $all += Test-AlwaysInstallElevated
    $all += Test-LsaProtection
    $all += Get-CredentialGuardStatus
    $all += Test-RdpNla
    $all += Get-DefenderTamperStatus
    $all += Test-AsrRules
    $all += Test-SystemExploitProtection
    $all += Test-ByovdDrivers
    $all += Test-LocalAdminCensus
    $all += Test-LocalPasswordRisk
    $all += Get-TpmStatus
    $all += Test-AutoLogon
    $all += Test-WDigest
    $all += Test-RemoteUacBypass
    $all += Test-AnonymousEnumeration
    $all += Test-CachedLogonsCount
    $all += Test-ScreenLock
    $all += Test-DefenderExclusions
    $all += Test-PrivilegedGroupCensus
    $all += Get-ExposedLocalServices
    $all += Get-ExposedUdpServices
    $all += Test-RemoteAccessTools
    if ($NetScanReportPath -ne '') { $all += Import-NetScanReport -Path $NetScanReportPath }
    $all += Test-SoftwareEol

    $summary = @{
        Critical = @($all | Where-Object { $_.Severity -eq 'Critical' }).Count
        High     = @($all | Where-Object { $_.Severity -eq 'High' }).Count
        Medium   = @($all | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low      = @($all | Where-Object { $_.Severity -eq 'Low' }).Count
        Info     = @($all | Where-Object { $_.Severity -eq 'Info' }).Count
    }
    Write-Host ("[+] Findings: Critical={0} High={1} Medium={2} Low={3} Info={4}" -f `
        $summary.Critical, $summary.High, $summary.Medium, $summary.Low, $summary.Info) -ForegroundColor Yellow
    return [pscustomobject]@{ Summary = $summary; Findings = $all; Host = $env:COMPUTERNAME }
}

function Export-VulnReport {
    param(
        [Parameter(Mandatory = $true)]$Report,
        [string]$OutDir = "$env:USERPROFILE\Sentinel\reports"
    )
    try {
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $jsonPath = Join-Path $OutDir "vulncheck-$stamp.json"
        $txtPath  = Join-Path $OutDir "vulncheck-$stamp.txt"
        $Report | ConvertTo-Json -Depth 6 | Set-Content $jsonPath -Encoding UTF8
        $lines = @()
        $lines += "Sentinel Vulnerability Audit — $($Report.Host) — $stamp"
        $s = $Report.Summary
        $lines += "Summary: Critical=$($s.Critical) High=$($s.High) Medium=$($s.Medium) Low=$($s.Low) Info=$($s.Info)"
        $lines += ''
        foreach ($f in $Report.Findings) {
            $lines += "[$($f.Severity)] $($f.Category): $($f.Title)"
            $lines += "  Evidence: $($f.Evidence)"
            $lines += "  Fix: $($f.FixGuidance)"
            if ($f.FixCommand) { $lines += "  Command: $($f.FixCommand)" }
            $lines += ''
        }
        $lines | Set-Content $txtPath -Encoding UTF8
        $hash = (Get-FileHash $jsonPath -Algorithm SHA256).Hash
        Write-Host "[+] Report: $jsonPath" -ForegroundColor Green
        Write-Host "[+] Report: $txtPath"
        Write-Host "[+] SHA-256: $hash"

        # Vault log if the vault module sits alongside
        try {
            $vault = Join-Path (Split-Path $PSScriptRoot -Parent) '12-timeline-vault\Sentinel-Vault.ps1'
            if (Test-Path $vault) {
                . $vault
                if (Get-Command Add-VaultEntry -ErrorAction SilentlyContinue) {
                    Add-VaultEntry -Category 'vulncheck' -Summary "Vuln audit ${stamp}: C=$($s.Critical) H=$($s.High) M=$($s.Medium)" -DataHash $hash | Out-Null
                    Write-Host '[+] Vault-logged.' -ForegroundColor Green
                }
            }
        } catch { Write-Host "[-] Vault log skipped: $($_.Exception.Message)" -ForegroundColor Yellow }

        return $jsonPath
    } catch {
        Write-Host "[-] Export failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# ---------------------------------------------------------------------------
# Entry point (runs only when executed directly, not when dot-sourced)
# ---------------------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {
    $report = New-VulnReport -NetScanReportPath $NetScanReportPath
    foreach ($f in ($report.Findings | Where-Object { $_.Severity -in 'Critical','High' })) {
        Write-Host "[$($f.Severity)] $($f.Title)" -ForegroundColor Red
        Write-Host "    Fix: $($f.FixGuidance)" -ForegroundColor Gray
    }
    if ($ExportReport) { Export-VulnReport -Report $report -OutDir $ReportOutDir | Out-Null }
}
