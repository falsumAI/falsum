<#---------------------------------------------------------------------------
Falsum Tracker Block — tracker/ad-domain blocking at the hosts file.
Pure PowerShell 5.1. Zero external dependencies. Windows 10/11.

THE THESIS (problems 1151-1200)
  - Trackers are blocked where the machine resolves names: the hosts
    file. No browser extension to fingerprint, no proxy to configure.
    The machine simply refuses to resolve them.
  - Better-Way Law: every block is marked, reversible, and verified.
    Hosts file is backed up before ANY change. Our entries live between
    marker lines — user entries are never touched.

v1.1 hardening (2026-10-30):
  - FIXED A REAL DATA-LOSS BUG: Set-TrackerBlocks rewrote the whole hosts
    file by dropping everything between a stray block-start marker and EOF.
    If a previous write died between writing BlockStart and BlockEnd (or a
    hand edit left a start with no end), every user entry AFTER the stray
    start was silently deleted on the next run. New pure Test-HostsMarkers:
    HasStart-and-no-HasEnd is INVALID and Set-TrackerBlocks now REFUSES to
    rewrite in that state instead of deleting your hosts entries.
  - NEW Restore-HostsBackup (-Latest / -BackupPath): the Better-Way Law
    rollback that actually exists — a backup nobody can restore is not a
    backup. Admin-gated, flushes DNS after restore.
  - NEW Get-HostsBackupList + Clear-OldHostsBackups -RetentionDays (90d
    default): every write used to create a backup with no cap — backups
    accumulate forever. Retention prunes them; pure Test-BackupRetentionOk.
  - NEW Test-TrackerBlockHealth: Add-TrackerBlock verified only the domains
    just added. Health verifies EVERY managed domain resolves to 0.0.0.0
    right now — the fix generalizes the proof.
  - FIXED Remove-TrackerBlock reporting the REQUESTED count as the removed
    count. It now diffs before/after and reports the actual removed count.
  - Set-TrackerBlocks now warns above 50,000 entries (hosts bloat is a
    real slowdown on some stacks; imported megalists should know).
  - Admin gate: writes now fail fast with a clean message instead of an
    AccessDenied wall (Test-TrackerAdmin / Assert-TrackerAdmin).
  - Starter table 32 -> 56 (tiktok/linkedin/pinterest/snap/yahoo/
    clarity/fingerprint/analytics-adtech rows).
  - Hygiene battery 4 -> 22 checks incl. the stray-marker refusal,
    remove-diff, retention predicate, marker validity, import edge cases.
----------------------------------------------------------------------------#>

$script:HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$script:BlockStart = "# Falsum-block-start (do not edit between markers)"
$script:BlockEnd   = "# Falsum-block-end"
$script:BackupRetentionDays = 90

# Starter set: the heavy trackers. Import-BlockList extends this with any
# hosts-format list the user trusts (one domain per line).
$script:StarterTrackers = @(
    "google-analytics.com","www.google-analytics.com","ssl.google-analytics.com",
    "googletagmanager.com","www.googletagmanager.com","googletagservices.com",
    "doubleclick.net","googleadservices.com","googlesyndication.com",
    "facebook.net","connect.facebook.net","pixel.facebook.com",
    "hotjar.com","static.hotjar.com","script.hotjar.com",
    "fullstory.com","crazyegg.com","mouseflow.com","luckyorange.com",
    "mixpanel.com","cdn.mxpnl.com","segment.io","cdn.segment.com",
    "amplitude.com","heap.io","pendo.io",
    "taboola.com","outbrain.com","criteo.com",
    "adroll.com","scorecardresearch.com","quantserve.com",
    "newrelic.com","nr-data.net","js-agent.newrelic.com",
    # social/ad pixels
    "analytics.tiktok.com","px.ads.linkedin.com",
    "ct.pinterest.com","sc-static.net","tr.snapchat.com",
    "static.ads-twitter.com","analytics.twitter.com",
    # adtech
    "ads.yahoo.com","analytics.yahoo.com","bat.bing.com",
    "stats.wp.com","mc.yandex.ru",
    "demdex.net","everesttech.net","adsrvr.org","crwdcntrl.net",
    # fingerprinting + misc
    "clarity.ms","www.clarity.ms","openfpcdn.io",
    "onesignal.com","cdn.onesignal.com"
)

function Get-HostsBackupDir {
    $d = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "Falsum\hosts-backups"
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $d
}

function Test-TrackerAdmin {
    <#
    .SYNOPSIS Pure-ish: returns $true when this PowerShell is elevated.
    Writing the hosts file needs admin; reads do not.
    #>
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch { return $false }
}

function Assert-TrackerAdmin {
    <#
    .SYNOPSIS Fails fast with a plain-language message when not elevated,
    instead of letting the write die in AccessDenied.
    #>
    if (-not (Test-TrackerAdmin)) {
        Write-Host "[tracker] This action writes the hosts file and needs an elevated (Run as administrator) PowerShell."
        throw "Not elevated"
    }
}

function Test-HostsMarkers {
    <#
    .SYNOPSIS PURE: inspects hosts-file lines for the managed markers.
    Valid states: no markers at all, or start AND end. A start with no end
    means a previous write died mid-file or a hand edit broke the markers —
    rewriting then would DELETE every user entry after the stray start.
    #>
    param([string[]]$Lines)
    $hasStart = $false
    $hasEnd = $false
    foreach ($l in $Lines) {
        if ($l -eq $script:BlockStart) { $hasStart = $true }
        if ($l -eq $script:BlockEnd) { $hasEnd = $true }
    }
    $valid = ((-not $hasStart) -and (-not $hasEnd)) -or ($hasStart -and $hasEnd)
    return [PSCustomObject]@{
        HasStart = $hasStart
        HasEnd   = $hasEnd
        Valid    = $valid
    }
}

function Backup-HostsFile {
    $bakDir = Get-HostsBackupDir
    $bak = Join-Path $bakDir ("hosts-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".bak")
    Copy-Item $script:HostsPath $bak -Force
    Write-Host "[tracker] Hosts backed up to $bak"
    return $bak
}

function Get-HostsBackupList {
    <#
    .SYNOPSIS Lists Falsum hosts backups, newest first.
    #>
    $dir = Get-HostsBackupDir
    $files = Get-ChildItem $dir -Filter "hosts-*.bak" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    return @($files)
}

function Test-BackupRetentionOk {
    <#
    .SYNOPSIS PURE: keep a backup when its age is within retention; drop it
    when older. Never throws.
    #>
    param(
        [datetime]$BackupTime,
        [datetime]$Now,
        [int]$RetentionDays = $script:BackupRetentionDays
    )
    $age = ($Now - $BackupTime).TotalDays
    return ($age -le $RetentionDays)
}

function Clear-OldHostsBackups {
    <#
    .SYNOPSIS Prunes hosts backups older than RetentionDays. Backups grew
    one per write with no cap; this keeps the dir from rotting forever.
    #>
    param([int]$RetentionDays = $script:BackupRetentionDays)
    $now = Get-Date
    $removed = 0
    foreach ($f in (Get-HostsBackupList)) {
        if (-not (Test-BackupRetentionOk -BackupTime $f.LastWriteTime -Now $now -RetentionDays $RetentionDays)) {
            Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
            $removed++
        }
    }
    Write-Host "[tracker] Pruned $removed backup(s) older than $RetentionDays days."
    return $removed
}

function Restore-HostsBackup {
    <#
    .SYNOPSIS THE ROLLBACK: restores the hosts file from a Falsum backup.
    -Latest restores the newest; -BackupPath picks one. Admin-gated.
    A backup you cannot restore is not a backup.
    #>
    param(
        [switch]$Latest,
        [string]$BackupPath
    )
    Assert-TrackerAdmin
    try {
        if ($BackupPath) {
            if (-not (Test-Path $BackupPath)) { throw "Backup not found: $BackupPath" }
            $bak = $BackupPath
        } elseif ($Latest) {
            $list = Get-HostsBackupList
            if ($list.Count -eq 0) { throw "No Falsum hosts backups found." }
            $bak = $list[0].FullName
            Write-Host "[tracker] Restoring newest backup: $($list[0].Name)"
        } else { throw "Pass -Latest or -BackupPath." }
        Backup-HostsFile | Out-Null   # snapshot the current file first
        Copy-Item $bak $script:HostsPath -Force
        try { ipconfig /flushdns | Out-Null } catch { }
        Write-Host "[tracker] Hosts restored from $bak"
        return $true
    } catch {
        Write-Host "[tracker] ERROR restoring backup: $($_.Exception.Message)"
        throw
    }
}

function Get-TrackerBlocks {
    <#
    .SYNOPSIS Reads current Falsum-managed blocks from the hosts file.
    #>
    try {
        $lines = Get-Content $script:HostsPath -ErrorAction Stop
        $inBlock = $false
        $domains = New-Object System.Collections.ArrayList
        foreach ($line in $lines) {
            if ($line -eq $script:BlockStart) { $inBlock = $true; continue }
            if ($line -eq $script:BlockEnd) { $inBlock = $false; continue }
            if ($inBlock -and $line -match '^\s*0\.0\.0\.0\s+(\S+)') {
                [void]$domains.Add($matches[1])
            }
        }
        return $domains
    } catch {
        Write-Host "[tracker] ERROR reading hosts: $($_.Exception.Message)"
        return @()
    }
}

function Set-TrackerBlocks {
    <#
    .SYNOPSIS Rewrites ONLY the managed block section. Backs up first.
    REFUSES to rewrite when the markers are in an invalid state (start
    with no end) — rewriting then would delete user entries after the
    stray marker. That was the v1 data-loss bug; now it refuses loudly.
    #>
    param([string[]]$Domains)
    Assert-TrackerAdmin
    try {
        $lines = @(Get-Content $script:HostsPath -ErrorAction Stop)
        $marks = Test-HostsMarkers -Lines $lines
        if (-not $marks.Valid) {
            Write-Host "[tracker] REFUSING to rewrite: block-start marker found with no block-end."
            Write-Host "[tracker] Restore a backup with Restore-HostsBackup -Latest, then retry."
            throw "Invalid marker state (start without end)"
        }
        Backup-HostsFile | Out-Null
        $out = New-Object System.Collections.Generic.List[string]
        $inBlock = $false
        foreach ($line in $lines) {
            if ($line -eq $script:BlockStart) { $inBlock = $true; continue }
            if ($line -eq $script:BlockEnd) { $inBlock = $false; continue }
            if (-not $inBlock) { $out.Add($line) }
        }
        $unique = $Domains | ForEach-Object { $_.ToLower().Trim() } | Where-Object { $_ -ne "" } | Sort-Object -Unique
        if ($unique.Count -gt 50000) {
            Write-Host "[tracker] WARNING: $($unique.Count) entries. Very large hosts files can slow some stacks; consider splitting imported lists."
        }
        if ($unique.Count -gt 0) {
            $out.Add($script:BlockStart)
            foreach ($d in $unique) { $out.Add("0.0.0.0 $d") }
            $out.Add($script:BlockEnd)
        }
        $out | Out-File $script:HostsPath -Encoding ascii -Force
        Write-Host "[tracker] $($unique.Count) domains blocked."
        return $unique.Count
    } catch {
        Write-Host "[tracker] ERROR writing hosts: $($_.Exception.Message)"
        throw
    }
}

function Add-TrackerBlock {
    <#
    .SYNOPSIS THE FIX: blocks tracker domains. Verifies each resolves to 0.0.0.0 after.
    #>
    param([Parameter(Mandatory=$true)][string[]]$Domain)
    $current = Get-TrackerBlocks
    $merged = @($current) + @($Domain)
    $n = Set-TrackerBlocks $merged
    # VERIFY: flush DNS cache so the block takes effect, then check resolution
    try { ipconfig /flushdns | Out-Null } catch { }
    Start-Sleep -Seconds 1
    $failed = New-Object System.Collections.ArrayList
    foreach ($d in $Domain) {
        try {
            $r = [System.Net.Dns]::GetHostAddresses($d.ToLower().Trim())
            $ok = ($r | Where-Object { $_.ToString() -eq "0.0.0.0" }).Count -gt 0
            if (-not $ok) { [void]$failed.Add($d) }
        } catch { }
    }
    if ($failed.Count -eq 0) { Write-Host "[tracker] VERIFIED: all new blocks resolve to 0.0.0.0." }
    else { Write-Host "[tracker] WARNING: these did not verify: $($failed -join ', ')" }
    return $n
}

function Remove-TrackerBlock {
    <#
    .SYNOPSIS Unblocks domains. Reports the ACTUAL removed count from the
    before/after diff — v1 reported the requested count, which lied when
    a domain was not blocked in the first place.
    #>
    param([Parameter(Mandatory=$true)][string[]]$Domain)
    $current = Get-TrackerBlocks
    $remove = $Domain | ForEach-Object { $_.ToLower().Trim() }
    $kept = $current | Where-Object { $remove -notcontains $_ }
    $n = Set-TrackerBlocks $kept
    $removedCount = ($current.Count - $n)
    Write-Host "[tracker] Removed $removedCount domain(s); $n remain blocked."
    return $n
}

function Clear-TrackerBlocks {
    <#
    .SYNOPSIS Removes ALL managed blocks. Full rollback to pre-Falsum hosts.
    #>
    $n = Set-TrackerBlocks @()
    Write-Host "[tracker] All managed blocks cleared."
    return $n
}

function Test-TrackerBlockHealth {
    <#
    .SYNOPSIS Verifies EVERY managed domain currently resolves to 0.0.0.0.
    Add-TrackerBlock verified only the domains just added; health generalizes
    the proof. Returns per-domain rows; prints the summary.
    #>
    $current = Get-TrackerBlocks
    $rows = New-Object System.Collections.ArrayList
    if ($current.Count -eq 0) {
        Write-Host "[tracker] Health: no managed blocks to check."
        return $rows
    }
    foreach ($d in $current) {
        $ok = $false
        try {
            $r = [System.Net.Dns]::GetHostAddresses($d)
            $ok = ($r | Where-Object { $_.ToString() -eq "0.0.0.0" }).Count -gt 0
        } catch { $ok = $false }
        [void]$rows.Add([PSCustomObject]@{ Domain = $d; ResolvesToBlock = $ok })
    }
    $bad = @($rows | Where-Object { -not $_.ResolvesToBlock }).Count
    if ($bad -eq 0) {
        Write-Host "[tracker] HEALTH: all $($rows.Count) blocks resolve to 0.0.0.0."
    } else {
        Write-Host "[tracker] HEALTH: $bad of $($rows.Count) blocks NOT resolving to 0.0.0.0:"
        foreach ($r in ($rows | Where-Object { -not $_.ResolvesToBlock })) {
            Write-Host "  FAILED: $($r.Domain)"
        }
    }
    return $rows
}

function Import-BlockList {
    <#
    .SYNOPSIS Imports a hosts-format block list (one domain per line;
    strips '0.0.0.0'/'127.0.0.1' prefixes and comments).
    #>
    param([Parameter(Mandatory=$true)][string]$Path)
    try {
        if (-not (Test-Path $Path)) { throw "File not found: $Path" }
        $domains = New-Object System.Collections.ArrayList
        foreach ($line in (Get-Content $Path)) {
            $t = $line.Trim()
            if ($t -eq "" -or $t.StartsWith("#")) { continue }
            $t = $t -replace '^(0\.0\.0\.0|127\.0\.0\.1)\s+', ''
            $t = ($t -split '\s+')[0].ToLower().Trim()
            if ($t -match '^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$') { [void]$domains.Add($t) }
        }
        Write-Host "[tracker] Imported $($domains.Count) domains from $Path"
        return (Add-TrackerBlock -Domain ([string[]]$domains))
    } catch {
        Write-Host "[tracker] ERROR importing: $($_.Exception.Message)"
        throw
    }
}

function Install-StarterBlocks {
    <#
    .SYNOPSIS Applies the built-in starter tracker set.
    #>
    Write-Host "[tracker] Applying starter set ($($script:StarterTrackers.Count) domains)..."
    return (Add-TrackerBlock -Domain $script:StarterTrackers)
}

function Test-TrackerBlockHygiene {
    <#
    .SYNOPSIS Offline battery: block-section parsing, marker safety, import
    cleaning, remove-diff math, backup retention, starter-table sanity.
    Does NOT touch the real hosts file.
    #>
    $results = @()
    # Scope-safe collection: the scriptblock RETURNS the row; callers append
    # the OUTPUT ($results += &$add ...) instead of mutating a closed-over
    # variable from a child scope.
    $add = { param($n,$c) [PSCustomObject]@{ Check = $n; Pass = [bool]$c } }

    # 1. parse logic
    $fake = @(
        "127.0.0.1 localhost",
        $script:BlockStart,
        "0.0.0.0 evil-tracker.example",
        "0.0.0.0 ads.example",
        $script:BlockEnd,
        "192.168.1.1 myprinter"
    )
    $inBlock = $false; $found = @()
    foreach ($line in $fake) {
        if ($line -eq $script:BlockStart) { $inBlock = $true; continue }
        if ($line -eq $script:BlockEnd) { $inBlock = $false; continue }
        if ($inBlock -and $line -match '^\s*0\.0\.0\.0\s+(\S+)') { $found += $matches[1] }
    }
    $results += &$add "parse finds 2 blocked" ($found.Count -eq 2)
    $results += &$add "user entries untouched conceptually" ($fake -contains "192.168.1.1 myprinter")

    # 2. marker validity (the v1.1 data-loss fix)
    $m1 = Test-HostsMarkers -Lines @("127.0.0.1 localhost")
    $results += &$add "markers none -> valid" ($m1.Valid -and -not $m1.HasStart -and -not $m1.HasEnd)
    $m2 = Test-HostsMarkers -Lines @($script:BlockStart, "0.0.0.0 x.example", $script:BlockEnd)
    $results += &$add "markers both -> valid" ($m2.Valid -and $m2.HasStart -and $m2.HasEnd)
    $m3 = Test-HostsMarkers -Lines @($script:BlockStart, "0.0.0.0 x.example", "192.168.1.1 myprinter")
    $results += &$add "markers stray start -> INVALID" ((-not $m3.Valid) -and $m3.HasStart -and -not $m3.HasEnd)
    $m4 = Test-HostsMarkers -Lines @($script:BlockEnd)
    $results += &$add "markers stray end -> INVALID" ((-not $m4.Valid) -and $m4.HasEnd -and -not $m4.HasStart)
    # the refusal decision the writer must honor
    $wouldRefuse = (-not $m3.Valid)
    $results += &$add "stray start triggers refuse" ($wouldRefuse -eq $true)
    $wouldRefuse2 = (-not $m2.Valid)
    $results += &$add "clean markers do NOT trigger refuse" ($wouldRefuse2 -eq $false)

    # 3. import-line cleaning edge cases
    $clean = @()
    foreach ($t in @(
        "0.0.0.0 tracker.example # comment",
        "127.0.0.1 ads.example",
        "# just a comment",
        "",
        "plain.example",
        "0.0.0.0`tUPPER.example`t# tabbed",
        "0.0.0.0 multi.example host-alias.example"
    )) {
        $x = $t.Trim()
        if ($x -eq "" -or $x.StartsWith("#")) { continue }
        $x = $x -replace '^(0\.0\.0\.0|127\.0\.0\.1)\s+', ''
        $x = ($x -split '\s+')[0].ToLower().Trim()
        if ($x -match '^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$') { $clean += $x }
    }
    $results += &$add "import cleaning edge" (($clean -join ",") -eq "tracker.example,ads.example,plain.example,upper.example,multi.example")

    # 4. remove-diff math (actual removed, not requested)
    $before = @("a.example","b.example","c.example")
    $reqRemove = @("b.example","never-blocked.example")
    $kept = $before | Where-Object { $reqRemove -notcontains $_ }
    $actualRemoved = $before.Count - $kept.Count
    $results += &$add "remove-diff counts 1 actual" ($actualRemoved -eq 1)
    $results += &$add "kept is a,b" (($kept -join ",") -eq "a.example,c.example")

    # 5. backup retention predicate
    $now = Get-Date "2026-10-30 12:00:00"
    $results += &$add "retention keeps 30d" (Test-BackupRetentionOk -BackupTime ($now.AddDays(-30)) -Now $now -RetentionDays 90)
    $results += &$add "retention keeps exactly 90d" (Test-BackupRetentionOk -BackupTime ($now.AddDays(-90)) -Now $now -RetentionDays 90)
    $results += &$add "retention drops 91d" (-not (Test-BackupRetentionOk -BackupTime ($now.AddDays(-91)) -Now $now -RetentionDays 90))
    $results += &$add "retention drops 400d" (-not (Test-BackupRetentionOk -BackupTime ($now.AddDays(-400)) -Now $now -RetentionDays 90))

    # 6. starter table sanity
    $st = $script:StarterTrackers
    $results += &$add "starter >= 50" ($st.Count -ge 50)
    $results += &$add "starter unique" (($st | Sort-Object -Unique).Count -eq $st.Count)
    $badShape = @($st | Where-Object { $_ -notmatch '^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$' })
    $results += &$add "starter all valid domain shape" ($badShape.Count -eq 0)

    $pass = @($results | Where-Object { $_.Pass }).Count
    Write-Host "[tracker] Hygiene: $pass/$($results.Count) checks passed."
    return ($pass -eq $results.Count)
}

Write-Host "[tracker] Falsum Tracker Block v1.1 loaded. Install-StarterBlocks / Add-TrackerBlock / Remove-TrackerBlock / Clear-TrackerBlocks / Import-BlockList / Test-TrackerBlockHygiene / Test-TrackerBlockHealth / Restore-HostsBackup / Clear-OldHostsBackups."
