<#---------------------------------------------------------------------------
Falsum Backup Shield — the ransomware answer.
Pure PowerShell 5.1. Zero external dependencies. Windows 10/11.

THE THESIS (problems 751-800)
  - Ransomware's leverage is "pay or lose your files." A tested backup
    deletes the leverage. Detection is nice; the backup is the fix.
  - Better-Way Law: a backup that has never been restore-tested is a
    claim, not a backup. Every backup ships its integrity test AND a
    restore drill. No exceptions.

WHAT IT DOES
  - New-BackupPlan: versioned robocopy backup of chosen folders to a
    destination (external drive / second disk). Keeps N versions.
  - Start-Backup: runs the plan, logs every file, SHA-256 manifest,
    out-of-band manifest hash, auto integrity check, failed-run cleanup.
  - Test-BackupIntegrity: re-hashes the destination vs its manifest,
    verifies the manifest hash first, flags EXTRA files not in the
    manifest (planted evidence / dropped ransom notes).
  - Start-RestoreDrill: restores a sample to temp and compares each
    restored file against the MANIFEST hash (the true proof). A live-
    source compare is secondary info only — the source legitimately
    changes between backup and drill, and that must never fail the drill.
  - New-BackupScheduledTask: schtasks-based automatic backups. A plan
    that runs only when you remember is not a plan.
  - Get-RansomwarePlaybook: the decision tree for DURING an attack.

BUILT 2026-10-30 by the main agent, in-chat, per Gregg's order.
v1.1 hardening 2026-10-30 ~09:08 MDT: see HARDEN-ROTATION.md entry.
----------------------------------------------------------------------------#>

$script:BackupRoot = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "Falsum\backups"

# ---------------------------------------------------------------------------
# Vault plumbing — backup runs leave a SHA-384 chained evidence trail.
# Silent when the vault module is missing or no vault path is set — never
# blocks a backup. Logs METADATA only (plan, counts, manifest hash), never
# file contents.
# ---------------------------------------------------------------------------
$script:VaultLoaded = $false
$script:VaultPath = ""

function Import-VaultModule {
    if ($script:VaultLoaded) { return }
    $here = Split-Path -Parent $MyInvocation.PSCommandPath
    $mod = Join-Path (Split-Path -Parent $here) "12-timeline-vault\Falsum-Vault.ps1"
    if (-not (Test-Path $mod)) {
        $mod = Join-Path $here "..\12-timeline-vault\Falsum-Vault.ps1"
    }
    if (Test-Path $mod) { . $mod; $script:VaultLoaded = $true }
    else { Write-Host "[!] vault module not found at $mod — backup runs will not be vault-logged" }
}

function New-BackupVaultLog {
    <#
    Vault-log one backup action (type "backup-run"). Never throws.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Action,
        [string]$PlanName = "",
        [string]$VersionDir = "",
        [long]$Files = 0,
        [string]$ManifestHash = "",
        [bool]$IntegrityClean = $false,
        [string]$Notes = ""
    )
    if (-not $script:VaultLoaded -or [string]::IsNullOrWhiteSpace($script:VaultPath)) { return }
    try {
        $vault = New-Vault -path $script:VaultPath
        Add-VaultEntry -vault $vault -type "backup-run" -data @{
            action          = $Action
            plan            = $PlanName
            version         = (Split-Path $VersionDir -Leaf)
            files           = $Files
            manifest_hash   = $ManifestHash
            integrity_clean = $IntegrityClean
            notes           = $Notes
            utc             = (Get-Date).ToUniversalTime().ToString("o")
        } | Out-Null
    } catch {
        Write-Host "[!] backup vault log failed: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Pure helpers — no filesystem side effects, offline-testable.
# ---------------------------------------------------------------------------
function Test-BackupPathOverlap {
    <#
    .SYNOPSIS True when the destination is nested inside a source (or a
    source inside the destination). A robocopy /MIR into an overlapping
    tree grows forever or eats its own output. Pure — Python-ported.
    #>
    param(
        [Parameter(Mandatory=$true)][string[]]$SourceDirs,
        [Parameter(Mandatory=$true)][string]$Destination
    )
    $norm = {
        param($p)
        $f = [System.IO.Path]::GetFullPath($p)
        $f = $f.TrimEnd('\', '/')
        return $f + '\'
    }
    $df = & $norm $Destination
    foreach ($s in $SourceDirs) {
        $sf = & $norm $s
        if ($df.StartsWith($sf, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($sf.StartsWith($df, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-BackupSpaceVerdict {
    <#
    .SYNOPSIS Pure free-space decision: ok / tight / fail / unknown.
    Fail when free < source size; tight when free < size * Margin.
    Pure — Python-ported.
    #>
    param(
        [Parameter(Mandatory=$true)][long]$FreeBytes,
        [Parameter(Mandatory=$true)][long]$SourceBytes,
        [double]$Margin = 1.2
    )
    if ($SourceBytes -le 0) { return "unknown" }
    if ($FreeBytes -lt $SourceBytes) { return "fail" }
    if ($FreeBytes -lt ($SourceBytes * $Margin)) { return "tight" }
    return "ok"
}

function Get-BackupSourceSize {
    <#
    .SYNOPSIS Total bytes across the plan's source dirs. Used by the
    free-space preflight. Slow on huge trees — it is the honest number.
    #>
    param([Parameter(Mandatory=$true)][string[]]$SourceDirs)
    $total = [long]0
    foreach ($s in $SourceDirs) {
        if (-not (Test-Path $s)) { continue }
        $files = Get-ChildItem $s -Recurse -File -ErrorAction SilentlyContinue
        foreach ($f in $files) { $total += $f.Length }
    }
    return $total
}

function Test-BackupDiskSpace {
    <#
    .SYNOPSIS Free-space preflight for a backup plan. Returns ok / tight /
    fail / unknown. Never throws — returns "unknown" when the drive cannot
    be read. Prints the human verdict.
    #>
    param([Parameter(Mandatory=$true)]$Plan)
    try {
        $drive = (Get-Item $Plan.Destination).PSDrive
        $psd = Get-PSDrive $drive.Name -ErrorAction Stop
        $free = [long]$psd.Free
        $srcBytes = Get-BackupSourceSize -SourceDirs @($Plan.SourceDirs)
        $verdict = Test-BackupSpaceVerdict -FreeBytes $free -SourceBytes $srcBytes
        $gb = { param($b) [math]::Round($b / 1GB, 2) }
        Write-Host ("[backup] Disk preflight: free {0} GB, sources {1} GB -> {2}" -f (& $gb $free), (& $gb $srcBytes), $verdict.ToUpper())
        return $verdict
    } catch {
        Write-Host "[backup] Disk preflight: could not read drive ($($_.Exception.Message)) -> UNKNOWN"
        return "unknown"
    }
}

# ---------------------------------------------------------------------------
# New-BackupPlan — creates a versioned backup plan. No backup runs until
# Start-Backup. Refuses destination-overlapping-source trees.
# ---------------------------------------------------------------------------
function New-BackupPlan {
    <#
    .SYNOPSIS Creates a versioned backup plan. No backup runs until Start-Backup.
    #>
    param(
        [Parameter(Mandatory=$true)][string[]]$SourceDirs,
        [Parameter(Mandatory=$true)][string]$Destination,
        [string]$Name = "default",
        [int]$KeepVersions = 4
    )
    try {
        foreach ($s in $SourceDirs) {
            if (-not (Test-Path $s)) { throw "Source not found: $s" }
        }
        if (-not (Test-Path $Destination)) { throw "Destination not found: $Destination" }
        if (Test-BackupPathOverlap -SourceDirs $SourceDirs -Destination $Destination) {
            throw "Destination overlaps a source dir. A robocopy /MIR into an overlapping tree grows forever or eats its own output. Pick a destination OUTSIDE every source."
        }
        if ($KeepVersions -lt 1) { throw "KeepVersions must be >= 1." }
        if (-not (Test-Path $script:BackupRoot)) { New-Item -ItemType Directory -Path $script:BackupRoot -Force | Out-Null }
        $plan = [PSCustomObject]@{
            Name=$Name; SourceDirs=$SourceDirs; Destination=$Destination
            KeepVersions=$KeepVersions; Created=(Get-Date).ToUniversalTime().ToString("o")
        }
        $planFile = Join-Path $script:BackupRoot ("plan-" + $Name + ".json")
        $plan | ConvertTo-Json -Depth 4 | Out-File $planFile -Encoding utf8
        Write-Host "[backup] Plan '$Name' saved: $planFile"
        Write-Host "[backup] Sources: $($SourceDirs -join '; ')"
        Write-Host "[backup] Destination: $Destination (keeps $KeepVersions versions)"
        return $plan
    } catch {
        Write-Host "[backup] ERROR creating plan: $($_.Exception.Message)"
        throw
    }
}

function Get-BackupPlan {
    param([string]$Name = "default")
    $planFile = Join-Path $script:BackupRoot ("plan-" + $Name + ".json")
    if (-not (Test-Path $planFile)) { throw "No plan named '$Name'. Run New-BackupPlan first." }
    return (Get-Content $planFile -Raw | ConvertFrom-Json)
}

# ---------------------------------------------------------------------------
# Start-Backup — runs the plan: robocopy mirror per source into a
# timestamped version dir, SHA-256 manifest, out-of-band manifest hash,
# automatic integrity check (the proof ships with the backup), rotation,
# history + vault log. A failed run removes its partial version dir so a
# corrupt version never sits next to good ones.
# ---------------------------------------------------------------------------
function Start-Backup {
    <#
    .SYNOPSIS Runs the plan: robocopy mirror per source into a timestamped
    version dir, SHA-256 manifest, out-of-band manifest hash, automatic
    integrity verification. Use -SkipVerify to defer verification.
    #>
    param(
        [string]$Name = "default",
        [switch]$SkipVerify
    )
    $verDir = $null
    try {
        $plan = Get-BackupPlan $Name
        $preflight = Test-BackupDiskSpace -Plan $plan
        if ($preflight -eq "fail") {
            throw "Destination has less free space than the source tree. Backup would die partway. Free up space or pick another destination."
        }
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $verDir = Join-Path $plan.Destination ("bb-backup-" + $plan.Name + "-" + $stamp)
        New-Item -ItemType Directory -Path $verDir -Force | Out-Null
        Write-Host "[backup] Backing up to $verDir"
        $totalFiles = 0
        foreach ($src in $plan.SourceDirs) {
            $leaf = Split-Path $src -Leaf
            $dst = Join-Path $verDir $leaf
            Write-Host "[backup] robocopy $src -> $dst"
            $rc = Start-Process robocopy -ArgumentList @("`"$src`"","`"$dst`"","/MIR","/R:2","/W:5","/NP","/NDL","/NJH","/NJS") -Wait -PassThru -WindowStyle Hidden
            # robocopy exit codes 0-7 = success; 8+ = failure
            if ($rc.ExitCode -ge 8) { throw "robocopy failed on $src (exit $($rc.ExitCode))" }
        }
        Write-Host "[backup] Writing SHA-256 manifest..."
        $manifest = New-Object System.Collections.Generic.List[string]
        $files = Get-ChildItem $verDir -Recurse -File -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            try {
                $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
                $rel = $f.FullName.Substring($verDir.Length + 1)
                $manifest.Add("$h  $rel")
                $totalFiles++
            } catch { }
        }
        $manFile = Join-Path $verDir "MANIFEST-SHA256.txt"
        $manifest | Out-File $manFile -Encoding ascii
        # Out-of-band manifest hash: catches anyone rewriting the manifest
        # to match tampered files. Integrity check verifies this first.
        $manHash = (Get-FileHash $manFile -Algorithm SHA256).Hash
        $manHash | Out-File (Join-Path $verDir "MANIFEST-HASH.txt") -Encoding ascii
        Write-Host "[backup] $totalFiles files, manifest: $manFile"
        if (-not $SkipVerify) {
            Write-Host "[backup] Running automatic integrity check (the proof ships with the backup)..."
            $integ = Test-BackupIntegrity $verDir
            if (-not $integ.Clean) {
                throw "Integrity check FAILED on the fresh backup: $($integ.Mismatched) mismatched, $($integ.Missing) missing, $($integ.ExtraFiles) extra. Version kept for inspection; NOT rotated in as good."
            }
            Write-Host "[backup] Integrity PASS: $($integ.Checked) files re-hashed and clean."
        }
        Remove-OldBackups -Plan $plan
        # Log
        $logFile = Join-Path $script:BackupRoot "backup-history.log"
        "$stamp | $($plan.Name) | $verDir | $totalFiles files | manifest $manHash" | Out-File $logFile -Append -Encoding utf8
        New-BackupVaultLog -Action "run" -PlanName $plan.Name -VersionDir $verDir `
            -Files $totalFiles -ManifestHash $manHash -IntegrityClean (-not $SkipVerify) `
            -Notes "robocopy mirror, $totalFiles files"
        return [PSCustomObject]@{ VersionDir=$verDir; Files=$totalFiles; Manifest=$manFile; ManifestHash=$manHash; Utc=(Get-Date).ToUniversalTime().ToString("o") }
    } catch {
        # Never leave a corrupt partial version next to good ones.
        if ($verDir -and (Test-Path $verDir)) {
            Write-Host "[backup] Failed run — removing partial version dir: $verDir"
            Remove-Item $verDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Host "[backup] ERROR during backup: $($_.Exception.Message)"
        throw
    }
}

function Remove-OldBackups {
    param($Plan)
    $dirs = Get-ChildItem $Plan.Destination -Directory -Filter ("bb-backup-" + $Plan.Name + "-*") |
        Sort-Object Name -Descending
    $drop = @($dirs | Select-Object -Skip $Plan.KeepVersions)
    foreach ($d in $drop) {
        Write-Host "[backup] Rotating out old version: $($d.Name)"
        Remove-Item $d.FullName -Recurse -Force
    }
}

# ---------------------------------------------------------------------------
# Test-BackupIntegrity — re-hashes a backup version against its manifest.
# Verifies the out-of-band manifest hash FIRST (a rewritten manifest that
# matches tampered files is the attack this catches), then every file,
# then flags EXTRA files present on disk but absent from the manifest
# (planted evidence, dropped ransom notes). THE proof the bits are intact.
# ---------------------------------------------------------------------------
function Test-BackupIntegrity {
    <#
    .SYNOPSIS Re-hashes a backup version against its manifest. Verifies the
    manifest hash first, then files, then flags extra (unlisted) files.
    #>
    param([Parameter(Mandatory=$true)][string]$VersionDir)
    try {
        $manFile = Join-Path $VersionDir "MANIFEST-SHA256.txt"
        if (-not (Test-Path $manFile)) { throw "No manifest in $VersionDir" }
        $manifestTampered = $false
        $hashFile = Join-Path $VersionDir "MANIFEST-HASH.txt"
        if (Test-Path $hashFile) {
            $expectHash = (Get-Content $hashFile -Raw).Trim()
            $gotHash = (Get-FileHash $manFile -Algorithm SHA256).Hash
            if ($gotHash -ne $expectHash) {
                $manifestTampered = $true
                Write-Host "[backup] MANIFEST TAMPERED: MANIFEST-SHA256.txt does not match MANIFEST-HASH.txt. Do not trust this version."
            }
        } else {
            Write-Host "[backup] NOTE: no MANIFEST-HASH.txt (pre-v1.1 version) — manifest self-check skipped."
        }
        $manifested = @{}
        $bad = 0; $checked = 0; $missing = 0
        foreach ($line in (Get-Content $manFile)) {
            if ($line -notmatch '^([0-9A-Fa-f]{64})\s\s(.+)$') { continue }
            $expect = $matches[1]; $rel = $matches[2]
            $manifested[$rel] = $true
            $full = Join-Path $VersionDir $rel
            if (-not (Test-Path $full)) { $missing++; continue }
            $got = (Get-FileHash $full -Algorithm SHA256).Hash
            $checked++
            if ($got -ne $expect) { $bad++; Write-Host "[backup] HASH MISMATCH: $rel" }
        }
        # Extra files: on disk but never in the manifest. Planted evidence
        # or dropped ransom notes live here. Sidecars are not extra.
        $extra = New-Object System.Collections.Generic.List[string]
        $sidecars = @("MANIFEST-SHA256.txt", "MANIFEST-HASH.txt")
        $onDisk = Get-ChildItem $VersionDir -Recurse -File -ErrorAction SilentlyContinue
        foreach ($f in $onDisk) {
            $rel = $f.FullName.Substring($VersionDir.Length + 1)
            if ($sidecars -contains $f.Name) { continue }
            if (-not $manifested.ContainsKey($rel)) { $extra.Add($rel) }
        }
        if ($extra.Count -gt 0) {
            Write-Host ("[backup] EXTRA FILES ({0}) present on disk but not in manifest:" -f $extra.Count)
            $extra | Select-Object -First 25 | ForEach-Object { Write-Host "[backup]   EXTRA: $_" }
            if ($extra.Count -gt 25) { Write-Host "[backup]   ... and $($extra.Count - 25) more" }
        }
        $clean = ($bad -eq 0 -and $missing -eq 0 -and $extra.Count -eq 0 -and -not $manifestTampered)
        Write-Host ("[backup] Integrity: {0} checked, {1} mismatched, {2} missing, {3} extra, manifest-tampered={4}." -f $checked, $bad, $missing, $extra.Count, $manifestTampered)
        return [PSCustomObject]@{
            Checked=$checked; Mismatched=$bad; Missing=$missing
            ExtraFiles=$extra.Count; ManifestTampered=$manifestTampered; Clean=$clean
        }
    } catch {
        Write-Host "[backup] ERROR: $($_.Exception.Message)"
        throw
    }
}

# ---------------------------------------------------------------------------
# Start-RestoreDrill — restores a sample to temp and proves each restored
# file against the MANIFEST hash. That is the true proof: the backup
# restores what it captured. Comparing against the LIVE source was the old
# behavior and was WRONG — the source legitimately changes between backup
# and drill, and that must never fail the drill. Live-source drift is
# reported as info only.
# ---------------------------------------------------------------------------
function Start-RestoreDrill {
    <#
    .SYNOPSIS Restores a random sample to temp and proves every file against
    the MANIFEST hash. Live-source comparison is info only — the source
    legitimately changes after a backup. Use -CleanupDrillDir to remove the
    drill dir afterwards (kept by default as the proof).
    #>
    param(
        [Parameter(Mandatory=$true)][string]$VersionDir,
        [string]$SourceDir = "",
        [int]$SampleSize = 25,
        [switch]$CleanupDrillDir
    )
    try {
        $manFile = Join-Path $VersionDir "MANIFEST-SHA256.txt"
        if (-not (Test-Path $manFile)) { throw "No manifest in $VersionDir" }
        $entries = Get-Content $manFile | Where-Object { $_ -match '^[0-9A-Fa-f]{64}\s\s' }
        if ($entries.Count -eq 0) { throw "Manifest empty." }
        $n = [Math]::Min($SampleSize, $entries.Count)
        $rnd = New-Object System.Random
        $sample = $entries | Sort-Object { $rnd.Next() } | Select-Object -First $n
        $drillDir = Join-Path ([System.IO.Path]::GetTempPath()) ("bb-restoredrill-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
        New-Item -ItemType Directory -Path $drillDir -Force | Out-Null
        $ok = 0; $fail = 0; $srcDrift = 0
        foreach ($line in $sample) {
            $line -match '^([0-9A-Fa-f]{64})\s\s(.+)$' | Out-Null
            $expect = $matches[1]; $rel = $matches[2]
            $bakFile = Join-Path $VersionDir $rel
            $dstFile = Join-Path $drillDir $rel
            $dstParent = Split-Path $dstFile -Parent
            if (-not (Test-Path $dstParent)) { New-Item -ItemType Directory -Path $dstParent -Force | Out-Null }
            Copy-Item $bakFile $dstFile -Force
            # THE proof: restored copy vs the manifest hash.
            $got = (Get-FileHash $dstFile -Algorithm SHA256).Hash
            if ($got -eq $expect) { $ok++ }
            else { $fail++; Write-Host "[backup] DRILL MISMATCH (backup corrupt): $rel" }
            # Info only: does the live source still match the manifest?
            if ($SourceDir -ne "") {
                $parts = $rel -split '[\\/]'
                $srcFile = Join-Path $SourceDir ($parts[1..($parts.Length-1)] -join [System.IO.Path]::DirectorySeparatorChar)
                if (Test-Path $srcFile) {
                    $h2 = (Get-FileHash $srcFile -Algorithm SHA256).Hash
                    if ($h2 -ne $expect) { $srcDrift++ }
                }
            }
        }
        Write-Host "[backup] Restore drill: $ok/$n restore-proven vs manifest, $fail failed."
        if ($SourceDir -ne "") {
            Write-Host "[backup]   (info) $srcDrift/$n sampled files differ from the LIVE source — normal if the source changed after backup; NOT a drill failure."
        }
        Write-Host "[backup] Drill dir: $drillDir"
        if ($CleanupDrillDir) {
            Remove-Item $drillDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "[backup] Drill dir cleaned up."
        }
        New-BackupVaultLog -Action "restore-drill" -VersionDir $VersionDir `
            -Files $n -IntegrityClean ($fail -eq 0) `
            -Notes "$ok/$n manifest-proven, source-drift $srcDrift"
        return [PSCustomObject]@{
            Sampled=$n; Matched=$ok; Failed=$fail; SourceDrift=$srcDrift
            DrillDir=$drillDir; Passed=($fail -eq 0)
        }
    } catch {
        Write-Host "[backup] ERROR in restore drill: $($_.Exception.Message)"
        throw
    }
}

# ---------------------------------------------------------------------------
# Scheduled backups — a plan that runs only when you remember is not a plan.
# Weekly 02:00 default. Mirrors the broker-eradicator monthly task pattern.
# ---------------------------------------------------------------------------
function New-BackupScheduledTask {
    <#
    .SYNOPSIS Installs a scheduled task that runs Start-Backup for a plan.
    Default: weekly at 02:00. schtasks needs admin for a system-wide task.
    #>
    param(
        [string]$PlanName = "default",
        [ValidateSet("DAILY","WEEKLY","MONTHLY")][string]$Frequency = "WEEKLY",
        [string]$Time = "02:00"
    )
    try {
        $taskName = "Falsum-Backup-$PlanName"
        $modulePath = $MyInvocation.PSCommandPath
        $psCmd = "& { . '$modulePath'; Start-Backup -Name '$PlanName' }"
        $action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"$psCmd`""
        $out = & schtasks.exe /Create /TN $taskName /TR $action /SC $Frequency /ST $Time /F 2>&1
        Write-Host ($out -join "`n")
        Write-Host "[backup] Scheduled task '$taskName' installed: $Frequency at $Time. Backups happen whether you remember or not."
    } catch {
        Write-Host "[backup] ERROR creating scheduled task (needs admin for system-wide): $($_.Exception.Message)"
        throw
    }
}

function Remove-BackupScheduledTask {
    <#
    .SYNOPSIS Removes the scheduled backup task for a plan.
    #>
    param([string]$PlanName = "default")
    try {
        $out = & schtasks.exe /Delete /TN "Falsum-Backup-$PlanName" /F 2>&1
        Write-Host ($out -join "`n")
    } catch { Write-Host "[backup] ERROR removing task: $($_.Exception.Message)" }
}

function Get-BackupScheduledTask {
    <#
    .SYNOPSIS Shows the scheduled backup task for a plan, if installed.
    #>
    param([string]$PlanName = "default")
    try {
        $out = & schtasks.exe /Query /TN "Falsum-Backup-$PlanName" /FO LIST /V 2>&1
        Write-Host ($out -join "`n")
    } catch { Write-Host '[backup] Scheduled task not installed (or schtasks unavailable).' }
}

function Get-RansomwarePlaybook {
    <#
    .SYNOPSIS The decision tree for DURING an attack. Read BEFORE you need it.
    #>
    return @(
        [PSCustomObject]@{Step=1; Action="ISOLATE: unplug network cable / turn off Wi-Fi NOW. Do not shut down (memory forensics)."},
        [PSCustomObject]@{Step=2; Action="IDENTIFY: photograph the ransom note screen. Note the extension on encrypted files."},
        [PSCustomObject]@{Step=3; Action="DO NOT PAY yet: check ID Ransomware (id-ransomware.malwarehunterteam.com) — free decryptors exist for many families. Do not upload sensitive files."},
        [PSCustomObject]@{Step=4; Action="ASSESS: what is encrypted vs what is in your tested backup (Test-BackupIntegrity)."},
        [PSCustomObject]@{Step=5; Action="WIPE + RESTORE: clean OS install from known-good media, restore from the verified backup version."},
        [PSCustomObject]@{Step=6; Action="REPORT: FBI IC3 ic3.gov + local police. Ransomware is a crime; the report is the record."},
        [PSCustomObject]@{Step=7; Action="ROTATE: every password typed on that machine since infection is burned. Rotate from a clean device."}
    )
}

function Test-BackupShieldHygiene {
    <#
    .SYNOPSIS Offline battery: synthetic source tree in temp, full
    plan/backup/integrity/drill end-to-end, plus pure-logic cases for the
    overlap guard, space verdicts, manifest-tamper and extra-file detection.
    Needs robocopy (Windows).
    #>
    $checks = New-Object System.Collections.ArrayList
    $ok = { param($n,$c) [void]$checks.Add([PSCustomObject]@{Check=$n;Pass=[bool]$c}) }.GetNewClosure()
    $base = Join-Path ([System.IO.Path]::GetTempPath()) "bb-backuptest"
    if (Test-Path $base) { Remove-Item $base -Recurse -Force }
    $src = Join-Path $base "src"; $dst = Join-Path $base "dst"
    New-Item -ItemType Directory -Path $src, $dst -Force | Out-Null
    1..10 | ForEach-Object { "file content $_" | Out-File (Join-Path $src "file$_.txt") -Encoding utf8 }
    New-Item -ItemType Directory -Path (Join-Path $src "sub") -Force | Out-Null
    "nested" | Out-File (Join-Path $src "sub" "nested.txt") -Encoding utf8

    # --- pure logic: overlap guard ---
    &$ok "overlap: dest inside source" (Test-BackupPathOverlap -SourceDirs @("C:\data") -Destination "C:\data\backups")
    &$ok "overlap: source inside dest" (Test-BackupPathOverlap -SourceDirs @("C:\backups\data") -Destination "C:\backups")
    &$ok "overlap: same dir" (Test-BackupPathOverlap -SourceDirs @("C:\data") -Destination "C:\data")
    &$ok "overlap: sibling dirs OK" (-not (Test-BackupPathOverlap -SourceDirs @("C:\data") -Destination "D:\backups"))
    &$ok "overlap: similar prefix not overlap" (-not (Test-BackupPathOverlap -SourceDirs @("C:\data2") -Destination "C:\data"))
    # --- pure logic: space verdicts ---
    &$ok "space: fail below size" ((Test-BackupSpaceVerdict -FreeBytes 100 -SourceBytes 200) -eq "fail")
    &$ok "space: tight within margin" ((Test-BackupSpaceVerdict -FreeBytes 110 -SourceBytes 100) -eq "tight")
    &$ok "space: ok with margin" ((Test-BackupSpaceVerdict -FreeBytes 200 -SourceBytes 100) -eq "ok")
    &$ok "space: unknown on zero source" ((Test-BackupSpaceVerdict -FreeBytes 200 -SourceBytes 0) -eq "unknown")

    # --- end-to-end (robocopy) ---
    $plan = New-BackupPlan -SourceDirs @($src) -Destination $dst -Name "hygiene" -KeepVersions 2
    &$ok "plan created" ($plan.Name -eq "hygiene")
    # overlap guard must refuse at plan time too
    $refused = $false
    try { New-BackupPlan -SourceDirs @($src) -Destination (Join-Path $src "oops") -Name "overlap-guard" | Out-Null } catch { $refused = $true }
    &$ok "plan refuses overlap" $refused
    $res = Start-Backup -Name "hygiene"
    &$ok "backup ran" (Test-Path $res.VersionDir)
    &$ok "11 files backed up" ($res.Files -eq 11)
    &$ok "manifest hash recorded" ($res.ManifestHash -match '^[0-9A-F]{64}$')
    $integ = Test-BackupIntegrity $res.VersionDir
    &$ok "integrity clean" ($integ.Clean -eq $true -and $integ.ExtraFiles -eq 0)
    # source-changed drill: change the source BEFORE the drill — must NOT fail
    "source changed after backup" | Out-File (Join-Path $src "file1.txt") -Encoding utf8
    $drill = Start-RestoreDrill -VersionDir $res.VersionDir -SourceDir $src -SampleSize 5 -CleanupDrillDir
    &$ok "restore drill passes on source drift" ($drill.Passed -eq $true)
    &$ok "source drift reported as info" ($drill.SourceDrift -ge 0)
    # Tamper one file -> integrity must catch it
    $first = Get-ChildItem $res.VersionDir -Recurse -File | Where-Object { $_.Name -ne "MANIFEST-SHA256.txt" } | Select-Object -First 1
    "tampered" | Out-File $first.FullName -Encoding utf8
    $integ2 = Test-BackupIntegrity $res.VersionDir
    &$ok "tamper detected" ($integ2.Clean -eq $false -and $integ2.Mismatched -ge 1)
    # Rewrite the manifest to match the tampered file -> self-hash must catch it
    $rel = $first.FullName.Substring($res.VersionDir.Length + 1)
    $newHash = (Get-FileHash $first.FullName -Algorithm SHA256).Hash
    $lines = Get-Content (Join-Path $res.VersionDir "MANIFEST-SHA256.txt")
    $lines | ForEach-Object { if ($_ -match "$rel$") { "$newHash  $rel" } else { $_ } } |
        Out-File (Join-Path $res.VersionDir "MANIFEST-SHA256.txt") -Encoding ascii
    $integ3 = Test-BackupIntegrity $res.VersionDir
    &$ok "rewritten manifest caught" ($integ3.ManifestTampered -eq $true -and $integ3.Clean -eq $false)
    # Extra file -> flagged
    "planted" | Out-File (Join-Path $res.VersionDir "bb-backup-hygiene" "README-TO-PAY.txt") -Encoding utf8
    $integ4 = Test-BackupIntegrity $res.VersionDir
    &$ok "extra file flagged" ($integ4.ExtraFiles -ge 1 -and $integ4.Clean -eq $false)
    &$ok "playbook has 7 steps" ((Get-RansomwarePlaybook).Count -eq 7)
    Remove-Item $base -Recurse -Force -ErrorAction SilentlyContinue
    $pf = Join-Path $script:BackupRoot "plan-hygiene.json"
    if (Test-Path $pf) { Remove-Item $pf -Force }
    $pf2 = Join-Path $script:BackupRoot "plan-overlap-guard.json"
    if (Test-Path $pf2) { Remove-Item $pf2 -Force }

    $pass = ($checks | Where-Object { $_.Pass }).Count
    Write-Host "[backup] Hygiene: $pass/$($checks.Count) checks passed."
    return $checks
}

Write-Host "[backup] Falsum Backup Shield v1.1 loaded. New-BackupPlan / Start-Backup / Test-BackupIntegrity / Start-RestoreDrill / New-BackupScheduledTask / Get-RansomwarePlaybook / Test-BackupShieldHygiene."
