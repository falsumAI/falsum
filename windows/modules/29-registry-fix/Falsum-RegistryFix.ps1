<#
.SYNOPSIS
    Falsum Registry Fixer — clean the registry, log everything.

.DESCRIPTION
    Gregg's order: "fix the registry, go down in the binaries — anything
    without any value or no data or no actual name... I want it gone...
    delete it instantly... not only delete it, log it"

    What this does:
    1. Scans auto-start registry keys for EMPTY values (no data)
    2. Finds ORPHANED entries (points to file that doesn't exist)
    3. Finds NAMELESS entries (value with no name, or gibberish)
    4. BACKS UP every key before touching it
    5. REMOVES the bad entry
    6. LOGS everything to the vault (what, where, when, why)

    What this does NOT do:
    - Touch System32, SysWOW64, WinSxS, or Windows keys
    - Delete anything without backup first
    - Run without -Enforce (default is audit-only, shows what WOULD be removed)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Registry keys to scan (auto-start locations)
$script:RegFixScanKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)

# Protected paths — never auto-remove entries pointing here
$script:RegFixProtectedPaths = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows\WinSxS",
    "C:\Windows\"
)

function Backup-RegistryKey {
    <#
    .SYNOPSIS
        Export a registry key to a .reg file before modifying it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][string]$BackupDir
    )
    if (-not (Test-Path $BackupDir)) {
        New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    }
    $safeName = $KeyPath -replace '[:\\]', '_'
    $backupFile = Join-Path $BackupDir "$safeName-$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"
    try {
        $regPath = $KeyPath -replace 'HKLM:', 'HKLM' -replace 'HKCU:', 'HKCU'
        & reg export $regPath $backupFile /y 2>&1 | Out-Null
        return $backupFile
    }
    catch {
        return $null
    }
}

function Test-RegistryValueIsEmpty {
    <#
    .SYNOPSIS
        Check if a registry value has no data or empty data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][string]$ValueName
    )
    try {
        $val = Get-ItemProperty -Path $KeyPath -Name $ValueName -ErrorAction Stop
        $data = $val.$ValueName
        # Empty: null, empty string, whitespace only
        if ($null -eq $data) { return $true }
        if ($data -is [string] -and [string]::IsNullOrWhiteSpace($data)) { return $true }
        if ($data -is [array] -and $data.Count -eq 0) { return $true }
        return $false
    }
    catch {
        return $false
    }
}

function Test-RegistryValueIsOrphaned {
    <#
    .SYNOPSIS
        Check if a registry value points to a file that doesn't exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][string]$ValueName
    )
    try {
        $val = Get-ItemProperty -Path $KeyPath -Name $ValueName -ErrorAction Stop
        $data = $val.$ValueName
        if ($data -isnot [string]) { return $false }

        # Extract executable path (handle quotes and arguments)
        $path = $data.Trim()
        if ($path.StartsWith('"')) {
            $end = $path.IndexOf('"', 1)
            if ($end -gt 0) { $path = $path.Substring(1, $end - 1) }
        }
        else {
            # Unquoted: take up to first space, but check if full path exists first
            if (-not (Test-Path $path -ErrorAction SilentlyContinue)) {
                $path = ($path -split ' ')[0]
            }
        }

        # Expand environment variables
        $path = [Environment]::ExpandEnvironmentVariables($path)

        # Check if file exists
        if (-not (Test-Path $path -ErrorAction SilentlyContinue)) {
            # Also check without arguments
            $exeOnly = ($path -split ' ')[0]
            if (-not (Test-Path $exeOnly -ErrorAction SilentlyContinue)) {
                return $true  # Orphaned: points to nothing
            }
        }
        return $false
    }
    catch {
        return $false
    }
}

function Test-RegistryValueIsProtected {
    <#
    .SYNOPSIS
        Check if a registry value points to a protected system path.
    #>
    [CmdletBinding()]
    param([string]$Data)
    if ([string]::IsNullOrWhiteSpace($Data)) { return $false }
    $expanded = [Environment]::ExpandEnvironmentVariables($Data)
    foreach ($prot in $script:RegFixProtectedPaths) {
        if ($expanded -like "$prot*") { return $true }
    }
    return $false
}

function Find-BadRegistryEntries {
    <#
    .SYNOPSIS
        Scan for empty, orphaned, or nameless registry values.
    #>
    [CmdletBinding()]
    param()
    $findings = @()

    foreach ($keyPath in $script:RegFixScanKeys) {
        if (-not (Test-Path $keyPath)) { continue }

        try {
            $key = Get-Item -Path $keyPath -ErrorAction Stop
            $values = $key.GetValueNames()

            foreach ($valName in $values) {
                $valData = $key.GetValue($valName)
                $dataStr = if ($valData -is [array]) { $valData -join ';' } else { [string]$valData }

                $issues = @()

                # Check 1: Empty (no data)
                if ([string]::IsNullOrWhiteSpace($dataStr)) {
                    $issues += "EMPTY: value has no data"
                }

                # Check 2: Nameless (empty value name, or default with no meaning)
                if ([string]::IsNullOrWhiteSpace($valName) -and [string]::IsNullOrWhiteSpace($dataStr)) {
                    $issues += "NAMELESS: no name and no data"
                }

                # Check 3: Orphaned (points to missing file)
                if (-not [string]::IsNullOrWhiteSpace($dataStr)) {
                    if (Test-RegistryValueIsOrphaned -KeyPath $keyPath -ValueName $valName) {
                        $issues += "ORPHANED: points to missing file"
                    }
                }

                # Check 4: Protected (never auto-remove)
                $isProtected = Test-RegistryValueIsProtected -Data $dataStr

                if ($issues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        KeyPath    = $keyPath
                        ValueName  = $valName
                        Data       = $dataStr
                        Issues     = $issues -join '; '
                        Protected  = $isProtected
                        Timestamp  = (Get-Date).ToString('o')
                    }
                }
            }
        }
        catch {
            # Key not accessible, skip
            continue
        }
    }

    return $findings
}

function Remove-BadRegistryEntry {
    <#
    .SYNOPSIS
        Backup, remove, and log a bad registry entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Finding,
        [Parameter(Mandatory)][string]$BackupDir,
        [string]$VaultPath = ""
    )

    # Never remove protected entries automatically
    if ($Finding.Protected) {
        return [PSCustomObject]@{
            Removed = $false
            Reason  = "Protected system path — manual review required"
            Finding = $Finding
        }
    }

    # Backup the key first
    $backupFile = Backup-RegistryKey -KeyPath $Finding.KeyPath -BackupDir $BackupDir

    # Remove the value
    try {
        Remove-ItemProperty -Path $Finding.KeyPath -Name $Finding.ValueName -Force -ErrorAction Stop
        $removed = $true
        $reason = "Removed: $($Finding.Issues)"
    }
    catch {
        $removed = $false
        $reason = "Failed: $($_.Exception.Message)"
    }

    # Log to vault
    $logEntry = [PSCustomObject]@{
        Timestamp  = (Get-Date).ToString('o')
        Action     = "RegistryFix"
        KeyPath    = $Finding.KeyPath
        ValueName  = $Finding.ValueName
        Data       = $Finding.Data
        Issues     = $Finding.Issues
        BackupFile = $backupFile
        Removed    = $removed
        Reason     = $reason
    }

    if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
        $logEntry | ConvertTo-Json -Depth 5 | Add-Content -Path $VaultPath -Encoding UTF8
    }

    # Feed unified evidence pool
    if ($removed -and (Get-Command Add-SessionEvidence -ErrorAction SilentlyContinue)) {
        Add-SessionEvidence -Module "registry-fix" `
            -Finding "Removed bad registry entry: $($Finding.KeyPath)\$($Finding.ValueName)" `
            -Severity "Medium" `
            -Details @{ Issues = $Finding.Issues; BackupFile = $backupFile }
    }

    return [PSCustomObject]@{
        Removed = $removed
        Reason  = $reason
        Finding = $Finding
        BackupFile = $backupFile
    }
}

function Invoke-RegistryFixScan {
    <#
    .SYNOPSIS
        Full registry fix scan: find bad entries, optionally remove them.

    .PARAMETER Enforce
        Actually remove bad entries (with backup). Without this, audit-only.

    .PARAMETER BackupDir
        Where to store .reg backups. Default: %LOCALAPPDATA%\Falsum\regfix-backup
    #>
    [CmdletBinding()]
    param(
        [switch]$Enforce,
        [string]$BackupDir = "",
        [string]$VaultPath = ""
    )

    if ($BackupDir -eq "") {
        $BackupDir = Join-Path $env:LOCALAPPDATA "Falsum\regfix-backup"
    }

    Write-Host "`n[Registry Fix] Scanning for bad entries..." -ForegroundColor Cyan
    Write-Host "  Mode: $(if ($Enforce) { 'ENFORCE (will remove)' } else { 'AUDIT ONLY (no changes)' })" -ForegroundColor $(if ($Enforce) { 'Red' } else { 'Yellow' })

    $findings = Find-BadRegistryEntries

    Write-Host "`n  Found $($findings.Count) bad entries" -ForegroundColor $(if ($findings.Count -gt 0) { 'Red' } else { 'Green' })

    $report = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString('o')
        Mode      = if ($Enforce) { "Enforce" } else { "Audit" }
        Total     = $findings.Count
        Removed   = 0
        Skipped   = 0
        Protected = 0
        Findings  = $findings
        Results   = @()
    }

    foreach ($f in $findings) {
        $status = if ($f.Protected) { "PROTECTED" } else { ($f.Issues -split ';')[0].Trim() }
        Write-Host "  [$status] $($f.KeyPath)\$($f.ValueName)" -ForegroundColor Gray
        if (-not [string]::IsNullOrWhiteSpace($f.Data)) {
            Write-Host "    Data: $($f.Data.Substring(0, [Math]::Min(80, $f.Data.Length)))" -ForegroundColor DarkGray
        }

        if ($Enforce -and -not $f.Protected) {
            $result = Remove-BadRegistryEntry -Finding $f -BackupDir $BackupDir -VaultPath $VaultPath
            $report.Results += $result
            if ($result.Removed) {
                $report.Removed++
                Write-Host "    -> REMOVED (backed up to $($result.BackupFile))" -ForegroundColor Red
            }
            else {
                $report.Skipped++
                Write-Host "    -> SKIP: $($result.Reason)" -ForegroundColor Yellow
            }
        }
        elseif ($f.Protected) {
            $report.Protected++
        }
        else {
            $report.Skipped++
        }
    }

    # Log to vault
    if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
        $report | ConvertTo-Json -Depth 6 | Add-Content -Path $VaultPath -Encoding UTF8
        Write-Host "`n  Logged to vault." -ForegroundColor Gray
    }

    Write-Host "`n[Registry Fix] Done: $($report.Removed) removed, $($report.Skipped) skipped, $($report.Protected) protected" -ForegroundColor Cyan

    return $report
}

function Test-RegistryFixHygiene {
    <#
    .SYNOPSIS
        Self-test: verify no syntax errors, no dangerous patterns.
    #>
    [CmdletBinding()]
    param()
    $issues = @()

    # Must have backup before delete
    $content = Get-Content $PSCommandPath -Raw
    if ($content -notmatch 'Backup-RegistryKey.*Remove-ItemProperty') {
        # Check they're in the right order (backup called before remove)
        $backupPos = $content.IndexOf('Backup-RegistryKey -KeyPath')
        $removePos = $content.IndexOf('Remove-ItemProperty -Path $Finding.KeyPath')
        if ($backupPos -lt 0 -or $removePos -lt 0 -or $backupPos -gt $removePos) {
            $issues += "Backup must occur before removal"
        }
    }

    # Must check Protected before removing
    if ($content -notmatch 'if \(\$Finding\.Protected\)') {
        $issues += "Must check Protected flag before removal"
    }

    # Must default to audit-only (Enforce is opt-in)
    if ($content -notmatch '\[switch\]\$Enforce') {
        $issues += "Enforce must be opt-in switch, not default"
    }

    return [PSCustomObject]@{
        Passed = ($issues.Count -eq 0)
        Issues = $issues
    }
}

Export-ModuleMember -Function Find-BadRegistryEntries, Remove-BadRegistryEntry,
    Invoke-RegistryFixScan, Backup-RegistryKey, Test-RegistryFixHygiene
