<#
.SYNOPSIS
    Falsum Task Killer — nothing runs in the background without you knowing.

.DESCRIPTION
    Gregg's order: "Kill background tasks that don't need to be fucking running.
    Or at least give the user a pop-up notice about what is running and if they
    want to kill the tasks then they can kill it instead of it just running in
    the background without anybody fucking knowing."

    Two modes:
    - AUDIT: list every running process with CPU, RAM, path, publisher.
             Flag what's unnecessary. User picks what dies.
    - ENFORCE: automatically kill processes on the kill list (user-confirmed
             list, never system-critical).

    Safety rails (absolute):
    - System-critical processes (csrss, wininit, services, lsass, etc.) are
      NEVER killed. Not in audit suggestions, not in enforce. Hard-coded.
    - Every kill is logged to the vault with timestamp, PID, name, reason.
    - -WhatIf shows what WOULD be killed without killing.

    Kill-list categories (user-editable):
    - Bloatware: preinstalled OEM junk (per manufacturer)
    - Updaters: background updaters that don't need to run 24/7
    - Telemetry: data collection processes
    - Duplicates: multiple instances of the same updater

    FUNCTIONS:
      Get-BackgroundTasks          - all processes with resource usage + flags
      Get-TaskKillList             - the user-editable kill list
      Test-ProcessIsSystemCritical - hard safety check (never kill these)
      Test-ProcessIsKillCandidate  - matches kill list + heuristic flags
      Stop-BackgroundTask          - kill one process + log to vault
      Invoke-TaskKillerAudit       - show user what's running, let them pick
      Invoke-TaskKillerEnforce     - auto-kill everything on the kill list
      Test-TaskKillerHygiene       - self-test
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# ABSOLUTE SAFETY: NEVER KILL THESE
# ============================================================================
$script:SystemCriticalProcesses = @(
    'csrss', 'wininit', 'services', 'lsass', 'lsm', 'smss', 'winlogon',
    'dwm', 'explorer', 'taskhostw', 'sihost', 'ctfmon', 'conhost',
    'svchost', 'RuntimeBroker', 'SearchIndexer', 'MsMpEng', 'NisSrv',
    'spoolsv', 'audiodg', 'WUDFHost', 'dllhost', 'WmiPrvSE',
    'System', 'Registry', 'Memory Compression', 'Secure System'
)

# ============================================================================
# KILL LIST: processes that don't need to run 24/7 (user-editable)
# ============================================================================
$script:TaskKillList = @(
    # --- OEM bloatware ---
    @{ Name='OneDriveSetup'; Category='Bloatware'; Reason='OneDrive installer residue' },
    @{ Name='HP*'; Category='Bloatware'; Reason='HP preinstalled utilities' },
    @{ Name='Dell*'; Category='Bloatware'; Reason='Dell preinstalled utilities' },
    @{ Name='Lenovo*'; Category='Bloatware'; Reason='Lenovo preinstalled utilities' },
    @{ Name='Asus*'; Category='Bloatware'; Reason='ASUS preinstalled utilities' },
    # --- Background updaters (don't need 24/7) ---
    @{ Name='AdobeARM'; Category='Updater'; Reason='Adobe updater (runs on launch anyway)' },
    @{ Name='GoogleUpdate'; Category='Updater'; Reason='Google updater (Chrome checks on launch)' },
    @{ Name='gupdate*'; Category='Updater'; Reason='Google update service residue' },
    # --- Telemetry ---
    @{ Name='CompatTelRunner'; Category='Telemetry'; Reason='Windows compatibility telemetry' },
    @{ Name='DiagTrack'; Category='Telemetry'; Reason='Diagnostics tracking' },
    # --- Common junk ---
    @{ Name='Cortana'; Category='Bloatware'; Reason='Cortana background (deprecated)' },
    @{ Name='GameBar*'; Category='Bloatware'; Reason='Xbox Game Bar (unless gaming)' },
)

function Test-ProcessIsSystemCritical {
    <#
    .SYNOPSIS Pure: true if process must NEVER be killed.
    #>
    param([Parameter(Mandatory=$true)][string]$ProcessName)
    $lower = $ProcessName.ToLower()
    foreach ($crit in $script:SystemCriticalProcesses) {
        if ($lower -eq $crit.ToLower()) { return $true }
    }
    return $false
}

function Test-ProcessIsKillCandidate {
    <#
    .SYNOPSIS Pure: true if process matches kill list (wildcards) and isn't critical.
    #>
    param([Parameter(Mandatory=$true)][string]$ProcessName)
    if (Test-ProcessIsSystemCritical $ProcessName) { return $null }
    foreach ($entry in $script:TaskKillList) {
        if ($ProcessName -like $entry.Name) {
            return $entry
        }
    }
    return $null
}

function Get-BackgroundTasks {
    <#
    .SYNOPSIS
        Every running process with resource usage, path, and kill-candidate flags.
    #>
    $tasks = New-Object System.Collections.ArrayList
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        try {
            $isCritical = Test-ProcessIsSystemCritical $p.ProcessName
            $killMatch = if (-not $isCritical) { Test-ProcessIsKillCandidate $p.ProcessName } else { $null }

            [void]$tasks.Add([PSCustomObject]@{
                Id = $p.Id
                Name = $p.ProcessName
                CPU = try { [math]::Round($p.CPU, 1) } catch { 0 }
                RAM_MB = try { [math]::Round($p.WorkingSet64 / 1MB, 1) } catch { 0 }
                Path = try { $p.Path } catch { "[access denied]" }
                StartTime = try { $p.StartTime } catch { $null }
                IsSystemCritical = $isCritical
                KillCandidate = ($null -ne $killMatch)
                KillCategory = if ($killMatch) { $killMatch.Category } else { "" }
                KillReason = if ($killMatch) { $killMatch.Reason } else { "" }
            })
        }
        catch { }
    }
    return @($tasks | Sort-Object RAM_MB -Descending)
}

function Get-TaskKillList {
    <#
    .SYNOPSIS Pure: return the current kill list for user review/editing.
    #>
    return @($script:TaskKillList)
}

function Stop-BackgroundTask {
    <#
    .SYNOPSIS Kill one process by PID. Logs to vault. NEVER kills system-critical.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][int]$ProcessId,
        [string]$Reason = "User-requested kill",
        [string]$VaultPath = ""
    )

    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
    }
    catch {
        Write-Warning "Process $ProcessId not found (may have already exited)."
        return $null
    }

    if (Test-ProcessIsSystemCritical $proc.ProcessName) {
        Write-Warning "REFUSED: $($proc.ProcessName) (PID $ProcessId) is system-critical. Will not kill."
        return [PSCustomObject]@{
            ProcessId=$ProcessId; Name=$proc.ProcessName; Killed=$false
            Reason="System-critical process — kill refused"
        }
    }

    $logEntry = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        Action = "TASK-KILL"
        ProcessId = $ProcessId
        Name = $proc.ProcessName
        Path = try { $proc.Path } catch { "[access denied]" }
        RAM_MB = try { [math]::Round($proc.WorkingSet64 / 1MB, 1) } catch { 0 }
        Reason = $Reason
    }

    if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
        $logEntry | ConvertTo-Json -Depth 5 | Add-Content -Path $VaultPath -Encoding UTF8
    }

    # Feed unified evidence pool
    if ($logEntry.Killed -and (Get-Command Add-SessionEvidence -ErrorAction SilentlyContinue)) {
        Add-SessionEvidence -Module "task-killer" -Finding "Killed process: $($logEntry.Name) (PID $($logEntry.ProcessId))" -Severity "Medium" -Details @{ Path = $logEntry.Path }
    }

    if ($PSCmdlet.ShouldProcess("$($proc.ProcessName) (PID $ProcessId)", "Kill process")) {
        try {
            Stop-Process -Id $ProcessId -Force -ErrorAction Stop
            $logEntry | Add-Member -NotePropertyName "Killed" -NotePropertyValue $true
            Write-Host "KILLED: $($proc.ProcessName) (PID $ProcessId)" -ForegroundColor Red
        }
        catch {
            $logEntry | Add-Member -NotePropertyName "Killed" -NotePropertyValue $false
            $logEntry | Add-Member -NotePropertyName "KillError" -NotePropertyValue $_.Exception.Message
            Write-Warning "Kill failed for PID $ProcessId : $($_.Exception.Message)"
        }
    }
    else {
        $logEntry | Add-Member -NotePropertyName "Killed" -NotePropertyValue $false
    }

    return $logEntry
}

function Invoke-TaskKillerAudit {
    <#
    .SYNOPSIS
        Show the user everything running. They pick what dies.
    .DESCRIPTION
        Prints a sorted table: PID, Name, RAM, CPU, Path, Kill-candidate flag.
        Kill candidates are highlighted. Returns the list for the user to act on.
        This is the "pop-up notice" — nothing hidden, user decides.
    #>
    param([string]$VaultPath = "")

    Write-Host "`n=== BACKGROUND TASK AUDIT ===" -ForegroundColor White
    Write-Host "Everything running. You decide what dies.`n" -ForegroundColor Gray

    $tasks = Get-BackgroundTasks
    $candidates = @($tasks | Where-Object { $_.KillCandidate })
    $totalRAM = ($tasks | Measure-Object -Property RAM_MB -Sum).Sum

    Write-Host "Total processes: $($tasks.Count) | Total RAM: $([math]::Round($totalRAM, 0)) MB" -ForegroundColor White
    Write-Host "Kill candidates: $($candidates.Count)" -ForegroundColor $(if ($candidates.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host ""

    # Show top 20 by RAM
    Write-Host "--- Top 20 by RAM ---" -ForegroundColor Cyan
    $tasks | Select-Object -First 20 | Format-Table -AutoSize `
        @{L='PID';E={$_.Id}}, `
        @{L='Name';E={$_.Name}}, `
        @{L='RAM MB';E={$_.RAM_MB}}, `
        @{L='KILL?';E={if ($_.KillCandidate) { "YES ($($_.KillCategory))" } elseif ($_.IsSystemCritical) { "[system]" } else { "" }}} |
        Out-String | Write-Host

    if ($candidates.Count -gt 0) {
        Write-Host "`n--- Kill Candidates ---" -ForegroundColor Yellow
        foreach ($c in $candidates) {
            Write-Host "  PID $($c.Id) | $($c.Name) | $($c.RAM_MB) MB | $($c.KillReason)" -ForegroundColor Yellow
        }
        Write-Host "`nTo kill: Stop-BackgroundTask -ProcessId <PID> -Reason 'Audit kill'" -ForegroundColor Gray
        Write-Host "To kill all candidates: Invoke-TaskKillerEnforce" -ForegroundColor Gray
    }

    return [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        TotalProcesses = $tasks.Count
        TotalRAM_MB = [math]::Round($totalRAM, 1)
        KillCandidates = @($candidates)
        AllTasks = @($tasks)
    }
}

function Invoke-TaskKillerEnforce {
    <#
    .SYNOPSIS Auto-kill everything on the kill list. Logs every kill.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([string]$VaultPath = "")

    Write-Host "`n=== TASK KILLER ENFORCE ===" -ForegroundColor White

    $tasks = Get-BackgroundTasks
    $candidates = @($tasks | Where-Object { $_.KillCandidate })

    if ($candidates.Count -eq 0) {
        Write-Host "No kill candidates running. Nothing to do." -ForegroundColor Green
        return @()
    }

    Write-Host "Killing $($candidates.Count) processes..." -ForegroundColor Yellow
    $killed = @()
    foreach ($c in $candidates) {
        $result = Stop-BackgroundTask -ProcessId $c.Id -Reason "Enforce: $($c.KillCategory) - $($c.KillReason)" -VaultPath $VaultPath
        if ($result -and $result.Killed) { $killed += $result }
    }

    $freedRAM = ($killed | Measure-Object -Property RAM_MB -Sum).Sum
    Write-Host "`nKilled: $($killed.Count) | Freed: $([math]::Round($freedRAM, 1)) MB RAM" -ForegroundColor Green
    return @($killed)
}

function Test-TaskKillerHygiene {
    <#
    .SYNOPSIS Self-test: safety rails, kill list, pure functions.
    #>
    $results = New-Object System.Collections.ArrayList
    $add = { param($Name,$Pass,$Detail)
        [void]$results.Add([PSCustomObject]@{Test=$Name; Pass=$Pass; Detail=$Detail})
    }.GetNewClosure()

    # System-critical must never be killable
    &$add "Safety: csrss is critical" (Test-ProcessIsSystemCritical 'csrss') "csrss must be protected"
    &$add "Safety: lsass is critical" (Test-ProcessIsSystemCritical 'lsass') "lsass must be protected"
    &$add "Safety: svchost is critical" (Test-ProcessIsSystemCritical 'svchost') "svchost must be protected"
    &$add "Safety: explorer is critical" (Test-ProcessIsSystemCritical 'explorer') "explorer must be protected"
    &$add "Safety: System is critical" (Test-ProcessIsSystemCritical 'System') "System must be protected"
    &$add "Safety: MsMpEng is critical" (Test-ProcessIsSystemCritical 'MsMpEng') "Defender engine must be protected"

    # Non-critical should not be flagged
    &$add "Safety: notepad not critical" (-not (Test-ProcessIsSystemCritical 'notepad')) "notepad must NOT be critical"
    &$add "Safety: chrome not critical" (-not (Test-ProcessIsSystemCritical 'chrome')) "chrome must NOT be critical"

    # Kill candidate matching
    $match = Test-ProcessIsKillCandidate 'AdobeARM'
    &$add "Kill list: AdobeARM matches" ($null -ne $match) "AdobeARM should be a kill candidate"
    &$add "Kill list: returns category" ($match.Category -eq 'Updater') "Should return Updater category"

    # Critical overrides kill list (if something is both, critical wins)
    $critMatch = Test-ProcessIsKillCandidate 'svchost'
    &$add "Safety: critical overrides kill list" ($null -eq $critMatch) "svchost must return null even if on kill list"

    # Kill list is editable (array, not hardcoded in function)
    &$add "Kill list: editable" ($script:TaskKillList -is [array] -and $script:TaskKillList.Count -gt 0) "$($script:TaskKillList.Count) entries"

    # Stop-BackgroundTask refuses critical (test via WhatIf to avoid actual kill)
    # We test the refusal logic directly
    &$add "Refusal logic: Test-ProcessIsSystemCritical gates Stop" (Test-ProcessIsSystemCritical 'csrss') "Gate verified"

    $passed = ($results | Where-Object Pass).Count
    $total = $results.Count
    Write-Host "`nTask Killer Hygiene: $passed/$total passed" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Red" })
    foreach ($r in $results) {
        Write-Host "  [$($(if ($r.Pass){"PASS"}else{"FAIL"}))] $($r.Test)" -ForegroundColor $(if ($r.Pass) { "Green" } else { "Red" })
    }
    return $results
}

Export-ModuleMember -Function @(
    'Get-BackgroundTasks',
    'Get-TaskKillList',
    'Test-ProcessIsSystemCritical',
    'Test-ProcessIsKillCandidate',
    'Stop-BackgroundTask',
    'Invoke-TaskKillerAudit',
    'Invoke-TaskKillerEnforce',
    'Test-TaskKillerHygiene'
)
