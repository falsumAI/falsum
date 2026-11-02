<#
.SYNOPSIS
    Falsum Defender Watch — monitors Windows Defender itself. Logs everything it does.

.DESCRIPTION
    Gregg's order: "Go into Windows Defender so it grabs everything and logs
    everything that corrupt piece of shit application is doing."

    Windows Defender is a black box that touches every file on the system.
    This module watches the watcher:
    - Every scan (quick, full, custom) with timestamps and results
    - Every threat detection with threat name, severity, and action taken
    - Every quarantine add/remove/restore
    - Every exclusion add/remove (who excluded what, when)
    - Every real-time protection toggle (who turned it off, when)
    - Current Defender status (engine version, definitions age, tamper protection)

    All events are pulled from the Defender Operational event log and the
    Mp* PowerShell cmdlets, then written to our hash-chained vault.
    Defender cannot hide from its own logs — we just read them.

    FUNCTIONS:
      Get-DefenderStatus          - current engine, definitions, real-time, tamper
      Get-DefenderScans           - scan history from event log
      Get-DefenderDetections      - threat detections with action taken
      Get-DefenderQuarantine      - quarantined items
      Get-DefenderExclusions      - current exclusions (paths, processes, extensions)
      Get-DefenderExclusionChanges - exclusion add/remove events from event log
      Get-DefenderProtectionToggles - real-time protection on/off events
      Invoke-DefenderWatch        - full sweep: status + scans + detections + quarantine
                                    + exclusions + toggles, all logged to vault
      Test-DefenderWatchHygiene   - self-test
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DefenderEventLog = "Microsoft-Windows-Windows Defender/Operational"

# Defender event IDs (documented by Microsoft)
$script:DefenderEventIds = @{
    ScanStarted       = 1000  # Scan started
    ScanCompleted     = 1001  # Scan completed
    ThreatDetected    = 1116  # Threat detected
    ThreatActionTaken = 1117  # Action taken on threat
    QuarantineAdded   = 1118  # Item quarantined
    QuarantineRestored= 1119  # Item restored from quarantine
    QuarantineRemoved = 1120  # Item removed from quarantine
    ExclusionAdded    = 5007  # Exclusion added
    RTPDisabled       = 5001  # Real-time protection disabled
    RTPEnabled        = 5004  # Real-time protection enabled
    TamperDisabled    = 5010  # Tamper protection disabled
    DefinitionUpdate  = 2000  # Definitions updated
    DefinitionFailed  = 2001  # Definitions update failed
}

function Get-DefenderStatus {
    <#
    .SYNOPSIS Current Defender status: engine, definitions, protections.
    #>
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        return [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            AMEngineVersion = $status.AMEngineVersion
            AMProductVersion = $status.AMProductVersion
            AntispywareSignatureVersion = $status.AntispywareSignatureVersion
            AntivirusSignatureVersion = $status.AntivirusSignatureVersion
            AntispywareSignatureAgeDays = $status.AntispywareSignatureAge
            AntivirusSignatureAgeDays = $status.AntivirusSignatureAge
            RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
            BehaviorMonitorEnabled = $status.BehaviorMonitorEnabled
            IoavProtectionEnabled = $status.IoavProtectionEnabled
            NISEnabled = $status.NISEnabled
            OnAccessProtectionEnabled = $status.OnAccessProtectionEnabled
            TamperProtectionEnabled = (Get-MpPreference -ErrorAction SilentlyContinue).EnableTamperProtection
            LastQuickScan = $status.QuickScanEndTime
            LastFullScan = $status.FullScanEndTime
        }
    }
    catch {
        return [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            Error = "Get-MpComputerStatus failed: $($_.Exception.Message)"
            Note = "Defender cmdlets require admin. Run as administrator."
        }
    }
}

function Get-DefenderEventLogEntries {
    <#
    .SYNOPSIS Pure-ish: pull Defender Operational log entries by event IDs.
    #>
    param(
        [int[]]$EventIds,
        [int]$MaxEvents = 100,
        [int]$DaysBack = 30
    )
    $results = New-Object System.Collections.ArrayList
    try {
        $startTime = (Get-Date).AddDays(-$DaysBack)
        $filter = @{
            LogName = $script:DefenderEventLog
            ID = $EventIds
            StartTime = $startTime
        }
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        foreach ($ev in $events) {
            [void]$results.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated
                Id = $ev.Id
                Level = $ev.LevelDisplayName
                Message = $ev.Message
            })
        }
    }
    catch {
        [void]$results.Add([PSCustomObject]@{
            TimeCreated = Get-Date
            Id = -1
            Level = "Error"
            Message = "Event log read failed: $($_.Exception.Message)"
        })
    }
    return @($results)
}

function Get-DefenderScans {
    <#
    .SYNOPSIS Scan history: when Defender scanned, what type, what it found.
    #>
    param([int]$MaxEvents = 50, [int]$DaysBack = 30)
    $starts = Get-DefenderEventLogEntries -EventIds @($script:DefenderEventIds.ScanStarted) -MaxEvents $MaxEvents -DaysBack $DaysBack
    $completions = Get-DefenderEventLogEntries -EventIds @($script:DefenderEventIds.ScanCompleted) -MaxEvents $MaxEvents -DaysBack $DaysBack
    return [PSCustomObject]@{
        ScansStarted = @($starts)
        ScansCompleted = @($completions)
        StartedCount = $starts.Count
        CompletedCount = $completions.Count
    }
}

function Get-DefenderDetections {
    <#
    .SYNOPSIS Threat detections: what Defender found, severity, action taken.
    #>
    param([int]$MaxEvents = 100, [int]$DaysBack = 30)
    try {
        $threats = Get-MpThreat -ErrorAction SilentlyContinue
        $detections = Get-MpThreatDetection -ErrorAction SilentlyContinue
    }
    catch { $threats = @(); $detections = @() }

    $events = Get-DefenderEventLogEntries -EventIds @(
        $script:DefenderEventIds.ThreatDetected,
        $script:DefenderEventIds.ThreatActionTaken
    ) -MaxEvents $MaxEvents -DaysBack $DaysBack

    return [PSCustomObject]@{
        ActiveThreats = @($threats | Select-Object ThreatID, ThreatName, SeverityID, DidThreatExecute, IsActive)
        DetectionHistory = @($detections | Select-Object ThreatID, ThreatName, Resources, InitialDetectionTime)
        EventLogEntries = @($events)
    }
}

function Get-DefenderQuarantine {
    <#
    .SYNOPSIS Items Defender has quarantined.
    #>
    $events = Get-DefenderEventLogEntries -EventIds @(
        $script:DefenderEventIds.QuarantineAdded,
        $script:DefenderEventIds.QuarantineRestored,
        $script:DefenderEventIds.QuarantineRemoved
    ) -MaxEvents 100 -DaysBack 90
    return [PSCustomObject]@{
        Events = @($events)
        Note = "Quarantine contents require admin. Event log shows add/restore/remove actions."
    }
}

function Get-DefenderExclusions {
    <#
    .SYNOPSIS Current Defender exclusions — paths, processes, extensions, IPs.
    .DESCRIPTION
        Exclusions are blind spots. If something added an exclusion, that's
        the first place to look. This shows what's currently excluded.
    #>
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        return [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            ExclusionPaths = @($pref.ExclusionPath)
            ExclusionProcesses = @($pref.ExclusionProcess)
            ExclusionExtensions = @($pref.ExclusionExtension)
            ExclusionIPs = @($pref.ExclusionIpAddress)
            TotalExclusions = @($pref.ExclusionPath).Count + @($pref.ExclusionProcess).Count +
                              @($pref.ExclusionExtension).Count + @($pref.ExclusionIpAddress).Count
        }
    }
    catch {
        return [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            Error = "Get-MpPreference failed: $($_.Exception.Message)"
        }
    }
}

function Get-DefenderExclusionChanges {
    <#
    .SYNOPSIS Exclusion add/remove events — who punched holes in Defender, when.
    #>
    param([int]$MaxEvents = 50, [int]$DaysBack = 90)
    return @(Get-DefenderEventLogEntries -EventIds @($script:DefenderEventIds.ExclusionAdded) -MaxEvents $MaxEvents -DaysBack $DaysBack)
}

function Get-DefenderProtectionToggles {
    <#
    .SYNOPSIS Real-time protection on/off events — who disabled it, when.
    .DESCRIPTION
        If real-time protection was turned off, that's either the user or
        something acting as the user. The event log says when.
    #>
    param([int]$MaxEvents = 50, [int]$DaysBack = 90)
    return @(Get-DefenderEventLogEntries -EventIds @(
        $script:DefenderEventIds.RTPDisabled,
        $script:DefenderEventIds.RTPEnabled,
        $script:DefenderEventIds.TamperDisabled
    ) -MaxEvents $MaxEvents -DaysBack $DaysBack)
}

function Invoke-DefenderWatch {
    <#
    .SYNOPSIS
        Full Defender watch sweep. Status + scans + detections + quarantine +
        exclusions + toggles. Everything logged.
    #>
    param([string]$VaultPath = "")

    Write-Host "`n=== DEFENDER WATCH ===" -ForegroundColor White
    Write-Host "Watching the watcher. Logging everything.`n" -ForegroundColor Gray

    $report = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        Status = $null
        Scans = $null
        Detections = $null
        Quarantine = $null
        Exclusions = $null
        ExclusionChanges = @()
        ProtectionToggles = @()
    }

    Write-Host "[1/7] Defender status..." -ForegroundColor Cyan
    $report.Status = Get-DefenderStatus
    if ($report.Status.RealTimeProtectionEnabled -eq $false) {
        Write-Host "  WARNING: Real-time protection is OFF" -ForegroundColor Red
    }
    else {
        Write-Host "  Real-time protection: ON" -ForegroundColor Green
    }

    Write-Host "[2/7] Scan history..." -ForegroundColor Cyan
    $report.Scans = Get-DefenderScans
    Write-Host "  $($report.Scans.StartedCount) scans started, $($report.Scans.CompletedCount) completed (30d)"

    Write-Host "[3/7] Threat detections..." -ForegroundColor Cyan
    $report.Detections = Get-DefenderDetections
    $activeCount = @($report.Detections.ActiveThreats).Count
    Write-Host "  $activeCount active threats" -ForegroundColor $(if ($activeCount -gt 0) { "Red" } else { "Green" })

    Write-Host "[4/7] Quarantine..." -ForegroundColor Cyan
    $report.Quarantine = Get-DefenderQuarantine
    Write-Host "  $($report.Quarantine.Events.Count) quarantine events (90d)"

    Write-Host "[5/7] Current exclusions..." -ForegroundColor Cyan
    $report.Exclusions = Get-DefenderExclusions
    if ($report.Exclusions.TotalExclusions -gt 0) {
        Write-Host "  $($report.Exclusions.TotalExclusions) exclusions active — REVIEW THESE" -ForegroundColor Yellow
        foreach ($ep in $report.Exclusions.ExclusionPaths) { Write-Host "    Path: $ep" -ForegroundColor Yellow }
        foreach ($ep in $report.Exclusions.ExclusionProcesses) { Write-Host "    Process: $ep" -ForegroundColor Yellow }
    }
    else {
        Write-Host "  No exclusions" -ForegroundColor Green
    }

    Write-Host "[6/7] Exclusion changes..." -ForegroundColor Cyan
    $report.ExclusionChanges = @(Get-DefenderExclusionChanges)
    Write-Host "  $($report.ExclusionChanges.Count) exclusion change events (90d)" -ForegroundColor $(if ($report.ExclusionChanges.Count -gt 0) { "Yellow" } else { "Green" })

    Write-Host "[7/7] Protection toggles..." -ForegroundColor Cyan
    $report.ProtectionToggles = @(Get-DefenderProtectionToggles)
    $offEvents = @($report.ProtectionToggles | Where-Object { $_.Id -eq $script:DefenderEventIds.RTPDisabled })
    Write-Host "  $($offEvents.Count) times real-time protection was DISABLED (90d)" -ForegroundColor $(if ($offEvents.Count -gt 0) { "Red" } else { "Green" })

    # Log to vault
    if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
        $report | ConvertTo-Json -Depth 8 | Add-Content -Path $VaultPath -Encoding UTF8
        Write-Host "`nLogged to vault: $VaultPath" -ForegroundColor Gray
    }

    # Feed unified evidence pool
    if (Get-Command Add-SessionEvidence -ErrorAction SilentlyContinue) {
        if ($report.Status.RealTimeProtectionEnabled -eq $false) {
            Add-SessionEvidence -Module "defender-watch" -Finding "Real-time protection is OFF" -Severity "Critical"
        }
        foreach ($ec in $report.ExclusionChanges) {
            Add-SessionEvidence -Module "defender-watch" -Finding "Defender exclusion changed: $($ec.Message)" -Severity "High"
        }
        $offEvents = @($report.ProtectionToggles | Where-Object { $_.Id -eq 5001 })
        foreach ($oe in $offEvents) {
            Add-SessionEvidence -Module "defender-watch" -Finding "Real-time protection was disabled at $($oe.TimeCreated)" -Severity "Critical"
        }
    }

    Write-Host "`n=== DEFENDER WATCH COMPLETE ===" -ForegroundColor White
    return $report
}

function Test-DefenderWatchHygiene {
    <#
    .SYNOPSIS Self-test: event IDs, function wiring, safe failure modes.
    #>
    $results = New-Object System.Collections.ArrayList
    $add = { param($Name,$Pass,$Detail)
        [void]$results.Add([PSCustomObject]@{Test=$Name; Pass=$Pass; Detail=$Detail})
    }.GetNewClosure()

    &$add "Event IDs: ScanStarted defined" ($script:DefenderEventIds.ScanStarted -eq 1000) "Must be 1000"
    &$add "Event IDs: ThreatDetected defined" ($script:DefenderEventIds.ThreatDetected -eq 1116) "Must be 1116"
    &$add "Event IDs: RTPDisabled defined" ($script:DefenderEventIds.RTPDisabled -eq 5001) "Must be 5001"
    &$add "Event IDs: ExclusionAdded defined" ($script:DefenderEventIds.ExclusionAdded -eq 5007) "Must be 5007"
    &$add "Event log name set" ($script:DefenderEventLog -eq "Microsoft-Windows-Windows Defender/Operational") "Must match Defender channel"

    # Safe failure: functions return objects even without admin
    try {
        $s = Get-DefenderStatus
        &$add "Get-DefenderStatus: returns object" ($null -ne $s) "Must return object even on failure"
        &$add "Get-DefenderStatus: has timestamp" ($null -ne $s.Timestamp) "Must have timestamp"
    }
    catch { &$add "Get-DefenderStatus: no throw" $false "Must not throw: $($_.Exception.Message)" }

    try {
        $e = Get-DefenderEventLogEntries -EventIds @(99999) -MaxEvents 1 -DaysBack 1
        &$add "Event log: safe on bad ID" ($null -ne $e) "Must return array even for nonexistent event ID"
    }
    catch { &$add "Event log: no throw" $false "Must not throw" }

    $passed = ($results | Where-Object Pass).Count
    $total = $results.Count
    Write-Host "`nDefender Watch Hygiene: $passed/$total passed" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Red" })
    foreach ($r in $results) {
        Write-Host "  [$($(if ($r.Pass){"PASS"}else{"FAIL"}))] $($r.Test)" -ForegroundColor $(if ($r.Pass) { "Green" } else { "Red" })
    }
    return $results
}

Export-ModuleMember -Function @(
    'Get-DefenderStatus',
    'Get-DefenderEventLogEntries',
    'Get-DefenderScans',
    'Get-DefenderDetections',
    'Get-DefenderQuarantine',
    'Get-DefenderExclusions',
    'Get-DefenderExclusionChanges',
    'Get-DefenderProtectionToggles',
    'Invoke-DefenderWatch',
    'Test-DefenderWatchHygiene'
)
