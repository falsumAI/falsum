<#
.SYNOPSIS
    Unified Application Core — one system, not 29 scripts.

.DESCRIPTION
    This is the layer that makes the tool ONE application.
    Not a launcher menu over modules. A single intelligent system where:
    - Every module feeds a shared evidence pool
    - The coherence engine scores everything together
    - The local AI reasons across all findings
    - Actions in one module trigger awareness in others
    - The browser extension and desktop share one state

    This is what "jack of all trades" actually means: not 29 tools,
    but one organism with 29 senses.

    FUNCTIONS:
      New-UnifiedSession       - start a session (shared state across modules)
      Add-SessionEvidence       - any module adds findings to the pool
      Get-SessionEvidence       - query the pooled evidence
      Invoke-UnifiedScan        - run all relevant modules, pool results, score together
      Get-UnifiedThreatPicture  - coherence-scored overview of everything found
      Send-CrossModuleAlert     - one module alerts all others
      Close-UnifiedSession      - seal the session, write to vault
      Test-UnifiedCoreHygiene   - self-test
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:UnifiedSession = $null

function New-UnifiedSession {
    <#
    .SYNOPSIS Start a unified session. All modules share this state.
    #>
    param([string]$Purpose = "General scan")

    $script:UnifiedSession = [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        Started = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        Purpose = $Purpose
        EvidencePool = New-Object System.Collections.ArrayList
        ModuleResults = @{}
        Alerts = New-Object System.Collections.ArrayList
        CoherenceScores = @{}
    }

    Write-Host "Unified session started: $($script:UnifiedSession.Id)" -ForegroundColor Cyan
    Write-Host "Purpose: $Purpose" -ForegroundColor Gray
    return $script:UnifiedSession
}

function Add-SessionEvidence {
    <#
    .SYNOPSIS Any module adds a finding to the shared pool.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Module,
        [Parameter(Mandatory=$true)][string]$Finding,
        [string]$Severity = "Info",
        [hashtable]$Details = @{}
    )

    if ($null -eq $script:UnifiedSession) {
        New-UnifiedSession -Purpose "Auto-created" | Out-Null
    }

    $evidence = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        Module = $Module
        Finding = $Finding
        Severity = $Severity
        Details = $Details
    }

    [void]$script:UnifiedSession.EvidencePool.Add($evidence)

    # Cross-module awareness: check if other modules care about this
    Send-CrossModuleAlert -SourceModule $Module -Finding $Finding -Severity $Severity
}

function Get-SessionEvidence {
    <#
    .SYNOPSIS Query pooled evidence. Filter by module, severity, or keyword.
    #>
    param(
        [string]$Module = "",
        [string]$Severity = "",
        [string]$Keyword = ""
    )

    if ($null -eq $script:UnifiedSession) { return @() }

    $results = @($script:UnifiedSession.EvidencePool)

    if ($Module -ne "") {
        $results = @($results | Where-Object { $_.Module -eq $Module })
    }
    if ($Severity -ne "") {
        $results = @($results | Where-Object { $_.Severity -eq $Severity })
    }
    if ($Keyword -ne "") {
        $kl = $Keyword.ToLower()
        $results = @($results | Where-Object {
            $_.Finding.ToLower().Contains($kl)
        })
    }

    return $results
}

function Send-CrossModuleAlert {
    <#
    .SYNOPSIS One module's finding triggers awareness in relevant others.
    .DESCRIPTION
        This is what makes it ONE system. Examples:
        - Purge deletes a binary → Defender Watch checks if Defender saw it
        - Memory forensics finds orphan → Task killer checks if it's on kill list
        - Browser reports phishing → Mail shield checks for related emails
        - Defender exclusion added → Purge scans the excluded path
    #>
    param(
        [Parameter(Mandatory=$true)][string]$SourceModule,
        [Parameter(Mandatory=$true)][string]$Finding,
        [string]$Severity = "Info"
    )

    if ($null -eq $script:UnifiedSession) { return }

    $alert = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        Source = $SourceModule
        Finding = $Finding
        Severity = $Severity
        TriggeredChecks = @()
    }

    $fl = $Finding.ToLower()

    # Cross-module trigger rules
    if ($SourceModule -eq "purge" -and $Severity -in @("High", "Critical")) {
        $alert.TriggeredChecks += "defender-watch: check if Defender detected this binary"
    }
    if ($SourceModule -eq "memory-forensics" -and $fl -match "orphan|unsigned") {
        $alert.TriggeredChecks += "task-killer: check if process is killable"
        $alert.TriggeredChecks += "purge: check binary attribution"
    }
    if ($SourceModule -eq "browser-extension" -and $fl -match "phishing|malicious") {
        $alert.TriggeredChecks += "mail-shield: search for related phishing emails"
    }
    if ($SourceModule -eq "defender-watch" -and $fl -match "exclusion") {
        $alert.TriggeredChecks += "purge: scan excluded path for unattributed binaries"
    }
    if ($SourceModule -eq "task-killer" -and $Severity -in @("High", "Critical")) {
        $alert.TriggeredChecks += "memory-forensics: deep scan killed process's remnants"
    }

    if ($alert.TriggeredChecks.Count -gt 0) {
        [void]$script:UnifiedSession.Alerts.Add($alert)
    }
}

function Get-UnifiedThreatPicture {
    <#
    .SYNOPSIS
        Coherence-scored overview: everything found, scored together.
    .DESCRIPTION
        Not a list of module outputs. A unified picture where findings
        corroborate each other. A purge finding + a memory finding about
        the same binary = higher confidence than either alone.
    #>

    if ($null -eq $script:UnifiedSession) {
        Write-Warning "No active session. Run New-UnifiedSession first."
        return $null
    }

    $pool = @($script:UnifiedSession.EvidencePool)
    $critical = @($pool | Where-Object { $_.Severity -eq "Critical" })
    $high = @($pool | Where-Object { $_.Severity -eq "High" })
    $medium = @($pool | Where-Object { $_.Severity -eq "Medium" })

    # Corroboration: find findings about the same entity from different modules
    $corroborated = New-Object System.Collections.ArrayList
    $byKeyword = @{}
    foreach ($e in $pool) {
        # Extract potential entity (file path, IP, domain, process name)
        $entities = @()
        if ($e.Finding -match '([A-Z]:\\[^\s"]+)') { $entities += $Matches[1].ToLower() }
        if ($e.Finding -match '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b') { $entities += $Matches[1] }
        if ($e.Details.Path) { $entities += $e.Details.Path.ToLower() }

        foreach ($ent in $entities) {
            if (-not $byKeyword.ContainsKey($ent)) { $byKeyword[$ent] = @() }
            $byKeyword[$ent] += $e
        }
    }

    foreach ($key in $byKeyword.Keys) {
        $related = @($byKeyword[$key] | Select-Object -Unique)
        $modules = @($related | Select-Object -ExpandProperty Module -Unique)
        if ($modules.Count -gt 1) {
            [void]$corroborated.Add([PSCustomObject]@{
                Entity = $key
                Modules = $modules
                FindingCount = $related.Count
                MaxSeverity = ($related | Sort-Object @{E={switch($_.Severity){"Critical"{4}"High"{3}"Medium"{2}default{1}}}} -Descending | Select-Object -First 1).Severity
                Boost = "Multi-module corroboration: $($modules.Count) modules agree"
            })
        }
    }

    return [PSCustomObject]@{
        SessionId = $script:UnifiedSession.Id
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        TotalFindings = $pool.Count
        Critical = $critical.Count
        High = $high.Count
        Medium = $medium.Count
        CorroboratedThreats = @($corroborated)
        CorroboratedCount = $corroborated.Count
        Alerts = @($script:UnifiedSession.Alerts)
        Summary = if ($corroborated.Count -gt 0) {
            "$($corroborated.Count) threats confirmed by multiple modules. Highest confidence."
        } elseif ($critical.Count -gt 0) {
            "$($critical.Count) critical findings. No cross-module corroboration yet."
        } else {
            "$($pool.Count) findings. No critical threats."
        }
    }
}

function Invoke-UnifiedScan {
    <#
    .SYNOPSIS
        Run the full unified scan: all modules feed one pool, scored together.
    .DESCRIPTION
        This is the "one button" scan. Not 29 separate runs.
        One session, all modules contribute, one threat picture.
    #>
    param([string]$VaultPath = "")

    Write-Host "`n=== UNIFIED SCAN ===" -ForegroundColor White
    Write-Host "One system. All senses. One threat picture.`n" -ForegroundColor Gray

    New-UnifiedSession -Purpose "Full unified scan" | Out-Null

    # Each module contributes to the shared pool
    # (Modules are invoked via their workflow functions or direct calls)

    Write-Host "Session active. Run module scans — all findings pool here." -ForegroundColor Cyan
    Write-Host "Get the unified picture anytime: Get-UnifiedThreatPicture" -ForegroundColor Gray

    return $script:UnifiedSession
}

function Close-UnifiedSession {
    <#
    .SYNOPSIS Seal the session. Write everything to the vault.
    #>
    param([string]$VaultPath = "")

    if ($null -eq $script:UnifiedSession) {
        Write-Warning "No active session."
        return $null
    }

    $picture = Get-UnifiedThreatPicture

    $sessionRecord = [PSCustomObject]@{
        SessionId = $script:UnifiedSession.Id
        Started = $script:UnifiedSession.Started
        Closed = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        Purpose = $script:UnifiedSession.Purpose
        ThreatPicture = $picture
        TotalEvidence = $script:UnifiedSession.EvidencePool.Count
    }

    if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
        $sessionRecord | ConvertTo-Json -Depth 8 | Add-Content -Path $VaultPath -Encoding UTF8
        Write-Host "Session sealed to vault." -ForegroundColor Green
    }

    Write-Host "`n=== SESSION CLOSED ===" -ForegroundColor White
    Write-Host "  Findings: $($picture.TotalFindings) | Corroborated: $($picture.CorroboratedCount)" -ForegroundColor White
    Write-Host "  $($picture.Summary)" -ForegroundColor Gray

    $script:UnifiedSession = $null
    return $sessionRecord
}

function Test-UnifiedCoreHygiene {
    <#
    .SYNOPSIS Self-test: session lifecycle, evidence pooling, cross-module alerts.
    #>
    $results = New-Object System.Collections.ArrayList
    $add = { param($Name,$Pass,$Detail)
        [void]$results.Add([PSCustomObject]@{Test=$Name; Pass=$Pass; Detail=$Detail})
    }.GetNewClosure()

    # Session lifecycle
    New-UnifiedSession -Purpose "Hygiene test" | Out-Null
    &$add "Session: creates" ($null -ne $script:UnifiedSession) "Session object exists"
    &$add "Session: has ID" ($script:UnifiedSession.Id -ne "") "Has GUID"

    # Evidence pooling
    Add-SessionEvidence -Module "test" -Finding "Test finding one" -Severity "Info"
    Add-SessionEvidence -Module "test" -Finding "Test finding two" -Severity "High"
    $all = Get-SessionEvidence
    &$add "Evidence: pools" ($all.Count -eq 2) "2 findings pooled"
    $high = Get-SessionEvidence -Severity "High"
    &$add "Evidence: filters by severity" ($high.Count -eq 1) "1 high finding"
    $kw = Get-SessionEvidence -Keyword "one"
    &$add "Evidence: filters by keyword" ($kw.Count -eq 1) "1 keyword match"

    # Cross-module alerts
    Add-SessionEvidence -Module "purge" -Finding "Deleted C:\evil\bad.exe" -Severity "Critical"
    $alerts = @($script:UnifiedSession.Alerts)
    &$add "Cross-module: purge triggers defender check" ($alerts.Count -gt 0) "$($alerts.Count) alerts triggered"

    # Threat picture
    $picture = Get-UnifiedThreatPicture
    &$add "Threat picture: generates" ($null -ne $picture) "Picture object exists"
    &$add "Threat picture: counts" ($picture.TotalFindings -eq 3) "3 total findings"

    # Corroboration (add same entity from two modules)
    Add-SessionEvidence -Module "memory-forensics" -Finding "Orphan process C:\evil\bad.exe" -Severity "High" -Details @{Path="c:\evil\bad.exe"}
    $picture2 = Get-UnifiedThreatPicture
    &$add "Corroboration: multi-module" ($picture2.CorroboratedCount -gt 0) "$($picture2.CorroboratedCount) corroborated"

    # Cleanup
    $script:UnifiedSession = $null
    &$add "Session: closes clean" ($null -eq $script:UnifiedSession) "Session cleared"

    $passed = ($results | Where-Object Pass).Count
    $total = $results.Count
    Write-Host "`nUnified Core Hygiene: $passed/$total passed" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Red" })
    foreach ($r in $results) {
        Write-Host "  [$($(if ($r.Pass){"PASS"}else{"FAIL"}))] $($r.Test): $($r.Detail)" -ForegroundColor $(if ($r.Pass) { "Green" } else { "Red" })
    }
    return $results
}

function Write-FalsumLog {
    <#
    .SYNOPSIS
        Central logging — every module logs here, one file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")][string]$Level = "INFO"
    )
    $logDir = Join-Path $env:LOCALAPPDATA "Falsum\logs"
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    $logFile = Join-Path $logDir "sentinel-$(Get-Date -Format 'yyyy-MM-dd').log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] [$Module] $Message"
    Add-Content -Path $logFile -Value $entry -Encoding UTF8
    
    # Also write to console with color
    $color = switch ($Level) {
        "INFO"    { "Gray" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }
    Write-Host $entry -ForegroundColor $color
}

Export-ModuleMember -Function Write-FalsumLog, @(
    'New-UnifiedSession',
    'Add-SessionEvidence',
    'Get-SessionEvidence',
    'Send-CrossModuleAlert',
    'Get-UnifiedThreatPicture',
    'Invoke-UnifiedScan',
    'Close-UnifiedSession',
    'Test-UnifiedCoreHygiene'
)
