# Falsum Module 45: Router Tracker
# Captures router login events. Originally a standalone MV3 extension.
# User installs, tries 10.0.0.1 login with log open, exports JSON.

function Get-RouterTrackerVaultPath {
    $base = Join-Path $env:LOCALAPPDATA "Falsum\vault\router-tracker"
    if (-not (Test-Path $base)) { New-Item -ItemType Directory -Path $base -Force | Out-Null }
    return $base
}

function New-RouterLoginEntry {
    param(
        [string]$RouterIp,
        [string]$Username,
        [bool]$Success,
        [string]$UserAgent = "",
        [string]$Details = ""
    )
    $vault = Get-RouterTrackerVaultPath
    $logFile = Join-Path $vault "logins.jsonl"

    # NEVER store passwords
    $entry = @{
        ts = (Get-Date).ToString("o")
        routerIp = $RouterIp
        username = $Username
        success = $Success
        userAgent = $UserAgent
        details = $Details
    }

    $entry | ConvertTo-Json -Compress | Add-Content $logFile
    return $entry
}

function Get-RouterLoginHistory {
    param([int]$LastN = 100)
    $vault = Get-RouterTrackerVaultPath
    $logFile = Join-Path $vault "logins.jsonl"
    if (-not (Test-Path $logFile)) { return @() }
    return Get-Content $logFile -Tail $LastN | ForEach-Object { $_ | ConvertFrom-Json }
}

function Test-RouterLoginAnomaly {
    # Flag suspicious patterns: multiple failures, unusual times, unknown agents
    $history = Get-RouterLoginHistory -LastN 100
    if ($history.Count -eq 0) { return @{ anomalies = @(); message = "No login history" } }

    $anomalies = @()

    $failures = $history | Where-Object { $_.success -eq $false }
    if ($failures.Count -gt 5) {
        $anomalies += "Multiple failed logins ($($failures.Count)) - possible brute force"
    }

    $recentAgents = $history | Select-Object -ExpandProperty userAgent -Unique
    if ($recentAgents.Count -gt 3) {
        $anomalies += "Multiple different user agents ($($recentAgents.Count)) - possible unauthorized access"
    }

    $nightLogins = $history | Where-Object {
        $hour = ([datetime]$_.ts).Hour
        $hour -lt 5 -or $hour -gt 23
    }
    if ($nightLogins.Count -gt 0) {
        $anomalies += "$($nightLogins.Count) logins during unusual hours (11pm-5am)"
    }

    return @{
        anomalies = $anomalies
        totalLogins = $history.Count
        failedLogins = $failures.Count
    }
}

function Export-RouterTrackerJson {
    param([string]$OutputPath = "")
    if (-not $OutputPath) {
        $OutputPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "router-logins-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    }

    $history = Get-RouterLoginHistory -LastN 1000
    $anomalies = Test-RouterLoginAnomaly

    @{
        exported = (Get-Date).ToString("o")
        anomalyCheck = $anomalies
        logins = $history
    } | ConvertTo-Json -Depth 10 | Set-Content $OutputPath

    return $OutputPath
}
