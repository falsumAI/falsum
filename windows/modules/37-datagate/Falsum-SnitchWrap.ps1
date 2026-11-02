# Falsum Snitch Wrapper for DataGate (Module 37)
# Uses Snitch (github.com/henrypp/snitch, AGPL) — WRAP, DON'T BUNDLE.
# Snitch is AGPL: we call it as a separate process, we don't embed its code.
# Falsum orchestrates: detects Snitch, uses its connection data, adds our vault + user-approval layer.

function Get-SnitchPath {
    # Check common install locations — we don't bundle it, user installs separately
    $paths = @(
        "$env:ProgramFiles\Snitch\snitch.exe",
        "$env:LOCALAPPDATA\Falsum\tools\snitch.exe",
        (Get-Command snitch -ErrorAction SilentlyContinue).Source
    )
    foreach ($p in $paths) {
        if ($p -and (Test-Path $p)) { return $p }
    }
    return $null
}

function Install-SnitchGuide {
    # We can't bundle AGPL code. Guide the user to install it themselves.
    return @"
Snitch is not bundled with Falsum (AGPL license).
To enable deep packet inspection in DataGate:

1. Download Snitch from https://github.com/henrypp/snitch/releases
2. Install it (it's free and open source)
3. Falsum will detect it automatically and use its data

Until then, Falsum uses Windows built-in connection tracking (Get-NetTCPConnection).
"@
}

function Get-FalsumDataGateWithSnitch {
    $snitch = Get-SnitchPath

    if (-not $snitch) {
        Write-Host (Install-SnitchGuide) -ForegroundColor Yellow
        # Fall back to built-in
        return Start-FalsumDataGate -Monitor
    }

    Write-Host "Snitch detected at $snitch — using deep inspection mode." -ForegroundColor Green

    # Get Falsum's own connection data
    $falsumData = Start-FalsumDataGate -Monitor

    # Note: Snitch runs as its own UI. We read its log if available.
    $snitchLog = "$env:LOCALAPPDATA\Snitch\log.csv"
    $snitchEntries = @()
    if (Test-Path $snitchLog) {
        $snitchEntries = Import-Csv $snitchLog -ErrorAction SilentlyContinue |
            Select-Object -Last 100
    }

    return @{
        falsumConnections = $falsumData
        snitchAvailable = $true
        snitchLogEntries = $snitchEntries.Count
        note = "Snitch provides per-app firewall rules. Falsum provides the vault + approval audit trail."
    }
}

function New-FalsumDataApproval {
    param(
        [string]$ProcessName,
        [string]$RemoteAddress,
        [int]$RemotePort,
        [bool]$Approved
    )
    # User's egress decisions go in the vault — permanent record
    $vault = Join-Path $env:LOCALAPPDATA "Falsum\vault\datagate"
    if (-not (Test-Path $vault)) { New-Item -ItemType Directory -Path $vault -Force | Out-Null }

    $decision = @{
        ts = (Get-Date).ToString("o")
        process = $ProcessName
        remote = "$RemoteAddress`:$RemotePort"
        approved = $Approved
    }

    $decision | ConvertTo-Json -Compress | Add-Content (Join-Path $vault "approvals.jsonl")
    return $decision
}

function Get-FalsumDataApprovals {
    param([int]$LastN = 50)
    $file = Join-Path $env:LOCALAPPDATA "Falsum\vault\datagate\approvals.jsonl"
    if (-not (Test-Path $file)) { return @() }
    return Get-Content $file -Tail $LastN | ForEach-Object { $_ | ConvertFrom-Json }
}
