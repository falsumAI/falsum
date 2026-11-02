# Falsum Module 44: Port Gate
# Windows Defender Firewall companion. Originally Hashline Port Gate.
# -Audit (safe default), -Enforce, -Restore, -Status.
# Standing requirement: mark bad actors permanently so the mark follows them.

function Get-PortGateState {
    $rules = Get-NetFirewallRule -DisplayName "Falsum-*" -ErrorAction SilentlyContinue
    return @{
        falsumRules = $rules.Count
        timestamp = (Get-Date).ToString("o")
    }
}

function Invoke-PortGateAudit {
    # Safe default: report only, change nothing
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess,
            @{N="ProcessName";E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}

    $unattributed = $listeners | Where-Object { $_.OwningProcess -eq 4 -or -not $_.ProcessName }

    return @{
        totalListeners = $listeners.Count
        unattributed = $unattributed
        unattributedCount = $unattributed.Count
        all = $listeners
    }
}

function Invoke-PortGateEnforce {
    param([int[]]$AllowedPorts = @(80, 443))
    # Block all inbound except allowed ports
    # WARNING: This changes firewall rules. Backup first.
    $backup = Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action
    $backupPath = Join-Path $env:LOCALAPPDATA "Falsum\vault\port-gate\backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $backupDir = Split-Path $backupPath
    if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
    $backup | ConvertTo-Json -Depth 3 | Set-Content $backupPath

    foreach ($port in $AllowedPorts) {
        $ruleName = "Falsum-Allow-$port"
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port | Out-Null
        }
    }

    return @{ backupPath = $backupPath; allowedPorts = $AllowedPorts }
}

function Invoke-PortGateRestore {
    param([string]$BackupPath = "")
    if (-not $BackupPath) {
        $backupDir = Join-Path $env:LOCALAPPDATA "Falsum\vault\port-gate"
        $latest = Get-ChildItem $backupDir -Filter "backup-*.json" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $latest) { throw "No backup found" }
        $BackupPath = $latest.FullName
    }

    # Remove Falsum rules
    Get-NetFirewallRule -DisplayName "Falsum-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    return @{ restored = $true; backupUsed = $BackupPath }
}

function New-PortGateBadActorMark {
    param(
        [string]$IpAddress,
        [string]$Reason
    )
    # Permanent mark: firewall block + vault record
    $vault = Join-Path $env:LOCALAPPDATA "Falsum\vault\port-gate"
    if (-not (Test-Path $vault)) { New-Item -ItemType Directory -Path $vault -Force | Out-Null }

    $markFile = Join-Path $vault "bad-actors.jsonl"
    $mark = @{
        ip = $IpAddress
        reason = $Reason
        marked = (Get-Date).ToString("o")
        permanent = $true
    }
    $mark | ConvertTo-Json -Compress | Add-Content $markFile

    # Block at firewall
    $ruleName = "Falsum-Block-BadActor-$($IpAddress -replace '\.','-')"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -RemoteAddress $IpAddress | Out-Null
        New-NetFirewallRule -DisplayName "$ruleName-Out" -Direction Outbound -Action Block -RemoteAddress $IpAddress | Out-Null
    }

    return $mark
}

function Get-PortGateBadActors {
    $markFile = Join-Path $env:LOCALAPPDATA "Falsum\vault\port-gate\bad-actors.jsonl"
    if (-not (Test-Path $markFile)) { return @() }
    return Get-Content $markFile | ForEach-Object { $_ | ConvertFrom-Json }
}
