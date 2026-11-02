# Falsum Module 42: Agent Watchdog
# Bodycam for AI agents on the user's property.
# Tamper-evident SHA-384 hash-chained log. Human vs agent via event.isTrusted.
# Originally a standalone MV3 extension (v0.6.0). Now integrated into Falsum.
# Hard line: no agents in the browser, period. End consumer first.

function Get-AgentWatchdogVaultPath {
    $base = Join-Path $env:LOCALAPPDATA "Falsum\vault\agent-watchdog"
    if (-not (Test-Path $base)) { New-Item -ItemType Directory -Path $base -Force | Out-Null }
    return $base
}

function New-WatchdogEntry {
    param(
        [string]$Category,
        [string]$Action,
        [bool]$IsTrusted,
        [string]$Page = "",
        [string]$Target = "",
        [string]$Details = ""
    )
    $vault = Get-AgentWatchdogVaultPath
    $chainFile = Join-Path $vault "chain.jsonl"

    $prev = "AW-GENESIS"
    if (Test-Path $chainFile) {
        $lastLine = Get-Content $chainFile -Tail 1 -ErrorAction SilentlyContinue
        if ($lastLine) {
            $lastEntry = $lastLine | ConvertFrom-Json
            $prev = $lastEntry.hash
        }
    }

    $entry = @{
        seq = (Get-Date).ToFileTimeUtc()
        t = (Get-Date).ToString("o")
        cat = $Category
        act = $Action
        trusted = $IsTrusted
        agent = (-not $IsTrusted)  # Untrusted events = potential agent activity
        page = $Page
        target = $Target
        details = $Details
        prev = $prev
    }

    $canonical = "$($entry.seq)|$($entry.t)|$($entry.cat)|$($entry.act)|$($entry.trusted)|$($entry.page)|$($entry.target)|$($entry.prev)"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("$canonical|$prev")
    $sha384 = [System.Security.Cryptography.SHA384]::Create()
    $hashBytes = $sha384.ComputeHash($bytes)
    $entry.hash = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""

    $entry | ConvertTo-Json -Compress | Add-Content $chainFile

    # Alert on agent activity
    if ($entry.agent) {
        Write-Warning "AGENT ACTIVITY DETECTED: $($entry.act) on $($entry.page)"
    }

    return $entry
}

function Get-WatchdogAgentActivity {
    param([int]$LastN = 50)
    $vault = Get-AgentWatchdogVaultPath
    $chainFile = Join-Path $vault "chain.jsonl"
    if (-not (Test-Path $chainFile)) { return @() }

    $entries = Get-Content $chainFile -Tail $LastN | ForEach-Object { $_ | ConvertFrom-Json }
    return $entries | Where-Object { $_.agent -eq $true }
}

function Test-WatchdogChain {
    $vault = Get-AgentWatchdogVaultPath
    $chainFile = Join-Path $vault "chain.jsonl"
    if (-not (Test-Path $chainFile)) { return @{ ok = $true; count = 0 } }

    $lines = Get-Content $chainFile
    $prevHash = $null
    $count = 0

    foreach ($line in $lines) {
        $entry = $line | ConvertFrom-Json
        $canonical = "$($entry.seq)|$($entry.t)|$($entry.cat)|$($entry.act)|$($entry.trusted)|$($entry.page)|$($entry.target)|$($entry.prev)"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes("$canonical|$($entry.prev)")
        $sha384 = [System.Security.Cryptography.SHA384]::Create()
        $hashBytes = $sha384.ComputeHash($bytes)
        $computed = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""

        if ($computed -ne $entry.hash) {
            return @{ ok = $false; count = $count; message = "Tamper detected at entry $count" }
        }
        if ($count -gt 0 -and $entry.prev -ne $prevHash) {
            return @{ ok = $false; count = $count; message = "Chain broken at entry $count" }
        }
        $prevHash = $entry.hash
        $count++
    }
    return @{ ok = $true; count = $count }
}

function Export-WatchdogEvidencePack {
    param([string]$OutputPath = "")
    $vault = Get-AgentWatchdogVaultPath
    $chainFile = Join-Path $vault "chain.jsonl"
    if (-not (Test-Path $chainFile)) { throw "No watchdog data to export" }

    if (-not $OutputPath) {
        $OutputPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "watchdog-evidence-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    }

    $entries = Get-Content $chainFile | ForEach-Object { $_ | ConvertFrom-Json }
    $verification = Test-WatchdogChain

    $pack = @{
        exported = (Get-Date).ToString("o")
        chainValid = $verification.ok
        entryCount = $verification.count
        agentActivityCount = ($entries | Where-Object { $_.agent }).Count
        entries = $entries
    }

    $pack | ConvertTo-Json -Depth 10 | Set-Content $OutputPath
    return $OutputPath
}
