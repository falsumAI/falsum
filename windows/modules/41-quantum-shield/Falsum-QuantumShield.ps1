# Falsum Module 41: Quantum Shield
# Witness-only transmission logging with SHA-384 hash-chained ledger.
# Originally a standalone MV3 extension (v6). Now integrated into Falsum.
# v6 is witness-only: redaction is OUT. It logs what leaves, doesn't modify it.

function Get-QuantumShieldVaultPath {
    $base = Join-Path $env:LOCALAPPDATA "Falsum\vault\quantum-shield"
    if (-not (Test-Path $base)) { New-Item -ItemType Directory -Path $base -Force | Out-Null }
    return $base
}

function New-QuantumShieldEntry {
    param(
        [string]$Site,
        [string]$Endpoint,
        [string]$BodyHash,
        [int]$BodyLength
    )
    $vault = Get-QuantumShieldVaultPath
    $chainFile = Join-Path $vault "chain.jsonl"

    # Get previous hash
    $prev = "QS-GENESIS"
    if (Test-Path $chainFile) {
        $lastLine = Get-Content $chainFile -Tail 1 -ErrorAction SilentlyContinue
        if ($lastLine) {
            $lastEntry = $lastLine | ConvertFrom-Json
            $prev = $lastEntry.hash
        }
    }

    $entry = @{
        i = (Get-Date).ToFileTimeUtc()
        ts = (Get-Date).ToString("o")
        site = $Site
        endpoint = $Endpoint
        bodyLength = $BodyLength
        bodyHash = $BodyHash
        prev = $prev
    }

    # SHA-384(canonical + "|" + prev)
    $canonical = "$($entry.i)|$($entry.ts)|$($entry.site)|$($entry.endpoint)|$($entry.bodyLength)|$($entry.bodyHash)|$($entry.prev)"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("$canonical|$prev")
    $sha384 = [System.Security.Cryptography.SHA384]::Create()
    $hashBytes = $sha384.ComputeHash($bytes)
    $entry.hash = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""

    $entry | ConvertTo-Json -Compress | Add-Content $chainFile
    return $entry
}

function Test-QuantumShieldChain {
    $vault = Get-QuantumShieldVaultPath
    $chainFile = Join-Path $vault "chain.jsonl"
    if (-not (Test-Path $chainFile)) { return @{ ok = $true; count = 0; message = "No entries yet" } }

    $lines = Get-Content $chainFile
    $prevHash = $null
    $count = 0

    foreach ($line in $lines) {
        $entry = $line | ConvertFrom-Json
        $canonical = "$($entry.i)|$($entry.ts)|$($entry.site)|$($entry.endpoint)|$($entry.bodyLength)|$($entry.bodyHash)|$($entry.prev)"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes("$canonical|$($entry.prev)")
        $sha384 = [System.Security.Cryptography.SHA384]::Create()
        $hashBytes = $sha384.ComputeHash($bytes)
        $computed = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""

        if ($computed -ne $entry.hash) {
            return @{ ok = $false; count = $count; message = "Hash mismatch at entry $count - chain broken" }
        }
        if ($count -gt 0 -and $entry.prev -ne $prevHash) {
            return @{ ok = $false; count = $count; message = "Chain link broken at entry $count" }
        }
        $prevHash = $entry.hash
        $count++
    }

    return @{ ok = $true; count = $count; message = "Chain verified: $count entries" }
}

function Get-QuantumShieldStats {
    $vault = Get-QuantumShieldVaultPath
    $chainFile = Join-Path $vault "chain.jsonl"
    if (-not (Test-Path $chainFile)) { return @{ entries = 0; sites = @() } }

    $entries = Get-Content $chainFile | ForEach-Object { $_ | ConvertFrom-Json }
    $sites = $entries | Group-Object site | Select-Object Name, Count
    return @{
        entries = $entries.Count
        sites = $sites
        lastEntry = $entries[-1].ts
    }
}
