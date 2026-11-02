# Falsum Module 43: Hashline
# Browser-traffic hasher. SHA-256 per body, SHA-384 hash-chained ledger.
# Originally standalone (v3.1). Now integrated into Falsum.
# Standing requirement: data integrity checked before traffic leaves the router.

function Get-HashlineVaultPath {
    $base = Join-Path $env:LOCALAPPDATA "Falsum\vault\hashline"
    if (-not (Test-Path $base)) { New-Item -ItemType Directory -Path $base -Force | Out-Null }
    return $base
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha256.ComputeHash($Bytes)
    return ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
}

function New-HashlineEntry {
    param(
        [string]$Url,
        [string]$Method = "GET",
        [byte[]]$Body = @(),
        [string]$RemoteIp = "",
        [int]$RemotePort = 0
    )
    $vault = Get-HashlineVaultPath
    $chainFile = Join-Path $vault "chain.jsonl"

    $bodyHash = if ($Body.Length -gt 0) { Get-Sha256Hex $Body } else { "" }

    $prev = "HL-GENESIS"
    if (Test-Path $chainFile) {
        $lastLine = Get-Content $chainFile -Tail 1 -ErrorAction SilentlyContinue
        if ($lastLine) {
            $prev = ($lastLine | ConvertFrom-Json).hash
        }
    }

    $entry = @{
        ts = (Get-Date).ToString("o")
        url = $Url
        method = $Method
        bodyHash = $bodyHash
        bodyLength = $Body.Length
        remoteIp = $RemoteIp
        remotePort = $RemotePort
        prev = $prev
    }

    $canonical = "$($entry.ts)|$($entry.url)|$($entry.method)|$($entry.bodyHash)|$($entry.bodyLength)|$($entry.remoteIp)|$($entry.remotePort)|$($entry.prev)"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("$canonical|$prev")
    $sha384 = [System.Security.Cryptography.SHA384]::Create()
    $hashBytes = $sha384.ComputeHash($bytes)
    $entry.hash = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""

    $entry | ConvertTo-Json -Compress | Add-Content $chainFile
    return $entry
}

function Test-HashlineIntegrity {
    param(
        [byte[]]$Data,
        [string]$ExpectedHash
    )
    $actual = Get-Sha256Hex $Data
    return @{
        match = ($actual -eq $ExpectedHash)
        expected = $ExpectedHash
        actual = $actual
    }
}

# AI endpoint directory - known AI service domains for traffic labeling
$script:AIEndpoints = @(
    "chat.openai.com", "api.openai.com",
    "claude.ai", "api.anthropic.com",
    "gemini.google.com", "generativelanguage.googleapis.com",
    "copilot.microsoft.com", "copilot.cloud.microsoft",
    "grok.x.ai", "api.x.ai",
    "chat.deepseek.com", "api.deepseek.com",
    "meta.ai", "www.meta.ai"
)

function Test-IsAIEndpoint {
    param([string]$Url)
    foreach ($domain in $script:AIEndpoints) {
        if ($Url -like "*$domain*") { return $true }
    }
    return $false
}

function Get-HashlineStats {
    $vault = Get-HashlineVaultPath
    $chainFile = Join-Path $vault "chain.jsonl"
    if (-not (Test-Path $chainFile)) { return @{ entries = 0 } }

    $entries = Get-Content $chainFile | ForEach-Object { $_ | ConvertFrom-Json }
    $aiTraffic = $entries | Where-Object { Test-IsAIEndpoint $_.url }
    $nonStandardPorts = $entries | Where-Object { $_.remotePort -ne 80 -and $_.remotePort -ne 443 -and $_.remotePort -ne 0 }

    return @{
        totalEntries = $entries.Count
        aiEndpoints = $aiTraffic.Count
        nonStandardPorts = $nonStandardPorts.Count
        flaggedPorts = $nonStandardPorts | Select-Object url, remoteIp, remotePort -First 20
    }
}
