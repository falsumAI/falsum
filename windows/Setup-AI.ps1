<#
.SYNOPSIS
    Falsum AI Setup — downloads the local model and the llama.cpp server.

.DESCRIPTION
    One-command local-AI bootstrap for the Falsum installer. Installs into
    %LOCALAPPDATA%\Falsum (the paths the C# app actually looks at):

        ai\model.gguf           <- GGUF weights, tier-selected by RAM
        ai\model.info.json      <- what was installed, when, from where
        tools\llama-server.exe  <- llama.cpp server binary
        Start-AI.bat            <- launcher: server on localhost:8080

    RAM tiers (per docs/NATIVE-INTELLIGENCE.md):
        >= 8GB RAM : Phi-4-mini-instruct Q4_K_M  (3.8B, 128K ctx, MIT, ungated)
        4-8GB RAM  : Llama 3.2 3B Q4_K_M with -HfToken, else Qwen2.5-3B Q4_K_M (ungated)
        < 4GB RAM  : Gemma 3 1B Q4_K_M with -HfToken, else Qwen2.5-1.5B Q4_K_M (ungated)

    Llama 3.2 and Gemma 3 are gated on HuggingFace (their licenses require
    accepting terms on the site). Without -HfToken the script uses the
    ungated Qwen tiers instead and says so — it never pretends a download
    succeeded when the server returned 401/403.

    Robustness (every one of these burned us before):
    - No pinned llama.cpp build number: resolves the latest release asset
      via the GitHub API (pinned URLs 404 as soon as a new release ships).
    - Resumable download: HttpClient + Range resume with progress first,
      async BITS with a stall guard as fallback. Sync Start-BitsTransfer
      hung forever on stalled connections; the guard cancels loudly.
    - Integrity: verifies Content-Length against the final file size and
      checks the GGUF magic bytes ("GGUF") before calling it done.
    - Disk-space check before starting a multi-GB download.
    - TLS 1.2 forced for PowerShell 5.1.

    The model runs LOCALLY. No cloud. No tokens. No metering.
    Per Gregg's native-intelligence directive, the deterministic code is
    the authority and the local model is the mouthpiece — it never decides
    truth, it explains what the coherence engine already verified.
#>

[CmdletBinding()]
param(
    [ValidateSet('Auto', 'Phi4Mini', 'Llama3B', 'Qwen3B', 'Gemma1B', 'Qwen1_5B')]
    [string]$ModelTier = 'Auto',

    [string]$HfToken = '',        # HuggingFace token for gated repos (Llama 3.2, Gemma 3)

    [string]$ModelUrl = '',       # Override: any HuggingFace GGUF resolve URL

    [switch]$SkipModel,           # Install the server only
    [switch]$SkipServer,          # Install the model only
    [switch]$SmokeTest,           # Start the server, hit /health, shut it down
    [switch]$NonInteractive       # Installer mode: no prompts, no ReadKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# PowerShell 5.1 negotiates TLS 1.0/1.1 by default; HuggingFace and GitHub
# require 1.2+. Forcing this here is the difference between "it worked on
# my machine" and "it worked on Gregg's machine".
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:FalsumDir = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Falsum'
$script:AIDir     = Join-Path $script:FalsumDir 'ai'
$script:ToolsDir  = Join-Path $script:FalsumDir 'tools'
$script:ModelPath = Join-Path $script:AIDir 'model.gguf'
$script:ServerExe = Join-Path $script:ToolsDir 'llama-server.exe'

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

function Write-Step {
    param([string]$Msg, [string]$Color = 'Cyan')
    Write-Host "[AI Setup] $Msg" -ForegroundColor $Color
}

function Get-TotalMemoryGB {
    <# Returns installed RAM in GB. CIM first, WMI fallback for old hosts. #>
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        return [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    }
    catch {
        try {
            $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
            return [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        }
        catch {
            throw 'Could not detect installed RAM. Pass -ModelTier explicitly to skip detection.'
        }
    }
}

function Get-FreeSpaceGB {
    param([string]$Path)
    $drive = (Get-Item $Path -ErrorAction SilentlyContinue).PSDrive.Name
    if (-not $drive) { $drive = $Path.Substring(0, 1) }
    return [math]::Round((Get-PSDrive $drive -ErrorAction Stop).Free / 1GB, 1)
}

# ---------------------------------------------------------------------------
# Model tiers
# ---------------------------------------------------------------------------

function Get-ModelSpec {
    <#
    .SYNOPSIS
        Pick the model for this machine. Returns Name, Repo, File, Url,
        ApproxSizeGB, NeedsToken, Why.
    #>
    param(
        [string]$Tier,
        [double]$RamGB,
        [string]$Token
    )

    $specs = @{
        Phi4Mini = @{
            Name = 'Phi-4-mini-instruct (3.8B)'
            Repo = 'bartowski/microsoft_Phi-4-mini-instruct-GGUF'
            File = 'Phi-4-mini-instruct-Q4_K_M.gguf'
            ApproxSizeGB = 2.5; NeedsToken = $false
            Why = 'primary pick: 128K context, strong reasoning, MIT-licensed, ungated'
        }
        Llama3B = @{
            Name = 'Llama 3.2 3B Instruct'
            Repo = 'bartowski/Llama-3.2-3B-Instruct-GGUF'
            File = 'Llama-3.2-3B-Instruct-Q4_K_M.gguf'
            ApproxSizeGB = 1.9; NeedsToken = $true
            Why = 'documented fallback tier (gated: needs -HfToken)'
        }
        Qwen3B = @{
            Name = 'Qwen2.5-3B-Instruct'
            Repo = 'bartowski/Qwen2.5-3B-Instruct-GGUF'
            File = 'Qwen2.5-3B-Instruct-Q4_K_M.gguf'
            ApproxSizeGB = 1.9; NeedsToken = $false
            Why = 'ungated fallback for 4-8GB machines (Apache 2.0)'
        }
        Gemma1B = @{
            Name = 'Gemma 3 1B IT'
            Repo = 'bartowski/gemma-3-1b-it-GGUF'
            File = 'gemma-3-1b-it-Q4_K_M.gguf'
            ApproxSizeGB = 0.8; NeedsToken = $true
            Why = 'documented tight-memory tier (gated: needs -HfToken)'
        }
        Qwen1_5B = @{
            Name = 'Qwen2.5-1.5B-Instruct'
            Repo = 'bartowski/Qwen2.5-1.5B-Instruct-GGUF'
            File = 'Qwen2.5-1.5B-Instruct-Q4_K_M.gguf'
            ApproxSizeGB = 1.0; NeedsToken = $false
            Why = 'ungated tight-memory tier (Apache 2.0)'
        }
    }

    if ($Tier -eq 'Auto') {
        if ($RamGB -ge 8)    { $Tier = 'Phi4Mini' }
        elseif ($RamGB -ge 4) { $Tier = 'Qwen3B' }
        else                  { $Tier = 'Qwen1_5B' }
    }

    # Gated repos need a token; without one, step down to the ungated
    # equivalent instead of downloading an HTML 401 page and calling it
    # a model.
    $spec = $specs[$Tier]
    if ($spec.NeedsToken -and [string]::IsNullOrWhiteSpace($Token)) {
        if ($Tier -eq 'Llama3B') {
            Write-Step "Llama 3.2 is gated on HuggingFace and no -HfToken was given; using Qwen2.5-3B (ungated) instead." 'Yellow'
            $spec = $specs['Qwen3B']
        }
        elseif ($Tier -eq 'Gemma1B') {
            Write-Step "Gemma 3 is gated on HuggingFace and no -HfToken was given; using Qwen2.5-1.5B (ungated) instead." 'Yellow'
            $spec = $specs['Qwen1_5B']
        }
    }

    $spec['Url'] = "https://huggingface.co/$($spec.Repo)/resolve/main/$($spec.File)"
    return $spec
}

function Get-HfHeaders {
    param([string]$Token)
    $h = @{ 'User-Agent' = 'Falsum-AI-Setup/1.0 (+https://github.com/falsumAI/falsum)' }
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $h['Authorization'] = "Bearer $Token"
    }
    return $h
}

# ---------------------------------------------------------------------------
# Download engine: HttpClient (resumable) -> BITS (async, stall-guarded)
# ---------------------------------------------------------------------------

function Get-RemoteFileSize {
    <# HEAD request for Content-Length. Returns 0 when unknown. #>
    param([string]$Url, [hashtable]$Headers)
    try {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $client = New-Object System.Net.Http.HttpClient($handler)
        foreach ($k in $Headers.Keys) {
            if ($k -ne 'Authorization') { $client.DefaultRequestHeaders.Add($k, $Headers[$k]) }
        }
        if ($Headers.ContainsKey('Authorization')) {
            $client.DefaultRequestHeaders.Add('Authorization', $Headers['Authorization'])
        }
        $req = New-Object System.Net.Http.HttpRequestMessage(
            [System.Net.Http.HttpMethod]::Head, $Url)
        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        if ($resp.IsSuccessStatusCode -and $resp.Content.Headers.ContentLength) {
            return [long]$resp.Content.Headers.ContentLength
        }
        return 0
    }
    catch { return 0 }
    finally { if ($client) { $client.Dispose() } }
}

function Install-ResumableFile {
    <#
    .SYNOPSIS
        Download with resume. HttpClient + Range first (progress + resume),
        async BITS with a stall guard second. Verifies size and GGUF magic.
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination,
        [hashtable]$Headers = @{},
        [long]$ExpectedBytes = 0,
        [switch]$ExpectGguf
    )

    $dir = Split-Path -Parent $Destination
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $existing = 0
    if (Test-Path $Destination) { $existing = (Get-Item $Destination).Length }

    if ($ExpectedBytes -gt 0 -and $existing -eq $ExpectedBytes) {
        Write-Step "Already complete: $([System.IO.Path]::GetFileName($Destination)) ($([math]::Round($existing/1MB,1)) MB)" 'Green'
        return
    }

    $httpOk = $false
    try {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromHours(6)
        foreach ($k in $Headers.Keys) { $client.DefaultRequestHeaders.Add($k, $Headers[$k]) }

        $mode = [System.IO.FileMode]::Create
        $offset = 0
        if ($existing -gt 0) {
            # Resume: ask the server for bytes we don't have yet.
            $req = New-Object System.Net.Http.HttpRequestMessage(
                [System.Net.Http.HttpMethod]::Get, $Url)
            $req.Headers.Range = New-Object System.Net.Http.Headers.RangeHeaderValue($existing, $null)
            $resp = $client.SendAsync($req,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            if ($resp.StatusCode -eq [System.Net.HttpStatusCode]::PartialContent) {
                $mode = [System.IO.FileMode]::Append
                $offset = $existing
                Write-Step "Resuming at $([math]::Round($existing/1MB,1)) MB..." 'Gray'
            }
            else {
                $resp.Dispose()
                $req = New-Object System.Net.Http.HttpRequestMessage(
                    [System.Net.Http.HttpMethod]::Get, $Url)
                $resp = $client.SendAsync($req,
                    [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                $resp.EnsureSuccessStatusCode()
            }
        }
        else {
            $req = New-Object System.Net.Http.HttpRequestMessage(
                [System.Net.Http.HttpMethod]::Get, $Url)
            $resp = $client.SendAsync($req,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            $resp.EnsureSuccessStatusCode()
        }

        if ($ExpectedBytes -le 0 -and $resp.Content.Headers.ContentLength) {
            $ExpectedBytes = [long]$resp.Content.Headers.ContentLength + $offset
        }

        $stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $file = New-Object System.IO.FileStream($Destination, $mode,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $buffer = New-Object byte[] 1048576
            $total = $offset
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $lastReport = 0
            while ($true) {
                $read = $stream.Read($buffer, 0, $buffer.Length)
                if ($read -le 0) { break }
                $file.Write($buffer, 0, $read)
                $total += $read
                if ($total - $lastReport -ge 10485760) {  # every ~10MB
                    $lastReport = $total
                    $pct = if ($ExpectedBytes -gt 0) {
                        [math]::Round($total * 100 / $ExpectedBytes, 1) } else { 0 }
                    $mbps = if ($sw.Elapsed.TotalSeconds -gt 0) {
                        [math]::Round(($total - $offset) / 1MB / $sw.Elapsed.TotalSeconds, 1) } else { 0 }
                    Write-Progress -Activity 'Downloading' `
                        -Status "$([math]::Round($total/1MB,1)) / $([math]::Round($ExpectedBytes/1MB,1)) MB  ($mbps MB/s)" `
                        -PercentComplete ([int]$pct)
                }
            }
        }
        finally { $file.Close(); $stream.Close(); $resp.Dispose(); $client.Dispose() }
        Write-Progress -Activity 'Downloading' -Completed
        $httpOk = $true
    }
    catch {
        Write-Step "Direct download failed ($($_.Exception.Message)); trying BITS..." 'Yellow'
    }

    if (-not $httpOk) {
        # BITS fallback: asynchronous with a stall guard. The old synchronous
        # Start-BitsTransfer hung FOREVER on a stalled connection; a job that
        # transfers no bytes for 180s is cancelled loudly instead of parking.
        $bitsModule = $false
        try { Import-Module BitsTransfer -ErrorAction Stop; $bitsModule = $true }
        catch { $bitsModule = $false }
        if (-not $bitsModule) {
            throw 'Both download paths failed and BITS is unavailable on this machine.'
        }
        $job = Start-BitsTransfer -Source $Url -Destination $Destination `
            -Description 'Falsum AI download' -Asynchronous -ErrorAction Stop
        $jobId = $job.JobId
        $lastBytes = [long]0
        $lastProgressUtc = [datetime]::UtcNow
        $stallSec = 180
        $deadline = [datetime]::UtcNow.AddHours(6)
        try {
            while ($true) {
                Start-Sleep -Seconds 5
                try { $job = Get-BitsTransfer -JobId $jobId -ErrorAction Stop }
                catch { throw 'BITS job vanished mid-download.' }
                if ($job.BytesTransferred -gt $lastBytes) {
                    $lastBytes = [long]$job.BytesTransferred
                    $lastProgressUtc = [datetime]::UtcNow
                }
                if ($job.BytesTotal -gt 0) {
                    Write-Progress -Activity 'Downloading (BITS)' `
                        -Status "$([math]::Round($lastBytes/1MB,1)) / $([math]::Round($job.BytesTotal/1MB,1)) MB" `
                        -PercentComplete ([int][math]::Round($lastBytes * 100 / $job.BytesTotal))
                }
                if (([datetime]::UtcNow - $lastProgressUtc).TotalSeconds -ge $stallSec) {
                    throw "BITS download stalled: no bytes transferred for ${stallSec}s — cancelled, not parked."
                }
                if ([datetime]::UtcNow -gt $deadline) {
                    throw 'BITS download exceeded the 6-hour total timeout — cancelled.'
                }
                switch ($job.JobState) {
                    'Transferred' { Complete-BitsTransfer -BitsJob $job -ErrorAction Stop; break }
                    'Error' {
                        $err = $job.ErrorDescription
                        throw "BITS job failed: $err"
                    }
                }
                if ($job.JobState -eq 'Transferred') { break }
            }
        }
        finally { Write-Progress -Activity 'Downloading (BITS)' -Completed }
    }

    # Integrity: size check, then GGUF magic for model files.
    if ($ExpectedBytes -gt 0) {
        $actual = (Get-Item $Destination).Length
        if ($actual -ne $ExpectedBytes) {
            throw "Size mismatch after download: expected $ExpectedBytes bytes, got $actual. Delete the file and re-run."
        }
    }
    if ($ExpectGguf) { Test-GgufMagic -Path $Destination }
    Write-Step "Downloaded: $([System.IO.Path]::GetFileName($Destination))" 'Green'
}

function Test-GgufMagic {
    <# A truncated or HTML-error download is not a model. GGUF files start
       with the 4 ASCII bytes "GGUF". #>
    param([Parameter(Mandatory)][string]$Path)
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $buf = New-Object byte[] 4
        if ($fs.Read($buf, 0, 4) -ne 4) { throw 'File is shorter than 4 bytes.' }
        $magic = [System.Text.Encoding]::ASCII.GetString($buf)
        if ($magic -ne 'GGUF') {
            throw "Not a GGUF file (magic was '$magic'). The download is corrupt or the URL served an error page."
        }
    }
    finally { $fs.Close() }
}

# ---------------------------------------------------------------------------
# llama.cpp server
# ---------------------------------------------------------------------------

function Get-LatestLlamaServerUrl {
    <#
    .SYNOPSIS
        Resolve the current llama.cpp Windows CPU release asset via the
        GitHub API. Never hardcode a build number — pinned URLs 404 as soon
        as the next release ships.
    #>
    $api = 'https://api.github.com/repos/ggerganov/llama.cpp/releases/latest'
    try {
        $rel = Invoke-RestMethod -Uri $api -UseBasicParsing -TimeoutSec 30 `
            -Headers @{ 'User-Agent' = 'Falsum-AI-Setup/1.0' }
        $asset = @($rel.assets) | Where-Object {
            $_.name -like 'llama-*-bin-win-cpu-x64.zip'
        } | Select-Object -First 1
        if (-not $asset) { throw 'No win-cpu-x64 asset in the latest release.' }
        Write-Step "llama.cpp latest: $($rel.tag_name) ($($asset.name))" 'Gray'
        return $asset.browser_download_url
    }
    catch {
        throw ("Could not resolve the latest llama.cpp release: {0}`n" -f $_.Exception.Message) +
              'Download it manually from https://github.com/ggerganov/llama.cpp/releases ' +
              'and extract llama-server.exe into %LOCALAPPDATA%\Falsum\tools\'
    }
}

function Install-LlamaServer {
    if (Test-Path $script:ServerExe) {
        Write-Step "llama-server.exe already present." 'Green'
        return
    }
    Write-Step 'Resolving latest llama.cpp release...'
    $zipUrl = Get-LatestLlamaServerUrl
    $zipPath = Join-Path $env:TEMP 'falsum-llama.zip'
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Install-ResumableFile -Url $zipUrl -Destination $zipPath
    $extractDir = Join-Path $env:TEMP 'falsum-llama-extract'
    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
    Remove-Item $zipPath -Force
    # The zip nests the exe one folder deep (llama-<build>-bin-win-cpu-x64\).
    $exe = Get-ChildItem -Path $extractDir -Filter 'llama-server.exe' -Recurse |
           Select-Object -First 1
    if (-not $exe) { throw 'llama-server.exe not found inside the release zip.' }
    if (-not (Test-Path $script:ToolsDir)) {
        New-Item -ItemType Directory -Path $script:ToolsDir -Force | Out-Null
    }
    Copy-Item $exe.FullName $script:ServerExe -Force
    Remove-Item $extractDir -Recurse -Force
    Write-Step "llama-server.exe installed to tools\." 'Green'
}

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

function Install-AIModel {
    param([string]$Tier, [string]$Token, [string]$OverrideUrl)

    if (Test-Path $script:ModelPath) {
        # Present: make sure it is actually a model, not a leftover.
        try { Test-GgufMagic -Path $script:ModelPath }
        catch {
            Write-Step "Existing model.gguf failed validation ($($_.Exception.Message)); re-downloading." 'Yellow'
            Remove-Item $script:ModelPath -Force
        }
        if (Test-Path $script:ModelPath) {
            Write-Step "Model already present: ai\model.gguf" 'Green'
            return
        }
    }

    $ramGB = Get-TotalMemoryGB
    Write-Step "Detected RAM: ${ramGB}GB" 'Gray'

    if ($OverrideUrl) {
        $spec = @{ Name = 'Custom model'; Url = $OverrideUrl; ApproxSizeGB = 2.5; Why = 'user override' }
    }
    else {
        $spec = Get-ModelSpec -Tier $Tier -RamGB $ramGB -Token $Token
        Write-Step "Selected: $($spec.Name) (~$($spec.ApproxSizeGB)GB) — $($spec.Why)" 'Gray'
    }

    $headers = Get-HfHeaders -Token $Token
    $expected = Get-RemoteFileSize -Url $spec.Url -Headers $headers
    $needGB = [math]::Round($spec.ApproxSizeGB + 0.5, 1)
    $freeGB = Get-FreeSpaceGB -Path $env:LOCALAPPDATA
    if ($freeGB -lt $needGB) {
        throw "Not enough disk space: need ~${needGB}GB, have ${freeGB}GB free."
    }

    Write-Step "Downloading $($spec.Name) (one time; the AI works offline after this)..."
    Install-ResumableFile -Url $spec.Url -Destination $script:ModelPath `
        -Headers $headers -ExpectedBytes $expected -ExpectGguf

    $info = [ordered]@{
        name      = $spec.Name
        url       = $spec.Url
        installed = (Get-Date).ToString('o')
        bytes     = (Get-Item $script:ModelPath).Length
        tier      = $Tier
        ramGB     = $ramGB
    }
    $info | ConvertTo-Json | Set-Content (Join-Path $script:AIDir 'model.info.json') -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Launcher + smoke test
# ---------------------------------------------------------------------------

function Write-StartAiBat {
    $bat = @"
@echo off
REM Falsum Local AI Server — runs on YOUR machine, localhost only.
REM No internet needed after the one-time model download.
"%LOCALAPPDATA%\Falsum\tools\llama-server.exe" -m "%LOCALAPPDATA%\Falsum\ai\model.gguf" --port 8080 --ctx-size 4096
"@
    $bat | Out-File (Join-Path $script:FalsumDir 'Start-AI.bat') -Encoding ASCII -Force
    Write-Step 'Start-AI.bat written.' 'Green'
}

function Test-AISmoke {
    <#
    .SYNOPSIS
        Start llama-server with the downloaded model, hit /health, shut down.
        Proves the whole chain works before the user ever opens the chat.
    #>
    if (-not (Test-Path $script:ServerExe)) { throw 'llama-server.exe missing; cannot smoke-test.' }
    if (-not (Test-Path $script:ModelPath)) { throw 'model.gguf missing; cannot smoke-test.' }
    Write-Step 'Smoke test: starting server...'
    $p = Start-Process -FilePath $script:ServerExe `
        -ArgumentList "-m `"$script:ModelPath`" --port 8080" `
        -WindowStyle Hidden -PassThru
    try {
        $deadline = (Get-Date).AddSeconds(120)
        $healthy = $false
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 2
            try {
                $r = Invoke-WebRequest -Uri 'http://localhost:8080/health' `
                    -UseBasicParsing -TimeoutSec 5
                if ($r.StatusCode -eq 200) { $healthy = $true; break }
            }
            catch { <# not up yet #> }
            if ($p.HasExited) { throw "llama-server exited early (code $($p.ExitCode))." }
        }
        if (-not $healthy) { throw 'Server did not answer /health within 120s.' }
        Write-Step 'Smoke test PASSED: server answered /health with the model loaded.' 'Green'
    }
    finally {
        if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  Falsum AI Setup' -ForegroundColor White
Write-Host '  Local model. No cloud. No limits.' -ForegroundColor Gray
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

foreach ($d in @($script:FalsumDir, $script:AIDir, $script:ToolsDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

try {
    if (-not $SkipServer) { Install-LlamaServer }
    if (-not $SkipModel)  { Install-AIModel -Tier $ModelTier -Token $HfToken -OverrideUrl $ModelUrl }
    Write-StartAiBat
    if ($SmokeTest) { Test-AISmoke }

    Write-Host ''
    Write-Step 'AI setup complete.' 'Green'
    Write-Host "  Model : $script:ModelPath" -ForegroundColor Gray
    Write-Host "  Server: $script:ServerExe" -ForegroundColor Gray
    Write-Host '  Start the server with Start-AI.bat, or from Settings in the app.' -ForegroundColor Gray
}
catch {
    Write-Host ''
    Write-Step "FAILED: $($_.Exception.Message)" 'Red'
    Write-Host '  Re-run this script to resume — downloads pick up where they stopped.' -ForegroundColor Yellow
    exit 1
}

if (-not $NonInteractive) {
    Write-Host ''
    Write-Host 'Press any key to continue...'
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}
