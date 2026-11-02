<#
.SYNOPSIS
    Falsum AI Setup — downloads local model, sets up llama.cpp

.DESCRIPTION
    Gregg's order: "you can get an AI model from GitHub"
    Downloads:
    - llama.cpp (from GitHub, CPU-only build)
    - Phi-4-mini (3.8B, Q4, ~2.5GB) OR TinyLlama (1.1B, Q4, ~600MB) for tight machines
    
    The model runs LOCALLY. No cloud. No tokens. No limits.
    The intelligence core (Falsum-Intelligence.ps1) talks to it.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:InstallDir = Split-Path -Parent $PSCommandPath
$script:ModelDir = Join-Path $script:InstallDir "models"
$script:LlamaDir = Join-Path $script:InstallDir "llama.cpp"

function Write-Status {
    param([string]$Msg, [string]$Color = "Cyan")
    Write-Host "[AI Setup] $Msg" -ForegroundColor $Color
}

# Model selection based on RAM
function Get-RecommendedModel {
    $ramGB = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    
    if ($ramGB -ge 8) {
        return @{
            Name = "Phi-4-mini"
            Url = "https://huggingface.co/microsoft/Phi-4-mini-instruct/resolve/main/phi-4-mini-instruct-q4_k_m.gguf"
            Size = "2.5GB"
            File = "phi-4-mini-q4_k_m.gguf"
        }
    }
    else {
        # Gregg's machine: 5.8GB RAM — use TinyLlama
        return @{
            Name = "TinyLlama"
            Url = "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
            Size = "600MB"
            File = "tinyllama-1.1b-q4_k_m.gguf"
        }
    }
}

function Install-LlamaCpp {
    Write-Status "Setting up llama.cpp (from GitHub)..."
    
    if (Test-Path $script:LlamaDir) {
        Write-Status "llama.cpp already exists, skipping." "Green"
        return
    }
    
    # Download llama.cpp release (Windows CPU build)
    $llamaUrl = "https://github.com/ggerganov/llama.cpp/releases/latest/download/llama-b6489-bin-win-cpu-x64.zip"
    $zipPath = Join-Path $env:TEMP "llama.zip"
    
    Write-Status "Downloading llama.cpp..."
    try {
        Invoke-WebRequest -Uri $llamaUrl -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $script:LlamaDir -Force
        Remove-Item $zipPath -Force
        Write-Status "llama.cpp installed." "Green"
    }
    catch {
        Write-Status "Failed to download llama.cpp: $($_.Exception.Message)" "Red"
        Write-Status "You can manually download from https://github.com/ggerganov/llama.cpp/releases" "Yellow"
    }
}

function Install-Model {
    $model = Get-RecommendedModel
    
    # Pain point #75 FIX: Check disk space before downloading
    $drive = (Get-Item $script:ModelDir).PSDrive.Name
    $freeGB = (Get-PSDrive $drive).Free / 1GB
    $needGB = if ($model.Size -like "*2.5*") { 3.0 } else { 1.0 }
    if ($freeGB -lt $needGB) {
        Write-Status "Not enough disk space. Need $($needGB)GB, have $([math]::Round($freeGB,1))GB." "Red"
        return $null
    }
    
    Write-Status "Recommended model for your machine: $($model.Name) ($($model.Size))"
    
    if (-not (Test-Path $script:ModelDir)) {
        New-Item -Path $script:ModelDir -ItemType Directory -Force | Out-Null
    }
    
    $modelPath = Join-Path $script:ModelDir $model.File
    
    if (Test-Path $modelPath) {
        Write-Status "Model already downloaded: $($model.File)" "Green"
        return $modelPath
    }
    
    Write-Status "Downloading $($model.Name) ($($model.Size))..."
    Write-Status "This is a one-time download. The model runs locally, forever." "Gray"
    
    try {
        # Use BITS for resumable download
        Start-BitsTransfer -Source $model.Url -Destination $modelPath -Description "Downloading $($model.Name)"
        Write-Status "Model downloaded." "Green"
        return $modelPath
    }
    catch {
        Write-Status "BITS failed, trying Invoke-WebRequest..." "Yellow"
        try {
            Invoke-WebRequest -Uri $model.Url -OutFile $modelPath -UseBasicParsing
            Write-Status "Model downloaded." "Green"
            return $modelPath
        }
        catch {
            Write-Status "Failed: $($_.Exception.Message)" "Red"
            return $null
        }
    }
}

function Test-ModelWorks {
    param([string]$ModelPath)
    
    $llamaExe = Join-Path $script:LlamaDir "llama-cli.exe"
    if (-not (Test-Path $llamaExe)) {
        $llamaExe = Join-Path $script:LlamaDir "main.exe"
    }
    
    if (-not (Test-Path $llamaExe)) {
        Write-Status "llama.cpp executable not found." "Red"
        return $false
    }
    
    Write-Status "Testing model with: 'Hello, are you working?'"
    try {
        $output = & $llamaExe -m $ModelPath -p "Hello, are you working? Reply in 10 words." -n 20 2>&1 | Out-String
        Write-Status "Model output:" "Gray"
        Write-Host $output -ForegroundColor White
        return $true
    }
    catch {
        Write-Status "Test failed: $($_.Exception.Message)" "Red"
        return $false
    }
}

# ============================================================================
# Main
# ============================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Falsum AI Setup" -ForegroundColor White
Write-Host "  Local model. No cloud. No limits." -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Install-LlamaCpp
$modelPath = Install-Model

if ($modelPath -and (Test-Path $modelPath)) {
    Write-Status "Testing..." 
    if (Test-ModelWorks -ModelPath $modelPath) {
        Write-Status "AI is ready." "Green"
        Write-Status "The intelligence core will use: $modelPath" "Gray"
        
        # Save config for the intelligence module
        $config = @{
            ModelPath = $modelPath
            LlamaExe = (Join-Path $script:LlamaDir "llama-cli.exe")
            Configured = (Get-Date).ToString('o')
        }
        $config | ConvertTo-Json | Set-Content (Join-Path $script:InstallDir "ai-config.json") -Encoding UTF8
    }
}
else {
    Write-Status "AI setup incomplete. You can run this again later." "Yellow"
}

Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
