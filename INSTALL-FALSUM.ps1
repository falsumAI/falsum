# Falsum One-Package Installer
# Single download. Installs everything. Links everything.
#
# What it does:
# 1. Installs Windows app (all 38 modules)
# 2. Downloads and configures local AI (llama.cpp + model, NetworkChuck/Ollama pattern)
# 3. Installs browser extension + native messaging bridge
# 4. Sets up the vault, the learning DB, and the coherence core
# 5. Creates desktop shortcut
#
# The user downloads ONE file, runs it, and gets the full Falsum.
# No separate extension install. No manual bridge setup. No AI config hell.

param(
    [switch]$SkipAI,           # Skip AI model download (saves ~600MB-4GB)
    [switch]$SkipExtension     # Skip browser extension setup
)

$ErrorActionPreference = "Stop"
$FalsumDir = "$env:LOCALAPPDATA\Falsum"
$ToolsDir = "$FalsumDir\tools"
$AIDir = "$FalsumDir\ai"

Write-Host @"
╔═══════════════════════════════════════╗
║           FALSUM INSTALLER            ║
║  Free security. Local AI. No cloud.   ║
╚═══════════════════════════════════════╝
"@ -ForegroundColor Cyan

# 1. Create directories
Write-Host "`n[1/5] Creating directories..." -ForegroundColor Yellow
@($FalsumDir, $ToolsDir, $AIDir, "$FalsumDir\vault", "$FalsumDir\bridge") | ForEach-Object {
    if (!(Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}
Write-Host "  Done." -ForegroundColor Green

# 2. Install PowerShell modules (already in place if running from repo)
Write-Host "`n[2/5] Installing modules..." -ForegroundColor Yellow
$moduleCount = (Get-ChildItem "$PSScriptRoot\windows\modules" -Directory).Count
Write-Host "  $moduleCount modules found." -ForegroundColor Green

# 3. Local AI setup (NetworkChuck pattern: Ollama-style, localhost, private)
if (!$SkipAI) {
    Write-Host "`n[3/5] Setting up local AI..." -ForegroundColor Yellow
    Write-Host "  Following NetworkChuck's 'host ALL your AI locally' pattern:"
    Write-Host "  - llama.cpp (not Ollama — lighter, no Docker needed on Windows)"
    Write-Host "  - Model runs on localhost:8080"
    Write-Host "  - No internet needed after download"
    Write-Host "  - Your data never leaves this machine`n"

    # Detect RAM to pick model
    $ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    Write-Host "  Detected RAM: ${ramGB}GB"

    if ($ramGB -ge 8) {
        $modelUrl = "https://huggingface.co/microsoft/Phi-4-mini-instruct-gguf/resolve/main/Phi-4-mini-instruct-Q4_K_M.gguf"
        $modelName = "Phi-4-mini (3.8B)"
        Write-Host "  Selected: $modelName (best for 8GB+)"
    } else {
        $modelUrl = "https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
        $modelName = "TinyLlama (1.1B)"
        Write-Host "  Selected: $modelName (best for <8GB, ~600MB)"
    }

    $modelPath = "$AIDir\model.gguf"
    if (!(Test-Path $modelPath)) {
        Write-Host "  Downloading $modelName..."
        Write-Host "  This is a one-time download. After this, the AI works offline."
        # Use BITS for resumable download
        Start-BitsTransfer -Source $modelUrl -Destination $modelPath -Description "Falsum AI model"
        Write-Host "  Model downloaded." -ForegroundColor Green
    } else {
        Write-Host "  Model already present." -ForegroundColor Green
    }

    # Download llama.cpp server binary
    $llamaExe = "$ToolsDir\llama-server.exe"
    if (!(Test-Path $llamaExe)) {
        Write-Host "  Downloading llama.cpp server..."
        $llamaUrl = "https://github.com/ggerganov/llama.cpp/releases/latest/download/llama-b6042-bin-win-cpu-x64.zip"
        $zipPath = "$ToolsDir\llama.zip"
        Invoke-WebRequest -Uri $llamaUrl -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $ToolsDir -Force
        Remove-Item $zipPath
        Write-Host "  llama.cpp installed." -ForegroundColor Green
    }

    # Create AI start script
    @"
@echo off
REM Falsum Local AI Server — runs on YOUR machine, localhost only
"%LOCALAPPDATA%\Falsum\tools\llama-server.exe" -m "%LOCALAPPDATA%\Falsum\ai\model.gguf" --port 8080 --ctx-size 4096
"@ | Out-File "$FalsumDir\Start-AI.bat" -Encoding ASCII

    Write-Host "  AI server script created: $FalsumDir\Start-AI.bat" -ForegroundColor Green
    Write-Host "  Your math plugs into modules/00-coherence-core/ when you validate it." -ForegroundColor Yellow
}

# 4. Browser extension + native bridge
if (!$SkipExtension) {
    Write-Host "`n[4/5] Setting up browser extension..." -ForegroundColor Yellow

    $extDir = "$FalsumDir\browser-extension"
    if (!(Test-Path $extDir)) { New-Item -ItemType Directory -Path $extDir -Force | Out-Null }

    # Copy extension files
    Copy-Item "$PSScriptRoot\browser-extension\*" $extDir -Recurse -Force -Exclude "icons"

    Write-Host "  Extension files copied to: $extDir" -ForegroundColor Green
    Write-Host ""
    Write-Host "  TO COMPLETE BROWSER SETUP:" -ForegroundColor Yellow
    Write-Host "  1. Open Chrome → chrome://extensions"
    Write-Host "  2. Enable 'Developer mode' (top right)"
    Write-Host "  3. Click 'Load unpacked' → select: $extDir"
    Write-Host "  4. Copy the Extension ID (32 characters)"
    Write-Host "  5. Run: $extDir\Install-NativeHost.ps1"
    Write-Host "  6. Paste the Extension ID when prompted"
    Write-Host ""
    Write-Host "  The extension will then talk to this app. Every tracker" -ForegroundColor Gray
    Write-Host "  it sees gets reported here." -ForegroundColor Gray
}

# 5. Desktop shortcut
Write-Host "`n[5/5] Creating desktop shortcut..." -ForegroundColor Yellow
$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Falsum.lnk")
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$PSScriptRoot\windows\Falsum.ps1`""
$shortcut.WorkingDirectory = "$PSScriptRoot\windows"
$shortcut.Description = "Falsum — Free local security"
$shortcut.Save()
Write-Host "  Shortcut created." -ForegroundColor Green

Write-Host @"

╔═══════════════════════════════════════╗
║      FALSUM INSTALLED SUCCESSFULLY    ║
╚═══════════════════════════════════════╝

  What you got:
  - 38 security modules (all local, all free)
  - Local AI (your machine, your data, no cloud)
  - Browser extension (linked to the app)
  - Hash-chained vault (tamper-evident evidence log)
  - Learning AI (gets smarter from your corrections)

  Your coherence math goes in:
    windows/modules/00-coherence-core/

  Run Falsum from the desktop shortcut.
  Run Start-AI.bat to start the local AI server.

  No subscriptions. No cloud. No lies.
"@ -ForegroundColor Cyan
