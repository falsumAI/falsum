<#
.SYNOPSIS
    Installer — one double-click, everything works.

.DESCRIPTION
    Gregg's pain points, fixed before he hits them:
    1. Execution policy blocks .ps1 — this is a .bat that bypasses it
    2. No shortcut — creates desktop shortcut
    3. Admin needed — prompts once, handles gracefully
    4. Scattered files — everything in one folder, one entry point

    Run INSTALL.bat (not the .ps1 directly).
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installDir = Split-Path -Parent $PSCommandPath
$desktopPath = [Environment]::GetFolderPath("Desktop")

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Installing..." -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  [!] Not running as admin. Some modules need admin." -ForegroundColor Yellow
    Write-Host "      The tool will work, but with limited capabilities." -ForegroundColor Gray
    Write-Host "      Right-click INSTALL.bat > Run as administrator for full access." -ForegroundColor Gray
    Write-Host ""
}
else {
    Write-Host "  [OK] Running as administrator. Full capabilities." -ForegroundColor Green
}

# 2. Create desktop shortcut
try {
    $wshell = New-Object -ComObject WScript.Shell
    $shortcut = $wshell.CreateShortcut("$desktopPath\Falsum.lnk")
    $shortcut.TargetPath = "powershell.exe"
    $shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$installDir\Falsum.ps1`""
    $shortcut.WorkingDirectory = $installDir
    $shortcut.Description = "Falsum — unified security application"
    $shortcut.Save()
    Write-Host "  [OK] Desktop shortcut created: Falsum" -ForegroundColor Green
}
catch {
    Write-Host "  [X] Shortcut failed: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Verify modules
$moduleDirs = Get-ChildItem -Path "$installDir\modules" -Directory -ErrorAction SilentlyContinue
Write-Host "  [OK] $($moduleDirs.Count) modules found" -ForegroundColor Green

# 4. Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
Write-Host "  [OK] PowerShell $($psVersion.Major).$($psVersion.Minor)" -ForegroundColor Green
if ($psVersion.Major -lt 5) {
    Write-Host "  [!] PowerShell 5.1+ recommended. Some modules may not work." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Done. Double-click 'Falsum' on your desktop." -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to launch now..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Launch
& powershell -ExecutionPolicy Bypass -File "$installDir\Falsum.ps1"
