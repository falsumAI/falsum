# Falsum Build Script — Run on Windows
# Produces the full installable Falsum package.
# Requires: Windows 10/11, .NET 8 SDK, PowerShell 5.1+

param(
    [switch]$SkipBuild,    # Skip C# compilation (use existing binaries)
    [string]$OutputDir = "$PSScriptRoot\dist"
)

$ErrorActionPreference = "Stop"
$RepoRoot = $PSScriptRoot

Write-Host @"
╔═══════════════════════════════════════╗
║         FALSUM BUILD SCRIPT           ║
║  Building the full application package ║
╚═══════════════════════════════════════╝
"@ -ForegroundColor Cyan

# 1. Compile C# app
if (-not $SkipBuild) {
    Write-Host "`n[1/4] Compiling C# application..." -ForegroundColor Yellow

    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $dotnet) {
        Write-Host "  ERROR: .NET SDK not found." -ForegroundColor Red
        Write-Host "  Download from https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
        Write-Host "  Then re-run this script." -ForegroundColor Yellow
        exit 1
    }

    $csproj = "$RepoRoot\src\FalsumApp\FalsumApp.csproj"
    if (-not (Test-Path $csproj)) {
        Write-Host "  ERROR: $csproj not found" -ForegroundColor Red
        exit 1
    }

    Write-Host "  Restoring NuGet packages..."
    dotnet restore $csproj

    Write-Host "  Building Release..."
    dotnet build $csproj --configuration Release --no-restore

    if ($LASTEXITCODE -ne 0) {
        Write-Host "  BUILD FAILED" -ForegroundColor Red
        exit 1
    }
    Write-Host "  Build succeeded." -ForegroundColor Green
} else {
    Write-Host "`n[1/4] Skipping C# build (--SkipBuild)" -ForegroundColor Yellow
}

# 2. Assemble package
Write-Host "`n[2/4] Assembling package..." -ForegroundColor Yellow
if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# C# binaries
$binDir = "$RepoRoot\src\FalsumApp\bin\Release\net8.0-windows"
if (Test-Path $binDir) {
    Copy-Item "$binDir\*" -Destination $OutputDir -Recurse -Force
    Write-Host "  C# binaries copied." -ForegroundColor Green
} else {
    Write-Host "  WARNING: No compiled binaries found. Run without -SkipBuild first." -ForegroundColor Yellow
}

# PowerShell modules
$modulesDest = "$OutputDir\modules"
New-Item -ItemType Directory -Path $modulesDest -Force | Out-Null
Copy-Item "$RepoRoot\windows\modules\*" -Destination $modulesDest -Recurse -Force
$moduleCount = (Get-ChildItem $modulesDest -Directory).Count
Write-Host "  $moduleCount PowerShell modules copied." -ForegroundColor Green

# Browser extension
$extDest = "$OutputDir\browser-extension"
New-Item -ItemType Directory -Path $extDest -Force | Out-Null
Copy-Item "$RepoRoot\browser-extension\*" -Destination $extDest -Recurse -Force
Write-Host "  Browser extension copied." -ForegroundColor Green

# Installer scripts
Copy-Item "$RepoRoot\INSTALL-FALSUM.ps1" -Destination $OutputDir -Force
Copy-Item "$RepoRoot\TEST-FALSUM.ps1" -Destination $OutputDir -Force
Copy-Item "$RepoRoot\browser-extension\Install-NativeHost.ps1" -Destination $OutputDir -Force
Write-Host "  Installer scripts copied." -ForegroundColor Green

# Licenses and docs
Copy-Item "$RepoRoot\LICENSE-GPL" -Destination $OutputDir -Force
Copy-Item "$RepoRoot\LICENSE-COMMERCIAL" -Destination $OutputDir -Force
Copy-Item "$RepoRoot\CLA.md" -Destination $OutputDir -Force
Copy-Item "$RepoRoot\README.md" -Destination $OutputDir -Force
Write-Host "  Licenses and docs copied." -ForegroundColor Green

# 3. Create zip
Write-Host "`n[3/4] Creating zip..." -ForegroundColor Yellow
$zipPath = "$RepoRoot\Falsum-v1.0.0-Windows.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$OutputDir\*" -DestinationPath $zipPath -Force
$zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
Write-Host "  Created: $zipPath ($zipSize MB)" -ForegroundColor Green

# 4. Verify
Write-Host "`n[4/4] Verifying package..." -ForegroundColor Yellow
$checks = @(
    @{ Name = "Falsum.exe"; Path = "$OutputDir\Falsum.exe" },
    @{ Name = "Modules directory"; Path = $modulesDest },
    @{ Name = "Browser extension"; Path = "$extDest\manifest.json" },
    @{ Name = "Installer"; Path = "$OutputDir\INSTALL-FALSUM.ps1" },
    @{ Name = "GPL License"; Path = "$OutputDir\LICENSE-GPL" }
)
$failed = 0
foreach ($check in $checks) {
    if (Test-Path $check.Path) {
        Write-Host "  [OK] $($check.Name)" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $($check.Name)" -ForegroundColor Red
        $failed++
    }
}

if ($failed -eq 0) {
    Write-Host "`n=== BUILD COMPLETE ===" -ForegroundColor Cyan
    Write-Host "Package: $zipPath ($zipSize MB)" -ForegroundColor White
    Write-Host "`nTo install:" -ForegroundColor Yellow
    Write-Host "  1. Extract the zip" -ForegroundColor White
    Write-Host "  2. Run INSTALL-FALSUM.ps1 as Administrator" -ForegroundColor White
    Write-Host "  3. Run Falsum.exe" -ForegroundColor White
} else {
    Write-Host "`n=== BUILD INCOMPLETE: $failed checks failed ===" -ForegroundColor Red
    exit 1
}
