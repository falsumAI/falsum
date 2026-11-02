# Falsum Windows Validation Script
# Run this on your Windows machine to verify the full Falsum build.
# Run as Administrator for full coverage.

$ErrorActionPreference = "Continue"
$FalsumRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Pass = 0
$Fail = 0

function Test-Step {
    param([string]$Name, [scriptblock]$Test)
    try {
        $result = & $Test
        if ($result) {
            Write-Host "  [PASS] $Name" -ForegroundColor Green
            $script:Pass++
        } else {
            Write-Host "  [FAIL] $Namet" -ForegroundColor Red
            $script:Fail++
        }
    } catch {
        Write-Host "  [FAIL] $Name : $_" -ForegroundColor Red
        $script:Fail++
    }
}

Write-Host "`n=== Falsum Validation ===" -ForegroundColor Cyan

# 1. PowerShell modules exist and parse
Write-Host "`n[1] PowerShell modules" -ForegroundColor Yellow
$modules = Get-ChildItem "$FalsumRoot\windows\modules" -Directory
Write-Host "  Found $($modules.Count) module directories"
foreach ($mod in $modules) {
    $ps1 = Get-ChildItem $mod.FullName -Filter "Falsum-*.ps1" | Select-Object -First 1
    if ($ps1) {
        $errors = $null
        [void][System.Management.Automation.PSParser]::Tokenize((Get-Content $ps1.FullName -Raw), [ref]$errors)
        Test-Step "$($mod.Name) parses clean" { $errors.Count -eq 0 }
    }
}

# 2. C# project structure
Write-Host "`n[2] C# application structure" -ForegroundColor Yellow
Test-Step "FalsumApp.csproj exists" { Test-Path "$FalsumRoot\src\FalsumApp\FalsumApp.csproj" }
Test-Step "MainWindow.xaml exists" { Test-Path "$FalsumRoot\src\FalsumApp\Views\MainWindow.xaml" }
Test-Step "All services exist" {
    $services = @("PowerShellEngine", "BrowserControlService", "SystemPolicyService",
                  "LocalAIService", "QuantumCoherenceEngine", "PriorArtService",
                  "NativeMessagingHost")
    ($services | Where-Object { Test-Path "$FalsumRoot\src\FalsumApp\Services\$_.cs" }).Count -eq $services.Count
}
Test-Step "All windows exist" {
    $windows = @("MainWindow", "AIChatWindow", "BrowserControlWindow",
                 "GovernmentWatchWindow", "PriorArtWindow", "SettingsWindow")
    ($windows | Where-Object { Test-Path "$FalsumRoot\src\FalsumApp\Views\$_.xaml" }).Count -eq $windows.Count
}

# 3. Browser extension
Write-Host "`n[3] Browser extension" -ForegroundColor Yellow
Test-Step "manifest.json valid" {
    try { $null = Get-Content "$FalsumRoot\browser-extension\manifest.json" -Raw | ConvertFrom-Json; $true }
    catch { $false }
}
Test-Step "background.js exists" { Test-Path "$FalsumRoot\browser-extension\background.js" }
Test-Step "content.js exists" { Test-Path "$FalsumRoot\browser-extension\content.js" }
Test-Step "Native host installer exists" { Test-Path "$FalsumRoot\browser-extension\Install-NativeHost.ps1" }

# 4. Android app
Write-Host "`n[4] Android app" -ForegroundColor Yellow
Test-Step "FalsumVpnService.kt exists" { Test-Path "$FalsumRoot\android-app\app\src\main\java\com\falsum\FalsumVpnService.kt" }
Test-Step "AndroidManifest exists" { Test-Path "$FalsumRoot\android-app\app\src\main\AndroidManifest.xml" }

# 5. Licenses
Write-Host "`n[5] Licenses" -ForegroundColor Yellow
Test-Step "LICENSE-GPL exists" { Test-Path "$FalsumRoot\LICENSE-GPL" }
Test-Step "LICENSE-COMMERCIAL exists" { Test-Path "$FalsumRoot\LICENSE-COMMERCIAL" }
Test-Step "CLA.md exists" { Test-Path "$FalsumRoot\CLA.md" }

# 6. Documentation
Write-Host "`n[6] Documentation" -ForegroundColor Yellow
Test-Step "README.md exists" { Test-Path "$FalsumRoot\README.md" }
Test-Step "CONTRIBUTING.md exists" { Test-Path "$FalsumRoot\CONTRIBUTING.md" }
Test-Step "SECURITY.md exists" { Test-Path "$FalsumRoot\SECURITY.md" }
Test-Step "Drift math doc exists" { Test-Path "$FalsumRoot\docs\GREGG-DRIFT-MATH.md" }
Test-Step "Hardware math spec exists" { Test-Path "$FalsumRoot\docs\PHI-SEED-HARDWARE-MATH.md" }

Write-Host "`n=== Results: $Pass passed, $Fail failed ===" -ForegroundColor Cyan
if ($Fail -eq 0) {
    Write-Host "All checks passed. Falsum structure is valid." -ForegroundColor Green
} else {
    Write-Host "Some checks failed. See above for details." -ForegroundColor Red
}
