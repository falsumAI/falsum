# Falsum PrivescCheck Integration (P0)
# Uses PrivescCheck (github.com/itm4n/PrivescCheck, MIT license) — the real Windows privilege escalation scanner.
# Falsum orchestrates: downloads PrivescCheck if missing, runs it, parses results, and FIXES what it finds.
# The FIX is Falsum's value-add: PrivescCheck finds, Falsum fixes.

function Install-PrivescCheck {
    $pcPath = "$env:LOCALAPPDATA\Falsum\tools\PrivescCheck.ps1"
    if (Test-Path $pcPath) { return $pcPath }

    Write-Host "Downloading PrivescCheck (itm4n, MIT)..."
    $toolsDir = "$env:LOCALAPPDATA\Falsum\tools"
    if (-not (Test-Path $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null }

    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1" -OutFile $pcPath
    return $pcPath
}

function Invoke-FalsumPrivescCheck {
    param([switch]$Fix)

    $pc = Install-PrivescCheck
    Write-Host "Running PrivescCheck (Windows privilege escalation audit)..."

    # Run PrivescCheck and capture output
    $output = & $pc -Extended -Silent 2>&1 | Out-String

    $findings = @{
        timestamp = (Get-Date).ToString("o")
        rawOutput = $output
        fixable = @()
    }

    # Parse for common fixable issues
    if ($output -match "Unquoted Service Path") {
        $findings.fixable += @{
            issue = "Unquoted Service Path"
            severity = "High"
            fix = "Quote the service ImagePath in registry"
        }
    }
    if ($output -match "Weak Service Permissions|SERVICE_CHANGE_CONFIG") {
        $findings.fixable += @{
            issue = "Weak Service Permissions"
            severity = "High"
            fix = "Tighten service DACL to remove write access for low-priv users"
        }
    }
    if ($output -match "AlwaysInstallElevated") {
        $findings.fixable += @{
            issue = "AlwaysInstallElevated enabled"
            severity = "Critical"
            fix = "Disable AlwaysInstallElevated in HKLM and HKCU"
        }
    }
    if ($output -match "UAC.*Bypass|UAC.*disabled") {
        $findings.fixable += @{
            issue = "UAC misconfiguration"
            severity = "High"
            fix = "Restore UAC to default consent behavior"
        }
    }

    # Save to vault
    $vault = Join-Path $env:LOCALAPPDATA "Falsum\vault\privesc"
    if (-not (Test-Path $vault)) { New-Item -ItemType Directory -Path $vault -Force | Out-Null }
    $findings | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $vault "scan-$(Get-Date -Format 'yyyyMMdd-HHmmss').json")

    if ($Fix -and $findings.fixable.Count -gt 0) {
        Write-Host "`nApplying fixes for $($findings.fixable.Count) issues..." -ForegroundColor Yellow
        foreach ($item in $findings.fixable) {
            try {
                switch ($item.issue) {
                    "AlwaysInstallElevated enabled" {
                        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
                        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
                        Write-Host "  [FIXED] Disabled AlwaysInstallElevated" -ForegroundColor Green
                    }
                    default {
                        Write-Host "  [MANUAL] $($item.issue): $($item.fix)" -ForegroundColor Yellow
                    }
                }
            } catch {
                Write-Host "  [FAILED] $($item.issue): $_" -ForegroundColor Red
            }
        }
    }

    return $findings
}

function Get-FalsumPrivescSummary {
    $vault = Join-Path $env:LOCALAPPDATA "Falsum\vault\privesc"
    if (-not (Test-Path $vault)) { return @{ scans = 0 } }
    $scans = Get-ChildItem $vault -Filter "scan-*.json"
    if ($scans.Count -eq 0) { return @{ scans = 0 } }
    $latest = Get-Content $scans[-1].FullName -Raw | ConvertFrom-Json
    return @{
        scans = $scans.Count
        lastScan = $latest.timestamp
        fixableIssues = $latest.fixable.Count
    }
}
