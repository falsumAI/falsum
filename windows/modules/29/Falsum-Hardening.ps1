# Falsum Module 29: Windows Hardening (Real Integration)
# Uses HardeningKitty (github.com/scipag/HardeningKitty) — real CIS/Microsoft baseline checks.
# Falsum orchestrates: downloads HardeningKitty if missing, runs audit, applies fixes.

function Install-HardeningKitty {
    $hkPath = "$env:LOCALAPPDATA\Falsum\tools\HardeningKitty.psm1"
    if (Test-Path $hkPath) { return $hkPath }

    Write-Host "Downloading HardeningKitty (scipag)..."
    $toolsDir = "$env:LOCALAPPDATA\Falsum\tools"
    if (!(Test-Path $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null }

    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/scipag/HardeningKitty/main/HardeningKitty.psm1" -OutFile $hkPath

    # Also get the finding lists
    $lists = @("finding_list_cis_microsoft.csv", "finding_list_msft_baseline.csv")
    foreach ($list in $lists) {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/scipag/HardeningKitty/main/lists/$list" -OutFile "$toolsDir\$list"
    }

    return $hkPath
}

function Invoke-FalsumHardeningAudit {
    $hk = Install-HardeningKitty
    Import-Module $hk -Force

    $reportFile = "$env:TEMP\falsum-hardening-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $findingList = "$env:LOCALAPPDATA\Falsum\tools\finding_list_msft_baseline.csv"

    Write-Host "Running HardeningKitty audit (Microsoft baseline)..."
    Invoke-HardeningKitty -Mode Audit -Log -Report -ReportPath $reportFile -FindingList $findingList

    $results = Import-Csv $reportFile

    # Log failures to vault
    $failed = $results | Where-Object { $_.Result -eq "Failed" }
    foreach ($f in $failed) {
        Add-FalsumVaultEntry -Type "hardening" -Data @{
            id = $f.ID
            category = $f.Category
            name = $f.Name
            result = "Failed"
            recommended = $f.'Recommended Value'
        }
    }

    Write-Host "Audit complete: $($failed.Count) failed checks out of $($results.Count)."
    return $results
}

function Invoke-FalsumHardeningFix {
    # Apply HardeningKitty fixes (HailMary mode = aggressive, use with caution)
    $hk = Install-HardeningKitty
    Import-Module $hk -Force

    Write-Host "Applying hardening fixes (this modifies system settings)..."
    $findingList = "$env:LOCALAPPDATA\Falsum\tools\finding_list_msft_baseline.csv"

    # Backup first via system restore point
    Checkpoint-Computer -Description "Falsum hardening backup" -RestorePointType "MODIFY_SETTINGS"

    Invoke-HardeningKitty -Mode HailMary -Log -FindingList $findingList

    Add-FalsumVaultEntry -Type "hardening-fix" -Data @{
        action = "HailMary applied"
        backup = "System restore point created"
        timestamp = (Get-Date).ToString("o")
    }

    Write-Host "Hardening applied. Restore point created for rollback."
}
