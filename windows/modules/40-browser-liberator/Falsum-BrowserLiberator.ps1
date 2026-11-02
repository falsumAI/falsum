# Falsum Module 40: Browser Control Liberator
# Greyed-out Chrome settings = enterprise policies locking YOUR browser.
# If you didn't set them, they shouldn't be there.
# Falsum finds them, shows you what they control, and removes them on your word.

function Get-FalsumBrowserPolicies {
    Write-Host "`n=== BROWSER POLICIES (what's locking your settings) ===" -ForegroundColor Cyan

    $policyPaths = @{
        "Chrome" = "HKLM:\SOFTWARE\Policies\Google\Chrome"
        "Chrome (user)" = "HKCU:\SOFTWARE\Policies\Google\Chrome"
        "Edge" = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        "Edge (user)" = "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
    }

    $allPolicies = @()

    foreach ($name in $policyPaths.Keys) {
        $path = $policyPaths[$name]
        if (Test-Path $path) {
            Write-Host "`n[$name] Policies found at $path" -ForegroundColor Yellow

            $policies = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($policies) {
                $props = $policies.PSObject.Properties | Where-Object {
                    $_.Name -notmatch "^(PSPath|PSParentPath|PSChildName|PSDrive|PSProvider)$"
                }

                foreach ($prop in $props) {
                    Write-Host "  LOCKED: $($prop.Name) = $($prop.Value)" -ForegroundColor Red
                    $allPolicies += @{
                        Browser = $name
                        Path = $path
                        Name = $prop.Name
                        Value = $prop.Value
                    }
                }

                if ($props.Count -eq 0) {
                    Write-Host "  (key exists but empty)"
                }
            }
        }
    }

    # Also check for the ExtensionInstallForcelist (extensions you can't remove)
    $forceListPaths = @(
        "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
        "HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
    )
    foreach ($fp in $forceListPaths) {
        if (Test-Path $fp) {
            Write-Host "`n[FORCED EXTENSIONS] at $fp" -ForegroundColor Red
            $forced = Get-ItemProperty -Path $fp -ErrorAction SilentlyContinue
            $forced.PSObject.Properties | Where-Object {
                $_.Name -notmatch "^(PSPath|PSParentPath|PSChildName|PSDrive|PSProvider)$"
            } | ForEach-Object {
                Write-Host "  FORCED: $($_.Name) = $($_.Value)" -ForegroundColor Red
                $allPolicies += @{
                    Browser = "Chrome"
                    Path = $fp
                    Name = "ForcedExtension_$($_.Name)"
                    Value = $_.Value
                }
            }
        }
    }

    if ($allPolicies.Count -eq 0) {
        Write-Host "`nNo browser policies found. Your browser is under YOUR control." -ForegroundColor Green
    }
    else {
        Write-Host "`n$($allPolicies.Count) policies locking your browser." -ForegroundColor Red
        Write-Host "These are what grey out your settings." -ForegroundColor Yellow
    }

    foreach ($p in $allPolicies) {
        Add-FalsumVaultEntry -Type "browser-policy" -Data $p
    }

    return $allPolicies
}

function Remove-FalsumBrowserPolicies {
    # Remove ALL browser policies — give the user back control.
    # BACKUP FIRST. Always.
    param([switch]$Force)

    $policies = Get-FalsumBrowserPolicies

    if ($policies.Count -eq 0) {
        Write-Host "Nothing to remove." -ForegroundColor Green
        return
    }

    Write-Host "`nThis will REMOVE all browser policies and unlock your settings." -ForegroundColor Yellow
    Write-Host "A backup will be saved first." -ForegroundColor Gray

    if (!$Force) {
        $confirm = Read-Host "`nRemove all $($policies.Count) policies? (type YES to confirm)"
        if ($confirm -ne "YES") {
            Write-Host "Aborted. Policies left in place." -ForegroundColor Yellow
            return
        }
    }

    # BACKUP
    $backupDir = "$env:LOCALAPPDATA\Falsum\vault\policy-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

    $policyRoots = @(
        "HKLM:\SOFTWARE\Policies\Google",
        "HKCU:\SOFTWARE\Policies\Google",
        "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
        "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
    )

    foreach ($root in $policyRoots) {
        if (Test-Path $root) {
            $backupFile = Join-Path $backupDir (($root -replace "[:\\]", "_") + ".reg")
            reg export ($root -replace "HKLM:", "HKLM" -replace "HKCU:", "HKCU" -replace ":\\", "\\") $backupFile /y 2>$null
            Write-Host "  Backed up: $root" -ForegroundColor Gray
        }
    }

    Write-Host "`nBackup saved to: $backupDir" -ForegroundColor Green

    # REMOVE
    $removed = 0
    foreach ($root in $policyRoots) {
        if (Test-Path $root) {
            try {
                Remove-Item -Path $root -Recurse -Force -ErrorAction Stop
                Write-Host "  REMOVED: $root" -ForegroundColor Green
                $removed++
            }
            catch {
                Write-Host "  FAILED to remove $root : $_" -ForegroundColor Red
                Write-Host "  (Try running Falsum as Administrator)" -ForegroundColor Yellow
            }
        }
    }

    Add-FalsumVaultEntry -Type "browser-policies-removed" -Data @{
        removed_count = $removed
        backup_location = $backupDir
        timestamp = (Get-Date).ToString("o")
    }

    Write-Host "`n$removed policy trees removed." -ForegroundColor Green
    Write-Host "Restart Chrome/Edge. Your greyed-out settings should be unlocked." -ForegroundColor Cyan
    Write-Host "Backup is at: $backupDir (to restore, double-click the .reg files)" -ForegroundColor Gray
}

function Restore-FalsumBrowserPolicies {
    param([string]$BackupDir)

    if (!$BackupDir -or !(Test-Path $BackupDir)) {
        # Find the most recent backup
        $vaultDir = "$env:LOCALAPPDATA\Falsum\vault"
        $backups = Get-ChildItem $vaultDir -Directory -Filter "policy-backup-*" -ErrorAction SilentlyContinue |
                   Sort-Object Name -Descending
        if ($backups.Count -eq 0) {
            Write-Host "No policy backups found." -ForegroundColor Yellow
            return
        }
        $BackupDir = $backups[0].FullName
        Write-Host "Using most recent backup: $BackupDir" -ForegroundColor Gray
    }

    Get-ChildItem $BackupDir -Filter "*.reg" | ForEach-Object {
        Write-Host "  Restoring: $($_.Name)" -ForegroundColor Gray
        reg import $_.FullName 2>$null
    }

    Write-Host "Policies restored. Restart Chrome/Edge." -ForegroundColor Green
}
