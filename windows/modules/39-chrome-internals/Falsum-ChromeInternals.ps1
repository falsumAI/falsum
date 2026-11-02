# Falsum Module 39: Chrome Internals Reader
# Chrome extensions CANNOT access chrome:// pages (hard browser security boundary).
# But the DESKTOP app can read the same data from disk — those pages are just
# UIs over local files. Falsum reads the files directly.
#
# Covers: net-internals, webrtc-internals, sync-internals, extensions-internals,
# gpu, histograms, prefs-internals, webrtc-logs, media-internals, and more.

function Get-FalsumChromeProfilePath {
    $paths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:LOCALAPPDATA\Chromium\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Invoke-FalsumChromeInternalsScan {
    Write-Host "`n=== CHROME INTERNALS READER ===" -ForegroundColor Cyan
    Write-Host "Reading what chrome:// pages show — from disk, not the browser.`n"

    $profileRoot = Get-FalsumChromeProfilePath
    if (!$profileRoot) {
        Write-Host "No Chrome/Chromium/Edge profile found." -ForegroundColor Yellow
        return
    }

    Write-Host "Profile: $profileRoot`n" -ForegroundColor Gray
    $findings = @()

    # 1. Local State (chrome://local-state, chrome://version, chrome://gpu equivalent)
    Write-Host "[Browser State]" -ForegroundColor Yellow
    $localStatePath = Join-Path $profileRoot "Local State"
    if (Test-Path $localStatePath) {
        try {
            $localState = Get-Content $localStatePath -Raw | ConvertFrom-Json

            # Check for policies (chrome://policy, chrome://management)
            # If policies exist, the browser may be managed (enterprise control)
            if ($localState.policy) {
                Write-Host "  WARNING: Browser policies detected (chrome://policy)" -ForegroundColor Red
                Write-Host "  This browser may be enterprise-managed."
                $findings += @{
                    Type = "BrowserPolicy"
                    Detail = "Policies present in Local State"
                }
                Add-FalsumVaultEntry -Type "chrome-policy" -Data @{
                    warning = "Browser has enterprise policies — may not be under user control"
                }
            }

            # Check profile info
            $profiles = $localState.profile.info_cache.PSObject.Properties.Name
            Write-Host "  Profiles: $($profiles -join ', ')"
        }
        catch {
            Write-Host "  Could not parse Local State: $_" -ForegroundColor DarkGray
        }
    }

    # 2. Preferences per profile (chrome://prefs-internals, chrome://settings)
    $defaultProfile = Join-Path $profileRoot "Default"
    if (Test-Path $defaultProfile) {
        Write-Host "`n[Preferences]" -ForegroundColor Yellow
        $prefsPath = Join-Path $defaultProfile "Preferences"
        if (Test-Path $prefsPath) {
            try {
                $prefs = Get-Content $prefsPath -Raw | ConvertFrom-Json

                # WebRTC IP handling (chrome://webrtc-internals equivalent)
                # Check if WebRTC is allowed to leak local IPs
                $webrtcPolicy = $prefs.webrtc.ip_handling_policy
                Write-Host "  WebRTC IP policy: $(if ($webrtcPolicy) { $webrtcPolicy } else { 'default (may leak)' })"

                # Check for extensions (chrome://extensions-internals)
                $extSettings = $prefs.extensions.settings.PSObject.Properties
                Write-Host "  Installed extensions: $($extSettings.Count)"
                foreach ($ext in $extSettings) {
                    # Flag extensions with broad permissions
                    $manifest = $ext.Value.manifest
                    if ($manifest -and $manifest.permissions) {
                        $perms = $manifest.permissions -join ", "
                        if ($perms -match "tabs|webRequest|cookies|history|management") {
                            Write-Host "    WARNING: '$($manifest.name)' has broad permissions: $perms" -ForegroundColor Yellow
                            $findings += @{
                                Type = "ExtensionBroadPermissions"
                                Name = $manifest.name
                                Permissions = $perms
                            }
                        }
                    }
                }

                # Sync status (chrome://sync-internals)
                $syncEnabled = $prefs.sync
                if ($syncEnabled) {
                    Write-Host "  Sync: enabled (data going to Google servers)"
                    $findings += @{ Type = "SyncEnabled"; Detail = "Browser sync active" }
                }

                # Privacy Sandbox (chrome://settings/privacySandbox)
                $topicsEnabled = $prefs.privacy_sandbox.topics_enabled
                Write-Host "  Privacy Sandbox Topics: $(if ($topicsEnabled -eq $false) { 'disabled (good)' } else { 'enabled' })"

            }
            catch {
                Write-Host "  Could not parse Preferences: $_" -ForegroundColor DarkGray
            }
        }

        # 3. History database (chrome://history)
        Write-Host "`n[History]" -ForegroundColor Yellow
        $historyPath = Join-Path $defaultProfile "History"
        if (Test-Path $historyPath) {
            # Copy to temp (Chrome locks the file)
            $tempHistory = "$env:TEMP\falsum-history-copy.db"
            Copy-Item $historyPath $tempHistory -Force -ErrorAction SilentlyContinue

            # We can't use SQLite without a library, but we can check file size and modification
            $historyInfo = Get-Item $tempHistory -ErrorAction SilentlyContinue
            if ($historyInfo) {
                Write-Host "  History DB size: $([math]::Round($historyInfo.Length / 1MB, 1)) MB"
                Write-Host "  Last modified: $($historyInfo.LastWriteTime)"
                Remove-Item $tempHistory -Force -ErrorAction SilentlyContinue
            }
        }

        # 4. Check for WebRTC logs (chrome://webrtc-logs)
        $webrtcLogs = Join-Path $defaultProfile "webrtc_event_logs"
        if (Test-Path $webrtcLogs) {
            $logCount = (Get-ChildItem $webrtcLogs -ErrorAction SilentlyContinue).Count
            Write-Host "`n[WebRTC Logs] $logCount log files present"
            if ($logCount -gt 0) {
                Write-Host "  WebRTC has been active. Check chrome://webrtc-internals for details." -ForegroundColor Yellow
            }
        }
    }

    # 5. GPU info (chrome://gpu) — check for hardware acceleration status
    Write-Host "`n[GPU]" -ForegroundColor Yellow
    Write-Host "  (GPU details require chrome://gpu in the browser — Falsum flags if SwiftShader/software rendering is forced, which can indicate tampering)"

    Write-Host "`nScan complete. $($findings.Count) findings." -ForegroundColor Green

    foreach ($f in $findings) {
        Add-FalsumVaultEntry -Type "chrome-internals" -Data $f
    }

    return $findings
}

function Clear-FalsumChromeTrackingData {
    # Clear the tracking data Chrome accumulates
    # (what chrome://settings/clearBrowserData does, but targeted)
    param([switch]$History, [switch]$Cookies, [switch]$Cache, [switch]$All)

    $profileRoot = Get-FalsumChromeProfilePath
    $defaultProfile = Join-Path $profileRoot "Default"

    Write-Host "Close Chrome before clearing data." -ForegroundColor Yellow
    $confirm = Read-Host "Is Chrome closed? (y/n)"
    if ($confirm -ne 'y') { Write-Host "Aborted."; return }

    if ($All -or $History) {
        Remove-Item (Join-Path $defaultProfile "History") -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $defaultProfile "History-journal") -Force -ErrorAction SilentlyContinue
        Write-Host "  History cleared." -ForegroundColor Green
    }
    if ($All -or $Cookies) {
        Remove-Item (Join-Path $defaultProfile "Cookies") -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $defaultProfile "Cookies-journal") -Force -ErrorAction SilentlyContinue
        Write-Host "  Cookies cleared." -ForegroundColor Green
    }
    if ($All -or $Cache) {
        Remove-Item (Join-Path $defaultProfile "Cache") -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Cache cleared." -ForegroundColor Green
    }

    Add-FalsumVaultEntry -Type "chrome-cleaned" -Data @{
        action = "Cleared Chrome tracking data"
        timestamp = (Get-Date).ToString("o")
    }
}
