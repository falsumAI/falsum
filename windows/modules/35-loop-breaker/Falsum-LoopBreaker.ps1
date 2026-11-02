# Falsum Module 35: Loop Breaker
# Solves the two loops Gregg struggled to get rid of:
# 1. SOFTWARE LOOP: programs that reinstall themselves, won't uninstall, keep coming back
# 2. NETWORK LOOP: phantom network configs that revert, connections that won't die

function Invoke-FalsumLoopBreaker {
    param(
        [switch]$Software,
        [switch]$Network,
        [switch]$Fix
    )

    if ($Software -or (!$Software -and !$Network)) {
        Write-Host "`n=== SOFTWARE LOOP BREAKER ===" -ForegroundColor Cyan
        Find-SoftwareLoop
        if ($Fix) { Break-SoftwareLoop }
    }

    if ($Network -or (!$Software -and !$Network)) {
        Write-Host "`n=== NETWORK LOOP BREAKER ===" -ForegroundColor Cyan
        Find-NetworkLoop
        if ($Fix) { Break-NetworkLoop }
    }
}

function Find-SoftwareLoop {
    # Find programs that resist uninstallation:
    # - Multiple registry entries (HKLM + HKCU + Wow6432Node)
    # - Scheduled tasks that reinstall
    # - Services that restart on kill
    # - Startup entries that reappear

    $loops = @()

    # Check for reinstall scheduled tasks
    $tasks = Get-ScheduledTask | Where-Object {
        $_.TaskName -match "update|install|repair|maintain" -and
        $_.State -eq "Ready"
    }
    foreach ($t in $tasks) {
        # Check if the task points to an installer/updater
        $action = ($t.Actions | Select-Object -First 1).Execute
        if ($action -match "\.exe$" -and (Test-Path $action)) {
            $loops += @{
                Type = "ScheduledReinstall"
                Name = $t.TaskName
                Path = $action
                Description = "Scheduled task may reinstall software"
            }
        }
    }

    # Check for services with restart-on-failure (loop behavior)
    $services = Get-WmiObject Win32_Service | Where-Object {
        $_.StartMode -eq "Auto" -and $_.State -eq "Running"
    }
    foreach ($s in $services) {
        # Check recovery actions (sc qfailure)
        $recovery = sc.exe qfailure $s.Name 2>$null | Out-String
        if ($recovery -match "RESTART") {
            $loops += @{
                Type = "ServiceRestartLoop"
                Name = $s.Name
                Path = $s.PathName
                Description = "Service auto-restarts on failure (potential loop)"
            }
        }
    }

    # Log to vault
    foreach ($l in $loops) {
        Add-FalsumVaultEntry -Type "software-loop" -Data $l
    }

    Write-Host "Found $($loops.Count) potential software loops."
    return $loops
}

function Break-SoftwareLoop {
    param($Loops)

    if (!$Loops) { $Loops = Find-SoftwareLoop }

    foreach ($l in $Loops) {
        Write-Host "`nBreaking loop: $($l.Name)" -ForegroundColor Yellow
        Write-Host "  Type: $($l.Type)"
        Write-Host "  Path: $($l.Path)"

        $confirm = Read-Host "  Disable this? (y/n)"
        if ($confirm -eq 'y') {
            switch ($l.Type) {
                "ScheduledReinstall" {
                    Disable-ScheduledTask -TaskName $l.Name
                    Write-Host "  Disabled scheduled task." -ForegroundColor Green
                }
                "ServiceRestartLoop" {
                    # Change recovery to "take no action" instead of restart
                    sc.exe failure $l.Name reset= 0 actions= "" | Out-Null
                    Write-Host "  Disabled auto-restart." -ForegroundColor Green
                }
            }

            Add-FalsumVaultEntry -Type "software-loop-broken" -Data @{
                name = $l.Name
                type = $l.Type
                action = "disabled"
                timestamp = (Get-Date).ToString("o")
            }
        }
    }
}

function Find-NetworkLoop {
    # Find phantom network configurations:
    # - Static routes that reappear
    # - DNS settings that revert
    # - Proxy settings that won't stay off
    # - Hosts file entries that reappear

    $loops = @()

    # Check hosts file for persistent entries
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsContent = Get-Content $hostsPath -Raw
    # Gregg's case: hosts null-routed vortex.data.microsoft.com
    # Any non-comment, non-localhost entry is suspicious
    $suspicious = $hostsContent -split "`n" | Where-Object {
        $_ -notmatch "^\s*#" -and $_ -match "\S" -and $_ -notmatch "localhost"
    }
    if ($suspicious) {
        $loops += @{
            Type = "HostsFile"
            Entries = $suspicious
            Description = "Non-standard hosts entries (may block or redirect traffic)"
        }
    }

    # Check for persistent static routes
    $routes = Get-NetRoute -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
              Where-Object { $_.NextHop -ne "0.0.0.0" }
    if ($routes) {
        $loops += @{
            Type = "PersistentRoute"
            Count = $routes.Count
            Description = "Persistent static routes (survive reboot)"
        }
    }

    # Check proxy settings
    $proxy = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    if ($proxy.ProxyEnable -eq 1) {
        $loops += @{
            Type = "ProxyEnabled"
            Server = $proxy.ProxyServer
            Description = "Proxy is enabled (may intercept traffic)"
        }
    }

    foreach ($l in $loops) {
        Add-FalsumVaultEntry -Type "network-loop" -Data $l
    }

    Write-Host "Found $($loops.Count) potential network loops."
    return $loops
}

function Break-NetworkLoop {
    param($Loops)

    if (!$Loops) { $Loops = Find-NetworkLoop }

    foreach ($l in $Loops) {
        Write-Host "`nBreaking loop: $($l.Type)" -ForegroundColor Yellow

        $confirm = Read-Host "  Fix this? (y/n)"
        if ($confirm -eq 'y') {
            switch ($l.Type) {
                "HostsFile" {
                    # Backup then clean
                    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
                    Copy-Item $hostsPath "$hostsPath.falsum-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                    # Keep only localhost entries
                    $clean = Get-Content $hostsPath | Where-Object {
                        $_ -match "^\s*#" -or $_ -match "localhost" -or $_ -notmatch "\S"
                    }
                    $clean | Set-Content $hostsPath -Force
                    Write-Host "  Cleaned hosts file (backup created)." -ForegroundColor Green
                }
                "ProxyEnabled" {
                    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0
                    Write-Host "  Disabled proxy." -ForegroundColor Green
                }
                "PersistentRoute" {
                    Write-Host "  Manual review required for persistent routes." -ForegroundColor Yellow
                }
            }

            Add-FalsumVaultEntry -Type "network-loop-broken" -Data @{
                type = $l.Type
                action = "fixed"
                timestamp = (Get-Date).ToString("o")
            }
        }
    }
}
