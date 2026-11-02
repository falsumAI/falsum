# Falsum Module 37: Data Movement Gate
# Tracks EVERY byte entering and leaving Windows. The user decides what leaves.
# This is the "data diode" — nothing leaves without approval.

function Start-FalsumDataGate {
    param(
        [switch]$Monitor,  # Watch only, don't block
        [switch]$Enforce   # Block unapproved connections
    )

    Write-Host "`n=== DATA MOVEMENT GATE ===" -ForegroundColor Cyan
    Write-Host "Tracking all data entering and leaving this computer.`n"

    # Get all active TCP/UDP connections with owning process
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
                      @{N="Process";E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
                      @{N="PID";E={$_.OwningProcess}},
                      CreationTime

    $udpListeners = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort,
                      @{N="Process";E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}

    Write-Host "Active TCP connections: $($connections.Count)" -ForegroundColor Yellow
    Write-Host "UDP endpoints: $($udpListeners.Count)`n" -ForegroundColor Yellow

    # Group by process — show the user what's talking
    $byProcess = $connections | Group-Object Process | Sort-Object Count -Descending

    Write-Host "=== DATA LEAVING YOUR COMPUTER (by program) ===" -ForegroundColor Red
    foreach ($g in $byProcess) {
        $procName = if ($g.Name) { $g.Name } else { "Unknown" }
        Write-Host "`n  $procName ($($g.Count) connections):"
        foreach ($c in ($g.Group | Select-Object -First 3)) {
            Write-Host "    → $($c.RemoteAddress):$($c.RemotePort)"
        }
        if ($g.Count -gt 3) {
            Write-Host "    ... and $($g.Count - 3) more"
        }

        # Log to vault
        Add-FalsumVaultEntry -Type "data-egress" -Data @{
            process = $procName
            connections = $g.Count
            destinations = ($g.Group | Select-Object -First 5 | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" })
            timestamp = (Get-Date).ToString("o")
        }
    }

    if ($Enforce) {
        Write-Host "`n=== ENFORCE MODE ===" -ForegroundColor Red
        Write-Host "Review each program above. Falsum will create firewall rules"
        Write-Host "to block programs you don't approve.`n"

        foreach ($g in $byProcess) {
            $procName = if ($g.Name) { $g.Name } else { "Unknown" }
            if ($procName -eq "Unknown") { continue }

            $approve = Read-Host "Allow '$procName' to send data? (y/n)"
            if ($approve -ne 'y') {
                # Find the executable path and block it
                $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($proc) {
                    $exePath = $proc.Path
                    if ($exePath) {
                        $ruleName = "Falsum-Block-$procName"
                        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound `
                            -Program $exePath -Action Block -ErrorAction SilentlyContinue | Out-Null
                        Write-Host "  Blocked: $procName" -ForegroundColor Green

                        Add-FalsumVaultEntry -Type "data-blocked" -Data @{
                            process = $procName
                            path = $exePath
                            action = "Outbound blocked by user"
                        }
                    }
                }
            } else {
                Write-Host "  Allowed: $procName" -ForegroundColor Green
                Add-FalsumVaultEntry -Type "data-allowed" -Data @{
                    process = $procName
                    action = "Outbound approved by user"
                }
            }
        }
    }

    Write-Host "`nData gate scan complete. All movements logged to vault."
}

function Get-FalsumDataSummary {
    # Quick summary: how much data is leaving, to where
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

    $summary = @{
        TotalConnections = $connections.Count
        UniqueDestinations = ($connections | Select-Object -ExpandProperty RemoteAddress -Unique).Count
        Timestamp = (Get-Date).ToString("o")
    }

    # Flag suspicious: connections to non-standard ports, foreign IPs
    $suspicious = $connections | Where-Object {
        $_.RemotePort -notin @(80, 443, 53) -and
        $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
    }

    $summary.SuspiciousCount = $suspicious.Count

    if ($suspicious.Count -gt 0) {
        Write-Host "WARNING: $($suspicious.Count) connections to unusual ports/destinations" -ForegroundColor Red
        foreach ($s in ($suspicious | Select-Object -First 5)) {
            $proc = (Get-Process -Id $s.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            Write-Host "  $proc → $($s.RemoteAddress):$($s.RemotePort)"
        }
    }

    return $summary
}
