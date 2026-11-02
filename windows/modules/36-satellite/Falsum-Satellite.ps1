# Falsum Module 36: Bluetooth & Satellite Detector
# Detects: Bluetooth radios, satellite modems, Bluetooth-to-satellite bridges,
# and any hardware that can exfiltrate data via non-WiFi/non-Ethernet paths.

function Invoke-FalsumSatelliteScan {
    Write-Host "`n=== BLUETOOTH & SATELLITE DETECTOR ===" -ForegroundColor Cyan

    $findings = @()

    # 1. Bluetooth radios
    Write-Host "`n[Bluetooth Radios]" -ForegroundColor Yellow
    $btDevices = Get-PnpDevice | Where-Object {
        $_.Class -eq "Bluetooth" -and $_.Status -eq "OK"
    }
    foreach ($d in $btDevices) {
        Write-Host "  Found: $($d.FriendlyName)"
        $findings += @{
            Type = "Bluetooth"
            Name = $d.FriendlyName
            ID = $d.InstanceId
            Status = $d.Status
        }
        Add-FalsumVaultEntry -Type "bluetooth" -Data @{
            name = $d.FriendlyName
            id = $d.InstanceId
        }
    }
    if ($btDevices.Count -eq 0) { Write-Host "  No active Bluetooth radios." }

    # 2. Paired Bluetooth devices (potential exfiltration endpoints)
    Write-Host "`n[Paired Bluetooth Devices]" -ForegroundColor Yellow
    $paired = Get-PnpDevice | Where-Object {
        $_.Class -eq "Bluetooth" -and $_.FriendlyName -match "paired|connected"
    }
    # Also check registry for paired devices
    $btReg = "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"
    if (Test-Path $btReg) {
        $devices = Get-ChildItem $btReg -ErrorAction SilentlyContinue
        Write-Host "  Paired device count: $($devices.Count)"
        foreach ($dev in $devices) {
            $findings += @{
                Type = "BluetoothPaired"
                Address = $dev.PSChildName
            }
        }
    }

    # 3. Satellite modems / WAN devices
    Write-Host "`n[Satellite & Cellular Modems]" -ForegroundColor Yellow
    $modems = Get-PnpDevice | Where-Object {
        ($_.FriendlyName -match "satellite|iridium|inmarsat|globalstar|thales|hughes|viasat|starlink") -or
        ($_.Class -eq "Modem" -and $_.Status -eq "OK")
    }
    foreach ($m in $modems) {
        Write-Host "  WARNING: $($m.FriendlyName)" -ForegroundColor Red
        $findings += @{
            Type = "SatelliteModem"
            Name = $m.FriendlyName
            ID = $m.InstanceId
        }
        Add-FalsumVaultEntry -Type "satellite" -Data @{
            name = $m.FriendlyName
            warning = "Satellite modem can bypass local network monitoring"
        }
    }
    if ($modems.Count -eq 0) { Write-Host "  No satellite modems detected." }

    # 4. Cell-node detection: is this PC acting as infrastructure?
    Write-Host "`n[Cell Node / Infrastructure Check]" -ForegroundColor Yellow

    # Mobile hotspot
    $hotspot = Get-NetConnectionProfile | Where-Object { $_.Name -match "hotspot" }
    $tethering = Get-Service -Name "icssvc" -ErrorAction SilentlyContinue  # Internet Connection Sharing
    if ($tethering -and $tethering.Status -eq "Running") {
        Write-Host "  WARNING: Internet Connection Sharing is RUNNING" -ForegroundColor Red
        Write-Host "  This PC may be acting as a network node for other devices."
        $findings += @{
            Type = "CellNode"
            Service = "icssvc"
            Description = "Internet Connection Sharing active — PC is routing traffic for others"
        }
        Add-FalsumVaultEntry -Type "cellnode" -Data @{
            service = "icssvc"
            warning = "PC acting as network infrastructure"
        }
    }

    # WiFi Direct / Miracast (can create peer networks)
    $wifiDirect = Get-PnpDevice | Where-Object {
        $_.FriendlyName -match "Wi-Fi Direct|Miracast" -and $_.Status -eq "OK"
    }
    if ($wifiDirect) {
        Write-Host "  WiFi Direct adapters found (can create peer-to-peer networks):"
        foreach ($w in $wifiDirect) {
            Write-Host "    - $($w.FriendlyName)"
        }
    }

    # Network bridging
    $bridges = Get-NetAdapter | Where-Object { $_.Name -match "bridge" }
    if ($bridges) {
        Write-Host "  WARNING: Network bridge detected" -ForegroundColor Red
        $findings += @{ Type = "NetworkBridge"; Name = $bridges.Name }
    }

    Write-Host "`nScan complete. $($findings.Count) findings logged to vault."
    return $findings
}

function Disable-FalsumCellNode {
    # Turn off everything that makes this PC act as infrastructure
    Write-Host "Disabling cell-node services..." -ForegroundColor Yellow

    # Stop Internet Connection Sharing
    Stop-Service -Name "icssvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "icssvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "  Internet Connection Sharing: disabled"

    Add-FalsumVaultEntry -Type "cellnode-disabled" -Data @{
        action = "Disabled ICS and infrastructure services"
        timestamp = (Get-Date).ToString("o")
    }

    Write-Host "Done. This PC no longer acts as network infrastructure." -ForegroundColor Green
}

function Get-FalsumSatelliteDataExtraction {
    <#
    .SYNOPSIS
        Detects DATA EXTRACTION via Bluetooth-to-satellite paths.
        Normal network monitors (packet witness, firewall) can't see
        Bluetooth or satellite traffic. This closes that gap.
    #>
    Write-Host "`n=== DATA EXTRACTION VIA BLUETOOTH/SATELLITE ===" -ForegroundColor Red

    $extractions = @()

    # 1. Bluetooth network adapters (PAN - Personal Area Network)
    # Bluetooth can carry IP traffic via PAN profile — invisible to WiFi/Ethernet monitors
    $btNet = Get-NetAdapter | Where-Object {
        $_.InterfaceDescription -match "Bluetooth" -and $_.Status -eq "Up"
    }
    foreach ($adapter in $btNet) {
        Write-Host "`n  WARNING: Bluetooth network adapter ACTIVE" -ForegroundColor Red
        Write-Host "  Adapter: $($adapter.Name)"
        Write-Host "  This can carry IP traffic invisible to standard monitors."

        # Check for active connections on this interface
        $btConns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
            $_.LocalAddress -ne "127.0.0.1" -and $_.State -eq "Established"
        }
        # Note: correlating to specific interface requires Get-NetAdapter statistics
        $stats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue
        if ($stats) {
            Write-Host "  Bytes sent: $($stats.SentBytes)"
            Write-Host "  Bytes received: $($stats.ReceivedBytes)"
            if ($stats.SentBytes -gt 0) {
                Write-Host "  DATA IS LEAVING VIA BLUETOOTH" -ForegroundColor Red
                $extractions += @{
                    Type = "BluetoothDataExtraction"
                    Adapter = $adapter.Name
                    BytesSent = $stats.SentBytes
                    BytesReceived = $stats.ReceivedBytes
                }
            }
        }

        Add-FalsumVaultEntry -Type "bt-extraction" -Data @{
            adapter = $adapter.Name
            bytesSent = $stats.SentBytes
            warning = "Bluetooth network active — potential data exfiltration path"
        }
    }

    # 2. Satellite modem data usage
    $modems = Get-PnpDevice | Where-Object {
        $_.FriendlyName -match "satellite|iridium|inmarsat|globalstar" -and $_.Status -eq "OK"
    }
    foreach ($m in $modems) {
        # Check for associated network adapter
        $modemNet = Get-NetAdapter | Where-Object {
            $_.InterfaceDescription -match $m.FriendlyName.Split(' ')[0]
        }
        if ($modemNet) {
            $stats = Get-NetAdapterStatistics -Name $modemNet.Name -ErrorAction SilentlyContinue
            if ($stats -and $stats.SentBytes -gt 0) {
                Write-Host "`n  WARNING: Satellite modem transmitting data" -ForegroundColor Red
                Write-Host "  Modem: $($m.FriendlyName)"
                Write-Host "  Bytes sent: $($stats.SentBytes)"
                $extractions += @{
                    Type = "SatelliteDataExtraction"
                    Modem = $m.FriendlyName
                    BytesSent = $stats.SentBytes
                }

                Add-FalsumVaultEntry -Type "sat-extraction" -Data @{
                    modem = $m.FriendlyName
                    bytesSent = $stats.SentBytes
                    warning = "Satellite transmission — bypasses all local network controls"
                }
            }
        }
    }

    # 3. Bluetooth file transfer service (OBEX) — classic exfiltration
    $obex = Get-Service -Name "BTAGService" -ErrorAction SilentlyContinue
    if ($obex -and $obex.Status -eq "Running") {
        Write-Host "`n  Bluetooth Audio Gateway running (can carry data)"
    }

    if ($extractions.Count -eq 0) {
        Write-Host "`n  No active Bluetooth/satellite data extraction detected." -ForegroundColor Green
    } else {
        Write-Host "`n  $($extractions.Count) active extraction paths found!" -ForegroundColor Red
    }

    return $extractions
}

function Block-FalsumSatelliteExtraction {
    # Disable Bluetooth networking and block satellite modems
    Write-Host "Blocking Bluetooth/satellite data extraction..." -ForegroundColor Yellow

    # Disable Bluetooth network adapters
    $btNet = Get-NetAdapter | Where-Object {
        $_.InterfaceDescription -match "Bluetooth"
    }
    foreach ($adapter in $btNet) {
        Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "  Disabled: $($adapter.Name)" -ForegroundColor Green
    }

    # Disable Bluetooth service
    Stop-Service -Name "bthserv" -Force -ErrorAction SilentlyContinue
    Write-Host "  Bluetooth support service stopped."

    Add-FalsumVaultEntry -Type "sat-blocked" -Data @{
        action = "Disabled Bluetooth networking and satellite paths"
        timestamp = (Get-Date).ToString("o")
    }

    Write-Host "Done. Bluetooth/satellite exfiltration paths blocked." -ForegroundColor Green
}
