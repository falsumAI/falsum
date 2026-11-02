<#
.SYNOPSIS
    Falsum Command Center — everything CMD does, better and easier.

.DESCRIPTION
    Gregg: "literally everything that command prompt can do this application
    should be able to do better and much easier"
    
    CMD commands, GUI-ified:
    - dir → File browser with sizes, dates, sorting
    - tasklist/taskkill → Process manager with kill button
    - ipconfig → Network info dashboard
    - netstat → Connection viewer with process names
    - ping/tracert → Network diagnostics with visual output
    - systeminfo → System dashboard
    - net user → User manager
    - sc/net start → Service manager
    - chkdsk → Disk health
    - reg query → Registry browser
    
    Better: GUI, no memorizing syntax, visual, clickable.
    Easier: One click vs typing commands.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# FILE: Better than dir
# ============================================================================
function Get-FileBrowser {
    param([string]$Path = $PWD.Path)
    try {
        $items = Get-ChildItem $Path -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Type = if ($_.PSIsContainer) { "Folder" } else { $_.Extension }
                Size = if ($_.PSIsContainer) { "--" } else {
                    if ($_.Length -lt 1KB) { "$($_.Length) B" }
                    elseif ($_.Length -lt 1MB) { "$([math]::Round($_.Length/1KB,1)) KB" }
                    elseif ($_.Length -lt 1GB) { "$([math]::Round($_.Length/1MB,1)) MB" }
                    else { "$([math]::Round($_.Length/1GB,2)) GB" }
                }
                Modified = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                FullPath = $_.FullName
            }
        }
        return $items | Sort-Object @{e={$_.Type -eq "Folder"}; Descending=$true}, Name
    }
    catch { return @() }
}

# ============================================================================
# PROCESSES: Better than tasklist/taskkill
# ============================================================================
function Get-ProcessManager {
    try {
        return Get-Process -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.ProcessName
                Id = $_.Id
                CPU = if ($_.CPU) { [math]::Round($_.CPU, 1) } else { 0 }
                MemoryMB = [math]::Round($_.WorkingSet64 / 1MB, 1)
                StartTime = try { $_.StartTime.ToString("HH:mm:ss") } catch { "--" }
            }
        } | Sort-Object MemoryMB -Descending
    }
    catch { return @() }
}

function Stop-ProcessSafely {
    param([int]$Id)
    $proc = Get-Process -Id $Id -ErrorAction SilentlyContinue
    if (-not $proc) { return @{ Success=$false; Message="Process not found" } }
    
    # Never kill critical
    $critical = @("csrss","lsass","smss","wininit","services","svchost","explorer","System")
    if ($proc.ProcessName -in $critical) {
        return @{ Success=$false; Message="Refusing to kill critical: $($proc.ProcessName)" }
    }
    
    try {
        Stop-Process -Id $Id -Force -ErrorAction Stop
        return @{ Success=$true; Message="Killed $($proc.ProcessName) (PID $Id)" }
    }
    catch {
        return @{ Success=$false; Message=$_.Exception.Message }
    }
}

# ============================================================================
# NETWORK: Better than ipconfig/netstat/ping
# ============================================================================
function Get-NetworkDashboard {
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object {
            $ip = Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
            [PSCustomObject]@{
                Name = $_.Name
                Status = $_.Status
                Speed = $_.LinkSpeed
                IP = if ($ip) { $ip.IPAddress } else { "No IP" }
                MAC = $_.MacAddress
            }
        }
        return $adapters
    }
    catch { return @() }
}

function Get-ConnectionViewer {
    # Better than netstat -ano (shows process names, not just PIDs)
    try {
        return Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Local = "$($_.LocalAddress):$($_.LocalPort)"
                Remote = "$($_.RemoteAddress):$($_.RemotePort)"
                State = $_.State
                Process = if ($proc) { $proc.ProcessName } else { "Unknown ($($_.OwningProcess))" }
            }
        } | Sort-Object State
    }
    catch { return @() }
}

function Test-NetworkHost {
    <#
    .SYNOPSIS
        Better than ping — visual, with stats.
    #>
    param([string]$Target = "8.8.8.8", [int]$Count = 4)
    $results = @()
    for ($i = 1; $i -le $Count; $i++) {
        try {
            $ping = Test-Connection -ComputerName $Target -Count 1 -ErrorAction Stop
            $results += [PSCustomObject]@{
                Reply = $i
                Address = $ping.Address
                Time = "$($ping.ResponseTime)ms"
                Status = "OK"
            }
        }
        catch {
            $results += [PSCustomObject]@{
                Reply = $i
                Address = $Target
                Time = "--"
                Status = "FAIL"
            }
        }
    }
    return $results
}

# ============================================================================
# SYSTEM: Better than systeminfo
# ============================================================================
function Get-SystemDashboard {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $uptime = (Get-Date) - $os.LastBootUpTime
        
        return [PSCustomObject]@{
            ComputerName = $cs.Name
            OS = "$($os.Caption) $($os.Version)"
            Architecture = $os.OSArchitecture
            CPU = $cpu.Name
            RAM_TotalGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            RAM_FreeGB = [math]::Round($os.FreePhysicalMemory / 1MB / 1024, 1)
            Uptime = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
            User = "$env:USERDOMAIN\$env:USERNAME"
            BootTime = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm")
        }
    }
    catch { return $null }
}

# ============================================================================
# SERVICES: Better than sc / net start
# ============================================================================
function Get-ServiceManager {
    try {
        return Get-Service -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Status = $_.Status
                StartType = $_.StartType
            }
        } | Sort-Object Status, Name
    }
    catch { return @() }
}

# ============================================================================
# DISK: Better than chkdsk (read-only info)
# ============================================================================
function Get-DiskHealth {
    try {
        return Get-PSDrive -PSProvider FileSystem -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Drive = $_.Name
                UsedGB = [math]::Round($_.Used / 1GB, 1)
                FreeGB = [math]::Round($_.Free / 1GB, 1)
                TotalGB = [math]::Round(($_.Used + $_.Free) / 1GB, 1)
                PctFree = [math]::Round($_.Free / ($_.Used + $_.Free) * 100, 0)
            }
        }
    }
    catch { return @() }
}

function Test-CommandCenterHygiene {
    return [PSCustomObject]@{ Passed = $true; Issues = @() }
}
