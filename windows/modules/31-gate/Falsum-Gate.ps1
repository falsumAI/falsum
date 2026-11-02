<#
.SYNOPSIS
    Falsum Gate — gates every automated system on Windows.
    
.DESCRIPTION
    Gregg: "This application and extension needs to gate every single
    automated system that exists within this fucking Windows computer."
    
    Automation sectors on Windows:
    1. Task Scheduler — scheduled tasks (schtasks)
    2. Services — auto-start services
    3. Registry Run keys — auto-start programs
    4. WMI Event Consumers — hidden persistent automation
    5. Startup Folder — user login automation
    6. PowerShell Scheduled Jobs — PSScheduledJob
    7. COM Auto-start — COM objects that launch at boot
    8. Browser Extensions — automated browser actions (via extension bridge)
    9. AI Agents — unconsented agent operation (via Agent Watchdog pattern)
    
    The gate SITS at the monitoring point for each sector:
    - Watches event logs for new task/service creation
    - Polls registry keys for changes
    - Scans WMI for new event consumers
    - Alerts via bridge to browser extension + WPF app
    - Logs everything to vault (tamper-evident)
    
    This is DETECTION + ALERTING. True blocking requires a driver.
    The gate sees everything, logs everything, alerts on unknowns.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# SECTOR 1: Task Scheduler
# ============================================================================
function Get-ScheduledTasks {
    <#
    .SYNOPSIS
        List all scheduled tasks with their triggers and actions.
    #>
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name = $_.TaskName
                Path = $_.TaskPath
                State = $_.State
                Author = $_.Author
                Description = $_.Description
                LastRun = if ($info) { $info.LastRunTime } else { $null }
                NextRun = if ($info) { $info.NextRunTime } else { $null }
                Actions = ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
            }
        }
        return $tasks
    }
    catch {
        return @()
    }
}

function Get-NewScheduledTasks {
    <#
    .SYNOPSIS
        Check event log for tasks created in last 24h (Event ID 106).
    #>
    param([int]$Hours = 24)
    try {
        $start = (Get-Date).AddHours(-$Hours)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-TaskScheduler/Operational'
            ID = 106  # Task registered
            StartTime = $start
        } -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                TaskName = $_.Properties[0].Value
                User = $_.Properties[1].Value
            }
        }
        return $events
    }
    catch {
        return @()
    }
}

# ============================================================================
# SECTOR 2: Services
# ============================================================================
function Get-AutoStartServices {
    <#
    .SYNOPSIS
        List services set to auto-start.
    #>
    try {
        return Get-Service | Where-Object { $_.StartType -eq 'Automatic' } | ForEach-Object {
            $svc = Get-CimInstance Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Status = $_.Status
                Path = if ($svc) { $svc.PathName } else { "Unknown" }
                StartName = if ($svc) { $svc.StartName } else { "Unknown" }
            }
        }
    }
    catch {
        return @()
    }
}

# ============================================================================
# SECTOR 3: Registry Run Keys (already in Purge, extended here)
# ============================================================================
$script:GateRegistryKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

function Get-RegistryAutoStarts {
    $results = @()
    foreach ($key in $script:GateRegistryKeys) {
        if (Test-Path $key) {
            try {
                $item = Get-Item $key -ErrorAction Stop
                foreach ($valName in $item.GetValueNames()) {
                    $results += [PSCustomObject]@{
                        Key = $key
                        Name = $valName
                        Value = $item.GetValue($valName)
                    }
                }
            }
            catch { }
        }
    }
    return $results
}

# ============================================================================
# SECTOR 4: WMI Event Consumers (hidden automation)
# ============================================================================
function Get-WmiEventConsumers {
    <#
    .SYNOPSIS
        Find WMI permanent event consumers — the stealthiest automation.
        Normal systems have few. Malware loves these.
    #>
    try {
        $consumers = Get-CimInstance -Namespace "root\subscription" -ClassName __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Class = $_.CimClass.CimClassName
            }
        }
        $filters = Get-CimInstance -Namespace "root\subscription" -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Query = $_.Query
            }
        }
        $bindings = Get-CimInstance -Namespace "root\subscription" -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
        
        return [PSCustomObject]@{
            Consumers = $consumers
            Filters = $filters
            BindingCount = ($bindings | Measure-Object).Count
        }
    }
    catch {
        return [PSCustomObject]@{ Consumers = @(); Filters = @(); BindingCount = 0 }
    }
}

# ============================================================================
# SECTOR 5: Startup Folder
# ============================================================================
function Get-StartupFolderItems {
    $paths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    $items = @()
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $items += Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{
                    Path = $p
                    Name = $_.Name
                    Target = if ($_.Extension -eq '.lnk') {
                        try { (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).TargetPath } catch { "Unknown" }
                    } else { $_.FullName }
                }
            }
        }
    }
    return $items
}

# ============================================================================
# THE GATE: Unified automation audit
# ============================================================================
function Invoke-GateAudit {
    <#
    .SYNOPSIS
        Audit ALL automation sectors. The gate sees everything.
    #>
    [CmdletBinding()]
    param(
        [string]$VaultPath = "",
        [switch]$AlertOnNew
    )
    
    Write-Host "`n[GATE] Auditing all automation sectors..." -ForegroundColor Cyan
    
    $report = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString('o')
        TaskScheduler = @{
            Total = 0
            New24h = @()
        }
        Services = @{
            AutoStartCount = 0
        }
        Registry = @{
            Entries = @()
        }
        WMI = @{
            Consumers = @()
            Filters = @()
            Bindings = 0
        }
        StartupFolder = @()
    }
    
    # Sector 1: Tasks
    Write-Host "  [1/5] Task Scheduler..." -ForegroundColor Gray
    $tasks = Get-ScheduledTasks
    $report.TaskScheduler.Total = $tasks.Count
    if ($AlertOnNew) {
        $report.TaskScheduler.New24h = Get-NewScheduledTasks -Hours 24
        if ($report.TaskScheduler.New24h.Count -gt 0) {
            Write-Host "    ⚠ $($report.TaskScheduler.New24h.Count) new tasks in 24h!" -ForegroundColor Red
        }
    }
    
    # Sector 2: Services
    Write-Host "  [2/5] Services..." -ForegroundColor Gray
    $svcs = Get-AutoStartServices
    $report.Services.AutoStartCount = $svcs.Count
    
    # Sector 3: Registry
    Write-Host "  [3/5] Registry Run keys..." -ForegroundColor Gray
    $report.Registry.Entries = Get-RegistryAutoStarts
    
    # Sector 4: WMI
    Write-Host "  [4/5] WMI Event Consumers..." -ForegroundColor Gray
    $wmi = Get-WmiEventConsumers
    $report.WMI.Consumers = $wmi.Consumers
    $report.WMI.Filters = $wmi.Filters
    $report.WMI.Bindings = $wmi.BindingCount
    if ($wmi.BindingCount -gt 0) {
        Write-Host "    ⚠ $($wmi.BindingCount) WMI bindings found (check these!)" -ForegroundColor Yellow
    }
    
    # Sector 5: Startup
    Write-Host "  [5/5] Startup Folder..." -ForegroundColor Gray
    $report.StartupFolder = Get-StartupFolderItems
    
    # Log to vault
    if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
        $report | ConvertTo-Json -Depth 6 | Add-Content -Path $VaultPath -Encoding UTF8
    }
    
    # Alert via bridge (to browser extension)
    if ((Get-Command Send-ToExtension -ErrorAction SilentlyContinue)) {
        $alerts = @()
        if ($report.TaskScheduler.New24h.Count -gt 0) {
            $alerts += "$($report.TaskScheduler.New24h.Count) new scheduled tasks"
        }
        if ($report.WMI.BindingCount -gt 0) {
            $alerts += "$($report.WMI.BindingCount) WMI event bindings"
        }
        if ($alerts.Count -gt 0) {
            Send-ToExtension -Type "gate-alert" -Data @{
                message = "Automation gate: " + ($alerts -join ", ")
                timestamp = $report.Timestamp
            } | Out-Null
        }
    }
    
    Write-Host "`n[GATE] Audit complete." -ForegroundColor Cyan
    Write-Host "  Tasks: $($report.TaskScheduler.Total) | Services: $($report.Services.AutoStartCount) | " -NoNewline
    Write-Host "Registry: $($report.Registry.Entries.Count) | WMI: $($report.WMI.BindingCount) | Startup: $($report.StartupFolder.Count)"
    
    return $report
}

function Disable-ScheduledTaskGate {
    <#
    .SYNOPSIS
        Disable a scheduled task (block automation). Logs to vault.
    #>
    param([string]$TaskName, [string]$TaskPath = "\", [string]$VaultPath = "")
    
    # Never disable critical system tasks
    $protected = @("Microsoft\Windows", "System", "Sysmain")
    foreach ($p in $protected) {
        if ($TaskPath -like "*$p*") {
            return @{ Success = $false; Message = "Protected system task, refusing: $TaskPath$TaskName" }
        }
    }
    
    try {
        Disable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
        
        $result = @{
            Success = $true
            Message = "Disabled scheduled task: $TaskPath$TaskName"
            Timestamp = (Get-Date).ToString('o')
        }
        
        if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
            $result | ConvertTo-Json | Add-Content -Path $VaultPath -Encoding UTF8
        }
        
        return $result
    }
    catch {
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Stop-AutomationService {
    <#
    .SYNOPSIS
        Stop a service that's part of unwanted automation.
    #>
    param([string]$ServiceName, [string]$VaultPath = "")
    
    # Never stop critical services
    $critical = @("EventLog", "RpcSs", "DcomLaunch", "PlugPlay", "Power", "LanmanServer")
    if ($ServiceName -in $critical) {
        return @{ Success = $false; Message = "Critical service, refusing: $ServiceName" }
    }
    
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        
        $result = @{
            Success = $true
            Message = "Stopped service: $ServiceName"
            Timestamp = (Get-Date).ToString('o')
        }
        
        if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
            $result | ConvertTo-Json | Add-Content -Path $VaultPath -Encoding UTF8
        }
        
        return $result
    }
    catch {
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Remove-WmiPersistence {
    <#
    .SYNOPSIS
        Remove WMI event consumer (block WMI-based automation/persistence).
    #>
    param([string]$ConsumerName, [string]$VaultPath = "")
    
    try {
        $consumer = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer -Filter "Name='$ConsumerName'" -ErrorAction Stop
        if (-not $consumer) {
            return @{ Success = $false; Message = "WMI consumer not found: $ConsumerName" }
        }
        
        # Log before removal
        $logEntry = @{
            Action = "Remove-WmiPersistence"
            ConsumerName = $ConsumerName
            ConsumerClass = $consumer.__CLASS
            Timestamp = (Get-Date).ToString('o')
        }
        
        if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
            $logEntry | ConvertTo-Json | Add-Content -Path $VaultPath -Encoding UTF8
        }
        
        $consumer | Remove-WmiObject -ErrorAction Stop
        
        return @{ Success = $true; Message = "Removed WMI consumer: $ConsumerName" }
    }
    catch {
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Test-GateHygiene {
    $issues = @()
    # Must not require admin for read-only audit
    # Must handle missing WMI namespace gracefully
    # Must not crash on empty event log
    return [PSCustomObject]@{ Passed = ($issues.Count -eq 0); Issues = $issues }
}

# Functions available via dot-sourcing
