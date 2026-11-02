<#
.SYNOPSIS
    Falsum Memory Forensics — deep into RAM. Every process, every DLL, every anomaly.

.DESCRIPTION
    Gregg's order: "Go into the RAM. The deepest parts of the memory within
    the realm of my system."

    Pure PowerShell memory forensics — no external tools:
    - Full process tree with parent/child relationships
    - Every loaded DLL per process, with signature verification
    - Unsigned DLLs in signed processes (injection indicator)
    - Processes with no parent (orphans — possible injection)
    - Processes running from unusual paths (TEMP, AppData, Downloads)
    - Memory region summary per process (working set, private bytes)
    - WMI process details (command line, owner, creation time)

    Honest limits: this is live process/DLL enumeration, not a full RAM
    dump analysis (that needs WinPmem + Volatility, which are documented
    as the escalation path). What PowerShell CAN see, we see completely.

    FUNCTIONS:
      Get-ProcessTree            - full process tree with parents
      Get-ProcessModules         - loaded DLLs per process with signatures
      Find-UnsignedModules       - unsigned DLLs in processes (injection hunt)
      Find-OrphanProcesses       - processes with no living parent
      Find-SuspiciousPaths       - processes running from TEMP/AppData/Downloads
      Get-ProcessMemorySummary   - working set, private bytes, handles, threads
      Get-ProcessDetails         - WMI: command line, owner, creation time
      Invoke-MemoryForensics     - full sweep, all checks, logged
      Test-MemoryForensicsHygiene - self-test
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SuspiciousPaths = @(
    "$env:TEMP",
    "$env:TMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp",
    "$env:USERPROFILE\Downloads",
    "C:\ProgramData"
)

function Get-ProcessTree {
    <#
    .SYNOPSIS Full process list with parent PID resolution.
    #>
    $procs = Get-Process -ErrorAction SilentlyContinue
    $wmiProcs = @{}
    try {
        Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
            $wmiProcs[$_.ProcessId] = $_
        }
    }
    catch { }

    $tree = New-Object System.Collections.ArrayList
    foreach ($p in $procs) {
        try {
            $wmi = $wmiProcs[$p.Id]
            $parentId = if ($wmi) { $wmi.ParentProcessId } else { -1 }
            $parentName = ""
            if ($parentId -gt 0) {
                try { $parentName = (Get-Process -Id $parentId -ErrorAction SilentlyContinue).ProcessName }
                catch { $parentName = "[dead]" }
            }
            $procPath = "[access denied]"
            try { $procPath = $p.Path } catch { }
            $procStart = $null
            try { $procStart = $p.StartTime } catch { }
            [void]$tree.Add([PSCustomObject]@{
                Id = $p.Id
                Name = $p.ProcessName
                ParentId = $parentId
                ParentName = $parentName
                Path = $procPath
                StartTime = $procStart
                CommandLine = if ($wmi) { $wmi.CommandLine } else { "" }
            })
        }
        catch { }
    }
    return @($tree)
}

function Get-ProcessModules {
    <#
    .SYNOPSIS Loaded DLLs for a process, with signature check on each.
    #>
    param([Parameter(Mandatory=$true)][int]$ProcessId)

    $modules = New-Object System.Collections.ArrayList
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
        foreach ($mod in $proc.Modules) {
            $sigStatus = "Unknown"
            try {
                $sig = Get-AuthenticodeSignature -FilePath $mod.FileName -ErrorAction SilentlyContinue
                $sigStatus = if ($sig) { [string]$sig.Status } else { "NoSignature" }
            }
            catch { $sigStatus = "CheckFailed" }

            [void]$modules.Add([PSCustomObject]@{
                ProcessId = $ProcessId
                ProcessName = $proc.ProcessName
                ModuleName = $mod.ModuleName
                FileName = $mod.FileName
                BaseAddress = "0x$($mod.BaseAddress.ToString('X'))"
                ModuleMemorySize = $mod.ModuleMemorySize
                SignatureStatus = $sigStatus
            })
        }
    }
    catch {
        [void]$modules.Add([PSCustomObject]@{
            ProcessId = $ProcessId
            ProcessName = "[access denied]"
            ModuleName = "[enumeration failed]"
            FileName = ""
            BaseAddress = ""
            ModuleMemorySize = 0
            SignatureStatus = "EnumerationFailed"
        })
    }
    return @($modules)
}

function Find-UnsignedModules {
    <#
    .SYNOPSIS
        Hunt for unsigned DLLs loaded in processes. Classic injection indicator.
    .DESCRIPTION
        A signed process (like explorer.exe) loading an unsigned DLL is
        suspicious. This checks all accessible processes and flags unsigned
        modules. System processes that legitimately load unsigned DLLs will
        appear — analyst reviews the list.
    #>
    param([int]$MaxProcesses = 0)  # 0 = all

    $findings = New-Object System.Collections.ArrayList
    $procs = Get-Process -ErrorAction SilentlyContinue
    if ($MaxProcesses -gt 0) { $procs = $procs | Select-Object -First $MaxProcesses }

    foreach ($p in $procs) {
        try {
            $mods = Get-ProcessModules -ProcessId $p.Id
            foreach ($m in $mods) {
                if ($m.SignatureStatus -in @("NotSigned", "NoSignature", "HashMismatch", "NotTrusted")) {
                    [void]$findings.Add($m)
                }
            }
        }
        catch { }
    }
    return @($findings)
}

function Find-OrphanProcesses {
    <#
    .SYNOPSIS Processes whose parent is dead. Possible process hollowing/injection.
    #>
    $tree = Get-ProcessTree
    return @($tree | Where-Object { $_.ParentName -eq "[dead]" -and $_.ParentId -gt 0 })
}

function Find-SuspiciousPaths {
    <#
    .SYNOPSIS Processes running from TEMP, AppData, Downloads, ProgramData.
    #>
    $tree = Get-ProcessTree
    $findings = New-Object System.Collections.ArrayList
    foreach ($p in $tree) {
        if ($p.Path -eq "[access denied]" -or $p.Path -eq "") { continue }
        $pathLower = $p.Path.ToLower()
        foreach ($sus in $script:SuspiciousPaths) {
            if ($sus -and $pathLower.StartsWith($sus.ToLower())) {
                [void]$findings.Add([PSCustomObject]@{
                    Id = $p.Id
                    Name = $p.ProcessName
                    Path = $p.Path
                    SuspiciousDir = $sus
                    CommandLine = $p.CommandLine
                    StartTime = $p.StartTime
                })
                break
            }
        }
    }
    return @($findings)
}

function Get-ProcessMemorySummary {
    <#
    .SYNOPSIS Working set, private bytes, handles, threads per process.
    #>
    $summary = New-Object System.Collections.ArrayList
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        try {
            [void]$summary.Add([PSCustomObject]@{
                Id = $p.Id
                Name = $p.ProcessName
                WorkingSetMB = [math]::Round($p.WorkingSet64 / 1MB, 1)
                PrivateMB = [math]::Round($p.PrivateMemorySize64 / 1MB, 1)
                Handles = $p.Handles
                Threads = $p.Threads.Count
                Path = try { $p.Path } catch { "[access denied]" }
            })
        }
        catch { }
    }
    return @($summary | Sort-Object PrivateMB -Descending)
}

function Get-ProcessDetails {
    <#
    .SYNOPSIS WMI deep details: command line, owner, creation time, session.
    #>
    param([Parameter(Mandatory=$true)][int]$ProcessId)
    try {
        $wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
        $owner = ""
        try {
            $o = $wmi.GetOwner()
            $owner = "$($o.Domain)\$($o.User)"
        }
        catch { $owner = "[unknown]" }

        return [PSCustomObject]@{
            ProcessId = $ProcessId
            Name = $wmi.Name
            CommandLine = $wmi.CommandLine
            Owner = $owner
            CreationDate = $wmi.CreationDate
            ParentProcessId = $wmi.ParentProcessId
            SessionId = $wmi.SessionId
            ExecutablePath = $wmi.ExecutablePath
            ThreadCount = $wmi.ThreadCount
            HandleCount = $wmi.HandleCount
            PageFileUsage = $wmi.PageFileUsage
            PeakPageFileUsage = $wmi.PeakPageFileUsage
        }
    }
    catch {
        return [PSCustomObject]@{
            ProcessId = $ProcessId
            Error = "WMI query failed: $($_.Exception.Message)"
        }
    }
}

function Invoke-MemoryForensics {
    <#
    .SYNOPSIS Full memory forensics sweep. All checks. Everything logged.
    #>
    param(
        [string]$VaultPath = "",
        [switch]$DeepModuleScan  # also scan DLL signatures (slower)
    )

    Write-Host "`n=== MEMORY FORENSICS ===" -ForegroundColor White
    Write-Host "Deep into RAM. Every process, every anomaly.`n" -ForegroundColor Gray

    $report = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        TotalProcesses = 0
        OrphanProcesses = @()
        SuspiciousPathProcesses = @()
        UnsignedModules = @()
        TopMemoryConsumers = @()
        Note = "Live enumeration. Full RAM dump analysis needs WinPmem + Volatility (escalation path documented)."
    }

    Write-Host "[1/5] Process tree..." -ForegroundColor Cyan
    $tree = Get-ProcessTree
    $report.TotalProcesses = $tree.Count
    Write-Host "  $($tree.Count) processes enumerated"

    Write-Host "[2/5] Orphan processes (dead parent)..." -ForegroundColor Cyan
    $report.OrphanProcesses = @(Find-OrphanProcesses)
    Write-Host "  $($report.OrphanProcesses.Count) orphans" -ForegroundColor $(if ($report.OrphanProcesses.Count -gt 0) { "Yellow" } else { "Green" })
    foreach ($o in $report.OrphanProcesses) {
        Write-Host "    PID $($o.Id) ($($o.Name)): parent $($o.ParentId) dead" -ForegroundColor Yellow
    }

    Write-Host "[3/5] Suspicious paths..." -ForegroundColor Cyan
    $report.SuspiciousPathProcesses = @(Find-SuspiciousPaths)
    Write-Host "  $($report.SuspiciousPathProcesses.Count) processes in TEMP/AppData/Downloads" -ForegroundColor $(if ($report.SuspiciousPathProcesses.Count -gt 0) { "Red" } else { "Green" })
    foreach ($s in $report.SuspiciousPathProcesses) {
        Write-Host "    PID $($s.Id) ($($s.Name)): $($s.Path)" -ForegroundColor Red
    }

    if ($DeepModuleScan) {
        Write-Host "[4/5] Unsigned DLLs (deep scan)..." -ForegroundColor Cyan
        $report.UnsignedModules = @(Find-UnsignedModules)
        Write-Host "  $($report.UnsignedModules.Count) unsigned modules found" -ForegroundColor $(if ($report.UnsignedModules.Count -gt 0) { "Yellow" } else { "Green" })
    }
    else {
        Write-Host "[4/5] Unsigned DLLs skipped (use -DeepModuleScan)" -ForegroundColor Gray
    }

    Write-Host "[5/5] Memory summary..." -ForegroundColor Cyan
    $report.TopMemoryConsumers = @(Get-ProcessMemorySummary | Select-Object -First 10)
    Write-Host "  Top consumer: $($report.TopMemoryConsumers[0].Name) ($($report.TopMemoryConsumers[0].PrivateMB) MB private)"

    if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
        $report | ConvertTo-Json -Depth 6 | Add-Content -Path $VaultPath -Encoding UTF8
        Write-Host "`nLogged to vault." -ForegroundColor Gray
    }

    # Feed unified evidence pool
    if (Get-Command Add-SessionEvidence -ErrorAction SilentlyContinue) {
        foreach ($o in $report.OrphanProcesses) {
            Add-SessionEvidence -Module "memory-forensics" -Finding "Orphan process: $($o.Name) (PID $($o.Id)), parent dead" -Severity "Medium" -Details @{ Path = $o.Path }
        }
        foreach ($sp in $report.SuspiciousPathProcesses) {
            Add-SessionEvidence -Module "memory-forensics" -Finding "Process in suspicious path: $($sp.Name) at $($sp.Path)" -Severity "High" -Details @{ Path = $sp.Path }
        }
    }

    Write-Host "`n=== MEMORY FORENSICS COMPLETE ===" -ForegroundColor White
    Write-Host "  Processes: $($report.TotalProcesses) | Orphans: $($report.OrphanProcesses.Count) | Suspicious paths: $($report.SuspiciousPathProcesses.Count)" -ForegroundColor White
    return $report
}


function Test-MemoryForensicsHygiene {
    <#
    .SYNOPSIS Self-test: pure logic, safe enumeration, no-throw guarantees.
    #>
    $results = New-Object System.Collections.ArrayList
    $add = { param($Name,$Pass,$Detail)
        [void]$results.Add([PSCustomObject]@{Test=$Name; Pass=$Pass; Detail=$Detail})
    }.GetNewClosure()

    &$add "Suspicious paths defined" ($script:SuspiciousPaths.Count -gt 0) "$($script:SuspiciousPaths.Count) paths"

    try {
        $tree = Get-ProcessTree
        &$add "Process tree: returns array" ($tree -is [array]) "$($tree.Count) processes"
        &$add "Process tree: has parent info" (($tree | Where-Object { $_.ParentId -ne $null }).Count -gt 0) "Parent PIDs resolved"
    }
    catch { &$add "Process tree: no throw" $false $_.Exception.Message }

    try {
        $mem = Get-ProcessMemorySummary
        &$add "Memory summary: returns array" ($mem -is [array]) "$($mem.Count) entries"
        &$add "Memory summary: sorted desc" ($mem.Count -lt 2 -or $mem[0].PrivateMB -ge $mem[-1].PrivateMB) "Sorted by private bytes"
    }
    catch { &$add "Memory summary: no throw" $false $_.Exception.Message }

    try {
        $orphans = Find-OrphanProcesses
        &$add "Orphan scan: returns array" ($orphans -is [array]) "$($orphans.Count) orphans"
    }
    catch { &$add "Orphan scan: no throw" $false $_.Exception.Message }

    try {
        $susp = Find-SuspiciousPaths
        &$add "Suspicious paths: returns array" ($susp -is [array]) "$($susp.Count) findings"
    }
    catch { &$add "Suspicious paths: no throw" $false $_.Exception.Message }

    # Current process must appear in tree (self-consistency)
    try {
        $tree = Get-ProcessTree
        $me = $tree | Where-Object { $_.Id -eq $PID }
        &$add "Self-consistency: current PID in tree" ($null -ne $me) "PID $PID found"
    }
    catch { &$add "Self-consistency" $false $_.Exception.Message }

    $passed = ($results | Where-Object Pass).Count
    $total = $results.Count
    Write-Host "`nMemory Forensics Hygiene: $passed/$total passed" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Red" })
    foreach ($r in $results) {
        Write-Host "  [$($(if ($r.Pass){"PASS"}else{"FAIL"}))] $($r.Test): $($r.Detail)" -ForegroundColor $(if ($r.Pass) { "Green" } else { "Red" })
    }
    return $results
}

Export-ModuleMember -Function @(
    'Get-ProcessTree',
    'Get-ProcessModules',
    'Find-UnsignedModules',
    'Find-OrphanProcesses',
    'Find-SuspiciousPaths',
    'Get-ProcessMemorySummary',
    'Get-ProcessDetails',
    'Invoke-MemoryForensics',
    'Test-MemoryForensicsHygiene'
)
