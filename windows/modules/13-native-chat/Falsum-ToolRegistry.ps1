<#
.SYNOPSIS
    Falsum Tool Registry — every module function registered as an intelligence tool.

.DESCRIPTION
    Wires all 29 modules into the intelligence core (module 13).
    The AI can now invoke any module function as a tool.
    This is what makes it ONE application, not 29 scripts.

    Run once at startup: Import-ToolRegistry
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Import-ToolRegistry {
    <#
    .SYNOPSIS Register all module functions as intelligence tools.
    #>

    # Purge tools (module 25)
    Register-IntelligenceTool -Name "purge-scan" -Category "Purge" `
        -Description "Scan for unattributed binaries (no publisher, no signature, no version). Returns list with paths and hashes." `
        -Action { Invoke-PurgeScan -AuditOnly }

    Register-IntelligenceTool -Name "purge-check-binary" -Category "Purge" `
        -Description "Check a single binary's attribution (publisher, signature, version)." `
        -Action { param($Path) Get-BinaryAttribution -Path $Path }

    # Defender Watch tools (module 26)
    Register-IntelligenceTool -Name "defender-status" -Category "Defender" `
        -Description "Current Windows Defender status: engine version, definitions age, real-time protection, tamper protection." `
        -Action { Get-DefenderStatus }

    Register-IntelligenceTool -Name "defender-watch" -Category "Defender" `
        -Description "Full Defender sweep: scans, detections, quarantine, exclusions, protection toggles. Logs everything Defender does." `
        -Action { Invoke-DefenderWatch }

    Register-IntelligenceTool -Name "defender-exclusions" -Category "Defender" `
        -Description "Current Defender exclusions (blind spots). Shows what's excluded from scanning." `
        -Action { Get-DefenderExclusions }

    # Memory Forensics tools (module 27)
    Register-IntelligenceTool -Name "memory-sweep" -Category "Memory" `
        -Description "Deep RAM enumeration: process tree, orphans, suspicious paths, memory usage." `
        -Action { Invoke-MemoryForensics }

    Register-IntelligenceTool -Name "memory-deep-scan" -Category "Memory" `
        -Description "Deep RAM scan including unsigned DLL check (injection hunt). Slower." `
        -Action { Invoke-MemoryForensics -DeepModuleScan }

    Register-IntelligenceTool -Name "process-tree" -Category "Memory" `
        -Description "Full process tree with parent/child relationships." `
        -Action { Get-ProcessTree }

    # Task Killer tools (module 28)
    Register-IntelligenceTool -Name "task-audit" -Category "Tasks" `
        -Description "Show all running processes with RAM/CPU. User picks what dies." `
        -Action { Invoke-TaskKillerAudit }

    Register-IntelligenceTool -Name "task-kill-list" -Category "Tasks" `
        -Description "Show the kill list (bloatware, updaters, telemetry)." `
        -Action { Get-TaskKillList }

    # Evidence tools (module 01)
    Register-IntelligenceTool -Name "evidence-sweep" -Category "Evidence" `
        -Description "44-step system evidence collection." `
        -Action { Invoke-EvidenceSweep }

    # Network tools (modules 02, 03)
    Register-IntelligenceTool -Name "packet-capture" -Category "Network" `
        -Description "Capture network traffic (DNS, TLS SNI, flows)." `
        -Action { param($Duration = 60) Start-Capture -Duration $Duration }

    Register-IntelligenceTool -Name "network-scan" -Category "Network" `
        -Description "Scan local network: who's there, what's open." `
        -Action { Start-NetScan }

    # OSINT tools (modules 04, 05)
    Register-IntelligenceTool -Name "ip-lookup" -Category "OSINT" `
        -Description "Attribute an IP or domain (RDAP, ASN, threat intel)." `
        -Action { param($Target) Get-AttributionReport -Target $Target }

    Register-IntelligenceTool -Name "username-search" -Category "OSINT" `
        -Description "Check a username across 820 sites." `
        -Action { param($Username) Invoke-PeopleTrack -Username $Username }

    # Vuln tools (module 06)
    Register-IntelligenceTool -Name "vuln-audit" -Category "Vuln" `
        -Description "Check this PC for vulnerabilities and misconfigurations." `
        -Action { New-VulnReport }

    # Broker tools (module 09)
    Register-IntelligenceTool -Name "broker-eradication" -Category "Privacy" `
        -Description "Full data broker eradication cycle (958 brokers)." `
        -Action { Invoke-BrokerEradication -AuditOnly }

    # Mail tools (module 16)
    Register-IntelligenceTool -Name "phishing-check" -Category "Email" `
        -Description "Analyze an email for phishing signals (Kanca scoring)." `
        -Action { param($Path) $email = Import-EmlFile -Path $Path; Get-KancaScoredVerdict -Email $email }

    # Tracker tools (module 22)
    Register-IntelligenceTool -Name "tracker-block" -Category "Privacy" `
        -Description "Block trackers using DDG/Disconnect/EasyPrivacy feeds." `
        -Action { Invoke-TrackerBlock }

    # Mobile tools (module 24)
    Register-IntelligenceTool -Name "stalkerware-scan" -Category "Mobile" `
        -Description "Scan this PC for monitoring software (stalkerware, parental, bossware)." `
        -Action { Find-WindowsMonitoringSoftware }

    $count = (Get-IntelligenceTools).Count
    Write-Host "Tool registry loaded: $count tools across 29 modules." -ForegroundColor Green
    return $count
}

Export-ModuleMember -Function @('Import-ToolRegistry')
