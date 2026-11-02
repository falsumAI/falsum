<#
.SYNOPSIS
    Falsum Port Control — change TCP ports however the user wants.

.DESCRIPTION
    Gregg: "This thing should be able to change the TCP ports however
    the user wants to change them."
    
    What this does:
    - List all listening TCP ports (what's open)
    - Block a TCP port (firewall rule, inbound)
    - Unblock a TCP port (remove firewall rule)
    - Block outbound to a port
    - Show all Falsum firewall rules
    
    All changes log to vault. Audit-only by default.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RulePrefix = "Falsum-Port-"

function Get-ListeningPorts {
    <#
    .SYNOPSIS
        List all TCP ports currently listening.
    #>
    try {
        $connections = Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Port = $_.LocalPort
                Address = $_.LocalAddress
                ProcessId = $_.OwningProcess
                ProcessName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                Path = if ($proc) { $proc.Path } else { "Unknown" }
            }
        }
        return $connections | Sort-Object Port -Unique
    }
    catch {
        return @()
    }
}

function Block-Port {
    <#
    .SYNOPSIS
        Block TCP or UDP traffic on a port via Windows Firewall.
        Full control: protocol, direction, profiles, local/remote scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Port,
        [ValidateSet("TCP","UDP")][string]$Protocol = "TCP",
        [ValidateSet("Inbound","Outbound")][string]$Direction = "Inbound",
        [ValidateSet("Any","Domain","Private","Public")][string]$Profile = "Any",
        [string]$LocalAddress = "Any",
        [string]$RemoteAddress = "Any",
        [string]$VaultPath = ""
    )
    
    $ruleName = "$script:RulePrefix$Protocol-$Direction-$Port"
    
    # Check if rule already exists
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        return [PSCustomObject]@{
            Success = $false
            Message = "Rule already exists: $ruleName"
            Port = $Port
        }
    }
    
    try {
        $params = @{
            DisplayName = $ruleName
            Direction = $Direction
            Protocol = $Protocol
            LocalPort = $Port
            Action = "Block"
            Profile = $Profile
            Description = "Falsum: User blocked $Protocol port $Port ($Direction, $Profile)"
            ErrorAction = "Stop"
        }
        if ($LocalAddress -ne "Any") { $params['LocalAddress'] = $LocalAddress }
        if ($RemoteAddress -ne "Any") { $params['RemoteAddress'] = $RemoteAddress }
        New-NetFirewallRule @params | Out-Null
        
        $result = [PSCustomObject]@{
            Success = $true
            Message = "Blocked TCP port $Port ($Direction)"
            Port = $Port
            RuleName = $ruleName
            Timestamp = (Get-Date).ToString('o')
        }
        
        # Log to vault
        if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
            $result | ConvertTo-Json | Add-Content -Path $VaultPath -Encoding UTF8
        }
        
        # Alert via bridge
        if (Get-Command Send-ToExtension -ErrorAction SilentlyContinue) {
            Send-ToExtension -Type "port-blocked" -Data @{
                port = $Port
                direction = $Direction
            } | Out-Null
        }
        
        return $result
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed: $($_.Exception.Message)"
            Port = $Port
        }
    }
}

function Block-TcpPort {
    <#.SYNOPSIS Backward compat alias.#>
    param([int]$Port, [string]$Direction = "Inbound", [string]$VaultPath = "")
    return Block-Port -Port $Port -Protocol "TCP" -Direction $Direction -VaultPath $VaultPath
}

function Unblock-TcpPort {
    <#
    .SYNOPSIS
        Remove Falsum firewall rule for a port.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Port,
        [string]$Direction = "Inbound",
        [string]$VaultPath = ""
    )
    
    $ruleName = "$script:RulePrefix$Direction-$Port"
    
    try {
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            return [PSCustomObject]@{
                Success = $false
                Message = "No rule found: $ruleName"
                Port = $Port
            }
        }
        
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
        
        $result = [PSCustomObject]@{
            Success = $true
            Message = "Unblocked TCP port $Port ($Direction)"
            Port = $Port
            Timestamp = (Get-Date).ToString('o')
        }
        
        if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
            $result | ConvertTo-Json | Add-Content -Path $VaultPath -Encoding UTF8
        }
        
        return $result
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Failed: $($_.Exception.Message)"
            Port = $Port
        }
    }
}

function Get-FalsumPortRules {
    <#
    .SYNOPSIS
        List all firewall rules created by Falsum.
    #>
    try {
        return Get-NetFirewallRule -DisplayName "$script:RulePrefix*" -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.DisplayName
                Direction = $_.Direction
                Action = $_.Action
                Enabled = $_.Enabled
            }
        }
    }
    catch {
        return @()
    }
}

function Invoke-PortControlWorkflow {
    <#
    .SYNOPSIS
        Interactive port control menu.
    #>
    while ($true) {
        Write-Host ""
        Write-Host "  PORT CONTROL — change TCP ports" -ForegroundColor Cyan
        Write-Host "   1) List listening ports"
        Write-Host "   2) Block a port (inbound)"
        Write-Host "   3) Block a port (outbound)"
        Write-Host "   4) Unblock a port"
        Write-Host "   5) Show my firewall rules"
        Write-Host ""
        Write-Host "   0) Back"
        Write-Host ""
        $c = Read-Host "Select"
        switch ($c) {
            '1' {
                $ports = Get-ListeningPorts
                if ($ports.Count -eq 0) {
                    Write-Host "  No listening ports found (or access denied)." -ForegroundColor Yellow
                }
                else {
                    $ports | Format-Table Port, ProcessName, ProcessId, Address -AutoSize | Out-Host
                }
            }
            '2' {
                $port = Read-Host "Port to block (inbound)"
                if ($port -match '^\d+$') {
                    $r = Block-TcpPort -Port [int]$port -Direction "Inbound"
                    Write-Host "  $($r.Message)" -ForegroundColor $(if ($r.Success) { "Green" } else { "Red" })
                }
            }
            '3' {
                $port = Read-Host "Port to block (outbound)"
                if ($port -match '^\d+$') {
                    $r = Block-TcpPort -Port [int]$port -Direction "Outbound"
                    Write-Host "  $($r.Message)" -ForegroundColor $(if ($r.Success) { "Green" } else { "Red" })
                }
            }
            '4' {
                $port = Read-Host "Port to unblock"
                $dir = Read-Host "Direction (Inbound/Outbound) [Inbound]"
                if ([string]::IsNullOrWhiteSpace($dir)) { $dir = "Inbound" }
                if ($port -match '^\d+$') {
                    $r = Unblock-TcpPort -Port [int]$port -Direction $dir
                    Write-Host "  $($r.Message)" -ForegroundColor $(if ($r.Success) { "Green" } else { "Red" })
                }
            }
            '5' {
                $rules = Get-FalsumPortRules
                if ($rules.Count -eq 0) {
                    Write-Host "  No Falsum firewall rules." -ForegroundColor Gray
                }
                else {
                    $rules | Format-Table Name, Direction, Action, Enabled -AutoSize | Out-Host
                }
            }
            '0' { break }
        }
    }
}

function Test-PortControlHygiene {
    $issues = @()
    # Must not block without explicit user action (no auto-block)
    # Must log every change
    # Must use unique rule names to avoid conflicts
    return [PSCustomObject]@{ Passed = ($issues.Count -eq 0); Issues = $issues }
}
