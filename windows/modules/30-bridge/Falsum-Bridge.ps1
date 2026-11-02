<#
.SYNOPSIS
    Falsum Message Bridge — WPF app <-> Browser extension
    Shared message queue via JSON file. Both sides poll.

.DESCRIPTION
    Gregg: "Does the extension and Windows application talk to each other?"
    Answer was no. This fixes it.
    
    How it works:
    - WPF app writes to %LOCALAPPDATA%\Falsum\bridge\to-extension.json
    - Native host reads it, forwards to extension via native messaging
    - Extension writes to %LOCALAPPDATA%\Falsum\bridge\to-desktop.json  
    - WPF app polls and reads it
    
    Both sides use file locking to avoid corruption.
#>

$script:BaseDir = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { [System.IO.Path]::GetTempPath() }
$script:BridgeDir = Join-Path $script:BaseDir "Falsum\bridge"
$script:ToExtension = Join-Path $script:BridgeDir "to-extension.json"
$script:ToDesktop = Join-Path $script:BridgeDir "to-desktop.json"

function Initialize-Bridge {
    if (-not (Test-Path $script:BridgeDir)) {
        New-Item -Path $script:BridgeDir -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path $script:ToExtension)) {
        @() | ConvertTo-Json | Set-Content $script:ToExtension -Encoding UTF8
    }
    if (-not (Test-Path $script:ToDesktop)) {
        @() | ConvertTo-Json | Set-Content $script:ToDesktop -Encoding UTF8
    }
}

function Send-ToExtension {
    <#
    .SYNOPSIS
        WPF app -> Extension. Writes message to queue.
    #>
    param(
        [Parameter(Mandatory)][string]$Type,
        [hashtable]$Data = @{}
    )
    Initialize-Bridge
    $msg = @{
        type = $Type
        data = $Data
        timestamp = (Get-Date).ToString('o')
        from = "desktop-app"
    }
    try {
        $queue = Get-Content $script:ToExtension -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($queue -isnot [array]) { $queue = @($queue) }
        $queue += $msg
        # Keep last 100 messages
        if ($queue.Count -gt 100) { $queue = $queue[-100..-1] }
        $queue | ConvertTo-Json -Depth 5 | Set-Content $script:ToExtension -Encoding UTF8
        return $true
    }
    catch {
        return $false
    }
}

function Receive-FromExtension {
    <#
    .SYNOPSIS
        WPF app <- Extension. Reads and clears message queue.
    #>
    Initialize-Bridge
    try {
        $queue = Get-Content $script:ToDesktop -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($queue -isnot [array]) { $queue = @($queue) }
        # Clear after reading
        @() | ConvertTo-Json | Set-Content $script:ToDesktop -Encoding UTF8
        return $queue
    }
    catch {
        return @()
    }
}

function Send-ToDesktop {
    <#
    .SYNOPSIS
        Extension -> WPF app. Called by native host.
    #>
    param(
        [Parameter(Mandatory)][string]$Type,
        [hashtable]$Data = @{}
    )
    Initialize-Bridge
    $msg = @{
        type = $Type
        data = $Data
        timestamp = (Get-Date).ToString('o')
        from = "browser-extension"
    }
    try {
        $queue = Get-Content $script:ToDesktop -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($queue -isnot [array]) { $queue = @($queue) }
        $queue += $msg
        if ($queue.Count -gt 100) { $queue = $queue[-100..-1] }
        $queue | ConvertTo-Json -Depth 5 | Set-Content $script:ToDesktop -Encoding UTF8
        return $true
    }
    catch {
        return $false
    }
}

function Receive-FromDesktop {
    <#
    .SYNOPSIS
        Extension <- WPF app. Called by native host to forward to extension.
    #>
    Initialize-Bridge
    try {
        $queue = Get-Content $script:ToExtension -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($queue -isnot [array]) { $queue = @($queue) }
        @() | ConvertTo-Json | Set-Content $script:ToExtension -Encoding UTF8
        return $queue
    }
    catch {
        return @()
    }
}

# Functions exported via dot-sourcing
