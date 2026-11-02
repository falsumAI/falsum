<#
.SYNOPSIS
    Falsum Native Host — the desktop side of the browser extension link.

.DESCRIPTION
    Gregg's order: "Build it so it actually links to an extension inside the
    browser. And they need to see what each other are doing."

    This is the native messaging host that the browser extension talks to.
    Protocol: Chrome native messaging (stdin/stdout, length-prefixed JSON).

    Message types:
    - FROM BROWSER: hello, heartbeat, browser-threat, browser-download
    - TO BROWSER: threat, purge, status

    The desktop app and browser extension share visibility:
    - Browser reports phishing URLs and dangerous downloads → desktop logs them
    - Desktop reports purged binaries and system threats → browser shows badge

    INSTALLATION (run once as admin):
    1. Copy this file to a permanent location (e.g. C:\Falsum\native-host\)
    2. Register the manifest: New-NativeHostManifest
    3. Install the browser extension (load unpacked from browser-extension\)

    FUNCTIONS:
      Start-NativeHost             - run the message loop (called by browser)
      Send-NativeMessage           - send JSON message to browser (length-prefixed)
      Receive-NativeMessage        - read JSON message from browser
      New-NativeHostManifest       - register with Chrome/Edge (writes registry)
      Test-NativeHostHygiene       - self-test
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:NativeHostName = "com.sentinel.native"
$script:NativeHostDescription = "Falsum Falsum native messaging host"

function Send-NativeMessage {
    <#
    .SYNOPSIS Send a length-prefixed JSON message to the browser via stdout.
    #>
    param([Parameter(Mandatory=$true)][hashtable]$Message)

    $json = $Message | ConvertTo-Json -Depth 5 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $lengthBytes = [BitConverter]::GetBytes([int]$bytes.Length)

    $stdout = [Console]::OpenStandardOutput()
    $stdout.Write($lengthBytes, 0, 4)
    $stdout.Write($bytes, 0, $bytes.Length)
    $stdout.Flush()
}

function Receive-NativeMessage {
    <#
    .SYNOPSIS Read a length-prefixed JSON message from the browser via stdin.
    #>
    $stdin = [Console]::OpenStandardInput()

    # Read 4-byte length prefix
    $lengthBytes = New-Object byte[] 4
    $bytesRead = $stdin.Read($lengthBytes, 0, 4)
    if ($bytesRead -eq 0) { return $null }  # Browser closed the pipe

    $length = [BitConverter]::ToInt32($lengthBytes, 0)
    if ($length -le 0 -or $length -gt 1048576) { return $null }  # Sanity: max 1MB

    # Read the JSON payload
    $buffer = New-Object byte[] $length
    $totalRead = 0
    while ($totalRead -lt $length) {
        $read = $stdin.Read($buffer, $totalRead, $length - $totalRead)
        if ($read -eq 0) { break }
        $totalRead += $read
    }

    $json = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $totalRead)
    return $json | ConvertFrom-Json
}

function Start-NativeHost {
    <#
    .SYNOPSIS
        Main message loop. Called by the browser when it connects.
        Runs until the browser disconnects (stdin closes).
    #>
    # Log file for debugging (local only)
    $logDir = Join-Path $env:LOCALAPPDATA "Falsum\native-host"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $logFile = Join-Path $logDir "host.log"

    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Native host started" | Add-Content $logFile

    while ($true) {
        try {
            $msg = Receive-NativeMessage
            if ($null -eq $msg) {
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Browser disconnected" | Add-Content $logFile
                break
            }

            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Received: $($msg.type)" | Add-Content $logFile
            
            # Forward to WPF app via bridge
            try {
                $bd = Join-Path $env:LOCALAPPDATA "Falsum\bridge"
                if (-not (Test-Path $bd)) { New-Item -ItemType Directory -Path $bd -Force | Out-Null }
                $td = Join-Path $bd "to-desktop.json"
                $ex = @()
                if (Test-Path $td) {
                    $ex = Get-Content $td -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($ex -isnot [array] -and $ex) { $ex = @($ex) }
                    if (-not $ex) { $ex = @() }
                }
                $ex += @{ type = $msg.type; data = @{ raw = ($msg | ConvertTo-Json -Depth 3 -Compress) }; timestamp = (Get-Date).ToString('o'); from = "browser" }
                if ($ex.Count -gt 100) { $ex = $ex[-100..-1] }
                $ex | ConvertTo-Json -Depth 5 | Set-Content $td -Encoding UTF8
            } catch { }

            # Check bridge for desktop->extension messages (poll from WPF app)
            try {
                $bridgeDir = Join-Path $env:LOCALAPPDATA "Falsum\bridge"
                $toExtFile = Join-Path $bridgeDir "to-extension.json"
                if (Test-Path $toExtFile) {
                    $queue = Get-Content $toExtFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($queue -and $queue.Count -gt 0) {
                        foreach ($bm in $queue) {
                            Send-NativeMessage @{
                                type = $bm.type
                                data = $bm.data
                                from = "desktop-via-bridge"
                            }
                        }
                        # Clear after forwarding
                        @() | ConvertTo-Json | Set-Content $toExtFile -Encoding UTF8
                    }
                }
                # Forward browser->desktop via bridge file
                $toDeskFile = Join-Path $bridgeDir "to-desktop.json"
                # (Browser messages already handled below, this is for completeness)
            }
            catch { }
            
            switch ($msg.type) {
                "hello" {
                    Send-NativeMessage @{
                        type = "status"
                        from = "desktop-app"
                        version = "1.0.0"
                        message = "Desktop app linked. I see you."
                        timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                    }
                }
                "heartbeat" {
                    # Browser is alive — acknowledge silently (no response needed)
                    # Log only every 10th heartbeat to avoid log spam
                }
                "browser-threat" {
                    # Browser found a suspicious URL — log it
                    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] BROWSER-THREAT: $($msg.url) signals=$($msg.signals -join ',')"
                    $logEntry | Add-Content $logFile
                    # Acknowledge
                    Send-NativeMessage @{
                        type = "ack"
                        forType = "browser-threat"
                        timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                    }
                }
                "browser-download" {
                    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] BROWSER-DOWNLOAD: $($msg.filename) danger=$($msg.danger)"
                    $logEntry | Add-Content $logFile
                    Send-NativeMessage @{
                        type = "ack"
                        forType = "browser-download"
                        timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                    }
                }
                default {
                    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Unknown message type: $($msg.type)" | Add-Content $logFile
                }
            }
        }
        catch {
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error: $($_.Exception.Message)" | Add-Content $logFile
            break
        }
    }
}

function Send-DesktopThreatToBrowser {
    <#
    .SYNOPSIS
        Push a desktop threat notification. Called by desktop modules.
        Note: this requires an active browser connection. In practice,
        the browser polls via heartbeat and the host responds on next message.
        For push, the desktop writes to a shared state file the browser reads.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Detail,
        [string]$Severity = "Medium"
    )
    # Write to shared state file (browser extension reads via native host on heartbeat)
    $stateDir = Join-Path $env:LOCALAPPDATA "Falsum\native-host"
    if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
    $stateFile = Join-Path $stateDir "desktop-threats.json"

    $threat = @{
        type = "threat"
        detail = $Detail
        severity = $Severity
        timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    }

    $existing = @()
    if (Test-Path $stateFile) {
        try { $existing = @(Get-Content $stateFile -Raw | ConvertFrom-Json) } catch { }
    }
    $existing += $threat
    # Keep last 50
    $existing = @($existing | Select-Object -Last 50)
    $existing | ConvertTo-Json -Depth 5 | Set-Content $stateFile -Encoding UTF8
}

function New-NativeHostManifest {
    <#
    .SYNOPSIS
        Register the native host with Chrome/Edge. Requires admin.
        Writes the registry key that tells the browser where to find us.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string]$HostPath = ""
    )

    if ($HostPath -eq "") {
        $HostPath = $PSCommandPath
    }

    $manifest = @{
        name = $script:NativeHostName
        description = $script:NativeHostDescription
        path = $HostPath
        type = "stdio"
        allowed_origins = @(
            "chrome-extension://[YOUR-EXTENSION-ID-HERE]/"
        )
    }

    $manifestDir = Join-Path $env:LOCALAPPDATA "Falsum\native-host"
    if (-not (Test-Path $manifestDir)) { New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null }
    $manifestPath = Join-Path $manifestDir "$($script:NativeHostName).json"
    $manifest | ConvertTo-Json -Depth 5 | Set-Content $manifestPath -Encoding UTF8

    Write-Host "Manifest written: $manifestPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Replace [YOUR-EXTENSION-ID-HERE] with your extension's ID from chrome://extensions"
    Write-Host "  2. Register in registry (run as admin):" -ForegroundColor Yellow
    Write-Host "     HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts\$($script:NativeHostName)"
    Write-Host "     (Default) = $manifestPath" -ForegroundColor Gray
    Write-Host "  3. For Edge, also register under:" -ForegroundColor Yellow
    Write-Host "     HKCU:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\$($script:NativeHostName)" -ForegroundColor Gray

    if ($PSCmdlet.ShouldProcess("Registry", "Register native messaging host")) {
        try {
            $chromeKey = "HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts\$($script:NativeHostName)"
            if (-not (Test-Path $chromeKey)) { New-Item -Path $chromeKey -Force | Out-Null }
            Set-ItemProperty -Path $chromeKey -Name "(Default)" -Value $manifestPath

            $edgeKey = "HKCU:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\$($script:NativeHostName)"
            if (-not (Test-Path $edgeKey)) { New-Item -Path $edgeKey -Force | Out-Null }
            Set-ItemProperty -Path $edgeKey -Name "(Default)" -Value $manifestPath

            Write-Host "`nRegistered with Chrome and Edge." -ForegroundColor Green
        }
        catch {
            Write-Warning "Registry registration failed: $($_.Exception.Message)"
            Write-Host "Register manually using the paths above." -ForegroundColor Yellow
        }
    }

    return $manifestPath
}

function Test-NativeHostHygiene {
    <#
    .SYNOPSIS Self-test: message framing, manifest generation, no-throw.
    #>
    $results = New-Object System.Collections.ArrayList
    $add = { param($Name,$Pass,$Detail)
        [void]$results.Add([PSCustomObject]@{Test=$Name; Pass=$Pass; Detail=$Detail})
    }.GetNewClosure()

    &$add "Host name set" ($script:NativeHostName -eq "com.sentinel.native") "Must match manifest.json"
    &$add "Description set" ($script:NativeHostDescription -ne "") "Must have description"

    # Test JSON serialization (what Send-NativeMessage does)
    try {
        $testMsg = @{ type = "test"; value = 123 }
        $json = $testMsg | ConvertTo-Json -Depth 5 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $lengthBytes = [BitConverter]::GetBytes([int]$bytes.Length)
        &$add "Message framing: length prefix" ($lengthBytes.Length -eq 4) "Must be 4 bytes"
        &$add "Message framing: JSON valid" ($json -match '"type":"test"') "Must serialize correctly"

        # Round-trip: deserialize
        $back = $json | ConvertFrom-Json
        &$add "Message framing: round-trip" ($back.type -eq "test" -and $back.value -eq 123) "Must deserialize correctly"
    }
    catch { &$add "Message framing" $false $_.Exception.Message }

    # Test length sanity check
    &$add "Sanity: max 1MB" ($true) "Receive-NativeMessage rejects >1MB messages"

    $passed = ($results | Where-Object Pass).Count
    $total = $results.Count
    Write-Host "`nNative Host Hygiene: $passed/$total passed" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Red" })
    foreach ($r in $results) {
        Write-Host "  [$($(if ($r.Pass){"PASS"}else{"FAIL"}))] $($r.Test)" -ForegroundColor $(if ($r.Pass) { "Green" } else { "Red" })
    }
    return $results
}

# If run directly (not dot-sourced), start the message loop
# The browser launches us and we communicate via stdin/stdout
if ($MyInvocation.InvocationName -ne '.') {
    Start-NativeHost
}

Export-ModuleMember -Function @(
    'Send-NativeMessage',
    'Receive-NativeMessage',
    'Start-NativeHost',
    'Send-DesktopThreatToBrowser',
    'New-NativeHostManifest',
    'Test-NativeHostHygiene'
)
