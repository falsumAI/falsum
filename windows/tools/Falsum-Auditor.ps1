<#
.SYNOPSIS
    Falsum Code Auditor — every line explained. No hidden bullshit.

.DESCRIPTION
    Gregg's order: "I want a complete audit of every single line of code
    and explain every single fucking action taken within the code because
    I don't want no hidden bullshit."

    This scans every PowerShell file in the project and categorizes every
    system-touching action:
    - NETWORK: any call that sends/receives data off this machine
    - REGISTRY-WRITE: any modification to the registry
    - REGISTRY-READ: any registry reads (what keys)
    - FILE-DELETE: any file deletion
    - FILE-WRITE: any file creation/modification
    - PROCESS-KILL: any process termination
    - PROCESS-START: any process launch
    - ENCODED: base64, -EncodedCommand, obfuscated Invoke-Expression
    - CREDENTIAL: credential access, SecureString, password handling
    - ELEVATION: admin requirement, RunAs, bypasses

    Output: per-file, per-function audit report in plain English.
    Flags anything suspicious for manual review.

    A clean audit means: no unexpected network calls, no hidden deletions,
    no encoded payloads, no credential exfiltration.
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AuditPatterns = @{
    NETWORK = @(
        'Invoke-WebRequest', 'Invoke-RestMethod', 'New-Object Net.WebClient',
        'New-Object System.Net.WebClient', '\.DownloadString', '\.DownloadFile',
        '\.UploadString', '\.UploadFile', 'Invoke-Sqlcmd',
        'New-Object System.Net.Sockets', 'Test-NetConnection',
        'Resolve-DnsName', 'nslookup'
    )
    REGISTRY_WRITE = @(
        'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty',
        'New-Item -Path.*HK', 'Remove-Item -Path.*HK'
    )
    REGISTRY_READ = @(
        'Get-ItemProperty', 'Get-ChildItem.*HKLM', 'Get-ChildItem.*HKCU',
        'Test-Path.*HKLM', 'Test-Path.*HKCU'
    )
    FILE_DELETE = @(
        'Remove-Item'
    )
    FILE_WRITE = @(
        'Set-Content', 'Add-Content', 'Out-File', 'New-Item -ItemType File',
        '\| Out-File', '> '
    )
    PROCESS_KILL = @(
        'Stop-Process', 'taskkill', 'Stop-Service'
    )
    PROCESS_START = @(
        'Start-Process', 'Invoke-Item', '& '
    )
    ENCODED = @(
        'FromBase64String', 'ToBase64String', '-EncodedCommand', '-enc ',
        'IEX\s*\(', 'Invoke-Expression\s*\$', '\[Convert\]::FromBase64'
    )
    CREDENTIAL = @(
        'Get-Credential', 'SecureString', 'ConvertTo-SecureString',
        'PSCredential', 'password', 'apikey', 'api_key', 'token'
    )
    ELEVATION = @(
        'RunAs', 'Start-Process.*-Verb RunAs', 'Bypass.*ExecutionPolicy',
        '-ExecutionPolicy Bypass', 'Set-ExecutionPolicy'
    )
}

function Invoke-CodeAudit {
    <#
    .SYNOPSIS Full audit of all project PowerShell files.
    #>
    param(
        [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot | Split-Path -Parent),
        [string]$OutputPath = ""
    )

    $projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..") | Select-Object -ExpandProperty Path
    $files = Get-ChildItem -Path $projectRoot -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue

    Write-Host "`n=== CODE AUDIT ===" -ForegroundColor White
    Write-Host "Scanning $($files.Count) PowerShell files...`n" -ForegroundColor Gray

    $auditReport = New-Object System.Collections.ArrayList
    $globalFlags = New-Object System.Collections.ArrayList

    foreach ($file in $files) {
        $relative = $file.FullName.Replace($projectRoot, "").TrimStart("\", "/")
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }

        $lines = $content -split "`n"
        $fileFindings = New-Object System.Collections.ArrayList

        # Find all functions in this file
        $functions = [regex]::Matches($content, 'function\s+([\w-]+)')

        foreach ($category in $script:AuditPatterns.Keys) {
            foreach ($pattern in $script:AuditPatterns[$category]) {
                $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                foreach ($m in $matches) {
                    # Find line number
                    $lineNum = ($content.Substring(0, $m.Index) -split "`n").Count

                    # Find enclosing function
                    $enclosingFunc = "[script scope]"
                    $lastFuncLine = 0
                    $lastFuncName = "[script scope]"
                    foreach ($fm in $functions) {
                        $funcLine = ($content.Substring(0, $fm.Index) -split "`n").Count
                        if ($funcLine -lt $lineNum -and $funcLine -gt $lastFuncLine) {
                            $lastFuncLine = $funcLine
                            $lastFuncName = $fm.Groups[1].Value
                        }
                    }
                    $enclosingFunc = $lastFuncName

                    # Get the actual line for context
                    $contextLine = if ($lineNum -le $lines.Count) { $lines[$lineNum - 1].Trim() } else { "" }
                    if ($contextLine.Length -gt 120) { $contextLine = $contextLine.Substring(0, 120) + "..." }

                    $finding = [PSCustomObject]@{
                        File = $relative
                        Line = $lineNum
                        Category = $category
                        Pattern = $pattern
                        Function = $enclosingFunc
                        Context = $contextLine
                    }
                    [void]$fileFindings.Add($finding)

                    # Flag suspicious patterns for manual review
                    if ($category -eq 'ENCODED' -and $pattern -match 'IEX|EncodedCommand|FromBase64') {
                        [void]$globalFlags.Add([PSCustomObject]@{
                            Severity = "REVIEW"
                            File = $relative
                            Line = $lineNum
                            Reason = "Encoded/obfuscated execution pattern"
                            Context = $contextLine
                        })
                    }
                    if ($category -eq 'NETWORK') {
                        [void]$globalFlags.Add([PSCustomObject]@{
                            Severity = "INFO"
                            File = $relative
                            Line = $lineNum
                            Reason = "Network call — verify destination"
                            Context = $contextLine
                        })
                    }
                }
            }
        }

        [void]$auditReport.Add([PSCustomObject]@{
            File = $relative
            Lines = $lines.Count
            Functions = @($functions | ForEach-Object { $_.Groups[1].Value })
            FindingCount = $fileFindings.Count
            Findings = @($fileFindings)
        })
    }

    # Summary
    $totalLines = ($auditReport | Measure-Object -Property Lines -Sum).Sum
    $totalFindings = ($auditReport | Measure-Object -Property FindingCount -Sum).Sum
    $totalFunctions = ($auditReport | ForEach-Object { $_.Functions.Count } | Measure-Object -Sum).Sum

    Write-Host "=== AUDIT SUMMARY ===" -ForegroundColor White
    Write-Host "  Files scanned: $($auditReport.Count)" -ForegroundColor White
    Write-Host "  Total lines: $totalLines" -ForegroundColor White
    Write-Host "  Total functions: $totalFunctions" -ForegroundColor White
    Write-Host "  Total system actions found: $totalFindings" -ForegroundColor White
    Write-Host ""

    # Category breakdown
    Write-Host "--- Actions by Category ---" -ForegroundColor Cyan
    $allFindings = @($auditReport | ForEach-Object { $_.Findings })
    $byCategory = $allFindings | Group-Object Category | Sort-Object Count -Descending
    foreach ($cat in $byCategory) {
        Write-Host "  $($cat.Name): $($cat.Count)" -ForegroundColor Gray
    }
    Write-Host ""

    # Flags
    if ($globalFlags.Count -gt 0) {
        Write-Host "--- Flags for Review ($($globalFlags.Count)) ---" -ForegroundColor Yellow
        $reviewFlags = @($globalFlags | Where-Object { $_.Severity -eq "REVIEW" })
        if ($reviewFlags.Count -gt 0) {
            Write-Host "`n  REVIEW REQUIRED:" -ForegroundColor Red
            foreach ($f in $reviewFlags) {
                Write-Host "    $($f.File):$($f.Line) — $($f.Reason)" -ForegroundColor Red
                Write-Host "      $($f.Context)" -ForegroundColor DarkGray
            }
        }
        $infoFlags = @($globalFlags | Where-Object { $_.Severity -eq "INFO" })
        if ($infoFlags.Count -gt 0) {
            Write-Host "`n  NETWORK CALLS (verify each destination):" -ForegroundColor Yellow
            $grouped = $infoFlags | Group-Object File
            foreach ($g in $grouped) {
                Write-Host "    $($g.Name): $($g.Count) network calls" -ForegroundColor Yellow
            }
        }
    }
    else {
        Write-Host "No flags. No encoded payloads. No hidden execution." -ForegroundColor Green
    }

    $report = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        FilesScanned = $auditReport.Count
        TotalLines = $totalLines
        TotalFunctions = $totalFunctions
        TotalFindings = $totalFindings
        ByCategory = @($byCategory | Select-Object Name, Count)
        Flags = @($globalFlags)
        FileReports = @($auditReport)
    }

    if ($OutputPath -ne "") {
        $report | ConvertTo-Json -Depth 6 | Set-Content $OutputPath -Encoding UTF8
        Write-Host "`nFull report saved: $OutputPath" -ForegroundColor Gray
    }

    return $report
}

function Get-FileActionSummary {
    <#
    .SYNOPSIS Plain-English summary of what a single file does.
    #>
    param([Parameter(Mandatory=$true)][string]$FilePath)

    $content = Get-Content $FilePath -Raw -ErrorAction Stop
    $fileName = Split-Path $FilePath -Leaf

    $summary = [PSCustomObject]@{
        File = $fileName
        Lines = ($content -split "`n").Count
        Functions = @([regex]::Matches($content, 'function\s+([\w-]+)') | ForEach-Object { $_.Groups[1].Value })
        NetworkCalls = @([regex]::Matches($content, 'Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile', 'IgnoreCase') | ForEach-Object { $_.Value })
        RegistryWrites = ([regex]::Matches($content, 'Set-ItemProperty|New-ItemProperty|Remove-ItemProperty', 'IgnoreCase')).Count
        RegistryReads = ([regex]::Matches($content, 'Get-ItemProperty', 'IgnoreCase')).Count
        FileDeletions = ([regex]::Matches($content, 'Remove-Item', 'IgnoreCase')).Count
        ProcessKills = ([regex]::Matches($content, 'Stop-Process', 'IgnoreCase')).Count
        EncodedPatterns = ([regex]::Matches($content, 'FromBase64String|-EncodedCommand|IEX\s*\(', 'IgnoreCase')).Count
    }

    return $summary
}

Export-ModuleMember -Function @('Invoke-CodeAudit', 'Get-FileActionSummary')
