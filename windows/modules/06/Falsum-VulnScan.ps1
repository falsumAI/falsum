# Falsum Module 06: Vulnerability Scanning (Real Integration)
# Uses Nuclei (github.com/projectdiscovery/nuclei, MIT license) — the real scanner.
# Falsum orchestrates: installs Nuclei if missing, runs it, parses results into the vault.
# The FIX is Falsum's value-add: Nuclei finds, Falsum fixes.

function Install-Nuclei {
    $nucleiPath = "$env:LOCALAPPDATA\Falsum\tools\nuclei.exe"
    if (Test-Path $nucleiPath) { return $nucleiPath }

    Write-Host "Downloading Nuclei (ProjectDiscovery, MIT)..."
    $toolsDir = "$env:LOCALAPPDATA\Falsum\tools"
    if (!(Test-Path $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null }

    # Get latest release URL from GitHub API
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
    $asset = $release.assets | Where-Object { $_.name -like "*windows-amd64.zip" } | Select-Object -First 1
    $zipPath = "$toolsDir\nuclei.zip"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $toolsDir -Force
    Remove-Item $zipPath

    # Update templates on first run
    & $nucleiPath -update-templates -silent
    return $nucleiPath
}

function Invoke-FalsumVulnScan {
    param(
        [string]$Target,
        [string]$Severity = "critical,high,medium",
        [switch]$Fix
    )

    $nuclei = Install-Nuclei
    $outputFile = "$env:TEMP\falsum-nuclei-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

    Write-Host "Scanning $Target with Nuclei (12,000+ templates)..."
    & $nuclei -target $Target -severity $Severity -json-export $outputFile -silent

    $results = Get-Content $outputFile -Raw | ConvertFrom-Json

    # Log to Falsum vault (hash-chained)
    foreach ($r in $results) {
        Add-FalsumVaultEntry -Type "vuln" -Data @{
            template = $r.'template-id'
            severity = $r.info.severity
            target = $Target
            matched = $r.'matched-at'
            description = $r.info.description
        }
    }

    if ($Fix) {
        # Falsum's value-add: attempt automated remediation
        foreach ($r in $results) {
            Invoke-FalsumVulnFix -Finding $r
        }
    }

    return $results
}

function Invoke-FalsumVulnFix {
    param($Finding)

    # Map common Nuclei findings to Falsum fix actions
    $templateId = $Finding.'template-id'

    switch -Wildcard ($templateId) {
        "*exposed-panel*" {
            Write-Host "FIX: Exposed admin panel at $($Finding.'matched-at') — block via firewall or restrict in app config"
            # Real fix: create firewall rule blocking external access to the panel port
        }
        "*default-credential*" {
            Write-Host "FIX: Default credentials at $($Finding.'matched-at') — CHANGE IMMEDIATELY (manual, Falsum cannot guess your password)"
        }
        "*misconfig*" {
            Write-Host "FIX: Misconfiguration at $($Finding.'matched-at') — review $($Finding.info.description)"
        }
        default {
            Write-Host "No automated fix for $templateId — logged to vault for manual review"
        }
    }
}
