# Falsum Module 04: OSINT Username Search (Real Integration)
# Uses Maigret (github.com/soxoj/maigret, MIT license) — 3,000+ sites, real OSINT.
# Falsum orchestrates: installs Maigret if missing, runs it, parses results into the vault.

function Install-Maigret {
    # Check if maigret is installed via pip
    $maigret = Get-Command maigret -ErrorAction SilentlyContinue
    if ($maigret) { return $maigret.Source }

    Write-Host "Installing Maigret (soxoj, MIT) via pip..."
    pip install maigret

    $maigret = Get-Command maigret -ErrorAction SilentlyContinue
    if (!$maigret) { throw "Maigret installation failed. Ensure Python 3.8+ and pip are installed." }
    return $maigret.Source
}

function Invoke-FalsumOsintSearch {
    param(
        [string]$Username,
        [switch]$Full,  # -a flag: all 3000 sites (slow, 15-30 min). Default: top 500.
        [int]$Timeout = 10
    )

    $maigret = Install-Maigret
    $outputFile = "$env:TEMP\falsum-maigret-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

    Write-Host "Searching username '$Username' across sites with Maigret..."
    $args = @($Username, "--json", "simple", "--timeout", $Timeout, "--no-progressbar")
    if ($Full) { $args += "-a" }

    & $maigret @args > $outputFile

    $results = Get-Content $outputFile -Raw | ConvertFrom-Json

    # Log to Falsum vault
    foreach ($site in $results.PSObject.Properties) {
        if ($site.Value.status -eq "found") {
            Add-FalsumVaultEntry -Type "osint" -Data @{
                username = $Username
                site = $site.Name
                url = $site.Value.url
            }
        }
    }

    $found = ($results.PSObject.Properties | Where-Object { $_.Value.status -eq "found" }).Count
    Write-Host "Found $Username on $found sites."

    return $results
}
