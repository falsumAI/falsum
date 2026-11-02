# Falsum Native Host Installer
# Run this AFTER loading the extension in Chrome (chrome://extensions → Developer mode → Load unpacked)
# It asks for the extension ID and registers the native host with the real ID. No placeholders.

$extensionId = Read-Host "Paste the extension ID from chrome://extensions (32 characters)"

if ($extensionId -notmatch '^[a-z]{32}$') {
    Write-Host "Invalid extension ID. Must be 32 lowercase letters." -ForegroundColor Red
    exit 1
}

$hostDir = "$env:LOCALAPPDATA\Falsum\browser-extension"
if (!(Test-Path $hostDir)) { New-Item -ItemType Directory -Path $hostDir -Force | Out-Null }

# Copy the native host files
Copy-Item "$PSScriptRoot\Falsum-NativeHost.ps1" "$hostDir\" -Force
Copy-Item "$PSScriptRoot\Falsum-NativeHost.bat" "$hostDir\" -Force

# Generate the manifest with the REAL extension ID
$manifest = @{
    name = "com.falsum.native"
    description = "Falsum Native Host — links browser extension to desktop app"
    path = "$hostDir\Falsum-NativeHost.bat"
    type = "stdio"
    allowed_origins = @("chrome-extension://$extensionId/")
} | ConvertTo-Json

$manifestPath = "$hostDir\com.falsum.native.json"
$manifest | Out-File -FilePath $manifestPath -Encoding UTF8

# Register in Windows registry for Chrome
$regPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.falsum.native"
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "(Default)" -Value $manifestPath

Write-Host "Native host registered for extension $extensionId" -ForegroundColor Green
Write-Host "Manifest: $manifestPath"
