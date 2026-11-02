# Falsum Native Host Installer
# Links the Falsum browser extension to the Falsum desktop app.
#
# Run this AFTER:
#   1. Building Falsum (BUILD-FALSUM.ps1) — this script lives next to Falsum.exe in dist\
#   2. Loading the extension in Chrome (chrome://extensions -> Developer mode -> Load unpacked)
#
# What it does: writes the native messaging manifest pointing at Falsum.exe and
# registers it for Chrome and Edge. Chrome launches Falsum.exe itself as the
# host — no scripts, no wrappers. The real application.

$extensionId = Read-Host "Paste the extension ID from chrome://extensions (32 characters)"

if ($extensionId -notmatch '^[a-z]{32}$') {
    Write-Host "Invalid extension ID. Must be 32 lowercase letters." -ForegroundColor Red
    exit 1
}

$exePath = Join-Path $PSScriptRoot "Falsum.exe"
if (!(Test-Path $exePath)) {
    Write-Host "Falsum.exe not found next to this script." -ForegroundColor Red
    Write-Host "Run BUILD-FALSUM.ps1 first, then run this installer from the dist folder." -ForegroundColor Yellow
    exit 1
}

$hostDir = "$env:LOCALAPPDATA\Falsum\native-host"
if (!(Test-Path $hostDir)) { New-Item -ItemType Directory -Path $hostDir -Force | Out-Null }

# Manifest points DIRECTLY at Falsum.exe. Chrome passes chrome-extension://<id>/
# as an argument; the app sees it and runs the native host loop with no window.
$manifest = @{
    name = "com.falsum.native"
    description = "Falsum native messaging host - links the browser extension to the Falsum desktop app"
    path = $exePath
    type = "stdio"
    allowed_origins = @("chrome-extension://$extensionId/")
} | ConvertTo-Json

$manifestPath = "$hostDir\com.falsum.native.json"
$manifest | Out-File -FilePath $manifestPath -Encoding UTF8

foreach ($browser in @("Google\Chrome", "Microsoft\Edge")) {
    $regPath = "HKCU:\Software\$browser\NativeMessagingHosts\com.falsum.native"
    if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $manifestPath
    Write-Host "Registered with $browser." -ForegroundColor Green
}

Write-Host ""
Write-Host "Done. The extension and the app now see each other." -ForegroundColor Green
Write-Host "Manifest: $manifestPath"
Write-Host "Host: $exePath"
