# Falsum: Take Back Control — Run this to unlock your computer
# Right-click → Run with PowerShell (or Run as Administrator for system-wide policies)

Write-Host "`n=== FALSUM: TAKE BACK CONTROL ===" -ForegroundColor Cyan
Write-Host "Removing policies that block downloads and grey out settings.`n"

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$isAdmin) {
    Write-Host "WARNING: Not running as Administrator." -ForegroundColor Yellow
    Write-Host "System-wide (HKLM) policies need admin. User-level (HKCU) will still work.`n"
}

# Backup
$backupDir = "$env:USERPROFILE\Desktop\Falsum-Policy-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
Write-Host "Backup going to: $backupDir`n" -ForegroundColor Gray

$removed = 0

# Policies that block downloads and lock settings
$targets = @(
    @{ Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows\System"; Desc="SmartScreen download blocks" },
    @{ Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen"; Desc="Defender SmartScreen blocks" },
    @{ Hive="HKCU"; Path="Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Desc="Attachment/download zone blocks" },
    @{ Hive="HKLM"; Path="SOFTWARE\Policies\Google\Chrome"; Desc="Chrome enterprise policies" },
    @{ Hive="HKCU"; Path="SOFTWARE\Policies\Google\Chrome"; Desc="Chrome user policies" },
    @{ Hive="HKLM"; Path="SOFTWARE\Policies\Microsoft\Edge"; Desc="Edge enterprise policies" },
    @{ Hive="HKCU"; Path="SOFTWARE\Policies\Microsoft\Edge"; Desc="Edge user policies" }
)

foreach ($t in $targets) {
    $regPath = "$($t.Hive):\$($t.Path)"

    if (Test-Path $regPath) {
        Write-Host "FOUND: $($t.Desc)" -ForegroundColor Yellow
        Write-Host "  at $regPath"

        # Backup
        $safeName = ($t.Hive + "_" + $t.Path -replace '[\\:]', '_') + ".reg"
        $backupFile = Join-Path $backupDir $safeName
        $exportPath = $t.Hive -replace "HKLM", "HKLM" -replace "HKCU", "HKCU"
        # Use reg.exe for reliable export
        $regExportPath = "$exportPath\$($t.Path)"
        reg export $regExportPath $backupFile /y 2>$null
        if ($?) { Write-Host "  Backed up." -ForegroundColor Gray }

        # Remove
        try {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
            Write-Host "  REMOVED." -ForegroundColor Green
            $removed++
        }
        catch {
            Write-Host "  FAILED: $_" -ForegroundColor Red
            Write-Host "  (Run as Administrator for HKLM keys)" -ForegroundColor Yellow
        }
        Write-Host ""
    }
}

Write-Host "`n=== DONE ===" -ForegroundColor Cyan
Write-Host "Removed $removed policy locations." -ForegroundColor Green
Write-Host "Backup saved to: $backupDir" -ForegroundColor Gray
Write-Host "`nRESTART YOUR COMPUTER, then try downloading Codex again." -ForegroundColor Yellow
Write-Host "`nPress any key to close..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
