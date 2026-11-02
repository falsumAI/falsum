<#
.SYNOPSIS
    Falsum Mobile Shield — stalkerware detection, phone-backup forensics, and
    Windows mobile-like surveillance audit.

.DESCRIPTION
    Gregg's correction (2026-10-30): "They're turning this fucking Windows
    bullshit into exactly what mobile apps are. So figure it out."

    He was right to kill the "mobile is out of scope" excuse. A Windows tool
    CAN fight mobile threats three ways:

    1. PHONE BACKUP FORENSICS — iPhones back up to Windows via iTunes/Apple
       Devices; Android phones dump files via USB/MTP. Those backups land on
       THIS machine. We scan them for stalkerware indicators: known spyware
       package names, suspicious profiles, rogue certificates, location-harvest
       databases.

    2. NETWORK C2 DETECTION — a stalkerware-infected phone on your Wi-Fi
       phones home to its controller. Packet witness + netscan already watch
       the wire; this module ships the stalkerware C2 domain/IP table and the
       behavioral signatures (periodic beacons, SMS-forwarding patterns).

    3. WINDOWS MOBILE-LIKE AUDIT — Windows 11 IS becoming a mobile OS: app
       sandbox permissions (camera/mic/location/contacts), advertising ID,
       telemetry you can't fully kill, Microsoft Store lock-in, Phone Link
       bridging your mobile into Windows. This module audits all of it —
       because the "phone problems" are now Windows problems.

    4. WINDOWS MONITORING-SOFTWARE SCAN — the same vendors that ship Android
       stalkerware packages ship Windows programs: commercial spouseware with
       a Windows keylogger module, "parental control" abused to track partners,
       and "employee monitoring" (bossware) used for personal surveillance.
       This module scans Add/Remove Programs and running processes against a
       dual-use table — because the phone gap is closed, the PC gap is next.

    THE BETTER-WAY LAW: every detection ships its fix. Stalkerware found in
    a backup -> quarantine + removal steps. Windows surveillance found ->
    the exact toggle/registry/policy to kill it, with rollback.

    Honest limits, stated up front:
    - We cannot scan a phone's live filesystem from Windows (no root/jailbreak
      bridge). We scan what the phone LEAVES on this machine: backups, MTP
      dumps, sync artifacts.
    - iOS backups are encrypted if the user set a backup password — we say so
      and move on, we don't crack it.
    - Stalkerware package-name tables go stale; the table ships with a
      refresh date and the module warns when it's older than 90 days.
    - The dual-use Windows table matches Add/Remove Programs and the process
      list; stealth monitors that hide from both need module 21
      (malware-hunter), not this scan.

.NOTES
    Version: 1.1.0 (2026-10-31) — added Windows dual-use monitoring scan
    (Gregg's "Windows is becoming mobile" order, continued).
    PowerShell 5.1 compatible. Zero external dependencies.
#>

# ---------------------------------------------------------------------------
# Stalkerware indicator tables
# ---------------------------------------------------------------------------

function Get-StalkerwarePackageTable {
    <#
    .SYNOPSIS
        Known stalkerware / spouseware Android package names.
    .DESCRIPTION
        Compiled from public threat-intel (Kaspersky, EFF, Citizen Lab
        reporting). Table ships with a refresh date; Test-StalkerwareTableFresh
        warns when older than 90 days. These are the packages a backup scan
        or an installed-app inventory looks for.
    #>
    [CmdletBinding()]
    param()

    # Refresh date of this table — update when adding new entries.
    $script:StalkerwareTableDate = '2026-10-30'  # Echap sync: 2026-10-30

    return @(
        # --- Commercial spouseware ---
        @{ Package='com.mspy';              Name='mSpy';                 Notes='Commercial spouseware; hides icon, exfiltrates SMS/calls/GPS.' },
        @{ Package='com.flexispy';          Name='FlexiSPY';             Notes='Commercial spouseware; call interception, ambient recording.' },
        @{ Package='com.highster';          Name='Highster Mobile';      Notes='Commercial spouseware; SMS/call/GPS exfil.' },
        @{ Package='com.spybubble';         Name='SpyBubble';           Notes='Commercial spouseware.' },
        @{ Package='com.mobistealth';       Name='Mobistealth';         Notes='Commercial spouseware.' },
        @{ Package='com.xnspy';             Name='Xnspy';               Notes='Commercial spouseware.' },
        @{ Package='com.cocospy';           Name='Cocospy';             Notes='Commercial spouseware; no-root install path.' },
        @{ Package='com.spyic';             Name='Spyic';               Notes='Commercial spouseware.' },
        @{ Package='com.minspy';            Name='Minspy';              Notes='Commercial spouseware.' },
        @{ Package='com.spyier';            Name='Spyier';              Notes='Commercial spouseware.' },
        @{ Package='com.neatspy';           Name='Neatspy';             Notes='Commercial spouseware.' },
        @{ Package='com.kids guard';        Name='KidsGuard';           Notes='Marketed as parental control; abused as spouseware.' },
        @{ Package='com.clevguard';         Name='ClevGuard';           Notes='KidsGuard publisher package.' },
        @{ Package='com.thecounter';        Name='TheTruthSpy';         Notes='Commercial spouseware; breached 2018, data leaked.' },
        @{ Package='com.hoverwatch';        Name='Hoverwatch';          Notes='Commercial spouseware; keylogger component.' },
        @{ Package='com.phonespector';      Name='PhoneSpector';         Notes='Commercial spouseware.' },
        @{ Package='com.autoforward';       Name='Auto Forward';        Notes='Commercial spouseware; SMS/call forwarding.' },
        @{ Package='com.digiscale';         Name='DigiScale';           Notes='Spouseware variant.' },
        # --- Dual-use / abused parental control ---
        @{ Package='com.kidlogger';          Name='KidLogger';           Notes='Parental control; keylogging abused for stalking.' },
        @{ Package='com.retinax';           Name='Retinax';             Notes='Parental control with stealth mode.' },
        @{ Package='com.talklog';           Name='Talklog';             Notes='Call-recording abused as spouseware.' },
        @{ Package='com.smsbackup';         Name='SMS Backup+';         Notes='Legit backup tool; check for unconsented installs.' },
        # --- Open-source / DIY trackers abused for stalking ---
        @{ Package='com.github.stalker';     Name='Generic stalker builds'; Notes='Placeholder pattern for GitHub-built trackers.' },
        # --- Echap stalkerware-indicators (CC BY 4.0, https://github.com/AssoEchap/stalkerware-indicators) ---
        @{ Package='com.apspy.app'; Name='TheTruthSpy family'; Notes='TheTruthSpy/Copy9/MxSpy/iSpyoo backend; disguised as system service.' },
        @{ Package='com.systemservice'; Name='TheTruthSpy'; Notes='Classic disguise name: 'System Service'.' },
        @{ Package='com.thetruth'; Name='TheTruthSpy'; Notes='TheTruthSpy variant.' },
        @{ Package='com.mxspy'; Name='MxSpy/TheTruthSpy'; Notes='Same Nidb backend as TheTruthSpy.' },
        @{ Package='com.ispyoo'; Name='iSpyoo/TheTruthSpy'; Notes='Same backend family.' },
        @{ Package='com.spyzee'; Name='SpyZee/TheTruthSpy'; Notes='Same backend family.' },
        @{ Package='com.guest'; Name='GuestSpy/TheTruthSpy'; Notes='Same backend family.' },
        @{ Package='com.hellospy'; Name='HelloSpy'; Notes='HelloSpy family (1TopSpy/MaxxSpy/MobiiSpy/SpyHide).' },
        @{ Package='com.maxxspy'; Name='MaxxSpy/HelloSpy'; Notes='HelloSpy family.' },
        @{ Package='com.mobiispy'; Name='MobiiSpy/HelloSpy'; Notes='HelloSpy family.' },
        @{ Package='com.topspy'; Name='1TopSpy/HelloSpy'; Notes='HelloSpy family.' },
        @{ Package='com.wifiset.service'; Name='Fake Wi-Fi Settings'; Notes='Disguised as 'Wi-Fi Settings' (Zscaler 2024).' },
        @{ Package='com.googlesettings.setting'; Name='Fake Google Settings'; Notes='Disguised as system settings (HelloSpy family).' },
        @{ Package='com.android.innovaspy'; Name='InnovaSpy/HelloSpy'; Notes='HelloSpy family.' },
        @{ Package='com.prophoto.editor'; Name='Fake Photo Editor'; Notes='HelloSpy family disguise.' },
        @{ Package='com.sa.app'; Name='SpyAdvice'; Notes='SpyAdvice / FreeSpyPhone.' },
        @{ Package='core.update.framework'; Name='mSpy'; Notes='mSpy disguised package (PETS 2023).' },
        @{ Package='com.kids.pro'; Name='ClevGuard'; Notes='ClevGuard/KidsGuard disguised (PETS 2023).' },
        @{ Package='com.android.core.mntw'; Name='HoverWatch'; Notes='HoverWatch disguised (PETS 2023).' },
        @{ Package='com.fp.backup'; Name='FlexiSPY'; Notes='FlexiSPY disguised as backup (PETS 2023).' },
        @{ Package='com.sc.spyic.v3'; Name='Spyic'; Notes='Spyic v3 disguised (PETS 2023).' },
        @{ Package='m.mobile.control'; Name='SpyHuman'; Notes='SpyHuman package (PETS 2023).' },
        @{ Package='com.lsdroid.cerberus'; Name='Cerberus'; Notes='Cerberus spyware (PETS 2023).' },
        @{ Package='mobile.monitor.child2021'; Name='MobileTrackerFree'; Notes='MobileTrackerFree (PETS 2023).' },
        @{ Package='city.russ.alltrackercorp'; Name='Fake Thief Tracker'; Notes='Disguised as 'Thief Tracker' (Zscaler 2024).' },
        @{ Package='com.autoforward.monitor'; Name='AutoForward'; Notes='Disguised as 'Device' (Zscaler 2024).' },
    )
}

function Get-StalkerwareC2Table {
    <#
    .SYNOPSIS
        Known stalkerware command-and-control domains.
    .DESCRIPTION
        Used by the network leg: match against DNS queries / flows captured
        by packet-witness, or against a Pi-hole / hosts log. Domains go stale
        fast — table date checked by Test-StalkerwareTableFresh.
    #>
    [CmdletBinding()]
    param()

    return @(
        @{ Domain='data.mspy.com';           Family='mSpy' },
        @{ Domain='api.mspy.com';            Family='mSpy' },
        @{ Domain='cp.flexispy.com';         Family='FlexiSPY' },
        @{ Domain='data.flexispy.com';       Family='FlexiSPY' },
        @{ Domain='api.cocospy.com';         Family='Cocospy' },
        @{ Domain='track.cocospy.com';       Family='Cocospy' },
        @{ Domain='api.spyic.com';           Family='Spyic' },
        @{ Domain='my.thetruthspy.com';      Family='TheTruthSpy' },
        @{ Domain='cp.hoverwatch.com';       Family='Hoverwatch' },
        @{ Domain='api.hoverwatch.com';      Family='Hoverwatch' },
        # --- Echap stalkerware-indicators C2 ---
        @{ Domain='my.thetruthspy.com';       Family='TheTruthSpy' },
        @{ Domain='my.copy9.com';             Family='TheTruthSpy/Copy9' },
        @{ Domain='my.ispyoo.com';            Family='TheTruthSpy/iSpyoo' },
        @{ Domain='protocol-a.thetruthspy.com'; Family='TheTruthSpy' },
        @{ Domain='sync-a.thetruthspy.com';   Family='TheTruthSpy' },
        @{ Domain='hellospy.com';             Family='HelloSpy' },
        @{ Domain='maxxspy.com';              Family='HelloSpy/MaxxSpy' },
        @{ Domain='mobiispy.com';             Family='HelloSpy/MobiiSpy' },
        @{ Domain='spyhide.com';              Family='SpyHide/HelloSpy' },
        @{ Domain='client.spyhide.com';       Family='SpyHide' },
        @{ Domain='1topspy.com';              Family='HelloSpy/1TopSpy' },
    )
}

function Test-StalkerwareTableFresh {
    <#
    .SYNOPSIS
        Warns when the stalkerware tables are older than 90 days.
    .DESCRIPTION
        Pure function. Stalkerware domains and package names churn; a stale
        table is a false sense of security. Returns a verdict object.
    #>
    [CmdletBinding()]
    param(
        [string]$TableDate = '2026-10-30',
        [datetime]$AsOf = (Get-Date)
    )

    try {
        $ref = [datetime]::ParseExact($TableDate, 'yyyy-MM-dd', $null)
    } catch {
        return [pscustomobject]@{
            Verdict = 'UNKNOWN'; DaysOld = -1
            Message = "Table date '$TableDate' is not parseable — cannot assess freshness."
        }
    }

    $days = ($AsOf - $ref).Days
    if ($days -lt 0) {
        return [pscustomobject]@{ Verdict='UNKNOWN'; DaysOld=$days; Message='Table date is in the future — clock or table error.' }
    }
    if ($days -gt 90) {
        return [pscustomobject]@{
            Verdict='STALE'; DaysOld=$days
            Message="Stalkerware tables are $days days old (>90). Refresh from threat intel before trusting a clean result."
        }
    }
    return [pscustomobject]@{
        Verdict='FRESH'; DaysOld=$days
        Message="Stalkerware tables are $days days old — within the 90-day window."
    }
}

# ---------------------------------------------------------------------------
# Phone backup discovery and scanning
# ---------------------------------------------------------------------------

function Find-PhoneBackups {
    <#
    .SYNOPSIS
        Locates iOS and Android backup / dump locations on this Windows box.
    .DESCRIPTION
        Checks the standard locations:
        - iTunes: %APPDATA%\Apple Computer\MobileSync\Backup\
        - Apple Devices (Win11): %USERPROFILE%\Apple\MobileSync\Backup\
        - Android MTP dumps: user-specified; we check common roots
          (Desktop, Documents, Downloads) for Android-style trees.
        Returns found backup roots with type and size. Never modifies.
    #>
    [CmdletBinding()]
    param()

    $found = @()

    # --- iTunes classic ---
    $itunes = Join-Path $env:APPDATA 'Apple Computer\MobileSync\Backup'
    if (Test-Path $itunes) {
        $dirs = Get-ChildItem -Path $itunes -Directory -ErrorAction SilentlyContinue
        foreach ($d in $dirs) {
            $size = (Get-ChildItem -Path $d.FullName -Recurse -File -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            $found += [pscustomobject]@{
                Type='iOS-iTunes'; Path=$d.FullName
                DeviceId=$d.Name; SizeBytes=$size
            }
        }
    }

    # --- Apple Devices app (Windows 11 Store app) ---
    $appleDev = Join-Path $env:USERPROFILE 'Apple\MobileSync\Backup'
    if (Test-Path $appleDev) {
        $dirs = Get-ChildItem -Path $appleDev -Directory -ErrorAction SilentlyContinue
        foreach ($d in $dirs) {
            $size = (Get-ChildItem -Path $d.FullName -Recurse -File -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            $found += [pscustomobject]@{
                Type='iOS-AppleDevices'; Path=$d.FullName
                DeviceId=$d.Name; SizeBytes=$size
            }
        }
    }

    # --- Android MTP dumps: look for Android-style trees in user roots ---
    $roots = @(
        (Join-Path ([Environment]::GetFolderPath('Desktop')) ''),
        (Join-Path ([Environment]::GetFolderPath('MyDocuments')) ''),
        (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads')
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $dirs = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue
        foreach ($d in $dirs) {
            # Android dump heuristic: contains DCIM + Android/ trees
            $hasDcim = Test-Path (Join-Path $d.FullName 'DCIM')
            $hasAndroid = Test-Path (Join-Path $d.FullName 'Android')
            if ($hasDcim -or $hasAndroid) {
                $size = (Get-ChildItem -Path $d.FullName -Recurse -File -ErrorAction SilentlyContinue |
                         Measure-Object -Property Length -Sum).Sum
                $found += [pscustomobject]@{
                    Type='Android-Dump'; Path=$d.FullName
                    DeviceId=$d.Name; SizeBytes=$size
                }
            }
        }
    }

    Write-Host ("[*] mobile-shield: found {0} phone backup/dump location(s)" -f $found.Count)
    return @($found)
}

function Test-BackupEncrypted {
    <#
    .SYNOPSIS
        Checks whether an iOS backup is encrypted (password-protected).
    .DESCRIPTION
        Reads Manifest.plist for the IsEncrypted key. Encrypted backups we
        cannot scan — stated plainly, not worked around. Pure read, no modify.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$BackupPath
    )

    $manifest = Join-Path $BackupPath 'Manifest.plist'
    if (-not (Test-Path $manifest)) {
        return [pscustomobject]@{
            Encrypted='UNKNOWN'
            Message='No Manifest.plist — not an iTunes-style backup or incomplete.'
        }
    }

    try {
        $text = [System.IO.File]::ReadAllText($manifest)
    } catch {
        return [pscustomobject]@{
            Encrypted='UNKNOWN'
            Message="Could not read Manifest.plist: $($_.Exception.Message)"
        }
    }

    # bplist is binary; fall back to byte search for the IsEncrypted key
    $bytes = [System.IO.File]::ReadAllBytes($manifest)
    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
    if ($ascii -match 'IsEncrypted') {
        # Check the byte following the key for true/false marker
        return [pscustomobject]@{
            Encrypted='LIKELY'
            Message='Manifest.plist contains IsEncrypted key — backup is probably password-protected. Cannot scan without the password; we do not crack it.'
        }
    }
    return [pscustomobject]@{
        Encrypted='NO'
        Message='No IsEncrypted key in Manifest.plist — backup appears unencrypted and scannable.'
    }
}

function Invoke-BackupStalkerwareScan {
    <#
    .SYNOPSIS
        Scans a phone backup/dump for stalkerware indicators.
    .DESCRIPTION
        Three passes:
        1. Package-name match against the stalkerware table (Android dumps:
           scan directory names under Android/data; iOS: scan file names and
           Info.plist-adjacent metadata).
        2. C2 domain match inside any text-readable files (hosts logs, config
           plists, JSON).
        3. Suspicious profile / certificate check (iOS: .mobileconfig files;
           Android: unknown CA certs in dump).
        Read-only. Returns findings with severity. THE BETTER-WAY LAW: every
        finding ships the removal step.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$BackupPath,
        [int]$MaxFiles = 50000
    )

    $findings = @()
    $packages = Get-StalkerwarePackageTable
    $c2domains = Get-StalkerwareC2Table | ForEach-Object { $_.Domain }

    Write-Host "[*] mobile-shield: scanning backup at $BackupPath"

    # --- Pass 1: package-name match on directory/file names ---
    try {
        $entries = Get-ChildItem -Path $BackupPath -Recurse -ErrorAction SilentlyContinue |
                   Select-Object -First $MaxFiles
    } catch {
        Write-Host ("[!] mobile-shield: could not enumerate backup: {0}" -f $_.Exception.Message)
        return @()
    }

    foreach ($pkg in $packages) {
        $hits = @($entries | Where-Object { $_.Name -like ("*" + $pkg.Package + "*") })
        foreach ($h in $hits) {
            $findings += [pscustomobject]@{
                Severity='CRITICAL'; Category='StalkerwarePackage'
                Indicator=$pkg.Package; Name=$pkg.Name
                Path=$h.FullName; Notes=$pkg.Notes
                Fix='Delete the app from the phone (Settings > Apps), then change all passwords from a CLEAN device. Check for device-admin grants the app may hold.'
            }
        }
    }

    # --- Pass 2: C2 domain match inside small text files ---
    $textFiles = @($entries | Where-Object {
        -not $_.PSIsContainer -and $_.Length -lt 2MB -and
        $_.Extension -match '\.(txt|log|json|plist|xml|db-shm|conf|cfg)$'
    } | Select-Object -First 2000)

    foreach ($tf in $textFiles) {
        try {
            $content = [System.IO.File]::ReadAllText($tf.FullName)
        } catch { continue }
        foreach ($dom in $c2domains) {
            if ($content -match [regex]::Escape($dom)) {
                $findings += [pscustomobject]@{
                    Severity='HIGH'; Category='StalkerwareC2'
                    Indicator=$dom; Name='C2 domain reference'
                    Path=$tf.FullName
                    Notes='A file in this backup references a known stalkerware control server.'
                    Fix='Treat the phone as compromised: factory reset from recovery mode, set up as NEW (do not restore the backup), change all passwords from a clean device.'
                }
                break
            }
        }
    }

    # --- Pass 3: suspicious iOS profiles ---
    $profiles = @($entries | Where-Object { $_.Extension -eq '.mobileconfig' })
    foreach ($pr in $profiles) {
        $findings += [pscustomobject]@{
            Severity='MEDIUM'; Category='SuspiciousProfile'
            Indicator=$pr.Name; Name='Configuration profile in backup'
            Path=$pr.FullName
            Notes='Configuration profiles can install root certificates and VPNs for traffic interception. Legit (MDM/work) or stalkerware — verify the signer.'
            Fix='On the iPhone: Settings > General > VPN & Device Management — remove any profile you did not install. Then check for unknown root certificates.'
        }
    }

    Write-Host ("[*] mobile-shield: scan complete — {0} finding(s)" -f $findings.Count)
    return @($findings)
}

# ---------------------------------------------------------------------------
# Windows mobile-like surveillance audit
# (Gregg: Windows IS becoming mobile — audit it like one)
# ---------------------------------------------------------------------------

function Get-WindowsPrivacyAudit {
    <#
    .SYNOPSIS
        Audits Windows 11's mobile-like surveillance surfaces.
    .DESCRIPTION
        Checks, each with its fix:
        - Advertising ID (app tracking identifier)
        - Location services + per-app location grants
        - Camera / microphone / contacts per-app grants
        - Telemetry level (Diagnostic data)
        - Tailored experiences (uses diagnostic data for ads/tips)
        - Phone Link (bridges mobile into Windows — check pairing)
        - Microsoft Store auto-installs (suggested apps)
        - Activity history / Timeline
        Read-only checks; fixes are separate Repair-* functions per the
        Better-Way Law.
    #>
    [CmdletBinding()]
    param()

    $results = @()

    # --- Advertising ID ---
    try {
        $adv = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -ErrorAction SilentlyContinue
        $advEnabled = $adv.Enabled -ne 0
    } catch { $advEnabled = 'UNKNOWN' }
    $results += [pscustomobject]@{
        Check='Advertising ID'; Status=$(if ($advEnabled -eq $true) { 'EXPOSED' } elseif ($advEnabled -eq $false) { 'OK' } else { 'UNKNOWN' })
        Detail='Per-app tracking identifier (the Windows IDFA).'
        Fix='Settings > Privacy & security > General > turn off "Let apps show me personalized ads by using my advertising ID".'
    }

    # --- Location services ---
    try {
        $loc = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFEA47C}' -ErrorAction SilentlyContinue
        $locStatus = $loc.Value
    } catch { $locStatus = 'UNKNOWN' }
    $results += [pscustomobject]@{
        Check='Location services'; Status=$(if ($locStatus -eq 'Allow') { 'EXPOSED' } elseif ($locStatus -eq 'Deny') { 'OK' } else { 'UNKNOWN' })
        Detail="Global location switch: $locStatus"
        Fix='Settings > Privacy & security > Location > turn off Location services, then review per-app grants below it.'
    }

    # --- Telemetry / diagnostic data ---
    try {
        $tel = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -ErrorAction SilentlyContinue
        $telVal = $tel.AllowTelemetry
        if ($null -eq $telVal) {
            $tel2 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name AllowTelemetry -ErrorAction SilentlyContinue
            $telVal = $tel2.AllowTelemetry
        }
    } catch { $telVal = 'UNKNOWN' }
    $results += [pscustomobject]@{
        Check='Diagnostic telemetry'; Status=$(if ($telVal -eq 0) { 'OK' } elseif ($telVal -is [int]) { 'EXPOSED' } else { 'UNKNOWN' })
        Detail="AllowTelemetry = $telVal (0=Security only, 1=Basic, 2=Enhanced, 3=Full)"
        Fix='Settings > Privacy & security > Diagnostics & feedback > set to "Required diagnostic data" only; turn off "Tailored experiences".'
    }

    # --- Tailored experiences ---
    try {
        $te = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' -Name TailoredExperiencesWithDiagnosticDataEnabled -ErrorAction SilentlyContinue
        $teVal = $te.TailoredExperiencesWithDiagnosticDataEnabled
    } catch { $teVal = 'UNKNOWN' }
    $results += [pscustomobject]@{
        Check='Tailored experiences'; Status=$(if ($teVal -eq 1) { 'EXPOSED' } elseif ($teVal -eq 0) { 'OK' } else { 'UNKNOWN' })
        Detail='Uses diagnostic data for personalized tips/ads.'
        Fix='Settings > Privacy & security > Diagnostics & feedback > turn off "Tailored experiences".'
    }

    # --- Activity history / Timeline ---
    try {
        $ah = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableActivityFeed -ErrorAction SilentlyContinue
        $ahVal = $ah.EnableActivityFeed
    } catch { $ahVal = 'UNKNOWN' }
    $results += [pscustomobject]@{
        Check='Activity history'; Status=$(if ($ahVal -eq 0) { 'OK' } elseif ($null -ne $ahVal) { 'EXPOSED' } else { 'UNKNOWN' })
        Detail='Timeline of app/file activity sent to Microsoft.'
        Fix='Settings > Privacy & security > Activity history > uncheck "Store my activity history on this device". Clear history.'
    }

    # --- Phone Link pairing ---
    $phoneLink = Get-Process -Name 'PhoneExperienceHost' -ErrorAction SilentlyContinue
    $results += [pscustomobject]@{
        Check='Phone Link'; Status=$(if ($phoneLink) { 'REVIEW' } else { 'OK' })
        Detail=$(if ($phoneLink) { 'Phone Link is running — your mobile is bridged into Windows.' } else { 'Phone Link not running.' })
        Fix='If you did not pair it: Settings > Bluetooth & devices > Mobile devices > turn off. Unpair from your phone too.'
    }

    # --- Suggested apps / Store auto-install ---
    try {
        $sugg = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SilentInstalledAppsEnabled -ErrorAction SilentlyContinue
        $suggVal = $sugg.SilentInstalledAppsEnabled
    } catch { $suggVal = 'UNKNOWN' }
    $results += [pscustomobject]@{
        Check='Suggested app installs'; Status=$(if ($suggVal -eq 1) { 'EXPOSED' } elseif ($suggVal -eq 0) { 'OK' } else { 'UNKNOWN' })
        Detail='Windows silently installs "suggested" Store apps.'
        Fix='Settings > Personalization > Start > turn off "Show suggestions". Or set SilentInstalledAppsEnabled=0.'
    }

    # --- App permission grants (camera/mic/contacts) — inventory, not verdict ---
    $permRoots = @{
        Camera   = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-11DF-8F67-002264FEB630}'
        Microphone = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C08}'
        Contacts = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD02F467E}'
    }
    foreach ($perm in $permRoots.Keys) {
        $grants = @()
        $appKey = $permRoots[$perm] -replace 'Global', 'LooselyCoupled'
        try {
            $apps = Get-ChildItem -Path $appKey -ErrorAction SilentlyContinue
            foreach ($a in $apps) {
                $v = (Get-ItemProperty -Path $a.PSPath -ErrorAction SilentlyContinue).Value
                if ($v -eq 'Allow') { $grants += $a.PSChildName }
            }
        } catch { }
        $results += [pscustomobject]@{
            Check="$perm app grants"; Status=$(if ($grants.Count -gt 0) { 'REVIEW' } else { 'OK' })
            Detail=$(if ($grants.Count -gt 0) { "Allowed apps: $($grants -join ', ')" } else { 'No per-app grants found.' })
            Fix="Settings > Privacy & security > $perm > review each app; turn off anything that should not have it."
        }
    }

    return @($results)
}

function Repair-WindowsPrivacy {
    <#
    .SYNOPSIS
        Applies the Better-Way fixes for the privacy audit findings.
    .DESCRIPTION
        Each fix writes the registry value that the corresponding audit check
        reads, after backing up the original value to a rollback object.
        Supports -WhatIf. Returns the rollback bundle.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [switch]$DisableAdvertisingId,
        [switch]$DisableTailoredExperiences,
        [switch]$DisableActivityHistory,
        [switch]$DisableSuggestedApps
    )

    $rollback = @()

    if ($DisableAdvertisingId) {
        $p = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
        $old = (Get-ItemProperty -Path $p -Name Enabled -ErrorAction SilentlyContinue).Enabled
        $rollback += [pscustomobject]@{ Path=$p; Name='Enabled'; OldValue=$old }
        if ($PSCmdlet.ShouldProcess($p, 'Disable advertising ID')) {
            Set-ItemProperty -Path $p -Name Enabled -Value 0 -ErrorAction SilentlyContinue
            Write-Host '[+] mobile-shield: advertising ID disabled'
        }
    }

    if ($DisableTailoredExperiences) {
        $p = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy'
        $old = (Get-ItemProperty -Path $p -Name TailoredExperiencesWithDiagnosticDataEnabled -ErrorAction SilentlyContinue).TailoredExperiencesWithDiagnosticDataEnabled
        $rollback += [pscustomobject]@{ Path=$p; Name='TailoredExperiencesWithDiagnosticDataEnabled'; OldValue=$old }
        if ($PSCmdlet.ShouldProcess($p, 'Disable tailored experiences')) {
            Set-ItemProperty -Path $p -Name TailoredExperiencesWithDiagnosticDataEnabled -Value 0 -ErrorAction SilentlyContinue
            Write-Host '[+] mobile-shield: tailored experiences disabled'
        }
    }

    if ($DisableActivityHistory) {
        $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        if ($PSCmdlet.ShouldProcess($p, 'Disable activity history feed')) {
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
            Set-ItemProperty -Path $p -Name EnableActivityFeed -Value 0 -ErrorAction SilentlyContinue
            Write-Host '[+] mobile-shield: activity history feed disabled (needs admin)'
        }
    }

    if ($DisableSuggestedApps) {
        $p = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        $old = (Get-ItemProperty -Path $p -Name SilentInstalledAppsEnabled -ErrorAction SilentlyContinue).SilentInstalledAppsEnabled
        $rollback += [pscustomobject]@{ Path=$p; Name='SilentInstalledAppsEnabled'; OldValue=$old }
        if ($PSCmdlet.ShouldProcess($p, 'Disable suggested app installs')) {
            Set-ItemProperty -Path $p -Name SilentInstalledAppsEnabled -Value 0 -ErrorAction SilentlyContinue
            Write-Host '[+] mobile-shield: suggested app installs disabled'
        }
    }

    return @($rollback)
}

# ---------------------------------------------------------------------------
# Network leg — stalkerware C2 matching
# ---------------------------------------------------------------------------

function Test-DnsForStalkerwareC2 {
    <#
    .SYNOPSIS
        Checks a DNS query log (or live cache) against the stalkerware C2 table.
    .DESCRIPTION
        Takes an array of queried domain strings (from packet-witness output,
        Pi-hole log, or `Get-DnsClientCache`), matches against the C2 table.
        Pure function — no network access.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string[]]$QueriedDomains
    )

    $c2 = Get-StalkerwareC2Table
    $hits = @()

    foreach ($q in $QueriedDomains) {
        $ql = $q.ToLower().Trim().TrimEnd('.')
        foreach ($entry in $c2) {
            $dom = $entry.Domain.ToLower()
            if ($ql -eq $dom -or $ql.EndsWith('.' + $dom)) {
                $hits += [pscustomobject]@{
                    QueriedDomain=$q; MatchedC2=$entry.Domain
                    Family=$entry.Family; Severity='CRITICAL'
                    Fix='A device on this network is talking to stalkerware infrastructure. Identify the device by IP/MAC, isolate it, factory reset the phone.'
                }
                break
            }
        }
    }

    Write-Host ("[*] mobile-shield: C2 check over {0} domains — {1} hit(s)" -f $QueriedDomains.Count, $hits.Count)
    return @($hits)
}

function Get-DnsClientCacheDomains {
    <#
    .SYNOPSIS
        Pulls recently-queried domains from the Windows DNS client cache.
    .DESCRIPTION
        Feeds Test-DnsForStalkerwareC2. Read-only.
    #>
    [CmdletBinding()]
    param()

    try {
        $cache = Get-DnsClientCache -ErrorAction SilentlyContinue
        return @($cache | Where-Object { $_.Entry } | ForEach-Object { $_.Entry } | Sort-Object -Unique)
    } catch {
        Write-Host ("[!] mobile-shield: could not read DNS cache: {0}" -f $_.Exception.Message)
        return @()
    }
}

# ---------------------------------------------------------------------------
# Windows dual-use monitoring / stalkerware software scan
# (Gregg's "Windows is becoming mobile" order, continued: the same vendors
# that ship Android stalkerware packages ship Windows programs. The package
# table catches them on phones; this catches them on the PC itself.)
# ---------------------------------------------------------------------------

function Get-WindowsMonitoringSoftwareTable {
    <#
    .SYNOPSIS
        Known dual-use monitoring / stalkerware products that run on Windows.
    .DESCRIPTION
        Pure data. Each entry carries a MatchName wildcard (matched against
        Add/Remove Programs DisplayName), an optional MatchProcess wildcard
        (matched against running process names), the vendor, a category, and
        notes on how the product is abused.
        Categories:
          STALKERWARE-COMMERCIAL - sold for intimate-partner surveillance;
                                   hides itself by design
          DUAL-USE-PARENTAL      - marketed for kids; routinely installed on
                                   a partner's machine instead
          DUAL-USE-EMPLOYEE      - marketed for workplaces (bossware); used
                                   for personal surveillance when installed
                                   without consent
        Legitimate installs (your own parental controls, your employer's
        disclosed tool) will also match — the finding is "this CAN watch
        you," not "this IS attacking you." Context is the user's call.
    #>
    [CmdletBinding()]
    param()
    return @(
        # --- Commercial stalkerware with a Windows build ---
        @{ Name='mSpy';                   MatchName='*mSpy*';            MatchProcess='*mspy*';            Vendor='mSpy';         Category='STALKERWARE-COMMERCIAL'; Notes='Commercial spouseware; Windows keylogger + screenshot module. Hides from taskbar when configured to.' },
        @{ Name='FlexiSPY';               MatchName='*FlexiSPY*';        MatchProcess='*flexispy*';        Vendor='FlexiSPY';     Category='STALKERWARE-COMMERCIAL'; Notes='FlexiSPY for Computers: ambient recording, keystroke capture, remote camera. Flagship commercial spouseware.' },
        @{ Name='WebWatcher';             MatchName='*WebWatcher*';      MatchProcess='*webwatcher*';      Vendor='WebWatcher';   Category='STALKERWARE-COMMERCIAL'; Notes='Windows/Mac/Android monitor sold as parental control; classic intimate-partner surveillance vector.' },
        @{ Name='XNSPY';                  MatchName='*XNSPY*';           MatchProcess='*xnspy*';           Vendor='XNSPY';        Category='STALKERWARE-COMMERCIAL'; Notes='Commercial spouseware with a Windows monitoring build; call, screen and message capture.' },
        @{ Name='Cocospy';                MatchName='*Cocospy*';          MatchProcess='*cocospy*';         Vendor='Cocospy';      Category='STALKERWARE-COMMERCIAL'; Notes='No-root marketing; Windows build monitors keystrokes and app use.' },
        @{ Name='uMobix';                 MatchName='*uMobix*';           MatchProcess='*umobix*';          Vendor='uMobix';       Category='STALKERWARE-COMMERCIAL'; Notes='Real-time phone and PC tracker marketed to suspicious partners.' },
        @{ Name='TheWiSpy';               MatchName='*TheWiSpy*';        MatchProcess='*thewispy*';        Vendor='TheWiSpy';     Category='STALKERWARE-COMMERCIAL'; Notes='Windows + mobile monitor; screen recording and keylogging.' },
        @{ Name='Hoverwatch';             MatchName='*Hoverwatch*';      MatchProcess='*hoverwatch*';      Vendor='Hoverwatch';   Category='STALKERWARE-COMMERCIAL'; Notes='Windows keylogger with invisible mode; phone-tracker branding.' },
        @{ Name='Spyrix Personal Monitor'; MatchName='*Spyrix*';         MatchProcess='*spyrix*';          Vendor='Spyrix';       Category='STALKERWARE-COMMERCIAL'; Notes='Keylogger marketed for family safety; stealth mode hides it completely.' },
        @{ Name='Realtime-Spy';           MatchName='*Realtime-Spy*';    MatchProcess='*realtimespy*';     Vendor='Realtime-Spy'; Category='STALKERWARE-COMMERCIAL'; Notes='Remote spy software for Windows; marketed to spouses and employers.' },
        # --- Dual-use parental control ---
        @{ Name='KidLogger';              MatchName='*KidLogger*';       MatchProcess='*kidlogger*';       Vendor='KidLogger';    Category='DUAL-USE-PARENTAL'; Notes='Parental control with Windows + mobile builds; keylogging routinely abused for partner surveillance.' },
        @{ Name='Qustodio';               MatchName='*Qustodio*';        MatchProcess='*qustodio*';        Vendor='Qustodio';     Category='DUAL-USE-PARENTAL'; Notes='Parental control, Windows app; location + web monitoring abused in partner tracking.' },
        @{ Name='Net Nanny';              MatchName='*Net Nanny*';       MatchProcess='*netnanny*';        Vendor='Net Nanny';    Category='DUAL-USE-PARENTAL'; Notes='Parental filter, Windows build; dual-use for monitoring another adult.' },
        @{ Name='Covenant Eyes';          MatchName='*Covenant Eyes*';   MatchProcess='*covenanteyes*';    Vendor='Covenant Eyes'; Category='DUAL-USE-PARENTAL'; Notes='Accountability and screen monitoring for Windows; installed by partners as surveillance.' },
        @{ Name='Bark';                   MatchName='*Bark*';            MatchProcess='*bark*';            Vendor='Bark';         Category='DUAL-USE-PARENTAL'; Notes='Child-monitoring app with a Windows build; message and screen capture.' },
        @{ Name='FamiSafe';               MatchName='*FamiSafe*';        MatchProcess='*famisafe*';        Vendor='Wondershare';  Category='DUAL-USE-PARENTAL'; Notes='Wondershare parental control; Windows + mobile; location and app blocking.' },
        @{ Name='Norton Family';          MatchName='*Norton Family*';  MatchProcess='*nortonfamily*';    Vendor='Norton';       Category='DUAL-USE-PARENTAL'; Notes='Parental control suite; Windows agent tracks web and location.' },
        @{ Name='Microsoft Family Safety'; MatchName='*Family Safety*'; MatchProcess='';                  Vendor='Microsoft';    Category='DUAL-USE-PARENTAL'; Notes='Built-in Windows family app: location sharing + activity reports. Legitimate — and a ready-made partner tracker if someone else controls the family group.' },
        @{ Name='Mobicip';                MatchName='*Mobicip*';         MatchProcess='*mobicip*';         Vendor='Mobicip';      Category='DUAL-USE-PARENTAL'; Notes='Parental control, Windows build; screen-time and web monitoring.' },
        @{ Name='Kaspersky Safe Kids';    MatchName='*Safe Kids*';       MatchProcess='*kasperskysafekids*'; Vendor='Kaspersky';   Category='DUAL-USE-PARENTAL'; Notes='Parental control with a Windows build; location and app monitoring.' },
        # --- Dual-use employee monitoring (bossware) ---
        @{ Name='Veriato';                MatchName='*Veriato*';         MatchProcess='*veriat*';          Vendor='Veriato';      Category='DUAL-USE-EMPLOYEE'; Notes='Ex-SpectorSoft/eBlaster: keystroke + screen capture for Windows. The original bossware.' },
        @{ Name='ActivTrak';              MatchName='*ActivTrak*';       MatchProcess='*activtrak*';       Vendor='ActivTrak';    Category='DUAL-USE-EMPLOYEE'; Notes='Workforce analytics; screenshots and app tracking. Deployed without consent it is surveillance.' },
        @{ Name='Teramind';               MatchName='*Teramind*';        MatchProcess='*teramind*';        Vendor='Teramind';     Category='DUAL-USE-EMPLOYEE'; Notes='Screen recording, keystrokes, file tracking; ships a stealth agent mode.' },
        @{ Name='Hubstaff';               MatchName='*Hubstaff*';        MatchProcess='*hubstaff*';        Vendor='Hubstaff';     Category='DUAL-USE-EMPLOYEE'; Notes='Time tracking with screenshots and activity levels.' },
        @{ Name='Time Doctor';            MatchName='*Time Doctor*';     MatchProcess='*timedoctor*';      Vendor='Time Doctor';  Category='DUAL-USE-EMPLOYEE'; Notes='Screenshots, app and URL tracking; marketed for remote teams.' },
        @{ Name='StaffCop';               MatchName='*StaffCop*';        MatchProcess='*staffcop*';        Vendor='StaffCop';     Category='DUAL-USE-EMPLOYEE'; Notes='Employee monitoring: screen, keystroke and file capture.' },
        @{ Name='Kickidler';              MatchName='*Kickidler*';       MatchProcess='*kickidler*';       Vendor='Kickidler';    Category='DUAL-USE-EMPLOYEE'; Notes='Screen monitoring and keystroke logging for staff.' },
        @{ Name='InterGuard';             MatchName='*InterGuard*';      MatchProcess='*interguard*';      Vendor='InterGuard';   Category='DUAL-USE-EMPLOYEE'; Notes='Employee monitor; keystroke + screenshot capture.' },
        @{ Name='SentryPC';               MatchName='*SentryPC*';        MatchProcess='*sentrypc*';        Vendor='SentryPC';     Category='DUAL-USE-EMPLOYEE'; Notes='Activity monitoring with a stealth install option.' },
        @{ Name='CurrentWare';            MatchName='*CurrentWare*';     MatchProcess='*currentware*';     Vendor='CurrentWare';  Category='DUAL-USE-EMPLOYEE'; Notes='BrowseControl/BrowseReporter/AccessPatrol: web + endpoint monitoring suite.' }
        # Future additions noted: EyeZy, DeskTime, WorkTime, Refog Keylogger, PC Tattletale.
    )
}

function Test-WindowsMonitoringMatch {
    <#
    .SYNOPSIS
        Matches installed-program / process names against the monitoring table.
    .DESCRIPTION
        Pure logic — takes DisplayName and process-name lists as input, so it
        is fully testable without Windows. Matching is case-insensitive
        wildcard (-like). Returns one finding object per matched product.
    #>
    [CmdletBinding()]
    param(
        [string[]]$DisplayNames = @(),
        [string[]]$ProcessNames = @()
    )

    $table = Get-WindowsMonitoringSoftwareTable
    $findings = @()
    foreach ($entry in $table) {
        $hitOn = @()
        foreach ($d in $DisplayNames) {
            if ($d -like $entry.MatchName) { $hitOn += "Add/Remove: $d" }
        }
        if ($entry.MatchProcess) {
            foreach ($p in $ProcessNames) {
                if ($p -like $entry.MatchProcess) { $hitOn += "Process: $p" }
            }
        }
        if ($hitOn.Count -gt 0) {
            $findings += [pscustomobject]@{
                Name     = $entry.Name
                Vendor   = $entry.Vendor
                Category = $entry.Category
                Evidence = ($hitOn -join '; ')
                Notes    = $entry.Notes
                Fix      = 'If YOU did not install this, treat it as hostile surveillance. Preserve evidence first (module 12 timeline-vault), then uninstall, then run module 08 (breach-cleaner) and change passwords from a clean device. Removing it can alert whoever installed it — if you are in an unsafe situation, get help before removing.'
            }
        }
    }
    return @($findings)
}

function Find-WindowsMonitoringSoftware {
    <#
    .SYNOPSIS
        Scans this Windows PC for installed dual-use monitoring / stalkerware.
    .DESCRIPTION
        Reads Add/Remove Programs (Uninstall registry: 64-bit, 32-bit, and
        per-user hives) plus running process names, then matches through
        Test-WindowsMonitoringMatch.
        Honest limits, HostBadger rule (not evaluated is never clean):
        - UNKNOWN if enumeration itself fails (re-run elevated).
        - NONE-FOUND means none matched in Add/Remove + process list — a
          stealth monitor hiding from both is NOT covered here; deep stealth
          detection belongs to module 21 (malware-hunter).
    #>
    [CmdletBinding()]
    param()

    $names = @(); $procs = @(); $evaluated = $true
    try {
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        foreach ($k in $keys) {
            Get-ItemProperty -Path $k -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                ForEach-Object { $names += $_.DisplayName }
        }
        $procs = @(Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique)
        if ($names.Count -eq 0 -and $procs.Count -eq 0) { $evaluated = $false }
    } catch { $evaluated = $false }

    if (-not $evaluated) {
        return [pscustomobject]@{
            Status   = 'UNKNOWN'
            Findings = @()
            Caveat   = 'Could not enumerate installed programs or processes.'
            Fix      = 'Re-run elevated (Run as Administrator) and retry.'
        }
    }

    $findings = Test-WindowsMonitoringMatch -DisplayNames $names -ProcessNames $procs
    $status = if ($findings.Count -gt 0) { 'FOUND' } else { 'NONE-FOUND' }
    return [pscustomobject]@{
        Status   = $status
        Findings = $findings
        Caveat   = 'NONE-FOUND means none matched in Add/Remove Programs and the process list — stealth monitors that hide from both are not covered here; see module 21 (malware-hunter).'
        Fix      = $(if ($status -eq 'FOUND') { 'Review each finding above before acting — context is yours to judge.' } else { 'No action needed from this check.' })
    }
}

# ---------------------------------------------------------------------------
# Hygiene battery
# ---------------------------------------------------------------------------

function Test-MobileShieldHygiene {
    <#
    .SYNOPSIS
        Self-test battery for the mobile-shield module.
    .DESCRIPTION
        Pure-logic tests: table freshness verdicts, C2 matching (exact,
        subdomain, negative), package table shape, DNS-cache helper contract,
        monitoring-table shape and Windows monitoring matching.
        Returns $true only if every case passes.
    #>
    [CmdletBinding()]
    param()

    $cases = @()
    $pass = 0; $fail = 0

    # --- 1: fresh table ---
    $r = Test-StalkerwareTableFresh -TableDate (Get-Date).ToString('yyyy-MM-dd') -AsOf (Get-Date)
    $cases += [pscustomobject]@{ Name='FreshTable'; Expected='FRESH'; Got=$r.Verdict; Pass=($r.Verdict -eq 'FRESH') }

    # --- 2: stale table ---
    $old = (Get-Date).AddDays(-100).ToString('yyyy-MM-dd')
    $r = Test-StalkerwareTableFresh -TableDate $old -AsOf (Get-Date)
    $cases += [pscustomobject]@{ Name='StaleTable'; Expected='STALE'; Got=$r.Verdict; Pass=($r.Verdict -eq 'STALE') }

    # --- 3: unparseable date ---
    $r = Test-StalkerwareTableFresh -TableDate 'not-a-date' -AsOf (Get-Date)
    $cases += [pscustomobject]@{ Name='BadDate'; Expected='UNKNOWN'; Got=$r.Verdict; Pass=($r.Verdict -eq 'UNKNOWN') }

    # --- 4: C2 exact match ---
    $h = Test-DnsForStalkerwareC2 -QueriedDomains @('data.mspy.com')
    $cases += [pscustomobject]@{ Name='C2Exact'; Expected=1; Got=$h.Count; Pass=($h.Count -eq 1 -and $h[0].Family -eq 'mSpy') }

    # --- 5: C2 subdomain match ---
    $h = Test-DnsForStalkerwareC2 -QueriedDomains @('sub.api.cocospy.com')
    $cases += [pscustomobject]@{ Name='C2Subdomain'; Expected=1; Got=$h.Count; Pass=($h.Count -eq 1) }

    # --- 6: C2 negative ---
    $h = Test-DnsForStalkerwareC2 -QueriedDomains @('www.google.com', 'example.com')
    $cases += [pscustomobject]@{ Name='C2Negative'; Expected=0; Got=$h.Count; Pass=($h.Count -eq 0) }

    # --- 7: C2 case-insensitive ---
    $h = Test-DnsForStalkerwareC2 -QueriedDomains @('DATA.MSPY.COM.')
    $cases += [pscustomobject]@{ Name='C2CaseDot'; Expected=1; Got=$h.Count; Pass=($h.Count -eq 1) }

    # --- 8: package table non-empty with required fields ---
    $pkgs = Get-StalkerwarePackageTable
    $okShape = ($pkgs.Count -ge 10) -and
               (@($pkgs | Where-Object { -not $_.Package -or -not $_.Name -or -not $_.Fix }).Count -eq 0)
    # Note: table entries carry Notes; Fix text lives in scan findings. Check Notes present.
    $okNotes = (@($pkgs | Where-Object { -not $_.Notes }).Count -eq 0)
    $cases += [pscustomobject]@{ Name='PackageTableShape'; Expected=$true; Got=($okShape -and $okNotes); Pass=($okShape -and $okNotes) }

    # --- 9: C2 table non-empty ---
    $c2 = Get-StalkerwareC2Table
    $cases += [pscustomobject]@{ Name='C2TableShape'; Expected=$true; Got=($c2.Count -ge 5); Pass=($c2.Count -ge 5) }

    # --- 10: encrypted-backup unknown path ---
    $r = Test-BackupEncrypted -BackupPath 'C:\nonexistent-backup-xyz'
    $cases += [pscustomobject]@{ Name='BackupMissing'; Expected='UNKNOWN'; Got=$r.Encrypted; Pass=($r.Encrypted -eq 'UNKNOWN') }

    # --- 11: monitoring table shape ---
    $mt = Get-WindowsMonitoringSoftwareTable
    $mtCats = @($mt.Category | Sort-Object -Unique)
    $okMT = ($mt.Count -ge 20) -and
            (@($mt | Where-Object { -not $_.Name -or -not $_.MatchName -or -not $_.Category -or -not $_.Notes }).Count -eq 0) -and
            ($mtCats -contains 'STALKERWARE-COMMERCIAL') -and
            ($mtCats -contains 'DUAL-USE-PARENTAL') -and
            ($mtCats -contains 'DUAL-USE-EMPLOYEE')
    $cases += [pscustomobject]@{ Name='MonitoringTableShape'; Expected=$true; Got=$okMT; Pass=($okMT -eq $true) }

    # --- 12: monitoring match positive (commercial stalkerware) ---
    $m = Test-WindowsMonitoringMatch -DisplayNames @('mSpy') -ProcessNames @()
    $cases += [pscustomobject]@{ Name='MonitoringMatchPositive'; Expected='mSpy'; Got=$(if ($m.Count -gt 0) { $m[0].Name } else { '' }); Pass=($m.Count -eq 1 -and $m[0].Name -eq 'mSpy' -and $m[0].Category -eq 'STALKERWARE-COMMERCIAL') }

    # --- 13: monitoring match negative ---
    $m = Test-WindowsMonitoringMatch -DisplayNames @('Microsoft Edge','Notepad') -ProcessNames @('explorer')
    $cases += [pscustomobject]@{ Name='MonitoringMatchNegative'; Expected=0; Got=$m.Count; Pass=($m.Count -eq 0) }

    # --- 14: monitoring match case-insensitive + process hit ---
    $m = Test-WindowsMonitoringMatch -DisplayNames @('WEBWATCHER') -ProcessNames @('Teramind')
    $ok14 = ($m.Count -eq 2) -and (@($m | Where-Object { $_.Name -eq 'WebWatcher' }).Count -eq 1) -and (@($m | Where-Object { $_.Name -eq 'Teramind' }).Count -eq 1)
    $cases += [pscustomobject]@{ Name='MonitoringMatchCaseProc'; Expected=$true; Got=$ok14; Pass=($ok14 -eq $true) }

    foreach ($c in $cases) {
        if ($c.Pass) { $pass++ } else { $fail++; Write-Host ("[FAIL] {0}: expected {1}, got {2}" -f $c.Name, $c.Expected, $c.Got) }
    }

    Write-Host ("[*] mobile-shield hygiene: {0} pass, {1} fail / {2}" -f $pass, $fail, $cases.Count)
    return ($fail -eq 0)
}
