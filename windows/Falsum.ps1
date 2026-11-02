<#
.SYNOPSIS
    Falsum launcher — the front door. (Working title; rename on Gregg's word.)

.DESCRIPTION
    Main menu for the free, Windows-native, transparent security and
    forensics workstation. Lists every module in plain language, dot-sources
    module functions, runs guided workflows, shows vault status and the
    value ledger. Admin-gated features fail with a clean message instead of
    crashing.

    Windows 11 / PowerShell 5.1 compatible. Zero external dependencies.
    Usage: right-click > Run with PowerShell, or:
        powershell -ExecutionPolicy Bypass -File Falsum.ps1

.NOTES
    The Better-Way Law: every detection ships its fix. The launcher's job is
    to route to the right module, never to fake one.

    Hardening 2026-10-30: admin result cached; option 26 relaunches elevated;
    packet-witness analyzers work on the last stopped capture (no more lost
    analysis); vuln menu actually applies per-finding Repair-* fixes via the
    finding's own FixCommand (was: printed guidance only, and used the
    nonexistent .Name field instead of .Title); trap menu rebuilt around the
    real blocker API (Block-TrapTopOffenders / New-TrapBlock -IpAddress /
    Get-TrapBlocked / Remove-TrapBlock / Export-TrapReport — was: called
    New-TrapBlock with no args, which always failed); menu site count 154.

    Hardening v1.1 (launcher rotation pass, 2026-10-30 ~06:24 MDT):
    sweep step count corrected (34, was stale "20"); breach workflow no-arg
    New-RotationChecklist call FIXED (it gained a mandatory -ExposedAccounts
    param — the launcher used to prompt the user into a wall); menu choices
    retry twice on bad input instead of dropping to the menu; module health
    now verifies spot functions per module (loaded != working); OSINT
    workflow logs to the repo vault; netscan workflow offers report save +
    port-closure plan; PHP workflow feeds webshell scan, web bindings, and
    mitigation verification into the report; new option 18 runs every
    module's offline self-test battery in one pass.

    Hardening v1.2 (launcher rotation pass, 2026-10-30 ~09:35 MDT):
    FIXED a real cross-target bug: entering the OSINT workflow left
    $script:LastOsintReport set from the PREVIOUS target, so the fix plan
    (option 3) and export (option 4) silently acted on the wrong target's
    report — reset at workflow entry. FIXED the self-test false-green:
    option 27 counted any battery that didn't throw as PASSED even when the
    battery printed failures; the boolean verdict each sibling battery
    returns is now honored (fail verdict = FAIL). FIXED stale menu
    references: every "option 17 restarts as Administrator" pointed at the
    photo-scrub menu — the real item is option 26 (banner, vuln menu, trap
    menu x3, header comment). FIXED stale "34-step" sweep text (the sweep
    is 41 steps since v1.2). Spot manifest grows to 258 verified functions
    across 23 modules: every function the launcher's workflows actually call
    is now covered (trap Get-TrapStatus/Get-TrapEvents/New-TrapBlock/...,
    defense Get-EstablishedSession/Get-BadActorList/Import-BadActorList,
    chat Test-ChatSmoke/Clear-ChatProbeCache, mail Get-EmailAddressParts,
    php New-PhpMitigation, bounty Get-BrokerDripSchedule). The value ledger
    view now prints the ship log (the old filter silently dropped it).
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$script:RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:ModuleDir = Join-Path $script:RepoRoot 'modules'
$script:Loaded = @{}
$script:Failed = @{}

# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

$script:IsAdmin = $null

function Test-LauncherAdmin {
    if ($null -eq $script:IsAdmin) {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        $script:IsAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    return $script:IsAdmin
}

function Start-FalsumElevated {
    # Relaunches THIS script in an elevated PowerShell window.
    # Plain-language path to admin for users who don't know
    # right-click > Run as administrator. The elevated window stays open.
    $scriptPath = Join-Path $script:RepoRoot 'Falsum.ps1'
    if (-not (Test-Path $scriptPath)) {
        Write-Host ("Cannot find {0}" -f $scriptPath) -ForegroundColor Red
        return
    }
    Write-Host "Requesting elevation — accept the UAC prompt..." -ForegroundColor Yellow
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', ('"' + $scriptPath + '"')
        ) | Out-Null
        Write-Host "Elevated window launched. You can close this one." -ForegroundColor Green
    } catch {
        Write-Host ("Elevation failed or was denied: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
}

function Import-LauncherModule {
    param(
        [Parameter(Mandatory=$true)][string]$DirName,
        [Parameter(Mandatory=$true)][string]$FileName
    )
    $key = $DirName
    if ($script:Loaded.ContainsKey($key) -or $script:Failed.ContainsKey($key)) {
        return $script:Loaded.ContainsKey($key)
    }
    $path = Join-Path (Join-Path $script:ModuleDir $DirName) $FileName
    if (-not (Test-Path $path)) {
        $script:Failed[$key] = "file missing: $path"
        return $false
    }
    try {
        . $path
        $script:Loaded[$key] = $path
        return $true
    } catch {
        $script:Failed[$key] = $_.Exception.Message
        return $false
    }
}

# Spot functions each module must expose after import. A module that
# dot-sources but silently drops a function (bad edit, truncated file) used
# to read "loaded" here — the menu then failed mid-workflow instead.
$script:ModuleFiles = @{
    '00-coherence-core'   = 'Falsum-Coherence.ps1'
    '01-evidence-sweep'   = 'Falsum-Sweep.ps1'
    '02-packet-witness'   = 'Falsum-PacketWitness.ps1'
    '03-netscan'          = 'Falsum-NetScan.ps1'
    '04-osint-attribution'= 'Falsum-Osint.ps1'
    '05-people-track'     = 'Falsum-PeopleTrack.ps1'
    '06-vuln-check'       = 'Falsum-VulnCheck.ps1'
    '07-php-shield'       = 'Falsum-PhpShield.ps1'
    '08-breach-cleaner'   = 'Falsum-BreachClean.ps1'
    '09-broker-eradicator'= 'Falsum-BrokerEradicator.ps1'
    '10-trap-network'     = 'Falsum-Traps.ps1'
    '11-active-defense'   = 'Falsum-ActiveDefense.ps1'
    '12-timeline-vault'   = 'Falsum-Vault.ps1'
    '13-native-chat'      = 'Falsum-Chat.ps1'
    '14-bugbounty'        = 'Falsum-BugBounty.ps1'
    '15-web-proxy'          = 'Falsum-WebProxy.ps1'
    '16-mail-shield'        = 'Falsum-MailShield.ps1'
    '17-photo-scrub'        = 'Falsum-PhotoScrub.ps1'
    '18-scam-shield'        = 'Falsum-ScamShield.ps1'
    '19-wifi-router'        = 'Falsum-WifiRouter.ps1'
    '20-backup-shield'      = 'Falsum-BackupShield.ps1'
    '21-malware-hunter'     = 'Falsum-MalwareHunter.ps1'
    '22-tracker-block'      = 'Falsum-TrackerBlock.ps1'
    '23-fraud-pack'         = 'Falsum-FraudPack.ps1'
    '24-mobile-shield'      = 'Falsum-MobileShield.ps1'
    '25-purge'              = 'Falsum-Purge.ps1'
    '26-defender-watch'     = 'Falsum-DefenderWatch.ps1'
    '27-memory-forensics'   = 'Falsum-MemoryForensics.ps1'
    '28-task-killer'        = 'Falsum-TaskKiller.ps1'
    '29-registry-fix'       = 'Falsum-RegistryFix.ps1'
    '30-bridge'             = 'Falsum-Bridge.ps1'
    '31-gate'               = 'Falsum-Gate.ps1'
    '32-port-control'       = 'Falsum-PortControl.ps1'
    '33-command-center'     = 'Falsum-CommandCenter.ps1'
}
$script:SpotFunctions = @{
    '00-coherence-core'    = @('New-EvidenceItem','Test-Coherence','New-Receipt','Test-ReceiptChain','Test-CoherenceHygiene','Get-FileMagicTable','Get-MagicTypeTable','Get-TrustedCaKeywordTable','Get-KLDivergence','Measure-EIUAE','Test-EIUAE')
    '00-unified-core'        = @('New-UnifiedSession','Add-SessionEvidence','Get-SessionEvidence','Send-CrossModuleAlert','Get-UnifiedThreatPicture','Invoke-UnifiedScan','Close-UnifiedSession','Test-UnifiedCoreHygiene','Write-FalsumLog')
    '02-packet-witness'    = @('Start-Capture','Stop-Capture','Get-DnsQueries','Get-TlsSnis','Get-FlowSummary','Get-DnsTunnelSignals','Get-BeaconingFlows','Get-SniDnsMismatch','Test-PacketWitnessHygiene','Export-PacketWitnessReport','ConvertTo-EndpointParts','Get-DoHSuspectFlows','Get-PacketWitnessFixPlan')
    '03-netscan'           = @('Start-NetScan','Start-NetScanParallel','Expand-PortSpec','Save-NetScanReport','New-PortClosurePlan','Test-NetScanHygiene','Confirm-PortClosed','ConvertTo-ClosureVerdict','Test-DriftKeyVerdict')
    '04-osint-attribution' = @('Get-AttributionReport','Get-RdapIp','Get-CrtSh','Get-AsnInfo','Get-UrlhausHost','Get-MailAuthRecords','Test-OsintHygiene','New-SelfExposureFixPlan','Export-AttributionReport','Test-TakeoverNameSkip','ConvertTo-OsintUtcDate','Get-HttpEdgeHint')
    '05-people-track'      = @('Invoke-PeopleTrack','Get-Dossier','Test-Username','Test-SiteTableValidation','Test-PeopleTrackHygiene','Export-Dossier','Compare-Dossier','Test-LoginRedirectUrl')
    '06-vuln-check'        = @('New-VulnReport','Export-VulnReport','Get-WindowsUpdateStatus','Test-WeakConfigs','Repair-Smb1Disable','Repair-LlmnrDisable','Test-VulnCheckHygiene','Test-AsrRules','Repair-EnableAsrRules','Test-SystemExploitProtection','Repair-EnableSystemExploitProtection','Test-ByovdDrivers','Repair-ByovdDriverDisable','Test-LocalAdminCensus','Test-LocalPasswordRisk','Get-TpmStatus','Test-AutoLogon','Test-WDigest','Test-RemoteUacBypass','Test-AnonymousEnumeration','Test-CachedLogonsCount','Test-ScreenLock','Test-DefenderExclusions','Test-PrivilegedGroupCensus','Test-AutoLogonVerdict','Test-WDigestVerdict','Test-RemoteUacVerdict','Test-AnonymousVerdict','Test-CachedLogonsVerdict','Test-ScreenLockVerdict','Test-DefenderExclusionRisk','Test-DefenderChannelExclusionRisk','Test-BitLockerStatusVerdict','Test-PrivilegedGroupVerdict','Repair-DisableAutoLogon','Repair-DisableWDigest','Repair-RestoreRemoteUac','Repair-HardenAnonymousAccess','Repair-ReduceCachedLogons','Repair-EnableScreenLock','Repair-RemoveDefenderExclusion')
    '07-php-shield'        = @('Test-PhpInstalls','New-PhpShieldReport','Export-PhpShieldReport','New-PhpMitigation','Test-PhpMitigation','Get-PhpWebBindings','Get-ApachePhpBindings','Get-PhpFpmProcesses','Get-PhpRecentlyChangedFiles','Find-PhpSuspiciousFiles','Invoke-PhpProbe','Test-PhpShieldHygiene','New-ApacheWafRuleText','Add-ApacheWafRule','Add-IisWafRule','New-PhpCgiWafRuleText','New-PhpCgiIisWafRuleText','Merge-IisDenyQueryStringSequences','Add-PhpCgiWafRule','Add-PhpCgiIisWafRule','Test-PhpShieldMarkerPresent','Get-PhpFpmPoolOverrides','Test-FpmPoolOverrideVerdict','Test-PhpMemoryExposureRisk')
    '08-breach-cleaner'    = @('Get-BreachReportForEmail','Start-BreachSweep','Test-PasswordPwned','New-RotationChecklist','Test-BreachCleanHygiene','Test-BreachSeverity','Get-BreachExposureProfile','Set-HibpKeyFileSecure','Test-HibpKeyFileAcl','ConvertTo-BreachCheckResults','Get-BreachSummaryForEmail','Test-HibpPaceDue','Start-HibpPace')
    '09-broker-eradicator' = @('Start-OptOutRun','Get-BrokerRunSummary','Get-BrokerRelistCheck','New-BrokerMonthlyTask','Get-BrokerCoverage','Confirm-BrokerRemoval','Get-BrokerBrokenLinks','Get-BrokerNextAction','Get-BrokerDripSchedule','New-OptOutMailLetter','Test-BrokerUrlVerdict','Test-BrokerNameMatch')
    '10-trap-network'      = @('Start-TrapListener','Stop-TrapListener','Get-TrapStatus','Get-TrapEvents','Block-TrapTopOffenders','New-TrapBlock','Get-TrapBlocked','Remove-TrapBlock','Get-TrapOffenderSummary','Sync-TrapBlocksToBadActors','Test-TrapHygiene','Test-TrapPayloadPattern','Get-TrapAttackPatterns','Export-TrapReport','Clear-OldTrapLogs','Import-TrapBlockRules','ConvertFrom-NetshRuleOutput')
    '11-active-defense'    = @('Start-Backtrace','Get-EstablishedSession','Stop-HostileSession','New-AbusePack','Add-BadActor','Get-BadActorList','Get-HostileSessionReport','Sync-FirewallBlockRules','Import-BadActorList','Test-ActiveDefenseHygiene','Get-SuspiciousPortTable','ConvertTo-DefenseIpTarget','Get-DefenseOutDir','Get-BacktracePortTable','Confirm-ProcessTerminated','Confirm-SessionClosed','Test-DeskKeyMatch','Test-AuthenticodeVerdict')
    '12-timeline-vault'    = @('New-Vault','Add-VaultEntry','Verify-Vault','Get-VaultTip','Export-EvidencePack','New-VaultCheckpoint','Test-VaultCheckpoint','Test-VaultHygiene','Read-VaultEntries','Clear-VaultTornTail','Test-VaultTimestampFormat','Test-CheckpointFreshness','Write-VaultFileAtomic','Test-VaultChainFromLines')
    '13-native-chat'       = @('Send-ChatPrompt','Get-ModelStatus','Install-NativeModel','Test-ChatSmoke','Test-ChatHygiene','Save-ChatSession','Export-ChatTranscript','Test-InjectionShapedText','Test-ChatEndpointIsLoopback','New-ChatCompactionReceipt','Get-ChatBestEndpoint','ConvertFrom-SseChunk','Test-ValidIpv4Octets','Clear-ChatProbeCache','Set-ChatBestEndpoint','Get-ChatEndpointList','Start-NativeModelServer','Stop-NativeModelServer','Get-NativeModelFiles','Find-NativeModelServerExe','New-NativeServerArgList','Test-NativeModelServerRunning')
    '14-bugbounty'         = @('Get-BountyPrograms','Register-BountyTarget','Test-BountyScopeRegistered','Start-BountyRecon','New-BountyReport','Get-BountySummary','Test-BountyHygiene','Get-BountyDanglingFingerprintTable','Test-CnameDanglingPattern','Test-BountyScopeFreshness','Test-BountyCandidateNew','Request-BountyActiveTestGate','Update-BountyScopeRecord','ConvertFrom-BountyCtRowsDetailed','Test-BountyCertStatus','Get-BountyHostDisposition','Invoke-BountyCtHostQuery')
    '15-web-proxy'           = @('New-ProxyCa','Remove-ProxyCa','Get-ProxyCaStatus','Start-WebProxy','Stop-WebProxy','Get-ProxyHistory','Export-ProxyLog','Send-RepeaterRequest','Add-ProxyScope','Test-ProxyScope','Test-ProxyHygiene','Set-SystemProxy','Clear-SystemProxy','Get-ProxyFlowSummary','Remove-ProxyHostCerts','Test-JobFlowScope','Test-ProxyScopePattern','ConvertTo-ConnectTarget','Test-ChunkedSizeLine','Read-ChunkedHttpBody','Test-ExpectContinueHeader','Get-MitmTlsProtocols')
    '16-mail-shield'         = @('Import-EmlFile','Get-EmailVerdict','Test-PhishingSignals','New-PhishReportPack','Test-MailShieldHygiene','Test-LevenshteinDistance','ConvertFrom-Rfc2047EncodedWord','Test-DomainLookalikeDistance','ConvertFrom-AuthResultsLine','Test-ReceivedChainAnomaly','Split-MimeParts','Add-PhishSenderBlocklist','Test-PhishSenderBlocklist','Get-MailShieldOutDir','Get-EmailAddressParts')
    '17-photo-scrub'         = @('Get-PhotoMetadata','Get-PhotoRisk','Clear-PhotoMetadata','Clear-PngMetadata','Get-GpsDecimal','Get-TiffMeta','Get-Crc32','Test-PhotoScrubHygiene')
    '18-scam-shield'         = @('Get-ScamChecklist','Start-ScamCheck','Test-PaymentRedFlag','Get-PaymentRiskScore','Test-ScamUrgency','Get-ScamLinksFromText','Start-ScamMessageTriage','ConvertTo-ScamLevel','New-ScamReportPack','Test-ScamShieldHygiene')
    '19-wifi-router'         = @('Start-WifiRouterAudit','Get-WifiVisible','Get-WifiRisk','Remove-WifiProfile','Test-RouterPorts','Test-RouterUpnp','Get-RouterHardeningChecklist','Test-WifiRouterHygiene','Get-WifiEvilTwinCandidates','Test-SavedProfileVerdict','Get-WifiSavedProfileRisk','Test-DnsServerVerdict','Get-RouterFingerprint','Test-MacRandomization')
    '20-backup-shield'       = @('New-BackupPlan','Start-Backup','Test-BackupIntegrity','Start-RestoreDrill','Get-RansomwarePlaybook','Test-BackupShieldHygiene','Test-BackupPathOverlap','Test-BackupSpaceVerdict','Test-BackupDiskSpace','Get-BackupSourceSize','New-BackupScheduledTask','Remove-BackupScheduledTask','Get-BackupScheduledTask','Import-VaultModule','New-BackupVaultLog')
    '21-malware-hunter'      = @('Start-MalwareHunt','Get-AutostartAnomalies','Get-ProcessAnomalies','Get-SuspiciousServices','Get-PUPList','Stop-MalwareProcess','Test-MalwareHunterHygiene','Test-HunterScoreVerdict','Test-SuspiciousCommandLine','Test-HunterPathVerdict','Get-ScheduledTaskPersistence','Get-WmiEventPersistence','Remove-AutostartEntry','Get-QuarantineList','Restore-QuarantinedFile','Get-FileEvidenceHash','Export-MalwareHuntReport')
    '22-tracker-block'       = @('Get-TrackerBlocks','Add-TrackerBlock','Remove-TrackerBlock','Clear-TrackerBlocks','Import-BlockList','Install-StarterBlocks','Test-TrackerBlockHygiene','Test-HostsMarkers','Restore-HostsBackup','Test-TrackerBlockHealth','Clear-OldHostsBackups')
    '23-fraud-pack'          = @('Get-FraudChecklist','New-FraudPack','Add-FraudTimelineEntry','Get-FraudTimeline','Compress-FraudPack','Test-FraudPackIntegrity','New-FraudManifest','Test-FraudDateFormat','Get-FraudPackOutDir','Get-IdentityTheftLockdown','Test-FraudPackHygiene')
    '24-mobile-shield'       = @('Get-StalkerwarePackageTable','Get-StalkerwareC2Table','Test-StalkerwareTableFresh','Find-PhoneBackups','Test-BackupEncrypted','Invoke-BackupStalkerwareScan','Get-WindowsPrivacyAudit','Repair-WindowsPrivacy','Test-DnsForStalkerwareC2','Get-DnsClientCacheDomains','Get-WindowsMonitoringSoftwareTable','Test-WindowsMonitoringMatch','Find-WindowsMonitoringSoftware','Test-MobileShieldHygiene')
    '25-purge'               = @('Get-BinaryAttribution','Test-BinaryIsUnattributed','Test-PurgePathProtected','Find-UnattributedBinaries','Find-RegistryAutoStartBinaries','Remove-UnattributedBinary','Invoke-PurgeScan','Get-PurgeLog','Test-PurgeHygiene')
    '26-defender-watch'        = @('Get-DefenderStatus','Get-DefenderEventLogEntries','Get-DefenderScans','Get-DefenderDetections','Get-DefenderQuarantine','Get-DefenderExclusions','Get-DefenderExclusionChanges','Get-DefenderProtectionToggles','Invoke-DefenderWatch','Test-DefenderWatchHygiene')
    '27-memory-forensics'      = @('Get-ProcessTree','Get-ProcessModules','Find-UnsignedModules','Find-OrphanProcesses','Find-SuspiciousPaths','Get-ProcessMemorySummary','Get-ProcessDetails','Invoke-MemoryForensics','Test-MemoryForensicsHygiene')
    '28-task-killer'           = @('Get-BackgroundTasks','Get-TaskKillList','Test-ProcessIsSystemCritical','Test-ProcessIsKillCandidate','Stop-BackgroundTask','Invoke-TaskKillerAudit','Invoke-TaskKillerEnforce','Test-TaskKillerHygiene')
    '29-registry-fix'          = @('Find-BadRegistryEntries','Remove-BadRegistryEntry','Invoke-RegistryFixScan','Backup-RegistryKey','Test-RegistryFixHygiene')
    '30-bridge'                = @('Initialize-Bridge','Send-ToExtension','Receive-FromExtension','Send-ToDesktop','Receive-FromDesktop')
    '31-gate'                  = @('Get-ScheduledTasks','Get-NewScheduledTasks','Get-AutoStartServices','Get-RegistryAutoStarts','Get-WmiEventConsumers','Get-StartupFolderItems','Invoke-GateAudit','Test-GateHygiene')
    '32-port-control'          = @('Get-ListeningPorts','Block-TcpPort','Unblock-TcpPort','Get-FalsumPortRules','Invoke-PortControlWorkflow','Test-PortControlHygiene')
    '33-command-center'        = @('Get-FileBrowser','Get-ProcessManager','Stop-ProcessSafely','Get-NetworkDashboard','Get-ConnectionViewer','Test-NetworkHost','Get-SystemDashboard','Get-ServiceManager','Get-DiskHealth','Test-CommandCenterHygiene')
}

function Get-LauncherModuleHealth {
    $rows = @()
    foreach ($key in $script:ModuleFiles.Keys | Sort-Object) {
        if ($key -eq '01-evidence-sweep') {
            # The sweep auto-executes on dot-source — never import it here.
            $path = Join-Path (Join-Path $script:ModuleDir $key) $script:ModuleFiles[$key]
            $status = if (Test-Path $path) { 'parse-only (auto-executes; never dot-sourced)' } else { 'FAILED: file missing' }
            $rows += [pscustomobject]@{ Module = $key; Status = $status }
            continue
        }
        $ok = Import-LauncherModule -DirName $key -FileName $script:ModuleFiles[$key]
        if (-not $ok) {
            $rows += [pscustomobject]@{ Module = $key; Status = ('FAILED: ' + $script:Failed[$key]) }
            continue
        }
        $want = $script:SpotFunctions[$key]
        $missing = @($want | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) })
        if ($missing.Count -eq 0) {
            $rows += [pscustomobject]@{ Module = $key; Status = ("loaded ({0}/{0} spot functions)" -f $want.Count) }
        } else {
            $rows += [pscustomobject]@{ Module = $key; Status = ('LOADED BUT BROKEN, missing: ' + ($missing -join ', ')) }
        }
    }
    return $rows
}

function Read-MenuChoice {
    param([string]$Prompt = 'Select', [string[]]$Valid = @())
    # Retries twice on bad input (a single fat-finger used to dump the user
    # back to the menu and lose the whole submenu context).
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $choice = Read-Host $Prompt
        if ($null -eq $choice) { $choice = '' }
        $choice = $choice.Trim()
        if ($Valid.Count -eq 0 -or ($Valid -contains $choice)) { return $choice }
        if ($attempt -lt 3) {
            Write-Host ("Not a valid choice: '{0}'. Try again ({1} left)." -f $choice, (3 - $attempt)) -ForegroundColor Yellow
        } else {
            Write-Host "Too many bad choices — heading back to the menu." -ForegroundColor Yellow
        }
    }
    return $null
}

function Invoke-SafeAction {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$Action
    )
    Write-Host ""
    Write-Host "--- $Name ---" -ForegroundColor Cyan
    try {
        & $Action
    } catch {
        Write-Host "Error in '$Name': $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    Read-Host "Press Enter to return to the menu" | Out-Null
}

# ---------------------------------------------------------------------------
# Vault status + value ledger
# ---------------------------------------------------------------------------

function Show-VaultStatus {
    if (-not (Import-LauncherModule -DirName '12-timeline-vault' -FileName 'Falsum-Vault.ps1')) {
        Write-Host 'Vault module failed to load.' -ForegroundColor Red; return
    }
    $vaultPath = Join-Path $script:RepoRoot 'vault'
    if (-not (Test-Path $vaultPath)) {
        Write-Host "No vault yet at $vaultPath. Run an evidence sweep or any module action to create one." -ForegroundColor Yellow
        return
    }
    $vault = New-Vault -path $vaultPath
    $tip = Get-VaultTip -vault $vault
    if ($tip) {
        $count = @(Get-Content (Join-Path $vaultPath 'ledger.jsonl')).Count
        Write-Host ("Vault entries : {0}" -f $count)
        Write-Host ("Tip seq       : {0}" -f $tip.seq)
        Write-Host ("Tip time      : {0}" -f $tip.utc)
        if ($tip.sha384) {
            Write-Host ("Tip hash      : {0}..." -f $tip.sha384.Substring(0, [Math]::Min(24, $tip.sha384.Length)))
        }
        Write-Host ""
        Write-Host "Verifying chain..."
        $ok = Verify-Vault -vault $vault
        if ($ok.valid) {
            Write-Host ("Chain: VALID ({0} entries)" -f $ok.entries) -ForegroundColor Green
        } else {
            # Was: if ($ok) — always true, because Verify-Vault returns an
            # object. The vault could have reported BROKEN as VALID forever.
            Write-Host ("Chain: INVALID — {0}" -f $ok.reason) -ForegroundColor Red
            if ($ok.reason -match 'corrupt ledger line|Unparseable') {
                $yn = Read-Host "Looks like a torn tail (crash mid-append). Repair it now? (y/N)"
                if ($yn -eq 'y') {
                    try {
                        $r = Clear-VaultTornTail -vault $vault -Confirm:$false
                        if ($r.repaired) { Write-Host ("Repaired: removed {0} line(s). Backup: {1}" -f $r.removedLines, $r.backupPath) -ForegroundColor Green }
                        else { Write-Host ("No repair: {0}" -f $r.reason) -ForegroundColor Yellow }
                    } catch { Write-Host ("Repair failed: {0}" -f $_.Exception.Message) -ForegroundColor Red }
                }
            } else {
                Write-Host "Restore from an evidence pack (option 2 in the evidence-pack workflow) — the chain alone cannot repair this." -ForegroundColor Yellow
            }
        }
        $cpPath = Join-Path $vaultPath 'CHECKPOINT.json'
        if (Test-Path $cpPath) {
            $cp = Test-VaultCheckpoint -vault $vault -checkpointPath $cpPath
            if ($cp.valid) {
                if ($cp.checkpointStale) {
                    Write-Host ("Checkpoint: VALID but STALE ({0} entries since checkpoint — re-run checkpoint)" -f $cp.entriesSinceCheckpoint) -ForegroundColor Yellow
                } else {
                    Write-Host ("Checkpoint: VALID (seq {0}, tip {1})" -f $cp.checkpointSeq, $cp.currentSeq) -ForegroundColor Green
                }
            } else {
                Write-Host ("Checkpoint: {0}" -f $cp.reason) -ForegroundColor Red
            }
        }
    } else {
        Write-Host "Vault directory exists but is empty." -ForegroundColor Yellow
    }
}

function Show-ValueLedger {
    $path = Join-Path $script:RepoRoot 'VALUE-LEDGER.md'
    if (-not (Test-Path $path)) { Write-Host "VALUE-LEDGER.md not found." -ForegroundColor Red; return }
    $lines = Get-Content $path
    # Show the summary table, the totals, and the ship log. The old filter
    # printed every ## header but skipped the ship-log bullets entirely —
    # the evidence that the modules actually shipped never appeared.
    $inShipLog = $false
    foreach ($line in $lines) {
        if ($line -match '^\s*##\s+Module ship log') {
            $inShipLog = $true
            Write-Host $line -ForegroundColor Cyan
            continue
        }
        if ($line -match '^\s*##\s') {
            $inShipLog = $false
            Write-Host $line -ForegroundColor Cyan
            continue
        }
        if ($line -match '^\s*#') { $inShipLog = $false; continue }
        if ($inShipLog) {
            if ($line -match '^\s*-') { Write-Host $line }
            continue
        }
        if ($line -match '^\s*\|') { Write-Host $line; continue }
        if ($line -match 'replaced|value|free|\$|users x') {
            Write-Host $line
        }
    }
    Write-Host ""
    Write-Host "(Full ledger: VALUE-LEDGER.md in the repo folder)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Module workflows
# ---------------------------------------------------------------------------

function Invoke-EvidenceSweepWorkflow {
    $sweep = Join-Path (Join-Path $script:ModuleDir '01-evidence-sweep') 'Falsum-Sweep.ps1'
    while ($true) {
        Write-Host ""
        Write-Host "Evidence sweep (44 steps, collection only)" -ForegroundColor Cyan
        Write-Host "  1) Collect evidence (new 44-step sweep)"
        Write-Host "  2) Verify a prior sweep directory (tamper check)"
        Write-Host "  3) Self-test battery (offline, no collection)"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' {
                Write-Host "Running the 44-step evidence sweep..."
                Write-Host "(Collection only. Nothing is modified on this machine.)" -ForegroundColor DarkGray
                try { & $sweep } catch { Write-Host "Sweep failed: $($_.Exception.Message)" -ForegroundColor Red }
            }
            '2' {
                $dir = Read-Host "Sweep directory to verify"
                if ([string]::IsNullOrWhiteSpace($dir)) { Write-Host "No directory given." -ForegroundColor Yellow; break }
                $h = Read-Host "Expected MANIFEST.csv hash (Enter to use the in-dir receipt only)"
                try {
                    if ([string]::IsNullOrWhiteSpace($h)) { & $sweep -Verify -VerifyDir $dir }
                    else { & $sweep -Verify -VerifyDir $dir -ExpectedHash $h }
                } catch { Write-Host "Verify failed: $($_.Exception.Message)" -ForegroundColor Red }
            }
            '3' {
                try { & $sweep -TestHygiene } catch { Write-Host "Self-test failed: $($_.Exception.Message)" -ForegroundColor Red }
            }
        }
    }
}

function Get-PacketCaptureForAnalysis {
    # Analyzers work on the active capture, or the most recent stopped one —
    # stopping used to throw the analysis away, which is the wrong default.
    if ($script:Capture)     { return $script:Capture }
    if ($script:LastCapture) { return $script:LastCapture }
    Write-Host "No capture yet — start one first (option 1)." -ForegroundColor Yellow
    return $null
}

function Invoke-PacketWitnessMenu {
    if (-not (Import-LauncherModule -DirName '02-packet-witness' -FileName 'Falsum-PacketWitness.ps1')) {
        Write-Host 'Packet witness module failed to load.' -ForegroundColor Red; return
    }
    $script:Capture = $null
    $script:LastCapture = $null
    while ($true) {
        Write-Host ""
        Write-Host "Packet witness" -ForegroundColor Cyan
        if ($script:Capture) {
            Write-Host ("  Active capture: {0}" -f $script:Capture.etlPath) -ForegroundColor DarkGray
        } elseif ($script:LastCapture) {
            Write-Host ("  Last capture (stopped, still analyzable): {0}" -f $script:LastCapture.etlPath) -ForegroundColor DarkGray
        }
        Write-Host "  1) Start capture (admin)"
        Write-Host "  2) Stop capture"
        Write-Host "  3) Show DNS queries (active or last capture)"
        Write-Host "  4) Show TLS SNI hostnames (active or last capture)"
        Write-Host "  5) Show flow summary, bytes per connection (active or last capture)"
        Write-Host "  6) DNS tunnel/exfil signals (active or last capture)"
        Write-Host "  7) Beaconing / periodic flows (active or last capture)"
        Write-Host "  8) SNI hostnames never seen in DNS (active or last capture)"
        Write-Host "  9) Full report (JSON + txt, hashed)"
        Write-Host "  10) DNS-over-HTTPS suspect flows (active or last capture)"
        Write-Host "  11) Fix plan for a flagged IP (copy-paste commands)"
        Write-Host "  12) Self-test battery (offline, no admin)"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','6','7','8','9','10','11','12','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' {
                if (-not (Test-LauncherAdmin)) {
                    Write-Host "Packet capture needs an elevated (Run as Administrator) PowerShell window." -ForegroundColor Yellow
                    break
                }
                $dir = Read-Host "Output directory [Desktop\Falsum-Captures]"
                if ([string]::IsNullOrWhiteSpace($dir)) {
                    $dir = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Falsum-Captures'
                }
                $filter = Read-Host "pktmon filter (optional, Enter for none)"
                try {
                    if ([string]::IsNullOrWhiteSpace($filter)) { $script:Capture = Start-Capture -OutDir $dir }
                    else { $script:Capture = Start-Capture -OutDir $dir -Filter $filter }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '2' {
                if (-not $script:Capture) { Write-Host "No capture running." -ForegroundColor Yellow; break }
                try {
                    Stop-Capture -Capture $script:Capture
                    $script:LastCapture = $script:Capture
                    $script:Capture = $null
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '3' {
                $cap = Get-PacketCaptureForAnalysis
                if (-not $cap) { break }
                try { Get-DnsQueries -TxtPath $cap.txtPath | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '4' {
                $cap = Get-PacketCaptureForAnalysis
                if (-not $cap) { break }
                try { Get-TlsSnis -TxtPath $cap.txtPath | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '5' {
                $cap = Get-PacketCaptureForAnalysis
                if (-not $cap) { break }
                try { Get-FlowSummary -TxtPath $cap.txtPath | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '6' {
                $cap = Get-PacketCaptureForAnalysis
                if (-not $cap) { break }
                try { Get-DnsTunnelSignals -TxtPath $cap.txtPath | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '7' {
                $cap = Get-PacketCaptureForAnalysis
                if (-not $cap) { break }
                try { Get-BeaconingFlows -TxtPath $cap.txtPath | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '8' {
                $cap = Get-PacketCaptureForAnalysis
                if (-not $cap) { break }
                try { Get-SniDnsMismatch -TxtPath $cap.txtPath | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '9' {
                $cap = Get-PacketCaptureForAnalysis
                if (-not $cap) { break }
                $dir = Read-Host "Report output directory [Desktop\Falsum-Reports]"
                if ([string]::IsNullOrWhiteSpace($dir)) {
                    $dir = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Falsum-Reports'
                }
                try { Export-PacketWitnessReport -TxtPath $cap.txtPath -OutDir $dir | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '10' {
                $cap = Get-PacketCaptureForAnalysis
                if (-not $cap) { break }
                try {
                    $flows = Get-FlowSummary -TxtPath $cap.txtPath
                    Get-DoHSuspectFlows -Flows $flows -TxtPath $cap.txtPath | Format-Table -AutoSize | Out-Host
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '11' {
                $ip = Read-Host "Flagged IP to build the fix plan for"
                if ([string]::IsNullOrWhiteSpace($ip)) { Write-Host "No IP given." -ForegroundColor Yellow; break }
                try { Get-PacketWitnessFixPlan -BlockIp $ip.Trim() | Format-Table order, title, needsAdmin -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
                Write-Host "(Full commands print with: Get-PacketWitnessFixPlan -BlockIp '$($ip.Trim())' | Format-List *)" -ForegroundColor DarkGray
            }
            '12' {
                try { Test-PacketWitnessHygiene | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
        }
    }
}

function Invoke-NetScanWorkflow {
    if (-not (Import-LauncherModule -DirName '03-netscan' -FileName 'Falsum-NetScan.ps1')) {
        Write-Host 'Net scan module failed to load.' -ForegroundColor Red; return
    }
    $target = Read-Host "Target (IP, hostname, CIDR like 192.168.1.0/24, or 'localhost')"
    if ([string]::IsNullOrWhiteSpace($target)) { return }
    $ports = Read-Host "Ports [common]"
    if ([string]::IsNullOrWhiteSpace($ports)) { $ports = 'common' }
    try {
        # Validate the port spec up front: a typo used to kill the scan
        # mid-run. Expand-PortSpec throws with a clean message.
        $expanded = Expand-PortSpec -Spec $ports
        Write-Host ("Ports: {0} (from '{1}')" -f $expanded.Count, $ports) -ForegroundColor DarkGray
    } catch {
        Write-Host "Bad port spec: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    $banner = Read-Host "Grab banners? (y/n) [y]"
    $b = ($banner -ne 'n')
    try {
        if ($b) { $results = @(Start-NetScan -Targets $target -Ports $expanded -Banners) }
        else    { $results = @(Start-NetScan -Targets $target -Ports $expanded) }
        $save = Read-Host "Save the scan report (JSON + txt, hashed)? (y/n) [y]"
        if ($save -ne 'n') {
            $dir = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Falsum-Reports'
            Save-NetScanReport -Results $results -OutDir $dir -PortSpecLabel $ports -TargetLabel $target -PortsScanned $expanded
        }
        $planRows = @()
        $plan = Read-Host "Build a port-closure plan for open ports? (y/n) [n]"
        if ($plan -eq 'y') { $planRows = @(New-PortClosurePlan -Results $results) }
        if ($planRows.Count -gt 0) {
            $verify = Read-Host "Apply the block rules, then verify closures now? (y/n) [n]"
            if ($verify -eq 'y') {
                foreach ($pr in $planRows) {
                    Confirm-PortClosed -Target $pr.target -Port $pr.port -Protocol $pr.protocol
                }
            }
        }
    } catch {
        Write-Host "Scan failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-OsintWorkflow {
    if (-not (Import-LauncherModule -DirName '04-osint-attribution' -FileName 'Falsum-Osint.ps1')) {
        Write-Host 'OSINT module failed to load.' -ForegroundColor Red; return
    }
    $target = Read-Host "Target (IP address or domain)"
    if ([string]::IsNullOrWhiteSpace($target)) { return }
    # Never act on a previous target's report: options 3 and 4 build the
    # fix plan and the export from this report, so it dies with the
    # workflow instead of silently carrying a stale target's data.
    $script:LastOsintReport = $null
    $vaultPath = Join-Path $script:RepoRoot 'vault'
    while ($true) {
        Write-Host ""
        Write-Host "OSINT attribution for $target" -ForegroundColor Cyan
        Write-Host "  1) Full attribution report (RDAP, ASN, Shodan, DNS, crt.sh, URLhaus, DNSSEC, CAA, mail-auth, takeover, CT delta, HTTP)"
        Write-Host "  2) Mail-auth only (SPF/DMARC/DKIM — the spoofing posture check)"
        Write-Host "  3) Self-exposure fix plan for this target (for assets you own)"
        Write-Host "  4) Export the last full report to JSON/txt + SHA-256"
        Write-Host "  5) Hygiene self-test (offline)"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','0')
        if ($c -eq $null -or $c -eq '0') { break }
        try {
            switch ($c) {
                '1' {
                    # Log every query into the repo vault: attribution without an
                    # evidence trail is exactly what this build exists to kill.
                    $script:LastOsintReport = Get-AttributionReport -Target $target -VaultPath $vaultPath
                }
                '2' {
                    $ma = Get-MailAuthRecords -Domain $target
                    if ($ma.ok) {
                        Write-Host "SPF:   $($ma.spf.verdict) $(if ($ma.spf.provider -ne '') { '(' + $ma.spf.provider + ')' })" -ForegroundColor $(if ($ma.spf.verdict -eq 'dangerous-plusall') { 'Red' } else { 'Gray' })
                        Write-Host "DMARC: $(if ($ma.dmarc.present) { 'p=' + $ma.dmarc.policy } else { 'MISSING' })" -ForegroundColor $(if (-not $ma.dmarc.present) { 'Red' } else { 'Gray' })
                        Write-Host "DKIM:  $(if ($ma.dkimSelectorsFound.Count -gt 0) { 'keys at ' + ($ma.dkimSelectorsFound -join ', ') } else { 'no keys at common selectors' })"
                    }
                }
                '3' {
                    if ($script:LastOsintReport -eq $null) {
                        Write-Host "Run option 1 first — the fix plan is built from the report." -ForegroundColor Yellow
                    } else {
                        $plan = New-SelfExposureFixPlan -Report $script:LastOsintReport
                        foreach ($f in @($plan.findings)) {
                            Write-Host "[$($f.severity)] $($f.title)" -ForegroundColor $(if ($f.severity -eq 'P1') { 'Red' } elseif ($f.severity -eq 'P2') { 'Yellow' } else { 'Gray' })
                            foreach ($s in @($f.steps)) { Write-Host "    - $s" }
                        }
                    }
                }
                '4' {
                    if ($script:LastOsintReport -eq $null) {
                        Write-Host "Run option 1 first — there is no report to export yet." -ForegroundColor Yellow
                    } else {
                        [void](Export-AttributionReport -Report $script:LastOsintReport -OutDir (Join-Path $script:RepoRoot 'reports'))
                    }
                }
                '5' { try { [void](Test-OsintHygiene) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
        } catch {
            Write-Host "OSINT failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Invoke-PeopleTrackWorkflow {
    if (-not (Import-LauncherModule -DirName '05-people-track' -FileName 'Falsum-PeopleTrack.ps1')) {
        Write-Host 'People-track module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "Username exposure check (own handles or authorized ones only)" -ForegroundColor Cyan
        Write-Host "  1) Run full pipeline (scan -> dossier -> export -> remediation plan)"
        Write-Host "  2) Hygiene self-test (offline scoring/validation battery)"
        Write-Host "  3) Site-table coverage"
        Write-Host "  4) Handle variants for a username (suffixes, prefixes, leetspeak)"
        Write-Host "  5) Compare two dossier JSONs (re-scan diff: cleanup proof)"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','0')
        if ($c -eq $null -or $c -eq '0') { return }
        switch ($c) {
            '1' {
                $user = Read-Host "Username to check (e.g. gregg2haynes4)"
                if ([string]::IsNullOrWhiteSpace($user)) { continue }
                $email = Read-Host "Email for breach check (optional, Enter to skip)"
                try {
                    if ([string]::IsNullOrWhiteSpace($email)) { Invoke-PeopleTrack -Username $user }
                    else { Invoke-PeopleTrack -Username $user -Email $email }
                } catch {
                    Write-Host "People-track failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            '2' { try { [void](Test-PeopleTrackHygiene) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '3' {
                $cov = Get-SiteCoverage
                Write-Host ("  {0} sites across {1} categories" -f $cov.Total, $cov.ByCategory.Count)
                foreach ($r in $cov.ByCategory) { Write-Host ("    {0}: {1}" -f $r.Category, $r.Sites) }
            }
            '4' {
                $user = Read-Host "Username"
                if ([string]::IsNullOrWhiteSpace($user)) { continue }
                try {
                    $vars = Get-UsernameVariants -Username $user
                    Write-Host ("  {0} variants: {1}" -f $vars.Count, ($vars -join ", "))
                } catch {
                    Write-Host "Variants failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            '5' {
                $old = Read-Host "Old dossier JSON path"
                $new = Read-Host "New dossier JSON path"
                if ([string]::IsNullOrWhiteSpace($old) -or [string]::IsNullOrWhiteSpace($new)) { continue }
                try { [void](Compare-Dossier -OldPath $old -NewPath $new) } catch {
                    Write-Host "Compare failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
}

function Invoke-VulnMenu {
    if (-not (Import-LauncherModule -DirName '06-vuln-check' -FileName 'Falsum-VulnCheck.ps1')) {
        Write-Host 'Vuln-check module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "Vulnerability check (Better-Way Law: every finding ships its fix)" -ForegroundColor Cyan
        Write-Host "  1) Run full audit (updates, weak configs, exposed services, EOL software)"
        Write-Host "  2) Apply fixes for what the audit found (per-finding confirm, admin)"
        Write-Host "  3) Run the offline self-test (proves the audit's classification logic)"
        Write-Host "  4) Credential & logon posture only (autologon, WDigest, cached logons, screen lock, ...)"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' {
                try { $r = New-VulnReport; Export-VulnReport -Report $r } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '2' {
                if (-not (Test-LauncherAdmin)) {
                    Write-Host "Fixes need an elevated PowerShell window." -ForegroundColor Yellow
                    Write-Host "Use main menu option 26 to restart Falsum as Administrator." -ForegroundColor DarkGray
                    break
                }
                try {
                    $r = New-VulnReport
                    # Findings carry their own FixCommand (the Repair-* function name);
                    # Info entries and guidance-only findings are not offered for fixing.
                    $fixable = @($r.Findings | Where-Object {
                        $_.Severity -ne 'Info' -and -not [string]::IsNullOrWhiteSpace($_.FixCommand)
                    })
                    if ($fixable.Count -eq 0) {
                        Write-Host "Nothing fixable found — audit is clean on everything with an automatic fix." -ForegroundColor Green
                        break
                    }
                    Write-Host ("{0} finding(s) have an automatic fix. Each one asks before it changes anything." -f $fixable.Count) -ForegroundColor Yellow
                    $applied = 0; $skipped = 0
                    foreach ($f in $fixable) {
                        Write-Host ""
                        Write-Host ("[{0}] {1}" -f $f.Severity, $f.Title) -ForegroundColor White
                        Write-Host ("  Why: {0}" -f $f.Evidence) -ForegroundColor DarkGray
                        Write-Host ("  Fix: {0}" -f $f.FixGuidance) -ForegroundColor DarkGray
                        $ans = Read-Host ("Apply this fix ({0})? (y/n) [n]" -f $f.FixCommand)
                        if ($ans -ne 'y') { $skipped++; continue }
                        if (-not (Get-Command -Name $f.FixCommand -ErrorAction SilentlyContinue)) {
                            Write-Host ("Fix command '{0}' is not loaded — skipping." -f $f.FixCommand) -ForegroundColor Red
                            $skipped++; continue
                        }
                        try {
                            & $f.FixCommand
                            $applied++
                        } catch {
                            Write-Host ("Fix failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                        }
                    }
                    Write-Host ""
                    Write-Host ("Fix run complete: {0} applied, {1} skipped." -f $applied, $skipped) -ForegroundColor Green
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '3' {
                try { [void](Test-VulnCheckHygiene) } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '4' {
                # Credential & logon posture mini-audit (v1.4 checks).
                try {
                    $ch = @()
                    $ch += Test-AutoLogon
                    $ch += Test-WDigest
                    $ch += Test-RemoteUacBypass
                    $ch += Test-AnonymousEnumeration
                    $ch += Test-CachedLogonsCount
                    $ch += Test-ScreenLock
                    $ch += Test-DefenderExclusions
                    $ch += Test-PrivilegedGroupCensus
                    $bad = @($ch | Where-Object { $_.Severity -in 'Critical','High','Medium' })
                    Write-Host ""
                    Write-Host ("Credential-hygiene findings: {0} need attention" -f $bad.Count) -ForegroundColor Yellow
                    foreach ($f in $bad) {
                        Write-Host ("  [{0}] {1}" -f $f.Severity, $f.Title) -ForegroundColor White
                        if ($f.FixCommand) { Write-Host ("    Fix: {0}" -f $f.FixCommand) -ForegroundColor DarkGray }
                    }
                    if ($bad.Count -eq 0) { Write-Host "  Clean — nothing to fix." -ForegroundColor Green }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
        }
    }
}

function Invoke-PhpShieldWorkflow {
    if (-not (Import-LauncherModule -DirName '07-php-shield' -FileName 'Falsum-PhpShield.ps1')) {
        Write-Host 'PHP shield module failed to load.' -ForegroundColor Red; return
    }
    Write-Host ""
    Write-Host "  1) Full scan (installs + bindings + live workers + webshell + report)"
    Write-Host "  2) Apply mitigations"
    Write-Host "  3) Verify mitigations"
    Write-Host "  4) Hygiene self-test (offline)"
    $c = Read-Host "Choice [1]"
    if ([string]::IsNullOrWhiteSpace($c)) { $c = '1' }
    switch ($c) {
        '1' { Invoke-PhpShieldFullScan }
        '2' {
            try {
                $root = Read-Host "Web root for WAF rules (Enter to skip docroot rules)"
                $srv = Read-Host "Server type [Apache/IIS/Both]"
                if ([string]::IsNullOrWhiteSpace($srv)) { $srv = 'Both' }
                if ([string]::IsNullOrWhiteSpace($root)) { New-PhpMitigation -ServerType $srv }
                else { New-PhpMitigation -DocRoot $root -ServerType $srv }
                Test-PhpMitigation -DocRoot $root
            } catch { Write-Host "PHP shield failed: $($_.Exception.Message)" -ForegroundColor Red }
        }
        '3' {
            try {
                $root = Read-Host "Web root to verify (Enter for php.ini layer only)"
                Test-PhpMitigation -DocRoot $root
            } catch { Write-Host "PHP shield failed: $($_.Exception.Message)" -ForegroundColor Red }
        }
        '4' {
            try { [void](Test-PhpShieldHygiene) } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
        }
        default { Write-Host 'Unknown choice.' -ForegroundColor Yellow }
    }
}

function Invoke-PhpShieldFullScan {
    try {
        $root = Read-Host "Web root for webshell scan (optional, e.g. C:\inetpub\wwwroot — Enter to skip)"
        $scan = Test-PhpInstalls
        # Web-serving PHP is the PHP that PHP2Shell can reach: bindings first.
        $bindings = Get-PhpWebBindings
        $apache   = Get-ApachePhpBindings
        # A RUNNING php is the one an attacker reaches first.
        $fpm      = Get-PhpFpmProcesses
        # Webshell scan + recent-change sweep run when a docroot is given;
        # the report carries whatever they found, not just the CVE match.
        $webshells = @()
        $changed   = @()
        if (-not [string]::IsNullOrWhiteSpace($root)) {
            if (Test-Path $root) {
                $webshells = @(Find-PhpSuspiciousFiles -DocRoot $root)
                $changed   = @(Get-PhpRecentlyChangedFiles -DocRoot $root -Days 30)
            }
            else { Write-Host ("Web root not found: {0} — skipping webshell/recent-change scans." -f $root) -ForegroundColor Yellow }
        }
        $rep = New-PhpShieldReport -ScanResults $scan -WebshellScan $webshells `
            -WebBindings $bindings -ApacheBindings $apache -FpmProcesses $fpm `
            -ChangedFiles $changed
        Export-PhpShieldReport -Report $rep
        $fix = Read-Host "Apply mitigations for what was found? (y/n) [n]"
        if ($fix -eq 'y') {
            $srv = Read-Host "Server type [Apache/IIS/Both]"
            if ([string]::IsNullOrWhiteSpace($srv)) { $srv = 'Both' }
            if ([string]::IsNullOrWhiteSpace($root)) { New-PhpMitigation -ServerType $srv }
            else { New-PhpMitigation -DocRoot $root -ServerType $srv }
            # Verify what was actually applied — the Better-Way Law needs
            # proof of the fix, not a claim of it.
            Test-PhpMitigation -DocRoot $root
        } else {
            Test-PhpMitigation -DocRoot $root
        }
    } catch {
        Write-Host "PHP shield failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-BreachWorkflow {
    if (-not (Import-LauncherModule -DirName '08-breach-cleaner' -FileName 'Falsum-BreachClean.ps1')) {
        Write-Host 'Breach-cleaner module failed to load.' -ForegroundColor Red; return
    }
    $email = Read-Host "Email to check for breaches"
    if ([string]::IsNullOrWhiteSpace($email)) { return }
    try {
        # Get-BreachReportForEmail prints the rotation checklist itself when
        # exposure is found; the follow-up offer re-prints it on demand
        # (the old bare New-RotationChecklist call broke when the function
        # gained a mandatory -ExposedAccounts param).
        $summary = Get-BreachReportForEmail -Email $email
        $exposed = ($summary -ne $null) -and
                   (([int]$summary.breachCount) -gt 0 -or ([int]$summary.pasteCount) -gt 0)
        if ($exposed) {
            $again = Read-Host "Show the rotation checklist again? (y/n) [n]"
            if ($again -eq 'y') {
                $names = @($summary.breaches | ForEach-Object { $_.Name })
                New-RotationChecklist -ExposedAccounts @($email) -PriorityBreaches $names
            }
        }
    } catch {
        Write-Host "Breach check failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-BrokerWorkflow {
    if (-not (Import-LauncherModule -DirName '09-broker-eradicator' -FileName 'Falsum-BrokerEradicator.ps1')) {
        Write-Host 'Broker module failed to load.' -ForegroundColor Red; return
    }
    try {
        $summary = Get-BrokerRunSummary
        if ($summary) { $summary | Format-List | Out-Host }
        Get-BrokerRelistCheck -Quiet:$false | Out-Null
        $audit = Read-Host "Audit opt-out links for rot (dead pages)? (y/n) [n]"
        if ($audit -eq 'y') { Get-BrokerBrokenLinks -TimeoutSec 10 | Out-Null }
        $next = Read-Host "Show the single next action to take? (y/n) [y]"
        if ($next -ne 'n') { Get-BrokerNextAction | Out-Null }
        $drip = Read-Host "Show the day-by-day drip schedule? (y/n) [n]"
        if ($drip -eq 'y') { Get-BrokerDripSchedule }
        $go = Read-Host "Start an opt-out run? (y/n) [n]"
        if ($go -eq 'y') { Start-OptOutRun }
        $sched = Read-Host "Schedule the monthly re-run (brokers relist)? (y/n) [n]"
        if ($sched -eq 'y') { New-BrokerMonthlyTask }
    } catch {
        Write-Host "Broker eradicator failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-TrapMenu {
    if (-not (Import-LauncherModule -DirName '10-trap-network' -FileName 'Falsum-Traps.ps1')) {
        Write-Host 'Trap module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "Honeypot traps (defensive listeners — nothing leaves this machine)" -ForegroundColor Cyan
        Write-Host "  1) Start traps"
        Write-Host "  2) Show status"
        Write-Host "  3) Show recent trap events"
        Write-Host "  4) Block top offenders in the firewall (admin)"
        Write-Host "  5) Block one IP in the firewall (admin)"
        Write-Host "  6) List blocked IPs"
        Write-Host "  7) Unblock an IP (admin)"
        Write-Host "  8) Export trap report (JSON + txt + CSV, hashed)"
        Write-Host "  9) Stop traps"
        Write-Host " 10) Offender summary (ranked)"
        Write-Host " 11) Prune old trap logs"
        Write-Host " 12) Sync blocked IPs to permanent bad-actor list"
        Write-Host " 13) Self-test"
        Write-Host " 14) Attack patterns (what is knocking)"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','6','7','8','9','10','11','12','13','14','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' { try { Start-TrapListener } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '2' { try { Get-TrapStatus | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '3' {
                try {
                    $n = Read-Host "How many recent events? [20]"
                    $last = 20
                    [int]::TryParse($n, [ref]$last) | Out-Null
                    if ($last -lt 1) { $last = 20 }
                    Get-TrapEvents -Last $last | Format-Table -AutoSize | Out-Host
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '4' {
                if (-not (Test-LauncherAdmin)) { Write-Host "Firewall blocks need an elevated window (main menu option 26)." -ForegroundColor Yellow; break }
                $t = Read-Host "Minimum hits before blocking [10]"
                $min = 10
                [int]::TryParse($t, [ref]$min) | Out-Null
                if ($min -lt 1) { $min = 10 }
                try { Block-TrapTopOffenders -MinHits $min } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '5' {
                if (-not (Test-LauncherAdmin)) { Write-Host "Firewall blocks need an elevated window (main menu option 26)." -ForegroundColor Yellow; break }
                $ip = Read-Host "IP to block"
                $why = Read-Host "Reason [trap hit]"
                if ([string]::IsNullOrWhiteSpace($why)) { $why = 'trap hit' }
                if ($ip) { try { New-TrapBlock -IpAddress $ip -Reason $why } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
            '6' { try { Get-TrapBlocked | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '7' {
                if (-not (Test-LauncherAdmin)) { Write-Host "Firewall changes need an elevated window (main menu option 26)." -ForegroundColor Yellow; break }
                $ip = Read-Host "IP to unblock"
                if ($ip) { try { Remove-TrapBlock -IpAddress $ip } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
            '8' {
                $dir = Read-Host "Report output directory [Desktop\Falsum-TrapReports]"
                if ([string]::IsNullOrWhiteSpace($dir)) { $dir = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Falsum-TrapReports' }
                try { Export-TrapReport -Path $dir } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '9' { try { Stop-TrapListener } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '10' { try { Get-TrapOffenderSummary | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '11' {
                $d = Read-Host "Retention days [30]"
                $days = 30
                [int]::TryParse($d, [ref]$days) | Out-Null
                if ($days -lt 1) { $days = 30 }
                try { Clear-OldTrapLogs -RetentionDays $days } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '12' { try { Sync-TrapBlocksToBadActors } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '13' { try { [void](Test-TrapHygiene) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '14' { try { Get-TrapAttackPatterns | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
        }
    }
}

function Invoke-ActiveDefenseMenu {
    if (-not (Import-LauncherModule -DirName '11-active-defense' -FileName 'Falsum-ActiveDefense.ps1')) {
        Write-Host 'Active-defense module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "Active defense (manual trigger only; evidence first)" -ForegroundColor Cyan
        Write-Host "  1) Backtrace an IP (passive evidence: banners, RDAP, reverse DNS)"
        Write-Host "  2) List established sessions"
        Write-Host "  3) Stop a hostile session (local kill, admin)"
        Write-Host "  4) Build an abuse-report bundle"
        Write-Host "  5) Mark a bad actor (permanent blocklist + firewall)"
        Write-Host "  6) List marked bad actors"
        Write-Host "  7) Threat-hunt session report (indicators on your wire)"
        Write-Host "  8) Sync firewall block rules (repair drift, admin)"
        Write-Host "  9) Import shared bad-actor marks (file)"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','6','7','8','9','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' {
                $ip = Read-Host "IP to backtrace"
                if ($ip) { try { Start-Backtrace -Ip $ip } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
            '2' { try { Get-EstablishedSession | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '3' {
                if (-not (Test-LauncherAdmin)) { Write-Host "Needs an elevated window." -ForegroundColor Yellow; break }
                $pid_ = Read-Host "Process ID to kill"
                if ($pid_) { try { Stop-HostileSession -ProcessId ([int]$pid_) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
            '4' {
                $ip = Read-Host "Attacker IP for the abuse bundle"
                $dir = Read-Host "Evidence directory (Enter = repo vault)"
                if ([string]::IsNullOrWhiteSpace($dir)) { $dir = Join-Path $script:RepoRoot 'vault' }
                if ($ip) { try { New-AbusePack -IpAddress $ip -EvidenceDir $dir } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
            '5' {
                $ip = Read-Host "IP to mark permanently"
                $why = Read-Host "Reason / evidence summary"
                if ($ip -and $why) { try { Add-BadActor -IpAddress $ip -Reason $why } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
            '6' { try { Get-BadActorList | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '7' { try { Get-HostileSessionReport } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '8' {
                if (-not (Test-LauncherAdmin)) { Write-Host "Needs an elevated window." -ForegroundColor Yellow; break }
                try { Sync-FirewallBlockRules } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '9' {
                $f = Read-Host "Path to marks file (JSON or CSV)"
                if ($f) {
                    $csv = (Read-Host "CSV format? (y/N)") -eq 'y'
                    try { Import-BadActorList -Path $f -AsCsv:$csv } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
                }
            }
        }
    }
}

function Invoke-ChatWorkflow {
    if (-not (Import-LauncherModule -DirName '13-native-chat' -FileName 'Falsum-Chat.ps1')) {
        Write-Host 'Chat module failed to load.' -ForegroundColor Red; return
    }
    try {
        $status = Get-ModelStatus
        $up = @($status | Where-Object { $_.Reachable })
        while ($up.Count -eq 0) {
            # The chat half used to dead-end here with "start one, then come
            # back". The tool can now DO both halves of the setup itself:
            # download the model and start the server.
            Write-Host "No local model is running." -ForegroundColor Yellow
            Write-Host "  1) Download a GGUF model to this machine (~2.5GB, one time)"
            Write-Host "  2) Start the local llama.cpp model server"
            Write-Host "  0) Back"
            $m = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','0')
            if ($m -eq $null -or $m -eq '0') { return }
            if ($m -eq '1') { try { [void](Install-NativeModel) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            if ($m -eq '2') { try { [void](Start-NativeModelServer) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            $status = Get-ModelStatus
            $up = @($status | Where-Object { $_.Reachable })
        }
        Write-Host ("Connected: {0}" -f (($up | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor Green
    } catch { Write-Host $_.Exception.Message -ForegroundColor Red; return }
    Write-Host "Local model chat. It summarizes findings — it never decides truth." -ForegroundColor DarkGray
    while ($true) {
        Write-Host ""
        Write-Host "Chat (mouthpiece: summarizes, never judges)" -ForegroundColor Cyan
        Write-Host "  1) Chat (type prompts; 'quit' leaves the chat loop)"
        Write-Host "  2) Smoke test (needs a running model)"
        Write-Host "  3) Save session"
        Write-Host "  4) Export transcript (JSON+txt, SHA-256)"
        Write-Host "  5) Hygiene self-test (offline)"
        Write-Host "  6) Best endpoint (latency-ranked failover pick)"
        Write-Host "  7) Clear probe cache (force fresh endpoint probes)"
        Write-Host "  8) Failover to fastest runtime (set active)"
        Write-Host "  9) Download a GGUF model (Install-NativeModel)"
        Write-Host "  10) Start local model server (Start-NativeModelServer)"
        Write-Host "  11) Stop local model server (Stop-NativeModelServer)"
        Write-Host "  12) List downloaded models (Get-NativeModelFiles)"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','6','7','8','9','10','11','12','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' {
                Write-Host "Type 'quit' to leave." -ForegroundColor DarkGray
                while ($true) {
                    $q = Read-Host "you"
                    if ($q -eq 'quit' -or $q -eq 'exit') { break }
                    if ([string]::IsNullOrWhiteSpace($q)) { continue }
                    try { Send-ChatPrompt -Prompt $q } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
                }
            }
            '2' { try { [void](Test-ChatSmoke) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '3' { try { [void](Save-ChatSession) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '4' { try { [void](Export-ChatTranscript) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '5' { try { [void](Test-ChatHygiene) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '6' { try { [void](Get-ModelStatus) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }  # re-probe + print latency-ranked pick
            '7' { try { Clear-ChatProbeCache } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '8' { try { [void](Set-ChatBestEndpoint) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '9'  { try { [void](Install-NativeModel) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '10' { try { [void](Start-NativeModelServer) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '11' { try { [void](Stop-NativeModelServer) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '12' {
                try {
                    $mods = @(Get-NativeModelFiles)
                    if ($mods.Count -eq 0) { Write-Host 'No .gguf models downloaded yet.' -ForegroundColor Yellow }
                    else { $mods | Format-Table Name, SizeGB, ModifiedUtc -AutoSize | Out-String | Write-Host }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
        }
    }
}

function Invoke-BountyWorkflow {
    if (-not (Import-LauncherModule -DirName '14-bugbounty' -FileName 'Falsum-BugBounty.ps1')) {
        Write-Host 'Bug-bounty module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "Bug bounty (passive recon only; Scope Law absolute)" -ForegroundColor Cyan
        Write-Host "  1) List programs"
        Write-Host "  2) Register a target (scope URL required)"
        Write-Host "  3) Run passive recon on a registered target"
        Write-Host "  4) Build a bounty report"
        Write-Host "  5) Summary"
        Write-Host "  6) Hygiene self-test (offline)"
        Write-Host "  7) Check one host's CT status (passive, crt.sh only)"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','6','7','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' { try { Get-BountyPrograms | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '2' {
                $name = Read-Host "Target name (e.g. example.com)"
                $target = Read-Host "Target address (e.g. https://example.com)"
                $scope = Read-Host "Scope URL (published bounty scope page)"
                $note = Read-Host "What the scope permits, in your words"
                if ($name -and $target -and $scope -and $note) {
                    try { Register-BountyTarget -Name $name -Target $target -ScopeUrl $scope -AuthorizedNote $note } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
                }
            }
            '3' {
                $name = Read-Host "Program name (as registered)"
                $target = Read-Host "Target (as registered)"
                if ($name -and $target) { try { Start-BountyRecon -Name $name -Target $target } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
            '4' { try { New-BountyReport } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '5' { try { Get-BountySummary | Format-List | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '6' { try { [void](Test-BountyHygiene) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '7' {
                $h = Read-Host "Hostname (e.g. branch.github.com)"
                if ($h) { try { Invoke-BountyCtHostQuery -HostName $h } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
        }
    }
}

function Invoke-ProxyWorkflow {
    if (-not (Import-LauncherModule -DirName '15-web-proxy' -FileName 'Falsum-WebProxy.ps1')) {
        Write-Host 'Web-proxy module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "Web proxy (intercepting; HTTPS tunnels unless MITM is armed)" -ForegroundColor Cyan
        Write-Host "  1) Create local CA (no trust yet)"
        Write-Host "  2) Create local CA AND trust it (enables MITM)"
        Write-Host "  3) Start proxy (tunnel mode)"
        Write-Host "  4) Start proxy (MITM mode — decrypts with your CA)"
        Write-Host "  5) Stop proxy"
        Write-Host "  6) View capture history"
        Write-Host "  7) Repeater: resend an edited request"
        Write-Host "  8) Remove the local CA (full cleanup)"
        Write-Host "  9) Point system proxy at 127.0.0.1:8080"
        Write-Host "  10) Restore system proxy settings"
        Write-Host "  11) Flow summary of latest capture"
        Write-Host "  12) Prune expired per-host certs"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','6','7','8','9','10','11','12','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' { try { New-ProxyCa | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '2' { try { New-ProxyCa -InstallTrust | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '3' { try { Start-WebProxy } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '4' { try { Start-WebProxy -Mitm } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '5' { try { Stop-WebProxy } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '6' { try { Get-ProxyHistory -Latest | Format-List | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '7' {
                $m = Read-Host "Method (GET/POST)"; $u = Read-Host "URL"
                if ($u) { try { Send-RepeaterRequest -Method $m -Url $u | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
            '8' { try { Remove-ProxyCa } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '9' { try { Set-SystemProxy } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '10' { try { Clear-SystemProxy } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '11' {
                try {
                    $ph = Get-ProxyHistory -Latest
                    if ($ph) { Get-ProxyFlowSummary -History $ph | Format-List | Out-Host }
                    else { Write-Host 'No capture history yet.' }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '12' { try { Remove-ProxyHostCerts -ExpiredOnly } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
        }
    }
}

function Invoke-MailShieldWorkflow {
    if (-not (Import-LauncherModule -DirName '16-mail-shield' -FileName 'Falsum-MailShield.ps1')) {
        Write-Host 'Mail-shield module failed to load.' -ForegroundColor Red; return
    }
    $path = Read-Host "Path to the .eml file"
    if (-not $path) { return }
    try {
        $em = Import-EmlFile $path
        $v = Get-EmailVerdict $em
        Write-Host ""
        Write-Host "Verdict: $($v.Level) (score $($v.Score))" -ForegroundColor Cyan
        foreach ($s in $v.Signals) { Write-Host "  [$($s.Weight)] $($s.Signal) — $($s.Detail)" }
        Write-Host ""
        Write-Host $v.Note
        if ($v.Level -in @('High','Critical')) {
            $b = Read-Host "Add the sender domain to your phish blocklist so the next attempt scores against it? (y/n)"
            if ($b -eq 'y') {
                $dom = (Get-EmailAddressParts ($em.Headers['From'])).Domain
                if ($dom -ne "") { Add-PhishSenderBlocklist -Domains @($dom) -Reason "verdict $($v.Level) score $($v.Score) on $path" | Out-Null }
                else { Write-Host 'No sender domain to blocklist.' }
            }
        }
        $r = Read-Host "Build a report pack for this email? (y/n)"
        if ($r -eq 'y') { New-PhishReportPack $v | Out-Host }
    } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
}

function Invoke-PhotoScrubWorkflow {
    if (-not (Import-LauncherModule -DirName '17-photo-scrub' -FileName 'Falsum-PhotoScrub.ps1')) {
        Write-Host 'Photo-scrub module failed to load.' -ForegroundColor Red; return
    }
    $path = Read-Host "Path to the photo (JPEG/PNG)"
    if (-not $path) { return }
    try {
        $ph = Get-PhotoMetadata $path
        $risk = Get-PhotoRisk $ph
        Write-Host ""
        Write-Host "Risk: $($risk.Level) (score $($risk.Score))" -ForegroundColor Cyan
        foreach ($r in $risk.Reasons) { Write-Host "  - $r" }
        if ($ph.Gps) { Write-Host "  GPS: $($ph.Gps.Latitude), $($ph.Gps.Longitude)" }
        $s = Read-Host "Scrub metadata into a clean copy? (y/n)"
        if ($s -eq 'y') { Clear-PhotoMetadata -Path $path | Out-Host }
    } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
}

function Invoke-ScamShieldWorkflow {
    if (-not (Import-LauncherModule -DirName '18-scam-shield' -FileName 'Falsum-ScamShield.ps1')) {
        Write-Host 'Scam-shield module failed to load.' -ForegroundColor Red; return
    }
    Write-Host "Scam types: romance, grandparent, investment, job, rental, techsupport, smishing, vishing, deepfake"
    $mode = Read-Host "1 = guided checklist, 2 = paste a suspicious message for triage"
    if ($mode -eq '2') {
        Write-Host "Paste the message (end with an empty line):"
        $lines = @()
        while ($true) { $l = Read-Host; if ([string]::IsNullOrWhiteSpace($l)) { break }; $lines += $l }
        $msg = $lines -join "`n"
        if ([string]::IsNullOrWhiteSpace($msg)) { Write-Host "Nothing pasted."; return }
        Start-ScamMessageTriage -Text $msg | Out-Null
        return
    }
    $t = Read-Host "Which one are you dealing with"
    if (-not $t) { return }
    try {
        $check = Start-ScamCheck -Type $t
        $r = Read-Host "Build a report pack? (y/n)"
        if ($r -eq 'y') {
            $notes = Read-Host "Any notes (what happened, amounts, numbers)"
            New-ScamReportPack -Check $check -Notes $notes | Out-Host
        }
    } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
}

function Invoke-WifiRouterWorkflow {
    if (-not (Import-LauncherModule -DirName '19-wifi-router' -FileName 'Falsum-WifiRouter.ps1')) {
        Write-Host 'Wi-Fi/router module failed to load.' -ForegroundColor Red; return
    }
    try {
        $audit = Start-WifiRouterAudit
        $bad = @($audit.SavedRisks | Where-Object { $_.Risk -eq "High" })
        foreach ($b in $bad) {
            $yn = Read-Host "Delete risky saved profile '$($b.Profile)' ($($b.Reason))? (y/n)"
            if ($yn -eq 'y') { [void](Remove-WifiProfile -Name $b.Profile) }
        }
    } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
}

function Invoke-BackupWorkflow {
    if (-not (Import-LauncherModule -DirName '20-backup-shield' -FileName 'Falsum-BackupShield.ps1')) {
        Write-Host 'Backup module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "Backup shield (the ransomware answer)" -ForegroundColor Cyan
        Write-Host "  1) Create a backup plan"
        Write-Host "  2) Run backup now"
        Write-Host "  3) Test backup integrity (re-hash vs manifest)"
        Write-Host "  4) Restore drill (prove it restores)"
        Write-Host "  5) Show the ransomware playbook"
        Write-Host "  6) Schedule automatic backups"
        Write-Host "  7) Manage scheduled backup task"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','6','7','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' {
                $src = Read-Host "Source folders (semicolon separated)"
                $dst = Read-Host "Destination folder (external drive)"
                if ($src -and $dst) { try { New-BackupPlan -SourceDirs ($src -split ';') -Destination $dst | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
            '2' { try { Start-Backup | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '3' {
                $v = Read-Host "Backup version folder"
                if ($v) { try { Test-BackupIntegrity $v | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
            '4' {
                $v = Read-Host "Backup version folder"; $s = Read-Host "Original source folder"
                if ($v -and $s) { try { Start-RestoreDrill -VersionDir $v -SourceDir $s | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
            '5' { try { Get-RansomwarePlaybook | Format-Table -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '6' {
                $pn = Read-Host "Plan name (default)"
                if ([string]::IsNullOrWhiteSpace($pn)) { $pn = "default" }
                $fq = Read-Host "Frequency DAILY/WEEKLY/MONTHLY (default WEEKLY)"
                if ([string]::IsNullOrWhiteSpace($fq)) { $fq = "WEEKLY" }
                try { New-BackupScheduledTask -PlanName $pn -Frequency $fq | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '7' {
                $pn = Read-Host "Plan name (default)"
                if ([string]::IsNullOrWhiteSpace($pn)) { $pn = "default" }
                $a = Read-Host "show or remove? (s/r)"
                try {
                    if ($a -eq 'r') { Remove-BackupScheduledTask -PlanName $pn | Out-Host }
                    else { Get-BackupScheduledTask -PlanName $pn | Out-Host }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
        }
    }
}

function Invoke-MalwareHunterWorkflow {
    if (-not (Import-LauncherModule -DirName '21-malware-hunter' -FileName 'Falsum-MalwareHunter.ps1')) {
        Write-Host 'Malware-hunter module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "Malware hunter (behavioral, scored — never binary)" -ForegroundColor Cyan
        Write-Host "  1) Full hunt (autostart, processes, services, scheduled tasks, WMI, PUPs)"
        Write-Host "  2) Kill + quarantine a PID"
        Write-Host "  3) Remove an autostart entry (Run key / startup folder)"
        Write-Host "  4) List quarantine"
        Write-Host "  5) Restore a quarantined file (rollback)"
        Write-Host "  6) Export hashed hunt report"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','6','0')
        if ($c -eq $null -or $c -eq '0') { break }
        try {
            switch ($c) {
                '1' { Start-MalwareHunt | Out-Host }
                '2' {
                    $pidIn = Read-Host "Kill + quarantine PID (blank to skip)"
                    if ($pidIn -match '^\d+$') { try { Stop-MalwareProcess -Pid ([int]$pidIn) } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
                }
                '3' {
                    $area = Read-Host "Area (RunKey / StartupFolder)"
                    $key = Read-Host "Key (registry path or startup folder)"
                    $nm = Read-Host "Entry name"
                    if ($area -and $key -and $nm) { try { Remove-AutostartEntry -Area $area -Key $key -Name $nm } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
                }
                '4' { try { Get-QuarantineList | Format-Table Utc, OriginalPath, Reason, RestoredUtc -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
                '5' {
                    $nm = Read-Host "Quarantined file name (or part of it)"
                    if ($nm) { try { Restore-QuarantinedFile -Name $nm } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
                }
                '6' { try { Export-MalwareHuntReport | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            }
        } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
    }
}

function Invoke-TrackerBlockWorkflow {
    if (-not (Import-LauncherModule -DirName '22-tracker-block' -FileName 'Falsum-TrackerBlock.ps1')) {
        Write-Host 'Tracker-block module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        try { $n = (Get-TrackerBlocks).Count } catch { $n = 0 }
        Write-Host "Tracker block ($n domains currently blocked)" -ForegroundColor Cyan
        Write-Host "  1) Install starter block set"
        Write-Host "  2) Block domains"
        Write-Host "  3) Unblock domains"
        Write-Host "  4) Import a block list file"
        Write-Host "  5) Clear all blocks (full rollback)"
        Write-Host "  6) Verify ALL blocks (health check)"
        Write-Host "  7) Restore hosts from backup"
        Write-Host "  0) Back"
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','6','7','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' { try { Install-StarterBlocks | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '2' { $d = Read-Host "Domains (comma separated)"; if ($d) { try { Add-TrackerBlock -Domain ($d -split ',') | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } } }
            '3' { $d = Read-Host "Domains (comma separated)"; if ($d) { try { Remove-TrackerBlock -Domain ($d -split ',') | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } } }
            '4' { $f = Read-Host "Block list file path"; if ($f) { try { Import-BlockList $f | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } } }
            '5' { $y = Read-Host "Clear ALL managed blocks? (yes/no)"; if ($y -eq 'yes') { try { Clear-TrackerBlocks | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } } }
            '6' { try { Test-TrackerBlockHealth | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '7' { $y = Read-Host "Restore the newest hosts backup? (yes/no)"; if ($y -eq 'yes') { try { Restore-HostsBackup -Latest | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } } }
        }
    }
}

function Invoke-FraudPackWorkflow {
    if (-not (Import-LauncherModule -DirName '23-fraud-pack' -FileName 'Falsum-FraudPack.ps1')) {
        Write-Host 'Fraud-pack module failed to load.' -ForegroundColor Red; return
    }
    Write-Host "Fraud types: financial, identity, medical, tax, mail, family"
    $t = Read-Host "Which one happened"
    if (-not $t) { return }
    $title = Read-Host "Short title for the incident"
    try {
        $pack = New-FraudPack -Type $t -Title $title
        Write-Host "Add timeline entries now (blank date to finish):"
        while ($true) {
            $d = Read-Host "  Date (YYYY-MM-DD)"
            if (-not $d) { break }
            $w = Read-Host "  What happened"
            $a = Read-Host "  Amount (optional)"
            Add-FraudTimelineEntry -PackDir $pack.Dir -Date $d -What $w -Amount $a | Out-Null
        }
        Write-Host "Pack ready: $($pack.Dir)"
        $tl = Get-FraudTimeline -PackDir $pack.Dir
        Write-Host "Timeline (chronological):"
        foreach ($e in $tl) { Write-Host ("  {0} — {1}" -f $e.Date, $e.What) }
        $iv = Test-FraudPackIntegrity -PackDir $pack.Dir
        Write-Host ("Pack integrity: {0}" -f $iv.Overall)
        $mk = Read-Host "Make a handoff zip copy for police/bank (y/n)"
        if ($mk -eq 'y') { Compress-FraudPack -PackDir $pack.Dir | Out-Null }
    } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
}

function Invoke-MobileShieldWorkflow {
    if (-not (Import-LauncherModule -DirName '24-mobile-shield' -FileName 'Falsum-MobileShield.ps1')) {
        Write-Host 'Mobile-shield module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "  MOBILE SHIELD — stalkerware, phone backups, Windows monitoring" -ForegroundColor Cyan
        Write-Host "   1) Scan this PC for monitoring software (stalkerware, parental control, bossware)"
        Write-Host "   2) Audit Windows 11 mobile-like surveillance (privacy settings)"
        Write-Host "   3) Scan phone backups on this PC for stalkerware"
        Write-Host "   4) Check DNS cache for stalkerware C2 domains"
        Write-Host "   5) Run module self-test (offline hygiene battery)"
        Write-Host ""
        Write-Host "   0) Back"
        Write-Host ""
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' {
                try {
                    $r = Find-WindowsMonitoringSoftware
                    Write-Host ("Status: {0}" -f $r.Status)
                    if ($r.Status -eq 'UNKNOWN') {
                        Write-Host $r.Fix -ForegroundColor Yellow
                    } elseif ($r.Status -eq 'FOUND') {
                        foreach ($f in $r.Findings) {
                            Write-Host ("[!] {0} [{1}]" -f $f.Name, $f.Category) -ForegroundColor Red
                            Write-Host ("    Evidence: {0}" -f $f.Evidence)
                            Write-Host ("    {0}" -f $f.Notes)
                        }
                        Write-Host $r.Findings[0].Fix -ForegroundColor Yellow
                    } else {
                        Write-Host $r.Caveat -ForegroundColor DarkGray
                    }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '2' {
                try {
                    $rows = Get-WindowsPrivacyAudit
                    $rows | Format-Table Check, Status, Detail -AutoSize | Out-Host
                    $show = Read-Host "Show fixes for EXPOSED items (y/n)"
                    if ($show -eq 'y') {
                        $rows | Where-Object { $_.Status -eq 'EXPOSED' } | ForEach-Object {
                            Write-Host ("  {0}: {1}" -f $_.Check, $_.Fix)
                        }
                        $apply = Read-Host "Apply the safe fixes now (y/n)"
                        if ($apply -eq 'y') { try { Repair-WindowsPrivacy | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
                    }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '3' {
                try {
                    $backs = Find-PhoneBackups
                    if ($backs.Count -eq 0) { Write-Host "No phone backups found on this PC." -ForegroundColor Yellow; continue }
                    for ($i = 0; $i -lt $backs.Count; $i++) {
                        Write-Host ("  {0}) [{1}] {2}" -f ($i + 1), $backs[$i].Type, $backs[$i].Path)
                    }
                    $pick = Read-Host "Scan which backup (number, or 'all')"
                    $targets = if ($pick -eq 'all') { $backs } else { @($backs[[int]$pick - 1]) }
                    foreach ($t in $targets) {
                        Write-Host ("Scanning {0} ..." -f $t.Path)
                        $hits = Invoke-BackupStalkerwareScan -BackupPath $t.Path
                        foreach ($h in $hits) {
                            Write-Host ("[{0}] {1} — {2}" -f $h.Severity, $h.Name, $h.Indicator) -ForegroundColor Red
                            Write-Host ("    Fix: {0}" -f $h.Fix)
                        }
                        if ($hits.Count -eq 0) { Write-Host "No stalkerware indicators in this backup." -ForegroundColor Green }
                    }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '4' {
                try {
                    $doms = Get-DnsClientCacheDomains
                    $hits = Test-DnsForStalkerwareC2 -QueriedDomains $doms
                    foreach ($h in $hits) {
                        Write-Host ("[CRITICAL] {0} -> {1} ({2})" -f $h.QueriedDomain, $h.MatchedC2, $h.Family) -ForegroundColor Red
                        Write-Host ("    Fix: {0}" -f $h.Fix)
                    }
                    if ($hits.Count -eq 0) { Write-Host "No stalkerware C2 domains in the DNS cache." -ForegroundColor Green }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '5' { try { Test-MobileShieldHygiene | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
        }
    }
}


function Invoke-PurgeWorkflow {
    if (-not (Import-LauncherModule -DirName '25-purge' -FileName 'Falsum-Purge.ps1')) {
        Write-Host 'Purge module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "  PURGE — unattributed binary hunter (delete + log)" -ForegroundColor Cyan
        Write-Host "   1) Audit scan (safe: shows what WOULD be deleted)"
        Write-Host "   2) Enforce purge (DELETES unattributed binaries, logs everything)"
        Write-Host "   3) Check one binary's attribution"
        Write-Host "   4) Run module self-test"
        Write-Host ""
        Write-Host "   0) Back"
        Write-Host ""
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' { try { Invoke-PurgeScan -AuditOnly | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '2' {
                $confirm = Read-Host "ENFORCE will DELETE unattributed binaries. Type 'PURGE' to confirm"
                if ($confirm -eq 'PURGE') {
                    try { Invoke-PurgeScan -Enforce | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
                } else { Write-Host "Cancelled." -ForegroundColor Yellow }
            }
            '3' {
                $path = Read-Host "Binary path to check"
                try {
                    $attr = Get-BinaryAttribution -Path $path
                    Write-Host "  Signed: $($attr.Signed) | Version info: $($attr.HasVersionInfo)"
                    Write-Host "  Company: $($attr.CompanyName) | Product: $($attr.ProductName)"
                    Write-Host "  Attributed: $($attr.Attributed) ($($attr.AttributionSource))"
                    Write-Host "  SHA256: $($attr.SHA256)"
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '4' { try { Test-PurgeHygiene | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
        }
    }
}

function Invoke-DefenderWatchWorkflow {
    if (-not (Import-LauncherModule -DirName '26-defender-watch' -FileName 'Falsum-DefenderWatch.ps1')) {
        Write-Host 'Defender Watch module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "  DEFENDER WATCH — monitoring Windows Defender itself" -ForegroundColor Cyan
        Write-Host "   1) Full Defender watch sweep (status, scans, detections, exclusions, toggles)"
        Write-Host "   2) Current Defender status only"
        Write-Host "   3) Exclusion changes (who punched holes, when)"
        Write-Host "   4) Protection toggles (who turned it off, when)"
        Write-Host "   5) Run module self-test"
        Write-Host ""
        Write-Host "   0) Back"
        Write-Host ""
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' { try { Invoke-DefenderWatch | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '2' { try { Get-DefenderStatus | Format-List | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '3' {
                try {
                    $changes = Get-DefenderExclusionChanges
                    if ($changes.Count -eq 0) { Write-Host "No exclusion changes in 90 days." -ForegroundColor Green }
                    else { $changes | Format-Table TimeCreated, Message -Wrap -AutoSize | Out-Host }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '4' {
                try {
                    $toggles = Get-DefenderProtectionToggles
                    if ($toggles.Count -eq 0) { Write-Host "No protection toggles in 90 days." -ForegroundColor Green }
                    else { $toggles | Format-Table TimeCreated, Id, Message -Wrap -AutoSize | Out-Host }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '5' { try { Test-DefenderWatchHygiene | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
        }
    }
}

function Invoke-MemoryForensicsWorkflow {
    if (-not (Import-LauncherModule -DirName '27-memory-forensics' -FileName 'Falsum-MemoryForensics.ps1')) {
        Write-Host 'Memory Forensics module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "  MEMORY FORENSICS — deep into RAM" -ForegroundColor Cyan
        Write-Host "   1) Full memory sweep (processes, orphans, suspicious paths)"
        Write-Host "   2) Deep scan with unsigned DLL check (slower)"
        Write-Host "   3) Top memory consumers"
        Write-Host "   4) Process details (WMI: command line, owner)"
        Write-Host "   5) Run module self-test"
        Write-Host ""
        Write-Host "   0) Back"
        Write-Host ""
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','5','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' { try { Invoke-MemoryForensics | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '2' { try { Invoke-MemoryForensics -DeepModuleScan | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '3' { try { Get-ProcessMemorySummary | Select-Object -First 15 | Format-Table Name, Id, PrivateMB, WorkingSetMB -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '4' {
                $pidIn = Read-Host "Process ID"
                try { Get-ProcessDetails -ProcessId ([int]$pidIn) | Format-List | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '5' { try { Test-MemoryForensicsHygiene | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
        }
    }
}

function Invoke-TaskKillerWorkflow {
    if (-not (Import-LauncherModule -DirName '28-task-killer' -FileName 'Falsum-TaskKiller.ps1')) {
        Write-Host 'Task Killer module failed to load.' -ForegroundColor Red; return
    }
    while ($true) {
        Write-Host ""
        Write-Host "  TASK KILLER — nothing runs without you knowing" -ForegroundColor Cyan
        Write-Host "   1) Audit: show everything running (you pick what dies)"
        Write-Host "   2) Enforce: auto-kill everything on the kill list"
        Write-Host "   3) View kill list"
        Write-Host "   4) Run module self-test"
        Write-Host ""
        Write-Host "   0) Back"
        Write-Host ""
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' { try { Invoke-TaskKillerAudit | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '2' {
                $confirm = Read-Host "ENFORCE will kill all processes on the kill list. Type 'KILL' to confirm"
                if ($confirm -eq 'KILL') {
                    try { Invoke-TaskKillerEnforce | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
                } else { Write-Host "Cancelled." -ForegroundColor Yellow }
            }
            '3' { try { Get-TaskKillList | Format-Table Name, Category, Reason -AutoSize | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '4' { try { Test-TaskKillerHygiene | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
        }
    }
}

function Invoke-RegistryFixWorkflow {
    if (-not (Import-LauncherModule -DirName '29-registry-fix' -FileName 'Falsum-RegistryFix.ps1')) {
        Write-Host "Failed to load registry fix module." -ForegroundColor Red
        return
    }
    while ($true) {
        Write-Host ""
        Write-Host "  REGISTRY FIX — clean bad entries, log everything" -ForegroundColor Cyan
        Write-Host "   1) Audit only (show what WOULD be removed)"
        Write-Host "   2) Enforce (backup + remove + log)"
        Write-Host ""
        Write-Host "   0) Back"
        Write-Host ""
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' { try { Invoke-RegistryFixScan | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '2' {
                Write-Host "`n  This will BACK UP each key, then REMOVE bad entries." -ForegroundColor Yellow
                Write-Host "  Protected system paths are NEVER auto-removed." -ForegroundColor Gray
                $confirm = Read-Host "  Type 'FIX' to confirm"
                if ($confirm -eq 'FIX') {
                    try { Invoke-RegistryFixScan -Enforce | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
                }
                else { Write-Host "  Cancelled." -ForegroundColor Gray }
            }
        }
    }
}



function Invoke-UnifiedScanWorkflow {
    # Load unified core if not already loaded
    Import-LauncherModule -DirName '00-coherence-core' -FileName 'Falsum-Unified.ps1' | Out-Null
    while ($true) {
        Write-Host ""
        Write-Host "  UNIFIED SCAN — one system, all senses" -ForegroundColor Cyan
        Write-Host "   1) Start unified session (all modules feed one pool)"
        Write-Host "   2) Show unified threat picture (cross-module corroboration)"
        Write-Host "   3) Query evidence pool"
        Write-Host "   4) Close session and seal to vault"
        Write-Host ""
        Write-Host "   0) Back"
        Write-Host ""
        $c = Read-MenuChoice -Prompt 'Select' -Valid @('1','2','3','4','0')
        if ($c -eq $null -or $c -eq '0') { break }
        switch ($c) {
            '1' { try { Invoke-UnifiedScan | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
            '2' {
                try {
                    $pic = Get-UnifiedThreatPicture
                    if ($pic) {
                        Write-Host "`n$($pic.Summary)" -ForegroundColor White
                        Write-Host "  Total: $($pic.TotalFindings) | Critical: $($pic.Critical) | High: $($pic.High)" -ForegroundColor Gray
                        if ($pic.CorroboratedCount -gt 0) {
                            Write-Host "`n  Corroborated threats:" -ForegroundColor Yellow
                            foreach ($ct in $pic.CorroboratedThreats) {
                                Write-Host "    [$($ct.MaxSeverity)] $($ct.Entity) ($($ct.Modules -join ', '))" -ForegroundColor Red
                            }
                        }
                    }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '3' {
                $kw = Read-Host "Keyword to search"
                try { Get-SessionEvidence -Keyword $kw | Format-Table Timestamp, Module, Severity, Finding -AutoSize -Wrap | Out-Host } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
            '4' { try { Close-UnifiedSession | Out-Null } catch { Write-Host $_.Exception.Message -ForegroundColor Red } }
        }
    }
}

# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

function Invoke-SelfTestWorkflow {
    # Runs every module's offline self-test battery in one pass. A module
    # whose plumbing can't prove itself offline has no business going live.
    $pass = 0; $fail = 0
    $suites = @(
        @{ Dir = '00-coherence-core';  File = 'Falsum-Coherence.ps1'; Func = 'Test-CoherenceHygiene' },
        @{ Dir = '02-packet-witness';  File = 'Falsum-PacketWitness.ps1'; Func = 'Test-PacketWitnessHygiene' },
        @{ Dir = '03-netscan';          File = 'Falsum-NetScan.ps1';      Func = 'Test-NetScanHygiene' },
        @{ Dir = '04-osint-attribution'; File = 'Falsum-Osint.ps1';        Func = 'Test-OsintHygiene' },
        @{ Dir = '05-people-track';     File = 'Falsum-PeopleTrack.ps1'; Func = 'Test-PeopleTrackHygiene' },
        @{ Dir = '06-vuln-check';       File = 'Falsum-VulnCheck.ps1';   Func = 'Test-VulnCheckHygiene' },
        @{ Dir = '07-php-shield';       File = 'Falsum-PhpShield.ps1'; Func = 'Test-PhpShieldHygiene' },
        @{ Dir = '08-breach-cleaner';  File = 'Falsum-BreachClean.ps1';   Func = 'Test-BreachCleanHygiene' },
        @{ Dir = '09-broker-eradicator'; File = 'Falsum-BrokerEradicator.ps1'; Func = 'Test-BrokerEradicatorHygiene' },
        @{ Dir = '10-trap-network';    File = 'Falsum-Traps.ps1';         Func = 'Test-TrapHygiene' },
        @{ Dir = '11-active-defense';  File = 'Falsum-ActiveDefense.ps1'; Func = 'Test-ActiveDefenseHygiene' },
        @{ Dir = '12-timeline-vault';   File = 'Falsum-Vault.ps1';         Func = 'Test-VaultHygiene' },
        @{ Dir = '13-native-chat';     File = 'Falsum-Chat.ps1';          Func = 'Test-ChatHygiene' },
        @{ Dir = '14-bugbounty';       File = 'Falsum-BugBounty.ps1';   Func = 'Test-BountyHygiene' },
        @{ Dir = '15-web-proxy';        File = 'Falsum-WebProxy.ps1';     Func = 'Test-ProxyHygiene' },
        @{ Dir = '16-mail-shield';      File = 'Falsum-MailShield.ps1';   Func = 'Test-MailShieldHygiene' },
        @{ Dir = '17-photo-scrub';      File = 'Falsum-PhotoScrub.ps1';   Func = 'Test-PhotoScrubHygiene' },
        @{ Dir = '18-scam-shield';      File = 'Falsum-ScamShield.ps1';   Func = 'Test-ScamShieldHygiene' },
        @{ Dir = '19-wifi-router';      File = 'Falsum-WifiRouter.ps1';   Func = 'Test-WifiRouterHygiene' },
        @{ Dir = '20-backup-shield';    File = 'Falsum-BackupShield.ps1'; Func = 'Test-BackupShieldHygiene' },
        @{ Dir = '21-malware-hunter';   File = 'Falsum-MalwareHunter.ps1'; Func = 'Test-MalwareHunterHygiene' },
        @{ Dir = '22-tracker-block';    File = 'Falsum-TrackerBlock.ps1'; Func = 'Test-TrackerBlockHygiene' },
        @{ Dir = '23-fraud-pack';       File = 'Falsum-FraudPack.ps1';    Func = 'Test-FraudPackHygiene' },
        @{ Dir = '24-mobile-shield';    File = 'Falsum-MobileShield.ps1'; Func = 'Test-MobileShieldHygiene' },
        @{ Dir = '25-purge';             File = 'Falsum-Purge.ps1';          Func = 'Test-PurgeHygiene' },
        @{ Dir = '26-defender-watch';    File = 'Falsum-DefenderWatch.ps1';  Func = 'Test-DefenderWatchHygiene' },
        @{ Dir = '27-memory-forensics';  File = 'Falsum-MemoryForensics.ps1'; Func = 'Test-MemoryForensicsHygiene' },
        @{ Dir = '28-task-killer';       File = 'Falsum-TaskKiller.ps1';     Func = 'Test-TaskKillerHygiene' },
        @{ Dir = '29-registry-fix';      File = 'Falsum-RegistryFix.ps1';    Func = 'Test-RegistryFixHygiene' }
    )
    foreach ($s in $suites) {
        Write-Host ""
        Write-Host ("--- {0} : {1} ---" -f $s.Dir, $s.Func) -ForegroundColor Cyan
        if (-not (Import-LauncherModule -DirName $s.Dir -FileName $s.File)) {
            Write-Host "FAILED TO LOAD MODULE" -ForegroundColor Red; $fail++; continue
        }
        try {
            $out = @(& $s.Func)
            # Sibling batteries return a boolean verdict as their final
            # output. Honor it: a suite that prints 5 failures used to
            # count as PASSED here (a false-green in the one view meant to
            # prove the workstation works).
            $verdict = $out | Select-Object -Last 1
            if ($verdict -is [bool] -and -not $verdict) {
                Write-Host "SUITE REPORTED FAILURES (battery verdict: false)" -ForegroundColor Red
                $fail++
            } else {
                Write-Host "suite finished" -ForegroundColor DarkGray
                $pass++
            }
        } catch {
            Write-Host ("SUITE THREW: {0}" -f $_.Exception.Message) -ForegroundColor Red
            $fail++
        }
    }
    # Coherence determinism: the same evidence item twice must hash
    # identically — if this ever fails, nothing in the workstation is
    # trustworthy.
    Write-Host ""
    Write-Host "--- 00-coherence-core : determinism ---" -ForegroundColor Cyan
    try {
        Import-LauncherModule -DirName '00-coherence-core' -FileName 'Falsum-Coherence.ps1' | Out-Null
        $a = New-EvidenceItem -id 'selftest' -type 'selftest' -source 'launcher' -data @{ a = 1 } -utc '2026-10-30T00:00:00Z'
        $b = New-EvidenceItem -id 'selftest' -type 'selftest' -source 'launcher' -data @{ a = 1 } -utc '2026-10-30T00:00:00Z'
        if ($a.hash -eq $b.hash) { Write-Host "determinism: PASS" -ForegroundColor Green; $pass++ }
        else { Write-Host "determinism: FAIL (hashes differ)" -ForegroundColor Red; $fail++ }
    } catch {
        Write-Host ("determinism check threw: {0}" -f $_.Exception.Message) -ForegroundColor Red
        $fail++
    }
    # Vault tip integrity on the repo vault, if one exists.
    $vaultPath = Join-Path $script:RepoRoot 'vault'
    if (Test-Path $vaultPath) {
        Write-Host ""
        Write-Host "--- 12-timeline-vault : tip integrity ---" -ForegroundColor Cyan
        try {
            Import-LauncherModule -DirName '12-timeline-vault' -FileName 'Falsum-Vault.ps1' | Out-Null
            $v = New-Vault -path $vaultPath
            if (Test-VaultTipIntegrity -vault $v) { Write-Host "tip integrity: PASS" -ForegroundColor Green; $pass++ }
            else { Write-Host "tip integrity: FAIL" -ForegroundColor Red; $fail++ }
        } catch {
            Write-Host ("vault check threw: {0}" -f $_.Exception.Message) -ForegroundColor Red
            $fail++
        }
    }
    Write-Host ""
    Write-Host ("Self-tests: {0} passed, {1} failed." -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
}

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------

function Show-Banner {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  Falsum — free, transparent, Windows-native  " -ForegroundColor Cyan
    Write-Host "  security & forensics workstation              " -ForegroundColor Cyan
    Write-Host "  (working title — the poison pill for the      " -ForegroundColor Cyan
    Write-Host "   subscription model; name pending Gregg)     " -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    if (Test-LauncherAdmin) { Write-Host "  [ADMIN: elevated — captures, kills, fixes available]" -ForegroundColor Green }
    else                    { Write-Host "  [not elevated — option 26 restarts as Administrator]" -ForegroundColor Yellow }
    Write-Host ""
}

function Show-MainMenu {
    Clear-Host
    $w = 70
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host "  falsum — Unified Security Application" -ForegroundColor White
    Write-Host "  Transparent. Local. Yours." -ForegroundColor Gray
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  UNIFIED" -ForegroundColor Yellow
    Write-Host "   U) Unified scan (all modules, one threat picture)" -ForegroundColor White
    Write-Host ""
    Write-Host "  EVIDENCE & TRUTH" -ForegroundColor Yellow
    Write-Host "   1) Collect evidence (44-step system sweep)" -ForegroundColor Gray
    Write-Host "   2) Vault status (hash-chained log)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  NETWORK" -ForegroundColor Yellow
    Write-Host "   3) Packet witness (capture traffic)" -ForegroundColor Gray
    Write-Host "   4) Network scan (who's on your network)" -ForegroundColor Gray
    Write-Host "   5) IP/domain lookup (OSINT attribution)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  PEOPLE & PRIVACY" -ForegroundColor Yellow
    Write-Host "   6) Username check (820 sites)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  DEFENSE" -ForegroundColor Yellow
    Write-Host "   7) Vulnerability check (+ fixes)" -ForegroundColor Gray
    Write-Host "   8) PHP shield" -ForegroundColor Gray
    Write-Host "   9) Breach check" -ForegroundColor Gray
    Write-Host "   10) Data brokers (958)" -ForegroundColor Gray
    Write-Host "   11) Trap network (honeypots)" -ForegroundColor Gray
    Write-Host "   12) Active defense (backtrace)" -ForegroundColor Gray
    Write-Host "   13) Native chat (local AI)" -ForegroundColor Gray
    Write-Host "   14) Bug bounty (passive recon)" -ForegroundColor Gray
    Write-Host "   15) Web proxy" -ForegroundColor Gray
    Write-Host "   16) Mail shield (phishing)" -ForegroundColor Gray
    Write-Host "   17) Photo scrub (EXIF)" -ForegroundColor Gray
    Write-Host "   18) Scam shield" -ForegroundColor Gray
    Write-Host "   19) WiFi/router audit" -ForegroundColor Gray
    Write-Host "   20) Backup shield" -ForegroundColor Gray
    Write-Host "   21) Malware hunter" -ForegroundColor Gray
    Write-Host "   22) Tracker block" -ForegroundColor Gray
    Write-Host "   23) Fraud pack" -ForegroundColor Gray
    Write-Host "   24) Mobile shield (stalkerware)" -ForegroundColor Gray
    Write-Host "   25) Purge unattributed binaries" -ForegroundColor Gray
    Write-Host "   26) Defender watch (log everything)" -ForegroundColor Gray
    Write-Host "   27) Memory forensics (deep RAM)" -ForegroundColor Gray
    Write-Host "   28) Task killer (background processes)" -ForegroundColor Gray
    Write-Host "   29) Fix registry (clean bad entries)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  SYSTEM" -ForegroundColor Yellow
    Write-Host "   30) Module health" -ForegroundColor Gray
    Write-Host "   31) Restart as admin" -ForegroundColor Gray
    Write-Host "   32) Module self-tests" -ForegroundColor Gray
    Write-Host "   33) Value ledger" -ForegroundColor Gray
    Write-Host ""
    Write-Host ("-" * $w) -ForegroundColor DarkGray
    Write-Host "   0) Quit" -ForegroundColor Gray
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host ""
}

function Start-Falsum {
    Show-Banner
    # Pre-load the always-needed modules once.
    Import-LauncherModule -DirName '00-coherence-core' -FileName 'Falsum-Coherence.ps1' | Out-Null
    Import-LauncherModule -DirName '00-coherence-core' -FileName 'Falsum-Unified.ps1'   | Out-Null
    Import-LauncherModule -DirName '12-timeline-vault'  -FileName 'Falsum-Vault.ps1'     | Out-Null
    while ($true) {
        Show-MainMenu
        $c = Read-MenuChoice -Prompt 'Select' -Valid @(
            '0','1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31','32','33','U')
        if ($c -eq $null) { continue }
        switch ($c) {
            '0'  { Write-Host "Stay safe."; return }
            '1'  { Invoke-SafeAction 'Evidence sweep'     { Invoke-EvidenceSweepWorkflow } }
            '2'  { Invoke-SafeAction 'Vault status'       { Show-VaultStatus } }
            '3'  { Invoke-SafeAction 'Packet witness'     { Invoke-PacketWitnessMenu } }
            '4'  { Invoke-SafeAction 'Network scan'       { Invoke-NetScanWorkflow } }
            '5'  { Invoke-SafeAction 'IP/domain lookup'   { Invoke-OsintWorkflow } }
            '6'  { Invoke-SafeAction 'Username check'     { Invoke-PeopleTrackWorkflow } }
            '7'  { Invoke-SafeAction 'Vulnerability audit'{ Invoke-VulnMenu } }
            '8'  { Invoke-SafeAction 'PHP shield'         { Invoke-PhpShieldWorkflow } }
            '9'  { Invoke-SafeAction 'Breach check'       { Invoke-BreachWorkflow } }
            '10' { Invoke-SafeAction 'Data brokers'       { Invoke-BrokerWorkflow } }
            '11' { Invoke-SafeAction 'Honeypot traps'     { Invoke-TrapMenu } }
            '12' { Invoke-SafeAction 'Active defense'     { Invoke-ActiveDefenseMenu } }
            '13' { Invoke-SafeAction 'Local chat'         { Invoke-ChatWorkflow } }
            '14' { Invoke-SafeAction 'Bug bounty'         { Invoke-BountyWorkflow } }
            '15' { Invoke-SafeAction 'Web proxy'          { Invoke-ProxyWorkflow } }
            '16' { Invoke-SafeAction 'Mail shield'        { Invoke-MailShieldWorkflow } }
            '17' { Invoke-SafeAction 'Photo scrub'        { Invoke-PhotoScrubWorkflow } }
            '18' { Invoke-SafeAction 'Scam shield'        { Invoke-ScamShieldWorkflow } }
            '19' { Invoke-SafeAction 'Wi-Fi + router'     { Invoke-WifiRouterWorkflow } }
            '20' { Invoke-SafeAction 'Backup shield'      { Invoke-BackupWorkflow } }
            '21' { Invoke-SafeAction 'Malware hunt'       { Invoke-MalwareHunterWorkflow } }
            '22' { Invoke-SafeAction 'Tracker block'      { Invoke-TrackerBlockWorkflow } }
            '23' { Invoke-SafeAction 'Fraud pack'         { Invoke-FraudPackWorkflow } }
            '24' { Invoke-SafeAction 'Mobile shield'       { Invoke-MobileShieldWorkflow } }
            '25' { Invoke-SafeAction 'Purge (delete+log)' { Invoke-PurgeWorkflow } }
            '26' { Invoke-SafeAction 'Defender watch'     { Invoke-DefenderWatchWorkflow } }
            '27' { Invoke-SafeAction 'Memory forensics'   { Invoke-MemoryForensicsWorkflow } }
            '28' { Invoke-SafeAction 'Task killer'        { Invoke-TaskKillerWorkflow } }
            '29' { Invoke-SafeAction 'Registry fix'       { Invoke-RegistryFixWorkflow } }
            '33' { Invoke-SafeAction 'Value ledger'       { Show-ValueLedger } }
            '30' { Invoke-SafeAction 'Module health'      { Get-LauncherModuleHealth | Format-Table -AutoSize | Out-Host } }
            '31' { Start-FalsumElevated }
            '32' { Invoke-SafeAction 'Module self-tests'  { Invoke-SelfTestWorkflow } }
        }
    }
}

# Entry point
Start-Falsum
