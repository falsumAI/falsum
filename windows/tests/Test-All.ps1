<#
BLACKBOX Test Harness — tests/Test-All.ps1
Loads every module, verifies each parses, checks exported functions exist,
proves the coherence core is deterministic, appends 100 entries to a vault
and verifies the chain, and balance-checks braces/parens/brackets.

Run on Windows 11, PowerShell 5.1: powershell -ExecutionPolicy Bypass -File tests\Test-All.ps1
Zero external dependencies. Exits 0 when everything passes, 1 on any failure.

NOTE: Falsum-Sweep.ps1 and Falsum.ps1 (launcher) auto-execute on load,
so they get parse + balance + function-count checks only — never dot-sourced.
#>

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path $PSScriptRoot -Parent

$script:results = @()
$script:passCount = 0
$script:failCount = 0

function Write-TestResult {
    param([string]$name, [bool]$passed, [string]$detail)
    $script:results += [pscustomobject]@{ Test = $name; Passed = $passed; Detail = $detail }
    if ($passed) { $script:passCount++; Write-Host "  [PASS] $name" }
    else { $script:failCount++; Write-Host "  [FAIL] $name -- $detail" }
}

function Test-FileParse {
    param([string]$path)
    $errs = $null; $toks = $null
    try {
        [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$toks, [ref]$errs)
    } catch {
        return [pscustomobject]@{ ok = $false; msg = "parser threw: $($_.Exception.Message)" }
    }
    if ($null -ne $errs -and $errs.Count -gt 0) {
        $msg = ($errs | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" }) -join " | "
        return [pscustomobject]@{ ok = $false; msg = $msg }
    }
    return [pscustomobject]@{ ok = $true; msg = "" }
}

function Test-Balance {
    # String/comment-aware balance check: strips line comments, block
    # comments (<# #>), double-quoted strings (with ` escapes) and
    # single-quoted strings (with '' escapes) before counting, so
    # brackets inside menu text or log strings can't false-fail the check.
    param([string]$path)
    $text = [System.IO.File]::ReadAllText($path)
    $sb = New-Object System.Text.StringBuilder
    $i = 0; $n = $text.Length
    $inDq = $false; $inSq = $false; $esc = $false; $lineC = $false; $blockC = 0
    while ($i -lt $n) {
        $c = [string]$text[$i]
        $nx = ""; if ($i + 1 -lt $n) { $nx = [string]$text[$i + 1] }
        if ($lineC) {
            if ($c -eq "`n") { $lineC = $false; [void]$sb.Append($c) }
            $i++; continue
        }
        if ($blockC -gt 0) {
            if ($c -eq "#" -and $nx -eq ">") { $blockC--; $i += 2; continue }
            if ($c -eq "<" -and $nx -eq "#") { $blockC++; $i += 2; continue }
            $i++; continue
        }
        if ($inDq) {
            if ($esc) { $esc = $false; $i++; continue }
            if ($c -eq '`') { $esc = $true; $i++; continue }
            if ($c -eq '"') { $inDq = $false }
            $i++; continue
        }
        if ($inSq) {
            if ($c -eq "'" -and $nx -eq "'") { $i += 2; continue }
            if ($c -eq "'") { $inSq = $false }
            $i++; continue
        }
        if ($c -eq "#") { $lineC = $true; $i++; continue }
        if ($c -eq "<" -and $nx -eq "#") { $blockC = 1; $i += 2; continue }
        if ($c -eq '"') { $inDq = $true; $i++; continue }
        if ($c -eq "'") { $inSq = $true; $i++; continue }
        [void]$sb.Append($c); $i++
    }
    $code = $sb.ToString()
    $pairs = @(("{","}"), ("(",")"), ("[","]"))
    $bad = @()
    foreach ($p in $pairs) {
        $o = 0; $c2 = 0
        foreach ($ch in $code.ToCharArray()) {
            if ([string]$ch -eq $p[0]) { $o++ } elseif ([string]$ch -eq $p[1]) { $c2++ }
        }
        if ($o -ne $c2) { $bad += "$($p[0])$($p[1]): open=$o close=$c2" }
    }
    if ($bad.Count -gt 0) { return [pscustomobject]@{ ok = $false; msg = ($bad -join "; ") } }
    return [pscustomobject]@{ ok = $true; msg = "" }
}

function Get-FileFunctionNames {
    param([string]$path)
    $errs = $null; $toks = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$toks, [ref]$errs)
    $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    return @($fns | ForEach-Object { $_.Name })
}

# ---- Module manifest: Name, relative path, dot-sourceable?, minimum function count ----
$modules = @(
    @{ Name = "01-evidence-sweep";   Path = "modules/01-evidence-sweep/Falsum-Sweep.ps1";           Loadable = $false; MinFuncs = 1;  Spot = @() },
    @{ Name = "00-coherence-core";   Path = "modules/00-coherence-core/Falsum-Coherence.ps1";       Loadable = $true;  MinFuncs = 19; Spot = @("New-EvidenceItem","Test-Coherence","New-Receipt","Test-ReceiptChain","ConvertTo-CanonicalJson","Get-FileMagicTable","Get-MagicTypeTable","Get-TrustedCaKeywordTable") },
    @{ Name = "12-timeline-vault";   Path = "modules/12-timeline-vault/Falsum-Vault.ps1";           Loadable = $true;  MinFuncs = 25;  Spot = @("New-Vault","Add-VaultEntry","Verify-Vault","Get-VaultTip","Export-EvidencePack","Test-VaultHygiene","Read-VaultEntries","Clear-VaultTornTail","Test-VaultTimestampFormat","Test-CheckpointFreshness") },
    @{ Name = "02-packet-witness";   Path = "modules/02-packet-witness/Falsum-PacketWitness.ps1";   Loadable = $true;  MinFuncs = 29; Spot = @("Start-Capture","Stop-Capture","Get-DnsQueries","Get-TlsSnis","Get-FlowSummary","Get-DnsTunnelSignals","Get-BeaconingFlows","Get-SniDnsMismatch","Test-PacketWitnessHygiene","Export-PacketWitnessReport","ConvertTo-EndpointParts","Get-DoHSuspectFlows","Get-PacketWitnessFixPlan") },
    @{ Name = "03-netscan";          Path = "modules/03-netscan/Falsum-NetScan.ps1";                 Loadable = $true;  MinFuncs = 11;  Spot = @("Test-TcpPort","Get-PortBanner","Start-NetScan","Expand-PortSpec","Save-NetScanReport","Test-NetScanHygiene","New-PortClosurePlan","Confirm-PortClosed","Test-DriftKeyVerdict") },
    @{ Name = "04-osint-attribution";Path = "modules/04-osint-attribution/Falsum-Osint.ps1";        Loadable = $true;  MinFuncs = 31; Spot = @("Get-RdapIp","Get-CrtSh","Get-ShodanHost","Get-DnsRecords","Get-AttributionReport","ConvertFrom-CrtShRows","ConvertFrom-SpfRecord","ConvertFrom-DmarcRecord","Test-DkimSelectorRecord","Get-MailAuthRecords","Test-OsintHygiene","Test-TakeoverNameSkip","ConvertTo-OsintUtcDate","Get-HttpEdgeHint") },
    @{ Name = "05-people-track";     Path = "modules/05-people-track/Falsum-PeopleTrack.ps1";       Loadable = $true;  MinFuncs = 22; Spot = @("Test-Username","Get-Dossier","Export-Dossier","Get-SiteTable","Get-UsernameScore","Test-SiteRowValidation","Test-PeopleTrackHygiene","Invoke-PeopleTrack","Compare-Dossier","Test-LoginRedirectUrl") },
    @{ Name = "06-vuln-check";       Path = "modules/06-vuln-check/Falsum-VulnCheck.ps1";           Loadable = $true;  MinFuncs = 109; Spot = @("Get-WindowsUpdateStatus","Test-WeakConfigs","New-VulnReport","Export-VulnReport","Repair-Smb1Disable","Test-AlwaysInstallElevated","Test-LsaProtection","Get-UnquotedPathVerdict","Test-VulnCheckHygiene","Test-AutoLogon","Test-WDigest","Test-RemoteUacBypass","Test-AnonymousEnumeration","Test-CachedLogonsCount","Test-ScreenLock","Test-DefenderExclusions","Test-DefenderChannelExclusionRisk","Test-BitLockerStatusVerdict","Test-PrivilegedGroupCensus") },
    @{ Name = "07-php-shield";       Path = "modules/07-php-shield/Falsum-PhpShield.ps1";           Loadable = $true;  MinFuncs = 44; Spot = @("Test-PhpInstalls","Test-PhpCveMatch","New-PhpMitigation","Test-PhpMitigation","Export-PhpShieldReport","Invoke-PhpProbe","Get-PhpFpmProcesses","Get-ApachePhpBindings","Get-PhpRecentlyChangedFiles","Test-PhpShieldHygiene","Compare-PhpVersion","Test-PhpMemoryExposureRisk") },
    @{ Name = "08-breach-cleaner";   Path = "modules/08-breach-cleaner/Falsum-BreachClean.ps1";     Loadable = $true;  MinFuncs = 16; Spot = @("Get-BreachSummaryForEmail","Scan-CombolistFile","New-RotationChecklist","Export-BreachReport","Get-HibpKey","Test-BreachSeverity","Get-BreachExposureProfile","Set-HibpKeyFileSecure") },
    @{ Name = "09-broker-eradicator";Path = "modules/09-broker-eradicator/Falsum-BrokerEradicator.ps1"; Loadable = $true;  MinFuncs = 25; Spot = @("Get-BrokerTable","Start-OptOutRun","Export-BrokerReport","New-BrokerEradicationPlan","Get-BrokerBrokenLinks","Get-BrokerNextAction","Test-BrokerUrlVerdict") },
    @{ Name = "10-trap-network";     Path = "modules/10-trap-network/Falsum-Traps.ps1";             Loadable = $true;  MinFuncs = 24; Spot = @("Start-TrapListener","Stop-TrapListener","Get-TrapEvents","New-TrapBlock","Export-TrapReport","Test-TrapPayloadPattern","Get-TrapAttackPatterns") },
    @{ Name = "11-active-defense";   Path = "modules/11-active-defense/Falsum-ActiveDefense.ps1";   Loadable = $true;  MinFuncs = 28; Spot = @("Start-Backtrace","Get-EstablishedSession","Stop-HostileSession","New-AbusePack","Add-BadActor","Get-BadActorList","Test-ActiveDefenseHygiene","Get-SuspiciousPortTable") },
    @{ Name = "13-native-chat";      Path = "modules/13-native-chat/Falsum-Chat.ps1";               Loadable = $true;  MinFuncs = 33; Spot = @("Get-ModelStatus","Send-ChatPrompt","ConvertFrom-SseDataLine","Export-ChatTranscript","Test-InjectionShapedText","Test-ChatEndpointIsLoopback","New-ChatTurnHash","Test-ChatSessionChain","New-ChatCompactionReceipt","Get-ChatBestEndpoint","ConvertFrom-SseChunk","Test-ValidIpv4Octets","Set-ChatBestEndpoint") },
    @{ Name = "14-bugbounty";        Path = "modules/14-bugbounty/Falsum-BugBounty.ps1";            Loadable = $true;  MinFuncs = 34; Spot = @("Get-BountyPrograms","Register-BountyTarget","Test-BountyScopeRegistered","Start-BountyRecon","New-BountyReport","Request-BountyActiveTestGate","Test-BountyHygiene","Test-CnameDanglingPattern","Get-BountyDanglingFingerprintTable","Test-BountyScopeFreshness","Update-BountyScopeRecord","Test-BountyCertStatus","Get-BountyHostDisposition","Invoke-BountyCtHostQuery","ConvertFrom-BountyCtRowsDetailed") },
    @{ Name = "21-malware-hunter";   Path = "modules/21-malware-hunter/Falsum-MalwareHunter.ps1";   Loadable = $true;  MinFuncs = 20; Spot = @("Start-MalwareHunt","Stop-MalwareProcess","Get-PUPList","Test-MalwareHunterHygiene","Test-HunterScoreVerdict","Test-SuspiciousCommandLine","Test-HunterPathVerdict","Get-ScheduledTaskPersistence","Get-WmiEventPersistence","Remove-AutostartEntry","Get-QuarantineList","Restore-QuarantinedFile","Export-MalwareHuntReport") },
    @{ Name = "22-tracker-block";     Path = "modules/22-tracker-block/Falsum-TrackerBlock.ps1";     Loadable = $true;  MinFuncs = 12; Spot = @("Get-TrackerBlocks","Add-TrackerBlock","Remove-TrackerBlock","Clear-TrackerBlocks","Import-BlockList","Install-StarterBlocks","Test-TrackerBlockHygiene","Test-HostsMarkers","Restore-HostsBackup","Test-TrackerBlockHealth","Clear-OldHostsBackups","Get-HostsBackupList") },
    @{ Name = "23-fraud-pack";        Path = "modules/23-fraud-pack/Falsum-FraudPack.ps1";         Loadable = $true;  MinFuncs = 12; Spot = @("Get-FraudChecklist","New-FraudPack","Add-FraudTimelineEntry","Get-FraudTimeline","Compress-FraudPack","Test-FraudPackIntegrity","New-FraudManifest","Test-FraudDateFormat","Get-FraudPackOutDir","Get-IdentityTheftLockdown","Test-FraudPackHygiene") },
    @{ Name = "launcher";            Path = "Falsum.ps1";                                          Loadable = $false; MinFuncs = 23; Spot = @() }
)

Write-Host "==============================================================="
Write-Host "BLACKBOX full test harness — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "==============================================================="

foreach ($m in $modules) {
    $path = Join-Path $repoRoot $m.Path
    Write-Host ""
    Write-Host "[*] Module: $($m.Name)"

    if (-not (Test-Path $path)) {
        Write-TestResult "$($m.Name): file exists" $false "missing: $path"
        continue
    }
    Write-TestResult "$($m.Name): file exists" $true ""

    # 1. Parse (PSParser equivalent — .NET Parser)
    try {
        $pr = Test-FileParse $path
        Write-TestResult "$($m.Name): parse (no syntax errors)" $pr.ok $pr.msg
    } catch {
        Write-TestResult "$($m.Name): parse (no syntax errors)" $false $_.Exception.Message
    }

    # 2. Balance check
    try {
        $br = Test-Balance $path
        Write-TestResult "$($m.Name): balance { } ( ) [ ]" $br.ok $br.msg
    } catch {
        Write-TestResult "$($m.Name): balance { } ( ) [ ]" $false $_.Exception.Message
    }

    # 3. Function count via AST
    try {
        $names = Get-FileFunctionNames $path
        $ok = ($names.Count -ge $m.MinFuncs)
        Write-TestResult "$($m.Name): function count >= $($m.MinFuncs) (found $($names.Count))" $ok ""
    } catch {
        Write-TestResult "$($m.Name): function count" $false $_.Exception.Message
    }

    # 4. Load + spot-check exported functions
    if ($m.Loadable) {
        try {
            . $path
            $missing = @()
            foreach ($fn in $m.Spot) {
                if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { $missing += $fn }
            }
            if ($missing.Count -eq 0) {
                Write-TestResult "$($m.Name): load + $($m.Spot.Count) spot functions present" $true ""
            } else {
                Write-TestResult "$($m.Name): load + spot functions present" $false ("missing: " + ($missing -join ", "))
            }
        } catch {
            Write-TestResult "$($m.Name): load" $false $_.Exception.Message
        }
    } else {
        Write-TestResult "$($m.Name): load skipped (auto-executes; parse is the gate)" $true ""
    }
}

# ---- 5. Coherence core determinism: same input twice -> identical output ----
Write-Host ""
Write-Host "[*] Coherence core determinism"
try {
    $utc = "2026-01-01T00:00:00Z"
    $d1 = @{ port = 443; process = "chrome.exe" }
    $e1a = New-EvidenceItem -id "t1" -type "process-port" -data $d1 -source "netstat" -utc $utc
    $e1b = New-EvidenceItem -id "t1" -type "process-port" -data $d1 -source "netstat" -utc $utc
    $det1 = (ConvertTo-CanonicalJson $e1a) -eq (ConvertTo-CanonicalJson $e1b)
    Write-TestResult "coherence: New-EvidenceItem deterministic" $det1 ""

    $b = New-EvidenceItem -id "t2" -type "port-service" -data @{ port = 443; process = "chrome.exe" } -source "iana" -utc $utc
    $c1 = Test-Coherence -a $e1a -b $b -check "process-port"
    $c2 = Test-Coherence -a $e1b -b $b -check "process-port"
    $det2 = ($c1.score -eq $c2.score) -and ($c1.score -eq 100)
    Write-TestResult "coherence: Test-Coherence deterministic (score 100)" $det2 "got $($c1.score)/$($c2.score)"

    $r1 = New-Receipt -conclusion "test conclusion" -evidenceHashes @($e1a.sha256) -prevHash "" -utc $utc
    $r2 = New-Receipt -conclusion "test conclusion" -evidenceHashes @($e1a.sha256) -prevHash "" -utc $utc
    $det3 = ($r1.receipt -eq $r2.receipt) -and ($r1.receipt.Length -eq 96)
    Write-TestResult "coherence: New-Receipt deterministic (SHA-384)" $det3 "len=$($r1.receipt.Length)"

    $r3 = New-Receipt -conclusion "chain-2" -evidenceHashes @($e1a.sha256) -prevHash $r1.receipt -utc $utc
    $chain = Test-ReceiptChain -receipts @($r1, $r3)
    Write-TestResult "coherence: Test-ReceiptChain valid" ($chain.valid -eq $true) $chain.reason
} catch {
    Write-TestResult "coherence: determinism suite" $false $_.Exception.Message
}

# ---- 6. Vault: 100 appends then verify ----
Write-Host ""
Write-Host "[*] Vault 100-append stress"
try {
    $tmpVault = Join-Path $env:TEMP ("bb-test-vault-" + [guid]::NewGuid().ToString("N"))
    $vault = New-Vault -path $tmpVault
    for ($i = 1; $i -le 100; $i++) {
        Add-VaultEntry -vault $vault -type "test" -data @{ i = $i; note = "harness append $i" } | Out-Null
    }
    $vr = Verify-Vault -vault $vault
    $ok = ($vr.valid -eq $true) -and ($vr.entries -eq 101)
    Write-TestResult "vault: 100 appends + chain verifies" $ok "entries=$($vr.entries) reason=$($vr.reason)"
    if (Test-Path $tmpVault) { Remove-Item -Recurse -Force $tmpVault }
} catch {
    Write-TestResult "vault: 100 appends + chain verifies" $false $_.Exception.Message
}

# ---- 7. Vault hygiene battery ----
Write-Host ""
Write-Host "[*] Vault hygiene self-test"
try {
    $vh = Test-VaultHygiene
    Write-TestResult "vault: Test-VaultHygiene all pass" ($vh -eq $true) "all-pass=$vh"
} catch {
    Write-TestResult "vault: Test-VaultHygiene all pass" $false $_.Exception.Message
}

# ---- 8. Packet-witness hygiene battery ----
Write-Host ""
Write-Host "[*] Packet-witness hygiene self-test"
try {
    $pw = Test-PacketWitnessHygiene
    Write-TestResult "packet-witness: Test-PacketWitnessHygiene all pass" ($pw -eq $true) "all-pass=$pw"
} catch {
    Write-TestResult "packet-witness: Test-PacketWitnessHygiene all pass" $false $_.Exception.Message
}

# ---- 9. Netscan hygiene battery ----
Write-Host ""
Write-Host "[*] Netscan hygiene self-test"
try {
    $ns = Test-NetScanHygiene
    Write-TestResult "netscan: Test-NetScanHygiene all pass" ($ns -eq $true) "all-pass=$ns"
} catch {
    Write-TestResult "netscan: Test-NetScanHygiene all pass" $false $_.Exception.Message
}

# ---- 10. OSINT hygiene battery ----
Write-Host ""
Write-Host "[*] OSINT hygiene self-test"
try {
    $oh = Test-OsintHygiene
    Write-TestResult "osint: Test-OsintHygiene all pass" ($oh -eq $true) "all-pass=$oh"
} catch {
    Write-TestResult "osint: Test-OsintHygiene all pass" $false $_.Exception.Message
}

# ---- 11. People-track hygiene battery ----
Write-Host ""
Write-Host "[*] People-track hygiene self-test"
try {
    $pth = Test-PeopleTrackHygiene
    Write-TestResult "people-track: Test-PeopleTrackHygiene all pass" ($pth -eq $true) "all-pass=$pth"
} catch {
    Write-TestResult "people-track: Test-PeopleTrackHygiene all pass" $false $_.Exception.Message
}

# ---- 12. Vuln-check hygiene battery ----
Write-Host ""
Write-Host "[*] Vuln-check hygiene self-test"
try {
    $vch = Test-VulnCheckHygiene
    Write-TestResult "vuln-check: Test-VulnCheckHygiene all pass" ($vch -eq $true) "all-pass=$vch"
} catch {
    Write-TestResult "vuln-check: Test-VulnCheckHygiene all pass" $false $_.Exception.Message
}

# ---- 12b. PHP-shield hygiene battery ----
Write-Host ""
Write-Host "[*] PHP-shield hygiene self-test"
try {
    $psh = Test-PhpShieldHygiene
    Write-TestResult "php-shield: Test-PhpShieldHygiene all pass" ($psh -eq $true) "all-pass=$psh"
} catch {
    Write-TestResult "php-shield: Test-PhpShieldHygiene all pass" $false $_.Exception.Message
}

# ---- 12c. Bugbounty hygiene battery ----
Write-Host ""
Write-Host "[*] Bugbounty hygiene self-test"
try {
    $bh = Test-BountyHygiene
    Write-TestResult "bugbounty: Test-BountyHygiene all pass" ($bh -eq $true) "all-pass=$bh"
} catch {
    Write-TestResult "bugbounty: Test-BountyHygiene all pass" $false $_.Exception.Message
}

# ---- 12d. Tracker-block hygiene battery ----
Write-Host ""
Write-Host "[*] Tracker-block hygiene self-test"
try {
    $tb = Test-TrackerBlockHygiene
    Write-TestResult "tracker-block: Test-TrackerBlockHygiene all pass" ($tb -eq $true) "all-pass=$tb"
} catch {
    Write-TestResult "tracker-block: Test-TrackerBlockHygiene all pass" $false $_.Exception.Message
}

# ---- 12e. Fraud-pack hygiene battery ----
Write-Host ""
Write-Host "[*] Fraud-pack hygiene self-test"
try {
    $fp = Test-FraudPackHygiene
    Write-TestResult "fraud-pack: Test-FraudPackHygiene all pass" ($fp -eq $true) "all-pass=$fp"
} catch {
    Write-TestResult "fraud-pack: Test-FraudPackHygiene all pass" $false $_.Exception.Message
}

# ---- 12f. Evidence-sweep hygiene battery (subprocess: the sweep auto-executes,
# so it is never dot-sourced; -TestHygiene runs the battery only) ----
Write-Host ""
Write-Host "[*] Evidence-sweep hygiene self-test"
try {
    $sweepPath = Join-Path $repoRoot "modules/01-evidence-sweep/Falsum-Sweep.ps1"
    & $sweepPath -TestHygiene | Out-Null
    Write-TestResult "evidence-sweep: Test-SweepHygiene all pass" ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"
} catch {
    Write-TestResult "evidence-sweep: Test-SweepHygiene all pass" $false $_.Exception.Message
}

# ---- Summary ----
Write-Host ""
Write-Host "==============================================================="
Write-Host "RESULT: $($script:passCount) passed, $($script:failCount) failed"
Write-Host "==============================================================="

$script:results | Format-Table -AutoSize | Out-Host

if ($script:failCount -gt 0) { exit 1 } else { exit 0 }
