<#
BLACKBOX Module 01 — EVIDENCE SWEEP (hardened v1.3)
Automates the full machine-state forensic capture.
Windows-native PowerShell. Run: powershell -ExecutionPolicy Bypass -File Falsum-Sweep.ps1

Every output is timestamped, SHA-256 hashed, and listed in MANIFEST.csv.
Nothing is modified on the machine. Collection only.
44 steps: identity, network, processes (+SHA-256 of each running executable,
deduplicated by path), scheduled tasks, services, drivers, WMI persistence +
bindings, firewall, hosts, boot, registry persistence + extended (IFEO
debuggers, BootExecute, ShellServiceObjectDelayLoad, Explorer Run, WOW6432Node
32-bit Run keys), certs, Chromium extension inventory (ALL profiles: Chrome +
Edge, Default/Profile N/Guest), event logs, startup folders (+.lnk target
resolution), PowerShell profiles, DNS cache, ARP, local accounts + admin
group, installed-software inventory, USBSTOR history, network shares + RDP
state, Defender status + exclusions, network config, hotfix list, environment
+ PATH, PowerShell logging policy, Prefetch listing, Defender threat
detections, time-sync status, Security-log triage (4625/4720/4732/4740),
WinHTTP proxy config, BITS jobs, collection metadata.
VERIFY MODE: -Verify -VerifyDir <sweep dir> [-ExpectedHash <sha256>]
[-VerifyReportPath <path>] re-hashes every listed file against MANIFEST.csv
and reports OK / TAMPERED / MISSING. [EXTRA] flags files present in the
directory but absent from the manifest (planted evidence) — extras now FAIL
the verify (exit 2), they are tampering, not noise. MANIFEST-HASH.txt is
cross-checked automatically: if its recorded hash disagrees with MANIFEST.csv
the manifest was rewritten without the receipt (exit 3). Honest limit: that
receipt check catches INCONSISTENCY only — rewriting both files defeats it,
which is what -ExpectedHash anchors against. A VERIFY-REPORT-<stamp>.txt is
written OUTSIDE the sweep dir by default (sibling dir) so a later verify
never flags the report itself as [EXTRA]; its SHA-256 is printed.
-ExpectedHash anchors MANIFEST.csv itself: the hash is printed at collection
time (copy it into the vault / chat) and compared on verify — mismatch means
the manifest was rewritten, exit code 3.
-TESTHYGIENE: -TestHygiene runs the offline self-test battery (26 checks over
the pure helpers) and exits 0/1 without collecting anything.
All evidence timestamps are UTC with a trailing Z (Get-SweepUtcStamp, one
source of truth) — local-time-without-zone was a forensic ambiguity.
HARDENING v1.3: (1) FIXED a real step-killer — Get-SweepHotfixDate null-guards
InstalledOn (some hotfix rows carry no date; the bare .ToString() call threw
and failed the entire 36-hotfixes step). (2) MyDocuments-empty guard via
Get-SweepSpecialFolderPath (the Desktop-empty bug class: Server Core /
redirected profiles return "" and Join-Path then builds a relative path the
user never finds). (3) Process-hash dedup by exe path — the same binary was
hashed once per process. (4) 32-bit WOW6432Node Run/RunOnce added to step 16.
(5) Extension inventory now walks ALL Chromium profiles (Chrome + Edge).
(6) Startup-folder .lnk targets resolved via WScript.Shell. (7) NEW steps
42-44: Security-log triage, WinHTTP proxy, BITS jobs. (8) Verify now
cross-checks MANIFEST-HASH.txt, fails on [EXTRA], writes a hashed verify
report outside the dir, and takes its exit code from ConvertTo-SweepVerifyVerdict.
(9) Timestamps standardized to UTC-Z. (10) Test-SweepHygiene offline battery
(26 checks), runnable via -TestHygiene and wired into tests/Test-All.ps1 section 12f.
#>

param(
    [switch]$Verify,
    [string]$VerifyDir,
    [string]$ExpectedHash,
    [string]$VerifyReportPath,
    [switch]$TestHygiene
)

# ---------------------------------------------------------------------------
# Pure helpers (offline-testable, no machine calls except Get-Date/env)
# ---------------------------------------------------------------------------

function Get-SweepUtcStamp {
    # One source of truth for every evidence timestamp this module writes.
    # Local time without a zone is a forensic ambiguity; UTC with trailing Z
    # is not. Callers use this, never a bare Get-Date format string.
    return ((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + "Z")
}

function Get-SweepHotfixDate {
    param([object]$Hotfix)
    # InstalledOn is $null on some hotfix rows. The old code called
    # $_.InstalledOn.ToString("yyyy-MM-dd") inline, which THREW on those rows
    # and failed the entire 36-hotfixes step through Save-Step's catch.
    # "unknown" keeps the row and the step alive.
    if ($null -ne $Hotfix -and $null -ne $Hotfix.InstalledOn) {
        return $Hotfix.InstalledOn.ToString("yyyy-MM-dd")
    }
    return "unknown"
}

function Test-SweepChromeProfileDir {
    param([string]$Name)
    # Valid Chromium profile directory names. Everything else under
    # "User Data" (Crash Reports, ShaderCache, ...) is skipped so junk never
    # becomes a reported "profile".
    if ($Name -eq "Default") { return $true }
    if ($Name -eq "Guest Profile") { return $true }
    return ($Name -match "^Profile \d+$")
}

function Test-SweepExpectedByDesign {
    param([string]$FileName)
    # Files the design itself (or a prior verify) puts in a sweep dir that
    # must NOT be flagged [EXTRA] on a later verify. In particular, a
    # VERIFY-REPORT-*.txt written INSIDE the dir would otherwise self-flag.
    if ($FileName -eq "MANIFEST.csv") { return $true }
    if ($FileName -eq "MANIFEST-HASH.txt") { return $true }
    return ($FileName -like "VERIFY-REPORT-*.txt")
}

function ConvertTo-SweepVerifyVerdict {
    param(
        [int]$Ok,
        [int]$Tampered,
        [int]$Missing,
        [int]$Extra,
        [bool]$ManifestTampered
    )
    # Single source of truth for verify exit semantics. Planted evidence
    # ([EXTRA]) is tampering: it fails the verify, not just a warning line.
    if ($ManifestTampered) { return @{ ExitCode = 3; Verdict = "MANIFEST-TAMPERED" } }
    if ($Tampered -gt 0 -or $Missing -gt 0 -or $Extra -gt 0) {
        return @{ ExitCode = 2; Verdict = "TAMPER-DETECTED" }
    }
    return @{ ExitCode = 0; Verdict = "CLEAN" }
}

function Get-SweepSpecialFolderPath {
    param([string]$Name)
    # Same Desktop-empty bug class the mail-shield and fraud-pack passes
    # closed: [Environment]::GetFolderPath returns "" on Server Core /
    # redirected profiles, and Join-Path on "" builds a RELATIVE path the
    # user never finds. Callers must check for "" and skip.
    try {
        $p = [Environment]::GetFolderPath($Name)
    } catch {
        return ""
    }
    if ([string]::IsNullOrWhiteSpace($p)) { return "" }
    return $p
}

function Test-SweepHygiene {
    # Offline self-test battery. Scope-safe: the $add scriptblock RETURNS its
    # row and callers append the OUTPUT ($results += &$add ...) — appending
    # to $results INSIDE a scriptblock invoked via & writes to a child scope
    # and silently vanishes (the false-green bug the active-defense pass caught).
    $results = @()
    $add = {
        param([string]$name, [bool]$cond, [string]$detail)
        [pscustomobject]@{
            name = $name
            result = $(if ($cond) { "pass" } else { "fail" })
            detail = $detail
        }
    }

    # UTC stamp shape: "2026-10-30 09:38:00Z"
    $stamp = Get-SweepUtcStamp
    $results += &$add "stamp-format-utc-z" ($stamp -match "^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z$") $stamp

    # Hotfix date null-guard (the fixed bug)
    $withDate = [pscustomobject]@{ InstalledOn = [datetime]"2026-10-14" }
    $results += &$add "hotfix-date-present" ((Get-SweepHotfixDate $withDate) -eq "2026-10-14") (Get-SweepHotfixDate $withDate)
    $nullDate = [pscustomobject]@{ InstalledOn = $null }
    $results += &$add "hotfix-date-null" ((Get-SweepHotfixDate $nullDate) -eq "unknown") (Get-SweepHotfixDate $nullDate)
    $noProp = [pscustomobject]@{ HotFixID = "KB1" }
    $results += &$add "hotfix-date-missing-prop" ((Get-SweepHotfixDate $noProp) -eq "unknown") (Get-SweepHotfixDate $noProp)
    $results += &$add "hotfix-date-null-obj" ((Get-SweepHotfixDate $null) -eq "unknown") (Get-SweepHotfixDate $null)

    # Chromium profile name classifier
    $results += &$add "profile-default" (Test-SweepChromeProfileDir "Default") "Default"
    $results += &$add "profile-guest" (Test-SweepChromeProfileDir "Guest Profile") "Guest Profile"
    $results += &$add "profile-numbered" (Test-SweepChromeProfileDir "Profile 3") "Profile 3"
    $results += &$add "profile-bad-number" (-not (Test-SweepChromeProfileDir "Profile X")) "Profile X"
    $results += &$add "profile-crash-reports" (-not (Test-SweepChromeProfileDir "Crash Reports")) "Crash Reports"
    $results += &$add "profile-trailing-space" (-not (Test-SweepChromeProfileDir "Default ")) "Default "
    $results += &$add "profile-empty" (-not (Test-SweepChromeProfileDir "")) "(empty)"

    # Expected-by-design file classifier
    $results += &$add "bydesign-manifest" (Test-SweepExpectedByDesign "MANIFEST.csv") "MANIFEST.csv"
    $results += &$add "bydesign-hash-receipt" (Test-SweepExpectedByDesign "MANIFEST-HASH.txt") "MANIFEST-HASH.txt"
    $results += &$add "bydesign-verify-report" (Test-SweepExpectedByDesign "VERIFY-REPORT-20261030_093900.txt") "VERIFY-REPORT-20261030_093900.txt"
    $results += &$add "bydesign-step-file" (-not (Test-SweepExpectedByDesign "01-systeminfo.txt")) "01-systeminfo.txt"
    $results += &$add "bydesign-case-insensitive" (Test-SweepExpectedByDesign "manifest.csv") "manifest.csv (lowercase matches - Windows FS is case-insensitive)"
    $results += &$add "bydesign-report-wildcard-ci" (Test-SweepExpectedByDesign "verify-report-x.txt") "verify-report-x.txt (lowercase wildcard)"

    # Verify exit semantics
    $v = ConvertTo-SweepVerifyVerdict -Ok 44 -Tampered 0 -Missing 0 -Extra 0 -ManifestTampered $false
    $results += &$add "verdict-clean" (($v.ExitCode -eq 0) -and ($v.Verdict -eq "CLEAN")) "exit=$($v.ExitCode) verdict=$($v.Verdict)"
    $v = ConvertTo-SweepVerifyVerdict -Ok 43 -Tampered 1 -Missing 0 -Extra 0 -ManifestTampered $false
    $results += &$add "verdict-tampered" (($v.ExitCode -eq 2) -and ($v.Verdict -eq "TAMPER-DETECTED")) "exit=$($v.ExitCode)"
    $v = ConvertTo-SweepVerifyVerdict -Ok 43 -Tampered 0 -Missing 1 -Extra 0 -ManifestTampered $false
    $results += &$add "verdict-missing" ($v.ExitCode -eq 2) "exit=$($v.ExitCode)"
    $v = ConvertTo-SweepVerifyVerdict -Ok 44 -Tampered 0 -Missing 0 -Extra 1 -ManifestTampered $false
    $results += &$add "verdict-extra-fails" ($v.ExitCode -eq 2) "planted evidence fails the verify"
    $v = ConvertTo-SweepVerifyVerdict -Ok 44 -Tampered 0 -Missing 0 -Extra 0 -ManifestTampered $true
    $results += &$add "verdict-manifest-tampered" (($v.ExitCode -eq 3) -and ($v.Verdict -eq "MANIFEST-TAMPERED")) "exit=$($v.ExitCode)"
    $v = ConvertTo-SweepVerifyVerdict -Ok 0 -Tampered 2 -Missing 0 -Extra 0 -ManifestTampered $true
    $results += &$add "verdict-manifest-wins" ($v.ExitCode -eq 3) "manifest tamper outranks file tamper"

    # Special-folder guard never throws, returns a string, "" when unresolvable
    $bogus = Get-SweepSpecialFolderPath "NonExistentSpecialFolderXYZ"
    $results += &$add "specialfolder-bogus-empty" ($bogus -eq "") "bogus name -> empty string, no throw"
    $desk = Get-SweepSpecialFolderPath "Desktop"
    $results += &$add "specialfolder-string" ($desk -is [string]) "Desktop returns a string (empty allowed on Server Core)"

    return $results
}

# ---------------------------------------------------------------------------
# Mode gates (helpers above are already defined)
# ---------------------------------------------------------------------------

if ($TestHygiene) {
    # Offline self-test: no collection, no verify, just the battery.
    $rows = Test-SweepHygiene
    $pass = @($rows | Where-Object { $_.result -eq "pass" }).Count
    $fail = @($rows | Where-Object { $_.result -eq "fail" }).Count
    foreach ($r in $rows) {
        $tag = $r.result.ToUpper()
        if ($r.result -eq "pass") { Write-Host "[$tag] $($r.name)" }
        else { Write-Host "[$tag] $($r.name) -- $($r.detail)" }
    }
    Write-Host ""
    Write-Host "sweep hygiene: $pass pass, $fail fail"
    if ($fail -gt 0) { exit 1 } else { exit 0 }
}

if ($Verify) {
    # Tamper-evidence verification of a prior sweep. No collection happens.
    if (-not $VerifyDir -or -not (Test-Path $VerifyDir)) {
        Write-Host "usage: Falsum-Sweep.ps1 -Verify -VerifyDir <sweep output dir> [-ExpectedHash <sha256>] [-VerifyReportPath <path>]"
        exit 1
    }
    $mp = Join-Path $VerifyDir "MANIFEST.csv"
    if (-not (Test-Path $mp)) {
        Write-Host "MANIFEST.csv not found in $VerifyDir - cannot verify."
        exit 1
    }
    $manifestTampered = $false

    if ($ExpectedHash) {
        $manifestHash = (Get-FileHash -Path $mp -Algorithm SHA256).Hash
        if ($manifestHash -ne $ExpectedHash.ToUpperInvariant()) {
            Write-Host "[MANIFEST TAMPERED] MANIFEST.csv hash $manifestHash does not match expected $ExpectedHash"
            Write-Host "The manifest itself was rewritten - every row in it is suspect."
            $manifestTampered = $true
        } else {
            Write-Host "[OK] MANIFEST.csv hash matches expected value."
        }
    }

    # In-dir receipt cross-check: catches a manifest rewritten WITHOUT its
    # MANIFEST-HASH.txt receipt being updated (inconsistency). Honest limit:
    # rewriting BOTH files defeats this - that is what -ExpectedHash anchors
    # against, because the expected hash lives outside the sweep dir.
    if (-not $manifestTampered) {
        $receiptPath = Join-Path $VerifyDir "MANIFEST-HASH.txt"
        if (Test-Path $receiptPath) {
            $recorded = $null
            foreach ($line in (Get-Content $receiptPath -ErrorAction SilentlyContinue)) {
                if ($line -match "^SHA256\(MANIFEST\.csv\)\s*=\s*([0-9A-Fa-f]{64})") {
                    $recorded = $Matches[1]; break
                }
            }
            if ($recorded) {
                $actual = (Get-FileHash -Path $mp -Algorithm SHA256).Hash
                if ($actual -ne $recorded.ToUpperInvariant()) {
                    Write-Host "[MANIFEST TAMPERED] MANIFEST.csv hash $actual does not match the MANIFEST-HASH.txt receipt $recorded"
                    Write-Host "The manifest was rewritten without updating its receipt - every row in it is suspect."
                    $manifestTampered = $true
                } else {
                    Write-Host "[OK] MANIFEST.csv matches its in-dir MANIFEST-HASH.txt receipt."
                }
            } else {
                Write-Host "[WARN] MANIFEST-HASH.txt present but has no parseable SHA256 line - skipping receipt check."
            }
        } else {
            Write-Host "[WARN] No MANIFEST-HASH.txt in $VerifyDir - receipt cross-check skipped (pre-v1.2 sweeps lack it)."
        }
    }

    $rows = Import-Csv -Path $mp
    $listed = @{}
    foreach ($r in $rows) { $listed[$r.file] = $true }
    $ok = 0; $bad = 0; $miss = 0; $extra = 0
    $badFiles = @(); $missFiles = @(); $extraFiles = @()
    foreach ($r in $rows) {
        $f = Join-Path $VerifyDir $r.file
        if (-not (Test-Path $f)) {
            $miss++; $missFiles += $r.file; Write-Host "[MISSING]  $($r.file)"; continue
        }
        $h = (Get-FileHash -Path $f -Algorithm SHA256).Hash
        if ($h -eq $r.sha256) { $ok++ } else { $bad++; $badFiles += $r.file; Write-Host "[TAMPERED] $($r.file)" }
    }
    # Extra files: present on disk but absent from the manifest (planted
    # evidence). This is tampering, not noise: extras FAIL the verify.
    foreach ($f in (Get-ChildItem $VerifyDir -File -ErrorAction SilentlyContinue)) {
        if (-not $listed.ContainsKey($f.Name) -and -not (Test-SweepExpectedByDesign $f.Name)) {
            $extra++; $extraFiles += $f.Name; Write-Host "[EXTRA]    $($f.Name) (not in manifest - planted evidence)"
        }
    }

    $verdict = ConvertTo-SweepVerifyVerdict -Ok $ok -Tampered $bad -Missing $miss -Extra $extra -ManifestTampered $manifestTampered
    Write-Host ""
    Write-Host "Verify complete: $ok ok, $bad tampered, $miss missing, $extra extra (of $(@($rows).Count) listed) - verdict $($verdict.Verdict), exit $($verdict.ExitCode)"

    # Verify report: written OUTSIDE the sweep dir by default so a later
    # verify never flags the report itself as [EXTRA].
    if ([string]::IsNullOrWhiteSpace($VerifyReportPath)) {
        $parent = Split-Path -Parent $VerifyDir
        if ([string]::IsNullOrWhiteSpace($parent)) { $parent = $PWD }
        $VerifyReportPath = Join-Path $parent ("VERIFY-REPORT-" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt")
    }
    $reportLines = @(
        "BLACKBOX sweep verify report"
        "verified      = $(Get-SweepUtcStamp)"
        "sweep dir     = $VerifyDir"
        "manifest rows = $(@($rows).Count)"
        "ok            = $ok"
        "tampered      = $bad"
        "missing       = $miss"
        "extra         = $extra"
        "verdict       = $($verdict.Verdict)"
        "exit          = $($verdict.ExitCode)"
        ""
    )
    if ($manifestTampered) { $reportLines += "MANIFEST.csv itself failed the tamper check (see console output)."; $reportLines += "" }
    if ($badFiles.Count -gt 0)  { $reportLines += "TAMPERED FILES:"; $reportLines += ($badFiles | ForEach-Object { "  $_" }); $reportLines += "" }
    if ($missFiles.Count -gt 0) { $reportLines += "MISSING FILES:"; $reportLines += ($missFiles | ForEach-Object { "  $_" }); $reportLines += "" }
    if ($extraFiles.Count -gt 0) { $reportLines += "EXTRA FILES (not in manifest):"; $reportLines += ($extraFiles | ForEach-Object { "  $_" }); $reportLines += "" }
    $reportLines += "receipt cross-check: MANIFEST-HASH.txt compared against MANIFEST.csv when present (inconsistency check only - see header comment)."
    [System.IO.File]::WriteAllText($VerifyReportPath, ($reportLines -join "`r`n"))
    $reportHash = (Get-FileHash -Path $VerifyReportPath -Algorithm SHA256).Hash
    Write-Host "Verify report: $VerifyReportPath"
    Write-Host "Report SHA-256: $reportHash"
    exit $verdict.ExitCode
}

$ErrorActionPreference = "Continue"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outDir = Join-Path $PWD "blackbox-sweep-$stamp"
New-Item -ItemType Directory -Path $outDir | Out-Null
$manifest = @()

function Save-Step {
    param([string]$name, [scriptblock]$block)
    $file = Join-Path $outDir ($name + ".txt")
    Write-Host "[*] $name"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = "ok"
    try {
        # -Width 4096: Out-String defaults to the console width and TRUNCATES
        # long lines, which silently mutilates forensic output (WMI property
        # lists, service command lines, cert dumps). 4096 preserves them.
        $output = & $block 2>&1 | Out-String -Width 4096
        [System.IO.File]::WriteAllText($file, $output)
    } catch {
        $status = "failed"
        [System.IO.File]::WriteAllText($file, "COLLECTION FAILED: $($_.Exception.Message)")
    }
    $sw.Stop()
    $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
    $bytes = (Get-Item $file).Length
    # Semantics: $LASTEXITCODE holds the exit code of the LAST NATIVE command
    # run anywhere before this line (cmdlets do not touch it). For blocks whose
    # last native command is the meaningful one this is exact; blocks ending in
    # cmdlets report the most recent native command's code. Read the step text
    # for the full story; this column is a triage signal, not proof.
    $code = $LASTEXITCODE
    $script:manifest += [pscustomobject]@{
        file = $name + ".txt"; sha256 = $hash; bytes = $bytes
        ms = $sw.ElapsedMilliseconds; exitcode = "$code"; status = $status
        collected = (Get-SweepUtcStamp)
    }
}

# 01 system identity
Save-Step "01-systeminfo" { systeminfo }
Save-Step "02-whoami" { whoami /all }

# 03 network listeners with process attribution
Save-Step "03-netstat-ano" { netstat -ano }
Save-Step "04-netstat-b" { netstat -anob }

# 05 processes
Save-Step "05-tasklist" { tasklist /v /fo LIST }
Save-Step "06-tasklist-svc" { tasklist /svc /fo LIST }

# 07 scheduled tasks
Save-Step "07-schtasks" { schtasks /query /fo LIST /v }

# 08 services
Save-Step "08-services" { sc query state= all }
Save-Step "09-drivers" { driverquery /v /fo LIST }

# 10 WMI persistence check (command-line / ActiveScript consumers only)
Save-Step "10-wmi-persistence" {
    Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer |
        Where-Object { $_.__CLASS -match "CommandLine|ActiveScript" } |
        Format-List *
}

# 11 firewall
Save-Step "11-firewall-rules" { netsh advfirewall firewall show rule name=all verbose }
Save-Step "12-firewall-state" { netsh advfirewall show allprofiles state }

# 13 hosts file
Save-Step "13-hosts" { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" }

# 14 boot / hypervisor
Save-Step "14-bcdedit" { bcdedit /enum all }
Save-Step "15-dsregcmd" { dsregcmd /status }

# 16 registry persistence points (incl. 32-bit WOW6432Node Run keys)
Save-Step "16-reg-run" {
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
}

# 17 certificates
Save-Step "17-certutil-root" { certutil -store root }

# 18 Chromium extension inventory: ALL profiles, Chrome + Edge
# (v1.2 only read Chrome's Default profile - most users have several.)
Save-Step "18-chrome-extensions" {
    $roots = @(
        (Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data")
    )
    $found = $false
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        "== browser data: $root =="
        $profiles = Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-SweepChromeProfileDir $_.Name }
        if (-not $profiles) { "  (no profile directories found)" }
        foreach ($prof in $profiles) {
            "  -- profile: $($prof.Name) --"
            $prefs = Join-Path $prof.FullName "Secure Preferences"
            if (Test-Path $prefs) {
                try {
                    $j = Get-Content $prefs -Raw | ConvertFrom-Json
                    if ($j.extensions -and $j.extensions.settings) {
                        $ids = $j.extensions.settings | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                        if ($ids) { $ids | ForEach-Object { "     ext: $_" } }
                        else { "     (no extensions recorded)" }
                        $found = $true
                    } else {
                        "     (extensions section absent in Secure Preferences)"
                    }
                } catch {
                    "     (Secure Preferences unreadable: $($_.Exception.Message))"
                }
            } else {
                "     (Secure Preferences not found)"
            }
        }
        ""
    }
    if (-not $found) { "(no Chromium browser profiles with extensions found)" }
}

# 19 recent event log errors (System + Security, last 24h)
Save-Step "19-eventlog-system" {
    Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 200 -ErrorAction SilentlyContinue |
        Format-List TimeCreated, Id, ProviderName, Message
}

# 20 listening-port to process cross-map
Save-Step "20-port-process-map" {
    $conns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        try {
            $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            "$($c.LocalAddress):$($c.LocalPort)  PID $($c.OwningProcess)  $($p.ProcessName)  $($p.Path)"
        } catch { "$($c.LocalAddress):$($c.LocalPort)  PID $($c.OwningProcess)  (process exited)" }
    }
}

# 21 running-process executable hashes (SHA-256 of each process's main module,
# deduplicated by path - the same binary used to be hashed once per process)
Save-Step "21-process-hashes" {
    $procs = Get-Process -ErrorAction SilentlyContinue
    $seen = @{}
    foreach ($p in $procs) {
        try {
            $exe = $p.MainModule.FileName
            if (-not $exe -or -not (Test-Path $exe)) {
                "$($p.Id)  $($p.ProcessName)  (no file path - access denied or exited)"
                continue
            }
            $key = $exe.ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = (Get-FileHash -Path $exe -Algorithm SHA256 -ErrorAction Stop).Hash
            }
            "$($p.Id)  $($p.ProcessName)  $exe  $($seen[$key])"
        } catch {
            "$($p.Id)  $($p.ProcessName)  (hash failed: $($_.Exception.Message))"
        }
    }
}

# 22 DNS resolver cache
Save-Step "22-dns-cache" { ipconfig /displaydns }

# 23 ARP table
Save-Step "23-arp" { arp -a }

# 24 startup folders (All Users + current user) - LNK persistence with target resolution
Save-Step "24-startup-folders" {
    $paths = @(
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\StartUp"),
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup")
    )
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    foreach ($sp in $paths) {
        "== $sp =="
        if (Test-Path $sp) {
            $items = Get-ChildItem $sp -ErrorAction SilentlyContinue
            if (-not $items) { "(empty)" }
            foreach ($it in $items) {
                "$($it.Name)  $($it.Length) bytes  $($it.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                if ($shell -and ($it.Extension -eq ".lnk")) {
                    try {
                        $sc = $shell.CreateShortcut($it.FullName)
                        "    -> target: $($sc.TargetPath)"
                        "    -> args:   $($sc.Arguments)"
                        "    -> workdir: $($sc.WorkingDirectory)"
                    } catch {
                        "    -> (shortcut target unreadable: $($_.Exception.Message))"
                    }
                }
            }
        } else { "(not found)" }
        ""
    }
    if (-not $shell) { "(note: WScript.Shell unavailable - .lnk targets not resolved)" }
}

# 25 PowerShell profile scripts present on this machine
Save-Step "25-ps-profiles" {
    # Get-SweepSpecialFolderPath: [Environment]::GetFolderPath("MyDocuments")
    # returns "" on Server Core / redirected profiles; Join-Path on "" builds
    # a relative path the user never finds (the Desktop-empty bug class).
    $docs = Get-SweepSpecialFolderPath "MyDocuments"
    $profiles = @()
    if ($docs) {
        $profiles += Join-Path $docs "WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
        $profiles += Join-Path $docs "PowerShell\Microsoft.PowerShell_profile.ps1"
    } else {
        "(MyDocuments folder unresolvable on this machine - user profiles skipped)"
    }
    $profiles += "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1"
    $profiles += "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1"
    foreach ($pf in $profiles) {
        if (Test-Path $pf) {
            "== PRESENT: $pf =="
            Get-Item $pf | Format-List FullName, Length, LastWriteTime
            "---- content ----"
            Get-Content $pf -Raw
            ""
        } else { "absent: $pf" }
    }
}

# 26 WMI filter-to-consumer bindings (the wiring that fires persistence consumers)
Save-Step "26-wmi-bindings" {
    Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Format-List Filter, Consumer
}

# 27 services with image paths (non-standard paths stand out)
Save-Step "27-service-imagepaths" {
    Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue |
        Sort-Object Name |
        ForEach-Object { "$($_.Name)  [$($_.StartMode)/$($_.State)]  $($_.PathName)" }
}

# 28 collection metadata (receipt-grade context for everything above)
Save-Step "28-collection-metadata" {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
    @(
        "collected      = $(Get-SweepUtcStamp)"
        "machine        = $env:COMPUTERNAME"
        "user           = $($id.Name)"
        "elevated       = $elevated"
        "timezone       = $([System.TimeZoneInfo]::Local.DisplayName)"
        "powershell     = $($PSVersionTable.PSVersion)"
        "os             = $($os.Caption) build $($os.BuildNumber)"
        "module         = Falsum-Sweep.ps1 (hardened v1.3: 44 steps, verify mode with receipt cross-check + extra-fail, -TestHygiene, UTC timestamps)"
    ) -join "`r`n"
}

# 29 local accounts + who holds admin
Save-Step "29-local-accounts" {
    "== net user (all local accounts) =="
    net user
    ""
    "== net localgroup administrators =="
    net localgroup administrators
}

# 30 installed software inventory (registry uninstall keys)
Save-Step "30-installed-software" {
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Sort-Object DisplayName -Unique |
        ForEach-Object { "$($_.DisplayName)  [$($_.DisplayVersion)]  $($_.Publisher)  installed $($_.InstallDate)" }
}

# 31 USB storage device history (USBSTOR enumeration)
Save-Step "31-usbstor" {
    reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" 2>$null
    if ($LASTEXITCODE -ne 0) { "(USBSTOR key not readable - elevation usually required)" }
}

# 32 extended registry persistence: IFEO debuggers, BootExecute, SSODL, Explorer Run
Save-Step "32-reg-persistence-extended" {
    "== Image File Execution Options (Debugger hijacks) =="
    $ifeo = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $parentFull = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $subLines = reg query $ifeo 2>$null
    $hits = 0
    foreach ($l in $subLines) {
        $t = $l.Trim()
        if ($t -match "^HKEY_LOCAL_MACHINE" -and $t -ne $parentFull) {
            $dbg = reg query "$t" /v Debugger 2>$null
            if ($dbg) { $hits++; "== DEBUGGER SET: $t =="; $dbg }
        }
    }
    if ($hits -eq 0) { "(no Debugger values found under IFEO)" }
    ""
    "== Session Manager BootExecute =="
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute 2>$null
    ""
    "== ShellServiceObjectDelayLoad =="
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" 2>$null
    ""
    "== Explorer Run (HKLM + HKCU) =="
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" 2>$null
    reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" 2>$null
}

# 33 network shares + RDP state
Save-Step "33-shares-rdp" {
    "== net share =="
    net share
    ""
    "== Terminal Server fDenyTSConnections (0 = RDP allowed, 1 = denied) =="
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections 2>$null
    ""
    "== qwinsta sessions =="
    try {
        qwinsta 2>$null
    } catch {
        "(qwinsta unavailable: $($_.Exception.Message))"
    }
}

# 34 Defender status + exclusion list (exclusions are attacker gold)
Save-Step "34-defender-state" {
    "== Get-MpComputerStatus =="
    try {
        Get-MpComputerStatus -ErrorAction Stop | Format-List *
    } catch {
        "(unavailable - usually needs admin: $($_.Exception.Message))"
    }
    ""
    "== Get-MpPreference (exclusions) =="
    try {
        Get-MpPreference -ErrorAction Stop | Format-List *
    } catch {
        "(unavailable - usually needs admin: $($_.Exception.Message))"
    }
}

# 35 full network interface config (IP, DHCP, DNS servers at collection time)
Save-Step "35-network-config" { ipconfig /all }

# 36 installed hotfixes (patch state at collection time; null dates tolerated)
Save-Step "36-hotfixes" {
    Get-HotFix -ErrorAction SilentlyContinue |
        Sort-Object InstalledOn |
        ForEach-Object { "$(Get-SweepHotfixDate $_)  $($_.HotFixID)  $($_.Description)" }
}

# 37 environment variables + PATH split one-per-line (PATH hijack visibility)
Save-Step "37-env-path" {
    "== MACHINE environment =="
    [Environment]::GetEnvironmentVariables("Machine").GetEnumerator() |
        Sort-Object Key |
        ForEach-Object { "$($_.Key)=$($_.Value)" }
    ""
    "== PROCESS PATH, one entry per line =="
    $env:PATH -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

# 38 PowerShell logging policy (script-block / module / transcription)
Save-Step "38-ps-logging-policy" {
    $roots = @(
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    )
    foreach ($r in $roots) {
        "== $r =="
        $out = reg query "$r" 2>$null
        if ($out) { $out } else { "(key absent - logging not enforced by policy)" }
        ""
    }
}

# 39 Prefetch listing (recent execution evidence; timestamps, not contents)
Save-Step "39-prefetch" {
    $pf = "$env:SystemRoot\Prefetch"
    if (Test-Path $pf) {
        Get-ChildItem $pf -Filter "*.pf" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            ForEach-Object { "$($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))  $($_.Name)  $($_.Length) bytes" }
    } else {
        "(Prefetch directory not readable - elevation usually required)"
    }
}

# 40 Defender threat detections (recent, admin-gated gracefully)
Save-Step "40-defender-detections" {
    try {
        $d = Get-MpThreatDetection -ErrorAction Stop
        if ($d) {
            $d | ForEach-Object {
                "$($_.InitialDetectionTime)  sev=$($_.SeverityID)  $($_.ThreatID)  $($_.Resources -join '; ')"
            }
        } else { "(no threat detections recorded)" }
    } catch {
        "(unavailable - usually needs admin: $($_.Exception.Message))"
    }
}

# 41 time-sync status (clock integrity underpins every timestamp above)
Save-Step "41-time-sync" {
    "== w32tm /query /status =="
    w32tm /query /status 2>$null
    ""
    "== current UTC =="
    (Get-SweepUtcStamp)
}

# 42 Security-log triage: failed logons, account creations, group additions,
# lockouts in the last 24h (the intrusion signals the System log never carries)
Save-Step "42-security-log-triage" {
    $since = (Get-Date).AddDays(-1)
    $events = @(
        @{ Id = 4625; Label = "FAILED LOGONS (4625) - brute-force / password-spray signal" },
        @{ Id = 4720; Label = "USER ACCOUNTS CREATED (4720) - persistence signal" },
        @{ Id = 4732; Label = "ADDED TO LOCAL GROUP (4732) - privilege-escalation signal" },
        @{ Id = 4740; Label = "ACCOUNTS LOCKED OUT (4740) - brute-force aftermath signal" }
    )
    foreach ($e in $events) {
        "== $($e.Label) - last 24h =="
        try {
            $hits = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$e.Id; StartTime=$since} -MaxEvents 50 -ErrorAction Stop
            $total = @($hits).Count
            "events (display capped at 50): $total"
            foreach ($h in $hits) {
                $firstLine = ($h.Message -split "`n" | Select-Object -First 1).Trim()
                "$($h.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  $firstLine"
            }
        } catch {
            "(unavailable - usually needs admin: $($_.Exception.Message))"
        }
        ""
    }
}

# 43 WinHTTP proxy config (a proxy here redirects ALL WinHTTP traffic - a
# classic quiet persistence / exfil channel; nothing in v1.2 captured it)
Save-Step "43-winhttp-proxy" {
    "== netsh winhttp show proxy =="
    netsh winhttp show proxy
}

# 44 BITS jobs (Background Intelligent Transfer Service is an attacker
# download/persistence channel; bitsadmin is the native inspector)
Save-Step "44-bits-jobs" {
    "== bitsadmin /list /allusers /verbose =="
    bitsadmin /list /allusers /verbose 2>$null
    if ($LASTEXITCODE -ne 0) {
        "(bitsadmin unavailable or insufficient permission - elevation usually required)"
    }
}

# manifest
$manifestPath = Join-Path $outDir "MANIFEST.csv"
$manifest | Export-Csv -Path $manifestPath -NoTypeInformation
$manifestHash = (Get-FileHash -Path $manifestPath -Algorithm SHA256).Hash

# Out-of-band anchor for the manifest itself: a separate receipt file carrying
# the manifest's SHA-256. Copy this value into the vault / chat at collection
# time; -Verify -ExpectedHash <this> later proves the manifest was not rewritten.
# The receipt cross-check runs automatically on every verify (catches a manifest
# rewritten without its receipt; rewriting both defeats it - that is what the
# out-of-band -ExpectedHash anchors against).
$hashReceipt = Join-Path $outDir "MANIFEST-HASH.txt"
$receiptText = @(
    "BLACKBOX sweep manifest anchor"
    "collected = $(Get-SweepUtcStamp)"
    "SHA256(MANIFEST.csv) = $manifestHash"
    "verify: Falsum-Sweep.ps1 -Verify -VerifyDir <dir> -ExpectedHash $manifestHash"
) -join "`r`n"
[System.IO.File]::WriteAllText($hashReceipt, $receiptText)

$failed = @($manifest | Where-Object { $_.status -eq "failed" }).Count
Write-Host ""
Write-Host "Sweep complete: $outDir"
Write-Host "Steps collected: $($manifest.Count) ($failed failed - see step text)"
Write-Host "Manifest SHA-256: $manifestHash"
Write-Host "Copy this hash into your vault/chat - it anchors MANIFEST.csv itself:"
Write-Host "  $manifestHash"
