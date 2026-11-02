<#---------------------------------------------------------------------------
Falsum Fraud Pack — fraud reporting and recovery packs for end users.
Pure PowerShell 5.1. Zero external dependencies. Windows 10/11.

THE THESIS (problems 1651-1900)
  - After fraud, victims face a maze: who do I call, in what order, with
    what paperwork. The maze is why most fraud goes unreported and
    unrecovered. This module is the map: per-fraud-type checklists,
    the exact reporting destinations, evidence inventory, and a timeline
    builder — one pack per incident, ready to hand to police, banks,
    and insurers.
  - Reporting destinations are the stable official ones (FTC, FBI IC3,
    IdentityTheft.gov, the three bureaus, USPS Inspection, IRS). No
    hardcoded phone numbers that rot — names and official sites.
  - Time-critical windows ship WITH the checklist: debit-card liability
    tiers (EFTA/Reg E), the 60-day FCBA dispute window, the wire-recall
    window measured in hours. A map that doesn't tell you which bridges
    collapse first is a bad map.

v1.1 (2026-10-30, cron hardening):
  - FIXED the Desktop-empty path bug (Server Core / redirected profiles):
    Get-FraudPackOutDir falls back to a repo-relative directory instead of
    building a pack at a relative path the user never finds.
  - Evidence proof: every pack now ships MANIFEST.txt (SHA-256 of every
    pack file) plus out-of-band MANIFEST-HASH.txt; Test-FraudPackIntegrity
    re-hashes everything and catches a rewritten pack.json or a tampered
    file. A pack you can't prove unaltered is inadmissible as evidence.
  - Add-FraudTimelineEntry re-seals the manifest after every append
    (the old code left stale hashes after the first timeline entry).
  - Compress-FraudPack: zips the pack for handing to police/banks, with a
    SHA-256 of the zip and an honest "this is a COPY" note.
  - Get-FraudTimeline: chronological read of the timeline (bad dates sort
    last, never throw). Test-FraudDateFormat/Test-FraudDateSortKey are pure
    and offline-testable; bad dates WARN, never block — the timeline must
    capture the victim's story, not reject it.
  - Vault logging (metadata only: action, fraud type, counts — victim
    details NEVER touch the vault).
  - Test-All.ps1 manifest entry + harness battery section 12e (fraud was
    never covered — same gap tracker-block's pass flagged for 15-20).

BUILT 2026-10-30 by the main agent, in-chat, per Gregg's order.
----------------------------------------------------------------------------#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Vault import (graceful when missing) — metadata only, never victim details.
# ---------------------------------------------------------------------------
function Import-FraudVaultModule {
    if ($script:FraudVaultLoaded) { return }
    $here = Split-Path -Parent $MyInvocation.PSCommandPath
    $mod = Join-Path (Split-Path -Parent $here) "12-timeline-vault\Falsum-Vault.ps1"
    if (-not (Test-Path $mod)) { $mod = Join-Path $here "..\12-timeline-vault\Falsum-Vault.ps1" }
    if (Test-Path $mod) { . $mod; $script:FraudVaultLoaded = $true }
    else { Write-Host "[fraud] vault module not found — steps will not be vault-logged" }
}
Import-FraudVaultModule
$script:FraudVaultPath = Join-Path ([Environment]::GetFolderPath("ApplicationData")) "Falsum\vault.jsonl"

function New-FraudLog {
    <#
    Hash-chained vault log of a fraud-pack action. Logs ACTION + FRAUD TYPE
    + COUNTS ONLY. Victim titles, amounts, timeline text never touch the
    vault (PII stays out). Never throws.
    #>
    param([Parameter(Mandatory=$true)][string]$Action, [Parameter(Mandatory=$true)][string]$Type, [int]$Count = 0)
    if (-not $script:FraudVaultLoaded) { return }
    try {
        $vault = New-Vault -path $script:FraudVaultPath
        Add-VaultEntry -vault $vault -type "fraud-pack" -data @{
            action    = $Action
            fraudtype = $Type
            count     = [int]$Count
            utc       = (Get-Date).ToUniversalTime().ToString("o")
        } | Out-Null
    } catch { Write-Host "[fraud] vault log failed (non-fatal): $($_.Exception.Message)" }
}

$script:FraudTypes = @("financial","identity","medical","tax","mail","family")

function Get-FraudChecklist {
    <#
    .SYNOPSIS Per-type immediate-action checklist + time-critical windows +
    reporting destinations + evidence inventory.
    .DESCRIPTION
    Windows rows are the deadlines that decide outcomes: EFTA liability
    tiers and the FCBA 60-day window are verified against the FDIC's
    consumer guidance (Reg E / Reg Z). Times are law, not vibes.
    #>
    param([Parameter(Mandatory=$true)][ValidateSet("financial","identity","medical","tax","mail","family")][string]$Type)
    switch ($Type) {
        "financial" { return @{
            Immediate=@(
                "Call your bank/card issuer NOW — request the fraud department, not general support",
                "If a wire moved: ask for a wire recall / reversal immediately (window is hours)",
                "Change online banking passwords from a CLEAN device",
                "Pull your free credit reports: annualcreditreport.com — look for accounts you didn't open"
            );
            Windows=@(
                "DEBIT card (EFTA/Reg E): report within 2 BUSINESS days of learning of the loss -> liability capped at $50; within 60 days of the statement -> up to $500; after 60 days -> you can be liable for everything after that point",
                "CREDIT card (FCBA): dispute in WRITING within 60 days of the billing statement showing the charge -> liability capped at $50 ($0 for online/phone fraud)",
                "WIRE transfer recall: hours, not days — same-day recall is the only recall with a real chance",
                "While a credit-card dispute is under investigation: pay only the undisputed portion of the bill (Reg Z)"
            );
            Report=@("FTC: reportfraud.ftc.gov","FBI IC3: ic3.gov","Local police: get a report number","Your bank's fraud affidavit");
            Evidence=@("Statements showing the transactions","Any messages from the fraudster","Police report number once filed","Your written dispute letters + mailing receipts")
        }}
        "identity" { return @{
            Immediate=@(
                "Freeze credit at all three bureaus: Equifax, Experian, TransUnion (freeze is free, beats monitoring)",
                "File at IdentityTheft.gov — it builds your personal recovery plan + pre-filled letters",
                "File a police report and keep the number",
                "Review annualcreditreport.com reports from all three bureaus"
            );
            Windows=@(
                "Extended fraud alert: 7 YEARS with an Identity Theft Report (IdentityTheft.gov); the standard alert is only 1 year",
                "Credit freeze is free by federal law at all three bureaus — do the freeze, don't pay for monitoring instead",
                "Dispute fraudulent accounts in writing with each bureau; bureaus generally have 30 days to investigate"
            );
            Report=@("FTC IdentityTheft.gov: identitytheft.gov","FBI IC3: ic3.gov (if money moved)","Local police","IRS if tax identity theft: IRS Identity Protection (irs.gov)");
            Evidence=@("IdentityTheft.gov recovery plan PDF","Police report","Fraudulent account statements","Copies of freeze confirmations")
        }}
        "medical" { return @{
            Immediate=@(
                "Request an accounting of disclosures from your provider/insurer",
                "Check your Explanation of Benefits for services you never got",
                "Freeze your credit (medical identity theft becomes financial fast)",
                "File a complaint with HHS Office for Civil Rights if PHI was misused"
            );
            Windows=@(
                "Accounting of disclosures under HIPAA is a federal right covering 6 years — request it in writing",
                "Dispute fraudulent medical debt in writing; verify the debt is yours before paying anything"
            );
            Report=@("FTC: reportfraud.ftc.gov","HHS OCR: hhs.gov/ocr","Your insurer's fraud unit","Local police");
            Evidence=@("EOBs with fraudulent claims","Bills for unknown services","Correspondence with insurer","Written disclosure-request receipts")
        }}
        "tax" { return @{
            Immediate=@(
                "File IRS Form 14039 (Identity Theft Affidavit) — irs.gov",
                "Get an Identity Protection PIN from the IRS",
                "File your return on paper if e-file rejects as duplicate",
                "Check your IRS transcript for unknown income"
            );
            Windows=@(
                "The IRS IP PIN expires every year — get a NEW one each January before filing",
                "File as EARLY as possible each year with the IP PIN so the fraudster can't file first"
            );
            Report=@("IRS: Form 14039 + Identity Protection PIN program","FTC: identitytheft.gov","Local police");
            Evidence=@("IRS rejection notice","Copy of Form 14039","Unknown W-2s/1099s on transcript")
        }}
        "mail" { return @{
            Immediate=@(
                "Report to the US Postal Inspection Service (uspis.gov) — mail theft is federal",
                "If checks were stolen: stop-payment + close the account, don't just reorder",
                "Sign up for USPS Informed Delivery (see what's coming, spot what's missing)",
                "File a police report for the theft"
            );
            Windows=@(
                "USPS Informed Delivery is free — sign up BEFORE theft so missing mail is visible the same day",
                "Check washing: stop payment AND close the account — reordering checks re-exposes the same account number"
            );
            Report=@("US Postal Inspection Service: uspis.gov","Local police","Your bank (if checks involved)");
            Evidence=@("Informed Delivery images of missing mail","Bank records of forged checks","Police report number")
        }}
        "family" { return @{
            Immediate=@(
                "Document everything with dates — family exploitation cases live or die on the timeline",
                "Separate your finances: new accounts at a different bank the exploiter doesn't use",
                "Contact Adult Protective Services if the victim is elderly/vulnerable",
                "Consult a legal aid attorney — many exploitation cases need protective orders"
            );
            Windows=@(
                "Adult Protective Services intake costs nothing — call the state hotline; cases live or die on the dated timeline",
                "Protective-order and power-of-attorney paperwork is time-sensitive — see an attorney before the exploiter moves assets"
            );
            Report=@("Adult Protective Services (state hotline)","Local police","FTC: reportfraud.ftc.gov","An elder-law or legal-aid attorney");
            Evidence=@("Dated timeline of incidents","Bank statements showing unauthorized use","Witness names","Any written communications")
        }}
    }
}

function Get-FraudPackOutDir {
    <#
    .SYNOPSIS Resolves the pack output directory.
    .DESCRIPTION FIXES the Desktop-empty path bug (Server Core / redirected
    profiles): [Environment]::GetFolderPath("Desktop") can return empty,
    which used to build the pack at a relative path the user never finds.
    Falls back to a repo-relative directory. Never returns empty.
    #>
    $d = [Environment]::GetFolderPath("Desktop")
    if ([string]::IsNullOrWhiteSpace($d)) {
        $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        return (Join-Path $root "Falsum-FraudPacks")
    }
    return (Join-Path $d "Falsum-FraudPacks")
}

function Test-FraudDateFormat {
    <#
    .SYNOPSIS Pure date-shape validator. Returns @{ Ok; Normalized }.
    Accepts strict YYYY-MM-DD (real calendar dates). Anything else is a
    warning, never a block — the timeline must capture the story.
    #>
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$Date)
    $t = $Date.Trim()
    if ($t -match '^(\d{4})-(\d{2})-(\d{2})$') {
        try {
            $dt = [datetime]::ParseExact($t, "yyyy-MM-dd", $null)
            return @{ Ok = $true; Normalized = $dt.ToString("yyyy-MM-dd") }
        } catch { }
    }
    return @{ Ok = $false; Normalized = $t }
}

function Test-FraudDateSortKey {
    <#
    .SYNOPSIS Pure chronological sort key. Bad/unparsable dates sort LAST
    (never throw, never lose the entry).
    #>
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$Date)
    $r = Test-FraudDateFormat $Date
    if ($r.Ok) { return $r.Normalized }
    return "9999-99-99"
}

function New-FraudManifest {
    <#
    .SYNOPSIS Re-seals a pack: SHA-256 of every pack file -> MANIFEST.txt,
    plus out-of-band MANIFEST-HASH.txt (SHA-256 of the manifest itself).
    The manifest proves WHICH files existed; the manifest hash proves the
    manifest wasn't rewritten after a file was tampered with.
    NOTE: MANIFEST.txt and MANIFEST-HASH.txt are the seal, not the cargo —
    they are excluded from their own listing.
    #>
    param([Parameter(Mandatory=$true)][string]$PackDir)
    try {
        $files = Get-ChildItem -Path $PackDir -File | Where-Object { $_.Name -notin @("MANIFEST.txt","MANIFEST-HASH.txt") }
        $lines = @("# Falsum fraud-pack manifest — SHA-256 per file, sealed " + (Get-Date).ToUniversalTime().ToString("o"))
        foreach ($f in ($files | Sort-Object Name)) {
            $h = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash
            $lines += ("{0}  {1}" -f $h, $f.Name)
        }
        $mf = Join-Path $PackDir "MANIFEST.txt"
        $lines | Out-File -FilePath $mf -Encoding utf8
        $mhash = (Get-FileHash -Path $mf -Algorithm SHA256).Hash
        $mhash | Out-File -FilePath (Join-Path $PackDir "MANIFEST-HASH.txt") -Encoding ascii -NoNewline
        Write-Host "[fraud] Manifest sealed: $($files.Count) files, MANIFEST-HASH $mhash"
        return [PSCustomObject]@{ Manifest = $mf; ManifestHash = $mhash; FileCount = $files.Count }
    } catch {
        Write-Host "[fraud] ERROR sealing manifest: $($_.Exception.Message)"
        throw
    }
}

function Test-FraudPackIntegrity {
    <#
    .SYNOPSIS Re-hashes everything the manifest lists and compares.
    Catches: rewritten pack.json, tampered README, added/dropped files.
    Returns @{ PackDir; ManifestOk; Files; Missing; Extra; Overall }.
    #>
    param([Parameter(Mandatory=$true)][string]$PackDir)
    $result = [PSCustomObject]@{ PackDir = $PackDir; ManifestOk = $false; Files = @(); Missing = @(); Extra = @(); Overall = $false }
    try {
        $mf = Join-Path $PackDir "MANIFEST.txt"
        $mh = Join-Path $PackDir "MANIFEST-HASH.txt"
        if (-not (Test-Path $mf)) { Write-Host "[fraud] integrity: MANIFEST.txt missing"; return $result }
        if ((Test-Path $mh)) {
            $expected = (Get-Content -Path $mh -Raw -ErrorAction SilentlyContinue)
            if ($null -ne $expected) { $expected = $expected.Trim() }
            $actual = (Get-FileHash -Path $mf -Algorithm SHA256).Hash
            $result.ManifestOk = ($expected -eq $actual)
        } else {
            Write-Host "[fraud] integrity: MANIFEST-HASH.txt missing — manifest itself unverifiable"
        }
        $listed = @{}
        foreach ($line in (Get-Content -Path $mf)) {
            if ($line.StartsWith("#") -or [string]::IsNullOrWhiteSpace($line)) { continue }
            $parts = $line -split '\s+', 2
            if ($parts.Count -eq 2) { $listed[$parts[1].Trim()] = $parts[0].Trim() }
        }
        foreach ($name in ($listed.Keys | Sort-Object)) {
            $p = Join-Path $PackDir $name
            if (-not (Test-Path $p)) { $result.Missing += $name; continue }
            $h = (Get-FileHash -Path $p -Algorithm SHA256).Hash
            $result.Files += [PSCustomObject]@{ Name = $name; Expected = $listed[$name]; Actual = $h; Ok = ($h -eq $listed[$name]) }
        }
        $onDisk = @(Get-ChildItem -Path $PackDir -File | Where-Object { $_.Name -notin @("MANIFEST.txt","MANIFEST-HASH.txt") } | Select-Object -ExpandProperty Name)
        $result.Extra = @($onDisk | Where-Object { -not $listed.ContainsKey($_) })
        $result.Overall = $result.ManifestOk -and ($result.Missing.Count -eq 0) -and ($result.Extra.Count -eq 0) -and (@($result.Files | Where-Object { -not $_.Ok }).Count -eq 0)
        return $result
    } catch {
        Write-Host "[fraud] ERROR checking integrity: $($_.Exception.Message)"
        return $result
    }
}

function New-FraudPack {
    <#
    .SYNOPSIS THE FIX: builds the incident pack — checklist, windows,
    timeline, evidence inventory, reporting destinations — one folder,
    sealed with a SHA-256 manifest.
    #>
    param(
        [Parameter(Mandatory=$true)][ValidateSet("financial","identity","medical","tax","mail","family")][string]$Type,
        [string]$Title = "incident",
        [string]$OutDir
    )
    try {
        if (-not $OutDir) { $OutDir = Get-FraudPackOutDir }
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $safe = ($Title -replace '[^\w\- ]','').Trim() -replace '\s+','-'
        if ([string]::IsNullOrWhiteSpace($safe)) { $safe = "incident" }
        $dir = Join-Path $OutDir ("fraud-" + $Type + "-" + $safe + "-" + $stamp)
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $cl = Get-FraudChecklist $Type
        $pack = [PSCustomObject]@{
            Type=$Type; Title=$Title; Created=(Get-Date).ToUniversalTime().ToString("o")
            ImmediateActions=$cl.Immediate; TimeWindows=$cl.Windows; ReportTo=$cl.Report; EvidenceNeeded=$cl.Evidence
            Timeline=@()
        }
        $packFile = Join-Path $dir "pack.json"
        $pack | ConvertTo-Json -Depth 5 | Out-File $packFile -Encoding utf8
        $lines = @(
            "FRAUD PACK — $Type — generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
            "Title: $Title", ""
            "DO FIRST (in order):"
        )
        $i = 1
        foreach ($a in $cl.Immediate) { $lines += "  $i. $a"; $i++ }
        $lines += ""; $lines += "TIME CRITICAL WINDOWS (deadlines that decide outcomes):"
        foreach ($w in $cl.Windows) { $lines += "  ! $w" }
        $lines += ""; $lines += "REPORT TO:"
        foreach ($r in $cl.Report) { $lines += "  - $r" }
        $lines += ""; $lines += "GATHER THIS EVIDENCE:"
        foreach ($e in $cl.Evidence) { $lines += "  - $e" }
        $lines += ""; $lines += "Add timeline entries with Add-FraudTimelineEntry. Keep EVERYTHING — originals, not summaries."
        $lines += "Integrity: Test-FraudPackIntegrity proves the pack is unaltered. Compress-FraudPack makes a handoff copy."
        $lines | Out-File (Join-Path $dir "README.txt") -Encoding utf8
        $seal = New-FraudManifest -PackDir $dir
        $hash = (Get-FileHash $packFile -Algorithm SHA256).Hash
        New-FraudLog -Action "pack-created" -Type $Type -Count $seal.FileCount
        Write-Host "[fraud] Pack: $dir"
        Write-Host "[fraud] pack.json SHA-256: $hash"
        return [PSCustomObject]@{ Dir=$dir; PackFile=$packFile; Sha256=$hash; Manifest=$seal.Manifest; ManifestHash=$seal.ManifestHash }
    } catch {
        Write-Host "[fraud] ERROR building pack: $($_.Exception.Message)"
        throw
    }
}

function Add-FraudTimelineEntry {
    <#
    .SYNOPSIS Appends a dated entry to the pack's timeline, then RE-SEALS
    the manifest (v1 left stale hashes after the first append). The timeline
    is what makes the pack credible to police, banks, and insurers.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$PackDir,
        [Parameter(Mandatory=$true)][string]$Date,
        [Parameter(Mandatory=$true)][string]$What,
        [string]$Amount,
        [string]$EvidenceRef
    )
    try {
        $pf = Join-Path $PackDir "pack.json"
        if (-not (Test-Path $pf)) { throw "Not a fraud pack dir: $PackDir" }
        $dv = Test-FraudDateFormat $Date
        if (-not $dv.Ok) {
            Write-Host "[fraud] WARNING: date '$Date' is not YYYY-MM-DD — recorded as-is (it will sort last)."
        }
        $pack = Get-Content $pf -Raw | ConvertFrom-Json
        $entry = [PSCustomObject]@{Date=$dv.Normalized; What=$What; Amount=$Amount; EvidenceRef=$EvidenceRef}
        $pack.Timeline += $entry
        $pack | ConvertTo-Json -Depth 5 | Out-File $pf -Encoding utf8
        New-FraudManifest -PackDir $PackDir | Out-Null
        $re = Get-Content $pf -Raw | ConvertFrom-Json
        New-FraudLog -Action "timeline-added" -Type ([string]$pack.Type) -Count $re.Timeline.Count
        Write-Host "[fraud] Timeline entry added: $($dv.Normalized) — $What (manifest re-sealed)"
        return $entry
    } catch {
        Write-Host "[fraud] ERROR adding timeline entry: $($_.Exception.Message)"
        throw
    }
}

function Get-FraudTimeline {
    <#
    .SYNOPSIS Chronological read of a pack's timeline. Bad dates sort last
    (never throw, never lose an entry).
    #>
    param([Parameter(Mandatory=$true)][string]$PackDir)
    $pf = Join-Path $PackDir "pack.json"
    if (-not (Test-Path $pf)) { throw "Not a fraud pack dir: $PackDir" }
    $pack = Get-Content $pf -Raw | ConvertFrom-Json
    $rows = @($pack.Timeline)
    return @($rows | Sort-Object { Test-FraudDateSortKey ([string]$_.Date) })
}

function Compress-FraudPack {
    <#
    .SYNOPSIS Handoff copy: zips the pack for police/banks/insurers, with a
    SHA-256 of the zip. HONEST LIMIT: this is a COPY — keep the original
    folder as the evidentiary original, and keep originals of everything.
    #>
    param([Parameter(Mandatory=$true)][string]$PackDir)
    try {
        if (-not (Test-Path $PackDir)) { throw "Pack dir not found: $PackDir" }
        $zip = $PackDir + ".zip"
        if (Test-Path $zip) { Remove-Item $zip -Force }
        Compress-Archive -Path (Join-Path $PackDir "*") -DestinationPath $zip -Force
        $hash = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
        $hash | Out-File -FilePath ($zip + ".sha256") -Encoding ascii -NoNewline
        $tip = Test-FraudPackIntegrity -PackDir $PackDir
        New-FraudLog -Action "pack-zipped" -Type "handoff" -Count 1
        Write-Host "[fraud] Handoff copy: $zip"
        Write-Host "[fraud] zip SHA-256: $hash"
        Write-Host "[fraud] Pack integrity at handoff: $($tip.Overall) (this is a COPY — keep the original folder)"
        return [PSCustomObject]@{ Zip = $zip; Sha256 = $hash; IntegrityAtHandoff = $tip.Overall }
    } catch {
        Write-Host "[fraud] ERROR compressing pack: $($_.Exception.Message)"
        throw
    }
}

function Get-IdentityTheftLockdown {
    <#
    .SYNOPSIS The 10-step lockdown for identity theft, in order.
    #>
    return @(
        [PSCustomObject]@{Step=1; Action="Freeze credit at Equifax, Experian, TransUnion (free; do all three)"},
        [PSCustomObject]@{Step=2; Action="File at IdentityTheft.gov — follow its personal recovery plan"},
        [PSCustomObject]@{Step=3; Action="File a police report; keep the report number"},
        [PSCustomObject]@{Step=4; Action="Fraud alert as backup (one bureau notifies the other two)"},
        [PSCustomObject]@{Step=5; Action="Close/replace every compromised account; new account numbers, not just new cards"},
        [PSCustomObject]@{Step=6; Action="IRS Identity Protection PIN if tax-related"},
        [PSCustomObject]@{Step=7; Action="Review all three credit reports at annualcreditreport.com"},
        [PSCustomObject]@{Step=8; Action="Dispute fraudulent accounts in writing with each bureau"},
        [PSCustomObject]@{Step=9; Action="Change passwords from a clean device; enable MFA everywhere"},
        [PSCustomObject]@{Step=10; Action="Keep the pack: police report, FTC plan, dispute letters — for years, not months"}
    )
}

function Test-FraudPackHygiene {
    <#
    .SYNOPSIS Offline battery: builds a pack in temp, adds timeline entries
    (in and out of order), verifies manifest sealing, tamper detection,
    re-seal repair, date validation, chronological sort, zip handoff.
    No network. Returns $true when every check passes.
    #>
    $checks = New-Object System.Collections.ArrayList
    $ok = { param($n,$c) [void]$checks.Add([PSCustomObject]@{Check=$n;Pass=[bool]$c}) }.GetNewClosure()
    foreach ($t in $script:FraudTypes) {
        $cl = Get-FraudChecklist $t
        &$ok "checklist $t has actions" ($cl.Immediate.Count -ge 3)
        &$ok "checklist $t has reporting" ($cl.Report.Count -ge 2)
        &$ok "checklist $t has evidence list" ($cl.Evidence.Count -ge 2)
        &$ok "checklist $t has time windows" ($cl.Windows.Count -ge 2)
    }
    # Pure date logic.
    $dv = Test-FraudDateFormat "2026-10-01"
    &$ok "date valid ok" ($dv.Ok -and ($dv.Normalized -eq "2026-10-01"))
    $dv2 = Test-FraudDateFormat "10/01/2026"
    &$ok "date slashes not-ok" (-not $dv2.Ok)
    $dv3 = Test-FraudDateFormat "2026-13-99"
    &$ok "date impossible not-ok" (-not $dv3.Ok)
    &$ok "bad date sorts last" ((Test-FraudDateSortKey "garbage") -gt (Test-FraudDateSortKey "2026-10-01"))
    # Out-dir never empty.
    &$ok "outdir non-empty" (-not [string]::IsNullOrWhiteSpace((Get-FraudPackOutDir)))
    # Full pack lifecycle in temp.
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "bb-fraudtest"
    $pack = New-FraudPack -Type "financial" -Title "hygiene test" -OutDir $tmp
    &$ok "pack created" (Test-Path $pack.PackFile)
    &$ok "readme created" (Test-Path (Join-Path $pack.Dir "README.txt"))
    &$ok "manifest sealed" (Test-Path $pack.Manifest)
    &$ok "manifest-hash sealed" (Test-Path (Join-Path $pack.Dir "MANIFEST-HASH.txt"))
    $integ0 = Test-FraudPackIntegrity -PackDir $pack.Dir
    &$ok "integrity clean on seal" ($integ0.Overall -eq $true)
    # Out-of-order entries sort chronologically.
    Add-FraudTimelineEntry -PackDir $pack.Dir -Date "2026-10-05" -What "Second event" | Out-Null
    Add-FraudTimelineEntry -PackDir $pack.Dir -Date "2026-10-01" -What "First event" -Amount '$5,000' | Out-Null
    Add-FraudTimelineEntry -PackDir $pack.Dir -Date "sometime last month" -What "Undated event" | Out-Null
    $tl = Get-FraudTimeline -PackDir $pack.Dir
    &$ok "timeline count 3" ($tl.Count -eq 3)
    &$ok "timeline chronological" (($tl[0].Date -eq "2026-10-01") -and ($tl[1].Date -eq "2026-10-05"))
    &$ok "bad date sorts last" ($tl[2].What -eq "Undated event")
    $integ1 = Test-FraudPackIntegrity -PackDir $pack.Dir
    &$ok "integrity clean after appends (re-sealed)" ($integ1.Overall -eq $true)
    # Tamper detection: flip a byte in pack.json, integrity must fail.
    $bytes = [System.IO.File]::ReadAllBytes($pack.PackFile)
    $bytes[$bytes.Length - 1] = 0x20
    [System.IO.File]::WriteAllBytes($pack.PackFile, $bytes)
    $integ2 = Test-FraudPackIntegrity -PackDir $pack.Dir
    &$ok "tamper caught" ($integ2.Overall -eq $false)
    # Re-seal repairs (legit re-edit flow).
    $re = Get-Content $pack.PackFile -Raw | ConvertFrom-Json
    $re | ConvertTo-Json -Depth 5 | Out-File $pack.PackFile -Encoding utf8
    New-FraudManifest -PackDir $pack.Dir | Out-Null
    $integ3 = Test-FraudPackIntegrity -PackDir $pack.Dir
    &$ok "re-seal repairs" ($integ3.Overall -eq $true)
    # Handoff zip.
    $zip = Compress-FraudPack -PackDir $pack.Dir
    &$ok "zip created" (Test-Path $zip.Zip)
    &$ok "zip hash recorded" ($zip.Sha256.Length -eq 64)
    &$ok "zip integrity note" ($zip.IntegrityAtHandoff -eq $true)
    &$ok "lockdown has 10 steps" ((Get-IdentityTheftLockdown).Count -eq 10)
    # Vault logging never throws.
    try { New-FraudLog -Action "hygiene" -Type "financial" -Count 1; &$ok "vault log never throws" $true }
    catch { &$ok "vault log never throws" $false }
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    $pass = ($checks | Where-Object { $_.Pass }).Count
    $total = $checks.Count
    Write-Host "[fraud] Hygiene: $pass/$total checks passed."
    foreach ($c in ($checks | Where-Object { -not $_.Pass })) { Write-Host "[fraud]   FAILED: $($c.Check)" }
    return ($pass -eq $total)
}

Write-Host "[fraud] Falsum Fraud Pack loaded. New-FraudPack / Add-FraudTimelineEntry / Get-FraudTimeline / Compress-FraudPack / Test-FraudPackIntegrity / Get-IdentityTheftLockdown / Test-FraudPackHygiene."
Write-Host "[fraud] Types: $($script:FraudTypes -join ', ')"
