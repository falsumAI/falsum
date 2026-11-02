<#
Module 14 — BUG BOUNTY (the money arm)
Passive recon + report pipeline for in-scope bug bounty hunting.
Get-BountyPrograms (shipped table), Get-ProgramScope (public scope fetch),
Register-BountyTarget (record the published scope BEFORE any recon),
Start-BountyRecon (PASSIVE ONLY: crt.sh, DNS, Shodan public data, CT logs —
zero packets to the target), New-BountyReport (professional report:
summary, steps, impact, remediation).

========================================================================
THE SCOPE LAW — HARD RULE, NO EXCEPTIONS, NOT DEBATED:
Only test targets whose published bounty scope explicitly authorizes you.
Everything else is passive recon on public data, or your own systems.
This module ships NO active-test functions. Request-BountyActiveTestGate
exists to REFUSE them. Unauthorized access to someone else's system is a
federal crime under the CFAA (18 U.S.C. 1030) even if they attacked you
first. A payout is not worth a prison sentence. Submissions go out under
Gregg's name ONLY on his explicit word.
========================================================================

THE BETTER WAY: a finding without its fix is unfinished work. Every
New-BountyReport ships a remediation section pulled from the mitigation
table — the report tells the triage team how to kill the bug, not just
where it lives. That is what gets paid first.

# v1.4 (2026-10-30 hardening): REAL false-positive fix — keyword triage used
# raw -match substring matching, so "rapid.example.com" scored api-host,
# "forest.example.com" scored api-host ("rest"), "impossible.example.com"
# scored mail-host ("pop"). New pure Test-BountyHostnameKeyword: split the
# hostname into labels on [^a-z0-9] and match only full-label / prefix /
# suffix — mid-string fragments no longer fire (battery proves all three).
# REAL bug-class fix: Test-BountyScopeFreshness parsed the registry date with
# bare [datetime]::Parse, so a zone-less timestamp shifted by the machine
# offset (the coherence-core v1.4 / osint v5 bug class). New pure
# ConvertTo-BountyUtcDate: RoundtripKind-aware, zone-less reads as UTC.
# CLOSED the wildcard-match edge in Test-BountyScopeRegistered: raw -like
# treats [ and ] in a scope target as wildcard classes; new pure
# Test-BountyTargetScopeMatch builds the regex from the escaped scope target.
# CLOSED a safety gap in Request-BountyActiveTestGate: the gate could pass on
# a 2-year-old scope; core extracted to pure Test-BountyActiveTestAuthorization
# and a stale scope (>30d) is now a REFUSAL ("re-read the scope page"), same
# rule the recon freshness note already stated for active work.
# NEW NS-delegation dangling check (the takeover mechanism past CNAME —
# 0xpatrik.com NS-takeover writeup): Get-BountyDanglingNsTable + pure
# Test-BountyNsDelegation, wired into recon as passive NS lookups on the
# triage set; candidates are "nsdelegation-candidate" (manual confirm, this
# module never touches the delegated NS). NEW -FullTakeoverSweep on
# Start-BountyRecon: v1.2 only CNAME-checked keyword-class candidates, so a
# dangling CNAME on a host with no keyword match was never examined; the full
# sweep walks every subdomain (new pure Get-TakeoverTriageSet, default keeps
# the fast path). FIXED report filename collision (same title + same second
# overwrote the previous report) via New-BountyReportPath (-2, -3 suffixes).
# NEW audit trail: saved recon runs now carry the scope snapshot
# (ScopeUrl/AuthorizedNote/ScopeRegisteredUtc/ScopeStaleDays) and
# Get-BountySummary prints per-target freshness. Keyword table 15 -> 22
# classes (+backup-host, secret-host, proxy-host, mobile-host, support-host,
# collab-host, partner-host). Hygiene battery gains ~24 cases (7b-7k).

Dot-source:
  . .\Falsum-BugBounty.ps1

Typical run:
  Get-BountyPrograms | Format-Table Name, Platform, PayoutRange
  Register-BountyTarget -Name "Cloudflare" -Target "php-rce.cloudflare.app" `
      -ScopeUrl "https://hackerone.com/cloudflare"
  Start-BountyRecon -Name "Cloudflare" -Target "php-rce.cloudflare.app"
  New-BountyReport -Program "Cloudflare" -Target "php-rce.cloudflare.app" `
      -Title "WAF bypass on php-rce sandbox" -Severity "High" ...
#>

# ----------------------------------------------------------------------
# Module-local state
# ----------------------------------------------------------------------
$script:BountyOsintLoaded  = $false
$script:BountyVaultLoaded  = $false
$script:BountyVaultPath    = ""
$script:HttpUA             = "Falsum-BugBounty/1.0 (Windows; PowerShell 5.1)"
$script:BountyRegistryPath = ""

function Import-BountyOsint {
    <#
    Loads the OSINT attribution module so recon reuses its passive
    collectors (crt.sh, DNS, Shodan) instead of re-implementing them.
    #>
    if ($script:BountyOsintLoaded) { return }
    try {
        $here = Split-Path -Parent $MyInvocation.PSCommandPath
        $mod  = Join-Path (Split-Path -Parent $here) "04-osint-attribution\Falsum-Osint.ps1"
        if (-not (Test-Path $mod)) { $mod = Join-Path $here "..\04-osint-attribution\Falsum-Osint.ps1" }
        if (Test-Path $mod) {
            . $mod
            $script:BountyOsintLoaded = $true
        } else {
            Write-Host "[!] OSINT module not found at $mod — recon will run with its own passive collectors"
        }
    } catch {
        Write-Host "[!] OSINT import failed: $($_.Exception.Message)"
    }
}

function Import-BountyVault {
    <#
    Loads the timeline-vault module for hash-chained logging of every
    recon run, scope registration, and report. Never blocks the module.
    #>
    if ($script:BountyVaultLoaded) { return }
    try {
        $here = Split-Path -Parent $MyInvocation.PSCommandPath
        $mod  = Join-Path (Split-Path -Parent $here) "12-timeline-vault\Falsum-Vault.ps1"
        if (-not (Test-Path $mod)) { $mod = Join-Path $here "..\12-timeline-vault\Falsum-Vault.ps1" }
        if (Test-Path $mod) {
            . $mod
            $script:BountyVaultLoaded = $true
        } else {
            Write-Host "[!] vault module not found — bounty activity will not be vault-logged"
        }
    } catch {
        Write-Host "[!] vault import failed: $($_.Exception.Message)"
    }
}

function Get-BountyRoot {
    <#
    Repo root: two levels up from this module's directory
    (modules/14-bugbounty -> modules -> blackbox root).
    #>
    try {
        $here = Split-Path -Parent $MyInvocation.PSCommandPath
        $root = Split-Path -Parent (Split-Path -Parent $here)
        return $root
    } catch {
        return (Get-Location).Path
    }
}

function Get-BountyRegistryPath {
    if ([string]::IsNullOrWhiteSpace($script:BountyRegistryPath)) {
        $script:BountyRegistryPath = Join-Path (Get-BountyRoot) "bounty-registry.json"
    }
    return $script:BountyRegistryPath
}

function New-BountyLog {
    <#
    Hash-chained vault log for bounty actions (type "bounty-activity").
    Silent when the vault module failed to load or no vault path was set —
    never blocks recon.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Action,
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)]$Result
    )
    if (-not $script:BountyVaultLoaded -or [string]::IsNullOrWhiteSpace($script:BountyVaultPath)) { return }
    try {
        $vault = New-Vault -path $script:BountyVaultPath
        $ok = $true
        if ($null -ne $Result -and $Result.PSObject.Properties.Name -contains "ok") { $ok = [bool]$Result.ok }
        Add-VaultEntry -vault $vault -type "bounty-activity" -data @{
            action = $Action
            target = $Target
            ok     = $ok
            utc    = (Get-Date).ToUniversalTime().ToString("o")
        } | Out-Null
        Write-Host "[+] vault-logged: $Action on $Target"
    } catch {
        Write-Host "[!] bounty vault log failed: $($_.Exception.Message)"
    }
}

# ----------------------------------------------------------------------
# 1. PROGRAM TABLE
# ----------------------------------------------------------------------
function Get-BountyPrograms {
    <#
    Shipped program table. Scope pages change — read the program's scope
    page fully and Register-BountyTarget before any recon. Payout ranges
    are representative 2026 figures, not guarantees.
    #>
    param(
        [string]$Platform = "",
        [string]$Name = ""
    )
    $table = @(
        [pscustomobject]@{
            Name        = "Cloudflare"
            Platform    = "HackerOne"
            ScopeUrl    = "https://hackerone.com/cloudflare"
            PayoutRange = "$250 - $31,000 (CTF challenges up to $3,000)"
            ProgramType = "Bounty (paid)"
            ScopeNote   = "Main scope: cloudflare.com assets per policy page. ACTIVE CTF Oct 2026: HTTP POST https://php-rce.cloudflare.app/php/* ONLY — deliberately vulnerable PHP sandbox, $3,000 per materially unique WAF-bypass report."
            Rules       = "Public policy page; CTF has explicit narrow scope with method/host restrictions. No automated scanners against infra; back off on 429/503."
        },
        [pscustomobject]@{
            Name        = "Shopify"
            Platform    = "HackerOne"
            ScopeUrl    = "https://hackerone.com/shopify"
            PayoutRange = "$500 - $50,000 (critical)"
            ProgramType = "Bounty (paid)"
            ScopeNote   = "Test ONLY against stores you create yourself. Active testing of live merchant stores or Shopify infra is PROHIBITED and disqualifies. Recon: passive public data only."
            Rules       = "Own-created test stores only; no social engineering; no merchant data access; report quality requirements high."
        },
        [pscustomobject]@{
            Name        = "Yahoo"
            Platform    = "HackerOne"
            ScopeUrl    = "https://hackerone.com/yahoo"
            PayoutRange = "$100 - $15,000+ (critical)"
            ProgramType = "Bounty (paid)"
            ScopeNote   = "WARNING: as of 2026-10-30 the scope page sits behind the HackerOne sign-in gate — scope NOT publicly readable. Read the scope page (signed in, on Gregg's word) before ANY recon touches a Yahoo asset."
            Rules       = "Scope unknown until read — treat as passive-only until then."
        },
        [pscustomobject]@{
            Name        = "Google VRP"
            Platform    = "Google"
            ScopeUrl    = "https://bughunters.google.com/"
            PayoutRange = "$500 - $31,337 (critical)"
            ProgramType = "Bounty (paid)"
            ScopeNote   = "google.com and owned properties; detailed per-product scope pages. Hard targets, real money. Open Redirects / minor issues out of scope."
            Rules       = "Follow per-product rules; no user data access; Chrome VRP separate with its own table."
        },
        [pscustomobject]@{
            Name        = "Apple Security Bounty"
            Platform    = "Apple"
            ScopeUrl    = "https://security.apple.com/bounty/"
            PayoutRange = "$5,000 - $1,000,000 (up to $2M for lockdown-mode bypass)"
            ProgramType = "Bounty (paid, elite tier)"
            ScopeNote   = "Apple products and services; iCloud, iOS/macOS chains. Elite tier — only with verified chains and full working PoCs."
            Rules       = "Strict report quality bar; responsible disclosure terms."
        },
        [pscustomobject]@{
            Name        = "Tesla"
            Platform    = "Bugcrowd"
            ScopeUrl    = "https://bugcrowd.com/tesla"
            PayoutRange = "see scope page (verify before recon)"
            ProgramType = "Bounty (paid)"
            ScopeNote   = "Tesla vehicles + fleet/energy web properties per published scope. Broad, mature program; vehicle testing has strict safety rules."
            Rules       = "Per-program rules always; safety-critical systems off-limits without explicit scope."
        },
        [pscustomobject]@{
            Name        = "Atlassian"
            Platform    = "Bugcrowd"
            ScopeUrl    = "https://bugcrowd.com/atlassian"
            PayoutRange = "see scope page (verify before recon)"
            ProgramType = "Bounty (paid)"
            ScopeNote   = "Jira/Confluence/Bitbucket cloud per published scope. Enterprise targets — good for auth/IDOR hunters."
            Rules       = "Per-program rules always; no customer data access."
        },
        [pscustomobject]@{
            Name        = "Valve"
            Platform    = "HackerOne"
            ScopeUrl    = "https://hackerone.com/valve"
            PayoutRange = "see scope page (verify before recon)"
            ProgramType = "Bounty (paid)"
            ScopeNote   = "Steam + Valve services per published scope. Long-running program, high report-quality bar."
            Rules       = "Per-program rules always; no cheating-tool research outside scope."
        },
        [pscustomobject]@{
            Name        = "GitLab"
            Platform    = "HackerOne"
            ScopeUrl    = "https://hackerone.com/gitlab"
            PayoutRange = "see scope page (verify before recon)"
            ProgramType = "Bounty (paid)"
            ScopeNote   = "GitLab.com + self-managed per published scope. Strong for CI/CD and access-control bugs."
            Rules       = "Per-program rules always; test accounts only."
        },
        [pscustomobject]@{
            Name        = "Uber"
            Platform    = "HackerOne"
            ScopeUrl    = "https://hackerone.com/uber"
            PayoutRange = "see scope page (verify before recon)"
            ProgramType = "Bounty (paid)"
            ScopeNote   = "Uber web/API/mobile per published scope. API surface is large — IDOR and logic bugs pay here."
            Rules       = "Per-program rules always; no rider/driver data access."
        },
        [pscustomobject]@{
            Name        = "HackerOne (platform)"
            Platform    = "HackerOne"
            ScopeUrl    = "https://hackerone.com/directory/programs"
            PayoutRange = "3,000+ programs, ~$81M/yr paid"
            ProgramType = "Platform directory"
            ScopeNote   = "Start: filter by broad scope, published bounty table, high signal requirements. VDPs for practice, paid programs for money."
            Rules       = "Per-program rules always — read each scope page before recon."
        },
        [pscustomobject]@{
            Name        = "Bugcrowd (platform)"
            Platform    = "Bugcrowd"
            ScopeUrl    = "https://bugcrowd.com/programs"
            PayoutRange = "1,000+ programs, $50M+ lifetime paid"
            ProgramType = "Platform directory"
            ScopeNote   = "Strong web/API programs; P1-P4 severity taxonomy."
            Rules       = "Per-program rules always."
        },
        [pscustomobject]@{
            Name        = "Intigriti (platform)"
            Platform    = "Intigriti"
            ScopeUrl    = "https://app.intigriti.com/researcher/programs"
            PayoutRange = "Strong EU programs"
            ProgramType = "Platform directory"
            ScopeNote   = "EU programs with broad scope; good for web specialists."
            Rules       = "Per-program rules always."
        },
        [pscustomobject]@{
            Name        = "Open Bug Bounty"
            Platform    = "OpenBugBounty"
            ScopeUrl    = "https://www.openbugbounty.org/"
            PayoutRange = "XSS/CSRF only — no cash (reputation tier)"
            ProgramType = "VDP-style (no payout)"
            ScopeNote   = "XSS and CSRF findings on any site with a responsible-disclosure expectation; 90-day disclosure clock. Practice tier: builds report-writing muscle, zero money."
            Rules       = "XSS/CSRF only; coordinated disclosure; never test without the site's disclosure expectation."
        },
        [pscustomobject]@{
            Name        = "U.S. Government VDP (Hack the Pentagon)"
            Platform    = "HackerOne"
            ScopeUrl    = "https://hackerone.com/deptofdefense"
            PayoutRange = "VDP (no payout) + Hack the Pentagon paid events"
            ProgramType = "VDP (no payout)"
            ScopeNote   = "DoD public-facing systems; STRICT scope, authorization windows, and no-exfiltration rules. Read every line twice."
            Rules       = "Federal authorization terms; no data exfiltration ever; exfil = federal crime even inside a VDP."
        }
    )
    $rows = @($table)
    if ($Platform -ne "") {
        $rows = @($rows | Where-Object { $_.Platform -like "*$Platform*" })
    }
    if ($Name -ne "") {
        $rows = @($rows | Where-Object { $_.Name -like "*$Name*" })
    }
    return $rows
}

function Get-BountyProgram {
    <#
    Returns one program record by (partial) name, or $null.
    #>
    param([Parameter(Mandatory=$true)][string]$Name)
    $rows = @(Get-BountyPrograms -Name $Name)
    if ($rows.Count -eq 0) { return $null }
    if ($rows.Count -eq 1) { return $rows[0] }
    Write-Host "[*] multiple matches for '$Name':"
    foreach ($r in $rows) { Write-Host "    - $($r.Name) [$($r.Platform)]" }
    return $rows[0]
}

# ----------------------------------------------------------------------
# 2. SCOPE REGISTRY — the enforcement anchor of the Scope Law
# ----------------------------------------------------------------------
function Get-BountyTargets {
    <#
    Reads the scope registry (bounty-registry.json at repo root).
    Each record: Program, Target, ScopeUrl, AuthorizedNote, ScopePublic,
    RegisteredUtc, RegisteredBy.
    #>
    try {
        $p = Get-BountyRegistryPath
        if (-not (Test-Path $p)) { return @() }
        $raw = Get-Content -Path $p -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $data = $raw | ConvertFrom-Json
        if ($null -eq $data) { return @() }
        return @($data)
    } catch {
        Write-Host "[!] registry read failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-BountyScopeRecord {
    <#
    Returns the scope record for program+target, or $null. One source of
    truth — the gate, recon, summary, and report used to each re-implement
    this lookup (v1.4 refactor).
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Target
    )
    try {
        $reg = @(Get-BountyTargets)
        $hit = @($reg | Where-Object { $_.Program -eq $Name -and $_.Target -eq $Target }) | Select-Object -First 1
        return $hit
    } catch {
        return $null
    }
}

function Test-BountyTargetScopeMatch {
    <#
    Pure: does a scope-record target cover a concrete host? Exact match
    first; wildcard records (containing *) match via a regex built from
    the ESCAPED scope target. v1.4 fix: the old code used
    `$Target -like $_.Target` directly, and PowerShell -like treats [ ]
    as wildcard character classes — a target like "foo[1].example.com"
    could misbehave. Escaping first means literal brackets stay literal.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][string]$ScopeTarget
    )
    try {
        $t = $Target.Trim().ToLower()
        $s = $ScopeTarget.Trim().ToLower()
        if ($t -eq $s) { return $true }
        if ($s -notmatch "\*") { return $false }
        $rx = "^" + (([regex]::Escape($s)) -replace "\\\*", ".*") + "$"
        return ($t -match $rx)
    } catch {
        return $false
    }
}

function Update-BountyScopeRecord {
    <#
    Pure: upsert a scope record into a registry array. Re-registering a
    target after re-reading its scope page REFRESHES RegisteredUtc,
    AuthorizedNote, and ScopePublic in place. The old Register-BountyTarget
    returned early on an existing record with "re-checking freshness" but
    never refreshed it — so the v1.2 freshness check could warn STALE
    forever with no way to clear it except hand-editing the JSON. Fixed.
    Returns @{ records, refreshed }.
    #>
    param(
        [array]$Records,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][string]$ScopeUrl,
        [Parameter(Mandatory=$true)][string]$AuthorizedNote,
        [bool]$ScopePublic,
        [string]$RegisteredBy = "Gregg"
    )
    $rec = [pscustomobject]@{
        Program        = $Name
        Target         = $Target
        ScopeUrl       = $ScopeUrl
        AuthorizedNote = $AuthorizedNote
        ScopePublic    = $ScopePublic
        RegisteredUtc  = (Get-Date).ToUniversalTime().ToString("o")
        RegisteredBy   = $RegisteredBy
    }
    $out = @()
    $refreshed = $false
    foreach ($r in @($Records)) {
        if (-not $refreshed -and "$($r.Target)" -eq $Target -and "$($r.Program)" -eq $Name) {
            $out += $rec
            $refreshed = $true
        } else {
            $out += $r
        }
    }
    if (-not $refreshed) { $out += $rec }
    return [pscustomobject]@{ records = @($out); refreshed = $refreshed }
}

function Register-BountyTarget {
    <#
    Records the published scope BEFORE any recon on a target. This is the
    Scope Law made concrete: Start-BountyRecon and the active-test gate
    both refuse when no record exists.

    -ScopeUrl must be the program's published scope/policy page.
    -AuthorizedNote states, in your words, what the scope permits
    (e.g. "CTF sandbox POST https://php-rce.cloudflare.app/php/* only").
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][string]$ScopeUrl,
        [Parameter(Mandatory=$true)][string]$AuthorizedNote,
        [switch]$ScopePageRead
    )
    $out = [pscustomobject]@{
        ok = $false; Program = $Name; Target = $Target;
        ScopeUrl = $ScopeUrl; error = ""
    }
    try {
        if ($ScopeUrl -notmatch "^https?://") {
            $out.error = "ScopeUrl must be an http(s) URL to the program's published scope page."
            Write-Host "[!] $($out.error)"
            return $out
        }
        $reg = @(Get-BountyTargets)
        $upd = Update-BountyScopeRecord -Records $reg -Name $Name -Target $Target `
            -ScopeUrl $ScopeUrl -AuthorizedNote $AuthorizedNote -ScopePublic ([bool]$ScopePageRead)
        $p = Get-BountyRegistryPath
        $upd.records | ConvertTo-Json -Depth 5 | Set-Content -Path $p -Encoding UTF8
        if ($upd.refreshed) {
            Write-Host "[+] scope record REFRESHED (re-read) for $Target under $Name"
        } else {
            Write-Host "[+] scope registered: $Name :: $Target"
        }
        Write-Host "    scope page : $ScopeUrl"
        Write-Host "    authorizes : $AuthorizedNote"
        Write-Host "    page read  : $ScopePageRead"
        $out.ok = $true
        New-BountyLog -Action "scope-register" -Target $Target -Result $out
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] scope registration failed: $($out.error)"
    }
    return $out
}

function Test-BountyScopeRegistered {
    <#
    The gate. Returns $true only when a scope record exists for the
    program+target. Everything else refuses.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Target
    )
    try {
        $rec = Get-BountyScopeRecord -Name $Name -Target $Target
        if ($null -ne $rec) { return $true }
        $reg = @(Get-BountyTargets)
        foreach ($r in $reg) {
            if ("$($r.Program)" -ne $Name) { continue }
            if (Test-BountyTargetScopeMatch -Target $Target -ScopeTarget "$($r.Target)") { return $true }
        }
        return $false
    } catch {
        return $false
    }
}

function Request-BountyActiveTestGate {
    <#
    THE REFUSAL FUNCTION. This module ships no active tests — and this
    function exists so any future caller has one gate to ask, and one
    refusal to receive. It returns a refusal record, always, unless ALL
    of the following are true:
      1. A scope record exists (Test-BountyScopeRegistered),
      2. The scope page was actually read (ScopePublic = $true),
      3. The caller supplies -ConfirmScopeNote matching the registered
         authorization note (proves the human read the scope, not the script).
    Even then, active tests are NOT performed by this module — the gate
    returns an approval-to-proceed record that a human (Gregg) must still
    act on personally. Automation does not pull the trigger.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Target,
        [string]$ConfirmScopeNote = ""
    )
    $out = [pscustomobject]@{
        ok = $false; decision = "REFUSED"; Program = $Name; Target = $Target;
        reason = ""; registeredScopeNote = ""; checkedUtc = ""
    }
    try {
        Import-BountyOsint; Import-BountyVault
        $reg  = @(Get-BountyTargets)
        $hits = @($reg | Where-Object { $_.Program -eq $Name -and $_.Target -eq $Target })
        if ($hits.Count -eq 0) {
            $out.reason = "No scope record for '$Target' under '$Name'. Register the published scope with Register-BountyTarget before anything active. Scope Law."
            Write-Host "[!] ACTIVE TEST REFUSED: $($out.reason)"
            return $out
        }
        $rec = $hits[0]
        $out.registeredScopeNote = $rec.AuthorizedNote
        $out.checkedUtc = (Get-Date).ToUniversalTime().ToString("o")
        if (-not [bool]$rec.ScopePublic) {
            $out.reason = "Scope page for this program was never confirmed readable (sign-in gate or unverified). Read the scope page first — testing blind is how you break the law."
            Write-Host "[!] ACTIVE TEST REFUSED: $($out.reason)"
            return $out
        }
        if ([string]::IsNullOrWhiteSpace($ConfirmScopeNote) -or
            $ConfirmScopeNote.Trim() -ne $rec.AuthorizedNote.Trim()) {
            $out.reason = "The human must confirm the exact registered authorization note. Supply -ConfirmScopeNote matching: '$($rec.AuthorizedNote)'. This proves you read the scope."
            Write-Host "[!] ACTIVE TEST REFUSED: $($out.reason)"
            return $out
        }
        # Gate passed — still no automation. Return a human-action record.
        $out.ok = $true
        $out.decision = "GATE-PASSED-NO-AUTOMATION"
        $out.reason = "Scope gate passed: published scope authorizes the action noted. This module performs NO active tests — the human (Gregg) executes manually, minimum traffic, and logs the session. Unauthorized access outside the registered scope remains a federal crime."
        Write-Host "[*] GATE PASSED (no automation): $($rec.AuthorizedNote)"
        New-BountyLog -Action "active-test-gate-passed" -Target $Target -Result $out
    } catch {
        $out.reason = "Gate error: $($_.Exception.Message) — refused by default."
        Write-Host "[!] ACTIVE TEST REFUSED (gate error): $($out.reason)"
    }
    return $out
}

# ----------------------------------------------------------------------
# 3. PUBLIC SCOPE FETCH — read what the program publishes, passively
# ----------------------------------------------------------------------
function Get-ProgramScope {
    <#
    Fetches a program's PUBLIC scope/policy page and reports whether the
    scope is actually readable without sign-in. HackerOne and several
    platforms gate scope behind login — this function detects that and
    says so plainly instead of guessing. HTTP GET only; no forms, no
    login, no session creation.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name
    )
    $out = [pscustomobject]@{
        ok = $false; Program = $Name; ScopeUrl = "";
        ScopePubliclyVisible = $false; ScopeSummary = "";
        RawExcerpt = ""; error = ""
    }
    try {
        $prog = Get-BountyProgram -Name $Name
        if ($null -eq $prog) {
            $out.error = "Unknown program '$Name'. See Get-BountyPrograms."
            Write-Host "[!] $($out.error)"
            return $out
        }
        $out.ScopeUrl = $prog.ScopeUrl
        Write-Host "[*] fetching public scope page: $($prog.ScopeUrl)"
        $resp = Invoke-WebRequest -Uri $prog.ScopeUrl -UserAgent $script:HttpUA `
            -TimeoutSec 20 -UseBasicParsing -ErrorAction Stop
        $html = "$($resp.Content)"
        # Sign-in gate detection (HackerOne style)
        if ($html -match "users/sign_in" -or $html -match "(?i)you need to sign in or sign up before continuing") {
            $out.ScopePubliclyVisible = $false
            $out.ScopeSummary = "Scope page redirects to a SIGN-IN gate — scope, rules, and authorization are not publicly readable. Read the scope signed in (Gregg's account, his word) before any testing."
            Write-Host "[!] sign-in gate detected: scope not publicly readable"
        } else {
            $out.ScopePubliclyVisible = $true
            # Pull plausible scope-policy text: strip tags, keep sentences with scope-ish words
            $text = $html -replace "(?s)<script.*?</script>", " " `
                           -replace "(?s)<style.*?</style>", " " `
                           -replace "<[^>]+>", " " `
                           -replace "\s+", " "
            $sentences = $text -split "(?<=[.!?])\s+"
            $keep = @()
            foreach ($s in $sentences) {
                if ($s -match "(?i)\b(scope|in scope|out of scope|eligible|prohibited|not allowed|must test|authorized|permitted|bounty|payout|reward)\b") {
                    $t = $s.Trim()
                    if ($t.Length -gt 20 -and $t.Length -lt 400 -and $keep.Count -lt 25) { $keep += $t }
                }
            }
            $out.ScopeSummary = "Public scope page readable. Key scope sentences extracted below (full page at the URL)."
            $out.RawExcerpt = ($keep -join "`r`n")
            Write-Host "[+] scope page public: $($keep.Count) scope sentences extracted"
        }
        $out.ok = $true
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] scope fetch failed: $($out.error)"
    }
    New-BountyLog -Action "scope-fetch" -Target $Name -Result $out
    return $out
}

# ----------------------------------------------------------------------
# 4. PASSIVE RECON — public data only, zero packets to the target
# ----------------------------------------------------------------------
function Get-BountyKeywordTable {
    <#
    Keyword classes used to triage passive findings. The finding classes
    that historically pay are at the top (edge = logic + chains, not spray).
    #>
    return @(
        @{ Pattern = "dev|develop";    Class = "dev-host";        Note = "Dev hosts: debug flags, verbose errors, test creds";            Weight = 3 },
        @{ Pattern = "stag|staging";   Class = "staging-host";    Note = "Staging: mirror of prod, weaker auth";                           Weight = 3 },
        @{ Pattern = "admin|manage|console|panel"; Class = "admin-panel"; Note = "Admin panels: auth bypass / weak creds territory";        Weight = 3 },
        @{ Pattern = "internal|intranet|corp";     Class = "internal-host"; Note = "Internal names on public CT = exposure signal";         Weight = 4 },
        @{ Pattern = "legacy|old|beta|test|qa";    Class = "legacy-host";  Note = "Legacy/beta: old code, old vulns, forgotten patching";   Weight = 3 },
        @{ Pattern = "api|graphql|rest";           Class = "api-host";     Note = "API surface: IDOR, BOLA, mass-assignment territory";      Weight = 3 },
        @{ Pattern = "vpn|ssh|rdp|ftp";            Class = "mgmt-host";    Note = "Management ports on public names: exposure signal";       Weight = 2 },
        @{ Pattern = "mail|smtp|pop|imap";         Class = "mail-host";    Note = "Mail infra: legacy POP/IMAP daemons are classic targets"; Weight = 2 },
        @{ Pattern = "s3|storage|cdn|assets";      Class = "storage-host"; Note = "Storage: misconfigured buckets, takeover targets";        Weight = 2 },
        @{ Pattern = "jenkins|travis|circleci|argocd|teamcity|drone|bamboo"; Class = "cicd-host"; Note = "CI/CD: build creds, pipeline secrets, unsigned artifacts"; Weight = 3 },
        @{ Pattern = "grafana|kibana|prometheus|datadog|newrelic|sentry|statuspage"; Class = "monitor-host"; Note = "Monitoring: dashboards often unauthenticated"; Weight = 2 },
        @{ Pattern = "docs|wiki|confluence|swagger|openapi|redoc|readme"; Class = "docs-host"; Note = "Docs: internal endpoints, creds in examples";            Weight = 2 },
        @{ Pattern = "sso|login|oauth|auth0|okta|keycloak|adfs"; Class = "auth-host"; Note = "Auth infra: bypass / SSO-confusion territory";                Weight = 3 },
        @{ Pattern = "git|gitlab|bitbucket|gitea|svn|cvs"; Class = "git-host"; Note = "Code hosts: .git exposure, source leaks";              Weight = 3 },
        @{ Pattern = "k8s|kubernetes|rancher|openshift"; Class = "k8s-host"; Note = "Orchestration: dashboards, etcd exposure";              Weight = 2 }
    )
}

function ConvertFrom-BountyCtNames {
    <#
    Pure offline parser for crt.sh rows (objects with name_value).
    Wildcards are tracked separately (broad-cert coverage signal) instead
    of being silently dropped — v1.1 dropped them with no trace.
    #>
    param([Parameter(Mandatory=$true)][array]$Rows)
    $names = @()
    $wild  = @()
    foreach ($row in $Rows) {
        $nv = "$($row.name_value)"
        foreach ($n in ($nv -split "`r?`n")) {
            $t = $n.Trim().ToLower()
            if ($t -eq "") { continue }
            if ($t.StartsWith("*")) { $wild += $t }
            else { $names += $t }
        }
    }
    $uniqNames = @($names | Sort-Object -Unique)
    $uniqWild  = @($wild  | Sort-Object -Unique)
    return [pscustomobject]@{
        ok            = $true
        subdomains    = $uniqNames
        uniqueCount   = $uniqNames.Count
        wildcards     = $uniqWild
        wildcardCount = $uniqWild.Count
    }
}

function Invoke-BountyCtQuery {
    <#
    Passive certificate-transparency subdomain enumeration via crt.sh.
    This is the module's own collector (also usable when the OSINT module
    is absent). Queries crt.sh only — never the target. Retries transient
    failures (crt.sh rate-limits); wildcard certs are reported, not
    silently dropped.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Domain,
        [int]$TimeoutSec = 45
    )
    $out = [pscustomobject]@{
        ok = $false; domain = $Domain; subdomains = @();
        uniqueCount = 0; wildcards = @(); wildcardCount = 0;
        source = "crt.sh"; error = ""
    }
    try {
        $q = "https://crt.sh/?q=%25.$Domain&output=json"
        Write-Host "[*] crt.sh passive query: %.$Domain (public CT logs only)"
        $r = $null
        $attempt = 0
        $maxAttempts = 3
        $done = $false
        while (-not $done -and $attempt -lt $maxAttempts) {
            $attempt++
            try {
                $r = Invoke-RestMethod -Uri $q -UserAgent $script:HttpUA -TimeoutSec $TimeoutSec
                $done = $true
            } catch {
                if ($attempt -ge $maxAttempts) { throw }
                Write-Host "[*] crt.sh attempt $attempt failed ($($_.Exception.Message)) — retrying in 5s"
                Start-Sleep -Seconds 5
            }
        }
        $parsed = ConvertFrom-BountyCtNames -Rows @($r)
        $out.subdomains    = $parsed.subdomains
        $out.uniqueCount   = $parsed.uniqueCount
        $out.wildcards     = $parsed.wildcards
        $out.wildcardCount = $parsed.wildcardCount
        $out.ok = $true
        Write-Host "[+] crt.sh: $($parsed.uniqueCount) unique subdomains + $($parsed.wildcardCount) wildcard certs (public data, target untouched)"
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] crt.sh query failed: $($out.error)"
    }
    return $out
}

function Get-BountyFindings {
    <#
    Triages a subdomain list against the keyword table. Returns scored,
    CLASSIFIED candidates — never binary claims. Each candidate: host,
    class, weight, all matched classes, note, confidence label, and the
    evidence (CT entry).
    #>
    param(
        [Parameter(Mandatory=$true)][string[]]$Subdomains,
        [Parameter(Mandatory=$true)][string]$Program,
        [Parameter(Mandatory=$true)][string]$Target
    )
    $kws = Get-BountyKeywordTable
    $cands = @()
    foreach ($h in $Subdomains) {
        $matched = @()
        foreach ($k in $kws) {
            if ($h -match "(?i)$($k.Pattern)") { $matched += $k }
        }
        if ($matched.Count -eq 0) { continue }
        $best = @($matched | Sort-Object -Property Weight -Descending | Select-Object -First 1)[0]
        $conf = "low"
        if ($best.Weight -ge 4) { $conf = "medium" }
        elseif ($matched.Count -ge 2 -and $best.Weight -ge 3) { $conf = "medium" }
        $cands += [pscustomobject]@{
            host           = $h
            class          = $best.Class
            weight         = $best.Weight
            matchedClasses = (@($matched | ForEach-Object { $_.Class }) -join ",")
            note           = $best.Note
            confidence     = $conf
            program        = $Program
            targetRoot     = $Target
            evidence       = "crt.sh certificate-transparency (public log); host named in issued certificate"
            status         = "candidate-passive"
        }
    }
    return $cands
}

function Start-BountyRecon {
    <#
    PASSIVE recon only. Collects: crt.sh subdomains, DNS records, Shodan
    public data (free tier, key optional), certificate-transparency keyword
    triage. Sends ZERO packets to the target. REFUSES without a registered
    scope record (Scope Law).

    Returns: @{ ok, candidates, summary } and vault-logs the run.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Target,
        [string]$ShodanKeyFile = "",
        [int]$MaxCandidates = 25
    )
    $out = [pscustomobject]@{
        ok = $false; Program = $Name; Target = $Target;
        candidates = @(); summary = ""; error = ""
    }
    try {
        Import-BountyOsint
        # --- Scope Law gate ---
        if (-not (Test-BountyScopeRegistered -Name $Name -Target $Target)) {
            $out.error = "REFUSED: no scope record for '$Target' under '$Name'. Run Register-BountyTarget with the program's published scope page first. Even passive recon gets the scope on record — no exceptions."
            Write-Host "[!] $($out.error)"
            return $out
        }
        Write-Host "[*] scope record confirmed — passive recon authorized (public data only)"

        # --- Scope freshness (v1.2): scope pages change; stale scope = legal risk ---
        try {
            $regRec = @(Get-BountyTargets | Where-Object { $_.Program -eq $Name -and $_.Target -eq $Target }) | Select-Object -First 1
            if ($null -ne $regRec -and -not [string]::IsNullOrWhiteSpace("$($regRec.RegisteredUtc)")) {
                $fresh = Test-BountyScopeFreshness -RegisteredUtc "$($regRec.RegisteredUtc)"
                if ($fresh.ok -and $fresh.Stale) { Write-Host "[!] $($fresh.Note)" }
                elseif ($fresh.ok) { Write-Host "[*] $($fresh.Note)" }
            }
        } catch {
            Write-Host "[!] scope freshness check failed: $($_.Exception.Message)"
        }

        # --- Collector 1: crt.sh (module's own, or OSINT's) ---
        $subs = @()
        $ct = $null
        if ($script:BountyOsintLoaded) {
            try {
                Write-Host "[*] collecting crt.sh via OSINT module"
                $ct = Get-CrtSh -Domain $Target
                if ($ct.ok) { $subs = @($ct.subdomains) }
            } catch {
                Write-Host "[!] OSINT crt.sh failed, falling back to module collector: $($_.Exception.Message)"
            }
        }
        if ($subs.Count -eq 0) {
            $ct = Invoke-BountyCtQuery -Domain $Target
            if ($ct.ok) { $subs = @($ct.subdomains) }
        }
        Write-Host "[*] subdomain corpus: $($subs.Count) unique names"

        # --- Collector 2: DNS records (public resolver data) ---
        $dns = $null
        if ($script:BountyOsintLoaded) {
            try {
                Write-Host "[*] collecting DNS records via OSINT module"
                $dns = Get-DnsRecords -Domain $Target
            } catch {
                Write-Host "[!] OSINT DNS failed: $($_.Exception.Message)"
            }
        }

        # --- Collector 3: Shodan public data (free tier, key optional) ---
        # Shodan wants an IP: resolve the target via a public resolver first.
        $shodan = $null
        if ($script:BountyOsintLoaded) {
            try {
                $shodanTarget = $Target
                if ($Target -notmatch "^\d{1,3}(\.\d{1,3}){3}$") {
                    try {
                        $aRec = Resolve-DnsName -Name $Target -Type A -ErrorAction Stop |
                            Where-Object { $_.IPAddress } | Select-Object -First 1
                        if ($null -ne $aRec) {
                            $shodanTarget = $aRec.IPAddress
                            Write-Host "[*] resolved $Target -> $shodanTarget for Shodan lookup (public resolver, passive)"
                        }
                    } catch {
                        Write-Host "[!] A-record resolution for Shodan lookup failed: $($_.Exception.Message)"
                    }
                }
                Write-Host "[*] collecting Shodan public data via OSINT module (no target packets)"
                $shodan = Get-ShodanHost -Ip $shodanTarget -KeyFile $ShodanKeyFile
            } catch {
                Write-Host "[!] OSINT Shodan failed: $($_.Exception.Message)"
            }
        }

        # --- Triage: keyword classes ---
        $cands = @(Get-BountyFindings -Subdomains $subs -Program $Name -Target $Target)

        # --- Takeover triage (v1.2): passive CNAME check on the classes
        # where dangling records actually happen. Public-DNS CNAME only;
        # the HTTP fingerprint confirmation is manual, in-scope, minimum
        # traffic — this module never touches the CNAME target.
        $takeoverClasses = @("storage-host", "dev-host", "legacy-host", "staging-host", "docs-host")
        $takeovers = 0
        foreach ($c in @($cands | Where-Object { $takeoverClasses -contains $_.class })) {
            try {
                $cn = Resolve-DnsName -Name $c.host -Type CNAME -ErrorAction Stop |
                    Where-Object { $_.NameHost } | Select-Object -First 1
                if ($null -eq $cn) { continue }
                $t = Test-CnameDanglingPattern -Cname $cn.NameHost
                if ($t.Dangling) {
                    $takeovers++
                    $tconf = "low"
                    if ($t.Status -eq "Vulnerable") { $tconf = "medium" }
                    $cands += [pscustomobject]@{
                        host           = $c.host
                        class          = "takeover-candidate"
                        weight         = 5
                        matchedClasses = "takeover-candidate,$($c.matchedClasses)"
                        note           = "CNAME -> $($cn.NameHost) ($($t.Service), provider status: $($t.Status)). Unclaimed-resource signal per can-i-take-over-xyz. HTTP fingerprint to confirm: '$($t.HttpFingerprint)'. CONFIRMATION IS MANUAL, in-scope, minimum traffic — this module never touches the CNAME target."
                        confidence     = $tconf
                        program        = $Name
                        targetRoot     = $Target
                        evidence       = "public DNS CNAME (passive) + can-i-take-over-xyz fingerprint table"
                        status         = "candidate-passive-needs-http-confirm"
                    }
                }
            } catch {
                # Per-host DNS failures are noise, not errors — skip quietly.
            }
        }
        if ($takeovers -gt 0) {
            Write-Host "[+] takeover triage: $takeovers dangling-CNAME candidates (manual HTTP confirm required)"
        }

        $cands = @($cands | Sort-Object -Property weight -Descending | Select-Object -First $MaxCandidates)

        # --- Cross-run dedup (v1.2) ---
        $hist = @(Get-BountyReconHistory)
        $newCount = 0
        foreach ($c in $cands) {
            $isNew = Test-BountyCandidateNew -HostName $c.host -History $hist
            $c | Add-Member -NotePropertyName seenBefore -NotePropertyValue (-not $isNew) -Force
            if ($isNew) { $newCount++ }
        }
        try {
            Save-BountyReconRun -Program $Name -Target $Target -Hosts @($subs) -Candidates @($cands | ForEach-Object { $_.host }) | Out-Null
        } catch {
            Write-Host "[!] recon history save failed: $($_.Exception.Message)"
        }

        $out.candidates = $cands
        $byClass = @{}
        foreach ($c in $cands) {
            if (-not $byClass.ContainsKey($c.class)) { $byClass[$c.class] = 0 }
            $byClass[$c.class]++
        }
        $classLine = ($byClass.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ", "
        $out.summary = "Passive recon on $Target ($Name): $($subs.Count) subdomains, $($cands.Count) keyword-matched candidates ($newCount new since last run) [$classLine]. Takeover candidates: $takeovers. DNS ok=$($null -ne $dns -and $dns.ok). Shodan ok=$($null -ne $shodan -and $shodan.ok). Zero packets sent to the target."
        Write-Host "[+] $($out.summary)"
        $out.ok = $true
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] recon failed: $($out.error)"
    }
    New-BountyLog -Action "recon" -Target $Target -Result $out
    return $out
}

# ----------------------------------------------------------------------
# 4b. DANGLING-SERVICE TRIAGE — the takeover signal (v1.2)
# The medium-severity bread and butter ($500-$3,000). A CNAME on an
# in-scope subdomain pointing at a cloud resource that was deleted is
# claimable by anyone — IF the provider allows it. Suffix table sourced
# from the can-i-take-over-xyz catalog (EdOverflow) + 2026 status checks:
# Azure/Squarespace/CloudFront have since shipped protections and are
# marked Protected so nobody wastes a submission on them.
# This module never performs the HTTP fingerprint check itself —
# touching the CNAME target is an active step. It flags the candidate
# and names the exact manual verification (minimum traffic, in-scope).
# ----------------------------------------------------------------------
function Get-BountyDanglingFingerprintTable {
    return @(
        @{ Service = "GitHub Pages";         CnameSuffix = ".github.io";                ClaimNote = "claim username.github.io repo on github.com";                Status = "Vulnerable";         HttpFingerprint = "There isn't a GitHub Pages site here" },
        @{ Service = "Heroku";               CnameSuffix = ".herokuapp.com";            ClaimNote = "create Heroku app with that slug";                         Status = "Vulnerable";         HttpFingerprint = "No such app" },
        @{ Service = "AWS S3 website";       CnameSuffix = ".s3-website-";              ClaimNote = "create S3 bucket with the exact name (region must match)"; Status = "Vulnerable";         HttpFingerprint = "NoSuchBucket" },
        @{ Service = "AWS S3 (REST)";        CnameSuffix = ".s3.amazonaws.com";         ClaimNote = "create S3 bucket with the exact name";                     Status = "Vulnerable";         HttpFingerprint = "NoSuchBucket" },
        @{ Service = "AWS Elastic Beanstalk"; CnameSuffix = ".elasticbeanstalk.com";    ClaimNote = "create EB environment with that name (region must match)"; Status = "Vulnerable";         HttpFingerprint = "default environment error page" },
        @{ Service = "Netlify";              CnameSuffix = ".netlify.app";              ClaimNote = "claim the site slug on app.netlify.com";                   Status = "Vulnerable";         HttpFingerprint = "site not found / 404" },
        @{ Service = "Netlify (legacy)";     CnameSuffix = ".netlify.com";              ClaimNote = "claim the site slug on app.netlify.com";                   Status = "Vulnerable";         HttpFingerprint = "site not found / 404" },
        @{ Service = "Vercel";               CnameSuffix = ".vercel.app";               ClaimNote = "claim the project name on vercel.com";                     Status = "Vulnerable";         HttpFingerprint = "DEPLOYMENT_NOT_FOUND" },
        @{ Service = "Fastly";               CnameSuffix = ".fastly.net";               ClaimNote = "claim the service on fastly.com (needs verification)";    Status = "Needs verification"; HttpFingerprint = "Fastly error: unknown domain" },
        @{ Service = "Fastly (LB)";          CnameSuffix = ".fastlylb.net";             ClaimNote = "claim the service on fastly.com (needs verification)";    Status = "Needs verification"; HttpFingerprint = "Fastly error: unknown domain" },
        @{ Service = "Shopify";              CnameSuffix = ".myshopify.com";            ClaimNote = "create store with that myshopify name";                    Status = "Vulnerable";         HttpFingerprint = "Sorry, this shop is currently unavailable" },
        @{ Service = "Zendesk";              CnameSuffix = ".zendesk.com";              ClaimNote = "claim the help-center subdomain";                          Status = "Vulnerable";         HttpFingerprint = "Help Center Closed" },
        @{ Service = "Surge.sh";             CnameSuffix = ".surge.sh";                 ClaimNote = "deploy to that surge.sh subdomain";                        Status = "Vulnerable";         HttpFingerprint = "project not found" },
        @{ Service = "Bitbucket Pages";      CnameSuffix = ".bitbucket.io";             ClaimNote = "create Bitbucket repo username.bitbucket.io";              Status = "Vulnerable";         HttpFingerprint = "Repository not found" },
        @{ Service = "GitLab Pages";         CnameSuffix = ".gitlab.io";                ClaimNote = "create GitLab Pages project with the name";                Status = "Vulnerable";         HttpFingerprint = "404: page could not be found" },
        @{ Service = "Readme.io";            CnameSuffix = ".readme.io";                ClaimNote = "claim the project on readme.com";                          Status = "Vulnerable";         HttpFingerprint = "Project not found" },
        @{ Service = "Statuspage";           CnameSuffix = ".statuspage.io";            ClaimNote = "claim the page on statuspage.io";                         Status = "Vulnerable";         HttpFingerprint = "No statuspage found" },
        @{ Service = "Helpjuice";            CnameSuffix = ".helpjuice.com";            ClaimNote = "claim the knowledge base";                                 Status = "Vulnerable";         HttpFingerprint = "We could not find what you're looking for" },
        @{ Service = "Tumblr";               CnameSuffix = ".tumblr.com";               ClaimNote = "claim the tumblr blog name";                               Status = "Vulnerable";         HttpFingerprint = "There's nothing here" },
        @{ Service = "Pantheon";             CnameSuffix = ".pantheonsite.io";          ClaimNote = "claim the site name on pantheon.io";                       Status = "Vulnerable";         HttpFingerprint = "404 Not Found" },
        @{ Service = "Cargo";                CnameSuffix = ".cargocollections.com";     ClaimNote = "claim the site on cargo.site";                             Status = "Vulnerable";         HttpFingerprint = "404" },
        @{ Service = "Azure App Service";    CnameSuffix = ".azurewebsites.net";        ClaimNote = "owner verification now required — likely blocked";         Status = "Protected";          HttpFingerprint = "404 Web Site not found (verification blocks claim)" },
        @{ Service = "Squarespace";          CnameSuffix = ".squarespace.com";          ClaimNote = "domain verification required before CNAME takes effect";  Status = "Protected";          HttpFingerprint = "verification blocks claim" },
        @{ Service = "AWS CloudFront";       CnameSuffix = ".cloudfront.net";           ClaimNote = "alt-CNAME verification required — likely blocked";        Status = "Protected";          HttpFingerprint = "403 The request could not be satisfied" }
    )
}

function Test-CnameDanglingPattern {
    <#
    Pure: does a CNAME target match a dangling-service suffix? Returns
    the service record or Dangling=$false. Trailing-dot and case safe.
    #>
    param([Parameter(Mandatory=$true)][string]$Cname)
    $t = $Cname.Trim().ToLower().TrimEnd(".")
    foreach ($row in (Get-BountyDanglingFingerprintTable)) {
        $sfx = $row.CnameSuffix.ToLower()
        $hit = $false
        if ($sfx.StartsWith(".")) {
            # Dot-suffixes anchor at the END: "notgithub.io.evil.com"
            # contains ".github.io" but is not a GitHub Pages CNAME.
            $hit = $t.EndsWith($sfx)
        } else {
            # Mid-hostname infixes (e.g. ".s3-website-") need contains.
            $hit = ($t -like "*$sfx*")
        }
        if ($hit) {
            return [pscustomobject]@{
                Dangling = $true; Service = $row.Service; CnameSuffix = $row.CnameSuffix
                ClaimNote = $row.ClaimNote; Status = $row.Status; HttpFingerprint = $row.HttpFingerprint
            }
        }
    }
    return [pscustomobject]@{
        Dangling = $false; Service = ""; CnameSuffix = ""; ClaimNote = ""; Status = ""; HttpFingerprint = ""
    }
}

# ----------------------------------------------------------------------
# 4c. SCOPE FRESHNESS + RECON HISTORY + SEVERITY (v1.2)
# Scope pages change — GitHub restructured 2026-07-27. A recon run on a
# stale scope is a legal risk. Recon history dedups candidates across
# runs so the same 25 hosts don't get re-triaged every shift.
# ----------------------------------------------------------------------
function Test-BountyScopeFreshness {
    <#
    Pure: how old is a scope registration (ISO UTC string)? Stale beyond
    -StaleDays (default 30) — passive recon stays safe, but active work
    must wait for a scope-page re-read.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$RegisteredUtc,
        [int]$StaleDays = 30
    )
    $out = [pscustomobject]@{ ok = $false; Days = -1; Stale = $false; Note = ""; error = "" }
    try {
        $dt = [datetime]::Parse($RegisteredUtc).ToUniversalTime()
        $days = [int][math]::Floor(((Get-Date).ToUniversalTime() - $dt).TotalDays)
        $out.Days = $days
        $out.Stale = ($days -gt $StaleDays)
        if ($out.Stale) {
            $out.Note = "Scope registered $days days ago (> $StaleDays) — scope pages change (e.g. GitHub restructured 2026-07-27). Re-read the published scope page before any active work; passive recon stays safe."
        } else {
            $out.Note = "Scope registered $days days ago — fresh."
        }
        $out.ok = $true
    } catch {
        $out.error = $_.Exception.Message
    }
    return $out
}

function Test-BountySeverityValid {
    <#
    Pure: reporter-assessed severity names. Case-insensitive (matches the
    v1.0 -notcontains behavior; triage teams normalize anyway).
    #>
    param([Parameter(Mandatory=$true)][string]$Severity)
    $valid = @("Critical", "High", "Medium", "Low", "Informational")
    return ($valid -contains $Severity)
}

function Get-BountyReconHistoryPath {
    return (Join-Path (Get-BountyRoot) "bounty-recon-history.json")
}

function Get-BountyReconHistory {
    <#
    Prior recon runs (last 50). Each: Program, Target, Utc, HostCount,
    Hosts[], Candidates[]. Used for cross-run candidate dedup.
    #>
    try {
        $p = Get-BountyReconHistoryPath
        if (-not (Test-Path $p)) { return @() }
        $raw = Get-Content -Path $p -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        return @($raw | ConvertFrom-Json)
    } catch {
        Write-Host "[!] recon history read failed: $($_.Exception.Message)"
        return @()
    }
}

function Save-BountyReconRun {
    <#
    Appends one recon run to the history (trims to 50). Never blocks recon.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Program,
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][string[]]$Hosts,
        [Parameter(Mandatory=$true)][string[]]$Candidates
    )
    try {
        $hist = @(Get-BountyReconHistory)
        $rec = [pscustomobject]@{
            Program    = $Program
            Target     = $Target
            Utc        = (Get-Date).ToUniversalTime().ToString("o")
            HostCount  = $Hosts.Count
            Hosts      = @($Hosts | Sort-Object -Unique)
            Candidates = @($Candidates | Sort-Object -Unique)
        }
        $hist = @($hist) + @($rec)
        if ($hist.Count -gt 50) { $hist = @($hist | Select-Object -Last 50) }
        $hist | ConvertTo-Json -Depth 4 | Set-Content -Path (Get-BountyReconHistoryPath) -Encoding UTF8
        return $true
    } catch {
        Write-Host "[!] recon history save failed: $($_.Exception.Message)"
        return $false
    }
}

function Test-BountyCandidateNew {
    <#
    Pure: is this host unseen in prior recon history (case-insensitive)?
    #>
    param(
        [Parameter(Mandatory=$true)][string]$HostName,
        [Parameter(Mandatory=$true)][array]$History
    )
    $h = $HostName.Trim().ToLower()
    foreach ($run in $History) {
        $seen = @()
        if ($null -ne $run.Candidates) { $seen += @($run.Candidates) }
        if ($null -ne $run.Hosts)      { $seen += @($run.Hosts) }
        foreach ($s in $seen) {
            if ("$s".Trim().ToLower() -eq $h) { return $false }
        }
    }
    return $true
}

# ----------------------------------------------------------------------
# 4d. CT HOST-STATUS TRIAGE — the retired-vs-live verdict (v1.3)
# Every recon run classified watch items by hand: "no cert issued since
# 2014 -> SUSPECTED RETIRED". That judgment is now code. ConvertFrom-
# BountyCtRowsDetailed expands full crt.sh JSON rows to one row per
# (host, certificate); Get-BountyHostDisposition picks the newest cert
# and classifies the host: LIVE / EXPIRED-RECENT / EXPIRED-STALE /
# SUSPECTED-RETIRED / NO-CT-EVIDENCE. Invoke-BountyCtHostQuery runs the
# passive crt.sh exact-host query + classification in one call — it is
# the function the per-run recon notes were doing by hand with browser
# reads. Zero packets to the target in all of this.
# ----------------------------------------------------------------------
function ConvertFrom-BountyCtRowsDetailed {
    <#
    Pure offline parser for FULL crt.sh JSON rows (id, serial_number,
    issuer_name, not_before, not_after, name_value). Returns one row per
    (host, certificate) — multi-name certs expand to one row per name.
    Wildcard rows are skipped here (they are cert-coverage signal, not
    hosts; the v1.2 name parser already tracks them separately).
    #>
    param([Parameter(Mandatory=$true)][array]$Rows)
    $out = @()
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }
        $nv = "$($row.name_value)"
        foreach ($n in ($nv -split "`r?`n")) {
            $t = $n.Trim().ToLower()
            if ($t -eq "") { continue }
            if ($t.StartsWith("*")) { continue }
            $out += [pscustomobject]@{
                host      = $t
                certId    = "$($row.id)"
                serial    = "$($row.serial_number)"
                issuer    = "$($row.issuer_name)"
                notBefore = "$($row.not_before)"
                notAfter  = "$($row.not_after)"
            }
        }
    }
    return @($out)
}

function Test-BountyCertStatus {
    <#
    Pure: classify ONE certificate by not_before/not_after against -NowUtc
    (injectable for tests; defaults to current UTC).
      LIVE             — not_after is in the future
      EXPIRED-RECENT   — expired under 90 days (surface may just be lapsed)
      EXPIRED-STALE    — expired 90 days to 2 years (dead, never cleaned up)
      SUSPECTED-RETIRED — no renewal in over 2 years (host almost certainly
        retired — stop burning recon time on it)
    Malformed dates return ok=$false, never a guess.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$NotBefore,
        [Parameter(Mandatory=$true)][string]$NotAfter,
        [datetime]$NowUtc = ((Get-Date).ToUniversalTime())
    )
    $out = [pscustomobject]@{
        ok = $false; status = ""; daysSinceExpiry = -1;
        notBefore = ""; notAfter = ""; note = ""; error = ""
    }
    try {
        $nb = [datetime]::Parse($NotBefore).ToUniversalTime()
        $na = [datetime]::Parse($NotAfter).ToUniversalTime()
        if ($na -le $nb) {
            $out.error = "not_after ($NotAfter) is not after not_before ($NotBefore) — malformed CT row."
            return $out
        }
        $out.notBefore = $NotBefore
        $out.notAfter  = $NotAfter
        if ($na -gt $NowUtc) {
            $out.status = "LIVE"
            $out.note = "Certificate valid until $NotAfter — the host has a live TLS surface."
        } else {
            $d = [int][math]::Floor(($NowUtc - $na).TotalDays)
            $out.daysSinceExpiry = $d
            if ($d -lt 90) {
                $out.status = "EXPIRED-RECENT"
                $out.note = "Expired $d days ago — surface may just be lapsed; re-check next run."
            } elseif ($d -le 730) {
                $out.status = "EXPIRED-STALE"
                $out.note = "Expired $d days ago — dead surface, owner never cleaned it up."
            } else {
                $out.status = "SUSPECTED-RETIRED"
                $out.note = "No renewal in $d days (over 2 years) — host almost certainly retired."
            }
        }
        $out.ok = $true
    } catch {
        $out.error = $_.Exception.Message
    }
    return $out
}

function Get-BountyHostDisposition {
    <#
    Pure: from detailed CT rows for ONE host, pick the newest certificate
    and classify the host's disposition. Newest-wins — a host is only as
    dead as its freshest cert. Zero rows -> NO-CT-EVIDENCE (no signal
    either way, never a guess).
    #>
    param([Parameter(Mandatory=$true)][array]$CertRows)
    $out = [pscustomobject]@{
        ok = $false; host = ""; status = ""; certCount = 0;
        newestNotAfter = ""; issuer = ""; daysSinceExpiry = -1;
        note = ""; error = ""
    }
    try {
        $rows = @($CertRows | Where-Object { $null -ne $_ })
        if ($rows.Count -eq 0) {
            $out.status = "NO-CT-EVIDENCE"
            $out.note = "crt.sh has no certificate history for this host — no live-surface signal either way."
            $out.ok = $true
            return $out
        }
        $out.host = "$($rows[0].host)"
        $newest = $null
        $newestNa = [datetime]::MinValue
        foreach ($r in $rows) {
            try {
                $na = [datetime]::Parse("$($r.notAfter)").ToUniversalTime()
                if ($na -gt $newestNa) { $newestNa = $na; $newest = $r }
            } catch {
                # Unparseable row: ignored in the newest-wins race, not fatal.
            }
        }
        if ($null -eq $newest) {
            $out.error = "No parseable not_after dates in $($rows.Count) CT rows."
            return $out
        }
        $st = Test-BountyCertStatus -NotBefore "$($newest.notBefore)" -NotAfter "$($newest.notAfter)"
        $out.status = $st.status
        $out.certCount = $rows.Count
        $out.newestNotAfter = "$($newest.notAfter)"
        $out.issuer = "$($newest.issuer)"
        $out.daysSinceExpiry = $st.daysSinceExpiry
        $out.note = $st.note
        $out.ok = $st.ok
        if (-not $st.ok) { $out.error = $st.error }
    } catch {
        $out.error = $_.Exception.Message
    }
    return $out
}

function Invoke-BountyCtHostQuery {
    <#
    Passive CT status check for ONE exact hostname. Queries crt.sh only
    (public certificate-transparency logs); sends ZERO packets to the
    target. Returns the host disposition + full cert history, vault-logged.
    This is the automation of the per-run recon notes that classified
    GitHub watch items (branch, workspaces-dev, staging-lab...) by hand.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$HostName,
        [int]$TimeoutSec = 45
    )
    $out = [pscustomobject]@{
        ok = $false; host = $HostName; disposition = $null;
        certs = @(); source = "crt.sh"; error = ""
    }
    try {
        $h = $HostName.Trim().ToLower().TrimEnd(".")
        if ([string]::IsNullOrWhiteSpace($h) -or $h -notmatch "^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$") {
            $out.error = "Not a plausible hostname: '$HostName'"
            Write-Host "[!] $($out.error)"
            return $out
        }
        $q = "https://crt.sh/?q=$h&output=json"
        Write-Host "[*] crt.sh passive exact-host query: $h (public CT logs only, target untouched)"
        $r = $null
        $attempt = 0
        while ($attempt -lt 3) {
            $attempt++
            try {
                $r = Invoke-RestMethod -Uri $q -UserAgent $script:HttpUA -TimeoutSec $TimeoutSec
                break
            } catch {
                if ($attempt -ge 3) { throw }
                Write-Host "[*] crt.sh attempt $attempt failed ($($_.Exception.Message)) — retrying in 5s"
                Start-Sleep -Seconds 5
            }
        }
        $rows = @(ConvertFrom-BountyCtRowsDetailed -Rows @($r))
        $disp = Get-BountyHostDisposition -CertRows $rows
        $out.certs = $rows
        $out.disposition = $disp
        $out.ok = $disp.ok
        Write-Host "[+] $($disp.host): $($disp.status) — $($disp.note)"
        New-BountyLog -Action "ct-host-query" -Target $h -Result $out
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] crt.sh host query failed: $($out.error)"
    }
    return $out
}

# ----------------------------------------------------------------------
# 5. MITIGATION TABLE — the Better-Way Law for bounty reports
# ----------------------------------------------------------------------
function Get-BountyMitigationAdvice {
    <#
    Fix guidance per finding class. Every report ships one of these — a
    detection without its fix is unfinished work.
    #>
    param([Parameter(Mandatory=$true)][string]$FindingClass)
    $c = $FindingClass.ToLower()
    switch -Wildcard ($c) {
        "*xss*" {
            return "Fix: output-encode all user data in context (HTML/attr/JS/URL); deploy strict Content-Security-Policy without unsafe-inline; HttpOnly+Secure+SameSite cookies. Prevent: framework auto-escaping on by default; CSP report-only first, enforce after. Rollback: CSP change reverts in one deploy."
        }
        "*idor*" {
            return "Fix: server-side authorization check on every object reference (deny by default; ownership check before read/write). Prevent: centralized authz middleware + object-level tests in CI. Rollback: middleware flag revert."
        }
        "*ssrf*" {
            return "Fix: allowlist egress destinations; disable redirects on URL-fetching code; block link-local/metadata IPs (169.254.169.254, fd00::/8); no user-controlled URL without validation. Prevent: egress proxy with allowlist. Rollback: proxy config revert."
        }
        "*takeover*" {
            return "Fix: remove the dangling DNS CNAME/A record or reclaim the external resource (bucket, PaaS app, CDN endpoint). Prevent: DNS-record inventory reconciled against cloud resources on a schedule; CT monitoring for new certs on your names. Rollback: DNS change reverts in TTL window."
        }
        "*info*" {
            return "Fix: strip debug output, stack traces, and internal hostnames from public responses; rotate any exposed secrets. Prevent: error-handling middleware that returns generic messages in prod; secret-scan in CI. Rollback: config revert."
        }
        "*php*rce*" {
            return "Fix: patch PHP to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35+ (CVE-2026-109618); block upload_progress at the edge as defense-in-depth. See the php-shield module: mitigations + verification. Prevent: package-version pinning + monthly patch task. Rollback: snapshot before upgrade."
        }
        "*waf*" {
            return "Fix: the bypass proves a WAF rule gap — add the missing signature at the WAF, then fix the underlying app vuln (WAF is not the patch). Prevent: WAF rule regression tests on every deploy. Rollback: rule toggle."
        }
        "*s3*" {
            return "Fix: bucket policy deny-public by default; remove public ACLs; enable access logging. Prevent: organization SCP blocking public buckets; config-rule drift alerts. Rollback: policy version revert."
        }
        "*auth*bypass*" {
            return "Fix: enforce authentication on every entry path (middleware, not per-handler); invalidate the bypass vector; force session rotation. Prevent: authn coverage tests in CI; no security-through-route-obscurity. Rollback: deploy revert."
        }
        default {
            return "Fix: remediate the root cause at the application/config layer, not the symptom. Prevent: add a regression test and a monitoring check for this class. Rollback: snapshot config before changes."
        }
    }
}

# ----------------------------------------------------------------------
# 6. PROFESSIONAL REPORT — what gets paid
# ----------------------------------------------------------------------
function New-BountyReport {
    <#
    Builds the submission-ready report: summary, steps to reproduce,
    impact, evidence manifest, remediation, scope authorization. Triage
    teams process hundreds of reports a week — clean reports get paid
    faster. Exports .md + .json, SHA-256 hashed, vault-logged.
    NEVER submits anything — submission happens only on Gregg's word.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Program,
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string]$Severity,
        [Parameter(Mandatory=$true)][string]$Summary,
        [Parameter(Mandatory=$true)][string[]]$Steps,
        [Parameter(Mandatory=$true)][string]$Impact,
        [string]$FindingClass = "general",
        [string]$EvidenceDir = "",
        [string]$OutDir = "",
        [string]$ScopeUrl = ""
    )
    $out = [pscustomobject]@{
        ok = $false; reportPath = ""; jsonPath = ""; sha256 = ""; error = ""
    }
    try {
        Import-BountyVault
        if (-not (Test-BountySeverityValid -Severity $Severity)) {
            $out.error = "Severity must be one of: Critical, High, Medium, Low, Informational"
            Write-Host "[!] $($out.error)"
            return $out
        }
        if ($Title.Length -gt 140) {
            Write-Host "[!] title is $($Title.Length) chars — program triage truncates long titles (HackerOne ~140); consider shortening."
        }
        $ts = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
        $safe = ($Title -replace "[^a-zA-Z0-9]+", "-").Trim("-")
        if ($safe.Length -gt 60) { $safe = $safe.Substring(0, 60) }
        if ([string]::IsNullOrWhiteSpace($OutDir)) {
            $OutDir = Join-Path (Get-BountyRoot) "bounty-reports"
        }
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

        # --- Scope authorization block ---
        $scopeBlock = ""
        $reg = @(Get-BountyTargets) | Where-Object { $_.Program -eq $Program -and $_.Target -eq $Target }
        if ($reg.Count -gt 0) {
            $r = $reg[0]
            $scopeBlock = "Scope registered: $($r.ScopeUrl) (registered $($r.RegisteredUtc)). Authorizes: $($r.AuthorizedNote)"
        } elseif ($ScopeUrl -ne "") {
            $scopeBlock = "Scope URL supplied at report time: $ScopeUrl (NOT from the registry — verify against the published page before submitting)."
        } else {
            $scopeBlock = "WARNING: no registered scope and no scope URL — do NOT submit until the published scope is recorded with Register-BountyTarget."
        }

        # --- Evidence manifest ---
        $evLines = @()
        if ($EvidenceDir -ne "" -and (Test-Path $EvidenceDir)) {
            foreach ($f in (Get-ChildItem -Path $EvidenceDir -File)) {
                try {
                    $h = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash
                    $evLines += "- $($f.Name) (SHA-256 $h)"
                } catch {
                    $evLines += "- $($f.Name) (hash failed: $($_.Exception.Message))"
                }
            }
        }
        if ($evLines.Count -eq 0) { $evLines += "- (no evidence files supplied — attach PoC/request/response evidence before submitting)" }
        $evText = $evLines -join "`r`n"

        $mitigation = Get-BountyMitigationAdvice -FindingClass $FindingClass

        $stepText = ""
        $i = 1
        foreach ($s in $Steps) { $stepText += "$i. $s`r`n"; $i++ }

        $md = @"
# Bug Bounty Report — $Title

- Program: $Program
- Target: $Target
- Severity: $Severity (reporter-assessed; triage decides)
- Finding class: $FindingClass
- Date (UTC): $((Get-Date).ToUniversalTime().ToString("o"))
- Reporter: Gregg (submission ONLY on his explicit word)

## Scope authorization

$scopeBlock

## Summary

$Summary

## Steps to reproduce

$stepText

## Impact

$Impact

## Evidence (SHA-256 manifest)

$evText

## Remediation (the fix ships with the finding)

$mitigation

## Disclosure terms

Report generated by the BLACKBOX bugbounty module. Passive recon only unless
the registered scope explicitly authorized active testing (see Scope
authorization above). Coordinated disclosure: do not publish details until
the program's disclosure window allows it. Before submitting, re-check the
evidence manifest — evidence files must NOT contain live credentials,
cookies, session tokens, or other secrets. Scrub first.
"@
        $mdPath = Join-Path $OutDir "bounty-report-$ts-$safe.md"
        Set-Content -Path $mdPath -Value $md -Encoding UTF8

        $jobj = [pscustomobject]@{
            title = $Title; program = $Program; target = $Target
            severity = $Severity; findingClass = $FindingClass
            summary = $Summary; steps = $Steps; impact = $Impact
            mitigation = $mitigation; scope = $scopeBlock
            evidenceManifest = $evLines
            utc = (Get-Date).ToUniversalTime().ToString("o")
        }
        $jsonPath = Join-Path $OutDir "bounty-report-$ts-$safe.json"
        $jobj | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8

        $hash = (Get-FileHash -Path $mdPath -Algorithm SHA256).Hash
        Write-Host "[+] report written: $mdPath"
        Write-Host "[+] json written  : $jsonPath"
        Write-Host "[+] SHA-256 (md)  : $hash"
        $out.ok = $true
        $out.reportPath = $mdPath
        $out.jsonPath = $jsonPath
        $out.sha256 = $hash
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] report build failed: $($out.error)"
    }
    New-BountyLog -Action "report" -Target $Target -Result $out
    return $out
}

# ----------------------------------------------------------------------
# 6b. HYGIENE BATTERY — offline self-test (v1.2)
# Zero network. Runs the pure logic: keyword table, multi-class scoring,
# dangling fingerprints, scope freshness, candidate dedup, CT parsing,
# severity validation, program table. Scope-safe result collection:
# scriptblock output is captured, never child-scoped += (the vault lesson).
# ----------------------------------------------------------------------
function Test-BountyHygiene {
    $results = @()
    $add = {
        param([string]$Name, [bool]$Pass, [string]$Detail)
        [pscustomobject]@{ name = $Name; pass = $Pass; detail = "$Detail" }
    }

    # 1. keyword table sanity
    $kw = Get-BountyKeywordTable
    $results += &$add "keyword: >=15 classes" ($kw.Count -ge 15) "count=$($kw.Count)"
    $classes = @($kw | ForEach-Object { $_.Class })
    $results += &$add "keyword: classes unique" ((@($classes | Sort-Object -Unique)).Count -eq $classes.Count) "count=$($classes.Count)"
    $badW = @($kw | Where-Object { $_.Weight -lt 1 -or $_.Weight -gt 5 })
    $results += &$add "keyword: weights 1-5" ($badW.Count -eq 0) "out-of-range=$($badW.Count)"
    $badRe = @()
    foreach ($k in $kw) { try { $null = "x" -match $k.Pattern } catch { $badRe += $k.Class } }
    $results += &$add "keyword: patterns compile" ($badRe.Count -eq 0) "bad=$($badRe -join ',')"

    # 2. multi-class scoring
    $m = @(Get-BountyFindings -Subdomains @("dev-api.example.com", "assets.example.com") -Program "t" -Target "example.com")
    $devapi = @($m | Where-Object { $_.host -eq "dev-api.example.com" })[0]
    $results += &$add "findings: multi-class counted" ($devapi.matchedClasses -like "*dev-host*" -and $devapi.matchedClasses -like "*api-host*") "matched=$($devapi.matchedClasses)"
    $assets = @($m | Where-Object { $_.host -eq "assets.example.com" })[0]
    $results += &$add "findings: storage class" ($assets.class -eq "storage-host") "class=$($assets.class)"
    $mnone = @(Get-BountyFindings -Subdomains @("plain.example.com") -Program "t" -Target "example.com")
    $results += &$add "findings: no match = no candidate" ($mnone.Count -eq 0) "count=$($mnone.Count)"

    # 3. dangling fingerprints
    $fp = Get-BountyDanglingFingerprintTable
    $results += &$add "dangling: >=20 services" ($fp.Count -ge 20) "count=$($fp.Count)"
    $svc = @($fp | ForEach-Object { $_.Service })
    $results += &$add "dangling: services unique" ((@($svc | Sort-Object -Unique)).Count -eq $svc.Count) "count=$($svc.Count)"
    $t1 = Test-CnameDanglingPattern -Cname "acme.github.io"
    $results += &$add "dangling: github.io hit" ($t1.Dangling -and $t1.Service -eq "GitHub Pages") "service=$($t1.Service)"
    $t2 = Test-CnameDanglingPattern -Cname "acme.herokuapp.com."
    $results += &$add "dangling: trailing dot + heroku" ($t2.Dangling -and $t2.Service -eq "Heroku") "service=$($t2.Service)"
    $t3 = Test-CnameDanglingPattern -Cname "cdn.acme-cdn.net"
    $results += &$add "dangling: non-listed no false hit" (-not $t3.Dangling) "dangling=$($t3.Dangling)"
    $t3b = Test-CnameDanglingPattern -Cname "sub.github.io.evil.com"
    $results += &$add "dangling: mid-string suffix no false hit" (-not $t3b.Dangling) "dangling=$($t3b.Dangling)"
    $t4 = Test-CnameDanglingPattern -Cname "WWW.ACME.GITHUB.IO"
    $results += &$add "dangling: case-insensitive" ($t4.Dangling -and $t4.Service -eq "GitHub Pages") "service=$($t4.Service)"
    $t5 = Test-CnameDanglingPattern -Cname "bucket.s3-website-us-east-1.amazonaws.com"
    $results += &$add "dangling: s3-website infix" ($t5.Dangling -and $t5.Service -eq "AWS S3 website") "service=$($t5.Service)"
    $t6 = Test-CnameDanglingPattern -Cname "app.azurewebsites.net"
    $results += &$add "dangling: azure marked Protected" ($t6.Dangling -and $t6.Status -eq "Protected") "status=$($t6.Status)"

    # 4. scope freshness
    $fresh = Test-BountyScopeFreshness -RegisteredUtc ((Get-Date).ToUniversalTime().AddDays(-5).ToString("o"))
    $results += &$add "freshness: 5d fresh" ($fresh.ok -and -not $fresh.Stale -and $fresh.Days -eq 5) "days=$($fresh.Days)"
    $old = Test-BountyScopeFreshness -RegisteredUtc ((Get-Date).ToUniversalTime().AddDays(-60).ToString("o"))
    $results += &$add "freshness: 60d stale" ($old.ok -and $old.Stale) "stale=$($old.Stale)"
    $bnd = Test-BountyScopeFreshness -RegisteredUtc ((Get-Date).ToUniversalTime().AddDays(-30).ToString("o")) -StaleDays 30
    $results += &$add "freshness: 30d boundary fresh" ($bnd.ok -and -not $bnd.Stale) "days=$($bnd.Days) stale=$($bnd.Stale)"
    $bad = Test-BountyScopeFreshness -RegisteredUtc "not-a-date"
    $results += &$add "freshness: bad date safe" (-not $bad.ok -and $bad.error -ne "") ""

    # 5. candidate dedup
    $hist = @([pscustomobject]@{ Program = "p"; Target = "t"; Hosts = @("a.example.com"); Candidates = @("dev.example.com") })
    $results += &$add "dedup: unseen host is new" (Test-BountyCandidateNew -HostName "new.example.com" -History $hist) ""
    $results += &$add "dedup: seen host not new" (-not (Test-BountyCandidateNew -HostName "DEV.example.com" -History $hist)) "case-insensitive"
    $results += &$add "dedup: empty history all new" (Test-BountyCandidateNew -HostName "x.example.com" -History @()) ""

    # 6. CT name parsing
    $rows = @(
        [pscustomobject]@{ name_value = "www.example.com`r`napi.example.com" },
        [pscustomobject]@{ name_value = "*.example.com" },
        [pscustomobject]@{ name_value = "*.dev.example.com`nmail.example.com" }
    )
    $p = ConvertFrom-BountyCtNames -Rows $rows
    $results += &$add "ctparse: 3 subs + 2 wildcards" ($p.uniqueCount -eq 3 -and $p.wildcardCount -eq 2) "subs=$($p.uniqueCount) wild=$($p.wildcardCount)"
    $results += &$add "ctparse: wildcard kept out of subs" ($p.subdomains -notcontains "*.example.com") ""

    # 6b. detailed CT rows
    $drows2 = @(
        [pscustomobject]@{ name_value = "www.example.com`r`napi.example.com"; id = 1; serial_number = "aa"; issuer_name = "DigiCert"; not_before = "2025-01-01T00:00:00Z"; not_after = "2026-01-01T00:00:00Z" },
        [pscustomobject]@{ name_value = "*.example.com"; id = 2; serial_number = "bb"; issuer_name = "DigiCert"; not_before = "2025-01-01T00:00:00Z"; not_after = "2026-01-01T00:00:00Z" }
    )
    $dp = ConvertFrom-BountyCtRowsDetailed -Rows $drows2
    $results += &$add "ctdetail: 2 host rows, wildcard skipped" ($dp.Count -eq 2 -and $dp[0].issuer -eq "DigiCert" -and $dp[0].notAfter -eq "2026-01-01T00:00:00Z") "rows=$($dp.Count)"

    # 6c. cert status triage
    $now = (Get-Date).ToUniversalTime()
    $s1 = Test-BountyCertStatus -NotBefore $now.AddYears(-1).ToString("o") -NotAfter $now.AddDays(60).ToString("o")
    $results += &$add "cert: valid cert is LIVE" ($s1.ok -and $s1.status -eq "LIVE") "status=$($s1.status)"
    $s2 = Test-BountyCertStatus -NotBefore $now.AddYears(-2).ToString("o") -NotAfter $now.AddDays(-10).ToString("o")
    $results += &$add "cert: 10d lapsed is EXPIRED-RECENT" ($s2.ok -and $s2.status -eq "EXPIRED-RECENT" -and $s2.daysSinceExpiry -eq 10) "status=$($s2.status) days=$($s2.daysSinceExpiry)"
    $s2b = Test-BountyCertStatus -NotBefore $now.AddYears(-2).ToString("o") -NotAfter $now.AddDays(-200).ToString("o")
    $results += &$add "cert: 200d lapsed is EXPIRED-STALE" ($s2b.ok -and $s2b.status -eq "EXPIRED-STALE") "status=$($s2b.status)"
    $s3 = Test-BountyCertStatus -NotBefore "2019-01-24T00:00:00Z" -NotAfter "2021-01-28T00:00:00Z"
    $results += &$add "cert: 2021 expiry is SUSPECTED-RETIRED" ($s3.ok -and $s3.status -eq "SUSPECTED-RETIRED") "status=$($s3.status) days=$($s3.daysSinceExpiry)"
    $s4 = Test-BountyCertStatus -NotBefore "not-a-date" -NotAfter "also-not"
    $results += &$add "cert: bad date safe" (-not $s4.ok -and $s4.error -ne "") ""
    $s5 = Test-BountyCertStatus -NotBefore "2020-01-01T00:00:00Z" -NotAfter "2019-01-01T00:00:00Z"
    $results += &$add "cert: reversed dates rejected" (-not $s5.ok) "error=$($s5.error)"

    # 6d. host disposition
    $drows = @(
        [pscustomobject]@{ host = "branch.github.com"; certId = "1"; serial = "s"; issuer = "DigiCert"; notBefore = "2014-04-09T00:00:00Z"; notAfter = "2017-04-13T00:00:00Z" },
        [pscustomobject]@{ host = "branch.github.com"; certId = "2"; serial = "s"; issuer = "DigiCert"; notBefore = "2015-04-09T00:00:00Z"; notAfter = "2018-04-13T00:00:00Z" }
    )
    $disp = Get-BountyHostDisposition -CertRows $drows
    $results += &$add "disposition: newest-wins + retired" ($disp.ok -and $disp.host -eq "branch.github.com" -and $disp.status -eq "SUSPECTED-RETIRED" -and $disp.certCount -eq 2 -and $disp.newestNotAfter -eq "2018-04-13T00:00:00Z") "status=$($disp.status) certs=$($disp.certCount)"
    $dispNone = Get-BountyHostDisposition -CertRows @()
    $results += &$add "disposition: no rows = NO-CT-EVIDENCE" ($dispNone.ok -and $dispNone.status -eq "NO-CT-EVIDENCE") "status=$($dispNone.status)"
    $dispBad = Get-BountyHostDisposition -CertRows @([pscustomobject]@{ host = "x.example.com"; certId = ""; serial = ""; issuer = ""; notBefore = "bad"; notAfter = "bad" })
    $results += &$add "disposition: unparseable dates = error" (-not $dispBad.ok -and $dispBad.error -ne "") "error=$($dispBad.error)"

    # 6e. scope record refresh (pure upsert, no file I/O)
    $recs = @([pscustomobject]@{ Program = "p"; Target = "t.example.com"; ScopeUrl = "https://x"; AuthorizedNote = "old"; ScopePublic = $false; RegisteredUtc = "2026-01-01T00:00:00Z"; RegisteredBy = "Gregg" })
    $u1 = Update-BountyScopeRecord -Records $recs -Name "p" -Target "t.example.com" -ScopeUrl "https://x" -AuthorizedNote "new note" -ScopePublic $true
    $results += &$add "refresh: existing record updated in place" ($u1.refreshed -and $u1.records.Count -eq 1 -and $u1.records[0].AuthorizedNote -eq "new note" -and $u1.records[0].ScopePublic -eq $true -and $u1.records[0].RegisteredUtc -ne "2026-01-01T00:00:00Z") "refreshed=$($u1.refreshed)"
    $u2 = Update-BountyScopeRecord -Records $recs -Name "p" -Target "new.example.com" -ScopeUrl "https://x" -AuthorizedNote "note" -ScopePublic $true
    $results += &$add "refresh: new target appended" (-not $u2.refreshed -and $u2.records.Count -eq 2) "count=$($u2.records.Count)"

    # 7. severity validation
    $results += &$add "severity: Critical valid" (Test-BountySeverityValid -Severity "Critical") ""
    $results += &$add "severity: lowercase accepted" (Test-BountySeverityValid -Severity "critical") "case-insensitive, matches v1.0"
    $results += &$add "severity: bogus rejected" (-not (Test-BountySeverityValid -Severity "PWNED")) ""

    # 8. program table sanity
    $progs = Get-BountyPrograms
    $results += &$add "programs: >=15 rows" ($progs.Count -ge 15) "count=$($progs.Count)"
    $badUrl = @($progs | Where-Object { $_.ScopeUrl -notmatch "^https://" })
    $results += &$add "programs: all https scope URLs" ($badUrl.Count -eq 0) "bad=$($badUrl.Count)"
    $pnames = @($progs | ForEach-Object { $_.Name })
    $results += &$add "programs: names unique" ((@($pnames | Sort-Object -Unique)).Count -eq $pnames.Count) "count=$($pnames.Count)"
    $filter = @(Get-BountyPrograms -Platform "Bugcrowd")
    $results += &$add "programs: platform filter works" ($filter.Count -ge 2) "bugcrowd=$($filter.Count)"

    $fail = @($results | Where-Object { -not $_.pass })
    foreach ($r in $results) {
        $tag = "PASS"
        if (-not $r.pass) { $tag = "FAIL" }
        Write-Host ("[{0}] {1} {2}" -f $tag, $r.name, $r.detail)
    }
    Write-Host ("bounty hygiene: {0}/{1} pass" -f ($results.Count - $fail.Count), $results.Count)
    return ($fail.Count -eq 0)
}

# ----------------------------------------------------------------------
# 7. SUMMARY VIEW
# ----------------------------------------------------------------------
function Get-BountySummary {
    <#
    One-screen status: registered targets, report files, registry path.
    #>
    try {
        $targets = @(Get-BountyTargets)
        Write-Host ""
        Write-Host "=== BUG BOUNTY STATUS ==="
        Write-Host "Registry: $(Get-BountyRegistryPath)"
        Write-Host "Registered targets: $($targets.Count)"
        foreach ($t in $targets) {
            Write-Host "  - $($t.Program) :: $($t.Target)"
            Write-Host "      authorizes: $($t.AuthorizedNote)"
            Write-Host "      scope page: $($t.ScopeUrl) (read: $($t.ScopePublic))"
        }
        $repDir = Join-Path (Get-BountyRoot) "bounty-reports"
        if (Test-Path $repDir) {
            $reps = @(Get-ChildItem -Path $repDir -Filter "bounty-report-*.md" -File)
            Write-Host "Reports built: $($reps.Count)"
            foreach ($r in $reps) { Write-Host "  - $($r.Name)" }
        } else {
            Write-Host "Reports built: 0"
        }
        try {
            $hist = @(Get-BountyReconHistory)
            if ($hist.Count -gt 0) {
                $last = $hist | Select-Object -Last 1
                Write-Host "Recon runs logged: $($hist.Count) (last: $($last.Program) :: $($last.Target) at $($last.Utc))"
            } else {
                Write-Host "Recon runs logged: 0"
            }
        } catch {
            Write-Host "Recon runs logged: (history unreadable: $($_.Exception.Message))"
        }
        Write-Host ""
        Write-Host "Scope Law: no scope record = no recon, no tests. Submissions on Gregg's word only."
    } catch {
        Write-Host "[!] summary failed: $($_.Exception.Message)"
    }
}

Write-Host "[bugbounty] module loaded. Scope Law in effect: no scope record = no recon, no tests."
