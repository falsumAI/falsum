<#
.SYNOPSIS
    Falsum-BreachClean.ps1 — breach exposure check + credential rotation workflow.
    Module 08 of the transparent security workstation (working title: BLACKBOX).

.DESCRIPTION
    1. HaveIBeenPwned API v3 email breach + paste checks (API key from a
       secure FILE, never hardcoded, never logged, never written to the vault).
       Shared retry/backoff helper; 429 honors Retry-After; batch checks
       throttle between requests (HIBP rate limits). -Quick uses
       truncateResponse for a fast first pass; Invoke-HibpDomainSearch runs
       the subscription domain-wide check.
    2. Local combolist scan: scans user-supplied breach/combolist files for
       the user's accounts. PASSWORDS ARE NEVER PRINTED, LOGGED, OR SAVED —
       only the account name, file, and matching line numbers are reported.
       Encoding auto-detect (BOM) or forced (UTF8/UTF16/ASCII/Latin1);
       separator auto-detect; account-field position First/Any; comment lines
       (# // ; --) skipped; -AlsoMatchBareUsernames catches dumps that store
       usernames instead of emails.
    3. Per-account rotation workflow: a guided, ordered password-rotation
       checklist (Better-Way Law: the detection ships the fix), a JSON
       rotation TRACKER so rotated vs pending accounts are provable, a
       post-rotation re-check that verifies the exposure is gone, and a
       k-anonymity password check (HIBP Pwned Passwords) so the NEW
       password is safe before you commit to it.
    4. Orchestration: Start-BreachSweep runs key load -> connectivity ->
       HIBP checks -> combolist scans -> rotation tracker -> checklist ->
       hashed report in one call.
    5. Self-test: Test-BreachCleanHygiene proves the credential-safety
       promises (predicate battery + synthetic dump drill + verdict shape +
       severity classifier + tracker normalization + key-file ACL +
       result-normalization + combolist accumulation), no network needed.
       Export-BreachReport refuses to write results that contain
       credential-like fields.
      2026-10-30: v1.4 — FIXED a real false-positive: Test-BreachSeverity
      matched table patterns as plain substrings, so "usernames" fired the
      "names" rule (+5, could climb a tier) — patterns are now matched on
      word boundaries; table gains "passport numbers" (20), "recovery
      email addresses" (15), "pins" (15). FIXED a real phantom-exposure
      bug: failed HIBP queries returned $null and @($null).Count is 1, so
      a network failure produced a blank phantom breach row, breachCount=1,
      and the account was treated as EXPOSED — new pure
      ConvertTo-BreachCheckResults normalizes null to empty lists with
      complete=$false; summary objects carry complete=; Get-BreachReportForEmail,
      Start-BreachSweep, and the launcher refuse any clean/exposed verdict
      on incomplete checks. FIXED combolistHits overwriting across dump
      files (now accumulates; +25 bonus fires once). Hygiene battery gains
      6 boundary severity cases, 4 result-normalization cases, and the
      accumulation case.

    Every step is vault-logged (type "breach-step"); passwords never enter
    the vault. PS 5.1 compatible. Zero external dependencies.

    Hardening log:
      2026-10-30: v1.1 — HIBP retry/backoff (Retry-After honored), email
      validation+normalization, batch email checks with throttle, k-anonymity
      Test-PasswordPwned (key-free), rotation tracker JSON, combolist
      Any-field matching + encoding auto-detect.
      2026-10-30: v1.2 — Start-BreachSweep orchestration (one-call end to
      end); -Quick truncateResponse fast pass threaded through the whole
      HIBP chain; Invoke-HibpDomainSearch (v3 breacheddomain); combolist
      -AlsoMatchBareUsernames + comment-line skip + forced encodings;
      Test-IsCredentialFieldName safety predicate (shared by vault log,
      pre-export audit, self-test); Export-BreachReport refuses exports
      with credential-like fields; New-PwnedVerdict extracted; new
      Test-BreachCleanHygiene self-test (no network) proving passwords
      never surface.
      2026-10-30: v1.3 — DataClass-weighted breach SEVERITY scoring
      (Test-BreachSeverity pure classifier + Get-BreachSeverityTable +
      Get-BreachExposureProfile; triage order wired into the sweep
      checklist, single-email warnings, tracker accounts, and report
      export); Set-HibpKeyFileSecure ACL hardening for the key file
      (Get-HibpKey warns on loose ACLs, -FixAcl repairs); New-RotationTracker
      normalizes account keys (Trim+Lower, dedup) — Update-RotationStatus
      normalizes lookups so case/whitespace can't desync the tracker;
      Test-PasswordPwned retries transient failures (no auth header ever
      sent to api.pwnedpasswords.com); managed-plaintext zeroing stated as
      best-effort (honest limit); hygiene battery gains severity, tracker
      normalization, and key-file ACL cases.
      2026-10-30: v1.4 — FIXED a real pacing gap: breach+paste pairs fired
      ~10ms apart inside one email check while HIBP's published guidance is
      ~1 request per 1.5s — the reactive 429 backoff absorbed this
      wastefully; new Test-HibpPaceDue (pure) + Start-HibpPace enforce a
      1600ms per-REQUEST gate in Invoke-HibpRequest so every call in the
      session is spaced. Severity table 22->28 rows: biometric data (35,
      HIGH on its own — cannot be rotated), payment histories / partial
      credit card data (20), health data / sexual orientations / religions
      (15, extortion-grade PII); "partial dates of birth" deliberately NOT
      a row — it contains "dates of birth" and would double-fire (+16 for
      partial data). FIXED tracker status pollution: Update-RotationStatus
      -Status was free text, so a typo silently poisoned the tracker while
      pending-counts exact-match "pending" — ValidateSet
      pending/rotated/skipped. Better-Way Law gap CLOSED: the rotation
      CHECKLIST says "re-check combolist files you keep locally" but
      Start-RotationVerification was HIBP-only — optional -CombolistPaths
      now verified; a local dump hit is HISTORICAL exposure (old credential
      line in the dump, not a new breach): verdict CAUTION via pure
      ConvertTo-VerificationVerdict (PASS/CAUTION/FAIL), not FAIL. Hygiene
      battery gains pacing, new-row severity, status-validation, and
      verdict cases.

    Usage examples (run in PowerShell 5.1 on Windows 11):
        . .\Falsum-BreachClean.ps1
        # Save your HIBP key (one line) to a file first:
        #   "$env:APPDATA\Falsum\hibp.key"
        Get-BreachReportForEmail -Email "you@example.com"
        Get-BreachReportForEmail -Email "you@example.com" -Quick   # fast first pass (names only)
        Get-BreachReportForEmails -Emails @("a@x.com","b@x.com") -ApiKey $key
        Invoke-HibpDomainSearch -Domain "example.com" -ApiKey $key  # subscription domain check
        Scan-CombolistFile -Path ".\breach-dump.txt" -Accounts @("you@example.com","yourhandle")
        Scan-CombolistFile -Path ".\dump.txt" -Accounts @("you@example.com") -AlsoMatchBareUsernames -EncodingName Latin1
        Test-PasswordPwned              # prompts, masked; password never leaves your machine
        Test-BreachCleanHygiene         # self-test: proves passwords never surface (no network)
        Test-BreachSeverity -BreachName "Collection1" -DataClasses "Email addresses; Passwords"
        ConvertTo-BreachCheckResults -Breaches $null -Pastes @()  # incomplete -> never a "clean" verdict
        Get-BreachExposureProfile -EmailResults $summaries -CombolistResults $scans  # worst-first triage
        Get-HibpKey -FixAcl             # tighten the key file ACL (current user + SYSTEM)
        Set-HibpKeyFileSecure -KeyFilePath "$env:APPDATA\Falsum\hibp.key"
        New-RotationChecklist -ExposedAccounts @("you@example.com")
        $t = New-RotationTracker -ExposedAccounts @("you@example.com") -BreachesByAccount @{"you@example.com"=@("Collection1")}
        Update-RotationStatus -TrackerPath $t -Account "you@example.com" -Status "rotated"
        Export-BreachReport -Results $report -OutDir "$env:USERPROFILE\Desktop\Falsum-Reports"
        Start-BreachSweep -Emails @("you@example.com") -CombolistPaths @(".\dump1.txt") -OutDir "$env:USERPROFILE\Desktop\Falsum-Reports"
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Module imports (vault + coherence, graceful when missing)
# ---------------------------------------------------------------------------
function Import-VaultModule {
    if ($script:VaultLoaded) { return }
    $here = Split-Path -Parent $MyInvocation.PSCommandPath
    $mod = Join-Path (Split-Path -Parent $here) "12-timeline-vault\Falsum-Vault.ps1"
    if (-not (Test-Path $mod)) {
        $mod = Join-Path $here "..\12-timeline-vault\Falsum-Vault.ps1"
    }
    if (Test-Path $mod) { . $mod; $script:VaultLoaded = $true }
    else { Write-Host "[!] vault module not found at $mod — steps will not be vault-logged" }
}
Import-VaultModule

$script:VaultPath = Join-Path $env:APPDATA "Falsum\vault.jsonl"
$script:HttpUA    = "Falsum-BreachClean/1.0 (Windows; PowerShell 5.1)"

# ---------------------------------------------------------------------------
# HIBP API key handling — file only, never hardcoded, never logged
# ---------------------------------------------------------------------------
function Get-HibpKey {
    <#
    Reads the HIBP API v3 key from a file. The key value is NEVER written to
    console, log, vault, or report — callers use it only as an HTTP header.
    #>
    param(
        [string]$KeyFilePath = (Join-Path $env:APPDATA "Falsum\hibp.key"),
        [switch]$FixAcl
    )
    try {
        if (-not (Test-Path $KeyFilePath)) {
            Write-Host "[!] HIBP key file not found: $KeyFilePath"
            Write-Host "    Create it with your HIBP API key (one line, no quotes):"
            Write-Host "    New-Item -ItemType Directory -Force (Split-Path '$KeyFilePath') | Out-Null"
            Write-Host "    Set-Content -Path '$KeyFilePath' -Value 'YOUR-HIBP-API-KEY' -NoNewline"
            return $null
        }
        $key = (Get-Content -Path $KeyFilePath -Raw -ErrorAction Stop).Trim()
        if ([string]::IsNullOrWhiteSpace($key) -or $key -like "*YOUR-HIBP-API-KEY*") {
            Write-Host "[!] HIBP key file is empty or still a placeholder."
            return $null
        }
        Write-Host "[+] HIBP API key loaded from file (value not shown)."
        $loose = Test-HibpKeyFileAcl -KeyFilePath $KeyFilePath
        if ($null -ne $loose -and $loose.Count -gt 0) {
            Write-Host "[!] key file ACL is loose — readable by: $($loose -join ', ')"
            if ($FixAcl) {
                if (Set-HibpKeyFileSecure -KeyFilePath $KeyFilePath) {
                    Write-Host "[+] key file ACL tightened (current user + SYSTEM only)."
                }
            } else {
                Write-Host "    Re-run Get-HibpKey -FixAcl (or Set-HibpKeyFileSecure -KeyFilePath '$KeyFilePath') to lock it down."
            }
        }
        return $key
    } catch {
        Write-Host "[!] failed to read key file: $($_.Exception.Message)"
        return $null
    }
}

function Test-HibpKeyFileAcl {
    <#
    Reports identities (other than the current user, LOCAL SYSTEM, and
    Administrators) that hold an Allow rule on the HIBP key file. Returns
    the loose identity list, or @() when tight. $null when the ACL can't
    be read. Never touches the key value.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$KeyFilePath
    )
    try {
        if (-not (Test-Path $KeyFilePath)) { return $null }
        $acl = Get-Acl -Path $KeyFilePath
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $keepSids = @(
            $me.User.Value,
            "S-1-5-18",   # LOCAL SYSTEM
            "S-1-5-32-544" # BUILTIN\Administrators
        )
        $loose = @()
        foreach ($rule in @($acl.Access)) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid = $null
            try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $null }
            if ($null -eq $sid -or $keepSids -notcontains $sid) {
                $loose += [string]$rule.IdentityReference.Value
            }
        }
        return @($loose | Select-Object -Unique)
    } catch {
        Write-Host "[!] could not read key file ACL: $($_.Exception.Message)"
        return $null
    }
}

function Set-HibpKeyFileSecure {
    <#
    Locks the HIBP key file down to the current user + LOCAL SYSTEM
    (FullControl), removes inherited rules. The key is a bearer secret —
    a loose ACL in %APPDATA% lets any local user read it. Better-Way Law:
    the secret storage ships its own hardening. Returns $true on success.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$KeyFilePath
    )
    try {
        if (-not (Test-Path $KeyFilePath)) {
            Write-Host "[!] key file not found: $KeyFilePath"
            return $false
        }
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $mySid = $me.User
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $acl = Get-Acl -Path $KeyFilePath
        $acl.SetAccessRuleProtection($true, $false)  # block inheritance, drop inherited rules
        foreach ($rule in @($acl.Access)) {
            $acl.RemoveAccessRule($rule) | Out-Null
        }
        foreach ($sid in @($mySid, $systemSid)) {
            $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($newRule) | Out-Null
        }
        Set-Acl -Path $KeyFilePath -AclObject $acl
        Write-Host "[+] key file ACL locked: $($me.Name) + LOCAL SYSTEM only."
        return $true
    } catch {
        Write-Host "[!] ACL hardening failed: $($_.Exception.Message)"
        return $false
    }
}

function Test-HibpConnection {
    <#
    Cheap auth check against the HIBP subscription endpoint. Returns $true
    when the key is accepted, $false otherwise.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$ApiKey
    )
    try {
        Write-Host "[*] testing HIBP API key..."
        $r = Invoke-RestMethod -Uri "https://haveibeenpwned.com/api/v3/subscription/status" `
            -Headers @{ "hibp-api-key" = $ApiKey; "user-agent" = $script:HttpUA } `
            -TimeoutSec 20
        Write-Host "[+] HIBP key accepted. Subscription: $($r.SubscriptionName) (status: $($r.SubscriptionStatus))"
        return $true
    } catch {
        $msg = $_.Exception.Message
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 401) {
            Write-Host "[!] HIBP rejected the key (401 Unauthorized) — check the key file."
        } else {
            Write-Host "[!] HIBP connection failed: $msg"
        }
        return $false
    }
}

# ---------------------------------------------------------------------------
# HIBP request pacing — proactive rate-limit obedience (v1.4)
#
# HIBP's published guidance is roughly one request per 1.5s per API key.
# The old code spaced only BETWEEN emails (1600ms); the breach+paste pair
# inside one email check fired ~10ms apart, routinely risking a 429 that
# the reactive backoff then absorbed wastefully. The pacing gate makes the
# per-REQUEST interval the real guarantee: every HIBP call waits until at
# least $MinIntervalMs have passed since the previous call's start.
# ---------------------------------------------------------------------------
$script:__hibpLastRequestUtc = ""

function Test-HibpPaceDue {
    <#
    Pure predicate: given the UTC instant of the last request start
    (ISO-8601 string, or empty/$null when none yet) and a minimum
    interval, reports whether a request may fire now or how long to wait.
    Returns @{ due = $true/$false; waitMs = <int> }. Fail-open: a
    malformed timestamp returns due=$true — pacing must never BLOCK the
    request on a corrupt clock reading.
    #>
    param(
        [string]$LastRequestUtc = "",
        [int]$MinIntervalMs = 1600,
        [string]$NowUtc = ""
    )
    try {
        if ([string]::IsNullOrWhiteSpace($LastRequestUtc)) {
            return @{ due = $true; waitMs = 0 }
        }
        $last = [datetime]::Parse($LastRequestUtc).ToUniversalTime()
        $now  = if ([string]::IsNullOrWhiteSpace($NowUtc)) {
            (Get-Date).ToUniversalTime()
        } else {
            [datetime]::Parse($NowUtc).ToUniversalTime()
        }
        $elapsed = [int](($now - $last).TotalMilliseconds)
        if ($elapsed -ge $MinIntervalMs) { return @{ due = $true; waitMs = 0 } }
        return @{ due = $false; waitMs = ($MinIntervalMs - $elapsed) }
    } catch {
        return @{ due = $true; waitMs = 0 }
    }
}

function Start-HibpPace {
    <#
    Enforces the pacing gate BEFORE an HIBP call and records the request
    start instant AFTER waiting (Stamp-Request). Script-scoped timestamp,
    so EVERY HIBP request in the session is spaced, not just requests
    inside one caller.
    #>
    param([int]$MinIntervalMs = 1600)
    $gate = Test-HibpPaceDue -LastRequestUtc $script:__hibpLastRequestUtc -MinIntervalMs $MinIntervalMs
    if ((-not $gate.due) -and ([int]$gate.waitMs -gt 0)) {
        Start-Sleep -Milliseconds ([int]$gate.waitMs)
    }
    $script:__hibpLastRequestUtc = (Get-Date).ToUniversalTime().ToString("o")
}

# ---------------------------------------------------------------------------
# HIBP request helper — shared retry/backoff, honors Retry-After on 429
# ---------------------------------------------------------------------------
function Invoke-HibpRequest {
    <#
    One HTTP GET with HIBP auth headers. Retries transient failures
    (429, 503, timeouts, socket errors) with exponential backoff; honors
    the Retry-After response header when present. Returns a result
    hashtable: @{ ok=$true; body=$r } or @{ ok=$false; notFound=$true }
    for 404, or @{ ok=$false; error=$msg } after all retries.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$true)][string]$ApiKey,
        [int]$MaxRetries = 3,
        [int]$RetryBaseSec = 2,
        [int]$PaceMs = 1600
    )
    # Proactive pacing: every request waits until the minimum interval
    # has passed since the previous request start (v1.4 — the breach+paste
    # pair inside one email check used to fire ~10ms apart and risk 429s).
    # Retries inside the loop keep the reactive backoff on top of this.
    Start-HibpPace -MinIntervalMs $PaceMs
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $r = Invoke-RestMethod -Uri $Uri `
                -Headers @{ "hibp-api-key" = $ApiKey; "user-agent" = $script:HttpUA } `
                -TimeoutSec 30
            return @{ ok = $true; body = $r }
        } catch {
            $code = $null
            $retryAfter = $null
            if ($_.Exception.Response) {
                $code = [int]$_.Exception.Response.StatusCode
                try { $retryAfter = $_.Exception.Response.Headers.GetValues("Retry-After") | Select-Object -First 1 } catch { $retryAfter = $null }
            }
            if ($code -eq 404) {
                return @{ ok = $false; notFound = $true }
            }
            $transient = ($code -eq 429) -or ($code -eq 503) -or `
                         ($_.Exception -is [System.Net.WebException]) -or `
                         (($null -ne $_.Exception.InnerException) -and ($_.Exception.InnerException -is [System.Net.Sockets.SocketException]))
            if ((-not $transient) -or ($attempt -gt $MaxRetries)) {
                Write-Host "[!] HIBP request failed after $attempt attempt(s): $($_.Exception.Message)"
                return @{ ok = $false; error = $_.Exception.Message }
            }
            $wait = $RetryBaseSec * [math]::Pow(2, ($attempt - 1))
            $ra = 0
            if ($null -ne $retryAfter -and [int]::TryParse($retryAfter, [ref]$ra) -and $ra -gt 0) { $wait = $ra }
            Write-Host "[*] HIBP $code — backing off ${wait}s (attempt $attempt/$MaxRetries)..."
            Start-Sleep -Seconds $wait
        }
    }
}

# ---------------------------------------------------------------------------
# HIBP v3 breach + paste checks
# ---------------------------------------------------------------------------
function Invoke-HibpBreachCheck {
    <#
    Returns breach objects for an email (or @() when clean). 404 = clean.
    -IncludeUnverified also returns breaches still being verified.
    -Quick uses truncateResponse=true: returns bare breach NAMES only
    (fast first pass over many accounts); re-run without -Quick for detail.
    Never logs the API key.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Email,
        [Parameter(Mandatory=$true)][string]$ApiKey,
        [switch]$IncludeUnverified,
        [switch]$Quick,
        [int]$MaxRetries = 3
    )
    Write-Host "[*] HIBP breach check: $Email$(if ($Quick) { ' (quick mode)' })"
    $enc = [System.Uri]::EscapeDataString($Email)
    $truncate = if ($Quick) { "true" } else { "false" }
    $uri = "https://haveibeenpwned.com/api/v3/breachedaccount/$enc`?truncateResponse=$truncate"
    if ($IncludeUnverified) { $uri += "&includeUnverified=true" }
    $res = Invoke-HibpRequest -Uri $uri -ApiKey $ApiKey -MaxRetries $MaxRetries
    if ($res.notFound) {
        Write-Host "[+] $Email : no breaches on record"
        return @()
    }
    if (-not $res.ok) { return $null }
    $list = @($res.body)
    Write-Host "[!] $($list.Count) breach(es) found for $Email"
    return $list
}

function Invoke-HibpPasteCheck {
    <#
    Returns paste objects for an email (or @() when none). 404 = none.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Email,
        [Parameter(Mandatory=$true)][string]$ApiKey,
        [int]$MaxRetries = 3
    )
    Write-Host "[*] HIBP paste check: $Email"
    $enc = [System.Uri]::EscapeDataString($Email)
    $res = Invoke-HibpRequest `
        -Uri "https://haveibeenpwned.com/api/v3/pasteaccount/$enc" `
        -ApiKey $ApiKey -MaxRetries $MaxRetries
    if ($res.notFound) {
        Write-Host "[+] $Email : no pastes on record"
        return @()
    }
    if (-not $res.ok) { return $null }
    $list = @($res.body)
    Write-Host "[!] $($list.Count) paste(s) found for $Email"
    return $list
}

function Invoke-HibpDomainSearch {
    <#
    HIBP v3 domain search: returns the breached account addresses seen on a
    domain. Subscription endpoint — the key's domain must be authorized in
    the HIBP subscription. Account addresses are RETURNED (the user asked
    for their own domain) but the vault log records only the domain and
    counts, never the address list.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Domain,
        [Parameter(Mandatory=$true)][string]$ApiKey,
        [int]$MaxRetries = 3
    )
    $Domain = $Domain.Trim().ToLower()
    Write-Host "[*] HIBP domain search: $Domain"
    $enc = [System.Uri]::EscapeDataString($Domain)
    $res = Invoke-HibpRequest -Uri "https://haveibeenpwned.com/api/v3/breacheddomain/$enc" `
        -ApiKey $ApiKey -MaxRetries $MaxRetries
    if ($res.notFound) {
        Write-Host "[+] $Domain : no domain breaches on record"
        return @()
    }
    if (-not $res.ok) { return $null }
    $list = @($res.body)
    Write-Host "[!] $($list.Count) breached account address(es) seen on $Domain (addresses not vault-logged)"
    New-BreachLog -Step "hibp-domain-search" -Data @{
        domain       = $Domain
        accountCount = $list.Count
    }
    return $list
}

function Test-EmailFormat {
    <#
    Conservative email validation — refuse obviously malformed addresses
    BEFORE they hit the network. Returns $true/$false.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Email
    )
    $rx = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    if ($Email -match $rx) { return $true }
    return $false
}

# ---------------------------------------------------------------------------
# Result normalization — a failed check is NOT a clean bill of health
#
# Invoke-HibpBreachCheck / Invoke-HibpPasteCheck return $null when the
# request FAILED (network down, key rejected, HIBP erroring). Before this
# fix, $null flowed into @($breaches).Count — and @($null).Count is 1 —
# so a failed check produced a phantom breach row with blank fields,
# breachCount=1, and the workflow treated the account as EXPOSED.
# This pure normalizer turns failed queries into empty lists with
# complete=$false; callers must honor it and refuse any clean verdict
# until the check is re-run. Offline-testable via Test-BreachCleanHygiene.
# ---------------------------------------------------------------------------
function ConvertTo-BreachCheckResults {
    param(
        $Breaches,
        $Pastes
    )
    $breachFailed = $null -eq $Breaches
    $pasteFailed  = $null -eq $Pastes
    return [pscustomobject]@{
        breaches     = @(@($Breaches) | Where-Object { $null -ne $_ })
        pastes       = @(@($Pastes)   | Where-Object { $null -ne $_ })
        complete     = (-not ($breachFailed -or $pasteFailed))
        breachFailed = $breachFailed
        pasteFailed  = $pasteFailed
    }
}

function Get-BreachSummaryForEmail {
    <#
    Runs breach + paste checks for one email and returns a unified result
    object. Email is trimmed/lowercased and validated before querying.
    Vault-logs the query (email, counts, UTC) — never the key.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Email,
        [Parameter(Mandatory=$true)][string]$ApiKey,
        [switch]$IncludeUnverified,
        [switch]$Quick
    )
    $Email = $Email.Trim().ToLower()
    if (-not (Test-EmailFormat -Email $Email)) {
        Write-Host "[!] refusing to query HIBP: '$Email' is not a valid email address."
        return $null
    }
    $breaches = Invoke-HibpBreachCheck -Email $Email -ApiKey $ApiKey -IncludeUnverified:$IncludeUnverified -Quick:$Quick
    $pastes   = Invoke-HibpPasteCheck -Email $Email -ApiKey $ApiKey
    $norm = ConvertTo-BreachCheckResults -Breaches $breaches -Pastes $pastes
    $breaches = $norm.breaches
    $pastes   = $norm.pastes
    if (-not $norm.complete) {
        Write-Host "[!] check INCOMPLETE for $Email — breach query failed: $($norm.breachFailed); paste query failed: $($norm.pasteFailed)."
        Write-Host "    This is NOT a clean verdict. Re-run when HIBP is reachable; nothing below claims the account is safe."
    }
    $summary = [pscustomobject]@{
        email        = $Email
        checkedUtc   = (Get-Date).ToUniversalTime().ToString("o")
        complete     = $norm.complete
        breachCount  = @($breaches).Count
        pasteCount   = @($pastes).Count
        breaches     = @($breaches) | ForEach-Object {
            if ($_ -is [string]) {
                # -Quick mode: truncateResponse returns bare breach names
                [pscustomobject]@{
                    Name        = $_
                    Title       = $_
                    Domain      = ""
                    BreachDate  = ""
                    PwnCount    = 0
                    DataClasses = "(quick mode — re-run without -Quick for full detail)"
                }
            } else {
                [pscustomobject]@{
                    Name        = $_.Name
                    Title       = $_.Title
                    Domain      = $_.Domain
                    BreachDate  = $_.BreachDate
                    PwnCount    = $_.PwnCount
                    DataClasses = @($_.DataClasses) -join "; "
                }
            }
        }
        pastes       = @($pastes) | ForEach-Object {
            [pscustomobject]@{
                Source     = $_.Source
                Id         = $_.Id
                Title      = $_.Title
                Date       = $_.Date
                EmailCount = $_.EmailCount
            }
        }
    }
    New-BreachLog -Step "hibp-check" -Data @{
        email       = $Email
        breachCount = $summary.breachCount
        pasteCount  = $summary.pasteCount
    }
    return $summary
}

function Get-BreachReportForEmails {
    <#
    Batch wrapper: runs the full breach+paste check for many emails with a
    throttle pause between requests so HIBP rate limits (typically ~1 req
    per 1.5s) are not tripped. Skips invalid emails without stopping.
    Returns an array of summary objects (one per successfully checked email).
    #>
    param(
        [Parameter(Mandatory=$true)][string[]]$Emails,
        [Parameter(Mandatory=$true)][string]$ApiKey,
        [int]$ThrottleMs = 1600,
        [switch]$IncludeUnverified,
        [switch]$Quick
    )
    $out = @()
    $n = 0
    foreach ($e in $Emails) {
        $n++
        if ($n -gt 1) { Start-Sleep -Milliseconds $ThrottleMs }
        Write-Host "[*] batch check $n of $($Emails.Count)"
        $s = Get-BreachSummaryForEmail -Email $e -ApiKey $ApiKey -IncludeUnverified:$IncludeUnverified -Quick:$Quick
        if ($null -ne $s) { $out += $s } else { Write-Host "[!] skipped '$e' (invalid address or check failed)" }
    }
    Write-Host "[+] batch complete: $($out.Count)/$($Emails.Count) checked."
    return $out
}

# ---------------------------------------------------------------------------
# Breach severity scoring — triage, not just listing (Better-Way Law)
#
# A breach list without triage is a to-do list without an order. Scoring
# reads the breach DataClasses (what kind of data left the building) and
# ranks accounts so rotation starts where the damage is worst.
# ---------------------------------------------------------------------------
function Get-BreachSeverityTable {
    <#
    Shipped DataClass weight table. Patterns are lowercase WORDS/phrases
    matched on WORD BOUNDARIES (\b) against the lowercased DataClasses
    text — a plain substring test false-fired: "usernames" contains
    "names", so a usernames-only breach scored +5 for "names" and could
    climb a whole severity tier. Boundary matching fires "names" only for
    real full-name exposure. Deliberate non-row: "partial dates of birth"
    is NOT listed — it CONTAINS "dates of birth", so a naive row would
    double-fire (+16 for partial data). Tiers:
      >=60 CRITICAL, >=35 HIGH, >=15 MEDIUM, >0 LOW, 0 UNKNOWN.
    #>
    return @(
        @{ Pattern = "passwords";                Weight = 60; Reason = "password exposure (hash or plaintext) — critical on its own" },
        @{ Pattern = "password hints";           Weight = 30; Reason = "password recovery shortcut" },
        @{ Pattern = "security questions";       Weight = 30; Reason = "account-recovery bypass material" },
        @{ Pattern = "api keys";                 Weight = 25; Reason = "service credential" },
        @{ Pattern = "auth tokens";              Weight = 25; Reason = "session credential" },
        @{ Pattern = "biometric data";           Weight = 35; Reason = "immutable identifier — cannot be rotated (HIGH on its own)" },
        @{ Pattern = "social security numbers";  Weight = 20; Reason = "identity-theft material" },
        @{ Pattern = "government issued ids";    Weight = 20; Reason = "identity-theft material" },
        @{ Pattern = "passport numbers";         Weight = 20; Reason = "identity-theft material (travel document)" },
        @{ Pattern = "credit cards";             Weight = 20; Reason = "financial fraud material" },
        @{ Pattern = "partial credit card data"; Weight = 20; Reason = "financial fraud material (partial)" },
        @{ Pattern = "payment histories";        Weight = 20; Reason = "financial fraud material" },
        @{ Pattern = "bank account";             Weight = 20; Reason = "financial fraud material" },
        @{ Pattern = "recovery email addresses"; Weight = 15; Reason = "account-takeover material (reset path)" },
        @{ Pattern = "pins";                     Weight = 15; Reason = "credential (PIN)" },
        @{ Pattern = "health data";              Weight = 15; Reason = "sensitive PII — extortion target" },
        @{ Pattern = "sexual orientations";      Weight = 15; Reason = "sensitive PII — extortion target" },
        @{ Pattern = "religions";                Weight = 15; Reason = "sensitive PII — discrimination target" },
        @{ Pattern = "email addresses";          Weight = 10; Reason = "account identifier + phishing target" },
        @{ Pattern = "usernames";                Weight = 10; Reason = "account identifier" },
        @{ Pattern = "dates of birth";           Weight = 8;  Reason = "identity-theft corroboration" },
        @{ Pattern = "phone numbers";            Weight = 8;  Reason = "SIM-swap / vishing target" },
        @{ Pattern = "physical addresses";       Weight = 8;  Reason = "doxxing / mail fraud" },
        @{ Pattern = "geographic locations";     Weight = 5;  Reason = "movement profiling" },
        @{ Pattern = "names";                    Weight = 5;  Reason = "identity corroboration" },
        @{ Pattern = "employment";               Weight = 3;  Reason = "social-engineering context" },
        @{ Pattern = "occupations";              Weight = 3;  Reason = "social-engineering context" },
        @{ Pattern = "ip addresses";             Weight = 3;  Reason = "targeting / correlation" }
    )
}

function Test-BreachSeverity {
    <#
    Pure classifier: scores ONE breach from its DataClasses text.
    Returns: @{ name; score; level; firedRules } — CRITICAL/HIGH/MEDIUM/
    LOW, or UNKNOWN when no DataClass information exists (e.g. -Quick
    mode). Case-insensitive; safe on $null/empty input.
    #>
    param(
        [string]$BreachName = "",
        [string]$DataClasses = ""
    )
    $fired = @()
    $score = 0
    if ([string]::IsNullOrWhiteSpace($DataClasses) -or $DataClasses -match "quick mode") {
        return [pscustomobject]@{
            name       = $BreachName
            score      = 0
            level      = "UNKNOWN"
            firedRules = @()
            note       = "no DataClass detail — re-run without -Quick for a real score"
        }
    }
    $hay = $DataClasses.ToLower()
    foreach ($row in (Get-BreachSeverityTable)) {
        # Word-boundary match: "usernames" must not fire the "names" rule.
        $rx = "\b" + [regex]::Escape($row.Pattern) + "\b"
        if ($hay -match $rx) {
            $score += $row.Weight
            $fired += "$($row.Pattern) (+$($row.Weight): $($row.Reason))"
        }
    }
    $level = "LOW"
    if ($score -ge 60) { $level = "CRITICAL" }
    elseif ($score -ge 35) { $level = "HIGH" }
    elseif ($score -ge 15) { $level = "MEDIUM" }
    return [pscustomobject]@{
        name       = $BreachName
        score      = $score
        level      = $level
        firedRules = $fired
        note       = ""
    }
}

function Get-BreachExposureProfile {
    <#
    Builds the per-account exposure profile across HIBP email summaries
    and combolist scan results, ranked worst-first. Each profile:
    account, score (sum of breach scores), level (worst breach level),
    breachCount, pasteCount, combolistHits, topRules. A local combolist
    hit adds +25 (a credential line in a dump on your disk is exposure).
    Vault-logs the profile (accounts + levels only — no breach payload).
    #>
    param(
        [Parameter(Mandatory=$true)]$EmailResults,
        $CombolistResults = @()
    )
    $rank = @{ "CRITICAL" = 4; "HIGH" = 3; "MEDIUM" = 2; "LOW" = 1; "UNKNOWN" = 0 }
    $byAccount = @{}
    foreach ($s in @($EmailResults)) {
        if ($null -eq $s -or -not ($s.PSObject.Properties.Name -contains "email")) { continue }
        $acct = [string]$s.email
        $score = 0; $worst = "UNKNOWN"; $rules = @(); $names = @()
        foreach ($b in @($s.breaches)) {
            $sev = Test-BreachSeverity -BreachName ([string]$b.Name) -DataClasses ([string]$b.DataClasses)
            $names += [string]$b.Name
            $score += $sev.score
            if ($rank[$sev.level] -gt $rank[$worst]) { $worst = $sev.level }
            $rules += @($sev.firedRules | ForEach-Object { "$([string]$b.Name): $_" })
        }
        $byAccount[$acct] = [ordered]@{
            account       = $acct
            score         = $score
            level         = $worst
            breachCount   = [int]$s.breachCount
            pasteCount    = [int]$s.pasteCount
            breaches      = $names
            combolistHits = 0
            topRules      = @($rules | Select-Object -First 6)
        }
    }
    foreach ($c in @($CombolistResults)) {
        if ($null -eq $c -or -not ($c.PSObject.Properties.Name -contains "account")) { continue }
        $acct = [string]$c.account
        if (-not $byAccount.ContainsKey($acct)) {
            $byAccount[$acct] = [ordered]@{
                account = $acct; score = 0; level = "UNKNOWN"; breachCount = 0
                pasteCount = 0; breaches = @(); combolistHits = 0; topRules = @()
            }
        }
        $hits = [int]$c.hitCount
        # Accumulate across dump files — the old code overwrote, so an
        # account in two dumps kept only the second file's count.
        $wasHit = ([int]$byAccount[$acct].combolistHits) -gt 0
        $byAccount[$acct].combolistHits += $hits
        if ($hits -gt 0 -and -not $wasHit) {
            $byAccount[$acct].score += 25
            $byAccount[$acct].topRules = @("local combolist hit (+25: credential line in a dump on your disk)") + @($byAccount[$acct].topRules)
            if ($rank["MEDIUM"] -gt $rank[$byAccount[$acct].level]) { $byAccount[$acct].level = "MEDIUM" }
        }
    }
    $profiles = @($byAccount.Values | ForEach-Object {
        [pscustomobject]$_
    } | Sort-Object -Property @{ Expression = { $rank[$_.level] }; Descending = $true }, @{ Expression = { [int]$_.score }; Descending = $true })
    New-BreachLog -Step "exposure-profile" -Data @{
        accounts = (($profiles | ForEach-Object { "$($_.account)=$($_.level)" }) -join "; ")
    }
    return $profiles
}

# ---------------------------------------------------------------------------
# Local combolist scan — user-supplied breach files, passwords never surfaced
# ---------------------------------------------------------------------------
function Scan-CombolistFile {
    <#
    Scans a user-supplied combolist/breach dump for the user's accounts.
    Handles separators: colon, pipe, semicolon, tab, comma, space.
    REPORTS ONLY account name + file + line numbers. The password value is
    NEVER printed, returned, logged, or written anywhere. Returns one
    per-account match object (aliases collapsed to the canonical account).
    Encoding: BOM auto-detect (UTF-8/UTF-16) by default, or forced via
    -EncodingName. -AccountField Any matches the account in ANY
    separator-delimited field (for dumps that aren't account-first; note a
    password that equals an account string could false-positive in Any
    mode — First is the safer default). -SkipCommentLines (default on)
    skips # // ; -- comment lines common in shared dumps.
    -AlsoMatchBareUsernames additionally matches the local part of each
    email account (many dumps store usernames, not emails).
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string[]]$Accounts,
        [int]$MaxLines = 2000000,
        [ValidateSet("First","Any")]
        [string]$AccountField = "First",
        [int]$ProgressEvery = 250000,
        [switch]$AlsoMatchBareUsernames,
        [bool]$SkipCommentLines = $true,
        [ValidateSet("Auto","UTF8","UTF16","ASCII","Latin1")]
        [string]$EncodingName = "Auto"
    )
    try {
        if (-not (Test-Path $Path)) {
            Write-Host "[!] combolist file not found: $Path"
            return $null
        }
        $fi = Get-Item $Path
        Write-Host "[*] scanning combolist: $($fi.Name) ($([math]::Round($fi.Length/1MB,1)) MB)"
        Write-Host "[*] account field: $AccountField; separator auto-detect; passwords are NEVER surfaced."

        $sha = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        Write-Host "[+] SHA-256 of scanned file: $sha"

        # Normalize accounts once for case-insensitive exact matching.
        # $wanted maps every lookup key (canonical account + optional bare
        # username alias) to the canonical account, so aliases collapse in
        # the report instead of producing duplicate rows.
        $wanted = @{}
        $canonOrder = @()
        foreach ($a in $Accounts) {
            $norm = $a.Trim().ToLower()
            if ($canonOrder -notcontains $norm) { $canonOrder += $norm }
            $wanted[$norm] = $norm
            if ($AlsoMatchBareUsernames -and $norm.Contains("@")) {
                $bare = ($norm -split "@")[0]
                if (-not [string]::IsNullOrWhiteSpace($bare) -and -not $wanted.ContainsKey($bare)) {
                    $wanted[$bare] = $norm
                }
            }
        }
        if ($AlsoMatchBareUsernames) {
            Write-Host "[*] bare-username aliases enabled: $($wanted.Count) lookup key(s) for $($canonOrder.Count) account(s)"
        }

        $matches = @{}   # lookup key -> array of line numbers
        $lineNo  = 0
        $sepRx   = [regex]":|\||;|\t|,| "
        $commentRx = [regex]"^(#|//|;|--|REM\s)"

        # Reader: BOM auto-detect by default; forced encoding honors a BOM
        # when one is present, else uses the requested code page.
        $reader = $null
        if ($EncodingName -eq "Auto") {
            $reader = New-Object System.IO.StreamReader($Path, $true)
        } else {
            $enc = [System.Text.Encoding]::UTF8
            switch ($EncodingName) {
                "UTF16"  { $enc = [System.Text.Encoding]::Unicode }
                "ASCII"  { $enc = [System.Text.Encoding]::ASCII }
                "Latin1" { $enc = [System.Text.Encoding]::GetEncoding(28591) }
            }
            $reader = New-Object System.IO.StreamReader($Path, $enc, $true)
        }
        try {
            while (($line = $reader.ReadLine()) -ne $null -and $lineNo -lt $MaxLines) {
                $lineNo++
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $t = $line.Trim()
                if ($SkipCommentLines -and $commentRx.IsMatch($t)) { continue }
                $parts = $sepRx.Split($t)
                if ($parts.Count -lt 2) { continue }
                $fields = @()
                if ($AccountField -eq "Any") {
                    $fields = @($parts | ForEach-Object { $_.Trim().ToLower() })
                } else {
                    $fields = @($parts[0].Trim().ToLower())
                }
                foreach ($candidate in $fields) {
                    if ($wanted.ContainsKey($candidate)) {
                        if (-not $matches.ContainsKey($candidate)) { $matches[$candidate] = @() }
                        $matches[$candidate] += $lineNo
                        break  # one record per line, whichever field matched
                    }
                }
                if ($lineNo % $ProgressEvery -eq 0) {
                    Write-Host "[*] ... $lineNo lines scanned, matches so far: $($matches.Count) account(s)"
                }
            }
        } finally {
            $reader.Close()
        }

        $result = @()
        foreach ($acct in $canonOrder) {
            # Aggregate line numbers across every lookup key that maps to
            # this canonical account (email + bare-username alias).
            $hitLines = @()
            foreach ($k in $wanted.Keys) {
                if ($wanted[$k] -eq $acct -and $matches.ContainsKey($k)) {
                    $hitLines += $matches[$k]
                }
            }
            $hitLines = @($hitLines | Sort-Object -Unique)
            $r = [pscustomobject]@{
                account    = $acct
                file       = $fi.FullName
                fileSha256 = $sha
                hitLines   = $hitLines
                hitCount   = $hitLines.Count
                linesRead  = $lineNo
            }
            $result += $r
            if ($hitLines.Count -gt 0) {
                $preview = ($hitLines | Select-Object -First 10) -join ", "
                Write-Host "[!] EXPOSED: $acct — $($hitLines.Count) credential line(s) in $($fi.Name) (lines: $preview$(if($hitLines.Count -gt 10){', ...'}))"
            } else {
                Write-Host "[+] clean: $acct not found in $($fi.Name) ($lineNo lines read)"
            }
        }

        New-BreachLog -Step "combolist-scan" -Data @{
            file      = $fi.FullName
            fileSha256 = $sha
            linesRead = $lineNo
            accounts  = ($canonOrder -join "; ")
            exposed   = (($result | Where-Object { $_.hitCount -gt 0 } | ForEach-Object { $_.account }) -join "; ")
        }
        return $result
    } catch {
        Write-Host "[!] combolist scan failed: $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Pwned-password check (k-anonymity) — Better-Way Law: check the NEW
# password BEFORE you commit to it
# ---------------------------------------------------------------------------
function New-PwnedVerdict {
    <#
    Builds the pwned-password verdict object for a count. The password
    itself NEVER reaches this function — only the integer count — so the
    output shape provably cannot carry the plaintext. Extracted so
    Test-BreachCleanHygiene can verify the shape without network access.
    #>
    param(
        [Parameter(Mandatory=$true)][int]$Count
    )
    if ($Count -gt 0) {
        $advice = "PWNED $Count time(s) — do not use this password. Generate a unique one in your password manager."
    } else {
        $advice = "Not found in the HIBP pwned-passwords corpus. Still: unique per account, in a password manager."
    }
    return [pscustomobject]@{
        checkedUtc = (Get-Date).ToUniversalTime().ToString("o")
        pwnCount   = $Count
        isPwned    = ($Count -gt 0)
        advice     = $advice
    }
}

function Test-PasswordPwned {
    <#
    K-anonymity check against the HIBP Pwned Passwords API. NO API KEY
    needed (and none is ever sent to api.pwnedpasswords.com — a separate
    host from the keyed HIBP API, so auth headers stay off it). The full
    password AND its full SHA-1 NEVER leave this machine: the SHA-1 is
    computed locally and only the first 5 hex characters are sent over
    HTTPS (with Add-Padding so response sizes reveal nothing); the suffix
    match is done locally. The password is accepted as a SecureString
    (or prompted masked); the unmanaged BSTR copy is zeroed after use.
    HONEST LIMIT: the managed-string copy made by PtrToStringBSTR cannot
    be reliably zeroed from managed code — setting it $null + GC is
    best-effort only. Nothing credential-like is ever vault-logged or
    returned — only the pwn count and the verdict.
    #>
    param(
        [System.Security.SecureString]$SecurePassword,
        [int]$MaxRetries = 2
    )
    try {
        if ($null -eq $SecurePassword) {
            $SecurePassword = Read-Host -AsSecureString -Prompt "Enter the password to check (never shown, never sent)"
        }
        if ($null -eq $SecurePassword -or $SecurePassword.Length -eq 0) {
            Write-Host "[!] no password entered."
            return $null
        }
        # SecureString -> transient plaintext (local only). The BSTR is
        # zeroed in the finally block; the managed copy is best-effort
        # (see honest-limit note above).
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $hex = $null
        try {
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
            $sha1 = [System.Security.Cryptography.SHA1]::Create()
            $hashBytes = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plain))
            $sha1.Clear()
            $plain = $null
            $hex = (($hashBytes | ForEach-Object { $_.ToString("x2") }) -join "").ToUpper()
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
            [System.GC]::Collect()
        }
        $prefix = $hex.Substring(0, 5)
        $suffix = $hex.Substring(5)
        Write-Host "[*] querying Pwned Passwords range $prefix (k-anonymity: full hash never leaves this machine)..."
        $resp = $null
        $attempt = 0
        while ($true) {
            $attempt++
            try {
                # NOTE: deliberately no hibp-api-key header here — the
                # pwnedpasswords endpoint is key-free by design and lives on
                # a different host. Never send the key where it isn't wanted.
                $resp = Invoke-RestMethod -Uri "https://api.pwnedpasswords.com/range/$prefix" `
                    -Headers @{ "user-agent" = $script:HttpUA; "Add-Padding" = "true" } `
                    -TimeoutSec 30
                break
            } catch {
                $transient = ($_.Exception -is [System.Net.WebException]) -or `
                    (($null -ne $_.Exception.InnerException) -and ($_.Exception.InnerException -is [System.Net.Sockets.SocketException]))
                if ((-not $transient) -or ($attempt -ge $MaxRetries)) {
                    Write-Host "[!] password range query failed after $attempt attempt(s): $($_.Exception.Message)"
                    return $null
                }
                Write-Host "[*] transient error — retrying ($attempt/$MaxRetries)..."
                Start-Sleep -Seconds (2 * $attempt)
            }
        }
        $count = 0
        foreach ($line in ($resp -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $parts = $line.Split(":")
            if ($parts.Count -ne 2) { continue }
            if ($parts[0].Trim() -eq $suffix) { $count = [int]$parts[1].Trim(); break }
        }
        $verdict = New-PwnedVerdict -Count $count
        Write-Host $verdict.advice
        New-BreachLog -Step "password-check" -Data @{ pwnCount = $count; isPwned = $verdict.isPwned }
        return $verdict
    } catch {
        Write-Host "[!] password check failed: $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Rotation tracker — the checklist's memory: pending vs rotated is provable
# ---------------------------------------------------------------------------
function New-RotationTracker {
    <#
    Writes a rotation tracker JSON file: one entry per exposed account,
    status "pending". Update-RotationStatus flips accounts to "rotated"
    with a timestamp. The tracker is the checklist's memory — rotated
    accounts are provable, nothing falls through the cracks. Account keys
    are normalized (Trim + Lowercase, deduped) so "Alice@X.com" and
    "alice@x.com" can never desync the tracker; -SeverityByAccount stamps
    each account with its exposure level from Get-BreachExposureProfile.
    #>
    param(
        [Parameter(Mandatory=$true)][string[]]$ExposedAccounts,
        [hashtable]$BreachesByAccount = @{},
        [hashtable]$SeverityByAccount = @{},
        [string]$OutDir
    )
    try {
        if ([string]::IsNullOrWhiteSpace($OutDir)) {
            $OutDir = Join-Path $env:APPDATA "Falsum\trackers"
        }
        $dir = New-Item -ItemType Directory -Path $OutDir -Force
        $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
        $path = Join-Path $dir.FullName "rotation-tracker-$stamp.json"
        $accounts = @{}
        $seen = @{}
        foreach ($raw in $ExposedAccounts) {
            $a = ([string]$raw).Trim().ToLower()
            if ([string]::IsNullOrWhiteSpace($a) -or $seen.ContainsKey($a)) { continue }
            $seen[$a] = $true
            $b = @()
            # breach names may be keyed by the un-normalized or the
            # normalized account — try both.
            if ($BreachesByAccount.ContainsKey($a)) { $b = @($BreachesByAccount[$a]) }
            elseif ($BreachesByAccount.ContainsKey($raw)) { $b = @($BreachesByAccount[$raw]) }
            $sev = ""
            if ($SeverityByAccount.ContainsKey($a)) { $sev = [string]$SeverityByAccount[$a] }
            elseif ($SeverityByAccount.ContainsKey($raw)) { $sev = [string]$SeverityByAccount[$raw] }
            $accounts[$a] = @{
                breaches   = $b
                severity   = $sev
                status     = "pending"
                startedUtc = (Get-Date).ToUniversalTime().ToString("o")
                rotatedUtc = $null
            }
        }
        $tracker = [ordered]@{
            generatedUtc = (Get-Date).ToUniversalTime().ToString("o")
            accounts     = $accounts
        }
        ($tracker | ConvertTo-Json -Depth 6) | Set-Content -Path $path -Encoding UTF8
        $h = (Get-FileHash -Path $path -Algorithm SHA256).Hash
        "$h  $([System.IO.Path]::GetFileName($path))" | Set-Content -Path ($path + ".sha256")
        Write-Host "[+] rotation tracker written: $path  (SHA-256 $h)"
        New-BreachLog -Step "rotation-tracker" -Data @{ path = $path; accounts = ($ExposedAccounts -join "; ") }
        return $path
    } catch {
        Write-Host "[!] tracker creation failed: $($_.Exception.Message)"
        return $null
    }
}

function Update-RotationStatus {
    <#
    Marks an account's status (default "rotated") in a tracker file and
    reports how many accounts are still pending. Re-hashes the tracker
    file so the record stays verifiable. The -Account lookup is
    normalized (Trim + Lowercase) to match New-RotationTracker's keys,
    so case/whitespace can't desync the tracker. -Status is a closed
    vocabulary (ValidateSet): a free-text status used to let a typo
    silently poison the tracker while the pending-count query exact-matches
    "pending" — a misspelled status was neither pending nor rotated, and
    the account fell off every view. (v1.4)
    #>
    param(
        [Parameter(Mandatory=$true)][string]$TrackerPath,
        [Parameter(Mandatory=$true)][string]$Account,
        [ValidateSet("pending","rotated","skipped")]
        [string]$Status = "rotated"
    )
    try {
        if (-not (Test-Path $TrackerPath)) {
            Write-Host "[!] tracker not found: $TrackerPath"
            return $null
        }
        $Account = ([string]$Account).Trim().ToLower()
        $tracker = Get-Content -Path $TrackerPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not ($tracker.accounts.PSObject.Properties.Name -contains $Account)) {
            Write-Host "[!] account '$Account' not in tracker."
            return $null
        }
        $tracker.accounts.$Account.status = $Status
        $tracker.accounts.$Account.rotatedUtc = (Get-Date).ToUniversalTime().ToString("o")
        ($tracker | ConvertTo-Json -Depth 6) | Set-Content -Path $TrackerPath -Encoding UTF8
        $h = (Get-FileHash -Path $TrackerPath -Algorithm SHA256).Hash
        "$h  $([System.IO.Path]::GetFileName($TrackerPath))" | Set-Content -Path ($TrackerPath + ".sha256")
        $pending = @($tracker.accounts.PSObject.Properties | Where-Object { $_.Value.status -eq "pending" }).Count
        Write-Host "[+] $Account marked '$Status' in tracker. $pending account(s) still pending."
        New-BreachLog -Step "rotation-status" -Data @{ account = $Account; status = $Status; pending = $pending }
        return $tracker
    } catch {
        Write-Host "[!] tracker update failed: $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Rotation workflow — Better-Way Law: the detection ships the fix
# ---------------------------------------------------------------------------
function New-RotationChecklist {
    <#
    Builds the guided per-account rotation checklist. Ordered: contain the
    exposure first, then rotate, then verify. Prints it and returns it.
    #>
    param(
        [Parameter(Mandatory=$true)][string[]]$ExposedAccounts,
        [string[]]$PriorityBreaches = @()
    )
    $steps = @(
        "1. CONTAIN — sign out all sessions on the breached service(s) (look for 'sign out all devices' in account security settings).",
        "2. ROTATE — change the password on EVERY breached account NOW. One at a time, starting with email accounts (email = the key to every other reset).",
        "3. EMAIL FIRST — your email account password is the master key. Rotate it before anything else, then turn on 2-step verification there.",
        "4. NO REUSE — each rotated account gets a UNIQUE password. If the old password was reused anywhere else, those accounts are compromised too — rotate them.",
        "5. 2FA EVERYWHERE — enable app-based or hardware-key 2FA (not SMS) on every account you just rotated.",
        "6. PASSWORD MANAGER — generate the new passwords inside a password manager so you never type or reuse them.",
        "7. REVOKE TOKENS — after rotation, revoke app passwords, API tokens, and authorized sessions tied to the old credentials.",
        "8. VERIFY — re-run the breach check (Start-RotationVerification) to confirm the new exposure state; re-check combolist files you keep locally.",
        "9. MONITOR — watch the email account for password-reset emails you did not request for the next 30 days.",
        "10. NOTIFY — if a financial or work account was exposed, tell the institution/employer per their incident policy."
    )
    Write-Host ""
    Write-Host "=== CREDENTIAL ROTATION CHECKLIST ==="
    foreach ($a in $ExposedAccounts) { Write-Host "    account: $a" }
    if ($PriorityBreaches.Count -gt 0) {
        Write-Host "    priority breaches: $($PriorityBreaches -join ', ')"
    }
    Write-Host ""
    foreach ($s in $steps) { Write-Host "    $s" }
    Write-Host ""
    New-BreachLog -Step "rotation-checklist" -Data @{
        accounts = ($ExposedAccounts -join "; ")
        steps    = $steps.Count
    }
    return $steps
}

function Start-RotationVerification {
    <#
    Post-rotation re-check: re-runs the HIBP breach+paste query for an email
    and diffs breach names against a baseline list (names only, so a *new*
    breach appearing after rotation is flagged). Prints PASS/FAIL per email.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Email,
        [Parameter(Mandatory=$true)][string]$ApiKey,
        [string[]]$BaselineBreachNames = @()
    )
    try {
        Write-Host "[*] rotation verification re-check: $Email"
        $summary = Get-BreachSummaryForEmail -Email $Email -ApiKey $ApiKey
        if ($null -eq $summary) { return $null }
        $current = @($summary.breaches | ForEach-Object { $_.Name })
        $newOnes = @($current | Where-Object { $BaselineBreachNames -notcontains $_ })
        $verdict = [pscustomobject]@{
            email         = $Email
            checkedUtc    = $summary.checkedUtc
            baselineCount = $BaselineBreachNames.Count
            currentCount  = $current.Count
            newBreaches   = $newOnes
            status        = if ($newOnes.Count -eq 0) { "PASS" } else { "FAIL" }
        }
        if ($verdict.status -eq "PASS") {
            Write-Host "[+] VERIFICATION PASS: no new breaches since rotation baseline for $Email"
        } else {
            Write-Host "[!] VERIFICATION FAIL: new breach(es) since baseline: $($newOnes -join ', ')"
            Write-Host "    -> treat the new breach as unrotated: run New-RotationChecklist again."
        }
        New-BreachLog -Step "rotation-verification" -Data @{
            email  = $Email
            status = $verdict.status
            new    = ($newOnes -join "; ")
        }
        return $verdict
    } catch {
        Write-Host "[!] rotation verification failed: $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Vault logging + report export
# ---------------------------------------------------------------------------
function Test-IsCredentialFieldName {
    <#
    Safety predicate: $true when a property/field NAME looks like it could
    hold a credential. Single source of truth for the whole module — used by
    New-BreachLog (vault safety), Test-ResultForCredentialFields (pre-export
    audit), and Test-BreachCleanHygiene (self-test battery). The pattern is
    intentionally broad: a false positive only blocks a log line, while a
    false negative leaks a credential. -match is case-insensitive.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name
    )
    return ($Name -match "passw|passwd|pwd|secret|token|api[-_]?key|bearer|session[-_]?id|private[-_]?key")
}

function New-BreachLog {
    <#
    Vault-logs one breach-cleaner step (type "breach-step"). Silent when the
    vault module failed to load — never blocks the workflow. Passwords must
    NEVER appear in $Data; this function refuses data containing a key named
    like a password as a safety net.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Step,
        [Parameter(Mandatory=$true)]$Data
    )
    if (-not $script:VaultLoaded -or [string]::IsNullOrWhiteSpace($script:VaultPath)) { return }
    try {
        $flat = @{}
        foreach ($p in $Data.PSObject.Properties) {
            if (Test-IsCredentialFieldName -Name $p.Name) {
                Write-Host "[!] REFUSED to vault-log field '$($p.Name)' — looks like a credential."
                return
            }
            $flat[$p.Name] = $p.Value
        }
        $flat["step"] = $Step
        $flat["utc"]  = (Get-Date).ToUniversalTime().ToString("o")
        $vault = New-Vault -path $script:VaultPath
        Add-VaultEntry -vault $vault -type "breach-step" -data $flat | Out-Null
        Write-Host "[+] vault-logged: breach-step '$Step'"
    } catch {
        Write-Host "[!] vault log failed: $($_.Exception.Message)"
    }
}

function Test-ResultForCredentialFields {
    <#
    Recursively walks a result object (pscustomobject / hashtable / array)
    and returns every property/key NAME that looks credential-like per
    Test-IsCredentialFieldName. Strings and value types are leaves — never
    inspected (a password VALUE can't be caught by a name check; that job
    belongs to the scanners' never-surface rule, proven by the hygiene
    self-test). Depth-capped at 6 to avoid runaway on deep graphs.
    #>
    param(
        [Parameter(Mandatory=$true)]$Object,
        [int]$Depth = 0
    )
    $hits = @()
    if ($null -eq $Object -or $Depth -gt 6) { return $hits }
    if ($Object -is [string] -or $Object -is [System.ValueType]) { return $hits }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in $Object.Keys) {
            if (Test-IsCredentialFieldName -Name ([string]$k)) { $hits += [string]$k }
            $hits += Test-ResultForCredentialFields -Object $Object[$k] -Depth ($Depth + 1)
        }
        return $hits
    }
    if ($Object -is [System.Collections.IEnumerable]) {
        foreach ($item in $Object) {
            $hits += Test-ResultForCredentialFields -Object $item -Depth ($Depth + 1)
        }
        return $hits
    }
    foreach ($p in $Object.PSObject.Properties) {
        if (Test-IsCredentialFieldName -Name $p.Name) { $hits += $p.Name }
        else { $hits += Test-ResultForCredentialFields -Object $p.Value -Depth ($Depth + 1) }
    }
    return $hits
}

function Export-BreachReport {
    <#
    Writes the full result set to JSON + human-readable TXT in $OutDir,
    SHA-256 hashes each file, and vault-logs the export (counts only).
    #>
    param(
        [Parameter(Mandatory=$true)]$Results,
        [Parameter(Mandatory=$true)][string]$OutDir
    )
    try {
        # Safety net: refuse to write a report that carries credential-like
        # fields. If this ever fires, inspect the result objects — it means
        # a credential slipped into a result shape upstream.
        $credHits = Test-ResultForCredentialFields -Object $Results
        if ($credHits.Count -gt 0) {
            $uniq = @($credHits | Select-Object -Unique) -join ", "
            Write-Host "[!] REFUSED to export report — result contains credential-like field(s): $uniq"
            Write-Host "    Nothing was written. Inspect the result objects before exporting."
            return $null
        }
        $dir = New-Item -ItemType Directory -Path $OutDir -Force
        $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
        $jsonPath = Join-Path $dir.FullName "breach-report-$stamp.json"
        $txtPath  = Join-Path $dir.FullName "breach-report-$stamp.txt"

        $Results | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8

        $sb = New-Object System.Text.StringBuilder
        $sb.AppendLine("BLACKBOX BREACH REPORT — $stamp UTC") | Out-Null
        $sb.AppendLine("=" * 60) | Out-Null
        foreach ($r in @($Results)) {
            $sb.AppendLine("") | Out-Null
            if ($r.PSObject.Properties.Name -contains "email") {
                $sb.AppendLine("EMAIL: $($r.email)") | Out-Null
                $sb.AppendLine("  breaches: $($r.breachCount)   pastes: $($r.pasteCount)") | Out-Null
                foreach ($b in @($r.breaches)) {
                    $sb.AppendLine("    - $($b.Name) | $($b.Title) | $($b.BreachDate) | $($b.PwnCount) accounts | data: $($b.DataClasses)") | Out-Null
                }
                foreach ($p in @($r.pastes)) {
                    $sb.AppendLine("    - paste [$($p.Source)] $($p.Title) ($($p.Date))") | Out-Null
                }
            }
            if ($r.PSObject.Properties.Name -contains "hitCount") {
                $sb.AppendLine("COMBOLIST: $($r.account) in $([System.IO.Path]::GetFileName($r.file))") | Out-Null
                $sb.AppendLine("  credential lines found: $($r.hitCount) (passwords never shown)") | Out-Null
            }
        }
        # Triage section: worst-first exposure profile so rotation starts
        # where the damage is. Accounts + levels only — no payload.
        $emails = @($Results | Where-Object { $_.PSObject.Properties.Name -contains "email" })
        if ($emails.Count -gt 0) {
            $combos = @($Results | Where-Object { $_.PSObject.Properties.Name -contains "hitCount" })
            $profiles = Get-BreachExposureProfile -EmailResults $emails -CombolistResults $combos
            $sb.AppendLine("") | Out-Null
            $sb.AppendLine("EXPOSURE SEVERITY (triage order — rotate top-down)") | Out-Null
            $sb.AppendLine("-" * 60) | Out-Null
            foreach ($p in $profiles) {
                $sb.AppendLine("  [$($p.level)] $($p.account) — score $($p.score), $($p.breachCount) breach(es), $($p.pasteCount) paste(s), $($p.combolistHits) combolist hit(s)") | Out-Null
                foreach ($rule in @($p.topRules)) {
                    $sb.AppendLine("      * $rule") | Out-Null
                }
            }
        }
        Set-Content -Path $txtPath -Value $sb.ToString() -Encoding UTF8

        $jh = (Get-FileHash -Path $jsonPath -Algorithm SHA256).Hash
        $th = (Get-FileHash -Path $txtPath -Algorithm SHA256).Hash
        "$jh  $([System.IO.Path]::GetFileName($jsonPath))" | Set-Content -Path ($jsonPath + ".sha256")
        "$th  $([System.IO.Path]::GetFileName($txtPath))"  | Set-Content -Path ($txtPath + ".sha256")

        Write-Host "[+] report written:"
        Write-Host "    $jsonPath  (SHA-256 $jh)"
        Write-Host "    $txtPath  (SHA-256 $th)"
        New-BreachLog -Step "export-report" -Data @{
            json = $jsonPath; txt = $txtPath
            jsonSha256 = $jh; txtSha256 = $th
        }
        return @($jsonPath, $txtPath)
    } catch {
        Write-Host "[!] report export failed: $($_.Exception.Message)"
        return $null
    }
}

function Test-BreachCleanHygiene {
    <#
    Self-audit of the module's credential-safety and scoring promises. No
    network, no credentials needed. Eight checks:
      1. credential-predicate — Test-IsCredentialFieldName catches a battery
         of credential-like names and ignores benign ones.
      2. combolist-no-password-surface — runs Scan-CombolistFile against a
         synthetic dump containing a random password, then JSON-round-trips
         the result: the password must appear NOWHERE in the serialized
         output, no result property may be credential-like, and the expected
         hits must land on the expected lines.
      3. verdict-shape — New-PwnedVerdict output carries counts/verdict only.
      4. breach-severity — classifier levels + word-boundary regression
         cases + profile ordering.
      5. tracker-normalization — tracker key dedup/normalization round trip.
      6. key-file-acl — ACL tightening round trip (SKIP off Windows).
      7. result-normalization — a failed ($null) check normalizes to
         complete=$false, never to a clean bill of health.
      8. combolist-accumulation — hits accumulate across dump files, the
         +25 bonus fires once.
    Prints a pass/fail table; returns $true when all pass.
    #>
    param(
        [string]$WorkDir = (Join-Path ([System.IO.Path]::GetTempPath()) "Falsum-Hygiene")
    )
    $results = @()

    # --- 1. predicate battery ---
    $shouldCatch  = @("password","passwd","pwd","secret","api_key","api-key","apikey","auth_token","session_id","bearer","oldPassword","NEW_PASSWORD","private_key")
    $shouldIgnore = @("email","account","breachCount","file","hitCount","PwnCount","jsonSha256","Title","EmailCount","DataClasses")
    $missed   = @($shouldCatch  | Where-Object { -not (Test-IsCredentialFieldName -Name $_) })
    $falsePos = @($shouldIgnore | Where-Object {       Test-IsCredentialFieldName -Name $_ })
    $pass1 = ($missed.Count -eq 0 -and $falsePos.Count -eq 0)
    $results += [pscustomobject]@{
        check  = "credential-predicate"
        pass   = $pass1
        detail = "missed=[$($missed -join ',')]; false-positive=[$($falsePos -join ',')]"
    }

    # --- 2. synthetic combolist drill ---
    $ok2 = $false
    $detail2 = ""
    try {
        $dir = New-Item -ItemType Directory -Path $WorkDir -Force
        $dump = Join-Path $dir.FullName "synthetic-dump.txt"
        $fakePw = "SYNTHETIC-PW-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
        @(
            "alice@example.com:$fakePw:extra",
            "bob@example.com:someotherpw",
            "# this comment line must be skipped",
            "// another comment line",
            "carol:carolpw"
        ) | Set-Content -Path $dump -Encoding UTF8
        $scan = Scan-CombolistFile -Path $dump -Accounts @("alice@example.com","carol") `
            -AlsoMatchBareUsernames -ProgressEvery 1000000
        if ($null -ne $scan) {
            $rows = @($scan)
            $json = ($rows | ConvertTo-Json -Depth 4)
            $leak = $json.Contains($fakePw)
            $propNames = @()
            foreach ($r in $rows) { foreach ($p in $r.PSObject.Properties) { $propNames += $p.Name } }
            $credProps = @($propNames | Where-Object { Test-IsCredentialFieldName -Name $_ })
            $alice = $rows | Where-Object { $_.account -eq "alice@example.com" } | Select-Object -First 1
            $carol = $rows | Where-Object { $_.account -eq "carol" } | Select-Object -First 1
            $ok2 = ((-not $leak) -and ($credProps.Count -eq 0) -and `
                    ($null -ne $alice) -and ($alice.hitCount -eq 1) -and ($alice.hitLines[0] -eq 1) -and `
                    ($null -ne $carol) -and ($carol.hitCount -eq 1) -and ($carol.hitLines[0] -eq 5))
            $detail2 = "pw-leak-in-json=$leak; credential-props=[$($credProps -join ',')]; aliceHits=$($alice.hitCount)@L$($alice.hitLines -join ','); carolHits=$($carol.hitCount)@L$($carol.hitLines -join ',')"
        } else {
            $detail2 = "scan returned null"
        }
    } catch {
        $detail2 = "exception: $($_.Exception.Message)"
    }
    $results += [pscustomobject]@{ check = "combolist-no-password-surface"; pass = $ok2; detail = $detail2 }

    # --- 3. verdict shape ---
    $v = New-PwnedVerdict -Count 3
    $vProps = @($v.PSObject.Properties.Name)
    $vCred = @($vProps | Where-Object { Test-IsCredentialFieldName -Name $_ })
    $ok3 = ($v.pwnCount -eq 3) -and ($v.isPwned -eq $true) -and ($vCred.Count -eq 0)
    $results += [pscustomobject]@{
        check  = "verdict-shape"
        pass   = $ok3
        detail = "props=[$($vProps -join ',')]; credential-props=[$($vCred -join ',')]"
    }

    # --- 4. breach severity classifier ---
    $sevCases = @(
        @{ name = "BreachA"; classes = "Email addresses; Passwords";               expLevel = "CRITICAL"; expMin = 60 },
        @{ name = "BreachB"; classes = "Email addresses; Password hints";          expLevel = "HIGH";     expMin = 35 },
        @{ name = "BreachC"; classes = "Email addresses; Names";                   expLevel = "MEDIUM";   expMin = 15 },
        @{ name = "BreachD"; classes = "Email addresses; IP addresses";            expLevel = "LOW";      expMin = 1 },
        @{ name = "QuickX";  classes = "(quick mode — re-run without -Quick)";     expLevel = "UNKNOWN";  expMin = 0 },
        @{ name = "BreachE"; classes = "PASSWORDS";                                expLevel = "CRITICAL"; expMin = 60 },
        @{ name = "BreachF"; classes = "Usernames; Dates of birth";                expLevel = "MEDIUM";   expMin = 15 },
        @{ name = "BreachG"; classes = "";                                         expLevel = "UNKNOWN";  expMin = 0 },
        # word-boundary regression: "usernames" must NOT fire the "names" rule
        @{ name = "BreachH"; classes = "Usernames";                                expLevel = "LOW";      expMin = 10; expMax = 10 },
        @{ name = "BreachI"; classes = "Usernames; Names";                         expLevel = "MEDIUM";   expMin = 15; expMax = 15 },
        @{ name = "BreachJ"; classes = "Email addresses; IP addresses";            expLevel = "LOW";      expMin = 13; expMax = 13 },
        @{ name = "BreachK"; classes = "Passport numbers; Recovery email addresses"; expLevel = "HIGH";   expMin = 45; expMax = 45 },
        @{ name = "BreachL"; classes = "Recovery email addresses";                 expLevel = "MEDIUM";   expMin = 25; expMax = 25 },
        @{ name = "BreachM"; classes = "PINs";                                     expLevel = "MEDIUM";   expMin = 15; expMax = 15 }
    )
    $sevFails = @()
    foreach ($c in $sevCases) {
        $r = Test-BreachSeverity -BreachName $c.name -DataClasses $c.classes
        $fail = ($r.level -ne $c.expLevel) -or ([int]$r.score -lt [int]$c.expMin)
        if ($c.ContainsKey("expMax") -and [int]$r.score -gt [int]$c.expMax) { $fail = $true }
        if ($fail) {
            $sevFails += "$($c.name): got $($r.level)/$($r.score), want $($c.expLevel)>=$($c.expMin)$(if($c.ContainsKey('expMax')){ '<='+$c.expMax })"
        }
    }
    # profile ordering: worst-first
    $fakeSummaries = @(
        [pscustomobject]@{ email = "low@x.com";  breachCount = 1; pasteCount = 0;
            breaches = @([pscustomobject]@{ Name = "BreachD"; DataClasses = "Email addresses; IP addresses" }) },
        [pscustomobject]@{ email = "crit@x.com"; breachCount = 1; pasteCount = 0;
            breaches = @([pscustomobject]@{ Name = "BreachA"; DataClasses = "Email addresses; Passwords" }) }
    )
    $profs = Get-BreachExposureProfile -EmailResults $fakeSummaries -CombolistResults @()
    $orderOk = ($profs.Count -eq 2) -and ($profs[0].account -eq "crit@x.com") -and ($profs[1].account -eq "low@x.com")
    if (-not $orderOk) { $sevFails += "profile order wrong: $(($profs | ForEach-Object { $_.account }) -join ',')" }
    $ok4 = ($sevFails.Count -eq 0)
    $results += [pscustomobject]@{
        check  = "breach-severity"
        pass   = $ok4
        detail = "cases=$($sevCases.Count); order=$orderOk; fails=[$($sevFails -join '; ')]"
    }

    # --- 5. tracker key normalization ---
    $ok5 = $false; $detail5 = ""
    try {
        $tdir = Join-Path $dir.FullName "tracker-norm"
        $tpath = New-RotationTracker -ExposedAccounts @("  Alice@Example.COM ", "alice@example.com", "BOB@example.com") `
            -BreachesByAccount @{"alice@example.com"=@("BreachX")} `
            -SeverityByAccount @{"bob@example.com"="HIGH"} -OutDir $tdir
        $tobj = Get-Content -Path $tpath -Raw -Encoding UTF8 | ConvertFrom-Json
        $keys = @($tobj.accounts.PSObject.Properties.Name)
        Update-RotationStatus -TrackerPath $tpath -Account "ALICE@EXAMPLE.COM" -Status "rotated" | Out-Null
        $tobj2 = Get-Content -Path $tpath -Raw -Encoding UTF8 | ConvertFrom-Json
        $alice = $tobj2.accounts.'alice@example.com'
        $bob   = $tobj2.accounts.'bob@example.com'
        $pending = @($tobj2.accounts.PSObject.Properties | Where-Object { $_.Value.status -eq "pending" }).Count
        $ok5 = ($keys.Count -eq 2) -and ($alice.status -eq "rotated") -and `
               (@($alice.breaches) -contains "BreachX") -and `
               ($bob.severity -eq "HIGH") -and ($pending -eq 1)
        $detail5 = "keys=[$($keys -join ',')]; alice=$($alice.status); bobSeverity=$($bob.severity); pending=$pending"
    } catch {
        $detail5 = "exception: $($_.Exception.Message)"
    }
    $results += [pscustomobject]@{ check = "tracker-normalization"; pass = $ok5; detail = $detail5 }

    # --- 6. key-file ACL hardening ---
    $ok6 = $false; $detail6 = ""
    try {
        $aclStackOk = $true
        try { $null = [System.Security.AccessControl.FileSystemAccessRule] } catch { $aclStackOk = $false }
        if (-not $aclStackOk) {
            $ok6 = $true; $detail6 = "SKIP: no Windows ACL stack on this host"
        } else {
            $aclFile = Join-Path $dir.FullName "hibp-test.key"
            "TESTKEY-NOT-A-REAL-KEY" | Set-Content -Path $aclFile -NoNewline
            $tightened = Set-HibpKeyFileSecure -KeyFilePath $aclFile
            $looseAfter = Test-HibpKeyFileAcl -KeyFilePath $aclFile
            $ok6 = ($tightened -eq $true) -and ($null -ne $looseAfter) -and ($looseAfter.Count -eq 0)
            $detail6 = "tightened=$tightened; loose-after=[$($looseAfter -join ',')]"
            Remove-Item -Path $aclFile -Force -ErrorAction SilentlyContinue
        }
    } catch {
        $detail6 = "exception: $($_.Exception.Message)"
    }
    $results += [pscustomobject]@{ check = "key-file-acl"; pass = $ok6; detail = $detail6 }

    # --- 7. failed check is never a clean bill of health ---
    $n1 = ConvertTo-BreachCheckResults -Breaches $null -Pastes $null
    $n2 = ConvertTo-BreachCheckResults -Breaches @() -Pastes @()
    $oneBreach = [pscustomobject]@{ Name = "BreachX" }
    $n3 = ConvertTo-BreachCheckResults -Breaches @($oneBreach, $null) -Pastes @()
    $n4 = ConvertTo-BreachCheckResults -Breaches $oneBreach -Pastes @()
    $ok7 = ($n1.complete -eq $false) -and ($n1.breachFailed -eq $true) -and ($n1.pasteFailed -eq $true) -and `
           ($n1.breaches.Count -eq 0) -and ($n1.pastes.Count -eq 0) -and `
           ($n2.complete -eq $true) -and `
           ($n3.complete -eq $false) -and ($n3.breaches.Count -eq 1) -and ($n3.breaches[0].Name -eq "BreachX") -and `
           ($n4.complete -eq $true) -and ($n4.breaches.Count -eq 1)
    $results += [pscustomobject]@{
        check  = "result-normalization"
        pass   = $ok7
        detail = "null-null complete=$($n1.complete); empty-empty complete=$($n2.complete); mixed count=$($n3.breaches.Count); single count=$($n4.breaches.Count)"
    }

    # --- 8. combolist hits accumulate across dump files (no overwrite) ---
    $comboRows = @(
        [pscustomobject]@{ account = "dup@x.com"; hitCount = 3 },
        [pscustomobject]@{ account = "dup@x.com"; hitCount = 4 }
    )
    $profs8 = Get-BreachExposureProfile -EmailResults @() -CombolistResults $comboRows
    $dup = $profs8 | Where-Object { $_.account -eq "dup@x.com" } | Select-Object -First 1
    $ok8 = ($null -ne $dup) -and ($dup.combolistHits -eq 7) -and ($dup.score -eq 25) -and ($dup.level -eq "MEDIUM")
    $results += [pscustomobject]@{
        check  = "combolist-accumulation"
        pass   = $ok8
        detail = "hits=$($dup.combolistHits) (want 7); score=$($dup.score) (want 25, bonus once); level=$($dup.level)"
    }

    Write-Host ""
    Write-Host "=== BREACH-CLEAN HYGIENE SELF-TEST ==="
    $all = $true
    foreach ($r in $results) {
        $tag = if ($r.pass) { "[PASS]" } else { "[FAIL]" }
        Write-Host "  $tag $($r.check) — $($r.detail)"
        if (-not $r.pass) { $all = $false }
    }
    Write-Host ""
    if ($all) { Write-Host "[+] hygiene self-test: ALL PASS" }
    else { Write-Host "[!] hygiene self-test: FAILURES PRESENT — do not ship until green" }
    return $all
}

function Start-BreachSweep {
    <#
    End-to-end breach sweep (the better way): HIBP key load -> connectivity
    test -> batch email checks -> local combolist scans -> rotation tracker
    -> printed checklist -> hashed JSON+TXT report. Returns a master summary
    object. Passwords never appear anywhere — combolist scans report
    accounts + line numbers only.
    #>
    param(
        [Parameter(Mandatory=$true)][string[]]$Emails,
        [string[]]$CombolistPaths = @(),
        [string[]]$CombolistAccounts = @(),
        [string]$KeyFilePath,
        [string]$OutDir,
        [switch]$IncludeUnverified,
        [switch]$Quick,
        [switch]$AlsoMatchBareUsernames,
        [int]$ThrottleMs = 1600
    )
    try {
        $params = @{}
        if (-not [string]::IsNullOrWhiteSpace($KeyFilePath)) { $params["KeyFilePath"] = $KeyFilePath }
        $key = Get-HibpKey @params
        if ($null -eq $key) { return $null }
        if (-not (Test-HibpConnection -ApiKey $key)) { return $null }

        Write-Host ""
        Write-Host "=== PHASE 1: HIBP email checks ==="
        $emailResults = Get-BreachReportForEmails -Emails $Emails -ApiKey $key `
            -ThrottleMs $ThrottleMs -IncludeUnverified:$IncludeUnverified -Quick:$Quick
        $incompleteEmails = @($emailResults | Where-Object { -not $_.complete })
        if ($incompleteEmails.Count -gt 0) {
            Write-Host "[!] $($incompleteEmails.Count) email check(s) INCOMPLETE (HIBP unreachable) — excluded from triage, NOT counted as clean:"
            foreach ($ie in $incompleteEmails) { Write-Host "      - $($ie.email)  (retry when HIBP is reachable)" }
        }
        $exposedEmails = @($emailResults | Where-Object { $_.complete -and (($_.breachCount + $_.pasteCount) -gt 0) })

        Write-Host ""
        Write-Host "=== PHASE 2: local combolist scans ==="
        $comboAccounts = $CombolistAccounts
        if ($comboAccounts.Count -eq 0) { $comboAccounts = $Emails }
        $comboResults = @()
        foreach ($p in $CombolistPaths) {
            $scan = Scan-CombolistFile -Path $p -Accounts $comboAccounts -AlsoMatchBareUsernames:$AlsoMatchBareUsernames
            if ($null -ne $scan) { $comboResults += $scan }
        }
        $exposedCombo = @($comboResults | Where-Object { $_.hitCount -gt 0 } | ForEach-Object { $_.account })

        $breachesByAccount = @{}
        foreach ($e in $exposedEmails) {
            $breachesByAccount[$e.email] = @($e.breaches | ForEach-Object { $_.Name })
        }
        foreach ($c in $exposedCombo) {
            if (-not $breachesByAccount.ContainsKey($c)) { $breachesByAccount[$c] = @("combolist-hit") }
        }
        $allExposed = @($breachesByAccount.Keys)

        $trackerPath = $null
        if ($allExposed.Count -gt 0) {
            Write-Host ""
            Write-Host "=== PHASE 3: rotation workflow (severity triage) ==="
            $profiles = Get-BreachExposureProfile -EmailResults $emailResults -CombolistResults $comboResults
            Write-Host "[*] exposure triage (rotate top-down):"
            foreach ($p in $profiles) {
                Write-Host "    [$($p.level)] $($p.account) — score $($p.score)"
            }
            $triageOrder = @($profiles | ForEach-Object { $_.account })
            # include any exposed account the profile didn't cover (belt and suspenders)
            foreach ($a in $allExposed) { if ($triageOrder -notcontains $a) { $triageOrder += $a } }
            $priority = @()
            foreach ($k in $breachesByAccount.Keys) { $priority += $breachesByAccount[$k] }
            New-RotationChecklist -ExposedAccounts $triageOrder -PriorityBreaches @($priority | Select-Object -Unique) | Out-Null
            $sevByAcct = @{}
            foreach ($p in $profiles) { $sevByAcct[$p.account] = $p.level }
            $trackerPath = New-RotationTracker -ExposedAccounts $triageOrder -BreachesByAccount $breachesByAccount -SeverityByAccount $sevByAcct
        } else {
            Write-Host "[+] no exposures found — nothing to rotate."
        }

        Write-Host ""
        Write-Host "=== PHASE 4: export ==="
        if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = Join-Path $env:USERPROFILE "Desktop\Falsum-Reports" }
        $master = [pscustomobject]@{
            sweepUtc       = (Get-Date).ToUniversalTime().ToString("o")
            emailsChecked  = @($emailResults).Count
            exposedEmails  = @($exposedEmails | ForEach-Object { $_.email })
            combolistHits  = $exposedCombo
            trackerPath    = $trackerPath
        }
        $all = @()
        $all += @($emailResults)
        $all += @($comboResults)
        $exported = Export-BreachReport -Results $all -OutDir $OutDir
        Write-Host ""
        Write-Host "=== SWEEP COMPLETE ==="
        Write-Host "  emails checked : $($master.emailsChecked)"
        Write-Host "  exposed emails : $($master.exposedEmails.Count)"
        Write-Host "  combolist hits : $($master.combolistHits.Count)"
        if ($trackerPath) { Write-Host "  tracker        : $trackerPath" }
        New-BreachLog -Step "sweep-complete" -Data @{
            emailsChecked = $master.emailsChecked
            exposedEmails = ($master.exposedEmails -join "; ")
            combolistHits = ($master.combolistHits -join "; ")
        }
        return $master
    } catch {
        Write-Host "[!] sweep failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-BreachReportForEmail {
    <#
    One-call convenience: loads the key, checks connectivity, runs breach +
    paste checks, prints the rotation checklist when exposed. -Quick and
    -IncludeUnverified are threaded through to the HIBP check.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Email,
        [string]$KeyFilePath,
        [switch]$IncludeUnverified,
        [switch]$Quick
    )
    try {
        $params = @{}
        if (-not [string]::IsNullOrWhiteSpace($KeyFilePath)) { $params["KeyFilePath"] = $KeyFilePath }
        $key = Get-HibpKey @params
        if ($null -eq $key) { return $null }
        if (-not (Test-HibpConnection -ApiKey $key)) { return $null }

        $summary = Get-BreachSummaryForEmail -Email $Email -ApiKey $key -IncludeUnverified:$IncludeUnverified -Quick:$Quick
        if ($null -eq $summary) { return $null }

        if (-not $summary.complete) {
            Write-Host "[!] $Email : NO VERDICT — the check did not complete (HIBP unreachable). Do not treat this account as clean; retry and compare."
        }
        elseif ($summary.breachCount -gt 0 -or $summary.pasteCount -gt 0) {
            $names = @($summary.breaches | ForEach-Object { $_.Name })
            $profile = Get-BreachExposureProfile -EmailResults @($summary) -CombolistResults @() | Select-Object -First 1
            if ($null -ne $profile) {
                Write-Host "[!] exposure severity: [$($profile.level)] score $($profile.score)"
                foreach ($rule in @($profile.topRules)) { Write-Host "      * $rule" }
            }
            New-RotationChecklist -ExposedAccounts @($Email) -PriorityBreaches $names | Out-Null
            Write-Host "[!] $Email is exposed in $($summary.breachCount) breach(es), $($summary.pasteCount) paste(s) — rotate per the checklist above."
        } else {
            Write-Host "[+] $Email : no HIBP exposure found."
        }
        return $summary
    } catch {
        Write-Host "[!] breach report failed: $($_.Exception.Message)"
        return $null
    }
}

Write-Host "[+] Falsum-BreachClean loaded — 30 functions. Run Get-BreachReportForEmail, Start-BreachSweep, or Test-BreachCleanHygiene — or see the header for usage."
