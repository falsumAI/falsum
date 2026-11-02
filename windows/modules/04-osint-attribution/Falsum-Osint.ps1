<#
Module 04 — OSINT ATTRIBUTION
Every external IP/domain gets: RDAP lookup, crt.sh certificates, Shodan
(free tier, key optional), full DNS records, Team Cymru ASN (passive DNS,
no key), URLhaus threat listing (free, no key). Then the coherence core
converges it all into ONE attribution verdict with a receipt — not a pile
of maybe.

THE BETTER WAY: raw OSINT dumps are noise. This module's output is a
verdict: who this is, how sure, and the exact evidence chain. Diverged
sources get labeled uncertain with the divergence shown, never hidden.
Detection ships its fix: New-SelfExposureFixPlan turns a report on the
user's OWN assets into a concrete exposure-reduction checklist.

Dot-source:
  . .\Falsum-Osint.ps1

HARDENING LOG
- 2026-10-30 (cron, main agent): retry helper Invoke-OsintRest with
  exponential backoff + jitter for all HTTP calls (rdap.org / crt.sh /
  Shodan / URLhaus all flake under load); input validation
  Test-OsintInput (rejects IPs fed to crt.sh, junk strings); Get-AsnInfo
  via Team Cymru DNS (ASN, prefix, country, registry, ASN description,
  upstream peers — zero deps, no API key, IPv4 + IPv6); Get-UrlhausHost
  (free no-key malware-URL listing check); Get-PtrRecord factored out and
  wired into claims; asn-rdap coherence check (Team Cymru ASN name vs
  RDAP org) alongside the existing rdap-asn check; crt.sh hardened
  (email-address rows filtered, wildcard dedup, entry_timestamp guard);
  Get-AttributionReport validates input, dedups ASN claims across the
  domain's resolved IPs, flags URLhaus listings; New-SelfExposureFixPlan
  (Better-Way Law: the fix for exposed self-owned assets); Export-AttributionReport
  (JSON + txt + SHA-256 sidecar).
- 2026-10-30 (cron, main agent, hardening v4): REAL mail-auth gap closed —
  New-SelfExposureFixPlan claimed "missing DMARC is its own finding" but no
  function ever checked mail auth. New Get-MailAuthRecords: SPF parse with
  qualifier grading (dangerous +all = P1, missing SPF = P3), DMARC parse
  (missing = P2, p=none = P2, quarantine = P3 with graduation steps),
  DKIM selector probing across 10 common selectors, and a 10-row
  mail-provider include map (Microsoft 365 / Google Workspace / SES ...)
  feeding a real attribution claim; all wired into Get-AttributionReport
  + Export-AttributionReport + fix plan (MX finding text fixed to stop
  pointing at a check that did not exist). BUG FIX: Get-CrtSh bare-name
  dedup silently dropped wildcard entries ("*.example.com" skipped when
  "example.com" already seen) — exact-match dedup only; row parsing
  extracted as pure-logic ConvertFrom-CrtShRows for offline testing.
  FALSE-POSITIVE FIX: Get-TakeoverCandidates declared "dangling" on
  missing A alone — now also checks AAAA and follows one CNAME hop before
  the verdict. New IDN support: Test-OsintInput converts unicode domains
  via IdnMapping to punycode so DNS/RDAP/crt.sh queries actually run.
  New Test-OsintHygiene offline battery (input classification, IDN,
  SPF/DMARC/DKIM parsing, crt.sh dedup, cert-expiry classification,
  takeover table sanity, provider map sanity) using the scope-safe
  scriptblock-output pattern, wired into launcher option-18 and
  tests/Test-All.ps1 section 10.
- 2026-10-30 (cron, main agent, hardening v3): Get-RdapDomain (registrar,
  creation/expiry with days-to-expiry, nameservers, status flags,
  secureDNS delegation flag — passive, no key); Get-DnssecStatus
  (RRSIG/DNSKEY via own resolver + RDAP delegation flag; honest
  signed/unsigned/unknown states); Get-CaaRecords (CAA presence, type-name
  with numeric fallback); Get-CrtSh now captures per-cert not_before/
  not_after into $out.expiries; Get-CrtExpiryReport classifies
  EXPIRED/EXPIRING-SOON(<=30d)/OK with zero new queries;
  Get-TakeoverCandidates (passive subdomain-takeover triage from crt.sh
  names: dangling CNAMEs flagged high-confidence via NXDOMAIN on target,
  26-service fingerprint table at medium confidence labeled
  "verify manually" — claiming never automated); Get-CrtDelta (local CT
  baseline, NEW-host surfacing, first-run safe); Get-HttpFingerprint
  (ONE passive GET: server leaks, missing security headers, edge hints);
  all wired into Get-AttributionReport + claims + Export-AttributionReport
  + New-SelfExposureFixPlan (P1: expired certs, dangling CNAMEs, domain
  expiring<=30d; P2: certs expiring soon, fingerprint CNAMEs, unsigned
  DNSSEC, missing HSTS; P3: missing CAA, X-Powered-By leak).
- 2026-10-30 (cron, main agent, hardening v5): FIXED A DEAD SKIP RULE —
  the wildcard guard `-like "\*\.*"` was a no-op (backslash is not the
  wildcard escape in PowerShell; the pattern requires a literal "\"), so
  "*.example.com" names were probed through the zone's own wildcard
  records — new pure Test-TakeoverNameSkip (wildcard + apex skip) used by
  Get-TakeoverCandidates. FIXED trailing-dot FQDN rejection: "example.com."
  was invalid input (netscan parity). FIXED fix-plan cross-call pollution:
  New-SelfExposureFixPlan accumulated findings in $script:__fx across
  calls in one session — the $add scriptblock now returns the object and
  callers collect output (sibling convention). FIXED daysToExpiry
  machine-dependence: Get-RdapDomain parsed registry dates with bare
  [datetime], so zone-less strings shifted by the local offset — new pure
  ConvertTo-OsintUtcDate (RoundtripKind; zone-less read as UTC, the
  coherence-core v1.4 bug class). NEW per-IP Shodan in the domain path of
  Get-AttributionReport (graceful without a key) — the fix-plan P1
  "Shodan exposes open ports" could never fire for domain targets before.
  NEW table-driven Get-HttpEdgeHint (12 CDN/edge providers, header-first
  matching) replacing the 5-branch elseif chain. Hygiene battery gains
  section 9 (16 cases: trailing-dot, skip predicate, UTC dates, edge
  hints, fix-plan reentrancy proof).
#>

$script:CoherenceLoaded = $false
$script:VaultLoaded = $false
$script:VaultPath = ""
function Import-CoherenceCore {
    if ($script:CoherenceLoaded) { return }
    $here = Split-Path -Parent $MyInvocation.PSCommandPath
    $core = Join-Path (Split-Path -Parent $here) "00-coherence-core\Falsum-Coherence.ps1"
    if (-not (Test-Path $core)) {
        $core = Join-Path $here "..\00-coherence-core\Falsum-Coherence.ps1"
    }
    if (Test-Path $core) { . $core; $script:CoherenceLoaded = $true }
    else { Write-Host "[!] coherence core not found at $core — verdicts will lack scoring" }
}

function Import-VaultModule {
    if ($script:VaultLoaded) { return }
    $here = Split-Path -Parent $MyInvocation.PSCommandPath
    $mod = Join-Path (Split-Path -Parent $here) "12-timeline-vault\Falsum-Vault.ps1"
    if (-not (Test-Path $mod)) {
        $mod = Join-Path $here "..\12-timeline-vault\Falsum-Vault.ps1"
    }
    if (Test-Path $mod) { . $mod; $script:VaultLoaded = $true }
    else { Write-Host "[!] vault module not found at $mod — queries will not be vault-logged" }
}

function New-OsintLog {
    <#
    Every query goes to the vault (type "osint-query"). Silent when the
    vault module failed to load or no vault path was given — never blocks
    a query.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$QueryType,
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)]$Result
    )
    if (-not $script:VaultLoaded -or [string]::IsNullOrWhiteSpace($script:VaultPath)) { return }
    try {
        $vault = New-Vault -path $script:VaultPath
        $ok = $true
        if ($null -ne $Result -and $Result.PSObject.Properties.Name -contains "ok") { $ok = $Result.ok }
        Add-VaultEntry -vault $vault -type "osint-query" -data @{
            query  = $QueryType
            target = $Target
            ok     = $ok
            utc    = (Get-Date).ToUniversalTime().ToString("o")
        } | Out-Null
        Write-Host "[+] vault-logged: $QueryType on $Target"
    } catch {
        Write-Host "[!] vault log failed: $($_.Exception.Message)"
    }
}

$script:HttpUA = "Falsum-Osint/1.0 (Windows; PowerShell 5.1)"

function Invoke-OsintRest {
    <#
    HTTP with retry. rdap.org, crt.sh, Shodan and URLhaus all rate-limit or
    flake; one dropped call must not kill a report. Exponential backoff with
    jitter, PS 5.1 only (no SkipHttpErrorCheck — that is PS6+).
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [string]$Method = "Get",
        $Body = $null,
        [int]$TimeoutSec = 15,
        [int]$MaxAttempts = 3,
        [int]$BaseDelayMs = 800
    )
    $out = [pscustomobject]@{ ok = $false; response = $null; error = ""; attempts = 0 }
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        $out.attempts = $i
        try {
            $params = @{
                Uri = $Uri; Method = $Method; UserAgent = $script:HttpUA
                TimeoutSec = $TimeoutSec; ErrorAction = "Stop"
            }
            if ($null -ne $Body) { $params.Body = $Body }
            $out.response = Invoke-RestMethod @params
            $out.ok = $true
            $out.error = ""
            return $out
        } catch {
            $out.error = $_.Exception.Message
            if ($i -lt $MaxAttempts) {
                $delay = $BaseDelayMs * [math]::Pow(2, $i - 1)
                $jitter = Get-Random -Minimum 0 -Maximum ([int]($delay / 2) + 1)
                Start-Sleep -Milliseconds ([int]($delay + $jitter))
            }
        }
    }
    return $out
}

function Test-OsintInput {
    <#
    Classifies and validates a target before any query runs: IP, domain, or
    invalid. Stops the classic crt.sh-on-an-IP waste and junk-string lookups.
    #>
    param([Parameter(Mandatory=$true)][string]$Target)
    # Trailing-dot FQDNs ("example.com.") are valid DNS — accept them
    # (netscan parity: Test-TargetSpec accepts them too).
    $t = $Target.Trim().TrimEnd('.')
    $addr = $null
    if ([System.Net.IPAddress]::TryParse($t, [ref]$addr)) {
        return [pscustomobject]@{ valid = $true; kind = "ip"; value = $t; note = "" }
    }
    if ($t -match '^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$' -or
        $t -match '^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$') {
        return [pscustomobject]@{ valid = $true; kind = "domain"; value = $t.ToLower(); note = "" }
    }
    if ($t -match '[^\x00-\x7F]') {
        # Internationalized domain name — convert to punycode (IDNA) so DNS,
        # RDAP and crt.sh queries run against the ASCII form the wire uses.
        try {
            $idn = New-Object System.Globalization.IdnMapping
            $ascii = $idn.GetAscii($t)
            if ($ascii -match '^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$' -or
                $ascii -match '^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$') {
                return [pscustomobject]@{ valid = $true; kind = "domain"; value = $ascii.ToLower(); note = "idn:$t" }
            }
        } catch { }
    }
    return [pscustomobject]@{ valid = $false; kind = "unknown"; value = $t; note = "not a valid IP address or domain name" }
}

function Get-RdapIp {
    param([Parameter(Mandatory=$true)][string]$Ip)
    $out = [pscustomobject]@{
        ok = $false; ip = $Ip; org = ""; cidr = ""; country = "";
        handle = ""; asn = ""; source = "rdap"; error = ""
    }
    $chk = Test-OsintInput $Ip
    if (-not $chk.valid -or $chk.kind -ne "ip") {
        $out.error = "invalid-ip: $($chk.note)"
        Write-Host "[!] RDAP refused: '$Ip' is not an IP address"
        return $out
    }
    try {
        Write-Host "[*] RDAP $($chk.value)"
        $r = Invoke-OsintRest -Uri "https://rdap.org/ip/$($chk.value)" -TimeoutSec 15
        if (-not $r.ok) { throw $r.error }
        $body = $r.response
        $out.ok = $true
        if ($body.handle) { $out.handle = "$($body.handle)" }
        if ($body.country) { $out.country = "$($body.country)" }
        if ($body.cidr0_cidrs -and $body.cidr0_cidrs.Count -gt 0) {
            $c = $body.cidr0_cidrs[0]
            $out.cidr = "$($c.v4prefix)/$($c.length)"
        }
        # Prefer the registrant/admin vcard "fn"; fall back to the network name.
        foreach ($ent in @($body.entities)) {
            if ($null -eq $ent) { continue }
            $roles = @($ent.roles)
            foreach ($v in @($ent.vcardArray)) {
                if ($v -is [System.Collections.IList] -and $v.Count -gt 1) {
                    foreach ($prop in @($v[1])) {
                        if ($prop -is [System.Collections.IList] -and $prop.Count -ge 4 -and
                            "$($prop[0])" -eq "fn" -and $out.org -eq "") {
                            $out.org = "$($prop[3])"
                        }
                    }
                }
            }
            if ($out.org -ne "" -and $roles -contains "registrant") { break }
        }
        if ($out.org -eq "" -and $body.name) { $out.org = "$($body.name)" }
        Write-Host "[+] RDAP ok: org='$($out.org)' country='$($out.country)' (attempts=$($r.attempts))"
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] RDAP failed for $Ip : $($out.error)"
    }
    New-OsintLog -QueryType "rdap" -Target $Ip -Result $out
    return $out
}

function ConvertFrom-CrtShRows {
    <#
    Pure logic: crt.sh JSON rows -> deduped names + issuers + per-name
    expiries. Extracted so the offline hygiene battery can prove the dedup
    rules (wildcard entries KEPT, email-address rows dropped, exact-name
    dedup) without a network call.
    #>
    param([Parameter(Mandatory=$true)]$Rows)
    $names = @(); $issuers = @(); $expList = @()
    foreach ($row in @($Rows)) {
        if ($row.issuer_name -and $issuers -notcontains "$($row.issuer_name)") {
            $issuers += "$($row.issuer_name)"
        }
        foreach ($n in ("$($row.name_value)" -split "`n")) {
            $n = $n.Trim().ToLower()
            if ($n -eq "" -or $n -like "*@*") { continue }  # email-address rows are noise
            # exact-match dedup only: the old bare-name dedup silently dropped
            # "*.example.com" when "example.com" was already seen.
            if ($names -notcontains $n) {
                $names += $n
                $expList += [pscustomobject]@{
                    name = $n
                    not_before = "$($row.not_before)"
                    not_after  = "$($row.not_after)"
                }
            }
        }
    }
    return [pscustomobject]@{ names = $names; issuers = $issuers; expiries = $expList }
}

function Get-CrtSh {
    param([Parameter(Mandatory=$true)][string]$Domain)
    $chk = Test-OsintInput $Domain
    $out = [pscustomobject]@{
        ok = $false; domain = $Domain.Trim().ToLower(); subdomains = @(); count = 0;
        issuers = @(); latest = ""; expiries = @(); source = "crt.sh"; error = ""
    }
    if (-not $chk.valid -or $chk.kind -ne "domain") {
        $out.error = "invalid-domain: $($chk.note)"
        Write-Host "[!] crt.sh refused: '$Domain' is not a domain name"
        return $out
    }
    $d = $chk.value
    $out.domain = $d
    try {
        Write-Host "[*] crt.sh $d"
        $r = Invoke-OsintRest -Uri "https://crt.sh/?q=%25.$d&output=json" -TimeoutSec 20
        if (-not $r.ok) { throw $r.error }
        $rows = @($r.response)
        $parsed = ConvertFrom-CrtShRows $rows
        $names = $parsed.names; $issuers = $parsed.issuers; $expList = $parsed.expiries
        $out.ok = $true
        $out.subdomains = $names
        $out.count = $names.Count
        $out.issuers = $issuers
        $out.expiries = $expList
        try {
            $withTs = $rows | Where-Object { $_.PSObject.Properties.Name -contains "entry_timestamp" -and $_.entry_timestamp }
            $sorted = @($withTs) | Sort-Object entry_timestamp -Descending
            if ($sorted.Count -gt 0) { $out.latest = "$($sorted[0].entry_timestamp)" }
        } catch { }
        Write-Host "[+] crt.sh ok: $($out.count) names, $($issuers.Count) unique issuers (attempts=$($r.attempts))"
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] crt.sh failed for $d : $($out.error)"
    }
    New-OsintLog -QueryType "crtsh" -Target $d -Result $out
    return $out
}

function Get-ShodanHost {
    param([Parameter(Mandatory=$true)][string]$Ip)
    $out = [pscustomobject]@{
        ok = $false; ip = $Ip; org = ""; ports = @(); asn = "";
        country = ""; source = "shodan"; error = ""
    }
    $chk = Test-OsintInput $Ip
    if (-not $chk.valid -or $chk.kind -ne "ip") {
        $out.error = "invalid-ip: $($chk.note)"
        Write-Host "[!] Shodan refused: '$Ip' is not an IP address"
        return $out
    }
    $key = $env:BLACKBOX_SHODAN_KEY
    $keyFile = Join-Path ([Environment]::GetFolderPath("UserProfile")) ".blackbox\shodan.key"
    if ([string]::IsNullOrEmpty($key) -and (Test-Path $keyFile)) {
        try { $key = (Get-Content $keyFile -Raw).Trim() } catch { $key = "" }
    }
    if ([string]::IsNullOrEmpty($key)) {
        $out.error = "no-api-key"
        Write-Host "[*] Shodan skipped (no key; set BLACKBOX_SHODAN_KEY or %USERPROFILE%\.blackbox\shodan.key)"
        return $out
    }
    try {
        Write-Host "[*] Shodan $($chk.value)"
        $uri = "https://api.shodan.io/shodan/host/$($chk.value)" + "?key=" +
            [System.Net.WebUtility]::UrlEncode($key)
        $r = Invoke-OsintRest -Uri $uri -TimeoutSec 15
        if (-not $r.ok) { throw $r.error }
        $body = $r.response
        $out.ok = $true
        if ($body.ports) { $out.ports = @($body.ports | Sort-Object -Unique) }
        $out.org = "$($body.org)"
        $out.asn = "$($body.asn)"
        $out.country = "$($body.country_name)"
        Write-Host "[+] Shodan ok: org='$($out.org)' asn='$($out.asn)' ports=$($out.ports.Count)"
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] Shodan failed for $Ip : $($out.error)"
    }
    # The key is never written to the vault log.
    New-OsintLog -QueryType "shodan" -Target $Ip -Result $out
    return $out
}

function Get-DnsRecords {
    param([Parameter(Mandatory=$true)][string]$Domain)
    $out = [pscustomobject]@{
        ok = $true; domain = $Domain; A = @(); AAAA = @(); MX = @();
        TXT = @(); NS = @(); CNAME = @(); SOA = ""; source = "dns"
    }
    $chk = Test-OsintInput $Domain
    if (-not $chk.valid -or $chk.kind -ne "domain") {
        $out.ok = $false
        Write-Host "[!] DNS refused: '$Domain' is not a domain name"
        return $out
    }
    $d = $chk.value
    $out.domain = $d
    foreach ($t in @("A","AAAA","MX","TXT","NS","CNAME")) {
        try {
            $r = Resolve-DnsName -Name $d -Type $t -ErrorAction SilentlyContinue
            foreach ($rec in @($r)) {
                switch ($t) {
                    "A"     { if ($rec.IPAddress) { $out.A += "$($rec.IPAddress)" } }
                    "AAAA"  { if ($rec.IPAddress) { $out.AAAA += "$($rec.IPAddress)" } }
                    "MX"    { if ($rec.NameExchange) { $out.MX += "$($rec.NameExchange) (pref $($rec.Preference))" } }
                    "TXT"   { if ($rec.Strings) { $out.TXT += ($rec.Strings -join " ") } }
                    "NS"    { if ($rec.NameHost) { $out.NS += "$($rec.NameHost)" } }
                    "CNAME" { if ($rec.NameHost) { $out.CNAME += "$($rec.NameHost)" } }
                }
            }
        } catch { }
    }
    try {
        $soa = Resolve-DnsName -Name $d -Type SOA -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($soa) { $out.SOA = "$($soa.PrimaryServer) $($soa.ZoneAdmin)" }
    } catch { }
    Write-Host "[*] DNS $d : A=$($out.A.Count) AAAA=$($out.AAAA.Count) MX=$($out.MX.Count) TXT=$($out.TXT.Count) NS=$($out.NS.Count) CNAME=$($out.CNAME.Count)"
    New-OsintLog -QueryType "dns" -Target $d -Result $out
    return $out
}

function Get-AsnInfo {
    <#
    Team Cymru IP-to-ASN lookup over plain DNS TXT — passive, no API key,
    no account, no HTTP. Gives ASN, announced prefix, country, registry,
    the ASN's registered name, and upstream peers. IPv4 and IPv6.
    #>
    param([Parameter(Mandatory=$true)][string]$Ip)
    $out = [pscustomobject]@{
        ok = $false; ip = $Ip; asn = ""; prefix = ""; country = "";
        registry = ""; asnName = ""; upstreams = @(); source = "team-cymru"; error = ""
    }
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip.Trim(), [ref]$addr)) {
        $out.error = "not-an-ip"
        Write-Host "[!] ASN refused: '$Ip' is not an IP address"
        return $out
    }
    try {
        $bytes = $addr.GetAddressBytes()
        if ($bytes.Length -eq 4) {
            $rev = ($bytes[3..0] | ForEach-Object { "$_" }) -join "."
            $qname = "$rev.origin.asn.cymru.com"
        } else {
            $hex = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
            $nibbles = @($hex.ToCharArray() | ForEach-Object { "$_" })
            [array]::Reverse($nibbles)
            $qname = ($nibbles -join ".") + ".origin6.asn.cymru.com"
        }
        Write-Host "[*] ASN $($Ip.Trim())"
        $txt = Resolve-DnsName -Name $qname -Type TXT -ErrorAction Stop
        $first = ($txt | Where-Object { $_.Strings } | Select-Object -First 1).Strings -join " "
        $parts = @($first -split "\|" | ForEach-Object { $_.Trim() })
        if ($parts.Count -ge 4 -and $parts[0] -match '^\d+$') {
            $out.ok = $true
            $out.asn = $parts[0]; $out.prefix = $parts[1]
            $out.country = $parts[2]; $out.registry = $parts[3]
            try {
                $d = Resolve-DnsName -Name ("AS" + $out.asn + ".asn.cymru.com") -Type TXT -ErrorAction SilentlyContinue
                $ds = ($d | Where-Object { $_.Strings } | Select-Object -First 1).Strings -join " "
                $dp = @($ds -split "\|" | ForEach-Object { $_.Trim() })
                if ($dp.Count -ge 5) { $out.asnName = $dp[4] }
            } catch { }
            try {
                $p = Resolve-DnsName -Name ($out.asn + ".peer.asn.cymru.com") -Type TXT -ErrorAction SilentlyContinue
                foreach ($row in @($p)) {
                    foreach ($s in @($row.Strings)) {
                        $peers = @($s -split "\|" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' })
                        foreach ($peer in $peers) {
                            if ($out.upstreams -notcontains $peer) { $out.upstreams += $peer }
                        }
                    }
                }
            } catch { }
            Write-Host "[+] ASN ok: AS$($out.asn) '$($out.asnName)' $($out.prefix) $($out.country)"
        } else {
            $out.error = "unparseable-reply"
            Write-Host "[!] ASN lookup returned unparseable data for $Ip"
        }
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] ASN lookup failed for $Ip : $($out.error)"
    }
    New-OsintLog -QueryType "asn" -Target $Ip -Result $out
    return $out
}

function Get-UrlhausHost {
    <#
    abuse.ch URLhaus: is this host serving malware URLs right now?
    Free, no API key, single POST. Passive threat-intel pivot — if the
    target is listed, that fact belongs in the verdict.
    #>
    param([Parameter(Mandatory=$true)][string]$Host)
    $out = [pscustomobject]@{
        ok = $false; host = $Host; listed = $false; urlCount = 0;
        threats = @(); source = "urlhaus"; error = ""
    }
    $h = $Host.Trim().ToLower()
    if ([string]::IsNullOrWhiteSpace($h)) {
        $out.error = "empty-host"
        return $out
    }
    try {
        Write-Host "[*] URLhaus $h"
        $r = Invoke-OsintRest -Uri "https://urlhaus-api.abuse.ch/v1/host/" -Method Post `
            -Body @{ url = $h } -TimeoutSec 15
        if (-not $r.ok) { throw $r.error }
        $qs = "$($r.response.query_status)"
        if ($qs -eq "ok") {
            $out.ok = $true; $out.listed = $true
            $urls = @($r.response.urls)
            $out.urlCount = $urls.Count
            foreach ($u in ($urls | Select-Object -First 10)) {
                $out.threats += [pscustomobject]@{
                    url = "$($u.url)"; status = "$($u.url_status)";
                    threat = "$($u.threat)"; tags = "$($u.tags)"
                }
            }
            Write-Host "[!] URLhaus: LISTED — $($out.urlCount) malicious URL(s)"
        } elseif ($qs -eq "no_results") {
            $out.ok = $true; $out.listed = $false
            Write-Host "[+] URLhaus: not listed"
        } else {
            $out.error = "query_status=$qs"
            Write-Host "[!] URLhaus unexpected status: $qs"
        }
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] URLhaus failed for $h : $($out.error)"
    }
    New-OsintLog -QueryType "urlhaus" -Target $h -Result $out
    return $out
}

function Get-PtrRecord {
    <#
    Reverse DNS for one IP. Empty string when none — callers treat "no PTR"
    as a weak signal, not an error.
    #>
    param([Parameter(Mandatory=$true)][string]$Ip)
    try {
        $h = [Net.Dns]::GetHostEntry($Ip.Trim()).HostName
        if (-not [string]::IsNullOrWhiteSpace($h) -and $h -ne $Ip.Trim()) {
            Write-Host "[*] PTR $Ip -> $h"
            return "$h"
        }
    } catch { }
    return ""
}

function Get-AttributionReport {
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [string]$VaultPath = ""
    )
    if ($VaultPath -ne "") { $script:VaultPath = $VaultPath }
    Import-CoherenceCore
    Import-VaultModule
    $chk = Test-OsintInput $Target
    $report = [pscustomobject]@{
        target = $Target; valid = $chk.valid; verdict = "no-data"; agreement = 0
        threatListed = $false
        rdap = $null; asn = $null; shodan = $null; dns = $null; crtsh = $null
        urlhaus = $null; ptr = ""
        rdapDomain = $null; dnssec = $null; caa = $null; certExpiry = $null
        takeover = $null; ctDelta = $null; httpFp = $null; mailauth = $null
        breakdown = @(); coherenceChecks = @(); receipt = $null
    }
    if (-not $chk.valid) {
        $report.verdict = "invalid-input"
        Write-Host "[!] invalid target: $($chk.note)"
        return $report
    }
    Write-Host "[*] attribution report: $($chk.value) ($($chk.kind))"
    $claims = @()
    $asns = @{}
    if ($chk.kind -eq "ip") {
        $ip = $chk.value
        $report.rdap = Get-RdapIp $ip
        $report.asn = Get-AsnInfo $ip
        $report.shodan = Get-ShodanHost $ip
        $report.ptr = Get-PtrRecord $ip
        $report.urlhaus = Get-UrlhausHost $ip
        if ($report.rdap.org -ne "") {
            $claims += [pscustomobject]@{ value = $report.rdap.org; source = "rdap" }
        }
        if ($report.shodan.org -ne "") {
            $claims += [pscustomobject]@{ value = $report.shodan.org; source = "shodan" }
        }
        if ($report.asn.ok -and $report.asn.asnName -ne "") {
            $claims += [pscustomobject]@{ value = "AS$($report.asn.asn): $($report.asn.asnName)"; source = "asn" }
        }
        if ($report.ptr -ne "") {
            $claims += [pscustomobject]@{ value = $report.ptr; source = "ptr" }
        }
    } else {
        $d = $chk.value
        $report.dns = Get-DnsRecords $d
        $report.crtsh = Get-CrtSh $d
        $report.urlhaus = Get-UrlhausHost $d
        $report.rdapDomain = Get-RdapDomain $d
        $report.dnssec = Get-DnssecStatus -Domain $d -RdapDomain $report.rdapDomain
        $report.caa = Get-CaaRecords $d
        $report.mailauth = Get-MailAuthRecords $d
        $report.certExpiry = Get-CrtExpiryReport -CrtSh $report.crtsh
        $report.takeover = Get-TakeoverCandidates -CrtSh $report.crtsh
        $report.ctDelta = Get-CrtDelta -CrtSh $report.crtsh
        $report.httpFp = Get-HttpFingerprint $d
        foreach ($mx in $report.dns.MX) { $claims += [pscustomobject]@{ value = $mx; source = "mx" } }
        foreach ($ns in $report.dns.NS) { $claims += [pscustomobject]@{ value = $ns; source = "ns" } }
        # attribute each resolved IP too, with ASN for each
        $allIps = @($report.dns.A) + @($report.dns.AAAA) | Select-Object -Unique
        foreach ($ip in ($allIps | Select-Object -First 3)) {
            $rd = Get-RdapIp $ip
            if ($rd.org -ne "") { $claims += [pscustomobject]@{ value = $rd.org; source = "rdap:$ip" } }
            $ai = Get-AsnInfo $ip
            if ($ai.ok -and -not $asns.ContainsKey($ai.asn)) {
                $asns[$ai.asn] = $ai
                if ($ai.asnName -ne "") {
                    $claims += [pscustomobject]@{ value = "AS$($ai.asn): $($ai.asnName)"; source = "asn:$ip" }
                }
            }
            $ptr = Get-PtrRecord $ip
            if ($ptr -ne "") { $claims += [pscustomobject]@{ value = $ptr; source = "ptr:$ip" } }
            # Per-IP Shodan in the domain path too: without it the fix-plan
            # P1 "Shodan exposes open ports" could never fire for a domain
            # target. Get-ShodanHost skips gracefully when no key is set,
            # so no-key users see zero change.
            $sh = Get-ShodanHost $ip
            if ($sh.ok) {
                if ($report.shodan -eq $null) { $report.shodan = $sh }
                if ($sh.org -ne "") { $claims += [pscustomobject]@{ value = $sh.org; source = "shodan:$ip" } }
                if ($sh.ports.Count -gt 0) {
                    $claims += [pscustomobject]@{ value = "Shodan: $($sh.ports.Count) open port(s) ($($sh.ports -join ','))"; source = "shodan:$ip" }
                }
            }
        }
        if ($report.crtsh.ok -and $report.crtsh.count -gt 0) {
            $claims += [pscustomobject]@{ value = "$($report.crtsh.count) certs from $($report.crtsh.issuers.Count) issuers"; source = "certs" }
        }
        if ($report.rdapDomain -ne $null -and $report.rdapDomain.ok) {
            if ($report.rdapDomain.created -ne "") {
                $claims += [pscustomobject]@{ value = "registered $($report.rdapDomain.created)"; source = "rdap-domain" }
            }
            if ($report.rdapDomain.registrar -ne "") {
                $claims += [pscustomobject]@{ value = "registrar: $($report.rdapDomain.registrar)"; source = "rdap-domain" }
            }
        }
        if ($report.takeover -ne $null -and $report.takeover.dangling.Count -gt 0) {
            $claims += [pscustomobject]@{ value = "$($report.takeover.dangling.Count) dangling CNAME(s) — takeover surface"; source = "takeover" }
        }
        if ($report.ctDelta -ne $null -and -not $report.ctDelta.isFirstRun -and $report.ctDelta.newNames.Count -gt 0) {
            $claims += [pscustomobject]@{ value = "$($report.ctDelta.newNames.Count) new cert name(s) since $($report.ctDelta.baselineDate)"; source = "ct-delta" }
        }
        if ($report.mailauth -ne $null -and $report.mailauth.ok -and $report.mailauth.spf.provider -ne "") {
            $claims += [pscustomobject]@{ value = "outbound mail via $($report.mailauth.spf.provider)"; source = "mail-auth" }
        }
    }
    if ($report.urlhaus -ne $null -and $report.urlhaus.ok) {
        $report.threatListed = $report.urlhaus.listed
    }
    if ($script:CoherenceLoaded -and $claims.Count -gt 0) {
        $conv = Measure-AttributionConvergence -claims $claims
        $report.verdict = $conv.verdict
        $report.agreement = $conv.agreement
        $report.breakdown = $conv.breakdown
        # cross-source coherence checks
        if ($report.rdap.ok -and $report.shodan.ok -and
            $report.rdap.org -ne "" -and $report.shodan.org -ne "") {
            try {
                $ea = [pscustomobject]@{ data = @{ rdapOrg = $report.rdap.org } }
                $eb = [pscustomobject]@{ data = @{ asnOrg = $report.shodan.org } }
                $report.coherenceChecks += Test-Coherence -a $ea -b $eb -check "rdap-asn"
                $last = $report.coherenceChecks[$report.coherenceChecks.Count - 1]
                Write-Host "[*] coherence rdap-asn: score=$($last.score) coherent=$($last.coherent)"
            } catch {
                Write-Host "[!] coherence check failed: $($_.Exception.Message)"
            }
        }
        # ASN name (Team Cymru, passive DNS) vs RDAP org
        $asnName = ""
        if ($report.asn -ne $null -and $report.asn.ok) { $asnName = $report.asn.asnName }
        elseif ($asns.Count -gt 0) { $asnName = (@($asns.Values) | Select-Object -First 1).asnName }
        if ($report.rdap.ok -and $report.rdap.org -ne "" -and $asnName -ne "") {
            try {
                $ea = [pscustomobject]@{ data = @{ rdapOrg = $report.rdap.org } }
                $eb = [pscustomobject]@{ data = @{ asnOrg = $asnName } }
                $report.coherenceChecks += Test-Coherence -a $ea -b $eb -check "asn-rdap"
                $last = $report.coherenceChecks[$report.coherenceChecks.Count - 1]
                Write-Host "[*] coherence asn-rdap: score=$($last.score) coherent=$($last.coherent)"
            } catch {
                Write-Host "[!] coherence check failed: $($_.Exception.Message)"
            }
        }
        $hashes = @()
        foreach ($c in $claims) { $hashes += Get-Sha256Hex "$($c.source)=$($c.value)" }
        $conclusion = "$($conv.verdict): $($conv.top) ($($conv.agreement)% agreement, $($claims.Count) sources)"
        if ($report.threatListed) { $conclusion += " [URLHAUS LISTED]" }
        $report.receipt = (New-Receipt -conclusion $conclusion -evidenceHashes $hashes).receipt
        Write-Host "[+] verdict: $($conv.verdict) — $($conv.top) ($($conv.agreement)%)"
        if ($report.threatListed) { Write-Host "[!] threat flag: target is listed on URLhaus" }
    } elseif ($claims.Count -eq 0) {
        Write-Host "[!] no attribution data returned for $($chk.value)"
    }
    # vault-log the report itself
    if ($script:VaultLoaded -and -not [string]::IsNullOrWhiteSpace($script:VaultPath)) {
        try {
            $vault = New-Vault -path $script:VaultPath
            Add-VaultEntry -vault $vault -type "attribution-report" -data @{
                target   = $chk.value
                verdict  = $report.verdict
                claims   = $claims.Count
                threat   = $report.threatListed
                receipt  = "$($report.receipt)"
            } | Out-Null
        } catch {
            Write-Host "[!] report vault log failed: $($_.Exception.Message)"
        }
    }
    return $report
}

function New-SelfExposureFixPlan {
    <#
    THE BETTER-WAY LAW for OSINT: a report on the user's OWN domain/IP is
    not a finished product — it is a punch list. This turns the attribution
    report into concrete exposure-reduction steps with severity order.
    Pass a report object from Get-AttributionReport where $Target is an
    asset the user owns or administers.
    #>
    param([Parameter(Mandatory=$true)]$Report)
    Write-Host "[*] building self-exposure fix plan for $($Report.target)"
    $findings = @()
    # The $add scriptblock RETURNS the finding object; callers collect it
    # with $findings += & $add ... (the sibling-convention battery pattern).
    # Writing to a $script: accumulator inside the scriptblock "worked"
    # but leaked findings across calls and broke reentrancy — a second
    # call in the same session would report the first call's findings too.
    $add = {
        param($sev, $title, $evidence, $steps)
        return [pscustomobject]@{
            severity = $sev; title = $title; evidence = $evidence; steps = @($steps)
        }
    }
    $findings = @()
    # P1: URLhaus listing = active compromise indicator
    if ($Report.threatListed) {
        $findings += & $add "P1" "Host is listed on URLhaus (serving malware)" `
            "urlhaus.listed=true, $($Report.urlhaus.urlCount) malicious URL(s)" @(
            "Take the host offline or firewall it immediately — it is serving malware now.",
            "Rebuild from a known-clean image; do not try to clean in place.",
            "Rotate every credential that touched the host.",
            "Re-run Get-UrlhausHost after rebuild to confirm delisting."
        )
    }
    # P1: Shodan-visible open ports on own IP
    if ($Report.shodan -ne $null -and $Report.shodan.ok -and $Report.shodan.ports.Count -gt 0) {
        $findings += & $add "P1" "Shodan exposes $($Report.shodan.ports.Count) open port(s) to the whole internet" `
            ("ports: " + ($Report.shodan.ports -join ", ")) @(
            "Close every port that does not need to face the internet (firewall / security group).",
            "Put admin ports (SSH/RDP/panels) behind a VPN; never expose them publicly.",
            "Request Shodan removal after closing: shodan.io/labs/request-removal (takes days — closing first is what matters)."
        )
    }
    # P2: registrant identity in RDAP looks like a personal name
    $org = ""
    if ($Report.rdap -ne $null) { $org = $Report.rdap.org }
    if ($org -ne "" -and $org -notmatch '(?i)\b(inc|llc|ltd|corp|corporation|gmbh|pty|sarl|bv|ab|sa|sas|holdings|group|network|systems|hosting|cloud|telecom|communications|bank|university|government|ministry)\b' -and $org -match '^\S+\s+\S+') {
        $findings += & $add "P2" "Registrant identity exposed in public RDAP" `
            "rdap.org='$org'" @(
            "Enable WHOIS/RDAP privacy (redacted-for-privacy) at the registrar — free at most registrars.",
            "Replace personal contact data with a role address (e.g. hostmaster@).",
            "Check the DNS SOA contact too (Get-DnsRecords shows it); use a role address there as well."
        )
    }
    # P2: certificate sprawl
    if ($Report.crtsh -ne $null -and $Report.crtsh.ok -and $Report.crtsh.count -gt 20) {
        $findings += & $add "P2" "Certificate sprawl: $($Report.crtsh.count) public subdomains in CT logs" `
            "$($Report.crtsh.count) names, latest $($Report.crtsh.latest)" @(
            "Consolidate to one wildcard certificate (*.domain) instead of per-subdomain certs.",
            "Decommission dead subdomains — every CT-logged name is a recon lead.",
            "Revoke certificates for retired hosts."
        )
    }
    # P1: expired certificates — browsers hard-fail, visitors bounce
    if ($Report.certExpiry -ne $null -and $Report.certExpiry.expired.Count -gt 0) {
        $top3 = ($Report.certExpiry.expired | Select-Object -First 3 | ForEach-Object { "$($_.name) (expired $($_.not_after))" }) -join "; "
        $findings += & $add "P1" "$($Report.certExpiry.expired.Count) certificate(s) EXPIRED" `
            $top3 @(
            "Renew every expired certificate immediately — this is user-facing breakage.",
            "Move renewals to auto-renew (ACME/LetsEncrypt) so this class dies forever.",
            "Set the CT delta monitor baseline so next expiry shows up before it lapses."
        )
    }
    # P2: certs expiring within 30 days
    if ($Report.certExpiry -ne $null -and $Report.certExpiry.expiringSoon.Count -gt 0) {
        $top3 = ($Report.certExpiry.expiringSoon | Select-Object -First 3 | ForEach-Object { "$($_.name) ($($_.daysLeft)d left)" }) -join "; "
        $findings += & $add "P2" "$($Report.certExpiry.expiringSoon.Count) certificate(s) expire within 30 days" `
            $top3 @(
            "Renew now, not on day 29 — revocation and propagation eat your margin.",
            "Consolidate to wildcard + auto-renew to stop counting days forever."
        )
    }
    # P1: dangling CNAMEs = subdomain takeover surface
    if ($Report.takeover -ne $null -and $Report.takeover.dangling.Count -gt 0) {
        $top3 = ($Report.takeover.dangling | Select-Object -First 3 | ForEach-Object { "$($_.name) -> $($_.cnameTarget)" }) -join "; "
        $findings += & $add "P1" "$($Report.takeover.dangling.Count) dangling CNAME(s) — takeover surface" `
            $top3 @(
            "Remove each dangling DNS record now, or reclaim the service it points to.",
            "Dangling CNAMEs are the #1 passive-recon money finding ($500-$3,000 per takeover).",
            "Audit the full list in the report JSON — the fix plan shows only the first 3."
        )
    }
    # P2: fingerprint-matched CNAMEs need manual verification (in scope only)
    if ($Report.takeover -ne $null -and $Report.takeover.fingerprintMatches.Count -gt 0) {
        $top3 = ($Report.takeover.fingerprintMatches | Select-Object -First 3 | ForEach-Object { "$($_.name) -> $($_.service)" }) -join "; "
        $findings += & $add "P2" "$($Report.takeover.fingerprintMatches.Count) CNAME(s) point at claimable services — verify manually" `
            $top3 @(
            "For each, check whether the service account still owns it (provider dashboard, not automation).",
            "If unclaimed: claim it or delete the DNS record. Verification needs your own account + scope authorization."
        )
    }
    # P1: domain registration expiring soon
    if ($Report.rdapDomain -ne $null -and $Report.rdapDomain.ok -and $Report.rdapDomain.daysToExpiry -ne $null -and $Report.rdapDomain.daysToExpiry -le 30) {
        $findings += & $add "P1" "Domain expires in $($Report.rdapDomain.daysToExpiry) day(s) — $($Report.rdapDomain.expires)" `
            "registrar: $($Report.rdapDomain.registrar)" @(
            "Renew the domain NOW — an expired domain is hijackable the day it drops.",
            "Turn on auto-renew + registry lock (clientTransferProhibited) at the registrar."
        )
    }
    # P2: DNSSEC not signed
    if ($Report.dnssec -ne $null -and $Report.dnssec.state -eq "unsigned") {
        $findings += & $add "P2" "DNSSEC not signed — DNS answers are forgeable" `
            ($Report.dnssec.evidence -join "; ") @(
            "Enable DNSSEC at the DNS host (Cloudflare/Route53 do it in one toggle).",
            "Publish the DS record at the registrar — both halves are required.",
            "Re-run Get-DnssecStatus after the DS propagates (up to 48h)."
        )
    }
    # P3: no CAA record
    if ($Report.caa -ne $null -and $Report.caa.ok -and -not $Report.caa.present) {
        $findings += & $add "P3" "No CAA record — any CA on earth can issue for this domain" `
            "CAA query returned no records" @(
            'Publish a CAA record naming only your CA, e.g.: 0 issue "letsencrypt.org".',
            "Add issuewild for the wildcard policy too, or forbid wildcards with issuewild ';'."
        )
    }
    # P1: SPF +all authorizes the entire internet to spoof the domain
    if ($Report.mailauth -ne $null -and $Report.mailauth.ok -and $Report.mailauth.spf.verdict -eq "dangerous-plusall") {
        $findings += & $add "P1" "SPF authorizes the ENTIRE internet (+all) — spoofing is policy-blessed" `
            "SPF: $($Report.mailauth.spf.raw)" @(
            "Replace +all with -all (hard fail) immediately — this single change kills open spoofing.",
            "Keep only the includes/IPs you actually send from; re-test delivery before going -all.",
            "Read the DMARC aggregate reports (rua) for a week to confirm legitimate senders still pass."
        )
    }
    # P2: no DMARC at all
    if ($Report.mailauth -ne $null -and $Report.mailauth.ok -and -not $Report.mailauth.dmarc.present) {
        $dom = $Report.mailauth.domain
        $findings += & $add "P2" "No DMARC record — spoofed mail from this domain is invisible to receivers" `
            "no _dmarc.$dom TXT" @(
            "Publish _dmarc.$dom TXT `"v=DMARC1; p=none; rua=mailto:dmarc@$dom`".",
            "Watch the aggregate reports for 2 weeks, then move p=none -> quarantine -> reject.",
            "Set pct=100 only after quarantine is clean — a partial pct leaves the hole open."
        )
    }
    # P2: DMARC p=none (monitor-only)
    if ($Report.mailauth -ne $null -and $Report.mailauth.ok -and $Report.mailauth.dmarc.present -and $Report.mailauth.dmarc.policy -eq "none") {
        $findings += & $add "P2" "DMARC p=none — monitor-only, receivers enforce nothing" `
            "DMARC: $($Report.mailauth.dmarc.raw)" @(
            "Move to p=quarantine once aggregate reports show legitimate mail passing.",
            "Graduate to p=reject after 2 clean weeks at quarantine — that is the enforced end state."
        )
    }
    # P3: DMARC p=quarantine — good, but spoofed mail still lands in inboxes
    if ($Report.mailauth -ne $null -and $Report.mailauth.ok -and $Report.mailauth.dmarc.present -and $Report.mailauth.dmarc.policy -eq "quarantine") {
        $findings += & $add "P3" "DMARC p=quarantine — enforced, but spoofed mail still reaches inboxes" `
            "DMARC: $($Report.mailauth.dmarc.raw)" @(
            "Move to p=reject after 2 clean weeks — quarantine is the training wheels.",
            "Keep rua reporting on so a provider change shows up in the reports, not in a breach."
        )
    }
    # P3: no SPF record
    if ($Report.mailauth -ne $null -and $Report.mailauth.ok -and -not $Report.mailauth.spf.present) {
        $findings += & $add "P3" "No SPF record — anyone can send mail as this domain" `
            "no v=spf1 TXT on the apex" @(
            "Publish e.g. v=spf1 include:_spf.google.com -all (use YOUR provider's include).",
            "End with -all, not ~all — softfail still delivers spoofed mail.",
            "Count DNS lookups: SPF dies after 10 — flatten nested includes if you exceed it."
        )
    }
    # P3: DKIM selectors found at none of the common names
    if ($Report.mailauth -ne $null -and $Report.mailauth.ok -and $Report.mailauth.dkimSelectorsFound.Count -eq 0) {
        $findings += & $add "P3" "No DKIM signing keys at common selectors — confirm signing is ON" `
            ("probed: " + ($Report.mailauth.dkimChecked -join ", ")) @(
            "In the mail provider console (Google Workspace / Microsoft 365), enable DKIM and publish the given TXT.",
            "DKIM without DMARC does nothing receivers act on — pair it with the DMARC finding above."
        )
    }
    # P2: missing HSTS
    if ($Report.httpFp -ne $null -and $Report.httpFp.ok -and $Report.httpFp.missingSecurityHeaders -contains "strict-transport-security") {
        $findings += & $add "P2" "HSTS header missing — first-visit downgrade attacks work" `
            "https://$($Report.httpFp.domain) served without Strict-Transport-Security" @(
            "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
            "After 6 clean months, submit to the HSTS preload list."
        )
    }
    # P3: X-Powered-By version leak
    if ($Report.httpFp -ne $null -and $Report.httpFp.ok -and $Report.httpFp.poweredBy -ne "") {
        $findings += & $add "P3" "Server tech leaked in headers: $($Report.httpFp.poweredBy)" `
            "X-Powered-By: $($Report.httpFp.poweredBy)" @(
            "Strip X-Powered-By and version banners — attackers inventory versions first.",
            "If Server reveals a version, normalize it to the product name only."
        )
    }
    # P2: mail provider fingerprint via MX
    if ($Report.dns -ne $null -and $Report.dns.MX.Count -gt 0) {
        $findings += & $add "P3" "Mail provider fingerprinted via public MX" `
            ("MX: " + ($Report.dns.MX -join "; ")) @(
            "Decide if the MX target is acceptable public knowledge (it usually is).",
            "If the mail server runs on the same host, move it behind a dedicated mail gateway.",
            "SPF/DKIM/DMARC state is graded as its own findings above — apply those, not just this one."
        )
    }
    # P3: residential/dynamic ASN hosting services
    if ($Report.asn -ne $null -and $Report.asn.ok -and $Report.asn.asnName -ne "") {
        $findings += & $add "P3" "Services hosted on AS$($Report.asn.asn) ($($Report.asn.asnName))" `
            "prefix $($Report.asn.prefix), $($Report.asn.country)" @(
            "If this is a home/residential ASN, do not host public services on it — use a VPS.",
            "Confirm the prefix is actually yours (BGP hijack check: compare with your provider)."
        )
    }
    if ($findings.Count -eq 0) {
        $findings += & $add "P3" "No high-signal exposure found in this report" `
            "no URLhaus listing, no Shodan ports, no personal registrant, cert count within norms" @(
            "Re-run monthly — exposure drifts as certs and records change.",
            "Add the asset to the broker-eradicator schedule so relistings are caught."
        )
    }
    $plan = [pscustomobject]@{
        target = $Report.target; findings = $findings;
        p1 = @($findings | Where-Object { $_.severity -eq "P1" }).Count;
        p2 = @($findings | Where-Object { $_.severity -eq "P2" }).Count;
        p3 = @($findings | Where-Object { $_.severity -eq "P3" }).Count
    }
    Write-Host "[+] fix plan: P1=$($plan.p1) P2=$($plan.p2) P3=$($plan.p3)"
    return $plan
}

function Export-AttributionReport {
    <#
    Writes the attribution report as JSON + human-readable txt, with a
    SHA-256 sidecar so the file can be proven unaltered later.
    #>
    param(
        [Parameter(Mandatory=$true)]$Report,
        [string]$OutDir = "."
    )
    if (-not (Test-Path $OutDir)) {
        try { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
        catch { Write-Host "[!] cannot create $OutDir : $($_.Exception.Message)"; return $null }
    }
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $safe = ($Report.target -replace '[^a-zA-Z0-9.\-]', '_')
    $jsonPath = Join-Path $OutDir "attribution-$safe-$stamp.json"
    $txtPath = Join-Path $OutDir "attribution-$safe-$stamp.txt"
    try {
        $Report | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
        $lines = @()
        $lines += "ATTRIBUTION REPORT — $($Report.target)"
        $lines += "generated (UTC): $((Get-Date).ToUniversalTime().ToString('o'))"
        $lines += "verdict: $($Report.verdict)  agreement: $($Report.agreement)%"
        $lines += "threat listed (URLhaus): $($Report.threatListed)"
        $lines += ""
        if ($Report.rdap)   { $lines += "RDAP   : org='$($Report.rdap.org)' cidr='$($Report.rdap.cidr)' country='$($Report.rdap.country)'" }
        if ($Report.asn)    { $lines += "ASN    : AS$($Report.asn.asn) '$($Report.asn.asnName)' $($Report.asn.prefix) $($Report.asn.country)" }
        if ($Report.shodan) { $lines += "SHODAN : org='$($Report.shodan.org)' asn='$($Report.shodan.asn)' ports=$($Report.shodan.ports -join ',')" }
        if ($Report.ptr -ne "") { $lines += "PTR    : $($Report.ptr)" }
        if ($Report.dns) {
            $lines += "DNS A  : $($Report.dns.A -join ', ')"
            $lines += "DNS MX : $($Report.dns.MX -join '; ')"
            $lines += "DNS NS : $($Report.dns.NS -join '; ')"
            $lines += "DNS TXT: $($Report.dns.TXT -join ' | ')"
        }
        if ($Report.crtsh)  { $lines += "CRTSH  : $($Report.crtsh.count) names, issuers=$($Report.crtsh.issuers -join '; '), latest=$($Report.crtsh.latest)" }
        if ($Report.rdapDomain -and $Report.rdapDomain.ok) {
            $lines += "DOMAIN : registrar='$($Report.rdapDomain.registrar)' created=$($Report.rdapDomain.created) expires=$($Report.rdapDomain.expires) ($($Report.rdapDomain.daysToExpiry)d)"
        }
        if ($Report.dnssec -and $Report.dnssec.ok) {
            $lines += "DNSSEC : $($Report.dnssec.state) [$($Report.dnssec.evidence -join '; ')]"
        }
        if ($Report.caa -and $Report.caa.ok) {
            if ($Report.caa.present) { $lines += "CAA    : present: $($Report.caa.records -join ' | ')" }
            else { $lines += "CAA    : MISSING" }
        }
        if ($Report.mailauth -and $Report.mailauth.ok) {
            $ma = $Report.mailauth
            $prov = ""
            if ($ma.spf.provider -ne "") { $prov = " ($($ma.spf.provider))" }
            $lines += "SPF    : $($ma.spf.verdict)$prov includes=$($ma.spf.includes -join ',')"
            if ($ma.dmarc.present) { $lines += "DMARC  : p=$($ma.dmarc.policy) sp=$($ma.dmarc.subPolicy) pct=$($ma.dmarc.pct) rua=$($ma.dmarc.rua)" }
            else { $lines += "DMARC  : MISSING" }
            if ($ma.dkimSelectorsFound.Count -gt 0) { $lines += "DKIM   : signing keys at $($ma.dkimSelectorsFound -join ', ')" }
            else { $lines += "DKIM   : no keys at common selectors" }
        }
        if ($Report.certExpiry -and $Report.certExpiry.ok) {
            $lines += "CERTS  : EXPIRED=$($Report.certExpiry.expired.Count) EXPIRING-SOON=$($Report.certExpiry.expiringSoon.Count) OK=$($Report.certExpiry.okCount)"
        }
        if ($Report.takeover -and $Report.takeover.ok -and @($Report.takeover.dangling).Count -gt 0) {
            $lines += "TAKEOVER DANGLING: " + ((@($Report.takeover.dangling) | ForEach-Object { "$($_.name)->$($_.cnameTarget)" }) -join '; ')
        }
        if ($Report.takeover -and $Report.takeover.ok -and @($Report.takeover.fingerprintMatches).Count -gt 0) {
            $lines += "TAKEOVER FINGERPRINT: " + ((@($Report.takeover.fingerprintMatches) | ForEach-Object { "$($_.name)->$($_.service)" }) -join '; ')
        }
        if ($Report.ctDelta -and $Report.ctDelta.ok) {
            if ($Report.ctDelta.isFirstRun) { $lines += "CTDELTA: baseline created ($($Report.ctDelta.total) names)" }
            elseif (@($Report.ctDelta.newNames).Count -gt 0) { $lines += "CTDELTA: NEW since $($Report.ctDelta.baselineDate): " + (@($Report.ctDelta.newNames) -join ', ') }
            else { $lines += "CTDELTA: no new names since $($Report.ctDelta.baselineDate)" }
        }
        if ($Report.httpFp -and $Report.httpFp.ok) {
            $lines += "HTTP   : $($Report.httpFp.statusCode) server='$($Report.httpFp.server)' poweredBy='$($Report.httpFp.poweredBy)' edge='$($Report.httpFp.edgeHint)'"
            $lines += "HTTPSEC: missing=$($Report.httpFp.missingSecurityHeaders -join ',')"
        }
        if ($Report.urlhaus -and $Report.urlhaus.listed) {
            $lines += "URLHAUS: LISTED — $($Report.urlhaus.urlCount) malicious URL(s)"
        }
        $lines += ""
        $lines += "coherence checks:"
        foreach ($c in @($Report.coherenceChecks)) {
            $lines += "  $($c.check): score=$($c.score) coherent=$($c.coherent)"
        }
        $lines += ""
        $lines += "receipt: $($Report.receipt)"
        $lines | Set-Content -Path $txtPath -Encoding UTF8
        $hash = (Get-FileHash -Path $jsonPath -Algorithm SHA256).Hash
        $shaPath = "$jsonPath.sha256"
        "$hash  $(Split-Path -Leaf $jsonPath)" | Set-Content -Path $shaPath -Encoding UTF8
        Write-Host "[+] exported: $jsonPath"
        Write-Host "[+]           $txtPath"
        Write-Host "[+] sha256: $hash"
        New-OsintLog -QueryType "export" -Target $Report.target -Result ([pscustomobject]@{ ok = $true })
        return [pscustomobject]@{ json = $jsonPath; txt = $txtPath; sha256 = $shaPath; hash = $hash }
    } catch {
        Write-Host "[!] export failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-RdapDomain {
    <#
    RDAP registration data for a DOMAIN (rdap.org/domain/...) — passive,
    no key. Registrar, creation/expiry dates with days-to-expiry, name
    servers, registry status flags, and the registry's DNSSEC delegation
    flag (secureDNS.delegationSigned). An expiring-soon domain is a
    hijack risk; that is a P1 in the fix plan.
    #>
    param([Parameter(Mandatory=$true)][string]$Domain)
    $chk = Test-OsintInput $Domain
    $out = [pscustomobject]@{
        ok = $false; domain = $Domain.Trim().ToLower(); registrar = "";
        created = ""; expires = ""; daysToExpiry = $null; nameservers = @();
        status = @(); dnssecDelegationSigned = $false; dsKeyTag = "";
        source = "rdap"; error = ""
    }
    if (-not $chk.valid -or $chk.kind -ne "domain") {
        $out.error = "invalid-domain: $($chk.note)"
        Write-Host "[!] RDAP-domain refused: '$Domain' is not a domain name"
        return $out
    }
    $d = $chk.value
    $out.domain = $d
    try {
        Write-Host "[*] RDAP domain $d"
        $r = Invoke-OsintRest -Uri "https://rdap.org/domain/$d" -TimeoutSec 15
        if (-not $r.ok) { throw $r.error }
        $body = $r.response
        foreach ($ev in @($body.events)) {
            $action = "$($ev.eventAction)".ToLower()
            if ($action -eq "registration") { $out.created = "$($ev.eventDate)" }
            elseif ($action -eq "expiration") { $out.expires = "$($ev.eventDate)" }
        }
        if ($out.expires -ne "") {
            # ConvertTo-OsintUtcDate reads zone-less strings as UTC so the
            # count is machine-independent (local-offset shifts are the
            # coherence-core v1.4 bug class).
            $expDt = ConvertTo-OsintUtcDate $out.expires
            if ($expDt -ne $null) {
                $out.daysToExpiry = [int](($expDt - (Get-Date).ToUniversalTime()).TotalDays)
            }
        }
        foreach ($ns in @($body.nameservers)) {
            if ($ns.ldhName) { $out.nameservers += "$($ns.ldhName)" }
        }
        if ($body.status) { $out.status = @($body.status | ForEach-Object { "$_" }) }
        # registrar: prefer vcard "fn", fall back to handle
        foreach ($ent in @($body.entities)) {
            if ($null -eq $ent) { continue }
            $roles = @($ent.roles)
            if ($roles -notcontains "registrar") { continue }
            foreach ($v in @($ent.vcardArray)) {
                if ($v -is [System.Collections.IList] -and $v.Count -gt 1) {
                    foreach ($prop in @($v[1])) {
                        if ($prop -is [System.Collections.IList] -and $prop.Count -ge 4 -and
                            "$($prop[0])" -eq "fn" -and $out.registrar -eq "") {
                            $out.registrar = "$($prop[3])"
                        }
                    }
                }
            }
            if ($out.registrar -eq "" -and $ent.handle) { $out.registrar = "$($ent.handle)" }
            break
        }
        if ($null -ne $body.secureDNS) {
            $sd = $body.secureDNS
            if ("$($sd.delegationSigned)".ToLower() -eq "true") {
                $out.dnssecDelegationSigned = $true
            }
            if ($sd.dsData -and @($sd.dsData).Count -gt 0) {
                $out.dsKeyTag = "$((@($sd.dsData)[0]).keyTag)"
            }
        }
        $out.ok = $true
        Write-Host "[+] RDAP domain ok: registrar='$($out.registrar)' created=$($out.created) expires=$($out.expires) ($($out.daysToExpiry) days)"
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] RDAP domain failed for $d : $($out.error)"
    }
    New-OsintLog -QueryType "rdap-domain" -Target $d -Result $out
    return $out
}

function Get-DnssecStatus {
    <#
    Passive DNSSEC presence check using the machine's own resolver plus the
    registry's delegation flag from RDAP (when a Get-RdapDomain object is
    passed). Three states, honestly labeled: signed (positive evidence),
    unsigned (queries succeeded, no RRSIG/DNSKEY), unknown (query error —
    resolver may be stripping DNSSEC, never claim unsigned on an error).
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Domain,
        $RdapDomain = $null
    )
    $chk = Test-OsintInput $Domain
    $out = [pscustomobject]@{
        ok = $false; domain = $Domain; state = "unknown";
        evidence = @(); source = "dns"; error = ""
    }
    if (-not $chk.valid -or $chk.kind -ne "domain") {
        $out.error = "invalid-domain: $($chk.note)"
        return $out
    }
    $d = $chk.value
    $out.domain = $d
    $sawReply = $false
    foreach ($qtype in @("RRSIG", "DNSKEY")) {
        try {
            $r = Resolve-DnsName -Name $d -Type $qtype -ErrorAction SilentlyContinue
            if ($r) { $sawReply = $true }
            foreach ($rec in @($r)) {
                $props = $rec.PSObject.Properties.Name
                if ($qtype -eq "RRSIG" -and ($props -contains "TypeCovered" -or $props -contains "Type")) {
                    $out.state = "signed"; $out.evidence += "RRSIG present on apex"
                }
                if ($qtype -eq "DNSKEY" -and $props -contains "KeyTag") {
                    $out.state = "signed"; $out.evidence += "DNSKEY present on apex"
                }
            }
        } catch { }
    }
    if ($RdapDomain -ne $null -and $RdapDomain.dnssecDelegationSigned) {
        $out.state = "signed"
        $out.evidence += "registry delegationSigned (RDAP secureDNS)"
        if ($RdapDomain.dsKeyTag -ne "") { $out.evidence += "DS keyTag $($RdapDomain.dsKeyTag)" }
    }
    if ($out.state -eq "unknown" -and $sawReply) {
        $out.state = "unsigned"
        $out.evidence += "resolver answered, no RRSIG/DNSKEY on apex"
    }
    $out.ok = ($out.state -ne "unknown")
    Write-Host "[*] DNSSEC $d : $($out.state)"
    New-OsintLog -QueryType "dnssec" -Target $d -Result $out
    return $out
}

function Get-CaaRecords {
    <#
    CAA (RFC 8659) presence check. No CAA record = any CA on earth can
    issue for this name — a real, fixable risk (P3). Passive resolver query.
    #>
    param([Parameter(Mandatory=$true)][string]$Domain)
    $chk = Test-OsintInput $Domain
    $out = [pscustomobject]@{
        ok = $false; domain = $Domain; present = $false; records = @(); source = "dns"; error = ""
    }
    if (-not $chk.valid -or $chk.kind -ne "domain") {
        $out.error = "invalid-domain: $($chk.note)"
        return $out
    }
    $d = $chk.value
    $out.domain = $d
    $got = $null
    foreach ($t in @("CAA", 257)) {
        try {
            $got = Resolve-DnsName -Name $d -Type $t -ErrorAction SilentlyContinue
            if ($got) { break }
        } catch { }
    }
    foreach ($rec in @($got)) {
        $props = $rec.PSObject.Properties.Name
        $tag = ""; $val = ""
        if ($props -contains "Tag") { $tag = "$($rec.Tag)" }
        if ($props -contains "Data") { $val = "$($rec.Data)" }
        elseif ($props -contains "RecordData") { $val = "$($rec.RecordData)" }
        if ($tag -ne "" -or $val -ne "") { $out.records += "$tag $val".Trim() }
    }
    $out.ok = $true
    $out.present = ($out.records.Count -gt 0)
    Write-Host "[*] CAA $d : $(if ($out.present) { 'present (' + $out.records.Count + ')' } else { 'MISSING' })"
    New-OsintLog -QueryType "caa" -Target $d -Result $out
    return $out
}

function ConvertFrom-SpfRecord {
    <#
    Pure logic: one SPF TXT string -> structured policy. Verdicts:
    none (no SPF), strict (-all), softfail (~all), neutral (?all),
    dangerous-plusall (+all or bare all — authorizes the whole internet),
    no-policy (record exists but names no "all" mechanism — malformed).
    Bare "all" means +all per RFC 7208 section 4.6.4.
    #>
    param([Parameter(Mandatory=$true)][string]$Txt)
    $t = $Txt.Trim()
    $out = [pscustomobject]@{
        present = $false; raw = $t; mechanisms = @(); qualifier = "";
        includes = @(); verdict = "none"; provider = ""
    }
    if ($t -notmatch '^(?i)v=spf1\b') { return $out }
    $out.present = $true
    $tokens = @($t -split '\s+' | Where-Object { $_ -ne "" })
    $rest = @()
    if ($tokens.Count -gt 1) { $rest = $tokens[1..($tokens.Count - 1)] }
    foreach ($tok in $rest) {
        $mech = $tok; $q = ""
        if ($mech -match '^([+\-~?])(.+)$') { $q = $Matches[1]; $mech = $Matches[2] }
        if ($q -eq "" -and $mech -eq "all") { $q = "+" }  # bare all = +all
        $out.mechanisms += "$q$mech"
        if ($mech -like "include:*") { $out.includes += $mech.Substring(8) }
        if ($mech -eq "all") { $out.qualifier = $q }
    }
    switch ($out.qualifier) {
        "+" { $out.verdict = "dangerous-plusall" }
        "-" { $out.verdict = "strict" }
        "~" { $out.verdict = "softfail" }
        "?" { $out.verdict = "neutral" }
        default { $out.verdict = "no-policy" }
    }
    foreach ($inc in $out.includes) {
        foreach ($m in $script:MailProviderMap) {
            if ($inc -like "*$($m.include)*") { $out.provider = $m.provider; break }
        }
        if ($out.provider -ne "") { break }
    }
    return $out
}

function ConvertFrom-DmarcRecord {
    <#
    Pure logic: one DMARC TXT string -> structured policy. Absence of the
    record (present=$false) is itself the finding the fix plan grades.
    #>
    param([Parameter(Mandatory=$true)][string]$Txt)
    $t = $Txt.Trim()
    $out = [pscustomobject]@{
        present = $false; raw = $t; policy = ""; subPolicy = "";
        pct = ""; rua = ""; ruf = ""; adkim = ""; aspf = ""
    }
    if ($t -notmatch '^(?i)v=DMARC1\b') { return $out }
    $out.present = $true
    foreach ($pair in ($t -split ';')) {
        $kv = $pair -split '=', 2
        if ($kv.Count -ne 2) { continue }
        $k = $kv[0].Trim().ToLower(); $v = $kv[1].Trim()
        switch ($k) {
            "p"     { $out.policy = $v.ToLower() }
            "sp"    { $out.subPolicy = $v.ToLower() }
            "pct"   { $out.pct = $v }
            "rua"   { $out.rua = $v }
            "ruf"   { $out.ruf = $v }
            "adkim" { $out.adkim = $v.ToLower() }
            "aspf"  { $out.aspf = $v.ToLower() }
        }
    }
    return $out
}

function Test-DkimSelectorRecord {
    <#
    Pure logic: does a _domainkey TXT look like a DKIM signing key?
    Accepts RFC 6376 "v=DKIM1" and legacy bare "k=rsa; p=..." forms.
    #>
    param([Parameter(Mandatory=$true)][string]$Txt)
    $t = $Txt.Trim()
    if ($t -match '(?i)v=DKIM1') { return $true }
    if ($t -match '(?i)\bk=rsa\b' -and $t -match '(?i)\bp\s*=') { return $true }
    return $false
}

function Get-MailAuthRecords {
    <#
    Mail authentication posture: SPF (apex TXT), DMARC (_dmarc TXT), DKIM
    (selector probing at _domainkey). All passive resolver queries, no key.
    The piece the old fix plan referenced but never computed — now real.
    #>
    param([Parameter(Mandatory=$true)][string]$Domain)
    $chk = Test-OsintInput $Domain
    $out = [pscustomobject]@{
        ok = $false; domain = $Domain; spf = (ConvertFrom-SpfRecord "x");
        dmarc = (ConvertFrom-DmarcRecord "x"); dkimSelectorsFound = @();
        dkimChecked = @(); source = "dns"; error = ""
    }
    if (-not $chk.valid -or $chk.kind -ne "domain") {
        $out.error = "invalid-domain: $($chk.note)"
        return $out
    }
    $d = $chk.value
    $out.domain = $d
    try {
        $txts = Resolve-DnsName -Name $d -Type TXT -ErrorAction SilentlyContinue
        foreach ($rec in @($txts)) {
            $s = ($rec.Strings -join " ")
            if ($s -match '^(?i)v=spf1\b') { $out.spf = ConvertFrom-SpfRecord $s; break }
        }
    } catch { }
    try {
        $dm = Resolve-DnsName -Name "_dmarc.$d" -Type TXT -ErrorAction SilentlyContinue
        foreach ($rec in @($dm)) {
            $s = ($rec.Strings -join " ")
            if ($s -match '^(?i)v=DMARC1\b') { $out.dmarc = ConvertFrom-DmarcRecord $s; break }
        }
    } catch { }
    foreach ($sel in $script:DkimSelectors) {
        $out.dkimChecked += $sel
        try {
            $kr = Resolve-DnsName -Name "$sel._domainkey.$d" -Type TXT -ErrorAction SilentlyContinue
            foreach ($rec in @($kr)) {
                if (Test-DkimSelectorRecord ($rec.Strings -join " ")) {
                    $out.dkimSelectorsFound += $sel
                    break
                }
            }
        } catch { }
    }
    $out.ok = $true
    Write-Host "[*] mail-auth $d : spf=$($out.spf.verdict) dmarc=$($out.dmarc.policy) dkim-selectors=$($out.dkimSelectorsFound.Count)/$($out.dkimChecked.Count)"
    New-OsintLog -QueryType "mail-auth" -Target $d -Result $out
    return $out
}

function Get-CrtExpiryReport {
    <#
    Classifies every crt.sh cert by expiry: EXPIRED (serving or recently
    served an expired cert — browsers hard-fail, visitors bounce),
    EXPIRING-SOON (<=30 days, renew now), OK. Pure parsing of the crt.sh
    rows Get-CrtSh already fetched — zero new queries.
    #>
    param(
        [Parameter(Mandatory=$true)]$CrtSh,
        [int]$SoonDays = 30
    )
    $now = (Get-Date).ToUniversalTime()
    $limit = $now.AddDays($SoonDays)
    $exp = @(); $soon = @()
    foreach ($e in @($CrtSh.expiries)) {
        $dt = $null
        if (-not [datetime]::TryParse("$($e.not_after)", [ref]$dt)) { continue }
        if ($dt -lt $now) {
            $exp += [pscustomobject]@{ name = $e.name; not_after = "$($e.not_after)" }
        } elseif ($dt -lt $limit) {
            $soon += [pscustomobject]@{ name = $e.name; not_after = "$($e.not_after)"; daysLeft = [int](($dt - $now).TotalDays) }
        }
    }
    $seen = @{}
    foreach ($c in @($exp + $soon)) { $seen[$c.name] = $true }
    $rep = [pscustomobject]@{
        ok = $CrtSh.ok; domain = $CrtSh.domain; totalCerts = $CrtSh.count;
        expired = @($exp | Sort-Object not_after); expiringSoon = @($soon | Sort-Object daysLeft);
        okCount = $CrtSh.count - $seen.Count
    }
    Write-Host "[*] cert expiry for $($CrtSh.domain): EXPIRED=$($rep.expired.Count) EXPIRING-SOON(<=$SoonDays`d)=$($rep.expiringSoon.Count) OK=$($rep.okCount)"
    return $rep
}

$script:TakeoverFingerprints = @(
    @{ pattern = "*.github.io";          service = "GitHub Pages" },
    @{ pattern = "*.herokuapp.com";      service = "Heroku" },
    @{ pattern = "*.amazonaws.com";      service = "AWS S3 / ELB" },
    @{ pattern = "*.azurewebsites.net";  service = "Azure Web Apps" },
    @{ pattern = "*.blob.core.windows.net"; service = "Azure Blob Storage" },
    @{ pattern = "*.cloudapp.net";       service = "Azure Cloud Service" },
    @{ pattern = "*.myshopify.com";      service = "Shopify" },
    @{ pattern = "*.netlify.app";        service = "Netlify" },
    @{ pattern = "*.vercel.app";         service = "Vercel" },
    @{ pattern = "*.pantheonsite.io";    service = "Pantheon" },
    @{ pattern = "*.tumblr.com";         service = "Tumblr" },
    @{ pattern = "*.bitbucket.io";       service = "Bitbucket Pages" },
    @{ pattern = "*.wordpress.com";      service = "WordPress.com" },
    @{ pattern = "*.squarespace.com";    service = "Squarespace" },
    @{ pattern = "*.unbouncepages.com";  service = "Unbounce" },
    @{ pattern = "*.instapage.com";      service = "Instapage" },
    @{ pattern = "*.zendesk.com";        service = "Zendesk" },
    @{ pattern = "*.freshdesk.com";      service = "Freshdesk" },
    @{ pattern = "*.helpjuice.com";      service = "Helpjuice" },
    @{ pattern = "*.ghost.io";           service = "Ghost" },
    @{ pattern = "*.surge.sh";           service = "Surge.sh" },
    @{ pattern = "*.strikinglydns.com";  service = "Strikingly" },
    @{ pattern = "*.intercom-mail.com";  service = "Intercom" },
    @{ pattern = "*.landingi.com";       service = "Landingi" },
    @{ pattern = "*.tilda.ws";           service = "Tilda" },
    @{ pattern = "*.cargocollective.com"; service = "Cargo" }
)

# Common DKIM selectors to probe: <selector>._domainkey.<domain> TXT.
# Best-effort — absence proves nothing (custom selectors exist), but
# presence confirms signing is on. All passive resolver queries.
$script:DkimSelectors = @(
    "selector1", "selector2",    # Microsoft 365
    "google",                   # Google Workspace
    "default", "mail", "email", "dkim",   # generic
    "k1", "k2",                 # older generic
    "mxvault"                   # generic relay
)

# SPF "include:" mechanisms fingerprinted to the mail provider — a real
# attribution signal: the provider behind a domain's outbound mail.
$script:MailProviderMap = @(
    @{ include = "spf.protection.outlook.com"; provider = "Microsoft 365" },
    @{ include = "_spf.google.com";             provider = "Google Workspace" },
    @{ include = "_spf.mailgun.org";            provider = "Mailgun" },
    @{ include = "sendgrid.net";                provider = "SendGrid" },
    @{ include = "amazonses.com";               provider = "Amazon SES" },
    @{ include = "spf.mandrillapp.com";         provider = "Mailchimp (Mandrill)" },
    @{ include = "servers.mcsv.net";            provider = "Mailchimp" },
    @{ include = "_spf.elasticemail.com";       provider = "Elastic Email" },
    @{ include = "spf.messagingengine.com";     provider = "Fastmail" },
    @{ include = "_spf.salesforce.com";         provider = "Salesforce" }
)

function Test-TakeoverNameSkip {
    <#
    Pure logic: should a crt.sh name be skipped by the takeover triage?
    Wildcard names ("*.example.com") can resolve through the zone's own
    wildcard records, so probing them misattributes findings to a literal
    "*"; the apex is covered by the main report, not the triage loop.
    Extracted so the battery proves the skip rule — the old inline
    `-like "\*\.*"` check was a no-op (backslash is NOT the wildcard
    escape character in PowerShell; that pattern requires a literal "\"),
    so wildcard names were silently probed.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$ApexDomain
    )
    if ($Name.StartsWith("*")) { return $true }
    if ($Name -eq $ApexDomain) { return $true }
    return $false
}

function ConvertTo-OsintUtcDate {
    <#
    Pure logic: parse an RDAP/registry timestamp into UTC. RFC 9083 dates
    carry a zone (Z or numeric offset), but registry sources are not
    always well-behaved; a zone-less string is read as UTC rather than
    shifted by the machine's local offset (the coherence-core v1.4
    determinism fix applied here, so daysToExpiry is machine-independent).
    Returns $null when the string is unparseable.
    #>
    param([Parameter(Mandatory=$true)][string]$DateString)
    $s = $DateString.Trim()
    if ($s -eq "") { return $null }
    try {
        $dt = [datetime]::Parse($s, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind)
    } catch { return $null }
    if ($dt.Kind -eq [System.DateTimeKind]::Unspecified) {
        $dt = [datetime]::SpecifyKind($dt, [System.DateTimeKind]::Utc)
    }
    return $dt.ToUniversalTime()
}

$script:HttpEdgeRules = @(
    # name, server-banner wildcards, response-header names (lowercased).
    # Header hits checked first — a header is harder to spoof than a banner.
    @{ name = "Cloudflare";       server = @("*cloudflare*");            headers = @("cf-ray") },
    @{ name = "AWS CloudFront";   server = @("*cloudfront*");            headers = @("x-amz-cf-id", "x-amz-cf-pop") },
    @{ name = "Fastly";           server = @("*fastly*");                headers = @("x-served-by", "x-fastly-request-id") },
    @{ name = "Akamai";           server = @("*akamai*");                headers = @("x-akamai-transformed", "akamai-origin-hop") },
    @{ name = "Azure Front Door"; server = @("*azure*front*door*");      headers = @("x-azure-ref") },
    @{ name = "AWS ELB/ALB";      server = @("*awselb*");                headers = @("x-amzn-requestid", "x-amzn-trace-id") },
    @{ name = "Sucuri";           server = @("*sucuri*");                headers = @("x-sucuri-id", "x-sucuri-cache") },
    @{ name = "Imperva/Incapsula";server = @("*imperva*", "*incapsula*"); headers = @("x-iinfo", "x-cdn") },
    @{ name = "StackPath";        server = @("*stackpath*");             headers = @("x-sp-url") },
    @{ name = "BunnyCDN";         server = @("*bunnycdn*");              headers = @("cdn-pullzone", "cdn-uid") },
    @{ name = "G-Core";           server = @("*gcore*");                 headers = @() },
    @{ name = "Cloudinary";       server = @("*cloudinary*");            headers = @() }
)

function Get-HttpEdgeHint {
    <#
    Pure logic: Server banner + response headers -> CDN/edge provider.
    Table-driven so the provider list grows without touching the code
    path. "" means none detected — never a guess at the origin.
    #>
    param(
        [string]$Server = "",
        $Headers = $null   # hashtable of lowercased header name -> value
    )
    $h = @{}
    if ($Headers -ne $null) {
        foreach ($k in @($Headers.Keys)) { $h["$k".ToLower()] = $true }
    }
    $s = "$Server"
    foreach ($r in $script:HttpEdgeRules) {
        foreach ($hp in $r.headers) { if ($h.ContainsKey($hp)) { return $r.name } }
        foreach ($sp in $r.server)  { if ($s -like $sp) { return $r.name } }
    }
    return ""
}

function Get-TakeoverCandidates {
    <#
    PASSIVE subdomain-takeover triage from crt.sh names. For each name: does
    it CNAME to something that no longer resolves (dangling -> takeover
    surface, high value), or to a known claimable service (fingerprint ->
    verify manually)?

    Passive DNS only. Claiming/verification happens in a provider account
    and needs the bounty scope to authorize it — never automated here.
    dangling-nxdomain is reported at high confidence; fingerprint-match is
    medium and labeled "verify manually".
    #>
    param(
        [Parameter(Mandatory=$true)]$CrtSh,
        [int]$MaxSubdomains = 150
    )
    $out = [pscustomobject]@{
        ok = $CrtSh.ok; domain = $CrtSh.domain; checked = 0;
        dangling = @(); fingerprintMatches = @(); source = "dns+crt.sh"; error = ""
    }
    if (-not $CrtSh.ok) { $out.error = "crtsh-not-ok"; return $out }
    $names = @($CrtSh.subdomains | Select-Object -First $MaxSubdomains)
    foreach ($n in $names) {
        if (Test-TakeoverNameSkip -Name $n -ApexDomain $out.domain) { continue }
        $out.checked++
        try {
            $cn = Resolve-DnsName -Name $n -Type CNAME -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $cn -or -not $cn.NameHost) { continue }
            $target = "$($cn.NameHost)".TrimEnd(".")
            # does the CNAME target still resolve? A, then AAAA, then one
            # CNAME hop — a target that only lives on v6 or behind a chain
            # is NOT dangling. Declaring dangling on a missing A alone is
            # how false positives get filed as findings.
            $tgt = $null
            foreach ($qt in @("A","AAAA")) {
                try {
                    $tgt = Resolve-DnsName -Name $target -Type $qt -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($tgt) { break }
                } catch { }
            }
            if (-not $tgt) {
                try {
                    $chain = Resolve-DnsName -Name $target -Type CNAME -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($chain -and $chain.NameHost) {
                        $tgt = Resolve-DnsName -Name ("$($chain.NameHost)".TrimEnd(".")) -Type A -ErrorAction SilentlyContinue | Select-Object -First 1
                    }
                } catch { }
            }
            if (-not $tgt) {
                $out.dangling += [pscustomobject]@{
                    name = $n; cnameTarget = $target;
                    finding = "dangling-nxdomain"; confidence = "high"
                }
                Write-Host "[!] TAKEOVER-SURFACE: $n CNAME -> $target (does not resolve)"
                continue
            }
            foreach ($fp in $script:TakeoverFingerprints) {
                if ($target -like $fp.pattern) {
                    $out.fingerprintMatches += [pscustomobject]@{
                        name = $n; cnameTarget = $target; service = $fp.service;
                        finding = "fingerprint-match"; confidence = "medium (verify manually, in scope only)"
                    }
                    Write-Host "[*] TAKEOVER-FINGERPRINT: $n CNAME -> $($fp.service)"
                    break
                }
            }
        } catch { }
    }
    Write-Host "[+] takeover triage: checked $($out.checked), dangling=$($out.dangling.Count), fingerprint=$($out.fingerprintMatches.Count)"
    New-OsintLog -QueryType "takeover-triage" -Target $out.domain -Result ([pscustomobject]@{ ok = $true })
    return $out
}

function Get-CrtDelta {
    <#
    Certificate-transparency NEW-HOST monitor. Stores the crt.sh name set
    as a local baseline and reports names that appeared since the last run.
    New public certs = new attack surface the owner never saw. First run
    creates the baseline; every run after diffs and re-baselines.
    #>
    param([Parameter(Mandatory=$true)]$CrtSh)
    $out = [pscustomobject]@{
        ok = $CrtSh.ok; domain = $CrtSh.domain; isFirstRun = $false;
        baselineDate = ""; newNames = @(); removedNames = @(); total = $CrtSh.count; error = ""
    }
    if (-not $CrtSh.ok) { $out.error = "crtsh-not-ok"; return $out }
    $baseDir = Join-Path ([Environment]::GetFolderPath("UserProfile")) ".blackbox\ct-baselines"
    try {
        if (-not (Test-Path $baseDir)) { New-Item -ItemType Directory -Path $baseDir -Force | Out-Null }
    } catch {
        $out.error = "baseline-dir: $($_.Exception.Message)"
        return $out
    }
    $safe = ($out.domain -replace '[^a-zA-Z0-9.\-]', '_')
    $bPath = Join-Path $baseDir "ct-$safe.json"
    $current = @($CrtSh.subdomains | Sort-Object -Unique)
    if (Test-Path $bPath) {
        try {
            $base = Get-Content $bPath -Raw | ConvertFrom-Json
            $old = @($base.names)
            $out.baselineDate = "$($base.date)"
            $out.newNames = @($current | Where-Object { $old -notcontains $_ })
            $out.removedNames = @($old | Where-Object { $current -notcontains $_ })
            if ($out.newNames.Count -gt 0) {
                Write-Host "[!] CT DELTA: $($out.newNames.Count) NEW name(s) since $($out.baselineDate)"
            } else {
                Write-Host "[+] CT delta: no new names since $($out.baselineDate)"
            }
        } catch {
            $out.error = "baseline-read: $($_.Exception.Message)"
        }
    } else {
        $out.isFirstRun = $true
        Write-Host "[*] CT baseline created for $($out.domain) ($($current.Count) names)"
    }
    try {
        @{ date = (Get-Date).ToUniversalTime().ToString("o"); names = $current } |
            ConvertTo-Json -Depth 3 | Set-Content -Path $bPath -Encoding UTF8
    } catch {
        Write-Host "[!] CT baseline write failed: $($_.Exception.Message)"
    }
    return $out
}

function Get-HttpFingerprint {
    <#
    ONE passive HTTPS GET (same traffic as visiting the site in a browser):
    server tech leaks (Server / X-Powered-By), missing security headers
    (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy),
    and edge/CDN hints (cf-ray, cloudflare/fastly server banners). Single
    attempt, 12s timeout — it either answers or it doesn't.
    #>
    param([Parameter(Mandatory=$true)][string]$Domain)
    $chk = Test-OsintInput $Domain
    $out = [pscustomobject]@{
        ok = $false; domain = $Domain; statusCode = $null; server = "";
        poweredBy = ""; securityHeaders = @{}; missingSecurityHeaders = @();
        edgeHint = ""; tlsNote = ""; source = "http"; error = ""
    }
    if (-not $chk.valid -or $chk.kind -ne "domain") {
        $out.error = "invalid-domain: $($chk.note)"
        return $out
    }
    $d = $chk.value
    $out.domain = $d
    try {
        Write-Host "[*] HTTP fingerprint $d (single passive GET)"
        $resp = Invoke-WebRequest -Uri "https://$d/" -UseBasicParsing -Method Get `
            -MaximumRedirection 2 -TimeoutSec 12 -ErrorAction Stop
        $out.ok = $true
        $out.statusCode = [int]$resp.StatusCode
        $h = @{}
        foreach ($k in @($resp.Headers.Keys)) { $h["$k".ToLower()] = "$($resp.Headers[$k])" }
        if ($h.ContainsKey("server")) { $out.server = $h["server"] }
        if ($h.ContainsKey("x-powered-by")) { $out.poweredBy = $h["x-powered-by"] }
        foreach ($sh in @("strict-transport-security","content-security-policy",
                           "x-frame-options","x-content-type-options","referrer-policy")) {
            if ($h.ContainsKey($sh)) { $out.securityHeaders[$sh] = $h[$sh] }
            else { $out.missingSecurityHeaders += $sh }
        }
        # Edge/CDN attribution is table-driven (Get-HttpEdgeHint) — the
        # provider list grows as data, not as another elseif chain.
        $out.edgeHint = Get-HttpEdgeHint -Server $out.server -Headers $h
        Write-Host "[+] HTTP $d : $($out.statusCode), server='$($out.server)', missing-sec-headers=$($out.missingSecurityHeaders.Count), edge='$($out.edgeHint)'"
    } catch {
        $out.error = $_.Exception.Message
        Write-Host "[!] HTTP fingerprint failed for $d : $($out.error)"
    }
    New-OsintLog -QueryType "http-fingerprint" -Target $d -Result $out
    return $out
}

function Test-OsintHygiene {
    <#
    Offline self-test battery for osint-attribution: input classification
    (incl. IDN -> punycode), SPF/DMARC/DKIM parsing, crt.sh dedup rules,
    cert-expiry classification, takeover table sanity, provider map sanity.
    No network traffic; pure logic. Returns $true when every check passes,
    throws on the first failure.
    #>
    $checks = @()
    # NOTE: the $add scriptblock RETURNS the check object; callers capture
    # it with $checks += & $add ... — writing $checks inside the scriptblock
    # would hit a child scope and silently stay empty (the vault battery
    # caught this pattern in a sibling module).
    $add = {
        param([string]$Name, [bool]$Passed, [string]$Detail)
        return [pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail }
    }

    # 1. Input classification.
    $ic = @(
        @("8.8.8.8", "ip", "8.8.8.8"),
        @("2001:4860:4860::8888", "ip", "2001:4860:4860::8888"),
        @("example.com", "domain", "example.com"),
        @("ExAmPlE.COM", "domain", "example.com"),
        @("localhost", "domain", "localhost"),
        @("xn--mnchen-3ya.de", "domain", "xn--mnchen-3ya.de")
    )
    foreach ($c in $ic) {
        $r = Test-OsintInput $c[0]
        $checks += & $add ("input[$($c[0])]") ($r.valid -and $r.kind -eq $c[1] -and $r.value -eq $c[2]) "got=$($r.kind)/$($r.value)"
    }
    # unicode domain -> punycode (built via [char] to keep this file pure ASCII)
    $idn = Test-OsintInput ("m$([char]0xFC)nchen.de")
    $checks += & $add "input[idn-punycode]" ($idn.valid -and $idn.kind -eq "domain" -and $idn.value -eq "xn--mnchen-3ya.de") "got=$($idn.value)"
    $bad = Test-OsintInput "not a domain!!"
    $checks += & $add "input[invalid]" (-not $bad.valid) "kind=$($bad.kind)"

    # 2. SPF parsing.
    $spf = ConvertFrom-SpfRecord "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all"
    $checks += & $add "spf[multi-include]" ($spf.present -and $spf.verdict -eq "softfail" -and $spf.includes.Count -eq 2 -and $spf.provider -eq "Google Workspace") "verdict=$($spf.verdict) prov=$($spf.provider)"
    $spf2 = ConvertFrom-SpfRecord "v=spf1 include:spf.protection.outlook.com -all"
    $checks += & $add "spf[o365-strict]" ($spf2.verdict -eq "strict" -and $spf2.provider -eq "Microsoft 365") "verdict=$($spf2.verdict) prov=$($spf2.provider)"
    $spf3 = ConvertFrom-SpfRecord "v=spf1 +all"
    $checks += & $add "spf[plusall]" ($spf3.verdict -eq "dangerous-plusall") "verdict=$($spf3.verdict)"
    $spf4 = ConvertFrom-SpfRecord "v=spf1 mx all"
    $checks += & $add "spf[bare-all]" ($spf4.verdict -eq "dangerous-plusall") "verdict=$($spf4.verdict)"
    $spf5 = ConvertFrom-SpfRecord "some random txt"
    $checks += & $add "spf[absent]" (-not $spf5.present -and $spf5.verdict -eq "none") ""
    $spf6 = ConvertFrom-SpfRecord "v=spf1 ip4:192.0.2.0/24 ?all"
    $checks += & $add "spf[neutral]" ($spf6.verdict -eq "neutral" -and $spf6.mechanisms.Count -eq 2) "mechs=$($spf6.mechanisms.Count)"
    $spf7 = ConvertFrom-SpfRecord "v=spf1 ip4:192.0.2.1"
    $checks += & $add "spf[no-policy]" ($spf7.verdict -eq "no-policy") "verdict=$($spf7.verdict)"
    $spf8 = ConvertFrom-SpfRecord "V=SPF1 -all"
    $checks += & $add "spf[case-insensitive]" ($spf8.present -and $spf8.verdict -eq "strict") "verdict=$($spf8.verdict)"

    # 3. DMARC parsing.
    $dm = ConvertFrom-DmarcRecord "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"
    $checks += & $add "dmarc[reject]" ($dm.present -and $dm.policy -eq "reject" -and $dm.rua -eq "mailto:dmarc@example.com" -and $dm.pct -eq "100") ""
    $dm2 = ConvertFrom-DmarcRecord "v=DMARC1; p=none; sp=quarantine; adkim=s"
    $checks += & $add "dmarc[none]" ($dm2.present -and $dm2.policy -eq "none" -and $dm2.subPolicy -eq "quarantine" -and $dm2.adkim -eq "s") ""
    $dm3 = ConvertFrom-DmarcRecord "v=spf1 -all"
    $checks += & $add "dmarc[absent]" (-not $dm3.present) ""

    # 4. DKIM selector record detection.
    $checks += & $add "dkim[rfc6376]" (Test-DkimSelectorRecord "v=DKIM1; k=rsa; p=MIGfMA0GCSqG") ""
    $checks += & $add "dkim[legacy]" (Test-DkimSelectorRecord "k=rsa; p=ABCD1234") ""
    $checks += & $add "dkim[notkey]" (-not (Test-DkimSelectorRecord "v=spf1 -all")) ""

    # 5. crt.sh dedup rules (pure logic, no network).
    $rows = @(
        [pscustomobject]@{ name_value = "example.com`n*.example.com`nwww.example.com`nadmin@example.com"; issuer_name = "Let's Encrypt"; not_before = "2026-01-01"; not_after = "2026-04-01" },
        [pscustomobject]@{ name_value = "www.example.com"; issuer_name = "Let's Encrypt"; not_before = "2026-02-01"; not_after = "2026-05-01" },
        [pscustomobject]@{ name_value = "mail.example.com"; issuer_name = "DigiCert"; not_before = "2026-01-01"; not_after = "2025-01-01" }
    )
    $cd = ConvertFrom-CrtShRows $rows
    $checks += & $add "crtsh[dedup]" ($cd.names.Count -eq 4 -and $cd.names -contains "*.example.com" -and $cd.names -notcontains "admin@example.com") "names=$($cd.names.Count): $($cd.names -join ',')"
    $checks += & $add "crtsh[issuers]" ($cd.issuers.Count -eq 2) "issuers=$($cd.issuers -join ',')"

    # 6. Cert-expiry classification (relative dates — deterministic).
    $now = (Get-Date).ToUniversalTime()
    $fake = [pscustomobject]@{ ok = $true; domain = "example.com"; count = 3; expiries = @(
        [pscustomobject]@{ name = "old.example.com";  not_after = $now.AddDays(-5).ToString("o") },
        [pscustomobject]@{ name = "soon.example.com"; not_after = $now.AddDays(10).ToString("o") },
        [pscustomobject]@{ name = "ok.example.com";   not_after = $now.AddDays(90).ToString("o") }
    )}
    $ce = Get-CrtExpiryReport -CrtSh $fake
    $checks += & $add "certexp[classify]" ($ce.expired.Count -eq 1 -and $ce.expiringSoon.Count -eq 1 -and $ce.okCount -eq 1) "exp=$($ce.expired.Count) soon=$($ce.expiringSoon.Count) ok=$($ce.okCount)"

    # 7. Takeover fingerprint table sanity.
    $pats = @($script:TakeoverFingerprints | ForEach-Object { $_.pattern })
    $checks += & $add "takeover[table]" ($pats.Count -ge 20 -and ($pats | Sort-Object -Unique).Count -eq $pats.Count) "patterns=$($pats.Count)"
    $emptySvc = @($script:TakeoverFingerprints | Where-Object { [string]::IsNullOrWhiteSpace($_.service) })
    $checks += & $add "takeover[services]" ($emptySvc.Count -eq 0) ""

    # 8. Mail provider map sanity.
    $badMap = @($script:MailProviderMap | Where-Object { [string]::IsNullOrWhiteSpace($_.provider) -or [string]::IsNullOrWhiteSpace($_.include) })
    $checks += & $add "mailprov[map]" ($badMap.Count -eq 0 -and $script:MailProviderMap.Count -ge 8) "rows=$($script:MailProviderMap.Count)"
    $checks += & $add "mailprov[selectors]" ($script:DkimSelectors.Count -ge 8 -and ($script:DkimSelectors | Sort-Object -Unique).Count -eq $script:DkimSelectors.Count) "selectors=$($script:DkimSelectors.Count)"

    # 9. v5 fixes: trailing-dot input, wildcard/apex skip predicate,
    # zone-less date parsing, edge-hint table, fix-plan reentrancy.
    $td1 = Test-OsintInput "Example.COM."
    $checks += & $add "input[trailing-dot]" ($td1.valid -and $td1.kind -eq "domain" -and $td1.value -eq "example.com") "got=$($td1.kind)/$($td1.value)"
    $td2 = Test-OsintInput "8.8.8.8."
    $checks += & $add "input[trailing-dot-ip]" ($td2.valid -and $td2.kind -eq "ip" -and $td2.value -eq "8.8.8.8") "got=$($td2.kind)/$($td2.value)"
    $td3 = Test-OsintInput "."
    $checks += & $add "input[dot-only]" (-not $td3.valid) "kind=$($td3.kind)"

    $checks += & $add "skip[wildcard]" (Test-TakeoverNameSkip -Name "*.example.com" -ApexDomain "example.com") ""
    $checks += & $add "skip[apex]" (Test-TakeoverNameSkip -Name "example.com" -ApexDomain "example.com") ""
    $checks += & $add "skip[wildcard-other]" (Test-TakeoverNameSkip -Name "*.other.com" -ApexDomain "example.com") ""
    $checks += & $add "skip[host]" (-not (Test-TakeoverNameSkip -Name "www.example.com" -ApexDomain "example.com")) ""

    $udz = ConvertTo-OsintUtcDate "2027-01-15T00:00:00Z"
    $checks += & $add "date[z]" ($udz -ne $null -and $udz.Kind -eq [System.DateTimeKind]::Utc -and $udz.Hour -eq 0) "kind=$($udz.Kind) hour=$($udz.Hour)"
    $udo = ConvertTo-OsintUtcDate "2027-01-15T05:00:00+05:00"
    $checks += & $add "date[offset]" ($udo -ne $null -and $udo.Kind -eq [System.DateTimeKind]::Utc -and $udo.Hour -eq 0) "hour=$($udo.Hour)"
    $udn = ConvertTo-OsintUtcDate "2027-01-15 00:00:00"
    $checks += & $add "date[zone-less]" ($udn -ne $null -and $udn.Kind -eq [System.DateTimeKind]::Utc -and $udn.Hour -eq 0) "kind=$($udn.Kind) hour=$($udn.Hour)"
    $udb = ConvertTo-OsintUtcDate "not-a-date"
    $checks += & $add "date[bad]" ($udb -eq $null) ""

    $checks += & $add "edge[banner]" ((Get-HttpEdgeHint -Server "cloudflare") -eq "Cloudflare") ""
    $checks += & $add "edge[header]" ((Get-HttpEdgeHint -Server "gunicorn" -Headers @{ "cf-ray" = "abc123" }) -eq "Cloudflare") ""
    $checks += & $add "edge[cloudfront]" ((Get-HttpEdgeHint -Server "AmazonS3" -Headers @{ "x-amz-cf-id" = "x" }) -eq "AWS CloudFront") ""
    $checks += & $add "edge[bunny]" ((Get-HttpEdgeHint -Server "BunnyCDN-Edge") -eq "BunnyCDN") ""
    $checks += & $add "edge[none]" ((Get-HttpEdgeHint -Server "gunicorn") -eq "") ""

    # fix plan must not accumulate findings across calls in one session
    $emptyReport = [pscustomobject]@{
        target = "example.com"; threatListed = $false; shodan = $null; rdap = $null
        crtsh = $null; certExpiry = $null; takeover = $null; ctDelta = $null
        rdapDomain = $null; dnssec = $null; caa = $null; mailauth = $null
        httpFp = $null; dns = $null; asn = $null
    }
    $planA = New-SelfExposureFixPlan -Report $emptyReport
    $planB = New-SelfExposureFixPlan -Report $emptyReport
    $checks += & $add "fixplan[reentrant]" ($planA.findings.Count -eq $planB.findings.Count -and $planA.findings.Count -eq 1) "a=$($planA.findings.Count) b=$($planB.findings.Count)"

    $failed = @($checks | Where-Object { -not $_.Passed })
    Write-Host "[*] Test-OsintHygiene: $($checks.Count - $failed.Count)/$($checks.Count) checks passed"
    foreach ($f in $failed) { Write-Host "[FAIL] $($f.Name): $($f.Detail)" }
    if ($failed.Count -gt 0) { throw "$($failed.Count) osint hygiene checks failed" }
    return $true
}

# Dot-sourcing note: all functions load directly into the caller session.
