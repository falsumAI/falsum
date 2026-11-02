<#
BLACKBOX Module 00 — COHERENCE CORE
Deterministic evidence-scoring engine. No LLM. No randomness. No network.
Same evidence in -> same verdict out, every time.

Dot-source this file to use its functions:
  . .\Falsum-Coherence.ps1

Every function is pure: no I/O, no clock reads except where the caller
passes a timestamp. Hashing: SHA-256 for items, SHA-384 for receipts.

Functions:
  ConvertTo-CanonicalJson, Get-Sha256Hex, Get-Sha384Hex,
  New-EvidenceItem, Get-CoherenceChecks, Test-Coherence,
  Measure-AttributionConvergence, Test-Drift,
  Get-PortServiceTable, Get-PortServiceKeywordTable,
  Get-OuiVendorTable, Get-FileMagicTable, Get-MagicTypeTable,
  Get-TrustedCaKeywordTable, ConvertTo-CountryName,
  New-CoherenceVerdict, New-Receipt, Test-ReceiptChain,
  Test-CoherenceHygiene

Hardening history:
  2026-10-30 (cron): full JSON control-char escaping in canonical form;
  ValidateNotNullOrEmpty on evidence id/type; 4 new Test-Coherence checks
  (ip-match, domain-cert, port-service, cert-time) + shipped port/service
  table; deterministic tie-break in convergence; Test-Drift input guards;
  New-CoherenceVerdict weighted multi-check composer; Get-CoherenceChecks
  registry.
  2026-10-30 ~05:23 MDT (cron): determinism bug fix — [datetime]/numeric
  values in evidence data now canonicalize culture-invariant (was "$obj"
  coercion: locale-dependent, different hashes per machine). 4 new checks
  (ip-subnet, time-skew, domain-age, ttl-os) with parameterized thresholds
  via -CheckParams; port table 71 -> 107 entries; Test-Drift -IgnoreKeys;
  convergence -Threshold; Test-ReceiptChain -AllErrors.
  2026-10-30 ~06:35 MDT (cron): CANONICAL BUG FIX — non-string dictionary
  keys (numeric/bool) used to emit bare {5:...} which is not valid JSON;
  keys are now stringified first. 6 new checks: url-domain (URL host vs
  claimed domain, phishing lookalike signal), email-domain (sender domain
  vs claimed identity), port-banner (banner keywords vs port table, via new
  Get-PortServiceKeywordTable), mac-vendor (OUI vs claimed vendor, via new
  shipped 64-entry Get-OuiVendorTable), hash-verify (recomputes SHA-256 of
  the data — catches hand-edited hash fields), geo-agree (two independent
  geo sources, via new ConvertTo-CountryName + shipped ISO table).
  Test-CoherenceHygiene: 25-case offline self-test battery (canonical,
  every check pass+fail, verdict math, receipt chain, table sanity) wired
  into the launcher's option-18 self-test run.
  2026-10-30 ~09:50 MDT (cron, v1.4): CANONICAL BUG FIX — [datetime] with
  Kind=Unspecified was shifted by the MACHINE's timezone (ToUniversalTime
  treats Unspecified as local), so the same evidence hashed differently on
  different machines — the same determinism bug class the 05:23 pass fixed
  for culture. Unspecified is now treated as UTC; Local converts; Utc
  passes through (byte-proven by new battery case). New-CoherenceVerdict
  excludes checks with non-numeric/out-of-range scores instead of silently
  poisoning the mean. ip-subnet now requires address/prefix CIDR form
  ("10.0.0.0" used to silently degrade to /0 — everything "inside").
  url-domain accepts scheme-less hosts ("mail.example.com/inbox" used to
  fail as unparseable). email-domain extracts the addr-spec from
  display-name forms ("Jane <jane@x.com>" used to false-DRIFT on "x.com>").
  hash-verify distinguishes MALFORMED claims from genuine mismatches.
  Get-Sha256Hex/Get-Sha384Hex dispose under try/finally. 2 new checks:
  file-magic (extension vs magic-byte signature, renamed-binary/dropper
  signal, via new Get-FileMagicTable + Get-MagicTypeTable) and cert-issuer
  (self-signed vs known public CA vs neutral unknown, via new
  Get-TrustedCaKeywordTable). Registry 19 -> 21. Battery 25 -> 39 cases.
#>

function ConvertTo-CanonicalJson {
    param([Parameter(Mandatory=$true)]$obj)
    if ($null -eq $obj) { return "null" }
    if ($obj -is [string]) {
        # Full JSON string escaping: backslash, quote, named escapes,
        # then \b \f, then every remaining C0 control char as \u00XX.
        # A raw control char in output would not be valid JSON, and two
        # different byte sequences must never canonicalize identically.
        $e = $obj -replace '\\','\\' -replace '"','\"' -replace "`n",'\n' -replace "`r",'\r' -replace "`t",'\t'
        $e = $e -replace ([char]8).ToString(), '\b' -replace ([char]12).ToString(), '\f'
        $e = [regex]::Replace($e, '[\x00-\x1F]', { param($m) '\u{0:X4}' -f [int][char]$m.Value })
        return '"' + $e + '"'
    }
    if ($obj -is [bool]) { if ($obj) { return "true" } else { return "false" } }
    # DETERMINISM BUG FIX (2026-10-30): [datetime] values used to fall
    # through to "$obj" string coercion, which is culture-dependent
    # ("10/30/2026 5:23 AM" vs ISO 8601) — same evidence, different hash,
    # depending on Windows locale. Dates now canonicalize to invariant ISO.
    # v1.4 (2026-10-30): the Kind half of that bug. ToUniversalTime treats
    # Kind=Unspecified as LOCAL, so the same wall-clock timestamp hashed
    # differently on machines in different timezones. Unspecified is now
    # read as UTC (the forensically safe deterministic reading), Local is
    # converted, Utc passes through untouched.
    if ($obj -is [datetime]) {
        if ($obj.Kind -eq [System.DateTimeKind]::Utc) { return '"' + $obj.ToString("o") + '"' }
        if ($obj.Kind -eq [System.DateTimeKind]::Local) { return '"' + $obj.ToUniversalTime().ToString("o") + '"' }
        return '"' + $obj.ToString("yyyy-MM-ddTHH:mm:ss.fffffff\Z") + '"'
    }
    if ($obj -is [datetimeoffset]) { return '"' + $obj.ToUniversalTime().ToString("o") + '"' }
    if ($obj -is [timespan]) { return '"' + $obj.ToString("c") + '"' }
    if ($obj -is [guid]) { return '"' + $obj.ToString() + '"' }
    # Numeric primitives: culture-invariant, never quoted. "$obj" on a
    # [double] in a comma-decimal locale yields "1,5" — invalid JSON and
    # non-deterministic across machines. "R" keeps float round-trip exact.
    $numTypes = @("System.Byte","System.SByte","System.Int16","System.UInt16",
        "System.Int32","System.UInt32","System.Int64","System.UInt64",
        "System.Single","System.Double","System.Decimal")
    if ($numTypes -contains $obj.GetType().FullName) {
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        if ($obj -is [single] -or $obj -is [double]) { return $obj.ToString("R", $inv) }
        return $obj.ToString($inv)
    }
    if ($obj -is [System.Collections.IDictionary]) {
        $parts = @()
        foreach ($k in ($obj.Keys | Sort-Object)) {
            # CANONICAL BUG FIX (2026-10-30): keys must be JSON strings. A
            # numeric or bool key used to emit {5:...} — not valid JSON, and
            # two machines could serialize it differently. Stringify first.
            $key = $k
            if ($key -isnot [string]) { $key = "$key" }
            $parts += (ConvertTo-CanonicalJson $key) + ":" + (ConvertTo-CanonicalJson $obj[$k])
        }
        return "{" + ($parts -join ",") + "}"
    }
    if ($obj -is [System.Collections.IEnumerable] -and $obj -isnot [string]) {
        $parts = @()
        foreach ($v in $obj) { $parts += ConvertTo-CanonicalJson $v }
        return "[" + ($parts -join ",") + "]"
    }
    if ($obj -is [psobject]) {
        $h = @{}
        foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = $p.Value }
        return ConvertTo-CanonicalJson $h
    }
    return ConvertTo-CanonicalJson "$obj"
}

function Get-Sha256Hex {
    param([Parameter(Mandatory=$true)][string]$text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $h = [System.Security.Cryptography.SHA256]::Create()
    # v1.4: dispose under finally — a throw inside ComputeHash used to
    # leak the native hash handle.
    try {
        $hash = $h.ComputeHash($bytes)
        return -join ($hash | ForEach-Object { $_.ToString("x2") })
    } finally { $h.Dispose() }
}

function Get-Sha384Hex {
    param([Parameter(Mandatory=$true)][string]$text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $h = [System.Security.Cryptography.SHA384]::Create()
    try {
        $hash = $h.ComputeHash($bytes)
        return -join ($hash | ForEach-Object { $_.ToString("x2") })
    } finally { $h.Dispose() }
}

function New-EvidenceItem {
    param(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$id,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$type,
        [Parameter(Mandatory=$true)]$data,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$source,
        [string]$utc = ""
    )
    if ([string]::IsNullOrEmpty($utc)) { $utc = (Get-Date).ToUniversalTime().ToString("o") }
    $canon = ConvertTo-CanonicalJson $data
    return [pscustomobject]@{
        id     = $id
        type   = $type
        data   = $data
        source = $source
        utc    = $utc
        sha256 = Get-Sha256Hex $canon
    }
}

function Test-Coherence {
    <#
    Cross-checks two evidence items. Returns score 0-100 + reason strings.
    Supported check types (pass -check; see Get-CoherenceChecks):
      process-port : A={process,port}, B={port,service} — does the claimant match?
      dns-sni      : A={dns}, B={sni} — same domain?
      rdap-asn     : A={rdapOrg}, B={asnOrg} — org names agree?
      hash-match   : A={sha256}, B={sha256} — identical?
      time-order   : A={utc}, B={utc} — A before B?
      ip-match     : A={ip}, B={ip} — same address (normalizes IPv4-mapped, zone ids)?
      domain-cert  : A={domain}, B={certName} — cert (incl. wildcard) covers the domain?
      port-service : A={port}, B={service} — service matches the shipped port table?
      cert-time    : A={notBefore,notAfter}, B={utc} — event inside cert validity?
      ip-subnet    : A={ip}, B={cidr} — address inside the claimed IPv4 network?
      time-skew    : A={utc}, B={utc} — same event, witnesses within CheckParams.MaxSeconds (default 5)?
      domain-age   : A={registered}, B={utc} — domain older than CheckParams.MaxAgeDays (default 30) at event time?
      ttl-os       : A={ttl}, B={os} — observed IP TTL fits the claimed OS family (64/128/255 bands)?
      url-domain   : A={url}, B={domain} — the URL's host matches the claimed domain (exact or subdomain)?
      email-domain : A={email}, B={domain} — the sender's domain matches the claimed identity?
      port-banner  : A={port}, B={banner} — grabbed banner carries keywords of the service the port table expects?
      mac-vendor   : A={mac}, B={vendor} — the MAC's OUI (first 3 octets) matches the claimed hardware vendor?
      hash-verify  : A={data}, B={sha256} — RECOMPUTE: claimed hash equals the actual SHA-256 of the data?
      geo-agree    : A={geoA}, B={geoB} — two independent geo sources for the same IP agree on country?
      file-magic   : A={extension}, B={magicHex} — the file's first bytes match what its extension claims?
      cert-issuer  : A={issuer}, B={subject} — self-signed, known public CA, or unknown (neutral)?
    Optional -CheckParams hashtable tunes thresholds per check without
    changing the signature every caller uses. All new checks are pure logic:
    no network, no clock, deterministic.
    Unknown check type -> score 50, reason "no check defined".
    #>
    param(
        [Parameter(Mandatory=$true)]$a,
        [Parameter(Mandatory=$true)]$b,
        [Parameter(Mandatory=$true)][string]$check,
        [hashtable]$CheckParams = @{}
    )
    $reasons = @()
    $score = 50
    switch ($check) {
        "process-port" {
            $pa = "$($a.data.process)".ToLower(); $pb = "$($b.data.process)".ToLower()
            $portA = "$($a.data.port)"; $portB = "$($b.data.port)"
            if ($portA -eq $portB -and $pa -eq $pb -and $pa -ne "") {
                $score = 100; $reasons += "process '$pa' claims port $portA; independent source agrees"
            } elseif ($portA -eq $portB -and $pa -ne $pb) {
                $score = 20; $reasons += "DRIFT: port $portA claimed by '$pa' but source B says '$pb'"
            } elseif ($portA -ne $portB) {
                $score = 30; $reasons += "DRIFT: port mismatch ($portA vs $portB)"
            } else { $reasons += "insufficient data for process-port check" }
        }
        "dns-sni" {
            $da = "$($a.data.dns)".ToLower().TrimEnd("."); $db = "$($b.data.sni)".ToLower().TrimEnd(".")
            if ($da -ne "" -and $da -eq $db) { $score = 100; $reasons += "DNS query '$da' matches TLS SNI" }
            elseif ($da -ne "" -and $db -ne "") { $score = 15; $reasons += "DRIFT: DNS '$da' but TLS went to '$db' — possible hijack or tunnel" }
            else { $reasons += "insufficient data for dns-sni check" }
        }
        "rdap-asn" {
            $oa = "$($a.data.rdapOrg)".ToLower(); $ob = "$($b.data.asnOrg)".ToLower()
            if ($oa -ne "" -and ($oa -eq $ob -or $oa.Contains($ob) -or $ob.Contains($oa))) {
                $score = 90; $reasons += "RDAP org '$($a.data.rdapOrg)' consistent with ASN org '$($b.data.asnOrg)'"
            } elseif ($oa -ne "" -and $ob -ne "") {
                $score = 35; $reasons += "DIVERGED: RDAP '$($a.data.rdapOrg)' vs ASN '$($b.data.asnOrg)' — attribution uncertain"
            } else { $reasons += "insufficient data for rdap-asn check" }
        }
        "hash-match" {
            $ha = "$($a.data.sha256)".ToLower(); $hb = "$($b.data.sha256)".ToLower()
            if ($ha -ne "" -and $ha -eq $hb) { $score = 100; $reasons += "hashes identical — integrity verified" }
            elseif ($ha -ne "" -and $hb -ne "") { $score = 0; $reasons += "HASH MISMATCH — data altered between sources" }
            else { $reasons += "insufficient data for hash-match check" }
        }
        "time-order" {
            try {
                $ta = [datetime]$a.data.utc; $tb = [datetime]$b.data.utc
                if ($ta -le $tb) { $score = 100; $reasons += "timeline consistent: A precedes B" }
                else { $score = 25; $reasons += "DRIFT: A claims earlier event but timestamp is later" }
            } catch { $reasons += "unparseable timestamps for time-order check" }
        }
        "ip-match" {
            # Normalizes IPv4-mapped IPv6 (::ffff:1.2.3.4) and zone ids (%eth0).
            $normIp = {
                param($raw)
                $v = "$raw".Trim().ToLower()
                if ($v -like "*%*") { $v = $v.Substring(0, $v.IndexOf("%")) }
                if ($v -like "::ffff:*") { $v = $v.Substring(7) }
                return $v
            }
            $ia = & $normIp $a.data.ip; $ib = & $normIp $b.data.ip
            if ($ia -ne "" -and $ia -eq $ib) { $score = 100; $reasons += "IP '$ia' identical across sources" }
            elseif ($ia -ne "" -and $ib -ne "") { $score = 0; $reasons += "IP MISMATCH: '$ia' vs '$ib' — different hosts" }
            else { $reasons += "insufficient data for ip-match check" }
        }
        "domain-cert" {
            # B may be a wildcard (*.example.com): matches exactly one label deep.
            $da = "$($a.data.domain)".ToLower().Trim().TrimEnd(".")
            $cb = "$($b.data.certName)".ToLower().Trim().TrimEnd(".")
            $matched = $false; $wild = $false
            if ($da -ne "" -and $cb -ne "") {
                if ($da -eq $cb) { $matched = $true }
                elseif ($cb.StartsWith("*.")) {
                    $wild = $true
                    $suffix = $cb.Substring(2)
                    if ($da.EndsWith("." + $suffix)) {
                        $extra = $da.Substring(0, $da.Length - $suffix.Length - 1)
                        if ($extra -ne "" -and -not $extra.Contains(".")) { $matched = $true }
                    }
                }
            }
            if ($matched -and -not $wild) { $score = 100; $reasons += "cert name '$cb' exactly covers '$da'" }
            elseif ($matched) { $score = 100; $reasons += "wildcard cert '$cb' covers '$da'" }
            elseif ($wild) { $score = 35; $reasons += "DRIFT: wildcard '$cb' does not cover '$da' (deeper than one label or different suffix)" }
            elseif ($da -ne "" -and $cb -ne "") { $score = 35; $reasons += "DRIFT: cert '$cb' does not name '$da' — possible spoof or misissue" }
            else { $reasons += "insufficient data for domain-cert check" }
        }
        "port-service" {
            $port = 0
            $portOk = [int]::TryParse("$($a.data.port)", [ref]$port)
            $svc = "$($b.data.service)".ToLower().Trim()
            if ($portOk -and $svc -ne "") {
                $table = Get-PortServiceTable
                if ($table.ContainsKey($port)) {
                    $expected = $table[$port]
                    $aliases = @($expected -split "/")
                    if ($aliases -contains $svc -or $expected -eq $svc) {
                        $score = 100; $reasons += "port $port runs '$svc' per service table"
                    } else {
                        $score = 30; $reasons += "DRIFT: port $port is '$expected' per table but source claims '$svc'"
                    }
                } else { $reasons += "port $port not in service table — no check possible" }
            } else { $reasons += "insufficient data for port-service check" }
        }
        "cert-time" {
            try {
                $nb = [datetime]$a.data.notBefore; $na = [datetime]$a.data.notAfter; $ev = [datetime]$b.data.utc
                if ($ev -ge $nb -and $ev -le $na) { $score = 100; $reasons += "event inside certificate validity window" }
                elseif ($ev -lt $nb) { $score = 25; $reasons += "DRIFT: event predates certificate validity (notBefore $($a.data.notBefore))" }
                else { $score = 25; $reasons += "DRIFT: certificate expired before event (notAfter $($a.data.notAfter))" }
            } catch { $reasons += "unparseable timestamps for cert-time check" }
        }
        "ip-subnet" {
            # A={ip}, B={cidr} — does the observed address fall inside the
            # claimed IPv4 network? Pure prefix math; no network calls.
            try {
                $ipStr = "$($a.data.ip)".Trim()
                $cidr  = "$($b.data.cidr)".Trim()
                $addr  = [System.Net.IPAddress]::Parse($ipStr)
                $parts = $cidr -split "/"
                # v1.4: "10.0.0.0" (no prefix) used to silently degrade to
                # /0 — every address "inside" the network. Require the form.
                if ($parts.Count -ne 2) { throw "CIDR '$cidr' must be in address/prefix form (e.g. 10.0.0.0/8)" }
                $net   = [System.Net.IPAddress]::Parse($parts[0])
                $bits  = [int]$parts[1]
                if ($addr.AddressFamily -ne $net.AddressFamily) { throw "address and network are different IP families" }
                if ($bits -lt 0 -or $bits -gt 32) { throw "prefix length must be 0-32" }
                $ab = $addr.GetAddressBytes(); $nb = $net.GetAddressBytes()
                if ($ab.Length -ne 4) { throw "IPv6 not supported by this check — returns no verdict rather than a guess" }
                $inNet = $true
                for ($i = 0; $i -lt 4; $i++) {
                    $bitsLeft = [math]::Max(0, [math]::Min(8, $bits - (8 * $i)))
                    $oct = 0
                    if ($bitsLeft -gt 0) { $oct = [int](256 - [math]::Pow(2, 8 - $bitsLeft)) }
                    if (([int]$ab[$i] -band $oct) -ne ([int]$nb[$i] -band $oct)) { $inNet = $false; break }
                }
                if ($inNet) { $score = 100; $reasons += "'$ipStr' is inside claimed network '$cidr'" }
                else { $score = 0; $reasons += "DRIFT: '$ipStr' is OUTSIDE claimed network '$cidr' — spoof or wrong scope" }
            } catch { $reasons += "ip-subnet check failed: $($_.Exception.Message)" }
        }
        "time-skew" {
            # A={utc}, B={utc} — two witnesses of the SAME event should
            # timestamp it nearly together. CheckParams.MaxSeconds (default 5).
            $maxSec = 5
            if ($CheckParams.ContainsKey("MaxSeconds")) { $maxSec = [double]$CheckParams["MaxSeconds"] }
            try {
                $ta = [datetime]$a.data.utc; $tb = [datetime]$b.data.utc
                $skew = [math]::Abs(($ta - $tb).TotalSeconds)
                if ($skew -le $maxSec) { $score = 100; $reasons += "witness timestamps agree within $([math]::Round($skew,2))s (limit ${maxSec}s)" }
                else { $score = 20; $reasons += "DRIFT: witness timestamps skew $([math]::Round($skew,1))s > ${maxSec}s — different events or clock tampering" }
            } catch { $reasons += "unparseable timestamps for time-skew check" }
        }
        "domain-age" {
            # A={registered} (domain creation, any parseable date), B={utc}
            # (event). CheckParams.MaxAgeDays (default 30): a domain younger
            # than this at event time is the classic phishing/throwaway
            # pattern. An event BEFORE registration is an impossible timeline.
            $maxDays = 30
            if ($CheckParams.ContainsKey("MaxAgeDays")) { $maxDays = [double]$CheckParams["MaxAgeDays"] }
            try {
                $reg = [datetime]$a.data.registered; $ev = [datetime]$b.data.utc
                $age = ($ev - $reg).TotalDays
                if ($age -lt 0) { $score = 35; $reasons += "DRIFT: event predates domain registration — impossible timeline" }
                elseif ($age -le $maxDays) { $score = 15; $reasons += "DRIFT: domain was $([math]::Round($age,1)) days old at event (<= $maxDays) — throwaway/phishing pattern" }
                else { $score = 100; $reasons += "domain was $([math]::Round($age,0)) days old at event — established" }
            } catch { $reasons += "unparseable dates for domain-age check" }
        }
        "ttl-os" {
            # A={ttl}, B={os} — does the observed IP TTL fit the claimed OS?
            # 64 -> unix-like (linux/macos/bsd/android/ios), 128 -> windows,
            # 255 -> network gear (cisco/juniper/router). One-hop-off values
            # tolerated (63/127/254). Heuristic, not proof — the reason says so.
            $ttl = 0; $ok = [int]::TryParse("$($a.data.ttl)", [ref]$ttl)
            $os = "$($b.data.os)".ToLower().Trim()
            if ($ok -and $os -ne "") {
                $expect = ""
                if ($ttl -ge 63 -and $ttl -le 64) { $expect = "unix-like" }
                elseif ($ttl -ge 127 -and $ttl -le 128) { $expect = "windows" }
                elseif ($ttl -ge 254 -and $ttl -le 255) { $expect = "network-gear" }
                if ($expect -eq "") { $score = 50; $reasons += "TTL $ttl not in a known OS fingerprint band (64/128/255) — no verdict" }
                else {
                    $unixHit = $os -match "linux|unix|bsd|mac|darwin|android|ios"
                    $winHit  = $os -match "windows|microsoft"
                    $netHit  = $os -match "cisco|juniper|router|switch|network"
                    $fits = ($expect -eq "unix-like" -and $unixHit) -or ($expect -eq "windows" -and $winHit) -or ($expect -eq "network-gear" -and $netHit)
                    if ($fits) { $score = 100; $reasons += "TTL $ttl fits claimed OS family '$($b.data.os)' (heuristic)" }
                    else { $score = 40; $reasons += "DRIFT: TTL $ttl implies $expect stack but source claims '$($b.data.os)' — possible NAT or OS spoof (heuristic)" }
                }
            } else { $reasons += "insufficient data for ttl-os check" }
        }
        "url-domain" {
            # A={url}, B={domain} — does the URL's host match the claimed
            # domain (exact or subdomain)? A login/alert link pointing
            # elsewhere is the classic lookalike-phishing signal.
            # v1.4: accepts scheme-less hosts ("mail.example.com/inbox"),
            # which used to die as unparseable.
            try {
                $raw = "$($a.data.url)".Trim()
                if ($raw -ne "" -and $raw -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $raw = "http://" + $raw }
                $u = [System.Uri]$raw
                $uHost = $u.Host.ToLower().Trim().TrimEnd(".")
                $dom = "$($b.data.domain)".ToLower().Trim().TrimEnd(".")
                if ($uHost -eq "" -or $dom -eq "") { $reasons += "insufficient data for url-domain check" }
                elseif ($uHost -eq $dom -or $uHost.EndsWith("." + $dom)) {
                    $score = 100; $reasons += "URL host '$uHost' matches claimed domain '$dom'"
                }
                else { $score = 30; $reasons += "DRIFT: URL host '$uHost' is not the claimed domain '$dom' — lookalike or redirect risk" }
            } catch { $reasons += "url-domain check failed: unparseable URL '$($a.data.url)'" }
        }
        "email-domain" {
            # A={email}, B={domain} — does the sender's address domain match
            # the identity the message claims to represent? Heuristic, not
            # proof: mailing infrastructure (SPF/SRS) can legitimately differ.
            # v1.4: extracts the addr-spec from display-name forms —
            # "Jane Doe <jane@example.com>" used to false-DRIFT because the
            # trailing ">" became part of the domain ("example.com>").
            $em = "$($a.data.email)".Trim()
            $lt = $em.LastIndexOf("<"); $gt = $em.LastIndexOf(">")
            if ($lt -ge 0 -and $gt -gt $lt) { $em = $em.Substring($lt + 1, $gt - $lt - 1).Trim() }
            $dom = "$($b.data.domain)".ToLower().Trim().TrimEnd(".")
            $at = $em.LastIndexOf("@")
            if ($at -gt 0 -and $dom -ne "") {
                $mailDom = $em.Substring($at + 1).ToLower().Trim().TrimEnd(".")
                if ($mailDom -eq $dom -or $mailDom.EndsWith("." + $dom)) {
                    $score = 100; $reasons += "sender domain '$mailDom' matches '$dom'"
                }
                else { $score = 30; $reasons += "DRIFT: email from '$mailDom' claims to represent '$dom' — spoof risk (heuristic)" }
            } else { $reasons += "insufficient data for email-domain check" }
        }
        "port-banner" {
            # A={port}, B={banner} — does the grabbed banner carry keywords
            # of the service the port table expects? Catches mislabeled
            # services and tunneled protocols on well-known ports.
            $port = 0
            $portOk = [int]::TryParse("$($a.data.port)", [ref]$port)
            $banner = "$($b.data.banner)".ToLower().Trim()
            if ($portOk -and $banner -ne "") {
                $kw = Get-PortServiceKeywordTable
                if ($kw.ContainsKey($port)) {
                    $hit = $false
                    foreach ($term in $kw[$port]) { if ($banner.Contains($term)) { $hit = $true; break } }
                    if ($hit) { $score = 100; $reasons += "banner on port $port matches expected service keywords" }
                    else { $score = 35; $reasons += "DRIFT: port $port banner '$($b.data.banner)' carries none of the expected service keywords — mislabeled or tunneled service" }
                } else { $reasons += "port $port has no keyword entry — no check possible" }
            } else { $reasons += "insufficient data for port-banner check" }
        }
        "mac-vendor" {
            # A={mac}, B={vendor} — does the observed MAC's OUI (first 3
            # octets) match the claimed hardware vendor? Normalizes colon,
            # dash, and dot forms. Unknown OUI is neutral, never a spoof claim.
            $normMac = {
                param($raw)
                return ("$raw".ToUpper() -replace '[^0-9A-F]', '')
            }
            $m = & $normMac $a.data.mac
            $vendor = "$($b.data.vendor)".Trim()
            if ($m.Length -ge 6 -and $vendor -ne "") {
                $oui = $m.Substring(0, 6)
                $table = Get-OuiVendorTable
                if ($table.ContainsKey($oui)) {
                    $known = $table[$oui]
                    $vl = $vendor.ToLower()
                    if ($known.ToLower().Contains($vl) -or $vl.Contains($known.ToLower())) {
                        $score = 100; $reasons += "OUI $oui -> '$known' matches claimed vendor '$vendor'"
                    } else { $score = 40; $reasons += "DRIFT: OUI $oui is '$known' but source claims '$vendor' — spoofed MAC or wrong inventory" }
                } else { $score = 50; $reasons += "OUI $oui not in shipped vendor table — no verdict" }
            } else { $reasons += "insufficient data for mac-vendor check" }
        }
        "hash-verify" {
            # A={data}, B={sha256} — RECOMPUTE: does the claimed SHA-256
            # equal the actual SHA-256 of the data's canonical form?
            # Catches tampered evidence where the hash field was hand-edited
            # but the bytes weren't (the whole point of the coherence core).
            # v1.4: a malformed claim is reported as MALFORMED, not lumped
            # into "mismatch" — a bad claim and a tampered evidence item are
            # different findings with different next steps.
            $claimed = "$($b.data.sha256)".ToLower().Trim()
            if ($claimed -ne "" -and $null -ne $a.data) {
                if ($claimed -notmatch '^[0-9a-f]{64}$') {
                    $score = 0
                    $reasons += "MALFORMED: claimed hash '$claimed' is not a 64-char hex SHA-256 — integrity cannot be evaluated, re-collect the hash"
                } else {
                    $actual = Get-Sha256Hex (ConvertTo-CanonicalJson $a.data)
                    if ($actual -eq $claimed) {
                        $score = 100; $reasons += "recomputed SHA-256 matches claimed value — bytes intact"
                    } else {
                        $c16 = $claimed.Substring(0, 16)
                        $score = 0; $reasons += "HASH MISMATCH: claimed ${c16}... but data hashes to $($actual.Substring(0,16))... — bytes were altered after hashing"
                    }
                }
            } else { $reasons += "insufficient data for hash-verify check (needs A.data + B.sha256)" }
        }
        "geo-agree" {
            # A={geoA}, B={geoB} — two independent geo sources (country code
            # or name) for the same IP. A mismatch is anycast, VPN egress, or
            # a stale GeoIP database — divergence, not proof of anything.
            $ga = "$($a.data.geoA)".Trim(); $gb = "$($b.data.geoB)".Trim()
            if ($ga -ne "" -and $gb -ne "") {
                $na = ConvertTo-CountryName $ga; $nb = ConvertTo-CountryName $gb
                if ($na -eq $nb) { $score = 90; $reasons += "geo sources agree: '$($a.data.geoA)' / '$($b.data.geoB)' -> $na" }
                else { $score = 35; $reasons += "DIVERGED: geo '$($a.data.geoA)' vs '$($b.data.geoB)' — anycast, VPN egress, or stale DB" }
            } else { $reasons += "insufficient data for geo-agree check" }
        }
        "file-magic" {
            # A={extension}, B={magicHex} — do the file's first bytes match
            # what its extension claims? An .exe renamed to .pdf (or a .pdf
            # dropper that is really a .zip) is the classic mislabelled
            # payload / double-extension signal. magicHex is the first bytes
            # as a hex string (spaces/colons tolerated). Pure table lookup,
            # no I/O. Text formats (txt/csv/ps1/html/xml) have no magic and
            # are honestly neutral, not forced to pass or fail.
            $ext = "$($a.data.extension)".ToLower().Trim()
            if ($ext.StartsWith(".")) { $ext = $ext.Substring(1) }
            $magic = ("$($b.data.magicHex)".ToUpper() -replace '[^0-9A-F]','')
            if ($ext -ne "" -and $magic -ne "") {
                $mt = Get-FileMagicTable
                if ($mt.ContainsKey($ext)) {
                    $entry = $mt[$ext]
                    if ($entry.Text) {
                        $score = 50; $reasons += ".$ext is a text format — magic-byte check not applicable"
                    } else {
                        $hit = $false
                        foreach ($sig in $entry.Sigs) { if ($magic.StartsWith($sig)) { $hit = $true; break } }
                        if ($hit) {
                            $shown = $magic.Substring(0, [math]::Min(8, $magic.Length))
                            $score = 100; $reasons += ".$ext magic ${shown}... matches $($entry.Name) signature"
                        } else {
                            $actual = "unrecognized binary"
                            $rt = Get-MagicTypeTable
                            foreach ($sig in ($rt.Keys | Sort-Object { $_.Length } -Descending)) {
                                if ($magic.StartsWith($sig)) { $actual = $rt[$sig]; break }
                            }
                            $shown = $magic.Substring(0, [math]::Min(8, $magic.Length))
                            $score = 0
                            $reasons += "MISMATCH: file claims '.$ext' ($($entry.Name)) but first bytes ${shown}... read as '$actual' — renamed binary / double-extension signal"
                        }
                    }
                } else { $score = 50; $reasons += ".$ext not in shipped magic table — no verdict" }
            } else { $reasons += "insufficient data for file-magic check (needs extension + magicHex)" }
        }
        "cert-issuer" {
            # A={issuer}, B={subject} — self-signed, known public CA, or
            # unknown? A "secure login" page served on a self-signed cert is
            # the classic interception/MITM signal. Unknown issuers are
            # NEUTRAL (enterprise private CAs are legitimate) — never a
            # spoof claim.
            $iss = "$($a.data.issuer)".Trim()
            $sub = "$($b.data.subject)".Trim()
            if ($iss -ne "" -and $sub -ne "") {
                if ($iss -eq $sub) {
                    $score = 40; $reasons += "self-signed certificate (issuer == subject) — fine for dev/lab, suspect on a public login page"
                } else {
                    $known = $false; $ca = ""
                    foreach ($row in Get-TrustedCaKeywordTable) {
                        if ($iss -like ("*" + $row.Keyword + "*")) { $known = $true; $ca = $row.Ca; break }
                    }
                    if ($known) { $score = 100; $reasons += "issuer '$iss' matches known public CA ($ca)" }
                    else { $score = 50; $reasons += "issuer '$iss' not in shipped CA table — no verdict (private/enterprise CAs are legitimate)" }
                }
            } else { $reasons += "insufficient data for cert-issuer check" }
        }
        default { $reasons += "no check defined for type '$check'" }
    }
    return [pscustomobject]@{ score = $score; check = $check; reasons = $reasons; coherent = ($score -ge 70) }
}

function Get-PortServiceKeywordTable {
    <#
    Port -> lowercase keyword list for the port-banner check. A banner that
    carries none of the expected keywords for its port is mislabeled or a
    tunneled service. Common protocol banners only; honest limit: exotic
    services and custom banners will read as DRIFT.
    #>
    return @{
        21  = @("ftp")
        22  = @("ssh")
        23  = @("telnet")
        25  = @("smtp", "postfix", "exim", "sendmail")
        53  = @("dns", "bind", "named")
        80  = @("http", "nginx", "apache", "iis")
        110 = @("pop3")
        119 = @("nntp")
        143 = @("imap")
        443 = @("http", "https", "nginx", "apache", "iis", "tls", "ssl")
        445 = @("smb", "samba")
        1433 = @("mssql", "sql server")
        3306 = @("mysql", "mariadb")
        3389 = @("rdp", "terminal")
        5432 = @("postgres", "postgresql")
        5900 = @("rfb", "vnc")
        6379 = @("redis")
        8080 = @("http", "proxy", "nginx", "apache")
        27017 = @("mongo")
    }
}

function Get-OuiVendorTable {
    <#
    Shipped MAC OUI (first 6 hex digits, uppercase, no separators) ->
    vendor name. Common enterprise/consumer hardware only — a small honest
    subset, NOT the full IEEE registry (30k+ entries). An unknown OUI is a
    neutral "no verdict", never a claim of spoofing.
    #>
    return @{
        # Apple
        "0017F2"="Apple"; "0023DF"="Apple"; "00254A"="Apple"; "00D9D1"="Apple"
        "04E5A0"="Apple"; "7C6D62"="Apple"
        # Cisco
        "00000C"="Cisco"; "000142"="Cisco"; "0019E7"="Cisco"; "0022BD"="Cisco"
        "005073"="Cisco"; "F8B7E2"="Cisco"
        # Dell
        "000BDB"="Dell"; "001422"="Dell"; "002564"="Dell"; "180373"="Dell"
        "B8CA3A"="Dell"; "EC388F"="Dell"
        # HP
        "001279"="HP"; "0019BB"="HP"; "002481"="HP"; "2C44FD"="HP"
        "B4B52F"="HP"; "E02A82"="HP"
        # Intel (NICs)
        "0018DE"="Intel"; "00222B"="Intel"; "34E12D"="Intel"; "3C22FB"="Intel"
        "7CB2B2"="Intel"; "A0369F"="Intel"
        # Lenovo
        "00215E"="Lenovo"; "18E7F4"="Lenovo"; "5C3D2E"="Lenovo"; "F80D60"="Lenovo"
        # Samsung
        "001632"="Samsung"; "283EFA"="Samsung"; "8CE748"="Samsung"; "D4E8B2"="Samsung"
        # Google
        "F4F5E8"="Google"; "54EE75"="Google"; "3C5AB4"="Google"; "94EB2C"="Google"
        # Amazon
        "0C47C9"="Amazon"; "FC65DE"="Amazon"; "6854FD"="Amazon"; "68D1BA"="Amazon"
        # Microsoft
        "001DD8"="Microsoft"; "28D244"="Microsoft"; "C02FA5"="Microsoft"; "7CE9D3"="Microsoft"
        # Asus
        "002215"="Asus"; "1C872C"="Asus"; "2CF0EE"="Asus"
        # TP-Link
        "14CC20"="TP-Link"; "B0487A"="TP-Link"; "F4EC38"="TP-Link"
        # Netgear
        "001F33"="Netgear"; "20E52A"="Netgear"; "A0E4CB"="Netgear"
        # Ubiquiti
        "0418D6"="Ubiquiti"; "78C6BD"="Ubiquiti"
        # Huawei
        "000E10"="Huawei"; "00E05A"="Huawei"
        # Xiaomi
        "147DDA"="Xiaomi"; "34CE00"="Xiaomi"
    }
}

function Get-FileMagicTable {
    <#
    Extension (no dot, lowercase) -> @{ Name="friendly type"; Sigs=@(hex prefixes) }.
    Sigs are the file's FIRST bytes as uppercase hex — the check only sees
    the head of the file, so mid-file signatures (mp4 "ftyp" at offset 4)
    are honestly out of scope and not listed. Text formats carry Text=$true
    (no magic exists; the check stays neutral, never forces pass/fail).
    Honest limit: exotic formats and custom binaries read as "no verdict".
    #>
    return @{
        "pdf"  = @{ Name = "PDF document";        Sigs = @("25504446") }
        "exe"  = @{ Name = "Windows executable";  Sigs = @("4D5A") }
        "dll"  = @{ Name = "Windows executable";  Sigs = @("4D5A") }
        "msi"  = @{ Name = "Windows installer";   Sigs = @("D0CF11E0A1B11AE1") }
        "png"  = @{ Name = "PNG image";           Sigs = @("89504E470D0A1A0A") }
        "gif"  = @{ Name = "GIF image";           Sigs = @("47494638") }
        "jpg"  = @{ Name = "JPEG image";          Sigs = @("FFD8FF") }
        "jpeg" = @{ Name = "JPEG image";          Sigs = @("FFD8FF") }
        "bmp"  = @{ Name = "BMP image";           Sigs = @("424D") }
        "tif"  = @{ Name = "TIFF image";          Sigs = @("49492A00","4D4D002A") }
        "tiff" = @{ Name = "TIFF image";          Sigs = @("49492A00","4D4D002A") }
        "ico"  = @{ Name = "Windows icon";        Sigs = @("00000100") }
        "zip"  = @{ Name = "ZIP archive";         Sigs = @("504B0304","504B0506","504B0708") }
        "docx" = @{ Name = "Office Open XML";     Sigs = @("504B0304") }
        "xlsx" = @{ Name = "Office Open XML";     Sigs = @("504B0304") }
        "pptx" = @{ Name = "Office Open XML";     Sigs = @("504B0304") }
        "jar"  = @{ Name = "Java archive";        Sigs = @("504B0304") }
        "7z"   = @{ Name = "7-Zip archive";       Sigs = @("377ABCAF271C") }
        "rar"  = @{ Name = "RAR archive";         Sigs = @("526172211A0700","526172211A070100") }
        "mp3"  = @{ Name = "MP3 audio";           Sigs = @("494433","FFFB","FFF3","FFF2") }
        "wav"  = @{ Name = "WAV audio";           Sigs = @("52494646") }
        "doc"  = @{ Name = "legacy Office (OLE)"; Sigs = @("D0CF11E0A1B11AE1") }
        "xls"  = @{ Name = "legacy Office (OLE)"; Sigs = @("D0CF11E0A1B11AE1") }
        "ppt"  = @{ Name = "legacy Office (OLE)"; Sigs = @("D0CF11E0A1B11AE1") }
        "class"= @{ Name = "Java class";          Sigs = @("CAFEBABE") }
        "elf"  = @{ Name = "ELF executable";      Sigs = @("7F454C46") }
        "txt"  = @{ Name = "plain text";          Text = $true }
        "csv"  = @{ Name = "plain text";          Text = $true }
        "log"  = @{ Name = "plain text";          Text = $true }
        "ps1"  = @{ Name = "PowerShell script";   Text = $true }
        "bat"  = @{ Name = "batch script";        Text = $true }
        "cmd"  = @{ Name = "batch script";        Text = $true }
        "vbs"  = @{ Name = "VBScript";            Text = $true }
        "js"   = @{ Name = "JavaScript";          Text = $true }
        "html" = @{ Name = "HTML document";       Text = $true }
        "htm"  = @{ Name = "HTML document";       Text = $true }
        "xml"  = @{ Name = "XML document";        Text = $true }
        "json" = @{ Name = "JSON document";       Text = $true }
    }
}

function Get-MagicTypeTable {
    <#
    Reverse lookup for the file-magic check: magic prefix (uppercase hex) ->
    friendly type name. Used ONLY to name what a mismatched file actually
    looks like — best-effort labeling, not identification. Longer prefixes
    must be tried before shorter ones (callers sort by length descending).
    #>
    return @{
        "255044462D" = "PDF document"
        "25504446"   = "PDF document"
        "4D5A"       = "Windows executable (MZ)"
        "89504E47"   = "PNG image"
        "47494638"   = "GIF image"
        "FFD8FF"     = "JPEG image"
        "504B0304"   = "ZIP / Office Open XML / JAR archive"
        "377ABCAF"   = "7-Zip archive"
        "52617221"   = "RAR archive"
        "494433"     = "MP3 audio (ID3 tag)"
        "FFFB"       = "MP3 audio"
        "52494646"   = "WAV/AVI (RIFF)"
        "424D"       = "BMP image"
        "49492A00"   = "TIFF image (little-endian)"
        "4D4D002A"   = "TIFF image (big-endian)"
        "00000100"   = "Windows icon"
        "7F454C46"   = "ELF executable"
        "D0CF11E0"   = "legacy Office (OLE compound)"
        "CAFEBABE"   = "Java class / Mach-O"
        "1F8B08"     = "gzip stream"
        "425A68"     = "bzip2 stream"
        "FD377A585A00" = "xz stream"
    }
}

function Get-TrustedCaKeywordTable {
    <#
    Shipped public-CA keyword table for the cert-issuer check. Each row:
    Keyword (matched as a case-insensitive substring of the issuer string)
    -> Ca (display name). The widely-trusted public CAs only — an issuer
    absent from this table is NEUTRAL ("no verdict"), never untrusted:
    enterprise private CAs are legitimate.
    #>
    return @(
        [pscustomobject]@{ Keyword = "Let's Encrypt";  Ca = "Let's Encrypt (ISRG)" }
        [pscustomobject]@{ Keyword = "ISRG";           Ca = "Let's Encrypt (ISRG)" }
        [pscustomobject]@{ Keyword = "IdenTrust";      Ca = "IdenTrust (cross-signs LE)" }
        [pscustomobject]@{ Keyword = "DigiCert";       Ca = "DigiCert" }
        [pscustomobject]@{ Keyword = "GlobalSign";     Ca = "GlobalSign" }
        [pscustomobject]@{ Keyword = "Sectigo";        Ca = "Sectigo" }
        [pscustomobject]@{ Keyword = "Comodo";         Ca = "Sectigo (ex-Comodo)" }
        [pscustomobject]@{ Keyword = "GoDaddy";        Ca = "GoDaddy" }
        [pscustomobject]@{ Keyword = "Starfield";      Ca = "GoDaddy (Starfield)" }
        [pscustomobject]@{ Keyword = "Entrust";        Ca = "Entrust" }
        [pscustomobject]@{ Keyword = "Microsoft";      Ca = "Microsoft" }
        [pscustomobject]@{ Keyword = "Google Trust";   Ca = "Google Trust Services" }
        [pscustomobject]@{ Keyword = "GTS CA";         Ca = "Google Trust Services" }
        [pscustomobject]@{ Keyword = "Amazon";         Ca = "Amazon Trust Services" }
        [pscustomobject]@{ Keyword = "Cloudflare";     Ca = "Cloudflare" }
        [pscustomobject]@{ Keyword = "ZeroSSL";        Ca = "ZeroSSL" }
        [pscustomobject]@{ Keyword = "SSL.com";        Ca = "SSL.com" }
        [pscustomobject]@{ Keyword = "Buypass";        Ca = "Buypass" }
        [pscustomobject]@{ Keyword = "VeriSign";       Ca = "VeriSign (DigiCert)" }
        [pscustomobject]@{ Keyword = "Symantec";       Ca = "Symantec (DigiCert)" }
        [pscustomobject]@{ Keyword = "Thawte";         Ca = "Thawte (DigiCert)" }
        [pscustomobject]@{ Keyword = "RapidSSL";       Ca = "RapidSSL (DigiCert)" }
        [pscustomobject]@{ Keyword = "GeoTrust";       Ca = "GeoTrust (DigiCert)" }
        [pscustomobject]@{ Keyword = "QuoVadis";       Ca = "QuoVadis" }
        [pscustomobject]@{ Keyword = "SwissSign";      Ca = "SwissSign" }
        [pscustomobject]@{ Keyword = "Apple";          Ca = "Apple" }
    )
}

function ConvertTo-CountryName {
    <#
    Normalizes a geo value to a lowercase English country name. Accepts an
    ISO-3166-1 alpha-2 code or a free-text name; unknown codes pass through
    lowercased so two identical unknown values still agree. Shipped table
    covers the countries most commonly seen in geo attribution; it is not
    the full 249-code list.
    #>
    param([Parameter(Mandatory=$true)][string]$geo)
    $g = $geo.Trim().ToLower()
    $t = @{
        "us"="united states"; "usa"="united states"; "ca"="canada"; "mx"="mexico";
        "br"="brazil"; "ar"="argentina"; "cl"="chile"; "co"="colombia"; "pe"="peru";
        "gb"="united kingdom"; "uk"="united kingdom"; "ie"="ireland"; "de"="germany";
        "fr"="france"; "nl"="netherlands"; "be"="belgium"; "es"="spain"; "pt"="portugal";
        "it"="italy"; "ch"="switzerland"; "at"="austria"; "se"="sweden"; "no"="norway";
        "dk"="denmark"; "fi"="finland"; "pl"="poland"; "cz"="czechia"; "sk"="slovakia";
        "hu"="hungary"; "ro"="romania"; "bg"="bulgaria"; "gr"="greece"; "ua"="ukraine";
        "ru"="russia"; "by"="belarus"; "tr"="turkey"; "il"="israel"; "ae"="united arab emirates";
        "sa"="saudi arabia"; "eg"="egypt"; "za"="south africa"; "ng"="nigeria"; "ke"="kenya";
        "in"="india"; "pk"="pakistan"; "bd"="bangladesh"; "lk"="sri lanka"; "np"="nepal";
        "cn"="china"; "hk"="hong kong"; "tw"="taiwan"; "jp"="japan"; "kr"="south korea";
        "kp"="north korea"; "sg"="singapore"; "my"="malaysia"; "th"="thailand"; "vn"="vietnam";
        "ph"="philippines"; "id"="indonesia"; "au"="australia"; "nz"="new zealand";
        "is"="iceland"; "ee"="estonia"; "lv"="latvia"; "lt"="lithuania"; "lu"="luxembourg";
        "mt"="malta"; "cy"="cyprus"; "md"="moldova"; "rs"="serbia"; "hr"="croatia";
        "si"="slovenia"; "ba"="bosnia and herzegovina"; "al"="albania"; "mk"="north macedonia";
        "ge"="georgia"; "am"="armenia"; "az"="azerbaijan"; "kz"="kazakhstan"
    }
    if ($g.Length -eq 2 -and $t.ContainsKey($g)) { return $t[$g] }
    if ($t.ContainsKey($g)) { return $t[$g] }
    return $g
}

function Measure-AttributionConvergence {
    <#
    N sources each claiming an attribution string. Returns converged/diverged.
    Converged when the top value holds >= Threshold percent of non-empty
    claims (default 60). Raise the threshold when the stakes are higher.
    #>
    param(
        [Parameter(Mandatory=$true)][array]$claims,
        [double]$Threshold = 60
    )
    $norm = @()
    foreach ($c in $claims) {
        $v = "$($c.value)".Trim().ToLower()
        if ($v -ne "") { $norm += [pscustomobject]@{ value = $v; source = "$($c.source)" } }
    }
    if ($norm.Count -eq 0) {
        return [pscustomobject]@{ verdict = "no-data"; agreement = 0; breakdown = @() }
    }
    # Deterministic order: count descending, then name ascending, so ties
    # always resolve to the same top value on every machine, every run.
    $groups = $norm | Group-Object value | Sort-Object @{Expression={$_.Count};Descending=$true}, @{Expression={$_.Name}}
    $top = $groups[0]
    $agreement = [math]::Round(($top.Count / $norm.Count) * 100, 1)
    $breakdown = @()
    foreach ($g in $groups) {
        $breakdown += [pscustomobject]@{
            value   = $g.Name
            count   = $g.Count
            sources = @($g.Group | ForEach-Object { $_.source })
        }
    }
    $verdict = "diverged"
    if ($agreement -ge $Threshold) { $verdict = "converged" }
    return [pscustomobject]@{
        verdict   = $verdict
        agreement = $agreement
        top       = $top.Name
        threshold = $Threshold
        breakdown = $breakdown
    }
}

function Test-Drift {
    <#
    Compares baseline vs current state. Each is a hashtable key -> value
    (values compared by canonical JSON). Returns added/removed/changed.
    -IgnoreKeys skips volatile keys (e.g. "lastSeen") so routine churn
    does not read as drift. Deterministic: output sorted by key.
    #>
    param(
        [Parameter(Mandatory=$true)]$baseline,
        [Parameter(Mandatory=$true)]$current,
        [string[]]$IgnoreKeys = @()
    )
    # Guard: drift is only defined over key->value maps. Returning a
    # structured error object beats throwing inside a forensic pipeline.
    if ($baseline -isnot [System.Collections.IDictionary] -or $current -isnot [System.Collections.IDictionary]) {
        return [pscustomobject]@{
            added   = @()
            removed = @()
            changed = @()
            clean   = $false
            error   = "baseline and current must both be dictionaries/hashtables"
        }
    }
    $added = @(); $removed = @(); $changed = @()
    $ignore = @($IgnoreKeys | ForEach-Object { "$_" })
    $bKeys = @($baseline.Keys | Where-Object { $ignore -notcontains "$_" } | Sort-Object)
    $cKeys = @($current.Keys  | Where-Object { $ignore -notcontains "$_" } | Sort-Object)
    foreach ($k in $cKeys) { if ($bKeys -notcontains $k) { $added += $k } }
    foreach ($k in $bKeys) { if ($cKeys -notcontains $k) { $removed += $k } }
    foreach ($k in $bKeys) {
        if ($cKeys -contains $k) {
            $bj = ConvertTo-CanonicalJson $baseline[$k]
            $cj = ConvertTo-CanonicalJson $current[$k]
            if ($bj -ne $cj) {
                $changed += [pscustomobject]@{ key = $k; was = $baseline[$k]; now = $current[$k] }
            }
        }
    }
    return [pscustomobject]@{
        added   = $added
        removed = $removed
        changed = $changed
        clean   = ($added.Count -eq 0 -and $removed.Count -eq 0 -and $changed.Count -eq 0)
    }
}

function New-Receipt {
    <#
    Verifiable receipt for one intelligence conclusion. Chain: receipt hash =
    SHA-384(canonical(evidence hashes + conclusion + prev receipt hash)).
    Pass $prevHash = "" for the first receipt in a chain.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$conclusion,
        [Parameter(Mandatory=$true)][array]$evidenceHashes,
        [string]$prevHash = "",
        [string]$utc = ""
    )
    if ([string]::IsNullOrEmpty($utc)) { $utc = (Get-Date).ToUniversalTime().ToString("o") }
    $sorted = @($evidenceHashes | Sort-Object)
    $payload = @{
        conclusion = $conclusion
        evidence   = $sorted
        prev       = $prevHash
        utc        = $utc
    }
    $canon = ConvertTo-CanonicalJson $payload
    $rh = Get-Sha384Hex $canon
    return [pscustomobject]@{
        conclusion = $conclusion
        evidence   = $sorted
        prev       = $prevHash
        utc        = $utc
        receipt    = $rh
    }
}

function Test-ReceiptChain {
    <#
    Verifies a receipt chain. Default: stops at the first bad receipt and
    reports its index (backward compatible). -AllErrors collects every bad
    index instead, so a long chain gets one full failure report, not a
    fix-one-find-one loop.
    #>
    param(
        [Parameter(Mandatory=$true)][array]$receipts,
        [switch]$AllErrors
    )
    $prev = ""
    $failures = @()
    for ($i = 0; $i -lt $receipts.Count; $i++) {
        $r = $receipts[$i]
        if ($r.prev -ne $prev) {
            $f = [pscustomobject]@{ index = $i; reason = "prev hash break at index $i" }
            if ($AllErrors) { $failures += $f; continue }
            return [pscustomobject]@{ valid = $false; badIndex = $i; badIndices = @($i); reason = $f.reason; count = $receipts.Count }
        }
        $check = New-Receipt -conclusion $r.conclusion -evidenceHashes $r.evidence -prevHash $r.prev -utc $r.utc
        if ($check.receipt -ne $r.receipt) {
            $f = [pscustomobject]@{ index = $i; reason = "receipt hash mismatch at index $i" }
            if ($AllErrors) { $failures += $f; continue }
            return [pscustomobject]@{ valid = $false; badIndex = $i; badIndices = @($i); reason = $f.reason; count = $receipts.Count }
        }
        $prev = $r.receipt
    }
    if ($failures.Count -gt 0) {
        return [pscustomobject]@{
            valid = $false; badIndex = $failures[0].index
            badIndices = @($failures | ForEach-Object { $_.index })
            reason = ($failures | ForEach-Object { $_.reason }) -join "; "
            count = $receipts.Count
        }
    }
    return [pscustomobject]@{ valid = $true; badIndex = -1; badIndices = @(); reason = ""; count = $receipts.Count }
}

function Get-CoherenceChecks {
    <#
    Registry of every check Test-Coherence supports: name, the fields each
    side must carry, and what a pass means. Callers (and the test harness)
    use this instead of hardcoding check names.
    #>
    return @(
        [pscustomobject]@{ name = "process-port"; aFields = "process,port";   bFields = "process,port";   meaning = "independent source confirms which process holds the port" }
        [pscustomobject]@{ name = "dns-sni";      aFields = "dns";            bFields = "sni";            meaning = "observed DNS query matches the TLS SNI actually used" }
        [pscustomobject]@{ name = "rdap-asn";     aFields = "rdapOrg";        bFields = "asnOrg";         meaning = "RDAP registrant org agrees with routing (ASN) org" }
        [pscustomobject]@{ name = "hash-match";   aFields = "sha256";         bFields = "sha256";         meaning = "both sources hold byte-identical data" }
        [pscustomobject]@{ name = "time-order";   aFields = "utc";            bFields = "utc";            meaning = "claimed event order matches timestamps" }
        [pscustomobject]@{ name = "ip-match";     aFields = "ip";             bFields = "ip";             meaning = "both sources point at the same address (normalized)" }
        [pscustomobject]@{ name = "domain-cert";  aFields = "domain";         bFields = "certName";       meaning = "presented certificate (incl. wildcard) covers the domain" }
        [pscustomobject]@{ name = "port-service"; aFields = "port";           bFields = "service";        meaning = "claimed service matches the shipped port table" }
        [pscustomobject]@{ name = "cert-time";    aFields = "notBefore,notAfter"; bFields = "utc";        meaning = "event falls inside the certificate validity window" }
        [pscustomobject]@{ name = "ip-subnet";    aFields = "ip";             bFields = "cidr";           meaning = "observed address falls inside the claimed IPv4 network" }
        [pscustomobject]@{ name = "time-skew";    aFields = "utc";            bFields = "utc";            meaning = "two witnesses of the same event timestamp it within MaxSeconds (default 5)" }
        [pscustomobject]@{ name = "domain-age";   aFields = "registered";     bFields = "utc";            meaning = "domain older than MaxAgeDays (default 30) at event time — not a throwaway" }
        [pscustomobject]@{ name = "ttl-os";       aFields = "ttl";             bFields = "os";             meaning = "observed IP TTL fits the claimed OS family (64/128/255 bands, heuristic)" }
        [pscustomobject]@{ name = "url-domain";   aFields = "url";            bFields = "domain";         meaning = "the URL's host matches the claimed domain, exact or subdomain (lookalike-phishing signal)" }
        [pscustomobject]@{ name = "email-domain"; aFields = "email";          bFields = "domain";         meaning = "the sender's domain matches the identity the message claims (heuristic)" }
        [pscustomobject]@{ name = "port-banner";  aFields = "port";           bFields = "banner";         meaning = "grabbed banner carries keywords of the service the port table expects" }
        [pscustomobject]@{ name = "mac-vendor";   aFields = "mac";            bFields = "vendor";         meaning = "the MAC's OUI matches the claimed hardware vendor (unknown OUI = no verdict)" }
        [pscustomobject]@{ name = "hash-verify";  aFields = "data";           bFields = "sha256";         meaning = "recomputed SHA-256 of the data equals the claimed hash — bytes intact" }
        [pscustomobject]@{ name = "geo-agree";    aFields = "geoA";           bFields = "geoB";           meaning = "two independent geo sources for the same IP agree on country" }
        [pscustomobject]@{ name = "file-magic";   aFields = "extension";      bFields = "magicHex";       meaning = "the file's first bytes match what its extension claims (renamed-binary/dropper signal)" }
        [pscustomobject]@{ name = "cert-issuer";  aFields = "issuer";         bFields = "subject";        meaning = "certificate is self-signed, from a known public CA, or unknown (neutral — private CAs are legitimate)" }
    )
}

function Get-PortServiceTable {
    <#
    Shipped port -> service table used by the port-service check.
    Values are lowercase service names; "/" separates accepted aliases.
    Sources: IANA assignments + the netscan module's 70-port table.
    #>
    $t = @{}
    $t[20]="ftp"; $t[21]="ftp"; $t[22]="ssh"; $t[23]="telnet"; $t[25]="smtp"
    $t[53]="dns"; $t[67]="dhcp"; $t[68]="dhcp"; $t[69]="tftp"; $t[80]="http"
    $t[88]="kerberos"; $t[110]="pop3"; $t[119]="nntp"; $t[123]="ntp"; $t[135]="msrpc"
    $t[137]="netbios-ns"; $t[138]="netbios-dgm"; $t[139]="netbios-ssn"; $t[143]="imap"
    $t[161]="snmp"; $t[162]="snmptrap"; $t[179]="bgp"; $t[194]="irc"; $t[389]="ldap"
    $t[443]="https"; $t[445]="smb"; $t[465]="smtps"; $t[514]="syslog"; $t[515]="printer"
    $t[520]="rip"; $t[546]="dhcpv6"; $t[547]="dhcpv6"; $t[563]="nntps"; $t[587]="submission"
    $t[593]="msrpc"; $t[636]="ldaps"; $t[993]="imaps"; $t[995]="pop3s"; $t[1080]="socks"
    $t[1194]="openvpn"; $t[1433]="mssql"; $t[1434]="mssql"; $t[1521]="oracle"
    $t[1723]="pptp"; $t[2049]="nfs"; $t[2082]="cpanel"; $t[2083]="cpanel-ssl"
    $t[2375]="docker"; $t[2376]="docker-tls"; $t[3128]="squid"; $t[3306]="mysql"
    $t[3389]="rdp"; $t[3690]="svn"; $t[4369]="epmd"; $t[5000]="http-alt/upnp"
    $t[5432]="postgres/postgresql"; $t[5631]="pcanywhere"; $t[5672]="rabbitmq/amqp"
    $t[5900]="vnc"; $t[5985]="winrm"; $t[5986]="winrm-ssl"; $t[6379]="redis"
    $t[6443]="kubernetes"; $t[7001]="weblogic"; $t[8000]="http-alt"; $t[8008]="http-alt"
    $t[8080]="http-proxy"; $t[8081]="http-alt"; $t[8443]="https-alt"; $t[8888]="http-alt"
    $t[9000]="php-fpm/sonar"; $t[9090]="http-alt"; $t[9200]="elasticsearch"; $t[9300]="elasticsearch"
    $t[11211]="memcached"; $t[27017]="mongodb"; $t[27018]="mongodb"
    # Expanded 2026-10-30: more IANA-assigned services so port-service can
    # check old-school and protocol ports, not just the modern defaults.
    $t[7]="echo"; $t[11]="systat"; $t[13]="daytime"; $t[19]="chargen"
    $t[37]="time"; $t[42]="nameserver"; $t[43]="whois"; $t[49]="tacacs"
    $t[70]="gopher"; $t[79]="finger"; $t[109]="pop2"; $t[113]="ident"
    $t[118]="sqlserv"; $t[156]="sqlsrv"; $t[177]="xdmcp"; $t[201]="appletalk"
    $t[210]="z39.50"; $t[243]="surrog"; $t[264]="bgmp"; $t[318]="tsp"
    $t[356]="clos"; $t[366]="odmr"; $t[369]="rpc2portmap"; $t[370]="codaauth2"
    $t[371]="clearcase"; $t[376]="amqp"; $t[543]="klogin"; $t[544]="kshell"
    $t[548]="afp"; $t[554]="rtsp"; $t[749]="kerberos-adm"; $t[873]="rsync"
    $t[989]="ftps-data"; $t[990]="ftps"; $t[992]="telnets"; $t[994]="ircs"
    return $t
}

function New-CoherenceVerdict {
    <#
    Combines N Test-Coherence results into one weighted verdict.
    Checks that returned "no check defined" (score 50) carry no information
    and are excluded (weight 0) rather than dragging the average to neutral.
    Pass -Weights (one per check) to override the default weight of 1.0.

    Returns: verdict (coherent|inconclusive|contradicted|no-data), score,
    per-check table, and evidenceHashes (SHA-256 of each check's canonical
    JSON) ready to feed New-Receipt for a verifiable verdict receipt.
    #>
    param(
        [Parameter(Mandatory=$true)][array]$checks,
        [string]$conclusion = "",
        [double[]]$Weights = @(),
        [double]$CoherentFloor = 70,
        [double]$NeutralFloor = 40,
        [string]$utc = ""
    )
    if ($checks.Count -eq 0) {
        return [pscustomobject]@{
            verdict = "no-data"; score = $null; checkCount = 0
            detail = @(); evidenceHashes = @()
            reasons = @("no checks supplied")
        }
    }
    if ($Weights.Count -gt 0 -and $Weights.Count -ne $checks.Count) {
        return [pscustomobject]@{
            verdict = "no-data"; score = $null; checkCount = $checks.Count
            detail = @(); evidenceHashes = @()
            reasons = @("weights count ($($Weights.Count)) does not match checks count ($($checks.Count))")
        }
    }
    $detail = @(); $hashes = @(); $excl = @()
    $wSum = 0.0; $sSum = 0.0; $used = 0
    for ($i = 0; $i -lt $checks.Count; $i++) {
        $c = $checks[$i]
        $noCheck = ($c.reasons -join " ") -like "*no check defined*"
        # v1.4: a check with no usable 0-100 score used to flow into the
        # mean as $null/NaN or an out-of-band number, silently poisoning the
        # verdict. Such checks are now excluded with a stated reason.
        # ([double]$null is 0.0, not a throw — so $null needs its own guard.)
        $badScore = $false
        if ($null -eq $c.score) { $badScore = $true }
        else {
            try {
                $sc = [double]$c.score
                if ($sc -lt 0 -or $sc -gt 100) { $badScore = $true }
            } catch { $badScore = $true }
        }
        $w = 1.0
        if ($Weights.Count -gt 0) { $w = $Weights[$i] }
        if ($noCheck -or $badScore) { $w = 0.0 }
        if ($badScore) { $excl += "check '$($c.check)' returned no usable score ('$($c.score)') — excluded" }
        $h = Get-Sha256Hex (ConvertTo-CanonicalJson @{
            check = "$($c.check)"; score = $c.score; reasons = @($c.reasons)
        })
        $hashes += $h
        $detail += [pscustomobject]@{
            check = "$($c.check)"; score = $c.score; weight = $w
            hash = $h; coherent = ($c.score -ge $CoherentFloor); excluded = ($w -eq 0)
        }
        if ($w -gt 0) { $wSum += $w; $sSum += ($c.score * $w); $used++ }
    }
    if ($used -eq 0) {
        return [pscustomobject]@{
            verdict = "no-data"; score = $null; checkCount = $checks.Count
            detail = $detail; evidenceHashes = $hashes
            reasons = @("every check was undefined — nothing to combine")
        }
    }
    $score = [math]::Round($sSum / $wSum, 1)
    $verdict = "contradicted"
    if ($score -ge $CoherentFloor) { $verdict = "coherent" }
    elseif ($score -ge $NeutralFloor) { $verdict = "inconclusive" }
    $rs = @("weighted mean of $used informative check(s): $score")
    $rs += $excl
    if ($conclusion -ne "") { $rs += "conclusion under test: $conclusion" }
    return [pscustomobject]@{
        verdict = $verdict; score = $score; checkCount = $checks.Count
        informativeChecks = $used; detail = $detail
        evidenceHashes = $hashes; reasons = $rs
    }
}


# ============================================================================
# EIUAE — From DeepSeek transcripts (2026-08-29), NOT verified by Gregg
# Gregg 2026-11-01: "I don't know what the fuck EIUAE is"
# Status: UNVERIFIED. Do not treat as Gregg's math.
# Awaiting Gregg's actual math formalization.
# EIUAE(k) := SUM_{m,n in {I,U,A,E}, m!=n} beta_{mn} * D_KL(P~_m || P~_n) >= 0
# I = Intent, U = Utterance, A = Action, E = Evidence
# When all four channels align, EIUAE = 0. Divergence = positive score.
# Source: ~/workspace/goals/zero-plus-phi-seed-evidence-dossier/hidden_files/deepseek-transcripts/179.txt
# ============================================================================

function Get-KLDivergence {
    <#
    .SYNOPSIS
        KL divergence D_KL(P || Q) = SUM_x P(x) * ln(P(x)/Q(x)).
        Measures how much distribution P diverges from Q.
        Returns 0 when identical, positive when divergent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$P,
        [Parameter(Mandatory)][hashtable]$Q,
        [double]$Epsilon = 1e-10
    )
    [double]$kl = 0.0
    $allKeys = @($P.Keys) + @($Q.Keys) | Select-Object -Unique
    
    foreach ($k in $allKeys) {
        [double]$pVal = 0.0
        [double]$qVal = 0.0
        if ($P.ContainsKey($k)) { $pVal = [Convert]::ToDouble($P[$k]) }
        if ($Q.ContainsKey($k)) { $qVal = [Convert]::ToDouble($Q[$k]) }
        
        # Smoothing to avoid log(0)
        if ($pVal -lt $Epsilon) { $pVal = $Epsilon }
        if ($qVal -lt $Epsilon) { $qVal = $Epsilon }
        
        if ($pVal -gt $Epsilon) {
            $kl += $pVal * [Math]::Log($pVal / $qVal)
        }
    }
    
    if ($kl -lt 0) { $kl = 0.0 }
    return $kl
}

function Measure-EIUAE {
    <#
    .SYNOPSIS
        Gregg's EIUAE coherence score.
        EIUAE(k) = SUM_{m,n in {I,U,A,E}, m!=n} beta_{mn} * D_KL(P_m || P_n)
        
        Each channel (Intent, Utterance, Action, Evidence) is a probability
        distribution over outcomes. When all four agree, EIUAE = 0.
        When they diverge (e.g., said one thing, did another), EIUAE > 0.
    
    .PARAMETER Channels
        Hashtable with keys 'I', 'U', 'A', 'E', each a hashtable distribution.
    
    .PARAMETER Beta
        Optional weight matrix. Default: all pairs weighted 1.0.
        Format: @{ "I,U" = 1.0; "I,A" = 1.0; ... }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Channels,
        [hashtable]$Beta = @{}
    )
    
    $channelNames = @('I', 'U', 'A', 'E')
    foreach ($c in $channelNames) {
        if (-not $Channels.ContainsKey($c)) {
            throw "Channels must include '$c' (Intent, Utterance, Action, Evidence)"
        }
    }
    
    $eiuae = 0.0
    $pairScores = @{}
    
    foreach ($m in $channelNames) {
        foreach ($n in $channelNames) {
            if ($m -eq $n) { continue }
            
            $pairKey = "$m,$n"
            $betaWeight = if ($Beta.ContainsKey($pairKey)) { [double]$Beta[$pairKey] } else { 1.0 }
            
            $kl = Get-KLDivergence -P $Channels[$m] -Q $Channels[$n]
            $weighted = $betaWeight * $kl
            $eiuae += $weighted
            $pairScores[$pairKey] = $weighted
        }
    }
    
    # Normalize by number of pairs (12) for interpretable 0-1-ish range
    $normalized = $eiuae / 12.0
    
    return [PSCustomObject]@{
        EIUAE      = $eiuae
        Normalized = $normalized
        PairScores = $pairScores
        Coherent   = ($eiuae -lt 0.1)  # Threshold: below 0.1 = coherent
        Timestamp  = (Get-Date).ToString('o')
    }
}

function Test-EIUAE {
    <#
    .SYNOPSIS
        Self-test for EIUAE implementation.
    #>
    [CmdletBinding()]
    param()
    $issues = @()
    
    # Test 1: Identical distributions -> EIUAE = 0
    $dist = @{ "a" = 0.5; "b" = 0.3; "c" = 0.2 }
    $channels = @{ I = $dist; U = $dist; A = $dist; E = $dist }
    $result = Measure-EIUAE -Channels $channels
    if ($result.EIUAE -gt 0.001) {
        $issues += "Identical distributions should give EIUAE ~ 0, got $($result.EIUAE)"
    }
    
    # Test 2: Divergent distributions -> EIUAE > 0
    $channels2 = @{
        I = @{ "a" = 0.9; "b" = 0.1 }
        U = @{ "a" = 0.1; "b" = 0.9 }  # Opposite of intent
        A = @{ "a" = 0.9; "b" = 0.1 }
        E = @{ "a" = 0.9; "b" = 0.1 }
    }
    $result2 = Measure-EIUAE -Channels $channels2
    if ($result2.EIUAE -le 0.1) {
        $issues += "Divergent distributions should give EIUAE > 0.1, got $($result2.EIUAE)"
    }
    
    # Test 3: KL divergence basic
    $kl = Get-KLDivergence -P @{ "x" = 1.0 } -Q @{ "x" = 1.0 }
    if ($kl -gt 0.001) {
        $issues += "KL of identical should be ~0, got $kl"
    }
    
    return [PSCustomObject]@{
        Passed = ($issues.Count -eq 0)
        Issues = $issues
    }
}

function Test-CoherenceHygiene {
    <#
    Offline self-test battery for the coherence core. No network, no clock
    reads (every case passes explicit timestamps). Prints PASS/FAIL per
    case and returns {passed, failed, total, cases, healthy}.
    Run it before trusting any verdict: a module whose plumbing can't prove
    itself offline has no business going live.
    #>
    $cases = @(
        # --- Canonical JSON (5) ---
        @{ name = "canonical: key order independent"; test = {
            (ConvertTo-CanonicalJson @{b=1; a=2}) -eq (ConvertTo-CanonicalJson @{a=2; b=1})
        }},
        @{ name = "canonical: datetime invariant (ISO)"; test = {
            (ConvertTo-CanonicalJson ([datetime]"2026-10-30T06:00:00Z")).Contains("T06:00:00")
        }},
        @{ name = "canonical: numeric keys stringified to valid JSON"; test = {
            (ConvertTo-CanonicalJson @{5="x"}) -eq '{"5":"x"}'
        }},
        @{ name = "canonical: control char escaped as \u0007"; test = {
            (ConvertTo-CanonicalJson ("a" + [char]7 + "b")).Contains('\u0007')
        }},
        @{ name = "canonical: double uses round-trip R format"; test = {
            (ConvertTo-CanonicalJson @{v = [double]0.1}) -eq '{"v":0.1}'
        }},
        # --- New checks, pass cases (6) ---
        @{ name = "url-domain PASS: subdomain of claimed domain"; test = {
            $a = [pscustomobject]@{ data = @{url="https://mail.example.com/inbox"} }
            $b = [pscustomobject]@{ data = @{domain="example.com"} }
            (Test-Coherence -a $a -b $b -check "url-domain").score -eq 100
        }},
        @{ name = "email-domain PASS: exact sender domain"; test = {
            $a = [pscustomobject]@{ data = @{email="alerts@paypal.com"} }
            $b = [pscustomobject]@{ data = @{domain="paypal.com"} }
            (Test-Coherence -a $a -b $b -check "email-domain").score -eq 100
        }},
        @{ name = "port-banner PASS: SSH banner on 22"; test = {
            $a = [pscustomobject]@{ data = @{port=22} }
            $b = [pscustomobject]@{ data = @{banner="SSH-2.0-OpenSSH_9.3"} }
            (Test-Coherence -a $a -b $b -check "port-banner").score -eq 100
        }},
        @{ name = "mac-vendor PASS: Cisco OUI dash form"; test = {
            $a = [pscustomobject]@{ data = @{mac="00-00-0C-11-22-33"} }
            $b = [pscustomobject]@{ data = @{vendor="Cisco"} }
            (Test-Coherence -a $a -b $b -check "mac-vendor").score -eq 100
        }},
        @{ name = "hash-verify PASS: claimed hash is genuine"; test = {
            $payload = @{host="mail.example.com"; port=25}
            $a = [pscustomobject]@{ data = $payload }
            $b = [pscustomobject]@{ data = @{sha256=(Get-Sha256Hex (ConvertTo-CanonicalJson $payload))} }
            (Test-Coherence -a $a -b $b -check "hash-verify").score -eq 100
        }},
        @{ name = "geo-agree PASS: US vs United States"; test = {
            $a = [pscustomobject]@{ data = @{geoA="US"} }
            $b = [pscustomobject]@{ data = @{geoB="United States"} }
            (Test-Coherence -a $a -b $b -check "geo-agree").score -eq 90
        }},
        # --- New checks, fail cases (6) ---
        @{ name = "url-domain DRIFT: lookalike host"; test = {
            $a = [pscustomobject]@{ data = @{url="https://example-secure.com/login"} }
            $b = [pscustomobject]@{ data = @{domain="example.com"} }
            (Test-Coherence -a $a -b $b -check "url-domain").score -eq 30
        }},
        @{ name = "email-domain DRIFT: spoofed sender"; test = {
            $a = [pscustomobject]@{ data = @{email="alerts@paypa1.com"} }
            $b = [pscustomobject]@{ data = @{domain="paypal.com"} }
            (Test-Coherence -a $a -b $b -check "email-domain").score -eq 30
        }},
        @{ name = "port-banner DRIFT: ftp banner on port 22"; test = {
            $a = [pscustomobject]@{ data = @{port=22} }
            $b = [pscustomobject]@{ data = @{banner="220 ProFTPD ready"} }
            (Test-Coherence -a $a -b $b -check "port-banner").score -eq 35
        }},
        @{ name = "mac-vendor DRIFT: Apple OUI claims Cisco"; test = {
            $a = [pscustomobject]@{ data = @{mac="00:17:F2:AA:BB:CC"} }
            $b = [pscustomobject]@{ data = @{vendor="Cisco"} }
            (Test-Coherence -a $a -b $b -check "mac-vendor").score -eq 40
        }},
        @{ name = "mac-vendor NEUTRAL: unknown OUI is no verdict"; test = {
            $a = [pscustomobject]@{ data = @{mac="DE:AD:BE:11:22:33"} }
            $b = [pscustomobject]@{ data = @{vendor="Anyone"} }
            (Test-Coherence -a $a -b $b -check "mac-vendor").score -eq 50
        }},
        @{ name = "hash-verify CATCH: tampered hash field"; test = {
            $a = [pscustomobject]@{ data = @{host="x"} }
            $b = [pscustomobject]@{ data = @{sha256="0000000000000000000000000000000000000000000000000000000000000000"} }
            (Test-Coherence -a $a -b $b -check "hash-verify").score -eq 0
        }},
        # --- Verdict composer (3) ---
        @{ name = "verdict: weighted mean math"; test = {
            $c1 = [pscustomobject]@{ check="a"; score=100; reasons=@("x") }
            $c2 = [pscustomobject]@{ check="b"; score=40;  reasons=@("y") }
            $v = New-CoherenceVerdict -checks @($c1,$c2) -Weights @(3.0,1.0)
            $v.score -eq 85 -and $v.verdict -eq "coherent"
        }},
        @{ name = "verdict: undefined checks carry weight 0"; test = {
            $c1 = [pscustomobject]@{ check="ip-match"; score=100; reasons=@("ok") }
            $c2 = [pscustomobject]@{ check="bogus";    score=50;  reasons=@("no check defined for type 'bogus'") }
            $v = New-CoherenceVerdict -checks @($c1,$c2)
            $v.score -eq 100 -and $v.informativeChecks -eq 1
        }},
        @{ name = "verdict: band floor contradicted"; test = {
            $c1 = [pscustomobject]@{ check="a"; score=10; reasons=@("x") }
            (New-CoherenceVerdict -checks @($c1)).verdict -eq "contradicted"
        }},
        # --- Receipts (2) ---
        @{ name = "receipt: deterministic (twice identical)"; test = {
            $r1 = New-Receipt -conclusion "c" -evidenceHashes @("a","b") -prevHash "" -utc "2026-10-30T06:00:00Z"
            $r2 = New-Receipt -conclusion "c" -evidenceHashes @("b","a") -prevHash "" -utc "2026-10-30T06:00:00Z"
            $r1.receipt -eq $r2.receipt
        }},
        @{ name = "receipt: chain of 3 verifies"; test = {
            $r1 = New-Receipt -conclusion "c1" -evidenceHashes @("a") -prevHash "" -utc "2026-10-30T06:00:00Z"
            $r2 = New-Receipt -conclusion "c2" -evidenceHashes @("b") -prevHash $r1.receipt -utc "2026-10-30T06:01:00Z"
            $r3 = New-Receipt -conclusion "c3" -evidenceHashes @("c") -prevHash $r2.receipt -utc "2026-10-30T06:02:00Z"
            (Test-ReceiptChain -receipts @($r1,$r2,$r3)).valid
        }},
        # --- v1.4: bug fixes (5) ---
        @{ name = "canonical: unspecified datetime reads as UTC (cross-machine)"; test = {
            $unspec = New-Object datetime 2026,10,30,6,0,0, ([System.DateTimeKind]::Unspecified)
            (ConvertTo-CanonicalJson $unspec) -eq (ConvertTo-CanonicalJson ([datetime]"2026-10-30T06:00:00Z"))
        }},
        @{ name = "canonical: local datetime converts to the same UTC instant"; test = {
            $local = New-Object datetime 2026,10,30,6,0,0, ([System.DateTimeKind]::Local)
            (ConvertTo-CanonicalJson $local) -eq (ConvertTo-CanonicalJson $local.ToUniversalTime())
        }},
        @{ name = "url-domain PASS: scheme-less host accepted"; test = {
            $a = [pscustomobject]@{ data = @{url="mail.example.com/inbox"} }
            $b = [pscustomobject]@{ data = @{domain="example.com"} }
            (Test-Coherence -a $a -b $b -check "url-domain").score -eq 100
        }},
        @{ name = "email-domain PASS: display-name addr-spec extracted"; test = {
            $a = [pscustomobject]@{ data = @{email="Jane Doe <jane@example.com>"} }
            $b = [pscustomobject]@{ data = @{domain="example.com"} }
            (Test-Coherence -a $a -b $b -check "email-domain").score -eq 100
        }},
        @{ name = "ip-subnet: bare address without prefix is refused (not /0)"; test = {
            $a = [pscustomobject]@{ data = @{ip="10.9.9.9"} }
            $b = [pscustomobject]@{ data = @{cidr="10.0.0.0"} }
            $r = Test-Coherence -a $a -b $b -check "ip-subnet"
            ($r.score -eq 50) -and (($r.reasons -join " ") -like "*address/prefix*")
        }},
        # --- v1.4: file-magic (4) ---
        @{ name = "file-magic PASS: pdf header"; test = {
            $a = [pscustomobject]@{ data = @{extension="pdf"} }
            $b = [pscustomobject]@{ data = @{magicHex="255044462D312E34"} }
            (Test-Coherence -a $a -b $b -check "file-magic").score -eq 100
        }},
        @{ name = "file-magic CATCH: exe renamed to pdf names the real type"; test = {
            $a = [pscustomobject]@{ data = @{extension="pdf"} }
            $b = [pscustomobject]@{ data = @{magicHex="4D5A900003000000"} }
            $r = Test-Coherence -a $a -b $b -check "file-magic"
            ($r.score -eq 0) -and (($r.reasons -join " ") -like "*executable*")
        }},
        @{ name = "file-magic NEUTRAL: unknown extension"; test = {
            $a = [pscustomobject]@{ data = @{extension="xyzzy"} }
            $b = [pscustomobject]@{ data = @{magicHex="DEADBEEF"} }
            (Test-Coherence -a $a -b $b -check "file-magic").score -eq 50
        }},
        @{ name = "file-magic NEUTRAL: text format has no magic"; test = {
            $a = [pscustomobject]@{ data = @{extension="txt"} }
            $b = [pscustomobject]@{ data = @{magicHex="48656C6C6F"} }
            (Test-Coherence -a $a -b $b -check "file-magic").score -eq 50
        }},
        # --- v1.4: cert-issuer (3) ---
        @{ name = "cert-issuer self-signed: issuer == subject"; test = {
            $a = [pscustomobject]@{ data = @{issuer="CN=mail.example.com"} }
            $b = [pscustomobject]@{ data = @{subject="CN=mail.example.com"} }
            (Test-Coherence -a $a -b $b -check "cert-issuer").score -eq 40
        }},
        @{ name = "cert-issuer known CA: Let's Encrypt"; test = {
            $a = [pscustomobject]@{ data = @{issuer="CN=R3,O=Let's Encrypt,C=US"} }
            $b = [pscustomobject]@{ data = @{subject="CN=example.com"} }
            (Test-Coherence -a $a -b $b -check "cert-issuer").score -eq 100
        }},
        @{ name = "cert-issuer NEUTRAL: private CA is no verdict"; test = {
            $a = [pscustomobject]@{ data = @{issuer="CN=ACME Internal CA"} }
            $b = [pscustomobject]@{ data = @{subject="CN=app.internal"} }
            (Test-Coherence -a $a -b $b -check "cert-issuer").score -eq 50
        }},
        # --- v1.4: malformed hash + verdict hygiene (2) ---
        @{ name = "hash-verify MALFORMED: non-hex claim named, not lumped"; test = {
            $a = [pscustomobject]@{ data = @{host="x"} }
            $b = [pscustomobject]@{ data = @{sha256="not-a-hash"} }
            $r = Test-Coherence -a $a -b $b -check "hash-verify"
            ($r.score -eq 0) -and (($r.reasons -join " ") -like "*MALFORMED*")
        }},
        @{ name = "verdict: check with no usable score is excluded"; test = {
            $c1 = [pscustomobject]@{ check="a"; score=100; reasons=@("ok") }
            $c2 = [pscustomobject]@{ check="b"; score=$null; reasons=@("oops") }
            $v = New-CoherenceVerdict -checks @($c1,$c2)
            ($v.score -eq 100) -and ($v.informativeChecks -eq 1) -and (($v.reasons -join " ") -like "*excluded*")
        }},
        # --- Table sanity (5) ---
        @{ name = "oui table: >=50 unique valid 6-hex keys"; test = {
            $t = Get-OuiVendorTable
            $t.Count -ge 50 -and @($t.Keys | Where-Object { $_ -notmatch '^[0-9A-F]{6}$' }).Count -eq 0
        }},
        @{ name = "country table: US/DE/UK normalize"; test = {
            (ConvertTo-CountryName "US") -eq "united states" -and
            (ConvertTo-CountryName "DE") -eq "germany" -and
            (ConvertTo-CountryName "uk") -eq "united kingdom"
        }},
        @{ name = "check registry: 21 checks, all documented"; test = {
            $reg = Get-CoherenceChecks
            $reg.Count -eq 21 -and @($reg | Where-Object { "$($_.name)" -eq "" -or "$($_.meaning)" -eq "" }).Count -eq 0
        }},
        @{ name = "magic tables: pdf/exe sigs + reverse lookup names MZ"; test = {
            $t = Get-FileMagicTable
            ($t["pdf"].Sigs -contains "25504446") -and ($t["exe"].Sigs -contains "4D5A") -and
            ((Get-MagicTypeTable)["4D5A"] -like "*executable*")
        }},
        @{ name = "ca table: >=20 keywords, LE present"; test = {
            $t = Get-TrustedCaKeywordTable
            ($t.Count -ge 20) -and @($t | Where-Object { $_.Keyword -eq "Let's Encrypt" }).Count -eq 1
        }}
    )
    $pass = 0; $fail = 0; $results = @()
    foreach ($c in $cases) {
        $ok = $false; $err = ""
        try { $ok = [bool](& $c.test) } catch { $err = $_.Exception.Message }
        if ($ok) { $pass++ } else { $fail++ }
        $results += [pscustomobject]@{ name = $c.name; passed = $ok; error = $err }
        $tag = "PASS"; $color = "Green"
        if (-not $ok) { $tag = "FAIL"; $color = "Red" }
        Write-Host ("[{0}] {1}" -f $tag, $c.name) -ForegroundColor $color
        if ($err -ne "") { Write-Host ("       error: {0}" -f $err) -ForegroundColor Red }
    }
    Write-Host ("coherence hygiene: {0}/{1} passed" -f $pass, $cases.Count) -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
    return [pscustomobject]@{
        passed = $pass; failed = $fail; total = $cases.Count
        cases = $results; healthy = ($fail -eq 0)
    }
}

# Dot-source this file to load all functions into your session:
#   . .\Falsum-Coherence.ps1
# (Export-ModuleMember is intentionally absent: this file is designed for
# dot-sourcing, where all functions become available directly.)
