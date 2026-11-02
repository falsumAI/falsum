<#
Module 02 — PACKET WITNESS
Wraps Windows pktmon: capture traffic, convert to text, extract DNS queries
(+types) and answers, TLS SNIs, HTTP hosts, per-flow byte counts, top talkers,
DNS anomalies (answers without queries), unusual destination ports,
DNS tunnel/exfil verdicts, periodic-flow (beaconing) detection, and
SNI-vs-DNS mismatch detection. Every output SHA-256 hashed.

Requires elevation (pktmon needs admin). Clean error when not elevated.

Dot-source:
  . .\Falsum-PacketWitness.ps1

Typical flow:
  $cap = Start-Capture -OutDir "C:\cases\case01" -Preset web
  # ... let traffic run ...
  $sealed = Stop-Capture -Capture $cap   # seals hashes AND auto-verifies them
  Get-DnsQueries -TxtPath $sealed.txtPath
  Get-DnsResponses -TxtPath $sealed.txtPath
  Get-DnsAnomalyReport -TxtPath $sealed.txtPath
  Get-TlsSnis -TxtPath $sealed.txtPath
  Get-HttpHosts -TxtPath $sealed.txtPath
  $flows = Get-FlowSummary -TxtPath $sealed.txtPath   # streamed, IPv4+IPv6
  Get-TopTalkers -Flows $flows
  Get-UnusualPorts -Flows $flows
  Get-DnsTunnelSignals -TxtPath $sealed.txtPath   # v3: DNS exfil/tunnel verdicts
  Get-BeaconingFlows -TxtPath $sealed.txtPath     # v3: periodic-flow (C2 beacon) detector
  Get-SniDnsMismatch -TxtPath $sealed.txtPath     # v3: SNIs never seen in DNS
  Get-DoHSuspectFlows -Flows $flows -TxtPath $sealed.txtPath  # v4: DoH bypass detector
  Get-PacketWitnessFixPlan -BlockIp "203.0.113.7"             # v4: Better-Way fix commands
  Test-PacketWitnessHygiene                       # v4: offline self-test battery
  Export-PacketWitnessReport -TxtPath $sealed.txtPath -OutDir "C:\cases\case01"

v4 hardening (2026-10-30): ConvertTo-EndpointParts — one pure, TryParse-
validated endpoint parser shared by Get-FlowSummary and Get-BeaconingFlows.
FIXES the v3 silent flow loss: pktmon's TCPDump IPv6 rendering
("2001:db8::1.443", dot port) never matched the old colon-only v6 regex, and
unvalidated v4 tokens ("999.999.999.999:80", version strings) parsed as
endpoints. NEW Get-DoHResolverTable + Get-DoHSuspectFlows: names the DNS-
over-HTTPS bypass mechanism behind SNI/DNS mismatches (capture-wide SNI
evidence, likely-doh vs possible-doh confidence labels — never a guess).
NEW Get-PacketWitnessFixPlan: every detection ships its fix (process hunt,
firewall block, resolver pin, cache flush, re-capture proof) as copy-paste
commands — string generation only, nothing executes. Get-TopTalkers isLocal
now lowercases IPv6 hex before the local-range match. Dead no-op line
removed from Export-PacketWitnessReport; report gains the DoH section.

Capture presets: Get-CapturePreset lists them (dns-only, web, tls-only,
smb, icmp, unfiltered). Multiple pktmon filter lines are ORed by pktmon;
preset lines plus -Filter custom string combine on the same capture.
#>

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    if (-not (Test-IsAdmin)) {
        throw "Packet witness needs elevation: right-click PowerShell -> Run as administrator, then retry."
    }
}

function Test-Pktmon {
    # pktmon ships on Windows 10 build 19041+ and Windows 11. Absent (or
    # broken) on older builds. Returns version string or $null.
    try {
        $out = pktmon version 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0 -or $out -match "not recognized") { return $null }
        $line = ($out -split "`r?`n" | Where-Object { $_ -match "\d+\.\d+" } | Select-Object -First 1)
        return ($line.Trim())
    } catch {
        return $null
    }
}

function Test-CaptureActive {
    # Returns $true when a pktmon capture is currently running. Used so two
    # overlapping captures cannot silently fight over the same ETL file.
    try {
        $out = pktmon status 2>&1 | Out-String
        return ($out -match "(?i)capture.*(running|started|active)")
    } catch {
        return $false
    }
}

function Get-CapturePreset {
    # Named capture filters. Returns the array of pktmon filter lines to add.
    # Multiple lines are OR'd by pktmon. Syntax: -p port, -t protocol
    # (TCP/UDP/ICMP/ICMPv6), -i ip/CIDR. Ref: Microsoft pktmon filter docs.
    param([Parameter(Mandatory=$true)][ValidateSet("dns-only","web","tls-only","smb","icmp","unfiltered")][string]$Preset)
    switch ($Preset) {
        "dns-only"   { return @("-t UDP -p 53") }
        "web"        { return @("-p 80", "-p 443") }
        "tls-only"   { return @("-t TCP -p 443") }
        "smb"        { return @("-t TCP -p 445") }
        "icmp"       { return @("-t ICMP", "-t ICMPv6") }
        "unfiltered" { return @() }
    }
}

function Start-Capture {
    param(
        [Parameter(Mandatory=$true)][string]$OutDir,
        [string]$Filter = "",
        [ValidateSet("dns-only","web","tls-only","smb","icmp","unfiltered")][string]$Preset = ""
    )
    Assert-Admin
    try {
        # Pre-flight: pktmon must exist and no capture may already be running.
        $pktmonVer = Test-Pktmon
        if (-not $pktmonVer) {
            throw "pktmon not found on this build. Packet witness needs Windows 10 build 19041+ or Windows 11."
        }
        Write-Host "[*] pktmon: $pktmonVer"
        if (Test-CaptureActive) {
            throw "a pktmon capture is already running. Stop-Capture the running one first (or run 'pktmon stop' from an elevated shell)."
        }
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
        $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $etl = Join-Path $OutDir "capture_$stamp.etl"
        Write-Host "[*] Starting pktmon capture -> $etl"
        $appliedFilters = @()
        if ($Preset -ne "" -or $Filter -ne "") {
            # Clear stale filters first (a leftover filter is silent evidence loss).
            $null = pktmon filter remove 2>&1
            if ($Preset -ne "") {
                foreach ($line in (Get-CapturePreset -Preset $Preset)) {
                    $null = pktmon filter add $line 2>&1
                    $appliedFilters += $line
                    Write-Host "[*] filter preset: $Preset -> '$line'"
                }
            }
            if ($Filter -ne "") {
                $null = pktmon filter add $Filter 2>&1
                $appliedFilters += $Filter
                Write-Host "[*] custom filter: '$Filter'"
            }
        }
        $out = pktmon start --capture --pkt-size 0 -f hex --file-name $etl 2>&1 | Out-String
        if ($out -match "started|Started") { Write-Host "[+] capture running" }
        else { Write-Host "[!] pktmon output: $out" }
        # Confirm the capture actually took: a "started" banner alone is not
        # proof the kernel logger attached. status is the honest check.
        if (-not (Test-CaptureActive)) {
            Write-Host "[!] WARNING: pktmon status shows no active capture. The start may have failed silently."
        }
        return [pscustomobject]@{
            outDir  = $OutDir
            etlPath = $etl
            txtPath = ($etl -replace "\.etl$", ".txt")
            started = (Get-Date).ToUniversalTime().ToString("o")
            pktmonVersion = $pktmonVer
            filter = $Filter
            preset = $Preset
            appliedFilters = $appliedFilters
        }
    } catch {
        throw "Start-Capture failed: $($_.Exception.Message)"
    }
}

function Stop-Capture {
    param([Parameter(Mandatory=$true)]$Capture)
    Assert-Admin
    try {
        if (-not (Test-CaptureActive)) {
            Write-Host "[!] WARNING: no pktmon capture appears to be running. Attempting stop anyway."
        }
        Write-Host "[*] Stopping pktmon capture"
        $null = pktmon stop 2>&1
        # Clean up any filter left behind so the NEXT capture starts unfiltered
        # unless the user explicitly passes -Filter. A stale filter is a
        # silent-evidence-loss bug.
        $null = pktmon filter remove 2>&1
        $etl = $Capture.etlPath
        if (-not (Test-Path $etl)) {
            # pktmon may have named it with an increment; find newest etl in dir
            $etl = Get-ChildItem $Capture.outDir -Filter "capture_*.etl" |
                   Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
        }
        Write-Host "[*] Converting ETL -> TXT"
        $txt = $Capture.txtPath
        $convOut = pktmon etl2txt $etl -o $txt 2>&1 | Out-String
        $convOk = ($LASTEXITCODE -eq 0) -and (Test-Path $txt) -and ((Get-Item $txt).Length -gt 0)
        if (-not $convOk) {
            Write-Host "[!] WARNING: etl2txt failed (exit $LASTEXITCODE): $convOut"
        }
        $result = [pscustomobject]@{
            etlPath  = $etl
            txtPath  = $txt
            etlHash  = ""
            txtHash  = ""
            etlBytes = 0
            txtBytes = 0
            converted = $convOk
            integrityOk = $false
        }
        if (Test-Path $etl) {
            $result.etlHash = (Get-FileHash $etl -Algorithm SHA256).Hash
            $result.etlBytes = (Get-Item $etl).Length
        }
        if (Test-Path $txt) {
            $result.txtHash = (Get-FileHash $txt -Algorithm SHA256).Hash
            $result.txtBytes = (Get-Item $txt).Length
        }
        # Seal-then-verify in the same function: evidence is only sealed if
        # the hashes check back clean immediately, before anything else runs.
        if ($result.etlHash -ne "" -or $result.txtHash -ne "") {
            $check = Test-CaptureIntegrity -CaptureResult $result
            $result.integrityOk = $check
            if (-not $check) { Write-Host "[!] Stop-Capture: sealed hashes did NOT verify back. Treat outputs as suspect." }
        }
        Write-Host "[+] capture sealed: etl $($result.etlBytes) bytes, txt $($result.txtBytes) bytes"
        return $result
    } catch {
        throw "Stop-Capture failed: $($_.Exception.Message)"
    }
}

function Get-DnsQueries {
    param([Parameter(Mandatory=$true)][string]$TxtPath)
    try {
        if (-not (Test-Path $TxtPath)) { throw "not found: $TxtPath" }
        $found = @{}
        # Pair "Query Name" with the "Query Type" on the following line so the
        # report carries A vs AAAA vs MX, not just names. Single streaming pass
        # over the file (large captures are hundreds of MB — two Select-String
        # passes and full-array materialization are slow and memory-heavy).
        $reader = [System.IO.File]::OpenText($TxtPath)
        try {
            $curName = $null
            while ($null -ne ($line = $reader.ReadLine())) {
                if ($line -match "Query Name\s*:\s*(\S+)") {
                    $curName = $Matches[1].Trim().TrimEnd(".").ToLower()
                } elseif ($null -ne $curName -and $line -match "Query Type\s*:\s*([A-Za-z0-9]+)") {
                    $key = "$curName [" + $Matches[1].ToUpper() + "]"
                    if (-not $found.ContainsKey($key)) { $found[$key] = 0 }
                    $found[$key]++
                    $curName = $null
                } elseif ($line -match "^\s*(Query|Packet|Frame)") {
                    # a new packet/question block started before we saw a type
                    # (defensive formats): record the name with unknown type
                    if ($null -ne $curName -and $curName -ne "") {
                        $key = "$curName [?]"
                        if (-not $found.ContainsKey($key)) { $found[$key] = 0 }
                        $found[$key]++
                    }
                    $curName = $null
                }
            }
            # trailing pending name (file ended mid-block)
            if ($null -ne $curName -and $curName -ne "") {
                $key = "$curName [?]"
                if (-not $found.ContainsKey($key)) { $found[$key] = 0 }
                $found[$key]++
            }
        }
        finally { $reader.Close() }
        # fallback: A-record question lines (older etl2txt renderings)
        if ($found.Count -eq 0) {
            Select-String -Path $TxtPath -Pattern "(?i)\bDNS\b.*?\b([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}\b" -AllMatches | ForEach-Object {
                foreach ($m in $_.Matches) {
                    $name = $m.Groups[1].Value.TrimEnd(".").ToLower()
                    if (-not $found.ContainsKey($name)) { $found[$name] = 0 }
                    $found[$name]++
                }
            }
        }
        return @($found.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            [pscustomobject]@{ query = $_.Key; hits = $_.Value }
        })
    } catch {
        Write-Host "[!] Get-DnsQueries failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-DnsResponses {
    # The other half of DNS: what the answers were. etl2txt renders A/AAAA
    # answers under "Resolved Name" / "A Record" / "AAAA Record" lines.
    # Returns name -> distinct answer IPs with hit counts. Answers without a
    # matching query in Get-DnsQueries are a spoofing/pinning smell worth flagging.
    param([Parameter(Mandatory=$true)][string]$TxtPath)
    try {
        if (-not (Test-Path $TxtPath)) { throw "not found: $TxtPath" }
        $found = @{}
        $reader = [System.IO.File]::OpenText($TxtPath)
        try {
            $curName = $null
            while ($null -ne ($line = $reader.ReadLine())) {
                if ($line -match "Resolved Name\s*:\s*(\S+)") {
                    $curName = $Matches[1].Trim().TrimEnd(".").ToLower()
                } elseif ($null -ne $curName -and $line -match "(?:A{1,4} Record|RDATA|Answer)\s*[:=]\s*(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})") {
                    $key = "$curName -> " + $Matches[1]
                    if (-not $found.ContainsKey($key)) { $found[$key] = 0 }
                    $found[$key]++
                    # keep $curName for multi-answer responses; cleared below
                } elseif ($line -match "^\s*(Query|Packet|Frame|DNS Response)") {
                    $curName = $null
                }
            }
        }
        finally { $reader.Close() }
        return @($found.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            [pscustomobject]@{ answer = $_.Key; hits = $_.Value }
        })
    } catch {
        Write-Host "[!] Get-DnsResponses failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-TlsSnis {
    param([Parameter(Mandatory=$true)][string]$TxtPath)
    try {
        if (-not (Test-Path $TxtPath)) { throw "not found: $TxtPath" }
        $found = @{}
        # ClientHello SNI appears as "Server Name" / "server_name" in etl2txt.
        # Some builds render the extension block header "Server Name Indication"
        # with the name on the following line, so we try both.
        $patterns = @(
            "(?i)server name\s*[:=]\s*(\S+)",
            "(?i)server name indication[^\r\n]*[\r\n]+\s*(\S+)"
        )
        $ipRe = "^\d{1,3}(\.\d{1,3}){3}$|^\[?[0-9a-fA-F:]+\]?$"
        foreach ($pat in $patterns) {
            Select-String -Path $TxtPath -Pattern $pat -AllMatches | ForEach-Object {
                foreach ($m in $_.Matches) {
                    $name = $m.Groups[1].Value.Trim().TrimEnd(".").Trim(",;:`"").ToLower()
                    # SNI is a hostname, never an IP literal. IPs here are
                    # usually parser noise (e.g. addresses in the extension
                    # blob) — dropping them kills a whole class of false hits.
                    if ($name -match $ipRe) { continue }
                    if ($name -match "\.") {
                        if (-not $found.ContainsKey($name)) { $found[$name] = 0 }
                        $found[$name]++
                    }
                }
            }
        }
        return @($found.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            [pscustomobject]@{ sni = $_.Key; hits = $_.Value }
        })
    } catch {
        Write-Host "[!] Get-TlsSnis failed: $($_.Exception.Message)"
        return @()
    }
}

function ConvertTo-EndpointParts {
    # PURE parser: one "endpoint token" -> ip / port / ok / note. Handles:
    #   1.2.3.4:443        (v4, colon port)      1.2.3.4.443  (v4, dot port)
    #   [2001:db8::1]:443  (v6, bracketed)
    #   2001:db8::1.443    (v6, dot port — pktmon's TCPDump rendering)
    #   2001:db8::1:443    (v6, bare colon port — resolved longest-IP-first)
    # v3 BUG FIXED HERE: Get-FlowSummary/Get-BeaconingFlows ran raw regexes
    # with no IP validation, so dot-separated IPv6 ports (the shape pktmon
    # actually renders) never matched at all — silent flow loss — and junk
    # like "999.999.999.999:80" or version strings parsed as endpoints.
    # Every candidate ip is now validated with [Net.IPAddress]::TryParse and
    # the port must be 0..65535. Tokens that fail every shape return
    # ok=$false instead of a fabricated endpoint.
    param([Parameter(Mandatory=$true)][string]$Token)
    $t = $Token.Trim().TrimEnd(",", ";")
    $bad = [pscustomobject]@{ ip = ""; port = 0; ok = $false; note = "unrecognized endpoint token: '$Token'" }
    try {
        $ipStr = ""; $portStr = ""
        if ($t -match "^\[([^\]]+)\]:(\d{1,5})$") {
            $ipStr = $Matches[1]; $portStr = $Matches[2]
        } elseif ($t -match "^(\d{1,3}(?:\.\d{1,3}){3})[:.](\d{1,5})$") {
            $ipStr = $Matches[1]; $portStr = $Matches[2]
        } elseif ($t -match "^(.+)\.(\d{1,5})$") {
            # v6 with dot port ("2001:db8::1.443"). The v4 branch above runs
            # first, so a colon in the candidate ip means v6-shaped. NOTE:
            # do NOT chain a second -match in the condition — it clobbers
            # $Matches and would corrupt $ipStr/$portStr below.
            $candIp = $Matches[1]; $candPort = $Matches[2]
            if ($candIp -match ":") { $ipStr = $candIp; $portStr = $candPort }
            else { return $bad }
        } elseif ($t -match "^(.+):(\d{1,5})$") {
            $ipStr = $Matches[1]; $portStr = $Matches[2]
        } else {
            return $bad
        }
        $addr = $null
        if (-not [System.Net.IPAddress]::TryParse($ipStr, [ref]$addr)) { return $bad }
        $port = [int]$portStr
        if ($port -lt 0 -or $port -gt 65535) { return $bad }
        return [pscustomobject]@{ ip = $addr.ToString(); port = $port; ok = $true; note = "" }
    } catch {
        return $bad
    }
}

function Get-DoHResolverTable {
    # Shipped table of well-known public DNS-over-HTTPS endpoints: resolver
    # IP + provider + DoH hostname. Public, stable, documented by the
    # providers themselves. Used by Get-DoHSuspectFlows to name the DoH
    # mechanism behind SNI/DNS mismatches.
    return @(
        [pscustomobject]@{ ip = "1.1.1.1";         provider = "Cloudflare"; dohHost = "cloudflare-dns.com" },
        [pscustomobject]@{ ip = "1.0.0.1";         provider = "Cloudflare"; dohHost = "cloudflare-dns.com" },
        [pscustomobject]@{ ip = "8.8.8.8";         provider = "Google";     dohHost = "dns.google" },
        [pscustomobject]@{ ip = "8.8.4.4";         provider = "Google";     dohHost = "dns.google" },
        [pscustomobject]@{ ip = "9.9.9.9";         provider = "Quad9";      dohHost = "dns.quad9.net" },
        [pscustomobject]@{ ip = "149.112.112.112"; provider = "Quad9";      dohHost = "dns.quad9.net" },
        [pscustomobject]@{ ip = "208.67.222.222";  provider = "OpenDNS";    dohHost = "doh.opendns.com" },
        [pscustomobject]@{ ip = "208.67.220.220";  provider = "OpenDNS";    dohHost = "doh.opendns.com" }
    )
}

function Get-DoHSuspectFlows {
    # DNS-over-HTTPS bypass detector: TLS/443 flows to the shipped public-
    # resolver table, cross-checked with the capture's SNIs. A 443 flow to
    # 1.1.1.1 with SNI cloudflare-dns.com in the capture is "likely-doh";
    # the same flow with no such SNI is "possible-doh" — it may be plain
    # HTTPS to another Cloudflare-fronted service, and the confidence label
    # says exactly that. Honest limit: SNI attribution is capture-wide, not
    # per-flow, because Get-TlsSnis does not bind SNIs to flows.
    # Why it matters: DoH bypasses every DNS parser in this module, which
    # is the mechanism behind most Get-SniDnsMismatch rows; this function
    # names it.
    param(
        [Parameter(Mandatory=$true)]$Flows,
        [Parameter(Mandatory=$true)][string]$TxtPath
    )
    try {
        $byIp = @{}
        foreach ($r in (Get-DoHResolverTable)) { $byIp[$r.ip] = $r }
        $snis = @(Get-TlsSnis -TxtPath $TxtPath)
        $rows = @()
        foreach ($f in $Flows) {
            $dip = [string]$f.dstIp
            if (-not $byIp.ContainsKey($dip)) { continue }
            if ([int]$f.dstPort -ne 443) { continue }
            $r = $byIp[$dip]
            $sniHit = @($snis | Where-Object { $_.sni -eq $r.dohHost } | Select-Object -First 1)
            $conf = "possible-doh"
            $ev = "no SNI '$($r.dohHost)' observed in this capture"
            if ($sniHit.Count -gt 0) {
                $conf = "likely-doh"
                $ev = "SNI '$($r.dohHost)' seen $($sniHit[0].hits)x in this capture"
            }
            $rows += [pscustomobject]@{
                flow       = $f.flow
                dstIp      = $dip
                provider   = $r.provider
                confidence = $conf
                evidence   = $ev
                bytes      = $f.bytes
                packets    = $f.packets
                note       = "DoH bypasses this module's DNS parsers. To confirm: resolver IP + DoH SNI together are the mechanism. Fix: pin the machine to your chosen resolver (Get-PacketWitnessFixPlan) and re-capture with the dns-only preset."
            }
        }
        return @($rows | Sort-Object bytes -Descending)
    } catch {
        Write-Host "[!] Get-DoHSuspectFlows failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-PacketWitnessFixPlan {
    # BETTER-WAY LAW for the witness: every detection ships its fix. Emits
    # concrete, copy-paste remediation commands for this module's findings:
    # find the owning process, firewall-block a hostile IP, pin DNS
    # resolvers, flush the cache, and re-capture to prove the fix worked.
    # STRING GENERATION ONLY — nothing here executes; the operator pastes
    # what they want. Hostile-session killing and bad-actor marking live in
    # module 11 (active-defense) and are referenced, not duplicated.
    param(
        [string]$BlockIp = "",
        [string]$BlockReason = "flagged by packet witness",
        [string[]]$NewDnsServers = @("1.1.1.1", "8.8.8.8"),
        [string]$DnsInterfaceAlias = ""
    )
    $steps = @()
    $mkStep = {
        param($order, $title, $command, $needsAdmin, $note)
        [pscustomobject]@{ order = $order; title = $title; command = $command;
                            needsAdmin = [bool]$needsAdmin; note = $note }
    }
    $n = 1
    if ($BlockIp -ne "") {
        $steps += & $mkStep $n "Find the process talking to $BlockIp" `
            ("Get-NetTCPConnection -RemoteAddress '$BlockIp' | " +
             "Select-Object LocalAddress,LocalPort,RemotePort,OwningProcess,State | Format-Table -AutoSize") `
            $false "Run while the connection is live. OwningProcess -> Get-Process -Id <pid> names it. If it is malware, module 11 Stop-HostileSession kills it (local only)."
        $n++
        $steps += & $mkStep $n "Firewall-block $BlockIp (outbound)" `
            ("New-NetFirewallRule -DisplayName 'Falsum-block-$BlockIp' " +
             "-Description 'Falsum packet witness: $BlockReason' " +
             "-Direction Outbound -RemoteAddress '$BlockIp' -Action Block -Profile Any -Enabled True") `
            $true "Undo: Remove-NetFirewallRule -DisplayName 'Falsum-block-$BlockIp'. Permanent mark of the actor goes in module 11 Add-BadActor."
        $n++
    }
    $alias = $DnsInterfaceAlias
    if ($alias -eq "") { $alias = "<InterfaceAlias from Get-NetAdapter>" }
    $servers = ($NewDnsServers | ForEach-Object { "'$_'" }) -join ", "
    $steps += & $mkStep $n "Pin DNS resolvers (kills rogue-DNS + most DoH bypass)" `
        "Set-DnsClientServerAddress -InterfaceAlias '$alias' -ServerAddresses $servers" `
        $true "Pick resolvers you trust. Re-capture with -Preset dns-only afterwards: if queries now hit your resolver, the bypass is closed."
    $n++
    $steps += & $mkStep $n "Flush the DNS cache" `
        "Clear-DnsClientCache" `
        $true "Do this AFTER pinning resolvers, or poisoned entries come straight back."
    $n++
    $steps += & $mkStep $n "Re-capture and verify" `
        "Start-Capture -OutDir '<case-dir>' -Preset dns-only" `
        $true "The proof: Get-DnsQueries and Get-DoHSuspectFlows on the new capture should show traffic only to your pinned resolvers."
    return $steps
}

function Get-FlowSummary {
    # Single streaming pass (StreamReader). Select-String materializes every
    # match object plus the full line array — on multi-hundred-MB captures
    # that is slow and memory-heavy. IPv4 and bracketed/plain IPv6 supported.
    param([Parameter(Mandatory=$true)][string]$TxtPath)
    try {
        if (-not (Test-Path $TxtPath)) { throw "not found: $TxtPath" }
        $flows = @{}
        $arrowRe = "(\S+)\s*(?:->|→)\s*(\S+)"
        $lenRe = "[Ll]en(?:gth)?\s*[:=]\s*(\d+)"
        $count = 0
        $skipped = 0
        $reader = [System.IO.File]::OpenText($TxtPath)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                $count++
                # [regex]::Match (not -match) so endpoint parsing stays in
                # the pure ConvertTo-EndpointParts helper — one code path,
                # validated IPs, no fabricated endpoints.
                $am = [regex]::Match($line, $arrowRe)
                if (-not $am.Success) { continue }
                $src = ConvertTo-EndpointParts -Token $am.Groups[1].Value
                $dst = ConvertTo-EndpointParts -Token $am.Groups[2].Value
                if (-not $src.ok -or -not $dst.ok) { $skipped++; continue }
                $sIp = $src.ip; $sPort = $src.port
                $dIp = $dst.ip; $dPort = $dst.port
                $key = "${sIp}:${sPort} -> ${dIp}:${dPort}"
                if (-not $flows.ContainsKey($key)) {
                    $flows[$key] = [pscustomobject]@{ flow = $key; srcIp = $sIp; srcPort = $sPort; dstIp = $dIp; dstPort = $dPort; packets = 0; bytes = 0 }
                }
                $flows[$key].packets++
                $len = 0
                if ($line -match $lenRe) { $len = [int]$Matches[1] }
                $flows[$key].bytes += $len
            }
        }
        finally { $reader.Close() }
        Write-Host "[*] flow parse: $count lines, $($flows.Count) distinct flows ($skipped arrow-lines skipped: no valid endpoints)"
        return @($flows.Values | Sort-Object bytes -Descending)
    } catch {
        Write-Host "[!] Get-FlowSummary failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-HttpHosts {
    # Plaintext HTTP is still common on LANs and IoT. etl2txt hex-dumps the
    # payload, but many builds also decode ASCII — "Host:" lines appear.
    # Returns distinct Host header values with hit counts.
    param([Parameter(Mandatory=$true)][string]$TxtPath)
    try {
        if (-not (Test-Path $TxtPath)) { throw "not found: $TxtPath" }
        $found = @{}
        Select-String -Path $TxtPath -Pattern "(?m)^\s*Host\s*:\s*(\S+)" -AllMatches | ForEach-Object {
            foreach ($m in $_.Matches) {
                $name = $m.Groups[1].Value.Trim().TrimEnd(".").Trim(",;:`"").ToLower()
                if ($name -match "\." -and $name.Length -le 253) {
                    if (-not $found.ContainsKey($name)) { $found[$name] = 0 }
                    $found[$name]++
                }
            }
        }
        return @($found.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            [pscustomobject]@{ host = $_.Key; hits = $_.Value }
        })
    } catch {
        Write-Host "[!] Get-HttpHosts failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-TopTalkers {
    # Roll Get-FlowSummary output up to per-IP byte counts so the heaviest
    # external endpoint is one sort away. -Flows takes the array returned by
    # Get-FlowSummary. Local/RFC1918 addresses are flagged, not dropped.
    param([Parameter(Mandatory=$true)]$Flows)
    try {
        $talkers = @{}
        $privRe = "^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1$|fe80:|fc00:|fd)"
        foreach ($f in $Flows) {
            # Prefer the parsed fields (v4 and v6 both) over re-parsing the key.
            $pairs = @()
            if ($f.srcIp -ne $null -and $f.srcIp -ne "") {
                $pairs = @(@{ ip = $f.srcIp; bytes = $f.bytes; packets = $f.packets },
                           @{ ip = $f.dstIp; bytes = $f.bytes; packets = $f.packets })
            } elseif ($f.flow -match "^\s*([0-9.]+):\d+\s*->\s*([0-9.]+):\d+") {
                $pairs = @(@{ ip = $Matches[1]; bytes = $f.bytes; packets = $f.packets },
                           @{ ip = $Matches[2]; bytes = $f.bytes; packets = $f.packets })
            }
            foreach ($p in $pairs) {
                $ip = $p.ip
                if ($ip -eq $null -or $ip -eq "") { continue }
                # v4 hardening: isLocal regex is lowercase-only; IPv6 hex can
                # arrive uppercase, so compare against the lowered address.
                $ipLower = ([string]$ip).ToLower()
                if (-not $talkers.ContainsKey($ip)) {
                    $talkers[$ip] = [pscustomobject]@{
                        ip       = $ip
                        bytes    = 0
                        packets  = 0
                        isLocal  = ($ipLower -match $privRe)
                    }
                }
                $talkers[$ip].bytes   += $p.bytes
                $talkers[$ip].packets += $p.packets
            }
        }
        return @($talkers.Values | Sort-Object bytes -Descending)
    } catch {
        Write-Host "[!] Get-TopTalkers failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-DnsAnomalyReport {
    # Detection (the fix for this module's promise): answers with NO matching
    # query in the same capture are unsolicited — the textbook DNS spoof /
    # cache-poison shape. Queries with no answer are dead-ends worth one look
    # (failed lookups, blocked DNS, or exfil-style queries). The "fix" is
    # awareness plus the recommended next step in the note field; the machine
    # cannot repair a poisoned upstream resolver by itself and it says so.
    param([Parameter(Mandatory=$true)][string]$TxtPath)
    try {
        $queries   = Get-DnsQueries -TxtPath $TxtPath
        $responses = Get-DnsResponses -TxtPath $TxtPath
        $qNames = @{}
        foreach ($q in $queries) {
            $name = ($q.query -replace "\s*\[[^\]]*\]\s*$", "").Trim().ToLower()
            if (-not $qNames.ContainsKey($name)) { $qNames[$name] = 0 }
            $qNames[$name] += $q.hits
        }
        $rNames = @{}
        foreach ($r in $responses) {
            $name = ($r.answer -split " -> ")[0].Trim().ToLower()
            if (-not $rNames.ContainsKey($name)) { $rNames[$name] = 0 }
            $rNames[$name] += $r.hits
        }
        $anomalies = @()
        foreach ($n in $rNames.Keys) {
            if (-not $qNames.ContainsKey($n)) {
                $anomalies += [pscustomobject]@{
                    kind = "answer-without-query"
                    name = $n
                    hits = $rNames[$n]
                    note = "Unsolicited DNS answers seen with no matching query. Cross-check the answering IP against the expected resolver; re-capture with DNS-over-TLS to kill the spoof vector."
                }
            }
        }
        foreach ($n in $qNames.Keys) {
            if (-not $rNames.ContainsKey($n)) {
                $anomalies += [pscustomobject]@{
                    kind = "query-without-answer"
                    name = $n
                    hits = $qNames[$n]
                    note = "Queries with no observed answer. Usually benign (blocked/failed), but repeated high-rate lookups are the DNS-tunnel smell — check byte counts on port 53 in Get-FlowSummary."
                }
            }
        }
        return @($anomalies | Sort-Object hits -Descending)
    } catch {
        Write-Host "[!] Get-DnsAnomalyReport failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-UnusualPorts {
    # Flags flows whose DESTINATION port is not in the expected-service table
    # (well-known service ports + common application ports). C2 and exfil
    # channels live on non-standard ports; this is the first-pass detector.
    # -ExtraExpected: your environment's known odd ports (e.g. game servers).
    param(
        [Parameter(Mandatory=$true)]$Flows,
        [int[]]$ExtraExpected = @()
    )
    try {
        $expected = @{}
        $svc = @(21,22,23,25,53,67,68,69,80,110,119,123,135,137,138,139,143,
                 161,162,194,389,443,445,465,514,587,636,993,995,1194,1433,1521,
                 1723,2049,2082,2083,2086,2087,2095,2096,2181,2375,2376,3000,
                 3306,3389,5060,5061,5222,5432,5601,5672,5900,5985,5986,6379,
                 8000,8008,8080,8443,8888,9000,9090,9200,9300,10000,25565,
                 27015,27017,32400,500,4500,5353,5355,1900,3702,2869,7680,51820)
        foreach ($p in $svc) { $expected[$p] = $true }
        foreach ($p in $ExtraExpected) { $expected[$p] = $true }
        $flagged = @()
        foreach ($f in $Flows) {
            $dstPort = 0
            if ($f.dstPort -ne $null -and $f.dstPort -ne 0) { $dstPort = [int]$f.dstPort }
            elseif ($f.flow -match "->\s*\S+:(\d+)\s*$") { $dstPort = [int]$Matches[1] }
            if ($dstPort -ne 0 -and -not $expected.ContainsKey($dstPort)) {
                $flagged += [pscustomobject]@{
                    flow    = $f.flow
                    dstPort = $dstPort
                    packets = $f.packets
                    bytes   = $f.bytes
                    note    = "Destination port not in the expected-service table. Verify the endpoint (RDAP/crt.sh via the OSINT module) before assuming C2."
                }
            }
        }
        return @($flagged | Sort-Object bytes -Descending)
    } catch {
        Write-Host "[!] Get-UnusualPorts failed: $($_.Exception.Message)"
        return @()
    }
}

function Test-CaptureIntegrity {
    # Re-hash the ETL/TXT on disk and compare against the hashes recorded by
    # Stop-Capture. $true = evidence still byte-identical.
    param([Parameter(Mandatory=$true)]$CaptureResult)
    try {
        $ok = $true
        foreach ($pair in @( @{path=$CaptureResult.etlPath; hash=$CaptureResult.etlHash; label="ETL"},
                             @{path=$CaptureResult.txtPath; hash=$CaptureResult.txtHash; label="TXT"} )) {
            if ($pair.hash -eq "") { Write-Host "[!] Test-CaptureIntegrity: no recorded hash for $($pair.label)"; $ok = $false; continue }
            if (-not (Test-Path $pair.path)) { Write-Host "[!] Test-CaptureIntegrity: missing $($pair.label): $($pair.path)"; $ok = $false; continue }
            $now = (Get-FileHash $pair.path -Algorithm SHA256).Hash
            if ($now -ne $pair.hash) {
                Write-Host "[!] INTEGRITY FAIL: $($pair.label) changed on disk"
                $ok = $false
            } else {
                Write-Host "[+] $($pair.label) integrity OK"
            }
        }
        return $ok
    } catch {
        Write-Host "[!] Test-CaptureIntegrity failed: $($_.Exception.Message)"
        return $false
    }
}

function Export-PacketWitnessReport {
    # One-call completeness (the better-way law for this module): runs every
    # analyzer over $TxtPath, writes a JSON + txt report with SHA-256 hashes
    # and a manifest entry. This is the file Gregg opens; everything else is
    # machinery underneath it.
    param(
        [Parameter(Mandatory=$true)][string]$TxtPath,
        [Parameter(Mandatory=$true)][string]$OutDir
    )
    try {
        if (-not (Test-Path $TxtPath)) { throw "not found: $TxtPath" }
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
        Write-Host "[*] Analyzing $TxtPath"
        $dns    = Get-DnsQueries -TxtPath $TxtPath
        $dnresp = Get-DnsResponses -TxtPath $TxtPath
        $dnanom = Get-DnsAnomalyReport -TxtPath $TxtPath
        $snis   = Get-TlsSnis -TxtPath $TxtPath
        $hosts  = Get-HttpHosts -TxtPath $TxtPath
        $flows  = Get-FlowSummary -TxtPath $TxtPath
        $talkers = Get-TopTalkers -Flows $flows
        $unusual = Get-UnusualPorts -Flows $flows
        $tunnel = Get-DnsTunnelSignals -TxtPath $TxtPath
        $beacon = Get-BeaconingFlows -TxtPath $TxtPath
        $mismatch = Get-SniDnsMismatch -TxtPath $TxtPath
        $doh = Get-DoHSuspectFlows -Flows $flows -TxtPath $TxtPath
        $stamp  = Get-Date -Format "yyyyMMdd_HHmmss"
        $report = [pscustomobject]@{
            generatedUtc   = (Get-Date).ToUniversalTime().ToString("o")
            txtPath        = $TxtPath
            txtSha256      = (Get-FileHash $TxtPath -Algorithm SHA256).Hash
            dnsQueries     = $dns
            dnsResponses   = $dnresp
            dnsAnomalies   = $dnanom
            dnsTunnelSignals = $tunnel
            tlsSnis        = $snis
            httpHosts      = $hosts
            sniDnsMismatch = $mismatch
            dohSuspectFlows = $doh
            beaconingFlows = $beacon
            unusualPorts   = @($unusual | Select-Object -First 50)
            topFlows       = @($flows | Select-Object -First 50)
            topTalkers     = @($talkers | Select-Object -First 50)
        }
        $jsonPath = Join-Path $OutDir "packetwitness_$stamp.json"
        $txtOut   = Join-Path $OutDir "packetwitness_$stamp.txt"
        $report | ConvertTo-Json -Depth 6 | Set-Content $jsonPath -Encoding UTF8
        $lines = @()
        $lines += "PACKET WITNESS REPORT - $stamp"
        $lines += "source txt: $($report.txtPath)"
        $lines += "source sha256: $($report.txtSha256)"
        $lines += ""
        $lines += "== TOP DNS QUERIES =="
        foreach ($q in @($dns | Select-Object -First 25)) { $lines += "  $($q.hits)  $($q.query)" }
        $lines += ""
        $lines += "== DNS ANOMALIES =="
        if ($dnanom.Count -eq 0) { $lines += "  none" }
        foreach ($a in @($dnanom | Select-Object -First 25)) { $lines += "  [$($a.kind)] $($a.hits)  $($a.name)" }
        $lines += ""
        $lines += "== DNS TUNNEL / EXFIL SIGNALS (heuristic) =="
        $tFlags = @($tunnel | Where-Object { $_.kind -eq "tunnel-signal" } | Select-Object -First 25)
        $tNote  = @($tunnel | Where-Object { $_.kind -ne "tunnel-signal" } | Select-Object -First 1)
        if ($tFlags.Count -eq 0) { $lines += "  none" }
        foreach ($t in $tFlags) { $lines += "  [$($t.verdict)] $($t.sld)  queries=$($t.queries) uniq=$($t.uniqueNames) entropy=$($t.avgEntropy) maxlabel=$($t.maxLabelLen)  $($t.reasons)" }
        foreach ($n in $tNote) { $lines += "  $($n.text)" }
        $lines += ""
        $lines += "== PERIODIC FLOWS (BEACONING, heuristic) =="
        $bHits = @($beacon | Where-Object { $_.kind -eq "beacon" } | Select-Object -First 25)
        $bNote = @($beacon | Where-Object { $_.kind -eq "note" } | Select-Object -First 1)
        if ($bHits.Count -eq 0 -and $bNote.Count -eq 0) { $lines += "  none" }
        foreach ($b in $bHits) { $lines += "  $($b.flow)  packets=$($b.packets) interval=$($b.meanIntervalSec)s CV=$($b.cv)" }
        foreach ($n in $bNote) { $lines += "  NOTE: $($n.text)" }
        $lines += ""
        $lines += "== SNI NEVER SEEN IN DNS =="
        if ($mismatch.Count -eq 0) { $lines += "  none" }
        foreach ($m in @($mismatch | Select-Object -First 25)) { $lines += "  $($m.hits)  $($m.sni)" }
        $lines += ""
        $lines += "== DNS-OVER-HTTPS SUSPECT FLOWS =="
        if ($doh.Count -eq 0) { $lines += "  none" }
        foreach ($d in @($doh | Select-Object -First 25)) { $lines += "  [$($d.confidence)] $($d.dstIp) ($($d.provider))  $($d.bytes) bytes  $($d.evidence)" }
        $lines += ""
        $lines += "== UNUSUAL DESTINATION PORTS =="
        if ($unusual.Count -eq 0) { $lines += "  none" }
        foreach ($u in @($unusual | Select-Object -First 25)) { $lines += "  $($u.dstPort)  $($u.bytes) bytes  $($u.flow)" }
        $lines += ""
        $lines += "== TOP TLS SNIS =="
        foreach ($s in @($snis | Select-Object -First 25)) { $lines += "  $($s.hits)  $($s.sni)" }
        $lines += ""
        $lines += "== HTTP HOSTS =="
        foreach ($h in @($hosts | Select-Object -First 25)) { $lines += "  $($h.hits)  $($h.host)" }
        $lines += ""
        $lines += "== TOP TALKERS (bytes) =="
        foreach ($t in @($talkers | Select-Object -First 25)) { $lines += "  $($t.bytes)  $($t.ip)  (local=$($t.isLocal))" }
        $lines += ""
        $lines += "== MANIFEST =="
        $lines += "json sha256: $((Get-FileHash $jsonPath -Algorithm SHA256).Hash)"
        $lines += "txt  sha256: " # filled after write
        $lines | Set-Content $txtOut -Encoding UTF8
        $txtHash = (Get-FileHash $txtOut -Algorithm SHA256).Hash
        # append the txt's own hash to the manifest (hash-after-write)
        $content = Get-Content $txtOut -Raw
        $content = $content -replace "txt  sha256: \s*$", "txt  sha256: $txtHash"
        $content | Set-Content $txtOut -Encoding UTF8
        Write-Host "[+] report written: $jsonPath"
        Write-Host "[+] report written: $txtOut"
        return [pscustomobject]@{ jsonPath = $jsonPath; txtPath = $txtOut }
    } catch {
        throw "Export-PacketWitnessReport failed: $($_.Exception.Message)"
    }
}

function Get-LabelEntropy {
    # Shannon entropy (bits per character) of a string. Used to tell
    # human-readable hostnames ("mail.example.com", ~3 bits) from
    # tunnel/exfil labels ("a9f3Kx...base64 blob...", ~5.5+ bits).
    # PS 5.1-safe: [Math]::Log only, no PS7 helpers.
    param([Parameter(Mandatory=$true)][string]$Text)
    try {
        if ([string]::IsNullOrEmpty($Text)) { return 0.0 }
        $counts = @{}
        foreach ($ch in $Text.ToCharArray()) {
            $k = [string]$ch
            if (-not $counts.ContainsKey($k)) { $counts[$k] = 0 }
            $counts[$k]++
        }
        $n = [double]$Text.Length
        $h = 0.0
        foreach ($k in $counts.Keys) {
            $p = [double]$counts[$k] / $n
            $h -= $p * ([Math]::Log($p) / [Math]::Log(2))
        }
        return [Math]::Round($h, 4)
    } catch {
        return 0.0
    }
}

function Get-SldRollup {
    # Rolls a DNS name up to its 2-label registrable domain
    # ("a.b.example.com" -> "example.com") for per-domain aggregation.
    # HONEST LIMIT: no public-suffix table is shipped, so multi-level
    # suffixes roll up wrong ("a.b.example.co.uk" -> "co.uk"). Documented,
    # not hidden; add a suffix list later if Gregg wants the table.
    param([Parameter(Mandatory=$true)][string]$Name)
    try {
        $n = $Name.Trim().TrimEnd(".").ToLower()
        if ($n -eq "") { return "" }
        if ($n -match "^\d{1,3}(\.\d{1,3}){3}$") { return $n }
        if ($n -match ":" ) { return $n }   # IPv6 literal: not a domain
        $parts = $n -split "\."
        if ($parts.Count -le 2) { return $n }
        return ($parts[$parts.Count - 2] + "." + $parts[$parts.Count - 1])
    } catch {
        return ""
    }
}

function Get-InterArrivalStats {
    # Timestamps (as [datetime]) -> inter-arrival delta stats. Population
    # stddev (not sample): a perfectly periodic beacon must score CV = 0.
    param([Parameter(Mandatory=$true)][datetime[]]$Times)
    try {
        $sorted = @($Times | Sort-Object)
        if ($sorted.Count -lt 2) { return $null }
        $deltas = @()
        for ($i = 1; $i -lt $sorted.Count; $i++) {
            $deltas += ($sorted[$i] - $sorted[$i - 1]).TotalSeconds
        }
        $mean = ($deltas | Measure-Object -Average).Average
        $var = 0.0
        foreach ($d in $deltas) { $var += ($d - $mean) * ($d - $mean) }
        $var = $var / $deltas.Count
        $sd = [Math]::Sqrt($var)
        $cv = 0.0
        if ($mean -gt 0) { $cv = $sd / $mean }
        return [pscustomobject]@{
            packets           = $sorted.Count
            meanIntervalSec   = [Math]::Round($mean, 3)
            stddevIntervalSec = [Math]::Round($sd, 3)
            cv                = [Math]::Round($cv, 4)
            minIntervalSec    = [Math]::Round(($deltas | Measure-Object -Minimum).Minimum, 3)
            maxIntervalSec    = [Math]::Round(($deltas | Measure-Object -Maximum).Maximum, 3)
        }
    } catch {
        return $null
    }
}

function Test-PeriodicFlow {
    # The beacon rule: enough packets, low coefficient of variation, and a
    # mean interval in the sane C2 range (1s..24h). Heuristic, not proof —
    # keepalives and health checks beacon too. Thresholds are parameters.
    param(
        [Parameter(Mandatory=$true)]$Stats,
        [int]$MinPackets = 8,
        [double]$MaxCv = 0.35,
        [double]$MinMeanSec = 1,
        [double]$MaxMeanSec = 86400
    )
    if ($Stats -eq $null) { return $false }
    return ($Stats.packets -ge $MinPackets -and
            $Stats.cv -le $MaxCv -and
            $Stats.meanIntervalSec -ge $MinMeanSec -and
            $Stats.meanIntervalSec -le $MaxMeanSec)
}

function Get-DnsTunnelSignals {
    # DNS exfiltration / tunnel detector (the analyzer Get-DnsAnomalyReport
    # points at but did not ship). Aggregates queries per 2-label domain and
    # scores the tunnel shape: many unique subdomains + high label entropy
    # + long labels + TXT/NULL query share. Verdicts are heuristic and say
    # so; every flag carries the exact rule that fired and the next step
    # (Better-Way Law). Returns only SUSPICIOUS/LIKELY-TUNNEL rows plus one
    # kind="summary" row with the benign count — a full dump of every SLD
    # would be noise.
    param(
        [Parameter(Mandatory=$true)][string]$TxtPath,
        [int]$MinUniqueNames = 40,
        [int]$SuspiciousUniqueNames = 15,
        [double]$TunnelEntropy = 4.1,
        [double]$SuspiciousEntropy = 3.9,
        [int]$TunnelLabelLen = 32,
        [int]$SuspiciousLabelLen = 24
    )
    try {
        $queries = @(Get-DnsQueries -TxtPath $TxtPath)
        if ($queries.Count -eq 0) {
            return @([pscustomobject]@{ kind = "note"; sld = ""; verdict = "NO-DATA";
                text = "no DNS queries parsed from $TxtPath — nothing to assess." })
        }
        $bySld = @{}
        foreach ($q in $queries) {
            $raw = [string]$q.query
            $type = ""
            $name = $raw
            if ($raw -match "^(.*)\s*\[([^\]]*)\]\s*$") {
                $name = $Matches[1].Trim()
                $type = $Matches[2].Trim().ToUpper()
            }
            $sld = Get-SldRollup -Name $name
            if ($sld -eq "") { continue }
            if (-not $bySld.ContainsKey($sld)) {
                $bySld[$sld] = [pscustomobject]@{ names = @{}; hits = 0; exfilTypeHits = 0 }
            }
            $e = $bySld[$sld]
            $e.hits += [int]$q.hits
            if (-not $e.names.ContainsKey($name)) { $e.names[$name] = 0 }
            $e.names[$name] += [int]$q.hits
            if ($type -eq "TXT" -or $type -eq "NULL") { $e.exfilTypeHits += [int]$q.hits }
        }
        $flagged = @()
        $benignCount = 0
        foreach ($sld in $bySld.Keys) {
            $e = $bySld[$sld]
            $uniqueNames = $e.names.Count
            $entSum = 0.0
            $maxLabel = 0
            $totalLen = 0
            $labelCount = 0
            foreach ($nm in $e.names.Keys) {
                $stripped = $nm.ToLower() -replace "\.", ""
                $entSum += Get-LabelEntropy -Text $stripped
                foreach ($lbl in ($nm -split "\.")) {
                    if ($lbl.Length -gt $maxLabel) { $maxLabel = $lbl.Length }
                    $totalLen += $lbl.Length
                    $labelCount++
                }
            }
            $avgEntropy = [Math]::Round($entSum / [Math]::Max(1, $uniqueNames), 3)
            $avgLabel = [Math]::Round($totalLen / [Math]::Max(1, $labelCount), 1)
            $txtShare = 0.0
            if ($e.hits -gt 0) { $txtShare = [Math]::Round([double]$e.exfilTypeHits / $e.hits, 3) }
            $reasons = @()
            if ($uniqueNames -ge $MinUniqueNames)          { $reasons += "unique-subdomains=$uniqueNames (>= $MinUniqueNames)" }
            if ($avgEntropy -ge $TunnelEntropy)           { $reasons += "avg-entropy=$avgEntropy bits (>= $TunnelEntropy)" }
            if ($maxLabel -ge $TunnelLabelLen)            { $reasons += "max-label-len=$maxLabel (>= $TunnelLabelLen)" }
            if ($txtShare -ge 0.3)                        { $reasons += "TXT/NULL-share=$txtShare" }
            $verdict = "BENIGN"
            if ($uniqueNames -ge $MinUniqueNames -and ($avgEntropy -ge $TunnelEntropy -or $maxLabel -ge $TunnelLabelLen)) {
                $verdict = "LIKELY-TUNNEL"
            } elseif ($uniqueNames -ge $SuspiciousUniqueNames -and ($avgEntropy -ge $SuspiciousEntropy -or $maxLabel -ge $SuspiciousLabelLen -or $txtShare -ge 0.3)) {
                $verdict = "SUSPICIOUS"
            }
            if ($verdict -eq "BENIGN") { $benignCount++; continue }
            $note = "Re-capture with the dns-only preset for 10+ minutes; check port-53 byte counts in Get-FlowSummary (tunnels move data, beacons don't); find the querying process (Get-NetTCPConnection owning PID on the capture machine); block the SLD at the resolver if confirmed."
            $flagged += [pscustomobject]@{
                kind        = "tunnel-signal"
                sld         = $sld
                verdict     = $verdict
                queries     = $e.hits
                uniqueNames = $uniqueNames
                avgEntropy  = $avgEntropy
                avgLabelLen = $avgLabel
                maxLabelLen = $maxLabel
                txtNullShare = $txtShare
                reasons     = ($reasons -join "; ")
                note        = $note
            }
        }
        $out = @($flagged | Sort-Object @{Expression={ if ($_.verdict -eq "LIKELY-TUNNEL") { 0 } else { 1 } }}, uniqueNames -Descending)
        $out += [pscustomobject]@{ kind = "summary"; sld = ""; verdict = "";
            text = "assessed $($bySld.Count) domains: $($flagged.Count) flagged, $benignCount benign." }
        return $out
    } catch {
        Write-Host "[!] Get-DnsTunnelSignals failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-BeaconingFlows {
    # C2-beacon / keepalive detector: parses per-packet timestamps off the
    # TCPDump-style etl2txt lines ("2023-10-01 12:30:01.123  TCP
    # 192.168.1.5:54321 -> 192.168.1.1:80  Len=95") and flags flows whose
    # inter-arrival times are regular (low CV, enough packets). Best-effort:
    # etl2txt renderings differ by build; when no timestamps parse, this
    # returns a kind="note" row saying so instead of an empty lie.
    param(
        [Parameter(Mandatory=$true)][string]$TxtPath,
        [int]$MinPackets = 8,
        [double]$MaxCv = 0.35
    )
    try {
        if (-not (Test-Path $TxtPath)) { throw "not found: $TxtPath" }
        $arrowRe = "(\S+)\s*(?:->|→)\s*(\S+)"
        $tsRe = "(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)|(\d{1,2}/\d{1,2}/\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
        $byFlow = @{}
        $tsFound = 0
        $reader = [System.IO.File]::OpenText($TxtPath)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                # [regex]::Match (not -match) so $Matches stays clean for the
                # flow regexes below.
                $ts = $null
                $tm = [regex]::Match($line, $tsRe)
                if ($tm.Success) {
                    try { $ts = [datetime]::Parse($tm.Value, [Globalization.CultureInfo]::InvariantCulture) } catch { $ts = $null }
                }
                # Endpoint parsing shares ConvertTo-EndpointParts with
                # Get-FlowSummary: one validated code path (v4 hardening).
                $am = [regex]::Match($line, $arrowRe)
                if (-not $am.Success) { continue }
                $src = ConvertTo-EndpointParts -Token $am.Groups[1].Value
                $dst = ConvertTo-EndpointParts -Token $am.Groups[2].Value
                if (-not $src.ok -or -not $dst.ok) { continue }
                $sIp = $src.ip; $sPort = $src.port
                $dIp = $dst.ip; $dPort = $dst.port
                $key = "${sIp}:${sPort} -> ${dIp}:${dPort}"
                if (-not $byFlow.ContainsKey($key)) { $byFlow[$key] = @() }
                if ($ts -ne $null) { $byFlow[$key] += $ts; $tsFound++ }
            }
        }
        finally { $reader.Close() }
        if ($tsFound -eq 0) {
            return @([pscustomobject]@{ kind = "note"; flow = ""; packets = 0;
                text = "no parseable packet timestamps in this etl2txt rendering — beaconing needs TCPDump-style lines like 'yyyy-MM-dd HH:mm:ss.fff  TCP  1.2.3.4:5 -> 6.7.8.9:443  Len=..'. Tried ISO (yyyy-MM-dd) and US (M/d/yyyy) shapes." })
        }
        $flagged = @()
        foreach ($key in $byFlow.Keys) {
            $stats = Get-InterArrivalStats -Times $byFlow[$key]
            if (Test-PeriodicFlow -Stats $stats -MinPackets $MinPackets -MaxCv $MaxCv) {
                $flagged += [pscustomobject]@{
                    kind            = "beacon"
                    flow            = $key
                    packets         = $stats.packets
                    meanIntervalSec = $stats.meanIntervalSec
                    cv              = $stats.cv
                    note            = "Regular interval (CV $($stats.cv)). C2 beacons, malware check-ins AND benign keepalives look exactly like this — confirm the endpoint (RDAP/crt.sh via the OSINT module, process owner on the capture machine) before treating it as hostile."
                }
            }
        }
        return @($flagged | Sort-Object meanIntervalSec)
    } catch {
        Write-Host "[!] Get-BeaconingFlows failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-SniDnsMismatch {
    # SNIs observed in TLS handshakes that NEVER appeared in the capture's
    # DNS queries or answers. A TLS connection to a name the machine never
    # resolved is the DoH/DoT-bypass or hardcoded-C2 shape — worth one look
    # each. Honest: a resolver that ran before capture start also produces
    # this, and the note says so.
    param([Parameter(Mandatory=$true)][string]$TxtPath)
    try {
        $snis      = @(Get-TlsSnis -TxtPath $TxtPath)
        $queries   = @(Get-DnsQueries -TxtPath $TxtPath)
        $responses = @(Get-DnsResponses -TxtPath $TxtPath)
        $dnsNames = @{}
        foreach ($q in $queries) {
            $n = [string]$q.query
            if ($n -match "^(.*)\s*\[[^\]]*\]\s*$") { $n = $Matches[1].Trim().ToLower() }
            if (-not $dnsNames.ContainsKey($n)) { $dnsNames[$n] = $true }
        }
        foreach ($r in $responses) {
            $n = (([string]$r.answer) -split " -> ")[0].Trim().ToLower()
            if (-not $dnsNames.ContainsKey($n)) { $dnsNames[$n] = $true }
        }
        $rows = @()
        foreach ($s in $snis) {
            $nm = ([string]$s.sni).ToLower()
            if (-not $dnsNames.ContainsKey($nm)) {
                $rows += [pscustomobject]@{
                    sni  = $s.sni
                    hits = $s.hits
                    dnsSeen = $false
                    note = "TLS to a name never resolved in this capture's DNS. Could be DoH/DoT bypass, a hardcoded endpoint, or the resolver ran before capture start. Cross-check: Get-FlowSummary flows to the destination IP; RDAP the IP via the OSINT module."
                }
            }
        }
        return @($rows | Sort-Object hits -Descending)
    } catch {
        Write-Host "[!] Get-SniDnsMismatch failed: $($_.Exception.Message)"
        return @()
    }
}

function Test-PacketWitnessHygiene {
    # Offline self-test battery: builds synthetic etl2txt-shaped text files
    # in the temp dir and proves the analyzers' claims — entropy values,
    # rollup rules, inter-arrival math, the tunnel verdict (benign traffic
    # stays BENIGN, a 50-subdomain TXT storm flags LIKELY-TUNNEL), the
    # beaconing detector on timestamped flow lines (and its honest note
    # when timestamps are absent), SNI/DNS mismatch logic, the v4 endpoint
    # parser (v6 dot-port flow recovery, invalid-token refusal), the DoH
    # suspect detector (likely vs possible confidence), and the fix-plan
    # command generation. No admin, no network, no pktmon — the parsers are
    # the thing being tested.
    # Scope-safe result collection (see Test-VaultHygiene note): captures
    # each scriptblock's OUTPUT object, never child-scope +=.
    [CmdletBinding()]
    param()
    Write-Host "[*] Packet witness self-test (temp files only, no network, no admin)..." -ForegroundColor Cyan
    $results = @()
    $mk = {
        param($name, $pass, $detail)
        [pscustomobject]@{ Check = $name; Pass = [bool]$pass; Detail = "$detail" }
    }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("bb-pw-hygiene-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        # --- unit: entropy ---
        $results += & $mk "entropy-zero" ((Get-LabelEntropy -Text "aaaaaaaaaaaaaaaa") -eq 0.0) "aaaa x16 -> 0.0"
        $results += & $mk "entropy-two-bit" ([Math]::Abs((Get-LabelEntropy -Text "abcd") - 2.0) -lt 0.0001) "abcd -> 2.0"
        $results += & $mk "entropy-empty" ((Get-LabelEntropy -Text "") -eq 0.0) "empty -> 0.0"
        # --- unit: SLD rollup ---
        $results += & $mk "rollup-3label" ((Get-SldRollup -Name "a.b.example.com") -eq "example.com") "a.b.example.com"
        $results += & $mk "rollup-2label" ((Get-SldRollup -Name "Example.COM.") -eq "example.com") "trailing dot + case"
        $results += & $mk "rollup-ip" ((Get-SldRollup -Name "8.8.8.8") -eq "8.8.8.8") "IPv4 passthrough"
        # --- unit: inter-arrival math ---
        $t0 = [datetime]"2026-10-30T12:00:00"
        $perfect = @(0..9 | ForEach-Object { $t0.AddSeconds($_ * 60) })
        $st = Get-InterArrivalStats -Times $perfect
        $results += & $mk "arrival-perfect" ($st.packets -eq 10 -and $st.meanIntervalSec -eq 60 -and $st.cv -eq 0) "10x 60s -> cv=0"
        $results += & $mk "periodic-rule-hit" (Test-PeriodicFlow -Stats $st) "perfect beacon flags"
        $noisy = @(0, 61, 119, 245, 301, 359, 480, 541, 602, 905) | ForEach-Object { $t0.AddSeconds($_) }
        $st2 = Get-InterArrivalStats -Times $noisy
        $results += & $mk "periodic-rule-miss" (-not (Test-PeriodicFlow -Stats $st2)) "irregular intervals do not flag (cv=$($st2.cv))"
        $short = @(0, 60, 120) | ForEach-Object { $t0.AddSeconds($_) }
        $results += & $mk "periodic-min-packets" (-not (Test-PeriodicFlow -Stats (Get-InterArrivalStats -Times $short))) "3 packets < MinPackets"
        # --- integration: benign DNS stays BENIGN, storm flags LIKELY-TUNNEL ---
        $dnsFile = Join-Path $tmp "dns.txt"
        $dnsLines = @()
        foreach ($i in 1..6)  { $dnsLines += "Query Name: www.example.com";  $dnsLines += "Query Type: A" }
        foreach ($i in 1..4)  { $dnsLines += "Query Name: mail.example.com"; $dnsLines += "Query Type: MX" }
        $dnsLines += "Server Name: cdn.example.com"
        $dnsLines | Set-Content $dnsFile -Encoding UTF8
        $sig = @(Get-DnsTunnelSignals -TxtPath $dnsFile)
        $flagRows = @($sig | Where-Object { $_.kind -eq "tunnel-signal" })
        $results += & $mk "tunnel-benign" ($flagRows.Count -eq 0) "10 benign queries -> no flags"
        $stormFile = Join-Path $tmp "storm.txt"
        $stormLines = @()
        $rng = New-Object System.Random(42)
        $alpha = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
        for ($i = 0; $i -lt 50; $i++) {
            $lbl = -join (1..32 | ForEach-Object { $alpha[$rng.Next($alpha.Length)] })
            $stormLines += "Query Name: $lbl.evil.test"
            $stormLines += "Query Type: TXT"
        }
        $stormLines | Set-Content $stormFile -Encoding UTF8
        $sig2 = @(Get-DnsTunnelSignals -TxtPath $stormFile)
        $stormRow = @($sig2 | Where-Object { $_.kind -eq "tunnel-signal" -and $_.sld -eq "evil.test" })
        $results += & $mk "tunnel-storm" ($stormRow.Count -eq 1 -and $stormRow[0].verdict -eq "LIKELY-TUNNEL") "50 random 32-char TXT subdomains -> LIKELY-TUNNEL ($($stormRow[0].reasons))"
        # --- integration: beaconing on timestamped lines, note without ---
        $bFile = Join-Path $tmp "beacon.txt"
        $bLines = @()
        for ($i = 0; $i -lt 10; $i++) {
            $ts = $t0.AddSeconds($i * 60).ToString("yyyy-MM-dd HH:mm:ss.fff")
            $bLines += "$ts   TCP     192.168.1.5:52341 → 93.184.216.34:443   Len=95"
        }
        $bLines += "2026-10-30 12:00:01.123   TCP     192.168.1.5:52342 → 1.1.1.1:80   Len=60"
        $bLines | Set-Content $bFile -Encoding UTF8
        $beacons = @(Get-BeaconingFlows -TxtPath $bFile)
        $bHits = @($beacons | Where-Object { $_.kind -eq "beacon" })
        $results += & $mk "beacon-detect" ($bHits.Count -eq 1 -and $bHits[0].packets -eq 10 -and $bHits[0].meanIntervalSec -eq 60) "10x 60s flow flags, single packet does not"
        $noTsFile = Join-Path $tmp "nots.txt"
        @("TCP     192.168.1.5:52341 -> 93.184.216.34:443   Len=95") | Set-Content $noTsFile -Encoding UTF8
        $noTs = @(Get-BeaconingFlows -TxtPath $noTsFile)
        $results += & $mk "beacon-no-ts-note" ($noTs.Count -eq 1 -and $noTs[0].kind -eq "note") "no timestamps -> honest note, not empty lie"
        # --- integration: SNI/DNS mismatch ---
        $sniFile = Join-Path $tmp "sni.txt"
        @(
            "Query Name: seen.example.com", "Query Type: A",
            "Server Name: seen.example.com",
            "Server Name: unseen.evil.test"
        ) | Set-Content $sniFile -Encoding UTF8
        $mm = @(Get-SniDnsMismatch -TxtPath $sniFile)
        $results += & $mk "sni-mismatch" ($mm.Count -eq 1 -and $mm[0].sni -eq "unseen.evil.test") "unseen SNI flags, resolved SNI does not"
        # --- unit: endpoint parser (v4 hardening) ---
        $ep = ConvertTo-EndpointParts -Token "192.168.1.5:52341"
        $results += & $mk "endpoint-v4-colon" ($ep.ok -and $ep.ip -eq "192.168.1.5" -and $ep.port -eq 52341) "v4 colon port"
        $ep = ConvertTo-EndpointParts -Token "192.168.1.5.54321"
        $results += & $mk "endpoint-v4-dot" ($ep.ok -and $ep.ip -eq "192.168.1.5" -and $ep.port -eq 54321) "v4 dot port"
        $ep = ConvertTo-EndpointParts -Token "[2001:db8::1]:443"
        $results += & $mk "endpoint-v6-bracket" ($ep.ok -and $ep.ip -eq "2001:db8::1" -and $ep.port -eq 443) "bracketed v6"
        $ep = ConvertTo-EndpointParts -Token "2001:db8::1.443"
        $results += & $mk "endpoint-v6-dot" ($ep.ok -and $ep.ip -eq "2001:db8::1" -and $ep.port -eq 443) "v6 dot port (pktmon shape)"
        $ep = ConvertTo-EndpointParts -Token "2001:db8::1:443"
        $results += & $mk "endpoint-v6-colon" ($ep.ok -and $ep.ip -eq "2001:db8::1" -and $ep.port -eq 443) "bare v6 colon port"
        $ep = ConvertTo-EndpointParts -Token "999.999.999.999:80"
        $results += & $mk "endpoint-bad-octets" (-not $ep.ok) "invalid v4 refused (was fabricated before)"
        $ep = ConvertTo-EndpointParts -Token "notanendpoint"
        $results += & $mk "endpoint-garbage" (-not $ep.ok) "garbage refused"
        $ep = ConvertTo-EndpointParts -Token "10.0.0.1:99999"
        $results += & $mk "endpoint-bad-port" (-not $ep.ok) "port > 65535 refused"
        # --- integration: v6 dot-port lines parse into flows (the v3 silent loss) ---
        $v6File = Join-Path $tmp "v6flows.txt"
        @(
            "2026-10-30 12:00:01.123   TCP     2001:db8::1.52341 → 2001:db8::2.443   Len=120",
            "2026-10-30 12:00:02.123   TCP     2001:db8::1.52341 → 2001:db8::2.443   Len=80"
        ) | Set-Content $v6File -Encoding UTF8
        $v6flows = @(Get-FlowSummary -TxtPath $v6File)
        $results += & $mk "flow-v6-dotport" ($v6flows.Count -eq 1 -and $v6flows[0].bytes -eq 200 -and $v6flows[0].dstPort -eq 443) "2 v6 dot-port lines -> 1 flow, 200 bytes"
        # --- integration: DoH suspect flows ---
        $dohFlows = @(
            [pscustomobject]@{ flow = "192.168.1.5:52341 -> 1.1.1.1:443"; srcIp = "192.168.1.5"; srcPort = 52341; dstIp = "1.1.1.1"; dstPort = 443; packets = 40; bytes = 9000 },
            [pscustomobject]@{ flow = "192.168.1.5:52342 -> 93.184.216.34:443"; srcIp = "192.168.1.5"; srcPort = 52342; dstIp = "93.184.216.34"; dstPort = 443; packets = 40; bytes = 9000 },
            [pscustomobject]@{ flow = "192.168.1.5:53 -> 1.1.1.1:53"; srcIp = "192.168.1.5"; srcPort = 53; dstIp = "1.1.1.1"; dstPort = 53; packets = 10; bytes = 800 }
        )
        $dohTxt = Join-Path $tmp "doh.txt"
        @("Server Name: cloudflare-dns.com") | Set-Content $dohTxt -Encoding UTF8
        $dohRows = @(Get-DoHSuspectFlows -Flows $dohFlows -TxtPath $dohTxt)
        $results += & $mk "doh-likely" ($dohRows.Count -eq 1 -and $dohRows[0].confidence -eq "likely-doh" -and $dohRows[0].dstIp -eq "1.1.1.1") "443->1.1.1.1 + cloudflare-dns.com SNI -> likely-doh; non-resolver 443 and port-53 rows excluded"
        $dohTxt2 = Join-Path $tmp "doh2.txt"
        @("Server Name: some.other.site") | Set-Content $dohTxt2 -Encoding UTF8
        $dohRows2 = @(Get-DoHSuspectFlows -Flows $dohFlows -TxtPath $dohTxt2)
        $results += & $mk "doh-possible" ($dohRows2.Count -eq 1 -and $dohRows2[0].confidence -eq "possible-doh") "same flow, no DoH SNI -> possible-doh, never a guess"
        $results += & $mk "doh-table" ((Get-DoHResolverTable).Count -ge 8) "shipped resolver table present"
        # --- unit: fix plan (Better-Way Law) ---
        $plan = @(Get-PacketWitnessFixPlan -BlockIp "203.0.113.7" -NewDnsServers @("1.1.1.1","9.9.9.9"))
        $hasBlock = @($plan | Where-Object { $_.command -match "New-NetFirewallRule" -and $_.command -match "203\.0\.113\.7" }).Count
        $hasDns = @($plan | Where-Object { $_.command -match "Set-DnsClientServerAddress" -and $_.command -match "9\.9\.9\.9" }).Count
        $ordered = ($plan | ForEach-Object { $_.order }) -join ","
        $results += & $mk "fixplan" ($hasBlock -eq 1 -and $hasDns -eq 1 -and $ordered -eq "1,2,3,4,5") "block+DNS-pin steps, ordered, IP and servers embedded"
        $plan2 = @(Get-PacketWitnessFixPlan)
        $results += & $mk "fixplan-noip" (@($plan2 | Where-Object { $_.command -match "New-NetFirewallRule" }).Count -eq 0) "no -BlockIp -> no block step"
        # --- report ---
        $passed = @($results | Where-Object { $_.Pass }).Count
        $total = $results.Count
        foreach ($r in $results) {
            $mark = "PASS"; if (-not $r.Pass) { $mark = "FAIL" }
            Write-Host ("  [{0}] {1}  {2}" -f $mark, $r.Check, $r.Detail)
        }
        Write-Host ("[+] packet-witness hygiene: {0}/{1} pass" -f $passed, $total) -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Red" })
        return ($passed -eq $total)
    } finally {
        Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Dot-sourcing note: all functions load directly into the caller session.
