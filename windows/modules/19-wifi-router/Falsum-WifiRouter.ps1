<#---------------------------------------------------------------------------
Falsum Wi-Fi + Router — wireless audit and router hardening.
Pure PowerShell 5.1. Zero external dependencies. Windows 10/11.

WHAT IT DOES
  Wi-Fi side (read-only audit + fixes where safe):
  - Lists visible networks with signal/auth: flags OPEN networks and
    WEP/WPA (not WPA2/3).
  - Reviews known (saved) networks: flags stale/never-used profiles and
    auto-connect risks. Remove-  functions delete chosen profiles.
  - Checks the CURRENT connection: auth type, cipher, PMF, signal.
  Router side (guided + active where possible):
  - Gateway discovery, UPnP exposure check (SSDP), remote-admin port probe
    on the gateway (80/443/8080/22/23/3389) — read-only probes.
  - DNS audit: what DNS the interface uses vs the router's DHCP offer.
  - Generates a hardening checklist with the exact clicks for the common
    firmware families, plus a re-test to prove each fix.

Covers problems 951-1050 (Wi-Fi attacks, router vulnerabilities).

BUILT 2026-10-30 by the main agent, in-chat, per Gregg's order.
v1.1 (2026-10-30, cron hardening): +evil-twin detection, +saved-profile
auto-connect risk, +DNS server verdicts (the DHCP-offer comparison the old
synopsis claimed is now real verdicts), +router admin-page fingerprint,
+MAC-randomization check, port 7547 (TR-069) probe, WPA2-TKIP-only flag,
checklist 8 -> 9 steps (DNS), 32-case hygiene battery.
----------------------------------------------------------------------------#>

function Get-WifiVisible {
    <#
    .SYNOPSIS Visible networks with auth/cipher/signal. Read-only.
    #>
    try {
        $raw = netsh wlan show networks mode=bssid 2>$null
        $nets = New-Object System.Collections.ArrayList
        $cur = $null
        foreach ($line in $raw) {
            $t = $line.Trim()
            if ($t -match '^SSID \d+ : (.*)$') {
                if ($cur) { [void]$nets.Add($cur) }
                $cur = [PSCustomObject]@{ SSID=$matches[1].Trim(); Auth=""; Cipher=""; Signal=0; BSSIDs=0 }
            } elseif ($cur -and $t -match '^Authentication\s*:\s*(.+)$') { $cur.Auth = $matches[1].Trim() }
            elseif ($cur -and $t -match '^Cipher\s*:\s*(.+)$') { $cur.Cipher = $matches[1].Trim() }
            elseif ($cur -and $t -match '^Signal\s*:\s*(\d+)%') {
                $s = [int]$matches[1]
                if ($s -gt $cur.Signal) { $cur.Signal = $s }
                $cur.BSSIDs++
            }
        }
        if ($cur) { [void]$nets.Add($cur) }
        return $nets
    } catch {
        Write-Host "[wifirouter] ERROR listing networks: $($_.Exception.Message)"
        return @()
    }
}

function Get-WifiRisk {
    <#
    .SYNOPSIS Scores visible networks. Open/WEP/WPA = findings with fixes.
    #>
    param($Networks)
    $findings = New-Object System.Collections.ArrayList
    foreach ($n in $Networks) {
        if ([string]::IsNullOrWhiteSpace($n.SSID)) { continue }
        if ($n.Auth -match 'Open') {
            [void]$findings.Add([PSCustomObject]@{SSID=$n.SSID; Risk="High"; Issue="OPEN network — no encryption"; Fix="Do not join. If you must: VPN on before any traffic."})
        } elseif ($n.Auth -match 'WEP') {
            [void]$findings.Add([PSCustomObject]@{SSID=$n.SSID; Risk="High"; Issue="WEP — broken since 2001, cracked in minutes"; Fix="Replace the access point or reconfigure to WPA2-AES minimum."})
        } elseif ($n.Auth -match 'WPA([^23]|$)') {
            [void]$findings.Add([PSCustomObject]@{SSID=$n.SSID; Risk="Medium"; Issue="WPA (v1) — weak TKIP"; Fix="Reconfigure to WPA2-AES or WPA3."})
        } elseif ($n.Auth -match 'WPA2' -and $n.Cipher -match 'TKIP' -and $n.Cipher -notmatch 'CCMP|GCMP|AES') {
            [void]$findings.Add([PSCustomObject]@{SSID=$n.SSID; Risk="Medium"; Issue="WPA2 with TKIP-only cipher — no AES"; Fix="Reconfigure the AP to WPA2-AES (CCMP)."})
        }
    }
    return $findings
}

function Get-WifiEvilTwinCandidates {
    <#
    .SYNOPSIS THE finding for Wi-Fi attacks: the same SSID advertising
    different auth/cipher across BSSIDs = possible evil twin. Pure logic
    over Get-WifiVisible rows — no hardware needed to test.
    #>
    param($Networks)
    $out = New-Object System.Collections.ArrayList
    $groups = @{}
    $hidden = 0
    foreach ($n in $Networks) {
        if ([string]::IsNullOrWhiteSpace($n.SSID)) { $hidden++; continue }
        $key = $n.SSID.Trim().ToLowerInvariant()
        if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.ArrayList }
        [void]$groups[$key].Add($n)
    }
    foreach ($key in $groups.Keys) {
        $g = $groups[$key]
        if ($g.Count -lt 2) { continue }
        $auths = @($g | Select-Object -ExpandProperty Auth -Unique | Where-Object { $_ -ne "" })
        $ciphers = @($g | Select-Object -ExpandProperty Cipher -Unique | Where-Object { $_ -ne "" })
        $name = $g[0].SSID
        if ($auths.Count -gt 1) {
            [void]$out.Add([PSCustomObject]@{
                SSID=$name; Bssids=$g.Count; Auths=($auths -join " / "); Ciphers=($ciphers -join " / ")
                Risk="High"
                Issue="Same SSID '$name' advertises DIFFERENT auth ($($auths -join ' vs ')) — classic evil-twin signal"
                Fix="Do not join '$name' until verified. Confirm the real AP's auth with the owner; forget the network, re-add it manually."
            })
        } elseif ($ciphers.Count -gt 1) {
            [void]$out.Add([PSCustomObject]@{
                SSID=$name; Bssids=$g.Count; Auths=($auths -join " / "); Ciphers=($ciphers -join " / ")
                Risk="Medium"
                Issue="Same SSID '$name' advertises different ciphers ($($ciphers -join ' vs ')) — possible misconfig or twin"
                Fix="Verify with the AP owner which cipher is real before joining."
            })
        }
    }
    return [PSCustomObject]@{ Findings=$out; HiddenBssids=$hidden }
}

function Get-WifiKnown {
    <#
    .SYNOPSIS Saved profiles: what your machine auto-joins. Read-only.
    #>
    try {
        $raw = netsh wlan show profiles 2>$null
        $profiles = New-Object System.Collections.ArrayList
        foreach ($line in $raw) {
            if ($line -match 'All User Profile\s*:\s*(.+)$') {
                [void]$profiles.Add($matches[1].Trim())
            }
        }
        return $profiles
    } catch { return @() }
}

function Test-SavedProfileVerdict {
    <#
    .SYNOPSIS Pure classifier: saved profile auth + connection mode -> risk.
    Auto-join to an open network is the drive-by-join vector: your machine
    will attach to any evil twin broadcasting that SSID.
    #>
    param([string]$Auth, [string]$ConnectionMode)
    $auto = $ConnectionMode -match 'auto'
    if ($Auth -match 'Open' -and $auto)   { return [PSCustomObject]@{Risk="High"; Reason="Auto-connects to an OPEN network — your machine will join any twin of it"} }
    if ($Auth -match 'WEP' -and $auto)    { return [PSCustomObject]@{Risk="High"; Reason="Auto-connects to WEP — cracked in minutes"} }
    if ($Auth -match 'WPA([^23]|$)')      { return [PSCustomObject]@{Risk="Medium"; Reason="Saved WPA1 network — weak TKIP"} }
    if ($Auth -match 'Open')              { return [PSCustomObject]@{Risk="Medium"; Reason="Saved OPEN network — one click (or one twin) joins it"} }
    return [PSCustomObject]@{Risk="Low"; Reason="OK"}
}

function Get-WifiSavedProfileRisk {
    <#
    .SYNOPSIS Per saved profile: connection mode + auth -> risk verdict.
    Read-only; THE FIX ships as Remove-WifiProfile (already in module).
    #>
    $names = Get-WifiKnown
    $out = New-Object System.Collections.ArrayList
    foreach ($nm in $names) {
        try {
            $raw = netsh wlan show profiles name="$nm" 2>$null
            $auth = ""; $mode = ""
            foreach ($line in $raw) {
                if ($line -match 'Authentication\s*:\s*(.+)$') { $auth = $matches[1].Trim() }
                elseif ($line -match 'Connection mode\s*:\s*(.+)$') { $mode = $matches[1].Trim() }
            }
            $v = Test-SavedProfileVerdict -Auth $auth -ConnectionMode $mode
            [void]$out.Add([PSCustomObject]@{Profile=$nm; Auth=$auth; ConnectionMode=$mode; Risk=$v.Risk; Reason=$v.Reason})
        } catch {
            Write-Host "[wifirouter] WARN: could not read profile '$nm': $($_.Exception.Message)"
        }
    }
    return $out
}

function Remove-WifiProfile {
    <#
    .SYNOPSIS THE FIX for stale/rogue saved networks: deletes the profile.
    #>
    param([Parameter(Mandatory=$true)][string]$Name)
    try {
        $out = netsh wlan delete profile name="$Name" 2>&1
        Write-Host "[wifirouter] $out"
        return ($out -match 'deleted')
    } catch {
        Write-Host "[wifirouter] ERROR deleting profile: $($_.Exception.Message)"
        return $false
    }
}

function Get-WifiCurrent {
    <#
    .SYNOPSIS Current connection detail: auth, cipher, signal, PMF if shown.
    #>
    try {
        $raw = netsh wlan show interfaces 2>$null
        $info = @{}
        foreach ($line in $raw) {
            if ($line -match '^\s*SSID\s*:\s*(.+)$') { $info['SSID'] = $matches[1].Trim() }
            elseif ($line -match '^\s*Authentication\s*:\s*(.+)$') { $info['Auth'] = $matches[1].Trim() }
            elseif ($line -match '^\s*Cipher\s*:\s*(.+)$') { $info['Cipher'] = $matches[1].Trim() }
            elseif ($line -match '^\s*Signal\s*:\s*(.+)$') { $info['Signal'] = $matches[1].Trim() }
            elseif ($line -match '^\s*802\.11[^\r\n]*:\s*(.+)$') { $info['Radio'] = $matches[1].Trim() }
        }
        $issues = New-Object System.Collections.ArrayList
        if ($info['Auth'] -match 'Open') { [void]$issues.Add("Connected to an OPEN network — treat as hostile: VPN on, no banking.") }
        if ($info['Cipher'] -match 'WEP|TKIP') { [void]$issues.Add("Weak cipher $($info['Cipher']) — reconfigure the AP to AES.") }
        return [PSCustomObject]@{ Info=$info; Issues=$issues }
    } catch {
        Write-Host "[wifirouter] ERROR: $($_.Exception.Message)"
        return $null
    }
}

function Get-RouterGateway {
    try {
        $gw = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
            Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop
        return $gw
    } catch {
        try {
            $r = netsh interface ip show config 2>$null | Select-String "Default Gateway"
            if ($r -match '(\d{1,3}\.){3}\d{1,3}') { return $matches[0] }
        } catch { }
        return $null
    }
}

function Test-RouterPorts {
    <#
    .SYNOPSIS Read-only probe of the gateway's admin surface from the LAN.
    Open telnet/HTTP admin on the LAN side is the finding; the fix is the checklist.
    #>
    param([string]$Gateway)
    if (-not $Gateway) { $Gateway = Get-RouterGateway }
    if (-not $Gateway) { Write-Host "[wifirouter] No gateway found."; return @() }
    Write-Host "[wifirouter] Probing gateway $Gateway (read-only TCP connect)..."
    $ports = @(80,443,8080,8443,7547,22,23,3389,53)
    $res = New-Object System.Collections.ArrayList
    foreach ($p in $ports) {
        $c = New-Object System.Net.Sockets.TcpClient
        $open = $false
        try {
            $iar = $c.BeginConnect($Gateway, $p, $null, $null)
            $open = $iar.AsyncWaitHandle.WaitOne(1500)
            if ($open) { $c.EndConnect($iar) }
        } catch { $open = $false }
        try { $c.Close() } catch { }
        $note = ""
        if ($open -and $p -eq 23) { $note = "TELNET open on gateway — plaintext admin, disable it" }
        if ($open -and $p -eq 80) { $note = "HTTP admin reachable — ensure HTTPS-only + strong password" }
        if ($open -and $p -eq 7547) { $note = "TR-069 (7547) open — ISP remote management; on your own router disable CWMP, on ISP-leased gear you cannot" }
        if ($open -and $p -eq 22) { $note = "SSH admin open on gateway — ensure strong creds, disable if unused" }
        [void]$res.Add([PSCustomObject]@{Port=$p; Open=$open; Note=$note})
    }
    return $res
}

function Test-RouterUpnp {
    <#
    .SYNOPSIS Checks whether the gateway answers SSDP/UPnP discovery.
    UPnP on = LAN devices can open inbound ports without asking you.
    #>
    param([string]$Gateway)
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = 2500
        $msg = [System.Text.Encoding]::ASCII.GetBytes("M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ns=01`"; ns=01`r`nMX: 2`r`nST: upnp:rootdevice`r`n`r`n")
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("239.255.255.250"), 1900)
        [void]$udp.Send($msg, $msg.Length, $ep)
        $found = New-Object System.Collections.ArrayList
        try {
            while ($true) {
                $r = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $b = $udp.Receive([ref]$r)
                $t = [System.Text.Encoding]::ASCII.GetString($b)
                if ($t -match 'LOCATION:\s*(\S+)') { [void]$found.Add([PSCustomObject]@{From=$r.Address.ToString(); Location=$matches[1]}) }
            }
        } catch { }
        $udp.Close()
        return $found
    } catch {
        Write-Host "[wifirouter] UPnP check error: $($_.Exception.Message)"
        return @()
    }
}

function Get-KnownDnsTable {
    <#
    .SYNOPSIS Shipped table of well-known public resolvers.
    #>
    return @(
        [PSCustomObject]@{Ip="1.1.1.1"; Provider="Cloudflare"},
        [PSCustomObject]@{Ip="1.0.0.1"; Provider="Cloudflare"},
        [PSCustomObject]@{Ip="2606:4700:4700::1111"; Provider="Cloudflare"},
        [PSCustomObject]@{Ip="9.9.9.9"; Provider="Quad9"},
        [PSCustomObject]@{Ip="149.112.112.112"; Provider="Quad9"},
        [PSCustomObject]@{Ip="8.8.8.8"; Provider="Google"},
        [PSCustomObject]@{Ip="8.8.4.4"; Provider="Google"},
        [PSCustomObject]@{Ip="208.67.222.222"; Provider="OpenDNS"},
        [PSCustomObject]@{Ip="208.67.220.220"; Provider="OpenDNS"},
        [PSCustomObject]@{Ip="94.140.14.14"; Provider="AdGuard"},
        [PSCustomObject]@{Ip="94.140.15.15"; Provider="AdGuard"}
    )
}

function Test-IsPrivateIpv4 {
    param([string]$Ip)
    if ($Ip -match '^10\.') { return $true }
    if ($Ip -match '^192\.168\.') { return $true }
    if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $true }
    if ($Ip -match '^127\.') { return $true }
    if ($Ip -match '^169\.254\.') { return $true }
    return $false
}

function Test-DnsServerVerdict {
    <#
    .SYNOPSIS Pure classifier for one DNS server IP: known-good / gateway /
    private / unknown-public. An unknown-public resolver you did not set is
    the DNS-hijack signal.
    #>
    param([string]$Ip, [string]$Gateway)
    $known = Get-KnownDnsTable | Where-Object { $_.Ip -eq $Ip } | Select-Object -First 1
    if ($known) { return [PSCustomObject]@{Verdict="known-good"; Detail="Public resolver: $($known.Provider)"} }
    if ($Gateway -and $Ip -eq $Gateway) { return [PSCustomObject]@{Verdict="gateway"; Detail="Router DNS relay — normal, but its upstream is your ISP unless you overrode it"} }
    if (Test-IsPrivateIpv4 $Ip) { return [PSCustomObject]@{Verdict="private"; Detail="Private-range resolver (Pi-hole / LAN DNS?) — fine IF you set it"} }
    if ($Ip -match ':') { return [PSCustomObject]@{Verdict="unknown"; Detail="Unrecognized IPv6 resolver — verify you chose it"} }
    return [PSCustomObject]@{Verdict="unknown-public"; Detail="Unknown public resolver — if you did not set this, treat as a DNS-hijack signal"}
}

function Get-RouterDnsAudit {
    <#
    .SYNOPSIS Interface DNS servers with a verdict per server: known-good /
    gateway-relay / private / unknown-public. Read-only.
    #>
    param([string]$Gateway)
    try {
        $v4 = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway -ne $null }
        $out = New-Object System.Collections.ArrayList
        foreach ($c in $v4) {
            $vers = New-Object System.Collections.ArrayList
            foreach ($s in $c.DNSServer.ServerAddresses) {
                $v = Test-DnsServerVerdict -Ip $s -Gateway $Gateway
                [void]$vers.Add([PSCustomObject]@{Server=$s; Verdict=$v.Verdict; Detail=$v.Detail})
            }
            [void]$out.Add([PSCustomObject]@{Interface=$c.InterfaceAlias; Servers=$vers})
        }
        return $out
    } catch {
        Write-Host "[wifirouter] DNS audit error: $($_.Exception.Message)"
        return @()
    }
}

function ConvertFrom-RouterAdminPage {
    <#
    .SYNOPSIS Pure parser: admin-page HTML + Server header -> vendor hint.
    Never guesses beyond the keyword table: unknown stays unknown.
    #>
    param([string]$Html, [string]$ServerHeader)
    $title = ""
    if ($Html -match '(?is)<title[^>]*>(.*?)</title>') { $title = $matches[1].Trim() }
    $blob = ("$title $ServerHeader").ToLowerInvariant()
    $map = @(
        @{Re='netgear'; Vendor='Netgear'}, @{Re='linksys'; Vendor='Linksys'},
        @{Re='tp-link|tplink'; Vendor='TP-Link'}, @{Re='asus'; Vendor='ASUS'},
        @{Re='arris'; Vendor='Arris'}, @{Re='xfinity|comcast'; Vendor='Xfinity/Comcast gateway'},
        @{Re='motorola'; Vendor='Motorola'}, @{Re='d-link|dlink'; Vendor='D-Link'},
        @{Re='ubiquiti|unifi'; Vendor='Ubiquiti/UniFi'}, @{Re='mikrotik'; Vendor='MikroTik'},
        @{Re='zyxel'; Vendor='ZyXEL'}, @{Re='fritz'; Vendor='AVM FRITZ!Box'},
        @{Re='huawei'; Vendor='Huawei'}, @{Re='eero'; Vendor='eero'},
        @{Re='sagemcom'; Vendor='Sagemcom'}, @{Re='technicolor'; Vendor='Technicolor'}
    )
    $hint = "unknown"
    foreach ($m in $map) { if ($blob -match $m.Re) { $hint = $m.Vendor; break } }
    return [PSCustomObject]@{Title=$title; Server=$ServerHeader; VendorHint=$hint}
}

function Get-RouterFingerprint {
    <#
    .SYNOPSIS Read-only GET of the gateway admin page: Server header + title
    -> vendor hint. Feeds the hardening checklist with the firmware family.
    #>
    param([string]$Gateway)
    if (-not $Gateway) { $Gateway = Get-RouterGateway }
    if (-not $Gateway) { return $null }
    try {
        $req = [System.Net.HttpWebRequest]::Create("http://$Gateway/")
        $req.Timeout = 3000
        $req.UserAgent = "Falsum-WifiRouter/1.1"
        $resp = $req.GetResponse()
        $server = $resp.Headers["Server"]
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $html = $sr.ReadToEnd()
        $sr.Close(); $resp.Close()
        if ($html.Length -gt 8192) { $html = $html.Substring(0, 8192) }
        $p = ConvertFrom-RouterAdminPage -Html $html -ServerHeader $server
        Write-Host "[wifirouter] Gateway admin page: title='$($p.Title)' server='$($p.Server)' -> $($p.VendorHint)"
        return $p
    } catch {
        Write-Host "[wifirouter] Fingerprint: no admin page on http://$Gateway/ ($($_.Exception.Message))"
        return $null
    }
}

function Test-MacRandomization {
    <#
    .SYNOPSIS Reports the Wi-Fi adapter's MAC-randomization advanced property.
    Honest: if the driver does not expose it, say so instead of guessing.
    #>
    try {
        $ad = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.MediaType -match '802\.11' -or $_.InterfaceDescription -match 'Wi-?Fi|Wireless' }
        $out = New-Object System.Collections.ArrayList
        foreach ($a in $ad) {
            $props = Get-NetAdapterAdvancedProperty -Name $a.Name -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -match 'random' -or $_.RegistryKeyword -match 'random' }
            if ($props) {
                foreach ($p in $props) {
                    [void]$out.Add([PSCustomObject]@{Adapter=$a.Name; Property=$p.DisplayName; Value=$p.DisplayValue})
                }
            } else {
                [void]$out.Add([PSCustomObject]@{Adapter=$a.Name; Property="(not exposed by driver)"; Value=""})
            }
        }
        return $out
    } catch {
        Write-Host "[wifirouter] MAC randomization check error: $($_.Exception.Message)"
        return @()
    }
}

function Get-RouterHardeningChecklist {
    <#
    .SYNOPSIS THE FIX: concrete hardening steps + re-test commands.
    #>
    return @(
        [PSCustomObject]@{Step=1; Action="Change the router admin password (not the Wi-Fi password — the admin page login)"; Retest="Try the old password — it must fail"},
        [PSCustomObject]@{Step=2; Action="Disable remote administration / WAN-side management"; Retest="Test-RouterPorts from OUTSIDE the LAN must show admin ports closed"},
        [PSCustomObject]@{Step=3; Action="Disable UPnP unless you run game consoles that need it"; Retest="Test-RouterUpnp returns nothing"},
        [PSCustomObject]@{Step=4; Action="Disable WPS (PIN method)"; Retest="No WPS PIN option on the router page"},
        [PSCustomObject]@{Step=5; Action="Set WPA3 (or WPA2-AES minimum); disable WEP/WPA-TKIP"; Retest="Get-WifiCurrent shows WPA2/WPA3 + CCMP/AES"},
        [PSCustomObject]@{Step=6; Action="Update router firmware to the vendor's latest"; Retest="Firmware date on the admin page is current-year"},
        [PSCustomObject]@{Step=7; Action="Turn off telnet/SSH admin unless you use them; use HTTPS admin"; Retest="Test-RouterPorts: 23 closed"},
        [PSCustomObject]@{Step=8; Action="Review port-forwarding rules — delete what you didn't add"; Retest="No unexplained forwards on the admin page"},
        [PSCustomObject]@{Step=9; Action="Point DNS at a resolver YOU chose (Quad9 9.9.9.9, Cloudflare 1.1.1.1) instead of the ISP default"; Retest="Get-RouterDnsAudit shows verdict known-good on your interfaces"}
    )
}

function Start-WifiRouterAudit {
    <#
    .SYNOPSIS Full audit: Wi-Fi visible/known/current + evil-twin + saved-risk
    + MAC randomization + gateway probes + fingerprint + DNS verdicts +
    hardening checklist.
    #>
    Write-Host "[wifirouter] === Wi-Fi + Router audit ==="
    $vis = Get-WifiVisible
    Write-Host "[wifirouter] Visible networks: $($vis.Count)"
    $risks = Get-WifiRisk $vis
    foreach ($r in $risks) { Write-Host "[wifirouter] [$($r.Risk)] $($r.SSID): $($r.Issue)" }
    $twins = Get-WifiEvilTwinCandidates $vis
    foreach ($t in $twins.Findings) { Write-Host "[wifirouter] [$($t.Risk)] EVIL-TWIN? $($t.Issue)" }
    if ($twins.HiddenBssids -gt 0) { Write-Host "[wifirouter] NOTE: $($twins.HiddenBssids) hidden-SSID BSSID(s) seen — rogue APs often hide their SSID." }
    $known = Get-WifiKnown
    Write-Host "[wifirouter] Saved profiles: $($known.Count) — checking auto-connect risk..."
    $savedRisk = Get-WifiSavedProfileRisk
    foreach ($s in ($savedRisk | Where-Object { $_.Risk -ne "Low" })) {
        Write-Host "[wifirouter] [$($s.Risk)] saved '$($s.Profile)': $($s.Reason)"
        Write-Host "[wifirouter]   FIX: Remove-WifiProfile -Name '$($s.Profile)'"
    }
    $cur = Get-WifiCurrent
    if ($cur) {
        Write-Host "[wifirouter] Current: $($cur.Info['SSID']) auth=$($cur.Info['Auth']) cipher=$($cur.Info['Cipher'])"
        foreach ($i in $cur.Issues) { Write-Host "[wifirouter] ISSUE: $i" }
    }
    $macr = Test-MacRandomization
    foreach ($m in $macr) { Write-Host "[wifirouter] MAC randomization [$($m.Adapter)]: $($m.Property) = $($m.Value)" }
    $gw = Get-RouterGateway
    Write-Host "[wifirouter] Gateway: $gw"
    $fp = Get-RouterFingerprint $gw
    $ports = Test-RouterPorts $gw
    foreach ($p in ($ports | Where-Object { $_.Open })) { Write-Host "[wifirouter] Gateway port $($p.Port) OPEN. $($p.Note)" }
    $upnp = Test-RouterUpnp $gw
    if ($upnp.Count -gt 0) { Write-Host "[wifirouter] UPnP responders: $($upnp.Count) — consider disabling UPnP." }
    $dns = Get-RouterDnsAudit -Gateway $gw
    foreach ($d in $dns) {
        foreach ($s in $d.Servers) {
            Write-Host "[wifirouter] $($d.Interface) DNS $($s.Server): $($s.Verdict) — $($s.Detail)"
        }
    }
    Write-Host ""
    Write-Host "[wifirouter] === Hardening checklist ==="
    foreach ($c in (Get-RouterHardeningChecklist)) { Write-Host "  $($c.Step). $($c.Action)" }
    return [PSCustomObject]@{
        Visible=$vis; WifiRisks=$risks; EvilTwins=$twins.Findings; HiddenBssids=$twins.HiddenBssids
        KnownProfiles=$known; SavedRisks=$savedRisk; Current=$cur; MacRandomization=$macr
        Gateway=$gw; Fingerprint=$fp; OpenPorts=($ports | Where-Object { $_.Open }); Upnp=$upnp; Dns=$dns
    }
}

function Test-WifiRouterHygiene {
    <#
    .SYNOPSIS Offline battery: pure-logic checks, no hardware, no network.
    #>
    $checks = New-Object System.Collections.ArrayList
    $ok = { param($n,$c) [void]$checks.Add([PSCustomObject]@{Check=$n;Pass=[bool]$c}) }.GetNewClosure()
    # Risk scoring on synthetic networks
    $fake = @(
        [PSCustomObject]@{SSID="FreeWifi"; Auth="Open"; Cipher="None"; Signal=80; BSSIDs=1},
        [PSCustomObject]@{SSID="OldRouter"; Auth="WEP"; Cipher="WEP"; Signal=60; BSSIDs=1},
        [PSCustomObject]@{SSID="Wpa1"; Auth="WPA-Personal"; Cipher="TKIP"; Signal=60; BSSIDs=1},
        [PSCustomObject]@{SSID="Wpa1bare"; Auth="WPA"; Cipher="TKIP"; Signal=60; BSSIDs=1},
        [PSCustomObject]@{SSID="Home"; Auth="WPA2-Personal"; Cipher="CCMP-128"; Signal=90; BSSIDs=1},
        [PSCustomObject]@{SSID="Home3"; Auth="WPA3-Personal"; Cipher="GCMP-256"; Signal=90; BSSIDs=1},
        [PSCustomObject]@{SSID="TkipOnly"; Auth="WPA2-Personal"; Cipher="TKIP"; Signal=70; BSSIDs=1}
    )
    $r = Get-WifiRisk $fake
    &$ok "open flagged High" ((($r | Where-Object { $_.SSID -eq "FreeWifi" }).Risk) -eq "High")
    &$ok "wep flagged High" ((($r | Where-Object { $_.SSID -eq "OldRouter" }).Risk) -eq "High")
    &$ok "wpa1-personal flagged Medium" ((($r | Where-Object { $_.SSID -eq "Wpa1" }).Risk) -eq "Medium")
    &$ok "wpa1 bare flagged Medium" ((($r | Where-Object { $_.SSID -eq "Wpa1bare" }).Risk) -eq "Medium")
    &$ok "wpa2 clean" ((($r | Where-Object { $_.SSID -eq "Home" }).Count) -eq 0)
    &$ok "wpa3 clean" ((($r | Where-Object { $_.SSID -eq "Home3" }).Count) -eq 0)
    &$ok "wpa2-tkip-only flagged Medium" ((($r | Where-Object { $_.SSID -eq "TkipOnly" }).Risk) -eq "Medium")
    # Evil twin detection
    $twin = @(
        [PSCustomObject]@{SSID="Cafe"; Auth="WPA2-Personal"; Cipher="CCMP-128"; Signal=80; BSSIDs=1},
        [PSCustomObject]@{SSID="cafe"; Auth="Open"; Cipher="None"; Signal=95; BSSIDs=1},
        [PSCustomObject]@{SSID="Office"; Auth="WPA2-Personal"; Cipher="CCMP-128"; Signal=80; BSSIDs=1},
        [PSCustomObject]@{SSID="Office"; Auth="WPA2-Personal"; Cipher="CCMP-128"; Signal=70; BSSIDs=1},
        [PSCustomObject]@{SSID=""; Auth="WPA2-Personal"; Cipher="CCMP-128"; Signal=60; BSSIDs=1}
    )
    $et = Get-WifiEvilTwinCandidates $twin
    &$ok "twin flagged High" ((($et.Findings | Where-Object { $_.SSID -eq "Cafe" }).Risk) -eq "High")
    &$ok "same-auth dupes clean" ((($et.Findings | Where-Object { $_.SSID -eq "Office" }).Count) -eq 0)
    &$ok "hidden counted not crashed" ($et.HiddenBssids -eq 1)
    # Saved profile verdicts
    &$ok "auto+open High" ((Test-SavedProfileVerdict -Auth "Open" -ConnectionMode "Connect automatically").Risk -eq "High")
    &$ok "auto+wep High" ((Test-SavedProfileVerdict -Auth "WEP" -ConnectionMode "Connect automatically").Risk -eq "High")
    &$ok "manual+open Medium" ((Test-SavedProfileVerdict -Auth "Open" -ConnectionMode "Connect manually").Risk -eq "Medium")
    &$ok "auto+wpa1 Medium" ((Test-SavedProfileVerdict -Auth "WPA-Personal" -ConnectionMode "Connect automatically").Risk -eq "Medium")
    &$ok "auto+wpa2 Low" ((Test-SavedProfileVerdict -Auth "WPA2-Personal" -ConnectionMode "Connect automatically").Risk -eq "Low")
    # DNS verdicts
    &$ok "dns cloudflare known-good" ((Test-DnsServerVerdict -Ip "1.1.1.1" -Gateway "192.168.1.1").Verdict -eq "known-good")
    &$ok "dns quad9 known-good" ((Test-DnsServerVerdict -Ip "9.9.9.9" -Gateway "192.168.1.1").Verdict -eq "known-good")
    &$ok "dns gateway" ((Test-DnsServerVerdict -Ip "192.168.1.1" -Gateway "192.168.1.1").Verdict -eq "gateway")
    &$ok "dns private" ((Test-DnsServerVerdict -Ip "192.168.1.50" -Gateway "192.168.1.1").Verdict -eq "private")
    &$ok "dns unknown-public" ((Test-DnsServerVerdict -Ip "185.22.155.21" -Gateway "192.168.1.1").Verdict -eq "unknown-public")
    &$ok "private 10/8" (Test-IsPrivateIpv4 "10.0.0.5")
    &$ok "private 172.16" (Test-IsPrivateIpv4 "172.16.9.9")
    &$ok "private 172.31" (Test-IsPrivateIpv4 "172.31.255.1")
    &$ok "not private 172.15" (-not (Test-IsPrivateIpv4 "172.15.9.9"))
    &$ok "not private 172.32" (-not (Test-IsPrivateIpv4 "172.32.0.1"))
    &$ok "not private 8.8.8.8" (-not (Test-IsPrivateIpv4 "8.8.8.8"))
    # Admin page fingerprint parse
    $ap = ConvertFrom-RouterAdminPage -Html "<html><head><title>NETGEAR Router R7000</title></head></html>" -ServerHeader "NETGEAR"
    &$ok "fingerprint netgear" ($ap.VendorHint -eq "Netgear")
    &$ok "fingerprint title" ($ap.Title -eq "NETGEAR Router R7000")
    $ap2 = ConvertFrom-RouterAdminPage -Html "<title>Home</title>" -ServerHeader "mini_httpd"
    &$ok "fingerprint unknown honest" ($ap2.VendorHint -eq "unknown")
    &$ok "checklist has 9 steps" ((Get-RouterHardeningChecklist).Count -eq 9)
    &$ok "checklist steps have retests" (((Get-RouterHardeningChecklist) | Where-Object { $_.Retest }).Count -eq 9)
    &$ok "known dns table 11 rows" ((Get-KnownDnsTable).Count -eq 11)
    $pass = ($checks | Where-Object { $_.Pass }).Count
    Write-Host "[wifirouter] Hygiene: $pass/$($checks.Count) checks passed."
    return $checks
}

Write-Host "[wifirouter] Falsum Wi-Fi + Router v1.1 loaded. Start-WifiRouterAudit / Get-WifiEvilTwinCandidates / Get-WifiSavedProfileRisk / Test-SavedProfileVerdict / Test-DnsServerVerdict / Get-RouterFingerprint / Test-MacRandomization / Test-RouterPorts / Test-RouterUpnp / Get-RouterHardeningChecklist / Test-WifiRouterHygiene."
