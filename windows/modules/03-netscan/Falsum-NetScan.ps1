<#
Module 03 — NETSCAN  (hardened 2026-10-30, v4 pass)
TCP connect scan + banner grab + UDP service probes for the user's OWN
network and localhost. No raw sockets, no drivers — pure .NET, works
unprivileged.

Hardening pass: runspace-parallel port sweep (sequential scans of a /24
took hours), real 100-port list, ~160-port service table, TLS certificate
inspection, protocol-aware banner probes, target validation, ARP-table
discovery merge, scan-size guard, port-closure plan (Better-Way Law),
scan-drift diff between two reports.

v2 hardening (this pass): CFAA scope guard — public-IP targets need
-AcknowledgePublic, hostname pre-resolution with dedupe, IPv6 subnet
support (/120../128 enumeration + v6 Test-IpInSubnet), UDP service sweep
(DNS/NTP/NetBIOS/SNMP/IKE/memcached with real protocol probes and
response parsing incl. open-resolver and default-community detection),
HTTP Server-header capture, banner->service classification, OS fingerprint
HINTS (weighted, honestly labeled), -JitterMs stealth timing, expanded
port risk notes, report metadata + CSV export, drift JSON export,
closure plan now covers UDP too.

v3 hardening (this pass): FIXED Test-IsPrivateIp ignoring IPv4-mapped IPv6
(::ffff:10.0.0.1 was misclassified PUBLIC and tripped the scope guard on
your own address); FIXED Get-LiveHosts sharing one Ping instance across
concurrent SendPingAsync calls (race bug); REMOVED dead first $ruleName
assignment in New-PortClosurePlan; NEW port-state detail (-IncludeClosedPorts:
closed vs filtered per port — the difference between RST and silence, needed
for real firewall auditing; reports gain state summary + CSV, drift diff gains
[state] transitions, v1 reports still read as all-open); Test-TargetSpec accepts
trailing-dot FQDNs; Test-TcpPortState replaces duplicated connect logic
(Test-TcpPort stays as a thin wrapper); port-risk table +13 rows; NEW
Test-NetScanHygiene offline battery, wired into launcher option-18 and
tests/Test-All.ps1.

v4 hardening (this pass): FIXED New-PortClosurePlan emitting firewall block
rules for CLOSED and FILTERED ports when the report came from an
-IncludeClosedPorts run (blocking an already-closed port is noise at best,
a false sense of protection at worst — the plan now only considers rows
with state open / open|filtered, and UDP open|filtered rows carry an
explicit "confirm before and after" note); NEW Confirm-PortClosed +
ConvertTo-ClosureVerdict (Better-Way Law: the closure plan ships the fix,
this ships the PROOF — re-probe one target/port and report PASS/FAIL/
INCONCLUSIVE; plan rows now carry a ready-made verify command);
FIXED Get-TlsCertificate mutating the process-global
ServicePointManager.SecurityProtocol (save/restore, it no longer leaks
state into the rest of the session); NEW TLS expiry urgency in the
enrichment phase (certs expiring in <=30 days print EXPIRES IN N DAYS,
expired certs print EXPIRED); NEW SSDP UDP probe (M-SEARCH to :1900 —
routers/TVs/NAS boxes answer unauthenticated, now in the UDP sweep with
response parsing); FIXED drift false-positives — Save-NetScanReport now
records meta.portsScanned and Compare-NetScanReports labels ports the old
scan never probed as [NEWSCOPE] / hosts absent from the new scan as
[UNSCANNED] instead of phantom [NEW]/[CLOSED] (v1-v3 reports without
coverage fall back to the old behavior); FIXED duplicate 8443 in TlsPorts
and duplicate key 53 in PortRiskNotes (second entry silently shadowed the
first — hashtable data bug); battery +22 cases incl. plan-filtering,
verdict mapper, drift verdicts, SSDP packet/detail, TLS-table dedup.

Dot-source:
  . .\Falsum-NetScan.ps1

Typical flow:
  $r = Start-NetScan -Targets @("127.0.0.1") -Ports "common"
  $r = Start-NetScan -Targets @("subnet:10.0.0.0/24") -Ports "top100" -Banners -IncludeUdp
  $r = Start-NetScan -Targets @("subnet:10.0.0.0/24") -Ports "top100" -IncludeClosedPorts
  $r | Where-Object { $_.state -eq "open" } | Format-Table
  Get-OsFingerprintHint -Results $r
  Save-NetScanReport -Results $r -OutDir "C:\cases\case01" -PortSpecLabel "top100" -TargetLabel "subnet:10.0.0.0/24"
  New-PortClosurePlan -Results $r -Keep @("3389")
  Compare-NetScanReports -OldJson .\netscan_old.json -NewJson .\netscan_new.json -OutFile .\drift.json
#>

# ---------------------------------------------------------------------------
# Data tables
# ---------------------------------------------------------------------------

$script:CommonPorts = @{
    21="ftp"; 22="ssh"; 23="telnet"; 25="smtp"; 53="dns"; 67="dhcp-server";
    68="dhcp-client"; 69="tftp"; 80="http"; 88="kerberos"; 110="pop3";
    111="rpcbind"; 119="nntp"; 123="ntp"; 135="msrpc"; 137="netbios-ns";
    138="netbios-dgm"; 139="netbios-ssn"; 143="imap"; 161="snmp";
    162="snmptrap"; 179="bgp"; 199="smux"; 209="qmtp"; 210="z3950";
    220="imap3"; 389="ldap"; 427="slp"; 443="https"; 444="snpp";
    445="smb"; 464="kpasswd"; 465="smtps"; 500="isakmp"; 512="exec";
    513="login"; 514="syslog"; 515="printer"; 517="talk"; 518="ntalk";
    520="rip"; 521="ripng"; 524="ncp"; 530="rpc"; 532="netnews"; 540="uucp";
    543="klogin"; 544="kshell"; 546="dhcpv6-client"; 547="dhcpv6-server";
    548="afp"; 554="rtsp"; 563="nntps"; 567="dantz"; 587="submission";
    591="filemaker"; 593="msft-rpc-http"; 623="ipmi-rmcp"; 631="ipp";
    635="mountd"; 636="ldaps"; 639="msdp"; 646="ldp"; 647="dhcp-failover";
    655="tinc"; 873="rsync"; 989="ftps-data"; 990="ftps"; 992="telnets";
    993="imaps"; 994="ircs"; 995="pop3s"; 1025="nfs-or-iis"; 1080="socks";
    1194="openvpn"; 1241="nessus"; 1311="dell-openmanage"; 1433="mssql";
    1434="mssql-mon"; 1494="citrix-ica"; 1521="oracle"; 1688="kms";
    1701="l2tp"; 1719="h323"; 1720="h323"; 1723="pptp"; 1755="ms-streaming";
    1801="msmq"; 1863="msnp"; 1883="mqtt"; 1900="ssdp"; 1935="rtmp";
    2000="cisco-sccp"; 2049="nfs"; 2082="cpanel"; 2083="cpanel-ssl";
    2086="whm"; 2087="whm-ssl"; 2095="webmail"; 2096="webmail-ssl";
    2121="ccproxy-ftp"; 2179="vmrdp"; 2181="zookeeper"; 2222="directadmin";
    2301="compaqdiag"; 23023="telnet-alt"; 2375="docker"; 2376="docker-tls";
    2379="etcd"; 2401="cvspserver"; 2427="mgcp"; 2483="oracle-net";
    2484="oracle-net-ssl"; 2525="smtp-alt"; 2598="citrix-session";
    2638="sybase"; 28017="mongodb-web"; 2869="icslap"; 2967="symantec-av";
    3000="dev-http"; 3128="squid-proxy"; 3260="iscsi"; 3268="msft-gc";
    3269="msft-gc-ssl"; 3306="mysql"; 3389="rdp"; 3478="stun"; 3689="daap";
    3690="svn"; 3702="ws-discovery"; 4045="nfs-lock"; 4190="sieve";
    4200="vrpn"; 4222="nats"; 4369="epmd"; 4500="ipsec-nat";
    4505="salt-master"; 4506="salt-minion"; 47808="bacnet"; 4848="glassfish";
    4899="radmin"; 5000="upnp"; 5038="asterisk"; 5060="sip"; 5061="sip-tls";
    5190="aim"; 5222="xmpp"; 5269="xmpp-s2s"; 5357="ws-discovery-http";
    5432="postgres"; 5555="adb"; 5601="vnc"; 5631="pcanywhere";
    5632="pcanywhere-data"; 5671="amqp-ssl"; 5672="amqp"; 5800="vnc-http"; 5900="vnc"; 5938="teamviewer";
    5985="winrm-http"; 5986="winrm-https"; 5989="wbem-https"; 6000="x11";
    6001="x11-1"; 6379="redis"; 6443="k8s-api"; 6514="syslog-tls";
    6660="irc"; 6666="irc"; 6667="irc"; 6668="irc"; 6669="irc";
    6697="irc-ssl"; 6881="bittorrent"; 6969="bittorrent-tracker";
    7001="weblogic"; 7474="neo4j"; 7547="tr069"; 8000="http-alt";
    8008="http-alt"; 8009="ajp13"; 8080="http-proxy"; 8081="http-alt";
    8140="puppet"; 8443="https-alt"; 8888="http-alt"; 8983="solr";
    9000="sonar"; 9050="tor-socks"; 9090="http-alt"; 9092="kafka";
    9042="cassandra"; 9100="jetdirect"; 9160="cassandra-thrift";
    9200="elasticsearch"; 9300="elasticsearch-node"; 9418="git";
    10000="webmin"; 10050="zabbix-agent"; 10051="zabbix-server";
    11211="memcached"; 11371="pgp-keyserver"; 11434="ollama";
    12345="netbus"; 15672="rabbitmq-mgmt"; 17500="dropbox-lan";
    27017="mongodb"; 27018="mongodb-shard"; 31337="backorifice"; 33434="traceroute";
    50070="hadoop"; 62078="iphone-sync"
}

# 100 most commonly encountered open TCP ports, grouped: web, mail,
# remote-admin, windows-infra, databases, queues, net-services, voip,
# unix-legacy, mgmt-monitoring. Count is verified == 100.
$script:Top100Ports = @(
    80,443,8080,8000,8008,8081,8443,8888,9000,9090,3000,5000,7001,3128,
    25,110,143,465,587,993,995,4190,2525,
    22,23,3389,5900,5800,5631,5632,5938,2222,4899,
    88,135,137,138,139,389,445,464,593,636,1688,3268,3269,5985,5986,
    1433,1434,1521,3306,5432,6379,27017,28017,9042,9160,
    5671,5672,4369,4222,1883,9092,2181,15672,
    21,53,67,69,123,161,427,520,
    5060,5061,1719,1720,1723,554,1935,3478,2427,
    512,513,514,515,548,873,2049,4045,
    10000,10050,10051,1241,1311,2301,8009,8140,7547
)

# Ports where a direct TLS handshake is worth attempting during -Banners.
$script:TlsPorts = @(443,8443,465,993,995,636,990,6443,5986,3269,2083,2087,2096,2376)

# Ports where an HTTP probe gets a better banner than silence.
$script:HttpProbePorts = @(80,8000,8008,8080,8081,8888,9000,9090,3000,5000,7001,3128)

# Risk notes for the closure plan (Better-Way Law: detection ships the fix).
$script:PortRiskNotes = @{
    21="cleartext FTP auth — replace with SFTP/FTPS or close";
    22="SSH — brute-force target if password auth is on; require key-only auth, fail2ban if exposed";
    23="cleartext telnet — close, use SSH";
    53="DNS — verify NOT an open recursive resolver";
    69="TFTP has no auth — close unless provisioning devices";
    80="HTTP — verify no admin panels or debug endpoints exposed; prefer HTTPS";
    111="rpcbind — close unless NFS in use";
    123="NTP — must NOT be an open amplifier; disable monlist/ntpdc queries";
    135="MSRPC — close unless domain-joined services need it";
    137="NetBIOS — legacy, close";
    138="NetBIOS — legacy, close";
    139="NetBIOS session — legacy, close";
    161="SNMP — close or restrict to management hosts";
    389="LDAP cleartext — require LDAPS (636) or close";
    443="HTTPS — verify certificate validity, disable TLS below 1.2";
    445="SMB — lateral-movement vector, close unless file sharing needed";
    500="IKE — verify PSKs are strong; aggressive mode with weak PSK is crackable";
    512="rexec — cleartext, close";
    513="rlogin — cleartext, close";
    514="syslog — close inbound unless a log collector";
    636="LDAPS — verify certificate and access control";
    1434="SQL Server monitor — close unless clustered";
    2049="NFS — close unless NFS in use";
    2375="Docker API unauthenticated — CLOSE, equals root";
    3306="MySQL — bind localhost or close";
    3389="RDP — keep only if used, restrict source";
    5432="Postgres — bind localhost or close";
    5601="VNC — often weak auth, close or tunnel";
    5900="VNC — often weak auth, close or tunnel";
    6379="Redis — no auth by default, bind localhost or close";
    9200="Elasticsearch — close unless clustered";
    9300="Elasticsearch node — close unless clustered";
    11211="memcached — no auth, close";
    27017="MongoDB — close unless clustered";
    27018="MongoDB shard — close unless clustered";
    28017="MongoDB web — close";
    7547="TR-069 — ISP management, close if not needed";
    25="open SMTP — verify not an open relay; require auth + TLS";
    902="VMware authd — close unless the host is vSphere-managed";
    1099="JNDI/RMI — classic RCE vector, close";
    1433="MSSQL — close unless the database is actually in use";
    1521="Oracle listener — close unless Oracle in use";
    1900="UPnP/SSDP — close, abused for DDoS reflection";
    4500="IPsec NAT-T — only if a VPN is actually in use";
    5000="UPnP — close unless needed";
    5357="WS-Discovery — close unless device discovery needed";
    5985="WinRM HTTP — restrict to management hosts";
    5986="WinRM HTTPS — restrict to management hosts";
    6443="Kubernetes API — close unless this is a cluster node";
    8009="AJP — Ghostcat risk on unpatched Tomcat, close";
    8080="often a web console — require auth, restrict source";
    8443="HTTPS-alt — harden like 443";
    9000="often dev/debug or PHP-FPM — close unless intended";
    9090="often admin/dev dashboards — close unless intended";
    15672="RabbitMQ mgmt — default creds are public knowledge, close or require auth";
    2376="Docker TLS — verify certs are real, restrict source";
    12345="NetBus trojan port — investigate immediately";
    31337="BackOrifice trojan port — investigate immediately"
}

function Get-PortRiskNote {
    param([int]$Port)
    $note = $script:PortRiskNotes[$Port]
    if ($null -eq $note) { return "review whether this service is needed; close if not" }
    return $note
}

# ---------------------------------------------------------------------------
# Scope helpers: private-IP check + hostname pre-resolution
# ---------------------------------------------------------------------------

function Test-IsPrivateIp {
    <#
    True for loopback, RFC1918, link-local, and IPv6 ULA/link-local/loopback.
    Everything else counts as PUBLIC for the scope guard.
    #>
    param([Parameter(Mandatory=$true)][string]$Ip)
    try { $a = [Net.IPAddress]::Parse($Ip) } catch { return $false }
    # FIX (v3): ::ffff:10.0.0.1 is an IPv6 address object in .NET. Without
    # mapping it down first, a private IPv4 address in IPv6 clothing fails
    # every IPv4 check below and trips the scope guard on your own address.
    try { if ($a.IsIPv4MappedToIPv6) { $a = $a.MapToIPv4() } } catch { }
    $b = $a.GetAddressBytes()
    if ($a.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($b.Count -ne 16) { return $false }
        $allZero = $true
        for ($i = 0; $i -lt 15; $i++) { if ($b[$i] -ne 0) { $allZero = $false; break } }
        if ($allZero -and $b[15] -eq 1) { return $true }              # ::1 loopback
        if (($b[0] -band 0xFE) -eq 0xFC) { return $true }              # fc00::/7 ULA
        if ($b[0] -eq 0xFE -and ($b[1] -band 0xC0) -eq 0x80) { return $true } # fe80::/10
        return $false
    }
    if ($b[0] -eq 10) { return $true }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $true }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $true }
    if ($b[0] -eq 127) { return $true }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $true }
    return $false
}

function Resolve-ScanTarget {
    <#
    Resolves one target spec to concrete IPs: expands subnets, pre-resolves
    hostnames (catches typos early instead of mid-scan), returns @{ ips; cidrs }.
    #>
    param([Parameter(Mandatory=$true)][string]$Target)
    $spec = Test-TargetSpec $Target
    if ($spec.kind -eq "subnet") {
        return @{ ips = @(Get-SubnetHosts $spec.value); cidrs = @($spec.value) }
    }
    if ($spec.kind -eq "ip") {
        return @{ ips = @($spec.value); cidrs = @() }
    }
    try {
        $addrs = @([Net.Dns]::GetHostAddresses($spec.value) | ForEach-Object { $_.ToString() })
    } catch {
        throw "Could not resolve hostname '$($spec.value)': $($_.Exception.Message)"
    }
    if ($addrs.Count -eq 0) { throw "Hostname '$($spec.value)' resolved to nothing" }
    Write-Host "[*] $($spec.value) -> $($addrs -join ', ')"
    return @{ ips = $addrs; cidrs = @() }
}

# ---------------------------------------------------------------------------
# Target validation and subnet math
# ---------------------------------------------------------------------------

function Test-TargetSpec {
    param([Parameter(Mandatory=$true)][string]$Target)
    $t = $Target.Trim()
    # Trailing-dot FQDN form ("host.") is legal DNS — normalize before the
    # hostname regex, which only accepts the bare form.
    if ($t.Length -gt 1 -and $t.EndsWith(".")) { $t = $t.Substring(0, $t.Length - 1) }
    if ($t -like "subnet:*") {
        $cidr = $t.Substring(7)
        $parts = $cidr -split "/"
        if ($parts.Count -ne 2) { throw "Bad subnet spec '$Target' — use subnet:10.0.0.0/24" }
        $parsed = $null
        try { $parsed = [Net.IPAddress]::Parse($parts[0]) }
        catch { throw "Bad subnet IP in '$Target': $($_.Exception.Message)" }
        $prefix = 0
        if (-not [int]::TryParse($parts[1], [ref]$prefix)) {
            throw "Bad prefix in '$Target' — use /16../30 (IPv4) or /48../128 (IPv6)"
        }
        if ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
            if ($prefix -lt 48 -or $prefix -gt 128) {
                throw "IPv6 prefix /48../128 supported (got /$prefix in '$Target'). Enumeration needs /120 or narrower."
            }
        } else {
            if ($prefix -lt 16 -or $prefix -gt 30) {
                throw "Prefix /16../30 supported (got /$prefix in '$Target')"
            }
        }
        return [pscustomobject]@{ valid = $true; kind = "subnet"; value = $cidr }
    }
    try {
        [void][Net.IPAddress]::Parse($t)
        return [pscustomobject]@{ valid = $true; kind = "ip"; value = $t }
    } catch { }
    if ($t -match '^[A-Za-z0-9]([A-Za-z0-9\.\-]{0,251}[A-Za-z0-9])?$' -and $t.Length -le 253) {
        return [pscustomobject]@{ valid = $true; kind = "hostname"; value = $t }
    }
    throw "Bad target '$Target' — use an IP, a hostname, or subnet:10.0.0.0/24"
}

function Convert-Ip6ToBigInt {
    # IPv6 bytes (big-endian) -> BigInteger for arithmetic.
    param([Parameter(Mandatory=$true)][byte[]]$Bytes)
    $le = [byte[]]$Bytes.Clone()
    [Array]::Reverse($le)
    $signed = [byte[]]($le + [byte[]]@(0x00))  # extra zero = positive sign byte
    return [System.Numerics.BigInteger]::new($signed)
}

function Convert-BigIntToIp6 {
    param([Parameter(Mandatory=$true)][System.Numerics.BigInteger]$Value)
    $le = @($Value.ToByteArray())
    if ($le.Count -gt 16 -and $le[$le.Count - 1] -eq 0) { $le = $le[0..($le.Count - 2)] }
    while ($le.Count -lt 16) { $le += 0x00 }
    $be = [byte[]]$le
    [Array]::Reverse($be)
    return ([Net.IPAddress]$be).ToString()
}

function Get-SubnetHosts {
    param([Parameter(Mandatory=$true)][string]$Cidr)
    $parts = $Cidr -split "/"
    if ($parts.Count -ne 2) { throw "CIDR must look like 10.0.0.0/24" }
    $addr = [Net.IPAddress]::Parse($parts[0])
    $prefix = [int]$parts[1]
    if ($addr.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($prefix -lt 120 -or $prefix -gt 128) {
            throw "IPv6 enumeration needs /120../128 (got /$prefix — a /64 holds 18 quintillion addresses). Pass explicit host addresses instead."
        }
        $base = Convert-Ip6ToBigInt $addr.GetAddressBytes()
        $count = [System.Numerics.BigInteger]::Pow(2, (128 - $prefix))
        $hosts = @()
        $i = [System.Numerics.BigInteger]::One
        while ($i -lt $count) {
            $hosts += (Convert-BigIntToIp6 ($base + $i))
            $i = $i + 1
        }
        return $hosts
    }
    $base = $addr.GetAddressBytes()
    [Array]::Reverse($base)
    $baseInt = [BitConverter]::ToUInt32($base, 0)
    if ($prefix -lt 16 -or $prefix -gt 30) { throw "prefix /16..30 supported" }
    $count = [math]::Pow(2, (32 - $prefix)) - 2  # exclude network + broadcast
    $hosts = @()
    for ($i = 1; $i -le $count; $i++) {
        $ip = $baseInt + $i
        $b = [BitConverter]::GetBytes([uint32]$ip)
        [Array]::Reverse($b)
        $hosts += ([Net.IPAddress]$b).ToString()
    }
    return $hosts
}

function Test-IpInSubnet {
    param(
        [Parameter(Mandatory=$true)][string]$Ip,
        [Parameter(Mandatory=$true)][string]$Cidr
    )
    $parts = $Cidr -split "/"
    $baseAddr = [Net.IPAddress]::Parse($parts[0])
    $ipAddr = [Net.IPAddress]::Parse($Ip)
    if ($baseAddr.AddressFamily -ne $ipAddr.AddressFamily) { return $false }
    $prefix = [int]$parts[1]
    if ($baseAddr.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        $all = [System.Numerics.BigInteger]::Pow(2, 128) - 1
        $hostBits = [System.Numerics.BigInteger]::Pow(2, (128 - $prefix)) - 1
        $mask = $all - $hostBits
        $b = Convert-Ip6ToBigInt $baseAddr.GetAddressBytes()
        $n = Convert-Ip6ToBigInt $ipAddr.GetAddressBytes()
        return (($n -band $mask) -eq ($b -band $mask))
    }
    $base = $baseAddr.GetAddressBytes()
    [Array]::Reverse($base)
    $baseInt = [BitConverter]::ToUInt32($base, 0)
    $shift = 32 - $prefix
    if ($shift -eq 0) { $mask = [uint32]::MaxValue }
    else { $mask = [uint32]([uint32]::MaxValue -shl $shift) }
    $ipb = $ipAddr.GetAddressBytes()
    [Array]::Reverse($ipb)
    $ipInt = [BitConverter]::ToUInt32($ipb, 0)
    return (($ipInt -band $mask) -eq ($baseInt -band $mask))
}

# ---------------------------------------------------------------------------
# Host discovery: ping sweep + ARP table merge
# ---------------------------------------------------------------------------

function Get-LiveHosts {
    param(
        [Parameter(Mandatory=$true)][string[]]$Hosts,
        [int]$TimeoutMs = 600
    )
    # One Ping instance per host: the .NET Ping class does not reliably
    # support concurrent SendPingAsync calls on a single shared instance
    # (a busy instance can fail or misroute replies), so sharing one
    # across the whole sweep is a race bug. Each instance is disposed.
    $tasks = @{}
    foreach ($h in $Hosts) {
        $p = $null
        try {
            $p = New-Object Net.NetworkInformation.Ping
            $tasks[$h] = [pscustomobject]@{
                Ping = $p
                Task = $p.SendPingAsync($h, $TimeoutMs)
            }
        } catch {
            try { if ($null -ne $p) { $p.Dispose() } } catch { }
        }
    }
    $live = @()
    foreach ($h in $tasks.Keys) {
        $entry = $tasks[$h]
        try {
            if ($entry.Task.Wait($TimeoutMs + 500) -and $entry.Task.Result.Status -eq "Success") {
                $live += $h
            }
        } catch { }
        finally { try { $entry.Ping.Dispose() } catch { } }
    }
    return $live
}

function Get-ArpHosts {
    # Hosts this machine has recently ARPed — catches ping-silent hosts on LAN.
    $out = @()
    try {
        $neigh = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop
        foreach ($n in $neigh) {
            if ($n.State -in @("Reachable","Stale","Permanent","Delay","Probe")) {
                if ($n.IPAddress -notmatch ":") { $out += $n.IPAddress }
            }
        }
    } catch {
        Write-Host "[*] ARP table unreadable: $($_.Exception.Message)"
    }
    return @($out | Sort-Object -Unique)
}

function Get-ReverseDns {
    param([Parameter(Mandatory=$true)][string]$Ip)
    try {
        $e = [Net.Dns]::GetHostEntry($Ip)
        return $e.HostName
    } catch { return "" }
}

# ---------------------------------------------------------------------------
# Port spec expansion
# ---------------------------------------------------------------------------

function Expand-PortSpec {
    param([Parameter(Mandatory=$true)]$Spec)
    # Accepts: "common", "top100", "80-100", "22,80,443", "80-100,443,8080", @(22,80)
    $list = @()
    $tokens = @()
    if ($Spec -is [string]) {
        if ($Spec -eq "common") { return @($script:CommonPorts.Keys | Sort-Object) }
        if ($Spec -eq "top100") { return @($script:Top100Ports | Sort-Object) }
        $tokens = $Spec -split ","
    } else {
        $tokens = @($Spec)
    }
    foreach ($tok in $tokens) {
        $t = "$tok".Trim()
        if ($t -match '^(\d+)\s*-\s*(\d+)$') {
            $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
            if ($lo -gt $hi) { $tmp = $lo; $lo = $hi; $hi = $tmp }
            for ($p = $lo; $p -le $hi; $p++) { $list += $p }
        } elseif ($t -match '^\d+$') {
            $list += [int]$t
        } else {
            throw "Bad port spec token: '$t' (use N, N-M, or comma list)"
        }
    }
    return @($list | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Sort-Object -Unique)
}

# ---------------------------------------------------------------------------
# UDP service sweep: real protocol probes, not just "port open"
# ---------------------------------------------------------------------------

# UDP ports with hand-built probes. No response = open|filtered (ICMP
# unreachable doesn't reliably surface through .NET), a parsed response
# = the service is really there.
$script:UdpProbePorts = @{
    53    = "dns"
    123   = "ntp"
    137   = "netbios-ns"
    161   = "snmp"
    500   = "ike"
    1900  = "ssdp"
    11211 = "memcached"
}

function New-UdpProbePacket {
    param([Parameter(Mandatory=$true)][string]$Service)
    switch ($Service) {
        "dns" {
            # version.bind TXT/CHAOS query: a real resolver answers, and the
            # RA flag tells us whether recursion is offered (open resolver?).
            $id = Get-Random -Minimum 0 -Maximum 65535
            $pkt = @(
                ($id -shr 8) -band 0xFF, $id -band 0xFF,
                0x01, 0x00,   # flags: standard query, RD=1
                0x00, 0x01,   # QDCOUNT=1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
            foreach ($label in ("version.bind" -split "\.")) {
                $pkt += $label.Length
                foreach ($c in $label.ToCharArray()) { $pkt += [byte][char]$c }
            }
            $pkt += 0x00, 0x00, 0x10, 0x00, 0x03   # QTYPE=TXT, QCLASS=CHAOS
            return [byte[]]$pkt
        }
        "ntp" {
            # 48-byte client request, LI=0 VN=3 Mode=3.
            $pkt = New-Object byte[] 48
            $pkt[0] = 0x1B
            return $pkt
        }
        "netbios-ns" {
            # NBNS name query for "*" — a NetBIOS responder answers.
            $id = Get-Random -Minimum 0 -Maximum 65535
            $pkt = @(
                ($id -shr 8) -band 0xFF, $id -band 0xFF,
                0x00, 0x10,   # flags: query, RD=1
                0x00, 0x01,   # QDCOUNT=1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
            $pkt += 0x20  # 32 encoded bytes follow
            $nameBytes = @(0x2A) + (@(0x00) * 15)  # '*' + 15 zero bytes
            foreach ($b in $nameBytes) {
                $pkt += (0x41 + ($b -shr 4))       # 'A' + high nibble
                $pkt += (0x41 + ($b -band 0x0F))   # 'A' + low nibble
            }
            $pkt += 0x00, 0x00, 0x20, 0x00, 0x01   # terminator, NB type, IN class
            return [byte[]]$pkt
        }
        "snmp" {
            # SNMPv2c GET sysDescr.0 with community "public", built byte-exact.
            $reqId = Get-Random -Minimum 1 -Maximum 2147483647
            $rid = @(
                ($reqId -shr 24) -band 0xFF, ($reqId -shr 16) -band 0xFF,
                ($reqId -shr 8) -band 0xFF, $reqId -band 0xFF
            )
            $varbind = @(
                0x30, 0x0E,                                   # varbind SEQUENCE, len 14
                0x30, 0x0C,                                   # value SEQUENCE, len 12
                0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01,
                0x01, 0x01, 0x00,                             # OID 1.3.6.1.2.1.1.1.0
                0x05, 0x00                                    # NULL
            )
            # PDU: 0xA0 get-request, len 28 (2+4+3+3+16)
            $pdu = @(0xA0, 0x1C, 0x02, 0x04) + $rid + @(0x02, 0x01, 0x00, 0x02, 0x01, 0x00) + $varbind
            $community = @("public".ToCharArray() | ForEach-Object { [byte][char]$_ })
            # message: SEQUENCE len 41, version 0, community, pdu
            $msg = @(0x30, 0x29, 0x02, 0x01, 0x00, 0x04, $community.Count) + $community + $pdu
            return [byte[]]$msg
        }
        "ike" {
            # IKEv2 SA_INIT header with random initiator SPI. A real IKE
            # responder replies with a non-zero responder SPI (bytes 8..15).
            $spi = 1..8 | ForEach-Object { Get-Random -Minimum 1 -Maximum 256 }
            $pkt = $spi + @(
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # responder SPI = 0
                0x22, 0x20, 0x22, 0x08,                          # SA, v2.0, IKE_SA_INIT, initiator flag
                0x00, 0x00, 0x00, 0x00,                          # message id
                0x00, 0x00, 0x00, 0x1C                           # length 28
            )
            return [byte[]]$pkt
        }
        "memcached" {
            # memcached speaks UDP: 8-byte header + "version\r\n".
            $id = Get-Random -Minimum 0 -Maximum 65535
            $hdr = @(($id -shr 8) -band 0xFF, $id -band 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00)
            $pay = @("version`r`n".ToCharArray() | ForEach-Object { [byte][char]$_ })
            return [byte[]]($hdr + $pay)
        }
        "ssdp" {
            # SSDP M-SEARCH: UPnP devices (routers, TVs, NAS boxes) answer a
            # unicast M-SEARCH to :1900 with no auth. This is a probe of YOUR
            # LAN — every responder is a device that will talk to anyone.
            $text = 'M-SEARCH * HTTP/1.1' + "`r`n" +
                    'HOST: 239.255.255.250:1900' + "`r`n" +
                    'MAN: "ns:discovery"' + "`r`n" +
                    'MX: 2' + "`r`n" +
                    'ST: ssdp:all' + "`r`n`r`n"
            $bytes = @($text.ToCharArray() | ForEach-Object { [byte][char]$_ })
            return [byte[]]$bytes
        }
    }
    throw "No UDP probe defined for service '$Service'"
}

function Get-UdpResponseDetail {
    param(
        [Parameter(Mandatory=$true)][string]$Service,
        [Parameter(Mandatory=$true)][byte[]]$Response
    )
    if ($Response.Count -eq 0) { return "empty response" }
    switch ($Service) {
        "dns" {
            if ($Response.Count -lt 4) { return "short DNS response" }
            $b3 = $Response[3]
            $ra = ($b3 -band 0x80) -ne 0
            $rcode = $b3 -band 0x0F
            $d = "DNS answered (rcode=$rcode)"
            if ($ra) { $d += " — RECURSION OFFERED: verify this is not an open resolver" }
            return $d
        }
        "ntp" {
            $mode = $Response[0] -band 0x07
            if ($mode -eq 4) { return "NTP server (mode 4)" }
            return "NTP-ish response (mode=$mode)"
        }
        "snmp" {
            if ($Response[0] -eq 0x30 -and $Response.Count -gt 20) {
                return "SNMP answered with community 'public' — CHANGE the community string"
            }
            return "SNMP-ish response"
        }
        "netbios-ns" {
            if ($Response.Count -ge 8 -and (($Response[2] -band 0x80) -ne 0)) {
                $an = ($Response[6] -shl 8) -bor $Response[7]
                return "NetBIOS name service answered (answers=$an)"
            }
            return "NetBIOS-ish response"
        }
        "ike" {
            $nonzero = $false
            for ($i = 8; $i -lt 16 -and $i -lt $Response.Count; $i++) {
                if ($Response[$i] -ne 0) { $nonzero = $true; break }
            }
            if ($nonzero) { return "IKE responder (responder SPI present)" }
            return "IKE-ish response"
        }
        "memcached" {
            $t = [Text.Encoding]::ASCII.GetString($Response)
            if ($t -match "VERSION\s+(\S+)") {
                return "memcached UDP exposed (version $($Matches[1])) — firewall it"
            }
            return "memcached-ish response"
        }
        "ssdp" {
            $t = [Text.Encoding]::ASCII.GetString($Response)
            if ($t -match "^HTTP/1\.1 200") {
                $st = "unknown"
                if ($t -match "(?im)^ST:\s*([^\r\n]+)") { $st = $Matches[1].Trim() }
                return "SSDP/UPnP answered (ST=$st) — review exposed devices, disable UPnP if unneeded"
            }
            return "SSDP-ish response"
        }
    }
    return "response received ($($Response.Count) bytes)"
}

function Test-UdpService {
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][int]$Port,
        [Parameter(Mandatory=$true)][string]$Service,
        [int]$TimeoutMs = 1500
    )
    $udp = New-Object Net.Sockets.UdpClient
    try {
        [void]$udp.Connect($Target, $Port)
        $pkt = New-UdpProbePacket -Service $Service
        [void]$udp.Send($pkt, $pkt.Length)
        $iar = $udp.BeginReceive($null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return [pscustomobject]@{
                target = $Target; port = $Port; service = $Service
                state = "open|filtered"; detail = "no response (firewalled or filtered)"
            }
        }
        $remote = New-Object Net.IPEndPoint ([Net.IPAddress]::Any, 0)
        $resp = $udp.EndReceive($iar, [ref]$remote)
        return [pscustomobject]@{
            target = $Target; port = $Port; service = $Service
            state = "open"; detail = (Get-UdpResponseDetail -Service $Service -Response $resp)
        }
    } catch {
        return [pscustomobject]@{
            target = $Target; port = $Port; service = $Service
            state = "error"; detail = $_.Exception.Message
        }
    } finally {
        $udp.Close()
    }
}

function Start-UdpServiceScan {
    param(
        [Parameter(Mandatory=$true)][string[]]$Targets,
        [int]$TimeoutMs = 1500
    )
    $results = @()
    foreach ($h in $Targets) {
        foreach ($port in ($script:UdpProbePorts.Keys | Sort-Object)) {
            $results += Test-UdpService -Target $h -Port $port `
                -Service $script:UdpProbePorts[$port] -TimeoutMs $TimeoutMs
        }
    }
    $answered = @($results | Where-Object { $_.state -eq "open" }).Count
    Write-Host ("[+] UDP sweep: {0} answered, {1} silent/error of {2} probes" -f
        $answered, ($results.Count - $answered), $results.Count)
    return $results
}

# ---------------------------------------------------------------------------
# Probing: single connect, banner grab, TLS cert
# ---------------------------------------------------------------------------

function Get-ScanResultState {
    <#
    Normalizes a result's state. v1 reports (and old rows) had no state
    field — every v1 row was an open port, so missing means "open".
    #>
    param($Row)
    $s = "$($Row.state)"
    if ($s -eq "") { return "open" }
    return $s
}

function Test-TcpPortState {
    <#
    Port state, not just open-or-not: "open" (connect succeeded),
    "closed" (RST / fast refusal — nothing listening), "filtered"
    (no response within the timeout — firewalled or dropped).
    This is the distinction a firewall audit needs: a closed port and a
    filtered port mean different things about what's in front of you.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][int]$Port,
        [int]$TimeoutMs = 400
    )
    $client = New-Object Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Target, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            try {
                $client.EndConnect($iar)
                return "open"
            } catch {
                return "closed"   # EndConnect threw = refused (RST)
            }
        }
        return "filtered"          # silence for the whole timeout
    } catch {
        return "closed"
    } finally {
        $client.Close()
    }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][int]$Port,
        [int]$TimeoutMs = 400
    )
    return ((Test-TcpPortState @PSBoundParameters) -eq "open")
}

function Read-BannerChunk {
    param(
        [Parameter(Mandatory=$true)][Net.Sockets.NetworkStream]$Stream,
        [int]$TimeoutMs = 800
    )
    $text = ""
    try {
        $Stream.ReadTimeout = $TimeoutMs
        $buf = New-Object byte[] 2048
        $read = $Stream.Read($buf, 0, $buf.Length)
        if ($read -gt 0) {
            $text = [Text.Encoding]::ASCII.GetString($buf, 0, $read)
            $text = $text -replace "[^\x20-\x7e\r\n]", ""
        }
    } catch { }
    return $text
}

function Get-BannerFirstLine {
    param([string]$Text)
    $first = ($Text -split "`r?`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -First 1)
    if ($null -eq $first) { return "" }
    if ($first.Length -gt 120) { $first = $first.Substring(0, 120) }
    return $first.Trim()
}

function Get-PortBanner {
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][int]$Port,
        [int]$TimeoutMs = 1500
    )
    $client = New-Object Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Target, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return "" }
        $client.EndConnect($iar)
        $client.ReceiveTimeout = $TimeoutMs
        $client.SendTimeout = $TimeoutMs
        $stream = $client.GetStream()

        # Phase 1: wait for self-announcing banners (ssh/ftp/smtp/pop3/imap/mysql/vnc...)
        $text = Read-BannerChunk -Stream $stream -TimeoutMs 800
        if ($text.Trim() -ne "") { return Get-BannerFirstLine $text }

        # Phase 2: protocol-aware probe
        $probe = ""
        if ($script:HttpProbePorts -contains $Port) {
            $probe = "HEAD / HTTP/1.0`r`nHost: $Target`r`n`r`n"
        } elseif ($Port -eq 6379) {
            $probe = "PING`r`n"          # redis -> +PONG
        } elseif ($Port -eq 11211) {
            $probe = "version`r`n"       # memcached -> VERSION x.y.z
        } elseif ($Port -eq 25) {
            $probe = "EHLO netscan`r`n"  # smtp servers that wait for client first
        }
        if ($probe -ne "") {
            try {
                $bytes = [Text.Encoding]::ASCII.GetBytes($probe)
                $stream.Write($bytes, 0, $bytes.Length)
                $text = Read-BannerChunk -Stream $stream -TimeoutMs 800
                if ($text.Trim() -ne "") {
                    $line = Get-BannerFirstLine $text
                    if ($script:HttpProbePorts -contains $Port -and $text -match "(?im)^server:\s*([^\r\n]+)") {
                        $srv = $Matches[1].Trim()
                        if ($srv -ne "" -and $line -notlike "*$srv*") { $line = "$line | server: $srv" }
                    }
                    return $line
                }
            } catch { }
        }

        # Phase 3: bare CRLF nudge for anything still silent
        try {
            $bytes = [Text.Encoding]::ASCII.GetBytes("`r`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $text = Read-BannerChunk -Stream $stream -TimeoutMs 600
        } catch { }
        return Get-BannerFirstLine $text
    } catch {
        return ""
    } finally {
        $client.Close()
    }
}

function Get-TlsCertificate {
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][int]$Port,
        [int]$TimeoutMs = 3000
    )
    $client = New-Object Net.Sockets.TcpClient
    # SecurityProtocol is process-global: save it and restore in the
    # finally block so probing one TLS port doesn't change TLS behavior
    # for the rest of the session.
    $oldProto = [Net.ServicePointManager]::SecurityProtocol
    try {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
        $iar = $client.BeginConnect($Target, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $null }
        $client.EndConnect($iar)
        $stream = $client.GetStream()
        $validator = { param($s, $c, $ch, $e) return $true }
        $ssl = New-Object Net.Security.SslStream($stream, $false, $validator)
        $ssl.AuthenticateAsClient($Target)
        $cert = $ssl.RemoteCertificate
        if ($null -eq $cert) { return $null }
        $c2 = New-Object Security.Cryptography.X509Certificates.X509Certificate2($cert)
        return [pscustomobject]@{
            subject    = $c2.Subject
            issuer     = $c2.Issuer
            notAfter   = $c2.NotAfter.ToString("yyyy-MM-dd")
            notAfterDt = $c2.NotAfter
            thumbprint = $c2.Thumbprint
        }
    } catch {
        return $null
    } finally {
        try { [Net.ServicePointManager]::SecurityProtocol = $oldProto } catch { }
        $client.Close()
    }
}

function Get-BannerServiceClass {
    <#
    Classifies the service from banner content — catches services on
    unexpected ports where the port table says "unknown".
    #>
    param([string]$Banner)
    if ([string]::IsNullOrWhiteSpace($Banner)) { return "" }
    $b = $Banner.ToLower()
    $map = @(
        @{ re = "^ssh-";                          svc = "ssh" },
        @{ re = "^220.*ftp|ftp server";            svc = "ftp" },
        @{ re = "^220.*smtp|esmtp";                svc = "smtp" },
        @{ re = "^\+ok";                           svc = "pop3" },
        @{ re = "^\* ok";                          svc = "imap" },
        @{ re = "^rtsp/";                          svc = "rtsp" },
        @{ re = "microsoft-iis|microsoft httpapi"; svc = "iis-http" },
        @{ re = "apache";                          svc = "apache-http" },
        @{ re = "nginx";                           svc = "nginx-http" },
        @{ re = "^http/";                          svc = "http" },
        @{ re = "mysql|mariadb";                   svc = "mysql" },
        @{ re = "postgres";                        svc = "postgres" },
        @{ re = "redis|\+pong";                     svc = "redis" },
        @{ re = "version \d";                      svc = "memcached" },
        @{ re = "vnc|rbf";                         svc = "vnc" }
    )
    foreach ($m in $map) { if ($b -match $m.re) { return $m.svc } }
    return ""
}

function Get-OsFingerprintHint {
    <#
    OS hints from open-port combos + banner keywords. These are HINTS with
    weights, not fingerprint claims — honest about uncertainty.
    #>
    param([Parameter(Mandatory=$true)][object[]]$Results)
    $rules = @(
        @{ ports = @(135, 139, 445);      os = "Windows";                  weight = 3 },
        @{ ports = @(3389);               os = "Windows";                  weight = 2 },
        @{ ports = @(5985, 5986);         os = "Windows";                  weight = 3 },
        @{ ports = @(88, 389, 464);       os = "Windows (domain-joined)";  weight = 3 },
        @{ ports = @(111, 2049);          os = "Linux/Unix (NFS)";         weight = 2 },
        @{ ports = @(22); banner = "openssh";  os = "Linux/Unix (OpenSSH)"; weight = 1 },
        @{ ports = @(22); banner = "dropbear"; os = "embedded (Dropbear)";  weight = 2 },
        @{ ports = @(548, 88);            os = "macOS";                    weight = 2 },
        @{ ports = @(62078);              os = "iOS device";               weight = 2 },
        @{ ports = @(7547);               os = "ISP router (TR-069)";      weight = 2 },
        @{ ports = @(1900, 5000, 2869);   os = "UPnP device / router";     weight = 2 },
        @{ ports = @(9100);               os = "printer (JetDirect)";     weight = 2 }
    )
    $out = @()
    foreach ($g in ($Results | Group-Object -Property target)) {
        $tcpPorts = @($g.Group | Where-Object { "$($_.protocol)" -in @("", "tcp") } |
            Select-Object -ExpandProperty port)
        $banners = ($g.Group | Select-Object -ExpandProperty banner) -join "`n"
        $scores = @{}
        foreach ($rule in $rules) {
            $hit = $true
            foreach ($p in $rule.ports) {
                if ($tcpPorts -notcontains $p) { $hit = $false; break }
            }
            if ($hit -and $rule.ContainsKey("banner")) {
                if ($banners -notmatch $rule.banner) { $hit = $false }
            }
            if ($hit) {
                if (-not $scores.ContainsKey($rule.os)) { $scores[$rule.os] = 0 }
                $scores[$rule.os] += $rule.weight
            }
        }
        $top = $scores.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 2
        $hint = ($top | ForEach-Object { "$($_.Key) (w$($_.Value))" }) -join "; "
        if ($hint -eq "") { $hint = "no strong signal" }
        $out += [pscustomobject]@{ target = $g.Name; osHint = $hint }
        Write-Host ("  [os] {0}: {1}" -f $g.Name, $hint)
    }
    return $out
}

# ---------------------------------------------------------------------------
# Parallel sweep engine (runspaces — PS 5.1 compatible)
# ---------------------------------------------------------------------------

function Start-NetScanParallel {
    param(
        [Parameter(Mandatory=$true)][string[]]$Targets,
        [Parameter(Mandatory=$true)][int[]]$Ports,
        [int]$TimeoutMs = 400,
        [int]$Parallelism = 64,
        [switch]$IncludeClosedPorts
    )
    # Self-contained worker: runspace threads cannot call module functions,
    # so the connect + state-classify logic is embedded in the script block.
    $scanBlock = {
        param($Target_, $Port_, $TimeoutMs_, $EmitAll_)
        $client = New-Object Net.Sockets.TcpClient
        $state = "closed"
        try {
            $iar = $client.BeginConnect($Target_, $Port_, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs_, $false)) {
                try {
                    $client.EndConnect($iar)
                    $state = "open"
                } catch {
                    $state = "closed"    # refused (RST)
                }
            } else {
                $state = "filtered"      # silence for the whole timeout
            }
        } catch {
            $state = "closed"
        }
        finally { $client.Close() }
        if ($state -ne "open" -and -not $EmitAll_) { return $null }
        return [pscustomobject]@{ target = $Target_; port = $Port_; state = $state }
    }

    $all = @()
    foreach ($h in $Targets) { foreach ($p in $Ports) { $all += [pscustomobject]@{ t = $h; p = $p } } }
    $total = $all.Count
    if ($total -eq 0) { return @() }
    $batchSize = $Parallelism * 32

    $iss = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Parallelism, $iss, $Host)
    $found = @()
    try {
        $pool.Open()
        for ($i = 0; $i -lt $total; $i += $batchSize) {
            $end = [math]::Min($i + $batchSize, $total)
            $jobs = @()
            for ($j = $i; $j -lt $end; $j++) {
                $ps = [Management.Automation.PowerShell]::Create()
                $ps.RunspacePool = $pool
                [void]$ps.AddScript($scanBlock).AddParameters(@{
                    Target_ = $all[$j].t; Port_ = $all[$j].p; TimeoutMs_ = $TimeoutMs
                    EmitAll_ = [bool]$IncludeClosedPorts
                })
                $jobs += [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
            }
            foreach ($jb in $jobs) {
                try {
                    $out = $jb.PS.EndInvoke($jb.Handle)
                    foreach ($o in $out) { if ($null -ne $o) { $found += $o } }
                } catch { }
                $jb.PS.Dispose()
            }
            Write-Host ("[*] probed {0}/{1} ({2} open so far)" -f $end, $total, $found.Count)
        }
    } catch {
        Write-Host "[!] parallel sweep failed: $($_.Exception.Message)"
        throw
    } finally {
        $pool.Close()
        $pool.Dispose()
    }
    return $found
}

# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

function Start-NetScan {
    param(
        [Parameter(Mandatory=$true)][string[]]$Targets,
        $Ports = "common",
        [int]$TimeoutMs = 400,
        [int]$ThrottleMs = 0,
        [int]$JitterMs = 0,
        [switch]$Banners,
        [switch]$IncludeUdp,
        [switch]$IncludeClosedPorts,
        [switch]$SkipDiscovery,
        [int]$Parallelism = 64,
        [switch]$Force,
        [switch]$AcknowledgePublic
    )
    # Validate every target up front with a clean error, not a .NET stack.
    foreach ($t in $Targets) { [void](Test-TargetSpec $t) }

    # Resolve hostnames now (catches typos early) and expand subnets.
    $hosts = @()
    $subnetCidrs = @()
    $targetLabel = ($Targets -join ", ")
    foreach ($t in $Targets) {
        $r = Resolve-ScanTarget $t
        $hosts += $r.ips
        $subnetCidrs += $r.cidrs
    }
    $hosts = @($hosts | Sort-Object -Unique)

    # SCOPE GUARD: this tool scans YOUR network. Public-IP targets require
    # -AcknowledgePublic — probing systems you don't own or aren't
    # authorized to test is a federal crime under the CFAA.
    $publicIps = @($hosts | Where-Object { -not (Test-IsPrivateIp $_) })
    if ($publicIps.Count -gt 0 -and -not $AcknowledgePublic) {
        Write-Host "[!] SCOPE GUARD: these targets are PUBLIC IPs, not your local network:"
        foreach ($p in $publicIps) { Write-Host "      $p" }
        Write-Host "[!] Only scan systems you own or are explicitly authorized to test."
        throw "Refusing to scan public IPs without -AcknowledgePublic. Narrow -Targets to your own network, or re-run with -AcknowledgePublic if these are your own authorized systems."
    }
    if ($publicIps.Count -gt 0) {
        Write-Host "[*] -AcknowledgePublic: $($publicIps.Count) public target(s) accepted as your authorized scope."
    }

    $portList = Expand-PortSpec $Ports
    $portSpecLabel = "custom($($portList.Count))"
    if ($Ports -is [string]) { $portSpecLabel = $Ports }

    $totalProbes = $hosts.Count * $portList.Count
    if ($totalProbes -gt 200000 -and -not $Force) {
        throw ("Scan too large: {0} hosts x {1} ports = {2} probes. " -f $hosts.Count, $portList.Count, $totalProbes) +
              "Narrow the scope (smaller subnet, 'top100', -SkipDiscovery) or pass -Force."
    }
    Write-Host "[*] $($hosts.Count) targets x $($portList.Count) ports = $totalProbes probes"

    if (-not $SkipDiscovery -and $hosts.Count -gt 1) {
        Write-Host "[*] host discovery over $($hosts.Count) addresses..."
        $live = Get-LiveHosts -Hosts $hosts
        if ($subnetCidrs.Count -gt 0) {
            $arp = Get-ArpHosts
            foreach ($a in $arp) {
                foreach ($c in $subnetCidrs) {
                    try {
                        if (Test-IpInSubnet -Ip $a -Cidr $c) { $live += $a; break }
                    } catch { }
                }
            }
            $live = @($live | Sort-Object -Unique)
            Write-Host "[*] ARP merge: $($live.Count) candidate hosts"
        }
        $hosts = $live
        Write-Host "[+] $($hosts.Count) live hosts"
    }
    if ($hosts.Count -eq 0) {
        Write-Host "[!] no live hosts — nothing to scan"
        return @()
    }

    if ($ThrottleMs -gt 0 -and $Parallelism -gt 1) {
        Write-Host "[*] -ThrottleMs ignored when -Parallelism > 1 (use -Parallelism 1 for stealth)"
    }

    $portProbes = @()
    if ($Parallelism -le 1) {
        # Sequential path: original behavior, for stealth or tiny scans.
        foreach ($h in $hosts) {
            Write-Host "[*] scanning $h ($($portList.Count) ports)"
            foreach ($p in $portList) {
                $st = Test-TcpPortState -Target $h -Port $p -TimeoutMs $TimeoutMs
                if ($st -eq "open" -or $IncludeClosedPorts) {
                    $portProbes += [pscustomobject]@{ target = $h; port = $p; state = $st }
                    if ($st -eq "open") { Write-Host "  [+] $h`:$p open" }
                }
                if ($ThrottleMs -gt 0) { Start-Sleep -Milliseconds $ThrottleMs }
                if ($JitterMs -gt 0) {
                    Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum ($JitterMs + 1))
                }
            }
        }
    } else {
        Write-Host "[*] parallel sweep, $Parallelism threads..."
        $portProbes = Start-NetScanParallel -Targets $hosts -Ports $portList `
            -TimeoutMs $TimeoutMs -Parallelism $Parallelism -IncludeClosedPorts:$IncludeClosedPorts
    }
    $openRows = @($portProbes | Where-Object { $_.state -eq "open" })

    # Enrichment phase (sequential, open ports only): banners, TLS certs, rDNS.
    $results = @()
    $rdnsCache = @{}
    foreach ($o in ($openRows | Sort-Object target, port)) {
        $h = $o.target
        $p = $o.port
        $svc = $script:CommonPorts[$p]
        if ($null -eq $svc) { $svc = "unknown" }
        if (-not $rdnsCache.ContainsKey($h)) { $rdnsCache[$h] = Get-ReverseDns $h }
        $banner = ""
        $tlsInfo = ""
        if ($Banners) {
            $banner = Get-PortBanner -Target $h -Port $p
            $cls = Get-BannerServiceClass $banner
            if ($cls -ne "" -and $svc -eq "unknown") { $svc = $cls }
            if ($script:TlsPorts -contains $p) {
                $cert = Get-TlsCertificate -Target $h -Port $p
                if ($null -ne $cert) {
                    $tlsInfo = "TLS cert: $($cert.subject) | issuer: $($cert.issuer) | expires: $($cert.notAfter)"
                    if ($null -ne $cert.notAfterDt) {
                        $daysLeft = [int][math]::Floor(($cert.notAfterDt - (Get-Date)).TotalDays)
                        if ($daysLeft -lt 0) {
                            $tlsInfo += "  <-- EXPIRED $([math]::Abs($daysLeft)) days ago"
                        } elseif ($daysLeft -le 30) {
                            $tlsInfo += "  <-- EXPIRES IN $daysLeft DAYS"
                        }
                    }
                }
            }
        }
        $results += [pscustomobject]@{
            target   = $h
            rdns     = $rdnsCache[$h]
            port     = $p
            protocol = "tcp"
            state    = "open"
            service  = $svc
            banner   = $banner
            tls      = $tlsInfo
        }
        Write-Host "  [+] $h`:$p ($svc) $banner"
        if ($tlsInfo -ne "") { Write-Host "      $tlsInfo" }
    }

    # Port-state detail rows: closed/filtered ports get no banners or TLS
    # checks (nothing to grab), but they join the report so the firewall
    # posture is auditable. Default scans have none of these rows.
    $closedRows = @($portProbes | Where-Object { $_.state -ne "open" } | Sort-Object target, port)
    if ($closedRows.Count -gt 0) {
        $nClosed   = @($closedRows | Where-Object { $_.state -eq "closed" }).Count
        $nFiltered = @($closedRows | Where-Object { $_.state -eq "filtered" }).Count
        Write-Host ("[*] port-state detail: {0} closed, {1} filtered" -f $nClosed, $nFiltered)
        foreach ($o in $closedRows) {
            if (-not $rdnsCache.ContainsKey($o.target)) { $rdnsCache[$o.target] = Get-ReverseDns $o.target }
            $svc = $script:CommonPorts[$o.port]
            if ($null -eq $svc) { $svc = "unknown" }
            $results += [pscustomobject]@{
                target   = $o.target
                rdns     = $rdnsCache[$o.target]
                port     = $o.port
                protocol = "tcp"
                state    = $o.state
                service  = $svc
                banner   = ""
                tls      = ""
            }
        }
    }

    # UDP service sweep (optional): real protocol probes, parsed responses.
    if ($IncludeUdp) {
        Write-Host "[*] UDP service probes ($($script:UdpProbePorts.Count) services x $($hosts.Count) hosts)..."
        $udpResults = Start-UdpServiceScan -Targets $hosts -TimeoutMs 1500
        foreach ($u in $udpResults) {
            if (-not $rdnsCache.ContainsKey($u.target)) { $rdnsCache[$u.target] = Get-ReverseDns $u.target }
            $results += [pscustomobject]@{
                target   = $u.target
                rdns     = $rdnsCache[$u.target]
                port     = $u.port
                protocol = "udp"
                state    = $u.state
                service  = $u.service
                banner   = $u.detail
                tls      = ""
            }
            Write-Host ("  [udp] {0}:{1} ({2}) {3} — {4}" -f $u.target, $u.port, $u.service, $u.state, $u.detail)
        }
    }

    Write-Host "[+] scan done: $($results.Count) ports/services on $($hosts.Count) hosts"
    return $results
}

# ---------------------------------------------------------------------------
# Reports, drift diff, closure plan (the fix)
# ---------------------------------------------------------------------------

function Save-NetScanReport {
    param(
        [Parameter(Mandatory=$true)][object[]]$Results,
        [Parameter(Mandatory=$true)][string]$OutDir,
        [string]$PortSpecLabel = "",
        [string]$TargetLabel = "",
        # The port list that was actually probed (int[]). Stored in the
        # report so Compare-NetScanReports can tell a real port change from
        # a scan that simply covered more ports than the last one.
        [int[]]$PortsScanned = @()
    )
    try {
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
        $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $base = Join-Path $OutDir ("netscan_" + $stamp)
        $json = $base + ".json"
        $txt  = $base + ".txt"
        $csv  = $base + ".csv"
        $meta = [pscustomobject]@{
            tool         = "Falsum-NetScan"
            version      = "v4-hardened"
            timestamp    = $stamp
            targets      = $TargetLabel
            portSpec     = $PortSpecLabel
            portsScanned = @($PortsScanned | Sort-Object -Unique)
            hosts        = @($Results | Select-Object -ExpandProperty target -Unique).Count
            openCount    = @($Results | Where-Object { (Get-ScanResultState $_) -eq "open" }).Count
            closedCount  = @($Results | Where-Object { (Get-ScanResultState $_) -eq "closed" }).Count
            filteredCount = @($Results | Where-Object { (Get-ScanResultState $_) -eq "filtered" }).Count
        }
        $payload = [pscustomobject]@{ meta = $meta; results = $Results }
        $payload | ConvertTo-Json -Depth 4 | Set-Content -Path $json -Encoding UTF8
        $lines = @("# NetScan report $stamp", "# targets: $TargetLabel | portSpec: $PortSpecLabel", "")
        $byHost = $Results | Group-Object -Property target
        foreach ($g in $byHost) {
            $lines += "HOST: $($g.Name)  (rdns: $($g.Group[0].rdns))"
            foreach ($r in ($g.Group | Where-Object { (Get-ScanResultState $_) -eq "open" } | Sort-Object protocol, port)) {
                $proto = "$($r.protocol)"; if ($proto -eq "") { $proto = "tcp" }
                $lines += ("  {0} {1,5}  {2,-16}  {3}" -f $proto, $r.port, $r.service, $r.banner)
                if ("$($r.tls)" -ne "") { $lines += ("          {0}" -f $r.tls) }
            }
            # Closed/filtered rows live in the CSV (too many for the txt);
            # the txt carries the per-host posture summary.
            $nC = @($g.Group | Where-Object { (Get-ScanResultState $_) -eq "closed" }).Count
            $nF = @($g.Group | Where-Object { (Get-ScanResultState $_) -eq "filtered" }).Count
            if ($nC -gt 0 -or $nF -gt 0) {
                $lines += ("  port-state: {0} closed, {1} filtered (full list in CSV)" -f $nC, $nF)
            }
            $lines += ""
        }
        $lines | Set-Content -Path $txt -Encoding UTF8
        $Results | Select-Object target, protocol, port, state, service, rdns, banner, tls |
            Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
        $hashes = @{}
        foreach ($f in @($json, $txt, $csv)) {
            $h = Get-FileHash -Path $f -Algorithm SHA256
            $hashes[$f] = $h.Hash
            Write-Host "[+] wrote $f"
            Write-Host "    SHA256 $($h.Hash)"
        }
        return @{ json = $json; txt = $txt; csv = $csv; hashes = $hashes }
    } catch {
        Write-Host "[!] report write failed: $($_.Exception.Message)"
        throw
    }
}

function Test-DriftKeyVerdict {
    <#
    Pure: decides whether a key ("target/proto/port") that appears in only
    ONE of two scan reports is a real change or a coverage artifact. Drift
    lies when one scan covered ports the other never probed — this is the
    function that stops the lie. Verdicts: new (real change), closed (real
    change), newscope (the port wasn't probed in the other scan), unscanned
    (the host wasn't in the new scan at all).
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][ValidateSet("opened","closed")][string]$Direction,
        $OldCoverage = $null,        # ports probed in the OLD scan ($null = unknown -> legacy)
        $NewCoverage = $null,        # ports probed in the NEW scan ($null = unknown -> legacy)
        [string[]]$NewTargets = $null  # targets present in the NEW scan ($null = unknown)
    )
    $parts = $Key -split "/"
    $port = 0
    [int]::TryParse($parts[$parts.Count - 1], [ref]$port) | Out-Null
    $tgt = ""
    if ($parts.Count -ge 3) { $tgt = ($parts[0..($parts.Count - 3)] -join "/") }
    if ($Direction -eq "opened") {
        if ($null -eq $OldCoverage) { return "new" }
        $cov = @($OldCoverage | ForEach-Object { try { [int]$_ } catch { -1 } })
        if ($cov -contains $port) { return "new" }
        return "newscope"
    }
    # Direction = closed: the key WAS in the old report.
    if ($null -eq $NewCoverage) { return "closed" }
    if ($null -ne $NewTargets -and $NewTargets -notcontains $tgt) { return "unscanned" }
    $cov = @($NewCoverage | ForEach-Object { try { [int]$_ } catch { -1 } })
    if ($cov -contains $port) { return "closed" }
    return "newscope"
}

function Compare-NetScanReports {
    param(
        [Parameter(Mandatory=$true)][string]$OldJson,
        [Parameter(Mandatory=$true)][string]$NewJson,
        [string]$OutFile = ""
    )
    try {
        $oldDoc = Get-Content -Path $OldJson -Raw -Encoding UTF8 | ConvertFrom-Json
        $newDoc = Get-Content -Path $NewJson -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "Could not read report JSON: $($_.Exception.Message)"
    }
    # v2 reports wrap results in {meta, results}; v1 reports are a raw array.
    $old = $oldDoc
    if ($null -ne $oldDoc.results) { $old = $oldDoc.results }
    $new = $newDoc
    if ($null -ne $newDoc.results) { $new = $newDoc.results }

    $keyOf = {
        param($r)
        $proto = "$($r.protocol)"
        if ($proto -eq "") { $proto = "tcp" }   # v1 reports had no protocol field
        return "$($r.target)/$proto/$($r.port)"
    }
    $oldMap = @{}
    $newMap = @{}
    foreach ($r in $old) { $oldMap[(& $keyOf $r)] = $r }
    foreach ($r in $new) { $newMap[(& $keyOf $r)] = $r }

    $opened = @()
    $closed = @()
    $changed = @()
    $stateChanged = @()
    $newscopeOpened = @()
    $newscopeClosed = @()
    $unscanned = @()
    # v4 reports record which ports were probed (meta.portsScanned). Without
    # coverage, a bigger second scan reports phantom "[NEW]" ports that the
    # first scan never looked at — drift must say NEWSCOPE instead of crying
    # wolf, and a host missing from the new scan is UNSCANNED, not CLOSED.
    $oldCoverage = $null
    $newCoverage = $null
    if ($null -ne $oldDoc.meta -and $null -ne $oldDoc.meta.portsScanned) { $oldCoverage = @($oldDoc.meta.portsScanned) }
    if ($null -ne $newDoc.meta -and $null -ne $newDoc.meta.portsScanned) { $newCoverage = @($newDoc.meta.portsScanned) }
    $newTargets = @($new | Select-Object -ExpandProperty target -Unique)
    foreach ($k in $newMap.Keys) {
        if (-not $oldMap.ContainsKey($k)) {
            if ((Test-DriftKeyVerdict -Key $k -Direction "opened" -OldCoverage $oldCoverage) -eq "newscope") {
                $newscopeOpened += $newMap[$k]
            } else {
                $opened += $newMap[$k]
            }
        } else {
            $oldState = Get-ScanResultState $oldMap[$k]
            $newState = Get-ScanResultState $newMap[$k]
            if ($oldState -ne $newState) {
                # Filtered->open means a firewall rule changed or a service
                # was exposed; open->filtered means something stopped
                # answering. Both are posture events worth surfacing.
                $stateChanged += [pscustomobject]@{
                    key      = $k
                    oldState = $oldState
                    newState = $newState
                    service  = $newMap[$k].service
                    banner   = $newMap[$k].banner
                }
            } elseif ("$($oldMap[$k].banner)" -ne "$($newMap[$k].banner)") {
                $changed += [pscustomobject]@{
                    key       = $k
                    oldBanner = $oldMap[$k].banner
                    newBanner = $newMap[$k].banner
                }
            }
        }
    }
    foreach ($k in $oldMap.Keys) {
        if (-not $newMap.ContainsKey($k)) {
            switch (Test-DriftKeyVerdict -Key $k -Direction "closed" -NewCoverage $newCoverage -NewTargets $newTargets) {
                "unscanned" { $unscanned += $oldMap[$k] }
                "newscope"  { $newscopeClosed += $oldMap[$k] }
                default     { $closed += $oldMap[$k] }
            }
        }
    }
    Write-Host ("[+] scan drift: {0} newly open, {1} closed, {2} state changes, {3} banner changes, {4} new-coverage, {5} unscanned" -f
        $opened.Count, $closed.Count, $stateChanged.Count, $changed.Count,
        ($newscopeOpened.Count + $newscopeClosed.Count), $unscanned.Count)
    foreach ($r in ($opened | Sort-Object target, protocol, port)) {
        Write-Host ("  [NEW]    {0}/{1}/{2} ({3}) {4}" -f $r.target, $r.protocol, $r.port, $r.service, $r.banner)
    }
    foreach ($r in ($newscopeOpened | Sort-Object target, protocol, port)) {
        Write-Host ("  [NEWSCOPE] {0}/{1}/{2} ({3}) — not covered by the old scan, not a change" -f $r.target, $r.protocol, $r.port, $r.service)
    }
    foreach ($r in ($closed | Sort-Object target, protocol, port)) {
        Write-Host ("  [CLOSED] {0}/{1}/{2} ({3})" -f $r.target, $r.protocol, $r.port, $r.service)
    }
    foreach ($r in ($unscanned | Sort-Object target, protocol, port)) {
        Write-Host ("  [UNSCANNED] {0}/{1}/{2} ({3}) — host not in the new scan" -f $r.target, $r.protocol, $r.port, $r.service)
    }
    foreach ($r in ($newscopeClosed | Sort-Object target, protocol, port)) {
        Write-Host ("  [NEWSCOPE] {0}/{1}/{2} ({3}) — not covered by the new scan, not a change" -f $r.target, $r.protocol, $r.port, $r.service)
    }
    foreach ($s in ($stateChanged | Sort-Object key)) {
        Write-Host ("  [STATE]  {0}: {1} -> {2} ({3}) {4}" -f $s.key, $s.oldState, $s.newState, $s.service, $s.banner)
    }
    foreach ($c in $changed) {
        Write-Host ("  [BANNER] {0}" -f $c.key)
        Write-Host ("           was: {0}" -f $c.oldBanner)
        Write-Host ("           now: {0}" -f $c.newBanner)
    }
    $drift = [pscustomobject]@{ opened = $opened; closed = $closed; bannerChanged = $changed; stateChanged = $stateChanged; newscopeOpened = $newscopeOpened; newscopeClosed = $newscopeClosed; unscanned = $unscanned }
    if ($OutFile -ne "") {
        $drift | ConvertTo-Json -Depth 4 | Set-Content -Path $OutFile -Encoding UTF8
        Write-Host "[+] drift written to $OutFile"
    }
    return $drift
}

function New-PortClosurePlan {
    <#
    Better-Way Law: a scan that only reports is unfinished work.
    Emits exact Windows Firewall commands to close unneeded open ports,
    plus the rollback for each. Nothing is applied — the user reviews
    and runs the block commands. Pass ports to keep via -Keep
    (e.g. @("3389") or @("10.0.0.5:445")).
    #>
    param(
        [Parameter(Mandatory=$true)][object[]]$Results,
        [string[]]$Keep = @()
    )
    $keepSet = @{}
    foreach ($k in $Keep) { $keepSet["$k"] = $true }
    $plan = @()
    Write-Host "# Port closure plan — REVIEW each line before running anything."
    Write-Host "# Every block rule has its rollback printed beside it."
    Write-Host "# Run from an ELEVATED PowerShell prompt."
    # Only OPEN ports get block rules: with -IncludeClosedPorts reports, the
    # rows include closed/filtered ports too, and the v3 plan emitted blocks
    # for those — blocking an already-closed port is noise at best, a false
    # sense of protection at worst.
    $candidates = @($Results | Where-Object {
        (Get-ScanResultState $_) -in @("open", "open|filtered")
    } | Sort-Object target, port)
    foreach ($r in $candidates) {
        $key1 = "$($r.port)"
        $key2 = "$($r.target):$($r.port)"
        if ($keepSet.ContainsKey($key1) -or $keepSet.ContainsKey($key2)) {
            Write-Host "[keep] $($r.target):$($r.port) ($($r.service)) — kept per -Keep"
            continue
        }
        $proto = "$($r.protocol)"
        if ($proto -eq "") { $proto = "tcp" }
        $ruleName = "BB-Block-$($proto.ToUpper())-$($r.port)-$($r.target -replace '[.:]','-')"
        $blockCmd = "New-NetFirewallRule -DisplayName '$ruleName' -Direction Inbound -Protocol $($proto.ToUpper()) -LocalPort $($r.port) -Action Block -Profile Any"
        $undoCmd  = "Remove-NetFirewallRule -DisplayName '$ruleName'"
        $verifyCmd = "Confirm-PortClosed -Target '$($r.target)' -Port $($r.port) -Protocol $proto"
        $why = Get-PortRiskNote $r.port
        $note = ""
        if ((Get-ScanResultState $r) -eq "open|filtered") {
            $note = "UDP probe was inconclusive (no response = filtered or dropped) — run the verify command BEFORE and AFTER blocking."
        }
        $plan += [pscustomobject]@{
            target   = $r.target
            port     = $r.port
            protocol = $proto
            service  = $r.service
            risk     = $why
            block    = $blockCmd
            rollback = $undoCmd
            verify   = $verifyCmd
            note     = $note
        }
        Write-Host "[block] $($r.target):$($r.port)/$proto ($($r.service))"
        Write-Host "        why: $why"
        Write-Host "        $blockCmd"
        Write-Host "        rollback: $undoCmd"
        Write-Host "        verify:   $verifyCmd"
        if ($note -ne "") { Write-Host "        note: $note" }
    }
    if ($plan.Count -eq 0) { Write-Host "[+] nothing to close — every open port is in -Keep" }
    return $plan
}

function ConvertTo-ClosureVerdict {
    <#
    Pure: maps a re-probe state to a closure verdict. TCP is honest —
    closed/filtered means the block worked. UDP has no RST, so a silent
    probe ("open|filtered") means the block is effective; an answer means
    it is not.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$State,
        [Parameter(Mandatory=$true)][ValidateSet("tcp","udp")][string]$Protocol
    )
    if ($Protocol -eq "tcp") {
        if ($State -in @("closed", "filtered")) { return "PASS" }
        if ($State -eq "open") { return "FAIL" }
        return "INCONCLUSIVE"
    }
    if ($State -eq "open|filtered") { return "PASS" }
    if ($State -eq "open") { return "FAIL" }
    return "INCONCLUSIVE"
}

function Confirm-PortClosed {
    <#
    Better-Way Law: the closure plan ships the fix; this ships the PROOF.
    Re-probes one target/port and reports PASS (closure effective), FAIL
    (still answering — the block rule did not land), or INCONCLUSIVE
    (could not probe). Run it after applying the block rules printed by
    New-PortClosurePlan — a fix you never verify is a guess.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][int]$Port,
        [ValidateSet("tcp","udp")][string]$Protocol = "tcp",
        [int]$TimeoutMs = 800
    )
    $state = "error"
    $detail = ""
    if ($Protocol -eq "tcp") {
        $state = Test-TcpPortState -Target $Target -Port $Port -TimeoutMs $TimeoutMs
    } else {
        $svc = $script:UdpProbePorts[$Port]
        if ($null -eq $svc) {
            Write-Host "[?] $Target`:$Port/$Protocol — no UDP probe defined for this port, cannot verify"
            return [pscustomobject]@{
                target = $Target; port = $Port; protocol = $Protocol
                state = "error"; verdict = "INCONCLUSIVE"; detail = "no UDP probe defined for port $Port"
            }
        }
        $probe = Test-UdpService -Target $Target -Port $Port -Service $svc -TimeoutMs ([math]::Max($TimeoutMs, 1500))
        $state = $probe.state
        $detail = $probe.detail
    }
    $verdict = ConvertTo-ClosureVerdict -State $state -Protocol $Protocol
    $tag = @{ PASS = "[+]"; FAIL = "[!]"; INCONCLUSIVE = "[?]" }[$verdict]
    Write-Host ("{0} {1}:{2}/{3} re-probe state={4} -> {5} {6}" -f $tag, $Target, $Port, $Protocol, $state, $verdict, $detail)
    return [pscustomobject]@{
        target = $Target; port = $Port; protocol = $Protocol
        state = $state; verdict = $verdict; detail = $detail
    }
}

function Test-NetScanHygiene {
    <#
    Offline self-test battery for netscan: scope-guard predicate (private
    IP detection — the thing that keeps scans on your own network), port
    spec expansion, subnet math, banner classification, risk table, and
    target-spec validation. No network traffic; pure logic. Returns $true
    when every check passes, throws on the first failure.
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

    # 1. Private-IP predicate — scope guard's foundation.
    $privateCases = @(
        @("127.0.0.1", $true),  @("10.1.2.3", $true),
        @("172.16.0.1", $true), @("172.31.255.255", $true),
        @("192.168.0.1", $true), @("169.254.1.1", $true),
        @("172.32.0.1", $false), @("8.8.8.8", $false),
        @("::1", $true), @("fc00::1", $true), @("fe80::1", $true),
        @("2001:db8::1", $false),
        @("::ffff:10.0.0.1", $true),   # v4-mapped: the v3 fix
        @("::ffff:8.8.8.8", $false),
        @("not-an-ip", $false)
    )
    foreach ($c in $privateCases) {
        $got = Test-IsPrivateIp $c[0]
        $checks += & $add ("private-ip[$($c[0])]") ($got -eq $c[1]) ("want=$($c[1]) got=$got")
    }

    # 2. Port spec expansion.
    $checks += & $add "expand['80-82']" ((@(Expand-PortSpec "80-82") -join ",") -eq "80,81,82") "got=$((@(Expand-PortSpec '80-82')) -join ',')"
    $checks += & $add "expand['22,443']" ((@(Expand-PortSpec "22,443") -join ",") -eq "22,443") ""
    $checks += & $add "expand['100-90']" ((@(Expand-PortSpec "100-90") -join ",") -eq "90,91,92,93,94,95,96,97,98,99,100") "reversed range"
    $checks += & $add "expand[@(22,80)]" ((@(Expand-PortSpec @(22,80)) -join ",") -eq "22,80") "array form"
    $checks += & $add "expand['common']" ((@(Expand-PortSpec "common")).Count -eq $script:CommonPorts.Count) "count=$((@(Expand-PortSpec 'common')).Count)"
    $thrown = $false; try { [void](Expand-PortSpec "abc") } catch { $thrown = $true }
    $checks += & $add "expand['abc']-throws" $thrown "bad token must throw"

    # 3. Subnet math.
    $checks += & $add "subnet/30=2" ((@(Get-SubnetHosts "10.0.0.0/30")).Count -eq 2) ""
    $checks += & $add "subnet/24=254" ((@(Get-SubnetHosts "10.0.0.0/24")).Count -eq 254) ""
    $checks += & $add "in-subnet[10.0.0.5]" ((Test-IpInSubnet -Ip "10.0.0.5" -Cidr "10.0.0.0/24") -eq $true) ""
    $checks += & $add "in-subnet[10.0.1.5]" ((Test-IpInSubnet -Ip "10.0.1.5" -Cidr "10.0.0.0/24") -eq $false) ""
    $checks += & $add "in-subnet-v6[fe80::1]" ((Test-IpInSubnet -Ip "fe80::1" -Cidr "fe80::/10") -eq $true) ""
    $checks += & $add "in-subnet-v6[2001:db8::1]" ((Test-IpInSubnet -Ip "2001:db8::1" -Cidr "fe80::/10") -eq $false) ""

    # 4. Banner classification.
    $checks += & $add "banner[ssh]" ((Get-BannerServiceClass "SSH-2.0-OpenSSH_9.0") -eq "ssh") ""
    $checks += & $add "banner[pop3]" ((Get-BannerServiceClass "+OK Dovecot ready") -eq "pop3") ""
    $checks += & $add "banner[empty]" ((Get-BannerServiceClass "") -eq "") "empty stays empty"

    # 5. Risk table.
    $checks += & $add "risk[12345-trojan]" ((Get-PortRiskNote 12345) -like "*NetBus*") ""
    $checks += & $add "risk[99999-default]" ((Get-PortRiskNote 99999) -like "*review whether*") "unknown ports get a fallback note"
    $checks += & $add "risk-table-nonempty" ($script:PortRiskNotes.Count -ge 50) "count=$($script:PortRiskNotes.Count)"

    # 6. Target spec validation.
    $checks += & $add "spec[ip]" ((Test-TargetSpec "10.0.0.1").kind -eq "ip") ""
    $checks += & $add "spec[subnet]" ((Test-TargetSpec "subnet:10.0.0.0/24").kind -eq "subnet") ""
    $checks += & $add "spec[hostname]" ((Test-TargetSpec "example.com").kind -eq "hostname") ""
    $checks += & $add "spec[trailing-dot]" ((Test-TargetSpec "example.com.").kind -eq "hostname") "FQDN root form"
    $badThrown = $false; try { [void](Test-TargetSpec "not a host!") } catch { $badThrown = $true }
    $checks += & $add "spec[bad-throws]" $badThrown ""

    # 7. State normalization (v1 reports carry no state field).
    $checks += & $add "state[missing->open]" ((Get-ScanResultState ([pscustomobject]@{ port = 80 })) -eq "open") ""
    $checks += & $add "state[filtered]" ((Get-ScanResultState ([pscustomobject]@{ state = "filtered" })) -eq "filtered") ""

    # 8. v4: closure-plan only targets OPEN ports (the v3 plan blocked
    # already-closed rows); closure verdict mapper; drift coverage verdicts.
    $cpRows = @(
        [pscustomobject]@{ target = "10.0.0.1"; port = 80; protocol = "tcp"; state = "open"; service = "http" },
        [pscustomobject]@{ target = "10.0.0.1"; port = 81; protocol = "tcp"; state = "closed"; service = "unknown" },
        [pscustomobject]@{ target = "10.0.0.1"; port = 82; protocol = "tcp"; state = "filtered"; service = "unknown" },
        [pscustomobject]@{ target = "10.0.0.1"; port = 53; protocol = "udp"; state = "open|filtered"; service = "dns" }
    )
    $cp = New-PortClosurePlan -Results $cpRows -Keep @()
    $checks += & $add "plan[open-in]" ((@($cp | Where-Object { $_.port -eq 80 }).Count) -eq 1) ""
    $checks += & $add "plan[closed-out]" ((@($cp | Where-Object { $_.port -eq 81 }).Count) -eq 0) "closed must not get a block rule"
    $checks += & $add "plan[filtered-out]" ((@($cp | Where-Object { $_.port -eq 82 }).Count) -eq 0) "filtered must not get a block rule"
    $checks += & $add "plan[udp-ambiguous-in]" ((@($cp | Where-Object { $_.port -eq 53 }).Count) -eq 1) ""
    $udpRow = @($cp | Where-Object { $_.port -eq 53 })[0]
    $checks += & $add "plan[verify-cmd]" ($udpRow.verify -like "*Confirm-PortClosed*") ""
    $checks += & $add "plan[udp-note]" ($udpRow.note -ne "") "inconclusive UDP gets the confirm note"
    $cpKeep = New-PortClosurePlan -Results $cpRows -Keep @("10.0.0.1:80")
    $checks += & $add "plan[keep-targetport]" ((@($cpKeep | Where-Object { $_.port -eq 80 }).Count) -eq 0) "-Keep target:port still works"

    $checks += & $add "verdict[tcp-closed]" ((ConvertTo-ClosureVerdict -State "closed" -Protocol "tcp") -eq "PASS") ""
    $checks += & $add "verdict[tcp-filtered]" ((ConvertTo-ClosureVerdict -State "filtered" -Protocol "tcp") -eq "PASS") ""
    $checks += & $add "verdict[tcp-open]" ((ConvertTo-ClosureVerdict -State "open" -Protocol "tcp") -eq "FAIL") ""
    $checks += & $add "verdict[tcp-bogus]" ((ConvertTo-ClosureVerdict -State "bogus" -Protocol "tcp") -eq "INCONCLUSIVE") ""
    $checks += & $add "verdict[udp-silent]" ((ConvertTo-ClosureVerdict -State "open|filtered" -Protocol "udp") -eq "PASS") ""
    $checks += & $add "verdict[udp-open]" ((ConvertTo-ClosureVerdict -State "open" -Protocol "udp") -eq "FAIL") ""
    $checks += & $add "verdict[udp-error]" ((ConvertTo-ClosureVerdict -State "error" -Protocol "udp") -eq "INCONCLUSIVE") ""

    $checks += & $add "drift[opened-new]" ((Test-DriftKeyVerdict -Key "10.0.0.5/tcp/443" -Direction "opened" -OldCoverage @(80,443)) -eq "new") ""
    $checks += & $add "drift[opened-newscope]" ((Test-DriftKeyVerdict -Key "10.0.0.5/tcp/443" -Direction "opened" -OldCoverage @(80)) -eq "newscope") ""
    $checks += & $add "drift[opened-unknown]" ((Test-DriftKeyVerdict -Key "10.0.0.5/tcp/443" -Direction "opened") -eq "new") "v1/v2/v3 fallback"
    $checks += & $add "drift[opened-ipv6]" ((Test-DriftKeyVerdict -Key "fe80::1/tcp/80" -Direction "opened" -OldCoverage @(80)) -eq "new") "IPv6 key parse"
    $checks += & $add "drift[closed-closed]" ((Test-DriftKeyVerdict -Key "10.0.0.5/tcp/443" -Direction "closed" -NewCoverage @(80,443) -NewTargets @("10.0.0.5")) -eq "closed") ""
    $checks += & $add "drift[closed-unscanned]" ((Test-DriftKeyVerdict -Key "10.0.0.5/tcp/443" -Direction "closed" -NewCoverage @(80,443) -NewTargets @("10.0.0.9")) -eq "unscanned") ""
    $checks += & $add "drift[closed-newscope]" ((Test-DriftKeyVerdict -Key "10.0.0.5/tcp/443" -Direction "closed" -NewCoverage @(80) -NewTargets @("10.0.0.5")) -eq "newscope") ""
    $checks += & $add "drift[closed-unknown]" ((Test-DriftKeyVerdict -Key "10.0.0.5/tcp/443" -Direction "closed") -eq "closed") "v1/v2/v3 fallback"

    $checks += & $add "tlsports-no-dups" ((@($script:TlsPorts | Sort-Object -Unique).Count) -eq $script:TlsPorts.Count) ""
    $checks += & $add "risk53-single" ((Get-PortRiskNote 53) -eq "DNS — verify NOT an open recursive resolver") "duplicate 53 key removed"
    $ssdpPkt = New-UdpProbePacket -Service "ssdp"
    $ssdpTxt = [Text.Encoding]::ASCII.GetString($ssdpPkt)
    $checks += & $add "ssdp[pkt]" ($ssdpTxt -like "M-SEARCH * HTTP/1.1*") "got: $($ssdpTxt.Substring(0, [math]::Min(24, $ssdpTxt.Length)))"
    $ssdpResp = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nST: upnp:rootdevice`r`n`r`n")
    $checks += & $add "ssdp[detail]" ((Get-UdpResponseDetail -Service "ssdp" -Response $ssdpResp) -like "*SSDP*") ""

    $failed = @($checks | Where-Object { -not $_.Passed })
    Write-Host ("[netscan hygiene] {0}/{1} checks passed" -f ($checks.Count - $failed.Count), $checks.Count)
    foreach ($f in $failed) {
        Write-Host ("  [FAIL] {0} -- {1}" -f $f.Name, $f.Detail)
    }
    if ($failed.Count -gt 0) { throw "$($failed.Count) hygiene checks failed" }
    return $true
}

# Dot-sourcing note: all functions load directly into the caller session.
