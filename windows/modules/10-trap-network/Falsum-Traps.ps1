<#
.SYNOPSIS
    Falsum Trap Network — decoy TCP listeners (honeypots) for the user's
    own machine (poison pill for the "threat detection" subscription tier:
    every EDR charges per endpoint per year to notice someone knocking;
    this is a knock-logger that costs nothing and ships its own fix).

.DESCRIPTION
    Runs fake-service TCP listeners on configurable ports with believable
    text-protocol banners (SSH, Telnet, HTTP, FTP, SMTP, POP3, IMAP, Redis,
    Memcached, SIP, VNC). Every inbound connection is logged: UTC timestamp,
    remote IP/port, bytes in/out, per-connection duration in milliseconds,
    SHA-256 of the raw payload, and an ASCII-sanitized payload preview.
    Per-IP flood protection: max 25 logged events per IP per 60 seconds;
    plus a per-port GLOBAL cap (default 200 events per 60 seconds across all
    IPs) so a distributed spray can't fill the disk either. Excess hits are
    counted in the session's Dropped (per-IP) and PortDropped (global)
    counters instead of being written to disk.
    Events land in per-port JSONL files immediately (survives a shell close)
    and are hash-chained into the evidence vault (type "trap-event") on the
    main thread via Sync-TrapVault.

    THE BETTER-WAY LAW: a detection ships its fix. The fix here is
    New-TrapBlock: a local Windows Defender Firewall inbound block rule for
    the offending IP — on the user's OWN machine only — plus Start-TrapListener
    -AutoBlock to block each new attacker IP the moment the trap fires.
    AutoBlock never fires on loopback (127.0.0.0/8, ::1) — your own scans
    won't lock you out — and -AutoBlockAfter N waits for N hits within 60
    seconds before the rule lands, so one accidental knock doesn't earn a
    firewall entry. Sync-TrapBlocksToBadActors carries every blocked IP into
    the active-defense permanent blocklist (the mark that follows them).

    NEVER OUTBOUND, EVER. This module creates listeners only. It never
    initiates a connection, never scans, never probes. Purely defensive.

    PowerShell 5.1 compatible. Zero external dependencies. Each trap runs in
    its own runspace with a non-blocking accept loop; the vault ledger is
    written from the main thread only (the vault's read-tip+append is not
    safe for concurrent writers). One connection is handled at a time per
    port: a peer that connects and dribbles data ties up that listener for
    the rest of its interaction (read budgets bound it at seconds, not
    minutes), so a slowloris-style hold is the honest residual weakness of
    this design — the event is still logged, the hold is still evidence.

    HONEST LIMITS: text-protocol decoys only (SSH, Telnet, HTTP, FTP,
    SMTP, POP3, IMAP, Redis, Memcached, SIP, VNC, Docker-API, Elasticsearch)
    plus four canned binary handshakes — MQTT CONNACK, MySQL greeting +
    login-refusal, TCP-DNS REFUSED (fixed byte replies, query ID echoed
    where the protocol demands it), and PostgreSQL startup + MD5-auth-refusal
    (SSLRequest answered 'N', canned 28P01 invalid_password error — no
    database runs here). RDP, real TLS, and SMB are not faked. A banner can
    lie about a service; it cannot hold a real protocol conversation. Bind
    addresses are the user's own interfaces (127.0.0.1 default, 0.0.0.0 for
    the LAN). Binding real
    service ports (22, 23, 80) collides with real services — the module
    tests the port first and refuses cleanly when it is taken.

.USAGE
    . .\Falsum-Traps.ps1
    Get-TrapProfiles                                  # see decoy profiles (17 protocols)
    Get-TrapAttackPatterns                          # what kind of attacker is knocking
    Start-TrapListener -ProfileName telnet -VaultPath "C:\Falsum\vault"
    Start-TrapListener -ProfileName redis -BindAddress 0.0.0.0 -AutoBlock
    Start-TrapListener -ProfileName vnc -AutoBlock -AutoBlockAfter 5  # block after 5 hits/60s
    Get-TrapStatus                                    # incl. Dropped / PortDropped columns
    Get-TrapEvents -Since (Get-Date).AddHours(-1)
    Get-TrapOffenderSummary                           # ranked offender table
    Get-TrapJsonlEvents -Port 2323                    # review raw logs after restart
    Export-TrapReport -Path "C:\Falsum\traps\report.json"   # JSON + txt + CSV, hashed
    New-TrapBlock -IpAddress 203.0.113.7 -Reason "trap hit on telnet decoy"
    Block-TrapTopOffenders -MinHits 10                # block every repeat offender
    Sync-TrapBlocksToBadActors                        # carry blocks into the permanent bad-actor list
    Clear-OldTrapLogs -RetentionDays 30               # prune stale JSONL logs
    Test-TrapHygiene                                  # built-in self-test
    Stop-TrapListener -All
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
$script:TrapSessions  = @{}   # port -> @{ PowerShell, Runspace, Shared, Profile, BindAddress, LogDir, StartUtc }
$script:TrapCache     = New-Object System.Collections.ArrayList   # vault-logged events (main thread)
$script:VaultLoaded   = $false
$script:VaultPath     = ""
$script:BlockedIps    = @{}   # ip -> @{ utc; reason; rule }
$script:RulesImported = $false  # firewall rule import happens once per session
$script:DefaultLogDir = ""

function Import-VaultModule {
    if ($script:VaultLoaded) { return }
    $here = Split-Path -Parent $MyInvocation.PSCommandPath
    $mod = Join-Path (Split-Path -Parent $here) "12-timeline-vault\Falsum-Vault.ps1"
    if (-not (Test-Path $mod)) {
        $mod = Join-Path $here "..\12-timeline-vault\Falsum-Vault.ps1"
    }
    if (Test-Path $mod) { . $mod; $script:VaultLoaded = $true }
    else { Write-Host "[!] vault module not found at $mod — events go to JSONL only" }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-TrapLogDir {
    if ($script:DefaultLogDir -ne "") { return $script:DefaultLogDir }
    $d = Join-Path ([Environment]::GetFolderPath("UserProfile")) "Falsum\traps"
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    $script:DefaultLogDir = $d
    return $d
}

# ---------------------------------------------------------------------------
# Decoy profiles — text protocols only. Each profile: fake banner served on
# connect, a short interaction mode, and the closing line. The mode drives a
# tiny generic state machine inside the listener runspace (no code is
# generated from strings — the scriptblock is fixed and profile-agnostic).
# ---------------------------------------------------------------------------
function Get-TrapProfiles {
    [CmdletBinding()]
    param()
    return @(
        [pscustomobject]@{ Name='ssh';    Ports=@(2222); Mode='banner';
            Banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`r`n";
            Reply="Protocol mismatch.`r`n";
            Note='Fake SSH banner; real SSH clients disconnect on their own.' },
        [pscustomobject]@{ Name='telnet'; Ports=@(2323); Mode='telnet';
            Banner="`r`nrouter-os 5.4 LTS`r`nlogin: ";
            Reply="Login incorrect`r`n";
            Note='Two-stage: login prompt, then password prompt, then refuse.' },
        [pscustomobject]@{ Name='http';   Ports=@(8080); Mode='http';
            Banner="";
            Reply="HTTP/1.1 401 Unauthorized`r`nServer: httpd/2.4`r`nContent-Length: 13`r`nConnection: close`r`n`r`nUnauthorized.`r`n";
            Note='Reads the request headers, answers 401, closes.' },
        [pscustomobject]@{ Name='ftp';    Ports=@(2121); Mode='banner';
            Banner="220 ProFTPD 1.3.8 Server ready.`r`n";
            Reply="530 Login incorrect.`r`n";
            Note='One command read, one refusal, close.' },
        [pscustomobject]@{ Name='smtp';   Ports=@(2525); Mode='banner';
            Banner="220 mail.local ESMTP Postfix`r`n";
            Reply="550 5.7.1 Access denied.`r`n";
            Note='One command read, one refusal, close.' },
        [pscustomobject]@{ Name='pop3';   Ports=@(2110); Mode='banner';
            Banner="+OK fake-pop3 service ready.`r`n";
            Reply="-ERR unauthorized.`r`n";
            Note='One command read, one refusal, close.' },
        [pscustomobject]@{ Name='imap';   Ports=@(2143); Mode='banner';
            Banner="* OK fake-imap service ready.`r`n";
            Reply="a001 NO unauthorized.`r`n";
            Note='One command read, one refusal, close.' },
        [pscustomobject]@{ Name='redis';  Ports=@(6379); Mode='banner';
            Banner="";
            Reply="+PONG`r`n";
            Note='No greeting sent; answers PONG to the first command.' },
        [pscustomobject]@{ Name='memcached'; Ports=@(11211); Mode='banner';
            Banner="";
            Reply="ERROR`r`n";
            Note='No greeting sent; answers ERROR to the first command.' },
        [pscustomobject]@{ Name='sip';    Ports=@(5060); Mode='banner';
            Banner="";
            Reply="SIP/2.0 403 Forbidden`r`nContent-Length: 0`r`n`r`n";
            Note='Answers 403 to the first SIP message.' }
        [pscustomobject]@{ Name='vnc';    Ports=@(5900); Mode='vnc';
            Banner="RFB 003.008`n";
            Reply="RFB 0000`n";
            Note='VNC version exchange + security-type pick (None), then security-result OK. ASCII handshake only — full RFB auth is not faked.' },
        [pscustomobject]@{ Name='mqtt';   Ports=@(1883); Mode='mqtt';
            Banner="";
            Reply="";
            Note='Canned MQTT handshake: reads the CONNECT packet, answers CONNACK accepted (0x20 0x02 0x00 0x00). No broker runs here.' },
        [pscustomobject]@{ Name='mysql';  Ports=@(3306); Mode='mysql';
            Banner="";
            Reply="";
            Note='Canned MySQL 8.0 greeting packet (protocol 0x0a), then a canned 1045 Access-denied error. No database runs here.' },
        [pscustomobject]@{ Name='docker-api'; Ports=@(2375); Mode='http';
            Banner="";
            Reply="HTTP/1.1 404 Not Found`r`nServer: Docker/24.0.7 (windows)`r`nContent-Length: 23`r`nConnection: close`r`n`r`n404 page not found.`r`n";
            Note='Docker Remote API facade: any request gets a Docker-flavored 404. Useful — exposed Docker daemons are ransomware targets.' },
        [pscustomobject]@{ Name='dns-tcp'; Ports=@(5353); Mode='dnsrefuse';
            Banner="";
            Reply="";
            Note='Canned TCP-DNS REFUSED for every query (ID echoed, RCODE=5). No resolver runs here; port 5353 avoids the real 53.' },
        [pscustomobject]@{ Name='postgres'; Ports=@(5432); Mode='postgres';
            Banner="";
            Reply="";
            Note='Canned PostgreSQL startup handshake: SSLRequest answered N (no SSL), AuthenticationMD5Password request, then canned 28P01 invalid_password error. No database runs here.' },
        [pscustomobject]@{ Name='elastic'; Ports=@(9200); Mode='http';
            Banner="";
            Reply="HTTP/1.1 401 Unauthorized`r`nContent-Type: application/json; charset=UTF-8`r`nContent-Length: 231`r`nConnection: close`r`n`r`n{`"error`":{`"root_cause`":[{`"type`":`"security_exception`",`"reason`":`"missing authentication credentials for REST request [/]`"}],`"type`":`"security_exception`",`"reason`":`"missing authentication credentials for REST request [/]`"},`"status`":401}";
            Note='Elasticsearch-flavored 401 facade: any request gets a security_exception JSON body. Exposed ES clusters are ransomware targets.' }
    )
}

function Test-TrapPort {
    <#
    Tries to bind the port on the requested address; returns $true when free.
    Clean failure message when the port is taken by a real service.
    #>
    param(
        [Parameter(Mandatory=$true)][int]$Port,
        [string]$BindAddress = "127.0.0.1"
    )
    try {
        $ip = [System.Net.IPAddress]::Parse($BindAddress)
        $t = New-Object System.Net.Sockets.TcpListener($ip, $Port)
        $t.Start()
        $t.Stop()
        return $true
    } catch {
        Write-Host "[!] port $Port on $BindAddress is not available: $($_.Exception.Message)"
        return $false
    }
}

# ---------------------------------------------------------------------------
# Fixed listener scriptblock. Receives ONE argument: a synchronized hashtable
# $S with Port, BindAddress, ProfileName, Mode, Banner, Reply, LogFile.
# It owns: listener lifecycle, per-client interaction, JSONL logging, the
# in-memory event queue. It NEVER touches the network beyond accepting and
# answering its own inbound peers, and NEVER writes to the vault (main
# thread owns the vault — see Sync-TrapVault).
# ---------------------------------------------------------------------------
$script:ListenerCode = {
    param($S)

    function Sanitize-Preview([byte[]]$Bytes, [int]$Max = 256) {
        $sb = New-Object System.Text.StringBuilder
        $n = $Bytes.Length
        if ($n -gt $Max) { $n = $Max }
        for ($i = 0; $i -lt $n; $i++) {
            $b = $Bytes[$i]
            if ($b -ge 32 -and $b -le 126) { [void]$sb.Append([char]$b) }
            elseif ($b -eq 10 -or $b -eq 13) { [void]$sb.Append(' ') }
            else { [void]$sb.Append('.') }
        }
        return $sb.ToString()
    }

    function Sha256-Hex([byte[]]$Bytes) {
        $h = New-Object System.Security.Cryptography.SHA256Managed
        try {
            $d = $h.ComputeHash($Bytes)
            return ([System.BitConverter]::ToString($d)).Replace('-', '').ToLower()
        } finally { $h.Dispose() }
    }

    function Read-Peer($Stream, [int]$BudgetMs = 8000, [int]$MaxBytes = 8192, [string]$Until = "") {
        $Stream.ReadTimeout = 2500
        $all = New-Object System.Collections.Generic.List[byte]
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            while ($sw.ElapsedMilliseconds -lt $BudgetMs -and $all.Count -lt $MaxBytes) {
                $buf = New-Object byte[] 4096
                try { $n = $Stream.Read($buf, 0, $buf.Length) }
                catch [System.IO.IOException] { break }  # read timeout: peer went quiet
                if ($n -le 0) { break }
                for ($i = 0; $i -lt $n; $i++) { [void]$all.Add($buf[$i]) }
                if ($Until -ne "" -and $all.Count -ge $Until.Length) {
                    $txt = [System.Text.Encoding]::ASCII.GetString($all.ToArray())
                    if ($txt.Contains($Until)) { break }
                }
                if (-not $Stream.DataAvailable) { Start-Sleep -Milliseconds 150 }
                if (-not $Stream.DataAvailable) { break }
            }
        } finally { $sw.Stop() }
        return $all.ToArray()
    }

    function Emit-Event($PeerEp, [byte[]]$InBytes, [int]$OutBytes, [int]$DurationMs) {
        # Per-IP rate limit: a flooding peer gets at most 25 logged events
        # per 60 seconds. A GLOBAL per-port cap ($S.PortMaxEventsPerMinute
        # per 60 seconds, across all IPs) stops a distributed spray from
        # filling the disk. Anything beyond either cap is counted in
        # $S.Dropped (per-IP) or $S.PortDropped (global) and skipped.
        $ip = $PeerEp.Address.ToString()
        $now = [datetime]::UtcNow
        $allowIp = $true
        [System.Threading.Monitor]::Enter($S.IpHits.SyncRoot)
        try {
            $hits = $S.IpHits[$ip]
            if ($null -eq $hits) {
                $hits = New-Object System.Collections.Generic.List[datetime]
                $S.IpHits[$ip] = $hits
            }
            while ($hits.Count -gt 0 -and ($now - $hits[0]).TotalSeconds -gt 60) { $hits.RemoveAt(0) }
            if ($hits.Count -ge 25) { $allowIp = $false }
            else { [void]$hits.Add($now) }
        } finally { [System.Threading.Monitor]::Exit($S.IpHits.SyncRoot) }
        if (-not $allowIp) {
            [System.Threading.Monitor]::Enter($S.IpHits.SyncRoot)
            try { $S.Dropped = [int]$S.Dropped + 1 }
            finally { [System.Threading.Monitor]::Exit($S.IpHits.SyncRoot) }
            return
        }
        $allowPort = $true
        [System.Threading.Monitor]::Enter($S.PortHits.SyncRoot)
        try {
            $ph = $S.PortHits
            while ($ph.Count -gt 0 -and ($now - $ph[0]).TotalSeconds -gt 60) { $ph.RemoveAt(0) }
            if ($ph.Count -ge [int]$S.PortMaxEventsPerMinute) { $allowPort = $false }
            else { [void]$ph.Add($now) }
        } finally { [System.Threading.Monitor]::Exit($S.PortHits.SyncRoot) }
        if (-not $allowPort) {
            [System.Threading.Monitor]::Enter($S.PortHits.SyncRoot)
            try { $S.PortDropped = [int]$S.PortDropped + 1 }
            finally { [System.Threading.Monitor]::Exit($S.PortHits.SyncRoot) }
            return
        }
        $ev = [ordered]@{
            utc            = $now.ToString("o")
            profile        = $S.ProfileName
            local_port     = $S.Port
            bind           = $S.BindAddress
            remote_ip      = $ip
            remote_port    = $PeerEp.Port
            bytes_in       = $InBytes.Length
            bytes_out      = $OutBytes
            duration_ms    = $DurationMs
            payload_sha256 = (Sha256-Hex $InBytes)
            payload_preview= (Sanitize-Preview $InBytes 256)
        }
        $line = ($ev | ConvertTo-Json -Depth 4 -Compress)
        [System.Threading.Monitor]::Enter($S.FileLock)
        try { [System.IO.File]::AppendAllText($S.LogFile, $line + "`r`n") }
        finally { [System.Threading.Monitor]::Exit($S.FileLock) }
        [System.Threading.Monitor]::Enter($S.Events.SyncRoot)
        try { [void]$S.Events.Add($ev) }
        finally { [System.Threading.Monitor]::Exit($S.Events.SyncRoot) }
    }

    function Send-Text($Stream, [string]$Text) {
        if ([string]::IsNullOrEmpty($Text)) { return 0 }
        $b = [System.Text.Encoding]::ASCII.GetBytes($Text)
        $Stream.Write($b, 0, $b.Length)
        $Stream.Flush()
        return $b.Length
    }

    function Send-Binary($Stream, [byte[]]$Bytes) {
        $Stream.Write($Bytes, 0, $Bytes.Length)
        $Stream.Flush()
        return $Bytes.Length
    }

    try {
        $ip = [System.Net.IPAddress]::Parse($S.BindAddress)
        $listener = New-Object System.Net.Sockets.TcpListener($ip, $S.Port)
        $listener.Start()
        $S.Listener = $listener
        $S.Running = $true

        while (-not $S.Stop) {
            try {
                if ($listener.Pending()) {
                    $client = $listener.AcceptTcpClient()
                    try {
                        $peer = $client.Client.RemoteEndPoint
                        $stream = $client.GetStream()
                        $inAll  = New-Object System.Collections.Generic.List[byte]
                        $outTot = 0
                        $connSw = [System.Diagnostics.Stopwatch]::StartNew()

                        switch ($S.Mode) {
                            'vnc' {
                                # RFB ASCII handshake only: server version, client
                                # version read, security-type offer (1=None),
                                # client's 1-byte pick, security result, close.
                                $outTot += Send-Text $stream $S.Banner
                                $r1 = Read-Peer $stream -BudgetMs 5000 -MaxBytes 12
                                for ($i = 0; $i -lt $r1.Length; $i++) { [void]$inAll.Add($r1[$i]) }
                                $secTypes = [byte[]]@(0x01, 0x02)
                                $stream.Write($secTypes, 0, $secTypes.Length)
                                $stream.Flush()
                                $outTot += $secTypes.Length
                                $r2 = Read-Peer $stream -BudgetMs 5000 -MaxBytes 1
                                for ($i = 0; $i -lt $r2.Length; $i++) { [void]$inAll.Add($r2[$i]) }
                                if ($r2.Length -ge 1 -and $r2[0] -eq 1) { $outTot += Send-Text $stream $S.Reply }
                                else { $outTot += Send-Text $stream "RFB 0001`n" }
                            }
                            'telnet' {
                                $outTot += Send-Text $stream $S.Banner
                                $r1 = Read-Peer $stream
                                for ($i = 0; $i -lt $r1.Length; $i++) { [void]$inAll.Add($r1[$i]) }
                                $outTot += Send-Text $stream "Password: "
                                $r2 = Read-Peer $stream
                                for ($i = 0; $i -lt $r2.Length; $i++) { [void]$inAll.Add($r2[$i]) }
                                $outTot += Send-Text $stream $S.Reply
                            }
                            'http' {
                                $r = Read-Peer $stream -Until "`r`n`r`n"
                                for ($i = 0; $i -lt $r.Length; $i++) { [void]$inAll.Add($r[$i]) }
                                $outTot += Send-Text $stream $S.Reply
                            }
                            'mqtt' {
                                # Canned MQTT handshake: read the CONNECT packet,
                                # answer CONNACK accepted (0x20 0x02 0x00 0x00).
                                # No broker runs here; the peer's PINGREQ is logged, not answered.
                                $r = Read-Peer $stream -BudgetMs 5000 -MaxBytes 256
                                for ($i = 0; $i -lt $r.Length; $i++) { [void]$inAll.Add($r[$i]) }
                                $outTot += Send-Binary $stream ([byte[]]@(0x20, 0x02, 0x00, 0x00))
                                $r2 = Read-Peer $stream -BudgetMs 2000 -MaxBytes 64
                                for ($i = 0; $i -lt $r2.Length; $i++) { [void]$inAll.Add($r2[$i]) }
                            }
                            'mysql' {
                                # Canned MySQL 8.0 server greeting (protocol 0x0a),
                                # then a canned 1045 Access-denied error packet.
                                # Fixed byte arrays — no real database runs here.
                                $gp = New-Object System.Collections.Generic.List[byte]
                                [void]$gp.Add(0x0A)
                                foreach ($ch in [System.Text.Encoding]::ASCII.GetBytes("8.0.42-Falsum")) { [void]$gp.Add($ch) }
                                [void]$gp.Add(0x00)
                                $cid = [System.BitConverter]::GetBytes([uint32]4242)
                                for ($i = 0; $i -lt 4; $i++) { [void]$gp.Add($cid[$i]) }
                                foreach ($ch in [System.Text.Encoding]::ASCII.GetBytes("s4lT_p4r")) { [void]$gp.Add($ch) }
                                [void]$gp.Add(0x00)                       # filler
                                [void]$gp.Add(0xFF); [void]$gp.Add(0xFF)   # capability flags, lower
                                [void]$gp.Add(0x21)                       # charset utf8mb4
                                [void]$gp.Add(0x02); [void]$gp.Add(0x00)   # status flags
                                [void]$gp.Add(0xFF); [void]$gp.Add(0xC7)   # capability flags, upper
                                [void]$gp.Add(0x15)                       # auth plugin data length
                                for ($i = 0; $i -lt 10; $i++) { [void]$gp.Add(0x00) }
                                foreach ($ch in [System.Text.Encoding]::ASCII.GetBytes("m0r3_s4lT!!!")) { [void]$gp.Add($ch) }
                                [void]$gp.Add(0x00)
                                foreach ($ch in [System.Text.Encoding]::ASCII.GetBytes("mysql_native_password")) { [void]$gp.Add($ch) }
                                [void]$gp.Add(0x00)
                                $pa = $gp.ToArray()
                                $gl = $pa.Length
                                $hdr = [byte[]]@([byte]($gl -band 0xFF), [byte](($gl -shr 8) -band 0xFF), [byte](($gl -shr 16) -band 0xFF), 0x00)
                                $outTot += Send-Binary $stream $hdr
                                $outTot += Send-Binary $stream $pa
                                $r = Read-Peer $stream -BudgetMs 5000 -MaxBytes 4096
                                for ($i = 0; $i -lt $r.Length; $i++) { [void]$inAll.Add($r[$i]) }
                                $ep = New-Object System.Collections.Generic.List[byte]
                                [void]$ep.Add(0xFF)
                                [void]$ep.Add(0x15); [void]$ep.Add(0x04)   # errno 1045 (0x0415, LE)
                                foreach ($ch in [System.Text.Encoding]::ASCII.GetBytes("#28000Access denied for user")) { [void]$ep.Add($ch) }
                                $ea = $ep.ToArray()
                                $eh = [byte[]]@([byte]($ea.Length -band 0xFF), 0x00, 0x00, 0x02)
                                $outTot += Send-Binary $stream $eh
                                $outTot += Send-Binary $stream $ea
                            }
                            'dnsrefuse' {
                                # Canned TCP-DNS REFUSED (RCODE=5) for every query:
                                # query ID echoed, the question section copied back.
                                $req = Read-Peer $stream -BudgetMs 5000 -MaxBytes 512
                                for ($i = 0; $i -lt $req.Length; $i++) { [void]$inAll.Add($req[$i]) }
                                if ($req.Length -ge 2) {
                                    $rb = New-Object System.Collections.Generic.List[byte]
                                    [void]$rb.Add(0x00); [void]$rb.Add(0x00)   # length placeholder
                                    if ($req.Length -gt 2) { [void]$rb.Add($req[2]) } else { [void]$rb.Add(0x00) }
                                    if ($req.Length -gt 3) { [void]$rb.Add($req[3]) } else { [void]$rb.Add(0x00) }
                                    [void]$rb.Add(0x81); [void]$rb.Add(0x85)   # QR=1, RD copied, RCODE=5 REFUSED
                                    [void]$rb.Add(0x00); [void]$rb.Add(0x01)   # QDCOUNT=1
                                    [void]$rb.Add(0x00); [void]$rb.Add(0x00)   # ANCOUNT=0
                                    [void]$rb.Add(0x00); [void]$rb.Add(0x00)   # NSCOUNT=0
                                    [void]$rb.Add(0x00); [void]$rb.Add(0x00)   # ARCOUNT=0
                                    for ($i = 4; $i -lt $req.Length; $i++) { [void]$rb.Add($req[$i]) }
                                    $ra = $rb.ToArray()
                                    $blen = $ra.Length - 2
                                    $ra[0] = [byte](($blen -shr 8) -band 0xFF)
                                    $ra[1] = [byte]($blen -band 0xFF)
                                    $outTot += Send-Binary $stream $ra
                                }
                            }
                            'postgres' {
                                # Canned PostgreSQL wire handshake (binary, fixed
                                # bytes — no database runs here):
                                #  1. read first message; 8-byte SSLRequest (code
                                #     80877103) is answered 'N' (SSL refused);
                                #     otherwise it was a StartupMessage, proceed.
                                #  2. send AuthenticationMD5Password ('R', len 12,
                                #     type 5, 4-byte salt).
                                #  3. read the password packet, answer ErrorResponse
                                #     28P01 invalid_password, close (a real server
                                #     closes the connection after failed auth).
                                $r1 = Read-Peer $stream -BudgetMs 5000 -MaxBytes 256
                                for ($i = 0; $i -lt $r1.Length; $i++) { [void]$inAll.Add($r1[$i]) }
                                if ($r1.Length -ge 8) {
                                    $code = (([int]$r1[4] -shl 24) -bor ([int]$r1[5] -shl 16) -bor ([int]$r1[6] -shl 8) -bor [int]$r1[7])
                                    if ($code -eq 80877103) {
                                        $outTot += Send-Binary $stream ([byte[]]@(0x4E))  # 'N'
                                        $r2 = Read-Peer $stream -BudgetMs 5000 -MaxBytes 1024
                                        for ($i = 0; $i -lt $r2.Length; $i++) { [void]$inAll.Add($r2[$i]) }
                                    }
                                }
                                $auth = New-Object System.Collections.Generic.List[byte]
                                [void]$auth.Add(0x52)   # 'R'
                                [void]$auth.Add(0x00); [void]$auth.Add(0x00); [void]$auth.Add(0x00); [void]$auth.Add(0x0C)
                                [void]$auth.Add(0x00); [void]$auth.Add(0x00); [void]$auth.Add(0x00); [void]$auth.Add(0x05)
                                [void]$auth.Add(0x11); [void]$auth.Add(0x22); [void]$auth.Add(0x33); [void]$auth.Add(0x44)
                                $outTot += Send-Binary $stream $auth.ToArray()
                                $r3 = Read-Peer $stream -BudgetMs 5000 -MaxBytes 1024
                                for ($i = 0; $i -lt $r3.Length; $i++) { [void]$inAll.Add($r3[$i]) }
                                $ebody = New-Object System.Collections.Generic.List[byte]
                                $flds = @(@(0x53,"FATAL"), @(0x56,"FATAL"), @(0x43,"28P01"), @(0x4D,'password authentication failed for user "postgres"'))
                                foreach ($f in $flds) {
                                    [void]$ebody.Add([byte]$f[0])
                                    foreach ($ch in [System.Text.Encoding]::ASCII.GetBytes([string]$f[1])) { [void]$ebody.Add($ch) }
                                    [void]$ebody.Add(0x00)
                                }
                                [void]$ebody.Add(0x00)
                                $eba = $ebody.ToArray()
                                $elen = $eba.Length + 4
                                $err = New-Object System.Collections.Generic.List[byte]
                                [void]$err.Add(0x45)    # 'E'
                                [void]$err.Add([byte](($elen -shr 24) -band 0xFF))
                                [void]$err.Add([byte](($elen -shr 16) -band 0xFF))
                                [void]$err.Add([byte](($elen -shr 8) -band 0xFF))
                                [void]$err.Add([byte]($elen -band 0xFF))
                                foreach ($b in $eba) { [void]$err.Add($b) }
                                $outTot += Send-Binary $stream $err.ToArray()
                            }
                            default {  # 'banner'
                                $outTot += Send-Text $stream $S.Banner
                                $r = Read-Peer $stream
                                for ($i = 0; $i -lt $r.Length; $i++) { [void]$inAll.Add($r[$i]) }
                                $outTot += Send-Text $stream $S.Reply
                            }
                        }
                        $connSw.Stop()
                        Emit-Event $peer $inAll.ToArray() $outTot ([int]$connSw.ElapsedMilliseconds)
                    } catch {
                        # A single hostile or broken peer must never kill the trap.
                    } finally {
                        try { $client.Close() } catch {}
                    }
                } else {
                    Start-Sleep -Milliseconds 250
                }
            } catch [System.Net.Sockets.SocketException] {
                if ($S.Stop) { break }
                Start-Sleep -Milliseconds 500
            }
        }
    } catch {
        $S.Error = $_.Exception.Message
    } finally {
        $S.Running = $false
        try { if ($null -ne $S.Listener) { $S.Listener.Stop() } } catch {}
    }
}

function Start-TrapListener {
    <#
    Starts decoy listener(s) for a profile. Binds ONLY the user's own
    interfaces (default 127.0.0.1; 0.0.0.0 covers the LAN). Never outbound.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$ProfileName,
        [int[]]$Ports = @(),
        [string]$BindAddress = "127.0.0.1",
        [string]$LogDir = "",
        [string]$VaultPath = "",
        [switch]$AutoBlock,
        [int]$AutoBlockAfter = 1,
        [int]$PortMaxEventsPerMinute = 200
    )
    try {
        Write-Host "[*] starting trap listeners (profile: $ProfileName, bind: $BindAddress)"
        $prof = Get-TrapProfiles | Where-Object { $_.Name -eq $ProfileName }
        if ($null -eq $prof) {
            Write-Host "[!] unknown profile '$ProfileName'. Available: $((Get-TrapProfiles | ForEach-Object { $_.Name }) -join ', ')"
            return
        }
        if ($Ports.Count -eq 0) { $Ports = $prof.Ports }
        $bad = @($Ports | Where-Object { $_ -lt 1 -or $_ -gt 65535 })
        foreach ($b in $bad) { Write-Host "[!] port $b out of range (1-65535) — skipping" }
        $Ports = @($Ports | Where-Object { $_ -ge 1 -and $_ -le 65535 })
        if ($Ports.Count -eq 0) { Write-Host "[!] no valid ports left — aborting"; return }
        if ($AutoBlockAfter -lt 1) { $AutoBlockAfter = 1; Write-Host "[*] -AutoBlockAfter raised to 1" }
        if ($PortMaxEventsPerMinute -lt 10) { $PortMaxEventsPerMinute = 10; Write-Host "[*] -PortMaxEventsPerMinute raised to 10" }
        if ($LogDir -eq "") { $LogDir = Get-TrapLogDir }
        if ($VaultPath -ne "") { $script:VaultPath = $VaultPath }
        Import-VaultModule
        if (-not $script:RulesImported -and (Test-IsAdmin)) {
            [void](Import-TrapBlockRules)
            $script:RulesImported = $true
        }

        if ($BindAddress -eq "0.0.0.0" -and -not (Test-IsAdmin)) {
            Write-Host "[!] binding all interfaces without admin may miss inbound LAN traffic behind the firewall; continuing anyway"
        }
        foreach ($p in $Ports) {
            if ($p -lt 1024 -and -not (Test-IsAdmin)) {
                Write-Host "[!] port $p is below 1024 and this shell is not elevated — binding may fail"
            }
        }

        foreach ($p in $Ports) {
            if ($script:TrapSessions.ContainsKey($p)) {
                Write-Host "[!] port $p already has a trap running — skipping"
                continue
            }
            if (-not (Test-TrapPort -Port $p -BindAddress $BindAddress)) { continue }

            $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd")
            $logFile = Join-Path $LogDir ("trap-{0}-{1}.jsonl" -f $p, $stamp)
            $shared = [hashtable]::Synchronized(@{
                Stop        = $false
                Running     = $false
                Port        = $p
                BindAddress = $BindAddress
                ProfileName = $prof.Name
                Mode        = $prof.Mode
                Banner      = $prof.Banner
                Reply       = $prof.Reply
                LogFile     = $logFile
                Listener    = $null
                Error       = ""
                Events      = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
                FileLock    = (New-Object System.Object)
                IpHits      = [hashtable]::Synchronized(@{})
                Dropped     = 0
                PortHits    = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
                PortDropped = 0
                PortMaxEventsPerMinute = $PortMaxEventsPerMinute
                AutoBlockAfter = $AutoBlockAfter
            })
            $ps = [powershell]::Create()
            [void]$ps.AddScript($script:ListenerCode)
            [void]$ps.AddArgument($shared)
            $rs = $ps.BeginInvoke()

            $script:TrapSessions[$p] = @{
                PowerShell  = $ps
                Handle      = $rs
                Shared      = $shared
                Profile     = $prof.Name
                BindAddress = $BindAddress
                LogDir      = $LogDir
                LogFile     = $logFile
                StartUtc    = (Get-Date).ToUniversalTime().ToString("o")
                AutoBlock   = $AutoBlock.IsPresent
            }
            Write-Host ("[+] trap up: {0} on {1}:{2}  ->  {3}" -f $prof.Name, $BindAddress, $p, $logFile)
            if ($AutoBlock) { Write-Host "    [!] AutoBlock ON: new attacker IPs will get a local firewall block rule" }
        }
        Write-Host "[*] defensive only — this module never initiates outbound connections."
    } catch {
        Write-Host ("[!] Start-TrapListener failed: {0}" -f $_.Exception.Message)
    }
}

function Test-TrapIpIsLoopback {
    <#
    True for 127.0.0.0/8 and ::1. AutoBlock must never firewall your own
    loopback — a self-scan hitting your own traps would otherwise lock you
    out of your own listeners. Also covers IPv4-mapped IPv6 loopback
    (::ffff:127.0.0.1), which a dual-stack peer can present.
    #>
    param([Parameter(Mandatory=$true)][string]$Ip)
    $s = "$Ip".ToLower().Trim()
    if ($s -eq "::1" -or $s -eq "0:0:0:0:0:0:0:1") { return $true }
    if ($s.StartsWith("::ffff:")) { $s = $s.Substring(7) }
    return $s.StartsWith("127.")
}

function Sync-TrapVault {
    <#
    Drains each trap's in-memory event queue into the vault (type
    "trap-event") — main thread only, so the hash chain stays sequential.
    Applies AutoBlock to new remote IPs when enabled.
    #>
    [CmdletBinding()]
    param()
    try {
        if ($script:VaultPath -eq "" -or -not $script:VaultLoaded) {
            Write-Host "[!] no vault path set — events stay in JSONL; pass -VaultPath to Start-TrapListener"
            return
        }
        Import-VaultModule
        $vault = New-Vault -path $script:VaultPath
        $synced = 0
        foreach ($port in @($script:TrapSessions.Keys)) {
            $sess = $script:TrapSessions[$port]
            $S = $sess.Shared
            $batch = @()
            [System.Threading.Monitor]::Enter($S.Events.SyncRoot)
            try {
                $batch = @($S.Events.ToArray())
                $S.Events.Clear()
            } finally { [System.Threading.Monitor]::Exit($S.Events.SyncRoot) }
            foreach ($ev in $batch) {
                Add-VaultEntry -vault $vault -type "trap-event" -data $ev | Out-Null
                [void]$script:TrapCache.Add($ev)
                $synced++
                if ($sess.AutoBlock -and -not $script:BlockedIps.ContainsKey($ev.remote_ip)) {
                    if (Test-TrapIpIsLoopback $ev.remote_ip) {
                        Write-Host ("[*] AutoBlock skipped loopback {0} — your own scan won't lock you out" -f $ev.remote_ip)
                    } else {
                        # Block only after AutoBlockAfter hits inside the last
                        # 60 seconds (IpHits is pruned to that window).
                        $recent = 0
                        [System.Threading.Monitor]::Enter($S.IpHits.SyncRoot)
                        try {
                            $lst = $S.IpHits[$ev.remote_ip]
                            if ($null -ne $lst) { $recent = $lst.Count }
                        } finally { [System.Threading.Monitor]::Exit($S.IpHits.SyncRoot) }
                        if ($recent -ge [int]$S.AutoBlockAfter) {
                            New-TrapBlock -IpAddress $ev.remote_ip -Reason ("auto-block: {0} trap hit(s)/60s on {1}:{2}" -f $recent, $ev.profile, $ev.local_port)
                        }
                    }
                }
            }
        }
        Write-Host "[+] vault-synced $synced trap event(s)"
    } catch {
        Write-Host ("[!] Sync-TrapVault failed: {0}" -f $_.Exception.Message)
    }
}

function Get-TrapEvents {
    <#
    Returns vault-logged trap events (syncs the live queues first).
    #>
    param(
        [datetime]$Since = [datetime]::MinValue,
        [int]$Port = 0,
        [int]$Last = 0
    )
    try {
        Sync-TrapVault | Out-Null
        $evs = @($script:TrapCache)
        if ($Since -ne [datetime]::MinValue) { $evs = @($evs | Where-Object { [datetime]$_.utc -ge $Since }) }
        if ($Port -ne 0) { $evs = @($evs | Where-Object { [int]$_.local_port -eq $Port }) }
        if ($Last -gt 0 -and $evs.Count -gt $Last) { $evs = $evs[($evs.Count - $Last)..($evs.Count - 1)] }
        Write-Host ("[*] {0} trap event(s)" -f $evs.Count)
        return $evs
    } catch {
        Write-Host ("[!] Get-TrapEvents failed: {0}" -f $_.Exception.Message)
        return @()
    }
}

function Test-TrapLogFileSizeOk {
    <#
    Pure predicate: a trap JSONL log is safe to read in full when its byte
    size fits inside the megabyte cap. Keeps Get-TrapJsonlEvents from
    slurping a flood-grown file into memory after a burst the caps missed.
    #>
    param(
        [Parameter(Mandatory=$true)][long]$Bytes,
        [int]$MaxFileMb = 100
    )
    return $Bytes -le ([long]$MaxFileMb * 1MB)
}

function Get-TrapJsonlEvents {
    <#
    Reads the raw per-port JSONL files (they survive shell close and reboot)
    and returns parsed events. Use after a restart to review what fired while
    no vault sync ran. Files over -MaxFileMb are skipped, never slurped.
    #>
    param(
        [string]$LogDir = "",
        [int]$Port = 0,
        [int]$MaxFileMb = 100
    )
    try {
        if ($LogDir -eq "") { $LogDir = Get-TrapLogDir }
        $files = @(Get-ChildItem -Path $LogDir -Filter "trap-*.jsonl" -ErrorAction SilentlyContinue)
        if ($Port -ne 0) { $files = @($files | Where-Object { $_.Name -like ("trap-{0}-*.jsonl" -f $Port) }) }
        $evs = @()
        $skipped = 0
        foreach ($f in $files) {
            if (-not (Test-TrapLogFileSizeOk -Bytes $f.Length -MaxFileMb $MaxFileMb)) {
                Write-Host ("[!] skipping {0} ({1:N1} MB > {2} MB cap) — prune with Clear-OldTrapLogs or raise -MaxFileMb" -f $f.Name, ($f.Length / 1MB), $MaxFileMb)
                $skipped++
                continue
            }
            try {
                foreach ($line in [System.IO.File]::ReadLines($f.FullName)) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    try { $evs += ($line | ConvertFrom-Json) }
                    catch { Write-Host ("[!] bad JSONL line in {0} — skipped" -f $f.Name) }
                }
            } catch {
                Write-Host ("[!] cannot read {0}: {1} — skipped" -f $f.Name, $_.Exception.Message)
                $skipped++
            }
        }
        Write-Host ("[*] {0} event(s) from {1} JSONL file(s){2}" -f $evs.Count, $files.Count, $(if ($skipped -gt 0) { " ($skipped skipped)" } else { "" }))
        return $evs
    } catch {
        Write-Host ("[!] Get-TrapJsonlEvents failed: {0}" -f $_.Exception.Message)
        return @()
    }
}

function Get-TrapStatus {
    [CmdletBinding()]
    param()
    try {
        if ($script:TrapSessions.Count -eq 0) {
            Write-Host "[*] no traps running"
            return @()
        }
        $rows = @()
        foreach ($port in ($script:TrapSessions.Keys | Sort-Object)) {
            $sess = $script:TrapSessions[$port]
            $S = $sess.Shared
            $q = 0
            [System.Threading.Monitor]::Enter($S.Events.SyncRoot)
            try { $q = $S.Events.Count } finally { [System.Threading.Monitor]::Exit($S.Events.SyncRoot) }
            $rows += [pscustomobject]@{
                Port        = $port
                Profile     = $sess.Profile
                Bind        = $sess.BindAddress
                Running     = [bool]$S.Running
                Queued      = $q
                VaultLogged = @($script:TrapCache | Where-Object { [int]$_.local_port -eq $port }).Count
                StartUtc    = $sess.StartUtc
                LogFile     = $sess.LogFile
                Dropped     = [int]$S.Dropped
                PortDropped = [int]$S.PortDropped
                Error       = $S.Error
            }
        }
        return $rows
    } catch {
        Write-Host ("[!] Get-TrapStatus failed: {0}" -f $_.Exception.Message)
        return @()
    }
}

function Stop-TrapListener {
    <#
    Stops trap(s), syncs remaining events to the vault, tears down runspaces.
    #>
    param(
        [int[]]$Port = @(),
        [switch]$All
    )
    try {
        if ($All) { $Port = @($script:TrapSessions.Keys) }
        if ($Port.Count -eq 0) { Write-Host "[!] specify -Port or -All"; return }
        foreach ($p in $Port) {
            if (-not $script:TrapSessions.ContainsKey($p)) {
                Write-Host "[!] no trap on port $p"
                continue
            }
            $sess = $script:TrapSessions[$p]
            Write-Host "[*] stopping trap on port $p ..."
            try {
                $sess.Shared.Stop = $true
                try { if ($null -ne $sess.Shared.Listener) { $sess.Shared.Listener.Stop() } } catch {}
                Start-Sleep -Milliseconds 800
                try { $sess.PowerShell.Stop() } catch {}
                $sess.PowerShell.Dispose()
                Write-Host "[+] trap on port $p stopped"
            } catch {
                Write-Host ("[!] stop on port {0}: {1}" -f $p, $_.Exception.Message)
            }
            $script:TrapSessions.Remove($p)
        }
        Sync-TrapVault | Out-Null
    } catch {
        Write-Host ("[!] Stop-TrapListener failed: {0}" -f $_.Exception.Message)
    }
}

function New-TrapBlock {
    <#
    THE FIX for a trap hit: a local inbound firewall block rule for the
    offending IP. Runs on the user's OWN machine only. Admin-gated.
    Idempotent per IP.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$IpAddress,
        [string]$Reason = "trap hit"
    )
    try {
        if ($script:BlockedIps.ContainsKey($IpAddress)) {
            Write-Host "[*] $IpAddress already blocked — skipping"
            return
        }
        if (-not (Test-IsAdmin)) {
            Write-Host "[!] New-TrapBlock needs an elevated shell (firewall rule). IP noted, not blocked: $IpAddress"
            return
        }
        $rule = "Falsum-TrapBlock-$IpAddress"
        $desc = "Falsum trap: $Reason"
        $out = netsh advfirewall firewall add rule name="$rule" dir=in action=block remoteip="$IpAddress" description="$desc" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] netsh failed: $out"
            return
        }
        $script:BlockedIps[$IpAddress] = [pscustomobject]@{
            utc = (Get-Date).ToUniversalTime().ToString("o"); reason = $Reason; rule = $rule
        }
        Write-Host "[+] blocked inbound from $IpAddress (rule: $rule)"
        if ($script:VaultLoaded -and $script:VaultPath -ne "") {
            try {
                $vault = New-Vault -path $script:VaultPath
                Add-VaultEntry -vault $vault -type "trap-block" -data @{
                    remote_ip = $IpAddress; reason = $Reason; rule = $rule
                    utc = (Get-Date).ToUniversalTime().ToString("o")
                } | Out-Null
            } catch { Write-Host ("[!] vault log of block failed: {0}" -f $_.Exception.Message) }
        }
    } catch {
        Write-Host ("[!] New-TrapBlock failed: {0}" -f $_.Exception.Message)
    }
}

function Remove-TrapBlock {
    param([Parameter(Mandatory=$true)][string]$IpAddress)
    try {
        if (-not (Test-IsAdmin)) { Write-Host "[!] Remove-TrapBlock needs an elevated shell"; return }
        $rule = "Falsum-TrapBlock-$IpAddress"
        netsh advfirewall firewall delete rule name="$rule" 2>&1 | Out-Null
        $script:BlockedIps.Remove($IpAddress)
        Write-Host "[+] removed block rule for $IpAddress"
    } catch {
        Write-Host ("[!] Remove-TrapBlock failed: {0}" -f $_.Exception.Message)
    }
}

function ConvertFrom-NetshRuleOutput {
    <#
    Pure parser: `netsh advfirewall firewall show rule name=all` text ->
    the Falsum trap-block rules in it. Rules are name=all blocks of the
    form "Rule Name:  Falsum-TrapBlock-<ip>" ... "RemoteIP:  <ip>".
    Unrelated rules, "Any" remote IPs, and non-trap rules are skipped.
    #>
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Text
    )
    $rules = @()
    $chunks = (($Text.Trim() + "`r`n`r`n") -split "`r?`n`r?`n")
    foreach ($chunk in $chunks) {
        $name = ""; $remote = ""
        foreach ($line in ($chunk -split "`r?`n")) {
            $t = $line.Trim()
            if ($t -like "Rule Name:*") { $name = $t.Substring(10).Trim() }
            elseif ($t -like "RemoteIP:*") { $remote = $t.Substring(9).Trim() }
        }
        if ($name -like "Falsum-TrapBlock-*" -and $remote -ne "" -and $remote -ne "Any") {
            $ip = $name.Substring("Falsum-TrapBlock-".Length)
            $rules += [pscustomobject]@{ Ip = $ip; Rule = $name; RemoteIp = $remote }
        }
    }
    return $rules
}

function Import-TrapBlockRules {
    <#
    Imports the Falsum trap-block firewall rules that already exist on
    this machine into the session's block table. Without this, a fresh
    shell forgets what a previous shell blocked: New-TrapBlock would
    re-add a duplicate rule and Remove-TrapBlock would report a removal
    that the firewall never confirmed. Admin-gated (reading the rule
    store needs elevation). Called once per session by Start-TrapListener.
    #>
    [CmdletBinding()]
    param()
    try {
        if (-not (Test-IsAdmin)) {
            Write-Host "[!] Import-TrapBlockRules needs an elevated shell — block table stays session-local"
            return 0
        }
        $out = netsh advfirewall firewall show rule name=all 2>&1 | Out-String
        $rules = @(ConvertFrom-NetshRuleOutput -Text $out)
        $added = 0
        foreach ($r in $rules) {
            if (-not $script:BlockedIps.ContainsKey($r.Ip)) {
                $script:BlockedIps[$r.Ip] = [pscustomobject]@{
                    utc = "imported"; reason = "imported from firewall rule store"; rule = $r.Rule
                }
                $added++
            }
        }
        Write-Host ("[+] {0} Falsum trap-block rule(s) in the firewall, {1} new to this session" -f $rules.Count, $added)
        return $added
    } catch {
        Write-Host ("[!] Import-TrapBlockRules failed: {0}" -f $_.Exception.Message)
        return 0
    }
}

function Get-TrapBlockDecision {
    <#
    Pure block-eligibility decision for Block-TrapTopOffenders: one IP's
    hit count -> 'skip-loopback' | 'skip-blocked' | 'block' | 'below-threshold'.
    Loopback is NEVER blocked (your own scans must not firewall 127.0.0.1).
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Ip,
        [int]$Hits,
        [int]$MinHits,
        [bool]$AlreadyBlocked
    )
    if (Test-TrapIpIsLoopback $Ip) { return 'skip-loopback' }
    if ($AlreadyBlocked) { return 'skip-blocked' }
    if ($Hits -ge $MinHits) { return 'block' }
    return 'below-threshold'
}

function Get-TrapBlocked {    [CmdletBinding()]
    param()
    return @($script:BlockedIps.Keys | ForEach-Object {
        [pscustomobject]@{ Ip = $_; Utc = $script:BlockedIps[$_].utc; Reason = $script:BlockedIps[$_].reason; Rule = $script:BlockedIps[$_].rule }
    })
}

function Block-TrapTopOffenders {
    <#
    THE BETTER-WAY LAW, aggregator edition: counts trap hits per IP from the
    vault-logged events and firewall-blocks every IP at or above the hit
    threshold. New-TrapBlock stays admin-gated and idempotent.
    #>
    param([int]$MinHits = 10)
    try {
        Sync-TrapVault | Out-Null
        $counts = @{}
        foreach ($e in @($script:TrapCache)) {
            $ip = $e.remote_ip
            if ($counts.ContainsKey($ip)) { $counts[$ip]++ } else { $counts[$ip] = 1 }
        }
        $blocked = 0
        foreach ($ip in @($counts.Keys)) {
            $decision = Get-TrapBlockDecision -Ip $ip -Hits ([int]$counts[$ip]) -MinHits $MinHits -AlreadyBlocked ($script:BlockedIps.ContainsKey($ip))
            if ($decision -eq 'skip-loopback') {
                Write-Host ("[*] skipping loopback {0} ({1} hits) — your own scans are never firewalled" -f $ip, $counts[$ip])
                continue
            }
            if ($decision -eq 'block') {
                New-TrapBlock -IpAddress $ip -Reason ("top offender: {0} trap hits" -f $counts[$ip])
                $blocked++
            }
        }
        Write-Host ("[+] {0} offender IP(s) at/above {1} hits — block attempted" -f $blocked, $MinHits)
        return $counts
    } catch {
        Write-Host ("[!] Block-TrapTopOffenders failed: {0}" -f $_.Exception.Message)
        return @{}
    }
}

function Export-TrapReport {
    <#
    Writes JSON + human-readable .txt report of all vault-logged trap events,
    SHA-256 hashes both files, vault-logs the report itself.
    #>
    param([Parameter(Mandatory=$true)][string]$Path)
    try {
        Sync-TrapVault | Out-Null
        $evs = @($script:TrapCache)
        $byIp = @{}
        foreach ($e in $evs) {
            if (-not $byIp.ContainsKey($e.remote_ip)) { $byIp[$e.remote_ip] = 0 }
            $byIp[$e.remote_ip]++
        }
        $report = [pscustomobject]@{
            generated_utc = (Get-Date).ToUniversalTime().ToString("o")
            total_events  = $evs.Count
            unique_ips    = $byIp.Count
            hits_by_ip    = $byIp
            blocked_ips   = @($script:BlockedIps.Keys)
            events        = $evs
        }
        $json = $report | ConvertTo-Json -Depth 6
        [System.IO.File]::WriteAllText($Path, $json, [System.Text.Encoding]::UTF8)

        $txt = $Path -replace '\.[^.]+$', '.txt'
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("BLACKBOX TRAP REPORT")
        [void]$sb.AppendLine(("generated (UTC): {0}" -f $report.generated_utc))
        [void]$sb.AppendLine(("total events  : {0}" -f $evs.Count))
        [void]$sb.AppendLine(("unique IPs    : {0}" -f $byIp.Count))
        [void]$sb.AppendLine(("blocked IPs   : {0}" -f (($script:BlockedIps.Keys) -join ', ')))
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("UTC timestamp            | profile  | port  | remote ip:port        | in/out bytes | payload sha256 (first 16) | preview")
        foreach ($e in $evs) {
            [void]$sb.AppendLine(("{0} | {1,-8} | {2,-5} | {3}:{4,-5} | {5}/{6} | {7} | {8}" -f
                $e.utc, $e.profile, $e.local_port, $e.remote_ip, $e.remote_port,
                $e.bytes_in, $e.bytes_out, $e.payload_sha256.Substring(0, 16), $e.payload_preview))
        }
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("ATTACK PATTERNS (triage)")
        $pats = Get-TrapAttackPatterns -Quiet
        if ($pats.Count -eq 0) { [void]$sb.AppendLine("  (no events classified)") }
        foreach ($r in $pats) {
            [void]$sb.AppendLine(("  {0,-20} events={1,-6} ips={2,-4} conf={3}" -f $r.Pattern, $r.Events, $r.UniqueIps, $r.Confidence))
            [void]$sb.AppendLine(("    next: {0}" -f $r.Action))
        }
        [System.IO.File]::WriteAllText($txt, $sb.ToString(), [System.Text.Encoding]::UTF8)

        $csv = $Path -replace '\.[^.]+$', '.csv'
        $csb = New-Object System.Text.StringBuilder
        [void]$csb.AppendLine("utc,profile,local_port,remote_ip,remote_port,bytes_in,bytes_out,duration_ms,payload_sha256,payload_preview")
        foreach ($e in $evs) {
            $fields = @(
                $e.utc, $e.profile, $e.local_port, $e.remote_ip, $e.remote_port,
                $e.bytes_in, $e.bytes_out, $e.duration_ms, $e.payload_sha256,
                (($e.payload_preview -replace '"', '""'))
            )
            [void]$csb.AppendLine(('"{0}"' -f ($fields -join '","')))
        }
        [System.IO.File]::WriteAllText($csv, $csb.ToString(), [System.Text.Encoding]::UTF8)

        foreach ($f in @($Path, $txt, $csv)) {
            $h = New-Object System.Security.Cryptography.SHA256Managed
            try {
                $d = $h.ComputeHash([System.IO.File]::ReadAllBytes($f))
                $hex = ([System.BitConverter]::ToString($d)).Replace('-', '').ToLower()
                Write-Host ("[+] {0}  SHA-256 {1}" -f $f, $hex)
            } finally { $h.Dispose() }
        }
        if ($script:VaultLoaded -and $script:VaultPath -ne "") {
            try {
                $vault = New-Vault -path $script:VaultPath
                Add-VaultEntry -vault $vault -type "trap-report" -data @{
                    utc = $report.generated_utc; events = $evs.Count; unique_ips = $byIp.Count
                    json = $Path; txt = $txt
                } | Out-Null
                Write-Host "[+] report vault-logged"
            } catch { Write-Host ("[!] vault log of report failed: {0}" -f $_.Exception.Message) }
        }
        return $report
    } catch {
        Write-Host ("[!] Export-TrapReport failed: {0}" -f $_.Exception.Message)
        return $null
    }
}

function Get-TrapOffenderSummary {
    <#
    Ranked offender table from vault-logged events (plus raw JSONL with
    -IncludeJsonl): hits, ports, profiles, first/last seen, distinct
    payload hashes. The shape Block-TrapTopOffenders reasons about.
    #>
    param([switch]$IncludeJsonl)
    try {
        Sync-TrapVault | Out-Null
        $evs = @($script:TrapCache)
        if ($IncludeJsonl) { $evs += @(Get-TrapJsonlEvents) }
        $byIp = @{}
        foreach ($e in $evs) {
            $ip = "$($e.remote_ip)"
            if (-not $byIp.ContainsKey($ip)) {
                $byIp[$ip] = @{
                    Hits = 0; Ports = @{}; Profiles = @{};
                    First = $null; Last = $null; Payloads = @{}
                }
            }
            $b = $byIp[$ip]
            $b.Hits++
            $b.Ports["$($e.local_port)"] = $true
            $b.Profiles["$($e.profile)"] = $true
            $b.Payloads["$($e.payload_sha256)"] = $true
            try {
                $t = [datetime]$e.utc
                if ($null -eq $b.First -or $t -lt $b.First) { $b.First = $t }
                if ($null -eq $b.Last -or $t -gt $b.Last) { $b.Last = $t }
            } catch {}
        }
        $rows = @()
        foreach ($ip in $byIp.Keys) {
            $b = $byIp[$ip]
            $rows += [pscustomobject]@{
                Ip               = $ip
                Hits             = $b.Hits
                Ports            = (($b.Ports.Keys | Sort-Object) -join ',')
                Profiles         = (($b.Profiles.Keys | Sort-Object) -join ',')
                DistinctPayloads = $b.Payloads.Count
                FirstSeenUtc     = $b.First
                LastSeenUtc      = $b.Last
                Blocked          = $script:BlockedIps.ContainsKey($ip)
            }
        }
        $rows = @($rows | Sort-Object -Property Hits -Descending)
        Write-Host ("[*] {0} offender IP(s) ranked" -f $rows.Count)
        return $rows
    } catch {
        Write-Host ("[!] Get-TrapOffenderSummary failed: {0}" -f $_.Exception.Message)
        return @()
    }
}

function Test-TrapPayloadPattern {
    <#
    Pure classifier: one trap event's payload preview (+ profile + inbound
    byte count) -> an attack-pattern verdict with the next action. Verdicts
    are scored and labeled, never claimed as certainties: 'unknown-interaction'
    with Low confidence is the honest default. Every pattern carries its
    next-step action (Better-Way Law).
    #>
    param(
        [string]$Preview = "",
        [string]$Profile = "",
        [int]$BytesIn = 0
    )
    try {
        $p = if ($null -eq $Preview) { "" } else { "$Preview" }
        $pl = $p.ToLower().Trim()

        # 1. Scanner tooling signatures — the most specific signal.
        $scannerSigs = @('masscan','nmap','nikto','zgrab','shodan','hydra','censys','nuclei','sqlmap','dirbuster','gobuster','feroxbuster','whatweb')
        foreach ($s in $scannerSigs) {
            if ($pl.Contains($s)) {
                return [pscustomobject]@{
                    Pattern    = 'scanner-signature'
                    Confidence = 'Medium'
                    Action     = "Recon tooling signature ('$s'). Watch for the same IP across ports/profiles; if it sweeps, block via Block-TrapTopOffenders."
                }
            }
        }

        # 2. Web-probe: HTTP-shaped payload with attack paths.
        if (@('http','docker-api') -contains $Profile -and $pl.Contains(' http/')) {
            $webSigs = @('/phpmyadmin','/wp-login','/.env','/cgi-bin','shell.php','cmd=','xdebug','/boaform','/hnap1','/.git','/actuator','/graphql','/../../','eval(','base64_decode','/admin/console')
            foreach ($s in $webSigs) {
                if ($pl.Contains($s)) {
                    return [pscustomobject]@{
                        Pattern    = 'web-probe'
                        Confidence = 'Medium'
                        Action     = "Web exploitation probe ('$s'). This IP wants in. If -AutoBlock is off, block manually; check other decoys for the same IP."
                    }
                }
            }
        }

        # 3. Mirai/IoT credential pairs — distinctive tokens only, so a
        # generic 'admin' alone does not get promoted to mirai.
        $miraiSigs = @('xc3511','vizxv','7ujmko0','ubnt/ubnt','zte521','anko','666666','888888','jvbzd','daowa','5up','xmhdipc')
        foreach ($s in $miraiSigs) {
            if ($pl.Contains($s)) {
                return [pscustomobject]@{
                    Pattern    = 'mirai-iot-cred'
                    Confidence = 'Medium'
                    Action     = "IoT-botnet credential pattern ('$s'). Block this IP now; check every decoy port for it — Mirai-style sweeps hit everything."
                }
            }
        }

        # 4. Credential stuffing: generic credential tokens, real payload size.
        if ($BytesIn -gt 8) {
            $credSigs = @('login','username','password','admin','root','enable','passwd','user:','pass:')
            $hits = @($credSigs | Where-Object { $pl.Contains($_) })
            if ($hits.Count -ge 2) {
                return [pscustomobject]@{
                    Pattern    = 'credential-stuffing'
                    Confidence = 'Low'
                    Action     = ("Suspected credential guessing ({0}). Review the offender summary; block at the repeat-hit threshold, not on one row." -f ($hits -join ', '))
                }
            }
        }

        # 5. Recon scan: near-empty payload — a connect/knock, not a conversation.
        if ($BytesIn -le 8 -and $pl.Length -lt 8) {
            return [pscustomobject]@{
                Pattern    = 'recon-scan'
                Confidence = 'High'
                Action     = "Port knock / connect scan. Cross-reference: same IP on multiple ports or profiles = a scanner. Block with Block-TrapTopOffenders -MinHits 10."
            }
        }

        return [pscustomobject]@{
            Pattern    = 'unknown-interaction'
            Confidence = 'Low'
            Action     = "Unclassified interaction. Read the payload preview yourself; if it repeats from one IP, block that IP and watch the port."
        }
    } catch {
        return [pscustomobject]@{ Pattern = 'unknown-interaction'; Confidence = 'Low'; Action = "Classifier error — inspect the payload preview manually." }
    }
}

function Get-TrapAttackPatterns {
    <#
    Aggregates vault-logged trap events (plus raw JSONL with -IncludeJsonl)
    into attack-pattern counts: how many recon scans, mirai sweeps, web
    probes, credential stuffing attempts — with the top IPs per pattern
    and the next action. This is the triage layer over raw trap logs.
    #>
    param(
        [switch]$IncludeJsonl,
        [switch]$Quiet
    )
    try {
        Sync-TrapVault | Out-Null
        $evs = @($script:TrapCache)
        if ($IncludeJsonl) { $evs += @(Get-TrapJsonlEvents) }
        $agg = @{}
        foreach ($e in $evs) {
            $v = Test-TrapPayloadPattern -Preview "$($e.payload_preview)" -Profile "$($e.profile)" -BytesIn ([int]$e.bytes_in)
            $k = $v.Pattern
            if (-not $agg.ContainsKey($k)) {
                $agg[$k] = @{ Count = 0; Ips = @{}; Samples = @(); Confidence = $v.Confidence; Action = $v.Action }
            }
            $agg[$k].Count++
            $agg[$k].Ips["$($e.remote_ip)"] = $true
            if ($agg[$k].Samples.Count -lt 3 -and -not [string]::IsNullOrWhiteSpace($e.payload_preview)) {
                $agg[$k].Samples += "$($e.payload_preview)"
            }
        }
        $rows = @()
        foreach ($k in $agg.Keys) {
            $rows += [pscustomobject]@{
                Pattern    = $k
                Events     = $agg[$k].Count
                UniqueIps  = $agg[$k].Ips.Count
                Confidence = $agg[$k].Confidence
                Sample     = $(if ($agg[$k].Samples.Count -gt 0) { $agg[$k].Samples[0] } else { "" })
                Action     = $agg[$k].Action
            }
        }
        $rows = @($rows | Sort-Object -Property Events -Descending)
        if (-not $Quiet) {
            if ($rows.Count -eq 0) { Write-Host "[*] no trap events classified yet" }
            else {
                Write-Host ("[*] {0} attack pattern(s) across {1} event(s)" -f $rows.Count, $evs.Count)
                $rows | Format-Table -Property Pattern, Events, UniqueIps, Confidence -AutoSize | Out-Host
                foreach ($r in $rows) { Write-Host ("  {0}: {1}" -f $r.Pattern, $r.Action) }
            }
        }
        return $rows
    } catch {
        Write-Host ("[!] Get-TrapAttackPatterns failed: {0}" -f $_.Exception.Message)
        return @()
    }
}

function Clear-OldTrapLogs {
    <#
    Prunes stale per-port JSONL trap logs older than RetentionDays.
    The vault chain keeps the evidence; this only reclaims disk.
    SupportsShouldProcess, ConfirmImpact Medium.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [int]$RetentionDays = 30,
        [string]$LogDir = ""
    )
    try {
        if ($LogDir -eq "") { $LogDir = Get-TrapLogDir }
        $cutoff = (Get-Date).AddDays(-$RetentionDays)
        $files = @(Get-ChildItem -Path $LogDir -Filter "trap-*.jsonl" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff })
        $removed = @()
        foreach ($f in $files) {
            if ($PSCmdlet.ShouldProcess($f.FullName, "delete trap log older than $RetentionDays days")) {
                Remove-Item -Path $f.FullName -Force -ErrorAction Stop
                $removed += $f.FullName
                Write-Host ("[-] removed {0}" -f $f.Name)
            }
        }
        Write-Host ("[*] {0} stale log(s) removed, {1} kept" -f $removed.Count, ((Get-ChildItem -Path $LogDir -Filter "trap-*.jsonl" -ErrorAction SilentlyContinue | Measure-Object).Count))
        return $removed
    } catch {
        Write-Host ("[!] Clear-OldTrapLogs failed: {0}" -f $_.Exception.Message)
        return @()
    }
}

function Sync-TrapBlocksToBadActors {
    <#
    Carries every trap-blocked IP into the active-defense permanent
    blocklist (Add-BadActor): the persistent JSON mark plus its own
    firewall rule — his "mark follows them" requirement. Loopback is
    skipped (Add-BadActor refuses non-routable IPs anyway).
    #>
    param([string]$VaultPath = "")
    try {
        $here = Split-Path -Parent $MyInvocation.PSCommandPath
        $mod = Join-Path (Split-Path -Parent $here) "11-active-defense\Falsum-ActiveDefense.ps1"
        if (-not (Test-Path $mod)) { $mod = Join-Path $here "..\11-active-defense\Falsum-ActiveDefense.ps1" }
        if (-not (Test-Path $mod)) { Write-Host "[!] active-defense module not found — cannot sync"; return 0 }
        . $mod
        if (-not (Get-Command Add-BadActor -ErrorAction SilentlyContinue)) {
            Write-Host "[!] Add-BadActor not available after loading module"; return 0
        }
        if ($VaultPath -eq "" -and $script:VaultPath -ne "") { $VaultPath = $script:VaultPath }
        $synced = 0
        foreach ($ip in @($script:BlockedIps.Keys)) {
            if (Test-TrapIpIsLoopback $ip) { continue }
            $info = $script:BlockedIps[$ip]
            try {
                Add-BadActor -IpAddress $ip -Reason ("trap-network: " + $info.reason) `
                    -Evidence ("blocked by trap module at " + $info.utc + "; rule " + $info.rule) `
                    -SkipFirewall -VaultPath $VaultPath
                $synced++
            } catch {
                Write-Host ("[!] Add-BadActor for {0}: {1}" -f $ip, $_.Exception.Message)
            }
        }
        Write-Host ("[+] {0} trap-blocked IP(s) synced to the permanent bad-actor list" -f $synced)
        return $synced
    } catch {
        Write-Host ("[!] Sync-TrapBlocksToBadActors failed: {0}" -f $_.Exception.Message)
        return 0
    }
}

function Test-TrapHygiene {
    <#
    Built-in self-test for the trap module. No listeners started, no
    network touched. Fails closed: any failure returns $false.
    #>
    [CmdletBinding()]
    param()
    $fails = @()
    try {
        # 1. profile table shape: unique names, ports in range, known modes
        $profs = Get-TrapProfiles
        $names = @($profs | ForEach-Object { $_.Name })
        if ($names.Count -ne (($names | Sort-Object -Unique).Count)) { $fails += "duplicate profile names" }
        foreach ($p in $profs) {
            foreach ($port in $p.Ports) {
                if ($port -lt 1 -or $port -gt 65535) { $fails += ("profile {0}: port {1} out of range" -f $p.Name, $port) }
            }
            if (@('banner','telnet','http','vnc','mqtt','mysql','dnsrefuse') -notcontains $p.Mode) { $fails += ("profile {0}: unknown mode {1}" -f $p.Name, $p.Mode) }
            if ([string]::IsNullOrWhiteSpace($p.Note)) { $fails += ("profile {0}: empty note" -f $p.Name) }
        }
        # binary-reply profiles must not use a text Banner (the listener
        # ignores Banner for them — a leftover banner would be a dead config)
        foreach ($p in $profs) {
            if (@('mqtt','mysql','dnsrefuse') -contains $p.Mode -and -not [string]::IsNullOrEmpty($p.Banner)) {
                $fails += ("profile {0}: binary mode must not carry a text banner" -f $p.Name)
            }
        }
        # 2. loopback predicate
        $lbCases = @(
            @{ ip = "127.0.0.1"; want = $true }, @{ ip = "127.9.9.9"; want = $true },
            @{ ip = "::1"; want = $true }, @{ ip = "0:0:0:0:0:0:0:1"; want = $true },
            @{ ip = "203.0.113.7"; want = $false }, @{ ip = "192.168.1.5"; want = $false },
            @{ ip = "10.0.0.1"; want = $false }
        )
        foreach ($c in $lbCases) {
            $got = Test-TrapIpIsLoopback $c.ip
            if ($got -ne $c.want) { $fails += ("loopback predicate: {0} -> {1}, want {2}" -f $c.ip, $got, $c.want) }
        }
        # 3. autoblock threshold decision rule (mirrors Sync-TrapVault)
        $thCases = @(
            @{ recent = 5; after = 5; want = $true }, @{ recent = 4; after = 5; want = $false },
            @{ recent = 1; after = 1; want = $true }, @{ recent = 0; after = 1; want = $false }
        )
        foreach ($c in $thCases) {
            $got = ($c.recent -ge $c.after)
            if ($got -ne $c.want) { $fails += ("threshold rule: recent={0} after={1}" -f $c.recent, $c.after) }
        }
        # 4. profile count sanity
        if ($profs.Count -lt 15) { $fails += ("profile count {0} < 15" -f $profs.Count) }
        # 5. attack-pattern classifier battery (pure, no network)
        $patCases = @(
            @{ prev = "";                                prof = 'telnet';   bytes = 0;   want = 'recon-scan' },
            @{ prev = "  ";                              prof = 'ssh';      bytes = 3;   want = 'recon-scan' },
            @{ prev = "nmap scan probe";                 prof = 'http';     bytes = 16;  want = 'scanner-signature' },
            @{ prev = "masscan v1.3";                    prof = 'telnet';   bytes = 11;  want = 'scanner-signature' },
            @{ prev = "root xc3511";                     prof = 'telnet';   bytes = 11;  want = 'mirai-iot-cred' },
            @{ prev = "admin vizxv";                     prof = 'ssh';      bytes = 11;  want = 'mirai-iot-cred' },
            @{ prev = "POST /wp-login.php HTTP/1.1 host: x"; prof = 'http'; bytes = 30;  want = 'web-probe' },
            @{ prev = "GET /.env HTTP/1.1";              prof = 'docker-api'; bytes = 18; want = 'web-probe' },
            @{ prev = "login: admin password: hunter2";  prof = 'telnet';   bytes = 31;  want = 'credential-stuffing' },
            @{ prev = "random ascii garbage qwerty 123"; prof = 'banner';   bytes = 29;  want = 'unknown-interaction' },
            @{ prev = "some http junk without marker";   prof = 'http';     bytes = 28;  want = 'unknown-interaction' }
        )
        foreach ($c in $patCases) {
            $got = (Test-TrapPayloadPattern -Preview $c.prev -Profile $c.prof -BytesIn $c.bytes).Pattern
            if ($got -ne $c.want) {
                $fails += ("pattern classifier: '{0}'/{1} -> {2}, want {3}" -f $c.prev, $c.prof, $got, $c.want)
            }
        }
        # 6. JSONL size-guard predicate battery (boundary-sensitive)
        $sizeCases = @(
            @{ bytes = 0;              mb = 100; want = $true },
            @{ bytes = 104857600;      mb = 100; want = $true },
            @{ bytes = 104857601;      mb = 100; want = $false },
            @{ bytes = 1048576;        mb = 1;   want = $true },
            @{ bytes = 1048577;        mb = 1;   want = $false }
        )
        foreach ($c in $sizeCases) {
            $got = Test-TrapLogFileSizeOk -Bytes $c.bytes -MaxFileMb $c.mb
            if ($got -ne $c.want) {
                $fails += ("size-guard: {0} bytes / {1} MB -> {2}, want {3}" -f $c.bytes, $c.mb, $got, $c.want)
            }
        }
    } catch {
        $fails += ("exception: " + $_.Exception.Message)
    }
    if ($fails.Count -eq 0) { Write-Host "[+] Test-TrapHygiene: all checks pass"; return $true }
    foreach ($f in $fails) { Write-Host ("[!] hygiene FAIL: {0}" -f $f) }
    return $false
}

Write-Host "[*] Falsum Traps loaded. Profiles: $((Get-TrapProfiles | ForEach-Object { $_.Name }) -join ', ')"
Write-Host "[*] DEFENSIVE ONLY: listeners on your own interfaces. This module never initiates outbound connections."
