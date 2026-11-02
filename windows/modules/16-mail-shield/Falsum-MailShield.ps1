<#---------------------------------------------------------------------------
Falsum Mail Shield — phishing email analyzer + email metadata examiner.
Pure PowerShell 5.1. Zero external dependencies. Windows 10/11.

WHAT IT DOES
  - Parses .eml files: unfolded headers, Received chain, body text/html,
    link inventory, attachments (decoded + SHA-256).
  - Runs a weighted phishing-signal battery (never a binary "safe" stamp):
    From/Reply-To mismatch, display-name spoofing, lookalike/typosquat and
    homograph domains, SPF/DKIM/DMARC failures, link anchor-vs-href
    mismatch, urgency language, dangerous attachments, Received-chain
    forgery, date anomalies.
  - Verdicts are SCORED (Low/Medium/High/Critical) with reasons listed.
  - Builds report packs for abuse desks / FTC / IC3.
  - PASSIVE by default: no link fetching, no pixel firing. A -ResolveLinks
    switch exists and is off unless the user asks — firing tracking pixels
    confirms the address is live.

BUILT 2026-10-30 by the main agent, in-chat, per Gregg's order.
Covers problems 201-250 (phishing email) and 1351-1400 (email metadata).

v1.2 hardening (2026-10-30): FIXED real bugs — multipart/alternative took
only the first text/* part so HTML links were never harvested on real mail
(recursive walker now collects text/plain AND text/html), New-PhishReportPack
crashed when Desktop resolved empty (repo-relative fallback), Get-LinksFromBody
missed single-quoted hrefs. NEW: edit-distance typosquat detection
(Test-LevenshteinDistance catches micorsoft.com/paypall.com), RFC2047 header
decoding, per-block Authentication-Results grading (softfail/dmarc-none),
Received-chain anomaly checks (minimal hops, Date-vs-transit skew),
user phish-sender blocklist (your mark follows the sender, +20 on re-hit),
report pack copies the original .eml + SHA-256 manifest + victim checklist.
----------------------------------------------------------------------------#>

$script:MailBrands = @(
    "paypal.com","microsoft.com","apple.com","amazon.com","google.com","gmail.com",
    "outlook.com","live.com","hotmail.com","yahoo.com","aol.com",
    "chase.com","bankofamerica.com","wellsfargo.com","citibank.com","capitalone.com",
    "usps.com","ups.com","fedex.com","dhl.com",
    "irs.gov","ssa.gov",
    "netflix.com","ebay.com","walmart.com","target.com","costco.com",
    "facebook.com","meta.com","instagram.com","linkedin.com","whatsapp.com",
    "dropbox.com","adobe.com","zoom.us",
    "sharepoint.com","onedrive.com","office.com","office365.com","teams.microsoft.com",
    "venmo.com","cash.app","zellepay.com","coinbase.com",
    "bestbuy.com","homedepot.com","lowes.com","samsclub.com",
    "americanexpress.com","discover.com","navyfederal.org","usaa.com",
    "appleid.apple.com","icloud.com",
    "xfinity.com","spectrum.com","att.com","verizon.com","t-mobile.com",
    "geico.com","statefarm.com","progressive.com",
    "delta.com","united.com","americanairlines.com","southwest.com"
)

$script:UrgentPhrases = @(
    "act now","immediate action","account suspended","account locked",
    "verify your account","unusual activity","suspicious activity",
    "final notice","last chance","expires today","within 24 hours",
    "click here immediately","confirm your identity","update your payment",
    "your account will be closed","security alert","unauthorized access"
)

$script:DangerousExtensions = @(
    ".exe",".scr",".bat",".cmd",".ps1",".vbs",".js",".jse",".wsf",".wsh",
    ".msi",".com",".pif",".lnk",".hta",".jar",".docm",".xlsm",".pptm"
)

function Unfold-Headers {
    param([string]$RawHeaderBlock)
    $lines = ($RawHeaderBlock -replace "`r`n","`n") -split "`n"
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        if ($line -match '^[ \t]' -and $out.Count -gt 0) {
            $out[$out.Count-1] = $out[$out.Count-1] + " " + $line.Trim()
        } else {
            $out.Add($line)
        }
    }
    return $out
}

function Get-MailShieldRepoRoot {
    <#
    .SYNOPSIS Repo root for mail-shield working files (reports, blocklist).
    modules/16-mail-shield -> repo root = two levels up.
    #>
    try {
        $here = $PSScriptRoot
        if ([string]::IsNullOrEmpty($here)) { $here = Split-Path $PSCommandPath -Parent }
        $mods = Split-Path $here -Parent
        return (Split-Path $mods -Parent)
    } catch { return [System.IO.Path]::GetTempPath().TrimEnd('\','/') }
}

function Get-MailShieldOutDir {
    <#
    .SYNOPSIS Report output dir. Prefers Desktop; falls back to a
    repo-relative dir when Desktop resolves empty (Server Core, redirected
    profiles — Join-Path on "" would crash New-PhishReportPack).
    #>
    $desk = [Environment]::GetFolderPath("Desktop")
    if (-not [string]::IsNullOrWhiteSpace($desk) -and (Test-Path $desk)) {
        return (Join-Path $desk "Falsum-PhishReports")
    }
    $root = Get-MailShieldRepoRoot
    return (Join-Path $root "Falsum-PhishReports")
}

function Split-MimeParts {
    <#
    .SYNOPSIS Splits a MIME body on a boundary into part objects
    {HeaderBlock, Body}. Handles the final "--boundary--" terminator.
    Pure string logic — the recursion caller walks nested multiparts.
    #>
    param([string]$Body, [string]$Boundary)
    $parts = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrEmpty($Boundary)) { return $parts }
    foreach ($raw in ($Body -split [regex]::Escape("--$Boundary"))) {
        $p = $raw.Trim("`r","`n")
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if ($p -eq "--") { continue }
        if ($p.EndsWith("--")) { $p = $p.Substring(0, $p.Length - 2).TrimEnd("`r","`n") }
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $ps = $p.IndexOf("`r`n`r`n")
        if ($ps -lt 0) { $ps = $p.IndexOf("`n`n") }
        $ph = if ($ps -ge 0) { $p.Substring(0,$ps) } else { "" }
        $pb = if ($ps -ge 0) { $p.Substring($ps).Trim("`r","`n") } else { $p }
        [void]$parts.Add([PSCustomObject]@{ HeaderBlock=$ph; Body=$pb })
    }
    return $parts
}

function Add-MailMimePart {
    <#
    .SYNOPSIS Recursive MIME walker. Feeds attachments, body text/html.
    Multipart parts recurse on their own boundary.
    #>
    param([PSCustomObject]$Part, $Attachments, [ref]$BodyText, [ref]$BodyHtml)
    $ph = $Part.HeaderBlock; $pb = $Part.Body
    $ct = ""
    if ($ph -match '(?im)^Content-Type:\s*([^\r\n;]+)') { $ct = $matches[1].Trim().ToLower() }
    if ($ct -like "multipart/*" -and $ph -match 'boundary="?([^";\s]+)"?') {
        $b2 = $matches[1]
        foreach ($sub in (Split-MimeParts -Body $pb -Boundary $b2)) {
            Add-MailMimePart -Part $sub -Attachments $Attachments -BodyText $BodyText -BodyHtml $BodyHtml
        }
        return
    }
    $disp = ""
    if ($ph -match '(?im)^Content-Disposition:\s*([^;\r\n]+)') { $disp = $matches[1].Trim() }
    $fname = ""
    if ($ph -match 'filename="?([^";\r\n]+)"?') { $fname = $matches[1].Trim() }
    if ($ct -eq "" -and $disp -notlike "attachment*" -and $fname -eq "") {
        $ct = "text/plain"  # typeless body part: treat as text, don't drop it
    }
    if ($disp -like "attachment*" -or $fname -ne "") {
        $enc = ""
        if ($ph -match '(?im)^Content-Transfer-Encoding:\s*([^\r\n;]+)') { $enc = $matches[1].Trim().ToLower() }
        $fbytes = $null
        try {
            if ($enc -eq "base64") { $fbytes = [Convert]::FromBase64String($pb -replace '\s','') }
            else { $fbytes = [System.Text.Encoding]::UTF8.GetBytes($pb) }
        } catch { $fbytes = $null }
        $sha = ""
        if ($fbytes) {
            $h = [System.Security.Cryptography.SHA256]::Create()
            try { $sha = -join ($h.ComputeHash($fbytes) | ForEach-Object { $_.ToString("x2") }) }
            finally { $h.Dispose() }
        }
        [void]$Attachments.Add([PSCustomObject]@{
            FileName=$fname; Disposition=$disp; Encoding=$enc
            Bytes=($fbytes | Measure-Object -Property Length -Sum).Sum
            Sha256=$sha
        })
    } elseif ($ct -like "text/plain*" -and [string]::IsNullOrEmpty($BodyText.Value)) {
        $BodyText.Value = Convert-TransferDecoded -Text $pb -HeaderBlock $ph
    } elseif ($ct -like "text/html*" -and [string]::IsNullOrEmpty($BodyHtml.Value)) {
        $BodyHtml.Value = Convert-TransferDecoded -Text $pb -HeaderBlock $ph
    }
}

function Import-EmlFile {
    <#
    .SYNOPSIS Parses an .eml file into headers, body, links, attachments.
    v1.2: recursive MIME walker (nested multipart), text/plain AND
    text/html both collected (v1.0 took only the first text/* part, so
    real multipart/alternative mail silently skipped every HTML link),
    RFC2047-decoded Subject stored as DecodedSubject.
    #>
    param([Parameter(Mandatory=$true)][string]$Path)
    try {
        if (-not (Test-Path $Path)) { throw "File not found: $Path" }
        $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        $splitAt = $raw.IndexOf("`r`n`r`n")
        if ($splitAt -lt 0) { $splitAt = $raw.IndexOf("`n`n") }
        $headerBlock = if ($splitAt -ge 0) { $raw.Substring(0, $splitAt) } else { $raw }
        $bodyBlock   = if ($splitAt -ge 0) { $raw.Substring($splitAt).Trim("`r","`n") } else { "" }

        $headers = @{}
        foreach ($line in (Unfold-Headers $headerBlock)) {
            $c = $line.IndexOf(':')
            if ($c -gt 0) {
                $k = $line.Substring(0,$c).Trim()
                $v = $line.Substring($c+1).Trim()
                if ($headers.ContainsKey($k)) { $headers[$k] = $headers[$k] + "`n" + $v } else { $headers[$k] = $v }
            }
        }
        if ($headers.ContainsKey('Subject')) { $headers['SubjectDecoded'] = ConvertFrom-Rfc2047EncodedWord $headers['Subject'] }

        $attachments = New-Object System.Collections.ArrayList
        $bodyText = ""; $bodyHtml = ""
        $ct = ""
        if ($headers.ContainsKey('Content-Type')) { $ct = $headers['Content-Type'] }
        if ($ct -match '(?i)multipart/' -and $ct -match 'boundary="?([^";\s]+)"?') {
            $boundary = $matches[1]
            foreach ($part in (Split-MimeParts -Body $bodyBlock -Boundary $boundary)) {
                Add-MailMimePart -Part $part -Attachments $attachments -BodyText ([ref]$bodyText) -BodyHtml ([ref]$bodyHtml)
            }
        } else {
            $bt = Convert-TransferDecoded -Text $bodyBlock -HeaderBlock $headerBlock
            if ($ct -like "*text/html*") { $bodyHtml = $bt } else { $bodyText = $bt }
        }

        $links = New-Object System.Collections.ArrayList
        $sigText = if ($bodyText -ne "") { $bodyText } else { $bodyHtml -replace '<[^>]+>',' ' }
        foreach ($l in (Get-LinksFromBody -Body $bodyText)) { [void]$links.Add($l) }
        foreach ($l in (Get-LinksFromBody -Body $bodyHtml)) {
            if (-not ($links | Where-Object { $_.Href -eq $l.Href })) { [void]$links.Add($l) }
        }
        $prev = $sigText
        if ($prev.Length -gt 4000) { $prev = $prev.Substring(0,4000) }
        $htmlPrev = $bodyHtml
        if ($htmlPrev.Length -gt 2000) { $htmlPrev = $htmlPrev.Substring(0,2000) }
        return [PSCustomObject]@{
            Path=$Path; Headers=$headers; BodyPreview=$prev; BodyHtmlPreview=$htmlPrev
            Links=$links; Attachments=$attachments
        }
    } catch {
        Write-Host "[mail] ERROR parsing eml: $($_.Exception.Message)"
        throw
    }
}

function Convert-TransferDecoded {
    param([string]$Text, [string]$HeaderBlock)
    $enc = ""
    if ($HeaderBlock -match 'Content-Transfer-Encoding:\s*([^\r\n;]+)') { $enc = $matches[1].Trim().ToLower() }
    try {
        if ($enc -eq "base64") {
            $b = [Convert]::FromBase64String($Text -replace '\s','')
            $cs = "utf-8"
            if ($HeaderBlock -match 'charset="?([^";\s]+)"?') { $cs = $matches[1] }
            return [System.Text.Encoding]::GetEncoding($cs).GetString($b)
        } elseif ($enc -eq "quoted-printable") {
            $t = $Text -replace "=\r`n","" -replace "=\n",""
            $t = [regex]::Replace($t, '=([0-9A-Fa-f]{2})', { param($m) [char][Convert]::ToInt32($m.Groups[1].Value,16) })
            return $t
        }
    } catch { }
    return $Text
}

function Get-LinksFromBody {
    param([string]$Body)
    $links = New-Object System.Collections.ArrayList
    $patterns = @(
        '<a\s[^>]*href\s*=\s*"([^"]+)"[^>]*>(.*?)</a>',
        "<a\s[^>]*href\s*=\s*'([^']+)'[^>]*>(.*?)</a>"
    )
    foreach ($pat in $patterns) {
        foreach ($m in [regex]::Matches($Body, $pat, 'IgnoreCase,Singleline')) {
            [void]$links.Add([PSCustomObject]@{ Href=$m.Groups[1].Value; Anchor=($m.Groups[2].Value -replace '<[^>]+>','').Trim() })
        }
    }
    foreach ($m in [regex]::Matches($Body, 'https?://[^\s<>"\)'']+', 'IgnoreCase')) {
        $u = $m.Value.TrimEnd('.')
        if (-not ($links | Where-Object { $_.Href -eq $u })) {
            [void]$links.Add([PSCustomObject]@{ Href=$u; Anchor="" })
        }
    }
    return $links
}

function Get-EmailAddressParts {
    param([string]$Field)
    $display = ""; $addr = ""
    $m = [regex]::Match($Field, '^\s*"?(.*?)"?\s*<([^>]+)>\s*$')
    if ($m.Success) { $display = $m.Groups[1].Value.Trim('" '); $addr = $m.Groups[2].Value.Trim() }
    else {
        # Fallback: split on the LAST < ... > (display names with stray brackets)
        $lt = $Field.LastIndexOf('<'); $gt = $Field.LastIndexOf('>')
        if ($lt -ge 0 -and $gt -gt $lt) {
            $display = $Field.Substring(0,$lt).Trim().Trim('"')
            $addr = $Field.Substring($lt+1,$gt-$lt-1).Trim()
        } else { $addr = $Field.Trim() }
    }
    $display = ConvertFrom-Rfc2047EncodedWord $display
    $domain = ""
    if ($addr -match '@(.+)$') { $domain = $matches[1].ToLower() }
    return [PSCustomObject]@{ Display=$display; Address=$addr.ToLower(); Domain=$domain }
}

function ConvertFrom-Rfc2047EncodedWord {
    <#
    .SYNOPSIS Decodes RFC2047 encoded words (=?charset?B|Q?...?=) in headers.
    Pure string logic. Returns the original text when nothing matches.
    #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    foreach ($m in [regex]::Matches($Text, '=\?([^?]+)\?([bBqQ])\?([^?]*)\?=')) {
        $cs = $m.Groups[1].Value; $enc = $m.Groups[2].Value.ToUpper(); $data = $m.Groups[3].Value
        try {
            $dec = ""
            if ($enc -eq "B") {
                $b = [Convert]::FromBase64String($data)
                $dec = [System.Text.Encoding]::GetEncoding($cs).GetString($b)
            } else {
                $t = $data -replace '_',' '
                $t = [regex]::Replace($t, '=([0-9A-Fa-f]{2})', { param($mm) [char][Convert]::ToInt32($mm.Groups[1].Value,16) })
                $b = [System.Text.Encoding]::GetEncoding("iso-8859-1").GetBytes($t)
                $dec = [System.Text.Encoding]::GetEncoding($cs).GetString($b)
            }
            $out = $out.Replace($m.Value, $dec)
        } catch { }
    }
    return $out
}

function Test-LevenshteinDistance {
    <#
    .SYNOPSIS Pure edit-distance (insert/delete/substitute) between two strings.
    DP over two rows — O(m*n) time, O(n) memory. PS 5.1 safe.
    #>
    param([string]$A, [string]$B)
    if ($A -eq $B) { return 0 }
    $a = $A.ToCharArray(); $b = $B.ToCharArray()
    $m = $a.Length; $n = $b.Length
    if ($m -eq 0) { return $n }
    if ($n -eq 0) { return $m }
    $prev = 0..$n
    $curr = New-Object int[] ($n + 1)
    for ($i = 1; $i -le $m; $i++) {
        $curr[0] = $i
        for ($j = 1; $j -le $n; $j++) {
            $cost = if ($a[$i-1] -eq $b[$j-1]) { 0 } else { 1 }
            $del = $prev[$j] + 1
            $ins = $curr[$j-1] + 1
            $sub = $prev[$j-1] + $cost
            $curr[$j] = [Math]::Min($del, [Math]::Min($ins, $sub))
        }
        $prev = $curr.Clone()
    }
    return $prev[$n]
}

function Test-DomainLookalikeDistance {
    <#
    .SYNOPSIS Edit-distance lookalike test against the brand table.
    Catches typosquats the confusable-normalizer misses: micorsoft.com,
    paypall.com, amazom.com. Returns finding strings (empty = clean).
    Threshold <=2 on the full domain; legit subdomains and the brand
    itself are never flagged.
    #>
    param([string]$Domain)
    $d = $Domain.ToLower()
    $findings = New-Object System.Collections.ArrayList
    foreach ($brand in $script:MailBrands) {
        if ($d -eq $brand) { continue }
        if ($d.EndsWith(".$brand")) { continue }
        $dist = Test-LevenshteinDistance $d $brand
        if ($dist -gt 0 -and $dist -le 2) {
            [void]$findings.Add("Edit-distance lookalike of $brand : $d (distance $dist)")
        }
    }
    return $findings
}

function Get-DomainLookalikeVerdict {
    <#
    .SYNOPSIS Flags typosquat / homograph / punycode lookalikes of known brands.
    Pure string logic — no network.
    #>
    param([string]$Domain)
    $d = $Domain.ToLower()
    $findings = New-Object System.Collections.ArrayList
    if ($d.StartsWith("xn--")) {
        [void]$findings.Add("Punycode/homograph domain: $d (non-ASCII disguised as ASCII)")
    }
    # Normalize common confusables, then compare to brands
    $norm = $d -replace '0','o' -replace '1','l' -replace '5','s' -replace '8','b' `
                -replace 'rn','m' -replace 'vv','w' -replace 'cl','d'
    foreach ($brand in $script:MailBrands) {
        if ($d -eq $brand) { continue }
        if ($norm -eq $brand -or $norm -eq ($brand -replace '\.com$','')) {
            [void]$findings.Add("Lookalike of $brand : $d")
        }
        elseif ($d -like "*$($brand -replace '\..*$','')*" -and $d -ne $brand -and -not $d.EndsWith(".$brand")) {
            # contains brand string but is not the brand or its subdomain — inspect, don't auto-flag
            [void]$findings.Add("Contains brand string '$($brand -replace '\..*$','')' but is not $brand : $d (inspect)")
        }
    }
    foreach ($f in (Test-DomainLookalikeDistance $d)) { [void]$findings.Add($f) }
    return $findings
}

function Get-ReceivedChain {
    param([hashtable]$Headers)
    $chain = New-Object System.Collections.ArrayList
    if (-not $Headers.ContainsKey('Received')) { return $chain }
    $blocks = $Headers['Received'] -split "`n"
    foreach ($b in $blocks) {
        $ips = [regex]::Matches($b, '\b(?:\d{1,3}\.){3}\d{1,3}\b') | ForEach-Object { $_.Value }
        $dt = ""
        $m = [regex]::Match($b, ';\s*(.+)$')
        if ($m.Success) { $dt = $m.Groups[1].Value.Trim() }
        [void]$chain.Add([PSCustomObject]@{ Raw=$b.Trim(); IPs=@($ips | Select-Object -Unique); Date=$dt })
    }
    return $chain
}

function ConvertFrom-AuthResultsLine {
    <#
    .SYNOPSIS Parses one Authentication-Results header value into
    {Mechanism, Result} rows. Pure string logic, no network.
    #>
    param([string]$Value)
    $rows = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Value)) { return $rows }
    $flat = ($Value -replace "`r`n"," ") -replace "\s+"," "
    foreach ($m in [regex]::Matches($flat, '\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)')) {
        [void]$rows.Add([PSCustomObject]@{
            Mechanism=$m.Groups[1].Value.ToLower(); Result=$m.Groups[2].Value.ToLower()
        })
    }
    return $rows
}

function Test-ReceivedChainAnomaly {
    <#
    .SYNOPSIS Pure-logic Received-chain checks: minimal hop count and
    Date-header vs transit-timestamp skew (forged or clock-tampered mail).
    Returns finding objects {Name, Weight, Detail}.
    #>
    param($Chain, [string]$DateHeader)
    $findings = New-Object System.Collections.ArrayList
    if ($Chain.Count -gt 0 -and $Chain.Count -lt 2) {
        [void]$findings.Add([PSCustomObject]@{
            Name="Minimal Received trail"; Weight=12
            Detail="Only $($Chain.Count) Received hop(s) — stripped or forged-minimal headers"
        })
    }
    if (-not [string]::IsNullOrWhiteSpace($DateHeader)) {
        try {
            $msgDate = [DateTime]::Parse($DateHeader)
            $hopDates = @()
            foreach ($h in $Chain) {
                try {
                    if (-not [string]::IsNullOrWhiteSpace($h.Date)) {
                        $hopDates += [DateTime]::Parse($h.Date)
                    }
                } catch { }
            }
            if ($hopDates.Count -gt 0) {
                $newest = ($hopDates | Sort-Object)[-1]
                $skew = [Math]::Abs(($msgDate - $newest).TotalDays)
                if ($skew -gt 2) {
                    [void]$findings.Add([PSCustomObject]@{
                        Name="Date header vs transit skew"; Weight=15
                        Detail="Date: $DateHeader vs newest Received $newest (skew $([Math]::Round($skew,1)) days)"
                    })
                }
            }
        } catch { }
    }
    return $findings
}

function Get-PhishBlocklistPath {
    # Test seam: the hygiene battery points this at a temp file.
    if ($script:MailBlocklistOverride) { return $script:MailBlocklistOverride }
    $root = Get-MailShieldRepoRoot
    return (Join-Path $root "Falsum-PhishBlocklist.txt")
}

function Test-PhishSenderBlocklist {
    <#
    .SYNOPSIS Checks a domain against the local blocklist the user built
    with Add-PhishSenderBlocklist. Returns $true on an exact or subdomain hit.
    #>
    param([string]$Domain)
    $d = $Domain.ToLower()
    $p = Get-PhishBlocklistPath
    if (-not (Test-Path $p)) { return $false }
    foreach ($line in (Get-Content $p -ErrorAction SilentlyContinue)) {
        $b = $line.Trim().ToLower()
        if ($b -eq "" -or $b.StartsWith("#")) { continue }
        if ($d -eq $b -or $d.EndsWith(".$b")) { return $true }
    }
    return $false
}

function Add-PhishSenderBlocklist {
    <#
    .SYNOPSIS Adds domains to the user's local phish blocklist (the mark
    that follows the sender: future mail from these domains scores +20).
    Better-Way Law: a detection that recurs without a record is unfinished.
    #>
    param([string[]]$Domains, [string]$Reason)
    $p = Get-PhishBlocklistPath
    if (-not (Test-Path $p)) {
        "# Falsum phish sender blocklist — one domain per line. Added by Add-PhishSenderBlocklist." | Out-File $p -Encoding utf8
    }
    $existing = @{}
    foreach ($line in (Get-Content $p)) { $existing[$line.Trim().ToLower()] = $true }
    $added = 0
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm"
    foreach ($dom in $Domains) {
        $d = $dom.Trim().ToLower()
        if ($d -eq "" -or $existing.ContainsKey($d)) { continue }
        "# $stamp — $Reason" | Out-File $p -Append -Encoding utf8
        $d | Out-File $p -Append -Encoding utf8
        $existing[$d] = $true; $added++
    }
    Write-Host "[mail] Blocklist: $p ($added added)"
    return $p
}

function Test-PhishingSignals {
    <#
    .SYNOPSIS Weighted phishing-signal battery. Returns signal objects.
    #>
    param([Parameter(Mandatory=$true)]$Email)
    $signals = New-Object System.Collections.ArrayList
    $add = { param($Name,$Weight,$Detail) [void]$signals.Add([PSCustomObject]@{Signal=$Name;Weight=$Weight;Detail=$Detail}) }.GetNewClosure()

    $from = Get-EmailAddressParts ($Email.Headers['From'])
    if ($Email.Headers.ContainsKey('Reply-To')) {
        $rt = Get-EmailAddressParts ($Email.Headers['Reply-To'])
        if ($rt.Address -ne "" -and $rt.Address -ne $from.Address) {
            &$add "Reply-To differs from From" 25 "From: $($from.Address) / Reply-To: $($rt.Address)"
        }
    }
    if ($from.Display -ne "" -and $from.Domain -ne "") {
        $dl = $from.Display.ToLower()
        foreach ($brand in $script:MailBrands) {
            $bname = ($brand -split '\.')[0]
            if ($dl.Contains($bname) -and $from.Domain -ne $brand -and -not $from.Domain.EndsWith(".$brand")) {
                &$add "Display-name brand spoof" 30 "Display '$($from.Display)' claims $brand but sender domain is $($from.Domain)"
                break
            }
        }
    }
    $lookalikeHit = @{}
    foreach ($f in (Get-DomainLookalikeVerdict $from.Domain)) {
        if ($f -like "Punycode*") { &$add "Homograph sender domain" 35 $f; $lookalikeHit[$from.Domain] = $true }
        elseif ($f -like "Lookalike*") { &$add "Lookalike sender domain" 30 $f; $lookalikeHit[$from.Domain] = $true }
        elseif ($f -like "Edit-distance*" -and -not $lookalikeHit.ContainsKey($from.Domain)) { &$add "Edit-distance lookalike sender domain" 30 $f; $lookalikeHit[$from.Domain] = $true }
        elseif ($f -notlike "Edit-distance*") { &$add "Brand-string in domain (inspect)" 10 $f }
    }
    if ($from.Domain -ne "" -and (Test-PhishSenderBlocklist $from.Domain)) {
        &$add "Sender on your phish blocklist" 20 "Domain $($from.Domain) was blocklisted by you before"
    }

    if ($Email.Headers.ContainsKey('Authentication-Results')) {
        $blocks = $Email.Headers['Authentication-Results'] -split "`n"
        $seen = @{}
        foreach ($block in $blocks) {
            foreach ($r in (ConvertFrom-AuthResultsLine $block)) {
                $key = "$($r.Mechanism)=$($r.Result)"
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                $detail = $block.Trim().Substring(0,[Math]::Min(160,$block.Trim().Length))
                if ($r.Result -eq "fail") {
                    $w = if ($r.Mechanism -eq "dmarc") { 30 } else { 25 }
                    &$add "$($r.Mechanism.ToUpper()) fail" $w $detail
                } elseif ($r.Mechanism -eq "spf" -and $r.Result -in @("softfail","neutral","temperror")) {
                    &$add "SPF $($r.Result) (weak pass)" 12 $detail
                } elseif ($r.Mechanism -eq "dmarc" -and $r.Result -eq "none") {
                    &$add "DMARC none (no policy published)" 12 $detail
                } elseif ($r.Result -eq "none") {
                    &$add "$($r.Mechanism.ToUpper()) not evaluated" 5 $detail
                }
            }
        }
    } else {
        &$add "No Authentication-Results header" 8 "Cannot verify SPF/DKIM/DMARC from headers present"
    }

    $chain = Get-ReceivedChain $Email.Headers
    $dateHdr = ""
    if ($Email.Headers.ContainsKey('Date')) { $dateHdr = $Email.Headers['Date'] }
    foreach ($fa in (Test-ReceivedChainAnomaly -Chain $chain -DateHeader $dateHdr)) {
        &$add $fa.Name $fa.Weight $fa.Detail
    }
    if ($chain.Count -gt 0) {
        $first = $chain[$chain.Count-1]  # oldest = origin
        if ($first.IPs.Count -gt 0 -and $from.Domain -ne "") {
            &$add "Origin hop recorded" 0 "Oldest Received hop IPs: $($first.IPs -join ', ')"
        }
    } elseif ($chain.Count -eq 0) {
        &$add "No Received headers" 12 "No transit trail — headers may be stripped or forged minimal"
    }

    if ($Email.Headers.ContainsKey('Date')) {
        try {
            $dt = [DateTime]::Parse($Email.Headers['Date'])
            if ($dt -gt (Get-Date).AddDays(2)) { &$add "Future-dated message" 15 "Date: $($Email.Headers['Date'])" }
        } catch { &$add "Unparseable Date header" 8 $Email.Headers['Date'] }
    }

    $bodyLower = $Email.BodyPreview.ToLower()
    $subjLower = ""
    if ($Email.Headers.ContainsKey('SubjectDecoded')) { $subjLower = $Email.Headers['SubjectDecoded'].ToLower() }
    elseif ($Email.Headers.ContainsKey('Subject')) { $subjLower = $Email.Headers['Subject'].ToLower() }
    $urgText = "$bodyLower $subjLower"
    foreach ($phrase in $script:UrgentPhrases) {
        if ($urgText.Contains($phrase)) { &$add "Urgency language" 10 "Phrase: '$phrase'"; break }
    }

    $blockHitHosts = @{}
    foreach ($link in $Email.Links) {
        try {
            $hrefHost = ([System.Uri]$link.Href).Host.ToLower()
            if ($link.Anchor -ne "" -and $link.Anchor -match '^https?://') {
                $anchorHost = ([System.Uri]$link.Anchor).Host.ToLower()
                if ($anchorHost -ne $hrefHost) {
                    &$add "Link anchor/href mismatch" 30 "Shows $anchorHost but goes to $hrefHost"
                }
            }
            if ($hrefHost -match 'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly') {
                &$add "URL shortener hides destination" 12 $link.Href
            }
            $linkLookalikeHit = @{}
            foreach ($f in (Get-DomainLookalikeVerdict $hrefHost)) {
                if ($f -like "Punycode*") { &$add "Homograph link domain" 35 $f; $linkLookalikeHit[$hrefHost] = $true }
                elseif ($f -like "Lookalike*") { &$add "Lookalike link domain" 30 $f; $linkLookalikeHit[$hrefHost] = $true }
                elseif ($f -like "Edit-distance*" -and -not $linkLookalikeHit.ContainsKey($hrefHost)) { &$add "Edit-distance lookalike link domain" 30 $f; $linkLookalikeHit[$hrefHost] = $true }
            }
            if ((Test-PhishSenderBlocklist $hrefHost) -and -not $blockHitHosts.ContainsKey($hrefHost)) {
                &$add "Link host on your phish blocklist" 20 $link.Href
                $blockHitHosts[$hrefHost] = $true
            }
            if ($hrefHost -ne $from.Domain -and $from.Domain -ne "" -and $link.Href -match 'login|signin|verify|account|secure|update') {
                &$add "Credential-harvest link off-domain" 20 "$hrefHost (sender: $($from.Domain))"
            }
        } catch { }
    }

    foreach ($att in $Email.Attachments) {
        $ext = [System.IO.Path]::GetExtension($att.FileName).ToLower()
        if ($ext -in $script:DangerousExtensions) {
            &$add "Dangerous attachment type" 35 "$($att.FileName) ($ext), sha256 $($att.Sha256)"
        }
        if ($att.FileName -match '\.[^.]+\.[^.]+$') {
            $inner = [System.IO.Path]::GetExtension([System.IO.Path]::GetFileNameWithoutExtension($att.FileName)).ToLower()
            if ($inner -in $script:DangerousExtensions -or $inner -match '^\.(exe|scr|bat|js)$') {
                &$add "Double-extension attachment" 30 $att.FileName
            }
        }
    }
    return $signals
}

function Get-EmailVerdict {
    <#
    .SYNOPSIS Scored verdict: sums signal weights into Low/Medium/High/Critical.
    Never a binary "safe" stamp — absence of signals is not proof.
    #>
    param([Parameter(Mandatory=$true)]$Email)
    $signals = Test-PhishingSignals $Email
    $score = ($signals | Measure-Object -Property Weight -Sum).Sum
    if (-not $score) { $score = 0 }
    $level = "Low"
    if ($score -ge 80) { $level = "Critical" }
    elseif ($score -ge 45) { $level = "High" }
    elseif ($score -ge 20) { $level = "Medium" }
    $from = Get-EmailAddressParts ($Email.Headers['From'])
    $subj = ""
    if ($Email.Headers.ContainsKey('SubjectDecoded')) { $subj = $Email.Headers['SubjectDecoded'] }
    elseif ($Email.Headers.ContainsKey('Subject')) { $subj = $Email.Headers['Subject'] }
    return [PSCustomObject]@{
        File=$Email.Path; From=$from.Address; Subject=$subj
        Score=$score; Level=$level
        Signals=$signals
        Note="Scored verdict, not a safety stamp. Low score = no signals found in headers/body, not proof of legitimacy."
    }
}


function Get-KancaScoredVerdict {
    <#
    .SYNOPSIS
        Kanca-style scored verdict: per-layer caps, diminishing repeats, cross-layer bonus.
    .DESCRIPTION
        Upgrades the flat weighted sum with anti-noise design from Kanca
        (github.com/Kadirify/kanca, MIT):
        - Signals grouped into layers: Headers, Links, Content, Attachments, Domain
        - Each layer capped (weak signals can't dominate via volume)
        - Repeat hits of the SAME signal add only 25% per repeat
        - +5 bonus if 3+ layers fire (cross-signal corroboration)
        - Total capped at 100
        Layer is inferred from signal name keywords. Pure function over the
        signal list from Test-PhishingSignals.
    #>
    param([Parameter(Mandatory=$true)]$Email)

    $signals = Test-PhishingSignals $Email

    # --- Layer inference from signal name ---
    $layerOf = {
        param($name)
        $n = $name.ToLower()
        if ($n -match 'reply-to|display-name|homograph|lookalike|edit-distance|brand-string|blocklist|received|auth|spf|dkim|dmarc|message-id') { return 'Headers' }
        if ($n -match 'link|href|anchor|url|domain.*link|shortener|redirect') { return 'Links' }
        if ($n -match 'attach|executable|macro|archive|html.*attach|qr') { return 'Attachments' }
        if ($n -match 'tld|hyphen|digit|newly.*regist|sender.*domain') { return 'Domain' }
        return 'Content'
    }

    # --- Layer caps (Kanca design: no single layer dominates) ---
    $layerCaps = @{ Headers=35; Links=35; Content=30; Attachments=35; Domain=30 }

    # --- Group by layer, apply diminishing repeats ---
    $layerScores = @{}
    $layerCounts = @{}
    $seenSignals = @{}

    foreach ($sig in $signals) {
        $layer = &$layerOf $sig.Signal
        $key = "$layer::$($sig.Signal)"

        if (-not $seenSignals.ContainsKey($key)) {
            $seenSignals[$key] = 0
        }
        $seenSignals[$key]++

        # First hit: full weight. Repeats: 25% each (Kanca diminishing)
        $w = $sig.Weight
        if ($seenSignals[$key] -gt 1) { $w = [math]::Round($w * 0.25) }

        if (-not $layerScores.ContainsKey($layer)) {
            $layerScores[$layer] = 0
            $layerCounts[$layer] = 0
        }
        $layerScores[$layer] += $w
        $layerCounts[$layer]++
    }

    # --- Apply per-layer caps ---
    $cappedTotal = 0
    $activeLayers = 0
    foreach ($layer in $layerScores.Keys) {
        $cap = $layerCaps[$layer]
        $capped = [math]::Min($layerScores[$layer], $cap)
        $cappedTotal += $capped
        if ($capped -gt 0) { $activeLayers++ }
    }

    # --- Cross-layer bonus: +5 if 3+ layers fire ---
    if ($activeLayers -ge 3) { $cappedTotal += 5 }

    # --- Total cap at 100 ---
    $score = [math]::Min($cappedTotal, 100)

    $level = "Low"
    if ($score -ge 80) { $level = "Critical" }
    elseif ($score -ge 45) { $level = "High" }
    elseif ($score -ge 20) { $level = "Medium" }

    $from = Get-EmailAddressParts ($Email.Headers['From'])
    $subj = ""
    if ($Email.Headers.ContainsKey('SubjectDecoded')) { $subj = $Email.Headers['SubjectDecoded'] }
    elseif ($Email.Headers.ContainsKey('Subject')) { $subj = $Email.Headers['Subject'] }

    return [PSCustomObject]@{
        File=$Email.Path; From=$from.Address; Subject=$subj
        Score=$score; Level=$level
        Signals=$signals; ActiveLayers=$activeLayers
        Scoring="Kanca-style (per-layer caps, 25% repeat diminishing, +5 cross-layer bonus, cap 100)"
        Note="Scored verdict, not a safety stamp. Low score = no signals found, not proof of legitimacy."
    }
}

function New-PhishReportPack {
    <#
    .SYNOPSIS Builds an evidence pack for reporting phishing: abuse desk, FTC, IC3.
    v1.2: copies the original .eml into the pack, hashes everything into a
    MANIFEST, writes a victim action checklist (Better-Way Law — a detection
    ships the next step), and no longer crashes when the Desktop folder
    resolves empty (Server Core / redirected profiles).
    THE FIX for "I got phished, now what": a ready-to-send report.
    #>
    param([Parameter(Mandatory=$true)]$Verdict, [string]$OutDir)
    try {
        if (-not $OutDir) { $OutDir = Get-MailShieldOutDir }
        if ([string]::IsNullOrWhiteSpace($OutDir)) { throw "Could not resolve a report output directory." }
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $dir = Join-Path $OutDir "phish-$stamp"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $Verdict | ConvertTo-Json -Depth 6 | Out-File (Join-Path $dir "verdict.json") -Encoding utf8
        $emlHash = ""
        if ($Verdict.File -and (Test-Path $Verdict.File)) {
            Copy-Item $Verdict.File (Join-Path $dir "original.eml") -Force
            $emlHash = (Get-FileHash (Join-Path $dir "original.eml") -Algorithm SHA256).Hash
        }
        $lines = @(
            "PHISHING REPORT PACK — generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
            "File: $($Verdict.File)"
            "From: $($Verdict.From)"
            "Subject: $($Verdict.Subject)"
            "Score: $($Verdict.Score) ($($Verdict.Level))"
            ""
            "SIGNALS:"
        )
        foreach ($s in $Verdict.Signals) { $lines += "  [$($s.Weight)] $($s.Signal) — $($s.Detail)" }
        $lines += ""
        $lines += "WHAT TO DO NOW (victim checklist):"
        $lines += "  1. Do NOT click links, open attachments, or reply to this message."
        $lines += "  2. If you already clicked/entered credentials: change that password NOW, from a"
        $lines += "     device you trust, and turn on two-factor authentication (app-based, not SMS)."
        $lines += "  3. Check the account's recent login/activity page for sessions you did not start"
        $lines += "     and sign them out."
        $lines += "  4. Forward the message as an attachment (not inline) to the impersonated brand's"
        $lines += "     abuse desk (abuse@ / phishing@ their domain) and to the FTC: reportfraud.ftc.gov."
        $lines += "  5. If money moved: file with FBI IC3 (ic3.gov) and call your bank's fraud line."
        $lines += "  6. Blocklist the sender domain so the next attempt scores against your record:"
        $lines += "     Add-PhishSenderBlocklist -Domains '<sender-domain>' -Reason 'phish <date>'."
        $lines += ""
        $lines += "Report to: the impersonated brand's abuse desk, FTC (reportfraud.ftc.gov), FBI IC3 (ic3.gov)."
        $lines | Out-File (Join-Path $dir "report.txt") -Encoding utf8
        $manifest = @(
            "phish-$stamp evidence manifest — generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            "original.eml SHA-256: $emlHash"
            "verdict.json SHA-256: $((Get-FileHash (Join-Path $dir 'verdict.json') -Algorithm SHA256).Hash)"
            "report.txt  SHA-256: $((Get-FileHash (Join-Path $dir 'report.txt') -Algorithm SHA256).Hash)"
        )
        $manifest | Out-File (Join-Path $dir "MANIFEST.txt") -Encoding utf8
        $hash = (Get-FileHash (Join-Path $dir "verdict.json") -Algorithm SHA256).Hash
        Write-Host "[mail] Report pack: $dir"
        Write-Host "[mail] verdict.json SHA-256: $hash"
        if ($emlHash -ne "") { Write-Host "[mail] original.eml SHA-256: $emlHash" }
        return [PSCustomObject]@{ Dir=$dir; Sha256=$hash; EmlSha256=$emlHash }
    } catch {
        Write-Host "[mail] ERROR building report pack: $($_.Exception.Message)"
        throw
    }
}

function Test-MailShieldHygiene {
    <#
    .SYNOPSIS Offline self-test battery: synthetic eml samples, no network.
    #>
    $checks = New-Object System.Collections.ArrayList
    $ok = { param($n,$c) [void]$checks.Add([PSCustomObject]@{Check=$n;Pass=[bool]$c}) }.GetNewClosure()

    # 1. Lookalike verdict: typosquat
    $f = Get-DomainLookalikeVerdict "paypa1.com"
    &$ok "typosquat paypa1.com flagged" (($f | Where-Object { $_ -like "Lookalike*" }).Count -gt 0)
    # 2. Punycode
    $f = Get-DomainLookalikeVerdict "xn--paypl-4ve.com"
    &$ok "punycode flagged" (($f | Where-Object { $_ -like "Punycode*" }).Count -gt 0)
    # 3. Legit brand not flagged
    $f = Get-DomainLookalikeVerdict "paypal.com"
    &$ok "legit paypal.com clean" ($f.Count -eq 0)
    # 4. Address parts parse
    $p = Get-EmailAddressParts '"PayPal" <spoof@evil.example>'
    &$ok "address parse" ($p.Display -eq "PayPal" -and $p.Domain -eq "evil.example")
    # 5. Full verdict on synthetic phish
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "bb-phishtest.eml"
    @'
From: "PayPal" <security@paypa1.com>
Reply-To: harvest@evil.example
Subject: Act now: unusual activity
Authentication-Results: spf=fail dkim=fail
Date: Thu, 30 Oct 2026 10:00:00 -0600
Content-Type: text/html

<a href="http://paypa1.com/login">https://paypal.com/login</a> Act now, your account will be closed within 24 hours.
'@ | Out-File $tmp -Encoding utf8
    $em = Import-EmlFile $tmp
    $v = Get-EmailVerdict $em
    &$ok "synthetic phish scores High/Critical" ($v.Level -in @("High","Critical"))
    &$ok "reply-to mismatch signal" (($v.Signals | Where-Object { $_.Signal -like "Reply-To*" }).Count -gt 0)
    &$ok "anchor/href mismatch signal" (($v.Signals | Where-Object { $_.Signal -like "Link anchor*" }).Count -gt 0)
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    # 6. Clean mail scores Low (brand table expanded — must stay false-positive free).
    # Realistic: real mail carries Received + Authentication-Results headers.
    $tmp2 = Join-Path ([System.IO.Path]::GetTempPath()) "bb-cleantest.eml"
    @'
From: "Mom" <mom@example.com>
Subject: Sunday dinner
Date: Thu, 30 Oct 2026 10:00:00 -0600
Received: from mail.example.com (mail.example.com [192.0.2.10]) by mx.receiver.example; Thu, 30 Oct 2026 10:01:00 -0600
Received: from [192.168.1.5] by mail.example.com; Thu, 30 Oct 2026 10:00:30 -0600
Authentication-Results: mx.receiver.example; spf=pass; dkim=pass; dmarc=pass

See you Sunday.
'@ | Out-File $tmp2 -Encoding utf8
    $em2 = Import-EmlFile $tmp2
    $v2 = Get-EmailVerdict $em2
    &$ok "clean mail scores Low" ($v2.Level -eq "Low")
    &$ok "clean mail score 0" ($v2.Score -eq 0)
    Remove-Item $tmp2 -Force -ErrorAction SilentlyContinue

    # 7. Levenshtein distance
    &$ok "lev identical 0" ((Test-LevenshteinDistance "paypal.com" "paypal.com") -eq 0)
    &$ok "lev kitten/sitting 3" ((Test-LevenshteinDistance "kitten" "sitting") -eq 3)
    &$ok "lev paypall/paypal 1" ((Test-LevenshteinDistance "paypall.com" "paypal.com") -eq 1)
    &$ok "lev empty vs abc 3" ((Test-LevenshteinDistance "" "abc") -eq 3)
    # 8. Edit-distance typosquats the confusable-normalizer misses
    $f = Get-DomainLookalikeVerdict "paypall.com"
    &$ok "edit-distance paypall.com flagged" (($f | Where-Object { $_ -like "Edit-distance*" }).Count -gt 0)
    $f = Get-DomainLookalikeVerdict "micorsoft.com"
    &$ok "edit-distance micorsoft.com flagged" (($f | Where-Object { $_ -like "Edit-distance*" }).Count -gt 0)
    $f = Get-DomainLookalikeVerdict "mail.google.com"
    &$ok "legit subdomain mail.google.com clean" ($f.Count -eq 0)
    $f = Get-DomainLookalikeVerdict "example.com"
    &$ok "unrelated example.com clean" ($f.Count -eq 0)
    # 9. RFC2047 decode
    &$ok "rfc2047 B decode" ((ConvertFrom-Rfc2047EncodedWord "=?UTF-8?B?UGF5UGFs?=") -eq "PayPal")
    &$ok "rfc2047 Q decode" ((ConvertFrom-Rfc2047EncodedWord "=?UTF-8?Q?Verify_=C3=A9_now?=") -eq "Verify é now")
    &$ok "rfc2047 plain passthrough" ((ConvertFrom-Rfc2047EncodedWord "Hello World") -eq "Hello World")
    # 10. multipart/alternative: html links harvested even when text/plain comes first (v1.0 gap)
    $tmp3 = Join-Path ([System.IO.Path]::GetTempPath()) "bb-multitest.eml"
    @'
From: "PayPal" <security@paypa1.com>
Subject: Verify your account
Content-Type: multipart/alternative; boundary="b1"

--b1
Content-Type: text/plain; charset="utf-8"

Please verify.

--b1
Content-Type: text/html; charset="utf-8"

<a href='http://paypa1.com/login'>https://paypal.com/login</a>
--b1--
'@ | Out-File $tmp3 -Encoding utf8
    $em3 = Import-EmlFile $tmp3
    $hrefs = @($em3.Links | ForEach-Object { $_.Href })
    &$ok "multipart html link harvested" ($hrefs -contains "http://paypa1.com/login")
    $v3 = Get-EmailVerdict $em3
    &$ok "multipart anchor/href mismatch fires" (($v3.Signals | Where-Object { $_.Signal -like "Link anchor*" }).Count -gt 0)
    &$ok "single-quote href parsed" (($em3.Links | Where-Object { $_.Anchor -like "*paypal.com*" }).Count -gt 0)
    # NOTE: $tmp3 is removed after check 15 (report pack copies it as evidence)
    # 11. nested multipart (mixed > alternative)
    $tmp4 = Join-Path ([System.IO.Path]::GetTempPath()) "bb-nesttest.eml"
    @'
From: "Shop" <shop@example.com>
Subject: Receipt
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain

Thanks.

--inner
Content-Type: text/html

<p>Thanks.</p> <a href="https://example.com/rcpt">receipt</a>
--inner--

--outer--
'@ | Out-File $tmp4 -Encoding utf8
    $em4 = Import-EmlFile $tmp4
    &$ok "nested multipart link harvested" ((@($em4.Links | ForEach-Object { $_.Href }) -contains "https://example.com/rcpt"))
    Remove-Item $tmp4 -Force -ErrorAction SilentlyContinue
    # 12. auth-results grading
    $ar = ConvertFrom-AuthResultsLine "mx.example.com; spf=softfail smtp.mailfrom=evil.example; dkim=none"
    &$ok "auth-results parse count" ($ar.Count -eq 2)
    &$ok "auth-results spf softfail row" (($ar | Where-Object { $_.Mechanism -eq "spf" -and $_.Result -eq "softfail" }).Count -eq 1)
    $tmp5 = Join-Path ([System.IO.Path]::GetTempPath()) "bb-authtest.eml"
    @'
From: "Bank" <alerts@banc0.com>
Subject: Verify
Authentication-Results: mx.example.com; spf=softfail; dkim=fail; dmarc=none
Date: Thu, 30 Oct 2026 10:00:00 -0600

Verify now.
'@ | Out-File $tmp5 -Encoding utf8
    $em5 = Import-EmlFile $tmp5
    $v5 = Get-EmailVerdict $em5
    &$ok "spf softfail signal" (($v5.Signals | Where-Object { $_.Signal -like "SPF softfail*" }).Count -gt 0)
    &$ok "dkim fail signal" (($v5.Signals | Where-Object { $_.Signal -eq "DKIM fail" }).Count -gt 0)
    &$ok "dmarc none signal" (($v5.Signals | Where-Object { $_.Signal -like "DMARC none*" }).Count -gt 0)
    Remove-Item $tmp5 -Force -ErrorAction SilentlyContinue
    # 13. received-chain anomalies
    $tmp6 = Join-Path ([System.IO.Path]::GetTempPath()) "bb-rcvdtest.eml"
    @'
From: "X" <x@example.com>
Date: Sat, 24 Oct 2026 10:00:00 -0600
Received: from evil.example (evil.example [203.0.113.7]) by mx.example.com; Thu, 30 Oct 2026 10:05:00 -0600
Subject: Hi

Hi.
'@ | Out-File $tmp6 -Encoding utf8
    $em6 = Import-EmlFile $tmp6
    $v6 = Get-EmailVerdict $em6
    &$ok "minimal-hop signal" (($v6.Signals | Where-Object { $_.Signal -eq "Minimal Received trail" }).Count -gt 0)
    &$ok "date-skew signal" (($v6.Signals | Where-Object { $_.Signal -eq "Date header vs transit skew" }).Count -gt 0)
    Remove-Item $tmp6 -Force -ErrorAction SilentlyContinue
    # 14. blocklist round-trip (temp-file seam, not the real blocklist)
    $script:MailBlocklistOverride = Join-Path ([System.IO.Path]::GetTempPath()) "bb-blocktest.txt"
    if (Test-Path $script:MailBlocklistOverride) { Remove-Item $script:MailBlocklistOverride -Force }
    Add-PhishSenderBlocklist -Domains @("evil.example","banc0.com") -Reason "hygiene test" | Out-Null
    &$ok "blocklist exact hit" (Test-PhishSenderBlocklist "evil.example")
    &$ok "blocklist subdomain hit" (Test-PhishSenderBlocklist "sub.evil.example")
    &$ok "blocklist unrelated miss" (-not (Test-PhishSenderBlocklist "good.example"))
    $tmp7 = Join-Path ([System.IO.Path]::GetTempPath()) "bb-blockmail.eml"
    @'
From: "X" <x@evil.example>
Subject: Hi
Date: Thu, 30 Oct 2026 10:00:00 -0600

Hi.
'@ | Out-File $tmp7 -Encoding utf8
    $em7 = Import-EmlFile $tmp7
    $v7 = Get-EmailVerdict $em7
    &$ok "blocklist signal scores +20" (($v7.Signals | Where-Object { $_.Signal -eq "Sender on your phish blocklist" -and $_.Weight -eq 20 }).Count -gt 0)
    Remove-Item $tmp7 -Force -ErrorAction SilentlyContinue
    Remove-Item $script:MailBlocklistOverride -Force -ErrorAction SilentlyContinue
    $script:MailBlocklistOverride = $null
    # 15. report pack: manifest + eml copy + victim checklist, explicit outdir
    $tmpOut = Join-Path ([System.IO.Path]::GetTempPath()) "bb-phishout"
    $rp = New-PhishReportPack $v3 -OutDir $tmpOut
    &$ok "report pack dir created" (Test-Path $rp.Dir)
    &$ok "report pack has manifest" (Test-Path (Join-Path $rp.Dir "MANIFEST.txt"))
    &$ok "report pack copies original eml" (Test-Path (Join-Path $rp.Dir "original.eml"))
    $rtxt = Get-Content (Join-Path $rp.Dir "report.txt") -Raw
    &$ok "report pack has victim checklist" ($rtxt -like "*WHAT TO DO NOW*")
    &$ok "report pack hashes eml" ($rp.EmlSha256 -match '^[0-9a-f]{64}$')
    Remove-Item $tmpOut -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $tmp3 -Force -ErrorAction SilentlyContinue
    &$ok "outdir helper non-empty" (-not [string]::IsNullOrWhiteSpace((Get-MailShieldOutDir)))

    $pass = ($checks | Where-Object { $_.Pass }).Count
    Write-Host "[mail] Hygiene: $pass/$($checks.Count) checks passed."
    return $checks
}

Write-Host "[mail] Falsum Mail Shield loaded. Import-EmlFile / Get-EmailVerdict / New-PhishReportPack / Test-MailShieldHygiene."
