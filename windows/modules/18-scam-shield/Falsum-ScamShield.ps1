<#---------------------------------------------------------------------------
Falsum Scam Shield — scam verification workflows for end users.
Pure PowerShell 5.1. Zero external dependencies. Windows 10/11.

HONEST SCOPE (stated, not hidden)
  - Scams are human problems, not packet problems. No PowerShell module
    detects a romance scammer's lies. What a tool CAN do: force the
    verification steps scammers rely on you skipping — identity checks,
    payment-method red flags, independent contact verification — and
    capture evidence for reporting.
  - Smishing/vishing/deepfake: this module triages (what to check, what to
    never do) and verifies through independent channels. It does NOT claim
    ML deepfake detection — that would be a lie in a .ps1 file.
  - Message triage (Start-ScamMessageTriage) is heuristic: payment-demand
    weight + urgency language + links. It scores suspicion; it does not
    prove a scam. The checklist is the verdict path.
  - Every check ends in a scored verdict + an FTC/IC3 report pack.
    The fix for "I think I'm being scammed" is verification + reporting.

Covers problems 251-700 (smishing, vishing, deepfakes, romance, tech
support, grandparent, investment/crypto, job, rental scams).

BUILT 2026-10-30 by the main agent, in-chat, per Gregg's order.
v1.1 (2026-10-30, hardening): FIXED A REAL SCORING BUG — roughly half the
checklist questions were scored backwards. Questions have mixed polarity:
some safe answers are 'y' ("Have you video-called them live?"), others are
'n' ("Have they asked for money?"), but Start-ScamCheck scored every 'n'
as a failed step. Every step now carries Good='y'/'n' and only the unsafe
answer scores points. Levels are now normalized to percent-of-max so a
40% red-flag rate means High on every scam type, not a different number
per type. NEW: weighted payment-demand table (gift cards 30, steam/itunes
cards 35 — the irreversibility hierarchy), word-boundary matching so
"cryptography" no longer trips "crypto", Get-PaymentRiskScore,
urgency-language table + Test-ScamUrgency, Get-ScamLinksFromText, and
Start-ScamMessageTriage (paste a suspicious message, get a scored triage).
New-ScamReportPack gains the Desktop-empty fallback (Server Core bug class)
and hashes both output files. Vault-logs check metadata only — never
victim notes (PII stays out of the vault).
----------------------------------------------------------------------------#>

$script:ScamTypes = @("romance","grandparent","investment","job","rental","techsupport","smishing","vishing","deepfake")

# Weighted payment-demand table: Weight = how irreversible / how scam-typical.
# 30-35 = effectively irreversible (gift cards, crypto); 20-25 = reversible
# only with fast bank action (wire, Zelle); 15 = worth a hard look.
$script:PaymentRedFlagTable = @(
    @{Term="steam card";      W=35; Why="Steam/gift cards are irreversible and untraceable — the #1 scam payout."},
    @{Term="itunes card";     W=35; Why="iTunes/App Store cards are irreversible — no legit business takes them."},
    @{Term="google play card";W=35; Why="Play cards are irreversible — no legit business takes them."},
    @{Term="gift card";       W=30; Why="Gift cards are irreversible — no legit bill, bail, or support takes them."},
    @{Term="giftcard";        W=30; Why="Gift cards are irreversible — no legit bill, bail, or support takes them."},
    @{Term="western union";   W=30; Why="WU transfers are cash-like: gone in minutes, hard to recall."},
    @{Term="moneygram";       W=30; Why="MoneyGram transfers are cash-like: gone in minutes, hard to recall."},
    @{Term="wire transfer";   W=25; Why="Wire transfers are hard to reverse — recall windows are hours."},
    @{Term="bank wire";       W=25; Why="Wire transfers are hard to reverse — recall windows are hours."},
    @{Term="crypto";          W=25; Why="Crypto is irreversible. 'Send crypto' = the money is gone."},
    @{Term="bitcoin";         W=25; Why="Bitcoin is irreversible. 'Send bitcoin' = the money is gone."},
    @{Term="usdt";            W=25; Why="USDT is irreversible — the stablecoin of pig-butchering payouts."},
    @{Term="ethereum";        W=25; Why="ETH is irreversible. 'Send ETH' = the money is gone."},
    @{Term="prepaid card";    W=25; Why="Prepaid/reloadable cards are cash-like and untraceable."},
    @{Term="zelle";           W=20; Why="Zelle is instant and bank-to-bank — reversals are rare."},
    @{Term="cashapp";         W=20; Why="Cash App is instant P2P — reversals are rare."},
    @{Term="cash app";        W=20; Why="Cash App is instant P2P — reversals are rare."},
    @{Term="venmo";           W=20; Why="Venmo is instant P2P — reversals are rare."},
    @{Term="cashier's check"; W=20; Why="Fake cashier's checks + 'forward the rest' = the classic mule trap."},
    @{Term="money order";     W=15; Why="Money orders are cash-like; combined with urgency they are a flag."}
)

# Urgency / secrecy language: Weight = how load-bearing the lever is.
$script:UrgencyTable = @(
    @{Term="immediately";    W=10; Why="Urgency compresses your thinking — the core lever."},
    @{Term="right now";      W=10; Why="Urgency compresses your thinking — the core lever."},
    @{Term="urgent";         W=10; Why="Urgency compresses your thinking — the core lever."},
    @{Term="keep it secret"; W=10; Why="Secrecy blocks the one defense that works: a second opinion."},
    @{Term="don't tell";     W=8;  Why="Secrecy blocks the one defense that works: a second opinion."},
    @{Term="do not tell";    W=8;  Why="Secrecy blocks the one defense that works: a second opinion."},
    @{Term="act now";        W=8;  Why="Forced speed skips verification."},
    @{Term="final notice";   W=8;  Why="Manufactured deadline — real senders give real process."},
    @{Term="suspend";        W=8;  Why="Fear trigger: 'account suspended'."},
    @{Term="suspended";      W=8;  Why="Fear trigger: 'account suspended'."},
    @{Term="arrest";         W=10; Why="Fear trigger: authority impersonation."},
    @{Term="warrant";        W=10; Why="Fear trigger: authority impersonation."},
    @{Term="today only";     W=8;  Why="Manufactured deadline."},
    @{Term="expire";         W=7;  Why="Manufactured deadline."},
    @{Term="locked";         W=7;  Why="Fear trigger: 'account locked'."},
    @{Term="limited time";   W=6;  Why="Manufactured deadline."}
)

# ---------------------------------------------------------------------------
# Module imports (vault, graceful when missing) — metadata logging only.
# ---------------------------------------------------------------------------
$script:VaultLoaded = $false
function Import-ScamVaultModule {
    if ($script:VaultLoaded) { return }
    $here = Split-Path -Parent $MyInvocation.PSCommandPath
    $mod = Join-Path (Split-Path -Parent $here) "12-timeline-vault\Falsum-Vault.ps1"
    if (-not (Test-Path $mod)) { $mod = Join-Path $here "..\12-timeline-vault\Falsum-Vault.ps1" }
    if (Test-Path $mod) { . $mod; $script:VaultLoaded = $true }
    else { Write-Host "[!] vault module not found — scam checks will not be vault-logged" }
}
Import-ScamVaultModule
$script:ScamVaultPath = Join-Path ([Environment]::GetFolderPath("ApplicationData")) "Falsum\vault.jsonl"

function New-ScamLog {
    <# Hash-chained vault log of a scam check — TYPE/SCORE/LEVEL ONLY.
       Victim notes are NEVER written to the vault (PII stays out). #>
    param([Parameter(Mandatory=$true)][string]$Action, [Parameter(Mandatory=$true)]$Result)
    if (-not $script:VaultLoaded) { return }
    try {
        $vault = New-Vault -path $script:ScamVaultPath
        Add-VaultEntry -vault $vault -type "scam-shield" -data @{
            action = $Action
            scamtype = [string]$Result.Type
            score = [int]$Result.Score
            level = [string]$Result.Level
            utc = (Get-Date).ToUniversalTime().ToString("o")
        } | Out-Null
    } catch { Write-Host "[!] scam vault log failed: $($_.Exception.Message)" }
}

function Get-ScamChecklist {
    <#
    .SYNOPSIS Returns the weighted verification checklist for a scam type.
    Each step: Id, Q (question as written), Good ('y' or 'n' = the SAFE
    answer), W (points added when the answer is UNSAFE), How (concrete action).
    #>
    param([Parameter(Mandatory=$true)][ValidateSet("romance","grandparent","investment","job","rental","techsupport","smishing","vishing","deepfake")][string]$Type)
    switch ($Type) {
        "romance" { return @(
            @{Id="R1"; Q="Have you video-called them live (not a recorded clip)?"; Good="y"; W=30; How="Demand a live call with an unpredictable gesture (hold up 3 fingers, say today's date). Refusal = fail."},
            @{Id="R2"; Q="Did you reverse-image-search their photos?"; Good="y"; W=20; How="Save the photo, search it on TinEye / Google Images. Same photo under other names = fail."},
            @{Id="R3"; Q="Have they asked for money, gift cards, or crypto for ANY reason?"; Good="n"; W=40; How="Emergency, plane ticket, customs fee — the story changes, the ask doesn't. Any ask = fail."},
            @{Id="R4"; Q="Can you verify them through an independent channel?"; Good="y"; W=20; How="Find them outside the dating app: employer, public records, people-track username search. Ghost = fail."},
            @{Id="R5"; Q="Are they avoiding meeting in person with endless excuses?"; Good="n"; W=15; How="Deployed soldier, oil rig, doctor abroad — classic scripts. Pattern match = fail."}
        )}
        "grandparent" { return @(
            @{Id="G1"; Q="Did you verify the caller's identity through a KNOWN number?"; Good="y"; W=40; How="Hang up. Call your grandchild on the number YOU have saved — not the one the caller gives you."},
            @{Id="G2"; Q="Did the caller demand secrecy ('don't tell mom and dad')?"; Good="n"; W=25; How="Secrecy is the mechanism. Real emergencies don't need secrecy."},
            @{Id="G3"; Q="Is payment demanded via gift cards, wire, or cash pickup?"; Good="n"; W=35; How="No bail bondsman, lawyer, or hospital takes iTunes cards. Any such demand = fail."},
            @{Id="G4"; Q="Did you ask a question only the real person could answer?"; Good="y"; W=20; How="A shared memory, a pet's name. Voice cloning beats hello; it doesn't beat specifics."}
        )}
        "investment" { return @(
            @{Id="I1"; Q="Is the platform registered? (SEC/FINRA check)"; Good="y"; W=30; How="Search the firm on SEC EDGAR / FINRA BrokerCheck. Unregistered + promises returns = fail."},
            @{Id="I2"; Q="Are returns guaranteed or unusually high?"; Good="n"; W=25; How="'Guaranteed 20% monthly' is mathematically a Ponzi. Guaranteed = fail."},
            @{Id="I3"; Q="Can you withdraw easily, or only deposit?"; Good="y"; W=30; How="Try a small withdrawal early. Deposit-only, fees-to-withdraw, 'taxes due first' = fail."},
            @{Id="I4"; Q="Did contact come unsolicited (DM, wrong-number text)?"; Good="n"; W=15; How="Pig-butchering starts with 'sorry, wrong number'. Unsolicited = fail."},
            @{Id="I5"; Q="Is pressure applied to act now / keep it secret?"; Good="n"; W=20; How="Urgency + secrecy = the two levers. Both present = fail."}
        )}
        "job" { return @(
            @{Id="J1"; Q="Did they ask YOU for money (equipment, training, background check)?"; Good="n"; W=35; How="Real employers pay you. Any upfront fee = fail."},
            @{Id="J2"; Q="Is the company verifiable independently?"; Good="y"; W=25; How="Company website (check domain age), LinkedIn employees, physical address. Ghost company = fail."},
            @{Id="J3"; Q="Did a real interview happen (not text-only)?"; Good="y"; W=20; How="Text-only 'interview' over chat apps = fail."},
            @{Id="J4"; Q="Were you sent a check to deposit and forward funds?"; Good="n"; W=40; How="Fake-check/mule scheme. Any check + forward instruction = fail and report."}
        )}
        "rental" { return @(
            @{Id="N1"; Q="Have you seen the property interior in person or via live video?"; Good="y"; W=30; How="Photos-only listings get scraped from real sales. No interior access = fail."},
            @{Id="N2"; Q="Is the price far below market for the area?"; Good="n"; W=20; How="Bait pricing. Check 3 comparable listings."},
            @{Id="N3"; Q="Does the 'landlord' refuse in-person meeting / demand wire before keys?"; Good="n"; W=35; How="Money before keys, sight unseen = fail."},
            @{Id="N4"; Q="Does the lister claim to be abroad / missionary / military?"; Good="n"; W=15; How="Classic script. Verify ownership via county assessor records."}
        )}
        "techsupport" { return @(
            @{Id="T1"; Q="Did THEY contact YOU (call, popup, email) claiming a problem?"; Good="n"; W=35; How="Microsoft/Apple/Google never call about your computer. Unsolicited = fail."},
            @{Id="T2"; Q="Did they ask for remote access (AnyDesk, TeamViewer)?"; Good="n"; W=35; How="Remote access = the heist. Never grant to unsolicited callers."},
            @{Id="T3"; Q="Is payment demanded via gift cards or wire?"; Good="n"; W=30; How="No legit support takes gift cards. Ever."},
            @{Id="T4"; Q="Did a browser popup with a phone number claim virus infection?"; Good="n"; W=20; How="Popups are ads, not diagnoses. Close the browser; the 'virus' vanishes."}
        )}
        "smishing" { return @(
            @{Id="S1"; Q="Did the text come from a random 10-digit number or email-to-text?"; Good="n"; W=20; How="Banks/shippers don't text from random mobiles. Check the sender."},
            @{Id="S2"; Q="Does it demand urgency + a link (package held, account locked)?"; Good="n"; W=25; How="Go to the company's site/app directly — never the link. Compare."},
            @{Id="S3"; Q="Does the link domain match the real company?"; Good="y"; W=30; How="Read the domain character by character. usps-track-package.top is not usps.com."},
            @{Id="S4"; Q="Were you expecting this message?"; Good="y"; W=15; How="Unexpected + link + urgency = the whole playbook."}
        )}
        "vishing" { return @(
            @{Id="V1"; Q="Did you verify via a number YOU looked up independently?"; Good="y"; W=40; How="Hang up. Call the number on your card / statement / official site."},
            @{Id="V2"; Q="Are they asking for full SSN, passwords, or codes texted to you?"; Good="n"; W=35; How="No legit caller asks for the code they just sent you. That code is the keys."},
            @{Id="V3"; Q="Is there urgency + secrecy?"; Good="n"; W=20; How="Same levers as every other scam. Recognize the shape."}
        )}
        "deepfake" { return @(
            @{Id="D1"; Q="Can you verify through a second channel?"; Good="y"; W=40; How="Video call from 'the boss'? Message them on another app, call their known number. One channel is never enough now."},
            @{Id="D2"; Q="Does the request break normal procedure?"; Good="n"; W=25; How="Urgent wire, skip approvals, keep it quiet — procedure exists to stop exactly this."},
            @{Id="D3"; Q="Do you have a family/office code word?"; Good="y"; W=20; How="Set one TODAY with family and coworkers: 'what's the code word?' defeats cloned voices."},
            @{Id="D4"; Q="Are you being asked to confirm identity with video/audio?"; Good="n"; W=15; How="Your face/voice are now keys. Don't hand biometric samples to unverified callers."}
        )}
    }
}

function Get-ScamMaxPoints {
    <# Pure: maximum possible score for a scam type. #>
    param([Parameter(Mandatory=$true)][string]$Type)
    $sum = 0
    foreach ($s in (Get-ScamChecklist $Type)) { $sum += $s.W }
    return $sum
}

function ConvertTo-ScamLevel {
    <# Pure: level from SCORE AS PERCENT of max. 60/40/15 thresholds so every
       scam type reads the same: Critical >=60%, High >=40%, Medium >=15%. #>
    param([Parameter(Mandatory=$true)][int]$Score, [Parameter(Mandatory=$true)][int]$Max)
    if ($Max -le 0) { return "Low" }
    $pct = 100.0 * $Score / $Max
    if ($pct -ge 60) { return "Critical" }
    if ($pct -ge 40) { return "High" }
    if ($pct -ge 15) { return "Medium" }
    return "Low"
}

function Start-ScamCheck {
    <#
    .SYNOPSIS Guided interactive verification. Records answers, scores, verdicts.
    Pass an -Answers hashtable to run non-interactively: @{R1='y';R2='n';...}
    The SAFE answer per step is shown as [safe: y|n]; 'u'/blank = unknown
    (half weight — unverified is half a red flag, not zero).
    #>
    param(
        [Parameter(Mandatory=$true)][ValidateSet("romance","grandparent","investment","job","rental","techsupport","smishing","vishing","deepfake")][string]$Type,
        [hashtable]$Answers
    )
    try {
        $steps = Get-ScamChecklist $Type
        $results = New-Object System.Collections.ArrayList
        $score = 0
        foreach ($s in $steps) {
            $ans = ""
            if ($Answers -and $Answers.ContainsKey($s.Id)) {
                $ans = $Answers[$s.Id]
            } else {
                Write-Host ""
                Write-Host "[$($s.Id)] $($s.Q)"
                Write-Host "    [safe answer: $($s.Good)]  How to verify: $($s.How)"
                $ans = Read-Host "    Your answer (y / n / u = unknown)"
            }
            $a = $ans.ToString().Trim().ToLower()
            $failed = ($a -ne $s.Good -and $a -ne 'u' -and $a -ne '')
            $unknown = (-not $failed -and ($a -eq 'u' -or $a -eq ''))
            $pts = 0
            if ($failed) { $pts = $s.W } elseif ($unknown) { $pts = [math]::Round($s.W/2) }
            $score += $pts
            [void]$results.Add([PSCustomObject]@{Id=$s.Id; Question=$s.Q; SafeAnswer=$s.Good; Answer=$a; Failed=$failed; Unknown=$unknown; Points=$pts; How=$s.How})
        }
        $max = Get-ScamMaxPoints $Type
        $level = ConvertTo-ScamLevel -Score $score -Max $max
        $check = [PSCustomObject]@{
            Type=$Type; Utc=(Get-Date).ToUniversalTime().ToString("o")
            Score=$score; MaxPoints=$max; Level=$level; Steps=$results
            Guidance=$(Get-ScamGuidance $Type $level)
        }
        Write-Host ""
        Write-Host "[scam] $Type check: $score/$max points -> $level"
        Write-Host "[scam] $($check.Guidance)"
        New-ScamLog -Action "check" -Result $check
        return $check
    } catch {
        Write-Host "[scam] ERROR running check: $($_.Exception.Message)"
        throw
    }
}

function Get-ScamGuidance {
    param([string]$Type,[string]$Level)
    if ($Level -eq "Critical" -or $Level -eq "High") {
        return "STOP. Do not send money, do not grant access, do not keep it secret. Tell someone you trust. Report: FTC reportfraud.ftc.gov, FBI IC3 ic3.gov. If money moved: call your bank NOW — wire recall windows are hours, not days."
    }
    if ($Level -eq "Medium") {
        return "Do not proceed until every failed step is verified through an independent channel. Scammers rely on the steps you skip."
    }
    return "No red flags tripped on the steps checked — stay alert; new information re-opens the check."
}

function Test-PaymentRedFlag {
    <#
    .SYNOPSIS Scans free text (a message, listing, email) for scam payment
    demands. Word-boundary matching: "cryptography" does NOT trip "crypto".
    Trailing-s tolerant: "steam cards" matches the "steam card" row.
    Returns one object per hit: Term, Weight, Why.
    #>
    param([Parameter(Mandatory=$true)][string]$Text)
    $hits = New-Object System.Collections.ArrayList
    foreach ($p in $script:PaymentRedFlagTable) {
        $pat = "\b" + [regex]::Escape($p.Term) + "s?\b"
        if ([regex]::IsMatch($Text, $pat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            [void]$hits.Add([PSCustomObject]@{Term=$p.Term; Weight=$p.W; Why=$p.Why})
        }
    }
    return $hits
}

function Get-PaymentRiskScore {
    <# Pure: totals payment-demand weight in text. >=50 Critical, >=25 High,
       >0 Flagged — the irreversibility of the demand is the risk. #>
    param([Parameter(Mandatory=$true)][string]$Text)
    $hits = Test-PaymentRedFlag $Text
    $total = 0
    foreach ($h in $hits) { $total += $h.Weight }
    $level = "Clean"
    if ($total -ge 50) { $level = "Critical" } elseif ($total -ge 25) { $level = "High" } elseif ($total -gt 0) { $level = "Flagged" }
    return [PSCustomObject]@{ Total=$total; Level=$level; Hits=$hits }
}

function Test-ScamUrgency {
    <#
    .SYNOPSIS Scores urgency/secrecy/fear language in free text. Returns
    one object per hit: Term, Weight, Why. Heuristic — urgency alone is
    not proof of a scam; combined with a payment demand it is the playbook.
    #>
    param([Parameter(Mandatory=$true)][string]$Text)
    $hits = New-Object System.Collections.ArrayList
    foreach ($p in $script:UrgencyTable) {
        $pat = "\b" + [regex]::Escape($p.Term) + "s?\b"
        if ([regex]::IsMatch($Text, $pat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            [void]$hits.Add([PSCustomObject]@{Term=$p.Term; Weight=$p.W; Why=$p.Why})
        }
    }
    return $hits
}

function Get-ScamLinksFromText {
    <# Pure: pulls http/https URLs from text, trims trailing punctuation. #>
    param([Parameter(Mandatory=$true)][string]$Text)
    $out = New-Object System.Collections.ArrayList
    $m = [regex]::Matches($Text, 'https?://[^\s<>"''`]+', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($x in $m) {
        $u = $x.Value.TrimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}')
        if ($u.Length -gt 10) { [void]$out.Add($u) }
    }
    return $out
}

function Start-ScamMessageTriage {
    <#
    .SYNOPSIS Paste a suspicious message — get a scored triage.
    Payment-demand weight + urgency language + link presence. Pure offline,
    heuristic: this scores SUSPICION, it does not prove a scam. The
    checklist (Start-ScamCheck) is the verdict path. Better-Way Law: a
    triage without next steps is a lecture, so every level prints them.
    #>
    param([Parameter(Mandatory=$true)][string]$Text)
    try {
        $pay = Get-PaymentRiskScore $Text
        $urg = Test-ScamUrgency $Text
        $urgTotal = 0
        foreach ($u in $urg) { $urgTotal += $u.Weight }
        $links = Get-ScamLinksFromText $Text
        $score = $pay.Total + $urgTotal + ($links.Count * 5)
        $level = ConvertTo-ScamLevel -Score ([math]::Min($score,100)) -Max 100
        $signals = New-Object System.Collections.ArrayList
        foreach ($h in $pay.Hits)  { [void]$signals.Add("PAYMENT: '$($h.Term)' (weight $($h.Weight)) — $($h.Why)") }
        foreach ($h in $urg)       { [void]$signals.Add("URGENCY: '$($h.Term)' (weight $($h.Weight)) — $($h.Why)") }
        foreach ($l in $links)     { [void]$signals.Add("LINK: $l — go to the company directly, never through this link.") }
        $fix = @(
            "Do NOT pay, click, or call back yet.",
            "Verify through an INDEPENDENT channel: the number/site YOU have, not the one in the message.",
            "Payment demanded via gift cards, wire, Zelle, or crypto = walk away, then report.",
            "If this matches a scam type, run Start-ScamCheck for the full checklist.",
            "Report: FTC reportfraud.ftc.gov, FBI IC3 ic3.gov. Forward smishing to 7726 (SPAM)."
        )
        if ($level -eq "Low") {
            $fix = @("No strong signals in this message — stay alert; new details re-open the triage.")
        }
        Write-Host ""
        Write-Host "[scam] Message triage: score $score -> $level"
        foreach ($s in $signals) { Write-Host "[scam]   $s" }
        Write-Host "[scam] Next steps:"
        foreach ($f in $fix) { Write-Host "[scam]   - $f" }
        $triage = [PSCustomObject]@{
            Utc=(Get-Date).ToUniversalTime().ToString("o"); Score=$score; Level=$level
            PaymentTotal=$pay.Total; UrgencyTotal=$urgTotal; LinkCount=$links.Count
            Signals=$signals; FixSteps=$fix
        }
        New-ScamLog -Action "message-triage" -Result ([PSCustomObject]@{Type="message"; Score=$score; Level=$level})
        return $triage
    } catch {
        Write-Host "[scam] ERROR in message triage: $($_.Exception.Message)"
        throw
    }
}

function Get-ScamReportOutDir {
    <# Repo-relative fallback when the Desktop folder is unavailable
       (Server Core / redirected profiles) — mirrors the mail-shield fix. #>
    param([string]$OutDir)
    if ($OutDir) { return $OutDir }
    $d = [Environment]::GetFolderPath("Desktop")
    if ([string]::IsNullOrWhiteSpace($d)) {
        $root = $MyInvocation.PSCommandPath
        if ($root) { $root = Split-Path -Parent (Split-Path -Parent $root) }
        if ([string]::IsNullOrWhiteSpace($root)) { $root = "." }
        $d = Join-Path $root "Falsum-ScamReports"
    } else {
        $d = Join-Path $d "Falsum-ScamReports"
    }
    return $d
}

function New-ScamReportPack {
    <#
    .SYNOPSIS THE FIX for "I've been scammed, now what": evidence pack for
    FTC / IC3 / local police, with everything they ask for in one place.
    Both files are SHA-256 hashed. Vault-logs TYPE/SCORE/LEVEL only —
    victim notes are never written to the vault.
    #>
    param(
        [Parameter(Mandatory=$true)]$Check,
        [string]$Notes,
        [string]$OutDir
    )
    try {
        $base = Get-ScamReportOutDir -OutDir $OutDir
        if (-not (Test-Path $base)) { New-Item -ItemType Directory -Path $base -Force | Out-Null }
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $dir = Join-Path $base ("scam-" + $Check.Type + "-" + $stamp)
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $Check | ConvertTo-Json -Depth 6 | Out-File (Join-Path $dir "check.json") -Encoding utf8
        $lines = @(
            "SCAM REPORT PACK — generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
            "Type: $($Check.Type) | Score: $($Check.Score)/$($Check.MaxPoints) ($($Check.Level))"
            ""
            "STEP RESULTS (answer vs safe answer):"
        )
        foreach ($s in $Check.Steps) { $lines += "  [$($s.Id)] answer=$($s.Answer) safe=$($s.SafeAnswer) points=$($s.Points) :: $($s.Question)" }
        $lines += ""
        if ($Notes) { $lines += "VICTIM NOTES:"; $lines += $Notes; $lines += "" }
        $lines += "FILE WITH:"
        $lines += "  - FTC: reportfraud.ftc.gov"
        $lines += "  - FBI IC3: ic3.gov"
        $lines += "  - Local police (for a report number — banks and insurers ask for it)"
        $lines += "  - The impersonated brand's fraud/abuse desk"
        $lines += ""
        $lines += "PRESERVE: original messages, numbers, addresses, transaction receipts, screenshots. Do not delete anything."
        $lines | Out-File (Join-Path $dir "report.txt") -Encoding utf8
        $jHash = (Get-FileHash (Join-Path $dir "check.json") -Algorithm SHA256).Hash
        $tHash = (Get-FileHash (Join-Path $dir "report.txt") -Algorithm SHA256).Hash
        Write-Host "[scam] Report pack: $dir"
        Write-Host "[scam] check.json SHA-256: $jHash"
        Write-Host "[scam] report.txt SHA-256: $tHash"
        New-ScamLog -Action "report-pack" -Result $Check
        return [PSCustomObject]@{ Dir=$dir; CheckJsonSha256=$jHash; ReportTxtSha256=$tHash; Sha256=$jHash }
    } catch {
        Write-Host "[scam] ERROR building report pack: $($_.Exception.Message)"
        throw
    }
}

function Test-ScamShieldHygiene {
    <#
    .SYNOPSIS Offline battery: scripted answers, no network, no interaction.
    #>
    $checks = New-Object System.Collections.ArrayList
    $ok = { param($n,$c) [void]$checks.Add([PSCustomObject]@{Check=$n;Pass=[bool]$c}) }.GetNewClosure()

    # Checklist shape + polarity coverage on every type
    foreach ($t in $script:ScamTypes) {
        $cl = Get-ScamChecklist $t
        &$ok "checklist $t non-empty" ($cl.Count -ge 3)
        &$ok "checklist $t weights positive" ((($cl | Measure-Object -Property W -Sum).Sum) -gt 0)
        $allPolar = $true
        foreach ($s in $cl) { if ($s.Good -ne 'y' -and $s.Good -ne 'n') { $allPolar = $false } }
        &$ok "checklist $t polarity on every step" $allPolar
        &$ok "checklist $t max points > 0" ((Get-ScamMaxPoints $t) -gt 0)
    }
    # Spot polarity: the questions the old code scored backwards
    $rom = Get-ScamChecklist "romance"
    &$ok "polarity R3 (asked for money) safe=n" ((($rom | Where-Object { $_.Id -eq "R3" }).Good) -eq 'n')
    &$ok "polarity R5 (avoiding meeting) safe=n" ((($rom | Where-Object { $_.Id -eq "R5" }).Good) -eq 'n')
    &$ok "polarity T3 (gift cards) safe=n" ((($tech = Get-ScamChecklist "techsupport") | Where-Object { $_.Id -eq "T3" }).Good -eq 'n')
    &$ok "polarity V1 (verify known number) safe=y" ((($vis = Get-ScamChecklist "vishing") | Where-Object { $_.Id -eq "V1" }).Good -eq 'y')
    &$ok "polarity S3 (domain matches) safe=y" ((($smi = Get-ScamChecklist "smishing") | Where-Object { $_.Id -eq "S3" }).Good -eq 'y')

    # Level normalization boundaries
    &$ok "level 60/100 = Critical" ((ConvertTo-ScamLevel -Score 60 -Max 100) -eq "Critical")
    &$ok "level 59/100 = High"     ((ConvertTo-ScamLevel -Score 59 -Max 100) -eq "High")
    &$ok "level 40/100 = High"     ((ConvertTo-ScamLevel -Score 40 -Max 100) -eq "High")
    &$ok "level 39/100 = Medium"   ((ConvertTo-ScamLevel -Score 39 -Max 100) -eq "Medium")
    &$ok "level 15/100 = Medium"   ((ConvertTo-ScamLevel -Score 15 -Max 100) -eq "Medium")
    &$ok "level 14/100 = Low"      ((ConvertTo-ScamLevel -Score 14 -Max 100) -eq "Low")
    &$ok "level 0/100 = Low"       ((ConvertTo-ScamLevel -Score 0 -Max 100) -eq "Low")
    &$ok "level max=0 guard"       ((ConvertTo-ScamLevel -Score 5 -Max 0) -eq "Low")

    # Romance: every UNSAFE answer -> Critical; every safe answer -> Low
    $wrong = @{ R1='n'; R2='n'; R3='y'; R4='n'; R5='y' }
    $v = Start-ScamCheck -Type romance -Answers $wrong
    &$ok "romance all-unsafe = Critical" ($v.Level -eq "Critical")
    &$ok "romance score = max" ($v.Score -eq $v.MaxPoints)
    $right = @{ R1='y'; R2='y'; R3='n'; R4='y'; R5='n' }
    $v2 = Start-ScamCheck -Type romance -Answers $right
    &$ok "romance all-safe = Low" ($v2.Level -eq "Low")
    # Unknown answers score half, never zero (per-step rounding)
    $unk = @{ R1='u'; R2='u'; R3='u'; R4='u'; R5='u' }
    $v3 = Start-ScamCheck -Type romance -Answers $unk
    $expHalf = 0
    foreach ($s in (Get-ScamChecklist "romance")) { $expHalf += [math]::Round($s.W/2) }
    &$ok "romance all-unknown scores half (per-step)" ($v3.Score -eq $expHalf)
    # Mixed-polarity proof: old bug scored R3='n' as fail; now it must be safe
    $v4 = Start-ScamCheck -Type romance -Answers @{ R1='y'; R2='y'; R3='n'; R4='y'; R5='n' }
    &$ok "R3='n' (no money ask) scores 0" (($v4.Steps | Where-Object { $_.Id -eq 'R3' }).Points -eq 0)

    # Payment flags: weighted, word-boundary
    $hits = Test-PaymentRedFlag "please pay with steam cards and bitcoin urgently"
    &$ok "payment flags caught >=2" ($hits.Count -ge 2)
    $steam = $hits | Where-Object { $_.Term -eq "steam card" }
    &$ok "steam card weight 35" (($steam | Select-Object -First 1).Weight -eq 35)
    $hits2 = Test-PaymentRedFlag "see you sunday for dinner"
    &$ok "clean text no flags" ($hits2.Count -eq 0)
    $hits3 = Test-PaymentRedFlag "cryptography is fascinating"
    &$ok "word boundary: cryptography != crypto" ($hits3.Count -eq 0)
    $pr = Get-PaymentRiskScore "send bitcoin and usdt now"
    &$ok "payment risk 50 = Critical" ($pr.Level -eq "Critical" -and $pr.Total -eq 50)
    $pr2 = Get-PaymentRiskScore "zelle me the money"
    &$ok "payment risk zelle = Flagged/20" ($pr2.Total -eq 20 -and $pr2.Level -eq "Flagged")

    # Urgency + links
    $uh = Test-ScamUrgency "your account will be suspended immediately, act now"
    &$ok "urgency hits >=3" ($uh.Count -ge 3)
    $uh2 = Test-ScamUrgency "see you sunday for dinner"
    &$ok "clean text no urgency" ($uh2.Count -eq 0)
    $lk = Get-ScamLinksFromText "visit https://usps-track-package.top/claim, ok?"
    &$ok "link extracted and trimmed" ($lk.Count -eq 1 -and $lk[0] -eq "https://usps-track-package.top/claim")

    # Message triage: full playbook text -> High+; clean text -> Low
    $t1 = Start-ScamMessageTriage "URGENT: your account will be suspended immediately. Pay the fee with steam cards at https://pay-now.example/claim. Do not tell anyone."
    &$ok "triage playbook text >= High" ($t1.Level -eq "High" -or $t1.Level -eq "Critical")
    &$ok "triage signals non-empty" ($t1.Signals.Count -ge 3)
    $t2 = Start-ScamMessageTriage "see you sunday for dinner"
    &$ok "triage clean text = Low" ($t2.Level -eq "Low")

    # Guidance present at every level
    foreach ($lv in @("Low","Medium","High","Critical")) {
        &$ok "guidance $lv" ((Get-ScamGuidance "job" $lv).Length -gt 20)
    }

    # Report pack writes to an explicit out dir, hashes both files
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("bb-scamtest-" + [System.Diagnostics.Process]::GetCurrentProcess().Id)
    $pack = New-ScamReportPack -Check $v2 -Notes "hygiene test" -OutDir $tmp
    &$ok "report pack dir exists" (Test-Path $pack.Dir)
    &$ok "report pack check.json exists" (Test-Path (Join-Path $pack.Dir "check.json"))
    &$ok "report pack report.txt exists" (Test-Path (Join-Path $pack.Dir "report.txt"))
    &$ok "report pack hashes set" ($pack.CheckJsonSha256.Length -eq 64 -and $pack.ReportTxtSha256.Length -eq 64)
    try { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue } catch {}

    # Vault log must never throw when the vault is unreachable
    $threw = $false
    try { New-ScamLog -Action "hygiene" -Result ([PSCustomObject]@{Type="hygiene"; Score=0; Level="Low"}) } catch { $threw = $true }
    &$ok "vault log never throws" (-not $threw)

    $pass = ($checks | Where-Object { $_.Pass }).Count
    Write-Host "[scam] Hygiene: $pass/$($checks.Count) checks passed."
    return $checks
}

Write-Host "[scam] Falsum Scam Shield v1.1 loaded. Start-ScamCheck / Start-ScamMessageTriage / Test-PaymentRedFlag / Get-PaymentRiskScore / Test-ScamUrgency / New-ScamReportPack / Test-ScamShieldHygiene."
Write-Host "[scam] Types: $($script:ScamTypes -join ', ')"


function Block-ScammerAddress {
    <#
    .SYNOPSIS
        Block a scammer's IP or domain via Windows Firewall.
        This is the FIX — not just detection, but blocking.
    #>
    param(
        [Parameter(Mandatory)][string]$Address,
        [string]$Reason = "Scam",
        [string]$VaultPath = ""
    )
    
    $ruleName = "Falsum-ScamBlock-$($Address -replace '[^a-zA-Z0-9]','-')"
    
    try {
        # Check if already blocked
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($existing) {
            return @{ Success = $false; Message = "Already blocked: $Address" }
        }
        
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Outbound `
            -RemoteAddress $Address `
            -Action Block `
            -Profile Any `
            -Description "Falsum: Blocked scammer address $Address ($Reason)" `
            -ErrorAction Stop | Out-Null
        
        $result = @{
            Success = $true
            Message = "Blocked scammer: $Address"
            Timestamp = (Get-Date).ToString('o')
        }
        
        if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
            $result | ConvertTo-Json | Add-Content -Path $VaultPath -Encoding UTF8
        }
        
        return $result
    }
    catch {
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}
