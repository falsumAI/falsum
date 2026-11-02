<#
BLACKBOX Module 12 — TIMELINE + VAULT
SHA-384 hash-chained append-only evidence ledger. JSONL format.
Every entry links to the previous entry's hash. Tamper-evident.

Hardening (2026-10-30): process-exclusive locks on every write path so two
processes can never interleave an append; tip integrity is recomputed BEFORE
appending so a corrupt chain can never be extended; seq continuity is checked
on both append and verify; checkpoints detect tail truncation (the one attack
a hash chain alone cannot see — deleting the last N lines leaves a valid
chain); Verify-Vault retries transient torn reads instead of false-alarming;
timestamps more than a day in the future fail verification (clock-tampering
signal); Get-VaultTip/Verify-Vault tolerate blank lines; entry lookup and
type-filter helpers added for the launcher and evidence-pack builders.

Hardening (2026-10-30 ~05:27 MDT): Read-VaultLines — one retry-wrapped
reader shared by Get-VaultEntry/Find-VaultEntries/stats/csv/time lookups so
a torn read during a concurrent append can never crash a lookup; Add-VaultEntries
batch append under a single lock (one integrity check, for trap listeners and
sweeps); Restore-VaultFromPack — the Better-Way fix for what the checkpoint
detects: restores a truncated/altered ledger from an exported pack only after
verifying the pack's manifest hash, chain, and checkpoint, then verifies the
restored vault before returning; Find-VaultEntriesByTime UTC-window lookup;
Get-VaultStats health overview (counts, per-type table, first/last UTC,
ledger size); Export-VaultCsv flat index export for spreadsheet handoff.

Hardening v1.2 (2026-10-30 ~06:37 MDT): Verify-Vault now also catches
timestamp REGRESSION (>1 day older than the previous entry) — clock rollback
or a recomputed chain; threshold mirrors the future-timestamp check so
legit NTP skew can never false-fail. New Test-VaultHygiene offline battery
(12 checks: genesis, append, batch, clean verify, altered entry caught at
exact index, tip-localization, corrupt-tip refusal, truncation invisibility
vs checkpoint, restore-from-pack round trip, forged-future catch, regression
catch). NOTE: the $add-scriptblock result pattern used by sibling hygiene
functions is scope-broken under & (child scope swallows +=) — this battery
captures scriptblock OUTPUT instead, which is scope-safe.

Hardening v1.3 (2026-10-30): NEW Read-VaultEntries shared parser (one parse
path for every lookup — Strict mode throws the exact line number instead of
"could not read/parse"); Verify-Vault now FAILS non-conforming timestamps
(pure Test-VaultTimestampFormat, ISO-8601 UTC only — every entry the module
writes conforms; a hand-forged timestamp format is a forgery signal).
REAL FIX: the checkpoint file itself was unprotected — an attacker truncating
the ledger could just rewrite CHECKPOINT.json to match; New-VaultCheckpoint
now writes CHECKPOINT.json.SHA256 beside it and Test-VaultCheckpoint rejects
a rewritten checkpoint FIRST (sweep/backup-shield MANIFEST-HASH pattern).
NEW Clear-VaultTornTail: the Better-Way fix for the #1 real-world ledger
failure (a crash mid-append leaves a partial last line) — backs up the ledger,
drops only the trailing unparseable lines, re-verifies, and REFUSES mid-chain
corruption (that one is Restore-VaultFromPack, not truncation).
NEW Test-CheckpointFreshness pure predicate (checkpoint 10k entries behind =
stale — a checkpoint that old is not a safety net). Export-VaultCsv writes a
.SHA256 sidecar. All lookup paths route through Read-VaultEntries.

Dot-source:
  . .\Falsum-Vault.ps1

Hardening v1.4 (2026-10-30 ~13:35 MDT): REAL FIX - New-VaultCheckpoint and
Export-EvidencePack had a check-then-act race: Verify-Vault, Get-VaultTip,
and Get-FileHash/Copy-Item ran as separate UNLOCKED reads, so a concurrent
append (trap listeners append rapidly) could land between them and leave a
checkpoint whose ledgerSha256/entries/tip describe three different ledger
states, or a pack whose manifest disagrees with its ledger copy. Both now
take the exclusive lock ONCE, snapshot the raw ledger bytes, verify the
chain FROM THE SNAPSHOT (new Test-VaultChainFromLines - the core loop
extracted; Verify-Vault is now a thin retry wrapper over it), and hash/copy
from the same bytes; the checkpoint is internally consistent by
construction. REAL FIX - checkpoint and seal are now written atomically
(new Write-VaultFileAtomic: temp file + rename), so a crash mid-write can
never leave a half CHECKPOINT.json. REAL FIX - two modules' vault logging
was silently broken: 06-vuln-check and 07-php-shield called Add-VaultEntry
with a (-Category, -Summary, -DataHash) signature that does not exist
(those names describe a draft API that was never shipped); the parameter
binding threw inside try/catch, so the intent "vault-logged" never happened
and the user only ever saw "vault log skipped". Both call sites corrected
to the real (-vault, -type, -data) contract with a repo-relative vault dir.
REAL FIX - launcher self-test used if (Test-VaultTipIntegrity ...) on the
verdict OBJECT (always truthy - the same bug class the v1.3 launcher fix
caught in Show-VaultStatus); it now checks .valid. NEW entry-type taxonomy
guard: Get-VaultEntryTypeTable lists every type modules actually log;
Test-VaultEntryType classifies known/unknown; Add-VaultEntry/Add-VaultEntries
Write-Warning on unknown types (a typo'd type silently forks the taxonomy
and Find-VaultEntries misses it - warning, never refusal; the vault stays
extensible).
#>

function Get-Sha384HexV {
    param([Parameter(Mandatory=$true)][string]$text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $h = [System.Security.Cryptography.SHA384]::Create()
    $hash = $h.ComputeHash($bytes)
    $h.Dispose()
    return -join ($hash | ForEach-Object { $_.ToString("x2") })
}

function Get-Sha256HexV {
    param([Parameter(Mandatory=$true)][string]$text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $h = [System.Security.Cryptography.SHA256]::Create()
    $hash = $h.ComputeHash($bytes)
    $h.Dispose()
    return -join ($hash | ForEach-Object { $_.ToString("x2") })
}

function Get-Utf8NoBom {
    return (New-Object System.Text.UTF8Encoding($false))
}

function Read-VaultLines {
    # Single shared reader with retry: a concurrent append can tear a read.
    # Every lookup/export path routes through this so failures are
    # transient-retry, never crash.
    param([Parameter(Mandatory=$true)][string]$ledger)
    $attempt = 0
    $lastError = $null
    while ($attempt -lt 3) {
        $attempt++
        try {
            return [System.IO.File]::ReadAllLines($ledger)
        } catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Milliseconds 250
        }
    }
    throw "Could not read vault ledger after 3 attempts: $ledger ($lastError)"
}

function Read-VaultEntries {
    # One shared parse path for every lookup. Skips blank lines.
    # -Strict: throws on the first unparseable line with its exact line
    # number, so Verify-Vault can localize corruption instead of returning
    # an ambiguous "could not read/parse" after retries.
    param(
        [Parameter(Mandatory=$true)][string]$ledger,
        [switch]$Strict
    )
    $out = @()
    $lineNo = 0
    foreach ($raw in (Read-VaultLines $ledger)) {
        $lineNo++
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        try {
            $out += ,($raw | ConvertFrom-Json)
        } catch {
            if ($Strict) { throw "Unparseable ledger line $lineNo`: $($_.Exception.Message)" }
        }
    }
    return $out
}

function Write-VaultFileAtomic {
    # Atomic file write: write to a temp file in the same directory, then
    # rename over the target. A crash mid-write leaves the OLD file intact
    # (plus an orphaned .tmp, never a half-written target). Used for the
    # checkpoint and its seal: a half-written CHECKPOINT.json is worse than
    # none, because its seal would then disagree and the checkpoint would
    # refuse to verify.
    param(
        [Parameter(Mandatory=$true)][string]$path,
        [Parameter(Mandatory=$true)][string]$text
    )
    $dir = Split-Path $path -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $tmp = "$path.tmp-" + [Guid]::NewGuid().ToString("N")
    try {
        [System.IO.File]::WriteAllText($tmp, $text, (Get-Utf8NoBom))
        Move-Item -Path $tmp -Destination $path -Force
    } catch {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        throw
    }
}

function Get-VaultEntryTypeTable {
    # Every entry type the shipped modules actually log, collected from the
    # real -type arguments across the repo (2026-10-30). The table is a
    # typo-guard, not a gate: unknown types are allowed but WARNED about,
    # because a typo'd type ("trapp-event") silently forks the taxonomy and
    # Find-VaultEntries("trap-event") misses it forever.
    $types = @(
        'genesis',            # New-Vault
        'osint-query',        # 04-osint-attribution (New-OsintLog)
        'attribution-report', # 04-osint-attribution
        'people-track',       # 05-people-track
        'username-hit',       # 05-people-track
        'vulncheck',          # 06-vuln-check (Export-VulnReport)
        'phpshield',          # 07-php-shield (Write-PhpShieldVaultLog)
        'breach-step',        # 08-breach-cleaner
        'broker-optout',      # 09-broker-eradicator
        'trap-event',         # 10-trap-network
        'trap-block',         # 10-trap-network (New-TrapBlock)
        'trap-report',        # 10-trap-network (Export-TrapReport)
        'active-defense',     # 11-active-defense (New-ActiveDefenseVaultLog)
        'bounty-activity',    # 14-bugbounty
        'proxy-export',       # 15-web-proxy
        'scam-shield',        # 18-scam-shield
        'backup-run',         # 20-backup-shield (New-BackupVaultLog)
        'fraud-pack',         # 23-fraud-pack
        'evidence-sweep',     # 01-evidence-sweep
        'packet-capture',     # 02-packet-witness
        'netscan-run',        # 03-netscan
        'mail-scan',          # 16-mail-shield
        'chat-session',       # 13-native-chat
        'test',               # self-test batteries
        'selftest'            # launcher self-test
    )
    return $types
}

function Test-VaultEntryType {
    # Pure predicate: is this type in the shipped taxonomy? Unknown is not
    # a refusal - the vault is extensible infrastructure - but callers WARN
    # so a typo doesn't silently fork the taxonomy.
    param([Parameter(Mandatory=$true)][string]$type)
    $known = Get-VaultEntryTypeTable
    $hit = @($known | Where-Object { $_ -eq $type }).Count -gt 0
    return [pscustomobject]@{ type = $type; known = $hit }
}

function Test-VaultChainFromLines {
    # The chain-verification core, extracted from Verify-Vault so callers
    # that already hold the exclusive lock (New-VaultCheckpoint,
    # Export-EvidencePack) can verify FROM A SNAPSHOT instead of re-reading
    # the path unlocked. $lines: non-blank ledger lines (genesis first).
    # Returns the same verdict shape as Verify-Vault plus the tip entry, so
    # the checkpoint/export can hash the same bytes they verified.
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][array]$lines
    )
    $prev = "GENESIS"
    $prevUtc = $null
    $expectedSeq = 0
    $count = 0
    $tip = $null
    $nowUtc = (Get-Date).ToUniversalTime()
    foreach ($raw in $lines) {
        $lineNo = $count + 1
        try {
            $e = $raw | ConvertFrom-Json
        } catch {
            return [pscustomobject]@{ valid = $false; badIndex = -1; reason = "unparseable ledger line ${lineNo}: $($_.Exception.Message)"; entries = $count; tip = $null }
        }
        if ($e.seq -ne $expectedSeq) {
            return [pscustomobject]@{ valid = $false; badIndex = $count; reason = "sequence gap: expected seq $expectedSeq, found $($e.seq) - entries removed"; entries = $count; tip = $null }
        }
        if ($e.prev -ne $prev) {
            return [pscustomobject]@{ valid = $false; badIndex = $count; reason = "chain break at seq $($e.seq)"; entries = $count; tip = $null }
        }
        $check = ($e | Select-Object seq, utc, type, prev, data | ConvertTo-Json -Depth 10 -Compress)
        if ((Get-Sha384HexV $check) -ne $e.sha384) {
            return [pscustomobject]@{ valid = $false; badIndex = $count; reason = "hash mismatch at seq $($e.seq) - entry altered"; entries = $count; tip = $null }
        }
        if (-not (Test-VaultTimestampFormat $e.utc)) {
            return [pscustomobject]@{ valid = $false; badIndex = $count; reason = "non-conforming timestamp at seq $($e.seq) ('$($e.utc)' is not ISO-8601 UTC) - hand-forged or foreign entry"; entries = $count; tip = $null }
        }
        try {
            $tsUtc = [DateTime]::Parse($e.utc).ToUniversalTime()
            if ($tsUtc -gt $nowUtc.AddDays(1)) {
                return [pscustomobject]@{ valid = $false; badIndex = $count; reason = "timestamp at seq $($e.seq) is more than a day in the future - clock tampering suspected"; entries = $count; tip = $null }
            }
            if ($null -ne $prevUtc -and $tsUtc -lt $prevUtc.AddDays(-1)) {
                return [pscustomobject]@{ valid = $false; badIndex = $count; reason = "timestamp regression at seq $($e.seq) ($($e.utc) is more than a day older than the previous entry) - clock rollback or a recomputed chain suspected"; entries = $count; tip = $null }
            }
            $prevUtc = $tsUtc
        } catch {
            return [pscustomobject]@{ valid = $false; badIndex = $count; reason = "unparseable timestamp at seq $($e.seq)"; entries = $count; tip = $null }
        }
        $prev = $e.sha384
        $tip = $e
        $expectedSeq++
        $count++
    }
    return [pscustomobject]@{ valid = $true; badIndex = -1; reason = ""; entries = $count; tip = $tip }
}

function Test-VaultTimestampFormat {
    # Pure predicate: every entry this module writes stamps ISO-8601 UTC via
    # ToString("o") (e.g. 2026-10-30T15:53:10.1234567Z). A ledger entry with
    # any other shape was not written by this module — hand-forged or foreign.
    param([string]$utc)
    if ([string]::IsNullOrWhiteSpace($utc)) { return $false }
    return $utc -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$'
}

function Test-CheckpointFreshness {
    # Pure predicate: how far has the ledger moved past the checkpoint? A
    # checkpoint that old is not a safety net — restoring from it would
    # silently lose everything written since.
    param(
        [Parameter(Mandatory=$true)][int]$CheckpointSeq,
        [Parameter(Mandatory=$true)][int]$TipSeq,
        [int]$MaxEntriesSinceCheckpoint = 10000
    )
    $behind = $TipSeq - $CheckpointSeq
    if ($behind -lt 0) { $behind = 0 }
    return [pscustomobject]@{
        behind = $behind
        stale  = ($behind -gt $MaxEntriesSinceCheckpoint)
    }
}

function Open-VaultStream {
    # Exclusive lock: FileShare.None. A second process blocks here until the
    # first releases. Callers MUST close the stream in a finally block.
    param([Parameter(Mandatory=$true)][string]$ledger)
    try {
        return [System.IO.File]::Open($ledger,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
    } catch {
        throw "Vault is locked by another process or inaccessible: $ledger. Retry shortly. $_"
    }
}

function New-Vault {
    param([Parameter(Mandatory=$true)][string]$path)
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path | Out-Null }
    $ledger = Join-Path $path "ledger.jsonl"
    $fs = Open-VaultStream $ledger
    try {
        $sr = New-Object System.IO.StreamReader($fs, (Get-Utf8NoBom), $true, 4096, $true)
        $content = $sr.ReadToEnd()
        $sr.Dispose()
        if ([string]::IsNullOrWhiteSpace($content)) {
            $genesis = [pscustomobject]@{
                seq    = 0
                utc    = (Get-Date).ToUniversalTime().ToString("o")
                type   = "genesis"
                sha384 = ""
                prev   = "GENESIS"
                data   = @{ note = "BLACKBOX evidence vault created" }
            }
            $check = ($genesis | Select-Object seq, utc, type, prev, data | ConvertTo-Json -Depth 10 -Compress)
            $genesis.sha384 = Get-Sha384HexV $check
            $line = ($genesis | ConvertTo-Json -Depth 10 -Compress)
            $fs.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
            $fs.SetLength(0)
            $sw = New-Object System.IO.StreamWriter($fs, (Get-Utf8NoBom), 4096, $true)
            $sw.WriteLine($line)
            $sw.Flush()
            $sw.Dispose()
            Write-Host "Vault created: $ledger (genesis seq 0)"
        }
    } finally {
        $fs.Close()
    }
    return [pscustomobject]@{ path = $path; ledger = $ledger }
}

function Get-VaultTip {
    param([Parameter(Mandatory=$true)]$vault)
    $attempt = 0
    while ($attempt -lt 3) {
        $attempt++
        try {
            $lines = [System.IO.File]::ReadAllLines($vault.ledger)
            for ($i = $lines.Count - 1; $i -ge 0; $i--) {
                if (-not [string]::IsNullOrWhiteSpace($lines[$i])) {
                    return ($lines[$i] | ConvertFrom-Json)
                }
            }
            return $null
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    throw "Could not read vault tip after 3 attempts: $($vault.ledger)"
}

function Test-VaultTipIntegrity {
    # Recomputes the tip entry's hash. Refuses blind trust: if the tip is
    # corrupt, nothing may be appended on top of it.
    param([Parameter(Mandatory=$true)]$vault)
    $tip = Get-VaultTip $vault
    if ($null -eq $tip) {
        return [pscustomobject]@{ valid = $false; reason = "ledger is empty — no tip" }
    }
    $check = ($tip | Select-Object seq, utc, type, prev, data | ConvertTo-Json -Depth 10 -Compress)
    if ((Get-Sha384HexV $check) -ne $tip.sha384) {
        return [pscustomobject]@{ valid = $false; reason = "tip hash mismatch at seq $($tip.seq) — tip entry altered" }
    }
    return [pscustomobject]@{ valid = $true; reason = ""; seq = $tip.seq }
}

function Add-VaultEntry {
    param(
        [Parameter(Mandatory=$true)]$vault,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$type,
        [Parameter(Mandatory=$true)]$data
    )
    $typeVerdict = Test-VaultEntryType -type $type
    if (-not $typeVerdict.known) {
        Write-Warning "Unknown vault entry type '$type' - not in Get-VaultEntryTypeTable. Typo? Find-VaultEntries('$type') is how this gets queried later."
    }
    $fs = Open-VaultStream $vault.ledger
    try {
        $sr = New-Object System.IO.StreamReader($fs, (Get-Utf8NoBom), $true, 4096, $true)
        $content = $sr.ReadToEnd()
        $sr.Dispose()
        $lines = @($content -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $seq = 0; $prev = "GENESIS"
        if ($lines.Count -gt 0) {
            $tip = $lines[$lines.Count - 1] | ConvertFrom-Json
            # Never extend a corrupt chain.
            $tipCheck = ($tip | Select-Object seq, utc, type, prev, data | ConvertTo-Json -Depth 10 -Compress)
            if ((Get-Sha384HexV $tipCheck) -ne $tip.sha384) {
                throw "Vault tip at seq $($tip.seq) fails integrity check — refusing append. Restore from a checkpoint first."
            }
            if ($tip.seq -ne ($lines.Count - 1)) {
                throw "Vault sequence gap: expected tip seq $($lines.Count - 1), found $($tip.seq) — refusing append."
            }
            $seq = $tip.seq + 1
            $prev = $tip.sha384
        }
        $entry = [pscustomobject]@{
            seq    = $seq
            utc    = (Get-Date).ToUniversalTime().ToString("o")
            type   = $type
            sha384 = ""
            prev   = $prev
            data   = $data
        }
        $check = ($entry | Select-Object seq, utc, type, prev, data | ConvertTo-Json -Depth 10 -Compress)
        $entry.sha384 = Get-Sha384HexV $check
        $line = ($entry | ConvertTo-Json -Depth 10 -Compress)
        $fs.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
        $sw = New-Object System.IO.StreamWriter($fs, (Get-Utf8NoBom), 4096, $true)
        $sw.WriteLine($line)
        $sw.Flush()
        $sw.Dispose()
    } finally {
        $fs.Close()
    }
    return $entry
}

function Add-VaultEntries {
    # Batch append under a single lock. One integrity check up front instead
    # of N. For trap listeners and sweep runs that append rapidly.
    # $entries: array of objects with .type (string) and .data (any).
    param(
        [Parameter(Mandatory=$true)]$vault,
        [Parameter(Mandatory=$true)][array]$entries
    )
    if ($entries.Count -eq 0) { return @() }
    $added = @()
    $fs = Open-VaultStream $vault.ledger
    try {
        $sr = New-Object System.IO.StreamReader($fs, (Get-Utf8NoBom), $true, 4096, $true)
        $content = $sr.ReadToEnd()
        $sr.Dispose()
        $lines = @($content -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $seq = 0; $prev = "GENESIS"
        if ($lines.Count -gt 0) {
            $tip = $lines[$lines.Count - 1] | ConvertFrom-Json
            $tipCheck = ($tip | Select-Object seq, utc, type, prev, data | ConvertTo-Json -Depth 10 -Compress)
            if ((Get-Sha384HexV $tipCheck) -ne $tip.sha384) {
                throw "Vault tip at seq $($tip.seq) fails integrity check — refusing append. Restore from a checkpoint first."
            }
            if ($tip.seq -ne ($lines.Count - 1)) {
                throw "Vault sequence gap: expected tip seq $($lines.Count - 1), found $($tip.seq) — refusing append."
            }
            $seq = $tip.seq + 1
            $prev = $tip.sha384
        }
        $fs.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
        $sw = New-Object System.IO.StreamWriter($fs, (Get-Utf8NoBom), 4096, $true)
        try {
            foreach ($item in $entries) {
                if ([string]::IsNullOrWhiteSpace($item.type)) {
                    throw "Batch entry is missing a type — refusing append."
                }
                $tv = Test-VaultEntryType -type $item.type
                if (-not $tv.known) {
                    Write-Warning "Unknown vault entry type '$($item.type)' - not in Get-VaultEntryTypeTable. Typo?"
                }
                $entry = [pscustomobject]@{
                    seq    = $seq
                    utc    = (Get-Date).ToUniversalTime().ToString("o")
                    type   = $item.type
                    sha384 = ""
                    prev   = $prev
                    data   = $item.data
                }
                $check = ($entry | Select-Object seq, utc, type, prev, data | ConvertTo-Json -Depth 10 -Compress)
                $entry.sha384 = Get-Sha384HexV $check
                $sw.WriteLine(($entry | ConvertTo-Json -Depth 10 -Compress))
                $added += $entry
                $seq++
                $prev = $entry.sha384
            }
            $sw.Flush()
        } finally {
            $sw.Dispose()
        }
    } finally {
        $fs.Close()
    }
    Write-Host "Appended $($added.Count) entries (seq $($added[0].seq)..$($added[$added.Count-1].seq))."
    return $added
}

function Verify-Vault {
    # Thin retry wrapper over Test-VaultChainFromLines. Without the lock, a
    # concurrent append can tear a read, so reads retry; the verification
    # itself always runs on one complete snapshot of lines. A permanently
    # corrupt line is deterministic - it fails the same way every time, and
    # Test-VaultChainFromLines localizes it by line number.
    param([Parameter(Mandatory=$true)]$vault)
    $attempt = 0
    $lastError = $null
    while ($attempt -lt 3) {
        $attempt++
        try {
            $lines = @([System.IO.File]::ReadAllLines($vault.ledger) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        } catch {
            # Transient torn read (a concurrent append mid-read): retry,
            # don't false-alarm.
            $lastError = $_.Exception.Message
            Start-Sleep -Milliseconds 250
            continue
        }
        return (Test-VaultChainFromLines -lines $lines)
    }
    return [pscustomobject]@{ valid = $false; badIndex = -1; reason = "could not read ledger after 3 attempts (possible concurrent append or corruption): $lastError"; entries = 0; tip = $null }
}


function Get-VaultEntry {
    # Lookup by sequence number. Returns $null when absent.
    param(
        [Parameter(Mandatory=$true)]$vault,
        [Parameter(Mandatory=$true)][int]$seq
    )
    foreach ($e in (Read-VaultEntries -ledger $vault.ledger)) {
        if ($e.seq -eq $seq) { return $e }
    }
    return $null
}

function Find-VaultEntries {
    # All entries of one type (e.g. "trap-event", "osint-query").
    param(
        [Parameter(Mandatory=$true)]$vault,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$type
    )
    $out = @()
    foreach ($e in (Read-VaultEntries -ledger $vault.ledger)) {
        if ($e.type -eq $type) { $out += $e }
    }
    return $out
}

function Find-VaultEntriesByTime {
    # Time-window lookup: evidence queries are almost always "what happened
    # between X and Y". UTC window, inclusive.
    param(
        [Parameter(Mandatory=$true)]$vault,
        [Parameter(Mandatory=$true)][DateTime]$Since,
        [Parameter(Mandatory=$true)][DateTime]$Until,
        [string]$Type
    )
    $sinceUtc = $Since.ToUniversalTime()
    $untilUtc = $Until.ToUniversalTime()
    $out = @()
    foreach ($e in (Read-VaultEntries -ledger $vault.ledger)) {
        if ($Type -and $e.type -ne $Type) { continue }
        try { $ts = [DateTime]::Parse($e.utc).ToUniversalTime() } catch { continue }
        if ($ts -ge $sinceUtc -and $ts -le $untilUtc) { $out += $e }
    }
    return $out
}

function Get-VaultStats {
    # Health overview for the launcher and evidence-pack builders.
    param([Parameter(Mandatory=$true)]$vault)
    $typeCounts = @{}
    $first = $null; $last = $null; $count = 0
    foreach ($e in (Read-VaultEntries -ledger $vault.ledger)) {
        $count++
        if ($typeCounts.ContainsKey($e.type)) { $typeCounts[$e.type]++ } else { $typeCounts[$e.type] = 1 }
        try { $ts = [DateTime]::Parse($e.utc) } catch { continue }
        if ($null -eq $first -or $ts -lt $first) { $first = $ts }
        if ($null -eq $last -or $ts -gt $last) { $last = $ts }
    }
    $ledgerSize = 0
    if (Test-Path $vault.ledger) { $ledgerSize = (Get-Item $vault.ledger).Length }
    return [pscustomobject]@{
        entries    = $count
        types      = $typeCounts
        firstUtc   = $first
        lastUtc    = $last
        ledgerSize = $ledgerSize
        tipSeq     = if ($count -gt 0) { $count - 1 } else { -1 }
    }
}

function Export-VaultCsv {
    # Flat CSV (seq,utc,type,sha384,prev) for spreadsheet handoff.
    # Full JSONL ships separately; this is the human-scannable index.
    param(
        [Parameter(Mandatory=$true)]$vault,
        [Parameter(Mandatory=$true)][string]$outPath
    )
    $dir = Split-Path $outPath -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $sw = New-Object System.IO.StreamWriter($outPath, $false, (Get-Utf8NoBom))
    try {
        $sw.WriteLine("seq,utc,type,sha384,prev")
        foreach ($e in (Read-VaultEntries -ledger $vault.ledger)) {
            $type = ([string]$e.type) -replace '"', '""'
            $sw.WriteLine("$($e.seq),""$($e.utc)"",""$type"",$($e.sha384),$($e.prev)")
        }
    } finally {
        $sw.Close()
    }
    $sidecar = "$outPath.SHA256"
    [System.IO.File]::WriteAllText($sidecar, (Get-FileHash $outPath -Algorithm SHA256).Hash, (Get-Utf8NoBom))
    Write-Host "CSV exported: $outPath (SHA-256 sidecar: $sidecar)"
    return $outPath
}

function New-VaultCheckpoint {
    # Writes a signed checkpoint (seq + tip hash + ledger SHA-256). Restoring
    # the ledger later re-verifies against it: Test-VaultCheckpoint catches
    # tail truncation, the one attack a bare hash chain cannot see.
    #
    # The whole checkpoint is built from ONE snapshot taken under the
    # exclusive lock: bytes read, chain verified from those bytes, hashes
    # computed from those bytes. The old code did Verify-Vault, Get-VaultTip,
    # and Get-FileHash as three separate unlocked reads - a concurrent append
    # landing between them produced a checkpoint whose entries/tip/ledgerSha256
    # described three different ledger states.
    param(
        [Parameter(Mandatory=$true)]$vault,
        [Parameter(Mandatory=$true)][string]$checkpointPath
    )
    $fs = Open-VaultStream $vault.ledger
    try {
        $sr = New-Object System.IO.StreamReader($fs, (Get-Utf8NoBom), $true, 4096, $true)
        $rawBytes = [System.IO.MemoryStream]::new()
        $fs.CopyTo($rawBytes)
        $sr.Dispose()
        $bytes = $rawBytes.ToArray()
        $rawBytes.Dispose()
    } finally {
        $fs.Close()
    }
    $text = (Get-Utf8NoBom).GetString($bytes)
    $snapLines = @($text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $v = Test-VaultChainFromLines -lines $snapLines
    if (-not $v.valid) { throw "Vault failed verification: $($v.reason). Checkpoint NOT written." }
    if ($null -eq $v.tip) { throw "Ledger is empty - nothing to checkpoint." }
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { $ledgerSha256 = -join ($h.ComputeHash($bytes) | ForEach-Object { $_.ToString("X2") }) }
    finally { $h.Dispose() }
    $cp = [pscustomobject]@{
        checkpointUtc = (Get-Date).ToUniversalTime().ToString("o")
        seq           = $v.tip.seq
        tipSha384     = $v.tip.sha384
        entries       = $v.entries
        ledgerSha256  = $ledgerSha256
    }
    $cpJson = ($cp | ConvertTo-Json -Depth 5)
    # Atomic writes: a crash mid-write must leave the OLD checkpoint intact,
    # never a half-written CHECKPOINT.json whose seal then refuses to verify.
    Write-VaultFileAtomic -path $checkpointPath -text $cpJson
    # The checkpoint is the trust anchor for truncation detection - an
    # attacker who rewrites CHECKPOINT.json to match a truncated ledger
    # defeats the checkpoint entirely. The .SHA256 seal (sweep v1.2 /
    # backup-shield v1.1 pattern) makes that rewrite detectable.
    $sealHash = (Get-FileHash $checkpointPath -Algorithm SHA256).Hash
    Write-VaultFileAtomic -path "$checkpointPath.SHA256" -text $sealHash
    Write-Host "Checkpoint written: seq $($v.tip.seq), $($v.entries) entries (sealed, atomic)."
    return $cp
}


function Test-VaultCheckpoint {
    param(
        [Parameter(Mandatory=$true)]$vault,
        [Parameter(Mandatory=$true)][string]$checkpointPath
    )
    if (-not (Test-Path $checkpointPath)) {
        return [pscustomobject]@{ valid = $false; reason = "checkpoint file not found: $checkpointPath" }
    }
    # Seal check first: a rewritten checkpoint that matches a truncated
    # ledger is the attack this seal exists to catch.
    $sealPath = "$checkpointPath.SHA256"
    if (Test-Path $sealPath) {
        $want = ([System.IO.File]::ReadAllText($sealPath)).Trim()
        $got = (Get-FileHash $checkpointPath -Algorithm SHA256).Hash
        if ($want -ne $got) {
            return [pscustomobject]@{ valid = $false; reason = "checkpoint seal mismatch — CHECKPOINT.json was rewritten after sealing. Do NOT trust this checkpoint; restore from an evidence pack." }
        }
    }
    $cp = Get-Content $checkpointPath -Raw | ConvertFrom-Json
    $tip = Get-VaultTip $vault
    if ($null -eq $tip) {
        return [pscustomobject]@{ valid = $false; reason = "ledger is empty — checkpoint seq $($cp.seq) missing" }
    }
    if ($tip.seq -lt $cp.seq) {
        return [pscustomobject]@{ valid = $false; reason = "ledger is SHORTER than the checkpoint (tip seq $($tip.seq) < checkpoint seq $($cp.seq)) — tail truncated" }
    }
    $entry = Get-VaultEntry $vault -Seq $cp.seq
    if ($null -eq $entry) {
        return [pscustomobject]@{ valid = $false; reason = "checkpoint seq $($cp.seq) missing from ledger — entries removed below the checkpoint" }
    }
    if ($entry.sha384 -ne $cp.tipSha384) {
        return [pscustomobject]@{ valid = $false; reason = "hash mismatch at checkpoint seq $($cp.seq) — ledger altered below the checkpoint" }
    }
    $fresh = Test-CheckpointFreshness -CheckpointSeq $cp.seq -TipSeq $tip.seq
    return [pscustomobject]@{ valid = $true; reason = ""; checkpointSeq = $cp.seq; currentSeq = $tip.seq; entriesSinceCheckpoint = $fresh.behind; checkpointStale = $fresh.stale }
}

function Clear-VaultTornTail {
    # THE FIX for a crash mid-append: the last ledger line is a partial JSON
    # fragment that fails verification. This backs the ledger up, drops ONLY
    # the trailing unparseable lines, and re-verifies. Mid-chain corruption
    # (an unparseable line with good lines after it) is NOT a torn tail —
    # that refuses and points at Restore-VaultFromPack. ConfirmImpact=High
    # because it rewrites the ledger; the backup is the rollback.
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory=$true)]$vault)
    $v = Verify-Vault $vault
    if ($v.valid) {
        return [pscustomobject]@{ repaired = $false; removedLines = 0; backupPath = $null; reason = "ledger verifies clean — nothing to repair" }
    }
    if ($v.reason -notmatch 'corrupt ledger line|Unparseable') {
        return [pscustomobject]@{ repaired = $false; removedLines = 0; backupPath = $null; reason = "not a torn-tail case ($($v.reason)) — use Restore-VaultFromPack" }
    }
    $lines = Read-VaultLines $vault.ledger
    $keepTo = $lines.Count
    while ($keepTo -gt 0) {
        $l = $lines[$keepTo - 1]
        if ([string]::IsNullOrWhiteSpace($l)) { $keepTo--; continue }
        try { $l | ConvertFrom-Json | Out-Null; break } catch { $keepTo-- }
    }
    if ($keepTo -le 0) {
        return [pscustomobject]@{ repaired = $false; removedLines = 0; backupPath = $null; reason = "no parseable ledger lines remain — ledger is not recoverable by truncation; use Restore-VaultFromPack" }
    }
    if ($keepTo -eq $lines.Count) {
        return [pscustomobject]@{ repaired = $false; removedLines = 0; backupPath = $null; reason = "tail parses — corruption is mid-chain, not a torn tail; use Restore-VaultFromPack" }
    }
    # Mid-chain sanity: everything we keep must parse.
    for ($i = 0; $i -lt $keepTo; $i++) {
        try { $lines[$i] | ConvertFrom-Json | Out-Null } catch {
            return [pscustomobject]@{ repaired = $false; removedLines = 0; backupPath = $null; reason = "unparseable line at kept index $i — mid-chain corruption, not a torn tail; use Restore-VaultFromPack" }
        }
    }
    $removed = $lines.Count - $keepTo
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $backupPath = "$($vault.ledger).bak-$stamp"
    if ($PSCmdlet.ShouldProcess($vault.ledger, "remove $removed torn trailing line(s), backup to $backupPath")) {
        Copy-Item $vault.ledger $backupPath
        [System.IO.File]::WriteAllLines($vault.ledger, $lines[0..($keepTo - 1)], (Get-Utf8NoBom))
        $v2 = Verify-Vault $vault
        if (-not $v2.valid) {
            throw "Repaired ledger failed verification: $($v2.reason). Backup preserved at $backupPath."
        }
        Write-Host "Torn tail repaired: removed $removed line(s), ledger verifies clean ($($v2.entries) entries). Backup: $backupPath"
    }
    return [pscustomobject]@{ repaired = $true; removedLines = $removed; backupPath = $backupPath; reason = "" }
}

function Export-EvidencePack {
    # Packs the ledger for handoff. The ledger is snapshotted ONCE under the
    # exclusive lock and the chain is verified from that snapshot; the pack
    # copy and the manifest hash are then written from the same bytes. The
    # old code did Verify-Vault, Copy-Item, and Get-FileHash as three
    # separate unlocked reads - a concurrent append landing between them
    # produced a manifest whose ledgerSha256 described different bytes than
    # the packed ledger.jsonl.
    param(
        [Parameter(Mandatory=$true)]$vault,
        [Parameter(Mandatory=$true)][string]$outPath,
        [string]$CheckpointPath
    )
    $fs = Open-VaultStream $vault.ledger
    try {
        $rawBytes = [System.IO.MemoryStream]::new()
        $fs.CopyTo($rawBytes)
        $bytes = $rawBytes.ToArray()
        $rawBytes.Dispose()
    } finally {
        $fs.Close()
    }
    $text = (Get-Utf8NoBom).GetString($bytes)
    $snapLines = @($text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $v = Test-VaultChainFromLines -lines $snapLines
    if (-not $v.valid) { throw "Vault failed verification: $($v.reason). Pack NOT exported." }
    if ($null -eq $v.tip) { throw "Ledger is empty - nothing to export." }
    if ($CheckpointPath) {
        $cpTest = Test-VaultCheckpoint $vault $CheckpointPath
        if (-not $cpTest.valid) { throw "Checkpoint failed: $($cpTest.reason). Pack NOT exported." }
    }
    if (-not (Test-Path $outPath)) { New-Item -ItemType Directory -Path $outPath | Out-Null }
    # The packed ledger is the verified snapshot, not a second unlocked read.
    [System.IO.File]::WriteAllBytes((Join-Path $outPath "ledger.jsonl"), $bytes)
    if ($CheckpointPath -and (Test-Path $CheckpointPath)) {
        Copy-Item $CheckpointPath (Join-Path $outPath "CHECKPOINT.json")
        $sealSrc = "$CheckpointPath.SHA256"
        if (Test-Path $sealSrc) { Copy-Item $sealSrc (Join-Path $outPath "CHECKPOINT.json.SHA256") }
    }
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { $ledgerSha256 = -join ($h.ComputeHash($bytes) | ForEach-Object { $_.ToString("X2") }) }
    finally { $h.Dispose() }
    $manifest = [pscustomobject]@{
        exportedUtc  = (Get-Date).ToUniversalTime().ToString("o")
        entries      = $v.entries
        tipSeq       = $v.tip.seq
        tipSha384    = $v.tip.sha384
        ledgerSha256 = $ledgerSha256
        chainValid   = $true
        checkpointed = [bool]$CheckpointPath
    }
    Write-VaultFileAtomic -path (Join-Path $outPath "MANIFEST.json") -text ($manifest | ConvertTo-Json -Depth 5)
    $zip = $outPath.TrimEnd('\','/') + ".zip"
    if (Test-Path $zip) { Remove-Item $zip }
    Compress-Archive -Path (Join-Path $outPath "*") -DestinationPath $zip
    return [pscustomobject]@{ pack = $zip; entries = $v.entries; manifest = $manifest }
}


function Restore-VaultFromPack {
    # THE FIX for what the checkpoint detects. A truncated/altered ledger is
    # unrecoverable from the chain alone — you need a known-good copy. This
    # restores the ledger from an exported evidence pack, verifying the pack
    # first: zip extracts, MANIFEST.json parses, the pack ledger's SHA-256
    # matches the manifest, the pack ledger's hash chain verifies, and the
    # restored vault verifies before this function returns. Refuses to
    # restore from an unverifiable pack.
    param(
        [Parameter(Mandatory=$true)][string]$packZip,
        [Parameter(Mandatory=$true)][string]$vaultPath
    )
    if (-not (Test-Path $packZip)) { throw "Pack not found: $packZip" }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("bbrestore-" + [Guid]::NewGuid().ToString("N"))
    try {
        Expand-Archive -Path $packZip -DestinationPath $tmp
        $packLedger = Join-Path $tmp "ledger.jsonl"
        $manifestPath = Join-Path $tmp "MANIFEST.json"
        if (-not (Test-Path $packLedger)) { throw "Pack is missing ledger.jsonl — refusing restore." }
        if (-not (Test-Path $manifestPath)) { throw "Pack is missing MANIFEST.json — refusing restore." }
        $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
        $actualHash = (Get-FileHash $packLedger -Algorithm SHA256).Hash
        if ($actualHash -ne $manifest.ledgerSha256) {
            throw "Pack ledger SHA-256 ($actualHash) does not match manifest ($($manifest.ledgerSha256)) — pack tampered, refusing restore."
        }
        # Verify the pack ledger's own chain before trusting it.
        $packVault = [pscustomobject]@{ path = $tmp; ledger = $packLedger }
        $pv = Verify-Vault $packVault
        if (-not $pv.valid) { throw "Pack ledger failed chain verification: $($pv.reason) — refusing restore." }
        # Optional: pack checkpoint, if shipped. The seal check runs inside
        # Test-VaultCheckpoint before the checkpoint itself is trusted.
        $packCp = Join-Path $tmp "CHECKPOINT.json"
        if (Test-Path $packCp) {
            $cpTest = Test-VaultCheckpoint $packVault $packCp
            if (-not $cpTest.valid) { throw "Pack checkpoint failed: $($cpTest.reason) — refusing restore." }
        }
        if (-not (Test-Path $vaultPath)) { New-Item -ItemType Directory -Path $vaultPath | Out-Null }
        $target = Join-Path $vaultPath "ledger.jsonl"
        $fs = Open-VaultStream $target
        try {
            $fs.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
            $fs.SetLength(0)
            $bytes = [System.IO.File]::ReadAllBytes($packLedger)
            $fs.Write($bytes, 0, $bytes.Length)
            $fs.Flush()
        } finally {
            $fs.Close()
        }
        $restored = [pscustomobject]@{ path = $vaultPath; ledger = $target }
        $rv = Verify-Vault $restored
        if (-not $rv.valid) { throw "Restored vault failed verification: $($rv.reason)" }
        Write-Host "Vault restored from pack: $($rv.entries) entries, tip seq $($manifest.tipSeq). Verified."
        return [pscustomobject]@{
            vault      = $restored
            entries    = $rv.entries
            tipSeq     = $manifest.tipSeq
            fromPack   = $packZip
        }
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
    }
}

function Test-VaultHygiene {
    # Offline self-test battery: builds throwaway vaults in the temp dir and
    # proves the defenses the vault claims actually work — genesis, append,
    # batch, clean verify, and every tamper class: altered entry (caught at
    # the exact index), corrupt tip (refused), tail truncation (invisible to
    # the chain alone, caught by the checkpoint), restore-from-pack round
    # trip, forged-future timestamp, and timestamp regression. No network,
    # no admin, no external dependencies. Returns $true only when all
    # checks pass.
    #
    # Hardening v1.3: 39 checks: genesis, append, batch, clean verify, and every
    # tamper class: altered entry (caught at the exact index), corrupt tip
    # (refused), tail truncation (invisible to the chain alone, caught by the
    # checkpoint), restore-from-pack round trip, forged-future timestamp,
    # timestamp regression, corrupt JSON line localized by line number,
    # torn-tail repair round trip (Clear-VaultTornTail), torn-tail refusal on a
    # clean ledger and on mid-chain corruption, rewritten-checkpoint seal
    # refusal, ISO-8601 timestamp format gate, checkpoint-freshness predicate,
    # CSV SHA-256 sidecar, shared parser blank-line tolerance.
    #
    # NOTE on sibling hygiene functions: several modules collect results via
    # `$add = { ... $results += ... }` invoked with `&$add`. The call operator
    # runs in a child scope, so the `+=` writes to a child-scope copy and the
    # parent's $results stays empty — those batteries always print 0/0 and
    # always pass. This battery captures the scriptblock's OUTPUT object
    # instead ($results += &$mk ...), which is scope-safe.
    [CmdletBinding()]
    param()
    Write-Host "[*] Vault self-test (temp dirs only, no network, no admin)..." -ForegroundColor Cyan
    $results = @()
    $mk = {
        param($name, $pass, $detail)
        [pscustomobject]@{ Check = $name; Pass = [bool]$pass; Detail = "$detail" }
    }
    $newTmpVault = {
        param($tag)
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("bb-hygiene-$tag-" + [Guid]::NewGuid().ToString("N"))
        return (New-Vault -path $dir)
    }
    $craftEntry = {
        # Appends a properly-hashed entry with a CALLER-CHOSEN timestamp, in
        # the same canonical form Add-VaultEntry uses. Simulates a forged
        # clock: the hash is valid, the timeline is a lie.
        param($vault, $utc, $type)
        $tip = Get-VaultTip $vault
        $entry = [pscustomobject]@{
            seq    = $tip.seq + 1
            utc    = $utc
            type   = $type
            sha384 = ""
            prev   = $tip.sha384
            data   = @{ note = "forged-clock test entry" }
        }
        $check = ($entry | Select-Object seq, utc, type, prev, data | ConvertTo-Json -Depth 10 -Compress)
        $entry.sha384 = Get-Sha384HexV $check
        $fs = Open-VaultStream $vault.ledger
        try {
            $fs.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
            $sw = New-Object System.IO.StreamWriter($fs, (Get-Utf8NoBom), 4096, $true)
            $sw.WriteLine(($entry | ConvertTo-Json -Depth 10 -Compress))
            $sw.Flush()
            $sw.Dispose()
        } finally {
            $fs.Close()
        }
        return $entry
    }
    $rewriteEntryData = {
        # Simulates tampering: rewrites one entry's data field in the raw
        # ledger WITHOUT recomputing its hash.
        param($vault, $seq, $newNote)
        $lines = [System.IO.File]::ReadAllLines($vault.ledger)
        $hit = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ([string]::IsNullOrWhiteSpace($lines[$i])) { continue }
            $e = $lines[$i] | ConvertFrom-Json
            if ($e.seq -eq $seq) {
                $e.data.note = $newNote
                $lines[$i] = ($e | ConvertTo-Json -Depth 10 -Compress)
                $hit = $true
                break
            }
        }
        if (-not $hit) { throw "seq $seq not found for rewrite test" }
        [System.IO.File]::WriteAllLines($vault.ledger, $lines, (Get-Utf8NoBom))
    }
    $dropLastLine = {
        param($vault)
        $lines = @([System.IO.File]::ReadAllLines($vault.ledger) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($lines.Count -le 1) { throw "cannot drop the only ledger line" }
        [System.IO.File]::WriteAllLines($vault.ledger, $lines[0..($lines.Count - 2)], (Get-Utf8NoBom))
    }

    $vaults = @()
    $cpPath = $null; $packDir = $null; $packZip = $null
    try {
        # --- Vault A: build, verify, tamper ---
        $va = &$newTmpVault "a"; $vaults += $va
        $tip = Get-VaultTip $va
        $ti = Test-VaultTipIntegrity $va
        $vv = Verify-Vault $va
        $results += &$mk "genesis + clean verify" ($vv.valid -and $vv.entries -eq 1 -and $tip.seq -eq 0 -and $ti.valid) "entries=$($vv.entries) tip=$($tip.seq)"

        $e1 = Add-VaultEntry -vault $va -type "test" -data @{ note = "entry one" }
        $results += &$mk "single append links prev" ($e1.seq -eq 1 -and $e1.prev -eq $tip.sha384) "seq=$($e1.seq)"

        $batch = Add-VaultEntries -vault $va -entries @(
            @{ type = "test"; data = @{ note = "batch two" } },
            @{ type = "test"; data = @{ note = "batch three" } },
            @{ type = "test"; data = @{ note = "batch four" } }
        )
        $tipA = Get-VaultTip $va
        $results += &$mk "batch append (one lock)" ($batch.Count -eq 3 -and $batch[0].seq -eq 2 -and $batch[2].seq -eq 4 -and $tipA.seq -eq 4) "seqs $($batch[0].seq)..$($batch[2].seq)"

        $vv2 = Verify-Vault $va
        $results += &$mk "clean chain verifies" ($vv2.valid -and $vv2.entries -eq 6) "entries=$($vv2.entries)"

        &$rewriteEntryData $va 2 "attacker was here"
        $vv3 = Verify-Vault $va
        $results += &$mk "altered entry caught at exact index" (-not $vv3.valid -and $vv3.badIndex -eq 2 -and $vv3.reason -match "hash mismatch") "badIndex=$($vv3.badIndex)"

        $ti2 = Test-VaultTipIntegrity $va
        $results += &$mk "tip still valid after mid-chain tamper" ($ti2.valid) "tip seq=$($ti2.seq)"

        &$rewriteEntryData $va 5 "tip rewritten"
        $ti3 = Test-VaultTipIntegrity $va
        $results += &$mk "corrupt tip refused" (-not $ti3.valid -and $ti3.reason -match "tip hash mismatch") $ti3.reason

        # --- Vault B: checkpoint catches truncation; restore repairs it ---
        $vb = &$newTmpVault "b"; $vaults += $vb
        [void](Add-VaultEntry -vault $vb -type "test" -data @{ note = "pre-checkpoint" })
        $cpPath = Join-Path ([System.IO.Path]::GetTempPath()) ("bb-hygiene-cp-" + [Guid]::NewGuid().ToString("N") + ".json")
        $packDir = Join-Path ([System.IO.Path]::GetTempPath()) ("bb-hygiene-pack-" + [Guid]::NewGuid().ToString("N"))
        New-VaultCheckpoint -vault $vb -checkpointPath $cpPath | Out-Null
        $pack = Export-EvidencePack -vault $vb -outPath $packDir -CheckpointPath $cpPath
        $packZip = $pack.pack
        &$dropLastLine $vb

        $vvB = Verify-Vault $vb
        $results += &$mk "truncation invisible to chain alone" ($vvB.valid -and $vvB.entries -eq 1) "chain of genesis still valid — this is WHY checkpoints exist"

        $cpTest = Test-VaultCheckpoint $vb $cpPath
        $results += &$mk "checkpoint catches tail truncation" (-not $cpTest.valid -and $cpTest.reason -match "truncat") $cpTest.reason

        $restoreDir = Join-Path ([System.IO.Path]::GetTempPath()) ("bb-hygiene-rest-" + [Guid]::NewGuid().ToString("N"))
        $r = Restore-VaultFromPack -packZip $packZip -vaultPath $restoreDir
        $vaults += $r.vault
        $cpTest2 = Test-VaultCheckpoint $r.vault $cpPath
        $results += &$mk "restore-from-pack repairs truncation" ($r.entries -eq 2 -and $cpTest2.valid) "entries=$($r.entries) checkpoint valid=$($cpTest2.valid)"

        # --- Vault C: forged-future clock ---
        $vc = &$newTmpVault "c"; $vaults += $vc
        [void](Add-VaultEntry -vault $vc -type "test" -data @{ note = "real entry" })
        $futureUtc = (Get-Date).ToUniversalTime().AddDays(3).ToString("o")
        [void](&$craftEntry $vc $futureUtc "test")
        $vvC = Verify-Vault $vc
        $results += &$mk "future timestamp caught" (-not $vvC.valid -and $vvC.reason -match "future") $vvC.reason

        # --- Vault D: clock rollback ---
        $vd = &$newTmpVault "d"; $vaults += $vd
        [void](Add-VaultEntry -vault $vd -type "test" -data @{ note = "real entry" })
        $tipD = Get-VaultTip $vd
        $backUtc = ([DateTime]::Parse($tipD.utc)).AddDays(-3).ToString("o")
        [void](&$craftEntry $vd $backUtc "test")
        $vvD = Verify-Vault $vd
        $results += &$mk "timestamp regression caught" (-not $vvD.valid -and $vvD.reason -match "regression") $vvD.reason

        # --- Vault E: corrupt line localized; torn tail repaired ---
        $ve = &$newTmpVault "e"; $vaults += $ve
        [void](Add-VaultEntry -vault $ve -type "test" -data @{ note = "good entry" })
        [void](Add-VaultEntry -vault $ve -type "test" -data @{ note = "second good entry" })
        # Simulate a crash mid-append: a partial JSON fragment as the tail.
        [System.IO.File]::AppendAllText($ve.ledger, '{"seq": 3, "utc": "2026-10-30T15:00:00.', (Get-Utf8NoBom))
        $vvE = Verify-Vault $ve
        $results += &$mk "corrupt line localized by line number" (-not $vvE.valid -and $vvE.reason -match "line 4") "reason=$($vvE.reason)"

        $repair = Clear-VaultTornTail -vault $ve -Confirm:$false
        $vvE2 = Verify-Vault $ve
        $results += &$mk "torn-tail repair round trip" ($repair.repaired -and $repair.removedLines -eq 1 -and (Test-Path $repair.backupPath) -and $vvE2.valid -and $vvE2.entries -eq 3) "repaired=$($repair.repaired) removed=$($repair.removedLines) entries=$($vvE2.entries)"

        $vf = &$newTmpVault "f"; $vaults += $vf
        [void](Add-VaultEntry -vault $vf -type "test" -data @{ note = "clean" })
        $noRepair = Clear-VaultTornTail -vault $vf -Confirm:$false
        $results += &$mk "torn-tail refuses a clean ledger" (-not $noRepair.repaired -and $noRepair.reason -match "verifies clean") $noRepair.reason

        # Mid-chain corruption is NOT a torn tail — must refuse, not truncate.
        $vg = &$newTmpVault "g"; $vaults += $vg
        [void](Add-VaultEntry -vault $vg -type "test" -data @{ note = "first" })
        [void](Add-VaultEntry -vault $vg -type "test" -data @{ note = "second" })
        [void](Add-VaultEntry -vault $vg -type "test" -data @{ note = "third" })
        $rawLines = [System.IO.File]::ReadAllLines($vg.ledger)
        $rawLines[2] = 'BROKEN JSON HERE'
        [System.IO.File]::WriteAllLines($vg.ledger, $rawLines, (Get-Utf8NoBom))
        $midRepair = Clear-VaultTornTail -vault $vg -Confirm:$false
        $results += &$mk "torn-tail refuses mid-chain corruption" (-not $midRepair.repaired -and $midRepair.reason -match "mid-chain") $midRepair.reason

        # --- Vault H: rewritten checkpoint caught by the seal ---
        $vh = &$newTmpVault "h"; $vaults += $vh
        [void](Add-VaultEntry -vault $vh -type "test" -data @{ note = "pre-checkpoint" })
        [void](Add-VaultEntry -vault $vh -type "test" -data @{ note = "pre-checkpoint 2" })
        $cpH = Join-Path ([System.IO.Path]::GetTempPath()) ("bb-hygiene-cph-" + [Guid]::NewGuid().ToString("N") + ".json")
        New-VaultCheckpoint -vault $vh -checkpointPath $cpH | Out-Null
        $sealedOk = Test-VaultCheckpoint $vh $cpH
        $results += &$mk "sealed checkpoint verifies with freshness fields" ($sealedOk.valid -and $sealedOk.entriesSinceCheckpoint -eq 0 -and -not $sealedOk.checkpointStale) "behind=$($sealedOk.entriesSinceCheckpoint) stale=$($sealedOk.checkpointStale)"
        # Attacker rewrites the checkpoint to match a later truncation:
        $cpJson = Get-Content $cpH -Raw
        [System.IO.File]::WriteAllText($cpH, ($cpJson + ' '), (Get-Utf8NoBom))
        $sealedBad = Test-VaultCheckpoint $vh $cpH
        $results += &$mk "rewritten checkpoint refused by seal" (-not $sealedBad.valid -and $sealedBad.reason -match "seal") $sealedBad.reason
        if (Test-Path $cpH) { Remove-Item $cpH -Force -ErrorAction SilentlyContinue }
        if (Test-Path "$cpH.SHA256") { Remove-Item "$cpH.SHA256" -Force -ErrorAction SilentlyContinue }

        # --- Timestamp format gate ---
        $results += &$mk "timestamp format: canonical ISO UTC" (Test-VaultTimestampFormat "2026-10-30T15:53:10.1234567Z") "true"
        $results += &$mk "timestamp format: offset form" (Test-VaultTimestampFormat "2026-10-30T15:53:10+02:00") "true"
        $results += &$mk "timestamp format: no-zone rejected" (-not (Test-VaultTimestampFormat "2026-10-30T15:53:10")) "false"
        $results += &$mk "timestamp format: US locale rejected" (-not (Test-VaultTimestampFormat "10/30/2026 3:53 PM")) "false"
        $results += &$mk "timestamp format: empty rejected" (-not (Test-VaultTimestampFormat "")) "false"

        $vi = &$newTmpVault "i"; $vaults += $vi
        [void](Add-VaultEntry -vault $vi -type "test" -data @{ note = "good" })
        $tipI = Get-VaultTip $vi
        $forgedUtc = 'October 30, 2026 3:53 PM'
        [void](&$craftEntry $vi $forgedUtc "test")
        $vvI = Verify-Vault $vi
        $results += &$mk "non-conforming timestamp fails verify" (-not $vvI.valid -and $vvI.reason -match "non-conforming") $vvI.reason

        # --- Checkpoint freshness predicate ---
        $f1 = Test-CheckpointFreshness -CheckpointSeq 0 -TipSeq 5 -MaxEntriesSinceCheckpoint 3
        $results += &$mk "freshness: stale past threshold" ($f1.stale -and $f1.behind -eq 5) "behind=$($f1.behind)"
        $f2 = Test-CheckpointFreshness -CheckpointSeq 0 -TipSeq 5 -MaxEntriesSinceCheckpoint 10
        $results += &$mk "freshness: fresh inside threshold" (-not $f2.stale -and $f2.behind -eq 5) "behind=$($f2.behind)"

        # --- CSV export SHA-256 sidecar + parser blank-line tolerance ---
        $vj = &$newTmpVault "j"; $vaults += $vj
        [void](Add-VaultEntry -vault $vj -type "test" -data @{ note = "one" })
        [void](Add-VaultEntry -vault $vj -type "test" -data @{ note = "two" })
        [System.IO.File]::AppendAllText($vj.ledger, "`r`n`r`n", (Get-Utf8NoBom))
        $blankTip = Get-VaultTip $vj
        $results += &$mk "parser tolerates blank lines" ($blankTip.seq -eq 2) "tip=$($blankTip.seq)"
        $csvPath = Join-Path ([System.IO.Path]::GetTempPath()) ("bb-hygiene-csv-" + [Guid]::NewGuid().ToString("N") + ".csv")
        Export-VaultCsv -vault $vj -outPath $csvPath | Out-Null
        $sidecarOk = (Test-Path "$csvPath.SHA256") -and (([System.IO.File]::ReadAllText("$csvPath.SHA256")).Trim() -eq (Get-FileHash $csvPath -Algorithm SHA256).Hash)
        $results += &$mk "CSV export writes SHA-256 sidecar" ($sidecarOk) "$csvPath.SHA256"
        if (Test-Path $csvPath) { Remove-Item $csvPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path "$csvPath.SHA256") { Remove-Item "$csvPath.SHA256" -Force -ErrorAction SilentlyContinue }
    } finally {
        foreach ($v in $vaults) {
            if (Test-Path $v.path) { Remove-Item -Recurse -Force $v.path -ErrorAction SilentlyContinue }
        }
        if ($cpPath -and (Test-Path $cpPath)) { Remove-Item $cpPath -Force -ErrorAction SilentlyContinue }
        if ($packDir -and (Test-Path $packDir)) { Remove-Item -Recurse -Force $packDir -ErrorAction SilentlyContinue }
        if ($packZip -and (Test-Path $packZip)) { Remove-Item $packZip -Force -ErrorAction SilentlyContinue }
    }

    $passed = @($results | Where-Object { $_.Pass }).Count
    $failed = @($results | Where-Object { -not $_.Pass }).Count
    Write-Host "  $passed passed, $failed failed." -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Red' })
    foreach ($r in $results) {
        $mark = if ($r.Pass) { '[+]' } else { '[X]' }
        Write-Host "  $mark $($r.Check) - $($r.Detail)" -ForegroundColor $(if ($r.Pass) { 'Gray' } else { 'Red' })
    }
    return $failed -eq 0
}

# Dot-sourcing note: all functions load directly into the caller session.
