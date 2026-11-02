# BLACKBOX CODE AUDIT — Every Action Explained
**Date:** 2026-10-31
**Scope:** 33 PowerShell files, 40,817 lines, 877 functions
**Rule:** If this application pulls hidden shit, it cannot have hidden shit itself.

---

## NETWORK CALLS (42 total)

**What they do:** The tool makes outbound network requests in exactly these situations:

1. **OSINT lookups** (modules 04, 05): When YOU ask it to look up an IP or domain, it queries public APIs (RDAP, crt.sh, VirusTotal, urlhaus). These only fire when you run the lookup. They send the IP/domain you asked about — nothing else.

2. **Username checks** (module 05): When YOU run people-track, it sends HTTP requests to social media sites to check if a username exists. It sends the username you provided. Nothing else.

3. **Data broker verification** (module 09): Checks if opt-out URLs are still alive. Sends nothing but a GET request.

4. **Threat intel feeds** (module 22): Downloads tracker blocklists (DuckDuckGo, Disconnect, EasyPrivacy). These are public feeds. Downloads only.

5. **Vulnerability data** (module 06): Queries NVD/MSRC for CVE details. Sends CVE IDs. Nothing personal.

**What they NEVER do:**
- Never send your files, your data, or your identity anywhere
- Never phone home to any server I control
- Never exfiltrate. Every network call is either a public API lookup YOU triggered or a public feed download.

---

## REGISTRY WRITES (42 total)

**What they do:** The tool modifies the registry ONLY in these situations:

1. **Remediation** (modules 06, 07, 24): When YOU approve a fix, it changes the specific registry value for that fix. Example: disabling SMB1, disabling LLMNR, fixing privacy settings. Each fix shows you exactly what it changes BEFORE it changes it.

2. **Scheduled tasks** (module 09): Creates a monthly scheduled task for broker relist checks. Only when you run New-BrokerMonthlyTask.

3. **Rollback data** (multiple): Before any registry change, the old value is saved so you can undo it.

**What they NEVER do:**
- Never modify registry without your explicit approval (each fix asks first)
- Never touch keys outside the specific fix you approved
- Never delete registry keys (only modifies values, and only with rollback saved)

---

## REGISTRY READS (47 total)

**What they do:** Read-only inspection of:
- Run/RunOnce keys (what starts at boot) — modules 21, 25
- Services ImagePaths (what services run) — modules 21, 25
- Uninstall keys (what's installed) — modules 06, 24
- Defender preferences (exclusions, protection status) — modules 06, 26
- Privacy settings (telemetry, advertising ID) — module 24

**These are reads. They change nothing.**

---

## FILE DELETIONS (58 total)

**What they do:** Files are deleted ONLY in these situations:

1. **Purge module** (module 25): Deletes unattributed binaries (no publisher, no signature, no version info). ONLY with -Enforce flag. Logs to vault BEFORE deleting. NEVER touches System32/SysWOW64/WinSxS/Windows.

2. **Task killer** (module 28): Does NOT delete files. Only kills processes.

3. **Test cleanup**: Self-test functions create temp files and delete them after.

**What they NEVER do:**
- Never delete without your explicit -Enforce flag
- Never delete system files (hard-coded protection)
- Never delete without logging first (vault entry before deletion)

---

## FILE WRITES (126 total)

**What they do:**
1. **Evidence vault** (module 12): Hash-chained log entries. Every finding, every action.
2. **Reports**: HTML/text reports you requested.
3. **Memory** (module 13): Local JSON file with learnings. On your machine only.
4. **Ledger** (module 09): Broker opt-out progress tracking.
5. **Config**: Module settings, kill lists (user-editable).

**All writes are local. Nothing leaves the machine.**

---

## PROCESS KILLS (9 total)

**What they do:** ONLY in module 28 (task killer):
- Kills processes on the user-editable kill list
- ONLY with your explicit approval (audit shows you, you pick, or you run enforce)
- NEVER kills system-critical (csrss, lsass, svchost, explorer, etc. — hard-coded refusal)
- Every kill logged to vault

---

## PROCESS STARTS (10 total)

**What they do:**
- Launching pktmon for packet capture (module 02) — only when you start a capture
- Opening URLs in browser for broker opt-outs (module 09) — only the opt-out URL
- No hidden process launches

---

## ENCODED PATTERNS (9 total, all clean)

**The 4 flagged:**
- 3 in mail-shield: `[Convert]::FromBase64String` — decoding base64 MIME email attachments. This is how email works. Not obfuscation.
- 1 in malware-hunter: regex pattern `'FromBase64String|Invoke-Expression|\bIEX\b'` — this is a DETECTION signature. The hunter looks FOR these patterns in malware. It's not using them.

**The other 5:** ToBase64String for encoding vault entries (not hiding, just encoding for JSON).

**Verdict:** No obfuscated code. No hidden payloads. No -EncodedCommand. No IEX with variables.

---

## CREDENTIAL HANDLING (12 total)

**What they do:**
- Get-Credential prompts (user types, never stored)
- SecureString for in-memory password handling (never written to disk in plaintext)
- No credential storage. No credential transmission. No credential logging.

---

## ELEVATION (9 total)

**What they do:**
- Check if running as admin (some modules need it for full access)
- Offer to restart as admin (user clicks, UAC prompts — standard Windows flow)
- No bypasses. No silent elevation. No UAC bypass tricks.

---

## BOTTOM LINE

**Data flow:** Everything stays on your machine. Network calls are only public API lookups YOU trigger or public feed downloads. No exfiltration. No phone-home. No telemetry.

**Destructive actions:** File deletions and process kills ONLY happen with your explicit approval (-Enforce flag or menu confirmation). System paths are hard-protected. Every destructive action is logged BEFORE it happens.

**Hidden code:** None found. No obfuscation. No encoded payloads. No IEX tricks. The 4 base64 hits are legitimate MIME decoding and detection signatures.

**This code does exactly what it says it does. Nothing more.**
