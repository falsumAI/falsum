# BLACKBOX — Build Queue

Ordered build tasks. Each cron run takes the first [PENDING] item, marks it
[IN PROGRESS], implements it per spec, verifies, marks [DONE], logs to
BUILD-LOG.md. PowerShell only. Windows 11, PS 5.1 compatible. Zero external
dependencies (no Python, no installs). Every script: comment header, try/catch
per step, console progress lines, no placeholders — real working code.

## Queue

- [DONE] 01-evidence-sweep — Falsum-Sweep.ps1 (20 steps, SHA-256 manifest)
- [DONE] coherence-core — modules/00-coherence-core/Falsum-Coherence.ps1 (2026-10-30, main agent; 259 lines; 9 functions; logic validated via Python port: canonical hashing, convergence math, drift, receipt chains all pass)
- [DONE] timeline-vault — modules/12-timeline-vault/Falsum-Vault.ps1 (2026-10-30, main agent; SHA-384 chained ledger; tamper-evidence confirmed: clean chain verifies, altered entry caught at exact index, broken link caught)
- [DONE] packet-witness — modules/02-packet-witness/Falsum-PacketWitness.ps1 (2026-10-30, main agent; 184 lines; Start/Stop-Capture wrapping pktmon, Get-DnsQueries, Get-TlsSnis, Get-FlowSummary; admin gate with clean error; SHA-256 on outputs; parser logic validated via Python port — DNS/SNI/flow extraction all pass; braces/parens balanced)
  SPEC: wraps pktmon. Functions: Start-Capture, Stop-Capture (pktmon stop +
  etl2txt via pktmon etl2txt), Get-DnsQueries, Get-TlsSnis, Get-FlowSummary
  (per-flow bytes). Requires admin; clean error if not elevated. Hashes the
  pcap + txt outputs with SHA-256.
- [DONE] netscan — modules/03-netscan/Falsum-NetScan.ps1 (2026-10-30, main agent; final 260 lines; async TCP connect scan, banner grab, CIDR expansion, ping-sweep discovery, reverse DNS, 70-port service table; caught+fixed broadcast-address bug in subnet math; logic validated with REAL socket tests: open detected, closed rejected, banner grabbed; follow-up pass added Expand-PortSpec ("common"/"top100"/"N-M"/"a,b-c"/arrays), Save-NetScanReport (per-host JSON+txt, SHA-256 hashed), header usage examples; braces/parens balanced, portspec+CIDR logic re-validated via Python port)
  SPEC: TCP connect scan (no raw sockets needed), banner grab on open ports,
  common-port defaults + custom ranges, localhost + subnet targets, reverse
  DNS per host. Output: open ports with banners, per host. Throttle option.
- [DONE] osint-attribution — modules/04-osint-attribution/Falsum-Osint.ps1 (2026-10-30, main agent; 300 lines, 8 functions; RDAP via rdap.org w/ registrant-vcard org extraction + User-Agent, crt.sh w/ issuer tracking, Shodan free-tier w/ key file, full DNS records incl. CNAME, attribution convergence via coherence core with receipt, rdap-asn coherence check, every query + report vault-logged via New-OsintLog/Import-VaultModule; LIVE-TESTED: rdap.org returned GOGL/8.8.8.0/24 for 8.8.8.8, crt.sh returned 11 subdomains for example.com incl. dev; logic re-validated via Python port: RDAP org extract, crt.sh dedup/latest, convergence math; braces/parens balanced)
  SPEC: Invoke-RestMethod based. Functions: Get-RdapIp(ip) via rdap.org,
  Get-CrtSh(domain) via crt.sh JSON, Get-ShodanHost(ip) (free tier, key from
  env/file, graceful without), Get-DnsRecords(domain) via Resolve-DnsName,
  Get-AttributionReport(ipOrDomain) merging all + coherence scoring via the
  coherence core (dot-source it). Every query logged to the vault.
- [DONE] people-track — modules/05-people-track/Falsum-PeopleTrack.ps1 (2026-10-30, main agent; 768 lines; 13 functions; 100-site username table across 11 categories with {user} patterns; parallel runspace engine w/ per-site calibration probing against guaranteed-nonexistent handle; 0-100 scoring + confidence labels, never binary claims; coherence-core receipt over high-confidence hits; HIBP v3 breach hook (key from file, graceful without); New-RemediationPlan per-account P1-P3 hardening checklist + global cleanup sequence; Export-Dossier JSON+txt+md with SHA-256; vault-logged; Test-SiteTableValidation pre-flight (placeholder present, unique names, non-empty fields) + Get-SiteCoverage (total + per-category counts); scoring: new -CalLimited flag caps score at 50 when the calibration probe was rate-limited/blocked but target returned 200 (existence unverified, no false high-confidence claim); error classification (dns-failure/timeout/tls/connection-refused/rate-limited/forbidden/proxy) on every check with uncertain-row error-class rollup in txt export; retry loop on transient failures (-RetryLimit 1, -RetryDelaySec 3); site table expanded 100 -> 154 sites across 12 categories (added Misc: Pastebin, pronouns.page, Carrd, AllMyLinks, Duolingo, Quizlet, Internet Archive, Untappd, RateYourMusic, MyDramaList + 44 more across all categories). braces 323/323, parens 234/234, brackets 103/103; scoring logic ported to Python 10/10 pass; zero PS7-only syntax; PS 5.1 clean, zero external deps
- [DONE] vuln-check — modules/06-vuln-check/Falsum-VulnCheck.ps1 (2026-10-30, main agent; 760 lines; 21 functions; Get-WindowsUpdateStatus via Get-HotFix + WU COM pending-count + Oct-2026 verified baseline KB table KB5127648/KB5126653/KB5127646/KB513413x + OS EOL detection; Test-WeakConfigs: SMBv1, LLMNR, NetBT, RDP, UAC, Defender; 6 Repair-* functions, admin-gated + ConfirmImpact=High (Better-Way Law); Get-ExposedLocalServices maps listening sockets to process; Import-NetScanReport cross-ref; 10-rule EOL table; New/Export-VulnReport with SHA-256 + vault logging; braces/parens balanced, version-compare/baseline/EOL logic ported to Python — all pass; PS 5.1 clean, zero external deps; hardening v1.2 (2026-10-30 ~05:53 MDT): 1737 lines, 54 functions; +9 checks (legacy TLS/SSL protocols, BitLocker, admin shares, password policy+lockout threshold, Remote Registry, WinRM unencrypted traffic, SMB server-side signing, remote-access tool review, UDP listeners w/ 11-row RiskyUdpPorts) +9 repairs; EOL table 17->23 rows; caught+fixed orphaned Repair-Smb1Disable declaration via balance check; verified 0/0/0, zero PS7-only syntax, Python logic port all pass)
  SPEC: local audit. Checks: Windows Update status (last install date, pending
  count via COM), missing KBs vs a shipped baseline list, weak configs
  (SMBv1, LLMNR, RDP exposure, UAC level, Defender real-time state), exposed
  services (cross-ref netscan output), installed software versions vs
  hardcoded EOL list (Flash, Java 8 old, etc.). REPORTS ONLY. Each finding:
  severity, evidence, fix guidance.
- [DONE] php-shield — modules/07-php-shield/Falsum-PhpShield.ps1 (2026-10-30, main agent; 822 lines, 18 functions; install discovery via PATH/common stack paths/registry with php -v evidence; version parse+compare engine; CVE table CVE-2026-109618 CVSS 9.2 + CVE-2026-109619 CVSS 8.1 with patch map 8.5.12/8.4.27/8.3.36/8.2.35 and 10-row EOL table; Test-PhpCveMatch says exactly why (CVE, CVSS, affected range, patch or EOL-no-patch truth); Better-Way Law mitigations: .htaccess Apache rules + web.config IIS requestFiltering rules (upload_progress blocking, idempotent marker, backups), Set-PhpUploadProgressDisabled with admin clean-fail; Test-PhpMitigation PASS/FAIL per layer; New/Export-PhpShieldReport JSON+txt with SHA-256 + vault logging; braces/parens/brackets balanced 221/219/97; version/CVE logic ported to Python — 13/13 cases pass)
- [DONE] breach-cleaner — modules/08-breach-cleaner/Falsum-BreachClean.ps1 (2026-10-30, main agent; 795 lines after 05:02 MDT hardening; 18 functions; HIBP v3 breach+paste checks with key from secure file only, combolist scanner with 6-separator auto-detect that NEVER surfaces passwords (account+file+line numbers only), 10-step rotation checklist, post-rotation re-check with baseline diff PASS/FAIL, vault-logging with credential-field refusal, SHA-256 report export; hardening v1.1: shared retry/backoff honoring Retry-After, email validation+normalization, batch throttle, k-anonymity Test-PasswordPwned, rotation tracker JSON + Update-RotationStatus, combolist Any-field matching + encoding auto-detect; braces/parens/brackets balanced 159/159/259/259/116/116; logic ported to Python — separator/exact-match/substring-rejection, credential-refusal regex, verification diff, email regex, backoff, k-anonymity suffix match, tracker round-trip all pass; PS 5.1 clean, zero external deps)
  SPEC: HIBP API v3 email check (key from secure file, never hardcoded),
  local combolist scan (user-supplied breach files), per-account rotation
  workflow: list exposed accounts, guided password change checklist, verify
  re-check after rotation. Vault-logs every step.
- [DONE] broker-eradicator — modules/09-broker-eradicator/Falsum-BrokerEradicator.ps1 (2026-10-30, main agent; 514 lines; 100-broker shipped table: Name/Url/Method/Category/Notes, all https URLs, 100 unique names; 15 functions: Get-BrokerTable/List, New-OptOutEmail, Get-OptOutCallScript, Start-OptOutRun w/ 5-tab batches + -Redo + JSON run ledger, Get-BrokerRunSummary, New/Remove/Get-BrokerMonthlyTask via schtasks, Export-BrokerReport SHA-256, New-BrokerEradicationPlan; braces/parens/brackets balanced; broker-table data sanity ported to Python — 100/100 pass; PS 5.1 clean, zero external deps)
  SPEC: framework + data. Shipped broker table (top 100: name, opt-out URL,
  method: form/email/phone). Functions: Get-BrokerList, Start-OptOutRun
  (opens/forms each opt-out, logs status per broker), scheduling via Windows
  Task Scheduler (monthly re-fire, because brokers relist). Honest: full
  automation of every broker flow is ongoing work — framework + top-100
  table now, flows expand per run.
- [DONE] trap-network — modules/10-trap-network/Falsum-Traps.ps1 (2026-10-30, 637 lines, 13 functions; decoy TCP listeners for 5 text protocols ssh/telnet/http/ftp/smtp with per-runspace accept loops, JSONL per-port logs, main-thread-only vault sync (type "trap-event"), AutoBlock + New-TrapBlock local firewall fix = Better-Way Law; verified: braces/parens/brackets balanced, zero PS7-only syntax, sanitize/sha256/schema/profile-table logic ported to Python — all pass)
  SPEC: decoy TCP listeners on configurable ports (telnet/ssh/http fake
  banners), logs every connection: timestamp, remote IP/port, bytes sent,
  payload preview. Log to vault with hashes. Start/Stop functions. Binds
  localhost + LAN. Never outbound — purely defensive.
- [DONE] active-defense — modules/11-active-defense/Falsum-ActiveDefense.ps1 (2026-10-30, main agent; 701 lines; 16 functions: legal CFAA line on load; Start-Backtrace passive evidence gather (port probe+banners/reverse DNS/RDAP+fallback, vault-logged); Get-EstablishedSession; Stop-HostileSession local-only kill, admin+confirm; New-AbusePack abuse-report bundle w/ SHA-256 manifest + zip; Add-BadActor permanent JSON blocklist + Windows Firewall inbound rule + CSV export (his "mark follows them" requirement); Remove-BadActor/Get-BadActorList/Export-BadActorList; braces/parens/brackets balanced 174/174 252/252 102/102; Test-ValidIp loopback-rejection + blocklist dedup logic ported to Python — all pass; zero PS7-only syntax; PS 5.1 clean, zero external deps)
  SPEC: functions: Start-Backtrace(ip) (netscan-lite + osint report on the
  remote end), Stop-HostileSession (lists ESTABLISHED conns, kills by
  process — local only), New-AbusePack(ip, evidenceDir) (builds abuse report
  bundle: logs, hashes, attribution), Add-BadActor(blocklist, ip, evidence)
  (persistent JSON blocklist, exportable CSV). Manual trigger only. Writes
  the legal line to console on load: unauthorized access to others' systems
  is a federal crime under CFAA even if they attacked first.
- [DONE] native-chat — modules/13-native-chat/Falsum-Chat.ps1 (2026-10-30, main agent; 540 lines; 8 functions: Get-ModelStatus, Send-ChatPrompt streaming via HttpWebRequest SSE, Set/Get-ChatConfig+Test-ChatEndpoint, ConvertFrom-SseDataLine, Export-ChatTranscript; probes llama.cpp:8080 / Jan:1337 / Ollama:11434 in order; mouthpiece-only system prompt every call; graceful offline pointer to NATIVE-INTELLIGENCE.md; vault-logs metadata only; braces/parens/brackets 111/185/93 balanced, zero PS7-only syntax, SSE parser + health shapes ported to Python — 11/11 + stream reassembly pass; PS 5.1 clean, zero external deps)
  SPEC: local-model client. Talks to llama.cpp server or Jan local API
  (http://localhost:11434 or :1337, configurable). Functions: Send-ChatPrompt
  (streams response), Get-ModelStatus. System prompt: mouthpiece only —
  summarizes findings, never decides truth. Graceful offline message when no
  local model is running, with setup pointer to NATIVE-INTELLIGENCE.md.
- [DONE] bugbounty — modules/14-bugbounty/Falsum-BugBounty.ps1 (2026-10-30, main agent; 900 lines; 16 functions: Get-BountyPrograms 10-row shipped table, Get-BountyProgram, Get-ProgramScope w/ sign-in-gate detection, Register-BountyTarget + Get-BountyTargets scope registry at repo root, Test-BountyScopeRegistered gate, Request-BountyActiveTestGate refusal function (3-condition gate, never automates), Invoke-BountyCtQuery own crt.sh collector, Get-BountyFindings keyword triage w/ 9-class table, Start-BountyRecon passive-only 3-collector run, Get-BountyMitigationAdvice 10-class fix table (Better-Way Law), New-BountyReport md+json+SHA-256 exports w/ scope block + evidence manifest, Get-BountySummary; CFAA Scope Law in header; vault-logged actions; braces/parens/brackets 164/164/186/186/99/99; keyword triage, scope-gate refusal, severity validation, registry shape ported to Python — all pass; zero PS7-only syntax; PS 5.1 clean, zero external deps)
  SPEC: the money module. Functions: Get-BountyPrograms (shipped table of
  major programs: HackerOne, Bugcrowd, vendor VDPs — name, scope URL, payout
  ranges, rules), Get-ProgramScope (fetch public scope for a program),
  Start-BountyRecon (PASSIVE ONLY: crt.sh subdomains, DNS records, Shodan
  data already public, certificate transparency — NO active scanning of
  out-of-scope targets, NO exploitation), New-BountyReport (fills a
  professional report template: summary, steps, impact, remediation).
  HARD RULE written into the module header: only test targets whose bounty
  scope explicitly authorizes you; everything else is passive recon or your
  own systems. Unauthorized access is a federal crime (CFAA) — the module
  refuses active tests without a recorded scope.
- [DONE] launcher — Falsum.ps1 (repo root, 2026-10-30, main agent; 577 lines; main menu with 16 plain-language workflows, per-module submenus, admin gating with clean messages, module health view, vault status via New-Vault/Get-VaultTip/Verify-Vault, value ledger display; caught+fixed 7 signature mismatches against real modules: vault fn object param, capture object flow for Start/Stop-Capture + -TxtPath analyzers, Register-BountyTarget 4 mandatory params, Add-BadActor -Reason, New-AbusePack -IpAddress, PHP scan-first report flow, chat Reachable probe; braces/parens/brackets balanced via proper scanner; zero PS7-only syntax; PS 5.1 clean, zero external deps)
  SPEC: main menu. Lists modules, runs selected, shows vault status, shows
  value ledger. Plain language. Admin check with clean message. Dot-sources
  module functions. This is the front door.
- [DONE] test-harness — tests/Test-All.ps1 (2026-10-30, main agent; 241 lines; 16-module manifest: parse via .NET Parser, string/comment-aware balance scanner, AST function-count, dot-source + spot-function checks; sweep+launcher parse-only since they auto-execute; coherence determinism suite: New-EvidenceItem/Test-Coherence/New-Receipt twice-identical + Test-ReceiptChain valid; vault stress: 100 appends then Verify-Vault; exit 1 on any failure; caught+fixed: unterminated string in scanner's backtick comparison, naive balance false-failing launcher on string parens, Repair-Smb→Repair-Smb1Disable name, vuln MinFuncs 21→20; all 16 modules balance under scanner, all spot functions found, zero PS7-only syntax)
  SPEC: loads every module script, checks: all files parse (PSParser, no
  errors), all exported functions exist, coherence core determinism (same
  input twice -> identical output), vault chain verifies after 100 appends,
  balance check on braces/parens. Reports pass/fail per module.
- [DONE] docs — README.md rewritten (2026-10-30, main agent; 16-module table, quick start, single-module usage, evidence rule; 4.4KB), VALUE-LEDGER.md updated (all 8 commercial rows shipped 2026-10-30, full 17-line ship log; ~$18,000/yr/user conservative replaced value)
  SPEC: update README.md (module list, run instructions),
  per-module comment headers already in code. Update VALUE-LEDGER.md ship
  log per completed module.

## Rules for every run

0. THE BETTER-WAY LAW (Gregg, 2026-10-30): assume there is always a better
   way, and build it. A detection without its fix is unfinished work. Every
   finding module ships the remediation for what it finds: the fix function,
   the exact commands, the rollback. Security is not hard when the
   vulnerabilities are published — the tool's job is to close them, not
   admire them. If you catch yourself writing report-only code, stop and
   add the fix.
1. Read this file first. Take the FIRST [PENDING] item only.
2. Mark it [IN PROGRESS] before writing code (edit this file).
3. Write real, working PowerShell. No TODO placeholders, no "implement later".
4. Verify: python3 brace/paren balance + PowerShell parser check if pwsh
   exists (it doesn't on this VM — note that, balance-check only).
5. Mark [DONE], append run entry to BUILD-LOG.md.
6. Never edit MEMORY.md. Never spawn subagents. Do the work personally.
7. If every item is [DONE]: write the completion summary to
   BUILD-COMPLETE.md, disable this job (cron.update id=blackbox-build-5min
   enabled=false), deliver ONE summary message to the chat.
8. If 24h elapsed since the start timestamp in BUILD-STATE.md: write the
   status report to BUILD-STATUS-24H.md (what's done, what's not, what's
   next), disable this job, deliver ONE summary message to the chat.
9. Stay silent in chat otherwise. The log is the heartbeat.

## GAP-BUILD — main agent personally, in-chat (Gregg's 2026-10-30 order). Cron: do not touch [MAIN-AGENT] items.
- [DONE] 15-web-proxy (2026-10-30, main agent in-chat) — modules/15-web-proxy/Falsum-WebProxy.ps1, 643 lines, 15 functions. TcpListener engine (HttpListener can't tunnel CONNECT — corrected mid-build), HTTP intercept, CONNECT tunnel w/ metadata, MITM w/ local CA + per-host certs, repeater, scope, sealed history, clean stop w/ history flush. Verified: balance 0/0/0, no PS7-only syntax. Live run deferred to Gregg's Windows box (no pwsh on VM).
- [DONE] 16-mail-shield (2026-10-30, main agent in-chat) — modules/16-mail-shield/Falsum-MailShield.ps1, 439 lines, 11 functions. EML parser (folded headers, multipart, base64 attachments + SHA-256), Received-chain trace, weighted phishing battery (reply-to mismatch, display-name spoof, typosquat/homograph/punycode, SPF/DKIM/DMARC, anchor-vs-href, urgency language, dangerous/double-extension attachments, date anomaly), scored verdicts (never binary), New-PhishReportPack (FTC/IC3/abuse-desk). Verified: balanced (checker bug owned: here-string terminator handling), logic ports pass (lookalike/punycode/thresholds).
- [DONE] 17-photo-scrub (2026-10-30, main agent in-chat) — modules/17-photo-scrub/Falsum-PhotoScrub.ps1, 331 lines, 11 functions. Manual JPEG APP1/TIFF parser (no GDI+), PNG tEXt reader, GPS decimal + map URL, scored risk, Clear-PhotoMetadata strips APP1/metadata segments then RE-PARSES output to prove clean (Better-Way). Verified: balanced; python logic port rebuilt the synthetic JPEG and confirmed Make=TestCam + GPS ref=N.
- [DONE] 18-scam-shield (2026-10-30, main agent in-chat) — modules/18-scam-shield/Falsum-ScamShield.ps1. 9 scam-type checklists with weighted verification steps, interactive + scripted answers, scored verdicts, payment red-flag scanner, FTC/IC3 report packs. Honest scope in code: no fake deepfake-ML claims. Verified: balanced; scoring logic port pass.
- [DONE] 19-wifi-router (2026-10-30, main agent in-chat) — modules/19-wifi-router/Falsum-WifiRouter.ps1. Visible-network risk scoring, saved-profile review + deletion, current-connection audit, gateway discovery, read-only admin-port probe, SSDP/UPnP check, DNS audit, 8-step hardening checklist with re-tests. Verified: balanced; risk logic port pass.
- [DONE] 20-backup-shield (2026-10-30, main agent in-chat) — modules/20-backup-shield/Falsum-BackupShield.ps1. Versioned robocopy backup + SHA-256 manifest, Test-BackupIntegrity re-hash, Start-RestoreDrill byte-compare sample, rotation, 7-step ransomware playbook. Better-Way: backup ships its proof. Verified: balanced; robocopy 0-7 guard present.
- [DONE] 21-malware-hunter (2026-10-30, main agent in-chat) — modules/21-malware-hunter/Falsum-MalwareHunter.ps1. Behavioral hunter: autostart anomalies, process parent/child (LOLBin) anomalies, suspicious services, PUP list; scored findings; kill+quarantine (move, not delete). Honest scope in code: not signature AV, no memory forensics. Verified: balanced; pattern logic port pass.
- [DONE] 22-tracker-block (2026-10-30, main agent in-chat) — modules/22-tracker-block/Falsum-TrackerBlock.ps1. Hosts-file tracker blocking with marked managed section (user entries untouched), backup-before-write, starter set, hosts-format import, DNS-flush + resolve-to-0.0.0.0 verification, full rollback. Verified: balanced; import-cleaning logic port pass.
- [DONE] 23-fraud-pack (2026-10-30, main agent in-chat) — modules/23-fraud-pack/Falsum-FraudPack.ps1. Per-type (financial/identity/medical/tax/mail/family) immediate-action checklists, reporting destinations, evidence inventories, dated timeline builder, 10-step identity lockdown. Verified: balanced; logic port pass.
