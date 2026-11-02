# FALSUM MASTER TASK LIST
# Everything Gregg ordered the app to do. Knock off one by one until finished.
# Last updated: 2026-11-02

## CORE IDENTITY (non-negotiable)
- [x] Name: Falsum (not Sentinel, not black box)
- [x] Free for people, paid for giants (GPL v3 + commercial dual)
- [x] Local software, NOT a website/cloud URL
- [x] User never sees PowerShell files (C# hosts them invisibly)
- [x] 25-year code standard
- [x] Poison pill: free + better + always current + community-driven

## THE 40 MODULES (C# UI cards)
- [x] 00-coherence-core — Drift math engine
- [x] 01-evidence-sweep — System evidence sweep
- [x] 02-packet-witness — Network traffic capture
- [x] 03-netscan — Network device mapping
- [x] 04-osint-attribution — Attack attribution
- [x] 05-people-track — Username tracking
- [x] 06-vuln-check — Vulnerability scanning
- [x] 07-php-shield — PHP security
- [x] 08-breach-cleaner — Breach monitoring
- [x] 09-broker-eradicator — 958 data brokers, one-click purge
- [x] 10-trap-network — Honeypots
- [x] 11-active-defense — Backtrace, session kill, abuse reports
- [x] 12-timeline-vault — Hash-chained evidence vault
- [x] 13-native-chat — Local AI chat (PowerShell side)
- [x] 14-bugbounty — Passive recon, SCOPE LAW
- [x] 15-web-proxy — Encrypted traffic inspection
- [x] 16-mail-shield — Email phishing detection
- [x] 17-photo-scrub — Metadata stripping
- [x] 18-scam-shield — Scam detection
- [x] 19-wifi-router — Wi-Fi and router audit
- [x] 20-backup-shield — Ransomware backup protection
- [x] 21-malware-hunter — Malware detection and removal
- [x] 22-tracker-block — Hosts-file tracker blocking
- [x] 23-fraud-pack — Fraud documentation for law enforcement
- [x] 24-mobile-shield — Stalkerware detection
- [x] 25-purge — Unattributed binary removal
- [x] 26-defender-watch — Windows Defender monitoring
- [x] 27-memory-forensics — Deep memory analysis
- [x] 28-task-killer — Background task management
- [x] 29-registry-fix — Registry repair
- [x] 30-bridge — Tool integration bridge
- [x] 31-gate — Automation sector gating
- [x] 32-port-control — TCP/UDP port control
- [x] 33-command-center — System command interface
- [x] 35-loop-breaker — Kill self-reinstalling software
- [x] 36-satellite — Bluetooth/satellite exfiltration detection
- [x] 37-datagate — Data movement detection, user controls egress
- [x] 38-learning-ai — Local AI with lesson learning
- [x] 39-chrome-internals — Chrome profile inspection from disk
- [x] 40-browser-liberator — Remove phantom browser policies

## C# APPLICATION
- [x] MainWindow with all 40 module cards
- [x] ProtectAll orchestration (runs all modules in order)
- [x] AIChatWindow (local AI chat)
- [x] BrowserControlWindow (policy removal)
- [x] GovernmentWatchWindow (7 sectors)
- [x] PriorArtWindow (invention timestamping)
- [x] SettingsWindow (AI server, bridge, vault, about)
- [x] NativeMessagingHost (extension bridge receiver)
- [x] PowerShellEngine (hosts .ps1 invisibly)
- [x] QuantumCoherenceEngine (Gregg's drift math wired)
- [x] LocalAIService (deterministic self-correction, no warnings)
- [x] BrowserControlService (registry policy scan/remove)
- [x] SystemPolicyService (Windows policy scan)
- [x] PriorArtService (hash-chained inventions)
- [ ] COMPILE VERIFICATION on Windows (needs dotnet SDK or VS)
- [ ] RUNTIME TEST on Windows (needs Gregg's machine)

## LOCAL AI (Altman Challenge)
- [x] llama.cpp localhost:8080 integration
- [x] Lessons database (learns from "wrong, [correction]")
- [x] Deterministic self-correction (regenerate, no warnings)
- [x] Real KL-divergence drift scoring (not keyword proxy)
- [x] GreggDriftMeasure wired into response scoring
- [x] Poison pill check on drift threshold
- [ ] Model download automation in installer
- [ ] Benchmark vs cloud AI (needs Gregg's validation)

## BROWSER EXTENSION
- [x] Manifest V3
- [x] content.js (fingerprinting spoofing, 13.5KB)
- [x] background.js (native messaging, FP badge)
- [x] popup.js and popup.html
- [x] Real PIL shield icons
- [x] Install-NativeHost.ps1
- [x] Native messaging bridge (both directions)
- [ ] LIVE TEST on Windows (extension to app communication)
- [ ] world: "MAIN" for strict-CSP pages (known follow-up)

## ANDROID APP
- [x] FalsumVpnService.kt (TUN, DNS sinkholing)
- [x] PermissionAuditor.kt
- [x] StalkerwareScanner.kt
- [x] TrackerList.kt (60 domains)
- [x] VaultLogger.kt (SHA-256 chained)
- [x] MainActivity.kt
- [ ] COMPILE VERIFICATION (needs Android SDK)
- [ ] APK BUILD and sideload test

## GITHUB REPO (falsumAI/falsum)
- [x] Public repo
- [x] README with badges
- [x] LICENSE-GPL (full v3 text)
- [x] LICENSE-COMMERCIAL (Big Tech pays, hardened v2)
- [x] CLA.md
- [x] CONTRIBUTING.md
- [x] SECURITY.md
- [x] FUNDING.yml (sponsor button)
- [x] Issue templates
- [x] PR template
- [x] Topics and description
- [x] Every-minute auto-push cron
- [ ] CI workflow (needs token with workflow scope)
- [ ] First release with downloadable zip

## DESIGN LAWS
- [x] Better-way law: every detection ships its fix
- [x] Gate law: gate every automation sector
- [x] CMD law: CMD's capabilities are the floor
- [x] User controls TCP/UDP ports (global and local)
- [x] One single zip only when fully done

## REMAINING INTEGRATIONS (from VALUE-RESEARCH.md)
- [ ] PrivescCheck (P0 priority)
- [ ] Snitch wrapper (don't bundle, AGPL)
- [ ] AASIST deepfake detection module
- [ ] Merge Nuclei/Maigret/HardeningKitty side files into modules
- [ ] Breach/dark-web monitoring (0day feature parity gap)

## BUG BOUNTY (money)
- [x] Module 14 with SCOPE LAW
- [x] BOUNTY-PLAYBOOK.md
- [x] Cloudflare PHP CTF scope logged
- [ ] Passive recon results
- [ ] Gregg runs probes, reports back

## INVESTIGATION WEBSITE (separate from app)
- [x] Review copy built (5 pages)
- [x] IPFS publishing path proven
- [ ] Gregg decides: strip personal details for public, or keep private
- [ ] Publish to IPFS (needs Gregg's machine for public swarm)
