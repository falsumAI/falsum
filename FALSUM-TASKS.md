# FALSUM MASTER TASK LIST
# Everything Gregg ordered. Updated 2026-11-02 with all integrations.
# The 2-minute build worker works through this non-stop.

## CORE IDENTITY (done)
- [x] Name: Falsum (not Sentinel, not black box)
- [x] Free for people, paid for giants (GPL v3 + commercial dual, Big Tech $50K-$5M/yr)
- [x] Local software, NOT a website/cloud URL
- [x] User never sees PowerShell files (C# hosts them invisibly)
- [x] 25-year code standard
- [x] Poison pill: free + better + always current + community-driven

## GREGG'S ETHICS (foundation)
- [x] "More than ethical" — offensive action when defense can't win
- [x] Must SOLVE problems, not just log them — remediation engines required
- [x] Must be free — subscriptions are "the biggest scam of the entire tech world"

## THE 2,000 PROBLEMS — 40 categories (all in UI)
- [x] 1. Data brokers, 2. People-search, 3. Breach creds, 4. Passwords, 5. Phishing
- [x] 6. Smishing, 7. Vishing, 8. Deepfakes, 9. Romance scams, 10. Tech-support scams
- [x] 11. Grandparent scams, 12. Investment/crypto, 13. Job scams, 14. Rental scams, 15. Infostealers
- [x] 16. Ransomware, 17. RATs, 18. Stalkerware, 19. Adware/PUPs, 20. Wi-Fi
- [x] 21. Router, 22. MITM, 23. DNS, 24. Trackers/fingerprinting, 25. Social media
- [x] 26. Username OSINT, 27. Photo metadata, 28. Email headers, 29. Unpatched software, 30. PHP
- [x] 31. Weak home network, 32. IoT, 33. Mobile apps, 34. Financial fraud, 35. Medical fraud
- [x] 36. Tax fraud, 37. Mail/check fraud, 38. Family/insider, 39. Harassment/doxxing, 40. Enterprise gaps

## 45 MODULES (all in C# UI)
- [x] 00-coherence-core through 40-browser-liberator (40 modules)
- [x] 41-quantum-shield — Witness-only transmission logging, SHA-384 chain
- [x] 42-agent-watchdog — AI agent bodycam, tamper-evident log
- [x] 43-hashline — Browser traffic hasher, SHA-256 per body
- [x] 44-port-gate — Firewall companion, permanent bad-actor marks
- [x] 45-router-tracker — Router login capture and anomaly detection

## C# APPLICATION
- [x] MainWindow with all 45 module cards
- [x] ProtectAll orchestration
- [x] AIChatWindow, BrowserControlWindow, GovernmentWatchWindow, PriorArtWindow, SettingsWindow
- [x] NativeMessagingHost (extension bridge receiver)
- [x] PowerShellEngine, QuantumCoherenceEngine, LocalAIService
- [x] BrowserControlService, SystemPolicyService, PriorArtService
- [x] Bug fixes: NavButton style, shield.ico reference, unused package removed
- [ ] COMPILE VERIFICATION on Windows [NEEDS-GREGG-MACHINE]
- [ ] RUNTIME TEST on Windows [NEEDS-GREGG-MACHINE]

## LOCAL AI (Altman Challenge)
- [x] llama.cpp localhost:8080, lessons DB, deterministic self-correction (no warnings)
- [x] Real KL-divergence drift scoring, GreggDriftMeasure wired, poison pill check
- [x] Drift math locally verified (5/5 tests pass)
- [x] Model download automation in installer (2026-11-02: rewrote windows/Setup-AI.ps1 — RAM tiers, GitHub-API llama.cpp resolution, resumable downloads, GGUF/size checks, smoke test; INSTALL-FALSUM.ps1 calls it)
- [ ] Benchmark vs cloud AI [NEEDS-GREGG-VALIDATION]

## BROWSER EXTENSION
- [x] Manifest V3, content.js (13.5KB fingerprinting defense), background.js, popup
- [x] Native messaging both directions, real icons, Install-NativeHost.ps1
- [x] JS syntax verified clean
- [ ] LIVE TEST on Windows [NEEDS-GREGG-MACHINE]
- [ ] world: "MAIN" for strict-CSP pages

## ANDROID APP
- [x] FalsumVpnService.kt, PermissionAuditor.kt, StalkerwareScanner.kt
- [x] TrackerList.kt, VaultLogger.kt, MainActivity.kt
- [ ] COMPILE VERIFICATION [NEEDS-ANDROID-SDK]
- [ ] APK BUILD [NEEDS-ANDROID-SDK]

## GITHUB (falsumAI/falsum)
- [x] Public, README with badges, LICENSE-GPL, LICENSE-COMMERCIAL (hardened v2)
- [x] CLA.md, CONTRIBUTING.md, SECURITY.md, FUNDING.yml (sponsor button)
- [x] Issue/PR templates, 12 topics, description
- [x] Every-minute auto-push cron, 2-minute build worker cron
- [ ] CI workflow [NEEDS-TOKEN-WITH-WORKFLOW-SCOPE — file ready at /tmp/build.yml.workflows-pending]
- [ ] First release zip [NEEDS-GREGG-MACHINE for build]

## 7 GOVERNMENT SECTORS
- [x] Defense/Public Safety, Healthcare, Education, Tax & Revenue
- [x] Transportation, Judiciary, Citizen Services
- [x] GovernmentWatchWindow built

## REMAINING INTEGRATIONS
- [x] PrivescCheck (P0) — 2026-11-02, module 06
- [x] Snitch wrapper (AGPL — wrap, don't bundle) — 2026-11-02, module 37
- [x] AASIST deepfake detection — 2026-11-02, module 18 (Python ML wrapper, honest about weights)
- [ ] Merge Nuclei/Maigret/HardeningKitty side files into modules (already orchestrated, verify completeness)
- [x] Breach/dark-web monitoring — 2026-11-02, module 08 (HIBP-based, weekly scheduled)

## BUG BOUNTY (money)
- [x] Module 14, SCOPE LAW, BOUNTY-PLAYBOOK.md
- [x] Cloudflare PHP CTF scope logged ($3K per unique RCE)
- [ ] Passive recon results
- [ ] Gregg runs probes [NEEDS-GREGG]

## INVESTIGATION WEBSITE
- [x] Review copy built (5 pages), IPFS path proven
- [ ] Gregg decides: strip personal details for public, or keep private [AWAITING-GREGG]

## DESIGN LAWS
- [x] Better-way law, Gate law, CMD law, user controls all ports, one zip when done
