# Falsum Value Research — Real Tools to Integrate

> Lazy smart engineer doctrine: don't write what already exists. Find real open-source
> code, wrap it in PowerShell, add Falsum's vault + fix functions. The value is
> orchestration, remediation, and the unified interface — not reinventing scanners.

Research date: 2026-11-02. All repos verified public on GitHub.

---

## 1. Windows Privilege Escalation Checkers

### PrivescCheck — https://github.com/itm4n/PrivescCheck
- **What:** PowerShell script that enumerates Windows misconfigurations enabling local
  privilege escalation (unquoted service paths, weak service ACLs, AlwaysInstallElevated,
  writable PATH, DLL hijacking, scheduled task abuse, UAC bypass vectors).
- **License:** Not specified in search results — verify before bundling. (itm4n's other
  work is typically permissive; check the repo LICENSE file.)
- **Why Falsum needs it:** Module 06 (vuln-check) audits the local machine but doesn't
  check privesc vectors. An attacker who lands on the box uses exactly these paths.
  Gregg's investigation (phantom enterprise control, Codex running as SYSTEM) is a
  privesc story — this tool finds how.
- **Integration:** Download PrivescCheck.ps1 to `$env:LOCALAPPDATA\Falsum\tools\`,
  dot-source it, run `Invoke-PrivescCheck`, parse output objects, log each finding
  to the vault, map each finding type to a Falsum fix function
  (e.g., unquoted service path → quote it + restart service; weak ACL → icacls reset).
  Pure PowerShell — zero new dependencies.

### winPEAS — https://github.com/peass-ng/PEASS-ng (winPEAS subdirectory)
- **What:** The standard Windows privilege escalation enumerator. Checks services,
  registry, credentials in files, named pipes, Potato-exploit preconditions,
  disconnected high-privilege RDP sessions, LSASS accessibility.
- **License:** Verify in repo (PEASS-ng is open source; confirm license file).
- **Why Falsum needs it:** Deeper than PrivescCheck, catches what the script misses.
  The Nov 2026 PR #538 added checks for Potato-family escalation and RDP session
  abuse — directly relevant to enterprise-control scenarios.
- **Integration:** Download winPEASx64.exe release binary, run with output redirect,
  parse the color-coded text output for the red/yellow findings, vault-log them.
  Heavier than PrivescCheck — offer as "deep scan" option in module 06.

---

## 2. Browser Privacy Tools

### FingerprintJS (open-source edition) — https://github.com/fingerprintjs/fingerprintjs
- **What:** The most advanced open-source browser fingerprinting library. Computes a
  stable visitor ID from 50+ browser attributes (canvas, WebGL, audio, fonts, etc.).
- **License:** BSL (Business Source License) — free for non-production. Verify terms.
- **Why Falsum needs it:** Adversarial testing. Falsum's extension claims to block
  fingerprinting — prove it by running FingerprintJS against the protected browser
  and showing the ID changes every session (or that collection is blocked).
  "We spoof fingerprinting — here's the proof" is a trillion-dollar demo.
- **Integration:** Bundle the OSS script in the extension's test page. Add a
  "Test my fingerprint protection" button that runs FingerprintJS twice with
  different sessions and compares. Log results to the desktop app via the bridge.

### Privacy extension stack (all open source, Manifest V3)
These are the six vetted in 2025-2026 guides — Falsum's extension should match or
exceed their coverage, or recommend them as companions:
- **uBlock Origin Lite** — network-level ad/tracker blocking
- **Privacy Badger** (EFF) — heuristic tracker detection
- **Cookie AutoDelete** — cookie/localStorage cleanup on tab close
- **ClearURLs** — strips tracking parameters from URLs
- **Canvas Blocker** — fingerprint randomization (fake mode returns plausible noise)
- **LocalCDN** — replaces Google Fonts / jQuery CDN with local copies
- **Why Falsum needs them:** Module 22 (tracker-block) + the extension must cover
  every vector these cover. Where Falsum's extension already does it, document parity.
  Where it doesn't (e.g., LocalCDN's CDN localization), add it — don't leave gaps
  that a free extension fills.

### Helium browser — https://github.com/imputnet/helium (21.8k stars, GPL-3.0)
- **What:** Privacy-first Chromium fork (from ungoogled-chromium) with built-in
  uBlock Origin, fingerprinting protections, no Google service integration.
- **Why Falsum needs it:** Reference implementation. Study how Helium does
  fingerprinting protection at the browser level — Falsum's extension does it at
  the content-script level. Where Helium's approach is stronger, adapt the technique.

---

## 3. Android Security Tools

### AndroDR — https://github.com/yasirhamza/AndroDR
- **What:** Open-source Android security scanner. Checks installed apps against
  stalkerware/malware databases (AssoEchap/stalkerware-indicators on GitHub),
  flags dangerous permission combinations, checks spyware C2 domains
  (mvt-project/mvt-indicators — Pegasus, Predator, RCS Lab campaigns).
  Fully offline-capable. No accounts, no telemetry.
- **License:** Verify in repo (project emphasizes open source).
- **Why Falsum needs it:** Module 24 (mobile-shield) has a 49-package signature DB.
  AndroDR's database is larger and maintained. The Falsum Android app's
  StalkerwareScanner.kt should pull from the same indicator sources
  (AssoEchap/stalkerware-indicators) rather than maintaining a separate list.
- **Integration:** For the Android app: study AndroDR's
  `app/src/main/java/com/androdr/scanner/` detection logic, adapt the permission-
  combination heuristics. For the Windows side: module 24 can already scan
  Android backups — add AndroDR's indicator URLs as additional sources.

### ISDi (IPV Spyware Discovery) — https://github.com/stopipv/isdi
- **What:** Checks Android/iOS devices for intimate-partner-violence spyware
  ("stalkerware", "spouseware"). `pip install isdi-scanner`. Needs adb for Android.
  Research-backed (USENIX 2019).
- **Why Falsum needs it:** Different threat model from generic malware — IPV
  stalkerware is installed by someone with physical access. Falsum's mobile-shield
  should distinguish "malware from the internet" from "spyware from your partner"
  because the remediation is different (the latter needs safety planning, not just
  uninstall).
- **Integration:** PowerShell wrapper: check for adb, `pip install isdi-scanner`,
  run scan against connected Android device, parse output, vault-log. Add a
  "safety resources" pointer in the output (don't just say "stalkerware found" —
  link to NNEDV Safety Net).

### Zero-Breach-Toolkit — https://github.com/gl00myb0y/Zero-Breach-Toolkit
- **What:** Free, open-source, offline checks for mercenary spyware traces
  (Pegasus, Predator, Candiru/DevilsTongue, Paragon Graphite). 12,400 indicators
  from 29 sources (Amnesty Security Lab, MVT, Citizen Lab). Works on Windows,
  macOS, Linux, Android phones, iPhone backups.
- **License:** Apache-2.0.
- **Why Falsum needs it:** This is the "am I targeted by nation-state spyware"
  check. No other free tool does this offline. Falsum's mobile-shield + evidence
  modules should offer it as the deepest scan tier.
- **Integration:** Clone or pip-install, run `scan/zero-breach-toolkit.py` against
  the target (local machine or phone backup), parse the report (it states its own
  limits honestly — preserve that), vault-log findings.

---

## 4. Network Monitors

### Snitch — https://github.com/aixisstudio/Snitch
- **What:** Real-time network monitor + outbound firewall. See and block every
  connection. Privacy-first, local-first, 100% local. Cross-platform
  (Windows/macOS/Linux). AGPL-3.0. Explicitly a free Little Snitch / GlassWire
  alternative — no account, no telemetry, no paywall.
- **Why Falsum needs it:** Module 37 (datagate) currently uses
  `Get-NetTCPConnection` polling — it works but it's not real-time and has no
  blocking UI. Snitch IS the data-movement gate Gregg asked for, already built,
  already open source. Falsum should either bundle it, recommend it, or study
  its Rust implementation for the blocking logic.
- **Integration (lazy smart):** Don't rewrite datagate. Add a Falsum function
  `Install-FalsumSnitch` that downloads the Snitch release, and
  `Start-FalsumSnitchMonitor` that launches it. Falsum's value-add: the vault
  logging of Snitch's decisions + the one-click "block everything except..."
  profiles for non-technical users. Note the license is AGPL — bundling has
  implications; recommending + wrapping is cleaner.

### Sniffnet — https://github.com/gyulyvgc/sniffnet
- **What:** Rust open-source network monitor with a visual dashboard. Passive
  packet capture (Npcap on Windows), per-application bandwidth, GeoIP, threat
  intel lookups, PCAP export.
- **Why Falsum needs it:** Visual proof for the user. Module 02 (packet-witness)
  uses pktmon — powerful but CLI-only. Sniffnet gives the "trillion-dollar look"
  — a dashboard a non-technical user can understand.
- **Integration:** Recommend as the visual companion to packet-witness. Or: study
  its per-application attribution logic for module 37's process-to-connection
  mapping.

### Portmaster — https://github.com/safing/portmaster
- **What:** Open-source application firewall for Linux/Windows. Per-app network
  rules, DNS filtering, SPN (VPN) integration.
- **Why Falsum needs it:** Reference for module 32 (port-control) + module 37
  (datagate). Portmaster's per-app rule engine is the model for "user chooses
  whether data leaves."

---

## 5. Pain-Point Gaps (from PROBLEMS.md)

### Category 8: AI voice cloning and deepfakes (351-400) — PARTIAL
Current state: verification workflow only (family code words, "hang up and call back").
No ML detection. Problem 368: "No detection tools available to regular people."

**Real tools to integrate:**
- **AASIST** — https://github.com/clovaai/aasist — graph-attention audio deepfake
  detector, ~50ms inference (real-time capable). Python + PyTorch.
- **Resemblyzer** — https://github.com/resemble-ai/Resemblyzer — speaker embedding
  comparison. Enroll a family member's voice once, compare incoming call audio
  against the embedding. 1000x real-time.
- **Integration:** New module 38 (deepfake-guard). PowerShell wrapper that:
  1. Records or ingests a suspicious call (user plays it into the mic or uploads).
  2. Runs AASIST via Python for AI-vs-human classification.
  3. Optionally compares against enrolled family voiceprints via Resemblyzer.
  4. Returns a verdict + confidence, vault-logged. The fix: "This call is 94%
     likely AI-generated. Hang up. Call them back on a known number."

### Category 25: Social media exposure (1201-1250) — DISCOVERY-GRADE
Problems: location tags, vacation posts, kids' photos with school names, security-
question answers in posts, license plates in photos, etc.

**What's missing:** No module audits the user's OWN social media footprint.
**Integration path (no new external tool needed — use existing):**
- Extend module 04 (OSINT): the Maigret integration already finds accounts by
  username. Add a "self-audit" mode: user provides their own usernames, Falsum
  pulls their public profiles and flags exposure patterns (location tags, birthdate
  in bio, school names in photos via alt-text, etc.).
- Extend module 17 (photo-scrub): before stripping metadata, SCAN the image
  for visible PII (house numbers, license plates, school names) and warn.
  (This needs a vision model — TinyLlama can't do vision. Flag as requiring
  LLaVA or similar in the local model roadmap.)

### Category 32: IoT device exposure (1551-1600) — DISCOVERY-GRADE
Problems: default credentials on cameras, Shodan-exposed devices, Tuya phoning
home, unpatchable firmware, smart TV screenshots.

**Real tools to integrate:**
- **Nuclei IoT templates** — the nuclei-templates repo has a dedicated
  `http/misconfiguration/` and IoT section. Falsum's module 06 Nuclei integration
  should include `-tags iot` scans against the user's LAN.
- **Integration:** Extend module 03 (netscan): after discovering LAN hosts,
  run Nuclei with `-tags iot,default-credentials` against each. Map findings to
  fixes (change default password → provide the device's manual link; block
  WAN access → firewall rule).

---

## 6. Government AI Sector Gaps

`docs/GOVERNMENT-SECTORS.md` covers 7 sectors. Gaps found in research:

1. **Education AI monitoring:** Student proctoring AI (e.g., Respondus, Proctorio)
   does screen recording, eye tracking, room scans. Falsum's browser extension
   should detect and report proctoring scripts — students have a right to know
   when they're being surveilled. (Add to extension's hidden-action detection.)

2. **Welfare/benefits algorithms:** Automated eligibility denials with no
   explanation. Falsum's vault is the citizen's counter-record: log every
   interaction with benefits portals (timestamps, what was submitted) so a
   wrongful denial can be appealed with evidence.

3. **Predictive policing:** Crime-pattern AI trained on biased data. Falsum
   can't fix the algorithm, but module 09 (broker eradicator) + module 24
   (mobile shield) reduce the data exhaust that feeds it.

---

## 7. Integration Priority (lazy-smart order)

| Priority | Tool | Module | Effort | Impact |
|----------|------|--------|--------|--------|
| P0 | PrivescCheck | 06 vuln-check | Low (PS1 wrapper) | Finds how attackers escalate — core to Gregg's case |
| P0 | Snitch | 37 datagate | Low (recommend + wrap) | Real data-movement gate, already built |
| P1 | AASIST | 38 deepfake-guard (new) | Medium (Python bridge) | Only real deepfake detection for regular people |
| P1 | AndroDR indicators | 24 mobile-shield | Low (URL list) | Bigger stalkerware DB, maintained upstream |
| P1 | ISDi | 24 mobile-shield | Low (pip wrapper) | IPV-specific threat model |
| P2 | Nuclei iot tags | 03 netscan | Low (add flag) | IoT default-credential scanning |
| P2 | FingerprintJS test | browser-extension | Low (test page) | Proof the anti-fingerprinting works |
| P2 | winPEAS | 06 vuln-check | Low (binary run) | Deep privesc scan option |
| P3 | Zero-Breach-Toolkit | 24 mobile-shield | Medium | Nation-state spyware check |
| P3 | Resemblyzer | 38 deepfake-guard | Medium | Family voiceprint verification |

**License check required before bundling:** PrivescCheck, winPEAS, AndroDR, Snitch
(AGPL — wrap don't bundle), FingerprintJS (BSL).
**Safe to bundle:** Zero-Breach-Toolkit (Apache-2.0), ISDi (verify), Sniffnet
components (MIT/Apache).

---

## 8. What NOT to Build From Scratch (ever)

- Another vulnerability scanner (use Nuclei)
- Another username enumerator (use Maigret)
- Another hardening checklist (use HardeningKitty)
- Another privesc checker (use PrivescCheck)
- Another network monitor (use/wrap Snitch)
- Another deepfake detector (use AASIST)
- Another stalkerware DB (use AndroDR/AssoEchap indicators)

**Falsum builds:** the vault, the fix functions, the unified UI, the local AI
narrator, the bridge between desktop/browser/Android, the one-click workflows,
the evidence packaging. That is the product. Everything else is integration.
