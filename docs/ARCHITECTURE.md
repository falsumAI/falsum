# BLACKBOX — Architecture

## Mission

One free Windows-native program that does what the entire commercial security
industry sells separately — and fixes problems instead of logging them.
Built for the everyday end user first, not the enterprise SOC.

## Who it serves

The person with no security team, no budget, and no patience for dashboards
full of red alerts. Identity theft hit 36 million Americans in 2025 ($38B
lost). Infostealer malware harvested 1.8 billion credentials from 5.8 million
devices. AI-enabled fraud grew 1,210% year over year. Adults over 60 lost
$7.75 billion at $38,500 per victim. Every one of those victims needed a tool
that finds the problem AND fixes it. None existed. This is that tool.

## The twist — why this is not another toolbox

Seven things no existing tool combines:

1. END USER FIRST. Plain language. One action answers one question. No
   600-tool firehose. (Kali's documented failure: "running tools without
   understanding output and confusing noise with evidence.")
2. WORKFLOW, NOT TOOLBOX. Guided investigations: "am I breached?" runs the
   full chain — breach check, process sweep, network witness, attribution —
   and reports one verdict.
3. SOLVE, NOT LOG. Every finding carries a fix. Remediation engines with
   backup and rollback. Post-fix verification proves the fix worked.
4. COHERENCE CORE. Gregg's deterministic coherence framework scores evidence
   convergence across every module. No probabilistic guessing. Every
   conclusion ships a verifiable receipt.
5. FREE FOREVER. No subscription. No tiers. No "pro" unlock. The subscription
   model is the scam this tool kills.
6. WINDOWS-NATIVE. The victims are on Windows. The tool runs where they are.
   No Linux install, no VM, no dual boot.
7. EVIDENCE-GRADE. Every output SHA-256 hashed, timestamped, chain of
   custody. A regular person can hand the evidence pack to police, a lawyer,
   or a reporter and it holds up.

## Module map

01. EVIDENCE SWEEP — automates the full machine-state capture: systeminfo,
    netstat with process attribution, tasklist, schtasks, services, drivers,
    registry keys, firewall rules, hosts file, event logs, bcdedit,
    dsregcmd, certificates, browser extensions. Every output hashed,
    timestamped, manifest-bundled.
02. PACKET WITNESS — pktmon capture. DNS queries, TLS SNIs, per-flow byte
    counts. Hashed pcaps. Answers: what is actually leaving this machine.
03. NETSCAN — TCP SYN scan, UDP scan, service banners, OS fingerprint basics.
    For the user's own network and localhost.
04. OSINT ATTRIBUTION — every external IP/domain gets RDAP/ASN lookup,
    Shodan/Censys queries, crt.sh for domains, breach-data correlation.
    Every query logged for the dossier.
05. PEOPLE TRACK — username and email intelligence: Maigret-class multi-site
    dossier, Sherlock-class quick checks, Holehe-class registration checks,
    GHunt-class Google footprint, breach-data matching. Scored matches,
    never binary guesses.
06. VULN CHECK — Nuclei-class template scanning against the user's own
    systems, missing-patch detection, weak-config flags. Reports, never
    exploits.
07. PHP SHIELD — version detection, CVE matching (PHP2Shell and beyond),
    mitigation application, verification. Proof case from Oct 2026: 70% of
    the web exposed, most owners unaware of their PHP version.
08. BREACH CLEANER — finds the user's exposed credentials in breach data,
    drives rotation, verifies the rotation took.
09. BROKER ERADICATOR — automated opt-out across hundreds of data brokers,
    on a schedule, free forever. Brokers relist; the tool re-fires.
    This kills the $129-500/yr subscription farm.
10. TRAP NETWORK — automated decoy listeners and fake services. Logs every
    probe, credential attempt, and payload. Hashed into the vault.
11. ACTIVE DEFENSE — backtrace/scan-back on hostile endpoints, session kill
    on the user's own wire, abuse-report pipeline with evidence packs,
    permanent bad-actor marking. Exploit intelligence prepared; the trigger
    stays manual with the legal exposure stated once, plainly.
12. TIMELINE + VAULT — chronological merge of all module outputs.
    SHA-384 hash-chained ledger. Exportable evidence packs.

## The coherence core

NATIVE FIRST: the intelligence runs on the user's machine, no cloud in the
investigative path. Full spec in NATIVE-INTELLIGENCE.md. The coherence core
ships as deterministic code; the local model is the mouthpiece, never the
authority.

Interface specification. Formalization is Gregg's math and needs his
validation at every step. The core exposes four functions to every module:

- COHERENCE SCORE: each evidence item checked against every other item.
  Process claiming a socket vs binary on disk. DNS query vs TLS SNI.
  RDAP org vs ASN geography. Converged evidence scores toward zero.
  Diverged evidence is flagged as drift, never silently dropped.
- ATTRIBUTION CONVERGENCE: N sources pointing at one entity measured for
  convergence. Converged attribution ships with a receipt. Diverged
  attribution is labeled uncertain with the divergence shown.
- DRIFT DETECTION: machine baseline vs current state. Deterministic.
  Anything climbing away from baseline gets flagged.
- VERIFIABLE RECEIPTS: every conclusion carries its evidence chain,
  hash-chained. Same evidence in, same verdict out, every time.

## Open-source tool catalog (integration map)

Researched Oct 30, 2026. Each maps to a BLACKBOX module. Nothing reinvented
where open source already solved it; the value is the integration, the
workflow, the coherence scoring, and the remediation.

PEOPLE: Maigret (3,000+ sites, recursive, no API keys) / Sherlock (400+,
scriptable) / Social-Analyzer (1,000+, 0-100 rating, OCR) / Blackbird
(username+email) / WhatsMyName dataset.
EMAIL/BREACH: Holehe (120+ sites via reset flows) / GHunt (Google footprint) /
h8mail (breach credential hunting) / Mosint / Epieos.
DOMAIN: Subfinder (35+ passive sources) / Amass / theHarvester (emails, names,
IPs) / dnsx / httpx / crt.sh.
VULN: Nuclei (12,000+ templates, 4,400 CVEs, MIT) / Naabu / Katana / tlsx /
uncover.
FRAMEWORK LESSONS: SpiderFoot (200+ modules but aging, OSINT-only, no
remediation) / HexStrike AI (150+ tools via MCP, but agent-oriented and
Linux-only) / Kali (600+ tools, no workflow, Linux-only, overwhelms).

## Value ledger

Per-user replaced commercial value (verified prices, Oct 30, 2026):
Nessus Pro ~$4,790 + Burp Pro ~$475 + Maltego ~$3,270 + data-broker removal
~$150 + Shodan $49 + pentest engagement amortized ~$9,000 = ~$18,000/yr.
The trillion-dollar case rests on prevented damage: cybercrime ~$10.5T/yr
globally, driven by the alert-to-remediation gap (Teleskope Aug 2026: tools
detect, none fix). Ledger kept in VALUE-LEDGER.md, updated per module.

## Build order

01 sweep+vault first (Gregg's investigation needs it now) -> coherence core
with his validation -> packet witness + OSINT -> remediation engines ->
broker eradicator. Each module standalone, each shippable, each growing
the value ledger.

## Ethics

Gregg's, in his words: the end user is sovereign over their own machine and
network. Defense alone doesn't win wars. Offensive action is legitimate
against those attacking the user and end users — retributive, not predatory.
Evidence first: document everything. Legal reality stated once, plainly:
unauthorized access to someone else's system is a federal crime under the
CFAA even if they attacked first. What happens on the user's own machine
and wire is the user's business.
