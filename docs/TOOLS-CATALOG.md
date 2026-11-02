# BLACKBOX — Open-Source Tool Catalog

Researched Oct 30, 2026. Integration map: what each tool does, which
BLACKBOX module absorbs it, and what BLACKBOX adds (workflow + coherence
scoring + remediation + free).

## People / username

- Maigret (soxoj) — 3,000+ sites, recursive search, profile parsing, no API
  keys, Tor support, web UI. -> Module 05. BLACKBOX adds: coherence-scored
  matches, one-click dossier, evidence receipts.
- Sherlock — 400+ sites, scriptable CLI. -> Module 05 quick-check mode.
- Social-Analyzer (qeeqbox) — 1,000+ sites, 0-100 match rating, OCR.
  -> Module 05 scoring layer.
- Blackbird — username + email, PDF reports. -> Module 05.
- WhatsMyName dataset — community site signatures, open license.
  -> Module 05 detection data.

## Email / breach

- Holehe (megadose, 15k stars) — 120+ sites via password-reset flows, silent.
  -> Module 08.
- GHunt (mxrch, 20k stars) — Google account footprint. -> Module 05/08.
- h8mail (khast3x, 5.3k stars) — breach credential hunting, local breach
  files. -> Module 08. BLACKBOX adds: rotation workflow, not just lookup.
- Mosint, Epieos — email intel automation. -> Module 08.

## Domain / network

- Subfinder (ProjectDiscovery, 12.5k stars) — 35+ passive sources, Go.
  -> Module 04.
- Amass (OWASP) — active + passive enumeration. -> Module 04.
- theHarvester — emails, subdomains, names, IPs. -> Module 04.
- dnsx, httpx, tlsx — resolution, probing, cert analysis. -> Module 04.
- crt.sh — certificate transparency. -> Module 04.
- Shodan / Censys (free tiers) — infrastructure. -> Module 04.

## Vulnerability

- Nuclei (ProjectDiscovery, 29k+ stars, MIT) — 12,000+ templates, 4,400
  CVEs. -> Module 06. BLACKBOX adds: auto-remediation for fixable findings.
- Naabu — port discovery. -> Module 03.
- Katana — web crawling. -> Module 06.
- uncover — multi-engine host queries. -> Module 04.

## Framework lessons (what not to repeat)

- SpiderFoot: 200+ modules, but last major release aging, OSINT-only, no
  remediation, no coherence. Lesson: modules without a decision layer are
  noise.
- HexStrike AI: 150+ Kali tools via MCP, 9k stars, but agent-oriented and
  Linux-only. Lesson: the integration idea is right; the audience is wrong.
- Kali: 600+ tools, no workflow, Linux-only, documented beginner failure
  mode ("confusing noise with evidence"). Lesson: workflow beats toolbox.

## The 20000x

Not 20000 tools. One workflow where every finding is coherence-scored,
every problem carries its fix, every conclusion ships a receipt, and the
price is zero. None of the above does all four.
