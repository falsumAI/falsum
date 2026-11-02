# BOUNTY PLAYBOOK

Gregg's order, 2026-10-30: hunt bugs across the internet, get paid in the
process of building. This is the money arm of the build.

## The landscape (researched 2026-10-30, honest numbers)

Platforms: HackerOne (3,000+ programs, $300M+ paid lifetime, ~$81M/yr),
Bugcrowd (1,000+ programs, $50M+ lifetime), Intigriti, Synack (invite-only,
higher payouts: criticals $10K-$30K+).

What findings actually pay (HackerOne 90-day data, 2026):
- Low $173 avg — 49% of resolved reports. Noise tier.
- Medium $1,500 avg — 39%. Subdomain takeovers, info disclosure.
- High $7,000 avg — 9%. Stored XSS, IDOR with data, SSRF, privesc.
- Critical $15,000 avg — 2.7%. RCE, auth bypass, mass account takeover.
- Weighted average per resolved report: ~$1,720. Report acceptance: 25-35%.

The honest math: 78% of hunters earn under $30K/yr; most new hunters make a
few hundred or nothing in year one. This is not a salary — it is a lottery
where skill buys tickets. Our edge is volume of quality recon, not luck.

2026 market notes: AI-assisted discovery flooded programs (Curl ended its
HackerOne program Jan 2026; HackerOne paused Internet Bug Bounty Mar 2026 —
too many AI-found bugs, not enough remediation). 82% of hackers use AI;
58% of researchers say AI misses business-logic flaws and chained exploits.
THE EDGE IS THERE: logic bugs and chains, not sprayed XSS.

## Our systematic edge

1. PASSIVE RECON AT SCALE. The OSINT module (crt.sh, Shodan public data,
   RDAP, DNS) enumerates subdomains and exposed services across every
   in-scope target without touching them. Dev/staging/admin panels,
   forgotten subdomains, dangling DNS — the medium-severity bread and
   butter ($500-$3,000 each), found passively.
2. FRESH VULNS. PHP2Shell (CVE-2026-109618/109619, disclosed Oct 21 2026,
   CVSS 9.2, ~70% of web on PHP) is NINE DAYS OLD. Programs with PHP in
   scope that haven't patched are live targets — where authorized.
3. COHERENCE. Every candidate gets converged attribution + a receipt before
   it goes near a report. No duplicate, no invalid, no burned reputation.
4. REPORT PIPELINE. The bugbounty module generates professional reports
   (summary, steps, impact, remediation) — triage teams process hundreds
   per week; clean reports get paid faster.

## THE SCOPE LAW (absolute, no exceptions)

Only test targets whose published bounty scope explicitly authorizes you.
Everything else: passive recon (public data) or your own systems ONLY.
Unauthorized access is a federal crime under the CFAA — a payout is not
worth a prison sentence. The module enforces this: no recorded scope, no
active tests. This law is not debated, not bent, not "just this once."

## Workflow

1. PICK: choose a program from the table below. Read its scope page fully.
   Record the scope URL in the bounty log BEFORE any recon.
2. RECON (passive): crt.sh subdomains, DNS records, Shodan public data,
   certificate transparency. Log candidates with evidence.
3. VERIFY: confirm the finding is real and in-scope. One candidate per run.
4. REPORT: generate via the bugbounty module. Gregg reviews.
5. SUBMIT: only on Gregg's explicit word, under his name/account.

## Program table (starting points — verify scope pages before recon)

- GitHub (HackerOne): https://hackerone.com/github?type=team — public program
  restructured 2026-07-27: fixed payouts Low $250 / Medium $2,000 / High $5,000 /
  Critical $10,000; invite-only VIP tier ($1k/$7.5k/$20k/$30k+) for 1 critical,
  2 high, 4 medium, or 7 low qualifying findings; HackerOne signal requirement
  (4 initial submissions for new researchers). Scope = published in-scope
  domain list on that page; *.github.com subdomains operated by third parties
  are OUT. Contact bounty@github.com when in doubt.
- HackerOne: hackerone.com — 3,000+ programs. Filter: broad scope, high
  signal requirements, bounty table published. Start with VDPs for practice,
  paid programs for money.
- Bugcrowd: bugcrowd.com — 1,000+ programs. Good for web/API specialists.
- Intigriti: intigriti.com — strong EU programs.
- Google VRP: $10K-$31K critical range. Hard targets, real money.
- Apple: up to $200K critical. Elite tier.
- Synack: invite-only. Goal once the track record exists.

Strategy: begin with 2-3 broad-scope programs, run passive recon across
all of them every run, log candidates. Depth beats breadth per target;
breadth across targets beats staring at one.

## Bounty log format (BOUNTY-LOG.md)

date | program | scope URL | target | finding | severity guess |
evidence | status (candidate/verified/reported/paid)
