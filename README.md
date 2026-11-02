# Falsum

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE-GPL)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Android%20%7C%20Chrome-blue)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Free, local, transparent security for the everyday person. The poison pill for the subscription security industry and cloud AI.**

> Norton charges $99/year. McAfee charges $89/year. DeleteMe charges $129/year. ChatGPT Plus charges $20/month.
>
> Falsum does what all of them do — free, on your machine, with fixes not just reports.

## What it is

Falsum (Latin: *deception, falsehood* — named for everything Big Tech told you about privacy, security, and AI) is a Windows security application with a linked browser extension and Android app.

- **Not a website.** Not a cloud subscription. It sits installed on your computer.
- **45 security modules** — vulnerability scanning, malware hunting, data broker removal, breach monitoring, tracker blocking, fingerprinting defense, scam detection, and more.
- **Local AI** — talks to a model running on your machine. Learns from your corrections. Self-corrects with drift math. No tokens, no cloud, no data leaving your computer.
- **Every detection ships its fix.** Falsum doesn't just tell you what's wrong — it fixes it.

## Quick start

**Windows:** Download the latest release, run the installer as Administrator.
**Browser:** Load `browser-extension/` in Chrome developer mode, run the native host installer.
**Android:** Download the APK from releases, install directly (no Play Store needed).

## The poison pill

Wikipedia did it to Britannica. Falsum does it to the security and AI subscription industries.

Once free, local, transparent security exists and works, charging a subscription for it becomes absurd. That's the pill.

## License

**Free for people. Paid for giants.**

- **Individuals, nonprofits, open-source projects, researchers:** free forever under GPL v3. See LICENSE-GPL.
- **Companies with revenue over $10M, or anyone embedding Falsum in proprietary products:** you MUST purchase a commercial license. See LICENSE-COMMERCIAL. Big Tech does not get a free ride — every dollar funds the free version that makes their subscriptions irrelevant.
- **Patent protection:** Falsum's methods are defensively published via the Prior Art Vault. Any company that files patents on Falsum's algorithms automatically loses their license.

Contributors: you must sign the CLA before your pull request is merged. See CLA.md.

## Structure

- `windows/` — Desktop application (C# WPF + 45 PowerShell modules)
- `browser-extension/` — Manifest V3 extension, linked to the desktop app via native messaging
- `android-app/` — Native Android app (Kotlin), distributed as free APK outside Google Play Store
- `docs/` — Architecture, audit reports, implementation guides

## Contributing

We need bug fixes, new problem coverage, translations, documentation, and testing. See CONTRIBUTING.md.

## Security

Found a vulnerability? See SECURITY.md. Do not open a public issue.
