# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Email: falsum.ai@proton.me
Subject: "Falsum Security Report"

Include:
- What the vulnerability is
- How to reproduce it
- What the impact could be

You will get a response within 48 hours. If the vulnerability is confirmed, it will be fixed and you will be credited (unless you prefer to stay anonymous).

## Scope

Falsum is local-first security software. The following are in scope:

- The Windows application (C# / PowerShell)
- The browser extension
- The Android app
- The installer

The following are NOT vulnerabilities:

- Falsum requiring admin for system-level operations (by design)
- The local AI needing ~4GB disk for the model (documented)
- PowerShell execution policy bypass in the installer (required to run modules)

## Bug bounties

Falsum does not currently offer paid bounties, but security researchers who report valid vulnerabilities get:
- Public credit in the release notes
- A permanent spot in CONTRIBUTORS.md
- Our genuine thanks
