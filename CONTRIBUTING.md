# Contributing to Falsum

Falsum is free for everyone, forever. Your contributions make the poison pill stronger.

## The deal

- **License:** GPL v3 for the community. Your PR also grants the copyright holder commercial licensing rights (see CLA.md — your PR is your signature).
- **Standard:** 25-year code standard. Write it like it has to run for 25 years.
- **Language:** Plain. If a 5-year-old or a blind grandmother can't understand what your feature does, rewrite the description.

## How to contribute

1. Fork the repo
2. Create a branch: `git checkout -b my-feature`
3. Make your changes
4. Test on Windows if you can (note it in your PR if you can't)
5. Push and open a PR using the template

## What we need most

- **Bug fixes** — especially in the PowerShell modules
- **New problem coverage** — check PROBLEMS.md for gaps
- **Translations** — Falsum should speak everyone's language
- **Documentation** — plain-language guides for non-technical users
- **Testing** — run it on your machine, report what breaks

## What we don't want

- Cloud dependencies in the core app
- Telemetry or tracking of any kind
- Subscription or payment code in the free version
- Code that phones home

## Code style

- **C#:** Follow the existing service patterns. Async for I/O, never block the UI thread.
- **PowerShell:** Every detection ships its fix. Backup before you change anything. Admin checks where needed.
- **Kotlin (Android):** No Google dependencies. Minimize permissions.

## Questions?

Open an issue. The maintainer (Gregg) reads every one.
