# Falsum

Free, local, transparent security for the everyday person. The poison pill for the subscription security industry and cloud AI.

## What it is

Falsum (Latin: deception, falsehood — named for everything Big Tech told you about privacy, security, and AI) is a Windows security application with a linked browser extension and Android app. It sits installed on your computer. Not a website. Not a cloud subscription. It uses the internet only for lookups you trigger and for updates.

It does everything the paid tools do — vulnerability scanning, malware hunting, data broker removal, breach monitoring, tracker blocking, fingerprinting defense — free, locally, with fixes not just reports.

## The poison pill

Norton charges $99/year. McAfee charges $89/year. DeleteMe charges $129/year. ChatGPT Plus charges $20/month. 

Falsum does what all of them do, free, on your machine. Once it exists and works, charging a subscription for this becomes absurd. That's the pill — Wikipedia did it to Britannica, Falsum does it to the security and AI subscription industries.

## License

Free under GPL v3 for open-source use. See LICENSE-GPL.

Companies wanting proprietary use without GPL obligations: commercial license available. See LICENSE-COMMERCIAL. Contact the copyright holder.

Contributors: you must sign the CLA before your pull request is merged. See CLA.md.

## Structure

- `windows/` — Desktop application (console, WinForms, WPF launchers + 34 PowerShell modules)
- `browser-extension/` — Manifest V3 extension, linked to the desktop app via native messaging bridge
- `android-app/` — Native Android app (Kotlin), distributed as free APK outside Google Play Store
- `docs/` — Architecture, audit reports, implementation guides

## Building

Windows: run `windows/INSTALL.bat` as Administrator.
Extension: load `browser-extension/` in Chrome developer mode, run the native host installer.
Android: build with Android Studio, install the APK directly.

## Contributing

Read CLA.md first. All contributions stay under GPL v3 for the community. Commercial licensing is handled separately by the copyright holder.
