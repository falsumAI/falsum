# Falsum Browser Bubble — Extension

The browser runs inside Falsum. This extension is the inner eye — the desktop app is the gate.

## What it does

- **Gates every navigation** — asks the desktop app before loading dangerous pages
- **Gates every download** — blocks malware file types, asks about executables
- **Blocks fingerprinting** — spoofs canvas, WebGL, audio, battery, fonts
- **Reports tracking** — every tracker, beacon, and pixel reported to the desktop vault
- **Monitors uploads** — large uploads flagged as potential exfiltration
- **Blocks tracking cookies** — third-party cookies from known tracker domains

## Architecture

```
Browser Tab → content.js (gate check + fingerprint shield)
     ↓
background.js (service worker — captures everything)
     ↓
Native Messaging → Falsum.exe (the gate — makes decisions)
     ↓
User consent → allow or block
```

**Fail-closed:** If the desktop app can't be reached, dangerous traffic is blocked.

## Install

1. Build Falsum on Windows (see BUILD-FALSUM.ps1)
2. Run INSTALL-FALSUM.ps1 — registers the native messaging host
3. Load this folder as an unpacked extension in Chrome/Edge (chrome://extensions → Developer mode)

## Permissions

- `nativeMessaging` — talk to the desktop app
- `tabs`, `webNavigation`, `webRequest` — see what the browser does
- `downloads` — gate downloads
- `cookies` — block tracking cookies
- `storage`, `alarms` — local state, heartbeat

## Files

- `manifest.json` — MV3 manifest, v2.0.0
- `background.js` — service worker, message routing, gate client
- `content.js` — page shield (runs at document_start), gate check
- `popup.js` / `popup.html` — status popup with gate state
