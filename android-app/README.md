# Falsum Android App

Native Android security app. Free APK distributed outside Google Play Store
(F-Droid compatible). **No Google Play Services. No Firebase. No analytics.**
The only dependency is the Kotlin stdlib.

## What it does

- **Local VPN tracker filter** (`FalsumVpnService.kt`) — a `VpnService` that
  creates a TUN interface and inspects packets on-device:
  - DNS queries to tracker / ad / stalkerware-C2 domains are sinkholed
    locally (answered with 0.0.0.0 — the query never leaves the phone).
  - Other UDP is forwarded through protected sockets.
  - TCP is relayed through a minimal userspace TCP state machine
    (handshake, seq/ack bookkeeping, bidirectional relay).
  - No root required. Filtering decisions use the `TrackerList` shipped
    in the APK; nothing is sent anywhere for "analysis".
- **Permission auditor** (`PermissionAuditor.kt`) — enumerates installed
  packages via PackageManager, scores GRANTED dangerous permissions, and
  flags exfiltration combos (e.g. READ_SMS + INTERNET).
- **Stalkerware scanner** (`StalkerwareScanner.kt`) — checks installed
  packages against the 49-package signature table mirrored from desktop
  module 24 (`windows/modules/24-mobile-shield/`), plus heuristics for
  hidden-icon + sensitive-permission spyware not yet in the table.
- **Vault** (`VaultLogger.kt`) — SHA-256 hash-chained local event log,
  same concept as the desktop vault. Tamper-evident; verifiable.

## Building

Requires the Android SDK (build toolchain only — not a runtime dependency).

```bash
cd android-app
./gradlew assembleDebug        # or assembleRelease
# APK: app/build/outputs/apk/debug/app-debug.apk
```

Install directly on the phone (`adb install`) or distribute the APK yourself.
`minSdk 26` (Android 8.0+).

## Project layout

```
android-app/
├── build.gradle / settings.gradle / gradle.properties
└── app/
    ├── build.gradle
    └── src/main/
        ├── AndroidManifest.xml
        └── java/ai/falsum/
            ├── MainActivity.kt        # plain-language UI
            ├── FalsumVpnService.kt    # TUN packet filter
            ├── TrackerList.kt         # tracker/C2 domain blocklist
            ├── PermissionAuditor.kt   # permission overreach audit
            ├── StalkerwareScanner.kt  # 49-package stalkerware scan
            └── VaultLogger.kt         # hash-chained local log
```

## Status

Working skeleton with real structure: the VPN service, DNS sinkholing,
TCP/UDP relay, audits, and scanner are implemented. Hardening items for
the next pass: TCP retransmission/out-of-order buffering, IPv6, DoH/DoT
interception, per-app allow/block UI, and a polished Fluent-style design
replacing the programmatic skeleton UI.
