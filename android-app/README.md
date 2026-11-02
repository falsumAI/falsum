# Falsum Android App

Native Android security app. Free APK distributed outside Google Play Store. No Play Services dependency. F-Droid compatible.

## Architecture

- `VpnFilterService.kt` — Local VPNService for tracker filtering. No root required. No data leaves the device.
- `PermissionAuditor.kt` — Maps every installed app's permissions, flags overreach.
- `StalkerwareScanner.kt` — Extends the 49-package signature database to Android packages.
- `VaultLogger.kt` — SHA-384 hash-chained logging, same format as desktop.
- `BridgeClient.kt` — Talks to desktop app on LAN for unified threat picture.

## Building

Open in Android Studio. Min SDK 26. Build APK. Distribute directly — no Play Store.

## Status

Skeleton. Implementation guide in docs/android-implementation.md.
