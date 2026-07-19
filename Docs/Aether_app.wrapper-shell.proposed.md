# Proposed Aether_app Wrapper / Shell Plan

This note describes a practical way to turn the current browser dashboard into an Android-friendly wrapper for `Aether_app`.

## Goal
Provide a lightweight Android shell that can:
- load the local/installable PWA dashboard UI
- expose the same Persian / English interface
- keep APK size small
- use Android build shrinking/optimization features such as **R8** and resource shrinking

## Suggested approach

### Option 1 — Flutter WebView wrapper
A minimal Flutter Android app with:
- one screen
- a full-screen WebView
- bundled local web assets from `termux-webapp/static`
- optional bridge methods for Android intents and file import/export

### Option 2 — Trusted Web Activity / PWA shell
If the dashboard is hosted somewhere stable, the app can be packaged as a TWA/PWA shell. For fully local/offline usage, the bundled WebView approach is simpler.

## Recommended Android optimizations
Inside `Aether_app/android/app/build.gradle.kts`:
- `isMinifyEnabled = true`
- `isShrinkResources = true`
- release build with **R8**
- remove unused ABIs if native binaries are not bundled in the wrapper
- keep rules only for the minimum required WebView / file-picker code

## Practical wrapper features
- splash screen matching the dashboard branding
- file picker for config import
- share sheet for QR/link export
- open external browser when needed
- optional offline local asset mode

## Why this helps
- users get an app-like launcher icon and splash screen
- smaller APK than a full native rewrite
- reuse of the already-built dashboard UX
- easier maintenance alongside upstream Aether changes

## Suggested release naming
- `Aether-web-shell.apk`
- `Aether-web-shell-arm64.apk`

## Notes
This wrapper would still be different from the full native Aether Android client. It is best treated as:
- a lightweight dashboard shell
- a companion app
- or a staging path before a deeper native integration
