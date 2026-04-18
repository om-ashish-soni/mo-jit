# mo-jit Terminal — Android app

The first product built on mo-jit: a standalone terminal app that ships a fully isolated, native-speed Debian userland on stock unrooted Android.

## Vision

"Termux but with real isolation, real native speed on Debian, and real upstream packages."

- Installs as a normal APK. Target: Play Store + F-Droid + GitHub Releases.
- No root, no Shizuku, no ADB pairing, no custom ROM.
- Target devices: Android 10+ arm64 (covers ~97% of active arm64 devices in 2026).

## First-run flow

1. User installs the APK (~8–12 MB).
2. App opens to a welcome screen explaining the download.
3. Downloads the Debian slim rootfs (~220 MB, resumable, progress-reported, SHA256-verified).
4. Extracts into `filesDir/rootfs-debian/lower/` (read-only).
5. Opens into a `bash` prompt inside the isolated guest. Full internet. `apt` ready. Node, Python, git, gh pre-installed.

Total time to first prompt on a mid-range 2024 device on WiFi: target ≤90 seconds.

## Day-1 features

- **Sessions:** multiple concurrent PTY sessions, persistent across screen-off and Doze (foreground service + notification channel).
- **Keyboard extras bar:** Ctrl / Esc / Tab / arrows / Home / End / PgUp / PgDn / `|` / `/` / `-` / `~` / custom-configurable.
- **Selection + clipboard:** long-press to select, Android clipboard integration.
- **Font + color:** bundled monospace fonts, light/dark theme, terminal color scheme picker.
- **Storage bridge:** `$HOME/storage/shared` → Android `/sdcard` (opt-in, requires `MANAGE_EXTERNAL_STORAGE`).
- **Share-intent:** "Open in mo-jit Terminal" target for text files from any app (drops into a `vim` session inside the sandbox).

## Explicitly out of scope for v1

- GUI apps inside the guest (Xvnc, Wayland).
- GPU passthrough.
- Multiple distros (Debian only at v1; Alpine/Ubuntu are v2 items).
- Remote pair / SSH daemon on guest listening to LAN (blocked by netgate policy; local-only is OK later).
- iOS port (separate research track; Apple's JIT restrictions are a different problem).

## UI framework decision — TBD

Open question as of 2026-04-18: **Jetpack Compose (Kotlin-native)** vs **Flutter**.

- **Compose:** tighter PTY + IME integration, easier Android-idiomatic keyboard handling, no second runtime inside the APK. Natural fit for a system-level product. Termux-app is pure Android (they predate Compose, but the lesson is: native pays off for terminal work).
- **Flutter:** consistency with mo-code's existing Flutter stack, single UI codebase for both products. But the PTY / keyboard-bar / IME path is awkward in Flutter on Android and would need platform channels everywhere.

**Leaning Compose.** Decision gets made before M6 (the product-packaging milestone) starts.

## Status

Placeholder directory. Real scaffolding lands with M6 of [../PLAN.md](../PLAN.md), after the runtime (`gate/`, `gum/`, `shell/`) is solid enough to run real workloads end-to-end.

## Relationship to mo-code

mo-code is a separate product — an AI coding agent. It embeds mo-jit as a Go module through a thin adapter. Nothing in mo-jit Terminal depends on mo-code, and nothing in mo-jit Terminal knows about AI or agents. The two products share only the runtime; their UX, audience, and positioning are independent.
