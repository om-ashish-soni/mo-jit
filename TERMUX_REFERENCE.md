# mo-jit and Termux — What we study, what we do differently

[Termux](https://termux.dev) is the reference point for serious Linux userspace on stock Android. Before us, they are the only project that has shipped a broadly usable Linux environment on unrooted Android at scale, for a decade, across thousands of devices. Ignoring their engineering would be stupid.

This doc lists **what we study from Termux** and **what we do differently**, subsystem by subsystem. It is also a license-hygiene record: we reference, we do not import.

## License boundary

- Termux's main app (`termux-app`): **GPL-3.0-only**.
- Termux utilities (`termux-tools`, `termux-exec`, individual packages): various — mostly GPL-3.0 and some permissive.
- mo-jit: **Apache-2.0** for `gate/`, `shell/`, `cmd/`, `android-app/`; **LGPL-2.1-or-later** for `gum/` (Frida Stalker fork).

**No Termux GPL-3.0 code is copied or directly derived.** Where a Termux subsystem gives us a valuable idea, we re-implement cleanly from published documentation, API traces, and our own design — as we would for any prior-art system (Firecracker, gVisor, fuse-overlayfs).

## Subsystem-by-subsystem

### 1. W^X on Android 10+

**Termux:** patched loader and patched `bash` / `ncurses` / `proot` to cope with SELinux denying `mmap(PROT_EXEC)` on `app_data_file`. They ship a custom `ld.so` and patched binaries.

**What we learn:** the practical tricks — `memfd_create` + `mmap(PROT_EXEC)` — and the failure modes (SELinux audits, Android 15 denials).

**What we do differently:** one loader, built into `mojit-shell`, applied uniformly. Guest binaries never execute directly from disk; they run through the gum code cache, which is backed by memfd pages. Guest ELFs in the rootfs are treated as data, not executables.

### 2. APK-asset boot sequence

**Termux:** extracts a bootstrap tarball from APK assets to `$PREFIX` on first run, then the user runs `pkg install ...` to grow it.

**What we learn:** the APK-asset → `filesDir` extraction pattern; dealing with Android's constrained storage; upgrade-in-place semantics.

**What we do differently:** we don't ship packages in the APK. The APK carries only `libmojit-gum.so`, `mojit-shell`, `mojit-run`, and the terminal UI (~8 MB total). The Debian rootfs is a ~220 MB download on first run, resumable, verified by SHA256, streamed into the userspace CoW lower layer. This keeps the APK small enough for Play Store and lets us ship rootfs updates without an APK update.

### 3. PTY + terminal emulator

**Termux:** they wrote and maintain [`terminal-emulator`](https://github.com/termux/termux-app/tree/master/terminal-emulator), a Java ANSI/VT-220 emulator tuned for Android. Handles Unicode, alt-screen, 256-color, mouse, selection.

**What we learn:** PTY handling on Android (open /dev/ptmx, grantpt/unlockpt semantics, input/output threading), mobile-specific ANSI handling (tiny screens, swipe-select).

**What we do differently:** we write our own terminal emulator (or integrate a permissive one — `libvterm` is MIT; `xterm.js`-like Rust reimplementations exist) to keep the Apache-2.0 boundary clean. We are explicit about this in `android-app/README.md` once we pick a base.

### 4. Keyboard extras bar

**Termux:** the row of Ctrl/Esc/Tab/↑↓←→ buttons above the soft keyboard is their signature UX. Configurable per-user via `~/.termux/termux.properties`.

**What we learn:** the specific keys most-used in real terminal work on Android (Ctrl, Esc, Tab, arrows, Home/End, PgUp/PgDn, `|`, `/`, `-`, `~`). The chord mechanic (Ctrl+key when Ctrl is tapped first). Swipe-up gesture for volume-down-as-Ctrl.

**What we do differently:** we ship the same ergonomics (reinvented from scratch) with a slightly richer default row and an in-app config screen instead of a properties file. Parity-or-better with Termux on keyboard UX is a v0.1 requirement — users coming from Termux should feel at home instantly.

### 5. `termux-exec` and `termux-chroot`

**Termux:** an `LD_PRELOAD` library (`termux-exec.so`) that rewrites hardcoded paths like `/tmp`, `/usr/bin/env`, `/bin/sh` to Termux-prefix equivalents at exec time. `termux-chroot` is a shell wrapper that sets up a fake `/` using `proot`.

**What we learn:** every real-world shebang line, every hardcoded Python/Perl/Ruby path, every way shell scripts break under a non-`/usr` prefix.

**What we do differently:** we don't need `LD_PRELOAD` path-rewriting at all. Our guest sees a real Debian `/` because the gate translates every `openat` in the kernel-visible path after the guest's syscall. Hardcoded `/usr/bin/python3` works unchanged — the gate resolves it to `filesDir/rootfs-debian/lower/usr/bin/python3` transparently.

### 6. `proot-distro`

**Termux:** a shell script that bootstraps Debian/Ubuntu/Alpine/Arch/Fedora/... under `proot`. The most-used "real Linux on Android" path today.

**What we learn:** the bootstrap sequence — fetch tarball, unpack, fix `/etc/resolv.conf`, drop in a stub `/proc` / `/sys`, launch `proot` with the right binds. Also: which upstream base images actually work cleanly on Android.

**What we do differently:** we don't use proot. At all. The JIT + gate replaces proot's ptrace-based path translation with in-JIT syscall redirection. We ship one base (Debian slim) at v0.1 with the toolchain layer we want; users can swap the lower layer for Ubuntu/Alpine/Arch in v0.2 if demand is there.

### 7. Termux packaging ecosystem

**Termux:** they maintain ~2000 packages cross-compiled for bionic/Android in their own apt-compatible repos (`packages.termux.dev`). Huge amount of engineering per-package — patches for bionic's missing glibc features, custom build scripts, CI.

**What we learn:** what's hard to cross-compile for non-glibc Linux. Which packages have cgo/libc assumptions.

**What we do differently:** **we do not maintain a package repo.** Our guest is real glibc Debian — packages come from `deb.debian.org` unchanged. Someone running `apt install rustc` gets Debian's rustc, not a Termux-patched rustc. This is the single biggest strategic divergence: we inherit Debian's 60k-package ecosystem for free at the cost of a larger rootfs.

### 8. Android app lifecycle + foreground service

**Termux:** runs its shell sessions under a foreground service so Android doesn't kill them when the app is backgrounded. Handles notification channel, wake-lock, boot-recover.

**What we learn:** the exact foreground-service + notification setup that keeps a terminal session alive through screen-off, home-button, and Doze. The `ACTION_BOOT_COMPLETED` receiver for recovering sessions.

**What we do differently:** nothing substantive. The Android lifecycle problem is the same shape for us. We'll follow Termux's proven pattern (foreground service + persistent notification + session registry) and document the lineage in `android-app/` code comments.

## Summary

We are not "the new Termux." We are the first project to bring real isolation and native speed to Android userspace, and Termux is our most important teacher about everything Android-specific between our JIT and the user's fingers. Specific, non-overlapping goals; respectful, explicit, clean-room relationship to their code.
