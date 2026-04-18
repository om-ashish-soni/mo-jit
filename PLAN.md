# mo-jit — Roadmap

**Status:** scaffolded 2026-04-18. Targeting `v0.1.0` in ~12 weeks (single engineer) or ~8 weeks (two engineers). +3 weeks risk buffer for Stalker Android-port surprises.

## The invention, in one sentence

If the guest and host share the same ISA, you don't need an emulator — you need an instrumentor with a syscall gate. mo-jit is the instrumentor (forked Frida Stalker) plus the gate (in-process FS/net/PID virtualization).

## Milestones

### M1 — Frida Stalker fork + Android build (weeks 1–3)

- Fork `github.com/frida/frida-gum` at a pinned release → `gum/` subtree.
- Strip non-ARM64 backends (x86, x86_64, mips, arm32), non-Linux OS shims (Windows/macOS/iOS), and the JavaScript VM binding.
- Build pipeline `scripts/build-gum.sh` with NDK r26+ → `libmojit-gum.so`.
- **W^X:** use `memfd_create` + `ftruncate` + `mmap(PROT_EXEC)` — same loader pattern mo-code already ships for proot on Android 15.
- **Exit criterion:** a statically linked ARM64 hello-world ELF runs inside `shell/mojit-shell` with every `svc` observed in a log; instrumentation overhead ≤1.5× on a tight arithmetic loop.

### M2 — Syscall dispatcher + FS virtualization (weeks 3–6)

- `gate/dispatch.go` — table-driven `svc` handler covering `openat`, `open`, `stat`, `lstat`, `fstatat`, `access`, `faccessat`, `readlink`, `readlinkat`, `mkdir`, `mkdirat`, `unlink`, `rename`, `chdir`, `getcwd`, plus `/proc/<pid>/*` virtualization.
- `gate/fsgate.go` — userspace copy-on-write overlay with OCI overlay semantics: read walks `upper/` then `lower/`, writes trigger copy-up, deletes record whiteouts. Pure Go — no kernel overlayfs (not available without user-ns).
- `gate/procmap.go` — synthesize `/proc` to show only guest-PID-tree.
- Tests pin the translation table: `/etc/hostname` → `upper/etc/hostname` or `lower/etc/hostname`; `/../../sdcard` escape → `EACCES`.

### M3 — Network virtualization (weeks 6–8)

- `gate/netgate.go` — intercept `socket`/`connect`/`bind`/`accept`/`send*`/`recv*`/`getsockname`/`getpeername`. Real host sockets beneath (inherit app's `INTERNET` permission); policy layer rejects RFC1918 + loopback + link-local.
- `gate/dns.go` — synthetic `/etc/resolv.conf` pointing at `10.0.2.3`; intercept UDP sends to that address and forward through the host resolver (DNS list learned from `ConnectivityManager` on mo-code side, from `/etc/resolv.conf` on generic Linux).
- **seccomp-BPF belt-and-braces:** any socket syscall not issued from the gate's code address → `SIGSYS`. Even if Stalker misses a `svc` on a cold path, the kernel kills the escape attempt.
- Tests: `curl https://example.com` succeeds, `nc 127.0.0.1 <host-port>` fails with `ECONNREFUSED`, `nc 192.168.1.1 80` fails.

### M4 — `mojit-run` CLI + OCI-ish config (week 9)

- `cmd/mojit-run/main.go` — `mojit-run --rootfs ./rootfs --upper ./upper --net internet -- /bin/sh -lc "$CMD"`
- Parse a minimal `mojit.json` config: paths, network policy, env, binds.
- Exit codes match the guest's exit; stdout/stderr are forwarded transparently.

### M5 — Examples + public release (week 10)

- `examples/helloworld-elf/` — statically linked C hello-world ELF, proves the block-cache path end to end.
- `examples/debian-demo/` — fetch a Debian arm64 slim rootfs (~220 MB), run `git clone`, `apt install htop`, `go build` inside.
- Publish `v0.1.0` GitHub Release with prebuilt `libmojit-gum.so` and `mojit-shell` for `arm64-v8a` Android.
- Announce on HN / r/androiddev / r/programming.

### M6 — mo-jit Terminal (Android app) — the first product (weeks 11–14)

**This is the product that ships mo-jit to the world.** Not mo-code. See [android-app/README.md](android-app/README.md) for the full product scope.

- Android app wrapper: Jetpack Compose (leaning) or Flutter — decision due start of M6.
- PTY host: opens `/dev/ptmx`, wires to a terminal emulator (plan: wrap `libvterm` (MIT) or ship a clean-room Rust VT-220 impl; **not** Termux's GPL emulator).
- Foreground service + persistent notification to survive Doze.
- Keyboard extras bar at parity-or-better with Termux.
- First-run download UX: 220 MB Debian slim rootfs, resumable, SHA256-verified, extracted to `filesDir/rootfs-debian/lower/`.
- Session registry: multiple concurrent shells, persistent across screen-off.
- Release channels: GitHub Releases first (universal APK + arm64-split APK), then F-Droid, then Play Store (if reviewer doesn't object to JIT + memfd).
- Exit criterion: on a mid-range 2024 Android arm64 device, fresh install → `bash` prompt in ≤90 s on WiFi; `apt install htop && htop` works; `go build` of `cli/cli` completes in ≤240 s.

### M7 — mo-code adapter (week 15)

- mo-code's `backend/sandbox/mojit/backend.go` depends on `github.com/om-ashish-soni/mo-jit/gate` via Go modules.
- Feature-flag rollout inside mo-code with the old proot path as fallback.
- Telemetry on instrumentation overhead in real-world builds (`go build`, `npm install`).

## Out of scope for v0.1

- x86 / x86_64 guest (arm64-on-arm64 only — the whole invention depends on matching ISA).
- GPU passthrough.
- Persistent network listeners inside guest (port-mapping helper is a v0.2 item).
- iOS support (iOS gate is a separate research track — Apple's JIT restrictions are a different problem).

## Hard unknowns (tracked as issues once the repo is live)

1. **Stalker `svc` interception completeness.** glibc sometimes issues syscalls via inlined `svc` inside functions Stalker hasn't cached yet (cold path). Spike week 1: instrument `libc.so.6` on a Debian rootfs, count uninstrumented `svc` sites. If >0: use seccomp-BPF to send `SIGSYS` on kernel entry from any non-cached code page and re-enter Stalker on the signal.
2. **Stalker block-cache memory pressure.** Large apps (`gcc`, `rustc`) may translate 100 MB+ of code. Start with a 256 MB cache cap + LRU eviction; bump to 512 MB if evictions thrash.
3. **`mmap(PROT_EXEC)` from memfd under Android 15/16.** Stalker's code cache needs *continuous* memfd churn. Risk: SELinux audit noise, possible `execmem` denial on Android 16+. Mitigation: pre-allocate one large memfd and manage sub-regions in-process.
4. **glibc TLS + Stalker re-entry.** Stalker traps must preserve guest `tpidr_el0`. Frida already handles this on Android; verify under our seccomp filter.
5. **CoW correctness under `rename()` across lower/upper boundary.** `apt` uses atomic renames heavily. Reference the `fuse-overlayfs` source for the algorithm.

## Upstream prior art we're standing on

- **Frida Stalker** — the block-cache and `svc` hook machinery we fork.
- **fuse-overlayfs** — reference for userspace OCI overlay semantics.
- **QEMU TCG** — baseline for "what we beat" (IR-based, 10× slower).
- **gVisor** — same spirit (syscall-gate isolation), different platform (needs ptrace or KVM).

## Decision log

- **2026-04-18** — project scoped and scaffolded. Primary consumer: mo-code. Default license split: Apache-2.0 everywhere except the LGPL-2.1 gum fork.
- **2026-04-18** — fork Frida Stalker over DynamoRIO (400K LOC, patchy Android CI) or valgrind VEX (IR-based, same problem as TCG).
- **2026-04-18** — no kernel namespaces path: `CONFIG_USER_NS` is disabled for `untrusted_app` on every GKI kernel we ship to in 2026. The gate does everything in user space.
