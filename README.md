# mo-jit

**A user-space ARM64 container runtime for unrooted Android.**

mo-jit runs a full Linux userland — Debian, Alpine, anything — inside an Android app, with:

- **True isolation** from the host app (syscall-level gate, not ptrace)
- **Near-native speed** (ARM64→ARM64 dynamic translation, ~2× native target; vs QEMU TCG's 10–12×)
- **Full internet access** via in-process socket redirection
- **Zero onboarding** — no root, no Shizuku, no ADB pairing, no custom ROM

No kernel namespaces, no `/dev/kvm`, no `MANAGE_VIRTUAL_MACHINE`. Works on any Android 10+ arm64 device, inside a standard `untrusted_app` UID.

## Status

**Pre-alpha — scaffolded 2026-04-18.** M1 (Stalker fork + Android build) kicks off next. See [PLAN.md](PLAN.md) for the roadmap.

## How it works

mo-jit is three things stacked:

1. **`gum/`** — a dynamic binary translator forked from [Frida Stalker](https://frida.re/docs/stalker/). Because guest ISA == host ISA (both ARM64), translation is block-copy + PC-relative fixups, not emulation. This is why we get near-native speed where QEMU TCG does not.
2. **`gate/`** — an in-process syscall dispatcher that intercepts every `svc #0` and routes it through filesystem virtualization (userspace copy-on-write overlay), network virtualization (socket redirect + DNS intercept), and PID-tree scoping.
3. **`shell/`** — a minimal init process (`mojit-shell`) that hosts the JIT and the guest rootfs.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and [SECURITY.md](SECURITY.md) for the honest threat model.

## Why this exists

The primary consumer is [mo-code](https://github.com/om-ashish-soni/mo-code), an on-device AI coding agent for Android that needs to clone repos, run `apt install`, build with Go/Node/Python/Rust, and raise GitHub PRs from inside a real sandbox. But the runtime is deliberately generic — Termux, postmarketOS, research sandboxes, or any Android app that wants to run untrusted code at native speed can use mo-jit.

Everything else was ruled out:

| Path | Why it doesn't work on unrooted Android |
|---|---|
| AVF / Microdroid | `MANAGE_VIRTUAL_MACHINE` is `@SystemApi` — signature-gated |
| gVisor ptrace | SELinux blocks cross-process ptrace in `untrusted_app` |
| Firecracker / KVM | `/dev/kvm` denied to 3rd-party apps |
| User namespaces (`unshare`/`chroot`) | `CONFIG_USER_NS` disabled for `untrusted_app` on GKI |
| QEMU TCG | Works, but 10–12× slowdown — unusable for `go build`, `npm install` |
| Shizuku + bwrap | Works, but requires one-time Wireless-Debugging pairing |
| proot | Not real isolation — same UID, same SELinux label |

mo-jit is the answer when none of those fit.

## Quickstart (once M4 lands)

```bash
# Fetch an arm64 Debian rootfs
curl -L https://.../debian-slim-arm64.sqsh | unsquashfs -d rootfs -

# Run a shell inside it
mojit-run \
    --rootfs ./rootfs \
    --upper  ./overlay-upper \
    --net    internet \
    -- /bin/sh -lc "apt update && apt install -y htop && htop"
```

Today (pre-M4) this just prints the resolved policy and exits — the real guest exec lands in M4.

## Building

```bash
# Host-side gate library and CLI scaffold
go build ./gate/... ./cmd/...
go test  ./gate/...

# Cross-build for Android (lands in M1)
# NDK r26+ required.
```

## License

- `gate/`, `shell/`, `cmd/`, top-level code and docs: **Apache-2.0** (see [LICENSE](LICENSE)).
- `gum/`: a fork of Frida Stalker, remains **LGPL-2.1-or-later**. The Apache-2.0 subtrees link against `gum` at the library boundary — the LGPL terms apply to modifications to `gum/` itself, not to `gate/` consumers.

## Contributing

Early days — the architecture is still settling. If you're interested in ARM64 JIT work, Android user-space sandboxing, or building dev tools for mobile, open an issue before sending a PR so we can scope together.

## Security disclosure

Pre-alpha; no formal disclosure policy yet. For now: open a GitHub issue, or email the maintainer listed on the [profile](https://github.com/om-ashish-soni).
