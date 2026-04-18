# mo-jit — Architecture

## The core idea

mo-jit is user-space isolation built on one insight: **if the guest and host share the same ISA, you don't need an emulator — you need an instrumentor with a syscall gate.**

QEMU TCG lifts guest ARM64 → TCG IR → host ARM64. The IR round-trip is the 10× slowdown. If you just copy the guest block to an executable cache, patch PC-relative addresses, and redirect `svc #0` to a dispatcher, you get near-native speed.

That's what [Frida Stalker](https://frida.re/docs/stalker/) already does for dynamic instrumentation. We fork it and add three gates — filesystem, network, PID — to turn it from an instrumentor into a container runtime.

## Process model

```
┌──────────────────────────────────────────────────────────────────┐
│  host app  (untrusted_app, u0_a<N>)                              │
│                                                                  │
│    mojit-run ──fork+exec──► mojit-shell (child)                  │
│                                    │                             │
│                                    ▼                             │
│                              ┌───────────────────────┐           │
│                              │  mojit-shell          │           │
│                              │  • prctl(DUMPABLE,0)  │           │
│                              │  • seccomp-BPF belt   │           │
│                              │  • loads guest ELFs   │           │
│                              │                       │           │
│                              │  ┌─────────────────┐  │           │
│                              │  │ gum             │  │           │
│                              │  │ (Stalker fork)  │  │           │
│                              │  │                 │  │           │
│                              │  │ block cache     │  │           │
│                              │  │ (memfd-backed)  │  │           │
│                              │  │                 │  │           │
│                              │  │ svc hook ───────┼──┼──► gate   │
│                              │  │                 │  │  dispatch │
│                              │  │ trampolines     │  │           │
│                              │  └─────────────────┘  │           │
│                              └───────────────────────┘           │
└──────────────────────────────────────────────────────────────────┘
```

The guest runs in a **child process** of the host app. Same UID. Different `prctl(PR_SET_DUMPABLE)` setting, different seccomp filter, different view of the filesystem and network — all enforced in userspace by the gate.

## Three gates

### FS gate (`gate/fsgate.go`)

Every path-touching syscall (`openat`, `stat`, `readlink`, `mkdir`, `rename`, …) is intercepted. The gate normalizes the guest path, walks the CoW stack (`upper/` first, then `lower/`), and rewrites the syscall argument to point at the real host-side path. Paths outside the configured rootfs and bind mounts return `-EACCES`.

**Copy-on-write is pure userspace.** No kernel overlayfs — it's unavailable without user namespaces. Writes to a file that exists only in `lower/` trigger a copy-up into `upper/` before the write proceeds. Whiteouts for `unlink` are recorded as special files in `upper/`. Reference: `fuse-overlayfs` source for the algorithm.

### Net gate (`gate/netgate.go`)

`socket`/`connect`/`bind`/`send*`/`recv*`/`getsockname` are intercepted. The gate creates a real host socket (inheriting the app's `INTERNET` permission) but enforces a policy that rejects:

- Loopback (`127.0.0.0/8`, `::1/128`)
- Link-local (`169.254.0.0/16`, `fe80::/10`)
- RFC1918 (`10/8`, `172.16/12`, `192.168/16`)
- Any extra CIDRs the caller specifies in `NetPolicy.DenyCIDRs`

The guest sees unrestricted public internet; the host app's attack surface (localhost services, other apps' sockets, LAN peers) stays hidden.

DNS is intercepted at the UDP layer — packets to the synthetic `/etc/resolv.conf` address (`10.0.2.3`) are reshaped into queries against the host's real resolvers (learned from `ConnectivityManager` on Android, from the host's `/etc/resolv.conf` on generic Linux).

**seccomp-BPF runs as belt-and-braces.** Any socket syscall not issued from the gate's code range kills the process with `SIGSYS`. Even if Stalker misses a `svc`, the kernel stops the escape.

### PID gate (`gate/procmap.go`)

`/proc/<pid>/*` is synthesized: only PIDs in the guest process tree are visible. The host app's daemon — which may hold secrets, tokens, or IPC handles in memory — is invisible to the guest. Access to `/proc/<other_pid>/*` returns `-ENOENT`, matching the user's expectation that the process does not exist.

## Why this is stronger than proot

proot runs every syscall through ptrace and rewrites paths. Same UID, same SELinux label, same namespaces — the kernel sees one process. A kernel bug in ptrace, a race in path translation, or a missed syscall is a full escape.

mo-jit's guest still runs in the same UID, but:

- Every instruction executes through Stalker — there is no "native" path the guest can take.
- Every `svc` is trapped twice: Stalker's hook at the userspace level, and seccomp-BPF at the kernel level.
- The guest process has `DUMPABLE=0` and runs under seccomp; the host app does not.

## Why this is weaker than a real VM

- No hardware isolation — a kernel LPE bug escapes.
- Not a security boundary against an attacker with arbitrary kernel primitives.

**Intended for:** running your own toolchains, isolating AI-agent-generated code, sandboxing semi-trusted CI-style tasks on-device.

**Not intended for:** multi-tenant SaaS, running malware samples, executing code from untrusted internet strangers.

See [SECURITY.md](SECURITY.md) for the full threat model.

## What's generic vs. Android-specific

Most of mo-jit is **generic Linux user-space** — it will build and run on any arm64 Linux. The Android-specific pieces are:

- The `memfd_create`-based W^X code-cache allocator in `gum/`. Generic Linux doesn't need this.
- The `ConnectivityManager` DNS-server lookup path — on generic Linux, `gate/dns.go` reads `/etc/resolv.conf` directly.

This means mo-jit is a viable isolation runtime for arm64 Linux desktops (Asahi, Pi, etc.), not just Android. That's a happy accident of the design, not a primary goal.
