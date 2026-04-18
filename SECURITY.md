# mo-jit — Threat Model

This document is deliberately honest. mo-jit is a useful runtime for a specific class of threats and useless for others. Read this before deciding whether to use it.

## What mo-jit defends against

| Threat | Defense | Strength |
|---|---|---|
| Guest reads/writes files outside its rootfs | FS gate path translation; paths outside `LowerDir`, `UpperDir`, and bind mounts return `EACCES` | Strong |
| Guest connects to host's localhost services | Net gate rejects `127.0.0.0/8` and `::1/128`; seccomp-BPF kills socket syscalls from non-gate code | Strong |
| Guest connects to LAN peers / RFC1918 | Net gate rejects RFC1918 ranges and link-local | Strong |
| Guest enumerates other app processes | PID gate + synthetic `/proc` showing only guest-PID-tree | Strong |
| Guest ptraces the host app | SELinux `untrusted_app` domain already denies cross-process ptrace; host app sets `prctl(PR_SET_DUMPABLE, 0)` | Strong |
| Guest reads host app memory via `/proc/<host-pid>/mem` | Separate process, `DUMPABLE=0`, host PID not in guest's PID view | Strong |
| Guest exploits a Stalker instrumentation bug to run un-translated code | seccomp-BPF: any syscall from a non-gate code address → `SIGSYS` | Strong |
| Guest injects into `mojit-shell`'s own memory to bypass the gate | Stalker code-cache pages are mapped read-exec from memfd; gate's policy pages are read-only at runtime; W^X enforced | Medium — depends on Stalker's internal integrity |

## What mo-jit does NOT defend against

- **Kernel LPE.** A Linux kernel bug that gives the guest arbitrary kernel execution escapes mo-jit. No user-space runtime can defend this. You would need a VM (AVF, KVM, Firecracker) — all of which are unreachable for 3rd-party Android apps.
- **Hardware side channels.** Spectre, Meltdown, Rowhammer, cache-timing — guest and host share the same CPU core and cache hierarchy. mo-jit has no answer for these.
- **Host app compromise.** If the app embedding mo-jit is already compromised, the guest is the least of your problems.
- **Confidential computing.** mo-jit is not a TEE, not a realm, not an enclave. It is a syscall-gate sandbox.

## Intended use cases

✅ Running your own toolchains (Go, Node, Python, Rust, Java) on code you authored or chose to trust.

✅ Isolating AI-agent-generated code from the agent's own host app — keeping accidental or mischievous `rm -rf ~` confined.

✅ Sandboxing semi-trusted CI-style tasks on-device (linters, test runners, bundlers).

✅ Dev tools that need `apt install` mutability without polluting the host.

## NOT intended for

❌ Running malware samples — they will escape via kernel bugs.

❌ Multi-tenant SaaS sandboxing — you need a real VM.

❌ Executing code from untrusted internet strangers.

❌ Any use case where a kernel LPE CVE is in your threat model.

## Reporting vulnerabilities

Pre-alpha. No formal disclosure process yet. For now:

- **Low severity / design questions:** open a GitHub issue.
- **High severity:** email the maintainer listed on the [GitHub profile](https://github.com/om-ashish-soni). We'll set up a proper security contact before v0.1.0.

## Security properties we promise to measure before v0.1.0

- **seccomp coverage.** Every syscall the gate handles must have a corresponding kernel-side `SIGSYS` for the non-gate code path. This is tested in CI.
- **Escape corpus.** Standard container-escape techniques (`/proc/self/exe` games, symlink races, `TOCTOU` in path rewrite, rename across boundary) must fail. Corpus lives in `gate/escape_test.go` once M2 lands.
- **No-instrumentation detection.** Guest code must not be able to detect that it is running under Stalker — no timing side channels, no `/proc/self/maps` leaks of the code cache. Documented in the security audit for M5.
