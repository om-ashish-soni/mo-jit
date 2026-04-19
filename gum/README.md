# gum — Frida Stalker fork for mo-jit

This subtree hosts the ARM64→ARM64 dynamic translator, forked from
[frida-gum](https://github.com/frida/frida-gum). The upstream sources
live in the [`frida-gum/`](./frida-gum) git submodule, pinned to a
specific release; mo-jit-specific sources (C glue into `gate/`, the
memfd-backed code cache, Android build script outputs) live alongside
in this directory as they land.

## Current state (2026-04-19)

- Submodule `frida-gum/` is pinned to upstream tag **17.9.1**
  (commit `8bf4e03`).
- The fork org is [`om-ashish-soni/frida-gum`](https://github.com/om-ashish-soni/frida-gum);
  we track upstream tags and rebase on each frida-gum release.
- Build scaffolding: [`../scripts/build-gum.sh`](../scripts/build-gum.sh)
  (NDK r26+ cross-build into `build/android-arm64/`).
- Strip inventory: [`STRIP_LIST.md`](./STRIP_LIST.md) — the canonical
  list of what we drop from upstream and why.
- svc-hook ABI landed: [`mojit_hook.h`](./mojit_hook.h) defines the
  gum ↔ gate contract, [`mojit_hook.c`](./mojit_hook.c) implements the
  register/enter/init/shutdown lifecycle, and
  [`mojit_hook_test.c`](./mojit_hook_test.c) pins the behaviour under CI.
- memfd W^X code-cache allocator landed:
  [`memfd_alloc.c`](./memfd_alloc.c) backs `mojit_code_alloc` /
  `mojit_code_free` with a page-aligned `memfd_create` + `ftruncate`
  + `mmap(PROT_RWX, MAP_SHARED)`, tested on x86_64 and aarch64 via
  [`memfd_alloc_test.c`](./memfd_alloc_test.c) (writes machine code
  into the region and executes it).
- Remaining M1 work: link `libmojit-gum.so` from the stripped upstream
  slice and wire Stalker's svc interceptor to `mojit_hook_enter()`.

## Checkout

```bash
git submodule update --init --depth 1 gum/frida-gum
```

The submodule is shallow (single commit at the pinned tag). If you
need full history for a rebase, fetch it explicitly:

```bash
git -C gum/frida-gum fetch --unshallow origin
```

## What the fork adds on top of upstream

1. **ARM64-only, Linux/Android-only build slice.** Every other backend
   and OS shim is disabled at Meson time. See
   [`STRIP_LIST.md`](./STRIP_LIST.md) for the complete matrix.
2. **Minimal C ABI for the `svc` hook** that calls into the Go gate's
   syscall dispatcher (`../gate/dispatch.go`). No JavaScript VM, no
   GLib mainloop.
3. **`memfd_create`-backed code-cache allocator** that survives
   Android 10+ W^X restrictions. Android denies
   `mmap(PROT_EXEC)` on `app_data_file` inodes for `untrusted_app`;
   memfd pages land in a different SELinux context that stays
   exec-allowed.

Points 2 and 3 are intrusive enough that upstream is unlikely to
accept them, which is why we carry a thin fork rather than contribute.
We still track upstream releases and rebase mechanically.

## License

frida-gum is **LGPL-2.1-or-later**. The fork in this subtree remains
under the same license; the upstream `COPYING` file inside
`frida-gum/` is authoritative.

The `gate/`, `shell/`, `cmd/`, and `android-app/` subtrees at the top
of this repo are **Apache-2.0**, and link against `libmojit-gum.so`
dynamically. That dynamic-link boundary is the LGPL compliance point:
consumers using `gate/` as a library are unaffected by the copyleft
terms; modifications to anything inside `gum/` itself must be released
under LGPL-2.1-or-later.

## Layout

```
gum/
├── README.md         ← you are here
├── STRIP_LIST.md     ← which parts of upstream we drop and why
└── frida-gum/        ← submodule (upstream fork at pinned tag)
```

C glue currently under `gum/`:

```
gum/
├── mojit_hook.h            ← public C ABI consumed by shell/ and gate/
├── mojit_hook.c            ← svc hook lifecycle + default passthrough
├── mojit_hook_test.c       ← portable smoke test (runs in CI)
├── memfd_alloc.c           ← memfd-backed W^X code cache allocator
├── memfd_alloc_test.c      ← portable alloc/exec smoke test (runs in CI)
└── ... patches applied on top of frida-gum, if any (none yet)
```
