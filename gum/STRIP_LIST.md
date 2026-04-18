# frida-gum strip list

frida-gum upstream targets every ISA × every OS. mo-jit targets exactly
one pair: **ARM64 guest on Linux/Android host**. Everything else is dead
weight.

This file is the canonical record of what the mo-jit fork removes from
upstream and why. It is authoritative: if you add a file or directory
back, update this doc.

Applied against tag `17.9.1` (commit `8bf4e03`).

## Directory-level strips under `gum/frida-gum/gum/`

**Keep:**

- `arch-arm64/` — guest disassembly / codegen we target.
- `backend-arm64/` — Stalker ARM64 translator.
- `backend-linux/` — Linux OS-specific process / module / mmap shims.
- `backend-elf/` — ELF module loader used by the Linux backend.
- `backend-posix/` — signal and thread primitives we inherit.
- Core translator files directly under `gum/` (block cache, code
  allocator, ELF module iteration, stalker core) — see file-level
  section below for the few darwin-only outliers to drop.

**Strip:**

| Path | Reason |
|---|---|
| `arch-arm/` | 32-bit ARM guest — unsupported target |
| `arch-mips/` | MIPS guest — unsupported |
| `arch-x86/` | x86 / x86_64 guest — out of scope for v0.1 (arm64-only invariant) |
| `backend-arm/` | 32-bit ARM Stalker backend |
| `backend-mips/` | MIPS Stalker backend |
| `backend-x86/` | x86 Stalker backend |
| `backend-barebone/` | Bare-metal (no OS) backend — we always have Linux |
| `backend-darwin/` | macOS / iOS host — unsupported |
| `backend-dbghelp/` | Windows debug-helper — unsupported |
| `backend-freebsd/` | FreeBSD host — unsupported |
| `backend-qnx/` | QNX host — unsupported |
| `backend-windows/` | Windows host — unsupported |
| `backend-libdwarf/` | DWARF backtracer alt — we use the ELF path |
| `backend-libunwind/` | libunwind backtracer alt — we use the ELF path |

## File-level strips under `gum/frida-gum/gum/`

Darwin-specific translator files (not under a backend- dir, but still
macOS-only):

- `gumdarwingrafter.c` / `.h` / `-priv.h`
- `gumdarwinmodule.c` / `.h` / `-priv.h`

## Top-level strips under `gum/frida-gum/`

| Path | Reason |
|---|---|
| `bindings/` | JavaScript VM (QuickJS / V8) bindings. mo-jit calls gum from C only. Strips ~20 MB. |
| `tests/` | Upstream test harness. We write our own focused tests for the stripped ABI. |
| `tools/` | Release tooling for upstream. Not needed by consumers. |
| `docs/` | Upstream docs — we maintain our own under `mo-jit/docs/`. |
| `ext/` | Optional extensions — none target our platform. |
| `vapi/` | Vala API files — we don't use Vala. |
| `configure` / `configure.bat` / `make.bat` / `BSDmakefile` / `Makefile` | Non-Meson entry points for non-Linux hosts. We build via Meson only on NDK. |

## Non-strip: intentionally kept even if unused today

- `releng/` — Meson wrapping conventions. Upstream's build system is
  Meson-first; we keep releng intact so rebase-on-upstream stays cheap.
- `subprojects/` — Meson subproject pins (capstone, glib, etc.). Needed
  by the Meson build. We vendor these through Meson's wrap system.
- `libs/` — Small helpers used by the core. Small enough to carry.

## How strips are applied

We do **not** delete files from the submodule checkout. Instead:

1. The Meson build configured by `scripts/build-gum.sh` passes
   `-Dbackends=arm64`, `-Darch=arm64`, `-Dos=linux`, and
   `-Dbindings=disabled` to frida-gum's Meson. This excludes the
   stripped backends from the compile graph.
2. `scripts/build-gum.sh` additionally passes
   `--exclude-subdir=bindings,tests,tools,docs,vapi,ext` via
   frida-gum's `meson.options` overrides. (If upstream Meson ignores
   any option, we layer a tiny `meson.build.patch` in
   `scripts/patches/gum/`.)
3. At package time, the final `libmojit-gum.so` ships with only the
   symbols the arm64 + linux + elf + posix slice produces — everything
   else never reaches the linker.

Keeping upstream sources in-tree but disabling them at the build layer
means `git submodule update` + rebase against upstream remains
mechanical. If we ever physically deleted files, every upstream bump
would fight `git merge`.
