# gum — Frida Stalker fork for mo-jit

This directory will host the ARM64→ARM64 dynamic translator, forked from
[frida-gum](https://github.com/frida/frida-gum). The fork lands in **M1**
(see [../PLAN.md](../PLAN.md)).

## Scope once populated

- Strip every Stalker backend except `arch-arm64` and every OS shim except
  Linux.
- Drop the JavaScript VM bindings — we invoke the translator from C only.
- Add the `svc` hook entry point that calls into the Go gate's syscall
  dispatcher (`../gate/dispatch.go`) via a minimal C ABI.
- Replace Stalker's default code-cache allocator with an
  `memfd_create`-backed allocator that survives Android 10+ W^X
  restrictions. (Android denies `mmap(PROT_EXEC)` on `app_data_file`
  inodes for `untrusted_app`; memfd pages get a different SELinux
  context that stays exec-allowed.)

Until M1, this directory is a placeholder with this README.

## License

frida-gum is **LGPL-2.1-or-later**. The fork in this subtree remains
under the same license.

The `gate/`, `shell/`, `cmd/` subtrees are **Apache-2.0** and link
against `gum` dynamically; that link boundary is the LGPL compliance
point. Consumers of `gate/` as a library are unaffected by the copyleft
terms; modifications to `gum/` itself must be released under LGPL.

A verbatim `LICENSE` file reproducing LGPL-2.1 will ship inside this
directory alongside the forked sources when M1 lands.

## Why a fork, not a dependency

We need three things upstream does not currently offer:

1. A stable C ABI for the svc hook that calls into an external
   dispatcher with minimal overhead (no JS VM, no GLib event loop).
2. An `memfd_create`-backed code-cache allocator for Android W^X.
3. Permission to freeze on a pinned release and guarantee the ABI to
   downstream users.

Point 1 and 2 are too intrusive to expect upstream to accept; point 3
is a release-engineering concern. Keeping a thin fork is the least-bad
path. We track upstream and rebase on each frida-gum release.
