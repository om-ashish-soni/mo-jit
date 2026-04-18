/*
 * mojit_hook.h — C ABI between the gum svc hook and the mo-jit gate.
 *
 * This header is the contract. gum's Stalker backend (C) intercepts
 * every guest `svc #0` and calls mojit_hook_enter() with the register
 * state. The gate (Go, via cgo in gate/gumhook/) inspects the call,
 * applies filesystem / network / PID virtualization, and fills the
 * return value on the way out.
 *
 * Stability: pinned at v0 for the whole 0.1.x series. Breaking
 * changes bump the MOJIT_HOOK_ABI_VERSION constant. Consumers verify
 * the constant at init.
 *
 * Threading: reentrant. Multiple guest threads call enter() in
 * parallel; the registered handler must be safe under concurrent
 * invocation. The only shared mutable state inside gum is the code
 * cache, which has its own lock.
 *
 * Not thread-local: guest TLS (tpidr_el0) belongs to the guest and is
 * preserved by Stalker's context switch. The handler must not touch
 * it.
 *
 * Copyright 2026 Om Ashish Soni and mo-jit contributors.
 * SPDX-License-Identifier: Apache-2.0
 *
 * (The `gum/` subtree is otherwise LGPL-2.1-or-later because it is a
 * frida-gum fork; this header defines the boundary at which mo-jit's
 * own Apache-2.0 code attaches and is therefore Apache-2.0 itself.
 * It contains no frida-gum-derived material.)
 */

#ifndef MOJIT_HOOK_H
#define MOJIT_HOOK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MOJIT_HOOK_ABI_VERSION 0

/*
 * mojit_regs_t — ARM64 register snapshot captured at the svc
 * boundary. x0..x7 are the syscall arguments, x8 holds the syscall
 * number (Linux AArch64 ABI). The handler writes the result back
 * into regs->x0 before returning.
 *
 * Only the fields that matter at the syscall boundary are captured.
 * The guest's remaining GPRs, NEON/SVE state, and tpidr_el0 are
 * preserved by the Stalker trampoline and are opaque to the handler.
 */
typedef struct mojit_regs {
    uint64_t x[8];      /* syscall args x0..x7                       */
    uint64_t nr;        /* syscall number (x8)                       */
    uint64_t pc;        /* guest PC of the svc instruction           */
    uint64_t sp;        /* guest SP at entry                         */
} mojit_regs_t;

/*
 * Handler verdict.
 *
 *   MOJIT_HANDLED    The handler produced a result; regs->x[0]
 *                    holds the return value (or -errno on failure,
 *                    per Linux syscall convention). Do NOT issue the
 *                    real kernel syscall.
 *
 *   MOJIT_PASSTHROUGH The handler declines. gum issues the real
 *                    kernel `svc #0` with the captured registers
 *                    and writes the kernel's return value back into
 *                    regs->x[0]. Use only for syscalls that are
 *                    safe to run unfiltered (arithmetic-only ones
 *                    like futex / clock_gettime / getrandom — see
 *                    gate/dispatch.go for the whitelist).
 *
 *   MOJIT_KILL       The handler detected a policy violation it
 *                    refuses to paper over (a raw socket, an
 *                    attempted escape from the rootfs). gum raises
 *                    SIGSYS on the guest thread. The kernel-side
 *                    seccomp-BPF filter is a redundant backstop.
 */
typedef enum mojit_verdict {
    MOJIT_HANDLED     = 0,
    MOJIT_PASSTHROUGH = 1,
    MOJIT_KILL        = 2,
} mojit_verdict_t;

/*
 * Handler signature. Registered once at init by the gate. Called by
 * the Stalker svc trampoline on every intercepted syscall.
 *
 * The handler MUST NOT call back into gum (no nested svc, no cache
 * flush). It may call any libc function that does not itself issue
 * a syscall — the svc hook is installed globally, so a recursive
 * syscall from the handler would deadlock.
 */
typedef mojit_verdict_t (*mojit_handler_fn)(mojit_regs_t *regs,
                                            void *user_data);

/*
 * Register the global svc handler. Called once by mojit-shell during
 * init, before gum is started. Subsequent calls replace the prior
 * handler atomically; passing NULL unregisters (every svc then
 * defaults to PASSTHROUGH, useful for debug builds).
 *
 * Returns 0 on success, negative errno-style on failure:
 *   -EINVAL  abi_version != MOJIT_HOOK_ABI_VERSION
 */
int mojit_hook_register(int abi_version,
                        mojit_handler_fn handler,
                        void *user_data);

/*
 * Code-cache allocator hook — see memfd_alloc.c. Installed before
 * gum is started so Stalker's GumCodeAllocator routes through our
 * memfd-backed allocator instead of anonymous PROT_EXEC mappings
 * (which SELinux denies on Android 10+ for untrusted_app on
 * app_data_file inodes).
 *
 *   size_hint  number of bytes the caller intends to use. Rounded
 *              up internally to a page multiple.
 *   out_fd     memfd file descriptor backing the region (owned by
 *              the allocator; do not close).
 *
 * Returns a pointer to an rwx region of at least size_hint bytes,
 * or NULL on failure.
 */
void *mojit_code_alloc(size_t size_hint, int *out_fd);
void  mojit_code_free(void *ptr, size_t size);

/*
 * Lifecycle.
 *
 * mojit_hook_init() wires gum's svc interceptor. Must be called
 * AFTER mojit_hook_register() and BEFORE any guest code is launched.
 *
 * mojit_hook_shutdown() quiesces the interceptor. After it returns,
 * subsequent guest syscalls go straight to the kernel (which the
 * seccomp filter will likely kill — call only on teardown).
 */
int  mojit_hook_init(void);
void mojit_hook_shutdown(void);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* MOJIT_HOOK_H */
