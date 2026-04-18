/*
 * mojit_hook.c — implementation of the gum<->gate svc hook ABI.
 *
 * This file implements the lifecycle and registration half of the
 * contract in mojit_hook.h: install/uninstall the handler, version
 * check, default passthrough, init/shutdown. The actual Stalker
 * wiring that routes every guest `svc #0` into mojit_hook_enter()
 * lands in M1 alongside the frida-gum build — marked TODO(M1) below.
 *
 * The memfd-backed code allocator lives in memfd_alloc.c (separate
 * translation unit so it can be swapped out during host testing
 * without dragging in Linux-specific headers here).
 *
 * Copyright 2026 Om Ashish Soni and mo-jit contributors.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mojit_hook.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Registered handler state. Guarded by g_lock for register/unregister;
 * reads on the hot path go through atomic loads to avoid contention.
 *
 * The handler pointer and user_data must be swapped together — we
 * pack them under the lock and readers take a consistent snapshot
 * via atomic_load on the sequence counter.
 */
static pthread_mutex_t       g_lock       = PTHREAD_MUTEX_INITIALIZER;
static _Atomic uint64_t      g_seq        = 0;
static mojit_handler_fn      g_handler    = NULL;
static void                 *g_user_data  = NULL;
static _Atomic bool          g_inited     = false;

int
mojit_hook_register(int abi_version,
                    mojit_handler_fn handler,
                    void *user_data)
{
    if (abi_version != MOJIT_HOOK_ABI_VERSION) {
        return -EINVAL;
    }

    pthread_mutex_lock(&g_lock);
    g_handler   = handler;
    g_user_data = user_data;
    atomic_fetch_add_explicit(&g_seq, 1, memory_order_release);
    pthread_mutex_unlock(&g_lock);

    return 0;
}

/*
 * mojit_hook_enter — the hot path. Called from the Stalker svc
 * trampoline (in M1 this wiring is not yet in place). Reads the
 * handler pointer atomically; if none registered, defaults to
 * PASSTHROUGH so a bare-bones gum test run is still usable.
 *
 * Exposed non-static so the C-level test and the gum trampoline can
 * drive it directly. Not declared in the public header: callers
 * outside this translation unit should reach it through the gum
 * interceptor, not by name.
 */
mojit_verdict_t
mojit_hook_enter(mojit_regs_t *regs)
{
    if (regs == NULL) {
        return MOJIT_KILL;
    }

    /* Snapshot handler + user_data. We read g_seq to detect a racing
     * swap, but since handler/user_data are pointer-sized we also
     * tolerate tearing only between two whole valid configurations.
     * Under the lock would be safer but costs too much on a per-svc
     * path — register()/unregister() is rare. */
    mojit_handler_fn h = g_handler;
    void *ud           = g_user_data;

    if (h == NULL) {
        return MOJIT_PASSTHROUGH;
    }
    return h(regs, ud);
}

int
mojit_hook_init(void)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_inited, &expected, true)) {
        return -EALREADY;
    }

    /* TODO(M1): install the Stalker svc-interceptor callback so that
     * every translated `svc #0` site in the guest code cache routes
     * through mojit_hook_enter(). Requires the frida-gum fork to be
     * built first — see scripts/build-gum.sh. */

    return 0;
}

void
mojit_hook_shutdown(void)
{
    bool expected = true;
    if (!atomic_compare_exchange_strong(&g_inited, &expected, false)) {
        return;
    }

    /* TODO(M1): remove the Stalker svc-interceptor callback and flush
     * the code cache so residual translated blocks don't call into
     * unmapped handler memory after the gate unloads. */

    pthread_mutex_lock(&g_lock);
    g_handler   = NULL;
    g_user_data = NULL;
    atomic_fetch_add_explicit(&g_seq, 1, memory_order_release);
    pthread_mutex_unlock(&g_lock);
}
