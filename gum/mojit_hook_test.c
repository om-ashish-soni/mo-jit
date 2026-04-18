/*
 * mojit_hook_test.c — portable smoke test for the svc hook ABI
 * lifecycle. Does not exercise the Stalker wiring; that requires the
 * full gum build and is covered by an on-device M1 test.
 *
 * Build:
 *   cc -std=c11 -pthread mojit_hook.c mojit_hook_test.c -o mojit_hook_test
 * Run:
 *   ./mojit_hook_test
 */

#include "mojit_hook.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Expose the internal hot-path entry so we can drive it from the
 * test without the Stalker machinery. Not in the public header. */
extern mojit_verdict_t mojit_hook_enter(mojit_regs_t *regs);

static int g_handler_calls = 0;

static mojit_verdict_t
test_handler(mojit_regs_t *regs, void *user_data)
{
    assert(regs != NULL);
    assert(user_data == (void *)0xdeadbeefUL);
    g_handler_calls++;

    /* Pretend we serviced getpid() by writing a fake pid. */
    regs->x[0] = 1234;
    return MOJIT_HANDLED;
}

static void
test_version_rejected(void)
{
    int rc = mojit_hook_register(MOJIT_HOOK_ABI_VERSION + 1,
                                 test_handler, NULL);
    assert(rc == -22 /* EINVAL */);
}

static void
test_passthrough_when_unregistered(void)
{
    /* Make sure no handler is installed. */
    (void)mojit_hook_register(MOJIT_HOOK_ABI_VERSION, NULL, NULL);

    mojit_regs_t regs;
    memset(&regs, 0, sizeof(regs));
    regs.nr = 172; /* getpid */

    mojit_verdict_t v = mojit_hook_enter(&regs);
    assert(v == MOJIT_PASSTHROUGH);
}

static void
test_handler_fires_and_sees_user_data(void)
{
    g_handler_calls = 0;

    int rc = mojit_hook_register(MOJIT_HOOK_ABI_VERSION,
                                 test_handler,
                                 (void *)0xdeadbeefUL);
    assert(rc == 0);

    mojit_regs_t regs;
    memset(&regs, 0, sizeof(regs));
    regs.nr = 172;

    mojit_verdict_t v = mojit_hook_enter(&regs);
    assert(v == MOJIT_HANDLED);
    assert(regs.x[0] == 1234);
    assert(g_handler_calls == 1);

    /* Unregister. */
    (void)mojit_hook_register(MOJIT_HOOK_ABI_VERSION, NULL, NULL);
}

static void
test_init_is_idempotent(void)
{
    int rc = mojit_hook_init();
    assert(rc == 0);
    rc = mojit_hook_init();
    assert(rc == -114 /* EALREADY */);
    mojit_hook_shutdown();
    /* After shutdown, init can succeed again. */
    rc = mojit_hook_init();
    assert(rc == 0);
    mojit_hook_shutdown();
}

int
main(void)
{
    test_version_rejected();
    test_passthrough_when_unregistered();
    test_handler_fires_and_sees_user_data();
    test_init_is_idempotent();
    printf("mojit_hook_test: OK\n");
    return 0;
}
