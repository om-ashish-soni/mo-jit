/*
 * memfd_alloc_test.c — portable smoke test for the memfd-backed W^X
 * code allocator. Runs on any Linux host that allows memfd_create +
 * mmap(PROT_EXEC) on tmpfs (CI runners, generic dev boxes, and the
 * Android targets we actually ship to).
 *
 * Build:
 *   cc -std=c11 -pthread memfd_alloc.c memfd_alloc_test.c -o memfd_alloc_test
 * Run:
 *   ./memfd_alloc_test
 *
 * Exec coverage: on x86_64 and aarch64 hosts we assemble a tiny
 * "return 42" function into the allocated region and call it. On
 * other hosts the exec test is skipped (only the alloc/free
 * plumbing is exercised). The production target is aarch64 but CI
 * runs on x86_64 — both paths must stay healthy.
 */

#include "mojit_hook.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void
test_alloc_basic(void)
{
    int fd = -1;
    void *p = mojit_code_alloc(0, &fd);
    assert(p != NULL);
    assert(fd >= 0);

    /* Region is writable and readable. */
    memset(p, 0xaa, 256);
    assert(((uint8_t *)p)[0]   == 0xaa);
    assert(((uint8_t *)p)[255] == 0xaa);

    mojit_code_free(p, 0);
}

static void
test_alloc_page_rounding(void)
{
    int fd = -1;
    void *p = mojit_code_alloc(1, &fd);
    assert(p != NULL);

    long pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0) {
        pg = 4096;
    }

    /* The full page should be writable even though we asked for 1 byte. */
    memset(p, 0x55, (size_t)pg);
    assert(((uint8_t *)p)[pg - 1] == 0x55);

    mojit_code_free(p, 0);
}

static void
test_out_fd_nullable(void)
{
    void *p = mojit_code_alloc(128, NULL);
    assert(p != NULL);
    mojit_code_free(p, 0);
}

static void
test_multiple_allocations(void)
{
    void *a = mojit_code_alloc(64, NULL);
    void *b = mojit_code_alloc(64, NULL);
    void *c = mojit_code_alloc(64, NULL);
    assert(a != NULL && b != NULL && c != NULL);
    assert(a != b && b != c && a != c);

    memset(a, 1, 64);
    memset(b, 2, 64);
    memset(c, 3, 64);
    assert(((uint8_t *)a)[0] == 1);
    assert(((uint8_t *)b)[0] == 2);
    assert(((uint8_t *)c)[0] == 3);

    /* Free out of order to exercise the linked-list unlink. */
    mojit_code_free(b, 0);
    mojit_code_free(a, 0);
    mojit_code_free(c, 0);
}

static void
test_free_null_is_noop(void)
{
    mojit_code_free(NULL, 0);
    mojit_code_free(NULL, 1024);
}

static void
test_free_unknown_ptr_is_noop(void)
{
    int dummy = 0;
    /* A pointer we never allocated. Must not crash, must not touch
     * the real allocation list. */
    mojit_code_free(&dummy, 0);

    /* Verify normal alloc/free still works after a spurious free. */
    void *p = mojit_code_alloc(64, NULL);
    assert(p != NULL);
    mojit_code_free(p, 0);
}

#if defined(__x86_64__) || defined(__aarch64__)
typedef int (*fn42_t)(void);

static void
test_exec(void)
{
    int fd = -1;
    void *p = mojit_code_alloc(64, &fd);
    assert(p != NULL);

    uint8_t *code = (uint8_t *)p;
# if defined(__x86_64__)
    /* x86_64: mov eax, 42 ; ret */
    static const uint8_t prog[] = {
        0xb8, 0x2a, 0x00, 0x00, 0x00,   /* mov eax, 0x2a */
        0xc3                             /* ret           */
    };
    memcpy(code, prog, sizeof(prog));
# else /* __aarch64__ */
    /* aarch64: mov w0, #42 ; ret */
    static const uint8_t prog[] = {
        0x40, 0x05, 0x80, 0x52,          /* mov w0, #0x2a */
        0xc0, 0x03, 0x5f, 0xd6           /* ret           */
    };
    memcpy(code, prog, sizeof(prog));
    __builtin___clear_cache((char *)code,
                            (char *)code + sizeof(prog));
# endif

    fn42_t fn = (fn42_t)(uintptr_t)code;
    int result = fn();
    assert(result == 42);

    mojit_code_free(p, 0);
}
#else
static void
test_exec(void)
{
    /* Unsupported arch for this smoke test — skip quietly. The
     * alloc/free plumbing above still exercises the W^X path. */
}
#endif

int
main(void)
{
    test_alloc_basic();
    test_alloc_page_rounding();
    test_out_fd_nullable();
    test_multiple_allocations();
    test_free_null_is_noop();
    test_free_unknown_ptr_is_noop();
    test_exec();
    printf("memfd_alloc_test: OK\n");
    return 0;
}
