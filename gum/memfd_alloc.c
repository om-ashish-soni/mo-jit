/*
 * memfd_alloc.c — memfd-backed W^X code-cache allocator.
 *
 * Android 10+ denies `mmap(PROT_EXEC)` on `app_data_file` inodes for
 * `untrusted_app`. An anonymous RWX mapping via /dev/ashmem or plain
 * MAP_ANONYMOUS is gone too — SELinux enforces `execmem` / `execmod`
 * denials that kill `mmap(PROT_EXEC)` on anything backed by app-owned
 * disk. memfd pages land in a tmpfs-flavoured inode under a distinct
 * SELinux context that stays exec-allowed for `untrusted_app` across
 * every Android release we target in 2026 (10..16).
 *
 * What we do:
 *   1. memfd_create("mojit-code", MFD_CLOEXEC [| MFD_EXEC]).
 *   2. ftruncate to a page-rounded size.
 *   3. mmap(PROT_R|W|X, MAP_SHARED, fd).
 *   4. Remember (ptr, size, fd) in a linked list so free() can tear
 *      the region down cleanly.
 *
 * MFD_EXEC (Linux 6.3, Android 14+): signals to the kernel that the
 * returned fd is intended for executable mappings. Older kernels
 * reject the flag with EINVAL; we retry without it and still succeed.
 *
 * This v0 allocator does one memfd per allocation. Stalker's real
 * working set is a handful of long-lived code slabs, not a flood of
 * tiny requests, so the bookkeeping cost is negligible. A pool
 * allocator sitting on top of a single big memfd is an optimization
 * for v0.2 once we have measurements from real workloads.
 *
 * Thread-safety: the allocation record list is guarded by g_alloc_lock.
 * The code region itself carries no lock — concurrent writers are the
 * caller's problem (Stalker already serializes code-cache publication
 * via its own locks).
 *
 * Copyright 2026 Om Ashish Soni and mo-jit contributors.
 * SPDX-License-Identifier: Apache-2.0
 */

/* _GNU_SOURCE exposes syscall() from <unistd.h> on glibc and bionic.
 * We call memfd_create via syscall() because older glibc (<2.27) and
 * bionic in NDK r23 lack the libc wrapper. The syscall number is
 * stable across every kernel we target. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mojit_hook.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

/* Defined by the kernel UAPI on Linux 6.3+. We hard-code the value so
 * we compile cleanly against older sysroots (Android NDK r26 targets
 * glibc 2.17-flavoured headers). The kernel either accepts the bit or
 * returns EINVAL; we handle the fallback. */
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

#define PAGE_ALIGN_UP(x, pg) (((x) + (pg) - 1) & ~((pg) - 1))

static int
memfd_create_compat(const char *name, unsigned int flags)
{
#ifdef __linux__
    /* Always go through syscall() — older glibc/bionic may lack the
     * libc wrapper, and the syscall number is stable across our
     * target kernels. */
    return (int)syscall(SYS_memfd_create, name, flags);
#else
    (void)name;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

typedef struct alloc_record {
    void                *ptr;
    size_t               size;
    int                  fd;
    struct alloc_record *next;
} alloc_record_t;

static pthread_mutex_t g_alloc_lock = PTHREAD_MUTEX_INITIALIZER;
static alloc_record_t *g_alloc_head = NULL;

void *
mojit_code_alloc(size_t size_hint, int *out_fd)
{
    long pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0) {
        pg = 4096;
    }
    size_t size = PAGE_ALIGN_UP(size_hint ? size_hint : (size_t)pg,
                                (size_t)pg);

    /* Prefer MFD_EXEC on kernels that support it. If the kernel is
     * older and rejects the unknown flag with EINVAL, retry without.
     * Any other failure is terminal. */
    int fd = memfd_create_compat("mojit-code", MFD_CLOEXEC | MFD_EXEC);
    if (fd < 0 && errno == EINVAL) {
        fd = memfd_create_compat("mojit-code", MFD_CLOEXEC);
    }
    if (fd < 0) {
        return NULL;
    }

    if (ftruncate(fd, (off_t)size) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return NULL;
    }

    void *ptr = mmap(NULL, size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        int err = errno;
        close(fd);
        errno = err;
        return NULL;
    }

    alloc_record_t *rec = (alloc_record_t *)calloc(1, sizeof(*rec));
    if (rec == NULL) {
        munmap(ptr, size);
        close(fd);
        errno = ENOMEM;
        return NULL;
    }
    rec->ptr  = ptr;
    rec->size = size;
    rec->fd   = fd;

    pthread_mutex_lock(&g_alloc_lock);
    rec->next    = g_alloc_head;
    g_alloc_head = rec;
    pthread_mutex_unlock(&g_alloc_lock);

    if (out_fd != NULL) {
        *out_fd = fd;
    }
    return ptr;
}

void
mojit_code_free(void *ptr, size_t size)
{
    /* size is advisory — we always trust the page-rounded size we
     * recorded at alloc time. Keeping the parameter in the signature
     * matches standard "size-tracking free" idioms and leaves room to
     * validate caller expectations in debug builds. */
    (void)size;

    if (ptr == NULL) {
        return;
    }

    pthread_mutex_lock(&g_alloc_lock);
    alloc_record_t **cur = &g_alloc_head;
    alloc_record_t  *rec = NULL;
    while (*cur != NULL) {
        if ((*cur)->ptr == ptr) {
            rec  = *cur;
            *cur = rec->next;
            break;
        }
        cur = &(*cur)->next;
    }
    pthread_mutex_unlock(&g_alloc_lock);

    if (rec == NULL) {
        /* Double-free or unknown pointer. Silent: this is a hot path
         * under gum's code-cache eviction and noisy logging inside
         * Stalker's teardown risks re-entering the svc hook. A debug
         * build can add an assert; release stays quiet. */
        return;
    }

    munmap(rec->ptr, rec->size);
    close(rec->fd);
    free(rec);
}
