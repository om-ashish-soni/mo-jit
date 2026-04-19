package gate

import "sync"

// FDTable maps guest-visible file descriptors to host file descriptors
// owned by the gate. The guest has its own fd namespace separate from
// the host: guest fd 3 might correspond to host fd 17 after a few
// unrelated host opens by the runtime itself.
//
// Guest fds 0, 1, 2 (stdin, stdout, stderr) map to host 0, 1, 2 so
// that printf/panic messages still reach the user's terminal during
// early bring-up. A full PID/TTY namespace would replace these with
// pipes into a guest-attached PTY; that's M4+ work.
//
// Thread-safety: a single mutex guards every field. Guest fd churn is
// infrequent compared to path syscalls, so RWMutex would be
// over-engineered.
type FDTable struct {
	mu      sync.Mutex
	entries map[int]int
}

// NewFDTable returns a table preseeded with stdio (0,1,2 -> host
// 0,1,2). Callers that want an empty table for testing can trim via
// Close.
func NewFDTable() *FDTable {
	return &FDTable{
		entries: map[int]int{0: 0, 1: 1, 2: 2},
	}
}

// Allocate registers hostFd under the smallest free guest fd and
// returns it. Linux open(2) guarantees lowest-free-fd allocation
// starting at 0, including below 3 if stdin/stdout/stderr were
// closed. A program that closes fd 1 and then opens a file gets
// fd 1 back, and code that hardcodes "stdout is fd 1" breaks
// accordingly. We mirror that behaviour faithfully.
//
// Allocate never fails in isolation — the table has no ceiling. A
// real rlimit check belongs at the caller (the openat handler).
func (t *FDTable) Allocate(hostFd int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	for g := 0; ; g++ {
		if _, taken := t.entries[g]; !taken {
			t.entries[g] = hostFd
			return g
		}
	}
}

// Resolve returns the host fd for a guest fd. ok is false if the
// guest fd is not currently open, which handlers translate to EBADF.
func (t *FDTable) Resolve(guestFd int) (hostFd int, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	host, ok := t.entries[guestFd]
	return host, ok
}

// Close removes the entry for guestFd and returns the host fd so the
// caller can close(2) it on the host. Returns ok=false if guestFd was
// not open. The table never closes the host fd itself — the calling
// handler owns that side effect so it can pick up errors (EINTR etc.)
// from the kernel directly.
func (t *FDTable) Close(guestFd int) (hostFd int, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	host, ok := t.entries[guestFd]
	if !ok {
		return -1, false
	}
	delete(t.entries, guestFd)
	return host, true
}

// Len returns the number of currently-open guest fds. Intended for
// tests and /proc/self/fd approximations; not on any hot path.
func (t *FDTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}
