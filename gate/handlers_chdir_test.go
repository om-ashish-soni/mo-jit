package gate

import (
	"path/filepath"
	"syscall"
	"testing"
)

// newChdirHarness returns a Dispatcher wired with a LowerDir under
// t.TempDir and a FakePathReader, ready for chdir tests. It hands
// back helpers so each test can register a guest path -> host path
// mapping and stage the bytes at a guest pointer in one line.
type chdirHarness struct {
	d     *Dispatcher
	lower string
	paths *FakePathReader
}

func newChdirHarness(t *testing.T) *chdirHarness {
	t.Helper()
	lower := filepath.Join(t.TempDir(), "lower")
	mustMkdirAll(t, lower)
	d := NewDispatcher(Policy{LowerDir: lower})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	return &chdirHarness{d: d, lower: lower, paths: paths}
}

// call stages guestPath at ptr and runs the chdir handler for it.
func (h *chdirHarness) call(ptr uint64, guestPath string) *Regs {
	h.paths.Entries[ptr] = guestPath
	r := &Regs{NR: SysChDir}
	r.X[0] = ptr
	h.d.Dispatch(r)
	return r
}

// expectErrno asserts regs.X[0] encodes -errno.
func expectErrno(t *testing.T, r *Regs, want syscall.Errno) {
	t.Helper()
	got := int64(r.X[0])
	expected := int64(-int(want))
	if got != expected {
		t.Errorf("regs.X[0] = %d (%#x), want %d (errno %s)", got, r.X[0], expected, want)
	}
}

func TestChDirSuccessAbsolutePathSetsCwd(t *testing.T) {
	h := newChdirHarness(t)
	mustMkdirAll(t, filepath.Join(h.lower, "home/dev"))

	r := h.call(0xaa01, "/home/dev")

	if r.X[0] != 0 {
		t.Fatalf("chdir should succeed, got X[0]=%#x", r.X[0])
	}
	if cwd := h.d.FS.GuestCwd(); cwd != "/home/dev" {
		t.Errorf("GuestCwd = %q, want /home/dev", cwd)
	}
}

func TestChDirSuccessRelativePathMergesWithCwd(t *testing.T) {
	h := newChdirHarness(t)
	mustMkdirAll(t, filepath.Join(h.lower, "home/dev/project"))
	if err := h.d.FS.SetGuestCwd("/home/dev"); err != nil {
		t.Fatal(err)
	}

	r := h.call(0xaa02, "project")

	if r.X[0] != 0 {
		t.Fatalf("chdir relative should succeed, got X[0]=%#x", r.X[0])
	}
	if cwd := h.d.FS.GuestCwd(); cwd != "/home/dev/project" {
		t.Errorf("GuestCwd = %q, want /home/dev/project", cwd)
	}
}

func TestChDirReadPathFaultReturnsEFAULT(t *testing.T) {
	h := newChdirHarness(t)
	// Do NOT register the pointer — FakePathReader will return ErrFault.
	r := &Regs{NR: SysChDir}
	r.X[0] = 0xdead
	h.d.Dispatch(r)

	expectErrno(t, r, syscall.EFAULT)
	if cwd := h.d.FS.GuestCwd(); cwd != "/" {
		t.Errorf("failed chdir must leave cwd at /, got %q", cwd)
	}
}

func TestChDirNullPointerReturnsEFAULT(t *testing.T) {
	h := newChdirHarness(t)
	r := &Regs{NR: SysChDir}
	r.X[0] = 0
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EFAULT)
}

func TestChDirMissingDirReturnsENOENT(t *testing.T) {
	h := newChdirHarness(t)
	// /nope has no backing on lower.
	r := h.call(0xaa03, "/nope")
	expectErrno(t, r, syscall.ENOENT)
	if cwd := h.d.FS.GuestCwd(); cwd != "/" {
		t.Errorf("failed chdir must not mutate cwd, got %q", cwd)
	}
}

func TestChDirFileReturnsENOTDIR(t *testing.T) {
	h := newChdirHarness(t)
	mustTouch(t, filepath.Join(h.lower, "etc/hostname"))

	r := h.call(0xaa04, "/etc/hostname")
	expectErrno(t, r, syscall.ENOTDIR)
}

func TestChDirWhiteoutReturnsENOENT(t *testing.T) {
	h := newChdirHarness(t)
	upper := filepath.Join(t.TempDir(), "upper")
	mustMkdirAll(t, filepath.Join(h.lower, "workspace"))
	ok := mustWhiteout(t, filepath.Join(upper, "workspace"))
	if !ok {
		return
	}
	// Rebuild dispatcher with both lower and upper configured.
	h.d = NewDispatcher(Policy{LowerDir: h.lower, UpperDir: upper})
	h.d.Paths = h.paths

	r := h.call(0xaa05, "/workspace")
	expectErrno(t, r, syscall.ENOENT)
}

func TestChDirPathTooLongFaults(t *testing.T) {
	h := newChdirHarness(t)
	// Craft a path longer than MaxPathLen. FakePathReader checks
	// len+1 > maxLen, so this produces ErrFault → EFAULT. The real
	// kernel would return ENAMETOOLONG; that refinement belongs to
	// the production PathReader and the handler if we ever separate
	// fault vs. too-long in ReadPath's contract.
	long := make([]byte, MaxPathLen+10)
	for i := range long {
		long[i] = 'a'
	}
	long[0] = '/'
	r := h.call(0xaa06, string(long))
	expectErrno(t, r, syscall.EFAULT)
}

func TestChDirDispatchRouted(t *testing.T) {
	// Pin that registerDefaults actually wired chdir — a fresh
	// Dispatcher with no user Register must dispatch NR=SysChDir to
	// handleChDir. Without the wiring, we'd hit VerdictPassthrough.
	h := newChdirHarness(t)
	r := h.call(0xaa07, "/nope")
	// Handler ran (we got Handled + an errno) — if dispatch had
	// passed through, X[0] would be unchanged from whatever we set.
	if int64(r.X[0]) >= 0 {
		t.Errorf("chdir not routed to handler; X[0]=%#x", r.X[0])
	}
}
