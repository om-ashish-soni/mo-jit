package gate

import (
	"path/filepath"
	"syscall"
	"testing"
)

// atFDCWDAsX0 returns AT_FDCWD in the exact uint64 encoding the guest
// places in x0. Extracted to a function so the constant -100 doesn't
// trip Go's uint64 overflow check on -int conversions.
func atFDCWDAsX0() uint64 {
	v := atFDCWD
	return uint64(int64(v))
}

type faccessHarness struct {
	d     *Dispatcher
	lower string
	paths *FakePathReader
}

func newFAccessHarness(t *testing.T) *faccessHarness {
	t.Helper()
	lower := filepath.Join(t.TempDir(), "lower")
	mustMkdirAll(t, lower)
	d := NewDispatcher(Policy{LowerDir: lower})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	return &faccessHarness{d: d, lower: lower, paths: paths}
}

// call stages a guest path at ptr and invokes faccessat(NR) with the
// given (dirfd, mode, flags). Returns the regs mutated by dispatch.
func (h *faccessHarness) call(nr, dirfd, ptr, mode, flags uint64, path string) *Regs {
	h.paths.Entries[ptr] = path
	r := &Regs{NR: nr}
	r.X[0] = dirfd
	r.X[1] = ptr
	r.X[2] = mode
	r.X[3] = flags
	h.d.Dispatch(r)
	return r
}

func TestFAccessAt2SuccessOnExistingFile(t *testing.T) {
	h := newFAccessHarness(t)
	mustTouch(t, filepath.Join(h.lower, "etc/hostname"))

	r := h.call(SysFAccessAt2, atFDCWDAsX0(), 0xb001, 0 /*F_OK*/, 0, "/etc/hostname")
	if r.X[0] != 0 {
		t.Errorf("F_OK on existing file: X[0]=%#x, want 0", r.X[0])
	}
}

func TestFAccessAt3ArgSuccess(t *testing.T) {
	h := newFAccessHarness(t)
	mustTouch(t, filepath.Join(h.lower, "etc/hostname"))

	// NR=48 faccessat has no flags — X[3] ignored.
	r := h.call(SysFAccessAt, atFDCWDAsX0(), 0xb002, 0, 0xdeadbeef, "/etc/hostname")
	if r.X[0] != 0 {
		t.Errorf("faccessat (no flags) on existing file: X[0]=%#x, want 0", r.X[0])
	}
}

func TestFAccessAt2MissingFileReturnsENOENT(t *testing.T) {
	h := newFAccessHarness(t)
	r := h.call(SysFAccessAt2, atFDCWDAsX0(), 0xb003, 0, 0, "/etc/no-such-file")
	expectErrno(t, r, syscall.ENOENT)
}

func TestFAccessAt2NullPointerReturnsEFAULT(t *testing.T) {
	h := newFAccessHarness(t)
	r := &Regs{NR: SysFAccessAt2}
	r.X[0] = atFDCWDAsX0()
	r.X[1] = 0
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EFAULT)
}

func TestFAccessAt2UnknownDirfdReturnsEBADF(t *testing.T) {
	// Real dirfd (not AT_FDCWD). Until the fd table lands we can't
	// resolve it — must return EBADF deterministically rather than
	// silently resolving against the host cwd.
	h := newFAccessHarness(t)
	mustTouch(t, filepath.Join(h.lower, "etc/hostname"))
	r := h.call(SysFAccessAt2, 5, 0xb004, 0, 0, "/etc/hostname")
	expectErrno(t, r, syscall.EBADF)
}

func TestFAccessAt2RelativePathUsesCwd(t *testing.T) {
	h := newFAccessHarness(t)
	mustTouch(t, filepath.Join(h.lower, "home/dev/note.txt"))
	if err := h.d.FS.SetGuestCwd("/home/dev"); err != nil {
		t.Fatal(err)
	}
	r := h.call(SysFAccessAt2, atFDCWDAsX0(), 0xb005, 0, 0, "note.txt")
	if r.X[0] != 0 {
		t.Errorf("relative path via cwd: X[0]=%#x, want 0", r.X[0])
	}
}

func TestFAccessAt2WhiteoutReturnsENOENT(t *testing.T) {
	h := newFAccessHarness(t)
	upper := filepath.Join(t.TempDir(), "upper")
	mustTouch(t, filepath.Join(h.lower, "secret.txt"))
	if ok := mustWhiteout(t, filepath.Join(upper, "secret.txt")); !ok {
		return
	}
	h.d = NewDispatcher(Policy{LowerDir: h.lower, UpperDir: upper})
	h.d.Paths = h.paths

	r := h.call(SysFAccessAt2, atFDCWDAsX0(), 0xb006, 0, 0, "/secret.txt")
	expectErrno(t, r, syscall.ENOENT)
}

func TestFAccessAt2DispatchRouted(t *testing.T) {
	h := newFAccessHarness(t)
	r := h.call(SysFAccessAt2, atFDCWDAsX0(), 0xb007, 0, 0, "/nope")
	if int64(r.X[0]) >= 0 {
		t.Errorf("faccessat2 not routed; X[0]=%#x", r.X[0])
	}
}

func TestFAccessAtDispatchRouted(t *testing.T) {
	h := newFAccessHarness(t)
	r := h.call(SysFAccessAt, atFDCWDAsX0(), 0xb008, 0, 0, "/nope")
	if int64(r.X[0]) >= 0 {
		t.Errorf("faccessat not routed; X[0]=%#x", r.X[0])
	}
}
