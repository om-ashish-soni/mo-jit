package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type openatHarness struct {
	d     *Dispatcher
	lower string
	upper string
	paths *FakePathReader
}

func newOpenAtHarness(t *testing.T, withUpper bool) *openatHarness {
	t.Helper()
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	mustMkdirAll(t, lower)
	pol := Policy{LowerDir: lower}
	h := &openatHarness{lower: lower}
	if withUpper {
		upper := filepath.Join(tmp, "upper")
		mustMkdirAll(t, upper)
		pol.UpperDir = upper
		h.upper = upper
	}
	d := NewDispatcher(pol)
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	h.d = d
	h.paths = paths
	return h
}

func (h *openatHarness) open(ptr uint64, path string, dirfd int64, flags int, mode uint32) *Regs {
	h.paths.Entries[ptr] = path
	r := &Regs{NR: SysOpenAt}
	r.X[0] = uint64(dirfd)
	r.X[1] = ptr
	r.X[2] = uint64(flags)
	r.X[3] = uint64(mode)
	h.d.Dispatch(r)
	return r
}

func TestOpenAtReadOnlyLowerSucceeds(t *testing.T) {
	h := newOpenAtHarness(t, false)
	mustTouch(t, filepath.Join(h.lower, "etc/hostname"))

	r := h.open(0x5001, "/etc/hostname", int64(atFDCWD), syscall.O_RDONLY, 0)
	guestFd := int64(r.X[0])
	if guestFd < 0 {
		t.Fatalf("O_RDONLY on lower: X[0]=%d (%s)", guestFd, syscall.Errno(-guestFd))
	}
	// Record that the dispatcher stored a valid host fd for us.
	if _, ok := h.d.FDs.Resolve(int(guestFd)); !ok {
		t.Errorf("FDs.Resolve(%d) missing after openat", guestFd)
	}
	// Clean up: close it.
	cr := &Regs{NR: SysClose}
	cr.X[0] = uint64(guestFd)
	h.d.Dispatch(cr)
	if cr.X[0] != 0 {
		t.Errorf("close after openat: X[0]=%#x, want 0", cr.X[0])
	}
}

func TestOpenAtMissingReturnsENOENT(t *testing.T) {
	h := newOpenAtHarness(t, false)
	r := h.open(0x5002, "/nope", int64(atFDCWD), syscall.O_RDONLY, 0)
	expectErrno(t, r, syscall.ENOENT)
}

func TestOpenAtWritableLowerReturnsEROFS(t *testing.T) {
	// Without copy-up, writable opens on lower must surface EROFS
	// rather than silently escape the overlay.
	h := newOpenAtHarness(t, false)
	mustTouch(t, filepath.Join(h.lower, "file.txt"))
	r := h.open(0x5003, "/file.txt", int64(atFDCWD), syscall.O_WRONLY, 0)
	expectErrno(t, r, syscall.EROFS)
}

func TestOpenAtWritableLowerCopiesUp(t *testing.T) {
	// With UpperDir configured, a writable open on a lower-only file
	// must trigger copy-up: the open succeeds against a fresh upper
	// copy, subsequent writes hit upper, and the lower backing is
	// left untouched.
	h := newOpenAtHarness(t, true)
	lowerFile := filepath.Join(h.lower, "etc/config")
	mustMkdirAll(t, filepath.Join(h.lower, "etc"))
	if err := os.WriteFile(lowerFile, []byte("orig"), 0o640); err != nil {
		t.Fatal(err)
	}

	r := h.open(0x5020, "/etc/config", int64(atFDCWD), syscall.O_WRONLY, 0)
	guestFd := int64(r.X[0])
	if guestFd < 0 {
		t.Fatalf("writable lower with UpperDir: X[0]=%d (%s)",
			guestFd, syscall.Errno(-guestFd))
	}

	// Upper copy must exist with the original content and mode.
	upperFile := filepath.Join(h.upper, "etc/config")
	got, err := os.ReadFile(upperFile)
	if err != nil {
		t.Fatalf("upper copy missing after open: %v", err)
	}
	if string(got) != "orig" {
		t.Errorf("upper content after copy-up = %q, want orig", got)
	}

	// Write through the returned fd and verify it lands on upper,
	// not lower.
	mr := &FakeMemReader{}
	mr.Stage(0xc000, []byte("mutated"))
	h.d.MemR = mr
	w := &Regs{NR: SysWrite}
	w.X[0] = uint64(guestFd)
	w.X[1] = 0xc000
	w.X[2] = 7
	h.d.Dispatch(w)
	if int64(w.X[0]) != 7 {
		t.Fatalf("write through copied-up fd: X[0]=%d", int64(w.X[0]))
	}

	cr := &Regs{NR: SysClose}
	cr.X[0] = uint64(guestFd)
	h.d.Dispatch(cr)

	// Upper now holds the mutation; lower is still the pristine
	// backing. This is the whole point of copy-up.
	upperAfter, err := os.ReadFile(upperFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(upperAfter) != "mutated" {
		t.Errorf("upper after write = %q, want mutated", upperAfter)
	}
	lowerAfter, err := os.ReadFile(lowerFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(lowerAfter) != "orig" {
		t.Errorf("lower mutated after copy-up write: %q", lowerAfter)
	}
}

func TestOpenAtWritableUpperSucceeds(t *testing.T) {
	h := newOpenAtHarness(t, true)
	mustTouch(t, filepath.Join(h.upper, "file.txt"))

	r := h.open(0x5004, "/file.txt", int64(atFDCWD), syscall.O_WRONLY, 0)
	if int64(r.X[0]) < 0 {
		t.Fatalf("writable upper open: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	// Clean up.
	cr := &Regs{NR: SysClose}
	cr.X[0] = r.X[0]
	h.d.Dispatch(cr)
}

func TestOpenAtCreatOnUpperSucceeds(t *testing.T) {
	h := newOpenAtHarness(t, true)

	r := h.open(0x5005, "/new.txt", int64(atFDCWD),
		syscall.O_WRONLY|syscall.O_CREAT, 0o644)
	if int64(r.X[0]) < 0 {
		t.Fatalf("O_CREAT on upper: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	// File must exist on the upper layer now.
	if _, err := os.Stat(filepath.Join(h.upper, "new.txt")); err != nil {
		t.Errorf("expected new.txt on upper, got %v", err)
	}
	// Close and verify fd is released.
	guestFd := r.X[0]
	cr := &Regs{NR: SysClose}
	cr.X[0] = guestFd
	h.d.Dispatch(cr)
	if _, ok := h.d.FDs.Resolve(int(guestFd)); ok {
		t.Errorf("FDs still holds guest fd %d after close", guestFd)
	}
}

func TestOpenAtRelativePathUsesCwd(t *testing.T) {
	h := newOpenAtHarness(t, false)
	mustTouch(t, filepath.Join(h.lower, "home/dev/main.go"))
	if err := h.d.FS.SetGuestCwd("/home/dev"); err != nil {
		t.Fatal(err)
	}

	r := h.open(0x5006, "main.go", int64(atFDCWD), syscall.O_RDONLY, 0)
	if int64(r.X[0]) < 0 {
		t.Fatalf("relative via cwd: X[0]=%d", int64(r.X[0]))
	}
	cr := &Regs{NR: SysClose}
	cr.X[0] = r.X[0]
	h.d.Dispatch(cr)
}

func TestOpenAtDirRelativeWithRealDirfdReturnsENOSYS(t *testing.T) {
	h := newOpenAtHarness(t, false)
	// Valid dirfd (stdin=0) + relative path → not yet supported.
	r := h.open(0x5007, "foo.txt", 0, syscall.O_RDONLY, 0)
	expectErrno(t, r, syscall.ENOSYS)
}

func TestOpenAtAbsolutePathIgnoresDirfd(t *testing.T) {
	h := newOpenAtHarness(t, false)
	mustTouch(t, filepath.Join(h.lower, "etc/hostname"))
	// dirfd is a junk value; absolute path must succeed anyway.
	r := h.open(0x5008, "/etc/hostname", 12345, syscall.O_RDONLY, 0)
	if int64(r.X[0]) < 0 {
		t.Fatalf("absolute path with random dirfd: X[0]=%d", int64(r.X[0]))
	}
	cr := &Regs{NR: SysClose}
	cr.X[0] = r.X[0]
	h.d.Dispatch(cr)
}

func TestOpenAtWhiteoutReturnsENOENT(t *testing.T) {
	h := newOpenAtHarness(t, true)
	mustTouch(t, filepath.Join(h.lower, "secret"))
	if ok := mustWhiteout(t, filepath.Join(h.upper, "secret")); !ok {
		return
	}
	r := h.open(0x5009, "/secret", int64(atFDCWD), syscall.O_RDONLY, 0)
	expectErrno(t, r, syscall.ENOENT)
}

func TestOpenAtPathFaultReturnsEFAULT(t *testing.T) {
	h := newOpenAtHarness(t, false)
	r := &Regs{NR: SysOpenAt}
	r.X[0] = atFDCWDAsX0()
	r.X[1] = 0 // NULL
	r.X[2] = uint64(syscall.O_RDONLY)
	r.X[3] = 0
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EFAULT)
}

func TestCloseUnknownFdReturnsEBADF(t *testing.T) {
	h := newOpenAtHarness(t, false)
	r := &Regs{NR: SysClose}
	r.X[0] = 999
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EBADF)
}

func TestCloseStdioSucceeds(t *testing.T) {
	h := newOpenAtHarness(t, false)
	// Need a fresh dispatcher so we don't close the test process's
	// real stdio — but the FDTable preseed means guest fd 1 maps to
	// host fd 1, which IS the test runner's stdout. Avoid closing
	// that in the test by duping host fd 1 first and preseeding with
	// the dup.
	dup, err := syscall.Dup(1)
	if err != nil {
		t.Fatal(err)
	}
	h.d.FDs = &FDTable{entries: map[int]int{0: 0, 1: dup, 2: 2}}

	r := &Regs{NR: SysClose}
	r.X[0] = 1
	h.d.Dispatch(r)
	if r.X[0] != 0 {
		t.Errorf("close(1) = %#x, want 0", r.X[0])
	}
	// Must be released from the table.
	if _, ok := h.d.FDs.Resolve(1); ok {
		t.Errorf("FDs still holds fd 1 after close")
	}
}

func TestOpenAtFdLowestFreeMatchesPOSIX(t *testing.T) {
	h := newOpenAtHarness(t, false)
	mustTouch(t, filepath.Join(h.lower, "a"))
	mustTouch(t, filepath.Join(h.lower, "b"))

	r1 := h.open(0x5010, "/a", int64(atFDCWD), syscall.O_RDONLY, 0)
	r2 := h.open(0x5011, "/b", int64(atFDCWD), syscall.O_RDONLY, 0)
	if r1.X[0] != 3 {
		t.Errorf("first open fd = %d, want 3", int64(r1.X[0]))
	}
	if r2.X[0] != 4 {
		t.Errorf("second open fd = %d, want 4", int64(r2.X[0]))
	}

	// Close fd 3, then open again — must reuse fd 3.
	cr := &Regs{NR: SysClose}
	cr.X[0] = r1.X[0]
	h.d.Dispatch(cr)

	r3 := h.open(0x5012, "/a", int64(atFDCWD), syscall.O_RDONLY, 0)
	if r3.X[0] != 3 {
		t.Errorf("reuse: got fd %d, want 3", int64(r3.X[0]))
	}

	// Cleanup
	for _, fd := range []uint64{r2.X[0], r3.X[0]} {
		c := &Regs{NR: SysClose}
		c.X[0] = fd
		h.d.Dispatch(c)
	}
}
