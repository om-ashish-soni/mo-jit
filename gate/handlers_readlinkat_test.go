package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type readlinkHarness struct {
	d     *Dispatcher
	lower string
	paths *FakePathReader
	mem   *FakeMemWriter
}

func newReadLinkHarness(t *testing.T) *readlinkHarness {
	t.Helper()
	lower := filepath.Join(t.TempDir(), "lower")
	mustMkdirAll(t, lower)
	d := NewDispatcher(Policy{LowerDir: lower})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	mem := &FakeMemWriter{}
	d.Paths = paths
	d.Mem = mem
	return &readlinkHarness{d: d, lower: lower, paths: paths, mem: mem}
}

func (h *readlinkHarness) symlink(t *testing.T, linkPath, target string) {
	t.Helper()
	mustMkdirAll(t, filepath.Dir(linkPath))
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatal(err)
	}
}

func (h *readlinkHarness) call(dirfd int64, pathPtr uint64, path string, buf uint64, bufsiz uint64) *Regs {
	h.paths.Entries[pathPtr] = path
	r := &Regs{NR: SysReadLinkAt}
	r.X[0] = uint64(dirfd)
	r.X[1] = pathPtr
	r.X[2] = buf
	r.X[3] = bufsiz
	h.d.Dispatch(r)
	return r
}

func TestReadLinkAtSuccessCopiesTarget(t *testing.T) {
	h := newReadLinkHarness(t)
	h.symlink(t, filepath.Join(h.lower, "etc/mtab"), "/proc/mounts")

	r := h.call(int64(atFDCWD), 0xc001, "/etc/mtab", 0x4000, 64)

	want := "/proc/mounts"
	if int64(r.X[0]) != int64(len(want)) {
		t.Errorf("X[0]=%d, want %d", r.X[0], len(want))
	}
	got := string(h.mem.Read(0x4000, len(want)))
	if got != want {
		t.Errorf("buffer = %q, want %q", got, want)
	}
	// NOT NUL-terminated per Linux readlinkat(2).
	if _, trailing := h.mem.Bytes[0x4000+uint64(len(want))]; trailing {
		t.Errorf("readlinkat must not write a NUL terminator")
	}
}

func TestReadLinkAtTruncatesToBufsiz(t *testing.T) {
	h := newReadLinkHarness(t)
	h.symlink(t, filepath.Join(h.lower, "lnk"), "abcdefghij")

	// bufsiz=4: only first 4 bytes land, return=4, NO error.
	r := h.call(int64(atFDCWD), 0xc002, "/lnk", 0x4100, 4)

	if int64(r.X[0]) != 4 {
		t.Errorf("truncation: X[0]=%d, want 4", r.X[0])
	}
	got := string(h.mem.Read(0x4100, 4))
	if got != "abcd" {
		t.Errorf("truncated buffer = %q, want %q", got, "abcd")
	}
	// Byte at offset 4 must NOT have been written.
	if _, ok := h.mem.Bytes[0x4100+4]; ok {
		t.Errorf("truncation leaked byte past bufsiz")
	}
}

func TestReadLinkAtRelativeTarget(t *testing.T) {
	h := newReadLinkHarness(t)
	// The target is copied verbatim — interpretation is the guest's
	// job on its next path syscall. So a relative target stays
	// relative.
	h.symlink(t, filepath.Join(h.lower, "etc/localtime"), "../usr/share/zoneinfo/UTC")

	r := h.call(int64(atFDCWD), 0xc003, "/etc/localtime", 0x4200, 128)
	want := "../usr/share/zoneinfo/UTC"
	if int64(r.X[0]) != int64(len(want)) {
		t.Errorf("X[0]=%d, want %d", r.X[0], len(want))
	}
	got := string(h.mem.Read(0x4200, len(want)))
	if got != want {
		t.Errorf("buffer = %q, want %q", got, want)
	}
}

func TestReadLinkAtNonSymlinkReturnsEINVAL(t *testing.T) {
	h := newReadLinkHarness(t)
	mustTouch(t, filepath.Join(h.lower, "regular.txt"))

	r := h.call(int64(atFDCWD), 0xc004, "/regular.txt", 0x4300, 64)
	expectErrno(t, r, syscall.EINVAL)
}

func TestReadLinkAtMissingReturnsENOENT(t *testing.T) {
	h := newReadLinkHarness(t)
	r := h.call(int64(atFDCWD), 0xc005, "/no-such-link", 0x4400, 64)
	expectErrno(t, r, syscall.ENOENT)
}

func TestReadLinkAtPathFaultReturnsEFAULT(t *testing.T) {
	h := newReadLinkHarness(t)
	// Don't register the path pointer.
	r := &Regs{NR: SysReadLinkAt}
	r.X[0] = atFDCWDAsX0()
	r.X[1] = 0xdead
	r.X[2] = 0x4500
	r.X[3] = 64
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EFAULT)
}

func TestReadLinkAtZeroBufsizReturnsEINVAL(t *testing.T) {
	// Linux readlinkat(2): EINVAL if bufsiz <= 0.
	h := newReadLinkHarness(t)
	h.symlink(t, filepath.Join(h.lower, "lnk"), "target")
	r := h.call(int64(atFDCWD), 0xc006, "/lnk", 0x4600, 0)
	expectErrno(t, r, syscall.EINVAL)
}

func TestReadLinkAtWriteFaultReturnsEFAULT(t *testing.T) {
	h := newReadLinkHarness(t)
	h.symlink(t, filepath.Join(h.lower, "lnk"), "target")
	h.mem.DeniedPtrs = map[uint64]bool{0x4700: true}

	r := h.call(int64(atFDCWD), 0xc007, "/lnk", 0x4700, 64)
	expectErrno(t, r, syscall.EFAULT)
}

func TestReadLinkAtUnknownDirfdReturnsEBADF(t *testing.T) {
	h := newReadLinkHarness(t)
	h.symlink(t, filepath.Join(h.lower, "lnk"), "target")
	r := h.call(5, 0xc008, "/lnk", 0x4800, 64)
	expectErrno(t, r, syscall.EBADF)
}

func TestReadLinkAtDispatchRouted(t *testing.T) {
	h := newReadLinkHarness(t)
	r := h.call(int64(atFDCWD), 0xc009, "/nope", 0x4900, 64)
	if int64(r.X[0]) >= 0 {
		t.Errorf("readlinkat not routed; X[0]=%#x", r.X[0])
	}
}
