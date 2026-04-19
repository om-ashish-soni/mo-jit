package gate

import (
	"path/filepath"
	"syscall"
	"testing"
)

type getcwdHarness struct {
	d     *Dispatcher
	lower string
	mem   *FakeMemWriter
}

func newGetCwdHarness(t *testing.T) *getcwdHarness {
	t.Helper()
	lower := filepath.Join(t.TempDir(), "lower")
	mustMkdirAll(t, lower)
	d := NewDispatcher(Policy{LowerDir: lower})
	mem := &FakeMemWriter{}
	d.Mem = mem
	return &getcwdHarness{d: d, lower: lower, mem: mem}
}

func (h *getcwdHarness) call(buf, size uint64) *Regs {
	r := &Regs{NR: SysGetCwd}
	r.X[0] = buf
	r.X[1] = size
	h.d.Dispatch(r)
	return r
}

func TestGetCwdDefaultRoot(t *testing.T) {
	h := newGetCwdHarness(t)

	r := h.call(0x3000, 128)
	if int64(r.X[0]) != 2 {
		t.Errorf("getcwd(\"/\"): X[0]=%d, want 2 (len+NUL)", r.X[0])
	}
	got := h.mem.Read(0x3000, 2)
	if string(got) != "/\x00" {
		t.Errorf("buffer = %q, want %q", got, "/\x00")
	}
}

func TestGetCwdAfterChdir(t *testing.T) {
	h := newGetCwdHarness(t)
	if err := h.d.FS.SetGuestCwd("/home/dev"); err != nil {
		t.Fatal(err)
	}

	r := h.call(0x3100, 128)
	want := "/home/dev\x00"
	if int64(r.X[0]) != int64(len(want)) {
		t.Errorf("getcwd: X[0]=%d, want %d", r.X[0], len(want))
	}
	got := h.mem.Read(0x3100, len(want))
	if string(got) != want {
		t.Errorf("buffer = %q, want %q", got, want)
	}
}

func TestGetCwdSizeTooSmallReturnsERANGE(t *testing.T) {
	h := newGetCwdHarness(t)
	if err := h.d.FS.SetGuestCwd("/home/dev"); err != nil {
		t.Fatal(err)
	}

	// "/home/dev\x00" = 10 bytes; size=5 is too small.
	r := h.call(0x3200, 5)
	expectErrno(t, r, syscall.ERANGE)
	// Must not write any bytes on failure.
	if len(h.mem.Bytes) != 0 {
		t.Errorf("ERANGE must not produce partial write; got %d bytes", len(h.mem.Bytes))
	}
}

func TestGetCwdNullBufReturnsEFAULT(t *testing.T) {
	h := newGetCwdHarness(t)
	r := h.call(0, 128)
	expectErrno(t, r, syscall.EFAULT)
}

func TestGetCwdDeniedBufReturnsEFAULT(t *testing.T) {
	h := newGetCwdHarness(t)
	h.mem.DeniedPtrs = map[uint64]bool{0x3300: true}

	r := h.call(0x3300, 128)
	expectErrno(t, r, syscall.EFAULT)
}

func TestGetCwdExactFitBufSucceeds(t *testing.T) {
	// Edge: size == exact length including NUL must succeed.
	h := newGetCwdHarness(t)
	if err := h.d.FS.SetGuestCwd("/a"); err != nil {
		t.Fatal(err)
	}
	want := "/a\x00"
	r := h.call(0x3400, uint64(len(want)))
	if int64(r.X[0]) != int64(len(want)) {
		t.Errorf("exact-fit: X[0]=%d, want %d", r.X[0], len(want))
	}
	got := h.mem.Read(0x3400, len(want))
	if string(got) != want {
		t.Errorf("buffer = %q, want %q", got, want)
	}
}

func TestGetCwdDispatchRouted(t *testing.T) {
	h := newGetCwdHarness(t)
	r := h.call(0x3500, 128)
	// Default / root cwd, size 128 — must succeed, so X[0] >= 0. If
	// getcwd were not routed we'd hit VerdictPassthrough with X[0]
	// untouched (= 0x3500, a positive number). Distinguish by
	// checking the first two bytes of the buffer were written.
	if r.X[0] == 0 {
		t.Errorf("getcwd returned 0 bytes; not routed?")
	}
	if h.mem.Bytes == nil || len(h.mem.Bytes) == 0 {
		t.Errorf("getcwd produced no buffer write; not routed?")
	}
}
