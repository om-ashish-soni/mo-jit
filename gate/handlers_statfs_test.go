package gate

import (
	"encoding/binary"
	"path/filepath"
	"syscall"
	"testing"
)

// decodeStatfsBlob pulls the fields we assert against out of the
// 120-byte aarch64 struct statfs64 the handler writes.
type statfsBlob struct {
	Type    uint64
	Bsize   uint64
	Blocks  uint64
	Bfree   uint64
	Bavail  uint64
	Files   uint64
	Ffree   uint64
	Namelen uint64
	Frsize  uint64
	Flags   uint64
}

func decodeStatfsBlob(t *testing.T, b []byte) statfsBlob {
	t.Helper()
	if len(b) != aarch64StatfsSize {
		t.Fatalf("statfs blob size = %d, want %d", len(b), aarch64StatfsSize)
	}
	le := binary.LittleEndian
	return statfsBlob{
		Type:    le.Uint64(b[0:]),
		Bsize:   le.Uint64(b[8:]),
		Blocks:  le.Uint64(b[16:]),
		Bfree:   le.Uint64(b[24:]),
		Bavail:  le.Uint64(b[32:]),
		Files:   le.Uint64(b[40:]),
		Ffree:   le.Uint64(b[48:]),
		Namelen: le.Uint64(b[64:]),
		Frsize:  le.Uint64(b[72:]),
		Flags:   le.Uint64(b[80:]),
	}
}

// newStatfsHarness wires a dispatcher with lower+upper against the
// host's temp dir, so syscall.Statfs/Fstatfs return real host numbers.
type statfsHarness struct {
	d     *Dispatcher
	lower string
	upper string
	paths *FakePathReader
	mem   *FakeMemWriter
}

func newStatfsHarness(t *testing.T) *statfsHarness {
	t.Helper()
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	upper := filepath.Join(tmp, "upper")
	mustMkdirAll(t, lower)
	mustMkdirAll(t, upper)
	d := NewDispatcher(Policy{LowerDir: lower, UpperDir: upper})
	d.FDs = &FDTable{entries: map[int]int{}}
	d.Paths = &FakePathReader{Entries: map[uint64]string{}}
	d.Mem = &FakeMemWriter{}
	return &statfsHarness{
		d:     d,
		lower: lower,
		upper: upper,
		paths: d.Paths.(*FakePathReader),
		mem:   d.Mem.(*FakeMemWriter),
	}
}

func (h *statfsHarness) statfs(pathPtr uint64, path string, bufPtr uint64) *Regs {
	h.paths.Entries[pathPtr] = path
	r := &Regs{NR: SysStatFs}
	r.X[0] = pathPtr
	r.X[1] = bufPtr
	h.d.Dispatch(r)
	return r
}

func (h *statfsHarness) fstatfs(guestFd int, bufPtr uint64) *Regs {
	r := &Regs{NR: SysFStatFs}
	r.X[0] = uint64(guestFd)
	r.X[1] = bufPtr
	h.d.Dispatch(r)
	return r
}

func TestStatFsPathFormReturnsNonZeroBlocks(t *testing.T) {
	h := newStatfsHarness(t)
	r := h.statfs(0x3001, "/", 0x7000)
	if int64(r.X[0]) != 0 {
		t.Fatalf("statfs: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	raw := h.mem.Read(0x7000, aarch64StatfsSize)
	st := decodeStatfsBlob(t, raw)
	if st.Blocks == 0 {
		t.Errorf("f_blocks = 0, want >0 (real filesystem)")
	}
	if st.Bsize == 0 {
		t.Errorf("f_bsize = 0, want >0")
	}
	if st.Namelen == 0 {
		t.Errorf("f_namelen = 0, want >0 (typically 255)")
	}
}

func TestStatFsResolvesLowerLayerPath(t *testing.T) {
	h := newStatfsHarness(t)
	// Seed a subdir on the lower only. Resolve must fall through to
	// lower and statfs must succeed — a naive "apply to UpperDir" impl
	// would see the subdir as missing and ENOENT.
	sub := filepath.Join(h.lower, "only-lower")
	mustMkdirAll(t, sub)

	r := h.statfs(0x3010, "/only-lower", 0x7100)
	if int64(r.X[0]) != 0 {
		t.Fatalf("statfs only-lower: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
}

func TestStatFsMissingPathIsENOENT(t *testing.T) {
	h := newStatfsHarness(t)
	r := h.statfs(0x3020, "/nope", 0x7200)
	got := int64(r.X[0])
	if got != -int64(syscall.ENOENT) {
		t.Errorf("statfs missing: X[0]=%d, want -ENOENT(%d)", got, -int64(syscall.ENOENT))
	}
}

func TestStatFsNullBufferIsEFAULT(t *testing.T) {
	h := newStatfsHarness(t)
	r := h.statfs(0x3030, "/", 0)
	if int64(r.X[0]) != -int64(syscall.EFAULT) {
		t.Errorf("statfs NULL buf: X[0]=%d, want -EFAULT", int64(r.X[0]))
	}
}

func TestFStatFsReturnsRealNumbers(t *testing.T) {
	h := newStatfsHarness(t)
	// Open the upper dir on the host; register as a guest fd.
	hostFd, err := syscall.Open(h.upper, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	g := h.d.FDs.Allocate(hostFd)

	r := h.fstatfs(g, 0x7300)
	if int64(r.X[0]) != 0 {
		t.Fatalf("fstatfs: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	st := decodeStatfsBlob(t, h.mem.Read(0x7300, aarch64StatfsSize))
	if st.Blocks == 0 || st.Bsize == 0 {
		t.Errorf("fstatfs returned zeroed fields: %+v", st)
	}
}

func TestFStatFsBadFdIsEBADF(t *testing.T) {
	h := newStatfsHarness(t)
	r := h.fstatfs(99, 0x7400)
	if int64(r.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("fstatfs bad fd: X[0]=%d, want -EBADF", int64(r.X[0]))
	}
}

func TestFStatFsNullBufferIsEFAULT(t *testing.T) {
	h := newStatfsHarness(t)
	hostFd, err := syscall.Open(h.upper, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	g := h.d.FDs.Allocate(hostFd)

	r := h.fstatfs(g, 0)
	if int64(r.X[0]) != -int64(syscall.EFAULT) {
		t.Errorf("fstatfs NULL buf: X[0]=%d, want -EFAULT", int64(r.X[0]))
	}
}

// Cross-check that the two forms agree when pointed at the same
// directory via upper. Not every field is comparable (Bavail can
// drift between the two calls under heavy host IO), so we only
// compare stable, per-filesystem quantities.
func TestStatFsAndFStatFsAgreeOnSameDir(t *testing.T) {
	h := newStatfsHarness(t)

	r := h.statfs(0x3050, "/", 0x7500)
	if int64(r.X[0]) != 0 {
		t.Fatalf("statfs: %d", int64(r.X[0]))
	}
	pathBlob := decodeStatfsBlob(t, h.mem.Read(0x7500, aarch64StatfsSize))

	hostFd, err := syscall.Open(h.upper, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	g := h.d.FDs.Allocate(hostFd)
	r2 := h.fstatfs(g, 0x7600)
	if int64(r2.X[0]) != 0 {
		t.Fatalf("fstatfs: %d", int64(r2.X[0]))
	}
	fdBlob := decodeStatfsBlob(t, h.mem.Read(0x7600, aarch64StatfsSize))

	if pathBlob.Type != fdBlob.Type {
		t.Errorf("f_type mismatch: path=%#x fd=%#x", pathBlob.Type, fdBlob.Type)
	}
	if pathBlob.Bsize != fdBlob.Bsize {
		t.Errorf("f_bsize mismatch: path=%d fd=%d", pathBlob.Bsize, fdBlob.Bsize)
	}
	if pathBlob.Namelen != fdBlob.Namelen {
		t.Errorf("f_namelen mismatch: path=%d fd=%d", pathBlob.Namelen, fdBlob.Namelen)
	}
}
