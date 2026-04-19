package gate

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// readStatBlob decodes the fields the handler writes into the guest
// buffer. Uses the exported statOff* offsets so test + handler share
// the same source of truth.
type statBlob struct {
	Dev     uint64
	Ino     uint64
	Mode    uint32
	Nlink   uint32
	Uid     uint32
	Gid     uint32
	Rdev    uint64
	Size    uint64
	Blksize uint32
	Blocks  uint64
}

func decodeStatBlob(t *testing.T, b []byte) statBlob {
	t.Helper()
	if len(b) != aarch64StatSize {
		t.Fatalf("stat blob size = %d, want %d", len(b), aarch64StatSize)
	}
	le := binary.LittleEndian
	return statBlob{
		Dev:     le.Uint64(b[statOffDev:]),
		Ino:     le.Uint64(b[statOffIno:]),
		Mode:    le.Uint32(b[statOffMode:]),
		Nlink:   le.Uint32(b[statOffNlink:]),
		Uid:     le.Uint32(b[statOffUid:]),
		Gid:     le.Uint32(b[statOffGid:]),
		Rdev:    le.Uint64(b[statOffRdev:]),
		Size:    le.Uint64(b[statOffSize:]),
		Blksize: le.Uint32(b[statOffBlksz:]),
		Blocks:  le.Uint64(b[statOffBlocks:]),
	}
}

// readBlobFromMem extracts aarch64StatSize consecutive bytes from a
// FakeMemWriter at ptr. The handler writes them as one slice so we
// pull them out the same way.
func readBlobFromMem(t *testing.T, w *FakeMemWriter, ptr uint64) []byte {
	t.Helper()
	out := make([]byte, aarch64StatSize)
	for i := 0; i < aarch64StatSize; i++ {
		if v, ok := w.Bytes[ptr+uint64(i)]; ok {
			out[i] = v
		}
	}
	return out
}

type statHarness struct {
	d     *Dispatcher
	lower string
	upper string
	paths *FakePathReader
	mem   *FakeMemWriter
}

func newStatHarness(t *testing.T, withUpper bool) *statHarness {
	t.Helper()
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	mustMkdirAll(t, lower)
	pol := Policy{LowerDir: lower}
	h := &statHarness{lower: lower}
	if withUpper {
		upper := filepath.Join(tmp, "upper")
		mustMkdirAll(t, upper)
		pol.UpperDir = upper
		h.upper = upper
	}
	d := NewDispatcher(pol)
	h.paths = &FakePathReader{Entries: map[uint64]string{}}
	h.mem = &FakeMemWriter{}
	d.Paths = h.paths
	d.Mem = h.mem
	h.d = d
	return h
}

func (h *statHarness) stat(pathPtr uint64, path string, dirfd int64, bufPtr uint64, flags int) *Regs {
	h.paths.Entries[pathPtr] = path
	r := &Regs{NR: SysNewFStatAt}
	r.X[0] = uint64(dirfd)
	r.X[1] = pathPtr
	r.X[2] = bufPtr
	r.X[3] = uint64(flags)
	h.d.Dispatch(r)
	return r
}

func TestNewFStatAtRegularFileReturnsSize(t *testing.T) {
	h := newStatHarness(t, false)
	payload := []byte("hello world!")
	if err := os.WriteFile(filepath.Join(h.lower, "greet"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	r := h.stat(0x6001, "/greet", int64(atFDCWD), 0x7000, 0)
	if int64(r.X[0]) != 0 {
		t.Fatalf("newfstatat: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	st := decodeStatBlob(t, readBlobFromMem(t, h.mem, 0x7000))
	if st.Size != uint64(len(payload)) {
		t.Errorf("st_size = %d, want %d", st.Size, len(payload))
	}
	// Regular file bit + mode 0644.
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		t.Errorf("st_mode type bits = %#o, want S_IFREG", st.Mode&syscall.S_IFMT)
	}
	if st.Mode&0o777 != 0o644 {
		t.Errorf("st_mode perms = %#o, want 0o644", st.Mode&0o777)
	}
}

func TestNewFStatAtDirectoryReportsDirType(t *testing.T) {
	h := newStatHarness(t, false)
	mustMkdirAll(t, filepath.Join(h.lower, "sub/dir"))

	r := h.stat(0x6002, "/sub/dir", int64(atFDCWD), 0x7100, 0)
	if int64(r.X[0]) != 0 {
		t.Fatalf("stat dir: X[0]=%d", int64(r.X[0]))
	}
	st := decodeStatBlob(t, readBlobFromMem(t, h.mem, 0x7100))
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		t.Errorf("dir type bits = %#o, want S_IFDIR", st.Mode&syscall.S_IFMT)
	}
}

func TestNewFStatAtMissingReturnsENOENT(t *testing.T) {
	h := newStatHarness(t, false)
	r := h.stat(0x6003, "/nope", int64(atFDCWD), 0x7200, 0)
	expectErrno(t, r, syscall.ENOENT)
}

func TestNewFStatAtSymlinkFollowVsNoFollow(t *testing.T) {
	h := newStatHarness(t, false)
	// Target file that is clearly a regular file.
	target := filepath.Join(h.lower, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Link pointing at an absolute host-space target so os.Stat can
	// follow it — we're exercising the follow/no-follow flag, not
	// overlay resolution.
	if err := os.Symlink(target, filepath.Join(h.lower, "link")); err != nil {
		t.Fatal(err)
	}

	// Default: follow the link → report regular file.
	r := h.stat(0x6004, "/link", int64(atFDCWD), 0x7300, 0)
	if int64(r.X[0]) != 0 {
		t.Fatalf("follow stat: X[0]=%d", int64(r.X[0]))
	}
	followed := decodeStatBlob(t, readBlobFromMem(t, h.mem, 0x7300))
	if followed.Mode&syscall.S_IFMT != syscall.S_IFREG {
		t.Errorf("followed type = %#o, want S_IFREG", followed.Mode&syscall.S_IFMT)
	}

	// AT_SYMLINK_NOFOLLOW: report the link itself.
	r2 := h.stat(0x6005, "/link", int64(atFDCWD), 0x7400, atSymlinkNoFollow)
	if int64(r2.X[0]) != 0 {
		t.Fatalf("lstat: X[0]=%d", int64(r2.X[0]))
	}
	lnk := decodeStatBlob(t, readBlobFromMem(t, h.mem, 0x7400))
	if lnk.Mode&syscall.S_IFMT != syscall.S_IFLNK {
		t.Errorf("nofollow type = %#o, want S_IFLNK", lnk.Mode&syscall.S_IFMT)
	}
}

func TestNewFStatAtWhiteoutReturnsENOENT(t *testing.T) {
	h := newStatHarness(t, true)
	mustTouch(t, filepath.Join(h.lower, "secret"))
	if ok := mustWhiteout(t, filepath.Join(h.upper, "secret")); !ok {
		return
	}
	r := h.stat(0x6006, "/secret", int64(atFDCWD), 0x7500, 0)
	expectErrno(t, r, syscall.ENOENT)
}

func TestNewFStatAtDirRelativeWithRealDirfdReturnsENOSYS(t *testing.T) {
	h := newStatHarness(t, false)
	r := h.stat(0x6007, "relative", 0, 0x7600, 0)
	expectErrno(t, r, syscall.ENOSYS)
}

func TestNewFStatAtEmptyPathWithoutAtEmptyPathIsENOENT(t *testing.T) {
	h := newStatHarness(t, false)
	// Without AT_EMPTY_PATH, empty pathname must be rejected even
	// though our dirfd is AT_FDCWD.
	r := h.stat(0x6008, "", int64(atFDCWD), 0x7700, 0)
	expectErrno(t, r, syscall.ENOENT)
}

func TestNewFStatAtEmptyPathStatsGuestFd(t *testing.T) {
	// With AT_EMPTY_PATH, the handler treats dirfd as a guest fd and
	// stats the underlying file — the classic glibc fstat path.
	h := newStatHarness(t, false)
	file := filepath.Join(h.lower, "sized")
	if err := os.WriteFile(file, []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostFd, err := syscall.Open(file, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	guestFd := h.d.FDs.Allocate(hostFd)

	r := h.stat(0x6009, "", int64(guestFd), 0x7800, atEmptyPath)
	if int64(r.X[0]) != 0 {
		t.Fatalf("empty-path fstat: X[0]=%d", int64(r.X[0]))
	}
	st := decodeStatBlob(t, readBlobFromMem(t, h.mem, 0x7800))
	if st.Size != 6 {
		t.Errorf("empty-path fstat size = %d, want 6", st.Size)
	}
}

func TestNewFStatAtBufFaultReturnsEFAULT(t *testing.T) {
	h := newStatHarness(t, false)
	mustTouch(t, filepath.Join(h.lower, "f"))

	// Deny the destination buffer so MemWriter.WriteBytes faults.
	h.mem.DeniedPtrs = map[uint64]bool{0x7900: true}
	r := h.stat(0x600a, "/f", int64(atFDCWD), 0x7900, 0)
	expectErrno(t, r, syscall.EFAULT)
}

func TestNewFStatAtNullBufReturnsEFAULT(t *testing.T) {
	h := newStatHarness(t, false)
	mustTouch(t, filepath.Join(h.lower, "f2"))
	r := h.stat(0x600b, "/f2", int64(atFDCWD), 0, 0)
	expectErrno(t, r, syscall.EFAULT)
}

func TestFStatOnGuestFdReturnsSize(t *testing.T) {
	h := newStatHarness(t, false)
	file := filepath.Join(h.lower, "fstat.txt")
	if err := os.WriteFile(file, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostFd, err := syscall.Open(file, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	guestFd := h.d.FDs.Allocate(hostFd)

	r := &Regs{NR: SysFStat}
	r.X[0] = uint64(guestFd)
	r.X[1] = 0x7a00
	h.d.Dispatch(r)
	if int64(r.X[0]) != 0 {
		t.Fatalf("fstat: X[0]=%d", int64(r.X[0]))
	}
	st := decodeStatBlob(t, readBlobFromMem(t, h.mem, 0x7a00))
	if st.Size != 5 {
		t.Errorf("fstat size = %d, want 5", st.Size)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		t.Errorf("fstat mode = %#o, want S_IFREG", st.Mode&syscall.S_IFMT)
	}
}

func TestFStatUnknownFdReturnsEBADF(t *testing.T) {
	h := newStatHarness(t, false)
	r := &Regs{NR: SysFStat}
	r.X[0] = 12345
	r.X[1] = 0x7b00
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EBADF)
}

func TestFStatNullBufReturnsEFAULT(t *testing.T) {
	h := newStatHarness(t, false)
	hostFd, err := syscall.Open(h.lower, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	guestFd := h.d.FDs.Allocate(hostFd)

	r := &Regs{NR: SysFStat}
	r.X[0] = uint64(guestFd)
	r.X[1] = 0
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EFAULT)
}

// TestStatBlobOffsetsMatchAarch64ABI cross-checks the offsets in
// stat.go against a hand-computed reference, so a future drive-by
// refactor of packStatAarch64 can't silently shift a field.
func TestStatBlobOffsetsMatchAarch64ABI(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"dev", statOffDev, 0},
		{"ino", statOffIno, 8},
		{"mode", statOffMode, 16},
		{"nlink", statOffNlink, 20},
		{"uid", statOffUid, 24},
		{"gid", statOffGid, 28},
		{"rdev", statOffRdev, 32},
		{"size", statOffSize, 48},
		{"blksize", statOffBlksz, 56},
		{"blocks", statOffBlocks, 64},
		{"atim", statOffAtim, 72},
		{"mtim", statOffMtim, 88},
		{"ctim", statOffCtim, 104},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("offset %s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if aarch64StatSize != 128 {
		t.Errorf("aarch64StatSize = %d, want 128", aarch64StatSize)
	}
}
