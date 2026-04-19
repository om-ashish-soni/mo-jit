package gate

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
)

// parseDirent64 walks the linux_dirent64 buffer the kernel just wrote
// and returns the d_name strings in order. Keeps test assertions
// independent from the specific record layout — the invariant we
// actually care about is "these names are present".
func parseDirent64(buf []byte) []string {
	var names []string
	for len(buf) > 0 {
		if len(buf) < 19 {
			break
		}
		reclen := int(binary.LittleEndian.Uint16(buf[16:18]))
		if reclen == 0 || reclen > len(buf) {
			break
		}
		end := 19
		for end < reclen && buf[end] != 0 {
			end++
		}
		names = append(names, string(buf[19:end]))
		buf = buf[reclen:]
	}
	sort.Strings(names)
	return names
}

// openDirAsGuestFd opens dirPath on the host and registers it in the
// dispatcher's fd table. Returns the guest fd the rest of the test
// can hand to getdents64.
func openDirAsGuestFd(t *testing.T, d *Dispatcher, dirPath string) int {
	t.Helper()
	hostFd, err := syscall.Open(dirPath, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", dirPath, err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	return d.FDs.Allocate(hostFd)
}

func TestGetDents64ListsUpperLayerEntries(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	d.FDs = &FDTable{entries: map[int]int{}}
	d.Mem = &FakeMemWriter{}

	// Seed three files on upper.
	for _, n := range []string{"alpha", "beta", "gamma"} {
		path := filepath.Join(d.FS.policy.UpperDir, n)
		if err := os.WriteFile(path, []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g := openDirAsGuestFd(t, d, d.FS.policy.UpperDir)

	regs := &Regs{NR: SysGetDents64}
	regs.X[0] = uint64(g)
	regs.X[1] = 0xcafe0000
	regs.X[2] = 4096
	d.Dispatch(regs)

	n := int64(regs.X[0])
	if n <= 0 {
		t.Fatalf("getdents64 returned %d, want >0", n)
	}
	raw := d.Mem.(*FakeMemWriter).Read(0xcafe0000, int(n))
	names := parseDirent64(raw)

	want := map[string]bool{".": true, "..": true, "alpha": true, "beta": true, "gamma": true}
	for _, name := range names {
		delete(want, name)
	}
	if len(want) != 0 {
		t.Errorf("missing entries: %v; got %v", keys(want), names)
	}
}

func TestGetDents64EOFReturnsZero(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	d.FDs = &FDTable{entries: map[int]int{}}
	d.Mem = &FakeMemWriter{}

	g := openDirAsGuestFd(t, d, d.FS.policy.UpperDir)

	// First read: drains the dir (it's empty except for . and ..).
	first := &Regs{NR: SysGetDents64}
	first.X[0] = uint64(g)
	first.X[1] = 0xeee0
	first.X[2] = 4096
	d.Dispatch(first)
	if int64(first.X[0]) <= 0 {
		t.Fatalf("first getdents64 returned %d, want >0", int64(first.X[0]))
	}

	// Second read: the kernel cursor is past EOF → 0.
	second := &Regs{NR: SysGetDents64}
	second.X[0] = uint64(g)
	second.X[1] = 0xeee0
	second.X[2] = 4096
	d.Dispatch(second)
	if int64(second.X[0]) != 0 {
		t.Errorf("second getdents64 after EOF = %d, want 0", int64(second.X[0]))
	}
}

func TestGetDents64UnknownFdIsEBADF(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	d.FDs = &FDTable{entries: map[int]int{}}
	d.Mem = &FakeMemWriter{}

	regs := &Regs{NR: SysGetDents64}
	regs.X[0] = 999
	regs.X[1] = 0x1000
	regs.X[2] = 4096
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func TestGetDents64OnNonDirIsENOTDIR(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	d.FDs = &FDTable{entries: map[int]int{}}
	d.Mem = &FakeMemWriter{}

	path := filepath.Join(d.FS.policy.UpperDir, "file")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostFd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	g := d.FDs.Allocate(hostFd)

	regs := &Regs{NR: SysGetDents64}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x2000
	regs.X[2] = 4096
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOTDIR)
}

func TestGetDents64ZeroCountShortCircuits(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	d.FDs = &FDTable{entries: map[int]int{}}
	// MemWriter would fault — we must not reach it.
	d.Mem = &FakeMemWriter{DeniedPtrs: map[uint64]bool{0x3000: true}}
	g := openDirAsGuestFd(t, d, d.FS.policy.LowerDir)

	regs := &Regs{NR: SysGetDents64}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x3000
	regs.X[2] = 0
	d.Dispatch(regs)
	if regs.X[0] != 0 {
		t.Errorf("count=0 returned %d, want 0", regs.X[0])
	}
}

func TestGetDents64WriteFaultReturnsEFAULT(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	d.FDs = &FDTable{entries: map[int]int{}}
	d.Mem = &FakeMemWriter{DeniedPtrs: map[uint64]bool{0x4000: true}}
	g := openDirAsGuestFd(t, d, d.FS.policy.LowerDir)

	regs := &Regs{NR: SysGetDents64}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x4000
	regs.X[2] = 4096
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EFAULT)
}

func keys(m map[string]bool) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}

// openDirViaOpenAt routes through handleOpenAt so the dispatcher
// builds an overlay-merged dirent snapshot for the returned guest fd.
// Used by the merged-readdir tests; the older openDirAsGuestFd path
// bypasses handleOpenAt and therefore doesn't get a snapshot.
func openDirViaOpenAt(t *testing.T, d *Dispatcher, paths *FakePathReader, guestPath string) int {
	t.Helper()
	paths.Entries[0xabcd] = guestPath
	regs := &Regs{NR: SysOpenAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0xabcd
	regs.X[2] = uint64(syscall.O_RDONLY | syscall.O_DIRECTORY)
	regs.X[3] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) < 0 {
		t.Fatalf("openat %q: errno %d", guestPath, -int64(regs.X[0]))
	}
	return int(regs.X[0])
}

func TestGetDents64MergesUpperAndLower(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	d.Mem = &FakeMemWriter{}

	if err := os.WriteFile(filepath.Join(d.FS.policy.UpperDir, "u1"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.FS.policy.LowerDir, "l1"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}

	g := openDirViaOpenAt(t, d, paths, "/")
	regs := &Regs{NR: SysGetDents64}
	regs.X[0] = uint64(g)
	regs.X[1] = 0xd100
	regs.X[2] = 4096
	d.Dispatch(regs)
	n := int64(regs.X[0])
	if n <= 0 {
		t.Fatalf("getdents64 returned %d", n)
	}
	raw := d.Mem.(*FakeMemWriter).Read(0xd100, int(n))
	names := parseDirent64(raw)
	want := map[string]bool{".": true, "..": true, "u1": true, "l1": true}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Errorf("missing merged entries: %v; got %v", keys(want), names)
	}
}

func TestGetDents64UpperShadowsLower(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	d.Mem = &FakeMemWriter{}

	// Same name in both; upper wins — result should show exactly one.
	if err := os.WriteFile(filepath.Join(d.FS.policy.UpperDir, "dup"), []byte("U"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.FS.policy.LowerDir, "dup"), []byte("L"), 0o600); err != nil {
		t.Fatal(err)
	}

	g := openDirViaOpenAt(t, d, paths, "/")
	regs := &Regs{NR: SysGetDents64}
	regs.X[0] = uint64(g)
	regs.X[1] = 0xd200
	regs.X[2] = 4096
	d.Dispatch(regs)

	raw := d.Mem.(*FakeMemWriter).Read(0xd200, int(regs.X[0]))
	names := parseDirent64(raw)
	count := 0
	for _, n := range names {
		if n == "dup" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("shadowed entry appeared %d times, want 1; names=%v", count, names)
	}
}

func TestGetDents64WhiteoutHidesLower(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	d.Mem = &FakeMemWriter{}

	if err := os.WriteFile(filepath.Join(d.FS.policy.LowerDir, "gone"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeWhiteout(filepath.Join(d.FS.policy.UpperDir, "gone")); err != nil {
		t.Fatal(err)
	}
	// Also add a lower file that SHOULD be visible, to confirm the
	// filter is selective rather than "drop everything on lower".
	if err := os.WriteFile(filepath.Join(d.FS.policy.LowerDir, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	g := openDirViaOpenAt(t, d, paths, "/")
	regs := &Regs{NR: SysGetDents64}
	regs.X[0] = uint64(g)
	regs.X[1] = 0xd300
	regs.X[2] = 4096
	d.Dispatch(regs)

	raw := d.Mem.(*FakeMemWriter).Read(0xd300, int(regs.X[0]))
	names := parseDirent64(raw)
	for _, n := range names {
		if n == "gone" {
			t.Errorf("whited-out entry visible: names=%v", names)
		}
	}
	keep := false
	for _, n := range names {
		if n == "keep" {
			keep = true
		}
	}
	if !keep {
		t.Errorf("lower-only entry missing: names=%v", names)
	}
}

func TestGetDents64OpaqueDirHidesLower(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	d.Mem = &FakeMemWriter{}

	if err := os.WriteFile(filepath.Join(d.FS.policy.LowerDir, "hidden"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Stamp the upper root as opaque.
	if err := syscall.Setxattr(d.FS.policy.UpperDir, opaqueXattr, []byte{'y'}, 0); err != nil {
		t.Skipf("Setxattr opaque: %v (fs probably lacks user.* xattrs)", err)
	}

	g := openDirViaOpenAt(t, d, paths, "/")
	regs := &Regs{NR: SysGetDents64}
	regs.X[0] = uint64(g)
	regs.X[1] = 0xd400
	regs.X[2] = 4096
	d.Dispatch(regs)

	raw := d.Mem.(*FakeMemWriter).Read(0xd400, int(regs.X[0]))
	names := parseDirent64(raw)
	for _, n := range names {
		if n == "hidden" {
			t.Errorf("opaque dir didn't hide lower entry: names=%v", names)
		}
	}
}

func TestGetDents64MultiChunkDrain(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	d.Mem = &FakeMemWriter{}

	// Seed enough entries that one 128-byte chunk can't drain them all.
	for i := 0; i < 20; i++ {
		p := filepath.Join(d.FS.policy.UpperDir, string([]byte{'a' + byte(i)}))
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	g := openDirViaOpenAt(t, d, paths, "/")
	var got []string
	offset := uint64(0xd500)
	for {
		regs := &Regs{NR: SysGetDents64}
		regs.X[0] = uint64(g)
		regs.X[1] = offset
		regs.X[2] = 128
		d.Dispatch(regs)
		n := int64(regs.X[0])
		if n == 0 {
			break
		}
		if n < 0 {
			t.Fatalf("chunked getdents64 errno %d", -n)
		}
		raw := d.Mem.(*FakeMemWriter).Read(offset, int(n))
		got = append(got, parseDirent64(raw)...)
		offset += uint64(n)
	}
	// parseDirent64 already sorts alphabetically.
	wantNames := map[string]bool{".": true, "..": true}
	for i := 0; i < 20; i++ {
		wantNames[string([]byte{'a' + byte(i)})] = true
	}
	for _, n := range got {
		delete(wantNames, n)
	}
	if len(wantNames) != 0 {
		t.Errorf("multi-chunk drain missed %v; got %v", keys(wantNames), got)
	}
}

func TestGetDents64TooSmallBufferIsEINVAL(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	d.Mem = &FakeMemWriter{}

	if err := os.WriteFile(filepath.Join(d.FS.policy.UpperDir, "something"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	g := openDirViaOpenAt(t, d, paths, "/")
	regs := &Regs{NR: SysGetDents64}
	regs.X[0] = uint64(g)
	regs.X[1] = 0xd600
	regs.X[2] = 4 // smaller than even one header
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EINVAL)
}

func TestGetDents64CloseReleasesSnapshot(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	d.Mem = &FakeMemWriter{}

	g := openDirViaOpenAt(t, d, paths, "/")
	// Close releases both the host fd and the snapshot.
	closeRegs := &Regs{NR: SysClose}
	closeRegs.X[0] = uint64(g)
	d.Dispatch(closeRegs)
	if int64(closeRegs.X[0]) != 0 {
		t.Fatalf("close returned %d", int64(closeRegs.X[0]))
	}
	d.dirSnapshotsMu.Lock()
	_, still := d.dirSnapshots[g]
	d.dirSnapshotsMu.Unlock()
	if still {
		t.Errorf("snapshot persisted after close of fd %d", g)
	}
}
