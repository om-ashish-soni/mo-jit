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
