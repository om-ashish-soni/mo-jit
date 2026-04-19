package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func newTruncateHarness(t *testing.T, withUpper bool) (*Dispatcher, *FakePathReader) {
	t.Helper()
	pol := Policy{LowerDir: t.TempDir()}
	if withUpper {
		pol.UpperDir = t.TempDir()
	}
	d := NewDispatcher(pol)
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	return d, paths
}

func TestFTruncateShrinksFile(t *testing.T) {
	d, _ := newTruncateHarness(t, true)
	d.FDs = &FDTable{entries: map[int]int{}}

	path := filepath.Join(d.FS.policy.UpperDir, "f.bin")
	if err := os.WriteFile(path, []byte("abcdefghij"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostFd, err := syscall.Open(path, syscall.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	g := d.FDs.Allocate(hostFd)

	regs := &Regs{NR: SysFTruncate}
	regs.X[0] = uint64(g)
	regs.X[1] = 3
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("ftruncate returned %d, want 0", int64(regs.X[0]))
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "abc" {
		t.Errorf("file after truncate = %q, want abc", content)
	}
}

func TestFTruncateUnknownFdIsEBADF(t *testing.T) {
	d, _ := newTruncateHarness(t, true)
	d.FDs = &FDTable{entries: map[int]int{}}

	regs := &Regs{NR: SysFTruncate}
	regs.X[0] = 999
	regs.X[1] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func TestFTruncateOnReadOnlyFdIsEINVAL(t *testing.T) {
	d, _ := newTruncateHarness(t, true)
	d.FDs = &FDTable{entries: map[int]int{}}

	path := filepath.Join(d.FS.policy.UpperDir, "ro.bin")
	if err := os.WriteFile(path, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostFd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	g := d.FDs.Allocate(hostFd)

	regs := &Regs{NR: SysFTruncate}
	regs.X[0] = uint64(g)
	regs.X[1] = 0
	d.Dispatch(regs)
	// Linux returns EINVAL for ftruncate on an RDONLY fd.
	expectErrno(t, regs, syscall.EINVAL)
}

func TestTruncateOnUpperFile(t *testing.T) {
	d, paths := newTruncateHarness(t, true)
	path := filepath.Join(d.FS.policy.UpperDir, "f.bin")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}

	paths.Entries[0x8000] = "/f.bin"
	regs := &Regs{NR: SysTruncate}
	regs.X[0] = 0x8000
	regs.X[1] = 5
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("truncate returned %d, want 0", int64(regs.X[0]))
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "01234" {
		t.Errorf("file = %q, want 01234", content)
	}
}

func TestTruncateCopiesUpLowerFile(t *testing.T) {
	// Lower has the file; truncate must materialise an upper copy
	// and shrink it there, leaving lower untouched.
	d, paths := newTruncateHarness(t, true)
	lower := filepath.Join(d.FS.policy.LowerDir, "readme")
	if err := os.WriteFile(lower, []byte("LOWER-ORIGINAL"), 0o644); err != nil {
		t.Fatal(err)
	}

	paths.Entries[0x8100] = "/readme"
	regs := &Regs{NR: SysTruncate}
	regs.X[0] = 0x8100
	regs.X[1] = 5
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("truncate returned %d, want 0", int64(regs.X[0]))
	}

	// Lower is untouched.
	orig, err := os.ReadFile(lower)
	if err != nil {
		t.Fatal(err)
	}
	if string(orig) != "LOWER-ORIGINAL" {
		t.Errorf("lower file mutated: %q", orig)
	}
	// Upper has the shrunk copy.
	upper := filepath.Join(d.FS.policy.UpperDir, "readme")
	content, err := os.ReadFile(upper)
	if err != nil {
		t.Fatalf("upper copy missing after copy-up: %v", err)
	}
	if string(content) != "LOWER" {
		t.Errorf("upper copy = %q, want LOWER", content)
	}
}

func TestTruncateMissingFileIsENOENT(t *testing.T) {
	d, paths := newTruncateHarness(t, true)
	paths.Entries[0x8200] = "/nope"
	regs := &Regs{NR: SysTruncate}
	regs.X[0] = 0x8200
	regs.X[1] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOENT)
}

func TestTruncateNoUpperDirIsEROFS(t *testing.T) {
	d, paths := newTruncateHarness(t, false)
	paths.Entries[0x8300] = "/whatever"
	regs := &Regs{NR: SysTruncate}
	regs.X[0] = 0x8300
	regs.X[1] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EROFS)
}

func TestTruncateWhiteoutIsENOENT(t *testing.T) {
	d, paths := newTruncateHarness(t, true)
	// Place a whiteout on upper for a name that lower has.
	lower := filepath.Join(d.FS.policy.LowerDir, "ghost")
	if err := os.WriteFile(lower, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	upperGhost := filepath.Join(d.FS.policy.UpperDir, "ghost")
	if err := writeWhiteout(upperGhost); err != nil {
		t.Fatal(err)
	}

	paths.Entries[0x8400] = "/ghost"
	regs := &Regs{NR: SysTruncate}
	regs.X[0] = 0x8400
	regs.X[1] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOENT)
}
