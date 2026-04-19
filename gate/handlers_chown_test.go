package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// fchown/fchownat test helpers. Host-side uid/gid checking is weak on
// unprivileged CI runners — you can only chown to your own uid/gid
// without EPERM — so we read our own ids and chown to them. The point
// of these tests is the overlay routing + copy-up, not whether the
// kernel permits the ownership change.

func selfIDs(t *testing.T) (uid, gid int) {
	t.Helper()
	return os.Getuid(), os.Getgid()
}

func TestFChownChangesOwnerOnHostFd(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	d.FDs = &FDTable{entries: map[int]int{}}

	path := filepath.Join(d.FS.policy.UpperDir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostFd, err := syscall.Open(path, syscall.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	g := d.FDs.Allocate(hostFd)

	uid, gid := selfIDs(t)
	regs := &Regs{NR: SysFChOwn}
	regs.X[0] = uint64(g)
	regs.X[1] = uint64(uint32(uid))
	regs.X[2] = uint64(uint32(gid))
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("fchown returned %d, want 0", int64(regs.X[0]))
	}
}

func TestFChownUnknownFdIsEBADF(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	d.FDs = &FDTable{entries: map[int]int{}}
	regs := &Regs{NR: SysFChOwn}
	regs.X[0] = 999
	regs.X[1] = 0
	regs.X[2] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func chownAtRegs(paths *FakePathReader, guestPath string, uid, gid int, flags uint32) *Regs {
	paths.Entries[0x9A00] = guestPath
	regs := &Regs{NR: SysFChOwnAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0x9A00
	regs.X[2] = uint64(uint32(uid))
	regs.X[3] = uint64(uint32(gid))
	regs.X[4] = uint64(flags)
	return regs
}

func TestFChownAtUpperFile(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths

	path := filepath.Join(d.FS.policy.UpperDir, "a")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	uid, gid := selfIDs(t)
	regs := chownAtRegs(paths, "/a", uid, gid, 0)
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("fchownat returned %d, want 0", int64(regs.X[0]))
	}
}

func TestFChownAtCopiesUpLowerFile(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths

	lower := filepath.Join(d.FS.policy.LowerDir, "lib.so")
	if err := os.WriteFile(lower, []byte("BINARY"), 0o444); err != nil {
		t.Fatal(err)
	}

	uid, gid := selfIDs(t)
	regs := chownAtRegs(paths, "/lib.so", uid, gid, 0)
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("fchownat returned %d, want 0", int64(regs.X[0]))
	}
	// Upper copy exists.
	upper := filepath.Join(d.FS.policy.UpperDir, "lib.so")
	if _, err := os.Stat(upper); err != nil {
		t.Fatalf("upper copy missing: %v", err)
	}
	// Lower content untouched.
	content, err := os.ReadFile(lower)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "BINARY" {
		t.Errorf("lower content changed: %q", content)
	}
}

func TestFChownAtMissingFileIsENOENT(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths

	regs := chownAtRegs(paths, "/nope", 0, 0, 0)
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOENT)
}

func TestFChownAtWhiteoutIsENOENT(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	lower := filepath.Join(d.FS.policy.LowerDir, "gone")
	if err := os.WriteFile(lower, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeWhiteout(filepath.Join(d.FS.policy.UpperDir, "gone")); err != nil {
		t.Fatal(err)
	}

	regs := chownAtRegs(paths, "/gone", 0, 0, 0)
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOENT)
}

func TestFChownAtNoUpperDirIsEROFS(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths

	regs := chownAtRegs(paths, "/anything", 0, 0, 0)
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EROFS)
}
