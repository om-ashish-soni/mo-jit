package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFChmodChangesModeOnHostFd(t *testing.T) {
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

	regs := &Regs{NR: SysFChMod}
	regs.X[0] = uint64(g)
	regs.X[1] = 0o644
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("fchmod returned %d, want 0", int64(regs.X[0]))
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 644", st.Mode().Perm())
	}
}

func TestFChmodUnknownFdIsEBADF(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	d.FDs = &FDTable{entries: map[int]int{}}
	regs := &Regs{NR: SysFChMod}
	regs.X[0] = 999
	regs.X[1] = 0o644
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func chmodAtRegs(paths *FakePathReader, guestPath string, mode uint32) *Regs {
	paths.Entries[0x9100] = guestPath
	regs := &Regs{NR: SysFChModAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0x9100
	regs.X[2] = uint64(mode)
	regs.X[3] = 0
	return regs
}

func TestFChmodAtUpperFile(t *testing.T) {
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

	d.Dispatch(chmodAtRegs(paths, "/a", 0o755))
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Errorf("mode = %o, want 755", st.Mode().Perm())
	}
}

func TestFChmodAtCopiesUpLowerFile(t *testing.T) {
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

	regs := chmodAtRegs(paths, "/lib.so", 0o755)
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("fchmodat returned %d, want 0", int64(regs.X[0]))
	}

	// Lower unchanged.
	st, err := os.Stat(lower)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o444 {
		t.Errorf("lower mode changed: %o, want 444", st.Mode().Perm())
	}
	// Upper has the copy with the new mode.
	upper := filepath.Join(d.FS.policy.UpperDir, "lib.so")
	st2, err := os.Stat(upper)
	if err != nil {
		t.Fatalf("upper copy missing: %v", err)
	}
	if st2.Mode().Perm() != 0o755 {
		t.Errorf("upper mode = %o, want 755", st2.Mode().Perm())
	}
	content, err := os.ReadFile(upper)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "BINARY" {
		t.Errorf("upper content = %q, want BINARY", content)
	}
}

func TestFChmodAtMissingFileIsENOENT(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths

	d.Dispatch(chmodAtRegs(paths, "/nope", 0o644))
	// Expect ENOENT in X[0].
	regs := chmodAtRegs(paths, "/nope", 0o644)
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOENT)
}

func TestFChmodAtWhiteoutIsENOENT(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	// Lower has the file, but upper whites it out.
	lower := filepath.Join(d.FS.policy.LowerDir, "gone")
	if err := os.WriteFile(lower, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeWhiteout(filepath.Join(d.FS.policy.UpperDir, "gone")); err != nil {
		t.Fatal(err)
	}

	regs := chmodAtRegs(paths, "/gone", 0o755)
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOENT)
}

func TestFChmodAtNoUpperDirIsEROFS(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths

	regs := chmodAtRegs(paths, "/anything", 0o644)
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EROFS)
}
