package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// newXattrHarness wires up a dispatcher with both overlay layers + fake
// path/mem readers/writer. Tests that need an fd preallocate through
// d.FDs directly; path tests route through the fake PathReader.
func newXattrHarness(t *testing.T, withUpper bool) (*Dispatcher, *FakePathReader, *FakeMemReader, *FakeMemWriter) {
	t.Helper()
	pol := Policy{LowerDir: t.TempDir()}
	if withUpper {
		pol.UpperDir = t.TempDir()
	}
	d := NewDispatcher(pol)
	paths := &FakePathReader{Entries: map[uint64]string{}}
	mr := &FakeMemReader{}
	mw := &FakeMemWriter{}
	d.Paths = paths
	d.MemR = mr
	d.Mem = mw
	d.FDs = &FDTable{entries: map[int]int{}}
	return d, paths, mr, mw
}

// xattrSupported probes whether path can hold a user.* xattr. tmpfs
// under /tmp does; some CI exotica (overlayfs-on-rootfs, btrfs with
// user_xattr=off) doesn't. Returning false lets the test skip cleanly.
func xattrSupported(path string) bool {
	if err := syscall.Setxattr(path, "user.mojit.probe", []byte("1"), 0); err != nil {
		return false
	}
	_ = syscall.Removexattr(path, "user.mojit.probe")
	return true
}

func TestGetXattrOnUpperFile(t *testing.T) {
	d, paths, _, mw := newXattrHarness(t, true)
	path := filepath.Join(d.FS.policy.UpperDir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(path) {
		t.Skip("fs lacks user.* xattrs")
	}
	if err := syscall.Setxattr(path, "user.test", []byte("hello"), 0); err != nil {
		t.Fatal(err)
	}

	paths.Entries[0xA100] = "/f"
	paths.Entries[0xA101] = "user.test"
	regs := &Regs{NR: SysGetXattr}
	regs.X[0] = 0xA100
	regs.X[1] = 0xA101
	regs.X[2] = 0xA200
	regs.X[3] = 64
	d.Dispatch(regs)
	n := int64(regs.X[0])
	if n != 5 {
		t.Fatalf("getxattr returned %d, want 5", n)
	}
	if got := string(mw.Read(0xA200, int(n))); got != "hello" {
		t.Errorf("value = %q, want hello", got)
	}
}

func TestGetXattrSizeZeroReturnsLength(t *testing.T) {
	d, paths, _, _ := newXattrHarness(t, true)
	path := filepath.Join(d.FS.policy.UpperDir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(path) {
		t.Skip("fs lacks user.* xattrs")
	}
	if err := syscall.Setxattr(path, "user.len", []byte("1234567"), 0); err != nil {
		t.Fatal(err)
	}

	paths.Entries[0xA110] = "/f"
	paths.Entries[0xA111] = "user.len"
	regs := &Regs{NR: SysGetXattr}
	regs.X[0] = 0xA110
	regs.X[1] = 0xA111
	regs.X[2] = 0 // no buffer
	regs.X[3] = 0 // probe size
	d.Dispatch(regs)
	if int64(regs.X[0]) != 7 {
		t.Errorf("size probe returned %d, want 7", int64(regs.X[0]))
	}
}

func TestGetXattrMissingAttrIsENODATA(t *testing.T) {
	d, paths, _, _ := newXattrHarness(t, true)
	path := filepath.Join(d.FS.policy.UpperDir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(path) {
		t.Skip("fs lacks user.* xattrs")
	}

	paths.Entries[0xA120] = "/f"
	paths.Entries[0xA121] = "user.nope"
	regs := &Regs{NR: SysGetXattr}
	regs.X[0] = 0xA120
	regs.X[1] = 0xA121
	regs.X[2] = 0xA200
	regs.X[3] = 64
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENODATA)
}

func TestSetXattrOnUpperFile(t *testing.T) {
	d, paths, mr, _ := newXattrHarness(t, true)
	path := filepath.Join(d.FS.policy.UpperDir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(path) {
		t.Skip("fs lacks user.* xattrs")
	}

	paths.Entries[0xA130] = "/f"
	paths.Entries[0xA131] = "user.set"
	mr.Stage(0xA300, []byte("world"))

	regs := &Regs{NR: SysSetXattr}
	regs.X[0] = 0xA130
	regs.X[1] = 0xA131
	regs.X[2] = 0xA300
	regs.X[3] = 5
	regs.X[4] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("setxattr returned %d", int64(regs.X[0]))
	}
	got := make([]byte, 16)
	n, err := syscall.Getxattr(path, "user.set", got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != "world" {
		t.Errorf("read back %q, want world", got[:n])
	}
}

func TestSetXattrCopiesUpLowerFile(t *testing.T) {
	d, paths, mr, _ := newXattrHarness(t, true)
	// Probe xattr support on a writable sibling: the real target is
	// 0o444 (simulating a lower-layer read-only package file) which
	// would fail Setxattr with EACCES regardless of fs capability.
	if !xattrSupported(d.FS.policy.LowerDir) {
		t.Skip("fs lacks user.* xattrs")
	}
	lower := filepath.Join(d.FS.policy.LowerDir, "l.so")
	// 0o644 (not 0o444): Setxattr needs write perm on the file, and
	// the kernel overlayfs uses CAP_FOWNER to bypass that on real
	// overlays — we don't, so the test needs owner-writable bits.
	if err := os.WriteFile(lower, []byte("BINARY"), 0o644); err != nil {
		t.Fatal(err)
	}

	paths.Entries[0xA140] = "/l.so"
	paths.Entries[0xA141] = "user.cap"
	mr.Stage(0xA400, []byte("CAP"))

	regs := &Regs{NR: SysSetXattr}
	regs.X[0] = 0xA140
	regs.X[1] = 0xA141
	regs.X[2] = 0xA400
	regs.X[3] = 3
	regs.X[4] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("setxattr returned %d", int64(regs.X[0]))
	}

	upper := filepath.Join(d.FS.policy.UpperDir, "l.so")
	buf := make([]byte, 16)
	n, err := syscall.Getxattr(upper, "user.cap", buf)
	if err != nil {
		t.Fatalf("xattr missing on upper copy: %v", err)
	}
	if string(buf[:n]) != "CAP" {
		t.Errorf("upper xattr = %q, want CAP", buf[:n])
	}
	// Lower must not have picked up the new xattr.
	if _, err := syscall.Getxattr(lower, "user.cap", buf); err == nil {
		t.Errorf("setxattr leaked into lower layer")
	}
}

func TestSetXattrNoUpperDirIsEROFS(t *testing.T) {
	d, paths, mr, _ := newXattrHarness(t, false)
	paths.Entries[0xA150] = "/anything"
	paths.Entries[0xA151] = "user.any"
	mr.Stage(0xA500, []byte("v"))

	regs := &Regs{NR: SysSetXattr}
	regs.X[0] = 0xA150
	regs.X[1] = 0xA151
	regs.X[2] = 0xA500
	regs.X[3] = 1
	regs.X[4] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EROFS)
}

func TestFGetXattrOnHostFd(t *testing.T) {
	d, paths, _, mw := newXattrHarness(t, true)
	path := filepath.Join(d.FS.policy.UpperDir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(path) {
		t.Skip("fs lacks user.* xattrs")
	}
	if err := syscall.Setxattr(path, "user.fd", []byte("FDVAL"), 0); err != nil {
		t.Fatal(err)
	}
	hostFd, err := syscall.Open(path, syscall.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	g := d.FDs.Allocate(hostFd)

	paths.Entries[0xA161] = "user.fd"
	regs := &Regs{NR: SysFGetXattr}
	regs.X[0] = uint64(g)
	regs.X[1] = 0xA161
	regs.X[2] = 0xA600
	regs.X[3] = 64
	d.Dispatch(regs)
	n := int64(regs.X[0])
	if n != 5 {
		t.Fatalf("fgetxattr returned %d, want 5", n)
	}
	if got := string(mw.Read(0xA600, int(n))); got != "FDVAL" {
		t.Errorf("value = %q, want FDVAL", got)
	}
}

func TestFSetXattrOnHostFd(t *testing.T) {
	d, paths, mr, _ := newXattrHarness(t, true)
	path := filepath.Join(d.FS.policy.UpperDir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(path) {
		t.Skip("fs lacks user.* xattrs")
	}
	hostFd, err := syscall.Open(path, syscall.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	g := d.FDs.Allocate(hostFd)

	paths.Entries[0xA171] = "user.via_fd"
	mr.Stage(0xA700, []byte("setme"))
	regs := &Regs{NR: SysFSetXattr}
	regs.X[0] = uint64(g)
	regs.X[1] = 0xA171
	regs.X[2] = 0xA700
	regs.X[3] = 5
	regs.X[4] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("fsetxattr returned %d", int64(regs.X[0]))
	}
	buf := make([]byte, 16)
	n, err := syscall.Getxattr(path, "user.via_fd", buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "setme" {
		t.Errorf("xattr = %q, want setme", buf[:n])
	}
}

func TestFGetXattrUnknownFdIsEBADF(t *testing.T) {
	d, paths, _, _ := newXattrHarness(t, true)
	paths.Entries[0xA181] = "user.any"
	regs := &Regs{NR: SysFGetXattr}
	regs.X[0] = 999
	regs.X[1] = 0xA181
	regs.X[2] = 0
	regs.X[3] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}
