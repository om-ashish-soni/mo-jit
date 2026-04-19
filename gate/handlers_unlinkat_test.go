package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type unlinkHarness struct {
	d     *Dispatcher
	lower string
	upper string
	paths *FakePathReader
}

func newUnlinkHarness(t *testing.T, withUpper bool) *unlinkHarness {
	t.Helper()
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	mustMkdirAll(t, lower)
	pol := Policy{LowerDir: lower}
	h := &unlinkHarness{lower: lower}
	if withUpper {
		upper := filepath.Join(tmp, "upper")
		mustMkdirAll(t, upper)
		pol.UpperDir = upper
		h.upper = upper
	}
	d := NewDispatcher(pol)
	h.paths = &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = h.paths
	h.d = d
	return h
}

func (h *unlinkHarness) unlink(ptr uint64, path string, dirfd int64, flags int) *Regs {
	h.paths.Entries[ptr] = path
	r := &Regs{NR: SysUnlinkAt}
	r.X[0] = uint64(dirfd)
	r.X[1] = ptr
	r.X[2] = uint64(flags)
	h.d.Dispatch(r)
	return r
}

// pathMatches is a thin predicate the tests use to assert an upper
// entry is-whiteout without duplicating the detection logic.
func pathIsWhiteout(t *testing.T, path string) bool {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return isWhiteoutPath(path, info)
}

func TestUnlinkAtUpperOnlyRemovesFile(t *testing.T) {
	h := newUnlinkHarness(t, true)
	p := filepath.Join(h.upper, "a.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := h.unlink(0xa001, "/a.txt", int64(atFDCWD), 0)
	if int64(r.X[0]) != 0 {
		t.Fatalf("unlinkat: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Errorf("upper file still present: err=%v", err)
	}
	// No whiteout needed when lower doesn't back the path.
	if pathIsWhiteout(t, p) {
		t.Errorf("whiteout written for upper-only file")
	}
}

func TestUnlinkAtLowerOnlyWritesWhiteout(t *testing.T) {
	h := newUnlinkHarness(t, true)
	lowerFile := filepath.Join(h.lower, "b.txt")
	if err := os.WriteFile(lowerFile, []byte("lower"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := h.unlink(0xa002, "/b.txt", int64(atFDCWD), 0)
	if int64(r.X[0]) != 0 {
		t.Fatalf("unlinkat lower: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	// Lower must survive the guest's "delete" — the shared base
	// image is immutable.
	if _, err := os.Lstat(lowerFile); err != nil {
		t.Errorf("lower file disappeared: %v", err)
	}
	// Upper must hold a whiteout now so Resolve returns ErrWhiteout
	// and the guest sees the path as deleted.
	if !pathIsWhiteout(t, filepath.Join(h.upper, "b.txt")) {
		t.Errorf("no whiteout at upper/b.txt after unlink of lower file")
	}
	// Verify Resolve actually sees it as whiteout.
	if _, _, err := h.d.FS.Resolve("/b.txt"); err != ErrWhiteout {
		t.Errorf("Resolve after whiteout: got %v, want ErrWhiteout", err)
	}
}

func TestUnlinkAtBothLayersRemovesUpperAndWritesWhiteout(t *testing.T) {
	h := newUnlinkHarness(t, true)
	up := filepath.Join(h.upper, "c.txt")
	low := filepath.Join(h.lower, "c.txt")
	if err := os.WriteFile(up, []byte("upper"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(low, []byte("lower"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := h.unlink(0xa003, "/c.txt", int64(atFDCWD), 0)
	if int64(r.X[0]) != 0 {
		t.Fatalf("unlinkat both: X[0]=%d", int64(r.X[0]))
	}
	if !pathIsWhiteout(t, up) {
		t.Errorf("upper should be a whiteout, still looks like a regular file")
	}
	if _, err := os.Lstat(low); err != nil {
		t.Errorf("lower vanished: %v", err)
	}
}

func TestUnlinkAtMissingReturnsENOENT(t *testing.T) {
	h := newUnlinkHarness(t, true)
	r := h.unlink(0xa004, "/nope", int64(atFDCWD), 0)
	expectErrno(t, r, syscall.ENOENT)
}

func TestUnlinkAtAlreadyWhitedOutReturnsENOENT(t *testing.T) {
	h := newUnlinkHarness(t, true)
	// Lower has nothing at /gone; upper has a whiteout for it. This
	// corner comes up when the guest re-tries a delete.
	if ok := mustWhiteout(t, filepath.Join(h.upper, "gone")); !ok {
		return
	}
	r := h.unlink(0xa005, "/gone", int64(atFDCWD), 0)
	expectErrno(t, r, syscall.ENOENT)
}

func TestUnlinkAtOnDirectoryWithoutRemoveDirReturnsEISDIR(t *testing.T) {
	h := newUnlinkHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.upper, "d"))
	r := h.unlink(0xa006, "/d", int64(atFDCWD), 0)
	expectErrno(t, r, syscall.EISDIR)
}

func TestUnlinkAtRemoveDirOnFileReturnsENOTDIR(t *testing.T) {
	h := newUnlinkHarness(t, true)
	if err := os.WriteFile(filepath.Join(h.upper, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	r := h.unlink(0xa007, "/file", int64(atFDCWD), atRemoveDir)
	expectErrno(t, r, syscall.ENOTDIR)
}

func TestUnlinkAtRemoveDirUpperEmptySucceeds(t *testing.T) {
	h := newUnlinkHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.upper, "empty"))
	r := h.unlink(0xa008, "/empty", int64(atFDCWD), atRemoveDir)
	if int64(r.X[0]) != 0 {
		t.Fatalf("rmdir empty upper: X[0]=%d", int64(r.X[0]))
	}
	if _, err := os.Lstat(filepath.Join(h.upper, "empty")); !os.IsNotExist(err) {
		t.Errorf("upper dir still present: err=%v", err)
	}
}

func TestUnlinkAtRemoveDirUpperNonEmptyReturnsENOTEMPTY(t *testing.T) {
	h := newUnlinkHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.upper, "full"))
	if err := os.WriteFile(filepath.Join(h.upper, "full/child"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	r := h.unlink(0xa009, "/full", int64(atFDCWD), atRemoveDir)
	expectErrno(t, r, syscall.ENOTEMPTY)
}

func TestUnlinkAtRemoveDirLowerWithChildrenReturnsENOTEMPTY(t *testing.T) {
	h := newUnlinkHarness(t, true)
	// Lower has a populated dir; upper has nothing.
	mustMkdirAll(t, filepath.Join(h.lower, "base"))
	if err := os.WriteFile(filepath.Join(h.lower, "base/file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	r := h.unlink(0xa00a, "/base", int64(atFDCWD), atRemoveDir)
	expectErrno(t, r, syscall.ENOTEMPTY)
}

func TestUnlinkAtRemoveDirLowerEmptyWritesWhiteout(t *testing.T) {
	h := newUnlinkHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.lower, "empty_lower"))
	r := h.unlink(0xa00b, "/empty_lower", int64(atFDCWD), atRemoveDir)
	if int64(r.X[0]) != 0 {
		t.Fatalf("rmdir lower-empty: X[0]=%d (%s)",
			int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	if !pathIsWhiteout(t, filepath.Join(h.upper, "empty_lower")) {
		t.Errorf("no whiteout at upper/empty_lower")
	}
}

func TestUnlinkAtWithoutUpperDirReturnsEROFS(t *testing.T) {
	h := newUnlinkHarness(t, false)
	r := h.unlink(0xa00c, "/something", int64(atFDCWD), 0)
	expectErrno(t, r, syscall.EROFS)
}

func TestUnlinkAtRootReturnsEISDIR(t *testing.T) {
	h := newUnlinkHarness(t, true)
	r := h.unlink(0xa00d, "/", int64(atFDCWD), 0)
	expectErrno(t, r, syscall.EISDIR)
}

func TestUnlinkAtRootRemoveDirReturnsEBUSY(t *testing.T) {
	h := newUnlinkHarness(t, true)
	r := h.unlink(0xa00e, "/", int64(atFDCWD), atRemoveDir)
	expectErrno(t, r, syscall.EBUSY)
}

func TestUnlinkAtDirRelativeWithRealDirfdReturnsENOSYS(t *testing.T) {
	h := newUnlinkHarness(t, true)
	r := h.unlink(0xa00f, "relative", 0, 0)
	expectErrno(t, r, syscall.ENOSYS)
}

func TestUnlinkAtPathFaultReturnsEFAULT(t *testing.T) {
	h := newUnlinkHarness(t, true)
	r := &Regs{NR: SysUnlinkAt}
	r.X[0] = atFDCWDAsX0()
	r.X[1] = 0
	r.X[2] = 0
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EFAULT)
}

// TestUnlinkThenOpenSurfacesENOENT: full end-to-end — delete a lower
// file, then try openat on the same path. The open must see the
// whiteout and return ENOENT rather than reaching through to the
// still-present lower file.
func TestUnlinkThenOpenSurfacesENOENT(t *testing.T) {
	h := newUnlinkHarness(t, true)
	lowerFile := filepath.Join(h.lower, "delete-me")
	if err := os.WriteFile(lowerFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	u := h.unlink(0xa010, "/delete-me", int64(atFDCWD), 0)
	if int64(u.X[0]) != 0 {
		t.Fatalf("unlink: X[0]=%d", int64(u.X[0]))
	}

	h.paths.Entries[0xa011] = "/delete-me"
	open := &Regs{NR: SysOpenAt}
	open.X[0] = atFDCWDAsX0()
	open.X[1] = 0xa011
	open.X[2] = uint64(syscall.O_RDONLY)
	h.d.Dispatch(open)
	expectErrno(t, open, syscall.ENOENT)
}

// TestUnlinkXattrWhiteoutDetected: explicitly exercise the fallback
// whiteout format — a regular placeholder file with the xattr marker
// — to prove isWhiteoutPath recognises it and Resolve surfaces
// ErrWhiteout. Test uses writeWhiteout after forcing the mknod path
// to return EPERM via a file collision that mknod can't overcome.
func TestUnlinkXattrWhiteoutDetected(t *testing.T) {
	// Directly create an xattr-style whiteout using the package's
	// helper, bypassing unlinkat — we want to test detection, not
	// writing.
	tmp := t.TempDir()
	upper := filepath.Join(tmp, "upper")
	mustMkdirAll(t, upper)
	victim := filepath.Join(upper, "x.txt")
	// Force the xattr form: create a regular file first and stamp
	// the xattr manually. This mirrors what writeWhiteout's fallback
	// produces when mknod is denied.
	if err := os.WriteFile(victim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setxattr(victim, whiteoutXattr, []byte{'y'}, 0); err != nil {
		t.Skipf("user.* xattr unsupported on tmpfs used by t.TempDir(): %v", err)
	}

	info, err := os.Lstat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if !isWhiteoutPath(victim, info) {
		t.Errorf("xattr-marked placeholder not detected as whiteout")
	}
	// And via FSGate.Resolve end-to-end.
	g := NewFSGate(Policy{LowerDir: tmp, UpperDir: upper})
	if _, _, err := g.Resolve("/x.txt"); err != ErrWhiteout {
		t.Errorf("Resolve on xattr whiteout: got %v, want ErrWhiteout", err)
	}
}
