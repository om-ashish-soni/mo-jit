package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type mkdirHarness struct {
	d     *Dispatcher
	lower string
	upper string
	paths *FakePathReader
}

func newMkdirHarness(t *testing.T, withUpper bool) *mkdirHarness {
	t.Helper()
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	mustMkdirAll(t, lower)
	pol := Policy{LowerDir: lower}
	h := &mkdirHarness{lower: lower}
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

func (h *mkdirHarness) mkdir(ptr uint64, path string, dirfd int64, mode uint32) *Regs {
	h.paths.Entries[ptr] = path
	r := &Regs{NR: SysMkdirAt}
	r.X[0] = uint64(dirfd)
	r.X[1] = ptr
	r.X[2] = uint64(mode)
	h.d.Dispatch(r)
	return r
}

func TestMkdirAtOnUpperCreatesDir(t *testing.T) {
	h := newMkdirHarness(t, true)
	r := h.mkdir(0x8001, "/newdir", int64(atFDCWD), 0o755)
	if int64(r.X[0]) != 0 {
		t.Fatalf("mkdirat: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	info, err := os.Lstat(filepath.Join(h.upper, "newdir"))
	if err != nil {
		t.Fatalf("new dir missing on upper: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("upper entry is not a dir: %v", info.Mode())
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("dir perm = %v, want 0755", info.Mode().Perm())
	}
}

func TestMkdirAtExistingReturnsEEXIST(t *testing.T) {
	h := newMkdirHarness(t, true)
	// Pre-existing on upper.
	mustMkdirAll(t, filepath.Join(h.upper, "already"))
	r := h.mkdir(0x8002, "/already", int64(atFDCWD), 0o755)
	expectErrno(t, r, syscall.EEXIST)

	// Pre-existing on lower only — overlay still surfaces EEXIST.
	mustMkdirAll(t, filepath.Join(h.lower, "lowerdir"))
	r2 := h.mkdir(0x8003, "/lowerdir", int64(atFDCWD), 0o755)
	expectErrno(t, r2, syscall.EEXIST)
}

func TestMkdirAtWithoutUpperDirReturnsEROFS(t *testing.T) {
	h := newMkdirHarness(t, false)
	r := h.mkdir(0x8004, "/nope", int64(atFDCWD), 0o755)
	expectErrno(t, r, syscall.EROFS)
}

func TestMkdirAtParentOnLowerCreatesChainOnUpper(t *testing.T) {
	// Lower has /proj; guest calls mkdirat("/proj/build").  The
	// guest expects /proj/build to exist on its view, which means
	// upper must have BOTH /proj (parent surrogate) and /proj/build
	// — otherwise stat of the new dir would fall through to lower,
	// which doesn't have it.
	h := newMkdirHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.lower, "proj"))

	r := h.mkdir(0x8005, "/proj/build", int64(atFDCWD), 0o700)
	if int64(r.X[0]) != 0 {
		t.Fatalf("mkdir in lower-parent: X[0]=%d", int64(r.X[0]))
	}
	for _, p := range []string{"proj", "proj/build"} {
		info, err := os.Lstat(filepath.Join(h.upper, p))
		if err != nil || !info.IsDir() {
			t.Errorf("upper/%s missing or not dir: err=%v info=%v", p, err, info)
		}
	}
	if info, _ := os.Lstat(filepath.Join(h.upper, "proj/build")); info != nil {
		if info.Mode().Perm() != 0o700 {
			t.Errorf("leaf perm = %v, want 0700", info.Mode().Perm())
		}
	}
}

func TestMkdirAtOverWhiteoutSucceeds(t *testing.T) {
	h := newMkdirHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.lower, "hidden"))
	if ok := mustWhiteout(t, filepath.Join(h.upper, "hidden")); !ok {
		return
	}
	r := h.mkdir(0x8006, "/hidden", int64(atFDCWD), 0o755)
	if int64(r.X[0]) != 0 {
		t.Fatalf("mkdir over whiteout: X[0]=%d (%s)",
			int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	info, err := os.Lstat(filepath.Join(h.upper, "hidden"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Errorf("expected dir after whiteout removal, got %v", info.Mode())
	}
}

// TestMkdirAtOverWhiteoutStampsOpaque pins the correctness fix for
// "rm -rf dir && mkdir dir": without the opaque marker, the lower
// subtree's children leak back through readdir into the fresh dir.
func TestMkdirAtOverWhiteoutStampsOpaque(t *testing.T) {
	h := newMkdirHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.lower, "d"))
	if err := os.WriteFile(filepath.Join(h.lower, "d", "leaked"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok := mustWhiteout(t, filepath.Join(h.upper, "d")); !ok {
		return
	}

	r := h.mkdir(0x800A, "/d", int64(atFDCWD), 0o755)
	if int64(r.X[0]) != 0 {
		t.Fatalf("mkdir over whiteout: X[0]=%d", int64(r.X[0]))
	}

	buf := make([]byte, 1)
	if _, err := syscall.Getxattr(filepath.Join(h.upper, "d"), opaqueXattr, buf); err != nil {
		if err == syscall.ENOTSUP || err == syscall.EOPNOTSUPP {
			t.Skipf("filesystem lacks user.* xattrs: %v", err)
		}
		t.Errorf("opaque xattr missing on replacement dir: %v", err)
	}
}

func TestMkdirAtDirRelativeWithRealDirfdReturnsENOSYS(t *testing.T) {
	h := newMkdirHarness(t, true)
	r := h.mkdir(0x8007, "relative", 0, 0o755)
	expectErrno(t, r, syscall.ENOSYS)
}

func TestMkdirAtPathFaultReturnsEFAULT(t *testing.T) {
	h := newMkdirHarness(t, true)
	r := &Regs{NR: SysMkdirAt}
	r.X[0] = atFDCWDAsX0()
	r.X[1] = 0
	r.X[2] = 0o755
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EFAULT)
}

func TestMkdirAtRelativeUsesGuestCwd(t *testing.T) {
	h := newMkdirHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.lower, "home/dev"))
	if err := h.d.FS.SetGuestCwd("/home/dev"); err != nil {
		t.Fatal(err)
	}
	r := h.mkdir(0x8008, "build", int64(atFDCWD), 0o755)
	if int64(r.X[0]) != 0 {
		t.Fatalf("mkdir relative via cwd: X[0]=%d", int64(r.X[0]))
	}
	if _, err := os.Lstat(filepath.Join(h.upper, "home/dev/build")); err != nil {
		t.Errorf("expected upper/home/dev/build: %v", err)
	}
}
