package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type symlinkHarness struct {
	d     *Dispatcher
	lower string
	upper string
	paths *FakePathReader
}

func newSymlinkHarness(t *testing.T, withUpper bool) *symlinkHarness {
	t.Helper()
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	mustMkdirAll(t, lower)
	pol := Policy{LowerDir: lower}
	h := &symlinkHarness{lower: lower}
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

func (h *symlinkHarness) symlink(targetPtr uint64, target string, dirfd int64, linkPtr uint64, link string) *Regs {
	h.paths.Entries[targetPtr] = target
	h.paths.Entries[linkPtr] = link
	r := &Regs{NR: SysSymlinkAt}
	r.X[0] = targetPtr
	r.X[1] = uint64(dirfd)
	r.X[2] = linkPtr
	h.d.Dispatch(r)
	return r
}

func TestSymlinkAtCreatesLinkOnUpper(t *testing.T) {
	h := newSymlinkHarness(t, true)
	r := h.symlink(0x9001, "/etc/passwd", int64(atFDCWD), 0x9002, "/pw")
	if int64(r.X[0]) != 0 {
		t.Fatalf("symlinkat: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	info, err := os.Lstat(filepath.Join(h.upper, "pw"))
	if err != nil {
		t.Fatalf("upper link missing: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("upper entry is not a symlink: %v", info.Mode())
	}
	target, err := os.Readlink(filepath.Join(h.upper, "pw"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "/etc/passwd" {
		t.Errorf("link target = %q, want /etc/passwd", target)
	}
}

func TestSymlinkAtTargetStoredVerbatim(t *testing.T) {
	// The kernel stores target bytes without normalization: "../a"
	// stays "../a" in the link's data block.
	h := newSymlinkHarness(t, true)
	r := h.symlink(0x9010, "../weird/path", int64(atFDCWD), 0x9011, "/quirky")
	if int64(r.X[0]) != 0 {
		t.Fatalf("symlinkat: X[0]=%d", int64(r.X[0]))
	}
	target, err := os.Readlink(filepath.Join(h.upper, "quirky"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "../weird/path" {
		t.Errorf("link target = %q, want ../weird/path", target)
	}
}

func TestSymlinkAtExistingReturnsEEXIST(t *testing.T) {
	h := newSymlinkHarness(t, true)
	mustTouch(t, filepath.Join(h.upper, "taken"))
	r := h.symlink(0x9020, "/dest", int64(atFDCWD), 0x9021, "/taken")
	expectErrno(t, r, syscall.EEXIST)

	// Also EEXIST when only lower has it.
	mustTouch(t, filepath.Join(h.lower, "lowertaken"))
	r2 := h.symlink(0x9022, "/dest", int64(atFDCWD), 0x9023, "/lowertaken")
	expectErrno(t, r2, syscall.EEXIST)
}

func TestSymlinkAtWithoutUpperDirReturnsEROFS(t *testing.T) {
	h := newSymlinkHarness(t, false)
	r := h.symlink(0x9030, "/dest", int64(atFDCWD), 0x9031, "/link")
	expectErrno(t, r, syscall.EROFS)
}

func TestSymlinkAtParentOnLowerCreatesChainOnUpper(t *testing.T) {
	h := newSymlinkHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.lower, "proj"))

	r := h.symlink(0x9040, "../other", int64(atFDCWD), 0x9041, "/proj/shortcut")
	if int64(r.X[0]) != 0 {
		t.Fatalf("symlinkat in lower-parent: X[0]=%d", int64(r.X[0]))
	}
	parentInfo, err := os.Lstat(filepath.Join(h.upper, "proj"))
	if err != nil || !parentInfo.IsDir() {
		t.Errorf("upper parent missing/not-dir: err=%v info=%v", err, parentInfo)
	}
	info, err := os.Lstat(filepath.Join(h.upper, "proj/shortcut"))
	if err != nil {
		t.Fatalf("upper link missing: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("upper entry is not a symlink: %v", info.Mode())
	}
}

func TestSymlinkAtOverWhiteoutSucceeds(t *testing.T) {
	h := newSymlinkHarness(t, true)
	mustTouch(t, filepath.Join(h.lower, "removed"))
	if ok := mustWhiteout(t, filepath.Join(h.upper, "removed")); !ok {
		return
	}
	r := h.symlink(0x9050, "/elsewhere", int64(atFDCWD), 0x9051, "/removed")
	if int64(r.X[0]) != 0 {
		t.Fatalf("symlink over whiteout: X[0]=%d (%s)",
			int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	target, err := os.Readlink(filepath.Join(h.upper, "removed"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "/elsewhere" {
		t.Errorf("post-whiteout link = %q, want /elsewhere", target)
	}
}

func TestSymlinkAtEmptyTargetReturnsENOENT(t *testing.T) {
	h := newSymlinkHarness(t, true)
	r := h.symlink(0x9060, "", int64(atFDCWD), 0x9061, "/link")
	expectErrno(t, r, syscall.ENOENT)
}

func TestSymlinkAtDirRelativeWithRealDirfdReturnsENOSYS(t *testing.T) {
	h := newSymlinkHarness(t, true)
	r := h.symlink(0x9070, "/dest", 0, 0x9071, "relative/link")
	expectErrno(t, r, syscall.ENOSYS)
}

func TestSymlinkAtTargetFaultReturnsEFAULT(t *testing.T) {
	h := newSymlinkHarness(t, true)
	r := &Regs{NR: SysSymlinkAt}
	r.X[0] = 0 // NULL target
	r.X[1] = atFDCWDAsX0()
	r.X[2] = 0x9081
	h.paths.Entries[0x9081] = "/link"
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EFAULT)
}

func TestSymlinkAtLinkPathFaultReturnsEFAULT(t *testing.T) {
	h := newSymlinkHarness(t, true)
	r := &Regs{NR: SysSymlinkAt}
	r.X[0] = 0x9090
	r.X[1] = atFDCWDAsX0()
	r.X[2] = 0 // NULL linkpath
	h.paths.Entries[0x9090] = "/dest"
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EFAULT)
}

func TestSymlinkAtRelativeLinkUsesGuestCwd(t *testing.T) {
	h := newSymlinkHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.lower, "home/dev"))
	if err := h.d.FS.SetGuestCwd("/home/dev"); err != nil {
		t.Fatal(err)
	}
	r := h.symlink(0x90a0, "/usr/bin/go", int64(atFDCWD), 0x90a1, "go")
	if int64(r.X[0]) != 0 {
		t.Fatalf("symlink relative via cwd: X[0]=%d", int64(r.X[0]))
	}
	target, err := os.Readlink(filepath.Join(h.upper, "home/dev/go"))
	if err != nil {
		t.Fatalf("expected upper/home/dev/go: %v", err)
	}
	if target != "/usr/bin/go" {
		t.Errorf("target = %q, want /usr/bin/go", target)
	}
}
