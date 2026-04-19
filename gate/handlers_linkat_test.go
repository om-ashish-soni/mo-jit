package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// newLinkAtHarness builds a dispatcher with upper+lower tempdirs and
// a FakePathReader ready to hand out guest paths.
func newLinkAtHarness(t *testing.T) (*Dispatcher, *FakePathReader) {
	t.Helper()
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	d.Paths = paths
	return d, paths
}

func linkatRegs(paths *FakePathReader, oldPath, newPath string, flags uint64) *Regs {
	paths.Entries[0x7100] = oldPath
	paths.Entries[0x7200] = newPath
	regs := &Regs{NR: SysLinkAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0x7100
	regs.X[2] = atFDCWDAsX0()
	regs.X[3] = 0x7200
	regs.X[4] = flags
	return regs
}

func TestLinkAtSameLayerUpper(t *testing.T) {
	// File on upper → hardlink within upper → both paths share inode.
	d, paths := newLinkAtHarness(t)
	src := filepath.Join(d.FS.policy.UpperDir, "src.txt")
	if err := os.WriteFile(src, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	regs := linkatRegs(paths, "/src.txt", "/dst.txt", 0)
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("linkat returned %d, want 0", int64(regs.X[0]))
	}
	dst := filepath.Join(d.FS.policy.UpperDir, "dst.txt")
	var srcStat, dstStat syscall.Stat_t
	if err := syscall.Stat(src, &srcStat); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat(dst, &dstStat); err != nil {
		t.Fatal(err)
	}
	if srcStat.Ino != dstStat.Ino {
		t.Errorf("inode mismatch: src=%d, dst=%d — expected shared", srcStat.Ino, dstStat.Ino)
	}
	if srcStat.Nlink < 2 {
		t.Errorf("nlink = %d, want >=2", srcStat.Nlink)
	}
}

func TestLinkAtCrossLayerPromotesSrc(t *testing.T) {
	// File on LOWER only → copy-up src to upper → hardlink on upper.
	d, paths := newLinkAtHarness(t)
	lowerSrc := filepath.Join(d.FS.policy.LowerDir, "lower.txt")
	if err := os.WriteFile(lowerSrc, []byte("lower-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	regs := linkatRegs(paths, "/lower.txt", "/link.txt", 0)
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("linkat returned %d, want 0", int64(regs.X[0]))
	}
	upSrc := filepath.Join(d.FS.policy.UpperDir, "lower.txt")
	upDst := filepath.Join(d.FS.policy.UpperDir, "link.txt")
	var a, b syscall.Stat_t
	if err := syscall.Stat(upSrc, &a); err != nil {
		t.Fatalf("upper src after copy-up missing: %v", err)
	}
	if err := syscall.Stat(upDst, &b); err != nil {
		t.Fatalf("upper dst after link missing: %v", err)
	}
	if a.Ino != b.Ino {
		t.Errorf("inode mismatch after copy-up+link: %d vs %d", a.Ino, b.Ino)
	}
	content, err := os.ReadFile(upDst)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "lower-bytes" {
		t.Errorf("link target content = %q, want lower-bytes", content)
	}
}

func TestLinkAtDstExistsIsEEXIST(t *testing.T) {
	d, paths := newLinkAtHarness(t)
	src := filepath.Join(d.FS.policy.UpperDir, "a.txt")
	dst := filepath.Join(d.FS.policy.UpperDir, "b.txt")
	if err := os.WriteFile(src, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("2"), 0o600); err != nil {
		t.Fatal(err)
	}

	regs := linkatRegs(paths, "/a.txt", "/b.txt", 0)
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EEXIST)
}

func TestLinkAtDstIsLowerEntryIsEEXIST(t *testing.T) {
	d, paths := newLinkAtHarness(t)
	src := filepath.Join(d.FS.policy.UpperDir, "a.txt")
	if err := os.WriteFile(src, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	lowerDst := filepath.Join(d.FS.policy.LowerDir, "b.txt")
	if err := os.WriteFile(lowerDst, []byte("2"), 0o600); err != nil {
		t.Fatal(err)
	}

	regs := linkatRegs(paths, "/a.txt", "/b.txt", 0)
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EEXIST)
}

func TestLinkAtDstWhiteoutIsCleared(t *testing.T) {
	// Whiteout at dst should be transparently removed so linkat
	// doesn't EEXIST against it.
	d, paths := newLinkAtHarness(t)
	src := filepath.Join(d.FS.policy.UpperDir, "a.txt")
	if err := os.WriteFile(src, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(d.FS.policy.UpperDir, "ghost")
	if err := writeWhiteout(dst); err != nil {
		t.Fatalf("writeWhiteout: %v", err)
	}

	regs := linkatRegs(paths, "/a.txt", "/ghost", 0)
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("linkat returned %d, want 0", int64(regs.X[0]))
	}
	// After link, dst must be a real regular file, NOT a whiteout.
	info, err := os.Lstat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if isWhiteoutPath(dst, info) {
		t.Errorf("dst still a whiteout after successful linkat")
	}
}

func TestLinkAtSrcMissingIsENOENT(t *testing.T) {
	d, paths := newLinkAtHarness(t)
	regs := linkatRegs(paths, "/nope", "/new", 0)
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOENT)
}

func TestLinkAtEmptyPathFlagIsENOSYS(t *testing.T) {
	d, paths := newLinkAtHarness(t)
	regs := linkatRegs(paths, "/x", "/y", atEmptyPathFlag)
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOSYS)
}

func TestLinkAtROFSWithoutUpperDir(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	paths := &FakePathReader{Entries: map[uint64]string{
		0x7100: "/a", 0x7200: "/b",
	}}
	d.Paths = paths

	regs := &Regs{NR: SysLinkAt}
	regs.X[0] = atFDCWDAsX0()
	regs.X[1] = 0x7100
	regs.X[2] = atFDCWDAsX0()
	regs.X[3] = 0x7200
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EROFS)
}
