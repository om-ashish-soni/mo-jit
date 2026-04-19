package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type renameHarness struct {
	d     *Dispatcher
	lower string
	upper string
	paths *FakePathReader
}

func newRenameHarness(t *testing.T, withUpper bool) *renameHarness {
	t.Helper()
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	mustMkdirAll(t, lower)
	pol := Policy{LowerDir: lower}
	h := &renameHarness{lower: lower}
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

func (h *renameHarness) rename(oldPtr uint64, oldPath string, newPtr uint64, newPath string) *Regs {
	h.paths.Entries[oldPtr] = oldPath
	h.paths.Entries[newPtr] = newPath
	r := &Regs{NR: SysRenameAt}
	r.X[0] = atFDCWDAsX0()
	r.X[1] = oldPtr
	r.X[2] = atFDCWDAsX0()
	r.X[3] = newPtr
	h.d.Dispatch(r)
	return r
}

func (h *renameHarness) rename2(oldPtr uint64, oldPath string, newPtr uint64, newPath string, flags int) *Regs {
	h.paths.Entries[oldPtr] = oldPath
	h.paths.Entries[newPtr] = newPath
	r := &Regs{NR: SysRenameAt2}
	r.X[0] = atFDCWDAsX0()
	r.X[1] = oldPtr
	r.X[2] = atFDCWDAsX0()
	r.X[3] = newPtr
	r.X[4] = uint64(flags)
	h.d.Dispatch(r)
	return r
}

func TestRenameAtSameLayerUpperFile(t *testing.T) {
	h := newRenameHarness(t, true)
	src := filepath.Join(h.upper, "src.txt")
	if err := os.WriteFile(src, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := h.rename(0xb001, "/src.txt", 0xb002, "/dst.txt")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	if _, err := os.Lstat(src); !os.IsNotExist(err) {
		t.Errorf("src still exists after rename: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(h.upper, "dst.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Errorf("dst content = %q, want data", got)
	}
}

func TestRenameAtLowerOnlyCopiesAndWhitesOut(t *testing.T) {
	h := newRenameHarness(t, true)
	srcLower := filepath.Join(h.lower, "src.txt")
	if err := os.WriteFile(srcLower, []byte("lower-data"), 0o640); err != nil {
		t.Fatal(err)
	}
	r := h.rename(0xb010, "/src.txt", 0xb011, "/dst.txt")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename lower-only: X[0]=%d (%s)",
			int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	// Lower must survive (immutable).
	if _, err := os.Lstat(srcLower); err != nil {
		t.Errorf("lower src disappeared: %v", err)
	}
	// Dst upper must hold the content.
	got, err := os.ReadFile(filepath.Join(h.upper, "dst.txt"))
	if err != nil {
		t.Fatalf("dst missing on upper: %v", err)
	}
	if string(got) != "lower-data" {
		t.Errorf("dst content = %q, want lower-data", got)
	}
	// Permission should be preserved.
	info, _ := os.Lstat(filepath.Join(h.upper, "dst.txt"))
	if info.Mode().Perm() != 0o640 {
		t.Errorf("dst perm = %v, want 0640", info.Mode().Perm())
	}
	// Src location must be hidden by a whiteout so the guest stops
	// seeing it at /src.txt.
	if !pathIsWhiteout(t, filepath.Join(h.upper, "src.txt")) {
		t.Errorf("no whiteout at upper src after cross-layer rename")
	}
}

func TestRenameAtBothLayersMovesUpperAndWhitesOutSrc(t *testing.T) {
	h := newRenameHarness(t, true)
	lowerSrc := filepath.Join(h.lower, "dup")
	upperSrc := filepath.Join(h.upper, "dup")
	if err := os.WriteFile(lowerSrc, []byte("lower"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(upperSrc, []byte("upper-wins"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := h.rename(0xb020, "/dup", 0xb021, "/moved")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename both: X[0]=%d", int64(r.X[0]))
	}
	// Dst has the upper content (since upper masked lower).
	got, err := os.ReadFile(filepath.Join(h.upper, "moved"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "upper-wins" {
		t.Errorf("moved content = %q, want upper-wins", got)
	}
	// Src must now be whited-out so the lower entry stays hidden.
	if !pathIsWhiteout(t, upperSrc) {
		t.Errorf("no whiteout at original src upper path")
	}
	// Lower still intact (as always).
	if _, err := os.Lstat(lowerSrc); err != nil {
		t.Errorf("lower src vanished: %v", err)
	}
}

func TestRenameAtOverExistingUpperOverwrites(t *testing.T) {
	h := newRenameHarness(t, true)
	if err := os.WriteFile(filepath.Join(h.upper, "a"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.upper, "b"), []byte("B"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := h.rename(0xb030, "/a", 0xb031, "/b")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename overwrite: X[0]=%d", int64(r.X[0]))
	}
	got, err := os.ReadFile(filepath.Join(h.upper, "b"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "A" {
		t.Errorf("after overwrite b = %q, want A", got)
	}
	if _, err := os.Lstat(filepath.Join(h.upper, "a")); !os.IsNotExist(err) {
		t.Errorf("src still present after rename: %v", err)
	}
}

func TestRenameAtOverWhiteoutProceeds(t *testing.T) {
	h := newRenameHarness(t, true)
	if err := os.WriteFile(filepath.Join(h.upper, "src"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Whiteout at dst (pretend the guest had deleted /dst earlier).
	mustTouch(t, filepath.Join(h.lower, "dst"))
	if ok := mustWhiteout(t, filepath.Join(h.upper, "dst")); !ok {
		return
	}
	r := h.rename(0xb040, "/src", 0xb041, "/dst")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename over whiteout: X[0]=%d", int64(r.X[0]))
	}
	got, err := os.ReadFile(filepath.Join(h.upper, "dst"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "x" {
		t.Errorf("after rename over whiteout = %q, want x", got)
	}
}

func TestRenameAt2NoReplaceWithExistingReturnsEEXIST(t *testing.T) {
	h := newRenameHarness(t, true)
	if err := os.WriteFile(filepath.Join(h.upper, "s"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.upper, "d"), []byte("d"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := h.rename2(0xb050, "/s", 0xb051, "/d", renameNoReplace)
	expectErrno(t, r, syscall.EEXIST)
}

func TestRenameAt2NoReplaceOverWhiteoutSucceeds(t *testing.T) {
	// A whiteout at dst means the guest sees dst as absent, so
	// RENAME_NOREPLACE must succeed — matching kernel overlayfs.
	h := newRenameHarness(t, true)
	if err := os.WriteFile(filepath.Join(h.upper, "s"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustTouch(t, filepath.Join(h.lower, "d"))
	if ok := mustWhiteout(t, filepath.Join(h.upper, "d")); !ok {
		return
	}
	r := h.rename2(0xb060, "/s", 0xb061, "/d", renameNoReplace)
	if int64(r.X[0]) != 0 {
		t.Fatalf("noreplace over whiteout: X[0]=%d", int64(r.X[0]))
	}
}

func TestRenameAt2ExchangeReturnsENOSYS(t *testing.T) {
	h := newRenameHarness(t, true)
	r := h.rename2(0xb070, "/a", 0xb071, "/b", renameExchange)
	expectErrno(t, r, syscall.ENOSYS)
}

func TestRenameAt2WhiteoutFlagReturnsENOSYS(t *testing.T) {
	h := newRenameHarness(t, true)
	r := h.rename2(0xb080, "/a", 0xb081, "/b", renameWhiteout)
	expectErrno(t, r, syscall.ENOSYS)
}

func TestRenameAtMissingSourceReturnsENOENT(t *testing.T) {
	h := newRenameHarness(t, true)
	r := h.rename(0xb090, "/nope", 0xb091, "/dst")
	expectErrno(t, r, syscall.ENOENT)
}

func TestRenameAtSameSrcAndDstIsNoOp(t *testing.T) {
	h := newRenameHarness(t, true)
	mustTouch(t, filepath.Join(h.upper, "x"))
	r := h.rename(0xb0a0, "/x", 0xb0a1, "/x")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename(x,x): X[0]=%d", int64(r.X[0]))
	}
	if _, err := os.Lstat(filepath.Join(h.upper, "x")); err != nil {
		t.Errorf("x disappeared: %v", err)
	}
}

func TestRenameAtSameLayerUpperDir(t *testing.T) {
	h := newRenameHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.upper, "srcdir"))
	r := h.rename(0xb0b0, "/srcdir", 0xb0b1, "/dstdir")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename upper dir: X[0]=%d", int64(r.X[0]))
	}
	if _, err := os.Lstat(filepath.Join(h.upper, "dstdir")); err != nil {
		t.Errorf("dstdir missing: %v", err)
	}
}

// TestRenameAtCrossLayerEmptyDirPromotes is the simplest shape of
// cross-layer dir rename: a lower-only empty dir moved to a new name.
// Must succeed (kernel overlayfs would), produce the dst on upper,
// and leave a whiteout at the old path so the guest doesn't see it.
func TestRenameAtCrossLayerEmptyDirPromotes(t *testing.T) {
	h := newRenameHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.lower, "d"))
	r := h.rename(0xb0c0, "/d", 0xb0c1, "/d2")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename /d → /d2: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	if info, err := os.Stat(filepath.Join(h.upper, "d2")); err != nil || !info.IsDir() {
		t.Errorf("upper /d2 not a dir: err=%v info=%v", err, info)
	}
	if !pathIsWhiteout(t, filepath.Join(h.upper, "d")) {
		t.Errorf("upper /d not a whiteout after rename")
	}
}

// TestRenameAtCrossLayerDirWithChildrenPreservesTree mirrors apt's
// post-install pattern: move a populated config dir from the base
// image to a backup name. Every child — nested subdirs, regular
// files, symlinks — must land on upper at the new location, with
// perms and link targets intact.
func TestRenameAtCrossLayerDirWithChildrenPreservesTree(t *testing.T) {
	h := newRenameHarness(t, true)
	root := filepath.Join(h.lower, "src")
	mustMkdirAll(t, filepath.Join(root, "nested"))
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested/b.txt"), []byte("beta"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(root, "link-to-a")); err != nil {
		t.Fatal(err)
	}

	r := h.rename(0xb0d0, "/src", 0xb0d1, "/dst")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename /src → /dst: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}

	dst := filepath.Join(h.upper, "dst")
	data, err := os.ReadFile(filepath.Join(dst, "a.txt"))
	if err != nil || string(data) != "alpha" {
		t.Errorf("dst/a.txt contents = %q err=%v, want \"alpha\"", data, err)
	}
	if info, err := os.Stat(filepath.Join(dst, "a.txt")); err == nil && info.Mode().Perm() != 0o640 {
		t.Errorf("dst/a.txt mode = %o, want 0o640", info.Mode().Perm())
	}
	if b, err := os.ReadFile(filepath.Join(dst, "nested/b.txt")); err != nil || string(b) != "beta" {
		t.Errorf("dst/nested/b.txt contents = %q err=%v, want \"beta\"", b, err)
	}
	target, err := os.Readlink(filepath.Join(dst, "link-to-a"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "a.txt" {
		t.Errorf("dst/link-to-a → %q, want \"a.txt\"", target)
	}
	if !isOpaqueDir(dst) {
		t.Errorf("cross-layer dir rename dst is not marked opaque")
	}
	if !pathIsWhiteout(t, filepath.Join(h.upper, "src")) {
		t.Errorf("upper /src not whiteouted after rename")
	}
}

// If lower shadows dst at the same path, the opaque marker must
// prevent the merged readdir from leaking lower entries back into
// the renamed-into directory.
func TestRenameAtCrossLayerDirOpaqueHidesLowerShadow(t *testing.T) {
	h := newRenameHarness(t, true)
	mustMkdirAll(t, filepath.Join(h.lower, "src"))
	if err := os.WriteFile(filepath.Join(h.lower, "src/a.txt"), []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustMkdirAll(t, filepath.Join(h.lower, "dst"))
	if err := os.WriteFile(filepath.Join(h.lower, "dst/shadow.txt"), []byte("do-not-see-me"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := h.rename(0xb0e0, "/src", 0xb0e1, "/dst")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename /src → /dst: X[0]=%d (%s)", int64(r.X[0]), syscall.Errno(-int64(r.X[0])))
	}
	dst := filepath.Join(h.upper, "dst")
	if _, err := os.Stat(filepath.Join(dst, "a.txt")); err != nil {
		t.Errorf("dst/a.txt missing after rename: %v", err)
	}
	if !isOpaqueDir(dst) {
		t.Errorf("dst must be opaque to hide lower /dst/shadow.txt")
	}
}

func TestRenameAtSymlinkCrossLayerPreservesTarget(t *testing.T) {
	h := newRenameHarness(t, true)
	if err := os.Symlink("/opt/bin", filepath.Join(h.lower, "shortcut")); err != nil {
		t.Fatal(err)
	}
	r := h.rename(0xb0d0, "/shortcut", 0xb0d1, "/newshort")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename symlink lower: X[0]=%d", int64(r.X[0]))
	}
	target, err := os.Readlink(filepath.Join(h.upper, "newshort"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "/opt/bin" {
		t.Errorf("new link target = %q, want /opt/bin", target)
	}
	if !pathIsWhiteout(t, filepath.Join(h.upper, "shortcut")) {
		t.Errorf("original path not whited-out after symlink rename")
	}
}

func TestRenameAtWithoutUpperDirReturnsEROFS(t *testing.T) {
	h := newRenameHarness(t, false)
	r := h.rename(0xb0e0, "/a", 0xb0e1, "/b")
	expectErrno(t, r, syscall.EROFS)
}

func TestRenameAtDirRelativeWithRealDirfdReturnsENOSYS(t *testing.T) {
	h := newRenameHarness(t, true)
	h.paths.Entries[0xb0f0] = "relative/src"
	h.paths.Entries[0xb0f1] = "/dst"
	r := &Regs{NR: SysRenameAt}
	r.X[0] = 0 // real dirfd
	r.X[1] = 0xb0f0
	r.X[2] = atFDCWDAsX0()
	r.X[3] = 0xb0f1
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.ENOSYS)
}

func TestRenameAtOldPathFaultReturnsEFAULT(t *testing.T) {
	h := newRenameHarness(t, true)
	h.paths.Entries[0xb101] = "/dst"
	r := &Regs{NR: SysRenameAt}
	r.X[0] = atFDCWDAsX0()
	r.X[1] = 0 // NULL old path
	r.X[2] = atFDCWDAsX0()
	r.X[3] = 0xb101
	h.d.Dispatch(r)
	expectErrno(t, r, syscall.EFAULT)
}

// TestRenameThenStatSeesNewNameAndOldNameGone verifies the end-to-end
// guest view: after rename, newfstatat on dst succeeds, newfstatat on
// src returns ENOENT. This is the property apt/dpkg actually rely on.
func TestRenameThenStatSeesNewNameAndOldNameGone(t *testing.T) {
	h := newRenameHarness(t, true)
	if err := os.WriteFile(filepath.Join(h.lower, "conf"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := h.rename(0xb110, "/conf", 0xb111, "/conf.new")
	if int64(r.X[0]) != 0 {
		t.Fatalf("rename: X[0]=%d", int64(r.X[0]))
	}

	mw := &FakeMemWriter{}
	h.d.Mem = mw

	// Stat new name — must succeed.
	h.paths.Entries[0xb112] = "/conf.new"
	sr := &Regs{NR: SysNewFStatAt}
	sr.X[0] = atFDCWDAsX0()
	sr.X[1] = 0xb112
	sr.X[2] = 0xc000
	sr.X[3] = 0
	h.d.Dispatch(sr)
	if int64(sr.X[0]) != 0 {
		t.Errorf("stat new name: X[0]=%d", int64(sr.X[0]))
	}

	// Stat old name — must be ENOENT.
	h.paths.Entries[0xb113] = "/conf"
	sr2 := &Regs{NR: SysNewFStatAt}
	sr2.X[0] = atFDCWDAsX0()
	sr2.X[1] = 0xb113
	sr2.X[2] = 0xc100
	sr2.X[3] = 0
	h.d.Dispatch(sr2)
	expectErrno(t, sr2, syscall.ENOENT)
}
