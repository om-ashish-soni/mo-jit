package gate

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func mustMkdirAll(tb testing.TB, dir string) {
	tb.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatal(err)
	}
}

func mustTouch(tb testing.TB, path string) {
	tb.Helper()
	mustMkdirAll(tb, filepath.Dir(path))
	f, err := os.Create(path)
	if err != nil {
		tb.Fatal(err)
	}
	_ = f.Close()
}

func mustWhiteout(tb testing.TB, path string) bool {
	tb.Helper()
	mustMkdirAll(tb, filepath.Dir(path))
	// Whiteout = character device (mode|S_IFCHR) with rdev 0:0. Matches
	// fuse-overlayfs. Unprivileged users on Linux typically lack
	// CAP_MKNOD for character devices; in that case the caller should
	// skip the test rather than fail it.
	if err := syscall.Mknod(path, syscall.S_IFCHR|0o600, 0); err != nil {
		tb.Skipf("mknod whiteout unavailable (likely CAP_MKNOD missing on this runner): %v", err)
		return false
	}
	return true
}

func TestFSGateRejectsRelativePath(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})
	_, _, err := g.Resolve("etc/hostname")
	if !errors.Is(err, ErrEscape) {
		t.Fatalf("want ErrEscape, got %v", err)
	}
}

func TestFSGateLowerOnly(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	mustTouch(t, filepath.Join(lower, "etc/hostname"))

	g := NewFSGate(Policy{LowerDir: lower})
	host, layer, err := g.Resolve("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	if layer != LayerLower {
		t.Errorf("want lower, got %s", layer)
	}
	want := filepath.Join(lower, "etc/hostname")
	if host != want {
		t.Errorf("want %q, got %q", want, host)
	}
}

func TestFSGateLowerFallthroughWhenUpperMissing(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	upper := filepath.Join(tmp, "upper")
	mustTouch(t, filepath.Join(lower, "etc/hostname"))
	mustMkdirAll(t, upper)

	g := NewFSGate(Policy{LowerDir: lower, UpperDir: upper})
	_, layer, err := g.Resolve("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	if layer != LayerLower {
		t.Errorf("upper absent must fall through to lower, got %s", layer)
	}
}

func TestFSGateUpperShadowsLower(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	upper := filepath.Join(tmp, "upper")
	mustTouch(t, filepath.Join(lower, "etc/hostname"))
	mustTouch(t, filepath.Join(upper, "etc/hostname"))

	g := NewFSGate(Policy{LowerDir: lower, UpperDir: upper})
	host, layer, err := g.Resolve("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	if layer != LayerUpper {
		t.Errorf("want upper, got %s", layer)
	}
	want := filepath.Join(upper, "etc/hostname")
	if host != want {
		t.Errorf("want %q, got %q", want, host)
	}
}

func TestFSGateWhiteoutHidesLower(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	upper := filepath.Join(tmp, "upper")
	mustTouch(t, filepath.Join(lower, "etc/hostname"))
	if ok := mustWhiteout(t, filepath.Join(upper, "etc/hostname")); !ok {
		return
	}

	g := NewFSGate(Policy{LowerDir: lower, UpperDir: upper})
	_, _, err := g.Resolve("/etc/hostname")
	if !errors.Is(err, ErrWhiteout) {
		t.Fatalf("want ErrWhiteout, got %v", err)
	}
}

func TestFSGateDoubleDotNormalisesAtRoot(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	mustMkdirAll(t, lower)

	g := NewFSGate(Policy{LowerDir: lower})
	host, layer, err := g.Resolve("/../../sdcard")
	if err != nil {
		t.Fatalf("Clean must neutralise `..` at root, got error %v", err)
	}
	if layer != LayerLower {
		t.Errorf("want lower, got %s", layer)
	}
	want := filepath.Join(lower, "sdcard")
	if host != want {
		t.Errorf("want %q, got %q", want, host)
	}
}

func TestFSGateBindMount(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	project := filepath.Join(tmp, "project")
	mustMkdirAll(t, lower)
	mustTouch(t, filepath.Join(project, "main.go"))

	g := NewFSGate(Policy{
		LowerDir: lower,
		Binds: []BindMount{
			{HostPath: project, GuestPath: "/home/developer"},
		},
	})
	host, layer, err := g.Resolve("/home/developer/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if layer != LayerBind {
		t.Errorf("want bind, got %s", layer)
	}
	want := filepath.Join(project, "main.go")
	if host != want {
		t.Errorf("want %q, got %q", want, host)
	}
}

func TestFSGateBindExactGuestPath(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	project := filepath.Join(tmp, "project")
	mustMkdirAll(t, lower)
	mustMkdirAll(t, project)

	g := NewFSGate(Policy{
		LowerDir: lower,
		Binds: []BindMount{
			{HostPath: project, GuestPath: "/work"},
		},
	})
	host, layer, err := g.Resolve("/work")
	if err != nil {
		t.Fatal(err)
	}
	if layer != LayerBind {
		t.Errorf("want bind, got %s", layer)
	}
	if host != project {
		t.Errorf("want %q, got %q", project, host)
	}
}

func TestFSGateBindNestedLongestMatchWins(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	proj := filepath.Join(tmp, "project")
	vend := filepath.Join(tmp, "vendor")
	mustMkdirAll(t, lower)
	mustMkdirAll(t, proj)
	mustMkdirAll(t, vend)

	g := NewFSGate(Policy{
		LowerDir: lower,
		Binds: []BindMount{
			{HostPath: proj, GuestPath: "/work"},
			{HostPath: vend, GuestPath: "/work/vendor"},
		},
	})
	host, layer, err := g.Resolve("/work/vendor/pkg.go")
	if err != nil {
		t.Fatal(err)
	}
	if layer != LayerBind {
		t.Errorf("want bind, got %s", layer)
	}
	want := filepath.Join(vend, "pkg.go")
	if host != want {
		t.Errorf("nested bind: want %q, got %q", want, host)
	}
}

func TestFSGateBindDotDotDoesNotEscape(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	proj := filepath.Join(tmp, "project")
	mustMkdirAll(t, lower)
	mustMkdirAll(t, proj)

	g := NewFSGate(Policy{
		LowerDir: lower,
		Binds: []BindMount{
			{HostPath: proj, GuestPath: "/work"},
		},
	})
	// /work/../etc/passwd Clean-normalises to /etc/passwd, so the bind
	// does not apply and we resolve in lower/. The bind's HostPath
	// must NOT be exposed via `..`.
	host, layer, err := g.Resolve("/work/../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if layer != LayerLower {
		t.Errorf("want lower (bind must not leak via ..), got %s", layer)
	}
	want := filepath.Join(lower, "etc/passwd")
	if host != want {
		t.Errorf("want %q, got %q", want, host)
	}
}

func TestFSGateRootBind(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	mustTouch(t, filepath.Join(root, "etc/hostname"))

	g := NewFSGate(Policy{
		// No LowerDir: the root bind is the only layer.
		Binds: []BindMount{
			{HostPath: root, GuestPath: "/"},
		},
	})
	host, layer, err := g.Resolve("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	if layer != LayerBind {
		t.Errorf("want bind, got %s", layer)
	}
	want := filepath.Join(root, "etc/hostname")
	if host != want {
		t.Errorf("want %q, got %q", want, host)
	}
}

func TestFSGateBindPrefixDoesNotOvermatch(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	proj := filepath.Join(tmp, "project")
	mustTouch(t, filepath.Join(lower, "workspace/file.txt"))
	mustMkdirAll(t, proj)

	g := NewFSGate(Policy{
		LowerDir: lower,
		Binds: []BindMount{
			// Bind at /work — must NOT match /workspace/... which
			// merely shares a name prefix.
			{HostPath: proj, GuestPath: "/work"},
		},
	})
	host, layer, err := g.Resolve("/workspace/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if layer != LayerLower {
		t.Errorf("/workspace must NOT hit /work bind, got %s", layer)
	}
	want := filepath.Join(lower, "workspace/file.txt")
	if host != want {
		t.Errorf("want %q, got %q", want, host)
	}
}

func TestFSGateNoLowerConfiguredFails(t *testing.T) {
	g := NewFSGate(Policy{})
	if _, _, err := g.Resolve("/etc/hostname"); err == nil {
		t.Fatal("want error when neither binds nor lower cover the path")
	}
}

// -------- isWhiteout semantics, driven without requiring CAP_MKNOD --------

type fakeFileInfo struct {
	mode fs.FileMode
	stat *syscall.Stat_t
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return f.stat }

func TestIsWhiteoutOnlyForCharDevWithZeroRdev(t *testing.T) {
	tests := []struct {
		name string
		mode fs.FileMode
		rdev uint64
		want bool
	}{
		{"regular file", 0, 0, false},
		{"regular file with zero rdev", 0, 0, false},
		{"char dev with non-zero rdev", os.ModeDevice | os.ModeCharDevice, 0x100, false},
		{"char dev with zero rdev (whiteout)", os.ModeDevice | os.ModeCharDevice, 0, true},
		{"block dev with zero rdev", os.ModeDevice, 0, false},
		{"dir", os.ModeDir, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fi := fakeFileInfo{mode: tc.mode, stat: &syscall.Stat_t{Rdev: tc.rdev}}
			if got := isWhiteout(fi); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsWhiteoutHandlesNilStat(t *testing.T) {
	// FileInfo whose Sys() is not a *syscall.Stat_t (e.g. a platform
	// abstraction or test double) must not crash the whiteout check.
	fi := struct {
		os.FileInfo
	}{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("isWhiteout panicked on non-syscall Sys(): %v", r)
		}
	}()
	// Wrap in a minimal FileInfo impl: mode with ModeCharDevice, Sys
	// returning a non-stat value.
	type weird struct {
		mode fs.FileMode
		sys  any
	}
	_ = fi
	weirdFI := fakeFileInfoWeirdSys{mode: os.ModeDevice | os.ModeCharDevice, sys: "not a stat"}
	if got := isWhiteout(weirdFI); got {
		t.Errorf("expected false for non-syscall Sys, got true")
	}
}

type fakeFileInfoWeirdSys struct {
	mode fs.FileMode
	sys  any
}

func (f fakeFileInfoWeirdSys) Name() string       { return "weird" }
func (f fakeFileInfoWeirdSys) Size() int64        { return 0 }
func (f fakeFileInfoWeirdSys) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfoWeirdSys) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfoWeirdSys) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfoWeirdSys) Sys() any           { return f.sys }
