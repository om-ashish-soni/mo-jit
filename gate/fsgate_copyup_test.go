package gate

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func readFileContent(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCopyUpRegularFile(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	upper := filepath.Join(tmp, "upper")
	mustMkdirAll(t, upper)
	mustMkdirAll(t, filepath.Join(lower, "etc"))
	if err := os.WriteFile(filepath.Join(lower, "etc/config"), []byte("alpha"), 0o640); err != nil {
		t.Fatal(err)
	}

	g := NewFSGate(Policy{LowerDir: lower, UpperDir: upper})
	host, err := g.CopyUp("/etc/config")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(upper, "etc/config")
	if host != want {
		t.Errorf("CopyUp host = %q, want %q", host, want)
	}
	if got := readFileContent(t, host); got != "alpha" {
		t.Errorf("upper content = %q, want alpha", got)
	}
	info, err := os.Lstat(host)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("upper mode = %v, want 0640", info.Mode().Perm())
	}
	// Lower must be untouched.
	if got := readFileContent(t, filepath.Join(lower, "etc/config")); got != "alpha" {
		t.Errorf("lower content mutated after copy-up: %q", got)
	}
}

func TestCopyUpIdempotent(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	upper := filepath.Join(tmp, "upper")
	mustMkdirAll(t, upper)
	mustMkdirAll(t, lower)
	if err := os.WriteFile(filepath.Join(lower, "a"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	g := NewFSGate(Policy{LowerDir: lower, UpperDir: upper})
	host, err := g.CopyUp("/a")
	if err != nil {
		t.Fatal(err)
	}
	// Mutate upper directly to prove a second CopyUp does NOT clobber it.
	if err := os.WriteFile(host, []byte("v2-modified"), 0o644); err != nil {
		t.Fatal(err)
	}
	host2, err := g.CopyUp("/a")
	if err != nil {
		t.Fatal(err)
	}
	if host2 != host {
		t.Errorf("second CopyUp returned different path: %q vs %q", host2, host)
	}
	if got := readFileContent(t, host2); got != "v2-modified" {
		t.Errorf("CopyUp re-copied over existing upper; content = %q", got)
	}
}

func TestCopyUpSymlinkPreservesTarget(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	upper := filepath.Join(tmp, "upper")
	mustMkdirAll(t, upper)
	mustMkdirAll(t, lower)
	if err := os.Symlink("/proc/mounts", filepath.Join(lower, "mtab")); err != nil {
		t.Fatal(err)
	}

	g := NewFSGate(Policy{LowerDir: lower, UpperDir: upper})
	host, err := g.CopyUp("/mtab")
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(host)
	if err != nil {
		t.Fatal(err)
	}
	if target != "/proc/mounts" {
		t.Errorf("upper symlink target = %q, want /proc/mounts", target)
	}
}

func TestCopyUpCreatesParentDirs(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	upper := filepath.Join(tmp, "upper")
	mustMkdirAll(t, upper)
	if err := os.WriteFile(filepath.Join(lower, "a/b/c/deep.txt"),
		nil, 0o644); err != nil {
		// WriteFile won't auto-mkdir; do it manually.
		mustMkdirAll(t, filepath.Join(lower, "a/b/c"))
		if err := os.WriteFile(filepath.Join(lower, "a/b/c/deep.txt"),
			[]byte("hi"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	g := NewFSGate(Policy{LowerDir: lower, UpperDir: upper})
	host, err := g.CopyUp("/a/b/c/deep.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := readFileContent(t, host); got != "hi" {
		t.Errorf("deep file content = %q, want hi", got)
	}
	// Each parent must be a directory on upper now.
	for _, p := range []string{"a", "a/b", "a/b/c"} {
		info, err := os.Lstat(filepath.Join(upper, p))
		if err != nil || !info.IsDir() {
			t.Errorf("parent %q not a dir on upper: err=%v info=%v", p, err, info)
		}
	}
}

func TestCopyUpWithoutUpperDirFails(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})
	_, err := g.CopyUp("/anything")
	if !errors.Is(err, ErrNoUpperLayer) {
		t.Errorf("no-upper err = %v, want ErrNoUpperLayer", err)
	}
}

func TestCopyUpRejectsRelativePath(t *testing.T) {
	tmp := t.TempDir()
	g := NewFSGate(Policy{
		LowerDir: filepath.Join(tmp, "lower"),
		UpperDir: filepath.Join(tmp, "upper"),
	})
	_, err := g.CopyUp("relative")
	if !errors.Is(err, ErrEscape) {
		t.Errorf("relative err = %v, want ErrEscape", err)
	}
}

func TestCopyUpOverWhiteoutFails(t *testing.T) {
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	upper := filepath.Join(tmp, "upper")
	mustMkdirAll(t, upper)
	mustTouch(t, filepath.Join(lower, "gone"))
	if ok := mustWhiteout(t, filepath.Join(upper, "gone")); !ok {
		return
	}
	g := NewFSGate(Policy{LowerDir: lower, UpperDir: upper})
	_, err := g.CopyUp("/gone")
	if !errors.Is(err, ErrWhiteout) {
		t.Errorf("whiteout err = %v, want ErrWhiteout", err)
	}
}

func TestCopyUpConcurrentSameFileIsSafe(t *testing.T) {
	// Under -race, concurrent CopyUp on the same path must not
	// produce a data race or a half-written upper file. The mutex
	// serialises copies; O_EXCL is the defence-in-depth.
	tmp := t.TempDir()
	lower := filepath.Join(tmp, "lower")
	upper := filepath.Join(tmp, "upper")
	mustMkdirAll(t, upper)
	mustMkdirAll(t, lower)
	if err := os.WriteFile(filepath.Join(lower, "shared"),
		[]byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	g := NewFSGate(Policy{LowerDir: lower, UpperDir: upper})

	const N = 8
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := g.CopyUp("/shared"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent CopyUp: %v", err)
	}
	if got := readFileContent(t, filepath.Join(upper, "shared")); got != "content" {
		t.Errorf("upper content = %q, want content", got)
	}
}
