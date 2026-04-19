package gate

import (
	"errors"
	"sync"
	"testing"
)

func TestFSGateDefaultGuestCwdIsRoot(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})
	if cwd := g.GuestCwd(); cwd != "/" {
		t.Errorf("default guest cwd = %q, want %q", cwd, "/")
	}
}

func TestFSGateSetGuestCwdAcceptsAbsolute(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})
	if err := g.SetGuestCwd("/home/developer"); err != nil {
		t.Fatalf("SetGuestCwd: %v", err)
	}
	if cwd := g.GuestCwd(); cwd != "/home/developer" {
		t.Errorf("GuestCwd after set = %q, want /home/developer", cwd)
	}
}

func TestFSGateSetGuestCwdCleansPath(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})
	if err := g.SetGuestCwd("/home/./developer/../developer/"); err != nil {
		t.Fatalf("SetGuestCwd: %v", err)
	}
	if cwd := g.GuestCwd(); cwd != "/home/developer" {
		t.Errorf("GuestCwd = %q, want cleaned /home/developer", cwd)
	}
}

func TestFSGateSetGuestCwdRejectsRelative(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})
	err := g.SetGuestCwd("subdir")
	if !errors.Is(err, ErrEscape) {
		t.Fatalf("want ErrEscape for relative cwd, got %v", err)
	}
	if cwd := g.GuestCwd(); cwd != "/" {
		t.Errorf("failed SetGuestCwd must not mutate cwd, got %q", cwd)
	}
}

func TestFSGateAbsFromGuestAbsoluteCleans(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})
	got := g.AbsFromGuest("/etc/./foo/../hostname")
	if got != "/etc/hostname" {
		t.Errorf("AbsFromGuest cleaning: got %q, want /etc/hostname", got)
	}
}

func TestFSGateAbsFromGuestRelativeUsesCwd(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})
	if err := g.SetGuestCwd("/home/developer"); err != nil {
		t.Fatal(err)
	}
	got := g.AbsFromGuest("src/main.go")
	if got != "/home/developer/src/main.go" {
		t.Errorf("AbsFromGuest joined: got %q, want /home/developer/src/main.go", got)
	}
}

func TestFSGateAbsFromGuestRelativeWithDotDot(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})
	if err := g.SetGuestCwd("/home/developer/project"); err != nil {
		t.Fatal(err)
	}
	got := g.AbsFromGuest("../other/file")
	if got != "/home/developer/other/file" {
		t.Errorf("AbsFromGuest with ..: got %q, want /home/developer/other/file", got)
	}
}

func TestFSGateAbsFromGuestRelativeDotDotCannotEscapeRoot(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})
	// cwd is "/" by default; "../../etc/passwd" must clean to "/etc/passwd".
	got := g.AbsFromGuest("../../etc/passwd")
	if got != "/etc/passwd" {
		t.Errorf("AbsFromGuest must neutralise .. at root: got %q", got)
	}
}

// Resolve must still reject relative input directly — the absolute-ification
// step lives in AbsFromGuest / the chdir handler, not in Resolve.
func TestFSGateResolveStillRejectsRelative(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})
	if err := g.SetGuestCwd("/home/developer"); err != nil {
		t.Fatal(err)
	}
	_, _, err := g.Resolve("foo")
	if !errors.Is(err, ErrEscape) {
		t.Errorf("Resolve(relative) must return ErrEscape even with non-root cwd, got %v", err)
	}
}

// Concurrent SetGuestCwd and AbsFromGuest must not race.
// Run under `go test -race` to catch data races.
func TestFSGateCwdConcurrentAccess(t *testing.T) {
	g := NewFSGate(Policy{LowerDir: "/tmp/lower"})

	const N = 200
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			cwds := []string{"/a", "/b/c", "/d/e/f"}
			_ = g.SetGuestCwd(cwds[i%len(cwds)])
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			_ = g.GuestCwd()
			_ = g.AbsFromGuest("relative/path")
		}
	}()
	wg.Wait()
}
