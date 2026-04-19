package gate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// ErrEscape is returned when a guest path cannot be contained within
// the configured rootfs, upper layer, and bind-mount set.
var ErrEscape = errors.New("gate: path escape blocked")

// ErrWhiteout is returned when the upper layer marks a path as
// deleted. Callers must surface this to the guest as -ENOENT and
// must NOT fall through to the lower layer.
var ErrWhiteout = errors.New("gate: path marked deleted (whiteout)")

// Layer identifies which storage layer satisfied a path resolution.
type Layer int

const (
	LayerNone  Layer = 0
	LayerBind  Layer = 1
	LayerUpper Layer = 2
	LayerLower Layer = 3
)

func (l Layer) String() string {
	switch l {
	case LayerBind:
		return "bind"
	case LayerUpper:
		return "upper"
	case LayerLower:
		return "lower"
	default:
		return "none"
	}
}

// FSGate enforces filesystem virtualization for a Policy.
//
// The gate maintains the guest's view of the filesystem:
//
//   - / is the merged view of LowerDir (read-only) and UpperDir (writable).
//   - Reads walk UpperDir first, then LowerDir.
//   - Writes copy-up from LowerDir to UpperDir on first touch, then
//     proceed against UpperDir. (Copy-up lands in M2 alongside
//     ResolveForWrite.)
//   - Deletes record whiteouts in UpperDir (character devices with
//     major=0 minor=0, matching fuse-overlayfs semantics). A whiteout
//     hides the corresponding lower entry — callers receive ErrWhiteout
//     and must translate to -ENOENT.
//
// This is an OCI-style overlay implemented entirely in userspace. We do
// not use kernel overlayfs: it is unavailable without CONFIG_USER_NS,
// which is disabled for untrusted_app on every 2026 GKI kernel.
type FSGate struct {
	policy Policy

	// cwdMu guards guestCwd. The guest cwd is updated by chdir and
	// read by every path syscall handler that encounters a relative
	// path, so contention is shaped like a mostly-reader workload —
	// an RWMutex is the right primitive.
	cwdMu    sync.RWMutex
	guestCwd string
}

// NewFSGate constructs the filesystem gate. It does not touch the
// filesystem; validation of LowerDir and UpperDir existence happens at
// Prepare time (once the runtime is wired in M2).
//
// The guest cwd starts at "/". The real ELF loader adjusts it via the
// chdir handler once the runtime is wired up; tests can drive it via
// SetGuestCwd directly.
func NewFSGate(p Policy) *FSGate {
	return &FSGate{policy: p, guestCwd: "/"}
}

// GuestCwd returns the guest process's current working directory in
// GUEST path space (not host). The guest sees "/home/developer"; the
// host backing for that path resolves through Resolve.
func (g *FSGate) GuestCwd() string {
	g.cwdMu.RLock()
	defer g.cwdMu.RUnlock()
	return g.guestCwd
}

// SetGuestCwd replaces the guest cwd. The new path must be absolute
// (the chdir handler is responsible for validating existence and
// directory-ness via Resolve + Stat before calling this).
func (g *FSGate) SetGuestCwd(guestPath string) error {
	if !filepath.IsAbs(guestPath) {
		return fmt.Errorf("%w: guest cwd must be absolute: %q", ErrEscape, guestPath)
	}
	clean := filepath.Clean(guestPath)
	g.cwdMu.Lock()
	g.guestCwd = clean
	g.cwdMu.Unlock()
	return nil
}

// AbsFromGuest returns the absolute guest-space path for a possibly
// relative guestPath, resolving relative paths against the current
// guest cwd. The result is cleaned (no `.` / `..` / duplicate slashes)
// and still guest-space — feed it to Resolve to get a host path.
//
// Handlers call this as the first step after ReadPath when the dirfd
// argument is AT_FDCWD. For explicit dirfds (resolving relative to an
// open directory handle), M3 will add ResolveAt(dirfd, path) once the
// fd table exists.
func (g *FSGate) AbsFromGuest(guestPath string) string {
	if filepath.IsAbs(guestPath) {
		return filepath.Clean(guestPath)
	}
	g.cwdMu.RLock()
	cwd := g.guestCwd
	g.cwdMu.RUnlock()
	return filepath.Clean(filepath.Join(cwd, guestPath))
}

// Resolve translates an absolute guest path to the host-side path the
// kernel should operate on, plus the layer that satisfied the lookup.
//
// Resolution order:
//  1. Bind mounts (longest guest-prefix match wins).
//  2. UpperDir (writable overlay). A whiteout entry returns ErrWhiteout.
//  3. LowerDir (read-only base).
//
// A relative guest path is rejected with ErrEscape: the ELF loader
// always supplies absolute paths, and accepting anything else would
// silently let a clever guest translate relative to the real host cwd.
//
// Note on `..`: filepath.Clean neutralises `..` at root (`/../foo` →
// `/foo`), so bind-mount `..`-traversal cannot escape a bind's
// HostPath at the path layer. Symlink-based escape inside a bind's
// HostPath is NOT yet mitigated — that requires openat2
// RESOLVE_IN_ROOT, tracked for M2's ResolveForOpen path.
func (g *FSGate) Resolve(guestPath string) (string, Layer, error) {
	if !filepath.IsAbs(guestPath) {
		return "", LayerNone, fmt.Errorf("%w: guest path must be absolute: %q",
			ErrEscape, guestPath)
	}
	clean := filepath.Clean(guestPath)

	if host, ok := g.matchBind(clean); ok {
		return host, LayerBind, nil
	}

	if g.policy.UpperDir != "" {
		upperHost := filepath.Join(g.policy.UpperDir, clean)
		if info, err := os.Lstat(upperHost); err == nil {
			if isWhiteout(info) {
				return "", LayerNone, ErrWhiteout
			}
			return upperHost, LayerUpper, nil
		}
	}

	if g.policy.LowerDir == "" {
		return "", LayerNone, errors.New("gate: no lower layer configured")
	}
	return filepath.Join(g.policy.LowerDir, clean), LayerLower, nil
}

// matchBind returns (hostPath, true) if cleanGuestPath falls inside any
// configured bind mount. Longest guest-prefix match wins so that
// nested binds resolve correctly — e.g. /work bound to /host/proj and
// /work/vendor bound to /host/vendor both active; /work/vendor/pkg.go
// resolves via the vendor bind.
func (g *FSGate) matchBind(cleanGuestPath string) (string, bool) {
	bestLen := -1
	var bestHost string

	for _, b := range g.policy.Binds {
		if b.GuestPath == "" || !filepath.IsAbs(b.GuestPath) {
			continue
		}
		bGuest := filepath.Clean(b.GuestPath)
		var sub string
		matched := false
		switch {
		case cleanGuestPath == bGuest:
			matched = true
		case bGuest == "/":
			// Root bind: everything under / matches; sub is the
			// whole path including the leading slash stripped.
			sub = strings.TrimPrefix(cleanGuestPath, "/")
			matched = true
		case strings.HasPrefix(cleanGuestPath, bGuest+"/"):
			sub = strings.TrimPrefix(cleanGuestPath, bGuest)
			matched = true
		}
		if !matched {
			continue
		}
		if len(bGuest) > bestLen {
			bestLen = len(bGuest)
			bestHost = filepath.Join(b.HostPath, sub)
		}
	}
	if bestLen < 0 {
		return "", false
	}
	return bestHost, true
}

// isWhiteout reports whether info represents an overlay whiteout
// (character device with rdev 0:0). Matches fuse-overlayfs semantics.
// The caller has already stat'd; isWhiteout never touches the FS.
func isWhiteout(info os.FileInfo) bool {
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Rdev == 0
}
