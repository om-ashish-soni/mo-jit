package gate

import (
	"errors"
	"fmt"
	"io"
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

	// copyUpMu serialises CopyUp so two writable opens of the same
	// lower file can't race to create two upper copies with disjoint
	// contents. A per-path mutex would scale better, but copy-up is
	// a cold path (once per writable lower file, for the process
	// lifetime) so a single mutex is fine.
	copyUpMu sync.Mutex
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
			if isWhiteoutPath(upperHost, info) {
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

// ErrNoUpperLayer is returned by CopyUp when the policy has no
// UpperDir configured. The openat handler uses this to distinguish a
// truly read-only overlay (surface as EROFS to the guest) from a
// transient copy-up failure (surface the underlying errno).
var ErrNoUpperLayer = errors.New("gate: copy-up requires UpperDir")

// CopyUp ensures guestPath exists on the upper layer with the same
// content as its lower-layer backing, then returns the upper host
// path. Idempotent: if guestPath is already on upper (not a
// whiteout), returns the existing upper path without re-copying.
//
// Copy-up is overlayfs's answer to "writable lower layer": before a
// write can happen, the file is promoted to upper so the lower base
// remains immutable. The gate reimplements it in userspace because
// kernel overlayfs is unavailable without CONFIG_USER_NS on the 2026
// GKI kernels we target.
//
// Coverage:
//   - Regular files: streamed io.Copy, preserving the permission
//     bits. Ownership is NOT preserved (chown needs CAP_CHOWN; the
//     upper copy is owned by the host process).
//   - Symlinks: the link itself is copied via os.Symlink. The target
//     bytes are preserved verbatim, NOT dereferenced.
//   - Everything else (directories, char/block devices, fifos,
//     sockets): not currently supported — CopyUp returns an error
//     and the caller surfaces EOPNOTSUPP.
//
// Parent directories on upper are created with mode 0o755 rather
// than mirroring the lower parent's mode, since mirroring a
// restrictive lower mode could yield an upper dir the guest can't
// traverse.
func (g *FSGate) CopyUp(guestPath string) (string, error) {
	if g.policy.UpperDir == "" {
		return "", ErrNoUpperLayer
	}
	if !filepath.IsAbs(guestPath) {
		return "", fmt.Errorf("%w: copy-up needs absolute path: %q",
			ErrEscape, guestPath)
	}
	clean := filepath.Clean(guestPath)
	upperPath := filepath.Join(g.policy.UpperDir, clean)

	g.copyUpMu.Lock()
	defer g.copyUpMu.Unlock()

	if info, err := os.Lstat(upperPath); err == nil {
		if isWhiteoutPath(upperPath, info) {
			return "", fmt.Errorf("%w: cannot copy over whiteout: %q",
				ErrWhiteout, guestPath)
		}
		return upperPath, nil
	}

	if g.policy.LowerDir == "" {
		return "", fmt.Errorf("gate: no lower layer to copy from: %q", guestPath)
	}
	lowerPath := filepath.Join(g.policy.LowerDir, clean)
	srcInfo, err := os.Lstat(lowerPath)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(upperPath), 0o755); err != nil {
		return "", err
	}

	switch {
	case srcInfo.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(lowerPath)
		if err != nil {
			return "", err
		}
		if err := os.Symlink(target, upperPath); err != nil {
			return "", err
		}
	case srcInfo.Mode().IsRegular():
		if err := copyRegularFile(lowerPath, upperPath, srcInfo.Mode().Perm()); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("gate: copy-up unsupported for %q (mode %v)",
			guestPath, srcInfo.Mode())
	}

	return upperPath, nil
}

// copyRegularFile streams src to dst with O_EXCL to refuse clobbering
// an existing upper file. The caller's copyUpMu serialises callers,
// but O_EXCL guards against a racing host-side create we did not
// expect.
func copyRegularFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

// whiteoutXattr is the name of the xattr fuse-overlayfs stamps on a
// placeholder file to mark it as a whiteout. We use it as the
// fallback form whenever the preferred char-device-with-rdev-0
// format is unavailable because CAP_MKNOD is missing — which is the
// permanent case for untrusted_app on 2026 GKI kernels.
const whiteoutXattr = "user.overlay.whiteout"

// isWhiteout reports whether info alone unambiguously represents an
// overlay whiteout. Today that means the classic char-device-with-rdev-0
// form; the xattr form is detected via isWhiteoutPath, which also needs
// the host path to query the xattr.
func isWhiteout(info os.FileInfo) bool {
	if info == nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Rdev == 0
}

// isWhiteoutPath is isWhiteout augmented with the xattr fallback: a
// size-zero regular file stamped with user.overlay.whiteout is also
// a whiteout. Size-zero regulars are rare on a working upper layer
// (a real touched file is immediately populated) so the extra
// Getxattr on the hot path is negligible.
func isWhiteoutPath(path string, info os.FileInfo) bool {
	if isWhiteout(info) {
		return true
	}
	if info == nil || !info.Mode().IsRegular() || info.Size() != 0 {
		return false
	}
	buf := make([]byte, 1)
	_, err := syscall.Getxattr(path, whiteoutXattr, buf)
	return err == nil
}

// writeWhiteout marks path as a deleted overlay entry. Prefers the
// char-device-with-rdev-0 form (CAP_MKNOD required); falls back to a
// regular file tagged with user.overlay.whiteout when mknod is
// rejected by the kernel. The dual format means mo-jit works both in
// privileged CI runners and on unrooted Android where CAP_MKNOD is
// never granted to application code.
//
// The parent directory must already exist; the caller is responsible
// for MkdirAll (mirroring what os.Remove would require).
func writeWhiteout(path string) error {
	if err := syscall.Mknod(path, syscall.S_IFCHR|0o600, 0); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) &&
		!errors.Is(err, syscall.ENOSYS) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_ = f.Close()
	if err := syscall.Setxattr(path, whiteoutXattr, []byte{'y'}, 0); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
