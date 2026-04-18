package gate

import (
	"errors"
	"path/filepath"
)

// ErrEscape is returned when a guest path resolves outside the configured
// rootfs, upper layer, and bind-mount set.
var ErrEscape = errors.New("gate: path escape blocked")

// FSGate enforces filesystem virtualization for a Policy.
//
// The gate maintains the guest's view of the filesystem:
//
//   - / is the merged view of LowerDir (read-only) and UpperDir (writable).
//   - Reads walk UpperDir first, then LowerDir.
//   - Writes copy-up from LowerDir to UpperDir on first touch, then
//     proceed against UpperDir.
//   - Deletes record whiteouts in UpperDir (opaque character devices
//     with major=0 minor=0, matching fuse-overlayfs semantics).
//
// This is an OCI-style overlay implemented entirely in userspace. We do
// not use kernel overlayfs: it is unavailable without CONFIG_USER_NS,
// which is disabled for untrusted_app on every 2026 GKI kernel.
type FSGate struct {
	policy Policy
}

// NewFSGate constructs the filesystem gate. It does not touch the
// filesystem; validation of LowerDir and UpperDir existence happens at
// Prepare time (once the runtime is wired in M2).
func NewFSGate(p Policy) *FSGate {
	return &FSGate{policy: p}
}

// Resolve translates a guest absolute path to the host-side path the
// kernel should actually see. Returns ErrEscape if the path cannot be
// contained within LowerDir, UpperDir, or one of the bind mounts.
//
// TODO(M2): real implementation. Current stub resolves only the trivial
// "guest path lives under LowerDir, no bind mounts, no upper layer"
// case. It is NOT safe for production use and exists so that downstream
// consumers (cmd/mojit-run, gate_test.go, mo-code's adapter) can import
// the package and validate their wiring against a stable API.
func (g *FSGate) Resolve(guestPath string) (hostPath string, err error) {
	if !filepath.IsAbs(guestPath) {
		return "", errors.New("gate: guest path must be absolute")
	}
	clean := filepath.Clean(guestPath)
	// TODO(M2): walk upper/ then lower/; handle bind mounts; handle
	// whiteouts; reject escapes via ".." / symlinks / TOCTOU.
	return filepath.Join(g.policy.LowerDir, clean), nil
}
