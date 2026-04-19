package gate

import (
	"os"
	"syscall"
)

// atFDCWD mirrors Linux's AT_FDCWD (-100 on every arch), the magic
// dirfd that means "resolve relative paths against the process cwd".
// Handlers compare guest dirfd against this before consulting the fd
// table (landing in M3 with openat).
const atFDCWD = -100

// handleChDir services `chdir(const char *path)` (aarch64 NR=49).
//
// Contract (Linux chdir(2)):
//   - On success: 0 in x0, process cwd updated.
//   - On failure: -errno in x0.
//
// The gate reimplements chdir in user-space because the kernel's cwd
// is the host's cwd, not the guest's: we maintain a separate virtual
// cwd in FSGate and translate on every subsequent path syscall.
//
// Validation order:
//  1. ReadPath from guest memory (EFAULT on fault, ENAMETOOLONG on
//     oversize).
//  2. Absolute-ify via FSGate.AbsFromGuest (merges with current cwd
//     when the guest passes a relative path).
//  3. Resolve to a host path. ErrEscape / ErrWhiteout surface as
//     ENOENT; other errors translate via errnoFor.
//  4. Stat the host path. Missing = ENOENT; not-a-directory = ENOTDIR.
//  5. Commit the new guest cwd.
//
// The handler never touches the host process's own cwd — gum may be
// servicing many guest threads, all with their own virtual cwds, so
// mutating the host cwd would corrupt them.
func handleChDir(d *Dispatcher, regs *Regs) Verdict {
	path, err := d.Paths.ReadPath(regs.X[0], MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	absGuest := d.FS.AbsFromGuest(path)

	hostPath, _, err := d.FS.Resolve(absGuest)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	info, err := os.Stat(hostPath)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if !info.IsDir() {
		regs.X[0] = EncodeErrno(syscall.ENOTDIR)
		return VerdictHandled
	}

	if err := d.FS.SetGuestCwd(absGuest); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// resolveGuestPathAt turns a (dirfd, guest path pointer) pair into a
// host path the kernel can operate on. It handles the two shapes every
// *at syscall uses:
//
//   - dirfd == AT_FDCWD: the guest expects the path resolved against
//     its cwd. We read the path, merge with FSGate.GuestCwd if it's
//     relative, then Resolve to a host path.
//   - dirfd == any other value: the guest is naming a directory fd.
//     The fd table lands in M3; until then we refuse with EBADF so
//     the guest gets a deterministic error rather than silently
//     resolving against the host cwd (which would leak host paths).
//
// The caller chooses which X[] slot holds the dirfd and which holds
// the path pointer — for every *at syscall in the aarch64 table,
// dirfd is in x0 and pathname is in x1.
//
// Returns (hostPath, absGuestPath, "" on success) or ("", "", errno
// ready to pack into X[0] via EncodeErrno). absGuestPath is returned
// so handlers that also need to mutate guest state (mkdirat's
// copy-up, unlinkat's whiteout) can address the guest-space path
// consistently with other FSGate calls.
func resolveGuestPathAt(d *Dispatcher, dirfd int64, pathPtr uint64) (hostPath, absGuestPath string, err error) {
	if dirfd != int64(atFDCWD) {
		return "", "", syscall.EBADF
	}
	path, err := d.Paths.ReadPath(pathPtr, MaxPathLen)
	if err != nil {
		return "", "", err
	}
	absGuest := d.FS.AbsFromGuest(path)
	host, _, err := d.FS.Resolve(absGuest)
	if err != nil {
		return "", "", err
	}
	return host, absGuest, nil
}

// handleFAccessAt services faccessat(dirfd, pathname, mode) (NR=48)
// AND faccessat2(dirfd, pathname, mode, flags) (NR=439). The two
// differ only in whether a flags argument is present; faccessat2 is
// strictly more general (AT_EACCESS, AT_SYMLINK_NOFOLLOW).
//
// On aarch64:
//
//	x0 = dirfd, x1 = pathname, x2 = mode, [x3 = flags for NR=439]
//
// The host kernel's syscall.Faccessat handles the emulation of
// AT_EACCESS and AT_SYMLINK_NOFOLLOW on kernels without native
// faccessat2 — the ret path is identical either way.
func handleFAccessAt(d *Dispatcher, regs *Regs) Verdict {
	hostPath, _, err := resolveGuestPathAt(d, int64(regs.X[0]), regs.X[1])
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	mode := uint32(regs.X[2])
	flags := 0
	if regs.NR == SysFAccessAt2 {
		flags = int(regs.X[3])
	}

	if err := syscall.Faccessat(atFDCWD, hostPath, mode, flags); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleGetCwd services sys_getcwd(buf, size) (NR=17).
//
// Kernel semantics (NOT libc): returns the byte length of the path
// INCLUDING the trailing NUL in x0 on success; -errno on failure.
// Errors: ERANGE if size is too small, EFAULT if buf cannot be
// written. The glibc/musl wrapper turns this into a char* pointer.
//
// Crucially, the handler returns the GUEST cwd (FSGate.GuestCwd), not
// the host process cwd: the host cwd belongs to the frida-gum host
// runtime and is meaningless to the guest.
func handleGetCwd(d *Dispatcher, regs *Regs) Verdict {
	bufPtr := regs.X[0]
	size := regs.X[1]

	cwd := d.FS.GuestCwd()
	// The kernel writes the path plus a trailing NUL. Allocate a new
	// slice so we own the memory and the NUL is guaranteed; cwd may be
	// interned in FSGate.
	out := make([]byte, len(cwd)+1)
	copy(out, cwd)
	// out[len(cwd)] is already zero from make.

	if uint64(len(out)) > size {
		regs.X[0] = EncodeErrno(syscall.ERANGE)
		return VerdictHandled
	}
	if bufPtr == 0 {
		regs.X[0] = EncodeErrno(syscall.EFAULT)
		return VerdictHandled
	}
	if err := d.Mem.WriteBytes(bufPtr, out); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = uint64(len(out))
	return VerdictHandled
}
