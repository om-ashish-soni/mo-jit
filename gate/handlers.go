package gate

import (
	"os"
	"syscall"
)

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
