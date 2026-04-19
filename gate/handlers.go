package gate

import (
	"errors"
	"os"
	"path/filepath"
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

// handleReadLinkAt services readlinkat(dirfd, pathname, buf, bufsiz)
// (NR=78).
//
// Kernel semantics: on success, returns the number of BYTES placed in
// buf (NOT NUL-terminated, possibly truncated). If len(target) >
// bufsiz, only bufsiz bytes are written and the truncated byte count
// is returned — this is NOT an error per Linux readlinkat(2).
//
// The gate reads the link target via os.Readlink on the resolved host
// path, which returns the raw bytes the link stores on disk. That is
// the correct guest-visible content: a symlink like "../bar" is
// copied verbatim, and its interpretation happens on the guest's
// next path syscall (which will absolute-ify and FSGate-resolve it).
func handleReadLinkAt(d *Dispatcher, regs *Regs) Verdict {
	hostPath, _, err := resolveGuestPathAt(d, int64(regs.X[0]), regs.X[1])
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	bufPtr := regs.X[2]
	bufSiz := regs.X[3]
	if bufSiz == 0 {
		regs.X[0] = EncodeErrno(syscall.EINVAL)
		return VerdictHandled
	}

	target, err := os.Readlink(hostPath)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	payload := []byte(target)
	if uint64(len(payload)) > bufSiz {
		payload = payload[:bufSiz]
	}
	if len(payload) > 0 {
		if err := d.Mem.WriteBytes(bufPtr, payload); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}
	regs.X[0] = uint64(len(payload))
	return VerdictHandled
}

// openWritableMask captures every bit that means "this open wants to
// write, or wants the kernel to mutate the filesystem on the way in".
// O_RDONLY (=0) has no bits set; any of these flags implies the open
// hits an upper-layer path.
const openWritableMask = syscall.O_WRONLY |
	syscall.O_RDWR |
	syscall.O_CREAT |
	syscall.O_TRUNC |
	syscall.O_APPEND

// handleOpenAt services openat(dirfd, pathname, flags, mode) (NR=56).
//
// Currently supported:
//   - dirfd == AT_FDCWD, or a path that is absolute (dirfd ignored
//     per Linux). Dir-relative paths with a real dirfd return ENOSYS
//     until openat2(RESOLVE_IN_ROOT) is wired in M3 — we cannot safely
//     let the host kernel resolve a relative path against a host fd
//     whose directory sits inside the lower layer, because `..`
//     traversal would escape the overlay.
//   - read-only opens against any layer.
//   - writable opens (O_WRONLY / O_RDWR / O_CREAT / O_TRUNC / O_APPEND)
//     that resolve to the UPPER or BIND layer.
//
// Not yet supported:
//   - Writable opens that resolve to LOWER — requires copy-up. We
//     return EROFS so callers either stop or upper-promote their file
//     explicitly. A later commit will implement copy-up.
//   - O_TMPFILE. Returns EOPNOTSUPP for now.
func handleOpenAt(d *Dispatcher, regs *Regs) Verdict {
	path, err := d.Paths.ReadPath(regs.X[1], MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	flags := int(regs.X[2])
	mode := uint32(regs.X[3])
	dirfd := int64(regs.X[0])

	var absGuest string
	switch {
	case filepath.IsAbs(path):
		absGuest = filepath.Clean(path)
	case dirfd == int64(atFDCWD):
		absGuest = d.FS.AbsFromGuest(path)
	default:
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}

	hostPath, layer, err := d.FS.Resolve(absGuest)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	writable := flags&openWritableMask != 0
	if writable && layer == LayerLower {
		// Without an UpperDir the overlay is truly read-only; there's
		// nowhere to put the writable copy.
		if d.FS.policy.UpperDir == "" {
			regs.X[0] = EncodeErrno(syscall.EROFS)
			return VerdictHandled
		}
		switch _, statErr := os.Lstat(hostPath); {
		case statErr == nil:
			// File exists on lower — promote it to upper before the
			// kernel open touches it, so the write lands on upper.
			upperPath, err := d.FS.CopyUp(absGuest)
			if err != nil {
				regs.X[0] = EncodeErrno(err)
				return VerdictHandled
			}
			hostPath = upperPath
		case os.IsNotExist(statErr) && flags&syscall.O_CREAT != 0:
			// Fresh create: point directly at the upper layer.
			// Parent directories must already exist on upper (callers
			// mkdirat first); we don't implicit-MkdirAll because that
			// would hide guest path bugs.
			hostPath = filepath.Join(d.FS.policy.UpperDir, absGuest)
		}
		// Any other stat error (EACCES etc.) falls through to the
		// kernel open below with the lower path — it will surface
		// the same errno naturally.
	}

	hostFd, err := syscall.Open(hostPath, flags, mode)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	guestFd := d.FDs.Allocate(hostFd)
	regs.X[0] = uint64(guestFd)
	return VerdictHandled
}

// handleRead services read(fd, buf, count) (NR=63).
//
// The kernel does the actual I/O against the host fd; the gate's job
// is to translate the guest fd, read into a Go-owned scratch buffer,
// and copy that buffer into the guest's address space. Copying via
// MemWriter instead of handing the kernel a raw guest pointer keeps
// a consistent story with the rest of the *at handlers: the kernel
// never sees guest pointers, only gate-owned memory.
//
// count == 0 short-circuits to 0 without touching MemWriter — Linux
// read(2) defines count=0 as a successful no-op returning 0.
func handleRead(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	bufPtr := regs.X[1]
	count := regs.X[2]

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}

	if count == 0 {
		regs.X[0] = 0
		return VerdictHandled
	}

	buf := make([]byte, count)
	n, err := syscall.Read(hostFd, buf)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if n > 0 {
		if err := d.Mem.WriteBytes(bufPtr, buf[:n]); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}
	regs.X[0] = uint64(n)
	return VerdictHandled
}

// handleWrite services write(fd, buf, count) (NR=64).
//
// Mirror of handleRead. count == 0 is a successful no-op. Short
// writes (n < count) propagate to the guest as-is — it's the guest's
// job to loop if it cares.
func handleWrite(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	bufPtr := regs.X[1]
	count := regs.X[2]

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}

	if count == 0 {
		regs.X[0] = 0
		return VerdictHandled
	}

	buf, err := d.MemR.ReadBytes(bufPtr, int(count))
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	n, err := syscall.Write(hostFd, buf)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = uint64(n)
	return VerdictHandled
}

// handleMkdirAt services mkdirat(dirfd, pathname, mode) (NR=34).
//
// aarch64 layout:
//
//	x0 = dirfd, x1 = pathname, x2 = mode
//
// Semantics:
//   - No UpperDir: EROFS. Everything else assumes a writable overlay.
//   - Path already resolvable (lower OR non-whiteout upper): EEXIST,
//     matching Linux mkdir(2).
//   - Whiteout on upper: the guest sees a freshly-created directory,
//     so we remove the whiteout first and then mkdir — otherwise
//     os.Mkdir fails with EEXIST against the whiteout file entry.
//   - Parent chain missing on upper but present on lower: we
//     os.MkdirAll the upper parents with 0o755 before creating the
//     leaf, so stat of the new dir hits upper. This is the directory
//     analogue of copy-up for files — we're promoting the enclosing
//     namespace to upper so the new entry is visible to the guest.
//
// Missing parents that don't exist on lower either will surface as
// ENOENT from MkdirAll's first Mkdir (wrapped by errnoFor → ENOENT).
func handleMkdirAt(d *Dispatcher, regs *Regs) Verdict {
	dirfd := int64(regs.X[0])
	pathPtr := regs.X[1]
	mode := uint32(regs.X[2])

	if d.FS.policy.UpperDir == "" {
		regs.X[0] = EncodeErrno(syscall.EROFS)
		return VerdictHandled
	}

	path, err := d.Paths.ReadPath(pathPtr, MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	var absGuest string
	switch {
	case filepath.IsAbs(path):
		absGuest = filepath.Clean(path)
	case dirfd == int64(atFDCWD):
		absGuest = d.FS.AbsFromGuest(path)
	default:
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}

	upperPath := filepath.Join(d.FS.policy.UpperDir, absGuest)

	// Resolve tells us whether any layer CLAIMS this path (ErrWhiteout
	// if hidden, nil otherwise — but nil does NOT prove existence on
	// lower; Resolve joins paths without statting). We still need to
	// probe both layers for a real inode before deciding EEXIST.
	hostPath, _, rerr := d.FS.Resolve(absGuest)
	switch {
	case errors.Is(rerr, ErrWhiteout):
		if err := os.Remove(upperPath); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		// Whiteout removed — treat path as free and fall through.
	case rerr != nil:
		regs.X[0] = EncodeErrno(rerr)
		return VerdictHandled
	default:
		if _, err := os.Lstat(hostPath); err == nil {
			regs.X[0] = EncodeErrno(syscall.EEXIST)
			return VerdictHandled
		}
	}

	if err := os.MkdirAll(filepath.Dir(upperPath), 0o755); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if err := os.Mkdir(upperPath, os.FileMode(mode&0o7777)); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleSymlinkAt services symlinkat(target, newdirfd, linkpath) (NR=36).
//
// aarch64 layout:
//
//	x0 = target (const char *)
//	x1 = newdirfd
//	x2 = linkpath (const char *)
//
// Target is copied into the link verbatim — the kernel never walks it
// at creation time. Resolution happens lazily on each path syscall
// that traverses the link, at which point FSGate.Resolve re-enters
// for the link's target on the guest's behalf.
//
// Semantics:
//   - No UpperDir: EROFS.
//   - linkpath already present on either layer: EEXIST.
//   - Parent chain missing on upper but present on lower: we MkdirAll
//     upper parents (same pattern as mkdirat), so subsequent stats of
//     the link resolve through upper.
//   - Whiteout at linkpath: remove it, then create the symlink.
//     Matches mkdirat's whiteout handling.
func handleSymlinkAt(d *Dispatcher, regs *Regs) Verdict {
	targetPtr := regs.X[0]
	newdirfd := int64(regs.X[1])
	linkPtr := regs.X[2]

	if d.FS.policy.UpperDir == "" {
		regs.X[0] = EncodeErrno(syscall.EROFS)
		return VerdictHandled
	}

	target, err := d.Paths.ReadPath(targetPtr, MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	linkPath, err := d.Paths.ReadPath(linkPtr, MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	// Empty target would create a link to "" — the kernel rejects
	// this with ENOENT.
	if target == "" {
		regs.X[0] = EncodeErrno(syscall.ENOENT)
		return VerdictHandled
	}

	var absGuest string
	switch {
	case filepath.IsAbs(linkPath):
		absGuest = filepath.Clean(linkPath)
	case newdirfd == int64(atFDCWD):
		absGuest = d.FS.AbsFromGuest(linkPath)
	default:
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}

	upperPath := filepath.Join(d.FS.policy.UpperDir, absGuest)

	hostPath, _, rerr := d.FS.Resolve(absGuest)
	switch {
	case errors.Is(rerr, ErrWhiteout):
		if err := os.Remove(upperPath); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	case rerr != nil:
		regs.X[0] = EncodeErrno(rerr)
		return VerdictHandled
	default:
		if _, err := os.Lstat(hostPath); err == nil {
			regs.X[0] = EncodeErrno(syscall.EEXIST)
			return VerdictHandled
		}
	}

	if err := os.MkdirAll(filepath.Dir(upperPath), 0o755); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if err := os.Symlink(target, upperPath); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleNewFStatAt services newfstatat(dirfd, pathname, statbuf, flags)
// (NR=79). Modern glibc/musl route both the `stat` and `lstat` libc
// entry points through this syscall; libc's `fstat` also funnels here
// via AT_EMPTY_PATH on kernels new enough to advertise it.
//
// aarch64 register layout:
//
//	x0 = dirfd, x1 = pathname, x2 = statbuf, x3 = flags
//
// Relevant flags:
//   - AT_SYMLINK_NOFOLLOW: stat the link itself, not the target.
//   - AT_EMPTY_PATH: if pathname == "", stat the file referred to by
//     dirfd. We translate dirfd through FDTable so guest fds stay in
//     guest space.
//   - AT_NO_AUTOMOUNT: mo-jit doesn't automount; silently ignored.
//
// The stat buffer is always written in the aarch64 kernel wire format
// (packStatAarch64), even when the host is x86_64 — the guest is
// always arm64 regardless of test host.
func handleNewFStatAt(d *Dispatcher, regs *Regs) Verdict {
	dirfd := int64(regs.X[0])
	pathPtr := regs.X[1]
	bufPtr := regs.X[2]
	flags := int(regs.X[3])

	path, err := d.Paths.ReadPath(pathPtr, MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	if path == "" && flags&atEmptyPath == 0 {
		// Linux kernel: empty path without AT_EMPTY_PATH is ENOENT.
		regs.X[0] = EncodeErrno(syscall.ENOENT)
		return VerdictHandled
	}

	var st syscall.Stat_t
	switch {
	case path == "" && flags&atEmptyPath != 0:
		// Stat the fd itself. Translate the guest fd, never hand it
		// to the kernel directly.
		hostFd, ok := d.FDs.Resolve(int(dirfd))
		if !ok {
			regs.X[0] = EncodeErrno(syscall.EBADF)
			return VerdictHandled
		}
		if err := syscall.Fstat(hostFd, &st); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	default:
		var absGuest string
		switch {
		case filepath.IsAbs(path):
			absGuest = filepath.Clean(path)
		case dirfd == int64(atFDCWD):
			absGuest = d.FS.AbsFromGuest(path)
		default:
			regs.X[0] = EncodeErrno(syscall.ENOSYS)
			return VerdictHandled
		}
		hostPath, _, err := d.FS.Resolve(absGuest)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		// We've already resolved absGuest to a concrete host path, so
		// stat/lstat on the host kernel side is sufficient; AT_EMPTY_PATH
		// is handled by the other case, AT_NO_AUTOMOUNT is a no-op for
		// us, leaving only AT_SYMLINK_NOFOLLOW.
		var statErr error
		if flags&atSymlinkNoFollow != 0 {
			statErr = syscall.Lstat(hostPath, &st)
		} else {
			statErr = syscall.Stat(hostPath, &st)
		}
		if statErr != nil {
			regs.X[0] = EncodeErrno(statErr)
			return VerdictHandled
		}
	}

	if bufPtr == 0 {
		regs.X[0] = EncodeErrno(syscall.EFAULT)
		return VerdictHandled
	}
	if err := d.Mem.WriteBytes(bufPtr, packStatAarch64(&st)); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleFStat services fstat(fd, statbuf) (NR=80). Still present in
// the aarch64 table for old libc's that predate AT_EMPTY_PATH.
func handleFStat(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	bufPtr := regs.X[1]

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(hostFd, &st); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if bufPtr == 0 {
		regs.X[0] = EncodeErrno(syscall.EFAULT)
		return VerdictHandled
	}
	if err := d.Mem.WriteBytes(bufPtr, packStatAarch64(&st)); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleClose services close(fd) (NR=57).
//
// Releases the guest fd from the table, then close(2)s the backing
// host fd. Errors from close(2) (EIO on NFS etc.) are propagated to
// the guest even though the fd is already gone on our side — this
// matches Linux semantics, where close can report a deferred I/O
// error but the fd is still freed.
func handleClose(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	hostFd, ok := d.FDs.Close(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	if err := syscall.Close(hostFd); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}
