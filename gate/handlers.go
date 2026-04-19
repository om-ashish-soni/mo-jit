package gate

import (
	"encoding/binary"
	"errors"
	"io"
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

// atRemoveDir mirrors Linux's AT_REMOVEDIR flag: when set on
// unlinkat, the syscall behaves like rmdir(2) instead of unlink(2).
const atRemoveDir = 0x200

// renameat2 flags.
const (
	renameNoReplace = 0x1 // RENAME_NOREPLACE — fail with EEXIST if dst present
	renameExchange  = 0x2 // RENAME_EXCHANGE — atomic swap of two entries
	renameWhiteout  = 0x4 // RENAME_WHITEOUT — special kernel-internal form
)

// handleRenameAt services renameat(olddirfd, oldpath, newdirfd, newpath)
// (NR=38) AND renameat2(..., flags) (NR=276). The two share this
// single handler; renameat2 differs only by carrying RENAME_*
// flags in x4. apt/dpkg/git all lean on rename being atomic for
// crash-safe config writes, so this is a high-value handler even
// though the cross-layer semantics are genuinely tricky.
//
// aarch64 layout:
//
//	x0 = olddirfd, x1 = oldpath,
//	x2 = newdirfd, x3 = newpath,
//	[x4 = flags (renameat2 only)]
//
// Layer handling:
//   - src on upper (independent of lower): os.Rename upper → upper.
//     If lower ALSO has src, write a whiteout at the old location
//     so the lower entry stays hidden from the guest.
//   - src on lower only: copy lower content into the dst's upper
//     path (regular file → streamed copy preserving perm bits;
//     symlink → copy target bytes verbatim). Then whiteout the old
//     location so the guest stops seeing src there.
//   - dst on upper (non-whiteout): overwritten by os.Rename on the
//     upper-on-upper path; explicit os.Remove + then-copy-or-move
//     on the cross-layer path.
//   - dst is a whiteout: treat as absent, remove the whiteout so
//     the rename doesn't EEXIST against the char-dev marker.
//
// Flags:
//   - RENAME_NOREPLACE: EEXIST if dst is visible to the guest (upper
//     non-whiteout OR lower-not-masked). Whiteout-masked lower is
//     NOT considered existing.
//   - RENAME_EXCHANGE: atomic swap. ENOSYS for now — overlay
//     semantics for EXCHANGE need both entries promoted to upper
//     with atomic os.Rename, which Go's stdlib doesn't directly
//     expose. Tracked.
//   - RENAME_WHITEOUT: kernel-internal, ENOSYS.
//
// Directory renames: same-layer (src on upper) is supported via
// os.Rename. Cross-layer dir rename returns EXDEV — the correct POSIX
// errno for "try a userspace copy", deferring the recursive copy-up
// to a follow-up. apt/dpkg/git only rename files atomically, never
// directories, so this ordering is fine for real workloads.
//
// Not modelled yet: whiteout of a source DIR leaves children visible
// through lower on descendant path lookups, because FSGate.Resolve
// operates on the full clean path and doesn't walk parents checking
// for whiteout. That's an M2-level bug shared by every delete-shaped
// handler; tracked for the opaque-dir follow-up.
func handleRenameAt(d *Dispatcher, regs *Regs) Verdict {
	oldDirfd := int64(regs.X[0])
	oldPtr := regs.X[1]
	newDirfd := int64(regs.X[2])
	newPtr := regs.X[3]
	flags := 0
	if regs.NR == SysRenameAt2 {
		flags = int(regs.X[4])
	}

	if d.FS.policy.UpperDir == "" {
		regs.X[0] = EncodeErrno(syscall.EROFS)
		return VerdictHandled
	}
	if flags&(renameExchange|renameWhiteout) != 0 {
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}

	oldPath, err := d.Paths.ReadPath(oldPtr, MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	newPath, err := d.Paths.ReadPath(newPtr, MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	oldAbs, ok := absolutiseAt(d, oldDirfd, oldPath)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}
	newAbs, ok := absolutiseAt(d, newDirfd, newPath)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}

	if oldAbs == newAbs {
		// rename(x, x) is a no-op on Linux.
		regs.X[0] = 0
		return VerdictHandled
	}

	upperDir := d.FS.policy.UpperDir
	lowerDir := d.FS.policy.LowerDir
	oldUpper := filepath.Join(upperDir, oldAbs)
	newUpper := filepath.Join(upperDir, newAbs)
	var oldLower, newLower string
	if lowerDir != "" {
		oldLower = filepath.Join(lowerDir, oldAbs)
		newLower = filepath.Join(lowerDir, newAbs)
	}

	oldInfo, oldUpperErr := os.Lstat(oldUpper)
	oldIsWhiteout := oldUpperErr == nil && isWhiteoutPath(oldUpper, oldInfo)
	oldOnUpper := oldUpperErr == nil && !oldIsWhiteout

	var oldLowerInfo os.FileInfo
	oldOnLower := false
	if oldLower != "" {
		if li, err := os.Lstat(oldLower); err == nil {
			oldLowerInfo = li
			oldOnLower = true
		}
	}

	// Guest's view of src: present iff upper has it OR (lower has it
	// AND upper doesn't mask it with a whiteout).
	srcVisible := oldOnUpper || (oldOnLower && !oldIsWhiteout)
	if !srcVisible {
		regs.X[0] = EncodeErrno(syscall.ENOENT)
		return VerdictHandled
	}

	newInfo, newUpperErr := os.Lstat(newUpper)
	newIsWhiteout := newUpperErr == nil && isWhiteoutPath(newUpper, newInfo)
	newOnUpper := newUpperErr == nil && !newIsWhiteout
	newOnLower := false
	if newLower != "" {
		if _, err := os.Lstat(newLower); err == nil {
			newOnLower = true
		}
	}
	dstVisible := newOnUpper || (newOnLower && !newIsWhiteout)

	if flags&renameNoReplace != 0 && dstVisible {
		regs.X[0] = EncodeErrno(syscall.EEXIST)
		return VerdictHandled
	}

	var srcInfo os.FileInfo
	if oldOnUpper {
		srcInfo = oldInfo
	} else {
		srcInfo = oldLowerInfo
	}

	// Cross-layer dir rename would need a recursive copy-up; EXDEV
	// tells userspace "fall back to copy + unlink".
	if srcInfo.IsDir() && !oldOnUpper {
		regs.X[0] = EncodeErrno(syscall.EXDEV)
		return VerdictHandled
	}

	if err := os.MkdirAll(filepath.Dir(newUpper), 0o755); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	// Clear any whiteout at dst so os.Rename / os.Symlink / the
	// copyRegularFile helper below don't EEXIST against the char-dev
	// marker.
	if newIsWhiteout {
		if err := os.Remove(newUpper); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}

	if oldOnUpper {
		// Same-layer rename. os.Rename gives us atomicity on the
		// upper fs, which is what apt's .dpkg-new → target dance
		// actually cares about.
		if err := os.Rename(oldUpper, newUpper); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	} else {
		// src is lower-only. Materialise content at newUpper.
		switch {
		case srcInfo.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(oldLower)
			if err != nil {
				regs.X[0] = EncodeErrno(err)
				return VerdictHandled
			}
			// If dst upper has something non-whiteout, remove it
			// first — os.Symlink won't overwrite.
			if newOnUpper {
				if err := os.Remove(newUpper); err != nil {
					regs.X[0] = EncodeErrno(err)
					return VerdictHandled
				}
			}
			if err := os.Symlink(target, newUpper); err != nil {
				regs.X[0] = EncodeErrno(err)
				return VerdictHandled
			}
		case srcInfo.Mode().IsRegular():
			// copyRegularFile uses O_EXCL, so overwrite requires
			// clearing the existing upper entry first.
			if newOnUpper {
				if err := os.Remove(newUpper); err != nil {
					regs.X[0] = EncodeErrno(err)
					return VerdictHandled
				}
			}
			if err := copyRegularFile(oldLower, newUpper, srcInfo.Mode().Perm()); err != nil {
				regs.X[0] = EncodeErrno(err)
				return VerdictHandled
			}
		default:
			regs.X[0] = EncodeErrno(syscall.EOPNOTSUPP)
			return VerdictHandled
		}
	}

	// Hide the old location from the guest if lower still has it
	// there. No whiteout needed if src was upper-only — the rename
	// already cleared the old upper entry.
	if oldOnLower {
		if err := os.MkdirAll(filepath.Dir(oldUpper), 0o755); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		// oldUpper may still exist when src was on BOTH layers: the
		// os.Rename moved upper-src away, so the path is free for a
		// whiteout. If src was upper-only, oldOnLower is false and we
		// don't enter this branch.
		if err := writeWhiteout(oldUpper); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}

	regs.X[0] = 0
	return VerdictHandled
}

// absolutiseAt is the small DRY extraction shared by handlers that
// need (dirfd, path) → absolute guest path with the same dir-relative-
// real-dirfd-is-ENOSYS rule every other *at syscall uses.
func absolutiseAt(d *Dispatcher, dirfd int64, path string) (string, bool) {
	switch {
	case filepath.IsAbs(path):
		return filepath.Clean(path), true
	case dirfd == int64(atFDCWD):
		return d.FS.AbsFromGuest(path), true
	default:
		return "", false
	}
}

// handleUnlinkAt services unlinkat(dirfd, pathname, flags) (NR=35).
//
// aarch64 layout:
//
//	x0 = dirfd, x1 = pathname, x2 = flags (AT_REMOVEDIR)
//
// Three layer cases to cover, derived from overlay semantics:
//
//  1. Upper has the target, lower doesn't: os.Remove it, no whiteout
//     needed — the path is gone from both layers.
//  2. Upper has the target AND lower has the path: os.Remove upper,
//     then write a whiteout so the lower entry stays hidden.
//  3. Upper is missing but lower has the path: write a whiteout.
//     Lower stays untouched (it's meant to be immutable anyway, and
//     even if we wanted to delete from it we lack permission on most
//     deployments — the shared base image is typically read-only).
//
// AT_REMOVEDIR swaps unlink(2) semantics for rmdir(2): EISDIR becomes
// "this is NOT a dir", ENOTDIR becomes the wrong-shape error, and
// ENOTEMPTY is surfaced when children exist on either layer.
//
// The emptiness check for AT_REMOVEDIR of a lower-only directory
// walks the lower dir and subtracts any path covered by a whiteout
// or real entry on upper — without this, a dir the guest sees as
// empty (because upper whites out its last child) would still appear
// non-empty to rmdir. For now we approximate: we require lower to be
// empty ignoring upper masking. A later pass with getdents-level
// overlay merging will tighten this up.
func handleUnlinkAt(d *Dispatcher, regs *Regs) Verdict {
	dirfd := int64(regs.X[0])
	pathPtr := regs.X[1]
	flags := int(regs.X[2])
	removeDir := flags&atRemoveDir != 0

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

	if absGuest == "/" {
		// You can't unlink the root. Kernel: unlink → EISDIR,
		// rmdir → EBUSY. We stick with kernel behaviour.
		if removeDir {
			regs.X[0] = EncodeErrno(syscall.EBUSY)
		} else {
			regs.X[0] = EncodeErrno(syscall.EISDIR)
		}
		return VerdictHandled
	}

	upperPath := filepath.Join(d.FS.policy.UpperDir, absGuest)
	lowerPath := ""
	if d.FS.policy.LowerDir != "" {
		lowerPath = filepath.Join(d.FS.policy.LowerDir, absGuest)
	}

	upperInfo, upperErr := os.Lstat(upperPath)
	upperIsWhiteout := upperErr == nil && isWhiteoutPath(upperPath, upperInfo)
	upperPresent := upperErr == nil && !upperIsWhiteout

	var lowerInfo os.FileInfo
	lowerPresent := false
	if lowerPath != "" {
		if li, err := os.Lstat(lowerPath); err == nil {
			lowerInfo = li
			lowerPresent = true
		}
	}

	// Missing everywhere (including "upper has a whiteout and lower
	// doesn't back it") is just ENOENT.
	if !upperPresent && !lowerPresent {
		regs.X[0] = EncodeErrno(syscall.ENOENT)
		return VerdictHandled
	}

	// Determine effective type for the kind-check. Upper wins when
	// present, falling back to lower.
	var effective os.FileInfo
	switch {
	case upperPresent:
		effective = upperInfo
	default:
		effective = lowerInfo
	}

	if removeDir {
		if !effective.IsDir() {
			regs.X[0] = EncodeErrno(syscall.ENOTDIR)
			return VerdictHandled
		}
		if lowerPresent && lowerInfo.IsDir() {
			empty, err := lowerDirEmpty(lowerPath)
			if err != nil {
				regs.X[0] = EncodeErrno(err)
				return VerdictHandled
			}
			if !empty {
				regs.X[0] = EncodeErrno(syscall.ENOTEMPTY)
				return VerdictHandled
			}
		}
	} else if effective.IsDir() {
		regs.X[0] = EncodeErrno(syscall.EISDIR)
		return VerdictHandled
	}

	// Remove upper (if a real entry — not a whiteout). Rmdir shape
	// is handled by os.Remove matching the underlying inode type.
	if upperPresent {
		if err := os.Remove(upperPath); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	} else if upperIsWhiteout {
		// Already hidden — this shouldn't happen because we
		// treated upperIsWhiteout as !upperPresent above and
		// returned ENOENT when lower was also absent. Guard
		// anyway in case lower comes back into play under a race.
		regs.X[0] = EncodeErrno(syscall.ENOENT)
		return VerdictHandled
	}

	if lowerPresent {
		if err := os.MkdirAll(filepath.Dir(upperPath), 0o755); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		if err := writeWhiteout(upperPath); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}

	regs.X[0] = 0
	return VerdictHandled
}

// lowerDirEmpty reports whether a lower-layer directory has no
// children. Reads one entry; O(1) for non-empty dirs. Readdirnames
// returns io.EOF on a truly empty dir, any other error is surfaced.
func lowerDirEmpty(path string) (bool, error) {
	dir, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return len(names) == 0, nil
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

// handleDup services dup(oldfd) (NR=23).
//
// aarch64 layout: x0 = oldfd.
//
// Returns the lowest-free GUEST fd, backed by a fresh HOST fd obtained
// via syscall.Dup. The two host fds share the underlying file table
// entry — same file, same offset, same open-flags — which is what
// shell redirection (dup of stdout into a pipe write-end) relies on.
func handleDup(d *Dispatcher, regs *Regs) Verdict {
	guestOld := int(regs.X[0])
	hostOld, ok := d.FDs.Resolve(guestOld)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	hostNew, err := syscall.Dup(hostOld)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = uint64(d.FDs.Allocate(hostNew))
	return VerdictHandled
}

// handleDup3 services dup3(oldfd, newfd, flags) (NR=24).
//
// aarch64 layout: x0 = oldfd, x1 = newfd, x2 = flags (O_CLOEXEC only).
//
// Semantics differ from dup2 in two places:
//   - oldfd == newfd is an error (EINVAL), not a no-op.
//   - flags are a real mask — only O_CLOEXEC is defined; anything else
//     is EINVAL.
//
// If newfd was already open on the guest side, its host fd is closed
// after the new host fd is installed. We open-then-close rather than
// the kernel's close-then-open order because a failure in syscall.Dup
// must not leave the guest with newfd gone and nothing in its place.
func handleDup3(d *Dispatcher, regs *Regs) Verdict {
	guestOld := int(regs.X[0])
	guestNew := int(regs.X[1])
	flags := int(regs.X[2])

	if guestOld == guestNew {
		regs.X[0] = EncodeErrno(syscall.EINVAL)
		return VerdictHandled
	}
	if flags & ^syscall.O_CLOEXEC != 0 {
		regs.X[0] = EncodeErrno(syscall.EINVAL)
		return VerdictHandled
	}
	if guestNew < 0 {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	hostOld, ok := d.FDs.Resolve(guestOld)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}

	hostNew, err := syscall.Dup(hostOld)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if flags&syscall.O_CLOEXEC != 0 {
		if _, err := fcntlSetCloexec(hostNew); err != nil {
			_ = syscall.Close(hostNew)
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}
	if prevHost, had := d.FDs.AssignAt(guestNew, hostNew); had {
		_ = syscall.Close(prevHost)
	}
	regs.X[0] = uint64(guestNew)
	return VerdictHandled
}

// fcntlSetCloexec sets FD_CLOEXEC on a host fd. Extracted so handleDup3
// stays linear and a future handleFcntl can reuse the helper.
func fcntlSetCloexec(hostFd int) (int, error) {
	r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(hostFd), uintptr(syscall.F_SETFD), uintptr(syscall.FD_CLOEXEC))
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

// handleFcntl services fcntl(fd, cmd, arg) (NR=25). fcntl is a
// kitchen-sink syscall whose semantics depend on cmd; we only wire up
// the commands real programs lean on during init. Everything else
// returns ENOSYS so we notice when a guest reaches for advisory
// locking, F_NOTIFY, F_PIPE_SZ, or the *_LEASE family.
//
// Supported commands:
//   - F_DUPFD(arg): dup fd to the lowest free guest slot >= arg.
//   - F_DUPFD_CLOEXEC(arg): same + FD_CLOEXEC on host fd.
//   - F_GETFD: read FD_CLOEXEC.
//   - F_SETFD: set FD_CLOEXEC (other bits ignored — Linux F_SETFD
//     only defines this one flag as of 2026).
//   - F_GETFL: read open-status flags.
//   - F_SETFL: set the mutable subset (O_APPEND, O_NONBLOCK, O_ASYNC,
//     O_DIRECT, O_NOATIME). Kernel silently masks non-mutable bits.
func handleFcntl(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	cmd := int(regs.X[1])
	arg := regs.X[2]

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}

	switch cmd {
	case syscall.F_DUPFD, syscall.F_DUPFD_CLOEXEC:
		hostNew, err := syscall.Dup(hostFd)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		if cmd == syscall.F_DUPFD_CLOEXEC {
			if _, err := fcntlSetCloexec(hostNew); err != nil {
				_ = syscall.Close(hostNew)
				regs.X[0] = EncodeErrno(err)
				return VerdictHandled
			}
		}
		regs.X[0] = uint64(d.FDs.AllocateFrom(int(arg), hostNew))
		return VerdictHandled

	case syscall.F_GETFD, syscall.F_SETFD, syscall.F_GETFL, syscall.F_SETFL:
		r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(hostFd), uintptr(cmd), uintptr(arg))
		if errno != 0 {
			regs.X[0] = EncodeErrno(errno)
			return VerdictHandled
		}
		regs.X[0] = uint64(r)
		return VerdictHandled

	default:
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}
}

// pipe2AcceptedFlags is the set of flag bits Linux pipe2(2) accepts:
// O_CLOEXEC applies CLOEXEC to both new fds, O_NONBLOCK puts the fds
// in non-blocking mode, O_DIRECT switches the pipe to packet mode
// (rare, but well-defined). Any other bit is EINVAL.
const pipe2AcceptedFlags = syscall.O_CLOEXEC | syscall.O_NONBLOCK | syscall.O_DIRECT

// handlePipe2 services pipe2(pipefd, flags) (NR=59). pipe(2) doesn't
// exist on aarch64 — the generic syscall table only exposes pipe2.
//
// aarch64 layout: x0 = pipefd (int[2] out), x1 = flags.
//
// Writes two guest fds (4 bytes each, little-endian) into the caller's
// pipefd buffer: [0] = read end, [1] = write end. Host-side pipe is a
// real kernel pipe — the gate owns both ends through the FDTable, and
// reads/writes flow through handleRead/handleWrite like any other fd.
//
// If Pipe2 succeeds but the guest buffer write fails, we tear both
// fds down on the host AND in the guest table so the caller doesn't
// end up with two ghost fds the gate thinks are open but the guest
// has no names for.
func handlePipe2(d *Dispatcher, regs *Regs) Verdict {
	bufPtr := regs.X[0]
	flags := int(regs.X[1])

	if flags & ^pipe2AcceptedFlags != 0 {
		regs.X[0] = EncodeErrno(syscall.EINVAL)
		return VerdictHandled
	}
	if bufPtr == 0 {
		regs.X[0] = EncodeErrno(syscall.EFAULT)
		return VerdictHandled
	}

	var fds [2]int
	if err := syscall.Pipe2(fds[:], flags); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	gR := d.FDs.Allocate(fds[0])
	gW := d.FDs.Allocate(fds[1])

	out := make([]byte, 8)
	binary.LittleEndian.PutUint32(out[0:4], uint32(gR))
	binary.LittleEndian.PutUint32(out[4:8], uint32(gW))
	if err := d.Mem.WriteBytes(bufPtr, out); err != nil {
		d.FDs.Close(gR)
		d.FDs.Close(gW)
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
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
