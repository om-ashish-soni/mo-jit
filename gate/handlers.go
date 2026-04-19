package gate

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
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

	// Directory opens get a pre-built overlay-merged dirent stream so
	// the first getdents64 sees upper+lower union, whiteouts filtered,
	// opaque markers honoured. A snapshot returns nil when neither
	// layer resolves as a directory (caller opened a non-dir or a
	// path whose on-disk type isn't a directory); in that case we
	// leave the fd snapshot-less and getdents64 will fall through to
	// raw host readdir — which will usually surface ENOTDIR anyway.
	if info, statErr := os.Stat(hostPath); statErr == nil && info.IsDir() {
		if snap, err := buildDirSnapshot(d, absGuest); err == nil && snap != nil {
			d.setDirSnapshot(guestFd, snap)
		}
	}

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
	replacingWhiteout := false
	switch {
	case errors.Is(rerr, ErrWhiteout):
		if err := os.Remove(upperPath); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		replacingWhiteout = true
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
	// If we just replaced a whiteout, the lower layer may still hold a
	// directory at the same guest path. Without the opaque marker its
	// children would leak back through readdir — a surprise for the
	// guest that just "rm -rf'd" the dir. Stamp opaque so the merge
	// skips lower entirely. Ignore xattr errors (EROFS, ENOTSUP): on
	// filesystems that can't hold user.* xattrs we can't give the full
	// guarantee, but the mkdir itself should still succeed.
	if replacingWhiteout {
		_ = syscall.Setxattr(upperPath, opaqueXattr, []byte{'y'}, 0)
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

	// Cross-layer dir rename: src is a lower-only directory. Materialise
	// the whole subtree onto upper first, then fall through to the
	// same-layer os.Rename path below. After the rename lands, stamp
	// opaque on dst so any lower-side shadow at the dst path is hidden
	// from the guest's merged readdir.
	if srcInfo.IsDir() && !oldOnUpper {
		if err := os.MkdirAll(filepath.Dir(oldUpper), 0o755); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		if err := recursiveCopyUp(oldLower, oldUpper); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		oldOnUpper = true
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

	// For directory renames, stamp opaque on dst so any shadowing lower
	// entries at newAbs stay invisible in the guest's merged readdir.
	// POSIX says the dst is replaced entirely by src; without opaque,
	// buildDirSnapshot would merge upper (rename result) with whatever
	// lower happened to have at newAbs, bleeding stale entries through.
	if srcInfo.IsDir() {
		_ = syscall.Setxattr(newUpper, opaqueXattr, []byte{'y'}, 0)
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

// handleStatFs services statfs(path, bufp) (NR=43). apt/dpkg call this
// to decide whether /var/cache/apt has enough room to stage a download;
// df reads /proc/mounts then statfs's each entry. Without this handler
// the passthrough would hit the host kernel with a *guest* path,
// failing with ENOENT (or worse, leaking host-path info).
//
// aarch64 layout: x0 = pathname, x1 = buf.
//
// Path resolves through FSGate.Resolve so the kernel sees the real
// backing host path (upper if copied-up, lower otherwise). Whatever
// filesystem physically holds that backing path is what the guest
// learns about — which is the correct answer: writes will land there,
// so its free-space numbers are what actually constrains the guest.
func handleStatFs(d *Dispatcher, regs *Regs) Verdict {
	pathPtr := regs.X[0]
	bufPtr := regs.X[1]

	path, err := d.Paths.ReadPath(pathPtr, MaxPathLen)
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
	var st syscall.Statfs_t
	if err := syscall.Statfs(hostPath, &st); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if bufPtr == 0 {
		regs.X[0] = EncodeErrno(syscall.EFAULT)
		return VerdictHandled
	}
	if err := d.Mem.WriteBytes(bufPtr, packStatfsAarch64(&st)); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleFStatFs services fstatfs(fd, bufp) (NR=44). Same shape as
// handleStatFs but takes a guest fd which we resolve to a host fd.
//
// aarch64 layout: x0 = fd, x1 = buf.
func handleFStatFs(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	bufPtr := regs.X[1]

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	var st syscall.Statfs_t
	if err := syscall.Fstatfs(hostFd, &st); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if bufPtr == 0 {
		regs.X[0] = EncodeErrno(syscall.EFAULT)
		return VerdictHandled
	}
	if err := d.Mem.WriteBytes(bufPtr, packStatfsAarch64(&st)); err != nil {
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

// handleLSeek services lseek(fd, offset, whence) (NR=62).
//
// aarch64 layout: x0 = fd, x1 = offset (i64 — aarch64 off_t is 64-bit,
// no llseek split), x2 = whence.
//
// Pure host-fd passthrough. Layer bookkeeping happens at open time;
// once a guest fd has been bound to a host fd, the kernel's own offset
// is the source of truth. SEEK_DATA / SEEK_HOLE work automatically for
// overlay paths because the host fd resolves to either upper or lower.
func handleLSeek(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	offset := int64(regs.X[1])
	whence := int(regs.X[2])

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	off, err := syscall.Seek(hostFd, offset, whence)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = uint64(off)
	return VerdictHandled
}

// Linux linkat(2) flags the handler understands.
const (
	atSymlinkFollow = 0x400  // AT_SYMLINK_FOLLOW — follow a symlink at oldpath
	atEmptyPathFlag = 0x1000 // AT_EMPTY_PATH — oldpath=="" means "the file behind olddirfd"
)

// handleLinkAt services linkat(olddirfd, oldpath, newdirfd, newpath, flags)
// (NR=37). apt/dpkg pre-stage packages by hardlinking payloads out of
// a cache dir, and `cp -l` / git's object dedup rely on the same
// primitive — low-traffic but essential for "install a .deb" paths.
//
// aarch64 layout:
//
//	x0 = olddirfd, x1 = oldpath,
//	x2 = newdirfd, x3 = newpath, x4 = flags
//
// Layer handling:
//   - src on upper: os.Link upper-src → upper-dst. Same-layer,
//     atomic, shares inode.
//   - src on lower only: copy-up first, then link. Promotes src to
//     upper so both paths share an upper-layer inode. This breaks
//     "nlink across the copy-up boundary" but preserves "both paths
//     see the same bytes", which is what hardlink consumers
//     actually depend on in practice (apt, git, cp -l).
//
// Flags:
//   - AT_SYMLINK_FOLLOW is honoured via syscall.Linkat's flags arg.
//   - AT_EMPTY_PATH returns ENOSYS until dirfd-relative lookups are
//     wired (same as every other *at handler in M2).
//
// Unsupported shapes return ENOSYS so guest failures point us at the
// exact missing case.
func handleLinkAt(d *Dispatcher, regs *Regs) Verdict {
	oldDirfd := int64(regs.X[0])
	oldPtr := regs.X[1]
	newDirfd := int64(regs.X[2])
	newPtr := regs.X[3]
	flags := int(regs.X[4])

	if d.FS.policy.UpperDir == "" {
		regs.X[0] = EncodeErrno(syscall.EROFS)
		return VerdictHandled
	}
	if flags&atEmptyPathFlag != 0 {
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

	upperDir := d.FS.policy.UpperDir
	newUpper := filepath.Join(upperDir, newAbs)

	// Dst must not exist (upper non-whiteout OR lower-not-masked).
	if info, err := os.Lstat(newUpper); err == nil {
		if !isWhiteoutPath(newUpper, info) {
			regs.X[0] = EncodeErrno(syscall.EEXIST)
			return VerdictHandled
		}
		// Whiteout at dst — clear so Linkat doesn't trip on it.
		if err := os.Remove(newUpper); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	} else if d.FS.policy.LowerDir != "" {
		lowerNew := filepath.Join(d.FS.policy.LowerDir, newAbs)
		if _, err := os.Lstat(lowerNew); err == nil {
			regs.X[0] = EncodeErrno(syscall.EEXIST)
			return VerdictHandled
		}
	}

	// Locate src host path, promoting lower→upper via copy-up so the
	// hardlink lands within a single filesystem.
	hostOld, layer, err := d.FS.Resolve(oldAbs)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if layer == LayerLower {
		// Require the lower-side entry to actually exist before we
		// copy-up — Resolve can return nil for a lower path that has
		// never been statted.
		if _, err := os.Lstat(hostOld); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		upperSrc, err := d.FS.CopyUp(oldAbs)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		hostOld = upperSrc
	}

	if err := os.MkdirAll(filepath.Dir(newUpper), 0o755); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if err := linkatHost(hostOld, newUpper, flags&atSymlinkFollow); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// linkatHost invokes the raw linkat(2) syscall against the host with
// AT_FDCWD on both sides. Go's syscall package exposes SYS_LINKAT but
// not a typed Linkat wrapper on linux/arm64, so we drop to Syscall6.
// flags is passed through verbatim (AT_SYMLINK_FOLLOW — AT_EMPTY_PATH
// is filtered upstream since it implies dirfd-relative resolution).
func linkatHost(oldPath, newPath string, flags int) error {
	oldP, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return err
	}
	newP, err := syscall.BytePtrFromString(newPath)
	if err != nil {
		return err
	}
	fd := atFDCWD // local int so uintptr sign-extends, not overflows
	_, _, errno := syscall.Syscall6(
		syscall.SYS_LINKAT,
		uintptr(fd),
		uintptr(unsafe.Pointer(oldP)),
		uintptr(fd),
		uintptr(unsafe.Pointer(newP)),
		uintptr(flags),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// handleGetDents64 services getdents64(fd, dirp, count) (NR=61). Shells
// and file browsers call this on every `ls`, `find`, and tab-completion
// — second-most-important fd-ops handler after read/write.
//
// Currently we proxy the host kernel's own getdents64 verbatim. Works
// correctly for directories that live on exactly ONE layer (upper or
// lower). Known limitations, tracked for the overlay-merge follow-up:
//
//   - Directories that exist on BOTH layers return only the host-fd's
//     view (whichever layer the openat handler picked). Upper-side
//     additions AND whiteouts-masking-lower are both invisible. The
//     fix is to build a merged entry list: read upper dir, read lower
//     dir, subtract names whited out on upper, dedup on name.
//   - mknod-style whiteout char-device entries leak through to the
//     guest as visible files. Callers that stat the entry recover via
//     FSGate.Resolve's whiteout filter, but a naive getdents64 dump
//     will show the whiteout name.
//
// linux_dirent64 is architecture-independent (same layout on arm64 and
// amd64), so we can pass the kernel's raw bytes straight through the
// MemWriter without any repacking.
func handleGetDents64(d *Dispatcher, regs *Regs) Verdict {
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

	// Overlay-aware path: this fd was opened via handleOpenAt on a
	// directory, so we have a pre-built merged dirent stream.
	if snap := d.takeDirSnapshot(guestFd); snap != nil {
		chunk, errno := serveDirSnapshot(snap, int(count))
		if errno != 0 {
			regs.X[0] = EncodeErrno(errno)
			return VerdictHandled
		}
		if len(chunk) > 0 {
			if err := d.Mem.WriteBytes(bufPtr, chunk); err != nil {
				// Rewind the cursor so the guest can retry. Without
				// this, a transient fault would silently eat entries.
				snap.off -= len(chunk)
				regs.X[0] = EncodeErrno(err)
				return VerdictHandled
			}
		}
		regs.X[0] = uint64(len(chunk))
		return VerdictHandled
	}

	buf := make([]byte, count)
	n, err := syscall.ReadDirent(hostFd, buf)
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

// handleFTruncate services ftruncate(fd, length) (NR=46).
//
// Pure fd passthrough — the guest fd was bound to a host fd at open
// time, and any copy-up that needed to happen already happened there.
// If the guest opened the file read-only, the host kernel surfaces
// EBADF from the ftruncate(2) itself and we propagate.
func handleFTruncate(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	length := int64(regs.X[1])

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	if err := syscall.Ftruncate(hostFd, length); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleTruncate services truncate(path, length) (NR=45). Unlike
// ftruncate, there's no fd that already rode through openat's
// copy-up, so we have to handle the layer split here.
//
// aarch64 layout: x0 = path, x1 = length.
//
// Semantics:
//   - No UpperDir: EROFS — the overlay is genuinely read-only.
//   - Whiteout at path: ENOENT.
//   - Path on lower only: CopyUp then truncate the upper copy —
//     future reads still see the truncated content because upper
//     now masks lower for this name.
//   - Path on upper: truncate in place.
func handleTruncate(d *Dispatcher, regs *Regs) Verdict {
	pathPtr := regs.X[0]
	length := int64(regs.X[1])

	if d.FS.policy.UpperDir == "" {
		regs.X[0] = EncodeErrno(syscall.EROFS)
		return VerdictHandled
	}

	path, err := d.Paths.ReadPath(pathPtr, MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	absGuest := d.FS.AbsFromGuest(path)

	hostPath, layer, err := d.FS.Resolve(absGuest)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if layer == LayerLower {
		// Confirm lower has the file before copying — Resolve can
		// return nil for any lower path, without statting.
		if _, err := os.Lstat(hostPath); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		upperPath, err := d.FS.CopyUp(absGuest)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		hostPath = upperPath
	}
	if err := syscall.Truncate(hostPath, length); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleFChMod services fchmod(fd, mode) (NR=52). Pure host-fd
// passthrough — the copy-up decision was made at open time. A
// writable upper fd accepts chmod; an rdonly lower fd doesn't even
// reach us writable (ditto a fresh O_RDONLY anywhere).
func handleFChMod(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	mode := uint32(regs.X[1])

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	if err := syscall.Fchmod(hostFd, mode); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleFChModAt services fchmodat(dirfd, path, mode, flags) (NR=53).
// aarch64 layout: x0=dirfd, x1=path, x2=mode, x3=flags.
//
// Like truncate, fchmodat touches a guest path so it owns the layer
// split. Lower-only files get copied up first — a permission change
// only matters on the upper copy since that's what the guest sees
// afterwards.
//
// AT_SYMLINK_NOFOLLOW is accepted as a flag but Linux itself rejects
// chmod-on-symlink with ENOTSUP on every common filesystem; we pass
// it through to syscall.Fchmodat and let the kernel surface the
// errno.
func handleFChModAt(d *Dispatcher, regs *Regs) Verdict {
	dirfd := int64(regs.X[0])
	pathPtr := regs.X[1]
	mode := uint32(regs.X[2])
	flags := int(regs.X[3])

	if d.FS.policy.UpperDir == "" {
		regs.X[0] = EncodeErrno(syscall.EROFS)
		return VerdictHandled
	}

	path, err := d.Paths.ReadPath(pathPtr, MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	absGuest, ok := absolutiseAt(d, dirfd, path)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}

	hostPath, layer, err := d.FS.Resolve(absGuest)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if layer == LayerLower {
		if _, err := os.Lstat(hostPath); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		upperPath, err := d.FS.CopyUp(absGuest)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		hostPath = upperPath
	}
	if err := syscall.Fchmodat(atFDCWD, hostPath, mode, flags); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleFChOwn services fchown(fd, uid, gid) (NR=55). Pure host-fd
// passthrough for the same reason fchmod is: the copy-up happened at
// open time, so we already have a host fd pointing at the layer the
// guest is allowed to mutate.
//
// Unrooted Android lacks CAP_CHOWN, so the kernel will typically EPERM
// anything other than a no-op (same-owner) chown. We still route it
// rather than passthrough so the host's real /etc/* never gets touched.
func handleFChOwn(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	uid := int(int32(regs.X[1]))
	gid := int(int32(regs.X[2]))

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	if err := syscall.Fchown(hostFd, uid, gid); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleFChOwnAt services fchownat(dirfd, path, uid, gid, flags) (NR=54).
// aarch64 layout: x0=dirfd, x1=path, x2=uid, x3=gid, x4=flags.
//
// Same overlay shape as fchmodat: resolve the guest path, copy-up if
// it's lower-only, then forward to the kernel. AT_SYMLINK_NOFOLLOW is
// honoured (unlike fchmodat where chmod-on-symlink is universally
// ENOTSUP): chown(2) on a symlink changes the link's owner, and the
// kernel handles that distinction via the flag.
//
// uid/gid come in as 32-bit unsigned values; -1 (0xffffffff) means
// "don't change", and we forward that through as int(-1) so syscall.
// Fchownat sees the same sentinel the kernel expects.
func handleFChOwnAt(d *Dispatcher, regs *Regs) Verdict {
	dirfd := int64(regs.X[0])
	pathPtr := regs.X[1]
	uid := int(int32(regs.X[2]))
	gid := int(int32(regs.X[3]))
	flags := int(regs.X[4])

	if d.FS.policy.UpperDir == "" {
		regs.X[0] = EncodeErrno(syscall.EROFS)
		return VerdictHandled
	}

	path, err := d.Paths.ReadPath(pathPtr, MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	absGuest, ok := absolutiseAt(d, dirfd, path)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}

	hostPath, layer, err := d.FS.Resolve(absGuest)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if layer == LayerLower {
		if _, err := os.Lstat(hostPath); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		upperPath, err := d.FS.CopyUp(absGuest)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		hostPath = upperPath
	}
	if err := syscall.Fchownat(atFDCWD, hostPath, uid, gid, flags); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// utimeNow is the magic tv_nsec value that tells utimensat "use the
// current time for this field" (include/uapi/linux/stat.h — UTIME_NOW).
const utimeNow = ((1 << 30) - 1)

// handleUtimensAt services utimensat(dirfd, path, times, flags) (NR=88).
// Touch / make / rsync all lean on this to drive incremental-rebuild
// logic; missing it means every rebuild thinks the tree is stale.
//
// aarch64 layout:
//
//	x0 = dirfd, x1 = path (may be NULL for futimens-style),
//	x2 = times (struct timespec[2] or NULL), x3 = flags.
//
// times encoding (reads 32 bytes via MemReader):
//
//	[0] atime: tv_sec (8B), tv_nsec (8B)
//	[1] mtime: tv_sec (8B), tv_nsec (8B)
//
// tv_nsec may hold the magic UTIME_NOW or UTIME_OMIT; the kernel
// interprets those in-struct so we just forward the bytes.
//
// Two shapes the kernel allows:
//   - path != NULL: operate on (dirfd, path); honour AT_SYMLINK_NOFOLLOW
//     to touch the link itself instead of its target. Copy-up first so
//     the stamp lands on the upper layer.
//   - path == NULL: libc's futimens(fd, ts) translates to
//     utimensat(fd, NULL, ts, 0). Resolve the guest fd to a host fd and
//     call the raw syscall with a NULL path.
func handleUtimensAt(d *Dispatcher, regs *Regs) Verdict {
	dirfd := int64(regs.X[0])
	pathPtr := regs.X[1]
	timesPtr := regs.X[2]
	flags := int(regs.X[3])

	if d.FS.policy.UpperDir == "" {
		regs.X[0] = EncodeErrno(syscall.EROFS)
		return VerdictHandled
	}

	ts, err := readUtimensTimes(d, timesPtr)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	// futimens-style: path NULL, dirfd names the file. AT_FDCWD with
	// NULL path is undefined on real kernels; mirror that with EBADF.
	if pathPtr == 0 {
		if flags != 0 {
			// Linux rejects any flags when path==NULL; AT_SYMLINK_NOFOLLOW
			// has no meaning against an already-open fd.
			regs.X[0] = EncodeErrno(syscall.EINVAL)
			return VerdictHandled
		}
		if dirfd == int64(atFDCWD) {
			regs.X[0] = EncodeErrno(syscall.EBADF)
			return VerdictHandled
		}
		hostFd, ok := d.FDs.Resolve(int(dirfd))
		if !ok {
			regs.X[0] = EncodeErrno(syscall.EBADF)
			return VerdictHandled
		}
		if errno := rawUtimensAt(hostFd, "", ts, 0); errno != 0 {
			regs.X[0] = EncodeErrno(errno)
			return VerdictHandled
		}
		regs.X[0] = 0
		return VerdictHandled
	}

	path, err := d.Paths.ReadPath(pathPtr, MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	absGuest, ok := absolutiseAt(d, dirfd, path)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}

	hostPath, layer, err := d.FS.Resolve(absGuest)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if layer == LayerLower {
		// Lstat so symlinks promote-as-symlinks when NOFOLLOW is set:
		// CopyUp's symlink branch recreates the link on upper, and the
		// raw utimensat with NOFOLLOW below touches the link itself.
		if _, err := os.Lstat(hostPath); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		upperPath, err := d.FS.CopyUp(absGuest)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		hostPath = upperPath
	}

	if flags&atSymlinkNoFollow != 0 {
		// Go's UtimesNano always follows symlinks (flags=0 internally);
		// for NOFOLLOW we go raw.
		if errno := rawUtimensAt(atFDCWD, hostPath, ts, atSymlinkNoFollow); errno != 0 {
			regs.X[0] = EncodeErrno(errno)
			return VerdictHandled
		}
		regs.X[0] = 0
		return VerdictHandled
	}
	if err := syscall.UtimesNano(hostPath, ts); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// readUtimensTimes decodes the 32-byte struct timespec[2] at timesPtr,
// or synthesises a (UTIME_NOW, UTIME_NOW) pair when timesPtr is NULL.
// Go's UtimesNano with a nil slice maps to utimes(..., NULL) which
// EINVALs under utimensat; the sentinel pair keeps the kernel happy
// and matches what futimens(fd, NULL) expects.
func readUtimensTimes(d *Dispatcher, timesPtr uint64) ([]syscall.Timespec, error) {
	if timesPtr == 0 {
		return []syscall.Timespec{
			{Sec: 0, Nsec: utimeNow},
			{Sec: 0, Nsec: utimeNow},
		}, nil
	}
	buf, err := d.MemR.ReadBytes(timesPtr, 32)
	if err != nil {
		return nil, err
	}
	return []syscall.Timespec{
		{Sec: int64(binary.LittleEndian.Uint64(buf[0:8])), Nsec: int64(binary.LittleEndian.Uint64(buf[8:16]))},
		{Sec: int64(binary.LittleEndian.Uint64(buf[16:24])), Nsec: int64(binary.LittleEndian.Uint64(buf[24:32]))},
	}, nil
}

// rawUtimensAt wraps SYS_UTIMENSAT directly so the handler can pass a
// NULL path (futimens shape) or non-zero flags (AT_SYMLINK_NOFOLLOW) —
// neither is reachable through Go's typed syscall.UtimesNano. An empty
// path argument serialises to NULL, matching what the kernel wants for
// futimens-via-utimensat.
func rawUtimensAt(dirfd int, path string, ts []syscall.Timespec, flags int) syscall.Errno {
	var pathArg uintptr
	if path != "" {
		p, err := syscall.BytePtrFromString(path)
		if err != nil {
			return syscall.EINVAL
		}
		pathArg = uintptr(unsafe.Pointer(p))
	}
	var tsArg uintptr
	if len(ts) > 0 {
		tsArg = uintptr(unsafe.Pointer(&ts[0]))
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_UTIMENSAT,
		uintptr(dirfd),
		pathArg,
		tsArg,
		uintptr(flags),
		0, 0,
	)
	return errno
}

// xattrNameMax mirrors include/uapi/linux/limits.h XATTR_NAME_MAX.
// Using this instead of MaxPathLen keeps us honest about the kernel's
// actual ceiling (255 bytes + NUL) and caps how much we'll copy out
// of guest memory for a single call.
const xattrNameMax = 256

// handleGetXattr services getxattr(path, name, value, size) (NR=8).
// Pure read — no copy-up. Returns the number of bytes the attribute
// value occupies (or that was written into the guest buffer). size==0
// is the "how big is it?" probe; we honour it by handing the kernel a
// zero-length buffer.
//
// aarch64 layout: x0=path, x1=name, x2=value, x3=size.
func handleGetXattr(d *Dispatcher, regs *Regs) Verdict {
	path, err := d.Paths.ReadPath(regs.X[0], MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	name, err := d.Paths.ReadPath(regs.X[1], xattrNameMax)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	size := int(regs.X[3])
	absGuest, ok := absolutiseAt(d, int64(atFDCWD), path)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}
	hostPath, _, err := d.FS.Resolve(absGuest)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if size == 0 {
		n, err := syscall.Getxattr(hostPath, name, nil)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		regs.X[0] = uint64(n)
		return VerdictHandled
	}
	buf := make([]byte, size)
	n, err := syscall.Getxattr(hostPath, name, buf)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if n > 0 {
		if err := d.Mem.WriteBytes(regs.X[2], buf[:n]); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}
	regs.X[0] = uint64(n)
	return VerdictHandled
}

// handleSetXattr services setxattr(path, name, value, size, flags) (NR=5).
// Write path → copy-up if the target lives on lower so we don't stamp
// the read-only layer. flags carries XATTR_CREATE / XATTR_REPLACE; we
// just forward them to the kernel.
//
// aarch64 layout: x0=path, x1=name, x2=value, x3=size, x4=flags.
func handleSetXattr(d *Dispatcher, regs *Regs) Verdict {
	if d.FS.policy.UpperDir == "" {
		regs.X[0] = EncodeErrno(syscall.EROFS)
		return VerdictHandled
	}
	path, err := d.Paths.ReadPath(regs.X[0], MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	name, err := d.Paths.ReadPath(regs.X[1], xattrNameMax)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	size := int(regs.X[3])
	flags := int(regs.X[4])
	var value []byte
	if size > 0 {
		value, err = d.MemR.ReadBytes(regs.X[2], size)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}
	absGuest, ok := absolutiseAt(d, int64(atFDCWD), path)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}
	hostPath, layer, err := d.FS.Resolve(absGuest)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if layer == LayerLower {
		if _, err := os.Lstat(hostPath); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		upperPath, err := d.FS.CopyUp(absGuest)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		hostPath = upperPath
	}
	if err := syscall.Setxattr(hostPath, name, value, flags); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleFGetXattr services fgetxattr(fd, name, value, size) (NR=10).
// Pure host-fd passthrough — reads don't need copy-up, and the guest
// fd is already bound to the right layer from open time.
func handleFGetXattr(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	name, err := d.Paths.ReadPath(regs.X[1], xattrNameMax)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	size := int(regs.X[3])
	if size == 0 {
		n, err := fgetxattr(hostFd, name, nil)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		regs.X[0] = uint64(n)
		return VerdictHandled
	}
	buf := make([]byte, size)
	n, err := fgetxattr(hostFd, name, buf)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if n > 0 {
		if err := d.Mem.WriteBytes(regs.X[2], buf[:n]); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}
	regs.X[0] = uint64(n)
	return VerdictHandled
}

// handleFSetXattr services fsetxattr(fd, name, value, size, flags) (NR=7).
// Host-fd passthrough — we can't copy-up a live fd, so if the guest
// holds a lower-layer fd the kernel will decide (typically success
// since our "lower" is just a regular dir; a real read-only backing
// store would surface EROFS).
//
// TODO: track per-fd layer at open time and refuse fsetxattr on an fd
// that was opened O_RDONLY from lower, to keep the "lower is immutable"
// invariant the rest of the handlers maintain.
func handleFSetXattr(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	name, err := d.Paths.ReadPath(regs.X[1], xattrNameMax)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	size := int(regs.X[3])
	flags := int(regs.X[4])
	var value []byte
	if size > 0 {
		value, err = d.MemR.ReadBytes(regs.X[2], size)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}
	if err := fsetxattr(hostFd, name, value, flags); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// fgetxattr / fsetxattr wrap the Linux syscalls that Go's syscall
// package doesn't expose on linux/arm64 (only the path-based versions
// are typed). Raw Syscall6 plus BytePtrFromString.
func fgetxattr(fd int, name string, buf []byte) (int, error) {
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	var bufPtr unsafe.Pointer
	if len(buf) > 0 {
		bufPtr = unsafe.Pointer(&buf[0])
	}
	r, _, errno := syscall.Syscall6(
		syscall.SYS_FGETXATTR,
		uintptr(fd),
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(bufPtr),
		uintptr(len(buf)),
		0, 0,
	)
	if errno != 0 {
		return int(r), errno
	}
	return int(r), nil
}

func fsetxattr(fd int, name string, value []byte, flags int) error {
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	var valPtr unsafe.Pointer
	if len(value) > 0 {
		valPtr = unsafe.Pointer(&value[0])
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FSETXATTR,
		uintptr(fd),
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(valPtr),
		uintptr(len(value)),
		uintptr(flags),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// handleListXattr services listxattr(path, list, size) (NR=11).
// Returns the total byte count of NUL-separated attribute names.
// Pure read — no copy-up. Overlay namespace: we forward whatever the
// host returns; the merged list across upper+lower isn't implemented
// yet, so the guest sees exactly the layer Resolve picked.
//
// TODO: strip user.overlay.* from the list so the guest never sees
// our internal opaque/whiteout markers even if someone manages to
// listxattr the upper dir directly through a bind.
func handleListXattr(d *Dispatcher, regs *Regs) Verdict {
	path, err := d.Paths.ReadPath(regs.X[0], MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	size := int(regs.X[2])
	absGuest, ok := absolutiseAt(d, int64(atFDCWD), path)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}
	hostPath, _, err := d.FS.Resolve(absGuest)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if size == 0 {
		n, err := syscall.Listxattr(hostPath, nil)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		regs.X[0] = uint64(n)
		return VerdictHandled
	}
	buf := make([]byte, size)
	n, err := syscall.Listxattr(hostPath, buf)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if n > 0 {
		if err := d.Mem.WriteBytes(regs.X[1], buf[:n]); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}
	regs.X[0] = uint64(n)
	return VerdictHandled
}

// handleFListXattr services flistxattr(fd, list, size) (NR=13). Pure
// host-fd passthrough — the layer decision rode in at open time.
func handleFListXattr(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	size := int(regs.X[2])
	if size == 0 {
		n, err := flistxattr(hostFd, nil)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		regs.X[0] = uint64(n)
		return VerdictHandled
	}
	buf := make([]byte, size)
	n, err := flistxattr(hostFd, buf)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if n > 0 {
		if err := d.Mem.WriteBytes(regs.X[1], buf[:n]); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}
	regs.X[0] = uint64(n)
	return VerdictHandled
}

// handleRemoveXattr services removexattr(path, name) (NR=14). Write
// operation → copy-up for lower paths before issuing the removal.
func handleRemoveXattr(d *Dispatcher, regs *Regs) Verdict {
	if d.FS.policy.UpperDir == "" {
		regs.X[0] = EncodeErrno(syscall.EROFS)
		return VerdictHandled
	}
	path, err := d.Paths.ReadPath(regs.X[0], MaxPathLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	name, err := d.Paths.ReadPath(regs.X[1], xattrNameMax)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	absGuest, ok := absolutiseAt(d, int64(atFDCWD), path)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.ENOSYS)
		return VerdictHandled
	}
	hostPath, layer, err := d.FS.Resolve(absGuest)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if layer == LayerLower {
		if _, err := os.Lstat(hostPath); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		upperPath, err := d.FS.CopyUp(absGuest)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		hostPath = upperPath
	}
	if err := syscall.Removexattr(hostPath, name); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleFRemoveXattr services fremovexattr(fd, name) (NR=16). Host-fd
// passthrough, same caveat as fsetxattr: if the guest fd points at
// lower we don't refuse it — the host kernel will.
func handleFRemoveXattr(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	name, err := d.Paths.ReadPath(regs.X[1], xattrNameMax)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if err := fremovexattr(hostFd, name); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// flistxattr / fremovexattr wrap the fd-based xattr syscalls that
// aren't typed in Go's syscall package on linux/arm64.
func flistxattr(fd int, buf []byte) (int, error) {
	var bufPtr unsafe.Pointer
	if len(buf) > 0 {
		bufPtr = unsafe.Pointer(&buf[0])
	}
	r, _, errno := syscall.Syscall(
		syscall.SYS_FLISTXATTR,
		uintptr(fd),
		uintptr(bufPtr),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return int(r), errno
	}
	return int(r), nil
}

func fremovexattr(fd int, name string) error {
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_FREMOVEXATTR,
		uintptr(fd),
		uintptr(unsafe.Pointer(nameBytes)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
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
	// Release any overlay directory snapshot pinned under this fd.
	// No-op for non-directory fds.
	d.dropDirSnapshot(guestFd)
	if err := syscall.Close(hostFd); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleConnect services connect(sockfd, sockaddr, addrlen) (NR=203).
// Gates every outbound network destination against NetPolicy before
// forwarding to the kernel. This is the enforcement point for "don't
// let the guest connect to 10.x even if the user hasn't explicitly
// denied it" (builtin deny list in netgate.go).
//
// aarch64 layout: x0 = sockfd, x1 = sockaddr ptr, x2 = addrlen.
//
// Supported address families:
//   - AF_INET  (16-byte sockaddr_in): family + port + IPv4 addr.
//   - AF_INET6 (28-byte sockaddr_in6): family + port + flowinfo +
//     IPv6 addr + scope_id.
//   - AF_UNIX: ENOSYS for now. Unix paths need FSGate translation so
//     the guest can connect to sockets living under its virtualised
//     rootfs, not host /tmp. Tracked as a follow-up.
//
// Port bytes in the sockaddr are network-byte-order (big-endian);
// IPv4/IPv6 address bytes are already in network order as raw octets,
// so we feed them into netip.Addr directly.
func handleConnect(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	addrPtr := regs.X[1]
	addrLen := int(regs.X[2])

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	if addrLen < 2 {
		regs.X[0] = EncodeErrno(syscall.EINVAL)
		return VerdictHandled
	}
	buf, err := d.MemR.ReadBytes(addrPtr, addrLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	family := binary.LittleEndian.Uint16(buf[0:2])

	sa, ap, err := decodeSockaddr(family, buf)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	// NetPolicy check runs AFTER decode so we can tell the guest why.
	// Blocked destinations all become EACCES — indistinguishable from
	// the kernel's own decision when, say, firewall rules drop the
	// packet; a policy-aware guest has no need to distinguish.
	if err := d.Net.CheckConnect(ap); err != nil {
		regs.X[0] = EncodeErrno(syscall.EACCES)
		return VerdictHandled
	}
	if err := syscall.Connect(hostFd, sa); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// decodeSockaddr unpacks a sockaddr blob read from guest memory into
// (Go syscall.Sockaddr, netip.AddrPort). The AddrPort is what the
// policy gate inspects; the Sockaddr is what syscall.Connect wants.
// Returns EAFNOSUPPORT for families we don't emulate (AF_UNIX is
// deferred) and EINVAL for truncated blobs.
func decodeSockaddr(family uint16, buf []byte) (syscall.Sockaddr, netip.AddrPort, error) {
	switch family {
	case syscall.AF_INET:
		if len(buf) < 16 {
			return nil, netip.AddrPort{}, syscall.EINVAL
		}
		port := binary.BigEndian.Uint16(buf[2:4])
		var addr [4]byte
		copy(addr[:], buf[4:8])
		sa := &syscall.SockaddrInet4{Port: int(port), Addr: addr}
		return sa, netip.AddrPortFrom(netip.AddrFrom4(addr), port), nil
	case syscall.AF_INET6:
		if len(buf) < 28 {
			return nil, netip.AddrPort{}, syscall.EINVAL
		}
		port := binary.BigEndian.Uint16(buf[2:4])
		var addr [16]byte
		copy(addr[:], buf[8:24])
		scopeID := binary.LittleEndian.Uint32(buf[24:28])
		sa := &syscall.SockaddrInet6{Port: int(port), ZoneId: scopeID, Addr: addr}
		return sa, netip.AddrPortFrom(netip.AddrFrom16(addr), port), nil
	case syscall.AF_UNIX:
		return nil, netip.AddrPort{}, syscall.ENOSYS
	default:
		return nil, netip.AddrPort{}, syscall.EAFNOSUPPORT
	}
}

// handleBind services bind(sockfd, addr, addrlen) (NR=200). Shape
// matches connect: read the sockaddr out of guest memory, decode it,
// hand it to NetGate.CheckBind, then forward to the host kernel.
//
// The difference from connect is policy: bind gates the LOCAL source
// address (see NetGate.CheckBind), not a remote destination. For
// loopback-only that means the bind must be loopback or wildcard;
// for internet any local bind is allowed.
//
// AF_UNIX bind would need FSGate path translation (guest->host rootfs
// mapping) before it can be safe — without that, a bind to "/tmp/x"
// lands in the host's /tmp, not the guest's rootfs. Deferred: returns
// ENOSYS, same as connect.
func handleBind(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	addrPtr := regs.X[1]
	addrLen := int(regs.X[2])

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	if addrLen < 2 {
		regs.X[0] = EncodeErrno(syscall.EINVAL)
		return VerdictHandled
	}
	buf, err := d.MemR.ReadBytes(addrPtr, addrLen)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	family := binary.LittleEndian.Uint16(buf[0:2])

	sa, ap, err := decodeSockaddr(family, buf)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if err := d.Net.CheckBind(ap); err != nil {
		regs.X[0] = EncodeErrno(syscall.EACCES)
		return VerdictHandled
	}
	if err := syscall.Bind(hostFd, sa); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleSendTo services sendto(sockfd, buf, len, flags, dest_addr,
// addrlen) (NR=206). write(2) already handles connected sockets; this
// handler exists for the unconnected-UDP shape — notably musl's DNS
// resolver, which creates an AF_INET DGRAM socket and sendto's each
// query to the resolver directly. Every DNS lookup the guest makes
// flows through this path.
//
// aarch64 layout:
//
//	x0 = sockfd, x1 = buf, x2 = len,
//	x3 = flags, x4 = dest_addr, x5 = addrlen.
//
// When dest_addr is non-NULL and resolves to an AF_INET/AF_INET6
// destination, NetGate.CheckConnect vets it against policy exactly
// like connect() does — same builtin-deny, same mode-specific rules.
// The two handlers share enforcement so there's no "bypass connect
// by using sendto" trick.
//
// dest_addr == 0 means "use the socket's connected peer", mirroring
// write(2) semantics; we skip the policy check (connect already did
// it) and let the kernel deliver EDESTADDRREQ if the socket isn't
// actually connected.
func handleSendTo(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	bufPtr := regs.X[1]
	bufLen := int(regs.X[2])
	flags := int(regs.X[3])
	destPtr := regs.X[4]
	destLen := int(regs.X[5])

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	if bufLen < 0 {
		regs.X[0] = EncodeErrno(syscall.EINVAL)
		return VerdictHandled
	}
	var buf []byte
	if bufLen > 0 {
		b, err := d.MemR.ReadBytes(bufPtr, bufLen)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		buf = b
	}

	var sa syscall.Sockaddr
	if destPtr != 0 {
		if destLen < 2 {
			regs.X[0] = EncodeErrno(syscall.EINVAL)
			return VerdictHandled
		}
		saBytes, err := d.MemR.ReadBytes(destPtr, destLen)
		if err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
		family := binary.LittleEndian.Uint16(saBytes[0:2])
		decoded, ap, derr := decodeSockaddr(family, saBytes)
		if derr != nil {
			regs.X[0] = EncodeErrno(derr)
			return VerdictHandled
		}
		if err := d.Net.CheckConnect(ap); err != nil {
			regs.X[0] = EncodeErrno(syscall.EACCES)
			return VerdictHandled
		}
		sa = decoded
	}

	if err := syscall.Sendto(hostFd, buf, flags, sa); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = uint64(bufLen)
	return VerdictHandled
}

// handleRecvFrom services recvfrom(sockfd, buf, len, flags, src_addr,
// addrlen_ptr) (NR=207). Paired with sendto for unconnected-UDP; also
// the shape musl's DNS resolver uses to read the reply. When src_addr
// is non-NULL the kernel writes the sender's sockaddr there, and the
// updated length into *addrlen.
//
// aarch64 layout:
//
//	x0 = sockfd, x1 = buf, x2 = len, x3 = flags,
//	x4 = src_addr, x5 = addrlen_ptr.
//
// We allocate a host-side buffer of len bytes, recvfrom into it, copy
// the received prefix back into guest memory, and encode the remote
// sockaddr (if requested) back to the guest. Truncation is handled by
// the kernel — MSG_TRUNC etc. pass through via flags unchanged.
func handleRecvFrom(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	bufPtr := regs.X[1]
	bufLen := int(regs.X[2])
	flags := int(regs.X[3])
	srcPtr := regs.X[4]
	srcLenPtr := regs.X[5]

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	if bufLen < 0 {
		regs.X[0] = EncodeErrno(syscall.EINVAL)
		return VerdictHandled
	}
	host := make([]byte, bufLen)
	n, from, err := syscall.Recvfrom(hostFd, host, flags)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	if n > 0 {
		if err := d.Mem.WriteBytes(bufPtr, host[:n]); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}

	if srcPtr != 0 && from != nil {
		saBytes, err := encodeSockaddr(from)
		if err != nil {
			// Unencodable family — deliver the recv result without
			// src_addr; caller can still read the payload. This is
			// preferable to failing the whole recv for exotic peers.
		} else {
			// Clamp to the guest-provided addrlen if it was supplied.
			avail := len(saBytes)
			if srcLenPtr != 0 {
				var lenBuf [4]byte
				lb, lerr := d.MemR.ReadBytes(srcLenPtr, 4)
				if lerr == nil {
					copy(lenBuf[:], lb)
					glen := int(binary.LittleEndian.Uint32(lenBuf[:]))
					if glen < avail {
						avail = glen
					}
				}
			}
			if err := d.Mem.WriteBytes(srcPtr, saBytes[:avail]); err != nil {
				regs.X[0] = EncodeErrno(err)
				return VerdictHandled
			}
			if srcLenPtr != 0 {
				var lenBuf [4]byte
				binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(saBytes)))
				if err := d.Mem.WriteBytes(srcLenPtr, lenBuf[:]); err != nil {
					regs.X[0] = EncodeErrno(err)
					return VerdictHandled
				}
			}
		}
	}

	regs.X[0] = uint64(n)
	return VerdictHandled
}

// encodeSockaddr is the inverse of decodeSockaddr: it turns the
// kernel-returned Sockaddr (AF_INET or AF_INET6) back into the wire
// format the guest expects on the other side of an out-param.
func encodeSockaddr(sa syscall.Sockaddr) ([]byte, error) {
	switch s := sa.(type) {
	case *syscall.SockaddrInet4:
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint16(buf[0:2], uint16(syscall.AF_INET))
		binary.BigEndian.PutUint16(buf[2:4], uint16(s.Port))
		copy(buf[4:8], s.Addr[:])
		return buf, nil
	case *syscall.SockaddrInet6:
		buf := make([]byte, 28)
		binary.LittleEndian.PutUint16(buf[0:2], uint16(syscall.AF_INET6))
		binary.BigEndian.PutUint16(buf[2:4], uint16(s.Port))
		copy(buf[8:24], s.Addr[:])
		binary.LittleEndian.PutUint32(buf[24:28], s.ZoneId)
		return buf, nil
	default:
		return nil, syscall.EAFNOSUPPORT
	}
}

// handleListen services listen(sockfd, backlog) (NR=201). No policy:
// turning a bound socket into a passive listener isn't a destination
// decision — bind already vetted the local address. Pass through to
// the kernel, which may itself cap backlog at SOMAXCONN.
func handleListen(d *Dispatcher, regs *Regs) Verdict {
	guestFd := int(regs.X[0])
	backlog := int(regs.X[1])

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	if err := syscall.Listen(hostFd, backlog); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleAccept services accept(sockfd, addr, addrlen) (NR=202) — the
// legacy shape that doesn't take flags. Forwarded to handleAccept4
// with flags=0.
func handleAccept(d *Dispatcher, regs *Regs) Verdict {
	return acceptCommon(d, regs, 0)
}

// handleAccept4 services accept4(sockfd, addr, addrlen, flags)
// (NR=242). flags carry SOCK_NONBLOCK and SOCK_CLOEXEC in the same
// encoding as socket(2) — forwarded to the kernel call.
func handleAccept4(d *Dispatcher, regs *Regs) Verdict {
	return acceptCommon(d, regs, int(regs.X[3]))
}

// acceptCommon is the shared body for accept / accept4. It resolves
// the listening fd, pulls the next incoming peer from the host
// kernel, enforces NetGate.CheckAccept on the peer's address, encodes
// the peer's sockaddr back into the guest's (addr, *addrlen) out-
// params, and registers the new fd in the guest's FDTable.
//
// Policy violation on the peer closes the accepted host fd before
// returning EACCES — we never hand the guest an fd that wasn't
// policy-approved, and we don't leave a dangling half-open
// connection in the kernel either.
func acceptCommon(d *Dispatcher, regs *Regs, flags int) Verdict {
	guestFd := int(regs.X[0])
	addrPtr := regs.X[1]
	addrLenPtr := regs.X[2]

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	newFd, peer, err := syscall.Accept4(hostFd, flags)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	// Peer policy check. If CheckAccept denies, close the accepted fd
	// and surface EACCES — the guest never learns the fd existed.
	if ap, ok := sockaddrToAddrPort(peer); ok {
		if err := d.Net.CheckAccept(ap); err != nil {
			_ = syscall.Close(newFd)
			regs.X[0] = EncodeErrno(syscall.EACCES)
			return VerdictHandled
		}
	}

	if addrPtr != 0 {
		saBytes, encErr := encodeSockaddr(peer)
		if encErr == nil {
			avail := len(saBytes)
			if addrLenPtr != 0 {
				lb, lerr := d.MemR.ReadBytes(addrLenPtr, 4)
				if lerr != nil {
					_ = syscall.Close(newFd)
					regs.X[0] = EncodeErrno(lerr)
					return VerdictHandled
				}
				glen := int(binary.LittleEndian.Uint32(lb))
				if glen < avail {
					avail = glen
				}
			}
			if avail > 0 {
				if err := d.Mem.WriteBytes(addrPtr, saBytes[:avail]); err != nil {
					_ = syscall.Close(newFd)
					regs.X[0] = EncodeErrno(err)
					return VerdictHandled
				}
			}
			if addrLenPtr != 0 {
				var lb [4]byte
				binary.LittleEndian.PutUint32(lb[:], uint32(len(saBytes)))
				if err := d.Mem.WriteBytes(addrLenPtr, lb[:]); err != nil {
					_ = syscall.Close(newFd)
					regs.X[0] = EncodeErrno(err)
					return VerdictHandled
				}
			}
		}
	}

	regs.X[0] = uint64(d.FDs.Allocate(newFd))
	return VerdictHandled
}

// sockaddrToAddrPort pulls a netip.AddrPort out of a kernel-returned
// Sockaddr for the two families we gate (AF_INET, AF_INET6). Returns
// ok=false for anything else — callers treat that as "no policy
// applies" (AF_UNIX peers on an accept are filesystem, not network).
func sockaddrToAddrPort(sa syscall.Sockaddr) (netip.AddrPort, bool) {
	switch s := sa.(type) {
	case *syscall.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(s.Addr), uint16(s.Port)), true
	case *syscall.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(s.Addr), uint16(s.Port)), true
	default:
		return netip.AddrPort{}, false
	}
}

// handleGetSockName services getsockname(sockfd, addr, addrlen)
// (NR=204) and its sibling handleGetPeerName handles getpeername
// (NR=205). Both read *addrlen from guest memory, ask the kernel for
// the local (or remote) sockaddr of a host fd, encode it back to
// guest memory, and update *addrlen to the full length.
//
// No policy: these are pure introspection on an fd the guest already
// owns. Needed early because libc bind-with-port-0 patterns call
// getsockname afterwards to learn the ephemeral port — without it,
// things like Go's net.Listen("tcp4", "127.0.0.1:0") can't report
// back where they're listening.
func handleGetSockName(d *Dispatcher, regs *Regs) Verdict {
	return getNameCommon(d, regs, syscall.Getsockname)
}

// handleGetPeerName services getpeername (NR=205); see getsockname for
// shape notes.
func handleGetPeerName(d *Dispatcher, regs *Regs) Verdict {
	return getNameCommon(d, regs, syscall.Getpeername)
}

// getNameCommon is the shared body for getsockname / getpeername. The
// only difference between them is which kernel routine we call; the
// caller passes it as fn.
func getNameCommon(d *Dispatcher, regs *Regs, fn func(int) (syscall.Sockaddr, error)) Verdict {
	guestFd := int(regs.X[0])
	addrPtr := regs.X[1]
	addrLenPtr := regs.X[2]

	hostFd, ok := d.FDs.Resolve(guestFd)
	if !ok {
		regs.X[0] = EncodeErrno(syscall.EBADF)
		return VerdictHandled
	}
	sa, err := fn(hostFd)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	saBytes, err := encodeSockaddr(sa)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}

	avail := len(saBytes)
	if addrLenPtr != 0 {
		lb, lerr := d.MemR.ReadBytes(addrLenPtr, 4)
		if lerr != nil {
			regs.X[0] = EncodeErrno(lerr)
			return VerdictHandled
		}
		glen := int(binary.LittleEndian.Uint32(lb))
		if glen < 0 {
			regs.X[0] = EncodeErrno(syscall.EINVAL)
			return VerdictHandled
		}
		if glen < avail {
			avail = glen
		}
	}
	if addrPtr != 0 && avail > 0 {
		if err := d.Mem.WriteBytes(addrPtr, saBytes[:avail]); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}
	if addrLenPtr != 0 {
		var lb [4]byte
		binary.LittleEndian.PutUint32(lb[:], uint32(len(saBytes)))
		if err := d.Mem.WriteBytes(addrLenPtr, lb[:]); err != nil {
			regs.X[0] = EncodeErrno(err)
			return VerdictHandled
		}
	}
	regs.X[0] = 0
	return VerdictHandled
}

// handleSocket services socket(domain, type, protocol) (NR=198). Entry
// point for the NetGate family — nothing else in the net path works
// until this one allocates a guest fd backed by a real host socket.
//
// aarch64 layout: x0 = domain, x1 = type, x2 = protocol.
//
// The `type` argument carries SOCK_* flags (SOCK_STREAM, SOCK_DGRAM,
// SOCK_RAW, ...) in the low bits plus SOCK_CLOEXEC (0x80000) and
// SOCK_NONBLOCK (0x800) as ORable modifiers. We forward the full mask
// to the host kernel; libcurl / Go stdlib / musl all set CLOEXEC on
// the socket syscall itself rather than chasing it with fcntl, so
// this behaviour matters for fd-inheritance correctness across
// fork/exec in the guest.
//
// Policy lives in NetGate.AllowSocket: mode "none" blocks AF_INET*
// with EACCES, unknown domains return EAFNOSUPPORT. See netgate.go
// for why the whitelist is narrow by default.
func handleSocket(d *Dispatcher, regs *Regs) Verdict {
	domain := int(regs.X[0])
	sockType := int(regs.X[1])
	protocol := int(regs.X[2])

	if err := d.Net.AllowSocket(domain); err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	hostFd, err := syscall.Socket(domain, sockType, protocol)
	if err != nil {
		regs.X[0] = EncodeErrno(err)
		return VerdictHandled
	}
	regs.X[0] = uint64(d.FDs.Allocate(hostFd))
	return VerdictHandled
}
