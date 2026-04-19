package gate

import "sync"

// Dispatcher is the in-process syscall dispatcher invoked by gum's
// svc hook. It owns the gates (FS, Net) and a handler table keyed by
// aarch64 syscall number. Every intercepted `svc #0` lands in
// Dispatch, which routes to a registered Handler or defaults to
// VerdictPassthrough.
//
// The type is the Go half of the ABI mirror declared in abi.go; the
// cgo marshalling that copies mojit_regs_t into Regs lives alongside
// the frida-gum build under gum/ (not yet wired as of M1).
//
// Thread-safety: the handler table is written once by
// registerDefaults()/Register() during setup and read without a lock
// on the hot path. Callers that need dynamic reconfiguration must
// swap Dispatchers atomically rather than mutating the table of a
// running instance.
type Dispatcher struct {
	FS  *FSGate
	Net *NetGate

	// Paths reads NUL-terminated C strings out of the guest's virtual
	// address space. Handlers that take path arguments (openat,
	// newfstatat, faccessat, ...) call Paths.ReadPath on regs.X[N] to
	// materialise the guest-side path before handing it to FSGate.
	//
	// NewDispatcher installs NoopPathReader, which fails every call
	// with ErrFault. The cgo bridge swaps in a real reader backed by
	// gum's in-process memory access; see path_reader.go.
	Paths PathReader

	// Mem writes handler-produced bytes into the guest's virtual
	// address space. Used by handlers that return data through a
	// guest-supplied buffer (getcwd, readlinkat, newfstatat, read, ...).
	// NewDispatcher installs NoopMemWriter — see mem_writer.go.
	Mem MemWriter

	// MemR reads fixed-length byte ranges out of guest address space.
	// Handlers that source data from a guest-supplied buffer (write,
	// pwrite, sendmsg iovecs, ioctl struct args) call MemR.ReadBytes.
	// Separate from Paths because MemR returns raw bytes of a caller-
	// specified length rather than a NUL-terminated string.
	MemR MemReader

	// FDs is the guest's file-descriptor table. Preseeded with stdio
	// (0,1,2 -> host 0,1,2) so early prints survive. Handlers that
	// allocate fds (openat, socket, accept) register the host fd with
	// FDs.Allocate; handlers that release fds (close) go through
	// FDs.Close.
	FDs *FDTable

	// handlers maps aarch64 syscall number -> Handler. An absent
	// entry means "we don't intercept this syscall" and the svc hook
	// passes it through to the kernel.
	handlers map[uint64]Handler

	// dirSnapshots holds pre-built linux_dirent64 streams keyed by
	// guest directory fd. Directories opened via handleOpenAt get a
	// snapshot built at open time that respects overlay semantics
	// (whiteouts, opaque markers, upper-shadows-lower); handleGetDents64
	// serves chunks from here and handleClose cleans up. Directory fds
	// that somehow bypass the snapshot builder fall back to a raw
	// host-fd readdir — fine for pure-upper or pure-lower scenarios
	// but loses overlay merging.
	dirSnapshotsMu sync.Mutex
	dirSnapshots   map[int]*dirSnapshot
}

// NewDispatcher builds a Dispatcher for a given Policy, constructing
// the underlying gates and installing the default handler table.
func NewDispatcher(p Policy) *Dispatcher {
	d := &Dispatcher{
		FS:           NewFSGate(p),
		Net:          NewNetGate(p.Net),
		Paths:        NoopPathReader{},
		Mem:          NoopMemWriter{},
		MemR:         NoopMemReader{},
		FDs:          NewFDTable(),
		handlers:     make(map[uint64]Handler),
		dirSnapshots: make(map[int]*dirSnapshot),
	}
	d.registerDefaults()
	return d
}

// setDirSnapshot installs a pre-built linux_dirent64 stream under a
// guest directory fd. Replaces any prior snapshot for the same fd —
// happens when a guest fd is reused after close.
func (d *Dispatcher) setDirSnapshot(guestFd int, buf []byte) {
	d.dirSnapshotsMu.Lock()
	defer d.dirSnapshotsMu.Unlock()
	d.dirSnapshots[guestFd] = &dirSnapshot{buf: buf}
}

// takeDirSnapshot removes and returns the snapshot for a guest fd.
// Returns nil if the fd has no snapshot (non-overlay dir or a
// non-directory fd). Callers use the returned pointer to advance the
// cursor; the map no longer holds a reference after take, so close
// paths don't need to clean up again.
func (d *Dispatcher) takeDirSnapshot(guestFd int) *dirSnapshot {
	d.dirSnapshotsMu.Lock()
	defer d.dirSnapshotsMu.Unlock()
	s := d.dirSnapshots[guestFd]
	return s
}

// dropDirSnapshot forgets the snapshot for a guest fd. Called from
// handleClose. A missing fd is a no-op.
func (d *Dispatcher) dropDirSnapshot(guestFd int) {
	d.dirSnapshotsMu.Lock()
	defer d.dirSnapshotsMu.Unlock()
	delete(d.dirSnapshots, guestFd)
}

// Register installs or replaces the handler for an aarch64 syscall
// number. Intended for policy overrides (e.g. a test that wants to
// observe dispatch routing) and for future dynamic reconfiguration;
// the default handler table is installed by registerDefaults().
func (d *Dispatcher) Register(nr uint64, h Handler) {
	d.handlers[nr] = h
}

// Dispatch is the hot path. gum's cgo bridge copies mojit_regs_t into
// regs and calls this once per guest svc instruction. The returned
// Verdict tells the svc trampoline whether to treat regs.X[0] as the
// result (Handled), re-issue the kernel syscall (Passthrough), or
// kill the guest thread (Kill).
//
// Unknown / unhooked syscalls default to Passthrough. This is the
// correct behaviour for syscalls that carry no policy (clock_gettime,
// getrandom, futex, sigaction, nanosleep, ...): the guest gets the
// real kernel behaviour without the gate having to enumerate them.
// Syscalls that DO carry policy must be explicitly registered —
// omitting one is a bug, not a silent allow.
//
// Dispatch never panics. A nil regs is treated as a policy violation
// and returns VerdictKill so the svc hook can raise SIGSYS.
func (d *Dispatcher) Dispatch(regs *Regs) Verdict {
	if regs == nil {
		return VerdictKill
	}
	if h, ok := d.handlers[regs.NR]; ok {
		return h(d, regs)
	}
	return VerdictPassthrough
}

// registerDefaults installs the default handler table.
//
// TODO(M2): add openat / newfstatat / faccessat / getcwd / readlinkat
// / mkdirat / unlinkat / renameat handlers. chdir is wired below as
// the simplest pure-one-path handler that exercises the
// PathReader → AbsFromGuest → FSGate.Resolve → host-syscall chain.
//
// TODO(M3): populate with socket / connect / bind / send* / recv* /
// getsockname handlers that use NetGate.CheckConnect and create real
// host sockets.
//
// Syscalls not listed here fall through to VerdictPassthrough — the
// correct behaviour for policy-free calls (futex, clock_gettime,
// getrandom, ...) and the safe default during bring-up.
func (d *Dispatcher) registerDefaults() {
	d.handlers[SysChDir] = handleChDir
	d.handlers[SysGetXattr] = handleGetXattr
	d.handlers[SysSetXattr] = handleSetXattr
	d.handlers[SysFGetXattr] = handleFGetXattr
	d.handlers[SysFSetXattr] = handleFSetXattr
	d.handlers[SysListXattr] = handleListXattr
	d.handlers[SysFListXattr] = handleFListXattr
	d.handlers[SysRemoveXattr] = handleRemoveXattr
	d.handlers[SysFRemoveXattr] = handleFRemoveXattr
	d.handlers[SysFAccessAt] = handleFAccessAt
	d.handlers[SysFAccessAt2] = handleFAccessAt
	d.handlers[SysGetCwd] = handleGetCwd
	d.handlers[SysReadLinkAt] = handleReadLinkAt
	d.handlers[SysOpenAt] = handleOpenAt
	d.handlers[SysClose] = handleClose
	d.handlers[SysDup] = handleDup
	d.handlers[SysDup3] = handleDup3
	d.handlers[SysFCntl] = handleFcntl
	d.handlers[SysPipe2] = handlePipe2
	d.handlers[SysLSeek] = handleLSeek
	d.handlers[SysLinkAt] = handleLinkAt
	d.handlers[SysGetDents64] = handleGetDents64
	d.handlers[SysFTruncate] = handleFTruncate
	d.handlers[SysTruncate] = handleTruncate
	d.handlers[SysStatFs] = handleStatFs
	d.handlers[SysFStatFs] = handleFStatFs
	d.handlers[SysFChMod] = handleFChMod
	d.handlers[SysFChModAt] = handleFChModAt
	d.handlers[SysFChOwn] = handleFChOwn
	d.handlers[SysFChOwnAt] = handleFChOwnAt
	d.handlers[SysUtimensAt] = handleUtimensAt
	d.handlers[SysRead] = handleRead
	d.handlers[SysWrite] = handleWrite
	d.handlers[SysNewFStatAt] = handleNewFStatAt
	d.handlers[SysFStat] = handleFStat
	d.handlers[SysMkdirAt] = handleMkdirAt
	d.handlers[SysSymlinkAt] = handleSymlinkAt
	d.handlers[SysUnlinkAt] = handleUnlinkAt
	d.handlers[SysRenameAt] = handleRenameAt
	d.handlers[SysRenameAt2] = handleRenameAt
	d.handlers[SysSocket] = handleSocket
	d.handlers[SysConnect] = handleConnect
	d.handlers[SysSendTo] = handleSendTo
	d.handlers[SysRecvFrom] = handleRecvFrom
}
