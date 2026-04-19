package gate

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

	// handlers maps aarch64 syscall number -> Handler. An absent
	// entry means "we don't intercept this syscall" and the svc hook
	// passes it through to the kernel.
	handlers map[uint64]Handler
}

// NewDispatcher builds a Dispatcher for a given Policy, constructing
// the underlying gates and installing the default handler table.
func NewDispatcher(p Policy) *Dispatcher {
	d := &Dispatcher{
		FS:       NewFSGate(p),
		Net:      NewNetGate(p.Net),
		Paths:    NoopPathReader{},
		handlers: make(map[uint64]Handler),
	}
	d.registerDefaults()
	return d
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
// TODO(M2): populate with openat / newfstatat / faccessat / chdir /
// getcwd / readlinkat / mkdirat / unlinkat / renameat handlers that
// use FSGate.Resolve. Path args require reading guest memory, which
// the cgo bridge will expose via a PathReader interface — that
// interface lands with the first real handler implementation.
//
// TODO(M3): populate with socket / connect / bind / send* / recv* /
// getsockname handlers that use NetGate.CheckConnect and create real
// host sockets.
//
// For now the table is empty: every syscall falls through to
// VerdictPassthrough. This is the correct behaviour for a
// not-yet-wired build — the unit under test is the dispatch
// mechanism, not the policy.
func (d *Dispatcher) registerDefaults() {
	// Intentionally empty until M2 path-reader + M3 net handlers
	// land. See TODO comments above.
}
