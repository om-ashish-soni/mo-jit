package gate

// Dispatcher is the in-process syscall dispatcher invoked by gum's
// svc hook. It owns the three gates and routes each intercepted
// syscall to the appropriate one.
//
// TODO(M2, M3): wire real svc handlers. The current stub exists so
// downstream consumers (cmd/mojit-run, the mo-code adapter) can import
// the package and compile against a stable API shape. The real handler
// table lands alongside the gum C ABI in M2.
type Dispatcher struct {
	FS  *FSGate
	Net *NetGate
}

// NewDispatcher builds a Dispatcher for a given Policy, constructing
// the underlying gates.
func NewDispatcher(p Policy) *Dispatcher {
	return &Dispatcher{
		FS:  NewFSGate(p),
		Net: NewNetGate(p.Net),
	}
}
