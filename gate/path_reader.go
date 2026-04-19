package gate

import "errors"

// ErrFault mirrors Linux EFAULT — the translation that a handler
// should apply when a guest pointer cannot be safely dereferenced.
// Callers convert this to -EFAULT in regs.X[0] on the syscall return
// path.
var ErrFault = errors.New("gate: guest pointer fault")

// PathReader reads a NUL-terminated C string from the guest's virtual
// address space. The production implementation (landing alongside
// the frida-gum build; the guest shares the gate's address space
// since gum instruments in-process) dereferences the pointer
// directly under the protection of the gum code cache; a defensive
// version can fall back to process_vm_readv.
//
// Contract:
//   - maxLen caps the number of bytes read, including any NUL. A
//     longer string returns ErrFault (so callers cannot be fooled
//     into reading past a page boundary).
//   - The returned string is the bytes up to but not including the
//     first NUL.
//   - ptr == 0 always returns ErrFault.
//   - ReadPath MUST be safe under concurrent invocation from
//     multiple guest threads.
type PathReader interface {
	ReadPath(ptr uint64, maxLen int) (string, error)
}

// NoopPathReader is the default PathReader installed on a fresh
// Dispatcher. Every ReadPath call fails with ErrFault.
//
// This is deliberate. Until the cgo bridge swaps in a real reader,
// any handler that tries to read a guest path is running in a
// misconfigured setup — failing loudly is safer than silently
// pretending a zero-length path was supplied.
type NoopPathReader struct{}

// ReadPath always returns ErrFault.
func (NoopPathReader) ReadPath(uint64, int) (string, error) {
	return "", ErrFault
}
