package gate

// MemWriter is the write counterpart to PathReader. Handlers that
// return data into guest buffers (getcwd, readlinkat, newfstatat, ...)
// stage the bytes on the Go side and hand them to WriteBytes for
// placement into guest address space.
//
// Contract:
//   - ptr == 0 always returns ErrFault.
//   - WriteBytes MUST be safe under concurrent invocation from
//     multiple guest threads writing into disjoint guest regions.
//   - A partial write (page straddled where only the first page is
//     mapped, say) is a fault — WriteBytes must write all of data or
//     report ErrFault.
//   - data is never mutated by the implementation.
//
// The production implementation landing with the frida-gum bridge
// dereferences the guest pointer in-process; a defensive fallback
// can use process_vm_writev.
type MemWriter interface {
	WriteBytes(ptr uint64, data []byte) error
}

// NoopMemWriter is the default MemWriter installed on a fresh
// Dispatcher. Every WriteBytes call fails with ErrFault, matching
// NoopPathReader's loud-failure discipline: silently dropping writes
// would let handlers quietly report success to a guest that never
// sees the bytes.
type NoopMemWriter struct{}

// WriteBytes always returns ErrFault.
func (NoopMemWriter) WriteBytes(uint64, []byte) error {
	return ErrFault
}
