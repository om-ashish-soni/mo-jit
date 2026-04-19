package gate

// MemReader reads an exact number of bytes from the guest's virtual
// address space. Symmetrical to MemWriter. PathReader handles the
// "read until NUL, bounded by maxLen" path-argument case; MemReader
// handles fixed-length buffers (write(2)'s source, struct-holding
// ioctl args, msghdr iovecs).
//
// Contract:
//   - ptr == 0 always returns ErrFault.
//   - A partial read (page straddled where only the first page is
//     mapped) is a fault — ReadBytes must return ErrFault rather
//     than a truncated slice.
//   - The returned slice is freshly allocated; implementations must
//     not hand out references to guest memory.
//   - ReadBytes MUST be safe under concurrent invocation.
type MemReader interface {
	ReadBytes(ptr uint64, n int) ([]byte, error)
}

// NoopMemReader is the default MemReader installed on a fresh
// Dispatcher. Every ReadBytes call fails with ErrFault, keeping the
// same loud-failure discipline as NoopPathReader and NoopMemWriter.
type NoopMemReader struct{}

// ReadBytes always returns ErrFault.
func (NoopMemReader) ReadBytes(uint64, int) ([]byte, error) {
	return nil, ErrFault
}
