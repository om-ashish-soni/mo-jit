package gate

import (
	"errors"
	"testing"
)

func TestNoopMemWriterAlwaysFaults(t *testing.T) {
	var w MemWriter = NoopMemWriter{}
	if err := w.WriteBytes(0x1234, []byte("hello")); !errors.Is(err, ErrFault) {
		t.Errorf("NoopMemWriter.WriteBytes err = %v, want ErrFault", err)
	}
}

func TestNewDispatcherInstallsNoopMemWriter(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: "/tmp/lower"})
	if d.Mem == nil {
		t.Fatal("NewDispatcher left Mem nil")
	}
	if err := d.Mem.WriteBytes(0x1, []byte("x")); !errors.Is(err, ErrFault) {
		t.Errorf("default Mem.WriteBytes err = %v, want ErrFault", err)
	}
}

// FakeMemWriter is the symmetrical counterpart to FakePathReader.
// Tests stage guest-memory regions (slice backed by ptr) and handlers
// under test write through FakeMemWriter. The test then asserts on
// the staged buffer.
//
// Bytes are indexed by pointer value: a write of N bytes at ptr P
// lands as Bytes[P]=b0, Bytes[P+1]=b1, ... The zero pointer (NULL)
// always faults. Unknown pointers are auto-staged on first write so
// simple tests don't need to pre-declare every buffer.
type FakeMemWriter struct {
	Bytes map[uint64]byte
	// DeniedPtrs is an optional set of pointers that fault on write,
	// used to exercise the EFAULT path without needing NULL.
	DeniedPtrs map[uint64]bool
}

// WriteBytes stores data into the byte map at consecutive addresses
// starting at ptr. Mirrors real MMU behaviour only inasmuch as tests
// need: it's a dense address-indexed buffer, not a page table.
func (f *FakeMemWriter) WriteBytes(ptr uint64, data []byte) error {
	if ptr == 0 {
		return ErrFault
	}
	if f.DeniedPtrs != nil && f.DeniedPtrs[ptr] {
		return ErrFault
	}
	if f.Bytes == nil {
		f.Bytes = map[uint64]byte{}
	}
	for i, b := range data {
		f.Bytes[ptr+uint64(i)] = b
	}
	return nil
}

// Read reconstructs the n bytes staged at ptr by prior WriteBytes
// calls. Missing indices default to 0 so tests can check for "was
// anything written here".
func (f *FakeMemWriter) Read(ptr uint64, n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		if v, ok := f.Bytes[ptr+uint64(i)]; ok {
			out[i] = v
		}
	}
	return out
}

func TestFakeMemWriterRoundTrips(t *testing.T) {
	f := &FakeMemWriter{}
	if err := f.WriteBytes(0x2000, []byte("hello\x00")); err != nil {
		t.Fatal(err)
	}
	got := f.Read(0x2000, 6)
	if string(got) != "hello\x00" {
		t.Errorf("Read after WriteBytes: got %q, want %q", got, "hello\x00")
	}
}

func TestFakeMemWriterNullPointerFaults(t *testing.T) {
	f := &FakeMemWriter{}
	if err := f.WriteBytes(0, []byte("x")); !errors.Is(err, ErrFault) {
		t.Errorf("null ptr err = %v, want ErrFault", err)
	}
}

func TestFakeMemWriterDeniedPtrFaults(t *testing.T) {
	f := &FakeMemWriter{DeniedPtrs: map[uint64]bool{0xbad: true}}
	if err := f.WriteBytes(0xbad, []byte("x")); !errors.Is(err, ErrFault) {
		t.Errorf("denied ptr err = %v, want ErrFault", err)
	}
	// A different pointer must still succeed.
	if err := f.WriteBytes(0xcafe, []byte("x")); err != nil {
		t.Errorf("non-denied ptr err = %v, want nil", err)
	}
}
