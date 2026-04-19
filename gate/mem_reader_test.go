package gate

import (
	"bytes"
	"errors"
	"testing"
)

func TestNoopMemReaderAlwaysFaults(t *testing.T) {
	var r MemReader = NoopMemReader{}
	got, err := r.ReadBytes(0x1234, 16)
	if !errors.Is(err, ErrFault) {
		t.Errorf("NoopMemReader.ReadBytes err = %v, want ErrFault", err)
	}
	if got != nil {
		t.Errorf("NoopMemReader.ReadBytes returned %v, want nil", got)
	}
}

func TestNewDispatcherInstallsNoopMemReader(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: "/tmp/lower"})
	if d.MemR == nil {
		t.Fatal("NewDispatcher left MemR nil")
	}
	if _, err := d.MemR.ReadBytes(0x1, 4); !errors.Is(err, ErrFault) {
		t.Errorf("default MemR.ReadBytes err = %v, want ErrFault", err)
	}
}

// FakeMemReader is the mirror of FakeMemWriter: an address-indexed
// byte map that returns the contiguous slice starting at ptr. Any
// byte missing from the map at ptr..ptr+n defaults to 0, so tests
// that only care about the first few bytes of a larger read don't
// need to fully populate the range.
type FakeMemReader struct {
	Bytes      map[uint64]byte
	DeniedPtrs map[uint64]bool
}

// ReadBytes returns n bytes starting at ptr, or ErrFault if ptr is
// zero or in DeniedPtrs.
func (f *FakeMemReader) ReadBytes(ptr uint64, n int) ([]byte, error) {
	if ptr == 0 {
		return nil, ErrFault
	}
	if f.DeniedPtrs != nil && f.DeniedPtrs[ptr] {
		return nil, ErrFault
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		if v, ok := f.Bytes[ptr+uint64(i)]; ok {
			out[i] = v
		}
	}
	return out, nil
}

// Stage copies src into f.Bytes starting at ptr. Convenience for
// tests that want to pre-populate a guest buffer.
func (f *FakeMemReader) Stage(ptr uint64, src []byte) {
	if f.Bytes == nil {
		f.Bytes = map[uint64]byte{}
	}
	for i, b := range src {
		f.Bytes[ptr+uint64(i)] = b
	}
}

func TestFakeMemReaderRoundTrips(t *testing.T) {
	f := &FakeMemReader{}
	f.Stage(0x7000, []byte("hello"))
	got, err := f.ReadBytes(0x7000, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Errorf("ReadBytes = %q, want hello", got)
	}
}

func TestFakeMemReaderUnsetBytesZero(t *testing.T) {
	f := &FakeMemReader{}
	f.Stage(0x7100, []byte{0xab})
	got, err := f.ReadBytes(0x7100, 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xab, 0, 0, 0}
	if !bytes.Equal(got, want) {
		t.Errorf("ReadBytes = %v, want %v", got, want)
	}
}

func TestFakeMemReaderNullPointerFaults(t *testing.T) {
	f := &FakeMemReader{}
	if _, err := f.ReadBytes(0, 4); !errors.Is(err, ErrFault) {
		t.Errorf("null ptr err = %v, want ErrFault", err)
	}
}

func TestFakeMemReaderDeniedPtrFaults(t *testing.T) {
	f := &FakeMemReader{DeniedPtrs: map[uint64]bool{0xbad: true}}
	if _, err := f.ReadBytes(0xbad, 4); !errors.Is(err, ErrFault) {
		t.Errorf("denied ptr err = %v, want ErrFault", err)
	}
	if _, err := f.ReadBytes(0xcafe, 4); err != nil {
		t.Errorf("non-denied ptr err = %v, want nil", err)
	}
}
