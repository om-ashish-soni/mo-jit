package gate

import (
	"errors"
	"testing"
)

func TestNoopPathReaderAlwaysFaults(t *testing.T) {
	var r PathReader = NoopPathReader{}
	got, err := r.ReadPath(0x1234, 4096)
	if !errors.Is(err, ErrFault) {
		t.Errorf("NoopPathReader.ReadPath err = %v, want ErrFault", err)
	}
	if got != "" {
		t.Errorf("NoopPathReader.ReadPath returned %q, want empty string", got)
	}
}

func TestNewDispatcherInstallsNoopPathReader(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: "/tmp/lower"})
	if d.Paths == nil {
		t.Fatal("NewDispatcher left Paths nil; handlers would panic on first path arg")
	}
	if _, err := d.Paths.ReadPath(0x1, 16); !errors.Is(err, ErrFault) {
		t.Errorf("default Paths.ReadPath err = %v, want ErrFault", err)
	}
}

// FakePathReader is a test double used by handler tests to stage
// guest-memory contents without a running gum runtime. A handler
// under test asks the Dispatcher for Paths.ReadPath(ptr, max), the
// fake looks ptr up in its map, and the test asserts on the result.
type FakePathReader struct {
	Entries map[uint64]string
}

// ReadPath returns the registered entry for ptr or ErrFault if the
// pointer is unknown, zero, or the registered string exceeds maxLen.
// The length check mirrors the real reader's truncation semantics so
// handler tests exercise the error path when max is too small.
func (f *FakePathReader) ReadPath(ptr uint64, maxLen int) (string, error) {
	if ptr == 0 {
		return "", ErrFault
	}
	s, ok := f.Entries[ptr]
	if !ok {
		return "", ErrFault
	}
	if len(s)+1 > maxLen {
		return "", ErrFault
	}
	return s, nil
}

func TestFakePathReaderServesRegisteredPointer(t *testing.T) {
	f := &FakePathReader{Entries: map[uint64]string{
		0xcafe: "/etc/hosts",
	}}
	got, err := f.ReadPath(0xcafe, 4096)
	if err != nil {
		t.Fatalf("ReadPath: %v", err)
	}
	if got != "/etc/hosts" {
		t.Errorf("ReadPath = %q, want /etc/hosts", got)
	}
}

func TestFakePathReaderUnknownPointerFaults(t *testing.T) {
	f := &FakePathReader{Entries: map[uint64]string{0xcafe: "/etc/hosts"}}
	if _, err := f.ReadPath(0xbeef, 4096); !errors.Is(err, ErrFault) {
		t.Errorf("unknown ptr err = %v, want ErrFault", err)
	}
}

func TestFakePathReaderNullPointerFaults(t *testing.T) {
	f := &FakePathReader{Entries: map[uint64]string{}}
	if _, err := f.ReadPath(0, 4096); !errors.Is(err, ErrFault) {
		t.Errorf("null ptr err = %v, want ErrFault", err)
	}
}

func TestFakePathReaderMaxLenEnforced(t *testing.T) {
	f := &FakePathReader{Entries: map[uint64]string{0xcafe: "/etc/hosts"}}
	// 10 bytes of content + 1 NUL = 11, so maxLen=10 must fault.
	if _, err := f.ReadPath(0xcafe, 10); !errors.Is(err, ErrFault) {
		t.Errorf("oversize path err = %v, want ErrFault", err)
	}
	if _, err := f.ReadPath(0xcafe, 11); err != nil {
		t.Errorf("exact-fit maxLen err = %v, want nil", err)
	}
}

// A handler under test reaches the PathReader through the Dispatcher
// passed to it. This pins the contract: handlers do NOT close over a
// PathReader at registration time — they pull it from d.Paths on
// every invocation so tests can swap the reader per-call.
func TestHandlerReachesPathReaderThroughDispatcher(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: "/tmp/lower"})
	d.Paths = &FakePathReader{Entries: map[uint64]string{
		0xcafe: "/data/foo",
	}}

	var seen string
	d.Register(SysOpenAt, func(d *Dispatcher, regs *Regs) Verdict {
		path, err := d.Paths.ReadPath(regs.X[1], 4096)
		if err != nil {
			return VerdictKill
		}
		seen = path
		return VerdictHandled
	})

	r := &Regs{NR: SysOpenAt}
	r.X[1] = 0xcafe
	if v := d.Dispatch(r); v != VerdictHandled {
		t.Fatalf("Dispatch: got %s, want handled", v)
	}
	if seen != "/data/foo" {
		t.Errorf("handler read %q, want /data/foo", seen)
	}
}
