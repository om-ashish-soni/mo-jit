package gate

import (
	"bytes"
	"encoding/binary"
	"syscall"
	"testing"
)

func newPipe2Harness(t *testing.T) *Dispatcher {
	t.Helper()
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	d.FDs = &FDTable{entries: map[int]int{}}
	d.Mem = &FakeMemWriter{}
	return d
}

func TestPipe2WritesTwoGuestFdsLittleEndian(t *testing.T) {
	d := newPipe2Harness(t)
	mw := d.Mem.(*FakeMemWriter)

	regs := &Regs{NR: SysPipe2}
	regs.X[0] = 0xd000
	regs.X[1] = 0
	d.Dispatch(regs)

	if int64(regs.X[0]) != 0 {
		t.Fatalf("pipe2 returned %d, want 0", int64(regs.X[0]))
	}
	buf := mw.Read(0xd000, 8)
	if len(buf) != 8 {
		t.Fatalf("wrote %d bytes, want 8", len(buf))
	}
	gR := int32(binary.LittleEndian.Uint32(buf[0:4]))
	gW := int32(binary.LittleEndian.Uint32(buf[4:8]))
	if gR == gW {
		t.Errorf("read end == write end = %d", gR)
	}
	if _, ok := d.FDs.Resolve(int(gR)); !ok {
		t.Errorf("read-end guest fd %d not registered", gR)
	}
	if _, ok := d.FDs.Resolve(int(gW)); !ok {
		t.Errorf("write-end guest fd %d not registered", gW)
	}
	// Clean up host fds to keep the test runner tidy.
	if h, ok := d.FDs.Close(int(gR)); ok {
		_ = syscall.Close(h)
	}
	if h, ok := d.FDs.Close(int(gW)); ok {
		_ = syscall.Close(h)
	}
}

func TestPipe2EndToEndThroughReadWrite(t *testing.T) {
	// pipe2 → write "ping" to the write end → read 4 bytes from the
	// read end via the gate's own handleRead. Proves the guest fds
	// from pipe2 plug into the rest of the dispatch table.
	d := newPipe2Harness(t)
	reader := &FakeMemReader{}
	d.MemR = reader
	mw := d.Mem.(*FakeMemWriter)

	pr := &Regs{NR: SysPipe2}
	pr.X[0] = 0xe000
	pr.X[1] = 0
	d.Dispatch(pr)
	if int64(pr.X[0]) != 0 {
		t.Fatalf("pipe2 errored: %d", int64(pr.X[0]))
	}
	payload := mw.Read(0xe000, 8)
	gR := int(int32(binary.LittleEndian.Uint32(payload[0:4])))
	gW := int(int32(binary.LittleEndian.Uint32(payload[4:8])))

	reader.Stage(0xe100, []byte("ping"))

	w := &Regs{NR: SysWrite}
	w.X[0] = uint64(gW)
	w.X[1] = 0xe100
	w.X[2] = 4
	d.Dispatch(w)
	if int64(w.X[0]) != 4 {
		t.Fatalf("write: got %d, want 4", int64(w.X[0]))
	}

	r := &Regs{NR: SysRead}
	r.X[0] = uint64(gR)
	r.X[1] = 0xe200
	r.X[2] = 16
	d.Dispatch(r)
	if int64(r.X[0]) != 4 {
		t.Fatalf("read: got %d, want 4", int64(r.X[0]))
	}
	if got := mw.Read(0xe200, 4); !bytes.Equal(got, []byte("ping")) {
		t.Errorf("round-trip = %q, want ping", got)
	}

	if h, ok := d.FDs.Close(gR); ok {
		_ = syscall.Close(h)
	}
	if h, ok := d.FDs.Close(gW); ok {
		_ = syscall.Close(h)
	}
}

func TestPipe2CloexecPropagatesToHostFds(t *testing.T) {
	d := newPipe2Harness(t)
	mw := d.Mem.(*FakeMemWriter)

	regs := &Regs{NR: SysPipe2}
	regs.X[0] = 0xf000
	regs.X[1] = uint64(syscall.O_CLOEXEC)
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("pipe2(O_CLOEXEC) errored: %d", int64(regs.X[0]))
	}
	buf := mw.Read(0xf000, 8)
	gR := int(int32(binary.LittleEndian.Uint32(buf[0:4])))
	gW := int(int32(binary.LittleEndian.Uint32(buf[4:8])))
	hR, _ := d.FDs.Resolve(gR)
	hW, _ := d.FDs.Resolve(gW)
	if !hostFdCloexec(t, hR) {
		t.Errorf("read end host fd %d missing CLOEXEC", hR)
	}
	if !hostFdCloexec(t, hW) {
		t.Errorf("write end host fd %d missing CLOEXEC", hW)
	}
	if h, ok := d.FDs.Close(gR); ok {
		_ = syscall.Close(h)
	}
	if h, ok := d.FDs.Close(gW); ok {
		_ = syscall.Close(h)
	}
}

func TestPipe2InvalidFlagsAreEINVAL(t *testing.T) {
	d := newPipe2Harness(t)
	regs := &Regs{NR: SysPipe2}
	regs.X[0] = 0xaa00
	regs.X[1] = 0xdead // garbage flag bits
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EINVAL)
}

func TestPipe2NullBufIsEFAULT(t *testing.T) {
	d := newPipe2Harness(t)
	regs := &Regs{NR: SysPipe2}
	regs.X[0] = 0
	regs.X[1] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EFAULT)
}

func TestPipe2DeniedBufClosesHostFds(t *testing.T) {
	// If the WriteBytes cleanup path misfires we'd leak host fds
	// AND leave ghost entries in the table. Guard against both.
	d := newPipe2Harness(t)
	d.Mem = &FakeMemWriter{DeniedPtrs: map[uint64]bool{0xba00: true}}

	before := d.FDs.Len()

	regs := &Regs{NR: SysPipe2}
	regs.X[0] = 0xba00
	regs.X[1] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EFAULT)

	if got := d.FDs.Len(); got != before {
		t.Errorf("FDTable grew on failure: before=%d, after=%d", before, got)
	}
}
