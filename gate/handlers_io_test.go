package gate

import (
	"bytes"
	"os"
	"syscall"
	"testing"
)

// newIOHarness builds a Dispatcher with a fresh, fully test-owned
// FDTable (not the stdio-preseeded default) so read/write tests
// cannot accidentally touch the test runner's stdin/stdout/stderr.
func newIOHarness(t *testing.T) *Dispatcher {
	t.Helper()
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	d.FDs = &FDTable{entries: map[int]int{}}
	return d
}

// newPipeFds returns a fresh host pipe (read-end, write-end) and
// registers cleanup on t. It's the simplest real kernel I/O we can
// exercise without polluting stdio.
func newPipeFds(t *testing.T) (rFd, wFd int) {
	t.Helper()
	fds := make([]int, 2)
	if err := syscall.Pipe2(fds, syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
	})
	return fds[0], fds[1]
}

func TestWriteCopiesGuestBytesToHostFd(t *testing.T) {
	d := newIOHarness(t)
	hostR, hostW := newPipeFds(t)

	guestFd := d.FDs.Allocate(hostW)

	r := &FakeMemReader{}
	r.Stage(0x8000, []byte("hello pipe"))
	d.MemR = r

	regs := &Regs{NR: SysWrite}
	regs.X[0] = uint64(guestFd)
	regs.X[1] = 0x8000
	regs.X[2] = 10
	d.Dispatch(regs)

	if int64(regs.X[0]) != 10 {
		t.Fatalf("write return: got %d, want 10", int64(regs.X[0]))
	}

	buf := make([]byte, 16)
	n, err := syscall.Read(hostR, buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], []byte("hello pipe")) {
		t.Errorf("pipe contents = %q, want hello pipe", buf[:n])
	}
}

func TestReadCopiesHostBytesIntoGuestBuffer(t *testing.T) {
	d := newIOHarness(t)
	hostR, hostW := newPipeFds(t)

	if _, err := syscall.Write(hostW, []byte("greetings")); err != nil {
		t.Fatal(err)
	}

	guestFd := d.FDs.Allocate(hostR)

	w := &FakeMemWriter{}
	d.Mem = w

	regs := &Regs{NR: SysRead}
	regs.X[0] = uint64(guestFd)
	regs.X[1] = 0x9000
	regs.X[2] = 32

	d.Dispatch(regs)

	if int64(regs.X[0]) != 9 {
		t.Fatalf("read return: got %d, want 9", int64(regs.X[0]))
	}
	got := w.Read(0x9000, 9)
	if string(got) != "greetings" {
		t.Errorf("guest buffer = %q, want greetings", got)
	}
	// Untouched bytes past the read must not be written.
	if _, present := w.Bytes[0x9000+9]; present {
		t.Errorf("read wrote past returned length")
	}
}

func TestReadUnknownFdReturnsEBADF(t *testing.T) {
	d := newIOHarness(t)
	d.Mem = &FakeMemWriter{}

	regs := &Regs{NR: SysRead}
	regs.X[0] = 999
	regs.X[1] = 0x9100
	regs.X[2] = 8
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func TestWriteUnknownFdReturnsEBADF(t *testing.T) {
	d := newIOHarness(t)
	d.MemR = &FakeMemReader{}

	regs := &Regs{NR: SysWrite}
	regs.X[0] = 999
	regs.X[1] = 0x9200
	regs.X[2] = 8
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func TestWriteSourceFaultReturnsEFAULT(t *testing.T) {
	d := newIOHarness(t)
	_, hostW := newPipeFds(t)
	guestFd := d.FDs.Allocate(hostW)

	// NULL source pointer.
	d.MemR = &FakeMemReader{}
	regs := &Regs{NR: SysWrite}
	regs.X[0] = uint64(guestFd)
	regs.X[1] = 0
	regs.X[2] = 4
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EFAULT)
}

func TestReadDestFaultReturnsEFAULT(t *testing.T) {
	d := newIOHarness(t)
	hostR, hostW := newPipeFds(t)
	if _, err := syscall.Write(hostW, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	guestFd := d.FDs.Allocate(hostR)

	// Denied destination pointer — mem.WriteBytes will fault.
	d.Mem = &FakeMemWriter{DeniedPtrs: map[uint64]bool{0x9300: true}}
	regs := &Regs{NR: SysRead}
	regs.X[0] = uint64(guestFd)
	regs.X[1] = 0x9300
	regs.X[2] = 16
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EFAULT)
}

func TestReadZeroCountShortCircuits(t *testing.T) {
	d := newIOHarness(t)
	hostR, _ := newPipeFds(t)
	guestFd := d.FDs.Allocate(hostR)

	// MemWriter would fault if called; we check it isn't.
	d.Mem = NoopMemWriter{}

	regs := &Regs{NR: SysRead}
	regs.X[0] = uint64(guestFd)
	regs.X[1] = 0x1111
	regs.X[2] = 0
	d.Dispatch(regs)

	if regs.X[0] != 0 {
		t.Errorf("read(count=0) = %#x, want 0", regs.X[0])
	}
}

func TestWriteZeroCountShortCircuits(t *testing.T) {
	d := newIOHarness(t)
	_, hostW := newPipeFds(t)
	guestFd := d.FDs.Allocate(hostW)

	d.MemR = NoopMemReader{}

	regs := &Regs{NR: SysWrite}
	regs.X[0] = uint64(guestFd)
	regs.X[1] = 0x1111
	regs.X[2] = 0
	d.Dispatch(regs)

	if regs.X[0] != 0 {
		t.Errorf("write(count=0) = %#x, want 0", regs.X[0])
	}
}

func TestReadFromBadHostFdPropagatesErrno(t *testing.T) {
	// Wire a guest fd to a host fd we know is closed, exercising
	// the syscall.Read errno-propagation path.
	d := newIOHarness(t)
	d.Mem = &FakeMemWriter{}

	hostR, _ := newPipeFds(t)
	// Close the host side behind the table's back — subsequent
	// read on the guest fd will hit EBADF via the kernel.
	_ = syscall.Close(hostR)
	guestFd := d.FDs.Allocate(hostR)

	regs := &Regs{NR: SysRead}
	regs.X[0] = uint64(guestFd)
	regs.X[1] = 0xaa00
	regs.X[2] = 8
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func TestReadWriteRoundTripThroughOpenAt(t *testing.T) {
	// End-to-end: openat(O_CREAT) on upper, write "data", close,
	// reopen O_RDONLY, read, compare. Proves the whole chain wires
	// together correctly for a real file — openat->FDTable->write->
	// read->MemWriter.
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	paths := &FakePathReader{Entries: map[uint64]string{}}
	reader := &FakeMemReader{}
	writer := &FakeMemWriter{}
	d.Paths = paths
	d.MemR = reader
	d.Mem = writer

	// openat(AT_FDCWD, "/note.txt", O_WRONLY|O_CREAT, 0600)
	paths.Entries[0xb000] = "/note.txt"
	reader.Stage(0xb100, []byte("data"))

	open := &Regs{NR: SysOpenAt}
	open.X[0] = atFDCWDAsX0()
	open.X[1] = 0xb000
	open.X[2] = uint64(syscall.O_WRONLY | syscall.O_CREAT)
	open.X[3] = 0o600
	d.Dispatch(open)
	if int64(open.X[0]) < 0 {
		t.Fatalf("openat write: X[0]=%d", int64(open.X[0]))
	}
	wrFd := open.X[0]

	w := &Regs{NR: SysWrite}
	w.X[0] = wrFd
	w.X[1] = 0xb100
	w.X[2] = 4
	d.Dispatch(w)
	if int64(w.X[0]) != 4 {
		t.Fatalf("write: got %d, want 4", int64(w.X[0]))
	}

	c := &Regs{NR: SysClose}
	c.X[0] = wrFd
	d.Dispatch(c)

	// Reopen read-only, read back.
	open2 := &Regs{NR: SysOpenAt}
	open2.X[0] = atFDCWDAsX0()
	open2.X[1] = 0xb000
	open2.X[2] = uint64(syscall.O_RDONLY)
	d.Dispatch(open2)
	if int64(open2.X[0]) < 0 {
		t.Fatalf("openat read: X[0]=%d", int64(open2.X[0]))
	}
	rdFd := open2.X[0]

	r := &Regs{NR: SysRead}
	r.X[0] = rdFd
	r.X[1] = 0xb200
	r.X[2] = 16
	d.Dispatch(r)
	if int64(r.X[0]) != 4 {
		t.Fatalf("read: got %d, want 4", int64(r.X[0]))
	}
	got := writer.Read(0xb200, 4)
	if string(got) != "data" {
		t.Errorf("round-trip payload = %q, want data", got)
	}

	// Clean up
	c2 := &Regs{NR: SysClose}
	c2.X[0] = rdFd
	d.Dispatch(c2)
	// And remove the file from the underlying upper dir to keep
	// t.TempDir cleanup happy (it can clean files we owned).
	_ = os.Remove(d.FS.policy.UpperDir + "/note.txt")
}
