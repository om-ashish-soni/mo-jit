package gate

import (
	"bytes"
	"syscall"
	"testing"
)

// newDupHarness is the dup/dup3 analogue of newIOHarness — a dispatcher
// with an EMPTY FDTable so tests don't accidentally touch stdio.
func newDupHarness(t *testing.T) *Dispatcher {
	t.Helper()
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	d.FDs = &FDTable{entries: map[int]int{}}
	return d
}

// hostFdIsOpen probes whether a host fd is currently valid via
// fcntl(F_GETFD). Used by tests to assert that a dup3-evicted fd was
// actually closed.
func hostFdIsOpen(fd int) bool {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFD), 0)
	return errno == 0
}

// hostFdCloexec returns whether FD_CLOEXEC is set on a host fd.
func hostFdCloexec(t *testing.T, fd int) bool {
	t.Helper()
	r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFD), 0)
	if errno != 0 {
		t.Fatalf("F_GETFD(%d): %v", fd, errno)
	}
	return int(r)&syscall.FD_CLOEXEC != 0
}

func TestDupAllocatesLowestFreeGuestFd(t *testing.T) {
	d := newDupHarness(t)
	_, hostW := newPipeFds(t)
	guest := d.FDs.Allocate(hostW) // guest 0

	regs := &Regs{NR: SysDup}
	regs.X[0] = uint64(guest)
	d.Dispatch(regs)

	got := int64(regs.X[0])
	if got < 0 {
		t.Fatalf("dup returned errno %d", got)
	}
	if got == int64(guest) {
		t.Fatalf("dup returned same guest fd %d", got)
	}
	// Sharing the file table entry: a write via the new fd must land
	// on the same host pipe.
	hostNew, ok := d.FDs.Resolve(int(got))
	if !ok {
		t.Fatalf("new guest fd %d not in table", got)
	}
	if hostNew == hostW {
		t.Fatalf("dup returned the SAME host fd %d, expected a new one", hostNew)
	}
}

func TestDupSharesHostFileOffset(t *testing.T) {
	// write() through the duplicated guest fd must be readable from
	// the original pipe's read end — proves the host-side dup really
	// shared the file table entry.
	d := newDupHarness(t)
	hostR, hostW := newPipeFds(t)
	orig := d.FDs.Allocate(hostW)

	dup := &Regs{NR: SysDup}
	dup.X[0] = uint64(orig)
	d.Dispatch(dup)
	newFd := int(int64(dup.X[0]))
	if newFd < 0 {
		t.Fatalf("dup errored: %d", newFd)
	}

	reader := &FakeMemReader{}
	reader.Stage(0xc000, []byte("shared"))
	d.MemR = reader

	w := &Regs{NR: SysWrite}
	w.X[0] = uint64(newFd)
	w.X[1] = 0xc000
	w.X[2] = 6
	d.Dispatch(w)
	if int64(w.X[0]) != 6 {
		t.Fatalf("write via duped fd: got %d, want 6", int64(w.X[0]))
	}

	buf := make([]byte, 8)
	n, err := syscall.Read(hostR, buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], []byte("shared")) {
		t.Errorf("pipe payload = %q, want shared", buf[:n])
	}
}

func TestDupUnknownFdReturnsEBADF(t *testing.T) {
	d := newDupHarness(t)
	regs := &Regs{NR: SysDup}
	regs.X[0] = 999
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func TestDup3PlacesAtSpecificGuestSlot(t *testing.T) {
	d := newDupHarness(t)
	_, hostW := newPipeFds(t)
	orig := d.FDs.Allocate(hostW) // guest 0

	regs := &Regs{NR: SysDup3}
	regs.X[0] = uint64(orig)
	regs.X[1] = 17
	regs.X[2] = 0
	d.Dispatch(regs)

	if int64(regs.X[0]) != 17 {
		t.Fatalf("dup3 returned %d, want 17", int64(regs.X[0]))
	}
	if _, ok := d.FDs.Resolve(17); !ok {
		t.Errorf("guest fd 17 not registered after dup3")
	}
}

func TestDup3EvictsAndClosesPriorOccupant(t *testing.T) {
	d := newDupHarness(t)
	_, hostW1 := newPipeFds(t)

	// Allocate a second host pipe so there's a prior occupant for
	// slot 5 — use a fresh pipe rather than newPipeFds to sidestep
	// its t.Cleanup, since dup3 closes hostW2 on our behalf.
	fds := make([]int, 2)
	if err := syscall.Pipe2(fds, syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	hostR2, hostW2 := fds[0], fds[1]
	t.Cleanup(func() { _ = syscall.Close(hostR2) })

	orig := d.FDs.Allocate(hostW1)
	d.FDs.AssignAt(5, hostW2)

	regs := &Regs{NR: SysDup3}
	regs.X[0] = uint64(orig)
	regs.X[1] = 5
	regs.X[2] = 0
	d.Dispatch(regs)

	if int64(regs.X[0]) != 5 {
		t.Fatalf("dup3 returned %d, want 5", int64(regs.X[0]))
	}
	if hostFdIsOpen(hostW2) {
		t.Errorf("prior host fd %d still open after dup3 eviction", hostW2)
	}
}

func TestDup3SameOldfdAndNewfdIsEINVAL(t *testing.T) {
	d := newDupHarness(t)
	_, hostW := newPipeFds(t)
	orig := d.FDs.Allocate(hostW)

	regs := &Regs{NR: SysDup3}
	regs.X[0] = uint64(orig)
	regs.X[1] = uint64(orig)
	regs.X[2] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EINVAL)
}

func TestDup3UnknownOldfdIsEBADF(t *testing.T) {
	d := newDupHarness(t)
	regs := &Regs{NR: SysDup3}
	regs.X[0] = 999
	regs.X[1] = 10
	regs.X[2] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func TestDup3InvalidFlagsAreEINVAL(t *testing.T) {
	d := newDupHarness(t)
	_, hostW := newPipeFds(t)
	orig := d.FDs.Allocate(hostW)

	regs := &Regs{NR: SysDup3}
	regs.X[0] = uint64(orig)
	regs.X[1] = 7
	regs.X[2] = 0xDEAD // garbage — includes bits other than O_CLOEXEC
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EINVAL)
}

func TestDup3CLOEXECAppliedToHostFd(t *testing.T) {
	d := newDupHarness(t)
	_, hostW := newPipeFds(t)
	orig := d.FDs.Allocate(hostW)

	regs := &Regs{NR: SysDup3}
	regs.X[0] = uint64(orig)
	regs.X[1] = 9
	regs.X[2] = uint64(syscall.O_CLOEXEC)
	d.Dispatch(regs)
	if int64(regs.X[0]) != 9 {
		t.Fatalf("dup3 returned %d, want 9", int64(regs.X[0]))
	}
	hostNew, ok := d.FDs.Resolve(9)
	if !ok {
		t.Fatal("guest fd 9 missing after dup3")
	}
	if !hostFdCloexec(t, hostNew) {
		t.Errorf("FD_CLOEXEC not set on host fd %d", hostNew)
	}
}

func TestDup3NegativeNewfdIsEBADF(t *testing.T) {
	d := newDupHarness(t)
	_, hostW := newPipeFds(t)
	orig := d.FDs.Allocate(hostW)

	neg := int64(-1)
	regs := &Regs{NR: SysDup3}
	regs.X[0] = uint64(orig)
	regs.X[1] = uint64(neg)
	regs.X[2] = 0
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func TestDup3IntoEmptySlotDoesNotClose(t *testing.T) {
	// When newfd is unused, dup3 must NOT try to close anything —
	// it simply registers the new host fd. Regression guard.
	d := newDupHarness(t)
	_, hostW := newPipeFds(t)
	orig := d.FDs.Allocate(hostW)

	regs := &Regs{NR: SysDup3}
	regs.X[0] = uint64(orig)
	regs.X[1] = 42
	regs.X[2] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) != 42 {
		t.Fatalf("dup3 returned %d, want 42", int64(regs.X[0]))
	}
	// The original host fd must still be open.
	if !hostFdIsOpen(hostW) {
		t.Errorf("original host fd %d was incorrectly closed", hostW)
	}
}
