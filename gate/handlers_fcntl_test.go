package gate

import (
	"syscall"
	"testing"
)

// newFcntlHarness mirrors newDupHarness — empty FDTable so we don't
// race the test runner's stdio for flag queries.
func newFcntlHarness(t *testing.T) *Dispatcher {
	t.Helper()
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	d.FDs = &FDTable{entries: map[int]int{}}
	return d
}

func TestFcntlUnknownFdIsEBADF(t *testing.T) {
	d := newFcntlHarness(t)
	regs := &Regs{NR: SysFCntl}
	regs.X[0] = 999
	regs.X[1] = syscall.F_GETFD
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func TestFcntlDupFDAllocatesFromMinimum(t *testing.T) {
	d := newFcntlHarness(t)
	_, hostW := newPipeFds(t)
	orig := d.FDs.Allocate(hostW) // guest 0

	regs := &Regs{NR: SysFCntl}
	regs.X[0] = uint64(orig)
	regs.X[1] = syscall.F_DUPFD
	regs.X[2] = 30 // min
	d.Dispatch(regs)

	got := int64(regs.X[0])
	if got < 30 {
		t.Fatalf("F_DUPFD returned %d, want >=30", got)
	}
	if _, ok := d.FDs.Resolve(int(got)); !ok {
		t.Errorf("guest fd %d not registered", got)
	}
}

func TestFcntlDupFDSkipsOccupiedSlots(t *testing.T) {
	d := newFcntlHarness(t)
	_, hostW := newPipeFds(t)
	orig := d.FDs.Allocate(hostW)
	// Fill slot 30 so F_DUPFD(min=30) must land on 31.
	d.FDs.AssignAt(30, hostW)

	regs := &Regs{NR: SysFCntl}
	regs.X[0] = uint64(orig)
	regs.X[1] = syscall.F_DUPFD
	regs.X[2] = 30
	d.Dispatch(regs)
	if int64(regs.X[0]) != 31 {
		t.Fatalf("F_DUPFD returned %d, want 31 (slot 30 occupied)", int64(regs.X[0]))
	}
}

func TestFcntlDupFDCloexecSetsCloexecBit(t *testing.T) {
	d := newFcntlHarness(t)
	_, hostW := newPipeFds(t)
	orig := d.FDs.Allocate(hostW)

	regs := &Regs{NR: SysFCntl}
	regs.X[0] = uint64(orig)
	regs.X[1] = syscall.F_DUPFD_CLOEXEC
	regs.X[2] = 5
	d.Dispatch(regs)

	got := int64(regs.X[0])
	if got < 5 {
		t.Fatalf("F_DUPFD_CLOEXEC returned %d, want >=5", got)
	}
	hostNew, _ := d.FDs.Resolve(int(got))
	if !hostFdCloexec(t, hostNew) {
		t.Errorf("FD_CLOEXEC not set on host fd %d", hostNew)
	}
}

func TestFcntlGetFDDefaultsToZero(t *testing.T) {
	// Fresh pipe ends don't have FD_CLOEXEC on them unless we pass
	// O_CLOEXEC. newPipeFds does — so a fresh pipe should read 1.
	// We pass a fd we know NOT to have CLOEXEC to nail down the read
	// path.
	d := newFcntlHarness(t)
	fds := make([]int, 2)
	if err := syscall.Pipe(fds); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
	})
	g := d.FDs.Allocate(fds[1])

	regs := &Regs{NR: SysFCntl}
	regs.X[0] = uint64(g)
	regs.X[1] = syscall.F_GETFD
	d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Errorf("F_GETFD on non-CLOEXEC fd = %d, want 0", int64(regs.X[0]))
	}
}

func TestFcntlSetFDCloexecRoundTrip(t *testing.T) {
	d := newFcntlHarness(t)
	fds := make([]int, 2)
	if err := syscall.Pipe(fds); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
	})
	g := d.FDs.Allocate(fds[1])

	// Set
	set := &Regs{NR: SysFCntl}
	set.X[0] = uint64(g)
	set.X[1] = syscall.F_SETFD
	set.X[2] = uint64(syscall.FD_CLOEXEC)
	d.Dispatch(set)
	if int64(set.X[0]) < 0 {
		t.Fatalf("F_SETFD failed: %d", int64(set.X[0]))
	}

	// Get
	get := &Regs{NR: SysFCntl}
	get.X[0] = uint64(g)
	get.X[1] = syscall.F_GETFD
	d.Dispatch(get)
	if int64(get.X[0])&syscall.FD_CLOEXEC == 0 {
		t.Errorf("after F_SETFD(CLOEXEC), F_GETFD = %d (no CLOEXEC bit)", int64(get.X[0]))
	}
}

func TestFcntlGetFLReturnsOpenFlags(t *testing.T) {
	d := newFcntlHarness(t)
	// Write-only pipe end has O_WRONLY in the kernel's open-flags.
	_, hostW := newPipeFds(t)
	g := d.FDs.Allocate(hostW)

	regs := &Regs{NR: SysFCntl}
	regs.X[0] = uint64(g)
	regs.X[1] = syscall.F_GETFL
	d.Dispatch(regs)
	flags := int64(regs.X[0])
	if flags < 0 {
		t.Fatalf("F_GETFL errored: %d", flags)
	}
	if int(flags)&syscall.O_ACCMODE != syscall.O_WRONLY {
		t.Errorf("F_GETFL access mode = %#x, want O_WRONLY (%#x)", flags&int64(syscall.O_ACCMODE), syscall.O_WRONLY)
	}
}

func TestFcntlSetFLNonBlockRoundTrip(t *testing.T) {
	// O_NONBLOCK is the only F_SETFL flag near-universal Go code
	// actually uses. Set it, read back, confirm.
	d := newFcntlHarness(t)
	_, hostW := newPipeFds(t)
	g := d.FDs.Allocate(hostW)

	// Baseline: O_NONBLOCK absent.
	get0 := &Regs{NR: SysFCntl}
	get0.X[0] = uint64(g)
	get0.X[1] = syscall.F_GETFL
	d.Dispatch(get0)
	baseline := int(int64(get0.X[0]))
	if baseline&syscall.O_NONBLOCK != 0 {
		t.Fatalf("baseline already O_NONBLOCK; test precondition broken")
	}

	set := &Regs{NR: SysFCntl}
	set.X[0] = uint64(g)
	set.X[1] = syscall.F_SETFL
	set.X[2] = uint64(baseline | syscall.O_NONBLOCK)
	d.Dispatch(set)
	if int64(set.X[0]) < 0 {
		t.Fatalf("F_SETFL errored: %d", int64(set.X[0]))
	}

	get := &Regs{NR: SysFCntl}
	get.X[0] = uint64(g)
	get.X[1] = syscall.F_GETFL
	d.Dispatch(get)
	if int(int64(get.X[0]))&syscall.O_NONBLOCK == 0 {
		t.Errorf("F_SETFL(O_NONBLOCK) did not stick: flags=%#x", int64(get.X[0]))
	}
}

func TestFcntlUnsupportedCmdIsENOSYS(t *testing.T) {
	// F_SETLK (6) — advisory locking is out of scope for M2.
	d := newFcntlHarness(t)
	_, hostW := newPipeFds(t)
	g := d.FDs.Allocate(hostW)

	regs := &Regs{NR: SysFCntl}
	regs.X[0] = uint64(g)
	regs.X[1] = 6 // F_SETLK
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ENOSYS)
}
