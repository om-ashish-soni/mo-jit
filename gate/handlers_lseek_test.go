package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// newLSeekHarness opens a real file on an empty upper, writes some
// bytes, returns the dispatcher and the guest fd.
func newLSeekHarness(t *testing.T, payload []byte) (*Dispatcher, int) {
	t.Helper()
	d := NewDispatcher(Policy{
		LowerDir: t.TempDir(),
		UpperDir: t.TempDir(),
	})
	path := filepath.Join(d.FS.policy.UpperDir, "data.bin")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	hostFd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(hostFd) })
	d.FDs = &FDTable{entries: map[int]int{}}
	g := d.FDs.Allocate(hostFd)
	return d, g
}

func TestLSeekSetMovesToAbsolutePosition(t *testing.T) {
	d, g := newLSeekHarness(t, []byte("abcdefgh"))

	regs := &Regs{NR: SysLSeek}
	regs.X[0] = uint64(g)
	regs.X[1] = 4
	regs.X[2] = uint64(os.SEEK_SET) //nolint:staticcheck // whence constant
	d.Dispatch(regs)
	if int64(regs.X[0]) != 4 {
		t.Errorf("SEEK_SET 4 returned %d, want 4", int64(regs.X[0]))
	}
}

func TestLSeekCurAddsToOffset(t *testing.T) {
	d, g := newLSeekHarness(t, []byte("abcdefgh"))

	first := &Regs{NR: SysLSeek}
	first.X[0] = uint64(g)
	first.X[1] = 2
	first.X[2] = uint64(os.SEEK_SET) //nolint:staticcheck
	d.Dispatch(first)

	second := &Regs{NR: SysLSeek}
	second.X[0] = uint64(g)
	second.X[1] = 3
	second.X[2] = uint64(os.SEEK_CUR) //nolint:staticcheck
	d.Dispatch(second)
	if int64(second.X[0]) != 5 {
		t.Errorf("after SEEK_CUR +3 from 2, got %d, want 5", int64(second.X[0]))
	}
}

func TestLSeekEndReturnsFileSize(t *testing.T) {
	d, g := newLSeekHarness(t, []byte("abcdefgh"))

	regs := &Regs{NR: SysLSeek}
	regs.X[0] = uint64(g)
	regs.X[1] = 0
	regs.X[2] = uint64(os.SEEK_END) //nolint:staticcheck
	d.Dispatch(regs)
	if int64(regs.X[0]) != 8 {
		t.Errorf("SEEK_END returned %d, want 8", int64(regs.X[0]))
	}
}

func TestLSeekNegativeResultIsEINVAL(t *testing.T) {
	// SEEK_SET with negative offset: Linux returns EINVAL.
	d, g := newLSeekHarness(t, []byte("abcdefgh"))

	neg := int64(-1)
	regs := &Regs{NR: SysLSeek}
	regs.X[0] = uint64(g)
	regs.X[1] = uint64(neg)
	regs.X[2] = uint64(os.SEEK_SET) //nolint:staticcheck
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EINVAL)
}

func TestLSeekUnknownFdIsEBADF(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	d.FDs = &FDTable{entries: map[int]int{}}

	regs := &Regs{NR: SysLSeek}
	regs.X[0] = 999
	regs.X[1] = 0
	regs.X[2] = uint64(os.SEEK_SET) //nolint:staticcheck
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.EBADF)
}

func TestLSeekOnPipeIsESPIPE(t *testing.T) {
	// Pipes aren't seekable — the kernel surfaces ESPIPE and the
	// gate should propagate it verbatim.
	d := NewDispatcher(Policy{LowerDir: t.TempDir()})
	d.FDs = &FDTable{entries: map[int]int{}}
	hostR, _ := newPipeFds(t)
	g := d.FDs.Allocate(hostR)

	regs := &Regs{NR: SysLSeek}
	regs.X[0] = uint64(g)
	regs.X[1] = 0
	regs.X[2] = uint64(os.SEEK_SET) //nolint:staticcheck
	d.Dispatch(regs)
	expectErrno(t, regs, syscall.ESPIPE)
}
