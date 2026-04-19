package gate

import (
	"encoding/binary"
	"syscall"
	"testing"
)

// sockoptHarness wires a UDP socket with MemR (for optval / *optlen
// reads) and Mem (for getsockopt's value + length out-params).
type sockoptHarness struct {
	d   *Dispatcher
	mr  *FakeMemReader
	mw  *FakeMemWriter
	gfd int
	hfd int
}

func newSockoptHarness(t *testing.T) *sockoptHarness {
	t.Helper()
	d := NewDispatcher(Policy{Net: NetPolicy{Mode: "loopback-only"}})
	mr := &FakeMemReader{}
	mw := &FakeMemWriter{}
	d.MemR = mr
	d.Mem = mw

	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_INET)
	regs.X[1] = uint64(syscall.SOCK_DGRAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	gfd := int(regs.X[0])
	hfd, _ := d.FDs.Resolve(gfd)
	t.Cleanup(func() { _ = syscall.Close(hfd) })
	return &sockoptHarness{d: d, mr: mr, mw: mw, gfd: gfd, hfd: hfd}
}

// Set SO_REUSEADDR = 1 via the handler, then read it back via raw
// host getsockopt. This is the option every server binds with.
func TestSetSockOptSOReuseAddrTakesEffect(t *testing.T) {
	h := newSockoptHarness(t)

	// optval = int32(1) little-endian.
	var val [4]byte
	binary.LittleEndian.PutUint32(val[:], 1)
	h.mr.Stage(0xa000, val[:])

	regs := &Regs{NR: SysSetSockOpt}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = uint64(syscall.SOL_SOCKET)
	regs.X[2] = uint64(syscall.SO_REUSEADDR)
	regs.X[3] = 0xa000
	regs.X[4] = 4
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("setsockopt: X[0]=%d (%s)", int64(regs.X[0]), syscall.Errno(-int64(regs.X[0])))
	}

	got, err := syscall.GetsockoptInt(h.hfd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR)
	if err != nil {
		t.Fatal(err)
	}
	if got == 0 {
		t.Errorf("SO_REUSEADDR: got 0, want nonzero after set")
	}
}

// getsockopt returns the kernel's view; we set via host API and read
// back through the handler.
func TestGetSockOptSOTypeReturnsDGRAM(t *testing.T) {
	h := newSockoptHarness(t)

	var alen [4]byte
	binary.LittleEndian.PutUint32(alen[:], 4)
	h.mr.Stage(0xa100, alen[:])

	regs := &Regs{NR: SysGetSockOpt}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = uint64(syscall.SOL_SOCKET)
	regs.X[2] = uint64(syscall.SO_TYPE)
	regs.X[3] = 0xa200
	regs.X[4] = 0xa100
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("getsockopt: X[0]=%d", int64(regs.X[0]))
	}

	got := binary.LittleEndian.Uint32(h.mw.Read(0xa200, 4))
	if got != uint32(syscall.SOCK_DGRAM) {
		t.Errorf("SO_TYPE: got %d, want SOCK_DGRAM (%d)", got, syscall.SOCK_DGRAM)
	}
	gotLen := binary.LittleEndian.Uint32(h.mw.Read(0xa100, 4))
	if gotLen != 4 {
		t.Errorf("*optlen: got %d, want 4", gotLen)
	}
}

// optlen beyond the gate's cap is EINVAL — keeps the host from being
// coerced into allocating arbitrary memory per syscall.
func TestSetSockOptOversizedOptlenIsEINVAL(t *testing.T) {
	h := newSockoptHarness(t)
	regs := &Regs{NR: SysSetSockOpt}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = uint64(syscall.SOL_SOCKET)
	regs.X[2] = uint64(syscall.SO_REUSEADDR)
	regs.X[3] = 0xa300
	regs.X[4] = 1 << 20
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EINVAL) {
		t.Errorf("oversized: X[0]=%d, want -EINVAL", int64(regs.X[0]))
	}
}

func TestSetSockOptBadFdIsEBADF(t *testing.T) {
	h := newSockoptHarness(t)
	regs := &Regs{NR: SysSetSockOpt}
	regs.X[0] = 9999
	regs.X[1] = uint64(syscall.SOL_SOCKET)
	regs.X[2] = uint64(syscall.SO_REUSEADDR)
	regs.X[3] = 0
	regs.X[4] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}

func TestGetSockOptNullOptlenIsEFAULT(t *testing.T) {
	h := newSockoptHarness(t)
	regs := &Regs{NR: SysGetSockOpt}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = uint64(syscall.SOL_SOCKET)
	regs.X[2] = uint64(syscall.SO_TYPE)
	regs.X[3] = 0xa400
	regs.X[4] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EFAULT) {
		t.Errorf("null optlen: X[0]=%d, want -EFAULT", int64(regs.X[0]))
	}
}

// shutdown(how=SHUT_WR) on a fresh UDP socket: kernel accepts it on
// unconnected sockets for linux; if platform quirks block, fall back
// on the "must not be EBADF" check.
func TestShutdownOnTCPSocket(t *testing.T) {
	d := NewDispatcher(Policy{Net: NetPolicy{Mode: "loopback-only"}})
	d.MemR = &FakeMemReader{}
	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_INET)
	regs.X[1] = uint64(syscall.SOCK_STREAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	gfd := int(regs.X[0])
	hfd, _ := d.FDs.Resolve(gfd)
	t.Cleanup(func() { _ = syscall.Close(hfd) })

	// Unconnected TCP + shutdown returns ENOTCONN — handler must
	// surface that errno rather than 0.
	sregs := &Regs{NR: SysShutdown}
	sregs.X[0] = uint64(gfd)
	sregs.X[1] = uint64(syscall.SHUT_RDWR)
	d.Dispatch(sregs)
	if int64(sregs.X[0]) != -int64(syscall.ENOTCONN) {
		t.Errorf("unconnected shutdown: X[0]=%d, want -ENOTCONN", int64(sregs.X[0]))
	}
}

func TestShutdownBadFdIsEBADF(t *testing.T) {
	d := NewDispatcher(Policy{Net: NetPolicy{Mode: "loopback-only"}})
	regs := &Regs{NR: SysShutdown}
	regs.X[0] = 9999
	regs.X[1] = uint64(syscall.SHUT_RDWR)
	d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}
