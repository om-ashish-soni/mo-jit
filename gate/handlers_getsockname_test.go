package gate

import (
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

// nameHarness wires a dispatcher with both Mem (for the out-addr +
// out-addrlen writes) and MemR (for the initial *addrlen read) and
// opens an AF_INET TCP socket via the dispatcher.
type nameHarness struct {
	d   *Dispatcher
	mr  *FakeMemReader
	mw  *FakeMemWriter
	gfd int
	hfd int
}

func newNameHarness(t *testing.T) *nameHarness {
	t.Helper()
	d := NewDispatcher(Policy{Net: NetPolicy{Mode: "loopback-only"}})
	mr := &FakeMemReader{}
	mw := &FakeMemWriter{}
	d.MemR = mr
	d.Mem = mw

	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_INET)
	regs.X[1] = uint64(syscall.SOCK_STREAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) < 0 {
		t.Fatalf("socket: X[0]=%d", int64(regs.X[0]))
	}
	gfd := int(regs.X[0])
	hfd, _ := d.FDs.Resolve(gfd)
	t.Cleanup(func() { _ = syscall.Close(hfd) })
	return &nameHarness{d: d, mr: mr, mw: mw, gfd: gfd, hfd: hfd}
}

// TestGetSockNameReturnsBoundAddress: bind 127.0.0.1:0, call
// getsockname, expect the sockaddr and *addrlen=16 written back.
func TestGetSockNameReturnsBoundAddress(t *testing.T) {
	h := newNameHarness(t)
	if err := syscall.Bind(h.hfd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	got, err := syscall.Getsockname(h.hfd)
	if err != nil {
		t.Fatal(err)
	}
	wantPort := uint16(got.(*syscall.SockaddrInet4).Port)

	var alen [4]byte
	binary.LittleEndian.PutUint32(alen[:], 16)
	h.mr.Stage(0x7100, alen[:])

	regs := &Regs{NR: SysGetSockName}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x7000
	regs.X[2] = 0x7100
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("getsockname: X[0]=%d (%s)", int64(regs.X[0]), syscall.Errno(-int64(regs.X[0])))
	}

	gotSa := h.mw.Read(0x7000, 16)
	wantSa := buildSockaddrIn(wantPort, [4]byte{127, 0, 0, 1})
	if !bytes.Equal(gotSa, wantSa) {
		t.Errorf("sockaddr: got %x, want %x", gotSa, wantSa)
	}
	gotLen := h.mw.Read(0x7100, 4)
	if binary.LittleEndian.Uint32(gotLen) != 16 {
		t.Errorf("*addrlen: got %d, want 16", binary.LittleEndian.Uint32(gotLen))
	}
}

// *addrlen too small: the handler clamps the write to the provided
// length but *addrlen in the out-param reports the full 16, matching
// the kernel's "here's how big it would have been" contract.
func TestGetSockNameShortAddrlenClampsWriteButReportsFull(t *testing.T) {
	h := newNameHarness(t)
	if err := syscall.Bind(h.hfd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}

	var alen [4]byte
	binary.LittleEndian.PutUint32(alen[:], 4) // only 4 bytes of space
	h.mr.Stage(0x7200, alen[:])
	// Pre-poison the out-buffer with 0xAA so we can tell what the
	// handler actually wrote.
	h.mw.Bytes = map[uint64]byte{}
	for i := uint64(0); i < 16; i++ {
		h.mw.Bytes[0x7300+i] = 0xAA
	}

	regs := &Regs{NR: SysGetSockName}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x7300
	regs.X[2] = 0x7200
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("getsockname: X[0]=%d", int64(regs.X[0]))
	}

	// First 4 bytes of sockaddr got written; bytes 4..15 remain poisoned.
	for i := uint64(4); i < 16; i++ {
		if h.mw.Bytes[0x7300+i] != 0xAA {
			t.Errorf("byte %d overwritten: %#x", i, h.mw.Bytes[0x7300+i])
		}
	}
	// *addrlen must still advertise the full 16.
	gotLen := h.mw.Read(0x7200, 4)
	if binary.LittleEndian.Uint32(gotLen) != 16 {
		t.Errorf("*addrlen after short read: got %d, want 16", binary.LittleEndian.Uint32(gotLen))
	}
}

// Unconnected socket + getpeername = ENOTCONN. Handler must surface
// the kernel's errno unchanged.
func TestGetPeerNameUnconnectedIsENOTCONN(t *testing.T) {
	h := newNameHarness(t)

	var alen [4]byte
	binary.LittleEndian.PutUint32(alen[:], 16)
	h.mr.Stage(0x7500, alen[:])

	regs := &Regs{NR: SysGetPeerName}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x7400
	regs.X[2] = 0x7500
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.ENOTCONN) {
		t.Errorf("unconnected getpeername: X[0]=%d, want -ENOTCONN", int64(regs.X[0]))
	}
}

// Real end-to-end: connect to a loopback listener, then getpeername
// reports the listener's address.
func TestGetPeerNameReportsConnectedPeer(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
		}
	}()

	h := newNameHarness(t)
	h.mr.Stage(0x7600, buildSockaddrIn(port, [4]byte{127, 0, 0, 1}))
	regs := &Regs{NR: SysConnect}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x7600
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("connect: X[0]=%d", int64(regs.X[0]))
	}

	var alen [4]byte
	binary.LittleEndian.PutUint32(alen[:], 16)
	h.mr.Stage(0x7800, alen[:])

	regs = &Regs{NR: SysGetPeerName}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x7700
	regs.X[2] = 0x7800
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("getpeername: X[0]=%d", int64(regs.X[0]))
	}

	got := h.mw.Read(0x7700, 16)
	want := buildSockaddrIn(port, [4]byte{127, 0, 0, 1})
	if !bytes.Equal(got, want) {
		t.Errorf("peer sockaddr: got %x, want %x", got, want)
	}
}

func TestGetSockNameBadFdIsEBADF(t *testing.T) {
	h := newNameHarness(t)
	var alen [4]byte
	binary.LittleEndian.PutUint32(alen[:], 16)
	h.mr.Stage(0x7900, alen[:])
	regs := &Regs{NR: SysGetSockName}
	regs.X[0] = 9999
	regs.X[1] = 0x7a00
	regs.X[2] = 0x7900
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}

func TestGetPeerNameBadFdIsEBADF(t *testing.T) {
	h := newNameHarness(t)
	var alen [4]byte
	binary.LittleEndian.PutUint32(alen[:], 16)
	h.mr.Stage(0x7b00, alen[:])
	regs := &Regs{NR: SysGetPeerName}
	regs.X[0] = 9999
	regs.X[1] = 0x7c00
	regs.X[2] = 0x7b00
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}
