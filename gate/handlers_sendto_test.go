package gate

import (
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"time"
)

// udpHarness wires a dispatcher with loopback-only NetPolicy plus both
// a MemReader (for src buf / dest sockaddr) and a MemWriter (for
// recvfrom's payload + remote-sockaddr out-params).
type udpHarness struct {
	d   *Dispatcher
	mr  *FakeMemReader
	mw  *FakeMemWriter
	gfd int // guest fd of the dispatcher-owned UDP socket
	hfd int // host fd behind gfd
}

func newUDPHarness(t *testing.T, mode string) *udpHarness {
	t.Helper()
	d := NewDispatcher(Policy{Net: NetPolicy{Mode: mode}})
	mr := &FakeMemReader{}
	mw := &FakeMemWriter{}
	d.MemR = mr
	d.Mem = mw

	// socket(AF_INET, SOCK_DGRAM, 0) via the dispatcher so we exercise
	// the real FDTable plumbing.
	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_INET)
	regs.X[1] = uint64(syscall.SOCK_DGRAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) < 0 {
		t.Fatalf("socket AF_INET/DGRAM: X[0]=%d", int64(regs.X[0]))
	}
	gfd := int(regs.X[0])
	hfd, ok := d.FDs.Resolve(gfd)
	if !ok {
		t.Fatalf("fd %d not in FDTable", gfd)
	}
	return &udpHarness{d: d, mr: mr, mw: mw, gfd: gfd, hfd: hfd}
}

// bindLoopback binds the dispatcher socket to an ephemeral 127.0.0.1
// port so recvfrom tests have a known destination. Returns the bound
// port.
func (h *udpHarness) bindLoopback(t *testing.T) uint16 {
	t.Helper()
	sa := &syscall.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}}
	if err := syscall.Bind(h.hfd, sa); err != nil {
		t.Fatalf("bind: %v", err)
	}
	got, err := syscall.Getsockname(h.hfd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	return uint16(got.(*syscall.SockaddrInet4).Port)
}

// TestSendToLoopbackUDPDelivers sends a datagram via handleSendTo to a
// real UDP listener and verifies the payload arrives. This is the
// musl-DNS shape: unconnected socket + explicit dest.
func TestSendToLoopbackUDPDelivers(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)

	h := newUDPHarness(t, "loopback-only")
	payload := []byte("hello udp")
	h.mr.Stage(0x5000, payload)
	h.mr.Stage(0x5100, buildSockaddrIn(port, [4]byte{127, 0, 0, 1}))

	regs := &Regs{NR: SysSendTo}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x5000
	regs.X[2] = uint64(len(payload))
	regs.X[3] = 0
	regs.X[4] = 0x5100
	regs.X[5] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != int64(len(payload)) {
		t.Fatalf("sendto: X[0]=%d, want %d", int64(regs.X[0]), len(payload))
	}

	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("payload: got %q, want %q", buf[:n], payload)
	}
}

// Policy gates sendto the same way it gates connect. An explicit dest
// under mode=internet that falls inside the builtin-deny (10.0.0.0/8)
// must be EACCES — a sendto that bypasses connect is still a gateable
// destination.
func TestSendToBlockedByPolicyIsEACCES(t *testing.T) {
	h := newUDPHarness(t, "internet")
	h.mr.Stage(0x5200, []byte("x"))
	h.mr.Stage(0x5300, buildSockaddrIn(53, [4]byte{10, 0, 0, 53}))

	regs := &Regs{NR: SysSendTo}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x5200
	regs.X[2] = 1
	regs.X[3] = 0
	regs.X[4] = 0x5300
	regs.X[5] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EACCES) {
		t.Errorf("sendto to 10.0.0.53: X[0]=%d, want -EACCES", int64(regs.X[0]))
	}
}

func TestSendToBadFdIsEBADF(t *testing.T) {
	h := newUDPHarness(t, "loopback-only")
	h.mr.Stage(0x5400, []byte("x"))
	regs := &Regs{NR: SysSendTo}
	regs.X[0] = 4242
	regs.X[1] = 0x5400
	regs.X[2] = 1
	regs.X[3] = 0
	regs.X[4] = 0
	regs.X[5] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}

// destPtr non-zero with a length shorter than sa_family (2 bytes)
// can't carry any routable information. We surface EINVAL rather than
// letting the decoder read past the staged slice.
func TestSendToShortDestLenIsEINVAL(t *testing.T) {
	h := newUDPHarness(t, "loopback-only")
	h.mr.Stage(0x5500, []byte("x"))
	h.mr.Stage(0x5600, []byte{0})

	regs := &Regs{NR: SysSendTo}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x5500
	regs.X[2] = 1
	regs.X[3] = 0
	regs.X[4] = 0x5600
	regs.X[5] = 1
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EINVAL) {
		t.Errorf("short dest: X[0]=%d, want -EINVAL", int64(regs.X[0]))
	}
}

// TestRecvFromWritesPayloadAndSockaddr verifies the full recvfrom
// out-param path: the payload is written through MemWriter, the
// remote sockaddr gets encoded back to src_addr, and *addrlen is
// updated to the full length.
func TestRecvFromWritesPayloadAndSockaddr(t *testing.T) {
	h := newUDPHarness(t, "loopback-only")
	port := h.bindLoopback(t)

	// Peer that sends the datagram we'll recv.
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerPort := uint16(peer.LocalAddr().(*net.UDPAddr).Port)

	payload := []byte("dns-reply-blob")
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
	if _, err := peer.WriteTo(payload, dst); err != nil {
		t.Fatalf("peer WriteTo: %v", err)
	}

	// Stage initial *addrlen = 16 so the handler knows the out-buffer
	// can fit a sockaddr_in.
	var alen [4]byte
	binary.LittleEndian.PutUint32(alen[:], 16)
	h.mr.Stage(0x6100, alen[:])

	regs := &Regs{NR: SysRecvFrom}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x6000 // bufPtr
	regs.X[2] = 256
	regs.X[3] = 0
	regs.X[4] = 0x6200 // src_addr out-param
	regs.X[5] = 0x6100 // addrlen in/out-param (staged with 16)
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != int64(len(payload)) {
		t.Fatalf("recvfrom: X[0]=%d, want %d", int64(regs.X[0]), len(payload))
	}

	gotPayload := h.mw.Read(0x6000, len(payload))
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload: got %q, want %q", gotPayload, payload)
	}

	gotSa := h.mw.Read(0x6200, 16)
	wantSa := buildSockaddrIn(peerPort, [4]byte{127, 0, 0, 1})
	if !bytes.Equal(gotSa, wantSa) {
		t.Errorf("sockaddr: got %x, want %x", gotSa, wantSa)
	}

	// *addrlen must now read 16 (full sockaddr_in).
	gotLen := h.mw.Read(0x6100, 4)
	if binary.LittleEndian.Uint32(gotLen) != 16 {
		t.Errorf("*addrlen: got %d, want 16", binary.LittleEndian.Uint32(gotLen))
	}
}

// Payload still arrives when the caller passes NULL src_addr (they
// don't care who sent it). handleRecvFrom must not touch the MemWriter
// for the sockaddr path.
func TestRecvFromNullSrcAddrDeliversPayload(t *testing.T) {
	h := newUDPHarness(t, "loopback-only")
	port := h.bindLoopback(t)

	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
	payload := []byte("anon")
	if _, err := peer.WriteTo(payload, dst); err != nil {
		t.Fatal(err)
	}

	regs := &Regs{NR: SysRecvFrom}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x7000
	regs.X[2] = 64
	regs.X[3] = 0
	regs.X[4] = 0
	regs.X[5] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != int64(len(payload)) {
		t.Fatalf("recvfrom: X[0]=%d, want %d", int64(regs.X[0]), len(payload))
	}
	got := h.mw.Read(0x7000, len(payload))
	if !bytes.Equal(got, payload) {
		t.Errorf("payload: got %q, want %q", got, payload)
	}
}

func TestRecvFromBadFdIsEBADF(t *testing.T) {
	h := newUDPHarness(t, "loopback-only")
	regs := &Regs{NR: SysRecvFrom}
	regs.X[0] = 9999
	regs.X[1] = 0x8000
	regs.X[2] = 64
	regs.X[3] = 0
	regs.X[4] = 0
	regs.X[5] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}
