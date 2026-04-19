package gate

import (
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"time"
)

// msgHarness is like udpHarness but exposes memory layout helpers for
// packing msghdr + iovec + buffers into the FakeMemReader.
type msgHarness struct {
	d   *Dispatcher
	mr  *FakeMemReader
	mw  *FakeMemWriter
	gfd int
	hfd int
}

func newMsgHarness(t *testing.T, mode string) *msgHarness {
	t.Helper()
	d := NewDispatcher(Policy{Net: NetPolicy{Mode: mode}})
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
	return &msgHarness{d: d, mr: mr, mw: mw, gfd: gfd, hfd: hfd}
}

// packMsghdr serialises a struct msghdr at the given layout.
func packMsghdr(namePtr uint64, nameLen uint32, iovPtr uint64, iovLen uint64, ctlPtr uint64, ctlLen uint64, flags int32) []byte {
	buf := make([]byte, 56)
	binary.LittleEndian.PutUint64(buf[0:8], namePtr)
	binary.LittleEndian.PutUint32(buf[8:12], nameLen)
	binary.LittleEndian.PutUint64(buf[16:24], iovPtr)
	binary.LittleEndian.PutUint64(buf[24:32], iovLen)
	binary.LittleEndian.PutUint64(buf[32:40], ctlPtr)
	binary.LittleEndian.PutUint64(buf[40:48], ctlLen)
	binary.LittleEndian.PutUint32(buf[48:52], uint32(flags))
	return buf
}

func packIovec(entries [][2]uint64) []byte {
	buf := make([]byte, len(entries)*16)
	for i, e := range entries {
		binary.LittleEndian.PutUint64(buf[i*16:i*16+8], e[0])
		binary.LittleEndian.PutUint64(buf[i*16+8:i*16+16], e[1])
	}
	return buf
}

// TestSendMsgScatterGatherToUDP: stage two iovec chunks and verify the
// concatenated payload arrives at the UDP peer.
func TestSendMsgScatterGatherToUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)

	h := newMsgHarness(t, "loopback-only")
	h.mr.Stage(0xb000, []byte("hello "))
	h.mr.Stage(0xb100, []byte("scatter"))
	h.mr.Stage(0xb200, packIovec([][2]uint64{
		{0xb000, 6},
		{0xb100, 7},
	}))
	h.mr.Stage(0xb300, buildSockaddrIn(port, [4]byte{127, 0, 0, 1}))
	h.mr.Stage(0xb400, packMsghdr(0xb300, 16, 0xb200, 2, 0, 0, 0))

	regs := &Regs{NR: SysSendMsg}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0xb400
	regs.X[2] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 13 {
		t.Fatalf("sendmsg: X[0]=%d, want 13 (%s)", int64(regs.X[0]), syscall.Errno(-int64(regs.X[0])))
	}

	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "hello scatter" {
		t.Errorf("payload: got %q, want 'hello scatter'", buf[:n])
	}
}

// sendmsg with non-zero msg_controllen is deferred — ENOSYS rather
// than silently dropping the cmsg list or reaching the host kernel.
func TestSendMsgControlLenNonzeroIsENOSYS(t *testing.T) {
	h := newMsgHarness(t, "loopback-only")
	h.mr.Stage(0xc000, []byte("x"))
	h.mr.Stage(0xc100, packIovec([][2]uint64{{0xc000, 1}}))
	h.mr.Stage(0xc200, packMsghdr(0, 0, 0xc100, 1, 0xc300, 32, 0))

	regs := &Regs{NR: SysSendMsg}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0xc200
	regs.X[2] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.ENOSYS) {
		t.Errorf("cmsg sendmsg: X[0]=%d, want -ENOSYS", int64(regs.X[0]))
	}
}

// Oversized iovlen: the gate caps at IOV_MAX=1024 — anything above
// must EINVAL without allocating.
func TestSendMsgIovlenAboveCapIsEINVAL(t *testing.T) {
	h := newMsgHarness(t, "loopback-only")
	h.mr.Stage(0xd000, packMsghdr(0, 0, 0xd100, 999999, 0, 0, 0))

	regs := &Regs{NR: SysSendMsg}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0xd000
	regs.X[2] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EINVAL) {
		t.Errorf("oversized iovlen: X[0]=%d, want -EINVAL", int64(regs.X[0]))
	}
}

// policy check on the sendmsg msg_name path must match sendto: a
// denied destination surfaces EACCES regardless of iovec content.
func TestSendMsgPolicyBlocksMsgName(t *testing.T) {
	h := newMsgHarness(t, "internet")
	h.mr.Stage(0xe000, []byte("x"))
	h.mr.Stage(0xe100, packIovec([][2]uint64{{0xe000, 1}}))
	h.mr.Stage(0xe200, buildSockaddrIn(53, [4]byte{10, 0, 0, 53}))
	h.mr.Stage(0xe300, packMsghdr(0xe200, 16, 0xe100, 1, 0, 0, 0))

	regs := &Regs{NR: SysSendMsg}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0xe300
	regs.X[2] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EACCES) {
		t.Errorf("policy msg_name: X[0]=%d, want -EACCES", int64(regs.X[0]))
	}
}

// TestRecvMsgScattersAcrossIovecs: peer sends one 13-byte datagram,
// recvmsg scatters it across two 7 + 6 byte iovecs.
func TestRecvMsgScattersAcrossIovecs(t *testing.T) {
	h := newMsgHarness(t, "loopback-only")
	sa := &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	if err := syscall.Bind(h.hfd, sa); err != nil {
		t.Fatal(err)
	}
	got, _ := syscall.Getsockname(h.hfd)
	port := got.(*syscall.SockaddrInet4).Port

	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerPort := uint16(peer.LocalAddr().(*net.UDPAddr).Port)

	payload := []byte("hello scatter")
	if _, err := peer.WriteTo(payload, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}); err != nil {
		t.Fatal(err)
	}

	h.mr.Stage(0xf000, packIovec([][2]uint64{
		{0xf100, 7}, // first iovec target: 0xf100..0xf107
		{0xf200, 6}, // second iovec target: 0xf200..0xf205
	}))
	h.mr.Stage(0xf300, packMsghdr(0xf400, 16, 0xf000, 2, 0, 0, 0))

	regs := &Regs{NR: SysRecvMsg}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0xf300
	regs.X[2] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != int64(len(payload)) {
		t.Fatalf("recvmsg: X[0]=%d, want %d", int64(regs.X[0]), len(payload))
	}

	firstChunk := h.mw.Read(0xf100, 7)
	if !bytes.Equal(firstChunk, []byte("hello s")) {
		t.Errorf("first iovec: got %q, want 'hello s'", firstChunk)
	}
	secondChunk := h.mw.Read(0xf200, 6)
	if !bytes.Equal(secondChunk, []byte("catter")) {
		t.Errorf("second iovec: got %q, want 'catter'", secondChunk)
	}

	// Peer sockaddr written at msg_name.
	gotSa := h.mw.Read(0xf400, 16)
	wantSa := buildSockaddrIn(peerPort, [4]byte{127, 0, 0, 1})
	if !bytes.Equal(gotSa, wantSa) {
		t.Errorf("peer sockaddr: got %x, want %x", gotSa, wantSa)
	}
	// msg_namelen at msgPtr+8 updated to 16.
	gotLen := binary.LittleEndian.Uint32(h.mw.Read(0xf300+8, 4))
	if gotLen != 16 {
		t.Errorf("msg_namelen: got %d, want 16", gotLen)
	}
	// msg_controllen at msgPtr+40 zeroed.
	gotCtlLen := binary.LittleEndian.Uint64(h.mw.Read(0xf300+40, 8))
	if gotCtlLen != 0 {
		t.Errorf("msg_controllen: got %d, want 0", gotCtlLen)
	}
	// msg_flags at msgPtr+48 zeroed.
	gotFlags := binary.LittleEndian.Uint32(h.mw.Read(0xf300+48, 4))
	if gotFlags != 0 {
		t.Errorf("msg_flags: got %d, want 0", gotFlags)
	}
}

func TestSendMsgBadFdIsEBADF(t *testing.T) {
	h := newMsgHarness(t, "loopback-only")
	h.mr.Stage(0x10000, packMsghdr(0, 0, 0, 0, 0, 0, 0))
	regs := &Regs{NR: SysSendMsg}
	regs.X[0] = 9999
	regs.X[1] = 0x10000
	regs.X[2] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd sendmsg: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}

func TestRecvMsgBadFdIsEBADF(t *testing.T) {
	h := newMsgHarness(t, "loopback-only")
	h.mr.Stage(0x10100, packMsghdr(0, 0, 0, 0, 0, 0, 0))
	regs := &Regs{NR: SysRecvMsg}
	regs.X[0] = 9999
	regs.X[1] = 0x10100
	regs.X[2] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd recvmsg: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}
