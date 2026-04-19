package gate

import (
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"time"
)

// serverHarness owns a listening dispatcher socket bound to
// 127.0.0.1:<ephemeral> and exposes the bound port so a client can
// connect in from the test goroutine.
type serverHarness struct {
	d    *Dispatcher
	mr   *FakeMemReader
	mw   *FakeMemWriter
	gfd  int // guest fd of the listening socket
	hfd  int // host fd behind gfd
	port uint16
}

func newServerHarness(t *testing.T, mode string) *serverHarness {
	t.Helper()
	d := NewDispatcher(Policy{Net: NetPolicy{Mode: mode}})
	mr := &FakeMemReader{}
	mw := &FakeMemWriter{}
	d.MemR = mr
	d.Mem = mw

	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_INET)
	regs.X[1] = uint64(syscall.SOCK_STREAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	gfd := int(regs.X[0])
	hfd, _ := d.FDs.Resolve(gfd)
	t.Cleanup(func() { _ = syscall.Close(hfd) })

	// bind + getsockname directly via the host fd so we know the port.
	if err := syscall.Bind(hfd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	local, err := syscall.Getsockname(hfd)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(local.(*syscall.SockaddrInet4).Port)

	return &serverHarness{d: d, mr: mr, mw: mw, gfd: gfd, hfd: hfd, port: port}
}

func TestListenMarksSocketPassive(t *testing.T) {
	s := newServerHarness(t, "loopback-only")
	regs := &Regs{NR: SysListen}
	regs.X[0] = uint64(s.gfd)
	regs.X[1] = 16
	s.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("listen: X[0]=%d (%s)", int64(regs.X[0]), syscall.Errno(-int64(regs.X[0])))
	}

	// Connect from a plain host socket to prove the listener accepted
	// the listen(2) call (otherwise connect would get ECONNREFUSED).
	conn, err := net.DialTimeout("tcp4", "127.0.0.1:"+itoa(int(s.port)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

func TestListenBadFdIsEBADF(t *testing.T) {
	s := newServerHarness(t, "loopback-only")
	regs := &Regs{NR: SysListen}
	regs.X[0] = 9999
	regs.X[1] = 16
	s.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}

// TestAcceptLoopbackReturnsGuestFdAndPeer: bind+listen a dispatcher
// socket, spawn a host-side dialer, accept via the handler, check
// the guest fd is valid + the peer sockaddr was written back.
func TestAcceptLoopbackReturnsGuestFdAndPeer(t *testing.T) {
	s := newServerHarness(t, "loopback-only")

	// listen via the dispatcher so the handler path is covered.
	lregs := &Regs{NR: SysListen}
	lregs.X[0] = uint64(s.gfd)
	lregs.X[1] = 4
	s.d.Dispatch(lregs)
	if int64(lregs.X[0]) != 0 {
		t.Fatalf("listen: X[0]=%d", int64(lregs.X[0]))
	}

	// Dialer goroutine — connects from an ephemeral loopback port.
	dialErrC := make(chan error, 1)
	dialConnC := make(chan net.Conn, 1)
	go func() {
		c, err := net.DialTimeout("tcp4", "127.0.0.1:"+itoa(int(s.port)), 2*time.Second)
		dialErrC <- err
		dialConnC <- c
	}()

	var alen [4]byte
	binary.LittleEndian.PutUint32(alen[:], 16)
	s.mr.Stage(0x8100, alen[:])

	regs := &Regs{NR: SysAccept}
	regs.X[0] = uint64(s.gfd)
	regs.X[1] = 0x8000
	regs.X[2] = 0x8100
	s.d.Dispatch(regs)

	if err := <-dialErrC; err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := <-dialConnC
	t.Cleanup(func() { _ = c.Close() })

	got := int64(regs.X[0])
	if got < 0 {
		t.Fatalf("accept: X[0]=%d (%s)", got, syscall.Errno(-got))
	}
	newHostFd, ok := s.d.FDs.Resolve(int(got))
	if !ok {
		t.Fatalf("new guest fd %d not in FDTable", got)
	}
	t.Cleanup(func() { _ = syscall.Close(newHostFd) })

	// Peer sockaddr: same address family, loopback address, the
	// dialer's source port (not our listener port).
	gotSa := s.mw.Read(0x8000, 16)
	peerFam := binary.LittleEndian.Uint16(gotSa[0:2])
	if peerFam != uint16(syscall.AF_INET) {
		t.Errorf("peer family: got %d, want AF_INET", peerFam)
	}
	if !bytes.Equal(gotSa[4:8], []byte{127, 0, 0, 1}) {
		t.Errorf("peer addr: got %v, want 127.0.0.1", gotSa[4:8])
	}
	// *addrlen must read 16 (full sockaddr_in).
	gotLen := s.mw.Read(0x8100, 4)
	if binary.LittleEndian.Uint32(gotLen) != 16 {
		t.Errorf("*addrlen: got %d, want 16", binary.LittleEndian.Uint32(gotLen))
	}
}

// accept4 with SOCK_CLOEXEC: the returned host fd must have FD_CLOEXEC
// set — matches the socket() test's forwarding check.
func TestAccept4HonoursSOCKCLOEXEC(t *testing.T) {
	s := newServerHarness(t, "loopback-only")
	lregs := &Regs{NR: SysListen}
	lregs.X[0] = uint64(s.gfd)
	lregs.X[1] = 4
	s.d.Dispatch(lregs)

	dialC := make(chan net.Conn, 1)
	go func() {
		c, _ := net.DialTimeout("tcp4", "127.0.0.1:"+itoa(int(s.port)), 2*time.Second)
		dialC <- c
	}()

	regs := &Regs{NR: SysAccept4}
	regs.X[0] = uint64(s.gfd)
	regs.X[1] = 0
	regs.X[2] = 0
	regs.X[3] = uint64(syscall.SOCK_CLOEXEC)
	s.d.Dispatch(regs)

	c := <-dialC
	if c != nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	got := int64(regs.X[0])
	if got < 0 {
		t.Fatalf("accept4: X[0]=%d (%s)", got, syscall.Errno(-got))
	}
	hostFd, _ := s.d.FDs.Resolve(int(got))
	t.Cleanup(func() { _ = syscall.Close(hostFd) })

	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(hostFd), uintptr(syscall.F_GETFD), 0)
	if errno != 0 {
		t.Fatalf("fcntl F_GETFD: %v", errno)
	}
	if flags&syscall.FD_CLOEXEC == 0 {
		t.Errorf("SOCK_CLOEXEC did not propagate (flags=%#x)", flags)
	}
}

func TestAcceptBadFdIsEBADF(t *testing.T) {
	s := newServerHarness(t, "loopback-only")
	regs := &Regs{NR: SysAccept}
	regs.X[0] = 9999
	regs.X[1] = 0
	regs.X[2] = 0
	s.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}

// accept with no pending connection on a non-blocking socket must
// surface EAGAIN. Sets O_NONBLOCK on the host fd first.
func TestAcceptNonblockEmptyIsEAGAIN(t *testing.T) {
	s := newServerHarness(t, "loopback-only")
	// listen + set nonblocking on host fd directly.
	if err := syscall.Listen(s.hfd, 4); err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(s.hfd, true); err != nil {
		t.Fatal(err)
	}

	regs := &Regs{NR: SysAccept}
	regs.X[0] = uint64(s.gfd)
	regs.X[1] = 0
	regs.X[2] = 0
	s.d.Dispatch(regs)
	got := int64(regs.X[0])
	if got != -int64(syscall.EAGAIN) && got != -int64(syscall.EWOULDBLOCK) {
		t.Errorf("nonblock empty accept: X[0]=%d, want -EAGAIN/-EWOULDBLOCK", got)
	}
}

// Minimal itoa — the net package wants "host:port" as a string and we
// don't want fmt bloat in the test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
