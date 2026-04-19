package gate

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

// buildSockaddrIn packs a sockaddr_in blob (16 bytes, AF_INET). port
// is kernel-facing (big-endian on the wire), ip is the IPv4 octets in
// network order.
func buildSockaddrIn(port uint16, ip [4]byte) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(syscall.AF_INET))
	binary.BigEndian.PutUint16(buf[2:4], port)
	copy(buf[4:8], ip[:])
	return buf
}

// buildSockaddrIn6 packs a sockaddr_in6 blob (28 bytes, AF_INET6).
func buildSockaddrIn6(port uint16, ip [16]byte, scopeID uint32) []byte {
	buf := make([]byte, 28)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(syscall.AF_INET6))
	binary.BigEndian.PutUint16(buf[2:4], port)
	// flowinfo stays zero
	copy(buf[8:24], ip[:])
	binary.LittleEndian.PutUint32(buf[24:28], scopeID)
	return buf
}

// newConnectDispatcher wires a dispatcher with the requested NetPolicy
// mode plus an in-memory MemReader so tests can stage sockaddr blobs.
type connectHarness struct {
	d  *Dispatcher
	mr *FakeMemReader
}

func newConnectHarness(t *testing.T, mode string) *connectHarness {
	t.Helper()
	d := NewDispatcher(Policy{Net: NetPolicy{Mode: mode}})
	mr := &FakeMemReader{}
	d.MemR = mr
	return &connectHarness{d: d, mr: mr}
}

// allocClientSocket opens a real host socket via the dispatcher's
// socket() handler and returns the guest fd + the bound host fd.
func (h *connectHarness) allocClientSocket(t *testing.T, domain int) (int, int) {
	t.Helper()
	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(domain)
	regs.X[1] = uint64(syscall.SOCK_STREAM)
	regs.X[2] = 0
	h.d.Dispatch(regs)
	if int64(regs.X[0]) < 0 {
		t.Fatalf("socket(%d): X[0]=%d", domain, int64(regs.X[0]))
	}
	g := int(regs.X[0])
	hostFd, ok := h.d.FDs.Resolve(g)
	if !ok {
		t.Fatalf("guest fd %d not in FDTable", g)
	}
	return g, hostFd
}

func TestConnectLoopbackUnderLoopbackOnlyMode(t *testing.T) {
	// Start a real listener on 127.0.0.1; any ephemeral port.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	h := newConnectHarness(t, "loopback-only")
	g, _ := h.allocClientSocket(t, syscall.AF_INET)
	h.mr.Stage(0x4100, buildSockaddrIn(port, [4]byte{127, 0, 0, 1}))

	regs := &Regs{NR: SysConnect}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x4100
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("connect 127.0.0.1: X[0]=%d (%s)", int64(regs.X[0]), syscall.Errno(-int64(regs.X[0])))
	}
}

// internet mode's builtin deny includes 127.0.0.0/8 — any loopback
// connect must be blocked even though the user hasn't set an explicit
// deny rule. This is the "don't let the guest talk to host services"
// guardrail.
func TestConnectLoopbackUnderInternetModeBlocked(t *testing.T) {
	h := newConnectHarness(t, "internet")
	g, _ := h.allocClientSocket(t, syscall.AF_INET)
	h.mr.Stage(0x4200, buildSockaddrIn(80, [4]byte{127, 0, 0, 1}))

	regs := &Regs{NR: SysConnect}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x4200
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EACCES) {
		t.Errorf("internet/127.0.0.1: X[0]=%d, want -EACCES", int64(regs.X[0]))
	}
}

// loopback-only: a public destination must be EACCES even though the
// dest isn't in the builtin deny list (the mode itself restricts).
func TestConnectPublicUnderLoopbackOnlyBlocked(t *testing.T) {
	h := newConnectHarness(t, "loopback-only")
	g, _ := h.allocClientSocket(t, syscall.AF_INET)
	h.mr.Stage(0x4300, buildSockaddrIn(443, [4]byte{1, 1, 1, 1}))

	regs := &Regs{NR: SysConnect}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x4300
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EACCES) {
		t.Errorf("loopback-only/1.1.1.1: X[0]=%d, want -EACCES", int64(regs.X[0]))
	}
}

// Private (RFC1918) destinations are in the builtin deny — user set
// mode="internet" but the gate still blocks 10.x. Prevents the guest
// from reaching the host's LAN.
func TestConnectPrivateCIDRBlockedUnderInternet(t *testing.T) {
	h := newConnectHarness(t, "internet")
	g, _ := h.allocClientSocket(t, syscall.AF_INET)
	h.mr.Stage(0x4400, buildSockaddrIn(22, [4]byte{10, 0, 0, 5}))

	regs := &Regs{NR: SysConnect}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x4400
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EACCES) {
		t.Errorf("internet/10.0.0.5: X[0]=%d, want -EACCES", int64(regs.X[0]))
	}
}

// AF_INET6 connect to ::1 under loopback-only succeeds.
func TestConnectIPv6LoopbackUnderLoopbackOnly(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	var addr [16]byte
	addr[15] = 1 // ::1
	h := newConnectHarness(t, "loopback-only")
	g, _ := h.allocClientSocket(t, syscall.AF_INET6)
	h.mr.Stage(0x4500, buildSockaddrIn6(port, addr, 0))

	regs := &Regs{NR: SysConnect}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x4500
	regs.X[2] = 28
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("connect ::1: X[0]=%d (%s)", int64(regs.X[0]), syscall.Errno(-int64(regs.X[0])))
	}
}

func TestConnectBadFdIsEBADF(t *testing.T) {
	h := newConnectHarness(t, "loopback-only")
	h.mr.Stage(0x4600, buildSockaddrIn(80, [4]byte{127, 0, 0, 1}))
	regs := &Regs{NR: SysConnect}
	regs.X[0] = 999
	regs.X[1] = 0x4600
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}

func TestConnectTruncatedSockaddrIsEINVAL(t *testing.T) {
	h := newConnectHarness(t, "loopback-only")
	g, _ := h.allocClientSocket(t, syscall.AF_INET)
	// Stage only the family field — an 8-byte "addrlen" for AF_INET is
	// shorter than sockaddr_in's 16 bytes.
	partial := make([]byte, 8)
	binary.LittleEndian.PutUint16(partial[0:2], uint16(syscall.AF_INET))
	h.mr.Stage(0x4700, partial)

	regs := &Regs{NR: SysConnect}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x4700
	regs.X[2] = 8
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EINVAL) {
		t.Errorf("truncated sockaddr: X[0]=%d, want -EINVAL", int64(regs.X[0]))
	}
}

func TestConnectAddrlenBelowMinIsEINVAL(t *testing.T) {
	h := newConnectHarness(t, "loopback-only")
	g, _ := h.allocClientSocket(t, syscall.AF_INET)
	regs := &Regs{NR: SysConnect}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x4800
	regs.X[2] = 1 // too small to even hold the family field
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EINVAL) {
		t.Errorf("addrlen=1: X[0]=%d, want -EINVAL", int64(regs.X[0]))
	}
}

// AF_UNIX is deferred pending FSGate path translation, so connect to
// AF_UNIX sockaddrs must surface ENOSYS loudly rather than reaching
// the host kernel with a guest path.
func TestConnectAFUnixReturnsENOSYS(t *testing.T) {
	h := newConnectHarness(t, "loopback-only")
	g, _ := h.allocClientSocket(t, syscall.AF_UNIX)
	// Minimal AF_UNIX sockaddr: family + short path.
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(syscall.AF_UNIX))
	copy(buf[2:], "/x")
	h.mr.Stage(0x4900, buf)
	regs := &Regs{NR: SysConnect}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x4900
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.ENOSYS) {
		t.Errorf("AF_UNIX: X[0]=%d, want -ENOSYS", int64(regs.X[0]))
	}
}

func TestConnectUnsupportedFamilyIsEAFNOSUPPORT(t *testing.T) {
	h := newConnectHarness(t, "internet")
	g, _ := h.allocClientSocket(t, syscall.AF_INET)
	// Family 17 = AF_PACKET on Linux.
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], 17)
	h.mr.Stage(0x4a00, buf)
	regs := &Regs{NR: SysConnect}
	regs.X[0] = uint64(g)
	regs.X[1] = 0x4a00
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EAFNOSUPPORT) {
		t.Errorf("AF_PACKET: X[0]=%d, want -EAFNOSUPPORT", int64(regs.X[0]))
	}
}
