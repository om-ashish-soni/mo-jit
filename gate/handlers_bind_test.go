package gate

import (
	"syscall"
	"testing"
)

// bindHarness opens an AF_INET UDP socket via the dispatcher and
// exposes the MemReader for staging sockaddrs.
type bindHarness struct {
	d   *Dispatcher
	mr  *FakeMemReader
	gfd int
	hfd int
}

func newBindHarness(t *testing.T, mode string, domain int) *bindHarness {
	t.Helper()
	d := NewDispatcher(Policy{Net: NetPolicy{Mode: mode}})
	mr := &FakeMemReader{}
	d.MemR = mr

	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(domain)
	regs.X[1] = uint64(syscall.SOCK_DGRAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) < 0 {
		t.Fatalf("socket(%d): X[0]=%d", domain, int64(regs.X[0]))
	}
	gfd := int(regs.X[0])
	hfd, _ := d.FDs.Resolve(gfd)
	t.Cleanup(func() { _ = syscall.Close(hfd) })
	return &bindHarness{d: d, mr: mr, gfd: gfd, hfd: hfd}
}

func TestBindLoopbackUnderLoopbackOnlySucceeds(t *testing.T) {
	h := newBindHarness(t, "loopback-only", syscall.AF_INET)
	h.mr.Stage(0x5000, buildSockaddrIn(0, [4]byte{127, 0, 0, 1}))
	regs := &Regs{NR: SysBind}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x5000
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("bind 127.0.0.1:0: X[0]=%d (%s)", int64(regs.X[0]), syscall.Errno(-int64(regs.X[0])))
	}
}

// INADDR_ANY under loopback-only is the "libc ephemeral source port"
// shape — allowed, because the kernel route-matches at connect time.
func TestBindInaddrAnyUnderLoopbackOnlySucceeds(t *testing.T) {
	h := newBindHarness(t, "loopback-only", syscall.AF_INET)
	h.mr.Stage(0x5100, buildSockaddrIn(0, [4]byte{0, 0, 0, 0}))
	regs := &Regs{NR: SysBind}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x5100
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("bind 0.0.0.0:0: X[0]=%d (%s)", int64(regs.X[0]), syscall.Errno(-int64(regs.X[0])))
	}
}

// A non-loopback, non-wildcard bind address is a public-exposure
// attempt under loopback-only and must be EACCES.
func TestBindPublicUnderLoopbackOnlyIsEACCES(t *testing.T) {
	h := newBindHarness(t, "loopback-only", syscall.AF_INET)
	h.mr.Stage(0x5200, buildSockaddrIn(0, [4]byte{8, 8, 8, 8}))
	regs := &Regs{NR: SysBind}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x5200
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EACCES) {
		t.Errorf("bind 8.8.8.8: X[0]=%d, want -EACCES", int64(regs.X[0]))
	}
}

// Internet mode: bind to any local address is allowed (policy gates
// OUTBOUND, not inbound). Binding to a non-local address will fail at
// the kernel with EADDRNOTAVAIL — we surface that as-is.
func TestBindUnderInternetModePasses(t *testing.T) {
	h := newBindHarness(t, "internet", syscall.AF_INET)
	h.mr.Stage(0x5300, buildSockaddrIn(0, [4]byte{127, 0, 0, 1}))
	regs := &Regs{NR: SysBind}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x5300
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("internet bind 127.0.0.1:0: X[0]=%d", int64(regs.X[0]))
	}
}

func TestBindIPv6LoopbackUnderLoopbackOnlySucceeds(t *testing.T) {
	h := newBindHarness(t, "loopback-only", syscall.AF_INET6)
	var addr [16]byte
	addr[15] = 1 // ::1
	h.mr.Stage(0x5400, buildSockaddrIn6(0, addr, 0))
	regs := &Regs{NR: SysBind}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x5400
	regs.X[2] = 28
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != 0 {
		t.Fatalf("bind [::1]:0: X[0]=%d (%s)", int64(regs.X[0]), syscall.Errno(-int64(regs.X[0])))
	}
}

func TestBindBadFdIsEBADF(t *testing.T) {
	h := newBindHarness(t, "loopback-only", syscall.AF_INET)
	h.mr.Stage(0x5500, buildSockaddrIn(0, [4]byte{127, 0, 0, 1}))
	regs := &Regs{NR: SysBind}
	regs.X[0] = 9999
	regs.X[1] = 0x5500
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EBADF) {
		t.Errorf("bad fd: X[0]=%d, want -EBADF", int64(regs.X[0]))
	}
}

func TestBindAddrlenBelowMinIsEINVAL(t *testing.T) {
	h := newBindHarness(t, "loopback-only", syscall.AF_INET)
	regs := &Regs{NR: SysBind}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x5600
	regs.X[2] = 1
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EINVAL) {
		t.Errorf("addrlen=1: X[0]=%d, want -EINVAL", int64(regs.X[0]))
	}
}

// AF_UNIX bind needs FSGate path translation — same deferral as
// connect. ENOSYS rather than silently binding to a host-side path.
func TestBindAFUnixIsENOSYS(t *testing.T) {
	h := newBindHarness(t, "loopback-only", syscall.AF_UNIX)
	buf := make([]byte, 16)
	buf[0] = uint8(syscall.AF_UNIX)
	buf[1] = uint8(syscall.AF_UNIX >> 8)
	copy(buf[2:], "/x")
	h.mr.Stage(0x5700, buf)
	regs := &Regs{NR: SysBind}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x5700
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.ENOSYS) {
		t.Errorf("AF_UNIX bind: X[0]=%d, want -ENOSYS", int64(regs.X[0]))
	}
}

func TestBindUnsupportedFamilyIsEAFNOSUPPORT(t *testing.T) {
	h := newBindHarness(t, "internet", syscall.AF_INET)
	buf := make([]byte, 16)
	buf[0] = 17 // AF_PACKET
	h.mr.Stage(0x5800, buf)
	regs := &Regs{NR: SysBind}
	regs.X[0] = uint64(h.gfd)
	regs.X[1] = 0x5800
	regs.X[2] = 16
	h.d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EAFNOSUPPORT) {
		t.Errorf("AF_PACKET bind: X[0]=%d, want -EAFNOSUPPORT", int64(regs.X[0]))
	}
}

// Mode=none blocks AF_INET at socket(); the defense-in-depth CheckBind
// check applies if a caller somehow held an AF_INET fd from before a
// policy switch (not currently possible, but tested against
// regression).
func TestBindModeNoneIsEACCES(t *testing.T) {
	// Build socket under internet so it exists, then mutate policy.
	d := NewDispatcher(Policy{Net: NetPolicy{Mode: "internet"}})
	mr := &FakeMemReader{}
	d.MemR = mr
	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_INET)
	regs.X[1] = uint64(syscall.SOCK_DGRAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	gfd := int(regs.X[0])
	hfd, _ := d.FDs.Resolve(gfd)
	t.Cleanup(func() { _ = syscall.Close(hfd) })

	// Now install a none-mode NetGate without reseating the fd.
	d.Net = NewNetGate(NetPolicy{Mode: "none"})

	mr.Stage(0x5900, buildSockaddrIn(0, [4]byte{127, 0, 0, 1}))
	regs = &Regs{NR: SysBind}
	regs.X[0] = uint64(gfd)
	regs.X[1] = 0x5900
	regs.X[2] = 16
	d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EACCES) {
		t.Errorf("mode=none bind: X[0]=%d, want -EACCES", int64(regs.X[0]))
	}
}
