package gate

import (
	"syscall"
	"testing"
)

func newSocketDispatcher(t *testing.T, mode string) *Dispatcher {
	t.Helper()
	d := NewDispatcher(Policy{Net: NetPolicy{Mode: mode}})
	// Tests don't exercise paths/memory for socket(2).
	return d
}

func TestSocketInetInternetModeSucceeds(t *testing.T) {
	d := newSocketDispatcher(t, "internet")
	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_INET)
	regs.X[1] = uint64(syscall.SOCK_STREAM | syscall.SOCK_CLOEXEC)
	regs.X[2] = 0
	d.Dispatch(regs)
	got := int64(regs.X[0])
	if got < 0 {
		t.Fatalf("socket AF_INET STREAM: X[0]=%d (%s)", got, syscall.Errno(-got))
	}
	// Returned a guest fd — resolve it to a real host fd and close.
	hostFd, ok := d.FDs.Resolve(int(got))
	if !ok {
		t.Fatalf("guest fd %d did not register in FDTable", got)
	}
	// SOCK_CLOEXEC forwarding: FD_CLOEXEC must be set on the host fd.
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(hostFd), uintptr(syscall.F_GETFD), 0)
	if errno != 0 {
		t.Fatalf("fcntl F_GETFD: %v", errno)
	}
	if flags&syscall.FD_CLOEXEC == 0 {
		t.Errorf("SOCK_CLOEXEC not honoured on host fd (flags=%#x)", flags)
	}
	_ = syscall.Close(hostFd)
}

func TestSocketInet6InternetModeSucceeds(t *testing.T) {
	d := newSocketDispatcher(t, "internet")
	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_INET6)
	regs.X[1] = uint64(syscall.SOCK_DGRAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) < 0 {
		t.Fatalf("socket AF_INET6 DGRAM: X[0]=%d", int64(regs.X[0]))
	}
	hostFd, _ := d.FDs.Resolve(int(regs.X[0]))
	_ = syscall.Close(hostFd)
}

func TestSocketModeNoneBlocksInetWithEACCES(t *testing.T) {
	d := newSocketDispatcher(t, "none")
	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_INET)
	regs.X[1] = uint64(syscall.SOCK_STREAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EACCES) {
		t.Errorf("mode=none + AF_INET: X[0]=%d, want -EACCES", int64(regs.X[0]))
	}
}

func TestSocketModeNoneBlocksInet6WithEACCES(t *testing.T) {
	d := newSocketDispatcher(t, "none")
	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_INET6)
	regs.X[1] = uint64(syscall.SOCK_STREAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) != -int64(syscall.EACCES) {
		t.Errorf("mode=none + AF_INET6: X[0]=%d, want -EACCES", int64(regs.X[0]))
	}
}

// UNIX domain sockets aren't network — the docstring on NetPolicy says
// mode="none" only denies AF_INET*. Verify that path still works.
func TestSocketUnixDomainAllowedUnderNone(t *testing.T) {
	d := newSocketDispatcher(t, "none")
	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_UNIX)
	regs.X[1] = uint64(syscall.SOCK_STREAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) < 0 {
		t.Fatalf("AF_UNIX under mode=none: X[0]=%d", int64(regs.X[0]))
	}
	hostFd, _ := d.FDs.Resolve(int(regs.X[0]))
	_ = syscall.Close(hostFd)
}

// AF_PACKET would let the guest sniff host traffic; AF_NETLINK would
// leak host routing state. Both must return EAFNOSUPPORT regardless
// of mode — the whitelist is the enforcement, not the mode.
func TestSocketUnsupportedDomainReturnsEAFNOSUPPORT(t *testing.T) {
	cases := []struct {
		name   string
		domain int
	}{
		{"AF_PACKET", 17},
		{"AF_NETLINK", syscall.AF_NETLINK},
		{"AF_BLUETOOTH", 31},
	}
	for _, mode := range []string{"internet", "loopback-only", "none"} {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				d := newSocketDispatcher(t, mode)
				regs := &Regs{NR: SysSocket}
				regs.X[0] = uint64(tc.domain)
				regs.X[1] = uint64(syscall.SOCK_RAW)
				regs.X[2] = 0
				d.Dispatch(regs)
				if int64(regs.X[0]) != -int64(syscall.EAFNOSUPPORT) {
					t.Errorf("%s/%s: X[0]=%d, want -EAFNOSUPPORT", mode, tc.name, int64(regs.X[0]))
				}
			})
		}
	}
}

func TestSocketLoopbackOnlyPermitsCreation(t *testing.T) {
	// loopback-only gates connect/bind destinations, not creation.
	// socket() must still succeed; the address check happens later.
	d := newSocketDispatcher(t, "loopback-only")
	regs := &Regs{NR: SysSocket}
	regs.X[0] = uint64(syscall.AF_INET)
	regs.X[1] = uint64(syscall.SOCK_STREAM)
	regs.X[2] = 0
	d.Dispatch(regs)
	if int64(regs.X[0]) < 0 {
		t.Fatalf("loopback-only + AF_INET: X[0]=%d", int64(regs.X[0]))
	}
	hostFd, _ := d.FDs.Resolve(int(regs.X[0]))
	_ = syscall.Close(hostFd)
}
