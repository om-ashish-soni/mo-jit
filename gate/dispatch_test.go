package gate

import "testing"

func TestDispatchNilRegsIsKill(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: "/tmp/lower"})
	if v := d.Dispatch(nil); v != VerdictKill {
		t.Errorf("nil regs must Kill, got %s", v)
	}
}

func TestDispatchUnknownSyscallPassesThrough(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: "/tmp/lower"})
	r := &Regs{NR: 0xffff_ffff}
	if v := d.Dispatch(r); v != VerdictPassthrough {
		t.Errorf("unknown syscall must Passthrough, got %s", v)
	}
}

func TestDispatchRoutesToRegisteredHandler(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: "/tmp/lower"})

	called := 0
	d.Register(SysOpenAt, func(_ *Dispatcher, regs *Regs) Verdict {
		called++
		regs.X[0] = 0xdead_beef
		return VerdictHandled
	})

	r := &Regs{NR: SysOpenAt}
	v := d.Dispatch(r)
	if v != VerdictHandled {
		t.Errorf("want Handled, got %s", v)
	}
	if called != 1 {
		t.Errorf("handler call count: got %d, want 1", called)
	}
	if r.X[0] != 0xdead_beef {
		t.Errorf("handler result not propagated: got %#x", r.X[0])
	}
}

func TestRegisterOverridesPriorHandler(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: "/tmp/lower"})

	d.Register(SysOpenAt, func(_ *Dispatcher, _ *Regs) Verdict { return VerdictHandled })
	d.Register(SysOpenAt, func(_ *Dispatcher, _ *Regs) Verdict { return VerdictKill })

	v := d.Dispatch(&Regs{NR: SysOpenAt})
	if v != VerdictKill {
		t.Errorf("second Register must replace first, got %s", v)
	}
}

func TestDispatchDoesNotInvokeOtherHandlers(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: "/tmp/lower"})

	openatCalls := 0
	closeCalls := 0
	d.Register(SysOpenAt, func(_ *Dispatcher, _ *Regs) Verdict {
		openatCalls++
		return VerdictHandled
	})
	d.Register(SysClose, func(_ *Dispatcher, _ *Regs) Verdict {
		closeCalls++
		return VerdictHandled
	})

	_ = d.Dispatch(&Regs{NR: SysOpenAt})
	if openatCalls != 1 || closeCalls != 0 {
		t.Errorf("openat dispatch leaked into close handler: openat=%d close=%d",
			openatCalls, closeCalls)
	}

	_ = d.Dispatch(&Regs{NR: SysClose})
	if openatCalls != 1 || closeCalls != 1 {
		t.Errorf("close dispatch leaked into openat handler: openat=%d close=%d",
			openatCalls, closeCalls)
	}
}

func TestVerdictStringRendersAllValues(t *testing.T) {
	cases := []struct {
		v    Verdict
		want string
	}{
		{VerdictHandled, "handled"},
		{VerdictPassthrough, "passthrough"},
		{VerdictKill, "kill"},
		{Verdict(42), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.v.String(); got != tc.want {
			t.Errorf("Verdict(%d).String() = %q, want %q", tc.v, got, tc.want)
		}
	}
}

// Pin the numeric values of the Verdict constants to the C ABI side
// declared in gum/mojit_hook.h. A change here without the
// corresponding C-side change (or vice versa) is an ABI break.
func TestVerdictConstantsMatchCABI(t *testing.T) {
	if VerdictHandled != 0 {
		t.Errorf("VerdictHandled must be 0 to match MOJIT_HANDLED, got %d", VerdictHandled)
	}
	if VerdictPassthrough != 1 {
		t.Errorf("VerdictPassthrough must be 1 to match MOJIT_PASSTHROUGH, got %d", VerdictPassthrough)
	}
	if VerdictKill != 2 {
		t.Errorf("VerdictKill must be 2 to match MOJIT_KILL, got %d", VerdictKill)
	}
	if ABIVersion != 0 {
		t.Errorf("ABIVersion must be 0 to match MOJIT_HOOK_ABI_VERSION, got %d", ABIVersion)
	}
}

// Pin the aarch64 generic syscall numbers so a typo cannot go
// unnoticed. Each constant is cross-referenced to
// include/uapi/asm-generic/unistd.h in the Linux kernel.
func TestSyscallConstantsMatchAArch64GenericTable(t *testing.T) {
	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"getcwd", SysGetCwd, 17},
		{"fcntl", SysFCntl, 25},
		{"ioctl", SysIoctl, 29},
		{"mkdirat", SysMkdirAt, 34},
		{"unlinkat", SysUnlinkAt, 35},
		{"symlinkat", SysSymlinkAt, 36},
		{"linkat", SysLinkAt, 37},
		{"renameat", SysRenameAt, 38},
		{"faccessat", SysFAccessAt, 48},
		{"chdir", SysChDir, 49},
		{"openat", SysOpenAt, 56},
		{"close", SysClose, 57},
		{"readlinkat", SysReadLinkAt, 78},
		{"newfstatat", SysNewFStatAt, 79},
		{"fstat", SysFStat, 80},
		{"renameat2", SysRenameAt2, 276},
		{"faccessat2", SysFAccessAt2, 439},
		{"socket", SysSocket, 198},
		{"bind", SysBind, 200},
		{"accept", SysAccept, 202},
		{"connect", SysConnect, 203},
		{"getsockname", SysGetSockName, 204},
		{"getpeername", SysGetPeerName, 205},
		{"sendto", SysSendTo, 206},
		{"recvfrom", SysRecvFrom, 207},
		{"sendmsg", SysSendMsg, 211},
		{"recvmsg", SysRecvMsg, 212},
		{"accept4", SysAccept4, 242},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: got %d, want %d (aarch64 generic table)", tc.name, tc.got, tc.want)
		}
	}
}
