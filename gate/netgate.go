package gate

import (
	"errors"
	"net/netip"
)

// ErrBlockedByPolicy is returned when a net operation is denied by NetPolicy.
var ErrBlockedByPolicy = errors.New("gate: network destination blocked by policy")

// NetGate enforces NetPolicy for a guest process.
//
// Intercepted operations (once the runtime lands in M3):
//
//   - socket, connect, bind, accept
//   - sendto, sendmsg, recvfrom, recvmsg
//   - getsockname, getpeername
//
// The gate creates real host sockets (inheriting the host app's
// INTERNET permission on Android) but rejects any destination that
// matches the deny list. seccomp-BPF runs at process start as a
// belt-and-braces filter: any socket syscall from a code address
// outside the gate's range kills the process with SIGSYS.
type NetGate struct {
	policy NetPolicy
	deny   []netip.Prefix
}

// NewNetGate constructs the net gate with the built-in private-range
// denies extended by the policy's DenyCIDRs.
func NewNetGate(p NetPolicy) *NetGate {
	deny := builtinDeny()
	deny = append(deny, p.DenyCIDRs...)
	return &NetGate{
		policy: p,
		deny:   deny,
	}
}

// CheckConnect returns nil if the destination is allowed by policy, or
// ErrBlockedByPolicy otherwise. Callers should apply this before
// issuing the real host-side connect().
func (n *NetGate) CheckConnect(addr netip.AddrPort) error {
	switch n.policy.Mode {
	case "none", "":
		return ErrBlockedByPolicy
	case "loopback-only":
		if !addr.Addr().IsLoopback() {
			return ErrBlockedByPolicy
		}
		return nil
	case "internet":
		for _, pfx := range n.deny {
			if pfx.Contains(addr.Addr()) {
				return ErrBlockedByPolicy
			}
		}
		return nil
	default:
		return errors.New("gate: unknown NetPolicy.Mode (want none|loopback-only|internet)")
	}
}

func builtinDeny() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
}
