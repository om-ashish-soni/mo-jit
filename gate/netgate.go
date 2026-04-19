package gate

import (
	"errors"
	"net/netip"
	"syscall"
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

// CheckAccept is the policy gate for accept/accept4. Same rule as
// CheckConnect on the peer: loopback-only requires the incoming peer
// to be loopback (otherwise the guest is reachable from outside the
// local host via whatever bind the kernel routed), internet allows
// any, none rejects.
//
// In practice bind(2) + CheckBind already restrict the listen surface
// to loopback on loopback-only, so this is largely a belt-and-braces
// check. The cost is one call per accept, negligible next to the
// round-trip itself.
func (n *NetGate) CheckAccept(peer netip.AddrPort) error {
	switch n.policy.Mode {
	case "none", "":
		return ErrBlockedByPolicy
	case "loopback-only":
		if peer.Addr().IsLoopback() {
			return nil
		}
		return ErrBlockedByPolicy
	case "internet":
		return nil
	default:
		return errors.New("gate: unknown NetPolicy.Mode (want none|loopback-only|internet)")
	}
}

// CheckBind is the policy gate for bind(2). Connect and sendto gate
// the *destination*; bind gates the *local source* address. For a
// loopback-only guest, a bind to a public interface would expose the
// guest as an inbound server on the host's public IP — not what the
// policy promises. So loopback-only requires the bind address to be
// loopback (127.0.0.1/::1) or the wildcard (0.0.0.0/::). Wildcard
// itself isn't public-exposing in practice — libc often binds
// 0.0.0.0:0 for ephemeral source ports during implicit-bind-on-
// connect — and the kernel picks the route-matched interface when
// outbound traffic goes out.
//
// internet mode accepts any local bind (the danger is outbound
// destinations, which CheckConnect handles).
//
// mode=none rejects AF_INET/AF_INET6 even on bind; in practice
// AllowSocket already blocks creation, but the defense-in-depth check
// catches any fd that slipped in some other way.
func (n *NetGate) CheckBind(addr netip.AddrPort) error {
	switch n.policy.Mode {
	case "none", "":
		return ErrBlockedByPolicy
	case "loopback-only":
		a := addr.Addr()
		if a.IsLoopback() || a.IsUnspecified() {
			return nil
		}
		return ErrBlockedByPolicy
	case "internet":
		return nil
	default:
		return errors.New("gate: unknown NetPolicy.Mode (want none|loopback-only|internet)")
	}
}

// AllowSocket is the policy gate for socket(2): it decides whether the
// guest is even allowed to ASK for this kind of socket. Per NetPolicy
// docstring: mode "none" blocks AF_INET / AF_INET6 with EACCES but
// leaves AF_UNIX (and anything else inherently local) alone. Modes
// "loopback-only" and "internet" both permit creation — the actual
// destination check happens later on connect/bind/sendto.
//
// Unknown / unsupported domains (AF_PACKET, AF_NETLINK above what we
// emulate, etc.) return EAFNOSUPPORT so the guest gets a deterministic
// errno rather than us silently forwarding to the host kernel. The
// whitelist is intentionally narrow — widening requires a policy
// decision (AF_NETLINK in particular lets apps read host routing
// state we don't want to leak).
func (n *NetGate) AllowSocket(domain int) error {
	switch domain {
	case syscall.AF_INET, syscall.AF_INET6:
		if n.policy.Mode == "none" {
			return syscall.EACCES
		}
		return nil
	case syscall.AF_UNIX:
		return nil
	default:
		return syscall.EAFNOSUPPORT
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
