package gate

import "net/netip"

// Policy is the immutable configuration for a gated guest process.
// All fields are validated at load time; invalid policy causes an
// early exit before the guest ELF is loaded.
type Policy struct {
	// LowerDir is the read-only base rootfs, as an absolute host path.
	LowerDir string

	// UpperDir is the writable overlay layer, as an absolute host path.
	// Copy-up targets this directory; whiteouts are recorded here.
	UpperDir string

	// Binds overlay specific host paths into the guest at the given
	// guest-side mount points. Typical use: bind the user's project
	// directory at /home/developer.
	Binds []BindMount

	// Net configures the network gate. Zero value means "no network".
	Net NetPolicy

	// Env is the environment passed to the guest's pid 1.
	Env map[string]string

	// WorkDir is the guest-side working directory for pid 1.
	// Empty means "/".
	WorkDir string
}

// BindMount overlays a single host path into the guest rootfs.
type BindMount struct {
	HostPath  string
	GuestPath string
	ReadOnly  bool
}

// NetPolicy controls the network gate.
type NetPolicy struct {
	// Mode is "none", "loopback-only", or "internet".
	//
	// "none"          — all socket(AF_INET*) calls fail with EACCES.
	// "loopback-only" — only the guest's own loopback works;
	//                   external destinations are blocked.
	// "internet"      — public internet is reachable; RFC1918,
	//                   loopback, and link-local are always blocked.
	Mode string

	// DenyCIDRs extends the built-in deny list. Built-ins always deny:
	//   127.0.0.0/8, ::1/128, 169.254.0.0/16, fe80::/10,
	//   10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
	DenyCIDRs []netip.Prefix

	// DNSServers is the upstream resolver list the synthetic 10.0.2.3
	// forwarder will query. On Android, populate this from
	// ConnectivityManager.getLinkProperties().dnsServers.
	// On generic Linux, parse /etc/resolv.conf on the host.
	DNSServers []netip.Addr
}
