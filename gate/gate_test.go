package gate

import (
	"net/netip"
	"testing"
)

func TestNetGateNoneBlocksEverything(t *testing.T) {
	g := NewNetGate(NetPolicy{Mode: "none"})
	if err := g.CheckConnect(netip.MustParseAddrPort("1.1.1.1:443")); err != ErrBlockedByPolicy {
		t.Fatalf("mode=none must block public addr, got %v", err)
	}
}

func TestNetGateInternetBlocksLoopback(t *testing.T) {
	g := NewNetGate(NetPolicy{Mode: "internet"})
	for _, addr := range []string{
		"127.0.0.1:8080",
		"127.1.2.3:80",
		"[::1]:80",
	} {
		if err := g.CheckConnect(netip.MustParseAddrPort(addr)); err != ErrBlockedByPolicy {
			t.Errorf("%s: want blocked (loopback), got %v", addr, err)
		}
	}
}

func TestNetGateInternetBlocksRFC1918(t *testing.T) {
	g := NewNetGate(NetPolicy{Mode: "internet"})
	for _, addr := range []string{
		"10.0.0.1:80",
		"192.168.1.1:443",
		"172.16.0.1:22",
		"172.31.255.254:1",
	} {
		if err := g.CheckConnect(netip.MustParseAddrPort(addr)); err != ErrBlockedByPolicy {
			t.Errorf("%s: want blocked (RFC1918), got %v", addr, err)
		}
	}
}

func TestNetGateInternetBlocksLinkLocal(t *testing.T) {
	g := NewNetGate(NetPolicy{Mode: "internet"})
	for _, addr := range []string{
		"169.254.169.254:80", // cloud metadata
		"[fe80::1]:80",
	} {
		if err := g.CheckConnect(netip.MustParseAddrPort(addr)); err != ErrBlockedByPolicy {
			t.Errorf("%s: want blocked (link-local), got %v", addr, err)
		}
	}
}

func TestNetGateInternetAllowsPublic(t *testing.T) {
	g := NewNetGate(NetPolicy{Mode: "internet"})
	for _, addr := range []string{
		"1.1.1.1:443",
		"8.8.8.8:53",
		"140.82.114.4:443", // github.com-ish public range
		"[2606:4700:4700::1111]:443",
	} {
		if err := g.CheckConnect(netip.MustParseAddrPort(addr)); err != nil {
			t.Errorf("%s: want allowed (public), got %v", addr, err)
		}
	}
}

func TestNetGateLoopbackOnly(t *testing.T) {
	g := NewNetGate(NetPolicy{Mode: "loopback-only"})
	if err := g.CheckConnect(netip.MustParseAddrPort("127.0.0.1:80")); err != nil {
		t.Errorf("loopback-only: want 127.0.0.1 allowed, got %v", err)
	}
	if err := g.CheckConnect(netip.MustParseAddrPort("1.1.1.1:80")); err != ErrBlockedByPolicy {
		t.Errorf("loopback-only: want public blocked, got %v", err)
	}
}

func TestNetGateCustomDenyCIDR(t *testing.T) {
	g := NewNetGate(NetPolicy{
		Mode:      "internet",
		DenyCIDRs: []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")},
	})
	if err := g.CheckConnect(netip.MustParseAddrPort("1.1.1.1:443")); err != ErrBlockedByPolicy {
		t.Errorf("custom deny CIDR not honored: got %v", err)
	}
	if err := g.CheckConnect(netip.MustParseAddrPort("8.8.8.8:53")); err != nil {
		t.Errorf("unrelated public addr should be allowed: got %v", err)
	}
}

func TestDispatcherBuildsBothGates(t *testing.T) {
	d := NewDispatcher(Policy{
		LowerDir: "/tmp/lower",
		UpperDir: "/tmp/upper",
		Net:      NetPolicy{Mode: "internet"},
	})
	if d.FS == nil {
		t.Fatal("FSGate not constructed")
	}
	if d.Net == nil {
		t.Fatal("NetGate not constructed")
	}
}
