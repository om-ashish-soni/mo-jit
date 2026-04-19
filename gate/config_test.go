package gate

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfigHappyPath(t *testing.T) {
	data := []byte(`{
		"rootfs": "/opt/rootfs",
		"upper": "/var/mojit/upper",
		"workdir": "/home/developer",
		"env": {"PATH": "/bin:/usr/bin"},
		"binds": [{"host": "/home/u/proj", "guest": "/home/developer/proj", "readonly": false}],
		"net": {
			"mode": "internet",
			"deny_cidrs": ["203.0.113.0/24"],
			"dns": ["8.8.8.8", "1.1.1.1"]
		},
		"argv": ["/bin/sh", "-lc", "apt-get update"]
	}`)

	p, argv, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if p.LowerDir != "/opt/rootfs" || p.UpperDir != "/var/mojit/upper" {
		t.Errorf("rootfs/upper: got %q/%q", p.LowerDir, p.UpperDir)
	}
	if p.WorkDir != "/home/developer" {
		t.Errorf("workdir: got %q", p.WorkDir)
	}
	if p.Env["PATH"] != "/bin:/usr/bin" {
		t.Errorf("env PATH: got %q", p.Env["PATH"])
	}
	if len(p.Binds) != 1 || p.Binds[0].HostPath != "/home/u/proj" {
		t.Errorf("binds: got %+v", p.Binds)
	}
	if p.Net.Mode != "internet" {
		t.Errorf("net.mode: got %q", p.Net.Mode)
	}
	if len(p.Net.DenyCIDRs) != 1 || p.Net.DenyCIDRs[0] != netip.MustParsePrefix("203.0.113.0/24") {
		t.Errorf("deny_cidrs: got %+v", p.Net.DenyCIDRs)
	}
	if len(p.Net.DNSServers) != 2 {
		t.Errorf("dns: got %+v", p.Net.DNSServers)
	}
	if len(argv) != 3 || argv[0] != "/bin/sh" {
		t.Errorf("argv: got %+v", argv)
	}
}

// Defaults: workdir empty becomes "/", net.mode empty becomes "none".
func TestParseConfigDefaults(t *testing.T) {
	data := []byte(`{
		"rootfs": "/r",
		"upper": "/u",
		"argv": ["/bin/true"]
	}`)
	p, _, err := ParseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if p.WorkDir != "/" {
		t.Errorf("default workdir: got %q, want /", p.WorkDir)
	}
	if p.Net.Mode != "none" {
		t.Errorf("default net.mode: got %q, want none", p.Net.Mode)
	}
}

// All required-field errors must surface in one pass — don't short-
// circuit on the first problem.
func TestParseConfigAccumulatesErrors(t *testing.T) {
	data := []byte(`{
		"net": {"mode": "bogus", "deny_cidrs": ["not-a-cidr"], "dns": ["not-an-ip"]},
		"binds": [{"host": ""}]
	}`)
	_, _, err := ParseConfig(data)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	msg := err.Error()
	for _, substr := range []string{
		`"rootfs"`,
		`"upper"`,
		`"argv"`,
		`"net.mode"`,
		`net.deny_cidrs[0]`,
		`net.dns[0]`,
		`binds[0]`,
	} {
		if !strings.Contains(msg, substr) {
			t.Errorf("missing %q in %q", substr, msg)
		}
	}
}

// Unknown top-level field: typos like "rootfs_path" must not silently
// succeed — DisallowUnknownFields catches them.
func TestParseConfigRejectsUnknownFields(t *testing.T) {
	data := []byte(`{
		"rootfs": "/r",
		"upper": "/u",
		"argv": ["/bin/true"],
		"rootf_s": "typo"
	}`)
	_, _, err := ParseConfig(data)
	if err == nil {
		t.Fatal("want error for unknown field, got nil")
	}
}

func TestLoadConfigRoundsTripsFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mojit.json")
	body := `{"rootfs":"/r","upper":"/u","argv":["/bin/true"],"net":{"mode":"loopback-only"}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, argv, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Net.Mode != "loopback-only" || len(argv) != 1 {
		t.Errorf("round-trip: p=%+v argv=%+v", p, argv)
	}
}

func TestLoadConfigMissingFileFails(t *testing.T) {
	_, _, err := LoadConfig("/does/not/exist/mojit.json")
	if err == nil {
		t.Fatal("want error for missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("want ErrNotExist, got %v", err)
	}
}
