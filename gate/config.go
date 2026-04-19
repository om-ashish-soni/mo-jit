package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
)

// Config is the on-disk mojit.json shape. It mirrors Policy but uses
// JSON-friendly types (strings for CIDRs and IP addresses, a plain
// []string for argv) so a user can hand-author the file. LoadConfig
// validates and resolves it into a Policy.
//
// The split exists because Policy holds parsed netip values that
// don't round-trip cleanly through JSON, and because Config carries
// the argv / command name which aren't part of Policy itself (the
// gate doesn't care what the guest is running — only mojit-run does).
type Config struct {
	// Rootfs is the read-only lower layer (required, absolute path).
	Rootfs string `json:"rootfs"`
	// Upper is the writable upper layer (required, absolute path).
	Upper string `json:"upper"`
	// Workdir is the guest-side CWD for pid 1 (optional; defaults "/").
	Workdir string `json:"workdir"`
	// Env is the environment for pid 1 (optional).
	Env map[string]string `json:"env"`
	// Binds overlays specific host paths into the guest rootfs.
	Binds []ConfigBind `json:"binds"`
	// Net is the network policy (optional; zero value means mode=none).
	Net ConfigNet `json:"net"`
	// Argv is the guest command (required; argv[0] is the executable).
	Argv []string `json:"argv"`
}

// ConfigBind mirrors BindMount with JSON-friendly field names.
type ConfigBind struct {
	Host     string `json:"host"`
	Guest    string `json:"guest"`
	ReadOnly bool   `json:"readonly"`
}

// ConfigNet mirrors NetPolicy with string-typed CIDRs and addresses.
type ConfigNet struct {
	Mode      string   `json:"mode"`
	DenyCIDRs []string `json:"deny_cidrs"`
	DNS       []string `json:"dns"`
}

// ValidatePolicy checks that a Policy's host-side paths actually
// exist and are usable. Intended for mojit-run startup — not
// ParseConfig / LoadConfig, because those stay pure (no filesystem
// side-effects) so tests can exercise them with fictional paths.
//
// Rules:
//   - LowerDir must exist and be a directory. It's the guest's
//     read-only rootfs; a missing one means nothing will load.
//   - UpperDir must exist OR be creatable as a directory (we
//     MkdirAll at most one level on the user's behalf; deeper
//     paths surface as errors so typos don't silently spawn a
//     directory tree in an unexpected place).
//   - Binds: each HostPath must exist. GuestPath doesn't — it's a
//     guest-side mount point and the gate creates it in the upper
//     layer at runtime.
func ValidatePolicy(p Policy) error {
	var errs []error

	if fi, err := os.Stat(p.LowerDir); err != nil {
		errs = append(errs, fmt.Errorf("rootfs %q: %w", p.LowerDir, err))
	} else if !fi.IsDir() {
		errs = append(errs, fmt.Errorf("rootfs %q: not a directory", p.LowerDir))
	}

	if fi, err := os.Stat(p.UpperDir); err != nil {
		if os.IsNotExist(err) {
			// Create it — this is common for a first-run upper layer.
			if mkErr := os.MkdirAll(p.UpperDir, 0o755); mkErr != nil {
				errs = append(errs, fmt.Errorf("upper %q: %w", p.UpperDir, mkErr))
			}
		} else {
			errs = append(errs, fmt.Errorf("upper %q: %w", p.UpperDir, err))
		}
	} else if !fi.IsDir() {
		errs = append(errs, fmt.Errorf("upper %q: not a directory", p.UpperDir))
	}

	for i, b := range p.Binds {
		if _, err := os.Stat(b.HostPath); err != nil {
			errs = append(errs, fmt.Errorf("binds[%d] host %q: %w", i, b.HostPath, err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// LoadConfig reads and validates a mojit.json at path. On success
// returns the resolved Policy and the guest argv. A validation
// failure reports all errors at once so a user fixing a config file
// sees everything in one pass instead of playing whack-a-mole.
func LoadConfig(path string) (Policy, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, nil, fmt.Errorf("mojit.json: %w", err)
	}
	return ParseConfig(data)
}

// ParseConfig is LoadConfig minus the filesystem dependency — useful
// for tests and for callers that already have the bytes in hand.
func ParseConfig(data []byte) (Policy, []string, error) {
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Policy{}, nil, fmt.Errorf("mojit.json: parse: %w", err)
	}
	return cfg.resolve()
}

// resolve converts a validated Config into a Policy + argv tuple.
// Errors are accumulated and returned as a single joined error so
// the user sees every problem in one pass.
func (c Config) resolve() (Policy, []string, error) {
	var errs []error

	if c.Rootfs == "" {
		errs = append(errs, errors.New(`"rootfs" is required`))
	}
	if c.Upper == "" {
		errs = append(errs, errors.New(`"upper" is required`))
	}
	if len(c.Argv) == 0 {
		errs = append(errs, errors.New(`"argv" is required and must be non-empty`))
	}

	switch c.Net.Mode {
	case "", "none", "loopback-only", "internet":
		// valid
	default:
		errs = append(errs, fmt.Errorf(`"net.mode"=%q invalid (want none|loopback-only|internet)`, c.Net.Mode))
	}

	var denyCIDRs []netip.Prefix
	for i, s := range c.Net.DenyCIDRs {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			errs = append(errs, fmt.Errorf(`"net.deny_cidrs[%d]"=%q: %w`, i, s, err))
			continue
		}
		denyCIDRs = append(denyCIDRs, pfx)
	}

	var dns []netip.Addr
	for i, s := range c.Net.DNS {
		a, err := netip.ParseAddr(s)
		if err != nil {
			errs = append(errs, fmt.Errorf(`"net.dns[%d]"=%q: %w`, i, s, err))
			continue
		}
		dns = append(dns, a)
	}

	binds := make([]BindMount, 0, len(c.Binds))
	for i, b := range c.Binds {
		if b.Host == "" || b.Guest == "" {
			errs = append(errs, fmt.Errorf(`"binds[%d]": host and guest are required`, i))
			continue
		}
		binds = append(binds, BindMount{HostPath: b.Host, GuestPath: b.Guest, ReadOnly: b.ReadOnly})
	}

	if len(errs) > 0 {
		return Policy{}, nil, errors.Join(errs...)
	}

	workdir := c.Workdir
	if workdir == "" {
		workdir = "/"
	}
	mode := c.Net.Mode
	if mode == "" {
		mode = "none"
	}
	p := Policy{
		LowerDir: c.Rootfs,
		UpperDir: c.Upper,
		WorkDir:  workdir,
		Env:      c.Env,
		Binds:    binds,
		Net: NetPolicy{
			Mode:       mode,
			DenyCIDRs:  denyCIDRs,
			DNSServers: dns,
		},
	}
	return p, c.Argv, nil
}
