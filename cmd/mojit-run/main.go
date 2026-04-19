// Command mojit-run executes a guest command inside an mo-jit sandbox.
//
// Usage:
//
//	mojit-run --rootfs ./rootfs --upper ./upper --net internet -- /bin/sh -lc "..."
//	mojit-run --config mojit.json
//
// With --config, all policy is read from a JSON file; any additional
// CLI flags override the corresponding config values. This lets a
// user check a mojit.json into their project and still tweak, say,
// the net mode from the command line.
//
// TODO(M4): the gum cgo bridge + ELF loader land here; the current
// scaffold builds the gate.Dispatcher and prints the resolved policy
// so a user can at least validate their config before the runtime is
// ready.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/om-ashish-soni/mo-jit/gate"
)

func main() {
	configPath := flag.String("config", "", "path to mojit.json (optional; CLI flags override)")
	rootfs := flag.String("rootfs", "", "absolute path to the guest rootfs (read-only lower layer)")
	upper := flag.String("upper", "", "absolute path to the writable upper layer (copy-on-write)")
	netMode := flag.String("net", "", `network policy: "none" | "loopback-only" | "internet"`)
	workdir := flag.String("workdir", "", "guest-side working directory for pid 1")
	validateOnly := flag.Bool("validate", false, "validate policy and exit without launching the guest")
	flag.Parse()

	var (
		policy gate.Policy
		argv   []string
	)

	if *configPath != "" {
		p, a, err := gate.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("mojit-run: %v", err)
		}
		policy = p
		argv = a
	}

	// CLI flags override anything the config file set. A user passing
	// --net=loopback-only alongside --config mojit.json gets the CLI
	// value — useful for quick policy experiments without editing the
	// file.
	if *rootfs != "" {
		policy.LowerDir = *rootfs
	}
	if *upper != "" {
		policy.UpperDir = *upper
	}
	if *workdir != "" {
		policy.WorkDir = *workdir
	}
	if *netMode != "" {
		policy.Net.Mode = *netMode
	}
	if cliArgs := flag.Args(); len(cliArgs) > 0 {
		argv = cliArgs
	}

	// Fill missing defaults that LoadConfig would have supplied when
	// running in pure-CLI mode (no config file).
	if policy.WorkDir == "" {
		policy.WorkDir = "/"
	}
	if policy.Net.Mode == "" {
		policy.Net.Mode = "none"
	}

	// Final validation. Mirrors the errors LoadConfig would have
	// returned so pure-CLI users get the same guardrails.
	var missing []string
	if policy.LowerDir == "" {
		missing = append(missing, "--rootfs")
	}
	if policy.UpperDir == "" {
		missing = append(missing, "--upper")
	}
	if len(argv) == 0 {
		missing = append(missing, "guest command (pass after --)")
	}
	if len(missing) > 0 {
		log.Fatalf("mojit-run: missing required: %v", missing)
	}
	switch policy.Net.Mode {
	case "none", "loopback-only", "internet":
	default:
		log.Fatalf("mojit-run: invalid --net=%q (want none|loopback-only|internet)", policy.Net.Mode)
	}

	if err := gate.ValidatePolicy(policy); err != nil {
		log.Fatalf("mojit-run: policy validation:\n%v", err)
	}
	if *validateOnly {
		fmt.Fprintln(os.Stderr, "mojit-run: policy ok")
		os.Exit(0)
	}

	d := gate.NewDispatcher(policy)
	_ = d // TODO(M4): hand to gum, load guest ELF, run.

	fmt.Fprintf(os.Stderr, "mojit-run: scaffold only — guest exec lands in M4.\n")
	fmt.Fprintf(os.Stderr, "  rootfs  = %s\n", policy.LowerDir)
	fmt.Fprintf(os.Stderr, "  upper   = %s\n", policy.UpperDir)
	fmt.Fprintf(os.Stderr, "  net     = %s\n", policy.Net.Mode)
	fmt.Fprintf(os.Stderr, "  workdir = %s\n", policy.WorkDir)
	fmt.Fprintf(os.Stderr, "  argv    = %v\n", argv)
	os.Exit(2)
}
