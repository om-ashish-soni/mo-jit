// Command mojit-run executes a guest command inside an mo-jit sandbox.
//
// Usage:
//
//	mojit-run --rootfs ./rootfs --upper ./upper --net internet -- /bin/sh -lc "..."
//
// TODO(M4): real implementation. The current scaffold parses flags,
// validates the policy, constructs the gate dispatcher, and prints the
// resolved configuration. Guest ELF exec lands in M4 once gum and the
// svc dispatch handlers are wired.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/om-ashish-soni/mo-jit/gate"
)

func main() {
	rootfs := flag.String("rootfs", "", "absolute path to the guest rootfs (read-only lower layer)")
	upper := flag.String("upper", "", "absolute path to the writable upper layer (copy-on-write)")
	netMode := flag.String("net", "none", `network policy: "none" | "loopback-only" | "internet"`)
	workdir := flag.String("workdir", "/", "guest-side working directory for pid 1")
	flag.Parse()

	if *rootfs == "" {
		log.Fatal("mojit-run: --rootfs is required")
	}
	if *upper == "" {
		log.Fatal("mojit-run: --upper is required")
	}
	argv := flag.Args()
	if len(argv) == 0 {
		log.Fatal("mojit-run: no guest command given\n\tusage: mojit-run [flags] -- /bin/sh -lc '...'")
	}

	policy := gate.Policy{
		LowerDir: *rootfs,
		UpperDir: *upper,
		WorkDir:  *workdir,
		Net:      gate.NetPolicy{Mode: *netMode},
	}

	d := gate.NewDispatcher(policy)
	_ = d // TODO(M4): hand to gum, load guest ELF, run.

	fmt.Fprintf(os.Stderr, "mojit-run: scaffold only — guest exec lands in M4.\n")
	fmt.Fprintf(os.Stderr, "  rootfs  = %s\n", *rootfs)
	fmt.Fprintf(os.Stderr, "  upper   = %s\n", *upper)
	fmt.Fprintf(os.Stderr, "  net     = %s\n", *netMode)
	fmt.Fprintf(os.Stderr, "  workdir = %s\n", *workdir)
	fmt.Fprintf(os.Stderr, "  argv    = %v\n", argv)
	os.Exit(2)
}
