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
	"path/filepath"
	"strings"

	"github.com/om-ashish-soni/mo-jit/gate"
	"github.com/om-ashish-soni/mo-jit/loader"
)

func main() {
	configPath := flag.String("config", "", "path to mojit.json (optional; CLI flags override)")
	rootfs := flag.String("rootfs", "", "absolute path to the guest rootfs (read-only lower layer)")
	upper := flag.String("upper", "", "absolute path to the writable upper layer (copy-on-write)")
	netMode := flag.String("net", "", `network policy: "none" | "loopback-only" | "internet"`)
	workdir := flag.String("workdir", "", "guest-side working directory for pid 1")
	validateOnly := flag.Bool("validate", false, "validate policy and exit without launching the guest")
	inspect := flag.Bool("inspect", false, "parse the guest ELF + print its load plan; implies --validate")
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
	if *inspect {
		if err := inspectGuest(policy, argv); err != nil {
			log.Fatalf("mojit-run: inspect: %v", err)
		}
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

// inspectGuest resolves argv[0] through the guest rootfs, parses the
// ELF there, and prints the layout plan. It's a pre-flight check
// for users: "given this config, what would mojit-run actually try
// to load?"
func inspectGuest(policy gate.Policy, argv []string) error {
	// argv[0] is guest-side. For a simple inspection we look it up
	// under the rootfs (lower layer). This is approximate — the
	// guest's real lookup walks PATH through the overlay — but
	// it's enough to report "yes, an aarch64 ELF is there" for
	// the common case of an absolute argv[0].
	guestPath := argv[0]
	if !strings.HasPrefix(guestPath, "/") {
		return fmt.Errorf("argv[0] %q not absolute — inspect needs an absolute guest path", guestPath)
	}
	hostPath := filepath.Join(policy.LowerDir, guestPath)

	f, err := os.Open(hostPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", hostPath, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	type readerAtSize interface {
		ReadAt(p []byte, off int64) (int, error)
		Size() int64
	}
	// os.File has ReadAt but no Size; wrap.
	rs := &fileReaderAt{f: f, size: fi.Size()}
	var _ readerAtSize = rs

	img, err := loader.PlanImage(rs, 0x5555_0000_0000 /*canonical PIE base*/)
	if err != nil {
		return err
	}

	fmt.Printf("guest ELF   : %s  (host: %s)\n", guestPath, hostPath)
	fmt.Printf("  type      : %s\n", pieLabel(img.IsPIE))
	fmt.Printf("  entry     : %#x\n", img.Entry)
	fmt.Printf("  load bias : %#x\n", img.LoadBias)
	fmt.Printf("  phdr      : %#x  (%d × %d bytes)\n", img.PhdrAddr, img.PhNum, img.PhEnt)
	if img.Interp != "" {
		fmt.Printf("  interp    : %s\n", img.Interp)
	}
	fmt.Printf("  segments  : %d\n", len(img.Segments))
	for i, s := range img.Segments {
		fmt.Printf("    [%d] vaddr=%#x memsz=%#x filesz=%#x off=%#x prot=%s align=%#x\n",
			i, s.VAddr, s.MemSz, s.FileSz, s.FileOff, protString(s.Prot), s.Align)
	}
	return nil
}

type fileReaderAt struct {
	f    *os.File
	size int64
}

func (r *fileReaderAt) ReadAt(p []byte, off int64) (int, error) { return r.f.ReadAt(p, off) }
func (r *fileReaderAt) Size() int64                             { return r.size }

func pieLabel(isPIE bool) string {
	if isPIE {
		return "ET_DYN (PIE)"
	}
	return "ET_EXEC"
}

func protString(p uint32) string {
	var b strings.Builder
	if p&loader.ProtRead != 0 {
		b.WriteByte('R')
	} else {
		b.WriteByte('-')
	}
	if p&loader.ProtWrite != 0 {
		b.WriteByte('W')
	} else {
		b.WriteByte('-')
	}
	if p&loader.ProtExec != 0 {
		b.WriteByte('X')
	} else {
		b.WriteByte('-')
	}
	return b.String()
}
