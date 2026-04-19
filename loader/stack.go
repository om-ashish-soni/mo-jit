// Package loader builds the aarch64 Linux process-start state that a
// statically or dynamically linked ELF expects at entry.
//
// The kernel sets up a very specific memory image just below the
// initial stack pointer before jumping to e_entry: argc, then a
// NULL-terminated argv pointer array, then a NULL-terminated envp
// pointer array, then an AT_NULL-terminated auxv, then some auxiliary
// data blocks (AT_RANDOM's 16 bytes, the AT_PLATFORM string,
// AT_EXECFN's string), and finally the argv / envp string bodies.
// libc's _start / __libc_start_main reads all of that, so any loader
// that wants to run a real Linux binary has to reproduce it byte for
// byte.
//
// This package is pure byte manipulation — no mmap, no syscalls, no
// cgo. It's the foundation the ELF loader and the gum bridge sit on:
// both need to hand the guest a correctly-shaped stack.
package loader

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// aarch64 Linux auxv tag values. Keeping them here (rather than
// depending on x/sys/unix) lets the loader build on any host.
const (
	AtNull     uint64 = 0
	AtIgnore   uint64 = 1
	AtExecFD   uint64 = 2
	AtPHDR     uint64 = 3
	AtPHEnt    uint64 = 4
	AtPHNum    uint64 = 5
	AtPageSz   uint64 = 6
	AtBase     uint64 = 7
	AtFlags    uint64 = 8
	AtEntry    uint64 = 9
	AtNotELF   uint64 = 10
	AtUID      uint64 = 11
	AtEUID     uint64 = 12
	AtGID      uint64 = 13
	AtEGID     uint64 = 14
	AtPlatform uint64 = 15
	AtHWCap    uint64 = 16
	AtClkTck   uint64 = 17
	AtSecure   uint64 = 23
	AtBasePlat uint64 = 24
	AtRandom   uint64 = 25
	AtHWCap2   uint64 = 26
	AtExecFN   uint64 = 31
)

// AuxEntry is one (type, value) pair in the auxiliary vector. For
// tags whose "value" is actually a pointer into the aux-data area
// (AT_RANDOM, AT_PLATFORM, AT_EXECFN), leave Val zero here and pass
// the backing bytes via the matching field on BuildInput — the
// packer resolves the pointer once it knows where the data block
// landed.
type AuxEntry struct {
	Type uint64
	Val  uint64
}

// BuildInput is the declarative description of the initial stack.
// StackBase is the guest virtual address the packed image will
// live at; the packer uses it to turn in-image offsets into the
// absolute pointers argv/envp/auxv need.
type BuildInput struct {
	// StackBase is the guest-side virtual address where byte 0 of
	// the returned image will be mapped. Must be 16-byte aligned —
	// aarch64 requires 16B SP alignment at process entry.
	StackBase uint64

	// Argv and Envp are the guest command line and environment.
	// Argv must be non-empty (argv[0] is the program name per
	// execve semantics).
	Argv []string
	Envp []string

	// Aux is the auxv the guest sees, minus AT_RANDOM, AT_PLATFORM,
	// and AT_EXECFN — the packer appends those itself when the
	// corresponding bytes/strings below are provided, because their
	// Val fields must point into the aux-data region the packer
	// lays out.
	Aux []AuxEntry

	// Random is the 16 bytes exposed via AT_RANDOM. glibc uses
	// them to seed the stack canary and pointer-guard, so handing
	// the guest a deterministic value is a correctness hazard.
	// If nil, no AT_RANDOM entry is emitted.
	Random []byte

	// Platform is the string exposed via AT_PLATFORM. Linux on
	// aarch64 uses "aarch64". If empty, no AT_PLATFORM entry is
	// emitted.
	Platform string

	// ExecFN is the string exposed via AT_EXECFN (the path execve
	// was called with). If empty, no AT_EXECFN entry is emitted.
	ExecFN string
}

// BuildStartStack packs argc, argv, envp, auxv, and the aux-data
// region into a single byte image and returns (image, sp) where sp
// is the guest-side address the kernel would load into x0-on-entry
// (well, into SP; x0 is rewritten to NULL for static binaries).
//
// The returned image is intended to be written verbatim starting at
// StackBase; the guest's SP at entry is the returned sp value.
//
// The stack grows down on aarch64, but this packer writes the image
// bottom-up: the low addresses of the returned slice are where the
// kernel places argc, and the high addresses hold the string bodies.
// Callers that mmap a stack region should map [sp, stackTop) and
// copy the image starting at sp; the ergonomics are cleaner than
// mapping-then-writing-downward and make layout testable.
func BuildStartStack(in BuildInput) ([]byte, uint64, error) {
	if len(in.Argv) == 0 {
		return nil, 0, errors.New("loader: argv must be non-empty")
	}
	if in.StackBase%16 != 0 {
		return nil, 0, fmt.Errorf("loader: StackBase %#x not 16-byte aligned", in.StackBase)
	}
	if in.Random != nil && len(in.Random) != 16 {
		return nil, 0, fmt.Errorf("loader: Random must be 16 bytes, got %d", len(in.Random))
	}

	// Build the final auxv list: caller entries first, then the
	// tags whose values live in the aux-data region. We'll patch
	// their Val fields after we know where that region lands.
	aux := make([]AuxEntry, 0, len(in.Aux)+4)
	aux = append(aux, in.Aux...)
	randomIdx := -1
	if in.Random != nil {
		randomIdx = len(aux)
		aux = append(aux, AuxEntry{Type: AtRandom})
	}
	platformIdx := -1
	if in.Platform != "" {
		platformIdx = len(aux)
		aux = append(aux, AuxEntry{Type: AtPlatform})
	}
	execfnIdx := -1
	if in.ExecFN != "" {
		execfnIdx = len(aux)
		aux = append(aux, AuxEntry{Type: AtExecFN})
	}
	aux = append(aux, AuxEntry{Type: AtNull})

	// Build the string-body region: every argv string, then every
	// envp string. Each is NUL-terminated. We also lay out the
	// aux-data blocks (AT_RANDOM bytes, platform/execfn strings).
	// stringArea is appended bottom-up here but will be placed at
	// the HIGH end of the final image.
	var stringArea []byte
	argvStringOffsets := make([]int, len(in.Argv))
	for i, s := range in.Argv {
		argvStringOffsets[i] = len(stringArea)
		stringArea = append(stringArea, s...)
		stringArea = append(stringArea, 0)
	}
	envpStringOffsets := make([]int, len(in.Envp))
	for i, s := range in.Envp {
		envpStringOffsets[i] = len(stringArea)
		stringArea = append(stringArea, s...)
		stringArea = append(stringArea, 0)
	}
	var randomOffset, platformOffset, execfnOffset int
	if randomIdx >= 0 {
		randomOffset = len(stringArea)
		stringArea = append(stringArea, in.Random...)
	}
	if platformIdx >= 0 {
		platformOffset = len(stringArea)
		stringArea = append(stringArea, in.Platform...)
		stringArea = append(stringArea, 0)
	}
	if execfnIdx >= 0 {
		execfnOffset = len(stringArea)
		stringArea = append(stringArea, in.ExecFN...)
		stringArea = append(stringArea, 0)
	}

	// Compute the fixed-size prefix: argc + argv pointers + NULL +
	// envp pointers + NULL + auxv entries + AT_NULL. All u64s.
	const ptrSize = 8
	prefixWords := 1 + len(in.Argv) + 1 + len(in.Envp) + 1 + 2*len(aux)
	prefixBytes := prefixWords * ptrSize

	// The kernel places the string area above the auxv prefix with
	// an alignment pad so SP stays 16B-aligned. We pad the string
	// area's *start* so that (prefixBytes + pad) % 16 == 0, which
	// keeps the prefix 16B-aligned at StackBase.
	pad := (16 - prefixBytes%16) % 16

	total := prefixBytes + pad + len(stringArea)
	// Tail-pad to keep the whole image 16B-aligned — matches what
	// the kernel does and makes subsequent mmap math trivial.
	if total%16 != 0 {
		total += 16 - total%16
	}

	image := make([]byte, total)
	stringAreaStart := prefixBytes + pad

	copy(image[stringAreaStart:], stringArea)

	// Resolve guest addresses for strings and aux-data blocks.
	stringBase := in.StackBase + uint64(stringAreaStart)
	argvPtrs := make([]uint64, len(in.Argv))
	for i, off := range argvStringOffsets {
		argvPtrs[i] = stringBase + uint64(off)
	}
	envpPtrs := make([]uint64, len(in.Envp))
	for i, off := range envpStringOffsets {
		envpPtrs[i] = stringBase + uint64(off)
	}
	if randomIdx >= 0 {
		aux[randomIdx].Val = stringBase + uint64(randomOffset)
	}
	if platformIdx >= 0 {
		aux[platformIdx].Val = stringBase + uint64(platformOffset)
	}
	if execfnIdx >= 0 {
		aux[execfnIdx].Val = stringBase + uint64(execfnOffset)
	}

	// Write the prefix: argc, argv[], NULL, envp[], NULL, auxv.
	le := binary.LittleEndian
	w := image[:prefixBytes]
	off := 0
	le.PutUint64(w[off:], uint64(len(in.Argv)))
	off += 8
	for _, p := range argvPtrs {
		le.PutUint64(w[off:], p)
		off += 8
	}
	le.PutUint64(w[off:], 0)
	off += 8
	for _, p := range envpPtrs {
		le.PutUint64(w[off:], p)
		off += 8
	}
	le.PutUint64(w[off:], 0)
	off += 8
	for _, e := range aux {
		le.PutUint64(w[off:], e.Type)
		le.PutUint64(w[off+8:], e.Val)
		off += 16
	}

	return image, in.StackBase, nil
}
