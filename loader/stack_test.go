package loader

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// readU64 pulls a u64 out of the image at the given guest address,
// translating through stackBase. Panics (via t.Fatalf) on OOB so
// tests fail loud rather than wrap-around with junk values.
func readU64(t *testing.T, image []byte, stackBase, guestAddr uint64) uint64 {
	t.Helper()
	off := guestAddr - stackBase
	if off+8 > uint64(len(image)) {
		t.Fatalf("readU64 %#x out of image (off=%d, len=%d)", guestAddr, off, len(image))
	}
	return binary.LittleEndian.Uint64(image[off : off+8])
}

func readCString(t *testing.T, image []byte, stackBase, guestAddr uint64) string {
	t.Helper()
	off := guestAddr - stackBase
	if off >= uint64(len(image)) {
		t.Fatalf("readCString %#x out of image (off=%d, len=%d)", guestAddr, off, len(image))
	}
	end := bytes.IndexByte(image[off:], 0)
	if end < 0 {
		t.Fatalf("readCString %#x missing NUL terminator", guestAddr)
	}
	return string(image[off : off+uint64(end)])
}

func TestBuildStartStackBasicShape(t *testing.T) {
	in := BuildInput{
		StackBase: 0x7fff_0000_0000,
		Argv:      []string{"/bin/sh", "-lc", "echo hi"},
		Envp:      []string{"PATH=/usr/bin", "LANG=C"},
		Aux: []AuxEntry{
			{Type: AtPageSz, Val: 4096},
			{Type: AtUID, Val: 1000},
		},
		Random:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Platform: "aarch64",
		ExecFN:   "/bin/sh",
	}
	image, sp, err := BuildStartStack(in)
	if err != nil {
		t.Fatal(err)
	}
	if sp != in.StackBase {
		t.Errorf("sp: got %#x, want %#x", sp, in.StackBase)
	}
	if len(image)%16 != 0 {
		t.Errorf("image len %d not 16B aligned", len(image))
	}

	// argc at SP.
	argc := readU64(t, image, sp, sp)
	if argc != 3 {
		t.Errorf("argc: got %d, want 3", argc)
	}

	// argv[] starts at SP+8, NULL-terminated.
	for i, want := range in.Argv {
		p := readU64(t, image, sp, sp+8+uint64(i)*8)
		got := readCString(t, image, sp, p)
		if got != want {
			t.Errorf("argv[%d]: got %q, want %q", i, got, want)
		}
	}
	if p := readU64(t, image, sp, sp+8+uint64(len(in.Argv))*8); p != 0 {
		t.Errorf("argv NULL terminator: got %#x, want 0", p)
	}

	// envp[] starts after argv NULL.
	envpStart := sp + 8 + uint64(len(in.Argv)+1)*8
	for i, want := range in.Envp {
		p := readU64(t, image, sp, envpStart+uint64(i)*8)
		got := readCString(t, image, sp, p)
		if got != want {
			t.Errorf("envp[%d]: got %q, want %q", i, got, want)
		}
	}
	if p := readU64(t, image, sp, envpStart+uint64(len(in.Envp))*8); p != 0 {
		t.Errorf("envp NULL terminator: got %#x, want 0", p)
	}

	// auxv walk: find our AtPageSz, AtUID, AtRandom, AtPlatform,
	// AtExecFN, AtNull.
	auxStart := envpStart + uint64(len(in.Envp)+1)*8
	seen := map[uint64]uint64{}
	for i := 0; ; i++ {
		if i > 32 {
			t.Fatal("auxv walk ran away — no AT_NULL in first 32 entries")
		}
		tag := readU64(t, image, sp, auxStart+uint64(i)*16)
		val := readU64(t, image, sp, auxStart+uint64(i)*16+8)
		seen[tag] = val
		if tag == AtNull {
			break
		}
	}
	if seen[AtPageSz] != 4096 {
		t.Errorf("AT_PAGESZ: got %d, want 4096", seen[AtPageSz])
	}
	if seen[AtUID] != 1000 {
		t.Errorf("AT_UID: got %d, want 1000", seen[AtUID])
	}
	// AT_RANDOM points at the 16 bytes we passed.
	randomAddr, ok := seen[AtRandom]
	if !ok {
		t.Fatal("AT_RANDOM missing")
	}
	randomOff := randomAddr - sp
	gotRandom := image[randomOff : randomOff+16]
	if !bytes.Equal(gotRandom, in.Random) {
		t.Errorf("AT_RANDOM bytes: got %x, want %x", gotRandom, in.Random)
	}
	// AT_PLATFORM points at a NUL-terminated "aarch64".
	platAddr, ok := seen[AtPlatform]
	if !ok {
		t.Fatal("AT_PLATFORM missing")
	}
	if got := readCString(t, image, sp, platAddr); got != "aarch64" {
		t.Errorf("AT_PLATFORM: got %q, want aarch64", got)
	}
	// AT_EXECFN points at "/bin/sh".
	execAddr, ok := seen[AtExecFN]
	if !ok {
		t.Fatal("AT_EXECFN missing")
	}
	if got := readCString(t, image, sp, execAddr); got != "/bin/sh" {
		t.Errorf("AT_EXECFN: got %q, want /bin/sh", got)
	}
}

// Kernel ensures SP is 16B-aligned at process entry. StackBase is
// where SP lands, so the aux-data region offset must not shift the
// prefix alignment.
func TestBuildStartStackKeepsSP16BAligned(t *testing.T) {
	// Odd envp count + odd argv count — stresses the padding math.
	in := BuildInput{
		StackBase: 0x4000_0000,
		Argv:      []string{"/a"},
		Envp:      []string{"X=1", "Y=2", "Z=3"},
		Platform:  "aarch64",
	}
	image, sp, err := BuildStartStack(in)
	if err != nil {
		t.Fatal(err)
	}
	if sp%16 != 0 {
		t.Errorf("sp %#x not 16B-aligned", sp)
	}
	if len(image)%16 != 0 {
		t.Errorf("image length %d not 16B-aligned", len(image))
	}
}

// A guest that doesn't need randomness / platform hints (e.g. a
// stripped test harness) can pass zero values and the packer must
// emit neither AT_RANDOM nor AT_PLATFORM — not AT_RANDOM with NULL
// val (glibc would read 16 bytes from address 0 and crash).
func TestBuildStartStackSkipsOptionalAuxWhenAbsent(t *testing.T) {
	in := BuildInput{
		StackBase: 0x5000_0000,
		Argv:      []string{"/bin/true"},
		Envp:      nil,
		Aux:       []AuxEntry{{Type: AtPageSz, Val: 4096}},
	}
	image, sp, err := BuildStartStack(in)
	if err != nil {
		t.Fatal(err)
	}
	// Walk auxv: argc (8) + argv[1] + NULL (16) + envp NULL (8) = 32.
	auxStart := sp + 8 + uint64(len(in.Argv)+1)*8 + uint64(len(in.Envp)+1)*8
	seen := map[uint64]bool{}
	for i := 0; ; i++ {
		if i > 16 {
			t.Fatal("auxv too long")
		}
		tag := readU64(t, image, sp, auxStart+uint64(i)*16)
		seen[tag] = true
		if tag == AtNull {
			break
		}
	}
	if seen[AtRandom] {
		t.Error("AT_RANDOM emitted despite nil Random")
	}
	if seen[AtPlatform] {
		t.Error("AT_PLATFORM emitted despite empty Platform")
	}
	if seen[AtExecFN] {
		t.Error("AT_EXECFN emitted despite empty ExecFN")
	}
	if !seen[AtPageSz] {
		t.Error("AT_PAGESZ missing")
	}
}

func TestBuildStartStackRejectsEmptyArgv(t *testing.T) {
	_, _, err := BuildStartStack(BuildInput{StackBase: 0x1000})
	if err == nil {
		t.Fatal("want error for empty argv")
	}
}

func TestBuildStartStackRejectsMisalignedBase(t *testing.T) {
	_, _, err := BuildStartStack(BuildInput{
		StackBase: 0x1001,
		Argv:      []string{"/x"},
	})
	if err == nil {
		t.Fatal("want error for misaligned StackBase")
	}
}

func TestBuildStartStackRejectsWrongRandomLength(t *testing.T) {
	_, _, err := BuildStartStack(BuildInput{
		StackBase: 0x1000,
		Argv:      []string{"/x"},
		Random:    []byte{1, 2, 3},
	})
	if err == nil {
		t.Fatal("want error for short random")
	}
}

// A string-heavy argv shouldn't confuse the pointer arithmetic.
// Pack 32 small args and verify every pointer round-trips.
func TestBuildStartStackManyArgs(t *testing.T) {
	argv := make([]string, 32)
	for i := range argv {
		argv[i] = "arg-" + string(rune('A'+i%26))
	}
	image, sp, err := BuildStartStack(BuildInput{
		StackBase: 0x8000_0000,
		Argv:      argv,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range argv {
		p := readU64(t, image, sp, sp+8+uint64(i)*8)
		got := readCString(t, image, sp, p)
		if got != want {
			t.Errorf("argv[%d]: got %q, want %q", i, got, want)
		}
	}
}
