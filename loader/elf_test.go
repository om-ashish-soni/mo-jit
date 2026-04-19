package loader

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"testing"
)

// byteReaderAt wraps a []byte with a ReadAt + Size so debug/elf can
// parse it. bytes.Reader has these already but not through a named
// interface we can pass into PlanImage.
type byteReaderAt struct{ b []byte }

func (r *byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	return n, nil
}
func (r *byteReaderAt) Size() int64 { return int64(len(r.b)) }

// buildMinimalELF synthesises an ET_DYN aarch64 ELF with one PT_LOAD
// covering the ELF header + phdrs and one PT_LOAD for a fake .text.
// It's the smallest thing debug/elf will accept for our planner.
func buildMinimalELF(t *testing.T, etype elf.Type, withInterp bool) []byte {
	t.Helper()
	// We need: Ehdr (64B) | Phdrs (Nphdr * 56B) | optional interp
	// string | load2 (fake text) bytes. Everything is in one
	// contiguous file image; PlanImage only cares about file
	// offsets / vaddrs that it can map.
	var interp []byte
	if withInterp {
		interp = append([]byte("/lib/ld-linux-aarch64.so.1"), 0)
	}

	nPhdr := 2 + 1 /*PT_PHDR*/
	if withInterp {
		nPhdr++
	}
	ehdrSize := uint64(64)
	phdrSize := uint64(56)
	phdrsStart := ehdrSize
	phdrsEnd := phdrsStart + uint64(nPhdr)*phdrSize

	interpOff := phdrsEnd
	interpEnd := interpOff + uint64(len(interp))

	// Text segment file bytes — arbitrary payload.
	textFileOff := interpEnd
	textPayload := []byte("fake-text-segment-bytes\x00")
	textFileEnd := textFileOff + uint64(len(textPayload))

	// Choose vaddrs: load1 starts at 0 (so e_phoff = phdrsStart is
	// covered), load2 at 0x200000 (must match file offset % pagesize
	// so the kernel's mmap math works — we fake a small "page" of
	// 0x1000 here).
	load1Vaddr := uint64(0)
	load1Memsz := phdrsEnd
	load2Vaddr := uint64(0x200000)

	buf := make([]byte, textFileEnd)

	// Ehdr.
	le := binary.LittleEndian
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2 // ELFCLASS64
	buf[5] = 1 // ELFDATA2LSB
	buf[6] = 1 // EV_CURRENT
	buf[7] = 0 // ELFOSABI_NONE
	// e_type
	le.PutUint16(buf[16:], uint16(etype))
	// e_machine = EM_AARCH64 = 183
	le.PutUint16(buf[18:], 183)
	// e_version
	le.PutUint32(buf[20:], 1)
	// e_entry
	entryVaddr := load2Vaddr + 0x40
	le.PutUint64(buf[24:], entryVaddr)
	// e_phoff
	le.PutUint64(buf[32:], phdrsStart)
	// e_shoff = 0
	// e_flags
	le.PutUint32(buf[48:], 0)
	// e_ehsize
	le.PutUint16(buf[52:], uint16(ehdrSize))
	// e_phentsize
	le.PutUint16(buf[54:], uint16(phdrSize))
	// e_phnum
	le.PutUint16(buf[56:], uint16(nPhdr))
	// e_shentsize / e_shnum / e_shstrndx = 0.

	// Phdrs.
	pi := 0
	writePhdr := func(typ, flags uint32, off, vaddr, filesz, memsz, align uint64) {
		base := int(phdrsStart) + pi*56
		le.PutUint32(buf[base+0:], typ)
		le.PutUint32(buf[base+4:], flags)
		le.PutUint64(buf[base+8:], off)
		le.PutUint64(buf[base+16:], vaddr)
		le.PutUint64(buf[base+24:], vaddr) // paddr = vaddr
		le.PutUint64(buf[base+32:], filesz)
		le.PutUint64(buf[base+40:], memsz)
		le.PutUint64(buf[base+48:], align)
		pi++
	}

	// PT_PHDR
	writePhdr(uint32(elf.PT_PHDR), uint32(elf.PF_R), phdrsStart, phdrsStart, uint64(nPhdr)*phdrSize, uint64(nPhdr)*phdrSize, 8)
	// PT_LOAD #1 covers Ehdr+Phdrs.
	writePhdr(uint32(elf.PT_LOAD), uint32(elf.PF_R), 0, load1Vaddr, load1Memsz, load1Memsz, 0x1000)
	if withInterp {
		writePhdr(uint32(elf.PT_INTERP), uint32(elf.PF_R), interpOff, interpOff, uint64(len(interp)), uint64(len(interp)), 1)
	}
	// PT_LOAD #2: fake .text (R+X).
	writePhdr(uint32(elf.PT_LOAD), uint32(elf.PF_R|elf.PF_X), textFileOff, load2Vaddr, uint64(len(textPayload)), uint64(len(textPayload))+0x100 /*bss-ish tail*/, 0x1000)

	if withInterp {
		copy(buf[interpOff:], interp)
	}
	copy(buf[textFileOff:], textPayload)
	return buf
}

func TestPlanImageStaticET_EXEC(t *testing.T) {
	raw := buildMinimalELF(t, elf.ET_EXEC, false)
	img, err := PlanImage(&byteReaderAt{b: raw}, 0xdead0000 /*ignored for ET_EXEC*/)
	if err != nil {
		t.Fatal(err)
	}
	if img.IsPIE {
		t.Error("ET_EXEC: IsPIE should be false")
	}
	if img.LoadBias != 0 {
		t.Errorf("ET_EXEC: LoadBias=%#x, want 0", img.LoadBias)
	}
	if img.Interp != "" {
		t.Errorf("static: Interp=%q, want empty", img.Interp)
	}
	if img.PhEnt != 56 {
		t.Errorf("PhEnt: got %d, want 56", img.PhEnt)
	}
	if img.PhNum == 0 {
		t.Error("PhNum should be > 0")
	}
	if len(img.Segments) != 2 {
		t.Fatalf("segments: got %d, want 2", len(img.Segments))
	}
	// Second segment is R+X.
	if img.Segments[1].Prot != ProtRead|ProtExec {
		t.Errorf("segment 1 prot: got %#x, want R|X", img.Segments[1].Prot)
	}
	// PhdrAddr must land inside segment 0 (which covers the phdr
	// area at file offset 64).
	s0 := img.Segments[0]
	if img.PhdrAddr < s0.VAddr || img.PhdrAddr >= s0.VAddr+s0.MemSz {
		t.Errorf("PhdrAddr %#x not in segment 0 [%#x, %#x)",
			img.PhdrAddr, s0.VAddr, s0.VAddr+s0.MemSz)
	}
}

func TestPlanImagePIEAppliesLoadBias(t *testing.T) {
	raw := buildMinimalELF(t, elf.ET_DYN, false)
	const bias = uint64(0x5555_0000_0000)
	img, err := PlanImage(&byteReaderAt{b: raw}, bias)
	if err != nil {
		t.Fatal(err)
	}
	if !img.IsPIE {
		t.Error("ET_DYN: IsPIE should be true")
	}
	if img.LoadBias != bias {
		t.Errorf("LoadBias: got %#x, want %#x", img.LoadBias, bias)
	}
	// Entry = e_entry (0x200040) + bias.
	wantEntry := uint64(0x200040) + bias
	if img.Entry != wantEntry {
		t.Errorf("Entry: got %#x, want %#x", img.Entry, wantEntry)
	}
	// Segment vaddrs shifted.
	if img.Segments[1].VAddr != 0x200000+bias {
		t.Errorf("seg1 VAddr: got %#x, want %#x", img.Segments[1].VAddr, 0x200000+bias)
	}
	if img.PhdrAddr < bias {
		t.Errorf("PhdrAddr %#x not biased (< bias %#x)", img.PhdrAddr, bias)
	}
}

func TestPlanImageInterpStripsNul(t *testing.T) {
	raw := buildMinimalELF(t, elf.ET_DYN, true)
	img, err := PlanImage(&byteReaderAt{b: raw}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if img.Interp != "/lib/ld-linux-aarch64.so.1" {
		t.Errorf("Interp: got %q, want /lib/ld-linux-aarch64.so.1", img.Interp)
	}
	// Trailing NUL must be stripped; assert no NUL bytes.
	if bytes.IndexByte([]byte(img.Interp), 0) >= 0 {
		t.Error("Interp contains NUL — trim failed")
	}
}

func TestPlanImageRejectsNonAArch64(t *testing.T) {
	raw := buildMinimalELF(t, elf.ET_EXEC, false)
	// Rewrite e_machine to x86_64 (62).
	binary.LittleEndian.PutUint16(raw[18:], 62)
	_, err := PlanImage(&byteReaderAt{b: raw}, 0)
	if err == nil {
		t.Fatal("want error for non-AArch64 ELF")
	}
}

func TestPlanImageRejectsCoreDump(t *testing.T) {
	raw := buildMinimalELF(t, elf.ET_CORE, false)
	_, err := PlanImage(&byteReaderAt{b: raw}, 0)
	if err == nil {
		t.Fatal("want error for ET_CORE")
	}
}

func TestPlanImageRejectsGarbage(t *testing.T) {
	_, err := PlanImage(&byteReaderAt{b: []byte("not an elf")}, 0)
	if err == nil {
		t.Fatal("want error for non-ELF input")
	}
}
