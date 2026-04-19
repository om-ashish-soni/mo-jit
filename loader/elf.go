package loader

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
)

// Segment is one PT_LOAD region planned for the guest address space.
// VAddr / MemSz describe the *relocated* guest placement — for a PIE
// binary (ET_DYN) these already have the load bias folded in.
type Segment struct {
	// VAddr is the guest virtual address the segment loads at.
	VAddr uint64
	// MemSz is the in-memory size (Memsz ≥ Filesz for .bss-style tails).
	MemSz uint64
	// FileOff is the offset in the ELF file to read Filesz bytes from.
	FileOff uint64
	// FileSz is the number of bytes to copy from the ELF.
	FileSz uint64
	// Prot is an RWX bitmask mirroring PROT_READ/WRITE/EXEC. See the
	// ProtRead/Write/Exec constants below.
	Prot uint32
	// Align is the segment's required alignment (usually page size).
	Align uint64
}

const (
	ProtRead  uint32 = 0x1
	ProtWrite uint32 = 0x2
	ProtExec  uint32 = 0x4
)

// Image is the layout plan for a guest ELF: where each PT_LOAD
// segment lands, the entry point, the interpreter path (if any),
// and the auxv values that depend on how the binary got loaded.
type Image struct {
	// Entry is the guest PC to jump to (e_entry + load bias).
	Entry uint64
	// LoadBias is the offset applied to every virtual address in a
	// PIE binary; 0 for a non-PIE ET_EXEC.
	LoadBias uint64
	// Segments lists PT_LOAD segments in file order, with VAddr
	// already biased.
	Segments []Segment

	// Interp is the requested dynamic linker (PT_INTERP) or empty
	// if the binary is statically linked. Callers must load the
	// interpreter themselves and point AtBase at its LoadBias.
	Interp string

	// PhdrAddr is the guest address of the program-header table,
	// suitable for AT_PHDR. The loader must ensure this memory is
	// actually mapped — usually it is, because the first PT_LOAD
	// covers the ELF header, but pathological binaries may hide
	// the phdrs and we'll need to map them separately.
	PhdrAddr uint64
	// PhEnt is the size of each program header (AT_PHENT).
	PhEnt uint64
	// PhNum is the number of program headers (AT_PHNUM).
	PhNum uint64

	// IsPIE is true for ET_DYN (PIE executable or shared object).
	IsPIE bool
}

// ReaderAtSize combines ReaderAt with a known size — debug/elf needs
// both to parse. os.File satisfies it naturally; callers with raw
// bytes can wrap with bytes.Reader.
type ReaderAtSize interface {
	io.ReaderAt
	Size() int64
}

// PlanImage parses an aarch64 Linux ELF and produces the layout
// Image. loadBias is the offset to apply to PIE segments; for a
// non-PIE binary it's ignored. Pass 0 and let the caller rewrite
// the plan if they want to place PIE images at a specific address.
//
// PlanImage does not allocate memory or call mmap — it's pure
// computation so tests can exercise it without being root or
// bothering to reserve real memory.
func PlanImage(r ReaderAtSize, loadBias uint64) (*Image, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("loader: parse ELF: %w", err)
	}
	defer f.Close()

	if f.Machine != elf.EM_AARCH64 {
		return nil, fmt.Errorf("loader: expected EM_AARCH64, got %s", f.Machine)
	}
	if f.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("loader: expected ELFCLASS64, got %s", f.Class)
	}

	img := &Image{
		PhEnt: 56, // sizeof(Elf64_Phdr), fixed by the spec.
		PhNum: uint64(len(f.Progs)),
	}

	switch f.Type {
	case elf.ET_EXEC:
		img.IsPIE = false
		img.LoadBias = 0
	case elf.ET_DYN:
		img.IsPIE = true
		img.LoadBias = loadBias
	default:
		return nil, fmt.Errorf("loader: unsupported ELF type %s", f.Type)
	}

	img.Entry = f.Entry + img.LoadBias

	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_LOAD:
			seg := Segment{
				VAddr:   p.Vaddr + img.LoadBias,
				MemSz:   p.Memsz,
				FileOff: p.Off,
				FileSz:  p.Filesz,
				Align:   p.Align,
				Prot:    progProt(p.Flags),
			}
			img.Segments = append(img.Segments, seg)
		case elf.PT_INTERP:
			buf := make([]byte, p.Filesz)
			if _, err := p.ReadAt(buf, 0); err != nil {
				return nil, fmt.Errorf("loader: read PT_INTERP: %w", err)
			}
			// PT_INTERP is NUL-terminated inside the file; trim it.
			if len(buf) > 0 && buf[len(buf)-1] == 0 {
				buf = buf[:len(buf)-1]
			}
			img.Interp = string(buf)
		case elf.PT_PHDR:
			// PT_PHDR gives the phdr table's virtual address when
			// present. It's the canonical source for AT_PHDR —
			// otherwise we have to derive it from the first
			// PT_LOAD that covers e_phoff (see below).
			img.PhdrAddr = p.Vaddr + img.LoadBias
		}
	}

	if len(img.Segments) == 0 {
		return nil, errors.New("loader: no PT_LOAD segments")
	}

	// If PT_PHDR wasn't present (not required by the spec), derive
	// PhdrAddr from the PT_LOAD that covers the ELF header's
	// e_phoff. Static binaries with a PT_LOAD at file offset 0
	// have their phdrs at Vaddr + e_phoff after biasing.
	if img.PhdrAddr == 0 {
		phOff := elfHeaderPhoff(r)
		for _, s := range img.Segments {
			if phOff >= s.FileOff && phOff < s.FileOff+s.FileSz {
				img.PhdrAddr = s.VAddr + (phOff - s.FileOff)
				break
			}
		}
	}

	return img, nil
}

// progProt translates elf.ProgFlag (PF_R/W/X) into our Prot bitmask.
// The loader intentionally mirrors the ELF flags 1:1 rather than
// opinionating about W^X — enforcing that policy is the memory
// mapper's job, not the parser's.
func progProt(f elf.ProgFlag) uint32 {
	var p uint32
	if f&elf.PF_R != 0 {
		p |= ProtRead
	}
	if f&elf.PF_W != 0 {
		p |= ProtWrite
	}
	if f&elf.PF_X != 0 {
		p |= ProtExec
	}
	return p
}

// elfHeaderPhoff reads e_phoff from the ELF64 header directly. We
// can't use debug/elf for this because its File struct doesn't
// expose e_phoff — only the resolved Progs slice.
func elfHeaderPhoff(r io.ReaderAt) uint64 {
	// Elf64_Ehdr layout: 16B e_ident, then u16 e_type, u16 e_machine,
	// u32 e_version, u64 e_entry, u64 e_phoff — e_phoff is at offset
	// 0x20.
	var buf [8]byte
	if _, err := r.ReadAt(buf[:], 0x20); err != nil {
		return 0
	}
	return uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
		uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56
}
