package loader

import (
	"debug/elf"
	"testing"
)

func TestStandardAuxvHasExpectedTags(t *testing.T) {
	raw := buildMinimalELF(t, elf.ET_DYN, true)
	img, err := PlanImage(&byteReaderAt{b: raw}, 0x4000_0000)
	if err != nil {
		t.Fatal(err)
	}
	const interpBase uint64 = 0x7f00_0000
	aux := StandardAuxv(img, interpBase)

	want := map[uint64]uint64{
		AtPHDR:   img.PhdrAddr,
		AtPHEnt:  56,
		AtPHNum:  img.PhNum,
		AtPageSz: 4096,
		AtBase:   interpBase,
		AtEntry:  img.Entry,
	}
	got := map[uint64]uint64{}
	for _, e := range aux {
		got[e.Type] = e.Val
	}
	for tag, v := range want {
		if got[tag] != v {
			t.Errorf("aux[%d]: got %#x, want %#x", tag, got[tag], v)
		}
	}

	// Must NOT include AT_RANDOM / AT_PLATFORM / AT_EXECFN — those
	// go through BuildStartStack's aux-data path.
	for _, tag := range []uint64{AtRandom, AtPlatform, AtExecFN} {
		if _, ok := got[tag]; ok {
			t.Errorf("unexpected tag %d in StandardAuxv", tag)
		}
	}
	// Must NOT include AT_NULL — BuildStartStack terminates.
	if _, ok := got[AtNull]; ok {
		t.Error("StandardAuxv should not emit AT_NULL")
	}
}
